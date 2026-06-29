// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command kmip-gateway is a KMIP 2.1 front-end for the Privasys vHSM, run as a
// confidential container-app. Standard KMIP clients reach it over RA-TLS (via the
// kmip-proxy shim); the gateway translates to the vault constellation over RA-TLS
// (the platform is never in the key data path). It serves the KMIP TTLV protocol
// as POST /kmip plus a small HTTP surface (health probe + management MCP tools) on
// the manager-injected $PORT.
//
// Config is ZERO-TOUCH and attested: the gateway authenticates to the control
// plane with its manager-minted RA-TLS identity (TDX quote + app-id OID 3.6),
// discovers the vault the owner has designated it to operate, and builds the
// vault session — no owner bearer and no static secret. The owner designates the
// vault's operator app once (PATCH /keyvaults/{id}); everything else is automatic
// and survives token expiry (discovery vends + the loop refreshes the
// attestation-server token).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Privasys/kmip-gateway/internal/control"
	"github.com/Privasys/kmip-gateway/internal/identity"
	kmipsrv "github.com/Privasys/kmip-gateway/internal/kmip"
	"github.com/Privasys/kmip-gateway/internal/platform"
	"github.com/Privasys/kmip-gateway/internal/vault"
)

// version is set at build time via -ldflags.
var version = "untagged"

// defaultManagerMintURL is the in-TD manager's vault-identity mint endpoint,
// reachable over loopback (the manager listens on :9443).
const defaultManagerMintURL = "http://localhost:9443/api/v1/vault-identity"

// defaultMgmtURL is the control-plane API the gateway self-configures against
// when the runtime has not injected one. The launcher already knows this (its
// ToolSpecMgmtURL); once it injects PRIVASYS_MGMT_URL the image is fully
// env-agnostic and this dev fallback is unused.
const defaultMgmtURL = "https://api-test.developer.privasys.org"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// platformConfig holds the platform-injected, non-app-specific inputs the gateway
// needs to mint its attested identity (app id + the manager mint endpoint + the
// per-app mint-token the runtime injects).
type platformConfig struct {
	appID         string
	managerURL    string
	identityToken string
}

func loadPlatformConfig() platformConfig {
	managerURL := os.Getenv("KMIP_MANAGER_IDENTITY_URL")
	if managerURL == "" {
		managerURL = defaultManagerMintURL
	}
	return platformConfig{
		appID:      env("KMIP_APP_ID", os.Getenv("PRIVASYS_APP_ID")),
		managerURL: managerURL,
		// The per-app token is the platform-standard PRIVASYS_CONTAINER_TOKEN the
		// runtime injects (KMIP_VAULT_IDENTITY_TOKEN overrides it for local testing).
		identityToken: env("KMIP_VAULT_IDENTITY_TOKEN", os.Getenv("PRIVASYS_CONTAINER_TOKEN")),
	}
}

func main() {
	pc := loadPlatformConfig()
	ctrl := control.New(version)

	// The KMIP server (TTLV) and the MCP tools both dispatch to the session, reached
	// over the gateway's HTTP surface (POST /kmip etc.); the gateway serves no TLS of
	// its own — the enclave terminates RA-TLS and reverse-proxies plain HTTP in.
	install := func(sess *vault.Session) {
		ctrl.SetSession(sess, kmipsrv.New(sess))
	}

	// Zero-touch self-config: present the attested identity to mgmt-service, discover
	// the operated vault, build the session. No owner bearer, no static secret.
	mgmtURL := env("KMIP_MGMT_URL", env("PRIVASYS_MGMT_URL", defaultMgmtURL))
	if mgmtURL != "" && pc.identityToken != "" && pc.appID != "" {
		client := platform.New(mgmtURL, identity.New(pc.managerURL, pc.identityToken))
		go selfConfigureLoop(client, pc, install)
		log.Printf("kmip-gateway: zero-touch self-config via %s (app %s)", mgmtURL, pc.appID)
	} else {
		log.Printf("kmip-gateway: zero-touch self-config disabled — needs KMIP_MGMT_URL + a confidential-app runtime (container token + app id)")
	}

	// One HTTP surface on the manager-injected $PORT serves everything: the health
	// probe, the KMIP TTLV endpoint (POST /kmip), and the MCP tools. The KMIP/MCP
	// routes return 503 until the first successful self-config.
	httpAddr := "0.0.0.0:" + env("PORT", "8080")
	log.Printf("kmip-gateway %s: serving (health + KMIP + MCP tools) on %s", version, httpAddr)
	if err := http.ListenAndServe(httpAddr, ctrl.Handler()); err != nil {
		log.Fatalf("kmip-gateway: http serve: %v", err)
	}
}

// selfConfigureLoop discovers the operated vault by attestation and installs the
// vault session, then refreshes periodically so the discovery-vended
// attestation-server token never expires under a long-running gateway.
func selfConfigureLoop(client *platform.Client, pc platformConfig, install func(*vault.Session)) {
	const refresh = 30 * time.Minute
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		op, err := client.DiscoverOperated(ctx)
		cancel()
		if err != nil {
			log.Printf("kmip-gateway: self-config discovery: %v; retrying in 30s", err)
			time.Sleep(30 * time.Second)
			continue
		}
		install(vault.New(vault.Config{
			VaultID:       op.VaultID,
			OwnerSub:      op.OwnerSub,
			Endpoints:     op.Endpoints,
			MRENCLAVE:     op.MRENCLAVE,
			AttServer:     op.AttServer,
			AttToken:      op.AttestationToken,
			AppID:         pc.appID,
			ManagerURL:    pc.managerURL,
			IdentityToken: pc.identityToken,
		}, client))
		log.Printf("kmip-gateway: configured (attested) for vault %s (%d endpoints, vault auth = app identity, no owner bearer)", op.VaultID, len(op.Endpoints))
		time.Sleep(refresh)
	}
}
