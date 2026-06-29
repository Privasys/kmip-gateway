// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command kmip-gateway is a KMIP 2.1 front-end for the Privasys vHSM, run as a
// confidential container-app. KMIP clients connect over TLS; the gateway
// translates to the vault constellation over RA-TLS (the platform is never in the
// key data path). It serves the standard KMIP TTLV protocol on the KMIP port and
// a small HTTP surface (health probe + configure + management MCP tools) on the
// app port.
//
// Config is platform-native: the platform does not inject app env vars, so the
// gateway discovers the constellation from the directory and receives its
// app-specific config (the vault id + control-plane tokens) at runtime via
// POST /configure. For local testing, a full constellation in the environment
// self-configures the gateway at startup.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Privasys/kmip-gateway/internal/control"
	kmipsrv "github.com/Privasys/kmip-gateway/internal/kmip"
	"github.com/Privasys/kmip-gateway/internal/platform"
	"github.com/Privasys/kmip-gateway/internal/vault"
)

// version is set at build time via -ldflags.
var version = "untagged"

// defaultManagerMintURL is the in-TD manager's vault-identity mint endpoint,
// reachable over loopback (the manager listens on :9443).
const defaultManagerMintURL = "http://localhost:9443/api/v1/vault-identity"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// platformConfig holds the platform-injected, non-app-specific inputs (app
// identity + the manager mint endpoint) shared by every configuration path.
type platformConfig struct {
	appID         string
	managerURL    string
	identityToken string
}

func loadPlatformConfig() platformConfig {
	return platformConfig{
		appID:      env("KMIP_APP_ID", os.Getenv("PRIVASYS_APP_ID")),
		managerURL: os.Getenv("KMIP_MANAGER_IDENTITY_URL"),
		// App identity is opted in by setting KMIP_MANAGER_IDENTITY_URL; the per-app
		// token is the platform-standard PRIVASYS_CONTAINER_TOKEN the runtime already
		// injects (KMIP_VAULT_IDENTITY_TOKEN overrides it for local testing).
		identityToken: env("KMIP_VAULT_IDENTITY_TOKEN", os.Getenv("PRIVASYS_CONTAINER_TOKEN")),
	}
}

// envConstellation reads an explicitly-configured constellation from the
// environment (the local-testing path); empty endpoints means "discover it".
func envConstellation() (endpoints []string, mrenclave, attServer string) {
	for _, e := range strings.Split(os.Getenv("KMIP_VAULT_ENDPOINTS"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			endpoints = append(endpoints, e)
		}
	}
	return endpoints, os.Getenv("KMIP_VAULT_MRENCLAVE"), os.Getenv("KMIP_ATTESTATION_SERVER")
}

func newGrantor(mgmtURL, ownerToken string) vault.Grantor {
	if mgmtURL == "" {
		return nil
	}
	return platform.New(mgmtURL, ownerToken)
}

func authMode(s *vault.Session) string {
	if s.UsesAppIdentity() {
		return "app identity (manager-minted)"
	}
	return "owner bearer"
}

func main() {
	pc := loadPlatformConfig()
	ctrl := control.New(version)

	install := func(sess *vault.Session) {
		// The KMIP server (TTLV) and the MCP tools both dispatch to the session;
		// both are reached over the platform's sealed session via the control
		// surface, so the gateway serves no TLS of its own.
		ctrl.SetSession(sess, kmipsrv.New(sess))
	}

	// Runtime configuration: discover the constellation, build the session.
	ctrl.OnConfigure(func(req control.ConfigRequest) error {
		mgmtURL := req.MgmtURL
		if mgmtURL == "" {
			mgmtURL = os.Getenv("KMIP_MGMT_URL")
		}
		if mgmtURL == "" {
			return fmt.Errorf("mgmt_url is required (in the request or KMIP_MGMT_URL) to discover the constellation")
		}
		client := platform.New(mgmtURL, req.OwnerToken)
		// Gate: only the vault owner may configure the gateway, so a stray caller
		// cannot point it at a vault they do not own.
		owns, err := client.OwnsVault(context.Background(), req.VaultID)
		if err != nil {
			return fmt.Errorf("verify vault ownership: %w", err)
		}
		if !owns {
			return fmt.Errorf("owner_token cannot access vault %s", req.VaultID)
		}
		con, err := client.Directory(context.Background())
		if err != nil {
			return err
		}
		var grantor vault.Grantor = client
		// App-identity (no bearer in the data path) is selected here: point the
		// session at the manager mint endpoint + the per-app token. Otherwise the
		// session authenticates to the vault as the owner.
		managerMintURL, identityToken := "", ""
		if req.UseAppIdentity {
			managerMintURL = pc.managerURL
			if managerMintURL == "" {
				managerMintURL = defaultManagerMintURL
			}
			identityToken = pc.identityToken
		}
		sess := vault.New(vault.Config{
			VaultID:       req.VaultID,
			Endpoints:     con.Endpoints,
			MRENCLAVE:     con.MRENCLAVE,
			AttServer:     con.AttServer,
			AttToken:      req.AttestationToken,
			OwnerToken:    req.OwnerToken,
			AppID:         pc.appID,
			ManagerURL:    managerMintURL,
			IdentityToken: identityToken,
		}, grantor)
		log.Printf("kmip-gateway: configured for vault %s (%d constellation endpoints, vault auth = %s)",
			req.VaultID, len(con.Endpoints), authMode(sess))
		install(sess)
		return nil
	})

	// Local-testing path: a full constellation in the environment self-configures
	// at startup, with no discovery or /configure call needed.
	if eps, mre, as := envConstellation(); os.Getenv("KMIP_VAULT_ID") != "" && len(eps) > 0 {
		install(vault.New(vault.Config{
			VaultID:       os.Getenv("KMIP_VAULT_ID"),
			Endpoints:     eps,
			MRENCLAVE:     mre,
			AttServer:     as,
			AttToken:      os.Getenv("KMIP_ATTESTATION_TOKEN"),
			OwnerToken:    os.Getenv("KMIP_OWNER_TOKEN"),
			OwnerSub:      os.Getenv("KMIP_OWNER_SUB"),
			AppID:         pc.appID,
			ManagerURL:    pc.managerURL,
			IdentityToken: pc.identityToken,
		}, newGrantor(os.Getenv("KMIP_MGMT_URL"), os.Getenv("KMIP_OWNER_TOKEN"))))
		log.Printf("kmip-gateway: self-configured from the environment")
	}

	// One HTTP surface on the manager-injected $PORT serves everything: the health
	// probe, /configure, the KMIP TTLV endpoint (POST /kmip), and the MCP tools.
	// All of it rides the platform's sealed session — attested + confidential — so
	// the gateway terminates no TLS itself.
	httpAddr := "0.0.0.0:" + env("PORT", "8080")
	log.Printf("kmip-gateway: serving (health + configure + KMIP + MCP tools) on %s", httpAddr)
	if err := http.ListenAndServe(httpAddr, ctrl.Handler()); err != nil {
		log.Fatalf("kmip-gateway: http serve: %v", err)
	}
}
