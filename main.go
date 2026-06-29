// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command kmip-gateway is a KMIP 2.1 front-end for the Privasys vHSM, run as a
// confidential container-app. KMIP clients connect over TLS; the gateway
// translates to the vault constellation over RA-TLS (the platform is never in the
// key data path). It serves the standard KMIP TTLV protocol on the KMIP port and
// a small HTTP surface (health probe + management MCP tools) on the app port.
package main

import (
	"log"
	"net"
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

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() (vault.Config, string) {
	var endpoints []string
	for _, e := range strings.Split(os.Getenv("KMIP_VAULT_ENDPOINTS"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			endpoints = append(endpoints, e)
		}
	}
	return vault.Config{
		VaultID:    os.Getenv("KMIP_VAULT_ID"),
		Endpoints:  endpoints,
		MRENCLAVE:  os.Getenv("KMIP_VAULT_MRENCLAVE"),
		AttServer:  os.Getenv("KMIP_ATTESTATION_SERVER"),
		AttToken:   os.Getenv("KMIP_ATTESTATION_TOKEN"),
		OwnerToken: os.Getenv("KMIP_OWNER_TOKEN"),
		OwnerSub:   os.Getenv("KMIP_OWNER_SUB"),
		AppID:      env("KMIP_APP_ID", os.Getenv("PRIVASYS_APP_ID")),
		ManagerURL: os.Getenv("KMIP_MANAGER_IDENTITY_URL"),
		// App-identity is opted in by setting KMIP_MANAGER_IDENTITY_URL; the
		// per-app token is the platform-standard PRIVASYS_CONTAINER_TOKEN the
		// runtime already injects (KMIP_VAULT_IDENTITY_TOKEN overrides it for
		// local testing).
		IdentityToken: env("KMIP_VAULT_IDENTITY_TOKEN", os.Getenv("PRIVASYS_CONTAINER_TOKEN")),
	}, env("KMIP_LISTEN_ADDR", "0.0.0.0:5696")
}

func authMode(s *vault.Session) string {
	if s.UsesAppIdentity() {
		return "app identity (manager-minted)"
	}
	return "owner bearer"
}

func grantorState(g vault.Grantor) string {
	if g == nil {
		return "disabled (set KMIP_MGMT_URL to enable)"
	}
	return "enabled"
}

func main() {
	cfg, addr := loadConfig()
	if cfg.VaultID == "" || len(cfg.Endpoints) == 0 {
		log.Fatal("kmip-gateway: KMIP_VAULT_ID and KMIP_VAULT_ENDPOINTS are required")
	}
	var grantor vault.Grantor
	if mgmt := os.Getenv("KMIP_MGMT_URL"); mgmt != "" {
		grantor = platform.New(mgmt, cfg.OwnerToken)
	}
	sess := vault.New(cfg, grantor)

	// HTTP surface (health + management MCP tools) on the manager-injected $PORT.
	httpAddr := "0.0.0.0:" + env("PORT", "8080")
	go func() {
		log.Printf("kmip-gateway: HTTP (health + MCP tools) on %s", httpAddr)
		if err := http.ListenAndServe(httpAddr, control.New(sess, version).Handler()); err != nil {
			log.Fatalf("kmip-gateway: http serve: %v", err)
		}
	}()

	// KMIP TTLV surface.
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("kmip-gateway: listen %s: %v", addr, err)
	}
	log.Printf("kmip-gateway: fronting vault %s (%d constellation endpoints, key-creation %s, vault auth = %s); KMIP TTLV on %s",
		cfg.VaultID, len(cfg.Endpoints), grantorState(grantor), authMode(sess), addr)
	if err := kmipsrv.New(sess).Serve(l); err != nil {
		log.Fatalf("kmip-gateway: serve: %v", err)
	}
}
