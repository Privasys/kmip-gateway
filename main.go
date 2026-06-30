// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command kmip-gateway is a KMIP 2.1 front-end for the Privasys vHSM, run as a
// confidential container-app. Standard KMIP clients reach it over RA-TLS (via the
// kmip-proxy shim); the gateway translates to the vault constellation over RA-TLS
// (the platform is never in the key data path). It serves KMIP TTLV as POST /kmip
// plus a small HTTP surface (health + the typed config + management MCP tools) on
// the manager-injected $PORT.
//
// CONFIG is the platform's image-bound typed-config feature: the owner submits
// the role:config tool (privasys.json) in the native Configure tab — the
// management API URL + which of their vaults to front. The gateway persists it to
// the sealed /data volume and re-applies it on restart (re-lifting the manager's
// freeze gate), so the owner configures once. Everything else is attested and
// zero-touch: the gateway authenticates to the control plane with its
// manager-minted RA-TLS identity (TDX quote + app-id), discovers the constellation
// addressing + a fresh attestation token from the management API, and creates keys
// authorised by ownership — no owner bearer and no static secret.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Privasys/kmip-gateway/internal/control"
	"github.com/Privasys/kmip-gateway/internal/identity"
	kmipsrv "github.com/Privasys/kmip-gateway/internal/kmip"
	"github.com/Privasys/kmip-gateway/internal/platform"
	"github.com/Privasys/kmip-gateway/internal/vault"
)

// version is set at build time via -ldflags.
var version = "untagged"

// defaultManagerMintURL is the in-TD manager's loopback API (vault-identity mint
// + config-complete); the manager listens on :9443.
const (
	defaultManagerURL = "http://localhost:9443"
	configPath        = "/data/config.json"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// platformConfig holds the platform-injected inputs the gateway needs to mint its
// attested identity (app id + the manager loopback URL + the per-app token).
type platformConfig struct {
	appID         string
	managerURL    string
	identityToken string
	containerName string
}

func loadPlatformConfig() platformConfig {
	managerURL := os.Getenv("KMIP_MANAGER_URL")
	if managerURL == "" {
		managerURL = defaultManagerURL
	}
	return platformConfig{
		appID:         env("KMIP_APP_ID", os.Getenv("PRIVASYS_APP_ID")),
		managerURL:    managerURL,
		identityToken: env("KMIP_VAULT_IDENTITY_TOKEN", os.Getenv("PRIVASYS_CONTAINER_TOKEN")),
		containerName: os.Getenv("PRIVASYS_CONTAINER_NAME"),
	}
}

// gwConfig is the owner-submitted typed config, persisted on the sealed volume.
type gwConfig struct {
	MgmtURL string `json:"mgmt_url"`
	VaultID string `json:"vault_id"`
}

func main() {
	pc := loadPlatformConfig()
	ctrl := control.New(version)

	cm := &configManager{
		pc:     pc,
		minter: identity.New(pc.managerURL+"/api/v1/vault-identity", pc.identityToken),
		reload: make(chan struct{}, 1),
		install: func(sess *vault.Session) {
			ctrl.SetSession(sess, kmipsrv.New(sess))
		},
	}

	// Re-apply persisted config on restart: the manager re-arms the freeze gate on
	// every container load, so read the sealed config and re-lift it ourselves (no
	// owner needed after the one-time setup).
	if cfg, err := readConfig(); err != nil {
		log.Printf("kmip-gateway: read persisted config: %v", err)
	} else if cfg != nil {
		cm.set(cfg)
		if err := cm.liftFreeze(); err != nil {
			log.Printf("kmip-gateway: re-lift freeze on restart: %v", err)
		} else {
			log.Printf("kmip-gateway: re-applied persisted config (vault %s); freeze lifted", cfg.VaultID)
		}
	}

	// The owner's Configure-tab submission (role:config tool) lands here; returning
	// 2xx lifts the manager's freeze gate.
	ctrl.OnConfigure(func(req control.ConfigRequest) error {
		cfg := &gwConfig{MgmtURL: req.MgmtURL, VaultID: req.VaultID}
		// Best-effort persistence: with a sealed /data volume the gateway
		// re-applies this on restart; without one it simply needs reconfiguring
		// after a restart (the config still applies in-memory now).
		if err := writeConfig(cfg); err != nil {
			log.Printf("kmip-gateway: persist config (restart self-recovery disabled): %v", err)
		}
		cm.set(cfg)
		log.Printf("kmip-gateway: configured for vault %s via %s", cfg.VaultID, cfg.MgmtURL)
		return nil
	})

	go cm.run()

	// One HTTP surface on the manager-injected $PORT. The manager keeps every path
	// but /configure at HTTP 503 until the first successful configure.
	httpAddr := "0.0.0.0:" + env("PORT", "8080")
	log.Printf("kmip-gateway %s: serving (health + configure + KMIP + tools) on %s", version, httpAddr)
	if err := http.ListenAndServe(httpAddr, ctrl.Handler()); err != nil {
		log.Fatalf("kmip-gateway: http serve: %v", err)
	}
}

// configManager owns the gateway's runtime config + the attested self-config loop.
type configManager struct {
	pc      platformConfig
	minter  *identity.ManagerMinter
	install func(*vault.Session)
	reload  chan struct{}

	mu  sync.RWMutex
	cfg *gwConfig
}

func (cm *configManager) set(cfg *gwConfig) {
	cm.mu.Lock()
	cm.cfg = cfg
	cm.mu.Unlock()
	select {
	case cm.reload <- struct{}{}:
	default:
	}
}

func (cm *configManager) get() *gwConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.cfg
}

// liftFreeze tells the in-TD manager the app is configured, lifting the freeze
// gate without an external /configure call (used to recover after a restart).
func (cm *configManager) liftFreeze() error {
	if cm.pc.containerName == "" {
		return nil // not on enclave-os-virtual (e.g. local testing) — nothing to lift
	}
	url := cm.pc.managerURL + "/api/v1/containers/" + cm.pc.containerName + "/config-complete"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cm.pc.identityToken)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errFromResp(resp)
	}
	return nil
}

// run is the self-config loop: discover the constellation + a fresh attestation
// token (attested), build the session for the configured vault, and re-discover
// before the token expires. Re-runs immediately when the config changes. A panic
// in any iteration is recovered so a transient hiccup never crashes the gateway.
func (cm *configManager) run() {
	const (
		maxRefresh   = 30 * time.Minute
		minRefresh   = time.Minute
		retryBackoff = 30 * time.Second
		expiryMargin = 2 * time.Minute
	)
	for {
		cfg := cm.get()
		if cfg == nil {
			<-cm.reload // wait until the owner configures the gateway
			continue
		}
		sleep := func() time.Duration {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("kmip-gateway: self-config panic recovered: %v", r)
				}
			}()
			client := platform.New(cfg.MgmtURL, cm.minter)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			d, err := client.Discover(ctx)
			cancel()
			if err != nil {
				log.Printf("kmip-gateway: discovery: %v; retrying in %s", err, retryBackoff)
				return retryBackoff
			}
			if !d.Owns(cfg.VaultID) {
				log.Printf("kmip-gateway: vault %s is not owned by this app's owner; reconfigure", cfg.VaultID)
				return maxRefresh
			}
			cm.install(vault.New(vault.Config{
				VaultID:       cfg.VaultID,
				Endpoints:     d.Endpoints,
				MRENCLAVE:     d.MRENCLAVE,
				AttServer:     d.AttServer,
				AttToken:      d.AttestationToken,
				AppID:         cm.pc.appID,
				ManagerURL:    cm.pc.managerURL + "/api/v1/vault-identity",
				IdentityToken: cm.pc.identityToken,
			}, client))
			next := maxRefresh
			if d.AttTokenExpiresAt > 0 {
				if until := time.Until(time.Unix(d.AttTokenExpiresAt, 0).Add(-expiryMargin)); until < next {
					next = until
				}
			}
			if next < minRefresh {
				next = minRefresh
			}
			log.Printf("kmip-gateway: configured (attested) for vault %s (%d endpoints, app identity); refresh in %s", cfg.VaultID, len(d.Endpoints), next.Round(time.Second))
			return next
		}()
		select {
		case <-cm.reload:
		case <-time.After(sleep):
		}
	}
}

// ── sealed-config persistence ────────────────────────────────────────

func readConfig() (*gwConfig, error) {
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg gwConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.MgmtURL == "" || cfg.VaultID == "" {
		return nil, nil
	}
	return &cfg, nil
}

func writeConfig(cfg *gwConfig) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0o600)
}

func errFromResp(resp *http.Response) error {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return &httpError{status: resp.Status, body: buf.String()}
}

type httpError struct {
	status string
	body   string
}

func (e *httpError) Error() string { return "manager " + e.status + ": " + e.body }
