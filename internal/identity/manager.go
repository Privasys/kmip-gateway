// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package identity obtains the gateway's RA-TLS client identity for the vault
// from the in-TD manager. The gateway never mints its own identity: the measured
// manager is the platform's sole minter, so a certificate it stamps with the
// gateway's app id (OID 3.6) is trustworthy by construction, and the vault
// authorises the gateway by that app id.
//
// Mutual RA-TLS binds the quote to the vault's per-connection challenge, so the
// gateway asks the manager to mint a fresh one-shot certificate on every vault
// connection, via the GetClientCertificate TLS callback.
//
// Manager contract (local, in-TD only):
//
//	POST {ManagerURL}
//	  Authorization: Bearer {token}            // per-app mint-token, injected at launch
//	  { "challenge_b64": "<base64 std>" }      // the vault's RA-TLS challenge nonce
//	→ 200 { "cert_pem": "...", "key_pem": "..." }   // one-shot client cert + key
//
// The manager validates the token to the calling app id and runs its existing
// mintIdentity(challenge, imageDigest, appID); the gateway only completes the
// handshake with the returned ephemeral key. The manager stays out of the key
// data path.
package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ManagerMinter requests one-shot vault client identities from the in-TD manager.
type ManagerMinter struct {
	url   string
	token string
	hc    *http.Client
}

// New builds a minter for the manager mint endpoint (e.g.
// http://localhost:9443/api/v1/vault-identity) authenticated with the per-app
// mint-token the launcher injected.
func New(managerURL, token string) *ManagerMinter {
	return &ManagerMinter{
		url:   managerURL,
		token: token,
		hc:    &http.Client{Timeout: 15 * time.Second},
	}
}

type mintResponse struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// GetClientCertificate returns a TLS GetClientCertificate callback that asks the
// manager to mint a fresh identity bound to the vault's challenge for each
// connection. The challenge arrives on CertificateRequestInfo.RATLSChallenge
// (the Privasys Go fork).
func (m *ManagerMinter) GetClientCertificate() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if len(info.RATLSChallenge) == 0 {
			return nil, errors.New("identity: vault sent no RA-TLS challenge (mutual RA-TLS required)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return m.mint(ctx, info.RATLSChallenge)
	}
}

func (m *ManagerMinter) mint(ctx context.Context, challenge []byte) (*tls.Certificate, error) {
	body, err := json.Marshal(map[string]string{
		"challenge_b64": base64.StdEncoding.EncodeToString(challenge),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.token)
	resp, err := m.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: ask manager to mint: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("identity: manager mint %s: %s", resp.Status, string(data))
	}
	var out mintResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("identity: decode mint response: %w", err)
	}
	cert, err := tls.X509KeyPair([]byte(out.CertPEM), []byte(out.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("identity: parse minted certificate: %w", err)
	}
	return &cert, nil
}
