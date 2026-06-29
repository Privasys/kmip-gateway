// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package platform is the gateway's control-plane client. The platform authors
// each key's policy, catalogues the key and mints a holder-of-key-bound grant —
// it never sees key material. The gateway then creates the material directly on
// the vault over RA-TLS (the data plane), so the control plane stays out of the
// key path.
//
// The gateway authenticates to the control plane by ATTESTATION, not an owner
// bearer: every request carries a fresh manager-minted RA-TLS identity leaf (its
// TDX quote + app-id OID 3.6, report_data bound to a fresh timestamp challenge)
// in headers. mgmt-service verifies the quote and that the app is the vault's
// designated operator, then mints the grant on the owner's behalf — so no human
// token is ever in the loop (zero-touch).
package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/kmip-gateway/internal/vault"
)

// Attestor mints the gateway's attested identity for control-plane auth: a fresh
// leaf DER bound to the given challenge nonce. Satisfied by
// identity.ManagerMinter (the measured manager is the sole minter, so the
// stamped app-id is trustworthy by construction).
type Attestor interface {
	MintIdentityDER(ctx context.Context, challenge []byte) ([]byte, error)
}

// Client talks to management-service's key-vault API, authenticated by the
// gateway's attested app identity (no owner bearer).
type Client struct {
	baseURL  string
	attestor Attestor
	hc       *http.Client
}

// New builds a control-plane client. baseURL is the management-service origin
// (e.g. https://api.privasys.org); attestor mints the per-request attested
// identity.
func New(baseURL string, attestor Attestor) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		attestor: attestor,
		hc:       &http.Client{Timeout: 30 * time.Second},
	}
}

// makeChallenge builds a 32-byte challenge whose first 8 bytes are big-endian
// unix seconds (the control plane checks freshness) and whose tail is random
// (uniqueness). The quote's report_data binds the whole challenge.
func makeChallenge() ([]byte, error) {
	c := make([]byte, 32)
	binary.BigEndian.PutUint64(c[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(c[8:]); err != nil {
		return nil, err
	}
	return c, nil
}

// setAttestedAuth mints a fresh identity bound to a fresh challenge and attaches
// both to the request as the gateway's attested control-plane credential.
func (c *Client) setAttestedAuth(ctx context.Context, req *http.Request) error {
	challenge, err := makeChallenge()
	if err != nil {
		return err
	}
	der, err := c.attestor.MintIdentityDER(ctx, challenge)
	if err != nil {
		return fmt.Errorf("mint attested identity: %w", err)
	}
	req.Header.Set("X-Privasys-App-Identity", base64.StdEncoding.EncodeToString(der))
	req.Header.Set("X-Privasys-App-Challenge", base64.StdEncoding.EncodeToString(challenge))
	return nil
}

// grantResponse mirrors the platform's mint/rotate response shape.
type grantResponse struct {
	Key           map[string]interface{} `json:"key"`
	Grant         string                 `json:"grant"`
	Constellation struct {
		Endpoints         []string `json:"endpoints"`
		MRENCLAVE         string   `json:"mrenclave"`
		AttestationServer string   `json:"attestation_server"`
		OIDCIssuer        string   `json:"oidc_issuer"`
		Threshold         int      `json:"threshold"`
	} `json:"constellation"`
}

func (r *grantResponse) toKeyGrant() *vault.KeyGrant {
	handle, _ := r.Key["handle"].(string)
	return &vault.KeyGrant{
		Handle:    handle,
		Grant:     r.Grant,
		Endpoints: r.Constellation.Endpoints,
		MRENCLAVE: r.Constellation.MRENCLAVE,
		AttServer: r.Constellation.AttestationServer,
		Threshold: r.Constellation.Threshold,
	}
}

func (c *Client) post(ctx context.Context, path string, body interface{}) (*grantResponse, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.setAttestedAuth(ctx, req); err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("platform %s: %s: %s", path, resp.Status, strings.TrimSpace(string(data)))
	}
	var out grantResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode grant response: %w", err)
	}
	return &out, nil
}

// MintKeyGrant asks the platform to author the policy, catalogue a new key and
// mint a grant bound to the gateway's holder-of-key cnf. keyType is one of
// "p256", "aes", "secret" (empty = platform default). The operating app is
// derived from the gateway's attested app-id, so no operator id is sent.
func (c *Client) MintKeyGrant(ctx context.Context, vaultID, name, keyType, cnf string, exportable bool) (*vault.KeyGrant, error) {
	body := map[string]interface{}{
		"name":         name,
		"cnf_x5t_s256": cnf,
		"exportable":   exportable,
	}
	if keyType != "" {
		body["key_type"] = keyType
	}
	r, err := c.post(ctx, "/api/v1/keyvaults/"+url.PathEscape(vaultID)+"/keys", body)
	if err != nil {
		return nil, err
	}
	return r.toKeyGrant(), nil
}

// RotateKeyGrant mints a grant for a new primary version of an existing key
// (same type + policy), bound to cnf.
func (c *Client) RotateKeyGrant(ctx context.Context, vaultID, name, cnf string) (*vault.KeyGrant, error) {
	path := "/api/v1/keyvaults/" + url.PathEscape(vaultID) + "/keys/" + url.PathEscape(name) + "/rotate"
	r, err := c.post(ctx, path, map[string]interface{}{"cnf_x5t_s256": cnf})
	if err != nil {
		return nil, err
	}
	return r.toKeyGrant(), nil
}

// OperatedVault is what the attested gateway discovers at startup from a single
// attested call: the vault it fronts, the constellation addressing, and a fresh
// attestation-server token — everything it needs to build the vault session with
// no static secret and no owner bearer.
type OperatedVault struct {
	VaultID          string
	OwnerSub         string
	Endpoints        []string
	MRENCLAVE        string
	AttServer        string
	AttestationToken string
}

// DiscoverOperated fetches GET /api/v1/keyvaults/operated with the gateway's
// attested identity: the control plane returns the vault(s) this app is the
// designated operator of. A gateway fronts one vault, so the first is used.
func (c *Client) DiscoverOperated(ctx context.Context) (*OperatedVault, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/keyvaults/operated", nil)
	if err != nil {
		return nil, err
	}
	if err := c.setAttestedAuth(ctx, req); err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("discover operated vault %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var out struct {
		Vaults []struct {
			ID       string `json:"id"`
			OwnerSub string `json:"owner_sub"`
		} `json:"vaults"`
		Constellation struct {
			Endpoints         []string `json:"endpoints"`
			Mrenclave         string   `json:"mrenclave"`
			AttestationServer string   `json:"attestation_server"`
		} `json:"constellation"`
		AttestationToken string `json:"attestation_token"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode operated vaults: %w", err)
	}
	if len(out.Vaults) == 0 {
		return nil, fmt.Errorf("this app is not the designated operator of any vault")
	}
	return &OperatedVault{
		VaultID:          out.Vaults[0].ID,
		OwnerSub:         out.Vaults[0].OwnerSub,
		Endpoints:        out.Constellation.Endpoints,
		MRENCLAVE:        out.Constellation.Mrenclave,
		AttServer:        out.Constellation.AttestationServer,
		AttestationToken: out.AttestationToken,
	}, nil
}
