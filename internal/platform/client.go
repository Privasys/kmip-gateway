// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package platform is the gateway's control-plane client. The platform authors
// each key's policy, catalogues the key and mints a holder-of-key-bound grant —
// it never sees key material. The gateway then creates the material directly on
// the vault over RA-TLS (the data plane), so the control plane stays out of the
// key path.
package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/kmip-gateway/internal/vault"
)

// Client talks to management-service's key-vault API with the owner's bearer.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

// New builds a control-plane client. baseURL is the management-service origin
// (e.g. https://api.privasys.org); token is the owner's OIDC bearer
// (aud=privasys-platform).
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 30 * time.Second},
	}
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
	req.Header.Set("Authorization", "Bearer "+c.token)
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
// "p256", "aes", "secret" (empty = platform default).
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
