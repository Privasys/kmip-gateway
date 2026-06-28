// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package vault is the gateway's translation layer to the Privasys vault
// constellation. It dials the vaults DIRECTLY over RA-TLS (the platform control
// plane is never in the key data path) and exposes the in-enclave operations the
// KMIP front-end needs. This mirrors the CLI's data-plane flows; the gateway runs
// as a confidential container-app, so it is itself attested.
package vault

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	ratls "enclave-os-mini/clients/go/ratls"
	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// Config addresses one vault (the one this gateway fronts) + the owner identity.
type Config struct {
	VaultID    string   // the user-facing vault id (handles are vaults/<id>/<name>)
	Endpoints  []string // constellation vault endpoints (host:port)
	MRENCLAVE  string   // vault MRENCLAVE pin (hex)
	AttServer  string   // attestation server verify endpoint
	AttToken   string   // aud=attestation-server bearer for quote verification
	OwnerToken string   // the vault owner's OIDC bearer (aud = the vault audience)
}

// Session performs owner-authenticated, in-enclave operations on a vault's keys.
type Session struct{ cfg Config }

func New(cfg Config) *Session { return &Session{cfg: cfg} }

// Handle is the constellation handle for a key name in this vault.
func (s *Session) Handle(name string) string {
	return "vaults/" + s.cfg.VaultID + "/" + name
}

type staticToken string

func (t staticToken) Token(context.Context) (string, error) { return string(t), nil }

func (s *Session) policy() (*ratls.VerificationPolicy, error) {
	mre, err := hex.DecodeString(s.cfg.MRENCLAVE)
	if err != nil || len(mre) != 32 {
		return nil, fmt.Errorf("vault mrenclave must be 32 bytes of hex")
	}
	return &ratls.VerificationPolicy{
		TEE:        ratls.TeeTypeSGX,
		MRENCLAVE:  mre,
		ReportData: ratls.ReportDataDeterministic,
		QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: s.cfg.AttServer, Token: s.cfg.AttToken},
	}, nil
}

func (s *Session) dialOpts() (vsdk.DialOptions, error) {
	p, err := s.policy()
	if err != nil {
		return vsdk.DialOptions{}, err
	}
	return vsdk.DialOptions{AuthToken: staticToken(s.cfg.OwnerToken), VaultPolicy: p}, nil
}

// withHolder dials each endpoint and runs op until the holder vault answers
// (single-enclave operational keys live on one vault; others return "not found").
func withHolder[T any](s *Session, ctx context.Context, op func(c *vsdk.Client) (T, error)) (T, string, error) {
	var zero T
	opts, err := s.dialOpts()
	if err != nil {
		return zero, "", err
	}
	var lastErr error
	for _, ep := range s.cfg.Endpoints {
		c, derr := vsdk.Dial(ctx, vsdk.VaultRegistration{ID: ep, Endpoint: ep, Status: "static"}, opts)
		if derr != nil {
			lastErr = derr
			continue
		}
		v, oerr := op(c)
		c.Close()
		if oerr != nil {
			if strings.Contains(oerr.Error(), "not found") {
				continue
			}
			lastErr = oerr
			continue
		}
		return v, ep, nil
	}
	return zero, "", fmt.Errorf("no vault answered for the key: %v", lastErr)
}

// Wrap encrypts plaintext under an AES-256-GCM key in-enclave. Returns (ct, iv).
func (s *Session) Wrap(ctx context.Context, name string, plaintext []byte) (ct, iv []byte, err error) {
	type res struct{ ct, iv []byte }
	r, _, err := withHolder(s, ctx, func(c *vsdk.Client) (res, error) {
		ct, iv, e := c.Wrap(ctx, s.Handle(name), plaintext, nil, nil)
		return res{ct, iv}, e
	})
	return r.ct, r.iv, err
}

// Unwrap decrypts ciphertext under an AES-256-GCM key in-enclave.
func (s *Session) Unwrap(ctx context.Context, name string, ciphertext, iv []byte) ([]byte, error) {
	pt, _, err := withHolder(s, ctx, func(c *vsdk.Client) ([]byte, error) {
		return c.Unwrap(ctx, s.Handle(name), ciphertext, iv, nil)
	})
	return pt, err
}

// Sign produces an in-enclave ECDSA-P256-SHA256 signature (the message is hashed
// by the vault). Returns (signature, alg).
func (s *Session) Sign(ctx context.Context, name string, message []byte) (sig []byte, alg string, err error) {
	type res struct {
		sig []byte
		alg string
	}
	r, _, err := withHolder(s, ctx, func(c *vsdk.Client) (res, error) {
		sig, alg, e := c.Sign(ctx, s.Handle(name), message)
		return res{sig, alg}, e
	})
	return r.sig, r.alg, err
}

// GetKeyInfo returns a key's metadata (type, exportable, public key).
func (s *Session) GetKeyInfo(ctx context.Context, name string) (vsdk.KeyInfo, error) {
	info, _, err := withHolder(s, ctx, func(c *vsdk.Client) (vsdk.KeyInfo, error) {
		return c.GetKeyInfo(ctx, s.Handle(name))
	})
	return info, err
}

// Destroy deletes a key's material from the constellation (owner-authenticated,
// idempotent across endpoints).
func (s *Session) Destroy(ctx context.Context, name string) error {
	opts, err := s.dialOpts()
	if err != nil {
		return err
	}
	deleted := 0
	var lastErr error
	for _, ep := range s.cfg.Endpoints {
		c, derr := vsdk.Dial(ctx, vsdk.VaultRegistration{ID: ep, Endpoint: ep, Status: "static"}, opts)
		if derr != nil {
			lastErr = derr
			continue
		}
		derr = c.DeleteKey(ctx, s.Handle(name))
		c.Close()
		if derr != nil && !strings.Contains(derr.Error(), "not found") {
			lastErr = derr
			continue
		}
		if derr == nil {
			deleted++
		}
	}
	if deleted == 0 && lastErr != nil {
		return fmt.Errorf("destroy %q: %v", name, lastErr)
	}
	return nil
}
