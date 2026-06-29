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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"
	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/kmip-gateway/internal/identity"
)

// Config addresses one vault (the one this gateway fronts) + the owner identity.
type Config struct {
	VaultID    string   // the user-facing vault id (handles are vaults/<id>/<name>)
	Endpoints  []string // constellation vault endpoints (host:port)
	MRENCLAVE  string   // vault MRENCLAVE pin (hex)
	AttServer  string   // attestation server verify endpoint
	AttToken   string   // aud=attestation-server bearer for quote verification
	OwnerToken string   // the vault owner's OIDC bearer (aud = the vault audience)
	OwnerSub   string   // the owner's subject (cosmetic, used in the cnf cert CN)
	AppID      string   // the gateway's own app id; when set with app identity, keys it creates grant the op to this app's TEE principal

	// App identity (preferred over the bearer when set). When the gateway runs as
	// a Privasys confidential app, the in-TD manager mints its vault RA-TLS
	// identity on demand (stamping the gateway's app id, OID 3.6). ManagerURL is
	// the manager's mint endpoint and IdentityToken is the per-app mint-token the
	// launcher injects. With these set, the gateway authenticates to the vault as
	// the app and no owner bearer sits in the data path.
	ManagerURL    string
	IdentityToken string
}

// KeyGrant is the platform's grant for a new key plus the constellation
// addressing the gateway needs to create the material directly on the vault.
type KeyGrant struct {
	Handle    string
	Grant     string
	Endpoints []string
	MRENCLAVE string
	AttServer string
	Threshold int
}

// Grantor mints holder-of-key-bound grants from the platform control plane. The
// platform authors the policy + catalogues the key; it never sees material.
type Grantor interface {
	// MintKeyGrant authors the key policy and mints a creation grant. The platform
	// derives the operating app (whose TEE principal is granted the key-type op, so
	// the running app can use the key in-enclave) from the gateway's attested
	// app-id, so no operator id is passed here.
	MintKeyGrant(ctx context.Context, vaultID, name, keyType, cnf string, exportable bool) (*KeyGrant, error)
	RotateKeyGrant(ctx context.Context, vaultID, name, cnf string) (*KeyGrant, error)
}

// Session performs in-enclave operations on a vault's keys, and (via the platform
// grantor) creates new keys. It authenticates to the vault either as the app (a
// manager-minted RA-TLS identity) or as the owner (an OIDC bearer).
type Session struct {
	cfg     Config
	grantor Grantor
	minter  *identity.ManagerMinter // non-nil => app-identity vault auth
}

// New builds a session. When the config points at the manager mint endpoint, the
// gateway authenticates to the vault with its manager-minted app identity;
// otherwise it falls back to the owner bearer.
func New(cfg Config, grantor Grantor) *Session {
	s := &Session{cfg: cfg, grantor: grantor}
	if cfg.ManagerURL != "" && cfg.IdentityToken != "" {
		s.minter = identity.New(cfg.ManagerURL, cfg.IdentityToken)
	}
	return s
}

// UsesAppIdentity reports whether the gateway authenticates to the vault with its
// manager-minted app identity (rather than the owner bearer).
func (s *Session) UsesAppIdentity() bool { return s.minter != nil }

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
		TEE:               ratls.TeeTypeSGX,
		MRENCLAVE:         mre,
		ReportData:        ratls.ReportDataDeterministic,
		QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: s.cfg.AttServer, Token: s.cfg.AttToken},
	}, nil
}

// verifyPolicy builds a verification policy from explicit constellation values
// (used at Create time, where the addressing comes from the platform's grant
// response rather than the gateway's static config).
func verifyPolicy(mrenclaveHex, attServer, attToken string) (*ratls.VerificationPolicy, error) {
	mre, err := hex.DecodeString(mrenclaveHex)
	if err != nil || len(mre) != 32 {
		return nil, fmt.Errorf("vault mrenclave must be 32 bytes of hex")
	}
	return &ratls.VerificationPolicy{
		TEE:               ratls.TeeTypeSGX,
		MRENCLAVE:         mre,
		ReportData:        ratls.ReportDataDeterministic,
		QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: attServer, Token: attToken},
	}, nil
}

// generateClientCert mints an ephemeral P-256 RA-TLS leaf for holder-of-key
// binding and returns the cert plus its SHA-256 thumbprint (the cnf the grant is
// bound to). Mirrors the CLI's secrets path.
func generateClientCert(sub string) (*tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "kmip-gateway " + sub},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(der)
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	if leaf, perr := x509.ParseCertificate(der); perr == nil {
		cert.Leaf = leaf
	}
	return cert, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// vaultKeyType maps the gateway's internal key type ("p256"/"aes") to the vault
// key-type enum the platform expects when minting the grant.
func vaultKeyType(keyType string) string {
	switch keyType {
	case "p256":
		return string(vsdk.P256SigningKey)
	case "aes":
		return string(vsdk.Aes256GcmKey)
	}
	return keyType
}

// generateMaterial produces fresh key material for a managed (single-enclave)
// key type. P-256 signing keys are PKCS#8 DER (the vault's ring parser accepts
// v1); AES-256-GCM keys are 32 random bytes. The material is created whole on one
// vault and used in-enclave; the gateway holds it only transiently.
func generateMaterial(keyType string) ([]byte, error) {
	switch keyType {
	case "p256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate p256: %w", err)
		}
		return x509.MarshalPKCS8PrivateKey(key)
	case "aes":
		material := make([]byte, 32)
		if _, err := rand.Read(material); err != nil {
			return nil, fmt.Errorf("generate aes-256 key: %w", err)
		}
		return material, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q (want p256 or aes)", keyType)
	}
}

// Create generates a new managed key, has the platform author its policy +
// catalogue it + mint a cnf-bound grant, then creates the material directly on
// the holding vault over RA-TLS. Returns the catalogued handle. exportable
// defaults to false for operational keys (ops run in-enclave).
func (s *Session) Create(ctx context.Context, name, keyType string, exportable bool) (string, error) {
	if s.grantor == nil {
		return "", fmt.Errorf("no platform grantor configured for key creation")
	}
	material, err := generateMaterial(keyType)
	if err != nil {
		return "", err
	}
	cert, cnf, err := generateClientCert(s.cfg.OwnerSub)
	if err != nil {
		return "", fmt.Errorf("client cert: %w", err)
	}
	// The platform derives the operating app (the gateway's own app TEE, granted
	// the key-type op so it can use the key over its manager-minted identity) from
	// the gateway's attested app-id on the control-plane call.
	g, err := s.grantor.MintKeyGrant(ctx, s.cfg.VaultID, name, vaultKeyType(keyType), cnf, exportable)
	if err != nil {
		return "", err
	}
	if len(g.Endpoints) == 0 {
		return "", fmt.Errorf("the platform returned no vault endpoints")
	}
	verify, err := verifyPolicy(g.MRENCLAVE, g.AttServer, s.cfg.AttToken)
	if err != nil {
		return "", err
	}
	ep := g.Endpoints[0] // single-enclave: the first (deterministic) vault holds it
	c, err := vsdk.Dial(ctx, vsdk.VaultRegistration{ID: ep, Endpoint: ep, Status: "static"}, vsdk.DialOptions{ClientCert: cert, VaultPolicy: verify})
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", ep, err)
	}
	defer c.Close()
	if _, err := c.CreateKey(ctx, g.Handle, material, g.Grant); err != nil {
		return "", fmt.Errorf("create key on %s: %w", ep, err)
	}
	return g.Handle, nil
}

func (s *Session) dialOpts() (vsdk.DialOptions, error) {
	if s.minter != nil {
		// App identity: present a manager-minted RA-TLS identity (the gateway's app
		// id) instead of a bearer. Send a fresh client nonce in the ClientHello so
		// the vault enters bidirectional-challenge mode and issues its own challenge
		// in the CertificateRequest, which the minted client cert binds to; the same
		// nonce binds the vault's server quote to this connection.
		mre, err := hex.DecodeString(s.cfg.MRENCLAVE)
		if err != nil || len(mre) != 32 {
			return vsdk.DialOptions{}, fmt.Errorf("vault mrenclave must be 32 bytes of hex")
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return vsdk.DialOptions{}, fmt.Errorf("generate challenge nonce: %w", err)
		}
		return vsdk.DialOptions{
			Challenge:            nonce,
			GetClientCertificate: s.minter.GetClientCertificate(),
			VaultPolicy: &ratls.VerificationPolicy{
				TEE:               ratls.TeeTypeSGX,
				MRENCLAVE:         mre,
				ReportData:        ratls.ReportDataChallengeResponse,
				Nonce:             nonce,
				QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: s.cfg.AttServer, Token: s.cfg.AttToken},
			},
		}, nil
	}
	// Otherwise authenticate as the vault OWNER with an OIDC bearer, like the CLI.
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
