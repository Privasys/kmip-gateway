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
	"context"
	"crypto/tls"
	"strings"

	ratls "enclave-os-mini/clients/go/ratls"
)

// ManagerMinter holds the gateway's manager-minted RA-TLS v2 client identity
// and produces its evidence on demand.
type ManagerMinter struct {
	id *ratls.EgressIdentity
}

// New builds a minter for the in-TD manager. managerURL may be the manager
// base URL or the legacy mint endpoint (.../api/v1/vault-identity); token is
// the per-app mint token the launcher injected.
func New(managerURL, token string) *ManagerMinter {
	base := strings.TrimSuffix(strings.TrimSuffix(managerURL, "/"), "/api/v1/vault-identity")
	return &ManagerMinter{id: ratls.NewEgressIdentity(base, token)}
}

// GetClientCertificate returns the TLS GetClientCertificate callback: the
// manager-minted identity (leaf key, chain, app-id OID, no evidence), cached
// for its validity. Evidence for it is produced per connection by
// ClientEvidence (RA-TLS v2).
func (m *ManagerMinter) GetClientCertificate() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.id.GetClientCertificate
}

// ClientEvidence quotes the presented identity for one connection when the
// vault requires it.
func (m *ManagerMinter) ClientEvidence() ratls.ClientEvidenceSource {
	return m.id.ClientEvidence
}

// HeaderIdentity returns the identity leaf (DER) and a quote proving it for
// the given 32-byte challenge, the gateway's attested credential to the
// control plane (header flow, RA-TLS v2: the quote commits to the leaf key,
// the challenge and ratls.HeaderIdentityHctx).
func (m *ManagerMinter) HeaderIdentity(_ context.Context, challenge []byte) (der, quote []byte, err error) {
	return m.id.HeaderEvidence(challenge)
}
