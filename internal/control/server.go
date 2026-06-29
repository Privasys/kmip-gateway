// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package control is the gateway's small HTTP surface. It serves the liveness
// probe the Privasys manager expects on the injected $PORT, and exposes a few
// agent-friendly key operations as MCP tools (declared in privasys.json) so the
// gateway shows up in the developer portal's API Testing / AI Tools tabs. The
// heavy KMIP crypto traffic stays on the KMIP TTLV port; this surface is for
// management and health only. Like everywhere else, these operations run
// in-enclave on the vault; the gateway never sees plaintext key material.
package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// Vault is the subset of the vault session the control surface needs.
type Vault interface {
	Create(ctx context.Context, name, keyType string, exportable bool) (string, error)
	Sign(ctx context.Context, name string, message []byte) (sig []byte, alg string, err error)
	GetKeyInfo(ctx context.Context, name string) (vsdk.KeyInfo, error)
}

// ConfigRequest is the app-specific configuration delivered at runtime (the
// platform does not inject app env vars; apps configure themselves). The
// constellation itself is discovered, so only the vault id + the control-plane
// tokens are supplied here.
type ConfigRequest struct {
	VaultID          string `json:"vault_id"`
	MgmtURL          string `json:"mgmt_url"`
	OwnerToken       string `json:"owner_token"`
	AttestationToken string `json:"attestation_token"`
	// UseAppIdentity selects the no-bearer vault auth: the gateway authenticates
	// to the vault with its manager-minted RA-TLS identity (app id) rather than the
	// owner bearer. Selectable here because the platform does not inject app env.
	UseAppIdentity bool `json:"use_app_identity"`
}

// Server is the HTTP management + health surface. The vault session is installed
// at configure time, so the surface serves health (and accepts /configure) from
// the moment the process starts.
type Server struct {
	version   string
	mu        sync.RWMutex
	sess      Vault
	configure func(ConfigRequest) error
}

// New builds the control server. The session is nil until configured.
func New(version string) *Server { return &Server{version: version} }

// OnConfigure registers the handler that builds and installs the vault session
// from a runtime ConfigRequest (discovering the constellation and starting KMIP).
func (s *Server) OnConfigure(fn func(ConfigRequest) error) { s.configure = fn }

// SetSession installs the live vault session (called once configuration succeeds).
func (s *Server) SetSession(v Vault) {
	s.mu.Lock()
	s.sess = v
	s.mu.Unlock()
}

func (s *Server) session() Vault {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sess
}

// Handler returns the routed HTTP handler (Go 1.22 method+path patterns).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /version", s.versionInfo)
	mux.HandleFunc("GET /", s.root)
	mux.HandleFunc("POST /configure", s.configureHandler)
	mux.HandleFunc("POST /keys", s.createKey)
	mux.HandleFunc("POST /sign", s.sign)
	mux.HandleFunc("POST /public", s.getPublicKey)
	return mux
}

// configureHandler installs the app's runtime configuration. Idempotent-ish: the
// first successful configure wins; once configured the gateway serves KMIP.
func (s *Server) configureHandler(w http.ResponseWriter, r *http.Request) {
	if s.configure == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "configuration is not enabled"})
		return
	}
	if s.session() != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already configured"})
		return
	}
	var req ConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.VaultID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "vault_id is required"})
		return
	}
	if err := s.configure(req); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "configured"})
}

// requireSession returns the live session or writes a 503 when not yet configured.
func (s *Server) requireSession(w http.ResponseWriter) (Vault, bool) {
	sess := s.session()
	if sess == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway is awaiting configuration"})
		return nil, false
	}
	return sess, true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *Server) versionInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.version})
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	configured := "false"
	if s.session() != nil {
		configured = "true"
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"service":    "kmip-gateway",
		"version":    s.version,
		"configured": configured,
		"summary":    "KMIP 2.1 front-end for the Privasys vHSM. KMIP clients use the TTLV port; this surface is health + management.",
	})
}

// createKey (MCP tool) generates a managed key in-enclave and returns its handle.
func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if body.Type == "" {
		body.Type = "aes"
	}
	sess, ok := s.requireSession(w)
	if !ok {
		return
	}
	handle, err := sess.Create(r.Context(), body.Name, body.Type, false)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"handle": handle, "type": body.Type})
}

// sign (MCP tool) produces an in-enclave ECDSA-P256 signature over a message.
func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string `json:"name"`
		MessageB64 string `json:"message_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	msg, err := base64.StdEncoding.DecodeString(body.MessageB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message_b64 must be base64"})
		return
	}
	sess, ok := s.requireSession(w)
	if !ok {
		return
	}
	sig, alg, err := sess.Sign(r.Context(), body.Name, msg)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"signature_b64": base64.StdEncoding.EncodeToString(sig),
		"algorithm":     alg,
	})
}

// getPublicKey (MCP tool) returns the public key of a managed signing key.
func (s *Server) getPublicKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	sess, ok := s.requireSession(w)
	if !ok {
		return
	}
	info, err := sess.GetKeyInfo(r.Context(), body.Name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if len(info.PublicKey) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key has no public key (not a signing key)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"key_type":       string(info.KeyType),
		"public_key_b64": base64.StdEncoding.EncodeToString(info.PublicKey),
	})
}
