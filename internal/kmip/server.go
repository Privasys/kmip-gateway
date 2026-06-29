// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package kmip is the gateway's KMIP 2.1 wire front-end. It speaks the standard
// KMIP TTLV protocol (via github.com/gemalto/kmip-go) and dispatches each
// operation to the vault session, which performs it in-enclave over RA-TLS. The
// gateway translates KMIP nouns/verbs to the vHSM's: a KMIP UniqueIdentifier is
// the key name in the fronted vault; Encrypt/Decrypt map to AES-256-GCM
// wrap/unwrap; Sign maps to in-enclave ECDSA-P256.
package kmip

import (
	"bytes"
	"context"
	"fmt"
	"net"

	kmip "github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// Vault is the in-enclave key surface the KMIP front-end dispatches to. The
// concrete implementation is *vault.Session (dialing the constellation over
// RA-TLS); an interface keeps the wire layer testable.
type Vault interface {
	Create(ctx context.Context, name, keyType string, exportable bool) (string, error)
	Wrap(ctx context.Context, name string, plaintext []byte) (ct, iv []byte, err error)
	Unwrap(ctx context.Context, name string, ciphertext, iv []byte) ([]byte, error)
	Sign(ctx context.Context, name string, message []byte) (sig []byte, alg string, err error)
	GetKeyInfo(ctx context.Context, name string) (vsdk.KeyInfo, error)
	Destroy(ctx context.Context, name string) error
}

// Server is a KMIP TTLV server fronting one vault session.
type Server struct {
	sess Vault
	srv  kmip.Server
}

// New builds a KMIP server that dispatches to sess.
func New(sess Vault) *Server {
	s := &Server{sess: sess}
	mux := &kmip.OperationMux{}
	mux.Handle(kmip14.OperationDiscoverVersions, &kmip.DiscoverVersionsHandler{
		SupportedVersions: []kmip.ProtocolVersion{
			{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4},
			{ProtocolVersionMajor: 1, ProtocolVersionMinor: 3},
			{ProtocolVersionMajor: 1, ProtocolVersionMinor: 2},
		},
	})
	mux.Handle(kmip14.OperationCreate, kmip.ItemHandlerFunc(s.handleCreate))
	mux.Handle(kmip14.OperationDestroy, &kmip.DestroyHandler{Destroy: s.handleDestroy})
	mux.Handle(kmip14.OperationEncrypt, kmip.ItemHandlerFunc(s.handleEncrypt))
	mux.Handle(kmip14.OperationDecrypt, kmip.ItemHandlerFunc(s.handleDecrypt))
	mux.Handle(kmip14.OperationSign, kmip.ItemHandlerFunc(s.handleSign))
	mux.Handle(kmip14.OperationGetAttributes, kmip.ItemHandlerFunc(s.handleGetAttributes))
	mux.Handle(kmip14.OperationLocate, kmip.ItemHandlerFunc(s.handleLocate))
	s.srv.Handler = &kmip.StandardProtocolHandler{
		MessageHandler:  mux,
		ProtocolVersion: kmip.ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4},
	}
	return s
}

// Serve accepts KMIP connections on l until the listener is closed.
func (s *Server) Serve(l net.Listener) error { return s.srv.Serve(l) }

// HandleMessage runs one KMIP TTLV request message through the operation mux and
// returns the TTLV response message. This is the sealed-session transport: the
// gateway is reached over HTTP (POST /kmip) through the platform's session relay,
// so there is no gateway-managed TLS — attestation and confidentiality come from
// the sealed session (the same mechanism the platform uses for browser SDKs).
func (s *Server) HandleMessage(ctx context.Context, reqTTLV []byte) []byte {
	req := &kmip.Request{TTLV: ttlv.TTLV(reqTTLV)}
	var buf bytes.Buffer
	s.srv.Handler.ServeKMIP(ctx, req, &buf)
	return buf.Bytes()
}

// fail attaches a KMIP result reason to an error so the protocol handler maps it
// to a proper failure batch item (a reason-less error would panic the handler).
func fail(reason kmip14.ResultReason, format string, args ...interface{}) error {
	return kmip.WithResultReason(fmt.Errorf(format, args...), reason)
}

// ---- Create ----------------------------------------------------------------

// handleCreate generates a managed key in-enclave. The KMIP CryptographicAlgorithm
// (or ObjectType) selects the vault key type: AES-256-GCM for symmetric keys,
// ECDSA-P256 for asymmetric/private keys. The returned UniqueIdentifier is the
// key name.
func (s *Server) handleCreate(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var p kmip.CreateRequestPayload
	if err := req.DecodePayload(&p); err != nil {
		return nil, fail(kmip14.ResultReasonInvalidField, "decode create: %v", err)
	}
	keyType, err := keyTypeFor(&p)
	if err != nil {
		return nil, err
	}
	name := requestedName(&p.TemplateAttribute)
	if name == "" {
		name = generateName(keyType)
	}
	if _, err := s.sess.Create(ctx, name, keyType, false); err != nil {
		return nil, fail(kmip14.ResultReasonGeneralFailure, "create %q: %v", name, err)
	}
	req.IDPlaceholder = name
	return &kmip.ResponseBatchItem{ResponsePayload: &kmip.CreateResponsePayload{
		ObjectType:       p.ObjectType,
		UniqueIdentifier: name,
	}}, nil
}

// ---- Destroy ---------------------------------------------------------------

func (s *Server) handleDestroy(ctx context.Context, p *kmip.DestroyRequestPayload) (*kmip.DestroyResponsePayload, error) {
	if p.UniqueIdentifier == "" {
		return nil, fail(kmip14.ResultReasonInvalidField, "destroy: missing unique identifier")
	}
	if err := s.sess.Destroy(ctx, p.UniqueIdentifier); err != nil {
		return nil, fail(kmip14.ResultReasonGeneralFailure, "destroy %q: %v", p.UniqueIdentifier, err)
	}
	return &kmip.DestroyResponsePayload{UniqueIdentifier: p.UniqueIdentifier}, nil
}

// ---- Encrypt / Decrypt (AES-256-GCM wrap/unwrap) ---------------------------

// EncryptRequestPayload is the 4.29 request (subset the gateway honours).
type EncryptRequestPayload struct {
	UniqueIdentifier        string
	CryptographicParameters *kmip.CryptographicParameters `ttlv:",omitempty"`
	Data                    []byte
	IVCounterNonce          []byte `ttlv:",omitempty"`
}

// EncryptResponsePayload returns the ciphertext and the vault-chosen GCM IV.
type EncryptResponsePayload struct {
	UniqueIdentifier string
	Data             []byte
	IVCounterNonce   []byte `ttlv:",omitempty"`
}

func (s *Server) handleEncrypt(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var p EncryptRequestPayload
	if err := req.DecodePayload(&p); err != nil {
		return nil, fail(kmip14.ResultReasonInvalidField, "decode encrypt: %v", err)
	}
	if p.UniqueIdentifier == "" {
		return nil, fail(kmip14.ResultReasonInvalidField, "encrypt: missing unique identifier")
	}
	ct, iv, err := s.sess.Wrap(ctx, p.UniqueIdentifier, p.Data)
	if err != nil {
		return nil, fail(kmip14.ResultReasonGeneralFailure, "encrypt %q: %v", p.UniqueIdentifier, err)
	}
	return &kmip.ResponseBatchItem{ResponsePayload: &EncryptResponsePayload{
		UniqueIdentifier: p.UniqueIdentifier, Data: ct, IVCounterNonce: iv,
	}}, nil
}

// DecryptRequestPayload is the 4.30 request (subset the gateway honours).
type DecryptRequestPayload struct {
	UniqueIdentifier        string
	CryptographicParameters *kmip.CryptographicParameters `ttlv:",omitempty"`
	Data                    []byte
	IVCounterNonce          []byte `ttlv:",omitempty"`
}

// DecryptResponsePayload returns the recovered plaintext.
type DecryptResponsePayload struct {
	UniqueIdentifier string
	Data             []byte
}

func (s *Server) handleDecrypt(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var p DecryptRequestPayload
	if err := req.DecodePayload(&p); err != nil {
		return nil, fail(kmip14.ResultReasonInvalidField, "decode decrypt: %v", err)
	}
	if p.UniqueIdentifier == "" {
		return nil, fail(kmip14.ResultReasonInvalidField, "decrypt: missing unique identifier")
	}
	if len(p.IVCounterNonce) == 0 {
		return nil, fail(kmip14.ResultReasonInvalidField, "decrypt %q: missing IV/Counter/Nonce", p.UniqueIdentifier)
	}
	pt, err := s.sess.Unwrap(ctx, p.UniqueIdentifier, p.Data, p.IVCounterNonce)
	if err != nil {
		return nil, fail(kmip14.ResultReasonGeneralFailure, "decrypt %q: %v", p.UniqueIdentifier, err)
	}
	return &kmip.ResponseBatchItem{ResponsePayload: &DecryptResponsePayload{
		UniqueIdentifier: p.UniqueIdentifier, Data: pt,
	}}, nil
}

// ---- Sign (in-enclave ECDSA-P256) ------------------------------------------

// SignRequestPayload is the 4.31 request (subset the gateway honours).
type SignRequestPayload struct {
	UniqueIdentifier        string
	CryptographicParameters *kmip.CryptographicParameters `ttlv:",omitempty"`
	Data                    []byte
}

// SignResponsePayload returns the signature.
type SignResponsePayload struct {
	UniqueIdentifier string
	SignatureData    []byte
}

func (s *Server) handleSign(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var p SignRequestPayload
	if err := req.DecodePayload(&p); err != nil {
		return nil, fail(kmip14.ResultReasonInvalidField, "decode sign: %v", err)
	}
	if p.UniqueIdentifier == "" {
		return nil, fail(kmip14.ResultReasonInvalidField, "sign: missing unique identifier")
	}
	sig, _, err := s.sess.Sign(ctx, p.UniqueIdentifier, p.Data)
	if err != nil {
		return nil, fail(kmip14.ResultReasonGeneralFailure, "sign %q: %v", p.UniqueIdentifier, err)
	}
	return &kmip.ResponseBatchItem{ResponsePayload: &SignResponsePayload{
		UniqueIdentifier: p.UniqueIdentifier, SignatureData: sig,
	}}, nil
}

// ---- GetAttributes ---------------------------------------------------------

// GetAttributesRequestPayload is the 4.12 request (subset the gateway honours).
type GetAttributesRequestPayload struct {
	UniqueIdentifier string
	AttributeName    []string `ttlv:",omitempty"`
}

// GetAttributesResponsePayload returns the requested (or all known) attributes.
type GetAttributesResponsePayload struct {
	UniqueIdentifier string
	Attribute        []kmip.Attribute `ttlv:",omitempty"`
}

func (s *Server) handleGetAttributes(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var p GetAttributesRequestPayload
	if err := req.DecodePayload(&p); err != nil {
		return nil, fail(kmip14.ResultReasonInvalidField, "decode get-attributes: %v", err)
	}
	if p.UniqueIdentifier == "" {
		return nil, fail(kmip14.ResultReasonInvalidField, "get-attributes: missing unique identifier")
	}
	info, err := s.sess.GetKeyInfo(ctx, p.UniqueIdentifier)
	if err != nil {
		return nil, fail(kmip14.ResultReasonItemNotFound, "get-attributes %q: %v", p.UniqueIdentifier, err)
	}
	objType, alg := kmipTypeFor(info.KeyType)
	attrs := []kmip.Attribute{
		kmip.NewAttributeFromTag(kmip14.TagObjectType, 0, objType),
		kmip.NewAttributeFromTag(kmip14.TagCryptographicAlgorithm, 0, alg),
	}
	return &kmip.ResponseBatchItem{ResponsePayload: &GetAttributesResponsePayload{
		UniqueIdentifier: p.UniqueIdentifier, Attribute: filterAttributes(attrs, p.AttributeName),
	}}, nil
}

// ---- Locate ----------------------------------------------------------------

// LocateRequestPayload is the 4.9 request (subset: the gateway matches on Name).
type LocateRequestPayload struct {
	Attribute []kmip.Attribute `ttlv:",omitempty"`
}

// LocateResponsePayload returns the matching unique identifiers.
type LocateResponsePayload struct {
	UniqueIdentifier []string `ttlv:",omitempty"`
}

// handleLocate resolves a Name attribute to its unique identifier (the name).
// The catalogue is authoritative server-side; using an unknown UID later fails
// in-enclave. A richer Locate (list + filter) is a follow-up.
func (s *Server) handleLocate(_ context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var p LocateRequestPayload
	if err := req.DecodePayload(&p); err != nil {
		return nil, fail(kmip14.ResultReasonInvalidField, "decode locate: %v", err)
	}
	var ids []string
	if name := nameFromAttributes(p.Attribute); name != "" {
		ids = append(ids, name)
	}
	return &kmip.ResponseBatchItem{ResponsePayload: &LocateResponsePayload{UniqueIdentifier: ids}}, nil
}
