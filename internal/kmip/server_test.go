// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package kmip

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	kmip "github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
	"github.com/google/uuid"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// fakeVault stands in for the enclave: it does real AES-256-GCM so Encrypt then
// Decrypt round-trips, tracks created keys, and reports key info. It exercises
// the KMIP wire encode/decode of every payload without a vault constellation.
type fakeVault struct {
	mu   sync.Mutex
	keys map[string]vsdk.KeyType
}

func newFakeVault() *fakeVault { return &fakeVault{keys: map[string]vsdk.KeyType{}} }

func (f *fakeVault) Create(_ context.Context, name, keyType string, _ bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch keyType {
	case "aes":
		f.keys[name] = vsdk.Aes256GcmKey
	case "p256":
		f.keys[name] = vsdk.P256SigningKey
	default:
		return "", fmt.Errorf("unsupported key type %q", keyType)
	}
	return "vaults/test/" + name, nil
}

// deterministic per-name AES key so wrap/unwrap pair up within the test.
func (f *fakeVault) keyBytes(name string) []byte {
	k := make([]byte, 32)
	copy(k, []byte("kmip-gateway-test-key-"+name))
	return k
}

func (f *fakeVault) Wrap(_ context.Context, name string, plaintext []byte) ([]byte, []byte, error) {
	f.mu.Lock()
	_, ok := f.keys[name]
	f.mu.Unlock()
	if !ok {
		return nil, nil, fmt.Errorf("not found: %s", name)
	}
	block, _ := aes.NewCipher(f.keyBytes(name))
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, iv, plaintext, nil), iv, nil
}

func (f *fakeVault) Unwrap(_ context.Context, name string, ct, iv []byte) ([]byte, error) {
	block, _ := aes.NewCipher(f.keyBytes(name))
	gcm, _ := cipher.NewGCM(block)
	return gcm.Open(nil, iv, ct, nil)
}

func (f *fakeVault) Sign(_ context.Context, name string, message []byte) ([]byte, string, error) {
	f.mu.Lock()
	_, ok := f.keys[name]
	f.mu.Unlock()
	if !ok {
		return nil, "", fmt.Errorf("not found: %s", name)
	}
	// not a real signature; the test only checks the wire carries the bytes.
	return append([]byte("sig:"), message...), "ECDSA_SHA256", nil
}

func (f *fakeVault) GetKeyInfo(_ context.Context, name string) (vsdk.KeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kt, ok := f.keys[name]
	if !ok {
		return vsdk.KeyInfo{}, fmt.Errorf("not found: %s", name)
	}
	return vsdk.KeyInfo{KeyType: kt}, nil
}

func (f *fakeVault) Destroy(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, name)
	return nil
}

// startServer spins the KMIP server on a loopback port and returns its address.
func startServer(t *testing.T, v Vault) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := New(v)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().String()
}

// roundTrip sends one batch item and returns the decoded response batch item.
func roundTrip(t *testing.T, addr string, op kmip14.Operation, payload interface{}) kmip.ResponseBatchItem {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	id := uuid.New()
	msg := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4},
			BatchCount:      1,
		},
		BatchItem: []kmip.RequestBatchItem{{
			UniqueBatchItemID: id[:],
			Operation:         op,
			RequestPayload:    payload,
		}},
	}
	req, err := ttlv.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	dec := ttlv.NewDecoder(conn)
	resp, err := dec.NextTTLV()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var rm kmip.ResponseMessage
	if err := ttlv.Unmarshal(resp, &rm); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(rm.BatchItem) != 1 {
		t.Fatalf("expected 1 batch item, got %d", len(rm.BatchItem))
	}
	return rm.BatchItem[0]
}

func mustSucceed(t *testing.T, bi kmip.ResponseBatchItem, op string) {
	t.Helper()
	if bi.ResultStatus != kmip14.ResultStatusSuccess {
		t.Fatalf("%s failed: status=%v reason=%v msg=%q", op, bi.ResultStatus, bi.ResultReason, bi.ResultMessage)
	}
}

func TestKMIPWireRoundTrips(t *testing.T) {
	addr := startServer(t, newFakeVault())

	// DiscoverVersions
	{
		bi := roundTrip(t, addr, kmip14.OperationDiscoverVersions, kmip.DiscoverVersionsRequestPayload{})
		mustSucceed(t, bi, "DiscoverVersions")
		var p kmip.DiscoverVersionsResponsePayload
		decodePayload(t, bi, &p)
		if len(p.ProtocolVersion) == 0 {
			t.Fatal("DiscoverVersions returned no versions")
		}
	}

	// Create AES symmetric key
	aesName := "wrap-key"
	{
		ta := kmip.TemplateAttribute{}
		ta.Append(kmip14.TagName, kmip.Name{NameValue: aesName, NameType: kmip14.NameTypeUninterpretedTextString})
		bi := roundTrip(t, addr, kmip14.OperationCreate, kmip.CreateRequestPayload{
			ObjectType: kmip14.ObjectTypeSymmetricKey, TemplateAttribute: ta,
		})
		mustSucceed(t, bi, "Create(AES)")
		var p kmip.CreateResponsePayload
		decodePayload(t, bi, &p)
		if p.UniqueIdentifier != aesName {
			t.Fatalf("Create UID = %q, want %q", p.UniqueIdentifier, aesName)
		}
	}

	// Encrypt then Decrypt round-trips the plaintext
	plaintext := []byte("the platform never sees this")
	var ciphertext, iv []byte
	{
		bi := roundTrip(t, addr, kmip14.OperationEncrypt, EncryptRequestPayload{
			UniqueIdentifier: aesName, Data: plaintext,
		})
		mustSucceed(t, bi, "Encrypt")
		var p EncryptResponsePayload
		decodePayload(t, bi, &p)
		if len(p.Data) == 0 || len(p.IVCounterNonce) == 0 {
			t.Fatalf("Encrypt returned empty ciphertext/iv")
		}
		ciphertext, iv = p.Data, p.IVCounterNonce
	}
	{
		bi := roundTrip(t, addr, kmip14.OperationDecrypt, DecryptRequestPayload{
			UniqueIdentifier: aesName, Data: ciphertext, IVCounterNonce: iv,
		})
		mustSucceed(t, bi, "Decrypt")
		var p DecryptResponsePayload
		decodePayload(t, bi, &p)
		if string(p.Data) != string(plaintext) {
			t.Fatalf("Decrypt = %q, want %q", p.Data, plaintext)
		}
	}

	// Create P-256 signing key + Sign
	signName := "sign-key"
	{
		ta := kmip.TemplateAttribute{}
		ta.Append(kmip14.TagName, kmip.Name{NameValue: signName, NameType: kmip14.NameTypeUninterpretedTextString})
		bi := roundTrip(t, addr, kmip14.OperationCreate, kmip.CreateRequestPayload{
			ObjectType: kmip14.ObjectTypePrivateKey, TemplateAttribute: ta,
		})
		mustSucceed(t, bi, "Create(P256)")
	}
	{
		bi := roundTrip(t, addr, kmip14.OperationSign, SignRequestPayload{
			UniqueIdentifier: signName, Data: []byte("digest-or-message"),
		})
		mustSucceed(t, bi, "Sign")
		var p SignResponsePayload
		decodePayload(t, bi, &p)
		if len(p.SignatureData) == 0 {
			t.Fatal("Sign returned empty signature")
		}
	}

	// GetAttributes reports the key's object type + algorithm
	{
		bi := roundTrip(t, addr, kmip14.OperationGetAttributes, GetAttributesRequestPayload{
			UniqueIdentifier: aesName,
		})
		mustSucceed(t, bi, "GetAttributes")
		var p GetAttributesResponsePayload
		decodePayload(t, bi, &p)
		if len(p.Attribute) == 0 {
			t.Fatal("GetAttributes returned no attributes")
		}
	}

	// Locate by Name echoes the unique identifier
	{
		ta := []kmip.Attribute{kmip.NewAttributeFromTag(kmip14.TagName, 0,
			kmip.Name{NameValue: aesName, NameType: kmip14.NameTypeUninterpretedTextString})}
		bi := roundTrip(t, addr, kmip14.OperationLocate, LocateRequestPayload{Attribute: ta})
		mustSucceed(t, bi, "Locate")
		var p LocateResponsePayload
		decodePayload(t, bi, &p)
		if len(p.UniqueIdentifier) != 1 || p.UniqueIdentifier[0] != aesName {
			t.Fatalf("Locate = %v, want [%s]", p.UniqueIdentifier, aesName)
		}
	}

	// Destroy removes the key
	{
		bi := roundTrip(t, addr, kmip14.OperationDestroy, kmip.DestroyRequestPayload{UniqueIdentifier: aesName})
		mustSucceed(t, bi, "Destroy")
	}
	// Encrypt after Destroy fails
	{
		bi := roundTrip(t, addr, kmip14.OperationEncrypt, EncryptRequestPayload{
			UniqueIdentifier: aesName, Data: plaintext,
		})
		if bi.ResultStatus == kmip14.ResultStatusSuccess {
			t.Fatal("Encrypt succeeded after Destroy")
		}
	}
}

func decodePayload(t *testing.T, bi kmip.ResponseBatchItem, into interface{}) {
	t.Helper()
	raw, ok := bi.ResponsePayload.(ttlv.TTLV)
	if !ok {
		t.Fatalf("response payload is %T, want ttlv.TTLV", bi.ResponsePayload)
	}
	if err := ttlv.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
}
