// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command kmip-proxy is the local shim that lets standard KMIP tooling (PyKMIP,
// storage arrays) reach a Privasys kmip-gateway. It serves a local plain
// KMIP-over-TLS endpoint, establishes the platform's sealed session to the
// gateway (the attested, confidential channel), and relays each KMIP TTLV
// message as a sealed POST /kmip. The shim is the adapter for clients that can't
// verify enclave quotes: it does the attestation on their behalf.
//
//	kmip-proxy --gateway https://kmip-gateway.apps-test.privasys.org --listen 127.0.0.1:5696
//
// The standard KMIP client points at the --listen address; the shim carries the
// traffic to the gateway over the sealed session.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	bootstrapPath = "/__privasys/session-bootstrap"
	kmipPath      = "/kmip"
	hkdfInfo      = "privasys-session/v1"
	dirInfoC2S    = "privasys-dir/c2s"
	dirInfoS2C    = "privasys-dir/s2c"
	sealedCType   = "application/privasys-sealed+cbor"
)

func main() {
	gateway := flag.String("gateway", "", "gateway base URL, e.g. https://kmip-gateway.apps-test.privasys.org")
	listen := flag.String("listen", "127.0.0.1:5696", "local KMIP TLS listen address")
	insecure := flag.Bool("insecure", false, "skip TLS verification of the gateway (dev; the sealed session still provides confidentiality)")
	flag.Parse()
	if *gateway == "" {
		log.Fatal("kmip-proxy: --gateway is required")
	}

	cert, err := selfSigned()
	if err != nil {
		log.Fatalf("kmip-proxy: local cert: %v", err)
	}
	ln, err := tls.Listen("tcp", *listen, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		log.Fatalf("kmip-proxy: listen %s: %v", *listen, err)
	}
	log.Printf("kmip-proxy: local KMIP TLS on %s -> %s (sealed session)", *listen, *gateway)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("kmip-proxy: accept: %v", err)
			continue
		}
		go serve(c, strings.TrimRight(*gateway, "/"), *insecure)
	}
}

// serve handles one local KMIP connection: it opens a fresh sealed session and
// relays each TTLV message to the gateway.
func serve(c net.Conn, gateway string, insecure bool) {
	defer c.Close()
	sess, err := newSession(gateway, insecure)
	if err != nil {
		log.Printf("kmip-proxy: sealed session: %v", err)
		return
	}
	for {
		msg, err := readTTLV(c)
		if err != nil {
			if err != io.EOF {
				log.Printf("kmip-proxy: read KMIP: %v", err)
			}
			return
		}
		resp, err := sess.relay(msg)
		if err != nil {
			log.Printf("kmip-proxy: relay: %v", err)
			return
		}
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}

// readTTLV reads one KMIP TTLV message: a 3-byte tag, 1-byte type, 4-byte
// big-endian length, then that many value bytes.
func readTTLV(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[4:8])
	if n > 16*1024*1024 {
		return nil, fmt.Errorf("KMIP message too large (%d bytes)", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// session is a sealed session to the gateway.
type session struct {
	gateway   string
	hc        *http.Client
	id        string
	aead      cipher.AEAD
	c2sPrefix [4]byte
	s2cPrefix [4]byte

	mu     sync.Mutex
	c2sCtr uint64
}

func newSession(gateway string, insecure bool) (*session, error) {
	hc := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}},
	}

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{
		"sdk_pub": base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
	})
	resp, err := hc.Post(gateway+bootstrapPath, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("bootstrap %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var br struct {
		SessionID string `json:"session_id"`
		EncPub    string `json:"enc_pub"`
	}
	if err := json.Unmarshal(data, &br); err != nil {
		return nil, fmt.Errorf("bootstrap decode: %w", err)
	}
	encPubRaw, err := base64.RawURLEncoding.DecodeString(br.EncPub)
	if err != nil {
		return nil, fmt.Errorf("enc_pub: %w", err)
	}
	encPub, err := ecdh.P256().NewPublicKey(encPubRaw)
	if err != nil {
		return nil, fmt.Errorf("enc_pub key: %w", err)
	}
	shared, err := priv.ECDH(encPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	salt, err := base64.RawURLEncoding.DecodeString(br.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session_id: %w", err)
	}
	aeadKey := hkdf(shared, salt, []byte(hkdfInfo), 32)
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &session{gateway: gateway, hc: hc, id: br.SessionID, aead: gcm}
	copy(s.c2sPrefix[:], hkdf(shared, salt, []byte(dirInfoC2S), 4))
	copy(s.s2cPrefix[:], hkdf(shared, salt, []byte(dirInfoS2C), 4))
	return s, nil
}

// relay seals one KMIP message, POSTs it to /kmip, and returns the unsealed
// response.
func (s *session) relay(msg []byte) ([]byte, error) {
	s.mu.Lock()
	ctr := s.c2sCtr
	s.c2sCtr++
	s.mu.Unlock()

	ad := []byte("POST:" + kmipPath + ":" + s.id)
	ct := s.aead.Seal(nil, makeNonce(s.c2sPrefix[:], ctr), msg, ad)
	sealed := encodeSealed(1, ctr, ct)

	req, err := http.NewRequest(http.MethodPost, s.gateway+kmipPath, bytes.NewReader(sealed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", sealedCType)
	req.Header.Set("Authorization", "PrivasysSession "+s.id)
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("kmip %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	// The relay may seal the response either as a single envelope or as a stream
	// of length-prefixed frames ([4-byte big-endian length][CBOR envelope]...),
	// each with its own s2c counter. Handle both; concatenate the plaintexts.
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/privasys-sealed-stream+cbor") {
		var out []byte
		for off := 0; off+4 <= len(data); {
			flen := int(binary.BigEndian.Uint32(data[off : off+4]))
			off += 4
			if flen == 0 || off+flen > len(data) {
				break
			}
			rctr, rct, derr := decodeSealed(data[off : off+flen])
			if derr != nil {
				return nil, fmt.Errorf("decode sealed frame: %w", derr)
			}
			off += flen
			pt, oerr := s.aead.Open(nil, makeNonce(s.s2cPrefix[:], rctr), rct, ad)
			if oerr != nil {
				return nil, fmt.Errorf("open sealed frame: %w", oerr)
			}
			out = append(out, pt...)
		}
		return out, nil
	}
	rctr, rct, err := decodeSealed(data)
	if err != nil {
		return nil, fmt.Errorf("decode sealed response: %w", err)
	}
	return s.aead.Open(nil, makeNonce(s.s2cPrefix[:], rctr), rct, ad)
}

func makeNonce(prefix []byte, ctr uint64) []byte {
	n := make([]byte, 12)
	copy(n[:4], prefix[:4])
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// hkdf is HKDF-SHA256 (extract + expand), matching the enclave's derivation.
func hkdf(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)
	out := make([]byte, 0, length)
	var t []byte
	var counter byte = 1
	for len(out) < length {
		mac = hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

// encodeSealed/decodeSealed mirror the enclave's manual CBOR map(3){v,ctr,ct}.
func encodeSealed(v, ctr uint64, ct []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0xa3)
	cborText(&buf, "v")
	cborUint(&buf, v)
	cborText(&buf, "ctr")
	cborUint(&buf, ctr)
	cborText(&buf, "ct")
	cborBytes(&buf, ct)
	return buf.Bytes()
}

func decodeSealed(in []byte) (ctr uint64, ct []byte, err error) {
	if len(in) == 0 || in[0] != 0xa3 {
		return 0, nil, fmt.Errorf("expected map(3)")
	}
	off := 1
	for i := 0; i < 3; i++ {
		key, n, e := readCborText(in, off)
		if e != nil {
			return 0, nil, e
		}
		off = n
		switch key {
		case "v":
			_, off, err = readCborUint(in, off)
		case "ctr":
			ctr, off, err = readCborUint(in, off)
		case "ct":
			ct, off, err = readCborBytes(in, off)
		default:
			return 0, nil, fmt.Errorf("unexpected key %q", key)
		}
		if err != nil {
			return 0, nil, err
		}
	}
	return ctr, ct, nil
}

func cborText(buf *bytes.Buffer, s string) {
	cborHead(buf, 0x60, uint64(len(s)))
	buf.WriteString(s)
}
func cborBytes(buf *bytes.Buffer, b []byte) {
	cborHead(buf, 0x40, uint64(len(b)))
	buf.Write(b)
}
func cborUint(buf *bytes.Buffer, v uint64) { cborHead(buf, 0x00, v) }

func cborHead(buf *bytes.Buffer, major byte, n uint64) {
	switch {
	case n < 24:
		buf.WriteByte(major | byte(n))
	case n < 1<<8:
		buf.WriteByte(major | 24)
		buf.WriteByte(byte(n))
	case n < 1<<16:
		buf.WriteByte(major | 25)
		_ = binary.Write(buf, binary.BigEndian, uint16(n))
	case n < 1<<32:
		buf.WriteByte(major | 26)
		_ = binary.Write(buf, binary.BigEndian, uint32(n))
	default:
		buf.WriteByte(major | 27)
		_ = binary.Write(buf, binary.BigEndian, n)
	}
}

func readCborUint(in []byte, off int) (uint64, int, error) {
	if off >= len(in) {
		return 0, off, fmt.Errorf("truncated uint")
	}
	b := in[off]
	if b>>5 != 0 {
		return 0, off, fmt.Errorf("not a uint")
	}
	return readArg(in, off, b&0x1f)
}

func readCborText(in []byte, off int) (string, int, error) {
	if off >= len(in) || in[off]>>5 != 3 {
		return "", off, fmt.Errorf("not a text string")
	}
	n, off, err := readArg(in, off, in[off]&0x1f)
	if err != nil {
		return "", off, err
	}
	if off+int(n) > len(in) {
		return "", off, fmt.Errorf("truncated text")
	}
	return string(in[off : off+int(n)]), off + int(n), nil
}

func readCborBytes(in []byte, off int) ([]byte, int, error) {
	if off >= len(in) || in[off]>>5 != 2 {
		return nil, off, fmt.Errorf("not a byte string")
	}
	n, off, err := readArg(in, off, in[off]&0x1f)
	if err != nil {
		return nil, off, err
	}
	if off+int(n) > len(in) {
		return nil, off, fmt.Errorf("truncated bytes")
	}
	return in[off : off+int(n)], off + int(n), nil
}

func readArg(in []byte, off int, ai byte) (uint64, int, error) {
	off++
	switch {
	case ai < 24:
		return uint64(ai), off, nil
	case ai == 24:
		return uint64(in[off]), off + 1, nil
	case ai == 25:
		return uint64(binary.BigEndian.Uint16(in[off:])), off + 2, nil
	case ai == 26:
		return uint64(binary.BigEndian.Uint32(in[off:])), off + 4, nil
	case ai == 27:
		return binary.BigEndian.Uint64(in[off:]), off + 8, nil
	}
	return 0, off, fmt.Errorf("bad arg %d", ai)
}

// selfSigned mints a local TLS cert for the shim's KMIP listener. The standard
// KMIP client trusts this locally (it is talking to localhost).
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "kmip-proxy"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "kmip-proxy"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
