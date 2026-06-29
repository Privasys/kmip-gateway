// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command kmip-proxy is the local shim that lets standard KMIP tooling (PyKMIP,
// storage arrays) reach a Privasys kmip-gateway. It serves a local plain
// KMIP-over-TLS endpoint and re-originates each KMIP TTLV message to the gateway
// over a verified RA-TLS connection (POST /kmip).
//
//	kmip-proxy --gateway kmip-gateway.apps-test.privasys.org --listen 127.0.0.1:5696
//
// The shim is the adapter for KMIP clients that cannot verify enclave quotes: it
// does the attestation on their behalf. Unlike the platform's sealed-session
// relay (which exists for clients that genuinely cannot do RA-TLS, e.g.
// browsers), the shim is RA-TLS-capable, so it connects directly to the
// enclave's quote-bearing leaf and verifies the TDX quote before sending any
// KMIP data. The RA-TLS ALPN marker makes the platform gateway splice the
// connection through to the enclave (the enclave terminates TLS and serves the
// attestation leaf); a plain TLS client would instead land on the gateway's
// Let's Encrypt terminate path, which carries no quote.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	rc "enclave-os-mini/clients/go/ratls"
)

const kmipPath = "/kmip"

// verifier holds the settings the shim uses to attest the gateway enclave on
// each new client connection.
type verifier struct {
	host      string // enclave gateway FQDN (SNI + Host header)
	allowDev  bool
	insecure  bool
	attServer string
	attToken  string
}

func main() {
	gateway := flag.String("gateway", "", "gateway host or URL, e.g. kmip-gateway.apps-test.privasys.org")
	listen := flag.String("listen", "127.0.0.1:5696", "local KMIP TLS listen address")
	attServer := flag.String("attestation-server", "https://as.privasys.org/verify", "attestation server that verifies the gateway's TDX quote")
	attToken := flag.String("attestation-token", "", "bearer for the attestation server (aud=attestation-server); required unless --insecure")
	allowDev := flag.Bool("allow-dev", true, "accept dev-profile enclave images (m1-dev is a dev image)")
	insecure := flag.Bool("insecure", false, "skip the remote quote verification (still pins a genuine TDX quote in the leaf; dev only)")
	flag.Parse()
	if *gateway == "" {
		log.Fatal("kmip-proxy: --gateway is required")
	}

	host := hostFromGateway(*gateway)
	v := &verifier{host: host, allowDev: *allowDev, insecure: *insecure, attServer: *attServer, attToken: *attToken}
	if v.insecure {
		log.Printf("kmip-proxy: WARNING remote quote verification disabled (--insecure); the leaf must still carry a genuine TDX quote")
	} else {
		if v.attToken == "" {
			log.Fatal("kmip-proxy: --attestation-token is required (or pass --insecure)")
		}
		log.Printf("kmip-proxy: verifying the gateway enclave (TDX quote via %s)", v.attServer)
	}

	cert, err := selfSigned()
	if err != nil {
		log.Fatalf("kmip-proxy: local cert: %v", err)
	}
	ln, err := tls.Listen("tcp", *listen, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		log.Fatalf("kmip-proxy: listen %s: %v", *listen, err)
	}
	log.Printf("kmip-proxy: local KMIP TLS on %s -> %s (RA-TLS)", *listen, host)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("kmip-proxy: accept: %v", err)
			continue
		}
		go v.serve(c)
	}
}

// serve handles one local KMIP connection: it opens (and verifies) a fresh
// RA-TLS connection to the gateway, then relays each TTLV request to /kmip and
// writes the response back to the local client.
func (v *verifier) serve(c net.Conn) {
	defer c.Close()
	client, err := v.connect()
	if err != nil {
		log.Printf("kmip-proxy: gateway RA-TLS: %v", err)
		return
	}
	defer client.Close()
	for {
		msg, err := readTTLV(c)
		if err != nil {
			if err != io.EOF {
				log.Printf("kmip-proxy: read KMIP: %v", err)
			}
			return
		}
		resp, err := client.HTTPDo("POST", kmipPath, v.host, msg, "")
		if err != nil {
			log.Printf("kmip-proxy: relay: %v", err)
			return
		}
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			log.Printf("kmip-proxy: read gateway response: %v", rerr)
			return
		}
		if resp.StatusCode/100 != 2 {
			log.Printf("kmip-proxy: gateway %s: %s", resp.Status, strings.TrimSpace(string(body)))
			return
		}
		if _, err := c.Write(body); err != nil {
			return
		}
	}
}

// connect dials the gateway over RA-TLS and verifies its TDX quote before any
// KMIP data is sent. A fresh challenge nonce binds the quote's ReportData to
// this connection (anti-replay).
func (v *verifier) connect() (*rc.Client, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	client, err := rc.Connect(v.host, 443, &rc.Options{
		ServerName: v.host,
		Timeout:    60 * time.Second,
		Challenge:  nonce,
	})
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", v.host, err)
	}
	policy := &rc.VerificationPolicy{
		TEE:              rc.TeeTypeTDX,
		ReportData:       rc.ReportDataChallengeResponse,
		Nonce:            nonce,
		AllowDebugImages: v.allowDev,
	}
	if !v.insecure {
		policy.QuoteVerification = &rc.QuoteVerificationConfig{Endpoint: v.attServer, Token: v.attToken}
	}
	if _, err := client.VerifyCertificate(policy); err != nil {
		client.Close()
		return nil, fmt.Errorf("enclave attestation failed — refusing to relay KMIP: %w", err)
	}
	return client, nil
}

// hostFromGateway accepts either a bare host or a URL and returns the host
// (without scheme, port, or path).
func hostFromGateway(g string) string {
	g = strings.TrimSpace(g)
	if strings.Contains(g, "://") {
		if u, err := url.Parse(g); err == nil && u.Host != "" {
			g = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(g); err == nil {
		return h
	}
	return strings.TrimRight(g, "/")
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
