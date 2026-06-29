// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"time"
)

// kmipTLSConfig builds the server TLS config for the KMIP listener. KMIP clients
// connect over TLS, so the listener always serves TLS: a provided certificate
// (KMIP_TLS_CERT/KMIP_TLS_KEY) is used when set, otherwise a self-signed one is
// generated at startup and its fingerprint logged so a client can pin it. Client
// certificates are requested (for future per-client identity mapping) but not
// required.
func kmipTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	var (
		cert tls.Certificate
		err  error
	)
	if certPath != "" && keyPath != "" {
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load KMIP TLS certificate: %w", err)
		}
		log.Printf("kmip-gateway: KMIP TLS using provided certificate %s", certPath)
	} else {
		cert, err = selfSignedKMIPCert()
		if err != nil {
			return nil, err
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert,
	}, nil
}

// selfSignedKMIPCert generates an ephemeral self-signed P-256 server certificate
// for the KMIP listener and logs its SHA-256 fingerprint. For a stable identity,
// provide KMIP_TLS_CERT/KMIP_TLS_KEY instead.
func selfSignedKMIPCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate KMIP TLS key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "kmip-gateway"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"kmip-gateway"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create KMIP TLS certificate: %w", err)
	}
	sum := sha256.Sum256(der)
	log.Printf("kmip-gateway: KMIP TLS using a self-signed certificate (sha256 %s); set KMIP_TLS_CERT/KMIP_TLS_KEY for a stable certificate",
		hex.EncodeToString(sum[:]))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
