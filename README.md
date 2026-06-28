# kmip-gateway

A KMIP 2.1 front-end for the Privasys vHSM, run as a confidential container-app.

KMIP clients (enterprise key-management tooling, storage arrays, databases) connect
over TLS and speak the standard KMIP TTLV protocol. The gateway translates each
operation to the Privasys vault constellation over **RA-TLS**, so the platform
control plane is never in the key data path. Because the gateway itself runs inside
a TEE as an attested container-app, the whole chain stays confidential.

This is the standard-skin / novel-core pattern: a familiar KMIP interface in front
of the attested-policy vault core. Key material is created and used **in-enclave**;
the gateway never sees plaintext keys.

## Layout

- `main.go` — config (env) + session bootstrap; the KMIP TTLV listener.
- `internal/vault/` — the translation layer to the vault constellation: dials the
  vaults directly over RA-TLS and exposes the in-enclave operations the KMIP
  front-end needs (wrap/unwrap, sign, key info, destroy).

## Configuration

| Env | Meaning |
| --- | --- |
| `KMIP_VAULT_ID` | the vault this gateway fronts (handles are `vaults/<id>/<name>`) |
| `KMIP_VAULT_ENDPOINTS` | comma-separated constellation endpoints (`host:port`) |
| `KMIP_VAULT_MRENCLAVE` | vault MRENCLAVE pin (hex) |
| `KMIP_ATTESTATION_SERVER` | attestation server verify endpoint |
| `KMIP_ATTESTATION_TOKEN` | bearer for quote verification (`aud=attestation-server`) |
| `KMIP_OWNER_TOKEN` | the vault owner's OIDC bearer |
| `KMIP_LISTEN_ADDR` | KMIP listen address (default `0.0.0.0:5696`) |

## Build

The RA-TLS data-plane dial needs the Privasys Go fork (build with `-tags ratls`).
The vault SDK and RA-TLS client are vendored siblings under `platform/` via
`replace` directives in `go.mod`.

```
go build -tags ratls ./...
```

## Licence

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
