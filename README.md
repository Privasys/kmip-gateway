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

- `main.go` — config (env) + session bootstrap; starts the KMIP TTLV listener and
  the HTTP surface.
- `internal/vault/` — the translation layer to the vault constellation: dials the
  vaults directly over RA-TLS and exposes the in-enclave operations the KMIP
  front-end needs (wrap/unwrap, sign, key info, destroy), plus key creation.
- `internal/platform/` — the control-plane client: asks management-service to
  author each key's policy, catalogue it, and mint a holder-of-key grant. The
  platform never sees key material.
- `internal/kmip/` — the KMIP 2.1 TTLV front-end (over `gemalto/kmip-go`) that
  routes each operation to the vault session.
- `internal/control/` — a small HTTP surface: the manager's health probe and a
  few management operations exposed as MCP tools (see `privasys.json`).

## App identity and the vault

The gateway runs as a Privasys confidential container-app, so it has its own
attested identity: a per-app RA-TLS leaf carrying the app id (OID 3.6) and a
measured image (OID 3.2). Point it at that leaf (`KMIP_CLIENT_CERT` /
`KMIP_CLIENT_KEY`) and it authenticates to the vault **as the app**: keys it
creates bind to its stable certificate thumbprint (and, with an app-id-owner
policy, to MR_APP), so no long-lived owner bearer sits in the key data path. When
no leaf is configured it falls back to an owner bearer plus an ephemeral
holder-of-key certificate.

## Surfaces

- **KMIP TTLV** on `KMIP_LISTEN_ADDR` (default `:5696`) for KMIP clients.
- **HTTP** on `$PORT` (the manager-injected app port, default `:8080`):
  `GET /health`, `GET /version`, and the MCP tools (`POST /keys`, `POST /sign`,
  `POST /public`).

## Configuration

| Env | Meaning |
| --- | --- |
| `KMIP_VAULT_ID` | the vault this gateway fronts (handles are `vaults/<id>/<name>`) |
| `KMIP_VAULT_ENDPOINTS` | comma-separated constellation endpoints (`host:port`) |
| `KMIP_VAULT_MRENCLAVE` | vault MRENCLAVE pin (hex) |
| `KMIP_ATTESTATION_SERVER` | attestation server verify endpoint |
| `KMIP_ATTESTATION_TOKEN` | bearer for quote verification (`aud=attestation-server`) |
| `KMIP_MGMT_URL` | management-service origin (enables key creation via minted grants) |
| `KMIP_OWNER_TOKEN` | the vault owner's OIDC bearer (fallback when no app leaf) |
| `KMIP_CLIENT_CERT` / `KMIP_CLIENT_KEY` | the app RA-TLS leaf (cert / key) to authenticate to the vault as the app |
| `KMIP_LISTEN_ADDR` | KMIP listen address (default `0.0.0.0:5696`) |
| `PORT` | HTTP surface port, injected by the manager (default `8080`) |

## Built with

- [github.com/gemalto/kmip-go](https://github.com/ThalesGroup/kmip-go) — KMIP TTLV
  marshalling and the protocol server the front-end is built on (Apache 2.0).
- [Privasys/enclave-vaults-client](https://github.com/Privasys/enclave-vaults-client)
  (`/go`) — the vault SDK: the RA-TLS client to the vault constellation and the
  key operations (create, wrap/unwrap, sign, key info, delete).
- [Privasys/ra-tls-clients](https://github.com/Privasys/ra-tls-clients) (`/go`) —
  the RA-TLS verification policy and quote-verification client.
- [Privasys/go](https://github.com/Privasys/go) — the Go fork that adds the
  RA-TLS handshake hook the vault dial needs (built with `-tags ratls`).
- [github.com/google/uuid](https://github.com/google/uuid) — unique key names
  when a KMIP client does not supply one.

## Build

The RA-TLS data-plane dial needs the Privasys Go fork (build with `-tags ratls`).
The vault SDK and RA-TLS client are vendored siblings under `platform/` via
`replace` directives in `go.mod`.

```
go build -tags ratls ./...
```

The container image is built reproducibly by the [`Dockerfile`](./Dockerfile),
which fetches the Go fork release and clones the pinned sibling modules, so it
builds from this repo alone.

## Store and MCP

[`privasys.json`](./privasys.json) declares the App Store listing (tagline,
category, description) and the MCP tools (`create_key`, `sign`,
`get_public_key`), so the gateway lists in the store and its tools appear in the
developer portal's API Testing and AI Tools tabs.

## Licence

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
