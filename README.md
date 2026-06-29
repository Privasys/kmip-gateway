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

## Vault authentication

Today the gateway authenticates to the vault as the **vault owner**, using an
OIDC bearer (`KMIP_OWNER_TOKEN`), exactly like the CLI. Keys are owned by that
account; the bearer authorises data-plane operations and the platform mints the
holder-of-key grant for key creation.

**App identity (the target).** The gateway authenticates to the vault **as
itself**, the same way the per-app data key does, with no owner bearer in the
data path. On each vault connection the gateway's `GetClientCertificate` callback
hands the vault's RA-TLS challenge to the in-TD **manager**, which mints a
one-shot client certificate carrying a fresh TDX quote bound to the challenge and
the gateway's app id (OID 3.6) — the same `mintIdentity` it uses for the data key
(`enclave-os-virtual` `internal/vaultkey`). The vault trusts that app id because
the manager is the measured sole minter, the platform's root of trust: an app
never mints its own identity. The manager stays out of the key data path (it only
vouches for identity); the gateway remains the vault client.

The key policy then grants the operations to the gateway's app TEE principal
(app id OID 3.6), mirroring the per-app data-key policy that grants `ExportKey` to
`AnyTee`.

## Surfaces

- **KMIP TTLV over TLS** on `KMIP_LISTEN_ADDR` (default `:5696`) for KMIP clients.
  Provide a server certificate with `KMIP_TLS_CERT`/`KMIP_TLS_KEY`, or the gateway
  generates a self-signed one at startup and logs its fingerprint to pin.
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
| `KMIP_OWNER_TOKEN` | the vault owner's OIDC bearer |
| `KMIP_LISTEN_ADDR` | KMIP listen address (default `0.0.0.0:5696`) |
| `KMIP_TLS_CERT` / `KMIP_TLS_KEY` | KMIP server certificate (PEM); self-signed if unset |
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
