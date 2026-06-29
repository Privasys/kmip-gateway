# kmip-gateway

A KMIP 2.1 front-end for the Privasys vHSM, run as a confidential container-app.

KMIP clients (enterprise key-management tooling, storage arrays, databases) speak
the standard KMIP TTLV protocol to the **`privasys kmip-proxy`** shim, which
carries it to the gateway over the platform's attested **sealed session**. The
gateway translates each operation to the Privasys vault constellation over
**RA-TLS**, so the platform control plane is never in the key data path. Because
the gateway runs inside a TEE as an attested container-app and the transport is
the sealed session, the whole chain stays attested and confidential — with no
gateway-managed certificate.

This is the standard-skin / novel-core pattern: a familiar KMIP interface in front
of the attested-policy vault core. Key material is created and used **in-enclave**;
the gateway never sees plaintext keys.

## Layout

- `main.go` — config + session bootstrap; serves the single HTTP surface (the
  KMIP transport rides the platform's sealed session, so there is no own TLS).
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

The gateway terminates **no TLS of its own**. It serves one HTTP surface on
`$PORT` (the manager-injected app port), reached through the platform's **sealed
session** — an attested, confidential channel the manager relays, the same
mechanism the platform uses for browser SDKs and confidential-ai. So the KMIP
transport inherits the platform's attestation rather than a self-signed cert.

- `GET /health`, `GET /version` — health + info.
- `POST /configure` — runtime configuration (below).
- `POST /kmip` — the KMIP TTLV endpoint: the request body is a KMIP
  `RequestMessage`, the response body is the `ResponseMessage`. One KMIP batch per
  POST.
- `POST /keys`, `POST /sign`, `POST /public` — the management MCP tools.

Standard KMIP clients (PyKMIP, storage arrays) reach `POST /kmip` through the
**`privasys kmip-proxy`** shim: it serves a local plain KMIP-over-TLS endpoint,
bootstraps the sealed session (verifying the enclave quote on the client's
behalf), and relays each KMIP message. The standard client just points at
`localhost:5696`; the shim does the attestation.

## Configuration

The configuration is platform-native: the platform does not inject app env vars,
so the gateway **discovers the constellation** from the directory and receives
its app-specific configuration at runtime via **`POST /configure`**. The HTTP
surface (health + configure) is up from the moment the process starts; the KMIP
endpoint and the MCP tools become live once configured.

`POST /configure` (JSON):

| Field | Meaning |
| --- | --- |
| `vault_id` | the vault this gateway fronts (handles are `vaults/<id>/<name>`) |
| `mgmt_url` | management-service origin (discovers the constellation; mints key grants) |
| `owner_token` | OIDC bearer for the control plane (and, without app identity, vault owner auth) |
| `attestation_token` | bearer for vault quote verification (`aud=attestation-server`) |
| `use_app_identity` | authenticate to the vault as the app (manager-minted identity), no owner bearer in the data path |

The constellation endpoints, MRENCLAVE pin, and attestation server are fetched
from `GET /api/v1/vaults`, never configured by hand.

Platform-injected (the runtime sets these; no action needed):
`PORT`, `PRIVASYS_APP_ID`, `PRIVASYS_CONTAINER_TOKEN`.

For **local testing**, a full constellation in the environment self-configures
the gateway at startup (no `/configure` call): `KMIP_VAULT_ID`,
`KMIP_VAULT_ENDPOINTS`, `KMIP_VAULT_MRENCLAVE`, `KMIP_ATTESTATION_SERVER`,
`KMIP_ATTESTATION_TOKEN`, `KMIP_OWNER_TOKEN`, `KMIP_MGMT_URL`.

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
