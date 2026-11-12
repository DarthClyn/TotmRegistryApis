# pila-verifier

Verifies credentials **not issued by TOTM** (PILA-issued eLCs and other PILA credentials) for the TOTM Trust API's
`POST /api/v1/pila/verify`. A verification-only cut of the Orchestration Layer's `pila-bridge`: it runs **PILA's official
Go SDK** ([go-credential-sdk](https://github.com/pilacorp/go-credential-sdk) v1.13.1) and calls **NDAKey's verification
context API**. Nothing is reimplemented.

The API runs it for you as a child process on `127.0.0.1` (never exposed): the Dockerfile builds it into
`bin/pila-verifier`; locally, `npm run pila:build` does the same (needs Go 1.24.6+, https://go.dev/dl/).

| Endpoint (internal) | Body | Returns |
| --- | --- | --- |
| `GET /health` | – | resolver, NDAKey URL, whether the verifier key is set |
| `POST /verify` | `{ "credential": <JSON object or JWT string> }` | `checks.issuer / signature / expiration / revocation` (SDK) + `ndakey` (verification context) + `subject` |

How each check runs:

- **signature** – `cred.Verify()` in PILA's SDK (JSON-LD Data Integrity, VC-JWT ES256K/ES256, SD-JWT).
- **issuer** – resolves the issuer DID: `did:nda` via NDAKey's registry (`GET /dids/{did}`), then PILA's public resolver;
  `did:key` locally.
- **expiration / revocation** – SDK options `WithCheckExpiration()` / `WithCheckRevocation()` (when `credentialStatus` exists).
- **NDAKey verification context** – `POST /vp/verification-context` with `X-Api-Key: PILA_PARTNER_API_KEY`: issuer trusted
  (`isIssuerTrusted`) and live status (`active`, `revoked`, `expired`, `not_found`).

Settings (Railway variables, or `PILA_*` lines in the API's `.env`):

| Variable | Default | |
| --- | --- | --- |
| `PILA_PARTNER_API_KEY` | – | NDAKey verifier key (SECRET). Without it there is no trust/status answer. |
| `PILA_NDAKEY_URL` | `https://api-beta.ndakey.vn/service/api/v1` | `off` skips NDAKey |
| `PILA_DID_RESOLVER_URL` | `https://api.ndadid.vn/api/v1/did` | PILA's public DID resolver |

The child only receives `PILA_*`, proxy and certificate variables, never the API's own secrets, and a random token
per start, so nothing but the API can call it.

Not included from the bridge: issuing, demo identities, DIDComm and the demo bank's self-resolved DID document. A
`did:nda` issuer must therefore be known to NDAKey or PILA's resolver.
