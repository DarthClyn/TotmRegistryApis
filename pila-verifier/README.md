# pila-verifier

Verifies credentials **not issued by TOTM** (PILA-issued eLCs and other PILA credentials) for the TOTM Trust API's
`POST /api/v1/pila/verify`. A verification-only cut of the Orchestration Layer's `pila-bridge`: it runs **PILA's official
Go SDK** ([go-credential-sdk](https://github.com/pilacorp/go-credential-sdk) v1.13.1) for integrity and signature checks. Nothing is reimplemented.
Issuer trust and live status are PILA's own verification context API, called by the portal, not here.

The API runs it for you as a child process on `127.0.0.1` (never exposed): the Dockerfile builds it into
`bin/pila-verifier`; locally, `npm run pila:build` does the same (needs Go 1.24.6+, https://go.dev/dl/).

| Endpoint (internal) | Body | Returns |
| --- | --- | --- |
| `GET /health` | – | resolver, NDAKey URL, SDK version |
| `POST /verify` | `{ "credential": <JSON object or JWT string> }` | `checks.issuer / sigHow each check runs (all in PILA's SDK, no API key):

- **signature** – `cred.Verify()` (JSON-LD Data Integrity, VC-JWT ES256K/ES256, SD-JWT).
- **issuer** – resolves the issuer DID: `did:nda` via NDAKey's public registry lookup (`GET /dids/{did}`), then PILA's
  public resolver; `did:key` locally.
- **expiration / revocation** – `WithCheckExpiration()` / `WithCheckRevocation()` (when `credentialStatus` exists).

The SDK verifies the token itself (it reads the issuer from `iss` / `kid`); nothing we read is given to it. The response
also returns the credential's ID, issuer, holder and dates, which the portal needs to call PILA's verification context
API. They come from the credential body (`GetContents`); for a VC-JWT whose body leaves them out, from the JWT's
registered claims (`iss`, `jti`, `sub`, `nbf`, `exp`), as the VC-JWT encoding allows. The body wins when it has a value.
The SDK has no getter for these claims, so this is the one thing read outside it. Tests: `go test ./...` (`claims_test.go`).

| Variable | Default | |
| --- | --- | --- |
| `PILA_NDAKEY_URL` | `https://api-beta.ndakey.vn/service/api/v1` | public DID lookup; `off` uses PILA's resolver only |
| `PILA_DID_RESOLVER_URL` | `https://api.ndadid.vn/api/v1/did` | PILA's public DID resolver |

A_DID_RESOLVER_URL` | `https://api.ndadid.vn/api/v1/did` | PILA's public DID resolver |

The child only receives `PILA_*`, proxy and certificate variables, never the API's own secrets, and a random token
per start, so nothing but the API can call it.

Not included from the bridge: issuing, demo identities, DIDComm and the demo bank's self-resolved DID document. A
`did:nda` issuer must therefore be known to NDAKey or PILA's resolver.
