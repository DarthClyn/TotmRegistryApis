# pila-verifier

Verifies credentials **not issued by TOTM** (PILA-issued eLCs and other PILA credentials) for the TOTM Trust API's
`POST /api/v1/pila/verify`. A verification-only cut of the Orchestration Layer's `pila-bridge`: it runs **PILA's official
Go SDK** ([go-credential-sdk](https://github.com/pilacorp/go-credential-sdk) v1.13.1) for integrity and signature checks. Nothing is reimplemented.
Issuer trust and live status are PILA's own verification context API, called by the portal, not here.

The API runs it for you as a child process on `127.0.0.1` (never exposed): the Dockerfile builds it into
`bin/pila-verifier`; locally, `npm run pila:build` does the same (needs Go 1.24.6+, https://go.dev/dl/).

| Endpoint (internal) | Body | Returns |
| --- | --- | --- |
| `GET /health` | – | SDK version |
| `POST /verify` | `{ "credential": <JSON object or JWT string> }` | `checks.issuer / sigHow it works (no DID is resolved, no API key needed):

- **Issuer key**:
  1. from PILA's verification context API (`vcs[].didPublicKey`), which the portal calls first and passes in as
     `issuerPublicKey` (NDAKey verifier guide 3.2, steps 6–8);
  2. if PILA has none (issuer not registered): recovered from the ES256K signature of the VC-JWT, and used only if its
     address equals the issuer's `did:nda` DID. Open check: no registry needed.
- **signature** (integrity + issuer) – `cred.Verify()` in PILA's SDK with that key. A different signer or a changed
  payload fails.
- **expiration / revocation** – SDK options, reported but not shown in the portal.

Issuer trust (registered with PILA) and live status are PILA's verification context answer, not this program's.
For a VC-JWT whose body leaves out the issuer / ID, they are read from the JWT claims (`iss`, `jti`, `sub`).
Tests: `go test ./...`.

The child only receives `PILA_*`, proxy and certificate variables, never the API's own secrets, and a random token
per start, so nothing but the API can call it.

Not included from the bridge: issuing, demo identities, DIDComm and the demo bank's self-resolved DID document. A
`did:nda` issuer must therefore be known to NDAKey or PILA's resolver.
