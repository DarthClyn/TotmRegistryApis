# TOTM Trust API

A small API that lets partner platforms (PILA first) check eLCs issued on the TOTM side:

- **Who is this bank?** Issuer registry lookup by DID or BIC (on-chain, `IssuerRegistryV2`).
- **Is the issuer trusted, and is this eLC still valid?** Same request and response as NDAKey's
  `POST /vp/verification-context`, plus `txId` and the status `suspended`.
- **Is the eLC intact and signed by its issuer?** Content check of a TradeTrust (W3C) eLC with TrustVC.

It is separate from the VC Layer and deploys on its own. It stores no eLC content: only VC ID, Tx ID,
issuer DID, status and expiry per eLC.

## Endpoints

| Method | Path | Key | Purpose |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | none | Up check |
| GET | `/api/v1/dids/{did}` | none | Bank by DID: public key, name, BIC, status, trusted |
| GET | `/api/v1/banks/{bic}` | none | Same, by BIC |
| POST | `/api/v1/verifier` | OTP | Partner self-registration (as NDAKey): DID + public key + email + OTP → API key |
| GET | `/api/v1/partners/me` | `X-Api-Key` | Check your key |
| POST | `/api/v1/vp/verification-context` | `X-Api-Key` | Issuer trust + eLC status for a list of VC IDs |
| POST | `/api/v1/vc/verify` | `X-Api-Key` | Integrity + issuer check of a full eLC |
| POST | `/api/v1/admin/otps` | `X-Admin-Key` | One-time registration code for a partner's DID + email (24 h) |
| GET / DELETE | `/api/v1/admin/partners[/{did}]` | `X-Admin-Key` | List partners / revoke one (its key stops working) |
| POST | `/api/v1/admin/elc/issue` | `X-Admin-Key` | **Issuing API**: sign an eLC with the bank's key and register it (Tx ID, status active); returns the signed eLC |
| POST | `/api/v1/admin/vcs` | `X-Admin-Key` | Register an eLC issued elsewhere (creates the Tx ID, status active) |
| GET | `/api/v1/admin/vcs/{vcId}` | `X-Admin-Key` | One eLC record |
| GET | `/api/v1/admin/tx/{txId}` | `X-Admin-Key` | All eLCs of a Tx ID |
| POST | `/api/v1/admin/vcs/{vcId}/suspend` | `X-Admin-Key` | Suspend (final, no reactivation) |

Responses: `{code: "E00", message: "Success", data}`. Errors: `{code, error}` with `E400` (bad request),
`E15` (missing / wrong key), `E02` (not found), `E409` (already exists / already suspended), `E500`.
`X-Request-Id` (UUID) is echoed, or created when missing. The partner guide for PILA is in `docs/`.

Status per eLC: `active`, `suspended`, `expired` (past its `validUntil`), `not_found` (unknown VC ID, or the
issuer DID / Tx ID given does not match the record). Accept an eLC only when `status` is `active`,
`isIssuerTrusted` is `true` and `didPublicKey` is not null.

## Run locally

```bash
npm install
cp .env.example .env      # fill in what you have; without REGISTRY_ADDRESS the registry is empty
npm test                  # API tests + contract tests (local ganache chain)
npm run dev               # http://127.0.0.1:4300
```

Without `UPSTASH_REDIS_REST_URL` the eLC records live in memory (lost on restart). That is for local runs only.

## 1. Deploy the registry contract (once)

`IssuerRegistryV2` = v1 plus `bic` (unique, also looked up by BIC) and `signingKey` (compressed public key hex).

```bash
# .env: REGISTRY_OWNER_PRIVATE_KEY (funded with Sepolia ETH) and INFURA_API_KEY or REGISTRY_RPC_URL
npm run contract:deploy            # prints the address, saves deployments/11155111.json
```

Then add banks (the owner wallet signs; for a did:key the signing key is taken from the DID):

```bash
npm run registry -- add --did did:key:zDnae… --name "Bank Alpha ID" --role "Issuing bank" --bic ALPHIDJA --docs eLC
npm run registry -- add --did did:web:bank-b.example --name "…" --bic … --signing-key 0x02…
npm run registry -- get --bic ALPHIDJA
npm run registry -- status --did … --to suspended      # active | suspended | revoked
npm run registry -- list
```

Changes to the contract source need `npm run contract:build` (solc 0.8.24, Shanghai) and a new deploy.

## 2. Keys and partner onboarding

Admin key (TOTM only):

```bash
npm run keygen -- --admin     # prints the key once: ADMIN_API_KEY (local .env only) + ADMIN_API_KEY_HASH (server)
```

Partners onboard like NDAKey onboarded us; TOTM never sees their API key:

1. The partner sends its organisation name, email, DID and compressed public key (e.g. its NDAKey verifier DID).
2. TOTM issues a one-time code for exactly that DID and email (valid 24 h) and sends it privately:
   `npm run partner -- otp --name PILA --did did:nda:testnet:0x… --email ops@… --public-key 0x03…`
   For did:nda and did:key the public key is checked against the DID.
3. The partner calls `POST /api/v1/verifier` with name, did, publicKeyHex, otp, email and receives `data.apiKey`
   (shown once; only its hash is kept).
4. `npm run partner -- list` shows registered partners; `npm run partner -- revoke --did …` stops a key at once.

`PARTNER_API_KEYS` (hashes from `npm run keygen -- --name …`) still works for manual setups and needs no store.

## 3. Deploy on Vercel

1. New Vercel project from this folder. Framework preset: **Fastify** (set in `vercel.json`), entry `src/index.js`.
2. Storage: add **Upstash Redis** from the Vercel Marketplace (it sets `KV_REST_API_URL` / `KV_REST_API_TOKEN`,
   which the API also reads) or set `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` yourself.
3. Environment variables: `REGISTRY_CHAIN_ID`, `REGISTRY_ADDRESS`, `INFURA_API_KEY` (or `REGISTRY_RPC_URL`),
   `BANK_KEYS_JSON`, `ADMIN_API_KEY_HASH` (and `PARTNER_API_KEYS` only for manual keys). **Never** `REGISTRY_OWNER_PRIVATE_KEY`
   or `ADMIN_API_KEY`.
4. Deploy, then check `https://<project>.vercel.app/api/v1/health`.

When hosted (`VERCEL` set), a missing `REGISTRY_ADDRESS` or status store stops the start with an error.
Audit lines go to the platform logs as one JSON line each (`{"audit": …}`): partner, action, outcome, VC ID,
Tx ID, request ID. No eLC content or credential payloads.

## 4. Issue and register eLCs

The Issuing API signs with the issuing bank's own key (TrustVC `signW3C`, `ecdsa-sd-2023`), the same eLC format as
the VC Layer, and registers it in one step. The signed eLC is returned, not stored.

```bash
npm run bank-key -- --name "Bank Alpha ID" --bic ALPHIDJA   # once: prints BANK_KEYS_JSON (secret) + the registry command
# or reuse the VC Layer's demo bank: BANK_KEYS_JSON=<its ISSUER_KEY_JSON>
npm run elc -- issue --file my-elc-fields.json [--holder did:nda:…]   # saves <lcNumber>.json
```

Request body: `{ "data": { "lcNumber": "…", "dateOfIssue": "YYYY-MM-DD", "expiryDate": "YYYY-MM-DD", "currency": "USD",
"amount": "…", … }, "holderDid"?, "issuerDid"? (needed when several bank keys are configured), "attachments"?: [{filename,
mimeType, data(base64)}], "txId"? }`. Every MT700 field is optional; unknown keys come back in `ignoredFields`.
`validFrom` is the date of issue, or now if that is still in the future in UTC.

Already issued elsewhere (e.g. in the VC Layer)? Register it only:

When an eLC is issued on the TOTM side, register it so partners can check its status:

```bash
# .env: TRUST_API_URL=https://<project>.vercel.app and ADMIN_API_KEY=<admin key>
npm run elc -- register --vc-id urn:uuid:… --issuer did:key:… --until 2027-01-31
npm run elc -- suspend --vc-id urn:uuid:… --reason "amendment"
npm run elc -- get --vc-id urn:uuid:…
```

Amendment: suspend the old VC, then register the new VC with `--tx <same Tx ID>`.
The VC Layer's Issue eLC can later call `POST /api/v1/admin/vcs` directly with the admin key.

## Layout

```
contract/src/IssuerRegistryV2.sol      registry contract (owner writes, anyone reads)
contract/artifacts/                    compiled ABI + bytecode (committed)
deployments/<chainId>.json             deployed address (public)
src/api.js                             routes, key checks, response format, audit
src/registry.js                        on-chain reader (no cache), trust rule
src/store.js                           eLC status records (Upstash REST / memory), Tx IDs
src/verify.js                          TrustVC content check
src/elc.js                             eLC data model (MT700 fields, inline context) and signing
src/keys.js                            did:key public keys, key hashing
scripts/                               build, deploy, registry CLI, keygen, eLC admin client
test/                                  node:test (API with real TrustVC; contract on ganache)
```
