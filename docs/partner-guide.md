# TOTM Trust API: Integration Guide for Partners (Verifier)

For PILA, to check eLCs issued on the TOTM (Indonesia) side. Same structure as the NDAKey verifier API.

Base URL: `https://<to be shared>/api/v1`

## 1. Registration (same steps as NDAKey)

1. **Send us your details**: organisation name, email, your DID (e.g. `did:nda:testnet:0x…`) and its compressed
   secp256k1 public key (`0x02…` / `0x03…`, 66 hex characters). Your existing NDAKey verifier DID works.
2. **Receive an OTP** from TOTM (email or direct message). It is tied to that DID and email and expires after 24 hours.
3. **Register**: `POST /verifier` (no key needed)

```json
{
  "name": "PILA",
  "did": "did:nda:testnet:0x…",
  "publicKeyHex": "0x03…",
  "otp": "dbba81f8-5c33-4b2f-bddd-802a21c07d2e",
  "email": "ops@pila.example",
  "logoUrl": "https://…",
  "website": "https://…"
}
```

`logoUrl` and `website` are optional. For did:nda the public key must match the DID's address. Response:

```json
{ "code": "E00", "message": "Success", "data": { "apiKey": "tta_…", "did": "did:nda:testnet:0x…", "type": "verifier" } }
```

`data.apiKey` is shown once; TOTM keeps only a hash of it. Store it in your secret manager.

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | E400 | Missing / invalid field, key does not match the DID, or the DID is already registered |
| 401 | E401 | OTP expired or does not match this DID and email |

## 2. Access

- Send the API key in the `X-Api-Key` header, server to server only (never from a browser or device).
- Optional `X-Request-Id` (UUID) for reconciliation; it is returned in the `X-Request-Id` response header (and in
  `data.requestId` for the verification context). If missing or not a UUID, we create one.
- Success: `{"code": "E00", "message": "Success", "data": …}`. Errors: `{"code": "…", "error": "…"}`.
- A lost or leaked key: tell TOTM; we revoke it and you register again with a new OTP.

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | E400 | Missing or malformed fields |
| 401 | E15 | Missing or invalid `X-Api-Key` |
| 404 | E02 | DID / BIC not found |
| 500 | E500 | Internal error on the TOTM side |

## 3. APIs

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/verifier` | OTP | Register and receive your API key |
| GET | `/dids/{did}` | none | Resolve a bank DID: public key, name, BIC, status |
| GET | `/banks/{bic}` | none | Same, by SWIFT BIC |
| POST | `/vp/verification-context` | X-Api-Key | Issuer trust and eLC status for a list of credentials |
| POST | `/vc/verify` | X-Api-Key | Integrity and issuer check of a full eLC |
| GET | `/partners/me` | X-Api-Key | Check your key |

### 3.1 Resolve a DID: `GET /dids/{did}`

```json
{
  "code": "E00", "message": "Success",
  "data": {
    "did": "did:key:zDnaeYW5NSMq64vZAjwCxn11FXohzSkr81vU4QVXKukYYErGM",
    "type": "issuer",
    "publicKey": "0x02…",
    "name": "Bank Alpha ID", "role": "Issuing bank", "bic": "ALPHIDJA",
    "status": "active", "isTrusted": true, "allowedDocs": ["eLC"],
    "validFrom": null, "validUntil": null
  }
}
```

`publicKey` is the compressed public key hex (P-256 for TradeTrust banks). `status`: `active`, `suspended` or
`revoked`. `isTrusted` = active, inside its validity dates and allowed to issue eLCs.

### 3.2 Verification context: `POST /vp/verification-context`

Request (same as NDAKey; `holderDid` is optional here, `txId` per credential is optional):

```json
{
  "holderDid": "did:nda:testnet:0x…",
  "vcIds": [
    { "vcId": "urn:uuid:01a11205-bb3a-722e-8bca-720e7d64d83e", "issuerDid": "did:key:zDnae…", "txId": "TX-20261029-000001" }
  ]
}
```

Response:

```json
{
  "code": "E00", "message": "Success",
  "data": {
    "requestId": "3f2a9c14-8d51-4f0b-9c2e-6b1d0a7e5c38",
    "holderPublicKey": null,
    "vcs": [
      { "vcid": "urn:uuid:01a1…", "txId": "TX-20261029-000001", "didPublicKey": "0x02…", "isIssuerTrusted": true, "status": "active" }
    ]
  }
}
```

| Field | Meaning |
| --- | --- |
| `txId` | Transaction ID of the L/C deal, set by TOTM at issue (null when not found) |
| `didPublicKey` | Issuer public key (null if unknown) |
| `isIssuerTrusted` | Issuer is in TOTM's registry, active, within validity and allowed to issue eLCs |
| `status` | `active`, `suspended` (e.g. replaced by an amendment), `expired`, `not_found` |

`not_found` also covers an issuer DID or Tx ID that does not match our record. Up to 50 credentials per call.
**Accept an eLC only when `status` is `active`, `isIssuerTrusted` is `true` and `didPublicKey` is not null.**
The API answers 200 even when a credential fails these checks. Treat errors and timeouts as INDETERMINATE.

### 3.3 Content check: `POST /vc/verify`

For TOTM-issued eLCs (W3C VC, `ecdsa-sd-2023`, signed with TrustVC). Body: `{"vc": <the signed eLC JSON>}`.

```json
{
  "code": "E00", "message": "Success",
  "data": {
    "vcId": "urn:uuid:01a1…", "issuerDid": "did:key:zDnae…", "txId": "TX-20261029-000001",
    "integrity": { "passed": true, "result": "pass", "message": "Not tampered with: contents match the signature" },
    "issuer":    { "passed": true, "result": "pass", "message": "Signature belongs to the issuer DID" }
  }
}
```

`result`: `pass`, `fail` or `error` (could not be checked). This sends the eLC content to TOTM; use it when
your own SDK cannot verify the TradeTrust proof. Nothing from the eLC is stored.

### 3.4 Check your key: `GET /partners/me`

```json
{ "code": "E00", "message": "Success", "data": { "did": "did:nda:testnet:0x…", "name": "PILA", "type": "verifier" } }
```

## 4. Test data

A sample eLC and its identifiers will be shared with the base URL and key.
