// TOTM Trust API. Same shapes as NDAKey's verifier API so PILA can reuse its client:
// success {code: "E00", message: "Success", data}, errors {code, error}, X-Api-Key for partner calls, X-Request-Id echoed.
import { randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import { didMatchesKey, isCompressedKey, keyMatches, newApiKey, publicKeyFromDidKey, sha256Hex } from './keys.js';
import { isTrustedNow } from './registry.js';
import { effectiveStatus } from './store.js';
import { looksLikeW3cVc, verifyContent } from './verify.js';
import { ElcInputError, normaliseElcData, signElc } from './elc.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_VCS = 50;

class ApiError extends Error {
  constructor(http, code, message) { super(message); this.http = http; this.code = code; }
}
const bad = (msg) => new ApiError(400, 'E400', msg);
const ok = (data) => ({ code: 'E00', message: 'Success', data });

/**
 * @param {object} deps
 * @param {{byDid(did:string):Promise<object|null>, byBic(bic:string):Promise<object|null>}} deps.registry
 * @param {ReturnType<import('./store.js').memoryStore>} deps.store
 * @param {{name:string, did?:string, type?:string, keyHash:string}[]} deps.partners
 * @param {string} [deps.adminKeyHash]
 * @param {(vc:object)=>Promise<object[]>} [deps.verifier] TrustVC verifyDocument (injected in tests)
 * @param {(line:object)=>void} [deps.audit]
 * @param {Map<string, object>} [deps.bankKeys] issuing banks' TrustVC key pairs by DID (server-side only)
 * @param {Function} [deps.signer] TrustVC signW3C (injected in tests)
 */
export function buildApp({ registry, store, partners = [], adminKeyHash, verifier, bankKeys = new Map(), signer, audit = (l) => console.log(JSON.stringify({ audit: l })), logger = false }) {
  const app = Fastify({ logger, bodyLimit: 15 * 1024 * 1024, genReqId: () => randomUUID() });

  // X-Request-Id: the caller's UUID if valid, else a new one; always returned.
  app.addHook('onRequest', async (req, reply) => {
    const given = req.headers['x-request-id'];
    req.requestId = typeof given === 'string' && UUID.test(given) ? given : randomUUID();
    reply.header('x-request-id', req.requestId);
  });

  const audited = (req, action, outcome, details = {}) =>
    audit({ time: new Date().toISOString(), requestId: req.requestId, partner: req.partner?.name ?? null, action, outcome, ...details });

  // Partner key (X-Api-Key) and admin key (X-Admin-Key). Only hashes are kept; keys are never stored.
  // Partners come from self-registration (store) or, for manual setups, from PARTNER_API_KEYS.
  const requirePartner = async (req) => {
    const key = req.headers['x-api-key'];
    let p = partners.find((x) => keyMatches(key, x.keyHash));
    if (!p && typeof key === 'string' && key.length >= 16 && key.length <= 200) p = await store.partnerByKeyHash(sha256Hex(key));
    if (!p) { audited(req, 'auth.partner', 'denied'); throw new ApiError(401, 'E15', 'Missing or invalid X-Api-Key'); }
    req.partner = p;
  };
  const requireAdmin = async (req) => {
    if (!adminKeyHash || !keyMatches(req.headers['x-admin-key'], adminKeyHash)) {
      audited(req, 'auth.admin', 'denied');
      throw new ApiError(401, 'E15', 'Missing or invalid X-Admin-Key');
    }
    req.partner = { name: 'TOTM admin' };
  };

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ApiError) return reply.code(err.http).send({ code: err.code, error: err.message });
    if (err.validation || err.statusCode === 400 || err.code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE') return reply.code(400).send({ code: 'E400', error: 'Malformed request body' });
    if (err.statusCode === 413) return reply.code(413).send({ code: 'E400', error: 'Body too large' });
    req.log?.error?.(err);
    audited(req, 'error', 'failed', { reason: err.message?.slice(0, 200) });
    return reply.code(500).send({ code: 'E500', error: 'Internal error on the TOTM side' });
  });
  app.setNotFoundHandler((req, reply) => reply.code(404).send({ code: 'E404', error: 'No such endpoint' }));

  const publicKeyOf = (entry) => entry?.signingKey ?? (entry ? publicKeyFromDidKey(entry.did)?.hex ?? null : null);
  const didView = (e) => ({
    did: e.did, type: 'issuer', publicKey: publicKeyOf(e), name: e.name, role: e.role, bic: e.bic,
    status: e.status, isTrusted: isTrustedNow(e), allowedDocs: e.allowedDocs, validFrom: e.validFrom, validUntil: e.validUntil,
  });

  // ---------- Public ----------

  app.get('/api/v1/health', async () => ok({ status: 'ok', store: store.kind }));

  /** Resolve a bank DID: public key and registry facts. No key needed (like NDAKey GET /dids/{did}). */
  app.get('/api/v1/dids/:did', async (req) => {
    const e = await registry.byDid(req.params.did);
    if (!e) throw new ApiError(404, 'E02', 'DID not found');
    return ok(didView(e));
  });

  /** Same, looked up by SWIFT BIC. */
  app.get('/api/v1/banks/:bic', async (req) => {
    const e = await registry.byBic(String(req.params.bic).toUpperCase());
    if (!e) throw new ApiError(404, 'E02', 'BIC not found');
    return ok(didView(e));
  });

  // ---------- Partner (X-Api-Key) ----------

  app.get('/api/v1/partners/me', { preHandler: requirePartner }, async (req) =>
    ok({ did: req.partner.did ?? null, name: req.partner.name, type: req.partner.type ?? 'verifier' }));

  /**
   * Verifier registration, as NDAKey's POST /verifier: the partner sends its DID, public key, email and the OTP that
   * TOTM issued for exactly that DID and email. Returns the API key once (only its hash is kept).
   */
  app.post('/api/v1/verifier', async (req) => {
    const b = req.body ?? {};
    const str = (v, max = 300) => typeof v === 'string' && v.trim() !== '' && v.length <= max;
    if (!str(b.name, 200) || !str(b.did) || !str(b.publicKeyHex) || !str(b.otp, 100) || !str(b.email, 200)) throw bad('name, did, publicKeyHex, otp and email are required');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email)) throw bad('email is not a valid address');
    if (!/^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(b.did)) throw bad('did is not a DID');
    if (!isCompressedKey(b.publicKeyHex)) throw bad('publicKeyHex must be a compressed public key in hex (0x02… or 0x03…, 66 hex characters)');
    if ((await didMatchesKey(b.did, b.publicKeyHex)) === false) throw bad('publicKeyHex does not belong to this DID');
    if (await store.partnerByDid(b.did)) throw bad('This DID is already registered');
    const otpHash = sha256Hex(String(b.otp).trim());
    const otp = await store.getOtp(otpHash);
    if (!otp || otp.did !== b.did || otp.email.toLowerCase() !== b.email.trim().toLowerCase()) {
      audited(req, 'partner.register', 'denied', { did: b.did });
      throw new ApiError(401, 'E401', 'OTP expired or does not match this DID and email');
    }
    const apiKey = newApiKey();
    const rec = {
      did: b.did, name: b.name.trim(), email: b.email.trim(), type: 'verifier', publicKeyHex: b.publicKeyHex,
      ...(str(b.logoUrl, 500) ? { logoUrl: b.logoUrl } : {}), ...(str(b.website, 500) ? { website: b.website } : {}),
      keyHash: sha256Hex(apiKey), createdAt: new Date().toISOString(),
    };
    if (!(await store.createPartner(rec))) throw bad('This DID is already registered');
    await store.deleteOtp(otpHash);
    req.partner = rec;
    audited(req, 'partner.register', 'ok', { did: rec.did });
    return ok({ apiKey, did: rec.did, type: rec.type });
  });

  /**
   * Issuer trust and eLC status for a list of credentials. Request and response follow NDAKey's
   * POST /vp/verification-context; holderDid is optional here, txId is added, status adds "suspended".
   */
  app.post('/api/v1/vp/verification-context', { preHandler: requirePartner }, async (req) => {
    const body = req.body ?? {};
    const items = body.vcIds;
    if (!Array.isArray(items) || !items.length) throw bad('vcIds must be a non-empty array');
    if (items.length > MAX_VCS) throw bad(`At most ${MAX_VCS} credentials per call`);
    for (const it of items) {
      if (!it || typeof it.vcId !== 'string' || typeof it.issuerDid !== 'string') throw bad('Each vcIds item needs vcId and issuerDid');
    }
    if (body.holderDid != null && typeof body.holderDid !== 'string') throw bad('holderDid must be a string');

    const holder = body.holderDid ? await registry.byDid(body.holderDid) : null;
    const vcs = [];
    for (const it of items) {
      const [issuer, rec] = await Promise.all([registry.byDid(it.issuerDid), store.get(it.vcId)]);
      const matches = rec && rec.issuerDid === it.issuerDid && (!it.txId || it.txId === rec.txId);
      vcs.push({
        vcid: it.vcId,
        txId: matches ? rec.txId : null,
        didPublicKey: publicKeyOf(issuer) ?? publicKeyFromDidKey(it.issuerDid)?.hex ?? null,
        isIssuerTrusted: isTrustedNow(issuer),
        status: matches ? effectiveStatus(rec) : 'not_found',
      });
    }
    audited(req, 'vp.verification-context', 'ok', {
      count: vcs.length, results: vcs.map((v) => ({ vcId: v.vcid, txId: v.txId, status: v.status, trusted: v.isIssuerTrusted })),
    });
    return ok({ requestId: req.requestId, holderPublicKey: body.holderDid ? publicKeyOf(holder) ?? publicKeyFromDidKey(body.holderDid)?.hex ?? null : null, vcs });
  });

  /** Content check of a TOTM-issued (TradeTrust, W3C) eLC: integrity and issuer. Send the whole VC as `vc`. */
  app.post('/api/v1/vc/verify', { preHandler: requirePartner }, async (req) => {
    const vc = req.body?.vc;
    if (!looksLikeW3cVc(vc)) throw bad('Send the signed eLC as "vc" (a W3C verifiable credential with a proof)');
    const r = await verifyContent(vc, { verifier });
    const rec = r.vcId ? await store.get(r.vcId) : null;
    const data = { ...r, txId: rec && rec.issuerDid === r.issuerDid ? rec.txId : null };
    audited(req, 'vc.verify', r.integrity.passed && r.issuer.passed ? 'pass' : 'fail', {
      vcId: r.vcId, txId: data.txId, issuerDid: r.issuerDid, integrity: r.integrity.result, issuer: r.issuer.result,
    });
    return ok(data);
  });

  // ---------- Admin (X-Admin-Key, TOTM only) ----------

  /** Issue a one-time registration code for a partner's DID and email (valid 24 h by default). Send it privately. */
  app.post('/api/v1/admin/otps', { preHandler: requireAdmin }, async (req, reply) => {
    const { name, did, email, publicKeyHex, hours } = req.body ?? {};
    if (typeof did !== 'string' || !/^did:[a-z0-9]+:/.test(did) || typeof email !== 'string' || !email.includes('@')) throw bad('did and email are required');
    if (publicKeyHex != null && !isCompressedKey(publicKeyHex)) throw bad('publicKeyHex must be a compressed public key in hex');
    if (publicKeyHex && (await didMatchesKey(did, publicKeyHex)) === false) throw bad('publicKeyHex does not belong to this DID');
    if (await store.partnerByDid(did)) throw new ApiError(409, 'E409', 'This DID is already registered');
    const h = Math.min(Math.max(Number(hours) || 24, 1), 168);
    const otp = randomUUID();
    const expiresAt = new Date(Date.now() + h * 3600_000).toISOString();
    await store.putOtp(sha256Hex(otp), { did, email: email.trim(), name: typeof name === 'string' ? name : null, expiresAt });
    audited(req, 'admin.otp.issue', 'ok', { did });
    reply.code(201);
    return ok({ otp, did, email: email.trim(), expiresAt });
  });

  app.get('/api/v1/admin/partners', { preHandler: requireAdmin }, async () =>
    ok((await store.listPartners()).map(({ keyHash, ...p }) => p)));

  /** Revoke a partner: its API key stops working at once. It can register again with a new OTP. */
  app.delete('/api/v1/admin/partners/:did', { preHandler: requireAdmin }, async (req) => {
    if (!(await store.deletePartner(req.params.did))) throw new ApiError(404, 'E02', 'Partner not found');
    audited(req, 'admin.partner.revoke', 'ok', { did: req.params.did });
    return ok({ did: req.params.did, revoked: true });
  });

  /**
   * Issuing API: signs an eLC with the issuing bank's own key and registers it (new Tx ID, status active).
   * Body: { data: {MT700 fields}, issuerDid?, holderDid?, attachments?, txId? }. Returns the signed eLC.
   * `txId` keeps an existing Tx ID (amendment: suspend the old VC first). The eLC itself is not stored.
   */
  app.post('/api/v1/admin/elc/issue', { preHandler: requireAdmin }, async (req, reply) => {
    const body = req.body ?? {};
    if (!bankKeys.size) throw new ApiError(503, 'E503', 'No bank signing key is configured (BANK_KEYS_JSON)');
    const issuerDid = body.issuerDid ?? (bankKeys.size === 1 ? [...bankKeys.keys()][0] : undefined);
    if (!issuerDid) throw bad('issuerDid is required: more than one bank key is configured');
    const key = bankKeys.get(issuerDid);
    if (!key) throw new ApiError(403, 'E403', 'No signing key for this issuer DID on this server');
    if (body.txId != null && (typeof body.txId !== 'string' || !/^[A-Za-z0-9-]{3,40}$/.test(body.txId))) throw bad('txId must be 3-40 letters, digits or dashes');
    const { data, ignored } = normaliseElcData(body.data ?? {});
    if (!Object.keys(data).length) throw bad('data must contain eLC fields (e.g. lcNumber, amount, currency)');

    let vc;
    try {
      vc = await signElc({ data, attachments: body.attachments, key, holderDid: body.holderDid, signer });
    } catch (e) {
      if (e instanceof ElcInputError) throw bad(e.message);
      audited(req, 'elc.issue', 'failed', { issuerDid, reason: e.message.slice(0, 200) });
      throw e;
    }
    if (typeof vc.id !== 'string') throw new Error('Signed eLC has no id');
    const issuer = await registry.byDid(issuerDid).catch(() => null);
    const now = new Date().toISOString();
    const rec = { vcId: vc.id, txId: body.txId ?? (await store.nextTxId()), issuerDid, status: 'active', validUntil: vc.validUntil ?? null, createdAt: now, updatedAt: now };
    if (!(await store.create(rec))) throw new ApiError(409, 'E409', 'This VC ID is already registered');
    audited(req, 'elc.issue', 'ok', { vcId: rec.vcId, txId: rec.txId, issuerDid });
    reply.code(201);
    return ok({ txId: rec.txId, vcId: rec.vcId, issuerDid, status: rec.status, validUntil: rec.validUntil, issuerTrusted: isTrustedNow(issuer), ignoredFields: ignored, vc });
  });

  /** Register an issued eLC: creates its Tx ID (unless one is given, e.g. for an amendment) and sets status active. */
  app.post('/api/v1/admin/vcs', { preHandler: requireAdmin }, async (req, reply) => {
    const { vcId, issuerDid, validUntil, txId } = req.body ?? {};
    if (typeof vcId !== 'string' || !vcId || typeof issuerDid !== 'string' || !issuerDid) throw bad('vcId and issuerDid are required');
    if (validUntil != null && Number.isNaN(Date.parse(validUntil))) throw bad('validUntil must be an ISO date');
    if (txId != null && (typeof txId !== 'string' || !/^[A-Za-z0-9-]{3,40}$/.test(txId))) throw bad('txId must be 3-40 letters, digits or dashes');
    const now = new Date().toISOString();
    const rec = { vcId, txId: txId ?? (await store.nextTxId()), issuerDid, status: 'active', validUntil: validUntil ? new Date(validUntil).toISOString() : null, createdAt: now, updatedAt: now };
    if (!(await store.create(rec))) throw new ApiError(409, 'E409', 'This VC ID is already registered');
    audited(req, 'admin.vc.register', 'ok', { vcId, txId: rec.txId, issuerDid });
    reply.code(201);
    return ok(rec);
  });

  app.get('/api/v1/admin/vcs/:vcId', { preHandler: requireAdmin }, async (req) => {
    const rec = await store.get(req.params.vcId);
    if (!rec) throw new ApiError(404, 'E02', 'VC not found');
    return ok({ ...rec, status: effectiveStatus(rec) });
  });

  app.get('/api/v1/admin/tx/:txId', { preHandler: requireAdmin }, async (req) => {
    const recs = await store.byTxId(req.params.txId);
    if (!recs.length) throw new ApiError(404, 'E02', 'Tx ID not found');
    return ok({ txId: req.params.txId, vcs: recs.map((r) => ({ ...r, status: effectiveStatus(r) })) });
  });

  /** Suspend an eLC (e.g. while it is amended). Suspended is final: there is no reactivation in this PoC. */
  app.post('/api/v1/admin/vcs/:vcId/suspend', { preHandler: requireAdmin }, async (req) => {
    const rec = await store.get(req.params.vcId);
    if (!rec) throw new ApiError(404, 'E02', 'VC not found');
    if (rec.status === 'suspended') throw new ApiError(409, 'E409', 'Already suspended');
    const next = { ...rec, status: 'suspended', reason: typeof req.body?.reason === 'string' ? req.body.reason.slice(0, 200) : undefined, updatedAt: new Date().toISOString() };
    await store.put(next);
    audited(req, 'admin.vc.suspend', 'ok', { vcId: rec.vcId, txId: rec.txId });
    return ok(next);
  });

  return app;
}
