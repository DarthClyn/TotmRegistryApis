// eLC status records: VC ID -> { vcId, txId, issuerDid, status, validUntil, createdAt, updatedAt }.
// No eLC content is ever stored. Upstash Redis (REST) in production; memory for tests and local runs.

/** Tx ID: TX-YYYYMMDD-NNNNNN from a daily counter. */
const txIdFrom = (n, d = new Date()) => `TX-${d.toISOString().slice(0, 10).replace(/-/g, '')}-${String(n).padStart(6, '0')}`;

export function memoryStore() {
  const vcs = new Map();
  const byTx = new Map();
  const counters = new Map();
  const partners = new Map();
  const partnerKeys = new Map();
  const otps = new Map();
  return {
    kind: 'memory',
    async nextTxId() {
      const day = new Date().toISOString().slice(0, 10);
      const n = (counters.get(day) ?? 0) + 1;
      counters.set(day, n);
      return txIdFrom(n);
    },
    async get(vcId) { return vcs.get(vcId) ?? null; },
    async create(rec) {
      if (vcs.has(rec.vcId)) return false;
      vcs.set(rec.vcId, rec);
      byTx.set(rec.txId, [...(byTx.get(rec.txId) ?? []), rec.vcId]);
      return true;
    },
    async put(rec) { vcs.set(rec.vcId, rec); },
    async byTxId(txId) { return (byTx.get(txId) ?? []).map((id) => vcs.get(id)).filter(Boolean); },
    // Partners: { did, name, email, type, publicKeyHex, keyHash, createdAt }. Looked up by key hash or DID.
    async partnerByKeyHash(h) { const did = partnerKeys.get(h); return did ? partners.get(did) ?? null : null; },
    async partnerByDid(did) { return partners.get(did) ?? null; },
    async createPartner(p) {
      if (partners.has(p.did)) return false;
      partners.set(p.did, p); partnerKeys.set(p.keyHash, p.did); return true;
    },
    async deletePartner(did) {
      const p = partners.get(did); if (!p) return false;
      partners.delete(did); partnerKeys.delete(p.keyHash); return true;
    },
    async listPartners() { return [...partners.values()]; },
    // One-time registration codes, stored by hash with an expiry.
    async putOtp(hash, rec) { otps.set(hash, rec); },
    async getOtp(hash) { const r = otps.get(hash); return r && Date.parse(r.expiresAt) > Date.now() ? r : null; },
    async deleteOtp(hash) { otps.delete(hash); },
  };
}

/** Upstash Redis over its REST API (works on Vercel; set by the Upstash / Vercel KV integration). */
export function upstashStore({ url, token, prefix = 'tta:' }) {
  const cmd = async (...args) => {
    const res = await fetch(url.replace(/\/$/, ''), {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(args),
      signal: AbortSignal.timeout(4000),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || body.error) throw new Error(`store error: ${body.error ?? res.status}`);
    return body.result;
  };
  const k = (s) => prefix + s;
  return {
    kind: 'upstash',
    async nextTxId() {
      const day = new Date().toISOString().slice(0, 10);
      return txIdFrom(await cmd('INCR', k(`txseq:${day}`)));
    },
    async get(vcId) { const v = await cmd('GET', k(`vc:${vcId}`)); return v ? JSON.parse(v) : null; },
    async create(rec) {
      const ok = await cmd('SET', k(`vc:${rec.vcId}`), JSON.stringify(rec), 'NX');
      if (ok !== 'OK') return false;
      await cmd('SADD', k(`tx:${rec.txId}`), rec.vcId);
      return true;
    },
    async put(rec) { await cmd('SET', k(`vc:${rec.vcId}`), JSON.stringify(rec)); },
    async byTxId(txId) {
      const ids = (await cmd('SMEMBERS', k(`tx:${txId}`))) ?? [];
      const recs = await Promise.all(ids.map((id) => this.get(id)));
      return recs.filter(Boolean);
    },
    async partnerByKeyHash(h) {
      const did = await cmd('GET', k(`pkey:${h}`));
      return did ? this.partnerByDid(did) : null;
    },
    async partnerByDid(did) { const v = await cmd('GET', k(`partner:${did}`)); return v ? JSON.parse(v) : null; },
    async createPartner(p) {
      const ok = await cmd('SET', k(`partner:${p.did}`), JSON.stringify(p), 'NX');
      if (ok !== 'OK') return false;
      await cmd('SET', k(`pkey:${p.keyHash}`), p.did);
      await cmd('SADD', k('partners'), p.did);
      return true;
    },
    async deletePartner(did) {
      const p = await this.partnerByDid(did);
      if (!p) return false;
      await cmd('DEL', k(`partner:${did}`), k(`pkey:${p.keyHash}`));
      await cmd('SREM', k('partners'), did);
      return true;
    },
    async listPartners() {
      const dids = (await cmd('SMEMBERS', k('partners'))) ?? [];
      return (await Promise.all(dids.map((d) => this.partnerByDid(d)))).filter(Boolean);
    },
    async putOtp(hash, rec) {
      const ttl = Math.max(1, Math.ceil((Date.parse(rec.expiresAt) - Date.now()) / 1000));
      await cmd('SET', k(`otp:${hash}`), JSON.stringify(rec), 'EX', String(ttl));
    },
    async getOtp(hash) { const v = await cmd('GET', k(`otp:${hash}`)); return v ? JSON.parse(v) : null; },
    async deleteOtp(hash) { await cmd('DEL', k(`otp:${hash}`)); },
  };
}

/** Status as answered to partners: expired once validUntil has passed, else the stored status. */
export function effectiveStatus(rec, now = Date.now()) {
  if (!rec) return 'not_found';
  if (rec.status === 'active' && rec.validUntil && Date.parse(rec.validUntil) < now) return 'expired';
  return rec.status;
}
