// eLC status records: VC ID -> { vcId, txId, issuerDid, status, validUntil, createdAt, updatedAt }.
// No eLC content is ever stored. Upstash Redis (REST) in production; memory for tests and local runs.

/** Audit lines kept (newest first). */
export const AUDIT_MAX = 10000;

/** Tx ID: TX-YYYYMMDD-NNNNNN from a daily counter. */
const txIdFrom = (n, d = new Date()) => `TX-${d.toISOString().slice(0, 10).replace(/-/g, '')}-${String(n).padStart(6, '0')}`;

export function memoryStore() {
  const vcs = new Map();
  const byTx = new Map();
  const counters = new Map();
  const partners = new Map();
  const partnerKeys = new Map();
  const otps = new Map();
  const files = new Map();
  const audit = [];
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
    /** All eLC records, newest first (IDs, status and dates only). */
    async listVcs(limit = 500) { return [...vcs.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, limit); },
    /** Audit lines (no document content), newest first. */
    async appendAudit(line) { audit.unshift(line); audit.length = Math.min(audit.length, AUDIT_MAX); },
    async listAudit(limit = 200, offset = 0) { return { total: audit.length, lines: audit.slice(offset, offset + limit) }; },
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
    // Inbox file records: { fileId, from, to, fileName, contentType, size, sha256, txId, vcId, note, sentBy, sentAt, readAt, expiresAt }.
    async createFile(rec) { files.set(rec.fileId, rec); },
    async getFile(id) { const r = files.get(id); return r && Date.parse(r.expiresAt) > Date.now() ? r : null; },
    async putFile(rec) { if (files.has(rec.fileId)) files.set(rec.fileId, rec); },
    async deleteFile(id) { return files.delete(id); },
    // Returns { files, gone }: gone = IDs whose record expired (their bytes can be deleted).
    async listFiles(box, side, limit = 100) {
      const now = Date.now();
      const mine = [...files.values()].filter((r) => (box === 'inbox' ? r.to : r.from) === side);
      const gone = mine.filter((r) => Date.parse(r.expiresAt) <= now).map((r) => r.fileId);
      gone.forEach((id) => files.delete(id));
      const list = mine.filter((r) => !gone.includes(r.fileId)).sort((a, b) => b.sentAt.localeCompare(a.sentAt)).slice(0, limit);
      return { files: list, gone };
    },
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
      await cmd('ZADD', k('vcs'), String(Date.parse(rec.createdAt) || Date.now()), rec.vcId);
      return true;
    },
    async put(rec) { await cmd('SET', k(`vc:${rec.vcId}`), JSON.stringify(rec)); },
    async byTxId(txId) {
      const ids = (await cmd('SMEMBERS', k(`tx:${txId}`))) ?? [];
      const recs = await Promise.all(ids.map((id) => this.get(id)));
      return recs.filter(Boolean);
    },
    /** All eLC records, newest first. Index "vcs" (sorted set); built once from the records if it is missing. */
    async listVcs(limit = 500) {
      if (!(await cmd('GET', k('vcs:indexed')))) {
        let cursor = '0';
        do {
          const [next, keys] = await cmd('SCAN', cursor, 'MATCH', k('vc:*'), 'COUNT', '200');
          cursor = String(next);
          if (keys.length) {
            const vals = await cmd('MGET', ...keys);
            for (const v of vals.filter(Boolean)) {
              const r = JSON.parse(v);
              await cmd('ZADD', k('vcs'), String(Date.parse(r.createdAt) || 0), r.vcId);
            }
          }
        } while (cursor !== '0');
        await cmd('SET', k('vcs:indexed'), new Date().toISOString());
      }
      const ids = (await cmd('ZREVRANGE', k('vcs'), '0', String(limit - 1))) ?? [];
      if (!ids.length) return [];
      const vals = await cmd('MGET', ...ids.map((id) => k(`vc:${id}`)));
      return vals.filter(Boolean).map((v) => JSON.parse(v));
    },
    /** Audit lines (no document content), newest first, capped at AUDIT_MAX. */
    async appendAudit(line) {
      await cmd('LPUSH', k('audit'), JSON.stringify(line));
      await cmd('LTRIM', k('audit'), '0', String(AUDIT_MAX - 1));
    },
    async listAudit(limit = 200, offset = 0) {
      const [total, rows] = await Promise.all([
        cmd('LLEN', k('audit')),
        cmd('LRANGE', k('audit'), String(offset), String(offset + limit - 1)),
      ]);
      return { total: Number(total) || 0, lines: (rows ?? []).map((r) => JSON.parse(r)) };
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
    // Inbox: record per file (expires with the file), plus a sorted set per inbox and per sent box (score = sent time).
    async createFile(rec) {
      const ttl = Math.max(1, Math.ceil((Date.parse(rec.expiresAt) - Date.now()) / 1000));
      const t = String(Date.parse(rec.sentAt));
      await cmd('SET', k(`file:${rec.fileId}`), JSON.stringify(rec), 'EX', String(ttl));
      await cmd('ZADD', k(`inbox:${rec.to}`), t, rec.fileId);
      await cmd('ZADD', k(`sent:${rec.from}`), t, rec.fileId);
    },
    async getFile(id) { const v = await cmd('GET', k(`file:${id}`)); return v ? JSON.parse(v) : null; },
    async putFile(rec) { await cmd('SET', k(`file:${rec.fileId}`), JSON.stringify(rec), 'XX', 'KEEPTTL'); },
    async deleteFile(id) {
      const rec = await this.getFile(id);
      if (!rec) return false;
      await cmd('DEL', k(`file:${id}`));
      await cmd('ZREM', k(`inbox:${rec.to}`), id);
      await cmd('ZREM', k(`sent:${rec.from}`), id);
      return true;
    },
    // Returns { files, gone }: gone = IDs older than cutoffMs or whose record expired (their bytes can be deleted).
    async listFiles(box, side, limit = 100, cutoffMs = 0) {
      const set = k(`${box}:${side}`);
      const old = cutoffMs ? (await cmd('ZRANGEBYSCORE', set, '-inf', String(cutoffMs))) ?? [] : [];
      if (old.length) await cmd('ZREMRANGEBYSCORE', set, '-inf', String(cutoffMs));
      const ids = (await cmd('ZREVRANGE', set, '0', String(limit - 1))) ?? [];
      const vals = ids.length ? await cmd('MGET', ...ids.map((id) => k(`file:${id}`))) : [];
      const missing = ids.filter((_, i) => !vals[i]);
      if (missing.length) await cmd('ZREM', set, ...missing);
      return { files: vals.filter(Boolean).map((v) => JSON.parse(v)), gone: [...old, ...missing] };
    },
  };
}

/** Status as answered to partners: expired once validUntil has passed, else the stored status. */
export function effectiveStatus(rec, now = Date.now()) {
  if (!rec) return 'not_found';
  if (rec.status === 'active' && rec.validUntil && Date.parse(rec.validUntil) < now) return 'expired';
  return rec.status;
}
