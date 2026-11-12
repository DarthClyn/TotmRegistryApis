// Sending an issued eLC to the advising bank's inbox. The advising bank is on PILA (Bank Beta VN, BIC BETAVNVX): its
// Beta Inbox API (PILA guide "Beta Inbox API – Integration Guide for TOTM", 12 Nov 2026) takes
//   POST {PILA_INBOX_URL}  X-API-Key: <inbox key>  {txId, senderDid, vc, sentAt}  -> 202 {txId, status: RECEIVED}
// and later answers GET {PILA_INBOX_URL}/{txId} with {status: CONCLUDED, decision: PASS | FAIL, reasons}.
// PILA checks the sender in our registry, the signature, the eLC's status in our registry (same txId) and that the
// eLC names BETAVNVX as advising bank, so we check the same before sending. The eLC is passed through, never stored.

const DEFAULT_URL = 'https://elc-beta.ndakey.vn/api/v1/elc/inbox';
const MAX_BYTES = 1024 * 1024; // PILA rejects larger bodies (413 E7005)

export function pilaInboxFromEnv(env = process.env) {
  if (!env.PILA_INBOX_KEY) return null;
  return {
    url: (env.PILA_INBOX_URL || DEFAULT_URL).replace(/\/$/, ''),
    key: env.PILA_INBOX_KEY,
    bic: (env.PILA_INBOX_BIC || 'BETAVNVX').toUpperCase(),
    name: env.PILA_INBOX_BANK_NAME || 'Bank Beta VN',
  };
}

/** Routes: POST /api/v1/admin/elc/send and GET /api/v1/admin/elc/send/:txId (admin key, i.e. the portal). */
export function sendRoutes(app, { store, inbox, requireAdmin, audited, ApiError, ok, bad, fetchImpl = fetch }) {
  const need = () => { if (!inbox) throw new ApiError(503, 'E503', 'Sending to the advising bank is not configured (PILA_INBOX_KEY)'); };
  const call = async (method, url, body, requestId) => {
    let res;
    try {
      res = await fetchImpl(url, {
        method,
        headers: { 'x-api-key': inbox.key, ...(body ? { 'content-type': 'application/json' } : {}), ...(requestId ? { 'x-request-id': requestId } : {}) },
        body,
        signal: AbortSignal.timeout(20000),
      });
    } catch (e) {
      throw new ApiError(502, 'E502', `PILA inbox not reachable: ${e.name === 'TimeoutError' ? 'timed out' : e.message}`);
    }
    const json = await res.json().catch(() => ({}));
    return { status: res.status, json };
  };

  app.post('/api/v1/admin/elc/send', { preHandler: requireAdmin }, async (req, reply) => {
    need();
    const { txId, vc } = req.body ?? {};
    if (typeof txId !== 'string' || !txId) throw bad('txId is required');
    if (!vc || typeof vc !== 'object' || !vc.proof) throw bad('vc (the signed eLC, with its proof) is required');

    // Same checks PILA will make, so a send never fails for a reason we can see here.
    const rec = typeof vc.id === 'string' ? await store.get(vc.id) : null;
    if (!rec) throw bad('This eLC is not in the TOTM registry; issue or register it first');
    if (rec.txId !== txId) throw bad(`txId does not match the registry (${rec.txId})`);
    if (rec.status !== 'active') throw bad(`Only active eLCs can be sent (this one is ${rec.status})`);
    const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id;
    if (issuer !== rec.issuerDid) throw bad('The eLC issuer does not match the registry');
    const advising = String(vc.credentialSubject?.advisingBankBic ?? '').toUpperCase();
    if (advising !== inbox.bic) throw bad(`The eLC's advising bank must be ${inbox.name} (${inbox.bic}); it names ${advising || 'no advising bank BIC'}`);

    const sentAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const body = JSON.stringify({ txId, senderDid: rec.issuerDid, vc, sentAt });
    if (Buffer.byteLength(body) > MAX_BYTES) throw bad(`The eLC is ${(Buffer.byteLength(body) / 1048576).toFixed(1)} MB; ${inbox.name}'s inbox takes at most 1 MB. Issue it without the PDF copy or large attachments.`);

    const r = await call('POST', inbox.url, body, req.id);
    const d = r.json?.data ?? {};
    if (r.status !== 202 && r.status !== 200) {
      audited(req, 'elc.send', 'failed', { vcId: rec.vcId, txId, to: inbox.bic, http: r.status, code: r.json?.code ?? null });
      throw new ApiError(r.status === 401 ? 502 : r.status >= 500 ? 502 : 400, r.json?.code ?? 'E502',
        `${inbox.name} did not accept the eLC (${r.status}${r.json?.code ? ` ${r.json.code}` : ''}): ${r.json?.error ?? r.json?.message ?? 'no details'}`);
    }
    const sent = { to: inbox.bic, toName: inbox.name, via: 'PILA', at: sentAt, status: d.status ?? 'RECEIVED', pilaRequestId: d.requestId ?? null, receivedAt: d.receivedAt ?? null };
    await store.put({ ...rec, sent, updatedAt: new Date().toISOString() });
    audited(req, 'elc.send', 'ok', { vcId: rec.vcId, txId, to: inbox.bic, pilaRequestId: sent.pilaRequestId });
    reply.code(202);
    return ok({ txId, vcId: rec.vcId, ...sent });
  });

  // PILA's verification result for a sent eLC. PILA opens this lookup in its next release; until then it answers 404.
  app.get('/api/v1/admin/elc/send/:txId', { preHandler: requireAdmin }, async (req) => {
    need();
    const r = await call('GET', `${inbox.url}/${encodeURIComponent(req.params.txId)}`, undefined, req.id);
    if (r.status === 404) return ok({ txId: req.params.txId, status: 'PENDING', available: false, note: `${inbox.name} has no result for this txId yet (PILA's result lookup may not be open yet)` });
    if (r.status !== 200) throw new ApiError(502, r.json?.code ?? 'E502', `${inbox.name}'s result lookup failed (${r.status}): ${r.json?.error ?? 'no details'}`);
    const d = r.json?.data ?? {};
    const recs = await store.byTxId(req.params.txId);
    for (const rec of recs) if (rec.sent) await store.put({ ...rec, sent: { ...rec.sent, status: d.status, decision: d.decision ?? null, reasons: d.reasons ?? [] } });
    return ok({ txId: req.params.txId, available: true, status: d.status, decision: d.decision ?? null, reasons: d.reasons ?? [], concludedAt: d.concludedAt ?? null });
  });
}
