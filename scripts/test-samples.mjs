// Runs every sample eLC in a folder through the partner APIs, as PILA would call them:
// POST /vc/verify (integrity + issuer) and POST /vp/verification-context (issuer trusted + status), then prints a table.
// Live:  node --env-file=.env scripts/test-samples.mjs --dir "Sample VC" --key tta_…   (uses TRUST_API_URL)
// Local: node scripts/test-samples.mjs --dir "Sample VC" --local                       (in-memory, no network)
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const dir = arg('dir') ?? 'test-elcs';
const local = process.argv.includes('--local');
const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
const docs = files.map((f) => ({ file: f, vc: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));

let call;
if (local) {
  const { buildApp } = await import('../src/api.js');
  const { memoryRegistry } = await import('../src/registry.js');
  const { memoryStore } = await import('../src/store.js');
  const { sha256Hex } = await import('../src/keys.js');
  const bankDid = arg('bank-did') ?? 'did:key:zDnaekwEcNdmV6q5jW3LeDZYZokZhAr214p9aGxeotQuVM2Vm';
  const store = memoryStore();
  const app = buildApp({
    registry: memoryRegistry([{ did: bankDid, name: 'Bank Alpha ID', role: 'Issuing bank', bic: 'ALPHIDJA', signingKey: null, allowedDocs: ['eLC'], status: 'active', validFrom: null, validUntil: null }]),
    store, partners: [{ name: 'PILA', did: 'did:nda:testnet:0xtest', type: 'verifier', keyHash: sha256Hex('local') }], audit: () => {},
  });
  // Like the live store: every eLC Bank Alpha ID issued is registered once (same VC ID → one record).
  const seen = new Set();
  for (const { vc } of docs) {
    if (vc.issuer !== bankDid || seen.has(vc.id)) continue;
    seen.add(vc.id);
    await store.create({ vcId: vc.id, txId: await store.nextTxId(), issuerDid: vc.issuer, status: 'active', validUntil: vc.validUntil ?? null, createdAt: '', updatedAt: '' });
  }
  call = async (path, body) => (await app.inject({ method: 'POST', url: `/api/v1${path}`, payload: body, headers: { 'x-api-key': 'local' } })).json();
} else {
  const base = (process.env.TRUST_API_URL ?? '').replace(/\/$/, '');
  const key = arg('key') ?? process.env.PARTNER_API_KEY;
  if (!base || !key) { console.error('Set TRUST_API_URL in .env and pass --key tta_…'); process.exit(1); }
  call = async (path, body) => (await fetch(`${base}/api/v1${path}`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key }, body: JSON.stringify(body) })).json();
}

const rows = [];
for (const { file, vc } of docs) {
  const v = await call('/vc/verify', { vc });
  const c = await call('/vp/verification-context', { vcIds: [{ vcId: vc.id, issuerDid: vc.issuer }] });
  const ctx = c.data?.vcs?.[0] ?? c.data?.[0] ?? c.data;
  rows.push({
    file,
    integrity: v.data?.integrity?.result ?? v.error,
    issuer: v.data?.issuer?.result ?? v.error,
    trusted: ctx?.isIssuerTrusted ?? c.error,
    status: ctx?.status ?? c.error,
    txId: ctx?.txId ?? v.data?.txId ?? null,
  });
}
console.table(rows);
