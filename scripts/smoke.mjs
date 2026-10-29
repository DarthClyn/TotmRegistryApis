// End-to-end check of the partner APIs against a running Trust API, with a partner key.
// Usage: npm run smoke -- --key tta_… --file LC-2026-10-0471.json     (TRUST_API_URL from .env, default local)
import { readFileSync } from 'node:fs';
const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const base = (process.env.TRUST_API_URL || 'http://127.0.0.1:4300').replace(/\/$/, '') + '/api/v1';
const key = arg('key') ?? process.env.TEST_API_KEY;
if (!key || !arg('file')) { console.log('Usage: npm run smoke -- --key tta_… --file <signed eLC .json>'); process.exit(1); }
const vc = JSON.parse(readFileSync(arg('file'), 'utf8'));
const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id;
const call = async (label, method, path, body) => {
  const res = await fetch(base + path, { method, headers: { 'x-api-key': key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const json = await res.json().catch(() => ({}));
  console.log(`\n== ${label}: HTTP ${res.status}`);
  console.log(JSON.stringify(json.data ?? json, null, 2).slice(0, 1500));
  return json.data;
};
await call('Health', 'GET', '/health');
await call('My key', 'GET', '/partners/me');
await call('Issuer DID lookup', 'GET', `/dids/${encodeURIComponent(issuer)}`);
const ctx = await call('Verification context', 'POST', '/vp/verification-context', { vcIds: [{ vcId: vc.id, issuerDid: issuer }] });
const ver = await call('Content verify', 'POST', '/vc/verify', { vc });
const c = ctx?.vcs?.[0];
const pass = c?.status === 'active' && c?.isIssuerTrusted && c?.didPublicKey && ver?.integrity?.passed && ver?.issuer?.passed;
console.log(`\nOverall: ${pass ? 'PASS' : 'FAIL'} (status ${c?.status}, issuer trusted ${c?.isIssuerTrusted}, integrity ${ver?.integrity?.result}, issuer ${ver?.issuer?.result}, Tx ID ${c?.txId})`);
