// Calls the admin endpoints of a running Trust API (TRUST_API_URL, ADMIN_API_KEY in .env). Examples:
//   npm run elc -- issue --file elc-fields.json [--holder did:…] [--issuer did:key:…] [--tx TX-…] [--out signed.json]
//   npm run elc -- register --vc-id urn:uuid:… --issuer did:web:… [--until 2027-01-31] [--tx TX-…]
//   npm run elc -- get --vc-id urn:uuid:…      |   tx --tx TX-20261029-000001
//   npm run elc -- suspend --vc-id urn:uuid:… [--reason "amendment"]
const [cmd] = process.argv.slice(2);
const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const base = (process.env.TRUST_API_URL || 'http://127.0.0.1:4300').replace(/\/$/, '');
const key = process.env.ADMIN_API_KEY;
if (!key) throw new Error('ADMIN_API_KEY is not set (.env)');
const call = async (method, path, body) => {
  const res = await fetch(base + path, { method, headers: { 'x-admin-key': key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const json = await res.json();
  return { status: res.status, json };
};
const print = ({ status, json }) => console.log(status, JSON.stringify(json, null, 2));
const id = encodeURIComponent(arg('vc-id') ?? '');
if (cmd === 'issue') {
  const { readFileSync, writeFileSync } = await import('node:fs');
  const data = JSON.parse(readFileSync(arg('file'), 'utf8'));
  const r = await call('POST', '/api/v1/admin/elc/issue', { data, holderDid: arg('holder'), issuerDid: arg('issuer'), txId: arg('tx') });
  if (r.status !== 201) print(r);
  else {
    const { vc, ...rest } = r.json.data;
    const out = arg('out') ?? `${(vc.credentialSubject?.lcNumber ?? 'eLC').replace(/[^\w.-]+/g, '_')}.json`;
    writeFileSync(out, JSON.stringify(vc, null, 2));
    console.log(201, JSON.stringify(rest, null, 2), `\nSigned eLC saved to ${out}`);
  }
} else if (cmd === 'register') print(await call('POST', '/api/v1/admin/vcs', { vcId: arg('vc-id'), issuerDid: arg('issuer'), validUntil: arg('until'), txId: arg('tx') }));
else if (cmd === 'get') print(await call('GET', `/api/v1/admin/vcs/${id}`));
else if (cmd === 'tx') print(await call('GET', `/api/v1/admin/tx/${encodeURIComponent(arg('tx') ?? '')}`));
else if (cmd === 'suspend') print(await call('POST', `/api/v1/admin/vcs/${id}/suspend`, { reason: arg('reason') }));
else console.log('Commands: issue | register | get | tx | suspend (see the top of scripts/elc.mjs)');
