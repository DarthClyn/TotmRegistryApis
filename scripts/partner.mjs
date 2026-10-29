// Partner onboarding, NDAKey style. Calls the admin endpoints of a running Trust API (TRUST_API_URL, ADMIN_API_KEY in .env).
//   npm run partner -- otp --name PILA --did did:nda:testnet:0x… --email ops@pila.example [--public-key 0x03…] [--hours 24]
//       -> prints a one-time code; send it to the partner privately. They then call POST /api/v1/verifier themselves
//          and receive their API key (TOTM never sees it).
//   npm run partner -- list
//   npm run partner -- revoke --did did:nda:testnet:0x…
const [cmd] = process.argv.slice(2);
const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const base = (process.env.TRUST_API_URL || 'http://127.0.0.1:4300').replace(/\/$/, '');
const key = process.env.ADMIN_API_KEY;
if (!key) throw new Error('ADMIN_API_KEY is not set (.env)');
const call = async (method, path, body) => {
  const res = await fetch(base + path, { method, headers: { 'x-admin-key': key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  console.log(res.status, JSON.stringify(await res.json(), null, 2));
};
if (cmd === 'otp') await call('POST', '/api/v1/admin/otps', { name: arg('name'), did: arg('did'), email: arg('email'), publicKeyHex: arg('public-key'), hours: arg('hours') });
else if (cmd === 'list') await call('GET', '/api/v1/admin/partners');
else if (cmd === 'revoke') await call('DELETE', `/api/v1/admin/partners/${encodeURIComponent(arg('did') ?? '')}`);
else console.log('Commands: otp | list | revoke (see the top of scripts/partner.mjs)');
