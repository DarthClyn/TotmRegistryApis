// Registers a partner with its OTP (what a partner does on its side), so you can test the flow yourself.
// Usage: npm run register -- --name "TOTM Technologies Group" --did did:nda:testnet:0x… --public-key 0x03… --email … --otp <otp>
const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const base = (process.env.TRUST_API_URL || 'http://127.0.0.1:4300').replace(/\/$/, '');
const body = { name: arg('name'), did: arg('did'), publicKeyHex: arg('public-key'), email: arg('email'), otp: arg('otp') };
const res = await fetch(`${base}/api/v1/verifier`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
const json = await res.json();
console.log(res.status, JSON.stringify(json, null, 2));
if (json.data?.apiKey) console.log('\nSave this API key now (shown once). Keep it out of the server settings and out of git.');
