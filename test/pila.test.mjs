import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, chmodSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildApp } from '../src/api.js';
import { memoryRegistry } from '../src/registry.js';
import { memoryStore } from '../src/store.js';
import { sha256Hex } from '../src/keys.js';
import { childVerifier, pilaClient } from '../src/pila.js';

const PILA_KEY = 'tta_test_pila_key';
const ADMIN_KEY = 'tta_test_admin_key';
const setup = (pila) => {
  const lines = [];
  const app = buildApp({
    registry: memoryRegistry([]), store: memoryStore(), pila,
    partners: [{ name: 'PILA', did: 'did:nda:testnet:0xabc', type: 'verifier', keyHash: sha256Hex(PILA_KEY) }],
    adminKeyHash: sha256Hex(ADMIN_KEY), audit: (l) => lines.push(l),
  });
  return { app, lines };
};
const sdkAnswer = { format: 'jwt', id: 'urn:uuid:1', issuer: 'did:nda:testnet:0x1', checks: { issuer: { passed: true }, signature: { passed: true }, expiration: { passed: true }, revocation: { passed: true, skipped: true } }, ndakey: { called: true, status: 'active', isIssuerTrusted: true }, subject: { lcNumber: 'LC-1' }, sdk: 'test' };
const fake = (status, body) => ({ kind: 'fake', start: async () => {}, stop() {}, verify: async () => ({ status, body }), health: async () => ({ status: 200, body: { ok: true } }) });

test('PILA verify: 503 when no verifier is configured', async () => {
  const { app } = setup(null);
  const r = await app.inject({ method: 'POST', url: '/api/v1/pila/verify', headers: { 'x-admin-key': ADMIN_KEY }, payload: { credential: 'a.b.c' } });
  assert.equal(r.statusCode, 503);
});

test('PILA verify: needs a key, passes the result through, audits without content', async () => {
  const { app, lines } = setup(fake(200, sdkAnswer));
  const none = await app.inject({ method: 'POST', url: '/api/v1/pila/verify', payload: { credential: 'a.b.c' } });
  assert.equal(none.statusCode, 401);
  for (const headers of [{ 'x-admin-key': ADMIN_KEY }, { 'x-api-key': PILA_KEY }]) {
    const r = await app.inject({ method: 'POST', url: '/api/v1/pila/verify', headers, payload: { credential: 'a.b.c' } });
    assert.equal(r.statusCode, 200);
    assert.equal(r.json().code, 'E00');
    assert.equal(r.json().data.ndakey.status, 'active');
  }
  const line = lines.find((l) => l.action === 'pila.verify');
  assert.equal(line.outcome, 'ok');
  assert.equal(line.vcId, 'urn:uuid:1');
  assert.ok(!JSON.stringify(lines).includes('LC-1'), 'no credential content in audit');
});

test('PILA verify: missing credential is 400; verifier errors map to 400/503', async () => {
  assert.equal((await setup(fake(200, sdkAnswer)).app.inject({ method: 'POST', url: '/api/v1/pila/verify', headers: { 'x-admin-key': ADMIN_KEY }, payload: {} })).statusCode, 400);
  assert.equal((await setup(fake(400, { error: 'not a credential' })).app.inject({ method: 'POST', url: '/api/v1/pila/verify', headers: { 'x-admin-key': ADMIN_KEY }, payload: { credential: 'x' } })).statusCode, 400);
  assert.equal((await setup(fake(503, { error: 'down' })).app.inject({ method: 'POST', url: '/api/v1/pila/verify', headers: { 'x-admin-key': ADMIN_KEY }, payload: { credential: 'x' } })).statusCode, 503);
});

test('PILA verify: unreachable remote verifier answers 503', async () => {
  const r = await pilaClient({ kind: 'remote', url: 'http://127.0.0.1:9' }).verify('x');
  assert.equal(r.status, 503);
});

test('child verifier: started with a token, only PILA_* settings, restarted after a crash', async () => {
  // Stand-in for bin/pila-verifier: a tiny HTTP server that checks the token and reports its environment.
  const dir = mkdtempSync(join(tmpdir(), 'pv-'));
  const js = join(dir, 'fake.mjs');
  writeFileSync(js, `import http from 'node:http';
let n = 0;
http.createServer((q, s) => {
  if (q.url === '/health') return s.end('{"ok":true}');
  if (q.headers['x-verifier-token'] !== process.env.PILA_VERIFIER_TOKEN) { s.statusCode = 401; return s.end('{"error":"token"}'); }
  if (++n === 2) process.exit(3);
  s.end(JSON.stringify({ env: Object.keys(process.env).filter((k) => /SECRET|ADMIN|PILA/.test(k)), pid: process.pid }));
}).listen(Number(process.env.PORT), process.env.HOST);`);
  const bin = join(dir, 'pila-verifier');
  writeFileSync(bin, `#!/bin/sh\nexec "${process.execPath}" "${js}"\n`);
  chmodSync(bin, 0o755);
  const logs = [];
  const v = childVerifier({ bin, port: 4199, env: { ...process.env, PILA_PARTNER_API_KEY: 'k', ADMIN_API_KEY_HASH: 'secret' }, log: { info: (m) => logs.push(m), error: (m) => logs.push(m) } });
  await v.start();
  try {
    const a = await v.verify('x');
    assert.equal(a.status, 200);
    assert.deepEqual(a.body.env.sort(), ['PILA_PARTNER_API_KEY', 'PILA_VERIFIER_TOKEN']);
    const crash = await v.verify('x'); // the stand-in exits on its 2nd call
    assert.equal(crash.status, 503);
    let again;
    for (let i = 0; i < 20; i++) { again = await v.verify('x'); if (again.status === 200) break; await new Promise((r) => setTimeout(r, 250)); }
    assert.equal(again.status, 200);
    assert.notEqual(again.body.pid, a.body.pid);
    const direct = await fetch('http://127.0.0.1:4199/verify', { method: 'POST', body: '{}' });
    assert.equal(direct.status, 401, 'no token, no answer');
  } finally {
    v.stop();
  }
});
