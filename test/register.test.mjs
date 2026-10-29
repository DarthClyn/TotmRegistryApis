import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Wallet } from 'ethers';
import { buildApp } from '../src/app.js';
import { memoryRegistry } from '../src/registry.js';
import { memoryStore } from '../src/store.js';
import { sha256Hex } from '../src/keys.js';

const ADMIN = 'tta_admin_key_for_tests';

test('partner onboarding: OTP from TOTM, self-registration, key works, revoke stops it', async () => {
  const w = Wallet.createRandom();
  const did = `did:nda:testnet:${w.address.toLowerCase()}`;
  const publicKeyHex = w.signingKey.compressedPublicKey;
  const lines = [];
  const app = buildApp({ registry: memoryRegistry([]), store: memoryStore(), adminKeyHash: sha256Hex(ADMIN), audit: (l) => lines.push(l) });
  const call = (method, url, body, headers = {}) => app.inject({ method, url, payload: body, headers });
  const admin = { 'x-admin-key': ADMIN };

  // OTP only for admins; wrong key for the DID refused
  assert.equal((await call('POST', '/api/v1/admin/otps', { did, email: 'ops@pila.example' })).statusCode, 401);
  assert.equal((await call('POST', '/api/v1/admin/otps', { did, email: 'ops@pila.example', publicKeyHex: Wallet.createRandom().signingKey.compressedPublicKey }, admin)).statusCode, 400);
  const o = await call('POST', '/api/v1/admin/otps', { name: 'PILA', did, email: 'ops@pila.example', publicKeyHex }, admin);
  assert.equal(o.statusCode, 201);
  const { otp } = o.json().data;

  const reg = (over = {}) => call('POST', '/api/v1/verifier', { name: 'PILA', did, publicKeyHex, otp, email: 'ops@pila.example', ...over });
  assert.equal((await reg({ publicKeyHex: Wallet.createRandom().signingKey.compressedPublicKey })).json().error, 'publicKeyHex does not belong to this DID');
  assert.equal((await reg({ email: 'other@pila.example' })).statusCode, 401);
  assert.equal((await reg({ otp: 'dbba81f8-5c33-4b2f-bddd-802a21c07d2e' })).statusCode, 401);
  assert.equal((await reg({ email: 'not-an-email' })).statusCode, 400);

  const r = await reg();
  assert.equal(r.statusCode, 200);
  const { apiKey, type } = r.json().data;
  assert.equal(type, 'verifier');
  assert.match(apiKey, /^tta_/);
  assert.equal((await reg()).statusCode, 400); // already registered (and the OTP is used up)

  const me = await call('GET', '/api/v1/partners/me', null, { 'x-api-key': apiKey });
  assert.deepEqual(me.json().data, { did, name: 'PILA', type: 'verifier' });
  const listed = (await call('GET', '/api/v1/admin/partners', null, admin)).json().data;
  assert.equal(listed.length, 1);
  assert.equal('keyHash' in listed[0], false);
  assert.equal(JSON.stringify(lines).includes(apiKey), false);
  assert.equal(JSON.stringify(lines).includes(otp), false);

  assert.equal((await call('DELETE', `/api/v1/admin/partners/${encodeURIComponent(did)}`, null, admin)).statusCode, 200);
  assert.equal((await call('GET', '/api/v1/partners/me', null, { 'x-api-key': apiKey })).statusCode, 401);
});

test('OTP expires', async () => {
  const store = memoryStore();
  const app = buildApp({ registry: memoryRegistry([]), store, adminKeyHash: sha256Hex(ADMIN), audit: () => {} });
  const w = Wallet.createRandom();
  const did = `did:nda:testnet:${w.address}`;
  await store.putOtp(sha256Hex('old-otp'), { did, email: 'a@b.co', expiresAt: new Date(Date.now() - 1000).toISOString() });
  const r = await app.inject({ method: 'POST', url: '/api/v1/verifier', payload: { name: 'X', did, publicKeyHex: w.signingKey.compressedPublicKey, otp: 'old-otp', email: 'a@b.co' } });
  assert.equal(r.statusCode, 401);
});
