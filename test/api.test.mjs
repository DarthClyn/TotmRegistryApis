import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildApp } from '../src/app.js';
import { memoryRegistry } from '../src/registry.js';
import { memoryStore } from '../src/store.js';
import { sha256Hex } from '../src/keys.js';

const fx = (n) => JSON.parse(readFileSync(new URL(`fixtures/${n}.json`, import.meta.url), 'utf8'));
const valid = fx('elc-valid');
const BANK_DID = valid.issuer; // did:key P-256 of the demo bank
const PILA_KEY = 'tta_test_pila_key';
const ADMIN_KEY = 'tta_test_admin_key';
const bank = (over = {}) => ({ did: BANK_DID, name: 'Bank Alpha ID', role: 'Issuing bank', bic: 'ALPHIDJA', signingKey: null, allowedDocs: ['eLC'], status: 'active', validFrom: null, validUntil: null, ...over });

function setup(entries = [bank()]) {
  const lines = [];
  const app = buildApp({
    registry: memoryRegistry(entries), store: memoryStore(),
    partners: [{ name: 'PILA', did: 'did:nda:testnet:0xabc', type: 'verifier', keyHash: sha256Hex(PILA_KEY) }],
    adminKeyHash: sha256Hex(ADMIN_KEY), audit: (l) => lines.push(l),
  });
  const call = (method, url, { key, admin, body, headers = {} } = {}) => app.inject({
    method, url, payload: body,
    headers: { ...(key ? { 'x-api-key': key } : {}), ...(admin ? { 'x-admin-key': admin } : {}), ...headers },
  });
  return { app, call, lines };
}
const register = (call, extra = {}) => call('POST', '/api/v1/admin/vcs', { admin: ADMIN_KEY, body: { vcId: valid.id, issuerDid: BANK_DID, validUntil: '2099-01-01', ...extra } });
const ctx = (call, vcIds, key = PILA_KEY) => call('POST', '/api/v1/vp/verification-context', { key, body: { vcIds } });

test('DID lookup: public, NDAKey shape, key taken from did:key', async () => {
  const { call } = setup();
  const r = await call('GET', `/api/v1/dids/${encodeURIComponent(BANK_DID)}`);
  assert.equal(r.statusCode, 200);
  const b = r.json();
  assert.equal(b.code, 'E00');
  assert.equal(b.data.type, 'issuer');
  assert.match(b.data.publicKey, /^0x0[23][0-9a-f]{64}$/);
  assert.equal(b.data.bic, 'ALPHIDJA');
  assert.equal(b.data.isTrusted, true);
  const nf = await call('GET', '/api/v1/dids/did:web:nobody.example');
  assert.equal(nf.statusCode, 404);
  assert.deepEqual(nf.json(), { code: 'E02', error: 'DID not found' });
  assert.equal((await call('GET', '/api/v1/banks/alphidja')).json().data.did, BANK_DID);
});

test('partner key: missing or wrong key is refused and audited; partners/me answers', async () => {
  const { call, lines } = setup();
  for (const key of [undefined, 'wrong']) {
    const r = await call('GET', '/api/v1/partners/me', { key });
    assert.equal(r.statusCode, 401);
    assert.equal(r.json().code, 'E15');
  }
  assert.equal(lines.filter((l) => l.action === 'auth.partner' && l.outcome === 'denied').length, 2);
  const me = await call('GET', '/api/v1/partners/me', { key: PILA_KEY });
  assert.deepEqual(me.json().data, { did: 'did:nda:testnet:0xabc', name: 'PILA', type: 'verifier' });
});

test('verification-context: active + trusted with Tx ID, request ID echoed, audit has IDs only', async () => {
  const { call, lines } = setup();
  const reg = await register(call);
  assert.equal(reg.statusCode, 201);
  const txId = reg.json().data.txId;
  assert.match(txId, /^TX-\d{8}-000001$/);
  const rid = '3f2a9c14-8d51-4f0b-9c2e-6b1d0a7e5c38';
  const r = await call('POST', '/api/v1/vp/verification-context', { key: PILA_KEY, headers: { 'x-request-id': rid }, body: { vcIds: [{ vcId: valid.id, issuerDid: BANK_DID }] } });
  assert.equal(r.statusCode, 200);
  assert.equal(r.headers['x-request-id'], rid);
  const d = r.json().data;
  assert.equal(d.requestId, rid);
  assert.equal(d.holderPublicKey, null);
  assert.deepEqual({ ...d.vcs[0], didPublicKey: !!d.vcs[0].didPublicKey }, { vcid: valid.id, txId, didPublicKey: true, isIssuerTrusted: true, status: 'active' });
  const line = lines.find((l) => l.action === 'vp.verification-context');
  assert.equal(line.partner, 'PILA');
  assert.equal(JSON.stringify(line).includes('credentialSubject'), false);
});

test('verification-context: not_found, wrong issuer, wrong Tx ID, suspended, expired, untrusted issuer', async () => {
  const { call } = setup([bank({ status: 'suspended' })]);
  let r = await ctx(call, [{ vcId: 'urn:uuid:unknown', issuerDid: BANK_DID }]);
  assert.equal(r.json().data.vcs[0].status, 'not_found');
  assert.equal(r.json().data.vcs[0].isIssuerTrusted, false); // bank suspended in the registry
  await register(call);
  r = await ctx(call, [{ vcId: valid.id, issuerDid: 'did:web:other.example' }, { vcId: valid.id, issuerDid: BANK_DID, txId: 'TX-WRONG' }]);
  assert.deepEqual(r.json().data.vcs.map((v) => v.status), ['not_found', 'not_found']);
  assert.equal(r.json().data.vcs[0].didPublicKey, null);
  const s = await call('POST', `/api/v1/admin/vcs/${encodeURIComponent(valid.id)}/suspend`, { admin: ADMIN_KEY, body: { reason: 'amendment' } });
  assert.equal(s.json().data.status, 'suspended');
  assert.equal((await call('POST', `/api/v1/admin/vcs/${encodeURIComponent(valid.id)}/suspend`, { admin: ADMIN_KEY })).statusCode, 409);
  assert.equal((await ctx(call, [{ vcId: valid.id, issuerDid: BANK_DID }])).json().data.vcs[0].status, 'suspended');
  await call('POST', '/api/v1/admin/vcs', { admin: ADMIN_KEY, body: { vcId: 'urn:uuid:old', issuerDid: BANK_DID, validUntil: '2020-01-01' } });
  assert.equal((await ctx(call, [{ vcId: 'urn:uuid:old', issuerDid: BANK_DID }])).json().data.vcs[0].status, 'expired');
});

test('verification-context: malformed bodies get 400 E400', async () => {
  const { call } = setup();
  for (const body of [{}, { vcIds: [] }, { vcIds: [{ vcId: 1 }] }, { vcIds: Array(51).fill({ vcId: 'a', issuerDid: 'b' }) }]) {
    const r = await call('POST', '/api/v1/vp/verification-context', { key: PILA_KEY, body });
    assert.equal(r.statusCode, 400);
    assert.equal(r.json().code, 'E400');
  }
});

test('vc/verify: real TrustVC check of a valid and a tampered eLC', { timeout: 120000 }, async () => {
  const { call } = setup();
  await register(call);
  const ok = (await call('POST', '/api/v1/vc/verify', { key: PILA_KEY, body: { vc: valid } })).json().data;
  assert.equal(ok.integrity.result, 'pass');
  assert.equal(ok.issuer.result, 'pass');
  assert.equal(ok.issuerDid, BANK_DID);
  assert.match(ok.txId, /^TX-/);
  const bad = (await call('POST', '/api/v1/vc/verify', { key: PILA_KEY, body: { vc: fx('elc-tampered') } })).json().data;
  assert.equal(bad.integrity.result, 'fail');
  const junk = await call('POST', '/api/v1/vc/verify', { key: PILA_KEY, body: { vc: { hello: 1 } } });
  assert.equal(junk.statusCode, 400);
  assert.equal((await call('POST', '/api/v1/vc/verify', { body: { vc: valid } })).statusCode, 401);
});

test('admin: key required, duplicate VC refused, given Tx ID kept for an amendment, Tx lookup', async () => {
  const { call } = setup();
  assert.equal((await call('POST', '/api/v1/admin/vcs', { key: PILA_KEY, body: { vcId: 'x', issuerDid: BANK_DID } })).statusCode, 401);
  const first = (await register(call)).json().data;
  assert.equal((await register(call)).statusCode, 409);
  const amended = await call('POST', '/api/v1/admin/vcs', { admin: ADMIN_KEY, body: { vcId: 'urn:uuid:v2', issuerDid: BANK_DID, txId: first.txId } });
  assert.equal(amended.json().data.txId, first.txId);
  const tx = (await call('GET', `/api/v1/admin/tx/${first.txId}`, { admin: ADMIN_KEY })).json().data;
  assert.equal(tx.vcs.length, 2);
});
