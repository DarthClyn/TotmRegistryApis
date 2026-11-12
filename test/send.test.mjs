import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from '../src/api.js';
import { memoryRegistry } from '../src/registry.js';
import { memoryStore } from '../src/store.js';
import { sha256Hex } from '../src/keys.js';

const ADMIN_KEY = 'tta_test_admin_key';
const ISSUER = 'did:key:zDnaekwEcNdmV6q5jW3LeDZYZokZhAr214p9aGxeotQuVM2Vm';
const inbox = { url: 'https://pila.test/api/v1/elc/inbox', key: 'inbox-key', bic: 'BETAVNVX', name: 'Bank Beta VN' };
const vc = (over = {}) => ({ id: 'urn:uuid:1', issuer: ISSUER, credentialSubject: { lcNumber: 'LC-1', advisingBankBic: 'BETAVNVX', ...over }, proof: { type: 'DataIntegrityProof' } });

async function setup(pilaAnswer = { status: 202, json: { code: 'E00', data: { txId: 'TX-1', status: 'RECEIVED', requestId: 'req-1', receivedAt: '2026-11-12T06:43:16Z' } } }) {
  const store = memoryStore();
  await store.create({ vcId: 'urn:uuid:1', txId: 'TX-1', issuerDid: ISSUER, status: 'active', createdAt: 'x', updatedAt: 'x' });
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, init }); return { status: pilaAnswer.status, json: async () => pilaAnswer.json }; };
  const lines = [];
  const app = buildApp({ registry: memoryRegistry([]), store, adminKeyHash: sha256Hex(ADMIN_KEY), pilaInbox: inbox, fetchImpl, audit: (l) => lines.push(l) });
  const send = (body) => app.inject({ method: 'POST', url: '/api/v1/admin/elc/send', headers: { 'x-admin-key': ADMIN_KEY }, payload: body });
  return { app, store, calls, lines, send };
}

test('send: forwards {txId, senderDid, vc, sentAt} with the inbox key and records the send', async () => {
  const { send, calls, store, lines } = await setup();
  const r = await send({ txId: 'TX-1', vc: vc() });
  assert.equal(r.statusCode, 202);
  assert.equal(r.json().data.status, 'RECEIVED');
  assert.equal(calls[0].url, inbox.url);
  assert.equal(calls[0].init.headers['x-api-key'], 'inbox-key');
  const body = JSON.parse(calls[0].init.body);
  assert.deepEqual(Object.keys(body).sort(), ['senderDid', 'sentAt', 'txId', 'vc']);
  assert.equal(body.senderDid, ISSUER);
  assert.match(body.sentAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.equal((await store.get('urn:uuid:1')).sent.to, 'BETAVNVX');
  assert.ok(!JSON.stringify(lines).includes('LC-1'), 'no eLC content in audit');
});

test('send: refuses what PILA would refuse, before calling it', async () => {
  const { send, calls } = await setup();
  assert.equal((await send({ txId: 'TX-2', vc: vc() })).statusCode, 400); // txId mismatch
  assert.equal((await send({ txId: 'TX-1', vc: vc({ advisingBankBic: 'BANKAVNX' }) })).statusCode, 400);
  assert.equal((await send({ txId: 'TX-1', vc: { ...vc(), id: 'urn:uuid:unknown' } })).statusCode, 400);
  assert.equal((await send({ txId: 'TX-1', vc: { ...vc(), proof: undefined } })).statusCode, 400);
  assert.equal((await send({ txId: 'TX-1', vc: vc({ big: 'x'.repeat(1100000) }) })).statusCode, 400);
  assert.equal(calls.length, 0);
});

test('send: PILA refusals and the result lookup', async () => {
  const refused = await setup({ status: 401, json: { code: 'E15', error: 'Missing or invalid X-API-Key' } });
  const r = await refused.send({ txId: 'TX-1', vc: vc() });
  assert.equal(r.statusCode, 502);
  assert.match(r.json().error, /E15/);

  const notYet = await setup({ status: 404, json: { code: 'E404' } });
  const g = await notYet.app.inject({ method: 'GET', url: '/api/v1/admin/elc/send/TX-1', headers: { 'x-admin-key': ADMIN_KEY } });
  assert.equal(g.json().data.available, false);
});

test('send: not configured without PILA_INBOX_KEY', async () => {
  const app = buildApp({ registry: memoryRegistry([]), store: memoryStore(), adminKeyHash: sha256Hex(ADMIN_KEY) });
  const r = await app.inject({ method: 'POST', url: '/api/v1/admin/elc/send', headers: { 'x-admin-key': ADMIN_KEY }, payload: { txId: 'TX-1', vc: vc() } });
  assert.equal(r.statusCode, 503);
});
