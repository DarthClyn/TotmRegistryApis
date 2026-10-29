import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { buildApp } from '../src/api.js';
import { memoryRegistry } from '../src/registry.js';
import { memoryStore } from '../src/store.js';
import { sha256Hex } from '../src/keys.js';

const require = createRequire(import.meta.url);
const ADMIN = 'tta_admin'; const PILA = 'tta_pila';

test('Issuing API: signs with the bank key, registers Tx ID, and the eLC verifies', { timeout: 180000 }, async () => {
  const { generateDidKeyPair, CryptoSuite } = require('@trustvc/w3c-issuer');
  const { didKeyPairs: key } = await generateDidKeyPair(CryptoSuite.EcdsaSd2023);
  const did = key.controller;
  const lines = [];
  const app = buildApp({
    registry: memoryRegistry([{ did, name: 'Bank Alpha ID', role: 'Issuing bank', bic: 'ALPHIDJA', signingKey: null, allowedDocs: ['eLC'], status: 'active', validFrom: null, validUntil: null }]),
    store: memoryStore(), bankKeys: new Map([[did, key]]), adminKeyHash: sha256Hex(ADMIN),
    partners: [{ name: 'PILA', keyHash: sha256Hex(PILA) }], audit: (l) => lines.push(l),
  });
  const post = (url, body, h) => app.inject({ method: 'POST', url, payload: body, headers: h });
  const data = { lcNumber: 'LC-2026-10-0471', dateOfIssue: '2026-10-29', expiryDate: '2027-01-31', currency: 'USD', amount: '312000.00', beneficiaryName: 'Mekong Rice Export JSC', documentsRequired: 'Commercial invoice\nBill of lading', applicantBankName: 'Bank Alpha ID', nonsense: 'x' };

  assert.equal((await post('/api/v1/admin/elc/issue', { data }, { 'x-api-key': PILA })).statusCode, 401);
  assert.equal((await post('/api/v1/admin/elc/issue', { data: { dateOfIssue: '29/10/2026' } }, { 'x-admin-key': ADMIN })).statusCode, 400);
  assert.equal((await post('/api/v1/admin/elc/issue', { data, issuerDid: 'did:key:zOther' }, { 'x-admin-key': ADMIN })).statusCode, 403);

  const r = await post('/api/v1/admin/elc/issue', { data, holderDid: 'did:nda:testnet:0xabc' }, { 'x-admin-key': ADMIN });
  assert.equal(r.statusCode, 201, r.body);
  const out = r.json().data;
  assert.match(out.txId, /^TX-\d{8}-000001$/);
  assert.equal(out.issuerDid, did);
  assert.equal(out.issuerTrusted, true);
  assert.deepEqual(out.ignoredFields, ['nonsense']);
  assert.equal(out.vc.credentialSubject.applicantBank, 'Bank Alpha ID');
  assert.deepEqual(out.vc.credentialSubject.documentsRequired, ['Commercial invoice', 'Bill of lading']);
  assert.equal(out.validUntil, '2027-01-31T23:59:59Z');
  assert.equal(out.vcId, out.vc.id);

  const v = (await post('/api/v1/vc/verify', { vc: out.vc }, { 'x-api-key': PILA })).json().data;
  assert.equal(v.integrity.result, 'pass');
  assert.equal(v.issuer.result, 'pass');
  assert.equal(v.txId, out.txId);

  const c = (await post('/api/v1/vp/verification-context', { vcIds: [{ vcId: out.vcId, issuerDid: did, txId: out.txId }] }, { 'x-api-key': PILA })).json().data.vcs[0];
  assert.equal(c.status, 'active');
  assert.equal(c.isIssuerTrusted, true);
  assert.match(c.didPublicKey, /^0x0[23]/);

  const line = lines.find((l) => l.action === 'elc.issue' && l.outcome === 'ok');
  assert.equal(JSON.stringify(line).includes('Mekong'), false);
});
