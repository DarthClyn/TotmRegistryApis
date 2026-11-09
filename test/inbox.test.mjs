import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from '../src/api.js';
import { memoryRegistry } from '../src/registry.js';
import { memoryStore } from '../src/store.js';
import { memoryFiles } from '../src/files.js';
import { sha256Hex } from '../src/keys.js';

const PILA_KEY = 'tta_test_pila_key';
const ADMIN_KEY = 'tta_test_admin_key';
const PDF = Buffer.from('%PDF-1.4\n%test\n');
const JSONFILE = Buffer.from(JSON.stringify({ lcNumber: 'LC-1', amount: 100 }));

function setup({ files = memoryFiles(), maxBytes } = {}) {
  const lines = [];
  const app = buildApp({
    registry: memoryRegistry([]), store: memoryStore(), files, inbox: { maxBytes },
    partners: [{ name: 'PILA', did: 'did:nda:testnet:0xabc', type: 'verifier', keyHash: sha256Hex(PILA_KEY) }],
    adminKeyHash: sha256Hex(ADMIN_KEY), audit: (l) => lines.push(l),
  });
  const call = (method, url, { key, admin, body, type } = {}) => app.inject({
    method, url, payload: body,
    headers: { ...(key ? { 'x-api-key': key } : {}), ...(admin ? { 'x-admin-key': admin } : {}), ...(type ? { 'content-type': type } : {}) },
  });
  return { call, lines };
}
const send = (call, from, body, type, q = 'fileName=LC-1.pdf', auth = { key: PILA_KEY }) =>
  call('POST', `/api/v1/${from}/send?${q}`, { ...auth, body, type });

test('send from TOTM lands in the PILA inbox only; download returns the same bytes', async () => {
  const { call, lines } = setup();
  const s = await send(call, 'totm', PDF, 'application/pdf', 'fileName=LC-1.pdf&txId=TX-20261109-000001&note=hello', { admin: ADMIN_KEY });
  assert.equal(s.statusCode, 201);
  const rec = s.json().data;
  assert.equal(rec.from, 'totm');
  assert.equal(rec.to, 'pila');
  assert.equal(rec.sentBy, 'TOTM admin');
  assert.equal(rec.txId, 'TX-20261109-000001');

  assert.equal((await call('GET', '/api/v1/pila/inbox', { key: PILA_KEY })).json().data.count, 1);
  assert.equal((await call('GET', '/api/v1/totm/inbox', { key: PILA_KEY })).json().data.count, 0);
  assert.equal((await call('GET', '/api/v1/totm/sent', { admin: ADMIN_KEY })).json().data.files[0].fileId, rec.fileId);

  const d = await call('GET', `/api/v1/pila/inbox/${rec.fileId}`, { key: PILA_KEY });
  assert.equal(d.statusCode, 200);
  assert.equal(d.headers['content-type'], 'application/pdf');
  assert.equal(d.headers['x-file-sha256'], rec.sha256);
  assert.deepEqual(d.rawPayload, PDF);
  // Not reachable from the wrong inbox
  assert.equal((await call('GET', `/api/v1/totm/inbox/${rec.fileId}`, { key: PILA_KEY })).statusCode, 404);
  // Audit never carries the file name or content
  assert.ok(lines.every((l) => !JSON.stringify(l).includes('LC-1.pdf') && !JSON.stringify(l).includes('%PDF')));
});

test('send from PILA lands in the TOTM inbox; a JSON file is stored as-is, not parsed', async () => {
  const { call } = setup();
  const s = await send(call, 'pila', JSONFILE, 'application/json', 'fileName=elc.json');
  assert.equal(s.statusCode, 201);
  const id = s.json().data.fileId;
  const list = (await call('GET', '/api/v1/totm/inbox', { admin: ADMIN_KEY })).json().data;
  assert.equal(list.files[0].fileId, id);
  assert.equal(list.files[0].from, 'pila');
  const d = await call('GET', `/api/v1/totm/inbox/${id}`, { key: PILA_KEY });
  assert.deepEqual(d.rawPayload, JSONFILE);
});

test('ack sets readAt once and shows in the sender\'s sent box', async () => {
  const { call } = setup();
  const id = (await send(call, 'pila', PDF, 'application/pdf')).json().data.fileId;
  const a = await call('POST', `/api/v1/totm/inbox/${id}/ack`, { admin: ADMIN_KEY });
  assert.equal(a.statusCode, 200);
  const readAt = a.json().data.readAt;
  assert.ok(readAt);
  assert.equal((await call('POST', `/api/v1/totm/inbox/${id}/ack`, { key: PILA_KEY })).json().data.readAt, readAt);
  assert.equal((await call('GET', '/api/v1/pila/sent', { key: PILA_KEY })).json().data.files[0].readAt, readAt);
});

test('keys: either key works; none is refused; delete is admin only', async () => {
  const { call } = setup();
  assert.equal((await call('GET', '/api/v1/pila/inbox')).statusCode, 401);
  assert.equal((await call('GET', '/api/v1/pila/inbox', { key: 'wrong-key-wrong-key' })).statusCode, 401);
  assert.equal((await call('GET', '/api/v1/pila/inbox', { admin: 'wrong' })).statusCode, 401);
  const id = (await send(call, 'totm', PDF, 'application/pdf')).json().data.fileId;
  assert.equal((await call('DELETE', `/api/v1/pila/inbox/${id}`, { key: PILA_KEY })).statusCode, 401);
  const del = await call('DELETE', `/api/v1/pila/inbox/${id}`, { admin: ADMIN_KEY });
  assert.equal(del.statusCode, 200);
  assert.equal((await call('GET', `/api/v1/pila/inbox/${id}`, { key: PILA_KEY })).statusCode, 404);
  assert.equal((await call('GET', '/api/v1/pila/inbox', { key: PILA_KEY })).json().data.count, 0);
});

test('bad uploads are refused: type, content mismatch, no name, too large, unknown side', async () => {
  const { call } = setup({ maxBytes: 1024 });
  assert.equal((await send(call, 'pila', PDF, 'text/plain')).statusCode, 400);
  assert.equal((await send(call, 'pila', Buffer.from('not a pdf'), 'application/pdf')).statusCode, 400);
  assert.equal((await send(call, 'pila', Buffer.from('{bad'), 'application/json', 'fileName=x.json')).statusCode, 400);
  assert.equal((await send(call, 'pila', PDF, 'application/pdf', 'x=1')).statusCode, 400);
  assert.equal((await send(call, 'pila', Buffer.concat([PDF, Buffer.alloc(2000)]), 'application/pdf')).statusCode, 413);
  assert.equal((await send(call, 'bank', PDF, 'application/pdf')).statusCode, 404);
  assert.equal((await call('GET', '/api/v1/pila/inbox/not-a-uuid', { key: PILA_KEY })).statusCode, 404);
});

test('inbox off when no file store is configured', async () => {
  const { call } = setup({ files: null });
  const r = await call('GET', '/api/v1/pila/inbox', { key: PILA_KEY });
  assert.equal(r.statusCode, 503);
  assert.equal(r.json().code, 'E503');
});

test('expired files drop out of the list and their bytes are deleted', async () => {
  const files = memoryFiles();
  const { call } = setup({ files });
  const id = (await send(call, 'totm', PDF, 'application/pdf', 'fileName=a.pdf', { admin: ADMIN_KEY })).json().data.fileId;
  assert.ok(await files.get(`inbox/pila/${id}`));
  const realNow = Date.now;
  Date.now = () => realNow() + 31 * 86400_000;
  try {
    assert.equal((await call('GET', '/api/v1/pila/inbox', { key: PILA_KEY })).json().data.count, 0);
  } finally { Date.now = realNow; }
  assert.equal(await files.get(`inbox/pila/${id}`), null);
});
