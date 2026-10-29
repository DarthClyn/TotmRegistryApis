import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import ganache from 'ganache';
import { ContractFactory, JsonRpcProvider, Wallet } from 'ethers';
import { artifact, contractRegistry, toEntry } from '../src/registry.js';

const KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const OTHER = '0x' + '11'.repeat(32);
let server, rpc, c, owner, reader;
// ganache under-estimates calls that clear storage, and its 'pending' nonce can lag: set both explicitly.
let nonce = 0;
const G = async () => ({ gasLimit: 1_000_000, nonce: nonce++ });
const input = (o = {}) => ({ did: 'did:web:alpha.example', name: 'Bank Alpha ID', role: 'Issuing bank', bic: 'ALPHIDJA', signingKey: '0x02' + 'ab'.repeat(32), allowedDocs: ['eLC'], validFrom: 0, validUntil: 0, ...o });

before(async () => {
  server = ganache.server({ logging: { quiet: true }, chain: { chainId: 1337, hardfork: 'shanghai' },
    wallet: { accounts: [{ secretKey: KEY, balance: '0x56BC75E2D63100000' }, { secretKey: OTHER, balance: '0x56BC75E2D63100000' }] } });
  await server.listen(0);
  rpc = `http://127.0.0.1:${server.address().port}`;
  const p = new JsonRpcProvider(rpc, 1337, { staticNetwork: true });
  owner = new Wallet(KEY, p);
  c = await new ContractFactory(artifact.abi, artifact.bytecode, owner).deploy();
  await c.waitForDeployment();
  nonce = await p.getTransactionCount(owner.address, 'latest');
  reader = contractRegistry({ rpc, chainId: 1337, address: await c.getAddress() });
});
after(async () => { await server?.close(); });

test('add, read by DID and BIC, trusted for eLC', async () => {
  await (await c.addIssuer(input(), await G())).wait();
  const e = await reader.byDid('did:web:alpha.example');
  assert.equal(e.bic, 'ALPHIDJA');
  assert.equal(e.signingKey, '0x02' + 'ab'.repeat(32));
  assert.equal(e.status, 'active');
  assert.equal((await reader.byBic('ALPHIDJA')).did, 'did:web:alpha.example');
  assert.equal(await c.isTrusted('did:web:alpha.example', 'eLC'), true);
  assert.equal(await c.isTrusted('did:web:alpha.example', 'eBL'), false);
  assert.equal(await reader.byDid('did:web:nobody.example'), null);
});

test('BIC is unique, moves with updates and is freed on remove', async () => {
  await assert.rejects(c.addIssuer.staticCall(input({ did: 'did:web:beta.example' })), /BicTaken|revert/);
  await (await c.updateIssuer(input({ bic: 'ALPHIDJB' }), await G())).wait();
  assert.equal(await reader.byBic('ALPHIDJA'), null);
  assert.equal((await reader.byBic('ALPHIDJB')).did, 'did:web:alpha.example');
  await (await c.addIssuer(input({ did: 'did:web:beta.example', bic: 'ALPHIDJA', name: 'Bank Beta' }), await G())).wait();
  await (await c.removeIssuer('did:web:beta.example', await G())).wait();
  assert.equal(await reader.byBic('ALPHIDJA'), null);
  assert.equal(Number(await c.issuerCount()), 1);
});

test('status changes; only the owner can write', async () => {
  await (await c.setStatus('did:web:alpha.example', 2, await G())).wait();
  assert.equal((await reader.byDid('did:web:alpha.example')).status, 'suspended');
  assert.equal(await c.isTrusted('did:web:alpha.example', 'eLC'), false);
  const stranger = c.connect(new Wallet(OTHER, owner.provider));
  await assert.rejects(stranger.setStatus('did:web:alpha.example', 1), /NotOwner|revert/);
  assert.equal(toEntry({ status: 0n }), null);
});
