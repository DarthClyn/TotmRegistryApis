// Registry admin CLI (owner wallet signs). Examples:
//   npm run registry -- add --did did:web:bank-b.example --name "Bank Alpha ID" --role "Issuing bank" --bic ALPHIDJA --docs eLC
//   npm run registry -- update --did … (same options; all fields are replaced)
//   npm run registry -- status --did … --to suspended|active|revoked
//   npm run registry -- remove --did …
//   npm run registry -- get --did …   |   get --bic ALPHIDJA   |   list
// --signing-key 0x02… is optional for did:key DIDs (taken from the DID). --from / --until take dates (YYYY-MM-DD).
import { chainIdFrom, deployedAddress, ownerWallet, provider, registryContract } from './chain.mjs';
import { publicKeyFromDidKey } from '../src/keys.js';
import { toEntry } from '../src/registry.js';

const [cmd] = process.argv.slice(2);
const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const secs = (d) => (d ? Math.floor(Date.parse(d) / 1000) : 0);
const chainId = chainIdFrom(arg('chain'));
const p = await provider(chainId);
const address = deployedAddress(chainId);

const read = registryContract(p, address);
const show = (e) => console.log(JSON.stringify(toEntry(e) ?? { registered: false }, null, 2));

if (cmd === 'get') {
  show(arg('bic') ? await read.getIssuerByBic(arg('bic').toUpperCase()) : await read.getIssuer(arg('did')));
} else if (cmd === 'list') {
  const n = Number(await read.issuerCount());
  for (let i = 0; i < n; i++) show(await read.issuerAt(i));
  if (!n) console.log('No entries.');
} else if (['add', 'update', 'status', 'remove'].includes(cmd)) {
  const did = arg('did');
  if (!did) throw new Error('--did is required');
  const w = registryContract(ownerWallet(p), address);
  // 30% headroom on the gas estimate: clearing storage (BIC changes, remove) can make estimates too tight.
  const gas = async (fn, ...a) => ({ gasLimit: ((await w[fn].estimateGas(...a)) * 13n) / 10n });
  let tx;
  if (cmd === 'add' || cmd === 'update') {
    const signingKey = arg('signing-key') ?? publicKeyFromDidKey(did)?.hex ?? '';
    if (!signingKey) console.warn('No --signing-key given and none can be taken from this DID: the entry has no signing key.');
    const input = {
      did, name: arg('name') ?? '', role: arg('role') ?? '', bic: (arg('bic') ?? '').toUpperCase(), signingKey,
      allowedDocs: (arg('docs') ?? 'eLC').split(',').map((s) => s.trim()).filter(Boolean),
      validFrom: secs(arg('from')), validUntil: secs(arg('until')),
    };
    const fn = cmd === 'add' ? 'addIssuer' : 'updateIssuer';
    tx = await w[fn](input, await gas(fn, input));
  } else if (cmd === 'status') {
    const to = { active: 1, suspended: 2, revoked: 3 }[arg('to')];
    if (!to) throw new Error('--to must be active, suspended or revoked');
    tx = await w.setStatus(did, to, await gas('setStatus', did, to));
  } else {
    tx = await w.removeIssuer(did, await gas('removeIssuer', did));
  }
  console.log(`Sent ${tx.hash}…`);
  const r = await tx.wait();
  console.log(`Done in block ${r.blockNumber}.`);
  if (cmd !== 'remove') show(await read.getIssuer(did));
} else {
  console.log('Commands: add | update | status | remove | get | list (see the top of scripts/registry.mjs)');
}
