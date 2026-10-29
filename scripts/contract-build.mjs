// Compiles contract/src/IssuerRegistryV2.sol with solc-js 0.8.24 (EVM Shanghai) into contract/artifacts/IssuerRegistryV2.json.
// The artifact is committed, so deploying and running the API need no compiler.
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const solc = createRequire(import.meta.url)('solc');
const root = new URL('../contract/', import.meta.url);
const source = readFileSync(new URL('src/IssuerRegistryV2.sol', root), 'utf8');
const out = JSON.parse(solc.compile(JSON.stringify({
  language: 'Solidity',
  sources: { 'IssuerRegistryV2.sol': { content: source } },
  settings: { evmVersion: 'shanghai', viaIR: true, optimizer: { enabled: true, runs: 200 }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
})));
for (const e of out.errors ?? []) console.error(e.formattedMessage);
if ((out.errors ?? []).some((e) => e.severity === 'error')) process.exit(1);
const c = out.contracts['IssuerRegistryV2.sol'].IssuerRegistryV2;
writeFileSync(new URL('artifacts/IssuerRegistryV2.json', root), JSON.stringify({
  contractName: 'IssuerRegistryV2', compiler: `solc ${solc.version()}`, evmVersion: 'shanghai', abi: c.abi, bytecode: `0x${c.evm.bytecode.object}`,
}, null, 2) + '\n');
console.log(`Built IssuerRegistryV2 with solc ${solc.version()}`);
