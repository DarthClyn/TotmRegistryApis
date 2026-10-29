// Deploys IssuerRegistryV2 with the owner wallet (REGISTRY_OWNER_PRIVATE_KEY) and saves deployments/<chainId>.json
// (public: chain, address, owner). Usage: npm run contract:deploy [-- --chain 11155111]
import { mkdirSync, writeFileSync } from 'node:fs';
import { ContractFactory, formatEther } from 'ethers';
import { artifact, chainIdFrom, DEPLOYMENTS, ownerWallet, provider } from './chain.mjs';

const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const chainId = chainIdFrom(arg('chain'));
const p = await provider(chainId);
const w = ownerWallet(p);
const bal = await p.getBalance(w.address);
console.log(`Owner ${w.address} on chain ${chainId}, balance ${formatEther(bal)} ETH`);
if (bal === 0n) throw new Error('Owner wallet has no ETH on this chain. Fund it from a Sepolia faucet first.');
const c = await new ContractFactory(artifact.abi, artifact.bytecode, w).deploy();
console.log(`Deploying IssuerRegistryV2… tx ${c.deploymentTransaction().hash}`);
await c.waitForDeployment();
const address = await c.getAddress();
mkdirSync(DEPLOYMENTS, { recursive: true });
writeFileSync(new URL(`${chainId}.json`, DEPLOYMENTS), JSON.stringify({
  contract: 'IssuerRegistryV2', chainId, address, owner: w.address, deployedAt: new Date().toISOString(),
}, null, 2) + '\n');
console.log(`IssuerRegistryV2 at ${address}\nSaved to deployments/${chainId}.json. Set REGISTRY_ADDRESS=${address} on the server.`);
