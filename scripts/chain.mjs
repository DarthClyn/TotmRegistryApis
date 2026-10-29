// Shared by contract-deploy.mjs and registry.mjs. Never prints secrets.
import { readFileSync, existsSync } from 'node:fs';
import { Contract, JsonRpcProvider, Wallet } from 'ethers';
import { artifact, rpcUrl } from '../src/registry.js';
export { artifact };
export const DEPLOYMENTS = new URL('../deployments/', import.meta.url);
export const chainIdFrom = (arg) => Number(arg ?? process.env.REGISTRY_CHAIN_ID ?? 11155111);

export function deployedAddress(chainId) {
  if (process.env.REGISTRY_ADDRESS) return process.env.REGISTRY_ADDRESS;
  const f = new URL(`${chainId}.json`, DEPLOYMENTS);
  return existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')).address : '';
}

export async function provider(chainId) {
  const p = new JsonRpcProvider(rpcUrl(process.env, chainId), chainId, { staticNetwork: true });
  const net = await p.getNetwork();
  if (Number(net.chainId) !== chainId) throw new Error(`RPC is on chain ${net.chainId}, expected ${chainId}`);
  return p;
}

export function ownerWallet(p) {
  const key = process.env.REGISTRY_OWNER_PRIVATE_KEY;
  if (!key) throw new Error('REGISTRY_OWNER_PRIVATE_KEY is not set (.env)');
  return new Wallet(key, p);
}

export function registryContract(runner, address) {
  if (!address) throw new Error('No registry address: run "npm run contract:deploy" first, or set REGISTRY_ADDRESS');
  return new Contract(address, artifact.abi, runner);
}
