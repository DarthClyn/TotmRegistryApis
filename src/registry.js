// Reads the on-chain issuer registry (IssuerRegistryV2). Anyone can read; nothing is cached (fail-closed).
import { readFileSync } from 'node:fs';
import { Contract, JsonRpcProvider } from 'ethers';

export const artifact = JSON.parse(readFileSync(new URL('../contract/artifacts/IssuerRegistryV2.json', import.meta.url), 'utf8'));
export const STATUS = ['none', 'active', 'suspended', 'revoked'];

/** RPC: REGISTRY_RPC_URL, else Infura Sepolia with INFURA_API_KEY. */
export function rpcUrl(env, chainId) {
  const url = env.REGISTRY_RPC_URL || (chainId === 11155111 && env.INFURA_API_KEY ? `https://sepolia.infura.io/v3/${env.INFURA_API_KEY}` : '');
  if (!url) throw new Error(`No RPC for chain ${chainId}: set REGISTRY_RPC_URL (or INFURA_API_KEY for Sepolia)`);
  return url;
}

const iso = (s) => (Number(s) ? new Date(Number(s) * 1000).toISOString() : null);

/** Plain JSON view of a registry entry; null when not registered. */
export function toEntry(e) {
  const status = STATUS[Number(e.status)];
  if (!status || status === 'none') return null;
  return {
    did: e.did,
    name: e.name,
    role: e.role,
    bic: e.bic || null,
    signingKey: e.signingKey || null,
    allowedDocs: [...e.allowedDocs],
    status,
    validFrom: iso(e.validFrom),
    validUntil: iso(e.validUntil),
    updatedAt: iso(e.updatedAt),
  };
}

/** Trusted now for this document type: Active, inside validity, type allowed (empty list = any). */
export function isTrustedNow(entry, docType = 'eLC', now = Date.now()) {
  if (!entry || entry.status !== 'active') return false;
  if (entry.validFrom && Date.parse(entry.validFrom) > now) return false;
  if (entry.validUntil && Date.parse(entry.validUntil) < now) return false;
  return entry.allowedDocs.length === 0 || entry.allowedDocs.includes(docType);
}

/** Reader backed by the contract. `timeoutMs` bounds each RPC call. */
export function contractRegistry({ rpc, chainId, address, timeoutMs = 4000 }) {
  const provider = new JsonRpcProvider(rpc, chainId, { staticNetwork: true });
  const c = new Contract(address, artifact.abi, provider);
  const timed = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('registry timeout')), timeoutMs))]);
  return {
    async byDid(did) { return toEntry(await timed(c.getIssuer(did))); },
    async byBic(bic) { return toEntry(await timed(c.getIssuerByBic(bic))); },
  };
}

/** In-memory reader for tests and local runs without a chain. */
export function memoryRegistry(entries = []) {
  return {
    async byDid(did) { return entries.find((e) => e.did === did) ?? null; },
    async byBic(bic) { return entries.find((e) => e.bic && e.bic === bic) ?? null; },
  };
}
