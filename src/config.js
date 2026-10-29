// Settings from environment variables only. See .env.example.
import { contractRegistry, memoryRegistry, rpcUrl } from './registry.js';
import { memoryStore, upstashStore } from './store.js';
import { parseBankKeys } from './elc.js';

function parsePartners(raw) {
  if (!raw) return [];
  let list;
  try { list = JSON.parse(raw); } catch { throw new Error('PARTNER_API_KEYS is not valid JSON'); }
  if (!Array.isArray(list) || list.some((p) => !p?.name || !/^[0-9a-f]{64}$/i.test(p?.keyHash ?? ''))) {
    throw new Error('PARTNER_API_KEYS must be a JSON array of {name, did, type, keyHash} with a SHA-256 hex keyHash');
  }
  return list;
}

export function loadConfig(env = process.env) {
  const hosted = !!(env.VERCEL || env.RAILWAY_ENVIRONMENT || env.RENDER);
  const chainId = Number(env.REGISTRY_CHAIN_ID || 11155111);
  const registry = env.REGISTRY_ADDRESS
    ? contractRegistry({ rpc: rpcUrl(env, chainId), chainId, address: env.REGISTRY_ADDRESS })
    : null;
  if (!registry && hosted) throw new Error('REGISTRY_ADDRESS is required');

  const url = env.UPSTASH_REDIS_REST_URL || env.KV_REST_API_URL;
  const token = env.UPSTASH_REDIS_REST_TOKEN || env.KV_REST_API_TOKEN;
  if (!url && hosted) throw new Error('A status store is required when hosted: set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN');

  return {
    port: Number(env.PORT || 4300),
    registry: registry ?? memoryRegistry([]),
    registryKind: registry ? `chain ${chainId} · ${env.REGISTRY_ADDRESS}` : 'empty (no REGISTRY_ADDRESS)',
    store: url ? upstashStore({ url, token }) : memoryStore(),
    partners: parsePartners(env.PARTNER_API_KEYS),
    adminKeyHash: env.ADMIN_API_KEY_HASH || undefined,
    bankKeys: parseBankKeys(env.BANK_KEYS_JSON),
  };
}
