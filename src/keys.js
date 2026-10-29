// Small key helpers. No secrets are handled here.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Decode(s) {
  let n = 0n;
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error('not base58');
    n = n * 58n + BigInt(v);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const lead = s.match(/^1*/)[0].length;
  return Buffer.concat([Buffer.alloc(lead), Buffer.from(n === 0n ? '' : hex, 'hex')]);
}

// multicodec prefixes (varint) of public key types used in did:key
const CODECS = [
  { name: 'P-256', prefix: [0x80, 0x24], len: 33 },
  { name: 'secp256k1', prefix: [0xe7, 0x01], len: 33 },
  { name: 'Ed25519', prefix: [0xed, 0x01], len: 32 },
];

/** Public key of a did:key as 0x-hex (compressed for EC keys), or null if it is not a did:key we know. */
export function publicKeyFromDidKey(did) {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)/.exec(did ?? '');
  if (!m) return null;
  let bytes;
  try { bytes = base58Decode(m[1]); } catch { return null; }
  for (const c of CODECS) {
    if (bytes[0] === c.prefix[0] && bytes[1] === c.prefix[1] && bytes.length === c.len + 2) {
      return { type: c.name, hex: '0x' + bytes.subarray(2).toString('hex') };
    }
  }
  return null;
}

export const sha256Hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

/** Constant-time compare of a presented key against a stored SHA-256 hex hash. */
export function keyMatches(presented, hashHex) {
  if (typeof presented !== 'string' || !presented || typeof hashHex !== 'string' || hashHex.length !== 64) return false;
  const a = Buffer.from(sha256Hex(presented), 'hex');
  const b = Buffer.from(hashHex.toLowerCase(), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

/** A new API key: "tta_" + 48 random hex chars. Shown once; only its hash is stored. */
export const newApiKey = () => 'tta_' + randomBytes(24).toString('hex');

const COMPRESSED = /^0x0[23][0-9a-fA-F]{64}$/;
export const isCompressedKey = (s) => typeof s === 'string' && COMPRESSED.test(s);

/**
 * Does this public key belong to this DID? true / false when it can be checked, null when the DID method gives no
 * way to tell offline (e.g. did:web). did:nda:[network:]0x<address> = Ethereum-style address of a secp256k1 key.
 */
export async function didMatchesKey(did, publicKeyHex) {
  const nda = /^did:nda:(?:[a-z0-9]+:)?(0x[0-9a-fA-F]{40})$/.exec(did ?? '');
  if (nda) {
    const { computeAddress } = await import('ethers');
    try { return computeAddress(publicKeyHex).toLowerCase() === nda[1].toLowerCase(); } catch { return false; }
  }
  const fromKey = publicKeyFromDidKey(did);
  if (fromKey) return fromKey.hex.toLowerCase() === String(publicKeyHex).toLowerCase();
  return null;
}
