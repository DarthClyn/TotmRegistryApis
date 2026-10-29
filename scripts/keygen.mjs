// Creates an API key. Prints the key ONCE (give it to the partner privately) and the entry to add to the server settings.
// Partner: npm run keygen -- --name PILA --did did:nda:testnet:0x… [--type verifier]
// Admin:   npm run keygen -- --admin
import { newApiKey, sha256Hex } from '../src/keys.js';
const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const key = newApiKey();
const hash = sha256Hex(key);
if (process.argv.includes('--admin')) {
  console.log(`Admin key (keep it inside TOTM; shown once):\n  ${key}\n\nServer setting:\n  ADMIN_API_KEY_HASH=${hash}`);
} else {
  const name = arg('name');
  if (!name) { console.error('Usage: npm run keygen -- --name PILA --did did:nda:… [--type verifier]   or   --admin'); process.exit(1); }
  const entry = { name, did: arg('did') ?? null, type: arg('type') ?? 'verifier', keyHash: hash };
  console.log(`API key for ${name} (send privately; shown once, not stored anywhere):\n  ${key}\n`);
  console.log('Add this entry to the PARTNER_API_KEYS array (JSON) in the server settings:');
  console.log('  ' + JSON.stringify(entry));
}
