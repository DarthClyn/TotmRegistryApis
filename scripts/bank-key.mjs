// Creates a signing key for an issuing bank (did:key, P-256, ecdsa-sd-2023) and prints:
//  - the BANK_KEYS_JSON value for the server (SECRET: contains the private key; keep it out of chat and git),
//  - the registry command that lists the bank (its signing key is taken from the DID).
// To reuse the VC Layer's demo bank instead, put its data/issuer-key.json content (ISSUER_KEY_JSON) in BANK_KEYS_JSON.
// Usage: npm run bank-key -- [--name "Bank Alpha ID"] [--bic ALPHIDJA]
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { generateDidKeyPair, CryptoSuite } = require('@trustvc/w3c-issuer');
const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };

const { didKeyPairs } = await generateDidKeyPair(CryptoSuite.EcdsaSd2023);
const did = didKeyPairs.controller ?? didKeyPairs.id.split('#')[0];
console.log(`Bank DID: ${did}\n`);
console.log('Server setting (SECRET, contains the private key). Several banks: put the objects in one JSON array.');
console.log(`BANK_KEYS_JSON=${JSON.stringify(didKeyPairs)}\n`);
console.log('List the bank in the registry:');
console.log(`npm run registry -- add --did ${did} --name "${arg('name') ?? 'Bank Alpha ID'}" --role "Issuing bank" --bic ${arg('bic') ?? 'ALPHIDJA'} --docs eLC`);
