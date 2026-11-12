// Builds pila-verifier/ (PILA's Go SDK) into bin/, where the API finds and starts it. Needs Go 1.24.6+.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const out = fileURLToPath(new URL(`../bin/pila-verifier${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url));
const cwd = fileURLToPath(new URL('../pila-verifier/', import.meta.url));
const r = spawnSync('go', ['build', '-o', out, '.'], { cwd, stdio: 'inherit', shell: process.platform === 'win32' });
if (r.error) { console.error(`Could not run go (${r.error.message}). Install Go 1.24.6+ from https://go.dev/dl/`); process.exit(1); }
if (r.status === 0) console.log(`Built ${out}. npm run dev starts it with the API.`);
process.exit(r.status ?? 1);
