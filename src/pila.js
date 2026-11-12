// PILA verification for credentials not issued by TOTM. The work is done by pila-verifier/ (Go), which runs PILA's
// official credential SDK and NDAKey's verification context API; this module only reaches it. Two ways:
//   - child process (default when hosted with the Dockerfile): the API starts bin/pila-verifier on 127.0.0.1 with a
//     random token, restarts it if it stops, and is the only thing that can call it;
//   - PILA_VERIFIER_URL: a verifier running elsewhere (e.g. `go run .` in another terminal), with PILA_VERIFIER_TOKEN.
// Without either, PILA routes answer 503.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const defaultBin = () => fileURLToPath(new URL(`../bin/pila-verifier${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A client for a verifier at `url`; `start`/`stop` manage a child process when it is ours. */
function client({ kind, url, token, start = async () => {}, stop = () => {}, ready = async () => true }) {
  const call = async (method, path, body, requestId, timeoutMs = 30000) => {
    if (!(await ready())) return { status: 503, body: { error: 'The PILA verifier is starting or not running. Try again in a few seconds.' } };
    try {
      const res = await fetch(`${url}${path}`, {
        method,
        headers: { 'content-type': 'application/json', ...(token ? { 'x-verifier-token': token } : {}), ...(requestId ? { 'x-request-id': requestId } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      return { status: res.status, body: await res.json().catch(() => ({ error: `Unexpected answer (${res.status})` })) };
    } catch (e) {
      return { status: 503, body: { error: `PILA verifier not reachable: ${e.name === 'TimeoutError' ? 'timed out' : e.message}` } };
    }
  };
  return {
    kind,
    start,
    stop,
    verify: (credential, requestId) => call('POST', '/verify', { credential }, requestId, 45000),
    health: () => call('GET', '/health', undefined, undefined, 5000),
  };
}

// The child gets only what it needs: its PILA_* settings, proxy/certificate settings and basics. Never the API's own
// secrets (admin key hash, bank keys, store and blob tokens).
const PASS = /^(PILA_|HTTPS?_PROXY$|NO_PROXY$|SSL_CERT_|PATH$|HOME$|TZ$|SYSTEMROOT$|TEMP$|TMP$)/i;
const childEnv = (env) => Object.fromEntries(Object.entries(env).filter(([k, v]) => v !== undefined && PASS.test(k) && k !== 'PILA_VERIFIER_TOKEN'));

/** The verifier as a child process of this API, on loopback only. */
export function childVerifier({ bin, port = 4100, env = process.env, log = console }) {
  const url = `http://127.0.0.1:${port}`;
  const token = randomBytes(24).toString('hex'); // per start: nothing outside this process can call the child
  let child = null;
  let up = false;
  let stopping = false;
  let restarts = 0;

  const probe = async () => {
    try {
      const r = await fetch(`${url}/health`, { signal: AbortSignal.timeout(1500) });
      return r.ok;
    } catch { return false; }
  };

  const launch = () => {
    up = false;
    child = spawn(bin, [], {
      cwd: ROOT,
      env: { ...childEnv(env), PORT: String(port), HOST: '127.0.0.1', PILA_VERIFIER_TOKEN: token, DOTENV_FILE: `${ROOT}.env` },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const forward = (d) => String(d).split('\n').filter(Boolean).forEach((l) => log.info(`[pila-verifier] ${l}`));
    child.stdout.on('data', forward);
    child.stderr.on('data', forward);
    child.on('error', (e) => log.error(`[pila-verifier] could not start ${bin}: ${e.message}`));
    child.on('exit', (code) => {
      up = false;
      if (stopping) return;
      const wait = Math.min(30000, 1000 * 2 ** Math.min(restarts++, 5));
      log.error(`[pila-verifier] stopped (code ${code}); restarting in ${wait / 1000}s`);
      setTimeout(launch, wait);
    });
  };

  const ready = async () => {
    if (up) return true;
    for (let i = 0; i < 20 && child && !stopping; i++) {
      if (await probe()) { up = true; restarts = 0; return true; }
      await sleep(250);
    }
    return false;
  };

  return client({
    kind: `child process (${bin})`,
    url,
    token,
    ready,
    start: async () => { stopping = false; launch(); if (await ready()) log.info(`[pila-verifier] ready on ${url}`); },
    stop: () => { stopping = true; child?.kill(); },
  });
}

/** Picks how to reach the verifier from the environment; null when there is no verifier. */
export function pilaVerifierFromEnv(env = process.env) {
  if (env.PILA_VERIFIER === 'off') return null;
  if (env.PILA_VERIFIER_URL) {
    return client({ kind: `remote (${env.PILA_VERIFIER_URL})`, url: env.PILA_VERIFIER_URL.replace(/\/$/, ''), token: env.PILA_VERIFIER_TOKEN });
  }
  const bin = env.PILA_VERIFIER_BIN || defaultBin();
  return existsSync(bin) ? childVerifier({ bin, port: Number(env.PILA_VERIFIER_PORT || 4100), env }) : null;
}

export { client as pilaClient };
