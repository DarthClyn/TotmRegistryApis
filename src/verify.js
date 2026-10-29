// Content check of a TradeTrust (W3C) eLC with TrustVC: is it intact, and does the signature belong to the issuer DID?
// Issuer trust and eLC status come from the registry and the status store, not from here.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url); // named "require" so Vercel's file tracing sees the files below
try {
  // security-context reads these by a computed path; naming them makes hosted bundlers include them.
  require.resolve('security-context/contexts/security-v1.jsonld');
  require.resolve('security-context/contexts/security-v2.jsonld');
} catch { /* other layout: TrustVC reports it if ever needed */ }

let trustVc;
const load = () => (trustVc ??= require('@trustvc/trustvc'));
export const warmUp = () => { const t = Date.now(); load(); return Date.now() - t; };

export const issuerOf = (vc) => (typeof vc?.issuer === 'string' ? vc.issuer : vc?.issuer?.id) ?? null;

export function looksLikeW3cVc(vc) {
  return !!vc && typeof vc === 'object' && Array.isArray(vc['@context']) && !!vc.proof && !!issuerOf(vc);
}

/** Runs TrustVC and maps its fragments to the two checks partners asked for. */
export async function verifyContent(vc, { verifier } = {}) {
  const run = verifier ?? ((doc) => load().verifyDocument(doc));
  const fragments = await run(vc);
  const pick = (type) => fragments.filter((f) => f.type === type && f.status !== 'SKIPPED');
  const result = (type, ok, bad) => {
    const fs = pick(type);
    if (fs.some((f) => f.status === 'ERROR')) return { passed: false, result: 'error', message: 'Could not be checked (resolver or network error)' };
    if (!fs.length) return { passed: false, result: 'fail', message: 'No verifier recognised this proof' };
    const passed = fs.every((f) => f.status === 'VALID');
    return { passed, result: passed ? 'pass' : 'fail', message: passed ? ok : bad };
  };
  return {
    vcId: vc.id ?? null,
    issuerDid: issuerOf(vc),
    integrity: result('DOCUMENT_INTEGRITY', 'Not tampered with: contents match the signature', 'Contents changed after signing'),
    issuer: result('ISSUER_IDENTITY', 'Signature belongs to the issuer DID', 'Signature does not belong to the issuer DID'),
  };
}
