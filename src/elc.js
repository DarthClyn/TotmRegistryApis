// eLC issuing on the TOTM side: builds the W3C VC from MT700 fields and signs it with the bank's own key
// (TrustVC signW3C, ecdsa-sd-2023). Same data model and format as the VC Layer's Issue eLC, so eLCs from either
// verify the same way. The bank keys are held server-side (BANK_KEYS_JSON); they never leave the server.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/** eLC field keys in MT700 order (same as the VC Layer's ELC_FIELD_SPECS). `documentsRequired` is a list. */
export const ELC_FIELDS = [
  'sequenceOfTotal', 'formOfCredit', 'lcNumber', 'referenceToPreAdvice', 'dateOfIssue', 'applicableRules', 'expiryDate',
  'expiryPlace', 'issuingBankName', 'applicantBank', 'applicantName', 'applicantAddress', 'beneficiaryName',
  'beneficiaryAddress', 'currency', 'amount', 'amountTolerance', 'additionalAmountsCovered', 'availableWith',
  'availableBy', 'draftsAt', 'drawee', 'mixedPaymentDetails', 'negotiationDeferredPaymentDetails', 'partialShipments',
  'transhipment', 'placeOfTakingInCharge', 'portOfLoading', 'portOfDischarge', 'placeOfFinalDestination',
  'latestShipmentDate', 'shipmentPeriod', 'goodsDescription', 'documentsRequired', 'additionalConditions',
  'chargesClause', 'presentationPeriod', 'confirmationInstructions', 'specialPaymentConditionsBeneficiary',
  'specialPaymentConditionsReceivingBank', 'reimbursingBank', 'instructionsToBank', 'advisingBankName',
  'senderToReceiverInfo', 'requestedConfirmationParty',
];

/** Names used in PILA's eLC samples, mapped to ours. */
const ALIASES = {
  applicantBankName: 'applicantBank',
  preAdviceReference: 'referenceToPreAdvice',
  reimbursingBankName: 'reimbursingBank',
  instructionsToPayingBank: 'instructionsToBank',
};

const NS = 'urn:orchestration-layer:elc#';
export const ELC_TYPE = 'ElectronicLetterOfCredit';

/** Inline JSON-LD context (nothing hosted): defines every field so the signature covers them. Same as the VC Layer. */
export const ELC_CONTEXT = {
  '@version': 1.1,
  '@protected': true,
  [ELC_TYPE]: { '@id': `${NS}${ELC_TYPE}` },
  LetterOfCredit: {
    '@id': `${NS}LetterOfCredit`,
    '@context': { '@protected': true, ...Object.fromEntries(ELC_FIELDS.map((k) => [k, { '@id': `${NS}${k}` }])) },
  },
};

export class ElcInputError extends Error {}
const bad = (m) => new ElcInputError(m);

export const isDid = (s) => typeof s === 'string' && /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(s.trim());

/** Keeps only eLC fields (every field optional). Accepts flat fields or { data: {...} }. Unknown keys are reported. */
export function normaliseElcData(input) {
  const src = input && typeof input === 'object' ? (input.data && typeof input.data === 'object' ? input.data : input) : {};
  const data = {};
  const ignored = [];
  for (const [rawKey, v] of Object.entries(src)) {
    const k = ALIASES[rawKey] ?? rawKey;
    if (k === 'documentsRequired') {
      const list = (Array.isArray(v) ? v : typeof v === 'string' ? v.split(/\r?\n/) : []).map((x) => String(x).trim()).filter(Boolean);
      if (list.length) data.documentsRequired = list;
    } else if (ELC_FIELDS.includes(k)) {
      if (v !== undefined && v !== null && String(v).trim() !== '') {
        if (typeof v === 'object') throw bad(`${rawKey} must be text`);
        data[k] = String(v).slice(0, 10000);
      }
    } else {
      ignored.push(rawKey);
    }
  }
  return { data, ignored };
}

const isoDate = (s) => (s && /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : undefined);

/** Validity = date of issue (or now, if that is later) → end of expiry date, when given (else open-ended). */
export function elcValidity(data, now = new Date()) {
  for (const k of ['dateOfIssue', 'expiryDate']) {
    if (data[k] && !isoDate(data[k])) throw bad(`${k} must be a date as YYYY-MM-DD`);
  }
  const from = isoDate(data.dateOfIssue);
  const until = isoDate(data.expiryDate);
  if (from && until && until < from) throw bad('expiryDate is before dateOfIssue');
  // validFrom never lies in the future: verifiers reject a credential before its validFrom, and a bank east of UTC
  // issuing early on its "date of issue" would otherwise produce an eLC that fails for the next hours.
  const nowIso = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const start = from ? `${from}T00:00:00Z` : nowIso;
  return {
    validFrom: start > nowIso ? nowIso : start,
    ...(until ? { validUntil: `${until}T23:59:59Z` } : {}),
  };
}

/** Base64 files, 10 MB in total. */
export function checkAttachments(list) {
  if (list == null) return [];
  if (!Array.isArray(list)) throw bad('attachments must be a list');
  let total = 0;
  return list.map((a, i) => {
    if (typeof a?.filename !== 'string' || typeof a?.data !== 'string' || !/^[A-Za-z0-9+/=]*$/.test(a.data)) throw bad(`Attachment ${i + 1} is not a valid file`);
    total += Math.floor((a.data.length * 3) / 4);
    if (total > 10 * 1024 * 1024) throw bad('Attachments are larger than 10 MB in total');
    return { filename: a.filename.slice(0, 200), mimeType: typeof a.mimeType === 'string' && a.mimeType ? a.mimeType : 'application/octet-stream', data: a.data };
  });
}

export const keyDid = (key) => key.controller ?? String(key.id).split('#')[0];

/**
 * Bank keys from BANK_KEYS_JSON: a TrustVC key pair (as in the VC Layer's data/issuer-key.json / ISSUER_KEY_JSON),
 * or an array of them. Returned by DID.
 */
export function parseBankKeys(raw) {
  if (!raw) return new Map();
  let v;
  try { v = JSON.parse(raw); } catch { throw new Error('BANK_KEYS_JSON is not valid JSON'); }
  const list = Array.isArray(v) ? v : [v];
  const map = new Map();
  for (const k of list) {
    if (!k?.id || !k?.publicKeyMultibase || !k?.secretKeyMultibase) throw new Error('BANK_KEYS_JSON entries must be TrustVC key pairs (id, controller, publicKeyMultibase, secretKeyMultibase)');
    map.set(keyDid(k), k);
  }
  return map;
}

/** Builds and signs the eLC. `holderDid` (normally the beneficiary's DID) becomes credentialSubject.id. */
export async function signElc({ data, attachments, key, holderDid, signer }) {
  if (holderDid != null && holderDid !== '' && !isDid(holderDid)) throw bad('holderDid must be a DID');
  const files = checkAttachments(attachments);
  const raw = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://w3id.org/security/data-integrity/v2',
      'https://trustvc.io/context/attachments-context.json',
      ELC_CONTEXT,
    ],
    type: ['VerifiableCredential', ELC_TYPE],
    issuer: keyDid(key),
    ...elcValidity(data),
    credentialSubject: { ...(holderDid ? { id: holderDid.trim() } : {}), type: ['LetterOfCredit'], ...data, ...(files.length ? { attachments: files } : {}) },
  };
  const sign = signer ?? ((doc, k) => require('@trustvc/trustvc').signW3C(doc, k, 'ecdsa-sd-2023'));
  const result = await sign(raw, key);
  if (result?.error || !result?.signed) throw new Error(`Could not sign the eLC: ${result?.error ?? 'unknown error'}`);
  return result.signed;
}
