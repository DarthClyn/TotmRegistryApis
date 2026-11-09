// File bytes for the inbox. Vercel Blob (private store) in production; memory for tests and local runs.
// Only the bytes live here; file records (sender, receiver, hash, dates) live in the status store.
import { del, get, put } from '@vercel/blob';

export function memoryFiles() {
  const objects = new Map();
  return {
    kind: 'memory',
    async put(key, bytes, contentType) { objects.set(key, { bytes: Buffer.from(bytes), contentType }); },
    async get(key) { return objects.get(key)?.bytes ?? null; },
    async del(key) { objects.delete(key); },
  };
}

/**
 * Vercel Blob, private store: every read and write needs credentials; files have no public URL.
 * Auth (read by the SDK from the environment): on Vercel, OIDC + BLOB_STORE_ID, added when the store is connected
 * to the project; elsewhere BLOB_READ_WRITE_TOKEN.
 */
export function vercelBlobFiles() {
  return {
    kind: 'vercel-blob',
    async put(key, bytes, contentType) {
      await put(key, bytes, { access: 'private', contentType, addRandomSuffix: false, allowOverwrite: false });
    },
    async get(key) {
      const r = await get(key, { access: 'private' });
      if (!r || r.statusCode !== 200) return null;
      return Buffer.from(await new Response(r.stream).arrayBuffer());
    },
    async del(key) { await del(key); },
  };
}
