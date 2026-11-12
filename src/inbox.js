// Inbox: PILA and TOTM send each other files. Sending from one side delivers to the other side's inbox.
// Either key (X-Api-Key or X-Admin-Key) can use both sides; only an admin key can delete.
// Bytes go to the file store (Vercel Blob), records to the status store. File content is never logged.
import { createHash, randomUUID } from 'node:crypto';

/** Sending side -> receiving side. */
export const SIDES = { pila: 'totm', totm: 'pila' };

const isJwt = (b) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(~[A-Za-z0-9_~.-]*)?$/.test(b.toString('utf8').trim());
const TYPES = {
  'application/json': (b) => { try { JSON.parse(b.toString('utf8')); return true; } catch { return false; } },
  'application/pdf': (b) => b.subarray(0, 5).toString('latin1') === '%PDF-',
  'image/png': (b) => b.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47])),
  'image/jpeg': (b) => b.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff])),
  // A signed credential as a compact JWT (VC-JWT / SD-JWT), e.g. a .jwt file. Stored and returned exactly as sent.
  'application/jwt': (b) => isJwt(b),
  'application/vc+jwt': (b) => isJwt(b),
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const cleanName = (s) => String(s).split(/[\\/]/).pop().replace(/[^A-Za-z0-9._ -]/g, '_').replace(/^\.+/, '').slice(0, 150);
const optStr = (v, max, name, bad) => {
  if (v == null || v === '') return null;
  if (typeof v !== 'string' || v.length > max) throw bad(`${name} must be text of at most ${max} characters`);
  return v;
};

/**
 * @param {import('fastify').FastifyInstance} app
 * @param {object} d store, files (null = not configured), requireAny, requireAdmin, audited, ApiError, ok, bad, maxBytes, ttlDays
 */
export function inboxRoutes(app, { store, files, requireAny, requireAdmin, audited, ApiError, ok, bad, maxBytes, ttlDays }) {
  app.register(async (scope) => {
    // Upload bodies are the raw file bytes, whatever the content type (a JSON file is not parsed).
    scope.removeAllContentTypeParsers();
    scope.addContentTypeParser('*', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));

    const sideOf = (req) => {
      const side = req.params.side;
      if (!SIDES[side]) throw new ApiError(404, 'E404', 'No such endpoint');
      if (!files) throw new ApiError(503, 'E503', 'Inbox file storage is not configured on this server');
      return side;
    };
    const fileOf = async (req, side) => {
      if (!UUID.test(req.params.fileId)) throw new ApiError(404, 'E02', 'File not found');
      const rec = await store.getFile(req.params.fileId);
      if (!rec || rec.to !== side) throw new ApiError(404, 'E02', 'File not found');
      return rec;
    };
    const objectKey = (rec) => `inbox/${rec.to}/${rec.fileId}`;

    /** Send a file. Body = the file bytes with its Content-Type; ?fileName= required, ?txId= &vcId= &note= optional. */
    scope.post('/api/v1/:side/send', { preHandler: requireAny, bodyLimit: maxBytes }, async (req, reply) => {
      const from = sideOf(req);
      const to = SIDES[from];
      const body = req.body;
      if (!Buffer.isBuffer(body) || !body.length) throw bad('Send the file bytes as the request body');
      const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
      if (!TYPES[contentType]) throw bad(`Content-Type must be one of: ${Object.keys(TYPES).join(', ')}`);
      if (!TYPES[contentType](body)) throw bad(`File content does not match Content-Type ${contentType}`);
      const q = req.query ?? {};
      const fileName = typeof q.fileName === 'string' ? cleanName(q.fileName) : '';
      if (!fileName) throw bad('fileName query parameter is required');
      const txId = optStr(q.txId, 40, 'txId', bad);
      if (txId && !/^[A-Za-z0-9-]{3,40}$/.test(txId)) throw bad('txId must be 3-40 letters, digits or dashes');
      const vcId = optStr(q.vcId, 300, 'vcId', bad);
      const note = optStr(q.note, 500, 'note', bad);

      const now = new Date();
      const rec = {
        fileId: randomUUID(), from, to, fileName, contentType, size: body.length, sha256: sha256(body),
        txId, vcId, note, sentBy: req.partner?.name ?? null, requestId: req.requestId,
        sentAt: now.toISOString(), readAt: null, readBy: null,
        expiresAt: new Date(now.getTime() + ttlDays * 86400_000).toISOString(),
      };
      await files.put(objectKey(rec), body, contentType);
      try { await store.createFile(rec); } catch (e) { await files.del(objectKey(rec)).catch(() => {}); throw e; }
      audited(req, 'inbox.send', 'ok', { fileId: rec.fileId, from, to, size: rec.size, sha256: rec.sha256, txId, vcId });
      reply.code(201);
      return ok(rec);
    });

    // Listing also deletes the bytes of files whose record has expired, so the Blob store does not fill up.
    const list = async (req, box) => {
      const side = sideOf(req);
      const limit = Math.min(Math.max(Number(req.query?.limit) || 50, 1), 100);
      const { files: list, gone } = await store.listFiles(box, side, limit, Date.now() - ttlDays * 86400_000);
      const receiver = box === 'inbox' ? side : SIDES[side];
      await Promise.all(gone.map((id) => files.del(`inbox/${receiver}/${id}`).catch(() => {})));
      return ok({ side, box, count: list.length, files: list });
    };

    /** Files this side has received, newest first. ?limit= 1-100 (default 50). */
    scope.get('/api/v1/:side/inbox', { preHandler: requireAny }, (req) => list(req, 'inbox'));

    /** Files this side has sent, with readAt once the other side has acknowledged them. */
    scope.get('/api/v1/:side/sent', { preHandler: requireAny }, (req) => list(req, 'sent'));

    /** Download a received file (raw bytes). The SHA-256 is checked before it is returned. */
    scope.get('/api/v1/:side/inbox/:fileId', { preHandler: requireAny }, async (req, reply) => {
      const side = sideOf(req);
      const rec = await fileOf(req, side);
      const bytes = await files.get(objectKey(rec));
      if (!bytes) throw new ApiError(404, 'E02', 'File content not found (expired or deleted)');
      if (sha256(bytes) !== rec.sha256) {
        audited(req, 'inbox.download', 'failed', { fileId: rec.fileId, reason: 'hash mismatch' });
        throw new Error('Stored file does not match its SHA-256');
      }
      audited(req, 'inbox.download', 'ok', { fileId: rec.fileId, side });
      return reply
        .header('content-type', rec.contentType)
        .header('content-disposition', `attachment; filename="${rec.fileName.replace(/"/g, '')}"`)
        .header('x-file-sha256', rec.sha256)
        .send(bytes);
    });

    /** Acknowledge a received file: sets readAt (first time only) so the sender sees it arrived. */
    scope.post('/api/v1/:side/inbox/:fileId/ack', { preHandler: requireAny }, async (req) => {
      const side = sideOf(req);
      const rec = await fileOf(req, side);
      if (rec.readAt) return ok(rec);
      const next = { ...rec, readAt: new Date().toISOString(), readBy: req.partner?.name ?? null };
      await store.putFile(next);
      audited(req, 'inbox.ack', 'ok', { fileId: rec.fileId, side });
      return ok(next);
    });

    /** Delete a file from an inbox (admin key only). Removes the record and the bytes. */
    scope.delete('/api/v1/:side/inbox/:fileId', { preHandler: requireAdmin }, async (req) => {
      const side = sideOf(req);
      const rec = await fileOf(req, side);
      await files.del(objectKey(rec));
      await store.deleteFile(rec.fileId);
      audited(req, 'inbox.delete', 'ok', { fileId: rec.fileId, side });
      return ok({ fileId: rec.fileId, deleted: true });
    });
  });
}
