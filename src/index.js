// Entry point (local and Vercel). Vercel's Fastify preset looks for src/app.js, src/index.js, …; the routes live in
// src/api.js (not app.js) so that Vercel picks this file, which builds the app and listens.
import 'fastify'; // Vercel's Fastify preset only accepts an entry file that imports fastify itself
import { buildApp } from './api.js';
import { loadConfig } from './config.js';
import { warmUp } from './verify.js';

const config = loadConfig();
const app = buildApp({ ...config, logger: { level: process.env.LOG_LEVEL || 'info' } });
// Hosted platforms (Vercel, Railway, Render, Docker) route traffic to 0.0.0.0:$PORT; locally stay on 127.0.0.1.
const hosted = !!(process.env.VERCEL || process.env.RAILWAY_ENVIRONMENT || process.env.RENDER);
await app.listen({ port: config.port, host: process.env.HOST || (hosted ? '0.0.0.0' : '127.0.0.1') });
app.log.info(`TOTM Trust API on :${config.port} · registry: ${config.registryKind} · store: ${config.store.kind} · partners: ${config.partners.length}`);
if (!hosted) app.log.info(`TrustVC loaded in ${warmUp()} ms`);
