// Entry point (local and Vercel). Vercel's Fastify preset runs this file.
import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { warmUp } from './verify.js';

const config = loadConfig();
const app = buildApp({ ...config, logger: { level: process.env.LOG_LEVEL || 'info' } });
await app.listen({ port: config.port, host: process.env.VERCEL ? '0.0.0.0' : '127.0.0.1' });
app.log.info(`TOTM Trust API on :${config.port} · registry: ${config.registryKind} · store: ${config.store.kind} · partners: ${config.partners.length}`);
if (!process.env.VERCEL) app.log.info(`TrustVC loaded in ${warmUp()} ms`);
