import express, { type NextFunction, type Request, type Response } from 'express';
import { timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import dotenv from 'dotenv';
import { apiRouter } from './server/routes.js';

dotenv.config();

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT ?? 3000);
const apiToken = process.env.PROOFVAPT_API_TOKEN?.trim();

function tokenMatches(candidate: string | undefined): boolean {
  if (!apiToken || !candidate) return false;
  const expected = Buffer.from(apiToken, 'utf8');
  const supplied = Buffer.from(candidate, 'utf8');
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

function bearerToken(req: Request): string | undefined {
  const header = req.header('authorization');
  if (!header?.startsWith('Bearer ')) return undefined;
  return header.slice('Bearer '.length).trim();
}

function requireApiToken(req: Request, res: Response, next: NextFunction) {
  if (!isProduction || tokenMatches(bearerToken(req))) return next();
  res.status(401).json({ error: 'Authentication required. Enter the deployment API token to continue.' });
}

async function startServer() {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535.');
  }
  if (isProduction && (!apiToken || Buffer.byteLength(apiToken, 'utf8') < 32)) {
    throw new Error('Production startup blocked: set PROOFVAPT_API_TOKEN to a random secret of at least 32 bytes.');
  }

  app.disable('x-powered-by');
  app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (isProduction) {
      res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob:; connect-src 'self'");
      res.setHeader('Strict-Transport-Security', 'max-age=15552000');
    }
    next();
  });

  app.use(express.json({ limit: '256kb', strict: true }));

  // Liveness and one small authenticated-session check are intentionally available
  // before the API gate so the browser can establish whether its token is valid.
  app.get('/api/health', (_req, res) => {
    res.status(200).json({ status: 'ok', service: 'ProofVAPT', timestamp: new Date().toISOString() });
  });

  app.get('/api/session', (req, res) => {
    if (!isProduction) {
      res.json({ authenticated: true, authenticationRequired: false });
      return;
    }
    if (!tokenMatches(bearerToken(req))) {
      res.status(401).json({ authenticated: false, authenticationRequired: true });
      return;
    }
    res.json({ authenticated: true, authenticationRequired: true });
  });

  app.use('/api', requireApiToken, apiRouter);
  app.use('/api', requireApiToken, (_req, res) => {
    res.status(404).json({ error: 'API route not found' });
  });

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath, { index: false, fallthrough: true, maxAge: '1h' }));
    app.get('*', (_req, res, next) => {
      res.sendFile(path.resolve(distPath, 'index.html'), (err) => {
        if (err) next(err);
      });
    });
  }

  app.use((err: Error & { status?: number }, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status === 413 ? 413 : 400;
    if (status === 413) {
      res.status(status).json({ error: 'Request body is too large.' });
      return;
    }
    console.error('[ProofVAPT] Request failed:', err.message);
    res.status(400).json({ error: 'Invalid request.' });
  });

  const server = app.listen(port, '0.0.0.0', () => {
    console.log(`[ProofVAPT] Listening on 0.0.0.0:${port} (${isProduction ? 'production' : 'development'} mode)`);
  });
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;

  const shutdown = (signal: string) => {
    console.log(`[ProofVAPT] ${signal} received; shutting down HTTP server.`);
    server.close((error) => {
      if (error) {
        console.error('[ProofVAPT] Shutdown error:', error);
        process.exitCode = 1;
      }
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
}

startServer().catch((error) => {
  console.error('[ProofVAPT] Startup blocked:', error instanceof Error ? error.message : error);
  process.exit(1);
});
