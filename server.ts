/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Full-Stack Express + Vite Server Entry Point (Port 3000)
 */

import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { DatabaseSync } from 'node:sqlite';
import cookieParser from 'cookie-parser';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import { cleanEnvString, closeSharedDatabase, isDemoModeEnabled, openDatabase, runMigrations } from './src/server/db.ts';
import { createApiRouter } from './src/server/routes.ts';
import { assertSafeProductionSecrets, safeLog } from './src/server/security.ts';
import { ensureDefaultValidationRules, seedDatabase } from './src/server/seed.ts';

export interface CreateServerOptions {
  db?: DatabaseSync;
  dbPath?: string;
  uploadDir?: string;
  sampleDocsDir?: string;
  autoSeed?: boolean;
  attachFrontend?: boolean;
}

export async function createServerApp(options: CreateServerOptions = {}): Promise<{
  app: Express;
  db: DatabaseSync;
}> {
  assertSafeProductionSecrets();
  const db = options.db || openDatabase(options.dbPath);
  runMigrations(db);

  const shouldAutoSeed =
    options.autoSeed !== undefined
      ? options.autoSeed
      : isDemoModeEnabled() && cleanEnvString(process.env.AUTO_SEED_DEMO_DATA).toLowerCase() !== 'false';

  if (shouldAutoSeed) {
    await seedDatabase(db, {
      forceReset: false,
      uploadDir: options.uploadDir,
      sampleDocsDir: options.sampleDocsDir,
      skipExternalOcr: true,
    });
  } else {
    ensureDefaultValidationRules(db);
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Security & CORS headers
  const allowedOrigin = cleanEnvString(process.env.CORS_ORIGIN);
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (allowedOrigin && req.headers.origin === allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    }
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  app.use(cookieParser());
  app.use(express.json({ limit: '2mb' }));

  app.use(
    '/api',
    createApiRouter({
      getDb: () => db,
      uploadDir: options.uploadDir,
      sampleDocsDir: options.sampleDocsDir,
    })
  );

  // Unknown API route handler
  app.use('/api', (_req: Request, res: Response) => {
    res.status(404).json({ error: 'API endpoint not found.' });
  });

  // Frontend serving (Vite dev middleware or built SPA static files)
  if (options.attachFrontend !== false) {
    const distPath = path.resolve(process.cwd(), 'dist');
    const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(distPath);

    if (isProd) {
      app.use(express.static(distPath));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    } else {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
    }
  }

  // Global sanitized error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    safeLog('ERROR', 'unhandled_http_error', { message: err.message });
    res.status(500).json({ error: 'An unexpected server error occurred.' });
  });

  return { app, db };
}

async function ensureLocalOcrServiceIfNeeded(): Promise<(() => void) | null> {
  const autoStart = cleanEnvString(process.env.AUTO_START_OCR_SERVICE).toLowerCase();
  const ocrMode = cleanEnvString(process.env.OCR_MODE).toLowerCase();
  if (autoStart === 'false' || cleanEnvString(process.env.NODE_ENV) === 'test' || ocrMode === 'local-only') {
    return null;
  }

  const ocrUrlRaw = cleanEnvString(process.env.OCR_SERVICE_URL) || 'http://127.0.0.1:8001';
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(ocrUrlRaw);
  } catch {
    return null;
  }

  if (parsedUrl.hostname !== '127.0.0.1' && parsedUrl.hostname !== 'localhost') {
    return null;
  }

  const scriptPath = path.resolve(process.cwd(), 'services/ocr_service/server.py');
  if (!fs.existsSync(scriptPath)) {
    return null;
  }

  // Reuse existing listener if already started by launch script or separate terminal
  try {
    const healthRes = await fetch(`${ocrUrlRaw.replace(/\/$/, '')}/health`, {
      signal: AbortSignal.timeout(800),
    });
    if (healthRes.ok) {
      safeLog('INFO', 'ocr_service_already_online', { url: ocrUrlRaw });
      return null;
    }
  } catch {
    // Not running yet; attempt to spawn locally
  }

  const { spawn, spawnSync } = await import('node:child_process');
  const candidates: Array<{ cmd: string; args: string[] }> =
    process.platform === 'win32'
      ? [
          { cmd: 'py', args: ['-3'] },
          { cmd: 'python', args: [] },
        ]
      : [
          { cmd: 'python3', args: [] },
          { cmd: 'python', args: [] },
        ];

  let chosen: { cmd: string; args: string[] } | null = null;
  for (const cand of candidates) {
    const probe = spawnSync(cand.cmd, [...cand.args, '--version'], { encoding: 'utf8', timeout: 2000 });
    if (probe.status === 0 && `${probe.stdout}${probe.stderr}`.includes('Python 3.')) {
      chosen = cand;
      break;
    }
  }

  if (!chosen) {
    safeLog('WARN', 'ocr_python_runtime_not_found', {
      fallback: 'node-deterministic-pdf-png-extractor',
    });
    return null;
  }

  const ocrPort = parsedUrl.port || process.env.OCR_SERVICE_PORT || '8001';
  const child = spawn(chosen.cmd, [...chosen.args, scriptPath], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      OCR_SERVICE_HOST: '127.0.0.1',
      OCR_SERVICE_PORT: String(ocrPort),
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  });

  child.stderr?.on('data', (chunk: Buffer) => {
    const msg = chunk.toString('utf8').trim();
    if (msg && !msg.includes('GET /health') && !msg.includes('POST /analyze')) {
      safeLog('INFO', 'ocr_service_stderr', { message: msg.slice(0, 240) });
    }
  });

  // Poll briefly so initial requests see the microservice ready
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${ocrUrlRaw.replace(/\/$/, '')}/health`, {
        signal: AbortSignal.timeout(500),
      });
      if (res.ok) {
        safeLog('INFO', 'ocr_service_auto_started', { url: ocrUrlRaw, pid: child.pid });
        break;
      }
    } catch {
      await new Promise((r) => setTimeout(r, 150));
    }
  }

  return () => {
    if (!child.killed) {
      child.kill('SIGTERM');
    }
  };
}

// Start HTTP listener when server.ts is executed directly
const isDirectExecution =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectExecution) {
  const port = Number.parseInt(process.env.PORT || '3000', 10);
  (async () => {
    const stopOcr = await ensureLocalOcrServiceIfNeeded();
    const { app } = await createServerApp();
    const server = app.listen(port, '0.0.0.0', () => {
      safeLog('INFO', 'server_listening', {
        url: `http://0.0.0.0:${port}`,
        env: process.env.NODE_ENV || 'development',
      });
    });

    const shutdown = () => {
      if (stopOcr) stopOcr();
      server.close(() => {
        closeSharedDatabase();
        process.exit(0);
      });
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  })().catch((err) => {
    safeLog('ERROR', 'server_startup_failed', { error: (err as Error).message });
    process.exit(1);
  });
}
