/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Vitest Global Setup — Ephemeral Real Express + SQLite Server for Frontend JSDOM Tests
 *
 * Keeps `tests/frontend.test.tsx` free of Node-only `node:sqlite` imports so Vite's
 * browser (`client` / `jsdom`) bundler validates the React SPA exactly like a real browser
 * while talking to a live seeded Express + SQLite backend over HTTP.
 */

import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createServerApp } from '../server.ts';
import { openDatabase } from '../src/server/db.ts';

export default async function setup() {
  process.env.NODE_ENV = 'test';
  process.env.ENABLE_DEMO_MODE = 'true';
  process.env.DISABLE_RATE_LIMIT = 'true';

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authentix-ui-global-'));
  const db = openDatabase(path.join(tmpDir, 'ui.sqlite'));

  const { app } = await createServerApp({
    db,
    uploadDir: path.join(tmpDir, 'uploads'),
    sampleDocsDir: path.join(tmpDir, 'samples'),
    autoSeed: true,
    attachFrontend: false,
  });

  const httpServer = http.createServer(app);
  await new Promise<void>((resolve) => {
    httpServer.listen(0, '127.0.0.1', () => resolve());
  });

  const addr = httpServer.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  process.env.VITEST_UI_API_URL = `http://127.0.0.1:${port}`;

  return async () => {
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    try {
      db.close();
    } catch {
      // ignore close error
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  };
}
