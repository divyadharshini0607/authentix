/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Persistent Relational Database Layer (SQLite WAL + Foreign Keys + Versioned Migrations)
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { safeLog, sha256Hex } from './security.ts';

let sharedDb: DatabaseSync | null = null;
let sharedDbPath: string | null = null;

/**
 * Strips whitespace and surrounding single/double quotes that may be passed literally
 * when users paste `.env` assignments into cloud secret/environment panels.
 */
export function cleanEnvString(raw: string | undefined): string {
  if (!raw) return '';
  const trimmed = raw.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

/**
 * Reads the server-side `ENABLE_DEMO_MODE` configuration flag.
 * Safe by default: returns `true` ONLY when `ENABLE_DEMO_MODE` is explicitly `'true'` or `'1'`.
 * Returns `false` when `'false'`, `'0'`, unset, or any unrecognized value.
 */
export function isDemoModeEnabled(): boolean {
  const explicit = cleanEnvString(process.env.ENABLE_DEMO_MODE).toLowerCase();
  return explicit === 'true' || explicit === '1';
}

function ensureWritableDir(preferredDir: string, fallbackSubdir: string): string {
  try {
    fs.mkdirSync(preferredDir, { recursive: true });
    return preferredDir;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EROFS' || code === 'EACCES' || code === 'EPERM') {
      const fallback = path.join(os.tmpdir(), 'authentix-runtime', fallbackSubdir);
      fs.mkdirSync(fallback, { recursive: true });
      safeLog('WARN', 'storage_dir_readonly_fallback', { preferredDir, fallback });
      return fallback;
    }
    throw err;
  }
}

export function resolveDbPath(overridePath?: string): string {
  const configured = cleanEnvString(overridePath) || cleanEnvString(process.env.SQLITE_DB_PATH) || './data/authentix.sqlite';
  if (configured === ':memory:') {
    return ':memory:';
  }
  return path.resolve(process.cwd(), configured);
}

export function resolveUploadDir(overrideDir?: string): string {
  const raw = cleanEnvString(overrideDir) || cleanEnvString(process.env.UPLOAD_DIR) || './data/uploads';
  const dir = path.resolve(process.cwd(), raw);
  return ensureWritableDir(dir, 'uploads');
}

export function resolveSampleDocsDir(overrideDir?: string): string {
  const raw = cleanEnvString(overrideDir) || cleanEnvString(process.env.SAMPLE_DOCS_DIR) || './data/sample_docs';
  const dir = path.resolve(process.cwd(), raw);
  return ensureWritableDir(dir, 'sample_docs');
}

const KNOWN_POSTGRES_PLACEHOLDERS = new Set([
  '',
  'replace-with-strong-db-password',
  'change_me_local_pg',
  'changeme',
  'placeholder',
  'temp',
  'temporary-placeholder',
  'your-password-here',
]);

export function isPlaceholderPostgresPassword(value: string | undefined): boolean {
  const normalized = cleanEnvString(value).toLowerCase();
  return KNOWN_POSTGRES_PLACEHOLDERS.has(normalized) || normalized.includes('placeholder') || normalized.startsWith('replace-with-');
}

/**
 * Keeps database runtime in development SQLite mode (`./data/authentix.sqlite`) by default.
 * Never attempts PostgreSQL authentication when DB_ENGINE is unset/'sqlite', and strictly blocks
 * placeholder POSTGRES_PASSWORD values if DB_ENGINE='postgres' is requested.
 */
export function assertSafeDatabaseConfig(): void {
  const engine = (cleanEnvString(process.env.DB_ENGINE) || 'sqlite').toLowerCase();
  if (engine === 'postgres' || engine === 'postgresql') {
    if (isPlaceholderPostgresPassword(process.env.POSTGRES_PASSWORD)) {
      throw new Error(
        'Refusing to authenticate to PostgreSQL with a missing or placeholder POSTGRES_PASSWORD. Provide a real secret before enabling DB_ENGINE=postgres.'
      );
    }
    throw new Error(
      'DB_ENGINE=postgres requested, but the active runtime adapter uses node:sqlite. Install `pg` and wire the async pool adapter (see README / db/postgres-schema.sql) before switching DB_ENGINE.'
    );
  }
}

export function openDatabase(overridePath?: string): DatabaseSync {
  assertSafeDatabaseConfig();
  let targetPath = resolveDbPath(overridePath);
  if (!overridePath && sharedDb && sharedDbPath === targetPath) {
    return sharedDb;
  }

  if (targetPath !== ':memory:') {
    const writableParent = ensureWritableDir(path.dirname(targetPath), 'db');
    if (writableParent !== path.dirname(targetPath)) {
      targetPath = path.join(writableParent, path.basename(targetPath));
      if (!overridePath && sharedDb && sharedDbPath === targetPath) {
        return sharedDb;
      }
    }
  }

  const db = new DatabaseSync(targetPath);
  db.exec('PRAGMA foreign_keys = ON;');
  if (targetPath !== ':memory:') {
    db.exec('PRAGMA journal_mode = WAL;');
  }
  db.exec('PRAGMA busy_timeout = 5000;');

  if (!overridePath) {
    sharedDb = db;
    sharedDbPath = targetPath;
  }
  return db;
}

export function closeSharedDatabase(): void {
  if (sharedDb) {
    try {
      sharedDb.close();
    } catch {
      // already closed
    }
    sharedDb = null;
    sharedDbPath = null;
  }
}

export function runMigrations(db: DatabaseSync): { applied: string[]; totalMigrations: number } {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      checksum TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);

  const migrationsDir = path.resolve(process.cwd(), 'db/migrations');
  if (!fs.existsSync(migrationsDir)) {
    throw new Error(`Migrations directory not found at ${migrationsDir}`);
  }

  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const applied: string[] = [];

  for (const file of files) {
    const sqlContent = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    const checksum = sha256Hex(sqlContent);

    const existing = db
      .prepare('SELECT version, checksum FROM schema_migrations WHERE version = ?')
      .get(file) as { version: string; checksum: string } | undefined;

    if (existing) {
      continue;
    }

    withTransaction(db, () => {
      db.exec(sqlContent);
      db.prepare('INSERT INTO schema_migrations (version, checksum, applied_at) VALUES (?, ?, ?)').run(
        file,
        checksum,
        new Date().toISOString()
      );
    });
    applied.push(file);
  }

  return { applied, totalMigrations: files.length };
}

const activeTransactions = new WeakSet<DatabaseSync>();

export function withTransaction<T>(db: DatabaseSync, fn: () => T): T {
  if (activeTransactions.has(db)) {
    return fn();
  }
  db.exec('BEGIN IMMEDIATE;');
  activeTransactions.add(db);
  try {
    const result = fn();
    db.exec('COMMIT;');
    return result;
  } catch (err) {
    try {
      db.exec('ROLLBACK;');
    } catch {
      // ignore secondary rollback failure
    }
    throw err;
  } finally {
    activeTransactions.delete(db);
  }
}
