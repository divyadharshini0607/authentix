#!/usr/bin/env node
/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Database Migration, Seed, Reset, and Bootstrap Admin CLI Utility
 * Usage:
 *   npm run db:migrate
 *   npm run db:seed
 *   npm run db:reset
 *   npm run db:create-admin
 */

import 'dotenv/config';
import crypto from 'node:crypto';
import { appendAuditEvent, verifyAuditChain } from '../src/server/auditLog.ts';
import {
  cleanEnvString,
  closeSharedDatabase,
  isDemoModeEnabled,
  openDatabase,
  resolveDbPath,
  runMigrations,
  withTransaction,
} from '../src/server/db.ts';
import { hashPassword } from '../src/server/security.ts';
import { ensureDefaultValidationRules, seedDatabase } from '../src/server/seed.ts';

async function main() {
  const cmd = (process.argv[2] || 'migrate').toLowerCase();
  const forceDemoFlag = process.argv.includes('--force-demo');
  const dbPath = resolveDbPath();
  console.log(`[authentix-db] Target SQLite database: ${dbPath}`);
  const db = openDatabase();

  try {
    if (cmd === 'migrate') {
      const res = runMigrations(db);
      ensureDefaultValidationRules(db);
      console.log(
        `[authentix-db] Migrations complete. Newly applied: ${res.applied.length} / Total: ${res.totalMigrations}`
      );
    } else if (cmd === 'seed') {
      runMigrations(db);
      if (!isDemoModeEnabled() && !forceDemoFlag) {
        ensureDefaultValidationRules(db);
        console.log(
          '[authentix-db] ENABLE_DEMO_MODE is false: initialized baseline validation rules without synthetic demo accounts or sample data.'
        );
        console.log(
          "[authentix-db] Set ENABLE_DEMO_MODE=true in .env for synthetic evaluation data, or run 'npm run db:create-admin' to provision an institutional administrator."
        );
      } else {
        const summary = await seedDatabase(db, { forceReset: false });
        console.log(
          summary.seeded
            ? `[authentix-db] Seeded ${summary.usersCount} synthetic demo accounts, ${summary.institutionsCount} institutions, ${summary.applicationsCount} applications, ${summary.documentsCount} documents.`
            : `[authentix-db] Synthetic demo accounts already initialized (${summary.usersCount} users, ${summary.applicationsCount} applications). Use 'npm run db:reset' to wipe and re-seed.`
        );
      }
    } else if (cmd === 'reset') {
      if (!isDemoModeEnabled() && !forceDemoFlag) {
        console.error(
          "[authentix-db] Refusing destructive synthetic reset while ENABLE_DEMO_MODE=false. Set ENABLE_DEMO_MODE=true or pass '--force-demo'."
        );
        process.exitCode = 1;
        return;
      }
      const summary = await seedDatabase(db, { forceReset: true });
      const chain = verifyAuditChain(db);
      console.log(
        `[authentix-db] Reset & re-seeded complete: ${summary.applicationsCount} applications, ${summary.documentsCount} documents, audit chain valid=${chain.valid} (${chain.totalEventsChecked} events).`
      );
    } else if (cmd === 'create-admin') {
      runMigrations(db);
      ensureDefaultValidationRules(db);
      const email = cleanEnvString(process.env.BOOTSTRAP_ADMIN_EMAIL).toLowerCase();
      const password = cleanEnvString(process.env.BOOTSTRAP_ADMIN_PASSWORD);
      const fullName = cleanEnvString(process.env.BOOTSTRAP_ADMIN_NAME) || 'Platform Administrator';

      if (!email || !email.includes('@') || email.endsWith('.demo')) {
        console.error(
          '[authentix-db] Set BOOTSTRAP_ADMIN_EMAIL to a valid non-.demo institutional email address before running db:create-admin.'
        );
        process.exitCode = 1;
        return;
      }
      if (!password || password.length < 10) {
        console.error(
          '[authentix-db] Set BOOTSTRAP_ADMIN_PASSWORD (minimum 10 characters) before running db:create-admin.'
        );
        process.exitCode = 1;
        return;
      }

      const nowIso = new Date().toISOString();
      const pwHash = hashPassword(password);
      const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = ?').get(email) as
        | { id: string }
        | undefined;
      const userId = existing?.id || `USR-${crypto.randomUUID()}`;

      withTransaction(db, () => {
        if (existing) {
          db.prepare(
            'UPDATE users SET password_hash = ?, full_name = ?, role = ?, is_active = 1, is_demo_account = 0 WHERE id = ?'
          ).run(pwHash, fullName, 'ADMIN', userId);
        } else {
          db.prepare(
            `INSERT INTO users (
              id, email, password_hash, full_name, role, institution_id, is_active, is_demo_account, created_at
            ) VALUES (?, ?, ?, ?, 'ADMIN', NULL, 1, 0, ?)`
          ).run(userId, email, pwHash, fullName, nowIso);
        }

        appendAuditEvent(db, {
          actorUserId: userId,
          actorEmail: email,
          actorRole: 'ADMIN',
          action: existing ? 'ADMIN_ACCOUNT_UPDATED' : 'ADMIN_ACCOUNT_BOOTSTRAPPED',
          resourceType: 'USER',
          resourceId: userId,
          metadata: { provisionedViaCli: true },
          timestamp: nowIso,
        });
      });

      console.log(`[authentix-db] Provisioned active non-demo ADMIN account for ${email}.`);
    } else {
      console.error(`Unknown command '${cmd}'. Expected: migrate | seed | reset | create-admin`);
      process.exitCode = 1;
    }
  } finally {
    closeSharedDatabase();
  }
}

main().catch((err) => {
  console.error('[authentix-db] Fatal error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
