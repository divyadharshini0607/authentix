/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Backend Unit, Security, RBAC, Pipeline, Rules & Audit Chain Tests
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Express } from 'express';
import type { DatabaseSync } from 'node:sqlite';
import { createServerApp } from '../server.ts';
import { verifyAuditChain } from '../src/server/auditLog.ts';
import { openDatabase, runMigrations } from '../src/server/db.ts';
import { generateSyntheticPdfBuffer, generateSyntheticPngBuffer } from '../src/server/pdfGenerator.ts';
import {
  assertSafeProductionSecrets,
  hashPassword,
  QrSigningSecretUnavailableError,
  sha256Hex,
  signQrPayload,
  validateUploadedFileBuffer,
  verifyPassword,
} from '../src/server/security.ts';
import {
  DEFAULT_DEMO_PASSWORD,
  ensureDefaultValidationRules,
  seedDatabase,
} from '../src/server/seed.ts';

describe('AUTHENTIX Backend Core, Security, Rules & Persistence Suite', () => {
  let tmpDir: string;
  let dbPath: string;
  let uploadDir: string;
  let sampleDocsDir: string;
  let app: Express;
  let db: DatabaseSync;

  let officerToken = '';
  let officerCsrf = '';
  let officerCookie = '';
  let auditorToken = '';
  let adminToken = '';
  let instToken = '';

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.ENABLE_DEMO_MODE = 'true';
    process.env.DISABLE_RATE_LIMIT = 'true';

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authentix-backend-test-'));
    dbPath = path.join(tmpDir, 'test.sqlite');
    uploadDir = path.join(tmpDir, 'uploads');
    sampleDocsDir = path.join(tmpDir, 'samples');

    const created = await createServerApp({
      db: openDatabase(dbPath),
      uploadDir,
      sampleDocsDir,
      autoSeed: true,
      attachFrontend: false,
    });
    app = created.app;
    db = created.db;
  });

  afterAll(() => {
    try {
      db.close();
    } catch {
      // ignore
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('1. hashes and verifies passwords accurately with scrypt + constant-time check', () => {
    const hashed = hashPassword('StrongPass#2026');
    expect(hashed.startsWith('scrypt$16384$8$1$')).toBe(true);
    expect(verifyPassword('StrongPass#2026', hashed)).toBe(true);
    expect(verifyPassword('WrongPass#2026', hashed)).toBe(false);
    expect(verifyPassword('StrongPass#2026', 'malformed$hash')).toBe(false);
  });

  it('2. authenticates all seeded demo roles and rejects wrong credentials', async () => {
    const emptyRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'officer@authentix.demo', password: '' });
    expect(emptyRes.status).toBe(400);

    const unknownUserRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nonexistent@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
    expect(unknownUserRes.status).toBe(401);

    const badRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'officer@authentix.demo', password: 'WrongPassword123' });
    expect(badRes.status).toBe(401);

    // Verify HTTPS reverse-proxy request issues SameSite=None; Secure HttpOnly session cookie
    const httpsOfficerRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-Proto', 'https')
      .send({ email: 'officer@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
    expect(httpsOfficerRes.status).toBe(200);
    const httpsCookieHeader = String(httpsOfficerRes.headers['set-cookie'] || '');
    expect(httpsCookieHeader).toContain('SameSite=None');
    expect(httpsCookieHeader).toContain('Secure');
    expect(httpsCookieHeader).toContain('HttpOnly');

    const officerRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'officer@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
    expect(officerRes.status).toBe(200);
    expect(officerRes.body.user.role).toBe('REVIEW_OFFICER');
    officerToken = officerRes.body.sessionToken;
    officerCsrf = officerRes.body.csrfToken;
    const setCookies = officerRes.headers['set-cookie'];
    officerCookie = Array.isArray(setCookies) ? setCookies[0].split(';')[0] : String(setCookies).split(';')[0];

    const auditorRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'auditor@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
    expect(auditorRes.status).toBe(200);
    auditorToken = auditorRes.body.sessionToken;

    const adminRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
    expect(adminRes.status).toBe(200);
    adminToken = adminRes.body.sessionToken;

    const instRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'registrar@kaveritech.demo', password: DEFAULT_DEMO_PASSWORD });
    expect(instRes.status).toBe(200);
    expect(instRes.body.user.institutionId).toBe('INST-KVTC-02');
    instToken = instRes.body.sessionToken;
  });

  it('3. enforces session validation, CSRF on cookie mutations, expiry, and logout revocation', async () => {
    const noAuth = await request(app).get('/api/dashboard/stats');
    expect(noAuth.status).toBe(401);

    // Cookie session without X-CSRF-Token on POST must fail with 403
    const csrfBlocked = await request(app)
      .post('/api/applications/APP-ID-0101/re-evaluate')
      .set('Cookie', officerCookie);
    expect(csrfBlocked.status).toBe(403);

    // Cookie session WITH valid X-CSRF-Token succeeds
    const csrfAllowed = await request(app)
      .post('/api/applications/APP-ID-0101/re-evaluate')
      .set('Cookie', officerCookie)
      .set('X-CSRF-Token', officerCsrf);
    expect(csrfAllowed.status).toBe(200);

    // Create a temporary login, expire it in DB, and verify 401
    const tempLogin = await request(app)
      .post('/api/auth/login')
      .send({ email: 'officer@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
    const tempTok = tempLogin.body.sessionToken as string;
    db.prepare('UPDATE user_sessions SET expires_at = ? WHERE token_hash = ?').run(
      '2020-01-01T00:00:00.000Z',
      sha256Hex(tempTok)
    );
    const expiredCheck = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${tempTok}`);
    expect(expiredCheck.status).toBe(401);

    // Logout revocation test
    const logoutLogin = await request(app)
      .post('/api/auth/login')
      .send({ email: 'officer@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
    const revTok = logoutLogin.body.sessionToken as string;
    const outRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${revTok}`);
    expect(outRes.status).toBe(200);

    const afterLogout = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${revTok}`);
    expect(afterLogout.status).toBe(401);
  });

  it('4. enforces RBAC and strict institution-level data isolation', async () => {
    // Institution user only sees INST-KVTC-02 applications
    const instApps = await request(app)
      .get('/api/applications')
      .set('Authorization', `Bearer ${instToken}`);
    expect(instApps.status).toBe(200);
    expect(instApps.body.applications.length).toBe(1);
    expect(instApps.body.applications[0].institutionId).toBe('INST-KVTC-02');

    // Institution user blocked from viewing another institution's application (APP-ID-0101)
    const crossApp = await request(app)
      .get('/api/applications/APP-ID-0101')
      .set('Authorization', `Bearer ${instToken}`);
    expect(crossApp.status).toBe(403);

    // Institution user blocked from downloading another institution's document
    const crossDoc = await request(app)
      .get('/api/documents/DOC-0101-1/file')
      .set('Authorization', `Bearer ${instToken}`);
    expect(crossDoc.status).toBe(403);

    // Institution user blocked from audit logs and officer review endpoints
    const instAudit = await request(app)
      .get('/api/audit-logs')
      .set('Authorization', `Bearer ${instToken}`);
    expect(instAudit.status).toBe(403);

    const instOfficerAct = await request(app)
      .post('/api/applications/APP-ID-0102/officer-actions')
      .set('Authorization', `Bearer ${instToken}`)
      .send({ actionType: 'ADD_REVIEW_NOTE', rationale: 'Attempted unauthorized note' });
    expect(instOfficerAct.status).toBe(403);

    // Auditor blocked from final approval decision (restricted to REVIEW_OFFICER / ADMIN)
    const auditorApprove = await request(app)
      .post('/api/applications/APP-ID-0101/officer-actions')
      .set('Authorization', `Bearer ${auditorToken}`)
      .send({
        actionType: 'FINAL_DECISION_APPROVE',
        rationale: 'Auditor attempting final regulatory decision without officer role.',
      });
    expect(auditorApprove.status).toBe(403);
  });

  it('5. validates file uploads strictly (magic bytes, extensions, path traversal) and computes SHA-256', async () => {
    // Reject unsupported extension
    const badExt = await request(app)
      .post('/api/applications/APP-ID-0103/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'FIRE_SAFETY_CERTIFICATE')
      .attach('file', Buffer.from('MZ fake executable'), 'malware.exe');
    expect(badExt.status).toBe(400);

    // Reject fake PDF lacking %PDF- header
    const fakePdf = await request(app)
      .post('/api/applications/APP-ID-0103/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'FIRE_SAFETY_CERTIFICATE')
      .attach('file', Buffer.from('NOT A REAL PDF FILE'), 'fake.pdf');
    expect(fakePdf.status).toBe(400);
    expect(fakePdf.body.error).toContain('%PDF-');

    // Reject path traversal filename override
    const validPdfBuf = await generateSyntheticPdfBuffer({
      title: 'LAND USE CERTIFICATE',
      lines: [
        'Issuing Authority: Himachal Revenue Department',
        'Certificate No: LUC-HP-2026-9012',
        'Institution Name: Shivalik Hills Polytechnic',
        'Land Area: 4.0 Acres',
        'Issue Date: 2026-06-15',
      ],
    });

    const traversalRes = await request(app)
      .post('/api/applications/APP-ID-0103/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'LAND_USE_CERTIFICATE')
      .field('originalFilenameOverride', '../../etc/passwd.pdf')
      .attach('file', validPdfBuf, 'land.pdf');
    expect(traversalRes.status).toBe(400);

    // Valid PDF upload succeeds, hashes SHA-256 accurately, and extracts structured fields
    const goodUpload = await request(app)
      .post('/api/applications/APP-ID-0103/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'LAND_USE_CERTIFICATE')
      .attach('file', validPdfBuf, 'Land_Use_Shivalik_2026.pdf');

    expect(goodUpload.status).toBe(201);
    expect(goodUpload.body.document.sha256Hash).toBe(sha256Hex(validPdfBuf));
    expect(goodUpload.body.document.ocrStatus).toBe('COMPLETED');
    expect(goodUpload.body.document.detectedDocType).toBe('LAND_USE_CERTIFICATE');
    const certField = goodUpload.body.document.extractedFields.find(
      (f: { fieldName: string }) => f.fieldName === 'certificate_number'
    );
    expect(certField?.fieldValue).toBe('LUC-HP-2026-9012');
  });

  it('6. handles OCR unavailability, timeouts, and raster-only scans honestly without fabricating text', async () => {
    const pdfBuf = await generateSyntheticPdfBuffer({
      title: 'BUILDING PLAN APPROVAL',
      lines: ['Certificate No: BPA-HP-2026-100', 'Built-up Area: 900 sqm'],
    });

    const unavailRes = await request(app)
      .post('/api/applications/APP-ID-0103/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'BUILDING_PLAN_APPROVAL')
      .field('ocrModeOverride', 'unavailable')
      .attach('file', pdfBuf, 'Building_Unavailable_Test.pdf');

    expect(unavailRes.status).toBe(201);
    expect(unavailRes.body.document.ocrStatus).toBe('UNAVAILABLE');
    expect(unavailRes.body.document.extractedText).toBe('');
    expect(unavailRes.body.document.verificationStatus).toBe('MANUAL_REVIEW_REQUIRED');
    // Crucial safety rule: never auto-rejects application on OCR unavailability
    expect(unavailRes.body.application.finalOfficerDecision).toBeNull();

    const timeoutRes = await request(app)
      .post('/api/applications/APP-ID-0103/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'AICTE_FEE_RECEIPT')
      .field('ocrModeOverride', 'timeout')
      .attach('file', pdfBuf, 'Fee_Timeout_Test.pdf');

    expect(timeoutRes.status).toBe(201);
    expect(timeoutRes.body.document.ocrStatus).toBe('FAILED');
    expect(timeoutRes.body.document.extractedFields.length).toBe(0);

    // Raw raster PNG without embedded text
    const rawPng = generateSyntheticPngBuffer({ includeRasterOnly: true });
    const rasterRes = await request(app)
      .post('/api/applications/APP-ID-0103/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'FIRE_SAFETY_CERTIFICATE')
      .field('ocrModeOverride', 'local-only')
      .attach('file', rawPng, 'Raw_Scan.png');
    expect(rasterRes.status).toBe(201);
    expect(rasterRes.body.document.ocrStatus).toBe('UNAVAILABLE');
    expect(rasterRes.body.document.extractedText).toBe('');
  });

  it('7. detects expired certificates, intake mismatches, exact SHA-256 duplicates, and PDF metadata anomalies without auto-rejecting', async () => {
    // APP-ID-0102 has expired Fire Safety + intake mismatch
    const kvtcRes = await request(app)
      .get('/api/applications/APP-ID-0102')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(kvtcRes.status).toBe(200);
    const kvtcCodes = kvtcRes.body.findings.map((f: { ruleCode: string }) => f.ruleCode);
    expect(kvtcCodes).toContain('RULE-DOC-EXPIRY');
    expect(kvtcCodes).toContain('RULE-INTAKE-MATCH');
    expect(kvtcRes.body.finalOfficerDecision).toBeNull();

    // APP-ID-0104 has exact SHA-256 duplicate of DOC-0101-1 + Photoshop metadata indicator
    const dmceRes = await request(app)
      .get('/api/applications/APP-ID-0104')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(dmceRes.status).toBe(200);
    const dmceCodes = dmceRes.body.findings.map((f: { ruleCode: string }) => f.ruleCode);
    expect(dmceCodes).toContain('RULE-SHA256-DUPLICATE');
    expect(dmceCodes).toContain('RULE-DUP-IDENTIFIER');
    expect(dmceCodes).toContain('ANOMALY-PDF_IMAGE_EDITOR_PRODUCER');
    expect(dmceRes.body.finalOfficerDecision).toBeNull();
  });

  it('8. distinguishes sandbox vs manual source verification, supports officer decisions & auditor reopen, and updates configurable rules', async () => {
    // Simulated upstream source unavailability
    const unavailVerif = await request(app)
      .post('/api/applications/APP-ID-0102/documents/DOC-0102-3/verify-source')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({ method: 'SANDBOX_ISSUER_API', simulateIssuerUnavailable: true });
    expect(unavailVerif.status).toBe(200);
    expect(unavailVerif.body.verification.isSandboxDemo).toBe(true);
    expect(unavailVerif.body.verification.status).toBe('SOURCE_UNAVAILABLE');

    // Manual verification by officer
    const manualVerif = await request(app)
      .post('/api/applications/APP-ID-0102/documents/DOC-0102-3/verify-source')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        method: 'MANUAL_OFFICER_VERIFICATION',
        manualStatus: 'VERIFIED',
        issuerName: 'DTCP Coimbatore',
        referenceNumber: 'BPA-TN-2025-8812',
        notes: 'Confirmed via official dispatch letter #409.',
      });
    expect(manualVerif.status).toBe(200);
    expect(manualVerif.body.verification.isSandboxDemo).toBe(false);
    expect(manualVerif.body.verification.status).toBe('VERIFIED');

    // Officer approves clean application APP-ID-0101 with human rationale
    const approveRes = await request(app)
      .post('/api/applications/APP-ID-0101/officer-actions')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        actionType: 'FINAL_DECISION_APPROVE',
        rationale: 'All mandatory certificates verified and consistent with master records.',
      });
    expect(approveRes.status).toBe(200);
    expect(approveRes.body.status).toBe('APPROVED_BY_OFFICER');
    expect(approveRes.body.finalOfficerDecision).toBe('APPROVED_BY_OFFICER');

    // Auditor reopens APP-ID-0101
    const reopenRes = await request(app)
      .post('/api/applications/APP-ID-0101/officer-actions')
      .set('Authorization', `Bearer ${auditorToken}`)
      .send({
        actionType: 'REOPEN_APPLICATION',
        rationale: 'Reopened for spot-audit verification of building block annexure.',
      });
    expect(reopenRes.status).toBe(200);
    expect(reopenRes.body.status).toBe('REOPENED');
    expect(reopenRes.body.finalOfficerDecision).toBeNull();

    // Admin publishes a new version of RULE-INFRA-NORMS
    const ruleRes = await request(app)
      .post('/api/rules/RULE-INFRA-NORMS/versions')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        version: '1.1.0',
        severity: 'HIGH',
        description: 'Updated configurable built-up area threshold per student.',
        config: { minBuiltUpSqmPerStudent: 4.2 },
      });
    expect(ruleRes.status).toBe(201);
    expect(ruleRes.body.version).toBe('1.1.0');
  });

  it('9. exports accurate RFC-4180 CSV reports and detects unauthorised tampering in the SHA-256 audit hash chain', async () => {
    const csvRes = await request(app)
      .get('/api/applications/APP-ID-0102/report?format=csv')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(csvRes.status).toBe(200);
    expect(csvRes.headers['content-type']).toContain('text/csv');
    expect(csvRes.text).toContain('APP-2026-0102');
    expect(csvRes.text).toContain('RULE-DOC-EXPIRY');

    // Verify intact audit chain via API
    const chainOk = await request(app)
      .get('/api/audit-logs/verify')
      .set('Authorization', `Bearer ${auditorToken}`);
    expect(chainOk.status).toBe(200);
    expect(chainOk.body.valid).toBe(true);
    expect(chainOk.body.totalEventsChecked).toBeGreaterThan(10);

    // Simulate direct SQL tampering on an intermediate audit row and confirm detection
    const targetAudit = db
      .prepare('SELECT id, event_id, action FROM audit_logs ORDER BY id ASC LIMIT 1 OFFSET 2')
      .get() as { id: number; event_id: string; action: string };

    db.prepare('UPDATE audit_logs SET action = ? WHERE id = ?').run('TAMPERED_ACTION', targetAudit.id);

    const brokenCheck = verifyAuditChain(db);
    expect(brokenCheck.valid).toBe(false);
    expect(brokenCheck.brokenAtEventId).toBe(targetAudit.event_id);

    // Restore original value and confirm chain passes again
    db.prepare('UPDATE audit_logs SET action = ? WHERE id = ?').run(targetAudit.action, targetAudit.id);
    expect(verifyAuditChain(db).valid).toBe(true);
  });

  it('10. enforces ENABLE_DEMO_MODE=true rules: exposes only synthetic *.demo accounts and sample fixtures without bypassing password or RBAC', async () => {
    process.env.ENABLE_DEMO_MODE = 'true';

    // Insert a real non-demo institution (is_synthetic_demo = 0) and real officer (is_demo_account = 0)
    const nowIso = new Date().toISOString();
    const realOfficerPass = 'RealRegulator#Pass2026!';
    db.prepare(
      `INSERT INTO institutions (
        id, code, name, state, district, institution_type, established_year,
        approved_intake, land_area_acres, built_up_area_sqm, principal_name,
        aicte_permanent_id, is_synthetic_demo, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
    ).run(
      'INST-REAL-01',
      'NITS-KA',
      'National Institute of Technical Studies',
      'Karnataka',
      'Bengaluru',
      'Government Autonomous Technical Institution',
      1998,
      300,
      12.5,
      4800,
      'Dr. A.R. Kulkarni',
      '1-10000101',
      nowIso
    );

    db.prepare(
      `INSERT INTO users (
        id, email, password_hash, full_name, role, institution_id, is_active, is_demo_account, created_at
      ) VALUES (?, ?, ?, ?, 'REVIEW_OFFICER', NULL, 1, 0, ?)`
    ).run(
      'USR-REAL-OFFICER',
      'officer@regulator.gov.in',
      hashPassword(realOfficerPass),
      'S. Raghavan (Scrutiny Officer)',
      nowIso
    );

    const statusRes = await request(app).get('/api/auth/demo-status');
    expect(statusRes.status).toBe(200);
    expect(statusRes.body.demoMode).toBe(true);

    const demoRes = await request(app).get('/api/auth/demo-accounts');
    expect(demoRes.status).toBe(200);
    expect(demoRes.body.demoMode).toBe(true);
    expect(demoRes.body.accounts.length).toBeGreaterThanOrEqual(4);

    // Must ONLY return synthetic *.demo accounts and NEVER expose real non-demo users
    for (const acc of demoRes.body.accounts as Array<{ email: string; isSyntheticDemo: boolean }>) {
      expect(acc.email.endsWith('.demo')).toBe(true);
      expect(acc.isSyntheticDemo).toBe(true);
      expect(acc.email).not.toBe('officer@regulator.gov.in');
    }

    // Sample fixtures allowed and labeled synthetic in demo mode
    const fixturesRes = await request(app)
      .get('/api/sample-fixtures')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(fixturesRes.status).toBe(200);
    expect(fixturesRes.body.fixtures.length).toBeGreaterThan(0);
    expect(fixturesRes.body.fixtures[0].isSyntheticDemo).toBe(true);

    // Demo mode still never bypasses password verification or authorization
    const badDemoPass = await request(app)
      .post('/api/auth/login')
      .send({ email: 'officer@authentix.demo', password: 'ArbitraryBypassAttempt' });
    expect(badDemoPass.status).toBe(401);

    const rbacDenied = await request(app)
      .get('/api/audit-logs')
      .set('Authorization', `Bearer ${instToken}`);
    expect(rbacDenied.status).toBe(403);
  });

  it('11. enforces ENABLE_DEMO_MODE=false (and unset default): disables demo shortcuts, blocks demo accounts & synthetic data, and preserves real auth/RBAC', async () => {
    const prevDemoFlag = process.env.ENABLE_DEMO_MODE;

    try {
      // Unset ENABLE_DEMO_MODE defaults safely to false
      delete process.env.ENABLE_DEMO_MODE;
      const unsetStatus = await request(app).get('/api/auth/demo-status');
      expect(unsetStatus.status).toBe(200);
      expect(unsetStatus.body.demoMode).toBe(false);

      // Explicit ENABLE_DEMO_MODE=false
      process.env.ENABLE_DEMO_MODE = 'false';

      const healthRes = await request(app).get('/api/health');
      expect(healthRes.status).toBe(200);
      expect(healthRes.body.demoMode).toBe(false);

      // Demo accounts & credentials endpoint strictly disabled (403, no passphrase, empty accounts)
      const demoAccountsRes = await request(app).get('/api/auth/demo-accounts');
      expect(demoAccountsRes.status).toBe(403);
      expect(demoAccountsRes.body.demoMode).toBe(false);
      expect(demoAccountsRes.body.accounts).toEqual([]);
      expect(demoAccountsRes.body.demoPassphrase).toBeUndefined();

      // Synthetic demo login rejected: wrong password still returns 401; valid demo password returns 403
      const wrongDemoLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: 'officer@authentix.demo', password: 'WrongPassword!' });
      expect(wrongDemoLogin.status).toBe(401);

      const blockedDemoLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: 'officer@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
      expect(blockedDemoLogin.status).toBe(403);
      expect(blockedDemoLogin.body.error).toMatch(/ENABLE_DEMO_MODE is false/i);

      // Previously issued synthetic demo session token is also blocked in requireAuth
      const blockedDemoSession = await request(app)
        .get('/api/dashboard/stats')
        .set('Authorization', `Bearer ${officerToken}`);
      expect(blockedDemoSession.status).toBe(403);

      // Real non-demo account authenticates via scrypt and enforces RBAC + synthetic data isolation
      const badRealLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: 'officer@regulator.gov.in', password: 'WrongPassword!' });
      expect(badRealLogin.status).toBe(401);

      const realLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: 'officer@regulator.gov.in', password: 'RealRegulator#Pass2026!' });
      expect(realLogin.status).toBe(200);
      expect(realLogin.body.demoMode).toBe(false);
      expect(realLogin.body.user.isDemoAccount).toBe(false);
      const realToken = realLogin.body.sessionToken as string;

      // Demo-only sample fixtures & reset endpoints remain 403 even for authenticated non-demo users
      const blockedFixtures = await request(app)
        .get('/api/sample-fixtures')
        .set('Authorization', `Bearer ${realToken}`);
      expect(blockedFixtures.status).toBe(403);

      // RBAC still enforced for real officer (cannot publish ADMIN-only rule versions)
      const rbacRuleBlocked = await request(app)
        .post('/api/rules/RULE-INFRA-NORMS/versions')
        .set('Authorization', `Bearer ${realToken}`)
        .send({
          version: '1.2.0',
          severity: 'HIGH',
          description: 'Unauthorized attempt by non-admin officer.',
          config: { minBuiltUpSqmPerStudent: 4.5 },
        });
      expect(rbacRuleBlocked.status).toBe(403);

      // Synthetic sample institutions and applications are excluded when ENABLE_DEMO_MODE=false
      const instListRes = await request(app)
        .get('/api/institutions')
        .set('Authorization', `Bearer ${realToken}`);
      expect(instListRes.status).toBe(200);
      expect(instListRes.body.institutions.length).toBe(1);
      expect(instListRes.body.institutions[0].id).toBe('INST-REAL-01');
      expect(instListRes.body.institutions[0].isSyntheticDemo).toBe(false);

      const hiddenSynthApp = await request(app)
        .get('/api/applications/APP-ID-0101')
        .set('Authorization', `Bearer ${realToken}`);
      expect(hiddenSynthApp.status).toBe(404);

      const blockedSynthCreate = await request(app)
        .post('/api/applications')
        .set('Authorization', `Bearer ${realToken}`)
        .send({
          institutionId: 'INST-IIET-01',
          academicYear: '2026-27',
          category: 'EXTENSION_OF_APPROVAL',
          programNames: 'B.Tech Civil Engineering',
          requestedIntake: 120,
          submittedLandAcres: 5.5,
          submittedBuiltUpSqm: 1400,
          submittedPrincipalName: 'Dr. R. Prasad',
        });
      expect(blockedSynthCreate.status).toBe(403);

      // Creating an application for the real institution marks isSyntheticDemo = false
      const realAppCreate = await request(app)
        .post('/api/applications')
        .set('Authorization', `Bearer ${realToken}`)
        .send({
          institutionId: 'INST-REAL-01',
          academicYear: '2026-27',
          category: 'EXTENSION_OF_APPROVAL',
          programNames: 'B.Tech Electronics & Communication',
          requestedIntake: 180,
          submittedLandAcres: 12.5,
          submittedBuiltUpSqm: 4800,
          submittedPrincipalName: 'Dr. A.R. Kulkarni',
        });
      expect(realAppCreate.status).toBe(201);
      expect(realAppCreate.body.isSyntheticDemo).toBe(false);

      // Fresh server startup with ENABLE_DEMO_MODE=false does NOT auto-seed synthetic demo users/apps
      const cleanNonDemoDbPath = path.join(tmpDir, 'non-demo-startup.sqlite');
      const nonDemoInstance = await createServerApp({
        db: openDatabase(cleanNonDemoDbPath),
        uploadDir: path.join(tmpDir, 'non-demo-uploads'),
        sampleDocsDir: path.join(tmpDir, 'non-demo-samples'),
        attachFrontend: false,
      });
      try {
        const seededDemoUsers = (
          nonDemoInstance.db.prepare('SELECT COUNT(*) AS c FROM users WHERE is_demo_account = 1').get() as {
            c: number;
          }
        ).c;
        const seededDemoApps = (
          nonDemoInstance.db.prepare('SELECT COUNT(*) AS c FROM applications').get() as { c: number }
        ).c;
        const defaultRules = (
          nonDemoInstance.db.prepare('SELECT COUNT(*) AS c FROM validation_rules').get() as { c: number }
        ).c;
        expect(seededDemoUsers).toBe(0);
        expect(seededDemoApps).toBe(0);
        expect(defaultRules).toBe(10);
      } finally {
        nonDemoInstance.db.close();
      }
    } finally {
      if (prevDemoFlag === undefined) {
        delete process.env.ENABLE_DEMO_MODE;
      } else {
        process.env.ENABLE_DEMO_MODE = prevDemoFlag;
      }
    }
  });

  it('12. enforces production secret checks and fails safely on missing QR_SIGNING_SECRET without hard-coded fallbacks', async () => {
    const prevNodeEnv = process.env.NODE_ENV;
    const prevSessionSecret = process.env.SESSION_SECRET;
    const prevQrSecret = process.env.QR_SIGNING_SECRET;

    try {
      process.env.NODE_ENV = 'production';
      delete process.env.SESSION_SECRET;
      delete process.env.QR_SIGNING_SECRET;

      // Unset QR_SIGNING_SECRET in production must throw QrSigningSecretUnavailableError, never fall back to a hard-coded secret
      expect(() => signQrPayload('APP-2026-0101|DOC-0101-1')).toThrow(QrSigningSecretUnavailableError);

      // Weak or placeholder secrets in production must be rejected by assertSafeProductionSecrets
      process.env.SESSION_SECRET = 'change-me-in-env-for-shared-deployments';
      expect(() => assertSafeProductionSecrets()).toThrow(/Insecure SESSION_SECRET/i);
      delete process.env.SESSION_SECRET;

      process.env.QR_SIGNING_SECRET = 'authentix-demo-qr-hmac-key-sih26261';
      expect(() => assertSafeProductionSecrets()).toThrow(/Weak or placeholder QR_SIGNING_SECRET/i);
      delete process.env.QR_SIGNING_SECRET;

      // QR_SIGNATURE_CHECK endpoint in production without QR_SIGNING_SECRET must fail safely (SOURCE_UNAVAILABLE, no 500, no auto-reject)
      const safeFailRes = await request(app)
        .post('/api/applications/APP-ID-0101/documents/DOC-0101-1/verify-source')
        .set('Authorization', `Bearer ${officerToken}`)
        .send({ method: 'QR_SIGNATURE_CHECK' });
      expect(safeFailRes.status).toBe(200);
      expect(safeFailRes.body.verification.status).toBe('SOURCE_UNAVAILABLE');
      expect(safeFailRes.body.verification.sourceResponse.qrSigningConfigured).toBe(false);

      const healthProdMissingQr = await request(app).get('/api/health');
      expect(healthProdMissingQr.status).toBe(200);
      expect(healthProdMissingQr.body.security.qrSigningConfigured).toBe(false);

      // Configuring a strong 32+ character QR_SIGNING_SECRET enables cryptographic QR verification cleanly
      process.env.QR_SIGNING_SECRET = 'prod-strong-random-qr-hmac-secret-998877665544332211';
      expect(assertSafeProductionSecrets().qrSigningSecretConfigured).toBe(true);

      const healthProdStrongQr = await request(app).get('/api/health');
      expect(healthProdStrongQr.body.security.qrSigningConfigured).toBe(true);
    } finally {
      process.env.NODE_ENV = prevNodeEnv;
      if (prevSessionSecret === undefined) delete process.env.SESSION_SECRET;
      else process.env.SESSION_SECRET = prevSessionSecret;
      if (prevQrSecret === undefined) delete process.env.QR_SIGNING_SECRET;
      else process.env.QR_SIGNING_SECRET = prevQrSecret;
    }
  });

  it('13. transitions cleanly from ENABLE_DEMO_MODE=false to true without rule UNIQUE crashes and isolates all synthetic child routes when false', async () => {
    // Part A: Regression test for ensureDefaultValidationRules -> seedDatabase transition + existing real user
    const transitionDbPath = path.join(tmpDir, 'transition-mode.sqlite');
    const transitionDb = openDatabase(transitionDbPath);
    try {
      runMigrations(transitionDb);
      ensureDefaultValidationRules(transitionDb);
      transitionDb
        .prepare(
          `INSERT INTO users (
            id, email, password_hash, full_name, role, institution_id, is_active, is_demo_account, created_at
          ) VALUES (?, ?, ?, ?, 'ADMIN', NULL, 1, 0, ?)`
        )
        .run(
          'USR-LOCAL-ADMIN',
          'admin@regulator.gov.in',
          hashPassword('AdminStrong#2026!'),
          'Local System Admin',
          new Date().toISOString()
        );

      const seedResult = await seedDatabase(transitionDb, {
        forceReset: false,
        uploadDir: path.join(tmpDir, 'transition-uploads'),
        sampleDocsDir: path.join(tmpDir, 'transition-samples'),
      });
      expect(seedResult.seeded).toBe(true);

      const demoUserCount = (
        transitionDb.prepare('SELECT COUNT(*) AS c FROM users WHERE is_demo_account = 1').get() as {
          c: number;
        }
      ).c;
      expect(demoUserCount).toBe(4);
    } finally {
      transitionDb.close();
    }

    // Part B: Verify synthetic child routes return 404 when ENABLE_DEMO_MODE=false
    const prevDemoFlag = process.env.ENABLE_DEMO_MODE;
    try {
      process.env.ENABLE_DEMO_MODE = 'false';

      const realLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: 'officer@regulator.gov.in', password: 'RealRegulator#Pass2026!' });
      expect(realLogin.status).toBe(200);
      const realTok = realLogin.body.sessionToken as string;

      const docFileRes = await request(app)
        .get('/api/documents/DOC-0101-1/file')
        .set('Authorization', `Bearer ${realTok}`);
      expect(docFileRes.status).toBe(404);

      const reportRes = await request(app)
        .get('/api/applications/APP-ID-0101/report')
        .set('Authorization', `Bearer ${realTok}`);
      expect(reportRes.status).toBe(404);

      const reevalRes = await request(app)
        .post('/api/applications/APP-ID-0101/re-evaluate')
        .set('Authorization', `Bearer ${realTok}`);
      expect(reevalRes.status).toBe(404);

      const verifySynthSourceRes = await request(app)
        .post('/api/applications/APP-ID-0102/documents/DOC-0102-1/verify-source')
        .set('Authorization', `Bearer ${realTok}`)
        .send({ method: 'SANDBOX_ISSUER_API' });
      expect(verifySynthSourceRes.status).toBe(404);

      const officerSynthActionRes = await request(app)
        .post('/api/applications/APP-ID-0102/officer-actions')
        .set('Authorization', `Bearer ${realTok}`)
        .send({ actionType: 'ADD_REVIEW_NOTE', rationale: 'Should be hidden when demo mode disabled' });
      expect(officerSynthActionRes.status).toBe(404);

      // Dashboard recentActivity must also exclude synthetic sample applications and *.demo actors
      const nonDemoDash = await request(app)
        .get('/api/dashboard/stats')
        .set('Authorization', `Bearer ${realTok}`);
      expect(nonDemoDash.status).toBe(200);
      expect(nonDemoDash.body.totalApplications).toBe(1);
      for (const act of nonDemoDash.body.recentActivity as Array<{
        actorEmail: string | null;
        resourceId: string;
      }>) {
        if (act.actorEmail) {
          expect(act.actorEmail.endsWith('.demo')).toBe(false);
        }
        expect(act.resourceId.startsWith('APP-ID-010')).toBe(false);
        expect(act.resourceId.startsWith('DOC-010')).toBe(false);
      }
    } finally {
      process.env.ENABLE_DEMO_MODE = prevDemoFlag;
    }
  });

  it('14. locks finalized applications against unauthorized post-decision mutations until reopened and enforces upload size bounds', async () => {
    // Oversized buffer check in security validator
    const oversizedCheck = validateUploadedFileBuffer(
      Buffer.alloc(2 * 1024 * 1024, 0x25),
      'huge.pdf',
      'application/pdf',
      1 * 1024 * 1024
    );
    expect(oversizedCheck.valid).toBe(false);
    expect(oversizedCheck.error).toMatch(/exceeds maximum allowed limit/i);

    // Finalize APP-ID-0101 as REVIEW_OFFICER
    const finalizeRes = await request(app)
      .post('/api/applications/APP-ID-0101/officer-actions')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        actionType: 'FINAL_DECISION_APPROVE',
        rationale: 'Lock regression test approval decision.',
      });
    expect(finalizeRes.status).toBe(200);

    // Lookup an extracted field ID on DOC-0101-1
    const fieldRow = db
      .prepare('SELECT id FROM extracted_fields WHERE document_id = ? LIMIT 1')
      .get('DOC-0101-1') as { id: string };

    // Field edit must be rejected with 409 while finalized
    const lockedFieldPatch = await request(app)
      .patch(`/api/documents/DOC-0101-1/fields/${fieldRow.id}`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        fieldValue: 'TAMPER-ATTEMPT',
        correctionNote: 'Attempt edit after final decision',
      });
    expect(lockedFieldPatch.status).toBe(409);

    // Source verification must be rejected with 409 while finalized
    const lockedSourceCheck = await request(app)
      .post('/api/applications/APP-ID-0101/documents/DOC-0101-1/verify-source')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({ method: 'SANDBOX_ISSUER_API' });
    expect(lockedSourceCheck.status).toBe(409);

    // Conflicting second final decision without reopening must be rejected with 409
    const lockedSecondDecision = await request(app)
      .post('/api/applications/APP-ID-0101/officer-actions')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        actionType: 'FINAL_DECISION_REJECT',
        rationale: 'Attempt conflicting decision while locked.',
      });
    expect(lockedSecondDecision.status).toBe(409);

    // Non-mutating ADD_REVIEW_NOTE remains allowed
    const noteRes = await request(app)
      .post('/api/applications/APP-ID-0101/officer-actions')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        actionType: 'ADD_REVIEW_NOTE',
        rationale: 'Post-approval file archival note.',
      });
    expect(noteRes.status).toBe(200);

    // Reopen via SENIOR_AUDITOR unlocks the case cleanly
    const unlockRes = await request(app)
      .post('/api/applications/APP-ID-0101/officer-actions')
      .set('Authorization', `Bearer ${auditorToken}`)
      .send({
        actionType: 'REOPEN_APPLICATION',
        rationale: 'Unlocking APP-ID-0101 after regression check.',
      });
    expect(unlockRes.status).toBe(200);
    expect(unlockRes.body.finalOfficerDecision).toBeNull();
  });

  it('15. enforces Rule Governance active/inactive toggles during evaluation and verifies exact Dashboard SQLite parity', async () => {
    // Non-admin cannot toggle rule status
    const officerToggleDenied = await request(app)
      .patch('/api/rules/RULE-DOC-EXPIRY/status')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({ isActive: false });
    expect(officerToggleDenied.status).toBe(403);

    // Admin deactivates RULE-DOC-EXPIRY
    const deactivateRes = await request(app)
      .patch('/api/rules/RULE-DOC-EXPIRY/status')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ isActive: false });
    expect(deactivateRes.status).toBe(200);
    expect(deactivateRes.body.isActive).toBe(false);

    // Re-evaluating APP-ID-0102 omits RULE-DOC-EXPIRY while RULE-INTAKE-MATCH still triggers
    const evalWhileDisabled = await request(app)
      .post('/api/applications/APP-ID-0102/re-evaluate')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(evalWhileDisabled.status).toBe(200);
    const disabledCodes = evalWhileDisabled.body.findings.map((f: { ruleCode: string }) => f.ruleCode);
    expect(disabledCodes).not.toContain('RULE-DOC-EXPIRY');
    expect(disabledCodes).toContain('RULE-INTAKE-MATCH');

    // Admin re-activates RULE-DOC-EXPIRY and re-evaluates APP-ID-0102
    const reactivateRes = await request(app)
      .patch('/api/rules/RULE-DOC-EXPIRY/status')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ isActive: true });
    expect(reactivateRes.status).toBe(200);
    expect(reactivateRes.body.isActive).toBe(true);

    const evalAfterReenable = await request(app)
      .post('/api/applications/APP-ID-0102/re-evaluate')
      .set('Authorization', `Bearer ${officerToken}`);
    const reenabledCodes = evalAfterReenable.body.findings.map((f: { ruleCode: string }) => f.ruleCode);
    expect(reenabledCodes).toContain('RULE-DOC-EXPIRY');

    // Verify Dashboard KPI counts match exact SQLite table queries
    const dashRes = await request(app)
      .get('/api/dashboard/stats')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(dashRes.status).toBe(200);

    const sqlTotalApps = (db.prepare('SELECT COUNT(*) AS c FROM applications').get() as { c: number }).c;
    const sqlHighPriority = (
      db
        .prepare(
          "SELECT COUNT(*) AS c FROM applications WHERE review_priority = 'HIGH' AND final_officer_decision IS NULL"
        )
        .get() as { c: number }
    ).c;
    const sqlOpenFindings = (
      db
        .prepare('SELECT COUNT(*) AS c FROM validation_findings WHERE resolved_by_officer = 0')
        .get() as { c: number }
    ).c;
    const sqlTotalDocs = (db.prepare('SELECT COUNT(*) AS c FROM documents').get() as { c: number }).c;

    expect(dashRes.body.totalApplications).toBe(sqlTotalApps);
    expect(dashRes.body.highPriorityApplications).toBe(sqlHighPriority);
    expect(dashRes.body.openComplianceFindings).toBe(sqlOpenFindings);
    expect(dashRes.body.totalDocuments).toBe(sqlTotalDocs);
  });

  it('16. verifies Docker build files, compose secret safety, and PostgreSQL reference DDL defaults on disk', () => {
    const repoRoot = process.cwd();
    const appDockerfilePath = path.join(repoRoot, 'Dockerfile');
    const ocrDockerfilePath = path.join(repoRoot, 'services', 'ocr_service', 'Dockerfile');
    const composePath = path.join(repoRoot, 'docker-compose.yml');
    const pgSchemaPath = path.join(repoRoot, 'db', 'postgres-schema.sql');

    expect(fs.existsSync(appDockerfilePath)).toBe(true);
    expect(fs.existsSync(ocrDockerfilePath)).toBe(true);

    const composeText = fs.readFileSync(composePath, 'utf8');
    expect(composeText).toContain('dockerfile: Dockerfile');
    expect(composeText).toContain('dockerfile: services/ocr_service/Dockerfile');
    expect(composeText).not.toContain('authentix-demo-qr-hmac');
    expect(composeText).not.toContain('change-me-in-env');
    expect(composeText).not.toContain('DEMO_SIGNING_SECRET');
    expect(composeText).toContain('QR_SIGNING_SECRET:');
    expect(composeText).toContain('ENABLE_DEMO_MODE: "${ENABLE_DEMO_MODE:-false}"');
    expect(composeText).toContain('AUTO_SEED_DEMO_DATA: "${AUTO_SEED_DEMO_DATA:-false}"');

    const pgSchemaText = fs.readFileSync(pgSchemaPath, 'utf8');
    expect(pgSchemaText).not.toMatch(/is_synthetic_demo\s+BOOLEAN\s+NOT\s+NULL\s+DEFAULT\s+TRUE/i);
    expect(pgSchemaText).not.toMatch(/is_demo_account\s+BOOLEAN\s+NOT\s+NULL\s+DEFAULT\s+TRUE/i);
  });

  it('17. supports extensible categories, lifecycle stages, rectification resubmission history, and rejects invalid state transitions', async () => {
    // Non-admin cannot create category
    const forbiddenCat = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        code: 'PG_CYBER_EXPANSION',
        baseCategory: 'INCREASE_IN_INTAKE',
        name: 'PG Cyber Security Expansion',
        description: 'Postgraduate intake expansion requiring Fire Safety and Faculty Roster.',
        requiredDocTypes: ['FIRE_SAFETY_CERTIFICATE', 'FACULTY_ROSTER_STATEMENT'],
      });
    expect(forbiddenCat.status).toBe(403);

    // Admin creates extensible category variant
    const createCatRes = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        code: 'PG_CYBER_EXPANSION',
        baseCategory: 'INCREASE_IN_INTAKE',
        name: 'PG Cyber Security Expansion',
        description: 'Postgraduate intake expansion requiring Fire Safety and Faculty Roster.',
        requiredDocTypes: ['FIRE_SAFETY_CERTIFICATE', 'FACULTY_ROSTER_STATEMENT'],
      });
    expect(createCatRes.status).toBe(201);
    expect(createCatRes.body.requiredDocTypes).toEqual([
      'FIRE_SAFETY_CERTIFICATE',
      'FACULTY_ROSTER_STATEMENT',
    ]);

    // Institution registrar submits application for own institution using custom categoryCode
    const appRes = await request(app)
      .post('/api/applications')
      .set('Authorization', `Bearer ${instToken}`)
      .send({
        institutionId: 'INST-KVTC-02',
        academicYear: '2026-27',
        category: 'INCREASE_IN_INTAKE',
        categoryCode: 'PG_CYBER_EXPANSION',
        programNames: 'M.Tech Information Security',
        requestedIntake: 180,
        submittedLandAcres: 2.8,
        submittedBuiltUpSqm: 780,
        submittedPrincipalName: 'Dr. S. Meenakshi Sundaram',
      });
    expect(appRes.status).toBe(201);
    const lifecycleAppId = appRes.body.id as string;
    expect(appRes.body.categoryCode).toBe('PG_CYBER_EXPANSION');
    expect(appRes.body.requiredChecklistDocTypes).toEqual([
      'FIRE_SAFETY_CERTIFICATE',
      'FACULTY_ROSTER_STATEMENT',
    ]);
    expect(appRes.body.lifecycleStage).toBe('incomplete');
    expect(appRes.body.nextRecommendedAction).toMatch(/Upload/i);

    // Invalid state transition: cannot resubmit while SUBMITTED (before CLARIFICATION_REQUESTED)
    const prematureResubmit = await request(app)
      .post(`/api/applications/${lifecycleAppId}/resubmit`)
      .set('Authorization', `Bearer ${instToken}`)
      .send({ resubmissionSummary: 'Attempting premature resubmission before clarification request.' });
    expect(prematureResubmit.status).toBe(409);

    // Invalid state transition: cannot reopen an un-decided application
    const prematureReopen = await request(app)
      .post(`/api/applications/${lifecycleAppId}/officer-actions`)
      .set('Authorization', `Bearer ${auditorToken}`)
      .send({ actionType: 'REOPEN_APPLICATION', rationale: 'Cannot reopen undecided application.' });
    expect(prematureReopen.status).toBe(409);

    // Officer requests clarification
    const clarifRes = await request(app)
      .post(`/api/applications/${lifecycleAppId}/officer-actions`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        actionType: 'REQUEST_CLARIFICATION',
        rationale: 'Submit valid Fire Safety Certificate and Faculty Roster Statement.',
      });
    expect(clarifRes.status).toBe(200);
    expect(clarifRes.body.status).toBe('CLARIFICATION_REQUESTED');

    // Institution uploads Fire Safety Certificate and resubmits rectification
    const validFirePdf = await generateSyntheticPdfBuffer({
      title: 'FIRE SAFETY CERTIFICATE',
      lines: [
        'Department: Tamil Nadu Fire and Rescue Services',
        'Certificate No: FSC-KVTC-2026-9910',
        'Institution Name: Kaveri Valley Technical Campus',
        'Issue Date: 10/02/2026',
        'Valid Upto: 09/02/2029',
      ],
    });
    const upRes = await request(app)
      .post(`/api/applications/${lifecycleAppId}/documents`)
      .set('Authorization', `Bearer ${instToken}`)
      .field('declaredDocType', 'FIRE_SAFETY_CERTIFICATE')
      .attach('file', validFirePdf, 'KVTC_Fire_Safety_Rectified.pdf');
    expect(upRes.status).toBe(201);

    const resubmitRes = await request(app)
      .post(`/api/applications/${lifecycleAppId}/resubmit`)
      .set('Authorization', `Bearer ${instToken}`)
      .send({
        resubmissionSummary: 'Uploaded renewed Fire Safety Certificate valid through Feb 2029.',
      });
    expect(resubmitRes.status).toBe(200);
    expect(resubmitRes.body.status).toBe('UNDER_SCRUTINY');
    expect(resubmitRes.body.submissionCycle).toBe(2);
    expect(resubmitRes.body.priorCycleFindings.length).toBeGreaterThan(0);
    expect(resubmitRes.body.priorCycleFindings[0].submissionCycle).toBe(1);
    expect(resubmitRes.body.priorCycleFindings[0].archivedFromPriorCycle).toBe(true);
  });

  it('18. normalizes DD/MM/YYYY dates, extracts expanded regulatory fields, and recovers failed OCR via reprocess while preserving manual corrections', async () => {
    const richPdf = await generateSyntheticPdfBuffer({
      title: 'BUILDING PLAN & FACULTY SUMMARY APPROVAL',
      lines: [
        'Issuing Authority: Directorate of Town and Country Planning',
        'Certificate No: BPA-DTCP-2026-4401',
        'Institution Name: Indraprastha Institute of Engineering & Technology',
        'Address: Plot 19, Institutional Knowledge Park, New Delhi',
        'Architect Registration No: CA/2018/77421',
        'Total Faculty: 38',
        'Built-up Area: 1420 sqm',
        'Issue Date: 15/03/2026',
        'Expiry Date: 14-03-2031',
      ],
    });

    // First simulate timeout failure during initial upload
    const timeoutUpload = await request(app)
      .post('/api/applications/APP-ID-0101/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'BUILDING_PLAN_APPROVAL')
      .field('ocrModeOverride', 'timeout')
      .attach('file', richPdf, 'IIET_Building_Plan_2026.pdf');
    expect(timeoutUpload.status).toBe(201);
    expect(timeoutUpload.body.document.ocrStatus).toBe('FAILED');
    const docId = timeoutUpload.body.document.id as string;

    // Reprocess document via /reprocess endpoint and verify recovery + field normalization
    const reprocRes = await request(app)
      .post(`/api/applications/APP-ID-0101/documents/${docId}/reprocess`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({ ocrModeOverride: 'local-only' });
    expect(reprocRes.status).toBe(200);
    expect(reprocRes.body.document.ocrStatus).toBe('COMPLETED');
    expect(reprocRes.body.document.reprocessCount).toBe(1);
    expect(reprocRes.body.document.classificationConfidence).toBeGreaterThan(0.5);

    const fields = reprocRes.body.document.extractedFields as Array<{
      id: string;
      fieldName: string;
      fieldValue: string;
    }>;
    const fieldMap = new Map(fields.map((f) => [f.fieldName, f]));
    expect(fieldMap.get('issue_date')?.fieldValue).toBe('2026-03-15');
    expect(fieldMap.get('expiry_date')?.fieldValue).toBe('2031-03-14');
    expect(fieldMap.get('architect_registration_no')?.fieldValue).toBe('CA/2018/77421');
    expect(fieldMap.get('total_faculty_count')?.fieldValue).toBe('38');
    expect(fieldMap.get('address')?.fieldValue).toContain('Plot 19');

    // Officer corrects total_faculty_count to 44, then reprocesses again — manual correction must survive!
    const facField = fieldMap.get('total_faculty_count')!;
    const corrRes = await request(app)
      .patch(`/api/documents/${docId}/fields/${facField.id}`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        fieldValue: '44',
        correctionNote: 'Verified adjunct + regular faculty roster annexure count = 44.',
      });
    expect(corrRes.status).toBe(200);

    const reprocAgain = await request(app)
      .post(`/api/applications/APP-ID-0101/documents/${docId}/reprocess`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({ ocrModeOverride: 'local-only' });
    expect(reprocAgain.status).toBe(200);
    expect(reprocAgain.body.document.reprocessCount).toBe(2);
    const preservedFac = reprocAgain.body.document.extractedFields.find(
      (f: { fieldName: string }) => f.fieldName === 'total_faculty_count'
    );
    expect(preservedFac.fieldValue).toBe('44');
    expect(preservedFac.manuallyCorrected).toBe(true);
  });

  it('19. validates rule schemas before publication, rejects invalid rules, and executes custom versioned rules with effective dates', async () => {
    // Reject out-of-range confidence parameter before saving
    const badConfRule = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ruleCode: 'RULE-BAD-CONFIDENCE',
        version: '1.0.0',
        name: 'Invalid Confidence Rule',
        description: 'Out of bounds confidence threshold must fail pre-save validation.',
        category: 'ALL',
        ruleType: 'CONFIDENCE_THRESHOLD',
        severity: 'MEDIUM',
        config: { minConfidence: 2.5 },
      });
    expect(badConfRule.status).toBe(400);
    expect(badConfRule.body.error).toMatch(/minConfidence/i);

    // Reject NUMERIC_MINIMUM without fieldName
    const missingFieldRule = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ruleCode: 'RULE-BAD-NUMERIC',
        version: '1.0.0',
        name: 'Missing Field Name Rule',
        description: 'Missing fieldName must fail validation.',
        category: 'ALL',
        ruleType: 'NUMERIC_MINIMUM',
        severity: 'HIGH',
        config: { minValue: 50 },
      });
    expect(missingFieldRule.status).toBe(400);

    // Reject inverted effectiveFrom > effectiveTo
    const badDatesRule = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ruleCode: 'RULE-BAD-DATES',
        version: '1.0.0',
        name: 'Inverted Effective Dates',
        description: 'effectiveFrom after effectiveTo must fail validation.',
        category: 'ALL',
        ruleType: 'NUMERIC_MINIMUM',
        severity: 'MEDIUM',
        config: { fieldName: 'total_faculty_count', minValue: 20 },
        effectiveFrom: '2028-01-01',
        effectiveTo: '2026-01-01',
      });
    expect(badDatesRule.status).toBe(400);

    // Create valid custom NUMERIC_MINIMUM rule requiring total_faculty_count >= 60 on BUILDING_PLAN_APPROVAL
    const validRuleRes = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        ruleCode: 'RULE-CUSTOM-FACULTY-MIN',
        version: '1.0.0',
        name: 'Minimum Faculty Count Threshold',
        description: 'Illustrative policy check requiring at least 60 faculty members.',
        category: 'ALL',
        docType: 'BUILDING_PLAN_APPROVAL',
        ruleType: 'NUMERIC_MINIMUM',
        severity: 'MEDIUM',
        config: { fieldName: 'total_faculty_count', minValue: 60, unit: 'faculty' },
        effectiveFrom: '2025-01-01',
        recommendedAction: 'Verify faculty appointment letters against sanctioned intake.',
        isIllustrative: true,
      });
    expect(validRuleRes.status).toBe(201);

    // Re-evaluate APP-ID-0101 (which has total_faculty_count = 44 < 60) -> custom rule must fire with v1.0.0
    const evalActive = await request(app)
      .post('/api/applications/APP-ID-0101/re-evaluate')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(evalActive.status).toBe(200);
    const customFinding = evalActive.body.findings.find(
      (f: { ruleCode: string }) => f.ruleCode === 'RULE-CUSTOM-FACULTY-MIN'
    );
    expect(customFinding).toBeDefined();
    expect(customFinding.ruleVersion).toBe('1.0.0');
    expect(customFinding.epistemicClassification).toBe('ORDINARY_INCONSISTENCY');

    // Publish version 1.1.0 with future effectiveFrom (2099-01-01) -> rule should NOT fire today
    const futureVerRes = await request(app)
      .post('/api/rules/RULE-CUSTOM-FACULTY-MIN/versions')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        version: '1.1.0',
        severity: 'MEDIUM',
        description: 'Future-dated policy revision effective in 2099.',
        config: { fieldName: 'total_faculty_count', minValue: 60, unit: 'faculty' },
        effectiveFrom: '2099-01-01',
        effectiveTo: null,
      });
    expect(futureVerRes.status).toBe(201);

    const evalFuture = await request(app)
      .post('/api/applications/APP-ID-0101/re-evaluate')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(
      evalFuture.body.findings.some((f: { ruleCode: string }) => f.ruleCode === 'RULE-CUSTOM-FACULTY-MIN')
    ).toBe(false);
  });

  it('20. enforces honest 8-method Source Verification adapters and emits CONFIRMED_SOURCE_MISMATCH findings without fabricating live authority checks', async () => {
    // Unconfigured live government adapters must honestly return SOURCE_UNAVAILABLE with isSandboxDemo=false
    for (const liveMethod of ['OFFICIAL_API', 'OFFICIAL_PORTAL', 'DIGITAL_REPOSITORY'] as const) {
      const liveRes = await request(app)
        .post('/api/applications/APP-ID-0102/documents/DOC-0102-1/verify-source')
        .set('Authorization', `Bearer ${officerToken}`)
        .send({ method: liveMethod });
      expect(liveRes.status).toBe(200);
      expect(liveRes.body.verification.status).toBe('SOURCE_UNAVAILABLE');
      expect(liveRes.body.verification.isSandboxDemo).toBe(false);
    }

    // DIGITAL_SIGNATURE on unsigned PDF reports MANUAL_REVIEW_REQUIRED (never falsely VERIFIED)
    const unsignedSigRes = await request(app)
      .post('/api/applications/APP-ID-0102/documents/DOC-0102-1/verify-source')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({ method: 'DIGITAL_SIGNATURE' });
    expect(unsignedSigRes.status).toBe(200);
    expect(unsignedSigRes.body.verification.status).toBe('MANUAL_REVIEW_REQUIRED');
    expect(unsignedSigRes.body.verification.isSandboxDemo).toBe(false);

    // Upload a PDF containing /Type /Sig + /ByteRange markers and verify DIGITAL_SIGNATURE reports VERIFICATION_PENDING (still not falsely VERIFIED without CA chain validation)
    const rawPdf = await generateSyntheticPdfBuffer({
      title: 'SIGNED NOC TEST',
      lines: ['Certificate No: NOC-SIG-2026-01', 'Institution Name: Kaveri Valley Technical Campus'],
    });
    const pdfWithSigMarker = Buffer.concat([
      rawPdf,
      Buffer.from('\n% /Type /Sig /ByteRange [0 120 240 480]\n', 'latin1'),
    ]);
    const sigDocUp = await request(app)
      .post('/api/applications/APP-ID-0102/documents')
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'NOC_AFFILIATING_UNIVERSITY')
      .field('ocrModeOverride', 'local-only')
      .attach('file', pdfWithSigMarker, 'Signed_Marker_NOC.pdf');
    expect(sigDocUp.status).toBe(201);
    expect(sigDocUp.body.document.metadata.hasEmbeddedDigitalSignature).toBe(true);

    const embeddedSigCheck = await request(app)
      .post(`/api/applications/APP-ID-0102/documents/${sigDocUp.body.document.id}/verify-source`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({ method: 'DIGITAL_SIGNATURE' });
    expect(embeddedSigCheck.status).toBe(200);
    expect(embeddedSigCheck.body.verification.status).toBe('VERIFICATION_PENDING');

    // Record MISMATCH_DETECTED via manual officer source verification and verify RULE-SOURCE-MISMATCH (CONFIRMED_SOURCE_MISMATCH) is emitted
    const mismatchVerif = await request(app)
      .post(`/api/applications/APP-ID-0102/documents/${sigDocUp.body.document.id}/verify-source`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        method: 'MANUAL_OFFICER_VERIFICATION',
        manualStatus: 'MISMATCH_DETECTED',
        issuerName: 'Affiliating University Registrar',
        referenceNumber: 'NOC-SIG-2026-01',
        notes: 'University dispatch register confirmed certificate number was never issued.',
      });
    expect(mismatchVerif.status).toBe(200);
    const sourceMismatchFinding = mismatchVerif.body.application.findings.find(
      (f: { ruleCode: string }) => f.ruleCode === 'RULE-SOURCE-MISMATCH'
    );
    expect(sourceMismatchFinding).toBeDefined();
    expect(sourceMismatchFinding.epistemicClassification).toBe('CONFIRMED_SOURCE_MISMATCH');
  });

  it('21. evaluates Infrastructure Compliance visual evidence with honest limitations, flags physical inspection, and isolates In-App Notifications', async () => {
    const appDetailRes = await request(app)
      .get('/api/applications/APP-ID-0102')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(appDetailRes.status).toBe(200);
    expect(Array.isArray(appDetailRes.body.complianceItems)).toBe(true);
    expect(appDetailRes.body.complianceItems.length).toBeGreaterThan(0);

    // Seeded DOC-0102-4 (sample_facility_lab_photo.png) must link to laboratory infrastructure item with pixel dimensions + disclaimer
    const labItem = appDetailRes.body.complianceItems.find(
      (ci: { domain: string }) => ci.domain === 'LABORATORY_INFRASTRUCTURE'
    );
    expect(labItem).toBeDefined();
    expect(labItem.linkedDocumentFilename).toMatch(/Lab/i);
    expect(labItem.visualInspection.width).toBeGreaterThan(0);
    expect(labItem.visualInspection.height).toBeGreaterThan(0);
    expect(labItem.visualInspection.limitationsDisclaimer).toMatch(/NEVER proves real-world.*physical dimensions/i);

    // Officer reviews compliance item, flags Physical EVC Site Inspection, and requests additional evidence
    const reviewItemRes = await request(app)
      .patch(`/api/applications/APP-ID-0102/compliance-items/${labItem.id}`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        complianceStatus: 'INSUFFICIENT_EVIDENCE',
        officerObservation: 'Single lab photograph cannot confirm equipment count; schedule physical EVC visit.',
        additionalEvidenceRequested: true,
        additionalEvidenceNote: 'Upload sanctioned lab equipment invoice schedule and panoramic lab photos.',
        physicalInspectionFlagged: true,
      });
    expect(reviewItemRes.status).toBe(200);
    expect(reviewItemRes.body.physicalInspectionRequired).toBe(true);
    expect(reviewItemRes.body.status).toBe('CLARIFICATION_REQUESTED');

    // Verify In-App Notifications endpoint enforces IN_APP_ONLY and institution isolation
    const instNotifRes = await request(app)
      .get('/api/notifications')
      .set('Authorization', `Bearer ${instToken}`);
    expect(instNotifRes.status).toBe(200);
    expect(instNotifRes.body.deliveryMode).toBe('IN_APP_ONLY');
    expect(instNotifRes.body.unreadCount).toBeGreaterThan(0);
    for (const n of instNotifRes.body.notifications as Array<{
      recipientInstitutionId: string | null;
      deliveryChannel: string;
    }>) {
      expect(n.recipientInstitutionId).toBe('INST-KVTC-02');
      expect(n.deliveryChannel).toBe('IN_APP_ONLY');
    }

    // Mark notification as read
    const firstNotifId = instNotifRes.body.notifications[0].id as string;
    const markReadRes = await request(app)
      .patch(`/api/notifications/${firstNotifId}/read`)
      .set('Authorization', `Bearer ${instToken}`);
    expect(markReadRes.status).toBe(200);
    expect(markReadRes.body.isRead).toBe(true);

    // Verify audit chain remains 100% valid after all new lifecycle, rule, source, and compliance events
    const chainCheck = verifyAuditChain(db);
    expect(chainCheck.valid).toBe(true);
  });
});


