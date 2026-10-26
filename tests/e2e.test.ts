/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Full 13-Step End-to-End Integration Scenario Test
 * Spawns the real Python OCR service (`services/ocr_service/server.py`) AND Express backend,
 * closes and restarts the backend + SQLite connection mid-test to prove durable persistence,
 * verifies SHA-256 audit hash-chain integrity, RBAC isolation, and failure resilience.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServerApp } from '../server.ts';
import { openDatabase } from '../src/server/db.ts';
import { generateSyntheticPdfBuffer, generateSyntheticPngBuffer } from '../src/server/pdfGenerator.ts';
import { sha256Hex } from '../src/server/security.ts';
import { DEFAULT_DEMO_PASSWORD } from '../src/server/seed.ts';

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

async function waitForHttpHealth(url: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(800) });
      if (res.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`Timed out waiting for service health at ${url}`);
}

describe('AUTHENTIX 13-Step End-to-End Scenario & Restart Persistence', () => {
  let tmpDir: string;
  let dbPath: string;
  let uploadDir: string;
  let sampleDocsDir: string;
  let ocrPort = 0;
  let ocrProc: ChildProcess | null = null;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.ENABLE_DEMO_MODE = 'true';
    process.env.DISABLE_RATE_LIMIT = 'true';

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authentix-e2e-'));
    dbPath = path.join(tmpDir, 'e2e.sqlite');
    uploadDir = path.join(tmpDir, 'uploads');
    sampleDocsDir = path.join(tmpDir, 'samples');

    // Step 1a: Start real Python OCR & Forensics microservice
    ocrPort = await getFreePort();
    process.env.OCR_SERVICE_PORT = String(ocrPort);
    process.env.OCR_SERVICE_URL = `http://127.0.0.1:${ocrPort}`;
    process.env.OCR_MODE = 'auto';

    ocrProc = spawn('python3', ['services/ocr_service/server.py'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        OCR_SERVICE_HOST: '127.0.0.1',
        OCR_SERVICE_PORT: String(ocrPort),
      },
      stdio: 'pipe',
    });

    await waitForHttpHealth(`http://127.0.0.1:${ocrPort}/health`);
  });

  afterAll(() => {
    if (ocrProc) {
      ocrProc.kill('SIGTERM');
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('executes all 13 mandatory SIH end-to-end verification steps including backend restart persistence', async () => {
    // Step 1b: Start Express backend instance #1
    const instance1 = await createServerApp({
      db: openDatabase(dbPath),
      uploadDir,
      sampleDocsDir,
      autoSeed: true,
      attachFrontend: false,
    });
    const server1 = http.createServer(instance1.app);
    await new Promise<void>((resolve) => server1.listen(0, '127.0.0.1', () => resolve()));

    // Verify backend health reports Python OCR service online
    const healthRes = await request(server1).get('/api/health');
    expect(healthRes.status).toBe(200);
    expect(healthRes.body.ocrService.pythonMicroserviceOnline).toBe(true);

    // Step 2: Log in as authorised demo scrutiny officer
    const loginRes = await request(server1)
      .post('/api/auth/login')
      .send({ email: 'officer@authentix.demo', password: DEFAULT_DEMO_PASSWORD });
    expect(loginRes.status).toBe(200);
    const officerToken = loginRes.body.sessionToken as string;

    const dashBefore = await request(server1)
      .get('/api/dashboard/stats')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(dashBefore.status).toBe(200);
    const initialTotalApps = dashBefore.body.totalApplications as number;

    // Step 3: Submit a new institution application (requestedIntake 300 vs master 240 triggers cross-check finding)
    const createAppRes = await request(server1)
      .post('/api/applications')
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        institutionId: 'INST-IIET-01',
        academicYear: '2026-27',
        category: 'NEW_INSTITUTION',
        programNames: 'M.Tech Cyber Security (E2E Scenario)',
        requestedIntake: 300,
        submittedLandAcres: 5.5,
        submittedBuiltUpSqm: 1420,
        submittedPrincipalName: 'Dr. Raghavendra Prasad',
      });
    expect(createAppRes.status).toBe(201);
    const e2eAppId = createAppRes.body.id as string;

    // Step 4: Upload supporting PDF (with past expiry date to exercise expiry finding) + raster PNG scan + duplicate PDF
    const testPdf = await generateSyntheticPdfBuffer({
      title: 'FIRE SAFETY CERTIFICATE E2E',
      lines: [
        'Department: Delhi Fire Services Directorate',
        'Certificate No: FSC-E2E-2026-7788',
        'Institution Name: Indraprastha Institute of Engineering & Technology',
        'Approved Intake: 180',
        'Issue Date: 2023-03-01',
        'Expiry Date: 2024-02-28',
      ],
    });
    const expectedSha256 = sha256Hex(testPdf);

    const uploadRes = await request(server1)
      .post(`/api/applications/${e2eAppId}/documents`)
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'FIRE_SAFETY_CERTIFICATE')
      .attach('file', testPdf, 'Fire_Safety_E2E_Expired.pdf');
    expect(uploadRes.status).toBe(201);
    const uploadedDocId = uploadRes.body.document.id as string;

    // Upload duplicate of an existing document to exercise SHA-256 duplicate detection
    const dupUploadRes = await request(server1)
      .post(`/api/applications/${e2eAppId}/documents`)
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'AICTE_FEE_RECEIPT')
      .attach('file', testPdf, 'Duplicate_Submission_E2E.pdf');
    expect(dupUploadRes.status).toBe(201);

    // Upload raster-only PNG scan under local-only OCR mode to verify explicit UNAVAILABLE status
    const rasterPng = generateSyntheticPngBuffer({ includeRasterOnly: true });
    const rasterUploadRes = await request(server1)
      .post(`/api/applications/${e2eAppId}/documents`)
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'AFFIDAVIT_INTAKE')
      .field('ocrModeOverride', 'local-only')
      .attach('file', rasterPng, 'Affidavit_Raster_Scan.png');
    expect(rasterUploadRes.status).toBe(201);

    // Step 5: Confirm file is stored securely on disk and SHA-256 hash matches
    expect(uploadRes.body.document.sha256Hash).toBe(expectedSha256);
    const storedPath = path.join(uploadDir, uploadRes.body.document.storedFilename);
    expect(fs.existsSync(storedPath)).toBe(true);
    expect(sha256Hex(fs.readFileSync(storedPath))).toBe(expectedSha256);

    // Step 6: Confirm Python OCR extracted structured fields on digital PDF and explicitly showed UNAVAILABLE on raster scan
    expect(uploadRes.body.document.ocrEngine).toBe('python-pdf-stream-extractor');
    expect(uploadRes.body.document.ocrStatus).toBe('COMPLETED');
    const extractedCert = uploadRes.body.document.extractedFields.find(
      (f: { fieldName: string }) => f.fieldName === 'certificate_number'
    );
    expect(extractedCert?.fieldValue).toBe('FSC-E2E-2026-7788');
    expect(rasterUploadRes.body.document.ocrStatus).toBe('UNAVAILABLE');
    expect(rasterUploadRes.body.document.extractedText).toBe('');
    expect(rasterUploadRes.body.document.verificationStatus).toBe('MANUAL_REVIEW_REQUIRED');

    // Step 7: Confirm missing-doc, expiry, cross-document/master mismatch, and duplicate-file findings with linked evidence & explanation
    const appFindings = rasterUploadRes.body.application.findings as Array<{
      findingCode: string;
      ruleCode: string;
      documentId: string | null;
      explanation: string;
      evidence: Record<string, unknown>;
    }>;
    const findingCodes = appFindings.map((f) => f.ruleCode);
    expect(findingCodes).toContain('RULE-REQ-DOCS');
    expect(findingCodes).toContain('RULE-DOC-EXPIRY');
    expect(findingCodes).toContain('RULE-INTAKE-MATCH');
    expect(findingCodes).toContain('RULE-SHA256-DUPLICATE');

    for (const f of appFindings) {
      expect(f.findingCode.length).toBeGreaterThan(3);
      expect(f.explanation.length).toBeGreaterThan(10);
      expect(typeof f.evidence).toBe('object');
    }
    const expiryFinding = appFindings.find((f) => f.ruleCode === 'RULE-DOC-EXPIRY');
    expect(expiryFinding?.documentId).toBe(uploadedDocId);

    // Step 8: Confirm explainable advisory trust score with factors and version, and confirm NO automatic rejection
    const breakdown = rasterUploadRes.body.application.trustScoreBreakdown;
    expect(typeof rasterUploadRes.body.application.trustScore).toBe('number');
    expect(typeof breakdown.version).toBe('string');
    expect(breakdown.version.length).toBeGreaterThan(0);
    expect(Array.isArray(breakdown.contributions)).toBe(true);
    expect(breakdown.contributions.length).toBeGreaterThan(0);
    expect(rasterUploadRes.body.application.finalOfficerDecision).toBeNull();

    // Confirm Dashboard reflects real updated counts
    const dashAfter = await request(server1)
      .get('/api/dashboard/stats')
      .set('Authorization', `Bearer ${officerToken}`);
    expect(dashAfter.body.totalApplications).toBe(initialTotalApps + 1);

    // Step 9: Perform officer field correction, manual source verification, and written review rationale
    const expiryField = uploadRes.body.document.extractedFields.find(
      (f: { fieldName: string }) => f.fieldName === 'expiry_date'
    );
    expect(expiryField).toBeDefined();

    const correctFieldRes = await request(server1)
      .patch(`/api/documents/${uploadedDocId}/fields/${expiryField.id}`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        fieldValue: '2029-02-28',
        correctionNote: 'Verified physical corrigendum annexure extending Fire NOC validity to 2029-02-28.',
      });
    expect(correctFieldRes.status).toBe(200);

    // Confirm sandbox unavailable source check never fabricates verification
    const unavailIssuerRes = await request(server1)
      .post(`/api/applications/${e2eAppId}/documents/${rasterUploadRes.body.document.id}/verify-source`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({ method: 'SANDBOX_ISSUER_API', simulateIssuerUnavailable: true });
    expect(unavailIssuerRes.status).toBe(200);
    expect(unavailIssuerRes.body.verification.isSandboxDemo).toBe(true);
    expect(unavailIssuerRes.body.verification.status).toBe('SOURCE_UNAVAILABLE');

    const manualVerifRes = await request(server1)
      .post(`/api/applications/${e2eAppId}/documents/${uploadedDocId}/verify-source`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        method: 'MANUAL_OFFICER_VERIFICATION',
        manualStatus: 'VERIFIED',
        issuerName: 'Delhi Fire Services Directorate',
        referenceNumber: 'FSC-E2E-2026-7788',
        notes: 'E2E Manual Verification persisted before server restart.',
      });
    expect(manualVerifRes.status).toBe(200);
    expect(manualVerifRes.body.verification.status).toBe('VERIFIED');
    expect(manualVerifRes.body.verification.isSandboxDemo).toBe(false);

    const reviewNoteRes = await request(server1)
      .post(`/api/applications/${e2eAppId}/officer-actions`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        actionType: 'ADD_REVIEW_NOTE',
        rationale: 'Scrutiny officer reviewed duplicate upload and intake variance prior to final decision.',
      });
    expect(reviewNoteRes.status).toBe(200);

    // Upload a laboratory facility photo and record an officer compliance assessment with physical inspection flag
    const labPhotoPng = generateSyntheticPngBuffer({ includeRasterOnly: true });
    const labUploadRes = await request(server1)
      .post(`/api/applications/${e2eAppId}/documents`)
      .set('Authorization', `Bearer ${officerToken}`)
      .field('declaredDocType', 'FACILITY_PHOTO_LAB')
      .field('ocrModeOverride', 'local-only')
      .attach('file', labPhotoPng, 'E2E_Lab_Facility_Photo.png');
    expect(labUploadRes.status).toBe(201);

    const labCompItem = labUploadRes.body.application.complianceItems.find(
      (ci: { domain: string }) => ci.domain === 'LABORATORY_INFRASTRUCTURE'
    );
    expect(labCompItem).toBeDefined();
    expect(labCompItem.visualInspection.width).toBeGreaterThan(0);

    const compPatchRes = await request(server1)
      .patch(`/api/applications/${e2eAppId}/compliance-items/${labCompItem.id}`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        complianceStatus: 'NOT_SATISFIED',
        officerObservation: 'Lab capacity insufficient for requested 300 intake; physical EVC inspection flagged.',
        physicalInspectionFlagged: true,
      });
    expect(compPatchRes.status).toBe(200);
    expect(compPatchRes.body.physicalInspectionRequired).toBe(true);

    // Step 10: Record an authorised final officer decision with actor, timestamp, and decision history
    const finalDecisionRes = await request(server1)
      .post(`/api/applications/${e2eAppId}/officer-actions`)
      .set('Authorization', `Bearer ${officerToken}`)
      .send({
        actionType: 'FINAL_DECISION_REJECT',
        rationale:
          'Authorised human officer rejection due to unapproved intake expansion (300 vs 240) and duplicate fee receipt file.',
      });
    expect(finalDecisionRes.status).toBe(200);
    expect(finalDecisionRes.body.finalOfficerDecision).toBe('REJECTED_BY_OFFICER');
    expect(finalDecisionRes.body.lifecycleStage).toBe('completed');
    expect(finalDecisionRes.body.officerReviews[0].officerRole).toBe('REVIEW_OFFICER');
    expect(finalDecisionRes.body.officerReviews[0].createdAt).toBeTruthy();

    // Step 11: Export JSON & CSV scrutiny reports and verify all actions appear in Case Audit Trail
    const jsonReportRes = await request(server1)
      .get(`/api/applications/${e2eAppId}/report`)
      .set('Authorization', `Bearer ${officerToken}`);
    expect(jsonReportRes.status).toBe(200);
    expect(jsonReportRes.body.summaryMetrics.physicalInspectionRequired).toBe(true);

    const csvReportRes = await request(server1)
      .get(`/api/applications/${e2eAppId}/report?format=csv`)
      .set('Authorization', `Bearer ${officerToken}`);
    expect(csvReportRes.status).toBe(200);
    expect(csvReportRes.headers['content-type']).toContain('text/csv');
    expect(csvReportRes.text).toContain('REJECTED_BY_OFFICER');
    expect(csvReportRes.text).toContain('COMPLIANCE_ITEM');

    // Step 12: Shut down server1 + close SQLite connection, restart a fresh server2 on same DB file, and verify full persistence
    await new Promise<void>((resolve) => server1.close(() => resolve()));
    instance1.db.close();

    const instance2 = await createServerApp({
      db: openDatabase(dbPath),
      uploadDir,
      sampleDocsDir,
      autoSeed: false,
      attachFrontend: false,
    });
    const server2 = http.createServer(instance2.app);
    await new Promise<void>((resolve) => server2.listen(0, '127.0.0.1', () => resolve()));

    try {
      const persistedDetail = await request(server2)
        .get(`/api/applications/${e2eAppId}`)
        .set('Authorization', `Bearer ${officerToken}`);
      expect(persistedDetail.status).toBe(200);
      expect(persistedDetail.body.finalOfficerDecision).toBe('REJECTED_BY_OFFICER');
      expect(persistedDetail.body.physicalInspectionRequired).toBe(true);
      expect(persistedDetail.body.complianceItems.length).toBeGreaterThan(0);
      expect(persistedDetail.body.officerReviews.length).toBeGreaterThanOrEqual(4);

      const notifCheck = await request(server2)
        .get('/api/notifications')
        .set('Authorization', `Bearer ${officerToken}`);
      expect(notifCheck.status).toBe(200);
      expect(notifCheck.body.deliveryMode).toBe('IN_APP_ONLY');

      const persistedDoc = persistedDetail.body.documents.find((d: { id: string }) => d.id === uploadedDocId);
      expect(persistedDoc.verificationStatus).toBe('VERIFIED');
      const persistedCorrectedField = persistedDoc.extractedFields.find(
        (f: { fieldName: string }) => f.fieldName === 'expiry_date'
      );
      expect(persistedCorrectedField.fieldValue).toBe('2029-02-28');
      expect(persistedCorrectedField.manuallyCorrected).toBe(true);

      // Verify hash-chained audit trail records application + child document actions and verifies cleanly
      const auditVerifyRes = await request(server2)
        .get('/api/audit-logs/verify')
        .set('Authorization', `Bearer ${officerToken}`);
      expect(auditVerifyRes.status).toBe(200);
      expect(auditVerifyRes.body.valid).toBe(true);

      const caseAuditRes = await request(server2)
        .get(`/api/audit-logs?resourceId=${e2eAppId}&limit=50`)
        .set('Authorization', `Bearer ${officerToken}`);
      expect(caseAuditRes.status).toBe(200);
      const caseActions = caseAuditRes.body.logs.map((l: { action: string }) => l.action);
      expect(caseActions).toContain('APPLICATION_CREATED');
      expect(caseActions).toContain('DOCUMENT_UPLOADED_AND_PROCESSED');
      expect(caseActions).toContain('EXTRACTED_FIELD_CORRECTED');
      expect(caseActions).toContain('SOURCE_VERIFICATION_RECORDED');
      expect(caseActions).toContain('OFFICER_ADD_REVIEW_NOTE');
      expect(caseActions).toContain('OFFICER_FINAL_DECISION_REJECT');
      expect(caseActions).toContain('VALIDATION_REPORT_GENERATED');

      // Confirm unauthorised user (other institution) cannot access E2E application or document
      const unauthLogin = await request(server2)
        .post('/api/auth/login')
        .send({ email: 'registrar@kaveritech.demo', password: DEFAULT_DEMO_PASSWORD });
      const instTok = unauthLogin.body.sessionToken as string;

      const blockedApp = await request(server2)
        .get(`/api/applications/${e2eAppId}`)
        .set('Authorization', `Bearer ${instTok}`);
      expect(blockedApp.status).toBe(403);

      const blockedFile = await request(server2)
        .get(`/api/documents/${uploadedDocId}/file`)
        .set('Authorization', `Bearer ${instTok}`);
      expect(blockedFile.status).toBe(403);
    } finally {
      await new Promise<void>((resolve) => server2.close(() => resolve()));
      instance2.db.close();
    }
  });
});

