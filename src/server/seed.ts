/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Reproducible Synthetic Demo Seeder & Reset Engine
 *
 * All records created here are explicitly marked `is_synthetic_demo = 1`
 * and processed through the real OCR, Validation, Anomaly, Trust Score,
 * Infrastructure Compliance, In-App Notification, and Hash-Chained Audit pipelines.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import type { DocumentType } from '../shared/types.ts';
import { appendAuditEvent } from './auditLog.ts';
import { cleanEnvString, resolveSampleDocsDir, resolveUploadDir, runMigrations, withTransaction } from './db.ts';
import { processDocumentBuffer } from './ocrPipeline.ts';
import { generateSyntheticPdfBuffer, generateSyntheticPngBuffer } from './pdfGenerator.ts';
import { hashPassword, sha256Hex, signQrPayload, verifyPassword } from './security.ts';
import { executeSourceVerification } from './sourceVerification.ts';
import { ensureDefaultCategoriesAndCompliance, evaluateApplicationCompliance } from './validationEngine.ts';

export function getDemoSeedPassword(): string {
  return cleanEnvString(process.env.DEMO_SEED_PASSWORD) || 'Authentix@SIH2026!';
}

export const DEFAULT_DEMO_PASSWORD = getDemoSeedPassword();

export interface SeedSummary {
  seeded: boolean;
  usersCount: number;
  institutionsCount: number;
  applicationsCount: number;
  documentsCount: number;
  sampleFixturesWritten: string[];
}

export const DEFAULT_VALIDATION_RULES = [
  {
    id: 'RUL-001',
    ruleCode: 'RULE-REQ-DOCS',
    version: '1.2.0',
    name: 'Category Mandatory Document Checklist',
    description:
      'Verifies that all required supporting documents configured for the application category have been uploaded.',
    category: 'ALL',
    docType: null as string | null,
    ruleType: 'CHECKLIST_PRESENCE',
    severity: 'HIGH',
    authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE',
    recommendedAction: 'Request missing mandatory statutory certificates from the applicant institution.',
    evidenceReferenceLabel: 'Configurable Category Checklist (Illustrative APH Mapping)',
    expectedFields: [] as string[],
    isIllustrative: true,
    config: {
      requiredByCategory: {
        EXTENSION_OF_APPROVAL: ['FIRE_SAFETY_CERTIFICATE', 'AFFIDAVIT_INTAKE', 'AICTE_FEE_RECEIPT'],
        NEW_INSTITUTION: [
          'FIRE_SAFETY_CERTIFICATE',
          'LAND_USE_CERTIFICATE',
          'BUILDING_PLAN_APPROVAL',
          'AFFIDAVIT_INTAKE',
          'AICTE_FEE_RECEIPT',
        ],
        INCREASE_IN_INTAKE: [
          'FIRE_SAFETY_CERTIFICATE',
          'BUILDING_PLAN_APPROVAL',
          'AFFIDAVIT_INTAKE',
          'NOC_AFFILIATING_UNIVERSITY',
        ],
      },
    },
  },
  {
    id: 'RUL-002',
    ruleCode: 'RULE-DOC-EXPIRY',
    version: '1.1.0',
    name: 'Statutory Certificate Validity & Chronology Check',
    description:
      'Flags certificates whose expiry_date precedes the scrutiny reference date or precedes the certificate issue_date.',
    category: 'ALL',
    docType: 'FIRE_SAFETY_CERTIFICATE' as string | null,
    ruleType: 'TEMPORAL_VALIDITY',
    severity: 'CRITICAL',
    authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE',
    recommendedAction: 'Require renewed valid certificate or verify official extension corrigendum.',
    evidenceReferenceLabel: 'Extracted issue_date & expiry_date Fields',
    expectedFields: ['issue_date', 'expiry_date'],
    isIllustrative: true,
    config: { gracePeriodDays: 0 },
  },
  {
    id: 'RUL-003',
    ruleCode: 'RULE-REQ-FIELDS',
    version: '1.1.0',
    name: 'Mandatory Document Field Extraction Check',
    description:
      'Verifies presence of certificate reference number, institution name, issue date, and type-specific attributes.',
    category: 'ALL',
    docType: null as string | null,
    ruleType: 'FIELD_PRESENCE',
    severity: 'MEDIUM',
    authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE',
    recommendedAction: 'Inspect original document scan and enter missing field or request legible replacement.',
    evidenceReferenceLabel: 'Document Type Mandatory Field Matrix',
    expectedFields: ['certificate_number', 'institution_name', 'issue_date'],
    isIllustrative: true,
    config: {},
  },
  {
    id: 'RUL-004',
    ruleCode: 'RULE-INST-CROSSCHECK',
    version: '1.0.0',
    name: 'Institution Name & Land Record Cross-Verification',
    description:
      'Compares extracted institution name and land acreage against institutional master profile and application submission.',
    category: 'ALL',
    docType: null as string | null,
    ruleType: 'CROSS_DOCUMENT_CONSISTENCY',
    severity: 'HIGH',
    authoritySource: 'INSTITUTIONAL_CROSSCHECK',
    recommendedAction: 'Verify sponsoring trust/society records and land revenue demarcation.',
    evidenceReferenceLabel: 'Institution Master Profile vs Extracted Certificate Fields',
    expectedFields: ['institution_name', 'land_area_acres'],
    isIllustrative: false,
    config: { minTokenSimilarity: 0.5 },
  },
  {
    id: 'RUL-005',
    ruleCode: 'RULE-INTAKE-MATCH',
    version: '1.0.0',
    name: 'Sanctioned / Requested Intake Affidavit Consistency',
    description: 'Checks that intake stated in sworn Affidavit matches requested seat intake in the application.',
    category: 'ALL',
    docType: 'AFFIDAVIT_INTAKE' as string | null,
    ruleType: 'NUMERIC_EQUALITY',
    severity: 'HIGH',
    authoritySource: 'INSTITUTIONAL_CROSSCHECK',
    recommendedAction: 'Request amended notarized affidavit matching requested programme intake.',
    evidenceReferenceLabel: 'Application requestedIntake vs Affidavit approved_intake',
    expectedFields: ['approved_intake'],
    isIllustrative: false,
    config: {},
  },
  {
    id: 'RUL-006',
    ruleCode: 'RULE-SHA256-DUPLICATE',
    version: '1.0.0',
    name: 'Cryptographic SHA-256 Exact Duplicate File Check',
    description: 'Detects identical SHA-256 content hashes uploaded multiple times within or across applications.',
    category: 'ALL',
    docType: null as string | null,
    ruleType: 'HASH_UNIQUENESS',
    severity: 'CRITICAL',
    authoritySource: 'CRYPTOGRAPHIC_INTEGRITY',
    recommendedAction: 'Compare duplicate byte streams across filings and verify beneficiary institution.',
    evidenceReferenceLabel: 'Document SHA-256 Digest',
    expectedFields: [],
    isIllustrative: false,
    config: {},
  },
  {
    id: 'RUL-007',
    ruleCode: 'RULE-DUP-IDENTIFIER',
    version: '1.0.0',
    name: 'Cross-Application Certificate Identifier Collision',
    description: 'Flags identical certificate/receipt reference numbers reused across distinct institutional applications.',
    category: 'ALL',
    docType: null as string | null,
    ruleType: 'IDENTIFIER_UNIQUENESS',
    severity: 'CRITICAL',
    authoritySource: 'CRYPTOGRAPHIC_INTEGRITY',
    recommendedAction: 'Verify certificate serial against issuing authority registry across conflicting filings.',
    evidenceReferenceLabel: 'Cross-Application certificate_number Index',
    expectedFields: ['certificate_number'],
    isIllustrative: false,
    config: {},
  },
  {
    id: 'RUL-008',
    ruleCode: 'RULE-OCR-QUALITY',
    version: '1.0.0',
    name: 'OCR Readability & Minimum Confidence Threshold',
    description: 'Routes low-confidence scans or unavailable raster OCR documents to mandatory human officer review.',
    category: 'ALL',
    docType: null as string | null,
    ruleType: 'CONFIDENCE_THRESHOLD',
    severity: 'MEDIUM',
    authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE',
    recommendedAction: 'Inspect original scan visually in the Document Viewer; never auto-reject on OCR failure.',
    evidenceReferenceLabel: 'OCR Engine Confidence Metric',
    expectedFields: [],
    isIllustrative: true,
    config: { minConfidence: 0.75 },
  },
  {
    id: 'RUL-009',
    ruleCode: 'RULE-INFRA-NORMS',
    version: '1.0.0',
    name: 'Built-Up Area per Student Threshold (Configurable Demo Rule)',
    description:
      'Illustrative configurable check comparing submitted built-up sqm against requested intake * minBuiltUpSqmPerStudent.',
    category: 'ALL',
    docType: 'BUILDING_PLAN_APPROVAL' as string | null,
    ruleType: 'RATIO_THRESHOLD',
    severity: 'MEDIUM',
    authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE',
    recommendedAction: 'Verify instructional + circulation area against official APH handbook or flag EVC inspection.',
    evidenceReferenceLabel: 'Illustrative Area-per-Student Ratio (4.5 sqm/seat default)',
    expectedFields: ['built_up_area_sqm'],
    isIllustrative: true,
    config: { minBuiltUpSqmPerStudent: 4.5 },
  },
  {
    id: 'RUL-010',
    ruleCode: 'RULE-DOC-TYPE-MATCH',
    version: '1.0.0',
    name: 'Declared vs Detected Document Type Consistency',
    description:
      'Flags uploaded files whose detected document classification differs from the declared document slot.',
    category: 'ALL',
    docType: null as string | null,
    ruleType: 'DOCUMENT_CLASSIFICATION',
    severity: 'HIGH',
    authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE',
    recommendedAction: 'Confirm document classification visually and ask applicant to re-upload under proper slot if misfiled.',
    evidenceReferenceLabel: 'Declared Slot vs Heading Classifier',
    expectedFields: [],
    isIllustrative: true,
    config: {},
  },
];

/**
 * Ensures baseline regulatory validation rules, categories, and compliance items exist
 * even when `ENABLE_DEMO_MODE=false` and synthetic demo accounts/sample data are not seeded.
 */
export function ensureDefaultValidationRules(db: DatabaseSync): void {
  ensureDefaultCategoriesAndCompliance(db);

  const nowIso = new Date().toISOString();
  const adminUser = db.prepare('SELECT id FROM users WHERE id = ?').get('USR-ADMIN-01') as { id: string } | undefined;
  const updatedBy = adminUser ? adminUser.id : null;

  withTransaction(db, () => {
    const checkStmt = db.prepare('SELECT id FROM validation_rules WHERE rule_code = ? LIMIT 1');
    const ruleStmt = db.prepare(
      `INSERT OR IGNORE INTO validation_rules (
        id, rule_code, version, name, description, category, doc_type, rule_type,
        severity, authority_source, config_json, expected_fields_json,
        recommended_action, evidence_reference_label, is_illustrative,
        is_active, updated_by, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
    );
    for (const r of DEFAULT_VALIDATION_RULES) {
      if (!checkStmt.get(r.ruleCode)) {
        ruleStmt.run(
          r.id,
          r.ruleCode,
          r.version,
          r.name,
          r.description,
          r.category,
          r.docType,
          r.ruleType,
          r.severity,
          r.authoritySource,
          JSON.stringify(r.config),
          JSON.stringify(r.expectedFields),
          r.recommendedAction,
          r.evidenceReferenceLabel,
          r.isIllustrative ? 1 : 0,
          updatedBy,
          nowIso
        );
      }
    }
  });
}

export async function seedDatabase(
  db: DatabaseSync,
  options: { forceReset?: boolean; uploadDir?: string; sampleDocsDir?: string; skipExternalOcr?: boolean } = {}
): Promise<SeedSummary> {
  runMigrations(db);

  const uploadDir = resolveUploadDir(options.uploadDir);
  const sampleDir = resolveSampleDocsDir(options.sampleDocsDir);

  if (options.forceReset) {
    withTransaction(db, () => {
      db.exec(`
        DELETE FROM in_app_notifications;
        DELETE FROM application_compliance_items;
        DELETE FROM compliance_requirements;
        DELETE FROM application_categories;
        DELETE FROM audit_logs;
        DELETE FROM officer_reviews;
        DELETE FROM source_verifications;
        DELETE FROM validation_findings;
        DELETE FROM extracted_fields;
        DELETE FROM documents;
        DELETE FROM applications;
        DELETE FROM user_sessions;
        DELETE FROM validation_rules;
        DELETE FROM sandbox_issuer_registry;
        DELETE FROM users;
        DELETE FROM institutions;
      `);
    });
  } else {
    const existingDemoUsers = db
      .prepare('SELECT COUNT(*) AS cnt FROM users WHERE is_demo_account = 1')
      .get() as { cnt: number };
    if (existingDemoUsers.cnt > 0) {
      ensureDefaultValidationRules(db);
      // Idempotently verify that seeded demo accounts match current configured seed password hash
      const targetDemoPassword = getDemoSeedPassword();
      const demoRows = db
        .prepare('SELECT id, password_hash FROM users WHERE is_demo_account = 1')
        .all() as Array<{ id: string; password_hash: string }>;
      const staleIds = demoRows
        .filter((r) => !verifyPassword(targetDemoPassword, r.password_hash))
        .map((r) => r.id);
      if (staleIds.length > 0) {
        const refreshedHash = hashPassword(targetDemoPassword);
        withTransaction(db, () => {
          const upd = db.prepare('UPDATE users SET password_hash = ?, is_active = 1 WHERE id = ? AND is_demo_account = 1');
          for (const uid of staleIds) {
            upd.run(refreshedHash, uid);
          }
        });
      }

      const totalUsersCnt = (db.prepare('SELECT COUNT(*) AS cnt FROM users').get() as { cnt: number }).cnt;
      const appsCnt = (db.prepare('SELECT COUNT(*) AS cnt FROM applications').get() as { cnt: number }).cnt;
      const docsCnt = (db.prepare('SELECT COUNT(*) AS cnt FROM documents').get() as { cnt: number }).cnt;
      const instCnt = (db.prepare('SELECT COUNT(*) AS cnt FROM institutions').get() as { cnt: number }).cnt;
      return {
        seeded: false,
        usersCount: totalUsersCnt,
        institutionsCount: instCnt,
        applicationsCount: appsCnt,
        documentsCount: docsCnt,
        sampleFixturesWritten: [],
      };
    }
  }

  ensureDefaultCategoriesAndCompliance(db);

  const nowIso = '2026-10-25T08:00:00.000Z';
  const passwordHash = hashPassword(getDemoSeedPassword());

  // 1. Seed Sample Institutions (marked `is_synthetic_demo = 1` in schema)
  const institutions = [
    {
      id: 'INST-IIET-01',
      code: 'IIET-DEL',
      name: 'Indraprastha Institute of Engineering & Technology',
      state: 'Delhi',
      district: 'New Delhi',
      institutionType: 'Private Self-Financed Technical Institution',
      establishedYear: 2011,
      approvedIntake: 240,
      landAreaAcres: 5.5,
      builtUpAreaSqm: 1420,
      principalName: 'Dr. Raghavendra Prasad',
      aictePermanentId: '1-90011001-DEMO',
    },
    {
      id: 'INST-KVTC-02',
      code: 'KVTC-TN',
      name: 'Kaveri Valley Technical Campus',
      state: 'Tamil Nadu',
      district: 'Coimbatore',
      institutionType: 'Private Self-Financed Engineering College',
      establishedYear: 2015,
      approvedIntake: 240,
      landAreaAcres: 7.2,
      builtUpAreaSqm: 1850,
      principalName: 'Dr. S. Subramanian',
      aictePermanentId: '1-90022002-DEMO',
    },
    {
      id: 'INST-SHP-03',
      code: 'SHP-HP',
      name: 'Shivalik Hills Polytechnic',
      state: 'Himachal Pradesh',
      district: 'Solan',
      institutionType: 'Diploma Polytechnic Institution',
      establishedYear: 2026,
      approvedIntake: 180,
      landAreaAcres: 4.0,
      builtUpAreaSqm: 680,
      principalName: 'Prof. Harbans Thakur',
      aictePermanentId: '1-90033003-DEMO',
    },
    {
      id: 'INST-DMCE-04',
      code: 'DMCE-TS',
      name: 'Deccan Metro College of Engineering',
      state: 'Telangana',
      district: 'Rangareddy',
      institutionType: 'Private Self-Financed Technical Institution',
      establishedYear: 2017,
      approvedIntake: 240,
      landAreaAcres: 6.0,
      builtUpAreaSqm: 1320,
      principalName: 'Dr. Venkatramana Reddy',
      aictePermanentId: '1-90044004-DEMO',
    },
    {
      id: 'INST-NVS-05',
      code: 'NVS-BR',
      name: 'Nalanda Vishwakarma Sansthan',
      state: 'Bihar',
      district: 'Nalanda',
      institutionType: 'Rural Technical & Vocational Institute',
      establishedYear: 2019,
      approvedIntake: 120,
      landAreaAcres: 5.0,
      builtUpAreaSqm: 960,
      principalName: 'Dr. Ashutosh Mishra',
      aictePermanentId: '1-90055005-DEMO',
    },
  ];

  // 2. Seed Demo Accounts with Real Scrypt Hashes
  const users = [
    {
      id: 'USR-OFFICER-01',
      email: 'officer@authentix.demo',
      fullName: 'Ananya Sharma (Scrutiny Officer)',
      role: 'REVIEW_OFFICER',
      institutionId: null,
    },
    {
      id: 'USR-AUDITOR-01',
      email: 'auditor@authentix.demo',
      fullName: 'Dr. Vikramaditya Nair (Senior Vigilance Auditor)',
      role: 'SENIOR_AUDITOR',
      institutionId: null,
    },
    {
      id: 'USR-ADMIN-01',
      email: 'admin@authentix.demo',
      fullName: 'Rajeshwar Kulkarni (Rules & Platform Admin)',
      role: 'ADMIN',
      institutionId: null,
    },
    {
      id: 'USR-INST-KVTC',
      email: 'registrar@kaveritech.demo',
      fullName: 'Prof. Meenakshi Iyer (KVTC Registrar)',
      role: 'INSTITUTION_USER',
      institutionId: 'INST-KVTC-02',
    },
  ];

  // 3. Seed Configurable Versioned Validation Rules
  const rules = DEFAULT_VALIDATION_RULES;

  // 4. Deterministic Sandbox Issuer Fixtures
  const sandboxRegistry = [
    {
      id: 'SBX-001',
      issuerCode: 'DEL-FIRE',
      issuerName: 'Delhi Fire Services Directorate',
      referenceNumber: 'FSC-DEL-2026-1001',
      institutionName: 'Indraprastha Institute of Engineering & Technology',
      docType: 'FIRE_SAFETY_CERTIFICATE',
      issuedDate: '2026-02-10',
      expiryDate: '2029-02-09',
      statusSimulation: 'VERIFIED',
      payload: { buildingBlocksCovered: 3, nocCategory: 'Educational Group B' },
    },
    {
      id: 'SBX-002',
      issuerCode: 'AICTE-FIN',
      issuerName: 'AICTE e-Payment Gateway',
      referenceNumber: 'FEE-2026-990101',
      institutionName: 'Indraprastha Institute of Engineering & Technology',
      docType: 'AICTE_FEE_RECEIPT',
      issuedDate: '2026-09-12',
      expiryDate: null,
      statusSimulation: 'VERIFIED',
      payload: { amountInr: 150000, paymentSettlement: 'SETTLED' },
    },
    {
      id: 'SBX-003',
      issuerCode: 'TN-FIRE',
      issuerName: 'Tamil Nadu Fire & Rescue Services',
      referenceNumber: 'FSC-TN-2022-4410',
      institutionName: 'Kaveri Valley Technical Campus',
      docType: 'FIRE_SAFETY_CERTIFICATE',
      issuedDate: '2022-04-01',
      expiryDate: '2025-03-31',
      statusSimulation: 'EXPIRED',
      payload: { renewalApplicationFound: false },
    },
    {
      id: 'SBX-004',
      issuerCode: 'NOTARY-TN',
      issuerName: 'Coimbatore e-Stamp & Notary Registry',
      referenceNumber: 'AFF-TN-2026-7721',
      institutionName: 'Kaveri Valley Technical Campus',
      docType: 'AFFIDAVIT_INTAKE',
      issuedDate: '2026-09-20',
      expiryDate: '2027-09-19',
      statusSimulation: 'MISMATCH_DETECTED',
      payload: { registeredIntakeOnAffidavit: 240, discrepancyNote: 'Affidavit states 240 seats, filing claims 360.' },
    },
    {
      id: 'SBX-005',
      issuerCode: 'BR-FIRE',
      issuerName: 'Bihar State Fire Service Portal',
      referenceNumber: 'FSC-BR-2026-5509',
      institutionName: 'Nalanda Vishwakarma Sansthan',
      docType: 'FIRE_SAFETY_CERTIFICATE',
      issuedDate: '2026-05-14',
      expiryDate: '2028-05-13',
      statusSimulation: 'SOURCE_UNAVAILABLE',
      payload: { upstreamGatewayCode: 'GATEWAY_TIMEOUT_SIMULATION' },
    },
  ];

  withTransaction(db, () => {
    const instStmt = db.prepare(
      `INSERT OR IGNORE INTO institutions (
        id, code, name, state, district, institution_type, established_year,
        approved_intake, land_area_acres, built_up_area_sqm, principal_name,
        aicte_permanent_id, is_synthetic_demo, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
    );
    for (const inst of institutions) {
      instStmt.run(
        inst.id,
        inst.code,
        inst.name,
        inst.state,
        inst.district,
        inst.institutionType,
        inst.establishedYear,
        inst.approvedIntake,
        inst.landAreaAcres,
        inst.builtUpAreaSqm,
        inst.principalName,
        inst.aictePermanentId,
        nowIso
      );
    }

    const userStmt = db.prepare(
      `INSERT OR IGNORE INTO users (
        id, email, password_hash, full_name, role, institution_id, is_active, is_demo_account, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?)`
    );
    for (const u of users) {
      userStmt.run(u.id, u.email, passwordHash, u.fullName, u.role, u.institutionId, nowIso);
    }

    const checkRuleStmt = db.prepare('SELECT id FROM validation_rules WHERE rule_code = ? LIMIT 1');
    const ruleStmt = db.prepare(
      `INSERT OR IGNORE INTO validation_rules (
        id, rule_code, version, name, description, category, doc_type, rule_type,
        severity, authority_source, config_json, expected_fields_json,
        recommended_action, evidence_reference_label, is_illustrative,
        is_active, updated_by, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
    );
    for (const r of rules) {
      if (!checkRuleStmt.get(r.ruleCode)) {
        ruleStmt.run(
          r.id,
          r.ruleCode,
          r.version,
          r.name,
          r.description,
          r.category,
          r.docType,
          r.ruleType,
          r.severity,
          r.authoritySource,
          JSON.stringify(r.config),
          JSON.stringify(r.expectedFields),
          r.recommendedAction,
          r.evidenceReferenceLabel,
          r.isIllustrative ? 1 : 0,
          'USR-ADMIN-01',
          nowIso
        );
      }
    }

    const sbxStmt = db.prepare(
      `INSERT OR IGNORE INTO sandbox_issuer_registry (
        id, issuer_code, issuer_name, reference_number, institution_name,
        doc_type, issued_date, expiry_date, status_simulation, payload_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const s of sandboxRegistry) {
      sbxStmt.run(
        s.id,
        s.issuerCode,
        s.issuerName,
        s.referenceNumber,
        s.institutionName,
        s.docType,
        s.issuedDate,
        s.expiryDate,
        s.statusSimulation,
        JSON.stringify(s.payload)
      );
    }

    appendAuditEvent(db, {
      actorUserId: 'USR-ADMIN-01',
      actorEmail: 'admin@authentix.demo',
      actorRole: 'ADMIN',
      action: 'SYSTEM_SEED_INITIALIZED',
      resourceType: 'SYSTEM',
      resourceId: 'AUTHENTIX-DEMO',
      metadata: {
        syntheticInstitutions: institutions.length,
        demoUsers: users.length,
        configuredRules: rules.length,
      },
      timestamp: nowIso,
    });
  });

  // 5. Seed 5 Representative Synthetic Applications
  const applications = [
    {
      id: 'APP-ID-0101',
      applicationNumber: 'APP-2026-0101',
      institutionId: 'INST-IIET-01',
      academicYear: '2026-27',
      category: 'EXTENSION_OF_APPROVAL',
      programNames: 'B.Tech Computer Science & Engineering, B.Tech Electronics',
      requestedIntake: 240,
      submittedLandAcres: 5.5,
      submittedBuiltUpSqm: 1420,
      submittedPrincipalName: 'Dr. Raghavendra Prasad',
    },
    {
      id: 'APP-ID-0102',
      applicationNumber: 'APP-2026-0102',
      institutionId: 'INST-KVTC-02',
      academicYear: '2026-27',
      category: 'INCREASE_IN_INTAKE',
      programNames: 'B.E. Artificial Intelligence & Data Science, B.E. Mechanical',
      requestedIntake: 360,
      submittedLandAcres: 7.2,
      submittedBuiltUpSqm: 1850,
      submittedPrincipalName: 'Dr. S. Subramanian',
    },
    {
      id: 'APP-ID-0103',
      applicationNumber: 'APP-2026-0103',
      institutionId: 'INST-SHP-03',
      academicYear: '2026-27',
      category: 'NEW_INSTITUTION',
      programNames: 'Diploma in Civil Engineering, Diploma in Electrical Engineering',
      requestedIntake: 180,
      submittedLandAcres: 4.0,
      submittedBuiltUpSqm: 680,
      submittedPrincipalName: 'Prof. Harbans Thakur',
    },
    {
      id: 'APP-ID-0104',
      applicationNumber: 'APP-2026-0104',
      institutionId: 'INST-DMCE-04',
      academicYear: '2026-27',
      category: 'EXTENSION_OF_APPROVAL',
      programNames: 'B.Tech Information Technology, B.Tech Civil Engineering',
      requestedIntake: 240,
      submittedLandAcres: 6.0,
      submittedBuiltUpSqm: 1320,
      submittedPrincipalName: 'Dr. Venkatramana Reddy',
    },
    {
      id: 'APP-ID-0105',
      applicationNumber: 'APP-2026-0105',
      institutionId: 'INST-NVS-05',
      academicYear: '2026-27',
      category: 'EXTENSION_OF_APPROVAL',
      programNames: 'B.Voc Renewable Energy, Diploma in Manufacturing',
      requestedIntake: 120,
      submittedLandAcres: 5.0,
      submittedBuiltUpSqm: 960,
      submittedPrincipalName: 'Dr. Ashutosh Mishra',
    },
  ];

  for (const app of applications) {
    db.prepare(
      `INSERT OR IGNORE INTO applications (
        id, application_number, institution_id, academic_year, category, category_code,
        program_names, requested_intake, submitted_land_acres, submitted_built_up_sqm,
        submitted_principal_name, status, review_priority, is_synthetic_demo,
        created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SUBMITTED', 'STANDARD', 1, 'USR-OFFICER-01', ?, ?)`
    ).run(
      app.id,
      app.applicationNumber,
      app.institutionId,
      app.academicYear,
      app.category,
      app.category,
      app.programNames,
      app.requestedIntake,
      app.submittedLandAcres,
      app.submittedBuiltUpSqm,
      app.submittedPrincipalName,
      nowIso,
      nowIso
    );
  }

  // Generate real PDFs & PNGs for seeded applications AND sample fixtures folder
  const qrPayloadIiet = 'FSC-DEL-2026-1001|INST-IIET-01|2029-02-09';
  const qrSignedIiet = `${qrPayloadIiet}:${signQrPayload(qrPayloadIiet)}`;

  const iietFirePdf = await generateSyntheticPdfBuffer({
    title: 'FIRE SAFETY CERTIFICATE',
    lines: [
      'Department: Delhi Fire Services Directorate',
      'Certificate No: FSC-DEL-2026-1001',
      'Institution Name: Indraprastha Institute of Engineering & Technology',
      'Address: Plot 14, Institutional Area, New Delhi - 110020',
      'Issue Date: 2026-02-10',
      'Expiry Date: 2029-02-09',
      `QR Verification Token: ${qrSignedIiet}`,
      'Certified that fire prevention and life safety arrangements comply with Group-B Educational norms.',
    ],
  });

  const iietAffidavitPdf = await generateSyntheticPdfBuffer({
    title: 'SWORN AFFIDAVIT FOR EXTENSION OF APPROVAL',
    lines: [
      'Issuing Authority: New Delhi e-Notary Registry',
      'Certificate No: AFF-DEL-2026-3004',
      'Institution Name: Indraprastha Institute of Engineering & Technology',
      'Approved Intake: 240',
      'Total Regular Faculty: 28',
      'Land Area: 5.5 Acres',
      'Built-up Area: 1420 sqm',
      'Principal Name: Dr. Raghavendra Prasad',
      'Issue Date: 2026-09-10',
      'Expiry Date: 2027-09-09',
    ],
  });

  const iietFeePdf = await generateSyntheticPdfBuffer({
    title: 'AICTE PROCESSING FEE PAYMENT RECEIPT',
    lines: [
      'Issuing Authority: AICTE e-Payment Gateway',
      'Receipt No: FEE-2026-990101',
      'Institution Name: Indraprastha Institute of Engineering & Technology',
      'Issue Date: 2026-09-12',
      'Amount Paid: INR 150000 (Extension of Approval 2026-27)',
    ],
  });

  const kvtcExpiredFirePdf = await generateSyntheticPdfBuffer({
    title: 'FIRE SAFETY CERTIFICATE',
    lines: [
      'Department: Tamil Nadu Fire & Rescue Services',
      'Certificate No: FSC-TN-2022-4410',
      'Institution Name: Kaveri Valley Technical Campus',
      'Issue Date: 2022-04-01',
      'Expiry Date: 2025-03-31',
      'Notice: Statutory renewal required prior to 2026-27 academic session.',
    ],
  });

  const kvtcMismatchAffidavitPdf = await generateSyntheticPdfBuffer({
    title: 'NOTARIZED INTAKE AFFIDAVIT',
    lines: [
      'Issuing Authority: Coimbatore e-Stamp & Notary Registry',
      'Certificate No: AFF-TN-2026-7721',
      'Institution Name: Kaveri Valley Technical Campus',
      'Approved Intake: 240',
      'Land Area: 7.2 Acres',
      'Principal Name: Dr. S. Subramanian',
      'Issue Date: 2026-09-20',
      'Expiry Date: 2027-09-19',
    ],
  });

  const kvtcBuildingPdf = await generateSyntheticPdfBuffer({
    title: 'BUILDING PLAN & STRUCTURAL STABILITY APPROVAL',
    lines: [
      'Issuing Authority: Directorate of Town and Country Planning, Coimbatore',
      'Certificate No: BPA-TN-2025-8812',
      'Institution Name: Kaveri Valley Technical Campus',
      'Architect COA No: CA/2018/90412',
      'Built-up Area: 1850 sqm',
      'Issue Date: 2025-11-18',
    ],
  });

  const kvtcLabPhotoPng = generateSyntheticPngBuffer({
    width: 640,
    height: 420,
    includeRasterOnly: true,
    softwareTag: 'Campus Documentation Camera',
  });

  const shivalikAffidavitPdf = await generateSyntheticPdfBuffer({
    title: 'NEW INSTITUTION SWORN AFFIDAVIT',
    lines: [
      'Issuing Authority: Solan District Notary Registry',
      'Certificate No: AFF-HP-2026-1190',
      'Institution Name: Shivalik Hills Polytechnic',
      'Approved Intake: 180',
      'Land Area: 4.0 Acres',
      'Built-up Area: 680 sqm',
      'Principal Name: Prof. Harbans Thakur',
      'Issue Date: 2026-09-28',
    ],
  });

  const deccanEditedAffidavitPdf = await generateSyntheticPdfBuffer({
    title: 'SWORN AFFIDAVIT',
    producer: 'Adobe Photoshop 24.2 Image Editor',
    creator: 'Canva Export Utility',
    creationDate: new Date('2026-08-01T10:00:00.000Z'),
    modDate: new Date('2026-10-19T22:45:00.000Z'),
    appendIncrementalComment: true,
    lines: [
      'Issuing Authority: Rangareddy Notary Cell',
      'Certificate No: AFF-TS-2026-6044',
      'Institution Name: Deccan Metro College of Engineering',
      'Approved Intake: 240',
      'Land Area: 6.0 Acres',
      'Principal Name: Dr. Venkatramana Reddy',
      'Issue Date: 2026-08-01',
    ],
  });

  const deccanFeePdf = await generateSyntheticPdfBuffer({
    title: 'AICTE PROCESSING FEE RECEIPT',
    lines: [
      'Issuing Authority: AICTE e-Payment Gateway',
      'Receipt No: FEE-2026-990404',
      'Institution Name: Deccan Metro College of Engineering',
      'Issue Date: 2026-09-29',
    ],
  });

  const nalandaBilingualScanPng = generateSyntheticPngBuffer({
    ocrConfidence: 0.58,
    ocrTextLayer: [
      'प्रमाण पत्र : अग्नि सुरक्षा निदेशालय बिहार (Bilingual Scan Fixture)',
      'Issuing Authority: Bihar State Fire Service Portal',
      'Certificate No: FSC-BR-2026-5509',
      'Institution Name: Nalanda Vishwakarma Sansthan',
      'Issue Date: 2026-05-14',
      'Expiry Date: 2028-05-13',
    ].join('\n'),
  });

  const nalandaAffidavitPdf = await generateSyntheticPdfBuffer({
    title: 'AFFIDAVIT FOR EXTENSION OF APPROVAL',
    lines: [
      'Issuing Authority: Nalanda Sub-Divisional Notary',
      'Certificate No: AFF-BR-2026-5510',
      'Institution Name: Nalanda Vishwakarma Sansthan',
      'Approved Intake: 120',
      'Principal Name: Dr. Ashutosh Mishra',
      'Issue Date: 2026-09-14',
    ],
  });

  const nalandaFeePdf = await generateSyntheticPdfBuffer({
    title: 'AICTE PROCESSING FEE RECEIPT',
    lines: [
      'Issuing Authority: AICTE e-Payment Gateway',
      'Receipt No: FEE-2026-990505',
      'Institution Name: Nalanda Vishwakarma Sansthan',
      'Issue Date: 2026-09-16',
    ],
  });

  const rasterNoTextPng = generateSyntheticPngBuffer({
    includeRasterOnly: true,
    softwareTag: 'Scanner Utility Raw',
  });

  // Save downloadable sample fixtures in data/sample_docs/ for evaluator convenience
  const sampleFiles: Array<{ name: string; buf: Buffer }> = [
    { name: 'sample_valid_fire_safety.pdf', buf: iietFirePdf },
    { name: 'sample_expired_fire_safety.pdf', buf: kvtcExpiredFirePdf },
    { name: 'sample_tampered_metadata_affidavit.pdf', buf: deccanEditedAffidavitPdf },
    { name: 'sample_bilingual_low_conf_scan.png', buf: nalandaBilingualScanPng },
    { name: 'sample_unreadable_raster_only.png', buf: rasterNoTextPng },
    { name: 'sample_facility_lab_photo.png', buf: kvtcLabPhotoPng },
  ];
  for (const sf of sampleFiles) {
    fs.writeFileSync(path.join(sampleDir, sf.name), sf.buf);
  }

  // Helper to ingest a seeded document through the real deterministic extraction pipeline
  const ingestSeedDoc = async (params: {
    id: string;
    applicationId: string;
    declaredDocType: DocumentType;
    filename: string;
    mimeType: 'application/pdf' | 'image/png';
    buffer: Buffer;
  }) => {
    const hash = sha256Hex(params.buffer);
    const storedFilename = `${params.id}_${params.filename}`;
    fs.writeFileSync(path.join(uploadDir, storedFilename), params.buffer);

    const proc = await processDocumentBuffer(params.buffer, params.mimeType, params.declaredDocType, {
      ocrModeOverride: 'local-only',
    });

    const combinedMeta = {
      ...proc.metadata,
      forensicIndicators: proc.forensicIndicators,
    };

    const initialVerifStatus =
      proc.ocrStatus === 'UNAVAILABLE' || proc.ocrStatus === 'LOW_CONFIDENCE' ? 'MANUAL_REVIEW_REQUIRED' : 'UNVERIFIED';

    db.prepare(
      `INSERT INTO documents (
        id, application_id, declared_doc_type, detected_doc_type, classification_confidence,
        original_filename, stored_filename, mime_type, file_size_bytes,
        sha256_hash, page_count, ocr_status, ocr_engine, ocr_confidence,
        extracted_text, extracted_pages_json, metadata_json, verification_status,
        processed_at, uploaded_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'USR-OFFICER-01', ?, ?)`
    ).run(
      params.id,
      params.applicationId,
      params.declaredDocType,
      proc.detectedDocType,
      proc.classificationConfidence,
      params.filename,
      storedFilename,
      params.mimeType,
      params.buffer.length,
      hash,
      proc.pageCount,
      proc.ocrStatus,
      proc.ocrEngine,
      proc.ocrConfidence,
      proc.extractedText,
      JSON.stringify(proc.pages),
      JSON.stringify(combinedMeta),
      initialVerifStatus,
      nowIso,
      nowIso,
      nowIso
    );

    const efStmt = db.prepare(
      `INSERT INTO extracted_fields (
        id, document_id, field_name, field_value, confidence,
        page_number, bbox_json, extraction_method, manually_corrected
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`
    );
    for (const ef of proc.extractedFields) {
      efStmt.run(
        `EF-${crypto.randomUUID()}`,
        params.id,
        ef.fieldName,
        ef.fieldValue,
        ef.confidence,
        ef.pageNumber,
        ef.bbox ? JSON.stringify(ef.bbox) : null,
        ef.extractionMethod
      );
    }
  };

  // Ingest all seeded documents
  const seedDocs = [
    // APP-0101 (Complete & Clean)
    { id: 'DOC-0101-1', applicationId: 'APP-ID-0101', declaredDocType: 'FIRE_SAFETY_CERTIFICATE' as DocumentType, filename: 'Fire_Safety_IIET_2026.pdf', mimeType: 'application/pdf' as const, buffer: iietFirePdf },
    { id: 'DOC-0101-2', applicationId: 'APP-ID-0101', declaredDocType: 'AFFIDAVIT_INTAKE' as DocumentType, filename: 'Affidavit_Intake_IIET_2026.pdf', mimeType: 'application/pdf' as const, buffer: iietAffidavitPdf },
    { id: 'DOC-0101-3', applicationId: 'APP-ID-0101', declaredDocType: 'AICTE_FEE_RECEIPT' as DocumentType, filename: 'AICTE_Fee_Receipt_IIET_2026.pdf', mimeType: 'application/pdf' as const, buffer: iietFeePdf },
    // APP-0102 (Expired Fire + Intake Mismatch + Missing NOC + Lab Facility Photo)
    { id: 'DOC-0102-1', applicationId: 'APP-ID-0102', declaredDocType: 'FIRE_SAFETY_CERTIFICATE' as DocumentType, filename: 'Fire_Safety_KVTC_Expired.pdf', mimeType: 'application/pdf' as const, buffer: kvtcExpiredFirePdf },
    { id: 'DOC-0102-2', applicationId: 'APP-ID-0102', declaredDocType: 'AFFIDAVIT_INTAKE' as DocumentType, filename: 'Affidavit_KVTC_Mismatch.pdf', mimeType: 'application/pdf' as const, buffer: kvtcMismatchAffidavitPdf },
    { id: 'DOC-0102-3', applicationId: 'APP-ID-0102', declaredDocType: 'BUILDING_PLAN_APPROVAL' as DocumentType, filename: 'Building_Plan_KVTC_2025.pdf', mimeType: 'application/pdf' as const, buffer: kvtcBuildingPdf },
    { id: 'DOC-0102-4', applicationId: 'APP-ID-0102', declaredDocType: 'FACILITY_PHOTO_LAB' as DocumentType, filename: 'AI_Computing_Lab_KVTC_2026.png', mimeType: 'image/png' as const, buffer: kvtcLabPhotoPng },
    // APP-0103 (Missing 4 mandatory docs + infra norm shortfall)
    { id: 'DOC-0103-1', applicationId: 'APP-ID-0103', declaredDocType: 'AFFIDAVIT_INTAKE' as DocumentType, filename: 'Affidavit_Shivalik_2026.pdf', mimeType: 'application/pdf' as const, buffer: shivalikAffidavitPdf },
    // APP-0104 (Exact SHA-256 duplicate of IIET Fire Safety + Photoshop-edited Affidavit metadata)
    { id: 'DOC-0104-1', applicationId: 'APP-ID-0104', declaredDocType: 'FIRE_SAFETY_CERTIFICATE' as DocumentType, filename: 'Fire_Safety_DMCE_UploadedCopy.pdf', mimeType: 'application/pdf' as const, buffer: iietFirePdf },
    { id: 'DOC-0104-2', applicationId: 'APP-ID-0104', declaredDocType: 'AFFIDAVIT_INTAKE' as DocumentType, filename: 'Affidavit_DMCE_Modified.pdf', mimeType: 'application/pdf' as const, buffer: deccanEditedAffidavitPdf },
    { id: 'DOC-0104-3', applicationId: 'APP-ID-0104', declaredDocType: 'AICTE_FEE_RECEIPT' as DocumentType, filename: 'AICTE_Fee_DMCE_2026.pdf', mimeType: 'application/pdf' as const, buffer: deccanFeePdf },
    // APP-0105 (Low-confidence bilingual scan + upstream source unavailable)
    { id: 'DOC-0105-1', applicationId: 'APP-ID-0105', declaredDocType: 'FIRE_SAFETY_CERTIFICATE' as DocumentType, filename: 'Fire_Safety_Nalanda_Scan_Bilingual.png', mimeType: 'image/png' as const, buffer: nalandaBilingualScanPng },
    { id: 'DOC-0105-2', applicationId: 'APP-ID-0105', declaredDocType: 'AFFIDAVIT_INTAKE' as DocumentType, filename: 'Affidavit_Nalanda_2026.pdf', mimeType: 'application/pdf' as const, buffer: nalandaAffidavitPdf },
    { id: 'DOC-0105-3', applicationId: 'APP-ID-0105', declaredDocType: 'AICTE_FEE_RECEIPT' as DocumentType, filename: 'AICTE_Fee_Nalanda_2026.pdf', mimeType: 'application/pdf' as const, buffer: nalandaFeePdf },
  ];

  for (const sd of seedDocs) {
    await ingestSeedDoc(sd);
  }

  // Run Sandbox Source Verifications on representative documents
  executeSourceVerification(db, {
    applicationId: 'APP-ID-0101',
    documentId: 'DOC-0101-1',
    method: 'QR_SIGNATURE_CHECK',
    actorUserId: 'USR-OFFICER-01',
  });
  executeSourceVerification(db, {
    applicationId: 'APP-ID-0101',
    documentId: 'DOC-0101-2',
    method: 'MANUAL_OFFICER_VERIFICATION',
    manualStatus: 'VERIFIED',
    issuerName: 'New Delhi e-Notary Registry',
    notes: 'Notary serial verified against physical dispatch register by officer.',
    actorUserId: 'USR-OFFICER-01',
  });
  executeSourceVerification(db, {
    applicationId: 'APP-ID-0101',
    documentId: 'DOC-0101-3',
    method: 'SANDBOX_ISSUER_API',
    actorUserId: 'USR-OFFICER-01',
  });

  executeSourceVerification(db, {
    applicationId: 'APP-ID-0102',
    documentId: 'DOC-0102-1',
    method: 'SANDBOX_ISSUER_API',
    actorUserId: 'USR-OFFICER-01',
  });
  executeSourceVerification(db, {
    applicationId: 'APP-ID-0102',
    documentId: 'DOC-0102-2',
    method: 'SANDBOX_ISSUER_API',
    actorUserId: 'USR-OFFICER-01',
  });

  executeSourceVerification(db, {
    applicationId: 'APP-ID-0105',
    documentId: 'DOC-0105-1',
    method: 'SANDBOX_ISSUER_API',
    actorUserId: 'USR-OFFICER-01',
  });

  // Evaluate regulatory compliance & compute explainable Trust Scores across all 5 applications
  for (const app of applications) {
    const evalRes = evaluateApplicationCompliance(db, app.id);
    appendAuditEvent(db, {
      actorUserId: 'USR-OFFICER-01',
      actorEmail: 'officer@authentix.demo',
      actorRole: 'REVIEW_OFFICER',
      action: 'APPLICATION_COMPLIANCE_EVALUATED',
      resourceType: 'APPLICATION',
      resourceId: app.id,
      metadata: {
        applicationNumber: app.applicationNumber,
        unresolvedFindings: evalRes.findingsCount,
        advisoryTrustScore: evalRes.trustScore.score,
        priority: evalRes.recommendedPriority,
        lifecycleStage: evalRes.lifecycleStage,
      },
      timestamp: nowIso,
    });
  }

  // Seed persisted in-app notifications (IN_APP_ONLY; synthetic demo flagged)
  const notifStmt = db.prepare(
    `INSERT OR IGNORE INTO in_app_notifications (
      id, recipient_role, recipient_institution_id, application_id, alert_type,
      severity, title, message, delivery_channel, is_read, is_synthetic_demo, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'IN_APP_ONLY', 0, 1, ?)`
  );
  notifStmt.run(
    'NTF-DEMO-01',
    'INTERNAL_ALL',
    null,
    'APP-ID-0102',
    'SOURCE_MISMATCH_AND_EXPIRY',
    'CRITICAL',
    'APP-2026-0102: Expired Fire NOC & Intake Mismatch',
    'Kaveri Valley Technical Campus has an expired Fire Safety Certificate (2025-03-31) and sworn intake discrepancy (240 vs 360) awaiting officer scrutiny.',
    nowIso
  );
  notifStmt.run(
    'NTF-DEMO-02',
    'INTERNAL_ALL',
    null,
    'APP-ID-0104',
    'DUPLICATE_HASH_DETECTED',
    'HIGH',
    'APP-2026-0104: SHA-256 Duplicate & Metadata Heuristic Flag',
    'Deccan Metro College uploaded a byte-identical Fire Safety PDF matching APP-2026-0101 alongside graphics-editor PDF metadata markers.',
    nowIso
  );
  notifStmt.run(
    'NTF-DEMO-03',
    'INSTITUTION_USER',
    'INST-KVTC-02',
    'APP-ID-0102',
    'CHECKLIST_DEFICIENCY',
    'HIGH',
    'APP-2026-0102: Missing University NOC & Expired Fire Safety NOC',
    'Your Increase in Intake filing is missing NOC_AFFILIATING_UNIVERSITY and contains an expired Fire Safety Certificate.',
    nowIso
  );

  return {
    seeded: true,
    usersCount: users.length,
    institutionsCount: institutions.length,
    applicationsCount: applications.length,
    documentsCount: seedDocs.length,
    sampleFixturesWritten: sampleFiles.map((s) => s.name),
  };
}
