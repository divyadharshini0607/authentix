/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Configurable Regulatory Rules Engine, Pre-Publication Rule Validator,
 * 5-Way Epistemic Classification, Regulatory/Infrastructure Compliance Sync,
 * and Explainable Advisory Trust Score (trust-v1.0-advisory)
 */

import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type {
  ApplicationCategory,
  ComplianceDomain,
  ComplianceItemStatus,
  DocumentType,
  EpistemicClassification,
  FindingCategory,
  LifecycleStage,
  ReviewPriority,
  SeverityLevel,
  TrustScoreBreakdown,
  TrustScoreContribution,
} from '../shared/types.ts';
import { withTransaction } from './db.ts';
import { inspectVisualEvidenceFromMetadata, type ForensicIndicator } from './ocrPipeline.ts';

export const TRUST_SCORE_VERSION = 'trust-v1.0-advisory';
export const SCRUTINY_REFERENCE_DATE = '2026-10-25';

export const SUPPORTED_RULE_TYPES = [
  'CHECKLIST_PRESENCE',
  'TEMPORAL_VALIDITY',
  'FIELD_PRESENCE',
  'CROSS_DOCUMENT_CONSISTENCY',
  'NUMERIC_EQUALITY',
  'NUMERIC_MINIMUM',
  'HASH_UNIQUENESS',
  'IDENTIFIER_UNIQUENESS',
  'CONFIDENCE_THRESHOLD',
  'RATIO_THRESHOLD',
  'DOCUMENT_CLASSIFICATION',
] as const;

export const ALL_VALID_DOCUMENT_TYPES = new Set<DocumentType>([
  'FIRE_SAFETY_CERTIFICATE',
  'LAND_USE_CERTIFICATE',
  'AFFIDAVIT_INTAKE',
  'BUILDING_PLAN_APPROVAL',
  'AICTE_FEE_RECEIPT',
  'NOC_AFFILIATING_UNIVERSITY',
  'FACILITY_PHOTO_LAB',
  'FACILITY_PHOTO_LIBRARY',
  'FACILITY_PHOTO_CAMPUS',
  'FLOOR_PLAN_DRAWING',
  'FACULTY_ROSTER_STATEMENT',
  'UNKNOWN_DOCUMENT',
]);

const FACILITY_PHOTO_DOC_TYPES = new Set<DocumentType>([
  'FACILITY_PHOTO_LAB',
  'FACILITY_PHOTO_LIBRARY',
  'FACILITY_PHOTO_CAMPUS',
]);

export interface ActiveRuleRow {
  id: string;
  rule_code: string;
  version: string;
  name: string;
  description: string;
  category: string;
  doc_type: string | null;
  rule_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  authority_source: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE' | 'INSTITUTIONAL_CROSSCHECK' | 'CRYPTOGRAPHIC_INTEGRITY';
  config_json: string;
  effective_from?: string | null;
  effective_to?: string | null;
  expected_fields_json?: string | null;
  recommended_action?: string | null;
  evidence_reference_label?: string | null;
  is_illustrative?: number;
}

export const DEFAULT_APPLICATION_CATEGORIES: Array<{
  code: string;
  baseCategory: ApplicationCategory;
  name: string;
  description: string;
  requiredDocTypes: DocumentType[];
}> = [
  {
    code: 'EXTENSION_OF_APPROVAL',
    baseCategory: 'EXTENSION_OF_APPROVAL',
    name: 'Extension of Approval (EoA)',
    description:
      'Annual continuation of approval for existing technical programmes without change in sanctioned seat intake.',
    requiredDocTypes: ['FIRE_SAFETY_CERTIFICATE', 'AFFIDAVIT_INTAKE', 'AICTE_FEE_RECEIPT'],
  },
  {
    code: 'NEW_INSTITUTION',
    baseCategory: 'NEW_INSTITUTION',
    name: 'Setting Up of New Technical Institution',
    description:
      'Initial statutory scrutiny covering contiguous land ownership, approved building plan, fire safety, sworn affidavit, and scrutiny fee.',
    requiredDocTypes: [
      'FIRE_SAFETY_CERTIFICATE',
      'LAND_USE_CERTIFICATE',
      'BUILDING_PLAN_APPROVAL',
      'AFFIDAVIT_INTAKE',
      'AICTE_FEE_RECEIPT',
    ],
  },
  {
    code: 'INCREASE_IN_INTAKE',
    baseCategory: 'INCREASE_IN_INTAKE',
    name: 'Increase in Approved Intake / Additional Course',
    description:
      'Expansion of sanctioned student intake requiring affiliating university NOC, instructional area approval, fire safety, and intake affidavit.',
    requiredDocTypes: [
      'FIRE_SAFETY_CERTIFICATE',
      'BUILDING_PLAN_APPROVAL',
      'AFFIDAVIT_INTAKE',
      'NOC_AFFILIATING_UNIVERSITY',
    ],
  },
];

export const DEFAULT_COMPLIANCE_REQUIREMENTS: Array<{
  id: string;
  requirementCode: string;
  category: string;
  domain: ComplianceDomain;
  title: string;
  description: string;
  acceptedDocTypes: DocumentType[];
  isMandatory: boolean;
  isIllustrative: boolean;
}> = [
  {
    id: 'CRQ-001',
    requirementCode: 'REQ-SAFETY-FIRE-NOC',
    category: 'ALL',
    domain: 'SAFETY_AND_ACCESSIBILITY',
    title: 'Active Fire & Life Safety Certificate',
    description:
      'Valid, unexpired Fire & Life Safety NOC issued by the competent Fire Services authority covering instructional blocks.',
    acceptedDocTypes: ['FIRE_SAFETY_CERTIFICATE'],
    isMandatory: true,
    isIllustrative: true,
  },
  {
    id: 'CRQ-002',
    requirementCode: 'REQ-FACULTY-INTAKE-AFFIDAVIT',
    category: 'ALL',
    domain: 'FACULTY_AND_AFFIDAVIT',
    title: 'Notarized Intake, Faculty & Regulatory Compliance Affidavit',
    description:
      'Sworn notarized undertaking confirming sanctioned seat intake, principal appointment, and adherence to statutory norms.',
    acceptedDocTypes: ['AFFIDAVIT_INTAKE'],
    isMandatory: true,
    isIllustrative: true,
  },
  {
    id: 'CRQ-003',
    requirementCode: 'REQ-STATUTORY-FEE',
    category: 'EXTENSION_OF_APPROVAL',
    domain: 'STATUTORY_APPROVAL',
    title: 'Regulatory Scrutiny Processing Fee Receipt',
    description: 'Settled payment receipt for the applicable academic session application filing.',
    acceptedDocTypes: ['AICTE_FEE_RECEIPT'],
    isMandatory: true,
    isIllustrative: true,
  },
  {
    id: 'CRQ-004',
    requirementCode: 'REQ-LAND-TITLE-CONTIGUITY',
    category: 'NEW_INSTITUTION',
    domain: 'LAND_AND_BUILDING',
    title: 'Non-Agricultural Land Use & Contiguous Acreage Certificate',
    description:
      'Revenue authority certificate confirming clear institutional land use and acreage matching the submitted application.',
    acceptedDocTypes: ['LAND_USE_CERTIFICATE'],
    isMandatory: true,
    isIllustrative: true,
  },
  {
    id: 'CRQ-005',
    requirementCode: 'REQ-BUILDING-INSTRUCTIONAL-AREA',
    category: 'ALL',
    domain: 'LAND_AND_BUILDING',
    title: 'Competent Authority Building Plan & Instructional Area Schedule',
    description:
      'Approved building plan or architectural floor-plan schedule substantiating built-up instructional and circulation area (illustrative threshold rule).',
    acceptedDocTypes: ['BUILDING_PLAN_APPROVAL', 'FLOOR_PLAN_DRAWING'],
    isMandatory: false,
    isIllustrative: true,
  },
  {
    id: 'CRQ-006',
    requirementCode: 'REQ-AFFILIATING-UNIV-NOC',
    category: 'INCREASE_IN_INTAKE',
    domain: 'STATUTORY_APPROVAL',
    title: 'Affiliating University No-Objection Certificate',
    description: 'University NOC consenting to additional divisions/intake for the target academic year.',
    acceptedDocTypes: ['NOC_AFFILIATING_UNIVERSITY'],
    isMandatory: true,
    isIllustrative: true,
  },
  {
    id: 'CRQ-007',
    requirementCode: 'REQ-LAB-VISUAL-EVIDENCE',
    category: 'ALL',
    domain: 'LABORATORY_INFRASTRUCTURE',
    title: 'Laboratory, Library & Barrier-Free Campus Visual Evidence',
    description:
      'Supplementary facility photographs for officer inspection. Uploaded photos never automatically verify physical room dimensions or operational status.',
    acceptedDocTypes: ['FACILITY_PHOTO_LAB', 'FACILITY_PHOTO_LIBRARY', 'FACILITY_PHOTO_CAMPUS'],
    isMandatory: false,
    isIllustrative: true,
  },
  {
    id: 'CRQ-008',
    requirementCode: 'REQ-FACULTY-CADRE-ROSTER',
    category: 'ALL',
    domain: 'FACULTY_AND_AFFIDAVIT',
    title: 'Teaching Faculty Roster & Cadre Summary',
    description:
      'Certified statement of regular faculty strength or sworn faculty undertaking for officer scrutiny.',
    acceptedDocTypes: ['FACULTY_ROSTER_STATEMENT', 'AFFIDAVIT_INTAKE'],
    isMandatory: false,
    isIllustrative: true,
  },
];

export function ensureDefaultCategoriesAndCompliance(db: DatabaseSync): void {
  const nowIso = new Date().toISOString();
  withTransaction(db, () => {
    const catStmt = db.prepare(
      `INSERT OR IGNORE INTO application_categories (
        code, base_category, name, description, required_doc_types_json, is_active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`
    );
    for (const cat of DEFAULT_APPLICATION_CATEGORIES) {
      catStmt.run(
        cat.code,
        cat.baseCategory,
        cat.name,
        cat.description,
        JSON.stringify(cat.requiredDocTypes),
        nowIso,
        nowIso
      );
    }

    const reqStmt = db.prepare(
      `INSERT OR IGNORE INTO compliance_requirements (
        id, requirement_code, category, domain, title, description,
        accepted_doc_types_json, is_mandatory, is_illustrative, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const req of DEFAULT_COMPLIANCE_REQUIREMENTS) {
      reqStmt.run(
        req.id,
        req.requirementCode,
        req.category,
        req.domain,
        req.title,
        req.description,
        JSON.stringify(req.acceptedDocTypes),
        req.isMandatory ? 1 : 0,
        req.isIllustrative ? 1 : 0,
        nowIso
      );
    }
  });
}

function normalizeTextTokens(input: string): string[] {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 2 && !['the', 'and', 'for', 'college', 'institute', 'of', 'technology'].includes(w));
}

function jaccardSimilarity(a: string, b: string): number {
  const setA = new Set(normalizeTextTokens(a));
  const setB = new Set(normalizeTextTokens(b));
  if (setA.size === 0 || setB.size === 0) return 0;
  let inter = 0;
  for (const item of setA) {
    if (setB.has(item)) inter++;
  }
  const union = setA.size + setB.size - inter;
  return union === 0 ? 0 : inter / union;
}

export function parseIsoDate(val: string | undefined | null): Date | null {
  if (!val || !/^\d{4}-\d{2}-\d{2}$/.test(val.trim())) return null;
  const [y, m, d] = val.trim().split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) {
    return null;
  }
  return dt;
}

export interface RuleDefinitionValidationInput {
  ruleCode: string;
  version: string;
  ruleType: string;
  severity: string;
  category: string;
  docType?: string | null;
  config: unknown;
  effectiveFrom?: string | null;
  effectiveTo?: string | null;
  expectedFields?: string[];
}

/**
 * Validates rule schema, semantic version, effective dates, and type-specific parameters
 * BEFORE saving or activating a rule so invalid rules are rejected cleanly and never silently executed.
 */
export function validateRuleDefinition(input: RuleDefinitionValidationInput): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (!/^RULE-[A-Z0-9_-]{3,40}$/.test(input.ruleCode.trim())) {
    errors.push('ruleCode must match RULE-[A-Z0-9_-]{3,40} (e.g. RULE-LAB-AREA-MIN).');
  }

  if (!/^\d+\.\d+\.\d+$/.test(input.version.trim())) {
    errors.push('version must be a valid semantic version (MAJOR.MINOR.PATCH, e.g. 1.0.0).');
  }

  if (!(SUPPORTED_RULE_TYPES as readonly string[]).includes(input.ruleType)) {
    errors.push(
      `Unsupported ruleType '${input.ruleType}'. Supported types: ${SUPPORTED_RULE_TYPES.join(', ')}.`
    );
  }

  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(input.severity)) {
    errors.push('severity must be CRITICAL, HIGH, MEDIUM, or LOW.');
  }

  if (input.docType && !ALL_VALID_DOCUMENT_TYPES.has(input.docType as DocumentType)) {
    errors.push(`Invalid docType '${input.docType}'.`);
  }

  const effFrom = input.effectiveFrom ? parseIsoDate(input.effectiveFrom) : null;
  const effTo = input.effectiveTo ? parseIsoDate(input.effectiveTo) : null;
  if (input.effectiveFrom && !effFrom) {
    errors.push(`effectiveFrom '${input.effectiveFrom}' must be a valid YYYY-MM-DD calendar date.`);
  }
  if (input.effectiveTo && !effTo) {
    errors.push(`effectiveTo '${input.effectiveTo}' must be a valid YYYY-MM-DD calendar date.`);
  }
  if (effFrom && effTo && effFrom.getTime() > effTo.getTime()) {
    errors.push('effectiveFrom cannot be later than effectiveTo.');
  }

  if (typeof input.config !== 'object' || input.config === null || Array.isArray(input.config)) {
    errors.push('config must be a JSON object.');
    return { valid: false, errors };
  }

  const cfg = input.config as Record<string, unknown>;

  switch (input.ruleType) {
    case 'CONFIDENCE_THRESHOLD': {
      if (cfg.minConfidence !== undefined) {
        if (typeof cfg.minConfidence !== 'number' || !Number.isFinite(cfg.minConfidence) || cfg.minConfidence <= 0 || cfg.minConfidence > 1) {
          errors.push('CONFIDENCE_THRESHOLD config.minConfidence must be a number in (0, 1].');
        }
      }
      break;
    }
    case 'RATIO_THRESHOLD': {
      if (cfg.minBuiltUpSqmPerStudent !== undefined || input.ruleCode !== 'RULE-INFRA-NORMS') {
        if (
          typeof cfg.minBuiltUpSqmPerStudent !== 'number' ||
          !Number.isFinite(cfg.minBuiltUpSqmPerStudent) ||
          cfg.minBuiltUpSqmPerStudent <= 0 ||
          cfg.minBuiltUpSqmPerStudent > 500
        ) {
          errors.push('RATIO_THRESHOLD config.minBuiltUpSqmPerStudent must be a positive number in (0, 500].');
        }
      }
      break;
    }
    case 'TEMPORAL_VALIDITY': {
      if (cfg.gracePeriodDays !== undefined) {
        if (
          typeof cfg.gracePeriodDays !== 'number' ||
          !Number.isInteger(cfg.gracePeriodDays) ||
          cfg.gracePeriodDays < 0 ||
          cfg.gracePeriodDays > 3650
        ) {
          errors.push('TEMPORAL_VALIDITY config.gracePeriodDays must be an integer between 0 and 3650.');
        }
      }
      break;
    }
    case 'CROSS_DOCUMENT_CONSISTENCY': {
      if (cfg.minTokenSimilarity !== undefined) {
        if (
          typeof cfg.minTokenSimilarity !== 'number' ||
          !Number.isFinite(cfg.minTokenSimilarity) ||
          cfg.minTokenSimilarity <= 0 ||
          cfg.minTokenSimilarity > 1
        ) {
          errors.push('CROSS_DOCUMENT_CONSISTENCY config.minTokenSimilarity must be a number in (0, 1].');
        }
      }
      break;
    }
    case 'CHECKLIST_PRESENCE': {
      if (cfg.requiredByCategory !== undefined) {
        if (typeof cfg.requiredByCategory !== 'object' || cfg.requiredByCategory === null || Array.isArray(cfg.requiredByCategory)) {
          errors.push('CHECKLIST_PRESENCE config.requiredByCategory must be an object mapping category codes to document type arrays.');
        } else {
          for (const [catKey, docArr] of Object.entries(cfg.requiredByCategory as Record<string, unknown>)) {
            if (!Array.isArray(docArr) || docArr.length === 0) {
              errors.push(`CHECKLIST_PRESENCE requiredByCategory['${catKey}'] must be a non-empty array.`);
              continue;
            }
            for (const dt of docArr) {
              if (typeof dt !== 'string' || !ALL_VALID_DOCUMENT_TYPES.has(dt as DocumentType)) {
                errors.push(`CHECKLIST_PRESENCE requiredByCategory['${catKey}'] contains invalid DocumentType '${String(dt)}'.`);
              }
            }
          }
        }
      }
      break;
    }
    case 'NUMERIC_MINIMUM': {
      if (typeof cfg.fieldName !== 'string' || cfg.fieldName.trim().length < 2) {
        errors.push('NUMERIC_MINIMUM requires a non-empty string config.fieldName (e.g. "total_faculty_count").');
      }
      if (typeof cfg.minValue !== 'number' || !Number.isFinite(cfg.minValue)) {
        errors.push('NUMERIC_MINIMUM requires a finite numeric config.minValue.');
      }
      break;
    }
    case 'FIELD_PRESENCE': {
      if (input.ruleCode !== 'RULE-REQ-FIELDS') {
        const reqFields = cfg.requiredFields ?? input.expectedFields;
        if (
          !Array.isArray(reqFields) ||
          reqFields.length === 0 ||
          !reqFields.every((f) => typeof f === 'string' && f.trim().length > 0)
        ) {
          errors.push('Custom FIELD_PRESENCE rules require a non-empty array of field names in config.requiredFields or expectedFields.');
        }
      }
      break;
    }
    default:
      break;
  }

  return { valid: errors.length === 0, errors };
}

export function resolveRequiredChecklistForApplication(
  db: DatabaseSync,
  baseCategory: ApplicationCategory,
  categoryCode?: string | null
): DocumentType[] {
  let defaultByCat: Record<string, DocumentType[]> = {
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
  };

  if (categoryCode) {
    const catRow = db
      .prepare('SELECT required_doc_types_json FROM application_categories WHERE code = ? AND is_active = 1')
      .get(categoryCode) as { required_doc_types_json: string } | undefined;
    if (catRow) {
      try {
        const parsed = JSON.parse(catRow.required_doc_types_json) as DocumentType[];
        if (Array.isArray(parsed) && parsed.length > 0) {
          defaultByCat[categoryCode] = parsed;
        }
      } catch {
        // ignore malformed custom checklist fallback
      }
    }
  }

  const reqDocsRule = db
    .prepare("SELECT config_json FROM validation_rules WHERE rule_code = 'RULE-REQ-DOCS' AND is_active = 1 LIMIT 1")
    .get() as { config_json: string } | undefined;
  if (reqDocsRule) {
    try {
      const cfg = JSON.parse(reqDocsRule.config_json) as { requiredByCategory?: Record<string, DocumentType[]> };
      if (cfg.requiredByCategory) {
        defaultByCat = { ...defaultByCat, ...cfg.requiredByCategory };
      }
    } catch {
      // keep defaults
    }
  }

  if (categoryCode && defaultByCat[categoryCode]) {
    return defaultByCat[categoryCode];
  }
  return defaultByCat[baseCategory] || defaultByCat.EXTENSION_OF_APPROVAL;
}

export function evaluateApplicationCompliance(
  db: DatabaseSync,
  applicationId: string,
  referenceDateStr: string = SCRUTINY_REFERENCE_DATE
): {
  findingsCount: number;
  trustScore: TrustScoreBreakdown;
  recommendedPriority: ReviewPriority;
  lifecycleStage: LifecycleStage;
  nextRecommendedAction: string;
} {
  ensureDefaultCategoriesAndCompliance(db);

  const appRow = db
    .prepare(
      `SELECT a.*, i.name AS inst_name, i.approved_intake AS inst_intake,
              i.land_area_acres AS inst_land, i.built_up_area_sqm AS inst_built_up,
              i.principal_name AS inst_principal
       FROM applications a
       JOIN institutions i ON i.id = a.institution_id
       WHERE a.id = ?`
    )
    .get(applicationId) as
    | {
        id: string;
        application_number: string;
        institution_id: string;
        category: ApplicationCategory;
        category_code: string | null;
        submission_cycle: number;
        physical_inspection_required: number;
        requested_intake: number;
        submitted_land_acres: number;
        submitted_built_up_sqm: number;
        submitted_principal_name: string;
        status: string;
        final_officer_decision: string | null;
        inst_name: string;
        inst_intake: number;
        inst_land: number;
        inst_built_up: number;
        inst_principal: string;
      }
    | undefined;

  if (!appRow) {
    throw new Error(`Application ${applicationId} not found`);
  }

  const effectiveCatCode = appRow.category_code || appRow.category;
  const currentCycle = Math.max(1, Number(appRow.submission_cycle || 1));
  const refDate = parseIsoDate(referenceDateStr) || new Date(Date.UTC(2026, 9, 25));

  const totalConfiguredRules = (
    db.prepare('SELECT COUNT(*) AS cnt FROM validation_rules').get() as { cnt: number }
  ).cnt;

  const rawActiveRules = db
    .prepare('SELECT * FROM validation_rules WHERE is_active = 1 ORDER BY rule_code ASC')
    .all() as unknown as ActiveRuleRow[];

  const activeRules = rawActiveRules.filter((r) => {
    if (r.effective_from) {
      const ef = parseIsoDate(r.effective_from);
      if (ef && refDate.getTime() < ef.getTime()) return false;
    }
    if (r.effective_to) {
      const et = parseIsoDate(r.effective_to);
      if (et && refDate.getTime() > et.getTime()) return false;
    }
    if (r.category && r.category !== 'ALL' && r.category !== appRow.category && r.category !== effectiveCatCode) {
      return false;
    }
    return true;
  });

  const ruleMap = new Map<string, ActiveRuleRow>();
  for (const r of activeRules) {
    ruleMap.set(r.rule_code, r);
  }

  const docs = db
    .prepare('SELECT * FROM documents WHERE application_id = ? ORDER BY created_at ASC')
    .all(applicationId) as Array<{
    id: string;
    declared_doc_type: DocumentType;
    detected_doc_type: DocumentType;
    original_filename: string;
    mime_type: string;
    file_size_bytes: number;
    sha256_hash: string;
    ocr_status: string;
    ocr_engine: string;
    ocr_confidence: number | null;
    extracted_text: string;
    metadata_json: string;
    verification_status: string;
  }>;

  const fieldsByDoc = new Map<string, Map<string, { value: string; confidence: number; page: number; bbox: string | null }>>();
  for (const doc of docs) {
    const fRows = db
      .prepare('SELECT field_name, field_value, confidence, page_number, bbox_json FROM extracted_fields WHERE document_id = ?')
      .all(doc.id) as Array<{
      field_name: string;
      field_value: string;
      confidence: number;
      page_number: number;
      bbox_json: string | null;
    }>;
    const fMap = new Map<string, { value: string; confidence: number; page: number; bbox: string | null }>();
    for (const f of fRows) {
      fMap.set(f.field_name, {
        value: f.field_value,
        confidence: f.confidence,
        page: f.page_number,
        bbox: f.bbox_json,
      });
    }
    fieldsByDoc.set(doc.id, fMap);
  }

  // Preserve officer-resolved findings notes on current-cycle findings
  const priorResolved = db
    .prepare(
      `SELECT rule_code, COALESCE(document_id, '') AS doc_key, COALESCE(field_name, '') AS field_key,
              resolved_by_officer, resolution_note, resolved_by, resolved_at
       FROM validation_findings
       WHERE application_id = ? AND resolved_by_officer = 1 AND archived_from_prior_cycle = 0`
    )
    .all(applicationId) as Array<{
    rule_code: string;
    doc_key: string;
    field_key: string;
    resolved_by_officer: number;
    resolution_note: string | null;
    resolved_by: string | null;
    resolved_at: string | null;
  }>;
  const resolvedLookup = new Map<string, (typeof priorResolved)[number]>();
  for (const pr of priorResolved) {
    resolvedLookup.set(`${pr.rule_code}|${pr.doc_key}|${pr.field_key}`, pr);
  }

  // Clear only current-cycle findings; archived prior-cycle findings from resubmissions remain intact
  db.prepare('DELETE FROM validation_findings WHERE application_id = ? AND archived_from_prior_cycle = 0').run(
    applicationId
  );

  interface PendingFinding {
    documentId: string | null;
    fieldName: string | null;
    pageRegion: string | null;
    ruleCode: string;
    ruleVersion: string;
    authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE' | 'INSTITUTIONAL_CROSSCHECK' | 'CRYPTOGRAPHIC_INTEGRITY';
    findingCategory: FindingCategory;
    epistemicClassification: EpistemicClassification;
    detectorConfidence: number | null;
    limitationsNote: string | null;
    recommendedFollowUp: string | null;
    severity: SeverityLevel;
    expectedValue: string | null;
    observedValue: string | null;
    explanation: string;
    evidence: Record<string, unknown>;
  }

  const generatedFindings: PendingFinding[] = [];

  const getRuleMeta = (
    code: string,
    fallbackSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    fallbackSource: PendingFinding['authoritySource']
  ) => {
    const r = ruleMap.get(code);
    let parsedConfig: Record<string, unknown> = {};
    if (r?.config_json) {
      try {
        parsedConfig = JSON.parse(r.config_json) as Record<string, unknown>;
      } catch {
        parsedConfig = {};
      }
    }
    return {
      active: totalConfiguredRules === 0 ? true : Boolean(r),
      code,
      version: r?.version || '1.0.0',
      severity: (r?.severity || fallbackSeverity) as SeverityLevel,
      authoritySource: r?.authority_source || fallbackSource,
      recommendedAction: r?.recommended_action || null,
      config: parsedConfig,
    };
  };

  // 1. RULE-REQ-DOCS: Mandatory Documents Check by Category
  const reqDocsMeta = getRuleMeta('RULE-REQ-DOCS', 'HIGH', 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE');
  const requiredDocTypes = resolveRequiredChecklistForApplication(db, appRow.category, effectiveCatCode);
  const presentDocTypes = new Set(docs.map((d) => d.declared_doc_type));

  let missingMandatoryCount = 0;
  if (reqDocsMeta.active) {
    for (const reqType of requiredDocTypes) {
      if (!presentDocTypes.has(reqType)) {
        missingMandatoryCount++;
        generatedFindings.push({
          documentId: null,
          fieldName: 'mandatory_document',
          pageRegion: null,
          ruleCode: reqDocsMeta.code,
          ruleVersion: reqDocsMeta.version,
          authoritySource: reqDocsMeta.authoritySource,
          findingCategory: 'RULE_VALIDATION',
          epistemicClassification: 'MISSING_INFORMATION',
          detectorConfidence: 1.0,
          limitationsNote: 'Evaluated against configured category document checklist (illustrative statutory configuration).',
          recommendedFollowUp:
            reqDocsMeta.recommendedAction ||
            `Request institution to upload '${reqType}' or record an authorised exemption rationale.`,
          severity: reqDocsMeta.severity,
          expectedValue: `${reqType} uploaded`,
          observedValue: 'Document not uploaded',
          explanation: `Required checklist document '${reqType}' for category '${effectiveCatCode}' is missing from the application package (configurable checklist rule).`,
          evidence: { category: effectiveCatCode, missingDocType: reqType },
        });
      }
    }
  }

  // Latest adverse source verifications per document
  const sourceVerifs = db
    .prepare(
      `SELECT id, document_id, status, is_sandbox_demo, verification_method, issuer_name, reference_number, error_reason
       FROM source_verifications
       WHERE application_id = ?
       ORDER BY attempted_at DESC`
    )
    .all(applicationId) as Array<{
    id: string;
    document_id: string | null;
    status: string;
    is_sandbox_demo: number;
    verification_method: string;
    issuer_name: string;
    reference_number: string | null;
    error_reason: string | null;
  }>;

  const latestMismatchByDoc = new Map<string, (typeof sourceVerifs)[number]>();
  for (const sv of sourceVerifs) {
    if (sv.document_id && sv.status === 'MISMATCH_DETECTED' && !latestMismatchByDoc.has(sv.document_id)) {
      latestMismatchByDoc.set(sv.document_id, sv);
    }
  }

  // 2. Per-document checks
  for (const doc of docs) {
    const fMap = fieldsByDoc.get(doc.id) || new Map();
    const isFacilityPhoto = FACILITY_PHOTO_DOC_TYPES.has(doc.declared_doc_type);

    // 2a. OCR Status & Confidence Check (skip pure facility photographs which are inspected visually)
    const ocrMeta = getRuleMeta('RULE-OCR-QUALITY', 'MEDIUM', 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE');
    const minConfidence = typeof ocrMeta.config.minConfidence === 'number' ? ocrMeta.config.minConfidence : 0.75;

    if (ocrMeta.active && !isFacilityPhoto) {
      if (doc.ocr_status === 'UNAVAILABLE' || doc.ocr_status === 'FAILED') {
        generatedFindings.push({
          documentId: doc.id,
          fieldName: 'ocr_extraction',
          pageRegion: 'Page 1',
          ruleCode: ocrMeta.code,
          ruleVersion: ocrMeta.version,
          authoritySource: ocrMeta.authoritySource,
          findingCategory: 'OCR_QUALITY',
          epistemicClassification: 'TECHNICAL_PROCESSING_FAILURE',
          detectorConfidence: null,
          limitationsNote:
            'Technical OCR pipeline limitation — NOT evidence of document invalidity or tampering.',
          recommendedFollowUp:
            'Inspect the original document visually in the Document Viewer, retry OCR if service was unreachable, or record manual verification.',
          severity: 'HIGH',
          expectedValue: 'Readable text extraction (>= 0.75 confidence)',
          observedValue: `OCR ${doc.ocr_status} via ${doc.ocr_engine}`,
          explanation: `Automated text extraction could not complete (${doc.ocr_status}). Document is NOT rejected; visual human review by an authorised officer is required.`,
          evidence: { ocrStatus: doc.ocr_status, ocrEngine: doc.ocr_engine, filename: doc.original_filename },
        });
      } else if (doc.ocr_status === 'LOW_CONFIDENCE' || (doc.ocr_confidence !== null && doc.ocr_confidence < minConfidence)) {
        generatedFindings.push({
          documentId: doc.id,
          fieldName: 'ocr_confidence',
          pageRegion: 'Page 1',
          ruleCode: ocrMeta.code,
          ruleVersion: ocrMeta.version,
          authoritySource: ocrMeta.authoritySource,
          findingCategory: 'OCR_QUALITY',
          epistemicClassification: 'TECHNICAL_PROCESSING_FAILURE',
          detectorConfidence: doc.ocr_confidence ?? 0.5,
          limitationsNote:
            'Low scan contrast, stamp overlap, or bilingual glyph noise reduced OCR certainty.',
          recommendedFollowUp:
            'Cross-check extracted fields against the original scan and apply Officer Field Correction where needed.',
          severity: 'MEDIUM',
          expectedValue: `OCR confidence >= ${minConfidence}`,
          observedValue: `OCR confidence ${doc.ocr_confidence ?? 0}`,
          explanation: `Low OCR extraction confidence (${((doc.ocr_confidence ?? 0) * 100).toFixed(0)}%) on '${doc.original_filename}'. Officer must inspect the original scan to verify extracted fields.`,
          evidence: { ocrConfidence: doc.ocr_confidence, threshold: minConfidence, ocrEngine: doc.ocr_engine },
        });
      }
    }

    // 2b. Document Type Consistency
    const dtMeta = getRuleMeta('RULE-DOC-TYPE-MATCH', 'HIGH', 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE');
    if (
      dtMeta.active &&
      doc.ocr_status === 'COMPLETED' &&
      doc.detected_doc_type !== 'UNKNOWN_DOCUMENT' &&
      doc.detected_doc_type !== doc.declared_doc_type
    ) {
      generatedFindings.push({
        documentId: doc.id,
        fieldName: 'declared_doc_type',
        pageRegion: 'Page 1',
        ruleCode: dtMeta.code,
        ruleVersion: dtMeta.version,
        authoritySource: dtMeta.authoritySource,
        findingCategory: 'RULE_VALIDATION',
        epistemicClassification: 'ORDINARY_INCONSISTENCY',
        detectorConfidence: 0.9,
        limitationsNote: 'Keyword-based document classifier compares extracted headings against declared upload slot.',
        recommendedFollowUp:
          'Verify whether the applicant uploaded the wrong file into this checklist slot and request rectification if misfiled.',
        severity: dtMeta.severity,
        expectedValue: doc.declared_doc_type,
        observedValue: doc.detected_doc_type,
        explanation: `Document was uploaded under slot '${doc.declared_doc_type}', but extracted text matches '${doc.detected_doc_type}'.`,
        evidence: { declared: doc.declared_doc_type, detected: doc.detected_doc_type },
      });
    }

    // 2b-ii. Confirmed Source Mismatch (when latest status on document is MISMATCH_DETECTED via source check)
    const mismatchSv = latestMismatchByDoc.get(doc.id);
    if (doc.verification_status === 'MISMATCH_DETECTED' && mismatchSv) {
      generatedFindings.push({
        documentId: doc.id,
        fieldName: 'source_verification_status',
        pageRegion: 'Document Certificate Record',
        ruleCode: 'RULE-SOURCE-MISMATCH',
        ruleVersion: '1.0.0',
        authoritySource: 'INSTITUTIONAL_CROSSCHECK',
        findingCategory: 'RULE_VALIDATION',
        epistemicClassification: 'CONFIRMED_SOURCE_MISMATCH',
        detectorConfidence: 0.98,
        limitationsNote: mismatchSv.is_sandbox_demo
          ? 'Mismatch reported against deterministic Sandbox Issuer Registry fixture (not a live government portal).'
          : 'Mismatch recorded via direct officer/cryptographic source check.',
        recommendedFollowUp:
          'Issue formal clarification notice or scrutinize original physical dispatch record before final decision.',
        severity: 'CRITICAL',
        expectedValue: `Authentic record matching ${mismatchSv.issuer_name}`,
        observedValue: mismatchSv.error_reason || 'MISMATCH_DETECTED',
        explanation: `Source verification (${mismatchSv.verification_method}${mismatchSv.is_sandbox_demo ? ' — Sandbox' : ''}) reported MISMATCH_DETECTED for '${doc.original_filename}': ${mismatchSv.error_reason || 'Issuer attributes conflict with submitted document.'}`,
        evidence: {
          sourceVerificationId: mismatchSv.id,
          method: mismatchSv.verification_method,
          issuerName: mismatchSv.issuer_name,
          referenceNumber: mismatchSv.reference_number,
          isSandboxDemo: Boolean(mismatchSv.is_sandbox_demo),
        },
      });
    }

    // Only run text-dependent field rules when text was actually extracted
    if (doc.extracted_text.trim().length > 0 && !isFacilityPhoto) {
      // 2c. Required Fields per Document Type
      const reqFieldsMeta = getRuleMeta('RULE-REQ-FIELDS', 'MEDIUM', 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE');
      if (reqFieldsMeta.active) {
        const requiredFieldsByDoc: Record<string, string[]> = {
          FIRE_SAFETY_CERTIFICATE: ['certificate_number', 'institution_name', 'issue_date', 'expiry_date'],
          LAND_USE_CERTIFICATE: ['certificate_number', 'institution_name', 'issue_date', 'land_area_acres'],
          AFFIDAVIT_INTAKE: ['certificate_number', 'institution_name', 'approved_intake', 'principal_name'],
          BUILDING_PLAN_APPROVAL: ['certificate_number', 'institution_name', 'built_up_area_sqm'],
          FLOOR_PLAN_DRAWING: ['certificate_number', 'institution_name', 'built_up_area_sqm'],
          FACULTY_ROSTER_STATEMENT: ['certificate_number', 'institution_name', 'total_faculty_count'],
          AICTE_FEE_RECEIPT: ['certificate_number', 'institution_name', 'issue_date'],
          NOC_AFFILIATING_UNIVERSITY: ['certificate_number', 'institution_name', 'issue_date'],
        };
        const expectedFields = requiredFieldsByDoc[doc.declared_doc_type] || ['certificate_number', 'institution_name'];
        for (const reqField of expectedFields) {
          if (!fMap.has(reqField)) {
            generatedFindings.push({
              documentId: doc.id,
              fieldName: reqField,
              pageRegion: 'Page 1',
              ruleCode: reqFieldsMeta.code,
              ruleVersion: reqFieldsMeta.version,
              authoritySource: reqFieldsMeta.authoritySource,
              findingCategory: 'RULE_VALIDATION',
              epistemicClassification: 'MISSING_INFORMATION',
              detectorConfidence: 0.88,
              limitationsNote:
                'Anchor-based regex extraction may miss non-standard tabular layouts; inspect document visually.',
              recommendedFollowUp:
                `Verify whether '${reqField}' appears on '${doc.original_filename}' and either enter it or request a complete certificate.`,
              severity: reqFieldsMeta.severity,
              expectedValue: `Non-empty ${reqField}`,
              observedValue: 'Missing / Not extracted',
              explanation: `Mandatory field '${reqField}' could not be located in '${doc.original_filename}'.`,
              evidence: { docType: doc.declared_doc_type, missingField: reqField },
            });
          }
        }
      }

      // 2d. Expiry & Chronology Validation
      const issueField = fMap.get('issue_date');
      const expiryField = fMap.get('expiry_date');
      const expiryMeta = getRuleMeta('RULE-DOC-EXPIRY', 'CRITICAL', 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE');
      const graceDays =
        typeof expiryMeta.config.gracePeriodDays === 'number' ? expiryMeta.config.gracePeriodDays : 0;

      if (expiryMeta.active) {
        if (issueField && !parseIsoDate(issueField.value)) {
          generatedFindings.push({
            documentId: doc.id,
            fieldName: 'issue_date',
            pageRegion: `Page ${issueField.page}`,
            ruleCode: expiryMeta.code,
            ruleVersion: expiryMeta.version,
            authoritySource: expiryMeta.authoritySource,
            findingCategory: 'RULE_VALIDATION',
            epistemicClassification: 'ORDINARY_INCONSISTENCY',
            detectorConfidence: issueField.confidence,
            limitationsNote: 'Calendar parser checks normalized ISO date validity.',
            recommendedFollowUp: 'Inspect certificate issue date on original scan and correct OCR read error if applicable.',
            severity: 'HIGH',
            expectedValue: 'Valid calendar date (YYYY-MM-DD)',
            observedValue: issueField.value,
            explanation: `Extracted issue_date '${issueField.value}' is not a valid calendar date.`,
            evidence: { bbox: issueField.bbox },
          });
        }

        if (expiryField) {
          const expDate = parseIsoDate(expiryField.value);
          const issDate = issueField ? parseIsoDate(issueField.value) : null;
          if (!expDate) {
            generatedFindings.push({
              documentId: doc.id,
              fieldName: 'expiry_date',
              pageRegion: `Page ${expiryField.page}`,
              ruleCode: expiryMeta.code,
              ruleVersion: expiryMeta.version,
              authoritySource: expiryMeta.authoritySource,
              findingCategory: 'RULE_VALIDATION',
              epistemicClassification: 'ORDINARY_INCONSISTENCY',
              detectorConfidence: expiryField.confidence,
              limitationsNote: 'Calendar parser checks normalized ISO date validity.',
              recommendedFollowUp: 'Inspect certificate expiry date on original scan and correct if misread.',
              severity: 'HIGH',
              expectedValue: 'Valid calendar date (YYYY-MM-DD)',
              observedValue: expiryField.value,
              explanation: `Extracted expiry_date '${expiryField.value}' is invalid.`,
              evidence: { bbox: expiryField.bbox },
            });
          } else {
            const effectiveCutoffMs = refDate.getTime() - graceDays * 86_400_000;
            if (issDate && expDate.getTime() < issDate.getTime()) {
              generatedFindings.push({
                documentId: doc.id,
                fieldName: 'expiry_date',
                pageRegion: `Page ${expiryField.page}`,
                ruleCode: expiryMeta.code,
                ruleVersion: expiryMeta.version,
                authoritySource: expiryMeta.authoritySource,
                findingCategory: 'ANOMALY_INDICATOR',
                epistemicClassification: 'SUSPECTED_ANOMALY',
                detectorConfidence: Math.min(expiryField.confidence, issueField?.confidence ?? 0.9),
                limitationsNote:
                  'Chronological contradiction may arise from clerical typo, OCR misread, or altered date field — not standalone proof of forgery.',
                recommendedFollowUp:
                  'Inspect original scan dates and verify certificate serial directly with issuing authority.',
                severity: 'CRITICAL',
                expectedValue: `Expiry date after issue date (${issueField?.value})`,
                observedValue: expiryField.value,
                explanation: `Impossible chronology: certificate expiry date (${expiryField.value}) precedes its issue date (${issueField?.value}).`,
                evidence: { issueDate: issueField?.value, expiryDate: expiryField.value },
              });
            } else if (expDate.getTime() < effectiveCutoffMs) {
              generatedFindings.push({
                documentId: doc.id,
                fieldName: 'expiry_date',
                pageRegion: `Page ${expiryField.page}`,
                ruleCode: expiryMeta.code,
                ruleVersion: expiryMeta.version,
                authoritySource: expiryMeta.authoritySource,
                findingCategory: 'RULE_VALIDATION',
                epistemicClassification: 'ORDINARY_INCONSISTENCY',
                detectorConfidence: expiryField.confidence,
                limitationsNote: `Evaluated against scrutiny reference date ${referenceDateStr} (gracePeriodDays=${graceDays}).`,
                recommendedFollowUp:
                  'Request renewed statutory certificate from institution or verify official renewal corrigendum.',
                severity: expiryMeta.severity,
                expectedValue: `Valid on or after ${referenceDateStr}`,
                observedValue: expiryField.value,
                explanation: `Document '${doc.original_filename}' expired on ${expiryField.value} (prior to scrutiny reference date ${referenceDateStr}).`,
                evidence: { expiryDate: expiryField.value, referenceDate: referenceDateStr, bbox: expiryField.bbox },
              });
              if (doc.verification_status === 'UNVERIFIED') {
                db.prepare('UPDATE documents SET verification_status = ? WHERE id = ?').run('EXPIRED', doc.id);
              }
            }
          }
        }
      }

      // 2e. Institution Name Cross-Check
      const instMeta = getRuleMeta('RULE-INST-CROSSCHECK', 'HIGH', 'INSTITUTIONAL_CROSSCHECK');
      const minSim = typeof instMeta.config.minTokenSimilarity === 'number' ? instMeta.config.minTokenSimilarity : 0.5;
      const instNameField = fMap.get('institution_name');
      if (instMeta.active && instNameField) {
        const sim = jaccardSimilarity(instNameField.value, appRow.inst_name);
        if (sim < minSim) {
          generatedFindings.push({
            documentId: doc.id,
            fieldName: 'institution_name',
            pageRegion: `Page ${instNameField.page}`,
            ruleCode: instMeta.code,
            ruleVersion: instMeta.version,
            authoritySource: instMeta.authoritySource,
            findingCategory: 'RULE_VALIDATION',
            epistemicClassification: 'ORDINARY_INCONSISTENCY',
            detectorConfidence: instNameField.confidence,
            limitationsNote:
              'Token similarity check may flag legitimate society/trust name variations or historical campus renamings.',
            recommendedFollowUp:
              'Verify sponsoring trust/society name change notification or confirm whether another institution’s document was attached.',
            severity: instMeta.severity,
            expectedValue: appRow.inst_name,
            observedValue: instNameField.value,
            explanation: `Institution name on '${doc.original_filename}' ('${instNameField.value}') diverges from institutional master record ('${appRow.inst_name}').`,
            evidence: { tokenSimilarity: Number(sim.toFixed(2)), bbox: instNameField.bbox },
          });
        }
      }

      // 2f. Intake Capacity & Land Cross-Check
      const intMeta = getRuleMeta('RULE-INTAKE-MATCH', 'HIGH', 'INSTITUTIONAL_CROSSCHECK');
      const intakeField = fMap.get('approved_intake');
      if (intMeta.active && intakeField) {
        const docIntake = Number.parseInt(intakeField.value, 10);
        if (Number.isFinite(docIntake) && docIntake !== appRow.requested_intake) {
          generatedFindings.push({
            documentId: doc.id,
            fieldName: 'approved_intake',
            pageRegion: `Page ${intakeField.page}`,
            ruleCode: intMeta.code,
            ruleVersion: intMeta.version,
            authoritySource: intMeta.authoritySource,
            findingCategory: 'RULE_VALIDATION',
            epistemicClassification: 'ORDINARY_INCONSISTENCY',
            detectorConfidence: intakeField.confidence,
            limitationsNote: 'Compares sworn intake figure on document against application form requestedIntake.',
            recommendedFollowUp:
              'Request updated notarized intake affidavit matching the requested seat intake or clarify division-level breakdown.',
            severity: intMeta.severity,
            expectedValue: `${appRow.requested_intake} seats (application form)`,
            observedValue: `${docIntake} seats (document)`,
            explanation: `Intake figure in '${doc.original_filename}' (${docIntake}) does not match application requested intake (${appRow.requested_intake}).`,
            evidence: {
              requestedIntake: appRow.requested_intake,
              institutionalApprovedIntake: appRow.inst_intake,
              documentIntake: docIntake,
              bbox: intakeField.bbox,
            },
          });
        }
      }

      const landField = fMap.get('land_area_acres');
      if (instMeta.active && landField) {
        const docLand = Number.parseFloat(landField.value);
        if (Number.isFinite(docLand) && Math.abs(docLand - appRow.submitted_land_acres) > 0.05) {
          generatedFindings.push({
            documentId: doc.id,
            fieldName: 'land_area_acres',
            pageRegion: `Page ${landField.page}`,
            ruleCode: instMeta.code,
            ruleVersion: instMeta.version,
            authoritySource: instMeta.authoritySource,
            findingCategory: 'RULE_VALIDATION',
            epistemicClassification: 'ORDINARY_INCONSISTENCY',
            detectorConfidence: landField.confidence,
            limitationsNote: 'Compares extracted land acreage against submitted application acreage.',
            recommendedFollowUp: 'Verify contiguous land revenue khasra/patta deeds and survey demarcation.',
            severity: 'HIGH',
            expectedValue: `${appRow.submitted_land_acres} acres`,
            observedValue: `${docLand} acres`,
            explanation: `Land area in '${doc.original_filename}' (${docLand} acres) differs from submitted application land area (${appRow.submitted_land_acres} acres).`,
            evidence: { masterRecordLandAcres: appRow.inst_land, documentLandAcres: docLand },
          });
        }
      }

      // 2g. Duplicate Certificate Number across different applications
      const dupIdMeta = getRuleMeta('RULE-DUP-IDENTIFIER', 'CRITICAL', 'CRYPTOGRAPHIC_INTEGRITY');
      const certField = fMap.get('certificate_number');
      if (dupIdMeta.active && certField) {
        const otherCertRow = db
          .prepare(
            `SELECT d.id AS doc_id, d.original_filename, a.application_number
             FROM extracted_fields ef
             JOIN documents d ON d.id = ef.document_id
             JOIN applications a ON a.id = d.application_id
             WHERE ef.field_name = 'certificate_number'
               AND ef.field_value = ?
               AND d.application_id != ?
             LIMIT 1`
          )
          .get(certField.value, applicationId) as
          | { doc_id: string; original_filename: string; application_number: string }
          | undefined;

        if (otherCertRow) {
          generatedFindings.push({
            documentId: doc.id,
            fieldName: 'certificate_number',
            pageRegion: `Page ${certField.page}`,
            ruleCode: dupIdMeta.code,
            ruleVersion: dupIdMeta.version,
            authoritySource: dupIdMeta.authoritySource,
            findingCategory: 'DUPLICATE_CHECK',
            epistemicClassification: 'SUSPECTED_ANOMALY',
            detectorConfidence: certField.confidence,
            limitationsNote:
              'Cross-application reference collision may reflect multi-programme campus sharing or unauthorized reuse of another institution’s certificate.',
            recommendedFollowUp:
              `Compare against application ${otherCertRow.application_number} and verify issuer beneficiary name.`,
            severity: dupIdMeta.severity,
            expectedValue: 'Unique certificate identifier per institutional filing',
            observedValue: `${certField.value} (also in ${otherCertRow.application_number})`,
            explanation: `Certificate identifier '${certField.value}' also appears on application ${otherCertRow.application_number} (${otherCertRow.original_filename}). Requires cross-application officer check.`,
            evidence: {
              certificateNumber: certField.value,
              conflictingApplicationNumber: otherCertRow.application_number,
              conflictingDocumentId: otherCertRow.doc_id,
            },
          });
        }
      }

      // 2h. Custom Admin-Configured Rules (NUMERIC_MINIMUM & custom FIELD_PRESENCE)
      for (const customRule of activeRules) {
        if (customRule.doc_type && customRule.doc_type !== doc.declared_doc_type) {
          continue;
        }
        let customCfg: Record<string, unknown> = {};
        try {
          customCfg = JSON.parse(customRule.config_json) as Record<string, unknown>;
        } catch {
          continue;
        }

        if (customRule.rule_type === 'NUMERIC_MINIMUM') {
          const targetField = typeof customCfg.fieldName === 'string' ? customCfg.fieldName.trim() : '';
          const minVal = typeof customCfg.minValue === 'number' ? customCfg.minValue : Number.NaN;
          if (!targetField || !Number.isFinite(minVal)) continue;

          const extracted = fMap.get(targetField);
          if (extracted) {
            const numericVal = Number.parseFloat(extracted.value);
            if (Number.isFinite(numericVal) && numericVal < minVal) {
              generatedFindings.push({
                documentId: doc.id,
                fieldName: targetField,
                pageRegion: `Page ${extracted.page}`,
                ruleCode: customRule.rule_code,
                ruleVersion: customRule.version,
                authoritySource: customRule.authority_source,
                findingCategory: 'RULE_VALIDATION',
                epistemicClassification: 'ORDINARY_INCONSISTENCY',
                detectorConfidence: extracted.confidence,
                limitationsNote: 'Evaluated via administrator-configured NUMERIC_MINIMUM regulatory rule.',
                recommendedFollowUp:
                  customRule.recommended_action ||
                  `Verify '${targetField}' (${numericVal}) against applicable handbook threshold (${minVal}).`,
                severity: customRule.severity,
                expectedValue: `>= ${minVal}`,
                observedValue: String(numericVal),
                explanation: `${customRule.name}: extracted '${targetField}' (${numericVal}) in '${doc.original_filename}' is below configured minimum (${minVal}).`,
                evidence: { fieldName: targetField, observed: numericVal, minValue: minVal },
              });
            }
          }
        } else if (customRule.rule_type === 'FIELD_PRESENCE' && customRule.rule_code !== 'RULE-REQ-FIELDS') {
          let reqList: string[] = [];
          if (Array.isArray(customCfg.requiredFields)) {
            reqList = customCfg.requiredFields.filter((x): x is string => typeof x === 'string' && x.trim().length > 0);
          } else if (customRule.expected_fields_json) {
            try {
              const ef = JSON.parse(customRule.expected_fields_json) as unknown[];
              if (Array.isArray(ef)) {
                reqList = ef.filter((x): x is string => typeof x === 'string' && x.trim().length > 0);
              }
            } catch {
              reqList = [];
            }
          }
          for (const rf of reqList) {
            if (!fMap.has(rf)) {
              generatedFindings.push({
                documentId: doc.id,
                fieldName: rf,
                pageRegion: 'Page 1',
                ruleCode: customRule.rule_code,
                ruleVersion: customRule.version,
                authoritySource: customRule.authority_source,
                findingCategory: 'RULE_VALIDATION',
                epistemicClassification: 'MISSING_INFORMATION',
                detectorConfidence: 0.85,
                limitationsNote: 'Evaluated via administrator-configured FIELD_PRESENCE regulatory rule.',
                recommendedFollowUp:
                  customRule.recommended_action || `Confirm presence of '${rf}' on '${doc.original_filename}'.`,
                severity: customRule.severity,
                expectedValue: `Non-empty ${rf}`,
                observedValue: 'Missing / Not extracted',
                explanation: `${customRule.name}: required field '${rf}' was not found in '${doc.original_filename}'.`,
                evidence: { ruleCode: customRule.rule_code, missingField: rf },
              });
            }
          }
        }
      }
    }

    // 3. Exact Cryptographic SHA-256 Duplicate File Check
    const hashMeta = getRuleMeta('RULE-SHA256-DUPLICATE', 'CRITICAL', 'CRYPTOGRAPHIC_INTEGRITY');
    if (hashMeta.active) {
      const dupHashRows = db
        .prepare(
          `SELECT d.id, d.original_filename, d.application_id, a.application_number
           FROM documents d
           JOIN applications a ON a.id = d.application_id
           WHERE d.sha256_hash = ? AND d.id != ?`
        )
        .all(doc.sha256_hash, doc.id) as Array<{
        id: string;
        original_filename: string;
        application_id: string;
        application_number: string;
      }>;

      if (dupHashRows.length > 0) {
        const otherRefs = dupHashRows.map((r) => `${r.application_number}/${r.original_filename}`).join(', ');
        generatedFindings.push({
          documentId: doc.id,
          fieldName: 'sha256_hash',
          pageRegion: 'Entire File',
          ruleCode: hashMeta.code,
          ruleVersion: hashMeta.version,
          authoritySource: hashMeta.authoritySource,
          findingCategory: 'DUPLICATE_CHECK',
          epistemicClassification: 'SUSPECTED_ANOMALY',
          detectorConfidence: 1.0,
          limitationsNote:
            'Cryptographic SHA-256 match proves byte-identical file reuse; officer must determine whether reuse was accidental duplicate upload or cross-institution misrepresentation.',
          recommendedFollowUp:
            `Inspect matching filing(s) (${otherRefs}) and verify beneficiary institution on the certificate.`,
          severity: hashMeta.severity,
          expectedValue: 'Distinct document byte stream',
          observedValue: `SHA-256 ${doc.sha256_hash.slice(0, 16)}... duplicated in ${otherRefs}`,
          explanation: `Exact byte-for-byte SHA-256 hash collision detected with ${otherRefs}. Indicator of duplicate upload or reused certificate file.`,
          evidence: {
            sha256Hash: doc.sha256_hash,
            matchingDocuments: dupHashRows,
          },
        });
      }
    }

    // 4. Forensic / Metadata Tampering Indicators stored on document metadata
    let parsedMeta: {
      forensicIndicators?: ForensicIndicator[];
      Producer?: string;
      ModDate?: string;
      CreationDate?: string;
    } = {};
    try {
      parsedMeta = JSON.parse(doc.metadata_json) as typeof parsedMeta;
    } catch {
      parsedMeta = {};
    }
    const indicators = parsedMeta.forensicIndicators || [];
    for (const ind of indicators) {
      generatedFindings.push({
        documentId: doc.id,
        fieldName: ind.code.toLowerCase(),
        pageRegion: 'Document Container Metadata',
        ruleCode: `ANOMALY-${ind.code}`,
        ruleVersion: '1.0.0',
        authoritySource: 'CRYPTOGRAPHIC_INTEGRITY',
        findingCategory: 'ANOMALY_INDICATOR',
        epistemicClassification: 'SUSPECTED_ANOMALY',
        detectorConfidence: ind.severity === 'HIGH' ? 0.78 : 0.62,
        limitationsNote:
          'Heuristic container/compression indicator ONLY — legitimate scan compression, PDF merging, or institutional stationery tools can trigger metadata flags. NEVER treat as standalone proof of forgery.',
        recommendedFollowUp:
          'Verify certificate authenticity directly against the issuing authority or physical certified copy.',
        severity: ind.severity,
        expectedValue: 'Direct issuer generation without post-creation graphics editing markers',
        observedValue: ind.code,
        explanation: ind.description,
        evidence: {
          indicatorCode: ind.code,
          producer: parsedMeta.Producer ?? null,
          creationDate: parsedMeta.CreationDate ?? null,
          modDate: parsedMeta.ModDate ?? null,
        },
      });
    }
  }

  // 5. Configurable Infrastructure Norm Check (Illustrative Example Rule + custom RATIO_THRESHOLD rules)
  for (const ratioRule of activeRules.filter((r) => r.rule_type === 'RATIO_THRESHOLD')) {
    let cfg: Record<string, unknown> = {};
    try {
      cfg = JSON.parse(ratioRule.config_json) as Record<string, unknown>;
    } catch {
      cfg = {};
    }
    const minSqmPerStudent =
      typeof cfg.minBuiltUpSqmPerStudent === 'number' ? cfg.minBuiltUpSqmPerStudent : 4.5;
    const requiredSqm = Math.round(appRow.requested_intake * minSqmPerStudent);
    if (appRow.submitted_built_up_sqm < requiredSqm) {
      generatedFindings.push({
        documentId: null,
        fieldName: 'submitted_built_up_sqm',
        pageRegion: null,
        ruleCode: ratioRule.rule_code,
        ruleVersion: ratioRule.version,
        authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE',
        findingCategory: 'RULE_VALIDATION',
        epistemicClassification: 'ORDINARY_INCONSISTENCY',
        detectorConfidence: 1.0,
        limitationsNote:
          'Illustrative configurable area-per-student threshold — verify applicable programme/location norms in the official AICTE Approval Process Handbook.',
        recommendedFollowUp:
          ratioRule.recommended_action ||
          'Verify sanctioned instructional + circulation built-up area on approved architectural drawings or flag for EVC physical inspection.',
        severity: ratioRule.severity,
        expectedValue: `>= ${requiredSqm} sqm (${minSqmPerStudent} sqm/student configurable norm)`,
        observedValue: `${appRow.submitted_built_up_sqm} sqm`,
        explanation: `Submitted built-up area (${appRow.submitted_built_up_sqm} sqm) is below the configurable demonstration threshold of ${requiredSqm} sqm for ${appRow.requested_intake} seats. (Configurable example rule — requires officer handbook verification.)`,
        evidence: {
          requestedIntake: appRow.requested_intake,
          minSqmPerStudent,
          submittedBuiltUpSqm: appRow.submitted_built_up_sqm,
        },
      });
    }
  }

  // Persist all generated findings for current submission cycle
  const nowIso = new Date().toISOString();
  const insertStmt = db.prepare(
    `INSERT INTO validation_findings (
      id, finding_code, application_id, document_id, field_name, page_region,
      rule_code, rule_version, authority_source, finding_category,
      epistemic_classification, detector_confidence, limitations_note, recommended_follow_up,
      submission_cycle, archived_from_prior_cycle,
      severity, expected_value, observed_value, explanation, evidence_json,
      requires_human_review, resolved_by_officer, resolution_note, resolved_by, resolved_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  let idx = 1;
  let unresolvedFindingsCount = 0;
  let criticalOrHighUnresolved = 0;
  const unresolvedDocIds = new Set<string>();

  for (const f of generatedFindings) {
    const id = `FND-${crypto.randomUUID()}`;
    const findingCode = `F-${String(idx++).padStart(3, '0')}`;
    const priorKey = `${f.ruleCode}|${f.documentId || ''}|${f.fieldName || ''}`;
    const prior = resolvedLookup.get(priorKey);
    const isResolved = prior ? 1 : 0;

    if (!isResolved) {
      unresolvedFindingsCount++;
      if (f.documentId) unresolvedDocIds.add(f.documentId);
      if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
        criticalOrHighUnresolved++;
      }
    }

    insertStmt.run(
      id,
      findingCode,
      applicationId,
      f.documentId,
      f.fieldName,
      f.pageRegion,
      f.ruleCode,
      f.ruleVersion,
      f.authoritySource,
      f.findingCategory,
      f.epistemicClassification,
      f.detectorConfidence,
      f.limitationsNote,
      f.recommendedFollowUp,
      currentCycle,
      f.severity,
      f.expectedValue,
      f.observedValue,
      f.explanation,
      JSON.stringify(f.evidence),
      1,
      isResolved,
      prior?.resolution_note ?? null,
      prior?.resolved_by ?? null,
      prior?.resolved_at ?? null,
      nowIso
    );
  }

  // 5b. Synchronize Regulatory & Infrastructure Compliance Items (without overwriting officer-reviewed decisions)
  const reqRows = db
    .prepare(
      `SELECT * FROM compliance_requirements
       WHERE category = 'ALL' OR category = ? OR category = ?
       ORDER BY id ASC`
    )
    .all(appRow.category, effectiveCatCode) as Array<{
    id: string;
    requirement_code: string;
    category: string;
    domain: ComplianceDomain;
    title: string;
    description: string;
    accepted_doc_types_json: string;
    is_mandatory: number;
    is_illustrative: number;
  }>;

  const existingCompItems = db
    .prepare('SELECT * FROM application_compliance_items WHERE application_id = ?')
    .all(applicationId) as Array<{
    id: string;
    requirement_id: string;
    reviewed_by: string | null;
    compliance_status: ComplianceItemStatus;
  }>;
  const existingByReq = new Map(existingCompItems.map((c) => [c.requirement_id, c]));

  for (const req of reqRows) {
    let acceptedTypes: DocumentType[] = [];
    try {
      acceptedTypes = JSON.parse(req.accepted_doc_types_json) as DocumentType[];
    } catch {
      acceptedTypes = [];
    }

    const matchedDoc = docs.find(
      (d) => acceptedTypes.includes(d.declared_doc_type) || acceptedTypes.includes(d.detected_doc_type)
    );

    let parsedDocMeta: Record<string, unknown> = {};
    if (matchedDoc) {
      try {
        parsedDocMeta = JSON.parse(matchedDoc.metadata_json) as Record<string, unknown>;
      } catch {
        parsedDocMeta = {};
      }
    }

    const visualSummary = matchedDoc
      ? inspectVisualEvidenceFromMetadata(matchedDoc.mime_type, matchedDoc.file_size_bytes, parsedDocMeta)
      : {};

    let autoStatus: ComplianceItemStatus = 'MANUAL_REVIEW_REQUIRED';
    let autoNote = '';

    if (!matchedDoc) {
      const mandatoryByChecklist = acceptedTypes.some((t) => requiredDocTypes.includes(t)) || Boolean(req.is_mandatory);
      if (mandatoryByChecklist) {
        autoStatus = 'INSUFFICIENT_EVIDENCE';
        autoNote = `Required supporting evidence (${acceptedTypes.join(' / ')}) has not been uploaded.`;
      } else {
        autoStatus = 'MANUAL_REVIEW_REQUIRED';
        autoNote = 'Supplementary visual/roster evidence not attached; officer may waive or request if warranted.';
      }
    } else if (
      FACILITY_PHOTO_DOC_TYPES.has(matchedDoc.declared_doc_type) ||
      matchedDoc.mime_type.toLowerCase().startsWith('image/')
    ) {
      autoStatus = 'MANUAL_REVIEW_REQUIRED';
      const dimLabel =
        visualSummary.width && visualSummary.height
          ? `${visualSummary.width}x${visualSummary.height}px (${visualSummary.legibilityFlag})`
          : matchedDoc.mime_type;
      autoNote = `Image evidence '${matchedDoc.original_filename}' [${dimLabel}] linked. Requires human officer visual inspection or physical EVC check — uploaded photos never establish physical room dimensions or operational status.`;
    } else if (
      unresolvedDocIds.has(matchedDoc.id) ||
      matchedDoc.verification_status === 'MISMATCH_DETECTED' ||
      matchedDoc.verification_status === 'EXPIRED'
    ) {
      autoStatus = 'NOT_SATISFIED';
      autoNote = `Linked document '${matchedDoc.original_filename}' has open compliance, expiry, or source mismatch findings.`;
    } else if (matchedDoc.verification_status === 'VERIFIED') {
      autoStatus = 'SATISFIED';
      autoNote = `Linked document '${matchedDoc.original_filename}' passed automated rules and holds VERIFIED standing.`;
    } else {
      autoStatus = 'MANUAL_REVIEW_REQUIRED';
      autoNote = `Linked document '${matchedDoc.original_filename}' extracted; awaiting source or manual officer verification.`;
    }

    const existing = existingByReq.get(req.id);
    if (!existing) {
      db.prepare(
        `INSERT INTO application_compliance_items (
          id, application_id, requirement_id, linked_document_id, compliance_status,
          auto_evaluated_note, visual_inspection_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        `ACI-${crypto.randomUUID()}`,
        applicationId,
        req.id,
        matchedDoc?.id || null,
        autoStatus,
        autoNote,
        JSON.stringify(visualSummary),
        nowIso
      );
    } else if (!existing.reviewed_by) {
      db.prepare(
        `UPDATE application_compliance_items
         SET linked_document_id = ?, compliance_status = ?, auto_evaluated_note = ?,
             visual_inspection_json = ?, updated_at = ?
         WHERE id = ?`
      ).run(matchedDoc?.id || null, autoStatus, autoNote, JSON.stringify(visualSummary), nowIso, existing.id);
    } else {
      // Preserve officer-determined status & observations while keeping linked document & visual metadata fresh
      db.prepare(
        `UPDATE application_compliance_items
         SET linked_document_id = COALESCE(?, linked_document_id),
             auto_evaluated_note = ?, visual_inspection_json = ?, updated_at = ?
         WHERE id = ?`
      ).run(matchedDoc?.id || null, autoNote, JSON.stringify(visualSummary), nowIso, existing.id);
    }
  }

  // 6. Compute Reproducible Explainable Advisory Trust Score (0 - 100)
  const contributions: TrustScoreContribution[] = [];

  // Factor 1: Document Completeness (25 pts)
  const presentRatio =
    requiredDocTypes.length > 0 ? Math.max(0, requiredDocTypes.length - missingMandatoryCount) / requiredDocTypes.length : 1;
  const completenessPts = Math.round(25 * presentRatio);
  contributions.push({
    factorCode: 'DOC_COMPLETENESS',
    category: 'COMPLETENESS',
    signalOrigin: 'CONFIGURED_RULE',
    label: 'Mandatory Checklist Completeness',
    maxPoints: 25,
    awardedPoints: completenessPts,
    deltaPoints: completenessPts - 25,
    explanation:
      missingMandatoryCount === 0
        ? `All ${requiredDocTypes.length} required category documents uploaded.`
        : `${missingMandatoryCount} of ${requiredDocTypes.length} required category documents missing.`,
    evidenceRef: 'RULE-REQ-DOCS',
  });

  // Factor 2: Regulatory Rule Compliance (30 pts)
  const activeRuleFindings = generatedFindings.filter(
    (f) =>
      f.findingCategory === 'RULE_VALIDATION' &&
      f.ruleCode !== 'RULE-REQ-DOCS' &&
      !resolvedLookup.has(`${f.ruleCode}|${f.documentId || ''}|${f.fieldName || ''}`)
  );
  let rulePenalty = 0;
  for (const rf of activeRuleFindings) {
    if (rf.severity === 'CRITICAL') rulePenalty += 15;
    else if (rf.severity === 'HIGH') rulePenalty += 10;
    else if (rf.severity === 'MEDIUM') rulePenalty += 5;
    else rulePenalty += 2;
  }
  const rulePts = Math.max(0, 30 - rulePenalty);
  contributions.push({
    factorCode: 'REGULATORY_COMPLIANCE',
    category: 'RULE_COMPLIANCE',
    signalOrigin: 'CONFIGURED_RULE',
    label: 'Field, Expiry & Institutional Record Consistency',
    maxPoints: 30,
    awardedPoints: rulePts,
    deltaPoints: -Math.min(30, rulePenalty),
    explanation:
      activeRuleFindings.length === 0
        ? 'No unresolved field, expiry, or institutional cross-check violations.'
        : `${activeRuleFindings.length} unresolved regulatory validation finding(s) detected.`,
    evidenceRef: activeRuleFindings.map((f) => f.ruleCode).join(', ') || 'PASS',
  });

  // Factor 3: Cryptographic & Metadata Integrity (20 pts)
  const anomalyAndDupFindings = generatedFindings.filter(
    (f) =>
      (f.findingCategory === 'ANOMALY_INDICATOR' || f.findingCategory === 'DUPLICATE_CHECK') &&
      !resolvedLookup.has(`${f.ruleCode}|${f.documentId || ''}|${f.fieldName || ''}`)
  );
  let integrityPenalty = 0;
  for (const af of anomalyAndDupFindings) {
    if (af.severity === 'CRITICAL') integrityPenalty += 14;
    else if (af.severity === 'HIGH') integrityPenalty += 9;
    else integrityPenalty += 4;
  }
  const integrityPts = docs.length === 0 ? 0 : Math.max(0, 20 - integrityPenalty);
  contributions.push({
    factorCode: 'INTEGRITY_AND_DUPLICATES',
    category: 'INTEGRITY_METADATA',
    signalOrigin: 'HEURISTIC_ANOMALY_SIGNAL',
    label: 'SHA-256 Uniqueness & Container Metadata Heuristics',
    maxPoints: 20,
    awardedPoints: integrityPts,
    deltaPoints: docs.length === 0 ? -20 : -Math.min(20, integrityPenalty),
    explanation:
      docs.length === 0
        ? 'No documents uploaded yet to evaluate cryptographic integrity.'
        : anomalyAndDupFindings.length === 0
          ? 'No SHA-256 collisions or container metadata editing indicators detected.'
          : `${anomalyAndDupFindings.length} duplicate or heuristic metadata indicator(s) flagged for investigation.`,
    evidenceRef: anomalyAndDupFindings.map((f) => f.ruleCode).join(', ') || 'SHA256-CLEAN',
  });

  // Factor 4: OCR & Evidence Readability (10 pts)
  const ocrIssues = generatedFindings.filter(
    (f) =>
      f.findingCategory === 'OCR_QUALITY' &&
      !resolvedLookup.has(`${f.ruleCode}|${f.documentId || ''}|${f.fieldName || ''}`)
  );
  const ocrPts = docs.length === 0 ? 0 : Math.max(0, 10 - ocrIssues.length * 5);
  contributions.push({
    factorCode: 'OCR_EVIDENCE_CLARITY',
    category: 'OCR_CLARITY',
    signalOrigin: 'OCR_QUALITY',
    label: 'OCR Extraction Readability & Field Confidence',
    maxPoints: 10,
    awardedPoints: ocrPts,
    deltaPoints: docs.length === 0 ? -10 : -Math.min(10, ocrIssues.length * 5),
    explanation:
      docs.length === 0
        ? 'No documents processed yet.'
        : ocrIssues.length === 0
          ? 'All uploaded textual documents extracted with confidence >= 0.75.'
          : `${ocrIssues.length} document(s) have low OCR confidence or unavailable raster OCR requiring visual review.`,
  });

  // Factor 5: Source Verification Standing (15 pts)
  const certDocs = docs.filter((d) => !FACILITY_PHOTO_DOC_TYPES.has(d.declared_doc_type));
  const verifiedDocs = certDocs.filter((d) => d.verification_status === 'VERIFIED').length;
  const mismatchedOrExpiredVerif = sourceVerifs.filter(
    (sv) => sv.status === 'MISMATCH_DETECTED' || sv.status === 'EXPIRED'
  ).length;
  let verifPts = 0;
  if (certDocs.length > 0) {
    verifPts = Math.round((verifiedDocs / certDocs.length) * 15);
    if (mismatchedOrExpiredVerif > 0) {
      verifPts = Math.max(0, verifPts - mismatchedOrExpiredVerif * 6);
    }
  }
  contributions.push({
    factorCode: 'SOURCE_VERIFICATION_STANDING',
    category: 'SOURCE_VERIFICATION',
    signalOrigin: 'SOURCE_VERIFICATION',
    label: 'Source & Officer Verification Standing',
    maxPoints: 15,
    awardedPoints: verifPts,
    deltaPoints: verifPts - 15,
    explanation:
      certDocs.length === 0
        ? 'No statutory certificates verified yet.'
        : `${verifiedDocs} of ${certDocs.length} certificate(s) marked VERIFIED; ${mismatchedOrExpiredVerif} adverse source-check outcome(s).`,
  });

  const totalScore = Math.max(
    0,
    Math.min(100, contributions.reduce((acc, item) => acc + item.awardedPoints, 0))
  );

  const trustScore: TrustScoreBreakdown = {
    score: totalScore,
    maxScore: 100,
    version: TRUST_SCORE_VERSION,
    calculatedAt: nowIso,
    advisoryNotice:
      'Advisory composite risk/readiness indicator only (not a calibrated probability of fraud). Automated flags never reject an institution; final regulatory decisions require an authorised human officer.',
    contributions,
  };

  let recommendedPriority: ReviewPriority = 'STANDARD';
  if (criticalOrHighUnresolved > 0 || totalScore < 60 || Boolean(appRow.physical_inspection_required)) {
    recommendedPriority = 'HIGH';
  } else if (unresolvedFindingsCount > 0 || totalScore < 85) {
    recommendedPriority = 'MEDIUM';
  }

  const summaryText =
    unresolvedFindingsCount === 0 && docs.length >= requiredDocTypes.length
      ? `All ${docs.length} uploaded document(s) passed automated checklist and consistency checks. Ready for final officer review.`
      : `${unresolvedFindingsCount} open finding(s) across ${docs.length} uploaded document(s) (${criticalOrHighUnresolved} high/critical priority). Flagged for human scrutiny.`;

  // Never overwrite final officer decisions (`APPROVED_BY_OFFICER` / `REJECTED_BY_OFFICER` / `CLARIFICATION_REQUESTED`)
  let nextStatus = appRow.status;
  if (!appRow.final_officer_decision && !['CLARIFICATION_REQUESTED', 'REOPENED'].includes(appRow.status)) {
    const hasPendingSource = certDocs.some((d) =>
      ['VERIFICATION_PENDING', 'SOURCE_UNAVAILABLE', 'MANUAL_REVIEW_REQUIRED'].includes(d.verification_status)
    );
    nextStatus = hasPendingSource ? 'PENDING_VERIFICATION' : docs.length > 0 ? 'UNDER_SCRUTINY' : 'SUBMITTED';
  }

  // Compute explicit visual lifecycle stage & recommended next action
  let lifecycleStage: LifecycleStage = 'pending';
  let nextRecommendedAction = 'Review submitted application and supporting evidence.';

  const hasFailedOcr = docs.some((d) => d.ocr_status === 'FAILED');
  const hasPendingOcr = docs.some((d) => d.ocr_status === 'PENDING');
  const hasUnverifiedCerts = certDocs.some((d) => d.verification_status !== 'VERIFIED');

  if (appRow.final_officer_decision) {
    lifecycleStage = 'completed';
    nextRecommendedAction =
      'Final officer decision recorded. Export scrutiny report or reopen via Senior Auditor / Admin if post-decision audit is warranted.';
  } else if (nextStatus === 'CLARIFICATION_REQUESTED') {
    lifecycleStage = 'incomplete';
    nextRecommendedAction =
      'Awaiting institutional rectification: upload replacement/missing evidence and submit formal rectification summary.';
  } else if (missingMandatoryCount > 0) {
    lifecycleStage = 'incomplete';
    nextRecommendedAction = `Upload ${missingMandatoryCount} missing mandatory checklist document(s) or issue a formal Clarification Request.`;
  } else if (hasPendingOcr) {
    lifecycleStage = 'processing';
    nextRecommendedAction = 'Automated OCR & document extraction is currently in progress.';
  } else if (hasFailedOcr) {
    lifecycleStage = 'failed';
    nextRecommendedAction =
      'One or more documents encountered an OCR processing failure/timeout. Retry OCR processing or complete visual manual inspection.';
  } else if (
    unresolvedFindingsCount > 0 ||
    hasUnverifiedCerts ||
    Boolean(appRow.physical_inspection_required) ||
    nextStatus === 'REOPENED'
  ) {
    lifecycleStage = 'review-required';
    nextRecommendedAction =
      unresolvedFindingsCount > 0
        ? `Scrutinize ${unresolvedFindingsCount} open finding(s), verify source records, or request institutional clarification.`
        : Boolean(appRow.physical_inspection_required)
          ? 'Physical inspection flagged — review EVC site observations before recording final officer decision.'
          : 'Complete source/manual verification of remaining certificates and record final officer decision.';
  } else {
    lifecycleStage = 'pending';
    nextRecommendedAction =
      'All automated checklist, field, and source checks satisfied — ready for authorised officer final decision.';
  }

  db.prepare(
    `UPDATE applications
     SET trust_score = ?, trust_score_version = ?, trust_score_breakdown_json = ?,
         review_priority = ?, automated_summary = ?, status = ?,
         lifecycle_stage = ?, next_recommended_action = ?, updated_at = ?
     WHERE id = ?`
  ).run(
    trustScore.score,
    trustScore.version,
    JSON.stringify(trustScore),
    recommendedPriority,
    summaryText,
    nextStatus,
    lifecycleStage,
    nextRecommendedAction,
    nowIso,
    applicationId
  );

  return {
    findingsCount: unresolvedFindingsCount,
    trustScore,
    recommendedPriority,
    lifecycleStage,
    nextRecommendedAction,
  };
}
