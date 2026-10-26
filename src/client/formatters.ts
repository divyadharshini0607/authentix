/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Human-Readable Regulatory Labels & Formatting Utilities
 */

import type {
  ApplicationCategory,
  ApplicationStatus,
  ComplianceDomain,
  ComplianceItemStatus,
  DocumentType,
  EpistemicClassification,
  LifecycleStage,
  ReviewPriority,
  SeverityLevel,
  UserRole,
  VerificationMethod,
  VerificationStatus,
} from '../shared/types.ts';

export const DOC_TYPE_LABELS: Record<DocumentType, string> = {
  FIRE_SAFETY_CERTIFICATE: 'Fire Safety Certificate',
  LAND_USE_CERTIFICATE: 'Land Use / NA Conversion Certificate',
  AFFIDAVIT_INTAKE: 'Sworn Intake & Infrastructure Affidavit',
  BUILDING_PLAN_APPROVAL: 'Building Plan & Structural Stability Approval',
  AICTE_FEE_RECEIPT: 'AICTE Processing Fee Receipt',
  NOC_AFFILIATING_UNIVERSITY: 'Affiliating University / State NOC',
  FACILITY_PHOTO_LAB: 'Laboratory Facility Photograph',
  FACILITY_PHOTO_LIBRARY: 'Library & Reading Room Photograph',
  FACILITY_PHOTO_CAMPUS: 'Campus & Barrier-Free Access Photograph',
  FLOOR_PLAN_DRAWING: 'Sanctioned Architectural Floor Plan',
  FACULTY_ROSTER_STATEMENT: 'Faculty Cadre & Qualification Roster',
  UNKNOWN_DOCUMENT: 'Unclassified Supporting Document',
};

export const CATEGORY_LABELS: Record<ApplicationCategory, string> = {
  EXTENSION_OF_APPROVAL: 'Extension of Approval (EoA)',
  NEW_INSTITUTION: 'New Technical Institution',
  INCREASE_IN_INTAKE: 'Increase in Approved Intake',
};

export function formatCategoryDisplay(
  category: ApplicationCategory,
  categoryCode?: string | null,
  customName?: string | null
): string {
  if (customName) return customName;
  if (categoryCode && !(categoryCode in CATEGORY_LABELS)) {
    return `${categoryCode.replace(/_/g, ' ')} (${CATEGORY_LABELS[category]})`;
  }
  return CATEGORY_LABELS[category] || category;
}

export const STATUS_LABELS: Record<ApplicationStatus, string> = {
  SUBMITTED: 'Submitted',
  UNDER_SCRUTINY: 'Under Officer Scrutiny',
  CLARIFICATION_REQUESTED: 'Clarification Requested',
  PENDING_VERIFICATION: 'Verification Pending',
  APPROVED_BY_OFFICER: 'Approved by Officer',
  REJECTED_BY_OFFICER: 'Rejected by Officer',
  REOPENED: 'Reopened for Review',
};

export const LIFECYCLE_LABELS: Record<LifecycleStage, string> = {
  pending: 'Pending Initial Scrutiny',
  incomplete: 'Incomplete / Deficient',
  processing: 'Processing Pipeline',
  failed: 'Extraction Failed',
  'review-required': 'Officer Review Required',
  completed: 'Decision Completed',
};

export const VERIFICATION_STATUS_LABELS: Record<VerificationStatus, string> = {
  UNVERIFIED: 'Unverified',
  VERIFIED: 'Verified',
  MISMATCH_DETECTED: 'Mismatch Detected',
  EXPIRED: 'Expired Certificate',
  VERIFICATION_PENDING: 'Verification Pending',
  SOURCE_UNAVAILABLE: 'Source Unavailable',
  MANUAL_REVIEW_REQUIRED: 'Manual Review Required',
};

export const VERIFICATION_METHOD_LABELS: Record<VerificationMethod, string> = {
  SANDBOX_ISSUER_API: 'Sandbox Issuer Registry Lookup (Non-Live Demo)',
  QR_SIGNATURE_CHECK: 'QR Cryptographic Signature Verification (HMAC-SHA256)',
  REFERENCE_LOOKUP: 'Sandbox Reference Number Lookup (Non-Live Demo)',
  DIGITAL_SIGNATURE: 'PDF Embedded Digital Signature Inspection (/Sig)',
  OFFICIAL_API: 'Official Government Authority API (Unconfigured Live Adapter)',
  OFFICIAL_PORTAL: 'Official Government Portal Adapter (Unconfigured Live Adapter)',
  DIGITAL_REPOSITORY: 'National Digital Repository / DigiLocker (Unconfigured Live Adapter)',
  MANUAL_OFFICER_VERIFICATION: 'Authorised Officer Manual Verification (Persistent)',
};

export const EPISTEMIC_LABELS: Record<EpistemicClassification, string> = {
  MISSING_INFORMATION: 'Missing Mandatory Information',
  ORDINARY_INCONSISTENCY: 'Rule / Cross-Document Inconsistency',
  TECHNICAL_PROCESSING_FAILURE: 'Technical / OCR Processing Failure',
  SUSPECTED_ANOMALY: 'Heuristic Metadata / Integrity Signal',
  CONFIRMED_SOURCE_MISMATCH: 'Confirmed Source / Registry Mismatch',
};

export const COMPLIANCE_STATUS_LABELS: Record<ComplianceItemStatus, string> = {
  SATISFIED: 'Satisfied',
  NOT_SATISFIED: 'Not Satisfied',
  INSUFFICIENT_EVIDENCE: 'Insufficient Evidence',
  NOT_APPLICABLE: 'Not Applicable',
  MANUAL_REVIEW_REQUIRED: 'Manual Review Required',
};

export const COMPLIANCE_DOMAIN_LABELS: Record<ComplianceDomain, string> = {
  STATUTORY_APPROVAL: 'Statutory Approvals & NOCs',
  LAND_AND_BUILDING: 'Land & Built-Up Area',
  LABORATORY_INFRASTRUCTURE: 'Laboratory Infrastructure',
  LIBRARY_AND_COMPUTING: 'Library & Computing Resources',
  SAFETY_AND_ACCESSIBILITY: 'Fire Safety & Accessibility',
  FACULTY_AND_AFFIDAVIT: 'Faculty Cadre & Sworn Affidavits',
};

export const ROLE_LABELS: Record<UserRole, string> = {
  REVIEW_OFFICER: 'Scrutiny Officer',
  SENIOR_AUDITOR: 'Senior Vigilance Auditor',
  ADMIN: 'Platform & Rules Administrator',
  INSTITUTION_USER: 'Institution Representative',
};

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return '—';
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;
  return dt.toLocaleString('en-IN', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function statusColorClass(status: ApplicationStatus): string {
  switch (status) {
    case 'APPROVED_BY_OFFICER':
      return 'text-emerald-700 font-semibold';
    case 'REJECTED_BY_OFFICER':
      return 'text-red-700 font-semibold';
    case 'CLARIFICATION_REQUESTED':
    case 'PENDING_VERIFICATION':
      return 'text-amber-700 font-medium';
    case 'REOPENED':
      return 'text-blue-700 font-medium';
    default:
      return 'text-slate-700 font-medium';
  }
}

export function lifecycleColorClass(stage: LifecycleStage): string {
  switch (stage) {
    case 'completed':
      return 'text-emerald-700 font-semibold';
    case 'failed':
      return 'text-red-700 font-semibold';
    case 'incomplete':
      return 'text-amber-700 font-semibold';
    case 'review-required':
      return 'text-blue-900 font-semibold';
    case 'processing':
      return 'text-blue-700 font-medium';
    default:
      return 'text-slate-600 font-medium';
  }
}

export function complianceColorClass(status: ComplianceItemStatus): string {
  switch (status) {
    case 'SATISFIED':
      return 'text-emerald-700 font-semibold';
    case 'NOT_SATISFIED':
      return 'text-red-700 font-semibold';
    case 'INSUFFICIENT_EVIDENCE':
      return 'text-amber-700 font-semibold';
    case 'MANUAL_REVIEW_REQUIRED':
      return 'text-blue-900 font-medium';
    default:
      return 'text-slate-500';
  }
}

export function verificationColorClass(status: VerificationStatus): string {
  switch (status) {
    case 'VERIFIED':
      return 'text-emerald-700 font-semibold';
    case 'MISMATCH_DETECTED':
    case 'EXPIRED':
      return 'text-red-700 font-semibold';
    case 'SOURCE_UNAVAILABLE':
    case 'MANUAL_REVIEW_REQUIRED':
    case 'VERIFICATION_PENDING':
      return 'text-amber-700 font-medium';
    default:
      return 'text-slate-600';
  }
}

export function severityColorClass(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return 'text-red-700 font-semibold';
    case 'HIGH':
      return 'text-red-600 font-semibold';
    case 'MEDIUM':
      return 'text-amber-700 font-medium';
    case 'LOW':
      return 'text-slate-700 font-medium';
    default:
      return 'text-slate-600';
  }
}

export function priorityColorClass(priority: ReviewPriority): string {
  switch (priority) {
    case 'HIGH':
      return 'text-red-700 font-semibold';
    case 'MEDIUM':
      return 'text-amber-700 font-medium';
    default:
      return 'text-slate-600';
  }
}

export function formatVerificationOrigin(sv: {
  verificationMethod: VerificationMethod;
  isSandboxDemo: boolean;
}): string {
  if (sv.isSandboxDemo) return 'Sandbox Non-Live';
  if (sv.verificationMethod === 'MANUAL_OFFICER_VERIFICATION') return 'Authorised Officer Manual Check';
  if (sv.verificationMethod === 'DIGITAL_SIGNATURE' || sv.verificationMethod === 'QR_SIGNATURE_CHECK') {
    return 'Cryptographic / Container Check';
  }
  return 'External Live Adapter';
}
