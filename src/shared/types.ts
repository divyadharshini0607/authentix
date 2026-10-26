/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Shared Domain Contracts & Types
 */

export type UserRole = 'ADMIN' | 'REVIEW_OFFICER' | 'SENIOR_AUDITOR' | 'INSTITUTION_USER';

export type ApplicationCategory =
  | 'EXTENSION_OF_APPROVAL'
  | 'NEW_INSTITUTION'
  | 'INCREASE_IN_INTAKE';

export type ApplicationStatus =
  | 'SUBMITTED'
  | 'UNDER_SCRUTINY'
  | 'CLARIFICATION_REQUESTED'
  | 'PENDING_VERIFICATION'
  | 'APPROVED_BY_OFFICER'
  | 'REJECTED_BY_OFFICER'
  | 'REOPENED';

export type LifecycleStage =
  | 'pending'
  | 'incomplete'
  | 'processing'
  | 'failed'
  | 'review-required'
  | 'completed';

export type ReviewPriority = 'HIGH' | 'MEDIUM' | 'STANDARD';

export type DocumentType =
  | 'FIRE_SAFETY_CERTIFICATE'
  | 'LAND_USE_CERTIFICATE'
  | 'AFFIDAVIT_INTAKE'
  | 'BUILDING_PLAN_APPROVAL'
  | 'AICTE_FEE_RECEIPT'
  | 'NOC_AFFILIATING_UNIVERSITY'
  | 'FACILITY_PHOTO_LAB'
  | 'FACILITY_PHOTO_LIBRARY'
  | 'FACILITY_PHOTO_CAMPUS'
  | 'FLOOR_PLAN_DRAWING'
  | 'FACULTY_ROSTER_STATEMENT'
  | 'UNKNOWN_DOCUMENT';

export type OcrStatus = 'COMPLETED' | 'LOW_CONFIDENCE' | 'UNAVAILABLE' | 'FAILED' | 'PENDING';

export type VerificationStatus =
  | 'UNVERIFIED'
  | 'VERIFIED'
  | 'MISMATCH_DETECTED'
  | 'EXPIRED'
  | 'VERIFICATION_PENDING'
  | 'SOURCE_UNAVAILABLE'
  | 'MANUAL_REVIEW_REQUIRED';

export type VerificationMethod =
  | 'SANDBOX_ISSUER_API'
  | 'OFFICIAL_API'
  | 'OFFICIAL_PORTAL'
  | 'DIGITAL_SIGNATURE'
  | 'QR_SIGNATURE_CHECK'
  | 'DIGITAL_REPOSITORY'
  | 'REFERENCE_LOOKUP'
  | 'MANUAL_OFFICER_VERIFICATION';

export type FindingCategory =
  | 'RULE_VALIDATION'
  | 'ANOMALY_INDICATOR'
  | 'DUPLICATE_CHECK'
  | 'OCR_QUALITY';

export type EpistemicClassification =
  | 'MISSING_INFORMATION'
  | 'ORDINARY_INCONSISTENCY'
  | 'TECHNICAL_PROCESSING_FAILURE'
  | 'SUSPECTED_ANOMALY'
  | 'CONFIRMED_SOURCE_MISMATCH';

export type ComplianceItemStatus =
  | 'SATISFIED'
  | 'NOT_SATISFIED'
  | 'INSUFFICIENT_EVIDENCE'
  | 'NOT_APPLICABLE'
  | 'MANUAL_REVIEW_REQUIRED';

export type ComplianceDomain =
  | 'STATUTORY_APPROVAL'
  | 'LAND_AND_BUILDING'
  | 'LABORATORY_INFRASTRUCTURE'
  | 'LIBRARY_AND_COMPUTING'
  | 'SAFETY_AND_ACCESSIBILITY'
  | 'FACULTY_AND_AFFIDAVIT';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type OfficerActionType =
  | 'MARK_DOCUMENT_VERIFIED'
  | 'RECORD_MISMATCH'
  | 'REQUEST_CLARIFICATION'
  | 'RECORD_MANUAL_VERIFICATION'
  | 'ADD_REVIEW_NOTE'
  | 'CORRECT_EXTRACTED_FIELD'
  | 'RESOLVE_FINDING'
  | 'FLAG_PHYSICAL_INSPECTION'
  | 'CLEAR_PHYSICAL_INSPECTION'
  | 'REQUEST_ADDITIONAL_EVIDENCE'
  | 'RESUBMIT_APPLICATION'
  | 'FINAL_DECISION_APPROVE'
  | 'FINAL_DECISION_REJECT'
  | 'REOPEN_APPLICATION';

export interface UserProfile {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  institutionId: string | null;
  institutionName?: string | null;
  isDemoAccount: boolean;
  lastLoginAt: string | null;
}

export interface InstitutionRecord {
  id: string;
  code: string;
  name: string;
  state: string;
  district: string;
  institutionType: string;
  establishedYear: number;
  approvedIntake: number;
  landAreaAcres: number;
  builtUpAreaSqm: number;
  principalName: string;
  aictePermanentId: string;
  isSyntheticDemo: boolean;
}

export interface ApplicationCategoryDefinition {
  code: string;
  baseCategory: ApplicationCategory;
  name: string;
  description: string;
  requiredDocTypes: DocumentType[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface TrustScoreContribution {
  factorCode: string;
  category: 'COMPLETENESS' | 'RULE_COMPLIANCE' | 'INTEGRITY_METADATA' | 'OCR_CLARITY' | 'SOURCE_VERIFICATION';
  signalOrigin: 'CONFIGURED_RULE' | 'SOURCE_VERIFICATION' | 'HEURISTIC_ANOMALY_SIGNAL' | 'OCR_QUALITY';
  label: string;
  maxPoints: number;
  awardedPoints: number;
  deltaPoints: number;
  explanation: string;
  evidenceRef?: string;
}

export interface TrustScoreBreakdown {
  score: number;
  maxScore: 100;
  version: string;
  calculatedAt: string;
  advisoryNotice: string;
  contributions: TrustScoreContribution[];
}

export interface ExtractedFieldRecord {
  id: string;
  documentId: string;
  fieldName: string;
  fieldValue: string;
  confidence: number;
  pageNumber: number;
  bbox: [number, number, number, number] | null;
  extractionMethod: string;
  manuallyCorrected: boolean;
  correctedBy: string | null;
  correctedAt: string | null;
  correctionNote: string | null;
}

export interface DocumentRecord {
  id: string;
  applicationId: string;
  declaredDocType: DocumentType;
  detectedDocType: DocumentType;
  classificationConfidence?: number | null;
  originalFilename: string;
  storedFilename: string;
  mimeType: string;
  fileSizeBytes: number;
  sha256Hash: string;
  pageCount: number;
  ocrStatus: OcrStatus;
  ocrEngine: string;
  ocrConfidence: number | null;
  reprocessCount?: number;
  lastErrorReason?: string | null;
  extractedText: string;
  extractedPages: Array<{
    page_number: number;
    blocks: Array<{ text: string; bbox: number[]; confidence: number }>;
  }>;
  metadata: Record<string, unknown>;
  verificationStatus: VerificationStatus;
  processedAt: string | null;
  uploadedBy: string | null;
  createdAt: string;
  updatedAt: string;
  extractedFields: ExtractedFieldRecord[];
}

export interface ValidationFindingRecord {
  id: string;
  findingCode: string;
  applicationId: string;
  documentId: string | null;
  documentFilename?: string | null;
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
  submissionCycle: number;
  archivedFromPriorCycle: boolean;
  severity: SeverityLevel;
  expectedValue: string | null;
  observedValue: string | null;
  explanation: string;
  evidence: Record<string, unknown>;
  requiresHumanReview: boolean;
  resolvedByOfficer: boolean;
  resolutionNote: string | null;
  resolvedBy: string | null;
  resolvedAt: string | null;
  createdAt: string;
}

export interface SourceVerificationRecord {
  id: string;
  applicationId: string;
  documentId: string | null;
  verificationMethod: VerificationMethod;
  issuerName: string;
  referenceNumber: string | null;
  isSandboxDemo: boolean;
  status: VerificationStatus;
  sourceResponse: Record<string, unknown>;
  errorReason: string | null;
  verifiedBy: string | null;
  verifiedByName?: string | null;
  notes: string | null;
  attemptedAt: string;
}

export interface OfficerReviewRecord {
  id: string;
  applicationId: string;
  documentId: string | null;
  officerId: string;
  officerName?: string;
  officerRole?: string;
  actionType: OfficerActionType;
  previousStatus: string | null;
  newStatus: string | null;
  rationale: string;
  evidenceReference: string | null;
  createdAt: string;
}

export interface VisualEvidenceSummary {
  adapterName?: string;
  width?: number | null;
  height?: number | null;
  aspectRatio?: number | null;
  megapixels?: number | null;
  byteLength?: number | null;
  legibilityFlag?: 'READABLE_RESOLUTION' | 'LOW_RESOLUTION_WARNING' | 'NON_IMAGE_DOCUMENT';
  limitationsDisclaimer?: string;
}

export interface ApplicationComplianceItemRecord {
  id: string;
  applicationId: string;
  requirementId: string;
  requirementCode: string;
  domain: ComplianceDomain;
  title: string;
  description: string;
  acceptedDocTypes: DocumentType[];
  isMandatory: boolean;
  isIllustrative: boolean;
  linkedDocumentId: string | null;
  linkedDocumentFilename: string | null;
  complianceStatus: ComplianceItemStatus;
  autoEvaluatedNote: string | null;
  visualInspection: VisualEvidenceSummary;
  officerObservation: string | null;
  additionalEvidenceRequested: boolean;
  additionalEvidenceNote: string | null;
  physicalInspectionFlagged: boolean;
  reviewedBy: string | null;
  reviewedByName: string | null;
  reviewedAt: string | null;
  updatedAt: string;
}

export interface InAppNotificationRecord {
  id: string;
  recipientRole: 'INTERNAL_ALL' | UserRole;
  recipientInstitutionId: string | null;
  applicationId: string | null;
  alertType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  title: string;
  message: string;
  deliveryChannel: 'IN_APP_ONLY';
  isRead: boolean;
  readBy: string | null;
  readAt: string | null;
  createdAt: string;
}

export interface ApplicationSummary {
  id: string;
  applicationNumber: string;
  institutionId: string;
  institutionName: string;
  institutionCode: string;
  institutionState: string;
  academicYear: string;
  category: ApplicationCategory;
  categoryCode?: string;
  programNames: string;
  requestedIntake: number;
  submittedLandAcres: number;
  submittedBuiltUpSqm: number;
  submittedPrincipalName: string;
  status: ApplicationStatus;
  lifecycleStage: LifecycleStage;
  nextRecommendedAction: string | null;
  submissionCycle: number;
  resubmittedAt: string | null;
  resubmissionSummary: string | null;
  physicalInspectionRequired: boolean;
  physicalInspectionReason: string | null;
  reviewPriority: ReviewPriority;
  trustScore: number | null;
  trustScoreVersion: string | null;
  automatedSummary: string | null;
  finalOfficerDecision: 'APPROVED_BY_OFFICER' | 'REJECTED_BY_OFFICER' | null;
  finalDecisionRationale: string | null;
  finalDecisionAt: string | null;
  isSyntheticDemo: boolean;
  documentCount: number;
  openFindingsCount: number;
  criticalFindingsCount: number;
  verifiedDocsCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface ApplicationDetail extends ApplicationSummary {
  institution: InstitutionRecord;
  trustScoreBreakdown: TrustScoreBreakdown | null;
  requiredChecklistDocTypes: DocumentType[];
  documents: DocumentRecord[];
  findings: ValidationFindingRecord[];
  priorCycleFindings: ValidationFindingRecord[];
  complianceItems: ApplicationComplianceItemRecord[];
  sourceVerifications: SourceVerificationRecord[];
  officerReviews: OfficerReviewRecord[];
}

export interface ValidationRuleRecord {
  id: string;
  ruleCode: string;
  version: string;
  name: string;
  description: string;
  category: string;
  docType: string | null;
  ruleType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  authoritySource: 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE' | 'INSTITUTIONAL_CROSSCHECK' | 'CRYPTOGRAPHIC_INTEGRITY';
  config: Record<string, unknown>;
  effectiveFrom: string | null;
  effectiveTo: string | null;
  expectedFields: string[];
  recommendedAction: string | null;
  evidenceReferenceLabel: string | null;
  isIllustrative: boolean;
  isActive: boolean;
  updatedAt: string;
}

export interface AuditLogRecord {
  id: number;
  eventId: string;
  timestamp: string;
  actorUserId: string | null;
  actorEmail: string | null;
  actorRole: string | null;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
}

export interface DashboardStats {
  totalApplications: number;
  awaitingReview: number;
  verifiedApplications: number;
  verifiedDocuments: number;
  totalDocuments: number;
  missingOrExpiredApplications: number;
  mismatchOrAnomalyApplications: number;
  verificationPendingApplications: number;
  highPriorityApplications: number;
  openComplianceFindings: number;
  physicalInspectionRequiredCount: number;
  additionalEvidenceRequestedCount: number;
  officerInterventionRequiredCount: number;
  unreadNotificationsCount: number;
  recentActivity: AuditLogRecord[];
  statusBreakdown: Record<string, number>;
  categoryBreakdown: Record<string, number>;
  lifecycleBreakdown: Record<string, number>;
}
