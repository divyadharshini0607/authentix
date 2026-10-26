-- ============================================================================
-- AUTHENTIX / EduVerify-AI (SIH26261)
-- PostgreSQL 16 Reference DDL Schema ONLY (1:1 column mirror of SQLite schema)
-- IMPORTANT: The active runtime database adapter uses Node 22 built-in SQLite WAL
-- (`./data/authentix.sqlite`). This file is reference DDL for future PostgreSQL
-- adapter work and schema validation (`docker compose --profile postgres-db up`).
-- ============================================================================

CREATE TABLE IF NOT EXISTS institutions (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  state TEXT NOT NULL,
  district TEXT NOT NULL,
  institution_type TEXT NOT NULL,
  established_year INTEGER NOT NULL,
  approved_intake INTEGER NOT NULL,
  land_area_acres NUMERIC(10, 2) NOT NULL,
  built_up_area_sqm NUMERIC(12, 2) NOT NULL,
  principal_name TEXT NOT NULL,
  aicte_permanent_id TEXT NOT NULL UNIQUE,
  is_synthetic_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('ADMIN', 'REVIEW_OFFICER', 'SENIOR_AUDITOR', 'INSTITUTION_USER')),
  institution_id TEXT REFERENCES institutions(id) ON DELETE SET NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_demo_account BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL,
  last_login_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_institution ON users(institution_id);

CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_token TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);

CREATE TABLE IF NOT EXISTS application_categories (
  code TEXT PRIMARY KEY,
  base_category TEXT NOT NULL CHECK (base_category IN ('EXTENSION_OF_APPROVAL', 'NEW_INSTITUTION', 'INCREASE_IN_INTAKE')),
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  required_doc_types_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  application_number TEXT NOT NULL UNIQUE,
  institution_id TEXT NOT NULL REFERENCES institutions(id) ON DELETE RESTRICT,
  academic_year TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('EXTENSION_OF_APPROVAL', 'NEW_INSTITUTION', 'INCREASE_IN_INTAKE')),
  category_code TEXT,
  submission_cycle INTEGER NOT NULL DEFAULT 1,
  resubmitted_at TIMESTAMPTZ,
  resubmission_summary TEXT,
  physical_inspection_required BOOLEAN NOT NULL DEFAULT FALSE,
  physical_inspection_reason TEXT,
  lifecycle_stage TEXT NOT NULL DEFAULT 'pending',
  next_recommended_action TEXT,
  program_names TEXT NOT NULL,
  requested_intake INTEGER NOT NULL,
  submitted_land_acres NUMERIC(10, 2) NOT NULL,
  submitted_built_up_sqm NUMERIC(12, 2) NOT NULL,
  submitted_principal_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'SUBMITTED',
    'UNDER_SCRUTINY',
    'CLARIFICATION_REQUESTED',
    'PENDING_VERIFICATION',
    'APPROVED_BY_OFFICER',
    'REJECTED_BY_OFFICER',
    'REOPENED'
  )),
  review_priority TEXT NOT NULL CHECK (review_priority IN ('HIGH', 'MEDIUM', 'STANDARD')),
  trust_score INTEGER,
  trust_score_version TEXT,
  trust_score_breakdown_json JSONB,
  automated_summary TEXT,
  final_officer_decision TEXT CHECK (final_officer_decision IS NULL OR final_officer_decision IN ('APPROVED_BY_OFFICER', 'REJECTED_BY_OFFICER')),
  final_decision_rationale TEXT,
  final_decision_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  final_decision_at TIMESTAMPTZ,
  is_synthetic_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_applications_institution ON applications(institution_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_applications_priority ON applications(review_priority);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  declared_doc_type TEXT NOT NULL,
  detected_doc_type TEXT NOT NULL,
  classification_confidence NUMERIC(5, 2),
  original_filename TEXT NOT NULL,
  stored_filename TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL,
  file_size_bytes BIGINT NOT NULL,
  sha256_hash TEXT NOT NULL,
  page_count INTEGER NOT NULL DEFAULT 1,
  ocr_status TEXT NOT NULL CHECK (ocr_status IN ('COMPLETED', 'LOW_CONFIDENCE', 'UNAVAILABLE', 'FAILED', 'PENDING')),
  ocr_engine TEXT NOT NULL,
  ocr_confidence NUMERIC(5, 2),
  reprocess_count INTEGER NOT NULL DEFAULT 0,
  last_error_reason TEXT,
  extracted_text TEXT NOT NULL DEFAULT '',
  extracted_pages_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  verification_status TEXT NOT NULL CHECK (verification_status IN (
    'UNVERIFIED',
    'VERIFIED',
    'MISMATCH_DETECTED',
    'EXPIRED',
    'VERIFICATION_PENDING',
    'SOURCE_UNAVAILABLE',
    'MANUAL_REVIEW_REQUIRED'
  )),
  processed_at TIMESTAMPTZ,
  uploaded_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_documents_application ON documents(application_id);
CREATE INDEX IF NOT EXISTS idx_documents_sha256 ON documents(sha256_hash);

CREATE TABLE IF NOT EXISTS extracted_fields (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  field_name TEXT NOT NULL,
  field_value TEXT NOT NULL,
  confidence NUMERIC(5, 2) NOT NULL,
  page_number INTEGER NOT NULL DEFAULT 1,
  bbox_json JSONB,
  extraction_method TEXT NOT NULL,
  manually_corrected BOOLEAN NOT NULL DEFAULT FALSE,
  corrected_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  corrected_at TIMESTAMPTZ,
  correction_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_extracted_fields_doc ON extracted_fields(document_id);

CREATE TABLE IF NOT EXISTS validation_rules (
  id TEXT PRIMARY KEY,
  rule_code TEXT NOT NULL,
  version TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL,
  doc_type TEXT,
  rule_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  authority_source TEXT NOT NULL CHECK (authority_source IN (
    'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE',
    'INSTITUTIONAL_CROSSCHECK',
    'CRYPTOGRAPHIC_INTEGRITY'
  )),
  config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  effective_from DATE,
  effective_to DATE,
  expected_fields_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  recommended_action TEXT,
  evidence_reference_label TEXT,
  is_illustrative BOOLEAN NOT NULL DEFAULT TRUE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  UNIQUE(rule_code, version)
);

CREATE TABLE IF NOT EXISTS validation_findings (
  id TEXT PRIMARY KEY,
  finding_code TEXT NOT NULL,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
  field_name TEXT,
  page_region TEXT,
  rule_code TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  authority_source TEXT NOT NULL,
  finding_category TEXT NOT NULL CHECK (finding_category IN ('RULE_VALIDATION', 'ANOMALY_INDICATOR', 'DUPLICATE_CHECK', 'OCR_QUALITY')),
  epistemic_classification TEXT NOT NULL DEFAULT 'ORDINARY_INCONSISTENCY',
  detector_confidence NUMERIC(5, 2),
  limitations_note TEXT,
  recommended_follow_up TEXT,
  submission_cycle INTEGER NOT NULL DEFAULT 1,
  archived_from_prior_cycle BOOLEAN NOT NULL DEFAULT FALSE,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  expected_value TEXT,
  observed_value TEXT,
  explanation TEXT NOT NULL,
  evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  requires_human_review BOOLEAN NOT NULL DEFAULT TRUE,
  resolved_by_officer BOOLEAN NOT NULL DEFAULT FALSE,
  resolution_note TEXT,
  resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  resolved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_application ON validation_findings(application_id);
CREATE INDEX IF NOT EXISTS idx_findings_document ON validation_findings(document_id);

CREATE TABLE IF NOT EXISTS source_verifications (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
  verification_method TEXT NOT NULL CHECK (verification_method IN (
    'SANDBOX_ISSUER_API',
    'OFFICIAL_API',
    'OFFICIAL_PORTAL',
    'DIGITAL_SIGNATURE',
    'QR_SIGNATURE_CHECK',
    'DIGITAL_REPOSITORY',
    'REFERENCE_LOOKUP',
    'MANUAL_OFFICER_VERIFICATION'
  )),
  issuer_name TEXT NOT NULL,
  reference_number TEXT,
  is_sandbox_demo BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL CHECK (status IN (
    'VERIFIED',
    'MISMATCH_DETECTED',
    'EXPIRED',
    'VERIFICATION_PENDING',
    'SOURCE_UNAVAILABLE',
    'MANUAL_REVIEW_REQUIRED'
  )),
  source_response_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_reason TEXT,
  verified_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  notes TEXT,
  attempted_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_source_verifications_app ON source_verifications(application_id);
CREATE INDEX IF NOT EXISTS idx_source_verifications_doc ON source_verifications(document_id);

CREATE TABLE IF NOT EXISTS officer_reviews (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  document_id TEXT REFERENCES documents(id) ON DELETE SET NULL,
  officer_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  action_type TEXT NOT NULL CHECK (action_type IN (
    'MARK_DOCUMENT_VERIFIED',
    'RECORD_MISMATCH',
    'REQUEST_CLARIFICATION',
    'RECORD_MANUAL_VERIFICATION',
    'ADD_REVIEW_NOTE',
    'CORRECT_EXTRACTED_FIELD',
    'RESOLVE_FINDING',
    'FLAG_PHYSICAL_INSPECTION',
    'CLEAR_PHYSICAL_INSPECTION',
    'REQUEST_ADDITIONAL_EVIDENCE',
    'RESUBMIT_APPLICATION',
    'FINAL_DECISION_APPROVE',
    'FINAL_DECISION_REJECT',
    'REOPEN_APPLICATION'
  )),
  previous_status TEXT,
  new_status TEXT,
  rationale TEXT NOT NULL,
  evidence_reference TEXT,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_officer_reviews_app ON officer_reviews(application_id);

CREATE TABLE IF NOT EXISTS compliance_requirements (
  id TEXT PRIMARY KEY,
  requirement_code TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL,
  domain TEXT NOT NULL CHECK (domain IN (
    'STATUTORY_APPROVAL',
    'LAND_AND_BUILDING',
    'LABORATORY_INFRASTRUCTURE',
    'LIBRARY_AND_COMPUTING',
    'SAFETY_AND_ACCESSIBILITY',
    'FACULTY_AND_AFFIDAVIT'
  )),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  accepted_doc_types_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  is_mandatory BOOLEAN NOT NULL DEFAULT TRUE,
  is_illustrative BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS application_compliance_items (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  requirement_id TEXT NOT NULL REFERENCES compliance_requirements(id) ON DELETE CASCADE,
  linked_document_id TEXT REFERENCES documents(id) ON DELETE SET NULL,
  compliance_status TEXT NOT NULL CHECK (compliance_status IN (
    'SATISFIED',
    'NOT_SATISFIED',
    'INSUFFICIENT_EVIDENCE',
    'NOT_APPLICABLE',
    'MANUAL_REVIEW_REQUIRED'
  )),
  auto_evaluated_note TEXT,
  visual_inspection_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  officer_observation TEXT,
  additional_evidence_requested BOOLEAN NOT NULL DEFAULT FALSE,
  additional_evidence_note TEXT,
  physical_inspection_flagged BOOLEAN NOT NULL DEFAULT FALSE,
  reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL,
  UNIQUE(application_id, requirement_id)
);

CREATE INDEX IF NOT EXISTS idx_app_compliance_app ON application_compliance_items(application_id);

CREATE TABLE IF NOT EXISTS in_app_notifications (
  id TEXT PRIMARY KEY,
  recipient_role TEXT NOT NULL CHECK (recipient_role IN (
    'INTERNAL_ALL',
    'REVIEW_OFFICER',
    'SENIOR_AUDITOR',
    'ADMIN',
    'INSTITUTION_USER'
  )),
  recipient_institution_id TEXT REFERENCES institutions(id) ON DELETE CASCADE,
  application_id TEXT REFERENCES applications(id) ON DELETE CASCADE,
  alert_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'INFO')),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  delivery_channel TEXT NOT NULL DEFAULT 'IN_APP_ONLY' CHECK (delivery_channel IN ('IN_APP_ONLY')),
  is_read BOOLEAN NOT NULL DEFAULT FALSE,
  read_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  read_at TIMESTAMPTZ,
  is_synthetic_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_role ON in_app_notifications(recipient_role, is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_inst ON in_app_notifications(recipient_institution_id, is_read);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  timestamp TIMESTAMPTZ NOT NULL,
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  actor_email TEXT,
  actor_role TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

CREATE TABLE IF NOT EXISTS sandbox_issuer_registry (
  id TEXT PRIMARY KEY,
  issuer_code TEXT NOT NULL,
  issuer_name TEXT NOT NULL,
  reference_number TEXT NOT NULL UNIQUE,
  institution_name TEXT NOT NULL,
  doc_type TEXT NOT NULL,
  issued_date TEXT NOT NULL,
  expiry_date TEXT,
  status_simulation TEXT NOT NULL CHECK (status_simulation IN (
    'VERIFIED',
    'MISMATCH_DETECTED',
    'EXPIRED',
    'VERIFICATION_PENDING',
    'SOURCE_UNAVAILABLE'
  )),
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb
);
