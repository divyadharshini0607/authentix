-- ============================================================================
-- AUTHENTIX / EduVerify-AI (SIH26261)
-- Migration 001: Initial Relational Schema (SQLite 3.35+ / WAL + Foreign Keys)
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
  land_area_acres REAL NOT NULL,
  built_up_area_sqm REAL NOT NULL,
  principal_name TEXT NOT NULL,
  aicte_permanent_id TEXT NOT NULL UNIQUE,
  is_synthetic_demo INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('ADMIN', 'REVIEW_OFFICER', 'SENIOR_AUDITOR', 'INSTITUTION_USER')),
  institution_id TEXT REFERENCES institutions(id) ON DELETE SET NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  is_demo_account INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  last_login_at TEXT
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
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  application_number TEXT NOT NULL UNIQUE,
  institution_id TEXT NOT NULL REFERENCES institutions(id) ON DELETE RESTRICT,
  academic_year TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('EXTENSION_OF_APPROVAL', 'NEW_INSTITUTION', 'INCREASE_IN_INTAKE')),
  program_names TEXT NOT NULL,
  requested_intake INTEGER NOT NULL,
  submitted_land_acres REAL NOT NULL,
  submitted_built_up_sqm REAL NOT NULL,
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
  trust_score_breakdown_json TEXT,
  automated_summary TEXT,
  final_officer_decision TEXT CHECK (final_officer_decision IS NULL OR final_officer_decision IN ('APPROVED_BY_OFFICER', 'REJECTED_BY_OFFICER')),
  final_decision_rationale TEXT,
  final_decision_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  final_decision_at TEXT,
  is_synthetic_demo INTEGER NOT NULL DEFAULT 1,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_applications_institution ON applications(institution_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_applications_priority ON applications(review_priority);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  declared_doc_type TEXT NOT NULL,
  detected_doc_type TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  stored_filename TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL,
  file_size_bytes INTEGER NOT NULL,
  sha256_hash TEXT NOT NULL,
  page_count INTEGER NOT NULL DEFAULT 1,
  ocr_status TEXT NOT NULL CHECK (ocr_status IN ('COMPLETED', 'LOW_CONFIDENCE', 'UNAVAILABLE', 'FAILED', 'PENDING')),
  ocr_engine TEXT NOT NULL,
  ocr_confidence REAL,
  extracted_text TEXT NOT NULL DEFAULT '',
  extracted_pages_json TEXT NOT NULL DEFAULT '[]',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  verification_status TEXT NOT NULL CHECK (verification_status IN (
    'UNVERIFIED',
    'VERIFIED',
    'MISMATCH_DETECTED',
    'EXPIRED',
    'VERIFICATION_PENDING',
    'SOURCE_UNAVAILABLE',
    'MANUAL_REVIEW_REQUIRED'
  )),
  processed_at TEXT,
  uploaded_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_documents_application ON documents(application_id);
CREATE INDEX IF NOT EXISTS idx_documents_sha256 ON documents(sha256_hash);

CREATE TABLE IF NOT EXISTS extracted_fields (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  field_name TEXT NOT NULL,
  field_value TEXT NOT NULL,
  confidence REAL NOT NULL,
  page_number INTEGER NOT NULL DEFAULT 1,
  bbox_json TEXT,
  extraction_method TEXT NOT NULL,
  manually_corrected INTEGER NOT NULL DEFAULT 0,
  corrected_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  corrected_at TEXT,
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
  config_json TEXT NOT NULL DEFAULT '{}',
  is_active INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TEXT NOT NULL,
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
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  expected_value TEXT,
  observed_value TEXT,
  explanation TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}',
  requires_human_review INTEGER NOT NULL DEFAULT 1,
  resolved_by_officer INTEGER NOT NULL DEFAULT 0,
  resolution_note TEXT,
  resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  resolved_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_application ON validation_findings(application_id);
CREATE INDEX IF NOT EXISTS idx_findings_document ON validation_findings(document_id);

CREATE TABLE IF NOT EXISTS source_verifications (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
  verification_method TEXT NOT NULL CHECK (verification_method IN (
    'SANDBOX_ISSUER_API',
    'QR_SIGNATURE_CHECK',
    'REFERENCE_LOOKUP',
    'MANUAL_OFFICER_VERIFICATION'
  )),
  issuer_name TEXT NOT NULL,
  reference_number TEXT,
  is_sandbox_demo INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK (status IN (
    'VERIFIED',
    'MISMATCH_DETECTED',
    'EXPIRED',
    'VERIFICATION_PENDING',
    'SOURCE_UNAVAILABLE',
    'MANUAL_REVIEW_REQUIRED'
  )),
  source_response_json TEXT NOT NULL DEFAULT '{}',
  error_reason TEXT,
  verified_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  notes TEXT,
  attempted_at TEXT NOT NULL
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
    'FINAL_DECISION_APPROVE',
    'FINAL_DECISION_REJECT',
    'REOPEN_APPLICATION'
  )),
  previous_status TEXT,
  new_status TEXT,
  rationale TEXT NOT NULL,
  evidence_reference TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_officer_reviews_app ON officer_reviews(application_id);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  timestamp TEXT NOT NULL,
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  actor_email TEXT,
  actor_role TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
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
  payload_json TEXT NOT NULL DEFAULT '{}'
);
