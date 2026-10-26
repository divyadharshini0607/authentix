-- ============================================================================
-- AUTHENTIX / EduVerify-AI (SIH26261)
-- Migration 003: Complete Application Lifecycle, Extensible Categories,
-- Configurable Rule Metadata, 5-Way Epistemic Findings, Provider-Adapter Source
-- Verification, Regulatory & Infrastructure Compliance Module, and In-App Alerts
-- ============================================================================

-- 1. Extend applications for full lifecycle, rectification cycles & physical inspection
ALTER TABLE applications ADD COLUMN category_code TEXT;
ALTER TABLE applications ADD COLUMN submission_cycle INTEGER NOT NULL DEFAULT 1;
ALTER TABLE applications ADD COLUMN resubmitted_at TEXT;
ALTER TABLE applications ADD COLUMN resubmission_summary TEXT;
ALTER TABLE applications ADD COLUMN physical_inspection_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE applications ADD COLUMN physical_inspection_reason TEXT;
ALTER TABLE applications ADD COLUMN lifecycle_stage TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE applications ADD COLUMN next_recommended_action TEXT;

UPDATE applications SET category_code = category WHERE category_code IS NULL;

-- 2. Extend documents for classification confidence & OCR retry tracking
ALTER TABLE documents ADD COLUMN classification_confidence REAL;
ALTER TABLE documents ADD COLUMN reprocess_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE documents ADD COLUMN last_error_reason TEXT;

-- 3. Extend validation_rules for effective dates, expected fields & governance guidance
ALTER TABLE validation_rules ADD COLUMN effective_from TEXT;
ALTER TABLE validation_rules ADD COLUMN effective_to TEXT;
ALTER TABLE validation_rules ADD COLUMN expected_fields_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE validation_rules ADD COLUMN recommended_action TEXT;
ALTER TABLE validation_rules ADD COLUMN evidence_reference_label TEXT;
ALTER TABLE validation_rules ADD COLUMN is_illustrative INTEGER NOT NULL DEFAULT 1;

-- 4. Extend validation_findings for 5-way epistemic classification & resubmission cycle history
ALTER TABLE validation_findings ADD COLUMN epistemic_classification TEXT NOT NULL DEFAULT 'ORDINARY_INCONSISTENCY';
ALTER TABLE validation_findings ADD COLUMN detector_confidence REAL;
ALTER TABLE validation_findings ADD COLUMN limitations_note TEXT;
ALTER TABLE validation_findings ADD COLUMN recommended_follow_up TEXT;
ALTER TABLE validation_findings ADD COLUMN submission_cycle INTEGER NOT NULL DEFAULT 1;
ALTER TABLE validation_findings ADD COLUMN archived_from_prior_cycle INTEGER NOT NULL DEFAULT 0;

-- 5. Rebuild leaf table source_verifications to support full provider-adapter method enum
CREATE TABLE source_verifications_v2 (
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

INSERT INTO source_verifications_v2 (
  id, application_id, document_id, verification_method, issuer_name,
  reference_number, is_sandbox_demo, status, source_response_json,
  error_reason, verified_by, notes, attempted_at
)
SELECT
  id, application_id, document_id, verification_method, issuer_name,
  reference_number, is_sandbox_demo, status, source_response_json,
  error_reason, verified_by, notes, attempted_at
FROM source_verifications;

DROP TABLE source_verifications;
ALTER TABLE source_verifications_v2 RENAME TO source_verifications;

CREATE INDEX IF NOT EXISTS idx_source_verifications_app ON source_verifications(application_id);
CREATE INDEX IF NOT EXISTS idx_source_verifications_doc ON source_verifications(document_id);

-- 6. Rebuild leaf table officer_reviews to support rectification, additional evidence & physical inspection actions
CREATE TABLE officer_reviews_v2 (
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
  created_at TEXT NOT NULL
);

INSERT INTO officer_reviews_v2 (
  id, application_id, document_id, officer_id, action_type,
  previous_status, new_status, rationale, evidence_reference, created_at
)
SELECT
  id, application_id, document_id, officer_id, action_type,
  previous_status, new_status, rationale, evidence_reference, created_at
FROM officer_reviews;

DROP TABLE officer_reviews;
ALTER TABLE officer_reviews_v2 RENAME TO officer_reviews;

CREATE INDEX IF NOT EXISTS idx_officer_reviews_app ON officer_reviews(application_id);

-- 7. Extensible Application Categories Catalog
CREATE TABLE IF NOT EXISTS application_categories (
  code TEXT PRIMARY KEY,
  base_category TEXT NOT NULL CHECK (base_category IN ('EXTENSION_OF_APPROVAL', 'NEW_INSTITUTION', 'INCREASE_IN_INTAKE')),
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  required_doc_types_json TEXT NOT NULL DEFAULT '[]',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- 8. Regulatory & Infrastructure Compliance Requirements Catalog
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
  accepted_doc_types_json TEXT NOT NULL DEFAULT '[]',
  is_mandatory INTEGER NOT NULL DEFAULT 1,
  is_illustrative INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

-- 9. Per-Application Regulatory & Infrastructure Compliance Items
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
  visual_inspection_json TEXT NOT NULL DEFAULT '{}',
  officer_observation TEXT,
  additional_evidence_requested INTEGER NOT NULL DEFAULT 0,
  additional_evidence_note TEXT,
  physical_inspection_flagged INTEGER NOT NULL DEFAULT 0,
  reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE(application_id, requirement_id)
);

CREATE INDEX IF NOT EXISTS idx_app_compliance_app ON application_compliance_items(application_id);

-- 10. Persisted In-App Notifications / Alerts (Scoped by Role & Institution; IN_APP_ONLY)
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
  is_read INTEGER NOT NULL DEFAULT 0,
  read_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  read_at TEXT,
  is_synthetic_demo INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_role ON in_app_notifications(recipient_role, is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_inst ON in_app_notifications(recipient_institution_id, is_read);
