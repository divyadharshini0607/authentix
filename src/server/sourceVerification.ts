/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Provider-Adapter Source Verification Module
 *
 * Supported Methods:
 * - SANDBOX_ISSUER_API        (Deterministic synthetic sandbox registry — marked isSandboxDemo = true)
 * - REFERENCE_LOOKUP          (Deterministic synthetic reference lookup — marked isSandboxDemo = true)
 * - QR_SIGNATURE_CHECK        (HMAC-SHA256 QR token verifier — marked isSandboxDemo = true; never accepts bare unsigned QR)
 * - DIGITAL_SIGNATURE         (Inspects PDF /Type /Sig + /ByteRange container; requires configured CA trust bundle for VERIFIED)
 * - OFFICIAL_API              (Adapter stub for live issuer REST gateway; returns honest SOURCE_UNAVAILABLE when unconfigured)
 * - OFFICIAL_PORTAL           (Adapter stub for live state/central portal check; returns honest SOURCE_UNAVAILABLE when unconfigured)
 * - DIGITAL_REPOSITORY        (Adapter stub for DigiLocker / NAD repository; returns honest SOURCE_UNAVAILABLE when unconfigured)
 * - MANUAL_OFFICER_VERIFICATION (Authorised officer attestation with reference & written notes — marked isSandboxDemo = false)
 *
 * Honesty Rule: No real external government portal is scraped or fabricated.
 */

import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type {
  SourceVerificationRecord,
  VerificationMethod,
  VerificationStatus,
} from '../shared/types.ts';
import { cleanEnvString } from './db.ts';
import {
  isQrSigningSecretConfigured,
  QrSigningSecretUnavailableError,
  verifyQrSignature,
} from './security.ts';

export interface RunSourceVerificationInput {
  applicationId: string;
  documentId: string;
  method: VerificationMethod;
  issuerName?: string;
  referenceNumber?: string;
  manualStatus?: VerificationStatus;
  notes?: string;
  actorUserId: string;
  simulateIssuerUnavailable?: boolean;
}

interface AdapterContext {
  db: DatabaseSync;
  input: RunSourceVerificationInput;
  doc: {
    id: string;
    application_id: string;
    declared_doc_type: string;
    original_filename: string;
    mime_type: string;
    metadata_json: string;
    inst_name: string;
  };
  certRef: string;
  qrToken: string;
  defaultIssuer: string;
  attemptedAt: string;
}

interface AdapterOutcome {
  status: VerificationStatus;
  isSandboxDemo: boolean;
  issuerName: string;
  sourceResponse: Record<string, unknown>;
  errorReason: string | null;
}

function parseDocMetadata(raw: string): Record<string, unknown> {
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function runManualOfficerAdapter(ctx: AdapterContext): AdapterOutcome {
  if (!ctx.input.manualStatus) {
    throw new Error('manualStatus is required when recording manual officer verification.');
  }
  return {
    status: ctx.input.manualStatus,
    isSandboxDemo: false,
    issuerName: ctx.input.issuerName || ctx.defaultIssuer || 'Direct Issuing Authority Contact',
    errorReason: null,
    sourceResponse: {
      adapterId: 'manual-officer-attestation',
      sandbox: false,
      verificationChannel: 'Authorised Officer Manual Check',
      recordedReference: ctx.certRef || null,
      recordedAt: ctx.attemptedAt,
    },
  };
}

function runQrSignatureAdapter(ctx: AdapterContext): AdapterOutcome {
  if (ctx.input.simulateIssuerUnavailable || process.env.ISSUER_SANDBOX_MODE === 'unavailable') {
    return {
      status: 'SOURCE_UNAVAILABLE',
      isSandboxDemo: true,
      issuerName: 'AUTHENTIX Demo QR Cryptographic Verifier (Sandbox)',
      errorReason: 'Sandbox issuer endpoint unreachable / timed out. Flagged for manual officer verification.',
      sourceResponse: { adapterId: 'sandbox-qr-hmac', sandbox: true, endpointStatus: 'HTTP_503_UNAVAILABLE' },
    };
  }

  const issuerName = 'AUTHENTIX Demo QR Cryptographic Verifier (Sandbox)';
  if (!isQrSigningSecretConfigured()) {
    return {
      status: 'SOURCE_UNAVAILABLE',
      isSandboxDemo: true,
      issuerName,
      errorReason:
        'QR signature check unavailable: strong QR_SIGNING_SECRET is not configured on this server. Routed for manual officer verification.',
      sourceResponse: { adapterId: 'sandbox-qr-hmac', sandbox: true, qrSigningConfigured: false },
    };
  }

  if (!ctx.qrToken || !ctx.qrToken.includes(':')) {
    return {
      status: 'MANUAL_REVIEW_REQUIRED',
      isSandboxDemo: true,
      issuerName,
      errorReason:
        'No structured cryptographic QR signature token found on document. Mere presence of a QR image or unsigned code never establishes authenticity; manual reference verification required.',
      sourceResponse: {
        adapterId: 'sandbox-qr-hmac',
        sandbox: true,
        qrPresent: Boolean(ctx.qrToken),
        signaturePresent: false,
        qrSigningConfigured: true,
      },
    };
  }

  const lastColon = ctx.qrToken.lastIndexOf(':');
  const payloadPart = ctx.qrToken.slice(0, lastColon);
  const sigPart = ctx.qrToken.slice(lastColon + 1);
  try {
    const sigValid = verifyQrSignature(payloadPart, sigPart);
    if (sigValid && (!ctx.certRef || payloadPart.includes(ctx.certRef))) {
      return {
        status: 'VERIFIED',
        isSandboxDemo: true,
        issuerName,
        errorReason: null,
        sourceResponse: {
          adapterId: 'sandbox-qr-hmac',
          sandbox: true,
          signatureValid: true,
          signedPayload: payloadPart,
          note: 'Demo HMAC-SHA256 QR token verified in sandbox.',
        },
      };
    }
    return {
      status: 'MISMATCH_DETECTED',
      isSandboxDemo: true,
      issuerName,
      errorReason: 'QR cryptographic signature failed verification or payload does not match certificate number.',
      sourceResponse: {
        adapterId: 'sandbox-qr-hmac',
        sandbox: true,
        signatureValid: false,
        observedPayload: payloadPart,
      },
    };
  } catch (err) {
    if (err instanceof QrSigningSecretUnavailableError) {
      return {
        status: 'SOURCE_UNAVAILABLE',
        isSandboxDemo: true,
        issuerName,
        errorReason:
          'QR signature check unavailable: strong QR_SIGNING_SECRET is not configured on this server. Routed for manual officer verification.',
        sourceResponse: { adapterId: 'sandbox-qr-hmac', sandbox: true, qrSigningConfigured: false },
      };
    }
    throw err;
  }
}

function runDigitalSignatureAdapter(ctx: AdapterContext): AdapterOutcome {
  const issuerName = ctx.input.issuerName || ctx.defaultIssuer || 'PDF PKCS#7 Digital Signature Inspector';
  if (ctx.doc.mime_type !== 'application/pdf') {
    return {
      status: 'MANUAL_REVIEW_REQUIRED',
      isSandboxDemo: false,
      issuerName,
      errorReason:
        'Digital signature inspection requires an original PDF container (/Type /Sig); uploaded file is a raster image.',
      sourceResponse: {
        adapterId: 'pdf-pkcs7-signature-inspector',
        sandbox: false,
        mimeType: ctx.doc.mime_type,
        embeddedSignaturePresent: false,
      },
    };
  }

  const meta = parseDocMetadata(ctx.doc.metadata_json);
  const hasEmbeddedSig = Boolean(meta.hasEmbeddedDigitalSignature || meta.hasEmbeddedPdfSignature);
  if (!hasEmbeddedSig) {
    return {
      status: 'MANUAL_REVIEW_REQUIRED',
      isSandboxDemo: false,
      issuerName,
      errorReason:
        'No embedded PDF cryptographic signature dictionary (/Type /Sig + /ByteRange) found in document byte stream. Routed for manual verification.',
      sourceResponse: {
        adapterId: 'pdf-pkcs7-signature-inspector',
        sandbox: false,
        embeddedSignaturePresent: false,
        caTrustChainVerified: false,
      },
    };
  }

  const caBundlePath = cleanEnvString(process.env.TRUSTED_CA_BUNDLE_PATH);
  if (!caBundlePath) {
    return {
      status: 'VERIFICATION_PENDING',
      isSandboxDemo: false,
      issuerName,
      errorReason:
        'Embedded PDF signature dictionary (/Type /Sig) detected, but TRUSTED_CA_BUNDLE_PATH (CCA India Root CA + OCSP/CRL verifier) is not configured in this environment. Signature container presence alone is NOT treated as verified.',
      sourceResponse: {
        adapterId: 'pdf-pkcs7-signature-inspector',
        sandbox: false,
        embeddedSignaturePresent: true,
        caTrustChainVerified: false,
        caBundleConfigured: false,
      },
    };
  }

  return {
    status: 'VERIFICATION_PENDING',
    isSandboxDemo: false,
    issuerName,
    errorReason:
      'Embedded PDF signature dictionary detected; offline PKCS#7 certificate revocation check requires manual officer confirmation.',
    sourceResponse: {
      adapterId: 'pdf-pkcs7-signature-inspector',
      sandbox: false,
      embeddedSignaturePresent: true,
      caTrustChainVerified: false,
      caBundleConfigured: true,
    },
  };
}

function runUnconfiguredLiveOfficialAdapter(ctx: AdapterContext): AdapterOutcome {
  const methodLabels: Record<'OFFICIAL_API' | 'OFFICIAL_PORTAL' | 'DIGITAL_REPOSITORY', { name: string; envKey: string; adapterId: string }> = {
    OFFICIAL_API: {
      name: 'Live Statutory Authority API Gateway',
      envKey: 'OFFICIAL_ISSUER_API_URL',
      adapterId: 'official-authority-rest-gateway',
    },
    OFFICIAL_PORTAL: {
      name: 'State / Central Regulatory Portal Lookup',
      envKey: 'OFFICIAL_PORTAL_GATEWAY_URL',
      adapterId: 'official-portal-lookup-adapter',
    },
    DIGITAL_REPOSITORY: {
      name: 'National Academic Depository / DigiLocker Connector',
      envKey: 'NAD_DIGILOCKER_API_URL',
      adapterId: 'digital-repository-connector',
    },
  };
  const info = methodLabels[ctx.input.method as 'OFFICIAL_API' | 'OFFICIAL_PORTAL' | 'DIGITAL_REPOSITORY'];
  const configuredUrl = cleanEnvString(process.env[info.envKey]);

  return {
    status: 'SOURCE_UNAVAILABLE',
    isSandboxDemo: false,
    issuerName: ctx.input.issuerName || ctx.defaultIssuer || info.name,
    errorReason: configuredUrl
      ? `Live authority connector (${info.name}) could not reach upstream partner endpoint or lacks mTLS credentials. No government response was fabricated; complete verification manually.`
      : `Live external authority integration (${ctx.input.method}) is not configured (${info.envKey} unset). No external government result was fabricated; record Manual Officer Verification or run the explicitly labelled Sandbox Issuer API for synthetic fixtures.`,
    sourceResponse: {
      adapterId: info.adapterId,
      sandbox: false,
      liveEndpointConfigured: Boolean(configuredUrl),
      requestedReference: ctx.certRef || null,
      fallbackAction: 'MANUAL_OFFICER_VERIFICATION',
    },
  };
}

function runSandboxRegistryAdapter(ctx: AdapterContext): AdapterOutcome {
  if (ctx.input.simulateIssuerUnavailable || process.env.ISSUER_SANDBOX_MODE === 'unavailable') {
    return {
      status: 'SOURCE_UNAVAILABLE',
      isSandboxDemo: true,
      issuerName: ctx.input.issuerName || ctx.defaultIssuer || 'Sandbox Regulatory Registry',
      errorReason: 'Sandbox issuer endpoint unreachable / timed out. Flagged for manual officer verification.',
      sourceResponse: {
        adapterId: ctx.input.method === 'REFERENCE_LOOKUP' ? 'sandbox-reference-lookup' : 'sandbox-issuer-api',
        sandbox: true,
        endpointStatus: 'HTTP_503_UNAVAILABLE',
      },
    };
  }

  if (!ctx.certRef) {
    return {
      status: 'MANUAL_REVIEW_REQUIRED',
      isSandboxDemo: true,
      issuerName: ctx.input.issuerName || ctx.defaultIssuer || 'Sandbox Regulatory Registry',
      errorReason: 'No certificate reference number available for registry lookup.',
      sourceResponse: {
        adapterId: ctx.input.method === 'REFERENCE_LOOKUP' ? 'sandbox-reference-lookup' : 'sandbox-issuer-api',
        sandbox: true,
        lookupKey: null,
      },
    };
  }

  const regRow = ctx.db
    .prepare('SELECT * FROM sandbox_issuer_registry WHERE reference_number = ?')
    .get(ctx.certRef) as
    | {
        issuer_code: string;
        issuer_name: string;
        reference_number: string;
        institution_name: string;
        doc_type: string;
        issued_date: string;
        expiry_date: string | null;
        status_simulation: VerificationStatus;
        payload_json: string;
      }
    | undefined;

  if (!regRow) {
    return {
      status: 'MANUAL_REVIEW_REQUIRED',
      isSandboxDemo: true,
      issuerName: ctx.input.issuerName || ctx.defaultIssuer || 'Sandbox Regulatory Registry',
      errorReason: `Reference '${ctx.certRef}' not found in Sandbox Issuer Registry; manual verification required.`,
      sourceResponse: {
        adapterId: ctx.input.method === 'REFERENCE_LOOKUP' ? 'sandbox-reference-lookup' : 'sandbox-issuer-api',
        sandbox: true,
        lookupKey: ctx.certRef,
        found: false,
      },
    };
  }

  const issuerName = `${regRow.issuer_name} [SANDBOX FIXTURE]`;
  const status = regRow.status_simulation;
  let extraPayload: Record<string, unknown> = {};
  try {
    extraPayload = JSON.parse(regRow.payload_json) as Record<string, unknown>;
  } catch {
    extraPayload = {};
  }

  let errorReason: string | null = null;
  if (status === 'SOURCE_UNAVAILABLE') {
    errorReason = 'Simulated upstream authority gateway downtime in sandbox fixture.';
  } else if (status === 'MISMATCH_DETECTED') {
    errorReason = 'Sandbox issuer record attributes conflict with submitted document values.';
  } else if (status === 'EXPIRED') {
    errorReason = `Sandbox issuer record confirms certificate expired on ${regRow.expiry_date}.`;
  }

  return {
    status,
    isSandboxDemo: true,
    issuerName,
    errorReason,
    sourceResponse: {
      adapterId: ctx.input.method === 'REFERENCE_LOOKUP' ? 'sandbox-reference-lookup' : 'sandbox-issuer-api',
      sandbox: true,
      notice: 'Deterministic sandbox demonstration response — NOT a live government API call.',
      registryReference: regRow.reference_number,
      registeredInstitution: regRow.institution_name,
      issuedDate: regRow.issued_date,
      expiryDate: regRow.expiry_date,
      ...extraPayload,
    },
  };
}

export function executeSourceVerification(
  db: DatabaseSync,
  input: RunSourceVerificationInput
): SourceVerificationRecord {
  const doc = db
    .prepare(
      `SELECT d.id, d.application_id, d.declared_doc_type, d.original_filename,
              d.mime_type, d.metadata_json, i.name AS inst_name
       FROM documents d
       JOIN applications a ON a.id = d.application_id
       JOIN institutions i ON i.id = a.institution_id
       WHERE d.id = ? AND d.application_id = ?`
    )
    .get(input.documentId, input.applicationId) as AdapterContext['doc'] | undefined;

  if (!doc) {
    throw new Error('Target document not found for this application.');
  }

  const fields = db
    .prepare('SELECT field_name, field_value FROM extracted_fields WHERE document_id = ?')
    .all(input.documentId) as Array<{ field_name: string; field_value: string }>;
  const fMap = new Map(fields.map((f) => [f.field_name, f.field_value]));

  const certRef = (input.referenceNumber || fMap.get('certificate_number') || '').trim();
  const qrToken = (fMap.get('qr_verification_code') || '').trim();
  const attemptedAt = new Date().toISOString();
  const id = `SVR-${crypto.randomUUID()}`;

  const adapterCtx: AdapterContext = {
    db,
    input,
    doc,
    certRef,
    qrToken,
    defaultIssuer: fMap.get('issuing_authority') || '',
    attemptedAt,
  };

  let outcome: AdapterOutcome;
  switch (input.method) {
    case 'MANUAL_OFFICER_VERIFICATION':
      outcome = runManualOfficerAdapter(adapterCtx);
      break;
    case 'QR_SIGNATURE_CHECK':
      outcome = runQrSignatureAdapter(adapterCtx);
      break;
    case 'DIGITAL_SIGNATURE':
      outcome = runDigitalSignatureAdapter(adapterCtx);
      break;
    case 'OFFICIAL_API':
    case 'OFFICIAL_PORTAL':
    case 'DIGITAL_REPOSITORY':
      outcome = runUnconfiguredLiveOfficialAdapter(adapterCtx);
      break;
    case 'SANDBOX_ISSUER_API':
    case 'REFERENCE_LOOKUP':
    default:
      outcome = runSandboxRegistryAdapter(adapterCtx);
      break;
  }

  db.prepare(
    `INSERT INTO source_verifications (
      id, application_id, document_id, verification_method, issuer_name,
      reference_number, is_sandbox_demo, status, source_response_json,
      error_reason, verified_by, notes, attempted_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    input.applicationId,
    input.documentId,
    input.method,
    outcome.issuerName,
    certRef || null,
    outcome.isSandboxDemo ? 1 : 0,
    outcome.status,
    JSON.stringify(outcome.sourceResponse),
    outcome.errorReason,
    input.actorUserId,
    input.notes || null,
    attemptedAt
  );

  // Update the document's current verification_status in the database
  db.prepare('UPDATE documents SET verification_status = ?, updated_at = ? WHERE id = ?').run(
    outcome.status,
    attemptedAt,
    input.documentId
  );

  return {
    id,
    applicationId: input.applicationId,
    documentId: input.documentId,
    verificationMethod: input.method,
    issuerName: outcome.issuerName,
    referenceNumber: certRef || null,
    isSandboxDemo: outcome.isSandboxDemo,
    status: outcome.status,
    sourceResponse: outcome.sourceResponse,
    errorReason: outcome.errorReason,
    verifiedBy: input.actorUserId,
    notes: input.notes || null,
    attemptedAt,
  };
}
