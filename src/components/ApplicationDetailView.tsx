import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  CheckCircle2,
  Download,
  Edit3,
  FileText,
  RefreshCw,
  ShieldAlert,
  Upload,
} from 'lucide-react';
import {
  correctFieldApi,
  downloadAuthenticatedBlob,
  fetchApplicationDetail,
  fetchAuditLogsApi,
  fetchDocumentPreviewObjectUrl,
  fetchSampleFixtures,
  reEvaluateApplicationApi,
  recordOfficerActionApi,
  reprocessDocumentOcrApi,
  resubmitApplicationApi,
  reviewComplianceItemApi,
  uploadApplicationDocument,
  verifyDocumentSourceApi,
} from '../client/api.ts';
import {
  COMPLIANCE_DOMAIN_LABELS,
  COMPLIANCE_STATUS_LABELS,
  complianceColorClass,
  DOC_TYPE_LABELS,
  EPISTEMIC_LABELS,
  formatBytes,
  formatCategoryDisplay,
  formatTimestamp,
  formatVerificationOrigin,
  LIFECYCLE_LABELS,
  lifecycleColorClass,
  priorityColorClass,
  severityColorClass,
  STATUS_LABELS,
  statusColorClass,
  VERIFICATION_METHOD_LABELS,
  VERIFICATION_STATUS_LABELS,
  verificationColorClass,
} from '../client/formatters.ts';
import type {
  ApplicationComplianceItemRecord,
  ApplicationDetail,
  AuditLogRecord,
  ComplianceItemStatus,
  DocumentType,
  UserProfile,
  VerificationMethod,
  VerificationStatus,
} from '../shared/types.ts';

interface ApplicationDetailViewProps {
  applicationId: string;
  user: UserProfile;
  demoMode?: boolean;
  onBack: () => void;
  onOpenReport: (applicationId: string) => void;
  onNotificationsChanged?: () => void;
}

type DetailTab = 'DOCUMENTS' | 'FINDINGS' | 'COMPLIANCE' | 'OFFICER_REVIEW' | 'TRUST_BREAKDOWN';

export function ApplicationDetailView({
  applicationId,
  user,
  demoMode = false,
  onBack,
  onOpenReport,
  onNotificationsChanged,
}: ApplicationDetailViewProps) {
  const [detail, setDetail] = useState<ApplicationDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<DetailTab>('DOCUMENTS');
  const [selectedDocId, setSelectedDocId] = useState<string | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);

  // Upload & Reprocess state
  const [uploadDocType, setUploadDocType] = useState<DocumentType>('FIRE_SAFETY_CERTIFICATE');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadNotice, setUploadNotice] = useState<string | null>(null);
  const [reprocessBusyDocId, setReprocessBusyDocId] = useState<string | null>(null);
  const [sampleFixtures, setSampleFixtures] = useState<
    Array<{ filename: string; sizeBytes: number; description: string }>
  >([]);

  // Rectification & Resubmission state
  const [resubmitSummary, setResubmitSummary] = useState('');
  const [resubmitBusy, setResubmitBusy] = useState(false);

  // Inline Field Correction State
  const [editingFieldId, setEditingFieldId] = useState<string | null>(null);
  const [editFieldValue, setEditFieldValue] = useState('');
  const [editFieldNote, setEditFieldNote] = useState('');
  const [fieldActionBusy, setFieldActionBusy] = useState(false);

  // Source Verification Form State
  const [verifMethod, setVerifMethod] = useState<VerificationMethod>('SANDBOX_ISSUER_API');
  const [manualStatus, setManualStatus] = useState<VerificationStatus>('VERIFIED');
  const [manualIssuer, setManualIssuer] = useState('');
  const [manualRef, setManualRef] = useState('');
  const [manualNotes, setManualNotes] = useState('');
  const [verifBusy, setVerifBusy] = useState(false);
  const [verifFeedback, setVerifFeedback] = useState<string | null>(null);

  // Compliance Item Review State
  const [reviewingItemId, setReviewingItemId] = useState<string | null>(null);
  const [itemStatus, setItemStatus] = useState<ComplianceItemStatus>('SATISFIED');
  const [itemObservation, setItemObservation] = useState('');
  const [itemRequestEvidence, setItemRequestEvidence] = useState(false);
  const [itemEvidenceNote, setItemEvidenceNote] = useState('');
  const [itemFlagInspection, setItemFlagInspection] = useState(false);
  const [itemBusy, setItemBusy] = useState(false);

  // Officer Review Form State
  const [officerActionType, setOfficerActionType] = useState<
    | 'ADD_REVIEW_NOTE'
    | 'MARK_DOCUMENT_VERIFIED'
    | 'RECORD_MISMATCH'
    | 'REQUEST_CLARIFICATION'
    | 'REQUEST_ADDITIONAL_EVIDENCE'
    | 'FLAG_PHYSICAL_INSPECTION'
    | 'CLEAR_PHYSICAL_INSPECTION'
    | 'FINAL_DECISION_APPROVE'
    | 'FINAL_DECISION_REJECT'
    | 'REOPEN_APPLICATION'
  >('ADD_REVIEW_NOTE');
  const [officerTargetDocId, setOfficerTargetDocId] = useState<string>('');
  const [officerRationale, setOfficerRationale] = useState('');
  const [officerBusy, setOfficerBusy] = useState(false);
  const [officerMessage, setOfficerMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Finding resolution inline state
  const [resolvingFindingId, setResolvingFindingId] = useState<string | null>(null);
  const [findingResolutionNote, setFindingResolutionNote] = useState('');

  // Connected Application Audit History (Officers, Auditors, Admins)
  const [appAuditLogs, setAppAuditLogs] = useState<AuditLogRecord[]>([]);

  const isOfficerOrAdmin = user.role === 'REVIEW_OFFICER' || user.role === 'ADMIN';
  const canReview = ['REVIEW_OFFICER', 'SENIOR_AUDITOR', 'ADMIN'].includes(user.role);
  const canReopen = user.role === 'SENIOR_AUDITOR' || user.role === 'ADMIN';
  const canUpload = user.role !== 'SENIOR_AUDITOR';

  const notifyAlertsChanged = () => {
    if (onNotificationsChanged) {
      onNotificationsChanged();
    }
  };

  const refreshAppAuditHistory = async (targetAppId: string) => {
    if (!canReview) return;
    try {
      const res = await fetchAuditLogsApi({ resourceId: targetAppId, limit: 30 });
      setAppAuditLogs(res.logs);
    } catch {
      // non-blocking
    }
  };

  const loadDetail = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchApplicationDetail(applicationId);
      setDetail(data);
      if (data.documents.length > 0 && !selectedDocId) {
        setSelectedDocId(data.documents[0].id);
        setOfficerTargetDocId(data.documents[0].id);
      }
      await refreshAppAuditHistory(applicationId);
    } catch (err) {
      setError((err as Error).message || 'Failed to load application details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDetail();
    if (demoMode) {
      fetchSampleFixtures()
        .then((res) => setSampleFixtures(res.fixtures))
        .catch(() => {});
    } else {
      setSampleFixtures([]);
    }
  }, [applicationId, demoMode]);

  const selectedDoc = detail?.documents.find((d) => d.id === selectedDocId) || detail?.documents[0] || null;

  useEffect(() => {
    let revokedUrl: string | null = null;
    let active = true;
    setPreviewError(null);
    if (!selectedDoc) {
      setPreviewUrl(null);
      return;
    }

    fetchDocumentPreviewObjectUrl(selectedDoc.id)
      .then((url) => {
        if (!active) {
          URL.revokeObjectURL(url);
          return;
        }
        revokedUrl = url;
        setPreviewUrl(url);
      })
      .catch((err) => {
        if (active) {
          setPreviewUrl(null);
          setPreviewError((err as Error).message || 'Preview unavailable');
        }
      });

    return () => {
      active = false;
      if (revokedUrl) URL.revokeObjectURL(revokedUrl);
    };
  }, [selectedDoc?.id]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUploadError(null);
    setUploadNotice(null);
    const file = e.target.files?.[0] || null;
    if (!file) {
      setSelectedFile(null);
      return;
    }
    const lower = file.name.toLowerCase();
    if (!/\.(pdf|png|jpg|jpeg)$/.test(lower)) {
      setUploadError('Invalid file format. Only PDF (.pdf), PNG (.png), and JPEG (.jpg/.jpeg) are permitted.');
      setSelectedFile(null);
      return;
    }
    if (file.size === 0) {
      setUploadError('Selected file is empty (0 bytes).');
      setSelectedFile(null);
      return;
    }
    if (file.size > 15 * 1024 * 1024) {
      setUploadError('File exceeds maximum allowed size of 15 MB.');
      setSelectedFile(null);
      return;
    }
    setSelectedFile(file);
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setUploadError(null);
    setUploadNotice(null);

    if (!selectedFile) {
      setUploadError('Select a valid PDF, PNG, or JPEG file before uploading.');
      return;
    }

    setUploadProgress(5);
    try {
      const res = await uploadApplicationDocument({
        applicationId,
        file: selectedFile,
        declaredDocType: uploadDocType,
        onProgress: (pct) => setUploadProgress(pct),
      });
      setDetail(res.application);
      setSelectedDocId(res.document.id);
      setOfficerTargetDocId(res.document.id);
      setSelectedFile(null);
      setUploadNotice(
        res.processingWarning
          ? `Stored & hashed (${res.document.sha256Hash.slice(0, 12)}...). Note: ${res.processingWarning}`
          : `Uploaded, hashed (${res.document.sha256Hash.slice(0, 12)}...), and validated via ${res.document.ocrEngine}.`
      );
      await refreshAppAuditHistory(applicationId);
      notifyAlertsChanged();
    } catch (err) {
      setUploadError((err as Error).message || 'Upload failed.');
    } finally {
      setUploadProgress(null);
    }
  };

  const handleReprocessDoc = async (docId: string) => {
    setReprocessBusyDocId(docId);
    setOfficerMessage(null);
    try {
      const res = await reprocessDocumentOcrApi(applicationId, docId);
      setDetail(res.application);
      setOfficerMessage({
        type: 'ok',
        text: res.processingWarning
          ? `Reprocessed OCR (${res.document?.ocrStatus || 'UPDATED'}): ${res.processingWarning}`
          : `Reprocessed OCR extraction successfully via ${res.document?.ocrEngine || 'pipeline'} and re-evaluated rules.`,
      });
      await refreshAppAuditHistory(applicationId);
    } catch (err) {
      setOfficerMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setReprocessBusyDocId(null);
    }
  };

  const handleResubmitApplication = async (e: React.FormEvent) => {
    e.preventDefault();
    setOfficerMessage(null);
    if (resubmitSummary.trim().length < 10) {
      setOfficerMessage({
        type: 'err',
        text: 'Provide at least 10 characters summarising the rectified documents or updated evidence.',
      });
      return;
    }
    setResubmitBusy(true);
    try {
      const updated = await resubmitApplicationApi(applicationId, {
        resubmissionSummary: resubmitSummary.trim(),
      });
      setDetail(updated);
      setResubmitSummary('');
      setOfficerMessage({
        type: 'ok',
        text: `Application resubmitted for officer scrutiny (Submission Cycle #${updated.submissionCycle}). Earlier findings were preserved in history.`,
      });
      await refreshAppAuditHistory(applicationId);
      notifyAlertsChanged();
    } catch (err) {
      setOfficerMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setResubmitBusy(false);
    }
  };

  const handleFieldCorrectionSave = async (fieldId: string) => {
    if (!selectedDoc) return;
    if (editFieldNote.trim().length < 5) {
      setOfficerMessage({ type: 'err', text: 'Provide at least 5 characters explaining the field correction.' });
      return;
    }
    setFieldActionBusy(true);
    setOfficerMessage(null);
    try {
      const updated = await correctFieldApi(
        selectedDoc.id,
        fieldId,
        editFieldValue.trim(),
        editFieldNote.trim()
      );
      setDetail(updated);
      setEditingFieldId(null);
      setEditFieldNote('');
      setOfficerMessage({
        type: 'ok',
        text: 'Persisted officer field correction, recalculated compliance rules, and logged audit event.',
      });
      await refreshAppAuditHistory(applicationId);
    } catch (err) {
      setOfficerMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setFieldActionBusy(false);
    }
  };

  const handleRunSourceVerification = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedDoc) return;
    setVerifBusy(true);
    setVerifFeedback(null);
    try {
      const res = await verifyDocumentSourceApi(applicationId, selectedDoc.id, {
        method: verifMethod,
        issuerName: manualIssuer.trim() || undefined,
        referenceNumber: manualRef.trim() || undefined,
        manualStatus: verifMethod === 'MANUAL_OFFICER_VERIFICATION' ? manualStatus : undefined,
        notes: manualNotes.trim() || undefined,
      });
      setDetail(res.application);
      setManualNotes('');
      setVerifFeedback(
        `[${formatVerificationOrigin(res.verification)}] Outcome: ${
          VERIFICATION_STATUS_LABELS[res.verification.status]
        }${res.verification.errorReason ? ` — ${res.verification.errorReason}` : ''}${
          res.verification.notes ? ` (${res.verification.notes})` : ''
        }`
      );
      await refreshAppAuditHistory(applicationId);
      notifyAlertsChanged();
    } catch (err) {
      setVerifFeedback(`Error: ${(err as Error).message}`);
    } finally {
      setVerifBusy(false);
    }
  };

  const startReviewComplianceItem = (ci: ApplicationComplianceItemRecord) => {
    setReviewingItemId(ci.id);
    setItemStatus(ci.complianceStatus);
    setItemObservation(ci.officerObservation || '');
    setItemRequestEvidence(ci.additionalEvidenceRequested);
    setItemEvidenceNote(ci.additionalEvidenceNote || '');
    setItemFlagInspection(ci.physicalInspectionFlagged);
  };

  const handleSaveComplianceItem = async (e: React.FormEvent, itemId: string) => {
    e.preventDefault();
    if (itemObservation.trim().length < 5) {
      setOfficerMessage({
        type: 'err',
        text: 'Provide an officer observation of at least 5 characters when recording a compliance assessment.',
      });
      return;
    }
    setItemBusy(true);
    setOfficerMessage(null);
    try {
      const updated = await reviewComplianceItemApi(applicationId, itemId, {
        complianceStatus: itemStatus,
        officerObservation: itemObservation.trim(),
        additionalEvidenceRequested: itemRequestEvidence,
        additionalEvidenceNote: itemRequestEvidence ? itemEvidenceNote.trim() || null : null,
        physicalInspectionFlagged: itemFlagInspection,
      });
      setDetail(updated);
      setReviewingItemId(null);
      setOfficerMessage({
        type: 'ok',
        text: 'Persisted compliance requirement assessment, updated application lifecycle state, and recorded audit entry.',
      });
      await refreshAppAuditHistory(applicationId);
      notifyAlertsChanged();
    } catch (err) {
      setOfficerMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setItemBusy(false);
    }
  };

  const handleOfficerActionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setOfficerMessage(null);
    setOfficerBusy(true);
    try {
      const needsDoc =
        officerActionType === 'MARK_DOCUMENT_VERIFIED' || officerActionType === 'RECORD_MISMATCH';
      const updated = await recordOfficerActionApi(applicationId, {
        actionType: officerActionType,
        documentId: needsDoc ? officerTargetDocId || selectedDoc?.id || null : null,
        rationale: officerRationale.trim(),
      });
      setDetail(updated);
      setOfficerRationale('');
      setOfficerMessage({
        type: 'ok',
        text: `Persisted officer action (${officerActionType}) and updated audit trail.`,
      });
      await refreshAppAuditHistory(applicationId);
      notifyAlertsChanged();
    } catch (err) {
      setOfficerMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setOfficerBusy(false);
    }
  };

  const handleResolveFinding = async (findingId: string) => {
    if (findingResolutionNote.trim().length < 5) {
      setOfficerMessage({ type: 'err', text: 'Provide at least 5 characters explaining the finding resolution.' });
      return;
    }
    setOfficerBusy(true);
    try {
      const updated = await recordOfficerActionApi(applicationId, {
        actionType: 'RESOLVE_FINDING',
        findingId,
        rationale: findingResolutionNote.trim(),
      });
      setDetail(updated);
      setResolvingFindingId(null);
      setFindingResolutionNote('');
      setOfficerMessage({
        type: 'ok',
        text: 'Persisted officer finding resolution and updated advisory trust indicator.',
      });
      await refreshAppAuditHistory(applicationId);
    } catch (err) {
      setOfficerMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setOfficerBusy(false);
    }
  };

  const handleReEvaluate = async () => {
    try {
      const updated = await reEvaluateApplicationApi(applicationId);
      setDetail(updated);
      setOfficerMessage({
        type: 'ok',
        text: 'Re-evaluated active regulatory rules and recalculated advisory trust indicator.',
      });
      await refreshAppAuditHistory(applicationId);
    } catch (err) {
      setOfficerMessage({ type: 'err', text: (err as Error).message });
    }
  };

  if (loading && !detail) {
    return (
      <div className="space-y-4" aria-busy="true">
        <div className="h-8 w-56 bg-slate-200 rounded animate-pulse" />
        <div className="h-40 bg-white border border-slate-200 rounded-lg animate-pulse" />
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div role="alert" className="bg-white border border-red-300 rounded-lg p-6 space-y-3">
        <h2 className="text-base font-semibold text-red-800">Unable to open application</h2>
        <p className="text-sm text-red-700">{error || 'Application not found.'}</p>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={loadDetail}
            className="px-4 py-2 rounded-md bg-blue-900 text-white text-sm font-medium hover:bg-blue-800"
          >
            Retry
          </button>
          <button
            type="button"
            onClick={onBack}
            className="px-4 py-2 rounded-md border border-slate-300 bg-white text-slate-800 text-sm font-medium hover:bg-slate-50"
          >
            Back to Applications
          </button>
        </div>
      </div>
    );
  }

  const verifiedFactsCount = detail.documents.filter((d) => d.verificationStatus === 'VERIFIED').length;
  const correctedFieldsCount = detail.documents.reduce(
    (acc, d) => acc + d.extractedFields.filter((ef) => ef.manuallyCorrected).length,
    0
  );
  const openRuleFlagsCount = detail.findings.filter(
    (f) => !f.resolvedByOfficer && f.findingCategory !== 'OCR_QUALITY'
  ).length;
  const unavailableChecksCount = detail.documents.filter(
    (d) =>
      d.verificationStatus === 'SOURCE_UNAVAILABLE' ||
      d.ocrStatus === 'UNAVAILABLE' ||
      d.ocrStatus === 'FAILED'
  ).length;
  const manualReviewDocsCount = detail.documents.filter(
    (d) =>
      d.verificationStatus === 'MANUAL_REVIEW_REQUIRED' ||
      d.verificationStatus === 'UNVERIFIED' ||
      d.verificationStatus === 'VERIFICATION_PENDING' ||
      d.ocrStatus === 'LOW_CONFIDENCE'
  ).length;

  const uploadedTypesSet = new Set<DocumentType>();
  for (const d of detail.documents) {
    uploadedTypesSet.add(d.declaredDocType);
    if (d.detectedDocType !== 'UNKNOWN_DOCUMENT') {
      uploadedTypesSet.add(d.detectedDocType);
    }
  }
  const checklistTypes = detail.requiredChecklistDocTypes || [];
  const complianceItems = detail.complianceItems || [];
  const satisfiedComplianceCount = complianceItems.filter((c) => c.complianceStatus === 'SATISFIED').length;

  return (
    <div className="space-y-6">
      {/* Top Context & Navigation Row */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-1.5 text-sm font-medium text-slate-600 hover:text-slate-900"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Application Queue</span>
        </button>

        <div className="flex items-center gap-3">
          {canReview && (
            <button
              type="button"
              onClick={handleReEvaluate}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md border border-slate-300 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Re-run Rules Engine</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => onOpenReport(detail.id)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-slate-900 text-xs font-semibold text-white hover:bg-slate-800 whitespace-nowrap shrink-0"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Validation Report &amp; CSV</span>
          </button>
        </div>
      </div>

      {/* Application Summary Header Panel */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 font-mono tabular-nums">
              <span className="font-semibold text-blue-900">{detail.applicationNumber}</span>
              <span aria-hidden="true">·</span>
              <span>{formatCategoryDisplay(detail.category, detail.categoryCode)}</span>
              <span aria-hidden="true">·</span>
              <span>Session {detail.academicYear}</span>
              <span aria-hidden="true">·</span>
              <span>Cycle #{detail.submissionCycle || 1}</span>
              <span aria-hidden="true">·</span>
              <span className={priorityColorClass(detail.reviewPriority)}>
                {detail.reviewPriority} Priority
              </span>
              {demoMode && detail.isSyntheticDemo && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="text-amber-800">Sample Data (Dev)</span>
                </>
              )}
            </div>
            <h1 className="font-display text-2xl font-bold text-slate-900">
              {detail.institutionName}
            </h1>
            <p className="text-sm text-slate-600">
              Programs: {detail.programNames} · Permanent ID:{' '}
              <span className="font-mono">{detail.institution.aictePermanentId}</span>
            </p>
          </div>

          <div className="text-left sm:text-right space-y-1">
            <div className="text-xs text-slate-500">Current Workflow Status</div>
            <div className={`text-sm ${statusColorClass(detail.status)}`}>
              {STATUS_LABELS[detail.status]}
            </div>
            <div className={`text-xs ${lifecycleColorClass(detail.lifecycleStage)}`}>
              Lifecycle: {LIFECYCLE_LABELS[detail.lifecycleStage]}
            </div>
            <div className="text-xs font-mono tabular-nums text-slate-600">
              Advisory Trust Indicator:{' '}
              <span className="font-bold text-slate-900">
                {detail.trustScore !== null ? `${detail.trustScore}/100` : '—'}
              </span>{' '}
              ({detail.trustScoreVersion || 'v1.0'})
            </div>
          </div>
        </div>

        {/* Submission vs Master Record Cross-Check Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 pt-4 border-t border-slate-200 text-xs">
          <div>
            <div className="text-slate-500">Requested vs Master Intake</div>
            <div className="font-mono tabular-nums font-semibold text-slate-900 mt-0.5">
              {detail.requestedIntake} seats{' '}
              <span className="font-normal text-slate-500">
                (Master: {detail.institution.approvedIntake})
              </span>
            </div>
          </div>
          <div>
            <div className="text-slate-500">Submitted vs Master Land</div>
            <div className="font-mono tabular-nums font-semibold text-slate-900 mt-0.5">
              {detail.submittedLandAcres} acres{' '}
              <span className="font-normal text-slate-500">
                (Master: {detail.institution.landAreaAcres})
              </span>
            </div>
          </div>
          <div>
            <div className="text-slate-500">Submitted Built-Up Area</div>
            <div className="font-mono tabular-nums font-semibold text-slate-900 mt-0.5">
              {detail.submittedBuiltUpSqm} sqm{' '}
              <span className="font-normal text-slate-500">
                (Master: {detail.institution.builtUpAreaSqm})
              </span>
            </div>
          </div>
          <div>
            <div className="text-slate-500">Human Officer Final Decision</div>
            <div className="font-semibold text-slate-900 mt-0.5">
              {detail.finalOfficerDecision
                ? STATUS_LABELS[detail.finalOfficerDecision]
                : 'Awaiting Human Officer Decision'}
            </div>
          </div>
        </div>

        {/* Next Recommended Action & Physical Inspection Banner */}
        {(detail.nextRecommendedAction || detail.physicalInspectionRequired) && (
          <div className="pt-4 border-t border-slate-200 flex flex-wrap items-center justify-between gap-3 text-xs">
            {detail.nextRecommendedAction && (
              <div className="text-slate-700">
                <span className="font-semibold text-slate-900">Next Recommended Action: </span>
                {detail.nextRecommendedAction}
              </div>
            )}
            {detail.physicalInspectionRequired && (
              <div className="text-amber-800 font-semibold">
                Physical EVC Site Inspection Flagged
                {detail.physicalInspectionReason ? ` — ${detail.physicalInspectionReason}` : ''}
              </div>
            )}
          </div>
        )}

        {detail.resubmissionSummary && detail.submissionCycle > 1 && (
          <div className="pt-3 border-t border-slate-200 text-xs text-slate-700">
            <span className="font-semibold text-slate-900">
              Latest Rectification Summary (Cycle #{detail.submissionCycle}):{' '}
            </span>
            {detail.resubmissionSummary}{' '}
            <span className="font-mono text-slate-500">({formatTimestamp(detail.resubmittedAt)})</span>
          </div>
        )}

        {detail.finalOfficerDecision && detail.finalDecisionRationale && (
          <div className="pt-4 border-t border-slate-200 text-sm text-slate-700">
            <span className="font-semibold text-slate-900">Recorded Officer Decision Rationale: </span>
            {detail.finalDecisionRationale}{' '}
            <span className="text-xs font-mono text-slate-500">
              ({formatTimestamp(detail.finalDecisionAt)})
            </span>
          </div>
        )}
      </section>

      {/* Rectification & Resubmission Workflow Panel */}
      {detail.status === 'CLARIFICATION_REQUESTED' && !detail.finalOfficerDecision && canUpload && (
        <section
          aria-label="Rectification and Resubmission"
          className="bg-amber-50/70 border border-amber-300 rounded-lg p-5 space-y-3"
        >
          <div>
            <h2 className="font-display text-base font-semibold text-amber-950">
              Deficiency Rectification &amp; Resubmission Required
            </h2>
            <p className="text-xs text-amber-900 mt-0.5">
              Upload any missing or updated supporting documents under the Documents tab, then submit a
              rectification summary below to advance this filing to Cycle #{detail.submissionCycle + 1}{' '}
              for officer scrutiny. Earlier findings and officer notes are preserved in the audit history.
            </p>
          </div>
          <form onSubmit={handleResubmitApplication} className="space-y-3">
            <textarea
              rows={2}
              aria-label="Rectification summary"
              value={resubmitSummary}
              onChange={(e) => setResubmitSummary(e.target.value)}
              placeholder="Describe the uploaded replacement certificates, additional facility evidence, or rectified disclosures (min 10 chars)..."
              className="w-full rounded-md border border-amber-300 bg-white px-3 py-2 text-xs text-slate-900"
              required
            />
            <div className="flex items-center justify-end">
              <button
                type="submit"
                disabled={resubmitBusy}
                className="px-4 py-2 rounded-md bg-slate-900 text-white text-xs font-semibold hover:bg-slate-800 disabled:opacity-60"
              >
                {resubmitBusy
                  ? 'Resubmitting Filing...'
                  : `Submit Rectification & Advance to Cycle #${detail.submissionCycle + 1}`}
              </button>
            </div>
          </form>
        </section>
      )}

      {/* 4-Category Epistemic Verification Summary */}
      <section
        aria-label="Evidence Verification Classification"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 border border-slate-200 rounded-lg bg-white divide-y sm:divide-y-0 sm:divide-x divide-slate-200"
      >
        <div className="p-4 space-y-1">
          <div className="text-xs font-semibold text-emerald-800">1. Verified Facts</div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-900">
            {verifiedFactsCount} / {detail.documents.length}{' '}
            <span className="text-xs font-normal text-slate-500">docs verified</span>
          </div>
          <p className="text-xs text-slate-600 leading-snug">
            SHA-256 digests confirmed{correctedFieldsCount > 0 ? `; ${correctedFieldsCount} field(s) officer-verified` : ''}.
          </p>
        </div>

        <div className="p-4 space-y-1">
          <div className="text-xs font-semibold text-red-800">2. Rule-Based Flags</div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-900">
            {openRuleFlagsCount}{' '}
            <span className="text-xs font-normal text-slate-500">unresolved</span>
          </div>
          <p className="text-xs text-slate-600 leading-snug">
            Versioned checklist, expiry, cross-check, duplicate hash, or metadata flags.
          </p>
        </div>

        <div className="p-4 space-y-1">
          <div className="text-xs font-semibold text-amber-800">3. Unavailable Checks</div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-900">
            {unavailableChecksCount}{' '}
            <span className="text-xs font-normal text-slate-500">affected docs</span>
          </div>
          <p className="text-xs text-slate-600 leading-snug">
            Upstream source or raster OCR unavailable — never treated as verified or rejected.
          </p>
        </div>

        <div className="p-4 space-y-1">
          <div className="text-xs font-semibold text-blue-900">4. Manual-Review Requirements</div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-900">
            {manualReviewDocsCount}{' '}
            <span className="text-xs font-normal text-slate-500">pending officer check</span>
          </div>
          <p className="text-xs text-slate-600 leading-snug">
            {detail.finalOfficerDecision
              ? 'Final regulatory decision recorded by human officer.'
              : 'Human officer must inspect primary evidence and record final decision.'}
          </p>
        </div>
      </section>

      {/* Interactive Section Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div
          role="tablist"
          aria-label="Application Scrutiny Sections"
          className="inline-flex flex-wrap items-center gap-1 p-1 bg-slate-200/70 rounded-lg"
        >
          <button
            role="tab"
            aria-selected={activeTab === 'DOCUMENTS'}
            type="button"
            onClick={() => setActiveTab('DOCUMENTS')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'DOCUMENTS'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Documents &amp; Side-by-Side Review ({detail.documents.length})
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'FINDINGS'}
            type="button"
            onClick={() => setActiveTab('FINDINGS')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'FINDINGS'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Validation &amp; Anomaly Findings ({detail.openFindingsCount} open)
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'COMPLIANCE'}
            type="button"
            onClick={() => setActiveTab('COMPLIANCE')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'COMPLIANCE'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Infrastructure &amp; Compliance ({satisfiedComplianceCount}/{complianceItems.length})
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'OFFICER_REVIEW'}
            type="button"
            onClick={() => setActiveTab('OFFICER_REVIEW')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'OFFICER_REVIEW'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Officer Review &amp; Decision ({detail.officerReviews.length})
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'TRUST_BREAKDOWN'}
            type="button"
            onClick={() => setActiveTab('TRUST_BREAKDOWN')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'TRUST_BREAKDOWN'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Explainable Trust Indicator ({detail.trustScore ?? 0}/100)
          </button>
        </div>
      </div>

      {officerMessage && (
        <div
          role={officerMessage.type === 'err' ? 'alert' : 'status'}
          className={`rounded-lg border px-4 py-3 text-sm ${
            officerMessage.type === 'err'
              ? 'border-red-300 bg-red-50 text-red-800'
              : 'border-emerald-300 bg-emerald-50 text-emerald-900'
          }`}
        >
          {officerMessage.text}
        </div>
      )}

      {/* TAB 1: DOCUMENTS, CHECKLIST, UPLOAD & SIDE-BY-SIDE REVIEW */}
      {activeTab === 'DOCUMENTS' && (
        <div className="space-y-6">
          {/* Required Checklist Progress Strip */}
          {checklistTypes.length > 0 && (
            <section className="bg-white border border-slate-200 rounded-lg p-4 space-y-2.5">
              <div className="flex flex-wrap items-baseline justify-between gap-2 text-xs">
                <span className="font-semibold text-slate-900">
                  Category Mandatory Document Checklist (
                  {checklistTypes.filter((dt) => uploadedTypesSet.has(dt)).length}/{checklistTypes.length}{' '}
                  present)
                </span>
                <span className="text-slate-500">
                  Select a missing item to prefill the upload category below
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
                {checklistTypes.map((dt) => {
                  const present = uploadedTypesSet.has(dt);
                  return present ? (
                    <span key={dt} className="text-emerald-700 font-medium">
                      ✓ {DOC_TYPE_LABELS[dt]}
                    </span>
                  ) : (
                    <button
                      key={dt}
                      type="button"
                      onClick={() => setUploadDocType(dt)}
                      className="text-amber-800 font-semibold hover:underline"
                    >
                      Missing: {DOC_TYPE_LABELS[dt]}
                    </button>
                  );
                })}
              </div>
            </section>
          )}

          {/* Upload Panel */}
          {canUpload && !detail.finalOfficerDecision && (
            <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
              <div className="flex flex-wrap items-baseline justify-between gap-4">
                <div>
                  <h2 className="font-display text-base font-semibold text-slate-900">
                    Upload &amp; Authenticate Supporting Document
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Validates file signature (PDF, PNG, JPEG up to 15 MB), calculates SHA-256 hash, runs OCR &amp;
                    metadata inspection, and evaluates handbook rules.
                  </p>
                </div>

                {sampleFixtures.length > 0 && (
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="text-slate-500">Sample test fixtures:</span>
                    {sampleFixtures.slice(0, 4).map((sf) => (
                      <button
                        key={sf.filename}
                        type="button"
                        title={sf.description}
                        onClick={() =>
                          downloadAuthenticatedBlob(
                            `/api/sample-fixtures/${encodeURIComponent(sf.filename)}`,
                            sf.filename
                          )
                        }
                        className="inline-flex items-center gap-1 text-blue-800 hover:underline font-mono"
                      >
                        <Download className="w-3 h-3" />
                        <span>{sf.filename.replace('sample_', '')}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {uploadError && (
                <div role="alert" className="border border-red-300 bg-red-50 text-red-800 rounded p-3 text-sm">
                  {uploadError}
                </div>
              )}

              {uploadNotice && (
                <div
                  role="status"
                  className="border border-emerald-300 bg-emerald-50 text-emerald-900 rounded p-3 text-sm"
                >
                  {uploadNotice}
                </div>
              )}

              <form onSubmit={handleUploadSubmit} className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
                <div className="md:col-span-4">
                  <label htmlFor="upload-doctype" className="block text-xs font-medium text-slate-700 mb-1">
                    Declared Document Category
                  </label>
                  <select
                    id="upload-doctype"
                    value={uploadDocType}
                    onChange={(e) => setUploadDocType(e.target.value as DocumentType)}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm bg-white"
                  >
                    {Object.entries(DOC_TYPE_LABELS).map(([key, label]) => (
                      <option key={key} value={key}>
                        {label}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="md:col-span-5">
                  <label htmlFor="upload-file-input" className="block text-xs font-medium text-slate-700 mb-1">
                    Document File (.pdf, .png, .jpg)
                  </label>
                  <input
                    id="upload-file-input"
                    type="file"
                    accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg"
                    onChange={handleFileChange}
                    className="w-full text-sm text-slate-700 file:mr-3 file:rounded-md file:border file:border-slate-300 file:bg-slate-50 file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-slate-800 hover:file:bg-slate-100"
                  />
                </div>

                <div className="md:col-span-3">
                  <button
                    type="submit"
                    disabled={uploadProgress !== null}
                    className="w-full min-h-[40px] inline-flex items-center justify-center gap-2 rounded-md bg-blue-900 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60 whitespace-nowrap"
                  >
                    <Upload className="w-4 h-4 shrink-0" />
                    <span>
                      {uploadProgress !== null ? `Processing (${uploadProgress}%)` : 'Upload & Process'}
                    </span>
                  </button>
                </div>
              </form>
            </section>
          )}

          {/* Document Selector + Side-by-Side Viewer */}
          {detail.documents.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-lg p-10 text-center space-y-2">
              <p className="text-base font-semibold text-slate-900">No documents uploaded yet</p>
              <p className="text-sm text-slate-500">
                Upload PDF or scanned certificate files above to trigger SHA-256 hashing, OCR extraction, and
                compliance validation.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Document Strip */}
              <div className="bg-white border border-slate-200 rounded-lg divide-y divide-slate-200">
                {detail.documents.map((doc) => {
                  const isSelected = selectedDoc?.id === doc.id;
                  return (
                    <button
                      key={doc.id}
                      type="button"
                      onClick={() => {
                        setSelectedDocId(doc.id);
                        setOfficerTargetDocId(doc.id);
                      }}
                      className={`w-full px-5 py-3.5 text-left flex flex-wrap items-center justify-between gap-4 transition-colors ${
                        isSelected ? 'bg-blue-50/60' : 'hover:bg-slate-50'
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-slate-900 truncate">
                          {doc.originalFilename}
                        </div>
                        <div className="text-xs text-slate-500 mt-0.5 flex flex-wrap items-center gap-1.5">
                          <span>{DOC_TYPE_LABELS[doc.declaredDocType]}</span>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono tabular-nums">{formatBytes(doc.fileSizeBytes)}</span>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono tabular-nums">
                            SHA-256: {doc.sha256Hash.slice(0, 14)}...
                          </span>
                        </div>
                      </div>

                      <div className="text-right text-xs space-y-0.5 shrink-0">
                        <div className={verificationColorClass(doc.verificationStatus)}>
                          {VERIFICATION_STATUS_LABELS[doc.verificationStatus]}
                        </div>
                        <div className="text-slate-500 font-mono tabular-nums">
                          OCR: {doc.ocrStatus}
                          {doc.ocrConfidence !== null
                            ? ` (${Math.round(doc.ocrConfidence * 100)}%)`
                            : ''}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Split 2-Column Document Review Workbench */}
              {selectedDoc && (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
                  {/* Left 6 Cols: Stored Original File Preview + Metadata */}
                  <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-5 flex flex-col justify-between space-y-4">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between gap-4">
                        <div>
                          <h3 className="font-display text-sm font-semibold text-slate-900">
                            Primary Evidence Preview
                          </h3>
                          <p className="text-xs text-slate-500 font-mono truncate">
                            {selectedDoc.originalFilename} · {selectedDoc.pageCount} page(s)
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() =>
                            downloadAuthenticatedBlob(
                              `/api/documents/${encodeURIComponent(selectedDoc.id)}/file`,
                              selectedDoc.originalFilename
                            )
                          }
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-slate-300 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Download Original</span>
                        </button>
                      </div>

                      {previewError ? (
                        <div className="h-[460px] rounded border border-slate-200 bg-slate-50 flex items-center justify-center p-6 text-center text-sm text-slate-600">
                          {previewError}
                        </div>
                      ) : previewUrl ? (
                        selectedDoc.mimeType === 'application/pdf' ? (
                          <iframe
                            title={`Preview of ${selectedDoc.originalFilename}`}
                            src={previewUrl}
                            className="w-full h-[460px] rounded border border-slate-200 bg-slate-100"
                          />
                        ) : (
                          <div className="h-[460px] rounded border border-slate-200 bg-slate-100 flex items-center justify-center p-3 overflow-auto">
                            <img
                              src={previewUrl}
                              alt={`Scanned document ${selectedDoc.originalFilename}`}
                              referrerPolicy="no-referrer"
                              className="max-h-full max-w-full object-contain"
                            />
                          </div>
                        )
                      ) : (
                        <div className="h-[460px] rounded border border-slate-200 bg-slate-100 animate-pulse" />
                      )}
                    </div>

                    <div className="pt-3 border-t border-slate-200 space-y-1.5 text-xs">
                      <div className="font-semibold text-slate-800">
                        Cryptographic &amp; Container Metadata
                      </div>
                      <div className="font-mono text-slate-600 break-all">
                        SHA-256: {selectedDoc.sha256Hash}
                      </div>
                      <div className="text-slate-600">
                        Detected Type:{' '}
                        <span className="font-medium">{DOC_TYPE_LABELS[selectedDoc.detectedDocType]}</span>
                        {selectedDoc.classificationConfidence !== null &&
                        selectedDoc.classificationConfidence !== undefined
                          ? ` (${Math.round(selectedDoc.classificationConfidence * 100)}%)`
                          : ''}{' '}
                        · Engine: <span className="font-mono">{selectedDoc.ocrEngine}</span>
                        {selectedDoc.reprocessCount && selectedDoc.reprocessCount > 0
                          ? ` · Reprocessed ${selectedDoc.reprocessCount}x`
                          : ''}
                      </div>
                      {Boolean(selectedDoc.metadata.Producer || selectedDoc.metadata.Creator) && (
                        <div className="text-slate-600 font-mono">
                          Producer: {String(selectedDoc.metadata.Producer || '—')} · Creator:{' '}
                          {String(selectedDoc.metadata.Creator || '—')}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right 6 Cols: Extracted Fields, Corrections & Source Verification */}
                  <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-5 space-y-6">
                    {/* OCR Status Banner if Unavailable, Failed, or Low Confidence */}
                    {(selectedDoc.ocrStatus === 'UNAVAILABLE' ||
                      selectedDoc.ocrStatus === 'FAILED' ||
                      selectedDoc.ocrStatus === 'LOW_CONFIDENCE') && (
                      <div className="border border-amber-300 bg-amber-50 text-amber-900 rounded-md p-3.5 text-xs space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="font-semibold flex items-center gap-1.5">
                            <ShieldAlert className="w-4 h-4 shrink-0" />
                            <span>
                              OCR Status: {selectedDoc.ocrStatus} — Human Visual Inspection Required
                            </span>
                          </div>
                          {canUpload && !detail.finalOfficerDecision && (
                            <button
                              type="button"
                              disabled={reprocessBusyDocId === selectedDoc.id}
                              onClick={() => handleReprocessDoc(selectedDoc.id)}
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 text-white font-semibold hover:bg-slate-800 disabled:opacity-60"
                            >
                              <RefreshCw className="w-3 h-3" />
                              <span>
                                {reprocessBusyDocId === selectedDoc.id ? 'Reprocessing...' : 'Retry OCR'}
                              </span>
                            </button>
                          )}
                        </div>
                        <p>
                          {selectedDoc.ocrStatus === 'UNAVAILABLE'
                            ? 'Raster OCR binary (tesseract-ocr) is not installed for raw scan extraction. No values were fabricated; inspect the image directly on the left.'
                            : selectedDoc.ocrStatus === 'FAILED'
                              ? `Extraction failed (${selectedDoc.lastErrorReason || 'pipeline error'}). Retry OCR or inspect the stored document directly.`
                              : `Low extraction confidence (${Math.round(
                                  (selectedDoc.ocrConfidence ?? 0) * 100
                                )}%). Verify extracted fields against the scan before recording a decision.`}
                        </p>
                      </div>
                    )}

                    {/* Extracted Fields Table */}
                    <div className="space-y-2.5">
                      <div className="flex flex-wrap items-baseline justify-between gap-2">
                        <h3 className="font-display text-sm font-semibold text-slate-900">
                          Extracted Structured Fields ({selectedDoc.extractedFields.length})
                        </h3>
                        <div className="flex items-center gap-3 text-xs">
                          <span className="text-slate-500">
                            {isOfficerOrAdmin ? 'Officers may correct misread OCR values' : 'Read-only view'}
                          </span>
                          {canUpload && !detail.finalOfficerDecision && (
                            <button
                              type="button"
                              disabled={reprocessBusyDocId === selectedDoc.id}
                              onClick={() => handleReprocessDoc(selectedDoc.id)}
                              className="text-blue-800 hover:underline font-medium disabled:opacity-50"
                            >
                              {reprocessBusyDocId === selectedDoc.id ? 'Running OCR...' : 'Re-run OCR'}
                            </button>
                          )}
                        </div>
                      </div>

                      {selectedDoc.extractedFields.length === 0 ? (
                        <div className="border border-slate-200 rounded p-4 text-xs text-slate-500">
                          No structured fields automatically extracted from this document.
                        </div>
                      ) : (
                        <div className="divide-y divide-slate-200 border border-slate-200 rounded-md">
                          {selectedDoc.extractedFields.map((ef) => (
                            <div key={ef.id} className="p-3 space-y-2">
                              <div className="flex items-start justify-between gap-3">
                                <div className="min-w-0">
                                  <div className="text-xs font-mono text-slate-500">
                                    {ef.fieldName} · Page {ef.pageNumber}
                                    {ef.bbox ? ` · Region [${ef.bbox.join(', ')}]` : ''}
                                  </div>
                                  <div className="text-sm font-medium text-slate-900 break-words mt-0.5">
                                    {ef.fieldValue}
                                  </div>
                                  {ef.manuallyCorrected && (
                                    <div className="text-xs text-blue-800 mt-0.5">
                                      Corrected by officer: {ef.correctionNote}
                                    </div>
                                  )}
                                </div>

                                <div className="flex items-center gap-2 shrink-0">
                                  <span
                                    className={`text-xs font-mono tabular-nums ${
                                      ef.confidence < 0.75 ? 'text-amber-700 font-semibold' : 'text-slate-500'
                                    }`}
                                  >
                                    {Math.round(ef.confidence * 100)}%
                                  </span>
                                  {isOfficerOrAdmin && !detail.finalOfficerDecision && (
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setEditingFieldId(ef.id);
                                        setEditFieldValue(ef.fieldValue);
                                        setEditFieldNote('');
                                      }}
                                      aria-label={`Correct ${ef.fieldName}`}
                                      className="p-1 rounded text-slate-500 hover:text-slate-900 hover:bg-slate-100"
                                    >
                                      <Edit3 className="w-3.5 h-3.5" />
                                    </button>
                                  )}
                                </div>
                              </div>

                              {editingFieldId === ef.id && (
                                <div className="pt-2 border-t border-slate-100 space-y-2">
                                  <input
                                    type="text"
                                    value={editFieldValue}
                                    onChange={(e) => setEditFieldValue(e.target.value)}
                                    className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs"
                                    placeholder="Corrected value"
                                  />
                                  <input
                                    type="text"
                                    value={editFieldNote}
                                    onChange={(e) => setEditFieldNote(e.target.value)}
                                    className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs"
                                    placeholder="Reason for correction (min 5 chars)"
                                  />
                                  <div className="flex items-center gap-2">
                                    <button
                                      type="button"
                                      disabled={fieldActionBusy}
                                      onClick={() => handleFieldCorrectionSave(ef.id)}
                                      className="px-3 py-1 rounded bg-blue-900 text-white text-xs font-medium"
                                    >
                                      Save Correction
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => setEditingFieldId(null)}
                                      className="px-3 py-1 rounded border border-slate-300 text-xs text-slate-600"
                                    >
                                      Cancel
                                    </button>
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Extracted Raw Text Snippet */}
                    <div className="space-y-1.5">
                      <h4 className="text-xs font-semibold text-slate-700">
                        Extracted Raw Text Layer
                      </h4>
                      <pre className="max-h-32 overflow-y-auto rounded border border-slate-200 bg-slate-50 p-3 text-xs font-mono text-slate-700 whitespace-pre-wrap">
                        {selectedDoc.extractedText || '(No text extracted)'}
                      </pre>
                    </div>

                    {/* Source Verification Adapter Controls */}
                    {canReview && (
                      <div className="pt-4 border-t border-slate-200 space-y-3">
                        <div>
                          <h3 className="font-display text-sm font-semibold text-slate-900">
                            Source Verification Adapter
                          </h3>
                          <p className="text-xs text-slate-500">
                            Distinguishes Sandbox Demo fixtures, cryptographic container checks, unconfigured
                            live government adapters (honestly reporting SOURCE_UNAVAILABLE), and officer manual
                            confirmations.
                          </p>
                        </div>

                        {verifFeedback && (
                          <div
                            role="status"
                            className="border border-slate-300 bg-slate-50 rounded p-2.5 text-xs text-slate-800"
                          >
                            {verifFeedback}
                          </div>
                        )}

                        <form onSubmit={handleRunSourceVerification} className="space-y-3">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                              <label
                                htmlFor="verif-method"
                                className="block text-xs font-medium text-slate-700 mb-1"
                              >
                                Verification Method
                              </label>
                              <select
                                id="verif-method"
                                value={verifMethod}
                                onChange={(e) => setVerifMethod(e.target.value as VerificationMethod)}
                                className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs bg-white"
                              >
                                {(Object.entries(VERIFICATION_METHOD_LABELS) as Array<[VerificationMethod, string]>).map(
                                  ([methodKey, methodLabel]) => (
                                    <option key={methodKey} value={methodKey}>
                                      {methodLabel}
                                    </option>
                                  )
                                )}
                              </select>
                            </div>

                            {verifMethod === 'MANUAL_OFFICER_VERIFICATION' && (
                              <div>
                                <label
                                  htmlFor="manual-verif-status"
                                  className="block text-xs font-medium text-slate-700 mb-1"
                                >
                                  Manual Verification Outcome
                                </label>
                                <select
                                  id="manual-verif-status"
                                  value={manualStatus}
                                  onChange={(e) =>
                                    setManualStatus(e.target.value as VerificationStatus)
                                  }
                                  className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs bg-white"
                                >
                                  <option value="VERIFIED">Verified with Issuing Authority</option>
                                  <option value="MISMATCH_DETECTED">Mismatch Confirmed</option>
                                  <option value="EXPIRED">Confirmed Expired</option>
                                  <option value="VERIFICATION_PENDING">Awaiting Authority Reply</option>
                                  <option value="SOURCE_UNAVAILABLE">Authority Unreachable</option>
                                </select>
                              </div>
                            )}
                          </div>

                          {verifMethod === 'MANUAL_OFFICER_VERIFICATION' && (
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <input
                                type="text"
                                value={manualIssuer}
                                onChange={(e) => setManualIssuer(e.target.value)}
                                placeholder="Issuing Authority Name (e.g. State Fire Dept)"
                                className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs"
                              />
                              <input
                                type="text"
                                value={manualRef}
                                onChange={(e) => setManualRef(e.target.value)}
                                placeholder="Dispatch / Reference Number"
                                className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          <input
                            type="text"
                            value={manualNotes}
                            onChange={(e) => setManualNotes(e.target.value)}
                            placeholder="Verification note / authority contact reference (optional for automated checks)"
                            className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs"
                          />

                          {detail.finalOfficerDecision ? (
                            <p className="text-xs text-slate-500">
                              Case has a recorded final decision. Reopen the application under Officer Review to record new source checks.
                            </p>
                          ) : (
                            <button
                              type="submit"
                              disabled={verifBusy}
                              className="px-4 py-2 rounded-md bg-slate-900 text-white text-xs font-semibold hover:bg-slate-800 disabled:opacity-60"
                            >
                              {verifBusy ? 'Recording Verification...' : 'Execute & Persist Source Check'}
                            </button>
                          )}
                        </form>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: EVIDENCE-LINKED VALIDATION & ANOMALY FINDINGS */}
      {activeTab === 'FINDINGS' && (
        <div className="space-y-6">
          <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200">
              <h2 className="font-display text-base font-semibold text-slate-900">
                Evidence-Linked Regulatory &amp; Integrity Findings ({detail.findings.length})
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Classifies findings into 5 epistemic categories (Missing Information, Rule Inconsistency,
                Technical Processing Failure, Heuristic Anomaly Signal, or Confirmed Source Mismatch).
                Heuristic indicators never claim proof of forgery.
              </p>
            </div>

            {detail.findings.length === 0 ? (
              <div className="p-8 text-center space-y-1">
                <CheckCircle2 className="w-6 h-6 text-emerald-700 mx-auto" />
                <p className="text-sm font-semibold text-slate-900">
                  No automated compliance or integrity findings triggered
                </p>
                <p className="text-xs text-slate-500">
                  All configured checklist, expiry, cross-check, and SHA-256 uniqueness checks passed.
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-200">
                {detail.findings.map((f) => (
                  <div key={f.id} className="p-5 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                        <span className={severityColorClass(f.severity)}>{f.severity}</span>
                        <span aria-hidden="true">·</span>
                        <span className="font-semibold text-slate-800">
                          {f.ruleCode} (v{f.ruleVersion})
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="text-blue-900 font-medium">
                          {EPISTEMIC_LABELS[f.epistemicClassification] || f.findingCategory}
                        </span>
                        {f.detectorConfidence !== null && f.detectorConfidence !== undefined && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="text-slate-500">
                              Detector Confidence: {Math.round(f.detectorConfidence * 100)}%
                            </span>
                          </>
                        )}
                        <span aria-hidden="true">·</span>
                        <span className="text-slate-500">
                          {f.authoritySource === 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE'
                            ? 'Configurable Example Rule'
                            : f.authoritySource === 'INSTITUTIONAL_CROSSCHECK'
                              ? 'Institutional Cross-Check'
                              : 'Cryptographic / Metadata Check'}
                        </span>
                      </div>

                      <div className="text-xs">
                        {f.resolvedByOfficer ? (
                          <span className="text-emerald-700 font-semibold">
                            Resolved by Officer ({formatTimestamp(f.resolvedAt)})
                          </span>
                        ) : canReview ? (
                          <button
                            type="button"
                            onClick={() => {
                              setResolvingFindingId(f.id);
                              setFindingResolutionNote('');
                            }}
                            className="text-blue-800 hover:underline font-medium"
                          >
                            Record Officer Resolution
                          </button>
                        ) : (
                          <span className="text-amber-700 font-medium">Requires Officer Review</span>
                        )}
                      </div>
                    </div>

                    <p className="text-sm text-slate-900">{f.explanation}</p>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs bg-slate-50 border border-slate-200 rounded p-3">
                      <div>
                        <span className="text-slate-500 block">Affected Evidence</span>
                        <span className="font-medium text-slate-800">
                          {f.documentFilename || 'Application Package'}
                          {f.pageRegion ? ` (${f.pageRegion})` : ''}
                          {f.fieldName ? ` · ${f.fieldName}` : ''}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Expected</span>
                        <span className="font-mono text-slate-800">{f.expectedValue || '—'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Observed</span>
                        <span className="font-mono text-red-700">{f.observedValue || '—'}</span>
                      </div>
                    </div>

                    {(f.limitationsNote || f.recommendedFollowUp) && (
                      <div className="text-xs text-slate-600 space-y-0.5">
                        {f.limitationsNote && (
                          <div>
                            <span className="font-semibold text-slate-700">Detector Limitation: </span>
                            {f.limitationsNote}
                          </div>
                        )}
                        {f.recommendedFollowUp && (
                          <div>
                            <span className="font-semibold text-slate-700">Recommended Follow-Up: </span>
                            {f.recommendedFollowUp}
                          </div>
                        )}
                      </div>
                    )}

                    {f.resolvedByOfficer && f.resolutionNote && (
                      <div className="text-xs text-emerald-800">
                        Officer Resolution Note: {f.resolutionNote}
                      </div>
                    )}

                    {resolvingFindingId === f.id && (
                      <div className="flex flex-wrap items-center gap-2 pt-2">
                        <input
                          type="text"
                          value={findingResolutionNote}
                          onChange={(e) => setFindingResolutionNote(e.target.value)}
                          placeholder="Enter verification explanation to resolve this finding (min 5 chars)..."
                          className="flex-1 min-w-[240px] rounded border border-slate-300 px-3 py-1.5 text-xs"
                        />
                        <button
                          type="button"
                          onClick={() => handleResolveFinding(f.id)}
                          className="px-3 py-1.5 rounded bg-blue-900 text-white text-xs font-medium"
                        >
                          Persist Resolution
                        </button>
                        <button
                          type="button"
                          onClick={() => setResolvingFindingId(null)}
                          className="px-3 py-1.5 rounded border border-slate-300 text-xs text-slate-600"
                        >
                          Cancel
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Archived Findings from Earlier Resubmission Cycles */}
          {detail.priorCycleFindings && detail.priorCycleFindings.length > 0 && (
            <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-200">
                <h3 className="font-display text-sm font-semibold text-slate-900">
                  Archived Findings from Earlier Submission Cycles ({detail.priorCycleFindings.length})
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Preserved audit record of deficiencies recorded prior to rectification resubmission.
                </p>
              </div>
              <div className="divide-y divide-slate-200 text-xs">
                {detail.priorCycleFindings.map((pf) => (
                  <div key={pf.id} className="px-6 py-3.5 space-y-1 bg-slate-50/40">
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono tabular-nums text-slate-600">
                      <span>
                        Cycle #{pf.submissionCycle} · {pf.ruleCode} (v{pf.ruleVersion}) · {pf.severity}
                      </span>
                      <span>{formatTimestamp(pf.createdAt)}</span>
                    </div>
                    <p className="text-slate-700">{pf.explanation}</p>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {/* TAB 5: REGULATORY & INFRASTRUCTURE COMPLIANCE MODULE */}
      {activeTab === 'COMPLIANCE' && (
        <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 space-y-1">
            <h2 className="font-display text-base font-semibold text-slate-900">
              Regulatory &amp; Infrastructure Compliance Checklist ({complianceItems.length})
            </h2>
            <p className="text-xs text-slate-500">
              Links category requirements to uploaded certificates, floor plans, faculty rosters, and
              facility photographs. Image inspection (`LocalDeterministicVisualInspector`) checks pixel
              dimensions and scan legibility only — uploaded photographs never prove real-world physical
              room dimensions, equipment availability, or structural safety without officer scrutiny or EVC
              site inspection.
            </p>
          </div>

          {complianceItems.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              No compliance items initialised for this category.
            </div>
          ) : (
            <div className="divide-y divide-slate-200">
              {complianceItems.map((ci) => {
                const isEditingItem = reviewingItemId === ci.id;
                const vis = ci.visualInspection;
                const hasVisualDims = Boolean(vis && vis.width && vis.height);

                return (
                  <div key={ci.id} className="p-5 space-y-2.5">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums text-slate-500">
                          <span className="font-semibold text-slate-900">{ci.requirementCode}</span>
                          <span aria-hidden="true">·</span>
                          <span>{COMPLIANCE_DOMAIN_LABELS[ci.domain]}</span>
                          <span aria-hidden="true">·</span>
                          <span>{ci.isMandatory ? 'Mandatory' : 'Supplementary'}</span>
                          {ci.isIllustrative && (
                            <>
                              <span aria-hidden="true">·</span>
                              <span>Configurable Norm</span>
                            </>
                          )}
                        </div>
                        <h3 className="text-sm font-semibold text-slate-900">{ci.title}</h3>
                        <p className="text-xs text-slate-600">{ci.description}</p>
                      </div>

                      <div className="text-right space-y-1 text-xs shrink-0">
                        <div className={complianceColorClass(ci.complianceStatus)}>
                          {COMPLIANCE_STATUS_LABELS[ci.complianceStatus]}
                        </div>
                        {ci.physicalInspectionFlagged && (
                          <div className="text-amber-800 font-semibold">
                            Physical EVC Inspection Flagged
                          </div>
                        )}
                        {ci.additionalEvidenceRequested && (
                          <div className="text-red-700 font-medium">
                            Additional Evidence Requested
                          </div>
                        )}
                        {isOfficerOrAdmin && !detail.finalOfficerDecision && !isEditingItem && (
                          <button
                            type="button"
                            onClick={() => startReviewComplianceItem(ci)}
                            className="text-blue-800 hover:underline font-medium"
                          >
                            Review Requirement
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-50 border border-slate-200 rounded p-3">
                      <div>
                        <span className="text-slate-500 block">Linked Supporting Evidence</span>
                        <span className="font-medium text-slate-900">
                          {ci.linkedDocumentFilename || 'No matching document uploaded yet'}
                        </span>
                        <span className="text-slate-500 block mt-0.5">
                          Accepted:{' '}
                          {ci.acceptedDocTypes.map((dt) => DOC_TYPE_LABELS[dt] || dt).join(', ')}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Automated Evidence Note</span>
                        <span className="text-slate-800">{ci.autoEvaluatedNote || '—'}</span>
                      </div>
                    </div>

                    {hasVisualDims && (
                      <div className="text-xs bg-slate-50/70 border border-slate-200 rounded p-3 space-y-1">
                        <div className="font-mono tabular-nums text-slate-800">
                          Visual Container Check ({vis.adapterName || 'LocalDeterministicVisualInspector'}):{' '}
                          {vis.width}×{vis.height} px · Aspect {vis.aspectRatio} · {vis.legibilityFlag}
                        </div>
                        {vis.limitationsDisclaimer && (
                          <p className="text-slate-600">{vis.limitationsDisclaimer}</p>
                        )}
                      </div>
                    )}

                    {ci.officerObservation && (
                      <div className="text-xs text-slate-800">
                        <span className="font-semibold">Officer Observation: </span>
                        {ci.officerObservation}
                        {ci.reviewedByName ? ` — ${ci.reviewedByName} (${formatTimestamp(ci.reviewedAt)})` : ''}
                      </div>
                    )}

                    {isEditingItem && (
                      <form
                        onSubmit={(e) => handleSaveComplianceItem(e, ci.id)}
                        className="pt-3 border-t border-slate-200 space-y-3 bg-slate-50/80 p-4 rounded-md text-xs"
                      >
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <div>
                            <label className="block font-medium text-slate-700 mb-1">
                              Officer Compliance Assessment
                            </label>
                            <select
                              aria-label="Compliance assessment status"
                              value={itemStatus}
                              onChange={(e) => setItemStatus(e.target.value as ComplianceItemStatus)}
                              className="w-full rounded border border-slate-300 px-2.5 py-1.5 bg-white"
                            >
                              {(Object.entries(COMPLIANCE_STATUS_LABELS) as Array<[ComplianceItemStatus, string]>).map(
                                ([stKey, stLabel]) => (
                                  <option key={stKey} value={stKey}>
                                    {stLabel}
                                  </option>
                                )
                              )}
                            </select>
                          </div>

                          <div className="flex flex-col justify-end gap-1.5">
                            <label className="flex items-center gap-2 text-slate-800 cursor-pointer">
                              <input
                                type="checkbox"
                                checked={itemRequestEvidence}
                                onChange={(e) => setItemRequestEvidence(e.target.checked)}
                              />
                              <span>Request Additional Evidence from Institution</span>
                            </label>
                            <label className="flex items-center gap-2 text-slate-800 cursor-pointer">
                              <input
                                type="checkbox"
                                checked={itemFlagInspection}
                                onChange={(e) => setItemFlagInspection(e.target.checked)}
                              />
                              <span>Flag Physical EVC Site Inspection</span>
                            </label>
                          </div>
                        </div>

                        {itemRequestEvidence && (
                          <input
                            type="text"
                            value={itemEvidenceNote}
                            onChange={(e) => setItemEvidenceNote(e.target.value)}
                            placeholder="Specify exact photographs, certificates, or drawings requested..."
                            className="w-full rounded border border-slate-300 px-2.5 py-1.5 bg-white"
                          />
                        )}

                        <textarea
                          rows={2}
                          aria-label="Compliance officer observation"
                          value={itemObservation}
                          onChange={(e) => setItemObservation(e.target.value)}
                          placeholder="Record written officer scrutiny observation for this requirement (min 5 chars)..."
                          className="w-full rounded border border-slate-300 px-2.5 py-1.5 bg-white"
                          required
                        />

                        <div className="flex items-center gap-2">
                          <button
                            type="submit"
                            disabled={itemBusy}
                            className="px-3.5 py-1.5 rounded bg-blue-900 text-white font-semibold disabled:opacity-60"
                          >
                            {itemBusy ? 'Saving...' : 'Save Compliance Assessment'}
                          </button>
                          <button
                            type="button"
                            onClick={() => setReviewingItemId(null)}
                            className="px-3 py-1.5 rounded border border-slate-300 bg-white text-slate-700"
                          >
                            Cancel
                          </button>
                        </div>
                      </form>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>
      )}

      {/* TAB 3: OFFICER REVIEW, SOURCE HISTORY & FINAL HUMAN DECISION */}
      {activeTab === 'OFFICER_REVIEW' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Officer Action Form */}
          <section className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                Record Officer Review or Regulatory Decision
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Every action writes permanently to the relational database and the hash-chained audit log.
              </p>
            </div>

            {!canReview ? (
              <div className="border border-slate-200 bg-slate-50 rounded p-4 text-sm text-slate-600">
                Institution representatives have read-only visibility into officer review notes and
                clarification requests.
              </div>
            ) : (
              <form onSubmit={handleOfficerActionSubmit} className="space-y-4">
                <div>
                  <label htmlFor="officer-action-select" className="block text-xs font-medium text-slate-700 mb-1">
                    Officer Action Type
                  </label>
                  <select
                    id="officer-action-select"
                    value={officerActionType}
                    onChange={(e) =>
                      setOfficerActionType(e.target.value as typeof officerActionType)
                    }
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm bg-white"
                  >
                    <option value="ADD_REVIEW_NOTE">Add Scrutiny Review Note</option>
                    <option value="MARK_DOCUMENT_VERIFIED">Mark Selected Document as Verified</option>
                    <option value="RECORD_MISMATCH">Record Document Mismatch / Missing Evidence</option>
                    <option value="REQUEST_CLARIFICATION">
                      Request Clarification / Additional Documents from Institution
                    </option>
                    <option value="REQUEST_ADDITIONAL_EVIDENCE">
                      Request Specific Additional Compliance Evidence
                    </option>
                    <option value="FLAG_PHYSICAL_INSPECTION">
                      Flag Application for Physical EVC Site Inspection
                    </option>
                    {detail.physicalInspectionRequired && (
                      <option value="CLEAR_PHYSICAL_INSPECTION">
                        Clear Physical Site Inspection Flag
                      </option>
                    )}
                    {isOfficerOrAdmin && (
                      <>
                        <option value="FINAL_DECISION_APPROVE">
                          Final Officer Decision: Approve Application
                        </option>
                        <option value="FINAL_DECISION_REJECT">
                          Final Officer Decision: Reject Application
                        </option>
                      </>
                    )}
                    {canReopen && (
                      <option value="REOPEN_APPLICATION">
                        Reopen Decided / Closed Application Case
                      </option>
                    )}
                  </select>
                </div>

                {(officerActionType === 'MARK_DOCUMENT_VERIFIED' ||
                  officerActionType === 'RECORD_MISMATCH') && (
                  <div>
                    <label htmlFor="officer-doc-target" className="block text-xs font-medium text-slate-700 mb-1">
                      Target Document
                    </label>
                    <select
                      id="officer-doc-target"
                      value={officerTargetDocId}
                      onChange={(e) => setOfficerTargetDocId(e.target.value)}
                      className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm bg-white"
                    >
                      {detail.documents.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.originalFilename} ({DOC_TYPE_LABELS[d.declaredDocType]})
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                <div>
                  <label htmlFor="officer-rationale" className="block text-xs font-medium text-slate-700 mb-1">
                    Officer Explanation / Rationale{' '}
                    {officerActionType.startsWith('FINAL_DECISION')
                      ? '(Minimum 15 characters required)'
                      : '(Minimum 5 characters)'}
                  </label>
                  <textarea
                    id="officer-rationale"
                    rows={4}
                    value={officerRationale}
                    onChange={(e) => setOfficerRationale(e.target.value)}
                    placeholder="Cite specific document evidence, source verification results, or clarification items..."
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={officerBusy}
                  className="w-full py-2.5 px-4 rounded-md bg-blue-900 text-white text-sm font-semibold hover:bg-blue-800 disabled:opacity-60"
                >
                  {officerBusy ? 'Persisting Officer Action...' : 'Submit & Persist Officer Action'}
                </button>
              </form>
            )}
          </section>

          {/* Chronological Review, Source Verification & Application Audit History */}
          <div className="lg:col-span-6 space-y-6">
            <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-200">
                <h2 className="font-display text-base font-semibold text-slate-900">
                  Persisted Review &amp; Source Verification History
                </h2>
              </div>

              <div className="divide-y divide-slate-200 max-h-[380px] overflow-y-auto">
                {detail.officerReviews.length === 0 && detail.sourceVerifications.length === 0 ? (
                  <div className="p-6 text-sm text-slate-500">
                    No manual officer actions or source checks recorded yet.
                  </div>
                ) : (
                  <>
                    {detail.officerReviews.map((rev) => (
                      <div key={rev.id} className="p-4 space-y-1">
                        <div className="flex items-center justify-between gap-2 text-xs">
                          <span className="font-mono font-semibold text-blue-900">{rev.actionType}</span>
                          <span className="font-mono tabular-nums text-slate-500">
                            {formatTimestamp(rev.createdAt)}
                          </span>
                        </div>
                        <p className="text-sm text-slate-800">{rev.rationale}</p>
                        <div className="text-xs text-slate-500">
                          By {rev.officerName || rev.officerId} ({rev.officerRole || 'Officer'})
                          {rev.newStatus ? ` · Status -> ${rev.newStatus}` : ''}
                        </div>
                      </div>
                    ))}

                    {detail.sourceVerifications.map((sv) => (
                      <div key={sv.id} className="p-4 space-y-1 bg-slate-50/50">
                        <div className="flex items-center justify-between gap-2 text-xs">
                          <span className="font-mono font-semibold text-slate-800">
                            {sv.verificationMethod} ({formatVerificationOrigin(sv)})
                          </span>
                          <span className="font-mono tabular-nums text-slate-500">
                            {formatTimestamp(sv.attemptedAt)}
                          </span>
                        </div>
                        <div className={`text-xs ${verificationColorClass(sv.status)}`}>
                          Outcome: {VERIFICATION_STATUS_LABELS[sv.status]} · Source: {sv.issuerName}
                        </div>
                        {(sv.notes || sv.errorReason) && (
                          <p className="text-xs text-slate-600">{sv.notes || sv.errorReason}</p>
                        )}
                      </div>
                    ))}
                  </>
                )}
              </div>
            </section>

            {canReview && (
              <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between gap-2">
                  <h3 className="font-display text-sm font-semibold text-slate-900">
                    Case Audit Trail (SHA-256 Hash-Chained)
                  </h3>
                  <span className="text-xs font-mono text-slate-500 tabular-nums">
                    {appAuditLogs.length} event(s)
                  </span>
                </div>
                {appAuditLogs.length === 0 ? (
                  <div className="p-5 text-xs text-slate-500">No audit entries recorded for this application ID.</div>
                ) : (
                  <ul className="divide-y divide-slate-200 max-h-[260px] overflow-y-auto text-xs">
                    {appAuditLogs.map((ev) => (
                      <li key={ev.eventId} className="px-5 py-3 space-y-0.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono font-semibold text-slate-900">{ev.action}</span>
                          <span className="font-mono tabular-nums text-slate-500">
                            {formatTimestamp(ev.timestamp)}
                          </span>
                        </div>
                        <div className="text-slate-600 flex flex-wrap items-center justify-between gap-2">
                          <span>{ev.actorEmail || 'System'} ({ev.actorRole || 'SYSTEM'})</span>
                          <span className="font-mono text-slate-400">
                            Digest: {ev.entryHash.slice(0, 12)}...
                          </span>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: EXPLAINABLE ADVISORY TRUST SCORE BREAKDOWN */}
      {activeTab === 'TRUST_BREAKDOWN' && (
        <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
          <div className="flex flex-wrap items-baseline justify-between gap-4 border-b border-slate-200 pb-4">
            <div>
              <h2 className="font-display text-lg font-bold text-slate-900">
                Explainable Advisory Trust Indicator ({detail.trustScore ?? 0} / 100)
              </h2>
              <p className="text-xs text-slate-600 mt-1 max-w-3xl">
                {detail.trustScoreBreakdown?.advisoryNotice ||
                  'Advisory composite indicator only. Never auto-rejects an institution.'}
              </p>
            </div>
            <div className="text-xs font-mono text-slate-500 tabular-nums">
              Model Version: {detail.trustScoreVersion} · Computed:{' '}
              {formatTimestamp(detail.trustScoreBreakdown?.calculatedAt)}
            </div>
          </div>

          {detail.trustScoreBreakdown ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 text-xs font-medium text-slate-500">
                    <th className="py-2.5 px-3">Scoring Component</th>
                    <th className="py-2.5 px-3">Signal Origin</th>
                    <th className="py-2.5 px-3 text-right">Awarded / Max</th>
                    <th className="py-2.5 px-3 text-right">Net Impact</th>
                    <th className="py-2.5 px-3">Explanation &amp; Linked Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-sm">
                  {detail.trustScoreBreakdown.contributions.map((c) => (
                    <tr key={c.factorCode}>
                      <td className="py-3 px-3 font-medium text-slate-900">{c.label}</td>
                      <td className="py-3 px-3 text-xs font-mono text-slate-600">{c.signalOrigin}</td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums font-semibold text-slate-900">
                        {c.awardedPoints} / {c.maxPoints}
                      </td>
                      <td
                        className={`py-3 px-3 text-right font-mono tabular-nums ${
                          c.deltaPoints < 0 ? 'text-red-700' : 'text-emerald-700'
                        }`}
                      >
                        {c.deltaPoints === 0 ? '0' : c.deltaPoints}
                      </td>
                      <td className="py-3 px-3 text-xs text-slate-700">
                        {c.explanation}
                        {c.evidenceRef ? (
                          <span className="font-mono text-slate-500"> [{c.evidenceRef}]</span>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-slate-500">No score calculation recorded.</p>
          )}
        </section>
      )}
    </div>
  );
}
