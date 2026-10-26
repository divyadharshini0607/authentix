import React, { useEffect, useState } from 'react';
import { CheckCircle2, Download, Printer, ShieldCheck } from 'lucide-react';
import {
  downloadAuthenticatedBlob,
  fetchApplications,
  fetchAuditLogsApi,
  fetchHealthStatus,
  fetchValidationReportJson,
  verifyAuditChainApi,
} from '../client/api.ts';
import {
  COMPLIANCE_DOMAIN_LABELS,
  COMPLIANCE_STATUS_LABELS,
  complianceColorClass,
  EPISTEMIC_LABELS,
  formatCategoryDisplay,
  formatTimestamp,
  LIFECYCLE_LABELS,
  severityColorClass,
  STATUS_LABELS,
  VERIFICATION_STATUS_LABELS,
} from '../client/formatters.ts';
import type {
  ApplicationDetail,
  ApplicationSummary,
  AuditLogRecord,
  UserProfile,
} from '../shared/types.ts';

interface ReportsAuditViewProps {
  user: UserProfile;
  demoMode?: boolean;
  initialReportAppId?: string | null;
}

export function ReportsAuditView({ user, initialReportAppId }: ReportsAuditViewProps) {
  const [applications, setApplications] = useState<ApplicationSummary[]>([]);
  const [selectedAppId, setSelectedAppId] = useState<string>(initialReportAppId || '');
  const [reportData, setReportData] = useState<{
    generatedAt: string;
    regulatoryDisclaimer: string;
    application: ApplicationDetail;
  } | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);

  // Audit Log State (Restricted to Officers/Auditors/Admins)
  const canViewAudit = ['REVIEW_OFFICER', 'SENIOR_AUDITOR', 'ADMIN'].includes(user.role);
  const isAdminOrAuditor = user.role === 'ADMIN' || user.role === 'SENIOR_AUDITOR';
  const [runtimeHealth, setRuntimeHealth] = useState<{
    database: { engine: string; connected: boolean; appliedMigrations: number };
    ocrService: {
      configuredUrl: string;
      pythonMicroserviceOnline: boolean;
      localPdfAndImageFallbackActive: boolean;
      mode: string;
      details?: Record<string, unknown> | null;
    };
    security?: {
      qrSigningConfigured: boolean;
      demoModeEnabled: boolean;
    };
  } | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([]);
  const [chainStatus, setChainStatus] = useState<{
    valid: boolean;
    totalEventsChecked: number;
    headHash: string;
    brokenAtEventId?: string;
    reason?: string;
    verifiedAt: string;
  } | null>(null);
  const [actionFilter, setActionFilter] = useState('');
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [exportNotice, setExportNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadInitialData = async () => {
    setError(null);
    try {
      const res = await fetchApplications({ pageSize: 50 });
      setApplications(res.applications);
      if (!selectedAppId && res.applications.length > 0) {
        setSelectedAppId(initialReportAppId || res.applications[0].id);
      }
      if (isAdminOrAuditor) {
        fetchHealthStatus()
          .then((h) => setRuntimeHealth(h))
          .catch(() => {});
      }
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, [initialReportAppId, isAdminOrAuditor]);

  const loadAudit = async () => {
    if (!canViewAudit) return;
    try {
      const res = await fetchAuditLogsApi({
        action: actionFilter.trim() || undefined,
        limit: 80,
      });
      setAuditLogs(res.logs);
      setChainStatus(res.chainVerification);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    if (!selectedAppId) return;
    setLoadingReport(true);
    setError(null);
    fetchValidationReportJson(selectedAppId)
      .then((res) => {
        setReportData(res);
        return loadAudit();
      })
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoadingReport(false));
  }, [selectedAppId]);

  useEffect(() => {
    loadAudit();
  }, [actionFilter, canViewAudit]);

  const handleVerifyChainNow = async () => {
    setVerifyingChain(true);
    setError(null);
    try {
      const res = await verifyAuditChainApi();
      setChainStatus(res);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setVerifyingChain(false);
    }
  };

  const handleExportCsv = async () => {
    if (!reportData) return;
    setExportNotice(null);
    setError(null);
    try {
      await downloadAuthenticatedBlob(
        `/api/applications/${encodeURIComponent(reportData.application.id)}/report?format=csv`,
        `AUTHENTIX_Report_${reportData.application.applicationNumber}.csv`
      );
      setExportNotice(
        `Exported CSV report for ${reportData.application.applicationNumber} and logged VALIDATION_REPORT_GENERATED in audit history.`
      );
      await loadAudit();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-display text-2xl font-bold text-slate-900">
          Validation Reports &amp; Tamper-Evident Audit Trail
        </h1>
        <p className="text-sm text-slate-600 mt-1">
          Export persisted application scrutiny reports (CSV / Printable Summary) and verify SHA-256 audit
          hash-chain linkage.
        </p>
      </div>

      {error && (
        <div
          role="alert"
          className="border border-red-300 bg-red-50 text-red-800 rounded-lg p-4 text-sm flex items-center justify-between gap-4"
        >
          <span>{error}</span>
          <button
            type="button"
            onClick={() => {
              loadInitialData();
              loadAudit();
            }}
            className="px-3 py-1.5 rounded-md bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 whitespace-nowrap shrink-0"
          >
            Retry
          </button>
        </div>
      )}

      {exportNotice && (
        <div role="status" className="border border-emerald-300 bg-emerald-50 text-emerald-900 rounded-lg p-3.5 text-sm">
          {exportNotice}
        </div>
      )}

      {/* Section 1: Application Validation Report & Exports */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex flex-wrap items-end justify-between gap-4 border-b border-slate-200 pb-4">
          <div className="flex-1 min-w-[260px] max-w-lg">
            <label htmlFor="report-app-select" className="block text-xs font-medium text-slate-700 mb-1">
              Select Application for Report Generation
            </label>
            <select
              id="report-app-select"
              value={selectedAppId}
              onChange={(e) => setSelectedAppId(e.target.value)}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm bg-white"
            >
              {applications.length === 0 ? (
                <option value="">No applications available</option>
              ) : (
                applications.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.applicationNumber} — {a.institutionName}
                  </option>
                ))
              )}
            </select>
          </div>

          {reportData && (
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={handleExportCsv}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-blue-900 text-white text-xs font-semibold hover:bg-blue-800 whitespace-nowrap shrink-0"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Persisted CSV Report</span>
              </button>

              <button
                type="button"
                onClick={() => window.print()}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-md border border-slate-300 bg-white text-slate-700 text-xs font-medium hover:bg-slate-50 whitespace-nowrap shrink-0"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print / Save PDF</span>
              </button>
            </div>
          )}
        </div>

        {loadingReport ? (
          <div className="h-32 bg-slate-100 rounded animate-pulse" />
        ) : reportData ? (
          <div className="space-y-5">
            <div className="text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded p-3">
              {reportData.regulatoryDisclaimer}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-5 gap-4 text-xs">
              <div>
                <span className="text-slate-500 block">Application Number</span>
                <span className="font-mono font-semibold text-slate-900">
                  {reportData.application.applicationNumber} (Cycle #{reportData.application.submissionCycle || 1})
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Category &amp; Session</span>
                <span className="font-medium text-slate-900">
                  {formatCategoryDisplay(
                    reportData.application.category,
                    reportData.application.categoryCode
                  )}{' '}
                  ({reportData.application.academicYear})
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Workflow &amp; Lifecycle</span>
                <span className="font-semibold text-slate-900">
                  {STATUS_LABELS[reportData.application.status]} ·{' '}
                  {LIFECYCLE_LABELS[reportData.application.lifecycleStage]}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Physical Site Inspection</span>
                <span className="font-semibold text-slate-900">
                  {reportData.application.physicalInspectionRequired ? 'Flagged for EVC' : 'Not Flagged'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Advisory Score / Version</span>
                <span className="font-mono tabular-nums font-semibold text-slate-900">
                  {reportData.application.trustScore ?? '—'}/100 ({reportData.application.trustScoreVersion})
                </span>
              </div>
            </div>

            {/* Summary of Documents & Hashes */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-800">
                Submitted Documents &amp; Cryptographic Hashes ({reportData.application.documents.length})
              </h3>
              <div className="overflow-x-auto border border-slate-200 rounded">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-slate-500">
                      <th className="py-2 px-3">Filename</th>
                      <th className="py-2 px-3">SHA-256 Digest</th>
                      <th className="py-2 px-3">OCR Engine &amp; Confidence</th>
                      <th className="py-2 px-3">Verification Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {reportData.application.documents.map((d) => (
                      <tr key={d.id}>
                        <td className="py-2 px-3 font-medium text-slate-900">{d.originalFilename}</td>
                        <td className="py-2 px-3 font-mono text-slate-600">{d.sha256Hash.slice(0, 20)}...</td>
                        <td className="py-2 px-3 font-mono tabular-nums text-slate-600">
                          {d.ocrEngine} ({d.ocrConfidence !== null ? `${Math.round(d.ocrConfidence * 100)}%` : d.ocrStatus})
                        </td>
                        <td className="py-2 px-3 font-medium text-slate-800">
                          {VERIFICATION_STATUS_LABELS[d.verificationStatus]}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Summary of Findings */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-800">
                Recorded Validation &amp; Integrity Findings ({reportData.application.findings.length})
              </h3>
              {reportData.application.findings.length === 0 ? (
                <p className="text-xs text-emerald-700">No findings recorded for this application.</p>
              ) : (
                <div className="overflow-x-auto border border-slate-200 rounded">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-500">
                        <th className="py-2 px-3">Rule &amp; Version</th>
                        <th className="py-2 px-3">Epistemic Type</th>
                        <th className="py-2 px-3">Severity</th>
                        <th className="py-2 px-3">Explanation</th>
                        <th className="py-2 px-3">Resolution</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200">
                      {reportData.application.findings.map((f) => (
                        <tr key={f.id}>
                          <td className="py-2 px-3 font-mono text-slate-800 whitespace-nowrap">
                            {f.ruleCode} (v{f.ruleVersion})
                          </td>
                          <td className="py-2 px-3 text-slate-700">
                            {EPISTEMIC_LABELS[f.epistemicClassification] || f.findingCategory}
                          </td>
                          <td className={`py-2 px-3 ${severityColorClass(f.severity)}`}>{f.severity}</td>
                          <td className="py-2 px-3 text-slate-700">{f.explanation}</td>
                          <td className="py-2 px-3 text-slate-600">
                            {f.resolvedByOfficer ? `Resolved: ${f.resolutionNote}` : 'Open'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Summary of Regulatory & Infrastructure Compliance Items */}
            {reportData.application.complianceItems && reportData.application.complianceItems.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-slate-800">
                  Regulatory &amp; Infrastructure Compliance Summary (
                  {reportData.application.complianceItems.length})
                </h3>
                <div className="overflow-x-auto border border-slate-200 rounded">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-500">
                        <th className="py-2 px-3">Requirement</th>
                        <th className="py-2 px-3">Domain</th>
                        <th className="py-2 px-3">Linked Evidence</th>
                        <th className="py-2 px-3">Compliance Status</th>
                        <th className="py-2 px-3">Notes / Officer Observation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200">
                      {reportData.application.complianceItems.map((ci) => (
                        <tr key={ci.id}>
                          <td className="py-2 px-3 font-medium text-slate-900">
                            <span className="font-mono text-slate-600">{ci.requirementCode}</span> · {ci.title}
                          </td>
                          <td className="py-2 px-3 text-slate-600">
                            {COMPLIANCE_DOMAIN_LABELS[ci.domain]}
                          </td>
                          <td className="py-2 px-3 font-mono text-slate-700">
                            {ci.linkedDocumentFilename || 'Unlinked'}
                          </td>
                          <td className={`py-2 px-3 ${complianceColorClass(ci.complianceStatus)}`}>
                            {COMPLIANCE_STATUS_LABELS[ci.complianceStatus]}
                          </td>
                          <td className="py-2 px-3 text-slate-600">
                            {ci.officerObservation || ci.autoEvaluatedNote || '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-slate-500">Select an application to view its validation report.</p>
        )}
      </section>

      {/* Section 2: Cryptographic Hash-Chained Audit Trail */}
      {canViewAudit && (
        <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="p-6 border-b border-slate-200 space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="font-display text-lg font-bold text-slate-900">
                  Hash-Chained Security &amp; Scrutiny Audit Log
                </h2>
                <p className="text-xs text-slate-500 mt-0.5 max-w-3xl">
                  Each event hashes `prev_hash | event_id | timestamp | actor | action | resource |
                  canonical_metadata`. Detects unauthorised in-place row edits or deletions (note: does not
                  replace external WORM storage if an OS-level administrator rewrites the entire file).
                </p>
              </div>

              <button
                type="button"
                disabled={verifyingChain}
                onClick={handleVerifyChainNow}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-slate-900 text-white text-xs font-semibold hover:bg-slate-800 disabled:opacity-60 whitespace-nowrap shrink-0"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>{verifyingChain ? 'Verifying Chain...' : 'Verify SHA-256 Chain Integrity'}</span>
              </button>
            </div>

            {chainStatus && (
              <div
                role="status"
                className={`rounded-md border p-3.5 text-xs flex flex-wrap items-center justify-between gap-3 ${
                  chainStatus.valid
                    ? 'border-emerald-300 bg-emerald-50 text-emerald-900'
                    : 'border-red-300 bg-red-50 text-red-900'
                }`}
              >
                <div className="flex items-center gap-2 font-semibold">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>
                    {chainStatus.valid
                      ? `Chain Verified: All ${chainStatus.totalEventsChecked} sequential audit events match canonical SHA-256 digests.`
                      : `Tampering Detected at ${chainStatus.brokenAtEventId}: ${chainStatus.reason}`}
                  </span>
                </div>
                <span className="font-mono tabular-nums">
                  Head Digest: {chainStatus.headHash.slice(0, 20)}...
                </span>
              </div>
            )}

            <div className="max-w-sm">
              <input
                type="search"
                aria-label="Filter audit events by action"
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                placeholder="Filter by action (e.g. LOGIN, OFFICER, UPLOAD)..."
                className="w-full rounded-md border border-slate-300 px-3 py-1.5 text-xs"
              />
            </div>
          </div>

          <div className="overflow-x-auto max-h-[480px] overflow-y-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-500">
                  <th className="py-2.5 px-4">#</th>
                  <th className="py-2.5 px-4">Timestamp</th>
                  <th className="py-2.5 px-4">Actor &amp; Role</th>
                  <th className="py-2.5 px-4">Action</th>
                  <th className="py-2.5 px-4">Affected Resource</th>
                  <th className="py-2.5 px-4">Prev → Entry SHA-256</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {auditLogs.map((log) => (
                  <tr key={log.eventId} className="hover:bg-slate-50">
                    <td className="py-2.5 px-4 font-mono tabular-nums text-slate-500">{log.id}</td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-slate-600 whitespace-nowrap">
                      {formatTimestamp(log.timestamp)}
                    </td>
                    <td className="py-2.5 px-4 text-slate-800">
                      <div>{log.actorEmail || 'System'}</div>
                      <div className="text-slate-400 font-mono">{log.actorRole || 'SYSTEM'}</div>
                    </td>
                    <td className="py-2.5 px-4 font-mono font-semibold text-blue-900">{log.action}</td>
                    <td className="py-2.5 px-4 font-mono text-slate-600">
                      {log.resourceType}:{log.resourceId.slice(0, 16)}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-500 whitespace-nowrap">
                      {log.prevHash.slice(0, 8)}... → {log.entryHash.slice(0, 10)}...
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Section 3: Administrator & Senior Auditor Runtime Verification Boundaries */}
      {isAdminOrAuditor && runtimeHealth && (
        <section
          aria-label="System Runtime and Verification Boundaries"
          className="bg-white border border-slate-200 rounded-lg p-6 space-y-4"
        >
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              Administrator Operational Status &amp; Verification Boundaries
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Truthful infrastructure capabilities and operational boundaries for administrative governance.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
            <div className="border border-slate-200 rounded-md p-3.5 space-y-1">
              <div className="font-semibold text-slate-900">Relational Persistence</div>
              <div className="font-mono text-slate-700">
                {runtimeHealth.database.engine} ({runtimeHealth.database.appliedMigrations} migrations)
              </div>
              <p className="text-slate-500 leading-snug">
                Single-node persistent SQLite WAL database active (`node:sqlite`). `db/postgres-schema.sql`
                is provided as reference DDL only; a runtime PostgreSQL driver adapter is not enabled.
              </p>
            </div>

            <div className="border border-slate-200 rounded-md p-3.5 space-y-1">
              <div className="font-semibold text-slate-900">OCR &amp; Document Extraction</div>
              <div className="font-mono text-slate-700">
                Mode: {runtimeHealth.ocrService.mode} · Python:{' '}
                {runtimeHealth.ocrService.pythonMicroserviceOnline ? 'Online' : 'Local Fallback'}
              </div>
              <p className="text-slate-500 leading-snug">
                Digital PDFs and embedded metadata parse locally. Raw raster scans without host{' '}
                <code className="font-mono">tesseract-ocr</code> report UNAVAILABLE and route to manual review.
              </p>
            </div>

            <div className="border border-slate-200 rounded-md p-3.5 space-y-1">
              <div className="font-semibold text-slate-900">External Authority &amp; Signing</div>
              <div className="font-mono text-slate-700">
                Sandbox + Manual · QR Key:{' '}
                {runtimeHealth.security?.qrSigningConfigured !== false ? 'Ready' : 'Not Configured'}
              </div>
              <p className="text-slate-500 leading-snug">
                No live government authority API connections are claimed. Automated lookups query the
                internal sandbox registry; official verification requires officer confirmation.
              </p>
            </div>

            <div className="border border-slate-200 rounded-md p-3.5 space-y-1">
              <div className="font-semibold text-slate-900">Audit Chain Scope</div>
              <div className="font-mono text-slate-700">SHA-256 Sequential Hash Chain</div>
              <p className="text-slate-500 leading-snug">
                Verifies integrity against in-place row edits or deletions. Does not replace external
                append-only WORM storage against OS-level file replacement.
              </p>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
