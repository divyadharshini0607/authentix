import React, { useEffect, useState } from 'react';
import { ArrowRight, RefreshCw } from 'lucide-react';
import { fetchApplications, fetchDashboardStats } from '../client/api.ts';
import {
  CATEGORY_LABELS,
  formatCategoryDisplay,
  formatTimestamp,
  LIFECYCLE_LABELS,
  lifecycleColorClass,
  priorityColorClass,
  STATUS_LABELS,
  statusColorClass,
} from '../client/formatters.ts';
import type {
  ApplicationCategory,
  ApplicationStatus,
  ApplicationSummary,
  DashboardStats,
  LifecycleStage,
  UserProfile,
} from '../shared/types.ts';

interface DashboardViewProps {
  user: UserProfile;
  demoMode?: boolean;
  onOpenApplication: (applicationId: string) => void;
  onNavigateApplications: (presetFilter?: {
    priority?: string;
    status?: string;
    lifecycleStage?: string;
    category?: string;
  }) => void;
}

const ORDERED_STATUSES: ApplicationStatus[] = [
  'SUBMITTED',
  'UNDER_SCRUTINY',
  'PENDING_VERIFICATION',
  'CLARIFICATION_REQUESTED',
  'APPROVED_BY_OFFICER',
  'REJECTED_BY_OFFICER',
  'REOPENED',
];

const ORDERED_LIFECYCLES: LifecycleStage[] = [
  'pending',
  'incomplete',
  'processing',
  'failed',
  'review-required',
  'completed',
];

export function DashboardView({
  user,
  demoMode = false,
  onOpenApplication,
  onNavigateApplications,
}: DashboardViewProps) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [priorityApps, setPriorityApps] = useState<ApplicationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, appsRes] = await Promise.all([
        fetchDashboardStats(),
        fetchApplications({ pageSize: 6 }),
      ]);
      setStats(statsRes);
      setPriorityApps(appsRes.applications);
    } catch (err) {
      setError((err as Error).message || 'Failed to load persisted dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading && !stats) {
    return (
      <div className="space-y-6" aria-busy="true">
        <div className="h-8 w-64 bg-slate-200 rounded animate-pulse" />
        <div className="grid grid-cols-2 lg:grid-cols-6 border border-slate-200 rounded-lg bg-white divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
          {Array.from({ length: 6 }).map((_, idx) => (
            <div key={idx} className="p-5 space-y-2">
              <div className="h-3 w-24 bg-slate-200 rounded animate-pulse" />
              <div className="h-7 w-12 bg-slate-200 rounded animate-pulse" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div
        role="alert"
        className="bg-white border border-red-300 rounded-lg p-6 flex items-center justify-between gap-4"
      >
        <div>
          <h2 className="text-base font-semibold text-red-800">Unable to load dashboard metrics</h2>
          <p className="text-sm text-red-700 mt-1">{error}</p>
        </div>
        <button
          type="button"
          onClick={loadData}
          className="px-4 py-2 rounded-md bg-slate-900 text-white text-sm font-medium hover:bg-slate-800 whitespace-nowrap shrink-0"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!stats) return null;

  const categoryEntries = Object.entries(stats.categoryBreakdown || {});

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-slate-900">
            Regulatory Scrutiny Overview
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {user.role === 'INSTITUTION_USER'
              ? `Application filings, document verification status, and compliance findings for ${user.institutionName || 'your institution'}.`
              : 'Persisted application counts, pending officer reviews, missing document alerts, compliance findings, and review status.'}
          </p>
        </div>
        <button
          type="button"
          onClick={loadData}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-md border border-slate-300 bg-white text-sm font-medium text-slate-700 hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Refresh Metrics</span>
        </button>
      </div>

      {/* Structured 6-Metric Strip (Tabular Numerals) */}
      <section
        aria-label="Key Scrutiny Statistics"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 border border-slate-200 rounded-lg bg-white divide-y sm:divide-y-0 sm:divide-x divide-slate-200"
      >
        <div className="p-5 space-y-1">
          <div className="text-xs font-medium text-slate-500">Total Applications</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-slate-900">
            {stats.totalApplications}
          </div>
          <div className="text-xs text-slate-500 tabular-nums">
            {stats.totalDocuments} stored documents
          </div>
        </div>

        <div className="p-5 space-y-1">
          <div className="text-xs font-medium text-slate-500">Pending Officer Reviews</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-blue-900">
            {stats.awaitingReview}
          </div>
          <div className="text-xs text-slate-500 tabular-nums">
            {stats.highPriorityApplications} high priority
          </div>
        </div>

        <div className="p-5 space-y-1">
          <div className="text-xs font-medium text-slate-500">Missing / Expired Docs</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-amber-700">
            {stats.missingOrExpiredApplications}
          </div>
          <div className="text-xs text-slate-500">Checklist or validity gaps</div>
        </div>

        <div className="p-5 space-y-1">
          <div className="text-xs font-medium text-slate-500">Compliance Findings</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-red-700">
            {stats.openComplianceFindings ?? stats.mismatchOrAnomalyApplications}
          </div>
          <div className="text-xs text-slate-500 tabular-nums">
            {stats.mismatchOrAnomalyApplications} apps with cross-check alerts
          </div>
        </div>

        <div className="p-5 space-y-1">
          <div className="text-xs font-medium text-slate-500">Verified Documents</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-emerald-700">
            {stats.verifiedDocuments}
            <span className="text-sm font-normal text-slate-400"> / {stats.totalDocuments}</span>
          </div>
          <div className="text-xs text-slate-500 tabular-nums">
            {stats.verifiedApplications} officer-approved filings
          </div>
        </div>

        <div className="p-5 space-y-1">
          <div className="text-xs font-medium text-slate-500">Verification Pending</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-slate-800">
            {stats.verificationPendingApplications}
          </div>
          <div className="text-xs text-slate-500">Manual or source review</div>
        </div>
      </section>

      {/* Review Status Distribution Strip */}
      <section
        aria-label="Review Status Distribution"
        className="bg-white border border-slate-200 rounded-lg p-5 space-y-3"
      >
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="font-display text-sm font-semibold text-slate-900">
            Review Status Distribution
          </h2>
          <span className="text-xs text-slate-500">
            Select any workflow status to open filtered filings
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5">
          {ORDERED_STATUSES.map((st) => {
            const count = stats.statusBreakdown[st] ?? 0;
            return (
              <button
                key={st}
                type="button"
                onClick={() => onNavigateApplications({ status: st })}
                className="text-left rounded-md border border-slate-200 px-3 py-2.5 hover:border-blue-800 hover:bg-slate-50 transition-colors"
              >
                <div className="text-lg font-bold font-mono tabular-nums text-slate-900">
                  {count}
                </div>
                <div className={`text-xs mt-0.5 truncate ${statusColorClass(st)}`}>
                  {STATUS_LABELS[st]}
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* Lifecycle Stage, Category & Officer Intervention Summary */}
      <section
        aria-label="Lifecycle Stage and Intervention Breakdown"
        className="grid grid-cols-1 lg:grid-cols-12 gap-6"
      >
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-5 space-y-3">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="font-display text-sm font-semibold text-slate-900">
              Application Lifecycle Stages
            </h2>
            <span className="text-xs text-slate-500">
              Filter queue by readiness or processing stage
            </span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
            {ORDERED_LIFECYCLES.map((stage) => {
              const count = stats.lifecycleBreakdown?.[stage] ?? 0;
              return (
                <button
                  key={stage}
                  type="button"
                  onClick={() => onNavigateApplications({ lifecycleStage: stage })}
                  className="text-left rounded-md border border-slate-200 px-3 py-2.5 hover:border-blue-800 hover:bg-slate-50 transition-colors"
                >
                  <div className="text-base font-bold font-mono tabular-nums text-slate-900">
                    {count}
                  </div>
                  <div className={`text-xs mt-0.5 truncate ${lifecycleColorClass(stage)}`}>
                    {LIFECYCLE_LABELS[stage]}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div>
            <h2 className="font-display text-sm font-semibold text-slate-900">
              Officer Intervention &amp; Category Mix
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Cases escalated for physical inspection, evidence clarification, or manual scrutiny
            </p>
          </div>
          <div className="grid grid-cols-3 gap-3 border-b border-slate-200 pb-3 text-xs">
            <div>
              <div className="text-slate-500">Intervention Needed</div>
              <div className="text-lg font-bold font-mono tabular-nums text-blue-900 mt-0.5">
                {stats.officerInterventionRequiredCount ?? 0}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Physical Inspection</div>
              <div className="text-lg font-bold font-mono tabular-nums text-amber-700 mt-0.5">
                {stats.physicalInspectionRequiredCount ?? 0}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Evidence Requested</div>
              <div className="text-lg font-bold font-mono tabular-nums text-slate-800 mt-0.5">
                {stats.additionalEvidenceRequestedCount ?? 0}
              </div>
            </div>
          </div>
          {categoryEntries.length > 0 && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-slate-600">
              {categoryEntries.map(([catKey, catCount]) => (
                <button
                  key={catKey}
                  type="button"
                  onClick={() => onNavigateApplications({ category: catKey })}
                  className="hover:text-blue-900 hover:underline font-mono tabular-nums"
                >
                  {CATEGORY_LABELS[catKey as ApplicationCategory] || catKey.replace(/_/g, ' ')}: {catCount}
                </button>
              ))}
            </div>
          )}
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left 8 Columns: Priority Scrutiny Queue */}
        <section className="lg:col-span-8 bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between gap-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                Prioritised Scrutiny Queue
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Ordered by review priority and unresolved compliance findings. Advisory indicators
                never auto-reject applications.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateApplications()}
              className="inline-flex items-center gap-1.5 text-sm font-medium text-blue-900 hover:text-blue-950 whitespace-nowrap shrink-0"
            >
              <span>View All Applications</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {priorityApps.length === 0 ? (
            <div className="p-8 text-center space-y-2">
              <p className="text-sm font-medium text-slate-700">No applications persisted yet.</p>
              <p className="text-xs text-slate-500">
                Register an application from the Applications workspace to begin scrutiny.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/70 text-xs font-medium text-slate-500">
                    <th className="py-3 px-4">Application</th>
                    <th className="py-3 px-4">Institution &amp; Category</th>
                    <th className="py-3 px-4 text-right">Open Flags</th>
                    <th className="py-3 px-4 text-right">Advisory Score</th>
                    <th className="py-3 px-4">Review Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-sm">
                  {priorityApps.map((app) => (
                    <tr
                      key={app.id}
                      onClick={() => onOpenApplication(app.id)}
                      className="hover:bg-slate-50 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4 align-top">
                        <div className="font-mono text-xs font-semibold text-blue-900 tabular-nums">
                          {app.applicationNumber}
                        </div>
                        <div className={`text-xs mt-0.5 ${priorityColorClass(app.reviewPriority)}`}>
                          {app.reviewPriority} Priority
                          {app.submissionCycle > 1 ? ` · Cycle #${app.submissionCycle}` : ''}
                        </div>
                        {demoMode && app.isSyntheticDemo && (
                          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                            Sample Data
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 align-top max-w-xs">
                        <div className="font-medium text-slate-900 truncate">{app.institutionName}</div>
                        <div className="text-xs text-slate-500 truncate mt-0.5">
                          {formatCategoryDisplay(app.category, app.categoryCode)} · {app.documentCount} docs ({app.verifiedDocsCount} verified)
                        </div>
                      </td>
                      <td className="py-3 px-4 align-top text-right font-mono tabular-nums">
                        <span
                          className={
                            app.openFindingsCount > 0 ? 'text-red-700 font-semibold' : 'text-emerald-700'
                          }
                        >
                          {app.openFindingsCount}
                        </span>
                      </td>
                      <td className="py-3 px-4 align-top text-right font-mono tabular-nums text-slate-800">
                        {app.trustScore !== null ? `${app.trustScore}/100` : '—'}
                      </td>
                      <td className="py-3 px-4 align-top">
                        <div className={`text-xs ${statusColorClass(app.status)}`}>
                          {STATUS_LABELS[app.status]}
                        </div>
                        <div className={`text-[11px] mt-0.5 ${lifecycleColorClass(app.lifecycleStage)}`}>
                          {LIFECYCLE_LABELS[app.lifecycleStage]}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Right 4 Columns: Recent Persisted Audit Activity */}
        <section className="lg:col-span-4 bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200">
            <h2 className="font-display text-base font-semibold text-slate-900">
              Recent Audit Activity
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Latest hash-chained authentication, document, and officer review events.
            </p>
          </div>
          {stats.recentActivity.length === 0 ? (
            <div className="p-6 text-sm text-slate-500">No recent activity recorded.</div>
          ) : (
            <ul className="divide-y divide-slate-200">
              {stats.recentActivity.slice(0, 8).map((ev) => (
                <li key={ev.eventId} className="px-5 py-3 space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-800 font-mono truncate">
                      {ev.action}
                    </span>
                    <span className="text-xs text-slate-500 font-mono tabular-nums whitespace-nowrap shrink-0">
                      {formatTimestamp(ev.timestamp)}
                    </span>
                  </div>
                  <div className="text-xs text-slate-600 truncate">
                    {ev.actorEmail || 'System'} · {ev.resourceType} ({ev.resourceId.slice(0, 14)})
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
