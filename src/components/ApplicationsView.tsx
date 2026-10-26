import React, { useEffect, useState } from 'react';
import { Plus, Search, X } from 'lucide-react';
import {
  createApplicationApi,
  createCategoryApi,
  fetchApplications,
  fetchCategories,
  fetchInstitutions,
} from '../client/api.ts';
import {
  CATEGORY_LABELS,
  DOC_TYPE_LABELS,
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
  ApplicationCategoryDefinition,
  ApplicationSummary,
  DocumentType,
  InstitutionRecord,
  LifecycleStage,
  UserProfile,
} from '../shared/types.ts';

interface ApplicationsViewProps {
  user: UserProfile;
  demoMode?: boolean;
  initialFilter?: {
    priority?: string;
    status?: string;
    lifecycleStage?: string;
    category?: string;
  };
  onOpenApplication: (applicationId: string) => void;
}

const DEFAULT_FALLBACK_CATEGORIES: ApplicationCategoryDefinition[] = [
  {
    code: 'EXTENSION_OF_APPROVAL',
    baseCategory: 'EXTENSION_OF_APPROVAL',
    name: 'Extension of Approval (EoA)',
    description: 'Annual extension of approval for existing AICTE-approved technical institutions.',
    requiredDocTypes: ['FIRE_SAFETY_CERTIFICATE', 'AFFIDAVIT_INTAKE', 'AICTE_FEE_RECEIPT'],
    isActive: true,
    createdAt: '',
    updatedAt: '',
  },
  {
    code: 'NEW_INSTITUTION',
    baseCategory: 'NEW_INSTITUTION',
    name: 'New Technical Institution',
    description: 'Establishment of a new technical institution requiring full statutory & facility clearances.',
    requiredDocTypes: [
      'FIRE_SAFETY_CERTIFICATE',
      'LAND_USE_CERTIFICATE',
      'BUILDING_PLAN_APPROVAL',
      'NOC_AFFILIATING_UNIVERSITY',
      'AFFIDAVIT_INTAKE',
      'AICTE_FEE_RECEIPT',
    ],
    isActive: true,
    createdAt: '',
    updatedAt: '',
  },
  {
    code: 'INCREASE_IN_INTAKE',
    baseCategory: 'INCREASE_IN_INTAKE',
    name: 'Increase in Approved Intake',
    description: 'Expansion of sanctioned student intake in existing approved diploma/degree programs.',
    requiredDocTypes: [
      'FIRE_SAFETY_CERTIFICATE',
      'BUILDING_PLAN_APPROVAL',
      'AFFIDAVIT_INTAKE',
      'NOC_AFFILIATING_UNIVERSITY',
      'AICTE_FEE_RECEIPT',
    ],
    isActive: true,
    createdAt: '',
    updatedAt: '',
  },
];

export function ApplicationsView({
  user,
  demoMode = false,
  initialFilter,
  onOpenApplication,
}: ApplicationsViewProps) {
  const [applications, setApplications] = useState<ApplicationSummary[]>([]);
  const [institutions, setInstitutions] = useState<InstitutionRecord[]>([]);
  const [categories, setCategories] = useState<ApplicationCategoryDefinition[]>(DEFAULT_FALLBACK_CATEGORIES);

  const [searchQuery, setSearchQuery] = useState('');
  const [priorityFilter, setPriorityFilter] = useState(initialFilter?.priority || 'ALL');
  const [statusFilter, setStatusFilter] = useState(initialFilter?.status || 'ALL');
  const [lifecycleFilter, setLifecycleFilter] = useState(initialFilter?.lifecycleStage || 'ALL');
  const [categoryFilter, setCategoryFilter] = useState(initialFilter?.category || 'ALL');
  const [institutionFilter, setInstitutionFilter] = useState('ALL');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Create Application Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newInstId, setNewInstId] = useState('');
  const [newYear, setNewYear] = useState('2026-27');
  const [newCategoryCode, setNewCategoryCode] = useState<string>('EXTENSION_OF_APPROVAL');
  const [newPrograms, setNewPrograms] = useState('B.Tech Computer Science & Engineering');
  const [newIntake, setNewIntake] = useState('240');
  const [newLand, setNewLand] = useState('5.5');
  const [newBuiltUp, setNewBuiltUp] = useState('1400');
  const [newPrincipal, setNewPrincipal] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Admin Extensible Category Modal State
  const [showCategoryModal, setShowCategoryModal] = useState(false);
  const [catCode, setCatCode] = useState('');
  const [catBase, setCatBase] = useState<ApplicationCategory>('INCREASE_IN_INTAKE');
  const [catName, setCatName] = useState('');
  const [catDesc, setCatDesc] = useState('');
  const [catDocs, setCatDocs] = useState<DocumentType[]>([
    'FIRE_SAFETY_CERTIFICATE',
    'AFFIDAVIT_INTAKE',
    'AICTE_FEE_RECEIPT',
  ]);
  const [catBusy, setCatBusy] = useState(false);
  const [catMessage, setCatMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const canCreate = user.role !== 'SENIOR_AUDITOR';
  const isAdmin = user.role === 'ADMIN';

  const loadMetadata = async () => {
    try {
      const [instRes, catRes] = await Promise.all([
        fetchInstitutions(),
        fetchCategories().catch(() => ({ categories: DEFAULT_FALLBACK_CATEGORIES })),
      ]);
      setInstitutions(instRes.institutions);
      if (instRes.institutions.length > 0) {
        const def = instRes.institutions[0];
        setNewInstId((prev) => prev || def.id);
        setNewPrincipal((prev) => prev || def.principalName);
        setNewLand((prev) => (prev === '5.5' ? String(def.landAreaAcres) : prev));
        setNewBuiltUp((prev) => (prev === '1400' ? String(def.builtUpAreaSqm) : prev));
        setNewIntake((prev) => (prev === '240' ? String(def.approvedIntake) : prev));
      }
      if (catRes.categories && catRes.categories.length > 0) {
        setCategories(catRes.categories);
      }
    } catch {
      // handled during main load
    }
  };

  useEffect(() => {
    loadMetadata();
  }, []);

  const loadApplications = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchApplications({
        q: searchQuery.trim() || undefined,
        priority: priorityFilter,
        status: statusFilter,
        lifecycleStage: lifecycleFilter,
        category: categoryFilter,
        institutionId: institutionFilter,
        page,
        pageSize: 12,
      });
      setApplications(res.applications);
      setTotalPages(res.pagination.totalPages);
      setTotalCount(res.pagination.totalCount);
    } catch (err) {
      setError((err as Error).message || 'Failed to load applications.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApplications();
  }, [searchQuery, priorityFilter, statusFilter, lifecycleFilter, categoryFilter, institutionFilter, page]);

  const selectedCategoryDef =
    categories.find((c) => c.code === newCategoryCode) || DEFAULT_FALLBACK_CATEGORIES[0];

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);

    const intakeNum = Number.parseInt(newIntake, 10);
    const landNum = Number.parseFloat(newLand);
    const builtNum = Number.parseFloat(newBuiltUp);

    if (!newInstId) {
      setCreateError('Select an institution.');
      return;
    }
    if (!Number.isFinite(intakeNum) || intakeNum < 30) {
      setCreateError('Requested intake must be at least 30 seats.');
      return;
    }
    if (!Number.isFinite(landNum) || landNum <= 0 || !Number.isFinite(builtNum) || builtNum <= 0) {
      setCreateError('Land area and built-up area must be positive numbers.');
      return;
    }

    setCreating(true);
    try {
      const created = await createApplicationApi({
        institutionId: newInstId,
        academicYear: newYear.trim(),
        category: selectedCategoryDef.baseCategory,
        categoryCode: selectedCategoryDef.code,
        programNames: newPrograms.trim(),
        requestedIntake: intakeNum,
        submittedLandAcres: landNum,
        submittedBuiltUpSqm: builtNum,
        submittedPrincipalName: newPrincipal.trim(),
      });
      setShowCreateModal(false);
      onOpenApplication(created.id);
    } catch (err) {
      setCreateError((err as Error).message || 'Failed to create application.');
    } finally {
      setCreating(false);
    }
  };

  const handleCreateCategory = async (e: React.FormEvent) => {
    e.preventDefault();
    setCatMessage(null);
    if (catDocs.length === 0) {
      setCatMessage({ type: 'err', text: 'Select at least one required checklist document type.' });
      return;
    }
    setCatBusy(true);
    try {
      const created = await createCategoryApi({
        code: catCode.trim().toUpperCase(),
        baseCategory: catBase,
        name: catName.trim(),
        description: catDesc.trim(),
        requiredDocTypes: catDocs,
      });
      await loadMetadata();
      setNewCategoryCode(created.code);
      setCatCode('');
      setCatName('');
      setCatDesc('');
      setShowCategoryModal(false);
      setCatMessage({
        type: 'ok',
        text: `Created extensible category '${created.code}' with ${created.requiredDocTypes.length} mandatory checklist item(s).`,
      });
    } catch (err) {
      setCatMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setCatBusy(false);
    }
  };

  const categoryNameMap = new Map<string, string>(categories.map((c) => [c.code, c.name]));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-slate-900">
            Applications &amp; Scrutiny Queue
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Search, filter, and open institutional filings for evidence-linked document verification and officer review.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {isAdmin && (
            <button
              type="button"
              onClick={() => {
                setCatMessage(null);
                setShowCategoryModal(true);
              }}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Define Category Variant</span>
            </button>
          )}
          {canCreate && (
            <button
              type="button"
              onClick={() => setShowCreateModal(true)}
              className="inline-flex items-center gap-2 rounded-md bg-blue-950 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-900 transition-colors whitespace-nowrap shrink-0"
            >
              <Plus className="w-4 h-4" />
              <span>Register Application</span>
            </button>
          )}
        </div>
      </div>

      {catMessage && (
        <div
          role={catMessage.type === 'err' ? 'alert' : 'status'}
          className={`rounded-lg border px-4 py-3 text-sm ${
            catMessage.type === 'err'
              ? 'border-red-300 bg-red-50 text-red-800'
              : 'border-emerald-300 bg-emerald-50 text-emerald-900'
          }`}
        >
          {catMessage.text}
        </div>
      )}

      {/* Filter & Search Toolbar */}
      <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          {/* Interactive Priority Segmented Control */}
          <div
            role="group"
            aria-label="Filter by Review Priority"
            className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg"
          >
            {[
              { key: 'ALL', label: 'All Priorities' },
              { key: 'HIGH', label: 'High Priority' },
              { key: 'MEDIUM', label: 'Medium' },
              { key: 'STANDARD', label: 'Standard' },
            ].map((item) => (
              <button
                key={item.key}
                type="button"
                onClick={() => {
                  setPriorityFilter(item.key);
                  setPage(1);
                }}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  priorityFilter === item.key
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>

          <div className="relative flex-1 min-w-[240px] max-w-md">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="search"
              aria-label="Search applications"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              placeholder="Search application ID, institution, or program..."
              className="w-full rounded-md border border-slate-300 pl-9 pr-3 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2 border-t border-slate-100">
          <div>
            <label htmlFor="filter-status" className="block text-xs font-medium text-slate-600 mb-1">
              Workflow Status
            </label>
            <select
              id="filter-status"
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm bg-white text-slate-900"
            >
              <option value="ALL">All Statuses</option>
              <option value="SUBMITTED">Submitted</option>
              <option value="UNDER_SCRUTINY">Under Officer Scrutiny</option>
              <option value="PENDING_VERIFICATION">Verification Pending</option>
              <option value="CLARIFICATION_REQUESTED">Clarification Requested</option>
              <option value="APPROVED_BY_OFFICER">Approved by Officer</option>
              <option value="REJECTED_BY_OFFICER">Rejected by Officer</option>
              <option value="REOPENED">Reopened</option>
            </select>
          </div>

          <div>
            <label htmlFor="filter-lifecycle" className="block text-xs font-medium text-slate-600 mb-1">
              Lifecycle Stage
            </label>
            <select
              id="filter-lifecycle"
              value={lifecycleFilter}
              onChange={(e) => {
                setLifecycleFilter(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm bg-white text-slate-900"
            >
              <option value="ALL">All Lifecycle Stages</option>
              {(Object.entries(LIFECYCLE_LABELS) as Array<[LifecycleStage, string]>).map(([k, lbl]) => (
                <option key={k} value={k}>
                  {lbl}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="filter-category" className="block text-xs font-medium text-slate-600 mb-1">
              Approval Category
            </label>
            <select
              id="filter-category"
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm bg-white text-slate-900"
            >
              <option value="ALL">All Categories</option>
              {categories.map((cat) => (
                <option key={cat.code} value={cat.code}>
                  {cat.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="filter-inst" className="block text-xs font-medium text-slate-600 mb-1">
              Institution
            </label>
            <select
              id="filter-inst"
              value={institutionFilter}
              onChange={(e) => {
                setInstitutionFilter(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm bg-white text-slate-900"
            >
              <option value="ALL">All Accessible Institutions</option>
              {institutions.map((inst) => (
                <option key={inst.id} value={inst.id}>
                  {inst.code} — {inst.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="border border-red-300 bg-red-50 text-red-800 rounded-lg p-4 text-sm flex items-center justify-between gap-4"
        >
          <span>{error}</span>
          <button
            type="button"
            onClick={loadApplications}
            className="px-3 py-1.5 rounded-md bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 whitespace-nowrap shrink-0"
          >
            Retry
          </button>
        </div>
      )}

      {/* Applications Data Table */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 space-y-3" aria-busy="true">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-10 bg-slate-100 rounded animate-pulse" />
            ))}
          </div>
        ) : applications.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <h2 className="text-base font-semibold text-slate-900">
              No matching applications found
            </h2>
            <p className="text-sm text-slate-500 max-w-md mx-auto">
              Adjust your search terms or filters, or register a new institutional application package to
              begin document verification.
            </p>
            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setPriorityFilter('ALL');
                  setStatusFilter('ALL');
                  setLifecycleFilter('ALL');
                  setCategoryFilter('ALL');
                  setInstitutionFilter('ALL');
                  setPage(1);
                }}
                className="px-4 py-2 rounded-md border border-slate-300 text-sm font-medium text-slate-700 hover:bg-slate-50"
              >
                Reset Filters
              </button>
              {canCreate && (
                <button
                  type="button"
                  onClick={() => setShowCreateModal(true)}
                  className="px-4 py-2 rounded-md bg-blue-900 text-sm font-semibold text-white hover:bg-blue-800"
                >
                  Create Application
                </button>
              )}
            </div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/70 text-xs font-medium text-slate-500">
                    <th className="py-3 px-4">Application ID</th>
                    <th className="py-3 px-4">Institution &amp; Next Action</th>
                    <th className="py-3 px-4">Category &amp; Intake</th>
                    <th className="py-3 px-4 text-right">Docs (Verified)</th>
                    <th className="py-3 px-4 text-right">Open Flags</th>
                    <th className="py-3 px-4 text-right">Advisory Score</th>
                    <th className="py-3 px-4">Status &amp; Lifecycle</th>
                    <th className="py-3 px-4 text-right">Updated</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-sm">
                  {applications.map((app) => (
                    <tr
                      key={app.id}
                      onClick={() => onOpenApplication(app.id)}
                      className="hover:bg-slate-50 cursor-pointer transition-colors"
                    >
                      <td className="py-3.5 px-4 align-top font-mono text-xs font-semibold text-blue-900 tabular-nums whitespace-nowrap">
                        <div>{app.applicationNumber}</div>
                        {app.submissionCycle > 1 && (
                          <div className="text-[11px] font-normal text-blue-800 mt-0.5">
                            Cycle #{app.submissionCycle}
                          </div>
                        )}
                        {demoMode && app.isSyntheticDemo && (
                          <div className="text-[11px] font-normal text-slate-400 mt-0.5">
                            Sample Data
                          </div>
                        )}
                      </td>
                      <td className="py-3.5 px-4 align-top max-w-xs">
                        <div className="font-medium text-slate-900 truncate">{app.institutionName}</div>
                        <div className="text-xs text-slate-500 mt-0.5">
                          {app.institutionCode} · {app.institutionState}
                          {app.physicalInspectionRequired ? ' · Physical Inspection Flagged' : ''}
                        </div>
                        {app.nextRecommendedAction && (
                          <div className="text-[11px] text-slate-500 truncate mt-0.5">
                            Next: {app.nextRecommendedAction}
                          </div>
                        )}
                      </td>
                      <td className="py-3.5 px-4 align-top">
                        <div className="text-slate-800 text-xs font-medium">
                          {formatCategoryDisplay(
                            app.category,
                            app.categoryCode,
                            app.categoryCode ? categoryNameMap.get(app.categoryCode) : undefined
                          )}
                        </div>
                        <div className="text-xs text-slate-500 font-mono tabular-nums mt-0.5">
                          {app.requestedIntake} seats · {app.academicYear}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 align-top text-right font-mono text-xs tabular-nums text-slate-700">
                        {app.documentCount} ({app.verifiedDocsCount})
                      </td>
                      <td className="py-3.5 px-4 align-top text-right font-mono text-xs tabular-nums">
                        <span
                          className={
                            app.openFindingsCount > 0 ? 'text-red-700 font-semibold' : 'text-emerald-700'
                          }
                        >
                          {app.openFindingsCount}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 align-top text-right font-mono text-xs tabular-nums text-slate-800">
                        {app.trustScore !== null ? `${app.trustScore}/100` : '—'}
                      </td>
                      <td className="py-3.5 px-4 align-top">
                        <div className={`text-xs ${statusColorClass(app.status)}`}>
                          {STATUS_LABELS[app.status]}
                        </div>
                        <div className={`text-[11px] mt-0.5 ${lifecycleColorClass(app.lifecycleStage)}`}>
                          {LIFECYCLE_LABELS[app.lifecycleStage]} ·{' '}
                          <span className={priorityColorClass(app.reviewPriority)}>
                            {app.reviewPriority}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 align-top text-right font-mono text-xs text-slate-500 tabular-nums whitespace-nowrap">
                        {formatTimestamp(app.updatedAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="px-4 py-3 border-t border-slate-200 flex items-center justify-between text-xs text-slate-600">
              <span className="tabular-nums">
                Showing {applications.length} of {totalCount} application(s)
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="px-3 py-1 rounded border border-slate-300 disabled:opacity-40 hover:bg-slate-50"
                >
                  Previous
                </button>
                <span className="font-mono tabular-nums">
                  Page {page} / {totalPages}
                </span>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="px-3 py-1 rounded border border-slate-300 disabled:opacity-40 hover:bg-slate-50"
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Create New Application Modal */}
      {showCreateModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="create-app-title"
          className="fixed inset-0 z-50 bg-slate-900/50 flex items-center justify-center p-4"
        >
          <div className="bg-white border border-slate-200 rounded-lg max-w-xl w-full p-6 space-y-5 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between gap-4 border-b border-slate-200 pb-3">
              <div>
                <h2 id="create-app-title" className="font-display text-lg font-bold text-slate-900">
                  Register Institutional Application
                </h2>
                <p className="text-xs text-slate-500">
                  Initialises a persisted application record and evaluates mandatory document checklist rules.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                aria-label="Close modal"
                className="p-1.5 rounded text-slate-500 hover:bg-slate-100"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {createError && (
              <div role="alert" className="border border-red-300 bg-red-50 text-red-800 rounded p-3 text-sm">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreateSubmit} className="space-y-4">
              <div>
                <label htmlFor="new-inst" className="block text-xs font-medium text-slate-700 mb-1">
                  Institution
                </label>
                <select
                  id="new-inst"
                  value={newInstId}
                  onChange={(e) => {
                    const id = e.target.value;
                    setNewInstId(id);
                    const found = institutions.find((i) => i.id === id);
                    if (found) {
                      setNewPrincipal(found.principalName);
                      setNewLand(String(found.landAreaAcres));
                      setNewBuiltUp(String(found.builtUpAreaSqm));
                      setNewIntake(String(found.approvedIntake));
                    }
                  }}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm bg-white"
                >
                  {institutions.map((inst) => (
                    <option key={inst.id} value={inst.id}>
                      {inst.code} — {inst.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="new-cat" className="block text-xs font-medium text-slate-700 mb-1">
                    Application Category
                  </label>
                  <select
                    id="new-cat"
                    value={newCategoryCode}
                    onChange={(e) => setNewCategoryCode(e.target.value)}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm bg-white"
                  >
                    {categories.map((cat) => (
                      <option key={cat.code} value={cat.code}>
                        {cat.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="new-year" className="block text-xs font-medium text-slate-700 mb-1">
                    Academic Session
                  </label>
                  <input
                    id="new-year"
                    type="text"
                    value={newYear}
                    onChange={(e) => setNewYear(e.target.value)}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-mono"
                    required
                  />
                </div>
              </div>

              {/* Dynamic Mandatory Document Checklist Preview */}
              <div className="rounded border border-slate-200 bg-slate-50 p-3 space-y-1 text-xs">
                <div className="font-semibold text-slate-800">
                  Required Checklist for {selectedCategoryDef.name} (
                  {selectedCategoryDef.requiredDocTypes.length} mandatory)
                </div>
                <div className="text-slate-600 leading-relaxed">
                  {selectedCategoryDef.requiredDocTypes
                    .map((dt) => DOC_TYPE_LABELS[dt] || dt)
                    .join(' · ')}
                </div>
              </div>

              <div>
                <label htmlFor="new-programs" className="block text-xs font-medium text-slate-700 mb-1">
                  Proposed / Existing Programs
                </label>
                <input
                  id="new-programs"
                  type="text"
                  value={newPrograms}
                  onChange={(e) => setNewPrograms(e.target.value)}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  required
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label htmlFor="new-intake" className="block text-xs font-medium text-slate-700 mb-1">
                    Requested Intake
                  </label>
                  <input
                    id="new-intake"
                    type="number"
                    min={30}
                    max={5000}
                    value={newIntake}
                    onChange={(e) => setNewIntake(e.target.value)}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-mono tabular-nums"
                    required
                  />
                </div>
                <div>
                  <label htmlFor="new-land" className="block text-xs font-medium text-slate-700 mb-1">
                    Land Area (Acres)
                  </label>
                  <input
                    id="new-land"
                    type="number"
                    step="0.1"
                    value={newLand}
                    onChange={(e) => setNewLand(e.target.value)}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-mono tabular-nums"
                    required
                  />
                </div>
                <div>
                  <label htmlFor="new-built" className="block text-xs font-medium text-slate-700 mb-1">
                    Built-Up Area (sqm)
                  </label>
                  <input
                    id="new-built"
                    type="number"
                    value={newBuiltUp}
                    onChange={(e) => setNewBuiltUp(e.target.value)}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-mono tabular-nums"
                    required
                  />
                </div>
              </div>

              <div>
                <label htmlFor="new-principal" className="block text-xs font-medium text-slate-700 mb-1">
                  Declared Principal / Director Name
                </label>
                <input
                  id="new-principal"
                  type="text"
                  value={newPrincipal}
                  onChange={(e) => setNewPrincipal(e.target.value)}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  required
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-200">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-md border border-slate-300 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 rounded-md bg-blue-900 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-60"
                >
                  {creating ? 'Creating Application...' : 'Create & Open Scrutiny'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Admin Extensible Category Definition Modal */}
      {showCategoryModal && isAdmin && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="create-cat-title"
          className="fixed inset-0 z-50 bg-slate-900/50 flex items-center justify-center p-4"
        >
          <div className="bg-white border border-slate-200 rounded-lg max-w-lg w-full p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between gap-4 border-b border-slate-200 pb-3">
              <div>
                <h2 id="create-cat-title" className="font-display text-lg font-bold text-slate-900">
                  Define Extensible Application Category
                </h2>
                <p className="text-xs text-slate-500">
                  Persists a custom regulatory filing category and mandatory document checklist.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowCategoryModal(false)}
                aria-label="Close category modal"
                className="p-1.5 rounded text-slate-500 hover:bg-slate-100"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {catMessage?.type === 'err' && (
              <div role="alert" className="border border-red-300 bg-red-50 text-red-800 rounded p-3 text-xs">
                {catMessage.text}
              </div>
            )}

            <form onSubmit={handleCreateCategory} className="space-y-3.5 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label htmlFor="cat-code" className="block font-medium text-slate-700 mb-1">
                    Category Code (UPPERCASE_SNAKE)
                  </label>
                  <input
                    id="cat-code"
                    type="text"
                    value={catCode}
                    onChange={(e) => setCatCode(e.target.value.toUpperCase())}
                    placeholder="POSTGRADUATE_EXPANSION"
                    className="w-full rounded border border-slate-300 px-3 py-1.5 font-mono"
                    required
                  />
                </div>
                <div>
                  <label htmlFor="cat-base" className="block font-medium text-slate-700 mb-1">
                    Base Regulatory Track
                  </label>
                  <select
                    id="cat-base"
                    value={catBase}
                    onChange={(e) => setCatBase(e.target.value as ApplicationCategory)}
                    className="w-full rounded border border-slate-300 px-3 py-1.5 bg-white"
                  >
                    {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
                      <option key={k} value={k}>
                        {v}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label htmlFor="cat-name" className="block font-medium text-slate-700 mb-1">
                  Display Title
                </label>
                <input
                  id="cat-name"
                  type="text"
                  value={catName}
                  onChange={(e) => setCatName(e.target.value)}
                  placeholder="Postgraduate M.Tech Intake Expansion"
                  className="w-full rounded border border-slate-300 px-3 py-1.5"
                  required
                />
              </div>

              <div>
                <label htmlFor="cat-desc" className="block font-medium text-slate-700 mb-1">
                  Description
                </label>
                <input
                  id="cat-desc"
                  type="text"
                  value={catDesc}
                  onChange={(e) => setCatDesc(e.target.value)}
                  placeholder="Introduction or expansion of PG technical programs with research lab evidence."
                  className="w-full rounded border border-slate-300 px-3 py-1.5"
                  required
                />
              </div>

              <div>
                <div className="font-medium text-slate-700 mb-1.5">Mandatory Document Checklist</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 border border-slate-200 rounded p-3 max-h-44 overflow-y-auto">
                  {(Object.entries(DOC_TYPE_LABELS) as Array<[DocumentType, string]>)
                    .filter(([dt]) => dt !== 'UNKNOWN_DOCUMENT')
                    .map(([dt, label]) => {
                      const checked = catDocs.includes(dt);
                      return (
                        <label key={dt} className="flex items-center gap-2 text-slate-700 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setCatDocs((prev) => [...prev, dt]);
                              } else {
                                setCatDocs((prev) => prev.filter((x) => x !== dt));
                              }
                            }}
                          />
                          <span className="truncate">{label}</span>
                        </label>
                      );
                    })}
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-200">
                <button
                  type="button"
                  onClick={() => setShowCategoryModal(false)}
                  className="px-3.5 py-1.5 rounded border border-slate-300 text-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={catBusy}
                  className="px-4 py-1.5 rounded bg-blue-900 text-white font-semibold disabled:opacity-60"
                >
                  {catBusy ? 'Saving...' : 'Save Category'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
