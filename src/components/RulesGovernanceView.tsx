import React, { useEffect, useState } from 'react';
import { Plus } from 'lucide-react';
import {
  createRuleApi,
  fetchValidationRules,
  publishRuleVersionApi,
  setRuleStatusApi,
} from '../client/api.ts';
import { DOC_TYPE_LABELS, formatTimestamp, severityColorClass } from '../client/formatters.ts';
import type { DocumentType, UserProfile, ValidationRuleRecord } from '../shared/types.ts';

interface RulesGovernanceViewProps {
  user: UserProfile;
}

const RULE_TYPE_TEMPLATES: Record<string, string> = {
  NUMERIC_MINIMUM: JSON.stringify(
    { fieldName: 'total_faculty_count', minValue: 16, unit: 'faculty members' },
    null,
    2
  ),
  FIELD_PRESENCE: JSON.stringify(
    { requiredFields: ['certificate_number', 'institution_name'] },
    null,
    2
  ),
  RATIO_THRESHOLD: JSON.stringify({ minBuiltUpSqmPerStudent: 4.5 }, null, 2),
  CHECKLIST_PRESENCE: JSON.stringify(
    { requiredByCategory: { NEW_INSTITUTION: ['FLOOR_PLAN_DRAWING'] } },
    null,
    2
  ),
  TEMPORAL_VALIDITY: JSON.stringify({ gracePeriodDays: 0 }, null, 2),
  CONFIDENCE_THRESHOLD: JSON.stringify({ minConfidence: 0.72 }, null, 2),
};

export function RulesGovernanceView({ user }: RulesGovernanceViewProps) {
  const [rules, setRules] = useState<ValidationRuleRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Version Update Form State
  const [editingCode, setEditingCode] = useState<string | null>(null);
  const [newVersion, setNewVersion] = useState('');
  const [newSeverity, setNewSeverity] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('HIGH');
  const [newDesc, setNewDesc] = useState('');
  const [newConfigJson, setNewConfigJson] = useState('{}');
  const [newEffectiveFrom, setNewEffectiveFrom] = useState('');
  const [newEffectiveTo, setNewEffectiveTo] = useState('');
  const [newRecommendedAction, setNewRecommendedAction] = useState('');
  const [saving, setSaving] = useState(false);
  const [togglingCode, setTogglingCode] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Create New Rule Form State (Admin)
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [createCode, setCreateCode] = useState('RULE-CUSTOM-FACULTY-MIN');
  const [createVersion, setCreateVersion] = useState('1.0.0');
  const [createName, setCreateName] = useState('Minimum Declared Faculty Count');
  const [createDesc, setCreateDesc] = useState(
    'Illustrative configurable check verifying extracted faculty roster count meets minimum threshold.'
  );
  const [createCategory, setCreateCategory] = useState('ALL');
  const [createDocType, setCreateDocType] = useState<string>('FACULTY_ROSTER_STATEMENT');
  const [createRuleType, setCreateRuleType] = useState('NUMERIC_MINIMUM');
  const [createSeverity, setCreateSeverity] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('MEDIUM');
  const [createEffectiveFrom, setCreateEffectiveFrom] = useState('2026-01-01');
  const [createEffectiveTo, setCreateEffectiveTo] = useState('');
  const [createRecommendedAction, setCreateRecommendedAction] = useState(
    'Verify faculty cadre roster and appointment letters against programme intake.'
  );
  const [createIllustrative, setCreateIllustrative] = useState(true);
  const [createConfigJson, setCreateConfigJson] = useState(RULE_TYPE_TEMPLATES.NUMERIC_MINIMUM);
  const [creatingRule, setCreatingRule] = useState(false);

  const isAdmin = user.role === 'ADMIN';

  const loadRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchValidationRules();
      setRules(res.rules);
    } catch (err) {
      setError((err as Error).message || 'Failed to load validation rules.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const bumpPatch = (ver: string) => {
    const parts = ver.split('.').map((n) => Number.parseInt(n, 10));
    if (parts.length === 3 && parts.every((n) => Number.isFinite(n))) {
      return `${parts[0]}.${parts[1] + 1}.0`;
    }
    return '1.1.0';
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);

    let parsedConfig: Record<string, unknown>;
    try {
      parsedConfig = JSON.parse(createConfigJson) as Record<string, unknown>;
    } catch {
      setFeedback({ type: 'err', text: 'Rule configuration JSON is syntactically invalid.' });
      return;
    }

    setCreatingRule(true);
    try {
      const created = await createRuleApi({
        ruleCode: createCode.trim().toUpperCase(),
        version: createVersion.trim(),
        name: createName.trim(),
        description: createDesc.trim(),
        category: createCategory,
        docType: createDocType || null,
        ruleType: createRuleType,
        severity: createSeverity,
        authoritySource: createIllustrative
          ? 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE'
          : 'INSTITUTIONAL_CROSSCHECK',
        config: parsedConfig,
        effectiveFrom: createEffectiveFrom.trim() || null,
        effectiveTo: createEffectiveTo.trim() || null,
        recommendedAction: createRecommendedAction.trim() || null,
        isIllustrative: createIllustrative,
        isActive: true,
      });
      setShowCreateForm(false);
      setFeedback({
        type: 'ok',
        text: `Created and validated rule ${created.ruleCode} (v${created.version}) and recorded audit entry.`,
      });
      await loadRules();
    } catch (err) {
      setFeedback({ type: 'err', text: (err as Error).message });
    } finally {
      setCreatingRule(false);
    }
  };

  const handlePublish = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingCode) return;
    setFeedback(null);

    let parsedConfig: Record<string, unknown>;
    try {
      parsedConfig = JSON.parse(newConfigJson) as Record<string, unknown>;
    } catch {
      setFeedback({ type: 'err', text: 'Configuration JSON is syntactically invalid.' });
      return;
    }

    setSaving(true);
    try {
      await publishRuleVersionApi(editingCode, {
        version: newVersion.trim(),
        severity: newSeverity,
        description: newDesc.trim(),
        config: parsedConfig,
        effectiveFrom: newEffectiveFrom.trim() || null,
        effectiveTo: newEffectiveTo.trim() || null,
        recommendedAction: newRecommendedAction.trim() || null,
      });
      setEditingCode(null);
      setFeedback({
        type: 'ok',
        text: `Published ${editingCode} version ${newVersion.trim()} and logged audit event.`,
      });
      await loadRules();
    } catch (err) {
      setFeedback({ type: 'err', text: (err as Error).message });
    } finally {
      setSaving(false);
    }
  };

  const handleToggleRuleStatus = async (ruleCode: string, nextActive: boolean) => {
    setFeedback(null);
    setTogglingCode(ruleCode);
    try {
      await setRuleStatusApi(ruleCode, nextActive);
      setFeedback({
        type: 'ok',
        text: `${nextActive ? 'Activated' : 'Deactivated'} ${ruleCode} and recorded audit event.`,
      });
      await loadRules();
    } catch (err) {
      setFeedback({ type: 'err', text: (err as Error).message });
    } finally {
      setTogglingCode(null);
    }
  };

  // Identify primary/latest entry per ruleCode so deactivated rules can still be re-enabled or versioned
  const primaryIdByCode = new Map<string, string>();
  const hasActiveByCode = new Set<string>();
  for (const r of rules) {
    if (r.isActive) hasActiveByCode.add(r.ruleCode);
    if (!primaryIdByCode.has(r.ruleCode)) {
      primaryIdByCode.set(r.ruleCode, r.id);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-slate-900">
            Versioned Regulatory Rules Engine
          </h1>
          <p className="text-sm text-slate-600 mt-1 max-w-3xl">
            Compliance rules are persisted with semantic versions, effective dates, pre-publication schema
            validation, and auditable parameter changes. Configurable sample policy thresholds are explicitly
            distinguished from institutional cross-checks and SHA-256 integrity checks.
          </p>
        </div>

        {isAdmin && (
          <button
            type="button"
            onClick={() => {
              setFeedback(null);
              setShowCreateForm((prev) => !prev);
            }}
            className="inline-flex items-center gap-2 rounded-md bg-blue-950 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-900 transition-colors whitespace-nowrap shrink-0"
          >
            <Plus className="w-4 h-4" />
            <span>{showCreateForm ? 'Close Rule Creator' : 'Create Configurable Rule'}</span>
          </button>
        )}
      </div>

      {feedback && (
        <div
          role={feedback.type === 'err' ? 'alert' : 'status'}
          className={`rounded-lg border px-4 py-3 text-sm ${
            feedback.type === 'err'
              ? 'border-red-300 bg-red-50 text-red-800'
              : 'border-emerald-300 bg-emerald-50 text-emerald-900'
          }`}
        >
          {feedback.text}
        </div>
      )}

      {showCreateForm && isAdmin && (
        <form
          onSubmit={handleCreateRule}
          aria-label="Create New Validation Rule"
          className="bg-white border border-slate-200 rounded-lg p-6 space-y-4 text-xs"
        >
          <div className="border-b border-slate-200 pb-3">
            <h2 className="font-display text-base font-semibold text-slate-900">
              Create &amp; Validate New Regulatory Rule
            </h2>
            <p className="text-slate-500 mt-0.5">
              Rule parameters and effective dates are validated before saving. Invalid rule configurations are
              rejected and never silently executed.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label htmlFor="create-rule-code" className="block font-medium text-slate-700 mb-1">
                Rule Code (RULE-...)
              </label>
              <input
                id="create-rule-code"
                type="text"
                value={createCode}
                onChange={(e) => setCreateCode(e.target.value.toUpperCase())}
                className="w-full rounded border border-slate-300 px-3 py-1.5 font-mono"
                required
              />
            </div>

            <div>
              <label htmlFor="create-rule-version" className="block font-medium text-slate-700 mb-1">
                Semantic Version
              </label>
              <input
                id="create-rule-version"
                type="text"
                value={createVersion}
                onChange={(e) => setCreateVersion(e.target.value)}
                className="w-full rounded border border-slate-300 px-3 py-1.5 font-mono"
                required
              />
            </div>

            <div>
              <label htmlFor="create-rule-type" className="block font-medium text-slate-700 mb-1">
                Rule Execution Type
              </label>
              <select
                id="create-rule-type"
                value={createRuleType}
                onChange={(e) => {
                  const nextType = e.target.value;
                  setCreateRuleType(nextType);
                  if (RULE_TYPE_TEMPLATES[nextType]) {
                    setCreateConfigJson(RULE_TYPE_TEMPLATES[nextType]);
                  }
                }}
                className="w-full rounded border border-slate-300 px-3 py-1.5 bg-white"
              >
                <option value="NUMERIC_MINIMUM">NUMERIC_MINIMUM</option>
                <option value="FIELD_PRESENCE">FIELD_PRESENCE</option>
                <option value="RATIO_THRESHOLD">RATIO_THRESHOLD</option>
                <option value="CHECKLIST_PRESENCE">CHECKLIST_PRESENCE</option>
                <option value="TEMPORAL_VALIDITY">TEMPORAL_VALIDITY</option>
                <option value="CONFIDENCE_THRESHOLD">CONFIDENCE_THRESHOLD</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label htmlFor="create-rule-name" className="block font-medium text-slate-700 mb-1">
                Rule Title
              </label>
              <input
                id="create-rule-name"
                type="text"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                className="w-full rounded border border-slate-300 px-3 py-1.5"
                required
              />
            </div>

            <div>
              <label htmlFor="create-rule-cat" className="block font-medium text-slate-700 mb-1">
                Target Category
              </label>
              <select
                id="create-rule-cat"
                value={createCategory}
                onChange={(e) => setCreateCategory(e.target.value)}
                className="w-full rounded border border-slate-300 px-3 py-1.5 bg-white"
              >
                <option value="ALL">ALL Categories</option>
                <option value="EXTENSION_OF_APPROVAL">Extension of Approval (EoA)</option>
                <option value="NEW_INSTITUTION">New Technical Institution</option>
                <option value="INCREASE_IN_INTAKE">Increase in Approved Intake</option>
              </select>
            </div>

            <div>
              <label htmlFor="create-rule-doctype" className="block font-medium text-slate-700 mb-1">
                Target Document Type (Optional)
              </label>
              <select
                id="create-rule-doctype"
                value={createDocType}
                onChange={(e) => setCreateDocType(e.target.value)}
                className="w-full rounded border border-slate-300 px-3 py-1.5 bg-white"
              >
                <option value="">Application-Wide (No single doc filter)</option>
                {(Object.entries(DOC_TYPE_LABELS) as Array<[DocumentType, string]>).map(([k, lbl]) => (
                  <option key={k} value={k}>
                    {lbl}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label htmlFor="create-rule-desc" className="block font-medium text-slate-700 mb-1">
              Rule Description
            </label>
            <input
              id="create-rule-desc"
              type="text"
              value={createDesc}
              onChange={(e) => setCreateDesc(e.target.value)}
              className="w-full rounded border border-slate-300 px-3 py-1.5"
              required
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label htmlFor="create-rule-severity" className="block font-medium text-slate-700 mb-1">
                Severity
              </label>
              <select
                id="create-rule-severity"
                value={createSeverity}
                onChange={(e) =>
                  setCreateSeverity(e.target.value as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW')
                }
                className="w-full rounded border border-slate-300 px-3 py-1.5 bg-white"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>

            <div>
              <label htmlFor="create-rule-from" className="block font-medium text-slate-700 mb-1">
                Effective From (YYYY-MM-DD)
              </label>
              <input
                id="create-rule-from"
                type="text"
                value={createEffectiveFrom}
                onChange={(e) => setCreateEffectiveFrom(e.target.value)}
                placeholder="2026-01-01"
                className="w-full rounded border border-slate-300 px-3 py-1.5 font-mono"
              />
            </div>

            <div>
              <label htmlFor="create-rule-to" className="block font-medium text-slate-700 mb-1">
                Effective To (Optional YYYY-MM-DD)
              </label>
              <input
                id="create-rule-to"
                type="text"
                value={createEffectiveTo}
                onChange={(e) => setCreateEffectiveTo(e.target.value)}
                placeholder="Leave blank for open-ended"
                className="w-full rounded border border-slate-300 px-3 py-1.5 font-mono"
              />
            </div>
          </div>

          <div>
            <label htmlFor="create-rule-action" className="block font-medium text-slate-700 mb-1">
              Recommended Officer Follow-Up Action
            </label>
            <input
              id="create-rule-action"
              type="text"
              value={createRecommendedAction}
              onChange={(e) => setCreateRecommendedAction(e.target.value)}
              className="w-full rounded border border-slate-300 px-3 py-1.5"
            />
          </div>

          <div>
            <label htmlFor="create-rule-config" className="block font-medium text-slate-700 mb-1">
              Rule Parameters (JSON)
            </label>
            <textarea
              id="create-rule-config"
              rows={4}
              value={createConfigJson}
              onChange={(e) => setCreateConfigJson(e.target.value)}
              className="w-full rounded border border-slate-300 px-3 py-1.5 font-mono"
            />
          </div>

          <label className="flex items-center gap-2 text-slate-700 cursor-pointer">
            <input
              type="checkbox"
              checked={createIllustrative}
              onChange={(e) => setCreateIllustrative(e.target.checked)}
            />
            <span>
              Mark explicitly as Configurable / Illustrative Policy Rule (not claimed as hardcoded statutory law)
            </span>
          </label>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-200">
            <button
              type="button"
              onClick={() => setShowCreateForm(false)}
              className="px-3.5 py-1.5 rounded border border-slate-300 text-slate-700"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creatingRule}
              className="px-4 py-1.5 rounded bg-blue-900 text-white font-semibold disabled:opacity-60"
            >
              {creatingRule ? 'Validating & Saving...' : 'Validate & Save Rule'}
            </button>
          </div>
        </form>
      )}

      {error && (
        <div
          role="alert"
          className="border border-red-300 bg-red-50 text-red-800 rounded-lg p-4 text-sm flex items-center justify-between gap-4"
        >
          <span>{error}</span>
          <button
            type="button"
            onClick={loadRules}
            className="px-3 py-1.5 rounded-md bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 whitespace-nowrap shrink-0"
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="h-48 bg-white border border-slate-200 rounded-lg animate-pulse" aria-busy="true" />
      ) : rules.length === 0 ? (
        <div className="bg-white border border-slate-200 rounded-lg p-8 text-center text-sm text-slate-500">
          No validation rules configured in the database.
        </div>
      ) : (
        <div className="bg-white border border-slate-200 rounded-lg divide-y divide-slate-200">
          {rules.map((r) => {
            const isPrimaryRow = primaryIdByCode.get(r.ruleCode) === r.id;
            const codeHasActive = hasActiveByCode.has(r.ruleCode);
            const statusLabel = r.isActive
              ? 'Active Version'
              : !codeHasActive && isPrimaryRow
                ? 'Disabled by Administrator'
                : 'Superseded Version';

            return (
              <div key={r.id} className="p-5 space-y-3">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                      <span className="font-bold text-slate-900">{r.ruleCode}</span>
                      <span aria-hidden="true">·</span>
                      <span>v{r.version}</span>
                      <span aria-hidden="true">·</span>
                      <span
                        className={
                          r.isActive
                            ? 'text-emerald-700 font-semibold'
                            : !codeHasActive && isPrimaryRow
                              ? 'text-amber-700 font-semibold'
                              : 'text-slate-400'
                        }
                      >
                        {statusLabel}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className={severityColorClass(r.severity)}>{r.severity}</span>
                      <span aria-hidden="true">·</span>
                      <span className="text-slate-500">{r.ruleType}</span>
                      <span aria-hidden="true">·</span>
                      <span className="text-slate-500">Category: {r.category}</span>
                    </div>
                    <h2 className="text-base font-semibold text-slate-900">{r.name}</h2>
                    <p className="text-sm text-slate-600">{r.description}</p>
                    {(r.effectiveFrom || r.effectiveTo || r.recommendedAction) && (
                      <div className="text-xs text-slate-500 pt-0.5">
                        {r.effectiveFrom || r.effectiveTo
                          ? `Effective Window: ${r.effectiveFrom || 'Inception'} to ${r.effectiveTo || 'Open'} `
                          : ''}
                        {r.recommendedAction ? `· Action: ${r.recommendedAction}` : ''}
                      </div>
                    )}
                  </div>

                  <div className="text-right space-y-1 shrink-0">
                    <div className="text-xs text-slate-500">
                      {r.authoritySource === 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE' || r.isIllustrative
                        ? 'Configurable Example Rule'
                        : r.authoritySource === 'INSTITUTIONAL_CROSSCHECK'
                          ? 'Institutional Cross-Check'
                          : 'Cryptographic Integrity Check'}
                    </div>
                    <div className="text-xs font-mono text-slate-400 tabular-nums">
                      Updated {formatTimestamp(r.updatedAt)}
                    </div>
                    {isAdmin && isPrimaryRow && (
                      <div className="flex items-center justify-end gap-3 pt-1">
                        <button
                          type="button"
                          disabled={togglingCode === r.ruleCode}
                          onClick={() => handleToggleRuleStatus(r.ruleCode, !r.isActive)}
                          className="text-xs font-medium text-slate-700 hover:text-slate-900 hover:underline disabled:opacity-50"
                        >
                          {togglingCode === r.ruleCode
                            ? 'Updating...'
                            : r.isActive
                              ? 'Deactivate Rule'
                              : 'Activate Rule'}
                        </button>
                        <span className="text-slate-300" aria-hidden="true">
                          ·
                        </span>
                        <button
                          type="button"
                          onClick={() => {
                            setEditingCode(r.ruleCode);
                            setNewVersion(bumpPatch(r.version));
                            setNewSeverity(r.severity);
                            setNewDesc(r.description);
                            setNewConfigJson(JSON.stringify(r.config, null, 2));
                            setNewEffectiveFrom(r.effectiveFrom || '');
                            setNewEffectiveTo(r.effectiveTo || '');
                            setNewRecommendedAction(r.recommendedAction || '');
                          }}
                          className="text-xs font-medium text-blue-800 hover:underline"
                        >
                          Configure New Version
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {Object.keys(r.config).length > 0 && (
                  <pre className="rounded border border-slate-200 bg-slate-50 p-3 text-xs font-mono text-slate-700 overflow-x-auto">
                    {JSON.stringify(r.config, null, 2)}
                  </pre>
                )}

                {editingCode === r.ruleCode && isPrimaryRow && (
                  <form
                    onSubmit={handlePublish}
                    className="pt-4 border-t border-slate-200 space-y-3 bg-slate-50/70 p-4 rounded-md"
                  >
                    <div className="text-xs font-semibold text-slate-800">
                      Publish New Version for {r.ruleCode}
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                      <div>
                        <label className="block text-xs text-slate-600 mb-1">New Semantic Version</label>
                        <input
                          type="text"
                          value={newVersion}
                          onChange={(e) => setNewVersion(e.target.value)}
                          className="w-full rounded border border-slate-300 px-3 py-1.5 text-xs font-mono bg-white"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-slate-600 mb-1">Severity</label>
                        <select
                          value={newSeverity}
                          onChange={(e) =>
                            setNewSeverity(e.target.value as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW')
                          }
                          className="w-full rounded border border-slate-300 px-3 py-1.5 text-xs bg-white"
                        >
                          <option value="CRITICAL">CRITICAL</option>
                          <option value="HIGH">HIGH</option>
                          <option value="MEDIUM">MEDIUM</option>
                          <option value="LOW">LOW</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs text-slate-600 mb-1">Effective From</label>
                        <input
                          type="text"
                          value={newEffectiveFrom}
                          onChange={(e) => setNewEffectiveFrom(e.target.value)}
                          placeholder="YYYY-MM-DD"
                          className="w-full rounded border border-slate-300 px-3 py-1.5 text-xs font-mono bg-white"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-slate-600 mb-1">Effective To</label>
                        <input
                          type="text"
                          value={newEffectiveTo}
                          onChange={(e) => setNewEffectiveTo(e.target.value)}
                          placeholder="Optional YYYY-MM-DD"
                          className="w-full rounded border border-slate-300 px-3 py-1.5 text-xs font-mono bg-white"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-xs text-slate-600 mb-1">Rule Description</label>
                      <input
                        type="text"
                        value={newDesc}
                        onChange={(e) => setNewDesc(e.target.value)}
                        className="w-full rounded border border-slate-300 px-3 py-1.5 text-xs bg-white"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-600 mb-1">Recommended Officer Action</label>
                      <input
                        type="text"
                        value={newRecommendedAction}
                        onChange={(e) => setNewRecommendedAction(e.target.value)}
                        className="w-full rounded border border-slate-300 px-3 py-1.5 text-xs bg-white"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-600 mb-1">Rule Parameters (JSON)</label>
                      <textarea
                        rows={4}
                        value={newConfigJson}
                        onChange={(e) => setNewConfigJson(e.target.value)}
                        className="w-full rounded border border-slate-300 px-3 py-1.5 text-xs font-mono bg-white"
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="submit"
                        disabled={saving}
                        className="px-4 py-1.5 rounded bg-blue-900 text-white text-xs font-semibold"
                      >
                        {saving ? 'Publishing...' : 'Publish Rule Version'}
                      </button>
                      <button
                        type="button"
                        onClick={() => setEditingCode(null)}
                        className="px-3 py-1.5 rounded border border-slate-300 text-xs text-slate-700 bg-white"
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
    </div>
  );
}
