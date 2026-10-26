/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Typed Frontend API Client with In-Memory Session/CSRF Token Management
 */

import type {
  ApplicationCategory,
  ApplicationCategoryDefinition,
  ApplicationDetail,
  ApplicationSummary,
  AuditLogRecord,
  ComplianceItemStatus,
  DashboardStats,
  DocumentRecord,
  DocumentType,
  InAppNotificationRecord,
  InstitutionRecord,
  LifecycleStage,
  OfficerActionType,
  SourceVerificationRecord,
  UserProfile,
  UserRole,
  ValidationRuleRecord,
  VerificationMethod,
  VerificationStatus,
} from '../shared/types.ts';

const SESSION_TOKEN_STORAGE_KEY = 'authentix_session_token';
const CSRF_TOKEN_STORAGE_KEY = 'authentix_csrf_token';

function readSessionValue(key: string): string | null {
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      return window.sessionStorage.getItem(key);
    }
  } catch {
    // Restricted storage environment — fall back to in-memory only
  }
  return null;
}

function writeSessionValue(key: string, value: string | null): void {
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      if (value) {
        window.sessionStorage.setItem(key, value);
      } else {
        window.sessionStorage.removeItem(key);
      }
    }
  } catch {
    // Restricted storage environment — ignore
  }
}

let csrfTokenInMemory: string | null = readSessionValue(CSRF_TOKEN_STORAGE_KEY);
let sessionTokenInMemory: string | null = readSessionValue(SESSION_TOKEN_STORAGE_KEY);
let onUnauthorizedHandler: (() => void) | null = null;

export function registerUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorizedHandler = fn;
}

export function setAuthTokens(csrfToken: string | null, sessionToken?: string | null): void {
  csrfTokenInMemory = csrfToken;
  writeSessionValue(CSRF_TOKEN_STORAGE_KEY, csrfToken);
  if (sessionToken !== undefined) {
    sessionTokenInMemory = sessionToken;
    writeSessionValue(SESSION_TOKEN_STORAGE_KEY, sessionToken);
  }
}

export function clearAuthTokens(): void {
  csrfTokenInMemory = null;
  sessionTokenInMemory = null;
  writeSessionValue(CSRF_TOKEN_STORAGE_KEY, null);
  writeSessionValue(SESSION_TOKEN_STORAGE_KEY, null);
}

function buildAuthHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...(extra || {}) };
  if (csrfTokenInMemory) {
    headers['X-CSRF-Token'] = csrfTokenInMemory;
  }
  if (sessionTokenInMemory) {
    headers['Authorization'] = `Bearer ${sessionTokenInMemory}`;
  }
  return headers;
}

async function apiRequest<T>(url: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method || 'GET').toUpperCase();
  const baseHeaders: Record<string, string> = {};
  if (init.body && !(init.body instanceof FormData)) {
    baseHeaders['Content-Type'] = 'application/json';
  }

  const res = await fetch(url, {
    ...init,
    method,
    credentials: 'include',
    headers: buildAuthHeaders({
      ...baseHeaders,
      ...(init.headers as Record<string, string> | undefined),
    }),
  });

  if (res.status === 401 && !url.includes('/api/auth/login')) {
    clearAuthTokens();
    if (!url.includes('/api/auth/me') && onUnauthorizedHandler) {
      onUnauthorizedHandler();
    }
  }

  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : await res.text();

  if (!res.ok) {
    const errMsg =
      typeof data === 'object' && data !== null && 'error' in data
        ? String((data as { error: unknown }).error)
        : `Request failed with HTTP ${res.status}`;
    throw new Error(errMsg);
  }

  return data as T;
}

export async function fetchHealthStatus(): Promise<{
  status: string;
  demoMode: boolean;
  externalAuthorityMode?: string;
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
}> {
  return apiRequest('/api/health');
}

export async function fetchDemoStatus(): Promise<{ demoMode: boolean }> {
  return apiRequest('/api/auth/demo-status');
}

export async function fetchDemoAccounts(): Promise<{
  demoMode: boolean;
  demoPassphrase?: string;
  accounts: Array<{
    email: string;
    fullName: string;
    role: UserRole;
    institutionName: string | null;
    isSyntheticDemo?: boolean;
  }>;
}> {
  return apiRequest('/api/auth/demo-accounts');
}

export async function loginApi(email: string, password: string): Promise<{
  user: UserProfile;
  csrfToken: string;
  sessionToken: string;
  expiresAt: string;
  demoMode?: boolean;
}> {
  const res = await apiRequest<{
    user: UserProfile;
    csrfToken: string;
    sessionToken: string;
    expiresAt: string;
    demoMode?: boolean;
  }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  setAuthTokens(res.csrfToken, res.sessionToken);
  return res;
}

export async function fetchCurrentUser(): Promise<{ user: UserProfile; csrfToken: string; demoMode?: boolean }> {
  const res = await apiRequest<{ user: UserProfile; csrfToken: string; demoMode?: boolean }>('/api/auth/me');
  setAuthTokens(res.csrfToken);
  return res;
}

export async function logoutApi(): Promise<void> {
  try {
    await apiRequest('/api/auth/logout', { method: 'POST' });
  } finally {
    clearAuthTokens();
  }
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  return apiRequest('/api/dashboard/stats');
}

export async function fetchCategories(): Promise<{ categories: ApplicationCategoryDefinition[] }> {
  return apiRequest('/api/categories');
}

export async function createCategoryApi(payload: {
  code: string;
  baseCategory: ApplicationCategory;
  name: string;
  description: string;
  requiredDocTypes: DocumentType[];
}): Promise<ApplicationCategoryDefinition> {
  return apiRequest('/api/categories', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchInstitutions(): Promise<{ institutions: InstitutionRecord[] }> {
  return apiRequest('/api/institutions');
}

export async function fetchSampleFixtures(): Promise<{
  fixtures: Array<{ filename: string; sizeBytes: number; description: string }>;
}> {
  return apiRequest('/api/sample-fixtures');
}

export async function downloadAuthenticatedBlob(url: string, downloadFilename: string): Promise<void> {
  const res = await fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers: buildAuthHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Download failed (HTTP ${res.status})`);
  }
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = downloadFilename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 2000);
}

export async function fetchDocumentPreviewObjectUrl(docId: string): Promise<string> {
  const res = await fetch(`/api/documents/${encodeURIComponent(docId)}/file`, {
    method: 'GET',
    credentials: 'include',
    headers: buildAuthHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Unable to load document preview (HTTP ${res.status})`);
  }
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

export async function fetchApplications(params: {
  q?: string;
  status?: string;
  category?: string;
  priority?: string;
  lifecycleStage?: string;
  institutionId?: string;
  page?: number;
  pageSize?: number;
}): Promise<{
  applications: ApplicationSummary[];
  pagination: { page: number; pageSize: number; totalCount: number; totalPages: number };
}> {
  const sp = new URLSearchParams();
  if (params.q) sp.set('q', params.q);
  if (params.status && params.status !== 'ALL') sp.set('status', params.status);
  if (params.category && params.category !== 'ALL') sp.set('category', params.category);
  if (params.priority && params.priority !== 'ALL') sp.set('priority', params.priority);
  if (params.lifecycleStage && params.lifecycleStage !== 'ALL') sp.set('lifecycleStage', params.lifecycleStage);
  if (params.institutionId && params.institutionId !== 'ALL') sp.set('institutionId', params.institutionId);
  if (params.page) sp.set('page', String(params.page));
  if (params.pageSize) sp.set('pageSize', String(params.pageSize));
  const qs = sp.toString();
  return apiRequest(`/api/applications${qs ? `?${qs}` : ''}`);
}

export async function createApplicationApi(payload: {
  institutionId: string;
  academicYear: string;
  category: ApplicationCategory;
  categoryCode?: string;
  programNames: string;
  requestedIntake: number;
  submittedLandAcres: number;
  submittedBuiltUpSqm: number;
  submittedPrincipalName: string;
}): Promise<ApplicationDetail> {
  return apiRequest('/api/applications', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchApplicationDetail(appId: string): Promise<ApplicationDetail> {
  return apiRequest(`/api/applications/${encodeURIComponent(appId)}`);
}

export async function resubmitApplicationApi(
  appId: string,
  payload: {
    resubmissionSummary: string;
    requestedIntake?: number;
    submittedLandAcres?: number;
    submittedBuiltUpSqm?: number;
    submittedPrincipalName?: string;
  }
): Promise<ApplicationDetail> {
  return apiRequest(`/api/applications/${encodeURIComponent(appId)}/resubmit`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function reEvaluateApplicationApi(appId: string): Promise<ApplicationDetail> {
  return apiRequest(`/api/applications/${encodeURIComponent(appId)}/re-evaluate`, {
    method: 'POST',
  });
}

export function uploadApplicationDocument(params: {
  applicationId: string;
  file: File;
  declaredDocType: DocumentType;
  onProgress?: (percent: number) => void;
}): Promise<{
  document: DocumentRecord;
  processingWarning: string | null;
  application: ApplicationDetail;
}> {
  return new Promise((resolve, reject) => {
    const formData = new FormData();
    formData.append('file', params.file);
    formData.append('declaredDocType', params.declaredDocType);

    // Use fetch in test environments where XMLHttpRequest upload events may be minimal
    if (typeof XMLHttpRequest === 'undefined' || navigator.userAgent.includes('jsdom')) {
      if (params.onProgress) params.onProgress(50);
      apiRequest<{
        document: DocumentRecord;
        processingWarning: string | null;
        application: ApplicationDetail;
      }>(`/api/applications/${encodeURIComponent(params.applicationId)}/documents`, {
        method: 'POST',
        body: formData,
      })
        .then((res) => {
          if (params.onProgress) params.onProgress(100);
          resolve(res);
        })
        .catch(reject);
      return;
    }

    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/applications/${encodeURIComponent(params.applicationId)}/documents`);
    xhr.withCredentials = true;

    const authHeaders = buildAuthHeaders();
    for (const [k, v] of Object.entries(authHeaders)) {
      xhr.setRequestHeader(k, v);
    }

    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable && params.onProgress) {
        params.onProgress(Math.round((ev.loaded / ev.total) * 100));
      }
    };

    xhr.onload = () => {
      try {
        const parsed = JSON.parse(xhr.responseText || '{}');
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(parsed);
        } else {
          if (xhr.status === 401 && onUnauthorizedHandler) onUnauthorizedHandler();
          reject(new Error(parsed.error || `Upload failed with HTTP ${xhr.status}`));
        }
      } catch {
        reject(new Error(`Unexpected response from server (HTTP ${xhr.status})`));
      }
    };

    xhr.onerror = () => reject(new Error('Network error while uploading document.'));
    xhr.send(formData);
  });
}

export async function reprocessDocumentOcrApi(
  appId: string,
  docId: string
): Promise<{
  document: DocumentRecord | null;
  processingWarning: string | null;
  application: ApplicationDetail;
}> {
  return apiRequest(
    `/api/applications/${encodeURIComponent(appId)}/documents/${encodeURIComponent(docId)}/reprocess`,
    {
      method: 'POST',
      body: JSON.stringify({}),
    }
  );
}

export async function correctFieldApi(
  docId: string,
  fieldId: string,
  fieldValue: string,
  correctionNote: string
): Promise<ApplicationDetail> {
  return apiRequest(`/api/documents/${encodeURIComponent(docId)}/fields/${encodeURIComponent(fieldId)}`, {
    method: 'PATCH',
    body: JSON.stringify({ fieldValue, correctionNote }),
  });
}

export async function verifyDocumentSourceApi(
  appId: string,
  docId: string,
  payload: {
    method: VerificationMethod;
    issuerName?: string;
    referenceNumber?: string;
    manualStatus?: VerificationStatus;
    notes?: string;
    simulateIssuerUnavailable?: boolean;
  }
): Promise<{ verification: SourceVerificationRecord; application: ApplicationDetail }> {
  return apiRequest(
    `/api/applications/${encodeURIComponent(appId)}/documents/${encodeURIComponent(docId)}/verify-source`,
    {
      method: 'POST',
      body: JSON.stringify(payload),
    }
  );
}

export async function reviewComplianceItemApi(
  appId: string,
  itemId: string,
  payload: {
    complianceStatus: ComplianceItemStatus;
    officerObservation: string;
    additionalEvidenceRequested?: boolean;
    additionalEvidenceNote?: string | null;
    physicalInspectionFlagged?: boolean;
  }
): Promise<ApplicationDetail> {
  return apiRequest(
    `/api/applications/${encodeURIComponent(appId)}/compliance-items/${encodeURIComponent(itemId)}`,
    {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }
  );
}

export async function recordOfficerActionApi(
  appId: string,
  payload: {
    actionType: Exclude<
      OfficerActionType,
      'RECORD_MANUAL_VERIFICATION' | 'CORRECT_EXTRACTED_FIELD' | 'RESUBMIT_APPLICATION'
    >;
    documentId?: string | null;
    findingId?: string | null;
    rationale: string;
    evidenceReference?: string;
  }
): Promise<ApplicationDetail> {
  return apiRequest(`/api/applications/${encodeURIComponent(appId)}/officer-actions`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchValidationRules(): Promise<{
  rules: ValidationRuleRecord[];
  supportedRuleTypes?: string[];
}> {
  return apiRequest('/api/rules');
}

export async function createRuleApi(payload: {
  ruleCode: string;
  version: string;
  name: string;
  description: string;
  category: string;
  docType?: string | null;
  ruleType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  authoritySource?: ValidationRuleRecord['authoritySource'];
  config: Record<string, unknown>;
  effectiveFrom?: string | null;
  effectiveTo?: string | null;
  expectedFields?: string[];
  recommendedAction?: string | null;
  evidenceReferenceLabel?: string | null;
  isIllustrative?: boolean;
  isActive?: boolean;
}): Promise<{ id: string; ruleCode: string; version: string; isActive: boolean; updatedAt: string }> {
  return apiRequest('/api/rules', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function publishRuleVersionApi(
  ruleCode: string,
  payload: {
    version: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    description: string;
    config: Record<string, unknown>;
    effectiveFrom?: string | null;
    effectiveTo?: string | null;
    expectedFields?: string[];
    recommendedAction?: string | null;
    evidenceReferenceLabel?: string | null;
    isIllustrative?: boolean;
  }
): Promise<{ ruleCode: string; version: string; updatedAt: string }> {
  return apiRequest(`/api/rules/${encodeURIComponent(ruleCode)}/versions`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function setRuleStatusApi(
  ruleCode: string,
  isActive: boolean
): Promise<{ ruleCode: string; version: string; isActive: boolean; updatedAt: string }> {
  return apiRequest(`/api/rules/${encodeURIComponent(ruleCode)}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ isActive }),
  });
}

export async function fetchNotificationsApi(): Promise<{
  deliveryMode: 'IN_APP_ONLY';
  deliveryNotice: string;
  unreadCount: number;
  notifications: InAppNotificationRecord[];
}> {
  return apiRequest('/api/notifications');
}

export async function markNotificationReadApi(
  notifId: string
): Promise<{ id: string; isRead: boolean; readAt: string }> {
  return apiRequest(`/api/notifications/${encodeURIComponent(notifId)}/read`, {
    method: 'PATCH',
  });
}

export async function markAllNotificationsReadApi(): Promise<{
  markedReadCount: number;
  readAt: string;
}> {
  return apiRequest('/api/notifications/read-all', {
    method: 'POST',
  });
}

export async function fetchValidationReportJson(appId: string): Promise<{
  generatedAt: string;
  generatedBy: { email: string; role: string };
  regulatoryDisclaimer: string;
  summaryMetrics?: {
    submissionCycle: number;
    lifecycleStage: LifecycleStage;
    openFindingsCount: number;
    priorCycleFindingsCount: number;
    complianceSatisfiedCount: number;
    complianceUnresolvedCount: number;
    physicalInspectionRequired: boolean;
  };
  application: ApplicationDetail;
}> {
  return apiRequest(`/api/applications/${encodeURIComponent(appId)}/report?format=json`);
}

export async function fetchAuditLogsApi(params?: {
  resourceId?: string;
  action?: string;
  limit?: number;
}): Promise<{
  logs: AuditLogRecord[];
  chainVerification: {
    valid: boolean;
    totalEventsChecked: number;
    headHash: string;
    brokenAtEventId?: string;
    reason?: string;
    verifiedAt: string;
  };
}> {
  const sp = new URLSearchParams();
  if (params?.resourceId) sp.set('resourceId', params.resourceId);
  if (params?.action) sp.set('action', params.action);
  if (params?.limit) sp.set('limit', String(params.limit));
  const qs = sp.toString();
  return apiRequest(`/api/audit-logs${qs ? `?${qs}` : ''}`);
}

export async function verifyAuditChainApi(): Promise<{
  valid: boolean;
  totalEventsChecked: number;
  headHash: string;
  brokenAtEventId?: string;
  reason?: string;
  verifiedAt: string;
}> {
  return apiRequest('/api/audit-logs/verify');
}

export async function resetDemoEnvironmentApi(): Promise<{
  reset: boolean;
  summary: { applicationsCount: number; documentsCount: number };
}> {
  return apiRequest('/api/admin/reset-demo', { method: 'POST' });
}
