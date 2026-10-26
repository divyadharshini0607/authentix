/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Express API Routes, RBAC & Institution Isolation Middleware,
 * Persistent Lifecycle Workflows, Configurable Rules, Infrastructure Compliance,
 * Scoped In-App Notifications, Reports & Audit Verification
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import express, { type Request, type Response, type NextFunction } from 'express';
import multer from 'multer';
import { z } from 'zod';
import type {
  ApplicationCategory,
  ApplicationCategoryDefinition,
  ApplicationComplianceItemRecord,
  ApplicationDetail,
  ApplicationSummary,
  AuditLogRecord,
  ComplianceDomain,
  ComplianceItemStatus,
  DashboardStats,
  DocumentRecord,
  DocumentType,
  EpistemicClassification,
  ExtractedFieldRecord,
  InAppNotificationRecord,
  InstitutionRecord,
  LifecycleStage,
  OfficerActionType,
  OfficerReviewRecord,
  SourceVerificationRecord,
  TrustScoreBreakdown,
  UserProfile,
  UserRole,
  ValidationFindingRecord,
  ValidationRuleRecord,
  VerificationMethod,
  VerificationStatus,
  VisualEvidenceSummary,
} from '../shared/types.ts';
import { appendAuditEvent, verifyAuditChain } from './auditLog.ts';
import { cleanEnvString, isDemoModeEnabled, resolveSampleDocsDir, resolveUploadDir, withTransaction } from './db.ts';
import { checkPythonOcrHealth, processDocumentBuffer } from './ocrPipeline.ts';
import {
  createRateLimiter,
  generateOpaqueToken,
  isQrSigningSecretConfigured,
  safeLog,
  sanitizeFilename,
  sha256Hex,
  validateUploadedFileBuffer,
  verifyPassword,
} from './security.ts';
import { getDemoSeedPassword, seedDatabase } from './seed.ts';
import { executeSourceVerification } from './sourceVerification.ts';
import {
  ALL_VALID_DOCUMENT_TYPES,
  ensureDefaultCategoriesAndCompliance,
  evaluateApplicationCompliance,
  resolveRequiredChecklistForApplication,
  SUPPORTED_RULE_TYPES,
  validateRuleDefinition,
} from './validationEngine.ts';

export interface AuthenticatedRequest extends Request {
  authUser?: UserProfile;
  sessionTokenHash?: string;
  csrfToken?: string;
  authViaCookie?: boolean;
}

export interface ApiRouterContext {
  getDb: () => DatabaseSync;
  uploadDir?: string;
  sampleDocsDir?: string;
}

const SESSION_COOKIE_NAME = 'authentix_session';

function parseJsonSafe<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function escapeCsvCell(val: unknown): string {
  const s = val === null || val === undefined ? '' : String(val);
  // Mitigate spreadsheet formula injection
  const sanitized = /^[=+\-@]/.test(s) ? `'${s}` : s;
  if (/[",\r\n]/.test(sanitized)) {
    return `"${sanitized.replace(/"/g, '""')}"`;
  }
  return sanitized;
}

function emitInAppNotification(
  db: DatabaseSync,
  params: {
    recipientRole: 'INTERNAL_ALL' | UserRole;
    recipientInstitutionId?: string | null;
    applicationId?: string | null;
    alertType: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
    title: string;
    message: string;
    isSyntheticDemo: boolean;
  }
): void {
  const nowIso = new Date().toISOString();
  db.prepare(
    `INSERT INTO in_app_notifications (
      id, recipient_role, recipient_institution_id, application_id, alert_type,
      severity, title, message, delivery_channel, is_read, is_synthetic_demo, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'IN_APP_ONLY', 0, ?, ?)`
  ).run(
    `NTF-${crypto.randomUUID()}`,
    params.recipientRole,
    params.recipientInstitutionId || null,
    params.applicationId || null,
    params.alertType,
    params.severity,
    params.title,
    params.message,
    params.isSyntheticDemo ? 1 : 0,
    nowIso
  );
}

function buildNotificationScopeSql(user: UserProfile, demoMode: boolean): { whereSql: string; args: string[] } {
  const conds: string[] = [];
  const args: string[] = [];

  if (user.role === 'INSTITUTION_USER') {
    conds.push("recipient_role = 'INSTITUTION_USER'");
    conds.push('recipient_institution_id = ?');
    args.push(user.institutionId || '__NONE__');
  } else {
    conds.push("recipient_role IN ('INTERNAL_ALL', ?)");
    args.push(user.role);
  }

  if (!demoMode) {
    conds.push('is_synthetic_demo = 0');
  }

  return {
    whereSql: `WHERE ${conds.join(' AND ')}`,
    args,
  };
}

export function createApiRouter(ctx: ApiRouterContext): express.Router {
  const router = express.Router();
  const maxUploadMb = Number.parseInt(process.env.MAX_UPLOAD_MB || '15', 10);
  const maxUploadBytes = maxUploadMb * 1024 * 1024;

  const uploadMiddleware = multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: maxUploadBytes + 1024, // allow validator to produce exact message up to boundary
      files: 1,
    },
  });

  const loginRateLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 20,
    label: 'auth-login',
  });

  const uploadRateLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 40,
    label: 'document-upload',
  });

  // Authentication & CSRF Verification Middleware
  const requireAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      const db = ctx.getDb();
      const authHeader = req.headers.authorization;
      let rawToken: string | undefined;
      let viaCookie = false;

      if (authHeader && authHeader.startsWith('Bearer ')) {
        rawToken = authHeader.slice(7).trim();
      } else if (req.cookies && typeof req.cookies[SESSION_COOKIE_NAME] === 'string') {
        rawToken = req.cookies[SESSION_COOKIE_NAME];
        viaCookie = true;
      }

      if (!rawToken) {
        res.status(401).json({ error: 'Authentication required. Please sign in.' });
        return;
      }

      const tokenHash = sha256Hex(rawToken);
      const sessionRow = db
        .prepare(
          `SELECT s.token_hash, s.csrf_token, s.expires_at, s.revoked_at,
                  u.id AS user_id, u.email, u.full_name, u.role, u.institution_id,
                  u.is_active, u.is_demo_account, u.last_login_at,
                  i.name AS inst_name
           FROM user_sessions s
           JOIN users u ON u.id = s.user_id
           LEFT JOIN institutions i ON i.id = u.institution_id
           WHERE s.token_hash = ?`
        )
        .get(tokenHash) as
        | {
            token_hash: string;
            csrf_token: string;
            expires_at: string;
            revoked_at: string | null;
            user_id: string;
            email: string;
            full_name: string;
            role: UserRole;
            institution_id: string | null;
            is_active: number;
            is_demo_account: number;
            last_login_at: string | null;
            inst_name: string | null;
          }
        | undefined;

      if (!sessionRow || sessionRow.revoked_at) {
        res.status(401).json({ error: 'Session is invalid or has been signed out.' });
        return;
      }

      if (new Date(sessionRow.expires_at).getTime() <= Date.now()) {
        res.status(401).json({ error: 'Session has expired. Please sign in again.' });
        return;
      }

      if (!sessionRow.is_active) {
        res.status(403).json({ error: 'User account is disabled.' });
        return;
      }

      if (Boolean(sessionRow.is_demo_account) && !isDemoModeEnabled()) {
        res.status(403).json({
          error: 'Synthetic demo account sessions are disabled when ENABLE_DEMO_MODE is false.',
        });
        return;
      }

      // Enforce synchronizer CSRF token on mutating cookie-authenticated requests
      const mutatingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
      if (viaCookie && mutatingMethods.has(req.method.toUpperCase())) {
        const headerCsrf = req.headers['x-csrf-token'];
        if (typeof headerCsrf !== 'string' || headerCsrf !== sessionRow.csrf_token) {
          res.status(403).json({ error: 'Invalid or missing X-CSRF-Token header for cookie session.' });
          return;
        }
      }

      req.authUser = {
        id: sessionRow.user_id,
        email: sessionRow.email,
        fullName: sessionRow.full_name,
        role: sessionRow.role,
        institutionId: sessionRow.institution_id,
        institutionName: sessionRow.inst_name,
        isDemoAccount: Boolean(sessionRow.is_demo_account),
        lastLoginAt: sessionRow.last_login_at,
      };
      req.sessionTokenHash = tokenHash;
      req.csrfToken = sessionRow.csrf_token;
      req.authViaCookie = viaCookie;
      next();
    } catch (err) {
      safeLog('ERROR', 'auth_middleware_error', { message: (err as Error).message });
      res.status(500).json({ error: 'Internal authentication verification error.' });
    }
  };

  const requireRoles = (...allowed: UserRole[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      if (!req.authUser) {
        res.status(401).json({ error: 'Authentication required.' });
        return;
      }
      if (!allowed.includes(req.authUser.role)) {
        appendAuditEvent(ctx.getDb(), {
          actorUserId: req.authUser.id,
          actorEmail: req.authUser.email,
          actorRole: req.authUser.role,
          action: 'AUTHORIZATION_DENIED',
          resourceType: 'ENDPOINT',
          resourceId: `${req.method} ${req.path}`,
          metadata: { requiredRoles: allowed },
        });
        res.status(403).json({
          error: `Access denied. Role '${req.authUser.role}' is not authorised for this action.`,
        });
        return;
      }
      next();
    };
  };

  // --------------------------------------------------------------------------
  // 1. Health Check
  // --------------------------------------------------------------------------
  router.get('/health', async (_req: Request, res: Response) => {
    try {
      const db = ctx.getDb();
      const ping = db.prepare('SELECT 1 AS ok').get() as { ok: number };
      const migRow = db.prepare('SELECT COUNT(*) AS cnt FROM schema_migrations').get() as { cnt: number };
      const demoRow = db.prepare('SELECT COUNT(*) AS cnt FROM users WHERE is_demo_account = 1').get() as { cnt: number };
      const pyOcr = await checkPythonOcrHealth();

      res.json({
        status: ping.ok === 1 ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        database: {
          engine: 'sqlite-wal-persistent',
          connected: ping.ok === 1,
          appliedMigrations: migRow.cnt,
        },
        ocrService: {
          configuredUrl: pyOcr.url,
          pythonMicroserviceOnline: pyOcr.reachable,
          localPdfAndImageFallbackActive: true,
          mode: cleanEnvString(process.env.OCR_MODE) || 'auto',
          details: pyOcr.details || null,
        },
        externalAuthorityMode: 'sandbox-and-manual-only',
        demoMode: demoRow.cnt > 0 && isDemoModeEnabled(),
        security: {
          qrSigningConfigured: isQrSigningSecretConfigured(),
          demoModeEnabled: isDemoModeEnabled(),
        },
      });
    } catch (err) {
      safeLog('ERROR', 'health_check_failed', { error: (err as Error).message });
      res.status(503).json({
        status: 'unhealthy',
        error: 'Database or core dependency check failed.',
      });
    }
  });

  // --------------------------------------------------------------------------
  // 2. Authentication & Session Management
  // --------------------------------------------------------------------------
  const loginSchema = z.object({
    email: z.string().email('Enter a valid email address.'),
    password: z.string().min(1, 'Password is required.'),
  });

  router.get('/auth/demo-status', (_req: Request, res: Response) => {
    res.json({ demoMode: isDemoModeEnabled() });
  });

  router.get('/auth/demo-accounts', (_req: Request, res: Response) => {
    try {
      if (!isDemoModeEnabled()) {
        res.status(403).json({
          demoMode: false,
          accounts: [],
          error: 'Demo mode is disabled (ENABLE_DEMO_MODE=false).',
        });
        return;
      }
      const db = ctx.getDb();
      const rows = db
        .prepare(
          `SELECT u.email, u.full_name, u.role, i.name AS inst_name
           FROM users u
           LEFT JOIN institutions i ON i.id = u.institution_id
           WHERE u.is_demo_account = 1
             AND LOWER(u.email) LIKE '%.demo'
             AND u.is_active = 1
           ORDER BY CASE u.role
             WHEN 'REVIEW_OFFICER' THEN 1
             WHEN 'SENIOR_AUDITOR' THEN 2
             WHEN 'ADMIN' THEN 3
             ELSE 4 END`
        )
        .all() as Array<{ email: string; full_name: string; role: UserRole; inst_name: string | null }>;

      res.json({
        demoMode: true,
        demoPassphrase: rows.length > 0 ? getDemoSeedPassword() : undefined,
        accounts: rows.map((r) => ({
          email: r.email,
          fullName: r.full_name,
          role: r.role,
          institutionName: r.inst_name,
          isSyntheticDemo: true,
        })),
      });
    } catch {
      res.status(500).json({ error: 'Unable to load demo account metadata.' });
    }
  });

  router.post('/auth/login', loginRateLimiter, (req: Request, res: Response) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: parsed.error.issues[0]?.message || 'Invalid login request payload.',
      });
      return;
    }

    try {
      const db = ctx.getDb();
      const normalizedEmail = parsed.data.email.trim().toLowerCase();
      const userRow = db
        .prepare(
          `SELECT u.*, i.name AS inst_name
           FROM users u
           LEFT JOIN institutions i ON i.id = u.institution_id
           WHERE LOWER(u.email) = ?`
        )
        .get(normalizedEmail) as
        | {
            id: string;
            email: string;
            password_hash: string;
            full_name: string;
            role: UserRole;
            institution_id: string | null;
            is_active: number;
            is_demo_account: number;
            inst_name: string | null;
          }
        | undefined;

      if (!userRow || !verifyPassword(parsed.data.password, userRow.password_hash)) {
        appendAuditEvent(db, {
          actorEmail: normalizedEmail,
          action: 'AUTH_LOGIN_FAILED',
          resourceType: 'AUTH',
          resourceId: normalizedEmail,
          metadata: { ip: req.ip || 'local' },
        });
        res.status(401).json({ error: 'Invalid email address or password.' });
        return;
      }

      if (!userRow.is_active) {
        res.status(403).json({ error: 'Account is deactivated. Contact system administrator.' });
        return;
      }

      if (Boolean(userRow.is_demo_account)) {
        if (!isDemoModeEnabled()) {
          appendAuditEvent(db, {
            actorUserId: userRow.id,
            actorEmail: userRow.email,
            actorRole: userRow.role,
            action: 'AUTH_DEMO_ACCOUNT_BLOCKED',
            resourceType: 'AUTH',
            resourceId: userRow.id,
            metadata: { reason: 'ENABLE_DEMO_MODE=false' },
          });
          res.status(403).json({
            error: 'Synthetic demo accounts are disabled when ENABLE_DEMO_MODE is false.',
          });
          return;
        }
        if (!normalizedEmail.endsWith('.demo')) {
          res.status(403).json({
            error: 'Demo accounts must use a clearly identified synthetic *.demo address.',
          });
          return;
        }
      }

      const rawSessionToken = generateOpaqueToken(32);
      const tokenHash = sha256Hex(rawSessionToken);
      const csrfToken = generateOpaqueToken(24);
      const ttlHours = Number.parseFloat(process.env.SESSION_TTL_HOURS || '12');
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttlHours * 3600 * 1000).toISOString();
      const nowIso = now.toISOString();

      withTransaction(db, () => {
        db.prepare(
          `INSERT INTO user_sessions (
            id, user_id, token_hash, csrf_token, ip_address, user_agent, expires_at, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          `SES-${crypto.randomUUID()}`,
          userRow.id,
          tokenHash,
          csrfToken,
          req.ip || null,
          String(req.headers['user-agent'] || '').slice(0, 200),
          expiresAt,
          nowIso
        );

        db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(nowIso, userRow.id);

        appendAuditEvent(db, {
          actorUserId: userRow.id,
          actorEmail: userRow.email,
          actorRole: userRow.role,
          action: 'AUTH_LOGIN_SUCCESS',
          resourceType: 'USER',
          resourceId: userRow.id,
          metadata: { expiresAt },
        });
      });

      const forwardedProto = String(req.headers['x-forwarded-proto'] || '')
        .split(',')[0]
        .trim()
        .toLowerCase();
      const isHttps = req.secure || forwardedProto === 'https';

      res.cookie(SESSION_COOKIE_NAME, rawSessionToken, {
        httpOnly: true,
        sameSite: isHttps ? 'none' : 'lax',
        secure: isHttps,
        maxAge: Math.round(ttlHours * 3600 * 1000),
        path: '/',
      });

      const profile: UserProfile = {
        id: userRow.id,
        email: userRow.email,
        fullName: userRow.full_name,
        role: userRow.role,
        institutionId: userRow.institution_id,
        institutionName: userRow.inst_name,
        isDemoAccount: Boolean(userRow.is_demo_account),
        lastLoginAt: nowIso,
      };

      res.json({
        user: profile,
        csrfToken,
        sessionToken: rawSessionToken,
        expiresAt,
        demoMode: isDemoModeEnabled(),
      });
    } catch (err) {
      safeLog('ERROR', 'login_failed_exception', { message: (err as Error).message });
      res.status(500).json({ error: 'Authentication service encountered an unexpected error.' });
    }
  });

  router.post('/auth/logout', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const nowIso = new Date().toISOString();
      if (req.sessionTokenHash) {
        db.prepare('UPDATE user_sessions SET revoked_at = ? WHERE token_hash = ?').run(nowIso, req.sessionTokenHash);
      }
      if (req.authUser) {
        appendAuditEvent(db, {
          actorUserId: req.authUser.id,
          actorEmail: req.authUser.email,
          actorRole: req.authUser.role,
          action: 'AUTH_LOGOUT',
          resourceType: 'USER',
          resourceId: req.authUser.id,
        });
      }
      res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
      res.json({ loggedOut: true });
    } catch {
      res.status(500).json({ error: 'Failed to terminate session cleanly.' });
    }
  });

  router.get('/auth/me', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    res.json({
      user: req.authUser,
      csrfToken: req.csrfToken,
      demoMode: isDemoModeEnabled(),
    });
  });

  // --------------------------------------------------------------------------
  // 3. Dashboard Statistics (Real Database Aggregates)
  // --------------------------------------------------------------------------
  router.get('/dashboard/stats', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;
      const instFilter = user.role === 'INSTITUTION_USER' ? user.institutionId : null;

      if (user.role === 'INSTITUTION_USER' && !instFilter) {
        res.status(403).json({ error: 'Institution user profile lacks assigned institution.' });
        return;
      }

      const demoMode = isDemoModeEnabled();
      const baseConds: string[] = [];
      const params: string[] = [];
      if (instFilter) {
        baseConds.push('a.institution_id = ?');
        params.push(instFilter);
      }
      if (!demoMode) {
        baseConds.push('a.is_synthetic_demo = 0');
      }

      const whereClause = baseConds.length > 0 ? `WHERE ${baseConds.join(' AND ')}` : '';
      const whereAnd = baseConds.length > 0 ? `WHERE ${baseConds.join(' AND ')} AND` : 'WHERE';

      const totalApplications = (
        db.prepare(`SELECT COUNT(*) AS c FROM applications a ${whereClause}`).get(...params) as { c: number }
      ).c;

      const awaitingReview = (
        db
          .prepare(
            `SELECT COUNT(*) AS c FROM applications a
             ${whereAnd} a.status IN ('SUBMITTED', 'UNDER_SCRUTINY', 'REOPENED')`
          )
          .get(...params) as { c: number }
      ).c;

      const verifiedApplications = (
        db
          .prepare(
            `SELECT COUNT(*) AS c FROM applications a
             ${whereAnd} a.status = 'APPROVED_BY_OFFICER'`
          )
          .get(...params) as { c: number }
      ).c;

      const verifiedDocuments = (
        db
          .prepare(
            `SELECT COUNT(*) AS c FROM documents d
             JOIN applications a ON a.id = d.application_id
             ${whereAnd} d.verification_status = 'VERIFIED'`
          )
          .get(...params) as { c: number }
      ).c;

      const totalDocuments = (
        db
          .prepare(
            `SELECT COUNT(*) AS c FROM documents d
             JOIN applications a ON a.id = d.application_id
             ${whereClause}`
          )
          .get(...params) as { c: number }
      ).c;

      const missingOrExpiredApplications = (
        db
          .prepare(
            `SELECT COUNT(DISTINCT vf.application_id) AS c
             FROM validation_findings vf
             JOIN applications a ON a.id = vf.application_id
             ${whereAnd} vf.resolved_by_officer = 0 AND vf.archived_from_prior_cycle = 0
             AND vf.rule_code IN ('RULE-REQ-DOCS', 'RULE-DOC-EXPIRY', 'RULE-REQ-FIELDS')`
          )
          .get(...params) as { c: number }
      ).c;

      const mismatchOrAnomalyApplications = (
        db
          .prepare(
            `SELECT COUNT(DISTINCT vf.application_id) AS c
             FROM validation_findings vf
             JOIN applications a ON a.id = vf.application_id
             ${whereAnd} vf.resolved_by_officer = 0 AND vf.archived_from_prior_cycle = 0
             AND (
               vf.finding_category IN ('ANOMALY_INDICATOR', 'DUPLICATE_CHECK')
               OR vf.authority_source = 'INSTITUTIONAL_CROSSCHECK'
             )`
          )
          .get(...params) as { c: number }
      ).c;

      const verificationPendingApplications = (
        db
          .prepare(
            `SELECT COUNT(DISTINCT a.id) AS c
             FROM applications a
             LEFT JOIN documents d ON d.application_id = a.id
             ${whereAnd} (
               a.status = 'PENDING_VERIFICATION'
               OR d.verification_status IN ('VERIFICATION_PENDING', 'SOURCE_UNAVAILABLE', 'MANUAL_REVIEW_REQUIRED', 'UNVERIFIED')
             )
             AND a.final_officer_decision IS NULL`
          )
          .get(...params) as { c: number }
      ).c;

      const highPriorityApplications = (
        db
          .prepare(
            `SELECT COUNT(*) AS c FROM applications a
             ${whereAnd} a.review_priority = 'HIGH' AND a.final_officer_decision IS NULL`
          )
          .get(...params) as { c: number }
      ).c;

      const physicalInspectionRequiredCount = (
        db
          .prepare(
            `SELECT COUNT(*) AS c FROM applications a
             ${whereAnd} a.physical_inspection_required = 1 AND a.final_officer_decision IS NULL`
          )
          .get(...params) as { c: number }
      ).c;

      const additionalEvidenceRequestedCount = (
        db
          .prepare(
            `SELECT COUNT(DISTINCT aci.application_id) AS c
             FROM application_compliance_items aci
             JOIN applications a ON a.id = aci.application_id
             ${whereAnd} aci.additional_evidence_requested = 1 AND a.final_officer_decision IS NULL`
          )
          .get(...params) as { c: number }
      ).c;

      const officerInterventionRequiredCount = (
        db
          .prepare(
            `SELECT COUNT(*) AS c FROM applications a
             ${whereAnd} a.lifecycle_stage IN ('review-required', 'failed', 'incomplete')
             AND a.final_officer_decision IS NULL`
          )
          .get(...params) as { c: number }
      ).c;

      const notifScope = buildNotificationScopeSql(user, demoMode);
      const unreadNotificationsCount = (
        db
          .prepare(`SELECT COUNT(*) AS c FROM in_app_notifications ${notifScope.whereSql} AND is_read = 0`)
          .get(...notifScope.args) as { c: number }
      ).c;

      const statusRows = db
        .prepare(`SELECT a.status, COUNT(*) AS c FROM applications a ${whereClause} GROUP BY a.status`)
        .all(...params) as Array<{ status: string; c: number }>;
      const statusBreakdown: Record<string, number> = {};
      for (const sr of statusRows) {
        statusBreakdown[sr.status] = sr.c;
      }

      const categoryRows = db
        .prepare(
          `SELECT COALESCE(a.category_code, a.category) AS cat, COUNT(*) AS c
           FROM applications a ${whereClause}
           GROUP BY COALESCE(a.category_code, a.category)`
        )
        .all(...params) as Array<{ cat: string; c: number }>;
      const categoryBreakdown: Record<string, number> = {};
      for (const cr of categoryRows) {
        categoryBreakdown[cr.cat] = cr.c;
      }

      const lifecycleRows = db
        .prepare(`SELECT a.lifecycle_stage, COUNT(*) AS c FROM applications a ${whereClause} GROUP BY a.lifecycle_stage`)
        .all(...params) as Array<{ lifecycle_stage: string; c: number }>;
      const lifecycleBreakdown: Record<string, number> = {};
      for (const lr of lifecycleRows) {
        lifecycleBreakdown[lr.lifecycle_stage] = lr.c;
      }

      let recentRows: Array<{
        id: number;
        event_id: string;
        timestamp: string;
        actor_user_id: string | null;
        actor_email: string | null;
        actor_role: string | null;
        action: string;
        resource_type: string;
        resource_id: string;
        metadata_json: string;
        prev_hash: string;
        entry_hash: string;
      }> = [];

      if (instFilter) {
        recentRows = db
          .prepare(
            `SELECT al.*
             FROM audit_logs al
             JOIN applications a ON a.id = al.resource_id
             WHERE al.resource_type = 'APPLICATION' AND a.institution_id = ?
             ${demoMode ? '' : 'AND a.is_synthetic_demo = 0'}
             ORDER BY al.id DESC LIMIT 10`
          )
          .all(instFilter) as typeof recentRows;
      } else if (demoMode) {
        recentRows = db
          .prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 12')
          .all() as typeof recentRows;
      } else {
        recentRows = db
          .prepare(
            `SELECT al.*
             FROM audit_logs al
             WHERE (al.actor_email IS NULL OR LOWER(al.actor_email) NOT LIKE '%.demo')
               AND al.resource_id != 'AUTHENTIX-DEMO'
               AND NOT EXISTS (
                 SELECT 1 FROM applications a
                 WHERE a.id = al.resource_id AND a.is_synthetic_demo = 1
               )
               AND NOT EXISTS (
                 SELECT 1 FROM documents d
                 JOIN applications a2 ON a2.id = d.application_id
                 WHERE d.id = al.resource_id AND a2.is_synthetic_demo = 1
               )
             ORDER BY al.id DESC LIMIT 12`
          )
          .all() as typeof recentRows;
      }

      const recentActivity: AuditLogRecord[] = recentRows.map((r) => ({
        id: r.id,
        eventId: r.event_id,
        timestamp: r.timestamp,
        actorUserId: r.actor_user_id,
        actorEmail: r.actor_email,
        actorRole: r.actor_role,
        action: r.action,
        resourceType: r.resource_type,
        resourceId: r.resource_id,
        metadata: parseJsonSafe(r.metadata_json, {}),
        prevHash: r.prev_hash,
        entryHash: r.entry_hash,
      }));

      const openComplianceFindings = (
        db
          .prepare(
            `SELECT COUNT(*) AS c
             FROM validation_findings vf
             JOIN applications a ON a.id = vf.application_id
             ${whereAnd} vf.resolved_by_officer = 0 AND vf.archived_from_prior_cycle = 0`
          )
          .get(...params) as { c: number }
      ).c;

      const stats: DashboardStats = {
        totalApplications,
        awaitingReview,
        verifiedApplications,
        verifiedDocuments,
        totalDocuments,
        missingOrExpiredApplications,
        mismatchOrAnomalyApplications,
        verificationPendingApplications,
        highPriorityApplications,
        openComplianceFindings,
        physicalInspectionRequiredCount,
        additionalEvidenceRequestedCount,
        officerInterventionRequiredCount,
        unreadNotificationsCount,
        recentActivity,
        statusBreakdown,
        categoryBreakdown,
        lifecycleBreakdown,
      };

      res.json(stats);
    } catch (err) {
      safeLog('ERROR', 'dashboard_stats_failed', { error: (err as Error).message });
      res.status(500).json({ error: 'Failed to compute persisted dashboard metrics.' });
    }
  });

  // --------------------------------------------------------------------------
  // 4. Institutions, Extensible Categories & Sample Fixtures
  // --------------------------------------------------------------------------
  router.get('/categories', requireAuth, (_req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      ensureDefaultCategoriesAndCompliance(db);
      const rows = db
        .prepare('SELECT * FROM application_categories WHERE is_active = 1 ORDER BY created_at ASC, code ASC')
        .all() as Array<Record<string, unknown>>;

      const categories: ApplicationCategoryDefinition[] = rows.map((r) => ({
        code: String(r.code),
        baseCategory: r.base_category as ApplicationCategory,
        name: String(r.name),
        description: String(r.description),
        requiredDocTypes: parseJsonSafe<DocumentType[]>(String(r.required_doc_types_json), []),
        isActive: Boolean(r.is_active),
        createdAt: String(r.created_at),
        updatedAt: String(r.updated_at),
      }));

      res.json({ categories });
    } catch {
      res.status(500).json({ error: 'Failed to retrieve application categories.' });
    }
  });

  const createCategorySchema = z.object({
    code: z
      .string()
      .regex(/^[A-Z][A-Z0-9_]{2,40}$/, 'Category code must be uppercase snake_case (e.g. POSTGRADUATE_EXPANSION).'),
    baseCategory: z.enum(['EXTENSION_OF_APPROVAL', 'NEW_INSTITUTION', 'INCREASE_IN_INTAKE']),
    name: z.string().min(4).max(120),
    description: z.string().min(10).max(400),
    requiredDocTypes: z.array(z.string()).min(1, 'At least one required checklist document type must be specified.'),
  });

  router.post(
    '/categories',
    requireAuth,
    requireRoles('ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = createCategorySchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid category definition.' });
        return;
      }

      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        ensureDefaultCategoriesAndCompliance(db);

        for (const dt of parsed.data.requiredDocTypes) {
          if (!ALL_VALID_DOCUMENT_TYPES.has(dt as DocumentType)) {
            res.status(400).json({ error: `Invalid required document type '${dt}'.` });
            return;
          }
        }

        const existing = db
          .prepare('SELECT code FROM application_categories WHERE code = ?')
          .get(parsed.data.code);
        if (existing) {
          res.status(409).json({ error: `Category '${parsed.data.code}' already exists.` });
          return;
        }

        const nowIso = new Date().toISOString();
        withTransaction(db, () => {
          db.prepare(
            `INSERT INTO application_categories (
              code, base_category, name, description, required_doc_types_json,
              is_active, created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)`
          ).run(
            parsed.data.code,
            parsed.data.baseCategory,
            parsed.data.name.trim(),
            parsed.data.description.trim(),
            JSON.stringify(parsed.data.requiredDocTypes),
            user.id,
            nowIso,
            nowIso
          );

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'APPLICATION_CATEGORY_CREATED',
            resourceType: 'CATEGORY',
            resourceId: parsed.data.code,
            metadata: {
              baseCategory: parsed.data.baseCategory,
              requiredDocTypes: parsed.data.requiredDocTypes,
            },
          });
        });

        res.status(201).json({
          code: parsed.data.code,
          baseCategory: parsed.data.baseCategory,
          name: parsed.data.name.trim(),
          description: parsed.data.description.trim(),
          requiredDocTypes: parsed.data.requiredDocTypes as DocumentType[],
          isActive: true,
          createdAt: nowIso,
          updatedAt: nowIso,
        });
      } catch (err) {
        safeLog('ERROR', 'create_category_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to create application category.' });
      }
    }
  );

  router.get('/institutions', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;
      const demoMode = isDemoModeEnabled();
      const rows =
        user.role === 'INSTITUTION_USER'
          ? (db
              .prepare(
                `SELECT * FROM institutions WHERE id = ? ${demoMode ? '' : 'AND is_synthetic_demo = 0'}`
              )
              .all(user.institutionId || '') as Array<Record<string, unknown>>)
          : (db
              .prepare(
                `SELECT * FROM institutions ${demoMode ? '' : 'WHERE is_synthetic_demo = 0'} ORDER BY name ASC`
              )
              .all() as Array<Record<string, unknown>>);

      const list: InstitutionRecord[] = rows.map((r) => ({
        id: String(r.id),
        code: String(r.code),
        name: String(r.name),
        state: String(r.state),
        district: String(r.district),
        institutionType: String(r.institution_type),
        establishedYear: Number(r.established_year),
        approvedIntake: Number(r.approved_intake),
        landAreaAcres: Number(r.land_area_acres),
        builtUpAreaSqm: Number(r.built_up_area_sqm),
        principalName: String(r.principal_name),
        aictePermanentId: String(r.aicte_permanent_id),
        isSyntheticDemo: Boolean(r.is_synthetic_demo),
      }));

      res.json({ institutions: list });
    } catch {
      res.status(500).json({ error: 'Failed to load institutions.' });
    }
  });

  router.get('/sample-fixtures', requireAuth, (_req: AuthenticatedRequest, res: Response) => {
    try {
      if (!isDemoModeEnabled()) {
        res.status(403).json({
          error: 'Synthetic sample fixtures are disabled when ENABLE_DEMO_MODE is false.',
          fixtures: [],
        });
        return;
      }
      const sampleDir = resolveSampleDocsDir(ctx.sampleDocsDir);
      const descriptions: Record<string, string> = {
        'sample_valid_fire_safety.pdf': 'Valid synthetic Fire Safety Certificate with signed demo QR token',
        'sample_expired_fire_safety.pdf': 'Expired synthetic Fire Safety Certificate (2025-03-31) for expiry rule testing',
        'sample_tampered_metadata_affidavit.pdf': 'PDF with Photoshop Producer tag & post-creation modification markers',
        'sample_bilingual_low_conf_scan.png': 'Hindi/English bilingual scan fixture with 0.58 OCR confidence',
        'sample_unreadable_raster_only.png': 'Raw raster PNG without embedded text layer (tests OCR unavailability routing)',
        'sample_facility_lab_photo.png': 'Synthetic laboratory facility photograph (640x420 PNG) for visual compliance check',
      };
      const files = fs.existsSync(sampleDir)
        ? fs
            .readdirSync(sampleDir)
            .filter((f) => /^sample_.*\.(pdf|png|jpg|jpeg)$/i.test(f))
            .map((f) => {
              const st = fs.statSync(path.join(sampleDir, f));
              return {
                filename: f,
                sizeBytes: st.size,
                description: descriptions[f] || 'Synthetic evaluation document fixture',
                isSyntheticDemo: true,
              };
            })
        : [];
      res.json({ fixtures: files });
    } catch {
      res.status(500).json({ error: 'Unable to list sample fixtures.' });
    }
  });

  router.get('/sample-fixtures/:filename', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    if (!isDemoModeEnabled()) {
      res.status(403).json({ error: 'Synthetic sample fixtures are disabled when ENABLE_DEMO_MODE is false.' });
      return;
    }
    const rawName = String(req.params.filename || '');
    const clean = path.basename(rawName);
    if (clean !== rawName || clean.includes('..') || !/^sample_.*\.(pdf|png|jpg|jpeg)$/i.test(clean)) {
      res.status(400).json({ error: 'Invalid synthetic fixture filename.' });
      return;
    }
    const sampleDir = resolveSampleDocsDir(ctx.sampleDocsDir);
    const fullPath = path.join(sampleDir, clean);
    if (!fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'Sample fixture not found.' });
      return;
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.download(fullPath, clean);
  });

  // --------------------------------------------------------------------------
  // 5. Application Management (List, Search, Filter, Create, Detail, Resubmit, Re-evaluate)
  // --------------------------------------------------------------------------
  router.get('/applications', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;

      const q = String(req.query.q || '').trim().toLowerCase();
      const status = String(req.query.status || '').trim();
      const category = String(req.query.category || '').trim();
      const priority = String(req.query.priority || '').trim();
      const lifecycleStage = String(req.query.lifecycleStage || '').trim();
      const instQuery = String(req.query.institutionId || '').trim();
      const page = Math.max(1, Number.parseInt(String(req.query.page || '1'), 10) || 1);
      const pageSize = Math.min(50, Math.max(1, Number.parseInt(String(req.query.pageSize || '20'), 10) || 20));

      const conditions: string[] = [];
      const args: Array<string | number> = [];

      if (!isDemoModeEnabled()) {
        conditions.push('a.is_synthetic_demo = 0');
      }

      if (user.role === 'INSTITUTION_USER') {
        conditions.push('a.institution_id = ?');
        args.push(user.institutionId || '__NONE__');
      } else if (instQuery) {
        conditions.push('a.institution_id = ?');
        args.push(instQuery);
      }

      if (status && status !== 'ALL') {
        conditions.push('a.status = ?');
        args.push(status);
      }
      if (category && category !== 'ALL') {
        conditions.push('(a.category = ? OR a.category_code = ?)');
        args.push(category, category);
      }
      if (priority && priority !== 'ALL') {
        conditions.push('a.review_priority = ?');
        args.push(priority);
      }
      if (lifecycleStage && lifecycleStage !== 'ALL') {
        conditions.push('a.lifecycle_stage = ?');
        args.push(lifecycleStage);
      }
      if (q) {
        conditions.push(
          '(LOWER(a.application_number) LIKE ? OR LOWER(i.name) LIKE ? OR LOWER(i.code) LIKE ? OR LOWER(a.program_names) LIKE ?)'
        );
        const like = `%${q}%`;
        args.push(like, like, like, like);
      }

      const whereSql = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const totalCount = (
        db
          .prepare(
            `SELECT COUNT(*) AS cnt
             FROM applications a
             JOIN institutions i ON i.id = a.institution_id
             ${whereSql}`
          )
          .get(...args) as { cnt: number }
      ).cnt;

      const offset = (page - 1) * pageSize;
      const rows = db
        .prepare(
          `SELECT a.*,
                  i.name AS inst_name, i.code AS inst_code, i.state AS inst_state,
                  (SELECT COUNT(*) FROM documents d WHERE d.application_id = a.id) AS doc_count,
                  (SELECT COUNT(*) FROM documents d WHERE d.application_id = a.id AND d.verification_status = 'VERIFIED') AS verified_doc_count,
                  (SELECT COUNT(*) FROM validation_findings vf WHERE vf.application_id = a.id AND vf.resolved_by_officer = 0 AND vf.archived_from_prior_cycle = 0) AS open_findings_count,
                  (SELECT COUNT(*) FROM validation_findings vf WHERE vf.application_id = a.id AND vf.resolved_by_officer = 0 AND vf.archived_from_prior_cycle = 0 AND vf.severity IN ('CRITICAL', 'HIGH')) AS critical_findings_count
           FROM applications a
           JOIN institutions i ON i.id = a.institution_id
           ${whereSql}
           ORDER BY
             CASE a.review_priority WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END ASC,
             a.updated_at DESC
           LIMIT ? OFFSET ?`
        )
        .all(...args, pageSize, offset) as Array<Record<string, unknown>>;

      const items: ApplicationSummary[] = rows.map((r) => ({
        id: String(r.id),
        applicationNumber: String(r.application_number),
        institutionId: String(r.institution_id),
        institutionName: String(r.inst_name),
        institutionCode: String(r.inst_code),
        institutionState: String(r.inst_state),
        academicYear: String(r.academic_year),
        category: r.category as ApplicationCategory,
        categoryCode: r.category_code ? String(r.category_code) : String(r.category),
        programNames: String(r.program_names),
        requestedIntake: Number(r.requested_intake),
        submittedLandAcres: Number(r.submitted_land_acres),
        submittedBuiltUpSqm: Number(r.submitted_built_up_sqm),
        submittedPrincipalName: String(r.submitted_principal_name),
        status: r.status as ApplicationSummary['status'],
        lifecycleStage: (r.lifecycle_stage as LifecycleStage) || 'pending',
        nextRecommendedAction: r.next_recommended_action ? String(r.next_recommended_action) : null,
        submissionCycle: Number(r.submission_cycle || 1),
        resubmittedAt: r.resubmitted_at ? String(r.resubmitted_at) : null,
        resubmissionSummary: r.resubmission_summary ? String(r.resubmission_summary) : null,
        physicalInspectionRequired: Boolean(r.physical_inspection_required),
        physicalInspectionReason: r.physical_inspection_reason ? String(r.physical_inspection_reason) : null,
        reviewPriority: r.review_priority as ApplicationSummary['reviewPriority'],
        trustScore: r.trust_score !== null && r.trust_score !== undefined ? Number(r.trust_score) : null,
        trustScoreVersion: r.trust_score_version ? String(r.trust_score_version) : null,
        automatedSummary: r.automated_summary ? String(r.automated_summary) : null,
        finalOfficerDecision: (r.final_officer_decision as ApplicationSummary['finalOfficerDecision']) || null,
        finalDecisionRationale: r.final_decision_rationale ? String(r.final_decision_rationale) : null,
        finalDecisionAt: r.final_decision_at ? String(r.final_decision_at) : null,
        isSyntheticDemo: Boolean(r.is_synthetic_demo),
        documentCount: Number(r.doc_count),
        verifiedDocsCount: Number(r.verified_doc_count),
        openFindingsCount: Number(r.open_findings_count),
        criticalFindingsCount: Number(r.critical_findings_count),
        createdAt: String(r.created_at),
        updatedAt: String(r.updated_at),
      }));

      res.json({
        applications: items,
        pagination: {
          page,
          pageSize,
          totalCount,
          totalPages: Math.max(1, Math.ceil(totalCount / pageSize)),
        },
      });
    } catch (err) {
      safeLog('ERROR', 'list_applications_failed', { error: (err as Error).message });
      res.status(500).json({ error: 'Failed to load applications.' });
    }
  });

  const createApplicationSchema = z.object({
    institutionId: z.string().min(3),
    academicYear: z.string().regex(/^\d{4}-\d{2}$/, 'Academic year must match YYYY-YY (e.g. 2026-27).'),
    category: z.enum(['EXTENSION_OF_APPROVAL', 'NEW_INSTITUTION', 'INCREASE_IN_INTAKE']),
    categoryCode: z.string().min(3).max(50).optional(),
    programNames: z.string().min(4, 'Program names must be at least 4 characters.').max(300),
    requestedIntake: z.number().int().min(30).max(5000),
    submittedLandAcres: z.number().positive().max(2000),
    submittedBuiltUpSqm: z.number().positive().max(500000),
    submittedPrincipalName: z.string().min(3).max(150),
  });

  router.post(
    '/applications',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'ADMIN', 'INSTITUTION_USER'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = createApplicationSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid application fields.' });
        return;
      }

      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const data = parsed.data;
        ensureDefaultCategoriesAndCompliance(db);

        if (user.role === 'INSTITUTION_USER' && data.institutionId !== user.institutionId) {
          res.status(403).json({
            error: 'Institution users may only create applications for their own assigned institution.',
          });
          return;
        }

        const inst = db
          .prepare('SELECT id, name, is_synthetic_demo FROM institutions WHERE id = ?')
          .get(data.institutionId) as { id: string; name: string; is_synthetic_demo: number } | undefined;
        if (!inst) {
          res.status(404).json({ error: 'Selected institution does not exist.' });
          return;
        }
        if (Boolean(inst.is_synthetic_demo) && !isDemoModeEnabled()) {
          res.status(403).json({
            error: 'Synthetic demo institutions cannot be used when ENABLE_DEMO_MODE is false.',
          });
          return;
        }

        let effectiveCategoryCode: string = data.categoryCode?.trim() || data.category;
        let baseCategory: ApplicationCategory = data.category;
        if (data.categoryCode) {
          const catRow = db
            .prepare('SELECT code, base_category FROM application_categories WHERE code = ? AND is_active = 1')
            .get(data.categoryCode.trim()) as { code: string; base_category: ApplicationCategory } | undefined;
          if (!catRow) {
            res.status(400).json({ error: `Unknown or inactive categoryCode '${data.categoryCode}'.` });
            return;
          }
          effectiveCategoryCode = catRow.code;
          baseCategory = catRow.base_category;
        }

        const isSyntheticDemo = isDemoModeEnabled() && (Boolean(inst.is_synthetic_demo) || user.isDemoAccount) ? 1 : 0;
        const appId = `APP-${crypto.randomUUID()}`;
        const seqNum =
          (db.prepare('SELECT COUNT(*) AS cnt FROM applications').get() as { cnt: number }).cnt + 101;
        const appNumber = `APP-2026-${String(seqNum).padStart(4, '0')}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
        const nowIso = new Date().toISOString();

        withTransaction(db, () => {
          db.prepare(
            `INSERT INTO applications (
              id, application_number, institution_id, academic_year, category, category_code,
              program_names, requested_intake, submitted_land_acres, submitted_built_up_sqm,
              submitted_principal_name, status, review_priority, is_synthetic_demo,
              created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SUBMITTED', 'MEDIUM', ?, ?, ?, ?)`
          ).run(
            appId,
            appNumber,
            data.institutionId,
            data.academicYear,
            baseCategory,
            effectiveCategoryCode,
            data.programNames.trim(),
            data.requestedIntake,
            data.submittedLandAcres,
            data.submittedBuiltUpSqm,
            data.submittedPrincipalName.trim(),
            isSyntheticDemo,
            user.id,
            nowIso,
            nowIso
          );

          evaluateApplicationCompliance(db, appId);

          if (user.role === 'INSTITUTION_USER') {
            emitInAppNotification(db, {
              recipientRole: 'INTERNAL_ALL',
              applicationId: appId,
              alertType: 'NEW_INSTITUTION_SUBMISSION',
              severity: 'INFO',
              title: `${appNumber}: New Institutional Filing Submitted`,
              message: `${inst.name} submitted ${effectiveCategoryCode} (${data.programNames.trim()}) for scrutiny.`,
              isSyntheticDemo: Boolean(isSyntheticDemo),
            });
          }

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'APPLICATION_CREATED',
            resourceType: 'APPLICATION',
            resourceId: appId,
            metadata: {
              applicationNumber: appNumber,
              institutionId: data.institutionId,
              category: baseCategory,
              categoryCode: effectiveCategoryCode,
              requestedIntake: data.requestedIntake,
            },
          });
        });

        res.status(201).json(loadApplicationDetail(db, appId));
      } catch (err) {
        safeLog('ERROR', 'create_application_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to create application.' });
      }
    }
  );

  router.get('/applications/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;
      const detail = loadApplicationDetail(db, String(req.params.id));
      if (!detail || (detail.isSyntheticDemo && !isDemoModeEnabled())) {
        res.status(404).json({ error: 'Application not found.' });
        return;
      }
      if (user.role === 'INSTITUTION_USER' && detail.institutionId !== user.institutionId) {
        appendAuditEvent(db, {
          actorUserId: user.id,
          actorEmail: user.email,
          actorRole: user.role,
          action: 'CROSS_INSTITUTION_ACCESS_BLOCKED',
          resourceType: 'APPLICATION',
          resourceId: detail.id,
        });
        res.status(403).json({ error: 'Access denied to another institution’s application.' });
        return;
      }
      res.json(detail);
    } catch (err) {
      safeLog('ERROR', 'get_application_detail_failed', { error: (err as Error).message });
      res.status(500).json({ error: 'Failed to retrieve application details.' });
    }
  });

  const resubmitApplicationSchema = z.object({
    resubmissionSummary: z
      .string()
      .min(10, 'Provide a clear rectification summary (at least 10 characters) describing updated evidence.')
      .max(2000),
    requestedIntake: z.number().int().min(30).max(5000).optional(),
    submittedLandAcres: z.number().positive().max(2000).optional(),
    submittedBuiltUpSqm: z.number().positive().max(500000).optional(),
    submittedPrincipalName: z.string().min(3).max(150).optional(),
  });

  router.post(
    '/applications/:id/resubmit',
    requireAuth,
    requireRoles('INSTITUTION_USER', 'REVIEW_OFFICER', 'ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = resubmitApplicationSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid resubmission payload.' });
        return;
      }

      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const appId = String(req.params.id);

        const appRow = db
          .prepare(
            `SELECT id, application_number, institution_id, status, submission_cycle,
                    final_officer_decision, is_synthetic_demo
             FROM applications WHERE id = ?`
          )
          .get(appId) as
          | {
              id: string;
              application_number: string;
              institution_id: string;
              status: string;
              submission_cycle: number;
              final_officer_decision: string | null;
              is_synthetic_demo: number;
            }
          | undefined;

        if (!appRow || (Boolean(appRow.is_synthetic_demo) && !isDemoModeEnabled())) {
          res.status(404).json({ error: 'Application not found.' });
          return;
        }

        if (user.role === 'INSTITUTION_USER' && appRow.institution_id !== user.institutionId) {
          res.status(403).json({ error: 'Cannot resubmit another institution’s application.' });
          return;
        }

        if (appRow.final_officer_decision || appRow.status !== 'CLARIFICATION_REQUESTED') {
          res.status(409).json({
            error:
              'Rectification resubmission is only permitted when application status is CLARIFICATION_REQUESTED and no final decision is locked.',
          });
          return;
        }

        const nowIso = new Date().toISOString();
        const nextCycle = Math.max(1, Number(appRow.submission_cycle || 1)) + 1;
        const summary = parsed.data.resubmissionSummary.trim();

        withTransaction(db, () => {
          // Preserve earlier cycle findings in history before evaluating the new submission cycle
          db.prepare(
            'UPDATE validation_findings SET archived_from_prior_cycle = 1 WHERE application_id = ? AND archived_from_prior_cycle = 0'
          ).run(appId);

          db.prepare(
            `UPDATE applications
             SET status = 'UNDER_SCRUTINY',
                 submission_cycle = ?,
                 resubmitted_at = ?,
                 resubmission_summary = ?,
                 requested_intake = COALESCE(?, requested_intake),
                 submitted_land_acres = COALESCE(?, submitted_land_acres),
                 submitted_built_up_sqm = COALESCE(?, submitted_built_up_sqm),
                 submitted_principal_name = COALESCE(?, submitted_principal_name),
                 updated_at = ?
             WHERE id = ?`
          ).run(
            nextCycle,
            nowIso,
            summary,
            parsed.data.requestedIntake ?? null,
            parsed.data.submittedLandAcres ?? null,
            parsed.data.submittedBuiltUpSqm ?? null,
            parsed.data.submittedPrincipalName?.trim() ?? null,
            nowIso,
            appId
          );

          // Clear pending additional-evidence flags that have now been resubmitted for scrutiny
          db.prepare(
            'UPDATE application_compliance_items SET additional_evidence_requested = 0, updated_at = ? WHERE application_id = ?'
          ).run(nowIso, appId);

          db.prepare(
            `INSERT INTO officer_reviews (
              id, application_id, document_id, officer_id, action_type,
              previous_status, new_status, rationale, evidence_reference, created_at
            ) VALUES (?, ?, NULL, ?, 'RESUBMIT_APPLICATION', 'CLARIFICATION_REQUESTED', 'UNDER_SCRUTINY', ?, ?, ?)`
          ).run(
            `REV-${crypto.randomUUID()}`,
            appId,
            user.id,
            summary,
            `Cycle #${nextCycle}`,
            nowIso
          );

          const evalRes = evaluateApplicationCompliance(db, appId);

          emitInAppNotification(db, {
            recipientRole: 'INTERNAL_ALL',
            applicationId: appId,
            alertType: 'APPLICATION_RESUBMITTED',
            severity: 'MEDIUM',
            title: `${appRow.application_number}: Rectification Resubmitted (Cycle #${nextCycle})`,
            message: `Rectified evidence submitted (${evalRes.findingsCount} open finding(s) in cycle #${nextCycle}): ${summary.slice(0, 140)}`,
            isSyntheticDemo: Boolean(appRow.is_synthetic_demo),
          });

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'APPLICATION_RECTIFIED_AND_RESUBMITTED',
            resourceType: 'APPLICATION',
            resourceId: appId,
            metadata: {
              applicationNumber: appRow.application_number,
              submissionCycle: nextCycle,
              resubmissionSummary: summary,
              openFindingsAfterResubmission: evalRes.findingsCount,
            },
          });
        });

        res.json(loadApplicationDetail(db, appId));
      } catch (err) {
        safeLog('ERROR', 'resubmit_application_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to process application resubmission.' });
      }
    }
  );

  router.post(
    '/applications/:id/re-evaluate',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'SENIOR_AUDITOR', 'ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const appId = String(req.params.id);
        const exists = db
          .prepare('SELECT id, application_number, is_synthetic_demo FROM applications WHERE id = ?')
          .get(appId) as { id: string; application_number: string; is_synthetic_demo: number } | undefined;
        if (!exists || (Boolean(exists.is_synthetic_demo) && !isDemoModeEnabled())) {
          res.status(404).json({ error: 'Application not found.' });
          return;
        }
        withTransaction(db, () => {
          const evalRes = evaluateApplicationCompliance(db, appId);
          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'APPLICATION_COMPLIANCE_RE_EVALUATED',
            resourceType: 'APPLICATION',
            resourceId: appId,
            metadata: {
              applicationNumber: exists.application_number,
              unresolvedFindings: evalRes.findingsCount,
              trustScore: evalRes.trustScore.score,
              lifecycleStage: evalRes.lifecycleStage,
            },
          });
        });
        res.json(loadApplicationDetail(db, appId));
      } catch (err) {
        safeLog('ERROR', 're_evaluate_application_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Compliance re-evaluation failed.' });
      }
    }
  );

  // --------------------------------------------------------------------------
  // 6. Document Upload, OCR Reprocess, Secure Retrieval & Field Correction
  // --------------------------------------------------------------------------
  router.post(
    '/applications/:id/documents',
    requireAuth,
    uploadRateLimiter,
    (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      uploadMiddleware.single('file')(req, res, (err: unknown) => {
        if (err) {
          const multerCode = (err as { code?: string })?.code;
          const message =
            multerCode === 'LIMIT_FILE_SIZE'
              ? `File size exceeds maximum allowed limit (${maxUploadMb} MB).`
              : 'File exceeds size limit or malformed multipart payload.';
          res.status(400).json({ error: `Upload rejected: ${message}` });
          return;
        }
        next();
      });
    },
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const appId = String(req.params.id);

        if (user.role === 'SENIOR_AUDITOR') {
          res.status(403).json({ error: 'Auditor role is read/audit only and cannot upload application files.' });
          return;
        }

        const appRow = db
          .prepare(
            'SELECT id, application_number, institution_id, final_officer_decision, is_synthetic_demo FROM applications WHERE id = ?'
          )
          .get(appId) as
          | {
              id: string;
              application_number: string;
              institution_id: string;
              final_officer_decision: string | null;
              is_synthetic_demo: number;
            }
          | undefined;

        if (!appRow || (Boolean(appRow.is_synthetic_demo) && !isDemoModeEnabled())) {
          res.status(404).json({ error: 'Application not found.' });
          return;
        }

        if (user.role === 'INSTITUTION_USER' && appRow.institution_id !== user.institutionId) {
          res.status(403).json({ error: 'Cannot upload documents to another institution’s application.' });
          return;
        }

        if (appRow.final_officer_decision) {
          res.status(409).json({
            error: 'Application has a recorded final decision. Reopen the case before uploading new documents.',
          });
          return;
        }

        if (!req.file) {
          res.status(400).json({ error: 'No document file provided in form field "file".' });
          return;
        }

        const rawOriginalName = req.body?.originalFilenameOverride || req.file.originalname || '';
        const declaredTypeRaw = String(req.body?.declaredDocType || 'UNKNOWN_DOCUMENT').trim() as DocumentType;
        if (!ALL_VALID_DOCUMENT_TYPES.has(declaredTypeRaw)) {
          res.status(400).json({ error: `Invalid declaredDocType '${declaredTypeRaw}'.` });
          return;
        }

        const fileCheck = validateUploadedFileBuffer(
          req.file.buffer,
          rawOriginalName,
          req.file.mimetype,
          maxUploadBytes
        );

        if (!fileCheck.valid || !fileCheck.detectedMime) {
          res.status(400).json({ error: fileCheck.error || 'Uploaded file failed validation.' });
          return;
        }

        const safeOriginal = sanitizeFilename(rawOriginalName);
        const docId = `DOC-${crypto.randomUUID()}`;
        const storedFilename = `${docId}_${safeOriginal}`;
        const sha256Hash = sha256Hex(req.file.buffer);
        const uploadDir = resolveUploadDir(ctx.uploadDir);
        const targetDiskPath = path.join(uploadDir, storedFilename);

        fs.writeFileSync(targetDiskPath, req.file.buffer);

        const ocrModeOverride =
          process.env.NODE_ENV !== 'production' &&
          ['auto', 'unavailable', 'timeout', 'local-only'].includes(String(req.body?.ocrModeOverride || ''))
            ? (req.body.ocrModeOverride as 'auto' | 'unavailable' | 'timeout' | 'local-only')
            : undefined;

        const proc = await processDocumentBuffer(req.file.buffer, fileCheck.detectedMime, declaredTypeRaw, {
          ocrModeOverride,
        });

        const nowIso = new Date().toISOString();
        const combinedMeta = {
          ...proc.metadata,
          forensicIndicators: proc.forensicIndicators,
          processingWarning: proc.errorMessage || null,
        };
        const detectedMime = fileCheck.detectedMime;
        const fileByteLength = req.file.buffer.length;
        const initialVerificationStatus: VerificationStatus =
          proc.ocrStatus === 'UNAVAILABLE' || proc.ocrStatus === 'FAILED' || proc.ocrStatus === 'LOW_CONFIDENCE'
            ? 'MANUAL_REVIEW_REQUIRED'
            : 'UNVERIFIED';

        withTransaction(db, () => {
          db.prepare(
            `INSERT INTO documents (
              id, application_id, declared_doc_type, detected_doc_type, classification_confidence,
              original_filename, stored_filename, mime_type, file_size_bytes,
              sha256_hash, page_count, ocr_status, ocr_engine, ocr_confidence,
              reprocess_count, last_error_reason,
              extracted_text, extracted_pages_json, metadata_json, verification_status,
              processed_at, uploaded_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            docId,
            appId,
            declaredTypeRaw,
            proc.detectedDocType,
            proc.classificationConfidence ?? null,
            safeOriginal,
            storedFilename,
            detectedMime,
            fileByteLength,
            sha256Hash,
            proc.pageCount,
            proc.ocrStatus,
            proc.ocrEngine,
            proc.ocrConfidence ?? null,
            proc.errorMessage || null,
            proc.extractedText,
            JSON.stringify(proc.pages),
            JSON.stringify(combinedMeta),
            initialVerificationStatus,
            nowIso,
            user.id,
            nowIso,
            nowIso
          );

          const efStmt = db.prepare(
            `INSERT INTO extracted_fields (
              id, document_id, field_name, field_value, confidence,
              page_number, bbox_json, extraction_method, manually_corrected
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`
          );
          for (const ef of proc.extractedFields) {
            efStmt.run(
              `EF-${crypto.randomUUID()}`,
              docId,
              ef.fieldName,
              ef.fieldValue,
              ef.confidence,
              ef.pageNumber,
              ef.bbox ? JSON.stringify(ef.bbox) : null,
              ef.extractionMethod
            );
          }

          const evalRes = evaluateApplicationCompliance(db, appId);

          if (proc.forensicIndicators.some((fi) => fi.severity === 'HIGH')) {
            emitInAppNotification(db, {
              recipientRole: 'INTERNAL_ALL',
              applicationId: appId,
              alertType: 'ANOMALY_INDICATOR_FLAGGED',
              severity: 'HIGH',
              title: `${appRow.application_number}: Document Metadata Heuristic Flag`,
              message: `Uploaded file '${safeOriginal}' triggered ${proc.forensicIndicators[0].code} — requires officer verification.`,
              isSyntheticDemo: Boolean(appRow.is_synthetic_demo),
            });
          }

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'DOCUMENT_UPLOADED_AND_PROCESSED',
            resourceType: 'DOCUMENT',
            resourceId: docId,
            metadata: {
              applicationId: appId,
              applicationNumber: appRow.application_number,
              filename: safeOriginal,
              sha256Hash,
              ocrStatus: proc.ocrStatus,
              ocrEngine: proc.ocrEngine,
              detectedDocType: proc.detectedDocType,
              trustScoreAfter: evalRes.trustScore.score,
            },
          });
        });

        const updatedApp = loadApplicationDetail(db, appId);
        const createdDoc = updatedApp?.documents.find((d) => d.id === docId);

        res.status(201).json({
          document: createdDoc,
          processingWarning: proc.errorMessage || null,
          application: updatedApp,
        });
      } catch (err) {
        safeLog('ERROR', 'document_upload_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Document storage or processing pipeline failed.' });
      }
    }
  );

  router.post(
    '/applications/:id/documents/:docId/reprocess',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'ADMIN', 'INSTITUTION_USER'),
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const appId = String(req.params.id);
        const docId = String(req.params.docId);

        const row = db
          .prepare(
            `SELECT d.*, a.application_number, a.institution_id, a.final_officer_decision, a.is_synthetic_demo
             FROM documents d
             JOIN applications a ON a.id = d.application_id
             WHERE d.id = ? AND d.application_id = ?`
          )
          .get(docId, appId) as
          | {
              id: string;
              application_id: string;
              declared_doc_type: DocumentType;
              original_filename: string;
              stored_filename: string;
              mime_type: string;
              reprocess_count: number;
              verification_status: VerificationStatus;
              application_number: string;
              institution_id: string;
              final_officer_decision: string | null;
              is_synthetic_demo: number;
            }
          | undefined;

        if (!row || (Boolean(row.is_synthetic_demo) && !isDemoModeEnabled())) {
          res.status(404).json({ error: 'Document not found.' });
          return;
        }

        if (user.role === 'INSTITUTION_USER' && row.institution_id !== user.institutionId) {
          res.status(403).json({ error: 'Cannot reprocess another institution’s document.' });
          return;
        }

        if (row.final_officer_decision) {
          res.status(409).json({
            error: 'Application has a recorded final decision. Reopen the case before reprocessing documents.',
          });
          return;
        }

        const uploadDir = path.resolve(resolveUploadDir(ctx.uploadDir));
        const safeStored = path.basename(row.stored_filename);
        const fullPath = path.resolve(uploadDir, safeStored);
        if (!fullPath.startsWith(`${uploadDir}${path.sep}`) || !fs.existsSync(fullPath)) {
          res.status(404).json({ error: 'Stored document file is unavailable on disk for reprocessing.' });
          return;
        }

        const buffer = fs.readFileSync(fullPath);
        const ocrModeOverride =
          process.env.NODE_ENV !== 'production' &&
          ['auto', 'unavailable', 'timeout', 'local-only'].includes(String(req.body?.ocrModeOverride || ''))
            ? (req.body.ocrModeOverride as 'auto' | 'unavailable' | 'timeout' | 'local-only')
            : undefined;

        const proc = await processDocumentBuffer(buffer, row.mime_type, row.declared_doc_type, {
          ocrModeOverride,
        });

        const nowIso = new Date().toISOString();
        const combinedMeta = {
          ...proc.metadata,
          forensicIndicators: proc.forensicIndicators,
          processingWarning: proc.errorMessage || null,
        };

        const nextVerifStatus: VerificationStatus =
          row.verification_status === 'VERIFIED' || row.verification_status === 'MISMATCH_DETECTED'
            ? row.verification_status
            : proc.ocrStatus === 'UNAVAILABLE' || proc.ocrStatus === 'FAILED' || proc.ocrStatus === 'LOW_CONFIDENCE'
              ? 'MANUAL_REVIEW_REQUIRED'
              : 'UNVERIFIED';

        withTransaction(db, () => {
          db.prepare(
            `UPDATE documents
             SET detected_doc_type = ?, classification_confidence = ?, page_count = ?,
                 ocr_status = ?, ocr_engine = ?, ocr_confidence = ?,
                 reprocess_count = COALESCE(reprocess_count, 0) + 1,
                 last_error_reason = ?, extracted_text = ?, extracted_pages_json = ?,
                 metadata_json = ?, verification_status = ?, processed_at = ?, updated_at = ?
             WHERE id = ?`
          ).run(
            proc.detectedDocType,
            proc.classificationConfidence ?? null,
            proc.pageCount,
            proc.ocrStatus,
            proc.ocrEngine,
            proc.ocrConfidence ?? null,
            proc.errorMessage || null,
            proc.extractedText,
            JSON.stringify(proc.pages),
            JSON.stringify(combinedMeta),
            nextVerifStatus,
            nowIso,
            nowIso,
            docId
          );

          // Preserve officer-corrected fields; replace only automatically extracted fields
          const manualFieldNames = new Set(
            (
              db
                .prepare('SELECT field_name FROM extracted_fields WHERE document_id = ? AND manually_corrected = 1')
                .all(docId) as Array<{ field_name: string }>
            ).map((r) => r.field_name)
          );

          db.prepare('DELETE FROM extracted_fields WHERE document_id = ? AND manually_corrected = 0').run(docId);

          const efStmt = db.prepare(
            `INSERT INTO extracted_fields (
              id, document_id, field_name, field_value, confidence,
              page_number, bbox_json, extraction_method, manually_corrected
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`
          );
          for (const ef of proc.extractedFields) {
            if (!manualFieldNames.has(ef.fieldName)) {
              efStmt.run(
                `EF-${crypto.randomUUID()}`,
                docId,
                ef.fieldName,
                ef.fieldValue,
                ef.confidence,
                ef.pageNumber,
                ef.bbox ? JSON.stringify(ef.bbox) : null,
                ef.extractionMethod
              );
            }
          }

          evaluateApplicationCompliance(db, appId);

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'DOCUMENT_OCR_REPROCESSED',
            resourceType: 'DOCUMENT',
            resourceId: docId,
            metadata: {
              applicationId: appId,
              applicationNumber: row.application_number,
              ocrStatus: proc.ocrStatus,
              ocrEngine: proc.ocrEngine,
              reprocessCount: Number(row.reprocess_count || 0) + 1,
            },
          });
        });

        const updatedApp = loadApplicationDetail(db, appId);
        res.json({
          document: updatedApp?.documents.find((d) => d.id === docId) || null,
          processingWarning: proc.errorMessage || null,
          application: updatedApp,
        });
      } catch (err) {
        safeLog('ERROR', 'reprocess_document_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to reprocess document OCR.' });
      }
    }
  );

  router.get('/documents/:docId/file', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;
      const docId = String(req.params.docId);

      const row = db
        .prepare(
          `SELECT d.stored_filename, d.original_filename, d.mime_type, a.institution_id, a.is_synthetic_demo
           FROM documents d
           JOIN applications a ON a.id = d.application_id
           WHERE d.id = ?`
        )
        .get(docId) as
        | {
            stored_filename: string;
            original_filename: string;
            mime_type: string;
            institution_id: string;
            is_synthetic_demo: number;
          }
        | undefined;

      if (!row || (Boolean(row.is_synthetic_demo) && !isDemoModeEnabled())) {
        res.status(404).json({ error: 'Document not found.' });
        return;
      }

      if (user.role === 'INSTITUTION_USER' && row.institution_id !== user.institutionId) {
        res.status(403).json({ error: 'Unauthorised access to another institution’s document.' });
        return;
      }

      const uploadDir = path.resolve(resolveUploadDir(ctx.uploadDir));
      const safeStored = path.basename(row.stored_filename);
      const fullPath = path.resolve(uploadDir, safeStored);
      if (!fullPath.startsWith(`${uploadDir}${path.sep}`)) {
        res.status(400).json({ error: 'Invalid document storage path.' });
        return;
      }
      if (!fs.existsSync(fullPath)) {
        res.status(404).json({ error: 'Stored document file missing from disk.' });
        return;
      }

      res.setHeader('Content-Type', row.mime_type);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Disposition', `inline; filename="${sanitizeFilename(row.original_filename)}"`);
      fs.createReadStream(fullPath).pipe(res);
    } catch {
      res.status(500).json({ error: 'Failed to retrieve document file.' });
    }
  });

  const correctFieldSchema = z.object({
    fieldValue: z.string().min(1).max(500),
    correctionNote: z.string().min(5, 'Provide a brief explanation (min 5 chars) for the field correction.').max(500),
  });

  router.patch(
    '/documents/:docId/fields/:fieldId',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = correctFieldSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid correction payload.' });
        return;
      }
      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const docId = String(req.params.docId);
        const fieldId = String(req.params.fieldId);

        const fieldRow = db
          .prepare(
            `SELECT ef.*, d.application_id, d.original_filename, a.is_synthetic_demo, a.final_officer_decision
             FROM extracted_fields ef
             JOIN documents d ON d.id = ef.document_id
             JOIN applications a ON a.id = d.application_id
             WHERE ef.id = ? AND ef.document_id = ?`
          )
          .get(fieldId, docId) as
          | {
              id: string;
              field_name: string;
              field_value: string;
              application_id: string;
              original_filename: string;
              is_synthetic_demo: number;
              final_officer_decision: string | null;
            }
          | undefined;

        if (!fieldRow || (Boolean(fieldRow.is_synthetic_demo) && !isDemoModeEnabled())) {
          res.status(404).json({ error: 'Extracted field record not found.' });
          return;
        }

        if (fieldRow.final_officer_decision) {
          res.status(409).json({
            error: 'Application has a recorded final decision. Reopen the case before modifying extracted fields.',
          });
          return;
        }

        const nowIso = new Date().toISOString();
        withTransaction(db, () => {
          db.prepare(
            `UPDATE extracted_fields
             SET field_value = ?, manually_corrected = 1, corrected_by = ?, corrected_at = ?, correction_note = ?
             WHERE id = ?`
          ).run(parsed.data.fieldValue.trim(), user.id, nowIso, parsed.data.correctionNote.trim(), fieldId);

          db.prepare(
            `INSERT INTO officer_reviews (
              id, application_id, document_id, officer_id, action_type,
              previous_status, new_status, rationale, evidence_reference, created_at
            ) VALUES (?, ?, ?, ?, 'CORRECT_EXTRACTED_FIELD', ?, ?, ?, ?, ?)`
          ).run(
            `REV-${crypto.randomUUID()}`,
            fieldRow.application_id,
            docId,
            user.id,
            `${fieldRow.field_name}=${fieldRow.field_value}`,
            `${fieldRow.field_name}=${parsed.data.fieldValue.trim()}`,
            parsed.data.correctionNote.trim(),
            fieldRow.original_filename,
            nowIso
          );

          evaluateApplicationCompliance(db, fieldRow.application_id);

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'EXTRACTED_FIELD_CORRECTED',
            resourceType: 'DOCUMENT',
            resourceId: docId,
            metadata: {
              applicationId: fieldRow.application_id,
              fieldName: fieldRow.field_name,
              previousValue: fieldRow.field_value,
              correctedValue: parsed.data.fieldValue.trim(),
              note: parsed.data.correctionNote.trim(),
            },
          });
        });

        res.json(loadApplicationDetail(db, fieldRow.application_id));
      } catch (err) {
        safeLog('ERROR', 'correct_field_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to persist field correction.' });
      }
    }
  );

  // --------------------------------------------------------------------------
  // 7. Source Verification, Compliance Review & Officer Review Decisions
  // --------------------------------------------------------------------------
  const sourceVerifySchema = z.object({
    method: z.enum([
      'SANDBOX_ISSUER_API',
      'OFFICIAL_API',
      'OFFICIAL_PORTAL',
      'DIGITAL_SIGNATURE',
      'QR_SIGNATURE_CHECK',
      'DIGITAL_REPOSITORY',
      'REFERENCE_LOOKUP',
      'MANUAL_OFFICER_VERIFICATION',
    ]),
    issuerName: z.string().max(200).optional(),
    referenceNumber: z.string().max(100).optional(),
    manualStatus: z
      .enum([
        'VERIFIED',
        'MISMATCH_DETECTED',
        'EXPIRED',
        'VERIFICATION_PENDING',
        'SOURCE_UNAVAILABLE',
        'MANUAL_REVIEW_REQUIRED',
      ])
      .optional(),
    notes: z.string().max(1000).optional(),
    simulateIssuerUnavailable: z.boolean().optional(),
  });

  router.post(
    '/applications/:id/documents/:docId/verify-source',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'SENIOR_AUDITOR', 'ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = sourceVerifySchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid source verification request.' });
        return;
      }

      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const appId = String(req.params.id);
        const docId = String(req.params.docId);

        const appCheck = db
          .prepare('SELECT id, application_number, is_synthetic_demo, final_officer_decision FROM applications WHERE id = ?')
          .get(appId) as
          | { id: string; application_number: string; is_synthetic_demo: number; final_officer_decision: string | null }
          | undefined;
        if (!appCheck || (Boolean(appCheck.is_synthetic_demo) && !isDemoModeEnabled())) {
          res.status(404).json({ error: 'Application not found.' });
          return;
        }
        if (appCheck.final_officer_decision) {
          res.status(409).json({
            error: 'Application has a recorded final decision. Reopen the case before recording new source verifications.',
          });
          return;
        }

        let record!: SourceVerificationRecord;
        withTransaction(db, () => {
          record = executeSourceVerification(db, {
            applicationId: appId,
            documentId: docId,
            method: parsed.data.method as VerificationMethod,
            issuerName: parsed.data.issuerName,
            referenceNumber: parsed.data.referenceNumber,
            manualStatus: parsed.data.manualStatus as VerificationStatus | undefined,
            notes: parsed.data.notes,
            actorUserId: user.id,
            simulateIssuerUnavailable:
              process.env.NODE_ENV !== 'production' ? parsed.data.simulateIssuerUnavailable : false,
          });

          if (parsed.data.method === 'MANUAL_OFFICER_VERIFICATION') {
            db.prepare(
              `INSERT INTO officer_reviews (
                id, application_id, document_id, officer_id, action_type,
                previous_status, new_status, rationale, evidence_reference, created_at
              ) VALUES (?, ?, ?, ?, 'RECORD_MANUAL_VERIFICATION', NULL, ?, ?, ?, ?)`
            ).run(
              `REV-${crypto.randomUUID()}`,
              appId,
              docId,
              user.id,
              record.status,
              parsed.data.notes || `Manual source verification recorded (${record.status}).`,
              record.referenceNumber || record.issuerName,
              record.attemptedAt
            );
          }

          evaluateApplicationCompliance(db, appId);

          if (record.status === 'MISMATCH_DETECTED') {
            emitInAppNotification(db, {
              recipientRole: 'INTERNAL_ALL',
              applicationId: appId,
              alertType: 'SOURCE_MISMATCH_DETECTED',
              severity: 'CRITICAL',
              title: `${appCheck.application_number}: Source Verification Mismatch`,
              message: `${record.issuerName} reported MISMATCH_DETECTED via ${record.verificationMethod}.`,
              isSyntheticDemo: Boolean(appCheck.is_synthetic_demo),
            });
          }

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'SOURCE_VERIFICATION_RECORDED',
            resourceType: 'DOCUMENT',
            resourceId: docId,
            metadata: {
              applicationId: appId,
              method: record.verificationMethod,
              isSandboxDemo: record.isSandboxDemo,
              status: record.status,
              issuerName: record.issuerName,
            },
          });
        });

        res.json({
          verification: record,
          application: loadApplicationDetail(db, appId),
        });
      } catch (err) {
        res.status(400).json({ error: (err as Error).message || 'Source verification failed.' });
      }
    }
  );

  const reviewComplianceItemSchema = z.object({
    complianceStatus: z.enum([
      'SATISFIED',
      'NOT_SATISFIED',
      'INSUFFICIENT_EVIDENCE',
      'NOT_APPLICABLE',
      'MANUAL_REVIEW_REQUIRED',
    ]),
    officerObservation: z.string().min(5, 'Provide an officer observation of at least 5 characters.').max(2000),
    additionalEvidenceRequested: z.boolean().optional(),
    additionalEvidenceNote: z.string().max(1000).nullable().optional(),
    physicalInspectionFlagged: z.boolean().optional(),
  });

  router.patch(
    '/applications/:id/compliance-items/:itemId',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = reviewComplianceItemSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid compliance review payload.' });
        return;
      }

      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const appId = String(req.params.id);
        const itemId = String(req.params.itemId);

        const row = db
          .prepare(
            `SELECT aci.*, cr.requirement_code, cr.title,
                    a.application_number, a.institution_id, a.status AS app_status,
                    a.final_officer_decision, a.is_synthetic_demo
             FROM application_compliance_items aci
             JOIN compliance_requirements cr ON cr.id = aci.requirement_id
             JOIN applications a ON a.id = aci.application_id
             WHERE aci.id = ? AND aci.application_id = ?`
          )
          .get(itemId, appId) as
          | {
              id: string;
              compliance_status: ComplianceItemStatus;
              requirement_code: string;
              title: string;
              application_number: string;
              institution_id: string;
              app_status: string;
              final_officer_decision: string | null;
              is_synthetic_demo: number;
            }
          | undefined;

        if (!row || (Boolean(row.is_synthetic_demo) && !isDemoModeEnabled())) {
          res.status(404).json({ error: 'Compliance item not found.' });
          return;
        }

        if (row.final_officer_decision) {
          res.status(409).json({
            error: 'Application has a recorded final decision. Reopen the case before modifying compliance assessments.',
          });
          return;
        }

        const nowIso = new Date().toISOString();
        const data = parsed.data;

        withTransaction(db, () => {
          db.prepare(
            `UPDATE application_compliance_items
             SET compliance_status = ?,
                 officer_observation = ?,
                 additional_evidence_requested = COALESCE(?, additional_evidence_requested),
                 additional_evidence_note = CASE WHEN ? IS NOT NULL THEN ? ELSE additional_evidence_note END,
                 physical_inspection_flagged = COALESCE(?, physical_inspection_flagged),
                 reviewed_by = ?,
                 reviewed_at = ?,
                 updated_at = ?
             WHERE id = ?`
          ).run(
            data.complianceStatus,
            data.officerObservation.trim(),
            data.additionalEvidenceRequested !== undefined ? (data.additionalEvidenceRequested ? 1 : 0) : null,
            data.additionalEvidenceNote !== undefined ? 'SET' : null,
            data.additionalEvidenceNote ?? null,
            data.physicalInspectionFlagged !== undefined ? (data.physicalInspectionFlagged ? 1 : 0) : null,
            user.id,
            nowIso,
            nowIso,
            itemId
          );

          if (data.physicalInspectionFlagged === true) {
            db.prepare(
              'UPDATE applications SET physical_inspection_required = 1, physical_inspection_reason = ?, updated_at = ? WHERE id = ?'
            ).run(data.officerObservation.trim(), nowIso, appId);

            emitInAppNotification(db, {
              recipientRole: 'INTERNAL_ALL',
              applicationId: appId,
              alertType: 'PHYSICAL_INSPECTION_FLAGGED',
              severity: 'HIGH',
              title: `${row.application_number}: Flagged for Physical EVC Inspection`,
              message: `${row.requirement_code}: ${data.officerObservation.trim().slice(0, 140)}`,
              isSyntheticDemo: Boolean(row.is_synthetic_demo),
            });
          }

          if (data.additionalEvidenceRequested === true) {
            db.prepare("UPDATE applications SET status = 'CLARIFICATION_REQUESTED', updated_at = ? WHERE id = ?").run(
              nowIso,
              appId
            );

            emitInAppNotification(db, {
              recipientRole: 'INSTITUTION_USER',
              recipientInstitutionId: row.institution_id,
              applicationId: appId,
              alertType: 'ADDITIONAL_EVIDENCE_REQUESTED',
              severity: 'HIGH',
              title: `${row.application_number}: Additional Evidence Requested`,
              message: `${row.title}: ${data.additionalEvidenceNote || data.officerObservation.trim()}`,
              isSyntheticDemo: Boolean(row.is_synthetic_demo),
            });
          }

          const actionType: OfficerActionType = data.physicalInspectionFlagged
            ? 'FLAG_PHYSICAL_INSPECTION'
            : data.additionalEvidenceRequested
              ? 'REQUEST_ADDITIONAL_EVIDENCE'
              : 'ADD_REVIEW_NOTE';

          db.prepare(
            `INSERT INTO officer_reviews (
              id, application_id, document_id, officer_id, action_type,
              previous_status, new_status, rationale, evidence_reference, created_at
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            `REV-${crypto.randomUUID()}`,
            appId,
            user.id,
            actionType,
            row.compliance_status,
            data.complianceStatus,
            data.officerObservation.trim(),
            row.requirement_code,
            nowIso
          );

          evaluateApplicationCompliance(db, appId);

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'COMPLIANCE_ITEM_REVIEWED',
            resourceType: 'APPLICATION',
            resourceId: appId,
            metadata: {
              applicationNumber: row.application_number,
              requirementCode: row.requirement_code,
              complianceStatus: data.complianceStatus,
              additionalEvidenceRequested: Boolean(data.additionalEvidenceRequested),
              physicalInspectionFlagged: Boolean(data.physicalInspectionFlagged),
            },
          });
        });

        res.json(loadApplicationDetail(db, appId));
      } catch (err) {
        safeLog('ERROR', 'review_compliance_item_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to update compliance item assessment.' });
      }
    }
  );

  const officerActionSchema = z.object({
    actionType: z.enum([
      'MARK_DOCUMENT_VERIFIED',
      'RECORD_MISMATCH',
      'REQUEST_CLARIFICATION',
      'REQUEST_ADDITIONAL_EVIDENCE',
      'FLAG_PHYSICAL_INSPECTION',
      'CLEAR_PHYSICAL_INSPECTION',
      'ADD_REVIEW_NOTE',
      'RESOLVE_FINDING',
      'FINAL_DECISION_APPROVE',
      'FINAL_DECISION_REJECT',
      'REOPEN_APPLICATION',
    ]),
    documentId: z.string().nullable().optional(),
    findingId: z.string().nullable().optional(),
    rationale: z.string().min(5, 'Rationale / review note must be at least 5 characters.').max(2000),
    evidenceReference: z.string().max(300).optional(),
  });

  router.post(
    '/applications/:id/officer-actions',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'SENIOR_AUDITOR', 'ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = officerActionSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid officer review action.' });
        return;
      }

      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const appId = String(req.params.id);
        const { actionType, documentId, findingId, rationale, evidenceReference } = parsed.data;

        if (
          (actionType === 'FINAL_DECISION_APPROVE' || actionType === 'FINAL_DECISION_REJECT') &&
          user.role === 'SENIOR_AUDITOR'
        ) {
          res.status(403).json({
            error: 'Final approval/rejection decisions are restricted to REVIEW_OFFICER or ADMIN roles.',
          });
          return;
        }

        if (
          (actionType === 'FINAL_DECISION_APPROVE' || actionType === 'FINAL_DECISION_REJECT') &&
          rationale.trim().length < 15
        ) {
          res.status(400).json({
            error: 'Final regulatory decisions require a substantive human rationale of at least 15 characters.',
          });
          return;
        }

        if (actionType === 'REOPEN_APPLICATION' && !['SENIOR_AUDITOR', 'ADMIN'].includes(user.role)) {
          res.status(403).json({
            error: 'Reopening a decided case requires SENIOR_AUDITOR or ADMIN permissions.',
          });
          return;
        }

        const appRow = db
          .prepare(
            'SELECT id, application_number, institution_id, status, final_officer_decision, is_synthetic_demo FROM applications WHERE id = ?'
          )
          .get(appId) as
          | {
              id: string;
              application_number: string;
              institution_id: string;
              status: string;
              final_officer_decision: string | null;
              is_synthetic_demo: number;
            }
          | undefined;

        if (!appRow || (Boolean(appRow.is_synthetic_demo) && !isDemoModeEnabled())) {
          res.status(404).json({ error: 'Application not found.' });
          return;
        }

        if (actionType === 'REOPEN_APPLICATION' && !appRow.final_officer_decision) {
          res.status(409).json({
            error: 'Cannot reopen an application that does not have a recorded final decision.',
          });
          return;
        }

        if (
          appRow.final_officer_decision &&
          actionType !== 'REOPEN_APPLICATION' &&
          actionType !== 'ADD_REVIEW_NOTE'
        ) {
          res.status(409).json({
            error:
              'Application already has a recorded final decision. Reopen the application before changing verification state or recording another decision.',
          });
          return;
        }

        const nowIso = new Date().toISOString();
        let prevStatus: string | null = appRow.status;
        let newStatus: string | null = appRow.status;

        withTransaction(db, () => {
          if (actionType === 'MARK_DOCUMENT_VERIFIED' || actionType === 'RECORD_MISMATCH') {
            if (!documentId) {
              throw new Error('documentId is required for document verification/mismatch actions.');
            }
            const docRow = db
              .prepare('SELECT id, verification_status FROM documents WHERE id = ? AND application_id = ?')
              .get(documentId, appId) as { id: string; verification_status: string } | undefined;
            if (!docRow) {
              throw new Error('Document does not belong to this application.');
            }
            prevStatus = docRow.verification_status;
            newStatus = actionType === 'MARK_DOCUMENT_VERIFIED' ? 'VERIFIED' : 'MISMATCH_DETECTED';
            db.prepare('UPDATE documents SET verification_status = ?, updated_at = ? WHERE id = ?').run(
              newStatus,
              nowIso,
              documentId
            );
          } else if (actionType === 'RESOLVE_FINDING') {
            if (!findingId) {
              throw new Error('findingId is required when resolving a validation finding.');
            }
            const fRow = db
              .prepare('SELECT id, finding_code FROM validation_findings WHERE id = ? AND application_id = ?')
              .get(findingId, appId) as { id: string; finding_code: string } | undefined;
            if (!fRow) {
              throw new Error('Validation finding not found on this application.');
            }
            prevStatus = 'OPEN_FINDING';
            newStatus = 'RESOLVED_BY_OFFICER';
            db.prepare(
              `UPDATE validation_findings
               SET resolved_by_officer = 1, resolution_note = ?, resolved_by = ?, resolved_at = ?
               WHERE id = ?`
            ).run(rationale.trim(), user.id, nowIso, findingId);
          } else if (actionType === 'REQUEST_CLARIFICATION' || actionType === 'REQUEST_ADDITIONAL_EVIDENCE') {
            newStatus = 'CLARIFICATION_REQUESTED';
            db.prepare('UPDATE applications SET status = ?, updated_at = ? WHERE id = ?').run(newStatus, nowIso, appId);

            emitInAppNotification(db, {
              recipientRole: 'INSTITUTION_USER',
              recipientInstitutionId: appRow.institution_id,
              applicationId: appId,
              alertType: 'CLARIFICATION_REQUESTED',
              severity: 'HIGH',
              title: `${appRow.application_number}: Regulatory Clarification Requested`,
              message: rationale.trim().slice(0, 180),
              isSyntheticDemo: Boolean(appRow.is_synthetic_demo),
            });
          } else if (actionType === 'FLAG_PHYSICAL_INSPECTION') {
            newStatus = appRow.status;
            db.prepare(
              'UPDATE applications SET physical_inspection_required = 1, physical_inspection_reason = ?, updated_at = ? WHERE id = ?'
            ).run(rationale.trim(), nowIso, appId);

            emitInAppNotification(db, {
              recipientRole: 'INTERNAL_ALL',
              applicationId: appId,
              alertType: 'PHYSICAL_INSPECTION_FLAGGED',
              severity: 'HIGH',
              title: `${appRow.application_number}: Flagged for Physical Site Inspection`,
              message: rationale.trim().slice(0, 180),
              isSyntheticDemo: Boolean(appRow.is_synthetic_demo),
            });
          } else if (actionType === 'CLEAR_PHYSICAL_INSPECTION') {
            newStatus = appRow.status;
            db.prepare(
              'UPDATE applications SET physical_inspection_required = 0, physical_inspection_reason = NULL, updated_at = ? WHERE id = ?'
            ).run(nowIso, appId);
          } else if (actionType === 'FINAL_DECISION_APPROVE' || actionType === 'FINAL_DECISION_REJECT') {
            newStatus = actionType === 'FINAL_DECISION_APPROVE' ? 'APPROVED_BY_OFFICER' : 'REJECTED_BY_OFFICER';
            db.prepare(
              `UPDATE applications
               SET status = ?, final_officer_decision = ?, final_decision_rationale = ?,
                   final_decision_by = ?, final_decision_at = ?, updated_at = ?
               WHERE id = ?`
            ).run(newStatus, newStatus, rationale.trim(), user.id, nowIso, nowIso, appId);

            emitInAppNotification(db, {
              recipientRole: 'INSTITUTION_USER',
              recipientInstitutionId: appRow.institution_id,
              applicationId: appId,
              alertType: 'FINAL_DECISION_RECORDED',
              severity: actionType === 'FINAL_DECISION_APPROVE' ? 'INFO' : 'CRITICAL',
              title: `${appRow.application_number}: Final Officer Decision (${newStatus})`,
              message: rationale.trim().slice(0, 180),
              isSyntheticDemo: Boolean(appRow.is_synthetic_demo),
            });
          } else if (actionType === 'REOPEN_APPLICATION') {
            newStatus = 'REOPENED';
            db.prepare(
              `UPDATE applications
               SET status = 'REOPENED', final_officer_decision = NULL,
                   final_decision_rationale = NULL, final_decision_by = NULL,
                   final_decision_at = NULL, updated_at = ?
               WHERE id = ?`
            ).run(nowIso, appId);
          }

          db.prepare(
            `INSERT INTO officer_reviews (
              id, application_id, document_id, officer_id, action_type,
              previous_status, new_status, rationale, evidence_reference, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            `REV-${crypto.randomUUID()}`,
            appId,
            documentId || null,
            user.id,
            actionType as OfficerActionType,
            prevStatus,
            newStatus,
            rationale.trim(),
            evidenceReference || findingId || null,
            nowIso
          );

          evaluateApplicationCompliance(db, appId);

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: `OFFICER_${actionType}`,
            resourceType: 'APPLICATION',
            resourceId: appId,
            metadata: {
              applicationNumber: appRow.application_number,
              documentId: documentId || null,
              findingId: findingId || null,
              previousStatus: prevStatus,
              newStatus,
              rationale: rationale.trim(),
            },
          });
        });

        res.json(loadApplicationDetail(db, appId));
      } catch (err) {
        res.status(400).json({ error: (err as Error).message || 'Failed to record officer action.' });
      }
    }
  );

  // --------------------------------------------------------------------------
  // 8. Configurable Versioned Regulatory Rules (List, Create, Version, Toggle)
  // --------------------------------------------------------------------------
  router.get('/rules', requireAuth, (_req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const rows = db
        .prepare('SELECT * FROM validation_rules ORDER BY is_active DESC, rule_code ASC, updated_at DESC')
        .all() as Array<Record<string, unknown>>;

      const rules: ValidationRuleRecord[] = rows.map((r) => ({
        id: String(r.id),
        ruleCode: String(r.rule_code),
        version: String(r.version),
        name: String(r.name),
        description: String(r.description),
        category: String(r.category),
        docType: r.doc_type ? String(r.doc_type) : null,
        ruleType: String(r.rule_type),
        severity: r.severity as ValidationRuleRecord['severity'],
        authoritySource: r.authority_source as ValidationRuleRecord['authoritySource'],
        config: parseJsonSafe(String(r.config_json), {}),
        effectiveFrom: r.effective_from ? String(r.effective_from) : null,
        effectiveTo: r.effective_to ? String(r.effective_to) : null,
        expectedFields: parseJsonSafe<string[]>(r.expected_fields_json ? String(r.expected_fields_json) : '[]', []),
        recommendedAction: r.recommended_action ? String(r.recommended_action) : null,
        evidenceReferenceLabel: r.evidence_reference_label ? String(r.evidence_reference_label) : null,
        isIllustrative: r.is_illustrative !== undefined ? Boolean(r.is_illustrative) : true,
        isActive: Boolean(r.is_active),
        updatedAt: String(r.updated_at),
      }));

      res.json({ rules, supportedRuleTypes: SUPPORTED_RULE_TYPES });
    } catch {
      res.status(500).json({ error: 'Failed to retrieve validation rules.' });
    }
  });

  const createRuleSchema = z.object({
    ruleCode: z.string().min(6).max(45),
    version: z.string().regex(/^\d+\.\d+\.\d+$/, 'Semantic version required (e.g. 1.0.0).'),
    name: z.string().min(4).max(150),
    description: z.string().min(10).max(500),
    category: z.string().min(2).max(50).default('ALL'),
    docType: z.string().nullable().optional(),
    ruleType: z.string().min(3).max(50),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
    authoritySource: z
      .enum(['ILLUSTRATIVE_CONFIGURABLE_EXAMPLE', 'INSTITUTIONAL_CROSSCHECK', 'CRYPTOGRAPHIC_INTEGRITY'])
      .default('ILLUSTRATIVE_CONFIGURABLE_EXAMPLE'),
    config: z.record(z.string(), z.unknown()),
    effectiveFrom: z.string().nullable().optional(),
    effectiveTo: z.string().nullable().optional(),
    expectedFields: z.array(z.string()).optional(),
    recommendedAction: z.string().max(400).nullable().optional(),
    evidenceReferenceLabel: z.string().max(200).nullable().optional(),
    isIllustrative: z.boolean().optional(),
    isActive: z.boolean().optional(),
  });

  router.post(
    '/rules',
    requireAuth,
    requireRoles('ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = createRuleSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid rule creation payload.' });
        return;
      }

      try {
        const data = parsed.data;
        const ruleValidation = validateRuleDefinition({
          ruleCode: data.ruleCode,
          version: data.version,
          ruleType: data.ruleType,
          severity: data.severity,
          category: data.category,
          docType: data.docType || null,
          config: data.config,
          effectiveFrom: data.effectiveFrom || null,
          effectiveTo: data.effectiveTo || null,
          expectedFields: data.expectedFields || [],
        });

        if (!ruleValidation.valid) {
          res.status(400).json({
            error: `Rule validation failed: ${ruleValidation.errors.join(' ')}`,
            validationErrors: ruleValidation.errors,
          });
          return;
        }

        const db = ctx.getDb();
        const user = req.authUser!;
        const ruleCode = data.ruleCode.trim();

        const existing = db.prepare('SELECT id FROM validation_rules WHERE rule_code = ? LIMIT 1').get(ruleCode);
        if (existing) {
          res.status(409).json({
            error: `Rule '${ruleCode}' already exists. Publish a new version via /api/rules/${ruleCode}/versions instead.`,
          });
          return;
        }

        const nowIso = new Date().toISOString();
        const newId = `RUL-${crypto.randomUUID()}`;
        const isIllustrative = data.isIllustrative ?? data.authoritySource === 'ILLUSTRATIVE_CONFIGURABLE_EXAMPLE';
        const isActive = data.isActive ?? true;

        withTransaction(db, () => {
          db.prepare(
            `INSERT INTO validation_rules (
              id, rule_code, version, name, description, category, doc_type, rule_type,
              severity, authority_source, config_json, effective_from, effective_to,
              expected_fields_json, recommended_action, evidence_reference_label,
              is_illustrative, is_active, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            newId,
            ruleCode,
            data.version,
            data.name.trim(),
            data.description.trim(),
            data.category.trim(),
            data.docType || null,
            data.ruleType,
            data.severity,
            data.authoritySource,
            JSON.stringify(data.config),
            data.effectiveFrom || null,
            data.effectiveTo || null,
            JSON.stringify(data.expectedFields || []),
            data.recommendedAction?.trim() || null,
            data.evidenceReferenceLabel?.trim() || null,
            isIllustrative ? 1 : 0,
            isActive ? 1 : 0,
            user.id,
            nowIso
          );

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'VALIDATION_RULE_CREATED',
            resourceType: 'RULE',
            resourceId: ruleCode,
            metadata: {
              version: data.version,
              ruleType: data.ruleType,
              severity: data.severity,
              category: data.category,
              isActive,
            },
          });
        });

        res.status(201).json({
          id: newId,
          ruleCode,
          version: data.version,
          isActive,
          updatedAt: nowIso,
        });
      } catch (err) {
        safeLog('ERROR', 'create_rule_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to create validation rule.' });
      }
    }
  );

  const updateRuleSchema = z.object({
    version: z.string().regex(/^\d+\.\d+\.\d+$/, 'Semantic version required (e.g. 1.3.0).'),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
    description: z.string().min(10).max(500),
    config: z.record(z.string(), z.unknown()),
    effectiveFrom: z.string().nullable().optional(),
    effectiveTo: z.string().nullable().optional(),
    expectedFields: z.array(z.string()).optional(),
    recommendedAction: z.string().max(400).nullable().optional(),
    evidenceReferenceLabel: z.string().max(200).nullable().optional(),
    isIllustrative: z.boolean().optional(),
  });

  router.post(
    '/rules/:ruleCode/versions',
    requireAuth,
    requireRoles('ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = updateRuleSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid rule version payload.' });
        return;
      }
      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const ruleCode = String(req.params.ruleCode);

        const current = db
          .prepare('SELECT * FROM validation_rules WHERE rule_code = ? ORDER BY is_active DESC, updated_at DESC LIMIT 1')
          .get(ruleCode) as Record<string, unknown> | undefined;

        if (!current) {
          res.status(404).json({ error: `Rule '${ruleCode}' not found.` });
          return;
        }

        const effectiveFrom =
          parsed.data.effectiveFrom !== undefined
            ? parsed.data.effectiveFrom
            : current.effective_from
              ? String(current.effective_from)
              : null;
        const effectiveTo =
          parsed.data.effectiveTo !== undefined
            ? parsed.data.effectiveTo
            : current.effective_to
              ? String(current.effective_to)
              : null;
        const expectedFields =
          parsed.data.expectedFields !== undefined
            ? parsed.data.expectedFields
            : parseJsonSafe<string[]>(current.expected_fields_json ? String(current.expected_fields_json) : '[]', []);

        const ruleValidation = validateRuleDefinition({
          ruleCode,
          version: parsed.data.version,
          ruleType: String(current.rule_type),
          severity: parsed.data.severity,
          category: String(current.category),
          docType: current.doc_type ? String(current.doc_type) : null,
          config: parsed.data.config,
          effectiveFrom,
          effectiveTo,
          expectedFields,
        });

        if (!ruleValidation.valid) {
          res.status(400).json({
            error: `Rule parameter validation failed: ${ruleValidation.errors.join(' ')}`,
            validationErrors: ruleValidation.errors,
          });
          return;
        }

        const dupVer = db
          .prepare('SELECT id FROM validation_rules WHERE rule_code = ? AND version = ?')
          .get(ruleCode, parsed.data.version);
        if (dupVer) {
          res.status(409).json({ error: `Rule ${ruleCode} version ${parsed.data.version} already exists.` });
          return;
        }

        const nowIso = new Date().toISOString();
        const newId = `RUL-${crypto.randomUUID()}`;
        const recommendedAction =
          parsed.data.recommendedAction !== undefined
            ? parsed.data.recommendedAction
            : current.recommended_action
              ? String(current.recommended_action)
              : null;
        const evidenceReferenceLabel =
          parsed.data.evidenceReferenceLabel !== undefined
            ? parsed.data.evidenceReferenceLabel
            : current.evidence_reference_label
              ? String(current.evidence_reference_label)
              : null;
        const isIllustrative =
          parsed.data.isIllustrative !== undefined
            ? parsed.data.isIllustrative
            : current.is_illustrative !== undefined
              ? Boolean(current.is_illustrative)
              : true;

        withTransaction(db, () => {
          db.prepare('UPDATE validation_rules SET is_active = 0 WHERE rule_code = ?').run(ruleCode);
          db.prepare(
            `INSERT INTO validation_rules (
              id, rule_code, version, name, description, category, doc_type,
              rule_type, severity, authority_source, config_json,
              effective_from, effective_to, expected_fields_json,
              recommended_action, evidence_reference_label, is_illustrative,
              is_active, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
          ).run(
            newId,
            ruleCode,
            parsed.data.version,
            String(current.name),
            parsed.data.description.trim(),
            String(current.category),
            current.doc_type ? String(current.doc_type) : null,
            String(current.rule_type),
            parsed.data.severity,
            String(current.authority_source),
            JSON.stringify(parsed.data.config),
            effectiveFrom,
            effectiveTo,
            JSON.stringify(expectedFields),
            recommendedAction,
            evidenceReferenceLabel,
            isIllustrative ? 1 : 0,
            user.id,
            nowIso
          );

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'VALIDATION_RULE_VERSION_PUBLISHED',
            resourceType: 'RULE',
            resourceId: ruleCode,
            metadata: {
              previousVersion: current.version,
              newVersion: parsed.data.version,
              severity: parsed.data.severity,
              effectiveFrom,
              effectiveTo,
            },
          });
        });

        res.status(201).json({
          ruleCode,
          version: parsed.data.version,
          updatedAt: nowIso,
        });
      } catch (err) {
        safeLog('ERROR', 'publish_rule_version_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to publish rule version.' });
      }
    }
  );

  const toggleRuleStatusSchema = z.object({
    isActive: z.boolean(),
  });

  router.patch(
    '/rules/:ruleCode/status',
    requireAuth,
    requireRoles('ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = toggleRuleStatusSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid rule status payload. Expected boolean isActive.' });
        return;
      }

      try {
        const db = ctx.getDb();
        const user = req.authUser!;
        const ruleCode = String(req.params.ruleCode);
        const latest = db
          .prepare(
            'SELECT id, version FROM validation_rules WHERE rule_code = ? ORDER BY is_active DESC, updated_at DESC LIMIT 1'
          )
          .get(ruleCode) as { id: string; version: string } | undefined;

        if (!latest) {
          res.status(404).json({ error: `Rule '${ruleCode}' not found.` });
          return;
        }

        const nowIso = new Date().toISOString();
        withTransaction(db, () => {
          db.prepare('UPDATE validation_rules SET is_active = 0 WHERE rule_code = ?').run(ruleCode);
          if (parsed.data.isActive) {
            db.prepare('UPDATE validation_rules SET is_active = 1, updated_by = ?, updated_at = ? WHERE id = ?').run(
              user.id,
              nowIso,
              latest.id
            );
          } else {
            db.prepare('UPDATE validation_rules SET updated_by = ?, updated_at = ? WHERE id = ?').run(
              user.id,
              nowIso,
              latest.id
            );
          }

          appendAuditEvent(db, {
            actorUserId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            action: 'VALIDATION_RULE_STATUS_UPDATED',
            resourceType: 'RULE',
            resourceId: ruleCode,
            metadata: {
              version: latest.version,
              isActive: parsed.data.isActive,
            },
          });
        });

        res.json({
          ruleCode,
          version: latest.version,
          isActive: parsed.data.isActive,
          updatedAt: nowIso,
        });
      } catch (err) {
        safeLog('ERROR', 'update_rule_status_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to update validation rule status.' });
      }
    }
  );

  // --------------------------------------------------------------------------
  // 8b. Persisted Scoped In-App Notifications (IN_APP_ONLY — No Email/SMS Claimed)
  // --------------------------------------------------------------------------
  router.get('/notifications', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;
      const demoMode = isDemoModeEnabled();
      const scope = buildNotificationScopeSql(user, demoMode);

      const rows = db
        .prepare(`SELECT * FROM in_app_notifications ${scope.whereSql} ORDER BY is_read ASC, created_at DESC LIMIT 40`)
        .all(...scope.args) as Array<Record<string, unknown>>;

      const notifications: InAppNotificationRecord[] = rows.map((r) => ({
        id: String(r.id),
        recipientRole: r.recipient_role as InAppNotificationRecord['recipientRole'],
        recipientInstitutionId: r.recipient_institution_id ? String(r.recipient_institution_id) : null,
        applicationId: r.application_id ? String(r.application_id) : null,
        alertType: String(r.alert_type),
        severity: r.severity as InAppNotificationRecord['severity'],
        title: String(r.title),
        message: String(r.message),
        deliveryChannel: 'IN_APP_ONLY',
        isRead: Boolean(r.is_read),
        readBy: r.read_by ? String(r.read_by) : null,
        readAt: r.read_at ? String(r.read_at) : null,
        createdAt: String(r.created_at),
      }));

      const unreadCount = notifications.filter((n) => !n.isRead).length;

      res.json({
        deliveryMode: 'IN_APP_ONLY',
        deliveryNotice: 'Persisted in-app regulatory alerts only; external email and SMS gateways are not configured.',
        unreadCount,
        notifications,
      });
    } catch {
      res.status(500).json({ error: 'Failed to retrieve in-app notifications.' });
    }
  });

  router.patch('/notifications/:id/read', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;
      const demoMode = isDemoModeEnabled();
      const notifId = String(req.params.id);
      const scope = buildNotificationScopeSql(user, demoMode);

      const existing = db
        .prepare(`SELECT id FROM in_app_notifications ${scope.whereSql} AND id = ?`)
        .get(...scope.args, notifId) as { id: string } | undefined;

      if (!existing) {
        res.status(404).json({ error: 'Notification not found.' });
        return;
      }

      const nowIso = new Date().toISOString();
      db.prepare('UPDATE in_app_notifications SET is_read = 1, read_by = ?, read_at = ? WHERE id = ?').run(
        user.id,
        nowIso,
        notifId
      );

      res.json({ id: notifId, isRead: true, readAt: nowIso });
    } catch {
      res.status(500).json({ error: 'Failed to mark notification as read.' });
    }
  });

  router.post('/notifications/read-all', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;
      const demoMode = isDemoModeEnabled();
      const scope = buildNotificationScopeSql(user, demoMode);
      const nowIso = new Date().toISOString();

      const info = db
        .prepare(
          `UPDATE in_app_notifications SET is_read = 1, read_by = ?, read_at = ?
           ${scope.whereSql} AND is_read = 0`
        )
        .run(user.id, nowIso, ...scope.args);

      res.json({ markedReadCount: Number(info.changes || 0), readAt: nowIso });
    } catch {
      res.status(500).json({ error: 'Failed to mark notifications as read.' });
    }
  });

  // --------------------------------------------------------------------------
  // 9. Validation Reports (JSON / CSV Export) & Tamper-Evident Audit Trail
  // --------------------------------------------------------------------------
  router.get('/applications/:id/report', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    try {
      const db = ctx.getDb();
      const user = req.authUser!;
      const detail = loadApplicationDetail(db, String(req.params.id));
      if (!detail || (detail.isSyntheticDemo && !isDemoModeEnabled())) {
        res.status(404).json({ error: 'Application not found.' });
        return;
      }
      if (user.role === 'INSTITUTION_USER' && detail.institutionId !== user.institutionId) {
        res.status(403).json({ error: 'Unauthorised access to another institution’s report.' });
        return;
      }

      const format = String(req.query.format || 'json').toLowerCase();
      appendAuditEvent(db, {
        actorUserId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'VALIDATION_REPORT_GENERATED',
        resourceType: 'APPLICATION',
        resourceId: detail.id,
        metadata: { applicationNumber: detail.applicationNumber, format },
      });

      if (format === 'csv') {
        const lines: string[] = [];
        lines.push(
          [
            'ApplicationNumber',
            'InstitutionName',
            'ApplicationStatus',
            'AdvisoryTrustScore',
            'TrustScoreVersion',
            'FinalOfficerDecision',
            'RecordType',
            'ReferenceOrRuleCode',
            'RuleVersion',
            'SeverityOrStatus',
            'DocumentFilename',
            'DocumentSHA256',
            'FieldOrMethod',
            'ExpectedValue',
            'ObservedValue',
            'ExplanationOrNotes',
            'Timestamp',
          ].join(',')
        );

        for (const doc of detail.documents) {
          lines.push(
            [
              detail.applicationNumber,
              detail.institutionName,
              detail.status,
              detail.trustScore ?? '',
              detail.trustScoreVersion ?? '',
              detail.finalOfficerDecision ?? 'PENDING_HUMAN_REVIEW',
              'DOCUMENT',
              doc.declaredDocType,
              '',
              doc.verificationStatus,
              doc.originalFilename,
              doc.sha256Hash,
              `OCR:${doc.ocrStatus} (${doc.ocrConfidence ?? 'N/A'})`,
              '',
              doc.detectedDocType,
              `Engine: ${doc.ocrEngine}`,
              doc.createdAt,
            ]
              .map(escapeCsvCell)
              .join(',')
          );
        }

        for (const f of detail.findings) {
          lines.push(
            [
              detail.applicationNumber,
              detail.institutionName,
              detail.status,
              detail.trustScore ?? '',
              detail.trustScoreVersion ?? '',
              detail.finalOfficerDecision ?? 'PENDING_HUMAN_REVIEW',
              `FINDING_${f.findingCategory}`,
              f.ruleCode,
              f.ruleVersion,
              f.resolvedByOfficer ? `${f.severity} (RESOLVED)` : f.severity,
              f.documentFilename || 'Application-Level',
              '',
              `${f.fieldName || ''} [${f.epistemicClassification}]`,
              f.expectedValue || '',
              f.observedValue || '',
              f.resolvedByOfficer ? `${f.explanation} [Officer Resolution: ${f.resolutionNote}]` : f.explanation,
              f.createdAt,
            ]
              .map(escapeCsvCell)
              .join(',')
          );
        }

        for (const ci of detail.complianceItems) {
          lines.push(
            [
              detail.applicationNumber,
              detail.institutionName,
              detail.status,
              detail.trustScore ?? '',
              detail.trustScoreVersion ?? '',
              detail.finalOfficerDecision ?? 'PENDING_HUMAN_REVIEW',
              'COMPLIANCE_ITEM',
              ci.requirementCode,
              '',
              ci.complianceStatus,
              ci.linkedDocumentFilename || 'Unlinked',
              '',
              ci.domain,
              ci.isMandatory ? 'MANDATORY' : 'SUPPLEMENTARY',
              ci.physicalInspectionFlagged ? 'PHYSICAL_INSPECTION_FLAGGED' : ci.complianceStatus,
              ci.officerObservation || ci.autoEvaluatedNote || '',
              ci.updatedAt,
            ]
              .map(escapeCsvCell)
              .join(',')
          );
        }

        for (const sv of detail.sourceVerifications) {
          lines.push(
            [
              detail.applicationNumber,
              detail.institutionName,
              detail.status,
              detail.trustScore ?? '',
              detail.trustScoreVersion ?? '',
              detail.finalOfficerDecision ?? 'PENDING_HUMAN_REVIEW',
              sv.isSandboxDemo ? 'SOURCE_CHECK_SANDBOX' : 'SOURCE_CHECK_LIVE_OR_MANUAL',
              sv.referenceNumber || '',
              '',
              sv.status,
              '',
              '',
              sv.verificationMethod,
              sv.issuerName,
              sv.status,
              sv.notes || sv.errorReason || '',
              sv.attemptedAt,
            ]
              .map(escapeCsvCell)
              .join(',')
          );
        }

        for (const rev of detail.officerReviews) {
          lines.push(
            [
              detail.applicationNumber,
              detail.institutionName,
              detail.status,
              detail.trustScore ?? '',
              detail.trustScoreVersion ?? '',
              detail.finalOfficerDecision ?? 'PENDING_HUMAN_REVIEW',
              'OFFICER_REVIEW_ACTION',
              rev.actionType,
              '',
              rev.newStatus || '',
              '',
              '',
              rev.officerName || rev.officerId,
              rev.previousStatus || '',
              rev.newStatus || '',
              rev.rationale,
              rev.createdAt,
            ]
              .map(escapeCsvCell)
              .join(',')
          );
        }

        const csvBody = `${lines.join('\r\n')}\r\n`;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="AUTHENTIX_Report_${sanitizeFilename(detail.applicationNumber)}.csv"`
        );
        res.send(csvBody);
        return;
      }

      const baseDisclaimer =
        'ADVISORY SCRUTINY REPORT — Automated rule checks, cryptographic hashes, and trust indicators assist human review only. Automated scores and anomaly indicators never reject an application; final regulatory decisions rest exclusively with authorised reviewing officers.';

      res.json({
        generatedAt: new Date().toISOString(),
        generatedBy: {
          email: user.email,
          role: user.role,
        },
        regulatoryDisclaimer:
          isDemoModeEnabled() && detail.isSyntheticDemo
            ? `${baseDisclaimer} [Development Sample Record]`
            : baseDisclaimer,
        summaryMetrics: {
          submissionCycle: detail.submissionCycle,
          lifecycleStage: detail.lifecycleStage,
          openFindingsCount: detail.openFindingsCount,
          priorCycleFindingsCount: detail.priorCycleFindings.length,
          complianceSatisfiedCount: detail.complianceItems.filter((c) => c.complianceStatus === 'SATISFIED').length,
          complianceUnresolvedCount: detail.complianceItems.filter(
            (c) => c.complianceStatus !== 'SATISFIED' && c.complianceStatus !== 'NOT_APPLICABLE'
          ).length,
          physicalInspectionRequired: detail.physicalInspectionRequired,
        },
        application: detail,
      });
    } catch (err) {
      safeLog('ERROR', 'generate_report_failed', { error: (err as Error).message });
      res.status(500).json({ error: 'Failed to generate validation report.' });
    }
  });

  router.get(
    '/audit-logs',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'SENIOR_AUDITOR', 'ADMIN'),
    (req: AuthenticatedRequest, res: Response) => {
      try {
        const db = ctx.getDb();
        const resourceId = String(req.query.resourceId || '').trim();
        const actionFilter = String(req.query.action || '').trim();
        const limit = Math.min(200, Math.max(1, Number.parseInt(String(req.query.limit || '80'), 10) || 80));

        const conds: string[] = [];
        const params: Array<string | number> = [];
        if (resourceId) {
          conds.push("(resource_id = ? OR json_extract(metadata_json, '$.applicationId') = ?)");
          params.push(resourceId, resourceId);
        }
        if (actionFilter) {
          conds.push('action LIKE ?');
          params.push(`%${actionFilter}%`);
        }

        const whereSql = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
        const rows = db
          .prepare(`SELECT * FROM audit_logs ${whereSql} ORDER BY id DESC LIMIT ?`)
          .all(...params, limit) as Array<Record<string, unknown>>;

        const logs: AuditLogRecord[] = rows.map((r) => ({
          id: Number(r.id),
          eventId: String(r.event_id),
          timestamp: String(r.timestamp),
          actorUserId: r.actor_user_id ? String(r.actor_user_id) : null,
          actorEmail: r.actor_email ? String(r.actor_email) : null,
          actorRole: r.actor_role ? String(r.actor_role) : null,
          action: String(r.action),
          resourceType: String(r.resource_type),
          resourceId: String(r.resource_id),
          metadata: parseJsonSafe(String(r.metadata_json), {}),
          prevHash: String(r.prev_hash),
          entryHash: String(r.entry_hash),
        }));

        const chainStatus = verifyAuditChain(db);

        res.json({
          logs,
          chainVerification: chainStatus,
        });
      } catch {
        res.status(500).json({ error: 'Failed to retrieve audit history.' });
      }
    }
  );

  router.get(
    '/audit-logs/verify',
    requireAuth,
    requireRoles('REVIEW_OFFICER', 'SENIOR_AUDITOR', 'ADMIN'),
    (_req: AuthenticatedRequest, res: Response) => {
      try {
        const result = verifyAuditChain(ctx.getDb());
        res.json(result);
      } catch {
        res.status(500).json({ error: 'Failed to verify cryptographic audit chain.' });
      }
    }
  );

  router.post(
    '/admin/reset-demo',
    requireAuth,
    requireRoles('ADMIN'),
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!isDemoModeEnabled()) {
          res.status(403).json({ error: 'Sample dataset reset is disabled when development demo mode is off.' });
          return;
        }
        const db = ctx.getDb();
        const summary = await seedDatabase(db, {
          forceReset: true,
          uploadDir: ctx.uploadDir,
          sampleDocsDir: ctx.sampleDocsDir,
        });
        appendAuditEvent(db, {
          actorUserId: req.authUser!.id,
          actorEmail: req.authUser!.email,
          actorRole: req.authUser!.role,
          action: 'DEMO_ENVIRONMENT_RESET',
          resourceType: 'SYSTEM',
          resourceId: 'AUTHENTIX-DEMO',
          metadata: { applicationsSeeded: summary.applicationsCount },
        });
        res.json({ reset: true, summary });
      } catch (err) {
        safeLog('ERROR', 'reset_demo_failed', { error: (err as Error).message });
        res.status(500).json({ error: 'Failed to reset demo environment.' });
      }
    }
  );

  return router;
}

function mapFindingRow(f: Record<string, unknown>): ValidationFindingRecord {
  return {
    id: String(f.id),
    findingCode: String(f.finding_code),
    applicationId: String(f.application_id),
    documentId: f.document_id ? String(f.document_id) : null,
    documentFilename: f.doc_filename ? String(f.doc_filename) : null,
    fieldName: f.field_name ? String(f.field_name) : null,
    pageRegion: f.page_region ? String(f.page_region) : null,
    ruleCode: String(f.rule_code),
    ruleVersion: String(f.rule_version),
    authoritySource: f.authority_source as ValidationFindingRecord['authoritySource'],
    findingCategory: f.finding_category as ValidationFindingRecord['findingCategory'],
    epistemicClassification:
      (f.epistemic_classification as EpistemicClassification) || 'ORDINARY_INCONSISTENCY',
    detectorConfidence:
      f.detector_confidence !== null && f.detector_confidence !== undefined
        ? Number(f.detector_confidence)
        : null,
    limitationsNote: f.limitations_note ? String(f.limitations_note) : null,
    recommendedFollowUp: f.recommended_follow_up ? String(f.recommended_follow_up) : null,
    submissionCycle: Number(f.submission_cycle || 1),
    archivedFromPriorCycle: Boolean(f.archived_from_prior_cycle),
    severity: f.severity as ValidationFindingRecord['severity'],
    expectedValue: f.expected_value !== null && f.expected_value !== undefined ? String(f.expected_value) : null,
    observedValue: f.observed_value !== null && f.observed_value !== undefined ? String(f.observed_value) : null,
    explanation: String(f.explanation),
    evidence: parseJsonSafe(String(f.evidence_json), {}),
    requiresHumanReview: Boolean(f.requires_human_review),
    resolvedByOfficer: Boolean(f.resolved_by_officer),
    resolutionNote: f.resolution_note ? String(f.resolution_note) : null,
    resolvedBy: f.resolved_by ? String(f.resolved_by) : null,
    resolvedAt: f.resolved_at ? String(f.resolved_at) : null,
    createdAt: String(f.created_at),
  };
}

export function loadApplicationDetail(db: DatabaseSync, applicationId: string): ApplicationDetail | null {
  ensureDefaultCategoriesAndCompliance(db);

  const row = db
    .prepare(
      `SELECT a.*,
              i.id AS i_id, i.code AS i_code, i.name AS i_name, i.state AS i_state,
              i.district AS i_district, i.institution_type AS i_type, i.established_year AS i_year,
              i.approved_intake AS i_intake, i.land_area_acres AS i_land,
              i.built_up_area_sqm AS i_built, i.principal_name AS i_principal,
              i.aicte_permanent_id AS i_pid, i.is_synthetic_demo AS i_demo
       FROM applications a
       JOIN institutions i ON i.id = a.institution_id
       WHERE a.id = ?`
    )
    .get(applicationId) as Record<string, unknown> | undefined;

  if (!row) return null;

  const docRows = db
    .prepare('SELECT * FROM documents WHERE application_id = ? ORDER BY created_at ASC')
    .all(applicationId) as Array<Record<string, unknown>>;

  const documents: DocumentRecord[] = docRows.map((d) => {
    const fRows = db
      .prepare('SELECT * FROM extracted_fields WHERE document_id = ? ORDER BY field_name ASC')
      .all(String(d.id)) as Array<Record<string, unknown>>;

    const extractedFields: ExtractedFieldRecord[] = fRows.map((f) => ({
      id: String(f.id),
      documentId: String(f.document_id),
      fieldName: String(f.field_name),
      fieldValue: String(f.field_value),
      confidence: Number(f.confidence),
      pageNumber: Number(f.page_number),
      bbox: parseJsonSafe<[number, number, number, number] | null>(
        f.bbox_json ? String(f.bbox_json) : null,
        null
      ),
      extractionMethod: String(f.extraction_method),
      manuallyCorrected: Boolean(f.manually_corrected),
      correctedBy: f.corrected_by ? String(f.corrected_by) : null,
      correctedAt: f.corrected_at ? String(f.corrected_at) : null,
      correctionNote: f.correction_note ? String(f.correction_note) : null,
    }));

    return {
      id: String(d.id),
      applicationId: String(d.application_id),
      declaredDocType: d.declared_doc_type as DocumentType,
      detectedDocType: d.detected_doc_type as DocumentType,
      classificationConfidence:
        d.classification_confidence !== null && d.classification_confidence !== undefined
          ? Number(d.classification_confidence)
          : null,
      originalFilename: String(d.original_filename),
      storedFilename: String(d.stored_filename),
      mimeType: String(d.mime_type),
      fileSizeBytes: Number(d.file_size_bytes),
      sha256Hash: String(d.sha256_hash),
      pageCount: Number(d.page_count),
      ocrStatus: d.ocr_status as DocumentRecord['ocrStatus'],
      ocrEngine: String(d.ocr_engine),
      ocrConfidence: d.ocr_confidence !== null && d.ocr_confidence !== undefined ? Number(d.ocr_confidence) : null,
      reprocessCount: Number(d.reprocess_count || 0),
      lastErrorReason: d.last_error_reason ? String(d.last_error_reason) : null,
      extractedText: String(d.extracted_text),
      extractedPages: parseJsonSafe(String(d.extracted_pages_json), []),
      metadata: parseJsonSafe(String(d.metadata_json), {}),
      verificationStatus: d.verification_status as VerificationStatus,
      processedAt: d.processed_at ? String(d.processed_at) : null,
      uploadedBy: d.uploaded_by ? String(d.uploaded_by) : null,
      createdAt: String(d.created_at),
      updatedAt: String(d.updated_at),
      extractedFields,
    };
  });

  const allFindingRows = db
    .prepare(
      `SELECT vf.*, d.original_filename AS doc_filename
       FROM validation_findings vf
       LEFT JOIN documents d ON d.id = vf.document_id
       WHERE vf.application_id = ?
       ORDER BY vf.resolved_by_officer ASC,
         CASE vf.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END ASC,
         vf.finding_code ASC`
    )
    .all(applicationId) as Array<Record<string, unknown>>;

  const mappedFindings = allFindingRows.map(mapFindingRow);
  const findings = mappedFindings.filter((f) => !f.archivedFromPriorCycle);
  const priorCycleFindings = mappedFindings.filter((f) => f.archivedFromPriorCycle);

  const compRows = db
    .prepare(
      `SELECT aci.*,
              cr.requirement_code, cr.domain, cr.title, cr.description,
              cr.accepted_doc_types_json, cr.is_mandatory, cr.is_illustrative,
              d.original_filename AS linked_doc_filename,
              u.full_name AS reviewed_by_name
       FROM application_compliance_items aci
       JOIN compliance_requirements cr ON cr.id = aci.requirement_id
       LEFT JOIN documents d ON d.id = aci.linked_document_id
       LEFT JOIN users u ON u.id = aci.reviewed_by
       WHERE aci.application_id = ?
       ORDER BY cr.id ASC`
    )
    .all(applicationId) as Array<Record<string, unknown>>;

  const complianceItems: ApplicationComplianceItemRecord[] = compRows.map((c) => ({
    id: String(c.id),
    applicationId: String(c.application_id),
    requirementId: String(c.requirement_id),
    requirementCode: String(c.requirement_code),
    domain: c.domain as ComplianceDomain,
    title: String(c.title),
    description: String(c.description),
    acceptedDocTypes: parseJsonSafe<DocumentType[]>(String(c.accepted_doc_types_json), []),
    isMandatory: Boolean(c.is_mandatory),
    isIllustrative: Boolean(c.is_illustrative),
    linkedDocumentId: c.linked_document_id ? String(c.linked_document_id) : null,
    linkedDocumentFilename: c.linked_doc_filename ? String(c.linked_doc_filename) : null,
    complianceStatus: c.compliance_status as ComplianceItemStatus,
    autoEvaluatedNote: c.auto_evaluated_note ? String(c.auto_evaluated_note) : null,
    visualInspection: parseJsonSafe<VisualEvidenceSummary>(String(c.visual_inspection_json), {}),
    officerObservation: c.officer_observation ? String(c.officer_observation) : null,
    additionalEvidenceRequested: Boolean(c.additional_evidence_requested),
    additionalEvidenceNote: c.additional_evidence_note ? String(c.additional_evidence_note) : null,
    physicalInspectionFlagged: Boolean(c.physical_inspection_flagged),
    reviewedBy: c.reviewed_by ? String(c.reviewed_by) : null,
    reviewedByName: c.reviewed_by_name ? String(c.reviewed_by_name) : null,
    reviewedAt: c.reviewed_at ? String(c.reviewed_at) : null,
    updatedAt: String(c.updated_at),
  }));

  const svRows = db
    .prepare(
      `SELECT sv.*, u.full_name AS verified_by_name
       FROM source_verifications sv
       LEFT JOIN users u ON u.id = sv.verified_by
       WHERE sv.application_id = ?
       ORDER BY sv.attempted_at DESC`
    )
    .all(applicationId) as Array<Record<string, unknown>>;

  const sourceVerifications: SourceVerificationRecord[] = svRows.map((sv) => ({
    id: String(sv.id),
    applicationId: String(sv.application_id),
    documentId: sv.document_id ? String(sv.document_id) : null,
    verificationMethod: sv.verification_method as VerificationMethod,
    issuerName: String(sv.issuer_name),
    referenceNumber: sv.reference_number ? String(sv.reference_number) : null,
    isSandboxDemo: Boolean(sv.is_sandbox_demo),
    status: sv.status as VerificationStatus,
    sourceResponse: parseJsonSafe(String(sv.source_response_json), {}),
    errorReason: sv.error_reason ? String(sv.error_reason) : null,
    verifiedBy: sv.verified_by ? String(sv.verified_by) : null,
    verifiedByName: sv.verified_by_name ? String(sv.verified_by_name) : null,
    notes: sv.notes ? String(sv.notes) : null,
    attemptedAt: String(sv.attempted_at),
  }));

  const revRows = db
    .prepare(
      `SELECT r.*, u.full_name AS officer_name, u.role AS officer_role
       FROM officer_reviews r
       JOIN users u ON u.id = r.officer_id
       WHERE r.application_id = ?
       ORDER BY r.created_at DESC`
    )
    .all(applicationId) as Array<Record<string, unknown>>;

  const officerReviews: OfficerReviewRecord[] = revRows.map((r) => ({
    id: String(r.id),
    applicationId: String(r.application_id),
    documentId: r.document_id ? String(r.document_id) : null,
    officerId: String(r.officer_id),
    officerName: r.officer_name ? String(r.officer_name) : undefined,
    officerRole: r.officer_role ? String(r.officer_role) : undefined,
    actionType: r.action_type as OfficerActionType,
    previousStatus: r.previous_status ? String(r.previous_status) : null,
    newStatus: r.new_status ? String(r.new_status) : null,
    rationale: String(r.rationale),
    evidenceReference: r.evidence_reference ? String(r.evidence_reference) : null,
    createdAt: String(r.created_at),
  }));

  const openFindingsCount = findings.filter((f) => !f.resolvedByOfficer).length;
  const criticalFindingsCount = findings.filter(
    (f) => !f.resolvedByOfficer && (f.severity === 'CRITICAL' || f.severity === 'HIGH')
  ).length;
  const verifiedDocsCount = documents.filter((d) => d.verificationStatus === 'VERIFIED').length;

  const institution: InstitutionRecord = {
    id: String(row.i_id),
    code: String(row.i_code),
    name: String(row.i_name),
    state: String(row.i_state),
    district: String(row.i_district),
    institutionType: String(row.i_type),
    establishedYear: Number(row.i_year),
    approvedIntake: Number(row.i_intake),
    landAreaAcres: Number(row.i_land),
    builtUpAreaSqm: Number(row.i_built),
    principalName: String(row.i_principal),
    aictePermanentId: String(row.i_pid),
    isSyntheticDemo: Boolean(row.i_demo),
  };

  const baseCategory = row.category as ApplicationCategory;
  const categoryCode = row.category_code ? String(row.category_code) : baseCategory;
  const requiredChecklistDocTypes = resolveRequiredChecklistForApplication(db, baseCategory, categoryCode);

  return {
    id: String(row.id),
    applicationNumber: String(row.application_number),
    institutionId: institution.id,
    institutionName: institution.name,
    institutionCode: institution.code,
    institutionState: institution.state,
    academicYear: String(row.academic_year),
    category: baseCategory,
    categoryCode,
    programNames: String(row.program_names),
    requestedIntake: Number(row.requested_intake),
    submittedLandAcres: Number(row.submitted_land_acres),
    submittedBuiltUpSqm: Number(row.submitted_built_up_sqm),
    submittedPrincipalName: String(row.submitted_principal_name),
    status: row.status as ApplicationDetail['status'],
    lifecycleStage: (row.lifecycle_stage as LifecycleStage) || 'pending',
    nextRecommendedAction: row.next_recommended_action ? String(row.next_recommended_action) : null,
    submissionCycle: Number(row.submission_cycle || 1),
    resubmittedAt: row.resubmitted_at ? String(row.resubmitted_at) : null,
    resubmissionSummary: row.resubmission_summary ? String(row.resubmission_summary) : null,
    physicalInspectionRequired: Boolean(row.physical_inspection_required),
    physicalInspectionReason: row.physical_inspection_reason ? String(row.physical_inspection_reason) : null,
    reviewPriority: row.review_priority as ApplicationDetail['reviewPriority'],
    trustScore: row.trust_score !== null && row.trust_score !== undefined ? Number(row.trust_score) : null,
    trustScoreVersion: row.trust_score_version ? String(row.trust_score_version) : null,
    trustScoreBreakdown: parseJsonSafe<TrustScoreBreakdown | null>(
      row.trust_score_breakdown_json ? String(row.trust_score_breakdown_json) : null,
      null
    ),
    requiredChecklistDocTypes,
    automatedSummary: row.automated_summary ? String(row.automated_summary) : null,
    finalOfficerDecision: (row.final_officer_decision as ApplicationDetail['finalOfficerDecision']) || null,
    finalDecisionRationale: row.final_decision_rationale ? String(row.final_decision_rationale) : null,
    finalDecisionAt: row.final_decision_at ? String(row.final_decision_at) : null,
    isSyntheticDemo: Boolean(row.is_synthetic_demo),
    documentCount: documents.length,
    openFindingsCount,
    criticalFindingsCount,
    verifiedDocsCount,
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    institution,
    documents,
    findings,
    priorCycleFindings,
    complianceItems,
    sourceVerifications,
    officerReviews,
  };
}
