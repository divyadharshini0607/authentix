/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Append-Only Hash-Chained Audit Trail
 *
 * Threat Model & Limitations (Documented Honestly):
 * - Every audit event computes:
 *   entry_hash = SHA-256(prev_hash | event_id | timestamp | actor_user_id | action | resource_type | resource_id | canonical_metadata_json)
 * - Unauthorised in-place modification, insertion, reordering, or deletion of intermediate rows
 *   breaks the cryptographic hash linkage and is immediately detected by `verifyAuditChain()`.
 * - Limitation: A privileged OS/DBA attacker with write access to the raw SQLite/PostgreSQL file could
 *   recompute the entire suffix chain unless root hashes are anchored to an external WORM store.
 */

import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { sha256Hex } from './security.ts';
import type { AuditLogRecord } from '../shared/types.ts';

export const GENESIS_PREV_HASH = '0'.repeat(64);

export function canonicalizeJson(obj: Record<string, unknown>): string {
  const sortValue = (val: unknown): unknown => {
    if (Array.isArray(val)) return val.map(sortValue);
    if (val !== null && typeof val === 'object') {
      const sortedKeys = Object.keys(val as Record<string, unknown>).sort();
      const res: Record<string, unknown> = {};
      for (const k of sortedKeys) {
        res[k] = sortValue((val as Record<string, unknown>)[k]);
      }
      return res;
    }
    return val;
  };
  return JSON.stringify(sortValue(obj || {}));
}

export function computeAuditEntryHash(params: {
  prevHash: string;
  eventId: string;
  timestamp: string;
  actorUserId: string | null;
  action: string;
  resourceType: string;
  resourceId: string;
  canonicalMetadata: string;
}): string {
  const preimage = [
    params.prevHash,
    params.eventId,
    params.timestamp,
    params.actorUserId ?? 'SYSTEM',
    params.action,
    params.resourceType,
    params.resourceId,
    params.canonicalMetadata,
  ].join('|');
  return sha256Hex(preimage);
}

export interface AppendAuditParams {
  actorUserId?: string | null;
  actorEmail?: string | null;
  actorRole?: string | null;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata?: Record<string, unknown>;
  timestamp?: string;
}

export function appendAuditEvent(db: DatabaseSync, params: AppendAuditParams): AuditLogRecord {
  const lastRow = db
    .prepare('SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1')
    .get() as { entry_hash: string } | undefined;

  const prevHash = lastRow ? lastRow.entry_hash : GENESIS_PREV_HASH;
  const eventId = `AUD-${crypto.randomUUID()}`;
  const timestamp = params.timestamp || new Date().toISOString();
  const canonicalMetadata = canonicalizeJson(params.metadata || {});
  const actorUserId = params.actorUserId ?? null;

  const entryHash = computeAuditEntryHash({
    prevHash,
    eventId,
    timestamp,
    actorUserId,
    action: params.action,
    resourceType: params.resourceType,
    resourceId: params.resourceId,
    canonicalMetadata,
  });

  const result = db
    .prepare(
      `INSERT INTO audit_logs (
        event_id, timestamp, actor_user_id, actor_email, actor_role,
        action, resource_type, resource_id, metadata_json, prev_hash, entry_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      eventId,
      timestamp,
      actorUserId,
      params.actorEmail ?? null,
      params.actorRole ?? null,
      params.action,
      params.resourceType,
      params.resourceId,
      canonicalMetadata,
      prevHash,
      entryHash
    );

  return {
    id: Number(result.lastInsertRowid),
    eventId,
    timestamp,
    actorUserId,
    actorEmail: params.actorEmail ?? null,
    actorRole: params.actorRole ?? null,
    action: params.action,
    resourceType: params.resourceType,
    resourceId: params.resourceId,
    metadata: JSON.parse(canonicalMetadata) as Record<string, unknown>,
    prevHash,
    entryHash,
  };
}

export interface AuditChainVerificationResult {
  valid: boolean;
  totalEventsChecked: number;
  headHash: string;
  brokenAtEventId?: string;
  brokenAtId?: number;
  reason?: string;
  verifiedAt: string;
}

export function verifyAuditChain(db: DatabaseSync): AuditChainVerificationResult {
  const rows = db
    .prepare(
      `SELECT id, event_id, timestamp, actor_user_id, action, resource_type, resource_id, metadata_json, prev_hash, entry_hash
       FROM audit_logs ORDER BY id ASC`
    )
    .all() as Array<{
    id: number;
    event_id: string;
    timestamp: string;
    actor_user_id: string | null;
    action: string;
    resource_type: string;
    resource_id: string;
    metadata_json: string;
    prev_hash: string;
    entry_hash: string;
  }>;

  let expectedPrev = GENESIS_PREV_HASH;
  for (const row of rows) {
    if (row.prev_hash !== expectedPrev) {
      return {
        valid: false,
        totalEventsChecked: rows.length,
        headHash: row.entry_hash,
        brokenAtEventId: row.event_id,
        brokenAtId: row.id,
        reason: `Chain linkage mismatch at event ${row.event_id}: expected prev_hash ${expectedPrev.slice(0, 12)}..., found ${row.prev_hash.slice(0, 12)}...`,
        verifiedAt: new Date().toISOString(),
      };
    }

    let canonicalMetadata = row.metadata_json;
    try {
      canonicalMetadata = canonicalizeJson(JSON.parse(row.metadata_json) as Record<string, unknown>);
    } catch {
      return {
        valid: false,
        totalEventsChecked: rows.length,
        headHash: row.entry_hash,
        brokenAtEventId: row.event_id,
        brokenAtId: row.id,
        reason: `Invalid metadata JSON in audit event ${row.event_id}.`,
        verifiedAt: new Date().toISOString(),
      };
    }

    const recomputed = computeAuditEntryHash({
      prevHash: row.prev_hash,
      eventId: row.event_id,
      timestamp: row.timestamp,
      actorUserId: row.actor_user_id,
      action: row.action,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      canonicalMetadata,
    });

    if (recomputed !== row.entry_hash) {
      return {
        valid: false,
        totalEventsChecked: rows.length,
        headHash: row.entry_hash,
        brokenAtEventId: row.event_id,
        brokenAtId: row.id,
        reason: `Entry hash mismatch at event ${row.event_id}: stored hash does not match canonical payload digest.`,
        verifiedAt: new Date().toISOString(),
      };
    }

    expectedPrev = row.entry_hash;
  }

  return {
    valid: true,
    totalEventsChecked: rows.length,
    headHash: expectedPrev,
    verifiedAt: new Date().toISOString(),
  };
}
