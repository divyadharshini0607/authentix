/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Security Primitives: Scrypt Password Hashing, Token Digest, File Signature Checks,
 * Filename Sanitization, Sensitive Log Redaction, and Sliding-Window Rate Limiting.
 */

import crypto from 'node:crypto';
import path from 'node:path';
import type { Request, Response, NextFunction } from 'express';

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;

/**
 * Generates a self-describing scrypt password hash:
 * Format: scrypt$16384$8$1$<saltHex>$<derivedKeyHex>
 */
export function hashPassword(plainPassword: string): string {
  if (!plainPassword || plainPassword.length < 8) {
    throw new Error('Password must be at least 8 characters long.');
  }
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(plainPassword, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('hex')}$${derivedKey.toString('hex')}`;
}

/**
 * Verifies a plaintext password against a stored scrypt$N$r$p$salt$hash record
 * using constant-time comparison (crypto.timingSafeEqual).
 */
export function verifyPassword(plainPassword: string, storedHash: string): boolean {
  try {
    if (!plainPassword || !storedHash) return false;
    const parts = storedHash.split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') {
      return false;
    }
    const N = Number.parseInt(parts[1], 10);
    const r = Number.parseInt(parts[2], 10);
    const p = Number.parseInt(parts[3], 10);
    const salt = Buffer.from(parts[4], 'hex');
    const expectedKey = Buffer.from(parts[5], 'hex');
    if (!N || !r || !p || salt.length < 8 || expectedKey.length < 32) {
      return false;
    }
    const candidateKey = crypto.scryptSync(plainPassword, salt, expectedKey.length, { N, r, p });
    return crypto.timingSafeEqual(candidateKey, expectedKey);
  } catch {
    return false;
  }
}

export function generateOpaqueToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export function sha256Hex(input: Buffer | string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export class QrSigningSecretUnavailableError extends Error {
  constructor(message = 'Strong QR_SIGNING_SECRET (>= 32 characters) is required in production.') {
    super(message);
    this.name = 'QrSigningSecretUnavailableError';
  }
}

const WEAK_SECRET_LITERALS = new Set([
  '',
  'authentix-demo-qr-hmac-key-sih26261',
  'authentix-demo-qr-hmac-secret',
  'change-me-in-env-for-shared-deployments',
  'replace-with-32-byte-random-hex-secret-in-production',
  'replace-with-demo-qr-hmac-secret-in-production',
  'changeme',
  'placeholder',
  'secret',
]);

let ephemeralDevQrSecret: string | null = null;

function stripEnvQuotes(raw: string | undefined): string {
  if (!raw) return '';
  const trimmed = raw.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

export function isStrongConfiguredSecret(raw: string | undefined): boolean {
  const val = stripEnvQuotes(raw);
  if (val.length < 32) return false;
  const lower = val.toLowerCase();
  if (
    WEAK_SECRET_LITERALS.has(lower) ||
    lower.startsWith('replace-with-') ||
    lower.startsWith('change-me-') ||
    lower.includes('placeholder')
  ) {
    return false;
  }
  return true;
}

export function isQrSigningSecretConfigured(): boolean {
  if (stripEnvQuotes(process.env.NODE_ENV) === 'production') {
    return isStrongConfiguredSecret(process.env.QR_SIGNING_SECRET);
  }
  return true;
}

function resolveQrSigningSecret(): string {
  const configured = stripEnvQuotes(process.env.QR_SIGNING_SECRET);
  const isProd = stripEnvQuotes(process.env.NODE_ENV) === 'production';

  if (isStrongConfiguredSecret(configured)) {
    return configured;
  }

  if (isProd) {
    throw new QrSigningSecretUnavailableError(
      'QR cryptographic verification is unavailable because a strong QR_SIGNING_SECRET (>= 32 characters) is not configured in production.'
    );
  }

  // Non-production only: generate or load a local gitignored CSPRNG key so no hardcoded secret exists in source code
  if (!ephemeralDevQrSecret) {
    ephemeralDevQrSecret = crypto.randomBytes(32).toString('hex');
  }
  return ephemeralDevQrSecret;
}

export function assertSafeProductionSecrets(): {
  sessionSecretStrong: boolean;
  qrSigningSecretConfigured: boolean;
} {
  const isProd = stripEnvQuotes(process.env.NODE_ENV) === 'production';
  const rawSessionSecret = stripEnvQuotes(process.env.SESSION_SECRET);
  const sessionSecretStrong = isStrongConfiguredSecret(rawSessionSecret);
  const qrSigningSecretConfigured = isStrongConfiguredSecret(process.env.QR_SIGNING_SECRET);

  if (isProd) {
    if (rawSessionSecret && !sessionSecretStrong) {
      throw new Error(
        'Insecure SESSION_SECRET rejected in production. Configure a random secret of at least 32 characters.'
      );
    }
    const rawQrSecret = stripEnvQuotes(process.env.QR_SIGNING_SECRET);
    if (rawQrSecret && !qrSigningSecretConfigured) {
      throw new Error(
        'Weak or placeholder QR_SIGNING_SECRET rejected in production. Configure a random secret of at least 32 characters.'
      );
    }
  }

  return { sessionSecretStrong, qrSigningSecretConfigured };
}

export function signQrPayload(payload: string): string {
  const secret = resolveQrSigningSecret();
  return crypto.createHmac('sha256', secret).update(payload).digest('hex').slice(0, 24);
}

export function verifyQrSignature(payload: string, signature: string): boolean {
  const expected = signQrPayload(payload);
  if (expected.length !== signature.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(signature, 'utf8'));
}

/**
 * Prevents path traversal, null bytes, control chars, and double-extension tricks.
 */
export function sanitizeFilename(rawFilename: string): string {
  const base = path.basename(rawFilename || 'document');
  const cleaned = base
    .replace(/[\x00-\x1f\x80-\x9f]/g, '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/\.{2,}/g, '.')
    .replace(/^_+/, '');
  return cleaned.slice(0, 120) || 'uploaded_document.pdf';
}

export interface FileValidationResult {
  valid: boolean;
  detectedMime?: 'application/pdf' | 'image/png' | 'image/jpeg';
  error?: string;
}

/**
 * Inspects magic bytes and structural integrity of uploaded document buffers
 * so renamed executables or corrupted empty files are rejected immediately.
 */
export function validateUploadedFileBuffer(
  buffer: Buffer,
  originalFilename: string,
  declaredMimeType: string,
  maxBytes: number
): FileValidationResult {
  if (!buffer || buffer.length === 0) {
    return { valid: false, error: 'Uploaded file is empty (0 bytes).' };
  }
  if (buffer.length > maxBytes) {
    return {
      valid: false,
      error: `File size (${(buffer.length / (1024 * 1024)).toFixed(2)} MB) exceeds maximum allowed limit (${(
        maxBytes /
        (1024 * 1024)
      ).toFixed(0)} MB).`,
    };
  }
  if (rawHasTraversal(originalFilename)) {
    return { valid: false, error: 'Unsafe filename containing path traversal sequence rejected.' };
  }

  const ext = path.extname(originalFilename || '').toLowerCase();
  const allowedExts = new Set(['.pdf', '.png', '.jpg', '.jpeg']);
  if (!allowedExts.has(ext)) {
    return {
      valid: false,
      error: `Unsupported file extension '${ext || 'none'}'. Allowed formats: PDF (.pdf), PNG (.png), JPEG (.jpg, .jpeg).`,
    };
  }

  // Magic byte verification
  const isPdf = buffer.length >= 5 && buffer.subarray(0, 5).toString('ascii') === '%PDF-';
  const isPng =
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a;
  const isJpeg = buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;

  if (ext === '.pdf') {
    if (!isPdf) {
      return { valid: false, error: 'File has .pdf extension but lacks valid %PDF- magic header.' };
    }
    return { valid: true, detectedMime: 'application/pdf' };
  }
  if (ext === '.png') {
    if (!isPng) {
      return { valid: false, error: 'File has .png extension but lacks valid PNG signature.' };
    }
    return { valid: true, detectedMime: 'image/png' };
  }
  if (ext === '.jpg' || ext === '.jpeg') {
    if (!isJpeg) {
      return { valid: false, error: 'File has JPEG extension but lacks valid JPEG SOI signature.' };
    }
    return { valid: true, detectedMime: 'image/jpeg' };
  }

  return { valid: false, error: `Unsupported MIME type '${declaredMimeType}'.` };
}

function rawHasTraversal(name: string): boolean {
  if (!name) return false;
  return name.includes('..') || name.includes('/') || name.includes('\\') || name.includes('\0');
}

const REDACTED_KEYS = new Set([
  'password',
  'passphrase',
  'demopassphrase',
  'passwordhash',
  'password_hash',
  'postgres_password',
  'token',
  'sessiontoken',
  'authorization',
  'cookie',
  'secret',
  'content_base64',
  'extractedtext',
  'extracted_text',
]);

export function redactSensitiveData(input: unknown): unknown {
  if (input === null || input === undefined) return input;
  if (Array.isArray(input)) {
    return input.map((item) => redactSensitiveData(item));
  }
  if (typeof input === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(input as Record<string, unknown>)) {
      const lower = key.toLowerCase();
      if (
        REDACTED_KEYS.has(lower) ||
        lower.includes('password') ||
        lower.includes('passphrase') ||
        lower.includes('secret')
      ) {
        out[key] = '[REDACTED]';
      } else {
        out[key] = redactSensitiveData(val);
      }
    }
    return out;
  }
  return input;
}

export function safeLog(level: 'INFO' | 'WARN' | 'ERROR', event: string, meta?: Record<string, unknown>): void {
  if (process.env.NODE_ENV === 'test' && level === 'INFO') return;
  const payload = {
    ts: new Date().toISOString(),
    level,
    event,
    ...(meta ? { meta: redactSensitiveData(meta) } : {}),
  };
  const line = JSON.stringify(payload);
  if (level === 'ERROR') {
    console.error(line);
  } else {
    console.log(line);
  }
}

/**
 * Lightweight sliding-window rate limiter middleware for sensitive routes.
 */
export function createRateLimiter(options: { windowMs: number; maxRequests: number; label: string }) {
  const hits = new Map<string, number[]>();

  return (req: Request, res: Response, next: NextFunction) => {
    if (process.env.DISABLE_RATE_LIMIT === 'true') {
      return next();
    }
    const key = `${options.label}:${req.ip || req.socket.remoteAddress || 'local'}`;
    const now = Date.now();
    const cutoff = now - options.windowMs;
    const prev = (hits.get(key) || []).filter((ts) => ts > cutoff);
    if (prev.length >= options.maxRequests) {
      res.status(429).json({
        error: `Too many requests (${options.label}). Please wait before retrying.`,
      });
      return;
    }
    prev.push(now);
    hits.set(key, prev);
    next();
  };
}
