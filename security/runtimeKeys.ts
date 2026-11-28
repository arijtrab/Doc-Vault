import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * Reads a secret supplied at runtime, never from the image or the code.
 * Preferred: NAME_FILE points to a mounted file (Compose secret, Kubernetes Secret volume).
 * Fallback: NAME as an environment variable (visible in `docker inspect`, so avoid in production).
 * The value is never logged.
 */
export function readSecret(name: string): string | undefined {
  const file = process.env[`${name}_FILE`];
  if (file) {
    const value = readFileSync(file, 'utf8').trim();
    if (!value) throw new Error(`${name}_FILE points to an empty file.`);
    return value;
  }
  const value = process.env[name]?.trim();
  return value || undefined;
}

export interface MasterKey {
  key: Buffer;
  version: string;
  /** First 8 hex characters of SHA-256(key): lets operators confirm a rotation without revealing the key. */
  fingerprint: string;
}

/** Loads the active AES-256 master key; the server refuses to start without a valid key. */
export function loadMasterKey(): MasterKey {
  const hex = readSecret('DOCVAULT_MASTER_KEY');
  if (!hex || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('DOCVAULT_MASTER_KEY_FILE (or DOCVAULT_MASTER_KEY) must provide 64 hexadecimal characters.');
  }
  const key = Buffer.from(hex, 'hex');
  const version = process.env.DOCVAULT_MASTER_KEY_VERSION || 'v1';
  const fingerprint = createHash('sha256').update(key).digest('hex').slice(0, 8);
  return { key, version, fingerprint };
}
