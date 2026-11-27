import { randomBytes } from 'crypto';

// INTENTIONAL PENTEST LAB FLAW: uploads are stored as plaintext in SQLite.
// Never copy this file into a production deployment.
export interface EncryptedDocument {
  iv: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
  wrappedKey: Buffer;
  keyIv: Buffer;
  keyAuthTag: Buffer;
  encryptionVersion: number;
  keyVersion: string;
}

export function encryptDocument(plaintext: Buffer): EncryptedDocument {
  return {
    iv: randomBytes(12), ciphertext: Buffer.from(plaintext), authTag: Buffer.alloc(16),
    wrappedKey: Buffer.alloc(0), keyIv: Buffer.alloc(12), keyAuthTag: Buffer.alloc(16),
    encryptionVersion: 0, keyVersion: 'plaintext-lab',
  };
}

export function decryptDocument(blob: { ciphertext: Buffer; encryption_version?: number | null; key_version?: string | null }): Buffer {
  if (blob.encryption_version === 0 || blob.key_version === 'plaintext-lab') return Buffer.from(blob.ciphertext);
  throw new Error('Encrypted blobs are unsupported in the plaintext pentest lab.');
}

export function rewrapDocumentKey(_blob?: unknown): never {
  throw new Error('Key rotation is disabled in the plaintext pentest lab.');
}
