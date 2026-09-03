import { createHash } from 'node:crypto';
import { toBase64, toBase64Url, utf8 } from './encoding.js';

function bytes(data: string | Uint8Array): Uint8Array {
  return typeof data === 'string' ? utf8(data) : data;
}

/** SHA-256 digest bytes. */
export function sha256(data: string | Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes(data)).digest());
}

/** Lowercase hex SHA-256. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(bytes(data)).digest('hex');
}

/** Subresource-Integrity string `sha256-<standard base64>` (spec v0.2-new §5.3 / D-e/N5). */
export function computeSRI(content: string | Uint8Array): string {
  return `sha256-${toBase64(sha256(content))}`;
}

/** Verify `content` against an SRI string. */
export function verifySRI(content: string | Uint8Array, sri: string): boolean {
  return computeSRI(content) === sri;
}

/**
 * The `ActionVersion.digestSRI` pin — `sha256-<base64url>` over plain `JSON.stringify`.
 *
 * **Deliberately not {@link computeSRI}, and deliberately not canonicalized.** This is a
 * different value, on a different algorithm, serving a different purpose: it is the
 * byte-stable identity the action API has published on every ActionVersion since before
 * the spec's `digestSRI` existed. Re-pinning published versions with the canonical form
 * would change a value consumers hold.
 *
 * The stored content round-trips through MongoDB with field order intact, so
 * `JSON.stringify` here reproduces the publish-time string. Nothing else may use this —
 * the spec's evidence and action-reference digests are {@link computeSRI}.
 */
export function actionVersionPinSRI(content: unknown): string {
  return `sha256-${toBase64Url(sha256(JSON.stringify(content)))}`;
}
