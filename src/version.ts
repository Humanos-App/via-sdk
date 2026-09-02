/**
 * Spec-version identity and detection.
 *
 * VIA has four independent version axes (see `spec/VERSIONING.md`):
 *  - **package** semver (`package.json`) — the SDK release;
 *  - **spec version** ({@link VIA_SPEC_VERSION}) — the data model, carried on every
 *    artifact as the signed `specVersion` marker;
 *  - **JSON-LD context version** ({@link VIA_CONTEXT_VERSION}) — the term definitions.
 *
 * This module owns the spec-version axis: what the SDK supports, and how to read
 * the marker off an artifact so a verifier can route deterministically instead of
 * guessing from the signature.
 */
import {
  SUPPORTED_SPEC_VERSIONS,
  type SpecVersion,
  type ViaMandateCredential,
  type VerifiablePresentation,
} from "./types.js";

export {
  VIA_SPEC_VERSION,
  SUPPORTED_SPEC_VERSIONS,
  VIA_CONTEXT_VERSION,
  type SpecVersion,
} from "./types.js";

/**
 * Outcome of inspecting an artifact's `specVersion`:
 *  - a {@link SpecVersion} this SDK supports;
 *  - `"unknown"` — absent, or a marker this SDK does not support → fail closed.
 *
 * There is no `"legacy"` outcome: pre-0.2 artifacts carried no marker, and none remain
 * (see docs/VIA/legacy.md). An unmarked artifact is now unsupported, not historical.
 */
export type DetectedSpecVersion = SpecVersion | "unknown";

function readMarker(o: unknown): unknown {
  return o && typeof o === "object" ? (o as Record<string, unknown>).specVersion : undefined;
}

/** True if this SDK can natively issue/verify the given spec version. */
export function isSupportedSpecVersion(v: unknown): v is SpecVersion {
  return typeof v === "string" && (SUPPORTED_SPEC_VERSIONS as readonly string[]).includes(v);
}

/**
 * Detect an artifact's spec version from its signed `specVersion` marker. A
 * presentation delegates to the credential it carries. A missing or unrecognized
 * marker is `"unknown"`, and every caller fails closed on it.
 */
export function detectSpecVersion(
  artifact:
    | ViaMandateCredential
    | VerifiablePresentation
    | Record<string, unknown>,
): DetectedSpecVersion {
  // a VP carries the credential that holds the marker; bare VCs hold it directly.
  const vc = (artifact as VerifiablePresentation)?.verifiableCredential ?? artifact;
  const marker = readMarker(vc) ?? readMarker(artifact);
  return isSupportedSpecVersion(marker) ? marker : "unknown";
}
