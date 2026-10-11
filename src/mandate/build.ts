import { randomUUID } from "node:crypto";
import { computeSRI } from "../crypto/digest.js";
import { createDataIntegrityProof, verifyDataIntegrityProof, type LifecycleAction } from "../crypto/proof.js";
import { VIA_PLATFORM_DID } from "../did/web.js";
import {
  DEFAULT_SCOPE,
  TYPE_VC,
  TYPE_VIA_MANDATE,
  VIA_CONTEXTS,
  VIA_SPEC_VERSION,
  type ActionReference,
  type BitstringStatusListEntry,
  type Enforcement,
  type EvidenceEntry,
  type MandateDescription,
  type MandateInitiator,
  type MandateStepUp,
  type SpecVersion,
  type ViaMandateCredential,
} from "../types.js";
import { validateMandateDescription } from "./description.js";
import type { WrappedUserParam } from "../action/execution-params.js";
import type { BoundKey } from "../agent/types.js";
import type { GrantorBinding } from "../grantor/binding.js";

export interface BuildMandateInput {
  credentialId?: string;
  /** Always the platform; defaults to `did:web:humanos.tech`. */
  issuer?: string;
  /** The requesting org DID — `credentialSubject.id`. */
  subjectOrg: string;
  grantor: string | string[];
  /** §17 — the verified grantor passkey binding (from `buildGrantorBinding`). */
  grantorBinding?: GrantorBinding;
  scope?: string;
  authorizedDIDs: string[];
  /** §16 — the bound agent key(s) (from registration). Present ⇒ verify requires a PoP. */
  authorizedAgents?: BoundKey[];
  /**
   * §16.4 — the re-attest window, in seconds, written onto every `authorizedAgents` entry (A8). The
   * mandate's author sets it; absent ⇒ no window. An entry that already carries a stricter one keeps
   * its own.
   */
  maxAttestationStaleness?: number;
  action?: ActionReference;
  userParams?: Record<string, WrappedUserParam>;
  /**
   * Bounded-Use extension (§19.5) — grant usable at most N times; omit for unbounded. When set,
   * it is written to `mandate.maxExecutions` and `"maxExecutions"` is added to the `extensions`
   * manifest. Validated (see {@link validateMaxExecutions}).
   */
  maxExecutions?: number;
  evidence?: EvidenceEntry[];
  credentialStatus?: BitstringStatusListEntry;
  validFrom: string;
  /** Omitted entirely when there is no expiry (never null — N19). */
  validUntil?: string;
  /** §20.1 — the words the person was shown, with their language and their author. REQUIRED. */
  description: MandateDescription;
  /**
   * §20.3 — which machinery governs. REQUIRED: a v0.3 issuer states it rather than leaving it to be
   * inferred from whether an action is pinned. Inference is a verifier's fallback for mandates
   * issued before §20, and it reads a forgotten field as `none` — a mandate nothing checks.
   */
  enforcement: Enforcement;
  /** §20.4 — who asked for this mandate, when that was not the grantor (§16.14). */
  initiator?: MandateInitiator;
  /** §17.4 — the mandate's own step-up declaration (`triggers`, `reasons`). */
  stepUp?: MandateStepUp;
}

/** §19.4 — the registered name of semantic review, listed when `enforcement` is `semantic`. */
export const EXT_SEMANTIC_REVIEW = "semanticReview";

/**
 * §19.2 — the first critical extension a verifier does not implement, or null. A verifier that meets
 * one denies (`extension_unsupported`) before any rule or reviewer runs: ignoring it is exactly the
 * failure a critical extension exists to prevent.
 */
export function unsupportedCriticalExtension(
  mandate: { criticalExtensions?: string[] },
  implemented: ReadonlySet<string>,
): string | null {
  return (mandate.criticalExtensions ?? []).find((name) => !implemented.has(name)) ?? null;
}

/** The registered name of the Bounded-Use extension (§19.5), as it appears in `mandate.extensions`. */
export const EXT_MAX_EXECUTIONS = "maxExecutions";

/**
 * Machine-readable exhaustion reason string (mirrors the platform's InactiveReason). The terminal
 * event *type* is `EXHAUST` (§19.5), which is self-describing; this may accompany it as optional
 * detail and is the string the platform records for a spent Bounded-Use grant.
 */
export const MAX_EXECUTIONS_REACHED = "max_executions_reached";

/**
 * Validate a `maxExecutions` bound at issuance (§19.5). Absent is valid (⇒ unbounded); otherwise it
 * MUST be a safe integer ≥ 1 — `0`/negative/fractional are rejected rather than reinterpreted, since
 * a grant exhausted before the grantor consents is a configuration error, not a runtime state.
 * Throws on an invalid value.
 */
export function validateMaxExecutions(value: number | undefined): void {
  if (value === undefined) return;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`maxExecutions must be a safe integer ≥ 1 (got ${value})`);
  }
}

export interface BuildEvidenceInput {
  id?: string;
  type?: string[];
  mediaType?: string;
  location: string;
  /** Artifact bytes/text to hash; supply this OR a precomputed `digestSRI`. */
  content?: string | Uint8Array;
  digestSRI?: string;
}

/**
 * An evidence `mediaType`: a bare lowercase `type/subtype` in RFC 6838 restricted-name syntax.
 *
 * It is signed, so a bad value cannot be corrected later. Parameters are rejected:
 * `application/json` and `application/json;charset=utf-8` would be two byte-different spellings
 * of one type inside a signature, and equivalent credentials would stop comparing equal. Which
 * media types are acceptable is platform policy; this is only the grammar.
 */
export const MEDIA_TYPE_PATTERN = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;

/** Build a by-reference `evidence` entry, computing the SRI digest from `content` if needed. */
export function buildEvidence(input: BuildEvidenceInput): EvidenceEntry {
  const digestSRI = input.digestSRI ?? (input.content !== undefined ? computeSRI(input.content) : undefined);
  if (!digestSRI) throw new Error("buildEvidence requires `content` or `digestSRI`");
  if (input.mediaType !== undefined && !MEDIA_TYPE_PATTERN.test(input.mediaType)) {
    throw new Error(
      `buildEvidence: invalid mediaType '${input.mediaType}': expected a lowercase type/subtype with no parameters`,
    );
  }
  return {
    id: input.id ?? `urn:via:evidence:${randomUUID()}`,
    type: input.type ?? ["VIAEvidence"],
    ...(input.mediaType !== undefined ? { mediaType: input.mediaType } : {}),
    digestSRI,
    location: input.location,
  };
}

/**
 * Build the **unsigned** VIA mandate credential (no `proof`). Secure it with the
 * single Humanos `STAMP` via {@link stampMandate}; consents and operational facts
 * are standalone `VIAEvent`s (see `src/event/build.ts`), not mandate proofs.
 */
/**
 * The §16.4 wire shape of a binding entry, whatever the caller handed in.
 *
 * `did` is REQUIRED on a signed entry: it is the agent's identity for rules and for "which
 * mandates does this agent hold", and a raw-JWK pin has no other place to carry it. `verifiedAt`
 * is written as ISO-8601 — a caller passing the epoch-ms a registration result carries gets it
 * converted here, so no v0.3-signed artifact carries the v0.2 encoding. `keyId`, when present,
 * must be a key of `did` (`<did>#key-N`) — the pin names a key, the entry names the actor.
 *
 * Only the §16.4 fields are signed. A registration result is a `BoundKey` too, and carries what
 * the registrar saw (`custodyRef`, `evidence`, `runtime`); spreading it would sign KMS details
 * and grading evidence into a mandate every relying party reads.
 */
/**
 * The mandate's own step-up declaration as it is signed (v0.3 §17.4), or nothing when it declares
 * none. Checked here because it is the last point before the value is signed, and a typo would
 * change who is asked: an unknown trigger is ignored by a verifier, so "ask me every time" spelled
 * wrong would be a mandate that never asks.
 *
 * `action` is not a mandate trigger — it is the ActionVersion's own. `reasons` narrows `verifier`
 * and means nothing without it.
 */
export function normalizeMandateStepUp(stepUp: MandateStepUp | undefined): MandateStepUp | undefined {
  if (stepUp === undefined) return undefined;
  const triggers = [...new Set(stepUp.triggers ?? [])];
  for (const t of triggers) {
    if (t !== "mandate" && t !== "verifier") {
      throw new Error(`stepUp.triggers: "${String(t)}" is not a mandate trigger — use "mandate" or "verifier" (§17.4)`);
    }
  }
  const reasons = stepUp.reasons === undefined ? undefined : [...new Set(stepUp.reasons)];
  if (reasons?.some((r) => typeof r !== "string" || !r)) throw new Error("stepUp.reasons must be non-empty strings (§17.4)");
  if (reasons?.length && !triggers.includes("verifier")) {
    throw new Error('stepUp.reasons narrows the "verifier" trigger and needs it in stepUp.triggers (§17.4)');
  }
  if (triggers.length === 0) return undefined;
  return { triggers, ...(reasons?.length ? { reasons } : {}) };
}

function normalizeBoundKey(bk: BoundKey, i: number, window?: number): BoundKey {
  if (!bk.did) throw new Error(`authorizedAgents[${i}] requires did (§16.4)`);
  if (bk.keyId && !bk.keyId.startsWith(`${bk.did}#`)) {
    throw new Error(`authorizedAgents[${i}]: keyId (${bk.keyId}) is not a key of did (${bk.did})`);
  }
  const ms = typeof bk.verifiedAt === "number" ? bk.verifiedAt : Date.parse(bk.verifiedAt);
  if (!Number.isFinite(ms)) throw new Error(`authorizedAgents[${i}]: verifiedAt is not an instant`);
  const windows = [bk.maxAttestationStaleness, window].filter((w): w is number => w !== undefined);
  for (const w of windows) {
    if (!Number.isSafeInteger(w) || w <= 0) throw new Error(`authorizedAgents[${i}]: maxAttestationStaleness must be a positive whole number of seconds`);
  }
  const maxAttestationStaleness = windows.length ? Math.min(...windows) : undefined;
  if (bk.attestationDigestSRI !== undefined && !bk.attestationDigestSRI.startsWith("sha256-")) {
    throw new Error(`authorizedAgents[${i}]: attestationDigestSRI is not an SRI string (sha256-…)`);
  }
  return {
    did: bk.did,
    cnf: { jwk: bk.cnf.jwk },
    ...(bk.keyId ? { keyId: bk.keyId } : {}),
    assurance: bk.assurance,
    binding: bk.binding,
    ...(bk.root ? { root: bk.root } : {}),
    verifiedAt: new Date(ms).toISOString(),
    ...(maxAttestationStaleness !== undefined ? { maxAttestationStaleness } : {}),
    ...(bk.attestationDigestSRI !== undefined ? { attestationDigestSRI: bk.attestationDigestSRI } : {}),
  };
}

export function buildMandate(input: BuildMandateInput): ViaMandateCredential {
  if (input.authorizedDIDs.length === 0) throw new Error("mandate requires at least one authorizedDID");
  // §20.1 / §20.3 — both are the issuer's to write on every new mandate; the types say so, and this
  // says so to a caller the types do not reach.
  if (!input.description) throw new Error("mandate requires a description (§20.1)");
  if (!input.enforcement) throw new Error("mandate requires an enforcement (§20.3)");
  // §20.3's validity rules are enforced HERE rather than at verify: an invalid pairing of
  // description and enforcement is a defective consent, and the moment to refuse it is before a
  // person is asked to sign, not after the artifact exists.
  const check = validateMandateDescription({
    ...(input.description ? { description: input.description } : {}),
    ...(input.enforcement ? { enforcement: input.enforcement } : {}),
    ...(input.action ? { action: input.action } : {}),
  } as never);
  if (!check.ok) throw new Error(`mandate description invalid: ${check.reason}`);
  // Extensions (§19). Each extension in use contributes its term(s) and its name to the signed
  // presence manifest. Only Bounded-Use exists today; the accumulator is the seam for the next one.
  validateMaxExecutions(input.maxExecutions);
  const extensions: string[] = [];
  if (input.maxExecutions !== undefined) extensions.push(EXT_MAX_EXECUTIONS);
  // §19.4 — semantic review is CRITICAL, not advisory: a verifier that ignored the term would
  // allow every call under a mandate whose whole point is that something reads it first. Listing
  // it in the signed manifest is what makes "this verifier does not implement §20.6" detectable.
  const enforcement = input.enforcement;
  const stepUp = normalizeMandateStepUp(input.stepUp);
  const criticalExtensions: string[] = [];
  if (enforcement === "semantic") {
    extensions.push(EXT_SEMANTIC_REVIEW);
    criticalExtensions.push(EXT_SEMANTIC_REVIEW);
  }
  const credential: ViaMandateCredential = {
    "@context": [...VIA_CONTEXTS],
    id: input.credentialId ?? `urn:via:credential:${randomUUID()}`,
    type: [TYPE_VC, TYPE_VIA_MANDATE],
    specVersion: VIA_SPEC_VERSION as SpecVersion,
    issuer: input.issuer ?? VIA_PLATFORM_DID,
    validFrom: input.validFrom,
    ...(input.validUntil ? { validUntil: input.validUntil } : {}),
    credentialSubject: {
      id: input.subjectOrg,
      mandate: {
        grantor: input.grantor,
        ...(input.grantorBinding ? { grantorBinding: input.grantorBinding } : {}),
        scope: input.scope ?? DEFAULT_SCOPE,
        context: {
          authorizedDIDs: input.authorizedDIDs,
          ...(input.authorizedAgents
            ? { authorizedAgents: input.authorizedAgents.map((bk, i) => normalizeBoundKey(bk, i, input.maxAttestationStaleness)) }
            : {}),
        },
        ...(input.action ? { action: input.action } : {}),
        ...(input.userParams ? { userParams: input.userParams } : {}),
        description: input.description,
        enforcement,
        ...(input.initiator ? { initiator: input.initiator } : {}),
        ...(stepUp ? { stepUp } : {}),
        ...(input.maxExecutions !== undefined ? { maxExecutions: input.maxExecutions } : {}),
        ...(extensions.length ? { extensions } : {}),
        ...(criticalExtensions.length ? { criticalExtensions } : {}),
      },
    },
    ...(input.evidence ? { evidence: input.evidence } : {}),
    ...(input.credentialStatus ? { credentialStatus: input.credentialStatus } : {}),
  };
  return credential;
}

export interface StampSigner {
  privateKey: Uint8Array;
  verificationMethod: string;
  created?: string;
}

/**
 * Secure the mandate with the single content-bound Humanos `STAMP` (spec §0.5) — a
 * Data Integrity proof whose `event` is `"STAMP"`. Returns the credential with its
 * `proof` set (a single object, not an array).
 */
export function stampMandate(credential: ViaMandateCredential, signer: StampSigner): ViaMandateCredential {
  const proof = createDataIntegrityProof({
    document: credential as unknown as Record<string, unknown>,
    privateKey: signer.privateKey,
    verificationMethod: signer.verificationMethod,
    proofPurpose: "assertionMethod",
    event: "STAMP",
    ...(signer.created ? { created: signer.created } : {}),
  });
  return { ...credential, proof };
}

export type ResolvePublicKey = (verificationMethod: string) => Uint8Array | Promise<Uint8Array>;

/** Verify the mandate's single securing `STAMP` proof (spec §0.5). */
export async function verifyStamp(
  credential: ViaMandateCredential,
  resolvePublicKey: ResolvePublicKey,
): Promise<{ valid: boolean; reason?: string }> {
  if (!credential.proof) return { valid: false, reason: "mandate has no STAMP proof" };
  try {
    const key = await resolvePublicKey(credential.proof.verificationMethod);
    return { valid: verifyDataIntegrityProof(credential as unknown as Record<string, unknown>, credential.proof, key) };
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }
}

/**
 * @deprecated Use {@link stampMandate} (the securing `STAMP`) plus standalone
 * `VIAEvent`s for consents (`src/event/build.ts`). Thin compat shim: a `STAMP`
 * signer delegates to {@link stampMandate}; any other `lifecycleAction` is a no-op
 * returning the credential unchanged (consents are no longer mandate proofs).
 */
export interface MandateSigner {
  privateKey: Uint8Array;
  verificationMethod: string;
  lifecycleAction: LifecycleAction;
  created?: string;
}

/** @deprecated Use {@link stampMandate}. See {@link MandateSigner}. */
export function addProof(credential: ViaMandateCredential, signer: MandateSigner): ViaMandateCredential {
  if (signer.lifecycleAction !== "STAMP") return credential;
  return stampMandate(credential, {
    privateKey: signer.privateKey,
    verificationMethod: signer.verificationMethod,
    ...(signer.created ? { created: signer.created } : {}),
  });
}

/** @deprecated Result shape of the retired {@link verifyMandateProofs} shim. */
export interface MandateProofCheck {
  verificationMethod: string;
  lifecycleAction?: string;
  valid: boolean;
}

/**
 * @deprecated Use {@link verifyStamp}. Normalizes the single-object mandate `proof`
 * into the old proof-set result shape: a one-element array (or `[]` when unsigned).
 */
export async function verifyMandateProofs(
  credential: ViaMandateCredential,
  resolvePublicKey: ResolvePublicKey,
): Promise<MandateProofCheck[]> {
  const proof = credential.proof;
  if (!proof) return [];
  let valid = false;
  try {
    const key = await resolvePublicKey(proof.verificationMethod);
    valid = verifyDataIntegrityProof(credential as unknown as Record<string, unknown>, proof, key);
  } catch {
    valid = false;
  }
  return [{ verificationMethod: proof.verificationMethod, lifecycleAction: proof.event ?? proof.lifecycleAction, valid }];
}
