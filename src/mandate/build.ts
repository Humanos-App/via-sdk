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
  type EvidenceEntry,
  type SpecVersion,
  type ViaMandateCredential,
} from "../types.js";
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
  /** v0.3 delegation — marks a CHILD mandate (attenuated from `parent`). */
  delegation?: { parent: string; depth: number; tools: string[] };
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

/** Build a by-reference `evidence` entry, computing the SRI digest from `content` if needed. */
export function buildEvidence(input: BuildEvidenceInput): EvidenceEntry {
  const digestSRI = input.digestSRI ?? (input.content !== undefined ? computeSRI(input.content) : undefined);
  if (!digestSRI) throw new Error("buildEvidence requires `content` or `digestSRI`");
  return {
    id: input.id ?? `urn:via:evidence:${randomUUID()}`,
    type: input.type ?? ["VIAEvidence"],
    ...(input.mediaType ? { mediaType: input.mediaType } : {}),
    digestSRI,
    location: input.location,
  };
}

/**
 * Build the **unsigned** VIA mandate credential (no `proof`). Secure it with the
 * single Humanos `STAMP` via {@link stampMandate}; consents and operational facts
 * are standalone `VIAEvent`s (see `src/event/build.ts`), not mandate proofs.
 */
export function buildMandate(input: BuildMandateInput): ViaMandateCredential {
  if (input.authorizedDIDs.length === 0) throw new Error("mandate requires at least one authorizedDID");
  // Extensions (§19). Each extension in use contributes its term(s) and its name to the signed
  // presence manifest. Only Bounded-Use exists today; the accumulator is the seam for the next one.
  validateMaxExecutions(input.maxExecutions);
  const extensions: string[] = [];
  if (input.maxExecutions !== undefined) extensions.push(EXT_MAX_EXECUTIONS);
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
          ...(input.authorizedAgents ? { authorizedAgents: input.authorizedAgents } : {}),
        },
        ...(input.action ? { action: input.action } : {}),
        ...(input.userParams ? { userParams: input.userParams } : {}),
        ...(input.delegation ? { delegation: input.delegation } : {}),
        ...(input.maxExecutions !== undefined ? { maxExecutions: input.maxExecutions } : {}),
        ...(extensions.length ? { extensions } : {}),
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
 * Secure the mandate with the single content-bound Humanos `STAMP` (spec v0.2-new §5) — a
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

/** Verify the mandate's single securing `STAMP` proof (spec v0.2-new §5). */
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
