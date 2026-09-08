import type { DataIntegrityProof, EventType } from "./crypto/proof.js";
import type { WrappedUserParam } from "./action/execution-params.js";
import type { BoundKey } from "./agent/types.js";
import type { GrantorBinding } from "./grantor/binding.js";

export type { EventType } from "./crypto/proof.js";

export const VC_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
export const VIA_CONTEXT = "https://via.humanos.tech/ns/v1";
export const VIA_CONTEXTS = [VC_V2_CONTEXT, VIA_CONTEXT] as const;

/**
 * VIA spec/data-model version. Carried on every artifact as the signed `specVersion`
 * marker — distinct from the package version and the JSON-LD context version
 * ({@link VIA_CONTEXT_VERSION}). See `spec/VERSIONING.md`.
 */
export const VIA_SPEC_VERSION = "0.3";

/**
 * Spec versions this SDK issues / verifies natively.
 *
 * It ISSUES {@link VIA_SPEC_VERSION} and verifies both: v0.3 is an evolution of v0.2, not a
 * replacement, and 0.2 artifacts are current — dropping them would reject live credentials.
 * That is a different thing from the retired pre-0.2 format, which carried no marker at all
 * and is rejected as unsupported.
 */
export const SUPPORTED_SPEC_VERSIONS = ["0.2", "0.3"] as const;

export type SpecVersion = (typeof SUPPORTED_SPEC_VERSIONS)[number];

/** JSON-LD context (term-definition) version — evolves independently of the spec version. */
export const VIA_CONTEXT_VERSION = "v1";

export const TYPE_VC = "VerifiableCredential";
export const TYPE_VIA_MANDATE = "VIAMandate";
export const TYPE_VIA_EVENT = "VIAEvent";
/** @deprecated Use {@link TYPE_VIA_EVENT}. `VIAReceipt` is a reference-bound `VIAEvent` alias (spec v0.2-new §10.2). */
export const TYPE_VIA_RECEIPT = "VIAReceipt";
export const TYPE_VP = "VerifiablePresentation";

export const DEFAULT_SCOPE = "humanos.credential.request";

export type CredentialStatus = "DRAFT" | "ACTIVE" | "REJECTED" | "CANCELED" | "REVOKED" | "EXPIRED";

/**
 * @deprecated Use {@link EventType}. Operational-event subset kept as an alias for
 * one migration window (spec v0.2-new §10.2). `VP_DENIED` / `MANDATE_REVOKED` predate the
 * unified taxonomy.
 */
export type ReceiptType =
  | "VP_CREATED"
  | "VP_DENIED"
  | "VERIFICATION_APPROVED"
  | "VERIFICATION_DENIED"
  | "MANDATE_REVOKED";

export interface ActionReference {
  id: string;
  digestSRI: string;
  location: string;
}

export interface Mandate {
  grantor: string | string[];
  /** §17 — the passkey Humanos verified at issuance (optional; absent ⇒ OTP-authorized). */
  grantorBinding?: GrantorBinding;
  scope: string;
  /** `authorizedAgents` (§16) — when present, verification additionally requires a per-action PoP. */
  context: { authorizedDIDs: string[]; authorizedAgents?: BoundKey[] };
  action?: ActionReference;
  userParams?: Record<string, WrappedUserParam>;
  /**
   * v0.3 delegation — present on a CHILD mandate minted by attenuation from
   * `parent`. `tools` is the STAMPed narrowed subset (⊆ the parent's); `depth`
   * counts from the root (issuance refuses past the platform's max). Verifiers
   * MUST deny tools outside `tools` and MUST require every ancestor mandate to
   * be ACTIVE (revocation cascades).
   */
  delegation?: { parent: string; depth: number; tools: string[] };
  /**
   * Bounded-Use extension (§19.5) — the grant is usable at most N times; absent ⇒ unbounded.
   * Positive safe integer ≥ 1. The count (`executionsUsed`) is issuer state, never in the
   * credential. When present, `"maxExecutions"` is listed in `extensions`.
   */
  maxExecutions?: number;
  /** §19.1 — presence manifest: the registered extensions this mandate uses, e.g. `["maxExecutions"]`. */
  extensions?: string[];
}

export interface BitstringStatusListCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  credentialSubject: {
    id: string;
    type: "BitstringStatusList";
    statusPurpose: "revocation" | "suspension";
    encodedList: string;
  };
}

export interface EvidenceEntry {
  id: string;
  type: string[];
  mediaType?: string;
  digestSRI: string;
  location: string;
}

export interface BitstringStatusListEntry {
  id: string;
  type: "BitstringStatusListEntry";
  statusPurpose: "revocation" | "suspension";
  statusListIndex: string;
  statusListCredential: string;
}

export interface ViaMandateCredential {
  "@context": string[];
  id: string;
  type: string[];
  /** Signed VIA spec-version marker (e.g. `"0.2"`). Absent on pre-0.2 ("legacy") artifacts. */
  specVersion?: SpecVersion;
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: { id: string; mandate: Mandate };
  evidence?: EvidenceEntry[];
  credentialStatus?: BitstringStatusListEntry;
  /**
   * A **single** content-bound securing proof — the Humanos `STAMP` (its proof
   * object carries `event: "STAMP"`), spec v0.2-new §4.1/§5. Consents (`ISSUE`/`ACCEPT`/
   * `REJECT`) and operational facts are standalone {@link ViaEvent}s, not entries
   * here.
   */
  proof?: DataIntegrityProof;
}

/**
 * The unified `VIAEvent` primitive (spec v0.2-new §5) — a W3C VC carrying one Data Integrity
 * proof that asserts "actor A asserts event E about credential C". Consents, the
 * securing `STAMP`, and operational facts are all `VIAEvent`s. Content-bound events
 * carry `credentialDigest`; reference-bound events omit it. `previousEvent` links
 * the credential's ordered event chain (spec v0.2-new §5.4).
 */
export interface ViaEvent {
  "@context": string[];
  id: string;
  type: string[];
  /** Signed VIA spec-version marker (e.g. `"0.2"`). */
  specVersion?: SpecVersion;
  /** The actor asserting the event (org / grantor / Humanos / verifier). */
  issuer: string;
  validFrom: string;
  credentialSubject: {
    /** The credential this event is about. */
    id: string;
    event: EventType;
    actor: string;
    /** Present iff content-bound: `SRI(canonicalizeRFC8785(credential-without-proof))`. */
    credentialDigest?: string;
    /** SRI of the prior event in this credential's chain, or null at the root. */
    previousEvent?: string | null;
    role?: string;
    reason?: string;
    evaluations?: unknown[];
    executionParams?: Record<string, unknown>;
    targetVerifier?: string;
    /** §16.9 — agent-binding detail (`AGENT_REGISTERED` rung, or `VERIFICATION_*` evidence). */
    agent?: Record<string, unknown>;
    /** §18 — operator detail (`AFFILIATION` org/relation, `REGULATORY` licence). */
    operator?: Record<string, unknown>;
    /** §17.4 — a step-up: the `STEP_UP_*` event's own detail, or on a `VERIFICATION_*` the co-sign it rested on. */
    stepUp?: Record<string, unknown>;
  };
  proof?: DataIntegrityProof;
}

/**
 * @deprecated Use {@link ViaEvent}. A `VIAReceipt` is a reference-bound `VIAEvent`
 * with a `receiptType` field (spec v0.2-new §10.2); kept readable for one migration window.
 */
export interface ViaReceiptCredential {
  "@context": string[];
  id: string;
  type: string[];
  /** Signed VIA spec-version marker (e.g. `"0.2"`). Absent on pre-0.2 ("legacy") artifacts. */
  specVersion?: SpecVersion;
  issuer: string;
  validFrom: string;
  credentialSubject: {
    id: string;
    receiptType: ReceiptType;
    actor: string;
    reason?: string;
    evaluations?: unknown[];
    executionParams?: Record<string, unknown>;
    targetVerifier?: string;
  };
  proof?: DataIntegrityProof;
}

export interface VerifiablePresentation {
  "@context": string[];
  type: string[];
  holder: string;
  /** Single secured VC object (with its `proof`) — N18. */
  verifiableCredential: ViaMandateCredential;
  proof?: DataIntegrityProof;
}
