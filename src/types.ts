import type { DataIntegrityProof, EventType, LegacyEventName } from "./crypto/proof.js";
import type { EventFields } from "./event/build.js";
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
/** @deprecated Use {@link TYPE_VIA_EVENT}. `VIAReceipt` is a reference-bound `VIAEvent` alias (spec §0.10.2). */
export const TYPE_VIA_RECEIPT = "VIAReceipt";
export const TYPE_VP = "VerifiablePresentation";

export const DEFAULT_SCOPE = "humanos.credential.request";

export type CredentialStatus = "DRAFT" | "ACTIVE" | "REJECTED" | "CANCELED" | "REVOKED" | "EXPIRED";

/**
 * @deprecated Use {@link EventType}. Operational-event subset kept as an alias for
 * one migration window (spec §0.10.2). `VP_DENIED` / `MANDATE_REVOKED` predate the
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
  /**
   * §20.5 — WHICH published version is pinned, readable without resolving the catalog.
   * Informative: `digestSRI` is the pin, and a verifier MUST NOT rely on this.
   */
  version?: number;
}

/**
 * §20.1 — the words the person was shown, as a signed field of the mandate.
 *
 * On every mandate, both kinds of §16.4. What varies is its JOB, which {@link Mandate.enforcement}
 * names: on a `rules` mandate it is the human-readable version of what the pinned CEL allows; on a
 * `semantic` or `none` mandate it IS the grant.
 */
export interface MandateDescription {
  /** The words. Exactly one normative text per mandate (§20.1). */
  text: string;
  /** BCP 47. REQUIRED — a reader's interpretation depends on it, and one reader is a machine. */
  lang: string;
  /** §20.2 — who WROTE these words. REQUIRED: text that travels without its author is guesswork. */
  author: DescriptionAuthor;
  /** Who drafted them when that was not the author, and whether the grantor took them as shown. */
  proposedBy?: { actor: string; adopted?: boolean };
}

/**
 * §20.2. `issuer` — derived from what governs (the only author a `rules` mandate may carry).
 * `grantor` — the person wrote or edited them. `agent` — drafted by the requester and accepted as
 * shown, which under §20.2's narrowing rule may deny or escalate a call, never allow one.
 */
export type DescriptionAuthor = "issuer" | "agent" | "grantor";

/** §20.3 — which machinery governs this mandate. */
export type Enforcement = "rules" | "semantic" | "none";

/** §17.4 — who may demand a fresh grantor co-sign for a call under this mandate. */
export type StepUpTrigger = "action" | "mandate" | "verifier";

/**
 * §17.4 — the mandate's own step-up declaration. The ONLY way an action-less mandate can ask for a
 * co-sign, and what permits a verifier-side escalation (§20.6) to raise `rechallenge`.
 */
export interface MandateStepUp {
  triggers?: StepUpTrigger[];
  reasons?: string[];
}

/** §20.4 — who asked for the mandate, when that was not the grantor (§16.14). */
export interface MandateInitiator {
  actor: string;
  role?: "execution" | "grantor";
  at?: string;
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
   * §20.1 — the words the person was shown. Optional on the TYPE because artifacts issued before
   * §20 exist and must keep verifying (§0.13); §20.3's validity rules are enforced by
   * `validateMandateDescription`, not by the type.
   */
  description?: MandateDescription;
  /**
   * §20.3 — which machinery governs. Absent on pre-§20 artifacts, where it is DERIVED
   * (`enforcementOf`): an action means `rules`, no action means `none`. A verifier returns it on
   * every decision so that `allow` stops meaning both "no rules ran" and "rules ran and matched
   * nothing".
   */
  enforcement?: Enforcement;
  /** §20.4 — who asked for this mandate (§16.14's agent-initiated request is the case that matters). */
  initiator?: MandateInitiator;
  /** §17.4 — the mandate's own step-up declaration. */
  stepUp?: MandateStepUp;
  /**
   * Bounded-Use extension (§19.5) — the grant is usable at most N times; absent ⇒ unbounded.
   * Positive safe integer ≥ 1. The count (`executionsUsed`) is issuer state, never in the
   * credential. When present, `"maxExecutions"` is listed in `extensions`.
   */
  maxExecutions?: number;
  /** §19.1 — presence manifest: the registered extensions this mandate uses, e.g. `["maxExecutions"]`. */
  extensions?: string[];
  /**
   * §19.2 — the extensions in use that a verifier MUST implement or deny (`extension_unsupported`).
   * Signed, a subset of `extensions`: a verifier that does not know an extension cannot tell it is
   * critical from its name, so the mandate says so.
   */
  criticalExtensions?: string[];
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
   * object carries `event: "STAMP"`), spec §0.4.1/§0.5. Consents (`ISSUE`/`ACCEPT`/
   * `REJECT`) and operational facts are standalone {@link ViaEvent}s, not entries
   * here.
   */
  proof?: DataIntegrityProof;
}

/**
 * The unified `VIAEvent` primitive (spec §0.5) — a W3C VC carrying one Data Integrity
 * proof that asserts "actor A asserts event E about credential C". Consents, the
 * securing `STAMP`, and operational facts are all `VIAEvent`s. Content-bound events
 * carry `credentialDigest`; reference-bound events omit it. `previousEvent` links
 * the credential's ordered event chain (spec §0.5.4).
 */
export interface ViaEvent {
  "@context": string[];
  id: string;
  type: string[];
  /** Signed VIA spec-version marker (`"0.3"` now; `"0.2"` on every event in production before it). */
  specVersion?: SpecVersion;
  /** The signer: the DID whose key signs the event (v0.3 §2). */
  issuer: string;
  validFrom: string;
  /**
   * The core fields, then the kind's own fields directly beside them (v0.3 §2.0) — see
   * {@link EventFields} for every field a kind may carry. A reader ignores a field it does not know.
   */
  credentialSubject: EventFields & {
    /** What the event is about: a mandate's URN, or an actor's DID on an actor-scoped event. */
    id: string;
    /** The kind — today's name, or on an older event the name of its day (v0.3 §3.4). */
    event: EventType | LegacyEventName;
    /** Present iff content-bound: `SRI(canonicalizeRFC8785(credential-without-proof))`. */
    credentialDigest?: string;
    /** SRI of the prior event in this chain, or null at its first event. */
    previousEvent?: string | null;
    /** @deprecated A `"0.2"` field naming the signer; a `"0.3"` event has none — `issuer` is the signer (v0.3 §2). */
    actor?: string;
    /**
     * @deprecated The wrapper actor events carried their fields in before 2026-10-11 (and every `"0.2"`
     * actor event). Read as a fallback, never written (v0.3 §2.0).
     */
    agent?: Record<string, unknown>;
    /** @deprecated A `"0.2"` term: approval policies that were never built. Not a v0.3 field. */
    role?: string;
    /** A JWK on an event written before 2026-10-11 — read as `publicKeyJwk` (v0.3 §3.1). */
    jwk?: Record<string, unknown>;
    [field: string]: unknown;
  };
  proof?: DataIntegrityProof;
}

/**
 * @deprecated Use {@link ViaEvent}. A `VIAReceipt` is a reference-bound `VIAEvent`
 * with a `receiptType` field (spec §0.10.2); kept readable for one migration window.
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
