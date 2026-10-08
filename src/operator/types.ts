// Operator Verification (§18 proposal) — the IDENTITY axis, orthogonal to §16.3's
// confinement axis. §16.3 asks "is this key real hardware?"; this asks "who operates
// this agent, and how well was that identity verified?".
//
// Mirrors §16.3's three-part anatomy on purpose — `level` (ordinal, CEL floors) +
// `method` (categorical, CEL matches) + `registrar` (the root) — so the existing CEL
// and staleness machinery consumes it unchanged.
import type { BitstringStatusListEntry, SpecVersion } from "../types.js";
import type { DataIntegrityProof } from "../crypto/proof.js";

/**
 * The verification ladder (ORDINAL — climb it; CEL floors compare the rank).
 * It measures **the strength of the verification procedure applied to the identity
 * claim**, NOT the trustworthiness of the operator (the TLS DV/OV/EV distinction):
 * - `unverified` — self-asserted, nothing vouched. The default, high-volume tier.
 * - `domain`     — namespace control proven (ACME/DNS challenge, no humans). Decays.
 * - `verified`   — legal identity confirmed (documents / registry / liveness).
 *
 * KYC vs KYB is *how it was earned* ({@link AccreditationMethod} / {@link SubjectType}),
 * never a separate top rung — a solo developer (KYC) must not be capped below a business.
 */
export type AccreditationLevel = "unverified" | "domain" | "verified";

export const ACCREDITATION_RANK: Record<AccreditationLevel, number> = { unverified: 1, domain: 2, verified: 3 };
/** Ordinal rank of an operator level (CEL helper `accreditationRank`). */
export function accreditationRank(level: AccreditationLevel): number {
  return ACCREDITATION_RANK[level] ?? 0;
}
/** True iff `actual` meets or exceeds the `floor` level. */
export function meetsAccreditation(actual: AccreditationLevel, floor: AccreditationLevel): boolean {
  return accreditationRank(actual) >= accreditationRank(floor);
}

/**
 * How the level was earned (CATEGORICAL — matched with `==` / `in`, never ranked).
 * A **fixed enum**: extending it is a spec change, so a verifier's categorical matches
 * stay total and registrars cannot invent private levels.
 */
export type AccreditationMethod = "dns-challenge" | "kyc-doc" | "kyb-registry" | "eidas-substantial" | "eidas-high";
export const ACCREDITATION_METHODS: AccreditationMethod[] = ["dns-challenge", "kyc-doc", "kyb-registry", "eidas-substantial", "eidas-high"];

export type SubjectType = "individual" | "organization";

/** `operates` = the ∧ link that lets an agent inherit its org's level; `vouches` = endorsement. */
/** §18: `operates` / `vouches`; `sandbox_of` — a production organization accountable for its sandbox (§3.6f). */
export type AffiliationRelation = "operates" | "vouches" | "sandbox_of";

/** §18 deny reasons (the O1–O5 gate). */
export type AccreditationReasonCode =
  | "accreditation_signature_invalid"
  | "affiliation_invalid"
  | "accreditation_revoked"
  | "accreditation_expired"
  | "accreditation_insufficient"
  | "accreditation_on_agent";

/** Why an operator's verification was pulled — underwriters need the *why*. */
export type AccreditationRevocationReason = "struck_off" | "fraud" | "sanctions";

/**
 * When a signed claim lapses — an accreditation's or an affiliation's (v0.3 §18.2, §18.4).
 *
 * The field is `validUntil`. Claims signed before 2026-10-07 say `expiresAt`, and a signed event is
 * read as written, never rewritten — so every reader goes through here. `validUntil` wins when both
 * are stated.
 *
 * `at` on a runtime attestation and on `anchoredBy` is NOT this family and was not renamed: it is
 * when something was CHECKED (like `verifiedAt`), not when a statement starts to hold. The event
 * that carries it has its own `validFrom`, and the two differ — a `MERGED` signed in October carries
 * a runtime attested in March.
 */
export function claimValidUntil(claim: { validUntil?: unknown; expiresAt?: unknown } | null | undefined): string | undefined {
  const text = (v: unknown) => (typeof v === "string" && v ? v : undefined);
  return text(claim?.validUntil) ?? text(claim?.expiresAt);
}

/** The registrar's verification claims about one operator. */
export interface AccreditationClaims {
  /** The operator (organization or individual) this credential is about. */
  id: string;
  level: AccreditationLevel;
  method: AccreditationMethod;
  subjectType: SubjectType;
  /**
   * Not stated since 2026-10-08: the registrar is who SIGNED the event (v0.3 §18.2). A claim signed
   * before may carry a name here; it is not read.
   */
  registrar?: string;
  verifiedAt: string;
  /**
   * When the claim lapses (v0.3 §18.2) — identity DECAYS by nature. The name the credential envelope
   * uses for the same meaning. A claim signed before 2026-10-07 says `expiresAt`; read it with
   * {@link claimValidUntil}, never by field.
   */
  validUntil?: string;
  /** Published, offline-checkable revocation (v0.2-new §10.1) — no live registrar call at verify. */
  status?: BitstringStatusListEntry;
}

/** A registrar-signed operator verification credential (a W3C VC, one securing proof). */

/** The verified, composed result an agent actually carries into CEL as `operator.*`. */
export interface AccreditationEnv {
  level: AccreditationLevel;
  method?: AccreditationMethod;
  subjectType?: SubjectType;
  registrar?: string;
  /** The org the agent is affiliated to (present only when a valid `operates` link exists). */
  org?: string;
  verifiedAt?: string;
}
