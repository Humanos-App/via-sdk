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
 * KYC vs KYB is *how it was earned* ({@link OperatorMethod} / {@link SubjectType}),
 * never a separate top rung — a solo developer (KYC) must not be capped below a business.
 */
export type OperatorLevel = "unverified" | "domain" | "verified";

export const OPERATOR_RANK: Record<OperatorLevel, number> = { unverified: 1, domain: 2, verified: 3 };
/** Ordinal rank of an operator level (CEL helper `operatorRank`). */
export function operatorRank(level: OperatorLevel): number {
  return OPERATOR_RANK[level] ?? 0;
}
/** True iff `actual` meets or exceeds the `floor` level. */
export function meetsOperator(actual: OperatorLevel, floor: OperatorLevel): boolean {
  return operatorRank(actual) >= operatorRank(floor);
}

/**
 * How the level was earned (CATEGORICAL — matched with `==` / `in`, never ranked).
 * A **fixed enum**: extending it is a spec change, so a verifier's categorical matches
 * stay total and registrars cannot invent private levels.
 */
export type OperatorMethod = "dns-challenge" | "kyc-doc" | "kyb-registry" | "eidas-substantial" | "eidas-high";
export const OPERATOR_METHODS: OperatorMethod[] = ["dns-challenge", "kyc-doc", "kyb-registry", "eidas-substantial", "eidas-high"];

export type SubjectType = "individual" | "organization";

/** `operates` = the ∧ link that lets an agent inherit its org's level; `vouches` = endorsement. */
export type AffiliationRelation = "operates" | "vouches";

/** §18 deny reasons (the O1–O5 gate). */
export type OperatorReasonCode =
  | "operator_signature_invalid"
  | "affiliation_invalid"
  | "operator_revoked"
  | "operator_expired"
  | "operator_insufficient";

/** Why an operator's verification was pulled — underwriters need the *why*. */
export type OperatorRevocationReason = "struck_off" | "fraud" | "sanctions";

/** The registrar's verification claims about one operator. */
export interface OperatorClaims {
  /** The operator (organization or individual) this credential is about. */
  id: string;
  level: OperatorLevel;
  method: OperatorMethod;
  subjectType: SubjectType;
  /** The root that performed the verification — `humanos` today; QTSPs / registries later. */
  registrar: string;
  verifiedAt: string;
  /** Identity DECAYS by nature — domain rungs re-challenge (~90d), `verified` refreshes annually. */
  expiresAt?: string;
  /** Published, offline-checkable revocation (v0.2-new §10.1) — no live registrar call at verify. */
  status?: BitstringStatusListEntry;
}

/** A registrar-signed operator verification credential (a W3C VC, one securing proof). */

/** The verified, composed result an agent actually carries into CEL as `operator.*`. */
export interface OperatorEnv {
  level: OperatorLevel;
  method?: OperatorMethod;
  subjectType?: SubjectType;
  registrar?: string;
  /** The org the agent is affiliated to (present only when a valid `operates` link exists). */
  org?: string;
  verifiedAt?: string;
}
