/**
 * v0.4 §15.2 — the mandate that binds an agent: built with its tools and their rules in place of an action, and
 * marked `specVersion: "0.4"`. A mandate that binds no agent keeps v0.3's shape and is built by `buildMandate`.
 */
import { randomUUID } from "node:crypto";
import { normalizeBoundKey } from "../mandate/build.js";
import { EXT_MAX_EXECUTIONS } from "../mandate/build.js";
import { DEFAULT_SCOPE, TYPE_VC, TYPE_VIA_MANDATE, VIA_CONTEXTS, type BitstringStatusListEntry, type EvidenceEntry, type Mandate, type MandateInitiator, type ViaMandateCredential } from "../types.js";
import type { BoundKey } from "../agent/types.js";
import type { GrantorBinding } from "../grantor/binding.js";
import { VIA_PLATFORM_DID } from "../did/web.js";
import { mandateLimitsIssues, type MandateLimitsContext } from "./policy.js";
import { LIMITS_SPEC_VERSION, type MandateLimits, type ReviewerPart } from "./types.js";

export interface BuildLimitsMandateInput {
  credentialId?: string;
  /** Always the platform; defaults to `did:web:humanos.tech`. */
  issuer?: string;
  /** The requesting organization's DID — `credentialSubject.id`. */
  subjectOrg: string;
  /** One person: who may grant is read against the policy's `grantors` (§15.5). */
  grantor: string;
  grantorBinding?: GrantorBinding;
  scope?: string;
  /** Who may present and verify. The subject organization is added when the list does not name it (v0.3 §12). */
  authorizedDIDs: string[];
  /** §16.4 — the agent key or keys it binds. At least one: a mandate that binds none keeps v0.3's shape. */
  authorizedAgents: BoundKey[];
  /** §16.4 — the re-attest window, in seconds, written onto every bound entry. */
  maxAttestationStaleness?: number;
  /** §15.2 — its words, its number of calls, and its tools with their rules. */
  limits: MandateLimits;
  /**
   * §15.2 — what the reviewer did before issue: the `reviewed` of {@link reviewMandateRequest}, which the issuer
   * runs first. A request it refused is never built.
   */
  reviewed: ReviewerPart;
  /** v0.3 §20.4 — who asked for it, when that was not the grantor. */
  initiator?: MandateInitiator;
  evidence?: EvidenceEntry[];
  credentialStatus?: BitstringStatusListEntry;
  validFrom: string;
  validUntil?: string;
}

/**
 * §15.2 — build the **unsigned** mandate for an agent (no `proof`); secure it with `stampMandate`. Refused, with
 * every reason, when its limits could not be signed (`mandateLimitsIssues`): the moment to refuse a defective
 * consent is before a person is asked for it.
 */
export function buildLimitsMandate(input: BuildLimitsMandateInput, ctx: MandateLimitsContext): ViaMandateCredential {
  if (input.authorizedDIDs.length === 0) throw new Error("mandate requires at least one authorizedDID");
  if (!input.authorizedAgents?.length) throw new Error("a v0.4 mandate binds an agent; one that binds none keeps v0.3's shape (v0.4 §15)");
  if (typeof input.grantor !== "string" || !input.grantor) throw new Error("a v0.4 mandate has one grantor (v0.4 §15.5)");
  const issues = mandateLimitsIssues(input.limits, ctx);
  if (issues.length) throw new Error(`mandate limits invalid: ${issues.join("; ")}`);
  const authorizedDIDs = input.authorizedDIDs.includes(input.subjectOrg) ? input.authorizedDIDs : [...input.authorizedDIDs, input.subjectOrg];
  const mandate: Mandate = {
    grantor: input.grantor,
    ...(input.grantorBinding ? { grantorBinding: input.grantorBinding } : {}),
    scope: input.scope ?? DEFAULT_SCOPE,
    context: {
      authorizedDIDs,
      authorizedAgents: input.authorizedAgents.map((bk, i) => normalizeBoundKey(bk, i, input.maxAttestationStaleness)),
    },
    description: input.limits.description,
    maxExecutions: input.limits.maxExecutions,
    ...(input.limits.rules?.length ? { rules: input.limits.rules } : {}),
    tools: input.limits.tools,
    reviewed: input.reviewed,
    ...(input.initiator ? { initiator: input.initiator } : {}),
    extensions: [EXT_MAX_EXECUTIONS],
  };
  return {
    "@context": [...VIA_CONTEXTS],
    id: input.credentialId ?? `urn:via:credential:${randomUUID()}`,
    type: [TYPE_VC, TYPE_VIA_MANDATE],
    specVersion: LIMITS_SPEC_VERSION,
    issuer: input.issuer ?? VIA_PLATFORM_DID,
    validFrom: input.validFrom,
    ...(input.validUntil ? { validUntil: input.validUntil } : {}),
    credentialSubject: { id: input.subjectOrg, mandate },
    ...(input.evidence ? { evidence: input.evidence } : {}),
    ...(input.credentialStatus ? { credentialStatus: input.credentialStatus } : {}),
  };
}

/** Is this credential a mandate of §15.2's shape? Read from its signed marker, never from its fields (§15.7). */
export function isLimitsMandate(credential: Pick<ViaMandateCredential, "specVersion">): boolean {
  return credential.specVersion === LIMITS_SPEC_VERSION;
}

/**
 * §15.2 — a §15.2 mandate's limits, as `decideLimits` reads them; null when the credential is marked 0.4 and does
 * not carry them, which no issuer should have signed.
 */
export function limitsOf(credential: ViaMandateCredential): MandateLimits | null {
  const m = credential.credentialSubject.mandate;
  if (!isLimitsMandate(credential) || !m.description || !Number.isInteger(m.maxExecutions) || !m.tools || typeof m.tools !== "object") return null;
  if (m.action !== undefined || m.enforcement !== undefined || m.userParams !== undefined || m.stepUp !== undefined) return null;
  return { description: m.description, maxExecutions: m.maxExecutions!, ...(m.rules ? { rules: m.rules } : {}), tools: m.tools };
}
