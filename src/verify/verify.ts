import { verifyDataIntegrityProof } from "../crypto/proof.js";
import { didFromUrl, verifierDomainOf, VIA_PLATFORM_DID } from "../did/web.js";
import { actionDigestSRI } from "../action/build.js";
import { validateExecutionParams, unwrapUserParamValues } from "../action/execution-params.js";
import type { ActionDetail } from "../action/types.js";
import { evaluateRules, type RuleEvaluation } from "../cel/evaluate.js";
import { domainMatches } from "../presentation/vp.js";
import { detectSpecVersion, type DetectedSpecVersion } from "../version.js";
import { enforcementFitsShape, enforcementOf } from "../mandate/description.js";
import { MAX_EXECUTIONS_REACHED, unsupportedCriticalExtension } from "../mandate/build.js";
import type { Enforcement } from "../types.js";
import type { CredentialStatus, VerifiablePresentation } from "../types.js";

export interface VerifyDeps {
  /** The calling verifier's identity (from its API key). */
  verifier: { did: string; domain?: string };
  resolvePublicKey: (vmId: string) => Uint8Array | Promise<Uint8Array>;
  /** Trusted record (DB/status list) — status + validity come from here, not the presented VC. */
  loadCredentialRecord: (urn: string) => CredentialRecord | Promise<CredentialRecord>;
  loadActionVersion: (actionId: string) => ActionDetail | null | Promise<ActionDetail | null>;
  /** Challenge freshness/replay check (platform state). Return 'ok' or a deny reason. */
  validateChallenge?: (challenge: string | undefined, mandateId: string) => string | Promise<string>;
  now?: Date;
  platformDid?: string;
}

export interface CredentialRecord {
  status: CredentialStatus;
  /**
   * §19.5 — the issuer's record says the grant is SPENT: its `maxExecutions` bound was used up. An
   * inactive record with this set denies `max_executions_reached`, not `credential_inactive` — used
   * exactly as agreed is not withdrawn. Only the issuer knows; a status bit alone cannot say why.
   */
  exhausted?: boolean;
  validFrom?: string;
  validUntil?: string;
  /**
   * The credential's authoritative `authorizedDIDs` as currently stored (e.g. in the
   * issuer's DB), used for the access check. The VP embeds a snapshot taken at VP-creation
   * time, but `authorizedDIDs` is mutable — a credential can be re-scoped after a VP is
   * minted (de-authorizing a verifier). When provided, this DB-current list is authoritative
   * and overrides the VP's embedded copy (matching the platform, which always re-loads it).
   * Omit it when there's no backing store and the embedded snapshot is the only source.
   */
  authorizedDIDs?: string[];
}

export interface VerifyResult {
  decision: "allow" | "deny";
  credentialId?: string;
  reason?: string;
  evaluations: RuleEvaluation[];
  /** The credential's detected spec version (`"0.2"` or `"unknown"`). */
  specVersion?: DetectedSpecVersion;
  /** §20.3 — which machinery governed. Derived for artifacts issued before the field existed. */
  enforcement?: Enforcement;
}

const deny = (reason: string, credentialId?: string): VerifyResult => ({
  decision: "deny",
  reason,
  credentialId,
  evaluations: [],
});

/**
 * Verify the outer VP proof: real `eddsa-jcs-2022` (proofConfig + doc hashes).
 * Returns `"ok"` or a deny reason.
 */
async function verifyVpSignature(vp: VerifiablePresentation, deps: VerifyDeps): Promise<string> {
  if (!vp.proof) return "vp_signature_invalid";
  const platformDid = deps.platformDid ?? VIA_PLATFORM_DID;
  if (didFromUrl(vp.proof.verificationMethod) !== platformDid) return "vp_holder_unknown";
  try {
    const key = await deps.resolvePublicKey(vp.proof.verificationMethod);
    const ok = verifyDataIntegrityProof(vp as unknown as Record<string, unknown>, vp.proof, key);
    return ok ? "ok" : "vp_signature_invalid";
  } catch {
    return "vp_holder_unknown";
  }
}

/** Steps 2–9 of v0.2-new §8. */
async function runChecks(
  vp: VerifiablePresentation,
  executionParams: Record<string, unknown>,
  deps: VerifyDeps,
): Promise<VerifyResult> {
  const credential = vp.verifiableCredential;
  const urn = credential.id;

  // 2. status (trusted record)
  const record = await deps.loadCredentialRecord(urn);
  if (record.status !== "ACTIVE") return deny(record.exhausted ? MAX_EXECUTIONS_REACHED : `credential_${record.status.toLowerCase()}`, urn);

  // 3. validity window
  const now = deps.now ?? new Date();
  if (record.validFrom && new Date(record.validFrom) > now) return deny("not_yet_valid", urn);
  if (record.validUntil && new Date(record.validUntil) < now) return deny("expired", urn);

  // 4. access check — the verifier DID must ALWAYS be on the mandate's authorizedDIDs.
  //    The platform enforces this unconditionally (its step 1), independent of any domain
  //    binding. Earlier this was `domain XOR authorizedDIDs`, which let a domain-bound VP
  //    skip the access check entirely — the SDK would then ALLOW a verifier the platform
  //    rejects (`verifier_not_authorized`). authorizedDIDs is the access control; domain is
  //    an *additional* audience binding, not an alternative to it.
  const mandate = credential.credentialSubject.mandate;
  // DB-current list wins over the VP's embedded snapshot (see CredentialRecord.authorizedDIDs).
  const authorizedDIDs = record.authorizedDIDs ?? mandate.context.authorizedDIDs;
  if (!authorizedDIDs.includes(deps.verifier.did)) {
    return deny("verifier_not_authorized", urn);
  }
  // 4b. audience binding — if the VP proof carries a domain it must match the verifier's
  //     domain, and the single-use challenge must validate. Binding is optional: a VP with
  //     no domain is unbound (but still gated by the access check above).
  if (vp.proof?.domain) {
    const verifierDomain = deps.verifier.domain ?? verifierDomainOf(deps.verifier.did);
    if (!verifierDomain || !domainMatches(vp.proof.domain, verifierDomain)) return deny("vp_domain_mismatch", urn);
    if (deps.validateChallenge) {
      const res = await deps.validateChallenge(vp.proof.challenge, urn);
      if (res !== "ok") return deny(res, urn);
    }
  }

  // 4c. agent binding (§16.10): this is the custodial presentation path — it carries no
  //     proof-of-possession. A mandate bound to agents verifies only with one (agent-direct,
  //     §16.11), so here it fails closed rather than falling back to `authorizedDIDs` alone.
  if (mandate.context.authorizedAgents?.length) return deny("pop_invalid", urn);
  // 4d. §19.2: this custodial path implements no critical extension — semantic review needs a reader
  //     it does not have — so a mandate that requires one is denied, never evaluated without it.
  if (unsupportedCriticalExtension(mandate, new Set())) return deny("extension_unsupported", urn);

  // 5. no action → the words govern, or nothing does (§20.3). `allow` says which.
  const enforcement = enforcementOf(mandate);
  if (!enforcementFitsShape(mandate)) return { ...deny("enforcement_invalid", urn), enforcement };
  if (!mandate.action) {
    // §20.6 — a `semantic` mandate is enforced by a READER, and this is the custodial
    // presentation path (v0.2-new §7.1), which has no reviewer to consult: semantic mandates
    // present agent-direct (§16.11). Failing closed is the only honest answer — allowing here
    // would let the one mode whose enforcement is a reader be verified by not reading.
    if (enforcement === "semantic") return { ...deny("reviewer_unavailable", urn), enforcement };
    return { decision: "allow", credentialId: urn, evaluations: [], enforcement };
  }

  // 6. load + pin-check the ActionVersion.
  //    The digest pin is only enforced when the credential actually carries one.
  //    Already-issued mandates whose ActionVersion was never published-with-digest
  //    carry an empty `digestSRI` (the platform stores `actionVersion.digestSRI ?? ""`
  //    at request time and never re-checks the action digest at verify) — accept those
  //    as unpinned rather than failing closed, matching the platform. When a digest IS
  //    present, recompute it and enforce the pin (N-?: this is a tamper check the
  //    platform verify lacks).
  const action = await deps.loadActionVersion(mandate.action.id);
  if (!action) return deny("action_not_found", urn);
  if (mandate.action.digestSRI && actionDigestSRI(action) !== mandate.action.digestSRI) {
    return deny("action_invalid", urn);
  }

  // 7. validate executionParams
  try {
    validateExecutionParams(action, executionParams);
  } catch (e) {
    return deny(`execution_params_invalid:${(e as Error).message}`, urn);
  }

  // 8. no rules → allow
  if (!action.rules || action.rules.length === 0) return { decision: "allow", credentialId: urn, evaluations: [], enforcement };

  // 9. CEL
  const { decision, evaluations } = evaluateRules(action.rules, {
    userParams: unwrapUserParamValues(mandate.userParams),
    executionParams,
  });
  // S13 — a governed call that omitted a required parameter is its own answer, not `rule_failed`:
  // the rule did not fail, the call never carried what the rule constrains. Same mapping as the
  // agent-direct path, because the same rule produced it.
  const missing = evaluations.some((e) => e.reason?.startsWith("required_param_missing"));
  return {
    decision,
    credentialId: urn,
    evaluations,
    enforcement,
    ...(decision === "deny" ? { reason: missing ? "required_param_missing" : "rule_failed" } : {}),
  };
}

export interface VerifyInput {
  presentation: VerifiablePresentation;
  executionParams?: Record<string, unknown>;
}

/**
 * After a signature matches: read the credential's spec version and fail closed if
 * it is one this SDK does not understand — an absent marker included, since pre-0.2
 * artifacts no longer exist — otherwise run the v0.2-new §8 checks and tag the result.
 */
async function finish(
  vp: VerifiablePresentation,
  input: VerifyInput,
  deps: VerifyDeps,
): Promise<VerifyResult> {
  const specVersion = detectSpecVersion(vp);
  if (specVersion === "unknown") {
    return { ...deny("unsupported_spec_version", vp.verifiableCredential?.id), specVersion };
  }
  return { ...(await runChecks(vp, input.executionParams ?? {}, deps)), specVersion };
}

/** Verify a presentation (spec v0.2-new §8). No top-level action — read from `mandate.action`. */
export async function verify(input: VerifyInput, deps: VerifyDeps): Promise<VerifyResult> {
  const vp = input.presentation;
  const sig = await verifyVpSignature(vp, deps);
  if (sig !== "ok") return deny(sig, vp.verifiableCredential?.id);
  return finish(vp, input, deps);
}
