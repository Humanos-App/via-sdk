// Agent-binding verification (§16.7 / §16.11 — agent-direct). Two entry points:
//  • verifyAgentBinding — the PoP identity checks A1–A6 + A8 (pure; returns the
//    validated rung as an `agent.*` env). A7 (the rung floor) is CEL over `agent.*`
//    at step 8, not a separate check (§16.8 / C1).
//  • verifyAgentDirect — the full §16.11 flow: status/validity/audience + A1–A8 +
//    the action CEL (with the rung env) + step-up → `rechallenge` (D7).
import { actionHash, decodePoP, verifyPoPSignature } from "./pop.js";
import { jwkThumbprint } from "../crypto/p256.js";
import { evaluateRules, type RuleEvaluation } from "../cel/evaluate.js";
import { agentReasonForRule } from "./constraints.js";
import { unwrapUserParamValues, validateExecutionParams } from "../action/execution-params.js";
import { actionDigestSRI } from "../action/build.js";
import type { ActionDetail } from "../action/types.js";
import { boundKeyVerifiedAtMs, type AgentReasonCode, type Assurance, type Binding, type BoundKey, type Root } from "./types.js";
import type {
  CredentialStatus,
  Enforcement,
  MandateDescription,
  MandateStepUp,
  StepUpTrigger,
  ViaMandateCredential,
} from "../types.js";
import { enforcementFitsShape, enforcementOf, mayWidenAuthority } from "../mandate/description.js";
import { EXT_SEMANTIC_REVIEW, MAX_EXECUTIONS_REACHED, unsupportedCriticalExtension, verifyStamp, type ResolvePublicKey } from "../mandate/build.js";

/** The validated rung, surfaced into the CEL context as `agent.*` (§16.8). */
export interface AgentEnv {
  assurance: Assurance;
  binding: Binding;
  root?: Root;
  /** Epoch ms — normalized from the entry's wire encoding (§16.4 ISO, or v0.2 epoch). */
  verifiedAt: number;
  /** The entry's `did` (§16.4) — identity for rules (`agent.did`), never authentication. */
  did?: string;
  /** The selected key's id (§16.7 step 0 / §9.9 `keyIdEvaluated`) — present on an id-pinned entry. */
  keyId?: string;
}

export interface PopCheckInput {
  /**
   * Whose key is presenting — `agent` (the default) or `user`/`organization`. Selects the permitted
   * PoP algorithms (§16.6): agents ES256-only because §16.2 chose P-256 for keys the ISSUER
   * controls; a person's authenticator chooses for them, so RS256 and EdDSA are permitted there.
   */
  actorType?: string;
  authorizedAgents: BoundKey[];
  pop: string; // the via-pop+jwt JWS
  verifier: string; // aud
  mandateId: string;
  action: string;
  params: Record<string, unknown>;
}
export interface PopCheckDeps {
  /** A5 — single-use/freshness of the PoP nonce; returns 'ok' or a deny reason. */
  validateNonce?: (nonce: string, mandateId: string) => string | Promise<string>;
  now?: Date;
}
export interface PopCheckResult {
  ok: boolean;
  reason?: AgentReasonCode;
  agent?: AgentEnv;
  boundKey?: BoundKey;
}

/** §16.7 A1–A6 + A8 — decode, select the bound key, verify the signature, aud, nonce, action_hash, staleness. */
export async function verifyAgentBinding(input: PopCheckInput, deps: PopCheckDeps = {}): Promise<PopCheckResult> {
  const d = decodePoP(input.pop); // A1: typ/alg/structure
  if (!d.ok || !d.payload || !d.jkt) return { ok: false, reason: d.reason ?? "pop_invalid" };

  const bk = input.authorizedAgents.find((k) => jwkThumbprint(k.cnf.jwk) === d.jkt); // A2
  if (!bk) return { ok: false, reason: "agent_not_bound" };

  if (!(await verifyPoPSignature(input.pop, bk.cnf.jwk))) return { ok: false, reason: "pop_invalid" }; // A3
  if (d.payload.aud !== input.verifier) return { ok: false, reason: "aud_mismatch" }; // A4

  if (deps.validateNonce) {
    const r = await deps.validateNonce(d.payload.nonce, input.mandateId); // A5
    if (r !== "ok") return { ok: false, reason: r as AgentReasonCode };
  }

  if (d.payload.action_hash !== actionHash(input.mandateId, input.action, input.params)) {
    return { ok: false, reason: "action_hash_mismatch" }; // A6
  }

  // A8. `verifiedAt` is ISO on the wire (v0.3) or epoch ms (v0.2-signed); compare in ms either way.
  // An unparseable instant on an entry WITH a window denies: `now - NaN > x` is false, so the
  // condition is written to fail closed rather than fall through.
  const now = (deps.now ?? new Date()).getTime();
  const verifiedAtMs = boundKeyVerifiedAtMs(bk);
  if (bk.maxAttestationStaleness !== undefined && !(now - verifiedAtMs <= bk.maxAttestationStaleness * 1000)) {
    return { ok: false, reason: "attestation_stale" };
  }

  return {
    ok: true,
    boundKey: bk,
    agent: {
      assurance: bk.assurance,
      binding: bk.binding,
      root: bk.root,
      verifiedAt: verifiedAtMs,
      ...(bk.did ? { did: bk.did } : {}),
      ...(bk.keyId ? { keyId: bk.keyId } : {}),
    },
  };
}

/**
 * A candidate stands in for a SIGNED entry of the same actor, and that entry's re-attest window
 * (§16.4, A8) is a term of the mandate, not of the key: it holds whatever key now presents. A
 * candidate list built from the actor carries no window of its own, so without this A8 would never
 * run on an id-pinned mandate. Where several bounds apply, the strictest wins.
 */
function withSignedWindow(candidates: BoundKey[], signed: BoundKey[]): BoundKey[] {
  return candidates.map((c) => {
    // After a merge the candidate names the survivor, not the DID the entry signed; with no entry of
    // its own it is held to every entry's window rather than to none.
    const own = signed.filter((e) => e.did !== undefined && e.did === c.did);
    const windows = [c, ...(own.length ? own : signed)]
      .map((e) => e.maxAttestationStaleness)
      .filter((w): w is number => w !== undefined);
    return windows.length ? { ...c, maxAttestationStaleness: Math.min(...windows) } : c;
  });
}

export interface CredentialRecordLike {
  status: CredentialStatus;
  /**
   * §19.5 — the issuer's record says the grant is SPENT: its `maxExecutions` bound was used up. An
   * inactive record with this set denies `max_executions_reached`, not `credential_inactive` — used
   * exactly as agreed is not withdrawn. Only the issuer knows; a status bit alone cannot say why.
   */
  exhausted?: boolean;
  validFrom?: string;
  validUntil?: string;
  authorizedDIDs?: string[];
}

export interface AgentDirectDeps {
  /** The calling relying party's identity (the PoP `aud`). */
  verifier: { did: string };
  /**
   * v0.3 §8 step 1 — resolves the Humanos key the mandate's STAMP names. The mandate is checked
   * against its own STAMP before anything else: a body edited after issuance (its
   * `authorizedAgents`, its `action`, its `userParams`) is `credential_stamp_invalid`, never verified.
   */
  resolvePublicKey: ResolvePublicKey;
  /**
   * §16.7 step 0 — the candidate key set the caller resolved from the mandate's `authorizedAgents`
   * through each entry's CURRENT actor (merge followed, status gated, pinned key walked). Passed
   * BESIDE the mandate, never written into it: the mandate must stay the body its STAMP signs.
   * Absent, the entries are read as written (raw pins, or a caller with no actor access).
   */
  candidates?: BoundKey[];
  loadCredentialRecord: (urn: string) => CredentialRecordLike | Promise<CredentialRecordLike>;
  loadActionVersion: (actionId: string) => ActionDetail | null | Promise<ActionDetail | null>;
  validateNonce?: (nonce: string, mandateId: string) => string | Promise<string>;
  /** §17.4 — does this action/amount require a fresh grantor step-up? */
  requiresStepUp?: (action: string, params: Record<string, unknown>) => boolean | Promise<boolean>;
  /**
   * §20.6 — the semantic reviewer, called only for `enforcement: "semantic"`.
   *
   * WHICH reviewer is the verifier's own, like the challenge in §16.11: the mandate says one is
   * required, not who. Absence is not silence — a `semantic` mandate presented to a verifier with
   * no reviewer wired is `reviewer_unavailable`, a deny, because the alternative is allowing a
   * call under a mandate whose whole point is that something reads it first.
   */
  review?: (input: SemanticReviewInput) => SemanticReviewVerdict | Promise<SemanticReviewVerdict>;
  /** Whether a fresh grantor step-up assertion accompanied this request (verified elsewhere, §17.4). */
  stepUpSatisfied?: boolean;
  now?: Date;
  /**
   * v0.3 §9.3 — EXTENDED `agent.*` fields (bootstrapAnchor, status, …) merged
   * into the CEL env beside the shipped assurance/binding. There is no separate
   * `actor.*` namespace: the artifact is actor-generic, projections are
   * role-specific.
   *
   * The PoP's own fields WIN over these: `assurance`, `binding`, `root`, `verifiedAt` and `did` come
   * from the entry whose key just signed (§9.1bis rule 1), and an extra carrying an actor summary
   * must not replace them.
   */
  agentEnvExtras?: Record<string, unknown>;
  /**
   * v0.3 §18.5 — the presenting actor's OPERATOR's `accreditation` (its own, when it has no
   * operator), projected as `accreditation.*`. A loader, called only when a rule references
   * `accreditation`, so the extra actor resolution costs nothing otherwise. A rule that references
   * it while no loader is supplied errors in CEL and therefore denies (fail closed, §16.8).
   */
  loadAccreditation?: () => AccreditationLoad | Promise<AccreditationLoad>;
}

/**
 * What the accreditation loader may answer (v0.3 §18.5): the env to evaluate, nothing at all, or a
 * FAILURE that denies.
 *
 * O1–O4 are ordered and "the first failure denies" — so an expired or revoked operator credential
 * cannot be projected as data and left for a rule to notice. Quietly downgrading it to `unverified`
 * would pass any floor written at `unverified`, which is the opposite of what decay means.
 */
export type AccreditationLoad = Record<string, unknown> | undefined | { denied: true; reason: string };

/** §20.6 — what a reviewer is asked. The words, their author, and the call. */
export interface SemanticReviewInput {
  description: MandateDescription;
  action: string;
  params: Record<string, unknown>;
  mandateId: string;
}

/**
 * §20.6 — what a reviewer answers.
 *
 * `unavailable` is a first-class verdict rather than a thrown error, because it decides something:
 * it is the one answer that must never become `allow`.
 */
export interface SemanticReviewVerdict {
  verdict: "entailed" | "not_entailed" | "escalate" | "unavailable";
  reviewer?: { id: string; version?: string };
  reason?: string;
}

export interface AgentDirectResult {
  decision: "allow" | "deny" | "rechallenge";
  credentialId?: string;
  reason?: string;
  evaluations: RuleEvaluation[];
  agent?: AgentEnv;
  /**
   * §20.3 — which machinery actually governed this decision. Present on EVERY result: without it
   * an `allow` with no evaluations means both "no rules ran" and "rules ran and matched nothing".
   */
  enforcement?: Enforcement;
  /** §17.4 — set on a `rechallenge`: who demanded the co-sign, and why. Recorded on the event (§9.9). */
  stepUp?: { trigger: StepUpTrigger; reason: string };
  /** §20.6 — the reviewer that took part, for the audit record (§9.9). */
  reviewer?: { id: string; version?: string };
}

const deny = (reason: string, credentialId?: string, enforcement?: Enforcement): AgentDirectResult => ({
  decision: "deny",
  reason,
  credentialId,
  evaluations: [],
  ...(enforcement ? { enforcement } : {}),
});

/** §19.2 — the critical extensions this verifier implements. */
const AGENT_DIRECT_EXTENSIONS: ReadonlySet<string> = new Set([EXT_SEMANTIC_REVIEW]);

/**
 * Full agent-direct verify (§16.11). The agent presents `{ mandateId, action, params, pop }`; the
 * RP checks the mandate's STAMP (§8 step 1), authority (status/validity/audience),
 * identity+possession (A1–A8), and the rung floor + action rules as CEL over `agent.*`. Returns
 * `allow | deny | rechallenge`.
 *
 * The caller's contract:
 * - `mandate` is the body the verifier LOADED by its id (§8 step 1), untouched — never a copy the
 *   agent sent, and never edited by the caller. Its STAMP is checked here, so any edit is refused.
 * - Step 0 (§16.7) is the caller's: resolve every `authorizedAgents` entry through its CURRENT
 *   actor (§8 steps 2–4 — follow a merge, gate on status, walk the pinned key) and pass the
 *   resulting set as `deps.candidates`. This function does not resolve actors.
 */
export async function verifyAgentDirect(
  mandate: ViaMandateCredential,
  req: { pop: string; action: string; params: Record<string, unknown> },
  deps: AgentDirectDeps,
): Promise<AgentDirectResult> {
  const urn = mandate.id;
  const m = mandate.credentialSubject.mandate;
  const now = deps.now ?? new Date();
  // §20.3 — what governs this mandate, carried on every result below. Derived for artifacts
  // issued before §20; the field wins wherever it is present.
  const enforcement = enforcementOf(m);
  // §8 step 1: the mandate's own STAMP, first. A copy edited after issuance verifies nothing.
  const stamp = await verifyStamp(mandate, deps.resolvePublicKey);
  if (!stamp.valid) return deny("credential_stamp_invalid", urn, enforcement);
  // §19.2: a critical extension this verifier does not implement is denied, never ignored. Agent-direct
  // implements semantic review (with a reviewer wired — without one §20.6 denies on its own).
  if (unsupportedCriticalExtension(m, AGENT_DIRECT_EXTENSIONS)) return deny("extension_unsupported", urn, enforcement);
  // §20.3: an enforcement that does not fit the mandate's shape fails open either way — refuse it.
  if (!enforcementFitsShape(m)) return deny("enforcement_invalid", urn, enforcement);

  // 2–3. status + validity (trusted record)
  const record = await deps.loadCredentialRecord(urn);
  if (record.status !== "ACTIVE") {
    return deny(record.exhausted ? MAX_EXECUTIONS_REACHED : `credential_${record.status.toLowerCase()}`, urn, enforcement);
  }
  if (record.validFrom && new Date(record.validFrom) > now) return deny("not_yet_valid", urn, enforcement);
  if (record.validUntil && new Date(record.validUntil) < now) return deny("expired", urn, enforcement);

  // 4. audience — the verifier must be authorized to use the mandate
  const authorizedDIDs = record.authorizedDIDs ?? m.context.authorizedDIDs;
  if (!authorizedDIDs.includes(deps.verifier.did)) return deny("verifier_not_authorized", urn, enforcement);

  // 5. agent binding is REQUIRED when the mandate carries authorizedAgents (§16.4)
  // Bound or not is the SIGNED mandate's question; which keys may sign is step 0's answer.
  const signed = m.context.authorizedAgents;
  const boundKeys = signed?.length ? (deps.candidates ? withSignedWindow(deps.candidates, signed) : signed) : signed;
  if (!boundKeys || boundKeys.length === 0) return deny("agent_not_bound", urn, enforcement);
  const pop = await verifyAgentBinding(
    { authorizedAgents: boundKeys, pop: req.pop, verifier: deps.verifier.did, mandateId: urn, action: req.action, params: req.params },
    { validateNonce: deps.validateNonce, now },
  );
  if (!pop.ok || !pop.agent) return deny(pop.reason ?? "pop_invalid", urn, enforcement);

  // A step-up is decided AFTER authority (S7). It used to be raised here, before the params and
  // the rules were looked at, so a call the rules would deny sent a person to their authenticator
  // first — consent fatigue bought with a decision that was wrong anyway.
  // Two sources ask before a call settles (§17.4): the pinned action (`action`, the caller's
  // `requiresStepUp`) and the mandate itself (`mandate` in `mandate.stepUp.triggers` — every call).
  const actionAsks = deps.requiresStepUp ? await deps.requiresStepUp(req.action, req.params) : false;
  const mandateAsks = m.stepUp?.triggers?.includes("mandate") ?? false;
  const askStepUp = (trigger: StepUpTrigger, reason: string, evaluations: RuleEvaluation[] = []): AgentDirectResult => ({
    decision: "rechallenge",
    credentialId: urn,
    reason,
    evaluations,
    agent: pop.agent,
    enforcement,
    stepUp: { trigger, reason },
  });

  // 6. no action → the words govern, or nothing does (§20.3). `allow` now SAYS which.
  if (!m.action) {
    let reviewer: { id: string; version?: string } | undefined;
    if (enforcement === "semantic") {
      const reviewed = await reviewSemantic(m.description, req, urn, deps);
      reviewer = reviewed.reviewer;
      const named = reviewer ? { reviewer } : {};
      if (reviewed.denied) return { ...deny(reviewed.reason, urn, enforcement), ...named };
      // §17.4: the reviewer may take a call to the person only where the mandate permits it —
      // `verifier` in `triggers`, and the reason in `reasons` when that list is present. Otherwise
      // the call it could not settle is a deny: nobody agreed to be asked.
      if (reviewed.escalate && !deps.stepUpSatisfied) {
        if (!verifierMayEscalate(m.stepUp, "semantic_review")) return { ...deny("semantic_review", urn, enforcement), ...named };
        return { ...askStepUp("verifier", "semantic_review"), ...named };
      }
    }
    if ((mandateAsks || actionAsks) && !deps.stepUpSatisfied) {
      return { ...askStepUp("mandate", "stepup_required"), ...(reviewer ? { reviewer } : {}) };
    }
    return { decision: "allow", credentialId: urn, evaluations: [], agent: pop.agent, enforcement, ...(reviewer ? { reviewer } : {}) };
  }

  // 6b. load + pin-check the ActionVersion
  const action = await deps.loadActionVersion(m.action.id);
  if (!action) return deny("action_not_found", urn, enforcement);
  if (m.action.digestSRI && actionDigestSRI(action) !== m.action.digestSRI) return deny("action_invalid", urn, enforcement);

  // 7. executionParams shape
  try {
    validateExecutionParams(action, req.params);
  } catch (e) {
    return deny(`execution_params_invalid:${(e as Error).message}`, urn, enforcement);
  }

  // 8. no rules → allow
  if (!action.rules || action.rules.length === 0) {
    if ((mandateAsks || actionAsks) && !deps.stepUpSatisfied) return askStepUp(mandateAsks ? "mandate" : "action", "stepup_required");
    return { decision: "allow", credentialId: urn, evaluations: [], agent: pop.agent, enforcement };
  }

  // 9. CEL — with the rung env as `agent.*` (this is where A7 is enforced).
  // v0.3: the env EXTENDS with actor-projection fields (bootstrapAnchor, status)
  // supplied by the deployment — same namespace, no `actor.*` (v0.3 §9.3).
  const wantsAccreditation = action.rules.some((r) => String(r.expression ?? "").includes("accreditation"));
  const loaded = wantsAccreditation && deps.loadAccreditation ? await deps.loadAccreditation() : undefined;
  // §18.5 — O1–O4 are ordered and the first failure denies. `accreditation_expired` and
  // `accreditation_revoked` are decisions, not data for a rule to weigh.
  const failure = loaded && "denied" in loaded ? (loaded as { denied: true; reason: string }) : null;
  if (failure) return deny(failure.reason, urn, enforcement);
  // §18.6 — an operator with no ACCREDITED is the unverified tier, not an absent object: a rule like
  // `amount <= 1000 || accreditationRank(...) >= …` must still allow the small call. Only a verifier
  // with no loader at all (accreditation not implemented) leaves it out — and the rule then denies.
  const accreditation = loaded ?? (wantsAccreditation && deps.loadAccreditation ? { level: "unverified" } : undefined);
  const { decision, evaluations } = evaluateRules(action.rules, {
    userParams: unwrapUserParamValues(m.userParams),
    executionParams: req.params,
    agent: { ...(deps.agentEnvExtras ?? {}), ...pop.agent },
    ...(accreditation ? { accreditation } : {}),
  });
  if (decision === "allow") {
    // Authority passed — NOW a step-up is worth a person's attention (S7).
    if ((mandateAsks || actionAsks) && !deps.stepUpSatisfied) {
      return askStepUp(mandateAsks ? "mandate" : "action", "stepup_required", evaluations);
    }
    return { decision: "allow", credentialId: urn, evaluations, agent: pop.agent, enforcement };
  }

  // map the first failing rule to a specific agent reason (A7) or the generic rule_failed
  const firstFail = evaluations.find((e) => e.result === "fail" || e.result === "error");
  // S13 — a governed call that omitted a required parameter is its own answer, not `rule_failed`:
  // the rule did not fail, the call never carried what the rule constrains.
  const missing = firstFail?.reason?.startsWith("required_param_missing") ? "required_param_missing" : null;
  const reason = missing ?? (firstFail && agentReasonForRule(firstFail.rule)) ?? "rule_failed";
  return { decision: "deny", credentialId: urn, reason, evaluations, agent: pop.agent, enforcement };
}

/**
 * §17.4 — may a verifier-side escalation reach the person? Only when the mandate lists `verifier` in
 * `stepUp.triggers`, and — when it also lists `reasons` — only for a reason named there.
 */
export function verifierMayEscalate(stepUp: MandateStepUp | undefined, reason: string): boolean {
  if (!stepUp?.triggers?.includes("verifier")) return false;
  return stepUp.reasons === undefined || stepUp.reasons.includes(reason);
}

/**
 * §20.6 — hand the words and the call to the reviewer, and turn its verdict into a decision.
 *
 * The three failure shapes are deliberately distinct. No reviewer wired, or one that cannot be
 * reached, is `reviewer_unavailable` — never `allow`, because a mandate whose enforcement is a
 * reader is unenforced without one. Words the REQUESTER wrote (§20.2) may narrow authority but
 * never widen it, so an agent-authored description cannot produce an allow here: it is exactly the
 * text a persuasive agent would craft.
 */
async function reviewSemantic(
  description: MandateDescription | undefined,
  req: { action: string; params: Record<string, unknown> },
  urn: string,
  deps: AgentDirectDeps,
): Promise<{ denied?: false; escalate?: boolean; reviewer?: { id: string; version?: string } } | { denied: true; reason: string; reviewer?: { id: string; version?: string } }> {
  if (!description) return { denied: true, reason: "description_required" };
  if (!deps.review) return { denied: true, reason: "reviewer_unavailable" };
  const verdict = await deps.review({ description, action: req.action, params: req.params, mandateId: urn });
  const reviewer = verdict.reviewer;
  if (verdict.verdict === "unavailable") return { denied: true, reason: "reviewer_unavailable", ...(reviewer ? { reviewer } : {}) };
  if (verdict.verdict === "not_entailed") return { denied: true, reason: "semantic_denied", ...(reviewer ? { reviewer } : {}) };
  if (verdict.verdict === "escalate") return { escalate: true, ...(reviewer ? { reviewer } : {}) };
  if (!mayWidenAuthority(description)) {
    // `entailed`, but on words the requester wrote: the reviewer may not widen on those, so the
    // call is escalated to the person rather than allowed on the agent's own say-so.
    return { escalate: true, ...(reviewer ? { reviewer } : {}) };
  }
  return { ...(reviewer ? { reviewer } : {}) };
}
