// Agent-binding verification (§16.7 / §16.11 — agent-direct). Three entry points:
//  • verifyAgentBinding — the PoP identity checks A1–A6 + A8 (pure; returns the
//    validated rung as an `agent.*` env). A7 (the rung floor) is CEL over `agent.*`
//    at step 8, not a separate check (§16.8 / C1).
//  • verifyAgentDirect — the full §16.11 flow: status/validity/audience + A1–A8 +
//    the action CEL (with the rung env) + step-up → `rechallenge` (D7).
//  • verifyAgentCall — §21.3's policy-first flow: the proof once, the policy's entry
//    or its default, and the mandate only where the entry asks for one.
import { actionHash, decodePoP, policyActionHash, verifyPoPSignature } from "./pop.js";
import { jwkThumbprint } from "../crypto/p256.js";
import { evaluateRules, type RuleEvaluation } from "../cel/evaluate.js";
import { agentReasonForRule } from "./constraints.js";
import { constantValues, unwrapUserParamValues, validateExecutionParams } from "../action/execution-params.js";
import { actionDigestSRI } from "../action/build.js";
import type { AccreditationRevocationReason } from "../operator/types.js";
import type { ActionDetail } from "../action/types.js";
import { boundKeyVerifiedAtMs, type AgentReasonCode, type Assurance, type Binding, type BoundKey, type Root } from "./types.js";
import type {
  CredentialStatus,
  DecisionEnforcement,
  Enforcement,
  MandateDescription,
  MandateStepUp,
  StepUpTrigger,
  ViaMandateCredential,
} from "../types.js";
import { enforcementFitsShape, enforcementOf, mayWidenAuthority } from "../mandate/description.js";
import { EXT_SEMANTIC_REVIEW, MAX_EXECUTIONS_REACHED, unsupportedCriticalExtension, verifyStamp, type ResolvePublicKey } from "../mandate/build.js";
import { detectSpecVersion } from "../version.js";
import { policyDefault } from "../policy/build.js";
import { evaluatePolicy, isUnder, type PolicyEvaluationDeps } from "../policy/evaluate.js";
import type { PolicyGuardrailRef, PolicyVersion } from "../policy/types.js";

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
  /** The mandate the call is made under — or, with no mandate, `policy` (§21.4). Exactly one. */
  mandateId?: string;
  /** §21.4 — the organization's policy, by URN, for a call with no mandate. */
  policy?: string;
  action: string;
  params: Record<string, unknown>;
}
export interface PopCheckDeps {
  /**
   * A5 — single-use/freshness of the PoP nonce; returns 'ok' or a deny reason. REQUIRED (0.3.6): without
   * it a captured PoP replays for as long as its other checks hold, and the verifier would not know.
   */
  validateNonce: (nonce: string, mandateId: string) => string | Promise<string>;
  now?: Date;
}

/** The authority a PoP is bound to: the mandate's id, or with no mandate the policy's URN (§21.4). */
function boundAuthority(input: Pick<PopCheckInput, "mandateId" | "policy">): string {
  const authority = input.mandateId ?? input.policy;
  if (!authority || (input.mandateId && input.policy)) {
    throw new TypeError("VIA: a PoP is bound to a mandate or, with no mandate, to a policy — exactly one (v0.3 §21.4)");
  }
  return authority;
}

/** A verifier wired without A5 is misconfigured, not presented a bad call: thrown, never a deny on the agent. */
function requireNonceCheck(deps: { validateNonce?: unknown }): void {
  if (typeof deps.validateNonce !== "function") {
    throw new TypeError("VIA: verifying a PoP requires deps.validateNonce (v0.3 §16.7 A5) — no nonce check is wired");
  }
}
export interface PopCheckResult {
  ok: boolean;
  reason?: AgentReasonCode;
  agent?: AgentEnv;
  boundKey?: BoundKey;
  /** §16.6 — the `action_hash` the PoP bound, checked: the call's fingerprint a decision event records (§2). */
  actionHash?: string;
}

/** §16.7 A1–A6 + A8 — decode, select the bound key, verify the signature, aud, nonce, action_hash, staleness. */
export async function verifyAgentBinding(input: PopCheckInput, deps: PopCheckDeps): Promise<PopCheckResult> {
  requireNonceCheck(deps ?? {});
  const d = decodePoP(input.pop); // A1: typ/alg/structure
  if (!d.ok || !d.payload || !d.jkt) return { ok: false, reason: d.reason ?? "pop_invalid" };

  const bk = input.authorizedAgents.find((k) => jwkThumbprint(k.cnf.jwk) === d.jkt); // A2
  if (!bk) return { ok: false, reason: "agent_not_bound" };

  if (!(await verifyPoPSignature(input.pop, bk.cnf.jwk))) return { ok: false, reason: "pop_invalid" }; // A3
  if (d.payload.aud !== input.verifier) return { ok: false, reason: "aud_mismatch" }; // A4

  const authority = boundAuthority(input);
  const nonce = await deps.validateNonce(d.payload.nonce, authority); // A5
  if (nonce !== "ok") return { ok: false, reason: nonce as AgentReasonCode };

  const expected = input.policy
    ? policyActionHash(input.policy, input.action, input.params)
    : actionHash(input.mandateId!, input.action, input.params);
  if (d.payload.action_hash !== expected) {
    return { ok: false, reason: "action_hash_mismatch" }; // A6
  }

  // A8
  if (attestationStale(bk, deps.now ?? new Date())) return { ok: false, reason: "attestation_stale" };

  return { ok: true, boundKey: bk, agent: agentEnvOf(bk), actionHash: expected };
}

/**
 * §16.7 A8 — the key's attestation is older than its entry's re-attest window. `verifiedAt` is ISO on the wire (v0.3)
 * or epoch ms (v0.2-signed); compared in ms either way. An unparseable instant on an entry WITH a window is stale:
 * `now - NaN > x` is false, so the condition is written to fail closed rather than fall through.
 */
function attestationStale(bk: BoundKey, now: Date): boolean {
  return bk.maxAttestationStaleness !== undefined && !(now.getTime() - boundKeyVerifiedAtMs(bk) <= bk.maxAttestationStaleness * 1000);
}

/** §16.8 — the validated rung of the entry whose key signed, as the CEL `agent.*` reads it. */
function agentEnvOf(bk: BoundKey): AgentEnv {
  return {
    assurance: bk.assurance,
    binding: bk.binding,
    root: bk.root,
    verifiedAt: boundKeyVerifiedAtMs(bk),
    ...(bk.did ? { did: bk.did } : {}),
    ...(bk.keyId ? { keyId: bk.keyId } : {}),
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
   * inactive record with this set denies `max_executions_reached`, not `credential_revoked` — used
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
   * through each entry's CURRENT actor (merge followed, status gated, operator checked — an agent
   * acts only for the mandate's subject organization, §8 step 3 — pinned key walked). Passed
   * BESIDE the mandate, never written into it: the mandate must stay the body its STAMP signs.
   * REQUIRED when the mandate binds agents (0.3.6): there is no offline profile (§8), so a mandate
   * with `authorizedAgents` and no candidates is denied `actor_unresolvable` — read as written, a
   * suspended agent or a revoked key would pass. A verifier with no actor access resolves each entry
   * from its DID document.
   */
  candidates?: BoundKey[];
  loadCredentialRecord: (urn: string) => CredentialRecordLike | Promise<CredentialRecordLike>;
  loadActionVersion: (actionId: string) => ActionDetail | null | Promise<ActionDetail | null>;
  /** §16.7 A5 — required, as for {@link verifyAgentBinding}. */
  validateNonce: (nonce: string, mandateId: string) => string | Promise<string>;
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
  /**
   * §21.3 — whether one of the policy's approvers confirmed this call (verified elsewhere). A step-up the
   * policy asks for is theirs, not the grantor's, under a mandate too.
   */
  policyStepUpSatisfied?: boolean;
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
  /**
   * v0.3 §21.3 — the current version of the policy of the agent's operator, the organization the §8
   * step 3 walk ends at. It caps the call after the mandate's rules and before the step-up. Absent when
   * the organization has published none.
   */
  policy?: PolicyVersion;
  /** §21.1 — every tool any published version of a guardrail lists; required when the policy targets guardrails. */
  guardrailTools?: PolicyEvaluationDeps["guardrailTools"];
  /**
   * §21.1 — every published version of an action, by any of them; required when the policy names `under` for a tool
   * a call under a mandate makes.
   */
  actionVersions?: PolicyEvaluationDeps["actionVersions"];
}

/** The fields of `accreditation.*` a rule may read — v0.3 §18.6, a closed list. */
export const ACCREDITATION_ENV_FIELDS = ["level", "method", "registrar", "verifiedAt"] as const;

/**
 * What a rule sees of an accreditation (v0.3 §18.6): the four listed fields and nothing a loader
 * happens to return beside them. A field one verifier projects and another does not makes the same
 * mandate allow here and deny there, so the list is closed HERE, where every loader's answer passes.
 *
 * Two that are deliberately absent: when the claim lapses — O4 denies an expired claim before any
 * rule runs, so a rule has nothing to decide — and the operator's organization, which is
 * `agent.operator.org` (§9.3), a relationship and not a standing.
 */
export function projectAccreditation(loaded: Record<string, unknown>): Record<string, unknown> {
  const env: Record<string, unknown> = {};
  for (const field of ACCREDITATION_ENV_FIELDS) {
    if (loaded[field] !== undefined && loaded[field] !== null) env[field] = loaded[field];
  }
  // An accreditation with no level is the bottom of the ladder, never an object a rank cannot read.
  if (env.level === undefined) env.level = "unverified";
  return env;
}

/**
 * What the accreditation loader may answer (v0.3 §18.5): the env to evaluate, nothing at all, or a
 * FAILURE that denies.
 *
 * O1–O4 are ordered and "the first failure denies" — so an expired or revoked operator credential
 * cannot be projected as data and left for a rule to notice. Quietly downgrading it to `unverified`
 * would pass any floor written at `unverified`, which is the opposite of what decay means.
 */
export type AccreditationLoad =
  | Record<string, unknown>
  | undefined
  // `revocationReason` with `accreditation_revoked`: why a registrar withdrew it for cause (v0.3 §18.2).
  | { denied: true; reason: string; revocationReason?: AccreditationRevocationReason };

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
  enforcement?: DecisionEnforcement;
  /** §17.4 — set on a `rechallenge`: who demanded the co-sign, and why. Recorded on the event (§9.9). */
  stepUp?: { trigger: StepUpTrigger; reason: string };
  /** §20.6 — the reviewer that took part, for the audit record (§9.9). */
  reviewer?: { id: string; version?: string };
  /** §18.5 O3 — with `accreditation_revoked`: why the registrar withdrew the accreditation (§18.2). */
  revocationReason?: AccreditationRevocationReason;
  /**
   * §0.6.1 — set on an `allow` for a tool the version marks unrestricted: no rule ran, on purpose, and
   * the decision says so rather than reading like a call the rules checked.
   */
  unrestricted?: true;
  /** §21.3 — the organization's policy version the call was checked against, under a mandate or not. */
  policyDigest?: string;
  /** §2, §16.6 — the `action_hash` the call's PoP bound, once checked: what its decision event records of the call. */
  actionHash?: string;
  /** §21.4–§21.5 — a call with no mandate: the policy's URN and the agent's DID, which name its chain. */
  policy?: string;
  agentDid?: string;
  /** §21.3 — on a `rechallenge` under the policy: the members who may confirm the call. */
  approvers?: string[];
  /** §21.3 — on `mandate_required`: the actions a mandate may be under, any one of them, for the agent to ask for. */
  under?: PolicyGuardrailRef[];
  /** §21.3 — no entry applied to the call: the policy's `default` decided it. */
  unset?: true;
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
 *   actor (§8 steps 2–4 — follow a merge, gate on status and operator, walk the pinned key) and pass the
 *   resulting set as `deps.candidates`. This function does not resolve actors.
 */
export async function verifyAgentDirect(
  mandate: ViaMandateCredential,
  req: { pop: string; action: string; params: Record<string, unknown> },
  deps: AgentDirectDeps,
): Promise<AgentDirectResult> {
  requireNonceCheck(deps);
  const urn = mandate.id;
  const m = mandate.credentialSubject.mandate;
  const now = deps.now ?? new Date();
  // §20.3 — what governs this mandate, carried on every result below. Derived for artifacts
  // issued before §20; the field wins wherever it is present.
  const enforcement = enforcementOf(m);
  // §8 step 1 to step 4: the mandate's STAMP and shape, its trusted record, its audience.
  const refused = await mandateAuthority(mandate, () => deps.loadCredentialRecord(urn), deps, now);
  if (refused) return refused;

  // 5. agent binding is REQUIRED when the mandate carries authorizedAgents (§16.4)
  // Bound or not is the SIGNED mandate's question; which keys may sign is step 0's answer.
  const signed = m.context.authorizedAgents;
  // §16.7 step 0 is the caller's, and not optional: entries read as written skip the actor gate.
  if (signed?.length && !deps.candidates) return deny("actor_unresolvable", urn, enforcement);
  const boundKeys = signed?.length ? withSignedWindow(deps.candidates!, signed) : signed;
  if (!boundKeys || boundKeys.length === 0) return deny("agent_not_bound", urn, enforcement);
  const pop = await verifyAgentBinding(
    { authorizedAgents: boundKeys, pop: req.pop, verifier: deps.verifier.did, mandateId: urn, action: req.action, params: req.params },
    { validateNonce: deps.validateNonce, now },
  );
  if (!pop.ok || !pop.agent) return deny(pop.reason ?? "pop_invalid", urn, enforcement);
  // §2, §16.6 — what the call's PoP bound, on every answer after it, as `verifyAgentCall` gives it.
  const proof = pop.actionHash ? { actionHash: pop.actionHash } : {};
  const done = (result: AgentDirectResult): AgentDirectResult => ({ ...result, ...proof });
  // §16.6: the call names its action once. When the params carry a discriminator (`tool`, or
  // `action`), it MUST be the action presented — otherwise the step-up decision reads one name and
  // the rules another, and a call named `Wire_Transfer` with `params.tool: "wire_transfer"` passes
  // the rules for the real tool while dodging the step-up that tool requires.
  if (discriminatorMismatch(req.action, req.params)) return done(deny("action_mismatch", urn, enforcement));

  // A step-up is decided AFTER authority (S7). It used to be raised here, before the params and
  // the rules were looked at, so a call the rules would deny sent a person to their authenticator
  // first — consent fatigue bought with a decision that was wrong anyway.
  // Two sources ask before a call settles (§17.4): the pinned action (`action` — the tool in its
  // `stepUp.tools`, or the caller's `requiresStepUp`) and the mandate itself (`mandate` in
  // `mandate.stepUp.triggers` — every call). The action's own list is read once the mandate's pass
  // has loaded it, below.
  const callerAsks = deps.requiresStepUp ? await deps.requiresStepUp(req.action, req.params) : false;
  const mandateAsks = m.stepUp?.triggers?.includes("mandate") ?? false;
  // §21.3 step 4 — the organization's policy caps the call: after the mandate's rules, before the step-up.
  // A `deny` or a failing `rules` entry refuses, and so does a `mandate` entry naming an `under` this mandate is not
  // on (`mandate_required`); `allow`, any other `mandate` and no entry leave the mandate's decision standing, since
  // an allow cannot widen a mandate. A step-up its action asks for is the grantor's.
  const policyMark = deps.policy ? { policyDigest: deps.policy.policyDigest } : {};
  let policyApprovers: string[] | undefined;
  const capped = async (): Promise<AgentDirectResult | null> => {
    if (!deps.policy) return null;
    const verdict = await evaluatePolicy(
      deps.policy.content,
      {
        tool: req.action,
        params: req.params,
        agent: _celAgent(deps.agentEnvExtras, pop.agent),
        mandate: m.action ? "guardrail" : "authorization",
        ...(m.action ? { mandateAction: m.action.id } : {}),
      },
      {
        loadActionVersion: deps.loadActionVersion,
        ...(deps.guardrailTools ? { guardrailTools: deps.guardrailTools } : {}),
        ...(deps.actionVersions ? { actionVersions: deps.actionVersions } : {}),
        ...(deps.loadAccreditation ? { loadAccreditation: projectedLoader(deps.loadAccreditation) } : {}),
      },
    );
    if (verdict.outcome === "deny") {
      const under = verdict.under ? { under: verdict.under } : {};
      return { ...deny(verdict.reason ?? "policy_denied", urn, enforcement), evaluations: verdict.evaluations, agent: pop.agent, ...policyMark, ...under };
    }
    policyApprovers = verdict.stepUp?.approvers;
    return null;
  };
  // §21.3 — a confirmation goes to whoever wrote the rule that asks for it: the policy's to its approvers,
  // after the grantor's. With no approver named it cannot be asked: `stepup_required`.
  const askApprovers = (evaluations: RuleEvaluation[] = []): AgentDirectResult | null => {
    if (!policyApprovers || deps.policyStepUpSatisfied) return null;
    if (policyApprovers.length === 0) return { ...deny("stepup_required", urn, enforcement), evaluations, agent: pop.agent, ...policyMark };
    return {
      decision: "rechallenge",
      credentialId: urn,
      reason: "stepup_required",
      evaluations,
      agent: pop.agent,
      enforcement,
      stepUp: { trigger: "policy", reason: "stepup_required" },
      approvers: policyApprovers,
      ...policyMark,
    };
  };
  const askStepUp = (trigger: StepUpTrigger, reason: string, evaluations: RuleEvaluation[] = []): AgentDirectResult => ({
    decision: "rechallenge",
    credentialId: urn,
    reason,
    evaluations,
    agent: pop.agent,
    enforcement,
    stepUp: { trigger, reason },
    ...policyMark,
  });

  // 6–9. What the mandate itself says of the call: its words, or its pinned action, the call inputs and the rules.
  const passed = await decideUnderMandate(mandate, req, pop.agent, deps);
  if (!("pass" in passed)) return done(passed);
  const named = passed.reviewer ? { reviewer: passed.reviewer } : {};
  // §17.4: the reviewer may take a call to the person only where the mandate permits it —
  // `verifier` in `triggers`, and the reason in `reasons` when that list is present. Otherwise
  // the call it could not settle is a deny: nobody agreed to be asked.
  if (passed.escalate && !deps.stepUpSatisfied) {
    if (!verifierMayEscalate(m.stepUp, "semantic_review")) return done({ ...deny("semantic_review", urn, enforcement), ...named });
    return done({ ...askStepUp("verifier", "semantic_review"), ...named });
  }
  const capRefused = await capped();
  if (capRefused) return done({ ...capRefused, evaluations: [...passed.evaluations, ...capRefused.evaluations], ...named });
  // Authority passed — NOW a step-up is worth a person's attention (S7).
  const actionAsks = passed.stepUpTool === true || callerAsks;
  if ((mandateAsks || actionAsks) && !deps.stepUpSatisfied) {
    return done({ ...askStepUp(mandateAsks ? "mandate" : "action", "stepup_required", passed.evaluations), ...named });
  }
  const staff = askApprovers(passed.evaluations);
  if (staff) return done({ ...staff, ...named });
  return done({
    decision: "allow",
    credentialId: urn,
    evaluations: passed.evaluations,
    agent: pop.agent,
    enforcement,
    ...(passed.unrestricted ? { unrestricted: true as const } : {}),
    ...policyMark,
    ...named,
  });
}

/**
 * §8 step 1 and §16.11 steps 2–4 — the mandate's own authority, before any key or rule: its STAMP, a spec version
 * and extensions this SDK understands, an enforcement that fits its shape, its trusted record (status, dates) and
 * this verifier among those it authorizes. A deny, or null when it holds. `loadRecord` runs once the STAMP holds.
 */
async function mandateAuthority(
  mandate: ViaMandateCredential,
  loadRecord: () => CredentialRecordLike | Promise<CredentialRecordLike>,
  deps: Pick<AgentDirectDeps, "resolvePublicKey" | "verifier">,
  now: Date,
): Promise<AgentDirectResult | null> {
  const urn = mandate.id;
  const m = mandate.credentialSubject.mandate;
  const enforcement = enforcementOf(m);
  // §8 step 1: the mandate's own STAMP, first. A copy edited after issuance verifies nothing.
  const stamp = await verifyStamp(mandate, deps.resolvePublicKey);
  if (!stamp.valid) return deny("credential_stamp_invalid", urn, enforcement);
  // §0.13 / §16.10: a version this SDK does not understand fails closed, as on the presentation path.
  if (detectSpecVersion(mandate) === "unknown") return deny("unsupported_spec_version", urn, enforcement);
  // §19.2: a critical extension this verifier does not implement is denied, never ignored. Agent-direct
  // implements semantic review (with a reviewer wired — without one §20.6 denies on its own).
  if (unsupportedCriticalExtension(m, AGENT_DIRECT_EXTENSIONS)) return deny("extension_unsupported", urn, enforcement);
  // §20.3: an enforcement that does not fit the mandate's shape fails open either way — refuse it.
  if (!enforcementFitsShape(m)) return deny("enforcement_invalid", urn, enforcement);

  // 2–3. status + validity (trusted record)
  const record = await loadRecord();
  if (record.status !== "ACTIVE") {
    return deny(record.exhausted ? MAX_EXECUTIONS_REACHED : `credential_${record.status.toLowerCase()}`, urn, enforcement);
  }
  if (record.validFrom && new Date(record.validFrom) > now) return deny("not_yet_valid", urn, enforcement);
  if (record.validUntil && new Date(record.validUntil) < now) return deny("expired", urn, enforcement);

  // 4. audience — the verifier must be authorized to use the mandate
  const authorizedDIDs = record.authorizedDIDs ?? m.context.authorizedDIDs;
  if (!authorizedDIDs.includes(deps.verifier.did)) return deny("verifier_not_authorized", urn, enforcement);
  return null;
}

/** What the mandate itself allows of a call (§16.11 steps 6–9), left for the caller to settle. */
interface MandatePass {
  pass: true;
  evaluations: RuleEvaluation[];
  /** §0.6.1 — the pinned version marks the tool unrestricted: no rule ran, on purpose. */
  unrestricted?: true;
  /** §20.6 — the reviewer that took part. */
  reviewer?: { id: string; version?: string };
  /** §20.6 — the reviewer could not settle the call: only a person could. */
  escalate?: true;
  /** §17.4 — the pinned action lists the tool under `stepUp.tools`: a person confirms each call of it. */
  stepUpTool?: true;
}

/**
 * §16.11 steps 6–9 — what the mandate itself says of a call whose authority and key have held: its words (a
 * reviewer, §20.6) or its pinned action (tool standing, call inputs, rules over `agent.*` and `accreditation.*`).
 * A deny, or a pass carrying what the caller settles after it: the policy, a step-up, approvers.
 */
async function decideUnderMandate(
  mandate: ViaMandateCredential,
  req: { action: string; params: Record<string, unknown> },
  agent: AgentEnv,
  deps: Pick<AgentDirectDeps, "review" | "loadActionVersion" | "loadAccreditation" | "agentEnvExtras">,
): Promise<AgentDirectResult | MandatePass> {
  const urn = mandate.id;
  const m = mandate.credentialSubject.mandate;
  const enforcement = enforcementOf(m);

  // 6. no action → the words govern, or nothing does (§20.3). `allow` now SAYS which.
  if (!m.action) {
    if (enforcement !== "semantic") return { pass: true, evaluations: [] };
    const reviewed = await reviewSemantic(m.description, req, urn, deps);
    const named = reviewed.reviewer ? { reviewer: reviewed.reviewer } : {};
    if (reviewed.denied) return { ...deny(reviewed.reason, urn, enforcement), ...named };
    return { pass: true, evaluations: [], ...named, ...(reviewed.escalate ? { escalate: true as const } : {}) };
  }

  // 6b. load + pin-check the ActionVersion
  const action = await deps.loadActionVersion(m.action.id);
  if (!action) return deny("action_not_found", urn, enforcement);
  if (m.action.digestSRI && actionDigestSRI(action) !== m.action.digestSRI) return deny("action_invalid", urn, enforcement);
  // §0.6.1, §0.8 — a version that lists its tools governs those alone. A tool it does not list is
  // refused, and so is a listed one it left undecided: a version no issuer should have published,
  // whose call every rule would `skip` straight into an allow.
  const standing = action.tools ? toolStanding(action, req.action) : "unlisted_version";
  if (standing === "not_covered") return deny("tool_not_covered", urn, enforcement);
  const unrestricted = standing === "unrestricted" ? ({ unrestricted: true } as const) : {};
  const asks = action.stepUp?.tools.includes(req.action) ? ({ stepUpTool: true } as const) : {};

  // 7. executionParams shape
  try {
    validateExecutionParams(action, req.params);
  } catch (e) {
    return deny(`execution_params_invalid:${(e as Error).message}`, urn, enforcement);
  }

  // 8. no rules → allow
  if (!action.rules || action.rules.length === 0) return { pass: true, evaluations: [], ...unrestricted, ...asks };

  // 9. CEL — with the rung env as `agent.*` (this is where A7 is enforced).
  // v0.3: the env EXTENDS with actor-projection fields (bootstrapAnchor, status)
  // supplied by the deployment — same namespace, no `actor.*` (v0.3 §9.3).
  const wantsAccreditation = action.rules.some((r) => String(r.expression ?? "").includes("accreditation"));
  const loaded = wantsAccreditation && deps.loadAccreditation ? await deps.loadAccreditation() : undefined;
  // §18.5 — O1–O4 are ordered and the first failure denies. `accreditation_expired` and
  // `accreditation_revoked` are decisions, not data for a rule to weigh.
  const failure = loaded && "denied" in loaded ? (loaded as Extract<AccreditationLoad, { denied: true }>) : null;
  if (failure) {
    return { ...deny(failure.reason, urn, enforcement), ...(failure.revocationReason ? { revocationReason: failure.revocationReason } : {}) };
  }
  // §18.6 — an operator with no ACCREDITED is the unverified tier, not an absent object: a rule like
  // `amount <= 1000 || accreditationRank(...) >= …` must still allow the small call. Only a verifier
  // with no loader at all (accreditation not implemented) leaves it out — and the rule then denies.
  const accreditation = loaded
    ? projectAccreditation(loaded as Record<string, unknown>)
    : wantsAccreditation && deps.loadAccreditation ? { level: "unverified" } : undefined;
  const { decision, evaluations } = evaluateRules(action.rules, {
    userParams: unwrapUserParamValues(m.userParams),
    constants: constantValues(action),
    // §16.6: the tool is the action presented — the PoP signs it, and a different `params.tool` was
    // refused above. Read from the params alone, a call that left `tool` out skipped every
    // `appliesTo` rule, so a missing input widened authority.
    executionParams: { ...req.params, tool: req.action },
    agent: _celAgent(deps.agentEnvExtras, agent),
    ...(accreditation ? { accreditation } : {}),
  });
  if (decision === "allow") return { pass: true, evaluations, ...unrestricted, ...asks };

  // map the first failing rule to a specific agent reason (A7) or the generic rule_failed
  const firstFail = evaluations.find((e) => e.result === "fail" || e.result === "error");
  // S13 — a governed call that omitted a required parameter is its own answer, not `rule_failed`:
  // the rule did not fail, the call never carried what the rule constrains.
  const missing = firstFail?.reason?.startsWith("required_param_missing") ? "required_param_missing" : null;
  const reason = missing ?? (firstFail && agentReasonForRule(firstFail.rule)) ?? "rule_failed";
  return { decision: "deny", credentialId: urn, reason, evaluations, agent, enforcement };
}

/**
 * §0.6.1 — where a tool stands in a version that lists its tools: limited by a rule that governs it,
 * marked unrestricted, or not covered (unlisted, or listed and left undecided). A tool both limited and
 * marked — a version the publish check refuses — is `limited`: its rules run, and nothing says no rule did.
 */
function toolStanding(action: Pick<ActionDetail, "rules" | "tools" | "unrestricted">, tool: string): "limited" | "unrestricted" | "not_covered" {
  if (!action.tools?.includes(tool)) return "not_covered";
  if ((action.rules ?? []).some((r) => !r.appliesTo?.length || r.appliesTo.includes(tool))) return "limited";
  return action.unrestricted?.includes(tool) ? "unrestricted" : "not_covered";
}

/** §18.6 — the accreditation loader, its answer projected to the fields a rule may read. */
function projectedLoader(load: NonNullable<AgentDirectDeps["loadAccreditation"]>): NonNullable<PolicyEvaluationDeps["loadAccreditation"]> {
  return async () => {
    const loaded = await load();
    if (!loaded) return undefined;
    if ("denied" in loaded && loaded.denied === true) return { denied: true, reason: String(loaded.reason) };
    return projectAccreditation(loaded as Record<string, unknown>);
  };
}

/** A mandate the verifier holds, read by its id for {@link verifyAgentCall} (§16.11 step 1). */
export interface HeldMandate {
  /** The body the verifier LOADED by its id, untouched: its STAMP is checked here, so any edit is refused. */
  mandate: ViaMandateCredential;
  /** Its trusted record: status, dates, audience. */
  record: CredentialRecordLike;
  /**
   * §16.7 step 0 — the mandate's `authorizedAgents`, each resolved through its CURRENT actor, as
   * {@link AgentDirectDeps.candidates} are. Required when the mandate binds agents.
   */
  candidates?: BoundKey[];
  /** A refusal the verifier reached on its own record of the mandate before the SDK reads it (a cancelled request). */
  denied?: string;
}

/** One agent tool call as {@link verifyAgentCall} takes it (§16.11, §21.4). */
export interface AgentCallRequest {
  /** The agent the caller resolved: its DID names the policy lane (§21.5). */
  agentDid: string;
  pop: string;
  /** The tool the call presents (§16.6). */
  action: string;
  params: Record<string, unknown>;
  /** A mandate the agent presents; its PoP then binds the mandate. Read only for a `mandate` entry (§21.3). */
  mandateId?: string;
  /** With no mandate presented: the policy the PoP binds, as the challenge named it (§21.4). */
  policy?: string;
}

export interface AgentCallDeps
  extends Pick<AgentDirectDeps, "resolvePublicKey" | "loadActionVersion" | "review" | "agentEnvExtras" | "loadAccreditation" | "now"> {
  /** The calling verifier's identity (the PoP `aud`). */
  verifier: { did: string };
  /**
   * §21.4 — the agent's usable keys (§7), resolved through its CURRENT actor as §8 steps 2–4 resolve a bound
   * agent: the keys a proof may be made with, whichever authority it names.
   */
  candidates: BoundKey[];
  /** §21.2 — the current version of the agent's operator's policy. Every organization has one: v0 at the least. */
  policy: PolicyVersion;
  /** §16.7 A5 — the nonce the challenge issued for the authority the PoP names: the mandate, or the policy. */
  validateNonce: (nonce: string, authority: string) => string | Promise<string>;
  /** §21.1 — every tool any published version of a guardrail lists; required when the policy targets guardrails. */
  guardrailTools?: PolicyEvaluationDeps["guardrailTools"];
  /** §21.1 — every published version of an action, by any of them; required when a `mandate` entry names `under`. */
  actionVersions?: PolicyEvaluationDeps["actionVersions"];
  /** The mandate presented, by its id; null when the verifier holds none of that id. Called only for a `mandate` entry. */
  loadMandate?: (mandateId: string) => HeldMandate | null | Promise<HeldMandate | null>;
}

/** What {@link verifyAgentCall} answers: allow or deny, never `rechallenge` (§17.4: it asks no person). */
export type AgentCallResult = Omit<AgentDirectResult, "decision" | "stepUp" | "approvers"> & { decision: "allow" | "deny" };

/**
 * §21.3 — one agent tool call, decided policy first. The agent's PoP is checked once, against its own usable keys,
 * over the authority it names: the mandate it presents, or the organization's policy. Then the policy's entry for
 * the tool and the agent decides: `allow`, `deny`, `rules` (its action's rules), or `mandate`. No entry applying is
 * the policy's `default`: `allow` is observed (`enforcement: "none"`, `unset`), `deny` is `policy_denied`.
 *
 * A mandate is read only for a `mandate` entry, and a mandate presented for any other is ignored, never loaded. Under
 * a `mandate` entry the mandate must be held, hold its own authority (§16.11 steps 1–4), be under the entry's action
 * when it names one, bind the key that proved, and allow the call itself (its words, or its pinned action's rules).
 *
 * This verifier asks no person to confirm a call: whatever would ask one (a policy action's or a mandate's step-up, a
 * reviewer that could not settle the call) refuses it, and nothing answers `rechallenge`. Every result names its
 * chain: `credentialId` for a decision taken on a mandate, else the policy lane (`policy`, `agentDid`, §21.5).
 */
export async function verifyAgentCall(req: AgentCallRequest, deps: AgentCallDeps): Promise<AgentCallResult> {
  requireNonceCheck(deps);
  if (!req.mandateId === !req.policy) {
    throw new TypeError("VIA: a call names the mandate its PoP binds or, with none, the policy — exactly one (v0.3 §21.4)");
  }
  const now = deps.now ?? new Date();
  const policyUrn = deps.policy.content.$id;
  const policyDigest = deps.policy.policyDigest;
  const onLane = (decision: AgentCallResult["decision"], extra: Partial<AgentCallResult> = {}): AgentCallResult => ({
    decision,
    evaluations: [],
    enforcement: "policy",
    policy: policyUrn,
    agentDid: req.agentDid,
    policyDigest,
    ...extra,
  });
  if (!deps.candidates?.length) return onLane("deny", { reason: "agent_not_bound" });

  // §16.7 A1–A6 + A8 — once, against the agent's own keys, over the authority the PoP names.
  const authority = req.mandateId ? { mandateId: req.mandateId } : { policy: req.policy };
  const pop = await verifyAgentBinding(
    { authorizedAgents: deps.candidates, pop: req.pop, verifier: deps.verifier.did, ...authority, action: req.action, params: req.params },
    { validateNonce: deps.validateNonce, now },
  );
  if (!pop.ok || !pop.agent || !pop.boundKey) return onLane("deny", { reason: pop.reason ?? "pop_invalid" });
  const agent = pop.agent;
  const proof = pop.actionHash ? { actionHash: pop.actionHash } : {};
  if (discriminatorMismatch(req.action, req.params)) return onLane("deny", { reason: "action_mismatch", agent, ...proof });
  // A PoP over the policy binds the one being read: the organization's own.
  if (!req.mandateId && req.policy !== policyUrn) return onLane("deny", { reason: "policy_denied", agent, ...proof });

  // The policy decides first. No mandate kind is passed: a mandate is read below, and only for a `mandate` entry.
  const verdict = await evaluatePolicy(
    deps.policy.content,
    { tool: req.action, params: req.params, agent: { ..._celAgent(deps.agentEnvExtras, agent), did: req.agentDid } },
    {
      loadActionVersion: deps.loadActionVersion,
      ...(deps.guardrailTools ? { guardrailTools: deps.guardrailTools } : {}),
      ...(deps.loadAccreditation ? { loadAccreditation: projectedLoader(deps.loadAccreditation) } : {}),
    },
  );
  const evaluations = verdict.evaluations;
  if (verdict.outcome === "deny") return onLane("deny", { reason: verdict.reason ?? "policy_denied", evaluations, agent, ...proof });
  // No entry: the policy's default decides, and every answer says so. An allow is observed — no rule of an entry ran
  // (§20.3 `none`); `mandate` goes on as a `mandate` entry naming no action.
  const unset = verdict.unset ? ({ unset: true } as const) : {};
  if (verdict.unset) {
    const byDefault = policyDefault(deps.policy.content);
    if (byDefault === "deny") return onLane("deny", { reason: "policy_denied", evaluations, agent, ...unset, ...proof });
    if (byDefault === "allow") return onLane("allow", { evaluations, agent, enforcement: "none", ...unset, ...proof });
  }
  if (verdict.outcome === "allow") {
    // A policy action asking a person to confirm the call: nobody is asked (§17.4), so it is refused.
    if (verdict.stepUp) return onLane("deny", { reason: "stepup_required", evaluations, agent, ...proof });
    return onLane("allow", { evaluations, agent, ...(verdict.unrestricted ? { unrestricted: true as const } : {}), ...proof });
  }
  const under = verdict.under;
  if (!req.mandateId) return onLane("deny", { reason: "mandate_required", evaluations, agent, ...(under ? { under } : {}), ...unset, ...proof });

  // `mandate`: the mandate presented decides, under the entry's action when it names one.
  if (!deps.loadMandate) {
    throw new TypeError("VIA: a `mandate` entry met a presented mandate, and no loadMandate is wired (v0.3 §21.3)");
  }
  const held = await deps.loadMandate(req.mandateId);
  if (!held) return onLane("deny", { reason: "mandate_not_found", evaluations, agent, ...unset, ...proof });
  // From here the decision is the mandate's, on its chain, with the policy version it was read under.
  const mandate = held.mandate;
  const urn = mandate.id;
  const m = mandate.credentialSubject.mandate;
  const enforcement = enforcementOf(m);
  // Each answer below is a refusal or the one approval: none of the checks it runs asks a person.
  const onMandate = (result: AgentDirectResult): AgentCallResult => ({
    ...result,
    decision: result.decision === "allow" ? "allow" : "deny",
    evaluations: [...evaluations, ...result.evaluations],
    policyDigest,
    ...unset,
    ...proof,
  });
  if (held.denied) return onMandate(deny(held.denied, urn, enforcement));
  const refused = await mandateAuthority(mandate, () => held.record, deps, now);
  if (refused) return onMandate(refused);
  if (under?.length) {
    const call = { tool: req.action, params: req.params, agent: {}, mandate: m.action ? ("guardrail" as const) : ("authorization" as const), ...(m.action ? { mandateAction: m.action.id } : {}) };
    const versions = { loadActionVersion: deps.loadActionVersion, ...(deps.actionVersions ? { actionVersions: deps.actionVersions } : {}) };
    if (!(await isUnder(call, under, versions))) return onMandate({ ...deny("mandate_required", urn, enforcement), under });
  }

  // §16.7 A2, A8 — the key that proved is one the mandate binds, inside the mandate's own re-attest window.
  const signed = m.context.authorizedAgents;
  if (signed?.length && !held.candidates) return onMandate(deny("actor_unresolvable", urn, enforcement));
  const proved = jwkThumbprint(pop.boundKey.cnf.jwk);
  const bound = (signed?.length ? withSignedWindow(held.candidates!, signed) : []).find((k) => jwkThumbprint(k.cnf.jwk) === proved);
  if (!bound) return onMandate(deny("agent_not_bound", urn, enforcement));
  if (attestationStale(bound, now)) return onMandate(deny("attestation_stale", urn, enforcement));
  const mandateAgent = agentEnvOf(bound);
  // §21.1 — the organization refuses plain authorizations: a mandate that pins no action.
  if (!m.action && deps.policy.content.authorizations === "deny") return onMandate({ ...deny("policy_denied", urn, enforcement), agent: mandateAgent });

  const passed = await decideUnderMandate(mandate, req, mandateAgent, deps);
  if (!("pass" in passed)) return onMandate(passed);
  const named = passed.reviewer ? { reviewer: passed.reviewer } : {};
  // Nobody is asked to confirm a call (§17.4): a reviewer that could not settle it, the mandate's own step-up or its
  // pinned action's refuses it.
  if (passed.escalate) return onMandate({ ...deny("semantic_review", urn, enforcement), agent: mandateAgent, ...named });
  if (m.stepUp?.triggers?.includes("mandate") || passed.stepUpTool) {
    return onMandate({ ...deny("stepup_required", urn, enforcement), evaluations: passed.evaluations, agent: mandateAgent, ...named });
  }
  return onMandate({
    decision: "allow",
    credentialId: urn,
    evaluations: passed.evaluations,
    agent: mandateAgent,
    enforcement,
    ...(passed.unrestricted ? { unrestricted: true as const } : {}),
    ...named,
  });
}

/** §16.6 — the params name a tool other than the action presented. */
export function discriminatorMismatch(action: string, params: Record<string, unknown>): boolean {
  for (const name of ["tool", "action"] as const) {
    if (name in params && params[name] !== action) return true;
  }
  return false;
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
  deps: Pick<AgentDirectDeps, "review">,
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

/**
 * v0.3 §9.3 — what rules read of the agent: the projection and the presenting key's rung, never its `keyId`. A key's id
 * changes when it rotates and a raw-key pin has none, so a rule over it would start denying; the decision event records
 * it as `keyIdEvaluated` (§9.9), from the PoP's result (2026-10-26).
 */
function _celAgent(extras: Record<string, unknown> | undefined, agent: AgentEnv | undefined): Record<string, unknown> {
  const { keyId: _keyId, ...rule } = { ...(extras ?? {}), ...agent } as Record<string, unknown>;
  return rule;
}
