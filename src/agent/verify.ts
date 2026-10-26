// Agent-binding verification (§16.7 / §16.11 — agent-direct). Two entry points:
//  • verifyAgentBinding — the PoP identity checks A1–A6 + A8 (pure; returns the
//    validated rung as an `agent.*` env). A7 (the rung floor) is CEL over `agent.*`
//    at step 8, not a separate check (§16.8 / C1).
//  • verifyAgentDirect — the full §16.11 flow: status/validity/audience + A1–A8 +
//    the action CEL (with the rung env) + step-up → `rechallenge` (D7).
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
import { evaluatePolicy, type PolicyEvaluationDeps } from "../policy/evaluate.js";
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
  /** §21.4–§21.5 — a call with no mandate: the policy's URN and the agent's DID, which name its chain. */
  policy?: string;
  agentDid?: string;
  /** §21.3 — on a `rechallenge` under the policy: the members who may confirm the call. */
  approvers?: string[];
  /** §21.3 — on `mandate_required`: the actions a mandate may be under, any one of them, for the agent to ask for. */
  under?: PolicyGuardrailRef[];
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
  // §16.7 step 0 is the caller's, and not optional: entries read as written skip the actor gate.
  if (signed?.length && !deps.candidates) return deny("actor_unresolvable", urn, enforcement);
  const boundKeys = signed?.length ? withSignedWindow(deps.candidates!, signed) : signed;
  if (!boundKeys || boundKeys.length === 0) return deny("agent_not_bound", urn, enforcement);
  const pop = await verifyAgentBinding(
    { authorizedAgents: boundKeys, pop: req.pop, verifier: deps.verifier.did, mandateId: urn, action: req.action, params: req.params },
    { validateNonce: deps.validateNonce, now },
  );
  if (!pop.ok || !pop.agent) return deny(pop.reason ?? "pop_invalid", urn, enforcement);
  // §16.6: the call names its action once. When the params carry a discriminator (`tool`, or
  // `action`), it MUST be the action presented — otherwise the step-up decision reads one name and
  // the rules another, and a call named `Wire_Transfer` with `params.tool: "wire_transfer"` passes
  // the rules for the real tool while dodging the step-up that tool requires.
  if (discriminatorMismatch(req.action, req.params)) return deny("action_mismatch", urn, enforcement);

  // A step-up is decided AFTER authority (S7). It used to be raised here, before the params and
  // the rules were looked at, so a call the rules would deny sent a person to their authenticator
  // first — consent fatigue bought with a decision that was wrong anyway.
  // Two sources ask before a call settles (§17.4): the pinned action (`action`, the caller's
  // `requiresStepUp`) and the mandate itself (`mandate` in `mandate.stepUp.triggers` — every call).
  const actionAsks = deps.requiresStepUp ? await deps.requiresStepUp(req.action, req.params) : false;
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
    const refused = await capped();
    if (refused) return { ...refused, ...(reviewer ? { reviewer } : {}) };
    if ((mandateAsks || actionAsks) && !deps.stepUpSatisfied) {
      return { ...askStepUp(mandateAsks ? "mandate" : "action", "stepup_required"), ...(reviewer ? { reviewer } : {}) };
    }
    const staff = askApprovers();
    if (staff) return { ...staff, ...(reviewer ? { reviewer } : {}) };
    return { decision: "allow", credentialId: urn, evaluations: [], agent: pop.agent, enforcement, ...policyMark, ...(reviewer ? { reviewer } : {}) };
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

  // 7. executionParams shape
  try {
    validateExecutionParams(action, req.params);
  } catch (e) {
    return deny(`execution_params_invalid:${(e as Error).message}`, urn, enforcement);
  }

  // 8. no rules → allow
  if (!action.rules || action.rules.length === 0) {
    const refused = await capped();
    if (refused) return refused;
    if ((mandateAsks || actionAsks) && !deps.stepUpSatisfied) return askStepUp(mandateAsks ? "mandate" : "action", "stepup_required");
    const staff = askApprovers();
    if (staff) return staff;
    return { decision: "allow", credentialId: urn, evaluations: [], agent: pop.agent, enforcement, ...unrestricted, ...policyMark };
  }

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
    agent: _celAgent(deps.agentEnvExtras, pop.agent),
    ...(accreditation ? { accreditation } : {}),
  });
  if (decision === "allow") {
    const refused = await capped();
    if (refused) return { ...refused, evaluations: [...evaluations, ...refused.evaluations] };
    // Authority passed — NOW a step-up is worth a person's attention (S7).
    if ((mandateAsks || actionAsks) && !deps.stepUpSatisfied) {
      return askStepUp(mandateAsks ? "mandate" : "action", "stepup_required", evaluations);
    }
    const staff = askApprovers(evaluations);
    if (staff) return staff;
    return { decision: "allow", credentialId: urn, evaluations, agent: pop.agent, enforcement, ...unrestricted, ...policyMark };
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

export interface AgentUnderPolicyDeps {
  /** The calling verifier's identity (the PoP `aud`). */
  verifier: { did: string };
  /**
   * §21.4 — the agent's usable keys (§7), resolved through its CURRENT actor as §8 steps 2–4 resolve a
   * bound agent: merge followed, status and operator gated. No mandate pins a key, so these are the
   * candidate set A1–A8 select from.
   */
  candidates: BoundKey[];
  /** §21.3 — the current version of the agent's operator's policy; null when it has published none. */
  policy: PolicyVersion | null;
  loadActionVersion: (actionId: string) => ActionDetail | null | Promise<ActionDetail | null>;
  /** §16.7 A5 — the nonce the challenge issued for this agent under the policy (§21.4). */
  validateNonce: (nonce: string, policy: string) => string | Promise<string>;
  /** Whether one of the policy's approvers confirmed this call (verified elsewhere, §21.3). */
  stepUpSatisfied?: boolean;
  now?: Date;
  /** v0.3 §9.3 — extended `agent.*` fields, as for {@link AgentDirectDeps.agentEnvExtras}. */
  agentEnvExtras?: Record<string, unknown>;
  /** v0.3 §18.5 — the operator's accreditation, as for {@link AgentDirectDeps.loadAccreditation}. */
  loadAccreditation?: () => AccreditationLoad | Promise<AccreditationLoad>;
  /** §21.1 — every tool any published version of a guardrail lists; required when the policy targets guardrails. */
  guardrailTools?: PolicyEvaluationDeps["guardrailTools"];
}

/**
 * v0.3 §21.4 — a call with no mandate, on the organization's policy. The agent presents
 * `{ policy, action, params, pop }`, its PoP binding `{ policy, action, params }`; the caller resolved
 * the agent (`agentDid`, its usable keys) and its operator's current policy version.
 *
 * Allowed when the policy's `everyCall` rules pass and its entry for the tool and agent is `allow`, or a
 * `rules` entry that passes; `mandate_required` when the policy says nothing of the tool, or `mandate`;
 * `policy_denied` when it refuses. A step-up the entry's action asks for goes to the policy's approvers
 * (`rechallenge`), and with none named is `stepup_required`. Every result names the policy and the
 * agent — its chain (§21.5) — with `enforcement: "policy"`.
 */
export async function verifyAgentUnderPolicy(
  req: { agentDid: string; policy: string; pop: string; action: string; params: Record<string, unknown> },
  deps: AgentUnderPolicyDeps,
): Promise<AgentDirectResult> {
  requireNonceCheck(deps);
  const scope = { enforcement: "policy" as const, policy: req.policy, agentDid: req.agentDid };
  const result = (decision: AgentDirectResult["decision"], extra: Partial<AgentDirectResult> = {}): AgentDirectResult => ({
    decision,
    evaluations: [],
    ...scope,
    ...extra,
  });
  if (!deps.candidates?.length) return result("deny", { reason: "agent_not_bound" });
  const pop = await verifyAgentBinding(
    { authorizedAgents: deps.candidates, pop: req.pop, verifier: deps.verifier.did, policy: req.policy, action: req.action, params: req.params },
    { validateNonce: deps.validateNonce, now: deps.now ?? new Date() },
  );
  if (!pop.ok || !pop.agent) return result("deny", { reason: pop.reason ?? "pop_invalid" });
  if (discriminatorMismatch(req.action, req.params)) return result("deny", { reason: "action_mismatch", agent: pop.agent });
  // An organization that has published no policy authorizes nothing on its own: every tool needs a mandate.
  if (!deps.policy) return result("deny", { reason: "mandate_required", agent: pop.agent });
  const mark = { policyDigest: deps.policy.policyDigest, agent: pop.agent };
  // The PoP binds the policy the agent claims; it must be its organization's, the one being read.
  if (deps.policy.content.$id !== req.policy) return result("deny", { reason: "policy_denied", ...mark });

  const verdict = await evaluatePolicy(
    deps.policy.content,
    { tool: req.action, params: req.params, agent: { ..._celAgent(deps.agentEnvExtras, pop.agent), did: req.agentDid } },
    {
      loadActionVersion: deps.loadActionVersion,
      ...(deps.guardrailTools ? { guardrailTools: deps.guardrailTools } : {}),
      ...(deps.loadAccreditation ? { loadAccreditation: projectedLoader(deps.loadAccreditation) } : {}),
    },
  );
  const evaluations = verdict.evaluations;
  if (verdict.outcome === "deny") return result("deny", { reason: verdict.reason ?? "policy_denied", evaluations, ...mark });
  if (verdict.outcome === "mandate") {
    return result("deny", { reason: "mandate_required", evaluations, ...mark, ...(verdict.under ? { under: verdict.under } : {}) });
  }
  if (verdict.stepUp && !deps.stepUpSatisfied) {
    // No approver named: nobody to ask, as on the presentation path (§17.4).
    if (verdict.stepUp.approvers.length === 0) return result("deny", { reason: "stepup_required", evaluations, ...mark });
    return result("rechallenge", {
      reason: "stepup_required",
      evaluations,
      ...mark,
      stepUp: { trigger: "policy", reason: "stepup_required" },
      approvers: verdict.stepUp.approvers,
    });
  }
  return result("allow", { evaluations, ...mark, ...(verdict.unrestricted ? { unrestricted: true as const } : {}) });
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

/**
 * v0.3 §9.3 — what rules read of the agent: the projection and the presenting key's rung, never its `keyId`. A key's id
 * changes when it rotates and a raw-key pin has none, so a rule over it would start denying; the decision event records
 * it as `keyIdEvaluated` (§9.9), from the PoP's result (2026-10-26).
 */
function _celAgent(extras: Record<string, unknown> | undefined, agent: AgentEnv | undefined): Record<string, unknown> {
  const { keyId: _keyId, ...rule } = { ...(extras ?? {}), ...agent } as Record<string, unknown>;
  return rule;
}
