// Agent audit — the §16.9 signed VIAEvents. Each verification is a reference-bound `VIAEvent`
// carrying the rung evidence, so the audit answers *which rung* acted, not only *what* was
// decided. Its fields sit directly in `credentialSubject` (v0.3 §2.0), and the verifier whose
// decision it is signs it — its `issuer` (§2). Registration is the actor's `ACTOR_REGISTERED`
// (§3.4); v0.2's `AGENT_REGISTERED` is read on v0.2-signed chains and never written.
import { buildEvent, signEvent, type EventFields, type EventSigner } from "../event/build.js";
import type { ViaEvent } from "../types.js";
import type { RuleEvaluation } from "../cel/evaluate.js";
import type { AgentEnv } from "./verify.js";
import type { LimitsCallResult } from "./verify-limits.js";

/**
 * §16.9 — a signed `VERIFICATION_APPROVED` / `VERIFICATION_DENIED` with the rung evidence, or `null`
 * for a `rechallenge`: that decision is pending and records no event (v0.3 §2.2) — the person's
 * `STEP_UP_*` and the decision after it are what the chain records.
 */
export function buildVerificationEvent(
  input: {
    /** The mandate the call was made under — or, with no mandate, `policy` (§21.5). Exactly one. */
    mandateId?: string;
    /** §21.5 — a call with no mandate: the policy and the agent whose chain the event is on. */
    policy?: { id: string; agentDid: string };
    decision: "allow" | "deny" | "rechallenge";
    /** The verifier's DID — the signer, so the event's `issuer` (v0.3 §2). */
    issuer: string;
    agent: AgentEnv;
    popNonceRef: string;
    reason?: string;
    evaluations?: RuleEvaluation[];
    targetVerifier?: string;
    previousEvent?: string | null;
    eventId?: string;
    validFrom?: string;
  } & Pick<
    EventFields,
    | "enforcement"
    | "executionParams"
    | "stepUp"
    | "review"
    | "client"
    | "keyIdEvaluated"
    | "levelEvaluated"
    | "methodEvaluated"
    | "registrarUsed"
    | "affiliationRef"
    | "revocationReason"
    | "unrestricted"
    | "policyDigest"
    | "unset"
    | "actionHash"
  >,
  signer: EventSigner,
): ViaEvent | null {
  if (input.decision === "rechallenge") return null;
  const { mandateId, policy, decision, agent, popNonceRef, previousEvent, ...rest } = input;
  const ev = buildEvent({
    ...rest,
    ...subjectOf(mandateId, policy),
    event: decision === "allow" ? "VERIFICATION_APPROVED" : "VERIFICATION_DENIED",
    previousEvent: previousEvent ?? null,
    assuranceEvaluated: agent.assurance,
    bindingEvaluated: agent.binding,
    ...(agent.root ? { rootUsed: agent.root } : {}),
    popNonceRef,
    attestationFreshnessAt: new Date(agent.verifiedAt).toISOString(),
  });
  return signEvent(ev, signer);
}

/**
 * v0.4 §15.8 — the signed `VERIFICATION_APPROVED` / `VERIFICATION_DENIED` of a call decided under a v0.4 policy,
 * from what {@link verifyLimitsCall} answered. It names the tool and the definition the call was made from, each
 * rule by its place, and what the reviewer did. It carries no `enforcement`: a §15.2 mandate has one kind.
 *
 * A refusal before the agent's proof held (`agent_not_bound`, `pop_invalid`, `pop_replayed`, a call that named no
 * definition, an agent that may not act) is recorded too: its result names no rung, so the event says
 * `proofHeld: false` and claims none — no assurance, no binding, no key, no proof's hash. Only what the call
 * presented is on it: the tool, the hash it named when it named one, its inputs, its nonce when the proof carried
 * one. An approval always names its rung: one without is refused here.
 */
export function buildLimitsVerificationEvent(
  input: {
    /** What the verifier answered: its chain (a mandate, or the policy and the agent), its decision, its reasons. */
    result: LimitsCallResult;
    /** The tool and the inputs the call presented, and the hash it named; empty when it named none. */
    tool: string;
    toolHash: string;
    /** The call's inputs, where the deployment records them; absent, `actionHash` alone stands for them (v0.3 §2). */
    params?: Record<string, unknown>;
    /** The verifier's DID — the signer, so the event's `issuer` (v0.3 §2). */
    issuer: string;
    /** v0.4 §14.8 — the entry of the model call that proposed this one, where Humanos matched it. */
    contextEntry?: { conversation: string; seq: number };
    /** The nonce the call's proof carried; absent only where the proof did not hold and carried none that reads. */
    popNonceRef?: string;
    targetVerifier?: string;
    previousEvent?: string | null;
    eventId?: string;
    validFrom?: string;
  } & Pick<EventFields, "client" | "keyIdEvaluated" | "levelEvaluated" | "methodEvaluated" | "registrarUsed" | "affiliationRef">,
  signer: EventSigner,
): ViaEvent {
  const { result, tool, toolHash, params, popNonceRef, previousEvent, keyIdEvaluated, levelEvaluated, methodEvaluated, registrarUsed, affiliationRef, ...rest } = input;
  const agent = result.agent;
  if (!agent && result.decision !== "deny") {
    throw new TypeError("VIA: an approval's event records the rung that acted; this result names none (v0.3 §16.9)");
  }
  if (agent && !popNonceRef) throw new TypeError("VIA: a decision whose proof held records the proof's nonce (v0.3 §16.9)");
  const policy = result.credentialId ? undefined : { id: result.policy!, agentDid: result.agentDid! };
  // What was verified, and so only where the proof held: the rung, the key, the operator's standing, the proof's hash.
  const proven = agent
    ? {
        ...(keyIdEvaluated ?? agent.keyId ? { keyIdEvaluated: keyIdEvaluated ?? agent.keyId } : {}),
        ...(levelEvaluated ? { levelEvaluated } : {}),
        ...(methodEvaluated ? { methodEvaluated } : {}),
        ...(registrarUsed ? { registrarUsed } : {}),
        ...(affiliationRef ? { affiliationRef } : {}),
        ...(result.actionHash ? { actionHash: result.actionHash } : {}),
        assuranceEvaluated: agent.assurance,
        bindingEvaluated: agent.binding,
        ...(agent.root ? { rootUsed: agent.root } : {}),
        attestationFreshnessAt: new Date(agent.verifiedAt).toISOString(),
      }
    : { proofHeld: false as const };
  const ev = buildEvent({
    ...rest,
    ...subjectOf(result.credentialId, policy),
    event: result.decision === "allow" ? "VERIFICATION_APPROVED" : "VERIFICATION_DENIED",
    previousEvent: previousEvent ?? null,
    ...(result.reason ? { reason: result.reason } : {}),
    evaluations: result.evaluations,
    tool,
    ...(toolHash ? { toolHash } : {}),
    ...(params ? { executionParams: params } : {}),
    policyDigest: result.policyDigest,
    ...(result.unset ? { unset: true } : {}),
    ...(result.reviewed ? { reviewed: result.reviewed } : {}),
    ...(result.reviewer ? { review: { ...result.reviewer } } : {}),
    ...(result.grantors !== undefined ? { grantors: result.grantors } : {}),
    ...(result.input ? { input: result.input } : {}),
    ...(result.detail ? { detail: result.detail } : {}),
    ...(result.context ? { context: { ...result.context } } : {}),
    ...(result.revocationReason ? { revocationReason: result.revocationReason } : {}),
    ...proven,
    ...(popNonceRef ? { popNonceRef } : {}),
  });
  return signEvent(ev, signer);
}

/** §2.1 — what the agent reports: the call `completed`, or `failed`. */
export type AgentOutcomeKind = "completed" | "failed";

/**
 * §2.1 — the params of a `report_outcome`, as the agent's PoP binds them (`action_hash`, §16.6) and the
 * gateway rebuilds them: `{ decisionEventId, outcome, error? }`, `error` only when given. A wire
 * contract: any divergence between the two sides is an `action_hash_mismatch` on every report.
 */
export function outcomeParams(
  decisionEventId: string,
  outcome: AgentOutcomeKind,
  error?: string,
): Record<string, unknown> {
  return { decisionEventId, outcome, ...(error ? { error } : {}) };
}

/**
 * §2.1 — a signed `ACTION_COMPLETED` / `ACTION_FAILED`: the outcome the agent reported, naming the
 * `VERIFICATION_APPROVED` it closes in `decision`, and signed by the verifier that made that decision
 * (the gateway). On a failure `reason` carries the error the agent reported. Never a rung (§2.1).
 */
export function buildOutcomeEvent(
  input: {
    /** The mandate the call was made under — or, with no mandate, `policy` (§21.5). Exactly one. */
    mandateId?: string;
    policy?: { id: string; agentDid: string };
    outcome: AgentOutcomeKind;
    /** The `id` of the `VERIFICATION_APPROVED` this outcome closes. */
    decision: string;
    /** The verifier's DID — the signer, so the event's `issuer` (v0.3 §2). */
    issuer: string;
    reason?: string;
    targetVerifier?: string;
    previousEvent?: string | null;
    eventId?: string;
    validFrom?: string;
  },
  signer: EventSigner,
): ViaEvent {
  const { mandateId, policy, outcome, previousEvent, ...rest } = input;
  const ev = buildEvent({
    ...rest,
    ...subjectOf(mandateId, policy),
    event: outcome === "completed" ? "ACTION_COMPLETED" : "ACTION_FAILED",
    previousEvent: previousEvent ?? null,
  });
  return signEvent(ev, signer);
}

/**
 * What a decision or an outcome is about: the mandate it was made under, or with no mandate the policy
 * and the agent, which together name its chain (v0.3 §21.5).
 */
function subjectOf(mandateId: string | undefined, policy: { id: string; agentDid: string } | undefined): { subject: string; agentDid?: string } {
  if (!mandateId === !policy) {
    throw new TypeError("VIA: a decision is about a mandate or, with no mandate, a policy and its agent — exactly one (v0.3 §21.5)");
  }
  return mandateId ? { subject: mandateId } : { subject: policy!.id, agentDid: policy!.agentDid };
}
