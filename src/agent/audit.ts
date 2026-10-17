// Agent audit — the §16.9 signed VIAEvents. Each verification is a reference-bound `VIAEvent`
// carrying the rung evidence, so the audit answers *which rung* acted, not only *what* was
// decided. Its fields sit directly in `credentialSubject` (v0.3 §2.0), and the verifier whose
// decision it is signs it — its `issuer` (§2). Registration is the actor's `ACTOR_REGISTERED`
// (§3.4); v0.2's `AGENT_REGISTERED` is read on v0.2-signed chains and never written.
import { buildEvent, signEvent, type EventFields, type EventSigner } from "../event/build.js";
import type { ViaEvent } from "../types.js";
import type { RuleEvaluation } from "../cel/evaluate.js";
import type { AgentEnv } from "./verify.js";

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
 * §2.1 — a signed `ACTION_COMPLETED` / `ACTION_FAILED`: the outcome the agent reported, naming the
 * `VERIFICATION_APPROVED` it closes in `decision`, and signed by the verifier that made that decision
 * (the gateway). On a failure `reason` carries the error the agent reported. Never a rung (§2.1).
 */
export function buildOutcomeEvent(
  input: {
    /** The mandate the call was made under — or, with no mandate, `policy` (§21.5). Exactly one. */
    mandateId?: string;
    policy?: { id: string; agentDid: string };
    outcome: "completed" | "failed";
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
