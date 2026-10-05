// Agent audit — the §16.9 signed VIAEvents. Each verification is a reference-bound `VIAEvent`
// carrying the rung evidence, so the audit answers *which rung* acted, not only *what* was
// decided. Signed with Humanos's Ed25519 key. Registration is the actor's `ACTOR_REGISTERED`
// (§3.4); v0.2's `AGENT_REGISTERED` is read on v0.2-signed chains and never written.
import { buildEvent, signEvent, type EventSigner } from "../event/build.js";
import type { ViaEvent } from "../types.js";
import type { RuleEvaluation } from "../cel/evaluate.js";
import type { AgentEnv } from "./verify.js";

/** §16.9 — a signed `VERIFICATION_APPROVED` / `VERIFICATION_DENIED` event with the rung evidence. */
export function buildVerificationEvent(
  input: {
    mandateId: string;
    decision: "allow" | "deny" | "rechallenge";
    actor: string; // the verifier DID
    agent: AgentEnv;
    popNonceRef: string;
    reason?: string;
    evaluations?: RuleEvaluation[];
    targetVerifier?: string;
    issuer?: string;
    previousEvent?: string | null;
    eventId?: string;
    validFrom?: string;
  },
  signer: EventSigner,
): ViaEvent {
  const ev = buildEvent({
    subject: input.mandateId,
    event: input.decision === "allow" ? "VERIFICATION_APPROVED" : "VERIFICATION_DENIED",
    actor: input.actor,
    issuer: input.issuer,
    previousEvent: input.previousEvent ?? null,
    eventId: input.eventId,
    validFrom: input.validFrom,
    ...(input.reason ? { reason: input.reason } : {}),
    ...(input.evaluations ? { evaluations: input.evaluations } : {}),
    ...(input.targetVerifier ? { targetVerifier: input.targetVerifier } : {}),
    agent: {
      assuranceEvaluated: input.agent.assurance,
      bindingEvaluated: input.agent.binding,
      ...(input.agent.root ? { rootUsed: input.agent.root } : {}),
      popNonceRef: input.popNonceRef,
      attestationFreshnessAt: new Date(input.agent.verifiedAt).toISOString(),
    },
  });
  return signEvent(ev, signer);
}
