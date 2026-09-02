// Agent audit — the §16.9 signed VIAEvents. The agent lifecycle IS the event stream
// (`AGENT_REGISTERED → VERIFICATION_* → REVOKE`): registration and each verification
// are reference-bound `VIAEvent`s carrying the rung evidence, so the audit answers
// *which rung* acted, not only *what* was decided. Signed with Humanos's Ed25519 key.
import { buildEvent, signEvent, type EventSigner } from "../event/build.js";
import { jwkThumbprint } from "../crypto/p256.js";
import type { ViaEvent } from "../types.js";
import type { RuleEvaluation } from "../cel/evaluate.js";
import type { BoundKey } from "./types.js";
import type { AgentEnv } from "./verify.js";

/** §16.9 — a signed `AGENT_REGISTERED` event (subject = the agent DID; detail = the locked rung). */
export function buildAgentRegisteredEvent(
  input: {
    agentDid: string;
    boundKey: BoundKey;
    issuer?: string;
    previousEvent?: string | null;
    eventId?: string;
    validFrom?: string;
  },
  signer: EventSigner,
): ViaEvent {
  const ev = buildEvent({
    credentialId: input.agentDid,
    event: "AGENT_REGISTERED",
    actor: input.agentDid,
    issuer: input.issuer,
    previousEvent: input.previousEvent ?? null,
    eventId: input.eventId,
    validFrom: input.validFrom,
    agent: {
      cnf: { jkt: jwkThumbprint(input.boundKey.cnf.jwk) },
      assurance: input.boundKey.assurance,
      binding: input.boundKey.binding,
      ...(input.boundKey.root ? { root: input.boundKey.root } : {}),
    },
  });
  return signEvent(ev, signer);
}

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
    credentialId: input.mandateId,
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
