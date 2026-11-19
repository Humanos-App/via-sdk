// v0.4 §15.7.1 — the protocol version an agent is under: set by its organization, accepted by a member, written on
// the agent's own chain. The fold reads it into the agent's record (`ViaActorSubject.version`).
import { buildEvent, signEvent, type EventSigner } from "../event/build.js";
import type { ViaEvent } from "../types.js";
import { isProtocolVersion, type ProtocolVersion } from "./model.js";

export interface BuildVersionSetInput {
  /** The agent moved. */
  subject: string;
  /** The organization the agent acts for: the signer, so the event's `issuer` (v0.3 §2). */
  org: string;
  /** The protocol version the agent is under from this event on. */
  specVersion: ProtocolVersion;
  /** The member who moved it, by person DID. */
  movedBy: string;
  /** How the member confirmed, as for publishing a policy (v0.3 §21.2). */
  movedWith: "webauthn" | "otp";
  eventId?: string;
  validFrom?: string;
  previousEvent?: string | null;
}

/**
 * Build and sign an `ACTOR_VERSION_SET` (v0.4 §15.7.1), with the organization's key. What may not be signed is refused
 * here, as the fold refuses it on a chain: a version that is none of the two, no member named, a confirmation that is
 * neither a passkey nor a code.
 */
export function buildVersionSet(input: BuildVersionSetInput, signer: EventSigner): ViaEvent {
  if (!isProtocolVersion(input.specVersion)) throw new TypeError("VIA: an agent is under protocol version 0.3 or 0.4 (v0.4 §15.7.1)");
  if (!input.movedBy) throw new TypeError("VIA: a move names the member who made it (v0.4 §15.7.1)");
  if (input.movedWith !== "webauthn" && input.movedWith !== "otp") throw new TypeError("VIA: a move is confirmed with a passkey or a code (v0.4 §15.7.1)");
  const ev = buildEvent({
    subject: input.subject,
    event: "ACTOR_VERSION_SET",
    issuer: input.org,
    eventId: input.eventId,
    validFrom: input.validFrom,
    previousEvent: input.previousEvent ?? null,
    specVersion: input.specVersion,
    movedBy: input.movedBy,
    movedWith: input.movedWith,
  });
  return signEvent(ev, signer);
}
