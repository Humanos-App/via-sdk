import { randomUUID } from "node:crypto";

/** A VIA resource type that has a `urn:via:<type>:<uuid>` identifier (spec §0.4). */
export type ViaUrnType = "credential" | "event" | "action" | "evidence" | "actor" | "signal";

/**
 * Mint a `urn:via:<type>:<uuid>` — the protocol URN scheme for mandates, events, actions, evidence,
 * actor snapshots and signals.
 *
 * For an actor snapshot the URN names ONE ISSUED COPY, never the actor (v0.3 §3.1): the actor is
 * named by its DID, which is that copy's `credentialSubject.id`. References BETWEEN snapshots are
 * content-addressed — `supersedes` carries the prior copy's digest — so nothing resolves by this
 * URN; it exists because a Verifiable Credential has an `id`.
 */
export function viaUrn(type: ViaUrnType): string {
  return `urn:via:${type}:${randomUUID()}`;
}
