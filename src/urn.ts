import { randomUUID } from "node:crypto";

/** A VIA resource type that has a `urn:via:<type>:<uuid>` identifier (spec v0.2-new §4). */
export type ViaUrnType = "credential" | "event" | "action" | "evidence";

/** Mint a `urn:via:<type>:<uuid>` — the protocol URN scheme for mandates, events, actions, evidence. */
export function viaUrn(type: ViaUrnType): string {
  return `urn:via:${type}:${randomUUID()}`;
}
