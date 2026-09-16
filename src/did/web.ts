import { randomUUID } from "node:crypto";

export const VIA_PLATFORM_DOMAIN = "humanos.tech";
export const VIA_PLATFORM_DID = `did:web:${VIA_PLATFORM_DOMAIN}`;

export const ACTOR_TYPES = ["org", "user", "agent"] as const;

export type ActorType = (typeof ACTOR_TYPES)[number];

function isActorType(value: string): value is ActorType {
  return (ACTOR_TYPES as readonly string[]).includes(value);
}

/**
 * `did:web:humanos.tech:{org|user|agent}:{uuid}` (v0.2-new §3.1; agents per v0.3 §16.1, §16.14).
 *
 * The id is RANDOM, and for agents that is the point: it was briefly minted from the genesis key's
 * RFC 7638 thumbprint, which read as self-certifying without being so — nothing re-derived it, so it
 * bought no property while breaking the shape every other actor uses and `parseDidWeb` with it. A
 * DID names an actor; the KEY is proven by the chain, not by the name.
 */
export function generateViaDID(actorType: ActorType, opts: { uuid?: string; domain?: string } = {}): string {
  if (!isActorType(actorType)) throw new Error(`invalid actor type: ${actorType}`);
  return `did:web:${opts.domain ?? VIA_PLATFORM_DOMAIN}:${actorType}:${opts.uuid ?? randomUUID()}`;
}

/** Normalize a domain the way the platform does (lowercase, strip scheme/path/www/trailing dot). */
export function normalizeDomain(input: string): string {
  let d = (input ?? "").trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, "");
  d = d.split("/")[0] ?? "";
  d = d.replace(/\.$/, "");
  d = d.replace(/^www\./, "");
  return d;
}

/** Graduated issuer DID `did:web:{domain}`. */
export function generateDomainDID(domain: string): { domain: string; did: string } {
  const normalized = normalizeDomain(domain);
  return { domain: normalized, did: `did:web:${normalized}` };
}

/** Strip the `#fragment` from a DID URL. */
export function didFromUrl(didUrl: string): string {
  const h = didUrl.indexOf("#");
  return h < 0 ? didUrl : didUrl.slice(0, h);
}

/** `<did>#<fragment>`. */
export function verificationMethodId(did: string, fragment: string): string {
  return `${did}#${fragment}`;
}

/** `<did>#key-<index>` — the verification-method id for a DID's Nth key (spec v0.2-new §3.1). */
export function getKeyId(did: string, index: number): string {
  return verificationMethodId(did, `key-${index}`);
}

/** Resolve a `did:web` to its document URL (did:web method). */
export function didWebToUrl(did: string): string {
  if (!did.startsWith("did:web:")) throw new Error(`not a did:web identifier: ${did}`);
  const parts = did.slice("did:web:".length).split(":");
  const domain = decodeURIComponent(parts[0]!);
  const path = parts.slice(1).map(decodeURIComponent);
  return path.length === 0
    ? `https://${domain}/.well-known/did.json`
    : `https://${domain}/${path.join("/")}/did.json`;
}

export interface ParsedDidWeb {
  domain: string;
  /** `org` / `user` / `agent` for platform DIDs; `undefined` for a bare graduated/platform DID. */
  actorType?: ActorType;
  /** The id for platform DIDs — a uuid for anything minted by {@link generateViaDID}. */
  id?: string;
}

/**
 * Classify a `did:web` into a platform actor vs a bare domain.
 *
 * `id` is returned as it was WRITTEN, never validated as a uuid: agents minted before v0.3 §16.1
 * was implemented carry a 16-character key-thumbprint tail, and those DIDs are named in signed
 * chains that cannot be rewritten. A parser that refused them would refuse history.
 */
export function parseDidWeb(did: string): ParsedDidWeb {
  if (!did.startsWith("did:web:")) throw new Error(`not a did:web identifier: ${did}`);
  const parts = didFromUrl(did).slice("did:web:".length).split(":");
  const domain = decodeURIComponent(parts[0]!);
  const actorType = parts[1];
  if (parts.length >= 3 && actorType !== undefined && isActorType(actorType)) {
    return { domain, actorType, id: parts.slice(2).join(":") };
  }
  return { domain };
}

/** The domain segment of a verifier DID (for audience/domain binding, v0.2-new §7.3). */
export function verifierDomainOf(did: string): string | undefined {
  return did.includes("did:web:") ? did.split("did:web:")[1]!.split(":")[0] : undefined;
}
