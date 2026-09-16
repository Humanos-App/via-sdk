/**
 * The platform DID shape: `did:web:{domain}:{org|user|agent}:{uuid}`.
 *
 * Agents joined this shape in v0.3 (§16.1, §16.14). They were briefly minted from the genesis key's
 * RFC 7638 thumbprint instead — a shape nothing re-derived and `parseDidWeb` could not read. Those
 * DIDs are named in signed chains, so the parser must still accept them.
 */
import { describe, it, expect } from "vitest";
// `DidActorSegment` is the DID PATH segment (`org`/`user`/`agent`). The actor model's own
// `ActorType` is a different vocabulary (`organization`, not `org`) — index.ts renames this one to
// keep the two apart.
import { generateViaDID, parseDidWeb, ACTOR_TYPES, VIA_PLATFORM_DOMAIN, type DidActorSegment } from "../src/index.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe("generateViaDID", () => {
  it.each(ACTOR_TYPES.map((t) => [t]))("mints `did:web:%s` with a uuid — the same shape for every actor", (actorType) => {
    const did = generateViaDID(actorType);
    expect(did.startsWith(`did:web:${VIA_PLATFORM_DOMAIN}:${actorType}:`)).toBe(true);
    expect(did.split(":").pop()).toMatch(UUID);
  });

  it("mints a DISTINCT id each time — the id identifies, it does not derive", () => {
    // An agent's DID used to be a slice of its key thumbprint, which made two registrations of the
    // same key collide on one DID. The key is proven by the chain; the name is just a name.
    const ids = new Set(Array.from({ length: 50 }, () => generateViaDID("agent").split(":").pop()));
    expect(ids.size).toBe(50);
  });

  it("refuses an actor type outside the union", () => {
    expect(() => generateViaDID("robot" as unknown as DidActorSegment)).toThrow(/invalid actor type/);
  });
});

describe("parseDidWeb", () => {
  it.each(ACTOR_TYPES.map((t) => [t]))("round-trips a minted %s DID back to its parts", (actorType) => {
    const did = generateViaDID(actorType, { uuid: "fixture-id" });
    expect(parseDidWeb(did)).toEqual({ domain: VIA_PLATFORM_DOMAIN, actorType, id: "fixture-id" });
  });

  it("reads an agent DID minted before the uuid shape — history is not reparsed", () => {
    // 16 base64url characters, leading hyphen and all: exactly what the thumbprint slice produced.
    expect(parseDidWeb("did:web:humanos.tech:agent:-rYbHWgB3b0Wd9wi")).toEqual({
      domain: "humanos.tech",
      actorType: "agent",
      id: "-rYbHWgB3b0Wd9wi",
    });
  });

  it("leaves a bare graduated DID as a domain, with no actor type", () => {
    expect(parseDidWeb("did:web:acme.example")).toEqual({ domain: "acme.example" });
  });

  it("ignores a `#fragment`, so a key id parses as its actor", () => {
    const did = generateViaDID("agent", { uuid: "k" });
    expect(parseDidWeb(`${did}#key-1`)).toEqual({ domain: VIA_PLATFORM_DOMAIN, actorType: "agent", id: "k" });
  });

  it("refuses something that is not a did:web", () => {
    expect(() => parseDidWeb("did:key:z6Mk")).toThrow(/not a did:web/);
  });
});
