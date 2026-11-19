// v0.4 §15.7.1 — the protocol version an agent is under: its event, its fold, and the policy in force per version.
import { describe, expect, it } from "vitest";
import {
  ACTOR_FOLD_VERSION,
  EVENT_SCOPE,
  actorSpecVersion,
  buildVersionSet,
  eventChainLink,
  foldActorChain,
  generateEd25519Key,
  policiesInForce,
  specVersionRefusal,
  verifyEvent,
  type ViaEvent,
} from "../src/index.js";

const ORG = "did:web:acme.example";
const OTHER_ORG = "did:web:other.example";
const AGENT = "did:web:humanos.tech:agent:support";
const ANA = "did:web:humanos.tech:user:ana";
const HUMANOS = "did:web:humanos.tech";
const POLICY_URN = "urn:via:policy:acme";

type Step = [event: string, fields: Record<string, unknown>, issuer: string];
function chain(subject: string, steps: Step[]): ViaEvent[] {
  const out: ViaEvent[] = [];
  steps.forEach(([event, fields, issuer], i) => {
    const prev = out[out.length - 1];
    out.push({
      "@context": ["https://www.w3.org/ns/credentials/v2", "https://via.humanos.tech/ns/v1"],
      id: `urn:via:event:version-${i}`,
      type: ["VerifiableCredential", "VIAEvent"],
      specVersion: "0.3",
      issuer,
      validFrom: `2026-11-${String(i + 10)}T00:00:00.000Z`,
      credentialSubject: { id: subject, event, previousEvent: prev ? eventChainLink(prev) : null, ...fields },
    } as unknown as ViaEvent);
  });
  return out;
}
const genesis = (actorType: string, subject = AGENT): Step => [
  "ACTOR_REGISTERED",
  { actorType, keyId: `${subject}#key-1`, publicKeyMultibase: "z6MkAcme", bootstrapAnchor: "manual" },
  HUMANOS,
];
const affiliated = (org = ORG): Step => ["ACTOR_AFFILIATED", { operator: { org, relation: "operates" } }, org];
const moved = (specVersion: unknown, over: Record<string, unknown> = {}, issuer = ORG): Step => [
  "ACTOR_VERSION_SET",
  { specVersion, movedBy: ANA, movedWith: "webauthn", ...over },
  issuer,
];
const agentChain = (...steps: Step[]) => foldActorChain(chain(AGENT, [genesis("agent"), affiliated(), ...steps]));

describe("ACTOR_VERSION_SET in the fold (v0.4 §15.7.1)", () => {
  it("is an actor's event, and this fold is the first that reads it", () => {
    expect(EVENT_SCOPE.ACTOR_VERSION_SET).toBe("actor");
    expect(ACTOR_FOLD_VERSION).toBe(18);
  });

  it("reads an agent nobody moved as under v0.3", () => {
    const r = agentChain();
    expect(r.ok && r.subject.version).toBeUndefined();
    expect(r.ok && actorSpecVersion(r.subject)).toBe("0.3");
  });

  it("records the version the organization set, the member who moved the agent and how they confirmed", () => {
    const r = agentChain(moved("0.4"));
    expect(r.ok && r.subject.version).toMatchObject({ specVersion: "0.4", movedBy: ANA, movedWith: "webauthn" });
    expect(r.ok && r.subject.version?.event).toMatch(/^sha256-/);
    expect(r.ok && actorSpecVersion(r.subject)).toBe("0.4");
  });

  it("follows a move back: the last move decides", () => {
    const r = agentChain(moved("0.4"), moved("0.3", { movedWith: "otp" }));
    expect(r.ok && r.subject.version).toMatchObject({ specVersion: "0.3", movedWith: "otp" });
    expect(r.ok && actorSpecVersion(r.subject)).toBe("0.3");
  });

  it("keeps recording the version of a suspended agent, as every fact about it", () => {
    const r = agentChain(["ACTOR_SUSPENDED", { reason: "review" }, ORG], moved("0.4"));
    expect(r.ok && r.subject).toMatchObject({ status: "suspended", version: { specVersion: "0.4" } });
  });

  // @refusal
  it.each([
    ["a version that is none of the two", moved("0.5")],
    ["no version", moved(undefined)],
    ["no member named", moved("0.4", { movedBy: undefined })],
    ["a confirmation that is neither a passkey nor a code", moved("0.4", { movedWith: "password" })],
    ["no confirmation named", moved("0.4", { movedWith: undefined })],
    ["the agent's own signature", moved("0.4", {}, AGENT)],
    ["Humanos's signature", moved("0.4", {}, HUMANOS)],
    ["another organization's signature", moved("0.4", {}, OTHER_ORG)],
  ])("refuses a move with %s", (_case, step) => {
    expect(agentChain(step)).toMatchObject({ ok: false, reason: "version_invalid", at: 2 });
  });

  // @refusal
  it("refuses a move of an agent no organization operates: nobody may set its version", () => {
    expect(foldActorChain(chain(AGENT, [genesis("agent"), moved("0.4")]))).toMatchObject({ ok: false, reason: "version_invalid" });
  });

  // @refusal
  it.each(["organization", "user"])("refuses a version on an actor that is no agent — %s", (actorType) => {
    expect(foldActorChain(chain(ORG, [genesis(actorType, ORG), moved("0.4")]))).toMatchObject({ ok: false, reason: "version_on_non_agent" });
  });
});

describe("buildVersionSet", () => {
  const key = generateEd25519Key();
  const signer = { privateKey: key.privateKey, verificationMethod: `${ORG}#key-1` };
  const input = { subject: AGENT, org: ORG, specVersion: "0.4" as const, movedBy: ANA, movedWith: "webauthn" as const };

  it("signs the move as the organization, and the fold reads what it built", async () => {
    const steps = chain(AGENT, [genesis("agent"), affiliated()]);
    const ev = buildVersionSet({ ...input, previousEvent: eventChainLink(steps[1]!) }, signer);
    expect((await verifyEvent(ev, async () => key.publicKey)).valid).toBe(true);
    expect(ev.issuer).toBe(ORG);
    expect(ev.credentialSubject).toMatchObject({ id: AGENT, event: "ACTOR_VERSION_SET", specVersion: "0.4", movedBy: ANA, movedWith: "webauthn" });
    const r = foldActorChain([...steps, ev]);
    expect(r.ok && r.subject.version).toMatchObject({ specVersion: "0.4", movedBy: ANA });
  });

  // @refusal
  it.each([
    ["another version", { specVersion: "0.5" }],
    ["no member", { movedBy: "" }],
    ["another confirmation", { movedWith: "password" }],
  ])("refuses to sign a move with %s", (_case, over) => {
    expect(() => buildVersionSet({ ...input, ...over } as never, signer)).toThrow(/v0\.4 §15\.7\.1/);
  });
});

describe("the policy in force per protocol version (v0.4 §15.7.1)", () => {
  const published = (version: number, specVersion?: string): Step => [
    "POLICY_PUBLISHED",
    { policy: POLICY_URN, version, policyDigest: `sha256-v${version}`, publishedBy: ANA, ...(specVersion ? { specVersion } : {}) },
    ORG,
  ];
  const orgChain = (...steps: Step[]) => chain(ORG, [genesis("organization", ORG), ...steps]);

  it("keeps the newest version of each protocol version, on the one line numbered in sequence", () => {
    const events = orgChain(published(1), published(2, "0.4"), published(3), published(4, "0.4"), published(5));
    const r = foldActorChain(events);
    expect(r.ok && r.subject.policy).toMatchObject({ version: 5 });
    expect(r.ok && r.subject.policies).toMatchObject({
      "0.3": { id: POLICY_URN, version: 5, policyDigest: "sha256-v5", specVersion: "0.3" },
      "0.4": { id: POLICY_URN, version: 4, policyDigest: "sha256-v4", specVersion: "0.4" },
    });
    // From the events alone, for a reader that holds no record of this fold: the same two.
    expect(policiesInForce(events)).toEqual(r.ok && r.subject.policies);
  });

  it("has one policy in force while only one protocol version was published", () => {
    const r = foldActorChain(orgChain(published(1), published(2)));
    expect(r.ok && Object.keys(r.subject.policies ?? {})).toEqual(["0.3"]);
    expect(policiesInForce(orgChain())).toEqual({});
  });

  // @refusal
  it("still refuses a version out of sequence, whichever protocol version it is of", () => {
    expect(foldActorChain(orgChain(published(1), published(3, "0.4")))).toMatchObject({ ok: false, reason: "policy_invalid", at: 2 });
    expect(foldActorChain(orgChain(published(1, "0.4"), published(1)))).toMatchObject({ ok: false, reason: "policy_invalid" });
  });

  // @refusal
  it("refuses a version marked with a protocol version this fold does not know", () => {
    expect(foldActorChain(orgChain(published(1, "0.5")))).toMatchObject({ ok: false, reason: "policy_invalid" });
  });
});

describe("specVersionRefusal", () => {
  it.each([
    ["0.3", "0.4", { reason: "spec_version_mismatch", expected: "0.3" }],
    ["0.4", "0.3", { reason: "spec_version_mismatch", expected: "0.4" }],
    ["0.3", "0.3", null],
    ["0.4", "0.4", null],
  ] as const)("an agent under %s called under %s", (agent, called, refusal) => {
    expect(specVersionRefusal(agent, called)).toEqual(refusal);
  });
});
