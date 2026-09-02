import { describe, it, expect, beforeAll } from "vitest";
import {
  generateP256Key,
  jwkThumbprint,
  buildMandate,
  buildPoP,
  actionHash,
  constraintsToRules,
  verifyAgentDirect,
  type P256KeyPair,
  type BoundKey,
  type Constraint,
  type ViaMandateCredential,
  type AgentDirectDeps,
} from "../src/index.js";
import type { ActionDetail } from "../src/action/types.js";

const RP = "acme-bank.example";
const now = new Date("2026-07-20T12:00:00.000Z");

function boundKey(pub: P256KeyPair["publicJwk"], rung: { assurance: BoundKey["assurance"]; binding: BoundKey["binding"]; root?: BoundKey["root"] }): BoundKey {
  return { cnf: { jwk: pub }, ...rung, verifiedAt: now.getTime() - 1000 };
}

// The mandate requires hardware/attested/aws-nitro for transfers over 25k, cap 45k.
const CONSTRAINTS: Constraint[] = [
  { type: "amount_max", value: 45000 },
  { type: "assurance_floor", min: "hardware", whenAmountAbove: 25000 },
  { type: "binding_required", binding: "attested", whenAmountAbove: 25000 },
  { type: "root_allow", roots: ["aws-nitro", "fido"] },
];

const ACTION: ActionDetail = {
  $id: "urn:via:action:transfer-1",
  type: "VIAAction",
  version: "1",
  userParams: {},
  executionParams: { amount: { type: "number", required: true }, action: { type: "string", required: true } },
  rules: constraintsToRules(CONSTRAINTS),
} as unknown as ActionDetail;

let attested: P256KeyPair, custodial: P256KeyPair, impostor: P256KeyPair;
let mandate: ViaMandateCredential;

beforeAll(async () => {
  attested = await generateP256Key();
  custodial = await generateP256Key();
  impostor = await generateP256Key();
  mandate = buildMandate({
    subjectOrg: "did:web:humanos.tech:org:acme",
    grantor: "did:web:humanos.tech:user:op",
    authorizedDIDs: [`did:web:${RP}`],
    authorizedAgents: [
      boundKey(attested.publicJwk, { assurance: "hardware", binding: "attested", root: "aws-nitro" }),
      boundKey(custodial.publicJwk, { assurance: "hardware", binding: "custodial", root: "aws-nitro" }),
    ],
    action: { id: ACTION.$id, digestSRI: "", location: "https://api.humanos.tech/actions/transfer-1" },
    validFrom: "2026-01-01T00:00:00.000Z",
  });
});

const deps = (over: Partial<AgentDirectDeps> = {}): AgentDirectDeps => ({
  verifier: { did: `did:web:${RP}` },
  loadCredentialRecord: async () => ({ status: "ACTIVE", validFrom: "2026-01-01T00:00:00.000Z" }),
  loadActionVersion: async (id) => (id === ACTION.$id ? ACTION : null),
  now,
  ...over,
});

async function pop(key: P256KeyPair, action: string, params: Record<string, unknown>, over: { aud?: string; params?: Record<string, unknown> } = {}) {
  return buildPoP(
    {
      cnf: { jkt: jwkThumbprint(key.publicJwk) },
      aud: over.aud ?? `did:web:${RP}`,
      nonce: "n-1",
      iat: 1,
      action_hash: actionHash(mandate.id, action, over.params ?? params),
    },
    key.privateJwk,
  );
}

describe("verifyAgentDirect — A1–A8 + agent.* CEL (M4)", () => {
  it("AUTHORIZED: attested key, 40k transfer within all floors", async () => {
    const params = { amount: 40000, action: "transfer" };
    const r = await verifyAgentDirect(mandate, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
    expect(r.decision).toBe("allow");
    expect(r.agent).toMatchObject({ assurance: "hardware", binding: "attested", root: "aws-nitro" });
  });

  it("A2 agent_not_bound: an unregistered (impostor) key", async () => {
    const params = { amount: 10, action: "transfer" };
    const r = await verifyAgentDirect(mandate, { pop: await pop(impostor, "transfer", params), action: "transfer", params }, deps());
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("agent_not_bound");
  });

  it("A4 aud_mismatch: PoP minted for a different verifier", async () => {
    const params = { amount: 10, action: "transfer" };
    const r = await verifyAgentDirect(mandate, { pop: await pop(attested, "transfer", params, { aud: "did:web:other.rp" }), action: "transfer", params }, deps());
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("aud_mismatch");
  });

  it("A6 action_hash_mismatch: params tampered after signing", async () => {
    const signed = { amount: 40000, action: "transfer" };
    const presented = { amount: 44000, action: "transfer" }; // agent presents a bigger amount than it signed
    const r = await verifyAgentDirect(mandate, { pop: await pop(attested, "transfer", signed, { params: signed }), action: "transfer", params: presented }, deps());
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("action_hash_mismatch");
  });

  it("A5 pop_replayed: injected nonce validator rejects", async () => {
    const params = { amount: 10, action: "transfer" };
    const r = await verifyAgentDirect(
      mandate,
      { pop: await pop(attested, "transfer", params), action: "transfer", params },
      deps({ validateNonce: async () => "pop_replayed" }),
    );
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("pop_replayed");
  });

  it("A7 agent_binding_insufficient: custodial key on a >25k transfer (needs attested)", async () => {
    const params = { amount: 40000, action: "transfer" };
    const r = await verifyAgentDirect(mandate, { pop: await pop(custodial, "transfer", params), action: "transfer", params }, deps());
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("agent_binding_insufficient");
  });

  it("custodial key IS allowed for a small (<25k) transfer (floor not triggered)", async () => {
    const params = { amount: 5000, action: "transfer" };
    const r = await verifyAgentDirect(mandate, { pop: await pop(custodial, "transfer", params), action: "transfer", params }, deps());
    expect(r.decision).toBe("allow");
  });

  it("rule_failed: amount over the 45k cap", async () => {
    const params = { amount: 90000, action: "transfer" };
    const r = await verifyAgentDirect(mandate, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("rule_failed"); // amount_max is a non-agent rule
  });

  it("rechallenge: step-up required and not yet satisfied (§17.4 / D7)", async () => {
    const params = { amount: 40000, action: "transfer" };
    const r = await verifyAgentDirect(
      mandate,
      { pop: await pop(attested, "transfer", params), action: "transfer", params },
      deps({ requiresStepUp: () => true, stepUpSatisfied: false }),
    );
    expect(r.decision).toBe("rechallenge");
    expect(r.reason).toBe("stepup_required");
  });

  it("step-up satisfied → proceeds to allow", async () => {
    const params = { amount: 40000, action: "transfer" };
    const r = await verifyAgentDirect(
      mandate,
      { pop: await pop(attested, "transfer", params), action: "transfer", params },
      deps({ requiresStepUp: () => true, stepUpSatisfied: true }),
    );
    expect(r.decision).toBe("allow");
  });

  it("credential_revoked short-circuits before the PoP", async () => {
    const params = { amount: 10, action: "transfer" };
    const r = await verifyAgentDirect(
      mandate,
      { pop: await pop(attested, "transfer", params), action: "transfer", params },
      deps({ loadCredentialRecord: async () => ({ status: "REVOKED" }) }),
    );
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("credential_revoked");
  });
});
