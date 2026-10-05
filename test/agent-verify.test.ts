import { describe, it, expect, beforeAll } from "vitest";
import {
  generateP256Key,
  jwkThumbprint,
  buildMandate,
  buildPoP,
  actionHash,
  constraintsToRules,
  generateEd25519Key,
  stampMandate,
  verifyAgentDirect as verifyStamped,
  type P256KeyPair,
  type BoundKey,
  type Constraint,
  type ViaMandateCredential,
  type AgentDirectDeps,
} from "../src/index.js";
import type { ActionDetail } from "../src/action/types.js";

/**
 * The platform's STAMP over every mandate these tests present: `verifyAgentDirect` checks it first
 * (§8 step 1), and each test here is about what comes after. A test that edits a mandate gets it
 * re-stamped, as if the issuer had signed that body; the STAMP check itself is tested on its own.
 */
const PLATFORM = generateEd25519Key();
const PLATFORM_VM = "did:web:humanos.tech#key-1";
const stamp = (m: ViaMandateCredential): ViaMandateCredential => {
  const { proof: _proof, ...body } = m as ViaMandateCredential & { proof?: unknown };
  return stampMandate(body as ViaMandateCredential, { privateKey: PLATFORM.privateKey, verificationMethod: PLATFORM_VM });
};
const verifyAgentDirect: typeof verifyStamped = (m, req, d) => verifyStamped(stamp(m), req, d);

const RP = "acme-bank.example";
const now = new Date("2026-07-20T12:00:00.000Z");

const AGENT_DID = "did:web:humanos.tech:agent:test0000000000000";

function boundKey(pub: P256KeyPair["publicJwk"], rung: { assurance: BoundKey["assurance"]; binding: BoundKey["binding"]; root?: BoundKey["root"] }): BoundKey {
  // Handed in as epoch ms (what a registration result carries); buildMandate writes ISO (§16.4).
  return { did: AGENT_DID, cnf: { jwk: pub }, ...rung, verifiedAt: now.getTime() - 1000 };
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
    description: { text: "Act within the pinned action.", lang: "en", author: "issuer" }, enforcement: "rules",
  });
});

// @invariant §19.2: a critical extension the verifier does not implement is denied, never ignored —
// the generic rule, so a future critical extension needs no new specVersion.
it("denies a mandate that lists a critical extension this verifier does not implement", async () => {
  const future = structuredClone(mandate);
  const body = future.credentialSubject.mandate as { extensions?: string[]; criticalExtensions?: string[] };
  body.extensions = ["futureCritical"];
  body.criticalExtensions = ["futureCritical"];
  const params = { amount: 10, action: "transfer" };
  const r = await verifyAgentDirect(future, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
  expect(r).toMatchObject({ decision: "deny", reason: "extension_unsupported" });
});

// @invariant §20.3: a mismatched enforcement is denied at verify too, before any rule or reviewer —
// a mandate from an issuer that did not refuse it must not fail open here.
// @invariant §8 step 1: the mandate is checked against its own STAMP before anything else — a body
// edited after issuance (here: a wider userParam) is refused, whatever else it would pass.
it("refuses a mandate edited after its STAMP", async () => {
  const signed = stamp(mandate);
  const edited = structuredClone(signed);
  (edited.credentialSubject.mandate as { validFrom?: string }).validFrom = "2025-01-01T00:00:00.000Z";
  const params = { amount: 10, action: "transfer" };
  const r = await verifyStamped(edited, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
  expect(r).toMatchObject({ decision: "deny", reason: "credential_stamp_invalid" });
});

// @invariant §9.1bis rule 1: the rung a rule reads is the presenting key's — an actor projection
// handed in beside it cannot replace it with a summary, or a weaker one.
it("keeps the presenting key's rung when the caller's actor projection carries another", async () => {
  const params = { amount: 30000, action: "transfer" };
  const r = await verifyAgentDirect(
    mandate,
    { pop: await pop(attested, "transfer", params), action: "transfer", params },
    deps({ agentEnvExtras: { assurance: "pop", binding: "self", status: "active" } }),
  );
  expect(r).toMatchObject({ decision: "allow", agent: { assurance: "hardware", binding: "attested" } });
});

// @invariant §16.7 step 0 + A8: the keys step 0 resolved beside the mandate are what may sign, and
// the signed entry's re-attest window still holds them — a candidate list built from the actor
// carries no window of its own, and must not be a way around A8.
it("accepts a step-0 candidate the mandate never named, held to the signed entry's window", async () => {
  const windowed = structuredClone(mandate);
  for (const e of windowed.credentialSubject.mandate.context.authorizedAgents!) e.maxAttestationStaleness = 60;
  const params = { amount: 10, action: "transfer" };
  // The rotated successor: not in the mandate, resolved through the actor by the caller.
  const successor = { ...boundKey(impostor.publicJwk, { assurance: "hardware", binding: "attested", root: "aws-nitro" }) };
  const fresh = await verifyAgentDirect(
    windowed,
    { pop: await pop(impostor, "transfer", params), action: "transfer", params },
    deps({ candidates: [successor] }),
  );
  expect(fresh).toMatchObject({ decision: "allow" });

  const stale = { ...successor, verifiedAt: now.getTime() - 120_000 }; // 2 min old, 1 min window
  const r = await verifyAgentDirect(
    windowed,
    { pop: await pop(impostor, "transfer", params), action: "transfer", params },
    deps({ candidates: [stale] }),
  );
  expect(r).toMatchObject({ decision: "deny", reason: "attestation_stale" });
});

it("denies a mandate whose enforcement does not fit its shape", async () => {
  const mismatched = structuredClone(mandate);
  (mismatched.credentialSubject.mandate as { enforcement?: string }).enforcement = "semantic"; // it has an action
  const params = { amount: 10, action: "transfer" };
  const r = await verifyAgentDirect(mismatched, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
  expect(r).toMatchObject({ decision: "deny", reason: "enforcement_invalid" });
});

const deps = (over: Partial<AgentDirectDeps> = {}): AgentDirectDeps => ({
  verifier: { did: `did:web:${RP}` },
  resolvePublicKey: (vm) => {
    if (vm !== PLATFORM_VM) throw new Error(`unknown key ${vm}`);
    return PLATFORM.publicKey;
  },
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

  it("a spent Bounded-Use grant denies max_executions_reached on the agent path too (§19.5)", async () => {
    const params = { amount: 10, action: "transfer" };
    const r = await verifyAgentDirect(
      mandate,
      { pop: await pop(attested, "transfer", params), action: "transfer", params },
      deps({ loadCredentialRecord: async () => ({ status: "REVOKED", exhausted: true }) }),
    );
    expect(r).toMatchObject({ decision: "deny", reason: "max_executions_reached" });
  });
});

describe("§20 — enforcement, semantic review, and when a person is asked (S7)", () => {
  const params = { amount: 40000, action: "transfer" };
  const words = { text: "Move money between my own accounts, nothing outbound.", lang: "en", author: "grantor" as const };

  /** The same mandate shape, minus the action: the words are the grant (§20.3). */
  const semantic = () =>
    buildMandate({
      subjectOrg: "did:web:humanos.tech:org:acme",
      grantor: "did:web:humanos.tech:user:op",
      authorizedDIDs: [`did:web:${RP}`],
      authorizedAgents: [boundKey(attested.publicJwk, { assurance: "hardware", binding: "attested", root: "aws-nitro" })],
      validFrom: "2026-01-01T00:00:00.000Z",
      enforcement: "semantic",
      description: words,
      stepUp: { triggers: ["verifier"], reasons: ["semantic_review"] },
    });

  const present = async (m: ViaMandateCredential, over: Partial<AgentDirectDeps> = {}) => {
    const popJwt = await buildPoP(
      {
        cnf: { jkt: jwkThumbprint(attested.publicJwk) },
        aud: `did:web:${RP}`,
        nonce: "n-1",
        iat: 1,
        action_hash: actionHash(m.id, "transfer", params),
      },
      attested.privateJwk,
    );
    return verifyAgentDirect(m, { pop: popJwt, action: "transfer", params }, deps(over));
  };

  it("says which machinery governed, on an allow and on a deny alike", async () => {
    const allowed = await verifyAgentDirect(mandate, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
    expect(allowed).toMatchObject({ decision: "allow", enforcement: "rules" });
    const denied = await verifyAgentDirect(
      mandate,
      { pop: await pop(attested, "transfer", { amount: 60000, action: "transfer" }), action: "transfer", params: { amount: 60000, action: "transfer" } },
      deps(),
    );
    expect(denied).toMatchObject({ decision: "deny", enforcement: "rules" });
  });

  // @invariant A mandate whose enforcement IS a reader is unenforced without one. Allowing here
  // would be the whole of §20.6 undone by a missing dependency.
  it("denies a semantic mandate when no reviewer is wired", async () => {
    expect(await present(semantic())).toMatchObject({ decision: "deny", reason: "reviewer_unavailable" });
  });

  it("denies when the reviewer cannot be reached, and names it in the audit", async () => {
    const r = await present(semantic(), {
      review: () => ({ verdict: "unavailable", reviewer: { id: "reys", version: "2026-09-14" } }),
    });
    expect(r).toMatchObject({ decision: "deny", reason: "reviewer_unavailable", reviewer: { id: "reys" } });
  });

  it("allows a call the words entail, recording the reviewer and its version (§9.9)", async () => {
    const r = await present(semantic(), {
      review: () => ({ verdict: "entailed", reviewer: { id: "reys", version: "2026-09-14" } }),
    });
    expect(r).toMatchObject({ decision: "allow", enforcement: "semantic", reviewer: { id: "reys", version: "2026-09-14" } });
  });

  it("denies a call the words do not entail", async () => {
    const r = await present(semantic(), { review: () => ({ verdict: "not_entailed" }) });
    expect(r).toMatchObject({ decision: "deny", reason: "semantic_denied" });
  });

  it("escalates to the person as a rechallenge the event can attribute", async () => {
    const r = await present(semantic(), { review: () => ({ verdict: "escalate", reviewer: { id: "reys" } }) });
    expect(r).toMatchObject({
      decision: "rechallenge",
      reason: "semantic_review",
      stepUp: { trigger: "verifier", reason: "semantic_review" },
    });
  });

  // §20.2's narrowing rule: the requester wrote these words, so a reviewer reading them may refuse
  // or escalate — it may not hand the agent an allow on its own sentence.
  it("will not allow on words the agent wrote, even when the reviewer says they entail the call", async () => {
    const m = buildMandate({
      subjectOrg: "did:web:humanos.tech:org:acme",
      grantor: "did:web:humanos.tech:user:op",
      authorizedDIDs: [`did:web:${RP}`],
      authorizedAgents: [boundKey(attested.publicJwk, { assurance: "hardware", binding: "attested", root: "aws-nitro" })],
      validFrom: "2026-01-01T00:00:00.000Z",
      enforcement: "semantic",
      description: { ...words, author: "agent", proposedBy: { actor: AGENT_DID, adopted: true } },
    });
    const r = await present(m, { review: () => ({ verdict: "entailed" }) });
    expect(r.decision).toBe("rechallenge");
  });

  // S7: the step-up used to be raised BEFORE the rules ran, so a call the rules would deny sent a
  // person to their authenticator first — a ceremony spent on a decision that was wrong anyway.
  it("denies a call the rules refuse instead of asking the person to co-sign it", async () => {
    const over = { amount: 60000, action: "transfer" };
    const r = await verifyAgentDirect(
      mandate,
      { pop: await pop(attested, "transfer", over), action: "transfer", params: over },
      deps({ requiresStepUp: () => true, stepUpSatisfied: false }),
    );
    expect(r.decision).toBe("deny");
  });

  it("asks for the co-sign once authority has passed, and says who demanded it", async () => {
    const r = await verifyAgentDirect(
      mandate,
      { pop: await pop(attested, "transfer", params), action: "transfer", params },
      deps({ requiresStepUp: () => true, stepUpSatisfied: false }),
    );
    expect(r).toMatchObject({ decision: "rechallenge", stepUp: { trigger: "action", reason: "stepup_required" } });
    expect(r.evaluations.length).toBeGreaterThan(0);
  });
});

describe("§16.4 binding entry — the wire shape and the two verifiedAt encodings", () => {
  it("buildMandate writes verifiedAt as ISO-8601 and carries did, whatever it was handed", () => {
    const entries = mandate.credentialSubject.mandate.context.authorizedAgents!;
    for (const e of entries) {
      expect(e.did).toBe(AGENT_DID);
      expect(typeof e.verifiedAt).toBe("string");
      expect(Date.parse(e.verifiedAt as string)).toBe(now.getTime() - 1000);
    }
    // …and the surfaced rung is in ms, so CEL freshness rules keep working on a number.
  });

  it("buildMandate refuses an entry without did, and a keyId that is not a key of did", () => {
    const base = {
      subjectOrg: "did:web:humanos.tech:org:acme", grantor: "g", authorizedDIDs: ["did:web:rp"],
      validFrom: "2026-01-01T00:00:00.000Z",
      description: { text: "Act for Acme within this scope.", lang: "en", author: "grantor" as const },
      enforcement: "none" as const,
    };
    const noDid = { cnf: { jwk: attested.publicJwk }, assurance: "pop", binding: "self", verifiedAt: 1 } as unknown as BoundKey;
    expect(() => buildMandate({ ...base, authorizedAgents: [noDid] })).toThrow(/requires did/);
    const mismatch: BoundKey = { ...boundKey(attested.publicJwk, { assurance: "pop", binding: "self" }), keyId: "did:web:humanos.tech:agent:other#key-1" };
    expect(() => buildMandate({ ...base, authorizedAgents: [mismatch] })).toThrow(/not a key of did/);
  });

  it("buildMandate signs only the §16.4 fields — not the registrar's custody, evidence or runtime", () => {
    const base = {
      subjectOrg: "did:web:humanos.tech:org:acme", grantor: "g", authorizedDIDs: ["did:web:rp"],
      validFrom: "2026-01-01T00:00:00.000Z",
      description: { text: "Act for Acme within this scope.", lang: "en", author: "grantor" as const },
      enforcement: "none" as const,
    };
    // A registration result handed straight in, as a caller is likely to.
    const registered = {
      ...boundKey(attested.publicJwk, { assurance: "hardware", binding: "attested" }),
      root: "aws-nitro",
      custodyRef: { provider: "aws-kms", keyArn: "arn:aws:kms:eu-west-1:1:key/abc" },
      evidence: { rootFingerprint: "ab" },
      runtime: { class: "tee", at: "2026-01-01T00:00:00.000Z" },
      maxAttestationStaleness: 600,
      attestationDigestSRI: "sha256-AAAA",
    } as unknown as BoundKey;
    const [entry] = buildMandate({ ...base, authorizedAgents: [registered] }).credentialSubject.mandate.context.authorizedAgents!;
    expect(Object.keys(entry!).sort()).toEqual(
      ["assurance", "attestationDigestSRI", "binding", "cnf", "did", "maxAttestationStaleness", "root", "verifiedAt"],
    );
    const unprefixed = { ...registered, attestationDigestSRI: "AAAA" } as BoundKey;
    expect(() => buildMandate({ ...base, authorizedAgents: [unprefixed] })).toThrow(/not an SRI string/);
  });

  it("buildMandate writes the author's re-attest window onto every entry; a stricter one on the entry stays", () => {
    const base = {
      subjectOrg: "did:web:humanos.tech:org:acme", grantor: "g", authorizedDIDs: ["did:web:rp"],
      validFrom: "2026-01-01T00:00:00.000Z",
      description: { text: "Act for Acme within this scope.", lang: "en", author: "grantor" as const },
      enforcement: "none" as const,
    };
    const plain = boundKey(attested.publicJwk, { assurance: "hardware", binding: "attested" });
    const strict = { ...boundKey(custodial.publicJwk, { assurance: "hardware", binding: "custodial" }), maxAttestationStaleness: 60 };
    const entries = buildMandate({ ...base, authorizedAgents: [plain, strict], maxAttestationStaleness: 3600 })
      .credentialSubject.mandate.context.authorizedAgents!;
    expect(entries.map((e) => e.maxAttestationStaleness)).toEqual([3600, 60]);
    // Absent ⇒ no window (§16.4).
    const none = buildMandate({ ...base, authorizedAgents: [plain] }).credentialSubject.mandate.context.authorizedAgents!;
    expect(none[0]).not.toHaveProperty("maxAttestationStaleness");
    expect(() => buildMandate({ ...base, authorizedAgents: [plain], maxAttestationStaleness: 0 })).toThrow(/positive whole number/);
  });

  it("a v0.2-signed entry (epoch-ms verifiedAt) still verifies, and A8 compares in ms either way", async () => {
    // Bypass buildMandate on purpose: this is an artifact signed while v0.2 was current.
    const legacy = structuredClone(mandate) as ViaMandateCredential;
    const entry = legacy.credentialSubject.mandate.context.authorizedAgents![0]!;
    entry.verifiedAt = now.getTime() - 1000; // number, as v0.2 wrote it
    entry.maxAttestationStaleness = 60;      // one minute window; 1 s old → fresh
    const params = { amount: 10, action: "transfer" };
    const fresh = await verifyAgentDirect(legacy, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
    expect(fresh.decision).toBe("allow");
    expect(fresh.agent?.verifiedAt).toBe(now.getTime() - 1000);
    expect(fresh.agent?.did).toBe(AGENT_DID);

    // The same window on the ISO form, now stale.
    const iso = structuredClone(mandate) as ViaMandateCredential;
    const e2 = iso.credentialSubject.mandate.context.authorizedAgents![0]!;
    e2.verifiedAt = new Date(now.getTime() - 120_000).toISOString();
    e2.maxAttestationStaleness = 60;
    const stale = await verifyAgentDirect(iso, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
    expect(stale).toMatchObject({ decision: "deny", reason: "attestation_stale" });

    // An unreadable instant on an entry WITH a window fails closed.
    e2.verifiedAt = "not-a-date";
    const bad = await verifyAgentDirect(iso, { pop: await pop(attested, "transfer", params), action: "transfer", params }, deps());
    expect(bad).toMatchObject({ decision: "deny", reason: "attestation_stale" });
  });
});


// §18.6 — an operator with no ACCREDITED is the unverified tier: projected, not left out.
describe("accreditation.* when the operator has none (§18.6)", () => {
  const SMALL_OR_VERIFIED: ActionDetail = {
    ...ACTION,
    $id: "urn:via:action:transfer-acc",
    rules: [{ name: "small_or_verified", description: "small, or a verified operator", expression: 'executionParams.amount <= 1000 || accreditationRank(accreditation.level) >= accreditationRank("verified")' }],
  } as unknown as ActionDetail;
  let accMandate: ViaMandateCredential;
  beforeAll(() => {
    accMandate = buildMandate({
      subjectOrg: "did:web:humanos.tech:org:acme",
      grantor: "did:web:humanos.tech:user:op",
      authorizedDIDs: [`did:web:${RP}`],
      authorizedAgents: [boundKey(attested.publicJwk, { assurance: "hardware", binding: "attested", root: "aws-nitro" })],
      action: { id: SMALL_OR_VERIFIED.$id, digestSRI: "", location: "https://api.humanos.tech/actions/transfer-acc" },
      validFrom: "2026-01-01T00:00:00.000Z",
      description: { text: "Act within the pinned action.", lang: "en", author: "issuer" }, enforcement: "rules",
    });
  });
  const call = async (amount: number, over: Partial<AgentDirectDeps>) => {
    const params = { amount, action: "transfer" };
    const signed = await buildPoP(
      { cnf: { jkt: jwkThumbprint(attested.publicJwk) }, aud: `did:web:${RP}`, nonce: "n-1", iat: 1, action_hash: actionHash(accMandate.id, "transfer", params) },
      attested.privateJwk,
    );
    return verifyAgentDirect(accMandate, { pop: signed, action: "transfer", params }, deps({ loadActionVersion: async () => SMALL_OR_VERIFIED, ...over }));
  };

  it("projects unverified, so the small call is allowed and the large one denied", async () => {
    expect(await call(50, { loadAccreditation: () => undefined })).toMatchObject({ decision: "allow" });
    expect(await call(5000, { loadAccreditation: () => undefined })).toMatchObject({ decision: "deny" });
  });

  // @invariant §16.10: a verifier that does not implement accreditation denies a rule that reads it.
  it("denies a rule that reads accreditation when the verifier has no loader at all", async () => {
    expect(await call(50, {})).toMatchObject({ decision: "deny" });
  });
});
