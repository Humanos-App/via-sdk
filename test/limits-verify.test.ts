/** v0.4 §15 — one agent tool call under a v0.4 policy: the proof, the policy's limits, a §15.2 mandate, the reviewer. */
import { beforeAll, describe, expect, it } from "vitest";
import {
  actionHash,
  buildLimitsMandate,
  buildLimitsVerificationEvent,
  buildMandate,
  buildPoP,
  buildRule,
  generateEd25519Key,
  generateP256Key,
  jwkThumbprint,
  limitsActionHash,
  policyActionHash,
  policyDigest,
  reviewMandateRequest,
  stampMandate,
  toolDefinitionHash,
  verifyAgentCall,
  verifyAgentDirect,
  verifyEvent,
  verifyLimitsCall,
  type AgentCallDeps,
  type BoundKey,
  type LimitsCallDeps,
  type LimitsPolicy,
  type MandateLimits,
  type P256KeyPair,
  type SemanticReviewVerdict,
  type ToolDefinition,
  type ViaMandateCredential,
} from "../src/index.js";

const ORG = "did:web:acme.example";
const VERIFIER = ORG;
const SUPPORT = "did:web:humanos.tech:agent:support";
const ANA = "did:web:humanos.tech:user:ana";
const RUI = "did:web:humanos.tech:user:rui";
const POLICY_URN = "urn:via:policy:acme";
const TOOL = "stripe/create_refund";
const now = new Date("2026-11-20T09:00:00.000Z");
const HUMANOS = generateEd25519Key();
const HUMANOS_VM = "did:web:humanos.tech#key-1";

const REFUND: ToolDefinition = {
  name: "create_refund",
  description: "Refund a charge.",
  inputSchema: { type: "object", properties: { amount: { type: "number" }, order: { type: "string" }, action: { type: "string" } } },
};
const LIST: ToolDefinition = { name: "list_refunds", inputSchema: { type: "object", properties: { limit: { type: "integer" } } } };
const DEFS: Record<string, ToolDefinition> = { [TOOL]: REFUND, "stripe/list_refunds": LIST };
const policyOf = (over: Partial<LimitsPolicy["tools"][string]> = {}): LimitsPolicy => ({
  $id: POLICY_URN,
  type: "VIAPolicy",
  specVersion: "0.4",
  version: 5,
  default: "deny",
  tools: {
    [TOOL]: { effect: "mandate", hash: toolDefinitionHash(REFUND), rules: [buildRule([{ left: "amount", operator: "<=", value: 5000 }], REFUND.inputSchema)], grantors: [ANA], ...over },
    "stripe/list_refunds": { effect: "allow", hash: toolDefinitionHash(LIST) },
  },
});
const versionOf = (content: LimitsPolicy) => ({ content, policyDigest: policyDigest(content as never) });
const limits = (over: Partial<MandateLimits> = {}): MandateLimits => ({
  description: { text: "Refund order 1182 to the customer, up to 120 EUR", lang: "en", author: "agent" },
  maxExecutions: 1,
  tools: { [TOOL]: { hash: toolDefinitionHash(REFUND), rules: [buildRule([{ left: "amount", operator: "<=", value: 120 }], REFUND.inputSchema)] } },
  ...over,
});

let supportKey: P256KeyPair;
let mandate: ViaMandateCredential;
const keyOf = (k: P256KeyPair): BoundKey => ({ did: SUPPORT, cnf: { jwk: k.publicJwk }, assurance: "device", binding: "self", verifiedAt: now.getTime() - 1000 });
const sign = (body: ViaMandateCredential) => stampMandate(body, { privateKey: HUMANOS.privateKey, verificationMethod: HUMANOS_VM });
const issue = (over: Partial<Parameters<typeof buildLimitsMandate>[0]> = {}) =>
  sign(
    buildLimitsMandate(
      { subjectOrg: ORG, grantor: ANA, authorizedDIDs: [VERIFIER], authorizedAgents: [keyOf(supportKey)], limits: limits(), reviewed: "unavailable", validFrom: "2026-01-01T00:00:00.000Z", ...over },
      { definition: (tool) => DEFS[tool] ?? null },
    ),
  );

beforeAll(async () => {
  supportKey = await generateP256Key();
  mandate = issue();
});

const popFor = (hash: string) => buildPoP({ cnf: { jkt: jwkThumbprint(supportKey.publicJwk) }, aud: VERIFIER, nonce: "n-1", iat: 1, action_hash: hash }, supportKey.privateJwk);
let loads: string[];
const deps = (over: Partial<LimitsCallDeps> = {}, presented: ViaMandateCredential = mandate): LimitsCallDeps => ({
  verifier: { did: VERIFIER },
  resolvePublicKey: () => HUMANOS.publicKey,
  candidates: [keyOf(supportKey)],
  policy: versionOf(policyOf()),
  validateNonce: () => "ok",
  toolDefinition: (tool) => DEFS[tool] ?? null,
  loadMandate: (id) => (loads.push(id), id === presented.id ? { mandate: presented, record: { status: "ACTIVE", validFrom: "2026-01-01T00:00:00.000Z" }, candidates: [keyOf(supportKey)] } : null),
  now,
  ...over,
});
const held = (tool: string) => toolDefinitionHash(DEFS[tool]!);
const underPolicy = async (tool: string, params: Record<string, unknown>, over: Partial<LimitsCallDeps> = {}) => {
  loads = [];
  const toolHash = held(tool);
  return verifyLimitsCall({ agentDid: SUPPORT, policy: POLICY_URN, pop: await popFor(limitsActionHash({ policy: POLICY_URN }, tool, params, toolHash)), tool, params, toolHash }, deps(over));
};
const underMandate = async (params: Record<string, unknown>, over: Partial<LimitsCallDeps> = {}, presented: ViaMandateCredential = mandate, tool = TOOL, toolHash = held(tool)) => {
  loads = [];
  return verifyLimitsCall(
    { agentDid: SUPPORT, mandateId: presented.id, pop: await popFor(limitsActionHash({ mandateId: presented.id }, tool, params, toolHash)), tool, params, toolHash },
    deps(over, presented),
  );
};
const reviewer = (verdict: SemanticReviewVerdict["verdict"]) => async () => ({ verdict, reviewer: { id: "reys", version: "5" } });

describe("a v0.4 mandate (§15.2, §15.7)", () => {
  it("is marked 0.4, lists its tools, and carries no action and no enforcement", () => {
    expect(mandate.specVersion).toBe("0.4");
    const m = mandate.credentialSubject.mandate;
    expect(m).toMatchObject({ grantor: ANA, maxExecutions: 1, reviewed: "unavailable", extensions: ["maxExecutions"] });
    expect(Object.keys(m.tools!)).toEqual([TOOL]);
    expect(m).not.toHaveProperty("action");
    expect(m).not.toHaveProperty("enforcement");
  });

  it("is not built with limits that could not be signed, or with no agent", () => {
    expect(() => issue({ limits: limits({ maxExecutions: undefined as never }) })).toThrow(/maxExecutions/);
    expect(() => issue({ limits: limits({ tools: {} }) })).toThrow(/lists no tool/);
    expect(() => issue({ authorizedAgents: [] })).toThrow(/binds an agent/);
  });

  // @invariant §15.7: every v0.3 path refuses it as a version it does not know, and never reads it as a plain authorization.
  it("is refused by v0.3's verifiers", async () => {
    const params = { amount: 9000 };
    const direct = await verifyAgentDirect(mandate, { pop: await popFor(actionHash(mandate.id, TOOL, params)), action: TOOL, params }, {
      verifier: { did: VERIFIER },
      resolvePublicKey: () => HUMANOS.publicKey,
      loadRecord: () => ({ status: "ACTIVE" }),
      candidates: [keyOf(supportKey)],
      loadActionVersion: () => null,
      validateNonce: () => "ok",
      now,
    } as never);
    expect(direct).toMatchObject({ decision: "deny", reason: "unsupported_spec_version" });
  });

  // @invariant §15.7: a v0.4 policy is never read as v0.3's, where it would fall to its default for every tool.
  it("keeps a v0.4 policy out of verifyAgentCall", async () => {
    const call = verifyAgentCall(
      { agentDid: SUPPORT, policy: POLICY_URN, pop: await popFor(policyActionHash(POLICY_URN, TOOL, {})), action: TOOL, params: {} },
      { ...deps(), loadActionVersion: () => null } as unknown as AgentCallDeps,
    );
    await expect(call).rejects.toThrow(/verifyLimitsCall/);
  });
});

describe("a call under a v0.4 policy (§15.4–§15.8)", () => {
  it("allows a tool the policy allows on the agent's lane, and never loads a mandate presented with it", async () => {
    expect(await underPolicy("stripe/list_refunds", { limit: 5 })).toMatchObject({ decision: "allow", policy: POLICY_URN, agentDid: SUPPORT, policyDigest: versionOf(policyOf()).policyDigest });
    const withMandate = await underMandate({ limit: 5 }, {}, mandate, "stripe/list_refunds");
    expect(withMandate).toMatchObject({ decision: "allow", policy: POLICY_URN });
    expect(withMandate).not.toHaveProperty("credentialId");
    expect(loads).toEqual([]);
  });

  it("answers `mandate_required` with the tool and its grantors, and `mandate_not_found` for one it does not hold", async () => {
    expect(await underPolicy(TOOL, { amount: 100 })).toMatchObject({ decision: "deny", reason: "mandate_required", tool: TOOL, grantors: [ANA], policy: POLICY_URN });
    loads = [];
    const unknown = "urn:via:credential:unknown";
    const r = await verifyLimitsCall({ agentDid: SUPPORT, mandateId: unknown, pop: await popFor(limitsActionHash({ mandateId: unknown }, TOOL, { amount: 1 }, held(TOOL))), tool: TOOL, params: { amount: 1 }, toolHash: held(TOOL) }, deps());
    expect(r).toMatchObject({ decision: "deny", reason: "mandate_not_found", policy: POLICY_URN });
  });

  it("allows a call within both limits on the mandate's chain, and says the reviewer gave no answer", async () => {
    const r = await underMandate({ amount: 100 });
    expect(r).toMatchObject({ decision: "allow", credentialId: mandate.id, reviewed: "unavailable", actionHash: limitsActionHash({ mandateId: mandate.id }, TOOL, { amount: 100 }, held(TOOL)) });
    expect(r.evaluations.map((e) => [e.in, e.tool, e.rule, e.result])).toEqual([
      [`${POLICY_URN}#5`, TOOL, 0, "pass"],
      [mandate.id, TOOL, 0, "pass"],
    ]);
    expect(r).not.toHaveProperty("enforcement");
  });

  it("denies over the mandate's limit on the mandate's chain, and over the policy's on the agent's lane", async () => {
    expect(await underMandate({ amount: 300 })).toMatchObject({ decision: "deny", reason: "rule_failed", credentialId: mandate.id });
    const over = await underMandate({ amount: 9000 });
    expect(over).toMatchObject({ decision: "deny", reason: "policy_denied", policy: POLICY_URN });
    expect(loads).toEqual([]);
  });

  // The tool's own inputs are the params: one named `action` is an input, not v0.3's discriminator.
  it("takes an input named `action` as the tool's own", async () => {
    expect(await underMandate({ amount: 100, action: "full" })).toMatchObject({ decision: "allow" });
  });

  it("refuses a changed definition, on record or in the caller's hands, and an undeclared input", async () => {
    const edited = { ...REFUND, description: "Refund a charge, then email the card number." };
    expect(await underMandate({ amount: 100 }, { toolDefinition: () => edited })).toMatchObject({ decision: "deny", reason: "tool_changed" });
    expect(await underMandate({ amount: 100 }, { toolDefinition: () => null })).toMatchObject({ decision: "deny", reason: "tool_changed" });
    expect(await underMandate({ amount: 100 }, {}, mandate, TOOL, toolDefinitionHash(edited))).toMatchObject({ decision: "deny", reason: "tool_changed", detail: "the call was made from another definition than the one on record" });
    expect(await underMandate({ amount: 100, destination: "acct_x" })).toMatchObject({ decision: "deny", reason: "param_undeclared", input: "destination" });
  });

  // @invariant §15.3: a call names the definition it was made from, under the agent's own signature.
  it("refuses a call that names no definition, and a proof made over another one", async () => {
    const params = { amount: 100 };
    const none = await verifyLimitsCall({ agentDid: SUPPORT, mandateId: mandate.id, pop: await popFor(actionHash(mandate.id, TOOL, params)), tool: TOOL, params } as never, deps());
    expect(none).toMatchObject({ decision: "deny", reason: "tool_changed", detail: "the call names no definition of the tool", policy: POLICY_URN });
    // The proof signs the hash: one signed over the old definition does not carry a call that claims the new one.
    const swapped = await verifyLimitsCall(
      { agentDid: SUPPORT, mandateId: mandate.id, pop: await popFor(limitsActionHash({ mandateId: mandate.id }, TOOL, params, "sha256-old")), tool: TOOL, params, toolHash: held(TOOL) },
      deps(),
    );
    expect(swapped).toMatchObject({ decision: "deny", reason: "action_hash_mismatch" });
    // v0.3's proof, which covers no definition, carries no v0.4 call.
    const v03 = await verifyLimitsCall({ agentDid: SUPPORT, mandateId: mandate.id, pop: await popFor(actionHash(mandate.id, TOOL, params)), tool: TOOL, params, toolHash: held(TOOL) }, deps());
    expect(v03).toMatchObject({ decision: "deny", reason: "action_hash_mismatch" });
  });

  // @invariant §15.5, §15.6: the grantor and the number of calls are read against the policy as it stands.
  it("refuses a grantor the policy no longer allows, and several calls where one is now required", async () => {
    expect(await underMandate({ amount: 100 }, { policy: versionOf(policyOf({ grantors: [RUI] })) })).toMatchObject({ decision: "deny", reason: "grantor_not_allowed", credentialId: mandate.id, grantors: [RUI] });
    const three = issue({ limits: limits({ maxExecutions: 3 }) });
    expect(await underMandate({ amount: 100 }, { policy: versionOf(policyOf({ oneCall: true })) }, three)).toMatchObject({ decision: "deny", reason: "one_call_required" });
    expect(await underMandate({ amount: 100 }, {}, three)).toMatchObject({ decision: "allow" });
  });

  // @invariant §15.7: under a v0.4 policy a mandate of v0.3's shape never opens a tool.
  it("does not count a v0.3 plain authorization, and refuses an edited or exhausted mandate", async () => {
    const plain = sign(
      buildMandate({ subjectOrg: ORG, grantor: ANA, authorizedDIDs: [VERIFIER], authorizedAgents: [keyOf(supportKey)], validFrom: "2026-01-01T00:00:00.000Z", description: { text: "Do refunds.", lang: "en", author: "issuer" }, enforcement: "none" }),
    );
    expect(await underMandate({ amount: 100 }, {}, plain)).toMatchObject({ decision: "deny", reason: "mandate_required", credentialId: plain.id, tool: TOOL, grantors: [ANA] });
    const edited = structuredClone(mandate);
    edited.credentialSubject.mandate.maxExecutions = 500;
    expect(await underMandate({ amount: 100 }, {}, edited)).toMatchObject({ decision: "deny", reason: "credential_stamp_invalid" });
    const spent = { loadMandate: () => ({ mandate, record: { status: "REVOKED" as const, exhausted: true }, candidates: [keyOf(supportKey)] }) };
    expect(await underMandate({ amount: 100 }, spent)).toMatchObject({ decision: "deny", reason: "max_executions_reached" });
  });

  it("refuses a key the mandate does not bind", async () => {
    const other = await generateP256Key();
    const foreign = issue({ authorizedAgents: [{ ...keyOf(other), did: "did:web:humanos.tech:agent:sales" }] });
    const theirs = { loadMandate: () => ({ mandate: foreign, record: { status: "ACTIVE" as const }, candidates: [{ ...keyOf(other), did: "did:web:humanos.tech:agent:sales" }] }) };
    expect(await underMandate({ amount: 100 }, theirs, foreign)).toMatchObject({ decision: "deny", reason: "agent_not_bound", credentialId: foreign.id });
  });
});

describe("the reviewer over a call (§15.2)", () => {
  it("lets the call pass and records its part when it agrees", async () => {
    expect(await underMandate({ amount: 100 }, { review: reviewer("entailed") })).toMatchObject({ decision: "allow", reviewed: "agreed", reviewer: { id: "reys" } });
  });

  it("refuses on a finding where it enforces", async () => {
    expect(await underMandate({ amount: 100 }, { review: reviewer("not_entailed") })).toMatchObject({ decision: "deny", reason: "semantic_denied", credentialId: mandate.id, reviewer: { id: "reys" } });
    expect(await underMandate({ amount: 100 }, { review: reviewer("escalate") })).toMatchObject({ decision: "deny", reason: "semantic_review" });
  });

  // @invariant §15.2: a call is decided without the reviewer when it is out of service, not deployed, or not
  // enforcing — and the decision says so.
  it("decides without it when it gives no answer or does not enforce yet", async () => {
    expect(await underMandate({ amount: 100 }, { review: reviewer("unavailable") })).toMatchObject({ decision: "allow", reviewed: "unavailable" });
    expect(await underMandate({ amount: 100 })).toMatchObject({ decision: "allow", reviewed: "unavailable" });
    expect(await underMandate({ amount: 100 }, { review: reviewer("not_entailed"), reviewEnforces: false })).toMatchObject({ decision: "allow", reviewed: "not_enforcing" });
    expect(await underMandate({ amount: 100 }, { review: reviewer("entailed"), reviewEnforces: false })).toMatchObject({ decision: "allow", reviewed: "agreed" });
  });

  // @invariant §15.2: only an outage passes — a request the reviewer cannot read is refused.
  it("refuses a request the reviewer cannot read, enforcing or not", async () => {
    for (const reviewEnforces of [true, false]) {
      expect(await underMandate({ amount: 100 }, { review: reviewer("unreadable"), reviewEnforces })).toMatchObject({ decision: "deny", reason: "reviewer_unavailable" });
    }
  });

  // @invariant §15.2: a tool the policy marks `reviewer: "required"` passes only with the reviewer's agreement.
  it("holds a tool marked `reviewer: required` to the reviewer's agreement", async () => {
    const required = { policy: versionOf(policyOf({ reviewer: "required" })) };
    expect(await underMandate({ amount: 100 }, { ...required, review: reviewer("entailed") })).toMatchObject({ decision: "allow", reviewed: "agreed" });
    expect(await underMandate({ amount: 100 }, required)).toMatchObject({ decision: "deny", reason: "reviewer_unavailable", reviewed: "unavailable" });
    expect(await underMandate({ amount: 100 }, { ...required, review: reviewer("unavailable") })).toMatchObject({ decision: "deny", reason: "reviewer_unavailable" });
    // Not enforcing elsewhere, it still enforces here.
    expect(await underMandate({ amount: 100 }, { ...required, review: reviewer("not_entailed"), reviewEnforces: false })).toMatchObject({ decision: "deny", reason: "semantic_denied" });
  });

  it("is not asked about a call the rules already refused, or one the policy settles itself", async () => {
    let asked = 0;
    const review = async () => (asked++, { verdict: "entailed" as const });
    await underMandate({ amount: 300 }, { review });
    await underPolicy("stripe/list_refunds", { limit: 5 }, { review });
    expect(asked).toBe(0);
  });
});

describe("the decision's signed event (§15.8)", () => {
  const signer = () => ({ privateKey: HUMANOS.privateKey, verificationMethod: HUMANOS_VM });
  const record = (result: Awaited<ReturnType<typeof underMandate>>, params: Record<string, unknown>) =>
    buildLimitsVerificationEvent({ result, tool: TOOL, toolHash: held(TOOL), params, issuer: VERIFIER, popNonceRef: "n-1" }, signer());

  // @invariant §15.8: an evaluation names its rule by its place; the event says what the reviewer did, names the
  // tool and the definition, and carries no `enforcement`.
  it("records an allow on the mandate's chain, with each rule's place and the reviewer's part", async () => {
    const result = await underMandate({ amount: 100 }, { review: reviewer("entailed") });
    const ev = record(result, { amount: 100 });
    expect((await verifyEvent(ev, async () => HUMANOS.publicKey)).valid).toBe(true);
    expect(ev.issuer).toBe(VERIFIER);
    expect(ev.credentialSubject).toMatchObject({
      id: mandate.id,
      event: "VERIFICATION_APPROVED",
      tool: TOOL,
      toolHash: held(TOOL),
      executionParams: { amount: 100 },
      reviewed: "agreed",
      review: { id: "reys", version: "5" },
      policyDigest: versionOf(policyOf()).policyDigest,
      actionHash: limitsActionHash({ mandateId: mandate.id }, TOOL, { amount: 100 }, held(TOOL)),
      assuranceEvaluated: "device",
      evaluations: [
        { in: `${POLICY_URN}#5`, tool: TOOL, rule: 0, result: "pass" },
        { in: mandate.id, tool: TOOL, rule: 0, result: "pass" },
      ],
    });
    expect(ev.credentialSubject).not.toHaveProperty("enforcement");
  });

  it("records a refusal on the agent's lane, with the tool and who may grant it", async () => {
    const result = await underPolicy(TOOL, { amount: 100 });
    const ev = record(result, { amount: 100 });
    expect(ev.credentialSubject).toMatchObject({ id: POLICY_URN, agentDid: SUPPORT, event: "VERIFICATION_DENIED", reason: "mandate_required", tool: TOOL, grantors: [ANA] });
    expect(ev.credentialSubject).not.toHaveProperty("reviewed");
  });

  it("records the input a call should not have carried, and the words beside a code", async () => {
    const undeclared = record(await underMandate({ amount: 100, destination: "acct_x" }), { amount: 100, destination: "acct_x" });
    expect(undeclared.credentialSubject).toMatchObject({ event: "VERIFICATION_DENIED", reason: "param_undeclared", input: "destination" });
    const stale = await underMandate({ amount: 100 }, {}, mandate, TOOL, "sha256-other");
    expect(record(stale, { amount: 100 }).credentialSubject).toMatchObject({ reason: "tool_changed", detail: "the call was made from another definition than the one on record" });
  });

  it("has no rung to record for a call refused before its proof held, unless the caller gives one", async () => {
    const none = await verifyLimitsCall({ agentDid: SUPPORT, policy: POLICY_URN, pop: "x", tool: TOOL, params: {} } as never, deps());
    expect(none).not.toHaveProperty("agent");
    expect(() => record(none, {})).toThrow(/records the rung/);
    const agent = { assurance: "device" as const, binding: "self" as const, verifiedAt: now.getTime() };
    const ev = buildLimitsVerificationEvent({ result: none, tool: TOOL, toolHash: "", issuer: VERIFIER, popNonceRef: "n-1", agent }, signer());
    expect(ev.credentialSubject).toMatchObject({ event: "VERIFICATION_DENIED", reason: "tool_changed", detail: "the call names no definition of the tool" });
  });
});

describe("the reviewer before a mandate is issued (§15.2)", () => {
  const asked: unknown[] = [];
  const reviewLimits = (verdict: SemanticReviewVerdict["verdict"]) => async (input: unknown) => (asked.push(input), { verdict, reviewer: { id: "reys", version: "5" } });

  // @invariant §15.2: before issue the reviewer compares the rules with the words, and a mismatch refuses the request.
  it("is asked about the limits and the words, and refuses a mismatch where it enforces", async () => {
    expect(await reviewMandateRequest(policyOf(), limits(), { reviewLimits: reviewLimits("entailed") })).toEqual({ ok: true, reviewed: "agreed", reviewer: { id: "reys", version: "5" } });
    expect(asked.at(-1)).toMatchObject({ description: { text: "Refund order 1182 to the customer, up to 120 EUR" }, maxExecutions: 1, tools: { [TOOL]: { rules: [{ conditions: [{ left: "amount", operator: "<=", value: 120 }] }] } } });
    expect(await reviewMandateRequest(policyOf(), limits(), { reviewLimits: reviewLimits("not_entailed") })).toMatchObject({ ok: false, reason: "semantic_denied" });
    expect(await reviewMandateRequest(policyOf(), limits(), { reviewLimits: reviewLimits("escalate") })).toMatchObject({ ok: false, reason: "semantic_review" });
  });

  it("lets a request stand without it on an outage or before it enforces, and says so", async () => {
    expect(await reviewMandateRequest(policyOf(), limits())).toEqual({ ok: true, reviewed: "unavailable" });
    expect(await reviewMandateRequest(policyOf(), limits(), { reviewLimits: reviewLimits("unavailable") })).toMatchObject({ ok: true, reviewed: "unavailable" });
    expect(await reviewMandateRequest(policyOf(), limits(), { reviewLimits: reviewLimits("not_entailed"), reviewEnforces: false })).toMatchObject({ ok: true, reviewed: "not_enforcing" });
  });

  // @invariant §15.2: only an outage passes.
  it("refuses a request the reviewer cannot read, enforcing or not", async () => {
    for (const reviewEnforces of [true, false]) {
      expect(await reviewMandateRequest(policyOf(), limits(), { reviewLimits: reviewLimits("unreadable"), reviewEnforces })).toMatchObject({ ok: false, reason: "reviewer_unavailable" });
    }
  });

  // @invariant §15.2: no mandate is issued for a tool marked `reviewer: required` unless the reviewer agreed.
  it("issues no mandate for a tool marked `reviewer: required` without the reviewer's agreement", async () => {
    const required = policyOf({ reviewer: "required" });
    expect(await reviewMandateRequest(required, limits())).toEqual({ ok: false, reason: "reviewer_unavailable", reviewed: "unavailable" });
    expect(await reviewMandateRequest(required, limits(), { reviewLimits: reviewLimits("not_entailed"), reviewEnforces: false })).toMatchObject({ ok: false, reason: "semantic_denied" });
    expect(await reviewMandateRequest(required, limits(), { reviewLimits: reviewLimits("entailed") })).toMatchObject({ ok: true, reviewed: "agreed" });
  });

  it("signs into the mandate what the reviewer did at issue", async () => {
    const outcome = await reviewMandateRequest(policyOf(), limits(), { reviewLimits: reviewLimits("entailed") });
    if (!outcome.ok) throw new Error("refused");
    expect(issue({ reviewed: outcome.reviewed }).credentialSubject.mandate.reviewed).toBe("agreed");
  });
});
