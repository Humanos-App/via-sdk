import { describe, it, expect, beforeAll } from "vitest";
import {
  actionDigestSRI,
  actionHash,
  buildActionVersion,
  buildMandate,
  buildOutcomeEvent,
  buildPoP,
  buildVerificationEvent,
  eventChainLink,
  eventScopeOf,
  evaluatePolicy,
  executionParamsRead,
  foldActorChain,
  generateEd25519Key,
  generateP256Key,
  jwkThumbprint,
  policyActionHash,
  policyDigest,
  policyEntryFor,
  policyPublishIssues,
  stampMandate,
  verifyAgentDirect,
  verifyAgentUnderPolicy,
  type ActionDetail,
  type AgentUnderPolicyDeps,
  type BoundKey,
  type P256KeyPair,
  type PolicyPublishContext,
  type ViaEvent,
  type ViaMandateCredential,
  type ViaPolicy,
} from "../src/index.js";

/**
 * v0.3 §21 — the organization's policy: one per organization, over every call of every agent it
 * operates. With no mandate it is the call's only authority; under one it caps the call.
 */

const ORG = "did:web:acme.example";
const SUPPORT = "did:web:humanos.tech:agent:support";
const SALES = "did:web:humanos.tech:agent:sales";
const ANA = "did:web:humanos.tech:user:ana";
const RUI = "did:web:humanos.tech:user:rui";
const POLICY_URN = "urn:via:policy:acme";
const VERIFIER = "did:web:acme.example";
const now = new Date("2026-10-20T09:00:00.000Z");

/** Messages to listed channels only; listing channels has no limits. */
const SLACK: ActionDetail = buildActionVersion({
  $id: "urn:via:action:slack",
  version: "1",
  tools: ["slack_send_message", "slack_list_channels"],
  unrestricted: ["slack_list_channels"],
  executionParams: { channel_id: { type: "string" } },
  rules: [{
    name: "support_channel",
    description: "Messages go only to #support",
    appliesTo: ["slack_send_message"],
    requires: ["channel_id"],
    conditions: [{ left: "executionParams.channel_id", operator: "==", right: "C-support" }],
  }],
});
// A literal on the right: the condition generator reads it as a ref, so the expression is set here.
SLACK.rules[0]!.expression = 'executionParams.channel_id == "C-support"';

/** Refunds up to €100, each confirmed (step-up). */
const REFUNDS: ActionDetail = {
  $id: "urn:via:action:refunds",
  type: "VIAAction",
  version: "1",
  tools: ["refund_order"],
  unrestricted: [],
  userParams: {},
  executionParams: { amount: { type: "number", required: true } },
  rules: [{ name: "refund_cap", description: "A refund is at most €100", appliesTo: ["refund_order"], conditions: [], expression: "executionParams.amount <= 100" }],
  stepUp: { tools: ["refund_order"] },
};

/** Every call: a key at least device-bound. */
const FLOOR: ActionDetail = {
  $id: "urn:via:action:floor",
  type: "VIAAction",
  version: "1",
  userParams: {},
  executionParams: {},
  rules: [{ name: "device_or_better", description: "The agent's key is at least device-bound", conditions: [], expression: 'assuranceRank(agent.assurance) >= assuranceRank("device")' }],
};

const ACTIONS = new Map([SLACK, REFUNDS, FLOOR].map((a) => [a.$id, a]));
const ref = (a: ActionDetail) => ({ id: a.$id, digestSRI: actionDigestSRI(a) });

const POLICY: ViaPolicy = {
  $id: POLICY_URN,
  type: "VIAPolicy",
  version: 4,
  everyCall: ref(FLOOR),
  approvers: [ANA],
  entries: [
    { tool: "kb_search", effect: "allow" },
    { tool: "kb_search", effect: "deny", agents: [SALES] },
    { tool: "slack_delete_channel", effect: "deny" },
    { tool: "slack_send_message", effect: "rules", action: ref(SLACK) },
    { tool: "slack_list_channels", effect: "rules", action: ref(SLACK) },
    { tool: "refund_order", effect: "rules", action: ref(REFUNDS), agents: [SUPPORT], approvers: [ANA, RUI] },
    { tool: "issue_credit", effect: "mandate" },
  ],
};
const VERSION = { content: POLICY, policyDigest: policyDigest(POLICY) };

const CONTEXT: PolicyPublishContext = {
  ownAction: (r) => {
    const a = ACTIONS.get(r.id);
    return a && actionDigestSRI(a) === r.digestSRI ? a : null;
  },
  operates: (did) => did === SUPPORT || did === SALES,
  isMember: (did) => did === ANA || did === RUI,
};

let supportKey: P256KeyPair;
const keyOf = (k: P256KeyPair, did: string, assurance: BoundKey["assurance"] = "device"): BoundKey => ({
  did,
  cnf: { jwk: k.publicJwk },
  assurance,
  binding: "self",
  verifiedAt: now.getTime() - 1000,
});

beforeAll(async () => {
  supportKey = await generateP256Key();
});

async function popFor(key: P256KeyPair, hash: string): Promise<string> {
  return buildPoP({ cnf: { jkt: jwkThumbprint(key.publicJwk) }, aud: VERIFIER, nonce: "n-1", iat: 1, action_hash: hash }, key.privateJwk);
}

const deps = (over: Partial<AgentUnderPolicyDeps> = {}): AgentUnderPolicyDeps => ({
  verifier: { did: VERIFIER },
  candidates: [keyOf(supportKey, SUPPORT)],
  policy: VERSION,
  loadActionVersion: (id) => ACTIONS.get(id) ?? null,
  validateNonce: () => "ok",
  now,
  ...over,
});

async function underPolicy(tool: string, params: Record<string, unknown>, over: Partial<AgentUnderPolicyDeps> = {}, agentDid = SUPPORT) {
  const pop = await popFor(supportKey, policyActionHash(POLICY_URN, tool, params));
  return verifyAgentUnderPolicy({ agentDid, policy: POLICY_URN, pop, action: tool, params }, deps(over));
}

describe("which entry applies (§21.1)", () => {
  // @invariant §21.1: the most specific entry wins — one naming the agent beats one naming none.
  it("prefers the entry naming the agent, and covers every other agent with the general one", () => {
    expect(policyEntryFor(POLICY, "kb_search", SALES)?.effect).toBe("deny");
    expect(policyEntryFor(POLICY, "kb_search", SUPPORT)?.effect).toBe("allow");
    expect(policyEntryFor(POLICY, "kb_search", "did:web:humanos.tech:agent:new")?.effect).toBe("allow");
    expect(policyEntryFor(POLICY, "refund_order", SALES)).toBeUndefined();
  });
});

describe("what may be published (§21.1)", () => {
  it("accepts the example policy", () => {
    expect(policyPublishIssues(POLICY, CONTEXT)).toEqual([]);
  });

  // @invariant §21.1: two entries at one level for one tool are refused, so order never decides.
  it("refuses two entries at one level for one tool and agent", () => {
    const twice = { ...POLICY, entries: [...POLICY.entries, { tool: "kb_search", effect: "deny" as const }] };
    expect(policyPublishIssues(twice, CONTEXT)).toEqual(["entry 8 (kb_search) overlaps another entry for kb_search"]);
    const sameAgent = { ...POLICY, entries: [...POLICY.entries, { tool: "kb_search", effect: "allow" as const, agents: [SALES] }] };
    expect(policyPublishIssues(sameAgent, CONTEXT)).toEqual([`entry 8 (kb_search) overlaps another entry for kb_search and ${SALES}`]);
  });

  it("refuses an action that is not the organization's, or does not list the entry's tool", () => {
    const foreign = { ...POLICY, entries: [{ tool: "pay", effect: "rules" as const, action: { id: "urn:via:action:theirs", digestSRI: "sha256-x" } }] };
    expect(policyPublishIssues(foreign, CONTEXT)).toEqual(["entry 1 (pay): its action is not a published action of the organization's own"]);
    const unlisted = { ...POLICY, entries: [{ tool: "slack_archive", effect: "rules" as const, action: ref(SLACK) }] };
    expect(policyPublishIssues(unlisted, CONTEXT)).toEqual(["entry 1 (slack_archive): its action does not list slack_archive in `tools`"]);
  });

  it("refuses an everyCall action that lists tools, an agent it does not operate, and an approver who is no member", () => {
    const bad: ViaPolicy = {
      ...POLICY,
      everyCall: ref(SLACK),
      approvers: ["did:web:humanos.tech:user:stranger"],
      entries: [{ tool: "kb_search", effect: "allow", agents: ["did:web:other.example:agent:x"] }],
    };
    expect(policyPublishIssues(bad, CONTEXT)).toEqual([
      "the `everyCall` action lists `tools`: it governs every call, whatever the tool",
      "approver did:web:humanos.tech:user:stranger is not a member of the organization",
      "entry 1 (kb_search): the organization does not operate did:web:other.example:agent:x",
    ]);
  });
});

describe("a call with no mandate (§21.3, §21.4)", () => {
  it("allows what the policy allows, and names the policy and the agent", async () => {
    expect(await underPolicy("kb_search", {})).toMatchObject({
      decision: "allow",
      enforcement: "policy",
      policy: POLICY_URN,
      agentDid: SUPPORT,
      policyDigest: VERSION.policyDigest,
    });
  });

  it("runs a `rules` entry's action, and says when the tool is unrestricted", async () => {
    expect(await underPolicy("slack_send_message", { channel_id: "C-general" })).toMatchObject({ decision: "deny", reason: "policy_denied" });
    expect(await underPolicy("slack_send_message", { channel_id: "C-support" })).toMatchObject({ decision: "allow" });
    expect(await underPolicy("slack_list_channels", {})).toMatchObject({ decision: "allow", unrestricted: true });
  });

  // @invariant §21.3: a tool the policy says nothing about, or marks `mandate`, needs a person's mandate.
  it("needs a person's mandate for a tool with no entry, a `mandate` entry, or an organization with no policy", async () => {
    expect(await underPolicy("send_invoice", {})).toMatchObject({ decision: "deny", reason: "mandate_required" });
    expect(await underPolicy("issue_credit", {})).toMatchObject({ decision: "deny", reason: "mandate_required" });
    expect(await underPolicy("kb_search", {}, { policy: null })).toMatchObject({ decision: "deny", reason: "mandate_required" });
  });

  it("refuses a `deny` entry, and the rules every call must pass", async () => {
    expect(await underPolicy("slack_delete_channel", {})).toMatchObject({ decision: "deny", reason: "policy_denied" });
    const popKey = keyOf(supportKey, SUPPORT, "pop");
    expect(await underPolicy("kb_search", {}, { candidates: [popKey] })).toMatchObject({
      decision: "deny",
      reason: "policy_denied",
      evaluations: [{ rule: "device_or_better", result: "fail" }],
    });
  });

  // @invariant §21.3: the step-up an entry's action asks for goes to the entry's approvers — the
  // policy's when it names none — and with no approver named is refused.
  it("takes a step-up to the policy's approvers, and refuses it with none named", async () => {
    expect(await underPolicy("refund_order", { amount: 40 })).toMatchObject({ decision: "rechallenge", stepUp: { trigger: "policy" }, approvers: [ANA, RUI] });
    expect(await underPolicy("refund_order", { amount: 40 }, { stepUpSatisfied: true })).toMatchObject({ decision: "allow" });
    expect(await underPolicy("refund_order", { amount: 400 })).toMatchObject({ decision: "deny", reason: "policy_denied" });

    const fromPolicy = { ...POLICY, entries: POLICY.entries.map((e) => (e.tool === "refund_order" ? { ...e, approvers: undefined } : e)) };
    const viaPolicy = await underPolicy("refund_order", { amount: 40 }, { policy: { content: fromPolicy, policyDigest: policyDigest(fromPolicy) } });
    expect(viaPolicy).toMatchObject({ decision: "rechallenge", approvers: [ANA] });

    const nobody = { ...fromPolicy, approvers: undefined };
    expect(await underPolicy("refund_order", { amount: 40 }, { policy: { content: nobody, policyDigest: policyDigest(nobody) } })).toMatchObject({
      decision: "deny",
      reason: "stepup_required",
    });
  });

  // @invariant §21.4: the PoP binds the policy — one made for a mandate does not pass here.
  it("refuses a PoP bound to anything but the policy presented", async () => {
    const params = {};
    const forMandate = await popFor(supportKey, actionHash("urn:via:credential:x", "kb_search", params));
    expect(await verifyAgentUnderPolicy({ agentDid: SUPPORT, policy: POLICY_URN, pop: forMandate, action: "kb_search", params }, deps())).toMatchObject({
      decision: "deny",
      reason: "action_hash_mismatch",
    });
    const other = "urn:via:policy:someone-else";
    const pop = await popFor(supportKey, policyActionHash(other, "kb_search", params));
    expect(await verifyAgentUnderPolicy({ agentDid: SUPPORT, policy: other, pop, action: "kb_search", params }, deps())).toMatchObject({
      decision: "deny",
      reason: "policy_denied",
    });
  });
});

describe("the policy under a mandate (§21.3 step 4)", () => {
  const PLATFORM = generateEd25519Key();
  const PLATFORM_VM = "did:web:humanos.tech#key-1";
  let mandate: ViaMandateCredential;
  const MESSAGES: ActionDetail = {
    $id: "urn:via:action:messages",
    type: "VIAAction",
    version: "1",
    tools: ["slack_send_message", "slack_delete_channel", "refund_order"],
    unrestricted: ["slack_send_message", "slack_delete_channel", "refund_order"],
    userParams: {},
    executionParams: { channel_id: { type: "string" }, amount: { type: "number" } },
    rules: [],
  };

  beforeAll(() => {
    mandate = stampMandate(
      buildMandate({
        subjectOrg: ORG,
        grantor: "did:web:humanos.tech:user:customer",
        authorizedDIDs: [VERIFIER],
        authorizedAgents: [keyOf(supportKey, SUPPORT)],
        action: { id: MESSAGES.$id, digestSRI: actionDigestSRI(MESSAGES), location: "https://api.humanos.tech/actions/messages" },
        validFrom: "2026-01-01T00:00:00.000Z",
        description: { text: "Message on my behalf.", lang: "en", author: "issuer" },
        enforcement: "rules",
      }),
      { privateKey: PLATFORM.privateKey, verificationMethod: PLATFORM_VM },
    );
  });

  const call = async (tool: string, params: Record<string, unknown>, over: Partial<Parameters<typeof verifyAgentDirect>[2]> = {}) =>
    verifyAgentDirect(
      mandate,
      { pop: await popFor(supportKey, actionHash(mandate.id, tool, params)), action: tool, params },
      {
        verifier: { did: VERIFIER },
        resolvePublicKey: () => PLATFORM.publicKey,
        candidates: [keyOf(supportKey, SUPPORT)],
        loadCredentialRecord: async () => ({ status: "ACTIVE", validFrom: "2026-01-01T00:00:00.000Z" }),
        loadActionVersion: (id) => (id === MESSAGES.$id ? MESSAGES : ACTIONS.get(id) ?? null),
        validateNonce: () => "ok",
        now,
        policy: VERSION,
        ...over,
      },
    );

  // @invariant §21.3: a `deny` in the policy refuses what the person's mandate grants; a failing `rules`
  // entry does too; an allow carries the version it read.
  it("refuses what the policy denies, whatever the mandate grants", async () => {
    expect(await call("slack_delete_channel", {})).toMatchObject({ decision: "deny", reason: "policy_denied", policyDigest: VERSION.policyDigest });
    expect(await call("slack_send_message", { channel_id: "C-general" })).toMatchObject({ decision: "deny", reason: "policy_denied" });
    expect(await call("slack_send_message", { channel_id: "C-support" })).toMatchObject({
      decision: "allow",
      enforcement: "rules",
      policyDigest: VERSION.policyDigest,
    });
  });

  // @invariant §21.3: a confirmation goes to whoever wrote the rule that asks for it — the policy's to its
  // approvers, under a customer's mandate too; the mandate's to its grantor, first.
  it("takes the policy's confirmation to its approvers under a mandate, after the grantor's own", async () => {
    expect(await call("refund_order", { amount: 40 })).toMatchObject({
      decision: "rechallenge",
      stepUp: { trigger: "policy" },
      approvers: [ANA, RUI],
    });
    expect(await call("refund_order", { amount: 40 }, { policyStepUpSatisfied: true })).toMatchObject({ decision: "allow" });
    // The mandate asks too: its grantor first, then the approvers, then the call runs.
    const asks = { requiresStepUp: (tool: string) => tool === "refund_order" };
    expect(await call("refund_order", { amount: 40 }, asks)).toMatchObject({ decision: "rechallenge", stepUp: { trigger: "action" } });
    expect(await call("refund_order", { amount: 40 }, { ...asks, stepUpSatisfied: true })).toMatchObject({
      decision: "rechallenge",
      stepUp: { trigger: "policy" },
    });
    expect(await call("refund_order", { amount: 40 }, { ...asks, stepUpSatisfied: true, policyStepUpSatisfied: true })).toMatchObject({ decision: "allow" });
  });
});

describe("the decisions' chain (§21.5)", () => {
  const key = generateEd25519Key();
  const signer = { privateKey: key.privateKey, verificationMethod: `${VERIFIER}#key-1` };
  const env = { assurance: "device" as const, binding: "self" as const, verifiedAt: now.getTime() };

  // @invariant §21.5: a decision with no mandate is about the policy and the agent, policy-scoped.
  it("puts a decision with no mandate on the policy and the agent, and scopes it there", () => {
    const decision = buildVerificationEvent(
      { policy: { id: POLICY_URN, agentDid: SUPPORT }, decision: "allow", issuer: VERIFIER, agent: env, popNonceRef: "n-1", enforcement: "policy", policyDigest: VERSION.policyDigest },
      signer,
    )!;
    expect(decision.credentialSubject).toMatchObject({ id: POLICY_URN, agentDid: SUPPORT, event: "VERIFICATION_APPROVED", policyDigest: VERSION.policyDigest });
    expect(eventScopeOf(decision)).toBe("policy");
    const outcome = buildOutcomeEvent({ policy: { id: POLICY_URN, agentDid: SUPPORT }, outcome: "completed", decision: decision.id, issuer: VERIFIER }, signer);
    expect(eventScopeOf(outcome)).toBe("policy");
    const onMandate = buildOutcomeEvent({ mandateId: "urn:via:credential:x", outcome: "completed", decision: decision.id, issuer: VERIFIER }, signer);
    expect(eventScopeOf(onMandate)).toBe("credential");
    expect(() => buildOutcomeEvent({ outcome: "completed", decision: decision.id, issuer: VERIFIER }, signer)).toThrow(/exactly one/);
  });
});

describe("POLICY_PUBLISHED in the fold (§5, §21.2)", () => {
  function chain(subject: string, steps: [string, Record<string, unknown>, string][]): ViaEvent[] {
    const out: ViaEvent[] = [];
    steps.forEach(([event, fields, issuer], i) => {
      const prev = out[out.length - 1];
      out.push({
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://via.humanos.tech/ns/v1"],
        id: `urn:via:event:policy-${i}`,
        type: ["VerifiableCredential", "VIAEvent"],
        specVersion: "0.3",
        issuer,
        validFrom: `2026-10-${String(i + 10)}T00:00:00.000Z`,
        credentialSubject: { id: subject, event, previousEvent: prev ? eventChainLink(prev) : null, ...fields },
      } as unknown as ViaEvent);
    });
    return out;
  }
  const genesis = (actorType: string): [string, Record<string, unknown>, string] =>
    ["ACTOR_REGISTERED", { actorType, keyId: `${ORG}#key-1`, publicKeyMultibase: "z6MkAcme", bootstrapAnchor: "manual" }, "did:web:humanos.tech"];
  const published = (version: number, over: Record<string, unknown> = {}, issuer = ORG): [string, Record<string, unknown>, string] =>
    ["POLICY_PUBLISHED", { policy: POLICY_URN, version, policyDigest: `sha256-v${version}`, publishedBy: ANA, ...over }, issuer];

  it("records the current version, and who accepted it", () => {
    const r = foldActorChain(chain(ORG, [genesis("organization"), published(1), published(2, { publishedBy: RUI })]));
    expect(r.ok).toBe(true);
    expect(r.ok && r.subject.policy).toMatchObject({ id: POLICY_URN, version: 2, policyDigest: "sha256-v2", publishedBy: RUI });
  });

  it("refuses one out of sequence, of another policy, unsigned by the organization, or with no member", () => {
    const refused = (steps: [string, Record<string, unknown>, string][]) => foldActorChain(chain(ORG, [genesis("organization"), ...steps]));
    expect(refused([published(2)])).toMatchObject({ ok: false, reason: "policy_invalid", at: 1 });
    expect(refused([published(1), published(3)])).toMatchObject({ ok: false, reason: "policy_invalid", at: 2 });
    expect(refused([published(1), published(2, { policy: "urn:via:policy:other" })])).toMatchObject({ ok: false, reason: "policy_invalid" });
    expect(refused([published(1, {}, "did:web:humanos.tech")])).toMatchObject({ ok: false, reason: "policy_invalid" });
    expect(refused([published(1, { publishedBy: undefined })])).toMatchObject({ ok: false, reason: "policy_invalid" });
  });

  it("refuses a policy on an agent or a person", () => {
    const agent = "did:web:humanos.tech:agent:x";
    expect(foldActorChain(chain(agent, [genesis("agent"), published(1, {}, agent)]))).toMatchObject({ ok: false, reason: "policy_on_non_organization" });
  });
});

describe("evaluatePolicy (§21.3)", () => {
  // @invariant §21.1: a rule for every call that reads a parameter is `skip` on a call without it — a
  // payment cap never denies a search.
  it("skips a rule for every call on a call that lacks the parameter it reads", async () => {
    const CAP: ActionDetail = {
      $id: "urn:via:action:cap",
      type: "VIAAction",
      version: "1",
      userParams: {},
      executionParams: {},
      rules: [{ name: "payment_cap", description: "No payment over €5,000", conditions: [], expression: "executionParams.amount <= 5000" }],
    };
    const capped: ViaPolicy = { $id: POLICY_URN, type: "VIAPolicy", version: 1, everyCall: ref(CAP), entries: [{ tool: "kb_search", effect: "allow" }, { tool: "pay", effect: "allow" }] };
    const run = (tool: string, params: Record<string, unknown>) =>
      evaluatePolicy(capped, { tool, params, agent: { did: SUPPORT } }, { loadActionVersion: (id) => (id === CAP.$id ? CAP : null) });
    expect(await run("kb_search", { query: "refund policy" })).toMatchObject({
      outcome: "allow",
      evaluations: [{ rule: "payment_cap", result: "skip", reason: "the call carries no amount" }],
    });
    expect(await run("pay", { amount: 9000 })).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(await run("pay", { amount: 40 })).toMatchObject({ outcome: "allow", evaluations: [{ rule: "payment_cap", result: "pass" }] });
  });

  it("reads the parameters an expression uses from its parse tree, not its text", () => {
    expect(executionParamsRead('executionParams.amount <= 5000 && executionParams["max-results"] < 10')?.sort()).toEqual(["amount", "max-results"]);
    expect(executionParamsRead('executionParams.note == "executionParams.secret"')).toEqual(["note"]);
    expect(executionParamsRead('assuranceRank(agent.assurance) >= assuranceRank("device")')).toEqual([]);
    expect(executionParamsRead("executionParams.amount <=")).toBeNull();
  });

  it("reads the action at its pinned digest, never a changed one", async () => {
    const changed = { ...REFUNDS, rules: [{ ...REFUNDS.rules[0]!, expression: "true" }] };
    const r = await evaluatePolicy(POLICY, { tool: "refund_order", params: { amount: 400 }, agent: { did: SUPPORT, assurance: "device" } }, {
      loadActionVersion: (id) => (id === REFUNDS.$id ? changed : ACTIONS.get(id) ?? null),
    });
    expect(r).toMatchObject({ outcome: "deny", reason: "action_invalid" });
  });
});
