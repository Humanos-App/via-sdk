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
  policyEntriesFor,
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
  ownGuardrail: (r) => ACTIONS.has(r.id),
  ownVersion: (r) => ACTIONS.get(r.id) ?? null,
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
  const none = () => new Set<string>();
  // @invariant §21.1: the most specific entry wins — one naming the agent beats one naming none.
  it("prefers the entry naming the agent, and covers every other agent with the general one", () => {
    expect(policyEntriesFor(POLICY, "kb_search", SALES, none)[0]?.effect).toBe("deny");
    expect(policyEntriesFor(POLICY, "kb_search", SUPPORT, none)[0]?.effect).toBe("allow");
    expect(policyEntriesFor(POLICY, "kb_search", "did:web:humanos.tech:agent:new", none)[0]?.effect).toBe("allow");
    expect(policyEntriesFor(POLICY, "refund_order", SALES, none)).toEqual([]);
  });

  // @invariant §21.1: the levels, in order — tool and agent, guardrail and agent, tool, guardrail — and within one,
  // the most restrictive first.
  it("ranks a tool over a guardrail within each level, an agent's over everyone's, and the most restrictive first", () => {
    const slack = new Set(["slack_send_message", "slack_list_channels"]);
    const ops = new Set(["slack_list_channels"]);
    const toolsOf = (g: { id: string }) => (g.id === "slack" ? slack : g.id === "ops" ? ops : new Set<string>());
    const policy = {
      entries: [
        { guardrail: { id: "slack" }, effect: "deny" as const },
        { guardrail: { id: "ops" }, effect: "allow" as const },
        { tool: "slack_send_message", effect: "allow" as const, agents: [SUPPORT] },
        { guardrail: { id: "slack" }, effect: "allow" as const, agents: [SALES] },
        { tool: "slack_list_channels", effect: "allow" as const },
      ],
    };
    expect(policyEntriesFor(policy, "slack_send_message", SUPPORT, toolsOf).map((e) => e.effect)).toEqual(["allow"]);
    expect(policyEntriesFor(policy, "slack_send_message", SALES, toolsOf).map((e) => e.guardrail?.id)).toEqual(["slack"]);
    expect(policyEntriesFor(policy, "slack_list_channels", SUPPORT, toolsOf).map((e) => e.tool)).toEqual(["slack_list_channels"]);
    expect(policyEntriesFor(policy, "slack_send_message", "did:web:other", toolsOf).map((e) => e.effect)).toEqual(["deny"]);
    // Two guardrails list one tool at one level: the deny comes first, and decides.
    const both = { entries: [{ guardrail: { id: "ops" }, effect: "allow" as const }, { guardrail: { id: "slack" }, effect: "deny" as const }] };
    expect(policyEntriesFor(both, "slack_list_channels", SUPPORT, toolsOf).map((e) => e.effect)).toEqual(["deny", "allow"]);
  });
});

describe("a guardrail as the target (§21.1)", () => {
  /** Payments: two tools. A later version of Slack adds `slack_archive` — the policy names neither version. */
  const PAYMENTS: ActionDetail = {
    $id: "urn:via:action:payments",
    type: "VIAAction",
    version: "1",
    tools: ["pay_invoice", "transfer"],
    unrestricted: ["pay_invoice", "transfer"],
    userParams: {},
    executionParams: { amount: { type: "number" }, invoice_id: { type: "string" } },
    rules: [],
  };
  const CAP: ActionDetail = {
    $id: "urn:via:action:cap-5000",
    type: "VIAAction",
    version: "1",
    userParams: {},
    executionParams: {},
    rules: [{ name: "payment_cap", description: "At most €5,000 a call", requires: ["amount"], conditions: [], expression: "executionParams.amount <= 5000" }],
  };
  const all = new Map([...ACTIONS, [PAYMENTS.$id, PAYMENTS], [CAP.$id, CAP]]);
  const groups: Record<string, string[]> = {
    [SLACK.$id]: ["slack_send_message", "slack_list_channels", "slack_archive"],
    [PAYMENTS.$id]: ["pay_invoice", "transfer"],
  };
  const policy: ViaPolicy = {
    $id: POLICY_URN,
    type: "VIAPolicy",
    version: 5,
    entries: [
      { guardrail: { id: SLACK.$id }, effect: "deny" },
      { tool: "slack_send_message", effect: "allow", agents: [SUPPORT] },
      { guardrail: { id: PAYMENTS.$id }, effect: "rules", action: ref(CAP) },
    ],
  };
  const run = (tool: string, params: Record<string, unknown>, agent = SALES, mandate?: "guardrail" | "authorization", over: Partial<ViaPolicy> = {}) =>
    evaluatePolicy({ ...policy, ...over }, { tool, params, agent: { did: agent }, ...(mandate ? { mandate } : {}) }, {
      loadActionVersion: (id) => all.get(id) ?? null,
      guardrailTools: (g) => new Set(groups[g.id] ?? []),
    });

  // @invariant §21.1: "Slack is off" covers every tool any version of the Slack guardrail lists, a later one's too.
  it("blocks every tool of a guardrail, one a later version adds included, but for an agent's own exception", async () => {
    expect(await run("slack_list_channels", {})).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(await run("slack_archive", {})).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(await run("slack_send_message", { channel_id: "C-1" }, SUPPORT)).toMatchObject({ outcome: "allow" });
    expect(await run("slack_list_channels", {}, SUPPORT)).toMatchObject({ outcome: "deny" });
  });

  // @invariant §21.1: a guardrail's rules run with `requires` — a payment that states no amount is refused, not skipped.
  it("caps a guardrail's tools, refusing a call that leaves the amount out", async () => {
    expect(await run("pay_invoice", { amount: 40 })).toMatchObject({ outcome: "allow" });
    expect(await run("transfer", { amount: 9000 })).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(await run("pay_invoice", { invoice_id: "123" })).toMatchObject({
      outcome: "deny",
      evaluations: [{ rule: "payment_cap", result: "fail", reason: "required_param_missing:amount" }],
    });
  });

  // @invariant §21.1: with `authorizations: "deny"`, a plain authorization reaches no tool.
  it("refuses a plain authorization where the organization says so, and only that", async () => {
    expect(await run("kb_search", {}, SALES, "authorization", { authorizations: "deny" })).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(await run("kb_search", {}, SALES, "guardrail", { authorizations: "deny" })).toMatchObject({ outcome: "mandate" });
    expect(await run("kb_search", {}, SALES, "authorization")).toMatchObject({ outcome: "mandate" });
  });

  it("refuses to read a policy that targets guardrails with no way to know their tools", async () => {
    await expect(
      evaluatePolicy(policy, { tool: "pay_invoice", params: {}, agent: { did: SALES } }, { loadActionVersion: (id) => all.get(id) ?? null }),
    ).rejects.toThrow(/guardrailTools/);
  });

  it("refuses to publish an entry with two targets, a guardrail of another's, or a guardrail cap that lists tools", () => {
    const issues = policyPublishIssues(
      {
        ...policy,
        entries: [
          { tool: "pay_invoice", guardrail: { id: PAYMENTS.$id }, effect: "deny" },
          { guardrail: { id: "urn:via:action:theirs" }, effect: "deny" },
          { guardrail: { id: PAYMENTS.$id }, effect: "rules", action: ref(SLACK) },
        ],
      },
      { ...CONTEXT, ownAction: (r) => (all.get(r.id) && actionDigestSRI(all.get(r.id)!) === r.digestSRI ? all.get(r.id)! : null), ownGuardrail: (r) => all.has(r.id) },
    );
    expect(issues).toEqual(
      expect.arrayContaining([
        `entry 1 (tool pay_invoice) must target a tool or a guardrail, and only one`,
        `entry 2 (guardrail urn:via:action:theirs): its guardrail is not a published action of the organization's own`,
        `entry 3 (guardrail ${PAYMENTS.$id}): its action lists \`tools\`, and a guardrail entry's governs the guardrail's`,
      ]),
    );
  });
});

describe("what may be published (§21.1)", () => {
  it("accepts the example policy", () => {
    expect(policyPublishIssues(POLICY, CONTEXT)).toEqual([]);
  });

  // @invariant §21.1: two entries at one level for one tool are refused, so order never decides.
  it("refuses two entries at one level for one tool and agent", () => {
    const twice = { ...POLICY, entries: [...POLICY.entries, { tool: "kb_search", effect: "deny" as const }] };
    expect(policyPublishIssues(twice, CONTEXT)).toEqual(["entry 8 (tool kb_search) overlaps another entry for tool kb_search"]);
    const sameAgent = { ...POLICY, entries: [...POLICY.entries, { tool: "kb_search", effect: "allow" as const, agents: [SALES] }] };
    expect(policyPublishIssues(sameAgent, CONTEXT)).toEqual([`entry 8 (tool kb_search) overlaps another entry for tool kb_search and ${SALES}`]);
  });

  it("refuses an action that is not the organization's, or does not list the entry's tool", () => {
    const foreign = { ...POLICY, entries: [{ tool: "pay", effect: "rules" as const, action: { id: "urn:via:action:theirs", digestSRI: "sha256-x" } }] };
    expect(policyPublishIssues(foreign, CONTEXT)).toEqual(["entry 1 (tool pay): its action is not a published action of the organization's own"]);
    const unlisted = { ...POLICY, entries: [{ tool: "slack_archive", effect: "rules" as const, action: ref(SLACK) }] };
    expect(policyPublishIssues(unlisted, CONTEXT)).toEqual(["entry 1 (tool slack_archive): its action does not list slack_archive in `tools`"]);
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
      "entry 1 (tool kb_search): the organization does not operate did:web:other.example:agent:x",
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

  // @invariant §21.3 step 4: a `mandate` entry naming `under` refuses a mandate on another action, `mandate_required`
  // naming the action, and leaves one on that action standing.
  it("refuses a mandate on another action where the tool needs one under a named action", async () => {
    const needs = (id: string) => {
      const content: ViaPolicy = { ...POLICY, entries: [{ tool: "slack_send_message", effect: "mandate", under: { id } }] };
      return { policy: { content, policyDigest: policyDigest(content) }, actionVersions: (a: { id: string }) => new Set([a.id]) };
    };
    expect(await call("slack_send_message", { channel_id: "C-1" }, needs("urn:via:action:credit"))).toMatchObject({
      decision: "deny",
      reason: "mandate_required",
      under: [{ id: "urn:via:action:credit" }],
    });
    expect(await call("slack_send_message", { channel_id: "C-1" }, needs(MESSAGES.$id))).toMatchObject({ decision: "allow" });
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

describe("a tool that needs a mandate under an action (`under`, §21.1, §21.3)", () => {
  /** Two versions of the credit action, Humanos's one group; billing and support also list `issue_credit`. */
  const credit = (version: string): ActionDetail => ({
    $id: `urn:via:action:credit-v${version}`,
    type: "VIAAction",
    version,
    for: "mandate",
    tools: ["issue_credit"],
    unrestricted: ["issue_credit"],
    userParams: {},
    executionParams: {},
    rules: [],
  });
  const CREDIT_V1 = credit("1");
  const CREDIT_V2 = credit("2");
  const BILLING: ActionDetail = { ...credit("1"), $id: "urn:via:action:billing", tools: ["issue_credit", "send_invoice"], unrestricted: ["issue_credit", "send_invoice"] };
  const OTHER: ActionDetail = { ...credit("1"), $id: "urn:via:action:support-desk" };
  const all = new Map([CREDIT_V1, CREDIT_V2, BILLING, OTHER].map((a) => [a.$id, a]));
  const group = (id: string): string[] => (id.startsWith("urn:via:action:credit-") ? [CREDIT_V1.$id, CREDIT_V2.$id] : [id]);
  const deps = {
    loadActionVersion: (id: string) => all.get(id) ?? null,
    guardrailTools: (g: { id: string }) => new Set(group(g.id).flatMap((v) => all.get(v)?.tools ?? [])),
    actionVersions: (a: { id: string }) => new Set(group(a.id)),
  };
  const policy = (entries: ViaPolicy["entries"]): ViaPolicy => ({ $id: POLICY_URN, type: "VIAPolicy", version: 9, entries });
  const run = (p: ViaPolicy, mandate?: "guardrail" | "authorization", mandateAction?: string, over: Partial<typeof deps> = {}) =>
    evaluatePolicy(p, { tool: "issue_credit", params: {}, agent: { did: SUPPORT }, ...(mandate ? { mandate } : {}), ...(mandateAction ? { mandateAction } : {}) }, {
      ...deps,
      ...over,
    });
  const onCredit = policy([{ tool: "issue_credit", effect: "mandate", under: { id: CREDIT_V2.$id } }]);

  // @invariant §21.3: with `under`, only a guardrail mandate on a version of that action meets the entry — any
  // version, the one the person consented to; a plain authorization never does.
  it("takes a mandate on any version of the action named, and refuses every other", async () => {
    expect(await run(onCredit, "guardrail", CREDIT_V1.$id)).toMatchObject({ outcome: "mandate" });
    expect(await run(onCredit, "guardrail", OTHER.$id)).toMatchObject({ outcome: "deny", reason: "mandate_required", under: [{ id: CREDIT_V2.$id }] });
    expect(await run(onCredit, "authorization")).toMatchObject({ outcome: "deny", reason: "mandate_required", under: [{ id: CREDIT_V2.$id }] });
    // Without `under`, any mandate meets it, as before.
    expect(await run(policy([{ tool: "issue_credit", effect: "mandate" }]), "authorization")).toMatchObject({ outcome: "mandate" });
  });

  it("names the action with no mandate, so the agent can ask for one", async () => {
    expect(await run(onCredit)).toMatchObject({ outcome: "mandate", under: [{ id: CREDIT_V2.$id }] });
  });

  // @invariant §21.1: where several `mandate` entries apply at one level, those naming an `under` decide and a mandate
  // under any one of their actions is enough; one naming none adds nothing beside them.
  it("takes a mandate under any of the actions the deciding entries name, and ignores one that names none", async () => {
    const either = policy([
      { guardrail: { id: CREDIT_V1.$id }, effect: "mandate", under: { id: CREDIT_V1.$id } },
      { guardrail: { id: BILLING.$id }, effect: "mandate", under: { id: BILLING.$id } },
    ]);
    expect(await run(either, "guardrail", CREDIT_V2.$id)).toMatchObject({ outcome: "mandate" });
    expect(await run(either, "guardrail", BILLING.$id)).toMatchObject({ outcome: "mandate" });
    expect(await run(either, "guardrail", OTHER.$id)).toMatchObject({ outcome: "deny", reason: "mandate_required", under: [{ id: CREDIT_V1.$id }, { id: BILLING.$id }] });
    const mixed = policy([
      { guardrail: { id: CREDIT_V1.$id }, effect: "mandate", under: { id: CREDIT_V1.$id } },
      { guardrail: { id: BILLING.$id }, effect: "mandate" },
    ]);
    expect(await run(mixed, "guardrail", OTHER.$id)).toMatchObject({ outcome: "deny", reason: "mandate_required", under: [{ id: CREDIT_V1.$id }] });
    expect(await run(mixed, "guardrail", CREDIT_V1.$id)).toMatchObject({ outcome: "mandate" });
  });

  it("refuses to read `under` with no way to know an action's versions, but needs none for a plain authorization", async () => {
    await expect(run(onCredit, "guardrail", CREDIT_V1.$id, { actionVersions: undefined })).rejects.toThrow(/actionVersions/);
    expect(await run(onCredit, "authorization", undefined, { actionVersions: undefined })).toMatchObject({ outcome: "deny", reason: "mandate_required" });
  });

  it("answers `mandate_required` naming the action, on a call with no mandate", async () => {
    const version = { content: onCredit, policyDigest: policyDigest(onCredit) };
    expect(await underPolicy("issue_credit", {}, { policy: version })).toMatchObject({
      decision: "deny",
      reason: "mandate_required",
      under: [{ id: CREDIT_V2.$id }],
      enforcement: "policy",
    });
  });

  // @invariant §21.1: `under` goes with `mandate` only, names an action of the organization's own, and never one written
  // for the policy; the policy names no action written for a mandate.
  it("refuses to publish an `under` elsewhere, of another's, or written for the policy, and a mandate's action", () => {
    const CAP: ActionDetail = { $id: "urn:via:action:cap-c", type: "VIAAction", version: "1", for: "policy", constants: { max: { type: "number", value: 5 } }, executionParams: {}, rules: [{ name: "cap", description: "d", conditions: [], expression: "executionParams.amount <= constants.max" }] };
    const owned = new Map([...all, [CAP.$id, CAP], ...ACTIONS]);
    const ctx: PolicyPublishContext = {
      ...CONTEXT,
      ownAction: (r) => (owned.get(r.id) && actionDigestSRI(owned.get(r.id)!) === r.digestSRI ? owned.get(r.id)! : null),
      ownGuardrail: (r) => owned.has(r.id),
      ownVersion: (r) => owned.get(r.id) ?? null,
    };
    const issues = policyPublishIssues(
      {
        ...policy([
          { tool: "kb_search", effect: "allow", under: { id: CREDIT_V1.$id } },
          { tool: "issue_credit", effect: "mandate", under: { id: "urn:via:action:theirs" } },
          { tool: "send_invoice", effect: "mandate", under: { id: CAP.$id } },
          { tool: "issue_credit", effect: "rules", action: ref(CREDIT_V1), agents: [SUPPORT] },
        ]),
        everyCall: ref(CREDIT_V2),
      },
      ctx,
    );
    expect(issues).toEqual([
      "the `everyCall` action lists `tools`: it governs every call, whatever the tool",
      "entry 1 (tool kb_search) names `under` without being `mandate`",
      "entry 2 (tool issue_credit): its `under` is not a published action of the organization's own",
      "entry 3 (tool send_invoice): its `under` is written for the policy, and no mandate pins one",
      "entry 4 (tool issue_credit): its action is written for a mandate, and the policy runs it with no person's values",
    ]);
    const FOR_MANDATE: ActionDetail = { ...CAP, for: "mandate", constants: undefined, rules: [{ ...CAP.rules[0]!, expression: "executionParams.amount <= 5" }] };
    const everyCall = { ...policy([]), everyCall: ref(FOR_MANDATE) };
    expect(policyPublishIssues(everyCall, { ...ctx, ownAction: (r) => (r.digestSRI === actionDigestSRI(FOR_MANDATE) ? FOR_MANDATE : null) })).toEqual([
      "the `everyCall` action is written for a mandate: the policy runs it with no person's values",
    ]);
  });

  // @invariant §0.6.3, §21.3: the policy runs its action with the version's constants.
  it("runs a policy action's constants", async () => {
    const CAP: ActionDetail = buildActionVersion({
      $id: "urn:via:action:cap-k",
      version: "1",
      for: "policy",
      constants: { maxAmount: { type: "number", value: 5000 } },
      executionParams: { amount: { type: "number" } },
      rules: [{ name: "payment_cap", description: "At most €5,000", requires: ["amount"], conditions: [{ left: "executionParams.amount", operator: "<=", right: "constants.maxAmount" }] }],
    });
    const capped = policy([{ guardrail: { id: BILLING.$id }, effect: "rules", action: ref(CAP) }]);
    const go = (amount: number) =>
      evaluatePolicy(capped, { tool: "send_invoice", params: { amount }, agent: { did: SUPPORT } }, { ...deps, loadActionVersion: (id) => (id === CAP.$id ? CAP : all.get(id) ?? null) });
    expect(await go(40)).toMatchObject({ outcome: "allow" });
    expect(await go(9000)).toMatchObject({ outcome: "deny", reason: "policy_denied", evaluations: [{ rule: "payment_cap", result: "fail" }] });
  });
});
