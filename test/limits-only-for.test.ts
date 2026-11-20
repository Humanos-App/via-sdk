/** v0.4 §15.4 — a rule may apply only to named agents (`onlyFor`): who is under a limit, beside the limit itself. */
import { describe, expect, it } from "vitest";
import {
  LIMITS_RULE_FIELDS,
  ONLY_FOR_SKIPPED,
  buildRule,
  decideLimits,
  limitsPolicyAgentRuleIssues,
  limitsPolicyPublishIssues,
  limitsPolicyUnknownFields,
  mandateLimitsIssues,
  mandateRequestRefusals,
  ruleExpression,
  ruleIssues,
  toolDefinitionHash,
  type LimitCondition,
  type LimitsPolicy,
  type MandateLimits,
  type PolicyTool,
  type RulePlace,
  type ToolDefinition,
} from "../src/limits/index.js";

const REFUND: ToolDefinition = { name: "create_refund", description: "Refund a charge.", inputSchema: { type: "object", properties: { amount: { type: "number" } } } };
const TOOL = "stripe/create_refund";
const HASH = toolDefinitionHash(REFUND);
const INTERN = "did:web:humanos.tech:agent:intern";
const SUPPORT = "did:web:humanos.tech:agent:support";
const ANA = "did:web:humanos.tech:user:ana";
const ctx = { definition: () => REFUND, isMember: (did: string) => did === ANA };

const atMost = (value: number): LimitCondition => ({ left: "amount", operator: "<=", value });
const forAll = buildRule([atMost(500)], REFUND.inputSchema);
const forIntern = buildRule([atMost(50)], REFUND.inputSchema, undefined, [INTERN]);
const policy = (entry: Partial<PolicyTool> = {}, over: Partial<LimitsPolicy> = {}): LimitsPolicy => ({
  $id: "urn:via:policy:0b1c",
  type: "VIAPolicy",
  specVersion: "0.4",
  version: 5,
  default: "deny",
  tools: { [TOOL]: { effect: "allow", hash: HASH, rules: [forAll, forIntern], ...entry } },
  ...over,
});
const call = (did: string, amount: number, p = policy(), mandate?: Parameters<typeof decideLimits>[2]) =>
  decideLimits(p, { tool: TOOL, params: { amount }, definition: REFUND, agent: { did }, madeFrom: HASH }, mandate);

describe("writing a rule only for named agents (§15.4)", () => {
  const place: RulePlace = { document: "policy", inputs: REFUND.inputSchema, root: false };

  it("leaves the expression what the conditions say: the agents are named beside it, never in it", () => {
    expect(forIntern).toEqual({ conditions: [atMost(50)], expression: ruleExpression([atMost(50)], REFUND.inputSchema), onlyFor: [INTERN] });
    expect(forIntern.expression).not.toContain("agent");
    expect(ruleIssues(forIntern, place)).toEqual([]);
    expect(limitsPolicyPublishIssues(policy(), ctx)).toEqual([]);
  });

  it("is published on a root rule too", () => {
    const root = buildRule([{ left: "agent.binding", operator: "==", value: "attested" }], undefined, undefined, [INTERN]);
    expect(limitsPolicyPublishIssues(policy({}, { rules: [root] }), ctx)).toEqual([]);
  });

  // @refusal
  it.each([
    ["an empty list", [], /at least one agent/],
    ["something that is no list", INTERN, /at least one agent/],
    ["a name that is no DID", ["the intern"], /by their DIDs/],
    ["a value that is no text", [7], /by their DIDs/],
    ["an agent named twice", [INTERN, INTERN], /names an agent once/],
  ])("refuses `onlyFor` that is %s", (_case, onlyFor, message) => {
    const rule = { ...forIntern, onlyFor: onlyFor as never };
    expect(ruleIssues(rule, place).join()).toMatch(message);
    expect(limitsPolicyPublishIssues(policy({ rules: [rule] }), ctx).join()).toMatch(message);
  });

  // @refusal
  it.each(["in", "not_in", "==", "!="] as const)("refuses a condition on `agent.did` (%s) in a rule that carries `onlyFor`", (operator) => {
    const value = operator === "in" || operator === "not_in" ? [SUPPORT] : SUPPORT;
    const rule = buildRule([{ left: "agent.did", operator, value }], REFUND.inputSchema, undefined, [INTERN]);
    expect(ruleIssues(rule, place).join()).toMatch(/has no condition on `agent\.did`/);
  });

  // @refusal
  it("refuses it in a mandate's rule, at the root and on a tool: a mandate names its agents", () => {
    const mandate = (over: Partial<MandateLimits>): MandateLimits => ({ description: { text: "Refund order 1182, up to 50 EUR", lang: "en", author: "agent" }, maxExecutions: 1, tools: { [TOOL]: { hash: HASH, rules: [] } }, ...over });
    const rootRule = buildRule([{ left: "agent.binding", operator: "==", value: "attested" }], undefined, undefined, [INTERN]);
    expect(ruleIssues(forIntern, { ...place, document: "mandate" }).join()).toMatch(/a mandate names its agents/);
    expect(mandateLimitsIssues(mandate({ tools: { [TOOL]: { hash: HASH, rules: [forIntern] } } }), ctx).join()).toMatch(/a mandate names its agents/);
    expect(mandateLimitsIssues(mandate({ rules: [rootRule] }), ctx).join()).toMatch(/a mandate names its agents/);
  });

  // @refusal
  it("refuses it in an app's rule", () => {
    expect(ruleIssues(forIntern, { ...place, document: "app" }).join()).toMatch(/on a policy's rule alone/);
  });
});

describe("a verifier and a rule's `onlyFor` (§15.7.3)", () => {
  it("knows the field", () => {
    expect(limitsPolicyUnknownFields(policy())).toEqual([]);
    expect(LIMITS_RULE_FIELDS).toContain("onlyFor");
  });

  // @refusal The list as it was before 2026-11-20: such a verifier would run the intern's limit on every agent, or on none.
  it("is refused by a verifier that does not know the field, which decides no call under the version", () => {
    const before = ["conditions", "expression", "otherwise"];
    expect(limitsPolicyUnknownFields(policy(), { rule: before })).toEqual([`tools.${TOOL}.rules[1].onlyFor`]);
    expect(limitsPolicyUnknownFields(policy({ rules: [forAll] }, { rules: [{ ...forAll, onlyFor: [INTERN] }] }), { rule: before })).toEqual(["rules[0].onlyFor"]);
  });

  // @refusal
  it.each([
    ["names nobody", { ...forIntern, onlyFor: [] }],
    ["also carries a condition on `agent.did`", buildRule([{ left: "agent.did", operator: "in", value: [SUPPORT] }], undefined, undefined, [INTERN])],
  ])("finds a stored rule whose `onlyFor` %s, so no call is decided under it", (_case, rule) => {
    expect(limitsPolicyAgentRuleIssues(policy({ rules: [rule as never] }))).toEqual([expect.stringContaining(`tools.${TOOL}.rules[0]: `)]);
    expect(limitsPolicyAgentRuleIssues(policy())).toEqual([]);
  });
});

describe("deciding a call under a rule only for named agents (§15.4)", () => {
  it("holds a named agent to its own limit and to everyone's", async () => {
    expect(await call(INTERN, 40)).toMatchObject({ outcome: "allow" });
    const refused = await call(INTERN, 60);
    expect(refused).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(refused.evaluations.map((e) => e.result)).toEqual(["pass", "fail"]);
    expect(await call(INTERN, 600)).toMatchObject({ outcome: "deny", reason: "policy_denied" });
  });

  it("records the rule as skipped for any other agent, and neither passes nor fails the call by it", async () => {
    const allowed = await call(SUPPORT, 60);
    expect(allowed).toMatchObject({ outcome: "allow" });
    expect(allowed.evaluations).toEqual([
      expect.objectContaining({ tool: TOOL, rule: 0, result: "pass" }),
      { in: "urn:via:policy:0b1c#5", tool: TOOL, rule: 1, result: "skip", reason: ONLY_FOR_SKIPPED },
    ]);
    // Everyone's limit still holds it; and an agent registered later is under no rule that does not name it.
    expect(await call(SUPPORT, 600)).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(await call("did:web:humanos.tech:agent:registered-later", 60)).toMatchObject({ outcome: "allow" });
  });

  it("compares the DID a rule reads as `agent.did`: a call with none is under no such rule", async () => {
    const decided = await decideLimits(policy(), { tool: TOOL, params: { amount: 60 }, definition: REFUND, agent: {}, madeFrom: HASH }, undefined);
    expect(decided.evaluations[1]).toMatchObject({ result: "skip" });
  });

  it("leaves to a person only a named agent's call, when the rule says `otherwise: mandate`", async () => {
    const asks = buildRule([atMost(50)], REFUND.inputSchema, "mandate", [INTERN]);
    const p = policy({ rules: [forAll, asks], grantors: [ANA] });
    expect(limitsPolicyPublishIssues(p, ctx)).toEqual([]);
    expect(await call(INTERN, 60, p)).toMatchObject({ outcome: "deny", reason: "mandate_required", tool: TOOL, grantors: [ANA] });
    expect(await call(SUPPORT, 60, p)).toMatchObject({ outcome: "allow", on: "policy" });
  });

  it("runs a root rule for the agents it names alone", async () => {
    const attested = buildRule([{ left: "agent.binding", operator: "==", value: "attested" }], undefined, undefined, [INTERN]);
    const p = policy({ rules: [forAll] }, { rules: [attested] });
    expect(await call(INTERN, 10, p)).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(await call(SUPPORT, 10, p)).toMatchObject({ outcome: "allow" });
  });

  // @refusal A mandate's rule names no agents: a stored one that does is never run as if it applied to someone else.
  it("fails a mandate's rule that carries `onlyFor`, whoever calls", async () => {
    const p = policy({ effect: "mandate", rules: [forAll], grantors: [ANA] });
    const limits: MandateLimits = { description: { text: "Refunds up to 50 EUR", lang: "en", author: "agent" }, maxExecutions: 1, tools: { [TOOL]: { hash: HASH, rules: [forIntern] } } };
    const decided = await call(SUPPORT, 10, p, { id: "urn:via:credential:m1", grantor: ANA, limits });
    expect(decided).toMatchObject({ outcome: "deny", reason: "rule_failed", on: "mandate" });
    expect(decided.evaluations.at(-1)).toMatchObject({ result: "error" });
  });
});

describe("a mandate request under a rule only for named agents (§15.2)", () => {
  const p = policy({ effect: "mandate", grantors: [ANA] });
  const asking = (amount: number): MandateLimits => ({
    description: { text: `Refunds up to ${amount} EUR`, lang: "en", author: "agent" },
    maxExecutions: 1,
    tools: { [TOOL]: { hash: HASH, rules: [buildRule([atMost(amount)], REFUND.inputSchema)] } },
  });
  const refusals = (amount: number, agents?: string[]) => mandateRequestRefusals(p, { grantor: ANA, limits: asking(amount), ...(agents ? { agents } : {}) });

  // @refusal
  it("refuses a request looser than the limit of an agent the mandate would bind", () => {
    expect(refusals(60, [INTERN])).toEqual([expect.objectContaining({ tool: TOOL, reason: "policy_denied" })]);
    expect(refusals(60, [SUPPORT, INTERN])).toHaveLength(1);
    expect(refusals(40, [INTERN])).toEqual([]);
  });

  it("does not hold another agent's request to it, nor one that names no agent", () => {
    expect(refusals(60, [SUPPORT])).toEqual([]);
    expect(refusals(60)).toEqual([]);
    // Everyone's limit binds every request.
    expect(refusals(600, [SUPPORT])).toHaveLength(1);
  });

  it("asks one call per approval only of an agent a rule that leaves its failure to a person names", () => {
    const asks = buildRule([atMost(50)], REFUND.inputSchema, "mandate", [INTERN]);
    const allow = policy({ rules: [forAll, asks], grantors: [ANA] });
    const many = { ...asking(40), maxExecutions: 3 };
    expect(mandateRequestRefusals(allow, { grantor: ANA, limits: many, agents: [INTERN] })).toEqual([expect.objectContaining({ reason: "one_call_required" })]);
    expect(mandateRequestRefusals(allow, { grantor: ANA, limits: many, agents: [SUPPORT] }).map((r) => r.reason)).not.toContain("one_call_required");
  });
});

// §15.7.2 — a tool being upgraded has two approved definitions, and a mandate names one of them.
describe("a mandate request for a tool with an earlier definition still approved", () => {
  const BEFORE: ToolDefinition = { ...REFUND, description: "Refund a charge, in full." };
  const p = policy({ effect: "mandate", grantors: [ANA], rules: [], earlier: { hash: toolDefinitionHash(BEFORE) } });
  const asking = (hash: string): MandateLimits => ({ description: { text: "Refund order 1182", lang: "en", author: "agent" }, maxExecutions: 1, tools: { [TOOL]: { hash, rules: [] } } });

  it("accepts the definition the policy pins and the earlier one it still approves", () => {
    expect(mandateRequestRefusals(p, { grantor: ANA, limits: asking(HASH) })).toEqual([]);
    expect(mandateRequestRefusals(p, { grantor: ANA, limits: asking(toolDefinitionHash(BEFORE)) })).toEqual([]);
  });

  // @refusal
  it("refuses `tool_changed` any other definition", () => {
    expect(mandateRequestRefusals(p, { grantor: ANA, limits: asking("sha256-another") })).toEqual([expect.objectContaining({ tool: TOOL, reason: "tool_changed" })]);
  });
});

