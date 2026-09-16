/**
 * CEL regression guards.
 *
 * Pins the operator semantics VIA's rule generator relies on (@marcbachmann/cel-js),
 * and the generator × engine pairing end-to-end. If a cel-js upgrade changes how any
 * operator/form evaluates, these fail rather than silently changing decisions.
 */
import { describe, it, expect } from "vitest";
import { evaluateRule, evaluateRules, validateCelExpression, CEL_EXPRESSION_MAX_LENGTH } from "../src/cel/evaluate.js";
import { buildActionVersion } from "../src/action/build.js";

const ctx = {
  // deadline is an issuer constant (userParam); when is a runtime value (executionParam).
  userParams: { maxAmount: 500, categories: ["a", "b"], blocked: ["x"], deadline: 200, flag: true },
  executionParams: { amount: 100, category: "a", when: 100, flag: true },
};
const rule = (expression: string) => ({ name: "r", expression });

describe("cel-js operator behavior (the forms generateCelExpression emits)", () => {
  const cases: [string, "pass" | "fail"][] = [
    ["executionParams.amount <= userParams.maxAmount", "pass"],
    ["executionParams.amount >= userParams.maxAmount", "fail"],
    ["executionParams.amount < userParams.maxAmount", "pass"],
    ["executionParams.amount > userParams.maxAmount", "fail"],
    // a real CEL impl distinguishes int (bigint) from double; the JS number 100
    // must still compare equal to the int literal 100 — guards that coercion.
    ["executionParams.amount == 100", "pass"],
    ["executionParams.amount != 100", "fail"],
    ["executionParams.category in userParams.categories", "pass"],
    ["executionParams.category in userParams.blocked", "fail"],
    ["!(executionParams.category in userParams.blocked)", "pass"], // not_in form
    ["!(executionParams.category in userParams.categories)", "fail"],
    ["executionParams.flag == userParams.flag", "pass"],
  ];
  for (const [expr, expected] of cases) {
    it(`${expr} → ${expected}`, () => {
      expect(evaluateRule(rule(expr), ctx).result).toBe(expected);
    });
  }

  it("non-boolean result → error (rules must return a boolean)", () => {
    expect(evaluateRule(rule("userParams.maxAmount"), ctx).result).toBe("error");
  });
  it("unknown identifier → error (engine throws, we catch)", () => {
    expect(evaluateRule(rule("missingThing == 1"), ctx).result).toBe("error");
  });
  it("numeric datetime values: timestamp() is stripped, compared as raw epochs (N31)", () => {
    // when/deadline are numbers here → timestamp(double) would throw, so we strip.
    expect(evaluateRule(rule("timestamp(executionParams.when) <= timestamp(userParams.deadline)"), ctx).result).toBe("pass");
  });
});

describe("datetime via native timestamp() — string values (N31)", () => {
  // ISO-8601 string datetimes: keep native timestamp(), which compares by INSTANT.
  const dctx = (when: string, deadline: string) => ({
    userParams: { deadline },
    executionParams: { when },
  });
  const tsRule = rule("timestamp(executionParams.when) <= timestamp(userParams.deadline)");

  it("before-deadline → pass; after-deadline → fail", () => {
    expect(evaluateRule(tsRule, dctx("2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")).result).toBe("pass");
    expect(evaluateRule(tsRule, dctx("2026-12-01T00:00:00Z", "2026-06-01T00:00:00Z")).result).toBe("fail");
  });

  it("compares by instant, NOT lexicographically (the upgrade over the old strip)", () => {
    // same instant, different representation: lexicographic string compare would call these unequal.
    const eq = rule("timestamp(executionParams.when) == timestamp(userParams.deadline)");
    expect(evaluateRule(eq, dctx("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000Z")).result).toBe("pass");
    // mixed UTC offset, same instant.
    expect(evaluateRule(eq, dctx("2026-01-01T10:00:00+01:00", "2026-01-01T09:00:00Z")).result).toBe("pass");
  });

  it("string literal inside timestamp() is kept native and evaluates", () => {
    expect(
      evaluateRule(rule('timestamp(executionParams.when) <= timestamp("2026-06-01T00:00:00Z")'),
        dctx("2026-01-01T00:00:00Z", "ignored")).result,
    ).toBe("pass");
  });

  it("generator-emitted datetime rule evaluates end to end with string values", () => {
    const action = buildActionVersion({
      $id: "urn:via:action:cel-dt",
      version: "1",
      userParams: { deadline: { type: "datetime", required: true } },
      executionParams: { when: { type: "datetime", required: true } },
      rules: [{ name: "before", conditions: [{ left: "executionParams.when", operator: "<=", right: "userParams.deadline" }] }],
    });
    expect(action.rules[0]!.expression).toBe("timestamp(executionParams.when) <= timestamp(userParams.deadline)");
    expect(
      evaluateRules(action.rules, {
        userParams: { deadline: "2026-06-01T00:00:00Z" },
        executionParams: { when: "2026-01-01T00:00:00Z" },
      }).decision,
    ).toBe("allow");
  });
});

describe("generateCelExpression × engine — end to end", () => {
  const action = buildActionVersion({
    $id: "urn:via:action:cel-1",
    version: "1",
    userParams: {
      maxAmount: { type: "number", required: true },
      categories: { type: "array", items: "string", required: true },
      blocked: { type: "array", items: "string", required: false },
    },
    executionParams: {
      amount: { type: "number", required: true },
      category: { type: "string", required: true },
    },
    rules: [
      { name: "amt", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }] },
      { name: "cat", conditions: [{ left: "executionParams.category", operator: "in", right: "userParams.categories" }] },
      { name: "notblocked", conditions: [{ left: "executionParams.category", operator: "not_in", right: "userParams.blocked" }] },
    ],
  });
  const userParams = { maxAmount: 500, categories: ["a", "b"], blocked: ["x"] };

  it("generated expressions are stable + evaluate correctly", () => {
    expect(action.rules.find((r) => r.name === "notblocked")!.expression).toBe(
      "!(executionParams.category in userParams.blocked)",
    );
    expect(evaluateRules(action.rules, { userParams, executionParams: { amount: 100, category: "a" } }).decision).toBe("allow");

    const bad = evaluateRules(action.rules, { userParams, executionParams: { amount: 999, category: "x" } });
    expect(bad.decision).toBe("deny");
    expect(bad.evaluations.find((e) => e.rule === "amt")?.result).toBe("fail"); // 999 > 500
    expect(bad.evaluations.find((e) => e.rule === "cat")?.result).toBe("fail"); // "x" not in [a,b]
    expect(bad.evaluations.find((e) => e.rule === "notblocked")?.result).toBe("fail"); // "x" IS blocked
  });
});

describe("validateCelExpression — the door a written rule comes through", () => {
  const cases: [string, string][] = [
    ["a comparison over both param sides", "userParams.maxPageSize >= executionParams.pageSize"],
    ["membership", "executionParams.category in userParams.categories"],
    ["a negation", "!(executionParams.category in userParams.blocked)"],
    ["the assurance ladder helper", 'assuranceRank(agent.assurance) >= assuranceRank("tee")'],
  ];
  it.each(cases)("accepts an expression that parses — %s", (_name, expression) => {
    expect(validateCelExpression(expression)).toEqual({ ok: true });
  });

  const bad: [string, string][] = [
    ["an unclosed call", "foo("],
    ["a dangling operator", "1 +"],
    ["prose", "this is not (cel"],
    ["empty", ""],
    ["blank", "   "],
  ];
  it.each(bad)("refuses an expression that does not parse, and says why — %s", (_name, expression) => {
    const result = validateCelExpression(expression);
    expect(result.ok).toBe(false);
    // The reason is one line: it is shown to whoever wrote the rule, which may be an agent.
    expect((result as { error: string }).error).toMatch(/\S/);
    expect((result as { error: string }).error).not.toContain("\n");
  });

  it("refuses an expression longer than the cap, without parsing it", () => {
    // The parser never sees it: size is bounded BEFORE the work starts.
    const huge = `userParams.a > ${"0 + ".repeat(2000)}1`;
    expect(huge.length).toBeGreaterThan(CEL_EXPRESSION_MAX_LENGTH);
    expect(validateCelExpression(huge)).toEqual({
      ok: false,
      error: `expression is longer than ${CEL_EXPRESSION_MAX_LENGTH} characters`,
    });
  });

  it("survives nesting deep enough to exhaust the stack — a refusal, never a crash", () => {
    // Under the length cap, so it reaches the parser. A RangeError here must read as "not a rule",
    // not propagate as a 500 to whoever is proposing.
    const deep = `${"(".repeat(400)}1${")".repeat(400)} > 0`;
    expect(deep.length).toBeLessThanOrEqual(CEL_EXPRESSION_MAX_LENGTH);
    const result = validateCelExpression(deep);
    if (!result.ok) expect(result.error.length).toBeLessThanOrEqual(201);
  });

  it("bounds the reason it quotes back, however long the offending input", () => {
    const noisy = `"${"x".repeat(1500)}" +`;
    const result = validateCelExpression(noisy);
    expect(result.ok).toBe(false);
    expect((result as { error: string }).error.length).toBeLessThanOrEqual(201);
  });

  it("parsing is not meaning: an expression that parses can still fail at evaluation", () => {
    // References a param that does not exist. It PARSES, so the door lets it through; evaluation
    // is where it becomes `error` -> deny. Nothing here can know the action's params.
    expect(validateCelExpression("userParams.nosuch > 1")).toEqual({ ok: true });
    expect(evaluateRule(rule("userParams.nosuch > 1"), ctx).result).toBe("error");
  });
});
