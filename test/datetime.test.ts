/**
 * Datetime values and comparisons (v0.3 §0.6.3).
 *
 * A `datetime` is an ISO-8601 string, compared by instant, or a finite number, compared unchanged.
 * A comparison that mixes the two is an error, never a decision. Ported from the platform's R11
 * regression check (`merge-october/patches/r11-sdk-v03.patch`), which fixed the platform's copy first.
 */
import { describe, it, expect } from "vitest";
import { evaluateRules } from "../src/cel/evaluate.js";
import { rewriteCelTimestamps } from "../src/cel/timestamps.js";
import { validateExecutionParams, validateUserParams } from "../src/action/execution-params.js";

const scalar = { type: "datetime", required: true } as const;
const map = { type: "map", values: "datetime", required: true } as const;
const content = {
  userParams: { until: scalar, dates: map },
  executionParams: { at: scalar, dates: map },
};
const iso = "2026-10-15T09:00:00Z";
const epoch = Date.parse(iso);

const run = (expression: string, at: unknown, until: unknown) =>
  evaluateRules([{ name: "window", expression }], {
    executionParams: { at, dates: { item: at } },
    userParams: { until, dates: { item: until } },
  });

describe("a datetime parameter is an ISO-8601 string or a finite number (§0.6.3)", () => {
  for (const value of [iso, "2026-10-15T10:00:00+01:00", epoch, epoch / 1000, 0, -1, 0.25, 1e20]) {
    it(`accepts ${JSON.stringify(value)}, as a value and in a map`, () => {
      expect(() => validateUserParams(content, { until: value, dates: { item: value } })).not.toThrow();
      expect(() => validateExecutionParams(content, { at: value, dates: { item: value } })).not.toThrow();
    });
  }

  for (const value of [NaN, Infinity, -Infinity, "", "not-a-date", true, {}, [], null]) {
    it(`refuses ${String(JSON.stringify(value) ?? value)}, as a value and in a map`, () => {
      expect(() => validateUserParams(content, { until: value, dates: { item: iso } })).toThrow();
      expect(() => validateExecutionParams(content, { at: value, dates: { item: iso } })).toThrow();
      expect(() => validateUserParams(content, { until: iso, dates: { item: value } })).toThrow();
      expect(() => validateExecutionParams(content, { at: iso, dates: { item: value } })).toThrow();
    });
  }

  it("refuses a required datetime that is absent", () => {
    expect(() => validateUserParams(content, { until: undefined, dates: { item: iso } })).toThrow();
    expect(() => validateExecutionParams(content, { at: undefined, dates: { item: iso } })).toThrow();
  });
});

describe("datetime comparisons (§0.6.3)", () => {
  const cases: [string, unknown, unknown, "allow" | "deny"][] = [
    ["timestamp(executionParams.at) <= timestamp(userParams.until)", epoch, epoch + 1, "allow"],
    ["timestamp(executionParams.at) <= timestamp(userParams.until)", epoch + 1, epoch, "deny"],
    ['timestamp(executionParams.dates["item"]) < timestamp(userParams.dates["item"])', 1, 2, "allow"],
    ["userParams.dates.all(k, timestamp(executionParams.dates[k]) <= timestamp(userParams.dates[k]))", 1, 2, "allow"],
    // ISO strings compare by instant: the same moment at another offset is equal.
    ["timestamp(executionParams.at) == timestamp(userParams.until)", "2026-10-15T10:00:00+01:00", iso, "allow"],
    ['timestamp(userParams.until) - timestamp(executionParams.at) == duration("1h")', iso, "2026-10-15T10:00:00Z", "allow"],
    // Numbers compare unchanged — no unit conversion: the caller uses one unit.
    ["timestamp(executionParams.at) < timestamp(userParams.until)", epoch / 1000, epoch, "allow"],
    ["timestamp(executionParams.at) + 1.0 == timestamp(userParams.until)", 0.25, 1.25, "allow"],
    // A branch a guard leaves unevaluated stays unevaluated, mixed or missing.
    ["!has(executionParams.missing) || timestamp(executionParams.missing) < timestamp(userParams.until)", epoch, iso, "allow"],
    ["true || timestamp(executionParams.at) != timestamp(userParams.until)", epoch, iso, "allow"],
    [
      'timestamp(executionParams.at) < timestamp(userParams.until) && timestamp("2026-01-01T00:00:00Z") < timestamp("2026-01-02T00:00:00Z")',
      1,
      2,
      "allow",
    ],
    // Only parsed calls are rewritten: quoted text and spacing keep their meaning.
    [
      '"timestamp(executionParams.at)".startsWith("timestamp(") && timestamp (executionParams.at) < timestamp(userParams.until)',
      1,
      2,
      "allow",
    ],
  ];
  for (const [expression, at, until, decision] of cases) {
    it(`${expression} with ${JSON.stringify(at)}, ${JSON.stringify(until)} → ${decision}`, () => {
      expect(run(expression, at, until).decision).toBe(decision);
    });
  }

  // A verifier MUST NOT mix string and numeric datetimes within one comparison.
  for (const op of ["==", "!=", "<", "<=", ">", ">="]) {
    for (const [at, until] of [
      [epoch, iso],
      [iso, epoch],
    ] as const) {
      for (const [left, right] of [
        ["executionParams.at", "userParams.until"],
        ['executionParams.dates["item"]', 'userParams.dates["item"]'],
      ]) {
        it(`timestamp(${left}) ${op} timestamp(${right}) mixing ${typeof at} and ${typeof until} is an error`, () => {
          const actual = run(`timestamp(${left}) ${op} timestamp(${right})`, at, until);
          expect(actual.decision).toBe("deny");
          expect(actual.evaluations[0]!.result).toBe("error");
        });
      }
    }
  }

  for (const value of [NaN, Infinity, -Infinity]) {
    it(`a non-finite number (${value}) is an error`, () => {
      expect(run("timestamp(executionParams.at) != timestamp(userParams.until)", value, 1).evaluations[0]!.result).toBe("error");
    });
  }
});

describe("rewriteCelTimestamps", () => {
  it("renames only parsed timestamp() calls", () => {
    expect(rewriteCelTimestamps('timestamp(a) < timestamp("2026-01-01T00:00:00Z")')).toBe(
      'viaTimestamp(a) < viaTimestamp("2026-01-01T00:00:00Z")',
    );
    expect(rewriteCelTimestamps('"timestamp(a)" == b')).toBe('"timestamp(a)" == b');
  });
});
