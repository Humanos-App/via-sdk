/**
 * v0.3 §9.2 / §9.4ter — the rank helpers are for the ONE ordinal axis, and anything else must not
 * rank.
 *
 * The regression this pins: an off-ladder argument used to substitute `0` on both sides, so a rule
 * that reads as a floor evaluated `0 >= 0` and passed for every actor — including one with no
 * evidence at all. A categorical axis (`binding`, `bootstrapAnchor`, `runtime`) is matched with
 * `in`; a typo is an authoring mistake. Both now deny.
 */
import { describe, expect, it } from "vitest";
import { evaluateRule, evaluateRules } from "../src/index.js";

const ctx = (agent: Record<string, unknown>) => ({ userParams: {}, executionParams: {}, agent });
const rule = (expression: string) => ({ name: "floor", description: "assurance floor", expression });

describe("assuranceRank / accreditationRank fail closed", () => {
  it("ranks the ordinal axis it is for", () => {
    expect(evaluateRule(rule('assuranceRank(agent.assurance) >= assuranceRank("device")'), ctx({ assurance: "hardware" }))).toMatchObject({ result: "pass" });
    expect(evaluateRule(rule('assuranceRank(agent.assurance) >= assuranceRank("device")'), ctx({ assurance: "pop" }))).toMatchObject({ result: "fail" });
  });

  it("refuses a CATEGORICAL axis instead of ranking it 0 >= 0", () => {
    const r = evaluateRule(rule('assuranceRank(agent.runtime) >= assuranceRank("tee")'), ctx({ assurance: "pop", runtime: "none" }));
    expect(r.result).toBe("error");
    expect(r.reason).toContain("not on the ladder");
    // …and the rule set therefore DENIES, where it used to allow everything.
    expect(evaluateRules([rule('assuranceRank(agent.runtime) >= assuranceRank("tee")')], ctx({ runtime: "none" })).decision).toBe("deny");
  });

  it("refuses a typo'd floor, and an absent value", () => {
    expect(evaluateRule(rule('assuranceRank(agent.assurance) >= assuranceRank("hardwaer")'), ctx({ assurance: "hardware" })).result).toBe("error");
    expect(evaluateRule(rule('assuranceRank(agent.assurance) >= assuranceRank("pop")'), ctx({})).result).toBe("error");
  });

  it("holds for the accreditation ladder too", () => {
    expect(evaluateRule(rule('accreditationRank(accreditation.level) >= accreditationRank("verified")'), { userParams: {}, executionParams: {}, accreditation: { level: "verified" } })).toMatchObject({ result: "pass" });
    expect(evaluateRule(rule('accreditationRank(accreditation.level) >= accreditationRank("verified")'), { userParams: {}, executionParams: {}, accreditation: { level: "gold" } }).result).toBe("error");
  });
});
