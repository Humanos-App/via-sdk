import { describe, expect, it } from "vitest";
import {
  assertNoUnverifiedClientRefs,
  unverifiedClientRefs,
} from "../src/agent/constraints.js";

// v0.3 §9.4ter / B6 — MCP and SDK client metadata is self-declared. It may be recorded as context
// on an event; it may never gate authorization. These tests pin the boundary at authoring time,
// which is the last point where the difference between an attested claim and a claimed one is
// still visible in the mandate.

describe("client metadata is not an axis", () => {
  it("catches the identifiers a caller declares about itself", () => {
    expect(unverifiedClientRefs('executionParams.client_id == "trusted-app"')).toEqual(["client_id"]);
    expect(unverifiedClientRefs('clientInfo.name == "claude-desktop"')).toEqual(["clientInfo"]);
    expect(unverifiedClientRefs("userAgent.startsWith(\"via-sdk\")")).toEqual(["userAgent"]);
  });

  it("leaves the attested axes alone", () => {
    expect(unverifiedClientRefs('assuranceRank(agent.assurance) >= assuranceRank("hardware")')).toEqual([]);
    expect(unverifiedClientRefs('agent.runtime in ["tee"]')).toEqual([]);
    expect(unverifiedClientRefs('operator.level == "verified"')).toEqual([]);
  });

  it("word-boundary matched, so a legitimate field is not caught by a prefix", () => {
    // `clientReference` is the integrator's own parameter, not the client declaring itself.
    expect(unverifiedClientRefs("userParams.clientReference == \"abc\"")).toEqual([]);
  });

  it("refuses to author a mandate that gates on it, naming the field and the alternative", () => {
    expect(() =>
      assertNoUnverifiedClientRefs([
        { name: "trusted_client", expression: 'executionParams.client_id == "trusted-app"' },
      ]),
    ).toThrow(/client_id/);
    expect(() =>
      assertNoUnverifiedClientRefs([{ name: "x", expression: "clientInfo.version > 2" }]),
    ).toThrow(/agent\.runtime/);
  });

  it("passes a clean rule set", () => {
    expect(() =>
      assertNoUnverifiedClientRefs([
        { name: "amount_max_0", expression: "executionParams.amount <= 1000" },
        { name: "runtime_0", expression: 'agent.runtime in ["tee"]' },
      ]),
    ).not.toThrow();
  });
});
