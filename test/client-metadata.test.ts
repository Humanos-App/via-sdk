import { describe, expect, it } from "vitest";
import {
  assertNoUnverifiedClientRefs,
  unverifiedClientRefs,
} from "../src/agent/constraints.js";
import { buildActionVersion } from "../src/action/build.js";

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

  it("names the verified way to say \"only this app\": the agent's DID", () => {
    expect(() =>
      assertNoUnverifiedClientRefs([{ name: "x", expression: 'executionParams.client_id == "trusted-app"' }]),
    ).toThrow(/agent\.did/);
  });

  // §9.4ter(c) (2026-10-14): an implementation MUST refuse it when the action is written — the SDK's builder is one.
  it("buildActionVersion refuses an action whose rule reads client metadata", () => {
    expect(() =>
      buildActionVersion({
        $id: "urn:via:action:x",
        version: "1",
        executionParams: { client_id: { type: "string" } },
        rules: [{ name: "trusted_client", conditions: [{ left: "executionParams.client_id", operator: "==", right: "trusted-app" }] }],
      } as never),
    ).toThrow(/client_id/);
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
