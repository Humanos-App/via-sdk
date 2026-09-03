// Agent-rung constraints → CEL (D1 / §16.8). The structured `assurance_floor` /
// `binding_required` / `root_allow` (and the standard `action_allow` / `amount_max`)
// forms are AUTHORING SUGAR: this compiler generates the `agent.*`/`executionParams`
// CEL rules that live in the ActionVersion and are evaluated at the normal step-8 CEL
// pass (there is no separate rung engine — see §16.7 A7). Ported from kya/contract.ts.
import type { ActionRule } from "../action/types.js";
import type { AgentReasonCode, Assurance, Binding, Root } from "./types.js";
import type { OperatorLevel, OperatorMethod, OperatorReasonCode } from "../operator/types.js";

/** Structured per-mandate policy (kya authoring form); compiled to CEL by this module. */
export type Constraint =
  | { type: "action_allow"; actions: string[] }
  | { type: "amount_max"; currency?: string; value: number }
  | { type: "assurance_floor"; min: Assurance; whenAction?: string[]; whenAmountAbove?: number }
  | { type: "binding_required"; binding: Binding; whenAmountAbove?: number }
  | { type: "root_allow"; roots: Root[] }
  | { type: "max_attestation_staleness"; seconds: number }
  // §18 operator verification — the IDENTITY axis (ordinal floor + categorical match).
  | { type: "operator_required"; min: OperatorLevel; whenAction?: string[]; whenAmountAbove?: number }
  | { type: "operator_method_in"; methods: OperatorMethod[] };

const celList = (items: string[]): string => "[" + items.map((s) => JSON.stringify(s)).join(", ") + "]";

const rule = (name: string, expression: string, description: string): ActionRule => ({
  name,
  description,
  conditions: [], // sugar-authored expression (not condition-derived); see §16.8 note
  expression,
});

/** Compile one structured constraint to a CEL `ActionRule` (deterministic — part of the interop contract). */
export function constraintToRule(c: Constraint, i = 0): ActionRule {
  switch (c.type) {
    case "action_allow":
      return rule(`action_allow_${i}`, `executionParams.action in ${celList(c.actions)}`, "action not allowed");
    case "amount_max":
      return rule(`amount_max_${i}`, `executionParams.amount <= ${c.value}`, "amount exceeds cap");
    case "assurance_floor": {
      const base = `assuranceRank(agent.assurance) >= assuranceRank(${JSON.stringify(c.min)})`;
      const guards: string[] = [];
      if (c.whenAction) guards.push(`!(executionParams.action in ${celList(c.whenAction)})`);
      if (c.whenAmountAbove !== undefined) guards.push(`executionParams.amount <= ${c.whenAmountAbove}`);
      return rule(`assurance_floor_${i}`, guards.length ? `${guards.join(" || ")} || ${base}` : base, "assurance below floor");
    }
    case "binding_required": {
      const base = `agent.binding == ${JSON.stringify(c.binding)}`;
      const expr = c.whenAmountAbove !== undefined ? `executionParams.amount <= ${c.whenAmountAbove} || ${base}` : base;
      return rule(`binding_required_${i}`, expr, "binding requirement not met");
    }
    case "root_allow":
      return rule(`root_allow_${i}`, `agent.root in ${celList(c.roots)}`, "root not accepted");
    case "max_attestation_staleness":
      // Needs the 🔮 `now` context item; enforced procedurally as A8 (v0.3 §16.7) until
      // then, against the key's `maxAttestationStaleness` (v0.3 §16.4).
      return rule(`max_attestation_staleness_${i}`, "true", "attestation staleness (procedural, A8)");
    case "operator_required": {
      // ORDINAL floor on the identity ladder — the §18 analogue of assurance_floor.
      const base = `operatorRank(operator.level) >= operatorRank(${JSON.stringify(c.min)})`;
      const guards: string[] = [];
      if (c.whenAction) guards.push(`!(executionParams.action in ${celList(c.whenAction)})`);
      if (c.whenAmountAbove !== undefined) guards.push(`executionParams.amount <= ${c.whenAmountAbove}`);
      return rule(`operator_required_${i}`, guards.length ? `${guards.join(" || ")} || ${base}` : base, "operator not verified enough");
    }
    case "operator_method_in":
      // CATEGORICAL — how the level was earned (e.g. eIDAS for a regulated flow).
      return rule(`operator_method_in_${i}`, `operator.method in ${celList(c.methods)}`, "operator verification method not accepted");
  }
}

/** Compile a mandate's structured constraints into ActionVersion CEL rules. */
export function constraintsToRules(constraints: Constraint[]): ActionRule[] {
  return constraints.map((c, i) => constraintToRule(c, i));
}

/**
 * Map a failed agent-rung rule name to its specific §16.7 A7 reason
 * (`agent_assurance_insufficient` / `agent_binding_insufficient` / `root_not_accepted`);
 * `undefined` ⇒ a non-agent rule → the generic `rule_failed`.
 */
export function agentReasonForRule(name: string): AgentReasonCode | OperatorReasonCode | undefined {
  if (name.startsWith("assurance_floor")) return "agent_assurance_insufficient";
  if (name.startsWith("binding_required")) return "agent_binding_insufficient";
  if (name.startsWith("root_allow")) return "root_not_accepted";
  // §18 — O5: the identity floor / method match failed.
  if (name.startsWith("operator_required") || name.startsWith("operator_method_in")) return "operator_insufficient";
  return undefined;
}
