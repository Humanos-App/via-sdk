export type ParamType = "string" | "number" | "integer" | "boolean" | "datetime" | "array" | "map";
/** Containers hold scalars only — no arrays of arrays, no maps of maps. */
export type ArrayItemType = Exclude<ParamType, "array" | "map">;
export type MapValueType = ArrayItemType;

export interface ParamDef {
  type: ParamType;
  required?: boolean;
  description?: string;
  /** `array` only: the element type. */
  items?: ArrayItemType;
  /** `map` only: the value type. Keys are always strings (see MAP_KEY_PATTERN). */
  values?: MapValueType;
}

export type ConditionOperator = "==" | "!=" | ">" | "<" | ">=" | "<=" | "in" | "not_in";

export interface RuleCondition {
  left: string; // e.g. "executionParams.amount"
  /**
   * When `left` names a `map` param, the ref whose value indexes it, producing
   * `left[leftKey]` — e.g. `userParams.caps[executionParams.instrument]`. The operand's
   * effective type becomes the map's declared `values` type. Map keys are strings, so this
   * must name a `string` param.
   */
  leftKey?: string;
  operator: ConditionOperator;
  right: string; // e.g. "userParams.maxAmount"
  /** As `leftKey`, for the right-hand operand. */
  rightKey?: string;
}

export interface ActionRule {
  name: string;
  /**
   * The sentence a person reads, and the reason an integrator maps (v0.3 §0.6.1). REQUIRED to publish —
   * {@link actionPublishIssues} refuses a rule without one — and optional here only because versions
   * published before it, and drafts, are read as written.
   */
  description?: string;
  conditions: RuleCondition[];
  /** Auto-generated CEL (N13). Derived from `conditions`; never hand-edited. */
  expression: string;
  /**
   * The tools this rule GOVERNS, by `executionParams.tool` (S13).
   *
   * Absent ⇒ it governs every call. Present ⇒ a call by a tool outside the list skips it, which is
   * what makes a per-tool limit expressible for a service whose tools do not all carry the same
   * parameter. It replaces the guard this generated instead —
   * `!has(executionParams.p) || …` — which was skipped by any call that simply omitted `p`, so the
   * limit a person believed they had set bound only the calls that volunteered the value.
   */
  appliesTo?: string[];
  /**
   * Execution parameters a GOVERNED call MUST carry (S13). A governed call missing one is DENIED
   * with `required_param_missing` — the fail-closed direction, and the one a grantor assumes when
   * they fix an allowlist.
   */
  requires?: string[];
}

export interface ActionTarget {
  method: string;
  domain: string;
  path: string;
}

export interface ActionDetail {
  $id: string;
  type: string;
  version: string;
  target?: ActionTarget;
  userParams: Record<string, ParamDef>;
  executionParams: Record<string, ParamDef>;
  rules: ActionRule[];
  mapper?: Record<string, string>;
  /** v0.3 §17.4 — the tools whose calls need the grantor's fresh co-sign. */
  stepUp?: { tools: string[] };
  /**
   * v0.3 §0.6.1 — the tools whose calls this version governs. On the agent path a call naming another
   * is `tool_not_covered`; the presentation path names no tool and checks none. Absent on every version
   * published before the list, which is read as written: no call's tool is checked against it.
   */
  tools?: string[];
  /** v0.3 §0.6.1 — those of `tools` no rule limits, on purpose. A decision on one says `unrestricted`. */
  unrestricted?: string[];
}
