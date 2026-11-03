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
  /** CEL generated from `conditions` (§0.6.2); written by hand only on a rule with none. */
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

/**
 * v0.3 §0.6.1 — what a version is for. `mandate`: a person's mandate pins it, and its limits may be the values they
 * fix (`userParams`). `policy`: the organization's policy (§21) names it, and it declares no `userParams`. Absent on
 * every version written before it, which is read as its content allows (`mandateMayPin`, `policyMayName`).
 */
export type ActionFor = "mandate" | "policy";

/**
 * v0.3 §0.6.1 — a value the version fixes, which its rules read as `constants.<name>`: a policy's limit, or a term a
 * mandate's person is shown as fixed. Typed as a parameter is, and pinned with the rest of the content by the digest.
 */
export interface ConstantDef {
  type: ParamType;
  description?: string;
  /** `array` only: the element type. */
  items?: ArrayItemType;
  /** `map` only: the value type. */
  values?: MapValueType;
  value: unknown;
}

export interface ActionDetail {
  $id: string;
  type: string;
  version: string;
  /** v0.3 §0.6.1 — a mandate's or a policy's; absent, as its content allows. */
  for?: ActionFor;
  target?: ActionTarget;
  /** The values a person fixes in the mandate. Optional: a policy action has none (§0.6.1). */
  userParams?: Record<string, ParamDef>;
  /** v0.3 §0.6.1 — the values the version fixes itself, read as `constants.<name>`; any version may declare them. */
  constants?: Record<string, ConstantDef>;
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
