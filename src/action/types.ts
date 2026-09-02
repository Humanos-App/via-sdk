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
  description?: string;
  conditions: RuleCondition[];
  /** Auto-generated CEL (N13). Derived from `conditions`; never hand-edited. */
  expression: string;
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
}
