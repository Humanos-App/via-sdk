export type ParamType = "string" | "number" | "integer" | "boolean" | "datetime" | "array";
export type ArrayItemType = Exclude<ParamType, "array">;

export interface ParamDef {
  type: ParamType;
  required?: boolean;
  description?: string;
  items?: ArrayItemType;
}

export type ConditionOperator = "==" | "!=" | ">" | "<" | ">=" | "<=" | "in" | "not_in";

export interface RuleCondition {
  left: string; // e.g. "executionParams.amount"
  operator: ConditionOperator;
  right: string; // e.g. "userParams.maxAmount"
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
