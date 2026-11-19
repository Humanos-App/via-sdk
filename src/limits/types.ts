/**
 * v0.4 §15 — limits per tool. For an agent's tool call there is no VIAAction: each tool's limits are rules written
 * in the organization's policy and in the mandate a person accepted. v0.3's policy (`../policy`) and action
 * (`../action`) are untouched: a document says which it is by its `specVersion`.
 */
import type { MandateDescription } from "../types.js";
import type { PolicyContext, ToolFill } from "../datalayer/policy.js";

/** §15.4 — a condition's operators: v0.3 §0.6.2's, and the ones the platform's limits already ran. */
export type LimitOperator =
  | "=="
  | "!="
  | "<"
  | "<="
  | ">"
  | ">="
  | "in"
  | "not_in"
  | "starts_with"
  | "ends_with"
  | "contains"
  | "every_in"
  | "none_in"
  | "includes_all"
  | "every_starts_with"
  | "every_ends_with"
  | "every_contains";

/** §15.4 — what a condition compares in place of the value itself: a text's length, a list's number of items. */
export type LimitMeasure = "length" | "count";

/**
 * §15.4 — one comparison. `left` is one of the tool's inputs, written bare (`amount`, `recipient.iban`,
 * `lines[].price`), or `agent.*`, `accreditation.*`, `context.*`, `checks.{capability}.{field}`. It carries a `value`
 * written in the rule, or, in a policy's or an app's rule only, a `right` naming a check's answer.
 */
export interface LimitCondition {
  left: string;
  operator: LimitOperator;
  value?: unknown;
  /** `checks.{capability}.{field}`: never an input of the same call, which would let the agent set its own ceiling. */
  right?: string;
  /** The name is *proposed* in §15.4. */
  measure?: LimitMeasure;
}

/** §15.4 — one limit. It has no name: its document, its tool and its position identify it. */
export interface LimitRule {
  conditions: LimitCondition[];
  /** The CEL that runs, generated from `conditions` when the document is signed (`ruleExpression`). */
  expression: string;
  /** §15.6 — in a policy's or an app's rule: its failure is settled by a person's one-call mandate. */
  otherwise?: "mandate";
}

/** §15.1 — what the policy says of a tool. */
export type ToolEffect = "allow" | "mandate" | "deny";

export const TOOL_EFFECTS: readonly ToolEffect[] = ["allow", "mandate", "deny"];

/** §15.1 — a tool's entry in the policy. A `server/*` key takes `deny` and nothing else. */
export interface PolicyTool {
  effect: ToolEffect;
  /** §15.3 — the hash of the definition a member reviewed. Required unless the effect is `deny`. */
  hash?: string;
  /** §13.1, §15.3 — a capability's entry: the version a member approved, whose digest is `hash`. */
  version?: number;
  rules?: LimitRule[];
  /** §15.5 — who may grant a mandate for it: DIDs, or `"any"` written out. */
  grantors?: string[] | "any";
  /** §15.6 — a mandate covers it only with `maxExecutions: 1`. */
  oneCall?: boolean;
  /** §15.2 — no mandate and no call under one without the reviewer's agreement. The name is *proposed*. */
  reviewer?: "required";
  /** §14.3 — per parameter, the kinds of personal data that may be filled into it. For every agent. */
  fill?: ToolFill;
}

/** §15.1 — a policy version of v0.4's shape. */
export interface LimitsPolicy {
  $id: string;
  type: "VIAPolicy";
  specVersion: "0.4";
  version: number;
  /** A tool `tools` does not name. Never `allow`: a tool nobody reviewed has no pinned definition and no limits. */
  default: "mandate" | "deny";
  /** Every call: the agent's record and its accreditation. */
  rules?: LimitRule[];
  tools: Record<string, PolicyTool>;
  /** §13.2 — installed apps; read by the router, not here. */
  apps?: unknown[];
  /** §14.3 — the context layer's settings. Absent, nothing is replaced. */
  context?: PolicyContext;
}

/** §15.2 — a tool a mandate covers: the definition the person approved it for, and its limits. `rules` may be empty. */
export interface MandateTool {
  /** §13.1 — for a capability: the version the person approved it at, whose digest is `hash`. */
  version?: number;
  hash: string;
  rules: LimitRule[];
}

/**
 * §15.2 — what a mandate that binds an agent carries in place of an action: its words, how many calls it is good
 * for, and the tools it covers. Its credential is marked `specVersion: "0.4"`.
 */
export interface MandateLimits {
  /** Required. Who wrote it stays recorded (`author`, v0.3 §20.2). */
  description: MandateDescription;
  /** Required: a person never approves an unlimited number of calls by an omission. */
  maxExecutions: number;
  /** On every tool it covers: the agent and its accreditation. */
  rules?: LimitRule[];
  tools: Record<string, MandateTool>;
}

/**
 * §15.2, §15.8 — what the reviewer did: it agreed; it answered and does not enforce yet (its answer is recorded and
 * refuses nothing); or it gave no answer, being out of service or not deployed. The spec's name for the field is
 * *proposed*.
 */
export type ReviewerPart = "agreed" | "not_enforcing" | "unavailable";

/** The marker a §15.2 mandate and a §15.1 policy carry (§15.7). */
export const LIMITS_SPEC_VERSION = "0.4";

/** §15.3 — what a tool's `hash` is over. Anything else a server sends is not part of it. */
export interface ToolDefinition {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: JsonSchema;
  outputSchema?: JsonSchema;
  annotations?: Record<string, unknown>;
}

/** A JSON Schema, as a tool's definition carries one. Only what §15 reads is typed. */
export interface JsonSchema {
  type?: string | string[];
  format?: string;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema;
  default?: unknown;
  [keyword: string]: unknown;
}

/**
 * §15.8 — one rule's result. A rule has no name, so the result names where it stands. The field names are
 * *proposed* in §15.8.
 */
export interface LimitEvaluation {
  /** The document: a policy's URN and version, or a mandate's URN. */
  in: string;
  /** The tool the rule is written for; absent for a root rule. */
  tool?: string;
  /** The rule's position in its list, from 0. */
  rule: number;
  result: "pass" | "fail" | "error";
  reason?: string;
}
