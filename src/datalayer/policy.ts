/** v0.4 §14.3, §14.5, §14.8 — the policy's `context`, a tool's `fill`, and a call's `context`. */
import { inputAt } from "../limits/tool.js";
import type { JsonSchema } from "../limits/types.js";
import { coversKind, isKind, isKindOrFamily, KIND_HINTS, kindsOfLabel } from "./kinds.js";
import { tokensIn, type TokenFound } from "./tokens.js";

/** §14.3 — the policy's settings for the context layer. Absent, nothing is replaced. */
export interface PolicyContext {
  /** Kinds, or families, that reach a model only as tokens. */
  tokens?: string[];
  /** What a token may show beside its label, by kind (§14.1). */
  hints?: Record<string, string[]>;
  /** The organization's own kinds: `org.customer_number`, each found by its pattern. */
  kinds?: Record<string, { pattern: string }>;
  /** Kinds removed before the model: never kept, never filled. Absent, `["secret.*"]`. */
  remove?: string[];
  /** An image or a file the layer cannot read. */
  unscanned?: "send" | "refuse";
  /** How long values are kept after the conversation's last call, an ISO 8601 duration. */
  retention?: string;
  /** §14.9 — the modules switched on. */
  modules?: Record<string, "on" | "required">;
}

/** §14.3 — per parameter, the kinds that may be filled into it. */
export type ToolFill = Record<string, string | string[]>;

/** §14.3 — the kinds removed when the policy says nothing. */
export const DEFAULT_REMOVE: readonly string[] = ["secret.*"];

const DURATION = /^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+S)?)?$/;
const PATTERN_MAX_LENGTH = 200;

/** §14.3 — what stops a policy's `context` being published, in words; empty when it may be. */
export function policyContextIssues(context: PolicyContext): string[] {
  const issues: string[] = [];
  if (!context || typeof context !== "object" || Array.isArray(context)) return ["`context` is not an object"];
  const own = Object.keys(context.kinds ?? {});
  const known = (name: unknown) => isKindOrFamily(name) && (!String(name).startsWith("org.") || name === "org.*" || own.includes(String(name)));
  for (const list of ["tokens", "remove"] as const) {
    const names = context[list];
    if (names === undefined) continue;
    if (!Array.isArray(names)) issues.push(`\`context.${list}\` is a list of kinds`);
    else for (const name of names) if (!known(name)) issues.push(`\`context.${list}\` names ${JSON.stringify(name)}, which is no kind`);
  }
  for (const [kind, hints] of Object.entries(context.hints ?? {})) {
    if (!isKind(kind)) issues.push(`\`context.hints\` names ${JSON.stringify(kind)}, which is no kind`);
    else for (const hint of Array.isArray(hints) ? hints : [hints]) {
      if (!KIND_HINTS[kind]?.includes(String(hint))) issues.push(`\`context.hints\`: ${kind} shows no ${JSON.stringify(hint)}`);
    }
  }
  for (const [kind, def] of Object.entries(context.kinds ?? {})) {
    if (!kind.startsWith("org.") || !isKind(kind)) issues.push(`\`context.kinds\`: ${JSON.stringify(kind)} is not an organization's own kind (\`org.<name>\`)`);
    else if (typeof def?.pattern !== "string" || !def.pattern || def.pattern.length > PATTERN_MAX_LENGTH) issues.push(`\`context.kinds\`: ${kind} has no pattern, or one over ${PATTERN_MAX_LENGTH} characters`);
    else {
      try {
        new RegExp(def.pattern, "u");
      } catch {
        issues.push(`\`context.kinds\`: ${kind}'s pattern does not compile`);
      }
    }
  }
  if (context.unscanned !== undefined && context.unscanned !== "send" && context.unscanned !== "refuse") issues.push("`context.unscanned` is `send` or `refuse`");
  if (context.retention !== undefined && (typeof context.retention !== "string" || !DURATION.test(context.retention))) issues.push("`context.retention` is an ISO 8601 duration, such as `P1D`");
  for (const [name, state] of Object.entries(context.modules ?? {})) {
    if (state !== "on" && state !== "required") issues.push(`\`context.modules\`: ${name} is \`on\` or \`required\``);
  }
  return issues;
}

/**
 * §14.3 — what stops a tool's `fill` being published, in words. Each parameter is one the tool declares, a text or
 * a list of them, and each kind is one the policy knows. That a capability's `fill` names no kind its parameter
 * does not carry (§14.2) is checked where the capability is read (§13).
 */
export function toolFillIssues(fill: ToolFill, inputs: JsonSchema | undefined, context: PolicyContext | undefined): string[] {
  const issues: string[] = [];
  if (!fill || typeof fill !== "object" || Array.isArray(fill)) return ["`fill` is not an object"];
  const own = Object.keys(context?.kinds ?? {});
  for (const [param, kinds] of Object.entries(fill)) {
    const declared = inputAt(inputs, param);
    if (!declared) issues.push(`\`fill\`: the tool declares no input ${JSON.stringify(param)}`);
    else if (declared.kind !== "text" && !(declared.kind === "list" && declared.items === "text")) issues.push(`\`fill\`: ${param} is not a text, and a value is filled into a text`);
    const names = Array.isArray(kinds) ? kinds : [kinds];
    if (names.length === 0) issues.push(`\`fill\`: ${param} names no kind`);
    for (const name of names) {
      if (!isKindOrFamily(name) || (String(name).startsWith("org.") && name !== "org.*" && !own.includes(String(name)))) issues.push(`\`fill\`: ${param} names ${JSON.stringify(name)}, which is no kind`);
    }
  }
  return issues;
}

/** §14.5 — may a token of this kind be filled into this parameter of the tool, by the tool's `fill`? */
export function mayFill(fill: ToolFill | undefined, param: string, kind: string): boolean {
  const names = fill?.[param];
  return names !== undefined && (Array.isArray(names) ? names : [names]).some((name) => coversKind(name, kind));
}

/** §14.8 — a call's context, as Humanos established it: never what an agent says of itself. */
export interface CallLayerContext {
  /** `hosted` and `router` only where Humanos ran the layer; an agent's own gives `agent`, whatever it reports. */
  mode: "hosted" | "router" | "agent" | "none";
  /** True only in `hosted`, where Humanos saw both the model's proposal and the call. */
  proposed: boolean;
  /** The arguments filled from tokens, by kind: never the values. */
  filled: Record<string, string[]>;
}

/** §14.8 — what a call with no layer carries: a rule over `context` always has a value to read. */
export const NO_LAYER_CONTEXT: CallLayerContext = { mode: "none", proposed: false, filled: {} };

/** §14.5 — a token left in a call's arguments, with what the model is told about it. */
export interface UnfilledToken extends TokenFound {
  /** The kinds its label may stand for; empty for a label nobody defined. */
  kinds: string[];
  /** The reason the model reads: "web_fetch may not receive person.email". */
  reason: string;
}

/**
 * §14.5 — the tokens a call's arguments still carry. An allowed token was filled before the agent ran the tool, so
 * one that reaches a verifier was refused, was never issued, or marks a removed value (`⟦SECRET⟧`): the call is
 * denied `token_unfilled`, and the tool never runs with a token as its argument.
 */
export function unfilledTokens(tool: string, params: Record<string, unknown>, context: PolicyContext | undefined): UnfilledToken[] {
  const own = Object.keys(context?.kinds ?? {});
  return tokensIn(params).map((found) => {
    const kinds = found.label ? kindsOfLabel(found.label, own) : [];
    const what = found.n === undefined && kinds.length ? "a value that was removed" : kinds.length === 1 ? kinds[0]! : kinds.length ? kinds[0]!.replace(/\.[^.]+$/, ".*") : "a token nobody issued";
    return { ...found, kinds, reason: `${tool} may not receive ${what}${found.at ? ` in ${found.at}` : ""}` };
  });
}
