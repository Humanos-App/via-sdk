/**
 * v0.4 §15.1 — the organization's policy without VIAAction: what stops a version being published, and the entry
 * that speaks for a tool.
 */
import { validateDescription } from "../mandate/description.js";
import { policyContextIssues, toolFillIssues } from "../datalayer/policy.js";
import { capabilityDefinition, capabilityDigest, capabilityFillIssues, isCapabilityName, type ViaCapability } from "../apps/capability.js";
import { ruleIssues } from "./rule.js";
import { nameOnlyHash, parseToolKey, toolDefinitionHash, wholeServerKey } from "./tool.js";
import { TOOL_EFFECTS, type LimitsPolicy, type MandateLimits, type PolicyTool, type ToolDefinition } from "./types.js";

/** Is this policy version of v0.4's shape? Read from its marker, never from which fields are present (§15.7). */
export function isLimitsPolicy(policy: unknown): policy is LimitsPolicy {
  return !!policy && typeof policy === "object" && (policy as { specVersion?: unknown }).specVersion === "0.4";
}

/**
 * §15.1 — what the policy says of a tool: its own entry, else its server's `server/*`, else nothing, and the
 * policy's `default` decides. A tool's own entry wins over its server's: `deny` on the server, one tool allowed.
 */
export function policyToolFor(policy: Pick<LimitsPolicy, "tools">, tool: string): { key: string; entry: PolicyTool } | null {
  const own = Object.prototype.hasOwnProperty.call(policy.tools, tool) ? policy.tools[tool] : undefined;
  if (own) return { key: tool, entry: own };
  const server = wholeServerKey(tool);
  const whole = server && Object.prototype.hasOwnProperty.call(policy.tools, server) ? policy.tools[server] : undefined;
  return whole ? { key: server!, entry: whole } : null;
}

/** Does a tool's entry leave a call to a person: its effect, or a rule whose failure a person settles (§15.6)? */
export const leavesToAPerson = (entry: PolicyTool) => entry.effect === "mandate" || !!entry.rules?.some((r) => r.otherwise === "mandate");

/** What the publish check needs beyond the policy: the platform's records, read beforehand. */
export interface LimitsPublishContext {
  /** The definition on record for a tool's key; null when there is none. A capability's is its approved version's. */
  definition: (tool: string) => ToolDefinition | null;
  /** Is this person a member of the organization, by Humanos's record (§15.5)? */
  isMember: (did: string) => boolean;
  /** §15.3 — was the definition on record cut when it was stored? One that was cannot be reviewed whole. */
  isCut?: (tool: string) => boolean;
  /** §13.1 — a published version of a capability; null when there is none. Needed when `tools` names one. */
  capability?: (name: string, version: number) => ViaCapability | null;
}

/** §15.3 — what a tool's key is pinned by: a server's tool by its definition, a capability by a version's digest. */
function pinnedFor(
  key: string,
  version: number | undefined,
  ctx: Pick<LimitsPublishContext, "definition" | "capability">,
): { definition: ToolDefinition | null; hash?: string; capability?: ViaCapability; issue?: string } {
  if (!isCapabilityName(key)) {
    const definition = ctx.definition(key);
    return { definition, ...(definition ? { hash: toolDefinitionHash(definition) } : {}) };
  }
  if (!Number.isInteger(version)) return { definition: null, issue: "a capability names the `version` a member approved" };
  const capability = ctx.capability?.(key, version!) ?? null;
  if (!capability) return { definition: null };
  return { definition: capabilityDefinition(capability), hash: capabilityDigest(capability), capability };
}

/** v0.3's fields a v0.4 policy does not carry (§15.9). */
const GONE = ["entries", "everyCall", "approvers", "authorizations"] as const;

/**
 * §15.1, §15.5, §15.6 — what stops a policy version being published, in words; empty when it may be. The issuer's
 * check before `POLICY_PUBLISHED` is written; a verifier reads a published version as written.
 */
export function limitsPolicyPublishIssues(policy: LimitsPolicy, ctx: LimitsPublishContext): string[] {
  const issues: string[] = [];
  if (policy.type !== "VIAPolicy") issues.push("`type` is not VIAPolicy");
  if (typeof policy.$id !== "string" || !policy.$id.startsWith("urn:via:policy:")) issues.push("`$id` is not a urn:via:policy URN");
  if (policy.specVersion !== "0.4") issues.push("`specVersion` is not 0.4");
  if (!Number.isInteger(policy.version) || policy.version < 1) issues.push("`version` is not a whole number of at least 1");
  if (policy.default !== "mandate" && policy.default !== "deny") {
    issues.push("`default` is `mandate` or `deny`, never `allow`: a tool nobody reviewed has no pinned definition and no limits");
  }
  for (const field of GONE) if (field in policy) issues.push(`\`${field}\` is not in a v0.4 policy`);

  for (const [i, rule] of (policy.rules ?? []).entries()) {
    for (const issue of ruleIssues(rule, { document: "policy", root: true })) issues.push(`rule ${i + 1}: ${issue}`);
    if (rule.otherwise) issues.push(`rule ${i + 1}: a root rule's failure is not left to a person: it names no tool to grant`);
  }

  if (policy.context !== undefined) issues.push(...policyContextIssues(policy.context));

  if (!policy.tools || typeof policy.tools !== "object" || Array.isArray(policy.tools)) return [...issues, "`tools` is missing"];
  for (const [key, entry] of Object.entries(policy.tools)) {
    const at = `tool ${key}`;
    const parsed = parseToolKey(key);
    if (!parsed) {
      issues.push(`${at}: its key is none of \`server/name\`, \`server/*\` and a capability's name`);
      continue;
    }
    if (!TOOL_EFFECTS.includes(entry.effect)) {
      issues.push(`${at}: its effect is none of allow, mandate and deny`);
      continue;
    }
    if (parsed.wholeServer) {
      if (entry.effect !== "deny" || Object.keys(entry).length > 1) issues.push(`${at}: a whole server takes \`deny\` and nothing else`);
      continue;
    }
    const personNeeded = leavesToAPerson(entry);
    if (entry.effect === "deny") {
      if (entry.rules?.length || entry.grantors !== undefined || entry.oneCall !== undefined || entry.reviewer !== undefined || entry.fill !== undefined) {
        issues.push(`${at}: a denied tool carries no rules, grantors, \`oneCall\`, \`reviewer\` or \`fill\``);
      }
      continue;
    }
    // §13.0 — a tool known by name only is pinned by its name: no definition to hash, no input to limit or fill.
    const pinned = entry.nameOnly ? { definition: { name: parsed.name }, hash: nameOnlyHash(key) ?? undefined } : pinnedFor(key, entry.version, ctx);
    const definition = pinned.definition;
    if (entry.nameOnly !== undefined && entry.nameOnly !== true) issues.push(`${at}: \`nameOnly\` is true, or absent`);
    if (entry.nameOnly && entry.fill !== undefined) issues.push(`${at}: a tool known by name only takes no \`fill\`: its inputs are not declared`);
    if ("issue" in pinned && pinned.issue) issues.push(`${at}: ${pinned.issue}`);
    else if (typeof entry.hash !== "string") issues.push(`${at}: it has no \`hash\`: a tool is pinned by the definition a member reviewed`);
    else if (!definition) issues.push(`${at}: no definition is on record for it`);
    else if (pinned.hash !== entry.hash) issues.push(`${at}: its \`hash\` is not its definition's`);
    if (entry.fill !== undefined && "capability" in pinned && pinned.capability) for (const issue of capabilityFillIssues(entry.fill, pinned.capability)) issues.push(`${at}: ${issue}`);
    if (ctx.isCut?.(key)) issues.push(`${at}: its definition was cut when it was stored, so nobody reviewed it whole`);
    for (const [i, rule] of (entry.rules ?? []).entries()) {
      for (const issue of ruleIssues(rule, { document: "policy", root: false, inputs: definition?.inputSchema })) issues.push(`${at}, rule ${i + 1}: ${issue}`);
    }
    if (personNeeded) {
      const g = entry.grantors;
      if (g === undefined) issues.push(`${at}: it leaves calls to a person and names no \`grantors\`; \`"any"\` is written out, never assumed`);
      else if (g !== "any" && (!Array.isArray(g) || g.length === 0 || g.some((did) => typeof did !== "string"))) issues.push(`${at}: \`grantors\` is a list of DIDs or \`"any"\``);
      else if (g !== "any") for (const did of g) if (!ctx.isMember(did)) issues.push(`${at}: grantor ${did} is not a member of the organization`);
    } else if (entry.grantors !== undefined || entry.oneCall !== undefined || entry.reviewer !== undefined) {
      issues.push(`${at}: \`grantors\`, \`oneCall\` and \`reviewer\` are for a tool that leaves calls to a person`);
    }
    if (entry.fill !== undefined) for (const issue of toolFillIssues(entry.fill, definition?.inputSchema, policy.context)) issues.push(`${at}: ${issue}`);
    if (entry.oneCall !== undefined && typeof entry.oneCall !== "boolean") issues.push(`${at}: \`oneCall\` is true or false`);
    if (entry.reviewer !== undefined && entry.reviewer !== "required") issues.push(`${at}: \`reviewer\` is \`required\`, or absent`);
  }
  return issues;
}

/** What the request check needs beyond the mandate. */
export interface MandateLimitsContext {
  /** The definition on record for a tool's key, as the person will be shown it; null when there is none. */
  definition: (tool: string) => ToolDefinition | null;
  /** §15.3 — was the definition on record cut when it was stored? */
  isCut?: (tool: string) => boolean;
  /** §13.1 — a published version of a capability; null when there is none. */
  capability?: (name: string, version: number) => ViaCapability | null;
}

/**
 * §15.2 — what stops a mandate's limits being signed, in words; empty when they may be. The mandate itself, before
 * the policy is read: its words, its number of calls, its tools and their rules.
 */
export function mandateLimitsIssues(limits: MandateLimits, ctx: MandateLimitsContext): string[] {
  const issues: string[] = [];
  const words = validateDescription(limits.description);
  if (!words.ok) issues.push(`its description is refused: ${words.reason}`);
  if (!Number.isInteger(limits.maxExecutions) || limits.maxExecutions < 1) {
    issues.push("`maxExecutions` is missing: a mandate states how many calls it is good for");
  }
  for (const [i, rule] of (limits.rules ?? []).entries()) {
    for (const issue of ruleIssues(rule, { document: "mandate", root: true })) issues.push(`rule ${i + 1}: ${issue}`);
  }
  const tools = limits.tools && typeof limits.tools === "object" && !Array.isArray(limits.tools) ? Object.entries(limits.tools) : [];
  if (tools.length === 0) issues.push("it lists no tool: a plain authorization is not issued in v0.4");
  for (const [key, tool] of tools) {
    const at = `tool ${key}`;
    const parsed = parseToolKey(key);
    if (!parsed || parsed.wholeServer) {
      issues.push(`${at}: a mandate names each tool, never a whole server`);
      continue;
    }
    const pinned = pinnedFor(key, tool.version, ctx);
    const definition = pinned.definition;
    if (pinned.issue) issues.push(`${at}: ${pinned.issue}`);
    else if (!definition) issues.push(`${at}: no definition is on record for it`);
    else if (pinned.hash !== tool.hash) issues.push(`${at}: its \`hash\` is not its definition's`);
    if (ctx.isCut?.(key)) issues.push(`${at}: its definition was cut when it was stored, so the person cannot be shown it whole`);
    if (!Array.isArray(tool.rules)) {
      issues.push(`${at}: \`rules\` is missing; a tool with no limits carries an empty list`);
      continue;
    }
    for (const [i, rule] of tool.rules.entries()) {
      for (const issue of ruleIssues(rule, { document: "mandate", root: false, inputs: definition?.inputSchema })) issues.push(`${at}, rule ${i + 1}: ${issue}`);
    }
  }
  return issues;
}

/** One reason a request is refused under the policy, with §15.8's code. */
export interface RequestRefusal {
  tool: string;
  reason: "tool_not_covered" | "tool_changed" | "grantor_not_allowed" | "one_call_required" | "policy_denied";
  detail: string;
}

const UPPER = new Set(["<", "<="]);
const LOWER = new Set([">", ">="]);

/**
 * §15.2 — is one of the mandate's limits looser than a policy limit on the same input, where the two compare: a
 * bound against a bound, a list against a list? Only a policy rule of one condition is compared; an exception
 * joined by OR is left to verify.
 */
function looserThan(asked: { operator: string; value?: unknown }, bound: { operator: string; value?: unknown }): boolean {
  const a = asked.value;
  const b = bound.value;
  if (UPPER.has(bound.operator) && typeof b === "number") {
    if ((UPPER.has(asked.operator) || asked.operator === "==") && typeof a === "number") return a > b || (a === b && bound.operator === "<" && asked.operator !== "<");
    if (asked.operator === "in" && Array.isArray(a)) return a.some((v) => typeof v === "number" && (v > b || (v === b && bound.operator === "<")));
  }
  if (LOWER.has(bound.operator) && typeof b === "number") {
    if ((LOWER.has(asked.operator) || asked.operator === "==") && typeof a === "number") return a < b || (a === b && bound.operator === ">" && asked.operator !== ">");
    if (asked.operator === "in" && Array.isArray(a)) return a.some((v) => typeof v === "number" && (v < b || (v === b && bound.operator === ">")));
  }
  if (bound.operator === "in" && Array.isArray(b)) {
    if (asked.operator === "in" && Array.isArray(a)) return a.some((v) => !b.includes(v));
    if (asked.operator === "==") return !b.includes(a);
  }
  if (bound.operator === "not_in" && Array.isArray(b)) {
    if (asked.operator === "in" && Array.isArray(a)) return a.some((v) => b.includes(v));
    if (asked.operator === "==") return b.includes(a);
  }
  return false;
}

/**
 * §15.2, §15.5, §15.6 — why a request for this mandate is refused under the policy as it stands, before the person
 * sees it; empty when it is not. A tool the policy does not leave to a person, a definition the policy pins
 * differently, a grantor the policy does not allow, more than one call where one is required, and a limit looser
 * than the policy's where the two compare. The rest is left to verify, where the policy is read live.
 */
export function mandateRequestRefusals(policy: LimitsPolicy, request: { grantor: string; limits: MandateLimits }): RequestRefusal[] {
  const refusals: RequestRefusal[] = [];
  for (const [tool, asked] of Object.entries(request.limits.tools ?? {})) {
    const found = policyToolFor(policy, tool);
    const entry = found?.entry;
    // A tool under the default has no entry and so nobody to grant it (§15.5): a member names it first.
    if (!entry || !leavesToAPerson(entry)) {
      refusals.push({ tool, reason: "tool_not_covered", detail: entry ? "the policy never reads a mandate for this tool" : "the policy does not name this tool" });
      continue;
    }
    if (entry?.hash !== undefined && entry.hash !== asked.hash) {
      refusals.push({ tool, reason: "tool_changed", detail: "the policy pins another definition of this tool" });
    }
    const grantors = entry?.grantors;
    if (grantors !== "any" && !grantors?.includes(request.grantor)) {
      refusals.push({ tool, reason: "grantor_not_allowed", detail: "the policy does not let this person grant it" });
    }
    const oneCall = entry?.oneCall === true || (entry?.effect !== "mandate" && !!entry?.rules?.some((r) => r.otherwise === "mandate"));
    if (oneCall && request.limits.maxExecutions !== 1) {
      refusals.push({ tool, reason: "one_call_required", detail: "this tool takes one call per approval" });
    }
    for (const rule of entry?.rules ?? []) {
      if (rule.conditions.length !== 1 || rule.otherwise) continue;
      const bound = rule.conditions[0]!;
      if (bound.right !== undefined || bound.measure) continue;
      for (const mine of asked.rules ?? []) {
        const c = mine.conditions[0];
        if (c && c.left === bound.left && !c.measure && looserThan(c, bound)) {
          refusals.push({ tool, reason: "policy_denied", detail: `its limit on ${c.left} asks more than the policy allows` });
        }
      }
    }
  }
  return refusals;
}
