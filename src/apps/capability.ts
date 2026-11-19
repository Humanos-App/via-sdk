/**
 * v0.4 §13.1 — a capability: a normalized tool with fixed parameters, pinned by digest, that any provider's app may
 * implement. `wallet.send` means the same at every provider, so a rule written on it holds at all of them.
 */
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { coversKind, isKindOrFamily } from "../datalayer/kinds.js";
import type { ToolFill } from "../datalayer/policy.js";
import type { JsonSchema, ToolDefinition } from "../limits/types.js";

/** A capability's parameter, or a field of its result. */
export interface CapabilityParam {
  type?: "string" | "number" | "integer" | "boolean" | "array" | "object";
  /** `decimal` for an amount of money (exact in rules), `date-time`, `caip2` for a chain. */
  format?: string;
  required?: boolean;
  enum?: unknown[];
  items?: CapabilityParam;
  default?: unknown;
  description?: string;
  /** §14.2 — the kinds of personal data it carries: one, or several for free text that may hold them. */
  personalData?: string | string[];
}

export interface ViaCapability {
  /** `urn:via:capability:{name}` */
  $id: string;
  type: "VIACapability";
  /** Neutral: `wallet.send`, never `humanos.wallet.send`, so another operator can implement the same schema. */
  name: string;
  version: number;
  description: string;
  params: Record<string, CapabilityParam>;
  result?: Record<string, CapabilityParam>;
}

const NAME = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const TYPES = ["string", "number", "integer", "boolean", "array", "object"];

/** §13.1 — the digest that pins a version: the `digestSRI` of its JCS form (v0.3 §0.5.3). */
export function capabilityDigest(capability: ViaCapability): string {
  return computeSRI(canonicalizeRFC8785(capability));
}

/** A capability's name is neutral and dotted; a tool of a server is `server/name`, which this is never. */
export const isCapabilityName = (name: unknown): name is string => typeof name === "string" && NAME.test(name);

/** §13.1 — what stops a capability's version being published, in words; empty when it may be. */
export function capabilityIssues(capability: ViaCapability): string[] {
  const issues: string[] = [];
  if (capability.type !== "VIACapability") issues.push("`type` is not VIACapability");
  if (!isCapabilityName(capability.name)) issues.push("`name` is not a neutral dotted name, such as `wallet.send`");
  else if (capability.$id !== `urn:via:capability:${capability.name}`) issues.push("`$id` is not `urn:via:capability:` and its name");
  if (!Number.isInteger(capability.version) || capability.version < 1) issues.push("`version` is not a whole number of at least 1");
  if (typeof capability.description !== "string" || !capability.description.trim()) issues.push("`description` is missing");
  if (!capability.params || typeof capability.params !== "object" || Array.isArray(capability.params)) return [...issues, "`params` is missing"];
  for (const [where, fields] of [["params", capability.params], ["result", capability.result ?? {}]] as const) {
    for (const [name, def] of Object.entries(fields)) {
      const at = `${where}.${name}`;
      if (def.type !== undefined && !TYPES.includes(def.type)) issues.push(`${at}: its type is none of ${TYPES.join(", ")}`);
      if (def.type === undefined && !Array.isArray(def.enum)) issues.push(`${at}: it has no type and no \`enum\``);
      if (def.format === "decimal" && def.type !== "string") issues.push(`${at}: a decimal is a string on the wire`);
      for (const kind of def.personalData === undefined ? [] : [def.personalData].flat()) {
        if (!isKindOrFamily(kind)) issues.push(`${at}: \`personalData\` names ${JSON.stringify(kind)}, which is no kind`);
      }
    }
  }
  return issues;
}

/**
 * §13.1 — what stops `next` being a version of `previous`: a version only adds optional parameters. A parameter
 * never changes meaning, so none is removed or altered, and a new one is never required: a call that leaves it out
 * does what it did before. (That a new parameter's default changes nothing for earlier calls is the reviewer's to
 * judge; it cannot be read off the schema.)
 */
export function capabilityVersionIssues(previous: ViaCapability, next: ViaCapability): string[] {
  const issues: string[] = [];
  if (next.name !== previous.name) issues.push("a version keeps the capability's name: a change of meaning is a new capability");
  if (next.version !== previous.version + 1) issues.push(`the version after ${previous.version} is ${previous.version + 1}`);
  for (const [name, def] of Object.entries(previous.params)) {
    if (!(name in next.params)) issues.push(`params.${name} was removed`);
    else if (canonicalizeRFC8785(next.params[name]) !== canonicalizeRFC8785(def)) issues.push(`params.${name} changed: a parameter never changes meaning`);
  }
  for (const [name, def] of Object.entries(next.params)) {
    if (!(name in previous.params) && def.required) issues.push(`params.${name} is new and required: a version only adds optional parameters`);
  }
  return issues;
}

function schemaOf(def: CapabilityParam): JsonSchema {
  return {
    ...(def.type ? { type: def.type } : {}),
    ...(def.format ? { format: def.format } : {}),
    ...(def.enum ? { enum: def.enum } : {}),
    ...(def.items ? { items: schemaOf(def.items) } : {}),
    ...(def.default !== undefined ? { default: def.default } : {}),
  };
}

/** §15.3 — a capability's parameters as the inputs a call is read against: declared, typed, with their defaults. */
export function capabilityInputSchema(capability: ViaCapability): JsonSchema {
  const required = Object.entries(capability.params).filter(([, def]) => def.required).map(([name]) => name).sort();
  return {
    type: "object",
    properties: Object.fromEntries(Object.entries(capability.params).map(([name, def]) => [name, schemaOf(def)])),
    ...(required.length ? { required } : {}),
  };
}

/** A capability as a tool's definition reads: its name, Humanos's description of it, and its inputs. */
export function capabilityDefinition(capability: ViaCapability): ToolDefinition {
  return { name: capability.name, description: capability.description, inputSchema: capabilityInputSchema(capability) };
}

/** §14.2 — the kinds a capability's parameter carries. */
export function capabilityCarries(capability: ViaCapability, param: string): string[] {
  const kinds = capability.params[param]?.personalData;
  return kinds === undefined ? [] : [kinds].flat();
}

/**
 * §14.3 — on a capability, a policy's `fill` MUST NOT name a kind the capability's parameter does not carry; it may
 * name fewer. In words; empty when it holds.
 */
export function capabilityFillIssues(fill: ToolFill, capability: ViaCapability): string[] {
  const issues: string[] = [];
  for (const [param, names] of Object.entries(fill)) {
    const carried = capabilityCarries(capability, param);
    for (const name of [names].flat()) {
      if (!carried.some((kind) => coversKind(kind, name) || kind === name)) issues.push(`\`fill\`: ${capability.name}'s ${param} does not carry ${name}`);
    }
  }
  return issues;
}
