/**
 * v0.4 §15.3 — a tool, its definition and its inputs: the key a document names it by, the hash that pins its
 * definition, and what a call's inputs are read against (the inputs it declares, their defaults, their types).
 */
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import type { JsonSchema, ToolDefinition } from "./types.js";

/** `server/name`, a whole server `server/*`, or a capability's bare name (`wallet.send`, §13.1). */
export interface ToolKey {
  server?: string;
  name: string;
  /** `server/*`: every tool of the server, one it adds later included. */
  wholeServer: boolean;
}

/** §15 — read a key of `tools`; null when it is none of the three forms. */
export function parseToolKey(key: string): ToolKey | null {
  if (typeof key !== "string" || key.length === 0) return null;
  const slash = key.indexOf("/");
  if (slash < 0) return { name: key, wholeServer: false };
  const server = key.slice(0, slash);
  const name = key.slice(slash + 1);
  if (!server || !name || name.includes("/")) return null;
  if (name === "*") return { server, name, wholeServer: true };
  return name.includes("*") ? null : { server, name, wholeServer: false };
}

/**
 * §15.3 — the server part of a tool's key, from the name a server or a service goes by: lowercase, with each run of
 * spaces, underscores, hyphens and slashes as one hyphen, and none at either end. "Google Calendar",
 * "google_calendar" and "google-calendar" are one server, so a tool a member allowed is the same tool however an
 * agent spells where it comes from.
 */
export function serverKey(label: string): string {
  return label.trim().toLowerCase().replace(/[\s_\-/]+/g, "-").replace(/^-+|-+$/g, "");
}

/** §15.3 — the server part of the key of a tool its host declares under no service: `own/create_refund`. */
export const OWN_SERVER = "own";

/**
 * §15.3 — a tool's key in a policy and a mandate: its server, spelled by {@link serverKey}, and its name as the
 * server gives it. A tool declared under no service, or under a label that spells nothing, is keyed under
 * {@link OWN_SERVER}. Null when the name is empty or holds a slash or a star: such a tool has no key.
 *
 * `own` is not reserved: a service that calls itself "Own" shares the key space of the tools with no service. The
 * server in a key is what the host says it is, never a boundary; the definition's hash is what holds a tool.
 */
export function toolKey(server: string | null | undefined, name: string): string | null {
  const key = `${serverKey(server ?? "") || OWN_SERVER}/${name}`;
  const parsed = parseToolKey(key);
  return parsed && !parsed.wholeServer ? key : null;
}

/** The key that covers a whole server's tools, for a tool's key; null for a capability, which has no server. */
export function wholeServerKey(key: string): string | null {
  const parsed = parseToolKey(key);
  return parsed?.server ? `${parsed.server}/*` : null;
}

/**
 * A schema as it is hashed: every `required` list sorted, since JSON Schema gives their order no meaning, and every
 * `$schema` left out, since it names the dialect the schema is written in and nothing of the tool. A key of a
 * `properties` map is an input's name, never a keyword: an input called `$schema` or `required` stays.
 */
function tidySchema(value: unknown, names = false): unknown {
  if (Array.isArray(value)) return value.map((v) => tidySchema(v));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => names || key !== "$schema")
      .map(([key, v]) => {
        if (names) return [key, tidySchema(v)];
        if (key === "required" && Array.isArray(v) && v.every((x) => typeof x === "string")) return [key, [...v].sort()];
        return [key, tidySchema(v, key === "properties" || key === "patternProperties" || key === "$defs" || key === "definitions")];
      }),
  );
}

/**
 * §15.3 — a tool's `hash`: the `digestSRI` (v0.3 §0.5.3) of the JCS form of its name, title, description, input
 * schema, output schema and annotations. A corrected typo changes it: a description is where a tool gives the
 * agent instructions.
 *
 * Three things that mean nothing are set aside first, and nothing else: the spaces around the name, the title and
 * the description; the order of a schema's `required` lists; and a schema's `$schema`, which names the dialect it
 * is written in, so the same tool described by two libraries, or by a library before and after it moves dialect,
 * is one tool. An absent or empty text is left out, so a missing
 * title and a blank one hash alike. Nothing is cut and nothing is dropped: every annotation and every character
 * counts. The server is not in it: the tool's key names it.
 */
export function toolDefinitionHash(definition: ToolDefinition): string {
  const pinned: Record<string, unknown> = { name: definition.name.trim() };
  for (const member of ["title", "description"] as const) {
    const text = typeof definition[member] === "string" ? definition[member].trim() : "";
    if (text) pinned[member] = text;
  }
  for (const member of ["inputSchema", "outputSchema"] as const) {
    if (definition[member] !== undefined && definition[member] !== null) pinned[member] = tidySchema(definition[member]);
  }
  if (definition.annotations !== undefined && definition.annotations !== null) pinned.annotations = definition.annotations;
  return computeSRI(canonicalizeRFC8785(pinned));
}

/**
 * §13.0, §15.3 — the hash of a tool known by name only, from its key: what a hook can compute from the name it is
 * handed, and what a policy pins for such a tool. Null for a key that names no one tool.
 */
export function nameOnlyHash(key: string): string | null {
  const parsed = parseToolKey(key);
  return parsed && !parsed.wholeServer ? toolDefinitionHash({ name: parsed.name }) : null;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * §15.3 — the first input a call carries that its tool does not declare, as a path (`recipient.note`,
 * `lines[].sku`); null when every one is declared. Checked inside an object, and inside each item of a list,
 * wherever the schema declares the properties. A tool that declares none takes no inputs.
 */
export function undeclaredInput(schema: JsonSchema | undefined, params: Record<string, unknown>): string | null {
  return undeclaredIn(schema ?? {}, params, "", true);
}

function undeclaredIn(schema: JsonSchema, value: unknown, at: string, root: boolean): string | null {
  if (Array.isArray(value)) {
    if (!schema.items) return null;
    for (const item of value) {
      const found = undeclaredIn(schema.items, item, `${at}[]`, false);
      if (found) return found;
    }
    return null;
  }
  if (!isObject(value)) return null;
  // Below the root, an object whose properties the schema does not declare is opaque: nothing to check against.
  if (!schema.properties && !root) return null;
  const declared = schema.properties ?? {};
  for (const [name, inner] of Object.entries(value)) {
    const path = at ? `${at}.${name}` : name;
    if (!Object.prototype.hasOwnProperty.call(declared, name)) return path;
    const found = undeclaredIn(declared[name]!, inner, path, false);
    if (found) return found;
  }
  return null;
}

/**
 * §15.3 — the call's inputs as the rules read them: an input the call leaves out takes the default its schema
 * declares, at the root and inside every object the call does carry. One with no default stays absent, and a
 * condition over it fails.
 */
export function inputsWithDefaults(schema: JsonSchema | undefined, params: Record<string, unknown>): Record<string, unknown> {
  return fill(schema ?? {}, params) as Record<string, unknown>;
}

function fill(schema: JsonSchema, value: unknown): unknown {
  if (Array.isArray(value)) return schema.items ? value.map((item) => fill(schema.items!, item)) : value;
  if (!isObject(value) || !schema.properties) return value;
  const out: Record<string, unknown> = { ...value };
  for (const [name, inner] of Object.entries(schema.properties)) {
    if (out[name] === undefined) {
      if (inner.default !== undefined) out[name] = structuredClone(inner.default);
    } else {
      out[name] = fill(inner, out[name]);
    }
  }
  return out;
}

/** What a condition's operators are chosen by (§15.4). */
export type InputKind = "number" | "integer" | "decimal" | "text" | "datetime" | "boolean" | "list" | "object" | "unknown";

/** One step of an input's path: a name, and whether the condition reads every item of the list found there. */
export interface PathStep {
  name: string;
  each: boolean;
}

/** §15.4 — `recipient.iban` and `lines[].price` as steps; null when a step is empty. */
export function parseInputPath(path: string): PathStep[] | null {
  if (typeof path !== "string" || path.length === 0) return null;
  const steps = path.split(".").map((part) => (part.endsWith("[]") ? { name: part.slice(0, -2), each: true } : { name: part, each: false }));
  return steps.every((s) => s.name.length > 0 && !s.name.includes("[") && !s.name.includes("]")) ? steps : null;
}

/** The kind a schema describes; `unknown` when it names none, or several. */
export function kindOf(schema: JsonSchema | undefined): InputKind {
  const type = Array.isArray(schema?.type) ? schema.type.filter((t) => t !== "null") : schema?.type ? [schema.type] : [];
  if (type.length !== 1) return "unknown";
  switch (type[0]) {
    case "number":
      return "number";
    case "integer":
      return "integer";
    case "boolean":
      return "boolean";
    case "array":
      return "list";
    case "object":
      return "object";
    case "string":
      // §13.1 — an amount of money is a text declared a decimal, and reaches a rule as an exact one.
      return schema?.format === "date-time" ? "datetime" : schema?.format === "decimal" ? "decimal" : "text";
    default:
      return "unknown";
  }
}

/**
 * §15.4 — what an input's path names in the tool's schema: its kind, and, for a list, its items' kind. Null when
 * the tool declares no such input, or the path reads items of something that is not a list.
 */
export function inputAt(schema: JsonSchema | undefined, path: string): { kind: InputKind; items?: InputKind } | null {
  const steps = parseInputPath(path);
  if (!steps) return null;
  let at: JsonSchema | undefined = schema;
  for (const step of steps) {
    at = at?.properties?.[step.name];
    if (!at) return null;
    if (step.each) {
      if (kindOf(at) !== "list" || !at.items) return null;
      at = at.items;
    }
  }
  const kind = kindOf(at);
  return kind === "list" ? { kind, items: kindOf(at?.items) } : { kind };
}
