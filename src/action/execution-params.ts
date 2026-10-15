import type { ArrayItemType, ParamDef } from "./types.js";

/** Every type this SDK understands. A declaration outside this set is refused (see below). */
const KNOWN_TYPES = new Set<string>([
  "string",
  "number",
  "integer",
  "boolean",
  "datetime",
  "array",
  "map",
]);

/**
 * Validate supplied values against a `Record<string, ParamDef>` declaration.
 *
 * SPEC-DELTA N28: uses a strict `undefined`/`null` "missing" check (the platform's
 * `validateUserParams` used `!value`, mishandling `0`/`false`/`""`).
 * N29: validates `datetime` (the platform validators omit it).
 *
 * An unrecognised `type` refuses the whole verification rather than skipping that one
 * parameter. This SDK is the spec implementation, so it is the thing an integrator runs to
 * check our decisions independently. If a newer platform declares a type this build does not
 * know, skipping it would let this verifier ALLOW an order the platform denies — wrong in the
 * permissive direction, and silent. Refusing is the fail-closed answer: a verifier that does
 * not understand a parameter is not checking what the customer signed.
 *
 * The check is on the DECLARATION, not on the supplied value, and so runs even when the
 * parameter is absent. "I do not understand this action" is true either way.
 */
export function validateParams(
  defs: Record<string, ParamDef>,
  values: Record<string, unknown>,
  kind: "User" | "Execution",
): void {
  for (const [name, def] of Object.entries(defs)) {
    if (!KNOWN_TYPES.has(def.type as string)) {
      throw new Error(
        `${kind} param '${name}' declares unknown type '${String(def.type)}'; this SDK build cannot verify it`,
      );
    }
    const value = values[name];
    if (value === undefined || value === null) {
      if (def.required) throw new Error(`${kind} param '${name}' is required`);
      continue;
    }
    switch (def.type) {
      case "number":
      case "integer":
      case "string":
      case "boolean":
      case "datetime":
        if (!matchesScalar(def.type, value)) throw err(kind, name, def.type);
        break;
      case "array":
        if (!Array.isArray(value)) throw err(kind, name, "array");
        break;
      case "map":
        validateMap(def.values, value, kind, name);
        break;
    }
  }
}

/**
 * Keys permitted in a `map` param: 1-100 characters of `A-Z a-z 0-9 . _ : -`.
 *
 * The length bound is the obvious half. The charset is the deliberate one: map keys are
 * rendered on the approval screen, so unrestricted Unicode would let a key be built from
 * homoglyphs that read as a legitimate identifier (an ISIN, an account id) to the human
 * signing the mandate. Colon is in because URNs and DIDs use it.
 */
export const MAP_KEY_PATTERN = /^[A-Za-z0-9._:-]{1,100}$/;

/** Shared by the top-level switch and by `map` values, so a value validates identically either way. */
function matchesScalar(type: ArrayItemType, value: unknown): boolean {
  switch (type) {
    case "number":
      return typeof value === "number" && !Number.isNaN(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "datetime":
      return typeof value === "number" ? Number.isFinite(value) : typeof value === "string" && Number.isFinite(Date.parse(value));
  }
}

function validateMap(
  valueType: ArrayItemType | undefined,
  value: unknown,
  kind: "User" | "Execution",
  name: string,
): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw err(kind, name, "map");
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (!MAP_KEY_PATTERN.test(key)) {
      throw new Error(
        `${kind} param '${name}' has an invalid key '${key}': map keys must be 1-100 characters of A-Z a-z 0-9 . _ : -`,
      );
    }
    if (valueType && !matchesScalar(valueType, entry)) {
      throw new Error(`${kind} param '${name}' value for key '${key}' must be a ${valueType}`);
    }
  }
}

function err(kind: string, name: string, type: string): Error {
  return new Error(`${kind} param '${name}' must be a ${type}`);
}

interface ActionContentShape {
  userParams?: Record<string, ParamDef>;
  executionParams?: Record<string, ParamDef>;
}

function parseContent(content: unknown): ActionContentShape {
  const c = typeof content === "string" ? (JSON.parse(content) as ActionContentShape) : (content as ActionContentShape);
  return c ?? {};
}

/** Validate agent-supplied `executionParams` against the action's declared shape (verify path). */
export function validateExecutionParams(content: unknown, executionParams: Record<string, unknown>): void {
  validateParams(parseContent(content).executionParams ?? {}, executionParams, "Execution");
}

/** Validate issuer-supplied `userParams` against the action's declared shape (issuance path). */
export function validateUserParams(content: unknown, userParams: Record<string, unknown>): void {
  validateParams(parseContent(content).userParams ?? {}, userParams, "User");
}

export interface WrappedUserParam {
  description: string;
  value: unknown;
}

/** Build the mandate instance shape `{ name: { description, value } }` from the action's descriptions. */
export function wrapUserParamsWithAction(
  content: unknown,
  userParams: Record<string, unknown>,
): Record<string, WrappedUserParam> {
  const defs = parseContent(content).userParams ?? {};
  const out: Record<string, WrappedUserParam> = {};
  for (const [name, value] of Object.entries(userParams)) {
    const description = typeof defs[name]?.description === "string" ? defs[name]!.description! : "";
    out[name] = { description, value };
  }
  return out;
}

/** Strip the `{ description, value }` envelope to a flat `{ name: value }` for CEL. */
export function unwrapUserParamValues(
  userParams: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  if (!userParams) return {};
  const out: Record<string, unknown> = {};
  for (const [name, raw] of Object.entries(userParams)) {
    if (raw && typeof raw === "object" && !Array.isArray(raw) && "value" in raw && "description" in raw) {
      out[name] = (raw as { value: unknown }).value;
    } else {
      out[name] = raw;
    }
  }
  return out;
}
