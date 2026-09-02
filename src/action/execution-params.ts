import type { ParamDef } from "./types.js";

/**
 * Validate supplied values against a `Record<string, ParamDef>` declaration.
 *
 * SPEC-DELTA N28: uses a strict `undefined`/`null` "missing" check (the platform's
 * `validateUserParams` used `!value`, mishandling `0`/`false`/`""`).
 * N29: validates `datetime` (the platform validators omit it).
 */
export function validateParams(
  defs: Record<string, ParamDef>,
  values: Record<string, unknown>,
  kind: "User" | "Execution",
): void {
  for (const [name, def] of Object.entries(defs)) {
    const value = values[name];
    if (value === undefined || value === null) {
      if (def.required) throw new Error(`${kind} param '${name}' is required`);
      continue;
    }
    switch (def.type) {
      case "number":
        if (typeof value !== "number" || Number.isNaN(value)) throw err(kind, name, "number");
        break;
      case "integer":
        if (typeof value !== "number" || !Number.isInteger(value)) throw err(kind, name, "integer");
        break;
      case "string":
        if (typeof value !== "string") throw err(kind, name, "string");
        break;
      case "boolean":
        if (typeof value !== "boolean") throw err(kind, name, "boolean");
        break;
      case "datetime":
        if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw err(kind, name, "datetime");
        break;
      case "array":
        if (!Array.isArray(value)) throw err(kind, name, "array");
        break;
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
