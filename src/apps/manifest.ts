/**
 * v0.4 §13.2 — an app: one signed manifest for everything in the marketplace. What it contributes — tools, checks,
 * rules, models, data access — decides how it is installed and what it reaches.
 */
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { signRaw, verifyRaw } from "../crypto/ed25519.js";
import { fromBase64Url, toBase64Url } from "../crypto/encoding.js";
import type { EventSigner } from "../event/build.js";
import { ruleIssues } from "../limits/rule.js";
import type { LimitRule } from "../limits/types.js";
import type { ResolvePublicKey } from "../mandate/build.js";
import { capabilityDigest, capabilityInputSchema, isCapabilityName, type ViaCapability } from "./capability.js";

/** The manifest's JWS `typ`. */
export const APP_MANIFEST_TYP = "via-app+jwt";

/** A capability an app implements, as a tool or as a check, pinned by its version's digest. */
export interface AppImplements {
  capability: string;
  version: number;
  digestSRI: string;
  /** Where it is available: ISO 3166 alpha-2 codes, or `EU`. The shape is *proposed* in §13.2. */
  regions?: string[];
  /** Over `mcp`: the publisher's tool, and the digest of its definition as reviewed. */
  mcpTool?: string;
  definitionDigest?: string;
  /** For a check: how long, in seconds, its answer may be reused. */
  maxAge?: number;
}

/** The app's rules: a floor an organization adopts, or a suggestion it copies. */
export interface AppRules {
  /** On every call. */
  rules?: LimitRule[];
  tools?: Record<string, { rules: LimitRule[] }>;
}

export interface ViaApp {
  /** `urn:via:app:{uuid}` */
  $id: string;
  type: "VIAApp";
  name: string;
  version: number;
  /** Who built it and maintains it. */
  publisher: string;
  /** With tools, checks or models: the provider Humanos calls. */
  service?: {
    name: string;
    /** The provider's DID, or its origin: the call proof's `aud` (v0.3 §16.16). */
    id: string;
    /** How Humanos reaches it; absent when the app is called, not calling. */
    transport?: "adapter" | "mcp" | "http";
    /** The only origin Humanos calls for this app. */
    endpoint?: string;
    processing?: string[];
  };
  tools?: {
    implements: AppImplements[];
    /** The provider's own tools, not normalized: denied unless a policy names them. */
    own?: { name: string; params?: Record<string, unknown> }[];
    chains?: string[];
    /** Who can sign for the wallets it creates. */
    custody?: string;
    credentials?: ("humanos" | "customer")[];
  } | null;
  checks?: AppImplements[];
  /** §14 — the models an agent's calls through Humanos may use: the APIs it speaks and the models it serves. */
  models?: { api: string[]; models: string[]; routing?: Record<string, unknown> } | null;
  rules?: AppRules | null;
  /** Required with tools or checks: rules an organization copies into its policy's `tools`. */
  suggestedRules?: AppRules;
  /** The organization's data it reads. */
  scopes?: string[];
  outcomes?: { webhook: string } | null;
  panels?: unknown[];
  /** The only sites its links may open. */
  domains?: string[];
  /** The vetter, whose key signs the manifest: the platform. */
  vettedBy: string;
  iat: number;
}

/** §13.2 — the digest that pins a version of an app: of its JCS form. */
export function appDigest(app: ViaApp): string {
  return computeSRI(canonicalizeRFC8785(app));
}

export interface AppManifestContext {
  /** A published capability's version; null when there is none. */
  capability: (name: string, version: number) => ViaCapability | null;
}

const httpsOrigin = (value: unknown): boolean => {
  try {
    return typeof value === "string" && new URL(value).protocol === "https:";
  } catch {
    return false;
  }
};

/** §13.2 — what stops an app's manifest being signed, in words; empty when it may be. */
export function appManifestIssues(app: ViaApp, ctx: AppManifestContext): string[] {
  const issues: string[] = [];
  if (app.type !== "VIAApp") issues.push("`type` is not VIAApp");
  if (typeof app.$id !== "string" || !app.$id.startsWith("urn:via:app:")) issues.push("`$id` is not a urn:via:app URN");
  if (typeof app.name !== "string" || !app.name) issues.push("`name` is missing");
  if (!Number.isInteger(app.version) || app.version < 1) issues.push("`version` is not a whole number of at least 1");
  for (const who of ["publisher", "vettedBy"] as const) if (typeof app[who] !== "string" || !app[who].startsWith("did:")) issues.push(`\`${who}\` is not a DID`);
  if (!Number.isInteger(app.iat)) issues.push("`iat` is missing");

  const implemented = [...(app.tools?.implements ?? []), ...(app.checks ?? [])];
  const calls = implemented.length > 0 || !!app.tools?.own?.length || !!app.models;
  if (calls) {
    if (!app.service) issues.push("an app with tools, checks or models names its `service`");
    else {
      if (!app.service.name || !app.service.id) issues.push("`service` has no name or no id");
      if (!["adapter", "mcp", "http"].includes(String(app.service.transport))) issues.push("`service.transport` is `adapter`, `mcp` or `http`");
      // Humanos calls only this origin, never one an agent or a call supplies.
      if (!httpsOrigin(app.service.endpoint)) issues.push("`service.endpoint` is not an https address");
    }
  }
  const capabilities = new Map<string, ViaCapability>();
  for (const entry of implemented) {
    const at = `${entry.capability} v${entry.version}`;
    const published = isCapabilityName(entry.capability) ? ctx.capability(entry.capability, entry.version) : null;
    if (!published) issues.push(`${at}: no such published capability`);
    else if (capabilityDigest(published) !== entry.digestSRI) issues.push(`${at}: its \`digestSRI\` is not that version's`);
    else capabilities.set(entry.capability, published);
    if (app.service?.transport === "mcp" && (!entry.mcpTool || !entry.definitionDigest)) issues.push(`${at}: over mcp it names its \`mcpTool\` and the reviewed \`definitionDigest\``);
  }
  for (const own of app.tools?.own ?? []) {
    if (typeof own.name !== "string" || !/^[a-z][a-z0-9_]*\._[a-z0-9_]+\.[a-z0-9_]+$/.test(own.name)) issues.push(`own tool ${JSON.stringify(own.name)}: a provider's own is named \`{family}._{provider}.{tool}\``);
  }
  if (app.models && (!Array.isArray(app.models.api) || !app.models.api.length || !Array.isArray(app.models.models) || !app.models.models.length)) {
    issues.push("`models` names the APIs it speaks and the models it serves");
  }
  if (implemented.length > 0 && !app.suggestedRules) issues.push("an app with tools or checks ships `suggestedRules`");
  for (const [field, set] of [["rules", app.rules], ["suggestedRules", app.suggestedRules]] as const) {
    if (!set) continue;
    for (const [i, rule] of (set.rules ?? []).entries()) for (const issue of ruleIssues(rule, { document: "app", root: true })) issues.push(`${field}, rule ${i + 1}: ${issue}`);
    for (const [tool, of] of Object.entries(set.tools ?? {})) {
      const capability = capabilities.get(tool);
      if (!capability) issues.push(`${field}: ${tool} is not a capability this app implements`);
      else for (const [i, rule] of of.rules.entries()) for (const issue of ruleIssues(rule, { document: "app", root: false, inputs: capabilityInputSchema(capability) })) issues.push(`${field}, ${tool}, rule ${i + 1}: ${issue}`);
    }
  }
  if (app.outcomes && !httpsOrigin(app.outcomes.webhook)) issues.push("`outcomes.webhook` is not an https address");
  return issues;
}

const te = new TextEncoder();
const td = new TextDecoder();

/** §13.2 — the manifest as the vetter signs it: a compact EdDSA JWS, `typ: via-app+jwt`, `kid` the vetter's key. */
export function signAppManifest(app: ViaApp, signer: EventSigner): string {
  const header = { alg: "EdDSA", typ: APP_MANIFEST_TYP, kid: signer.verificationMethod };
  const signingInput = `${toBase64Url(te.encode(JSON.stringify(header)))}.${toBase64Url(te.encode(canonicalizeRFC8785(app)))}`;
  return `${signingInput}.${toBase64Url(signRaw(te.encode(signingInput), signer.privateKey))}`;
}

/**
 * §13.2 — read a signed manifest: its `typ`, a vetter this reader trusts, a key of that vetter's, and its signature.
 * A manifest from any other signer proves nothing, however well its signature verifies.
 */
export async function readAppManifest(
  token: unknown,
  opts: { resolvePublicKey: ResolvePublicKey; trustedVetters: readonly string[] },
): Promise<{ ok: true; app: ViaApp; digest: string } | { ok: false; reason: "manifest_invalid" | "vetter_untrusted" | "signature_invalid" }> {
  const parts = typeof token === "string" ? token.split(".") : [];
  if (parts.length !== 3) return { ok: false, reason: "manifest_invalid" };
  let header: { alg?: unknown; typ?: unknown; kid?: unknown };
  let app: ViaApp;
  try {
    header = JSON.parse(td.decode(fromBase64Url(parts[0]!)));
    app = JSON.parse(td.decode(fromBase64Url(parts[1]!)));
  } catch {
    return { ok: false, reason: "manifest_invalid" };
  }
  if (header.alg !== "EdDSA" || header.typ !== APP_MANIFEST_TYP || typeof header.kid !== "string" || app?.type !== "VIAApp") return { ok: false, reason: "manifest_invalid" };
  if (!opts.trustedVetters.includes(app.vettedBy) || !header.kid.startsWith(`${app.vettedBy}#`)) return { ok: false, reason: "vetter_untrusted" };
  try {
    if (!verifyRaw(te.encode(`${parts[0]}.${parts[1]}`), fromBase64Url(parts[2]!), await opts.resolvePublicKey(header.kid))) return { ok: false, reason: "signature_invalid" };
  } catch {
    return { ok: false, reason: "signature_invalid" };
  }
  return { ok: true, app, digest: appDigest(app) };
}
