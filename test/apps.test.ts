/** v0.4 §13 — capabilities and apps: a capability's versions, a call of one, and an app's signed manifest. */
import { describe, expect, it } from "vitest";
import {
  appDigest,
  appManifestIssues,
  buildRule,
  capabilityDefinition,
  capabilityDigest,
  capabilityFillIssues,
  capabilityInputSchema,
  capabilityIssues,
  capabilityVersionIssues,
  decideLimits,
  generateEd25519Key,
  limitsPolicyPublishIssues,
  mandateLimitsIssues,
  readAppManifest,
  signAppManifest,
  type LimitsPolicy,
  type ViaApp,
  type ViaCapability,
} from "../src/index.js";

const SEND_V1: ViaCapability = {
  $id: "urn:via:capability:wallet.send",
  type: "VIACapability",
  name: "wallet.send",
  version: 1,
  description: "Send native tokens or a fungible token from a wallet to an address",
  params: {
    wallet_id: { type: "string", required: true },
    to: { type: "string", required: true },
    asset: { type: "string", required: true },
    amount: { type: "string", format: "decimal", required: true },
    idempotency_key: { type: "string", required: true },
  },
  result: { status: { enum: ["pending", "submitted", "succeeded", "failed"] }, tx_hash: { type: "string" } },
};
const SEND_V2: ViaCapability = { ...SEND_V1, version: 2, params: { ...SEND_V1.params, memo: { type: "string" } } };
const ACCEPT: ViaCapability = {
  $id: "urn:via:capability:credit.accept",
  type: "VIACapability",
  name: "credit.accept",
  version: 1,
  description: "Accept a loan offer",
  params: { offer_id: { type: "string", required: true }, borrower_contact: { type: "string", personalData: "person.email", required: true }, note: { type: "string", personalData: ["person.name"] } },
};
const PUBLISHED = [SEND_V1, SEND_V2, ACCEPT];
const capability = (name: string, version: number) => PUBLISHED.find((c) => c.name === name && c.version === version) ?? null;
const ANA = "did:web:humanos.tech:user:ana";
const ctx = { definition: () => null, isMember: () => true, capability };
const agent = { did: "did:web:humanos.tech:agent:treasury" };

const policy = (): LimitsPolicy => ({
  $id: "urn:via:policy:acme",
  type: "VIAPolicy",
  specVersion: "0.4",
  version: 2,
  default: "deny",
  tools: {
    "wallet.send": {
      effect: "allow",
      version: 1,
      hash: capabilityDigest(SEND_V1),
      rules: [buildRule([{ left: "asset", operator: "==", value: "usdc" }], capabilityInputSchema(SEND_V1)), buildRule([{ left: "amount", operator: "<=", value: "500" }], capabilityInputSchema(SEND_V1))],
    },
  },
});
const call = { wallet_id: "w1", to: "0xabc", asset: "usdc", amount: "12.50", idempotency_key: "k1" };

describe("a capability (§13.1)", () => {
  it("is pinned by the digest of its whole form", () => {
    expect(capabilityIssues(SEND_V1)).toEqual([]);
    expect(capabilityDigest(SEND_V1)).toMatch(/^sha256-/);
    expect(capabilityDigest({ ...SEND_V1, description: "Send tokens" })).not.toBe(capabilityDigest(SEND_V1));
    expect(capabilityDefinition(SEND_V1).inputSchema).toMatchObject({ properties: { amount: { type: "string", format: "decimal" } }, required: ["amount", "asset", "idempotency_key", "to", "wallet_id"] });
  });

  it("has a neutral name, and a decimal that is a string on the wire", () => {
    expect(capabilityIssues({ ...SEND_V1, name: "humanos/wallet_send", $id: "urn:via:capability:humanos/wallet_send" }).join()).toMatch(/neutral dotted name/);
    expect(capabilityIssues({ ...SEND_V1, params: { amount: { type: "number", format: "decimal" } } }).join()).toMatch(/a decimal is a string/);
    expect(capabilityIssues({ ...ACCEPT, params: { x: { type: "string", personalData: "person.shoe_size" } } }).join()).toMatch(/is no kind/);
  });

  // @invariant §13.1: a version only adds optional parameters; a parameter never changes meaning.
  it("takes as a new version only one that adds optional parameters", () => {
    expect(capabilityVersionIssues(SEND_V1, SEND_V2)).toEqual([]);
    expect(capabilityVersionIssues(SEND_V1, { ...SEND_V2, params: { ...SEND_V1.params, memo: { type: "string", required: true } } }).join()).toMatch(/new and required/);
    expect(capabilityVersionIssues(SEND_V1, { ...SEND_V2, params: { ...SEND_V2.params, amount: { type: "number" } } }).join()).toMatch(/amount changed/);
    const { asset: _asset, ...without } = SEND_V2.params;
    expect(capabilityVersionIssues(SEND_V1, { ...SEND_V2, params: without }).join()).toMatch(/asset was removed/);
    expect(capabilityVersionIssues(SEND_V1, { ...SEND_V2, version: 5 }).join()).toMatch(/the version after 1 is 2/);
  });
});

describe("a capability in a policy and a mandate (§15.3)", () => {
  it("is named by its name, with the version a member approved and that version's digest", () => {
    expect(limitsPolicyPublishIssues(policy(), ctx)).toEqual([]);
    const p = policy();
    delete p.tools["wallet.send"]!.version;
    expect(limitsPolicyPublishIssues(p, ctx).join()).toMatch(/names the `version` a member approved/);
    p.tools["wallet.send"]!.version = 1;
    p.tools["wallet.send"]!.hash = capabilityDigest(SEND_V2);
    expect(limitsPolicyPublishIssues(p, ctx).join()).toMatch(/is not its definition's/);
    p.tools["wallet.send"]!.version = 9;
    expect(limitsPolicyPublishIssues(p, ctx).join()).toMatch(/no definition is on record/);
    const limits = {
      description: { text: "Send 12.50 USDC to the supplier", lang: "en", author: "agent" as const },
      maxExecutions: 1,
      tools: { "wallet.send": { version: 1, hash: capabilityDigest(SEND_V1), rules: [buildRule([{ left: "amount", operator: "<=", value: "12.50" }], capabilityInputSchema(SEND_V1))] } },
    };
    expect(mandateLimitsIssues(limits, ctx)).toEqual([]);
  });

  // @invariant §14.3: on a capability `fill` names no kind the parameter does not carry; it may name fewer.
  it("lets `fill` narrow what a capability's parameter carries, never widen it", () => {
    expect(capabilityFillIssues({ borrower_contact: "person.email" }, ACCEPT)).toEqual([]);
    expect(capabilityFillIssues({ borrower_contact: "person.phone" }, ACCEPT).join()).toMatch(/does not carry person\.phone/);
    expect(capabilityFillIssues({ offer_id: "person.email" }, ACCEPT).join()).toMatch(/offer_id does not carry/);
    const p = policy();
    p.tools["credit.accept"] = { effect: "mandate", version: 1, hash: capabilityDigest(ACCEPT), grantors: "any", fill: { note: "person.email" } };
    expect(limitsPolicyPublishIssues(p, ctx).join()).toMatch(/credit\.accept's note does not carry person\.email/);
  });

  // @invariant §13.1, §15.3: a new version runs at once, and its new parameters stay closed until a member adopts it.
  it("runs a call made from a newer version, and keeps the newer version's parameter closed", async () => {
    const subject = { capability: { approved: SEND_V1, published: [SEND_V1, SEND_V2].map(capabilityDigest) } };
    const send = (params: Record<string, unknown>, madeFrom: string) => decideLimits(policy(), { tool: "wallet.send", params, agent, madeFrom, ...subject }, undefined);
    expect(await send(call, capabilityDigest(SEND_V1))).toMatchObject({ outcome: "allow" });
    expect(await send(call, capabilityDigest(SEND_V2))).toMatchObject({ outcome: "allow" }); // the current version
    expect(await send({ ...call, memo: "invoice 7" }, capabilityDigest(SEND_V2))).toMatchObject({ outcome: "deny", reason: "param_undeclared", input: "memo" });
    expect(await send(call, "sha256-someone-elses")).toMatchObject({ outcome: "deny", reason: "tool_changed" });
    // The amount is exact, in its asset: two rules.
    expect(await send({ ...call, amount: "500.01" }, capabilityDigest(SEND_V1))).toMatchObject({ outcome: "deny", reason: "policy_denied" });
    expect(await send({ ...call, asset: "eth" }, capabilityDigest(SEND_V1))).toMatchObject({ outcome: "deny", reason: "policy_denied" });
  });
});

describe("an app's manifest (§13.2)", () => {
  const HUMANOS = generateEd25519Key();
  const VETTER = "did:web:humanos.tech";
  const signer = { privateKey: HUMANOS.privateKey, verificationMethod: `${VETTER}#key-1` };
  const wallets = (): ViaApp => ({
    $id: "urn:via:app:5f0c",
    type: "VIAApp",
    name: "crossmint-wallets",
    version: 3,
    publisher: VETTER,
    service: { name: "Crossmint", id: "https://www.crossmint.com", transport: "adapter", endpoint: "https://www.crossmint.com/api", processing: ["US"] },
    tools: { implements: [{ capability: "wallet.send", version: 1, digestSRI: capabilityDigest(SEND_V1), regions: ["US", "EU"] }], custody: "developer_secret", credentials: ["humanos", "customer"] },
    suggestedRules: { tools: { "wallet.send": { rules: [buildRule([{ left: "amount", operator: "<=", value: "500" }], capabilityInputSchema(SEND_V1))] } } },
    domains: ["crossmint.com"],
    vettedBy: VETTER,
    iat: 1793491200,
  });
  const openrouter = (): ViaApp => ({
    $id: "urn:via:app:a1b2",
    type: "VIAApp",
    name: "openrouter",
    version: 1,
    publisher: VETTER,
    service: { name: "OpenRouter", id: "https://openrouter.ai", transport: "http", endpoint: "https://openrouter.ai/api/v1" },
    models: { api: ["openai-chat"], models: ["anthropic/*", "openai/*"] },
    vettedBy: VETTER,
    iat: 1793491200,
  });
  const mctx = { capability };

  it("accepts a wallet app and a model app", () => {
    expect(appManifestIssues(wallets(), mctx)).toEqual([]);
    expect(appManifestIssues(openrouter(), mctx)).toEqual([]);
    expect(appDigest(wallets())).not.toBe(appDigest({ ...wallets(), version: 4 }));
  });

  it("refuses an endpoint that is not https, a capability it pins wrongly, and tools with no suggested rules", () => {
    const http = wallets();
    http.service!.endpoint = "http://crossmint.example/api";
    expect(appManifestIssues(http, mctx).join()).toMatch(/not an https address/);
    const wrong = wallets();
    wrong.tools!.implements[0]!.digestSRI = capabilityDigest(SEND_V2);
    expect(appManifestIssues(wrong, mctx).join()).toMatch(/is not that version's/);
    const { suggestedRules: _s, ...bare } = wallets();
    expect(appManifestIssues(bare as ViaApp, mctx).join()).toMatch(/ships `suggestedRules`/);
    const { service: _v, ...unreachable } = openrouter();
    expect(appManifestIssues(unreachable as ViaApp, mctx).join()).toMatch(/names its `service`/);
    const loose = wallets();
    loose.suggestedRules = { tools: { "wallet.send": { rules: [{ conditions: [{ left: "memo", operator: "==", value: "x" }], expression: "true" }] } } };
    expect(appManifestIssues(loose, mctx).join()).toMatch(/declares no such input/);
  });

  // @invariant §13.2: a manifest is signed by the vetter, and one from any other signer proves nothing.
  it("is read only when a trusted vetter signed it", async () => {
    const token = signAppManifest(wallets(), signer);
    const read = (t: unknown, trustedVetters = [VETTER], key = HUMANOS.publicKey) => readAppManifest(t, { resolvePublicKey: () => key, trustedVetters });
    expect(await read(token)).toMatchObject({ ok: true, app: { name: "crossmint-wallets" }, digest: appDigest(wallets()) });
    expect(await read(token, ["did:web:other.example"])).toEqual({ ok: false, reason: "vetter_untrusted" });
    expect(await read(token, [VETTER], generateEd25519Key().publicKey)).toEqual({ ok: false, reason: "signature_invalid" });
    const [h, p, s] = token.split(".");
    const edited = Buffer.from(JSON.stringify({ ...wallets(), service: { ...wallets().service, endpoint: "https://evil.example" } })).toString("base64url");
    expect(await read(`${h}.${edited}.${s}`)).toEqual({ ok: false, reason: "signature_invalid" });
    expect(await read(`${h}.${p}`)).toEqual({ ok: false, reason: "manifest_invalid" });
    // A key of another DID cannot sign as the vetter.
    const foreign = signAppManifest(wallets(), { privateKey: HUMANOS.privateKey, verificationMethod: "did:web:other.example#key-1" });
    expect(await read(foreign)).toEqual({ ok: false, reason: "vetter_untrusted" });
  });
});
