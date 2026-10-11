import { describe, it, expect } from "vitest";
import {
  generateViaDID,
  generateDomainDID,
  parseDidWeb,
  didWebToUrl,
  verifierDomainOf,
  VIA_PLATFORM_DID,
} from "../src/did/web.js";
import { buildDidDocument, isAuthorizedFor, resolveVerificationJwk, resolveVerificationKey } from "../src/did/document.js";
import { generateEd25519Key } from "../src/crypto/ed25519.js";
import { buildActionVersion, actionDigestSRI, verifyActionReference } from "../src/action/build.js";
import { validateExecutionParams, validateUserParams, unwrapUserParamValues } from "../src/action/execution-params.js";
import { evaluateRules } from "../src/cel/evaluate.js";

describe("did:web", () => {
  it("generates platform + graduated DIDs", () => {
    expect(VIA_PLATFORM_DID).toBe("did:web:humanos.tech");
    const org = generateViaDID("org", { uuid: "u1" });
    expect(org).toBe("did:web:humanos.tech:org:u1");
    expect(generateDomainDID("HTTPS://www.Fidelidade.pt/").did).toBe("did:web:fidelidade.pt");
    // `agent` joined the union in v0.3 (§16.1, §16.14) — it used to throw here. Something outside
    // the union still does; see did-web.test.ts for the shape and the parse round-trip.
    expect(generateViaDID("agent", { uuid: "a1" })).toBe("did:web:humanos.tech:agent:a1");
    expect(() => generateViaDID("robot" as never)).toThrow();
  });
  it("parses + resolves URLs + verifier domain", () => {
    expect(parseDidWeb("did:web:humanos.tech:user:abc")).toMatchObject({ actorType: "user", id: "abc" });
    expect(didWebToUrl("did:web:humanos.tech:org:abc")).toBe("https://humanos.tech/org/abc/did.json");
    expect(didWebToUrl("did:web:fidelidade.pt")).toBe("https://fidelidade.pt/.well-known/did.json");
    expect(verifierDomainOf("did:web:fidelidade.pt")).toBe("fidelidade.pt");
  });
  it("builds a Multikey DID document authorized for both purposes", () => {
    const k = generateEd25519Key();
    const did = generateViaDID("org", { uuid: "u1" });
    const doc = buildDidDocument({ did, publicKey: k.publicKey });
    const vm = doc.verificationMethod[0]!;
    expect(vm.type).toBe("Multikey");
    expect(vm.type === "Multikey" && vm.publicKeyMultibase.startsWith("z6Mk")).toBe(true);
    expect(doc["@context"]).toContain("https://w3id.org/security/multikey/v1");
    expect(doc["@context"]).not.toContain("https://w3id.org/security/jwk/v1");
    expect(isAuthorizedFor(doc, `${did}#key-1`, "assertionMethod")).toBe(true);
    expect(isAuthorizedFor(doc, `${did}#key-1`, "authentication")).toBe(true);
  });

  // v0.3 §16.2: an agent's P-256 key is published as `JsonWebKey` + `publicKeyJwk`; a reader also
  // takes `JsonWebKey2020`, the older name documents used before 2026-10-11.
  it("builds and reads an agent's key as JsonWebKey, and still reads JsonWebKey2020", () => {
    const jwk = { kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" };
    const did = generateViaDID("agent", { uuid: "a1" });
    const doc = buildDidDocument({ did, publicKeyJwk: { ...jwk, d: "secret-must-not-leak" } });
    const vm = doc.verificationMethod[0]!;
    expect(vm.type).toBe("JsonWebKey");
    expect(vm.type !== "Multikey" && vm.publicKeyJwk).toEqual(jwk);
    // v0.3 §0.3.3: the context that defines JsonWebKey, or a JSON-LD processor drops the key.
    expect(doc["@context"]).toContain("https://w3id.org/security/jwk/v1");
    expect(resolveVerificationJwk(doc, `${did}#key-1`, "assertionMethod")).toEqual(jwk);
    expect(() => resolveVerificationKey(doc, `${did}#key-1`)).toThrow(/resolveVerificationJwk/);

    const older = { ...doc, verificationMethod: [{ id: vm.id, controller: vm.controller, type: "JsonWebKey2020" as const, publicKeyJwk: jwk }] };
    expect(resolveVerificationJwk(older, `${did}#key-1`)).toEqual(jwk);
  });

  // v0.3 §0.3.3: W3C's verifier rejects a method whose controller is not the document's own DID.
  it("names the DID itself as every key's controller, even when another party controls the document", () => {
    const k = generateEd25519Key();
    const did = generateViaDID("org", { uuid: "u3" });
    const doc = buildDidDocument({ did, publicKey: k.publicKey, controller: "did:web:humanos.tech" });
    expect(doc.verificationMethod[0]!.controller).toBe(did);
    expect(doc.controller).toBe("did:web:humanos.tech");
  });

  it("builds a key from exactly one of an Ed25519 key and a JWK", () => {
    const did = generateViaDID("org", { uuid: "u2" });
    expect(() => buildDidDocument({ did })).toThrow(/exactly one/);
  });
});

const content = buildActionVersion({
  $id: "urn:via:action:pay-1",
  version: "1",
  userParams: {
    maxAmount: { type: "number", required: true, description: "cap" },
    categories: { type: "array", items: "string", required: true },
    deadline: { type: "datetime", required: false },
  },
  executionParams: {
    amount: { type: "number", required: true, description: "txn amount" },
    category: { type: "string", required: true },
    when: { type: "datetime", required: false },
  },
  rules: [
    { name: "amount_limit", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }] },
    { name: "category_in", conditions: [{ left: "executionParams.category", operator: "in", right: "userParams.categories" }] },
    { name: "deadline", conditions: [{ left: "executionParams.when", operator: "<=", right: "userParams.deadline" }] },
  ],
});

describe("action build + CEL generation (N13)", () => {
  it("generates expressions verbatim", () => {
    const byName = Object.fromEntries(content.rules.map((r) => [r.name, r.expression]));
    expect(byName.amount_limit).toBe("executionParams.amount <= userParams.maxAmount");
    expect(byName.category_in).toBe("executionParams.category in userParams.categories");
    expect(byName.deadline).toBe("timestamp(executionParams.when) <= timestamp(userParams.deadline)");
  });
  it("digest is stable and verifies against a pinned reference", () => {
    const sri = actionDigestSRI(content);
    expect(sri.startsWith("sha256-")).toBe(true);
    expect(verifyActionReference(content, { id: content.$id, digestSRI: sri })).toBe(true);
    expect(verifyActionReference(content, { id: content.$id, digestSRI: "sha256-bogus" })).toBe(false);
  });
});

describe("executionParams validation (N28/N29)", () => {
  it("accepts valid; rejects wrong types", () => {
    expect(() => validateExecutionParams(content, { amount: 100, category: "books" })).not.toThrow();
    expect(() => validateExecutionParams(content, { amount: "lots", category: "books" })).toThrow(/must be a number/);
    expect(() => validateExecutionParams(content, { category: "books" })).toThrow(/required/);
  });
  it("treats 0 as present (N28 — not falsy-missing)", () => {
    expect(() => validateExecutionParams(content, { amount: 0, category: "books" })).not.toThrow();
  });
  it("validates datetime (N29)", () => {
    expect(() => validateExecutionParams(content, { amount: 1, category: "x", when: "2026-06-23T00:00:00Z" })).not.toThrow();
    expect(() => validateExecutionParams(content, { amount: 1, category: "x", when: "not-a-date" })).toThrow(/datetime/);
  });
});

describe("userParams validation + unwrap (platform-consumed)", () => {
  it("validateUserParams: valid ok; wrong type → User-kind message; N28 0 ok; required + N29 datetime", () => {
    expect(() => validateUserParams(content, { maxAmount: 100, categories: ["books"] })).not.toThrow();
    expect(() => validateUserParams(content, { maxAmount: "lots", categories: ["books"] })).toThrow(/User param 'maxAmount' must be a number/);
    expect(() => validateUserParams(content, { maxAmount: 0, categories: ["books"] })).not.toThrow(); // N28
    expect(() => validateUserParams(content, { categories: ["books"] })).toThrow(/User param 'maxAmount' is required/);
    expect(() => validateUserParams(content, { maxAmount: 1, categories: ["books"], deadline: "not-a-date" })).toThrow(/datetime/); // N29
  });

  it("unwrapUserParamValues: strips {description,value}, keeps 0/false, passes flat + arrays through, tolerates null", () => {
    expect(unwrapUserParamValues({ maxAmount: { description: "cap", value: 2500 }, flat: 5 })).toEqual({ maxAmount: 2500, flat: 5 });
    expect(unwrapUserParamValues({ zero: { description: "", value: 0 }, off: { description: "", value: false } })).toEqual({ zero: 0, off: false });
    expect(unwrapUserParamValues({ arr: [1, 2] })).toEqual({ arr: [1, 2] }); // arrays are not {description,value} envelopes
    expect(unwrapUserParamValues(null)).toEqual({});
    expect(unwrapUserParamValues(undefined)).toEqual({});
  });
});

describe("CEL evaluation", () => {
  const userParams = { maxAmount: 500, categories: ["books", "food"] };
  it("allows compliant, denies over-limit and disallowed category", () => {
    const ruleSubset = content.rules.filter((r) => r.name !== "deadline"); // skip datetime here
    expect(evaluateRules(ruleSubset, { userParams, executionParams: { amount: 100, category: "books" } }).decision).toBe("allow");
    const over = evaluateRules(ruleSubset, { userParams, executionParams: { amount: 999, category: "books" } });
    expect(over.decision).toBe("deny");
    expect(over.evaluations.find((e) => e.rule === "amount_limit")?.result).toBe("fail");
    const cat = evaluateRules(ruleSubset, { userParams, executionParams: { amount: 1, category: "weapons" } });
    expect(cat.evaluations.find((e) => e.rule === "category_in")?.result).toBe("fail");
  });
});
