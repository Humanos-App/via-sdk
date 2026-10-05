/**
 * Frozen wire-format fixtures — the backward-compat contract.
 *
 * Reads the committed, real artifacts under `test/fixtures/` (generated once by
 * `fixtures.generate.test.ts`) and verifies them with CURRENT code. If a change to
 * the builders / canonicalization / data model ever stops a shipped version's
 * artifacts from verifying, THIS fails — which is the whole point: already-issued
 * mandates must keep verifying forever (spec §13, VERSIONING.md, N40).
 *
 * Organized per (version × format); adding v0.3 later = drop `v0.3/` fixtures + a block.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  verify,
  verifyStamp,
  verifyEvent,
  walkEventChain,
  detectSpecVersion,
  type VerifyDeps,
  type VerifiablePresentation,
  type ViaMandateCredential,
  type ViaEvent,
} from "../src/index.js";
import type { ActionDetail } from "../src/action/types.js";

const read = <T>(rel: string): T =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`./fixtures/${rel}`, import.meta.url)), "utf8")) as T;

const keys = read<Record<string, string>>("keys.json");
const resolvePublicKey = (vm: string) => {
  const hex = keys[vm];
  if (!hex) throw new Error(`no key for ${vm}`);
  return new Uint8Array(Buffer.from(hex, "hex"));
};

const VERIFIER_DID = "did:web:fidelidade.pt";
const now = new Date("2026-06-01T00:00:00.000Z");

describe("frozen fixtures — v0.2", () => {
  const mandate = read<ViaMandateCredential>("v0.2/mandate.json");
  const presentation = read<VerifiablePresentation>("v0.2/presentation.json");
  const action = read<ActionDetail>("v0.2/action.json");
  const issueEvent = read<ViaEvent>("v0.2/event-issue.json");
  const acceptEvent = read<ViaEvent>("v0.2/event-accept.json");
  const verificationEvent = read<ViaEvent>("v0.2/event-verification.json");

  const deps: VerifyDeps = {
    verifier: { did: VERIFIER_DID },
    resolvePublicKey,
    loadCredentialRecord: async () => ({ status: "ACTIVE", validFrom: "2026-01-01T00:00:00.000Z" }),
    loadActionVersion: async (id) => (id === action.$id ? action : null),
    now,
  };

  it("mandate: the single securing STAMP still verifies; marker = 0.2", async () => {
    expect(detectSpecVersion(mandate)).toBe("0.2");
    expect(Array.isArray(mandate.proof)).toBe(false);
    expect(mandate.proof?.event).toBe("STAMP");
    expect((await verifyStamp(mandate, resolvePublicKey)).valid).toBe(true);
  });

  it("events: consent + operational VIAEvents verify and form an ordered chain", async () => {
    expect(issueEvent.credentialSubject.event).toBe("ISSUE");
    expect(acceptEvent.credentialSubject.event).toBe("ACCEPT");
    expect(verificationEvent.credentialSubject.event).toBe("VERIFICATION_APPROVED");
    // content-bound consents verify against the mandate body they committed to
    expect((await verifyEvent(issueEvent, resolvePublicKey, { credential: mandate })).valid).toBe(true);
    expect((await verifyEvent(acceptEvent, resolvePublicKey, { credential: mandate })).valid).toBe(true);
    // reference-bound operational event verifies on signature alone
    expect(verificationEvent.credentialSubject.credentialDigest).toBeUndefined();
    expect((await verifyEvent(verificationEvent, resolvePublicKey)).valid).toBe(true);
    // the whole chain is ordered
    expect((await walkEventChain([issueEvent, acceptEvent, verificationEvent])).ok).toBe(true);
  });

  it("presentation: verifies end to end → allow, format v0.2, specVersion 0.2", async () => {
    const r = await verify({ presentation, executionParams: { amount: 100 } }, deps);
    expect(r.decision).toBe("allow");
    expect(r.specVersion).toBe("0.2");
    expect(r.evaluations.find((e) => e.rule === "amt")?.result).toBe("pass");
  });

  it("presentation: tampering the embedded credential breaks verification", async () => {
    const tampered = { ...presentation, verifiableCredential: { ...presentation.verifiableCredential, issuer: "did:web:evil" } };
    const r = await verify({ presentation: tampered, executionParams: { amount: 100 } }, deps);
    expect(r.decision).toBe("deny");
  });

});

describe("frozen fixtures — v0.3 (§20: description, enforcement, and S13 applicability)", () => {
  const policy = read<ViaMandateCredential>("v0.3/mandate-rules.json");
  const semantic = read<ViaMandateCredential>("v0.3/mandate-semantic.json");
  const presentation = read<VerifiablePresentation>("v0.3/presentation.json");
  const action = read<ActionDetail>("v0.3/action.json");
  const issueEvent = read<ViaEvent>("v0.3/event-issue.json");
  const acceptEvent = read<ViaEvent>("v0.3/event-accept.json");
  const verificationEvent = read<ViaEvent>("v0.3/event-verification.json");
  const v03Now = new Date("2026-09-25T00:00:00.000Z");

  const deps: VerifyDeps = {
    verifier: { did: VERIFIER_DID },
    resolvePublicKey,
    loadCredentialRecord: async () => ({ status: "ACTIVE", validFrom: "2026-09-22T10:00:00.000Z" }),
    loadActionVersion: async (id) => (id === action.$id ? action : null),
    now: v03Now,
  };
  const m = (c: ViaMandateCredential) => c.credentialSubject.mandate;

  it("a policy mandate carries derived words, the machinery that governs, and who asked", () => {
    expect(m(policy).description).toMatchObject({ author: "issuer", lang: "en" });
    expect(m(policy).enforcement).toBe("rules");
    expect(m(policy).initiator?.actor).toContain(":agent:");
    expect(m(policy).action?.version).toBe(5);
  });

  it("the words are content-bound: one edited character breaks the STAMP", async () => {
    expect((await verifyStamp(policy, resolvePublicKey)).valid).toBe(true);
    const tampered = structuredClone(policy);
    tampered.credentialSubject.mandate.description!.text += " And post anywhere else too.";
    expect((await verifyStamp(tampered, resolvePublicKey)).valid).toBe(false);
  });

  it("presentation: a governed call naming an allowed channel verifies → allow", async () => {
    const r = await verify(
      { presentation, executionParams: { tool: "slack_send_message", channel_id: "C0BVB1KBPG8" } },
      deps,
    );
    expect(r).toMatchObject({ decision: "allow", enforcement: "rules" });
  });

  // S13, frozen: the guard this replaces (`!has(executionParams.channel_id) || …`) answered ALLOW
  // here, which is how a person's channel allowlist bound only the calls that volunteered one.
  it("presentation: a governed call that omits the parameter is DENIED, not skipped", async () => {
    const r = await verify({ presentation, executionParams: { tool: "slack_send_message" } }, deps);
    expect(r).toMatchObject({ decision: "deny", reason: "required_param_missing" });
  });

  it("presentation: a call outside the rule's tools records it as skipped and proceeds", async () => {
    const r = await verify(
      { presentation, executionParams: { tool: "slack_read_channel", channel_id: "C0BVB1KBPG8" } },
      deps,
    );
    expect(r.decision).toBe("allow");
    const other = await verify({ presentation, executionParams: { tool: "slack_read_channel" } }, deps);
    expect(other.decision).toBe("deny"); // slack_read_channel IS governed by the channel rule
  });

  it("a semantic mandate declares the critical extension and its words are the grantor's", async () => {
    expect((await verifyStamp(semantic, resolvePublicKey)).valid).toBe(true);
    expect(m(semantic).enforcement).toBe("semantic");
    expect(m(semantic).extensions).toContain("semanticReview");
    expect(m(semantic).description).toMatchObject({ author: "grantor", proposedBy: { adopted: true } });
    expect(m(semantic).stepUp).toMatchObject({ triggers: ["verifier"] });
  });

  // @invariant §20.6 / §19.2 — the custodial VP path has no reviewer to consult, and a mandate whose
  // enforcement IS a reader must not be verified by not reading. The mandate signs `semanticReview` as
  // critical, so the refusal is the generic one, before any reviewer would be looked for.
  it("the VP path fails closed on a semantic mandate rather than allowing it", async () => {
    const vp = read<VerifiablePresentation>("v0.3/presentation-semantic.json");
    const r = await verify({ presentation: vp, executionParams: {} }, deps);
    expect(r).toMatchObject({ decision: "deny", reason: "extension_unsupported" });
  });

  it("events verify, chain, and record who demanded the co-sign and which reader ran", async () => {
    expect((await verifyEvent(issueEvent, resolvePublicKey, { credential: policy })).valid).toBe(true);
    expect((await verifyEvent(acceptEvent, resolvePublicKey, { credential: policy })).valid).toBe(true);
    expect((await verifyEvent(verificationEvent, resolvePublicKey)).valid).toBe(true);
    expect((await walkEventChain([issueEvent, acceptEvent, verificationEvent])).ok).toBe(true);
    expect(verificationEvent.credentialSubject.stepUp).toMatchObject({
      trigger: "verifier",
      reason: "semantic_review",
      reviewer: { id: "reys", version: "2026-09-14" },
    });
  });
});

