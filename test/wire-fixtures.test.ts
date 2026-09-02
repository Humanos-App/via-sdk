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

