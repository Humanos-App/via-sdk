import { describe, it, expect, beforeAll } from "vitest";
import {
  generateEd25519Key,
  generateViaDID,
  VIA_PLATFORM_DID,
  buildActionVersion,
  buildActionReference,
  wrapUserParamsWithAction,
  buildMandate,
  buildSdJwtMandate,
  presentSdJwt,
  verifySdJwtPresentation,
  SD_JWT_TYP,
  type Ed25519KeyPair,
  type ViaMandateCredential,
} from "../src/index.js";
import { fromBase64Url, fromUtf8 } from "../src/crypto/encoding.js";

let issuer: Ed25519KeyPair, holder: Ed25519KeyPair;
let credential: ViaMandateCredential;
let sdJwt: string;

beforeAll(async () => {
  issuer = generateEd25519Key();
  holder = generateEd25519Key();
  const orgDid = generateViaDID("org", { uuid: "o" });
  const userDid = generateViaDID("user", { uuid: "u" });

  const action = buildActionVersion({
    $id: "urn:via:action:a1",
    version: "1",
    userParams: {
      maxAmount: { type: "number", required: true, description: "cap" },
      secretNote: { type: "string", required: false, description: "private" },
    },
    executionParams: { amount: { type: "number", required: true } },
    rules: [{ name: "amt", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }] }],
  });

  credential = buildMandate({
    subjectOrg: orgDid,
    grantor: userDid,
    authorizedDIDs: ["did:web:verifier.example"],
    action: buildActionReference(action, "https://api.humanos.tech/actions/a1"),
    userParams: wrapUserParamsWithAction(action, { maxAmount: 500, secretNote: "do-not-reveal" }),
    validFrom: "2026-01-01T00:00:00.000Z",
    description: { text: "Act within the pinned action.", lang: "en", author: "issuer" },
    enforcement: "rules",
  });

  sdJwt = await buildSdJwtMandate({
    credential,
    issuerPrivateKey: issuer.privateKey,
    issuerVerificationMethod: `${VIA_PLATFORM_DID}#key-1`,
    holderPublicKey: holder.publicKey,
  });
});

describe("SD-JWT VC presentation (D-f)", () => {
  it("issues a dc+sd-jwt with disclosures", () => {
    const header = JSON.parse(fromUtf8(fromBase64Url(sdJwt.split(".")[0]!))) as Record<string, unknown>;
    expect(header.typ).toBe(SD_JWT_TYP);
    expect(header.alg).toBe("EdDSA");
    expect(sdJwt.split("~").length).toBeGreaterThan(1); // has disclosures
  });

  it("discloses only the requested userParam; verifies with key binding", async () => {
    const presentation = await presentSdJwt({
      sdJwt,
      holderPrivateKey: holder.privateKey,
      disclose: { userParams: ["maxAmount"] }, // reveal maxAmount, hide secretNote
      audience: "did:web:verifier.example",
      nonce: "n-1",
    });
    const result = await verifySdJwtPresentation({
      presentation,
      issuerPublicKey: issuer.publicKey,
      nonce: "n-1",
      audience: "did:web:verifier.example",
    });
    expect(result.valid).toBe(true);
    expect(result.nonce).toBe("n-1");
    const mandate = (result.claims.credentialSubject as { mandate: { userParams?: Record<string, unknown>; action?: unknown } }).mandate;
    expect(mandate.userParams?.maxAmount).toBeDefined(); // disclosed
    expect(mandate.userParams?.secretNote).toBeUndefined(); // withheld
    expect(mandate.action).toBeDefined(); // always present
  });

  it("rejects a replayed/wrong nonce", async () => {
    const presentation = await presentSdJwt({
      sdJwt,
      holderPrivateKey: holder.privateKey,
      disclose: { userParams: ["maxAmount"] },
      audience: "did:web:verifier.example",
      nonce: "good",
    });
    await expect(
      verifySdJwtPresentation({ presentation, issuerPublicKey: issuer.publicKey, nonce: "wrong" }),
    ).rejects.toThrow();
  });

  /**
   * The guard this pins came from the platform's dev line, where it lived only in the VENDORED copy
   * — which carries no tests, and which `sync-via-sdk` overwrites wholesale. It was one sync away
   * from disappearing. The test is the point: an empty nonce must not reach the underlying verifier,
   * because that library reads "" as opting OUT of key binding, and the presentation would then
   * verify without the holder having proven anything at all.
   */
  it("refuses an empty or missing nonce instead of passing it down as 'no key binding'", async () => {
    const presentation = await presentSdJwt({
      sdJwt,
      holderPrivateKey: holder.privateKey,
      disclose: { userParams: ["maxAmount"] },
      audience: "did:web:verifier.example",
      nonce: "n-3",
    });
    await expect(
      verifySdJwtPresentation({ presentation, issuerPublicKey: issuer.publicKey, nonce: "" }),
    ).rejects.toThrow(/non-empty nonce/);
    await expect(
      verifySdJwtPresentation({ presentation, issuerPublicKey: issuer.publicKey, nonce: undefined as unknown as string }),
    ).rejects.toThrow(/non-empty nonce/);
    // …and the same presentation still verifies with the nonce it was actually made for.
    await expect(
      verifySdJwtPresentation({ presentation, issuerPublicKey: issuer.publicKey, nonce: "n-3", audience: "did:web:verifier.example" }),
    ).resolves.toMatchObject({ valid: true, nonce: "n-3" });
  });

  it("rejects a wrong issuer key", async () => {
    const presentation = await presentSdJwt({
      sdJwt,
      holderPrivateKey: holder.privateKey,
      disclose: { userParams: ["maxAmount"] },
      audience: "did:web:verifier.example",
      nonce: "n-2",
    });
    const wrong = generateEd25519Key();
    await expect(
      verifySdJwtPresentation({ presentation, issuerPublicKey: wrong.publicKey, nonce: "n-2" }),
    ).rejects.toThrow();
  });
});
