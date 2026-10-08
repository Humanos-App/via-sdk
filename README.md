# @humanos/via-sdk

Functions-only TypeScript SDK for the **VIA Protocol** — create and verify VIA
mandates, DIDs, actions, presentations, and receipts. Implements
[`spec/via-protocol-spec-v0.2.md`](../spec/via-protocol-spec-v0.2.md):
Ed25519 / `eddsa-jcs-2022` / W3C VC 2.0.

> **Functions-only.** No HTTP, DB, KMS, or network. All I/O — DID-document
> fetching, key decryption, status reads, persistence — is **injected** by the
> caller. See [`DESIGN.md`](./DESIGN.md).

## Install

```bash
npm install @humanos/via-sdk
```

## Quickstart — issue → present → verify

```ts
import {
  generateEd25519Key, generateViaDID, VIA_PLATFORM_DID,
  buildActionVersion, buildActionReference, wrapUserParamsWithAction,
  buildMandate, addProof, buildPresentation, verify,
} from "@humanos/via-sdk";

// keys (the platform decrypts these from KMS and passes raw bytes)
const platform = generateEd25519Key(), org = generateEd25519Key(), user = generateEd25519Key();
const orgDid = generateViaDID("org"), userDid = generateViaDID("user");
const vm = (d: string) => `${d}#key-1`;

// an Action: CEL rules + the param shapes it evaluates
const action = buildActionVersion({
  $id: "urn:via:action:pay-1", version: "1",
  userParams: { maxAmount: { type: "number", required: true, description: "cap" } },
  executionParams: { amount: { type: "number", required: true } },
  rules: [{ name: "amount", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }] }],
});

// build + sign a mandate (proof set: ISSUE → ACCEPT → STAMP)
let mandate = buildMandate({
  subjectOrg: orgDid, grantor: userDid, authorizedDIDs: ["did:web:fidelidade.pt"],
  action: buildActionReference(action, "https://api.humanos.tech/actions/pay-1"),
  userParams: wrapUserParamsWithAction(action, { maxAmount: 2500 }),
  validFrom: "2026-01-01T00:00:00.000Z",
});
mandate = addProof(mandate, { privateKey: org.privateKey, verificationMethod: vm(orgDid), lifecycleAction: "ISSUE" });
mandate = addProof(mandate, { privateKey: user.privateKey, verificationMethod: vm(userDid), lifecycleAction: "ACCEPT" });
mandate = addProof(mandate, { privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID), lifecycleAction: "STAMP" });

// present (Humanos-signed VP) and verify
const vp = buildPresentation({ credential: mandate, holder: VIA_PLATFORM_DID, privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) });
const result = await verify({ presentation: vp, executionParams: { amount: 1200 } }, {
  verifier: { did: "did:web:fidelidade.pt" },
  resolvePublicKey: async () => platform.publicKey,           // resolve VP signer key
  loadCredentialRecord: async () => ({ status: "ACTIVE", validFrom: "2026-01-01T00:00:00.000Z" }),
  loadActionVersion: async (id) => (id === action.$id ? action : null),
});
// → { decision: "allow", evaluations: [{ rule: "amount", result: "pass" }], ... }
```

A complete runnable script: [`examples/healthcare-claims.ts`](../examples/healthcare-claims.ts) (`npm run example:claims`). Sample artifacts: `npm run samples`.

## API reference

### Keys & crypto
| Function | Notes |
|---|---|
| `generateEd25519Key()` → `{ publicKey, privateKey }` | raw 32-byte Ed25519 |
| `publicKeyFromPrivate(priv)` | derive public from a stored private seed |
| `signRaw` / `signMultibase` / `verifyRaw` / `verifyMultibase` | Ed25519 (raw 64-byte / multibase `z…`) |
| `encodePublicKeyMultibase` / `decodePublicKeyMultibase` | Multikey (`z6Mk…`, multicodec `0xed01`) |
| `sha256` / `sha256Hex` / `computeSRI` / `verifySRI` | SRI = `sha256-<base64>` (v0.2) |
| `canonicalizeRFC8785` / `canonicalizeLegacy` / `canonicalize(value, mode)` | JCS |
| `createDataIntegrityProof(params)` / `verifyDataIntegrityProof(doc, proof, pub)` | real `eddsa-jcs-2022` |
| `base58Encode/Decode`, `toBase64(Url)/from…` | encoders |

### DIDs
| Function | Notes |
|---|---|
| `generateViaDID("org" \| "user", { uuid?, domain? })` | `did:web:humanos.tech:{org\|user}:{uuid}` |
| `generateDomainDID(domain)` → `{ domain, did }` | graduated `did:web:{domain}` |
| `buildDidDocument({ did, publicKey, keyFragment?, controller? })` | Multikey doc, both proof purposes |
| `resolveVerificationKey(doc, vmId, purpose?)` | DID doc → raw public key |
| `findVerificationMethod` / `isAuthorizedFor` | doc lookups |
| `didWebToUrl` / `parseDidWeb` / `verifierDomainOf` / `didFromUrl` / `verificationMethodId` | helpers |
| `VIA_PLATFORM_DID` / `VIA_PLATFORM_DOMAIN` | `did:web:humanos.tech` |

### Actions & CEL
| Function | Notes |
|---|---|
| `buildActionVersion(input)` → `ActionDetail` | generates each rule's CEL `expression` (N13) |
| `buildActionReference(content, location)` / `verifyActionReference` / `actionDigestSRI` | hash-pinning |
| `generateCelExpression(conditions, typeOf)` / `buildTypeResolver` / `operatorsByType` | rule → CEL |
| `validateExecutionParams` / `validateUserParams` | type/required checks |
| `wrapUserParamsWithAction` / `unwrapUserParamValues` | `{description,value}` ↔ flat |
| `evaluateRules(rules, ctx)` / `evaluateRule` | CEL over `{ userParams, executionParams }` |

### Mandates
| Function | Notes |
|---|---|
| `buildMandate(input)` | unsecured VC (proof set added next) |
| `buildEvidence({ content \| digestSRI, mediaType, location, id? })` | by-reference evidence entry |
| `addProof(credential, { privateKey, verificationMethod, lifecycleAction, created? })` | append to the `proof` set |
| `verifyMandateProofs(credential, resolvePublicKey)` | verify every proof |

### Status
| Function | Notes |
|---|---|
| `new StatusList(url, purpose?, lengthBits?)` | `.allocateIndex/.set/.get/.entry/.toStatusListCredential` |
| `buildCredentialStatusEntry({ statusListCredential, statusListIndex, statusPurpose? })` | credential entry |
| `checkCredentialStatus(entry, statusListCredential)` → `{ statusPurpose, value }` | offline revocation check |
| `createBitstring/setBit/getBit/encodeList/decodeList` | Bitstring Status List v1.0 |

### Presentations
| Function | Notes |
|---|---|
| `buildPresentation(input)` / `verifyPresentation(vp, resolvePublicKey)` | full VP (Humanos-signed) |
| `generateChallenge(ctx?)` / `domainMatches(bound, verifierDomain)` | audience binding (§0.7.3) |
| `buildSdJwtMandate(input)` / `presentSdJwt(input)` / `verifySdJwtPresentation(input)` | SD-JWT VC selective disclosure (`dc+sd-jwt`) |

### Verify
| Function | Notes |
|---|---|
| `verify({ presentation, executionParams }, deps)` | §0.8 flow |
| `verifyAny(...)` | dual-accept legacy + v0.2 during migration; reports `result.format` |

`deps` (injected I/O):

```ts
{
  verifier: { did: string; domain?: string };
  resolvePublicKey: (vmId) => Uint8Array | Promise<Uint8Array>;
  loadCredentialRecord: (urn) => { status; validFrom?; validUntil? } | Promise<…>;
  loadActionVersion: (urn) => ActionDetail | null | Promise<…>;
  validateChallenge?: (challenge, mandateId) => string | Promise<string>; // "ok" or a deny reason
  now?: Date;
  platformDid?: string;
}
```

Deny reasons: `vp_holder_unknown`, `vp_signature_invalid`, `credential_{status}`, `not_yet_valid`, `expired`, `vp_domain_mismatch`, `vp_challenge_replay`/`challenge_expired`, `verifier_not_authorized`, `action_not_found`/`action_invalid`, `execution_params_invalid:{msg}`, `rule_failed`.

### Receipts
| Function | Notes |
|---|---|
| `buildReceipt(input)` / `signReceipt(receipt, signer)` / `verifyReceipt(receipt, resolvePublicKey)` | `VIAReceipt` VCs |

### Compat (secondary, optional)
`import { compat } from "@humanos/via-sdk"` — the 5 functions + 2 types the platform consumes from the old `@humanos/via-protocol`, in legacy-compatible form (`signWithEd25519Multibase`, `canonicalizeJSON`, `encodePublicKeyMultibase`, `generateChallenge`, `generateDIDKey`). For transitional interop only.

## Decentralized verification (no trusted DB)

Compose external/offline verification from primitives:

```ts
const vpOk   = await verifyPresentation(vp, resolveKey);                         // outer Humanos proof
const vcOk   = await verifyMandateProofs(vp.verifiableCredential, resolveKey);   // ISSUE/ACCEPT/STAMP
const status = checkCredentialStatus(vc.credentialStatus, statusListCred);        // offline revocation
const eval   = evaluateRules(action.rules, { userParams, executionParams });      // CEL
// resolveKey = (vmId) => resolveVerificationKey(fetchedDidDoc, vmId)
```

## Format modes

Default is **`v0.2`** (spec-correct). A **`legacy`** mode (and the `compat` shim) reproduce the deployed platform's current wire format byte-for-byte for the migration window only — see [`../spec/MIGRATION.md`](../spec/MIGRATION.md).

## Status

`v0.2.0` reference implementation — 120 tests (incl. frozen per-version wire fixtures), KAT-guarded crypto, typechecks and builds. Not yet audited; the platform supplies real KMS-backed key material. Selective disclosure (SD-JWT) is additive/opt-in.

## Scripts

```bash
npm test          # vitest
npm run typecheck # tsc --noEmit
npm run build     # tsup → dist (ESM + d.ts)
```
