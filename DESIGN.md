# via-sdk — Design

A pure, functions-only TypeScript implementation of the VIA Protocol: v0.3 on `main`, the v0.4 draft on `v04`.
The specification is the source of truth; section numbers below are v0.3's. Usage is in `README.md`, branches and
releases in `CONTRIBUTING.md`.

## Principles

- **The spec decides.** A mismatch between this code and the spec is fixed in one of the two, never worked around
  in a caller.
- **No I/O.** No HTTP, database, KMS or network. Everything a check reads (a credential's record, an action version,
  an actor's keys, a nonce's freshness) and every signing key is passed in by the caller.
- **Fail closed.** An artifact whose `specVersion` this SDK does not support is refused (`unsupported_spec_version`);
  so is a critical extension it does not implement (§19.2). A verifier must wire its nonce check
  (`requireNonceCheck`).
- **One implementation.** The Humanos platform and agent-sdk run this code, not their own copy of the protocol.

## Layout

| `src/`                                   | What                                                                                                   |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `crypto/`                                | RFC 8785 canonicalization, SRI digests, Ed25519 and P-256 signing, `eddsa-jcs-2022` proofs, WebAuthn  |
| `did/`                                   | `did:web` identifiers, and the DID document as a projection of an actor's keys                         |
| `action/`, `cel/`                        | action versions, their execution parameters, CEL rules generated and evaluated                         |
| `mandate/`, `credential/`                | the mandate credential, and the STAMP that secures it (§0.5.4)                                         |
| `event/`                                 | the signed `VIAEvent` (§0.5)                                                                           |
| `status/`                                | Bitstring status lists                                                                                 |
| `presentation/`, `verify/`               | full and SD-JWT presentations, and verifying one                                                       |
| `agent/`                                 | agent binding (§16): registration and attestation, the PoP, `verifyAgentDirect`, `verifyAgentCall`, audit events, the call proof (§16.16) |
| `actor/`                                 | the `VIAActor` record folded from its chain (§3–§5)                                                    |
| `grantor/`, `operator/`                  | grantor binding (§17) and operator verification (§18)                                                  |
| `policy/`                                | the organization's `VIAPolicy` (§21): building a version and evaluating a call against it              |
| `signal/`                                | the SD-JWT `VIASignal`                                                                                 |
| `context/`                               | the JSON-LD context shipped with the package                                                           |

`src/index.ts` is the public surface, with two subpaths beside it: `./action/cel` (the rule generator alone, for a
browser) and `./agent/sim` (a simulated Nitro attestation, for development and tests only).

## Two verifiers

- **`verifyAgentCall`** — the platform's: one call under the organization's policy first (§21.3), then the mandate
  it presents when the policy leaves the tool to one. Nobody is asked to confirm a call: what would need a step-up
  is refused `stepup_required`.
- **`verifyAgentDirect`** — a relying party checking an agent's mandate itself (§16.11). It can answer `rechallenge`
  when the mandate, its pinned action (`stepUp.tools`) or the caller asks a person to confirm (§17.4).

Both check the PoP once against the agent's keys and answer the `action_hash` it bound.

## Crypto and libraries

- **Ed25519** for issuer and organization signatures (`eddsa-jcs-2022` over JCS); **P-256** (ES256) for an
  agent's key; a passkey's own algorithm for a grantor's assertion (§17.1).
- **SD-JWT VC** through `@sd-jwt/core` and `@sd-jwt/sd-jwt-vc`; JOSE through `jose`; CBOR through `cbor-x`
  (Nitro attestation documents).
- **CEL** through `@marcbachmann/cel-js`, a maintained, dependency-free engine.

## Versioning

Every artifact carries `specVersion` (`VIA_SPEC_VERSION`, `"0.3"` on `main`); `detectSpecVersion()` reads it and
anything unsupported reads as `unknown`. The package's own version is separate: `0.x` on npm's `latest` from `main`,
`1.0.0-v04.N` on `next` from `v04`.

## Testing

`npm test` (vitest): each module's own tests, round trips (build → sign → verify), known-answer tests for the
crypto (`crypto-kat.test.ts`), CEL operator semantics pinned to the engine (`cel.test.ts`), and frozen artifacts of
shipped versions that current code must still verify (`wire-fixtures.test.ts`).
