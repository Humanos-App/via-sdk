import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";
import { base58Encode, fromMultibaseBase58, toMultibaseBase58, utf8 } from "./encoding.js";

/** Multicodec prefix for an Ed25519 public key (0xed01). */
const MULTICODEC_ED25519_PUB = Uint8Array.from([0xed, 0x01]);

// DER wrappers so we can build KeyObjects from raw 32-byte Ed25519 keys.
const SPKI_PREFIX = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const PKCS8_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export interface Ed25519KeyPair {
  /** Raw 32-byte public key. */
  publicKey: Uint8Array;
  /** Raw 32-byte private key (seed). */
  privateKey: Uint8Array;
}

/** Generate a raw Ed25519 key pair (32-byte public + 32-byte private seed). */
export function generateEd25519Key(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubJwk = publicKey.export({ format: "jwk" }) as { x: string };
  const privJwk = privateKey.export({ format: "jwk" }) as { d: string };
  return {
    publicKey: new Uint8Array(Buffer.from(pubJwk.x, "base64url")),
    privateKey: new Uint8Array(Buffer.from(privJwk.d, "base64url")),
  };
}

function publicKeyObject(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]), format: "der", type: "spki" });
}

function privateKeyObject(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error(`Ed25519 private key must be 32 bytes, got ${raw.length}`);
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(raw)]), format: "der", type: "pkcs8" });
}

function toBytes(message: string | Uint8Array): Buffer {
  return typeof message === "string" ? Buffer.from(utf8(message)) : Buffer.from(message);
}

/** Derive the raw 32-byte public key from a raw 32-byte private seed. */
export function publicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
  const pubJwk = createPublicKey(privateKeyObject(privateKey)).export({ format: "jwk" }) as { x: string };
  return new Uint8Array(Buffer.from(pubJwk.x, "base64url"));
}

/** Sign with Ed25519; returns the raw 64-byte signature. */
export function signRaw(message: string | Uint8Array, privateKey: Uint8Array): Uint8Array {
  return new Uint8Array(nodeSign(null, toBytes(message), privateKeyObject(privateKey)));
}

/** Sign with Ed25519; returns a multibase base58btc signature (`z…`). */
export function signMultibase(message: string | Uint8Array, privateKey: Uint8Array): string {
  return toMultibaseBase58(signRaw(message, privateKey));
}

/** Verify an Ed25519 signature (raw bytes) against a raw 32-byte public key. */
export function verifyRaw(message: string | Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return nodeVerify(null, toBytes(message), publicKeyObject(publicKey), signature);
  } catch {
    return false;
  }
}

/** Verify a multibase base58btc signature against a raw 32-byte public key. */
export function verifyMultibase(message: string | Uint8Array, multibaseSig: string, publicKey: Uint8Array): boolean {
  try {
    return verifyRaw(message, fromMultibaseBase58(multibaseSig), publicKey);
  } catch {
    return false;
  }
}

/** Encode a raw Ed25519 public key as `publicKeyMultibase` (`z` + base58btc(0xed01 ‖ key)). */
export function encodePublicKeyMultibase(publicKey: Uint8Array): string {
  const out = new Uint8Array(MULTICODEC_ED25519_PUB.length + publicKey.length);
  out.set(MULTICODEC_ED25519_PUB, 0);
  out.set(publicKey, MULTICODEC_ED25519_PUB.length);
  return "z" + base58Encode(out);
}

/** Decode a `publicKeyMultibase` back to the raw 32-byte Ed25519 public key. */
export function decodePublicKeyMultibase(multibase: string): Uint8Array {
  const decoded = fromMultibaseBase58(multibase);
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("not an Ed25519 multicodec public key (expected 0xed01 prefix)");
  }
  return decoded.slice(2);
}

/** An Ed25519 keypair labelled with its `did:key` identifier. */
export interface DIDKeyPair {
  did: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  keyType: "ed25519";
}

/**
 * Generate an Ed25519 keypair and its `did:key` identifier.
 *
 * The platform mints every subject and org key through this, so the `did:key` form and
 * the raw bytes must stay together. It previously lived in the `compat/legacy` shim; it was
 * never legacy, only co-located with it (docs/VIA/legacy.md §1.3), and v0.2 rescued it here
 * before retiring that shim. The v0.3 fork retired the shim WITHOUT the rescue, which is how
 * this went missing — a deletion that took a non-legacy function with it.
 */
export function generateDIDKey(keyType: "ed25519" = "ed25519"): DIDKeyPair {
  if (keyType !== "ed25519") throw new Error(`unsupported key type: ${keyType}`);
  const { publicKey, privateKey } = generateEd25519Key();
  return {
    did: `did:key:${encodePublicKeyMultibase(publicKey)}`,
    publicKey,
    privateKey,
    keyType: "ed25519",
  };
}
