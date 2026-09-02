/** Encoding helpers: base64 / base64url / utf8 / base58btc. */

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}
export function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
export function fromBase64Url(b64url: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64url, "base64url"));
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}
export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

/** Bitcoin/IPFS base58 alphabet (base58btc). */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * base58btc encode. Ported verbatim from the platform so multibase output is
 * byte-identical (`encodePublicKeyMultibase`, `signWithEd25519Multibase`).
 */
export function base58Encode(input: Uint8Array): string {
  const bytes = Array.from(input);
  let leadingZeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) leadingZeros++;

  const encoded: number[] = [];
  for (let i = leadingZeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < encoded.length; j++) {
      carry += encoded[j]! * 256;
      encoded[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      encoded.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let result = "1".repeat(leadingZeros);
  for (let i = encoded.length - 1; i >= 0; i--) result += BASE58_ALPHABET[encoded[i]!];
  return result;
}

/** base58btc decode. Ported verbatim from the platform (`signature.utils.ts`). */
export function base58Decode(input: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < input.length; i++) {
    let carry = BASE58_ALPHABET.indexOf(input[i]!);
    if (carry < 0) throw new Error(`Invalid base58 character: ${input[i]}`);
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < input.length && input[i] === "1"; i++) bytes.push(0);
  return new Uint8Array(bytes.reverse());
}

/** Multibase base58btc: `z` + base58(bytes). */
export function toMultibaseBase58(bytes: Uint8Array): string {
  return "z" + base58Encode(bytes);
}
export function fromMultibaseBase58(s: string): Uint8Array {
  if (!s.startsWith("z")) throw new Error(`unsupported multibase prefix: ${s[0]} (only base58btc 'z')`);
  return base58Decode(s.slice(1));
}
