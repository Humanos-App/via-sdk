import { gzipSync, gunzipSync } from "node:zlib";
import { fromBase64Url, toBase64Url } from "../crypto/encoding.js";

/** Minimum list length for herd privacy (16 KB = 131,072 entries). */
export const MINIMUM_LIST_LENGTH = 131_072;

export function createBitstring(lengthBits: number = MINIMUM_LIST_LENGTH): Uint8Array {
  if (lengthBits % 8 !== 0) throw new Error("bitstring length must be a multiple of 8");
  return new Uint8Array(lengthBits / 8);
}

export function setBit(bits: Uint8Array, index: number, value: boolean): void {
  assertIndex(bits, index);
  const byte = index >> 3;
  const mask = 0x80 >> (index & 7); // most-significant-bit first
  if (value) bits[byte]! |= mask;
  else bits[byte]! &= ~mask & 0xff;
}

export function getBit(bits: Uint8Array, index: number): boolean {
  assertIndex(bits, index);
  return (bits[index >> 3]! & (0x80 >> (index & 7))) !== 0;
}

function assertIndex(bits: Uint8Array, index: number): void {
  if (index < 0 || index >= bits.length * 8) {
    throw new Error(`status list index ${index} out of range (0..${bits.length * 8 - 1})`);
  }
}

/** `encodedList` = Multibase-base64url (`u`) of the GZIP-compressed bitstring. */
export function encodeList(bits: Uint8Array): string {
  return "u" + toBase64Url(new Uint8Array(gzipSync(bits)));
}

export function decodeList(encoded: string): Uint8Array {
  if (!encoded.startsWith("u")) throw new Error("encodedList must be Multibase base64url (prefix 'u')");
  return new Uint8Array(gunzipSync(fromBase64Url(encoded.slice(1))));
}
