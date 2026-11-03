import rfc8785 from "canonicalize";

/** RFC 8785 (JCS) canonicalization — the one canonical form. */
export function canonicalizeRFC8785(value: unknown): string {
  const out = rfc8785(value);
  if (out === undefined) throw new Error("cannot canonicalize undefined");
  return out;
}
