declare module "canonicalize" {
  /** RFC 8785 (JCS) canonicalization. Returns undefined for `undefined` input. */
  export default function canonicalize(object: unknown): string;
}
