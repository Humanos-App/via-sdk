import { VC_V2_CONTEXT, type BitstringStatusListCredential, type BitstringStatusListEntry } from "../types.js";
import { createBitstring, decodeList, encodeList, getBit, setBit } from "./bitstring.js";

export type StatusPurpose = "revocation" | "suspension";

/** Build a credential's `credentialStatus` entry (N15/N26: index is a base-10 string; id ≠ list URL). */
export function buildCredentialStatusEntry(params: {
  statusListCredential: string;
  statusListIndex: number;
  statusPurpose?: StatusPurpose;
}): BitstringStatusListEntry {
  return {
    id: `${params.statusListCredential}#${params.statusListIndex}`,
    type: "BitstringStatusListEntry",
    statusPurpose: params.statusPurpose ?? "revocation",
    statusListIndex: String(params.statusListIndex),
    statusListCredential: params.statusListCredential,
  };
}

export interface CredentialStatusCheck {
  statusPurpose: StatusPurpose;
  /** The bit at the entry's index — `true` means the status applies (revoked / suspended). */
  value: boolean;
}

/**
 * Check a credential's `credentialStatus` entry against its `BitstringStatusListCredential`.
 * Lets an independent verifier check revocation/suspension offline (N15). Throws if the
 * entry's `statusPurpose` doesn't match the list's.
 */
export function checkCredentialStatus(
  entry: BitstringStatusListEntry,
  statusListCredential: { id?: string; credentialSubject: { statusPurpose: string; encodedList: string } },
): CredentialStatusCheck {
  const subject = statusListCredential.credentialSubject;
  if (subject.statusPurpose !== entry.statusPurpose) {
    throw new Error(`statusPurpose mismatch: entry "${entry.statusPurpose}" vs list "${subject.statusPurpose}"`);
  }
  const index = Number.parseInt(entry.statusListIndex, 10);
  if (!Number.isInteger(index) || index < 0) throw new Error(`invalid statusListIndex: ${entry.statusListIndex}`);
  return { statusPurpose: entry.statusPurpose, value: getBit(decodeList(subject.encodedList), index) };
}

/** In-memory status list that issues a `BitstringStatusListCredential` and flips bits. */
export class StatusList {
  readonly purpose: StatusPurpose;
  readonly listCredentialUrl: string;
  private readonly bits: Uint8Array;
  private next = 0;

  constructor(listCredentialUrl: string, purpose: StatusPurpose = "revocation", lengthBits?: number) {
    this.listCredentialUrl = listCredentialUrl;
    this.purpose = purpose;
    this.bits = createBitstring(lengthBits);
  }

  allocateIndex(): number {
    return this.next++;
  }
  set(index: number, value: boolean): void {
    setBit(this.bits, index, value);
  }
  get(index: number): boolean {
    return getBit(this.bits, index);
  }
  entry(index: number): BitstringStatusListEntry {
    return buildCredentialStatusEntry({
      statusListCredential: this.listCredentialUrl,
      statusListIndex: index,
      statusPurpose: this.purpose,
    });
  }

  /** Publishable `BitstringStatusListCredential` (unsecured; sign with the proof helpers). */
  toStatusListCredential(issuer: string, validFrom: string): BitstringStatusListCredential {
    return {
      "@context": [VC_V2_CONTEXT],
      id: this.listCredentialUrl,
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      issuer,
      validFrom,
      credentialSubject: {
        id: `${this.listCredentialUrl}#list`,
        type: "BitstringStatusList",
        statusPurpose: this.purpose,
        encodedList: encodeList(this.bits),
      },
    };
  }
}
