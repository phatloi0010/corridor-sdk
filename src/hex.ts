import { randomBytes } from "node:crypto";
import type { Bytes32 } from "./types.js";

/** BN254 scalar field modulus — values must be reduced below this. */
export const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Encodes a value into a canonical 32-byte hex string (`0x${string}` of 64 hex chars).
 *
 * Edge case behaviors:
 * - **Odd-length hex strings**: Left-padded with leading zeros (big-endian).
 * - **Optional 0x prefix**: Strips both `0x` and `0X` prefixes case-insensitively.
 * - **Empty input**: `""`, `"0x"`, `"0X"`, or empty `Uint8Array` produces 32 zero bytes (`0x00...00`).
 * - **Values above the field**: Encodes arbitrary 32-byte words (values up to 2^256 - 1). Values
 *   greater than or equal to `BN254_FR` are preserved as 32-byte words without modular reduction.
 *   Use `isFieldElement()` or `assertFieldElement()` if strict field-element bounds are required.
 * - **Overflow**: Throws if string hex exceeds 64 chars, Uint8Array exceeds 32 bytes, or integer >= 2^256.
 * - **Negative integers**: Throws an Error.
 * - **Invalid hex**: Throws an Error if a string contains non-hexadecimal characters.
 */
export function toBytes32(v: bigint | number | Uint8Array | string): Bytes32 {
  let hex: string;
  if (v instanceof Uint8Array) {
    if (v.length > 32)
      throw new Error(`value does not fit in 32 bytes: ${v.length} bytes`);
    hex = Buffer.from(v).toString("hex");
  } else if (typeof v === "string") {
    hex = v.replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]*$/.test(hex)) {
      throw new Error(`invalid hex string: ${v}`);
    }
  } else {
    const n = BigInt(v);
    if (n < 0n) throw new Error(`negative values cannot be converted to Bytes32: ${v}`);
    hex = n.toString(16);
  }
  if (hex.length > 64) throw new Error(`value does not fit in 32 bytes: ${hex}`);
  return `0x${hex.padStart(64, "0")}` as Bytes32;
}

/**
 * Converts a Bytes32 (or hex string) into a 32-byte Buffer.
 * Strips optional `0x`/`0X` prefix and left-pads with zeros to 32 bytes.
 */
export function bytes32ToBuffer(b: Bytes32 | string): Buffer {
  const hex = b.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`invalid hex string: ${b}`);
  }
  if (hex.length > 64) {
    throw new Error(`value does not fit in 32 bytes: ${b}`);
  }
  return Buffer.from(hex.padStart(64, "0"), "hex");
}

/**
 * Decodes a Bytes32 (or hex string) into an unsigned BigInt.
 *
 * Edge case behaviors:
 * - **Optional 0x prefix**: Accepts strings with or without `0x` or `0X` prefix.
 * - **Empty input**: `""`, `"0x"`, and `"0X"` return `0n` (consistent with `toBytes32("")`).
 * - **Odd-length strings**: Parsed directly as big-endian hex values.
 * - **Values above the field**: Full 256-bit values (up to 2^256 - 1) are decoded without reduction.
 */
export function bytes32ToBigInt(b: Bytes32 | string): bigint {
  const hex = b.replace(/^0x/i, "");
  if (hex === "") return 0n;
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`invalid hex string: ${b}`);
  }
  return BigInt(`0x${hex}`);
}

/** Returns true if the value is non-negative and strictly below the BN254 scalar field modulus BN254_FR. */
export function isFieldElement(v: Bytes32 | bigint | number | string): boolean {
  try {
    let n: bigint;
    if (typeof v === "bigint") {
      n = v;
    } else if (typeof v === "number") {
      n = BigInt(v);
    } else {
      const hex = v.replace(/^0x/i, "");
      if (!/^[0-9a-fA-F]*$/.test(hex)) return false;
      n = hex === "" ? 0n : BigInt(`0x${hex}`);
    }
    return n >= 0n && n < BN254_FR;
  } catch {
    return false;
  }
}

/** Asserts that a value is within the BN254 scalar field [0, BN254_FR). */
export function assertFieldElement(
  v: Bytes32 | bigint | number | string,
  name = "value",
): void {
  let n: bigint;
  if (typeof v === "bigint") {
    n = v;
  } else if (typeof v === "number") {
    n = BigInt(v);
  } else {
    const hex = v.replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]*$/.test(hex)) {
      throw new Error(`${name} is not valid hex: ${v}`);
    }
    n = hex === "" ? 0n : BigInt(`0x${hex}`);
  }
  if (n < 0n || n >= BN254_FR) {
    throw new Error(
      `${name} (${typeof v === "string" ? v : `0x${n.toString(16)}`}) is outside the BN254 scalar field [0, BN254_FR)`,
    );
  }
}

/** Big-endian integer in the low bytes of a 32-byte word (matches
 *  `corridor_types::word_to_u64` / `word_to_u32`). */
export function numberToWord(n: bigint | number): Bytes32 {
  return toBytes32(BigInt(n));
}

export function isBytes32(s: string): s is Bytes32 {
  return /^0x[0-9a-fA-F]{64}$/.test(s);
}

/** A random field element (< BN254_FR), 32-byte hex. Use for salt / nonce. */
export function randomFieldElement(): Bytes32 {
  let v: bigint;
  do {
    v = BigInt(`0x${randomBytes(32).toString("hex")}`);
  } while (v >= BN254_FR);
  return toBytes32(v);
}

/**
 * A fresh holder secret. **Load-bearing for privacy** — it blinds the credential
 * commitment and the nullifier is `Poseidon2(secret, corridorId)`, so a
 * low-entropy secret is grindable (link a holder across corridors, or brute a
 * target nullifier). Always generate it here, never from a user passphrase or a
 * weak seed. There is no recovery — store it securely.
 */
export const randomSecret = randomFieldElement;

/** Throw if a purported holder secret is obviously low-entropy (audit H5). A
 *  soft guard for issuer/wallet code — not a substitute for using randomSecret. */
export function assertStrongSecret(s: Bytes32): void {
  const v = bytes32ToBigInt(s);
  if (v < 1n << 200n) {
    throw new Error(
      "holder secret has < 200 bits — use randomSecret(); low-entropy secrets are grindable",
    );
  }
}
