import { test } from "node:test";
import assert from "node:assert/strict";
import {
  toBytes32,
  bytes32ToBigInt,
  bytes32ToBuffer,
  numberToWord,
  isBytes32,
  randomFieldElement,
  BN254_FR,
  isFieldElement,
  assertFieldElement,
  assertStrongSecret,
} from "./hex.js";

test("toBytes32 zero-pads and round-trips", () => {
  assert.equal(toBytes32(5n), "0x" + "0".repeat(63) + "5");
  assert.equal(bytes32ToBigInt(toBytes32(123456789n)), 123456789n);
  assert.equal(toBytes32(new Uint8Array([0xab, 0xcd])), "0x" + "0".repeat(60) + "abcd");
});

test("toBytes32 handles odd-length inputs", () => {
  // Odd length string without 0x
  assert.equal(toBytes32("1"), "0x" + "0".repeat(63) + "1");
  assert.equal(toBytes32("abc"), "0x" + "0".repeat(61) + "abc");
  assert.equal(bytes32ToBigInt(toBytes32("abc")), 0xabcn);

  // Odd length string with 0x
  assert.equal(toBytes32("0x1"), "0x" + "0".repeat(63) + "1");
  assert.equal(toBytes32("0xabc"), "0x" + "0".repeat(61) + "abc");

  // Odd length 63-character string
  const odd63 = "a".repeat(63);
  assert.equal(toBytes32(odd63), "0x0" + odd63);

  // Odd number of bytes in Uint8Array (3 bytes)
  const u3 = new Uint8Array([0x01, 0x02, 0x03]);
  assert.equal(toBytes32(u3), "0x" + "0".repeat(58) + "010203");
});

test("toBytes32 and bytes32ToBigInt handle optional 0x and 0X prefixes", () => {
  const expected = "0x" + "0".repeat(60) + "1234";

  // toBytes32 with lowercase, uppercase, and no prefix
  assert.equal(toBytes32("0x1234"), expected);
  assert.equal(toBytes32("0X1234"), expected);
  assert.equal(toBytes32("1234"), expected);

  // bytes32ToBigInt with lowercase, uppercase, and no prefix
  assert.equal(bytes32ToBigInt("0x1234"), 0x1234n);
  assert.equal(bytes32ToBigInt("0X1234"), 0x1234n);
  assert.equal(bytes32ToBigInt("1234"), 0x1234n);

  // bytes32ToBuffer with lowercase, uppercase, and no prefix
  assert.deepEqual(bytes32ToBuffer("0x1234"), bytes32ToBuffer("1234"));
  assert.deepEqual(bytes32ToBuffer("0X1234"), bytes32ToBuffer("1234"));
});

test("empty input yields 32 zero bytes in toBytes32 and 0n in bytes32ToBigInt", () => {
  const zero32 = ("0x" + "0".repeat(64)) as `0x${string}`;

  // toBytes32 with empty representations
  assert.equal(toBytes32(""), zero32);
  assert.equal(toBytes32("0x"), zero32);
  assert.equal(toBytes32("0X"), zero32);
  assert.equal(toBytes32(new Uint8Array(0)), zero32);

  // bytes32ToBigInt with empty representations
  assert.equal(bytes32ToBigInt(""), 0n);
  assert.equal(bytes32ToBigInt("0x"), 0n);
  assert.equal(bytes32ToBigInt("0X"), 0n);

  // bytes32ToBuffer with empty representations
  assert.deepEqual(bytes32ToBuffer(""), Buffer.alloc(32));
  assert.deepEqual(bytes32ToBuffer("0x"), Buffer.alloc(32));
});

test("values above the field: toBytes32 preserves 32-byte words, helpers validate field bounds", () => {
  // BN254 scalar field modulus is ~0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
  const frHex = BN254_FR.toString(16);
  assert.equal(frHex.length, 64);

  // toBytes32 accepts BN254_FR and values above it up to 2^256 - 1
  const atField = toBytes32(BN254_FR);
  assert.equal(atField, `0x${frHex}`);
  assert.equal(bytes32ToBigInt(atField), BN254_FR);

  const aboveField = BN254_FR + 1n;
  const aboveFieldHex = toBytes32(aboveField);
  assert.equal(bytes32ToBigInt(aboveFieldHex), aboveField);

  // Maximum unsigned 256-bit integer (2^256 - 1)
  const maxU256 = (1n << 256n) - 1n;
  const maxWord = toBytes32(maxU256);
  assert.equal(maxWord, "0x" + "f".repeat(64));
  assert.equal(bytes32ToBigInt(maxWord), maxU256);

  // Field element validators
  assert.equal(isFieldElement(0n), true);
  assert.equal(isFieldElement(BN254_FR - 1n), true);
  assert.equal(isFieldElement(BN254_FR), false);
  assert.equal(isFieldElement(aboveField), false);
  assert.equal(isFieldElement(maxU256), false);

  // assertFieldElement throws on values outside [0, BN254_FR)
  assert.doesNotThrow(() => assertFieldElement(BN254_FR - 1n));
  assert.throws(() => assertFieldElement(BN254_FR), /outside the BN254 scalar field/);
  assert.throws(() => assertFieldElement(aboveField), /outside the BN254 scalar field/);
  assert.throws(() => assertFieldElement(-1n), /outside the BN254 scalar field/);
});

test("toBytes32 rejects over-long values (> 32 bytes)", () => {
  // Over 64 hex characters
  assert.throws(() => toBytes32("0x" + "f".repeat(65)), /32 bytes/);
  assert.throws(() => toBytes32("f".repeat(65)), /32 bytes/);

  // Over 32 bytes Uint8Array
  assert.throws(() => toBytes32(new Uint8Array(33)), /32 bytes/);

  // Integer >= 2^256
  assert.throws(() => toBytes32(1n << 256n), /32 bytes/);
});

test("toBytes32 and helpers reject invalid hex strings and negative numbers", () => {
  assert.throws(() => toBytes32("0xnothex"), /invalid hex string/);
  assert.throws(() => toBytes32("xyz"), /invalid hex string/);
  assert.throws(() => toBytes32(-1n), /negative values/);
  assert.throws(() => toBytes32(-5), /negative values/);

  assert.throws(() => bytes32ToBigInt("0xnothex"), /invalid hex string/);
  assert.throws(() => bytes32ToBuffer("0xnothex"), /invalid hex string/);
  assert.throws(() => bytes32ToBuffer("f".repeat(65)), /32 bytes/);
  assert.throws(() => assertFieldElement("0xnothex"), /not valid hex/);
  assert.equal(isFieldElement("0xnothex"), false);
});

test("bytes32ToBuffer is 32 bytes", () => {
  assert.equal(bytes32ToBuffer(toBytes32(1n)).length, 32);
});

test("numberToWord accepts number and bigint", () => {
  assert.equal(numberToWord(7), numberToWord(7n));
});

test("isBytes32 validates exact 64-char 0x-prefixed hex", () => {
  assert.equal(isBytes32("0x" + "0".repeat(64)), true);
  assert.equal(isBytes32("0x" + "a".repeat(64)), true);
  assert.equal(isBytes32("0x" + "A".repeat(64)), true);
  assert.equal(isBytes32("0x04"), false);
  assert.equal(isBytes32("nope"), false);
  assert.equal(isBytes32("0X" + "0".repeat(64)), false);
  assert.equal(isBytes32("0".repeat(64)), false);
});

test("randomFieldElement is in-range and non-repeating", () => {
  const a = randomFieldElement();
  const b = randomFieldElement();
  assert.notEqual(a, b);
  assert.ok(bytes32ToBigInt(a) < BN254_FR);
  assert.ok(isFieldElement(a));
});

test("assertStrongSecret validates entropy threshold", () => {
  // Strong secret (> 200 bits)
  const strong = toBytes32(1n << 201n);
  assert.doesNotThrow(() => assertStrongSecret(strong));

  // Weak secret (< 200 bits)
  const weak = toBytes32(1n << 199n);
  assert.throws(() => assertStrongSecret(weak), /holder secret has < 200 bits/);
});
