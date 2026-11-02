import { test } from "node:test";
import assert from "node:assert/strict";
import { Corridor, SorobanReader, TESTNET } from "./index.js";
import { nativeToScVal } from "./soroban.js";
import type { Bytes32 } from "./types.js";
import { bytes32ToBuffer, toBytes32 } from "./hex.js";

const CID_A: Bytes32 = toBytes32(4n);
const CID_B: Bytes32 = toBytes32(5n);
const ISSUER_1: Bytes32 = toBytes32(0x1111n);
const ISSUER_2: Bytes32 = toBytes32(0x2222n);
const VK_HASH: Bytes32 = toBytes32(0x9999n);
const AUDITOR: Bytes32 = toBytes32(0n);

function mockPolicySimResult(minTier: number, issuer: Bytes32 = ISSUER_1) {
  const retval = nativeToScVal({
    operator: TESTNET.registryContractId,
    accepted_issuers: [bytes32ToBuffer(issuer)],
    min_tier: minTier,
    required_disclosures: 0,
    min_cred_epoch: 2n,
    verifier: TESTNET.attestationContractId,
    vk_hash: bytes32ToBuffer(VK_HASH),
    auditor_pubkey: bytes32ToBuffer(AUDITOR),
    now_tolerance_secs: 300n,
    paused: false,
  });
  return { result: { retval } };
}

function stubSimulate(
  reader: SorobanReader,
  fn: () => Promise<unknown>,
): { calls: () => number } {
  let count = 0;
  const srv = (
    reader as unknown as {
      server: { simulateTransaction: () => Promise<unknown> };
    }
  ).server;
  srv.simulateTransaction = async () => {
    count += 1;
    return fn();
  };
  return { calls: () => count };
}

test("SorobanReader.getPolicy queries RPC on every call by default (cache disabled)", async () => {
  const reader = new SorobanReader(TESTNET);
  let tier = 2;
  const rpc = stubSimulate(reader, async () => mockPolicySimResult(tier++));

  const first = await reader.getPolicy(CID_A);
  const second = await reader.getPolicy(CID_A);

  assert.equal(rpc.calls(), 2);
  assert.equal(first.minTier, 2);
  assert.equal(second.minTier, 3);
});

test("SorobanReader.getPolicy caches per corridor within TTL and re-fetches after expiry", async () => {
  let clock = 1_000;
  const reader = new SorobanReader(TESTNET, {
    policyCacheTtlMs: 5_000,
    now: () => clock,
  });
  let tier = 1;
  const rpc = stubSimulate(reader, async () => mockPolicySimResult(tier++));

  // Initial miss for CID_A
  const p1 = await reader.getPolicy(CID_A);
  assert.equal(rpc.calls(), 1);
  assert.equal(p1.minTier, 1);

  // Hit within TTL (even if caller mutates returned array)
  p1.acceptedIssuers.push(ISSUER_2);
  clock = 5_999;
  const p2 = await reader.getPolicy(CID_A);
  assert.equal(rpc.calls(), 1);
  assert.equal(p2.minTier, 1);
  assert.deepEqual(p2.acceptedIssuers, [ISSUER_1]);

  // Independent cache entry for CID_B
  const pB = await reader.getPolicy(CID_B);
  assert.equal(rpc.calls(), 2);
  assert.equal(pB.minTier, 2);

  // At exact TTL boundary (1_000 + 5_000 = 6_000), CID_A expires and re-fetches
  clock = 6_000;
  const p3 = await reader.getPolicy(CID_A);
  assert.equal(rpc.calls(), 3);
  assert.equal(p3.minTier, 3);
});

test("SorobanReader.invalidatePolicy evicts a single corridor or the entire cache", async () => {
  const clock = 10_000;
  const reader = new SorobanReader(
    { ...TESTNET, policyCacheTtlMs: 60_000 },
    { now: () => clock },
  );
  let tier = 10;
  const rpc = stubSimulate(reader, async () => mockPolicySimResult(tier++));

  await reader.getPolicy(CID_A);
  await reader.getPolicy(CID_B);
  assert.equal(rpc.calls(), 2);

  // Invalidate only CID_A; CID_B remains cached
  reader.invalidatePolicy(CID_A);
  const aAfter = await reader.getPolicy(CID_A);
  const bAfter = await reader.getPolicy(CID_B);
  assert.equal(rpc.calls(), 3);
  assert.equal(aAfter.minTier, 12);
  assert.equal(bAfter.minTier, 11);

  // Invalidate all corridors
  reader.invalidatePolicy();
  await reader.getPolicy(CID_A);
  await reader.getPolicy(CID_B);
  assert.equal(rpc.calls(), 5);
});

test("Corridor forwards policyCacheTtlMs and invalidatePolicy to SorobanReader", async () => {
  const corridor = new Corridor({ ...TESTNET, policyCacheTtlMs: 30_000 });
  const reader = (corridor as unknown as { reader: SorobanReader }).reader;
  let tier = 1;
  const rpc = stubSimulate(reader, async () => mockPolicySimResult(tier++));

  await corridor.getPolicy(CID_A);
  await corridor.getPolicy(CID_A);
  assert.equal(rpc.calls(), 1);

  corridor.invalidatePolicy(CID_A);
  await corridor.getPolicy(CID_A);
  assert.equal(rpc.calls(), 2);
});
