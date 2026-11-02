import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Account,
  Address,
  Keypair,
  SorobanDataBuilder,
  Transaction,
  xdr,
} from "@stellar/stellar-sdk";
import {
  Corridor,
  SorobanReader,
  TESTNET,
  makeFixture,
  buildWitness,
  simulatedEnter,
  toBytes32,
} from "./index.js";
import type { Bytes32, CorridorPolicy, Proof } from "./index.js";
import { scValToNative } from "./soroban.js";

const CID: Bytes32 = toBytes32(4n);

function sampleProof(): Proof {
  const fx = makeFixture();
  const policy: CorridorPolicy = {
    operator: "G".padEnd(56, "A"),
    acceptedIssuers: [fx.issuerId],
    minTier: 3,
    requiredDisclosures: 0,
    minCredEpoch: 1n,
    verifier: "C".padEnd(56, "A"),
    vkHash: toBytes32(9n),
    auditorPubkey: toBytes32(0n),
    nowToleranceSecs: 300n,
    paused: false,
  };
  const w = buildWitness(
    fx.credential,
    policy,
    { disclosedTag: 2, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(77n) },
    { corridorId: CID, now: 1_000_000 },
  );
  return {
    bytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    publicInputs: w.publicInputs,
  };
}

function mockSimSuccess() {
  return {
    _parsed: true,
    id: "sim-1",
    latestLedger: 123_456,
    minResourceFee: "45000",
    transactionData: new SorobanDataBuilder().setResourceFee(45_000),
    result: {
      auth: [],
      retval: xdr.ScVal.scvVoid(),
    },
  };
}

test("simulatedEnter builds and simulates corridor_attestation.enter for wallet signing", async () => {
  const kp = Keypair.random();
  const proof = sampleProof();
  const reader = new SorobanReader(TESTNET);

  let requestedAccount: string | null = null;
  let simulatedTx: Transaction | null = null;

  const srv = (
    reader as unknown as {
      server: {
        getAccount: (addr: string) => Promise<Account>;
        simulateTransaction: (tx: Transaction) => Promise<unknown>;
      };
    }
  ).server;

  srv.getAccount = async (addr: string) => {
    requestedAccount = addr;
    return new Account(addr, "100");
  };
  srv.simulateTransaction = async (tx: Transaction) => {
    simulatedTx = tx;
    return mockSimSuccess();
  };

  const tx = await reader.simulatedEnter(CID, proof, kp.publicKey());

  assert.equal(requestedAccount, kp.publicKey());
  assert.ok(simulatedTx);
  assert.equal(tx.source, kp.publicKey());
  assert.equal(tx.sequence, "101");
  // 100 base fee + 45000 minResourceFee
  assert.equal(tx.fee, "45100");
  assert.equal(tx.operations.length, 1);

  const op = tx.operations[0]!;
  assert.equal(op.type, "invokeHostFunction");
  if (
    op.type === "invokeHostFunction" &&
    op.func.type === "hostFunctionTypeInvokeContract"
  ) {
    const args = op.func.invokeContract;
    assert.equal(
      Address.fromScAddress(args.contractAddress).toString(),
      TESTNET.attestationContractId,
    );
    assert.equal(args.functionName.toString(), "enter");
    const callArgs = args.args;
    assert.equal(callArgs.length, 3);

    const argCorridor = Buffer.from(scValToNative(callArgs[0]!) as Uint8Array);
    assert.equal(`0x${argCorridor.toString("hex")}`, CID);

    const argProof = Buffer.from(scValToNative(callArgs[1]!) as Uint8Array);
    assert.deepEqual(new Uint8Array(argProof), proof.bytes);

    const argPi = (scValToNative(callArgs[2]!) as Uint8Array[]).map(
      (b) => `0x${Buffer.from(b).toString("hex")}`,
    );
    assert.deepEqual(argPi, proof.publicInputs);
  } else {
    assert.fail("expected hostFunctionTypeInvokeContract operation");
  }

  // Verify the returned transaction can be serialized to XDR (Freighter path) and signed
  const rehydrated = new Transaction(tx.toXDR(), TESTNET.networkPassphrase);
  rehydrated.sign(kp);
  assert.equal(rehydrated.signatures.length, 1);
});

test("simulatedEnter accepts an Account directly and works via Corridor class and top-level helper", async () => {
  const kp = Keypair.random();
  const proof = sampleProof();
  const corridor = new Corridor(TESTNET);
  const reader = (corridor as unknown as { reader: SorobanReader }).reader;

  let getAccountCalled = false;
  const srv = (
    reader as unknown as {
      server: {
        getAccount: () => Promise<Account>;
        simulateTransaction: () => Promise<unknown>;
      };
    }
  ).server;
  srv.getAccount = async () => {
    getAccountCalled = true;
    throw new Error("should not call getAccount when Account instance is passed");
  };
  srv.simulateTransaction = async () => mockSimSuccess();

  const tx = await corridor.simulatedEnter(
    CID,
    proof,
    new Account(kp.publicKey(), "7"),
    { fee: "250", timeoutSecs: 60 },
  );
  assert.equal(getAccountCalled, false);
  assert.equal(tx.sequence, "8");
  assert.equal(tx.fee, "45250");
  assert.equal(typeof simulatedEnter, "function");
});

test("simulatedEnter rejects wrong publicInputs length and propagates RPC simulation errors", async () => {
  const kp = Keypair.random();
  const proof = sampleProof();
  const reader = new SorobanReader(TESTNET);

  await assert.rejects(
    () =>
      reader.simulatedEnter(
        CID,
        { bytes: proof.bytes, publicInputs: proof.publicInputs.slice(0, 8) },
        new Account(kp.publicKey(), "1"),
      ),
    /expected 9 publicInputs, got 8/,
  );

  const srv = (
    reader as unknown as {
      server: { simulateTransaction: () => Promise<unknown> };
    }
  ).server;
  srv.simulateTransaction = async () => ({
    _parsed: true,
    id: "sim-err",
    latestLedger: 123_456,
    error: "HostError: Error(Contract, #4)",
  });

  await assert.rejects(
    () => reader.simulatedEnter(CID, proof, new Account(kp.publicKey(), "1")),
    /enter: HostError: Error\(Contract, #4\)/,
  );
});
