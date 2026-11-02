/**
 * Read-only Soroban calls against the deployed Corridor contracts. All of
 * these are simulation-only — no account, no fee, no signature.
 */

import {
  Account,
  Address,
  Contract,
  nativeToScVal,
  rpc,
  scValToNative,
  Transaction,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-sdk";
import { PI_LEN } from "./types.js";
import type { Bytes32, CorridorConfig, CorridorPolicy } from "./types.js";
import { bytes32ToBuffer } from "./hex.js";

// A well-formed but unfunded source account is enough for simulation.
const SIM_SOURCE = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

const b32 = (hex: Bytes32): xdr.ScVal =>
  nativeToScVal(bytes32ToBuffer(hex), { type: "bytes" });

export class SorobanReader {
  private readonly server: rpc.Server;

  constructor(private readonly cfg: CorridorConfig) {
    this.server = new rpc.Server(cfg.rpcUrl, {
      allowHttp: cfg.rpcUrl.startsWith("http://"),
    });
  }

  private async simulate(contractId: string, method: string, ...args: xdr.ScVal[]) {
    const tx = new TransactionBuilder(new Account(SIM_SOURCE, "0"), {
      fee: "100",
      networkPassphrase: this.cfg.networkPassphrase,
    })
      .addOperation(new Contract(contractId).call(method, ...args))
      .setTimeout(30)
      .build();
    const sim = await this.server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      return { error: sim.error } as const;
    }
    return { value: scValToNative(sim.result!.retval) } as const;
  }

  /** Fetch a corridor's on-chain policy. Throws if it isn't registered. */
  async getPolicy(corridorId: Bytes32): Promise<CorridorPolicy> {
    const r = await this.simulate(
      this.cfg.registryContractId,
      "get_policy",
      b32(corridorId),
    );
    if ("error" in r) throw new Error(`get_policy: ${r.error}`);
    const p = r.value as Record<string, unknown>;
    return {
      operator: String(p.operator),
      acceptedIssuers: (p.accepted_issuers as Buffer[]).map(
        (x) => `0x${Buffer.from(x).toString("hex")}` as Bytes32,
      ),
      minTier: Number(p.min_tier),
      requiredDisclosures: Number(p.required_disclosures),
      minCredEpoch: BigInt(p.min_cred_epoch as bigint),
      verifier: String(p.verifier),
      vkHash: `0x${Buffer.from(p.vk_hash as Buffer).toString("hex")}` as Bytes32,
      auditorPubkey:
        `0x${Buffer.from(p.auditor_pubkey as Buffer).toString("hex")}` as Bytes32,
      nowToleranceSecs: BigInt(p.now_tolerance_secs as bigint),
      paused: Boolean(p.paused),
    };
  }

  /** Has this nullifier been granted a pass on this corridor? (payout gate) */
  async isCleared(corridorId: Bytes32, nullifier: Bytes32): Promise<boolean> {
    const r = await this.simulate(
      this.cfg.attestationContractId,
      "is_cleared",
      b32(corridorId),
      b32(nullifier),
    );
    if ("error" in r) throw new Error(`is_cleared: ${r.error}`);
    return Boolean(r.value);
  }

  /** Aggregate pass count for a corridor. */
  async passes(corridorId: Bytes32): Promise<bigint> {
    const r = await this.simulate(
      this.cfg.attestationContractId,
      "passes",
      b32(corridorId),
    );
    if ("error" in r) throw new Error(`passes: ${r.error}`);
    return BigInt(r.value as bigint);
  }

  /** The full `PassRecord` for a granted nullifier, or null. */
  async passRecord(
    corridorId: Bytes32,
    nullifier: Bytes32,
  ): Promise<PassRecord | null> {
    const r = await this.simulate(
      this.cfg.attestationContractId,
      "pass_record",
      b32(corridorId),
      b32(nullifier),
    );
    if ("error" in r) throw new Error(`pass_record: ${r.error}`);
    if (r.value == null) return null;
    const p = r.value as Record<string, unknown>;
    return {
      tag: Number(p.tag),
      ledger: Number(p.ledger),
      timestamp: BigInt(p.timestamp as bigint),
      auditorBlob:
        `0x${Buffer.from(p.auditor_blob as Buffer).toString("hex")}` as Bytes32,
    };
  }

  /**
   * Assemble and simulate a `corridor_attestation.enter(corridor_id, proof, public_inputs)`
   * transaction without submitting it, returning a ready-to-sign Soroban `Transaction`
   * (with footprint, auth entries, and resource fee attached).
   *
   * Enables a wallet (such as Freighter) to sign `tx.toXDR()` directly when not
   * routing through a fee-sponsoring relayer.
   */
  async simulatedEnter(
    corridorId: Bytes32,
    proof: { bytes: Uint8Array; publicInputs: Bytes32[] },
    source: string | Account,
    opts: SimulatedEnterOptions = {},
  ): Promise<Transaction> {
    if (proof.publicInputs.length !== PI_LEN) {
      throw new Error(
        `enter: expected ${PI_LEN} publicInputs, got ${proof.publicInputs.length}`,
      );
    }
    const account =
      typeof source === "string" ? await this.server.getAccount(source) : source;
    const op = new Contract(this.cfg.attestationContractId).call(
      "enter",
      b32(corridorId),
      nativeToScVal(Buffer.from(proof.bytes), { type: "bytes" }),
      xdr.ScVal.scvVec(proof.publicInputs.map(b32)),
    );
    const raw = new TransactionBuilder(account, {
      fee: opts.fee ?? "100",
      networkPassphrase: this.cfg.networkPassphrase,
    })
      .addOperation(op)
      .setTimeout(opts.timeoutSecs ?? 30)
      .build();
    const sim = await this.server.simulateTransaction(raw);
    if (rpc.Api.isSimulationError(sim)) {
      throw new Error(`enter: ${sim.error}`);
    }
    if (rpc.Api.isSimulationRestore(sim)) {
      throw new Error(
        "enter: ledger state requires restoreFootprint before invoking enter",
      );
    }
    return rpc.assembleTransaction(raw, sim).build();
  }
}

export interface SimulatedEnterOptions {
  /** Base inclusion fee in stroops (defaults to `"100"`). Simulation adds `minResourceFee`. */
  fee?: string;
  /** Transaction timeout in seconds (defaults to `30`). */
  timeoutSecs?: number;
}

export interface PassRecord {
  tag: number;
  ledger: number;
  timestamp: bigint;
  auditorBlob: Bytes32;
}

// Re-export for callers that want to build their own scvals.
export { Address, nativeToScVal, scValToNative };
