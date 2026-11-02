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
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-sdk";
import type { Bytes32, CorridorConfig, CorridorPolicy } from "./types.js";
import { bytes32ToBuffer } from "./hex.js";

// A well-formed but unfunded source account is enough for simulation.
const SIM_SOURCE = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

const b32 = (hex: Bytes32): xdr.ScVal =>
  nativeToScVal(bytes32ToBuffer(hex), { type: "bytes" });

export interface SorobanReaderOptions {
  /**
   * Optional TTL (in milliseconds) for caching `getPolicy(corridorId)` responses
   * per corridor. Overrides `cfg.policyCacheTtlMs` when provided.
   * Disabled by default (`undefined` or `<= 0`).
   */
  policyCacheTtlMs?: number;
  /** Optional clock source returning current time in milliseconds (defaults to `Date.now`). */
  now?: () => number;
}

interface CachedPolicyEntry {
  policy: CorridorPolicy;
  expiresAt: number;
}

function clonePolicy(policy: CorridorPolicy): CorridorPolicy {
  return {
    ...policy,
    acceptedIssuers: [...policy.acceptedIssuers],
  };
}

export class SorobanReader {
  private readonly server: rpc.Server;
  private readonly policyCacheTtlMs: number;
  private readonly now: () => number;
  private readonly policyCache = new Map<Bytes32, CachedPolicyEntry>();

  constructor(
    private readonly cfg: CorridorConfig,
    opts: SorobanReaderOptions = {},
  ) {
    this.server = new rpc.Server(cfg.rpcUrl, {
      allowHttp: cfg.rpcUrl.startsWith("http://"),
    });
    this.policyCacheTtlMs = opts.policyCacheTtlMs ?? cfg.policyCacheTtlMs ?? 0;
    this.now = opts.now ?? Date.now;
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

  /**
   * Fetch a corridor's on-chain policy. Throws if it isn't registered.
   * When `policyCacheTtlMs > 0` is configured, serves cached responses per
   * corridor until the TTL expires or `invalidatePolicy` is called.
   */
  async getPolicy(corridorId: Bytes32): Promise<CorridorPolicy> {
    const cacheKey = corridorId.toLowerCase() as Bytes32;
    if (this.policyCacheTtlMs > 0) {
      const cached = this.policyCache.get(cacheKey);
      if (cached && this.now() < cached.expiresAt) {
        return clonePolicy(cached.policy);
      }
      if (cached) {
        this.policyCache.delete(cacheKey);
      }
    }

    const r = await this.simulate(
      this.cfg.registryContractId,
      "get_policy",
      b32(corridorId),
    );
    if ("error" in r) throw new Error(`get_policy: ${r.error}`);
    const p = r.value as Record<string, unknown>;
    const policy: CorridorPolicy = {
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

    if (this.policyCacheTtlMs > 0) {
      this.policyCache.set(cacheKey, {
        policy: clonePolicy(policy),
        expiresAt: this.now() + this.policyCacheTtlMs,
      });
    }

    return policy;
  }

  /**
   * Explicitly invalidate cached `CorridorPolicy` entries.
   * Pass a `corridorId` to evict a single corridor, or omit it to clear all cached policies.
   */
  invalidatePolicy(corridorId?: Bytes32): void {
    if (corridorId !== undefined) {
      this.policyCache.delete(corridorId.toLowerCase() as Bytes32);
    } else {
      this.policyCache.clear();
    }
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
}

export interface PassRecord {
  tag: number;
  ledger: number;
  timestamp: bigint;
  auditorBlob: Bytes32;
}

// Re-export for callers that want to build their own scvals.
export { Address, nativeToScVal, scValToNative };
