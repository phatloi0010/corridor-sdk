/**
 * @corridor/verify — client SDK for Corridor.
 *
 *   import { Corridor, TESTNET } from "@corridor/verify";
 *   const c = new Corridor(TESTNET);
 *   const policy = await c.getPolicy(corridorId);          // live
 *   const ok = await c.isCleared(corridorId, nullifier);   // live — the payout gate
 *   const w = c.buildWitness(cred, policy, disclosure, { corridorId, now });  // local
 *   const proof = await c.requestProof(w);                 // needs proverUrl (M3)
 *   await c.enter(corridorId, proof);                      // needs relayerUrl (M6)
 */

import type {
  Bytes32,
  CorridorConfig,
  CorridorPolicy,
  CredentialMaterial,
  DisclosureRequest,
  EligibilityWitness,
} from "./types.js";
import { SorobanReader } from "./soroban.js";
import { buildWitness } from "./witness.js";
import { fromEnv } from "./networks.js";

export * from "./types.js";
export { TESTNET, MAINNET, fromEnv, DisclosureTag } from "./networks.js";
export {
  buildWitness,
  statementMessage,
  credentialStatement,
  holderBinding,
  issuerIdOf,
} from "./witness.js";
export { poseidon2, CONFORMANCE_VECTOR } from "./poseidon.js";
export {
  GRUMPKIN_P,
  GRUMPKIN_Q,
  SCHNORR_CHALLENGE_DST,
  randomIssuerKey,
  publicKey,
  sign,
  verify as verifySchnorrSignature,
} from "./schnorr.js";
export {
  makeFixture,
  issueCredential,
  prepareCredentialRequest,
  assembleCredential,
} from "./fixture.js";
export { SorobanReader } from "./soroban.js";
export type { PassRecord, SorobanReaderOptions } from "./soroban.js";
export { verifyWitnessLocally } from "./verify-local.js";
export type { LocalCheck } from "./verify-local.js";
export * from "./hex.js"; // incl. randomSecret, assertStrongSecret (audit H5)

export interface Proof {
  bytes: Uint8Array;
  publicInputs: Bytes32[];
}

export class Corridor {
  private readonly reader: SorobanReader;

  constructor(private readonly cfg: CorridorConfig) {
    this.reader = new SorobanReader(cfg);
  }

  /** Build from `CORRIDOR_*` env vars (falls back to testnet). */
  static fromEnv(env: NodeJS.ProcessEnv = process.env): Corridor {
    return new Corridor(fromEnv(env));
  }

  /** Fetch a corridor's on-chain policy (cached per corridor if `policyCacheTtlMs` is set). */
  getPolicy(corridorId: Bytes32): Promise<CorridorPolicy> {
    return this.reader.getPolicy(corridorId);
  }

  /** Invalidate cached policy for a single `corridorId`, or all corridors when omitted. */
  invalidatePolicy(corridorId?: Bytes32): void {
    this.reader.invalidatePolicy(corridorId);
  }

  /** The payout gate: has this nullifier been granted a pass on this corridor? */
  isCleared(corridorId: Bytes32, nullifier: Bytes32): Promise<boolean> {
    return this.reader.isCleared(corridorId, nullifier);
  }

  /** The full pass record (tag, ledger, timestamp, auditor blob), or null. */
  passRecord(corridorId: Bytes32, nullifier: Bytes32) {
    return this.reader.passRecord(corridorId, nullifier);
  }

  /** Aggregate pass count for a corridor. */
  passes(corridorId: Bytes32): Promise<bigint> {
    return this.reader.passes(corridorId);
  }

  /** Assemble the circuit witness locally. No network, no secrets leave. */
  buildWitness(
    cred: CredentialMaterial,
    policy: CorridorPolicy,
    req: DisclosureRequest,
    opts: { corridorId: Bytes32; now: number },
  ): EligibilityWitness {
    return buildWitness(cred, policy, req, opts);
  }

  /** POST the witness to a prover. Never sends `privateInputs` to a server you
   *  don't control — point `proverUrl` at a local process. */
  async requestProof(witness: EligibilityWitness): Promise<Proof> {
    if (!this.cfg.proverUrl) {
      throw new Error("no proverUrl configured — run a local Noir prover (M3)");
    }
    const res = await fetch(`${this.cfg.proverUrl}/prove`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(witness),
    });
    if (!res.ok) throw new Error(`prover ${res.status}: ${await res.text()}`);
    const { proof } = (await res.json()) as { proof: string };
    return {
      bytes: Uint8Array.from(Buffer.from(proof.replace(/^0x/, ""), "hex")),
      publicInputs: witness.publicInputs,
    };
  }

  /** Submit `enter` via the **fee-sponsoring transaction relayer** so the
   *  holder's Stellar account is never linked to the pass. This is NOT
   *  `corridor-relayer` (that syncs roots) — it is the service specced in
   *  corridor/docs/TX_RELAYER.md, which is not built yet. */
  async enter(corridorId: Bytes32, proof: Proof): Promise<{ txHash: string }> {
    if (!this.cfg.relayerUrl) {
      throw new Error("no relayerUrl configured — see corridor/docs/TX_RELAYER.md");
    }
    const res = await fetch(`${this.cfg.relayerUrl}/enter`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        corridorId,
        proof: `0x${Buffer.from(proof.bytes).toString("hex")}`,
        publicInputs: proof.publicInputs,
      }),
    });
    if (!res.ok) throw new Error(`relayer ${res.status}: ${await res.text()}`);
    return (await res.json()) as { txHash: string };
  }
}

/** One-call helper for corridor operators. */
export async function isCleared(
  cfg: CorridorConfig,
  corridorId: Bytes32,
  nullifier: Bytes32,
): Promise<boolean> {
  return new Corridor(cfg).isCleared(corridorId, nullifier);
}
