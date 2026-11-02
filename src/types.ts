/**
 * Types shared across the SDK. The public-input layout mirrors
 * `corridor-contracts/crates/corridor_types` (`PI_*`) and
 * `corridor-circuits/corridor_eligibility/src/main.nr`. A change there is a
 * coordinated change here — see `corridor-contracts/ABI.md`.
 *
 * Option B (issuer-signed statements): no credential/revocation Merkle roots.
 */

/** A 32-byte value as a lowercase, `0x`-prefixed hex string. */
export type Bytes32 = `0x${string}`;

export const PI_INDEX = {
  corridorId: 0,
  minTier: 1,
  now: 2,
  nullifier: 3,
  disclosedTag: 4,
  issuerId: 5,
  minCredEpoch: 6,
  auditorPubkey: 7,
  auditorBlob: 8,
} as const;

export const PI_LEN = 9;

export interface CorridorPolicy {
  operator: string;
  /** issuer ids = `Poseidon2(issuer_pk.x, issuer_pk.y)` per accepted issuer */
  acceptedIssuers: Bytes32[];
  minTier: number;
  requiredDisclosures: number;
  /** bulk-revocation floor: a credential's `credEpoch` must be `>=` this */
  minCredEpoch: bigint;
  verifier: string;
  vkHash: Bytes32;
  /** Auditor key `auditor_blob` must bind to. `0x00…00` = no auditor. */
  auditorPubkey: Bytes32;
  nowToleranceSecs: bigint;
  paused: boolean;
}

/** An issuer's Grumpkin Schnorr key pair identity + the signature it produced. */
export interface IssuerSignature {
  /** issuer public key, Grumpkin point */
  pubkeyX: Bytes32;
  pubkeyY: Bytes32;
  /** signature (s, e) as 128-bit limb pairs */
  sLo: Bytes32;
  sHi: Bytes32;
  eLo: Bytes32;
  eHi: Bytes32;
}

/**
 * What a holder sends an issuer to be signed. Carries only the **blinded**
 * binding `Poseidon2(holderSecret, salt)` — never the raw secret, which would
 * let the issuer derive every one of the holder's per-corridor nullifiers.
 */
export interface CredentialRequest {
  holderBinding: Bytes32;
  tier: number;
  expiry: number;
  credEpoch: number;
}

/**
 * What an issuer returns: the attested attributes + the Schnorr signature over
 * `{ holderBinding, tier, expiry, credEpoch }`. Holds no holder data.
 */
export interface SignedStatement {
  tier: number;
  expiry: number;
  credEpoch: number;
  issuer: IssuerSignature;
}

/** Everything the holder's wallet holds for one credential. */
export interface CredentialMaterial {
  holderSecret: Bytes32;
  tier: number;
  expiry: number;
  /** the issuer's credential epoch — must stay `>=` the corridor's floor */
  credEpoch: number;
  salt: Bytes32;
  /** the issuer's signature over `{ holderBinding, tier, expiry, credEpoch }` */
  issuer: IssuerSignature;
}

export interface DisclosureRequest {
  /** Bounded enum index (< 16), not free text. */
  disclosedTag: number;
  /** Auditor public key the blob is bound to. `0x00…00` = no auditor. */
  auditorPubkey: Bytes32;
  /** Random nonce for the auditor blob (hex). Generate fresh per proof. */
  auditorNonce: Bytes32;
}

/** The assembled circuit inputs, ready for a Noir prover. */
export interface EligibilityWitness {
  /** length `PI_LEN`, ordered by `PI_INDEX`. */
  publicInputs: Bytes32[];
  /** Private witness map, keyed exactly as the circuit's `main` params. */
  privateInputs: Record<string, unknown>;
  /** Derived values a caller commonly needs. */
  issuerId: Bytes32;
  nullifier: Bytes32;
  auditorBlob: Bytes32;
}

export interface CorridorConfig {
  rpcUrl: string;
  networkPassphrase: string;
  registryContractId: string;
  attestationContractId: string;
  /** Endpoint of a fee-sponsoring relayer that submits `enter` for holders. */
  relayerUrl?: string;
  /** Optional: a local prover endpoint the SDK POSTs the witness to. */
  proverUrl?: string;
  /**
   * Optional TTL (in milliseconds) for caching `getPolicy(corridorId)` per corridor.
   * Disabled by default (`undefined` or `<= 0`), so every call hits the RPC unless opted in.
   */
  policyCacheTtlMs?: number;
}
// Network presets live in `networks.ts`.
