# corridor-sdk — `@corridor/verify`

[![CI](https://github.com/Sconce-Labs/corridor-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Sconce-Labs/corridor-sdk/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6)](./tsconfig.json)
[![Node](https://img.shields.io/badge/node-%E2%89%A522-339933)](./.nvmrc)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

The **TypeScript client SDK** for
[Corridor](https://github.com/Sconce-Labs/corridor) — a portable, zero-knowledge
proof of eligibility for cross-border payments.

One package covers all three roles:

- **Issuer** — sign a credential statement (`issueCredential`, Grumpkin Schnorr).
- **Holder** — read a corridor's policy, build and locally verify the ZK
  witness, request a proof, present it (`getPolicy`, `buildWitness`,
  `verifyWitnessLocally`, `requestProof`, `enter`).
- **Corridor operator** — check whether a payout is cleared (`isCleared`,
  `passRecord`, `passes`).

| | |
|---|---|
| **Product & architecture** | [Sconce-Labs/corridor](https://github.com/Sconce-Labs/corridor) |
| **Soroban contracts & the ABI** | [Sconce-Labs/corridor-contracts](https://github.com/Sconce-Labs/corridor-contracts) · [`ABI.md`](https://github.com/Sconce-Labs/corridor-contracts/blob/main/ABI.md) |
| **Noir circuit** | [Sconce-Labs/corridor-circuits](https://github.com/Sconce-Labs/corridor-circuits) |
| **Auditor blob** | [`docs/AUDITOR.md`](./docs/AUDITOR.md) |

---

## Install

```bash
npm install @corridor/verify @stellar/stellar-sdk
```

ESM only, Node ≥ 22. `@stellar/stellar-sdk` is a peer dependency (you likely
already have it).

---

## What works today

| API | Kind | Status |
|-----|------|--------|
| `getPolicy(corridorId)` · `invalidatePolicy(corridorId?)` | Soroban read | ✅ the on-chain `CorridorPolicy` (with opt-in per-corridor TTL cache via `policyCacheTtlMs`) |
| `isCleared(corridorId, nullifier)` | Soroban read | ✅ the payout gate |
| `passes(corridorId)` · `passRecord(corridorId, nullifier)` | Soroban read | ✅ aggregate count · full `PassRecord` |
| `buildWitness(cred, policy, req, opts)` | local | ✅ assembles the 9-field public vector + private witness, **verifies the issuer signature, every predicate, and the secret's entropy first** |
| `verifyWitnessLocally(witness)` | local | ✅ re-runs every circuit constraint in TS |
| `prepareCredentialRequest` · `issueCredential` · `assembleCredential` · `makeFixture` | local | ✅ the three issuance steps — the issuer sees only `holderBinding` |
| `sign` · `verify` · `publicKey` · `randomIssuerKey` · `GRUMPKIN_P` · `SCHNORR_CHALLENGE_DST` | local | ✅ the Grumpkin Schnorr primitives, pinned to `noir-lang/schnorr` v0.4.0 |
| `poseidon2` · `CONFORMANCE_VECTORS` · `holderBinding` · `statementMessage` · `issuerIdOf` | local | ✅ the hash helpers the circuit uses |
| `randomSecret` / `randomFieldElement` · `assertStrongSecret` | local | ✅ CSPRNG `holder_secret` + a weak-value guard (`buildWitness` enforces it) |
| `requestProof(witness)` | HTTP | ⏳ needs a local Noir prover (`proverUrl`) — M3/M6 |
| `enter(corridorId, proof)` | HTTP | ⏳ needs a fee-sponsoring tx-relayer (`relayerUrl`) — M6 |

---

## Usage

### Corridor operator — gate a payout

```ts
import { isCleared, TESTNET } from "@corridor/verify";

// in your payout contract's off-chain guard (or mirror it as a Soroban
// cross-contract call for on-chain enforcement):
if (!(await isCleared(TESTNET, corridorId, nullifier))) {
  throw new Error("recipient not cleared for this corridor");
}
```

The holder's app hands you the `nullifier` alongside the payment request. See
[`examples/payout-gate.ts`](./examples/payout-gate.ts).

### Issuance — three parties, and the issuer never sees the holder's secret

```ts
// ── holder ──────────────────────────────────────────────────────────────────
import { prepareCredentialRequest, randomSecret, randomFieldElement } from "@corridor/verify";

const holderSecret = randomSecret();          // CSPRNG — NEVER leaves the device
const salt = randomFieldElement();
const request = prepareCredentialRequest(holderSecret, salt, {
  tier: 3,
  expiry: nowSecs + 14 * 86_400,              // SHORT — days, not years
  credEpoch: 5,
});
// request = { holderBinding, tier, expiry, credEpoch }  — send this to the issuer

// ── issuer ──────────────────────────────────────────────────────────────────
import { issueCredential, randomIssuerKey, publicKey, issuerIdOf } from "@corridor/verify";

const issuerSk = randomIssuerKey();           // Grumpkin scalar — protect it, rotate on compromise
const pk = publicKey(issuerSk);               // register issuerIdOf(pk.x, pk.y) on-chain
const statement = issueCredential(issuerSk, request);   // signs — sees only `holderBinding`
// statement = { tier, expiry, credEpoch, issuer: { pubkeyX, pubkeyY, sLo, sHi, eLo, eHi } }

// ── holder again ────────────────────────────────────────────────────────────
import { assembleCredential } from "@corridor/verify";

const credential = assembleCredential(holderSecret, salt, statement); // → CredentialMaterial
```

The issuer receives `Poseidon2(holderSecret, salt)`, never `holderSecret`. An
issuer who learned the raw secret could derive every one of that holder's
per-corridor nullifiers and link all their activity.

### Holder — prove eligibility

```ts
import { Corridor, TESTNET, randomFieldElement } from "@corridor/verify";

const c = new Corridor({ ...TESTNET, proverUrl: "http://localhost:8787" });

const policy  = await c.getPolicy(corridorId);
const witness = c.buildWitness(
  credential,
  policy,
  {
    disclosedTag: 1,                         // a corridor category label (< 16) — NOT an attested attribute
    auditorPubkey: policy.auditorPubkey,     // must equal the policy's
    auditorNonce: randomFieldElement(),
  },
  { corridorId, now: Math.floor(Date.now() / 1000) },
);

// witness.publicInputs  → 9 × Bytes32, ordered by PI_INDEX
// witness.nullifier     → Poseidon2(holderSecret, corridorId) — unlinkable per corridor
// witness.privateInputs → keyed exactly as the circuit's `main` params

const proof = await c.requestProof(witness);   // POSTs to proverUrl (a process YOU control)
await c.enter(corridorId, proof);              // via relayerUrl (M6)
```

`buildWitness` **throws locally** on an expired credential, one below the
corridor's `min_cred_epoch` floor, a wrong issuer, a bad signature, or an
`auditorPubkey` that doesn't match the policy — before any proof is generated.
See [`examples/holder-flow.ts`](./examples/holder-flow.ts) and
[`examples/read-policy.ts`](./examples/read-policy.ts).

---

## Configuration

```ts
import { Corridor, TESTNET, fromEnv } from "@corridor/verify";

new Corridor(TESTNET);                        // Stellar testnet preset
Corridor.fromEnv();                           // CORRIDOR_RPC_URL / CORRIDOR_REGISTRY_ID / …
new Corridor({                                // or fully explicit
  rpcUrl, networkPassphrase,
  registryContractId, attestationContractId,
  proverUrl?, relayerUrl?,
  policyCacheTtlMs?,                          // opt-in TTL (ms) for getPolicy() per corridor
});
```

When `policyCacheTtlMs` is set (e.g. `30_000`), `getPolicy(corridorId)` caches
each corridor's policy in memory until the TTL expires or you call
`invalidatePolicy(corridorId)` (or `invalidatePolicy()` to clear all cached
corridors). By default (`undefined` or `<= 0`), every `getPolicy` call queries
the RPC directly.

`TESTNET` tracks
[`corridor-contracts/deployments/testnet.json`](https://github.com/Sconce-Labs/corridor-contracts/blob/main/deployments/testnet.json)
(`src/networks.ts` — update both together after a redeploy). `MAINNET` is a
placeholder; Corridor is not on mainnet yet.

---

## Module map

| Module | Role |
|--------|------|
| `index.ts` | the `Corridor` class + every re-export |
| `soroban.ts` | `SorobanReader` — `getPolicy` / `isCleared` / `passes` / `passRecord` (RPC simulation, no signatures) |
| `witness.ts` | `buildWitness` — assemble **and locally verify** the circuit inputs |
| `verify-local.ts` | `verifyWitnessLocally` — a faithful TS mirror of `eligibility::check` |
| `schnorr.ts` | Grumpkin Schnorr signer/verifier, pinned to `noir-lang/schnorr` v0.4.0; deterministic (EdDSA-style) nonces |
| `poseidon.ts` | Poseidon2 (`@zkpassport/poseidon2`) + the pinned conformance vector |
| `fixture.ts` | `prepareCredentialRequest` / `issueCredential` / `assembleCredential` / `makeFixture` |
| `types.ts` | `PI_INDEX` / `PI_LEN`, `CorridorPolicy`, `IssuerSignature`, `CredentialMaterial`, `EligibilityWitness` |
| `hex.ts` | `Bytes32` helpers, `randomFieldElement` / `randomSecret`, `assertStrongSecret` |
| `networks.ts` | `TESTNET` / `MAINNET` / `fromEnv` / `DisclosureTag` |
| `scripts/gen-circuit-fixture.ts` | prints (or `--write`s) `corridor-circuits`' `Prover.toml` + `fixture.nr` with a real signature |

---

## Develop

```bash
npm install
npm run format:check      # prettier
npm run typecheck         # tsc --noEmit, strict
npm test                  # node:test — 25 tests, offline
npm run build             # tsc → dist/
npm run gen-fixture       # sign a witness and print it (smoke test)
npm run gen-fixture -- --write   # also overwrite the circuit's fixture (needs corridor-circuits as a sibling)
npm run docs              # typedoc → docs/api
```

---

## Continuous integration

[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) — every push and PR to
`main`:

| Job | Steps | Blocking |
|-----|-------|----------|
| **`typecheck + test + format + build`** | `npm ci` · `npm run format:check` · `npm run typecheck` · `npm test` (25) · `npm run build` · `npm run gen-fixture` (signs a real witness as a smoke test) | ✅ required for merge |
| **`live testnet reads (non-blocking)`** | `npm run test:live` against Stellar testnet | ⚠️ `continue-on-error` — informational |

`main` is protected on the `typecheck + test + format + build` check.
Dependabot ([`.github/dependabot.yml`](./.github/dependabot.yml)) watches npm and
Actions weekly.

---

## Conformance

The SDK is one of three implementations that must agree, or nothing verifies:

- **Poseidon2** — `poseidon2([1n, 2n]) ==`
  `0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383`,
  asserted in `src/poseidon.test.ts`, in `corridor-circuits`, and in
  `corridor-contracts`.
- **Grumpkin Schnorr** — `src/schnorr.ts` is checked against `noir-lang/schnorr`
  v0.4.0's pinned test vector (`src/schnorr.test.ts`), and `gen-fixture`
  produces a witness that `nargo execute` solves in the circuit's CI — so the
  signer and the circuit's verifier provably accept the same signatures.

---

## Security

See [`SECURITY.md`](./SECURITY.md). In brief:

- **Testnet is not a cryptographic boundary yet.** The `TESTNET` deployment
  uses a *mock* ZK verifier (milestone M3), so a well-formed `enter()` call that
  matches a policy is accepted without a valid proof. `isCleared` on testnet
  attests the policy binding and one-time use, not the proof. Don't gate real
  value on it.
- `buildWitness` runs **entirely locally**; `privateInputs` never leave the
  process. `requestProof` only POSTs to a `proverUrl` you control.
- `holder_secret` **must** come from a CSPRNG (`randomSecret()`, enforced by
  `buildWitness`); low entropy makes nullifiers grindable and weakens hiding.
- Hand the issuer `holderBinding` (via `prepareCredentialRequest`), never the
  raw `holderSecret`.
- A malicious `rpcUrl` can lie about `isCleared` — an operator's real gate
  should be an on-chain cross-contract call, not only the SDK.

---

## Contributing

[`CONTRIBUTING.md`](./CONTRIBUTING.md). Issues labelled `drips` are
reward-eligible through the
**[Stellar Drips Wave](https://www.drips.network/wave/stellar)**
([`DRIPS.md`](https://github.com/Sconce-Labs/corridor/blob/main/DRIPS.md)).

- `npm run typecheck`, `npm test`, and `npm run format:check` must pass.
- A `PI_INDEX` change (`src/types.ts`) is a coordinated PR with
  `corridor-contracts` (+ `ABI.md`) and `corridor-circuits`.
- Keep the Poseidon2 vector and the Schnorr scheme matching the circuit.
- Conventional commits.

## License

[Apache-2.0](./LICENSE) · see [`NOTICE`](./NOTICE).
