# Changelog

## Unreleased

- (none)

## 1.4.0 - 2026-03-17

### Architecture and Public Surface

- Reorganized the public SDK surface around stable namespace-first entry points under `neo.runtime`, `neo.rpc`, `neo.contract`, `neo.transaction`, and `neo.wallet`, while preserving compatibility aliases.
- Added clearer canonical names for ambiguous wallet and transaction types, including `StoredAccount` / `SignerAccount`, `TransactionWitness` / `ScriptWitness`, and `WitnessScopeSet`.
- Extended `neo.rpc.types` into the complete RPC response-model catalog, with organized `core`, `extended`, `protocol`, and `remaining` families.

### RPC Layer Refactor

- Refactored the RPC client, config, and service layers into smaller focused modules with additive namespace exports and builder-based construction.
- Split the large RPC response files into façade-plus-category modules, significantly reducing file size without changing the public import paths.
- Kept the complete Neo RPC surface, including response models that were not previously easy to discover from the top-level RPC namespaces.

### Correctness and Reliability

- Fixed RPC request parameter ownership so request objects deep-clone parameter payloads safely.
- Fixed wallet account ownership boundaries so wallet-managed account storage clones on write and read APIs return borrowed views instead of sharing owning state.
- Cleaned up latent compile and test issues surfaced by the broader namespace exposure.

### Documentation and Examples

- Updated README, API, architecture, troubleshooting, usage, and migration docs to reflect the preferred namespace-first layout and builder-based RPC client construction.
- Updated examples to use the preferred public surface.

### Validation

- Re-ran the full verification matrix during the release prep, including `zig build rpc-test`, `zig build test`, and `zig build examples`.

## 1.3.1 - 2026-02-20

### Neo N3 v3.9.1 Compatibility + Stability Patch

- Hardened Neo v3.9.1 interop syscall constants to match SHA256-prefix values, with explicit validation tests.
- Verified native contract hash constants and version metadata handling against real Neo N3 node expectations.

### Reliability Fixes

- Fixed NEF checksum/round-trip vector handling in `src/contract/nef_file.zig`.
- Fixed NNS validation edge cases in `src/contract/nns_name.zig` (fragment-count bounds + parser typo correction).
- Added `NEP6Wallet.deinitOwned` for parsed-object ownership cleanup and used it in wallet tests to avoid leaks.

### Backward Compatibility

- Expanded legacy alias/export compatibility in public modules so prior call sites continue compiling.

### Validation

- Re-ran full verification before release (`zig build`, `zig build test`, targeted suite steps, and ReleaseSafe test run).

## 1.3.0 - 2026-02-11

### Neo N3 v3.9.0 Native Contract Implementations

Adds full SDK wrappers for the three native contracts introduced in the Faun
hardfork, plus protocol-compliance fixes verified against the `neo-project/neo`
C# reference implementation.

#### New Contracts

- **CryptoLib** (`src/contract/crypto_lib.zig`) — Cryptographic hash and
  signature operations: `sha256`, `ripemd160`, `murmur32`, `keccak256`
  (HF_Cockatrice), `verifyWithECDsa` (HF_Cockatrice), `recoverSecp256K1`
  (HF_Echidna), and 6 BLS12-381 methods (HF_Cockatrice).
- **Notary** (`src/contract/notary.zig`) — Notary-assisted transaction
  support: `lockDepositUntil`, `withdraw`, `balanceOf`, `expirationOf`,
  `getMaxNotValidBeforeDelta`, `setMaxNotValidBeforeDelta`, `verify`.
- **Treasury** (`src/contract/treasury.zig`) — Passive fund holder for
  recovered blocked-account assets. Exposes `verify` only (NEP-26/27/30).

#### New Types

- **`NamedCurveHash`** enum — Type-safe ECDSA curve+hash pairs (22/23/122/123)
  replacing raw `u8` values, matching the Neo N3 `NamedCurveHash` enum.

#### Protocol Compliance Fixes

- **Hardfork enum**: Renamed `Aspidiske` → `Aspidochelone` to match
  `HF_Aspidochelone` in the reference implementation.
- **CryptoLib**: Removed non-existent SHA3/Blake2b methods; added real
  `keccak256`, `recoverSecp256K1`, and BLS12-381 operations.
- **Treasury**: Removed fabricated `requestFund`/`getFundBalance` — Treasury
  is a passive contract with only `verify` and payment callbacks.
- **PolicyContract.recoverFund**: Fixed signature from 1 param to 2
  (`account` + `token`).
- **PolicyContract.setWhitelistFeeContract**: Fixed from 1 param to 4
  (`contractHash`, `method`, `argCount`, `fixedFee`).
- **PolicyContract.removeWhitelistFeeContract**: Fixed from 1 param to 3
  (`contractHash`, `method`, `argCount`).
- **Notary.withdraw**: Made `to` parameter nullable (`?Hash160`), matching
  the reference `UInt160?`.
- **CryptoLibAlgorithm**: Removed fake SHA3/Blake2b constants, added
  `KECCAK256`.

#### Infrastructure

- Added `callFunctionReturningBytes` to `SmartContract` for byte-array
  return values.
- Exported `NamedCurveHash` from the contract module.

#### Quality

- **Build**: `zig build` — zero errors, zero warnings
- **Tests**: `zig build test` — 358 tests passing
- **7 files changed**, ~800 lines added

### NeoSwift → Neo Rename & Codebase Consolidation

Major refactoring release that completes the migration from Swift-derived naming to
idiomatic Zig conventions, consolidates fragmented modules, and removes dead code.

#### Breaking Changes

- Removed all `neo_swift_*` source files — replaced by clean `neo_*` equivalents
- Removed `*_complete.zig` consolidation files — functionality merged into primary modules
- Removed `swift_aliases.zig` and `aliases.zig` — use canonical type paths directly

#### Renamed / Replaced Files

| Removed                              | Replacement                           |
| ------------------------------------ | ------------------------------------- |
| `src/protocol/neo_swift_express.zig` | `src/protocol/neo_express_client.zig` |
| `src/protocol/neo_swift_rx.zig`      | `src/protocol/neo_rx.zig`             |
| `src/rpc/neo_swift_config.zig`       | `src/rpc/neo_config.zig`              |
| `src/rpc/neo_swift_service.zig`      | `src/rpc/neo_service.zig`             |
| `src/core/neo_swift_error.zig`       | (merged into `src/core/errors.zig`)   |
| `src/types/swift_aliases.zig`        | (removed, no replacement needed)      |
| `src/types/aliases.zig`              | (removed, no replacement needed)      |

#### Consolidated Modules

- `src/serialization/binary_reader_complete.zig` → merged into `binary_reader.zig` + `binary_reader_ext.zig`
- `src/serialization/binary_writer_complete.zig` → merged into `binary_writer.zig` + `binary_writer_ext.zig`
- `src/transaction/witness_complete.zig` → merged into `witness.zig`
- `src/transaction/witness_scope_complete.zig` → `witness_scope.zig`
- `src/wallet/nep6_complete.zig` → `nep6_extended.zig`
- `src/script/verification_script_complete.zig` → merged into `wallet/verification_script.zig`
- `src/script/interop_service_complete.zig` → merged into `interop_service.zig`
- `src/protocol/response/complete_response_suite.zig` → `response_suite.zig`
- `src/protocol/stack_item_complete.zig` → merged into `types/stack_item.zig`
- `src/rpc/complete_responses.zig` → `extended_responses.zig`

#### Cleanup

- Removed 6 root-level scratch/demo files (`comprehensive_test.zig`, `final_demo.zig`, `minimal_build.zig`, `simple_test.zig`, `working_demo.zig`, `working_test.zig`)
- Removed `tests/all_swift_tests.zig` and `tests/complete_swift_test_conversion.zig`
- Cleaned Swift naming remnants from documentation and test log strings
- Zero `TODO`/`FIXME` markers remain in source

#### Quality

- **Build**: `zig build` — zero errors, zero warnings
- **Tests**: `zig build test` — all suites pass
- **223 files changed**, ~13k lines removed, ~2.8k lines added (net −10.5k)

## 1.1.1 - 2026-01-25

### Neo N3 v3.9.1 Compatibility

- **Version Constants**: Added `neo.constants.NeoVersion` with full version info (3.9.1)
- **Native Contracts**: Added explicit v3.9.1 documentation and version markers
- **Interop Services**: Expanded with v3.9.1 interop methods (Contract, Crypto, Runtime)
- **Documentation**: Updated architecture docs with v3.9.1 compatibility section
- **Native Contracts Listed**: ContractManagement, StdLib, CryptoLib, LedgerContract, NeoToken, GasToken, PolicyContract, RoleManagement, OracleContract, Notary, Treasury

## 1.1.0 - 2026-01-22

### Major Improvements

- **Neo v3.9.1 Compatibility** - Full alignment with Neo N3 v3.9.1 protocol
  - VM opcodes: PUSHT (0x08), PUSHF (0x09), MODMUL (0xA5), MODPOW (0xA6), ABORTMSG (0xE0), ASSERTMSG (0xE1)
  - Interop services and pricing matching v3.9.x
  - `getversion` parsing includes hardfork metadata
  - Updated native contract hashes and constants

- **BIP-39 Unicode Support** - Complete internationalization
  - NFKD (Normalization Form Compatibility Decomposition) for Unicode mnemonics
  - Support for Latin-1 Supplement, Latin Extended-A, Greek characters
  - UTF-8 sequence validation with clear error messages
  - 10 new tests covering various Unicode scenarios

### Documentation

- **Complete API Reference** (`docs/API.md`) - 678 lines of comprehensive API documentation
- **Troubleshooting Guide** (`docs/TROUBLESHOOTING.md`) - 525 lines covering common issues
- **Enhanced Usage Guide** (`docs/USAGE.md`) - Expanded from 95 to 945 lines
- **Architecture Guide** (`docs/ARCHITECTURE.md`) - Expanded from 45 to 514 lines
- Updated README with clearer examples and security guidelines

### Code Quality

- **Unified Code Formatting** - All 100+ Zig files formatted with `zig fmt`
- **Examples Expansion** - 8 comprehensive examples (vs 3 previously)
  - Hash operations, key generation, WIF handling
  - Address validation, transaction building
  - Wallet operations, contract parameters, RPC requests

### Type Safety

- **Iterator Genericization** - Type-safe `Iterator(T, Context)` replacing `*anyopaque`
- **Memory Utilities** (`src/utils/memory_utils.zig`) - Reusable deinit generation
- **Unused Parameter Cleanup** - Removed unused `allocator` parameters across 5+ functions
- **Comptime Validation** - Enhanced type checking

### Bug Fixes

- Fixed compilation errors in `nep2_error.zig` and `neo_swift_error.zig`
- Fixed RPC client initialization to avoid null pointer dereference
- Corrected method calls to use proper API (`toHex()` vs `toHexString()`)
- Fixed transaction builder and wallet operation examples

### Testing

- **524 tests passing** (vs 514 previously)
- 10 new BIP-39 Unicode tests
- Enhanced test coverage for contract, crypto, and transaction modules

### Performance

- Memory allocation optimizations in JSON parsing
- Reduced temporary buffer copies
- Improved iterator performance with proper alignment

---

## 1.0.1 - 2025-12-14

- Fix Neo N3 network magic constants to match `getversion` (`NEO3` / `N3T5`).
- Make `getversion` parsing accept real node payloads where `wsport` may be omitted.
- Add `TransactionBroadcaster.deinit()` and fix `BroadcastUtils.localhost()` endpoint ownership.
- Add safer NeoZig ownership helpers (`initFromService`, `buildFromService`, pointer-based factory constructors) and make `cloneWithConfig` non-owning to avoid double-free.
- Tighten demos/examples around secret handling (WIF decode zeroization, proper `deinit` usage).
- Expand `.gitignore` to cover Zig caches and other generated directories.
- Add `docs/USAGE.md` and `docs/ARCHITECTURE.md`.
- Refresh README/SECURITY wording to avoid unverifiable performance/security claims.

## 1.0.0

- Initial public release.
