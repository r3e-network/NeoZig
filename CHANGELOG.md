# Changelog

## Unreleased

- (none)

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
