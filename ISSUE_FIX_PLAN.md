# NeoZig Issue Fixing Plan

This document captures the remediation plan to bring the NeoZig SDK in line with the production-readiness expectations. Each section lists the existing issues, the resolution approach, and validation steps. The modules are ordered so that fixes with the largest blast radius land first.

## 1. Utilities: Base58 / Hash160 Address Handling ✅
- **Observed problems**: Base58 decoding logic rejects valid Neo addresses; `Hash160.fromAddress` therefore fails, blocking all address-driven flows.
- **Fix**: Implement a correct base58/base58check encoder/decoder following Neo's reference implementation. Ensure `Hash160` helpers use the corrected routines.
- **Validation**: Add focused unit tests with well-known Neo address and script-hash vectors; confirm `Hash160.fromAddress` and `toAddress` round-trip.

Status: Completed (`src/utils/base58.zig`, `src/types/hash160.zig` now validated by tests)

## 2. Transactions: Builder & Account Abstractions ✅
- **Observed problems**: `TransactionBuilder` fabricates chain height and uses placeholder signing; `Account.getPrivateKey` returns new random keys, so signatures never match the originating account.
- **Fix**:
  1. Introduce an `Account` representation that stores deterministic keys (loading from injected key material for now).
  2. Require callers to supply `valid_until_block` explicitly or source it via RPC (left for caller). Remove timestamp-derived default.
  3. Ensure signing uses the account's actual private key and optionally allow dependency injection for tests.
- **Validation**: Unit tests covering transaction build/sign flows, verifying witness count, fee fields, and deterministic signatures with fixture keys.

Status: Completed (`src/transaction/transaction_builder.zig`, `src/crypto/wif.zig`, `src/crypto/secp256r1.zig`)

## 3. RPC Client: Request Construction ✅
- **Observed problems**: `RpcParam.initArray` drops content and `RpcRequest.send` serialises an empty params array, so any request with arguments fails.
- **Fix**: Build JSON-RPC payloads using `std.json` APIs, correctly serialising params (ints, strings, arrays, complex struct encoders). Ensure batch support remains future-proof.
- **Validation**: Add tests with stubbed HTTP transport to assert the emitted JSON matches Neo expectations for representative calls (e.g., `getblock`, `invokefunction`).

Status: Completed (`src/rpc/neo_client.zig` now emits proper JSON payloads)

## 4. RPC Client: Response Parsing
- **Observed problems**: Response models are placeholders (`NeoBlock.fromJson`, `Transaction.fromJson`, etc.) returning zeros; SDK cannot consume responses.
- **Fix**: Port the missing parsing logic from NeoSwift, mapping JSON fields to Zig types (including nested arrays, optional fields, and witness/transaction lists). Consider splitting into focused sub-modules to keep files manageable.
- **Validation**: Fixture-driven tests that decode sample JSON payloads into strongly typed structures; ensure key fields (hashes, fees, witnesses) are parsed.

## 5. Regression & Documentation Updates
- **Tasks**: Run `zig test` suites, expand README or docs if APIs change, and ensure the plan's fixes are reflected in repo documentation.
- **Validation**: All tests green; README no longer over-claims unsupported features.

Execution order will follow the numbering above. Each module's fixes should land with dedicated tests before moving to the next.
