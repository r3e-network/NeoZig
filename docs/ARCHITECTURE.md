# Architecture Notes

This SDK is organized as a collection of focused modules under `src/`:

- `core/`: constants + error sets
- `types/`: Hash160/Hash256/Address + Neo VM parameter types
- `crypto/`: secp256r1, signatures, NEP-2, WIF, BIP32
- `rpc/`: JSON-RPC transport + typed responses + `NeoSwift` client
- `transaction/`: transaction builder, signers, witnesses, witness rules
- `wallet/`: NEP-6 + BIP-39 account helpers
- `contract/`: contract wrappers (NEP-17/NEP-11/native contracts)

## Ownership Model

General guideline:

- Builder-style types own internal heap allocations and expose `deinit(...)`.
- RPC response types that allocate (strings, slices, nested values) expose `deinit(allocator)`.

If you add new types, prefer an explicit `deinit` over “free individual fields from the outside”.

## Adding a New RPC Method

The SDK uses typed request builders plus typed response parsing:

1. Add/extend the response type in `src/rpc/responses.zig` (or `src/rpc/complete_responses.zig` if it’s a larger structure).
2. Add a response alias wrapper in `src/rpc/response_aliases.zig` if the protocol layer needs a `getX()` accessor.
3. Add a request builder in `src/protocol/neo_protocol.zig` (JSON-RPC method name + params).
4. Add a convenience method on `src/rpc/neo_client.zig` (`NeoSwift`) when appropriate.
5. Add a focused test under `tests/` validating request params and response parsing.

## Version / Protocol Parsing

Neo nodes differ slightly in `getversion` payloads (e.g., `wsport` may be omitted). The SDK’s parsers aim to accept real node payloads and treat optional fields as optional.

If you tighten parsing, prefer “optional + default” over hard-failing on missing keys unless the protocol guarantees the field.

