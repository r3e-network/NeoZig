# Architecture Notes

This document describes the Neo Zig SDK architecture, module organization, design decisions, and implementation details.

## Table of Contents

- [Module Organization](#module-organization)
- [Ownership Model](#ownership-model)
- [Module Details](#module-details)
- [Data Flow](#data-flow)
- [Adding New RPC Methods](#adding-new-rpc-methods)
- [Version and Protocol Parsing](#version-and-protocol-parsing)
- [Neo v3.9.1 Compatibility](#neo-v391-compatibility)
- [Design Patterns](#design-patterns)

## Module Organization

The SDK is organized as a collection of focused modules under `src/`:

```
src/
├── neo.zig             Public surface: Client, value types, errors, domain modules
├── client.zig          neo.Client struct + Builder + operation methods
├── core/               Shared constants and per-module error sets
├── types/              Hash160, Hash256, Address, ContractParameter, StackItem,
│                       CallFlags, Role, RecordType, NeoVmStateType
├── crypto/             secp256r1, ECDSA, hashing, NEP-2, BIP-32, WIF, base58
├── serialization/      BinaryReader/Writer, varint, NeoSerializable
├── script/             ScriptBuilder, OpCode, InteropService, ScriptReader
├── contract/           SmartContract, NEP-17/NEP-11, native contracts (NEO,
│                       GAS, Policy, Role, CryptoLib, Notary, Treasury,
│                       ContractManagement), NEF, NNS, NEP-9 URIs
├── transaction/        TransactionBuilder, NeoTransaction, AccountSigner,
│                       ContractSigner, Witness, WitnessRule, broadcast
├── wallet/             Wallet, Account, NEP-6, BIP-39 mnemonics
├── rpc/                Low-level RPC transport, request/response model,
│                       Backoff/ServerError types, full response catalog
├── protocol/           Internal JSON-RPC service helpers
└── utils/              base58, bytes/string/array/numeric helpers, JSON utils
```

The package's public entry point is `src/neo.zig`; the `neo.Client` struct
lives in `src/client.zig`. Domain modules (`crypto`, `transaction`, `wallet`,
`contract`, `script`, `serialization`, `rpc`, `protocol`) are exposed
flat — there are no intermediate `*_namespace.zig` shims.

## Ownership Model

### General Guidelines

- **Builder-style types** own internal heap allocations and expose `deinit(...)`
- **RPC response types** that allocate (strings, slices, nested values) expose `deinit(allocator)`
- **Cryptographic keys** expose `zeroize()` for secure cleanup
- **Allocated strings/slices** must be freed with the same allocator used to create them

### Ownership Patterns

```zig
// Pattern 1: Builder with owned allocations
var builder = neo.transaction.TransactionBuilder.init(allocator);
defer builder.deinit();  // Frees internal allocations

// Pattern 2: RPC response with allocated fields
//   getBlockCount returns u32, no deinit needed.
//   getVersion/getBlock return owned data — deinit with the client's allocator.
var version = try client.getVersion();
defer version.deinit(allocator);  // Frees allocated strings/slices

// Pattern 3: Key pair with zeroization
const key_pair = try neo.crypto.generateKeyPair(true);
defer {
    var kp = key_pair;
    kp.zeroize();  // Secure cleanup
}

// Pattern 4: Allocated string
const address_str = try address.toString(allocator);
defer allocator.free(address_str);

// Pattern 5: Nested cleanup
var decoded = try neo.crypto.decodeWIF(wif, allocator);
defer {
    var d = decoded;
    d.deinit();
}
```

### Allocator Selection

| Use Case | Recommended Allocator |
|----------|----------------------|
| Short-lived demos | `std.heap.page_allocator` |
| Long-running applications | `std.heap.GeneralPurposeAllocator` |
| Known size limits | `std.heap.FixedBufferAllocator` |
| Performance-critical | Custom allocator strategy |

## Module Details

### Core Module

Provides foundational types used throughout the SDK:

- **constants.zig**: Neo blockchain constants (address versions, network magic, contract hashes)
- **errors.zig**: Comprehensive error sets for all SDK operations

### Types Module

Core data types representing Neo blockchain entities:

- **Hash160**: 20-byte hash used for addresses and contract scripts
- **Hash256**: 32-byte hash used for blocks and transactions
- **Address**: Neo N3 address with Base58Check encoding and validation
- **ContractParameter**: Neo VM parameter types (integer, string, boolean, array, etc.)

### Crypto Module

Cryptographic operations following security best practices:

- **secp256r1**: Elliptic curve implementation for ECDSA
- **keys.zig**: Private/public key generation and management
- **signatures.zig**: ECDSA signing and verification
- **nep2.zig**: NEP-2 encrypted key format
- **wif.zig**: Wallet Import Format encoding/decoding
- **bip32.zig**: Hierarchical deterministic wallet derivation
- **ripemd160.zig**: RIPEMD-160 hash function

### Transaction Module

Complete transaction building and signing system:

- **TransactionBuilder**: Fluent API for constructing transactions
- **NeoTransaction**: Complete transaction with signing and serialization
- **TransactionWitness**: Serialized witness record embedded in transactions
- **ScriptWitness**: Higher-level witness helper with script-building utilities
- **WitnessScopeSet**: Extended witness scope enum with combination/extraction helpers
- **Signer**: Account-based signing with witness scopes
- **WitnessRule**: Advanced witness validation rules
- **BroadcastUtils**: Transaction broadcasting helpers

### RPC Module

Low-level JSON-RPC transport. Most application code should use `neo.Client`
instead; this module is the escape hatch for callers that need direct
transport control.

- **HttpClient**: JSON-RPC transport with exponential-backoff retry and structured server-error capture (`Backoff`, `ServerError`)
- **HttpService**: Configurable HTTP service wrapper used by NeoClient and Client
- **NeoService**: Service abstraction that owns the transport and statistics
- **NeoClient**: Legacy client retained for back-compat; alias of `neo.Client`
- **types.zig**: Flat response-type catalog re-exporting from the leaf definition files
- **responses.zig**: Facade over the per-domain leaf files (`responses_blockchain_*.zig`, `responses_contract_*.zig`, `responses_invocation.zig`, `responses_token.zig`)
- **extended_responses.zig / protocol_responses.zig / remaining_responses.zig**: Facades grouping account/oracle/network/system/wallet/state/node/misc response types
- **response_aliases.zig**: Operation-result aliases (`NeoGetBlock`, `NeoGetTransaction`, etc.) and generic helpers
- **response.zig**: JSON-RPC 2.0 envelope (`Response<T>`, `ResponseError`)
- **response_parser.zig**: JSON parsing utilities

### Contract Module

Smart contract wrappers and helpers:

- **FungibleToken**: NEP-17 token interface
- **NonFungibleToken**: NEP-11 NFT interface
- **GasToken**: Native GAS contract wrapper
- **NeoToken**: Native NEO contract wrapper
- **ContractManagement**: Contract deployment and management
- **NEF3**: Smart contract file format

### Wallet Module

Wallet and account management:

- **Wallet**: Core wallet implementation
- **StoredAccount**: Wallet-managed account record returned by wallet lookup APIs
- **SignerAccount**: Standalone signer-capable account model used by signing flows
- **CompleteNEP6Wallet**: Full NEP-6 standard implementation
- **Bip39Account**: BIP-39 mnemonic account derivation

### Script Module

Neo VM script construction:

- **ScriptBuilder**: Build Neo VM scripts using opcodes
- **OpCode**: All Neo VM opcodes (v3.9 compatible)

### Serialization Module

Binary serialization framework:

- **BinaryWriter**: Stream-based binary writing
- **BinaryReader**: Stream-based binary reading
- **NeoSerializable**: Interface for serializable types

## Data Flow

### RPC Request Flow

```
User Code
    |
    v
neo.Client.builder(allocator)
    .endpoint(...)               (or .network(.testnet))
    .timeoutMs(...)
    .retryPolicy(...)
    .build()
    |
    v
neo.Client (client instance, owns transport)
    |
    +-- getBlockCount() --> rpcCall(u32, "getblockcount", &.{})
    |
    v
RpcRequest.init().send()
    |
    v
NeoService.performRequest()
    |
    v
HttpService.performIO() --> HttpClient.post()
    |
    +-- on transient failure: exponential backoff + jitter, retry
    |
    v
std.http.Client sends JSON-RPC request
    |
    +-- on server error: capture { code, message, data } on client.last_rpc_error
    |
    v
Response parser converts JSON result to typed response
    |
    v
Returns response value (or error.ServerError; inspect via
takeLastServerError) to user
```

### Transaction Flow

```
User Code
    |
    v
TransactionBuilder.init(allocator)
    |
    +-- version(), additionalNetworkFee(), additionalSystemFee()
    |
    +-- signer(Signer)
    |
    +-- transferToken() / script()
    |
    v
build() --> NeoTransaction
    |
    v
validate() --> checks transaction structure
    |
    v
sign(key_pair, magic) --> adds witness
    |
    v
serialize() --> []u8
    |
    v
client.sendRawTransaction()
```

### Address Creation Flow

```
User Code
    |
    v
generateKeyPair() --> KeyPair { private_key, public_key }
    |
    v
public_key.toAddress(ADDRESS_VERSION) --> Address
    |
    v
toString(allocator) --> "NX5v2MtKixV3mPJPfbJdc7f3oGyM2eE9CQ"
```

## Adding a New RPC Method

To add a new JSON-RPC method to `neo.Client`:

### Step 1: Define (or locate) the response type

If the JSON-RPC method returns a complex object, define a response struct in
the appropriate `src/rpc/responses_*.zig` (or `extended_*_responses.zig` /
`remaining_*_responses.zig`) leaf file. Existing primitives like `u32`,
`bool`, and `Hash256` can be used directly. Each response type must provide:

```zig
pub fn fromJson(value: std.json.Value, allocator: std.mem.Allocator) !@This() { ... }
pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void { ... }
```

### Step 2: Re-export from the public catalog (if user-visible)

Add the type to `src/rpc/responses.zig` (or the appropriate facade) and to
`src/rpc/types.zig` if it should appear on `neo.rpc`. If user-facing,
re-export from `src/client.zig` so callers can write `neo.MyResponse`.

### Step 3: Add the operation method on `Client`

In `src/client.zig`, add a method that wraps `rpcCall`:

```zig
pub fn getMyMethod(self: *Self, param: []const u8) !MyResponse {
    const params = [_]RpcParam{RpcParam.initString(param)};
    return self.rpcCall(MyResponse, "getmymethod", &params);
}
```

For complex parameter sets, accept an `Options` struct (see
`GetBlockOptions`, `InvokeOptions`, `TransferRangeOptions`).

### Step 4: Test

Add a unit test inline in `src/client.zig` or a domain test in
`tests/rpc_tests.zig`:

```zig
test "client.getMyMethod builds correct request" {
    // Use HttpClient.withSender to stub the transport (see http_client.zig tests).
}
```

## Version and Protocol Parsing

Neo nodes differ slightly in `getversion` payloads:

- `wsport` may be omitted on some nodes
- Hardfork metadata fields vary by node version
- Optional fields in various responses

### Parsing Strategy

The SDK's parsers aim to accept real node payloads:

```zig
// Prefer "optional + default" over hard-failing
if (json.object.get("optional_field")) |value| {
    // Parse if present
} else {
    // Use default value
}
```

### Field Handling Rules

1. If protocol guarantees the field: parse strictly, fail on missing
2. If field is optional: use default, don't fail
3. If field format varies: handle common variants

## Neo v3.9.1 Compatibility

This SDK is fully compatible with Neo N3 v3.9.1.

Key v3.9.1 compatibility points in this SDK:

### VM Opcodes

All v3.9.x opcodes are implemented:

- `PUSHT` (0x08) / `PUSHF` (0x09): Push true/false constants
- `MODMUL` (0xA5) / `MODPOW` (0xA6): Modular multiplication/exponentiation
- `ABORTMSG` (0xE0) / `ASSERTMSG` (0xE1): Abort with message

See [src/script/op_code.zig](src/script/op_code.zig) for complete opcode list.

### Interop Services

Neo 3.9.1 interop pricing and services:

- `Runtime.GetAddressVersion`
- `Runtime.LoadScript`
- `Runtime.CurrentSigners`
- `Storage.Local.*`
- `Crypto.*` functions

See [src/core/constants.zig](src/core/constants.zig) for interop service hashes.

### Native Contract Hashes

Native contract addresses match Neo v3.9.1:

| Contract | Hash |
|----------|------|
| ContractManagement | `0xffd9c37...` |
| NeoToken | `0xef4073a0...` |
| GasToken | `0xd2a4cff3...` |
| PolicyContract | `0xcc5e4edd...` |
| RoleManagement | `0x49cf4e53...` |
| OracleContract | `0xfe924b7c...` |
| Notary | `0xc1e14f19...` |
| Treasury | `0x156326f2...` |

See [src/core/constants.zig](src/core/constants.zig) for complete list.

### getversion Parsing

Includes v3.9.1 hardfork metadata:

- `hardforks`: Array of hardfork information
- `standbycommittee`: Committee members
- `seedlist`: Network seed nodes

### Version Information

```zig
neo.constants.NeoVersion.STRING;  // "3.9.1"
neo.constants.NeoVersion.MAJOR;   // 3
neo.constants.NeoVersion.MINOR;   // 9
neo.constants.NeoVersion.PATCH;   // 1
```

## Design Patterns

### Builder Pattern

Used for complex object construction:

```zig
var builder = TransactionBuilder.init(allocator);
_ = builder.version(0)
    .additionalNetworkFee(500000)
    .additionalSystemFee(1000000);
```

### Result Type Pattern

Using Zig's error unions:

```zig
const result = function() !ReturnType {
    // May fail
};
```

### Resource Acquisition Is Initialization (RAII)

```zig
var wallet = Wallet.init(allocator);
defer wallet.deinit();  // Always called
```

### Type-Safe Enums

Using Zig's tagged unions and enums:

```zig
pub const WitnessScope = enum(u8) {
    None = 0x00,
    CalledByEntry = 0x01,
    CustomContracts = 0x10,
    CustomGroups = 0x20,
    Global = 0xFF,
};
```

### Interface Pattern

Using `anytype` for generic operations:

```zig
pub fn serializeTo(
    self: anytype,
    writer: *serialization.BinaryWriter,
) !void {
    // Type-agnostic serialization
}
```

### Dependency Injection

Passing services and clients to constructors:

```zig
const gas_token = neo.contract.GasToken.init(allocator, client);
// client is injected for RPC calls
```

## Related Documentation

- [API Reference](API.md) — Detailed API documentation
- [Usage Guide](USAGE.md) — Practical usage patterns
- [Migration v1 → v2](MIGRATION_V2.md) — What changed in v2.0 and how to update
- [Swift Migration](SWIFT_MIGRATION.md) — Migration from the NeoSwift SDK
- [Troubleshooting](TROUBLESHOOTING.md) — Common issues and solutions
