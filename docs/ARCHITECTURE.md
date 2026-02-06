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
├── neo.zig                     # Main SDK entry point
├── core/
│   ├── constants.zig          # Neo blockchain constants
│   └── errors.zig             # Comprehensive error system
├── types/
│   ├── hash160.zig            # 160-bit hashes (addresses, contracts)
│   ├── hash256.zig            # 256-bit hashes (blocks, transactions)
│   ├── address.zig            # Neo address with Base58Check
│   └── contract_parameter.zig # Neo VM parameter types
├── crypto/
│   ├── keys.zig               # Private/public key management
│   ├── signatures.zig         # ECDSA signature operations
│   ├── secp256r1.zig          # Elliptic curve implementation
│   ├── ripemd160.zig          # RIPEMD160 hash function
│   ├── nep2.zig               # Password-protected keys
│   ├── bip32.zig              # HD wallet derivation
│   └── wif.zig                # Wallet Import Format
├── transaction/
│   ├── transaction_builder.zig # Transaction construction
│   ├── neo_transaction.zig    # Complete transaction implementation
│   ├── account_signer.zig     # Account-based signing
│   ├── witness_rule.zig       # Witness validation rules
│   └── transaction_broadcast.zig # Network broadcasting
├── contract/
│   ├── smart_contract.zig     # Contract interaction
│   ├── contract_management.zig # Contract deployment
│   ├── fungible_token.zig     # NEP-17 tokens
│   ├── non_fungible_token.zig # NEP-11 NFTs
│   ├── gas_token.zig          # Native GAS token
│   ├── neo_token.zig          # Native NEO token
│   ├── policy_contract.zig    # Network policy
│   ├── role_management.zig    # Node roles
│   ├── nef_file.zig           # NEF3 format
│   ├── neo_uri.zig            # NEP-9 URI scheme
│   └── nns_name.zig           # Neo Name Service
├── rpc/
│   ├── neo_client.zig         # Main RPC client
│   ├── http_client.zig        # HTTP networking
│   ├── responses.zig          # Response types
│   └── response_parser.zig    # JSON parsing
├── wallet/
│   ├── neo_wallet.zig         # Core wallet management
│   ├── nep6_wallet.zig        # NEP-6 standard
│   ├── nep6_complete.zig      # Complete NEP-6 implementation
│   └── bip39_account.zig      # BIP-39 mnemonic accounts
├── script/
│   ├── script_builder.zig     # Neo VM script construction
│   └── op_code.zig            # VM opcodes
├── serialization/
│   ├── binary_writer.zig      # Binary serialization
│   ├── binary_reader.zig      # Binary deserialization
│   └── neo_serializable.zig   # Serialization framework
└── utils/
    ├── base58.zig             # Base58 encoding
    ├── string_extensions.zig  # String utilities
    ├── array_extensions.zig   # Array utilities
    ├── logging.zig            # Production logging
    └── validation.zig         # Input validation
```

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
const response = try client.getBlockCount().send();
defer response.deinit(allocator);  // Frees allocated strings/slices

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
- **Signer**: Account-based signing with witness scopes
- **WitnessRule**: Advanced witness validation rules
- **BroadcastUtils**: Transaction broadcasting helpers

### RPC Module

JSON-RPC client implementation:

- **NeoSwiftService**: HTTP transport with timeout and retry support
- **NeoSwift**: Main client with typed request builders
- **responses.zig**: Typed response structures
- **response_parser.zig**: JSON parsing with Neo protocol compatibility

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
NeoSwift.build(allocator, &service, config)
    |
    v
NeoSwift (client instance)
    |
    +-- getBlockCount() --> RPCRequest { method, params }
    |
    v
send() --> HttpClient.post()
    |
    v
std.http.Client sends JSON-RPC request
    |
    v
Response parser validates and converts JSON to typed response
    |
    v
Returns response to user
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

## Adding New RPC Method

The SDK uses typed request builders plus typed response parsing:

### Step 1: Add Response Type

In `src/rpc/responses.zig`:

```zig
pub const MyResponse = struct {
    result: MyResult,
    id: std.json.Value,
    jsonrpc: []const u8,

    pub fn deinit(self: *MyResponse, allocator: std.mem.Allocator) void {
        self.result.deinit(allocator);
    }
};

pub const MyResult = struct {
    field1: []const u8,
    field2: u64,

    pub fn deinit(self: *MyResult, allocator: std.mem.Allocator) void {
        allocator.free(self.field1);
    }
};
```

### Step 2: Add Response Alias

In `src/rpc/response_aliases.zig` if protocol layer needs accessor:

```zig
pub const MyResultAccessor = struct {
    response: *responses.MyResponse,

    pub fn getField1(self: MyResultAccessor) []const u8 {
        return self.response.result.field1;
    }
};
```

### Step 3: Add Request Builder

In `src/protocol/neo_protocol.zig`:

```zig
pub const MyRequest = struct {
    method: []const u8 = "getmymethod",
    params: Params,
    id: std.json.Value,

    pub fn init(params: Params) MyRequest {
        return .{
            .params = params,
            .id = .{ .integer = 1 },
        };
    }
};

pub const MyParams = struct {
    param1: []const u8,
};
```

### Step 4: Add Client Method

In `src/rpc/neo_client.zig`:

```zig
pub fn getMyMethod(
    self: *NeoSwift,
    param1: []const u8,
) !RPCRequest(MyResponse) {
    const params = protocol.MyParams{ .param1 = param1 };
    const request = protocol.MyRequest.init(params);
    return self.makeRequest(request);
}
```

### Step 5: Add Test

In `tests/rpc_tests.zig`:

```zig
test "getmymethod" {
    // Test request params
    // Test response parsing
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

- [API Reference](API.md) - Detailed API documentation
- [Usage Guide](USAGE.md) - Practical usage patterns
- [Swift Migration](SWIFT_MIGRATION.md) - Migration from Swift SDK
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions
