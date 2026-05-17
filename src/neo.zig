//! Neo N3 SDK — public API.
//!
//! Most users only need this module:
//!
//! ```zig
//! const neo = @import("neo-zig");
//!
//! pub fn main() !void {
//!     var client = try neo.Client.builder(allocator)
//!         .endpoint("http://localhost:20332")
//!         .timeoutMs(30_000)
//!         .build();
//!     defer client.deinit();
//!
//!     const count = try client.getBlockCount();
//!     std.debug.print("block count: {}\n", .{count});
//! }
//! ```
//!
//! The primary entry point is `Client`. Construct one with the builder, then
//! call operations as direct methods. Domain modules (`crypto`, `transaction`,
//! `wallet`, `contract`, `script`, `serialization`) are exposed for advanced
//! use cases.

const std = @import("std");

// ---------------------------------------------------------------------------
// Primary public surface
// ---------------------------------------------------------------------------

/// Neo client. See `client.zig` for the full API.
pub const Client = @import("client.zig").Client;

/// Network preset used by `Client.Builder.network`.
pub const Network = @import("client.zig").Network;

/// Retry policy used by `Client.Builder.retryPolicy`.
pub const RetryPolicy = @import("client.zig").RetryPolicy;

// ---------------------------------------------------------------------------
// Core value types
// ---------------------------------------------------------------------------

pub const Hash160 = @import("types/hash160.zig").Hash160;
pub const Hash256 = @import("types/hash256.zig").Hash256;
pub const Address = @import("types/address.zig").Address;
pub const ContractParameter = @import("types/contract_parameter.zig").ContractParameter;
pub const StackItem = @import("types/stack_item.zig").StackItem;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

const core_errors = @import("core/errors.zig");

/// Per-module error sets (re-exported here as a namespace for backward compat).
pub const errors = core_errors;

pub const NeoError = core_errors.NeoError;
pub const CryptoError = core_errors.CryptoError;
pub const SerializationError = core_errors.SerializationError;
pub const ValidationError = core_errors.ValidationError;
pub const NetworkError = core_errors.NetworkError;
pub const TransactionError = core_errors.TransactionError;
pub const WalletError = core_errors.WalletError;
pub const ContractError = core_errors.ContractError;

/// Umbrella error set covering every error any operation on `Client` can return.
/// Convenient for callers that want a single `!Error!T` return type.
pub const Error = NeoError ||
    CryptoError ||
    SerializationError ||
    ValidationError ||
    NetworkError ||
    TransactionError ||
    WalletError ||
    ContractError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const constants = @import("core/constants.zig");

// ---------------------------------------------------------------------------
// Domain modules — exposed for advanced use cases
// ---------------------------------------------------------------------------

/// Cryptographic primitives: key pairs, ECDSA, hashing, WIF, NEP-2, BIP-32.
pub const crypto = @import("crypto/crypto.zig");

/// Binary serialization: BinaryReader, BinaryWriter, varint, NeoSerializable.
pub const serialization = @import("serialization/serialization.zig");

/// Neo VM script construction: ScriptBuilder, OpCode, InteropService.
pub const script = @import("script/mod.zig");

/// Smart contracts: SmartContract, NEP-17, NEP-11, native contracts, NNS.
pub const contract = @import("contract/mod.zig");

/// Transaction building, signing, witness construction, broadcasting.
pub const transaction = @import("transaction/mod.zig");

/// Wallets: NEP-6, BIP-39, account management.
pub const wallet = @import("wallet/mod.zig");

/// Low-level RPC types and transport. Most users should not need this.
pub const rpc = @import("rpc/mod.zig");

/// Low-level protocol helpers. Most users should prefer `Client`.
pub const protocol = @import("protocol/mod.zig");

/// Core value types module (Hash160, Hash256, Address, ContractParameter,
/// StackItem, CallFlags, Role, RecordType, etc.).
///
/// Equivalent flat aliases are exposed directly on `neo` for the common types;
/// use this namespace for less-common types like `CallFlags` or `Role`.
pub const types = @import("types/types.zig");

// ---------------------------------------------------------------------------
// Backward-compatibility aliases (deprecated; will be removed in v3.0)
// ---------------------------------------------------------------------------

/// Deprecated: use `Client` instead.
pub const NeoClient = Client;

/// Deprecated: use `crypto` instead.
pub const security = struct {
    pub const crypto = @import("crypto/crypto.zig");
};

/// Deprecated: top-level value types are now exposed directly on `neo`.
pub const model = struct {
    pub const types = @import("types/types.zig");
    pub const Hash160 = @import("types/hash160.zig").Hash160;
    pub const Hash256 = @import("types/hash256.zig").Hash256;
    pub const Address = @import("types/address.zig").Address;
    pub const ContractParameter = @import("types/contract_parameter.zig").ContractParameter;
};

/// Deprecated: use `serialization` instead.
pub const io = struct {
    pub const serialization = @import("serialization/serialization.zig");
    pub const BinaryReader = @import("serialization/serialization.zig").BinaryReader;
    pub const BinaryWriter = @import("serialization/serialization.zig").BinaryWriter;
};

/// Deprecated: use top-level `script` instead.
pub const vm = struct {
    pub const script = @import("script/mod.zig");
};

/// Deprecated: use top-level domain modules (`contract`, `transaction`,
/// `wallet`, `rpc`) instead.
pub const runtime = struct {
    pub const contract = @import("contract/mod.zig");
    pub const transaction = @import("transaction/mod.zig");
    pub const wallet = @import("wallet/mod.zig");
    pub const rpc = @import("rpc/mod.zig");
};

/// Deprecated: use top-level errors and value types directly on `neo`.
pub const core = struct {
    pub const constants = @import("core/constants.zig");
    pub const errors = @import("core/errors.zig");
};

pub const utils = @import("utils/utils.zig");

pub const BinaryReader = @import("serialization/serialization.zig").BinaryReader;
pub const BinaryWriter = @import("serialization/serialization.zig").BinaryWriter;
pub const Transaction = @import("transaction/transaction_builder.zig").Transaction;
pub const TransactionBuilder = @import("transaction/transaction_builder.zig").TransactionBuilder;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "public surface refAllDecls" {
    std.testing.refAllDecls(@This());
}

test "Client builder creates client without contacting network" {
    const testing = std.testing;
    var client = try Client.builder(testing.allocator)
        .endpoint("http://127.0.0.1:20332")
        .timeoutMs(5_000)
        .build();
    defer client.deinit();
    try testing.expectEqual(@as(u32, 3), client.retry.max_attempts);
}

test "Error union covers per-module error sets" {
    const testing = std.testing;
    const e1: Error = NeoError.IllegalArgument;
    const e2: Error = CryptoError.InvalidKey;
    const e3: Error = TransactionError.InvalidWitness;
    try testing.expect(e1 == NeoError.IllegalArgument);
    try testing.expect(e2 == CryptoError.InvalidKey);
    try testing.expect(e3 == TransactionError.InvalidWitness);
}

test "deprecated aliases still resolve to canonical types" {
    const testing = std.testing;
    try testing.expect(NeoClient == Client);
    try testing.expect(model.Hash160 == Hash160);
    try testing.expect(model.Hash256 == Hash256);
    try testing.expect(io.BinaryReader == BinaryReader);
    try testing.expect(io.BinaryWriter == BinaryWriter);
}
