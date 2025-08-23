//! Neo Zig SDK - Complete Neo blockchain SDK implementation in Zig
//!
//! This SDK provides a comprehensive interface for interacting with the Neo blockchain,
//! including cryptographic operations, transaction building, wallet management,
//! and RPC communication.

const std = @import("std");

// Export core modules
pub const constants = @import("core/constants.zig");
pub const errors = @import("core/errors.zig");
pub const types = @import("types/types.zig");
pub const crypto = @import("crypto/crypto.zig");
pub const serialization = @import("serialization/serialization.zig");
pub const utils = @import("utils/utils.zig");
pub const script = @import("script/mod.zig");
pub const contract = @import("contract/mod.zig");
pub const transaction = @import("transaction/mod.zig");
pub const wallet = @import("wallet/mod.zig");
pub const rpc = @import("rpc/mod.zig");

// Export main types for convenience
pub const Hash160 = types.Hash160;
pub const Hash256 = types.Hash256;
pub const Address = types.Address;
pub const ContractParameter = types.ContractParameter;
pub const BinaryWriter = serialization.BinaryWriter;
pub const BinaryReader = serialization.BinaryReader;
pub const Transaction = transaction.Transaction;
pub const TransactionBuilder = transaction.TransactionBuilder;

// Export error types
pub const NeoError = errors.NeoError;
pub const CryptoError = errors.CryptoError;
pub const SerializationError = errors.SerializationError;
pub const ValidationError = errors.ValidationError;

test "neo zig sdk" {
    std.testing.refAllDecls(@This());
}