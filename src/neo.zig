//! Neo Zig SDK - Complete Neo blockchain SDK implementation in Zig
//!
//! This SDK provides a comprehensive interface for interacting with the Neo blockchain,
//! including cryptographic operations, transaction building, wallet management,
//! and RPC communication.

const std = @import("std");

pub const sdk = @import("sdk_namespace.zig");
pub const core = @import("core_namespace.zig");
pub const model = @import("model_namespace.zig");
pub const security = @import("security_namespace.zig");
pub const io = @import("io_namespace.zig");
pub const vm = @import("vm_namespace.zig");
pub const runtime = @import("runtime_namespace.zig");
pub const compat = @import("compat_namespace.zig");
pub const utils = @import("utils/utils.zig");

// Primary organized namespaces
pub const constants = core.constants;
pub const errors = core.errors;
pub const types = model.types;
pub const crypto = security.crypto;
pub const serialization = io.serialization;
pub const script = vm.script;
pub const contract = runtime.contract;
pub const transaction = runtime.transaction;
pub const wallet = runtime.wallet;
pub const rpc = runtime.rpc;
pub const protocol = runtime.protocol;
pub const NeoZig = sdk.NeoZig;

// Export main types for convenience
pub const Hash160 = compat.Hash160;
pub const Hash256 = compat.Hash256;
pub const Address = compat.Address;
pub const ContractParameter = compat.ContractParameter;
pub const BinaryWriter = compat.BinaryWriter;
pub const BinaryReader = compat.BinaryReader;
pub const Transaction = compat.Transaction;
pub const TransactionBuilder = compat.TransactionBuilder;

// Export error types
pub const NeoError = compat.NeoError;
pub const CryptoError = compat.CryptoError;
pub const SerializationError = compat.SerializationError;
pub const ValidationError = compat.ValidationError;

test "neo zig sdk" {
    std.testing.refAllDecls(@This());
}

test "compat namespace mirrors flat aliases" {
    const testing = std.testing;

    try testing.expect(compat.Hash160 == Hash160);
    try testing.expect(compat.Hash256 == Hash256);
    try testing.expect(compat.Address == Address);
    try testing.expect(compat.ContractParameter == ContractParameter);
    try testing.expect(compat.BinaryWriter == BinaryWriter);
    try testing.expect(compat.BinaryReader == BinaryReader);
    try testing.expect(compat.Transaction == Transaction);
    try testing.expect(compat.TransactionBuilder == TransactionBuilder);
    try testing.expect(compat.NeoError == NeoError);
    try testing.expect(compat.CryptoError == CryptoError);
    try testing.expect(compat.SerializationError == SerializationError);
    try testing.expect(compat.ValidationError == ValidationError);
}

test "runtime namespaces expose organized domain surfaces" {
    const testing = std.testing;

    try testing.expect(runtime.contract.naming.NeoNameService == runtime.contract.NeoNameService);
    try testing.expect(runtime.contract.native.ContractManagement == runtime.contract.ContractManagement);
    try testing.expect(runtime.contract.types.ContractError == runtime.contract.ContractError);

    try testing.expect(runtime.transaction.builder.TransactionBuilder == runtime.transaction.TransactionBuilder);
    try testing.expect(runtime.transaction.witnesses.TransactionWitness == runtime.transaction.TransactionWitness);
    try testing.expect(runtime.transaction.witnesses.ScriptWitness == runtime.transaction.ScriptWitness);
    try testing.expect(runtime.transaction.witnesses.WitnessScopeSet == runtime.transaction.WitnessScopeSet);
    try testing.expect(runtime.transaction.signers.ContractSigner == runtime.transaction.ContractSigner);
    try testing.expect(runtime.transaction.broadcast.TransactionBroadcaster == runtime.transaction.TransactionBroadcaster);

    try testing.expect(runtime.wallet.accounts.Wallet == runtime.wallet.Wallet);
    try testing.expect(runtime.wallet.accounts.StoredAccount == runtime.wallet.StoredAccount);
    try testing.expect(runtime.wallet.accounts.SignerAccount == runtime.wallet.SignerAccount);
    try testing.expect(runtime.wallet.nep6.NEP6Wallet == runtime.wallet.NEP6Wallet);
    try testing.expect(runtime.wallet.support.WalletError == runtime.wallet.WalletError);
}
