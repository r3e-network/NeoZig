//! Core RPC response types — facade over the per-domain definition files.
//!
//! All types are defined in `responses_blockchain_*.zig`, `responses_contract_*.zig`,
//! `responses_invocation.zig`, and `responses_token.zig`. This file re-exports
//! them as a flat set so consumers can import a single module.

const std = @import("std");
const json_utils = @import("../utils/json_utils.zig");

const Hash256 = @import("../types/hash256.zig").Hash256;
const errors = @import("../core/errors.zig");

pub const StackItem = @import("../types/stack_item.zig").StackItem;
pub const TransactionAttribute = @import("../protocol/response/transaction_attribute.zig").TransactionAttribute;

// Blockchain types
pub const NeoBlock = @import("responses_blockchain_block.zig").NeoBlock;
const tx_types = @import("responses_blockchain_transaction.zig");
pub const NeoWitness = tx_types.NeoWitness;
pub const Transaction = tx_types.Transaction;
pub const TransactionSigner = tx_types.TransactionSigner;
pub const WitnessRule = tx_types.WitnessRule;
pub const WitnessCondition = tx_types.WitnessCondition;
const network_types = @import("responses_blockchain_network.zig");
pub const NeoVersion = network_types.NeoVersion;
pub const HardforkInfo = network_types.HardforkInfo;
pub const ProtocolConfiguration = network_types.ProtocolConfiguration;
pub const NetworkFeeResponse = network_types.NetworkFeeResponse;
pub const SendRawTransactionResponse = network_types.SendRawTransactionResponse;

// Invocation types
const invocation_types = @import("responses_invocation.zig");
pub const InvocationResult = invocation_types.InvocationResult;
pub const NeoApplicationLog = invocation_types.NeoApplicationLog;
pub const Execution = invocation_types.Execution;
pub const Notification = invocation_types.Notification;

// NEP-17 token types
const token_types = @import("responses_token.zig");
pub const Nep17Balances = token_types.Nep17Balances;
pub const TokenBalance = token_types.TokenBalance;
pub const Nep17Transfers = token_types.Nep17Transfers;
pub const TokenTransfer = token_types.TokenTransfer;

// Contract types
const contract_state_types = @import("responses_contract_state.zig");
pub const ContractState = contract_state_types.ContractState;
pub const ContractNef = contract_state_types.ContractNef;
const contract_manifest_types = @import("responses_contract_manifest.zig");
pub const ContractFeatures = contract_manifest_types.ContractFeatures;
pub const ContractManifest = contract_manifest_types.ContractManifest;
pub const ContractGroup = contract_manifest_types.ContractGroup;
const contract_abi_types = @import("responses_contract_abi.zig");
pub const ContractParameterDefinition = contract_abi_types.ContractParameterDefinition;
pub const ContractMethod = contract_abi_types.ContractMethod;
pub const ContractEvent = contract_abi_types.ContractEvent;
pub const ContractABI = contract_abi_types.ContractABI;
pub const ContractPermission = contract_abi_types.ContractPermission;

test "NeoBlock response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    const block = NeoBlock.initDefault();
    try testing.expect(block.hash.eql(Hash256.ZERO));
    try testing.expectEqual(@as(u32, 0), block.size);
    try testing.expectEqual(@as(u32, 0), block.index);
}

test "InvocationResult parsing and operations" {
    const testing = std.testing;
    _ = testing.allocator;

    var invocation_result = InvocationResult.init();
    try testing.expect(!invocation_result.hasFaulted());
    invocation_result.state = .Fault;
    try testing.expect(invocation_result.hasFaulted());
    try testing.expectError(errors.NeoError.IllegalState, invocation_result.getFirstStackItem());
}

test "NetworkFeeResponse parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const string_value = std.json.Value{ .string = "1000" };
    const parsed_string = try NetworkFeeResponse.fromJson(string_value, allocator);
    try testing.expectEqual(@as(u64, 1000), parsed_string.network_fee);

    var object_map = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&object_map, allocator, "networkfee", std.json.Value{ .string = try allocator.dupe(u8, "42") });
    const object_value = std.json.Value{ .object = object_map };
    defer json_utils.freeValue(object_value, allocator);
    const parsed_object = try NetworkFeeResponse.fromJson(object_value, allocator);
    try testing.expectEqual(@as(u64, 42), parsed_object.network_fee);
}

test "SendRawTransactionResponse parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const bool_value = std.json.Value{ .bool = true };
    const parsed_bool = try SendRawTransactionResponse.fromJson(bool_value, allocator);
    try testing.expect(parsed_bool.success);
    try testing.expect(parsed_bool.hash == null);

    const hash_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const string_value = std.json.Value{ .string = hash_str };
    const parsed_string = try SendRawTransactionResponse.fromJson(string_value, allocator);
    try testing.expect(parsed_string.success);
    const expected_hash = try Hash256.initWithString(hash_str);
    try testing.expect(parsed_string.hash.?.eql(expected_hash));
}

test "Transaction response parses typed attributes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var tx_object = std.json.ObjectMap.init(allocator);

    try json_utils.putOwnedKey(&tx_object, allocator, "hash", std.json.Value{
        .string = try allocator.dupe(u8, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
    });
    try json_utils.putOwnedKey(&tx_object, allocator, "size", std.json.Value{ .integer = 1 });
    try json_utils.putOwnedKey(&tx_object, allocator, "version", std.json.Value{ .integer = 0 });
    try json_utils.putOwnedKey(&tx_object, allocator, "nonce", std.json.Value{ .integer = 123 });
    try json_utils.putOwnedKey(&tx_object, allocator, "sender", std.json.Value{
        .string = try allocator.dupe(u8, "NNEoYPoZHCe7iDh6TPazBQh6M7cV8K1u4d"),
    });
    try json_utils.putOwnedKey(&tx_object, allocator, "sysfee", std.json.Value{
        .string = try allocator.dupe(u8, "0"),
    });
    try json_utils.putOwnedKey(&tx_object, allocator, "netfee", std.json.Value{
        .string = try allocator.dupe(u8, "0"),
    });
    try json_utils.putOwnedKey(&tx_object, allocator, "validuntilblock", std.json.Value{ .integer = 100 });
    try json_utils.putOwnedKey(&tx_object, allocator, "script", std.json.Value{
        .string = try allocator.dupe(u8, ""),
    });

    const signers_array = std.json.Array.init(allocator);
    try json_utils.putOwnedKey(&tx_object, allocator, "signers", std.json.Value{ .array = signers_array });

    const witnesses_array = std.json.Array.init(allocator);
    try json_utils.putOwnedKey(&tx_object, allocator, "witnesses", std.json.Value{ .array = witnesses_array });

    var attrs_array = std.json.Array.init(allocator);
    {
        var attr = std.json.ObjectMap.init(allocator);
        try json_utils.putOwnedKey(&attr, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "NotValidBefore") });
        try json_utils.putOwnedKey(&attr, allocator, "height", std.json.Value{ .integer = 42 });
        try attrs_array.append(std.json.Value{ .object = attr });
    }
    {
        var attr = std.json.ObjectMap.init(allocator);
        try json_utils.putOwnedKey(&attr, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Conflicts") });
        try json_utils.putOwnedKey(&attr, allocator, "hash", std.json.Value{
            .string = try allocator.dupe(u8, "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        });
        try attrs_array.append(std.json.Value{ .object = attr });
    }
    {
        var attr = std.json.ObjectMap.init(allocator);
        try json_utils.putOwnedKey(&attr, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "NotaryAssisted") });
        try json_utils.putOwnedKey(&attr, allocator, "nkeys", std.json.Value{ .integer = 3 });
        try attrs_array.append(std.json.Value{ .object = attr });
    }
    try json_utils.putOwnedKey(&tx_object, allocator, "attributes", std.json.Value{ .array = attrs_array });

    const tx_value = std.json.Value{ .object = tx_object };
    defer json_utils.freeValue(tx_value, allocator);

    var transaction = try Transaction.fromJson(tx_value, allocator);
    defer transaction.deinit(allocator);

    try testing.expectEqual(@as(usize, 3), transaction.attributes.len);
    try testing.expect(std.meta.activeTag(transaction.attributes[0]) == .NotValidBefore);
    try testing.expectEqual(@as(u32, 42), transaction.attributes[0].NotValidBefore.height);
    try testing.expect(std.meta.activeTag(transaction.attributes[1]) == .Conflicts);
    try testing.expect(std.meta.activeTag(transaction.attributes[2]) == .NotaryAssisted);
    try testing.expectEqual(@as(u8, 3), transaction.attributes[2].NotaryAssisted.n_keys);
}
