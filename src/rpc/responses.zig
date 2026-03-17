//! RPC Response Types
//!
//! Neo N3
//! Handles all Neo RPC response parsing and serialization.

const std = @import("std");
const json_utils = @import("../utils/json_utils.zig");

const Hash256 = @import("../types/hash256.zig").Hash256;
const errors = @import("../core/errors.zig");

pub const blockchain = @import("responses_blockchain.zig");
pub const invocation = @import("responses_invocation.zig");
pub const token = @import("responses_token.zig");
pub const contract = @import("responses_contract.zig");

pub const StackItem = @import("../types/stack_item.zig").StackItem;
pub const TransactionAttribute = @import("../protocol/response/transaction_attribute.zig").TransactionAttribute;

pub const NeoBlock = blockchain.NeoBlock;
pub const NeoWitness = blockchain.NeoWitness;
pub const Transaction = blockchain.Transaction;
pub const TransactionSigner = blockchain.TransactionSigner;
pub const WitnessRule = blockchain.WitnessRule;
pub const WitnessCondition = blockchain.WitnessCondition;
pub const NeoVersion = blockchain.NeoVersion;
pub const HardforkInfo = blockchain.HardforkInfo;
pub const ProtocolConfiguration = blockchain.ProtocolConfiguration;
pub const NetworkFeeResponse = blockchain.NetworkFeeResponse;
pub const SendRawTransactionResponse = blockchain.SendRawTransactionResponse;

pub const InvocationResult = invocation.InvocationResult;
pub const NeoApplicationLog = invocation.NeoApplicationLog;
pub const Execution = invocation.Execution;
pub const Notification = invocation.Notification;

pub const Nep17Balances = token.Nep17Balances;
pub const TokenBalance = token.TokenBalance;
pub const Nep17Transfers = token.Nep17Transfers;
pub const TokenTransfer = token.TokenTransfer;

pub const ContractState = contract.ContractState;
pub const ContractNef = contract.ContractNef;
pub const ContractFeatures = contract.ContractFeatures;
pub const ContractManifest = contract.ContractManifest;
pub const ContractGroup = contract.ContractGroup;
pub const ContractParameterDefinition = contract.ContractParameterDefinition;
pub const ContractMethod = contract.ContractMethod;
pub const ContractEvent = contract.ContractEvent;
pub const ContractABI = contract.ContractABI;
pub const ContractPermission = contract.ContractPermission;

test "responses module exposes category namespaces" {
    const testing = std.testing;

    try testing.expect(blockchain.NeoBlock == NeoBlock);
    try testing.expect(invocation.InvocationResult == InvocationResult);
    try testing.expect(token.Nep17Balances == Nep17Balances);
    try testing.expect(contract.ContractState == ContractState);
}

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
