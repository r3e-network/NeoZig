//! Complete RPC Response Types
//!
//! Protocol response types
//! Ensures complete protocol coverage.

const std = @import("std");
const json_utils = @import("../utils/json_utils.zig");

const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

pub const account = @import("extended_account_responses.zig");
pub const oracle = @import("extended_oracle_responses.zig");
pub const network = @import("extended_network_responses.zig");
pub const system = @import("extended_system_responses.zig");

pub const NeoAccountState = account.NeoAccountState;
pub const NeoAddress = account.NeoAddress;
pub const TransactionSendToken = account.TransactionSendToken;
pub const NeoGetUnclaimedGas = account.NeoGetUnclaimedGas;
pub const Nep17Contract = account.Nep17Contract;
pub const NeoValidateAddress = account.NeoValidateAddress;

pub const OracleRequest = oracle.OracleRequest;
pub const ContractMethodToken = oracle.ContractMethodToken;
pub const NameState = oracle.NameState;
pub const RecordState = oracle.RecordState;
pub const OracleResponseCode = oracle.OracleResponseCode;

pub const NeoGetNextBlockValidators = network.NeoGetNextBlockValidators;
pub const NeoGetStateHeight = network.NeoGetStateHeight;
pub const NeoGetStateRoot = network.NeoGetStateRoot;
pub const NeoWitness = network.NeoWitness;
pub const NeoNetworkFee = network.NeoNetworkFee;
pub const PopulatedBlocks = network.PopulatedBlocks;

pub const NeoListPlugins = system.NeoListPlugins;
pub const NativeContractState = system.NativeContractState;
pub const ExpressContractState = system.ExpressContractState;
pub const ExpressShutdown = system.ExpressShutdown;
pub const Diagnostics = system.Diagnostics;
pub const ContractStorageEntry = system.ContractStorageEntry;

test "extended responses module exposes category namespaces" {
    const testing = std.testing;

    try testing.expect(account.NeoAccountState == NeoAccountState);
    try testing.expect(oracle.OracleRequest == OracleRequest);
    try testing.expect(network.NeoGetStateRoot == NeoGetStateRoot);
    try testing.expect(system.NeoListPlugins == NeoListPlugins);
}

test "NeoAccountState response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    const account_state = NeoAccountState.init(100000000, 12345, "02b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816");

    try testing.expectEqual(@as(i64, 100000000), account_state.balance);
    try testing.expectEqual(@as(u32, 12345), account_state.balance_height.?);
    try testing.expect(account_state.public_key != null);

    const no_vote_state = NeoAccountState.withNoVote(50000000, 54321);
    try testing.expectEqual(@as(i64, 50000000), no_vote_state.balance);
    try testing.expect(no_vote_state.public_key == null);

    const no_balance_state = NeoAccountState.withNoBalance();
    try testing.expectEqual(@as(i64, 0), no_balance_state.balance);
    try testing.expect(no_balance_state.balance_height == null);
}

test "Oracle response types" {
    const testing = std.testing;
    _ = testing.allocator;

    const oracle_request = OracleRequest.init();
    try testing.expectEqual(@as(usize, 0), oracle_request.url.len);
    try testing.expect(oracle_request.filter == null);

    try testing.expectEqual(@as(u8, 0x00), OracleResponseCode.Success.getByte());
    try testing.expectEqual(@as(u8, 0x14), OracleResponseCode.NotFound.getByte());
    try testing.expectEqual(@as(u8, 0xff), OracleResponseCode.Error.getByte());

    try testing.expectEqualStrings("Success", OracleResponseCode.Success.getJsonValue());
    try testing.expectEqualStrings("NotFound", OracleResponseCode.NotFound.getJsonValue());

    try testing.expectEqual(OracleResponseCode.Success, OracleResponseCode.fromByte(0x00).?);
    try testing.expectEqual(OracleResponseCode.NotFound, OracleResponseCode.fromByte(0x14).?);
    try testing.expectEqual(@as(?OracleResponseCode, null), OracleResponseCode.fromByte(0x99));
}

test "Validator and network response types" {
    const testing = std.testing;
    _ = testing.allocator;

    const validator = NeoGetNextBlockValidators.Validator.init();
    try testing.expectEqual(@as(usize, 0), validator.public_key.len);
    try testing.expectEqualStrings("0", validator.votes);
    try testing.expect(!validator.active);

    const validators = NeoGetNextBlockValidators.init();
    try testing.expectEqual(@as(usize, 0), validators.validators.len);

    const state_height = NeoGetStateHeight.init();
    try testing.expectEqual(@as(u32, 0), state_height.local_root_index);
    try testing.expectEqual(@as(u32, 0), state_height.validated_root_index);
}

test "Transaction and contract response types" {
    const testing = std.testing;
    _ = testing.allocator;

    const send_token = TransactionSendToken.init(
        Hash160.ZERO,
        100000000,
        "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7",
    );

    try testing.expect(send_token.asset.eql(Hash160.ZERO));
    try testing.expectEqual(@as(i64, 100000000), send_token.value);

    const method_token = ContractMethodToken.init();
    try testing.expect(method_token.hash.eql(Hash160.ZERO));
    try testing.expectEqual(@as(usize, 0), method_token.method.len);
    try testing.expectEqual(@as(u16, 0), method_token.parameters_count);

    const nep17_contract = Nep17Contract.init(Hash160.ZERO, "TEST", 8);
    try testing.expectEqualStrings("TEST", nep17_contract.symbol);
    try testing.expectEqual(@as(u8, 8), nep17_contract.decimals);
}

test "State and diagnostic response types" {
    const testing = std.testing;
    _ = testing.allocator;

    const state_root = NeoGetStateRoot.init();
    try testing.expectEqual(@as(u8, 0), state_root.version);
    try testing.expectEqual(@as(u32, 0), state_root.index);
    try testing.expect(state_root.root_hash.eql(Hash256.ZERO));

    const record_state = RecordState.init();
    try testing.expectEqual(@as(usize, 0), record_state.name.len);
    try testing.expectEqual(@as(usize, 0), record_state.record_type.len);

    const diagnostics = Diagnostics.init();
    try testing.expectEqual(@as(usize, 0), diagnostics.invocation_id.len);
    try testing.expectEqual(@as(u32, 0), diagnostics.invocation_counter);
}

test "Complete response fromJson smoke tests" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var interfaces_array = std.json.Array.init(allocator);
    try interfaces_array.append(std.json.Value{ .string = "IPlugin" });
    try interfaces_array.append(std.json.Value{ .string = "ILogging" });

    var plugin_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&plugin_obj, allocator, "name", std.json.Value{ .string = "RpcServer" });
    try json_utils.putOwnedKey(&plugin_obj, allocator, "version", std.json.Value{ .string = "1.0.1" });
    try json_utils.putOwnedKey(&plugin_obj, allocator, "interfaces", std.json.Value{ .array = interfaces_array });

    var plugins_array = std.json.Array.init(allocator);
    try plugins_array.append(std.json.Value{ .object = plugin_obj });

    const parsed_plugins = try NeoListPlugins.fromJson(std.json.Value{ .array = plugins_array }, allocator);
    try testing.expectEqual(@as(usize, 1), parsed_plugins.plugins.len);
    try testing.expectEqualStrings("RpcServer", parsed_plugins.plugins[0].name);
    try testing.expectEqual(@as(usize, 2), parsed_plugins.plugins[0].interfaces.len);

    var blocks_array = std.json.Array.init(allocator);
    try blocks_array.append(std.json.Value{ .integer = 1 });
    try blocks_array.append(std.json.Value{ .integer = 2 });

    var blocks_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&blocks_obj, allocator, "count", std.json.Value{ .integer = 2 });
    try json_utils.putOwnedKey(&blocks_obj, allocator, "blocks", std.json.Value{ .array = blocks_array });

    const populated = try PopulatedBlocks.fromJson(std.json.Value{ .object = blocks_obj }, allocator);
    try testing.expectEqual(@as(u32, 2), populated.count);
    try testing.expectEqual(@as(usize, 2), populated.blocks.len);

    var witnesses_array = std.json.Array.init(allocator);
    var witness_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&witness_obj, allocator, "invocation", std.json.Value{ .string = "00" });
    try json_utils.putOwnedKey(&witness_obj, allocator, "verification", std.json.Value{ .string = "01" });
    try witnesses_array.append(std.json.Value{ .object = witness_obj });

    var state_root_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&state_root_obj, allocator, "version", std.json.Value{ .integer = 0 });
    try json_utils.putOwnedKey(&state_root_obj, allocator, "index", std.json.Value{ .integer = 1 });
    try json_utils.putOwnedKey(
        &state_root_obj,
        allocator,
        "roothash",
        std.json.Value{ .string = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
    );
    try json_utils.putOwnedKey(&state_root_obj, allocator, "witnesses", std.json.Value{ .array = witnesses_array });

    const parsed_state_root = try NeoGetStateRoot.fromJson(std.json.Value{ .object = state_root_obj }, allocator);
    try testing.expectEqual(@as(usize, 1), parsed_state_root.witnesses.len);

    var validators_array = std.json.Array.init(allocator);
    var validator_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&validator_obj, allocator, "publickey", std.json.Value{ .string = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816" });
    try json_utils.putOwnedKey(&validator_obj, allocator, "votes", std.json.Value{ .string = "42" });
    try json_utils.putOwnedKey(&validator_obj, allocator, "active", std.json.Value{ .bool = true });
    try validators_array.append(std.json.Value{ .object = validator_obj });

    const parsed_validators = try NeoGetNextBlockValidators.fromJson(std.json.Value{ .array = validators_array }, allocator);
    try testing.expectEqual(@as(usize, 1), parsed_validators.validators.len);
    try testing.expectEqualStrings("42", parsed_validators.validators[0].votes);

    var nef_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&nef_obj, allocator, "magic", std.json.Value{ .integer = 123 });
    try json_utils.putOwnedKey(&nef_obj, allocator, "compiler", std.json.Value{ .string = "neo-zig-test" });
    try json_utils.putOwnedKey(&nef_obj, allocator, "script", std.json.Value{ .string = "00" });
    try json_utils.putOwnedKey(&nef_obj, allocator, "checksum", std.json.Value{ .integer = 1 });

    var manifest_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&manifest_obj, allocator, "name", std.json.Value{ .string = "TestContract" });

    var update_history_array = std.json.Array.init(allocator);
    try update_history_array.append(std.json.Value{ .integer = 1 });
    try update_history_array.append(std.json.Value{ .integer = 2 });

    var native_contract_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&native_contract_obj, allocator, "id", std.json.Value{ .integer = 1 });
    try json_utils.putOwnedKey(&native_contract_obj, allocator, "hash", std.json.Value{ .string = "1234567890abcdef1234567890abcdef12345678" });
    try json_utils.putOwnedKey(&native_contract_obj, allocator, "nef", std.json.Value{ .object = nef_obj });
    try json_utils.putOwnedKey(&native_contract_obj, allocator, "manifest", std.json.Value{ .object = manifest_obj });
    try json_utils.putOwnedKey(&native_contract_obj, allocator, "updatehistory", std.json.Value{ .array = update_history_array });

    var native_contract = try NativeContractState.fromJson(std.json.Value{ .object = native_contract_obj }, allocator);
    try testing.expectEqual(@as(i32, 1), native_contract.id);
    try testing.expectEqual(@as(usize, 2), native_contract.update_history.len);
    native_contract.deinit(allocator);
}
