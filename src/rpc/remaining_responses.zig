//! Remaining Response Types
//!
//! Remaining protocol response types grouped into focused category modules.

const std = @import("std");

const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

pub const token = @import("remaining_token_responses.zig");
pub const node = @import("remaining_node_responses.zig");
pub const state = @import("remaining_state_responses.zig");
pub const misc = @import("remaining_misc_responses.zig");

pub const NeoGetTokenBalances = token.NeoGetTokenBalances;
pub const TokenBalances = token.TokenBalances;
pub const TokenBalance = token.TokenBalance;
pub const NeoGetTokenTransfers = token.NeoGetTokenTransfers;

pub const NeoGetVersion = node.NeoGetVersion;
pub const NeoSendRawTransaction = node.NeoSendRawTransaction;

pub const NeoFindStates = state.NeoFindStates;
pub const NeoGetUnspents = state.NeoGetUnspents;

pub const TransactionAttributeResponse = misc.TransactionAttributeResponse;
pub const NotificationResponse = misc.NotificationResponse;
pub const ResponseAliases = misc.ResponseAliases;
pub const ExpressShutdownResponse = misc.ExpressShutdownResponse;
pub const DiagnosticsResponse = misc.DiagnosticsResponse;

pub const NeoGetWalletUnclaimedGas = ResponseAliases.NeoGetWalletUnclaimedGas;
pub const NeoGetProof = ResponseAliases.NeoGetProof;

test "Generic token balance responses" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test generic token balances
    const TestBalance = struct {
        asset_hash: Hash160,
        amount: []const u8,

        pub fn fromJson(json_value: std.json.Value, alloc: std.mem.Allocator) !@This() {
            _ = alloc;
            const obj = json_value.object;
            return @This(){
                .asset_hash = try Hash160.initWithString(obj.get("assethash").?.string),
                .amount = obj.get("amount").?.string,
            };
        }
    };

    const TestBalances = TokenBalances(TestBalance);
    const test_balances = TestBalances.init("test_address", &[_]TestBalance{});

    try testing.expectEqualStrings("test_address", test_balances.getAddress());
    try testing.expectEqual(@as(usize, 0), test_balances.getBalanceCount());
    try testing.expect(!test_balances.hasBalances());
}

test "remaining response module exposes category namespaces" {
    const testing = std.testing;

    try testing.expect(token.NeoGetTokenTransfers == NeoGetTokenTransfers);
    try testing.expect(node.NeoGetVersion == NeoGetVersion);
    try testing.expect(state.NeoFindStates == NeoFindStates);
    try testing.expect(misc.DiagnosticsResponse == DiagnosticsResponse);
}

test "Neo version response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test version response
    const version_response = NeoGetVersion.init();
    try testing.expectEqual(@as(u16, 0), version_response.tcp_port);
    try testing.expectEqual(@as(u16, 0), version_response.ws_port);
    try testing.expectEqual(@as(u32, 0), version_response.nonce);
    try testing.expectEqualStrings("", version_response.user_agent);

    // Test protocol settings
    const protocol_settings = NeoGetVersion.ProtocolSettings.init();
    try testing.expectEqual(@as(u32, 0), protocol_settings.network);
    try testing.expectEqual(@as(u8, 0), protocol_settings.address_version);
}

test "Transaction and state responses" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test send raw transaction response
    const send_response = NeoSendRawTransaction.init();
    try testing.expect(send_response.hash.eql(Hash256.ZERO));

    // Test find states response
    const find_states = NeoFindStates.init();
    try testing.expect(find_states.first_proof == null);
    try testing.expect(find_states.last_proof == null);
    try testing.expect(!find_states.truncated);
    try testing.expectEqual(@as(usize, 0), find_states.results.len);

    // Test state result
    const state_result = NeoFindStates.StateResult.init();
    try testing.expectEqual(@as(usize, 0), state_result.key.len);
    try testing.expectEqual(@as(usize, 0), state_result.value.len);

    // Test unspents response
    const unspents = NeoGetUnspents.init();
    try testing.expectEqual(@as(usize, 0), unspents.balance.len);
    try testing.expectEqualStrings("", unspents.address);
}

test "Response type registry" {
    const testing = std.testing;

    // Test response type registry
    try testing.expect(ResponseAliases.ResponseTypeRegistry.isMethodSupported("getbestblockhash"));
    try testing.expect(ResponseAliases.ResponseTypeRegistry.isMethodSupported("getblockcount"));
    try testing.expect(ResponseAliases.ResponseTypeRegistry.isMethodSupported("invokefunction"));
    try testing.expect(ResponseAliases.ResponseTypeRegistry.isMethodSupported("getnep17balances"));

    try testing.expect(!ResponseAliases.ResponseTypeRegistry.isMethodSupported("invalid_method"));
    try testing.expect(!ResponseAliases.ResponseTypeRegistry.isMethodSupported(""));
}

test "Diagnostics and utility responses" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test diagnostics response
    const diagnostics = DiagnosticsResponse.init();
    try testing.expectEqual(@as(usize, 0), diagnostics.invocation_id.len);
    try testing.expectEqual(@as(u32, 0), diagnostics.invocation_counter);
    try testing.expectEqual(@as(u64, 0), diagnostics.execution_time);
    try testing.expectEqualStrings("0", diagnostics.gas_consumed);

    // Test express shutdown response
    const shutdown = ExpressShutdownResponse.init();
    try testing.expectEqual(@as(u32, 0), shutdown.process_id);
    try testing.expectEqual(@as(usize, 0), shutdown.message.len);
}

test "Remaining response fromJson smoke tests" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const hash160_str = "1234567890abcdef1234567890abcdef12345678";
    const hash256_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // TokenBalances generic fromJson
    const TestBalance = struct {
        asset_hash: Hash160,
        amount: []const u8,

        pub fn fromJson(json_value: std.json.Value, alloc: std.mem.Allocator) !@This() {
            _ = alloc;
            const obj = json_value.object;
            return @This(){
                .asset_hash = try Hash160.initWithString(obj.get("assethash").?.string),
                .amount = obj.get("amount").?.string,
            };
        }
    };

    var balance_obj = std.json.ObjectMap.init(allocator);
    try balance_obj.put("assethash", std.json.Value{ .string = hash160_str });
    try balance_obj.put("amount", std.json.Value{ .string = "100" });

    var balance_array = std.json.Array.init(allocator);
    try balance_array.append(std.json.Value{ .object = balance_obj });

    var balances_obj = std.json.ObjectMap.init(allocator);
    try balances_obj.put("address", std.json.Value{ .string = "test_address" });
    try balances_obj.put("balance", std.json.Value{ .array = balance_array });

    const ParsedBalances = TokenBalances(TestBalance);
    const parsed_balances = try ParsedBalances.fromJson(std.json.Value{ .object = balances_obj }, allocator);
    try testing.expectEqualStrings("test_address", parsed_balances.address);
    try testing.expectEqual(@as(usize, 1), parsed_balances.balances.len);

    // NeoGetTokenTransfers fromJson
    var transfer_obj = std.json.ObjectMap.init(allocator);
    try transfer_obj.put("timestamp", std.json.Value{ .integer = 1640995200 });
    try transfer_obj.put("assethash", std.json.Value{ .string = hash160_str });
    try transfer_obj.put("transferaddress", std.json.Value{ .string = "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7" });
    try transfer_obj.put("amount", std.json.Value{ .string = "1" });
    try transfer_obj.put("blockindex", std.json.Value{ .integer = 1 });
    try transfer_obj.put("transfernotifyindex", std.json.Value{ .integer = 0 });
    try transfer_obj.put("txhash", std.json.Value{ .string = hash256_str });

    var sent_array = std.json.Array.init(allocator);
    try sent_array.append(std.json.Value{ .object = transfer_obj });

    var received_array = std.json.Array.init(allocator);
    try received_array.append(std.json.Value{ .object = transfer_obj });

    var transfers_obj = std.json.ObjectMap.init(allocator);
    try transfers_obj.put("address", std.json.Value{ .string = "test_address" });
    try transfers_obj.put("sent", std.json.Value{ .array = sent_array });
    try transfers_obj.put("received", std.json.Value{ .array = received_array });

    const parsed_transfers = try NeoGetTokenTransfers.fromJson(std.json.Value{ .object = transfers_obj }, allocator);
    try testing.expectEqual(@as(usize, 1), parsed_transfers.sent.len);
    try testing.expectEqual(@as(usize, 1), parsed_transfers.received.len);

    // NeoFindStates fromJson
    var result_obj = std.json.ObjectMap.init(allocator);
    try result_obj.put("key", std.json.Value{ .string = "01" });
    try result_obj.put("value", std.json.Value{ .string = "02" });

    var results_array = std.json.Array.init(allocator);
    try results_array.append(std.json.Value{ .object = result_obj });

    var find_states_obj = std.json.ObjectMap.init(allocator);
    try find_states_obj.put("firstproof", std.json.Value{ .string = "first" });
    try find_states_obj.put("lastproof", std.json.Value{ .string = "last" });
    try find_states_obj.put("truncated", std.json.Value{ .bool = false });
    try find_states_obj.put("results", std.json.Value{ .array = results_array });

    const parsed_states = try NeoFindStates.fromJson(std.json.Value{ .object = find_states_obj }, allocator);
    try testing.expect(!parsed_states.truncated);
    try testing.expectEqual(@as(usize, 1), parsed_states.results.len);

    // NeoGetUnspents fromJson
    var unspent_obj = std.json.ObjectMap.init(allocator);
    try unspent_obj.put("txid", std.json.Value{ .string = hash256_str });
    try unspent_obj.put("n", std.json.Value{ .integer = 0 });
    try unspent_obj.put("asset", std.json.Value{ .string = hash160_str });
    try unspent_obj.put("value", std.json.Value{ .string = "1" });
    try unspent_obj.put("address", std.json.Value{ .string = "test_address" });

    var unspent_array = std.json.Array.init(allocator);
    try unspent_array.append(std.json.Value{ .object = unspent_obj });

    var unspents_obj = std.json.ObjectMap.init(allocator);
    try unspents_obj.put("address", std.json.Value{ .string = "test_address" });
    try unspents_obj.put("balance", std.json.Value{ .array = unspent_array });

    const parsed_unspents = try NeoGetUnspents.fromJson(std.json.Value{ .object = unspents_obj }, allocator);
    try testing.expectEqual(@as(usize, 1), parsed_unspents.balance.len);

    // NotificationResponse fromJson
    var stack_item_obj = std.json.ObjectMap.init(allocator);
    try stack_item_obj.put("type", std.json.Value{ .string = "ByteString" });
    try stack_item_obj.put("value", std.json.Value{ .string = "SGVsbG8=" }); // "Hello" in base64

    var state_array = std.json.Array.init(allocator);
    try state_array.append(std.json.Value{ .object = stack_item_obj });

    var notification_obj = std.json.ObjectMap.init(allocator);
    try notification_obj.put("contract", std.json.Value{ .string = hash160_str });
    try notification_obj.put("eventname", std.json.Value{ .string = "Transfer" });
    try notification_obj.put("state", std.json.Value{ .array = state_array });

    var parsed_notification = try NotificationResponse.fromJson(std.json.Value{ .object = notification_obj }, allocator);
    try testing.expectEqualStrings("Transfer", parsed_notification.event_name);
    try testing.expectEqual(@as(usize, 1), parsed_notification.state.len);
    parsed_notification.deinit(allocator);
}
