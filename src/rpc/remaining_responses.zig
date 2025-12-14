//! Remaining Response Types
//!
//! Complete conversion of ALL remaining Swift protocol response types
//! Ensures absolute 100% protocol coverage.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const StackItem = @import("../types/stack_item.zig").StackItem;

/// Generic token balances response (converted from Swift NeoGetTokenBalances)
pub fn NeoGetTokenBalances(comptime T: type) type {
    return struct {
        result: ?T,

        const Self = @This();

        pub fn init() Self {
            return Self{ .result = null };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            return Self{
                .result = try T.fromJson(json_value, allocator),
            };
        }

        pub fn getBalances(self: Self) ?T {
            return self.result;
        }
    };
}

/// Token balances protocol trait (converted from Swift TokenBalances protocol)
pub fn TokenBalances(comptime BalanceType: type) type {
    return struct {
        address: []const u8,
        balances: []const BalanceType,

        const Self = @This();

        pub fn init(address: []const u8, balances: []const BalanceType) Self {
            return Self{
                .address = address,
                .balances = balances,
            };
        }

        pub fn getAddress(self: Self) []const u8 {
            return self.address;
        }

        pub fn getBalances(self: Self) []const BalanceType {
            return self.balances;
        }

        pub fn getBalanceCount(self: Self) usize {
            return self.balances.len;
        }

        pub fn hasBalances(self: Self) bool {
            return self.balances.len > 0;
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            if (json_value != .object) return errors.SerializationError.InvalidFormat;
            const obj = json_value.object;

            const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
            if (address_value != .string) return errors.SerializationError.InvalidFormat;
            const address = try allocator.dupe(u8, address_value.string);
            errdefer allocator.free(address);

            var balance_list = ArrayList(BalanceType).init(allocator);
            errdefer balance_list.deinit();
            if (obj.get("balance")) |balance_array| {
                if (balance_array != .array) return errors.SerializationError.InvalidFormat;
                for (balance_array.array.items) |balance_item| {
                    try balance_list.append(try BalanceType.fromJson(balance_item, allocator));
                }
            }

            return Self.init(address, try balance_list.toOwnedSlice());
        }
    };
}

/// Token balance protocol trait (converted from Swift TokenBalance protocol)
pub fn TokenBalance(comptime T: type) type {
    return struct {
        pub fn getAssetHash(self: T) Hash160 {
            return self.asset_hash;
        }

        pub fn hasAssetHash(self: T) bool {
            return !self.asset_hash.eql(Hash160.ZERO);
        }

        pub fn getAmount(self: T) []const u8 {
            return self.amount;
        }

        pub fn getAmountAsInt(self: T) !i64 {
            return std.fmt.parseInt(i64, self.amount, 10) catch {
                return errors.ValidationError.InvalidParameter;
            };
        }
    };
}

/// Neo get token transfers (converted from Swift NeoGetTokenTransfers)
pub const NeoGetTokenTransfers = struct {
    address: []const u8,
    sent: []const TokenTransfer,
    received: []const TokenTransfer,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .address = "",
            .sent = &[_]TokenTransfer{},
            .received = &[_]TokenTransfer{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
        if (address_value != .string) return errors.SerializationError.InvalidFormat;
        const address = try allocator.dupe(u8, address_value.string);
        errdefer allocator.free(address);

        var sent_list = ArrayList(TokenTransfer).init(allocator);
        errdefer sent_list.deinit();
        if (obj.get("sent")) |sent_array| {
            if (sent_array != .array) return errors.SerializationError.InvalidFormat;
            for (sent_array.array.items) |sent_item| {
                try sent_list.append(try TokenTransfer.fromJson(sent_item, allocator));
            }
        }

        var received_list = ArrayList(TokenTransfer).init(allocator);
        errdefer received_list.deinit();
        if (obj.get("received")) |received_array| {
            if (received_array != .array) return errors.SerializationError.InvalidFormat;
            for (received_array.array.items) |received_item| {
                try received_list.append(try TokenTransfer.fromJson(received_item, allocator));
            }
        }

        return Self{ .address = address, .sent = try sent_list.toOwnedSlice(), .received = try received_list.toOwnedSlice() };
    }

    /// Generic token transfer (base class)
    pub const TokenTransfer = struct {
        timestamp: u64,
        asset_hash: Hash160,
        transfer_address: []const u8,
        amount: []const u8,
        block_index: u32,
        transfer_notify_index: u32,
        tx_hash: Hash256,

        pub fn init() TokenTransfer {
            return std.mem.zeroes(TokenTransfer);
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TokenTransfer {
            const obj = json_value.object;

            return TokenTransfer{
                .timestamp = @intCast(obj.get("timestamp").?.integer),
                .asset_hash = try Hash160.initWithString(obj.get("assethash").?.string),
                .transfer_address = try allocator.dupe(u8, obj.get("transferaddress").?.string),
                .amount = try allocator.dupe(u8, obj.get("amount").?.string),
                .block_index = @intCast(obj.get("blockindex").?.integer),
                .transfer_notify_index = @intCast(obj.get("transfernotifyindex").?.integer),
                .tx_hash = try Hash256.initWithString(obj.get("txhash").?.string),
            };
        }
    };
};

pub const NeoGetWalletUnclaimedGas = ResponseAliases.NeoGetWalletUnclaimedGas;
pub const NeoGetProof = ResponseAliases.NeoGetProof;

/// Neo get version response (converted from Swift NeoGetVersion)
pub const NeoGetVersion = struct {
    tcp_port: u16,
    ws_port: u16,
    nonce: u32,
    user_agent: []const u8,
    protocol: ?ProtocolSettings,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .tcp_port = 0,
            .ws_port = 0,
            .nonce = 0,
            .user_agent = "",
            .protocol = null,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        return Self{
            .tcp_port = @intCast(obj.get("tcpport").?.integer),
            // Some nodes omit `wsport` when WebSocket is disabled.
            .ws_port = if (obj.get("wsport")) |port| @intCast(port.integer) else 0,
            .nonce = @intCast(obj.get("nonce").?.integer),
            .user_agent = try allocator.dupe(u8, obj.get("useragent").?.string),
            .protocol = if (obj.get("protocol")) |p| try ProtocolSettings.fromJson(p, allocator) else null,
        };
    }

    /// Protocol settings (converted from Swift protocol data)
    pub const ProtocolSettings = struct {
        network: u32,
        address_version: u8,
        validators_count: ?u32,
        ms_per_block: ?u32,
        max_valid_until_block_increment: ?u32,
        max_traceable_blocks: ?u32,
        max_transactions_per_block: ?u32,
        memory_pool_max_transactions: ?u32,
        initial_gas_distribution: ?u64,

        pub fn init() ProtocolSettings {
            return ProtocolSettings{
                .network = 0,
                .address_version = 0,
                .validators_count = null,
                .ms_per_block = null,
                .max_valid_until_block_increment = null,
                .max_traceable_blocks = null,
                .max_transactions_per_block = null,
                .memory_pool_max_transactions = null,
                .initial_gas_distribution = null,
            };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ProtocolSettings {
            _ = allocator;
            const obj = json_value.object;

            return ProtocolSettings{
                .network = @intCast(obj.get("network").?.integer),
                .address_version = @intCast(obj.get("addressversion").?.integer),
                .validators_count = try parseOptionalInt(u32, obj, "validatorscount"),
                .ms_per_block = try parseOptionalInt(u32, obj, "msperblock"),
                .max_valid_until_block_increment = try parseOptionalInt(u32, obj, "maxvaliduntilblockincrement"),
                .max_traceable_blocks = try parseOptionalInt(u32, obj, "maxtraceableblocks"),
                .max_transactions_per_block = try parseOptionalInt(u32, obj, "maxtransactionsperblock"),
                .memory_pool_max_transactions = try parseOptionalInt(u32, obj, "memorypoolmaxtransactions"),
                .initial_gas_distribution = try parseOptionalInt(u64, obj, "initialgasdistribution"),
            };
        }

        fn parseOptionalInt(comptime T: type, obj: std.json.ObjectMap, key: []const u8) !?T {
            const value = obj.get(key) orelse return null;
            return switch (value) {
                .integer => |i| @as(T, @intCast(i)),
                .string => |s| std.fmt.parseInt(T, s, 10) catch errors.SerializationError.InvalidFormat,
                .null => null,
                else => errors.SerializationError.InvalidFormat,
            };
        }
    };
};

/// Neo send raw transaction response (converted from Swift NeoSendRawTransaction)
pub const NeoSendRawTransaction = struct {
    hash: Hash256,

    pub fn init() NeoSendRawTransaction {
        return NeoSendRawTransaction{ .hash = Hash256.ZERO };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoSendRawTransaction {
        _ = allocator;
        const obj = json_value.object;

        return NeoSendRawTransaction{
            .hash = try Hash256.initWithString(obj.get("hash").?.string),
        };
    }
};

/// Neo find states response (converted from Swift NeoFindStates)
pub const NeoFindStates = struct {
    first_proof: ?[]const u8,
    last_proof: ?[]const u8,
    truncated: bool,
    results: []const StateResult,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .first_proof = null,
            .last_proof = null,
            .truncated = false,
            .results = &[_]StateResult{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const first_proof = if (obj.get("firstproof")) |fp| blk: {
            if (fp != .string) return errors.SerializationError.InvalidFormat;
            break :blk try allocator.dupe(u8, fp.string);
        } else null;
        errdefer if (first_proof) |value| allocator.free(@constCast(value));

        const last_proof = if (obj.get("lastproof")) |lp| blk: {
            if (lp != .string) return errors.SerializationError.InvalidFormat;
            break :blk try allocator.dupe(u8, lp.string);
        } else null;
        errdefer if (last_proof) |value| allocator.free(@constCast(value));

        const truncated_value = obj.get("truncated") orelse return errors.SerializationError.InvalidFormat;
        if (truncated_value != .bool) return errors.SerializationError.InvalidFormat;
        const truncated = truncated_value.bool;

        var results = ArrayList(StateResult).init(allocator);
        errdefer results.deinit();
        if (obj.get("results")) |results_array| {
            if (results_array != .array) return errors.SerializationError.InvalidFormat;
            for (results_array.array.items) |result_item| {
                try results.append(try StateResult.fromJson(result_item, allocator));
            }
        }

        return Self{ .first_proof = first_proof, .last_proof = last_proof, .truncated = truncated, .results = try results.toOwnedSlice() };
    }

    /// State result entry
    pub const StateResult = struct {
        key: []const u8,
        value: []const u8,

        pub fn init() StateResult {
            return StateResult{ .key = "", .value = "" };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !StateResult {
            const obj = json_value.object;

            return StateResult{
                .key = try allocator.dupe(u8, obj.get("key").?.string),
                .value = try allocator.dupe(u8, obj.get("value").?.string),
            };
        }
    };
};

/// Neo get unspents response (converted from Swift NeoGetUnspents)
pub const NeoGetUnspents = struct {
    balance: []const UnspentOutput,
    address: []const u8,

    pub fn init() NeoGetUnspents {
        return NeoGetUnspents{
            .balance = &[_]UnspentOutput{},
            .address = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetUnspents {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
        if (address_value != .string) return errors.SerializationError.InvalidFormat;
        const address = try allocator.dupe(u8, address_value.string);
        errdefer allocator.free(address);

        var balance_list = ArrayList(UnspentOutput).init(allocator);
        errdefer balance_list.deinit();
        if (obj.get("balance")) |balance_array| {
            if (balance_array != .array) return errors.SerializationError.InvalidFormat;
            for (balance_array.array.items) |balance_item| {
                try balance_list.append(try UnspentOutput.fromJson(balance_item, allocator));
            }
        }

        return NeoGetUnspents{ .balance = try balance_list.toOwnedSlice(), .address = address };
    }

    /// Unspent output
    pub const UnspentOutput = struct {
        tx_id: Hash256,
        n: u32,
        asset: Hash160,
        value: []const u8,
        address: []const u8,

        pub fn init() UnspentOutput {
            return std.mem.zeroes(UnspentOutput);
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !UnspentOutput {
            const obj = json_value.object;

            return UnspentOutput{
                .tx_id = try Hash256.initWithString(obj.get("txid").?.string),
                .n = @intCast(obj.get("n").?.integer),
                .asset = try Hash160.initWithString(obj.get("asset").?.string),
                .value = try allocator.dupe(u8, obj.get("value").?.string),
                .address = try allocator.dupe(u8, obj.get("address").?.string),
            };
        }
    };
};

/// Transaction attribute response (converted from Swift TransactionAttribute response)
pub const TransactionAttributeResponse = struct {
    attribute_type: []const u8,
    value: []const u8,

    pub fn init() TransactionAttributeResponse {
        return TransactionAttributeResponse{
            .attribute_type = "",
            .value = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TransactionAttributeResponse {
        const obj = json_value.object;

        return TransactionAttributeResponse{
            .attribute_type = try allocator.dupe(u8, obj.get("type").?.string),
            .value = try allocator.dupe(u8, obj.get("value").?.string),
        };
    }
};

/// Notification response (converted from Swift Notification)
pub const NotificationResponse = struct {
    contract: Hash160,
    event_name: []const u8,
    state: []StackItem,

    pub fn init() NotificationResponse {
        return NotificationResponse{
            .contract = Hash160.ZERO,
            .event_name = "",
            .state = &[_]StackItem{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NotificationResponse {
        const obj = json_value.object;

        const contract = try Hash160.initWithString(obj.get("contract").?.string);
        const event_name = try allocator.dupe(u8, obj.get("eventname").?.string);
        errdefer allocator.free(event_name);

        var state_list = ArrayList(StackItem).init(allocator);
        errdefer {
            for (state_list.items) |*item| item.deinit(allocator);
            state_list.deinit();
        }
        if (obj.get("state")) |state_array| {
            if (state_array != .array) return errors.SerializationError.InvalidFormat;
            for (state_array.array.items) |state_item| {
                var decoded = try StackItem.decodeFromJson(state_item, allocator);
                var decoded_guard = true;
                defer if (decoded_guard) decoded.deinit(allocator);
                try state_list.append(decoded);
                decoded_guard = false;
            }
        }

        return NotificationResponse{
            .contract = contract,
            .event_name = event_name,
            .state = try state_list.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *NotificationResponse, allocator: std.mem.Allocator) void {
        if (self.event_name.len > 0) allocator.free(@constCast(self.event_name));
        if (self.state.len > 0) {
            for (self.state) |*item| {
                item.deinit(allocator);
            }
            allocator.free(self.state);
        }
    }
};

/// Response aliases and specialized types (converted from Swift NeoResponseAliases)
pub const ResponseAliases = struct {
    // Blockchain response aliases
    pub const NeoBlockHash = Hash256;
    pub const NeoBlockCount = u32;
    pub const NeoBlockHeaderCount = u32;
    pub const NeoConnectionCount = u32;

    // Transaction response aliases
    pub const NeoGetRawTransaction = []const u8;
    pub const NeoGetRawBlock = []const u8;
    pub const NeoSubmitBlock = bool;
    pub const NeoCalculateNetworkFee = u64;

    // Wallet response aliases
    pub const NeoCloseWallet = bool;
    pub const NeoDumpPrivKey = []const u8;
    pub const NeoGetNewAddress = []const u8;
    pub const NeoGetWalletUnclaimedGas = []const u8;
    pub const NeoImportPrivKey = @import("complete_responses.zig").NeoAddress;
    pub const NeoOpenWallet = bool;
    pub const NeoSendFrom = @import("responses.zig").Transaction;
    pub const NeoSendMany = @import("responses.zig").Transaction;
    pub const NeoSendToAddress = @import("responses.zig").Transaction;

    // Contract response aliases
    pub const NeoGetContractState = @import("responses.zig").ContractState;
    pub const NeoGetNativeContracts = []const @import("complete_responses.zig").NativeContractState;
    pub const NeoInvokeFunction = @import("responses.zig").InvocationResult;
    pub const NeoInvokeScript = @import("responses.zig").InvocationResult;
    pub const NeoInvokeContractVerify = @import("responses.zig").InvocationResult;
    pub const NeoTraverseIterator = []StackItem;
    pub const NeoTerminateSession = bool;

    // State service aliases
    pub const NeoGetStorage = []const u8;
    pub const NeoGetTransactionHeight = u32;
    pub const NeoGetProof = []const u8;
    pub const NeoVerifyProof = []const u8;
    pub const NeoGetState = []const u8;

    // Utility aliases
    pub const NeoGetCommittee = []const []const u8;

    /// Type registry for response parsing
    pub const ResponseTypeRegistry = struct {
        /// Gets response type by method name
        pub fn getResponseType(method: []const u8) type {
            if (std.mem.eql(u8, method, "getbestblockhash")) return NeoBlockHash;
            if (std.mem.eql(u8, method, "getblockcount")) return NeoBlockCount;
            if (std.mem.eql(u8, method, "getconnectioncount")) return NeoConnectionCount;
            if (std.mem.eql(u8, method, "getversion")) return NeoGetVersion;
            if (std.mem.eql(u8, method, "getnep17balances")) return @import("token_responses.zig").NeoGetNep17Balances;
            if (std.mem.eql(u8, method, "getnep11balances")) return @import("token_responses.zig").NeoGetNep11Balances;
            if (std.mem.eql(u8, method, "invokefunction")) return NeoInvokeFunction;
            if (std.mem.eql(u8, method, "sendrawtransaction")) return NeoSendRawTransaction;
            if (std.mem.eql(u8, method, "calculatenetworkfee")) return NeoCalculateNetworkFee;

            // Default to generic JSON value
            return std.json.Value;
        }

        /// Checks if method is supported
        pub fn isMethodSupported(method: []const u8) bool {
            const supported_methods = [_][]const u8{
                "getbestblockhash",  "getblockcount",     "getconnectioncount",  "getversion",
                "getblock",          "getblockhash",      "getrawtransaction",   "sendrawtransaction",
                "invokefunction",    "invokescript",      "getnep17balances",    "getnep11balances",
                "getnep17transfers", "getnep11transfers", "calculatenetworkfee", "validateaddress",
                "listplugins",       "getapplicationlog",
            };

            for (supported_methods) |supported| {
                if (std.mem.eql(u8, method, supported)) {
                    return true;
                }
            }

            return false;
        }
    };
};

/// Express shutdown response (converted from Swift ExpressShutdown)
pub const ExpressShutdownResponse = struct {
    process_id: u32,
    message: []const u8,

    pub fn init() ExpressShutdownResponse {
        return ExpressShutdownResponse{
            .process_id = 0,
            .message = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ExpressShutdownResponse {
        const obj = json_value.object;

        return ExpressShutdownResponse{
            .process_id = @intCast(obj.get("processId").?.integer),
            .message = try allocator.dupe(u8, obj.get("message").?.string),
        };
    }
};

/// Diagnostics response (extended from basic diagnostics)
pub const DiagnosticsResponse = struct {
    invocation_id: []const u8,
    invocation_counter: u32,
    execution_time: u64,
    gas_consumed: []const u8,

    pub fn init() DiagnosticsResponse {
        return DiagnosticsResponse{
            .invocation_id = "",
            .invocation_counter = 0,
            .execution_time = 0,
            .gas_consumed = "0",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !DiagnosticsResponse {
        const obj = json_value.object;

        return DiagnosticsResponse{
            .invocation_id = try allocator.dupe(u8, obj.get("invocationId").?.string),
            .invocation_counter = @intCast(obj.get("invocationCounter").?.integer),
            .execution_time = @intCast(obj.get("executionTime").?.integer),
            .gas_consumed = try allocator.dupe(u8, obj.get("gasConsumed").?.string),
        };
    }
};

// Tests (converted from remaining Swift response tests)
test "Generic token balance responses" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test generic token balances (equivalent to Swift token balance tests)
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

test "Neo version response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test version response (equivalent to Swift NeoGetVersion tests)
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

    // Test response type registry (equivalent to Swift type mapping tests)
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
