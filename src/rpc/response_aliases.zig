//! Response Aliases implementation
//!
//! Neo N3
//! Provides all Neo RPC response type aliases and wrappers.

const std = @import("std");
const ArrayList = std.ArrayList;

const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const errors = @import("../core/errors.zig");
const StackItem = @import("../types/stack_item.zig").StackItem;

const responses = @import("responses.zig");
const NeoBlock = responses.NeoBlock;
const Transaction = responses.Transaction;
const ContractState = responses.ContractState;
const InvocationResult = responses.InvocationResult;
const NetworkFeeResponse = responses.NetworkFeeResponse;

const extended = @import("extended_responses.zig");
const PopulatedBlocks = extended.PopulatedBlocks;
const ContractStorageEntry = extended.ContractStorageEntry;
const Nep17Contract = extended.Nep17Contract;
const ExpressContractState = extended.ExpressContractState;
const OracleRequest = extended.OracleRequest;
const ExpressShutdown = extended.ExpressShutdown;
const NeoAddress = extended.NeoAddress;
const NativeContractState = extended.NativeContractState;

/// Generic response wrapper (base for all response types)
pub fn Response(comptime T: type) type {
    return struct {
        result: ?T,

        const Self = @This();

        pub fn init() Self {
            return Self{ .result = null };
        }

        pub fn initWithResult(result: T) Self {
            return Self{ .result = result };
        }

        pub fn getResult(self: Self) ?T {
            return self.result;
        }

        pub fn hasResult(self: Self) bool {
            return self.result != null;
        }
    };
}

// ============================================================================
// GENERIC RESPONSE HELPERS
// ============================================================================

/// Generic bool response (parses JSON bool)
pub fn BoolResponse() type {
    return struct {
        result: ?bool,
        const Self = @This();
        pub fn init() Self { return .{ .result = null }; }
        pub fn getResult(self: Self) ?bool { return self.result; }
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            _ = allocator;
            return .{ .result = json_value.bool };
        }
    };
}

/// Generic u32 response (parses JSON integer)
pub fn IntResponse() type {
    return struct {
        result: ?u32,
        const Self = @This();
        pub fn init() Self { return .{ .result = null }; }
        pub fn getResult(self: Self) ?u32 { return self.result; }
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            _ = allocator;
            return .{ .result = @intCast(json_value.integer) };
        }
    };
}

/// Generic owned-string response (parses JSON string, owns memory)
pub fn StringResponse() type {
    return struct {
        result: ?[]const u8,
        const Self = @This();
        pub fn init() Self { return .{ .result = null }; }
        pub fn getResult(self: Self) ?[]const u8 { return self.result; }
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            return .{ .result = try allocator.dupe(u8, json_value.string) };
        }
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.result) |res| {
                if (res.len > 0) allocator.free(@constCast(res));
                self.result = null;
            }
        }
    };
}

/// Generic Hash256 response (parses hex string to Hash256)
pub fn Hash256Response() type {
    return struct {
        result: ?Hash256,
        const Self = @This();
        pub fn init() Self { return .{ .result = null }; }
        pub fn getResult(self: Self) ?Hash256 { return self.result; }
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            _ = allocator;
            return .{ .result = try Hash256.initWithString(json_value.string) };
        }
    };
}

/// Generic object response (parses single JSON object with T.fromJson/deinit)
pub fn ObjectResponse(comptime T: type) type {
    return struct {
        result: ?T,
        const Self = @This();
        pub fn init() Self { return .{ .result = null }; }
        pub fn getResult(self: Self) ?T { return self.result; }
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            return .{ .result = try T.fromJson(json_value, allocator) };
        }
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.result) |*val| {
                val.deinit(allocator);
                self.result = null;
            }
        }
    };
}

/// Generic array response (parses JSON array of T with fromJson/deinit)
pub fn ArrayResponse(comptime T: type) type {
    return struct {
        result: ?[]const T,
        const Self = @This();
        pub fn init() Self { return .{ .result = null }; }
        pub fn getResult(self: Self) ?[]const T { return self.result; }
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            if (json_value != .array) return errors.SerializationError.InvalidFormat;
            var list = ArrayList(T).init(allocator);
            errdefer {
                for (list.items) |*item| item.deinit(allocator);
                list.deinit();
            }
            for (json_value.array.items) |entry| {
                var parsed = try T.fromJson(entry, allocator);
                errdefer parsed.deinit(allocator);
                try list.append(parsed);
            }
            return .{ .result = try list.toOwnedSlice() };
        }
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.result) |items| {
                for (@constCast(items)) |*item| {
                    item.deinit(allocator);
                }
                allocator.free(@constCast(items));
                self.result = null;
            }
        }
    };
}

// ============================================================================
// BLOCKCHAIN RESPONSE TYPES
// ============================================================================

pub const NeoBlockCount = IntResponse();
pub const NeoBlockHash = Hash256Response();

/// Block response wrapper
pub const NeoGetBlock = struct {
    result: ?*NeoBlock,

    pub fn init() NeoGetBlock {
        return NeoGetBlock{ .result = null };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetBlock {
        const block = try allocator.create(NeoBlock);
        errdefer allocator.destroy(block);

        block.* = try NeoBlock.fromJson(json_value, allocator);
        return NeoGetBlock{ .result = block };
    }

    pub fn getResult(self: NeoGetBlock) ?*const NeoBlock {
        return self.result;
    }

    pub fn takeBlock(self: *NeoGetBlock) ?*NeoBlock {
        const owned = self.result;
        self.result = null;
        return owned;
    }

    pub fn deinit(self: *NeoGetBlock, allocator: std.mem.Allocator) void {
        if (self.result) |block_ptr| {
            block_ptr.deinit(allocator);
            allocator.destroy(block_ptr);
            self.result = null;
        }
    }
};

/// Raw mempool hash list response
pub const NeoGetRawMemPool = struct {
    result: ?[]Hash256,

    pub fn init() NeoGetRawMemPool {
        return NeoGetRawMemPool{ .result = null };
    }

    pub fn getTransactions(self: NeoGetRawMemPool) ?[]Hash256 {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetRawMemPool {
        if (json_value != .array) {
            return errors.ValidationError.InvalidFormat;
        }

        var hashes = ArrayList(Hash256).init(allocator);
        defer hashes.deinit();

        for (json_value.array.items) |entry| {
            if (entry != .string) {
                return errors.ValidationError.InvalidFormat;
            }
            try hashes.append(try Hash256.initWithString(entry.string));
        }

        return NeoGetRawMemPool{ .result = try hashes.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoGetRawMemPool, allocator: std.mem.Allocator) void {
        if (self.result) |items| {
            allocator.free(items);
            self.result = null;
        }
    }
};

/// Block header count response (alias of connection count)
pub const NeoBlockHeaderCount = NeoConnectionCount;

/// NeoCalculateNetworkFee response
pub const NeoCalculateNetworkFee = ObjectResponse(NetworkFeeResponse);

pub const NeoCloseWallet = BoolResponse();
pub const NeoConnectionCount = IntResponse();

pub const NeoDumpPrivKey = StringResponse();

/// Raw transaction response (hex string)
pub const NeoGetRawTransaction = StringResponse();

/// Transaction response
pub const NeoGetTransaction = struct {
    result: ?*Transaction,

    pub fn init() NeoGetTransaction {
        return NeoGetTransaction{ .result = null };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetTransaction {
        const tx = try allocator.create(Transaction);
        errdefer allocator.destroy(tx);

        tx.* = try Transaction.fromJson(json_value, allocator);
        return NeoGetTransaction{ .result = tx };
    }

    pub fn getResult(self: NeoGetTransaction) ?*const Transaction {
        return self.result;
    }

    pub fn take(self: *NeoGetTransaction) ?*Transaction {
        const owned = self.result;
        self.result = null;
        return owned;
    }

    pub fn deinit(self: *NeoGetTransaction, allocator: std.mem.Allocator) void {
        if (self.result) |tx| {
            tx.deinit(allocator);
            allocator.destroy(tx);
            self.result = null;
        }
    }
};

// ============================================================================
// EXPRESS RESPONSE TYPES
// ============================================================================

pub const NeoExpressCreateCheckpoint = StringResponse();

/// Express create oracle response tx
pub const NeoExpressCreateOracleResponseTx = StringResponse();

/// NeoExpressGetPopulatedBlocks response
pub const NeoExpressGetPopulatedBlocks = ObjectResponse(PopulatedBlocks);

/// NeoExpressGetContractStorage response
pub const NeoExpressGetContractStorage = ArrayResponse(ContractStorageEntry);

/// NeoExpressGetNep17Contracts response
pub const NeoExpressGetNep17Contracts = ArrayResponse(Nep17Contract);

/// NeoExpressListContracts response
pub const NeoExpressListContracts = ArrayResponse(ExpressContractState);

/// NeoExpressListOracleRequests response
pub const NeoExpressListOracleRequests = ArrayResponse(OracleRequest);

/// NeoExpressShutdown response
pub const NeoExpressShutdown = ObjectResponse(ExpressShutdown);

pub const NeoExpressReset = BoolResponse();

// ============================================================================
// WALLET RESPONSE TYPES
// ============================================================================

pub const NeoGetNewAddress = StringResponse();

/// Open wallet response
pub const NeoOpenWallet = BoolResponse();

/// NeoListAddress response
pub const NeoListAddress = ArrayResponse(NeoAddress);

// ============================================================================
// TRANSACTION RESPONSE TYPES
// ============================================================================

/// Generic transaction response wrapper
pub fn TransactionResponse() type {
    return struct {
        result: ?Transaction,
        const Self = @This();
        pub fn init() Self { return .{ .result = null }; }
        pub fn getResult(self: Self) ?Transaction { return self.result; }
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            const transaction = try Transaction.fromJson(json_value, allocator);
            return .{ .result = transaction };
        }
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.result) |*tx| {
                tx.deinit(allocator);
                self.result = null;
            }
        }
    };
}

/// Send from response
pub const NeoSendFrom = TransactionResponse();

/// Send many response
pub const NeoSendMany = TransactionResponse();

/// Send to address response
pub const NeoSendToAddress = TransactionResponse();

// ============================================================================
// CONTRACT RESPONSE TYPES
// ============================================================================

/// NeoGetContractState response
pub const NeoGetContractState = ObjectResponse(ContractState);

/// NeoGetNativeContracts response
pub const NeoGetNativeContracts = ArrayResponse(NativeContractState);

/// Get NEP-11 properties response
pub const NeoGetNep11Properties = struct {
    result: ?std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),

    pub fn init() NeoGetNep11Properties {
        return NeoGetNep11Properties{ .result = null };
    }

    pub fn getProperties(self: NeoGetNep11Properties) ?std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage) {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetNep11Properties {
        var properties = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator);

        var prop_iterator = json_value.object.iterator();
        while (prop_iterator.next()) |entry| {
            const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
            const value_copy = try allocator.dupe(u8, entry.value_ptr.string);
            try properties.put(key_copy, value_copy);
        }

        return NeoGetNep11Properties{ .result = properties };
    }

    pub fn deinit(self: *NeoGetNep11Properties, allocator: std.mem.Allocator) void {
        if (self.result) |*map| {
            var iterator = map.iterator();
            while (iterator.next()) |entry| {
                const key_slice = entry.key_ptr.*;
                const value_slice = entry.value_ptr.*;
                if (key_slice.len > 0) allocator.free(@constCast(key_slice));
                if (value_slice.len > 0) allocator.free(@constCast(value_slice));
            }
            map.deinit();
            self.result = null;
        }
    }
};

// ============================================================================
// INVOCATION RESPONSE TYPES (aliases)
// ============================================================================

/// NeoInvoke response
pub const NeoInvoke = ObjectResponse(InvocationResult);

/// Type aliases for invocation methods
pub const NeoInvokeContractVerify = NeoInvoke;
pub const NeoInvokeFunction = NeoInvoke;
pub const NeoInvokeScript = NeoInvoke;

/// Traverse iterator response
pub const NeoTraverseIterator = struct {
    result: ?[]StackItem,

    pub fn init() NeoTraverseIterator {
        return NeoTraverseIterator{ .result = null };
    }

    pub fn getTraverseIterator(self: NeoTraverseIterator) ?[]const StackItem {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoTraverseIterator {
        var items_list = ArrayList(StackItem).init(allocator);
        defer items_list.deinit();
        if (json_value != .array) return errors.SerializationError.InvalidFormat;
        for (json_value.array.items) |item| {
            var parsed = try StackItem.decodeFromJson(item, allocator);
            var parsed_guard = true;
            defer if (parsed_guard) parsed.deinit(allocator);
            try items_list.append(parsed);
            parsed_guard = false;
        }

        return NeoTraverseIterator{ .result = try items_list.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoTraverseIterator, allocator: std.mem.Allocator) void {
        if (self.result) |items| {
            for (items) |*item| {
                item.deinit(allocator);
            }
            allocator.free(items);
            self.result = null;
        }
    }
};

pub const NeoTerminateSession = BoolResponse();

// ============================================================================
// STORAGE AND STATE RESPONSE TYPES
// ============================================================================

pub const NeoGetStorage = StringResponse();

/// Get state response
pub const NeoGetState = StringResponse();

/// Verify proof response
pub const NeoVerifyProof = StringResponse();

/// Submit block response
pub const NeoSubmitBlock = BoolResponse();

/// String context for HashMap
pub const StringContext = struct {
    pub fn hash(self: @This(), key: []const u8) u64 {
        _ = self;
        return std.hash_map.hashString(key);
    }

    pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
        _ = self;
        return std.mem.eql(u8, a, b);
    }
};

// Tests
test "Basic response types" {
    const testing = std.testing;

    // Test block count response
    const block_count = NeoBlockCount.init();
    try testing.expect(block_count.getResult() == null);

    const block_count_with_result = NeoBlockCount{ .result = 12345 };
    try testing.expectEqual(@as(u32, 12345), block_count_with_result.getResult().?);

    // Test connection count response
    const connection_count = NeoConnectionCount.init();
    try testing.expect(connection_count.getResult() == null);

    // Test boolean responses
    const close_wallet = NeoCloseWallet.init();
    try testing.expect(close_wallet.getResult() == null);

    const open_wallet = NeoOpenWallet{ .result = true };
    try testing.expect(open_wallet.getResult().?);
}

test "Express response types" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test express checkpoint response
    const checkpoint = NeoExpressCreateCheckpoint.init();
    try testing.expect(checkpoint.getResult() == null);

    const checkpoint_with_file = NeoExpressCreateCheckpoint{ .result = try allocator.dupe(u8, "checkpoint_001.acc") };
    defer if (checkpoint_with_file.result) |filename| allocator.free(filename);

    try testing.expectEqualStrings("checkpoint_001.acc", checkpoint_with_file.getResult().?);

    // Test oracle response tx
    const oracle_tx = NeoExpressCreateOracleResponseTx.init();
    try testing.expect(oracle_tx.getResult() == null);
}

test "Storage and state response types" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test storage response
    const storage = NeoGetStorage.init();
    try testing.expect(storage.getResult() == null);

    const storage_with_data = NeoGetStorage{ .result = try allocator.dupe(u8, "storage_data_hex") };
    defer if (storage_with_data.result) |data| allocator.free(data);

    try testing.expectEqualStrings("storage_data_hex", storage_with_data.getResult().?);

    // Test state response
    const state = NeoGetState.init();
    try testing.expect(state.getResult() == null);

    // Test proof response
    const proof = NeoVerifyProof.init();
    try testing.expect(proof.getResult() == null);
}

test "Transaction response types" {
    const testing = std.testing;

    // Test send transaction responses
    const send_from = NeoSendFrom.init();
    try testing.expect(send_from.getResult() == null);

    const send_many = NeoSendMany.init();
    try testing.expect(send_many.getResult() == null);

    const send_to_address = NeoSendToAddress.init();
    try testing.expect(send_to_address.getResult() == null);

    // Test session operations
    const terminate_session = NeoTerminateSession.init();
    try testing.expect(terminate_session.getResult() == null);

    const terminate_with_result = NeoTerminateSession{ .result = true };
    try testing.expect(terminate_with_result.getResult().?);
}

test "Response alias fromJson smoke tests" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // NeoListAddress
    var addr_obj = std.json.ObjectMap.init(allocator);
    try addr_obj.put("address", std.json.Value{ .string = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNn" });
    try addr_obj.put("isvalid", std.json.Value{ .bool = true });

    var addr_array = std.json.Array.init(allocator);
    try addr_array.append(std.json.Value{ .object = addr_obj });

    const parsed_addresses = try NeoListAddress.fromJson(std.json.Value{ .array = addr_array }, allocator);
    try testing.expect(parsed_addresses.result != null);
    try testing.expectEqual(@as(usize, 1), parsed_addresses.result.?.len);

    // NeoExpressGetContractStorage
    var entry_obj = std.json.ObjectMap.init(allocator);
    try entry_obj.put("key", std.json.Value{ .string = "01" });
    try entry_obj.put("value", std.json.Value{ .string = "02" });

    var storage_array = std.json.Array.init(allocator);
    try storage_array.append(std.json.Value{ .object = entry_obj });

    const parsed_storage = try NeoExpressGetContractStorage.fromJson(std.json.Value{ .array = storage_array }, allocator);
    try testing.expect(parsed_storage.result != null);
    try testing.expectEqual(@as(usize, 1), parsed_storage.result.?.len);

    // NeoGetNativeContracts
    var nef_obj = std.json.ObjectMap.init(allocator);
    try nef_obj.put("magic", std.json.Value{ .integer = 123 });
    try nef_obj.put("compiler", std.json.Value{ .string = "neo-zig-test" });
    try nef_obj.put("script", std.json.Value{ .string = "00" });
    try nef_obj.put("checksum", std.json.Value{ .integer = 1 });

    var manifest_obj = std.json.ObjectMap.init(allocator);
    try manifest_obj.put("name", std.json.Value{ .string = "TestContract" });

    var update_history_array = std.json.Array.init(allocator);
    try update_history_array.append(std.json.Value{ .integer = 1 });

    var native_contract_obj = std.json.ObjectMap.init(allocator);
    try native_contract_obj.put("id", std.json.Value{ .integer = 1 });
    try native_contract_obj.put("hash", std.json.Value{ .string = "1234567890abcdef1234567890abcdef12345678" });
    try native_contract_obj.put("nef", std.json.Value{ .object = nef_obj });
    try native_contract_obj.put("manifest", std.json.Value{ .object = manifest_obj });
    try native_contract_obj.put("updatehistory", std.json.Value{ .array = update_history_array });

    var native_array = std.json.Array.init(allocator);
    try native_array.append(std.json.Value{ .object = native_contract_obj });

    var parsed_native = try NeoGetNativeContracts.fromJson(std.json.Value{ .array = native_array }, allocator);
    defer parsed_native.deinit(allocator);
    try testing.expect(parsed_native.result != null);
    try testing.expectEqual(@as(usize, 1), parsed_native.result.?.len);
}
