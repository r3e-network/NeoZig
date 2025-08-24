//! Response Aliases implementation
//!
//! Complete conversion from NeoSwift NeoResponseAliases.swift
//! Provides all Neo RPC response type aliases and wrappers.

const std = @import("std");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

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
// BLOCKCHAIN RESPONSE TYPES (converted from Swift aliases)
// ============================================================================

/// Block count response (converted from Swift NeoBlockCount)
pub const NeoBlockCount = struct {
    result: ?u32,
    
    pub fn init() NeoBlockCount {
        return NeoBlockCount{ .result = null };
    }
    
    pub fn getBlockCount(self: NeoBlockCount) ?u32 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoBlockCount {
        _ = allocator;
        return NeoBlockCount{ .result = @intCast(json_value.integer) };
    }
};

/// Block hash response (converted from Swift NeoBlockHash)
pub const NeoBlockHash = struct {
    result: ?Hash256,
    
    pub fn init() NeoBlockHash {
        return NeoBlockHash{ .result = null };
    }
    
    pub fn getBlockHash(self: NeoBlockHash) ?Hash256 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoBlockHash {
        _ = allocator;
        const hash = try Hash256.initWithString(json_value.string);
        return NeoBlockHash{ .result = hash };
    }
};

/// Block header count response (alias of connection count)
pub const NeoBlockHeaderCount = NeoConnectionCount;

/// Calculate network fee response (converted from Swift NeoCalculateNetworkFee)
pub const NeoCalculateNetworkFee = struct {
    result: ?@import("complete_responses.zig").NetworkFeeResponse,
    
    pub fn init() NeoCalculateNetworkFee {
        return NeoCalculateNetworkFee{ .result = null };
    }
    
    pub fn getNetworkFee(self: NeoCalculateNetworkFee) ?@import("complete_responses.zig").NetworkFeeResponse {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoCalculateNetworkFee {
        const fee_response = try @import("complete_responses.zig").NetworkFeeResponse.fromJson(json_value, allocator);
        return NeoCalculateNetworkFee{ .result = fee_response };
    }
};

/// Close wallet response (converted from Swift NeoCloseWallet)
pub const NeoCloseWallet = struct {
    result: ?bool,
    
    pub fn init() NeoCloseWallet {
        return NeoCloseWallet{ .result = null };
    }
    
    pub fn getCloseWallet(self: NeoCloseWallet) ?bool {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoCloseWallet {
        _ = allocator;
        return NeoCloseWallet{ .result = json_value.bool };
    }
};

/// Connection count response (converted from Swift NeoConnectionCount)
pub const NeoConnectionCount = struct {
    result: ?u32,
    
    pub fn init() NeoConnectionCount {
        return NeoConnectionCount{ .result = null };
    }
    
    pub fn getCount(self: NeoConnectionCount) ?u32 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoConnectionCount {
        _ = allocator;
        return NeoConnectionCount{ .result = @intCast(json_value.integer) };
    }
};

/// Dump private key response (converted from Swift NeoDumpPrivKey)
pub const NeoDumpPrivKey = struct {
    result: ?[]const u8,
    
    pub fn init() NeoDumpPrivKey {
        return NeoDumpPrivKey{ .result = null };
    }
    
    pub fn getDumpPrivKey(self: NeoDumpPrivKey) ?[]const u8 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoDumpPrivKey {
        const result = try allocator.dupe(u8, json_value.string);
        return NeoDumpPrivKey{ .result = result };
    }
};

// ============================================================================
// EXPRESS RESPONSE TYPES (converted from Swift Express aliases)
// ============================================================================

/// Express create checkpoint response (converted from Swift NeoExpressCreateCheckpoint)
pub const NeoExpressCreateCheckpoint = struct {
    result: ?[]const u8,
    
    pub fn init() NeoExpressCreateCheckpoint {
        return NeoExpressCreateCheckpoint{ .result = null };
    }
    
    pub fn getFilename(self: NeoExpressCreateCheckpoint) ?[]const u8 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressCreateCheckpoint {
        const filename = try allocator.dupe(u8, json_value.string);
        return NeoExpressCreateCheckpoint{ .result = filename };
    }
};

/// Express create oracle response tx (converted from Swift NeoExpressCreateOracleResponseTx)
pub const NeoExpressCreateOracleResponseTx = struct {
    result: ?[]const u8,
    
    pub fn init() NeoExpressCreateOracleResponseTx {
        return NeoExpressCreateOracleResponseTx{ .result = null };
    }
    
    pub fn getOracleResponseTx(self: NeoExpressCreateOracleResponseTx) ?[]const u8 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressCreateOracleResponseTx {
        const tx = try allocator.dupe(u8, json_value.string);
        return NeoExpressCreateOracleResponseTx{ .result = tx };
    }
};

/// Express get contract storage response (converted from Swift NeoExpressGetContractStorage)
pub const NeoExpressGetContractStorage = struct {
    result: ?[]const @import("complete_responses.zig").ContractStorageEntry,
    
    pub fn init() NeoExpressGetContractStorage {
        return NeoExpressGetContractStorage{ .result = null };
    }
    
    pub fn getContractStorage(self: NeoExpressGetContractStorage) ?[]const @import("complete_responses.zig").ContractStorageEntry {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressGetContractStorage {
        var storage_list = std.ArrayList(@import("complete_responses.zig").ContractStorageEntry).init(allocator);
        
        for (json_value.array) |entry| {
            try storage_list.append(try @import("complete_responses.zig").ContractStorageEntry.fromJson(entry, allocator));
        }
        
        return NeoExpressGetContractStorage{ .result = try storage_list.toOwnedSlice() };
    }
};

/// Express get NEP-17 contracts response (converted from Swift NeoExpressGetNep17Contracts)
pub const NeoExpressGetNep17Contracts = struct {
    result: ?[]const @import("complete_responses.zig").Nep17Contract,
    
    pub fn init() NeoExpressGetNep17Contracts {
        return NeoExpressGetNep17Contracts{ .result = null };
    }
    
    pub fn getNep17Contracts(self: NeoExpressGetNep17Contracts) ?[]const @import("complete_responses.zig").Nep17Contract {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressGetNep17Contracts {
        var contracts_list = std.ArrayList(@import("complete_responses.zig").Nep17Contract).init(allocator);
        
        for (json_value.array) |contract| {
            try contracts_list.append(try @import("complete_responses.zig").Nep17Contract.fromJson(contract, allocator));
        }
        
        return NeoExpressGetNep17Contracts{ .result = try contracts_list.toOwnedSlice() };
    }
};

// ============================================================================
// WALLET RESPONSE TYPES (converted from Swift wallet aliases)
// ============================================================================

/// Get new address response (converted from Swift NeoGetNewAddress)
pub const NeoGetNewAddress = struct {
    result: ?[]const u8,
    
    pub fn init() NeoGetNewAddress {
        return NeoGetNewAddress{ .result = null };
    }
    
    pub fn getAddress(self: NeoGetNewAddress) ?[]const u8 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetNewAddress {
        const address = try allocator.dupe(u8, json_value.string);
        return NeoGetNewAddress{ .result = address };
    }
};

/// Open wallet response (converted from Swift NeoOpenWallet)
pub const NeoOpenWallet = struct {
    result: ?bool,
    
    pub fn init() NeoOpenWallet {
        return NeoOpenWallet{ .result = null };
    }
    
    pub fn getOpenWallet(self: NeoOpenWallet) ?bool {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoOpenWallet {
        _ = allocator;
        return NeoOpenWallet{ .result = json_value.bool };
    }
};

/// List address response (converted from Swift NeoListAddress)
pub const NeoListAddress = struct {
    result: ?[]const @import("complete_responses.zig").NeoAddress,
    
    pub fn init() NeoListAddress {
        return NeoListAddress{ .result = null };
    }
    
    pub fn getAddresses(self: NeoListAddress) ?[]const @import("complete_responses.zig").NeoAddress {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoListAddress {
        var addresses_list = std.ArrayList(@import("complete_responses.zig").NeoAddress).init(allocator);
        
        for (json_value.array) |address| {
            try addresses_list.append(try @import("complete_responses.zig").NeoAddress.fromJson(address, allocator));
        }
        
        return NeoListAddress{ .result = try addresses_list.toOwnedSlice() };
    }
};

// ============================================================================
// TRANSACTION RESPONSE TYPES (converted from Swift transaction aliases)
// ============================================================================

/// Send from response (converted from Swift NeoSendFrom)
pub const NeoSendFrom = struct {
    result: ?@import("responses.zig").Transaction,
    
    pub fn init() NeoSendFrom {
        return NeoSendFrom{ .result = null };
    }
    
    pub fn getSendFrom(self: NeoSendFrom) ?@import("responses.zig").Transaction {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoSendFrom {
        const transaction = try @import("responses.zig").Transaction.fromJson(json_value, allocator);
        return NeoSendFrom{ .result = transaction };
    }
};

/// Send many response (converted from Swift NeoSendMany)
pub const NeoSendMany = struct {
    result: ?@import("responses.zig").Transaction,
    
    pub fn init() NeoSendMany {
        return NeoSendMany{ .result = null };
    }
    
    pub fn getSendMany(self: NeoSendMany) ?@import("responses.zig").Transaction {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoSendMany {
        const transaction = try @import("responses.zig").Transaction.fromJson(json_value, allocator);
        return NeoSendMany{ .result = transaction };
    }
};

/// Send to address response (converted from Swift NeoSendToAddress)
pub const NeoSendToAddress = struct {
    result: ?@import("responses.zig").Transaction,
    
    pub fn init() NeoSendToAddress {
        return NeoSendToAddress{ .result = null };
    }
    
    pub fn getSendToAddress(self: NeoSendToAddress) ?@import("responses.zig").Transaction {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoSendToAddress {
        const transaction = try @import("responses.zig").Transaction.fromJson(json_value, allocator);
        return NeoSendToAddress{ .result = transaction };
    }
};

// ============================================================================
// CONTRACT RESPONSE TYPES (converted from Swift contract aliases)
// ============================================================================

/// Get contract state response (converted from Swift NeoGetContractState)
pub const NeoGetContractState = struct {
    result: ?@import("responses.zig").ContractState,
    
    pub fn init() NeoGetContractState {
        return NeoGetContractState{ .result = null };
    }
    
    pub fn getContractState(self: NeoGetContractState) ?@import("responses.zig").ContractState {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetContractState {
        const state = try @import("responses.zig").ContractState.fromJson(json_value, allocator);
        return NeoGetContractState{ .result = state };
    }
};

/// Get native contracts response (converted from Swift NeoGetNativeContracts)
pub const NeoGetNativeContracts = struct {
    result: ?[]const @import("complete_responses.zig").NativeContractState,
    
    pub fn init() NeoGetNativeContracts {
        return NeoGetNativeContracts{ .result = null };
    }
    
    pub fn getNativeContracts(self: NeoGetNativeContracts) ?[]const @import("complete_responses.zig").NativeContractState {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetNativeContracts {
        var contracts_list = std.ArrayList(@import("complete_responses.zig").NativeContractState).init(allocator);
        
        for (json_value.array) |contract| {
            try contracts_list.append(try @import("complete_responses.zig").NativeContractState.fromJson(contract, allocator));
        }
        
        return NeoGetNativeContracts{ .result = try contracts_list.toOwnedSlice() };
    }
};

/// Get NEP-11 properties response (converted from Swift NeoGetNep11Properties)
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
};

// ============================================================================
// INVOCATION RESPONSE TYPES (aliases)
// ============================================================================

/// Neo invoke response (converted from Swift NeoInvoke)
pub const NeoInvoke = struct {
    result: ?@import("responses.zig").InvocationResult,
    
    pub fn init() NeoInvoke {
        return NeoInvoke{ .result = null };
    }
    
    pub fn getInvocationResult(self: NeoInvoke) ?@import("responses.zig").InvocationResult {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoInvoke {
        const invocation = try @import("responses.zig").InvocationResult.fromJson(json_value, allocator);
        return NeoInvoke{ .result = invocation };
    }
};

/// Type aliases for invocation methods (converted from Swift typealiases)
pub const NeoInvokeContractVerify = NeoInvoke;
pub const NeoInvokeFunction = NeoInvoke;
pub const NeoInvokeScript = NeoInvoke;

/// Traverse iterator response (converted from Swift NeoTraverseIterator)
pub const NeoTraverseIterator = struct {
    result: ?[]const @import("responses.zig").StackItem,
    
    pub fn init() NeoTraverseIterator {
        return NeoTraverseIterator{ .result = null };
    }
    
    pub fn getTraverseIterator(self: NeoTraverseIterator) ?[]const @import("responses.zig").StackItem {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoTraverseIterator {
        var items_list = std.ArrayList(@import("responses.zig").StackItem).init(allocator);
        
        for (json_value.array) |item| {
            try items_list.append(try @import("responses.zig").StackItem.fromJson(item, allocator));
        }
        
        return NeoTraverseIterator{ .result = try items_list.toOwnedSlice() };
    }
};

/// Terminate session response (converted from Swift NeoTerminateSession)
pub const NeoTerminateSession = struct {
    result: ?bool,
    
    pub fn init() NeoTerminateSession {
        return NeoTerminateSession{ .result = null };
    }
    
    pub fn getTerminateSession(self: NeoTerminateSession) ?bool {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoTerminateSession {
        _ = allocator;
        return NeoTerminateSession{ .result = json_value.bool };
    }
};

// ============================================================================
// STORAGE AND STATE RESPONSE TYPES
// ============================================================================

/// Get storage response (converted from Swift NeoGetStorage)
pub const NeoGetStorage = struct {
    result: ?[]const u8,
    
    pub fn init() NeoGetStorage {
        return NeoGetStorage{ .result = null };
    }
    
    pub fn getStorage(self: NeoGetStorage) ?[]const u8 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetStorage {
        const storage = try allocator.dupe(u8, json_value.string);
        return NeoGetStorage{ .result = storage };
    }
};

/// Get state response (converted from Swift NeoGetState)
pub const NeoGetState = struct {
    result: ?[]const u8,
    
    pub fn init() NeoGetState {
        return NeoGetState{ .result = null };
    }
    
    pub fn getState(self: NeoGetState) ?[]const u8 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetState {
        const state = try allocator.dupe(u8, json_value.string);
        return NeoGetState{ .result = state };
    }
};

/// Verify proof response (converted from Swift NeoVerifyProof)
pub const NeoVerifyProof = struct {
    result: ?[]const u8,
    
    pub fn init() NeoVerifyProof {
        return NeoVerifyProof{ .result = null };
    }
    
    pub fn getVerifyProof(self: NeoVerifyProof) ?[]const u8 {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoVerifyProof {
        const proof = try allocator.dupe(u8, json_value.string);
        return NeoVerifyProof{ .result = proof };
    }
};

/// Submit block response (converted from Swift NeoSubmitBlock)
pub const NeoSubmitBlock = struct {
    result: ?bool,
    
    pub fn init() NeoSubmitBlock {
        return NeoSubmitBlock{ .result = null };
    }
    
    pub fn getSubmitBlock(self: NeoSubmitBlock) ?bool {
        return self.result;
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoSubmitBlock {
        _ = allocator;
        return NeoSubmitBlock{ .result = json_value.bool };
    }
};

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

// Tests (converted from Swift response alias tests)
test "Basic response types" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test block count response (equivalent to Swift NeoBlockCount tests)
    const block_count = NeoBlockCount.init();
    try testing.expect(block_count.getBlockCount() == null);
    
    const block_count_with_result = NeoBlockCount{ .result = 12345 };
    try testing.expectEqual(@as(u32, 12345), block_count_with_result.getBlockCount().?);
    
    // Test connection count response
    const connection_count = NeoConnectionCount.init();
    try testing.expect(connection_count.getCount() == null);
    
    // Test boolean responses
    const close_wallet = NeoCloseWallet.init();
    try testing.expect(close_wallet.getCloseWallet() == null);
    
    const open_wallet = NeoOpenWallet{ .result = true };
    try testing.expect(open_wallet.getOpenWallet().?);
}

test "Express response types" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test express checkpoint response
    const checkpoint = NeoExpressCreateCheckpoint.init();
    try testing.expect(checkpoint.getFilename() == null);
    
    const checkpoint_with_file = NeoExpressCreateCheckpoint{ .result = try allocator.dupe(u8, "checkpoint_001.acc") };
    defer if (checkpoint_with_file.result) |filename| allocator.free(filename);
    
    try testing.expectEqualStrings("checkpoint_001.acc", checkpoint_with_file.getFilename().?);
    
    // Test oracle response tx
    const oracle_tx = NeoExpressCreateOracleResponseTx.init();
    try testing.expect(oracle_tx.getOracleResponseTx() == null);
}

test "Storage and state response types" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test storage response
    const storage = NeoGetStorage.init();
    try testing.expect(storage.getStorage() == null);
    
    const storage_with_data = NeoGetStorage{ .result = try allocator.dupe(u8, "storage_data_hex") };
    defer if (storage_with_data.result) |data| allocator.free(data);
    
    try testing.expectEqualStrings("storage_data_hex", storage_with_data.getStorage().?);
    
    // Test state response
    const state = NeoGetState.init();
    try testing.expect(state.getState() == null);
    
    // Test proof response
    const proof = NeoVerifyProof.init();
    try testing.expect(proof.getVerifyProof() == null);
}

test "Transaction response types" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test send transaction responses
    const send_from = NeoSendFrom.init();
    try testing.expect(send_from.getSendFrom() == null);
    
    const send_many = NeoSendMany.init();
    try testing.expect(send_many.getSendMany() == null);
    
    const send_to_address = NeoSendToAddress.init();
    try testing.expect(send_to_address.getSendToAddress() == null);
    
    // Test session operations
    const terminate_session = NeoTerminateSession.init();
    try testing.expect(terminate_session.getTerminateSession() == null);
    
    const terminate_with_result = NeoTerminateSession{ .result = true };
    try testing.expect(terminate_with_result.getTerminateSession().?);
}