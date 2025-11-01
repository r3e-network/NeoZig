//! Response Aliases implementation
//!
//! Complete conversion from NeoSwift NeoResponseAliases.swift
//! Provides all Neo RPC response type aliases and wrappers.

const std = @import("std");
const ArrayList = std.array_list.Managed;

const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const errors = @import("../core/errors.zig");
const StackItem = @import("../types/stack_item.zig").StackItem;

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

/// Block response wrapper (converted from Swift NeoGetBlock)
pub const NeoGetBlock = struct {
    result: ?*@import("responses.zig").NeoBlock,

    pub fn init() NeoGetBlock {
        return NeoGetBlock{ .result = null };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetBlock {
        var block = try allocator.create(@import("responses.zig").NeoBlock);
        errdefer allocator.destroy(block);

        block.* = try @import("responses.zig").NeoBlock.fromJson(json_value, allocator);
        return NeoGetBlock{ .result = block };
    }

    pub fn getResult(self: NeoGetBlock) ?*const @import("responses.zig").NeoBlock {
        return self.result;
    }

    pub fn takeBlock(self: *NeoGetBlock) ?*@import("responses.zig").NeoBlock {
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

    pub fn deinit(self: *NeoDumpPrivKey, allocator: std.mem.Allocator) void {
        if (self.result) |res| {
            if (res.len > 0 and res.ptr != null) allocator.free(@constCast(res));
            self.result = null;
        }
    }
};

/// Raw transaction response (hex string)
pub const NeoGetRawTransaction = struct {
    result: ?[]const u8,

    pub fn init() NeoGetRawTransaction {
        return NeoGetRawTransaction{ .result = null };
    }

    pub fn getRawTransaction(self: NeoGetRawTransaction) ?[]const u8 {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetRawTransaction {
        const tx_hex = try allocator.dupe(u8, json_value.string);
        return NeoGetRawTransaction{ .result = tx_hex };
    }

    pub fn deinit(self: *NeoGetRawTransaction, allocator: std.mem.Allocator) void {
        if (self.result) |res| {
            if (res.len > 0 and res.ptr != null) allocator.free(@constCast(res));
            self.result = null;
        }
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

    pub fn deinit(self: *NeoExpressCreateCheckpoint, allocator: std.mem.Allocator) void {
        if (self.result) |res| {
            if (res.len > 0 and res.ptr != null) allocator.free(@constCast(res));
            self.result = null;
        }
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

    pub fn deinit(self: *NeoExpressCreateOracleResponseTx, allocator: std.mem.Allocator) void {
        if (self.result) |res| {
            if (res.len > 0 and res.ptr != null) allocator.free(@constCast(res));
            self.result = null;
        }
    }
};

/// Express get populated blocks response
pub const NeoExpressGetPopulatedBlocks = struct {
    result: ?@import("complete_responses.zig").PopulatedBlocks,

    pub fn init() NeoExpressGetPopulatedBlocks {
        return NeoExpressGetPopulatedBlocks{ .result = null };
    }

    pub fn getPopulatedBlocks(self: NeoExpressGetPopulatedBlocks) ?@import("complete_responses.zig").PopulatedBlocks {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressGetPopulatedBlocks {
        const populated = try @import("complete_responses.zig").PopulatedBlocks.fromJson(json_value, allocator);
        return NeoExpressGetPopulatedBlocks{ .result = populated };
    }

    pub fn deinit(self: *NeoExpressGetPopulatedBlocks, allocator: std.mem.Allocator) void {
        if (self.result) |*populated| {
            populated.deinit(allocator);
            self.result = null;
        }
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
        var storage_list = ArrayList(@import("complete_responses.zig").ContractStorageEntry).init(allocator);

        for (json_value.array) |entry| {
            try storage_list.append(try @import("complete_responses.zig").ContractStorageEntry.fromJson(entry, allocator));
        }

        return NeoExpressGetContractStorage{ .result = try storage_list.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoExpressGetContractStorage, allocator: std.mem.Allocator) void {
        if (self.result) |entries| {
            for (entries) |*entry| {
                entry.deinit(allocator);
            }
            allocator.free(@constCast(entries));
            self.result = null;
        }
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
        var contracts_list = ArrayList(@import("complete_responses.zig").Nep17Contract).init(allocator);

        for (json_value.array) |contract| {
            try contracts_list.append(try @import("complete_responses.zig").Nep17Contract.fromJson(contract, allocator));
        }

        return NeoExpressGetNep17Contracts{ .result = try contracts_list.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoExpressGetNep17Contracts, allocator: std.mem.Allocator) void {
        if (self.result) |contracts| {
            for (contracts) |*contract| {
                contract.deinit(allocator);
            }
            allocator.free(@constCast(contracts));
            self.result = null;
        }
    }
};

/// Express list contracts response
pub const NeoExpressListContracts = struct {
    result: ?[]const @import("complete_responses.zig").ExpressContractState,

    pub fn init() NeoExpressListContracts {
        return NeoExpressListContracts{ .result = null };
    }

    pub fn getContracts(self: NeoExpressListContracts) ?[]const @import("complete_responses.zig").ExpressContractState {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressListContracts {
        var list = ArrayList(@import("complete_responses.zig").ExpressContractState).init(allocator);
        defer list.deinit();

        for (json_value.array) |contract_value| {
            try list.append(try @import("complete_responses.zig").ExpressContractState.fromJson(contract_value, allocator));
        }

        return NeoExpressListContracts{ .result = try list.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoExpressListContracts, allocator: std.mem.Allocator) void {
        if (self.result) |contracts| {
            for (contracts) |*contract| {
                contract.deinit(allocator);
            }
            allocator.free(@constCast(contracts));
            self.result = null;
        }
    }
};

/// Express list oracle requests response
pub const NeoExpressListOracleRequests = struct {
    result: ?[]const @import("complete_responses.zig").OracleRequest,

    pub fn init() NeoExpressListOracleRequests {
        return NeoExpressListOracleRequests{ .result = null };
    }

    pub fn getOracleRequests(self: NeoExpressListOracleRequests) ?[]const @import("complete_responses.zig").OracleRequest {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressListOracleRequests {
        var list = ArrayList(@import("complete_responses.zig").OracleRequest).init(allocator);
        defer list.deinit();

        for (json_value.array) |request_value| {
            try list.append(try @import("complete_responses.zig").OracleRequest.fromJson(request_value, allocator));
        }

        return NeoExpressListOracleRequests{ .result = try list.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoExpressListOracleRequests, allocator: std.mem.Allocator) void {
        if (self.result) |requests| {
            for (requests) |*request| {
                request.deinit(allocator);
            }
            allocator.free(@constCast(requests));
            self.result = null;
        }
    }
};

/// Express shutdown response
pub const NeoExpressShutdown = struct {
    result: ?@import("complete_responses.zig").ExpressShutdown,

    pub fn init() NeoExpressShutdown {
        return NeoExpressShutdown{ .result = null };
    }

    pub fn getShutdown(self: NeoExpressShutdown) ?@import("complete_responses.zig").ExpressShutdown {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressShutdown {
        const shutdown = try @import("complete_responses.zig").ExpressShutdown.fromJson(json_value, allocator);
        return NeoExpressShutdown{ .result = shutdown };
    }

    pub fn deinit(self: *NeoExpressShutdown, allocator: std.mem.Allocator) void {
        if (self.result) |*shutdown| {
            shutdown.deinit(allocator);
            self.result = null;
        }
    }
};

/// Express reset response (boolean)
pub const NeoExpressReset = struct {
    result: ?bool,

    pub fn init() NeoExpressReset {
        return NeoExpressReset{ .result = null };
    }

    pub fn getResult(self: NeoExpressReset) ?bool {
        return self.result;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoExpressReset {
        _ = allocator;
        return NeoExpressReset{ .result = json_value.bool };
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

    pub fn deinit(self: *NeoGetNewAddress, allocator: std.mem.Allocator) void {
        if (self.result) |res| {
            if (res.len > 0 and res.ptr != null) allocator.free(@constCast(res));
            self.result = null;
        }
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
        var addresses_list = ArrayList(@import("complete_responses.zig").NeoAddress).init(allocator);

        for (json_value.array) |address| {
            try addresses_list.append(try @import("complete_responses.zig").NeoAddress.fromJson(address, allocator));
        }

        return NeoListAddress{ .result = try addresses_list.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoListAddress, allocator: std.mem.Allocator) void {
        if (self.result) |addresses| {
            for (addresses) |*address| {
                address.deinit(allocator);
            }
            allocator.free(@constCast(addresses));
            self.result = null;
        }
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

    pub fn deinit(self: *NeoSendFrom, allocator: std.mem.Allocator) void {
        if (self.result) |*tx| {
            tx.deinit(allocator);
            self.result = null;
        }
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

    pub fn deinit(self: *NeoSendMany, allocator: std.mem.Allocator) void {
        if (self.result) |*tx| {
            tx.deinit(allocator);
            self.result = null;
        }
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

    pub fn deinit(self: *NeoSendToAddress, allocator: std.mem.Allocator) void {
        if (self.result) |*tx| {
            tx.deinit(allocator);
            self.result = null;
        }
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

    pub fn deinit(self: *NeoGetContractState, allocator: std.mem.Allocator) void {
        if (self.result) |*state| {
            state.deinit(allocator);
            self.result = null;
        }
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
        var contracts_list = ArrayList(@import("complete_responses.zig").NativeContractState).init(allocator);
        defer contracts_list.deinit();

        for (json_value.array) |contract| {
            try contracts_list.append(try @import("complete_responses.zig").NativeContractState.fromJson(contract, allocator));
        }

        return NeoGetNativeContracts{ .result = try contracts_list.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoGetNativeContracts, allocator: std.mem.Allocator) void {
        if (self.result) |contracts| {
            for (contracts) |*contract| {
                contract.deinit(allocator);
            }
            allocator.free(@constCast(contracts));
            self.result = null;
        }
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

    pub fn deinit(self: *NeoInvoke, allocator: std.mem.Allocator) void {
        if (self.result) |*invocation| {
            invocation.deinit(allocator);
            self.result = null;
        }
    }
};

/// Type aliases for invocation methods (converted from Swift typealiases)
pub const NeoInvokeContractVerify = NeoInvoke;
pub const NeoInvokeFunction = NeoInvoke;
pub const NeoInvokeScript = NeoInvoke;

/// Traverse iterator response (converted from Swift NeoTraverseIterator)
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
        for (json_value.array) |item| {
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

    pub fn deinit(self: *NeoGetStorage, allocator: std.mem.Allocator) void {
        if (self.result) |res| {
            if (res.len > 0 and res.ptr != null) allocator.free(@constCast(res));
            self.result = null;
        }
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

    pub fn deinit(self: *NeoGetState, allocator: std.mem.Allocator) void {
        if (self.result) |res| {
            if (res.len > 0 and res.ptr != null) allocator.free(@constCast(res));
            self.result = null;
        }
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

    pub fn deinit(self: *NeoVerifyProof, allocator: std.mem.Allocator) void {
        if (self.result) |res| {
            if (res.len > 0 and res.ptr != null) allocator.free(@constCast(res));
            self.result = null;
        }
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
