//! Neo Swift Express Implementation
//!
//! Complete conversion from NeoSwift NeoSwiftExpress.swift
//! Provides Neo-express specific RPC methods for development.

const std = @import("std");


const Hash160 = @import("../types/hash160.zig").Hash160;
const NeoSwift = @import("../rpc/neo_client.zig").NeoSwift;

/// Neo-express development client (converted from Swift NeoSwiftExpress)
pub const NeoSwiftExpress = struct {
    /// Base NeoSwift client
    neo_swift: NeoSwift,
    
    const Self = @This();
    
    /// Creates Neo-express client (equivalent to Swift NeoSwiftExpress inheritance)
    pub fn init(neo_swift: NeoSwift) Self {
        return Self{
            .neo_swift = neo_swift,
        };
    }
    
    /// Gets populated blocks (equivalent to Swift expressGetPopulatedBlocks)
    pub fn expressGetPopulatedBlocks(self: Self) !ExpressRequest(PopulatedBlocks) {
        return ExpressRequest(PopulatedBlocks).init(
            "expressgetpopulatedblocks",
            "[]",
            self.neo_swift,
        );
    }
    
    /// Gets NEP-17 contracts (equivalent to Swift expressGetNep17Contracts)
    pub fn expressGetNep17Contracts(self: Self) !ExpressRequest([]Nep17Contract) {
        return ExpressRequest([]Nep17Contract).init(
            "expressgetnep17contracts",
            "[]",
            self.neo_swift,
        );
    }
    
    /// Gets contract storage (equivalent to Swift expressGetContractStorage)
    pub fn expressGetContractStorage(self: Self, contract_hash: Hash160, allocator: std.mem.Allocator) !ExpressRequest([]ContractStorageEntry) {
        const hash_string = try contract_hash.toString(allocator);
        defer allocator.free(hash_string);
        
        const params = try std.fmt.allocPrint(allocator, "[\"{s}\"]", .{hash_string});
        defer allocator.free(params);
        
        return ExpressRequest([]ContractStorageEntry).init(
            "expressgetcontractstorage",
            try allocator.dupe(u8, params),
            self.neo_swift,
        );
    }
    
    /// Lists all contracts (equivalent to Swift expressListContracts)
    pub fn expressListContracts(self: Self) !ExpressRequest([]ExpressContractState) {
        return ExpressRequest([]ExpressContractState).init(
            "expresslistcontracts",
            "[]",
            self.neo_swift,
        );
    }
    
    /// Creates checkpoint (equivalent to Swift expressCreateCheckpoint)
    pub fn expressCreateCheckpoint(self: Self, filename: []const u8, allocator: std.mem.Allocator) !ExpressRequest([]u8) {
        const params = try std.fmt.allocPrint(allocator, "[\"{s}\"]", .{filename});
        defer allocator.free(params);
        
        return ExpressRequest([]u8).init(
            "expresscreatecheckpoint",
            try allocator.dupe(u8, params),
            self.neo_swift,
        );
    }
    
    /// Lists checkpoints (equivalent to Swift expressListCheckpoints)
    pub fn expressListCheckpoints(self: Self) !ExpressRequest([][]u8) {
        return ExpressRequest([][]u8).init(
            "expresslistcheckpoints",
            "[]",
            self.neo_swift,
        );
    }
    
    /// Resets blockchain to checkpoint (equivalent to Swift expressReset)
    pub fn expressReset(self: Self, checkpoint_filename: []const u8, allocator: std.mem.Allocator) !ExpressRequest(bool) {
        const params = try std.fmt.allocPrint(allocator, "[\"{s}\"]", .{checkpoint_filename});
        defer allocator.free(params);
        
        return ExpressRequest(bool).init(
            "expressreset",
            try allocator.dupe(u8, params),
            self.neo_swift,
        );
    }
    
    /// Creates Oracle response transaction (equivalent to Swift expressOracleResponse)
    pub fn expressOracleResponse(
        self: Self,
        request_id: u64,
        response_code: u8,
        result: []const u8,
        allocator: std.mem.Allocator,
    ) !ExpressRequest([]u8) {
        const params = try std.fmt.allocPrint(
            allocator,
            "[{},{}.\"{s}\"]",
            .{ request_id, response_code, result }
        );
        defer allocator.free(params);
        
        return ExpressRequest([]u8).init(
            "expressoracleresponse",
            try allocator.dupe(u8, params),
            self.neo_swift,
        );
    }
    
    /// Shuts down Neo-express node (equivalent to Swift expressShutdown)
    pub fn expressShutdown(self: Self) !ExpressRequest(bool) {
        return ExpressRequest(bool).init(
            "expressshutdown",
            "[]",
            self.neo_swift,
        );
    }
    
    /// Gets all methods specific to Neo-express
    pub fn getExpressMethods() []const []const u8 {
        const methods = [_][]const u8{
            "expressgetpopulatedblocks",
            "expressgetnep17contracts", 
            "expressgetcontractstorage",
            "expresslistcontracts",
            "expresscreatecheckpoint",
            "expresslistcheckpoints",
            "expressreset",
            "expressoracleresponse",
            "expressshutdown",
        };
        return &methods;
    }
    
    /// Checks if method is Express-specific
    pub fn isExpressMethod(method_name: []const u8) bool {
        const express_methods = getExpressMethods();
        for (express_methods) |express_method| {
            if (std.mem.eql(u8, method_name, express_method)) {
                return true;
            }
        }
        return false;
    }
    
    /// Validates that client is connected to Neo-express
    pub fn validateExpressConnection(self: Self, allocator: std.mem.Allocator) !void {
        // Try to call an express-specific method to validate
        const populated_blocks_req = try self.expressGetPopulatedBlocks();
        defer populated_blocks_req.deinit(allocator);
        
        // If this doesn't throw an error about unknown method, we're connected to Neo-express
        _ = populated_blocks_req.send() catch |err| {
            switch (err) {
                error.MethodNotFound => return error.NotConnectedToNeoExpress,
                else => return err,
            }
        };
    }
};

/// Express-specific request wrapper
pub fn ExpressRequest(comptime T: type) type {
    return struct {
        method: []const u8,
        params: []const u8,
        neo_swift: NeoSwift,
        
        const Self = @This();
        
        pub fn init(method: []const u8, params: []const u8, neo_swift: NeoSwift) Self {
            return Self{
                .method = method,
                .params = params,
                .neo_swift = neo_swift,
            };
        }
        
        pub fn send(self: Self) !T {
            return try self.neo_swift.sendExpressRequest(T, self.method, self.params);
        }
        
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.params);
        }
    };
}

/// Express-specific response types (stubs for referenced types)
pub const PopulatedBlocks = @import("../response/populated_blocks.zig").PopulatedBlocks;
pub const Nep17Contract = @import("../response/nep17_contract.zig").Nep17Contract;

/// Contract storage entry for express responses
pub const ContractStorageEntry = struct {
    key: []const u8,
    value: []const u8,
    
    const Self = @This();
    
    pub fn init(key: []const u8, value: []const u8) Self {
        return Self{ .key = key, .value = value };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

/// Express contract state
pub const ExpressContractState = struct {
    hash: Hash160,
    manifest: []const u8,
    nef: []const u8,
    
    const Self = @This();
    
    pub fn init(hash: Hash160, manifest: []const u8, nef: []const u8) Self {
        return Self{ .hash = hash, .manifest = manifest, .nef = nef };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.manifest);
        allocator.free(self.nef);
    }
};

// Tests (converted from Swift NeoSwiftExpress tests)
test "NeoSwiftExpress creation and method availability" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test express client creation (equivalent to Swift tests)
    // Note: Would need actual NeoSwift instance for full testing
    const mock_neo_swift = undefined; // stub
    _ = allocator;
    _ = mock_neo_swift;
    
    // Test express method detection
    try testing.expect(NeoSwiftExpress.isExpressMethod("expressgetpopulatedblocks"));
    try testing.expect(NeoSwiftExpress.isExpressMethod("expressgetnep17contracts"));
    try testing.expect(!NeoSwiftExpress.isExpressMethod("getversion"));
    try testing.expect(!NeoSwiftExpress.isExpressMethod("getblock"));
    
    // Test method list
    const express_methods = NeoSwiftExpress.getExpressMethods();
    try testing.expect(express_methods.len >= 9); // Should have all express methods
    
    var found_populated_blocks = false;
    var found_nep17_contracts = false;
    
    for (express_methods) |method| {
        if (std.mem.eql(u8, method, "expressgetpopulatedblocks")) found_populated_blocks = true;
        if (std.mem.eql(u8, method, "expressgetnep17contracts")) found_nep17_contracts = true;
    }
    
    try testing.expect(found_populated_blocks);
    try testing.expect(found_nep17_contracts);
}

test "ExpressRequest creation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test express request creation
    const mock_neo_swift = undefined; // stub
    
    const method = "expressgetpopulatedblocks";
    const params = "[]";
    
    var request = ExpressRequest(PopulatedBlocks).init(method, params, mock_neo_swift);
    
    try testing.expectEqualStrings(method, request.method);
    try testing.expectEqualStrings(params, request.params);
    
    // Note: Cannot test send() without actual NeoSwift implementation
    _ = allocator;
}

test "Express response types" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test ContractStorageEntry
    const key = try allocator.dupe(u8, "test_key");
    const value = try allocator.dupe(u8, "test_value");
    
    var storage_entry = ContractStorageEntry.init(key, value);
    defer storage_entry.deinit(allocator);
    
    try testing.expectEqualStrings("test_key", storage_entry.key);
    try testing.expectEqualStrings("test_value", storage_entry.value);
    
    // Test ExpressContractState
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const manifest = try allocator.dupe(u8, "test_manifest");
    const nef = try allocator.dupe(u8, "test_nef");
    
    var contract_state = ExpressContractState.init(contract_hash, manifest, nef);
    defer contract_state.deinit(allocator);
    
    try testing.expect(contract_state.hash.eql(contract_hash));
    try testing.expectEqualStrings("test_manifest", contract_state.manifest);
    try testing.expectEqualStrings("test_nef", contract_state.nef);
}