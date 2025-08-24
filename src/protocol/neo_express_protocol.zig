//! Neo Express Protocol Implementation
//!
//! Complete conversion from NeoSwift NeoExpress.swift
//! Provides Neo-express protocol interface definition.

const std = @import("std");
const Hash160 = @import("../types/hash160.zig").Hash160;

/// Neo Express protocol interface (converted from Swift NeoExpress protocol)
pub const NeoExpressProtocol = struct {
    /// Interface implementation function pointers
    express_get_populated_blocks_fn: *const fn (*anyopaque) anyerror!ExpressRequest(PopulatedBlocks),
    express_get_nep17_contracts_fn: *const fn (*anyopaque) anyerror!ExpressRequest([]Nep17Contract),
    express_get_contract_storage_fn: *const fn (*anyopaque, Hash160, std.mem.Allocator) anyerror!ExpressRequest([]ContractStorageEntry),
    express_list_contracts_fn: *const fn (*anyopaque) anyerror!ExpressRequest([]ExpressContractState),
    express_create_checkpoint_fn: *const fn (*anyopaque, []const u8, std.mem.Allocator) anyerror!ExpressRequest([]u8),
    express_list_oracle_requests_fn: *const fn (*anyopaque) anyerror!ExpressRequest([]OracleRequest),
    express_create_oracle_response_tx_fn: *const fn (*anyopaque, TransactionAttribute, std.mem.Allocator) anyerror!ExpressRequest([]u8),
    express_shutdown_fn: *const fn (*anyopaque) anyerror!ExpressRequest(ExpressShutdown),
    
    /// Implementation instance
    implementation: *anyopaque,
    
    const Self = @This();
    
    /// Creates protocol implementation
    pub fn init(
        implementation: *anyopaque,
        express_get_populated_blocks_fn: *const fn (*anyopaque) anyerror!ExpressRequest(PopulatedBlocks),
        express_get_nep17_contracts_fn: *const fn (*anyopaque) anyerror!ExpressRequest([]Nep17Contract),
        express_get_contract_storage_fn: *const fn (*anyopaque, Hash160, std.mem.Allocator) anyerror!ExpressRequest([]ContractStorageEntry),
        express_list_contracts_fn: *const fn (*anyopaque) anyerror!ExpressRequest([]ExpressContractState),
        express_create_checkpoint_fn: *const fn (*anyopaque, []const u8, std.mem.Allocator) anyerror!ExpressRequest([]u8),
        express_list_oracle_requests_fn: *const fn (*anyopaque) anyerror!ExpressRequest([]OracleRequest),
        express_create_oracle_response_tx_fn: *const fn (*anyopaque, TransactionAttribute, std.mem.Allocator) anyerror!ExpressRequest([]u8),
        express_shutdown_fn: *const fn (*anyopaque) anyerror!ExpressRequest(ExpressShutdown),
    ) Self {
        return Self{
            .implementation = implementation,
            .express_get_populated_blocks_fn = express_get_populated_blocks_fn,
            .express_get_nep17_contracts_fn = express_get_nep17_contracts_fn,
            .express_get_contract_storage_fn = express_get_contract_storage_fn,
            .express_list_contracts_fn = express_list_contracts_fn,
            .express_create_checkpoint_fn = express_create_checkpoint_fn,
            .express_list_oracle_requests_fn = express_list_oracle_requests_fn,
            .express_create_oracle_response_tx_fn = express_create_oracle_response_tx_fn,
            .express_shutdown_fn = express_shutdown_fn,
        };
    }
    
    /// Gets populated blocks (equivalent to Swift expressGetPopulatedBlocks)
    pub fn expressGetPopulatedBlocks(self: Self) !ExpressRequest(PopulatedBlocks) {
        return try self.express_get_populated_blocks_fn(self.implementation);
    }
    
    /// Gets NEP-17 contracts (equivalent to Swift expressGetNep17Contracts)
    pub fn expressGetNep17Contracts(self: Self) !ExpressRequest([]Nep17Contract) {
        return try self.express_get_nep17_contracts_fn(self.implementation);
    }
    
    /// Gets contract storage (equivalent to Swift expressGetContractStorage)
    pub fn expressGetContractStorage(self: Self, contract_hash: Hash160, allocator: std.mem.Allocator) !ExpressRequest([]ContractStorageEntry) {
        return try self.express_get_contract_storage_fn(self.implementation, contract_hash, allocator);
    }
    
    /// Lists contracts (equivalent to Swift expressListContracts)
    pub fn expressListContracts(self: Self) !ExpressRequest([]ExpressContractState) {
        return try self.express_list_contracts_fn(self.implementation);
    }
    
    /// Creates checkpoint (equivalent to Swift expressCreateCheckpoint)
    pub fn expressCreateCheckpoint(self: Self, filename: []const u8, allocator: std.mem.Allocator) !ExpressRequest([]u8) {
        return try self.express_create_checkpoint_fn(self.implementation, filename, allocator);
    }
    
    /// Lists oracle requests (equivalent to Swift expressListOracleRequests)
    pub fn expressListOracleRequests(self: Self) !ExpressRequest([]OracleRequest) {
        return try self.express_list_oracle_requests_fn(self.implementation);
    }
    
    /// Creates oracle response transaction (equivalent to Swift expressCreateOracleResponseTx)
    pub fn expressCreateOracleResponseTx(self: Self, oracle_response: TransactionAttribute, allocator: std.mem.Allocator) !ExpressRequest([]u8) {
        return try self.express_create_oracle_response_tx_fn(self.implementation, oracle_response, allocator);
    }
    
    /// Shuts down express node (equivalent to Swift expressShutdown)
    pub fn expressShutdown(self: Self) !ExpressRequest(ExpressShutdown) {
        return try self.express_shutdown_fn(self.implementation);
    }
};

/// Helper type definitions (used in the protocol)
const ExpressRequest = @import("neo_swift_express.zig").ExpressRequest;
const PopulatedBlocks = @import("neo_swift_express.zig").PopulatedBlocks;
const Nep17Contract = @import("neo_swift_express.zig").Nep17Contract;
const ContractStorageEntry = @import("neo_swift_express.zig").ContractStorageEntry;
const ExpressContractState = @import("neo_swift_express.zig").ExpressContractState;
const TransactionAttribute = @import("../response/transaction_attribute.zig").TransactionAttribute;

/// Oracle request structure
pub const OracleRequest = struct {
    id: u64,
    url: []const u8,
    filter: []const u8,
    callback_contract: Hash160,
    user_data: []const u8,
    
    const Self = @This();
    
    pub fn init(id: u64, url: []const u8, filter: []const u8, callback_contract: Hash160, user_data: []const u8) Self {
        return Self{
            .id = id,
            .url = url,
            .filter = filter,
            .callback_contract = callback_contract,
            .user_data = user_data,
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.filter);
        allocator.free(self.user_data);
    }
};

/// Express shutdown response
pub const ExpressShutdown = struct {
    success: bool,
    message: []const u8,
    
    const Self = @This();
    
    pub fn init(success: bool, message: []const u8) Self {
        return Self{ .success = success, .message = message };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
    }
};

// Tests (converted from Swift NeoExpress protocol tests)
test "NeoExpressProtocol method signatures" {
    const testing = std.testing;
    
    // Test protocol method signatures exist (equivalent to Swift protocol tests)
    // Note: This is a conceptual test - actual testing would require implementations
    
    // Verify all required method function pointers exist
    const mock_impl = undefined;
    const mock_fn1 = struct {
        fn f(impl: *anyopaque) anyerror!ExpressRequest(PopulatedBlocks) {
            _ = impl;
            return error.NotImplemented;
        }
    }.f;
    const mock_fn2 = struct {
        fn f(impl: *anyopaque) anyerror!ExpressRequest([]Nep17Contract) {
            _ = impl;
            return error.NotImplemented;
        }
    }.f;
    const mock_fn3 = struct {
        fn f(impl: *anyopaque, hash: Hash160, allocator: std.mem.Allocator) anyerror!ExpressRequest([]ContractStorageEntry) {
            _ = impl;
            _ = hash;
            _ = allocator;
            return error.NotImplemented;
        }
    }.f;
    const mock_fn4 = struct {
        fn f(impl: *anyopaque) anyerror!ExpressRequest([]ExpressContractState) {
            _ = impl;
            return error.NotImplemented;
        }
    }.f;
    const mock_fn5 = struct {
        fn f(impl: *anyopaque, filename: []const u8, allocator: std.mem.Allocator) anyerror!ExpressRequest([]u8) {
            _ = impl;
            _ = filename;
            _ = allocator;
            return error.NotImplemented;
        }
    }.f;
    const mock_fn6 = struct {
        fn f(impl: *anyopaque) anyerror!ExpressRequest([]OracleRequest) {
            _ = impl;
            return error.NotImplemented;
        }
    }.f;
    const mock_fn7 = struct {
        fn f(impl: *anyopaque, attr: TransactionAttribute, allocator: std.mem.Allocator) anyerror!ExpressRequest([]u8) {
            _ = impl;
            _ = attr;
            _ = allocator;
            return error.NotImplemented;
        }
    }.f;
    const mock_fn8 = struct {
        fn f(impl: *anyopaque) anyerror!ExpressRequest(ExpressShutdown) {
            _ = impl;
            return error.NotImplemented;
        }
    }.f;
    
    const protocol = NeoExpressProtocol.init(
        mock_impl,
        mock_fn1,
        mock_fn2,
        mock_fn3,
        mock_fn4,
        mock_fn5,
        mock_fn6,
        mock_fn7,
        mock_fn8,
    );
    
    // Test that protocol structure is created correctly
    try testing.expect(protocol.implementation == mock_impl);
    
    // Test method calls would throw NotImplemented
    try testing.expectError(
        error.NotImplemented,
        protocol.expressGetPopulatedBlocks()
    );
}

test "Express helper types" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test OracleRequest
    const url = try allocator.dupe(u8, "https://api.example.com/data");
    const filter = try allocator.dupe(u8, "$.result");
    const user_data = try allocator.dupe(u8, "test_data");
    const callback_contract = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    var oracle_request = OracleRequest.init(123, url, filter, callback_contract, user_data);
    defer oracle_request.deinit(allocator);
    
    try testing.expectEqual(@as(u64, 123), oracle_request.id);
    try testing.expectEqualStrings("https://api.example.com/data", oracle_request.url);
    try testing.expectEqualStrings("$.result", oracle_request.filter);
    try testing.expect(oracle_request.callback_contract.eql(callback_contract));
    try testing.expectEqualStrings("test_data", oracle_request.user_data);
    
    // Test ExpressShutdown
    const message = try allocator.dupe(u8, "Shutdown successful");
    var shutdown = ExpressShutdown.init(true, message);
    defer shutdown.deinit(allocator);
    
    try testing.expect(shutdown.success);
    try testing.expectEqualStrings("Shutdown successful", shutdown.message);
}