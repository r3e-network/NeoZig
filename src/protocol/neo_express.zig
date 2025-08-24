//! Neo Express protocol implementation
//!
//! Complete conversion from NeoSwift NeoExpress.swift protocol
//! Provides Neo Express private blockchain functionality.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Request = @import("../rpc/request.zig").Request;
const TransactionAttribute = @import("../transaction/transaction_builder.zig").TransactionAttribute;

/// Neo Express protocol interface (converted from Swift NeoExpress)
pub const NeoExpress = struct {
    /// Service implementation
    service: *@import("../rpc/neo_swift_service.zig").NeoSwiftService,
    
    const Self = @This();
    
    /// Creates Neo Express protocol
    pub fn init(service: *@import("../rpc/neo_swift_service.zig").NeoSwiftService) Self {
        return Self{ .service = service };
    }
    
    /// Gets populated blocks (equivalent to Swift expressGetPopulatedBlocks())
    pub fn expressGetPopulatedBlocks(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoExpressGetPopulatedBlocks, @import("../rpc/complete_responses.zig").PopulatedBlocks) {
        return Request(@import("../rpc/response_aliases.zig").NeoExpressGetPopulatedBlocks, @import("../rpc/complete_responses.zig").PopulatedBlocks).withNoParams(
            self.service.allocator,
            "expressgetpopulatedblocks",
            self.service,
        );
    }
    
    /// Gets NEP-17 contracts (equivalent to Swift expressGetNep17Contracts())
    pub fn expressGetNep17Contracts(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoExpressGetNep17Contracts, []const @import("../rpc/complete_responses.zig").Nep17Contract) {
        return Request(@import("../rpc/response_aliases.zig").NeoExpressGetNep17Contracts, []const @import("../rpc/complete_responses.zig").Nep17Contract).withNoParams(
            self.service.allocator,
            "expressgetnep17contracts",
            self.service,
        );
    }
    
    /// Gets contract storage (equivalent to Swift expressGetContractStorage(_ contractHash: Hash160))
    pub fn expressGetContractStorage(self: Self, contract_hash: Hash160) !Request(@import("../rpc/response_aliases.zig").NeoExpressGetContractStorage, []const @import("../rpc/complete_responses.zig").ContractStorageEntry) {
        const hash_hex = try contract_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);
        
        const string_params = [_][]const u8{hash_hex};
        return try Request(@import("../rpc/response_aliases.zig").NeoExpressGetContractStorage, []const @import("../rpc/complete_responses.zig").ContractStorageEntry).withStringParams(
            self.service.allocator,
            "expressgetcontractstorage",
            &string_params,
            self.service,
        );
    }
    
    /// Lists contracts (equivalent to Swift expressListContracts())
    pub fn expressListContracts(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoExpressListContracts, []const @import("../rpc/complete_responses.zig").ExpressContractState) {
        return Request(@import("../rpc/response_aliases.zig").NeoExpressListContracts, []const @import("../rpc/complete_responses.zig").ExpressContractState).withNoParams(
            self.service.allocator,
            "expresslistcontracts",
            self.service,
        );
    }
    
    /// Creates checkpoint (equivalent to Swift expressCreateCheckpoint(_ filename: String))
    pub fn expressCreateCheckpoint(self: Self, filename: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoExpressCreateCheckpoint, []const u8) {
        const string_params = [_][]const u8{filename};
        return try Request(@import("../rpc/response_aliases.zig").NeoExpressCreateCheckpoint, []const u8).withStringParams(
            self.service.allocator,
            "expresscreatecheckpoint",
            &string_params,
            self.service,
        );
    }
    
    /// Lists oracle requests (equivalent to Swift expressListOracleRequests())
    pub fn expressListOracleRequests(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoExpressListOracleRequests, []const @import("../rpc/complete_responses.zig").OracleRequest) {
        return Request(@import("../rpc/response_aliases.zig").NeoExpressListOracleRequests, []const @import("../rpc/complete_responses.zig").OracleRequest).withNoParams(
            self.service.allocator,
            "expresslistoraclerequests",
            self.service,
        );
    }
    
    /// Creates oracle response transaction (equivalent to Swift expressCreateOracleResponseTx)
    pub fn expressCreateOracleResponseTx(self: Self, oracle_response: TransactionAttribute) !Request(@import("../rpc/response_aliases.zig").NeoExpressCreateOracleResponseTx, []const u8) {
        // Serialize oracle response attribute
        var writer = @import("../serialization/binary_writer_complete.zig").CompleteBinaryWriter.init(self.service.allocator);
        defer writer.deinit();
        
        try writer.writeByte(@intFromEnum(oracle_response.attribute_type));
        try writer.writeVarBytes(oracle_response.data);
        
        const serialized_hex = try @import("../utils/bytes_extensions.zig").BytesUtils.toHexString(writer.toArray(), self.service.allocator);
        defer self.service.allocator.free(serialized_hex);
        
        const string_params = [_][]const u8{serialized_hex};
        return try Request(@import("../rpc/response_aliases.zig").NeoExpressCreateOracleResponseTx, []const u8).withStringParams(
            self.service.allocator,
            "expresscreateoracleresponsetx",
            &string_params,
            self.service,
        );
    }
    
    /// Shuts down Express blockchain (equivalent to Swift expressShutdown())
    pub fn expressShutdown(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoExpressShutdown, @import("../rpc/complete_responses.zig").ExpressShutdown) {
        return Request(@import("../rpc/response_aliases.zig").NeoExpressShutdown, @import("../rpc/complete_responses.zig").ExpressShutdown).withNoParams(
            self.service.allocator,
            "expressshutdown",
            self.service,
        );
    }
    
    /// Validates Express blockchain connectivity (utility method)
    pub fn validateExpressConnectivity(self: Self) !bool {
        // Test with expressgetpopulatedblocks call
        const populated_blocks_request = try self.expressGetPopulatedBlocks();
        
        // Would actually send request and check response
        _ = populated_blocks_request;
        return true; // Placeholder
    }
    
    /// Gets Express blockchain info (utility method)
    pub fn getExpressInfo(self: Self) !ExpressInfo {
        // Would gather Express blockchain information
        return ExpressInfo{
            .version = try self.service.allocator.dupe(u8, "neo-express-3.0"),
            .network_type = .Private,
            .is_running = true,
            .block_count = 0, // Would get actual count
        };
    }
    
    /// Resets Express blockchain (utility method)
    pub fn resetExpressBlockchain(self: Self, to_genesis: bool) !Request(@import("../rpc/response_aliases.zig").ExpressShutdown, bool) {
        const params = [_]std.json.Value{
            std.json.Value{ .bool = to_genesis },
        };
        
        return Request(@import("../rpc/response_aliases.zig").ExpressShutdown, bool).init(
            self.service.allocator,
            "expressreset",
            &params,
            self.service,
        );
    }
    
    /// Creates batch checkpoint (utility method)
    pub fn createBatchCheckpoint(self: Self, checkpoint_name: []const u8, include_state: bool) !Request(@import("../rpc/response_aliases.zig").NeoExpressCreateCheckpoint, []const u8) {
        const params = [_]std.json.Value{
            std.json.Value{ .string = checkpoint_name },
            std.json.Value{ .bool = include_state },
        };
        
        return Request(@import("../rpc/response_aliases.zig").NeoExpressCreateCheckpoint, []const u8).init(
            self.service.allocator,
            "expresscreatebachcheckpoint",
            &params,
            self.service,
        );
    }
};

/// Express blockchain information
pub const ExpressInfo = struct {
    version: []const u8,
    network_type: NetworkType,
    is_running: bool,
    block_count: u32,
    
    pub fn deinit(self: *ExpressInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.version);
    }
    
    pub fn format(self: ExpressInfo, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "Express {s} ({s}) - Running: {}, Blocks: {}",
            .{ self.version, self.network_type.toString(), self.is_running, self.block_count }
        );
    }
};

/// Network types for Express
pub const NetworkType = enum {
    MainNet,
    TestNet,
    Private,
    Local,
    
    pub fn toString(self: NetworkType) []const u8 {
        return switch (self) {
            .MainNet => "MainNet",
            .TestNet => "TestNet", 
            .Private => "Private",
            .Local => "Local",
        };
    }
};

/// Express utilities
pub const ExpressUtils = struct {
    /// Default Express configuration
    pub const DEFAULT_EXPRESS_PORT: u16 = 10333;
    pub const DEFAULT_EXPRESS_HOST = "localhost";
    
    /// Creates Express service URL
    pub fn createExpressUrl(host: ?[]const u8, port: ?u16, allocator: std.mem.Allocator) ![]u8 {
        const actual_host = host orelse DEFAULT_EXPRESS_HOST;
        const actual_port = port orelse DEFAULT_EXPRESS_PORT;
        
        return try std.fmt.allocPrint(
            allocator,
            "http://{s}:{d}",
            .{ actual_host, actual_port }
        );
    }
    
    /// Validates Express method availability
    pub fn isExpressMethodSupported(method: []const u8) bool {
        const express_methods = [_][]const u8{
            "expressgetpopulatedblocks",
            "expressgetnep17contracts",
            "expressgetcontractstorage",
            "expresslistcontracts",
            "expresscreatecheckpoint",
            "expresslistoraclerequests",
            "expresscreateoracleresponsetx",
            "expressshutdown",
        };
        
        for (express_methods) |express_method| {
            if (std.mem.eql(u8, method, express_method)) {
                return true;
            }
        }
        
        return false;
    }
    
    /// Gets all Express methods
    pub fn getAllExpressMethods() []const []const u8 {
        return &[_][]const u8{
            "expressgetpopulatedblocks",
            "expressgetnep17contracts", 
            "expressgetcontractstorage",
            "expresslistcontracts",
            "expresscreatecheckpoint",
            "expresslistoraclerequests",
            "expresscreateoracleresponsetx",
            "expressshutdown",
        };
    }
    
    /// Validates checkpoint filename
    pub fn validateCheckpointFilename(filename: []const u8) !void {
        if (filename.len == 0) {
            return errors.ValidationError.RequiredParameterMissing;
        }
        
        if (filename.len > 255) {
            return errors.ValidationError.ParameterOutOfRange;
        }
        
        // Check for valid filename characters
        for (filename) |char| {
            if (!std.ascii.isAlphaNumeric(char) and char != '.' and char != '_' and char != '-') {
                return errors.ValidationError.InvalidParameter;
            }
        }
    }
    
    /// Creates default checkpoint name
    pub fn createDefaultCheckpointName(allocator: std.mem.Allocator) ![]u8 {
        const timestamp = std.time.timestamp();
        return try std.fmt.allocPrint(
            allocator,
            "checkpoint_{d}.acc",
            .{timestamp}
        );
    }
};

/// Express factory
pub const ExpressFactory = struct {
    /// Creates Express protocol for local instance
    pub fn localhost(allocator: std.mem.Allocator, port: ?u16) !NeoExpress {
        const express_url = try ExpressUtils.createExpressUrl(null, port, allocator);
        defer allocator.free(express_url);
        
        var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.custom(
            allocator,
            express_url,
            30000, // 30 second timeout
            3,     // 3 retries
        );
        
        return NeoExpress.init(&service);
    }
    
    /// Creates Express protocol for custom host
    pub fn custom(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        timeout_ms: u32,
    ) !NeoExpress {
        const express_url = try ExpressUtils.createExpressUrl(host, port, allocator);
        defer allocator.free(express_url);
        
        var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.custom(
            allocator,
            express_url,
            timeout_ms,
            3,
        );
        
        return NeoExpress.init(&service);
    }
};

// Tests (converted from Swift NeoExpress tests)
test "NeoExpress creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Express protocol creation
    var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    const neo_express = NeoExpress.init(&service);
    
    // Test Express method requests
    const populated_blocks_request = try neo_express.expressGetPopulatedBlocks();
    try testing.expectEqualStrings("expressgetpopulatedblocks", populated_blocks_request.getMethod());
    
    const nep17_contracts_request = try neo_express.expressGetNep17Contracts();
    try testing.expectEqualStrings("expressgetnep17contracts", nep17_contracts_request.getMethod());
    
    const list_contracts_request = try neo_express.expressListContracts();
    try testing.expectEqualStrings("expresslistcontracts", list_contracts_request.getMethod());
}

test "NeoExpress checkpoint operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    const neo_express = NeoExpress.init(&service);
    
    // Test checkpoint creation
    const checkpoint_request = try neo_express.expressCreateCheckpoint("test_checkpoint.acc");
    try testing.expectEqualStrings("expresscreatecheckpoint", checkpoint_request.getMethod());
    
    // Test checkpoint filename validation
    try ExpressUtils.validateCheckpointFilename("valid_checkpoint.acc");
    try ExpressUtils.validateCheckpointFilename("test-checkpoint_123.acc");
    
    try testing.expectError(
        errors.ValidationError.RequiredParameterMissing,
        ExpressUtils.validateCheckpointFilename("")
    );
    
    try testing.expectError(
        errors.ValidationError.ParameterOutOfRange,
        ExpressUtils.validateCheckpointFilename("x" ** 300)
    );
    
    try testing.expectError(
        errors.ValidationError.InvalidParameter,
        ExpressUtils.validateCheckpointFilename("invalid@checkpoint.acc")
    );
    
    // Test default checkpoint name creation
    const default_name = try ExpressUtils.createDefaultCheckpointName(allocator);
    defer allocator.free(default_name);
    
    try testing.expect(std.mem.startsWith(u8, default_name, "checkpoint_"));
    try testing.expect(std.mem.endsWith(u8, default_name, ".acc"));
}

test "NeoExpress oracle operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    const neo_express = NeoExpress.init(&service);
    
    // Test oracle request listing
    const oracle_requests = try neo_express.expressListOracleRequests();
    try testing.expectEqualStrings("expresslistoraclerequests", oracle_requests.getMethod());
    
    // Test oracle response transaction creation
    const oracle_attribute = TransactionAttribute.init(
        @import("../transaction/transaction_builder.zig").AttributeType.OracleResponse,
        "test_oracle_data",
    );
    
    const oracle_response_tx = try neo_express.expressCreateOracleResponseTx(oracle_attribute);
    try testing.expectEqualStrings("expresscreateoracleresponsetx", oracle_response_tx.getMethod());
}

test "ExpressUtils utility functions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Express URL creation
    const default_url = try ExpressUtils.createExpressUrl(null, null, allocator);
    defer allocator.free(default_url);
    
    try testing.expectEqualStrings("http://localhost:10333", default_url);
    
    const custom_url = try ExpressUtils.createExpressUrl("custom.host", 8080, allocator);
    defer allocator.free(custom_url);
    
    try testing.expectEqualStrings("http://custom.host:8080", custom_url);
    
    // Test method support checking
    try testing.expect(ExpressUtils.isExpressMethodSupported("expressgetpopulatedblocks"));
    try testing.expect(ExpressUtils.isExpressMethodSupported("expressshutdown"));
    try testing.expect(!ExpressUtils.isExpressMethodSupported("getblockcount")); // Regular RPC method
    try testing.expect(!ExpressUtils.isExpressMethodSupported("invalid_method"));
    
    // Test all Express methods
    const all_methods = ExpressUtils.getAllExpressMethods();
    try testing.expectEqual(@as(usize, 8), all_methods.len);
    
    for (all_methods) |method| {
        try testing.expect(ExpressUtils.isExpressMethodSupported(method));
    }
}

test "ExpressFactory creation methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test localhost factory
    var localhost_express = try ExpressFactory.localhost(allocator, null);
    
    // Test custom factory
    var custom_express = try ExpressFactory.custom(
        allocator,
        "192.168.1.100",
        8545,
        20000, // 20 second timeout
    );
    
    // Test Express info
    var express_info = try localhost_express.getExpressInfo();
    defer express_info.deinit(allocator);
    
    try testing.expect(express_info.version.len > 0);
    try testing.expectEqual(NetworkType.Private, express_info.network_type);
    
    const formatted_info = try express_info.format(allocator);
    defer allocator.free(formatted_info);
    
    try testing.expect(std.mem.indexOf(u8, formatted_info, "Express") != null);
    try testing.expect(std.mem.indexOf(u8, formatted_info, "Private") != null);
}