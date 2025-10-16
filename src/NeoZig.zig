//! NeoZig - Main Neo Zig SDK Client
//!
//! Complete conversion from NeoSwift NeoSwift.swift
//! Provides the main client interface for Neo blockchain interaction.

const std = @import("std");

const Hash160 = @import("types/hash160.zig").Hash160;
const NeoSwiftConfig = @import("rpc/neo_swift_config.zig").NeoSwiftConfig;
const NeoSwiftService = @import("rpc/neo_swift_service.zig").NeoSwiftService;
const ServiceImplementation = @import("rpc/neo_swift_service.zig").ServiceImplementation;
const HttpService = @import("rpc/http_service.zig").HttpService;
const JsonRpc2_0Rx = @import("protocol/json_rpc_2_0_rx.zig").JsonRpc2_0Rx;
const Neo = @import("protocol/neo_protocol.zig").NeoProtocol;
const NeoSwiftRx = @import("protocol/neo_swift_rx.zig").NeoSwiftRx;
const errors = @import("core/errors.zig");

/// Main Neo Zig SDK client (converted from Swift NeoSwift class)
pub const NeoZig = struct {
    /// Configuration
    config: NeoSwiftConfig,
    /// Neo service for RPC communication
    neo_swift_service: NeoSwiftService,
    /// Reactive client (lazy initialized)
    neo_swift_rx: ?JsonRpc2_0Rx,
    /// Allocator for memory management
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Creates new NeoZig instance (equivalent to Swift required init)
    pub fn init(config: NeoSwiftConfig, neo_swift_service: NeoSwiftService, allocator: std.mem.Allocator) Self {
        return Self{
            .config = config,
            .neo_swift_service = neo_swift_service,
            .neo_swift_rx = null,
            .allocator = allocator,
        };
    }

    /// Builder method (equivalent to Swift build static func)
    pub fn build(neo_swift_service: NeoSwiftService, config: ?NeoSwiftConfig, allocator: std.mem.Allocator) Self {
        const final_config = config orelse NeoSwiftConfig.init();
        return Self.init(final_config, neo_swift_service, allocator);
    }

    /// Gets NNS resolver (equivalent to Swift nnsResolver property)
    pub fn getNnsResolver(self: Self) Hash160 {
        return self.config.nns_resolver;
    }

    /// Gets block interval (equivalent to Swift blockInterval property)
    pub fn getBlockInterval(self: Self) u32 {
        return self.config.block_interval;
    }

    /// Gets polling interval (equivalent to Swift pollingInterval property)
    pub fn getPollingInterval(self: Self) u32 {
        return self.config.polling_interval;
    }

    /// Gets max valid until block increment (equivalent to Swift maxValidUntilBlockIncrement property)
    pub fn getMaxValidUntilBlockIncrement(self: Self) u32 {
        return self.config.max_valid_until_block_increment;
    }

    /// Allow transmission on fault (equivalent to Swift allowTransmissionOnFault)
    pub fn allowTransmissionOnFault(self: *Self) void {
        self.config.allows_transmission_on_fault = true;
    }

    /// Gets reactive client (equivalent to Swift lazy neoSwiftRx)
    pub fn getNeoSwiftRx(self: *Self) *JsonRpc2_0Rx {
        if (self.neo_swift_rx == null) {
            const self_ptr: *anyopaque = @ptrCast(self);
            self.neo_swift_rx = JsonRpc2_0Rx.init(
                self_ptr,
                getBlockCountCallback,
                getBlockByIndexCallback,
                self.config.polling_interval,
                self.allocator,
            );
        }
        return &self.neo_swift_rx.?;
    }

    /// Gets configuration
    pub fn getConfig(self: Self) NeoSwiftConfig {
        return self.config;
    }

    /// Gets mutable reference to underlying service
    pub fn getService(self: *Self) *NeoSwiftService {
        return &self.neo_swift_service;
    }

    /// Updates configuration
    pub fn updateConfig(self: *Self, new_config: NeoSwiftConfig) void {
        self.config = new_config;
    }

    /// Sets NNS resolver
    pub fn setNnsResolver(self: *Self, resolver: Hash160) void {
        self.config.nns_resolver = resolver;
    }

    /// Sets block interval
    pub fn setBlockInterval(self: *Self, interval: u32) void {
        self.config.block_interval = interval;
        self.config.max_valid_until_block_increment = NeoSwiftConfig.MAX_VALID_UNTIL_BLOCK_INCREMENT_BASE / interval;
    }

    /// Sets polling interval
    pub fn setPollingInterval(self: *Self, interval: u32) void {
        self.config.polling_interval = interval;
    }

    /// Checks if transmission on fault is allowed
    pub fn isTransmissionOnFaultAllowed(self: Self) bool {
        return self.config.allows_transmission_on_fault;
    }

    /// Gets network magic number
    pub fn getNetworkMagic(self: Self) ?u32 {
        return self.config.network_magic;
    }

    /// Sets network magic number
    pub fn setNetworkMagic(self: *Self, magic: u32) void {
        self.config.network_magic = magic;
    }

    pub fn getBlockCount(self: *Self) !u32 {
        var neo = Neo.init(self.getService());
        var request = try neo.getBlockCount();
        const response = try request.sendUsing(self.getService());

        const count = response.getBlockCount() orelse return errors.NeoError.InvalidConfiguration;
        return count;
    }

    pub fn getBlockByIndex(
        self: *Self,
        block_index: u32,
        full_transaction_objects: bool,
    ) !response_aliases.NeoGetBlock {
        var neo = Neo.init(self.getService());
        var request = try neo.getBlockByIndex(block_index, full_transaction_objects);
        return try request.sendUsing(self.getService());
    }

    /// Checks if connected to mainnet
    pub fn isMainnet(self: Self) bool {
        return self.config.isMainnet();
    }

    /// Checks if connected to testnet
    pub fn isTestnet(self: Self) bool {
        return self.config.isTestnet();
    }

    /// Gets block time in seconds
    pub fn getBlockTimeSeconds(self: Self) f64 {
        return self.config.getBlockTimeSeconds();
    }

    /// Gets max transaction lifetime in seconds
    pub fn getMaxTransactionLifetimeSeconds(self: Self) f64 {
        return self.config.getMaxTransactionLifetimeSeconds();
    }

    /// Validates client configuration
    pub fn validate(self: Self) !void {
        try self.config.validate();
        // Additional client-specific validation could be added here
    }

    /// Cleanup allocated resources
    pub fn deinit(self: *Self) void {
        if (self.neo_swift_rx) |*rx| {
            rx.deinit();
            self.neo_swift_rx = null;
        }
        self.neo_swift_service.deinit();
    }

    /// Clone client with new configuration
    pub fn cloneWithConfig(self: Self, new_config: NeoSwiftConfig) Self {
        return Self.init(new_config, self.neo_swift_service, self.allocator);
    }

    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const network_name = if (self.isMainnet())
            "MainNet"
        else if (self.isTestnet())
            "TestNet"
        else
            "Unknown";

        return try std.fmt.allocPrint(allocator, "NeoZig(network: {s}, block_time: {}ms, polling: {}ms, nns_resolver: available)", .{ network_name, self.getBlockInterval(), self.getPollingInterval() });
    }

    /// Factory methods for common configurations
    pub const Factory = struct {
        /// Creates NeoZig client for MainNet
        pub fn createMainNet(service: NeoSwiftService, allocator: std.mem.Allocator) Self {
            const config = NeoSwiftConfig.createMainNetConfig();
            return Self.init(config, service, allocator);
        }

        /// Creates NeoZig client for TestNet
        pub fn createTestNet(service: NeoSwiftService, allocator: std.mem.Allocator) Self {
            const config = NeoSwiftConfig.createTestNetConfig();
            return Self.init(config, service, allocator);
        }

        /// Creates NeoZig client for development
        pub fn createDev(service: NeoSwiftService, allocator: std.mem.Allocator) Self {
            const config = NeoSwiftConfig.createDevConfig();
            return Self.init(config, service, allocator);
        }

        /// Creates NeoZig client for production
        pub fn createProduction(service: NeoSwiftService, allocator: std.mem.Allocator) Self {
            const config = NeoSwiftConfig.createProductionConfig();
            return Self.init(config, service, allocator);
        }
    };
};

fn getBlockCountCallback(context: ?*anyopaque) !u32 {
    const ptr = context orelse return errors.NeoError.UnsupportedOperation;
    const client: *NeoZig = @ptrCast(@alignCast(ptr));
    return client.getBlockCount();
}

fn getBlockByIndexCallback(
    context: ?*anyopaque,
    block_index: u32,
    full_transactions: bool,
) !response_aliases.NeoGetBlock {
    const ptr = context orelse return errors.NeoError.UnsupportedOperation;
    const client: *NeoZig = @ptrCast(@alignCast(ptr));
    return client.getBlockByIndex(block_index, full_transactions);
}

// Tests (converted from Swift NeoSwift tests)
fn createTestService(allocator: std.mem.Allocator) !NeoSwiftService {
    const http_service = try allocator.create(HttpService);
    errdefer allocator.destroy(http_service);
    http_service.* = HttpService.init(allocator, "http://localhost:20332", false);
    const impl = ServiceImplementation.init(http_service, allocator, true);
    return NeoSwiftService.init(impl);
}

test "NeoZig creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test client creation (equivalent to Swift NeoSwift tests)
    const config = NeoSwiftConfig.init();
    var service = try createTestService(allocator);

    var client = NeoZig.init(config, service, allocator);
    service.relinquish();
    defer client.deinit();

    // Test configuration properties
    try testing.expectEqual(NeoSwiftConfig.DEFAULT_BLOCK_TIME, client.getBlockInterval());
    try testing.expectEqual(NeoSwiftConfig.DEFAULT_BLOCK_TIME, client.getPollingInterval());
    try testing.expect(!client.isTransmissionOnFaultAllowed());

    // Test validation
    try client.validate();
}

test "NeoZig factory methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test factory methods (equivalent to Swift factory tests)
    // Test MainNet client
    var mainnet_service = try createTestService(allocator);
    var mainnet_client = NeoZig.Factory.createMainNet(mainnet_service, allocator);
    mainnet_service.relinquish();
    defer mainnet_client.deinit();

    try testing.expect(mainnet_client.isMainnet());
    try testing.expect(!mainnet_client.isTestnet());

    // Test TestNet client
    var testnet_service = try createTestService(allocator);
    var testnet_client = NeoZig.Factory.createTestNet(testnet_service, allocator);
    testnet_service.relinquish();
    defer testnet_client.deinit();

    try testing.expect(testnet_client.isTestnet());
    try testing.expect(!testnet_client.isMainnet());

    // Test development client
    var dev_service = try createTestService(allocator);
    var dev_client = NeoZig.Factory.createDev(dev_service, allocator);
    dev_service.relinquish();
    defer dev_client.deinit();

    try testing.expectEqual(@as(u32, 1000), dev_client.getBlockInterval()); // Fast blocks for dev
    try testing.expect(dev_client.isTransmissionOnFaultAllowed()); // Allow faults for testing
}

test "NeoZig configuration management" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test configuration updates
    var service = try createTestService(allocator);

    var client = NeoZig.Factory.createDev(service, allocator);
    service.relinquish();
    defer client.deinit();

    // Test configuration changes
    client.setBlockInterval(5000);
    try testing.expectEqual(@as(u32, 5000), client.getBlockInterval());

    client.setPollingInterval(2500);
    try testing.expectEqual(@as(u32, 2500), client.getPollingInterval());

    client.allowTransmissionOnFault();
    try testing.expect(client.isTransmissionOnFaultAllowed());

    // Test network magic
    client.setNetworkMagic(0x4e454f00);
    try testing.expectEqual(@as(u32, 0x4e454f00), client.getNetworkMagic().?);
    try testing.expect(client.isMainnet());
}

test "NeoZig utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test utility methods
    var service = try createTestService(allocator);

    var client = NeoZig.Factory.createMainNet(service, allocator);
    service.relinquish();
    defer client.deinit();

    // Test time calculations
    const block_time = client.getBlockTimeSeconds();
    try testing.expectEqual(@as(f64, 15.0), block_time); // 15 second blocks

    const max_lifetime = client.getMaxTransactionLifetimeSeconds();
    try testing.expect(max_lifetime > 3600.0); // Should be over 1 hour

    // Test formatting
    const formatted = try client.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "NeoZig") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "MainNet") != null);
}

test "NeoZig reactive client access" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test reactive client access
    var service = try createTestService(allocator);

    var client = NeoZig.Factory.createDev(service, allocator);
    service.relinquish();
    defer client.deinit();

    // Test lazy initialization of reactive client
    const rx_client = client.getNeoSwiftRx();
    try testing.expect(rx_client.*.getDefaultPollingInterval() > 0);

    // Second access should return same instance
    const rx_client2 = client.getNeoSwiftRx();
    try testing.expectEqual(@as(*JsonRpc2_0Rx, rx_client), @as(*JsonRpc2_0Rx, rx_client2));
}
