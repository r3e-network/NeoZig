//! Neo Swift Configuration Implementation
//!
//! Complete conversion from NeoSwift NeoSwiftConfig.swift
//! Provides configuration settings for Neo RPC client.

const std = @import("std");
const Hash160 = @import("../types/hash160.zig").Hash160;

/// Request counter for RPC calls (converted from Swift Counter)
pub const Counter = struct {
    value: std.atomic.Atomic(u32),
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .value = std.atomic.Atomic(u32).init(0),
        };
    }
    
    pub fn next(self: *Self) u32 {
        return self.value.fetchAdd(1, .SeqCst);
    }
    
    pub fn get(self: *Self) u32 {
        return self.value.load(.SeqCst);
    }
    
    pub fn reset(self: *Self) void {
        self.value.store(0, .SeqCst);
    }
};

/// Neo Swift configuration (converted from Swift NeoSwiftConfig)
pub const NeoSwiftConfig = struct {
    /// Default block time in milliseconds
    pub const DEFAULT_BLOCK_TIME: u32 = 15000;
    /// Default address version byte
    pub const DEFAULT_ADDRESS_VERSION: u8 = 0x35;
    /// Maximum valid until block increment base
    pub const MAX_VALID_UNTIL_BLOCK_INCREMENT_BASE: u32 = 86400000; // 24 hours in ms
    /// MainNet NNS contract hash
    pub const MAINNET_NNS_CONTRACT_HASH = Hash160.fromHexString("0x50ac1c37690cc2cfc594472833cf57505d5f46de") catch Hash160.ZERO;
    
    /// Global request counter
    var REQUEST_COUNTER = Counter.init();
    
    /// Global address version (static configuration)
    var address_version: u8 = DEFAULT_ADDRESS_VERSION;
    
    /// Network magic number (fetched from node)
    network_magic: ?u32,
    /// Block interval in milliseconds
    block_interval: u32,
    /// Maximum valid until block increment
    max_valid_until_block_increment: u32,
    /// Polling interval in milliseconds
    polling_interval: u32,
    /// Allow transmission on fault
    allows_transmission_on_fault: bool,
    /// NNS resolver contract hash
    nns_resolver: Hash160,
    
    const Self = @This();
    
    /// Creates new configuration (equivalent to Swift init)
    pub fn init() Self {
        return Self{
            .network_magic = null,
            .block_interval = DEFAULT_BLOCK_TIME,
            .max_valid_until_block_increment = MAX_VALID_UNTIL_BLOCK_INCREMENT_BASE / DEFAULT_BLOCK_TIME,
            .polling_interval = DEFAULT_BLOCK_TIME,
            .allows_transmission_on_fault = false,
            .nns_resolver = MAINNET_NNS_CONTRACT_HASH,
        };
    }
    
    /// Creates configuration with parameters
    pub fn initWithParams(
        network_magic: ?u32,
        block_interval: u32,
        max_valid_until_block_increment: u32,
        polling_interval: u32,
        allows_transmission_on_fault: bool,
        nns_resolver: Hash160,
    ) Self {
        return Self{
            .network_magic = network_magic,
            .block_interval = block_interval,
            .max_valid_until_block_increment = max_valid_until_block_increment,
            .polling_interval = polling_interval,
            .allows_transmission_on_fault = allows_transmission_on_fault,
            .nns_resolver = nns_resolver,
        };
    }
    
    /// Sets network magic (equivalent to Swift setNetworkMagic)
    pub fn setNetworkMagic(self: *Self, magic: u32) *Self {
        self.network_magic = magic;
        return self;
    }
    
    /// Sets block interval (equivalent to Swift setBlockInterval)
    pub fn setBlockInterval(self: *Self, interval: u32) *Self {
        self.block_interval = interval;
        self.max_valid_until_block_increment = MAX_VALID_UNTIL_BLOCK_INCREMENT_BASE / interval;
        return self;
    }
    
    /// Sets polling interval (equivalent to Swift setPollingInterval)
    pub fn setPollingInterval(self: *Self, interval: u32) *Self {
        self.polling_interval = interval;
        return self;
    }
    
    /// Allows transmission on fault (equivalent to Swift allowTransmissionOnFault)
    pub fn allowTransmissionOnFault(self: *Self) *Self {
        self.allows_transmission_on_fault = true;
        return self;
    }
    
    /// Sets NNS resolver (equivalent to Swift setNnsResolver)
    pub fn setNnsResolver(self: *Self, resolver: Hash160) *Self {
        self.nns_resolver = resolver;
        return self;
    }
    
    /// Gets global address version (equivalent to Swift static addressVersion)
    pub fn getAddressVersion() u8 {
        return address_version;
    }
    
    /// Sets global address version (equivalent to Swift static addressVersion setter)
    pub fn setAddressVersion(version: u8) void {
        address_version = version;
    }
    
    /// Gets next request ID (equivalent to Swift REQUEST_COUNTER)
    pub fn getNextRequestId() u32 {
        return REQUEST_COUNTER.next();
    }
    
    /// Gets current request counter value
    pub fn getCurrentRequestId() u32 {
        return REQUEST_COUNTER.get();
    }
    
    /// Resets request counter
    pub fn resetRequestCounter() void {
        REQUEST_COUNTER.reset();
    }
    
    /// Validates configuration
    pub fn validate(self: Self) !void {
        if (self.block_interval == 0) {
            return error.InvalidBlockInterval;
        }
        
        if (self.polling_interval == 0) {
            return error.InvalidPollingInterval;
        }
        
        if (self.max_valid_until_block_increment == 0) {
            return error.InvalidMaxValidUntilBlockIncrement;
        }
        
        try self.nns_resolver.validate();
    }
    
    /// Checks if network magic is set
    pub fn hasNetworkMagic(self: Self) bool {
        return self.network_magic != null;
    }
    
    /// Gets network magic or default
    pub fn getNetworkMagicOrDefault(self: Self, default_magic: u32) u32 {
        return self.network_magic orelse default_magic;
    }
    
    /// Checks if configured for mainnet
    pub fn isMainnet(self: Self) bool {
        if (self.network_magic) |magic| {
            return magic == 0x4e454f00; // MainNet magic
        }
        return false;
    }
    
    /// Checks if configured for testnet
    pub fn isTestnet(self: Self) bool {
        if (self.network_magic) |magic| {
            return magic == 0x4e454f01; // TestNet magic
        }
        return false;
    }
    
    /// Gets block time in seconds
    pub fn getBlockTimeSeconds(self: Self) f64 {
        return @as(f64, @floatFromInt(self.block_interval)) / 1000.0;
    }
    
    /// Gets max transaction lifetime in seconds
    pub fn getMaxTransactionLifetimeSeconds(self: Self) f64 {
        return @as(f64, @floatFromInt(self.max_valid_until_block_increment * self.block_interval)) / 1000.0;
    }
    
    /// Creates MainNet configuration
    pub fn createMainNetConfig() Self {
        var config = Self.init();
        config.network_magic = 0x4e454f00;
        config.nns_resolver = MAINNET_NNS_CONTRACT_HASH;
        return config;
    }
    
    /// Creates TestNet configuration
    pub fn createTestNetConfig() Self {
        var config = Self.init();
        config.network_magic = 0x4e454f01;
        // TestNet might have different NNS resolver
        return config;
    }
    
    /// Creates development configuration (fast polling)
    pub fn createDevConfig() Self {
        var config = Self.init();
        config.block_interval = 1000;     // 1 second blocks
        config.polling_interval = 500;    // 0.5 second polling
        config.allows_transmission_on_fault = true; // Allow for testing
        return config;
    }
    
    /// Creates production configuration (conservative settings)
    pub fn createProductionConfig() Self {
        var config = Self.init();
        config.block_interval = DEFAULT_BLOCK_TIME;
        config.polling_interval = DEFAULT_BLOCK_TIME * 2; // Less frequent polling
        config.allows_transmission_on_fault = false; // Conservative
        return config;
    }
    
    /// JSON encoding
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const network_magic_str = if (self.network_magic) |magic|
            try std.fmt.allocPrint(allocator, "{}", .{magic})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(network_magic_str);
        
        const nns_resolver_str = try self.nns_resolver.toString(allocator);
        defer allocator.free(nns_resolver_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"networkMagic\":{s},\"blockInterval\":{},\"maxValidUntilBlockIncrement\":{},\"pollingInterval\":{},\"allowsTransmissionOnFault\":{},\"nnsResolver\":\"{s}\"}}",
            .{
                network_magic_str,
                self.block_interval,
                self.max_valid_until_block_increment,
                self.polling_interval,
                self.allows_transmission_on_fault,
                nns_resolver_str,
            }
        );
    }
    
    /// JSON decoding
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const network_magic = if (json_obj.get("networkMagic")) |magic_value|
            switch (magic_value) {
                .integer => |i| @as(u32, @intCast(i)),
                .null => null,
                else => null,
            }
        else
            null;
        
        const block_interval = @as(u32, @intCast(json_obj.get("blockInterval").?.integer));
        const max_valid_until_block_increment = @as(u32, @intCast(json_obj.get("maxValidUntilBlockIncrement").?.integer));
        const polling_interval = @as(u32, @intCast(json_obj.get("pollingInterval").?.integer));
        const allows_transmission_on_fault = json_obj.get("allowsTransmissionOnFault").?.bool;
        
        const nns_resolver_str = json_obj.get("nnsResolver").?.string;
        const nns_resolver = try Hash160.initWithString(nns_resolver_str);
        
        return Self.initWithParams(
            network_magic,
            block_interval,
            max_valid_until_block_increment,
            polling_interval,
            allows_transmission_on_fault,
            nns_resolver,
        );
    }
    
    /// Clone configuration
    pub fn clone(self: Self) Self {
        return Self.initWithParams(
            self.network_magic,
            self.block_interval,
            self.max_valid_until_block_increment,
            self.polling_interval,
            self.allows_transmission_on_fault,
            self.nns_resolver,
        );
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const network_name = if (self.isMainnet()) 
            "MainNet" 
        else if (self.isTestnet()) 
            "TestNet" 
        else 
            "Unknown";
        
        return try std.fmt.allocPrint(
            allocator,
            "NeoSwiftConfig(network: {s}, block_time: {}ms, polling: {}ms, fault_allowed: {})",
            .{ 
                network_name, 
                self.block_interval, 
                self.polling_interval, 
                self.allows_transmission_on_fault 
            }
        );
    }
};

// Tests (converted from Swift NeoSwiftConfig tests)
test "NeoSwiftConfig creation and defaults" {
    const testing = std.testing;
    
    // Test default configuration (equivalent to Swift tests)
    const config = NeoSwiftConfig.init();
    
    try testing.expect(config.network_magic == null);
    try testing.expectEqual(@as(u32, NeoSwiftConfig.DEFAULT_BLOCK_TIME), config.block_interval);
    try testing.expectEqual(@as(u32, NeoSwiftConfig.DEFAULT_BLOCK_TIME), config.polling_interval);
    try testing.expect(!config.allows_transmission_on_fault);
    try testing.expect(config.nns_resolver.eql(NeoSwiftConfig.MAINNET_NNS_CONTRACT_HASH));
    
    // Test validation
    try config.validate();
}

test "NeoSwiftConfig parameter configuration" {
    const testing = std.testing;
    
    // Test configuration with parameters
    var config = NeoSwiftConfig.init();
    
    _ = config.setNetworkMagic(0x4e454f00);
    try testing.expect(config.hasNetworkMagic());
    try testing.expect(config.isMainnet());
    try testing.expect(!config.isTestnet());
    
    _ = config.setBlockInterval(5000);
    try testing.expectEqual(@as(u32, 5000), config.block_interval);
    
    _ = config.setPollingInterval(2500);
    try testing.expectEqual(@as(u32, 2500), config.polling_interval);
    
    _ = config.allowTransmissionOnFault();
    try testing.expect(config.allows_transmission_on_fault);
}

test "NeoSwiftConfig preset configurations" {
    const testing = std.testing;
    
    // Test MainNet configuration
    const mainnet_config = NeoSwiftConfig.createMainNetConfig();
    try testing.expect(mainnet_config.isMainnet());
    try testing.expect(!mainnet_config.isTestnet());
    try testing.expectEqual(@as(u32, 0x4e454f00), mainnet_config.network_magic.?);
    
    // Test TestNet configuration
    const testnet_config = NeoSwiftConfig.createTestNetConfig();
    try testing.expect(testnet_config.isTestnet());
    try testing.expect(!testnet_config.isMainnet());
    try testing.expectEqual(@as(u32, 0x4e454f01), testnet_config.network_magic.?);
    
    // Test development configuration
    const dev_config = NeoSwiftConfig.createDevConfig();
    try testing.expectEqual(@as(u32, 1000), dev_config.block_interval);
    try testing.expectEqual(@as(u32, 500), dev_config.polling_interval);
    try testing.expect(dev_config.allows_transmission_on_fault);
    
    // Test production configuration
    const prod_config = NeoSwiftConfig.createProductionConfig();
    try testing.expectEqual(@as(u32, NeoSwiftConfig.DEFAULT_BLOCK_TIME), prod_config.block_interval);
    try testing.expectEqual(@as(u32, NeoSwiftConfig.DEFAULT_BLOCK_TIME * 2), prod_config.polling_interval);
    try testing.expect(!prod_config.allows_transmission_on_fault);
}

test "NeoSwiftConfig global settings" {
    const testing = std.testing;
    
    // Test global address version
    const original_version = NeoSwiftConfig.getAddressVersion();
    
    NeoSwiftConfig.setAddressVersion(0x99);
    try testing.expectEqual(@as(u8, 0x99), NeoSwiftConfig.getAddressVersion());
    
    // Restore original
    NeoSwiftConfig.setAddressVersion(original_version);
    try testing.expectEqual(original_version, NeoSwiftConfig.getAddressVersion());
}

test "NeoSwiftConfig request counter" {
    const testing = std.testing;
    
    // Test request counter
    const original_count = NeoSwiftConfig.getCurrentRequestId();
    
    const id1 = NeoSwiftConfig.getNextRequestId();
    const id2 = NeoSwiftConfig.getNextRequestId();
    const id3 = NeoSwiftConfig.getNextRequestId();
    
    try testing.expect(id2 == id1 + 1);
    try testing.expect(id3 == id2 + 1);
    
    // Reset counter
    NeoSwiftConfig.resetRequestCounter();
    const reset_id = NeoSwiftConfig.getNextRequestId();
    try testing.expectEqual(@as(u32, 0), reset_id);
}

test "NeoSwiftConfig time calculations" {
    const testing = std.testing;
    
    // Test time calculations
    const config = NeoSwiftConfig.init();
    
    const block_time_seconds = config.getBlockTimeSeconds();
    try testing.expectEqual(@as(f64, 15.0), block_time_seconds);
    
    const max_lifetime_seconds = config.getMaxTransactionLifetimeSeconds();
    try testing.expect(max_lifetime_seconds > 3600.0); // Should be over 1 hour
}

test "NeoSwiftConfig JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding
    var original_config = NeoSwiftConfig.createMainNetConfig();
    _ = original_config.setBlockInterval(10000);
    _ = original_config.allowTransmissionOnFault();
    
    const json_str = try original_config.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "10000") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "true") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "networkMagic") != null);
    
    const decoded_config = try NeoSwiftConfig.decodeFromJson(json_str, allocator);
    
    try testing.expectEqual(original_config.network_magic, decoded_config.network_magic);
    try testing.expectEqual(original_config.block_interval, decoded_config.block_interval);
    try testing.expectEqual(original_config.allows_transmission_on_fault, decoded_config.allows_transmission_on_fault);
}