//! Neo GetVersion Response Implementation
//!
//! Complete conversion from NeoSwift NeoGetVersion.swift
//! Provides version information response for Neo RPC calls.

const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../../core/errors.zig");
const PublicKey = @import("../../crypto/keys.zig").PublicKey;
const StringUtils = @import("../../utils/string_extensions.zig").StringUtils;

/// Hardfork entry in protocol settings.
pub const HardforkInfo = struct {
    name: []const u8,
    block_height: u32,

    pub fn init(name: []const u8, block_height: u32, allocator: std.mem.Allocator) !HardforkInfo {
        return HardforkInfo{
            .name = try allocator.dupe(u8, name),
            .block_height = block_height,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !HardforkInfo {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;
        const name_value = obj.get("name") orelse return errors.SerializationError.InvalidFormat;
        if (name_value != .string) return errors.SerializationError.InvalidFormat;
        const height_value = obj.get("blockheight") orelse return errors.SerializationError.InvalidFormat;
        const block_height = switch (height_value) {
            .integer => |i| @as(u32, @intCast(i)),
            .string => |s| std.fmt.parseInt(u32, s, 10) catch errors.SerializationError.InvalidFormat,
            else => return errors.SerializationError.InvalidFormat,
        };
        return try HardforkInfo.init(name_value.string, block_height, allocator);
    }

    pub fn clone(self: HardforkInfo, allocator: std.mem.Allocator) !HardforkInfo {
        return try HardforkInfo.init(self.name, self.block_height, allocator);
    }

    pub fn deinit(self: *HardforkInfo, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.name));
    }
};

/// Neo protocol information (converted from Swift NeoProtocol)
pub const NeoProtocol = struct {
    /// Network magic number
    network: u32,
    /// Number of validators (optional)
    validators_count: ?u32,
    /// Milliseconds per block
    ms_per_block: u32,
    /// Maximum valid until block increment
    max_valid_until_block_increment: u32,
    /// Maximum traceable blocks
    max_traceable_blocks: u32,
    /// Address version
    address_version: u8,
    /// Maximum transactions per block
    max_transactions_per_block: u32,
    /// Memory pool maximum transactions
    memory_pool_max_transactions: u32,
    /// Initial GAS distribution
    initial_gas_distribution: u64,
    /// Hardforks (optional)
    hardforks: ?[]HardforkInfo,
    /// Standby committee (optional)
    standby_committee: ?[]PublicKey,
    /// Seed list (optional)
    seed_list: ?[][]const u8,

    const Self = @This();

    /// Creates new NeoProtocol (equivalent to Swift init)
    pub fn init(
        network: u32,
        validators_count: ?u32,
        ms_per_block: u32,
        max_valid_until_block_increment: u32,
        max_traceable_blocks: u32,
        address_version: u8,
        max_transactions_per_block: u32,
        memory_pool_max_transactions: u32,
        initial_gas_distribution: u64,
        hardforks: ?[]HardforkInfo,
        standby_committee: ?[]PublicKey,
        seed_list: ?[][]const u8,
    ) Self {
        return Self{
            .network = network,
            .validators_count = validators_count,
            .ms_per_block = ms_per_block,
            .max_valid_until_block_increment = max_valid_until_block_increment,
            .max_traceable_blocks = max_traceable_blocks,
            .address_version = address_version,
            .max_transactions_per_block = max_transactions_per_block,
            .memory_pool_max_transactions = memory_pool_max_transactions,
            .initial_gas_distribution = initial_gas_distribution,
            .hardforks = hardforks,
            .standby_committee = standby_committee,
            .seed_list = seed_list,
        };
    }

    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return self.network == other.network and
            self.validators_count == other.validators_count and
            self.ms_per_block == other.ms_per_block and
            self.max_valid_until_block_increment == other.max_valid_until_block_increment and
            self.max_traceable_blocks == other.max_traceable_blocks and
            self.address_version == other.address_version and
            self.max_transactions_per_block == other.max_transactions_per_block and
            self.memory_pool_max_transactions == other.memory_pool_max_transactions and
            self.initial_gas_distribution == other.initial_gas_distribution and
            optionalHardforksEqual(self.hardforks, other.hardforks) and
            optionalCommitteeEqual(self.standby_committee, other.standby_committee) and
            optionalSeedListEqual(self.seed_list, other.seed_list);
    }

    fn optionalHardforksEqual(a: ?[]HardforkInfo, b: ?[]HardforkInfo) bool {
        if (a == null and b == null) return true;
        if (a == null or b == null) return false;
        const a_items = a.?;
        const b_items = b.?;
        if (a_items.len != b_items.len) return false;
        for (a_items, 0..) |item, i| {
            if (item.block_height != b_items[i].block_height) return false;
            if (!std.mem.eql(u8, item.name, b_items[i].name)) return false;
        }
        return true;
    }

    fn optionalCommitteeEqual(a: ?[]PublicKey, b: ?[]PublicKey) bool {
        if (a == null and b == null) return true;
        if (a == null or b == null) return false;
        const a_items = a.?;
        const b_items = b.?;
        if (a_items.len != b_items.len) return false;
        for (a_items, 0..) |item, i| {
            if (!std.mem.eql(u8, item.toSlice(), b_items[i].toSlice())) return false;
        }
        return true;
    }

    fn optionalSeedListEqual(a: ?[][]const u8, b: ?[][]const u8) bool {
        if (a == null and b == null) return true;
        if (a == null or b == null) return false;
        const a_items = a.?;
        const b_items = b.?;
        if (a_items.len != b_items.len) return false;
        for (a_items, 0..) |item, i| {
            if (!std.mem.eql(u8, item, b_items[i])) return false;
        }
        return true;
    }

    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.network));
        if (self.validators_count) |count| {
            hasher.update(std.mem.asBytes(&count));
        }
        hasher.update(std.mem.asBytes(&self.ms_per_block));
        hasher.update(std.mem.asBytes(&self.max_valid_until_block_increment));
        hasher.update(std.mem.asBytes(&self.max_traceable_blocks));
        hasher.update(std.mem.asBytes(&self.address_version));
        hasher.update(std.mem.asBytes(&self.max_transactions_per_block));
        hasher.update(std.mem.asBytes(&self.memory_pool_max_transactions));
        hasher.update(std.mem.asBytes(&self.initial_gas_distribution));
        if (self.hardforks) |hardforks| {
            const count: u64 = @intCast(hardforks.len);
            hasher.update(std.mem.asBytes(&count));
            for (hardforks) |item| {
                hasher.update(item.name);
                hasher.update(std.mem.asBytes(&item.block_height));
            }
        }
        if (self.standby_committee) |committee| {
            const count: u64 = @intCast(committee.len);
            hasher.update(std.mem.asBytes(&count));
            for (committee) |item| {
                hasher.update(item.toSlice());
            }
        }
        if (self.seed_list) |seeds| {
            const count: u64 = @intCast(seeds.len);
            hasher.update(std.mem.asBytes(&count));
            for (seeds) |seed| {
                hasher.update(seed);
            }
        }
        return hasher.final();
    }

    /// Checks if protocol is for mainnet
    pub fn isMainnet(self: Self) bool {
        return self.network == 0x334F454E; // "NEO" as little-endian
    }

    /// Checks if protocol is for testnet
    pub fn isTestnet(self: Self) bool {
        return self.network == 0x3554334E; // "N3T" + version as little-endian
    }

    /// Gets block time in seconds
    pub fn getBlockTimeSeconds(self: Self) f64 {
        return @as(f64, @floatFromInt(self.ms_per_block)) / 1000.0;
    }

    /// Gets maximum transaction lifetime in blocks
    pub fn getMaxTransactionLifetime(self: Self) u32 {
        return self.max_valid_until_block_increment;
    }

    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const validators_str = if (self.validators_count) |count|
            try std.fmt.allocPrint(allocator, "{}", .{count})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(validators_str);

        return try std.fmt.allocPrint(allocator, "{{\"network\":{},\"validatorscount\":{s},\"msperblock\":{},\"maxvaliduntilblockincrement\":{},\"maxtraceableblocks\":{},\"addressversion\":{},\"maxtransactionsperblock\":{},\"memorypoolmaxtransactions\":{},\"initialgasdistribution\":{}}}", .{
            self.network,
            validators_str,
            self.ms_per_block,
            self.max_valid_until_block_increment,
            self.max_traceable_blocks,
            self.address_version,
            self.max_transactions_per_block,
            self.memory_pool_max_transactions,
            self.initial_gas_distribution,
        });
    }

    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        const json_obj = parsed.value.object;

        const network = @as(u32, @intCast(json_obj.get("network").?.integer));

        const validators_count = if (json_obj.get("validatorscount")) |count_value|
            switch (count_value) {
                .integer => |i| @as(u32, @intCast(i)),
                .null => null,
                else => null,
            }
        else
            null;

        const ms_per_block = @as(u32, @intCast(json_obj.get("msperblock").?.integer));
        const max_valid_until_block_increment = @as(u32, @intCast(json_obj.get("maxvaliduntilblockincrement").?.integer));
        const max_traceable_blocks = @as(u32, @intCast(json_obj.get("maxtraceableblocks").?.integer));
        const address_version = @as(u8, @intCast(json_obj.get("addressversion").?.integer));
        const max_transactions_per_block = @as(u32, @intCast(json_obj.get("maxtransactionsperblock").?.integer));
        const memory_pool_max_transactions = @as(u32, @intCast(json_obj.get("memorypoolmaxtransactions").?.integer));
        const initial_gas_distribution = @as(u64, @intCast(json_obj.get("initialgasdistribution").?.integer));

        var hardforks_list: ?[]HardforkInfo = null;
        errdefer if (hardforks_list) |items| {
            for (items) |*item| item.deinit(allocator);
            allocator.free(items);
        };
        if (json_obj.get("hardforks")) |hardforks_value| {
            if (hardforks_value != .array) return errors.SerializationError.InvalidFormat;
            var hardforks = ArrayList(HardforkInfo).init(allocator);
            errdefer hardforks.deinit();
            for (hardforks_value.array.items) |item| {
                try hardforks.append(try HardforkInfo.fromJson(item, allocator));
            }
            hardforks_list = try hardforks.toOwnedSlice();
        }

        var standby_committee_list: ?[]PublicKey = null;
        errdefer if (standby_committee_list) |items| allocator.free(items);
        if (json_obj.get("standbycommittee")) |committee_value| {
            if (committee_value != .array) return errors.SerializationError.InvalidFormat;
            var committee = ArrayList(PublicKey).init(allocator);
            errdefer committee.deinit();
            for (committee_value.array.items) |item| {
                if (item != .string) return errors.SerializationError.InvalidFormat;
                const key_bytes = try StringUtils.bytesFromHex(item.string, allocator);
                defer allocator.free(key_bytes);
                try committee.append(try PublicKey.initFromBytes(key_bytes));
            }
            standby_committee_list = try committee.toOwnedSlice();
        }

        var seed_list_value: ?[][]const u8 = null;
        errdefer if (seed_list_value) |items| {
            for (items) |seed| allocator.free(@constCast(seed));
            allocator.free(items);
        };
        if (json_obj.get("seedlist")) |seed_value| {
            if (seed_value != .array) return errors.SerializationError.InvalidFormat;
            var seeds = ArrayList([]const u8).init(allocator);
            errdefer seeds.deinit();
            for (seed_value.array.items) |item| {
                if (item != .string) return errors.SerializationError.InvalidFormat;
                try seeds.append(try allocator.dupe(u8, item.string));
            }
            seed_list_value = try seeds.toOwnedSlice();
        }

        return Self.init(
            network,
            validators_count,
            ms_per_block,
            max_valid_until_block_increment,
            max_traceable_blocks,
            address_version,
            max_transactions_per_block,
            memory_pool_max_transactions,
            initial_gas_distribution,
            hardforks_list,
            standby_committee_list,
            seed_list_value,
        );
    }

    /// Cleanup allocated resources.
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.hardforks) |items| {
            for (items) |*item| item.deinit(allocator);
            allocator.free(items);
            self.hardforks = null;
        }

        if (self.standby_committee) |committee| {
            allocator.free(committee);
            self.standby_committee = null;
        }

        if (self.seed_list) |seeds| {
            for (seeds) |seed| allocator.free(@constCast(seed));
            allocator.free(seeds);
            self.seed_list = null;
        }
    }

    /// Deep clone with owned memory.
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        var hardforks_copy: ?[]HardforkInfo = null;
        errdefer if (hardforks_copy) |items| {
            for (items) |*item| item.deinit(allocator);
            allocator.free(items);
        };
        if (self.hardforks) |hardforks| {
            var items = try allocator.alloc(HardforkInfo, hardforks.len);
            for (hardforks, 0..) |item, i| {
                items[i] = try item.clone(allocator);
            }
            hardforks_copy = items;
        }

        var committee_copy: ?[]PublicKey = null;
        errdefer if (committee_copy) |items| allocator.free(items);
        if (self.standby_committee) |committee| {
            committee_copy = try allocator.dupe(PublicKey, committee);
        }

        var seed_list_copy: ?[][]const u8 = null;
        errdefer if (seed_list_copy) |items| {
            for (items) |seed| allocator.free(@constCast(seed));
            allocator.free(items);
        };
        if (self.seed_list) |seeds| {
            var items = try allocator.alloc([]const u8, seeds.len);
            for (seeds, 0..) |seed, i| {
                items[i] = try allocator.dupe(u8, seed);
            }
            seed_list_copy = items;
        }

        return Self.init(
            self.network,
            self.validators_count,
            self.ms_per_block,
            self.max_valid_until_block_increment,
            self.max_traceable_blocks,
            self.address_version,
            self.max_transactions_per_block,
            self.memory_pool_max_transactions,
            self.initial_gas_distribution,
            hardforks_copy,
            committee_copy,
            seed_list_copy,
        );
    }
};

/// Neo version information (converted from Swift NeoVersion)
pub const NeoVersion = struct {
    /// TCP port
    tcp_port: ?u16,
    /// WebSocket port
    ws_port: ?u16,
    /// Node nonce
    nonce: u32,
    /// User agent string
    user_agent: []const u8,
    /// Protocol information
    protocol: ?NeoProtocol,

    const Self = @This();

    /// Creates new NeoVersion (equivalent to Swift init)
    pub fn init(
        tcp_port: ?u16,
        ws_port: ?u16,
        nonce: u32,
        user_agent: []const u8,
        neo_protocol: ?NeoProtocol,
    ) Self {
        return Self{
            .tcp_port = tcp_port,
            .ws_port = ws_port,
            .nonce = nonce,
            .user_agent = user_agent,
            .protocol = neo_protocol,
        };
    }

    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        if (self.tcp_port != other.tcp_port or
            self.ws_port != other.ws_port or
            self.nonce != other.nonce or
            !std.mem.eql(u8, self.user_agent, other.user_agent))
        {
            return false;
        }

        if (self.protocol == null and other.protocol == null) return true;
        if (self.protocol == null or other.protocol == null) return false;

        return self.protocol.?.eql(other.protocol.?);
    }

    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);

        if (self.tcp_port) |port| {
            hasher.update(std.mem.asBytes(&port));
        }

        if (self.ws_port) |port| {
            hasher.update(std.mem.asBytes(&port));
        }

        hasher.update(std.mem.asBytes(&self.nonce));
        hasher.update(self.user_agent);

        if (self.protocol) |protocol| {
            const protocol_hash = protocol.hash();
            hasher.update(std.mem.asBytes(&protocol_hash));
        }

        return hasher.final();
    }

    /// Gets the network name
    pub fn getNetworkName(self: Self) []const u8 {
        if (self.protocol) |protocol| {
            if (protocol.isMainnet()) return "MainNet";
            if (protocol.isTestnet()) return "TestNet";
        }
        return "Unknown";
    }

    /// Checks if node supports WebSocket
    pub fn supportsWebSocket(self: Self) bool {
        return self.ws_port != null;
    }

    /// Checks if node supports TCP
    pub fn supportsTcp(self: Self) bool {
        return self.tcp_port != null;
    }

    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const tcp_port_str = if (self.tcp_port) |port|
            try std.fmt.allocPrint(allocator, "{}", .{port})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(tcp_port_str);

        const ws_port_str = if (self.ws_port) |port|
            try std.fmt.allocPrint(allocator, "{}", .{port})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(ws_port_str);

        const protocol_str = if (self.protocol) |protocol|
            try protocol.encodeToJson(allocator)
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(protocol_str);

        return try std.fmt.allocPrint(allocator, "{{\"tcpport\":{s},\"wsport\":{s},\"nonce\":{},\"useragent\":\"{s}\",\"protocol\":{s}}}", .{ tcp_port_str, ws_port_str, self.nonce, self.user_agent, protocol_str });
    }

    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        const json_obj = parsed.value.object;

        const tcp_port = if (json_obj.get("tcpport")) |port_value|
            switch (port_value) {
                .integer => |i| @as(u16, @intCast(i)),
                .null => null,
                else => null,
            }
        else
            null;

        const ws_port = if (json_obj.get("wsport")) |port_value|
            switch (port_value) {
                .integer => |i| @as(u16, @intCast(i)),
                .null => null,
                else => null,
            }
        else
            null;

        const nonce = @as(u32, @intCast(json_obj.get("nonce").?.integer));
        const user_agent = try allocator.dupe(u8, json_obj.get("useragent").?.string);

        const protocol = if (json_obj.get("protocol")) |protocol_value|
            switch (protocol_value) {
                .object => blk: {
                    const protocol_json = try std.json.stringifyAlloc(allocator, protocol_value, .{});
                    defer allocator.free(protocol_json);
                    break :blk try NeoProtocol.decodeFromJson(protocol_json, allocator);
                },
                .null => null,
                else => null,
            }
        else
            null;

        return Self.init(tcp_port, ws_port, nonce, user_agent, protocol);
    }

    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.user_agent);
        if (self.protocol) |*protocol| {
            protocol.deinit(allocator);
        }
        self.protocol = null;
    }

    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const user_agent_copy = try allocator.dupe(u8, self.user_agent);
        const protocol_copy = if (self.protocol) |protocol|
            try protocol.clone(allocator)
        else
            null;
        return Self.init(self.tcp_port, self.ws_port, self.nonce, user_agent_copy, protocol_copy);
    }

    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "NeoVersion(agent: {s}, network: {s}, tcp: {?}, ws: {?}, nonce: {})", .{ self.user_agent, self.getNetworkName(), self.tcp_port, self.ws_port, self.nonce });
    }
};

/// GetVersion RPC response wrapper (converted from Swift NeoGetVersion)
pub const NeoGetVersion = struct {
    /// The version result
    result: ?NeoVersion,

    const Self = @This();

    /// Creates new GetVersion response
    pub fn init(result: ?NeoVersion) Self {
        return Self{ .result = result };
    }

    /// Gets the version (equivalent to Swift version property)
    pub fn getVersion(self: Self) ?NeoVersion {
        return self.result;
    }

    /// Checks if response contains valid version
    pub fn hasVersion(self: Self) bool {
        return self.result != null;
    }

    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.result) |*version| {
            version.deinit(allocator);
        }
    }
};

// Tests (converted from Swift NeoGetVersion tests)
test "NeoProtocol creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test protocol creation (equivalent to Swift tests)
    const protocol = NeoProtocol.init(
        0x334F454E, // MainNet magic
        7, // 7 validators
        15000, // 15 second blocks
        5760, // Max valid until block increment
        2102400, // Max traceable blocks
        53, // Address version
        512, // Max transactions per block
        50000, // Memory pool max transactions
        52000000, // Initial GAS distribution
        null,
        null,
        null,
    );

    try testing.expect(protocol.isMainnet());
    try testing.expect(!protocol.isTestnet());
    try testing.expectEqual(@as(f64, 15.0), protocol.getBlockTimeSeconds());
    try testing.expectEqual(@as(u32, 5760), protocol.getMaxTransactionLifetime());

    // Test JSON serialization
    const json_str = try protocol.encodeToJson(allocator);
    defer allocator.free(json_str);

    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "334F454E") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "15000") != null);

    const decoded_protocol = try NeoProtocol.decodeFromJson(json_str, allocator);
    try testing.expect(protocol.eql(decoded_protocol));
}

test "NeoVersion creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test version creation (equivalent to Swift tests)
    const user_agent = try allocator.dupe(u8, "NEO-GO:3.5.0");
    var version = NeoVersion.init(10333, 10334, 123456, user_agent, null);
    defer version.deinit(allocator);

    try testing.expect(version.supportsTcp());
    try testing.expect(version.supportsWebSocket());
    try testing.expectEqual(@as(u32, 123456), version.nonce);
    try testing.expectEqualStrings("NEO-GO:3.5.0", version.user_agent);
    try testing.expectEqualStrings("Unknown", version.getNetworkName());

    // Test formatting
    const formatted = try version.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "NEO-GO:3.5.0") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "10333") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "123456") != null);
}

test "NeoVersion with protocol" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test version with protocol information
    const protocol = NeoProtocol.init(
        0x3554334E, // TestNet magic
        4, // 4 validators
        15000, // 15 second blocks
        5760, // Max valid until block increment
        2102400, // Max traceable blocks
        53, // Address version
        512, // Max transactions per block
        50000, // Memory pool max transactions
        52000000, // Initial GAS distribution
        null,
        null,
        null,
    );

    const user_agent = try allocator.dupe(u8, "NEO-GO:3.5.0");
    var version = NeoVersion.init(10333, null, 789012, user_agent, protocol);
    defer version.deinit(allocator);

    try testing.expectEqualStrings("TestNet", version.getNetworkName());
    try testing.expect(version.supportsTcp());
    try testing.expect(!version.supportsWebSocket());

    // Test cloning
    var cloned_version = try version.clone(allocator);
    defer cloned_version.deinit(allocator);

    try testing.expect(version.eql(cloned_version));
}

test "NeoGetVersion response wrapper" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test GetVersion response wrapper
    const user_agent = try allocator.dupe(u8, "NEO-GO:3.5.0");
    const version = NeoVersion.init(10333, 10334, 555666, user_agent, null);

    var get_version_response = NeoGetVersion.init(version);
    defer get_version_response.deinit(allocator);

    try testing.expect(get_version_response.hasVersion());

    const retrieved_version = get_version_response.getVersion().?;
    try testing.expectEqual(@as(u32, 555666), retrieved_version.nonce);
    try testing.expectEqualStrings("NEO-GO:3.5.0", retrieved_version.user_agent);

    // Test empty response
    var empty_response = NeoGetVersion.init(null);
    defer empty_response.deinit(allocator);

    try testing.expect(!empty_response.hasVersion());
    try testing.expect(empty_response.getVersion() == null);
}
