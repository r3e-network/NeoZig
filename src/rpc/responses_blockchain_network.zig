const std = @import("std");
const ArrayList = std.ArrayList;

const common = @import("responses_common.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;
const StringUtils = @import("../utils/string_extensions.zig").StringUtils;
const PublicKey = @import("../crypto/keys.zig").PublicKey;

const parseIntFromJson = common.parseIntFromJson;

/// Neo version response
pub const NeoVersion = struct {
    tcp_port: u16,
    ws_port: u16,
    nonce: u32,
    user_agent: []const u8,
    protocol: ?ProtocolConfiguration,

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
            .ws_port = if (obj.get("wsport")) |port| @intCast(port.integer) else 0,
            .nonce = @intCast(obj.get("nonce").?.integer),
            .user_agent = try allocator.dupe(u8, obj.get("useragent").?.string),
            .protocol = if (obj.get("protocol")) |p| try ProtocolConfiguration.fromJson(p, allocator) else null,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.user_agent.len > 0) {
            allocator.free(@constCast(self.user_agent));
            self.user_agent = "";
        }
        if (self.protocol) |*protocol| {
            protocol.deinit(allocator);
        }
        self.protocol = null;
    }
};

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

        const block_value = obj.get("blockheight") orelse return errors.SerializationError.InvalidFormat;
        const block_height = try parseIntFromJson(u32, block_value);

        return try HardforkInfo.init(name_value.string, block_height, allocator);
    }

    pub fn deinit(self: *HardforkInfo, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.name));
    }
};

/// Protocol configuration
pub const ProtocolConfiguration = struct {
    network: u32,
    address_version: u8,
    ms_per_block: ?u32,
    max_valid_until_block_increment: ?u32,
    max_traceable_blocks: ?u32,
    max_transactions_per_block: ?u32,
    memory_pool_max_transactions: ?u32,
    validators_count: ?u32,
    initial_gas_distribution: ?u64,
    hardforks: ?[]HardforkInfo,
    standby_committee: ?[]PublicKey,
    seed_list: ?[][]const u8,

    pub fn init() ProtocolConfiguration {
        return ProtocolConfiguration{
            .network = 0,
            .address_version = 0,
            .ms_per_block = null,
            .max_valid_until_block_increment = null,
            .max_traceable_blocks = null,
            .max_transactions_per_block = null,
            .memory_pool_max_transactions = null,
            .validators_count = null,
            .initial_gas_distribution = null,
            .hardforks = null,
            .standby_committee = null,
            .seed_list = null,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ProtocolConfiguration {
        const obj = json_value.object;

        var hardforks_list: ?[]HardforkInfo = null;
        errdefer if (hardforks_list) |items| {
            for (items) |*item| item.deinit(allocator);
            allocator.free(items);
        };
        if (obj.get("hardforks")) |hardforks_value| {
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
        if (obj.get("standbycommittee")) |committee_value| {
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
        if (obj.get("seedlist")) |seed_value| {
            if (seed_value != .array) return errors.SerializationError.InvalidFormat;
            var seeds = ArrayList([]const u8).init(allocator);
            errdefer seeds.deinit();
            for (seed_value.array.items) |item| {
                if (item != .string) return errors.SerializationError.InvalidFormat;
                try seeds.append(try allocator.dupe(u8, item.string));
            }
            seed_list_value = try seeds.toOwnedSlice();
        }

        return ProtocolConfiguration{
            .network = @intCast(obj.get("network").?.integer),
            .address_version = @intCast(obj.get("addressversion").?.integer),
            .ms_per_block = if (obj.get("msperblock")) |v| try parseIntFromJson(u32, v) else null,
            .max_valid_until_block_increment = if (obj.get("maxvaliduntilblockincrement")) |v| try parseIntFromJson(u32, v) else null,
            .max_traceable_blocks = if (obj.get("maxtraceableblocks")) |v| try parseIntFromJson(u32, v) else null,
            .max_transactions_per_block = if (obj.get("maxtransactionsperblock")) |v| try parseIntFromJson(u32, v) else null,
            .memory_pool_max_transactions = if (obj.get("memorypoolmaxtransactions")) |v| try parseIntFromJson(u32, v) else null,
            .validators_count = if (obj.get("validatorscount")) |v| try parseIntFromJson(u32, v) else null,
            .initial_gas_distribution = if (obj.get("initialgasdistribution")) |v| try parseIntFromJson(u64, v) else null,
            .hardforks = hardforks_list,
            .standby_committee = standby_committee_list,
            .seed_list = seed_list_value,
        };
    }

    pub fn deinit(self: *ProtocolConfiguration, allocator: std.mem.Allocator) void {
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
};

/// Network fee response
pub const NetworkFeeResponse = struct {
    network_fee: u64,

    pub fn init() NetworkFeeResponse {
        return NetworkFeeResponse{ .network_fee = 0 };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NetworkFeeResponse {
        _ = allocator;
        return switch (json_value) {
            .integer => |value| NetworkFeeResponse{ .network_fee = @intCast(value) },
            .string => |str| NetworkFeeResponse{ .network_fee = try parseFee(str) },
            .object => |obj| blk: {
                const field = obj.get("networkfee") orelse return errors.SerializationError.InvalidFormat;
                break :blk NetworkFeeResponse{ .network_fee = switch (field) {
                    .integer => |value| @intCast(value),
                    .string => |str| try parseFee(str),
                    else => return errors.SerializationError.InvalidFormat,
                } };
            },
            else => errors.SerializationError.InvalidFormat,
        };
    }

    fn parseFee(str: []const u8) !u64 {
        return std.fmt.parseInt(u64, str, 10) catch errors.SerializationError.InvalidFormat;
    }
};

/// Send transaction response
pub const SendRawTransactionResponse = struct {
    success: bool,
    hash: ?Hash256,

    pub fn init() SendRawTransactionResponse {
        return SendRawTransactionResponse{ .success = false, .hash = null };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !SendRawTransactionResponse {
        _ = allocator;
        return switch (json_value) {
            .bool => |value| SendRawTransactionResponse{ .success = value, .hash = null },
            .string => |str| SendRawTransactionResponse{
                .success = true,
                .hash = try Hash256.initWithString(str),
            },
            .object => |obj| blk: {
                if (obj.get("hash")) |hash_value| {
                    const hash = switch (hash_value) {
                        .string => |str| try Hash256.initWithString(str),
                        else => return errors.SerializationError.InvalidFormat,
                    };
                    break :blk SendRawTransactionResponse{ .success = true, .hash = hash };
                }
                if (obj.get("success")) |success_value| {
                    const success = switch (success_value) {
                        .bool => |b| b,
                        else => return errors.SerializationError.InvalidFormat,
                    };
                    break :blk SendRawTransactionResponse{ .success = success, .hash = null };
                }
                return errors.SerializationError.InvalidFormat;
            },
            else => errors.SerializationError.InvalidFormat,
        };
    }
};
