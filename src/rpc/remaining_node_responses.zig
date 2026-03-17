const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const StringUtils = @import("../utils/string_extensions.zig").StringUtils;

/// Neo get version response
pub const NeoGetVersion = struct {
    tcp_port: u16,
    ws_port: u16,
    nonce: u32,
    user_agent: []const u8,
    protocol: ?ProtocolSettings,

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
            // Some nodes omit `wsport` when WebSocket is disabled.
            .ws_port = if (obj.get("wsport")) |port| @intCast(port.integer) else 0,
            .nonce = @intCast(obj.get("nonce").?.integer),
            .user_agent = try allocator.dupe(u8, obj.get("useragent").?.string),
            .protocol = if (obj.get("protocol")) |p| try ProtocolSettings.fromJson(p, allocator) else null,
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

    /// Protocol settings
    pub const ProtocolSettings = struct {
        network: u32,
        address_version: u8,
        validators_count: ?u32,
        ms_per_block: ?u32,
        max_valid_until_block_increment: ?u32,
        max_traceable_blocks: ?u32,
        max_transactions_per_block: ?u32,
        memory_pool_max_transactions: ?u32,
        initial_gas_distribution: ?u64,
        hardforks: ?[]HardforkInfo,
        standby_committee: ?[]PublicKey,
        seed_list: ?[][]const u8,

        pub const HardforkInfo = struct {
            name: []const u8,
            block_height: u32,

            pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !HardforkInfo {
                if (json_value != .object) return errors.SerializationError.InvalidFormat;
                const obj = json_value.object;
                const name_value = obj.get("name") orelse return errors.SerializationError.InvalidFormat;
                if (name_value != .string) return errors.SerializationError.InvalidFormat;
                const block_height = try parseOptionalInt(u32, obj, "blockheight") orelse {
                    return errors.SerializationError.InvalidFormat;
                };
                return HardforkInfo{
                    .name = try allocator.dupe(u8, name_value.string),
                    .block_height = block_height,
                };
            }

            pub fn deinit(self: *HardforkInfo, allocator: std.mem.Allocator) void {
                allocator.free(@constCast(self.name));
            }
        };

        pub fn init() ProtocolSettings {
            return ProtocolSettings{
                .network = 0,
                .address_version = 0,
                .validators_count = null,
                .ms_per_block = null,
                .max_valid_until_block_increment = null,
                .max_traceable_blocks = null,
                .max_transactions_per_block = null,
                .memory_pool_max_transactions = null,
                .initial_gas_distribution = null,
                .hardforks = null,
                .standby_committee = null,
                .seed_list = null,
            };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ProtocolSettings {
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

            return ProtocolSettings{
                .network = @intCast(obj.get("network").?.integer),
                .address_version = @intCast(obj.get("addressversion").?.integer),
                .validators_count = try parseOptionalInt(u32, obj, "validatorscount"),
                .ms_per_block = try parseOptionalInt(u32, obj, "msperblock"),
                .max_valid_until_block_increment = try parseOptionalInt(u32, obj, "maxvaliduntilblockincrement"),
                .max_traceable_blocks = try parseOptionalInt(u32, obj, "maxtraceableblocks"),
                .max_transactions_per_block = try parseOptionalInt(u32, obj, "maxtransactionsperblock"),
                .memory_pool_max_transactions = try parseOptionalInt(u32, obj, "memorypoolmaxtransactions"),
                .initial_gas_distribution = try parseOptionalInt(u64, obj, "initialgasdistribution"),
                .hardforks = hardforks_list,
                .standby_committee = standby_committee_list,
                .seed_list = seed_list_value,
            };
        }

        pub fn deinit(self: *ProtocolSettings, allocator: std.mem.Allocator) void {
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

        fn parseOptionalInt(comptime T: type, obj: std.json.ObjectMap, key: []const u8) !?T {
            const value = obj.get(key) orelse return null;
            return switch (value) {
                .integer => |i| @as(T, @intCast(i)),
                .string => |s| std.fmt.parseInt(T, s, 10) catch errors.SerializationError.InvalidFormat,
                .null => null,
                else => errors.SerializationError.InvalidFormat,
            };
        }
    };
};

/// Neo send raw transaction response
pub const NeoSendRawTransaction = struct {
    hash: Hash256,

    pub fn init() NeoSendRawTransaction {
        return NeoSendRawTransaction{ .hash = Hash256.ZERO };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoSendRawTransaction {
        _ = allocator;
        const obj = json_value.object;

        return NeoSendRawTransaction{
            .hash = try Hash256.initWithString(obj.get("hash").?.string),
        };
    }
};
