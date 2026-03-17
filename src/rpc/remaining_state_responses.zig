const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

/// Neo find states response
pub const NeoFindStates = struct {
    first_proof: ?[]const u8,
    last_proof: ?[]const u8,
    truncated: bool,
    results: []const StateResult,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .first_proof = null,
            .last_proof = null,
            .truncated = false,
            .results = &[_]StateResult{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const first_proof = if (obj.get("firstproof")) |fp| blk: {
            if (fp != .string) return errors.SerializationError.InvalidFormat;
            break :blk try allocator.dupe(u8, fp.string);
        } else null;
        errdefer if (first_proof) |value| allocator.free(@constCast(value));

        const last_proof = if (obj.get("lastproof")) |lp| blk: {
            if (lp != .string) return errors.SerializationError.InvalidFormat;
            break :blk try allocator.dupe(u8, lp.string);
        } else null;
        errdefer if (last_proof) |value| allocator.free(@constCast(value));

        const truncated_value = obj.get("truncated") orelse return errors.SerializationError.InvalidFormat;
        if (truncated_value != .bool) return errors.SerializationError.InvalidFormat;
        const truncated = truncated_value.bool;

        var results = ArrayList(StateResult).init(allocator);
        errdefer results.deinit();
        if (obj.get("results")) |results_array| {
            if (results_array != .array) return errors.SerializationError.InvalidFormat;
            for (results_array.array.items) |result_item| {
                try results.append(try StateResult.fromJson(result_item, allocator));
            }
        }

        return Self{ .first_proof = first_proof, .last_proof = last_proof, .truncated = truncated, .results = try results.toOwnedSlice() };
    }

    /// State result entry
    pub const StateResult = struct {
        key: []const u8,
        value: []const u8,

        pub fn init() StateResult {
            return StateResult{ .key = "", .value = "" };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !StateResult {
            const obj = json_value.object;

            return StateResult{
                .key = try allocator.dupe(u8, obj.get("key").?.string),
                .value = try allocator.dupe(u8, obj.get("value").?.string),
            };
        }
    };
};

/// Neo get unspents response
pub const NeoGetUnspents = struct {
    balance: []const UnspentOutput,
    address: []const u8,

    pub fn init() NeoGetUnspents {
        return NeoGetUnspents{
            .balance = &[_]UnspentOutput{},
            .address = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetUnspents {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
        if (address_value != .string) return errors.SerializationError.InvalidFormat;
        const address = try allocator.dupe(u8, address_value.string);
        errdefer allocator.free(address);

        var balance_list = ArrayList(UnspentOutput).init(allocator);
        errdefer balance_list.deinit();
        if (obj.get("balance")) |balance_array| {
            if (balance_array != .array) return errors.SerializationError.InvalidFormat;
            for (balance_array.array.items) |balance_item| {
                try balance_list.append(try UnspentOutput.fromJson(balance_item, allocator));
            }
        }

        return NeoGetUnspents{ .balance = try balance_list.toOwnedSlice(), .address = address };
    }

    /// Unspent output
    pub const UnspentOutput = struct {
        tx_id: Hash256,
        n: u32,
        asset: Hash160,
        value: []const u8,
        address: []const u8,

        pub fn init() UnspentOutput {
            return std.mem.zeroes(UnspentOutput);
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !UnspentOutput {
            const obj = json_value.object;

            return UnspentOutput{
                .tx_id = try Hash256.initWithString(obj.get("txid").?.string),
                .n = @intCast(obj.get("n").?.integer),
                .asset = try Hash160.initWithString(obj.get("asset").?.string),
                .value = try allocator.dupe(u8, obj.get("value").?.string),
                .address = try allocator.dupe(u8, obj.get("address").?.string),
            };
        }
    };
};
