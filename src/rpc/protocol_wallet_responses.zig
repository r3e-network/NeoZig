const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;

/// Wallet balance response
pub const NeoGetWalletBalance = struct {
    balance: []const u8,

    pub fn init() NeoGetWalletBalance {
        return NeoGetWalletBalance{ .balance = "0" };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetWalletBalance {
        const obj = json_value.object;

        return NeoGetWalletBalance{
            .balance = try allocator.dupe(u8, obj.get("balance").?.string),
        };
    }

    pub fn deinit(self: *NeoGetWalletBalance, allocator: std.mem.Allocator) void {
        if (self.balance.len > 0 and (self.balance.ptr != "0".ptr or self.balance.len != "0".len)) {
            allocator.free(@constCast(self.balance));
        }
        self.balance = "0";
    }
};

/// Claimable GAS response
pub const NeoGetClaimable = struct {
    claimable: []const ClaimableTransaction,
    address: []const u8,
    unclaimed: []const u8,

    pub fn init() NeoGetClaimable {
        return NeoGetClaimable{
            .claimable = &[_]ClaimableTransaction{},
            .address = "",
            .unclaimed = "0",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetClaimable {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = NeoGetClaimable.init();
        errdefer result.deinit(allocator);

        if (obj.get("claimable")) |claimable_array| {
            if (claimable_array != .array) return errors.SerializationError.InvalidFormat;
            var claimable = ArrayList(ClaimableTransaction).init(allocator);
            errdefer claimable.deinit();
            for (claimable_array.array.items) |item| {
                try claimable.append(try ClaimableTransaction.fromJson(item, allocator));
            }
            result.claimable = try claimable.toOwnedSlice();
        }

        const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
        if (address_value != .string) return errors.SerializationError.InvalidFormat;
        result.address = try allocator.dupe(u8, address_value.string);

        const unclaimed_value = obj.get("unclaimed") orelse return errors.SerializationError.InvalidFormat;
        if (unclaimed_value != .string) return errors.SerializationError.InvalidFormat;
        result.unclaimed = try allocator.dupe(u8, unclaimed_value.string);

        return result;
    }

    pub fn deinit(self: *NeoGetClaimable, allocator: std.mem.Allocator) void {
        if (self.claimable.len > 0) {
            allocator.free(@constCast(self.claimable));
            self.claimable = &[_]ClaimableTransaction{};
        }
        if (self.address.len > 0) allocator.free(@constCast(self.address));
        if (self.unclaimed.len > 0 and (self.unclaimed.ptr != "0".ptr or self.unclaimed.len != "0".len)) {
            allocator.free(@constCast(self.unclaimed));
        }
        self.address = "";
        self.unclaimed = "0";
    }
};

/// Claimable transaction
pub const ClaimableTransaction = struct {
    tx_id: Hash256,
    n: u32,
    value: u64,
    start_height: u32,
    end_height: u32,

    pub fn init() ClaimableTransaction {
        return std.mem.zeroes(ClaimableTransaction);
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ClaimableTransaction {
        _ = allocator;
        const obj = json_value.object;

        return ClaimableTransaction{
            .tx_id = try Hash256.initWithString(obj.get("txid").?.string),
            .n = @as(u32, @intCast(obj.get("n").?.integer)),
            .value = @as(u64, @intCast(obj.get("value").?.integer)),
            .start_height = @as(u32, @intCast(obj.get("start_height").?.integer)),
            .end_height = @as(u32, @intCast(obj.get("end_height").?.integer)),
        };
    }
};
