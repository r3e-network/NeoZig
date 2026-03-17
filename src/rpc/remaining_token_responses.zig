const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

/// Generic token balances response
pub fn NeoGetTokenBalances(comptime T: type) type {
    return struct {
        result: ?T,

        const Self = @This();

        pub fn init() Self {
            return Self{ .result = null };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            return Self{
                .result = try T.fromJson(json_value, allocator),
            };
        }

        pub fn getBalances(self: Self) ?T {
            return self.result;
        }
    };
}

/// Token balances protocol trait
pub fn TokenBalances(comptime BalanceType: type) type {
    return struct {
        address: []const u8,
        balances: []const BalanceType,

        const Self = @This();

        pub fn init(address: []const u8, balances: []const BalanceType) Self {
            return Self{
                .address = address,
                .balances = balances,
            };
        }

        pub fn getAddress(self: Self) []const u8 {
            return self.address;
        }

        pub fn getBalances(self: Self) []const BalanceType {
            return self.balances;
        }

        pub fn getBalanceCount(self: Self) usize {
            return self.balances.len;
        }

        pub fn hasBalances(self: Self) bool {
            return self.balances.len > 0;
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            if (json_value != .object) return errors.SerializationError.InvalidFormat;
            const obj = json_value.object;

            const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
            if (address_value != .string) return errors.SerializationError.InvalidFormat;
            const address = try allocator.dupe(u8, address_value.string);
            errdefer allocator.free(address);

            var balance_list = ArrayList(BalanceType).init(allocator);
            errdefer balance_list.deinit();
            if (obj.get("balance")) |balance_array| {
                if (balance_array != .array) return errors.SerializationError.InvalidFormat;
                for (balance_array.array.items) |balance_item| {
                    try balance_list.append(try BalanceType.fromJson(balance_item, allocator));
                }
            }

            return Self.init(address, try balance_list.toOwnedSlice());
        }
    };
}

/// Token balance protocol trait
pub fn TokenBalance(comptime T: type) type {
    return struct {
        pub fn getAssetHash(self: T) Hash160 {
            return self.asset_hash;
        }

        pub fn hasAssetHash(self: T) bool {
            return !self.asset_hash.eql(Hash160.ZERO);
        }

        pub fn getAmount(self: T) []const u8 {
            return self.amount;
        }

        pub fn getAmountAsInt(self: T) !i64 {
            return std.fmt.parseInt(i64, self.amount, 10) catch {
                return errors.ValidationError.InvalidParameter;
            };
        }
    };
}

/// Neo get token transfers
pub const NeoGetTokenTransfers = struct {
    address: []const u8,
    sent: []const TokenTransfer,
    received: []const TokenTransfer,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .address = "",
            .sent = &[_]TokenTransfer{},
            .received = &[_]TokenTransfer{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
        if (address_value != .string) return errors.SerializationError.InvalidFormat;
        const address = try allocator.dupe(u8, address_value.string);
        errdefer allocator.free(address);

        var sent_list = ArrayList(TokenTransfer).init(allocator);
        errdefer sent_list.deinit();
        if (obj.get("sent")) |sent_array| {
            if (sent_array != .array) return errors.SerializationError.InvalidFormat;
            for (sent_array.array.items) |sent_item| {
                try sent_list.append(try TokenTransfer.fromJson(sent_item, allocator));
            }
        }

        var received_list = ArrayList(TokenTransfer).init(allocator);
        errdefer received_list.deinit();
        if (obj.get("received")) |received_array| {
            if (received_array != .array) return errors.SerializationError.InvalidFormat;
            for (received_array.array.items) |received_item| {
                try received_list.append(try TokenTransfer.fromJson(received_item, allocator));
            }
        }

        return Self{ .address = address, .sent = try sent_list.toOwnedSlice(), .received = try received_list.toOwnedSlice() };
    }

    /// Generic token transfer (base class)
    pub const TokenTransfer = struct {
        timestamp: u64,
        asset_hash: Hash160,
        transfer_address: []const u8,
        amount: []const u8,
        block_index: u32,
        transfer_notify_index: u32,
        tx_hash: Hash256,

        pub fn init() TokenTransfer {
            return std.mem.zeroes(TokenTransfer);
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TokenTransfer {
            const obj = json_value.object;

            return TokenTransfer{
                .timestamp = @intCast(obj.get("timestamp").?.integer),
                .asset_hash = try Hash160.initWithString(obj.get("assethash").?.string),
                .transfer_address = try allocator.dupe(u8, obj.get("transferaddress").?.string),
                .amount = try allocator.dupe(u8, obj.get("amount").?.string),
                .block_index = @intCast(obj.get("blockindex").?.integer),
                .transfer_notify_index = @intCast(obj.get("transfernotifyindex").?.integer),
                .tx_hash = try Hash256.initWithString(obj.get("txhash").?.string),
            };
        }
    };
};
