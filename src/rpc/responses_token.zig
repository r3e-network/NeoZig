const std = @import("std");
const ArrayList = std.ArrayList;

const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

/// NEP-17 balances response
pub const Nep17Balances = struct {
    balance: []const TokenBalance,
    address: []const u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .balance = &[_]TokenBalance{},
            .address = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const address = try allocator.dupe(u8, obj.get("address").?.string);

        var balances = ArrayList(TokenBalance).init(allocator);
        if (obj.get("balance")) |balance_array| {
            for (balance_array.array.items) |balance_item| {
                try balances.append(try TokenBalance.fromJson(balance_item, allocator));
            }
        }

        return Self{
            .balance = try balances.toOwnedSlice(),
            .address = address,
        };
    }
};

/// Token balance
pub const TokenBalance = struct {
    asset_hash: Hash160,
    amount: []const u8,
    last_updated_block: u32,

    pub fn init() TokenBalance {
        return TokenBalance{
            .asset_hash = Hash160.ZERO,
            .amount = "0",
            .last_updated_block = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TokenBalance {
        const obj = json_value.object;

        return TokenBalance{
            .asset_hash = try Hash160.initWithString(obj.get("assethash").?.string),
            .amount = try allocator.dupe(u8, obj.get("amount").?.string),
            .last_updated_block = @intCast(obj.get("lastupdatedblock").?.integer),
        };
    }
};

/// NEP-17 transfers response
pub const Nep17Transfers = struct {
    sent: []const TokenTransfer,
    received: []const TokenTransfer,
    address: []const u8,

    pub fn init() Nep17Transfers {
        return Nep17Transfers{
            .sent = &[_]TokenTransfer{},
            .received = &[_]TokenTransfer{},
            .address = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Nep17Transfers {
        const obj = json_value.object;

        const address = try allocator.dupe(u8, obj.get("address").?.string);

        var sent = ArrayList(TokenTransfer).init(allocator);
        if (obj.get("sent")) |sent_array| {
            for (sent_array.array.items) |item| {
                try sent.append(try TokenTransfer.fromJson(item, allocator));
            }
        }

        var received = ArrayList(TokenTransfer).init(allocator);
        if (obj.get("received")) |received_array| {
            for (received_array.array.items) |item| {
                try received.append(try TokenTransfer.fromJson(item, allocator));
            }
        }

        return Nep17Transfers{
            .sent = try sent.toOwnedSlice(),
            .received = try received.toOwnedSlice(),
            .address = address,
        };
    }
};

/// Token transfer
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
