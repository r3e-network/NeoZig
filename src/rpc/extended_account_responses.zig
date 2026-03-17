const std = @import("std");
const json_utils = @import("../utils/json_utils.zig");

const Hash160 = @import("../types/hash160.zig").Hash160;

/// Neo account state
pub const NeoAccountState = struct {
    balance: i64,
    balance_height: ?u32,
    public_key: ?[]const u8,

    const Self = @This();

    pub fn init(balance: i64, balance_height: ?u32, public_key: ?[]const u8) Self {
        return Self{
            .balance = balance,
            .balance_height = balance_height,
            .public_key = public_key,
        };
    }

    pub fn withNoVote(balance: i64, update_height: u32) Self {
        return Self.init(balance, update_height, null);
    }

    pub fn withNoBalance() Self {
        return Self.init(0, null, null);
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const balance = obj.get("balance").?.integer;
        const balance_height = if (obj.get("balanceHeight")) |bh| @as(u32, @intCast(bh.integer)) else null;
        const public_key = if (obj.get("voteTo")) |pk| try allocator.dupe(u8, pk.string) else null;

        return Self.init(balance, balance_height, public_key);
    }

    pub fn toJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var obj = std.json.ObjectMap.init(allocator);

        try json_utils.putOwnedKey(&obj, allocator, "balance", std.json.Value{ .integer = self.balance });

        if (self.balance_height) |bh| {
            try json_utils.putOwnedKey(&obj, allocator, "balanceHeight", std.json.Value{ .integer = @intCast(bh) });
        }

        if (self.public_key) |pk| {
            try json_utils.putOwnedKey(&obj, allocator, "voteTo", std.json.Value{ .string = pk });
        }

        return std.json.Value{ .object = obj };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.public_key) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
            self.public_key = null;
        }
    }
};

/// Neo address response
pub const NeoAddress = struct {
    address: []const u8,
    is_valid: bool,

    pub fn init(address: []const u8, is_valid: bool) NeoAddress {
        return NeoAddress{ .address = address, .is_valid = is_valid };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoAddress {
        const obj = json_value.object;

        return NeoAddress.init(
            try allocator.dupe(u8, obj.get("address").?.string),
            obj.get("isvalid").?.bool,
        );
    }

    pub fn deinit(self: *NeoAddress, allocator: std.mem.Allocator) void {
        if (self.address.len > 0) allocator.free(@constCast(self.address));
        self.address = "";
    }
};

/// Transaction send token
pub const TransactionSendToken = struct {
    asset: Hash160,
    value: i64,
    address: []const u8,

    pub fn init(asset: Hash160, value: i64, address: []const u8) TransactionSendToken {
        return TransactionSendToken{
            .asset = asset,
            .value = value,
            .address = address,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TransactionSendToken {
        const obj = json_value.object;

        return TransactionSendToken.init(
            try Hash160.initWithString(obj.get("asset").?.string),
            obj.get("value").?.integer,
            try allocator.dupe(u8, obj.get("address").?.string),
        );
    }

    pub fn toJson(self: TransactionSendToken, allocator: std.mem.Allocator) !std.json.Value {
        var obj = std.json.ObjectMap.init(allocator);

        const asset_hex = try self.asset.string(allocator);
        defer allocator.free(asset_hex);

        try json_utils.putOwnedKey(&obj, allocator, "asset", std.json.Value{ .string = asset_hex });
        try json_utils.putOwnedKey(&obj, allocator, "value", std.json.Value{ .integer = self.value });
        try json_utils.putOwnedKey(&obj, allocator, "address", std.json.Value{ .string = self.address });

        return std.json.Value{ .object = obj };
    }
};

/// Neo get unclaimed GAS
pub const NeoGetUnclaimedGas = struct {
    unclaimed: []const u8,
    address: []const u8,

    pub fn init() NeoGetUnclaimedGas {
        return NeoGetUnclaimedGas{
            .unclaimed = "0",
            .address = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetUnclaimedGas {
        const obj = json_value.object;

        return NeoGetUnclaimedGas{
            .unclaimed = try allocator.dupe(u8, obj.get("unclaimed").?.string),
            .address = try allocator.dupe(u8, obj.get("address").?.string),
        };
    }

    pub fn deinit(self: *NeoGetUnclaimedGas, allocator: std.mem.Allocator) void {
        if (self.unclaimed.len > 0) allocator.free(@constCast(self.unclaimed));
        if (self.address.len > 0) allocator.free(@constCast(self.address));
        self.unclaimed = "0";
        self.address = "";
    }
};

/// NEP-17 contract
pub const Nep17Contract = struct {
    script_hash: Hash160,
    symbol: []const u8,
    decimals: u8,

    pub fn init(script_hash: Hash160, symbol: []const u8, decimals: u8) Nep17Contract {
        return Nep17Contract{
            .script_hash = script_hash,
            .symbol = symbol,
            .decimals = decimals,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Nep17Contract {
        const obj = json_value.object;

        return Nep17Contract.init(
            try Hash160.initWithString(obj.get("scripthash").?.string),
            try allocator.dupe(u8, obj.get("symbol").?.string),
            @intCast(obj.get("decimals").?.integer),
        );
    }

    pub fn deinit(self: *Nep17Contract, allocator: std.mem.Allocator) void {
        if (self.symbol.len > 0) allocator.free(@constCast(self.symbol));
        self.symbol = "";
    }
};

/// Neo validate address
pub const NeoValidateAddress = struct {
    address: []const u8,
    is_valid: bool,

    pub fn init() NeoValidateAddress {
        return NeoValidateAddress{
            .address = "",
            .is_valid = false,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoValidateAddress {
        const obj = json_value.object;

        return NeoValidateAddress{
            .address = try allocator.dupe(u8, obj.get("address").?.string),
            .is_valid = obj.get("isvalid").?.bool,
        };
    }
};
