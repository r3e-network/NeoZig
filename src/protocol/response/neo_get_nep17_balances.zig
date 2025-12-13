//! Neo GetNep17Balances Implementation
//!
//! Complete conversion from NeoSwift NeoGetNep17Balances.swift
//! Provides NEP-17 token balance information for accounts.

const std = @import("std");
const ArrayList = std.ArrayList;


const Hash160 = @import("../../types/hash160.zig").Hash160;

/// NEP-17 balance for a specific token (converted from Swift Nep17Balance)
pub const Nep17Balance = struct {
    /// Token name
    name: ?[]const u8,
    /// Token symbol
    symbol: ?[]const u8,
    /// Token decimals
    decimals: ?[]const u8,
    /// Balance amount (as string to preserve precision)
    amount: []const u8,
    /// Last updated block number
    last_updated_block: f64,
    /// Asset hash (contract hash)
    asset_hash: Hash160,
    
    const Self = @This();
    
    /// Creates new NEP-17 balance (equivalent to Swift init)
    pub fn init(
        name: ?[]const u8,
        symbol: ?[]const u8,
        decimals: ?[]const u8,
        amount: []const u8,
        last_updated_block: f64,
        asset_hash: Hash160,
    ) Self {
        return Self{
            .name = name,
            .symbol = symbol,
            .decimals = decimals,
            .amount = amount,
            .last_updated_block = last_updated_block,
            .asset_hash = asset_hash,
        };
    }
    
    /// Gets token name or default
    pub fn getNameOrDefault(self: Self) []const u8 {
        return self.name orelse "Unknown Token";
    }
    
    /// Gets token symbol or default
    pub fn getSymbolOrDefault(self: Self) []const u8 {
        return self.symbol orelse "UNKNOWN";
    }
    
    /// Gets decimals as integer
    pub fn getDecimalsAsInt(self: Self) !u8 {
        if (self.decimals) |decimals_str| {
            return try std.fmt.parseInt(u8, decimals_str, 10);
        }
        return 0;
    }
    
    /// Gets amount as integer (considering decimals)
    pub fn getAmountAsInt(self: Self) !u64 {
        return try std.fmt.parseInt(u64, self.amount, 10);
    }
    
    /// Checks if balance is zero
    pub fn isZero(self: Self) bool {
        return std.mem.eql(u8, self.amount, "0");
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return self.asset_hash.eql(other.asset_hash) and
               std.mem.eql(u8, self.amount, other.amount) and
               self.last_updated_block == other.last_updated_block;
    }
    
    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        const asset_hash_value = self.asset_hash.hash();
        hasher.update(std.mem.asBytes(&asset_hash_value));
        hasher.update(self.amount);
        hasher.update(std.mem.asBytes(&self.last_updated_block));
        
        return hasher.final();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const asset_hash_str = try self.asset_hash.toString(allocator);
        defer allocator.free(asset_hash_str);
        
        const name_str = if (self.name) |name|
            try std.fmt.allocPrint(allocator, "\"{s}\"", .{name})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(name_str);
        
        const symbol_str = if (self.symbol) |symbol|
            try std.fmt.allocPrint(allocator, "\"{s}\"", .{symbol})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(symbol_str);
        
        const decimals_str = if (self.decimals) |decimals|
            try std.fmt.allocPrint(allocator, "\"{s}\"", .{decimals})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(decimals_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"name\":{s},\"symbol\":{s},\"decimals\":{s},\"amount\":\"{s}\",\"lastupdatedblock\":{d},\"assethash\":\"{s}\"}}",
            .{
                name_str,
                symbol_str,
                decimals_str,
                self.amount,
                self.last_updated_block,
                asset_hash_str,
            }
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }
        if (self.symbol) |symbol| {
            allocator.free(symbol);
        }
        if (self.decimals) |decimals| {
            allocator.free(decimals);
        }
        allocator.free(self.amount);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const name_copy = if (self.name) |name|
            try allocator.dupe(u8, name)
        else
            null;
        
        const symbol_copy = if (self.symbol) |symbol|
            try allocator.dupe(u8, symbol)
        else
            null;
        
        const decimals_copy = if (self.decimals) |decimals|
            try allocator.dupe(u8, decimals)
        else
            null;
        
        const amount_copy = try allocator.dupe(u8, self.amount);
        
        return Self.init(
            name_copy,
            symbol_copy,
            decimals_copy,
            amount_copy,
            self.last_updated_block,
            self.asset_hash,
        );
    }
};

/// NEP-17 balances collection (converted from Swift Nep17Balances)
pub const Nep17Balances = struct {
    /// Account address
    address: []const u8,
    /// Array of token balances
    balances: []Nep17Balance,
    
    const Self = @This();
    
    /// Creates new NEP-17 balances (equivalent to Swift init)
    pub fn init(address: []const u8, balances: []Nep17Balance) Self {
        return Self{
            .address = address,
            .balances = balances,
        };
    }
    
    /// Gets balance count
    pub fn getBalanceCount(self: Self) usize {
        return self.balances.len;
    }
    
    /// Gets balance for specific asset
    pub fn getBalanceForAsset(self: Self, asset_hash: Hash160) ?Nep17Balance {
        for (self.balances) |balance| {
            if (balance.asset_hash.eql(asset_hash)) {
                return balance;
            }
        }
        return null;
    }
    
    /// Gets total balance count
    pub fn getTotalTokenCount(self: Self) usize {
        return self.balances.len;
    }
    
    /// Gets non-zero balances
    pub fn getNonZeroBalances(self: Self, allocator: std.mem.Allocator) ![]Nep17Balance {
        var non_zero = ArrayList(Nep17Balance).init(allocator);
        defer non_zero.deinit();
        
        for (self.balances) |balance| {
            if (!balance.isZero()) {
                try non_zero.append(balance);
            }
        }
        
        return try non_zero.toOwnedSlice();
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        
        for (self.balances) |*balance| {
            balance.deinit(allocator);
        }
        allocator.free(self.balances);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const address_copy = try allocator.dupe(u8, self.address);
        
        var balances_copy = try ArrayList(Nep17Balance).initCapacity(allocator, self.balances.len);
        defer balances_copy.deinit();
        
        for (self.balances) |balance| {
            try balances_copy.append(try balance.clone(allocator));
        }
        
        return Self.init(address_copy, try balances_copy.toOwnedSlice());
    }
};

/// GetNep17Balances RPC response wrapper (converted from Swift NeoGetNep17Balances)
pub const NeoGetNep17Balances = struct {
    /// The balances result
    result: ?Nep17Balances,
    
    const Self = @This();
    
    /// Creates new GetNep17Balances response
    pub fn init(result: ?Nep17Balances) Self {
        return Self{ .result = result };
    }
    
    /// Gets the balances (equivalent to Swift balances property)
    pub fn getBalances(self: Self) ?Nep17Balances {
        return self.result;
    }
    
    /// Checks if response contains balances
    pub fn hasBalances(self: Self) bool {
        return self.result != null;
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.result) |*balances| {
            balances.deinit(allocator);
        }
    }
};

// Tests (converted from Swift NeoGetNep17Balances tests)
test "Nep17Balance creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test balance creation
    const asset_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const name = try allocator.dupe(u8, "TestToken");
    const symbol = try allocator.dupe(u8, "TEST");
    const decimals = try allocator.dupe(u8, "8");
    const amount = try allocator.dupe(u8, "1000000000");
    
    var balance = Nep17Balance.init(name, symbol, decimals, amount, 123456.0, asset_hash);
    defer balance.deinit(allocator);
    
    try testing.expectEqualStrings("TestToken", balance.getNameOrDefault());
    try testing.expectEqualStrings("TEST", balance.getSymbolOrDefault());
    try testing.expectEqual(@as(u8, 8), try balance.getDecimalsAsInt());
    try testing.expectEqual(@as(u64, 1000000000), try balance.getAmountAsInt());
    try testing.expect(!balance.isZero());
}

test "Nep17Balances collection operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create test balances
    const asset_hash1 = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const asset_hash2 = try Hash160.initWithString("0xabcdef1234567890abcdef1234567890abcdef12");
    
    const amount1 = try allocator.dupe(u8, "5000000000");
    const amount2 = try allocator.dupe(u8, "0");
    
    var balance1 = Nep17Balance.init(null, null, null, amount1, 100000.0, asset_hash1);
    defer balance1.deinit(allocator);
    
    var balance2 = Nep17Balance.init(null, null, null, amount2, 100001.0, asset_hash2);
    defer balance2.deinit(allocator);
    
    const balances_array = [_]Nep17Balance{ balance1, balance2 };
    const address = try allocator.dupe(u8, "NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj");
    defer allocator.free(address);
    
    var balances = Nep17Balances.init(address, &balances_array);
    
    try testing.expectEqual(@as(usize, 2), balances.getBalanceCount());
    try testing.expectEqual(@as(usize, 2), balances.getTotalTokenCount());
    
    // Test balance lookup
    const found_balance = balances.getBalanceForAsset(asset_hash1);
    try testing.expect(found_balance != null);
    try testing.expect(found_balance.?.asset_hash.eql(asset_hash1));
    
    const not_found = balances.getBalanceForAsset(try Hash160.initWithString("0x9999999999999999999999999999999999999999"));
    try testing.expect(not_found == null);
}