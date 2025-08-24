//! NEP-17 Contract Implementation
//!
//! Complete conversion from NeoSwift Nep17Contract.swift
//! Provides NEP-17 token contract representation.

const std = @import("std");
const Hash160 = @import("../../types/hash160.zig").Hash160;

/// NEP-17 token contract (converted from Swift Nep17Contract)
pub const Nep17Contract = struct {
    /// Contract script hash
    script_hash: Hash160,
    /// Token symbol
    symbol: []const u8,
    /// Token decimal places
    decimals: u32,
    
    const Self = @This();
    
    /// Creates new NEP-17 contract (equivalent to Swift init)
    pub fn init(script_hash: Hash160, symbol: []const u8, decimals: u32) Self {
        return Self{
            .script_hash = script_hash,
            .symbol = symbol,
            .decimals = decimals,
        };
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return self.script_hash.eql(other.script_hash) and
               std.mem.eql(u8, self.symbol, other.symbol) and
               self.decimals == other.decimals;
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.script_hash.toSlice());
        hasher.update(self.symbol);
        hasher.update(std.mem.asBytes(&self.decimals));
        return hasher.final();
    }
    
    /// Gets the script hash as string
    pub fn getScriptHashString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try self.script_hash.toString(allocator);
    }
    
    /// Checks if contract has valid symbol
    pub fn hasValidSymbol(self: Self) bool {
        return self.symbol.len > 0 and self.symbol.len <= 32;
    }
    
    /// Checks if contract has reasonable decimals
    pub fn hasValidDecimals(self: Self) bool {
        return self.decimals <= 30; // Reasonable upper bound for token decimals
    }
    
    /// Validates contract data
    pub fn validate(self: Self) !void {
        if (!self.hasValidSymbol()) {
            return error.InvalidTokenSymbol;
        }
        
        if (!self.hasValidDecimals()) {
            return error.InvalidTokenDecimals;
        }
        
        try self.script_hash.validate();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const script_hash_string = try self.script_hash.toString(allocator);
        defer allocator.free(script_hash_string);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"scriptHash\":\"{s}\",\"symbol\":\"{s}\",\"decimals\":{}}}",
            .{ script_hash_string, self.symbol, self.decimals }
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const script_hash_str = json_obj.get("scriptHash").?.string;
        const symbol_str = json_obj.get("symbol").?.string;
        const decimals_int = @as(u32, @intCast(json_obj.get("decimals").?.integer));
        
        const script_hash = try Hash160.initWithString(script_hash_str);
        const symbol = try allocator.dupe(u8, symbol_str);
        
        return Self.init(script_hash, symbol, decimals_int);
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.symbol);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const symbol_copy = try allocator.dupe(u8, self.symbol);
        return Self.init(self.script_hash, symbol_copy, self.decimals);
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const script_hash_string = try self.script_hash.toString(allocator);
        defer allocator.free(script_hash_string);
        
        return try std.fmt.allocPrint(
            allocator,
            "NEP-17 Contract: {s} ({s}) - {} decimals",
            .{ self.symbol, script_hash_string, self.decimals }
        );
    }
    
    /// Calculates token amount considering decimals
    pub fn calculateAmount(self: Self, raw_amount: u64) u64 {
        var amount = raw_amount;
        var i: u32 = 0;
        while (i < self.decimals) : (i += 1) {
            amount /= 10;
        }
        return amount;
    }
    
    /// Converts token amount to raw amount (considering decimals)
    pub fn toRawAmount(self: Self, token_amount: u64) u64 {
        var amount = token_amount;
        var i: u32 = 0;
        while (i < self.decimals) : (i += 1) {
            amount *= 10;
        }
        return amount;
    }
};

// Tests (converted from Swift Nep17Contract tests)
test "Nep17Contract creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test contract creation (equivalent to Swift init tests)
    const script_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const symbol = "TEST";
    const decimals = 8;
    
    const contract = Nep17Contract.init(script_hash, symbol, decimals);
    
    try testing.expect(contract.script_hash.eql(script_hash));
    try testing.expectEqualStrings(symbol, contract.symbol);
    try testing.expectEqual(decimals, contract.decimals);
    
    // Test validation
    try contract.validate();
    try testing.expect(contract.hasValidSymbol());
    try testing.expect(contract.hasValidDecimals());
}

test "Nep17Contract equality and hashing" {
    const testing = std.testing;
    
    // Test equality (equivalent to Swift Hashable tests)
    const script_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const contract1 = Nep17Contract.init(script_hash, "TEST", 8);
    const contract2 = Nep17Contract.init(script_hash, "TEST", 8);
    const contract3 = Nep17Contract.init(script_hash, "OTHER", 8);
    
    try testing.expect(contract1.eql(contract2));
    try testing.expect(!contract1.eql(contract3));
    
    // Test hashing
    const hash1 = contract1.hash();
    const hash2 = contract2.hash();
    const hash3 = contract3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same contracts should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different contracts should have different hash
}

test "Nep17Contract validation" {
    const testing = std.testing;
    
    const script_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    // Test valid contract
    const valid_contract = Nep17Contract.init(script_hash, "VALID", 18);
    try valid_contract.validate();
    
    // Test invalid symbol (empty)
    const invalid_symbol = Nep17Contract.init(script_hash, "", 8);
    try testing.expectError(error.InvalidTokenSymbol, invalid_symbol.validate());
    
    // Test invalid decimals (too high)
    const invalid_decimals = Nep17Contract.init(script_hash, "TEST", 50);
    try testing.expectError(error.InvalidTokenDecimals, invalid_decimals.validate());
}

test "Nep17Contract JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const script_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const original_contract = Nep17Contract.init(script_hash, "TEST", 8);
    
    const json_str = try original_contract.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "TEST") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "scriptHash") != null);
    
    var decoded_contract = try Nep17Contract.decodeFromJson(json_str, allocator);
    defer decoded_contract.deinit(allocator);
    
    try testing.expect(original_contract.eql(decoded_contract));
}

test "Nep17Contract amount calculations" {
    const testing = std.testing;
    
    // Test amount calculations with decimals
    const script_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const contract = Nep17Contract.init(script_hash, "TEST", 8);
    
    // Test raw amount to token amount
    const raw_amount: u64 = 100000000; // 1.0 token with 8 decimals
    const token_amount = contract.calculateAmount(raw_amount);
    try testing.expectEqual(@as(u64, 1), token_amount);
    
    // Test token amount to raw amount
    const calculated_raw = contract.toRawAmount(1);
    try testing.expectEqual(raw_amount, calculated_raw);
    
    // Test with different decimals
    const contract_18 = Nep17Contract.init(script_hash, "TEST18", 18);
    const raw_amount_18: u64 = 1000000000000000000; // 1.0 token with 18 decimals
    const token_amount_18 = contract_18.calculateAmount(raw_amount_18);
    try testing.expectEqual(@as(u64, 1), token_amount_18);
}

test "Nep17Contract formatting and utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test formatting
    const script_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const contract = Nep17Contract.init(script_hash, "TEST", 8);
    
    const formatted = try contract.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "TEST") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "NEP-17") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "8 decimals") != null);
    
    // Test script hash string
    const script_hash_string = try contract.getScriptHashString(allocator);
    defer allocator.free(script_hash_string);
    
    try testing.expect(script_hash_string.len > 0);
    try testing.expect(std.mem.startsWith(u8, script_hash_string, "0x"));
    
    // Test cloning
    var cloned_contract = try contract.clone(allocator);
    defer cloned_contract.deinit(allocator);
    
    try testing.expect(contract.eql(cloned_contract));
}