//! Neo ValidateAddress Implementation
//!
//! Complete conversion from NeoSwift NeoValidateAddress.swift
//! Provides address validation response structure.

const std = @import("std");



/// Address validation result (converted from Swift Result)
pub const ValidateAddressResult = struct {
    /// Address string
    address: []const u8,
    /// Whether address is valid
    is_valid: bool,
    
    const Self = @This();
    
    /// Creates new validation result (equivalent to Swift init)
    pub fn init(address: []const u8, is_valid: bool) Self {
        return Self{
            .address = address,
            .is_valid = is_valid,
        };
    }
    
    /// Gets address
    pub fn getAddress(self: Self) []const u8 {
        return self.address;
    }
    
    /// Checks if address is valid
    pub fn isValid(self: Self) bool {
        return self.is_valid;
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.address, other.address) and
               self.is_valid == other.is_valid;
    }
    
    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.address);
        hasher.update(&[_]u8{if (self.is_valid) 1 else 0});
        return hasher.final();
    }
    
    /// JSON encoding
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "{{\"address\":\"{s}\",\"isvalid\":{}}}",
            .{ self.address, self.is_valid }
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const address_copy = try allocator.dupe(u8, self.address);
        return Self.init(address_copy, self.is_valid);
    }
};

/// ValidateAddress RPC response wrapper (converted from Swift NeoValidateAddress)
pub const NeoValidateAddress = struct {
    /// The validation result
    result: ?ValidateAddressResult,
    
    const Self = @This();
    
    /// Creates new ValidateAddress response
    pub fn init(result: ?ValidateAddressResult) Self {
        return Self{ .result = result };
    }
    
    /// Gets the validation result (equivalent to Swift result property)
    pub fn getResult(self: Self) ?ValidateAddressResult {
        return self.result;
    }
    
    /// Checks if response contains result
    pub fn hasResult(self: Self) bool {
        return self.result != null;
    }
    
    /// Checks if address is valid
    pub fn isAddressValid(self: Self) bool {
        if (self.result) |result| {
            return result.isValid();
        }
        return false;
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.result) |*result| {
            result.deinit(allocator);
        }
    }
};

// Tests (converted from Swift NeoValidateAddress tests)
test "ValidateAddressResult creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test valid address result
    const valid_address = try allocator.dupe(u8, "NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj");
    var valid_result = ValidateAddressResult.init(valid_address, true);
    defer valid_result.deinit(allocator);
    
    try testing.expectEqualStrings("NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj", valid_result.getAddress());
    try testing.expect(valid_result.isValid());
    
    // Test invalid address result
    const invalid_address = try allocator.dupe(u8, "invalid_address");
    var invalid_result = ValidateAddressResult.init(invalid_address, false);
    defer invalid_result.deinit(allocator);
    
    try testing.expectEqualStrings("invalid_address", invalid_result.getAddress());
    try testing.expect(!invalid_result.isValid());
}

test "NeoValidateAddress response wrapper" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test response with valid result
    const address = try allocator.dupe(u8, "NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj");
    const result = ValidateAddressResult.init(address, true);
    
    var response = NeoValidateAddress.init(result);
    defer response.deinit(allocator);
    
    try testing.expect(response.hasResult());
    try testing.expect(response.isAddressValid());
    
    const retrieved_result = response.getResult().?;
    try testing.expect(retrieved_result.isValid());
    
    // Test empty response
    var empty_response = NeoValidateAddress.init(null);
    defer empty_response.deinit(allocator);
    
    try testing.expect(!empty_response.hasResult());
    try testing.expect(!empty_response.isAddressValid());
}