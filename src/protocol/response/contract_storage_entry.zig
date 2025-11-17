//! Contract StorageEntry Implementation
//!
//! Complete conversion from NeoSwift ContractStorageEntry.swift

const std = @import("std");



pub const ContractStorageEntry = struct {
    key: []const u8,
    value: []const u8,
    
    pub fn init(key: []const u8, value: []const u8) @This() {
        return .{ .key = key, .value = value };
    }
    
    pub fn getKey(self: @This()) []const u8 {
        return self.key;
    }
    
    pub fn getValue(self: @This()) []const u8 {
        return self.value;
    }
    
    pub fn isEmpty(self: @This()) bool {
        return self.value.len == 0;
    }
    
    pub fn eql(self: @This(), other: @This()) bool {
        return std.mem.eql(u8, self.key, other.key) and 
               std.mem.eql(u8, self.value, other.value);
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

test "ContractStorageEntry operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const key = try allocator.dupe(u8, "test_key");
    const value = try allocator.dupe(u8, "test_value");
    
    var entry = ContractStorageEntry.init(key, value);
    defer entry.deinit(allocator);
    
    try testing.expectEqualStrings("test_key", entry.getKey());
    try testing.expectEqualStrings("test_value", entry.getValue());
    try testing.expect(!entry.isEmpty());
}