//! Neo Address Implementation
//!
//! Complete conversion from NeoSwift NeoAddress.swift
//! Provides Neo address structure for RPC responses.

const std = @import("std");



/// Neo address structure (converted from Swift NeoAddress)
pub const NeoAddress = struct {
    /// Address string
    address: []const u8,
    /// Whether address has private key
    has_key: bool,
    /// Address label
    label: ?[]const u8,
    /// Whether address is watch-only
    watch_only: bool,
    
    const Self = @This();
    
    /// Creates new NeoAddress (equivalent to Swift init)
    pub fn init(address: []const u8, has_key: bool, label: ?[]const u8, watch_only: bool) Self {
        return Self{
            .address = address,
            .has_key = has_key,
            .label = label,
            .watch_only = watch_only,
        };
    }
    
    /// Gets address string
    pub fn getAddress(self: Self) []const u8 {
        return self.address;
    }
    
    /// Checks if address has private key
    pub fn hasKey(self: Self) bool {
        return self.has_key;
    }
    
    /// Gets label or default
    pub fn getLabelOrDefault(self: Self) []const u8 {
        return self.label orelse self.address;
    }
    
    /// Checks if address is watch-only
    pub fn isWatchOnly(self: Self) bool {
        return self.watch_only;
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.address, other.address) and
               self.has_key == other.has_key and
               self.watch_only == other.watch_only;
    }
    
    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.address);
        hasher.update(&[_]u8{if (self.has_key) 1 else 0});
        hasher.update(&[_]u8{if (self.watch_only) 1 else 0});
        return hasher.final();
    }
    
    /// JSON encoding
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const label_str = if (self.label) |label|
            try std.fmt.allocPrint(allocator, "\"{s}\"", .{label})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(label_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"address\":\"{s}\",\"haskey\":{},\"label\":{s},\"watchonly\":{}}}",
            .{ self.address, self.has_key, label_str, self.watch_only }
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        if (self.label) |label| {
            allocator.free(label);
        }
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const address_copy = try allocator.dupe(u8, self.address);
        const label_copy = if (self.label) |label|
            try allocator.dupe(u8, label)
        else
            null;
        
        return Self.init(address_copy, self.has_key, label_copy, self.watch_only);
    }
};

// Tests (converted from Swift NeoAddress tests)
test "NeoAddress creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test address creation
    const address_str = try allocator.dupe(u8, "NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj");
    const label_str = try allocator.dupe(u8, "Main Account");
    
    var address = NeoAddress.init(address_str, true, label_str, false);
    defer address.deinit(allocator);
    
    try testing.expectEqualStrings("NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj", address.getAddress());
    try testing.expect(address.hasKey());
    try testing.expect(!address.isWatchOnly());
    try testing.expectEqualStrings("Main Account", address.getLabelOrDefault());
}