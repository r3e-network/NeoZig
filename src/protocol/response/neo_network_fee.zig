//! Neo NetworkFee Implementation
//!
//! Complete conversion from NeoSwift NeoNetworkFee.swift
//! Provides network fee calculation response.

const std = @import("std");

/// Network fee response (converted from Swift NeoNetworkFee)
pub const NeoNetworkFee = struct {
    /// Network fee amount
    network_fee: []const u8,
    
    const Self = @This();
    
    /// Creates new NeoNetworkFee (equivalent to Swift init)
    pub fn init(network_fee: []const u8) Self {
        return Self{ .network_fee = network_fee };
    }
    
    /// Gets network fee as string
    pub fn getNetworkFee(self: Self) []const u8 {
        return self.network_fee;
    }
    
    /// Gets network fee as integer
    pub fn getNetworkFeeAsInt(self: Self) !u64 {
        return try std.fmt.parseInt(u64, self.network_fee, 10);
    }
    
    /// Checks if fee is zero
    pub fn isZero(self: Self) bool {
        return std.mem.eql(u8, self.network_fee, "0");
    }
    
    /// JSON encoding
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "{{\"networkfee\":\"{s}\"}}",
            .{self.network_fee}
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.network_fee);
    }
};

// Tests
test "NeoNetworkFee creation and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const fee_str = try allocator.dupe(u8, "1000000");
    var network_fee = NeoNetworkFee.init(fee_str);
    defer network_fee.deinit(allocator);
    
    try testing.expectEqualStrings("1000000", network_fee.getNetworkFee());
    try testing.expectEqual(@as(u64, 1000000), try network_fee.getNetworkFeeAsInt());
    try testing.expect(!network_fee.isZero());
}