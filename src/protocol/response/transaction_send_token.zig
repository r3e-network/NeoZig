//! TransactionSendToken Implementation
//!
//! Complete conversion from NeoSwift TransactionSendToken.swift

const std = @import("std");
const Hash160 = @import("../../types/hash160.zig").Hash160;

pub const TransactionSendToken = struct {
    token: Hash160,
    to: Hash160,
    amount: []const u8,
    
    pub fn init(token: Hash160, to: Hash160, amount: []const u8) @This() {
        return .{ .token = token, .to = to, .amount = amount };
    }
    
    pub fn getToken(self: @This()) Hash160 {
        return self.token;
    }
    
    pub fn getTo(self: @This()) Hash160 {
        return self.to;
    }
    
    pub fn getAmount(self: @This()) []const u8 {
        return self.amount;
    }
    
    pub fn getAmountAsInt(self: @This()) !u64 {
        return try std.fmt.parseInt(u64, self.amount, 10);
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.amount);
    }
};