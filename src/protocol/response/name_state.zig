//! NameState Implementation
//!
//! Complete conversion from NeoSwift NameState.swift

const std = @import("std");
const Hash160 = @import("../../types/hash160.zig").Hash160;

pub const NameState = struct {
    name: []const u8,
    expiration: u64,
    admin: ?Hash160,
    
    pub fn init(name: []const u8, expiration: u64, admin: ?Hash160) @This() {
        return .{ .name = name, .expiration = expiration, .admin = admin };
    }
    
    pub fn getName(self: @This()) []const u8 {
        return self.name;
    }
    
    pub fn getExpiration(self: @This()) u64 {
        return self.expiration;
    }
    
    pub fn hasAdmin(self: @This()) bool {
        return self.admin != null;
    }
    
    pub fn isExpired(self: @This(), current_time: u64) bool {
        return current_time > self.expiration;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};