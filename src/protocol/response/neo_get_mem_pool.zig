//! Neo GetMemPool Implementation
//!
//! Complete conversion from NeoSwift NeoGetMemPool.swift

const std = @import("std");


const Hash256 = @import("../../types/hash256.zig").Hash256;

pub const MemPoolDetails = struct {
    height: u32,
    verified: []Hash256,
    unverified: []Hash256,
    
    pub fn init(height: u32, verified: []Hash256, unverified: []Hash256) @This() {
        return .{ .height = height, .verified = verified, .unverified = unverified };
    }
    
    pub fn getHeight(self: @This()) u32 {
        return self.height;
    }
    
    pub fn getVerifiedCount(self: @This()) usize {
        return self.verified.len;
    }
    
    pub fn getUnverifiedCount(self: @This()) usize {
        return self.unverified.len;
    }
    
    pub fn getTotalCount(self: @This()) usize {
        return self.verified.len + self.unverified.len;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.verified);
        allocator.free(self.unverified);
    }
};

pub const NeoGetMemPool = struct {
    result: ?MemPoolDetails,
    
    pub fn init(result: ?MemPoolDetails) @This() {
        return .{ .result = result };
    }
    
    pub fn getMemPool(self: @This()) ?MemPoolDetails {
        return self.result;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        if (self.result) |*details| {
            details.deinit(allocator);
        }
    }
};