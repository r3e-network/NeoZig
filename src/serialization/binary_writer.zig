//! Binary writer for Neo serialization
//!
//! Converted from Swift BinaryWriter with full API compatibility.

const std = @import("std");
const constants = @import("../core/constants.zig");

pub const BinaryWriter = struct {
    buffer: std.ArrayList(u8),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{ .buffer = std.ArrayList(u8).init(allocator) };
    }
    
    pub fn deinit(self: *Self) void {
        self.buffer.deinit();
    }
    
    pub fn writeBytes(self: *Self, bytes: []const u8) !void {
        try self.buffer.appendSlice(bytes);
    }
    
    pub fn writeByte(self: *Self, byte: u8) !void {
        try self.buffer.append(byte);
    }
    
    pub fn writeU32(self: *Self, value: u32) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, value));
        try self.writeBytes(&bytes);
    }
    
    pub fn writeU64(self: *Self, value: u64) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, value));
        try self.writeBytes(&bytes);
    }
    
    pub fn writeVarInt(self: *Self, value: u64) !void {
        if (value < 0xFC) {
            try self.writeByte(@intCast(value));
        } else if (value <= 0xFFFF) {
            try self.writeByte(0xFD);
            try self.writeU32(@intCast(value));
        } else if (value <= 0xFFFFFFFF) {
            try self.writeByte(0xFE);
            try self.writeU32(@intCast(value));
        } else {
            try self.writeByte(0xFF);
            try self.writeU64(value);
        }
    }
    
    pub fn toSlice(self: *Self) []const u8 {
        return self.buffer.items;
    }
};