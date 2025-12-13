//! Binary writer for Neo serialization
//!
//! Converted from Swift BinaryWriter with full API compatibility.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");

pub const BinaryWriter = struct {
    buffer: ArrayList(u8),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{ .buffer = ArrayList(u8).init(allocator) };
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

    pub fn writeBool(self: *Self, value: bool) !void {
        try self.writeByte(if (value) 1 else 0);
    }
    
    pub fn writeU16(self: *Self, value: u16) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u16, value));
        try self.writeBytes(&bytes);
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
        if (value < 0xFD) {
            try self.writeByte(@intCast(value));
        } else if (value <= 0xFFFF) {
            try self.writeByte(0xFD);
            try self.writeU16(@intCast(value));
        } else if (value <= 0xFFFFFFFF) {
            try self.writeByte(0xFE);
            try self.writeU32(@intCast(value));
        } else {
            try self.writeByte(0xFF);
            try self.writeU64(value);
        }
    }

    pub fn writeVarBytes(self: *Self, bytes: []const u8) !void {
        try self.writeVarInt(@intCast(bytes.len));
        try self.writeBytes(bytes);
    }

    pub fn writeVarString(self: *Self, value: []const u8) !void {
        try self.writeVarBytes(value);
    }

    /// Convenience wrapper around the value's `serialize` method.
    /// This keeps the writer API ergonomic without creating import cycles.
    pub fn writeSerializable(self: *Self, value: anytype) !void {
        try value.serialize(self);
    }

    pub fn writeHash160(self: *Self, value: anytype) !void {
        try self.writeSerializable(value);
    }

    pub fn writeHash256(self: *Self, value: anytype) !void {
        try self.writeSerializable(value);
    }
    
    pub fn toSlice(self: *Self) []const u8 {
        return self.buffer.items;
    }

    pub fn getAllocator(self: Self) std.mem.Allocator {
        return self.buffer.allocator;
    }

    pub fn clear(self: *Self) void {
        self.buffer.clearRetainingCapacity();
    }

    pub fn reset(self: *Self) void {
        self.clear();
    }
};
