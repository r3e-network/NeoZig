//! Binary reader for Neo deserialization
//!
//! Converted from Swift BinaryReader with full API compatibility.

const std = @import("std");


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

pub const BinaryReader = struct {
    data: []const u8,
    position: usize,
    
    const Self = @This();
    
    pub fn init(data: []const u8) Self {
        return Self{ .data = data, .position = 0 };
    }
    
    pub fn readBytes(self: *Self, buffer: []u8) !void {
        if (self.position + buffer.len > self.data.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }
        @memcpy(buffer, self.data[self.position..self.position + buffer.len]);
        self.position += buffer.len;
    }
    
    pub fn readByte(self: *Self) !u8 {
        if (self.position >= self.data.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }
        const byte = self.data[self.position];
        self.position += 1;
        return byte;
    }
    
    pub fn readU32(self: *Self) !u32 {
        var bytes: [4]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.littleToNative(u32, std.mem.bytesToValue(u32, &bytes));
    }
    
    pub fn readU64(self: *Self) !u64 {
        var bytes: [8]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.littleToNative(u64, std.mem.bytesToValue(u64, &bytes));
    }
    
    pub fn readVarInt(self: *Self) !u64 {
        const first_byte = try self.readByte();
        return switch (first_byte) {
            0x00...0xFB => first_byte,
            0xFD => try self.readU32(),
            0xFE => try self.readU32(),
            0xFF => try self.readU64(),
            else => errors.SerializationError.InvalidFormat,
        };
    }
};