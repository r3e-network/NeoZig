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

    pub fn readBool(self: *Self) !bool {
        const value = try self.readByte();
        return value == 1;
    }

    pub fn readU16(self: *Self) !u16 {
        var bytes: [2]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.littleToNative(u16, std.mem.bytesToValue(u16, &bytes));
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
            0x00...0xFC => first_byte,
            0xFD => try self.readU16(),
            0xFE => try self.readU32(),
            0xFF => try self.readU64(),
        };
    }

    pub fn readVarBytes(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        const length = try self.readVarInt();

        if (length > constants.MAX_TRANSACTION_SIZE) {
            return errors.SerializationError.DataTooLarge;
        }

        const buffer = try allocator.alloc(u8, @intCast(length));
        errdefer allocator.free(buffer);

        try self.readBytes(buffer);
        return buffer;
    }

    pub fn readVarString(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        const length = try self.readVarInt();

        if (length > 1024 * 1024) {
            return errors.SerializationError.DataTooLarge;
        }

        const buffer = try allocator.alloc(u8, @intCast(length));
        errdefer allocator.free(buffer);

        try self.readBytes(buffer);
        return buffer;
    }
};
