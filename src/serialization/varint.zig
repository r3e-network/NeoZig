//! VarInt utility helpers
//!
//! Provides Zig equivalents of Neo's variable length integer encoding.

const std = @import("std");

pub const VarInt = struct {
    /// Returns the number of bytes required to encode `value` as a VarInt.
    pub fn size(value: usize) usize {
        if (value < 0xFD) return 1;
        if (value <= 0xFFFF) return 3;
        if (value <= 0xFFFF_FFFF) return 5;
        return 9;
    }

    /// Serialises a VarInt to the provided writer.
    pub fn write(writer: anytype, value: u64) !void {
        if (value < 0xFD) {
            try writer.writeByte(@intCast(value));
        } else if (value <= 0xFFFF) {
            try writer.writeByte(0xFD);
            try writer.writeBytes(&std.mem.toBytes(std.mem.nativeToLittle(u16, @intCast(value))));
        } else if (value <= 0xFFFF_FFFF) {
            try writer.writeByte(0xFE);
            try writer.writeBytes(&std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(value))));
        } else {
            try writer.writeByte(0xFF);
            try writer.writeBytes(&std.mem.toBytes(std.mem.nativeToLittle(u64, value)));
        }
    }

    /// Deserialises a VarInt from the provided reader.
    pub fn read(reader: anytype) !u64 {
        const prefix = try reader.readByte();
        return switch (prefix) {
            0xFD => @intCast(try reader.readInt(u16, .little)),
            0xFE => @intCast(try reader.readInt(u32, .little)),
            0xFF => try reader.readInt(u64, .little),
            else => prefix,
        };
    }
};

// Tests
test "varint size calculation" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 1), VarInt.size(0));
    try testing.expectEqual(@as(usize, 3), VarInt.size(0xFD));
    try testing.expectEqual(@as(usize, 5), VarInt.size(0x1_0000));
    try testing.expectEqual(@as(usize, 9), VarInt.size(0x1_0000_0000));
}
