//! Complete Binary Writer implementation
//!
//! Neo N3
//! Provides comprehensive binary serialization.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ECPoint = @import("../crypto/ec_point.zig").ECPoint;
const BytesUtils = @import("../utils/bytes_extensions.zig").BytesUtils;

/// Complete binary writer
pub const CompleteBinaryWriter = struct {
    /// Internal byte array
    array: ArrayList(u8),

    const Self = @This();

    /// Creates binary writer
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .array = ArrayList(u8).init(allocator),
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.array.deinit();
    }

    /// Gets size
    pub fn getSize(self: Self) usize {
        return self.array.items.len;
    }

    /// Writes byte buffer
    pub fn write(self: *Self, buffer: []const u8) !void {
        try self.array.appendSlice(buffer);
    }

    /// Convenience alias to match the simplified writer API and some tests.
    pub fn writeBytes(self: *Self, bytes: []const u8) !void {
        try self.write(bytes);
    }

    /// Writes boolean
    pub fn writeBoolean(self: *Self, value: bool) !void {
        try self.writeByte(if (value) 1 else 0);
    }

    /// Writes single byte
    pub fn writeByte(self: *Self, value: u8) !void {
        try self.array.append(value);
    }

    /// Writes double
    pub fn writeDouble(self: *Self, value: f64) !void {
        const bits: u64 = @bitCast(value);
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, bits));
        try self.write(&bytes);
    }

    /// Writes EC point
    pub fn writeECPoint(self: *Self, point: ECPoint, allocator: std.mem.Allocator) !void {
        const encoded = try point.getEncoded(true, allocator);
        defer allocator.free(encoded);

        try self.write(encoded);
    }

    /// Writes fixed-length string
    pub fn writeFixedString(self: *Self, string_value: ?[]const u8, length: usize, allocator: std.mem.Allocator) !void {
        const bytes = if (string_value) |str| str else &[_]u8{};

        if (bytes.len > length) {
            return errors.throwIllegalArgument("String too long for fixed length");
        }

        // Pad with trailing zeros
        const padded = try BytesUtils.toPadded(bytes, length, true, allocator);
        defer allocator.free(padded);

        try self.write(padded);
    }

    /// Writes float
    pub fn writeFloat(self: *Self, value: f32) !void {
        const bits: u32 = @bitCast(value);
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, bits));
        try self.write(&bytes);
    }

    /// Writes 32-bit signed integer
    pub fn writeInt32(self: *Self, value: i32) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(i32, value));
        try self.write(&bytes);
    }

    /// Writes 64-bit signed integer
    pub fn writeInt64(self: *Self, value: i64) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(i64, value));
        try self.write(&bytes);
    }

    /// Writes 16-bit unsigned integer
    pub fn writeUInt16(self: *Self, value: u16) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u16, value));
        try self.write(&bytes);
    }

    /// Writes 32-bit unsigned integer
    pub fn writeUInt32(self: *Self, value: u32) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, value));
        try self.write(&bytes);
    }

    /// Writes 64-bit unsigned integer
    pub fn writeUInt64(self: *Self, value: u64) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, value));
        try self.write(&bytes);
    }

    /// Writes variable-length integer
    pub fn writeVarInt(self: *Self, value: u64) !void {
        if (value < 0xFD) {
            try self.writeByte(@intCast(value));
        } else if (value <= 0xFFFF) {
            try self.writeByte(0xFD);
            try self.writeUInt16(@intCast(value));
        } else if (value <= 0xFFFFFFFF) {
            try self.writeByte(0xFE);
            try self.writeUInt32(@intCast(value));
        } else {
            try self.writeByte(0xFF);
            try self.writeUInt64(value);
        }
    }

    /// Writes variable-length string
    pub fn writeVarString(self: *Self, string_value: []const u8) !void {
        try self.writeVarInt(string_value.len);
        try self.write(string_value);
    }

    /// Writes variable-length byte array
    pub fn writeVarBytes(self: *Self, bytes: []const u8) !void {
        try self.writeVarInt(bytes.len);
        try self.write(bytes);
    }

    /// Writes Hash160
    pub fn writeHash160(self: *Self, hash: Hash160) !void {
        const little_endian = hash.toLittleEndianArray();
        try self.write(&little_endian);
    }

    /// Writes Hash256
    pub fn writeHash256(self: *Self, hash: Hash256) !void {
        const little_endian = hash.toLittleEndianArray();
        try self.write(&little_endian);
    }

    /// Writes big integer
    pub fn writeBigInteger(self: *Self, value: u256, byte_length: usize, allocator: std.mem.Allocator) !void {
        const bytes = try BytesUtils.fromBigInt(value, allocator);
        defer allocator.free(bytes);

        // Pad to specified length
        const padded = try BytesUtils.toPadded(bytes, byte_length, false, allocator);
        defer allocator.free(padded);

        try self.write(padded);
    }

    /// Writes serializable object
    pub fn writeSerializable(self: *Self, object: anytype) !void {
        try object.serialize(self);
    }

    /// Writes serializable array
    pub fn writeSerializableArray(self: *Self, objects: anytype) !void {
        for (objects) |object| {
            try object.serialize(self);
        }
    }

    /// Writes variable-length serializable array
    pub fn writeSerializableVarArray(self: *Self, objects: anytype) !void {
        try self.writeVarInt(objects.len);
        for (objects) |object| {
            try object.serialize(self);
        }
    }

    /// Gets written data
    pub fn toArray(self: Self) []const u8 {
        return self.array.items;
    }

    /// Clears writer
    pub fn clear(self: *Self) void {
        self.array.clearRetainingCapacity();
    }

    /// Alias used by some converted test suites.
    pub fn reset(self: *Self) void {
        self.clear();
    }

    /// Gets capacity
    pub fn getCapacity(self: Self) usize {
        return self.array.capacity;
    }

    /// Reserves capacity
    pub fn reserve(self: *Self, additional_capacity: usize) !void {
        try self.array.ensureTotalCapacity(self.array.items.len + additional_capacity);
    }

    /// Converts to owned slice
    pub fn toOwnedSlice(self: *Self) ![]u8 {
        return try self.array.toOwnedSlice();
    }
};

// Tests
test "CompleteBinaryWriter basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test basic writes
    try writer.writeBoolean(true);
    try writer.writeByte(0x42);
    try writer.writeUInt16(0x1234);
    try writer.writeUInt32(0x12345678);
    try writer.writeUInt64(0x123456789ABCDEF0);

    const written_data = writer.toArray();
    try testing.expect(written_data.len > 0);

    // Verify byte order (little-endian for integers)
    try testing.expectEqual(@as(u8, 1), written_data[0]); // Boolean true
    try testing.expectEqual(@as(u8, 0x42), written_data[1]); // Byte
    try testing.expectEqual(@as(u8, 0x34), written_data[2]); // UInt16 low byte
    try testing.expectEqual(@as(u8, 0x12), written_data[3]); // UInt16 high byte

    // Test size property
    try testing.expectEqual(written_data.len, writer.getSize());
}

test "CompleteBinaryWriter variable-length operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test VarInt writing
    try writer.writeVarInt(42); // 1 byte
    try writer.writeVarInt(0x1234); // 3 bytes (0xFD + 2 bytes)
    try writer.writeVarInt(0x12345678); // 5 bytes (0xFE + 4 bytes)

    // Test VarString writing
    try writer.writeVarString("Hello Neo");

    // Test VarBytes writing
    const test_bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    try writer.writeVarBytes(&test_bytes);

    const written_data = writer.toArray();
    try testing.expect(written_data.len > 0);

    // Test that string and bytes are included
    try testing.expect(std.mem.indexOf(u8, written_data, "Hello Neo") != null);
}

test "CompleteBinaryWriter hash operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test hash writing
    const test_hash160 = try Hash160.initWithString("000102030405060708090a0b0c0d0e0f10111213");
    const test_hash256 = try Hash256.initWithString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    try writer.writeHash160(test_hash160);
    try writer.writeHash256(test_hash256);

    const written_data = writer.toArray();
    try testing.expectEqual(@as(usize, 20 + 32), written_data.len);

    // Verify hashes written correctly
    const le160 = test_hash160.toLittleEndianArray();
    const le256 = test_hash256.toLittleEndianArray();

    try testing.expectEqualSlices(u8, &le160, written_data[0..20]);
    try testing.expectEqualSlices(u8, &le256, written_data[20..52]);
}

test "CompleteBinaryWriter signed integer operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test signed integer writing
    try writer.writeInt32(-1);
    try writer.writeInt64(-1);

    const written_data = writer.toArray();
    try testing.expectEqual(@as(usize, 12), written_data.len); // 4 + 8 bytes

    // Verify encoding for signed integers (byte order matches unsigned writers)
    const expected_int32 = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    const expected_int64 = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    try testing.expectEqualSlices(u8, &expected_int32, written_data[0..4]);
    try testing.expectEqualSlices(u8, &expected_int64, written_data[4..12]);
}

test "CompleteBinaryWriter floating point operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test floating point writing
    try writer.writeFloat(1.5);
    try writer.writeDouble(3.14159);

    const written_data = writer.toArray();
    try testing.expectEqual(@as(usize, 12), written_data.len); // 4 + 8 bytes

    // Verify data was written (exact values depend on IEEE 754 representation)
    try testing.expect(written_data.len == 12);
}

test "CompleteBinaryWriter string operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test fixed string writing
    try writer.writeFixedString("Test", 10, allocator);

    const written_data = writer.toArray();
    try testing.expectEqual(@as(usize, 10), written_data.len);

    // Verify string is padded with trailing zeros
    try testing.expectEqual(@as(u8, 'T'), written_data[0]);
    try testing.expectEqual(@as(u8, 'e'), written_data[1]);
    try testing.expectEqual(@as(u8, 's'), written_data[2]);
    try testing.expectEqual(@as(u8, 't'), written_data[3]);
    try testing.expectEqual(@as(u8, 0), written_data[4]); // Trailing zero
    try testing.expectEqual(@as(u8, 0), written_data[9]); // Last trailing zero

    // Test string too long error
    writer.clear();
    try testing.expectError(errors.NeoError.IllegalArgument, writer.writeFixedString("TooLongString", 5, allocator));
}

test "CompleteBinaryWriter big integer operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test big integer writing
    const test_value: u256 = 0x123456789ABCDEF0;
    try writer.writeBigInteger(test_value, 32, allocator);

    const written_data = writer.toArray();
    try testing.expectEqual(@as(usize, 32), written_data.len);

    // Verify big integer was written correctly (would need to verify exact bytes)
    try testing.expect(written_data.len == 32);
}

test "CompleteBinaryWriter utility operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test capacity management
    try writer.reserve(1000);
    try testing.expect(writer.getCapacity() >= 1000);

    // Test writing and clearing
    try writer.writeByte(0x42);
    try testing.expectEqual(@as(usize, 1), writer.getSize());

    writer.clear();
    try testing.expectEqual(@as(usize, 0), writer.getSize());

    // Test multiple writes
    try writer.writeVarString("Test1");
    try writer.writeVarString("Test2");
    try writer.writeVarString("Test3");

    const written_data = writer.toArray();
    try testing.expect(written_data.len > 0);

    // Test owned slice conversion
    var writer2 = CompleteBinaryWriter.init(allocator);
    defer writer2.deinit();

    try writer2.writeByte(0xFF);
    const owned_slice = try writer2.toOwnedSlice();
    defer allocator.free(owned_slice);

    try testing.expectEqual(@as(usize, 1), owned_slice.len);
    try testing.expectEqual(@as(u8, 0xFF), owned_slice[0]);
}

test "CompleteBinaryWriter error conditions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    // Test various error conditions

    // Test fixed string too long
    try testing.expectError(errors.NeoError.IllegalArgument, writer.writeFixedString("VeryLongStringThatExceedsLength", 5, allocator));

    // Test null string with fixed length (should work)
    writer.clear();
    try writer.writeFixedString(null, 5, allocator);

    const written_data = writer.toArray();
    try testing.expectEqual(@as(usize, 5), written_data.len);

    // All bytes should be zero
    for (written_data) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}
