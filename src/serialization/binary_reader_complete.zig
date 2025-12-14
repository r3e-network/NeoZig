//! Complete Binary Reader implementation
//!
//! Complete conversion from NeoSwift BinaryReader.swift
//! Provides comprehensive binary deserialization with Swift API compatibility.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

/// Complete binary reader (converted from Swift BinaryReader)
pub const CompleteBinaryReader = struct {
    /// Current reading position
    position: usize,
    /// Input data array
    array: []const u8,
    /// Marker for reset functionality
    marker: i32,

    const Self = @This();

    /// Creates binary reader (equivalent to Swift init(_ input: Bytes))
    pub fn init(input: []const u8) Self {
        return Self{
            .position = 0,
            .array = input,
            .marker = -1,
        };
    }

    /// Gets available bytes (equivalent to Swift .available property)
    pub fn getAvailable(self: Self) usize {
        return self.array.len - self.position;
    }

    /// Sets position marker (equivalent to Swift mark())
    pub fn mark(self: *Self) void {
        self.marker = @intCast(self.position);
    }

    /// Resets to marker (equivalent to Swift reset())
    pub fn reset(self: *Self) !void {
        if (self.marker < 0) {
            return errors.SerializationError.InvalidFormat;
        }

        self.position = @intCast(self.marker);
    }

    /// Reads boolean (equivalent to Swift readBoolean())
    pub fn readBoolean(self: *Self) !bool {
        if (self.position >= self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        const value = self.array[self.position] == 1;
        self.position += 1;
        return value;
    }

    /// Reads single byte (equivalent to Swift readByte())
    pub fn readByte(self: *Self) !u8 {
        if (self.position >= self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        const byte = self.array[self.position];
        self.position += 1;
        return byte;
    }

    /// Reads unsigned byte as integer (equivalent to Swift readUnsignedByte())
    pub fn readUnsignedByte(self: *Self) !u32 {
        const byte = try self.readByte();
        return @intCast(byte);
    }

    /// Reads bytes of specified length (equivalent to Swift readBytes(_ length:))
    pub fn readBytes(self: *Self, length: usize, allocator: std.mem.Allocator) ![]u8 {
        if (self.position + length > self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        const start_pos = self.position;
        self.position += length;

        return try allocator.dupe(u8, self.array[start_pos .. start_pos + length]);
    }

    /// Reads bytes into existing buffer (utility method)
    pub fn readBytesIntoBuffer(self: *Self, buffer: []u8) !void {
        if (self.position + buffer.len > self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        @memcpy(buffer, self.array[self.position .. self.position + buffer.len]);
        self.position += buffer.len;
    }

    /// Reads 16-bit unsigned integer (equivalent to Swift readUInt16())
    pub fn readUInt16(self: *Self) !u16 {
        if (self.position + 2 > self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        const bytes = self.array[self.position .. self.position + 2];
        self.position += 2;

        return std.mem.littleToNative(u16, std.mem.bytesToValue(u16, bytes[0..2]));
    }

    /// Reads 32-bit unsigned integer (equivalent to Swift readUInt32())
    pub fn readUInt32(self: *Self) !u32 {
        if (self.position + 4 > self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        const bytes = self.array[self.position .. self.position + 4];
        self.position += 4;

        return std.mem.littleToNative(u32, std.mem.bytesToValue(u32, bytes[0..4]));
    }

    /// Reads 64-bit unsigned integer (equivalent to Swift readUInt64())
    pub fn readUInt64(self: *Self) !u64 {
        if (self.position + 8 > self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        const bytes = self.array[self.position .. self.position + 8];
        self.position += 8;

        return std.mem.littleToNative(u64, std.mem.bytesToValue(u64, bytes[0..8]));
    }

    /// Reads signed 16-bit integer (equivalent to Swift readInt16())
    pub fn readInt16(self: *Self) !i16 {
        const unsigned = try self.readUInt16();
        return @bitCast(unsigned);
    }

    /// Reads signed 32-bit integer (equivalent to Swift readInt32())
    pub fn readInt32(self: *Self) !i32 {
        const unsigned = try self.readUInt32();
        return @bitCast(unsigned);
    }

    /// Reads signed 64-bit integer (equivalent to Swift readInt64())
    pub fn readInt64(self: *Self) !i64 {
        const unsigned = try self.readUInt64();
        return @bitCast(unsigned);
    }

    /// Reads variable-length integer (equivalent to Swift readVarInt())
    pub fn readVarInt(self: *Self) !u64 {
        const first_byte = try self.readByte();

        return switch (first_byte) {
            0x00...0xFC => first_byte,
            0xFD => try self.readUInt16(),
            0xFE => try self.readUInt32(),
            0xFF => try self.readUInt64(),
        };
    }

    /// Reads variable-length string (equivalent to Swift readVarString())
    pub fn readVarString(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        const length = try self.readVarInt();

        if (length > 1024 * 1024) { // 1MB limit
            return errors.SerializationError.DataTooLarge;
        }

        return try self.readBytes(@intCast(length), allocator);
    }

    /// Reads variable-length byte array (equivalent to Swift readVarBytes())
    pub fn readVarBytes(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        const length = try self.readVarInt();

        if (length > constants.MAX_TRANSACTION_SIZE) {
            return errors.SerializationError.DataTooLarge;
        }

        return try self.readBytes(@intCast(length), allocator);
    }

    /// Reads Hash160 (equivalent to Swift Hash160 reading)
    pub fn readHash160(self: *Self) !Hash160 {
        var hash_bytes: [20]u8 = undefined;
        try self.readBytesIntoBuffer(&hash_bytes);
        std.mem.reverse(u8, &hash_bytes);
        return Hash160.fromArray(hash_bytes);
    }

    /// Reads Hash256 (equivalent to Swift Hash256 reading)
    pub fn readHash256(self: *Self) !Hash256 {
        var hash_bytes: [32]u8 = undefined;
        try self.readBytesIntoBuffer(&hash_bytes);
        std.mem.reverse(u8, &hash_bytes);
        return try Hash256.initWithBytes(&hash_bytes);
    }

    /// Reads big integer (equivalent to Swift readBigInteger())
    pub fn readBigInteger(self: *Self, byte_length: usize, allocator: std.mem.Allocator) !u256 {
        const bytes = try self.readBytes(byte_length, allocator);
        defer allocator.free(bytes);

        return @import("../utils/bytes_extensions.zig").BytesUtils.toBigInt(bytes);
    }

    /// Reads serializable object (equivalent to Swift readSerializable())
    pub fn readSerializable(self: *Self, comptime T: type, allocator: std.mem.Allocator) !T {
        return try T.deserialize(self, allocator);
    }

    /// Skips bytes (equivalent to Swift skip())
    pub fn skip(self: *Self, byte_count: usize) !void {
        if (self.position + byte_count > self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        self.position += byte_count;
    }

    /// Seeks to position (equivalent to Swift seek())
    pub fn seek(self: *Self, new_position: usize) !void {
        if (new_position > self.array.len) {
            return errors.SerializationError.InvalidLength;
        }

        self.position = new_position;
    }

    /// Gets current position (equivalent to Swift .position property)
    pub fn getPosition(self: Self) usize {
        return self.position;
    }

    /// Checks if more data available
    pub fn hasMore(self: Self) bool {
        return self.position < self.array.len;
    }

    /// Gets remaining bytes
    pub fn getRemainingBytes(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try allocator.dupe(u8, self.array[self.position..]);
    }

    /// Peeks at next byte without advancing position
    pub fn peekByte(self: Self) !u8 {
        if (self.position >= self.array.len) {
            return errors.SerializationError.UnexpectedEndOfData;
        }

        return self.array[self.position];
    }

    /// Reads fixed-length string
    pub fn readFixedString(self: *Self, length: usize, allocator: std.mem.Allocator) ![]u8 {
        const bytes = try self.readBytes(length, allocator);

        // Find null terminator if present
        var actual_length = bytes.len;
        for (bytes, 0..) |byte, i| {
            if (byte == 0) {
                actual_length = i;
                break;
            }
        }

        const result = try allocator.alloc(u8, actual_length);
        @memcpy(result, bytes[0..actual_length]);
        allocator.free(bytes);

        return result;
    }
};

// Tests (converted from Swift BinaryReader tests)
test "CompleteBinaryReader basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;

    // Create test data
    const test_data = [_]u8{
        0x01, // boolean (true)
        0x42, // byte
        0x34, 0x12, // uint16 (0x1234 little-endian)
        0x78, 0x56, 0x34, 0x12, // uint32 (0x12345678 little-endian)
        0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, // uint64 (little-endian)
    };

    var reader = CompleteBinaryReader.init(&test_data);

    // Test basic reads (equivalent to Swift BinaryReader tests)
    const bool_val = try reader.readBoolean();
    try testing.expect(bool_val);

    const byte_val = try reader.readByte();
    try testing.expectEqual(@as(u8, 0x42), byte_val);

    const uint16_val = try reader.readUInt16();
    try testing.expectEqual(@as(u16, 0x1234), uint16_val);

    const uint32_val = try reader.readUInt32();
    try testing.expectEqual(@as(u32, 0x12345678), uint32_val);

    const uint64_val = try reader.readUInt64();
    try testing.expectEqual(@as(u64, 0x123456789ABCDEF0), uint64_val);

    // Test position tracking
    try testing.expectEqual(test_data.len, reader.getPosition());
    try testing.expect(!reader.hasMore());
}

test "CompleteBinaryReader variable-length operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create test data with VarInt and VarString
    const test_data = [_]u8{
        0x2A, // VarInt: 42
        0xFD, 0x00, 0x01, // VarInt: 256 (3 bytes)
        0x05, 'H', 'e', 'l', 'l', 'o', // VarString: "Hello"
    };

    var reader = CompleteBinaryReader.init(&test_data);

    // Test VarInt reading (equivalent to Swift readVarInt tests)
    const varint1 = try reader.readVarInt();
    try testing.expectEqual(@as(u64, 42), varint1);

    const varint2 = try reader.readVarInt();
    try testing.expectEqual(@as(u64, 256), varint2);

    // Test VarString reading (equivalent to Swift readVarString tests)
    const var_string = try reader.readVarString(allocator);
    defer allocator.free(var_string);

    try testing.expectEqualStrings("Hello", var_string);
}

test "CompleteBinaryReader hash operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create test data with hashes
    const hash160_be = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13,
    };
    const hash256_be = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };

    var test_data = ArrayList(u8).init(allocator);
    defer test_data.deinit();

    var hash160_le = hash160_be;
    std.mem.reverse(u8, &hash160_le);
    try test_data.appendSlice(&hash160_le);

    var hash256_le = hash256_be;
    std.mem.reverse(u8, &hash256_le);
    try test_data.appendSlice(&hash256_le);

    var reader = CompleteBinaryReader.init(test_data.items);

    // Test hash reading (equivalent to Swift hash reading tests)
    const read_hash160 = try reader.readHash160();
    try testing.expect(std.mem.eql(u8, &hash160_be, &read_hash160.toArray()));

    const read_hash256 = try reader.readHash256();
    try testing.expect(std.mem.eql(u8, &hash256_be, &read_hash256.toArray()));
}

test "CompleteBinaryReader mark and reset" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;

    const test_data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var reader = CompleteBinaryReader.init(&test_data);

    // Test mark and reset functionality (equivalent to Swift mark/reset tests)
    try testing.expectEqual(@as(usize, 0), reader.getPosition());

    reader.mark();

    _ = try reader.readByte();
    _ = try reader.readByte();
    try testing.expectEqual(@as(usize, 2), reader.getPosition());

    try reader.reset();
    try testing.expectEqual(@as(usize, 0), reader.getPosition());

    // Test reset without mark fails
    reader.marker = -1;
    try testing.expectError(errors.SerializationError.InvalidFormat, reader.reset());
}

test "CompleteBinaryReader signed integer operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;

    // Create test data with signed integers
    const test_data = [_]u8{
        0xFF, 0xFF, // int16: -1
        0xFF, 0xFF, 0xFF, 0xFF, // int32: -1
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // int64: -1
    };

    var reader = CompleteBinaryReader.init(&test_data);

    // Test signed integer reading
    const int16_val = try reader.readInt16();
    try testing.expectEqual(@as(i16, -1), int16_val);

    const int32_val = try reader.readInt32();
    try testing.expectEqual(@as(i32, -1), int32_val);

    const int64_val = try reader.readInt64();
    try testing.expectEqual(@as(i64, -1), int64_val);
}

test "CompleteBinaryReader error conditions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test reading beyond buffer (equivalent to Swift error tests)
    const small_data = [_]u8{ 0x01, 0x02 };
    var reader = CompleteBinaryReader.init(&small_data);

    // Should succeed
    _ = try reader.readByte();
    _ = try reader.readByte();

    // Should fail
    try testing.expectError(errors.SerializationError.UnexpectedEndOfData, reader.readByte());
    try testing.expectError(errors.SerializationError.UnexpectedEndOfData, reader.readUInt16());
    try testing.expectError(errors.SerializationError.UnexpectedEndOfData, reader.readBytes(1, allocator));
}

test "CompleteBinaryReader utility operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const test_data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var reader = CompleteBinaryReader.init(&test_data);

    // Test available bytes calculation
    try testing.expectEqual(@as(usize, 5), reader.getAvailable());

    _ = try reader.readByte();
    try testing.expectEqual(@as(usize, 4), reader.getAvailable());

    // Test peek functionality
    const peeked = try reader.peekByte();
    try testing.expectEqual(@as(u8, 0x02), peeked);
    try testing.expectEqual(@as(usize, 1), reader.getPosition()); // Position unchanged

    // Test skip functionality
    try reader.skip(2);
    try testing.expectEqual(@as(usize, 3), reader.getPosition());

    // Test seek functionality
    try reader.seek(1);
    try testing.expectEqual(@as(usize, 1), reader.getPosition());

    // Test remaining bytes
    const remaining = try reader.getRemainingBytes(allocator);
    defer allocator.free(remaining);

    const expected_remaining = [_]u8{ 0x02, 0x03, 0x04, 0x05 };
    try testing.expectEqualSlices(u8, &expected_remaining, remaining);
}
