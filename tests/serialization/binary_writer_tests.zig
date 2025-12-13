//! Binary Writer Tests
//!
//! Complete conversion from NeoSwift BinaryWriterTests.swift
//! Tests binary serialization functionality and data type writing.

const std = @import("std");

const testing = std.testing;
const neo = @import("neo-zig");
const BinaryWriter = neo.serialization.CompleteBinaryWriter;

/// Helper function to test and reset writer (equivalent to Swift testAndReset)
fn testAndReset(writer: *BinaryWriter, expected: []const u8) !void {
    const written_data = writer.toArray();
    try testing.expectEqualSlices(u8, expected, written_data);
    writer.reset();
}

// Test writing UInt32 values (converted from Swift testWriteUInt32)
test "Write UInt32 values" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Test maximum UInt32 value (equivalent to Swift 2.toPowerOf(32) - 1)
    const max_uint32: u32 = std.math.maxInt(u32); // 0xFFFFFFFF
    try writer.writeUInt32(max_uint32);
    try testAndReset(&writer, &[_]u8{ 0xff, 0xff, 0xff, 0xff });
    
    // Test zero value
    try writer.writeUInt32(0);
    try testAndReset(&writer, &[_]u8{ 0, 0, 0, 0 });
    
    // Test specific value (little-endian)
    try writer.writeUInt32(12345);
    try testAndReset(&writer, &[_]u8{ 0x39, 0x30, 0, 0 });
}

// Test writing Int64 values (converted from Swift testWriteInt64)
test "Write Int64 values" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Test maximum Int64 value
    try writer.writeInt64(std.math.maxInt(i64));
    try testAndReset(&writer, &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f });
    
    // Test minimum Int64 value  
    try writer.writeInt64(std.math.minInt(i64));
    try testAndReset(&writer, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 });
    
    // Test zero value
    try writer.writeInt64(0);
    try testAndReset(&writer, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 });
    
    // Test specific value (little-endian)
    try writer.writeInt64(1234567890);
    try testAndReset(&writer, &[_]u8{ 0xd2, 0x02, 0x96, 0x49, 0x00, 0x00, 0x00, 0x00 });
}

// Test writing UInt16 values (converted from Swift testWriteUInt16)
test "Write UInt16 values" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Test maximum UInt16 value
    const max_uint16: u16 = std.math.maxInt(u16); // 0xFFFF
    try writer.writeUInt16(max_uint16);
    try testAndReset(&writer, &[_]u8{ 0xff, 0xff });
    
    // Test zero value
    try writer.writeUInt16(0);
    try testAndReset(&writer, &[_]u8{ 0, 0 });
    
    // Test specific value
    try writer.writeUInt16(12345);
    try testAndReset(&writer, &[_]u8{ 0x39, 0x30 }); // Little-endian
}

// Test writing byte values
test "Write byte values" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Test various byte values
    const byte_test_cases = [_]u8{ 0, 1, 255, 42, 128 };
    
    for (byte_test_cases) |test_byte| {
        try writer.writeByte(test_byte);
        try testAndReset(&writer, &[_]u8{test_byte});
    }
}

// Test writing byte arrays
test "Write byte arrays" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Test various byte arrays
    const test_arrays = [_][]const u8{
        &[_]u8{},                    // Empty array
        &[_]u8{0x42},               // Single byte
        &[_]u8{ 1, 2, 3, 4, 5 },    // Small array
        &[_]u8{ 0xff, 0xfe, 0xfd }, // Large byte values
    };
    
    for (test_arrays) |test_array| {
        try writer.writeBytes(test_array);
        try testAndReset(&writer, test_array);
    }
}

// Test writing variable-length data
test "Write variable-length data" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Test VarBytes (length-prefixed byte arrays)
    const test_data = [_]u8{ 0x01, 0x02, 0x03 };
    
    try writer.writeVarBytes(&test_data);
    
    const written_data = writer.toArray();
    try testing.expect(written_data.len > test_data.len); // Should include length prefix
    try testing.expectEqual(@as(u8, test_data.len), written_data[0]); // First byte should be length
    try testing.expectEqualSlices(u8, &test_data, written_data[1..]); // Rest should be data
}

test "Write VarInt boundary values" {
    const allocator = testing.allocator;

    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();

    // 252 (0xFC) is still encoded in a single byte.
    try writer.writeVarInt(252);
    try testAndReset(&writer, &[_]u8{0xFC});

    // 253 (0xFD) switches to the 0xFD marker + little-endian UInt16.
    try writer.writeVarInt(253);
    try testAndReset(&writer, &[_]u8{ 0xFD, 0xFD, 0x00 });

    // 65535 (0xFFFF) still uses the 0xFD marker.
    try writer.writeVarInt(65535);
    try testAndReset(&writer, &[_]u8{ 0xFD, 0xFF, 0xFF });

    // 65536 (0x0001_0000) switches to 0xFE + little-endian UInt32.
    try writer.writeVarInt(65536);
    try testAndReset(&writer, &[_]u8{ 0xFE, 0x00, 0x00, 0x01, 0x00 });
}

// Test writer position and size
test "Writer position and size tracking" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Initially empty
    try testing.expectEqual(@as(usize, 0), writer.getSize());
    
    // Write some data
    try writer.writeUInt32(12345);
    try testing.expectEqual(@as(usize, 4), writer.getSize());
    
    try writer.writeUInt16(6789);
    try testing.expectEqual(@as(usize, 6), writer.getSize());
    
    try writer.writeByte(42);
    try testing.expectEqual(@as(usize, 7), writer.getSize());
    
    // Verify total content
    const total_data = writer.toArray();
    try testing.expectEqual(@as(usize, 7), total_data.len);
}

// Test writer reset functionality
test "Writer reset functionality" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Write some data
    try writer.writeUInt32(12345);
    try writer.writeBytes(&[_]u8{ 1, 2, 3 });
    
    try testing.expect(writer.getSize() > 0);
    
    // Reset writer
    writer.reset();
    
    // Should be empty after reset
    try testing.expectEqual(@as(usize, 0), writer.getSize());
    
    const empty_data = writer.toArray();
    try testing.expectEqual(@as(usize, 0), empty_data.len);
    
    // Should be usable after reset
    try writer.writeByte(99);
    try testing.expectEqual(@as(usize, 1), writer.getSize());
}
