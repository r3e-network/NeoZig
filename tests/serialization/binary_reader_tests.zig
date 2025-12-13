//! Binary Reader Tests
//!
//! Complete conversion from NeoSwift BinaryReaderTests.swift
//! Tests binary deserialization functionality and data type reading.

const std = @import("std");

const testing = std.testing;
const neo = @import("neo-zig");
const BinaryReader = neo.serialization.CompleteBinaryReader;
const BinaryWriter = neo.serialization.CompleteBinaryWriter;

test "Read UInt32 values" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    try writer.writeUInt32(0xFFFFFFFF);
    try writer.writeUInt32(0);
    try writer.writeUInt32(12345);
    
    const data = writer.toArray();
    var reader = BinaryReader.init(data);
    
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), try reader.readUInt32());
    try testing.expectEqual(@as(u32, 0), try reader.readUInt32());
    try testing.expectEqual(@as(u32, 12345), try reader.readUInt32());
}

test "Read Int64 values" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    try writer.writeInt64(std.math.maxInt(i64));
    try writer.writeInt64(std.math.minInt(i64));
    try writer.writeInt64(0);
    try writer.writeInt64(1234567890);
    
    const data = writer.toArray();
    var reader = BinaryReader.init(data);
    
    try testing.expectEqual(std.math.maxInt(i64), try reader.readInt64());
    try testing.expectEqual(std.math.minInt(i64), try reader.readInt64());
    try testing.expectEqual(@as(i64, 0), try reader.readInt64());
    try testing.expectEqual(@as(i64, 1234567890), try reader.readInt64());
}

test "Read byte arrays" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    const test_data = [_]u8{ 1, 2, 3, 4, 5 };
    try writer.writeBytes(&test_data);
    
    const written_data = writer.toArray();
    var reader = BinaryReader.init(written_data);
    
    const read_data = try reader.readBytes(test_data.len, allocator);
    defer allocator.free(read_data);
    
    try testing.expectEqualSlices(u8, &test_data, read_data);
}

test "Read variable-length data" {
    const allocator = testing.allocator;
    
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    const test_data = [_]u8{ 0xAB, 0xCD, 0xEF };
    try writer.writeVarBytes(&test_data);
    
    const written_data = writer.toArray();
    var reader = BinaryReader.init(written_data);
    
    const read_data = try reader.readVarBytes(allocator);
    defer allocator.free(read_data);
    
    try testing.expectEqualSlices(u8, &test_data, read_data);
}
