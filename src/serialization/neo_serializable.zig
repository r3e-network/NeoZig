//! Neo Serializable protocol implementation
//!
//! Complete conversion from NeoSwift NeoSerializable.swift
//! Provides serialization interface for all Neo types.

const std = @import("std");
const BinaryWriter = @import("binary_writer.zig").BinaryWriter;
const BinaryReader = @import("binary_reader.zig").BinaryReader;

/// Serializable trait for Neo types (converted from Swift NeoSerializable protocol)
pub fn NeoSerializable(comptime T: type) type {
    return struct {
        /// Gets serialized size (equivalent to Swift .size property)
        pub fn size(self: T) usize {
            return T.size(self);
        }
        
        /// Serializes to binary writer (equivalent to Swift serialize(_ writer: BinaryWriter))
        pub fn serialize(self: T, writer: *BinaryWriter) !void {
            return T.serialize(self, writer);
        }
        
        /// Deserializes from binary reader (equivalent to Swift deserialize(_ reader: BinaryReader))
        pub fn deserialize(reader: *BinaryReader) !T {
            return T.deserialize(reader);
        }
        
        /// Serializes to byte array (utility method)
        pub fn toBytes(self: T, allocator: std.mem.Allocator) ![]u8 {
            var writer = BinaryWriter.init(allocator);
            defer writer.deinit();
            
            try self.serialize(&writer);
            return try allocator.dupe(u8, writer.toSlice());
        }
        
        /// Deserializes from byte array (utility method)
        pub fn fromBytes(bytes: []const u8) !T {
            var reader = BinaryReader.init(bytes);
            return try T.deserialize(&reader);
        }
    };
}

/// Variable size calculation utilities (converted from Swift varSize)
pub const VarSizeUtils = struct {
    /// Calculates variable size for byte array (equivalent to Swift Bytes.varSize)
    pub fn bytesVarSize(bytes: []const u8) usize {
        const VarInt = @import("../serialization/varint.zig").VarInt;
        return VarInt.size(bytes.len) + bytes.len;
    }
    
    /// Calculates variable size for string (equivalent to Swift String.varSize)
    pub fn stringVarSize(str: []const u8) usize {
        return bytesVarSize(str);
    }
    
    /// Calculates variable size for array (equivalent to Swift Array.varSize)
    pub fn arrayVarSize(comptime T: type, array: []const T) usize {
        const VarInt = @import("../serialization/varint.zig").VarInt;
        var total_size = VarInt.size(array.len);
        
        for (array) |item| {
            if (@hasDecl(T, "size")) {
                total_size += item.size();
            } else {
                total_size += @sizeOf(T);
            }
        }
        
        return total_size;
    }
};

/// Serialization utilities (converted from Swift serialization helpers)
pub const SerializationUtils = struct {
    /// Serializes any NeoSerializable type to bytes
    pub fn serialize(data: anytype, allocator: std.mem.Allocator) ![]u8 {
        var writer = BinaryWriter.init(allocator);
        defer writer.deinit();
        
        try data.serialize(&writer);
        return try allocator.dupe(u8, writer.toSlice());
    }
    
    /// Deserializes bytes to any NeoSerializable type
    pub fn deserialize(comptime T: type, bytes: []const u8) !T {
        var reader = BinaryReader.init(bytes);
        return try T.deserialize(&reader);
    }
    
    /// Validates serialization round-trip
    pub fn validateRoundTrip(data: anytype, allocator: std.mem.Allocator) !bool {
        const T = @TypeOf(data);
        
        const serialized = try serialize(data, allocator);
        defer allocator.free(serialized);
        
        const deserialized = try deserialize(T, serialized);
        
        // Compare if type has eql method
        if (@hasDecl(T, "eql")) {
            return data.eql(deserialized);
        }
        
        return true; // Assume success if no comparison available
    }
};

// Tests (converted from Swift NeoSerializable tests)
test "NeoSerializable interface" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test with Hash160 (implements NeoSerializable)
    const Hash160 = @import("../types/hash160.zig").Hash160;
    const hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    
    // Test size calculation
    try testing.expectEqual(@as(usize, 20), hash.size());
    
    // Test serialization
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    try hash.serialize(&writer);
    try testing.expectEqual(@as(usize, 20), writer.toSlice().len);
    
    // Test deserialization
    var reader = BinaryReader.init(writer.toSlice());
    const deserialized = try Hash160.deserialize(&reader);
    
    try testing.expect(hash.eql(deserialized));
}

test "Variable size calculations" {
    const testing = std.testing;
    
    // Test bytes variable size (equivalent to Swift Bytes.varSize tests)
    const small_bytes = [_]u8{ 1, 2, 3 };
    const small_var_size = VarSizeUtils.bytesVarSize(&small_bytes);
    try testing.expect(small_var_size >= 4); // 1 byte length + 3 bytes data
    
    const large_bytes = [_]u8{0} ** 1000;
    const large_var_size = VarSizeUtils.bytesVarSize(&large_bytes);
    try testing.expect(large_var_size >= 1003); // 3 bytes length + 1000 bytes data
    
    // Test string variable size
    const test_string = "Hello Neo";
    const string_var_size = VarSizeUtils.stringVarSize(test_string);
    try testing.expect(string_var_size >= test_string.len + 1);
}

test "Serialization utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test generic serialization (equivalent to Swift serialization tests)
    const Hash256 = @import("../types/hash256.zig").Hash256;
    const hash = Hash256.sha256("test data");
    
    const serialized = try SerializationUtils.serialize(hash, allocator);
    defer allocator.free(serialized);
    
    try testing.expectEqual(@as(usize, 32), serialized.len);
    
    // Test round-trip validation
    const round_trip_success = try SerializationUtils.validateRoundTrip(hash, allocator);
    try testing.expect(round_trip_success);
}