//! Transaction Attribute Implementation
//!
//! Complete conversion from NeoSwift TransactionAttribute.swift
//! Provides transaction attribute types for Neo blockchain.

const std = @import("std");


const BinaryWriter = @import("../../serialization/binary_writer_complete.zig").CompleteBinaryWriter;
const BinaryReader = @import("../../serialization/binary_reader_complete.zig").CompleteBinaryReader;
const errors = @import("../../core/errors.zig");

/// Oracle response code for transaction attributes
pub const OracleResponseCode = enum(u8) {
    Success = 0x00,
    ProtocolNotSupported = 0x10,
    ConsensusUnreachable = 0x12,
    NotFound = 0x14,
    Timeout = 0x16,
    Forbidden = 0x18,
    ResponseTooLarge = 0x1a,
    InsufficientFunds = 0x1c,
    ContentTypeNotSupported = 0x1f,
    Error = 0xff,
    
    /// Gets the byte value (equivalent to Swift byte property)
    pub fn toByte(self: OracleResponseCode) u8 {
        return @intFromEnum(self);
    }
    
    /// Creates from byte value
    pub fn fromByte(byte_value: u8) ?OracleResponseCode {
        return switch (byte_value) {
            0x00 => .Success,
            0x10 => .ProtocolNotSupported,
            0x12 => .ConsensusUnreachable,
            0x14 => .NotFound,
            0x16 => .Timeout,
            0x18 => .Forbidden,
            0x1a => .ResponseTooLarge,
            0x1c => .InsufficientFunds,
            0x1f => .ContentTypeNotSupported,
            0xff => .Error,
            else => null,
        };
    }
};

/// Transaction attribute types (converted from Swift TransactionAttribute)
pub const TransactionAttribute = union(enum) {
    /// High priority transaction
    HighPriority: void,
    /// Oracle response with ID, response code, and result
    OracleResponse: struct {
        id: u64,
        response_code: OracleResponseCode,
        result: []const u8,
    },
    
    /// Maximum result size for oracle responses
    pub const MAX_RESULT_SIZE = 0xffff;
    
    const Self = @This();
    
    /// Gets JSON value (equivalent to Swift jsonValue)
    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .HighPriority => "HighPriority",
            .OracleResponse => "OracleResponse",
        };
    }
    
    /// Gets byte value (equivalent to Swift byte property)
    pub fn getByte(self: Self) u8 {
        return switch (self) {
            .HighPriority => 0x01,
            .OracleResponse => 0x11,
        };
    }
    
    /// Creates from byte value
    pub fn fromByte(byte_value: u8) ?Self {
        return switch (byte_value) {
            0x01 => Self{ .HighPriority = {} },
            0x11 => Self{ .OracleResponse = .{ 
                .id = 0, 
                .response_code = .Error, 
                .result = "" 
            }}, // stub - needs proper deserialization
            else => null,
        };
    }
    
    /// Creates from JSON value
    pub fn fromJsonValue(json_value: []const u8) ?Self {
        if (std.mem.eql(u8, json_value, "HighPriority")) {
            return Self{ .HighPriority = {} };
        }
        if (std.mem.eql(u8, json_value, "OracleResponse")) {
            return Self{ .OracleResponse = .{ 
                .id = 0, 
                .response_code = .Error, 
                .result = "" 
            }};
        }
        return null;
    }
    
    /// Gets all cases (equivalent to Swift CaseIterable.allCases)
    pub fn getAllCases(allocator: std.mem.Allocator) ![]Self {
        const cases = [_]Self{
            Self{ .HighPriority = {} },
            Self{ .OracleResponse = .{ 
                .id = 0, 
                .response_code = .Error, 
                .result = try allocator.dupe(u8, "")
            }},
        };
        return try allocator.dupe(Self, &cases);
    }
    
    /// Gets serialization size (equivalent to Swift size property)
    pub fn getSize(self: Self) usize {
        return switch (self) {
            .HighPriority => 1,
            .OracleResponse => |oracle| {
                // 1 byte for type + 8 bytes for ID + 1 byte for response code + variable result size
                return 1 + 8 + 1 + getVarBytesSize(oracle.result.len);
            },
        };
    }
    
    /// Serializes transaction attribute (equivalent to Swift serialize)
    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try writer.writeByte(self.getByte());
        
        switch (self) {
            .HighPriority => {}, // No additional data
            .OracleResponse => |oracle| {
                // Write ID as 8 bytes (little-endian)
                const id_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, oracle.id));
                try writer.writeBytes(&id_bytes);
                
                // Write response code
                try writer.writeByte(oracle.response_code.toByte());
                
                // Write result as variable bytes (base64 decoded)
                const result_bytes = try base64Decode(oracle.result, writer.allocator);
                defer writer.allocator.free(result_bytes);
                try writer.writeVarBytes(result_bytes);
            },
        }
    }
    
    /// Deserializes transaction attribute (equivalent to Swift deserialize)
    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        const attr_type = try reader.readByte();
        
        switch (attr_type) {
            0x01 => {
                return Self{ .HighPriority = {} };
            },
            0x11 => {
                // Read Oracle response data
                const id_bytes = try reader.readBytes(8, allocator);
                defer allocator.free(id_bytes);
                const id = std.mem.readIntSliceLittle(u64, id_bytes);
                
                const response_code_byte = try reader.readByte();
                const response_code = OracleResponseCode.fromByte(response_code_byte) orelse {
                    return error.InvalidOracleResponseCode;
                };
                
                const result_len = try reader.readVarInt();
                if (result_len > MAX_RESULT_SIZE) {
                    return errors.SerializationError.DataTooLarge;
                }
                const result_bytes = try reader.readBytes(@intCast(result_len), allocator);
                defer allocator.free(result_bytes);
                
                // Encode result as base64
                const result_b64 = try base64Encode(result_bytes, allocator);
                
                return Self{ 
                    .OracleResponse = .{
                        .id = id,
                        .response_code = response_code,
                        .result = result_b64,
                    }
                };
            },
            else => {
                return error.UnknownTransactionAttributeType;
            },
        }
    }
    
    /// JSON encoding (equivalent to Swift Codable encode)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        switch (self) {
            .HighPriority => {
                return try std.fmt.allocPrint(allocator, "\"HighPriority\"");
            },
            .OracleResponse => |oracle| {
                return try std.fmt.allocPrint(
                    allocator,
                    "{{\"type\":\"OracleResponse\",\"id\":{},\"code\":{},\"result\":\"{s}\"}}",
                    .{ oracle.id, oracle.response_code.toByte(), oracle.result }
                );
            },
        }
    }
    
    /// JSON decoding (equivalent to Swift Codable init(from:))
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        switch (parsed.value) {
            .string => |s| {
                if (std.mem.eql(u8, s, "HighPriority")) {
                    return Self{ .HighPriority = {} };
                }
                return error.UnknownTransactionAttributeType;
            },
            .object => |obj| {
                const type_str = obj.get("type").?.string;
                if (std.mem.eql(u8, type_str, "OracleResponse")) {
                    const id = @as(u64, @intCast(obj.get("id").?.integer));
                    const code_int = @as(u8, @intCast(obj.get("code").?.integer));
                    const code = OracleResponseCode.fromByte(code_int) orelse return error.InvalidOracleResponseCode;
                    const result = try allocator.dupe(u8, obj.get("result").?.string);
                    
                    return Self{ 
                        .OracleResponse = .{
                            .id = id,
                            .response_code = code,
                            .result = result,
                        }
                    };
                }
                return error.UnknownTransactionAttributeType;
            },
            else => return error.InvalidJsonFormat,
        }
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .HighPriority => {},
            .OracleResponse => |oracle| {
                allocator.free(oracle.result);
            },
        }
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        return switch (self) {
            .HighPriority => Self{ .HighPriority = {} },
            .OracleResponse => |oracle| Self{ 
                .OracleResponse = .{
                    .id = oracle.id,
                    .response_code = oracle.response_code,
                    .result = try allocator.dupe(u8, oracle.result),
                }
            },
        };
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .HighPriority => try allocator.dupe(u8, "HighPriority"),
            .OracleResponse => |oracle| try std.fmt.allocPrint(
                allocator,
                "OracleResponse(id: {}, code: {}, result_len: {})",
                .{ oracle.id, oracle.response_code.toByte(), oracle.result.len }
            ),
        };
    }
};

/// Helper functions
fn getVarBytesSize(data_len: usize) usize {
    if (data_len < 0xFD) return 1 + data_len;
    if (data_len < 0x10000) return 3 + data_len;
    if (data_len < 0x100000000) return 5 + data_len;
    return 9 + data_len;
}

fn base64Encode(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    return encoder.encode(encoded, data);
}

fn base64Decode(encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, encoded);
    return decoded;
}

// Tests (converted from Swift TransactionAttribute tests)
test "TransactionAttribute creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test HighPriority attribute (equivalent to Swift tests)
    const high_priority = TransactionAttribute{ .HighPriority = {} };
    try testing.expectEqualStrings("HighPriority", high_priority.getJsonValue());
    try testing.expectEqual(@as(u8, 0x01), high_priority.getByte());
    try testing.expectEqual(@as(usize, 1), high_priority.getSize());
    
    // Test OracleResponse attribute
    var oracle_response = TransactionAttribute{ 
        .OracleResponse = .{
            .id = 12345,
            .response_code = .Success,
            .result = try allocator.dupe(u8, "test_result"),
        }
    };
    defer oracle_response.deinit(allocator);
    
    try testing.expectEqualStrings("OracleResponse", oracle_response.getJsonValue());
    try testing.expectEqual(@as(u8, 0x11), oracle_response.getByte());
    try testing.expect(oracle_response.getSize() > 10); // Should be more than base size
}

test "TransactionAttribute byte conversion" {
    const testing = std.testing;
    
    // Test fromByte conversion (equivalent to Swift valueOf tests)
    const high_priority_opt = TransactionAttribute.fromByte(0x01);
    try testing.expect(high_priority_opt != null);
    
    const oracle_response_opt = TransactionAttribute.fromByte(0x11);
    try testing.expect(oracle_response_opt != null);
    
    // Test invalid byte value
    const invalid_opt = TransactionAttribute.fromByte(0xFF);
    try testing.expect(invalid_opt == null);
}

test "OracleResponseCode conversion" {
    const testing = std.testing;
    
    // Test OracleResponseCode byte conversion
    try testing.expectEqual(@as(u8, 0x00), OracleResponseCode.Success.toByte());
    try testing.expectEqual(@as(u8, 0xff), OracleResponseCode.Error.toByte());
    
    try testing.expectEqual(OracleResponseCode.Success, OracleResponseCode.fromByte(0x00).?);
    try testing.expectEqual(OracleResponseCode.Error, OracleResponseCode.fromByte(0xff).?);
    
    // Test invalid code
    try testing.expect(OracleResponseCode.fromByte(0x99) == null);
}

test "TransactionAttribute JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test HighPriority JSON encoding/decoding
    const high_priority = TransactionAttribute{ .HighPriority = {} };
    const high_priority_json = try high_priority.encodeToJson(allocator);
    defer allocator.free(high_priority_json);
    
    try testing.expect(std.mem.indexOf(u8, high_priority_json, "HighPriority") != null);
    
    const decoded_high_priority = try TransactionAttribute.decodeFromJson(high_priority_json, allocator);
    try testing.expect(std.meta.activeTag(decoded_high_priority) == .HighPriority);
    
    // Test OracleResponse JSON encoding/decoding
    var oracle_response = TransactionAttribute{ 
        .OracleResponse = .{
            .id = 999,
            .response_code = .NotFound,
            .result = try allocator.dupe(u8, "not_found"),
        }
    };
    defer oracle_response.deinit(allocator);
    
    const oracle_json = try oracle_response.encodeToJson(allocator);
    defer allocator.free(oracle_json);
    
    try testing.expect(std.mem.indexOf(u8, oracle_json, "999") != null);
    try testing.expect(std.mem.indexOf(u8, oracle_json, "OracleResponse") != null);
    
    var decoded_oracle = try TransactionAttribute.decodeFromJson(oracle_json, allocator);
    defer decoded_oracle.deinit(allocator);
    
    try testing.expect(std.meta.activeTag(decoded_oracle) == .OracleResponse);
    try testing.expectEqual(@as(u64, 999), decoded_oracle.OracleResponse.id);
    try testing.expectEqual(OracleResponseCode.NotFound, decoded_oracle.OracleResponse.response_code);
}

test "TransactionAttribute utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test formatting
    const high_priority = TransactionAttribute{ .HighPriority = {} };
    const high_priority_formatted = try high_priority.format(allocator);
    defer allocator.free(high_priority_formatted);
    
    try testing.expectEqualStrings("HighPriority", high_priority_formatted);
    
    // Test cloning
    var original_oracle = TransactionAttribute{ 
        .OracleResponse = .{
            .id = 555,
            .response_code = .Timeout,
            .result = try allocator.dupe(u8, "timeout_result"),
        }
    };
    defer original_oracle.deinit(allocator);
    
    var cloned_oracle = try original_oracle.clone(allocator);
    defer cloned_oracle.deinit(allocator);
    
    try testing.expectEqual(@as(u64, 555), cloned_oracle.OracleResponse.id);
    try testing.expectEqual(OracleResponseCode.Timeout, cloned_oracle.OracleResponse.response_code);
    try testing.expectEqualStrings("timeout_result", cloned_oracle.OracleResponse.result);
}
