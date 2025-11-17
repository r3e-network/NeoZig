//! Record Type implementation
//!
//! Complete conversion from NeoSwift RecordType.swift
//! Provides DNS record types for Neo Name Service operations.

const std = @import("std");


const errors = @import("../core/errors.zig");

/// DNS record types (converted from Swift RecordType)
pub const RecordType = enum(u8) {
    /// An address record (IPv4)
    A = 1,
    /// A canonical name record  
    CNAME = 5,
    /// A text record
    TXT = 16,
    /// An IPv6 address record
    AAAA = 28,
    
    const Self = @This();
    
    /// Gets JSON value (equivalent to Swift .jsonValue property)
    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .A => "A",
            .CNAME => "CNAME", 
            .TXT => "TXT",
            .AAAA => "AAAA",
        };
    }
    
    /// Gets byte value (equivalent to Swift .byte property)
    pub fn getByte(self: Self) u8 {
        return @intFromEnum(self);
    }
    
    /// Creates from byte value (equivalent to Swift ByteEnum.throwingValueOf)
    pub fn fromByte(byte_value: u8) ?Self {
        return switch (byte_value) {
            1 => .A,
            5 => .CNAME,
            16 => .TXT,
            28 => .AAAA,
            else => null,
        };
    }
    
    /// Creates from byte value with error (equivalent to Swift throwingValueOf)
    pub fn throwingValueOf(byte_value: u8) !Self {
        return Self.fromByte(byte_value) orelse {
            return errors.throwIllegalArgument("Invalid record type byte value");
        };
    }
    
    /// Creates from JSON value (equivalent to Swift fromJsonValue)
    pub fn fromJsonValue(json_value: []const u8) ?Self {
        if (std.mem.eql(u8, json_value, "A")) return .A;
        if (std.mem.eql(u8, json_value, "CNAME")) return .CNAME;
        if (std.mem.eql(u8, json_value, "TXT")) return .TXT;
        if (std.mem.eql(u8, json_value, "AAAA")) return .AAAA;
        return null;
    }
    
    /// Gets all record types (equivalent to Swift CaseIterable.allCases)
    pub fn getAllCases() []const Self {
        return &[_]Self{ .A, .CNAME, .TXT, .AAAA };
    }
    
    /// Gets record type description
    pub fn getDescription(self: Self) []const u8 {
        return switch (self) {
            .A => "IPv4 address record",
            .CNAME => "Canonical name record",
            .TXT => "Text record",
            .AAAA => "IPv6 address record",
        };
    }
    
    /// Checks if record type supports specific data format
    pub fn supportsIPv4(self: Self) bool {
        return self == .A;
    }
    
    pub fn supportsIPv6(self: Self) bool {
        return self == .AAAA;
    }
    
    pub fn supportsText(self: Self) bool {
        return self == .TXT or self == .CNAME;
    }
    
    /// Validates record data format for type
    pub fn validateRecordData(self: Self, data: []const u8) !void {
        switch (self) {
            .A => {
                // IPv4 address validation (simplified)
                if (data.len == 0 or data.len > 15) { // "255.255.255.255" max
                    return errors.ValidationError.InvalidParameter;
                }
                
                // Check for dots and digits
                var dot_count: u32 = 0;
                for (data) |char| {
                    if (char == '.') {
                        dot_count += 1;
                    } else if (!std.ascii.isDigit(char)) {
                        return errors.ValidationError.InvalidParameter;
                    }
                }
                
                if (dot_count != 3) {
                    return errors.ValidationError.InvalidParameter;
                }
            },
            .AAAA => {
                // IPv6 address validation (simplified)
                if (data.len == 0 or data.len > 39) { // IPv6 max length
                    return errors.ValidationError.InvalidParameter;
                }
                
                // Check for colons and hex characters
                for (data) |char| {
                    if (char != ':' and !std.ascii.isHex(char)) {
                        return errors.ValidationError.InvalidParameter;
                    }
                }
            },
            .TXT, .CNAME => {
                // Text records - validate UTF-8
                if (!std.unicode.utf8ValidateSlice(data)) {
                    return errors.ValidationError.InvalidParameter;
                }
                
                if (data.len > 1024) { // Reasonable text limit
                    return errors.ValidationError.ParameterOutOfRange;
                }
            },
        }
    }
    
    /// Decodes from JSON (equivalent to Swift Codable)
    pub fn decodeFromJson(json_value: std.json.Value) !Self {
        return switch (json_value) {
            .string => |s| {
                return Self.fromJsonValue(s) orelse {
                    return errors.ValidationError.InvalidParameter;
                };
            },
            .integer => |i| {
                return Self.fromByte(@intCast(i)) orelse {
                    return errors.ValidationError.InvalidParameter;
                };
            },
            else => errors.ValidationError.InvalidFormat,
        };
    }
    
    /// Encodes to JSON (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        _ = allocator;
        return std.json.Value{ .string = self.getJsonValue() };
    }
};

/// Record type utilities
pub const RecordTypeUtils = struct {
    /// Detects record type from data format
    pub fn detectRecordType(data: []const u8) ?RecordType {
        // Simple heuristic detection
        if (isIPv4Format(data)) return .A;
        if (isIPv6Format(data)) return .AAAA;
        if (isDomainFormat(data)) return .CNAME;
        return .TXT; // Default to text
    }
    
    /// Checks if data looks like IPv4
    fn isIPv4Format(data: []const u8) bool {
        var dot_count: u32 = 0;
        var digit_count: u32 = 0;
        
        for (data) |char| {
            if (char == '.') {
                dot_count += 1;
            } else if (std.ascii.isDigit(char)) {
                digit_count += 1;
            } else {
                return false;
            }
        }
        
        return dot_count == 3 and digit_count > 4;
    }
    
    /// Checks if data looks like IPv6
    fn isIPv6Format(data: []const u8) bool {
        var colon_count: u32 = 0;
        
        for (data) |char| {
            if (char == ':') {
                colon_count += 1;
            } else if (!std.ascii.isHex(char)) {
                return false;
            }
        }
        
        return colon_count >= 2; // IPv6 has multiple colons
    }
    
    /// Checks if data looks like domain name
    fn isDomainFormat(data: []const u8) bool {
        return std.mem.indexOf(u8, data, ".") != null and
               !isIPv4Format(data) and
               !isIPv6Format(data);
    }
    
    /// Validates record type and data combination
    pub fn validateRecordTypeAndData(record_type: RecordType, data: []const u8) !void {
        try record_type.validateRecordData(data);
        
        // Additional validation: ensure data format matches type
        const detected_type = detectRecordType(data);
        if (detected_type != null and detected_type.? != record_type) {
            return errors.ValidationError.InvalidParameter;
        }
    }
    
    /// Gets supported record types for NNS
    pub fn getSupportedNNSRecordTypes() []const RecordType {
        return &[_]RecordType{ .A, .CNAME, .TXT, .AAAA };
    }
    
    /// Checks if record type is supported by NNS
    pub fn isSupportedByNNS(record_type: RecordType) bool {
        const supported = getSupportedNNSRecordTypes();
        for (supported) |supported_type| {
            if (supported_type == record_type) return true;
        }
        return false;
    }
};

// Tests (converted from Swift RecordType tests)
test "RecordType values and properties" {
    const testing = std.testing;
    
    // Test record type values (equivalent to Swift RecordType tests)
    try testing.expectEqual(@as(u8, 1), RecordType.A.getByte());
    try testing.expectEqual(@as(u8, 5), RecordType.CNAME.getByte());
    try testing.expectEqual(@as(u8, 16), RecordType.TXT.getByte());
    try testing.expectEqual(@as(u8, 28), RecordType.AAAA.getByte());
    
    // Test JSON values
    try testing.expectEqualStrings("A", RecordType.A.getJsonValue());
    try testing.expectEqualStrings("CNAME", RecordType.CNAME.getJsonValue());
    try testing.expectEqualStrings("TXT", RecordType.TXT.getJsonValue());
    try testing.expectEqualStrings("AAAA", RecordType.AAAA.getJsonValue());
    
    // Test descriptions
    try testing.expect(std.mem.indexOf(u8, RecordType.A.getDescription(), "IPv4") != null);
    try testing.expect(std.mem.indexOf(u8, RecordType.CNAME.getDescription(), "canonical") != null);
    try testing.expect(std.mem.indexOf(u8, RecordType.TXT.getDescription(), "text") != null);
    try testing.expect(std.mem.indexOf(u8, RecordType.AAAA.getDescription(), "IPv6") != null);
}

test "RecordType conversion operations" {
    const testing = std.testing;
    
    // Test from byte conversion (equivalent to Swift ByteEnum tests)
    try testing.expectEqual(RecordType.A, RecordType.fromByte(1).?);
    try testing.expectEqual(RecordType.CNAME, RecordType.fromByte(5).?);
    try testing.expectEqual(RecordType.TXT, RecordType.fromByte(16).?);
    try testing.expectEqual(RecordType.AAAA, RecordType.fromByte(28).?);
    
    // Test invalid byte values
    try testing.expectEqual(@as(?RecordType, null), RecordType.fromByte(99));
    try testing.expectEqual(@as(?RecordType, null), RecordType.fromByte(0));
    
    // Test from JSON value conversion
    try testing.expectEqual(RecordType.A, RecordType.fromJsonValue("A").?);
    try testing.expectEqual(RecordType.CNAME, RecordType.fromJsonValue("CNAME").?);
    try testing.expectEqual(@as(?RecordType, null), RecordType.fromJsonValue("INVALID"));
    
    // Test throwing value of
    try testing.expectEqual(RecordType.TXT, try RecordType.throwingValueOf(16));
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        RecordType.throwingValueOf(99)
    );
}

test "RecordType data validation" {
    const testing = std.testing;
    
    // Test IPv4 address validation (equivalent to Swift data validation tests)
    try RecordType.A.validateRecordData("192.168.1.1");
    try RecordType.A.validateRecordData("10.0.0.1");
    
    try testing.expectError(
        errors.ValidationError.InvalidParameter,
        RecordType.A.validateRecordData("invalid.ipv4.address.here")
    );
    
    try testing.expectError(
        errors.ValidationError.InvalidParameter,
        RecordType.A.validateRecordData("192.168.1") // Missing octet
    );
    
    // Test IPv6 address validation
    try RecordType.AAAA.validateRecordData("2001:db8::1");
    try RecordType.AAAA.validateRecordData("::1");
    
    try testing.expectError(
        errors.ValidationError.InvalidParameter,
        RecordType.AAAA.validateRecordData("invalid::ipv6::address::format")
    );
    
    // Test text record validation
    try RecordType.TXT.validateRecordData("Valid text record");
    try RecordType.CNAME.validateRecordData("example.neo");
    
    try testing.expectError(
        errors.ValidationError.ParameterOutOfRange,
        RecordType.TXT.validateRecordData("x" ** 2000) // Too long
    );
}

test "RecordType support and detection" {
    const testing = std.testing;
    
    // Test data type support (equivalent to Swift support tests)
    try testing.expect(RecordType.A.supportsIPv4());
    try testing.expect(!RecordType.A.supportsIPv6());
    try testing.expect(!RecordType.A.supportsText());
    
    try testing.expect(RecordType.AAAA.supportsIPv6());
    try testing.expect(!RecordType.AAAA.supportsIPv4());
    
    try testing.expect(RecordType.TXT.supportsText());
    try testing.expect(RecordType.CNAME.supportsText());
    
    // Test NNS support
    try testing.expect(RecordTypeUtils.isSupportedByNNS(.A));
    try testing.expect(RecordTypeUtils.isSupportedByNNS(.CNAME));
    try testing.expect(RecordTypeUtils.isSupportedByNNS(.TXT));
    try testing.expect(RecordTypeUtils.isSupportedByNNS(.AAAA));
    
    const supported_types = RecordTypeUtils.getSupportedNNSRecordTypes();
    try testing.expectEqual(@as(usize, 4), supported_types.len);
}

test "RecordTypeUtils detection and validation" {
    const testing = std.testing;
    
    // Test automatic record type detection
    try testing.expectEqual(RecordType.A, RecordTypeUtils.detectRecordType("192.168.1.1").?);
    try testing.expectEqual(RecordType.AAAA, RecordTypeUtils.detectRecordType("2001:db8::1").?);
    try testing.expectEqual(RecordType.CNAME, RecordTypeUtils.detectRecordType("example.neo").?);
    try testing.expectEqual(RecordType.TXT, RecordTypeUtils.detectRecordType("Some text data").?);
    
    // Test combined validation
    try RecordTypeUtils.validateRecordTypeAndData(.A, "10.0.0.1");
    try RecordTypeUtils.validateRecordTypeAndData(.TXT, "Valid text");
    
    // Test mismatched type and data
    try testing.expectError(
        errors.ValidationError.InvalidParameter,
        RecordTypeUtils.validateRecordTypeAndData(.A, "not.an.ip.address")
    );
}

test "RecordType JSON operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const record_type = RecordType.A;
    
    const encoded_json = try record_type.encodeToJson(allocator);
    defer encoded_json.deinit();
    
    try testing.expectEqualStrings("A", encoded_json.string);
    
    const decoded_type = try RecordType.decodeFromJson(encoded_json);
    try testing.expectEqual(record_type, decoded_type);
    
    // Test decoding from integer
    const int_json = std.json.Value{ .integer = 5 };
    const decoded_from_int = try RecordType.decodeFromJson(int_json);
    try testing.expectEqual(RecordType.CNAME, decoded_from_int);
    
    // Test invalid JSON
    const invalid_json = std.json.Value{ .bool = true };
    try testing.expectError(errors.ValidationError.InvalidFormat, RecordType.decodeFromJson(invalid_json));
}