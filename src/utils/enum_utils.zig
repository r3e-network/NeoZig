//! Enum utilities and protocols
//!
//! Complete conversion from NeoSwift Enum.swift
//! Provides byte enum protocol and JSON conversion utilities.

const std = @import("std");


const errors = @import("../core/errors.zig");

/// Byte enum trait (converted from Swift ByteEnum protocol)
pub fn ByteEnum(comptime T: type) type {
    return struct {
        /// Gets byte value (equivalent to Swift .byte property)
        pub fn getByte(self: T) u8 {
            return T.getByte(self);
        }
        
        /// Gets JSON value (equivalent to Swift .jsonValue property)
        pub fn getJsonValue(self: T) []const u8 {
            return T.getJsonValue(self);
        }
        
        /// Creates from byte value with error (equivalent to Swift throwingValueOf)
        pub fn throwingValueOf(byte_value: u8) !T {
            return T.fromByte(byte_value) orelse {
                return errors.throwIllegalArgument("Enum value not found for byte");
            };
        }
        
        /// Creates from byte value safely (equivalent to Swift valueOf)
        pub fn valueOf(byte_value: u8) ?T {
            return T.fromByte(byte_value);
        }
        
        /// Creates from JSON value (equivalent to Swift fromJsonValue)
        pub fn fromJsonValue(json_string: []const u8) ?T {
            return T.fromJsonValue(json_string);
        }
        
        /// Decodes from JSON (equivalent to Swift init(from:))
        pub fn decodeFromJson(json_value: std.json.Value) !T {
            return switch (json_value) {
                .string => |s| {
                    return T.fromJsonValue(s) orelse errors.ValidationError.InvalidFormat;
                },
                .integer => |i| {
                    return T.fromByte(@intCast(i)) orelse errors.ValidationError.InvalidFormat;
                },
                else => errors.ValidationError.InvalidFormat,
            };
        }
        
        /// Encodes to JSON (equivalent to Swift encode(to:))
        pub fn encodeToJson(self: T, allocator: std.mem.Allocator) !std.json.Value {
            const value = try allocator.dupe(u8, self.getJsonValue());
            return std.json.Value{ .string = value };
        }
    };
}

/// Enum iteration utilities (converted from Swift CaseIterable)
pub const EnumUtils = struct {
    /// Gets all enum cases (equivalent to Swift .allCases)
    pub fn getAllCases(comptime T: type) []const T {
        return comptime blk: {
            const enum_info = @typeInfo(T).Enum;
            var cases: [enum_info.fields.len]T = undefined;
            
            for (enum_info.fields, 0..) |field, i| {
                cases[i] = @field(T, field.name);
            }
            
            break :blk &cases;
        };
    }
    
    /// Finds enum case by predicate (equivalent to Swift .first(where:))
    pub fn findCase(comptime T: type, predicate: *const fn (T) bool) ?T {
        const all_cases = getAllCases(T);
        
        for (all_cases) |case| {
            if (predicate(case)) {
                return case;
            }
        }
        
        return null;
    }
    
    /// Counts enum cases (equivalent to Swift .count)
    pub fn getCaseCount(comptime T: type) usize {
        return getAllCases(T).len;
    }
    
    /// Gets enum case names (equivalent to Swift case name access)
    pub fn getCaseNames(comptime T: type) []const []const u8 {
        return comptime blk: {
            const enum_info = @typeInfo(T).Enum;
            var names: [enum_info.fields.len][]const u8 = undefined;
            
            for (enum_info.fields, 0..) |field, i| {
                names[i] = field.name;
            }
            
            break :blk &names;
        };
    }
};

/// String enum utilities (converted from Swift string enum handling)
pub const StringEnumUtils = struct {
    /// Creates string enum from value (equivalent to Swift string enum init)
    pub fn fromString(comptime T: type, value: []const u8) ?T {
        const case_names = EnumUtils.getCaseNames(T);
        const all_cases = EnumUtils.getAllCases(T);
        
        for (case_names, all_cases) |name, case| {
            if (std.mem.eql(u8, name, value)) {
                return case;
            }
        }
        
        return null;
    }
    
    /// Converts enum to string (equivalent to Swift string enum string value)
    pub fn toString(comptime T: type, value: T) []const u8 {
        const case_names = EnumUtils.getCaseNames(T);
        const all_cases = EnumUtils.getAllCases(T);
        
        for (all_cases, case_names) |case, name| {
            if (std.meta.eql(case, value)) {
                return name;
            }
        }
        
        return "unknown";
    }
};

/// JSON enum conversion utilities
pub const JsonEnumUtils = struct {
    /// Encodes enum as JSON string (equivalent to Swift JSON encoding)
    pub fn encodeEnumAsString(comptime T: type, value: T, allocator: std.mem.Allocator) !std.json.Value {
        _ = allocator;
        const string_value = StringEnumUtils.toString(T, value);
        return std.json.Value{ .string = string_value };
    }
    
    /// Decodes enum from JSON string (equivalent to Swift JSON decoding)
    pub fn decodeEnumFromString(comptime T: type, json_value: std.json.Value) !T {
        const string_value = switch (json_value) {
            .string => |s| s,
            else => return errors.ValidationError.InvalidFormat,
        };
        
        return StringEnumUtils.fromString(T, string_value) orelse {
            return errors.ValidationError.InvalidParameter;
        };
    }
};

// Tests (converted from Swift Enum tests)
test "ByteEnum protocol operations" {
    const testing = std.testing;
    
    // Create test enum that implements ByteEnum-like behavior
    const TestByteEnum = enum(u8) {
        First = 0x01,
        Second = 0x02,
        Third = 0x03,
        
        const Self = @This();
        
        pub fn getByte(self: Self) u8 {
            return @intFromEnum(self);
        }
        
        pub fn getJsonValue(self: Self) []const u8 {
            return switch (self) {
                .First => "first",
                .Second => "second", 
                .Third => "third",
            };
        }
        
        pub fn fromByte(byte_value: u8) ?Self {
            return switch (byte_value) {
                0x01 => .First,
                0x02 => .Second,
                0x03 => .Third,
                else => null,
            };
        }
        
        pub fn fromJsonValue(json_value: []const u8) ?Self {
            if (std.mem.eql(u8, json_value, "first")) return .First;
            if (std.mem.eql(u8, json_value, "second")) return .Second;
            if (std.mem.eql(u8, json_value, "third")) return .Third;
            return null;
        }
    };
    
    // Test byte enum operations (equivalent to Swift ByteEnum tests)
    const first_enum = TestByteEnum.First;
    try testing.expectEqual(@as(u8, 0x01), first_enum.getByte());
    try testing.expectEqualStrings("first", first_enum.getJsonValue());
    
    // Test valueOf operations
    const from_byte = TestByteEnum.fromByte(0x02);
    try testing.expectEqual(TestByteEnum.Second, from_byte.?);
    
    const from_json = TestByteEnum.fromJsonValue("third");
    try testing.expectEqual(TestByteEnum.Third, from_json.?);
    
    // Test invalid values
    try testing.expectEqual(@as(?TestByteEnum, null), TestByteEnum.fromByte(0xFF));
    try testing.expectEqual(@as(?TestByteEnum, null), TestByteEnum.fromJsonValue("invalid"));
}

test "Enum utility functions" {
    const testing = std.testing;
    
    // Test with standard enum
    const TestEnum = enum {
        Alpha,
        Beta,
        Gamma,
    };
    
    // Test case counting (equivalent to Swift .allCases.count)
    const case_count = EnumUtils.getCaseCount(TestEnum);
    try testing.expectEqual(@as(usize, 3), case_count);
    
    // Test case names (equivalent to Swift case name access)
    const case_names = EnumUtils.getCaseNames(TestEnum);
    try testing.expectEqual(@as(usize, 3), case_names.len);
    try testing.expectEqualStrings("Alpha", case_names[0]);
    try testing.expectEqualStrings("Beta", case_names[1]);
    try testing.expectEqualStrings("Gamma", case_names[2]);
    
    // Test string conversion
    const alpha_string = StringEnumUtils.toString(TestEnum, TestEnum.Alpha);
    try testing.expectEqualStrings("Alpha", alpha_string);
    
    const beta_from_string = StringEnumUtils.fromString(TestEnum, "Beta");
    try testing.expectEqual(TestEnum.Beta, beta_from_string.?);
}
