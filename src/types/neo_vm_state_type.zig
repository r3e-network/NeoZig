//! Neo VM State Type implementation
//!
//! Complete conversion from NeoSwift NeoVMStateType.swift
//! Defines Neo virtual machine execution states.

const std = @import("std");

const errors = @import("../core/errors.zig");

/// Neo VM state type (converted from Swift NeoVMStateType)
pub const NeoVMStateType = enum {
    None,
    Halt,
    Fault,
    Break,

    const Self = @This();

    /// Gets JSON value (equivalent to Swift .jsonvalue property)
    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .None => "NONE",
            .Halt => "HALT",
            .Fault => "FAULT",
            .Break => "BREAK",
        };
    }

    /// Gets raw value (equivalent to Swift .rawValue property)
    pub fn getRawValue(self: Self) []const u8 {
        return self.getJsonValue();
    }

    /// Gets integer value (equivalent to Swift .int property)
    pub fn getIntValue(self: Self) i32 {
        return switch (self) {
            .None => 0,
            .Halt => 1,
            .Fault => 1 << 1, // 2
            .Break => 1 << 2, // 4
        };
    }

    /// Creates from JSON string value (equivalent to Swift fromJsonValue)
    pub fn fromJsonValue(value: ?[]const u8) ?Self {
        const actual_value = value orelse return .None;

        if (actual_value.len == 0) return .None;

        if (std.mem.eql(u8, actual_value, "NONE")) return .None;
        if (std.mem.eql(u8, actual_value, "HALT")) return .Halt;
        if (std.mem.eql(u8, actual_value, "FAULT")) return .Fault;
        if (std.mem.eql(u8, actual_value, "BREAK")) return .Break;

        return null;
    }

    /// Creates from integer value (equivalent to Swift fromIntValue)
    pub fn fromIntValue(int_value: ?i32) ?Self {
        const actual_int = int_value orelse return .None;

        return switch (actual_int) {
            0 => .None,
            1 => .Halt,
            2 => .Fault,
            4 => .Break,
            else => null,
        };
    }

    /// Gets all cases (equivalent to Swift .allCases)
    pub fn getAllCases() []const Self {
        return &[_]Self{ .None, .Halt, .Fault, .Break };
    }

    /// Decodes from JSON (equivalent to Swift init(from decoder:))
    pub fn decodeFromJson(json_value: std.json.Value) !Self {
        return switch (json_value) {
            .string => |s| {
                return Self.fromJsonValue(s) orelse {
                    return errors.throwIllegalArgument("Invalid NeoVMStateType string");
                };
            },
            .integer => |i| {
                return Self.fromIntValue(@intCast(i)) orelse {
                    return errors.throwIllegalArgument("Invalid NeoVMStateType integer");
                };
            },
            else => errors.ValidationError.InvalidParameter,
        };
    }

    /// Encodes to JSON (equivalent to Swift encode(to:))
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        _ = allocator;
        return std.json.Value{ .string = self.getJsonValue() };
    }

    /// Checks if state indicates successful execution
    pub fn isSuccess(self: Self) bool {
        return self == .Halt;
    }

    /// Checks if state indicates execution failure
    pub fn isFailure(self: Self) bool {
        return self == .Fault;
    }

    /// Checks if state indicates execution interruption
    pub fn isInterrupted(self: Self) bool {
        return self == .Break;
    }

    /// Gets state description
    pub fn getDescription(self: Self) []const u8 {
        return switch (self) {
            .None => "No execution state",
            .Halt => "Execution completed successfully",
            .Fault => "Execution failed with fault",
            .Break => "Execution interrupted",
        };
    }
};

// Tests (converted from Swift NeoVMStateType tests)
test "NeoVMStateType values and properties" {
    const testing = std.testing;

    // Test JSON values (equivalent to Swift jsonvalue tests)
    try testing.expectEqualStrings("NONE", NeoVMStateType.None.getJsonValue());
    try testing.expectEqualStrings("HALT", NeoVMStateType.Halt.getJsonValue());
    try testing.expectEqualStrings("FAULT", NeoVMStateType.Fault.getJsonValue());
    try testing.expectEqualStrings("BREAK", NeoVMStateType.Break.getJsonValue());

    // Test raw values
    try testing.expectEqualStrings("NONE", NeoVMStateType.None.getRawValue());
    try testing.expectEqualStrings("HALT", NeoVMStateType.Halt.getRawValue());

    // Test integer values (equivalent to Swift .int tests)
    try testing.expectEqual(@as(i32, 0), NeoVMStateType.None.getIntValue());
    try testing.expectEqual(@as(i32, 1), NeoVMStateType.Halt.getIntValue());
    try testing.expectEqual(@as(i32, 2), NeoVMStateType.Fault.getIntValue());
    try testing.expectEqual(@as(i32, 4), NeoVMStateType.Break.getIntValue());
}

test "NeoVMStateType conversion from values" {
    const testing = std.testing;

    // Test from JSON value (equivalent to Swift fromJsonValue tests)
    try testing.expectEqual(NeoVMStateType.None, NeoVMStateType.fromJsonValue("NONE").?);
    try testing.expectEqual(NeoVMStateType.Halt, NeoVMStateType.fromJsonValue("HALT").?);
    try testing.expectEqual(NeoVMStateType.Fault, NeoVMStateType.fromJsonValue("FAULT").?);
    try testing.expectEqual(NeoVMStateType.Break, NeoVMStateType.fromJsonValue("BREAK").?);

    // Test empty/null handling
    try testing.expectEqual(NeoVMStateType.None, NeoVMStateType.fromJsonValue(null).?);
    try testing.expectEqual(NeoVMStateType.None, NeoVMStateType.fromJsonValue("").?);

    // Test invalid value
    try testing.expectEqual(@as(?NeoVMStateType, null), NeoVMStateType.fromJsonValue("INVALID"));

    // Test from integer value (equivalent to Swift fromIntValue tests)
    try testing.expectEqual(NeoVMStateType.None, NeoVMStateType.fromIntValue(0).?);
    try testing.expectEqual(NeoVMStateType.Halt, NeoVMStateType.fromIntValue(1).?);
    try testing.expectEqual(NeoVMStateType.Fault, NeoVMStateType.fromIntValue(2).?);
    try testing.expectEqual(NeoVMStateType.Break, NeoVMStateType.fromIntValue(4).?);

    // Test null/invalid integer handling
    try testing.expectEqual(NeoVMStateType.None, NeoVMStateType.fromIntValue(null).?);
    try testing.expectEqual(@as(?NeoVMStateType, null), NeoVMStateType.fromIntValue(99));
}

test "NeoVMStateType state checking" {
    const testing = std.testing;

    // Test state classification (additional utility tests)
    try testing.expect(NeoVMStateType.Halt.isSuccess());
    try testing.expect(!NeoVMStateType.Fault.isSuccess());
    try testing.expect(!NeoVMStateType.Break.isSuccess());
    try testing.expect(!NeoVMStateType.None.isSuccess());

    try testing.expect(NeoVMStateType.Fault.isFailure());
    try testing.expect(!NeoVMStateType.Halt.isFailure());
    try testing.expect(!NeoVMStateType.Break.isFailure());
    try testing.expect(!NeoVMStateType.None.isFailure());

    try testing.expect(NeoVMStateType.Break.isInterrupted());
    try testing.expect(!NeoVMStateType.Halt.isInterrupted());
    try testing.expect(!NeoVMStateType.Fault.isInterrupted());
    try testing.expect(!NeoVMStateType.None.isInterrupted());
}

test "NeoVMStateType JSON encoding/decoding" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test JSON encoding (equivalent to Swift Codable tests)
    const halt_json = try NeoVMStateType.Halt.encodeToJson(allocator);

    try testing.expectEqualStrings("HALT", halt_json.string);

    // Test JSON decoding
    const string_json = std.json.Value{ .string = "FAULT" };
    const decoded_from_string = try NeoVMStateType.decodeFromJson(string_json);
    try testing.expectEqual(NeoVMStateType.Fault, decoded_from_string);

    const int_json = std.json.Value{ .integer = 2 };
    const decoded_from_int = try NeoVMStateType.decodeFromJson(int_json);
    try testing.expectEqual(NeoVMStateType.Fault, decoded_from_int);

    // Test invalid JSON
    const invalid_json = std.json.Value{ .bool = true };
    try testing.expectError(errors.ValidationError.InvalidParameter, NeoVMStateType.decodeFromJson(invalid_json));
}

test "NeoVMStateType all cases enumeration" {
    const testing = std.testing;

    // Test all cases (equivalent to Swift .allCases tests)
    const all_cases = NeoVMStateType.getAllCases();
    try testing.expectEqual(@as(usize, 4), all_cases.len);

    // Verify all expected cases are present
    try testing.expect(std.mem.indexOf(NeoVMStateType, all_cases, &[_]NeoVMStateType{.None}) != null);
    try testing.expect(std.mem.indexOf(NeoVMStateType, all_cases, &[_]NeoVMStateType{.Halt}) != null);
    try testing.expect(std.mem.indexOf(NeoVMStateType, all_cases, &[_]NeoVMStateType{.Fault}) != null);
    try testing.expect(std.mem.indexOf(NeoVMStateType, all_cases, &[_]NeoVMStateType{.Break}) != null);
}
