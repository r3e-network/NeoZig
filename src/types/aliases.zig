//! Type aliases and definitions
//!
//! Complete conversion from NeoSwift Aliases.swift
//! Provides Swift-compatible type aliases and utility types.

const std = @import("std");

/// Byte type alias (equivalent to Swift Byte typealias)
pub const Byte = u8;

/// Bytes type alias (equivalent to Swift Bytes typealias)
pub const Bytes = []const u8;

/// Mutable bytes type
pub const MutableBytes = []u8;

/// Address string type (equivalent to Swift address handling)
pub const AddressString = []const u8;

/// Hex string type (equivalent to Swift hex string handling)
pub const HexString = []const u8;

/// Script type (equivalent to Swift script handling)
pub const Script = []const u8;

/// Mutable script type
pub const MutableScript = []u8;

/// JSON object type (equivalent to Swift JSON handling)
pub const JsonObject = std.json.Value;

/// Result type for operations that may fail (equivalent to Swift Result type)
pub fn Result(comptime T: type, comptime E: type) type {
    return union(enum) {
        success: T,
        failure: E,
        
        const Self = @This();
        
        pub fn ok(value: T) Self {
            return Self{ .success = value };
        }
        
        pub fn err(error_value: E) Self {
            return Self{ .failure = error_value };
        }
        
        pub fn isOk(self: Self) bool {
            return switch (self) {
                .success => true,
                .failure => false,
            };
        }
        
        pub fn isErr(self: Self) bool {
            return !self.isOk();
        }
        
        pub fn unwrap(self: Self) T {
            return switch (self) {
                .success => |value| value,
                .failure => @panic("called unwrap on error result"),
            };
        }
        
        pub fn unwrapOr(self: Self, default_value: T) T {
            return switch (self) {
                .success => |value| value,
                .failure => default_value,
            };
        }
    };
}

/// Optional type utilities (equivalent to Swift Optional handling)
pub const OptionalUtils = struct {
    /// Unwraps optional or throws error (equivalent to Swift guard let)
    pub fn unwrapOrThrow(comptime T: type, optional: ?T, error_msg: []const u8) !T {
        return optional orelse {
            std.log.err("Unwrap failed: {s}", .{error_msg});
            return error.UnwrapFailed;
        };
    }
    
    /// Maps optional value (equivalent to Swift .map)
    pub fn map(comptime T: type, comptime U: type, optional: ?T, mapper: *const fn (T) U) ?U {
        return if (optional) |value| mapper(value) else null;
    }
    
    /// Flat maps optional value (equivalent to Swift .flatMap)
    pub fn flatMap(comptime T: type, comptime U: type, optional: ?T, mapper: *const fn (T) ?U) ?U {
        return if (optional) |value| mapper(value) else null;
    }
};

/// Comparison utilities (equivalent to Swift Comparable operations)
pub const ComparisonUtils = struct {
    /// Three-way comparison result (equivalent to Swift comparison)
    pub const ComparisonResult = enum {
        ascending,
        same,
        descending,
        
        pub fn fromOrder(order: std.math.Order) ComparisonResult {
            return switch (order) {
                .lt => .ascending,
                .eq => .same,
                .gt => .descending,
            };
        }
        
        pub fn toOrder(self: ComparisonResult) std.math.Order {
            return switch (self) {
                .ascending => .lt,
                .same => .eq,
                .descending => .gt,
            };
        }
    };
    
    /// Compares two values (equivalent to Swift comparison operators)
    pub fn compare(comptime T: type, lhs: T, rhs: T) ComparisonResult {
        if (@hasDecl(T, "compare")) {
            return ComparisonResult.fromOrder(lhs.compare(rhs));
        } else {
            const order = std.math.order(lhs, rhs);
            return ComparisonResult.fromOrder(order);
        }
    }
};

/// Collection utilities (equivalent to Swift Collection operations)
pub const CollectionUtils = struct {
    /// Checks if collection is empty
    pub fn isEmpty(collection: anytype) bool {
        return collection.len == 0;
    }
    
    /// Gets first element (equivalent to Swift .first)
    pub fn first(comptime T: type, collection: []const T) ?T {
        return if (collection.len > 0) collection[0] else null;
    }
    
    /// Gets last element (equivalent to Swift .last)
    pub fn last(comptime T: type, collection: []const T) ?T {
        return if (collection.len > 0) collection[collection.len - 1] else null;
    }
    
    /// Gets element at index safely (equivalent to Swift safe subscripting)
    pub fn safeGet(comptime T: type, collection: []const T, index: usize) ?T {
        return if (index < collection.len) collection[index] else null;
    }
};

/// Error utilities (equivalent to Swift error handling)
pub const ErrorUtils = struct {
    /// Throws error with message (equivalent to Swift throw with message)
    pub fn throwError(comptime E: type, error_value: E, message: []const u8) E {
        std.log.err("Error: {s}", .{message});
        return error_value;
    }
    
    /// Validates condition or throws (equivalent to Swift guard)
    pub fn validateOrThrow(condition: bool, error_msg: []const u8) !void {
        if (!condition) {
            std.log.err("Validation failed: {s}", .{error_msg});
            return error.ValidationFailed;
        }
    }
};

// Tests (converted from Swift alias and utility tests)
test "Type aliases and basic operations" {
    const testing = std.testing;
    
    // Test type aliases (equivalent to Swift typealias tests)
    const byte_value: Byte = 0x42;
    try testing.expectEqual(@as(u8, 0x42), byte_value);
    
    const bytes_value: Bytes = &[_]u8{ 1, 2, 3, 4 };
    try testing.expectEqual(@as(usize, 4), bytes_value.len);
    
    const address: AddressString = "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7";
    try testing.expect(address.len > 0);
    
    const hex: HexString = "1234abcd";
    try testing.expectEqualStrings("1234abcd", hex);
}

test "Result type operations" {
    const testing = std.testing;
    
    // Test Result type (equivalent to Swift Result tests)
    const TestResult = Result(i32, []const u8);
    
    const success = TestResult.ok(42);
    try testing.expect(success.isOk());
    try testing.expect(!success.isErr());
    try testing.expectEqual(@as(i32, 42), success.unwrap());
    try testing.expectEqual(@as(i32, 42), success.unwrapOr(0));
    
    const failure = TestResult.err("test error");
    try testing.expect(!failure.isOk());
    try testing.expect(failure.isErr());
    try testing.expectEqual(@as(i32, 0), failure.unwrapOr(0));
}

test "Optional utilities" {
    const testing = std.testing;
    
    // Test optional unwrapping (equivalent to Swift guard let tests)
    const some_value: ?i32 = 42;
    const unwrapped = try OptionalUtils.unwrapOrThrow(i32, some_value, "Should not fail");
    try testing.expectEqual(@as(i32, 42), unwrapped);
    
    const none_value: ?i32 = null;
    try testing.expectError(error.UnwrapFailed, OptionalUtils.unwrapOrThrow(i32, none_value, "Should fail"));
    
    // Test optional mapping (equivalent to Swift .map tests)
    const double = struct {
        fn mapper(x: i32) i32 {
            return x * 2;
        }
    }.mapper;
    
    const mapped_some = OptionalUtils.map(i32, i32, some_value, double);
    try testing.expectEqual(@as(i32, 84), mapped_some.?);
    
    const mapped_none = OptionalUtils.map(i32, i32, none_value, double);
    try testing.expectEqual(@as(?i32, null), mapped_none);
}

test "Comparison utilities" {
    const testing = std.testing;
    
    // Test comparison operations (equivalent to Swift Comparable tests)
    const result_less = ComparisonUtils.compare(i32, 1, 2);
    try testing.expectEqual(ComparisonUtils.ComparisonResult.ascending, result_less);
    
    const result_equal = ComparisonUtils.compare(i32, 5, 5);
    try testing.expectEqual(ComparisonUtils.ComparisonResult.same, result_equal);
    
    const result_greater = ComparisonUtils.compare(i32, 10, 3);
    try testing.expectEqual(ComparisonUtils.ComparisonResult.descending, result_greater);
}

test "Collection utilities" {
    const testing = std.testing;
    
    const test_array = [_]i32{ 1, 2, 3, 4, 5 };
    const empty_array = [_]i32{};
    
    // Test collection operations (equivalent to Swift Collection tests)
    try testing.expect(!CollectionUtils.isEmpty(&test_array));
    try testing.expect(CollectionUtils.isEmpty(&empty_array));
    
    try testing.expectEqual(@as(i32, 1), CollectionUtils.first(i32, &test_array).?);
    try testing.expectEqual(@as(i32, 5), CollectionUtils.last(i32, &test_array).?);
    
    try testing.expectEqual(@as(?i32, null), CollectionUtils.first(i32, &empty_array));
    try testing.expectEqual(@as(?i32, null), CollectionUtils.last(i32, &empty_array));
    
    // Test safe indexing
    try testing.expectEqual(@as(i32, 3), CollectionUtils.safeGet(i32, &test_array, 2).?);
    try testing.expectEqual(@as(?i32, null), CollectionUtils.safeGet(i32, &test_array, 10));
}

test "Error utilities" {
    const testing = std.testing;
    
    // Test validation (equivalent to Swift guard tests)
    try ErrorUtils.validateOrThrow(true, "Should not throw");
    try testing.expectError(error.ValidationFailed, ErrorUtils.validateOrThrow(false, "Should throw"));
}