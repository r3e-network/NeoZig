//! Array extension utilities
//!
//! Neo N3 
//! Array extension operations.

const std = @import("std");
const ArrayList = std.ArrayList;

/// Array utility functions
pub const ArrayUtils = struct {
    /// Appends element to array
    pub fn appendElement(comptime T: type, array: []const T, element: T, allocator: std.mem.Allocator) ![]T {
        var result = try allocator.alloc(T, array.len + 1);
        @memcpy(result[0..array.len], array);
        result[array.len] = element;
        return result;
    }

    /// Prepends element to array
    pub fn prependElement(comptime T: type, element: T, array: []const T, allocator: std.mem.Allocator) ![]T {
        var result = try allocator.alloc(T, array.len + 1);
        result[0] = element;
        @memcpy(result[1..], array);
        return result;
    }

    /// Concatenates two arrays
    pub fn concatenate(comptime T: type, lhs: []const T, rhs: []const T, allocator: std.mem.Allocator) ![]T {
        var result = try allocator.alloc(T, lhs.len + rhs.len);
        @memcpy(result[0..lhs.len], lhs);
        @memcpy(result[lhs.len..], rhs);
        return result;
    }

    /// Finds element in array
    pub fn contains(comptime T: type, array: []const T, element: T) bool {
        for (array) |item| {
            if (std.meta.eql(item, element)) {
                return true;
            }
        }
        return false;
    }

    /// Finds index of element
    pub fn firstIndex(comptime T: type, array: []const T, element: T) ?usize {
        for (array, 0..) |item, i| {
            if (std.meta.eql(item, element)) {
                return i;
            }
        }
        return null;
    }

    /// Filters array
    pub fn filter(
        comptime T: type,
        array: []const T,
        predicate: *const fn (T) bool,
        allocator: std.mem.Allocator,
    ) ![]T {
        var result = ArrayList(T).init(allocator);
        defer result.deinit();

        for (array) |item| {
            if (predicate(item)) {
                try result.append(item);
            }
        }

        return try result.toOwnedSlice();
    }

    /// Maps array to new type
    pub fn map(
        comptime T: type,
        comptime U: type,
        array: []const T,
        mapper: *const fn (T) U,
        allocator: std.mem.Allocator,
    ) ![]U {
        var result = try allocator.alloc(U, array.len);

        for (array, 0..) |item, i| {
            result[i] = mapper(item);
        }

        return result;
    }

    /// Reduces array to single value
    pub fn reduce(
        comptime T: type,
        comptime U: type,
        array: []const T,
        initial: U,
        reducer: *const fn (U, T) U,
    ) U {
        var result = initial;

        for (array) |item| {
            result = reducer(result, item);
        }

        return result;
    }

    /// Sorts array in place
    pub fn sort(comptime T: type, array: []T, comptime lessThan: fn (void, T, T) bool) void {
        std.sort.block(T, array, {}, lessThan);
    }

    /// Returns sorted copy
    pub fn sorted(
        comptime T: type,
        array: []const T,
        comptime lessThan: fn (void, T, T) bool,
        allocator: std.mem.Allocator,
    ) ![]T {
        const result = try allocator.dupe(T, array);
        sort(T, result, lessThan);
        return result;
    }

    /// Reverses array in place
    pub fn reverse(comptime T: type, array: []T) void {
        std.mem.reverse(T, array);
    }

    /// Returns reversed copy
    pub fn reversed(comptime T: type, array: []const T, allocator: std.mem.Allocator) ![]T {
        const result = try allocator.dupe(T, array);
        reverse(T, result);
        return result;
    }

    /// Checks if all elements satisfy condition
    pub fn allSatisfy(comptime T: type, array: []const T, predicate: *const fn (T) bool) bool {
        for (array) |item| {
            if (!predicate(item)) {
                return false;
            }
        }
        return true;
    }

    /// Checks if any element satisfies condition
    pub fn anySatisfy(comptime T: type, array: []const T, predicate: *const fn (T) bool) bool {
        for (array) |item| {
            if (predicate(item)) {
                return true;
            }
        }
        return false;
    }

    /// Gets first element satisfying condition
    pub fn first(comptime T: type, array: []const T, predicate: *const fn (T) bool) ?T {
        for (array) |item| {
            if (predicate(item)) {
                return item;
            }
        }
        return null;
    }

    /// Removes element at index
    pub fn removeAt(comptime T: type, array: *ArrayList(T), index: usize) T {
        return array.orderedRemove(index);
    }

    /// Inserts element at index
    pub fn insertAt(comptime T: type, array: *ArrayList(T), element: T, index: usize) !void {
        try array.insert(index, element);
    }
};

// Tests
test "Array concatenation operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test array + element
    const original_array = [_]u32{ 1, 2, 3 };
    const with_appended = try ArrayUtils.appendElement(u32, &original_array, 4, allocator);
    defer allocator.free(with_appended);

    const expected_appended = [_]u32{ 1, 2, 3, 4 };
    try testing.expectEqualSlices(u32, &expected_appended, with_appended);

    // Test element + array
    const with_prepended = try ArrayUtils.prependElement(u32, 0, &original_array, allocator);
    defer allocator.free(with_prepended);

    const expected_prepended = [_]u32{ 0, 1, 2, 3 };
    try testing.expectEqualSlices(u32, &expected_prepended, with_prepended);

    // Test array concatenation
    const array1 = [_]u32{ 1, 2 };
    const array2 = [_]u32{ 3, 4 };
    const concatenated = try ArrayUtils.concatenate(u32, &array1, &array2, allocator);
    defer allocator.free(concatenated);

    const expected_concat = [_]u32{ 1, 2, 3, 4 };
    try testing.expectEqualSlices(u32, &expected_concat, concatenated);
}

test "Array search and filtering" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const test_array = [_]i32{ 1, 2, 3, 4, 5, 6 };

    // Test contains
    try testing.expect(ArrayUtils.contains(i32, &test_array, 3));
    try testing.expect(!ArrayUtils.contains(i32, &test_array, 10));

    // Test firstIndex
    try testing.expectEqual(@as(usize, 2), ArrayUtils.firstIndex(i32, &test_array, 3).?);
    try testing.expectEqual(@as(?usize, null), ArrayUtils.firstIndex(i32, &test_array, 10));

    // Test filter
    const is_even = struct {
        fn predicate(x: i32) bool {
            return @mod(x, 2) == 0;
        }
    }.predicate;

    const even_numbers = try ArrayUtils.filter(i32, &test_array, is_even, allocator);
    defer allocator.free(even_numbers);

    const expected_evens = [_]i32{ 2, 4, 6 };
    try testing.expectEqualSlices(i32, &expected_evens, even_numbers);
}

test "Array transformation operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const test_array = [_]i32{ 1, 2, 3, 4 };

    // Test map
    const double = struct {
        fn mapper(x: i32) i32 {
            return x * 2;
        }
    }.mapper;

    const doubled = try ArrayUtils.map(i32, i32, &test_array, double, allocator);
    defer allocator.free(doubled);

    const expected_doubled = [_]i32{ 2, 4, 6, 8 };
    try testing.expectEqualSlices(i32, &expected_doubled, doubled);

    // Test reduce
    const sum = struct {
        fn reducer(acc: i32, x: i32) i32 {
            return acc + x;
        }
    }.reducer;

    const total = ArrayUtils.reduce(i32, i32, &test_array, 0, sum);
    try testing.expectEqual(@as(i32, 10), total); // 1+2+3+4 = 10
}

test "Array conditional operations" {
    const testing = std.testing;
    _ = testing.allocator;

    const test_array = [_]i32{ 2, 4, 6, 8 };
    const mixed_array = [_]i32{ 1, 2, 3, 4 };

    const is_even = struct {
        fn predicate(x: i32) bool {
            return @mod(x, 2) == 0;
        }
    }.predicate;

    // Test allSatisfy
    try testing.expect(ArrayUtils.allSatisfy(i32, &test_array, is_even));
    try testing.expect(!ArrayUtils.allSatisfy(i32, &mixed_array, is_even));

    // Test anySatisfy tests)
    try testing.expect(ArrayUtils.anySatisfy(i32, &mixed_array, is_even));

    const is_negative = struct {
        fn predicate(x: i32) bool {
            return x < 0;
        }
    }.predicate;

    try testing.expect(!ArrayUtils.anySatisfy(i32, &test_array, is_negative));

    // Test first(where:) tests)
    const first_even = ArrayUtils.first(i32, &mixed_array, is_even);
    try testing.expectEqual(@as(i32, 2), first_even.?);

    const first_negative = ArrayUtils.first(i32, &test_array, is_negative);
    try testing.expectEqual(@as(?i32, null), first_negative);
}
