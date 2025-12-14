//! Numeric Extensions
//!
//! Complete conversion from NeoSwift Numeric.swift extensions
//! Provides numeric utility functions and conversions.

const std = @import("std");
const BytesExt = @import("bytes_extensions.zig").BytesUtils;
const errors = @import("../core/errors.zig");

/// Big integer utilities (converted from Swift BInt extensions)
pub const BigIntUtils = struct {
    /// Converts big integer to padded bytes (equivalent to Swift toBytesPadded)
    pub fn toBytesPadded(value: u256, length: usize, allocator: std.mem.Allocator) ![]u8 {
        const magnitude_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, value));
        return try BytesUtils.toPadded(&magnitude_bytes, length, allocator);
    }

    /// Converts bytes to big integer (equivalent to Swift from bytes)
    pub fn fromBytes(bytes: []const u8) u256 {
        if (bytes.len == 0) return 0;

        var result: u256 = 0;
        for (bytes) |byte| {
            result = (result << 8) | byte;
        }
        return result;
    }

    /// Gets magnitude bytes (equivalent to Swift asMagnitudeBytes)
    pub fn asMagnitudeBytes(value: u256, allocator: std.mem.Allocator) ![]u8 {
        const bytes = std.mem.toBytes(std.mem.nativeToBig(u256, value));

        // Find first non-zero byte
        var start: usize = 0;
        while (start < bytes.len and bytes[start] == 0) {
            start += 1;
        }

        if (start == bytes.len) {
            // All zeros
            return try allocator.dupe(u8, &[_]u8{0});
        }

        return try allocator.dupe(u8, bytes[start..]);
    }
};

/// Integer utilities (converted from Swift Int extensions)
pub const IntUtils = struct {
    /// Power function (equivalent to Swift toPowerOf)
    pub fn toPowerOf(base: i64, exponent: u32) i64 {
        return std.math.pow(i64, base, exponent);
    }

    /// Gets variable size (equivalent to Swift varSize)
    pub fn varSize(value: i64) usize {
        const unsigned_value = if (value < 0) @as(u64, @bitCast(value)) else @as(u64, @intCast(value));

        if (unsigned_value < 0xFD) return 1;
        if (unsigned_value <= 0xFFFF) return 3;
        if (unsigned_value <= 0xFFFFFFFF) return 5;
        return 9;
    }

    /// Converts to unsigned (equivalent to Swift toUnsigned)
    pub fn toUnsigned(value: i32) u32 {
        return @bitCast(value);
    }

    /// Clamps value to range (utility function)
    pub fn clamp(comptime T: type, value: T, min_val: T, max_val: T) T {
        return @max(min_val, @min(max_val, value));
    }

    /// Safe integer conversion with overflow checking
    pub fn safeConvert(comptime From: type, comptime To: type, value: From) !To {
        if (@typeInfo(To).Int.signedness == .unsigned and value < 0) {
            return errors.ValidationError.ParameterOutOfRange;
        }

        const max_val = std.math.maxInt(To);
        const min_val = std.math.minInt(To);

        if (value > max_val or value < min_val) {
            return errors.ValidationError.ParameterOutOfRange;
        }

        return @intCast(value);
    }
};

/// Numeric type utilities (converted from Swift Numeric extensions)
pub const NumericUtils = struct {
    /// Gets bytes in little-endian format (equivalent to Swift .bytes)
    pub fn getBytes(comptime T: type, value: T) [@sizeOf(T)]u8 {
        return std.mem.toBytes(std.mem.nativeToLittle(T, value));
    }

    /// Gets bytes in big-endian format (equivalent to Swift .bigEndianBytes)
    pub fn getBigEndianBytes(comptime T: type, value: T) [@sizeOf(T)]u8 {
        return std.mem.toBytes(std.mem.nativeToBig(T, value));
    }

    /// Gets reversed bytes (equivalent to Swift reversed())
    pub fn getReversedBytes(comptime T: type, value: T, allocator: std.mem.Allocator) ![]u8 {
        const bytes = getBigEndianBytes(T, value);
        const result = try allocator.dupe(u8, &bytes);
        std.mem.reverse(u8, result);
        return result;
    }

    /// Creates value from bytes (equivalent to Swift from bytes)
    pub fn fromBytes(comptime T: type, bytes: []const u8, endian: std.builtin.Endian) !T {
        if (bytes.len != @sizeOf(T)) {
            return errors.ValidationError.InvalidParameter;
        }

        return switch (endian) {
            .little => std.mem.littleToNative(T, std.mem.bytesToValue(T, bytes[0..@sizeOf(T)])),
            .big => std.mem.bigToNative(T, std.mem.bytesToValue(T, bytes[0..@sizeOf(T)])),
        };
    }

    /// Converts between numeric types safely
    pub fn convertSafely(comptime From: type, comptime To: type, value: From) !To {
        return IntUtils.safeConvert(From, To, value);
    }
};

/// Decimal utilities (converted from Swift Decimal extensions)
pub const DecimalUtils = struct {
    /// Fixed-point decimal representation
    pub const FixedDecimal = struct {
        value: i64,
        scale: u8,

        const Self = @This();

        pub fn init(value: i64, scale: u8) Self {
            return Self{ .value = value, .scale = scale };
        }

        /// Gets scale (equivalent to Swift .scale property)
        pub fn getScale(self: Self) u8 {
            return self.scale;
        }

        /// Converts to float
        pub fn toFloat(self: Self) f64 {
            const divisor = std.math.pow(f64, 10.0, @floatFromInt(self.scale));
            return @as(f64, @floatFromInt(self.value)) / divisor;
        }

        /// Creates from float
        pub fn fromFloat(float_value: f64, scale: u8) Self {
            const multiplier = std.math.pow(f64, 10.0, @floatFromInt(scale));
            const scaled_value = @as(i64, @intFromFloat(float_value * multiplier));
            return Self.init(scaled_value, scale);
        }

        /// Formats as string
        pub fn toString(self: Self, allocator: std.mem.Allocator) ![]u8 {
            if (self.scale == 0) {
                return try std.fmt.allocPrint(allocator, "{d}", .{self.value});
            }

            const divisor = std.math.pow(i64, 10, self.scale);
            const integer_part = @divTrunc(self.value, divisor);
            const fractional_part = @rem(self.value, divisor);

            var digits = try allocator.alloc(u8, self.scale);
            defer allocator.free(digits);

            var remaining = @abs(fractional_part);
            var index: usize = self.scale;
            while (index > 0) {
                index -= 1;
                const digit: u8 = @intCast(remaining % 10);
                remaining /= 10;
                digits[index] = '0' + digit;
            }

            return try std.fmt.allocPrint(allocator, "{d}.{s}", .{ integer_part, digits });
        }

        /// Arithmetic operations
        pub fn add(self: Self, other: Self) !Self {
            if (self.scale != other.scale) {
                return errors.ValidationError.InvalidParameter;
            }

            const result_value = self.value + other.value;
            // Check for overflow
            if ((self.value > 0 and other.value > 0 and result_value < 0) or
                (self.value < 0 and other.value < 0 and result_value > 0))
            {
                return errors.ValidationError.ParameterOutOfRange;
            }

            return Self.init(result_value, self.scale);
        }

        pub fn subtract(self: Self, other: Self) !Self {
            if (self.scale != other.scale) {
                return errors.ValidationError.InvalidParameter;
            }

            const result_value = self.value - other.value;
            return Self.init(result_value, self.scale);
        }

        pub fn multiply(self: Self, multiplier: i64) !Self {
            const result_value = self.value * multiplier;
            // Check for overflow
            if (multiplier != 0 and @divTrunc(result_value, multiplier) != self.value) {
                return errors.ValidationError.ParameterOutOfRange;
            }

            return Self.init(result_value, self.scale);
        }

        pub fn divide(self: Self, divisor: i64) !Self {
            if (divisor == 0) {
                return errors.ValidationError.InvalidParameter;
            }

            return Self.init(@divTrunc(self.value, divisor), self.scale);
        }
    };

    /// Creates decimal from string
    pub fn fromString(decimal_str: []const u8, allocator: std.mem.Allocator) !FixedDecimal {
        const dot_index = std.mem.indexOf(u8, decimal_str, ".") orelse {
            // No decimal point - integer
            const int_value = try std.fmt.parseInt(i64, decimal_str, 10);
            return FixedDecimal.init(int_value, 0);
        };

        const integer_part = decimal_str[0..dot_index];
        const fractional_part = decimal_str[dot_index + 1 ..];

        const int_val = try std.fmt.parseInt(i64, integer_part, 10);
        const frac_val = try std.fmt.parseInt(i64, fractional_part, 10);
        const scale = @as(u8, @intCast(fractional_part.len));

        _ = allocator;
        const multiplier = std.math.pow(i64, 10, scale);
        const total_value = int_val * multiplier + frac_val;

        return FixedDecimal.init(total_value, scale);
    }
};

/// Bytes utilities (converted from Swift bytes operations)
pub const BytesUtils = struct {
    /// Pads bytes to specified length (equivalent to Swift toPadded)
    pub fn toPadded(bytes: []const u8, target_length: usize, allocator: std.mem.Allocator) ![]u8 {
        if (bytes.len >= target_length) {
            return try allocator.dupe(u8, bytes);
        }

        const result = try allocator.alloc(u8, target_length);
        const padding = target_length - bytes.len;

        @memset(result[0..padding], 0);
        @memcpy(result[padding..], bytes);

        return result;
    }

    /// Removes leading zeros (equivalent to Swift trimming)
    pub fn trimLeadingZeros(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var start: usize = 0;
        while (start < bytes.len and bytes[start] == 0) {
            start += 1;
        }

        if (start == bytes.len) {
            // All zeros - return single zero byte
            return try allocator.dupe(u8, &[_]u8{0});
        }

        return try allocator.dupe(u8, bytes[start..]);
    }

    /// Converts to hex string (equivalent to Swift hex conversion)
    pub fn toHexString(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return try BytesExt.toHexString(bytes, allocator);
    }
};

// Tests (converted from Swift Numeric tests)
test "IntUtils power and variable size operations" {
    const testing = std.testing;

    // Test power function (equivalent to Swift toPowerOf tests)
    try testing.expectEqual(@as(i64, 8), IntUtils.toPowerOf(2, 3)); // 2^3 = 8
    try testing.expectEqual(@as(i64, 100), IntUtils.toPowerOf(10, 2)); // 10^2 = 100
    try testing.expectEqual(@as(i64, 1), IntUtils.toPowerOf(5, 0)); // 5^0 = 1

    // Test variable size calculation (equivalent to Swift varSize tests)
    try testing.expectEqual(@as(usize, 1), IntUtils.varSize(100)); // < 0xFD
    try testing.expectEqual(@as(usize, 3), IntUtils.varSize(1000)); // <= 0xFFFF
    try testing.expectEqual(@as(usize, 5), IntUtils.varSize(100000)); // <= 0xFFFFFFFF
    try testing.expectEqual(@as(usize, 9), IntUtils.varSize(10000000000)); // > 0xFFFFFFFF

    // Test unsigned conversion
    try testing.expectEqual(@as(u32, 4294967295), IntUtils.toUnsigned(-1)); // -1 as unsigned
}

test "NumericUtils byte conversion operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test byte conversion (equivalent to Swift Numeric extensions tests)
    const test_value: u32 = 0x12345678;

    const little_endian_bytes = NumericUtils.getBytes(u32, test_value);
    const big_endian_bytes = NumericUtils.getBigEndianBytes(u32, test_value);

    // Verify byte order
    try testing.expectEqual(@as(u8, 0x78), little_endian_bytes[0]); // LSB first
    try testing.expectEqual(@as(u8, 0x12), big_endian_bytes[0]); // MSB first

    // Test reversed bytes
    const reversed_bytes = try NumericUtils.getReversedBytes(u32, test_value, allocator);
    defer allocator.free(reversed_bytes);

    try testing.expectEqual(@as(usize, 4), reversed_bytes.len);

    // Test round-trip conversion
    const from_little = try NumericUtils.fromBytes(u32, &little_endian_bytes, .little);
    const from_big = try NumericUtils.fromBytes(u32, &big_endian_bytes, .big);

    try testing.expectEqual(test_value, from_little);
    try testing.expectEqual(test_value, from_big);
}

test "DecimalUtils fixed-point operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test fixed decimal creation (equivalent to Swift Decimal tests)
    const decimal1 = DecimalUtils.FixedDecimal.fromFloat(1.23, 2);
    try testing.expectEqual(@as(i64, 123), decimal1.value);
    try testing.expectEqual(@as(u8, 2), decimal1.scale);

    const decimal2 = DecimalUtils.FixedDecimal.fromFloat(4.56, 2);

    // Test arithmetic operations
    const sum = try decimal1.add(decimal2);
    try testing.expect(sum.toFloat() > 0);

    const difference = try decimal2.subtract(decimal1);
    try testing.expect(difference.toFloat() > 0);

    const doubled = try decimal1.multiply(2);
    try testing.expect(doubled.toFloat() > 0);

    const halved = try decimal2.divide(2);
    try testing.expect(halved.toFloat() > 0);

    // Test string conversion
    const decimal_str = try decimal1.toString(allocator);
    defer allocator.free(decimal_str);
    try testing.expectEqualStrings("1.23", decimal_str);
}

test "DecimalUtils string parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test decimal parsing from string (equivalent to Swift string parsing tests)
    const decimal_from_string = try DecimalUtils.fromString("12.345", allocator);
    try testing.expectEqual(@as(i64, 12345), decimal_from_string.value);
    try testing.expectEqual(@as(u8, 3), decimal_from_string.scale);
    try testing.expectEqual(@as(f64, 12.345), decimal_from_string.toFloat());

    // Test integer parsing (no decimal point)
    const integer_from_string = try DecimalUtils.fromString("42", allocator);
    try testing.expectEqual(@as(i64, 42), integer_from_string.value);
    try testing.expectEqual(@as(u8, 0), integer_from_string.scale);
    try testing.expectEqual(@as(f64, 42.0), integer_from_string.toFloat());

    // Test zero parsing
    const zero_from_string = try DecimalUtils.fromString("0.00", allocator);
    try testing.expectEqual(@as(i64, 0), zero_from_string.value);
    try testing.expectEqual(@as(u8, 2), zero_from_string.scale);
}

test "BigIntUtils operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test big integer operations (equivalent to Swift BInt tests)
    const test_value: u256 = 0x123456789ABCDEF0;

    const magnitude_bytes = try BigIntUtils.asMagnitudeBytes(test_value, allocator);
    defer allocator.free(magnitude_bytes);

    try testing.expect(magnitude_bytes.len > 0);
    try testing.expect(magnitude_bytes[0] != 0); // Should not start with zero

    // Test padded bytes
    const padded_bytes = try BigIntUtils.toBytesPadded(test_value, 32, allocator);
    defer allocator.free(padded_bytes);

    try testing.expectEqual(@as(usize, 32), padded_bytes.len);

    // Test round-trip conversion
    const converted_back = BigIntUtils.fromBytes(magnitude_bytes);
    try testing.expectEqual(test_value, converted_back);
}

test "BytesUtils operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test byte padding (equivalent to Swift toPadded tests)
    const short_bytes = [_]u8{ 0x12, 0x34 };
    const padded = try BytesUtils.toPadded(&short_bytes, 5, allocator);
    defer allocator.free(padded);

    const expected_padded = [_]u8{ 0x00, 0x00, 0x00, 0x12, 0x34 };
    try testing.expectEqualSlices(u8, &expected_padded, padded);

    // Test leading zero trimming
    const bytes_with_zeros = [_]u8{ 0x00, 0x00, 0x12, 0x34 };
    const trimmed = try BytesUtils.trimLeadingZeros(&bytes_with_zeros, allocator);
    defer allocator.free(trimmed);

    const expected_trimmed = [_]u8{ 0x12, 0x34 };
    try testing.expectEqualSlices(u8, &expected_trimmed, trimmed);

    // Test all zeros
    const all_zeros = [_]u8{ 0x00, 0x00, 0x00 };
    const trimmed_zeros = try BytesUtils.trimLeadingZeros(&all_zeros, allocator);
    defer allocator.free(trimmed_zeros);

    try testing.expectEqual(@as(usize, 1), trimmed_zeros.len);
    try testing.expectEqual(@as(u8, 0), trimmed_zeros[0]);

    // Test hex string conversion
    const test_bytes = [_]u8{ 0xAB, 0xCD, 0xEF };
    const hex_string = try BytesUtils.toHexString(&test_bytes, allocator);
    defer allocator.free(hex_string);

    try testing.expectEqualStrings("abcdef", hex_string);
}
