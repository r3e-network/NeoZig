//! Scrypt Parameters Implementation
//!
//! Complete conversion from NeoSwift ScryptParams.swift
//! Provides scrypt algorithm parameters for NEP-2 encryption.

const std = @import("std");
const json_utils = @import("../utils/json_utils.zig");

/// Scrypt algorithm parameters (converted from Swift ScryptParams)
pub const ScryptParams = struct {
    /// Standard N parameter (cost factor)
    pub const N_STANDARD: u32 = 1 << 14; // 16384
    /// Standard r parameter (block size)
    pub const R_STANDARD: u32 = 8;
    /// Standard p parameter (parallelization factor)
    pub const P_STANDARD: u32 = 8;

    /// Cost factor (memory/time cost parameter)
    n: u32,
    /// Block size factor (affects memory usage)
    r: u32,
    /// Parallelization factor (affects memory usage)
    p: u32,

    const Self = @This();

    /// Creates new ScryptParams (equivalent to Swift init)
    pub fn init(n: u32, r: u32, p: u32) Self {
        return Self{
            .n = n,
            .r = r,
            .p = p,
        };
    }

    /// Creates default ScryptParams (equivalent to Swift DEFAULT)
    pub fn default() Self {
        return Self.init(N_STANDARD, R_STANDARD, P_STANDARD);
    }

    /// Creates ScryptParams for fast testing
    pub fn testParams() Self {
        return Self.init(1024, 1, 1); // Much faster for testing
    }

    /// Creates ScryptParams for light usage (faster but less secure)
    pub fn lightParams() Self {
        return Self.init(1 << 12, 4, 4); // 4096, 4, 4
    }

    /// Creates ScryptParams for strong security (slower but more secure)
    pub fn strongParams() Self {
        return Self.init(1 << 16, 16, 16); // 65536, 16, 16
    }

    /// Equality comparison (equivalent to Swift ==)
    pub fn eql(self: Self, other: Self) bool {
        return self.n == other.n and self.r == other.r and self.p == other.p;
    }

    /// Hash function (equivalent to Swift hash(into:))
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.n));
        hasher.update(std.mem.asBytes(&self.r));
        hasher.update(std.mem.asBytes(&self.p));
        return hasher.final();
    }

    /// Validates scrypt parameters
    pub fn validate(self: Self) !void {
        // N must be a power of 2 and > 1
        if (self.n <= 1 or (self.n & (self.n - 1)) != 0) {
            return error.InvalidScryptN;
        }

        // r must be > 0
        if (self.r == 0) {
            return error.InvalidScryptR;
        }

        // p must be > 0
        if (self.p == 0) {
            return error.InvalidScryptP;
        }

        // Check for potential overflow in memory calculation
        const max_memory = std.math.maxInt(u64) / 128;
        const required_memory: u64 = 128 * @as(u64, self.r) * self.n;
        if (required_memory > max_memory) {
            return error.ScryptMemoryTooLarge;
        }
    }

    /// Gets estimated memory usage in bytes
    pub fn estimateMemoryUsage(self: Self) u64 {
        return 128 * @as(u64, self.r) * self.n;
    }

    /// Gets estimated computation time factor (relative to default)
    pub fn estimateTimeFactor(self: Self) f64 {
        const default_ops = @as(f64, @floatFromInt(N_STANDARD)) * R_STANDARD * P_STANDARD;
        const our_ops = @as(f64, @floatFromInt(self.n)) * @as(f64, @floatFromInt(self.r)) * @as(f64, @floatFromInt(self.p));
        return our_ops / default_ops;
    }

    /// JSON encoding (equivalent to Swift Codable encode)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var json_obj = std.json.ObjectMap.init(allocator);
        defer json_obj.deinit();

        try json_utils.putOwnedKey(&json_obj, allocator, "n", std.json.Value{ .integer = @intCast(self.n) });
        try json_utils.putOwnedKey(&json_obj, allocator, "r", std.json.Value{ .integer = @intCast(self.r) });
        try json_utils.putOwnedKey(&json_obj, allocator, "p", std.json.Value{ .integer = @intCast(self.p) });

        const json_value = std.json.Value{ .object = json_obj };

        var json_string = ArrayList(u8).init(allocator);
        defer json_string.deinit();

        try std.json.stringify(json_value, .{}, json_string.writer());
        return try json_string.toOwnedSlice();
    }

    /// JSON decoding (equivalent to Swift Codable init(from:))
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        const json_obj = parsed.value.object;

        // Try different key names for compatibility (like Swift implementation)
        const n = blk: {
            if (json_obj.get("cost")) |value| break :blk @as(u32, @intCast(value.integer));
            if (json_obj.get("n")) |value| break :blk @as(u32, @intCast(value.integer));
            return error.MissingScryptN;
        };

        const r = blk: {
            if (json_obj.get("blockSize")) |value| break :blk @as(u32, @intCast(value.integer));
            if (json_obj.get("blocksize")) |value| break :blk @as(u32, @intCast(value.integer));
            if (json_obj.get("r")) |value| break :blk @as(u32, @intCast(value.integer));
            return error.MissingScryptR;
        };

        const p = blk: {
            if (json_obj.get("parallel")) |value| break :blk @as(u32, @intCast(value.integer));
            if (json_obj.get("p")) |value| break :blk @as(u32, @intCast(value.integer));
            return error.MissingScryptP;
        };

        const params = Self.init(n, r, p);
        try params.validate();
        return params;
    }

    /// Creates from NEP-2 JSON format
    pub fn fromNep2Json(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        return try Self.decodeFromJson(json_str, allocator);
    }

    /// Converts to NEP-2 JSON format
    pub fn toNep2Json(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try self.encodeToJson(allocator);
    }

    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "ScryptParams(n={}, r={}, p={}, memory={}KB, time_factor={d:.2})", .{ self.n, self.r, self.p, self.estimateMemoryUsage() / 1024, self.estimateTimeFactor() });
    }
};

// Tests (converted from Swift ScryptParams tests)
test "ScryptParams creation and properties" {
    const testing = std.testing;

    // Test default parameters (equivalent to Swift DEFAULT tests)
    const default_params = ScryptParams.default();
    try testing.expectEqual(@as(u32, ScryptParams.N_STANDARD), default_params.n);
    try testing.expectEqual(@as(u32, ScryptParams.R_STANDARD), default_params.r);
    try testing.expectEqual(@as(u32, ScryptParams.P_STANDARD), default_params.p);

    // Test custom parameters
    const custom_params = ScryptParams.init(1024, 4, 2);
    try testing.expectEqual(@as(u32, 1024), custom_params.n);
    try testing.expectEqual(@as(u32, 4), custom_params.r);
    try testing.expectEqual(@as(u32, 2), custom_params.p);

    // Test test parameters
    const test_params = ScryptParams.testParams();
    try testing.expect(test_params.n < ScryptParams.N_STANDARD); // Should be faster
}

test "ScryptParams equality and hashing" {
    const testing = std.testing;

    // Test equality (equivalent to Swift == tests)
    const params1 = ScryptParams.init(1024, 8, 8);
    const params2 = ScryptParams.init(1024, 8, 8);
    const params3 = ScryptParams.init(2048, 8, 8);

    try testing.expect(params1.eql(params2));
    try testing.expect(!params1.eql(params3));

    // Test hashing (equivalent to Swift hash(into:) tests)
    const hash1 = params1.hash();
    const hash2 = params2.hash();
    const hash3 = params3.hash();

    try testing.expectEqual(hash1, hash2); // Same params should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different params should have different hash
}

test "ScryptParams validation" {
    const testing = std.testing;

    // Test valid parameters
    const valid_params = ScryptParams.default();
    try valid_params.validate();

    // Test invalid N (not power of 2)
    const invalid_n = ScryptParams.init(1023, 8, 8);
    try testing.expectError(error.InvalidScryptN, invalid_n.validate());

    // Test invalid N (too small)
    const small_n = ScryptParams.init(1, 8, 8);
    try testing.expectError(error.InvalidScryptN, small_n.validate());

    // Test invalid r
    const invalid_r = ScryptParams.init(1024, 0, 8);
    try testing.expectError(error.InvalidScryptR, invalid_r.validate());

    // Test invalid p
    const invalid_p = ScryptParams.init(1024, 8, 0);
    try testing.expectError(error.InvalidScryptP, invalid_p.validate());
}

test "ScryptParams memory and time estimation" {
    const testing = std.testing;

    // Test memory estimation
    const params = ScryptParams.init(1024, 8, 1);
    const memory_usage = params.estimateMemoryUsage();
    const expected_memory = 128 * 8 * 1024; // 128 * r * n
    try testing.expectEqual(@as(u64, expected_memory), memory_usage);

    // Test time factor estimation
    const default_params = ScryptParams.default();
    const time_factor = default_params.estimateTimeFactor();
    try testing.expectApproxEqRel(time_factor, 1.0, 0.001); // Should be ~1.0 for default params

    const fast_params = ScryptParams.testParams();
    const fast_time = fast_params.estimateTimeFactor();
    try testing.expect(fast_time < 1.0); // Should be much faster
}

test "ScryptParams JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const original_params = ScryptParams.init(2048, 4, 2);

    const json_str = try original_params.encodeToJson(allocator);
    defer allocator.free(json_str);

    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "2048") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"n\"") != null);

    const decoded_params = try ScryptParams.decodeFromJson(json_str, allocator);
    try testing.expect(original_params.eql(decoded_params));
}

test "ScryptParams JSON compatibility" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test compatibility with different JSON key names (like Swift implementation)
    const cost_json = "{\"cost\": 1024, \"blockSize\": 8, \"parallel\": 1}";
    const params1 = try ScryptParams.decodeFromJson(cost_json, allocator);
    try testing.expectEqual(@as(u32, 1024), params1.n);
    try testing.expectEqual(@as(u32, 8), params1.r);
    try testing.expectEqual(@as(u32, 1), params1.p);

    const standard_json = "{\"n\": 1024, \"r\": 8, \"p\": 1}";
    const params2 = try ScryptParams.decodeFromJson(standard_json, allocator);
    try testing.expect(params1.eql(params2));

    // Test blocksize vs blockSize variants
    const blocksize_json = "{\"n\": 1024, \"blocksize\": 8, \"p\": 1}";
    const params3 = try ScryptParams.decodeFromJson(blocksize_json, allocator);
    try testing.expect(params1.eql(params3));
}

test "ScryptParams formatting" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test format display
    const params = ScryptParams.default();
    const formatted = try params.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "ScryptParams") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "n=16384") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "memory=") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "time_factor=") != null);
}
