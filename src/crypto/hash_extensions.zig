//! Hash Extensions
//!
//! Complete conversion from NeoSwift Hash.swift extensions
//! Provides all Swift hash utility methods for bytes and strings.

const std = @import("std");


const Hash256 = @import("../types/hash256.zig").Hash256;
const Hash160 = @import("../types/hash160.zig").Hash160;

/// Hash utilities for bytes (converted from Swift Bytes extensions)
pub const BytesHashUtils = struct {
    /// Double SHA-256 hash (equivalent to Swift .hash256())
    pub fn hash256(bytes: []const u8) Hash256 {
        const first_hash = Hash256.sha256(bytes);
        return Hash256.sha256(first_hash.toSlice());
    }
    
    /// RIPEMD160 hash (equivalent to Swift .ripemd160())
    pub fn ripemd160(bytes: []const u8) [20]u8 {
        const ripemd160_impl = @import("ripemd160.zig");
        return ripemd160_impl.ripemd160(bytes);
    }
    
    /// SHA256 then RIPEMD160 (equivalent to Swift .sha256ThenRipemd160())
    pub fn sha256ThenRipemd160(bytes: []const u8) [20]u8 {
        const sha_result = Hash256.sha256(bytes);
        return ripemd160(sha_result.toSlice());
    }
    
    /// HMAC-SHA512 (equivalent to Swift .hmacSha512(key:))
    pub fn hmacSha512(bytes: []const u8, key: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const block_size = 128; // SHA512 block size
        
        // Prepare key
        var actual_key: [block_size]u8 = undefined;
        if (key.len > block_size) {
            // Hash the key if too long
            var hasher = std.crypto.hash.sha2.Sha512.init(.{});
            hasher.update(key);
            var key_hash: [64]u8 = undefined;
            hasher.final(&key_hash);
            @memcpy(actual_key[0..64], &key_hash);
            @memset(actual_key[64..], 0);
        } else {
            @memcpy(actual_key[0..key.len], key);
            @memset(actual_key[key.len..], 0);
        }
        
        // Create i_pad and o_pad
        var i_pad: [block_size]u8 = undefined;
        var o_pad: [block_size]u8 = undefined;
        
        for (actual_key, 0..) |byte, i| {
            i_pad[i] = byte ^ 0x36;
            o_pad[i] = byte ^ 0x5C;
        }
        
        // Inner hash: SHA512(i_pad || message)
        var inner_hasher = std.crypto.hash.sha2.Sha512.init(.{});
        inner_hasher.update(&i_pad);
        inner_hasher.update(bytes);
        var inner_hash: [64]u8 = undefined;
        inner_hasher.final(&inner_hash);
        
        // Outer hash: SHA512(o_pad || inner_hash)
        var outer_hasher = std.crypto.hash.sha2.Sha512.init(.{});
        outer_hasher.update(&o_pad);
        outer_hasher.update(&inner_hash);
        var outer_hash: [64]u8 = undefined;
        outer_hasher.final(&outer_hash);
        
        return try allocator.dupe(u8, &outer_hash);
    }
    
    /// SHA-256 hash (utility method)
    pub fn sha256(bytes: []const u8) Hash256 {
        return Hash256.sha256(bytes);
    }
    
    /// Creates Hash160 from bytes (utility method)
    pub fn toHash160(bytes: []const u8) !Hash160 {
        if (bytes.len != 20) {
            return errors.ValidationError.InvalidHash;
        }
        
        var hash_bytes: [20]u8 = undefined;
        @memcpy(&hash_bytes, bytes);
        return Hash160.fromArray(hash_bytes);
    }
    
    /// Creates Hash256 from bytes (utility method)
    pub fn toHash256(bytes: []const u8) !Hash256 {
        if (bytes.len != 32) {
            return errors.ValidationError.InvalidHash;
        }
        
        var hash_bytes: [32]u8 = undefined;
        @memcpy(&hash_bytes, bytes);
        return Hash256.init(hash_bytes);
    }
};

/// Hash utilities for strings (converted from Swift String extensions)
pub const StringHashUtils = struct {
    /// Double SHA-256 hash for string (equivalent to Swift String.hash256())
    pub fn hash256(string: []const u8) Hash256 {
        return BytesHashUtils.hash256(string);
    }
    
    /// RIPEMD160 hash for string (equivalent to Swift String.ripemd160())
    pub fn ripemd160(string: []const u8) [20]u8 {
        return BytesHashUtils.ripemd160(string);
    }
    
    /// SHA256 then RIPEMD160 for string (equivalent to Swift String.sha256ThenRipemd160())
    pub fn sha256ThenRipemd160(string: []const u8) [20]u8 {
        return BytesHashUtils.sha256ThenRipemd160(string);
    }
    
    /// HMAC-SHA512 for string (equivalent to Swift String.hmacSha512(key:))
    pub fn hmacSha512(string: []const u8, key: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return try BytesHashUtils.hmacSha512(string, key, allocator);
    }
    
    /// SHA-256 hash for string (utility method)
    pub fn sha256(string: []const u8) Hash256 {
        return BytesHashUtils.sha256(string);
    }
    
    /// Creates address from string (utility method)
    pub fn stringToAddress(string: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const script_hash = sha256ThenRipemd160(string);
        return try BytesHashUtils.toHash160(&script_hash).?.toAddress(allocator);
    }
    
    /// Validates hash string format
    pub fn validateHashString(hash_string: []const u8, expected_length: usize) !void {
        const cleaned = @import("../utils/string_extensions.zig").StringUtils.cleanedHexPrefix(hash_string);
        
        if (cleaned.len != expected_length * 2) {
            return errors.ValidationError.InvalidHash;
        }
        
        for (cleaned) |char| {
            if (!std.ascii.isHex(char)) {
                return errors.ValidationError.InvalidHash;
            }
        }
    }
};

/// Hash computation utilities
pub const HashComputeUtils = struct {
    /// Computes all common hashes for data
    pub fn computeAllHashes(data: []const u8, allocator: std.mem.Allocator) !HashSet {
        const sha256_hash = BytesHashUtils.sha256(data);
        const double_sha256 = BytesHashUtils.hash256(data);
        const ripemd160_hash = BytesHashUtils.ripemd160(data);
        const sha256_then_ripemd = BytesHashUtils.sha256ThenRipemd160(data);
        
        return HashSet{
            .sha256 = sha256_hash,
            .double_sha256 = double_sha256,
            .ripemd160 = Hash160.fromArray(ripemd160_hash),
            .sha256_then_ripemd160 = Hash160.fromArray(sha256_then_ripemd),
        };
    }
    
    /// Verifies hash chain consistency
    pub fn verifyHashChain(original: []const u8, expected_hash: Hash256) bool {
        const computed = BytesHashUtils.sha256(original);
        return computed.eql(expected_hash);
    }
    
    /// Benchmarks hash operations
    pub fn benchmarkHashOperations(data: []const u8, iterations: u32) HashBenchmark {
        var timer = std.time.Timer.start() catch unreachable;
        
        // Benchmark SHA256
        timer.reset();
        var i: u32 = 0;
        while (i < iterations) : (i += 1) {
            _ = BytesHashUtils.sha256(data);
        }
        const sha256_time = timer.read();
        
        // Benchmark RIPEMD160
        timer.reset();
        i = 0;
        while (i < iterations) : (i += 1) {
            _ = BytesHashUtils.ripemd160(data);
        }
        const ripemd160_time = timer.read();
        
        // Benchmark double SHA256
        timer.reset();
        i = 0;
        while (i < iterations) : (i += 1) {
            _ = BytesHashUtils.hash256(data);
        }
        const double_sha256_time = timer.read();
        
        return HashBenchmark{
            .sha256_ns_per_op = sha256_time / iterations,
            .ripemd160_ns_per_op = ripemd160_time / iterations,
            .double_sha256_ns_per_op = double_sha256_time / iterations,
            .iterations = iterations,
        };
    }
};

/// Hash set structure
pub const HashSet = struct {
    sha256: Hash256,
    double_sha256: Hash256,
    ripemd160: Hash160,
    sha256_then_ripemd160: Hash160,
    
    pub fn eql(self: HashSet, other: HashSet) bool {
        return self.sha256.eql(other.sha256) and
               self.double_sha256.eql(other.double_sha256) and
               self.ripemd160.eql(other.ripemd160) and
               self.sha256_then_ripemd160.eql(other.sha256_then_ripemd160);
    }
};

/// Hash benchmark results
pub const HashBenchmark = struct {
    sha256_ns_per_op: u64,
    ripemd160_ns_per_op: u64,
    double_sha256_ns_per_op: u64,
    iterations: u32,
    
    pub fn printResults(self: HashBenchmark) void {
        std.log.info("Hash Benchmark Results ({d} iterations):", .{self.iterations});
        std.log.info("  SHA256: {d}ns per operation", .{self.sha256_ns_per_op});
        std.log.info("  RIPEMD160: {d}ns per operation", .{self.ripemd160_ns_per_op});
        std.log.info("  Double SHA256: {d}ns per operation", .{self.double_sha256_ns_per_op});
    }
};

// Tests (converted from Swift Hash extension tests)
test "BytesHashUtils hash operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const test_data = "Neo Zig SDK hash test data";
    
    // Test SHA256 (equivalent to Swift sha256 tests)
    const sha_hash = BytesHashUtils.sha256(test_data);
    try testing.expect(!sha_hash.isZero());
    
    // Test double SHA256 (equivalent to Swift hash256() tests)
    const double_sha = BytesHashUtils.hash256(test_data);
    try testing.expect(!double_sha.isZero());
    try testing.expect(!sha_hash.eql(double_sha)); // Should be different
    
    // Test RIPEMD160 (equivalent to Swift ripemd160() tests)
    const ripemd_hash = BytesHashUtils.ripemd160(test_data);
    try testing.expect(!std.mem.allEqual(u8, &ripemd_hash, 0));
    
    // Test SHA256 then RIPEMD160 (equivalent to Swift sha256ThenRipemd160() tests)
    const combined_hash = BytesHashUtils.sha256ThenRipemd160(test_data);
    try testing.expect(!std.mem.allEqual(u8, &combined_hash, 0));
    try testing.expect(!std.mem.eql(u8, &ripemd_hash, &combined_hash)); // Should be different
    
    // Test HMAC-SHA512 (equivalent to Swift hmacSha512 tests)
    const hmac_key = "test_hmac_key";
    const hmac_result = try BytesHashUtils.hmacSha512(test_data, hmac_key, allocator);
    defer allocator.free(hmac_result);
    
    try testing.expectEqual(@as(usize, 64), hmac_result.len); // SHA512 output is 64 bytes
    try testing.expect(!std.mem.allEqual(u8, hmac_result, 0));
}

test "StringHashUtils string hash operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const test_string = "Test string for hashing";
    
    // Test string hash operations (equivalent to Swift String hash tests)
    const string_sha = StringHashUtils.sha256(test_string);
    const bytes_sha = BytesHashUtils.sha256(test_string);
    
    try testing.expect(string_sha.eql(bytes_sha)); // Should be identical
    
    const string_double_sha = StringHashUtils.hash256(test_string);
    const bytes_double_sha = BytesHashUtils.hash256(test_string);
    
    try testing.expect(string_double_sha.eql(bytes_double_sha)); // Should be identical
    
    // Test string RIPEMD160
    const string_ripemd = StringHashUtils.ripemd160(test_string);
    const bytes_ripemd = BytesHashUtils.ripemd160(test_string);
    
    try testing.expectEqualSlices(u8, &string_ripemd, &bytes_ripemd);
    
    // Test string to address conversion
    const address = try StringHashUtils.stringToAddress(test_string, allocator);
    defer allocator.free(address);
    
    try testing.expect(address.len > 0);
}

test "HashComputeUtils comprehensive operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const test_data = "Comprehensive hash test data";
    
    // Test computing all hashes (utility function tests)
    const hash_set = try HashComputeUtils.computeAllHashes(test_data, allocator);
    
    try testing.expect(!hash_set.sha256.isZero());
    try testing.expect(!hash_set.double_sha256.isZero());
    try testing.expect(!hash_set.ripemd160.eql(Hash160.ZERO));
    try testing.expect(!hash_set.sha256_then_ripemd160.eql(Hash160.ZERO));
    
    // Verify relationships
    const manual_double_sha = BytesHashUtils.hash256(test_data);
    try testing.expect(hash_set.double_sha256.eql(manual_double_sha));
    
    const manual_combined = BytesHashUtils.sha256ThenRipemd160(test_data);
    try testing.expect(hash_set.sha256_then_ripemd160.eql(Hash160.fromArray(manual_combined)));
    
    // Test hash chain verification
    const original_data = "Original data for verification";
    const expected_hash = BytesHashUtils.sha256(original_data);
    
    try testing.expect(HashComputeUtils.verifyHashChain(original_data, expected_hash));
    
    const wrong_hash = Hash256.ZERO;
    try testing.expect(!HashComputeUtils.verifyHashChain(original_data, wrong_hash));
}

test "Hash validation operations" {
    const testing = std.testing;
    
    // Test hash string validation (equivalent to Swift validation tests)
    try StringHashUtils.validateHashString("1234567890abcdef1234567890abcdef12345678", 20); // Valid Hash160
    try StringHashUtils.validateHashString("0x1234567890abcdef1234567890abcdef12345678", 20); // With prefix
    
    try testing.expectError(
        errors.ValidationError.InvalidHash,
        StringHashUtils.validateHashString("invalid", 20)
    );
    
    try testing.expectError(
        errors.ValidationError.InvalidHash,
        StringHashUtils.validateHashString("1234567890abcdef", 20) // Too short
    );
    
    try testing.expectError(
        errors.ValidationError.InvalidHash,
        StringHashUtils.validateHashString("1234567890abcdef1234567890abcdef123456789abcdef", 20) // Too long
    );
}

test "Hash consistency verification" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test that hash operations are consistent (equivalent to Swift consistency tests)
    const test_data = "Consistency test data";
    
    // Multiple calls should produce same results
    const hash1 = BytesHashUtils.sha256(test_data);
    const hash2 = BytesHashUtils.sha256(test_data);
    try testing.expect(hash1.eql(hash2));
    
    const ripemd1 = BytesHashUtils.ripemd160(test_data);
    const ripemd2 = BytesHashUtils.ripemd160(test_data);
    try testing.expectEqualSlices(u8, &ripemd1, &ripemd2);
    
    const double_sha1 = BytesHashUtils.hash256(test_data);
    const double_sha2 = BytesHashUtils.hash256(test_data);
    try testing.expect(double_sha1.eql(double_sha2));
    
    // HMAC should be consistent with same key
    const hmac_key = "consistent_key";
    const hmac1 = try BytesHashUtils.hmacSha512(test_data, hmac_key, allocator);
    defer allocator.free(hmac1);
    
    const hmac2 = try BytesHashUtils.hmacSha512(test_data, hmac_key, allocator);
    defer allocator.free(hmac2);
    
    try testing.expectEqualSlices(u8, hmac1, hmac2);
}

test "Hash performance benchmarking" {
    const testing = std.testing;
    
    // Test hash performance benchmarking
    const test_data = "Performance test data for hash benchmarking";
    const benchmark = HashComputeUtils.benchmarkHashOperations(test_data, 100);
    
    try testing.expectEqual(@as(u32, 100), benchmark.iterations);
    try testing.expect(benchmark.sha256_ns_per_op > 0);
    try testing.expect(benchmark.ripemd160_ns_per_op > 0);
    try testing.expect(benchmark.double_sha256_ns_per_op > 0);
    
    // Performance should be reasonable (under 10ms per operation)
    try testing.expect(benchmark.sha256_ns_per_op < 10_000_000); // 10ms
    try testing.expect(benchmark.ripemd160_ns_per_op < 10_000_000);
    try testing.expect(benchmark.double_sha256_ns_per_op < 20_000_000); // 20ms for double
    
    // Print results for verification
    benchmark.printResults();
}
