//! Neo Witness Implementation
//!
//! Complete conversion from NeoSwift NeoWitness.swift
//! Provides Neo witness representation for protocol responses.

const std = @import("std");


const base64 = std.base64;

/// Neo witness for protocol responses (converted from Swift NeoWitness)
pub const NeoWitness = struct {
    /// Invocation script (base64 encoded)
    invocation: []const u8,
    /// Verification script (base64 encoded)
    verification: []const u8,
    
    const Self = @This();
    const Witness = @import("../../transaction/witness.zig").Witness;
    
    /// Creates new NeoWitness (equivalent to Swift init(_ invocation: String, _ verification: String))
    pub fn init(invocation: []const u8, verification: []const u8) Self {
        return Self{
            .invocation = invocation,
            .verification = verification,
        };
    }
    
    /// Creates NeoWitness from Witness (equivalent to Swift init(_ witness: Witness))
    pub fn initFromWitness(witness: Witness, allocator: std.mem.Allocator) !Self {
        const invocation_script = witness.getInvocationScript();
        const verification_script = witness.getVerificationScript();
        
        // Encode scripts as base64
        const invocation_b64 = try base64Encode(invocation_script, allocator);
        const verification_b64 = try base64Encode(verification_script, allocator);
        
        return Self{
            .invocation = invocation_b64,
            .verification = verification_b64,
        };
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.invocation, other.invocation) and
               std.mem.eql(u8, self.verification, other.verification);
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.invocation);
        hasher.update(self.verification);
        return hasher.final();
    }
    
    /// Converts to Witness (utility method)
    pub fn toWitness(self: Self, allocator: std.mem.Allocator) !Witness {
        const invocation_bytes = try base64Decode(self.invocation, allocator);
        defer allocator.free(invocation_bytes);
        
        const verification_bytes = try base64Decode(self.verification, allocator);
        defer allocator.free(verification_bytes);
        
        return try Witness.init(invocation_bytes, verification_bytes, allocator);
    }
    
    /// Gets invocation script as bytes
    pub fn getInvocationBytes(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try base64Decode(self.invocation, allocator);
    }
    
    /// Gets verification script as bytes
    pub fn getVerificationBytes(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try base64Decode(self.verification, allocator);
    }
    
    /// Validates witness format
    pub fn validate(self: Self) !void {
        if (self.invocation.len == 0 and self.verification.len == 0) {
            return error.EmptyWitness;
        }
        
        // Basic base64 validation
        if (!isValidBase64(self.invocation) or !isValidBase64(self.verification)) {
            return error.InvalidBase64Format;
        }
    }
    
    /// Checks if witness is empty
    pub fn isEmpty(self: Self) bool {
        return self.invocation.len == 0 and self.verification.len == 0;
    }
    
    /// Checks if witness has invocation script
    pub fn hasInvocationScript(self: Self) bool {
        return self.invocation.len > 0;
    }
    
    /// Checks if witness has verification script
    pub fn hasVerificationScript(self: Self) bool {
        return self.verification.len > 0;
    }
    
    /// Gets estimated size in bytes
    pub fn getEstimatedSize(self: Self) usize {
        // Estimate decoded size (base64 is ~4/3 the size of original)
        const invocation_size = (self.invocation.len * 3) / 4;
        const verification_size = (self.verification.len * 3) / 4;
        return invocation_size + verification_size;
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "{{\"invocation\":\"{s}\",\"verification\":\"{s}\"}}",
            .{ self.invocation, self.verification }
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const invocation_str = json_obj.get("invocation").?.string;
        const verification_str = json_obj.get("verification").?.string;
        
        const invocation = try allocator.dupe(u8, invocation_str);
        const verification = try allocator.dupe(u8, verification_str);
        
        return Self.init(invocation, verification);
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.invocation);
        allocator.free(self.verification);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const invocation_copy = try allocator.dupe(u8, self.invocation);
        const verification_copy = try allocator.dupe(u8, self.verification);
        return Self.init(invocation_copy, verification_copy);
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const inv_size = (self.invocation.len * 3) / 4;
        const ver_size = (self.verification.len * 3) / 4;
        
        return try std.fmt.allocPrint(
            allocator,
            "NeoWitness(invocation: {} bytes, verification: {} bytes)",
            .{ inv_size, ver_size }
        );
    }
};

/// Helper functions for base64 operations
fn base64Encode(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const encoder = base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    return encoder.encode(encoded, data);
}

fn base64Decode(encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const decoder = base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, encoded);
    return decoded;
}

fn isValidBase64(data: []const u8) bool {
    if (data.len == 0) return true; // Empty is valid
    
    if (data.len % 4 != 0) return false; // Must be multiple of 4
    
    for (data) |char| {
        if (!base64.standard.Decoder.isValidChar(char) and char != '=') {
            return false;
        }
    }
    
    return true;
}

// Tests (converted from Swift NeoWitness tests)
test "NeoWitness creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;
    
    // Test witness creation (equivalent to Swift init tests)
    const invocation_b64 = "SGVsbG8gV29ybGQ="; // "Hello World" in base64
    const verification_b64 = "VGVzdCBTY3JpcHQ="; // "Test Script" in base64
    
    const witness = NeoWitness.init(invocation_b64, verification_b64);
    
    try testing.expectEqualStrings(invocation_b64, witness.invocation);
    try testing.expectEqualStrings(verification_b64, witness.verification);
    
    // Test validation
    try witness.validate();
    try testing.expect(!witness.isEmpty());
    try testing.expect(witness.hasInvocationScript());
    try testing.expect(witness.hasVerificationScript());
}

test "NeoWitness equality and hashing" {
    const testing = std.testing;
    
    // Test equality (equivalent to Swift Hashable tests)
    const witness1 = NeoWitness.init("dGVzdDE=", "dGVzdDI=");
    const witness2 = NeoWitness.init("dGVzdDE=", "dGVzdDI=");
    const witness3 = NeoWitness.init("dGVzdDE=", "dGVzdDM=");
    
    try testing.expect(witness1.eql(witness2));
    try testing.expect(!witness1.eql(witness3));
    
    // Test hashing
    const hash1 = witness1.hash();
    const hash2 = witness2.hash();
    const hash3 = witness3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same witnesses should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different witnesses should have different hash
}

test "NeoWitness validation" {
    const testing = std.testing;
    
    // Test valid witness
    const valid_witness = NeoWitness.init("dGVzdA==", "dGVzdA==");
    try valid_witness.validate();
    
    // Test empty witness
    const empty_witness = NeoWitness.init("", "");
    try testing.expectError(error.EmptyWitness, empty_witness.validate());
    
    // Test invalid base64
    const invalid_witness = NeoWitness.init("invalid!base64", "valid_base64==");
    try testing.expectError(error.InvalidBase64Format, invalid_witness.validate());
}

test "NeoWitness base64 operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test getting bytes from base64
    const invocation_b64 = "SGVsbG8="; // "Hello" in base64
    const verification_b64 = "V29ybGQ="; // "World" in base64
    
    const witness = NeoWitness.init(invocation_b64, verification_b64);
    
    const invocation_bytes = try witness.getInvocationBytes(allocator);
    defer allocator.free(invocation_bytes);
    
    const verification_bytes = try witness.getVerificationBytes(allocator);
    defer allocator.free(verification_bytes);
    
    try testing.expectEqualStrings("Hello", invocation_bytes);
    try testing.expectEqualStrings("World", verification_bytes);
    
    // Test estimated size
    const estimated_size = witness.getEstimatedSize();
    try testing.expectEqual(@as(usize, 10), estimated_size); // "Hello" + "World" = 10 bytes
}

test "NeoWitness JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const original_witness = NeoWitness.init("dGVzdDE=", "dGVzdDI=");
    
    const json_str = try original_witness.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "invocation") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "verification") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "dGVzdDE=") != null);
    
    var decoded_witness = try NeoWitness.decodeFromJson(json_str, allocator);
    defer decoded_witness.deinit(allocator);
    
    try testing.expect(original_witness.eql(decoded_witness));
}

test "NeoWitness utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test formatting
    const witness = NeoWitness.init("dGVzdDE=", "dGVzdDI=");
    
    const formatted = try witness.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "NeoWitness") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "bytes") != null);
    
    // Test cloning
    var cloned_witness = try witness.clone(allocator);
    defer cloned_witness.deinit(allocator);
    
    try testing.expect(witness.eql(cloned_witness));
    
    // Test empty checks
    const empty_witness = NeoWitness.init("", "");
    try testing.expect(empty_witness.isEmpty());
    try testing.expect(!empty_witness.hasInvocationScript());
    try testing.expect(!empty_witness.hasVerificationScript());
    
    const partial_witness = NeoWitness.init("dGVzdA==", "");
    try testing.expect(!partial_witness.isEmpty());
    try testing.expect(partial_witness.hasInvocationScript());
    try testing.expect(!partial_witness.hasVerificationScript());
}
