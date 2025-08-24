//! Witness Implementation
//!
//! Complete conversion from NeoSwift Witness.swift
//! Provides witness (invocation and verification scripts) for transaction validation.

const std = @import("std");
const ECKeyPair = @import("../crypto/ec_key_pair.zig").ECKeyPair;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const SignatureData = @import("../crypto/sign.zig").SignatureData;

/// Invocation script wrapper
pub const InvocationScript = struct {
    script: []const u8,
    
    const Self = @This();
    
    /// Creates empty invocation script
    pub fn init() Self {
        return Self{ .script = "" };
    }
    
    /// Creates invocation script from bytes
    pub fn initWithBytes(bytes: []const u8) Self {
        return Self{ .script = bytes };
    }
    
    /// Creates invocation script from message and key pair (equivalent to Swift fromMessageAndKeyPair)
    pub fn fromMessageAndKeyPair(message: []const u8, key_pair: ECKeyPair, allocator: std.mem.Allocator) !Self {
        const signature = try key_pair.signMessage(message, allocator);
        defer signature.deinit(allocator);
        
        // Create invocation script with signature
        var script_builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
        defer script_builder.deinit();
        
        _ = try script_builder.pushData(signature.toBytes());
        
        const script = script_builder.toScript();
        return Self{ .script = try allocator.dupe(u8, script) };
    }
    
    /// Creates multi-sig invocation script from signatures
    pub fn fromSignatures(signatures: []const SignatureData, allocator: std.mem.Allocator) !Self {
        var script_builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
        defer script_builder.deinit();
        
        // Push null first for multi-sig
        _ = try script_builder.pushData(&[_]u8{});
        
        // Push signatures in order
        for (signatures) |signature| {
            const sig_bytes = signature.toBytes();
            _ = try script_builder.pushData(sig_bytes);
        }
        
        const script = script_builder.toScript();
        return Self{ .script = try allocator.dupe(u8, script) };
    }
    
    /// Gets script bytes
    pub fn getScript(self: Self) []const u8 {
        return self.script;
    }
    
    /// Checks if script is empty
    pub fn isEmpty(self: Self) bool {
        return self.script.len == 0;
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
    }
};

/// Verification script wrapper
pub const VerificationScript = struct {
    script: []const u8,
    
    const Self = @This();
    
    /// Creates empty verification script
    pub fn init() Self {
        return Self{ .script = "" };
    }
    
    /// Creates verification script from bytes
    pub fn initWithBytes(bytes: []const u8) Self {
        return Self{ .script = bytes };
    }
    
    /// Creates verification script from public key (equivalent to Swift init(_ publicKey:))
    pub fn fromPublicKey(public_key: PublicKey, allocator: std.mem.Allocator) !Self {
        var script_builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
        defer script_builder.deinit();
        
        // Push public key
        _ = try script_builder.pushData(public_key.toSlice());
        
        // Add CHECKSIG opcode
        _ = try script_builder.sysCall(.SystemCryptoCheckSig);
        
        const script = script_builder.toScript();
        return Self{ .script = try allocator.dupe(u8, script) };
    }
    
    /// Creates multi-sig verification script (equivalent to Swift init(_ publicKeys:, _ signingThreshold:))
    pub fn fromMultiSig(public_keys: []const PublicKey, signing_threshold: u32, allocator: std.mem.Allocator) !Self {
        var script_builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
        defer script_builder.deinit();
        
        // Push signing threshold
        _ = try script_builder.pushInteger(@intCast(signing_threshold));
        
        // Push public keys (should be sorted)
        for (public_keys) |pub_key| {
            _ = try script_builder.pushData(pub_key.toSlice());
        }
        
        // Push number of public keys
        _ = try script_builder.pushInteger(@intCast(public_keys.len));
        
        // Add CHECKMULTISIG opcode
        _ = try script_builder.sysCall(.SystemCryptoCheckMultisig);
        
        const script = script_builder.toScript();
        return Self{ .script = try allocator.dupe(u8, script) };
    }
    
    /// Gets script bytes
    pub fn getScript(self: Self) []const u8 {
        return self.script;
    }
    
    /// Checks if script is empty
    pub fn isEmpty(self: Self) bool {
        return self.script.len == 0;
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
    }
};

/// Witness structure (converted from Swift Witness)
pub const Witness = struct {
    invocation_script: InvocationScript,
    verification_script: VerificationScript,
    
    const Self = @This();
    
    /// Creates empty witness (equivalent to Swift init())
    pub fn init() Self {
        return Self{
            .invocation_script = InvocationScript.init(),
            .verification_script = VerificationScript.init(),
        };
    }
    
    /// Creates witness from bytes (equivalent to Swift init(_ invocationScript: Bytes, _ verificationScript: Bytes))
    pub fn initWithBytes(invocation_bytes: []const u8, verification_bytes: []const u8, allocator: std.mem.Allocator) !Self {
        return Self{
            .invocation_script = InvocationScript{ .script = try allocator.dupe(u8, invocation_bytes) },
            .verification_script = VerificationScript{ .script = try allocator.dupe(u8, verification_bytes) },
        };
    }
    
    /// Creates witness from scripts (equivalent to Swift init(_ invocationScript: InvocationScript, _ verificationScript: VerificationScript))
    pub fn initWithScripts(invocation_script: InvocationScript, verification_script: VerificationScript) Self {
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
        };
    }
    
    /// Creates witness from message and key pair (equivalent to Swift create(_ messageToSign:, _ keyPair:))
    pub fn create(message_to_sign: []const u8, key_pair: ECKeyPair, allocator: std.mem.Allocator) !Self {
        const invocation_script = try InvocationScript.fromMessageAndKeyPair(message_to_sign, key_pair, allocator);
        const verification_script = try VerificationScript.fromPublicKey(key_pair.getPublicKey(), allocator);
        
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
        };
    }
    
    /// Creates multi-sig witness (equivalent to Swift creatMultiSigWitness)
    pub fn createMultiSigWitness(
        signing_threshold: u32,
        signatures: []const SignatureData,
        public_keys: []const PublicKey,
        allocator: std.mem.Allocator,
    ) !Self {
        const invocation_script = try InvocationScript.fromSignatures(signatures, allocator);
        const verification_script = try VerificationScript.fromMultiSig(public_keys, signing_threshold, allocator);
        
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
        };
    }
    
    /// Creates multi-sig witness with verification script (equivalent to Swift creatMultiSigWitness(_ signatures:, _ verificationScript:))
    pub fn createMultiSigWitnessWithScript(
        signatures: []const SignatureData,
        verification_script: VerificationScript,
        allocator: std.mem.Allocator,
    ) !Self {
        const invocation_script = try InvocationScript.fromSignatures(signatures, allocator);
        
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
        };
    }
    
    /// Gets invocation script
    pub fn getInvocationScript(self: Self) []const u8 {
        return self.invocation_script.getScript();
    }
    
    /// Gets verification script
    pub fn getVerificationScript(self: Self) []const u8 {
        return self.verification_script.getScript();
    }
    
    /// Checks if witness is empty
    pub fn isEmpty(self: Self) bool {
        return self.invocation_script.isEmpty() and self.verification_script.isEmpty();
    }
    
    /// Gets witness size in bytes
    pub fn getSize(self: Self) usize {
        return self.invocation_script.script.len + self.verification_script.script.len + 2; // +2 for length prefixes
    }
    
    /// Validates witness format
    pub fn validate(self: Self) !void {
        if (self.isEmpty()) {
            return; // Empty witness is valid
        }
        
        if (self.invocation_script.isEmpty() and !self.verification_script.isEmpty()) {
            return error.InvalidWitness; // Should have both or neither
        }
        
        if (!self.invocation_script.isEmpty() and self.verification_script.isEmpty()) {
            return error.InvalidWitness; // Should have both or neither
        }
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.invocation_script.script, other.invocation_script.script) and
               std.mem.eql(u8, self.verification_script.script, other.verification_script.script);
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.invocation_script.script);
        hasher.update(self.verification_script.script);
        return hasher.final();
    }
    
    /// Serializes witness to bytes
    pub fn serialize(self: Self, writer: *@import("../serialization/binary_writer_complete.zig").CompleteBinaryWriter) !void {
        // Write invocation script
        try writer.writeVarBytes(self.invocation_script.script);
        
        // Write verification script
        try writer.writeVarBytes(self.verification_script.script);
    }
    
    /// Deserializes witness from bytes
    pub fn deserialize(reader: *@import("../serialization/binary_reader_complete.zig").CompleteBinaryReader, allocator: std.mem.Allocator) !Self {
        // Read invocation script
        const invocation_bytes = try reader.readVarBytes(1024, allocator); // Max reasonable size
        const invocation_script = InvocationScript{ .script = invocation_bytes };
        
        // Read verification script
        const verification_bytes = try reader.readVarBytes(1024, allocator); // Max reasonable size
        const verification_script = VerificationScript{ .script = verification_bytes };
        
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
        };
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.invocation_script.deinit(allocator);
        self.verification_script.deinit(allocator);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        return Self{
            .invocation_script = InvocationScript{ .script = try allocator.dupe(u8, self.invocation_script.script) },
            .verification_script = VerificationScript{ .script = try allocator.dupe(u8, self.verification_script.script) },
        };
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "Witness(invocation: {} bytes, verification: {} bytes, total: {} bytes)",
            .{ self.invocation_script.script.len, self.verification_script.script.len, self.getSize() }
        );
    }
};

// Tests (converted from Swift Witness tests)
test "Witness creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test empty witness creation (equivalent to Swift init() tests)
    const empty_witness = Witness.init();
    try testing.expect(empty_witness.isEmpty());
    try empty_witness.validate();
    
    // Test witness from bytes
    const invocation_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const verification_bytes = [_]u8{ 0x04, 0x05, 0x06 };
    
    var witness_from_bytes = try Witness.initWithBytes(&invocation_bytes, &verification_bytes, allocator);
    defer witness_from_bytes.deinit(allocator);
    
    try testing.expect(!witness_from_bytes.isEmpty());
    try testing.expectEqualSlices(u8, &invocation_bytes, witness_from_bytes.getInvocationScript());
    try testing.expectEqualSlices(u8, &verification_bytes, witness_from_bytes.getVerificationScript());
    
    // Test size calculation
    const expected_size = invocation_bytes.len + verification_bytes.len + 2; // +2 for length prefixes
    try testing.expectEqual(expected_size, witness_from_bytes.getSize());
}

test "Witness equality and hashing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test equality (equivalent to Swift Hashable tests)
    const invocation1 = [_]u8{ 0x01, 0x02 };
    const verification1 = [_]u8{ 0x03, 0x04 };
    
    var witness1 = try Witness.initWithBytes(&invocation1, &verification1, allocator);
    defer witness1.deinit(allocator);
    
    var witness2 = try Witness.initWithBytes(&invocation1, &verification1, allocator);
    defer witness2.deinit(allocator);
    
    const invocation3 = [_]u8{ 0x05, 0x06 };
    var witness3 = try Witness.initWithBytes(&invocation3, &verification1, allocator);
    defer witness3.deinit(allocator);
    
    try testing.expect(witness1.eql(witness2));
    try testing.expect(!witness1.eql(witness3));
    
    // Test hashing
    const hash1 = witness1.hash();
    const hash2 = witness2.hash();
    const hash3 = witness3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same witnesses should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different witnesses should have different hash
}

test "Witness validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test valid witness
    const invocation = [_]u8{ 0x01, 0x02 };
    const verification = [_]u8{ 0x03, 0x04 };
    
    var valid_witness = try Witness.initWithBytes(&invocation, &verification, allocator);
    defer valid_witness.deinit(allocator);
    
    try valid_witness.validate();
    
    // Test empty witness (should be valid)
    const empty_witness = Witness.init();
    try empty_witness.validate();
}

test "Witness utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test formatting
    const invocation = [_]u8{ 0x01, 0x02, 0x03 };
    const verification = [_]u8{ 0x04, 0x05 };
    
    var witness = try Witness.initWithBytes(&invocation, &verification, allocator);
    defer witness.deinit(allocator);
    
    const formatted = try witness.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "Witness") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "3 bytes") != null); // invocation size
    try testing.expect(std.mem.indexOf(u8, formatted, "2 bytes") != null); // verification size
    
    // Test cloning
    var cloned_witness = try witness.clone(allocator);
    defer cloned_witness.deinit(allocator);
    
    try testing.expect(witness.eql(cloned_witness));
    try testing.expectEqualSlices(u8, witness.getInvocationScript(), cloned_witness.getInvocationScript());
    try testing.expectEqualSlices(u8, witness.getVerificationScript(), cloned_witness.getVerificationScript());
}