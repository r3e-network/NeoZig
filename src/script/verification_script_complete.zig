//! Complete Verification Script implementation
//!
//! Complete conversion from NeoSwift VerificationScript.swift
//! Provides comprehensive verification script functionality for witnesses.

const std = @import("std");


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const ScriptBuilder = @import("script_builder.zig").ScriptBuilder;
const BinaryWriter = @import("../serialization/binary_writer_complete.zig").CompleteBinaryWriter;
const BinaryReader = @import("../serialization/binary_reader_complete.zig").CompleteBinaryReader;

/// Complete verification script (converted from Swift VerificationScript)
pub const CompleteVerificationScript = struct {
    /// Verification script as byte array
    script: []const u8,
    /// Cached script hash
    script_hash: ?Hash160,
    /// Signing threshold for multi-sig (null for single-sig)
    signing_threshold: ?u32,
    /// Public keys (null for non-standard scripts)
    public_keys: ?[]const PublicKey,
    
    allocator: ?std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates empty verification script (equivalent to Swift init())
    pub fn init() Self {
        return Self{
            .script = &[_]u8{},
            .script_hash = null,
            .signing_threshold = null,
            .public_keys = null,
            .allocator = null,
        };
    }
    
    /// Creates verification script from bytes (equivalent to Swift init(_ script: Bytes))
    pub fn initFromBytes(script_bytes: []const u8, allocator: std.mem.Allocator) !Self {
        const script_copy = try allocator.dupe(u8, script_bytes);
        const hash = Hash160.fromScript(script_copy) catch null;
        
        return Self{
            .script = script_copy,
            .script_hash = hash,
            .signing_threshold = null,
            .public_keys = null,
            .allocator = allocator,
        };
    }
    
    /// Creates verification script for public key (equivalent to Swift init(_ publicKey: ECPublicKey))
    pub fn initFromPublicKey(public_key: PublicKey, allocator: std.mem.Allocator) !Self {
        // Avoid returning a slice referencing a temporary `PublicKey` created by
        // `toCompressed()`.
        var compressed_pub_key = public_key;
        if (!compressed_pub_key.compressed) {
            compressed_pub_key = try compressed_pub_key.toCompressed();
        }
        
        const script = try ScriptBuilder.buildVerificationScript(compressed_pub_key.toSlice(), allocator);
        const hash = try Hash160.fromScript(script);
        
        const public_keys = try allocator.dupe(PublicKey, &[_]PublicKey{public_key});
        
        return Self{
            .script = script,
            .script_hash = hash,
            .signing_threshold = 1,
            .public_keys = public_keys,
            .allocator = allocator,
        };
    }
    
    /// Creates multi-sig verification script (equivalent to Swift init(_ publicKeys: [ECPublicKey], _ signingThreshold: Int))
    pub fn initFromPublicKeys(
        public_keys: []const PublicKey,
        signing_threshold: u32,
        allocator: std.mem.Allocator,
    ) !Self {
        // Validate parameters (equivalent to Swift validation)
        if (signing_threshold < 1 or signing_threshold > public_keys.len) {
            return errors.throwIllegalArgument("Signing threshold must be at least 1 and not higher than number of keys");
        }
        
        if (public_keys.len > constants.MAX_PUBLIC_KEYS_PER_MULTISIG_ACCOUNT) {
            return errors.throwIllegalArgument("Too many public keys for multi-sig account");
        }
        
        // Convert public keys to compressed bytes for script building.
        // NOTE: We must ensure any slices passed to `buildMultiSigVerificationScript`
        // remain valid for the duration of the call. In particular, avoid slices
        // referencing a temporary `PublicKey` returned from `toCompressed()`.
        var compressed_keys = try allocator.alloc([constants.PUBLIC_KEY_SIZE_COMPRESSED]u8, public_keys.len);
        defer allocator.free(compressed_keys);

        var key_bytes = try allocator.alloc([]const u8, public_keys.len);
        defer allocator.free(key_bytes);

        for (public_keys, 0..) |pub_key, i| {
            if (pub_key.compressed) {
                const slice = pub_key.toSlice();
                if (slice.len != constants.PUBLIC_KEY_SIZE_COMPRESSED) {
                    return errors.CryptoError.InvalidKey;
                }
                @memcpy(compressed_keys[i][0..], slice);
            } else {
                var compressed = try pub_key.toCompressed();
                @memcpy(compressed_keys[i][0..], compressed.toSlice());
            }
            key_bytes[i] = compressed_keys[i][0..];
        }
        
        const script = try ScriptBuilder.buildMultiSigVerificationScript(key_bytes, signing_threshold, allocator);
        const hash = try Hash160.fromScript(script);
        
        return Self{
            .script = script,
            .script_hash = hash,
            .signing_threshold = signing_threshold,
            .public_keys = try allocator.dupe(PublicKey, public_keys),
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        if (self.allocator) |alloc| {
            alloc.free(self.script);
            if (self.public_keys) |keys| {
                alloc.free(keys);
            }
        }
    }
    
    /// Gets script size (equivalent to Swift .size property)
    pub fn getSize(self: Self) usize {
        return @import("../utils/bytes_extensions.zig").BytesUtils.varSize(self.script);
    }
    
    /// Gets script hash (equivalent to Swift .scriptHash property)
    pub fn getScriptHash(self: Self) ?Hash160 {
        return self.script_hash;
    }
    
    /// Gets signing threshold (equivalent to Swift getSigningThreshold())
    pub fn getSigningThreshold(self: Self) !u32 {
        return self.signing_threshold orelse errors.ValidationError.InvalidParameter;
    }
    
    /// Gets public keys (utility method)
    pub fn getPublicKeys(self: Self) ?[]const PublicKey {
        return self.public_keys;
    }
    
    /// Gets script bytes
    pub fn getScript(self: Self) []const u8 {
        return self.script;
    }
    
    /// Checks if script is empty
    pub fn isEmpty(self: Self) bool {
        return self.script.len == 0;
    }
    
    /// Checks if script is multi-signature
    pub fn isMultiSig(self: Self) bool {
        return self.signing_threshold != null and self.signing_threshold.? > 1;
    }
    
    /// Serializes verification script (equivalent to Swift serialize)
    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try writer.writeVarBytes(self.script);
    }
    
    /// Deserializes verification script (equivalent to Swift deserialize)
    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        const script_bytes = try reader.readVarBytes(allocator);
        return try Self.initFromBytes(script_bytes, allocator);
    }
    
    /// Validates verification script
    pub fn validate(self: Self) !void {
        if (self.script.len > constants.MAX_TRANSACTION_SIZE) {
            return errors.TransactionError.InvalidWitness;
        }
        
        // Validate multi-sig constraints
        if (self.isMultiSig()) {
            const threshold = try self.getSigningThreshold();
            if (self.public_keys) |keys| {
                if (threshold > keys.len) {
                    return errors.TransactionError.InvalidWitness;
                }
            }
        }
    }
    
    /// Compares verification scripts for equality (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.script, other.script);
    }
    
    /// Hash function for HashMap usage (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        return std.hash_map.hashString(self.script);
    }
    
    /// Gets hex representation (utility method)
    pub fn toHex(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try @import("../utils/bytes_extensions.zig").BytesUtils.toHexString(self.script, allocator);
    }
    
    /// Checks if script matches public key (utility method)
    pub fn matchesPublicKey(self: Self, public_key: PublicKey, allocator: std.mem.Allocator) !bool {
        if (self.public_keys) |keys| {
            for (keys) |key| {
                if (key.eql(public_key)) return true;
            }
            return false;
        }
        
        // Try to create script from public key and compare
        var test_script = try Self.initFromPublicKey(public_key, allocator);
        defer test_script.deinit();
        
        return self.eql(test_script);
    }
    
    /// Estimates execution cost (utility method)
    pub fn estimateExecutionCost(self: Self) u32 {
        if (self.isMultiSig()) {
            const threshold = self.getSigningThreshold() catch 1;
            const key_count = if (self.public_keys) |keys| @as(u32, @intCast(keys.len)) else threshold;
            return threshold * 1000 + key_count * 100; // Rough estimate
        } else {
            return 1000; // Single signature cost
        }
    }
};

/// Verification script utilities
pub const VerificationScriptUtils = struct {
    /// Creates single-sig verification script
    pub fn createSingleSig(public_key: PublicKey, allocator: std.mem.Allocator) !CompleteVerificationScript {
        return try CompleteVerificationScript.initFromPublicKey(public_key, allocator);
    }
    
    /// Creates multi-sig verification script
    pub fn createMultiSig(
        public_keys: []const PublicKey,
        threshold: u32,
        allocator: std.mem.Allocator,
    ) !CompleteVerificationScript {
        return try CompleteVerificationScript.initFromPublicKeys(public_keys, threshold, allocator);
    }
    
    /// Creates script from script hash (utility method)
    pub fn createFromScriptHash(script_hash: Hash160, allocator: std.mem.Allocator) !CompleteVerificationScript {
        // Create a basic script that pushes the script hash
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        _ = try builder.pushData(&script_hash.toArray());
        
        return try CompleteVerificationScript.initFromBytes(builder.toScript(), allocator);
    }
    
    /// Validates multi-sig configuration
    pub fn validateMultiSigConfig(
        public_keys: []const PublicKey,
        threshold: u32,
    ) !void {
        if (threshold == 0) {
            return errors.throwIllegalArgument("Signing threshold cannot be zero");
        }
        
        if (threshold > public_keys.len) {
            return errors.throwIllegalArgument("Threshold cannot exceed number of public keys");
        }
        
        if (public_keys.len > constants.MAX_PUBLIC_KEYS_PER_MULTISIG_ACCOUNT) {
            return errors.throwIllegalArgument("Too many public keys for multi-sig");
        }
        
        // Validate all public keys
        for (public_keys) |pub_key| {
            if (!pub_key.isValid()) {
                return errors.CryptoError.InvalidKey;
            }
        }
    }
    
    /// Sorts public keys for multi-sig (utility method)
    pub fn sortPublicKeysForMultiSig(
        public_keys: []PublicKey,
        allocator: std.mem.Allocator,
    ) ![]PublicKey {
        var sorted_keys = try allocator.dupe(PublicKey, public_keys);
        
        const lessThan = struct {
            fn compare(context: void, a: PublicKey, b: PublicKey) bool {
                _ = context;
                return std.mem.order(u8, a.toSlice(), b.toSlice()) == .lt;
            }
        }.compare;
        
        std.sort.block(PublicKey, sorted_keys, {}, lessThan);
        return sorted_keys;
    }
    
    /// Gets standard script types
    pub fn getStandardScriptTypes() []const ScriptType {
        return &[_]ScriptType{ .SingleSignature, .MultiSignature, .Custom };
    }
    
    /// Detects script type
    pub fn detectScriptType(script: CompleteVerificationScript) ScriptType {
        if (script.isEmpty()) return .Empty;
        if (script.isMultiSig()) return .MultiSignature;
        if (script.signing_threshold == 1) return .SingleSignature;
        return .Custom;
    }
};

/// Script types for classification
pub const ScriptType = enum {
    Empty,
    SingleSignature,
    MultiSignature,
    Custom,
    
    pub fn toString(self: ScriptType) []const u8 {
        return switch (self) {
            .Empty => "Empty",
            .SingleSignature => "SingleSignature",
            .MultiSignature => "MultiSignature",
            .Custom => "Custom",
        };
    }
    
    pub fn getDescription(self: ScriptType) []const u8 {
        return switch (self) {
            .Empty => "Empty verification script",
            .SingleSignature => "Single signature verification",
            .MultiSignature => "Multi-signature verification",
            .Custom => "Custom verification logic",
        };
    }
};

// Tests (converted from Swift VerificationScript tests)
test "CompleteVerificationScript creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test empty verification script (equivalent to Swift VerificationScript() tests)
    var empty_script = CompleteVerificationScript.init();
    defer empty_script.deinit();
    
    try testing.expect(empty_script.isEmpty());
    try testing.expect(empty_script.getScriptHash() == null);
    try testing.expectEqual(ScriptType.Empty, VerificationScriptUtils.detectScriptType(empty_script));
    
    // Test script from bytes
    const test_bytes = [_]u8{ 0x0C, 0x21, 0x02, 0x03, 0x41, 0x30, 0x64, 0x76, 0x41 }; // Mock verification script
    var script_from_bytes = try CompleteVerificationScript.initFromBytes(&test_bytes, allocator);
    defer script_from_bytes.deinit();
    
    try testing.expect(!script_from_bytes.isEmpty());
    try testing.expectEqualSlices(u8, &test_bytes, script_from_bytes.script);
    try testing.expect(script_from_bytes.getScriptHash() != null);
}

test "CompleteVerificationScript single signature creation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test verification script from public key (equivalent to Swift init(publicKey) tests)
    const key_pair = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    var verification_script = try CompleteVerificationScript.initFromPublicKey(key_pair.getPublicKey(), allocator);
    defer verification_script.deinit();
    
    try testing.expect(!verification_script.isEmpty());
    try testing.expect(verification_script.getScriptHash() != null);
    try testing.expectEqual(@as(u32, 1), try verification_script.getSigningThreshold());
    try testing.expect(!verification_script.isMultiSig());
    try testing.expectEqual(ScriptType.SingleSignature, VerificationScriptUtils.detectScriptType(verification_script));
    
    // Test script validation
    try verification_script.validate();
}

test "CompleteVerificationScript multi-signature creation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create test public keys
    const key_pair1 = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp1 = key_pair1;
        mutable_kp1.zeroize();
    }
    
    const key_pair2 = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp2 = key_pair2;
        mutable_kp2.zeroize();
    }
    
    const key_pair3 = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp3 = key_pair3;
        mutable_kp3.zeroize();
    }
    
    const public_keys = [_]PublicKey{
        key_pair1.getPublicKey(),
        key_pair2.getPublicKey(),
        key_pair3.getPublicKey(),
    };
    
    // Test multi-sig verification script creation (equivalent to Swift multi-sig tests)
    var multi_sig_script = try CompleteVerificationScript.initFromPublicKeys(&public_keys, 2, allocator);
    defer multi_sig_script.deinit();
    
    try testing.expect(!multi_sig_script.isEmpty());
    try testing.expect(multi_sig_script.getScriptHash() != null);
    try testing.expectEqual(@as(u32, 2), try multi_sig_script.getSigningThreshold());
    try testing.expect(multi_sig_script.isMultiSig());
    try testing.expectEqual(ScriptType.MultiSignature, VerificationScriptUtils.detectScriptType(multi_sig_script));
    
    // Test that public keys are stored
    const stored_keys = multi_sig_script.getPublicKeys();
    try testing.expect(stored_keys != null);
    try testing.expectEqual(@as(usize, 3), stored_keys.?.len);
    
    // Test validation
    try multi_sig_script.validate();
}

test "CompleteVerificationScript error conditions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test invalid multi-sig parameters (equivalent to Swift error tests)
    const key_pair = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const single_key = [_]PublicKey{key_pair.getPublicKey()};
    
    // Test threshold too low
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        CompleteVerificationScript.initFromPublicKeys(&single_key, 0, allocator)
    );
    
    // Test threshold too high
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        CompleteVerificationScript.initFromPublicKeys(&single_key, 2, allocator)
    );
    
    // Test too many public keys
    const many_keys = [_]PublicKey{key_pair.getPublicKey()} ** (constants.MAX_PUBLIC_KEYS_PER_MULTISIG_ACCOUNT + 1);
    
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        CompleteVerificationScript.initFromPublicKeys(&many_keys, 1, allocator)
    );
}

test "CompleteVerificationScript serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test verification script serialization (equivalent to Swift serialization tests)
    const test_script = [_]u8{ 0x0C, 0x21, 0x02, 0xAB, 0x41, 0x30, 0x64, 0x76, 0x41 };
    var original_script = try CompleteVerificationScript.initFromBytes(&test_script, allocator);
    defer original_script.deinit();
    
    // Serialize
    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();
    
    try original_script.serialize(&writer);
    
    const serialized_data = writer.toArray();
    try testing.expect(serialized_data.len > 0);
    
    // Deserialize
    var reader = CompleteBinaryReader.init(serialized_data);
    var deserialized_script = try CompleteVerificationScript.deserialize(&reader, allocator);
    defer deserialized_script.deinit();
    
    // Verify round-trip
    try testing.expect(original_script.eql(deserialized_script));
}

test "VerificationScriptUtils utility functions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test utility script creation
    const key_pair = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    var single_sig_script = try VerificationScriptUtils.createSingleSig(key_pair.getPublicKey(), allocator);
    defer single_sig_script.deinit();
    
    try testing.expect(!single_sig_script.isEmpty());
    try testing.expect(!single_sig_script.isMultiSig());
    
    // Test multi-sig validation
    const public_keys = [_]PublicKey{key_pair.getPublicKey()};
    try VerificationScriptUtils.validateMultiSigConfig(&public_keys, 1);
    
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        VerificationScriptUtils.validateMultiSigConfig(&public_keys, 0)
    );
    
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        VerificationScriptUtils.validateMultiSigConfig(&public_keys, 2)
    );
    
    // Test script type detection
    try testing.expectEqual(ScriptType.SingleSignature, VerificationScriptUtils.detectScriptType(single_sig_script));
    
    const empty_script = CompleteVerificationScript.init();
    try testing.expectEqual(ScriptType.Empty, VerificationScriptUtils.detectScriptType(empty_script));
}

test "CompleteVerificationScript public key matching" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const key_pair = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    var verification_script = try CompleteVerificationScript.initFromPublicKey(key_pair.getPublicKey(), allocator);
    defer verification_script.deinit();
    
    // Test public key matching
    try testing.expect(try verification_script.matchesPublicKey(key_pair.getPublicKey(), allocator));
    
    // Test with different key
    const different_key_pair = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp_diff = different_key_pair;
        mutable_kp_diff.zeroize();
    }
    
    try testing.expect(!try verification_script.matchesPublicKey(different_key_pair.getPublicKey(), allocator));
    
    // Test execution cost estimation
    const cost = verification_script.estimateExecutionCost();
    try testing.expectEqual(@as(u32, 1000), cost); // Single sig cost
}
