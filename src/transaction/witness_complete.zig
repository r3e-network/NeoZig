//! Complete Witness implementation
//!
//! Complete conversion from NeoSwift Witness.swift
//! Provides comprehensive witness functionality for transaction validation.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const ECKeyPair = @import("../crypto/ec_key_pair.zig").ECKeyPair;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const SignatureData = @import("../crypto/sign.zig").SignatureData;
const BinaryWriter = @import("../serialization/binary_writer_complete.zig").CompleteBinaryWriter;
const BinaryReader = @import("../serialization/binary_reader_complete.zig").CompleteBinaryReader;

/// Complete witness implementation (converted from Swift Witness)
pub const CompleteWitness = struct {
    /// Invocation script (contains signatures)
    invocation_script: InvocationScript,
    /// Verification script (contains public keys and verification logic)
    verification_script: VerificationScript,
    
    const Self = @This();
    
    /// Creates empty witness (equivalent to Swift init())
    pub fn init() Self {
        return Self{
            .invocation_script = InvocationScript.init(),
            .verification_script = VerificationScript.init(),
        };
    }
    
    /// Creates witness from script bytes (equivalent to Swift init(_ invocationScript: Bytes, _ verificationScript: Bytes))
    pub fn initFromBytes(invocation_bytes: []const u8, verification_bytes: []const u8, allocator: std.mem.Allocator) !Self {
        return Self{
            .invocation_script = try InvocationScript.initFromBytes(invocation_bytes, allocator),
            .verification_script = try VerificationScript.initFromBytes(verification_bytes, allocator),
        };
    }
    
    /// Creates witness from script objects (equivalent to Swift init(_ invocationScript: InvocationScript, _ verificationScript: VerificationScript))
    pub fn initFromScripts(invocation_script: InvocationScript, verification_script: VerificationScript) Self {
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
        };
    }
    
    /// Creates witness from message and key pair (equivalent to Swift create(_ messageToSign: Bytes, _ keyPair: ECKeyPair))
    pub fn create(message_to_sign: []const u8, key_pair: ECKeyPair, allocator: std.mem.Allocator) !Self {
        const invocation_script = try InvocationScript.fromMessageAndKeyPair(message_to_sign, key_pair, allocator);
        const verification_script = try VerificationScript.initFromPublicKey(key_pair.getPublicKey(), allocator);
        
        return Self.initFromScripts(invocation_script, verification_script);
    }
    
    /// Creates multi-sig witness (equivalent to Swift creatMultiSigWitness)
    pub fn createMultiSigWitness(
        allocator: std.mem.Allocator,
        signing_threshold: u32,
        signatures: []const SignatureData,
        public_keys: []const PublicKey,
    ) !Self {
        const verification_script = try VerificationScript.initFromPublicKeys(public_keys, signing_threshold, allocator);
        return try createMultiSigWitnessWithScript(allocator, signatures, verification_script);
    }
    
    /// Creates multi-sig witness with verification script (equivalent to Swift creatMultiSigWitness with script)
    pub fn createMultiSigWitnessWithScript(
        allocator: std.mem.Allocator,
        signatures: []const SignatureData,
        verification_script: VerificationScript,
    ) !Self {
        const threshold = try verification_script.getSigningThreshold();
        
        if (signatures.len < threshold) {
            return errors.throwIllegalArgument("Not enough signatures for signing threshold");
        }
        
        // Use only the required number of signatures
        const required_signatures = signatures[0..threshold];
        const invocation_script = try InvocationScript.fromSignatures(required_signatures, allocator);
        
        return Self.initFromScripts(invocation_script, verification_script);
    }
    
    /// Creates contract witness (equivalent to Swift createContractWitness)
    pub fn createContractWitness(verify_params: []const ContractParameter, allocator: std.mem.Allocator) !Self {
        if (verify_params.len == 0) {
            return Self.init();
        }
        
        var builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        // Push parameters for verify method
        for (verify_params) |param| {
            _ = try builder.pushParam(param);
        }
        
        const invocation_bytes = builder.toScript();
        const invocation_script = try InvocationScript.initFromBytes(invocation_bytes, allocator);
        const verification_script = VerificationScript.init(); // Empty for contract witness
        
        return Self.initFromScripts(invocation_script, verification_script);
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.invocation_script.deinit();
        self.verification_script.deinit();
    }
    
    /// Gets size (equivalent to Swift .size property)
    pub fn getSize(self: Self) usize {
        return self.invocation_script.getSize() + self.verification_script.getSize();
    }
    
    /// Serializes witness (equivalent to Swift serialize)
    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try self.invocation_script.serialize(writer);
        try self.verification_script.serialize(writer);
    }
    
    /// Deserializes witness (equivalent to Swift deserialize)
    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        const invocation_script = try InvocationScript.deserialize(reader, allocator);
        const verification_script = try VerificationScript.deserialize(reader, allocator);
        
        return Self.initFromScripts(invocation_script, verification_script);
    }
    
    /// Compares witnesses for equality (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return self.invocation_script.eql(other.invocation_script) and
               self.verification_script.eql(other.verification_script);
    }
    
    /// Hash function for HashMap usage (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&[_]u8{@intCast(self.invocation_script.hash())});
        hasher.update(&[_]u8{@intCast(self.verification_script.hash())});
        return hasher.final();
    }
};

/// Invocation script (contains signatures)
pub const InvocationScript = struct {
    script: []const u8,
    allocator: ?std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates empty invocation script
    pub fn init() Self {
        return Self{
            .script = &[_]u8{},
            .allocator = null,
        };
    }
    
    /// Creates from bytes
    pub fn initFromBytes(script_bytes: []const u8, allocator: std.mem.Allocator) !Self {
        return Self{
            .script = try allocator.dupe(u8, script_bytes),
            .allocator = allocator,
        };
    }
    
    /// Creates from message and key pair
    pub fn fromMessageAndKeyPair(message: []const u8, key_pair: ECKeyPair, allocator: std.mem.Allocator) !Self {
        const signature_data = try @import("../crypto/sign.zig").Sign.signMessage(message, key_pair, allocator);
        
        var builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        // Push signature
        const signature_bytes = signature_data.getSignatureBytes();
        _ = try builder.pushData(&signature_bytes);
        
        return Self{
            .script = try allocator.dupe(u8, builder.toScript()),
            .allocator = allocator,
        };
    }
    
    /// Creates from signatures
    pub fn fromSignatures(signatures: []const SignatureData, allocator: std.mem.Allocator) !Self {
        var builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        // Push signatures in order
        for (signatures) |signature| {
            const sig_bytes = signature.getSignatureBytes();
            _ = try builder.pushData(&sig_bytes);
        }
        
        return Self{
            .script = try allocator.dupe(u8, builder.toScript()),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.allocator) |alloc| {
            alloc.free(self.script);
        }
    }
    
    pub fn getSize(self: Self) usize {
        return @import("../utils/bytes_extensions.zig").BytesUtils.varSize(self.script);
    }
    
    pub fn serialize(self: Self, writer: anytype) !void {
        try writer.writeVarBytes(self.script);
    }
    
    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !Self {
        const script_bytes = try reader.readVarBytes(allocator);
        return Self{
            .script = script_bytes,
            .allocator = allocator,
        };
    }
    
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.script, other.script);
    }
    
    pub fn hash(self: Self) u32 {
        return @truncate(std.hash_map.hashString(self.script));
    }
};

/// Verification script (contains public keys and verification logic)
pub const VerificationScript = struct {
    script: []const u8,
    signing_threshold: ?u32,
    public_keys: ?[]const PublicKey,
    allocator: ?std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates empty verification script
    pub fn init() Self {
        return Self{
            .script = &[_]u8{},
            .signing_threshold = null,
            .public_keys = null,
            .allocator = null,
        };
    }
    
    /// Creates from bytes
    pub fn initFromBytes(script_bytes: []const u8, allocator: std.mem.Allocator) !Self {
        return Self{
            .script = try allocator.dupe(u8, script_bytes),
            .signing_threshold = null,
            .public_keys = null,
            .allocator = allocator,
        };
    }
    
    /// Creates from public key (single-sig)
    pub fn initFromPublicKey(public_key: PublicKey, allocator: std.mem.Allocator) !Self {
        const script = try @import("../script/script_builder.zig").ScriptBuilder.buildVerificationScript(
            public_key.toSlice(),
            allocator,
        );
        
        const public_keys = try allocator.dupe(PublicKey, &[_]PublicKey{public_key});
        
        return Self{
            .script = script,
            .signing_threshold = 1,
            .public_keys = public_keys,
            .allocator = allocator,
        };
    }
    
    /// Creates from public keys (multi-sig)
    pub fn initFromPublicKeys(public_keys: []const PublicKey, signing_threshold: u32, allocator: std.mem.Allocator) !Self {
        if (signing_threshold == 0 or signing_threshold > public_keys.len) {
            return errors.throwIllegalArgument("Invalid signing threshold");
        }
        
        // Convert public keys to bytes for script building
        var key_bytes = try allocator.alloc([]const u8, public_keys.len);
        defer allocator.free(key_bytes);
        
        for (public_keys, 0..) |pub_key, i| {
            key_bytes[i] = pub_key.toSlice();
        }
        
        const script = try @import("../script/script_builder.zig").ScriptBuilder.buildMultiSigVerificationScript(
            key_bytes,
            signing_threshold,
            allocator,
        );
        
        return Self{
            .script = script,
            .signing_threshold = signing_threshold,
            .public_keys = try allocator.dupe(PublicKey, public_keys),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.allocator) |alloc| {
            alloc.free(self.script);
            if (self.public_keys) |keys| {
                alloc.free(keys);
            }
        }
    }
    
    pub fn getSigningThreshold(self: Self) !u32 {
        return self.signing_threshold orelse errors.ValidationError.InvalidParameter;
    }
    
    pub fn getPublicKeys(self: Self) ?[]const PublicKey {
        return self.public_keys;
    }
    
    pub fn getSize(self: Self) usize {
        return @import("../utils/bytes_extensions.zig").BytesUtils.varSize(self.script);
    }
    
    pub fn serialize(self: Self, writer: anytype) !void {
        try writer.writeVarBytes(self.script);
    }
    
    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !Self {
        const script_bytes = try reader.readVarBytes(allocator);
        return Self{
            .script = script_bytes,
            .signing_threshold = null,
            .public_keys = null,
            .allocator = allocator,
        };
    }
    
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.script, other.script);
    }
    
    pub fn hash(self: Self) u32 {
        return @truncate(std.hash_map.hashString(self.script));
    }
};

/// Witness factory utilities
pub const WitnessFactory = struct {
    /// Creates single-signature witness
    pub fn createSingleSig(
        message: []const u8,
        key_pair: ECKeyPair,
        allocator: std.mem.Allocator,
    ) !CompleteWitness {
        return try CompleteWitness.create(message, key_pair, allocator);
    }
    
    /// Creates multi-signature witness with automatic threshold
    pub fn createMultiSig(
        allocator: std.mem.Allocator,
        signatures: []const SignatureData,
        public_keys: []const PublicKey,
        threshold: ?u32,
    ) !CompleteWitness {
        const actual_threshold = threshold orelse @intCast(public_keys.len); // Default to all keys
        return try CompleteWitness.createMultiSigWitness(allocator, actual_threshold, signatures, public_keys);
    }
    
    /// Creates contract witness with parameters
    pub fn createContract(
        verify_params: []const ContractParameter,
        allocator: std.mem.Allocator,
    ) !CompleteWitness {
        return try CompleteWitness.createContractWitness(verify_params, allocator);
    }
    
    /// Creates empty witness for fee-only signers
    pub fn createEmpty() CompleteWitness {
        return CompleteWitness.init();
    }
};

/// Witness validation utilities
pub const WitnessValidation = struct {
    /// Validates witness structure
    pub fn validateWitness(witness: CompleteWitness) !void {
        // Check size constraints
        if (witness.getSize() > constants.MAX_TRANSACTION_SIZE) {
            return errors.TransactionError.InvalidWitness;
        }
        
        // Validate scripts are not empty for non-contract witnesses
        if (witness.verification_script.script.len > 0 and witness.invocation_script.script.len == 0) {
            return errors.TransactionError.InvalidWitness;
        }
    }
    
    /// Validates multi-sig witness
    pub fn validateMultiSigWitness(
        witness: CompleteWitness,
        expected_threshold: u32,
        expected_key_count: u32,
    ) !void {
        try validateWitness(witness);
        
        if (witness.verification_script.signing_threshold) |threshold| {
            if (threshold != expected_threshold) {
                return errors.TransactionError.InvalidWitness;
            }
        }
        
        if (witness.verification_script.public_keys) |keys| {
            if (keys.len != expected_key_count) {
                return errors.TransactionError.InvalidWitness;
            }
        }
    }
    
    /// Estimates witness size for planning
    pub fn estimateWitnessSize(
        signature_count: u32,
        public_key_count: u32,
        has_verification_script: bool,
    ) usize {
        var size: usize = 0;
        
        // Invocation script: signatures
        size += 1; // VarInt for script length
        size += signature_count * (1 + 64); // PUSHDATA + 64-byte signatures
        
        if (has_verification_script) {
            // Verification script: public keys + threshold + CheckSig/CheckMultiSig
            size += 1; // VarInt for script length
            size += 1; // Threshold
            size += public_key_count * (1 + 33); // PUSHDATA + 33-byte compressed keys
            size += 1; // Key count
            size += 5; // SYSCALL + InteropService
        }
        
        return size;
    }
};

// Tests (converted from Swift Witness tests)
test "CompleteWitness creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test empty witness creation (equivalent to Swift Witness() tests)
    var empty_witness = CompleteWitness.init();
    defer empty_witness.deinit();
    
    try testing.expectEqual(@as(usize, 0), empty_witness.invocation_script.script.len);
    try testing.expectEqual(@as(usize, 0), empty_witness.verification_script.script.len);
    
    // Test witness from bytes (equivalent to Swift init with bytes tests)
    const invocation_bytes = [_]u8{ 0x0C, 0x40 }; // PUSHDATA + signature placeholder
    const verification_bytes = [_]u8{ 0x0C, 0x21, 0x02, 0x03, 0x41, 0x9D }; // Verification script
    
    var witness_from_bytes = try CompleteWitness.initFromBytes(&invocation_bytes, &verification_bytes, allocator);
    defer witness_from_bytes.deinit();
    
    try testing.expectEqualSlices(u8, &invocation_bytes, witness_from_bytes.invocation_script.script);
    try testing.expectEqualSlices(u8, &verification_bytes, witness_from_bytes.verification_script.script);
}

test "CompleteWitness creation from key pair" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test witness creation from key pair (equivalent to Swift create tests)
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const message = "Test message for witness creation";
    var witness = try CompleteWitness.create(message, key_pair, allocator);
    defer witness.deinit();
    
    try testing.expect(witness.invocation_script.script.len > 0);
    try testing.expect(witness.verification_script.script.len > 0);
    
    // Validate witness structure
    try WitnessValidation.validateWitness(witness);
}

test "CompleteWitness multi-signature operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create test key pairs and signatures
    const key_pair1 = try ECKeyPair.createRandom();
    defer {
        var mutable_kp1 = key_pair1;
        mutable_kp1.zeroize();
    }
    
    const key_pair2 = try ECKeyPair.createRandom();
    defer {
        var mutable_kp2 = key_pair2;
        mutable_kp2.zeroize();
    }
    
    const message = "Multi-sig test message";
    const sig1 = try @import("../crypto/sign.zig").Sign.signMessage(message, key_pair1, allocator);
    const sig2 = try @import("../crypto/sign.zig").Sign.signMessage(message, key_pair2, allocator);
    
    const signatures = [_]SignatureData{ sig1, sig2 };
    const public_keys = [_]PublicKey{ key_pair1.getPublicKey(), key_pair2.getPublicKey() };
    
    // Test multi-sig witness creation (equivalent to Swift multi-sig tests)
    var multi_sig_witness = try CompleteWitness.createMultiSigWitness(
        allocator,
        2, // 2-of-2 threshold
        &signatures,
        &public_keys,
    );
    defer multi_sig_witness.deinit();
    
    try testing.expect(multi_sig_witness.invocation_script.script.len > 0);
    try testing.expect(multi_sig_witness.verification_script.script.len > 0);
    
    // Validate multi-sig witness
    try WitnessValidation.validateMultiSigWitness(multi_sig_witness, 2, 2);
}

test "CompleteWitness contract witness operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test contract witness creation (equivalent to Swift createContractWitness tests)
    const verify_params = [_]ContractParameter{
        ContractParameter.boolean(true),
        ContractParameter.integer(12345),
        ContractParameter.string("contract_verification"),
    };
    
    var contract_witness = try CompleteWitness.createContractWitness(&verify_params, allocator);
    defer contract_witness.deinit();
    
    try testing.expect(contract_witness.invocation_script.script.len > 0);
    try testing.expectEqual(@as(usize, 0), contract_witness.verification_script.script.len); // Empty for contracts
    
    // Test empty contract witness
    var empty_contract_witness = try CompleteWitness.createContractWitness(&[_]ContractParameter{}, allocator);
    defer empty_contract_witness.deinit();
    
    try testing.expectEqual(@as(usize, 0), empty_contract_witness.invocation_script.script.len);
}

test "CompleteWitness serialization operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test witness serialization (equivalent to Swift serialization tests)
    const invocation_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const verification_bytes = [_]u8{ 0x04, 0x05, 0x06 };
    
    var original_witness = try CompleteWitness.initFromBytes(&invocation_bytes, &verification_bytes, allocator);
    defer original_witness.deinit();
    
    // Serialize
    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();
    
    try original_witness.serialize(&writer);
    
    const serialized_data = writer.toArray();
    try testing.expect(serialized_data.len > 0);
    
    // Deserialize
    var reader = CompleteBinaryReader.init(serialized_data);
    var deserialized_witness = try CompleteWitness.deserialize(&reader, allocator);
    defer deserialized_witness.deinit();
    
    // Verify round-trip
    try testing.expect(original_witness.eql(deserialized_witness));
}

test "WitnessFactory utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test factory methods (equivalent to Swift factory tests)
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const message = "Factory test message";
    
    // Test single-sig factory
    var single_sig_witness = try WitnessFactory.createSingleSig(message, key_pair, allocator);
    defer single_sig_witness.deinit();
    
    try testing.expect(single_sig_witness.invocation_script.script.len > 0);
    
    // Test empty witness factory
    var empty_witness = WitnessFactory.createEmpty();
    defer empty_witness.deinit();
    
    try testing.expectEqual(@as(usize, 0), empty_witness.getSize());
    
    // Test contract witness factory
    const contract_params = [_]ContractParameter{ContractParameter.boolean(true)};
    var contract_witness = try WitnessFactory.createContract(&contract_params, allocator);
    defer contract_witness.deinit();
    
    try testing.expect(contract_witness.invocation_script.script.len > 0);
}