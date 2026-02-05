//! Invocation Script implementation
//!
//! Complete conversion from NeoSwift InvocationScript.swift
//! Provides invocation script functionality for transaction witnesses.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const ECKeyPair = @import("../crypto/ec_key_pair.zig").ECKeyPair;
const SignatureData = @import("../crypto/sign.zig").SignatureData;
const ScriptBuilder = @import("script_builder.zig").ScriptBuilder;
const BinaryWriter = @import("../serialization/binary_writer_complete.zig").CompleteBinaryWriter;
const BinaryReader = @import("../serialization/binary_reader_complete.zig").CompleteBinaryReader;

/// Invocation script for transaction witnesses (converted from Swift InvocationScript)
pub const InvocationScript = struct {
    /// Script as byte array
    script: []const u8,

    allocator: ?std.mem.Allocator,

    const Self = @This();

    /// Creates empty invocation script (equivalent to Swift init())
    pub fn init() Self {
        return Self{
            .script = &[_]u8{},
            .allocator = null,
        };
    }

    /// Creates invocation script from bytes (equivalent to Swift init(_ script: Bytes))
    pub fn initFromBytes(script_bytes: []const u8, allocator: std.mem.Allocator) !Self {
        return Self{
            .script = try allocator.dupe(u8, script_bytes),
            .allocator = allocator,
        };
    }

    /// Creates from signature (equivalent to Swift fromSignature(_ signature: Sign.SignatureData))
    pub fn fromSignature(signature: SignatureData, allocator: std.mem.Allocator) !Self {
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();

        const concatenated = signature.getConcatenated();
        _ = try builder.pushData(&concatenated);

        return Self{
            .script = try allocator.dupe(u8, builder.toScript()),
            .allocator = allocator,
        };
    }

    /// Creates from message and key pair (equivalent to Swift fromMessageAndKeyPair)
    pub fn fromMessageAndKeyPair(message: []const u8, key_pair: ECKeyPair, allocator: std.mem.Allocator) !Self {
        const signature_data = try @import("../crypto/sign.zig").Sign.signMessage(message, key_pair, allocator);
        return try Self.fromSignature(signature_data, allocator);
    }

    /// Creates from signatures (equivalent to Swift fromSignatures(_ signatures: [Sign.SignatureData]))
    pub fn fromSignatures(signatures: []const SignatureData, allocator: std.mem.Allocator) !Self {
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();

        for (signatures) |signature| {
            const concatenated = signature.getConcatenated();
            _ = try builder.pushData(&concatenated);
        }

        return Self{
            .script = try allocator.dupe(u8, builder.toScript()),
            .allocator = allocator,
        };
    }

    /// Creates from contract parameters (utility method)
    pub fn fromContractParameters(
        parameters: []const @import("../types/contract_parameter.zig").ContractParameter,
        allocator: std.mem.Allocator,
    ) !Self {
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();

        for (parameters) |param| {
            _ = try builder.pushParam(param);
        }

        return Self{
            .script = try allocator.dupe(u8, builder.toScript()),
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        if (self.allocator) |alloc| {
            alloc.free(self.script);
        }
    }

    /// Gets script size (equivalent to Swift .size property)
    pub fn getSize(self: Self) usize {
        return @import("../utils/bytes_extensions.zig").BytesUtils.varSize(self.script);
    }

    /// Gets script bytes
    pub fn getScript(self: Self) []const u8 {
        return self.script;
    }

    /// Checks if script is empty
    pub fn isEmpty(self: Self) bool {
        return self.script.len == 0;
    }

    /// Serializes invocation script (equivalent to Swift serialize)
    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try writer.writeVarBytes(self.script);
    }

    /// Deserializes invocation script (equivalent to Swift deserialize)
    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        const script_bytes = try reader.readVarBytes(allocator);
        return Self{
            .script = script_bytes,
            .allocator = allocator,
        };
    }

    /// Validates invocation script
    pub fn validate(self: Self) !void {
        if (self.script.len > constants.MAX_TRANSACTION_SIZE) {
            return errors.TransactionError.InvalidWitness;
        }

        // Additional script validation could be added here
    }

    /// Appends another invocation script (utility method)
    pub fn append(self: Self, other: Self, allocator: std.mem.Allocator) !Self {
        const combined_script = try @import("../utils/bytes_extensions.zig").BytesUtils.concatenate(
            &[_][]const u8{ self.script, other.script },
            allocator,
        );

        return Self{
            .script = combined_script,
            .allocator = allocator,
        };
    }

    /// Extracts signatures from script (utility method)
    pub fn extractSignatures(self: Self, allocator: std.mem.Allocator) ![]SignatureData {
        // Parse script to extract pushed signatures
        var signatures = ArrayList(SignatureData).init(allocator);
        defer signatures.deinit();

        var pos: usize = 0;
        while (pos < self.script.len) {
            const opcode = self.script[pos];
            pos += 1;

            if (opcode == 0x0C) { // PUSHDATA1
                if (pos >= self.script.len) break;
                const data_len = self.script[pos];
                pos += 1;

                if (data_len == 65 and pos + 65 <= self.script.len) { // Signature with recovery ID
                    const sig_data = self.script[pos .. pos + 65];
                    const r = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, sig_data[0..32]));
                    const s = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, sig_data[32..64]));
                    const v = sig_data[64];

                    try signatures.append(SignatureData.init(v, r, s));
                }

                pos += data_len;
            } else {
                // Other opcodes - skip
                continue;
            }
        }

        return try signatures.toOwnedSlice();
    }

    /// Compares invocation scripts for equality (equivalent to Swift Hashable)
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
};

/// Invocation script utilities
pub const InvocationScriptUtils = struct {
    /// Creates script for single signature
    pub fn createSingleSignatureScript(
        signature: SignatureData,
        allocator: std.mem.Allocator,
    ) !InvocationScript {
        return try InvocationScript.fromSignature(signature, allocator);
    }

    /// Creates script for multi-signature
    pub fn createMultiSignatureScript(
        signatures: []const SignatureData,
        required_signatures: u32,
        allocator: std.mem.Allocator,
    ) !InvocationScript {
        if (signatures.len < required_signatures) {
            return errors.throwIllegalArgument("Insufficient signatures for threshold");
        }

        // Use only the required number of signatures
        const used_signatures = signatures[0..required_signatures];
        return try InvocationScript.fromSignatures(used_signatures, allocator);
    }

    /// Creates empty script (utility method)
    pub fn createEmpty() InvocationScript {
        return InvocationScript.init();
    }

    /// Validates script for witness use
    pub fn validateForWitness(script: InvocationScript) !void {
        try script.validate();

        // Additional witness-specific validation
        if (script.getSize() > 1024) { // Reasonable witness script limit
            return errors.TransactionError.InvalidWitness;
        }
    }

    /// Estimates script execution cost (utility method)
    pub fn estimateExecutionCost(script: InvocationScript) u32 {
        // Basic cost estimation based on script length
        const base_cost = script.script.len * 100; // 100 units per byte
        return @intCast(@min(base_cost, 100000)); // Cap at reasonable max
    }

    /// Analyzes script structure (utility method)
    pub fn analyzeScript(script: InvocationScript, allocator: std.mem.Allocator) !ScriptAnalysis {
        var analysis = ScriptAnalysis{
            .total_bytes = script.script.len,
            .opcode_count = 0,
            .push_operations = 0,
            .signature_count = 0,
        };

        var pos: usize = 0;
        while (pos < script.script.len) {
            const opcode = script.script[pos];
            analysis.opcode_count += 1;
            pos += 1;

            // Analyze PUSHDATA operations
            if (opcode <= 75) { // Direct push
                analysis.push_operations += 1;
                pos += opcode;
            } else if (opcode == 0x0C) { // PUSHDATA1
                analysis.push_operations += 1;
                if (pos < script.script.len) {
                    const data_len = script.script[pos];
                    pos += 1 + data_len;

                    if (data_len == 64 or data_len == 65) { // Likely signature
                        analysis.signature_count += 1;
                    }
                }
            }
            // Add more opcode analysis as needed
        }

        return analysis;
    }
};

/// Script analysis results
pub const ScriptAnalysis = struct {
    total_bytes: usize,
    opcode_count: u32,
    push_operations: u32,
    signature_count: u32,

    pub fn format(self: ScriptAnalysis, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "Script: {} bytes, {} opcodes, {} pushes, {} signatures", .{ self.total_bytes, self.opcode_count, self.push_operations, self.signature_count });
    }

    pub fn isLikelySignatureScript(self: ScriptAnalysis) bool {
        return self.signature_count > 0 and self.push_operations == self.signature_count;
    }

    pub fn isComplexScript(self: ScriptAnalysis) bool {
        return self.opcode_count > self.push_operations + 5; // More than just pushes
    }
};

// Tests (converted from Swift InvocationScript tests)
test "InvocationScript creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test empty invocation script creation (equivalent to Swift InvocationScript() tests)
    var empty_script = InvocationScript.init();
    defer empty_script.deinit();

    try testing.expect(empty_script.isEmpty());
    try testing.expectEqual(@as(usize, 0), empty_script.script.len);
    try testing.expectEqual(@as(usize, 1), empty_script.getSize()); // VarInt for empty array

    // Test script from bytes
    const test_bytes = [_]u8{ 0x0C, 0x40 }; // PUSHDATA1, 64 bytes of data (stub)
    var script_from_bytes = try InvocationScript.initFromBytes(&test_bytes, allocator);
    defer script_from_bytes.deinit();

    try testing.expect(!script_from_bytes.isEmpty());
    try testing.expectEqualSlices(u8, &test_bytes, script_from_bytes.script);
}

test "InvocationScript creation from signatures" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test script from signature (equivalent to Swift fromSignature tests)
    const test_signature = SignatureData.init(28, 12345, 67890);
    var signature_script = try InvocationScript.fromSignature(test_signature, allocator);
    defer signature_script.deinit();

    try testing.expect(!signature_script.isEmpty());
    try testing.expect(signature_script.script.len > 0);

    // Test script from key pair (equivalent to Swift fromMessageAndKeyPair tests)
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }

    const message = "Test message for invocation script";
    var keypair_script = try InvocationScript.fromMessageAndKeyPair(message, key_pair, allocator);
    defer keypair_script.deinit();

    try testing.expect(!keypair_script.isEmpty());
    try testing.expect(keypair_script.script.len > 0);
}

test "InvocationScript multi-signature operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test script from multiple signatures (equivalent to Swift fromSignatures tests)
    const signatures = [_]SignatureData{
        SignatureData.init(27, 11111, 22222),
        SignatureData.init(28, 33333, 44444),
        SignatureData.init(29, 55555, 66666),
    };

    var multi_sig_script = try InvocationScript.fromSignatures(&signatures, allocator);
    defer multi_sig_script.deinit();

    try testing.expect(!multi_sig_script.isEmpty());
    try testing.expect(multi_sig_script.script.len > 0);

    // Should be larger than single signature script
    var single_sig_script = try InvocationScript.fromSignature(signatures[0], allocator);
    defer single_sig_script.deinit();

    try testing.expect(multi_sig_script.script.len > single_sig_script.script.len);
}

test "InvocationScript serialization operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test script serialization (equivalent to Swift serialization tests)
    const test_script = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var original_script = try InvocationScript.initFromBytes(&test_script, allocator);
    defer original_script.deinit();

    // Serialize
    var writer = CompleteBinaryWriter.init(allocator);
    defer writer.deinit();

    try original_script.serialize(&writer);

    const serialized_data = writer.toArray();
    try testing.expect(serialized_data.len > 0);

    // Deserialize
    var reader = CompleteBinaryReader.init(serialized_data);
    var deserialized_script = try InvocationScript.deserialize(&reader, allocator);
    defer deserialized_script.deinit();

    // Verify round-trip
    try testing.expect(original_script.eql(deserialized_script));
}

test "InvocationScript validation and analysis" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test script validation
    const valid_script = [_]u8{ 0x0C, 0x02, 0x01, 0x02 }; // PUSHDATA1, 2 bytes, data
    var script = try InvocationScript.initFromBytes(&valid_script, allocator);
    defer script.deinit();

    try script.validate();

    // Test script analysis
    const analysis = try InvocationScriptUtils.analyzeScript(script, allocator);
    try testing.expectEqual(@as(usize, 4), analysis.total_bytes);
    try testing.expect(analysis.opcode_count > 0);
    try testing.expect(analysis.push_operations > 0);

    const formatted_analysis = try analysis.format(allocator);
    defer allocator.free(formatted_analysis);

    try testing.expect(std.mem.indexOf(u8, formatted_analysis, "bytes") != null);
    try testing.expect(std.mem.indexOf(u8, formatted_analysis, "opcodes") != null);
}

test "InvocationScriptUtils utility functions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test utility script creation
    const test_signature = SignatureData.init(27, 123456, 789012);
    var single_sig_script = try InvocationScriptUtils.createSingleSignatureScript(test_signature, allocator);
    defer single_sig_script.deinit();

    try testing.expect(!single_sig_script.isEmpty());

    // Test multi-signature script creation
    const multi_signatures = [_]SignatureData{
        SignatureData.init(27, 111, 222),
        SignatureData.init(28, 333, 444),
        SignatureData.init(29, 555, 666),
    };

    var multi_sig_script = try InvocationScriptUtils.createMultiSignatureScript(&multi_signatures, 2, allocator);
    defer multi_sig_script.deinit();

    try testing.expect(!multi_sig_script.isEmpty());

    // Test insufficient signatures error
    try testing.expectError(errors.NeoError.IllegalArgument, InvocationScriptUtils.createMultiSignatureScript(&multi_signatures, 5, allocator));

    // Test empty script creation
    var empty_script = InvocationScriptUtils.createEmpty();
    defer empty_script.deinit();

    try testing.expect(empty_script.isEmpty());

    // Test witness validation
    try InvocationScriptUtils.validateForWitness(single_sig_script);

    // Test execution cost estimation
    const cost = InvocationScriptUtils.estimateExecutionCost(single_sig_script);
    try testing.expect(cost > 0);
    try testing.expect(cost <= 100000);
}
