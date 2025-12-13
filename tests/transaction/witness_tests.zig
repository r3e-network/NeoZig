//! Witness Tests
//!
//! Complete conversion from NeoSwift WitnessTests.swift
//! Tests witness creation, serialization, and multi-signature functionality.

const std = @import("std");
const neo = @import("neo-zig");

const testing = std.testing;
const ArrayList = std.ArrayList;

const ECKeyPair = neo.crypto.ECKeyPair;
const PublicKey = neo.crypto.PublicKey;
const Sign = neo.crypto.sign.Sign;
const SignatureData = neo.crypto.sign.SignatureData;
const Witness = neo.transaction.WitnessScripts;
const InvocationScript = neo.transaction.InvocationScript;
const VerificationScript = neo.transaction.VerificationScript;
const OpCode = neo.script.OpCode;

// Test witness creation (converted from Swift testCreateWitness)
test "Witness creation" {
    const allocator = testing.allocator;
    
    // Create test message (equivalent to Swift message = Bytes(repeating: 10, count: 10))
    const message = [_]u8{10} ** 10;
    
    // Create key pair (equivalent to Swift ECKeyPair.createEcKeyPair())
    var key_pair = try ECKeyPair.createRandom();
    defer key_pair.zeroize();
    
    // Create witness (equivalent to Swift Witness.create(message, keyPair))
    var witness = try Witness.create(&message, key_pair, allocator);
    defer witness.deinit(allocator);
    
    // Verify witness creation was successful
    try testing.expect(!witness.isEmpty());
    try testing.expect(witness.getInvocationScript().len > 0);
    try testing.expect(witness.getVerificationScript().len > 0);
    
    // Verify witness can be validated
    try witness.validate();
    
    // Test expected signature (equivalent to Swift expectedSignature check)
    const expected_signature = try Sign.signMessage(&message, key_pair, allocator);
    const signature_bytes = expected_signature.getSignatureBytes();
    
    // Verify the signature is present in invocation script
    const invocation_script = witness.getInvocationScript();
    try testing.expect(invocation_script.len > 0);
    try testing.expect(invocation_script.len >= 2 + signature_bytes.len);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.PUSHDATA1)), invocation_script[0]);
    try testing.expectEqual(@as(u8, signature_bytes.len), invocation_script[1]);
    try testing.expectEqualSlices(u8, &signature_bytes, invocation_script[2 .. 2 + signature_bytes.len]);
    
    // Verify verification script contains public key
    const verification_script = witness.getVerificationScript();
    try testing.expect(verification_script.len > 0);

    const expected_verification = try neo.script.ScriptBuilder.buildVerificationScript(
        key_pair.getPublicKey().toSlice(),
        allocator,
    );
    defer allocator.free(expected_verification);
    try testing.expectEqualSlices(u8, expected_verification, verification_script);
    
    // The exact byte verification would require more detailed script parsing
    // but the witness creation and basic structure validation is confirmed
}

// Test witness serialization (converted from Swift testSerializeWitness)
test "Witness serialization" {
    const allocator = testing.allocator;
    
    // Create test data (equivalent to Swift test setup)
    const message = [_]u8{10} ** 10;
    var key_pair = try ECKeyPair.createRandom();
    defer key_pair.zeroize();
    
    // Create witness (equivalent to Swift Witness.create)
    var witness = try Witness.create(&message, key_pair, allocator);
    defer witness.deinit(allocator);
    
    // Test serialization size calculation
    const witness_size = witness.getSize();
    try testing.expect(witness_size > 0);
    
    // Test that invocation and verification scripts have reasonable sizes
    const invocation_size = witness.getInvocationScript().len;
    const verification_size = witness.getVerificationScript().len;
    
    try testing.expect(invocation_size > 60); // Should contain signature data
    try testing.expect(verification_size > 35); // Should contain public key + syscall
    
    // Verify total size calculation
    const calculated_size = invocation_size + verification_size + 2; // +2 for length prefixes
    try testing.expectEqual(calculated_size, witness_size);
}

// Test multi-signature witness creation (converted from Swift testSerializeMultiSigWitness)
test "Multi-signature witness creation" {
    const allocator = testing.allocator;
    
    // Create test message (equivalent to Swift message setup)
    const message = [_]u8{10} ** 10;
    const signing_threshold: u32 = 2;
    
    // Create multiple key pairs and signatures (equivalent to Swift loop)
    var signatures = ArrayList(SignatureData).init(allocator);
    defer signatures.deinit();

    var public_keys = ArrayList(PublicKey).init(allocator);
    defer public_keys.deinit();
    
    // Create 3 key pairs (equivalent to Swift for loop 0...2)
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var key_pair = try ECKeyPair.createRandom();
        defer key_pair.zeroize();
        
        const signature = try Sign.signMessage(&message, key_pair, allocator);
        try signatures.append(signature);
        
        try public_keys.append(key_pair.getPublicKey());
    }
    
    // Create multi-sig witness (equivalent to Swift Witness.creatMultiSigWitness)
    var multi_sig_witness = try Witness.createMultiSigWitness(
        signing_threshold,
        signatures.items,
        public_keys.items,
        allocator,
    );
    defer multi_sig_witness.deinit(allocator);
    
    // Verify multi-sig witness creation
    try testing.expect(!multi_sig_witness.isEmpty());
    try multi_sig_witness.validate();
    
    // Verify witness has both scripts
    try testing.expect(multi_sig_witness.getInvocationScript().len > 0);
    try testing.expect(multi_sig_witness.getVerificationScript().len > 0);
    
    // Multi-sig witness should be larger than single-sig
    const multi_sig_size = multi_sig_witness.getSize();
    try testing.expect(multi_sig_size > 100); // Should be substantial for 3 signatures
}

// Test witness validation and edge cases
test "Witness validation and edge cases" {
    const allocator = testing.allocator;
    
    // Test empty witness (should be valid)
    const empty_witness = Witness.init();
    try empty_witness.validate();
    try testing.expect(empty_witness.isEmpty());
    
    // Test witness with only invocation script (should be invalid)
    const invocation_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const empty_verification = [_]u8{};
    
    var invalid_witness = try Witness.initWithBytes(&invocation_bytes, &empty_verification, allocator);
    defer invalid_witness.deinit(allocator);
    
    // This should fail validation (invocation without verification)
    try testing.expectError(error.InvalidWitness, invalid_witness.validate());
}

// Test witness equality and hashing
test "Witness equality and hashing" {
    const allocator = testing.allocator;
    
    // Create identical witnesses
    const invocation = [_]u8{ 0x01, 0x02, 0x03 };
    const verification = [_]u8{ 0x04, 0x05, 0x06 };
    
    var witness1 = try Witness.initWithBytes(&invocation, &verification, allocator);
    defer witness1.deinit(allocator);
    
    var witness2 = try Witness.initWithBytes(&invocation, &verification, allocator);
    defer witness2.deinit(allocator);
    
    // Different witness
    const different_invocation = [_]u8{ 0x07, 0x08, 0x09 };
    var witness3 = try Witness.initWithBytes(&different_invocation, &verification, allocator);
    defer witness3.deinit(allocator);
    
    // Test equality
    try testing.expect(witness1.eql(witness2));
    try testing.expect(!witness1.eql(witness3));
    
    // Test hashing
    const hash1 = witness1.hash();
    const hash2 = witness2.hash();
    const hash3 = witness3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same witnesses should have same hash
    try testing.expect(hash1 != hash3); // Different witnesses should have different hash
}

// Test witness utility methods
test "Witness utility methods" {
    const allocator = testing.allocator;
    
    // Create test witness
    const invocation = [_]u8{ 0x01, 0x02, 0x03 };
    const verification = [_]u8{ 0x04, 0x05, 0x06 };
    
    var witness = try Witness.initWithBytes(&invocation, &verification, allocator);
    defer witness.deinit(allocator);
    
    // Test size calculation
    const expected_size = invocation.len + verification.len + 2; // +2 for length prefixes
    try testing.expectEqual(expected_size, witness.getSize());
    
    // Test formatting
    const formatted = try witness.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "Witness") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "3 bytes") != null); // invocation size
    try testing.expect(std.mem.indexOf(u8, formatted, "3 bytes") != null); // verification size
    
    // Test cloning
    var cloned_witness = try witness.clone(allocator);
    defer cloned_witness.deinit(allocator);
    
    try testing.expect(witness.eql(cloned_witness));
    try testing.expectEqualSlices(u8, witness.getInvocationScript(), cloned_witness.getInvocationScript());
    try testing.expectEqualSlices(u8, witness.getVerificationScript(), cloned_witness.getVerificationScript());
}

// Test invocation script creation
test "InvocationScript creation and operations" {
    // Test empty invocation script
    const empty_invocation = InvocationScript.init();
    try testing.expect(empty_invocation.isEmpty());
    try testing.expectEqual(@as(usize, 0), empty_invocation.getScript().len);
    
    // Test invocation script from bytes
    const test_bytes = [_]u8{ 0xAB, 0xCD, 0xEF };
    const bytes_invocation = InvocationScript.initWithBytes(&test_bytes);
    try testing.expect(!bytes_invocation.isEmpty());
    try testing.expectEqualSlices(u8, &test_bytes, bytes_invocation.getScript());
}

// Test verification script creation
test "VerificationScript creation and operations" {
    const allocator = testing.allocator;
    
    // Test empty verification script
    const empty_verification = VerificationScript.init();
    try testing.expect(empty_verification.isEmpty());
    try testing.expectEqual(@as(usize, 0), empty_verification.getScript().len);
    
    // Test verification script from bytes
    const test_bytes = [_]u8{ 0x12, 0x34, 0x56 };
    const bytes_verification = VerificationScript.initWithBytes(&test_bytes);
    try testing.expect(!bytes_verification.isEmpty());
    try testing.expectEqualSlices(u8, &test_bytes, bytes_verification.getScript());
    
    // Test verification script from public key
    var key_pair = try ECKeyPair.createRandom();
    defer key_pair.zeroize();
    
    var verification_from_key = try VerificationScript.fromPublicKey(key_pair.getPublicKey(), allocator);
    defer verification_from_key.deinit(allocator);
    
    try testing.expect(!verification_from_key.isEmpty());
    try testing.expect(verification_from_key.getScript().len > 30); // Should contain pubkey + syscall
}
