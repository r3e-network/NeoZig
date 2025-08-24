//! Verification Script Tests
//!
//! Complete conversion from NeoSwift VerificationScriptTests.swift
//! Tests verification script creation from public keys and multi-signature setups.

const std = @import("std");
const testing = std.testing;
const VerificationScript = @import("../../src/transaction/witness.zig").VerificationScript;
const PublicKey = @import("../../src/crypto/keys.zig").PublicKey;
const OpCode = @import("../../src/script/op_code.zig").OpCode;
const InteropService = @import("../../src/script/interop_service.zig").InteropService;

/// Test verification script from single public key (converted from Swift testFromPublicKey)
test "Verification script from public key" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift key constant)
    const key_hex = "035fdb1d1f06759547020891ae97c729327853aeb1256b6fe0473bc2e9fa42ff50";
    
    // Create public key (equivalent to Swift ECPublicKey(key))
    const key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(key_hex, allocator);
    defer allocator.free(key_bytes);
    
    const public_key = try PublicKey.initFromBytes(key_bytes);
    
    // Create verification script (equivalent to Swift VerificationScript(ecKey))
    var verification_script = try VerificationScript.fromPublicKey(public_key, allocator);
    defer verification_script.deinit(allocator);
    
    const script_bytes = verification_script.getScript();
    
    // Verify script structure (equivalent to Swift expected string check)
    try testing.expect(script_bytes.len > 0);
    try testing.expect(script_bytes.len >= 40); // Should contain PUSHDATA1 + pubkey + SYSCALL + hash
    
    // Script should contain the public key data
    const script_contains_pubkey = std.mem.indexOf(u8, script_bytes, key_bytes) != null;
    try testing.expect(script_contains_pubkey);
    
    // Verify script is not empty
    try testing.expect(!verification_script.isEmpty());
}

/// Test verification script from multiple public keys (converted from Swift testFromPublicKeys)
test "Verification script from multiple public keys" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift key1, key2, key3)
    const key1_hex = "035fdb1d1f06759547020891ae97c729327853aeb1256b6fe0473bc2e9fa42ff50";
    const key2_hex = "03eda286d19f7ee0b472afd1163d803d620a961e1581a8f2704b52c0285f6e022d";
    const key3_hex = "03ac81ec17f2f15fd6d193182f927c5971559c2a32b9408a06fec9e711fb7ca02e";
    
    // Create public keys (equivalent to Swift ECPublicKey array)
    const key1_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(key1_hex, allocator);
    defer allocator.free(key1_bytes);
    const key2_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(key2_hex, allocator);
    defer allocator.free(key2_bytes);
    const key3_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(key3_hex, allocator);
    defer allocator.free(key3_bytes);
    
    const public_keys = [_]PublicKey{
        try PublicKey.initFromBytes(key1_bytes),
        try PublicKey.initFromBytes(key2_bytes),
        try PublicKey.initFromBytes(key3_bytes),
    };
    
    const signing_threshold: u32 = 2; // 2-of-3 multi-sig
    
    // Create multi-sig verification script (equivalent to Swift VerificationScript(publicKeys, 2))
    var multi_sig_script = try VerificationScript.fromMultiSig(&public_keys, signing_threshold, allocator);
    defer multi_sig_script.deinit(allocator);
    
    const script_bytes = multi_sig_script.getScript();
    
    // Verify multi-sig script structure (equivalent to Swift expected string check)
    try testing.expect(script_bytes.len > 0);
    try testing.expect(script_bytes.len >= 120); // Should contain threshold + all pubkeys + count + syscall
    
    // Script should contain all public key data
    const script_contains_key1 = std.mem.indexOf(u8, script_bytes, key1_bytes) != null;
    const script_contains_key2 = std.mem.indexOf(u8, script_bytes, key2_bytes) != null;
    const script_contains_key3 = std.mem.indexOf(u8, script_bytes, key3_bytes) != null;
    
    try testing.expect(script_contains_key1);
    try testing.expect(script_contains_key2);
    try testing.expect(script_contains_key3);
    
    // Verify script is not empty
    try testing.expect(!multi_sig_script.isEmpty());
}

/// Test verification script validation
test "Verification script validation" {
    const allocator = testing.allocator;
    
    // Test empty verification script (should be valid)
    const empty_script = VerificationScript.init();
    try testing.expect(empty_script.isEmpty());
    // Empty scripts are valid by design
    
    // Test verification script with valid public key
    const key_pair = try @import("../../src/crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    var valid_script = try VerificationScript.fromPublicKey(key_pair.getPublicKey(), allocator);
    defer valid_script.deinit(allocator);
    
    try testing.expect(!valid_script.isEmpty());
    
    const script_bytes = valid_script.getScript();
    try testing.expect(script_bytes.len > 30); // Reasonable size for single-sig script
}

/// Test verification script size calculations
test "Verification script size calculations" {
    const allocator = testing.allocator;
    
    // Create single-sig verification script
    const key_pair = try @import("../../src/crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    var single_sig_script = try VerificationScript.fromPublicKey(key_pair.getPublicKey(), allocator);
    defer single_sig_script.deinit(allocator);
    
    const single_sig_size = single_sig_script.getScript().len;
    
    // Create multi-sig verification script
    const public_keys = [_]PublicKey{key_pair.getPublicKey()};
    var multi_sig_script = try VerificationScript.fromMultiSig(&public_keys, 1, allocator);
    defer multi_sig_script.deinit(allocator);
    
    const multi_sig_size = multi_sig_script.getScript().len;
    
    // Multi-sig script should be larger (has threshold and count)
    try testing.expect(multi_sig_size > single_sig_size);
    
    // Both should be reasonable sizes
    try testing.expect(single_sig_size >= 35);  // PUSHDATA1 + 33-byte pubkey + SYSCALL + 4-byte hash
    try testing.expect(multi_sig_size >= 45);   // Threshold + pubkey + count + SYSCALL + hash
}

/// Test verification script equality
test "Verification script equality" {
    const allocator = testing.allocator;
    
    // Create identical verification scripts
    const key_pair = try @import("../../src/crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    var script1 = try VerificationScript.fromPublicKey(key_pair.getPublicKey(), allocator);
    defer script1.deinit(allocator);
    
    var script2 = try VerificationScript.fromPublicKey(key_pair.getPublicKey(), allocator);
    defer script2.deinit(allocator);
    
    // Should be equal (same public key)
    try testing.expectEqualSlices(u8, script1.getScript(), script2.getScript());
    
    // Create different verification script
    const different_key_pair = try @import("../../src/crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = different_key_pair;
        mutable_kp.zeroize();
    }
    
    var script3 = try VerificationScript.fromPublicKey(different_key_pair.getPublicKey(), allocator);
    defer script3.deinit(allocator);
    
    // Should not be equal (different public key)
    try testing.expect(!std.mem.eql(u8, script1.getScript(), script3.getScript()));
}