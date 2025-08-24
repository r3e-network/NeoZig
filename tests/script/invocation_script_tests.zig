//! Invocation Script Tests
//!
//! Complete conversion from NeoSwift InvocationScriptTests.swift
//! Tests invocation script creation and signature handling.

const std = @import("std");
const testing = std.testing;
const InvocationScript = @import("../../src/transaction/witness.zig").InvocationScript;
const ECKeyPair = @import("../../src/crypto/ec_key_pair.zig").ECKeyPair;

test "Invocation script creation from message and key pair" {
    const allocator = testing.allocator;
    
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const test_message = "Test message for signing";
    const message_bytes = @as([]const u8, test_message);
    
    var invocation_script = try InvocationScript.fromMessageAndKeyPair(message_bytes, key_pair, allocator);
    defer invocation_script.deinit(allocator);
    
    try testing.expect(!invocation_script.isEmpty());
    try testing.expect(invocation_script.getScript().len > 0);
    try testing.expect(invocation_script.getScript().len >= 65); // Should contain signature
}

test "Invocation script from signatures" {
    const allocator = testing.allocator;
    
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const message = "Multi-sig test message";
    const message_bytes = @as([]const u8, message);
    
    const signature = try key_pair.signMessage(message_bytes, allocator);
    defer signature.deinit(allocator);
    
    const signatures = [_]@import("../../src/crypto/sign.zig").SignatureData{signature};
    
    var multi_sig_invocation = try InvocationScript.fromSignatures(&signatures, allocator);
    defer multi_sig_invocation.deinit(allocator);
    
    try testing.expect(!multi_sig_invocation.isEmpty());
    try testing.expect(multi_sig_invocation.getScript().len > 60); // Should contain null + signature
}