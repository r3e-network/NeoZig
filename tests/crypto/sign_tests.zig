//! Sign Tests
//!
//! Complete conversion from NeoSwift SignTests.swift
//! Tests message signing, signature verification, and recovery functionality.

const std = @import("std");
const testing = std.testing;
const Sign = @import("../../src/crypto/sign.zig").Sign;
const ECKeyPair = @import("../../src/crypto/ec_key_pair.zig").ECKeyPair;

test "Sign message and verify signature" {
    const allocator = testing.allocator;
    
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const test_message = "Hello Neo blockchain signing!";
    const message_bytes = @as([]const u8, test_message);
    
    const signature = try Sign.signMessage(message_bytes, key_pair, allocator);
    defer signature.deinit(allocator);
    
    try testing.expect(signature.r != 0);
    try testing.expect(signature.s != 0);
    try testing.expect(signature.v >= 27 and signature.v <= 30);
    
    const is_valid = try key_pair.getPublicKey().verifySignature(message_bytes, signature, allocator);
    try testing.expect(is_valid);
}

test "Sign hex message" {
    const allocator = testing.allocator;
    
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const hex_message = "48656c6c6f"; // "Hello" in hex
    
    const signature = try Sign.signHexMessage(hex_message, key_pair, allocator);
    defer signature.deinit(allocator);
    
    try testing.expect(signature.r != 0);
    try testing.expect(signature.s != 0);
}

test "Signature recovery" {
    const allocator = testing.allocator;
    
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const message = "Test recovery message";
    const message_bytes = @as([]const u8, message);
    
    const signature = try Sign.signMessage(message_bytes, key_pair, allocator);
    defer signature.deinit(allocator);
    
    const recovered_key = try Sign.recoverFromSignature(signature, message_bytes, allocator);
    defer recovered_key.deinit(allocator);
    
    try testing.expect(key_pair.getPublicKey().eql(recovered_key));
}