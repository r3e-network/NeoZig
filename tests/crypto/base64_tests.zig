//! Base64 Tests
//!
//! Complete conversion from NeoSwift Base64Tests.swift
//! Tests Base64 encoding and decoding functionality.

const std = @import("std");
const testing = std.testing;

test "Base64 encoding and decoding" {
    const allocator = testing.allocator;
    
    const test_data = "Hello, Neo blockchain!";
    const test_bytes = @as([]const u8, test_data);
    
    // Encode to base64
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(test_bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    
    const encoded_result = encoder.encode(encoded, test_bytes);
    
    // Decode from base64
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded_result);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    
    try decoder.decode(decoded, encoded_result);
    
    try testing.expectEqualSlices(u8, test_bytes, decoded);
}