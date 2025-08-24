//! Contract Parameter Tests
//!
//! Complete conversion from NeoSwift ContractParameterTests.swift
//! Tests contract parameter creation, validation, and type operations.

const std = @import("std");
const testing = std.testing;
const ContractParameter = @import("../../src/types/contract_parameter.zig").ContractParameter;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const PublicKey = @import("../../src/crypto/keys.zig").PublicKey;

/// Helper function to verify contract parameter properties (equivalent to Swift assertContractParameter)
fn assertContractParameter(
    param: ContractParameter,
    expected_value: anytype,
    expected_type: ContractParameter.ParameterType,
) !void {
    try testing.expectEqual(expected_type, param.getParameterType());
    
    switch (expected_type) {
        .String => {
            const string_value = try param.getStringValue();
            try testing.expectEqualStrings(@as([]const u8, expected_value), string_value);
        },
        .ByteArray => {
            const bytes_value = try param.getBytesValue();
            try testing.expectEqualSlices(u8, @as([]const u8, expected_value), bytes_value);
        },
        .Array => {
            const array_value = try param.getArrayValue();
            const expected_array = @as([]const ContractParameter, expected_value);
            try testing.expectEqual(expected_array.len, array_value.len);
        },
        else => {
            // Additional type checks can be added here
        },
    }
}

/// Test string parameter creation (converted from Swift testStringFromString)
test "String parameter creation" {
    const allocator = testing.allocator;
    
    // Create string parameter (equivalent to Swift ContractParameter.string("value"))
    var string_param = try ContractParameter.createString("value", allocator);
    defer string_param.deinit(allocator);
    
    // Verify parameter properties (equivalent to Swift assertContractParameter)
    try assertContractParameter(string_param, "value", .String);
    
    // Additional validation
    try string_param.validate();
    try testing.expect(string_param.isString());
    try testing.expect(!string_param.isInteger());
    try testing.expect(!string_param.isByteArray());
}

/// Test byte array parameter from bytes (converted from Swift testBytesFromBytes)
test "Byte array parameter from bytes" {
    const allocator = testing.allocator;
    
    // Create byte array parameter (equivalent to Swift ContractParameter.byteArray(bytes))
    const test_bytes = [_]u8{ 0x01, 0x01 };
    var bytes_param = try ContractParameter.createByteArray(&test_bytes, allocator);
    defer bytes_param.deinit(allocator);
    
    // Verify parameter properties (equivalent to Swift assertContractParameter)
    try assertContractParameter(bytes_param, &test_bytes, .ByteArray);
    
    // Additional validation
    try bytes_param.validate();
    try testing.expect(bytes_param.isByteArray());
    try testing.expect(!bytes_param.isString());
    try testing.expect(!bytes_param.isInteger());
}

/// Test byte array parameter from hex string (converted from Swift testBytesFromBytesString)
test "Byte array parameter from hex string" {
    const allocator = testing.allocator;
    
    // Create byte array from hex string (equivalent to Swift ContractParameter.byteArray("0xa602"))
    const hex_string = "a602"; // Without 0x prefix
    const hex_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(hex_string, allocator);
    defer allocator.free(hex_bytes);
    
    var bytes_param = try ContractParameter.createByteArray(hex_bytes, allocator);
    defer bytes_param.deinit(allocator);
    
    // Expected bytes
    const expected_bytes = [_]u8{ 0xa6, 0x02 };
    
    // Verify parameter properties
    try assertContractParameter(bytes_param, &expected_bytes, .ByteArray);
}

/// Test byte array parameter equality (converted from Swift testBytesEquals)
test "Byte array parameter equality" {
    const allocator = testing.allocator;
    
    // Create byte array from hex string (equivalent to Swift ContractParameter.byteArray("0x796573"))
    const hex_string = "796573";
    const hex_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(hex_string, allocator);
    defer allocator.free(hex_bytes);
    
    var param1 = try ContractParameter.createByteArray(hex_bytes, allocator);
    defer param1.deinit(allocator);
    
    // Create byte array from direct bytes (equivalent to Swift ContractParameter.byteArray([0x79, 0x65, 0x73]))
    const direct_bytes = [_]u8{ 0x79, 0x65, 0x73 };
    var param2 = try ContractParameter.createByteArray(&direct_bytes, allocator);
    defer param2.deinit(allocator);
    
    // Parameters should be equal (equivalent to Swift XCTAssertEqual)
    try testing.expect(param1.eql(param2));
}

/// Test byte array from string (converted from Swift testBytesFromString)
test "Byte array parameter from string" {
    const allocator = testing.allocator;
    
    // Create byte array from string (equivalent to Swift ContractParameter.byteArrayFromString("Neo"))
    const string_value = "Neo";
    var string_bytes_param = try ContractParameter.createByteArrayFromString(string_value, allocator);
    defer string_bytes_param.deinit(allocator);
    
    // Expected bytes for "Neo" in UTF-8
    const expected_bytes = [_]u8{ 0x4e, 0x65, 0x6f };
    
    // Verify parameter properties
    try assertContractParameter(string_bytes_param, &expected_bytes, .ByteArray);
}

/// Test byte array from invalid hex string (converted from Swift testBytesFromInvalidBytesString)
test "Byte array from invalid hex string" {
    const allocator = testing.allocator;
    
    // Test invalid hex string (equivalent to Swift "value" which is not hex)
    const invalid_hex = "value"; // Not a valid hex string
    
    // Should throw error for invalid hex (equivalent to Swift assertErrorMessage)
    try testing.expectError(
        anyerror, // Could be InvalidHex or similar
        @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(invalid_hex, allocator)
    );
}

/// Test array parameter creation (converted from Swift testArrayfromArray)
test "Array parameter creation" {
    const allocator = testing.allocator;
    
    // Create array of parameters (equivalent to Swift params array)
    var string_param = try ContractParameter.createString("value", allocator);
    defer string_param.deinit(allocator);
    
    const hex_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex("0101", allocator);
    defer allocator.free(hex_bytes);
    
    var bytes_param = try ContractParameter.createByteArray(hex_bytes, allocator);
    defer bytes_param.deinit(allocator);
    
    const inner_params = [_]ContractParameter{ string_param, bytes_param };
    
    // Create array parameter (equivalent to Swift ContractParameter.array(params))
    var array_param = try ContractParameter.createArray(&inner_params, allocator);
    defer array_param.deinit(allocator);
    
    // Verify parameter properties
    try assertContractParameter(array_param, &inner_params, .Array);
    
    // Additional validation
    try array_param.validate();
    try testing.expect(array_param.isArray());
    try testing.expect(!array_param.isString());
    
    const array_items = try array_param.getArrayValue();
    try testing.expectEqual(@as(usize, 2), array_items.len);
}

/// Test empty array parameter (converted from Swift testArrayFromEmpty)
test "Empty array parameter creation" {
    const allocator = testing.allocator;
    
    // Create empty array parameter (equivalent to Swift ContractParameter.array([]))
    const empty_params = [_]ContractParameter{};
    var empty_array_param = try ContractParameter.createArray(&empty_params, allocator);
    defer empty_array_param.deinit(allocator);
    
    // Verify empty array properties
    try assertContractParameter(empty_array_param, &empty_params, .Array);
    
    try empty_array_param.validate();
    try testing.expect(empty_array_param.isArray());
    
    const array_items = try empty_array_param.getArrayValue();
    try testing.expectEqual(@as(usize, 0), array_items.len);
}

/// Test integer parameter creation
test "Integer parameter creation" {
    const allocator = testing.allocator;
    
    // Test various integer values
    const integer_test_cases = [_]i64{ 0, 1, -1, 42, -42, 1000000, -1000000 };
    
    for (integer_test_cases) |test_value| {
        var int_param = try ContractParameter.createInteger(test_value, allocator);
        defer int_param.deinit(allocator);
        
        try int_param.validate();
        try testing.expect(int_param.isInteger());
        
        const retrieved_value = try int_param.getIntegerValue();
        try testing.expectEqual(test_value, retrieved_value);
    }
}

/// Test boolean parameter creation
test "Boolean parameter creation" {
    const allocator = testing.allocator;
    
    // Test true parameter
    var true_param = try ContractParameter.createBoolean(true, allocator);
    defer true_param.deinit(allocator);
    
    try true_param.validate();
    try testing.expect(true_param.isBoolean());
    try testing.expect(try true_param.getBooleanValue());
    
    // Test false parameter
    var false_param = try ContractParameter.createBoolean(false, allocator);
    defer false_param.deinit(allocator);
    
    try false_param.validate();
    try testing.expect(false_param.isBoolean());
    try testing.expect(!(try false_param.getBooleanValue()));
}

/// Test Hash160 parameter creation
test "Hash160 parameter creation" {
    const allocator = testing.allocator;
    
    // Create Hash160 parameter
    const test_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    var hash_param = try ContractParameter.createHash160(test_hash, allocator);
    defer hash_param.deinit(allocator);
    
    try hash_param.validate();
    try testing.expect(hash_param.isHash160());
    
    const retrieved_hash = try hash_param.getHash160Value();
    try testing.expect(test_hash.eql(retrieved_hash));
}

/// Test public key parameter creation
test "Public key parameter creation" {
    const allocator = testing.allocator;
    
    // Create public key
    const encoded_point = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    const public_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(encoded_point, allocator);
    defer allocator.free(public_key_bytes);
    
    const public_key = try PublicKey.initFromBytes(public_key_bytes);
    
    // Create public key parameter
    var pubkey_param = try ContractParameter.createPublicKey(public_key, allocator);
    defer pubkey_param.deinit(allocator);
    
    try pubkey_param.validate();
    try testing.expect(pubkey_param.isPublicKey());
    
    const retrieved_pubkey = try pubkey_param.getPublicKeyValue();
    try testing.expect(public_key.eql(retrieved_pubkey));
}

/// Test parameter type validation
test "Parameter type validation" {
    const allocator = testing.allocator;
    
    // Test all parameter types have correct validation
    var string_param = try ContractParameter.createString("test", allocator);
    defer string_param.deinit(allocator);
    try testing.expect(string_param.isString());
    try testing.expect(!string_param.isInteger());
    try testing.expect(!string_param.isByteArray());
    try testing.expect(!string_param.isBoolean());
    try testing.expect(!string_param.isHash160());
    try testing.expect(!string_param.isPublicKey());
    try testing.expect(!string_param.isArray());
    
    var int_param = try ContractParameter.createInteger(42, allocator);
    defer int_param.deinit(allocator);
    try testing.expect(!int_param.isString());
    try testing.expect(int_param.isInteger());
    
    const test_bytes = [_]u8{ 1, 2, 3 };
    var bytes_param = try ContractParameter.createByteArray(&test_bytes, allocator);
    defer bytes_param.deinit(allocator);
    try testing.expect(bytes_param.isByteArray());
    try testing.expect(!bytes_param.isString());
}

/// Test parameter size estimation
test "Parameter size estimation" {
    const allocator = testing.allocator;
    
    // Test size estimation for different parameter types
    var small_string = try ContractParameter.createString("hi", allocator);
    defer small_string.deinit(allocator);
    
    var large_string = try ContractParameter.createString("this is a much longer string for testing", allocator);
    defer large_string.deinit(allocator);
    
    const small_size = small_string.getEstimatedSize();
    const large_size = large_string.getEstimatedSize();
    
    // Large string should have larger estimated size
    try testing.expect(large_size > small_size);
    
    // Test array size estimation
    const inner_params = [_]ContractParameter{ small_string, large_string };
    var array_param = try ContractParameter.createArray(&inner_params, allocator);
    defer array_param.deinit(allocator);
    
    const array_size = array_param.getEstimatedSize();
    
    // Array should be larger than sum of components (overhead)
    try testing.expect(array_size >= small_size + large_size);
}