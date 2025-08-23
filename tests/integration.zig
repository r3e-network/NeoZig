//! Integration tests for Neo Zig SDK
//!
//! This test suite validates end-to-end functionality and integration
//! between different SDK components.

const std = @import("std");
const neo = @import("neo-zig");

test "complete key generation and address workflow" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Generate a new key pair
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }
    
    // Validate key pair
    try testing.expect(key_pair.private_key.isValid());
    try testing.expect(key_pair.public_key.isValid());
    try testing.expect(key_pair.isValid());
    
    // Convert to address
    const address = try key_pair.public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
    try testing.expect(address.isValid());
    try testing.expect(address.isStandard());
    
    // Convert address to string and back
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    
    const parsed_address = try neo.Address.fromString(address_str, allocator);
    try testing.expect(address.eql(parsed_address));
    
    // Verify hash160 round-trip
    const script_hash = address.toHash160();
    const recovered_address = neo.Address.fromHash160(script_hash);
    try testing.expect(address.eql(recovered_address));
}

test "complete signing and verification workflow" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Generate key pair
    const private_key = neo.crypto.generatePrivateKey();
    const public_key = try private_key.getPublicKey(true);
    
    // Create test message
    const message = "Neo Zig SDK integration test message";
    
    // Sign message
    const signature = try neo.crypto.signMessage(message, private_key);
    try testing.expect(signature.isValid());
    
    // Verify signature
    const is_valid = try neo.crypto.verifyMessage(signature, message, public_key);
    try testing.expect(is_valid);
    
    // Test with wrong message
    const wrong_message = "Different message";
    const is_invalid = try neo.crypto.verifyMessage(signature, wrong_message, public_key);
    try testing.expect(!is_invalid);
    
    // Test signature serialization
    const sig_hex = try signature.toHex(allocator);
    defer allocator.free(sig_hex);
    
    const parsed_signature = try neo.crypto.Signature.fromHex(sig_hex);
    try testing.expect(signature.eql(parsed_signature));
}

test "hash operations integration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const test_data = "Neo blockchain integration test";
    
    // Test SHA256
    const sha_hash = neo.crypto.sha256(test_data);
    try testing.expect(!sha_hash.isZero());
    
    // Test Hash160
    const hash160_result = try neo.crypto.hash160(test_data);
    try testing.expect(!hash160_result.isZero());
    
    // Test hex conversion round-trip
    const sha_hex = try sha_hash.toHex(allocator);
    defer allocator.free(sha_hex);
    
    const parsed_sha = try neo.Hash256.fromHex(sha_hex);
    try testing.expect(sha_hash.eql(parsed_sha));
    
    const hash160_hex = try hash160_result.toHex(allocator);
    defer allocator.free(hash160_hex);
    
    const parsed_hash160 = try neo.Hash160.fromHex(hash160_hex);
    try testing.expect(hash160_result.eql(parsed_hash160));
}

test "contract parameter workflow" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create various contract parameters
    const bool_param = neo.ContractParameter.boolean(true);
    const int_param = neo.ContractParameter.integer(12345);
    const str_param = neo.ContractParameter.string("Integration test");
    
    const test_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const bytes_param = neo.ContractParameter.byteArray(&test_data);
    
    const hash_param = neo.ContractParameter.hash160(neo.Hash160.zero());
    
    // Create parameter array
    const params = [_]neo.ContractParameter{
        bool_param,
        int_param,
        str_param,
        bytes_param,
        hash_param,
    };
    
    // Validate all parameters
    try neo.types.ParameterUtils.validateArray(&params);
    
    // Test size estimation
    const total_size = neo.types.ParameterUtils.estimateArraySize(&params);
    try testing.expect(total_size > 0);
    
    // Test parameter conversion to strings
    for (params) |param| {
        const param_str = try param.toString(allocator);
        defer allocator.free(param_str);
        try testing.expect(param_str.len > 0);
    }
}

test "serialization round-trip" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create test data
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    var writer = neo.BinaryWriter.init(&buffer);
    
    // Write various data types
    try writer.writeByte(0x42);
    try writer.writeBool(true);
    try writer.writeU32(0x12345678);
    try writer.writeVarInt(0x123456);
    try writer.writeVarString("Integration test string");
    
    const test_hash160 = neo.Hash160.zero();
    const test_hash256 = neo.Hash256.zero();
    try writer.writeHash160(test_hash160);
    try writer.writeHash256(test_hash256);
    
    // Read back the data
    var stream = std.io.fixedBufferStream(buffer.items);
    var reader = neo.BinaryReader.init(stream.reader().any());
    
    const read_byte = try reader.readByte();
    try testing.expectEqual(@as(u8, 0x42), read_byte);
    
    const read_bool = try reader.readBool();
    try testing.expectEqual(true, read_bool);
    
    const read_u32 = try reader.readU32();
    try testing.expectEqual(@as(u32, 0x12345678), read_u32);
    
    const read_varint = try reader.readVarInt();
    try testing.expectEqual(@as(u64, 0x123456), read_varint);
    
    const read_string = try reader.readVarString(allocator);
    defer allocator.free(read_string);
    try testing.expectEqualStrings("Integration test string", read_string);
    
    const read_hash160 = try reader.readHash160();
    try testing.expect(test_hash160.eql(read_hash160));
    
    const read_hash256 = try reader.readHash256();
    try testing.expect(test_hash256.eql(read_hash256));
}

test "WIF encoding integration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Generate private key
    const private_key = neo.crypto.generatePrivateKey();
    try testing.expect(private_key.isValid());
    
    // Encode to WIF (compressed, mainnet)
    const wif_str = try neo.crypto.encodeWIF(private_key, true, .mainnet);
    defer allocator.free(wif_str);
    try testing.expect(wif_str.len > 0);
    
    // Decode WIF
    const wif_result = try neo.crypto.decodeWIF(wif_str, allocator);
    try testing.expect(wif_result.private_key.eql(private_key));
    try testing.expect(wif_result.compressed);
    try testing.expect(wif_result.network == .mainnet);
    
    // Test WIF validation
    try testing.expect(neo.crypto.wif.validate(wif_str, allocator));
}

test "error handling integration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test various error conditions across modules
    
    // Invalid hash hex
    try testing.expectError(neo.errors.ValidationError.InvalidHash, neo.Hash160.fromHex("invalid"));
    try testing.expectError(neo.errors.ValidationError.InvalidHash, neo.Hash256.fromHex("too_short"));
    
    // Invalid address
    try testing.expectError(neo.errors.ValidationError.InvalidAddress, neo.Address.fromString("invalid_address", allocator));
    
    // Invalid private key
    const zero_key = std.mem.zeroes([32]u8);
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PrivateKey.init(zero_key));
    
    // Invalid WIF
    try testing.expectError(neo.errors.CryptoError.InvalidWIF, neo.crypto.decodeWIF("invalid_wif", allocator));
    
    // Invalid contract parameter
    var invalid_key: [33]u8 = undefined;
    invalid_key[0] = 0x01; // Invalid prefix
    for (invalid_key[1..]) |*byte| {
        byte.* = 0xFF;
    }
    const invalid_param = neo.ContractParameter.publicKey(invalid_key);
    try testing.expectError(neo.errors.ValidationError.InvalidParameter, invalid_param.validate());
}

test "performance characteristics" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const iterations = 1000;
    var timer = try std.time.Timer.start();
    
    // Test key generation performance
    timer.reset();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const key = neo.crypto.generatePrivateKey();
        try testing.expect(key.isValid());
    }
    const key_gen_time = timer.read();
    
    // Test hash performance
    timer.reset();
    const test_data = "Performance test data for hashing operations";
    i = 0;
    while (i < iterations) : (i += 1) {
        const hash = neo.crypto.sha256(test_data);
        try testing.expect(!hash.isZero());
    }
    const hash_time = timer.read();
    
    // Test serialization performance
    timer.reset();
    i = 0;
    while (i < iterations) : (i += 1) {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        var writer = neo.BinaryWriter.init(&buffer);
        try writer.writeU32(0x12345678);
        try writer.writeVarString("Test string");
        try writer.writeHash256(neo.Hash256.zero());
        
        try testing.expect(buffer.items.len > 0);
    }
    const serialization_time = timer.read();
    
    // Log performance results
    std.log.info("Performance test results for {} iterations:", .{iterations});
    std.log.info("  Key generation: {}ns per operation", .{key_gen_time / iterations});
    std.log.info("  SHA256 hashing: {}ns per operation", .{hash_time / iterations});
    std.log.info("  Serialization: {}ns per operation", .{serialization_time / iterations});
}

test "memory safety validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test that we don't have memory leaks in common operations
    var leak_count: usize = 0;
    
    // Test hex conversion
    {
        const hash = neo.Hash256.sha256("memory safety test");
        const hex_str = try hash.toHex(allocator);
        defer allocator.free(hex_str);
        leak_count += 1;
    }
    
    // Test address creation
    {
        const private_key = neo.crypto.generatePrivateKey();
        const public_key = try private_key.getPublicKey(true);
        const address = try public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
        const address_str = try address.toString(allocator);
        defer allocator.free(address_str);
        leak_count += 1;
    }
    
    // Test serialization
    {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        var writer = neo.BinaryWriter.init(&buffer);
        try writer.writeVarString("Memory safety test");
        leak_count += 1;
    }
    
    // If we reach here without memory errors, the test passes
    try testing.expect(leak_count == 3);
}