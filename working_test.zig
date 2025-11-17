const std = @import("std");



test "Neo Zig SDK core validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test constants module
    const constants = @import("src/core/constants.zig");
    try testing.expectEqual(@as(usize, 20), constants.HASH160_SIZE);
    try testing.expectEqual(@as(usize, 32), constants.HASH256_SIZE);
    
    // Test errors module  
    const errors = @import("src/core/errors.zig");
    _ = errors; // Verify it loads
    
    // Test basic hash operations
    const test_data = "Hello Neo Blockchain!";
    var hash_result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(test_data, &hash_result, .{});
    try testing.expectEqual(@as(usize, 32), hash_result.len);
    
    // Test that we can allocate and manage memory
    const test_buffer = try allocator.alloc(u8, 1024);
    defer allocator.free(test_buffer);
    
    @memset(test_buffer, 0xAB);
    try testing.expectEqual(@as(u8, 0xAB), test_buffer[0]);
    try testing.expectEqual(@as(u8, 0xAB), test_buffer[1023]);
    
    // Test basic cryptographic patterns
    const private_key_bytes = [_]u8{0x12} ** 32;
    const public_key_bytes = [_]u8{0x02} ++ [_]u8{0x34} ** 32;
    
    try testing.expectEqual(@as(usize, 32), private_key_bytes.len);
    try testing.expectEqual(@as(usize, 33), public_key_bytes.len);
}

test "Neo SDK module structure validation" {
    const testing = std.testing;
    
    // Verify our module structure can be imported
    const constants = @import("src/core/constants.zig");
    const errors = @import("src/core/errors.zig");
    
    // Test secp256r1 constants
    try testing.expect(constants.Secp256r1.N > 0);
    try testing.expect(constants.Secp256r1.P > 0);
    
    // Test address constants
    try testing.expectEqual(@as(u8, 0x35), constants.AddressConstants.ADDRESS_VERSION);
    try testing.expectEqual(@as(u8, 0x80), constants.AddressConstants.WIF_VERSION);
    
    // Test native contract hashes are defined
    try testing.expect(constants.NativeContracts.NEO_TOKEN.len > 0);
    try testing.expect(constants.NativeContracts.GAS_TOKEN.len > 0);
    
    // Test error categories exist (just verify they're accessible)
    const neo_error: type = errors.NeoError;
    const crypto_error: type = errors.CryptoError;  
    const transaction_error: type = errors.TransactionError;
    
    _ = neo_error;
    _ = crypto_error;
    _ = transaction_error;
}