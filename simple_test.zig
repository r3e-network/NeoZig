const std = @import("std");

test "basic functionality test" {
    const testing = std.testing;
    
    // Test that basic Zig functionality works
    try testing.expect(true);
    try testing.expectEqual(@as(u32, 42), 42);
    
    // Test allocator works
    const allocator = testing.allocator;
    const test_data = try allocator.alloc(u8, 10);
    defer allocator.free(test_data);
    
    try testing.expectEqual(@as(usize, 10), test_data.len);
}

test "constants validation" {
    const testing = std.testing;
    
    // Import our constants module
    const constants = @import("src/core/constants.zig");
    
    // Test that constants are properly defined
    try testing.expectEqual(@as(usize, 20), constants.HASH160_SIZE);
    try testing.expectEqual(@as(usize, 32), constants.HASH256_SIZE);
    try testing.expectEqual(@as(usize, 32), constants.PRIVATE_KEY_SIZE);
    try testing.expectEqual(@as(u8, 0), constants.CURRENT_TX_VERSION);
}