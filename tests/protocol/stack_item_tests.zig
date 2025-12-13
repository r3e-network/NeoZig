//! Stack Item Tests
//!
//! Complete conversion from NeoSwift StackItemTests.swift
//! Tests Neo VM stack item types and operations.

const std = @import("std");


const testing = std.testing;
const neo = @import("neo-zig");
const StackItem = neo.rpc.StackItem;

test "Stack item creation and type checking" {
    const allocator = testing.allocator;
    
    // Test boolean stack item
    const bool_item = StackItem.Factory.createBoolean(true);
    try testing.expect(try bool_item.getBoolean());
    try testing.expectEqual(@as(i64, 1), try bool_item.getInteger());
    
    // Test integer stack item
    const int_item = StackItem.Factory.createInteger(42);
    try testing.expectEqual(@as(i64, 42), try int_item.getInteger());
    try testing.expect(try int_item.getBoolean()); // Non-zero is true
    
    // Test byte string stack item
    var byte_string_item = try StackItem.Factory.createByteString("Hello", allocator);
    defer byte_string_item.deinit(allocator);
    
    const string_value = try byte_string_item.getString(allocator);
    defer allocator.free(string_value);
    try testing.expectEqualStrings("Hello", string_value);
}

test "Stack item array operations" {
    const allocator = testing.allocator;
    
    const items = [_]StackItem{
        StackItem.Factory.createBoolean(true),
        StackItem.Factory.createInteger(42),
    };
    
    var array_item = try StackItem.Factory.createArray(&items, allocator);
    defer array_item.deinit(allocator);
    
    const retrieved_array = try array_item.getArray();
    try testing.expectEqual(@as(usize, 2), retrieved_array.len);
    
    try testing.expect(try retrieved_array[0].getBoolean());
    try testing.expectEqual(@as(i64, 42), try retrieved_array[1].getInteger());
}
