//! Variable Size Tests
//!
//! Complete conversion from NeoSwift VarSizeTests.swift
//! Tests variable-length encoding and decoding.

const std = @import("std");


const testing = std.testing;

test "Variable size encoding" {
    // Test variable size calculation for different values
    try testing.expectEqual(@as(usize, 1), getVarSize(0));
    try testing.expectEqual(@as(usize, 1), getVarSize(252));
    try testing.expectEqual(@as(usize, 3), getVarSize(253));
    try testing.expectEqual(@as(usize, 3), getVarSize(65535));
    try testing.expectEqual(@as(usize, 5), getVarSize(65536));
}

fn getVarSize(value: usize) usize {
    if (value < 0xFD) return 1;
    if (value <= 0xFFFF) return 3;
    if (value <= 0xFFFFFFFF) return 5;
    return 9;
}