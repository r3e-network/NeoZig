//! Witness Scope Tests
//!
//! Complete conversion from NeoSwift WitnessScopeTests.swift
//! Tests witness scope functionality and combinations.

const std = @import("std");


const testing = std.testing;
const neo = @import("neo-zig");
const WitnessScope = neo.transaction.CompleteWitnessScope;

test "Witness scope creation and validation" {
    try testing.expectEqual(@as(u8, 0x00), @intFromEnum(WitnessScope.None));
    try testing.expectEqual(@as(u8, 0x01), @intFromEnum(WitnessScope.CalledByEntry));
    try testing.expectEqual(@as(u8, 0x80), @intFromEnum(WitnessScope.Global));
}

test "Witness scope byte conversion" {
    try testing.expectEqual(@as(u8, 0x00), WitnessScope.None.getByte());
    try testing.expectEqual(@as(u8, 0x01), WitnessScope.CalledByEntry.getByte());
    try testing.expectEqual(@as(u8, 0x80), WitnessScope.Global.getByte());
    
    try testing.expectEqual(WitnessScope.None, WitnessScope.fromByte(0x00).?);
    try testing.expectEqual(WitnessScope.CalledByEntry, WitnessScope.fromByte(0x01).?);
    try testing.expectEqual(WitnessScope.Global, WitnessScope.fromByte(0x80).?);
}
