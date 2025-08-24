//! Witness Scope Tests
//!
//! Complete conversion from NeoSwift WitnessScopeTests.swift
//! Tests witness scope functionality and combinations.

const std = @import("std");
const testing = std.testing;
const WitnessScope = @import("../../src/transaction/witness_scope_complete.zig").WitnessScope;

test "Witness scope creation and validation" {
    const testing = std.testing;
    
    try testing.expect(WitnessScope.None.isNone());
    try testing.expect(WitnessScope.CalledByEntry.isCalledByEntry());
    try testing.expect(WitnessScope.Global.isGlobal());
    try testing.expect(!WitnessScope.None.isGlobal());
    try testing.expect(!WitnessScope.Global.isNone());
}

test "Witness scope byte conversion" {
    const testing = std.testing;
    
    try testing.expectEqual(@as(u8, 0x00), WitnessScope.None.toByte());
    try testing.expectEqual(@as(u8, 0x01), WitnessScope.CalledByEntry.toByte());
    try testing.expectEqual(@as(u8, 0x80), WitnessScope.Global.toByte());
    
    try testing.expectEqual(WitnessScope.None, WitnessScope.fromByte(0x00).?);
    try testing.expectEqual(WitnessScope.CalledByEntry, WitnessScope.fromByte(0x01).?);
    try testing.expectEqual(WitnessScope.Global, WitnessScope.fromByte(0x80).?);
}