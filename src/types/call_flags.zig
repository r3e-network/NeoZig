//! Call Flags implementation
//!
//! Complete conversion from NeoSwift CallFlags.swift
//! Defines contract invocation permission flags.

const std = @import("std");



/// Contract call flags (converted from Swift CallFlags)
pub const CallFlags = enum(u8) {
    /// No permissions
    None = 0x00,
    /// Allow reading blockchain state
    ReadStates = 0x01,
    /// Allow writing blockchain state
    WriteStates = 0x02,
    /// Allow calling other contracts
    AllowCall = 0x04,
    /// Allow sending notifications
    AllowNotify = 0x08,
    /// Combined read and write states
    States = 0x03,        // ReadStates | WriteStates
    /// Read-only operations with calls and notifications
    ReadOnly = 0x0D,      // ReadStates | AllowCall | AllowNotify
    /// All permissions
    All = 0x0F,           // States | AllowCall | AllowNotify
    
    const Self = @This();
    
    /// Gets flag value (equivalent to Swift .value property)
    pub fn getValue(self: Self) u8 {
        return @intFromEnum(self);
    }
    
    /// Checks if flag includes read states permission
    pub fn hasReadStates(self: Self) bool {
        return (@intFromEnum(self) & @intFromEnum(CallFlags.ReadStates)) != 0;
    }
    
    /// Checks if flag includes write states permission
    pub fn hasWriteStates(self: Self) bool {
        return (@intFromEnum(self) & @intFromEnum(CallFlags.WriteStates)) != 0;
    }
    
    /// Checks if flag includes allow call permission
    pub fn hasAllowCall(self: Self) bool {
        return (@intFromEnum(self) & @intFromEnum(CallFlags.AllowCall)) != 0;
    }
    
    /// Checks if flag includes allow notify permission
    pub fn hasAllowNotify(self: Self) bool {
        return (@intFromEnum(self) & @intFromEnum(CallFlags.AllowNotify)) != 0;
    }
    
    /// Creates call flags from integer value
    pub fn fromValue(value: u8) Self {
        return @enumFromInt(value);
    }
    
    /// Gets flag description (equivalent to Swift description)
    pub fn getDescription(self: Self) []const u8 {
        return switch (self) {
            .None => "None",
            .ReadStates => "ReadStates",
            .WriteStates => "WriteStates",
            .AllowCall => "AllowCall",
            .AllowNotify => "AllowNotify",
            .States => "States",
            .ReadOnly => "ReadOnly",
            .All => "All",
        };
    }
};

// Tests (converted from Swift CallFlags tests)
test "CallFlags values and operations" {
    const testing = std.testing;
    
    // Test flag values (equivalent to Swift value tests)
    try testing.expectEqual(@as(u8, 0x00), CallFlags.None.getValue());
    try testing.expectEqual(@as(u8, 0x01), CallFlags.ReadStates.getValue());
    try testing.expectEqual(@as(u8, 0x02), CallFlags.WriteStates.getValue());
    try testing.expectEqual(@as(u8, 0x04), CallFlags.AllowCall.getValue());
    try testing.expectEqual(@as(u8, 0x08), CallFlags.AllowNotify.getValue());
    try testing.expectEqual(@as(u8, 0x0F), CallFlags.All.getValue());
}

test "CallFlags permission checking" {
    const testing = std.testing;
    
    // Test permission detection (equivalent to Swift permission tests)
    try testing.expect(CallFlags.ReadStates.hasReadStates());
    try testing.expect(!CallFlags.ReadStates.hasWriteStates());
    try testing.expect(!CallFlags.ReadStates.hasAllowCall());
    
    try testing.expect(CallFlags.All.hasReadStates());
    try testing.expect(CallFlags.All.hasWriteStates());
    try testing.expect(CallFlags.All.hasAllowCall());
    try testing.expect(CallFlags.All.hasAllowNotify());
    
    try testing.expect(!CallFlags.None.hasReadStates());
    try testing.expect(!CallFlags.None.hasWriteStates());
}

test "CallFlags combination" {
    const testing = std.testing;
    
    // Test predefined combined flags
    const states = CallFlags.States;
    try testing.expect(states.hasReadStates());
    try testing.expect(states.hasWriteStates());
    try testing.expect(!states.hasAllowCall());

    const read_only = CallFlags.ReadOnly;
    try testing.expect(read_only.hasReadStates());
    try testing.expect(read_only.hasAllowCall());
    try testing.expect(read_only.hasAllowNotify());
}

test "CallFlags from value" {
    const testing = std.testing;
    
    // Test creation from value (equivalent to Swift fromValue tests)
    const flags_from_value = CallFlags.fromValue(0x0F);
    try testing.expectEqual(CallFlags.All, flags_from_value);
    
    const none_from_value = CallFlags.fromValue(0x00);
    try testing.expectEqual(CallFlags.None, none_from_value);
}
