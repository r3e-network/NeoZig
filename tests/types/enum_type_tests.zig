//! Enum Type Tests
//!
//! Complete conversion from NeoSwift EnumTypeTests.swift
//! Tests enum type functionality and ByteEnum protocol implementation.

const std = @import("std");

const testing = std.testing;
const neo = @import("neo-zig");
const RecordType = neo.types.RecordType;
const Role = neo.types.Role;

test "ByteEnum protocol implementation" {
    // Test RecordType byte enum functionality
    try testing.expectEqual(@as(u8, 1), RecordType.A.getByte());
    try testing.expectEqual(@as(u8, 5), RecordType.CNAME.getByte());
    
    try testing.expectEqual(RecordType.A, RecordType.fromByte(1).?);
    try testing.expectEqual(RecordType.CNAME, RecordType.fromByte(5).?);
    try testing.expect(RecordType.fromByte(99) == null);
    
    // Test Role byte enum functionality
    try testing.expectEqual(@as(u8, 0x04), Role.StateValidator.toByte());
    try testing.expectEqual(@as(u8, 0x08), Role.Oracle.toByte());
    
    try testing.expectEqual(Role.StateValidator, Role.fromByte(0x04).?);
    try testing.expectEqual(Role.Oracle, Role.fromByte(0x08).?);
    try testing.expect(Role.fromByte(0xFF) == null);
}

test "Enum JSON serialization" {
    // Test JSON value conversion
    try testing.expectEqualStrings("A", RecordType.A.getJsonValue());
    try testing.expectEqualStrings("CNAME", RecordType.CNAME.getJsonValue());
    
    try testing.expectEqualStrings("StateValidator", Role.StateValidator.toJsonString());
    try testing.expectEqualStrings("Oracle", Role.Oracle.toJsonString());
    
    // Test from JSON conversion
    try testing.expectEqual(RecordType.A, RecordType.fromJsonValue("A").?);
    try testing.expectEqual(Role.Oracle, Role.fromJsonString("Oracle").?);
    try testing.expect(RecordType.fromJsonValue("Invalid") == null);
}

test "Enum case iteration" {
    // Test getting all cases
    const all_record_types = RecordType.getAllCases();
    try testing.expect(all_record_types.len >= 4);
    
    const all_roles = Role.getAllRoles();
    try testing.expect(all_roles.len >= 3);
    
    // Verify known cases are present
    var found_a_record = false;
    var found_cname_record = false;
    for (all_record_types) |record_type| {
        if (record_type == .A) found_a_record = true;
        if (record_type == .CNAME) found_cname_record = true;
    }
    try testing.expect(found_a_record and found_cname_record);
}
