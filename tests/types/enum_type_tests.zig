//! Enum Type Tests
//!
//! Complete conversion from NeoSwift EnumTypeTests.swift
//! Tests enum type functionality and ByteEnum protocol implementation.

const std = @import("std");
const testing = std.testing;
const WitnessScope = @import("../../src/transaction/witness_scope_complete.zig").WitnessScope;
const RecordType = @import("../../src/types/record_type.zig").RecordType;
const Role = @import("../../src/types/role.zig").Role;

test "ByteEnum protocol implementation" {
    const testing = std.testing;
    
    // Test RecordType byte enum functionality
    try testing.expectEqual(@as(u8, 1), RecordType.A.toByte());
    try testing.expectEqual(@as(u8, 5), RecordType.CNAME.toByte());
    
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
    const testing = std.testing;
    
    // Test JSON value conversion
    try testing.expectEqualStrings("A", RecordType.A.toJsonString());
    try testing.expectEqualStrings("CNAME", RecordType.CNAME.toJsonString());
    
    try testing.expectEqualStrings("StateValidator", Role.StateValidator.toJsonString());
    try testing.expectEqualStrings("Oracle", Role.Oracle.toJsonString());
    
    // Test from JSON conversion
    try testing.expectEqual(RecordType.A, RecordType.fromJsonString("A").?);
    try testing.expectEqual(Role.Oracle, Role.fromJsonString("Oracle").?);
    try testing.expect(RecordType.fromJsonString("Invalid") == null);
}

test "Enum case iteration" {
    const testing = std.testing;
    
    // Test getting all cases
    const all_record_types = RecordType.getAllTypes();
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