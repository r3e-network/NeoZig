//! Role Implementation
//!
//! Complete conversion from NeoSwift Role.swift
//! Provides blockchain network roles for Neo consensus and services.

const std = @import("std");
const ArrayList = std.ArrayList;

/// Blockchain network roles (converted from Swift Role)
pub const Role = enum(u8) {
    /// State validator role (consensus node)
    StateValidator = 0x04,
    /// Oracle service role
    Oracle = 0x08,
    /// NeoFS alphabet node role
    NeoFSAlphabetNode = 0x10,

    /// Gets the JSON representation (equivalent to Swift jsonValue)
    pub fn toJsonString(self: Role) []const u8 {
        return switch (self) {
            .StateValidator => "StateValidator",
            .Oracle => "Oracle",
            .NeoFSAlphabetNode => "NeoFSAlphabetNode",
        };
    }

    /// Gets the byte value (equivalent to Swift byte property)
    pub fn toByte(self: Role) u8 {
        return @intFromEnum(self);
    }

    /// Creates Role from byte value (equivalent to Swift ByteEnum protocol)
    pub fn fromByte(byte_value: u8) ?Role {
        return switch (byte_value) {
            0x04 => .StateValidator,
            0x08 => .Oracle,
            0x10 => .NeoFSAlphabetNode,
            else => null,
        };
    }

    /// Creates Role from JSON string (utility method)
    pub fn fromJsonString(json_string: []const u8) ?Role {
        if (std.mem.eql(u8, json_string, "StateValidator")) return .StateValidator;
        if (std.mem.eql(u8, json_string, "Oracle")) return .Oracle;
        if (std.mem.eql(u8, json_string, "NeoFSAlphabetNode")) return .NeoFSAlphabetNode;
        return null;
    }

    /// Gets all available roles
    pub fn getAllRoles() []const Role {
        const roles = [_]Role{ .StateValidator, .Oracle, .NeoFSAlphabetNode };
        return &roles;
    }

    /// Checks if role is involved in consensus
    pub fn isConsensusRole(self: Role) bool {
        return switch (self) {
            .StateValidator => true,
            .Oracle, .NeoFSAlphabetNode => false,
        };
    }

    /// Checks if role provides data services
    pub fn isDataServiceRole(self: Role) bool {
        return switch (self) {
            .Oracle, .NeoFSAlphabetNode => true,
            .StateValidator => false,
        };
    }

    /// Gets role description
    pub fn getDescription(self: Role) []const u8 {
        return switch (self) {
            .StateValidator => "Consensus validator node",
            .Oracle => "External data oracle service",
            .NeoFSAlphabetNode => "NeoFS distributed storage node",
        };
    }

    /// Gets role permissions level (0 = highest)
    pub fn getPermissionLevel(self: Role) u8 {
        return switch (self) {
            .StateValidator => 0, // Highest permissions (consensus)
            .Oracle => 1, // Medium permissions (data)
            .NeoFSAlphabetNode => 2, // Lower permissions (storage)
        };
    }

    /// Checks if role can vote in governance
    pub fn canVote(self: Role) bool {
        return switch (self) {
            .StateValidator => true,
            .Oracle, .NeoFSAlphabetNode => false,
        };
    }

    /// Checks if role can access external data
    pub fn canAccessExternalData(self: Role) bool {
        return switch (self) {
            .Oracle => true,
            .StateValidator, .NeoFSAlphabetNode => false,
        };
    }

    /// Combines multiple roles (bitwise OR)
    pub fn combineRoles(roles: []const Role, allocator: std.mem.Allocator) !u8 {
        _ = allocator;
        var combined: u8 = 0;
        for (roles) |role| {
            combined |= role.toByte();
        }
        return combined;
    }

    /// Extracts roles from combined byte value
    pub fn extractRoles(combined_value: u8, allocator: std.mem.Allocator) ![]Role {
        var roles = ArrayList(Role).init(allocator);
        defer roles.deinit();

        const all_roles = getAllRoles();
        for (all_roles) |role| {
            if ((combined_value & role.toByte()) != 0) {
                try roles.append(role);
            }
        }

        return try roles.toOwnedSlice();
    }
};

// Tests (converted from Swift Role tests)
test "Role JSON conversion" {
    const testing = std.testing;

    // Test toJsonString (equivalent to Swift jsonValue)
    try testing.expectEqualStrings("StateValidator", Role.StateValidator.toJsonString());
    try testing.expectEqualStrings("Oracle", Role.Oracle.toJsonString());
    try testing.expectEqualStrings("NeoFSAlphabetNode", Role.NeoFSAlphabetNode.toJsonString());

    // Test fromJsonString
    try testing.expectEqual(Role.StateValidator, Role.fromJsonString("StateValidator").?);
    try testing.expectEqual(Role.Oracle, Role.fromJsonString("Oracle").?);
    try testing.expectEqual(Role.NeoFSAlphabetNode, Role.fromJsonString("NeoFSAlphabetNode").?);

    // Test invalid JSON string
    try testing.expect(Role.fromJsonString("InvalidRole") == null);
}

test "Role byte conversion" {
    const testing = std.testing;

    // Test toByte (equivalent to Swift byte property)
    try testing.expectEqual(@as(u8, 0x04), Role.StateValidator.toByte());
    try testing.expectEqual(@as(u8, 0x08), Role.Oracle.toByte());
    try testing.expectEqual(@as(u8, 0x10), Role.NeoFSAlphabetNode.toByte());

    // Test fromByte (equivalent to Swift ByteEnum protocol)
    try testing.expectEqual(Role.StateValidator, Role.fromByte(0x04).?);
    try testing.expectEqual(Role.Oracle, Role.fromByte(0x08).?);
    try testing.expectEqual(Role.NeoFSAlphabetNode, Role.fromByte(0x10).?);

    // Test invalid byte value
    try testing.expect(Role.fromByte(0xFF) == null);
}

test "Role properties and capabilities" {
    const testing = std.testing;

    // Test consensus role
    try testing.expect(Role.StateValidator.isConsensusRole());
    try testing.expect(!Role.Oracle.isConsensusRole());
    try testing.expect(!Role.NeoFSAlphabetNode.isConsensusRole());

    // Test data service role
    try testing.expect(!Role.StateValidator.isDataServiceRole());
    try testing.expect(Role.Oracle.isDataServiceRole());
    try testing.expect(Role.NeoFSAlphabetNode.isDataServiceRole());

    // Test voting capability
    try testing.expect(Role.StateValidator.canVote());
    try testing.expect(!Role.Oracle.canVote());
    try testing.expect(!Role.NeoFSAlphabetNode.canVote());

    // Test external data access
    try testing.expect(!Role.StateValidator.canAccessExternalData());
    try testing.expect(Role.Oracle.canAccessExternalData());
    try testing.expect(!Role.NeoFSAlphabetNode.canAccessExternalData());

    // Test permission levels
    try testing.expectEqual(@as(u8, 0), Role.StateValidator.getPermissionLevel());
    try testing.expectEqual(@as(u8, 1), Role.Oracle.getPermissionLevel());
    try testing.expectEqual(@as(u8, 2), Role.NeoFSAlphabetNode.getPermissionLevel());
}

test "Role descriptions" {
    const testing = std.testing;

    // Test role descriptions
    const validator_desc = Role.StateValidator.getDescription();
    try testing.expect(std.mem.indexOf(u8, validator_desc, "Consensus") != null);

    const oracle_desc = Role.Oracle.getDescription();
    try testing.expect(std.mem.indexOf(u8, oracle_desc, "oracle") != null);

    const neofs_desc = Role.NeoFSAlphabetNode.getDescription();
    try testing.expect(std.mem.indexOf(u8, neofs_desc, "NeoFS") != null);
}

test "Role combination and extraction" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test role combination (equivalent to Swift role combination tests)
    const roles = [_]Role{ .StateValidator, .Oracle };
    const combined = try Role.combineRoles(&roles, allocator);
    try testing.expectEqual(@as(u8, 0x04 | 0x08), combined); // 0x0C

    // Test role extraction
    const extracted_roles = try Role.extractRoles(combined, allocator);
    defer allocator.free(extracted_roles);

    try testing.expectEqual(@as(usize, 2), extracted_roles.len);

    var found_validator = false;
    var found_oracle = false;

    for (extracted_roles) |role| {
        if (role == .StateValidator) found_validator = true;
        if (role == .Oracle) found_oracle = true;
    }

    try testing.expect(found_validator and found_oracle);
}

test "Role getAllRoles" {
    const testing = std.testing;

    // Test getting all roles
    const all_roles = Role.getAllRoles();
    try testing.expectEqual(@as(usize, 3), all_roles.len);

    // Verify all known roles are present
    var found_validator = false;
    var found_oracle = false;
    var found_neofs = false;

    for (all_roles) |role| {
        switch (role) {
            .StateValidator => found_validator = true,
            .Oracle => found_oracle = true,
            .NeoFSAlphabetNode => found_neofs = true,
        }
    }

    try testing.expect(found_validator and found_oracle and found_neofs);
}
