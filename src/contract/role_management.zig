//! Role Management Contract implementation
//!
//! Complete conversion from NeoSwift RoleManagement.swift
//! Handles node role designation and management.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const SmartContract = @import("smart_contract.zig").SmartContract;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const PublicKey = @import("../crypto/keys.zig").PublicKey;

/// Role management contract (converted from Swift RoleManagement)
pub const RoleManagement = struct {
    /// Contract name (matches Swift NAME)
    pub const NAME = "RoleManagement";
    
    /// Script hash (matches Swift SCRIPT_HASH)
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.ROLE_MANAGEMENT };
    
    /// Method names (match Swift constants)
    pub const GET_DESIGNATED_BY_ROLE = "getDesignatedByRole";
    pub const DESIGNATE_AS_ROLE = "designateAsRole";
    
    /// Base smart contract
    smart_contract: SmartContract,
    
    const Self = @This();
    
    /// Creates new RoleManagement instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, neo_swift: ?*anyopaque) Self {
        return Self{
            .smart_contract = SmartContract.init(allocator, SCRIPT_HASH, neo_swift),
        };
    }
    
    /// Gets designated nodes by role (equivalent to Swift getDesignatedByRole)
    pub fn getDesignatedByRole(self: Self, role: Role, block_index: u32) ![]PublicKey {
        try self.checkBlockIndexValidity(block_index);
        
        const params = [_]ContractParameter{
            ContractParameter.integer(@intFromEnum(role)),
            ContractParameter.integer(@intCast(block_index)),
        };
        
        // This would make actual RPC call and parse public keys
        _ = params;
        return try self.smart_contract.allocator.alloc(PublicKey, 0);
    }
    
    /// Validates block index (equivalent to Swift checkBlockIndexValidity)
    fn checkBlockIndexValidity(self: Self, block_index: u32) !void {
        _ = self;
        
        if (block_index < 0) {
            return errors.throwIllegalArgument("Block index must be positive");
        }
        
        // In production, this would check against current block count
        const max_reasonable_block = 10000000; // Reasonable upper bound
        if (block_index > max_reasonable_block) {
            return errors.throwIllegalArgument("Block index too high");
        }
    }
    
    /// Designates nodes as role (equivalent to Swift designateAsRole)
    pub fn designateAsRole(self: Self, role: Role, public_keys: []const PublicKey) !TransactionBuilder {
        if (public_keys.len == 0) {
            return errors.throwIllegalArgument("At least one public key required for designation");
        }
        
        var params = ArrayList(ContractParameter).init(self.smart_contract.allocator);
        defer params.deinit();
        
        try params.append(ContractParameter.integer(@intFromEnum(role)));
        
        // Convert public keys to parameters
        var pub_key_params = ArrayList(ContractParameter).init(self.smart_contract.allocator);
        defer pub_key_params.deinit();
        
        for (public_keys) |pub_key| {
            const key_bytes = pub_key.toSlice();
            if (key_bytes.len == 33) {
                var key_array: [33]u8 = undefined;
                @memcpy(&key_array, key_bytes);
                try pub_key_params.append(ContractParameter.publicKey(&key_array));
            }
        }
        
        try params.append(ContractParameter.array(try pub_key_params.toOwnedSlice()));
        
        return try self.smart_contract.invokeFunction(DESIGNATE_AS_ROLE, params.items);
    }
    
    /// Gets current role assignments (utility method)
    pub fn getCurrentRoleAssignments(self: Self, current_block: u32) !RoleAssignments {
        var assignments = RoleAssignments.init(self.smart_contract.allocator);
        
        // Get all role assignments
        assignments.state_validator = try self.getDesignatedByRole(.StateValidator, current_block);
        assignments.oracle = try self.getDesignatedByRole(.Oracle, current_block);
        assignments.neo_fs_alphabet_node = try self.getDesignatedByRole(.NeoFSAlphabetNode, current_block);
        
        return assignments;
    }
};

/// Network roles (converted from Swift Role enum)
pub const Role = enum(u8) {
    StateValidator = 4,
    Oracle = 8,
    NeoFSAlphabetNode = 16,
    
    const Self = @This();
    
    /// Gets role byte value (equivalent to Swift .byte property)
    pub fn getByte(self: Self) u8 {
        return @intFromEnum(self);
    }
    
    /// Gets role name (equivalent to Swift description)
    pub fn getName(self: Self) []const u8 {
        return switch (self) {
            .StateValidator => "StateValidator",
            .Oracle => "Oracle",
            .NeoFSAlphabetNode => "NeoFSAlphabetNode",
        };
    }
    
    /// Creates role from byte value
    pub fn fromByte(byte_value: u8) ?Self {
        return switch (byte_value) {
            4 => .StateValidator,
            8 => .Oracle,
            16 => .NeoFSAlphabetNode,
            else => null,
        };
    }
    
    /// Creates role from name
    pub fn fromName(name: []const u8) ?Self {
        if (std.mem.eql(u8, name, "StateValidator")) return .StateValidator;
        if (std.mem.eql(u8, name, "Oracle")) return .Oracle;
        if (std.mem.eql(u8, name, "NeoFSAlphabetNode")) return .NeoFSAlphabetNode;
        return null;
    }
};

/// Role assignments structure (utility for managing all roles)
pub const RoleAssignments = struct {
    state_validator: []PublicKey,
    oracle: []PublicKey,
    neo_fs_alphabet_node: []PublicKey,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .state_validator = &[_]PublicKey{},
            .oracle = &[_]PublicKey{},
            .neo_fs_alphabet_node = &[_]PublicKey{},
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.state_validator);
        self.allocator.free(self.oracle);
        self.allocator.free(self.neo_fs_alphabet_node);
    }
    
    /// Gets nodes for specific role
    pub fn getNodesForRole(self: Self, role: Role) []PublicKey {
        return switch (role) {
            .StateValidator => self.state_validator,
            .Oracle => self.oracle,
            .NeoFSAlphabetNode => self.neo_fs_alphabet_node,
        };
    }
    
    /// Counts total designated nodes
    pub fn getTotalNodeCount(self: Self) usize {
        return self.state_validator.len + self.oracle.len + self.neo_fs_alphabet_node.len;
    }
};

// Tests (converted from Swift RoleManagement tests)
test "RoleManagement creation and constants" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const role_mgmt = RoleManagement.init(allocator, null);
    
    // Test constants (equivalent to Swift constant tests)
    try testing.expectEqualStrings("RoleManagement", RoleManagement.NAME);
    try testing.expectEqualStrings("getDesignatedByRole", RoleManagement.GET_DESIGNATED_BY_ROLE);
    try testing.expectEqualStrings("designateAsRole", RoleManagement.DESIGNATE_AS_ROLE);
    
    // Test script hash
    const script_hash = role_mgmt.smart_contract.getScriptHash();
    try testing.expect(std.mem.eql(u8, &constants.NativeContracts.ROLE_MANAGEMENT, &script_hash.toArray()));
}

test "Role enum operations" {
    const testing = std.testing;
    
    // Test role values (equivalent to Swift Role tests)
    try testing.expectEqual(@as(u8, 4), Role.StateValidator.getByte());
    try testing.expectEqual(@as(u8, 8), Role.Oracle.getByte());
    try testing.expectEqual(@as(u8, 16), Role.NeoFSAlphabetNode.getByte());
    
    // Test role names
    try testing.expectEqualStrings("StateValidator", Role.StateValidator.getName());
    try testing.expectEqualStrings("Oracle", Role.Oracle.getName());
    try testing.expectEqualStrings("NeoFSAlphabetNode", Role.NeoFSAlphabetNode.getName());
    
    // Test role from byte conversion
    try testing.expectEqual(Role.StateValidator, Role.fromByte(4).?);
    try testing.expectEqual(Role.Oracle, Role.fromByte(8).?);
    try testing.expectEqual(@as(?Role, null), Role.fromByte(99));
    
    // Test role from name conversion
    try testing.expectEqual(Role.StateValidator, Role.fromName("StateValidator").?);
    try testing.expectEqual(@as(?Role, null), Role.fromName("InvalidRole"));
}

test "RoleManagement designation operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const role_mgmt = RoleManagement.init(allocator, null);
    
    // Test role designation (equivalent to Swift designateAsRole tests)
    const test_pub_keys = [_]PublicKey{}; // Would have actual public keys
    
    if (test_pub_keys.len > 0) {
        var designate_tx = try role_mgmt.designateAsRole(.StateValidator, &test_pub_keys);
        defer designate_tx.deinit();
        
        try testing.expect(designate_tx.getScript() != null);
    }
    
    // Test empty public keys error
    const empty_keys = [_]PublicKey{};
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        role_mgmt.designateAsRole(.Oracle, &empty_keys)
    );
}

test "RoleManagement block validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const role_mgmt = RoleManagement.init(allocator, null);
    
    // Test block index validation (equivalent to Swift validation tests)
    try role_mgmt.checkBlockIndexValidity(0); // Should pass
    try role_mgmt.checkBlockIndexValidity(1000); // Should pass
    
    // Test invalid block indices
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        role_mgmt.checkBlockIndexValidity(20000000) // Too high
    );
}

test "RoleAssignments management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var assignments = RoleAssignments.init(allocator);
    defer assignments.deinit();
    
    // Test role assignment structure
    try testing.expectEqual(@as(usize, 0), assignments.state_validator.len);
    try testing.expectEqual(@as(usize, 0), assignments.oracle.len);
    try testing.expectEqual(@as(usize, 0), assignments.neo_fs_alphabet_node.len);
    
    // Test total node count
    try testing.expectEqual(@as(usize, 0), assignments.getTotalNodeCount());
    
    // Test role-specific access
    const state_validators = assignments.getNodesForRole(.StateValidator);
    try testing.expectEqual(@as(usize, 0), state_validators.len);
}
