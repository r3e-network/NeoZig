//! Role Management Contract implementation
//!
//! Neo N3 
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
const NeoClient = @import("../rpc/neo_client.zig").NeoClient;
const Role = @import("../types/role.zig").Role;
const Signer = @import("../transaction/transaction_builder.zig").Signer;

/// Role management contract
pub const RoleManagement = struct {
    /// Contract name
    pub const NAME = "RoleManagement";

    /// Script hash
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.ROLE_MANAGEMENT };

    /// Method names
    pub const GET_DESIGNATED_BY_ROLE = "getDesignatedByRole";
    pub const DESIGNATE_AS_ROLE = "designateAsRole";

    /// Base smart contract
    smart_contract: SmartContract,

    const Self = @This();

    /// Creates new RoleManagement instance
    pub fn init(allocator: std.mem.Allocator, client: ?*anyopaque) Self {
        return Self{
            .smart_contract = SmartContract.init(allocator, SCRIPT_HASH, client),
        };
    }

    /// Gets script hash for this contract.
    pub fn getScriptHash(self: Self) Hash160 {
        return self.smart_contract.getScriptHash();
    }

    /// Validates the underlying contract configuration.
    pub fn validate(self: Self) !void {
        try self.smart_contract.validate();
        if (!self.smart_contract.getScriptHash().eql(SCRIPT_HASH)) {
            return errors.ContractError.InvalidContract;
        }
    }

    /// Returns true if this contract is native.
    pub fn isNativeContract(self: Self) bool {
        return self.smart_contract.isNativeContract();
    }

    /// Gets designated nodes by role
    pub fn getDesignatedByRole(self: Self, role: Role, block_index: u32) ![]PublicKey {
        try self.checkBlockIndexValidity(block_index);

        const params = [_]ContractParameter{
            ContractParameter.integer(@intFromEnum(role)),
            ContractParameter.integer(@intCast(block_index)),
        };

        if (self.smart_contract.client == null) return errors.NeoError.InvalidConfiguration;

        const client: *NeoClient = @ptrCast(@alignCast(self.smart_contract.client.?));
        var request = try client.invokeFunction(
            SCRIPT_HASH,
            GET_DESIGNATED_BY_ROLE,
            &params,
            &[_]Signer{},
        );
        var invocation = try request.send();
        const service_allocator = client.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        const items = try stack_item.getArray();
        var keys = try self.smart_contract.allocator.alloc(PublicKey, items.len);
        errdefer self.smart_contract.allocator.free(keys);

        for (items, 0..) |item, i| {
            const bytes = switch (item) {
                .ByteString, .Buffer => |b| b,
                else => return errors.SerializationError.InvalidFormat,
            };
            keys[i] = try PublicKey.initFromBytes(bytes);
        }

        return keys;
    }

    /// Validates block index range.
    fn checkBlockIndexValidity(_: Self, block_index: u32) !void {
        // u32 is inherently non-negative; only upper-bound check is needed.
        const max_reasonable_block: u32 = 10_000_000;
        if (block_index > max_reasonable_block) {
            return errors.throwIllegalArgument("Block index too high");
        }
    }

    /// Designates nodes as role
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
                try pub_key_params.append(try ContractParameter.publicKey(&key_array));
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

// Role is imported from types/role.zig (single source of truth)

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

// Tests
test "RoleManagement creation and constants" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const role_mgmt = RoleManagement.init(allocator, null);

    // Test constants
    try testing.expectEqualStrings("RoleManagement", RoleManagement.NAME);
    try testing.expectEqualStrings("getDesignatedByRole", RoleManagement.GET_DESIGNATED_BY_ROLE);
    try testing.expectEqualStrings("designateAsRole", RoleManagement.DESIGNATE_AS_ROLE);

    // Test script hash
    const script_hash = role_mgmt.smart_contract.getScriptHash();
    try testing.expect(std.mem.eql(u8, &constants.NativeContracts.ROLE_MANAGEMENT, &script_hash.toArray()));
}

test "Role enum operations" {
    const testing = std.testing;

    // Test role values
    try testing.expectEqual(@as(u8, 4), Role.StateValidator.toByte());
    try testing.expectEqual(@as(u8, 8), Role.Oracle.toByte());
    try testing.expectEqual(@as(u8, 16), Role.NeoFSAlphabetNode.toByte());

    // Test role names
    try testing.expectEqualStrings("StateValidator", Role.StateValidator.toJsonString());
    try testing.expectEqualStrings("Oracle", Role.Oracle.toJsonString());
    try testing.expectEqualStrings("NeoFSAlphabetNode", Role.NeoFSAlphabetNode.toJsonString());

    // Test role from byte conversion
    try testing.expectEqual(Role.StateValidator, Role.fromByte(4).?);
    try testing.expectEqual(Role.Oracle, Role.fromByte(8).?);
    try testing.expectEqual(@as(?Role, null), Role.fromByte(99));

    // Test role from name conversion
    try testing.expectEqual(Role.StateValidator, Role.fromJsonString("StateValidator").?);
    try testing.expectEqual(@as(?Role, null), Role.fromJsonString("InvalidRole"));
}

test "RoleManagement designation operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const role_mgmt = RoleManagement.init(allocator, null);

    // Test role designation
    const test_pub_keys = [_]PublicKey{}; // Would have actual public keys

    if (test_pub_keys.len > 0) {
        var designate_tx = try role_mgmt.designateAsRole(.StateValidator, &test_pub_keys);
        defer designate_tx.deinit();

        try testing.expect(designate_tx.getScript() != null);
    }

    // Test empty public keys error
    const empty_keys = [_]PublicKey{};
    try testing.expectError(errors.NeoError.IllegalArgument, role_mgmt.designateAsRole(.Oracle, &empty_keys));
}

test "RoleManagement block validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const role_mgmt = RoleManagement.init(allocator, null);

    // Test block index validation
    try role_mgmt.checkBlockIndexValidity(0); // Should pass
    try role_mgmt.checkBlockIndexValidity(1000); // Should pass

    // Test invalid block indices
    try testing.expectError(errors.NeoError.IllegalArgument, role_mgmt.checkBlockIndexValidity(20000000) // Too high
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
