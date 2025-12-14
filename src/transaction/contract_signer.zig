//! Contract Signer implementation
//!
//! Complete conversion from NeoSwift ContractSigner.swift
//! Provides smart contract-based transaction signing capabilities.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const Signer = @import("transaction_builder.zig").Signer;
const WitnessScope = @import("transaction_builder.zig").WitnessScope;

/// Contract signer for smart contract verification (converted from Swift ContractSigner)
pub const ContractSigner = struct {
    /// Verification parameters for contract's verify() method
    verify_params: []const ContractParameter,
    /// Base signer
    signer: Signer,

    allocator: std.mem.Allocator,

    const Self = @This();

    /// Creates contract signer (equivalent to Swift private init)
    fn initPrivate(
        allocator: std.mem.Allocator,
        contract_hash: Hash160,
        scope: WitnessScope,
        verify_params: []const ContractParameter,
    ) Self {
        const signer = Signer.init(contract_hash, scope);

        return Self{
            .verify_params = verify_params,
            .signer = signer,
            .allocator = allocator,
        };
    }

    /// Creates signer with calledByEntry scope (equivalent to Swift calledByEntry)
    pub fn calledByEntry(
        allocator: std.mem.Allocator,
        contract_hash: Hash160,
        verify_params: []const ContractParameter,
    ) !Self {
        const params_copy = try allocator.dupe(ContractParameter, verify_params);
        return initPrivate(allocator, contract_hash, .CalledByEntry, params_copy);
    }

    /// Creates signer with global scope (equivalent to Swift global)
    pub fn global(
        allocator: std.mem.Allocator,
        contract_hash: Hash160,
        verify_params: []const ContractParameter,
    ) !Self {
        const params_copy = try allocator.dupe(ContractParameter, verify_params);
        return initPrivate(allocator, contract_hash, .Global, params_copy);
    }

    /// Creates signer with custom contracts scope (additional utility)
    pub fn customContracts(
        allocator: std.mem.Allocator,
        contract_hash: Hash160,
        verify_params: []const ContractParameter,
        allowed_contracts: []const Hash160,
    ) !Self {
        var signer = initPrivate(allocator, contract_hash, .CustomContracts, try allocator.dupe(ContractParameter, verify_params));
        signer.signer.allowed_contracts = allowed_contracts;
        return signer;
    }

    /// Creates signer with custom groups scope (additional utility)
    pub fn customGroups(
        allocator: std.mem.Allocator,
        contract_hash: Hash160,
        verify_params: []const ContractParameter,
        allowed_groups: []const [33]u8,
    ) !Self {
        var signer = initPrivate(allocator, contract_hash, .CustomGroups, try allocator.dupe(ContractParameter, verify_params));
        signer.signer.allowed_groups = allowed_groups;
        return signer;
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.verify_params);
    }

    /// Gets verification parameters (equivalent to Swift .verifyParams property)
    pub fn getVerifyParams(self: Self) []const ContractParameter {
        return self.verify_params;
    }

    /// Gets contract hash (equivalent to Swift contract hash access)
    pub fn getContractHash(self: Self) Hash160 {
        return self.signer.signer_hash;
    }

    /// Gets witness scope (equivalent to Swift scope access)
    pub fn getWitnessScope(self: Self) WitnessScope {
        return self.signer.scopes;
    }

    /// Gets base signer (equivalent to Swift base signer access)
    pub fn getSigner(self: Self) Signer {
        return self.signer;
    }

    /// Validates contract signer configuration (equivalent to Swift validation)
    pub fn validate(self: Self) !void {
        try self.signer.validate();

        // Validate verification parameters
        for (self.verify_params) |param| {
            try param.validate();
        }

        // Additional contract-specific validation
        if (self.verify_params.len > 16) { // Reasonable limit
            return errors.TransactionError.InvalidSigner;
        }
    }

    /// Builds verification script invocation (equivalent to Swift script building)
    pub fn buildVerificationInvocation(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var script_builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
        defer script_builder.deinit();

        // Push verification parameters in reverse order
        var i = self.verify_params.len;
        while (i > 0) {
            i -= 1;
            _ = try script_builder.pushParam(self.verify_params[i]);
        }

        // Call verify method
        _ = try script_builder.contractCall(
            self.signer.signer_hash,
            "verify",
            &[_]ContractParameter{},
            @import("../types/call_flags.zig").CallFlags.None,
        );

        return try allocator.dupe(u8, script_builder.toScript());
    }

    /// Converts to base signer for transaction use
    pub fn toSigner(self: Self) Signer {
        return self.signer;
    }

    /// Checks if signer can verify in context
    pub fn canVerifyInContext(self: Self, calling_contract: ?Hash160) bool {
        return switch (self.signer.scopes) {
            .Global => true,
            .CalledByEntry => calling_contract == null, // Entry context
            .CustomContracts => blk: {
                if (calling_contract == null) break :blk false;
                for (self.signer.allowed_contracts) |allowed| {
                    if (allowed.eql(calling_contract.?)) break :blk true;
                }
                break :blk false;
            },
            .None => false, // Contract signers need scope
            else => false,
        };
    }

    /// Creates verification context (additional utility)
    pub fn createVerificationContext(self: Self, allocator: std.mem.Allocator) !ContractVerificationContext {
        return ContractVerificationContext{
            .contract_hash = self.signer.signer_hash,
            .scope = self.signer.scopes,
            .parameters = try allocator.dupe(ContractParameter, self.verify_params),
            .allocator = allocator,
        };
    }
};

/// Contract verification context (additional utility)
pub const ContractVerificationContext = struct {
    contract_hash: Hash160,
    scope: WitnessScope,
    parameters: []const ContractParameter,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.parameters);
    }

    /// Checks if context is valid for verification
    pub fn isValidForVerification(self: Self) bool {
        // Basic validation
        if (self.scope == .None) return false;

        // All parameters must be valid
        for (self.parameters) |param| {
            param.validate() catch return false;
        }

        return true;
    }

    /// Gets parameter count
    pub fn getParameterCount(self: Self) usize {
        return self.parameters.len;
    }

    /// Gets specific parameter
    pub fn getParameter(self: Self, index: usize) ?ContractParameter {
        if (index >= self.parameters.len) return null;
        return self.parameters[index];
    }
};

/// Contract signer factory (utility methods)
pub const ContractSignerFactory = struct {
    /// Creates signer for token contract operations
    pub fn createForTokenContract(
        allocator: std.mem.Allocator,
        token_contract: Hash160,
        operation: TokenOperation,
    ) !ContractSigner {
        const params = switch (operation) {
            .Transfer => &[_]ContractParameter{},
            .Mint => &[_]ContractParameter{},
            .Burn => &[_]ContractParameter{},
        };

        return try ContractSigner.calledByEntry(allocator, token_contract, params);
    }

    /// Creates signer for governance operations
    pub fn createForGovernance(
        allocator: std.mem.Allocator,
        governance_contract: Hash160,
        voter_params: []const ContractParameter,
    ) !ContractSigner {
        return try ContractSigner.global(allocator, governance_contract, voter_params);
    }

    /// Creates signer for custom contract verification
    pub fn createForCustomVerification(
        allocator: std.mem.Allocator,
        contract_hash: Hash160,
        scope: WitnessScope,
        custom_params: []const ContractParameter,
    ) !ContractSigner {
        return switch (scope) {
            .CalledByEntry => try ContractSigner.calledByEntry(allocator, contract_hash, custom_params),
            .Global => try ContractSigner.global(allocator, contract_hash, custom_params),
            else => error.UnsupportedScope,
        };
    }
};

/// Token operation types
pub const TokenOperation = enum {
    Transfer,
    Mint,
    Burn,
};

// Tests (converted from Swift ContractSigner tests)
test "ContractSigner creation with different scopes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_hash = Hash160.ZERO;
    const verify_params = [_]ContractParameter{
        ContractParameter.string("test_param"),
        ContractParameter.integer(42),
    };

    // Test calledByEntry scope (equivalent to Swift calledByEntry tests)
    var entry_signer = try ContractSigner.calledByEntry(allocator, contract_hash, &verify_params);
    defer entry_signer.deinit();

    try testing.expectEqual(WitnessScope.CalledByEntry, entry_signer.getWitnessScope());
    try testing.expect(entry_signer.getContractHash().eql(contract_hash));
    try testing.expectEqual(@as(usize, 2), entry_signer.getVerifyParams().len);

    // Test global scope (equivalent to Swift global tests)
    var global_signer = try ContractSigner.global(allocator, contract_hash, &verify_params);
    defer global_signer.deinit();

    try testing.expectEqual(WitnessScope.Global, global_signer.getWitnessScope());
    try testing.expect(global_signer.getContractHash().eql(contract_hash));
}

test "ContractSigner validation and verification" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const valid_params = [_]ContractParameter{
        ContractParameter.boolean(true),
        ContractParameter.hash160(Hash160.ZERO),
    };

    var contract_signer = try ContractSigner.calledByEntry(allocator, contract_hash, &valid_params);
    defer contract_signer.deinit();

    // Test validation (equivalent to Swift validation tests)
    try contract_signer.validate();

    // Test verification context
    var verification_context = try contract_signer.createVerificationContext(allocator);
    defer verification_context.deinit();

    try testing.expect(verification_context.isValidForVerification());
    try testing.expectEqual(@as(usize, 2), verification_context.getParameterCount());

    const first_param = verification_context.getParameter(0);
    try testing.expect(first_param != null);
    try testing.expectEqual(@import("../types/contract_parameter.zig").ContractParameterType.Boolean, first_param.?.getType());
}

test "ContractSigner verification script building" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_hash = Hash160.ZERO;
    const verify_params = [_]ContractParameter{
        ContractParameter.string("verification_test"),
    };

    var contract_signer = try ContractSigner.calledByEntry(allocator, contract_hash, &verify_params);
    defer contract_signer.deinit();

    // Test verification script building (equivalent to Swift script tests)
    const verification_script = try contract_signer.buildVerificationInvocation(allocator);
    defer allocator.free(verification_script);

    try testing.expect(verification_script.len > 0);

    // Should contain contract call elements
    try testing.expect(std.mem.indexOf(u8, verification_script, &[_]u8{0x41}) != null); // SYSCALL opcode
}

test "ContractSigner context validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_hash = Hash160.ZERO;
    const verify_params = [_]ContractParameter{};

    // Test context validation (equivalent to Swift context tests)
    var entry_signer = try ContractSigner.calledByEntry(allocator, contract_hash, &verify_params);
    defer entry_signer.deinit();

    // Test verification in different contexts
    try testing.expect(entry_signer.canVerifyInContext(null)); // Entry context
    try testing.expect(!entry_signer.canVerifyInContext(Hash160.ZERO)); // Contract context

    var global_signer = try ContractSigner.global(allocator, contract_hash, &verify_params);
    defer global_signer.deinit();

    try testing.expect(global_signer.canVerifyInContext(null)); // Any context
    try testing.expect(global_signer.canVerifyInContext(Hash160.ZERO)); // Any context
}

test "ContractSignerFactory utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const token_contract = try Hash160.initWithString("d2a4cff31913016155e38e474a2c06d08be276cf");

    // Test token contract signer creation
    var token_signer = try ContractSignerFactory.createForTokenContract(
        allocator,
        token_contract,
        .Transfer,
    );
    defer token_signer.deinit();

    try testing.expect(token_signer.getContractHash().eql(token_contract));
    try testing.expectEqual(WitnessScope.CalledByEntry, token_signer.getWitnessScope());

    // Test governance signer creation
    const governance_params = [_]ContractParameter{
        ContractParameter.hash160(Hash160.ZERO),
    };

    var governance_signer = try ContractSignerFactory.createForGovernance(
        allocator,
        constants.NativeContracts.NEO_TOKEN,
        &governance_params,
    );
    defer governance_signer.deinit();

    try testing.expectEqual(WitnessScope.Global, governance_signer.getWitnessScope());
    try testing.expectEqual(@as(usize, 1), governance_signer.getVerifyParams().len);
}
