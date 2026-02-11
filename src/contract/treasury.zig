//! Treasury Contract implementation (v3.9.0+)
//!
//! Neo N3
//! Native contract for treasury fund management introduced in the Faun hardfork.
//! The Treasury is a passive fund holder that receives recovered funds from
//! blocked accounts. It supports NEP-26, NEP-27, and NEP-30 standards.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const SmartContract = @import("smart_contract.zig").SmartContract;

/// Treasury native contract (added in Neo N3 v3.9.0, Faun hardfork)
///
/// The Treasury contract is a passive fund holder. It receives funds recovered
/// from blocked accounts via PolicyContract.recoverFund(). The contract only
/// exposes verification and payment callbacks — it has no active fund
/// management methods.
///
/// Supported standards: NEP-26, NEP-27, NEP-30
pub const Treasury = struct {
    /// Contract name
    pub const NAME = "Treasury";

    /// Script hash
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.TREASURY };

    /// Method names
    pub const VERIFY = "verify";
    pub const ON_NEP17_PAYMENT = "onNEP17Payment";
    pub const ON_NEP11_PAYMENT = "onNEP11Payment";

    /// Base smart contract
    smart_contract: SmartContract,

    const Self = @This();

    /// Creates new Treasury instance
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

    /// Verifies that the transaction is signed by the committee.
    ///
    /// Requires an attached RPC client.
    pub fn verify(self: Self) !bool {
        return try self.smart_contract.callFunctionReturningBool(
            VERIFY,
            &[_]ContractParameter{},
        );
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Treasury creation and constants" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const treasury = Treasury.init(allocator, null);

    try testing.expectEqualStrings("Treasury", Treasury.NAME);
    try testing.expect(treasury.getScriptHash().eql(Treasury.SCRIPT_HASH));
    try testing.expect(treasury.isNativeContract());
}

test "Treasury verify requires RPC" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const treasury = Treasury.init(allocator, null);
    try testing.expectError(errors.NeoError.InvalidConfiguration, treasury.verify());
}
