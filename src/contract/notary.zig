//! Notary Contract implementation (v3.9.0+)
//!
//! Neo N3
//! Native contract for notary service operations introduced in the Faun hardfork.
//! Provides transaction co-signing and fee management for notary-assisted transactions.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const SmartContract = @import("smart_contract.zig").SmartContract;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;

/// Notary native contract (added in Neo N3 v3.9.0, Faun hardfork)
///
/// The Notary contract enables notary-assisted transactions where a designated
/// notary node co-signs transactions on behalf of participants, simplifying
/// multi-party workflows.
pub const Notary = struct {
    /// Contract name
    pub const NAME = "Notary";

    /// Script hash
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.NOTARY };

    /// Method names
    pub const VERIFY = "verify";
    pub const LOCK_DEPOSIT_UNTIL = "lockDepositUntil";
    pub const WITHDRAW = "withdraw";
    pub const BALANCE_OF = "balanceOf";
    pub const EXPIRATION_OF = "expirationOf";
    pub const GET_MAX_NOT_VALID_BEFORE_DELTA = "getMaxNotValidBeforeDelta";
    pub const SET_MAX_NOT_VALID_BEFORE_DELTA = "setMaxNotValidBeforeDelta";
    pub const ON_NEP17_PAYMENT = "onNEP17Payment";

    /// Base smart contract
    smart_contract: SmartContract,

    const Self = @This();

    /// Creates new Notary instance
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

    /// Locks a deposit until the specified block height.
    pub fn lockDepositUntil(
        self: Self,
        account: Hash160,
        till: u32,
    ) !TransactionBuilder {
        const params = [_]ContractParameter{
            ContractParameter.hash160(account),
            ContractParameter.integer(@intCast(till)),
        };
        return try self.smart_contract.invokeFunction(LOCK_DEPOSIT_UNTIL, &params);
    }

    /// Withdraws notary deposit to the specified account.
    /// If `to` is null, funds are sent back to `from`.
    pub fn withdraw(
        self: Self,
        from: Hash160,
        to: ?Hash160,
    ) !TransactionBuilder {
        if (to) |to_hash| {
            const params = [_]ContractParameter{
                ContractParameter.hash160(from),
                ContractParameter.hash160(to_hash),
            };
            return try self.smart_contract.invokeFunction(WITHDRAW, &params);
        } else {
            const params = [_]ContractParameter{
                ContractParameter.hash160(from),
                .{ .Any = {} },
            };
            return try self.smart_contract.invokeFunction(WITHDRAW, &params);
        }
    }

    /// Gets the notary deposit balance for an account.
    ///
    /// Requires an attached RPC client.
    pub fn balanceOf(self: Self, account: Hash160) !i64 {
        const params = [_]ContractParameter{ContractParameter.hash160(account)};
        return try self.smart_contract.callFunctionReturningInt(BALANCE_OF, &params);
    }

    /// Gets the deposit expiration block height for an account.
    ///
    /// Requires an attached RPC client.
    pub fn expirationOf(self: Self, account: Hash160) !i64 {
        const params = [_]ContractParameter{ContractParameter.hash160(account)};
        return try self.smart_contract.callFunctionReturningInt(EXPIRATION_OF, &params);
    }

    /// Gets the maximum `not_valid_before` delta value.
    ///
    /// Requires an attached RPC client.
    pub fn getMaxNotValidBeforeDelta(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(
            GET_MAX_NOT_VALID_BEFORE_DELTA,
            &[_]ContractParameter{},
        );
    }

    /// Sets the maximum `not_valid_before` delta value (committee-only).
    pub fn setMaxNotValidBeforeDelta(self: Self, value: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(value)};
        return try self.smart_contract.invokeFunction(SET_MAX_NOT_VALID_BEFORE_DELTA, &params);
    }

    /// Verifies that the transaction is signed by a notary node and that
    /// the deposited GAS covers the transaction fees.
    ///
    /// Requires an attached RPC client.
    pub fn verify(self: Self, signature: []const u8) !bool {
        const params = [_]ContractParameter{ContractParameter.byteArray(signature)};
        return try self.smart_contract.callFunctionReturningBool(VERIFY, &params);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Notary creation and constants" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const notary = Notary.init(allocator, null);

    try testing.expectEqualStrings("Notary", Notary.NAME);
    try testing.expect(notary.getScriptHash().eql(Notary.SCRIPT_HASH));
    try testing.expect(notary.isNativeContract());
}

test "Notary deposit operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const notary = Notary.init(allocator, null);

    // Read operations require RPC client
    try testing.expectError(errors.NeoError.InvalidConfiguration, notary.balanceOf(Hash160.ZERO));
    try testing.expectError(errors.NeoError.InvalidConfiguration, notary.expirationOf(Hash160.ZERO));
    try testing.expectError(errors.NeoError.InvalidConfiguration, notary.getMaxNotValidBeforeDelta());
    try testing.expectError(errors.NeoError.InvalidConfiguration, notary.verify("test"));

    // Write operations build transaction scripts without RPC
    var lock_tx = try notary.lockDepositUntil(Hash160.ZERO, 100_000);
    defer lock_tx.deinit();
    try testing.expect(lock_tx.getScript() != null);

    // withdraw with explicit `to`
    var withdraw_tx = try notary.withdraw(Hash160.ZERO, Hash160.ZERO);
    defer withdraw_tx.deinit();
    try testing.expect(withdraw_tx.getScript() != null);

    // withdraw with null `to` (sends back to `from`)
    var withdraw_null_tx = try notary.withdraw(Hash160.ZERO, null);
    defer withdraw_null_tx.deinit();
    try testing.expect(withdraw_null_tx.getScript() != null);

    var delta_tx = try notary.setMaxNotValidBeforeDelta(140);
    defer delta_tx.deinit();
    try testing.expect(delta_tx.getScript() != null);
}
