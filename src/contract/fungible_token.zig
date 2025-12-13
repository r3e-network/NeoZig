//! Fungible Token (NEP-17) implementation
//!
//! Complete conversion from NeoSwift FungibleToken.swift
//! Handles NEP-17 fungible token operations and transfers.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const SmartContract = @import("smart_contract.zig").SmartContract;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const Token = @import("token.zig").Token;

/// Fungible token contract (converted from Swift FungibleToken)
pub const FungibleToken = struct {
    /// Method names (match Swift constants)
    pub const BALANCE_OF = "balanceOf";
    pub const TRANSFER = "transfer";
    
    /// Base token contract
    token: Token,
    
    const Self = @This();
    
    /// Creates new FungibleToken instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, script_hash: Hash160, neo_swift: ?*anyopaque) Self {
        return Self{
            .token = Token.init(allocator, script_hash, neo_swift),
        };
    }
    
    /// Gets balance for account (equivalent to Swift getBalanceOf(_ account: Account))
    pub fn getBalanceOfAccount(self: Self, account: Account) !i64 {
        return try self.getBalanceOf(account.getScriptHash());
    }
    
    /// Gets balance for script hash (equivalent to Swift getBalanceOf(_ scriptHash: Hash160))
    pub fn getBalanceOf(self: Self, script_hash: Hash160) !i64 {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};
        return try self.token.smart_contract.callFunctionReturningInt(BALANCE_OF, &params);
    }
    
    /// Gets balance for wallet (equivalent to Swift getBalanceOf(_ wallet: Wallet))
    pub fn getBalanceOfWallet(self: Self, wallet: Wallet) !i64 {
        var sum: i64 = 0;
        const accounts = try wallet.getAccounts(self.token.smart_contract.allocator);
        defer self.token.smart_contract.allocator.free(accounts);
        
        for (accounts) |account| {
            sum += try self.getBalanceOfAccount(account);
        }
        
        return sum;
    }
    
    /// Creates transfer transaction with account (equivalent to Swift transfer(_ from: Account, _ to: Hash160, _ amount: Int, _ data: ContractParameter?))
    pub fn transferFromAccount(
        self: Self,
        from: Account,
        to: Hash160,
        amount: i64,
        data: ?ContractParameter,
    ) !TransactionBuilder {
        var tx_builder = try self.transfer(from.getScriptHash(), to, amount, data);
        
        // Add account signer (equivalent to Swift AccountSigner.calledByEntry)
        const signer = @import("../transaction/transaction_builder.zig").Signer.init(
            from.getScriptHash(),
            @import("../transaction/transaction_builder.zig").WitnessScope.CalledByEntry,
        );
        _ = try tx_builder.signer(signer);
        
        return tx_builder;
    }
    
    /// Creates transfer transaction with script hash (equivalent to Swift transfer(_ from: Hash160, _ to: Hash160, _ amount: Int, _ data: ContractParameter?))
    pub fn transfer(
        self: Self,
        from: Hash160,
        to: Hash160,
        amount: i64,
        data: ?ContractParameter,
    ) !TransactionBuilder {
        var params = ArrayList(ContractParameter).init(self.token.smart_contract.allocator);
        defer params.deinit();
        
        try params.append(ContractParameter.hash160(from));
        try params.append(ContractParameter.hash160(to));
        try params.append(ContractParameter.integer(amount));
        
        if (data) |transfer_data| {
            try params.append(transfer_data);
        }
        
        return try self.token.smart_contract.invokeFunction(TRANSFER, params.items);
    }
    
    /// Multi-transfer operation (equivalent to Swift multiTransfer)
    pub fn multiTransfer(
        self: Self,
        from: Hash160,
        recipients: []const TransferRecipient,
    ) !TransactionBuilder {
        if (recipients.len == 0) {
            return errors.TransactionError.InvalidTransaction;
        }

        var aggregated_script = ArrayList(u8).init(self.token.smart_contract.allocator);
        defer aggregated_script.deinit();

        for (recipients) |recipient| {
            var params = ArrayList(ContractParameter).init(self.token.smart_contract.allocator);
            defer params.deinit();

            try params.append(ContractParameter.hash160(from));
            try params.append(ContractParameter.hash160(recipient.to));
            try params.append(ContractParameter.integer(recipient.amount));

            if (recipient.data) |payload| {
                try params.append(payload);
            }

            const script = try self.token.smart_contract.buildInvokeFunctionScript(TRANSFER, params.items);
            defer self.token.smart_contract.allocator.free(script);
            try aggregated_script.appendSlice(script);
        }

        var builder = TransactionBuilder.init(self.token.smart_contract.allocator);
        _ = try builder.script(aggregated_script.items);
        return builder;
    }
    
    /// Gets token information (equivalent to Swift token info methods)
    pub fn getSymbol(self: Self) ![]u8 {
        return try self.token.getSymbol();
    }
    
    pub fn getDecimals(self: Self) !u8 {
        return try self.token.getDecimals();
    }
    
    pub fn getTotalSupply(self: Self) !i64 {
        return try self.token.getTotalSupply();
    }
};

/// Transfer recipient structure (converted from Swift transfer patterns)
pub const TransferRecipient = struct {
    to: Hash160,
    amount: i64,
    data: ?ContractParameter,
    
    const Self = @This();
    
    pub fn init(to: Hash160, amount: i64, data: ?ContractParameter) Self {
        return Self{
            .to = to,
            .amount = amount,
            .data = data,
        };
    }
};

// Import after definitions to avoid circular dependencies
const Account = @import("../transaction/transaction_builder.zig").Account;
const Wallet = @import("../wallet/neo_wallet.zig").Wallet;

// Tests (converted from Swift FungibleToken tests)
test "FungibleToken creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token_hash = try Hash160.initWithString("d2a4cff31913016155e38e474a2c06d08be276cf"); // GAS token
    const fungible_token = FungibleToken.init(allocator, token_hash, null);
    
    // Test balance query (stub implementation returns a mocked value)
    const test_script_hash = Hash160.ZERO;
    const balance = try fungible_token.getBalanceOf(test_script_hash);
    try testing.expect(balance >= 0);
}

test "FungibleToken transfer operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token_hash = Hash160.ZERO;
    const fungible_token = FungibleToken.init(allocator, token_hash, null);
    
    // Test transfer transaction building (equivalent to Swift transfer tests)
    var transfer_tx = try fungible_token.transfer(
        Hash160.ZERO, // from
        Hash160.ZERO, // to
        100000000,    // 1 token (8 decimals)
        null,         // no data
    );
    defer transfer_tx.deinit();
    
    // Should have script for transfer
    try testing.expect(transfer_tx.getScript() != null);
    try testing.expect(transfer_tx.getScript().?.len > 0);
    
    // Test transfer with data
    const transfer_data = ContractParameter.string("transfer_memo");
    var transfer_with_data_tx = try fungible_token.transfer(
        Hash160.ZERO,
        Hash160.ZERO,
        50000000,
        transfer_data,
    );
    defer transfer_with_data_tx.deinit();
    
    try testing.expect(transfer_with_data_tx.getScript() != null);
}

test "FungibleToken multi-transfer operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token_hash = Hash160.ZERO;
    const fungible_token = FungibleToken.init(allocator, token_hash, null);
    
    const recipients = [_]TransferRecipient{
        TransferRecipient.init(Hash160.ZERO, 1000000, null),
        TransferRecipient.init(Hash160.ZERO, 2000000, null),
    };
    
    var multi_transfer_tx = try fungible_token.multiTransfer(Hash160.ZERO, &recipients);
    defer multi_transfer_tx.deinit();
    
    try testing.expect(multi_transfer_tx.getScript() != null);
}

test "FungibleToken token information" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token_hash = Hash160.ZERO;
    const fungible_token = FungibleToken.init(allocator, token_hash, null);
    
    const symbol = try fungible_token.getSymbol();
    defer allocator.free(symbol);
    try testing.expectEqualStrings("UNKNOWN", symbol);
    
    const decimals = try fungible_token.getDecimals();
    try testing.expect(decimals <= 18);
    
    const total_supply = try fungible_token.getTotalSupply();
    try testing.expect(total_supply >= 0);
}
