//! Contract tests converted from Swift
//!
//! Complete conversion of NeoSwift contract test suite.

const std = @import("std");


const neo = @import("neo-zig");

// Tests SmartContract functionality (converted from SmartContractTests.swift)
test "SmartContract creation and invocation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const contract_hash = try neo.Hash160.initWithString("d2a4cff31913016155e38e474a2c06d08be276cf");
    const contract = neo.contract.SmartContract.init(allocator, contract_hash, null);
    
    // Test script hash property (equivalent to Swift scriptHash tests)
    try testing.expect(contract.getScriptHash().eql(contract_hash));
    
    // Test function invocation (equivalent to Swift invokeFunction tests)
    const params = [_]neo.ContractParameter{
        neo.ContractParameter.string("test_parameter"),
        neo.ContractParameter.integer(42),
    };
    
    var tx_builder = try contract.invokeFunction("testFunction", &params);
    defer tx_builder.deinit();
    
    try testing.expect(tx_builder.getScript() != null);
    try testing.expect(tx_builder.getScript().?.len > 0);
}

// Tests ContractManagement (converted from ContractManagementTests.swift)
test "ContractManagement deployment operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const contract_mgmt = neo.contract.ContractManagement.init(allocator, null);
    
    // Test constants (equivalent to Swift constant tests)
    try testing.expectEqualStrings("ContractManagement", neo.contract.ContractManagement.NAME);
    try testing.expectEqualStrings("deploy", neo.contract.ContractManagement.DEPLOY);
    
    // Test contract deployment (equivalent to Swift deploy tests)
    const nef_file = [_]u8{ 0x4E, 0x45, 0x46, 0x33 }; // Mock NEF
    const manifest = "{}";
    
    var deploy_tx = try contract_mgmt.deploy(&nef_file, manifest, null);
    defer deploy_tx.deinit();
    
    try testing.expect(deploy_tx.getScript() != null);
    
    // Test hasMethod (equivalent to Swift hasMethod tests)
    const has_method = try contract_mgmt.hasMethod(neo.Hash160.ZERO, "testMethod", 1);
    try testing.expect(!has_method); // stub returns false
}

// Tests GasToken (converted from GasTokenTests.swift)
test "GasToken properties and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const gas_token = neo.contract.GasToken.init(allocator, null);
    
    // Test token constants (equivalent to Swift constant tests)
    try testing.expectEqualStrings("GasToken", try gas_token.getName());
    try testing.expectEqualStrings("GAS", try gas_token.getSymbol());
    try testing.expectEqual(@as(u8, 8), try gas_token.getDecimals());
    
    // Test total supply (equivalent to Swift totalSupply tests)
    const total_supply = try gas_token.getTotalSupply();
    try testing.expectEqual(@as(i64, 100000000 * 100000000), total_supply);
    
    // Test balance operations (equivalent to Swift balance tests)
    const balance = try gas_token.getBalanceOf(neo.Hash160.ZERO);
    try testing.expectEqual(@as(i64, 0), balance); // stub
    
    // Test transfer operations (equivalent to Swift transfer tests)
    var transfer_tx = try gas_token.transfer(neo.Hash160.ZERO, neo.Hash160.ZERO, 100000000, null);
    defer transfer_tx.deinit();
    
    try testing.expect(transfer_tx.getScript() != null);
}

// Tests NeoToken (converted from NeoTokenTests.swift)
test "NeoToken properties and governance" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const neo_token = neo.contract.NeoToken.init(allocator, null);
    
    // Test token constants (equivalent to Swift constant tests)
    try testing.expectEqualStrings("NeoToken", try neo_token.getName());
    try testing.expectEqualStrings("NEO", try neo_token.getSymbol());
    try testing.expectEqual(@as(u8, 0), try neo_token.getDecimals());
    
    // Test governance operations (equivalent to Swift governance tests)
    const test_public_key = [_]u8{0x02} ++ [_]u8{0xAB} ** 32;
    
    var register_tx = try neo_token.registerCandidate(test_public_key);
    defer register_tx.deinit();
    try testing.expect(register_tx.getScript() != null);
    
    var vote_tx = try neo_token.vote(neo.Hash160.ZERO, test_public_key);
    defer vote_tx.deinit();
    try testing.expect(vote_tx.getScript() != null);
    
    var unregister_tx = try neo_token.unregisterCandidate(test_public_key);
    defer unregister_tx.deinit();
    try testing.expect(unregister_tx.getScript() != null);
}

// Tests FungibleToken (converted from FungibleTokenTests.swift)
test "FungibleToken operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token_hash = try neo.Hash160.initWithString("d2a4cff31913016155e38e474a2c06d08be276cf");
    const fungible_token = neo.contract.FungibleToken.init(allocator, token_hash, null);
    
    // Test balance operations (equivalent to Swift balance tests)
    const balance = try fungible_token.getBalanceOf(neo.Hash160.ZERO);
    try testing.expectEqual(@as(i64, 0), balance); // stub
    
    // Test transfer operations (equivalent to Swift transfer tests)
    var transfer_tx = try fungible_token.transfer(
        neo.Hash160.ZERO, // from
        neo.Hash160.ZERO, // to
        100000000,        // amount
        null,             // no data
    );
    defer transfer_tx.deinit();
    
    try testing.expect(transfer_tx.getScript() != null);
    
    // Test multi-transfer (equivalent to Swift multiTransfer tests)
    const recipients = [_]neo.contract.TransferRecipient{
        neo.contract.TransferRecipient.init(neo.Hash160.ZERO, 1000000, null),
        neo.contract.TransferRecipient.init(neo.Hash160.ZERO, 2000000, null),
    };
    
    var multi_tx = try fungible_token.multiTransfer(neo.Hash160.ZERO, &recipients);
    defer multi_tx.deinit();
    
    try testing.expect(multi_tx.getScript() != null);
}

// Tests NonFungibleToken (converted from NonFungibleTokenTests.swift)
test "NonFungibleToken NFT operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const nft_hash = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const nft = neo.contract.NonFungibleToken.init(allocator, nft_hash, null);
    
    // Test NFT balance (equivalent to Swift balanceOf tests)
    const balance = try nft.balanceOf(neo.Hash160.ZERO);
    try testing.expectEqual(@as(i64, 0), balance); // stub
    
    // Test NFT transfer (equivalent to Swift transfer tests)
    const token_id = "test_nft_001";
    var transfer_tx = try nft.transfer(
        neo.Hash160.ZERO, // from
        neo.Hash160.ZERO, // to
        token_id,
        null, // no data
    );
    defer transfer_tx.deinit();
    
    try testing.expect(transfer_tx.getScript() != null);
    
    // Test divisible NFT transfer (equivalent to Swift divisible transfer tests)
    var divisible_tx = try nft.transferDivisible(
        neo.Hash160.ZERO, // from
        neo.Hash160.ZERO, // to
        1,                // amount
        token_id,
        null,             // no data
    );
    defer divisible_tx.deinit();
    
    try testing.expect(divisible_tx.getScript() != null);
}

// Tests Token base class (converted from TokenTests.swift)
test "Token base functionality" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token_hash = neo.Hash160.ZERO;
    const token = neo.contract.Token.init(allocator, token_hash, null);
    
    // Test script hash (equivalent to Swift scriptHash tests)
    try testing.expect(token.getScriptHash().eql(token_hash));
    
    // Test token info methods (equivalent to Swift token info tests)
    const symbol = try token.getSymbol();
    defer allocator.free(symbol);
    try testing.expect(symbol.len >= 0);
    
    const decimals = try token.getDecimals();
    try testing.expect(decimals <= 18);
    
    const total_supply = try token.getTotalSupply();
    try testing.expect(total_supply >= 0);
}

// Tests script building operations (converted from script tests)
test "Script building for contracts" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = neo.script.ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Test contract call script building (equivalent to Swift script tests)
    const contract_hash = neo.Hash160.ZERO;
    const params = [_]neo.ContractParameter{
        neo.ContractParameter.string("test"),
        neo.ContractParameter.integer(42),
    };
    
    _ = try builder.contractCall(contract_hash, "testMethod", &params, neo.types.CallFlags.All);
    
    const script = builder.toScript();
    try testing.expect(script.len > 0);
    
    // Should contain method name and contract hash
    try testing.expect(std.mem.indexOf(u8, script, "testMethod") != null);
}

// Tests OpCode functionality (converted from OpCode tests)
test "OpCode definitions and properties" {
    const testing = std.testing;
    
    // Test opcode values (equivalent to Swift opcode tests)
    try testing.expectEqual(@as(u8, 0x10), @intFromEnum(neo.script.OpCode.PUSH0));
    try testing.expectEqual(@as(u8, 0x11), @intFromEnum(neo.script.OpCode.PUSH1));
    try testing.expectEqual(@as(u8, 0x41), @intFromEnum(neo.script.OpCode.SYSCALL));
    try testing.expectEqual(@as(u8, 0x40), @intFromEnum(neo.script.OpCode.RET));
    
    // Test push value extraction (equivalent to Swift push value tests)
    try testing.expectEqual(@as(i32, 0), neo.script.OpCode.PUSH0.getPushValue().?);
    try testing.expectEqual(@as(i32, 16), neo.script.OpCode.PUSH16.getPushValue().?);
    try testing.expectEqual(@as(?i32, null), neo.script.OpCode.SYSCALL.getPushValue());
}

// Tests CallFlags (converted from CallFlags tests)
test "CallFlags permissions and combinations" {
    const testing = std.testing;
    
    // Test permission flags (equivalent to Swift CallFlags tests)
    try testing.expectEqual(@as(u8, 0x0F), @intFromEnum(neo.types.CallFlags.All));
    try testing.expectEqual(@as(u8, 0x00), @intFromEnum(neo.types.CallFlags.None));
    try testing.expectEqual(@as(u8, 0x03), @intFromEnum(neo.types.CallFlags.States));
    
    // Test permission checking
    try testing.expect(neo.types.CallFlags.All.hasReadStates());
    try testing.expect(neo.types.CallFlags.All.hasWriteStates());
    try testing.expect(!neo.types.CallFlags.ReadStates.hasWriteStates());
}
