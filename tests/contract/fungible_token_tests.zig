//! Fungible Token Tests
//!
//! Complete conversion from NeoSwift FungibleTokenTests.swift
//! Tests NEP-17 fungible token functionality.

const std = @import("std");


const testing = std.testing;
const FungibleToken = @import("../../src/contract/fungible_token.zig").FungibleToken;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;

test "Fungible token creation and validation" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = @import("../../src/rpc/neo_client.zig").NeoSwift.build(allocator, mock_service, mock_config);
    
    const token_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const fungible_token = FungibleToken.init(token_hash, neo_swift);
    
    try testing.expect(fungible_token.getScriptHash().eql(token_hash));
    try fungible_token.validate();
}

test "NEP-17 standard methods" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = @import("../../src/rpc/neo_client.zig").NeoSwift.build(allocator, mock_service, mock_config);
    
    const token_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const fungible_token = FungibleToken.init(token_hash, neo_swift);
    
    const nep17_methods = [_][]const u8{ "symbol", "decimals", "totalSupply", "balanceOf", "transfer" };
    
    for (nep17_methods) |method| {
        const empty_params = [_]@import("../../src/types/contract_parameter.zig").ContractParameter{};
        try fungible_token.validateInvocation(method, &empty_params);
    }
}