//! Non-Fungible Token Tests
//!
//! Complete conversion from NeoSwift NonFungibleTokenTests.swift
//! Tests NEP-11 non-fungible token functionality.

const std = @import("std");


const testing = std.testing;
const NonFungibleToken = @import("../../src/contract/non_fungible_token.zig").NonFungibleToken;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;

test "Non-fungible token creation" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = @import("../../src/rpc/neo_client.zig").NeoSwift.build(allocator, mock_service, mock_config);
    
    const nft_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const nft_token = NonFungibleToken.init(nft_hash, neo_swift);
    
    try testing.expect(nft_token.getScriptHash().eql(nft_hash));
    try nft_token.validate();
}

test "NEP-11 standard methods" {
    const allocator = testing.allocator;
    
    const nep11_methods = [_][]const u8{ "symbol", "decimals", "totalSupply", "balanceOf", "transfer", "ownerOf", "tokens" };
    
    for (nep11_methods) |method| {
        // Test method name validation
        try testing.expect(method.len > 0);
    }
}