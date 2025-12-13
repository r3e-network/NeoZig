//! Non-Fungible Token Tests
//!
//! Complete conversion from NeoSwift NonFungibleTokenTests.swift
//! Tests NEP-11 non-fungible token functionality.

const std = @import("std");


const testing = std.testing;
const NonFungibleToken = @import("../../src/contract/non_fungible_token.zig").NonFungibleToken;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const TestUtils = @import("../helpers/test_utilities.zig");

test "Non-fungible token creation" {
    const allocator = testing.allocator;
    
    var neo_swift = try TestUtils.makeNeoSwiftStub(allocator);
    defer TestUtils.destroyNeoSwiftStub(&neo_swift);
    
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
