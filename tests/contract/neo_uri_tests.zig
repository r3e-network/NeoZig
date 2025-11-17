//! Neo URI Tests
//!
//! Complete conversion from NeoSwift NeoURITests.swift
//! Tests Neo URI parsing and construction.

const std = @import("std");


const testing = std.testing;
const NeoURI = @import("../../src/contract/neo_uri.zig").NeoURI;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;

test "Neo URI creation and parsing" {
    const allocator = testing.allocator;
    
    const test_address = "NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj";
    const uri_string = "neo:NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj";
    
    var neo_uri = try NeoURI.fromString(uri_string, allocator);
    defer neo_uri.deinit(allocator);
    
    try testing.expectEqualStrings(test_address, neo_uri.getAddress());
    try testing.expect(neo_uri.isValid());
}

test "Neo URI with amount parameter" {
    const allocator = testing.allocator;
    
    const uri_with_amount = "neo:NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj?amount=100";
    
    var neo_uri = try NeoURI.fromString(uri_with_amount, allocator);
    defer neo_uri.deinit(allocator);
    
    try testing.expect(neo_uri.hasAmount());
    try testing.expectEqual(@as(u64, 100), neo_uri.getAmount().?);
}