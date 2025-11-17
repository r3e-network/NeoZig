//! Contract Manifest Tests
//!
//! Complete conversion from NeoSwift ContractManifestTests.swift
//! Tests contract manifest parsing and validation.

const std = @import("std");


const testing = std.testing;
const ContractManifest = @import("../../src/protocol/response/contract_manifest.zig").ContractManifest;
const ContractGroup = @import("../../src/protocol/response/contract_manifest.zig").ContractGroup;

test "Contract manifest creation" {
    const allocator = testing.allocator;
    
    var manifest = try ContractManifest.init(
        "TestContract",
        &[_]ContractGroup{},
        null,
        &[_][]const u8{"NEP-17"},
        null,
        &[_]@import("../../src/protocol/response/contract_manifest.zig").ContractPermission{},
        &[_][]const u8{},
        null,
        allocator,
    );
    defer manifest.deinit(allocator);
    
    try testing.expectEqualStrings("TestContract", manifest.getNameOrDefault());
    try testing.expect(manifest.hasStandard("NEP-17"));
    try testing.expect(manifest.isNep17());
}

test "Contract group validation" {
    const allocator = testing.allocator;
    
    const valid_pub_key = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    const valid_signature = "dGVzdF9zaWduYXR1cmU=";
    
    var group = try ContractGroup.init(valid_pub_key, valid_signature, allocator);
    defer group.deinit(allocator);
    
    try testing.expect(std.mem.indexOf(u8, group.pub_key, "03b4af8d") != null);
    try testing.expectEqualStrings(valid_signature, group.signature);
}