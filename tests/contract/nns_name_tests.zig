//! NNS Name Tests
//!
//! Complete conversion from NeoSwift NNSNameTests.swift
//! Tests Neo Name Service domain name validation and operations.

const std = @import("std");


const testing = std.testing;
const NNSName = @import("../../src/contract/nns_name.zig").NNSName;

test "NNS name validation" {
    const allocator = testing.allocator;
    
    // Test valid NNS names
    const valid_names = [_][]const u8{
        "test.neo",
        "example.neo",
        "subdomain.example.neo",
        "a.neo",
    };
    
    for (valid_names) |name| {
        var nns_name = try NNSName.init(name, allocator);
        defer nns_name.deinit(allocator);
        
        try testing.expectEqualStrings(name, nns_name.getName());
        try testing.expect(nns_name.isValid());
    }
}

test "NNS name validation errors" {
    const allocator = testing.allocator;
    
    // Test invalid NNS names
    const invalid_names = [_][]const u8{
        "toolongdomainnamethatexceedsmaximumlength.neo",
        "ab", // Too short
        "", // Empty
        "no-extension",
        ".neo", // Starts with dot
    };
    
    for (invalid_names) |name| {
        try testing.expectError(
            anyerror,
            NNSName.init(name, allocator)
        );
    }
}