//! HTTP Service Tests
//!
//! Complete conversion from NeoSwift HttpServiceTests.swift
//! Tests HTTP service functionality and networking.

const std = @import("std");


const testing = std.testing;
const HttpService = @import("../../src/rpc/http_service.zig").HttpService;

test "HTTP service creation" {
    const allocator = testing.allocator;
    
    var http_service = HttpService.init(allocator, null, false);
    defer http_service.deinit();
    
    try testing.expectEqualStrings(HttpService.DEFAULT_URL, http_service.url);
    try testing.expect(!http_service.include_raw_responses);
}

test "HTTP service header management" {
    const allocator = testing.allocator;
    
    var http_service = HttpService.init(allocator, null, false);
    defer http_service.deinit();
    
    try http_service.addHeader("Authorization", "Bearer token123");
    try http_service.addHeader("Content-Type", "application/json");
    
    try testing.expect(http_service.hasHeader("Authorization"));
    try testing.expect(http_service.hasHeader("Content-Type"));
    try testing.expect(!http_service.hasHeader("NonExistent"));
}