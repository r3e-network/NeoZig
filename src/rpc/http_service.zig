//! HTTP Service implementation
//!
//! Complete conversion from NeoSwift HttpService.swift
//! Provides HTTP service implementation for Neo RPC communication.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

/// HTTP service for Neo RPC communication (converted from Swift HttpService)
pub const HttpService = struct {
    /// JSON media type constant (matches Swift JSON_MEDIA_TYPE)
    pub const JSON_MEDIA_TYPE = "application/json; charset=utf-8";
    
    /// Default URL constant (matches Swift DEFAULT_URL)
    pub const DEFAULT_URL = "http://localhost:10333/";
    
    /// Service URL
    url: []const u8,
    /// Include raw responses flag
    include_raw_responses: bool,
    /// HTTP headers
    headers: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    /// HTTP client for requests
    http_client: @import("http_client.zig").HttpClient,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates HTTP service (equivalent to Swift init)
    pub fn init(
        allocator: std.mem.Allocator,
        url: ?[]const u8,
        include_raw_responses: bool,
    ) Self {
        const service_url = url orelse DEFAULT_URL;
        
        return Self{
            .url = service_url,
            .include_raw_responses = include_raw_responses,
            .headers = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .http_client = @import("http_client.zig").HttpClient.init(allocator, service_url),
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }
    
    /// Performs I/O operation (equivalent to Swift performIO)
    pub fn performIO(self: *Self, payload: []const u8) ![]u8 {
        // Prepare HTTP client request
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();
        
        // Parse URL
        const uri = try std.Uri.parse(self.url);
        
        // Prepare headers
        var request_headers = std.http.Headers{ .allocator = self.allocator };
        defer request_headers.deinit();
        
        try request_headers.append("Content-Type", JSON_MEDIA_TYPE);
        try request_headers.append("User-Agent", "Neo-Zig-SDK/1.0");
        
        // Add custom headers
        var header_iterator = self.headers.iterator();
        while (header_iterator.next()) |entry| {
            try request_headers.append(entry.key_ptr.*, entry.value_ptr.*);
        }
        
        // Create request
        var request = try client.open(.POST, uri, .{
            .server_header_buffer = try self.allocator.alloc(u8, 16384),
            .headers = request_headers,
            .extra = .{ .expect_continue = false },
        });
        defer request.deinit();
        
        // Set content length
        request.transfer_encoding = .{ .content_length = payload.len };
        
        // Send request
        try request.send();
        try request.writeAll(payload);
        try request.finish();
        try request.wait();
        
        // Handle response
        switch (request.response.status) {
            .ok => {
                const response_body = try request.reader().readAllAlloc(
                    self.allocator,
                    10 * 1024 * 1024, // 10MB max response
                );
                return response_body;
            },
            .bad_request => return errors.NetworkError.InvalidRequest,
            .unauthorized => return errors.NetworkError.AuthenticationFailed,
            .not_found => return errors.NetworkError.InvalidEndpoint,
            .internal_server_error => return errors.NetworkError.ServerError,
            .service_unavailable => return errors.NetworkError.ServiceUnavailable,
            .gateway_timeout => return errors.NetworkError.NetworkTimeout,
            else => return errors.NetworkError.InvalidResponse,
        }
    }
    
    /// Adds HTTP header (equivalent to Swift addHeader)
    pub fn addHeader(self: *Self, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);
        
        // Remove existing header if present
        if (self.headers.fetchRemove(key)) |existing| {
            self.allocator.free(existing.key);
            self.allocator.free(existing.value);
        }
        
        try self.headers.put(key_copy, value_copy);
    }
    
    /// Adds multiple HTTP headers (equivalent to Swift addHeaders)
    pub fn addHeaders(self: *Self, headers_to_add: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage)) !void {
        var iterator = headers_to_add.iterator();
        while (iterator.next()) |entry| {
            try self.addHeader(entry.key_ptr.*, entry.value_ptr.*);
        }
    }
    
    /// Removes HTTP header (equivalent to Swift header removal)
    pub fn removeHeader(self: *Self, key: []const u8) bool {
        if (self.headers.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return true;
        }
        return false;
    }
    
    /// Gets header value (equivalent to Swift header access)
    pub fn getHeader(self: Self, key: []const u8) ?[]const u8 {
        return self.headers.get(key);
    }
    
    /// Gets all headers (utility method)
    pub fn getAllHeaders(self: Self) std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage) {
        return self.headers;
    }
    
    /// Validates service connectivity (utility method)
    pub fn validateConnectivity(self: *Self) !bool {
        // Test with simple JSON-RPC call
        const test_payload = 
            \\{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}
        ;
        
        const response = self.performIO(test_payload) catch |err| {
            return switch (err) {
                error.NetworkTimeout, error.ConnectionFailed => false,
                else => err,
            };
        };
        defer self.allocator.free(response);
        
        return response.len > 0;
    }
    
    /// Gets service configuration (utility method)
    pub fn getConfiguration(self: Self, allocator: std.mem.Allocator) !ServiceConfiguration {
        return ServiceConfiguration{
            .url = try allocator.dupe(u8, self.url),
            .include_raw_responses = self.include_raw_responses,
            .header_count = @intCast(self.headers.count()),
        };
    }
    
    /// Sets timeout (utility method)
    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.http_client.setTimeout(timeout_ms);
    }
    
    /// Sets max retries (utility method)
    pub fn setMaxRetries(self: *Self, max_retries: u32) void {
        self.http_client.setMaxRetries(max_retries);
    }
};

/// Service configuration information
pub const ServiceConfiguration = struct {
    url: []const u8,
    include_raw_responses: bool,
    header_count: u32,
    
    pub fn deinit(self: *ServiceConfiguration, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
    }
};

/// Service interface (converted from Swift Service protocol)
pub const Service = struct {
    /// Performs I/O operation
    pub fn performIO(self: anytype, payload: []const u8) ![]u8 {
        return self.performIO(payload);
    }
    
    /// Validates service implementation
    pub fn validate(self: anytype) !void {
        _ = self;
        // Service validation logic would go here
    }
};

/// String context for HashMap
pub const StringContext = struct {
    pub fn hash(self: @This(), key: []const u8) u64 {
        _ = self;
        return std.hash_map.hashString(key);
    }
    
    pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
        _ = self;
        return std.mem.eql(u8, a, b);
    }
};

/// HTTP service factory (utility)
pub const HttpServiceFactory = struct {
    /// Creates service for MainNet
    pub fn mainnet(allocator: std.mem.Allocator) HttpService {
        return HttpService.init(allocator, "https://mainnet1.neo.coz.io:443", false);
    }
    
    /// Creates service for TestNet
    pub fn testnet(allocator: std.mem.Allocator) HttpService {
        return HttpService.init(allocator, "https://testnet1.neo.coz.io:443", false);
    }
    
    /// Creates service for local node
    pub fn localhost(allocator: std.mem.Allocator, port: ?u16) HttpService {
        const actual_port = port orelse 10333;
        const url = std.fmt.allocPrint(
            allocator,
            "http://localhost:{d}/",
            .{actual_port},
        ) catch "http://localhost:10333/";
        
        return HttpService.init(allocator, url, false);
    }
    
    /// Creates service with custom configuration
    pub fn custom(
        allocator: std.mem.Allocator,
        url: []const u8,
        include_raw_responses: bool,
    ) HttpService {
        return HttpService.init(allocator, url, include_raw_responses);
    }
};

// Tests (converted from Swift HttpService tests)
test "HttpService creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test default service creation (equivalent to Swift HttpService tests)
    var service = HttpService.init(allocator, null, false);
    defer service.deinit();
    
    try testing.expectEqualStrings(HttpService.DEFAULT_URL, service.url);
    try testing.expect(!service.include_raw_responses);
    try testing.expectEqual(@as(u32, 0), @intCast(service.headers.count()));
    
    // Test custom service creation
    var custom_service = HttpService.init(allocator, "https://custom.neo.node:443", true);
    defer custom_service.deinit();
    
    try testing.expectEqualStrings("https://custom.neo.node:443", custom_service.url);
    try testing.expect(custom_service.include_raw_responses);
}

test "HttpService header management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var service = HttpService.init(allocator, null, false);
    defer service.deinit();
    
    // Test adding headers (equivalent to Swift addHeader tests)
    try service.addHeader("Authorization", "Bearer test_token");
    try service.addHeader("X-Custom-Header", "custom_value");
    
    try testing.expectEqual(@as(u32, 2), @intCast(service.headers.count()));
    
    // Test header retrieval
    const auth_header = service.getHeader("Authorization");
    try testing.expect(auth_header != null);
    try testing.expectEqualStrings("Bearer test_token", auth_header.?);
    
    const custom_header = service.getHeader("X-Custom-Header");
    try testing.expect(custom_header != null);
    try testing.expectEqualStrings("custom_value", custom_header.?);
    
    // Test header removal
    try testing.expect(service.removeHeader("Authorization"));
    try testing.expectEqual(@as(u32, 1), @intCast(service.headers.count()));
    
    try testing.expect(!service.removeHeader("NonExistent"));
}

test "HttpService factory methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test network presets (equivalent to Swift factory tests)
    var mainnet_service = HttpServiceFactory.mainnet(allocator);
    defer mainnet_service.deinit();
    
    try testing.expect(std.mem.containsAtLeast(u8, mainnet_service.url, 1, "mainnet"));
    
    var testnet_service = HttpServiceFactory.testnet(allocator);
    defer testnet_service.deinit();
    
    try testing.expect(std.mem.containsAtLeast(u8, testnet_service.url, 1, "testnet"));
    
    var localhost_service = HttpServiceFactory.localhost(allocator, null);
    defer localhost_service.deinit();
    
    try testing.expect(std.mem.containsAtLeast(u8, localhost_service.url, 1, "localhost"));
    try testing.expect(std.mem.containsAtLeast(u8, localhost_service.url, 1, "10333"));
    
    // Test custom service
    var custom_service = HttpServiceFactory.custom(allocator, "https://custom.endpoint:8080", true);
    defer custom_service.deinit();
    
    try testing.expectEqualStrings("https://custom.endpoint:8080", custom_service.url);
    try testing.expect(custom_service.include_raw_responses);
}

test "HttpService configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var service = HttpService.init(allocator, "https://test.node:443", false);
    defer service.deinit();
    
    // Test timeout and retry configuration
    service.setTimeout(15000); // 15 seconds
    service.setMaxRetries(5);
    
    try testing.expectEqual(@as(u32, 15000), service.http_client.timeout_ms);
    try testing.expectEqual(@as(u32, 5), service.http_client.max_retries);
    
    // Test configuration retrieval
    var config = try service.getConfiguration(allocator);
    defer config.deinit(allocator);
    
    try testing.expectEqualStrings("https://test.node:443", config.url);
    try testing.expect(!config.include_raw_responses);
    try testing.expectEqual(@as(u32, 0), config.header_count);
}