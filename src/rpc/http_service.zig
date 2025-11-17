//! HTTP Service implementation
//!
//! Complete conversion from NeoSwift HttpService.swift
//! Provides HTTP service implementation for Neo RPC communication.

const std = @import("std");
const ArrayList = std.array_list.Managed;

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
    /// Whether the URL memory is owned by this instance
    owns_url: bool,
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
        const maybe_copy = allocator.dupe(u8, service_url) catch null;
        const url_slice = maybe_copy orelse service_url;
        const owns_url = maybe_copy != null;
        
        return Self{
            .url = url_slice,
            .owns_url = owns_url,
            .include_raw_responses = include_raw_responses,
            .headers = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .http_client = @import("http_client.zig").HttpClient.init(allocator, url_slice),
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
        if (self.owns_url) {
            self.allocator.free(self.url);
        }
    }
    
    /// Performs I/O operation (equivalent to Swift performIO)
    pub fn performIO(self: *Self, payload: []const u8) ![]u8 {
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const uri = try std.Uri.parse(self.url);

        var extra_headers = ArrayList(std.http.Header).init(self.allocator);
        defer extra_headers.deinit();

        try extra_headers.append(.{ .name = "Content-Type", .value = JSON_MEDIA_TYPE });
        try extra_headers.append(.{ .name = "User-Agent", .value = "Neo-Zig-SDK/1.0" });

        var header_iterator = self.headers.iterator();
        while (header_iterator.next()) |entry| {
            try extra_headers.append(.{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
        }

        var request = try client.request(.POST, uri, .{
            .headers = .{
                .accept_encoding = .omit,
                .content_type = .omit,
                .user_agent = .omit,
            },
            .extra_headers = extra_headers.items,
            .redirect_behavior = .not_allowed,
        });
        defer request.deinit();

        request.transfer_encoding = .{ .content_length = @intCast(payload.len) };

        var body_writer = try request.sendBodyUnflushed(&.{});
        try body_writer.writer.writeAll(payload);
        try body_writer.end();
        try request.connection.?.flush();

        var response = try request.receiveHead(&.{});

        switch (response.head.status) {
            .ok => {},
            .bad_request => {
                try discardResponseBody(&response);
                return errors.NetworkError.RequestFailed;
            },
            .unauthorized => {
                try discardResponseBody(&response);
                return errors.NetworkError.AuthenticationFailed;
            },
            .not_found => {
                try discardResponseBody(&response);
                return errors.NetworkError.InvalidEndpoint;
            },
            .internal_server_error => {
                try discardResponseBody(&response);
                return errors.NetworkError.ServerError;
            },
            .service_unavailable => {
                try discardResponseBody(&response);
                return errors.NetworkError.NetworkUnavailable;
            },
            .gateway_timeout => {
                try discardResponseBody(&response);
                return errors.NetworkError.NetworkTimeout;
            },
            else => {
                try discardResponseBody(&response);
                return errors.NetworkError.InvalidResponse;
            },
        }

        var transfer_buffer: [64]u8 = undefined;
        const reader = response.reader(&transfer_buffer);
        const response_body = reader.allocRemaining(self.allocator, std.Io.Limit.limited(10 * 1024 * 1024)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => return err,
        };

        return response_body;
    }

fn discardResponseBody(response: *std.http.Client.Response) !void {
    const reader = response.reader(&.{});
    _ = reader.discardRemaining() catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr().?,
        else => return err,
    };
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
            .header_count = @as(u32, @intCast(self.headers.count())),
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
        const url_alloc = std.fmt.allocPrint(allocator, "http://localhost:{d}/", .{actual_port}) catch null;
        defer if (url_alloc) |owned| allocator.free(owned);

        const url = url_alloc orelse "http://localhost:10333/";
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
    try testing.expectEqual(@as(u32, 0), @as(u32, @intCast(service.headers.count())));
    
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
    
    try testing.expectEqual(@as(u32, 2), @as(u32, @intCast(service.headers.count())));
    
    // Test header retrieval
    const auth_header = service.getHeader("Authorization");
    try testing.expect(auth_header != null);
    try testing.expectEqualStrings("Bearer test_token", auth_header.?);
    
    const custom_header = service.getHeader("X-Custom-Header");
    try testing.expect(custom_header != null);
    try testing.expectEqualStrings("custom_value", custom_header.?);
    
    // Test header removal
    try testing.expect(service.removeHeader("Authorization"));
    try testing.expectEqual(@as(u32, 1), @as(u32, @intCast(service.headers.count())));
    
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
