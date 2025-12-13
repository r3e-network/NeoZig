//! HTTP Service implementation
//!
//! Complete conversion from NeoSwift HttpService.swift
//! Provides HTTP service implementation for Neo RPC communication.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

/// HTTP service for Neo RPC communication (converted from Swift HttpService)
pub const HttpService = struct {
    /// JSON media type constant (matches Swift JSON_MEDIA_TYPE)
    pub const JSON_MEDIA_TYPE = "application/json; charset=utf-8";
    
    /// Default URL constant (matches Swift DEFAULT_URL)
    pub const DEFAULT_URL = "http://localhost:20332/";
    
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
            .http_client = @import("http_client.zig").HttpClient.initBorrowed(allocator, url_slice),
            .allocator = allocator,
        };
    }

    /// Creates HTTP service by taking ownership of an already-allocated URL buffer.
    pub fn initOwned(
        allocator: std.mem.Allocator,
        url: []u8,
        include_raw_responses: bool,
    ) Self {
        return Self{
            .url = url,
            .owns_url = true,
            .include_raw_responses = include_raw_responses,
            .headers = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .http_client = @import("http_client.zig").HttpClient.initBorrowed(allocator, url),
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
        self.http_client.deinit();
        if (self.owns_url) {
            self.allocator.free(self.url);
        }
    }
    
    /// Performs I/O operation (equivalent to Swift performIO)
    pub fn performIO(self: *Self, payload: []const u8) ![]u8 {
        self.http_client.withSender(sendWithHeaders, self);
        return self.http_client.post(payload);
    }

fn discardResponseBody(response: *std.http.Client.Response) !void {
    const reader = response.reader(&.{});
    _ = reader.discardRemaining() catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr().?,
        else => return err,
    };
}

fn sendWithHeaders(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) errors.NetworkError![]u8 {
    var timer = std.time.Timer.start() catch return errors.NetworkError.RequestFailed;
    const raw_ctx = ctx orelse return errors.NetworkError.NetworkUnavailable;
    const service: *HttpService = @ptrCast(@alignCast(raw_ctx));

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = std.Uri.parse(endpoint) catch return errors.NetworkError.InvalidEndpoint;

    var extra_headers = ArrayList(std.http.Header).init(allocator);
    defer extra_headers.deinit();

    var header_iterator = service.headers.iterator();
    while (header_iterator.next()) |entry| {
        extra_headers.append(.{ .name = entry.key_ptr.*, .value = entry.value_ptr.* }) catch return errors.NetworkError.RequestFailed;
    }

    var response_body = ArrayList(u8).init(allocator);
    defer response_body.deinit();

    const result = client.fetch(.{
        .location = .{ .uri = uri },
        .method = .POST,
        .payload = payload,
        .headers = .{
            .content_type = .{ .override = JSON_MEDIA_TYPE },
            .user_agent = .{ .override = "Neo-Zig-SDK/1.0" },
        },
        .extra_headers = extra_headers.items,
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .response_storage = .{ .dynamic = &response_body },
        .max_append_size = @import("http_client.zig").HttpClient.DEFAULT_MAX_RESPONSE_BYTES,
    }) catch |err| {
        return mapFetchError(err);
    };

    switch (result.status) {
        .ok => {},
        .bad_request => return errors.NetworkError.RequestFailed,
        .unauthorized => return errors.NetworkError.AuthenticationFailed,
        .not_found => return errors.NetworkError.InvalidEndpoint,
        .internal_server_error => return errors.NetworkError.ServerError,
        .service_unavailable => return errors.NetworkError.NetworkUnavailable,
        .gateway_timeout => return errors.NetworkError.NetworkTimeout,
        else => {
            if (result.status.class() == .server_error) return errors.NetworkError.ServerError;
            return errors.NetworkError.InvalidResponse;
        },
    }

    const body = response_body.toOwnedSlice() catch return errors.NetworkError.RequestFailed;

    if (timer.read() / std.time.ns_per_ms > timeout_ms) {
        allocator.free(body);
        return errors.NetworkError.NetworkTimeout;
    }

    return body;
}

fn mapFetchError(err: anyerror) errors.NetworkError {
    return switch (err) {
        error.UnsupportedUriScheme,
        error.UriMissingHost,
        error.UriHostTooLong => errors.NetworkError.InvalidEndpoint,

        error.NetworkUnreachable,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.UnknownHostName,
        error.HostLacksNetworkAddresses,
        error.UnexpectedConnectFailure => errors.NetworkError.ConnectionFailed,

        error.ConnectionTimedOut => errors.NetworkError.NetworkTimeout,
        error.TemporaryNameServerFailure,
        error.NameServerFailure => errors.NetworkError.NetworkUnavailable,

        error.CertificateBundleLoadFailure,
        error.StreamTooLong,
        error.WriteFailed,
        error.UnsupportedCompressionMethod,
        error.TooManyHttpRedirects => errors.NetworkError.RequestFailed,
        else => errors.NetworkError.RequestFailed,
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

    /// Returns whether the given header is present.
    pub fn hasHeader(self: Self, key: []const u8) bool {
        return self.headers.contains(key);
    }
    
    /// Gets all headers (utility method)
    pub fn getAllHeaders(self: Self) std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage) {
        return self.headers;
    }
    
    /// Validates service connectivity (utility method)
    /// Performs a simple RPC call to validate connectivity using the shared HttpClient.
    /// Note: std.http lacks per-request deadlines; see HttpClient.post for elapsed-time guard.
    pub fn validateConnectivity(self: *Self) !bool {
        // Test with simple JSON-RPC call
        const test_payload = 
            \\{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}
        ;
        self.http_client.withSender(sendWithHeaders, self);
        const response = self.http_client.post(test_payload) catch |err| switch (err) {
            error.NetworkTimeout, error.ConnectionFailed => return false,
            else => return err,
        };
        defer self.http_client.allocator.free(response);
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
        const actual_port = port orelse 20332;
        const url = std.fmt.allocPrint(allocator, "http://localhost:{d}/", .{actual_port}) catch return HttpService.init(allocator, "http://localhost:20332/", false);
        return HttpService.initOwned(allocator, url, false);
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
    try testing.expect(std.mem.containsAtLeast(u8, localhost_service.url, 1, "20332"));
    
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
