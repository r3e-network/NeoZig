//! URL Session utilities
//!
//! Complete conversion from NeoSwift URLSession.swift extensions
//! Provides HTTP request functionality and URL handling.

const std = @import("std");
const errors = @import("../core/errors.zig");

/// URL requester interface (converted from Swift URLRequester protocol)
pub const URLRequester = struct {
    /// Performs HTTP request and returns data
    pub fn dataFromRequest(self: anytype, request: URLRequest) !HTTPResponse {
        return self.dataFromRequest(request);
    }
};

/// URL request structure (converted from Swift URLRequest)
pub const URLRequest = struct {
    url: []const u8,
    method: HTTPMethod,
    headers: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    body: ?[]const u8,
    timeout_ms: u32,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates URL request
    pub fn init(allocator: std.mem.Allocator, url: []const u8) Self {
        return Self{
            .url = url,
            .method = .GET,
            .headers = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .body = null,
            .timeout_ms = 30000,
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
        
        if (self.body) |body| {
            self.allocator.free(body);
        }
    }
    
    /// Adds header value (equivalent to Swift addValue)
    pub fn addValue(self: *Self, value: []const u8, for_field: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, for_field);
        const value_copy = try self.allocator.dupe(u8, value);
        
        // Remove existing header if present
        if (self.headers.fetchRemove(for_field)) |existing| {
            self.allocator.free(existing.key);
            self.allocator.free(existing.value);
        }
        
        try self.headers.put(key_copy, value_copy);
    }
    
    /// Sets HTTP method (equivalent to Swift httpMethod)
    pub fn setHttpMethod(self: *Self, method: HTTPMethod) void {
        self.method = method;
    }
    
    /// Sets HTTP body (equivalent to Swift httpBody)
    pub fn setHttpBody(self: *Self, body: []const u8) !void {
        if (self.body) |old_body| {
            self.allocator.free(old_body);
        }
        
        self.body = try self.allocator.dupe(u8, body);
    }
    
    /// Sets timeout
    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }
};

/// HTTP methods
pub const HTTPMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    
    pub fn toString(self: HTTPMethod) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .PATCH => "PATCH",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
        };
    }
};

/// HTTP response structure (converted from Swift response handling)
pub const HTTPResponse = struct {
    data: []const u8,
    response: ?URLResponse,
    
    const Self = @This();
    
    pub fn init(data: []const u8, response: ?URLResponse) Self {
        return Self{
            .data = data,
            .response = response,
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        
        if (self.response) |*resp| {
            resp.deinit(allocator);
        }
    }
};

/// URL response structure (converted from Swift URLResponse)
pub const URLResponse = struct {
    status_code: u16,
    headers: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, status_code: u16) URLResponse {
        return URLResponse{
            .status_code = status_code,
            .headers = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *URLResponse, allocator: std.mem.Allocator) void {
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }
};

/// URL session implementation (converted from Swift URLSession extension)
pub const URLSession = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u32,
    max_retries: u32,
    
    const Self = @This();
    
    /// Creates URL session
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .timeout_ms = 30000,
            .max_retries = 3,
        };
    }
    
    /// Performs data request (equivalent to Swift data(from:))
    pub fn dataFromRequest(self: Self, request: URLRequest) !HTTPResponse {
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();
        
        // Parse URL
        const uri = try std.Uri.parse(request.url);
        
        // Prepare headers
        var headers = std.http.Headers{ .allocator = self.allocator };
        defer headers.deinit();
        
        // Add request headers
        var header_iterator = request.headers.iterator();
        while (header_iterator.next()) |entry| {
            try headers.append(entry.key_ptr.*, entry.value_ptr.*);
        }
        
        // Create HTTP request
        var http_request = try client.open(
            switch (request.method) {
                .GET => .GET,
                .POST => .POST,
                .PUT => .PUT,
                .DELETE => .DELETE,
                .PATCH => .PATCH,
                .HEAD => .HEAD,
                .OPTIONS => .OPTIONS,
            },
            uri,
            .{
                .server_header_buffer = try self.allocator.alloc(u8, 16384),
                .headers = headers,
                .extra = .{ .expect_continue = false },
            }
        );
        defer http_request.deinit();
        
        // Set body if present
        if (request.body) |body| {
            http_request.transfer_encoding = .{ .content_length = body.len };
        }
        
        // Send request
        try http_request.send();
        
        if (request.body) |body| {
            try http_request.writeAll(body);
        }
        
        try http_request.finish();
        try http_request.wait();
        
        // Read response
        const response_data = try http_request.reader().readAllAlloc(
            self.allocator,
            10 * 1024 * 1024, // 10MB max
        );
        
        // Create response object
        var url_response = URLResponse.init(self.allocator, @intFromEnum(http_request.response.status));
        
        return HTTPResponse.init(response_data, url_response);
    }
    
    /// Shared session instance (equivalent to Swift .shared)
    pub var shared: ?URLSession = null;
    
    /// Gets shared session
    pub fn getShared(allocator: std.mem.Allocator) *URLSession {
        if (shared == null) {
            shared = URLSession.init(allocator);
        }
        return &shared.?;
    }
    
    /// Sets timeout for session
    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }
    
    /// Sets max retries for session
    pub fn setMaxRetries(self: *Self, max_retries: u32) void {
        self.max_retries = max_retries;
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

/// URL utilities
pub const URLUtils = struct {
    /// Validates URL format
    pub fn validateURL(url: []const u8) bool {
        if (url.len == 0) return false;
        
        return std.mem.startsWith(u8, url, "http://") or 
               std.mem.startsWith(u8, url, "https://");
    }
    
    /// Parses URL components
    pub fn parseURL(url: []const u8, allocator: std.mem.Allocator) !URLComponents {
        const uri = try std.Uri.parse(url);
        
        return URLComponents{
            .scheme = try allocator.dupe(u8, uri.scheme),
            .host = if (uri.host) |h| try allocator.dupe(u8, h.raw) else null,
            .port = uri.port,
            .path = if (uri.path.len > 0) try allocator.dupe(u8, uri.path.raw) else null,
        };
    }
};

/// URL components structure
pub const URLComponents = struct {
    scheme: []const u8,
    host: ?[]const u8,
    port: ?u16,
    path: ?[]const u8,
    
    pub fn deinit(self: *URLComponents, allocator: std.mem.Allocator) void {
        allocator.free(self.scheme);
        if (self.host) |host| allocator.free(host);
        if (self.path) |path| allocator.free(path);
    }
};

// Tests (converted from Swift URLSession tests)
test "URLRequest creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test URL request creation (equivalent to Swift URLRequest tests)
    var request = URLRequest.init(allocator, "https://test.neo.node:443");
    defer request.deinit();
    
    try testing.expectEqualStrings("https://test.neo.node:443", request.url);
    try testing.expectEqual(HTTPMethod.GET, request.method);
    try testing.expectEqual(@as(u32, 30000), request.timeout_ms);
    
    // Test header addition
    try request.addValue("application/json", "Content-Type");
    try request.addValue("Neo-Zig-SDK/1.0", "User-Agent");
    
    try testing.expectEqual(@as(u32, 2), @intCast(request.headers.count()));
    
    // Test method setting
    request.setHttpMethod(.POST);
    try testing.expectEqual(HTTPMethod.POST, request.method);
    
    // Test body setting
    try request.setHttpBody("test request body");
    try testing.expect(request.body != null);
    try testing.expectEqualStrings("test request body", request.body.?);
}

test "URLSession operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test URL session creation (equivalent to Swift URLSession tests)
    var session = URLSession.init(allocator);
    
    try testing.expectEqual(@as(u32, 30000), session.timeout_ms);
    try testing.expectEqual(@as(u32, 3), session.max_retries);
    
    // Test configuration
    session.setTimeout(15000);
    session.setMaxRetries(5);
    
    try testing.expectEqual(@as(u32, 15000), session.timeout_ms);
    try testing.expectEqual(@as(u32, 5), session.max_retries);
    
    // Test shared session
    const shared_session = URLSession.getShared(allocator);
    try testing.expect(shared_session != null);
}

test "URL utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test URL validation (equivalent to Swift URL validation tests)
    try testing.expect(URLUtils.validateURL("http://localhost:20332"));
    try testing.expect(URLUtils.validateURL("https://mainnet1.neo.coz.io:443"));
    
    try testing.expect(!URLUtils.validateURL(""));
    try testing.expect(!URLUtils.validateURL("invalid_url"));
    try testing.expect(!URLUtils.validateURL("ftp://invalid.protocol"));
    
    // Test URL parsing
    var components = try URLUtils.parseURL("https://test.neo.node:8080/rpc", allocator);
    defer components.deinit(allocator);
    
    try testing.expectEqualStrings("https", components.scheme);
    try testing.expectEqualStrings("test.neo.node", components.host.?);
    try testing.expectEqual(@as(u16, 8080), components.port.?);
    try testing.expectEqualStrings("/rpc", components.path.?);
}

test "HTTP method operations" {
    const testing = std.testing;
    
    // Test HTTP method string conversion (equivalent to Swift method tests)
    try testing.expectEqualStrings("GET", HTTPMethod.GET.toString());
    try testing.expectEqualStrings("POST", HTTPMethod.POST.toString());
    try testing.expectEqualStrings("PUT", HTTPMethod.PUT.toString());
    try testing.expectEqualStrings("DELETE", HTTPMethod.DELETE.toString());
    try testing.expectEqualStrings("PATCH", HTTPMethod.PATCH.toString());
    try testing.expectEqualStrings("HEAD", HTTPMethod.HEAD.toString());
    try testing.expectEqualStrings("OPTIONS", HTTPMethod.OPTIONS.toString());
}