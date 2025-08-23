//! HTTP Client implementation
//!
//! Production-ready HTTP client for Neo RPC communication
//! Replaces placeholder implementations with real networking.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

/// HTTP client for Neo RPC communication (production implementation)
pub const HttpClient = struct {
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    timeout_ms: u32,
    max_retries: u32,
    
    const Self = @This();
    
    /// Creates HTTP client
    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) Self {
        return Self{
            .allocator = allocator,
            .endpoint = endpoint,
            .timeout_ms = 30000, // 30 seconds
            .max_retries = 3,
        };
    }
    
    /// Sets timeout
    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }
    
    /// Sets max retries
    pub fn setMaxRetries(self: *Self, max_retries: u32) void {
        self.max_retries = max_retries;
    }
    
    /// Makes HTTP POST request with JSON payload
    pub fn post(self: Self, json_payload: []const u8) ![]u8 {
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();
        
        // Parse endpoint URL
        const uri = try std.Uri.parse(self.endpoint);
        
        // Prepare headers
        var headers = std.http.Headers{ .allocator = self.allocator };
        defer headers.deinit();
        
        try headers.append("Content-Type", "application/json");
        try headers.append("User-Agent", "Neo-Zig-SDK/1.0");
        
        var retry_count: u32 = 0;
        
        while (retry_count <= self.max_retries) {
            // Create request
            var request = client.open(.POST, uri, .{
                .server_header_buffer = try self.allocator.alloc(u8, 16384),
                .headers = headers,
                .extra = .{ .expect_continue = false },
            }) catch |err| {
                retry_count += 1;
                if (retry_count > self.max_retries) return err;
                std.time.sleep(std.time.ns_per_ms * 1000); // 1 second delay
                continue;
            };
            defer request.deinit();
            
            // Set content length
            request.transfer_encoding = .{ .content_length = json_payload.len };
            
            // Send request
            try request.send();
            try request.writeAll(json_payload);
            try request.finish();
            try request.wait();
            
            // Check response status
            switch (request.response.status) {
                .ok => {
                    // Read response body
                    const response_body = try request.reader().readAllAlloc(
                        self.allocator,
                        1024 * 1024, // 1MB max response
                    );
                    
                    return response_body;
                },
                .internal_server_error, .bad_gateway, .service_unavailable, .gateway_timeout => {
                    // Retry on server errors
                    retry_count += 1;
                    if (retry_count > self.max_retries) {
                        return errors.NetworkError.ServerError;
                    }
                    std.time.sleep(std.time.ns_per_ms * (1000 * retry_count)); // Exponential backoff
                    continue;
                },
                else => {
                    return errors.NetworkError.InvalidResponse;
                },
            }
        }
        
        return errors.NetworkError.NetworkTimeout;
    }
    
    /// Makes JSON-RPC request
    pub fn jsonRpcRequest(
        self: Self,
        method: []const u8,
        params: std.json.Value,
        request_id: u32,
    ) !std.json.Value {
        // Build JSON-RPC 2.0 request
        var request_obj = std.json.ObjectMap.init(self.allocator);
        defer request_obj.deinit();
        
        try request_obj.put("jsonrpc", std.json.Value{ .string = "2.0" });
        try request_obj.put("method", std.json.Value{ .string = method });
        try request_obj.put("params", params);
        try request_obj.put("id", std.json.Value{ .integer = @intCast(request_id) });
        
        const request_json = std.json.Value{ .object = request_obj };
        
        // Serialize request
        var json_buffer = std.ArrayList(u8).init(self.allocator);
        defer json_buffer.deinit();
        
        try std.json.stringify(request_json, .{}, json_buffer.writer());
        
        // Make HTTP request
        const response_body = try self.post(json_buffer.items);
        defer self.allocator.free(response_body);
        
        // Parse response
        var json_parser = std.json.Parser.init(self.allocator, .alloc_always);
        defer json_parser.deinit();
        
        var json_tree = try json_parser.parse(response_body);
        defer json_tree.deinit();
        
        const response_obj = json_tree.root.object;
        
        // Check for RPC error
        if (response_obj.get("error")) |error_value| {
            const error_code = error_value.object.get("code").?.integer;
            const error_message = error_value.object.get("message").?.string;
            
            std.log.err("RPC Error {d}: {s}", .{ error_code, error_message });
            return errors.NetworkError.ServerError;
        }
        
        // Return result
        const result = response_obj.get("result") orelse {
            return errors.NetworkError.InvalidResponse;
        };
        
        return try result.cloneWithAllocator(self.allocator);
    }
    
    /// Validates endpoint connectivity
    pub fn validateConnection(self: Self) !bool {
        // Test with getversion RPC call
        const params = std.json.Value{ .array = &[_]std.json.Value{} };
        
        const result = self.jsonRpcRequest("getversion", params, 1) catch |err| {
            switch (err) {
                error.NetworkTimeout, error.ConnectionFailed => return false,
                else => return err,
            }
        };
        defer result.deinit();
        
        return true;
    }
    
    /// Gets network latency
    pub fn getNetworkLatency(self: Self) !u64 {
        var timer = try std.time.Timer.start();
        
        const params = std.json.Value{ .array = &[_]std.json.Value{} };
        const result = try self.jsonRpcRequest("getblockcount", params, 1);
        defer result.deinit();
        
        return timer.read() / std.time.ns_per_ms; // Return milliseconds
    }
};

/// HTTP client factory for different networks
pub const HttpClientFactory = struct {
    /// Creates client for Neo MainNet
    pub fn mainnet(allocator: std.mem.Allocator) HttpClient {
        return HttpClient.init(allocator, "https://mainnet1.neo.coz.io:443");
    }
    
    /// Creates client for Neo TestNet
    pub fn testnet(allocator: std.mem.Allocator) HttpClient {
        return HttpClient.init(allocator, "https://testnet1.neo.coz.io:443");
    }
    
    /// Creates client for local Neo node
    pub fn localhost(allocator: std.mem.Allocator, port: ?u16) HttpClient {
        const actual_port = port orelse 20332;
        const endpoint = std.fmt.allocPrint(
            allocator,
            "http://localhost:{d}",
            .{actual_port},
        ) catch "http://localhost:20332";
        
        return HttpClient.init(allocator, endpoint);
    }
    
    /// Creates client with custom endpoint
    pub fn custom(allocator: std.mem.Allocator, endpoint: []const u8) HttpClient {
        return HttpClient.init(allocator, endpoint);
    }
};

// Tests
test "HttpClient creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var client = HttpClient.init(allocator, "http://localhost:20332");
    try testing.expectEqualStrings("http://localhost:20332", client.endpoint);
    try testing.expectEqual(@as(u32, 30000), client.timeout_ms);
    try testing.expectEqual(@as(u32, 3), client.max_retries);
    
    client.setTimeout(10000);
    try testing.expectEqual(@as(u32, 10000), client.timeout_ms);
    
    client.setMaxRetries(5);
    try testing.expectEqual(@as(u32, 5), client.max_retries);
}

test "HttpClientFactory network presets" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const mainnet_client = HttpClientFactory.mainnet(allocator);
    try testing.expect(std.mem.containsAtLeast(u8, mainnet_client.endpoint, 1, "mainnet"));
    
    const testnet_client = HttpClientFactory.testnet(allocator);
    try testing.expect(std.mem.containsAtLeast(u8, testnet_client.endpoint, 1, "testnet"));
    
    const localhost_client = HttpClientFactory.localhost(allocator, null);
    try testing.expect(std.mem.containsAtLeast(u8, localhost_client.endpoint, 1, "localhost"));
    try testing.expect(std.mem.containsAtLeast(u8, localhost_client.endpoint, 1, "20332"));
    
    const custom_client = HttpClientFactory.custom(allocator, "https://custom.neo.node:443");
    try testing.expectEqualStrings("https://custom.neo.node:443", custom_client.endpoint);
}