//! HTTP Client implementation
//!
//! Provides JSON-RPC transport for Neo nodes with pluggable send behaviour.

const std = @import("std");
const builtin = @import("builtin");
const errors = @import("../core/errors.zig");
const json_utils = @import("../utils/json_utils.zig");

const ArrayList = std.ArrayList;
const http = std.http;
const Uri = std.Uri;

const log = std.log.scoped(.neo_rpc);

pub const HttpClient = struct {
    /// Upper bound for HTTP response bodies captured into memory.
    /// This prevents unbounded growth when a node (or attacker) returns a huge body.
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

    allocator: std.mem.Allocator,
    endpoint: []const u8,
    owns_endpoint: bool,
    timeout_ms: u32,
    max_retries: u32,
    max_response_bytes: usize = DEFAULT_MAX_RESPONSE_BYTES,
    send_fn: ?*const SendFn,
    send_context: ?*anyopaque,

    const Self = @This();
    const SendFn = fn (ctx: ?*anyopaque, allocator: std.mem.Allocator, endpoint: []const u8, payload: []const u8, timeout_ms: u32) errors.NetworkError![]u8;

    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) Self {
        const endpoint_copy = allocator.dupe(u8, endpoint) catch endpoint;
        return Self{
            .allocator = allocator,
            .endpoint = endpoint_copy,
            .owns_endpoint = endpoint_copy.ptr != endpoint.ptr,
            .timeout_ms = 30_000,
            .max_retries = 3,
            .send_fn = &defaultSend,
            .send_context = null,
        };
    }

    /// Initializes a client that borrows the endpoint slice.
    /// The caller must ensure the endpoint memory outlives the client.
    pub fn initBorrowed(allocator: std.mem.Allocator, endpoint: []const u8) Self {
        return Self{
            .allocator = allocator,
            .endpoint = endpoint,
            .owns_endpoint = false,
            .timeout_ms = 30_000,
            .max_retries = 3,
            .send_fn = &defaultSend,
            .send_context = null,
        };
    }

    /// Initializes a client that takes ownership of an already-allocated endpoint buffer.
    pub fn initOwned(allocator: std.mem.Allocator, endpoint: []u8) Self {
        return Self{
            .allocator = allocator,
            .endpoint = endpoint,
            .owns_endpoint = true,
            .timeout_ms = 30_000,
            .max_retries = 3,
            .send_fn = &defaultSend,
            .send_context = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owns_endpoint) {
            self.allocator.free(self.endpoint);
            self.owns_endpoint = false;
        }
    }

    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }

    pub fn setMaxRetries(self: *Self, max_retries: u32) void {
        self.max_retries = max_retries;
    }

    /// Sets the maximum response body size captured into memory.
    /// Passing 0 resets to the default cap.
    pub fn setMaxResponseBytes(self: *Self, max_response_bytes: usize) void {
        self.max_response_bytes = if (max_response_bytes == 0) DEFAULT_MAX_RESPONSE_BYTES else max_response_bytes;
    }

    /// Overrides outbound transport (useful for tests/mocks).
    pub fn withSender(self: *Self, send_fn: *const SendFn, context: ?*anyopaque) void {
        self.send_fn = send_fn;
        self.send_context = context;
    }

    /// Posts JSON-RPC payload with best-effort timeout/retry enforcement.
    /// Note: actual socket-level deadlines are not enforced by std.http; we fall back
    /// to elapsed-time checks and retry bounds to avoid hanging forever.
    pub fn post(self: Self, json_payload: []const u8) ![]u8 {
        const sender = self.send_fn orelse return errors.NetworkError.NetworkUnavailable;
        var overall = std.time.Timer.start() catch return errors.NetworkError.RequestFailed;
        var attempt: u32 = 0;
        while (attempt <= self.max_retries) {
            const response = (if (sender == &defaultSend and self.send_context == null)
                sendFetch(self.allocator, self.endpoint, json_payload, self.timeout_ms, self.max_response_bytes)
            else
                sender(self.send_context, self.allocator, self.endpoint, json_payload, self.timeout_ms)) catch |err| {
                if (overall.read() / std.time.ns_per_ms >= self.timeout_ms) {
                    return errors.NetworkError.NetworkTimeout;
                }
                attempt += 1;
                if (attempt > self.max_retries or !shouldRetry(err)) {
                    return err;
                }
                // Backoff omitted on platforms without std.time.sleep
                continue;
            };
            return response;
        }
        return errors.NetworkError.NetworkTimeout;
    }

    pub fn jsonRpcRequest(
        self: Self,
        method: []const u8,
        params: std.json.Value,
        request_id: u32,
    ) !std.json.Value {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const temp_allocator = arena.allocator();

        var request_obj = std.json.ObjectMap.init(temp_allocator);
        try json_utils.putOwnedKey(&request_obj, temp_allocator, "jsonrpc", std.json.Value{ .string = try temp_allocator.dupe(u8, "2.0") });
        try json_utils.putOwnedKey(&request_obj, temp_allocator, "method", std.json.Value{ .string = try temp_allocator.dupe(u8, method) });
        try json_utils.putOwnedKey(&request_obj, temp_allocator, "params", params);
        try json_utils.putOwnedKey(&request_obj, temp_allocator, "id", std.json.Value{ .integer = @intCast(request_id) });

        const request_json = std.json.Value{ .object = request_obj };

        const request_bytes = try std.json.stringifyAlloc(self.allocator, request_json, .{});
        defer self.allocator.free(request_bytes);

        const response_body = try self.post(request_bytes);
        defer self.allocator.free(response_body);

        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, response_body, .{});
        defer parsed.deinit();

        const response_obj = parsed.value.object;

        if (response_obj.get("error")) |error_value| {
            const error_code = error_value.object.get("code").?.integer;
            const error_message = error_value.object.get("message").?.string;
            if (!builtin.is_test) {
                log.debug("RPC Error {d}: {s}", .{ error_code, error_message });
            }
            return errors.NetworkError.ServerError;
        }

        const result = response_obj.get("result") orelse return errors.NetworkError.InvalidResponse;
        return try json_utils.cloneValue(result, self.allocator);
    }

    pub fn validateConnection(self: Self) !bool {
        var params_array = std.json.Array.init(self.allocator);
        defer params_array.deinit();
        const params = std.json.Value{ .array = params_array };
        _ = self.jsonRpcRequest("getversion", params, 1) catch |err| {
            switch (err) {
                error.NetworkTimeout, error.ConnectionFailed => return false,
                else => return err,
            }
        };
        return true;
    }

    pub fn getNetworkLatency(self: Self) !u64 {
        var timer = try std.time.Timer.start();
        var params_array = std.json.Array.init(self.allocator);
        defer params_array.deinit();
        const params = std.json.Value{ .array = params_array };
        _ = try self.jsonRpcRequest("getblockcount", params, 1);
        return timer.read() / std.time.ns_per_ms;
    }
};

pub const HttpClientFactory = struct {
    pub fn mainnet(allocator: std.mem.Allocator) HttpClient {
        return HttpClient.init(allocator, "https://mainnet1.neo.coz.io:443");
    }

    pub fn testnet(allocator: std.mem.Allocator) HttpClient {
        return HttpClient.init(allocator, "https://testnet1.neo.coz.io:443");
    }

    pub fn localhost(allocator: std.mem.Allocator, port: ?u16) HttpClient {
        const actual_port = port orelse 20332;
        const endpoint = std.fmt.allocPrint(allocator, "http://localhost:{d}", .{actual_port}) catch return HttpClient.init(allocator, "http://localhost:20332");
        return HttpClient.initOwned(allocator, endpoint);
    }
};

fn shouldRetry(err: errors.NetworkError) bool {
    return switch (err) {
        error.ConnectionFailed, error.ServerError, error.NetworkUnavailable, error.RequestFailed => true,
        else => false,
    };
}

fn sendFetch(
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    payload: []const u8,
    timeout_ms: u32,
    max_response_bytes: usize,
) errors.NetworkError![]u8 {
    var timer = std.time.Timer.start() catch return errors.NetworkError.RequestFailed;

    var client = http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = std.Uri.parse(endpoint) catch return errors.NetworkError.InvalidEndpoint;

    var response_body = ArrayList(u8).init(allocator);
    defer response_body.deinit();

    const result = client.fetch(.{
        .location = .{ .uri = uri },
        .method = .POST,
        .payload = payload,
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .user_agent = .{ .override = "Neo-Zig-SDK/1.0" },
        },
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .response_storage = .{ .dynamic = &response_body },
        .max_append_size = max_response_bytes,
    }) catch |err| {
        return mapFetchError(err);
    };

    validateHttpStatus(result.status) catch |err| return err;

    const body = response_body.toOwnedSlice() catch return errors.NetworkError.RequestFailed;

    if (timer.read() / std.time.ns_per_ms > timeout_ms) {
        allocator.free(body);
        return errors.NetworkError.NetworkTimeout;
    }

    return body;
}

fn validateHttpStatus(status: std.http.Status) errors.NetworkError!void {
    switch (status) {
        .ok => {},
        .bad_request => return errors.NetworkError.RequestFailed,
        .unauthorized => return errors.NetworkError.AuthenticationFailed,
        .not_found => return errors.NetworkError.InvalidEndpoint,
        .internal_server_error => return errors.NetworkError.ServerError,
        .service_unavailable => return errors.NetworkError.NetworkUnavailable,
        .gateway_timeout => return errors.NetworkError.NetworkTimeout,
        else => {
            if (status.class() == .server_error) return errors.NetworkError.ServerError;
            return errors.NetworkError.InvalidResponse;
        },
    }
}

fn defaultSend(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) errors.NetworkError![]u8 {
    _ = ctx;
    return sendFetch(allocator, endpoint, payload, timeout_ms, HttpClient.DEFAULT_MAX_RESPONSE_BYTES);
}

fn mapFetchError(err: anyerror) errors.NetworkError {
    return switch (err) {
        error.UnsupportedUriScheme, error.UriMissingHost, error.UriHostTooLong => errors.NetworkError.InvalidEndpoint,

        error.NetworkUnreachable, error.ConnectionRefused, error.ConnectionResetByPeer, error.UnknownHostName, error.HostLacksNetworkAddresses, error.UnexpectedConnectFailure => errors.NetworkError.ConnectionFailed,

        error.ConnectionTimedOut => errors.NetworkError.NetworkTimeout,
        error.TemporaryNameServerFailure, error.NameServerFailure => errors.NetworkError.NetworkUnavailable,
        error.StreamTooLong => errors.NetworkError.InvalidResponse,
        error.CertificateBundleLoadFailure, error.TooManyHttpRedirects, error.WriteFailed, error.UnsupportedCompressionMethod => errors.NetworkError.RequestFailed,
        else => errors.NetworkError.RequestFailed,
    };
}

const StubContext = struct { storage: *ArrayList(u8) };

fn stubSend(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) errors.NetworkError![]u8 {
    _ = timeout_ms;
    std.testing.expectEqualStrings("http://example.com", endpoint) catch return errors.NetworkError.RequestFailed;
    const raw_ptr = ctx orelse return errors.NetworkError.RequestFailed;
    const context_ptr: *StubContext = @as(*StubContext, @alignCast(@ptrCast(raw_ptr)));
    context_ptr.storage.clearRetainingCapacity();
    context_ptr.storage.appendSlice(payload) catch return errors.NetworkError.RequestFailed;
    return allocator.dupe(u8, "{\"jsonrpc\":\"2.0\",\"result\":42,\"id\":1}") catch return errors.NetworkError.RequestFailed;
}

test "HttpClient custom sender" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var captured = ArrayList(u8).init(allocator);
    defer captured.deinit();

    var context = StubContext{ .storage = &captured };
    var client = HttpClient.init(allocator, "http://example.com");
    defer client.deinit();
    client.withSender(stubSend, &context);

    var params_array = std.json.Array.init(allocator);
    defer params_array.deinit();
    const params = std.json.Value{ .array = params_array };
    const result = try client.jsonRpcRequest("getnumber", params, 1);
    try testing.expectEqual(@as(i64, 42), result.integer);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"method\":\"getnumber\",\"params\":[],\"id\":1}", captured.items);
}

test "HttpClient maps oversized response to InvalidResponse" {
    const testing = std.testing;
    try testing.expectEqual(errors.NetworkError.InvalidResponse, mapFetchError(error.StreamTooLong));
}

test "HttpClient validates HTTP status codes" {
    const testing = std.testing;
    try validateHttpStatus(.ok);
    try testing.expectError(errors.NetworkError.InvalidEndpoint, validateHttpStatus(.not_found));
    try testing.expectError(errors.NetworkError.AuthenticationFailed, validateHttpStatus(.unauthorized));
    try testing.expectError(errors.NetworkError.RequestFailed, validateHttpStatus(.bad_request));
}

test "HttpClient maps redirect loops to RequestFailed" {
    const testing = std.testing;
    try testing.expectEqual(errors.NetworkError.RequestFailed, mapFetchError(error.TooManyHttpRedirects));
}
