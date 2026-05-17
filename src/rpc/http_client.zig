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

/// Structured JSON-RPC error reported by the server.
/// Populated on `HttpClient.last_rpc_error` whenever a JSON-RPC response
/// contains an `error` member. Always cleared at the start of every call.
pub const ServerError = struct {
    code: i32,
    message: []const u8,
    data: ?[]const u8,

    /// Frees owned strings on `message` and `data`.
    pub fn deinit(self: *ServerError, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
        if (self.data) |d| allocator.free(d);
        self.message = "";
        self.data = null;
    }
};

/// Exponential-backoff retry parameters.
pub const Backoff = struct {
    /// First-retry delay in milliseconds.
    initial_ms: u32 = 500,
    /// Growth factor applied per attempt.
    multiplier: f32 = 2.0,
    /// Maximum delay between attempts in milliseconds.
    max_ms: u32 = 30_000,
    /// Jitter as a fraction of the computed delay, e.g. 0.25 = ±25%.
    jitter: f32 = 0.25,

    /// Computes the delay for `attempt` (0-based: first retry is attempt=0).
    pub fn delayMs(self: Backoff, attempt: u32, rng: *std.Random.DefaultPrng) u32 {
        const base: f32 = @floatFromInt(self.initial_ms);
        var pow: f32 = 1.0;
        var i: u32 = 0;
        while (i < attempt) : (i += 1) pow *= self.multiplier;
        var delay = base * pow;
        if (delay > @as(f32, @floatFromInt(self.max_ms))) {
            delay = @floatFromInt(self.max_ms);
        }
        if (self.jitter > 0) {
            const span = delay * self.jitter;
            const r = rng.random().float(f32) * 2.0 - 1.0; // [-1, 1]
            delay += r * span;
            if (delay < 0) delay = 0;
        }
        return @intFromFloat(delay);
    }
};

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
    backoff: Backoff = .{},
    send_fn: ?*const SendFn,
    send_context: ?*anyopaque,
    /// Auto-incrementing JSON-RPC request id.
    next_request_id: u32 = 1,
    /// Populated when the last `jsonRpcRequest` saw a structured server error.
    /// Owned by the client; cleared at the start of each call.
    last_rpc_error: ?ServerError = null,

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
        if (self.last_rpc_error) |*err| err.deinit(self.allocator);
        self.last_rpc_error = null;
        if (self.owns_endpoint) {
            self.allocator.free(self.endpoint);
            self.owns_endpoint = false;
        }
    }

    /// Overrides the retry backoff policy.
    pub fn setBackoff(self: *Self, backoff: Backoff) void {
        self.backoff = backoff;
    }

    /// Consumes and returns the last structured server error, transferring
    /// ownership to the caller. Returns null when there is no captured error.
    pub fn takeLastServerError(self: *Self) ?ServerError {
        const out = self.last_rpc_error;
        self.last_rpc_error = null;
        return out;
    }

    fn clearLastError(self: *Self) void {
        if (self.last_rpc_error) |*err| err.deinit(self.allocator);
        self.last_rpc_error = null;
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

    /// Posts a JSON-RPC payload, retrying transient failures with
    /// exponential backoff. The retry budget is bounded by `max_retries`;
    /// the per-attempt timeout is `timeout_ms`. The std.http transport does
    /// not enforce socket-level deadlines, so `timeout_ms` is also re-checked
    /// against the cumulative elapsed time as a backstop.
    pub fn post(self: Self, json_payload: []const u8) ![]u8 {
        const sender = self.send_fn orelse return errors.NetworkError.NetworkUnavailable;
        var overall = std.time.Timer.start() catch return errors.NetworkError.RequestFailed;
        var rng = std.Random.DefaultPrng.init(seedFromTimer(&overall));
        var attempt: u32 = 0;
        while (true) {
            const send_attempt = if (sender == &defaultSend and self.send_context == null)
                sendFetch(self.allocator, self.endpoint, json_payload, self.timeout_ms, self.max_response_bytes)
            else
                sender(self.send_context, self.allocator, self.endpoint, json_payload, self.timeout_ms);

            if (send_attempt) |response| {
                return response;
            } else |err| {
                if (overall.read() / std.time.ns_per_ms >= self.timeout_ms) {
                    return errors.NetworkError.NetworkTimeout;
                }
                if (attempt >= self.max_retries or !shouldRetry(err)) {
                    return err;
                }
                const delay_ms = self.backoff.delayMs(attempt, &rng);
                if (delay_ms > 0) {
                    std.time.sleep(@as(u64, delay_ms) * std.time.ns_per_ms);
                }
                attempt += 1;
            }
        }
    }

    /// Issues a JSON-RPC 2.0 request and returns the `result` value.
    ///
    /// Auto-assigns a sequential request id from `next_request_id` when
    /// `request_id` is null, so callers can omit it. On a structured server
    /// error response (the JSON contains an `error` member) the parsed
    /// `code`/`message`/`data` is captured on `last_rpc_error` and the call
    /// returns `error.ServerError` — inspect via `takeLastServerError`.
    pub fn jsonRpcRequest(
        self: *Self,
        method: []const u8,
        params: std.json.Value,
        request_id: ?u32,
    ) !std.json.Value {
        self.clearLastError();
        const id = request_id orelse blk: {
            const value = self.next_request_id;
            self.next_request_id = if (value == std.math.maxInt(u32)) 1 else value + 1;
            break :blk value;
        };

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const temp_allocator = arena.allocator();

        var request_obj = std.json.ObjectMap.init(temp_allocator);
        try json_utils.putOwnedKey(&request_obj, temp_allocator, "jsonrpc", std.json.Value{ .string = try temp_allocator.dupe(u8, "2.0") });
        try json_utils.putOwnedKey(&request_obj, temp_allocator, "method", std.json.Value{ .string = try temp_allocator.dupe(u8, method) });
        try json_utils.putOwnedKey(&request_obj, temp_allocator, "params", params);
        try json_utils.putOwnedKey(&request_obj, temp_allocator, "id", std.json.Value{ .integer = @intCast(id) });

        const request_json = std.json.Value{ .object = request_obj };

        const request_bytes = try std.json.stringifyAlloc(self.allocator, request_json, .{});
        defer self.allocator.free(request_bytes);

        const response_body = try self.post(request_bytes);
        defer self.allocator.free(response_body);

        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, response_body, .{});
        defer parsed.deinit();

        const response_obj = parsed.value.object;

        if (response_obj.get("error")) |error_value| {
            try self.captureServerError(error_value);
            if (!builtin.is_test) {
                if (self.last_rpc_error) |rec| log.debug("RPC Error {d}: {s}", .{ rec.code, rec.message });
            }
            return errors.NetworkError.ServerError;
        }

        const result = response_obj.get("result") orelse return errors.NetworkError.InvalidResponse;
        return try json_utils.cloneValue(result, self.allocator);
    }

    fn captureServerError(self: *Self, error_value: std.json.Value) !void {
        if (error_value != .object) return errors.NetworkError.InvalidResponse;
        const obj = error_value.object;
        const code: i32 = if (obj.get("code")) |c| switch (c) {
            .integer => |v| @intCast(v),
            else => 0,
        } else 0;
        const message_src: []const u8 = if (obj.get("message")) |m| switch (m) {
            .string => |s| s,
            else => "",
        } else "";
        const message_owned = try self.allocator.dupe(u8, message_src);
        errdefer self.allocator.free(message_owned);
        var data_owned: ?[]const u8 = null;
        if (obj.get("data")) |d| switch (d) {
            .string => |s| data_owned = try self.allocator.dupe(u8, s),
            else => {},
        };
        self.last_rpc_error = ServerError{
            .code = code,
            .message = message_owned,
            .data = data_owned,
        };
    }

    pub fn validateConnection(self: *Self) !bool {
        var params_array = std.json.Array.init(self.allocator);
        defer params_array.deinit();
        const params = std.json.Value{ .array = params_array };
        _ = self.jsonRpcRequest("getversion", params, null) catch |err| {
            switch (err) {
                error.NetworkTimeout, error.ConnectionFailed => return false,
                else => return err,
            }
        };
        return true;
    }

    pub fn getNetworkLatency(self: *Self) !u64 {
        var timer = try std.time.Timer.start();
        var params_array = std.json.Array.init(self.allocator);
        defer params_array.deinit();
        const params = std.json.Value{ .array = params_array };
        _ = try self.jsonRpcRequest("getblockcount", params, null);
        return timer.read() / std.time.ns_per_ms;
    }
};

/// Seeds a PRNG from the current monotonic time. Deterministic only within
/// a single nanosecond, which is fine for jitter purposes.
fn seedFromTimer(timer: *std.time.Timer) u64 {
    return @as(u64, @bitCast(@as(i64, @intCast(timer.read())))) ^ 0xa5a5a5a5a5a5a5a5;
}

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
            .user_agent = .{ .override = "Neo-Zig-SDK/1.0.1" },
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
        .forbidden => return errors.NetworkError.AuthenticationFailed,
        .not_found => return errors.NetworkError.InvalidEndpoint,
        .request_timeout => return errors.NetworkError.NetworkTimeout,
        .too_many_requests => return errors.NetworkError.RateLimitExceeded,
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
    const result = try client.jsonRpcRequest("getnumber", params, null);
    try testing.expectEqual(@as(i64, 42), result.integer);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"method\":\"getnumber\",\"params\":[],\"id\":1}", captured.items);

    // Second call uses the next request id.
    var params2 = std.json.Array.init(allocator);
    defer params2.deinit();
    _ = try client.jsonRpcRequest("getnumber", std.json.Value{ .array = params2 }, null);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"method\":\"getnumber\",\"params\":[],\"id\":2}", captured.items);
}

test "Backoff.delayMs grows exponentially up to max" {
    const testing = std.testing;
    var rng = std.Random.DefaultPrng.init(42);
    const policy = Backoff{
        .initial_ms = 100,
        .multiplier = 2.0,
        .max_ms = 1_000,
        .jitter = 0,
    };
    try testing.expectEqual(@as(u32, 100), policy.delayMs(0, &rng));
    try testing.expectEqual(@as(u32, 200), policy.delayMs(1, &rng));
    try testing.expectEqual(@as(u32, 400), policy.delayMs(2, &rng));
    try testing.expectEqual(@as(u32, 800), policy.delayMs(3, &rng));
    try testing.expectEqual(@as(u32, 1_000), policy.delayMs(4, &rng));
    try testing.expectEqual(@as(u32, 1_000), policy.delayMs(5, &rng));
}

test "Backoff.delayMs applies jitter within fraction" {
    const testing = std.testing;
    var rng = std.Random.DefaultPrng.init(7);
    const policy = Backoff{
        .initial_ms = 1_000,
        .multiplier = 1.0,
        .max_ms = 10_000,
        .jitter = 0.5,
    };
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const d = policy.delayMs(0, &rng);
        try testing.expect(d >= 500 and d <= 1_500);
    }
}

const ServerErrorContext = struct {
    response: []const u8,
};

fn serverErrorSend(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) errors.NetworkError![]u8 {
    _ = endpoint;
    _ = payload;
    _ = timeout_ms;
    const raw_ptr = ctx orelse return errors.NetworkError.RequestFailed;
    const context_ptr: *ServerErrorContext = @ptrCast(@alignCast(raw_ptr));
    return allocator.dupe(u8, context_ptr.response) catch return errors.NetworkError.RequestFailed;
}

test "HttpClient captures structured server error" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var ctx = ServerErrorContext{
        .response = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"invalid params\"},\"id\":1}",
    };
    var client = HttpClient.init(allocator, "http://example.com");
    defer client.deinit();
    client.withSender(serverErrorSend, &ctx);

    var params_array = std.json.Array.init(allocator);
    defer params_array.deinit();
    const params = std.json.Value{ .array = params_array };

    try testing.expectError(
        errors.NetworkError.ServerError,
        client.jsonRpcRequest("badmethod", params, null),
    );

    var captured = client.takeLastServerError() orelse return error.MissingServerError;
    defer captured.deinit(allocator);
    try testing.expectEqual(@as(i32, -32602), captured.code);
    try testing.expectEqualStrings("invalid params", captured.message);
    try testing.expect(captured.data == null);

    // The error is consumed by takeLastServerError; second call returns null.
    try testing.expect(client.takeLastServerError() == null);
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
    try testing.expectError(errors.NetworkError.AuthenticationFailed, validateHttpStatus(.forbidden));
    try testing.expectError(errors.NetworkError.NetworkTimeout, validateHttpStatus(.request_timeout));
    try testing.expectError(errors.NetworkError.RateLimitExceeded, validateHttpStatus(.too_many_requests));
    try testing.expectError(errors.NetworkError.RequestFailed, validateHttpStatus(.bad_request));
}

test "HttpClient maps redirect loops to RequestFailed" {
    const testing = std.testing;
    try testing.expectEqual(errors.NetworkError.RequestFailed, mapFetchError(error.TooManyHttpRedirects));
}
