//! HTTP Client implementation
//!
//! Provides JSON-RPC transport for Neo nodes with pluggable send behaviour.

const std = @import("std");
const errors = @import("../core/errors.zig");
const json_utils = @import("../utils/json_utils.zig");

const ArrayList = std.array_list.Managed;
const http = std.http;
const Uri = std.Uri;

pub const HttpClient = struct {
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    timeout_ms: u32,
    max_retries: u32,
    send_fn: ?*const SendFn,
    send_context: ?*anyopaque,

    const Self = @This();
    const SendFn = fn (ctx: ?*anyopaque, allocator: std.mem.Allocator, endpoint: []const u8, payload: []const u8, timeout_ms: u32) errors.NetworkError![]u8;

    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) Self {
        return Self{
            .allocator = allocator,
            .endpoint = endpoint,
            .timeout_ms = 30_000,
            .max_retries = 3,
            .send_fn = &defaultSend,
            .send_context = null,
        };
    }

    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }

    pub fn setMaxRetries(self: *Self, max_retries: u32) void {
        self.max_retries = max_retries;
    }

    /// Overrides outbound transport (useful for tests/mocks).
    pub fn withSender(self: *Self, send_fn: *const SendFn, context: ?*anyopaque) void {
        self.send_fn = send_fn;
        self.send_context = context;
    }

    pub fn post(self: Self, json_payload: []const u8) ![]u8 {
    const sender = self.send_fn orelse return errors.NetworkError.NetworkUnavailable;
        var attempt: u32 = 0;
        while (attempt <= self.max_retries) {
            const response = sender(self.send_context, self.allocator, self.endpoint, json_payload, self.timeout_ms) catch |err| {
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

        var writer_state = std.Io.Writer.Allocating.init(self.allocator);
        defer writer_state.deinit();
        var stringify = std.json.Stringify{ .writer = &writer_state.writer, .options = .{} };
        try stringify.write(request_json);

        const request_bytes = try writer_state.toOwnedSlice();
        defer self.allocator.free(request_bytes);

        const response_body = try self.post(request_bytes);
        defer self.allocator.free(response_body);

        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, response_body, .{});
        defer parsed.deinit();

        const response_obj = parsed.value.object;

        if (response_obj.get("error")) |error_value| {
            const error_code = error_value.object.get("code").?.integer;
            const error_message = error_value.object.get("message").?.string;
            std.log.err("RPC Error {d}: {s}", .{ error_code, error_message });
            return errors.NetworkError.ServerError;
        }

        const result = response_obj.get("result") orelse return errors.NetworkError.InvalidResponse;
        return try json_utils.cloneValue(result, self.allocator);
    }

    pub fn validateConnection(self: Self) !bool {
        const params_array = std.json.Array.init(self.allocator);
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
        const params_array = std.json.Array.init(self.allocator);
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
        const endpoint = std.fmt.allocPrint(allocator, "http://localhost:{d}", .{actual_port}) catch "http://localhost:20332";
        return HttpClient.init(allocator, endpoint);
    }
};

fn shouldRetry(err: errors.NetworkError) bool {
    return switch (err) {
        error.ConnectionFailed,
        error.NetworkTimeout,
        error.ServerError,
        error.NetworkUnavailable,
        error.RequestFailed => true,
        else => false,
    };
}

fn defaultSend(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) errors.NetworkError![]u8 {
    _ = ctx;
    _ = timeout_ms;

    var client = http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = std.Uri.parse(endpoint) catch return errors.NetworkError.InvalidEndpoint;

    var request = client.request(.POST, uri, .{
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .user_agent = .{ .override = "Neo-Zig-SDK/1.0" },
        },
        .keep_alive = false,
    }) catch return errors.NetworkError.ConnectionFailed;
    defer request.deinit();

    request.transfer_encoding = .{ .content_length = payload.len };
    var body_buffer: [512]u8 = undefined;
    var body_writer = request.sendBody(&body_buffer) catch return errors.NetworkError.RequestFailed;
    body_writer.writer.writeAll(payload) catch return errors.NetworkError.RequestFailed;
    body_writer.end() catch return errors.NetworkError.RequestFailed;

    var redirect_buffer: [0]u8 = .{};
    var response = request.receiveHead(redirect_buffer[0..]) catch return errors.NetworkError.InvalidResponse;

    if (response.head.status.class() == .server_error) {
        return errors.NetworkError.ServerError;
    }

    if (response.head.content_encoding != .identity) {
        return errors.NetworkError.InvalidResponse;
    }

    var transfer_buffer: [1024]u8 = undefined;
    var reader_ptr = response.reader(&transfer_buffer);
    var response_writer = std.Io.Writer.Allocating.init(allocator);
    defer response_writer.deinit();
    _ = reader_ptr.streamRemaining(&response_writer.writer) catch return errors.NetworkError.InvalidResponse;
    const body = response_writer.toOwnedSlice() catch return errors.NetworkError.RequestFailed;

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
        error.UnsupportedCompressionMethod => errors.NetworkError.RequestFailed,
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
    client.withSender(stubSend, &context);

    const params_array = std.json.Array.init(allocator);
    const params = std.json.Value{ .array = params_array };
    const result = try client.jsonRpcRequest("getnumber", params, 1);
    try testing.expectEqual(@as(i64, 42), result.integer);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"method\":\"getnumber\",\"params\":[],\"id\":1}", captured.items);
}
