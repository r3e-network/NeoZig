//! Protocol Error Implementation
//!
//! Complete conversion from NeoSwift ProtocolError.swift
//! Provides protocol-specific error handling for Neo RPC communication.

const std = @import("std");
const builtin = @import("builtin");

const StackItem = @import("../types/stack_item.zig").StackItem;

const log = std.log.scoped(.neo_protocol);

/// Protocol errors for Neo RPC communication (converted from Swift ProtocolError)
pub const ProtocolError = union(enum) {
    /// RPC response error from Neo node
    RpcResponseError: []const u8,
    /// Invocation resulted in FAULT VM state
    InvocationFaultState: []const u8,
    /// Client connection error
    ClientConnection: []const u8,
    /// Stack item cast error
    StackItemCastError: struct {
        item_type: []const u8,
        target_type: []const u8,
    },

    const Self = @This();

    /// Creates RPC response error (equivalent to Swift .rpcResponseError)
    pub fn rpcResponseError(error_message: []const u8, allocator: std.mem.Allocator) !Self {
        const message_copy = try allocator.dupe(u8, error_message);
        return Self{ .RpcResponseError = message_copy };
    }

    /// Creates invocation fault state error (equivalent to Swift .invocationFaultState)
    pub fn invocationFaultState(error_message: []const u8, allocator: std.mem.Allocator) !Self {
        const message_copy = try allocator.dupe(u8, error_message);
        return Self{ .InvocationFaultState = message_copy };
    }

    /// Creates client connection error (equivalent to Swift .clientConnection)
    pub fn clientConnection(error_message: []const u8, allocator: std.mem.Allocator) !Self {
        const message_copy = try allocator.dupe(u8, error_message);
        return Self{ .ClientConnection = message_copy };
    }

    /// Creates stack item cast error (equivalent to Swift .stackItemCastError)
    pub fn stackItemCastError(
        item: StackItem,
        target_type: []const u8,
        allocator: std.mem.Allocator,
    ) !Self {
        const item_type_copy = try allocator.dupe(u8, item.getJsonValue());
        const target_type_copy = try allocator.dupe(u8, target_type);

        return Self{ .StackItemCastError = .{
            .item_type = item_type_copy,
            .target_type = target_type_copy,
        } };
    }

    /// Gets error description (equivalent to Swift errorDescription)
    pub fn getErrorDescription(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .RpcResponseError => |error_msg| {
                return try std.fmt.allocPrint(allocator, "The Neo node responded with an error: {s}", .{error_msg});
            },
            .InvocationFaultState => |error_msg| {
                return try std.fmt.allocPrint(allocator, "The invocation resulted in a FAULT VM state. The VM exited due to the following exception: {s}", .{error_msg});
            },
            .ClientConnection => |message| {
                return try allocator.dupe(u8, message);
            },
            .StackItemCastError => |cast_error| {
                return try std.fmt.allocPrint(allocator, "Cannot cast stack item {s} to a {s}.", .{ cast_error.item_type, cast_error.target_type });
            },
        };
    }

    /// Throws appropriate Zig error
    pub fn throwError(self: Self, allocator: std.mem.Allocator) !void {
        const description = try self.getErrorDescription(allocator);
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Protocol Error: {s}", .{description});
        }

        return switch (self) {
            .RpcResponseError => error.RpcError,
            .InvocationFaultState => error.VMFaultState,
            .ClientConnection => error.NetworkError,
            .StackItemCastError => error.TypeCastError,
        };
    }

    /// Logs error without throwing
    pub fn logError(self: Self, allocator: std.mem.Allocator) void {
        const description = self.getErrorDescription(allocator) catch "Unknown protocol error";
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Protocol Error: {s}", .{description});
        }
    }

    /// Gets error severity
    pub fn getSeverity(self: Self) ErrorSeverity {
        return switch (self) {
            .RpcResponseError => .Error,
            .InvocationFaultState => .Error,
            .ClientConnection => .Warning, // Might be temporary
            .StackItemCastError => .Error,
        };
    }

    /// Checks if error is recoverable
    pub fn isRecoverable(self: Self) bool {
        return switch (self) {
            .RpcResponseError => false, // Node error
            .InvocationFaultState => false, // VM fault
            .ClientConnection => true, // Network issue - might recover
            .StackItemCastError => false, // Type mismatch
        };
    }

    /// Checks if error indicates network issue
    pub fn isNetworkError(self: Self) bool {
        return switch (self) {
            .ClientConnection => true,
            else => false,
        };
    }

    /// Checks if error indicates VM issue
    pub fn isVmError(self: Self) bool {
        return switch (self) {
            .InvocationFaultState => true,
            else => false,
        };
    }

    /// Creates from JSON-RPC error response
    pub fn fromJsonRpcError(error_code: i32, error_message: []const u8, allocator: std.mem.Allocator) !Self {
        return switch (error_code) {
            -32700...-32600 => try Self.rpcResponseError(error_message, allocator),
            -32000...-30000 => try Self.invocationFaultState(error_message, allocator),
            else => try Self.clientConnection(error_message, allocator),
        };
    }

    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .RpcResponseError => |message| {
                allocator.free(message);
            },
            .InvocationFaultState => |message| {
                allocator.free(message);
            },
            .ClientConnection => |message| {
                allocator.free(message);
            },
            .StackItemCastError => |cast_error| {
                allocator.free(cast_error.item_type);
                allocator.free(cast_error.target_type);
            },
        }
    }

    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const description = try self.getErrorDescription(allocator);
        defer allocator.free(description);

        return try std.fmt.allocPrint(allocator, "ProtocolError({s}): {s}", .{ self.getSeverity().toString(), description });
    }
};

/// Error severity levels
pub const ErrorSeverity = enum {
    Warning,
    Error,
    Critical,

    pub fn toString(self: ErrorSeverity) []const u8 {
        return switch (self) {
            .Warning => "WARNING",
            .Error => "ERROR",
            .Critical => "CRITICAL",
        };
    }
};

/// Protocol error utilities
pub const ProtocolErrorUtils = struct {
    /// Creates error from HTTP status code
    pub fn fromHttpStatus(status_code: u32, response_body: []const u8, allocator: std.mem.Allocator) !ProtocolError {
        const message = try std.fmt.allocPrint(allocator, "HTTP {} error: {s}", .{ status_code, response_body });

        return switch (status_code) {
            400...499 => try ProtocolError.rpcResponseError(message, allocator),
            500...599 => try ProtocolError.invocationFaultState(message, allocator),
            else => try ProtocolError.clientConnection(message, allocator),
        };
    }

    /// Creates error from timeout
    pub fn fromTimeout(operation: []const u8, timeout_ms: u32, allocator: std.mem.Allocator) !ProtocolError {
        const message = try std.fmt.allocPrint(allocator, "Operation '{s}' timed out after {}ms", .{ operation, timeout_ms });

        return try ProtocolError.clientConnection(message, allocator);
    }

    /// Creates error from network failure
    pub fn fromNetworkFailure(operation: []const u8, error_details: []const u8, allocator: std.mem.Allocator) !ProtocolError {
        const message = try std.fmt.allocPrint(allocator, "Network failure during '{s}': {s}", .{ operation, error_details });

        return try ProtocolError.clientConnection(message, allocator);
    }

    /// Handles protocol error with retry logic
    pub fn handleWithRetry(
        error_obj: ProtocolError,
        operation: []const u8,
        retry_count: u32,
        max_retries: u32,
        allocator: std.mem.Allocator,
    ) !bool {
        if (!error_obj.isRecoverable()) {
            try error_obj.throwError(allocator);
            return false;
        }

        if (retry_count >= max_retries) {
            if (!builtin.is_test) {
                log.debug("Maximum retries ({}) exceeded for operation '{s}'", .{ max_retries, operation });
            }
            try error_obj.throwError(allocator);
            return false;
        }

        std.log.warn("Retrying operation '{s}' (attempt {}/{})", .{ operation, retry_count + 1, max_retries });

        // Exponential backoff
        const delay_ms = @min(30000, 1000 * (@as(u64, 1) << @intCast(retry_count)));
        std.time.sleep(delay_ms * std.time.ns_per_ms);

        return true; // Indicate should retry
    }
};

// Tests (converted from Swift ProtocolError tests)
test "ProtocolError creation and descriptions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test RPC response error (equivalent to Swift tests)
    var rpc_error = try ProtocolError.rpcResponseError("Method not found", allocator);
    defer rpc_error.deinit(allocator);

    const rpc_description = try rpc_error.getErrorDescription(allocator);
    defer allocator.free(rpc_description);

    try testing.expect(std.mem.indexOf(u8, rpc_description, "Neo node responded") != null);
    try testing.expect(std.mem.indexOf(u8, rpc_description, "Method not found") != null);
    try testing.expectEqual(ErrorSeverity.Error, rpc_error.getSeverity());
    try testing.expect(!rpc_error.isRecoverable());

    // Test invocation fault state error
    var fault_error = try ProtocolError.invocationFaultState("Contract execution failed", allocator);
    defer fault_error.deinit(allocator);

    const fault_description = try fault_error.getErrorDescription(allocator);
    defer allocator.free(fault_description);

    try testing.expect(std.mem.indexOf(u8, fault_description, "FAULT VM state") != null);
    try testing.expect(std.mem.indexOf(u8, fault_description, "Contract execution failed") != null);
    try testing.expect(fault_error.isVmError());

    // Test client connection error
    var connection_error = try ProtocolError.clientConnection("Connection refused", allocator);
    defer connection_error.deinit(allocator);

    try testing.expect(connection_error.isNetworkError());
    try testing.expect(connection_error.isRecoverable());
}

test "ProtocolError stack item cast error" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test stack item cast error
    const stack_item = StackItem.Factory.createBoolean(true);
    var cast_error = try ProtocolError.stackItemCastError(stack_item, "Integer", allocator);
    defer cast_error.deinit(allocator);

    const cast_description = try cast_error.getErrorDescription(allocator);
    defer allocator.free(cast_description);

    try testing.expect(std.mem.indexOf(u8, cast_description, "Cannot cast") != null);
    try testing.expect(std.mem.indexOf(u8, cast_description, "Boolean") != null);
    try testing.expect(std.mem.indexOf(u8, cast_description, "Integer") != null);
}

test "ProtocolErrorUtils factory methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test from HTTP status
    var http_error = try ProtocolErrorUtils.fromHttpStatus(404, "Not Found", allocator);
    defer http_error.deinit(allocator);

    const http_description = try http_error.getErrorDescription(allocator);
    defer allocator.free(http_description);

    try testing.expect(std.mem.indexOf(u8, http_description, "HTTP 404") != null);
    try testing.expect(std.mem.indexOf(u8, http_description, "Not Found") != null);

    // Test from timeout
    var timeout_error = try ProtocolErrorUtils.fromTimeout("getversion", 5000, allocator);
    defer timeout_error.deinit(allocator);

    const timeout_description = try timeout_error.getErrorDescription(allocator);
    defer allocator.free(timeout_description);

    try testing.expect(std.mem.indexOf(u8, timeout_description, "timed out") != null);
    try testing.expect(std.mem.indexOf(u8, timeout_description, "getversion") != null);
    try testing.expect(std.mem.indexOf(u8, timeout_description, "5000ms") != null);

    // Test from network failure
    var network_error = try ProtocolErrorUtils.fromNetworkFailure("connect", "Connection refused", allocator);
    defer network_error.deinit(allocator);

    try testing.expect(network_error.isNetworkError());
    try testing.expect(network_error.isRecoverable());
}

test "ProtocolError retry handling" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test recoverable error retry
    var recoverable_error = try ProtocolError.clientConnection("Temporary network issue", allocator);
    defer recoverable_error.deinit(allocator);

    const should_retry = try ProtocolErrorUtils.handleWithRetry(
        recoverable_error,
        "test_operation",
        0, // First retry
        3, // Max retries
        allocator,
    );

    try testing.expect(should_retry);

    // Test non-recoverable error
    var non_recoverable_error = try ProtocolError.rpcResponseError("Method not found", allocator);
    defer non_recoverable_error.deinit(allocator);

    try testing.expectError(error.RpcError, ProtocolErrorUtils.handleWithRetry(
        non_recoverable_error,
        "test_operation",
        0,
        3,
        allocator,
    ));
}

test "ProtocolError formatting and utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test formatting
    var error_obj = try ProtocolError.rpcResponseError("Test error", allocator);
    defer error_obj.deinit(allocator);

    const formatted = try error_obj.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "ProtocolError") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "ERROR") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "Test error") != null);

    // Test error classification
    try testing.expect(!error_obj.isNetworkError());
    try testing.expect(!error_obj.isVmError());
    try testing.expectEqual(ErrorSeverity.Error, error_obj.getSeverity());
}

test "ProtocolError JSON-RPC error creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test JSON-RPC error codes
    var parse_error = try ProtocolError.fromJsonRpcError(-32700, "Parse error", allocator);
    defer parse_error.deinit(allocator);

    try testing.expect(std.meta.activeTag(parse_error) == .RpcResponseError);

    var vm_error = try ProtocolError.fromJsonRpcError(-32001, "VM execution failed", allocator);
    defer vm_error.deinit(allocator);

    try testing.expect(std.meta.activeTag(vm_error) == .InvocationFaultState);

    var other_error = try ProtocolError.fromJsonRpcError(-1000, "Unknown error", allocator);
    defer other_error.deinit(allocator);

    try testing.expect(std.meta.activeTag(other_error) == .ClientConnection);
}
