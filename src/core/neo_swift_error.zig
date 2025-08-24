//! Neo Swift Error implementation
//!
//! Complete conversion from NeoSwift NeoSwiftError.swift
//! Provides main error types for Neo Swift compatibility.

const std = @import("std");
const errors = @import("errors.zig");

/// Main Neo Swift errors (converted from Swift NeoSwiftError)
pub const NeoSwiftError = union(enum) {
    IllegalArgument: ?[]const u8,
    Deserialization: ?[]const u8,
    IllegalState: ?[]const u8,
    IndexOutOfBounds: ?[]const u8,
    Runtime: []const u8,
    UnsupportedOperation: []const u8,
    
    const Self = @This();
    
    /// Creates illegal argument error (equivalent to Swift .illegalArgument)
    pub fn illegalArgument(message: ?[]const u8) Self {
        return Self{ .IllegalArgument = message };
    }
    
    /// Creates deserialization error (equivalent to Swift .deserialization)
    pub fn deserialization(message: ?[]const u8) Self {
        return Self{ .Deserialization = message };
    }
    
    /// Creates illegal state error (equivalent to Swift .illegalState)
    pub fn illegalState(message: ?[]const u8) Self {
        return Self{ .IllegalState = message };
    }
    
    /// Creates index out of bounds error (equivalent to Swift .indexOutOfBounds)
    pub fn indexOutOfBounds(message: ?[]const u8) Self {
        return Self{ .IndexOutOfBounds = message };
    }
    
    /// Creates runtime error (equivalent to Swift .runtime)
    pub fn runtime(message: []const u8) Self {
        return Self{ .Runtime = message };
    }
    
    /// Creates unsupported operation error (equivalent to Swift .unsupportedOperation)
    pub fn unsupportedOperation(message: []const u8) Self {
        return Self{ .UnsupportedOperation = message };
    }
    
    /// Gets error description (equivalent to Swift .errorDescription)
    pub fn getErrorDescription(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .IllegalArgument => |message| {
                return if (message) |msg| try allocator.dupe(u8, msg) else try allocator.dupe(u8, "Illegal argument");
            },
            .Deserialization => |message| {
                return if (message) |msg| try allocator.dupe(u8, msg) else try allocator.dupe(u8, "Deserialization error");
            },
            .IllegalState => |message| {
                return if (message) |msg| try allocator.dupe(u8, msg) else try allocator.dupe(u8, "Illegal state");
            },
            .IndexOutOfBounds => |message| {
                return if (message) |msg| try allocator.dupe(u8, msg) else try allocator.dupe(u8, "Index out of bounds");
            },
            .Runtime => |message| try allocator.dupe(u8, message),
            .UnsupportedOperation => |message| try allocator.dupe(u8, message),
        };
    }
    
    /// Throws appropriate Zig error (utility method)
    pub fn throwError(self: Self, allocator: std.mem.Allocator) !void {
        const description = try self.getErrorDescription(allocator);
        defer allocator.free(description);
        
        std.log.err("NeoSwift Error: {s}", .{description});
        
        return switch (self) {
            .IllegalArgument => errors.NeoError.IllegalArgument,
            .Deserialization => errors.SerializationError.DeserializationFailed,
            .IllegalState => errors.NeoError.IllegalState,
            .IndexOutOfBounds => errors.ValidationError.ParameterOutOfRange,
            .Runtime => errors.NeoError.UnsupportedOperation,
            .UnsupportedOperation => errors.NeoError.UnsupportedOperation,
        };
    }
    
    /// Creates from Zig error (utility conversion)
    pub fn fromZigError(zig_error: anyerror, context: ?[]const u8, allocator: std.mem.Allocator) !Self {
        const message = if (context) |ctx| 
            try std.fmt.allocPrint(allocator, "{s}: {}", .{ ctx, zig_error })
        else 
            try std.fmt.allocPrint(allocator, "{}", .{zig_error});
        
        return switch (zig_error) {
            error.IllegalArgument => Self.illegalArgument(message),
            error.IllegalState => Self.illegalState(message),
            error.DeserializationFailed => Self.deserialization(message),
            error.ParameterOutOfRange => Self.indexOutOfBounds(message),
            error.UnsupportedOperation => Self.unsupportedOperation(message),
            else => Self.runtime(message),
        };
    }
    
    /// Logs error without throwing
    pub fn logError(self: Self, allocator: std.mem.Allocator) void {
        const description = self.getErrorDescription(allocator) catch "Unknown NeoSwift error";
        defer allocator.free(description);
        
        std.log.err("NeoSwift Error: {s}", .{description});
    }
    
    /// Gets error severity
    pub fn getSeverity(self: Self) ErrorSeverity {
        return switch (self) {
            .IllegalArgument => .Error,
            .Deserialization => .Error,
            .IllegalState => .Error,
            .IndexOutOfBounds => .Warning,
            .Runtime => .Critical,
            .UnsupportedOperation => .Warning,
        };
    }
    
    /// Checks if error is recoverable
    pub fn isRecoverable(self: Self) bool {
        return switch (self) {
            .IllegalArgument => true,    // Can fix arguments
            .Deserialization => false,   // Data corruption
            .IllegalState => false,      // State corruption
            .IndexOutOfBounds => true,   // Can fix indices
            .Runtime => false,           // Runtime failure
            .UnsupportedOperation => true, // Can use different operation
        };
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

/// NeoSwift error utilities
pub const NeoSwiftErrorUtils = struct {
    /// Common error messages
    pub const INVALID_PARAMETER_MSG = "Invalid parameter provided";
    pub const INVALID_STATE_MSG = "Invalid operation state";
    pub const DESERIALIZATION_FAILED_MSG = "Failed to deserialize data";
    pub const INDEX_OUT_OF_BOUNDS_MSG = "Index is out of bounds";
    pub const RUNTIME_FAILURE_MSG = "Runtime operation failed";
    pub const UNSUPPORTED_OPERATION_MSG = "Operation is not supported";
    
    /// Creates common error instances
    pub fn createInvalidParameterError(allocator: std.mem.Allocator) !NeoSwiftError {
        return NeoSwiftError.illegalArgument(try allocator.dupe(u8, INVALID_PARAMETER_MSG));
    }
    
    pub fn createInvalidStateError(allocator: std.mem.Allocator) !NeoSwiftError {
        return NeoSwiftError.illegalState(try allocator.dupe(u8, INVALID_STATE_MSG));
    }
    
    pub fn createDeserializationError(allocator: std.mem.Allocator) !NeoSwiftError {
        return NeoSwiftError.deserialization(try allocator.dupe(u8, DESERIALIZATION_FAILED_MSG));
    }
    
    pub fn createIndexOutOfBoundsError(allocator: std.mem.Allocator) !NeoSwiftError {
        return NeoSwiftError.indexOutOfBounds(try allocator.dupe(u8, INDEX_OUT_OF_BOUNDS_MSG));
    }
    
    pub fn createRuntimeError(error_message: []const u8, allocator: std.mem.Allocator) !NeoSwiftError {
        return NeoSwiftError.runtime(try allocator.dupe(u8, error_message));
    }
    
    pub fn createUnsupportedOperationError(operation: []const u8, allocator: std.mem.Allocator) !NeoSwiftError {
        const message = try std.fmt.allocPrint(allocator, "Unsupported operation: {s}", .{operation});
        return NeoSwiftError.unsupportedOperation(message);
    }
    
    /// Validates operation parameters
    pub fn validateParameters(params: []const anytype) NeoSwiftError!void {
        for (params) |param| {
            if (param == null) {
                return NeoSwiftError.illegalArgument("Parameter cannot be null");
            }
        }
    }
    
    /// Validates array bounds
    pub fn validateArrayBounds(array_len: usize, index: usize) NeoSwiftError!void {
        if (index >= array_len) {
            return NeoSwiftError.indexOutOfBounds("Array index out of bounds");
        }
    }
    
    /// Validates state condition
    pub fn validateState(condition: bool, message: []const u8) NeoSwiftError!void {
        if (!condition) {
            return NeoSwiftError.illegalState(message);
        }
    }
    
    /// Handles conversion errors
    pub fn handleConversionError(
        operation: []const u8,
        zig_error: anyerror,
        allocator: std.mem.Allocator,
    ) !void {
        const neo_swift_error = try NeoSwiftError.fromZigError(zig_error, operation, allocator);
        try neo_swift_error.throwError(allocator);
    }
};

// Tests (converted from Swift NeoSwiftError tests)
test "NeoSwiftError creation and descriptions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test illegal argument error (equivalent to Swift NeoSwiftError tests)
    const illegal_arg_error = NeoSwiftError.illegalArgument("Test illegal argument");
    const arg_description = try illegal_arg_error.getErrorDescription(allocator);
    defer allocator.free(arg_description);
    
    try testing.expectEqualStrings("Test illegal argument", arg_description);
    try testing.expectEqual(ErrorSeverity.Error, illegal_arg_error.getSeverity());
    try testing.expect(illegal_arg_error.isRecoverable());
    
    // Test deserialization error
    const deser_error = NeoSwiftError.deserialization("Test deserialization error");
    const deser_description = try deser_error.getErrorDescription(allocator);
    defer allocator.free(deser_description);
    
    try testing.expectEqualStrings("Test deserialization error", deser_description);
    try testing.expectEqual(ErrorSeverity.Error, deser_error.getSeverity());
    try testing.expect(!deser_error.isRecoverable());
    
    // Test runtime error
    const runtime_error = NeoSwiftError.runtime("Test runtime error");
    const runtime_description = try runtime_error.getErrorDescription(allocator);
    defer allocator.free(runtime_description);
    
    try testing.expectEqualStrings("Test runtime error", runtime_description);
    try testing.expectEqual(ErrorSeverity.Critical, runtime_error.getSeverity());
    try testing.expect(!runtime_error.isRecoverable());
}

test "NeoSwiftError null message handling" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test errors with null messages (equivalent to Swift nil message tests)
    const null_arg_error = NeoSwiftError.illegalArgument(null);
    const null_description = try null_arg_error.getErrorDescription(allocator);
    defer allocator.free(null_description);
    
    try testing.expectEqualStrings("Illegal argument", null_description);
    
    const null_state_error = NeoSwiftError.illegalState(null);
    const null_state_description = try null_state_error.getErrorDescription(allocator);
    defer allocator.free(null_state_description);
    
    try testing.expectEqualStrings("Illegal state", null_state_description);
    
    const null_deser_error = NeoSwiftError.deserialization(null);
    const null_deser_description = try null_deser_error.getErrorDescription(allocator);
    defer allocator.free(null_deser_description);
    
    try testing.expectEqualStrings("Deserialization error", null_deser_description);
}

test "NeoSwiftErrorUtils validation functions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test parameter validation
    const valid_params = [_]?i32{ 1, 2, 3 };
    try NeoSwiftErrorUtils.validateParameters(&valid_params);
    
    const invalid_params = [_]?i32{ 1, null, 3 };
    try testing.expectError(
        NeoSwiftError.IllegalArgument,
        NeoSwiftErrorUtils.validateParameters(&invalid_params)
    );
    
    // Test array bounds validation
    try NeoSwiftErrorUtils.validateArrayBounds(5, 2); // Valid
    try NeoSwiftErrorUtils.validateArrayBounds(5, 4); // Valid (last index)
    
    try testing.expectError(
        NeoSwiftError.IndexOutOfBounds,
        NeoSwiftErrorUtils.validateArrayBounds(5, 5) // Invalid (equal to length)
    );
    
    try testing.expectError(
        NeoSwiftError.IndexOutOfBounds,
        NeoSwiftErrorUtils.validateArrayBounds(5, 10) // Invalid (way out of bounds)
    );
    
    // Test state validation
    try NeoSwiftErrorUtils.validateState(true, "Should not fail");
    
    try testing.expectError(
        NeoSwiftError.IllegalState,
        NeoSwiftErrorUtils.validateState(false, "Should fail")
    );
}

test "NeoSwiftErrorUtils common error creation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test common error creation
    var invalid_param = try NeoSwiftErrorUtils.createInvalidParameterError(allocator);
    const param_desc = try invalid_param.getErrorDescription(allocator);
    defer allocator.free(param_desc);
    
    try testing.expect(std.mem.indexOf(u8, param_desc, "Invalid parameter") != null);
    
    var invalid_state = try NeoSwiftErrorUtils.createInvalidStateError(allocator);
    const state_desc = try invalid_state.getErrorDescription(allocator);
    defer allocator.free(state_desc);
    
    try testing.expect(std.mem.indexOf(u8, state_desc, "Invalid operation state") != null);
    
    var deser_error = try NeoSwiftErrorUtils.createDeserializationError(allocator);
    const deser_desc = try deser_error.getErrorDescription(allocator);
    defer allocator.free(deser_desc);
    
    try testing.expect(std.mem.indexOf(u8, deser_desc, "deserialize") != null);
    
    var runtime_error = try NeoSwiftErrorUtils.createRuntimeError("Custom runtime message", allocator);
    const runtime_desc = try runtime_error.getErrorDescription(allocator);
    defer allocator.free(runtime_desc);
    
    try testing.expectEqualStrings("Custom runtime message", runtime_desc);
    
    var unsupported_error = try NeoSwiftErrorUtils.createUnsupportedOperationError("testOperation", allocator);
    const unsupported_desc = try unsupported_error.getErrorDescription(allocator);
    defer allocator.free(unsupported_desc);
    
    try testing.expect(std.mem.indexOf(u8, unsupported_desc, "testOperation") != null);
}