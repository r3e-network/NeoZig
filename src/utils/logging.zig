//! Production Logging System
//!
//! Enterprise-grade logging and monitoring for Neo Zig SDK
//! Provides structured logging with security and performance monitoring.

const std = @import("std");
const ArrayList = std.ArrayList;

const builtin = @import("builtin");

/// Log levels for production use
pub const LogLevel = enum(u8) {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Critical = 4,

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .Debug => "DEBUG",
            .Info => "INFO",
            .Warn => "WARN",
            .Error => "ERROR",
            .Critical => "CRITICAL",
        };
    }

    pub fn getColor(self: LogLevel) []const u8 {
        return switch (self) {
            .Debug => "\x1b[36m", // Cyan
            .Info => "\x1b[32m", // Green
            .Warn => "\x1b[33m", // Yellow
            .Error => "\x1b[31m", // Red
            .Critical => "\x1b[35m", // Magenta
        };
    }
};

/// Production logger with structured output
pub const Logger = struct {
    level: LogLevel,
    output_file: ?std.fs.File,
    use_colors: bool,
    include_timestamp: bool,
    include_source: bool,

    const Self = @This();

    /// Creates logger with configuration
    pub fn init(level: LogLevel) Self {
        return Self{
            .level = level,
            .output_file = null,
            .use_colors = builtin.os.tag != .windows,
            .include_timestamp = true,
            .include_source = true,
        };
    }

    /// Sets output file for logging
    pub fn setOutputFile(self: *Self, file_path: []const u8) !void {
        const file = try std.fs.cwd().createFile(file_path, .{ .truncate = false });
        self.output_file = file;
    }

    /// Closes output file
    pub fn close(self: *Self) void {
        if (self.output_file) |file| {
            file.close();
            self.output_file = null;
        }
    }

    /// Logs message with level
    pub fn log(
        self: Self,
        comptime level: LogLevel,
        comptime format: []const u8,
        args: anytype,
        src: std.builtin.SourceLocation,
    ) void {
        if (@intFromEnum(level) < @intFromEnum(self.level)) return;

        var buffer: [4096]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer);
        const allocator = fba.allocator();

        // Build log message
        var log_msg = ArrayList(u8).init(allocator);
        defer log_msg.deinit();

        // Timestamp
        if (self.include_timestamp) {
            const timestamp = std.time.timestamp();
            const formatted_time = std.fmt.allocPrint(
                allocator,
                "[{d}] ",
                .{timestamp},
            ) catch "[TIME] ";
            log_msg.appendSlice(formatted_time) catch {};
        }

        // Level with color
        if (self.use_colors) {
            log_msg.appendSlice(level.getColor()) catch {};
        }

        const level_str = std.fmt.allocPrint(
            allocator,
            "[{s}]",
            .{level.toString()},
        ) catch "[LEVEL]";
        log_msg.appendSlice(level_str) catch {};

        if (self.use_colors) {
            log_msg.appendSlice("\x1b[0m") catch {}; // Reset color
        }

        // Source location
        if (self.include_source) {
            const source_info = std.fmt.allocPrint(
                allocator,
                " {s}:{d}",
                .{ src.file, src.line },
            ) catch " [SRC]";
            log_msg.appendSlice(source_info) catch {};
        }

        log_msg.appendSlice(" ") catch {};

        // Message
        const formatted_msg = std.fmt.allocPrint(allocator, format, args) catch "LOG_ERROR";
        log_msg.appendSlice(formatted_msg) catch {};
        log_msg.append('\n') catch {};

        // Output to stderr and file
        std.debug.print("{s}", .{log_msg.items});

        if (self.output_file) |file| {
            file.writeAll(log_msg.items) catch {};
        }
    }

    /// Security-specific logging (no sensitive data)
    pub fn logSecurity(
        self: Self,
        comptime level: LogLevel,
        operation: []const u8,
        success: bool,
        src: std.builtin.SourceLocation,
    ) void {
        self.log(level, "Security: {s} - {s}", .{ operation, if (success) "SUCCESS" else "FAILURE" }, src);
    }

    /// Performance logging
    pub fn logPerformance(
        self: Self,
        operation: []const u8,
        duration_ns: u64,
        src: std.builtin.SourceLocation,
    ) void {
        const duration_ms = duration_ns / std.time.ns_per_ms;
        self.log(.Info, "Performance: {s} - {d}ms", .{ operation, duration_ms }, src);
    }

    /// Network operation logging
    pub fn logNetwork(
        self: Self,
        comptime level: LogLevel,
        method: []const u8,
        endpoint: []const u8,
        status: []const u8,
        src: std.builtin.SourceLocation,
    ) void {
        self.log(level, "Network: {s} -> {s} ({s})", .{ method, endpoint, status }, src);
    }
};

/// Global logger instance
var global_logger: ?Logger = null;

/// Initializes global logger
pub fn initGlobalLogger(level: LogLevel) void {
    global_logger = Logger.init(level);
}

/// Gets global logger
pub fn getGlobalLogger() ?*Logger {
    if (global_logger) |*logger| {
        return logger;
    }
    return null;
}

/// Convenience logging macros
pub fn logDebug(comptime format: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.log(.Debug, format, args, src);
    }
}

pub fn logInfo(comptime format: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.log(.Info, format, args, src);
    }
}

pub fn logWarn(comptime format: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.log(.Warn, format, args, src);
    }
}

pub fn logError(comptime format: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.log(.Error, format, args, src);
    }
}

pub fn logCritical(comptime format: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.log(.Critical, format, args, src);
    }
}

/// Security logging macros (no sensitive data)
pub fn logSecuritySuccess(operation: []const u8, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.logSecurity(.Info, operation, true, src);
    }
}

pub fn logSecurityFailure(operation: []const u8, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.logSecurity(.Warn, operation, false, src);
    }
}

/// Performance logging
pub fn logPerformanceOperation(operation: []const u8, duration_ns: u64, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.logPerformance(operation, duration_ns, src);
    }
}

/// Network logging
pub fn logNetworkRequest(method: []const u8, endpoint: []const u8, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.logNetwork(.Info, method, endpoint, "REQUEST", src);
    }
}

pub fn logNetworkSuccess(method: []const u8, endpoint: []const u8, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.logNetwork(.Info, method, endpoint, "SUCCESS", src);
    }
}

pub fn logNetworkError(method: []const u8, endpoint: []const u8, src: std.builtin.SourceLocation) void {
    if (getGlobalLogger()) |logger| {
        logger.logNetwork(.Error, method, endpoint, "ERROR", src);
    }
}

/// Monitoring utilities
pub const Monitoring = struct {
    /// Performance counter
    pub const PerformanceCounter = struct {
        start_time: i128,
        operation: []const u8,

        pub fn start(operation: []const u8) PerformanceCounter {
            return PerformanceCounter{
                .start_time = std.time.nanoTimestamp(),
                .operation = operation,
            };
        }

        pub fn end(self: PerformanceCounter, src: std.builtin.SourceLocation) void {
            const end_time = std.time.nanoTimestamp();
            const delta: i128 = end_time - self.start_time;
            const duration: u64 = if (delta <= 0) 0 else @intCast(delta);
            logPerformanceOperation(self.operation, duration, src);
        }
    };

    /// Security audit trail
    pub const SecurityAudit = struct {
        pub fn logKeyGeneration(success: bool, src: std.builtin.SourceLocation) void {
            if (success) {
                logSecuritySuccess("key_generation", src);
            } else {
                logSecurityFailure("key_generation", src);
            }
        }

        pub fn logSignature(success: bool, src: std.builtin.SourceLocation) void {
            if (success) {
                logSecuritySuccess("signature_operation", src);
            } else {
                logSecurityFailure("signature_operation", src);
            }
        }

        pub fn logWalletAccess(success: bool, src: std.builtin.SourceLocation) void {
            if (success) {
                logSecuritySuccess("wallet_access", src);
            } else {
                logSecurityFailure("wallet_access", src);
            }
        }

        pub fn logTransactionSigning(success: bool, src: std.builtin.SourceLocation) void {
            if (success) {
                logSecuritySuccess("transaction_signing", src);
            } else {
                logSecurityFailure("transaction_signing", src);
            }
        }
    };
};

// Tests
test "Logger creation and basic operations" {
    const testing = std.testing;

    var logger = Logger.init(.Info);
    defer logger.close();

    try testing.expectEqual(LogLevel.Info, logger.level);
    try testing.expect(logger.include_timestamp);
    try testing.expect(logger.include_source);

    // Test level filtering
    logger.level = .Critical;
    logger.log(.Debug, "Debug message should be filtered", .{}, @src());
    logger.log(.Info, "Info message should appear", .{}, @src());
    logger.log(.Error, "Error message should appear", .{}, @src());
}

test "Security and performance monitoring" {
    // Initialize global logger for testing
    initGlobalLogger(.Critical);

    // Test security logging
    logSecuritySuccess("test_operation", @src());
    logSecurityFailure("test_operation", @src());

    // Test performance monitoring
    var counter = Monitoring.PerformanceCounter.start("test_performance");

    // Simulate some work
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        _ = i * i;
    }

    counter.end(@src());

    // Test network logging
    logNetworkRequest("getblockcount", "localhost:20332", @src());
    logNetworkSuccess("getblockcount", "localhost:20332", @src());
}
