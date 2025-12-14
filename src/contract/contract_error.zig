//! Contract Error implementation
//!
//! Complete conversion from NeoSwift ContractError.swift
//! Provides specialized error handling for smart contract operations.

const std = @import("std");
const builtin = @import("builtin");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");

const log = std.log.scoped(.neo_contract);

/// Contract-specific errors (converted from Swift ContractError)
pub const ContractError = union(enum) {
    InvalidNeoName: []const u8,
    InvalidNeoNameServiceRoot: []const u8,
    UnexpectedReturnType: struct {
        actual_type: []const u8,
        expected_types: ?[]const []const u8,
    },
    UnresolvableDomainName: []const u8,

    const Self = @This();

    /// Creates invalid Neo name error (equivalent to Swift .invalidNeoName)
    pub fn invalidNeoName(name: []const u8) Self {
        return Self{ .InvalidNeoName = name };
    }

    /// Creates invalid NNS root error (equivalent to Swift .invalidNeoNameServiceRoot)
    pub fn invalidNeoNameServiceRoot(root: []const u8) Self {
        return Self{ .InvalidNeoNameServiceRoot = root };
    }

    /// Creates unexpected return type error (equivalent to Swift .unexpectedReturnType)
    pub fn unexpectedReturnType(actual_type: []const u8, expected_types: ?[]const []const u8) Self {
        return Self{ .UnexpectedReturnType = .{
            .actual_type = actual_type,
            .expected_types = expected_types,
        } };
    }

    /// Creates unresolvable domain name error (equivalent to Swift .unresolvableDomainName)
    pub fn unresolvableDomainName(name: []const u8) Self {
        return Self{ .UnresolvableDomainName = name };
    }

    /// Gets error description (equivalent to Swift .errorDescription)
    pub fn getErrorDescription(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .InvalidNeoName => |name| {
                return try std.fmt.allocPrint(allocator, "'{s}' is not a valid NNS name.", .{name});
            },
            .InvalidNeoNameServiceRoot => |root| {
                return try std.fmt.allocPrint(allocator, "'{s}' is not a valid NNS root.", .{root});
            },
            .UnexpectedReturnType => |data| {
                if (data.expected_types) |expected| {
                    var expected_str = ArrayList(u8).init(allocator);
                    defer expected_str.deinit();

                    for (expected, 0..) |exp_type, i| {
                        if (i > 0) try expected_str.appendSlice(", ");
                        try expected_str.appendSlice(exp_type);
                    }

                    return try std.fmt.allocPrint(allocator, "Got stack item of type {s} but expected {s}.", .{ data.actual_type, expected_str.items });
                } else {
                    return try allocator.dupe(u8, data.actual_type);
                }
            },
            .UnresolvableDomainName => |name| {
                return try std.fmt.allocPrint(allocator, "The provided domain name '{s}' could not be resolved.", .{name});
            },
        };
    }

    /// Throws appropriate Zig error (utility method)
    pub fn throwError(self: Self, allocator: std.mem.Allocator) !void {
        const description = try self.getErrorDescription(allocator);
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Contract Error: {s}", .{description});
        }

        return switch (self) {
            .InvalidNeoName, .InvalidNeoNameServiceRoot => errors.ContractError.InvalidContract,
            .UnexpectedReturnType => errors.ContractError.InvalidParameters,
            .UnresolvableDomainName => errors.ContractError.ContractCallFailed,
        };
    }

    /// Logs error without throwing (utility method)
    pub fn logError(self: Self, allocator: std.mem.Allocator) void {
        const description = self.getErrorDescription(allocator) catch "Unknown contract error";
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Contract Error: {s}", .{description});
        }
    }
};

/// Contract error utilities
pub const ContractErrorUtils = struct {
    /// Validates contract name and throws appropriate error
    pub fn validateContractName(name: []const u8) ContractError!void {
        if (name.len == 0) {
            return ContractError.invalidNeoName(name);
        }

        if (name.len > 255) {
            return ContractError.invalidNeoName(name);
        }

        // Additional name validation would go here
    }

    /// Validates NNS root domain
    pub fn validateNNSRoot(root: []const u8) ContractError!void {
        const valid_roots = [_][]const u8{ "neo", "test", "local" };

        for (valid_roots) |valid_root| {
            if (std.mem.eql(u8, root, valid_root)) {
                return;
            }
        }

        return ContractError.invalidNeoNameServiceRoot(root);
    }

    /// Validates stack item type
    pub fn validateStackItemType(
        actual_type: []const u8,
        expected_types: []const []const u8,
    ) ContractError!void {
        for (expected_types) |expected_type| {
            if (std.mem.eql(u8, actual_type, expected_type)) {
                return;
            }
        }

        return ContractError.unexpectedReturnType(actual_type, expected_types);
    }

    /// Checks if domain name is resolvable
    pub fn checkDomainResolvable(domain_name: []const u8) ContractError!void {
        // Basic domain format validation
        if (domain_name.len == 0) {
            return ContractError.unresolvableDomainName(domain_name);
        }

        if (std.mem.indexOf(u8, domain_name, ".") == null) {
            return ContractError.unresolvableDomainName(domain_name);
        }

        // Additional resolvability checks would go here
    }
};

// Tests (converted from Swift ContractError tests)
test "ContractError creation and descriptions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test invalid Neo name error (equivalent to Swift ContractError tests)
    const invalid_name_error = ContractError.invalidNeoName("invalid.name.here");
    const name_description = try invalid_name_error.getErrorDescription(allocator);
    defer allocator.free(name_description);

    try testing.expect(std.mem.indexOf(u8, name_description, "invalid.name.here") != null);
    try testing.expect(std.mem.indexOf(u8, name_description, "not a valid NNS name") != null);

    // Test invalid NNS root error
    const invalid_root_error = ContractError.invalidNeoNameServiceRoot("badroot");
    const root_description = try invalid_root_error.getErrorDescription(allocator);
    defer allocator.free(root_description);

    try testing.expect(std.mem.indexOf(u8, root_description, "badroot") != null);
    try testing.expect(std.mem.indexOf(u8, root_description, "not a valid NNS root") != null);

    // Test unexpected return type error
    const expected_types = [_][]const u8{ "String", "Integer" };
    const return_type_error = ContractError.unexpectedReturnType("Boolean", &expected_types);
    const type_description = try return_type_error.getErrorDescription(allocator);
    defer allocator.free(type_description);

    try testing.expect(std.mem.indexOf(u8, type_description, "Boolean") != null);
    try testing.expect(std.mem.indexOf(u8, type_description, "String, Integer") != null);

    // Test unresolvable domain name error
    const unresolvable_error = ContractError.unresolvableDomainName("bad.domain");
    const domain_description = try unresolvable_error.getErrorDescription(allocator);
    defer allocator.free(domain_description);

    try testing.expect(std.mem.indexOf(u8, domain_description, "bad.domain") != null);
    try testing.expect(std.mem.indexOf(u8, domain_description, "could not be resolved") != null);
}

test "ContractErrorUtils validation functions" {
    const testing = std.testing;

    // Test contract name validation (equivalent to Swift validation tests)
    try ContractErrorUtils.validateContractName("ValidContract");

    try testing.expectError(ContractError.InvalidNeoName, ContractErrorUtils.validateContractName(""));

    try testing.expectError(ContractError.InvalidNeoName, ContractErrorUtils.validateContractName("x" ** 300));

    // Test NNS root validation
    try ContractErrorUtils.validateNNSRoot("neo");
    try ContractErrorUtils.validateNNSRoot("test");

    try testing.expectError(ContractError.InvalidNeoNameServiceRoot, ContractErrorUtils.validateNNSRoot("invalid"));

    // Test stack item type validation
    const valid_types = [_][]const u8{ "String", "Integer" };
    try ContractErrorUtils.validateStackItemType("String", &valid_types);

    try testing.expectError(ContractError.UnexpectedReturnType, ContractErrorUtils.validateStackItemType("Boolean", &valid_types));

    // Test domain resolvability
    try ContractErrorUtils.checkDomainResolvable("example.neo");

    try testing.expectError(ContractError.UnresolvableDomainName, ContractErrorUtils.checkDomainResolvable(""));

    try testing.expectError(ContractError.UnresolvableDomainName, ContractErrorUtils.checkDomainResolvable("nodomain"));
}
