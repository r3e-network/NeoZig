//! Node Plugin Type implementation
//!
//! Complete conversion from NeoSwift NodePluginType.swift
//! Defines Neo node plugin types and capabilities.

const std = @import("std");

const errors = @import("../core/errors.zig");
const json_utils = @import("../utils/json_utils.zig");

/// Neo node plugin type (converted from Swift NodePluginType)
pub const NodePluginType = enum {
    ApplicationLogs,
    CoreMetrics,
    ImportBlocks,
    LevelDbStore,
    RocksDbStore,
    RpcNep17Tracker,
    RpcSecurity,
    RpcServerPlugin,
    RpcSystemAssetTracker,
    SimplePolicy,
    StatesDumper,
    SystemLog,

    const Self = @This();

    /// Gets raw string value (equivalent to Swift .rawValue property)
    pub fn getRawValue(self: Self) []const u8 {
        return switch (self) {
            .ApplicationLogs => "ApplicationLogs",
            .CoreMetrics => "CoreMetrics",
            .ImportBlocks => "ImportBlocks",
            .LevelDbStore => "LevelDBStore",
            .RocksDbStore => "RocksDBStore",
            .RpcNep17Tracker => "RpcNep17Tracker",
            .RpcSecurity => "RpcSecurity",
            .RpcServerPlugin => "RpcServerPlugin",
            .RpcSystemAssetTracker => "RpcSystemAssetTrackerPlugin",
            .SimplePolicy => "SimplePolicyPlugin",
            .StatesDumper => "StatesDumper",
            .SystemLog => "SystemLog",
        };
    }

    /// Creates from string value (equivalent to Swift init(rawValue:))
    pub fn fromRawValue(raw_value: []const u8) ?Self {
        if (std.mem.eql(u8, raw_value, "ApplicationLogs")) return .ApplicationLogs;
        if (std.mem.eql(u8, raw_value, "CoreMetrics")) return .CoreMetrics;
        if (std.mem.eql(u8, raw_value, "ImportBlocks")) return .ImportBlocks;
        if (std.mem.eql(u8, raw_value, "LevelDBStore")) return .LevelDbStore;
        if (std.mem.eql(u8, raw_value, "RocksDBStore")) return .RocksDbStore;
        if (std.mem.eql(u8, raw_value, "RpcNep17Tracker")) return .RpcNep17Tracker;
        if (std.mem.eql(u8, raw_value, "RpcSecurity")) return .RpcSecurity;
        if (std.mem.eql(u8, raw_value, "RpcServerPlugin")) return .RpcServerPlugin;
        if (std.mem.eql(u8, raw_value, "RpcSystemAssetTrackerPlugin")) return .RpcSystemAssetTracker;
        if (std.mem.eql(u8, raw_value, "SimplePolicyPlugin")) return .SimplePolicy;
        if (std.mem.eql(u8, raw_value, "StatesDumper")) return .StatesDumper;
        if (std.mem.eql(u8, raw_value, "SystemLog")) return .SystemLog;

        return null;
    }

    /// Gets all plugin types (equivalent to Swift CaseIterable)
    pub fn getAllCases() []const Self {
        return &[_]Self{
            .ApplicationLogs,
            .CoreMetrics,
            .ImportBlocks,
            .LevelDbStore,
            .RocksDbStore,
            .RpcNep17Tracker,
            .RpcSecurity,
            .RpcServerPlugin,
            .RpcSystemAssetTracker,
            .SimplePolicy,
            .StatesDumper,
            .SystemLog,
        };
    }

    /// Gets plugin description
    pub fn getDescription(self: Self) []const u8 {
        return switch (self) {
            .ApplicationLogs => "Provides application log functionality",
            .CoreMetrics => "Provides core metrics and monitoring",
            .ImportBlocks => "Enables block import functionality",
            .LevelDbStore => "LevelDB storage backend",
            .RocksDbStore => "RocksDB storage backend",
            .RpcNep17Tracker => "NEP-17 token tracking via RPC",
            .RpcSecurity => "RPC security and authentication",
            .RpcServerPlugin => "RPC server functionality",
            .RpcSystemAssetTracker => "System asset tracking",
            .SimplePolicy => "Simple policy management",
            .StatesDumper => "Blockchain state dumping",
            .SystemLog => "System logging functionality",
        };
    }

    /// Checks if plugin provides RPC functionality
    pub fn providesRpc(self: Self) bool {
        return switch (self) {
            .RpcNep17Tracker, .RpcSecurity, .RpcServerPlugin, .RpcSystemAssetTracker => true,
            else => false,
        };
    }

    /// Checks if plugin provides storage functionality
    pub fn providesStorage(self: Self) bool {
        return switch (self) {
            .LevelDbStore, .RocksDbStore => true,
            else => false,
        };
    }

    /// Checks if plugin provides monitoring functionality
    pub fn providesMonitoring(self: Self) bool {
        return switch (self) {
            .CoreMetrics, .ApplicationLogs, .SystemLog => true,
            else => false,
        };
    }

    /// Decodes from JSON string
    pub fn decodeFromJson(json_value: std.json.Value) !Self {
        const string_value = switch (json_value) {
            .string => |s| s,
            else => return errors.ValidationError.InvalidFormat,
        };

        return Self.fromRawValue(string_value) orelse {
            return errors.throwIllegalArgument("Unknown node plugin type");
        };
    }

    /// Encodes to JSON string
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        const value = try allocator.dupe(u8, self.getRawValue());
        return std.json.Value{ .string = value };
    }
};

// Tests (converted from Swift NodePluginType tests)
test "NodePluginType raw values" {
    const testing = std.testing;

    // Test raw value conversion (equivalent to Swift rawValue tests)
    try testing.expectEqualStrings("ApplicationLogs", NodePluginType.ApplicationLogs.getRawValue());
    try testing.expectEqualStrings("CoreMetrics", NodePluginType.CoreMetrics.getRawValue());
    try testing.expectEqualStrings("LevelDBStore", NodePluginType.LevelDbStore.getRawValue());
    try testing.expectEqualStrings("RocksDBStore", NodePluginType.RocksDbStore.getRawValue());
    try testing.expectEqualStrings("RpcServerPlugin", NodePluginType.RpcServerPlugin.getRawValue());
}

test "NodePluginType conversion from raw values" {
    const testing = std.testing;

    // Test creation from raw value (equivalent to Swift init(rawValue:) tests)
    try testing.expectEqual(NodePluginType.ApplicationLogs, NodePluginType.fromRawValue("ApplicationLogs").?);
    try testing.expectEqual(NodePluginType.CoreMetrics, NodePluginType.fromRawValue("CoreMetrics").?);
    try testing.expectEqual(NodePluginType.RpcServerPlugin, NodePluginType.fromRawValue("RpcServerPlugin").?);

    // Test invalid raw value
    try testing.expectEqual(@as(?NodePluginType, null), NodePluginType.fromRawValue("InvalidPlugin"));
    try testing.expectEqual(@as(?NodePluginType, null), NodePluginType.fromRawValue(""));
}

test "NodePluginType functionality classification" {
    const testing = std.testing;

    // Test RPC functionality classification
    try testing.expect(NodePluginType.RpcServerPlugin.providesRpc());
    try testing.expect(NodePluginType.RpcNep17Tracker.providesRpc());
    try testing.expect(NodePluginType.RpcSecurity.providesRpc());
    try testing.expect(!NodePluginType.ApplicationLogs.providesRpc());
    try testing.expect(!NodePluginType.LevelDbStore.providesRpc());

    // Test storage functionality classification
    try testing.expect(NodePluginType.LevelDbStore.providesStorage());
    try testing.expect(NodePluginType.RocksDbStore.providesStorage());
    try testing.expect(!NodePluginType.RpcServerPlugin.providesStorage());
    try testing.expect(!NodePluginType.ApplicationLogs.providesStorage());

    // Test monitoring functionality classification
    try testing.expect(NodePluginType.CoreMetrics.providesMonitoring());
    try testing.expect(NodePluginType.ApplicationLogs.providesMonitoring());
    try testing.expect(NodePluginType.SystemLog.providesMonitoring());
    try testing.expect(!NodePluginType.LevelDbStore.providesMonitoring());
    try testing.expect(!NodePluginType.RpcServerPlugin.providesMonitoring());
}

test "NodePluginType enumeration" {
    const testing = std.testing;

    // Test all cases enumeration (equivalent to Swift allCases tests)
    const all_cases = NodePluginType.getAllCases();
    try testing.expectEqual(@as(usize, 12), all_cases.len);

    // Verify specific plugins are included
    try testing.expect(std.mem.indexOf(NodePluginType, all_cases, &[_]NodePluginType{.ApplicationLogs}) != null);
    try testing.expect(std.mem.indexOf(NodePluginType, all_cases, &[_]NodePluginType{.RpcServerPlugin}) != null);
    try testing.expect(std.mem.indexOf(NodePluginType, all_cases, &[_]NodePluginType{.SystemLog}) != null);
}

test "NodePluginType JSON operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test JSON encoding/decoding round-trip
    const original_plugin = NodePluginType.RpcNep17Tracker;

    const encoded_json = try original_plugin.encodeToJson(allocator);
    defer json_utils.freeValue(encoded_json, allocator);

    const decoded_plugin = try NodePluginType.decodeFromJson(encoded_json);
    try testing.expectEqual(original_plugin, decoded_plugin);

    // Test description access
    const description = original_plugin.getDescription();
    try testing.expect(description.len > 0);
    try testing.expect(std.mem.indexOf(u8, description, "NEP-17") != null);
}
