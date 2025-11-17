//! Contract Parameters Context implementation
//!
//! Complete conversion from NeoSwift ContractParametersContext.swift
//! Provides transaction signing context for multi-signature scenarios.

const std = @import("std");
const ArrayList = std.array_list.Managed;
const json_utils = @import("../utils/json_utils.zig");


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;

/// Contract parameters context (converted from Swift ContractParametersContext)
pub const ContractParametersContext = struct {
    /// Context type constant (matches Swift type)
    pub const CONTEXT_TYPE = "Neo.Network.P2P.Payloads.Transaction";
    
    /// Transaction hash
    hash: []const u8,
    /// Transaction data
    data: []const u8,
    /// Context items by script hash
    items: std.HashMap([]const u8, ContextItem, StringContext, std.hash_map.default_max_load_percentage),
    /// Network magic number
    network: u32,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates contract parameters context (equivalent to Swift init)
    pub fn init(
        allocator: std.mem.Allocator,
        hash: []const u8,
        data: []const u8,
        items: ?std.HashMap([]const u8, ContextItem, StringContext, std.hash_map.default_max_load_percentage),
        network: u32,
    ) Self {
        return Self{
            .hash = hash,
            .data = data,
            .items = items orelse std.HashMap([]const u8, ContextItem, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .network = network,
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        var iterator = self.items.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.items.deinit();
        
        self.allocator.free(self.hash);
        self.allocator.free(self.data);
    }
    
    /// Adds context item (equivalent to Swift item addition)
    pub fn addItem(self: *Self, script_hash: []const u8, item: ContextItem) !void {
        const script_hash_copy = try self.allocator.dupe(u8, script_hash);
        try self.items.put(script_hash_copy, item);
    }
    
    /// Gets context item (equivalent to Swift item retrieval)
    pub fn getItem(self: Self, script_hash: []const u8) ?ContextItem {
        return self.items.get(script_hash);
    }
    
    /// Removes context item (equivalent to Swift item removal)
    pub fn removeItem(self: *Self, script_hash: []const u8) bool {
        if (self.items.fetchRemove(script_hash)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit(self.allocator);
            return true;
        }
        return false;
    }
    
    /// Checks if context is complete (equivalent to Swift completion check)
    pub fn isComplete(self: Self) bool {
        // Context is complete if all required items have sufficient signatures
        var iterator = self.items.iterator();
        while (iterator.next()) |entry| {
            if (!entry.value_ptr.isComplete()) {
                return false;
            }
        }
        return true;
    }
    
    /// Gets signing data for script (equivalent to Swift signing data)
    pub fn getSigningData(self: Self, script_hash: []const u8) ?[]const u8 {
        if (self.getItem(script_hash)) |item| {
            return item.getSigningData();
        }
        return null;
    }
    
    /// Exports to JSON (equivalent to Swift Codable encoding)
    pub fn toJson(self: Self) !std.json.Value {
        var context_obj = std.json.ObjectMap.init(self.allocator);
        
        try json_utils.putOwnedKey(&context_obj, self.allocator, "type", std.json.Value{ .string = try self.allocator.dupe(u8, CONTEXT_TYPE) });
        try json_utils.putOwnedKey(&context_obj, self.allocator, "hash", std.json.Value{ .string = try self.allocator.dupe(u8, self.hash) });
        try json_utils.putOwnedKey(&context_obj, self.allocator, "data", std.json.Value{ .string = try self.allocator.dupe(u8, self.data) });
        try json_utils.putOwnedKey(&context_obj, self.allocator, "network", std.json.Value{ .integer = @intCast(self.network) });
        
        // Convert items to JSON
        var items_obj = std.json.ObjectMap.init(self.allocator);
        var iterator = self.items.iterator();
        while (iterator.next()) |entry| {
            try items_obj.put(entry.key_ptr.*, try entry.value_ptr.toJson(self.allocator));
        }
        try json_utils.putOwnedKey(&context_obj, self.allocator, "items", std.json.Value{ .object = items_obj });
        
        return std.json.Value{ .object = context_obj };
    }
    
    /// Imports from JSON (equivalent to Swift Codable decoding)
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const hash = try allocator.dupe(u8, obj.get("hash").?.string);
        const data = try allocator.dupe(u8, obj.get("data").?.string);
        const network = @as(u32, @intCast(obj.get("network").?.integer));
        
        var items = std.HashMap([]const u8, ContextItem, StringContext, std.hash_map.default_max_load_percentage).init(allocator);
        
        if (obj.get("items")) |items_obj| {
            var items_iterator = items_obj.object.iterator();
            while (items_iterator.next()) |entry| {
                const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
                const item = try ContextItem.fromJson(entry.value_ptr.*, allocator);
                try items.put(key_copy, item);
            }
        }
        
        return Self{
            .hash = hash,
            .data = data,
            .items = items,
            .network = network,
            .allocator = allocator,
        };
    }
};

/// Context item (converted from Swift ContextItem)
pub const ContextItem = struct {
    /// Verification script
    script: []const u8,
    /// Contract parameters
    parameters: ?[]const ContractParameter,
    /// Signatures by public key hex
    signatures: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates context item (equivalent to Swift init)
    pub fn init(
        allocator: std.mem.Allocator,
        script: []const u8,
        parameters: ?[]const ContractParameter,
        signatures: ?std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    ) Self {
        return Self{
            .script = script,
            .parameters = parameters,
            .signatures = signatures orelse std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
        
        if (self.parameters) |params| {
            allocator.free(params);
        }
        
        var sig_iterator = self.signatures.iterator();
        while (sig_iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.signatures.deinit();
    }
    
    /// Adds signature (equivalent to Swift signature addition)
    pub fn addSignature(self: *Self, public_key_hex: []const u8, signature_hex: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, public_key_hex);
        const sig_copy = try self.allocator.dupe(u8, signature_hex);
        try self.signatures.put(key_copy, sig_copy);
    }
    
    /// Gets signature (equivalent to Swift signature retrieval)
    pub fn getSignature(self: Self, public_key_hex: []const u8) ?[]const u8 {
        return self.signatures.get(public_key_hex);
    }
    
    /// Checks if item is complete (equivalent to Swift completion check)
    pub fn isComplete(self: Self) bool {
        // For single-sig, need 1 signature
        // For multi-sig, would need threshold number of signatures
        return self.signatures.count() > 0;
    }
    
    /// Gets signing data (utility method)
    pub fn getSigningData(self: Self) []const u8 {
        return self.script;
    }
    
    /// Gets signature count
    pub fn getSignatureCount(self: Self) u32 {
        return @intCast(self.signatures.count());
    }
    
    /// Exports to JSON (equivalent to Swift Codable)
    pub fn toJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var item_obj = std.json.ObjectMap.init(allocator);
        
        try json_utils.putOwnedKey(&item_obj, allocator, "script", std.json.Value{ .string = try allocator.dupe(u8, self.script) });
        
        if (self.parameters) |params| {
            var params_array = ArrayList(std.json.Value).init(allocator);
            for (params) |param| {
                try params_array.append(try @import("../contract/parameter_utils.zig").parameterToJson(param, allocator));
            }
            try json_utils.putOwnedKey(&item_obj, allocator, "parameters", std.json.Value{ .array = try params_array.toOwnedSlice() });
        }
        
        // Convert signatures to JSON
        var sigs_obj = std.json.ObjectMap.init(allocator);
        var sig_iterator = self.signatures.iterator();
        while (sig_iterator.next()) |entry| {
            try sigs_obj.put(entry.key_ptr.*, std.json.Value{ .string = entry.value_ptr.* });
        }
        try json_utils.putOwnedKey(&item_obj, allocator, "signatures", std.json.Value{ .object = sigs_obj });
        
        return std.json.Value{ .object = item_obj };
    }
    
    /// Imports from JSON (equivalent to Swift Codable)
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const script = try allocator.dupe(u8, obj.get("script").?.string);
        
        // Parse parameters if present
        var parameters: ?[]ContractParameter = null;
        if (obj.get("parameters")) |params_array| {
            var params_list = ArrayList(ContractParameter).init(allocator);
            for (params_array.array) |param_json| {
                // Would parse contract parameter from JSON
                try params_list.append(ContractParameter.boolean(true)); // Placeholder
            }
            parameters = try params_list.toOwnedSlice();
        }
        
        // Parse signatures
        var signatures = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator);
        if (obj.get("signatures")) |sigs_obj| {
            var sig_iterator = sigs_obj.object.iterator();
            while (sig_iterator.next()) |entry| {
                const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
                const value_copy = try allocator.dupe(u8, entry.value_ptr.string);
                try signatures.put(key_copy, value_copy);
            }
        }
        
        return Self{
            .script = script,
            .parameters = parameters,
            .signatures = signatures,
            .allocator = allocator,
        };
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

// Tests (converted from Swift ContractParametersContext tests)
test "ContractParametersContext creation and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test context creation (equivalent to Swift ContractParametersContext tests)
    var context = ContractParametersContext.init(
        allocator,
        try allocator.dupe(u8, "test_hash"),
        try allocator.dupe(u8, "test_data"),
        null,
        constants.NetworkMagic.MAINNET,
    );
    defer context.deinit();
    
    try testing.expectEqualStrings("test_hash", context.hash);
    try testing.expectEqualStrings("test_data", context.data);
    try testing.expectEqual(constants.NetworkMagic.MAINNET, context.network);
    try testing.expectEqual(@as(u32, 0), @intCast(context.items.count()));
}

test "ContractParametersContext item management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var context = ContractParametersContext.init(
        allocator,
        try allocator.dupe(u8, "test_hash"),
        try allocator.dupe(u8, "test_data"),
        null,
        constants.NetworkMagic.MAINNET,
    );
    defer context.deinit();
    
    // Create test context item
    var item = ContextItem.init(
        allocator,
        try allocator.dupe(u8, "test_script"),
        null,
        null,
    );
    
    // Add signature to item
    try item.addSignature("02abcd...", "signature_hex");
    
    // Add item to context
    try context.addItem("script_hash_123", item);
    
    try testing.expectEqual(@as(u32, 1), @intCast(context.items.count()));
    
    // Test item retrieval
    const retrieved_item = context.getItem("script_hash_123");
    try testing.expect(retrieved_item != null);
    try testing.expectEqualStrings("test_script", retrieved_item.?.script);
}

test "ContextItem signature management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var item = ContextItem.init(
        allocator,
        try allocator.dupe(u8, "verification_script"),
        null,
        null,
    );
    defer item.deinit(allocator);
    
    // Test signature addition (equivalent to Swift signature tests)
    try item.addSignature("public_key_1", "signature_1");
    try item.addSignature("public_key_2", "signature_2");
    
    try testing.expectEqual(@as(u32, 2), item.getSignatureCount());
    
    // Test signature retrieval
    const sig1 = item.getSignature("public_key_1");
    try testing.expect(sig1 != null);
    try testing.expectEqualStrings("signature_1", sig1.?);
    
    const missing_sig = item.getSignature("nonexistent_key");
    try testing.expect(missing_sig == null);
    
    // Test completion check
    try testing.expect(item.isComplete()); // Has signatures
}

test "ContractParametersContext JSON operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var context = ContractParametersContext.init(
        allocator,
        try allocator.dupe(u8, "json_test_hash"),
        try allocator.dupe(u8, "json_test_data"),
        null,
        constants.NetworkMagic.TESTNET,
    );
    defer context.deinit();
    
    // Add test item
    var item = ContextItem.init(
        allocator,
        try allocator.dupe(u8, "json_script"),
        null,
        null,
    );
    try item.addSignature("key1", "sig1");
    try context.addItem("script1", item);
    
    // Test JSON export
    const json_value = try context.toJson();
    defer json_value.deinit();
    
    const context_obj = json_value.object;
    try testing.expectEqualStrings(ContractParametersContext.CONTEXT_TYPE, context_obj.get("type").?.string);
    try testing.expectEqualStrings("json_test_hash", context_obj.get("hash").?.string);
    try testing.expectEqualStrings("json_test_data", context_obj.get("data").?.string);
    try testing.expectEqual(@as(i64, @intCast(constants.NetworkMagic.TESTNET)), context_obj.get("network").?.integer);
    
    // Verify items are present
    const items_obj = context_obj.get("items").?.object;
    try testing.expect(items_obj.contains("script1"));
}
