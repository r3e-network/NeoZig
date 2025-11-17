//! NEP-6 Wallet implementation
//!
//! Complete conversion from NeoSwift NEP6Wallet.swift
//! Standard wallet format for Neo blockchain.

const std = @import("std");
const ArrayList = std.array_list.Managed;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;

/// NEP-6 wallet structure (converted from Swift NEP6Wallet)
pub const NEP6Wallet = struct {
    name: []const u8,
    version: []const u8,
    scrypt: ScryptParams,
    accounts: []const NEP6Account,
    extra: ?std.json.Value,
    
    const Self = @This();
    
    /// Creates NEP-6 wallet (equivalent to Swift init)
    pub fn init(
        name: []const u8,
        version: []const u8,
        scrypt: ScryptParams,
        accounts: []const NEP6Account,
        extra: ?std.json.Value,
    ) Self {
        return Self{
            .name = name,
            .version = version,
            .scrypt = scrypt,
            .accounts = accounts,
            .extra = extra,
        };
    }
    
    /// Equality comparison (equivalent to Swift == operator)
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.name, other.name) and
               std.mem.eql(u8, self.version, other.version) and
               self.scrypt.eql(other.scrypt) and
               self.accounts.len == other.accounts.len;
    }
    
    /// Converts to JSON (equivalent to Swift Codable encoding)
    pub fn toJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var wallet_obj = std.json.ObjectMap.init(allocator);
        
        try wallet_obj.put("name", std.json.Value{ .string = self.name });
        try wallet_obj.put("version", std.json.Value{ .string = self.version });
        try wallet_obj.put("scrypt", try self.scrypt.toJson(allocator));
        
        // Convert accounts array
        var accounts_array = ArrayList(std.json.Value).init(allocator);
        for (self.accounts) |account| {
            try accounts_array.append(try account.toJson(allocator));
        }
        try wallet_obj.put("accounts", std.json.Value{ .array = try accounts_array.toOwnedSlice() });
        
        if (self.extra) |extra| {
            try wallet_obj.put("extra", extra);
        }
        
        return std.json.Value{ .object = wallet_obj };
    }
    
    /// Parses from JSON (equivalent to Swift Codable decoding)
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const name = try allocator.dupe(u8, obj.get("name").?.string);
        const version = try allocator.dupe(u8, obj.get("version").?.string);
        const scrypt = try ScryptParams.fromJson(obj.get("scrypt").?, allocator);
        
        // Parse accounts
        var accounts = ArrayList(NEP6Account).init(allocator);
        if (obj.get("accounts")) |accounts_array| {
            for (accounts_array.array) |account_json| {
                try accounts.append(try NEP6Account.fromJson(account_json, allocator));
            }
        }
        
        const extra = obj.get("extra");
        
        return Self.init(name, version, scrypt, try accounts.toOwnedSlice(), extra);
    }
    
    /// Saves to file (equivalent to Swift file operations)
    pub fn saveToFile(self: Self, file_path: []const u8, allocator: std.mem.Allocator) !void {
        const json_value = try self.toJson(allocator);
        defer json_value.deinit();
        
        var writer_state = std.Io.Writer.Allocating.init(allocator);
        defer writer_state.deinit();
        
        var stringify = std.json.Stringify{ .writer = &writer_state.writer, .options = .{ .whitespace = .indent_2 } };
        try stringify.write(json_value);
        
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();
        
        try file.writeAll(writer_state.writer.buffered());
    }
    
    /// Loads from file (equivalent to Swift file operations)
    pub fn loadFromFile(file_path: []const u8, allocator: std.mem.Allocator) !Self {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();
        
        const file_content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(file_content);
        
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, file_content, .{});
        defer parsed.deinit();
        
        return try Self.fromJson(parsed.value, allocator);
    }
};

/// NEP-6 account (converted from Swift NEP6Account)
pub const NEP6Account = struct {
    address: []const u8,
    label: ?[]const u8,
    is_default: bool,
    lock: bool,
    key: ?[]const u8, // NEP-2 encrypted private key
    contract: ?NEP6Contract,
    extra: ?std.json.Value,
    
    const Self = @This();
    
    pub fn init(
        address: []const u8,
        label: ?[]const u8,
        is_default: bool,
        lock: bool,
        key: ?[]const u8,
        contract: ?NEP6Contract,
        extra: ?std.json.Value,
    ) Self {
        return Self{
            .address = address,
            .label = label,
            .is_default = is_default,
            .lock = lock,
            .key = key,
            .contract = contract,
            .extra = extra,
        };
    }
    
    /// Gets script hash (equivalent to Swift getScriptHash)
    pub fn getScriptHash(self: Self, allocator: std.mem.Allocator) !Hash160 {
        return try Hash160.fromAddress(self.address, allocator);
    }
    
    /// Checks if account has private key (equivalent to Swift hasPrivateKey)
    pub fn hasPrivateKey(self: Self) bool {
        return self.key != null;
    }
    
    /// Converts to JSON (equivalent to Swift Codable)
    pub fn toJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var account_obj = std.json.ObjectMap.init(allocator);
        
        try account_obj.put("address", std.json.Value{ .string = self.address });
        
        if (self.label) |label| {
            try account_obj.put("label", std.json.Value{ .string = label });
        }
        
        try account_obj.put("isDefault", std.json.Value{ .bool = self.is_default });
        try account_obj.put("lock", std.json.Value{ .bool = self.lock });
        
        if (self.key) |key| {
            try account_obj.put("key", std.json.Value{ .string = key });
        }
        
        if (self.contract) |contract| {
            try account_obj.put("contract", try contract.toJson(allocator));
        }
        
        if (self.extra) |extra| {
            try account_obj.put("extra", extra);
        }
        
        return std.json.Value{ .object = account_obj };
    }
    
    /// Parses from JSON (equivalent to Swift Codable)
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const address = try allocator.dupe(u8, obj.get("address").?.string);
        const label = if (obj.get("label")) |l| try allocator.dupe(u8, l.string) else null;
        const is_default = obj.get("isDefault").?.bool;
        const lock = obj.get("lock").?.bool;
        const key = if (obj.get("key")) |k| try allocator.dupe(u8, k.string) else null;
        const contract = if (obj.get("contract")) |c| try NEP6Contract.fromJson(c, allocator) else null;
        const extra = obj.get("extra");
        
        return Self.init(address, label, is_default, lock, key, contract, extra);
    }
};

/// NEP-6 contract (converted from Swift NEP6Contract)
pub const NEP6Contract = struct {
    script: []const u8,
    parameters: []const ContractParameterInfo,
    deployed: bool,
    
    const Self = @This();
    
    pub fn init(script: []const u8, parameters: []const ContractParameterInfo, deployed: bool) Self {
        return Self{
            .script = script,
            .parameters = parameters,
            .deployed = deployed,
        };
    }
    
    pub fn toJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var contract_obj = std.json.ObjectMap.init(allocator);
        
        const script_hex = try @import("../utils/bytes.zig").toHex(self.script, allocator);
        defer allocator.free(script_hex);
        
        try contract_obj.put("script", std.json.Value{ .string = script_hex });
        try contract_obj.put("deployed", std.json.Value{ .bool = self.deployed });
        
        // Convert parameters
        var params_array = ArrayList(std.json.Value).init(allocator);
        for (self.parameters) |param| {
            try params_array.append(try param.toJson(allocator));
        }
        try contract_obj.put("parameters", std.json.Value{ .array = try params_array.toOwnedSlice() });
        
        return std.json.Value{ .object = contract_obj };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const script_hex = obj.get("script").?.string;
        const script = try @import("../utils/bytes.zig").fromHex(script_hex, allocator);
        const deployed = obj.get("deployed").?.bool;
        
        // Parse parameters
        var parameters = ArrayList(ContractParameterInfo).init(allocator);
        if (obj.get("parameters")) |params_array| {
            for (params_array.array) |param_json| {
                try parameters.append(try ContractParameterInfo.fromJson(param_json, allocator));
            }
        }
        
        return Self.init(script, try parameters.toOwnedSlice(), deployed);
    }
};

/// Contract parameter info (converted from Swift parameter definitions)
pub const ContractParameterInfo = struct {
    name: []const u8,
    parameter_type: []const u8,
    
    pub fn init(name: []const u8, parameter_type: []const u8) ContractParameterInfo {
        return ContractParameterInfo{
            .name = name,
            .parameter_type = parameter_type,
        };
    }
    
    pub fn toJson(self: ContractParameterInfo, allocator: std.mem.Allocator) !std.json.Value {
        var param_obj = std.json.ObjectMap.init(allocator);
        try param_obj.put("name", std.json.Value{ .string = self.name });
        try param_obj.put("type", std.json.Value{ .string = self.parameter_type });
        return std.json.Value{ .object = param_obj };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractParameterInfo {
        const obj = json_value.object;
        const name = try allocator.dupe(u8, obj.get("name").?.string);
        const param_type = try allocator.dupe(u8, obj.get("type").?.string);
        return ContractParameterInfo.init(name, param_type);
    }
};

/// Scrypt parameters (converted from Swift ScryptParams)
pub const ScryptParams = struct {
    n: u32,
    r: u32,
    p: u32,
    
    const Self = @This();
    
    /// Default NEP-6 parameters (matches Swift default)
    pub const DEFAULT: ScryptParams = ScryptParams{ .n = 16384, .r = 8, .p = 8 };
    
    pub fn init(n: u32, r: u32, p: u32) Self {
        return Self{ .n = n, .r = r, .p = p };
    }
    
    pub fn eql(self: Self, other: Self) bool {
        return self.n == other.n and self.r == other.r and self.p == other.p;
    }
    
    pub fn toJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var scrypt_obj = std.json.ObjectMap.init(allocator);
        try scrypt_obj.put("n", std.json.Value{ .integer = @intCast(self.n) });
        try scrypt_obj.put("r", std.json.Value{ .integer = @intCast(self.r) });
        try scrypt_obj.put("p", std.json.Value{ .integer = @intCast(self.p) });
        return std.json.Value{ .object = scrypt_obj };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        _ = allocator;
        const obj = json_value.object;
        
        return Self.init(
            @intCast(obj.get("n").?.integer),
            @intCast(obj.get("r").?.integer),
            @intCast(obj.get("p").?.integer),
        );
    }
};

// Tests (converted from Swift NEP6Wallet tests)
test "NEP6Wallet creation and properties" {
    const testing = std.testing;
    _ = testing.allocator;
    
    // Test wallet creation (equivalent to Swift NEP6Wallet tests)
    const accounts = [_]NEP6Account{};
    const wallet = NEP6Wallet.init(
        "Test Wallet",
        "3.0",
        ScryptParams.DEFAULT,
        &accounts,
        null,
    );
    
    try testing.expectEqualStrings("Test Wallet", wallet.name);
    try testing.expectEqualStrings("3.0", wallet.version);
    try testing.expect(wallet.scrypt.eql(ScryptParams.DEFAULT));
    try testing.expectEqual(@as(usize, 0), wallet.accounts.len);
}

test "NEP6Wallet JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const accounts = [_]NEP6Account{};
    const wallet = NEP6Wallet.init(
        "JSON Test Wallet",
        "3.0",
        ScryptParams.DEFAULT,
        &accounts,
        null,
    );
    
    // Test JSON conversion (equivalent to Swift Codable tests)
    const json_value = try wallet.toJson(allocator);
    defer json_value.deinit();
    
    const wallet_obj = json_value.object;
    try testing.expectEqualStrings("JSON Test Wallet", wallet_obj.get("name").?.string);
    try testing.expectEqualStrings("3.0", wallet_obj.get("version").?.string);
    
    const scrypt_obj = wallet_obj.get("scrypt").?.object;
    try testing.expectEqual(@as(i64, 16384), scrypt_obj.get("n").?.integer);
    try testing.expectEqual(@as(i64, 8), scrypt_obj.get("r").?.integer);
    try testing.expectEqual(@as(i64, 8), scrypt_obj.get("p").?.integer);
}

test "NEP6Account creation and properties" {
    const testing = std.testing;
    _ = testing.allocator;
    
    // Test account creation (equivalent to Swift NEP6Account tests)
    const account = NEP6Account.init(
        "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNn",
        "Test Account",
        true,  // is_default
        false, // lock
        null,  // key
        null,  // contract
        null,  // extra
    );
    
    try testing.expectEqualStrings("NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNn", account.address);
    try testing.expectEqualStrings("Test Account", account.label.?);
    try testing.expect(account.is_default);
    try testing.expect(!account.lock);
    try testing.expect(!account.hasPrivateKey());
}

test "ScryptParams operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test default parameters (equivalent to Swift ScryptParams tests)
    const default_params = ScryptParams.DEFAULT;
    try testing.expectEqual(@as(u32, 16384), default_params.n);
    try testing.expectEqual(@as(u32, 8), default_params.r);
    try testing.expectEqual(@as(u32, 8), default_params.p);
    
    // Test custom parameters
    const custom_params = ScryptParams.init(1024, 4, 4);
    try testing.expectEqual(@as(u32, 1024), custom_params.n);
    try testing.expect(!default_params.eql(custom_params));
    
    // Test JSON conversion
    const json_value = try custom_params.toJson(allocator);
    defer json_value.deinit();
    
    const parsed_params = try ScryptParams.fromJson(json_value, allocator);
    try testing.expect(custom_params.eql(parsed_params));
}
