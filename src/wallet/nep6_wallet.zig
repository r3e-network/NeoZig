//! NEP-6 Wallet implementation
//!
//! Complete conversion from NeoSwift NEP6Wallet.swift
//! Standard wallet format for Neo blockchain.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const json_utils = @import("../utils/json_utils.zig");

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

        try json_utils.putOwnedKey(&wallet_obj, allocator, "name", std.json.Value{ .string = try allocator.dupe(u8, self.name) });
        try json_utils.putOwnedKey(&wallet_obj, allocator, "version", std.json.Value{ .string = try allocator.dupe(u8, self.version) });
        try json_utils.putOwnedKey(&wallet_obj, allocator, "scrypt", try self.scrypt.toJson(allocator));

        // Convert accounts array
        var accounts_array = ArrayList(std.json.Value).init(allocator);
        for (self.accounts) |account| {
            try accounts_array.append(try account.toJson(allocator));
        }
        try json_utils.putOwnedKey(&wallet_obj, allocator, "accounts", std.json.Value{ .array = accounts_array });

        if (self.extra) |extra| {
            try json_utils.putOwnedKey(&wallet_obj, allocator, "extra", try json_utils.cloneValue(extra, allocator));
        }

        return std.json.Value{ .object = wallet_obj };
    }

    /// Parses from JSON (equivalent to Swift Codable decoding)
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const name_value = obj.get("name") orelse return errors.SerializationError.InvalidFormat;
        if (name_value != .string) return errors.SerializationError.InvalidFormat;
        const name = try allocator.dupe(u8, name_value.string);
        errdefer allocator.free(name);

        const version_value = obj.get("version") orelse return errors.SerializationError.InvalidFormat;
        if (version_value != .string) return errors.SerializationError.InvalidFormat;
        const version = try allocator.dupe(u8, version_value.string);
        errdefer allocator.free(version);

        const scrypt_value = obj.get("scrypt") orelse return errors.SerializationError.InvalidFormat;
        const scrypt = try ScryptParams.fromJson(scrypt_value, allocator);

        // Parse accounts
        var accounts = ArrayList(NEP6Account).init(allocator);
        errdefer {
            for (accounts.items) |*account| deinitOwnedAccount(account, allocator);
            accounts.deinit();
        }
        if (obj.get("accounts")) |accounts_array| {
            if (accounts_array != .array) return errors.SerializationError.InvalidFormat;
            for (accounts_array.array.items) |account_json| {
                try accounts.append(try NEP6Account.fromJson(account_json, allocator));
            }
        }

        var extra_opt: ?std.json.Value = null;
        errdefer if (extra_opt) |extra_value| json_utils.freeValue(extra_value, allocator);
        if (obj.get("extra")) |extra_value| {
            extra_opt = try json_utils.cloneValue(extra_value, allocator);
        }

        return Self.init(name, version, scrypt, try accounts.toOwnedSlice(), extra_opt);
    }

    /// Saves to file (equivalent to Swift file operations)
    pub fn saveToFile(self: Self, file_path: []const u8, allocator: std.mem.Allocator) !void {
        const json_value = try self.toJson(allocator);
        defer json_utils.freeValue(json_value, allocator);

        const encoded = try std.json.stringifyAlloc(allocator, json_value, .{ .whitespace = .indent_2 });
        defer allocator.free(encoded);

        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try file.writeAll(encoded);
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

        try json_utils.putOwnedKey(&account_obj, allocator, "address", std.json.Value{ .string = try allocator.dupe(u8, self.address) });

        if (self.label) |label| {
            try json_utils.putOwnedKey(&account_obj, allocator, "label", std.json.Value{ .string = try allocator.dupe(u8, label) });
        }

        try json_utils.putOwnedKey(&account_obj, allocator, "isDefault", std.json.Value{ .bool = self.is_default });
        try json_utils.putOwnedKey(&account_obj, allocator, "lock", std.json.Value{ .bool = self.lock });

        if (self.key) |key| {
            try json_utils.putOwnedKey(&account_obj, allocator, "key", std.json.Value{ .string = try allocator.dupe(u8, key) });
        }

        if (self.contract) |contract| {
            try json_utils.putOwnedKey(&account_obj, allocator, "contract", try contract.toJson(allocator));
        }

        if (self.extra) |extra| {
            try json_utils.putOwnedKey(&account_obj, allocator, "extra", try json_utils.cloneValue(extra, allocator));
        }

        return std.json.Value{ .object = account_obj };
    }

    /// Parses from JSON (equivalent to Swift Codable)
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
        if (address_value != .string) return errors.SerializationError.InvalidFormat;
        const address = try allocator.dupe(u8, address_value.string);
        errdefer allocator.free(address);

        const label = if (obj.get("label")) |label_value|
            switch (label_value) {
                .string => |str| try allocator.dupe(u8, str),
                .null => null,
                else => return errors.SerializationError.InvalidFormat,
            }
        else
            null;
        errdefer if (label) |value| allocator.free(@constCast(value));

        const is_default_value = obj.get("isDefault") orelse return errors.SerializationError.InvalidFormat;
        if (is_default_value != .bool) return errors.SerializationError.InvalidFormat;

        const lock_value = obj.get("lock") orelse return errors.SerializationError.InvalidFormat;
        if (lock_value != .bool) return errors.SerializationError.InvalidFormat;

        const key = if (obj.get("key")) |key_value|
            switch (key_value) {
                .string => |str| try allocator.dupe(u8, str),
                .null => null,
                else => return errors.SerializationError.InvalidFormat,
            }
        else
            null;
        errdefer if (key) |value| allocator.free(@constCast(value));

        var contract_opt: ?NEP6Contract = null;
        errdefer if (contract_opt) |*contract_value| deinitOwnedContract(contract_value, allocator);
        if (obj.get("contract")) |contract_value| {
            if (contract_value == .null) {
                contract_opt = null;
            } else {
                contract_opt = try NEP6Contract.fromJson(contract_value, allocator);
            }
        }

        var extra_opt: ?std.json.Value = null;
        errdefer if (extra_opt) |extra_value| json_utils.freeValue(extra_value, allocator);
        if (obj.get("extra")) |extra_value| {
            extra_opt = try json_utils.cloneValue(extra_value, allocator);
        }

        return Self.init(
            address,
            label,
            is_default_value.bool,
            lock_value.bool,
            key,
            contract_opt,
            extra_opt,
        );
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

        try json_utils.putOwnedKey(&contract_obj, allocator, "script", std.json.Value{ .string = script_hex });
        try json_utils.putOwnedKey(&contract_obj, allocator, "deployed", std.json.Value{ .bool = self.deployed });

        // Convert parameters
        var params_array = ArrayList(std.json.Value).init(allocator);
        for (self.parameters) |param| {
            try params_array.append(try param.toJson(allocator));
        }
        try json_utils.putOwnedKey(&contract_obj, allocator, "parameters", std.json.Value{ .array = params_array });

        return std.json.Value{ .object = contract_obj };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const script_value = obj.get("script") orelse return errors.SerializationError.InvalidFormat;
        if (script_value != .string) return errors.SerializationError.InvalidFormat;
        const script = try @import("../utils/bytes.zig").fromHex(script_value.string, allocator);
        errdefer allocator.free(script);

        const deployed_value = obj.get("deployed") orelse return errors.SerializationError.InvalidFormat;
        if (deployed_value != .bool) return errors.SerializationError.InvalidFormat;
        const deployed = deployed_value.bool;

        // Parse parameters
        var parameters = ArrayList(ContractParameterInfo).init(allocator);
        errdefer {
            for (parameters.items) |*param| deinitOwnedContractParameterInfo(param, allocator);
            parameters.deinit();
        }
        if (obj.get("parameters")) |params_array| {
            if (params_array != .array) return errors.SerializationError.InvalidFormat;
            for (params_array.array.items) |param_json| {
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
        try json_utils.putOwnedKey(&param_obj, allocator, "name", std.json.Value{ .string = try allocator.dupe(u8, self.name) });
        try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, self.parameter_type) });
        return std.json.Value{ .object = param_obj };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractParameterInfo {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const name_value = obj.get("name") orelse return errors.SerializationError.InvalidFormat;
        if (name_value != .string) return errors.SerializationError.InvalidFormat;
        const name = try allocator.dupe(u8, name_value.string);
        errdefer allocator.free(name);

        const type_value = obj.get("type") orelse return errors.SerializationError.InvalidFormat;
        if (type_value != .string) return errors.SerializationError.InvalidFormat;
        const param_type = try allocator.dupe(u8, type_value.string);
        errdefer allocator.free(param_type);

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
        try json_utils.putOwnedKey(&scrypt_obj, allocator, "n", std.json.Value{ .integer = @intCast(self.n) });
        try json_utils.putOwnedKey(&scrypt_obj, allocator, "r", std.json.Value{ .integer = @intCast(self.r) });
        try json_utils.putOwnedKey(&scrypt_obj, allocator, "p", std.json.Value{ .integer = @intCast(self.p) });
        return std.json.Value{ .object = scrypt_obj };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        _ = allocator;
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const n_value = obj.get("n") orelse return errors.SerializationError.InvalidFormat;
        if (n_value != .integer) return errors.SerializationError.InvalidFormat;

        const r_value = obj.get("r") orelse return errors.SerializationError.InvalidFormat;
        if (r_value != .integer) return errors.SerializationError.InvalidFormat;

        const p_value = obj.get("p") orelse return errors.SerializationError.InvalidFormat;
        if (p_value != .integer) return errors.SerializationError.InvalidFormat;

        return Self.init(
            @intCast(n_value.integer),
            @intCast(r_value.integer),
            @intCast(p_value.integer),
        );
    }
};

fn deinitOwnedContractParameterInfo(param: *const ContractParameterInfo, allocator: std.mem.Allocator) void {
    if (param.name.len > 0) allocator.free(@constCast(param.name));
    if (param.parameter_type.len > 0) allocator.free(@constCast(param.parameter_type));
}

fn deinitOwnedContract(contract: *NEP6Contract, allocator: std.mem.Allocator) void {
    if (contract.script.len > 0) allocator.free(@constCast(contract.script));
    for (contract.parameters) |*param| deinitOwnedContractParameterInfo(param, allocator);
    if (contract.parameters.len > 0) allocator.free(@constCast(contract.parameters));
}

fn deinitOwnedAccount(account: *NEP6Account, allocator: std.mem.Allocator) void {
    if (account.address.len > 0) allocator.free(@constCast(account.address));
    if (account.label) |label| {
        if (label.len > 0) allocator.free(@constCast(label));
    }
    if (account.key) |key| {
        if (key.len > 0) allocator.free(@constCast(key));
    }
    if (account.contract) |*contract| deinitOwnedContract(contract, allocator);
    if (account.extra) |extra| json_utils.freeValue(extra, allocator);
}

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
    defer json_utils.freeValue(json_value, allocator);

    const wallet_obj = json_value.object;
    try testing.expectEqualStrings("JSON Test Wallet", wallet_obj.get("name").?.string);
    try testing.expectEqualStrings("3.0", wallet_obj.get("version").?.string);

    const scrypt_obj = wallet_obj.get("scrypt").?.object;
    try testing.expectEqual(@as(i64, 16384), scrypt_obj.get("n").?.integer);
    try testing.expectEqual(@as(i64, 8), scrypt_obj.get("r").?.integer);
    try testing.expectEqual(@as(i64, 8), scrypt_obj.get("p").?.integer);
}

test "NEP6Wallet and contract fromJson smoke tests" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Wallet round-trip (empty accounts)
    const accounts = [_]NEP6Account{};
    const wallet = NEP6Wallet.init(
        "Roundtrip Wallet",
        "3.0",
        ScryptParams.DEFAULT,
        &accounts,
        null,
    );

    const wallet_json = try wallet.toJson(allocator);
    const parsed_wallet = try NEP6Wallet.fromJson(wallet_json, allocator);
    try testing.expect(wallet.eql(parsed_wallet));

    // Contract parsing
    const script = [_]u8{ 0x01, 0x02 };
    const params = [_]ContractParameterInfo{
        ContractParameterInfo.init("param", "String"),
    };
    const contract = NEP6Contract.init(&script, &params, true);

    const contract_json = try contract.toJson(allocator);
    const parsed_contract = try NEP6Contract.fromJson(contract_json, allocator);
    try testing.expect(parsed_contract.deployed);
    try testing.expectEqual(@as(usize, 2), parsed_contract.script.len);
    try testing.expect(std.mem.eql(u8, parsed_contract.script, &script));
    try testing.expectEqual(@as(usize, 1), parsed_contract.parameters.len);
    try testing.expectEqualStrings("param", parsed_contract.parameters[0].name);
}

test "NEP6Account creation and properties" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test account creation (equivalent to Swift NEP6Account tests)
    const account = NEP6Account.init(
        "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNn",
        "Test Account",
        true, // is_default
        false, // lock
        null, // key
        null, // contract
        null, // extra
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
    defer json_utils.freeValue(json_value, allocator);

    const parsed_params = try ScryptParams.fromJson(json_value, allocator);
    try testing.expect(custom_params.eql(parsed_params));
}
