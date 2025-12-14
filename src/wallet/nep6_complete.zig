//! Complete NEP-6 Wallet Implementation
//!
//! Production-ready NEP-6 wallet format with full import/export capability
//! Handles complete wallet lifecycle and standard compliance.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Address = @import("../types/address.zig").Address;
const PrivateKey = @import("../crypto/keys.zig").PrivateKey;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const KeyPair = @import("../crypto/keys.zig").KeyPair;
const NEP2 = @import("../crypto/nep2.zig").NEP2;
const json_utils = @import("../utils/json_utils.zig");
const secure = @import("../utils/secure.zig");
pub const ScryptParams = @import("nep6_wallet.zig").ScryptParams;

/// Complete NEP-6 wallet implementation
pub const CompleteNEP6Wallet = struct {
    name: []const u8,
    owns_name: bool,
    version: []const u8,
    owns_version: bool,
    scrypt: ScryptParams,
    accounts: ArrayList(CompleteNEP6Account),
    extra: ?std.json.Value,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Creates complete NEP-6 wallet
    pub fn init(allocator: std.mem.Allocator, name: []const u8) Self {
        const owned_name = allocator.dupe(u8, name) catch name;
        return Self{
            .name = owned_name,
            .owns_name = owned_name.ptr != name.ptr,
            .version = "3.0",
            .owns_version = false,
            .scrypt = ScryptParams.init(16384, 8, 8), // NEP-6 standard
            .accounts = ArrayList(CompleteNEP6Account).init(allocator),
            .extra = null,
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        for (self.accounts.items) |*account| {
            account.deinit();
        }
        self.accounts.deinit();

        if (self.extra) |extra| json_utils.freeValue(extra, self.allocator);
        if (self.owns_name) self.allocator.free(@constCast(self.name));
        if (self.owns_version) self.allocator.free(@constCast(self.version));
    }

    /// Creates new account with password protection
    pub fn createAccount(self: *Self, password: []const u8, label: ?[]const u8) !*CompleteNEP6Account {
        const key_pair = try KeyPair.generate(true);
        const address = try key_pair.public_key.toAddress(constants.AddressConstants.ADDRESS_VERSION);

        var account = try CompleteNEP6Account.init(self.allocator, address, label);

        // Encrypt private key with NEP-2
        try account.setKeyPair(key_pair, password, self.scrypt);

        try self.accounts.append(account);
        return &self.accounts.items[self.accounts.items.len - 1];
    }

    /// Imports account from private key
    pub fn importAccount(
        self: *Self,
        private_key: PrivateKey,
        password: []const u8,
        label: ?[]const u8,
    ) !*CompleteNEP6Account {
        const public_key = try private_key.getPublicKey(true);
        const key_pair = KeyPair.init(private_key, public_key);
        const address = try public_key.toAddress(constants.AddressConstants.ADDRESS_VERSION);

        var account = try CompleteNEP6Account.init(self.allocator, address, label);
        try account.setKeyPair(key_pair, password, self.scrypt);

        try self.accounts.append(account);
        return &self.accounts.items[self.accounts.items.len - 1];
    }

    /// Imports account from WIF
    pub fn importAccountFromWIF(
        self: *Self,
        wif: []const u8,
        password: []const u8,
        label: ?[]const u8,
    ) !*CompleteNEP6Account {
        const wif_result = try @import("../crypto/wif.zig").decode(wif, self.allocator);
        return try self.importAccount(wif_result.private_key, password, label);
    }

    /// Imports account from NEP-2 encrypted key
    pub fn importAccountFromNEP2(
        self: *Self,
        nep2_key: []const u8,
        password: []const u8,
        label: ?[]const u8,
    ) !*CompleteNEP6Account {
        const key_pair = try NEP2.decrypt(password, nep2_key, self.scrypt, self.allocator);
        defer {
            var mutable_key_pair = key_pair;
            mutable_key_pair.zeroize();
        }

        return try self.importAccount(key_pair.private_key, password, label);
    }

    /// Exports to NEP-6 JSON format
    pub fn exportToJson(self: Self) !std.json.Value {
        var wallet_obj = std.json.ObjectMap.init(self.allocator);
        errdefer json_utils.freeValue(std.json.Value{ .object = wallet_obj }, self.allocator);

        const name_copy = try self.allocator.dupe(u8, self.name);
        json_utils.putOwnedKey(&wallet_obj, self.allocator, "name", std.json.Value{ .string = name_copy }) catch |e| {
            self.allocator.free(name_copy);
            return e;
        };

        const version_copy = try self.allocator.dupe(u8, self.version);
        json_utils.putOwnedKey(&wallet_obj, self.allocator, "version", std.json.Value{ .string = version_copy }) catch |e| {
            self.allocator.free(version_copy);
            return e;
        };

        const scrypt_value = try self.scrypt.toJson(self.allocator);
        json_utils.putOwnedKey(&wallet_obj, self.allocator, "scrypt", scrypt_value) catch |e| {
            json_utils.freeValue(scrypt_value, self.allocator);
            return e;
        };

        // Export accounts
        var accounts_array = ArrayList(std.json.Value).init(self.allocator);
        var accounts_cleanup = true;
        defer if (accounts_cleanup) {
            for (accounts_array.items) |item| json_utils.freeValue(item, self.allocator);
            accounts_array.deinit();
        };
        for (self.accounts.items) |account| {
            try accounts_array.append(try account.exportToJson());
        }
        try json_utils.putOwnedKey(&wallet_obj, self.allocator, "accounts", std.json.Value{ .array = accounts_array });
        accounts_cleanup = false;

        if (self.extra) |extra| {
            const extra_clone = try json_utils.cloneValue(extra, self.allocator);
            json_utils.putOwnedKey(&wallet_obj, self.allocator, "extra", extra_clone) catch |e| {
                json_utils.freeValue(extra_clone, self.allocator);
                return e;
            };
        }

        return std.json.Value{ .object = wallet_obj };
    }

    /// Imports from NEP-6 JSON format
    pub fn importFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const name_value = obj.get("name") orelse return errors.SerializationError.InvalidFormat;
        if (name_value != .string) return errors.SerializationError.InvalidFormat;
        const name = try allocator.dupe(u8, name_value.string);
        var name_cleanup = true;
        defer if (name_cleanup) allocator.free(name);

        const version_value = obj.get("version") orelse return errors.SerializationError.InvalidFormat;
        if (version_value != .string) return errors.SerializationError.InvalidFormat;
        const version = try allocator.dupe(u8, version_value.string);
        var version_cleanup = true;
        defer if (version_cleanup) allocator.free(version);

        const scrypt_value = obj.get("scrypt") orelse return errors.SerializationError.InvalidFormat;
        const scrypt = try ScryptParams.fromJson(scrypt_value, allocator);

        var wallet = Self{
            .name = name,
            .owns_name = true,
            .version = version,
            .owns_version = true,
            .scrypt = scrypt,
            .accounts = ArrayList(CompleteNEP6Account).init(allocator),
            .extra = null,
            .allocator = allocator,
        };
        name_cleanup = false;
        version_cleanup = false;
        errdefer wallet.deinit();

        if (obj.get("extra")) |extra_value| {
            wallet.extra = try json_utils.cloneValue(extra_value, allocator);
        }

        // Import accounts
        if (obj.get("accounts")) |accounts_array| {
            if (accounts_array != .array) return errors.SerializationError.InvalidFormat;
            for (accounts_array.array.items) |account_json| {
                const account = try CompleteNEP6Account.importFromJson(account_json, allocator);
                try wallet.accounts.append(account);
            }
        }

        return wallet;
    }

    /// Saves wallet to file
    pub fn saveToFile(self: Self, file_path: []const u8) !void {
        const json_value = try self.exportToJson();
        defer json_utils.freeValue(json_value, self.allocator);

        const encoded = try std.json.stringifyAlloc(self.allocator, json_value, .{ .whitespace = .indent_2 });
        defer self.allocator.free(encoded);

        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try file.writeAll(encoded);
    }

    /// Loads wallet from file
    pub fn loadFromFile(file_path: []const u8, allocator: std.mem.Allocator) !Self {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const file_content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024); // 10MB max
        defer allocator.free(file_content);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, file_content, .{});
        defer parsed.deinit();

        return try Self.importFromJson(parsed.value, allocator);
    }
};

/// Complete NEP-6 account implementation
pub const CompleteNEP6Account = struct {
    address: Address,
    label: ?[]const u8,
    is_default: bool,
    lock: bool,
    encrypted_private_key: ?[]const u8, // NEP-2 format
    contract: ?NEP6Contract,
    extra: ?std.json.Value,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Creates NEP-6 account
    pub fn init(allocator: std.mem.Allocator, address: Address, label: ?[]const u8) !Self {
        return Self{
            .address = address,
            .label = if (label) |l| try allocator.dupe(u8, l) else null,
            .is_default = false,
            .lock = false,
            .encrypted_private_key = null,
            .contract = null,
            .extra = null,
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        if (self.label) |label| {
            self.allocator.free(label);
        }

        if (self.encrypted_private_key) |key| {
            // Securely clear before freeing
            secure.secureZeroConstBytes(key);
            self.allocator.free(key);
        }

        if (self.contract) |*contract| {
            contract.deinit(self.allocator);
        }

        if (self.extra) |extra| json_utils.freeValue(extra, self.allocator);
    }

    /// Sets key pair with NEP-2 encryption
    pub fn setKeyPair(self: *Self, key_pair: KeyPair, password: []const u8, scrypt: ScryptParams) !void {
        // Encrypt private key with NEP-2
        const encrypted_key = try NEP2.encrypt(password, key_pair, scrypt, self.allocator);

        if (self.encrypted_private_key) |old_key| {
            secure.secureZeroConstBytes(old_key); // Secure clear
            self.allocator.free(old_key);
        }

        self.encrypted_private_key = encrypted_key;

        // Create contract info
        const verification_script = try createVerificationScript(key_pair.public_key, self.allocator);
        defer self.allocator.free(verification_script);

        if (self.contract) |*existing| {
            existing.deinit(self.allocator);
            self.contract = null;
        }

        const script_copy = try self.allocator.dupe(u8, verification_script);
        errdefer self.allocator.free(script_copy);

        const param_name = try self.allocator.dupe(u8, "signature");
        errdefer self.allocator.free(param_name);
        const param_type = try self.allocator.dupe(u8, "Signature");
        errdefer self.allocator.free(param_type);

        const parameters_copy = try self.allocator.dupe(NEP6ParameterInfo, &[_]NEP6ParameterInfo{
            NEP6ParameterInfo.init(param_name, param_type),
        });
        errdefer self.allocator.free(parameters_copy);

        self.contract = NEP6Contract{
            .script = script_copy,
            .parameters = parameters_copy,
            .deployed = false,
        };
    }

    /// Gets private key with password
    pub fn getPrivateKey(self: Self, password: []const u8, scrypt: ScryptParams) !PrivateKey {
        const encrypted_key = self.encrypted_private_key orelse return errors.WalletError.AccountNotFound;

        const key_pair = try NEP2.decrypt(password, encrypted_key, scrypt, self.allocator);
        defer {
            var mutable_key_pair = key_pair;
            mutable_key_pair.zeroize();
        }

        return key_pair.private_key;
    }

    /// Exports account to JSON
    pub fn exportToJson(self: Self) !std.json.Value {
        var account_obj = std.json.ObjectMap.init(self.allocator);
        errdefer json_utils.freeValue(std.json.Value{ .object = account_obj }, self.allocator);

        const address_str = try self.address.toString(self.allocator);
        json_utils.putOwnedKey(&account_obj, self.allocator, "address", std.json.Value{ .string = address_str }) catch |e| {
            self.allocator.free(address_str);
            return e;
        };

        if (self.label) |label| {
            const label_copy = try self.allocator.dupe(u8, label);
            json_utils.putOwnedKey(&account_obj, self.allocator, "label", std.json.Value{ .string = label_copy }) catch |e| {
                self.allocator.free(label_copy);
                return e;
            };
        }

        try json_utils.putOwnedKey(&account_obj, self.allocator, "isDefault", std.json.Value{ .bool = self.is_default });
        try json_utils.putOwnedKey(&account_obj, self.allocator, "lock", std.json.Value{ .bool = self.lock });

        if (self.encrypted_private_key) |key| {
            const key_copy = try self.allocator.dupe(u8, key);
            json_utils.putOwnedKey(&account_obj, self.allocator, "key", std.json.Value{ .string = key_copy }) catch |e| {
                self.allocator.free(key_copy);
                return e;
            };
        }

        if (self.contract) |contract| {
            const contract_value = try contract.exportToJson(self.allocator);
            json_utils.putOwnedKey(&account_obj, self.allocator, "contract", contract_value) catch |e| {
                json_utils.freeValue(contract_value, self.allocator);
                return e;
            };
        }

        if (self.extra) |extra| {
            const extra_clone = try json_utils.cloneValue(extra, self.allocator);
            json_utils.putOwnedKey(&account_obj, self.allocator, "extra", extra_clone) catch |e| {
                json_utils.freeValue(extra_clone, self.allocator);
                return e;
            };
        }

        return std.json.Value{ .object = account_obj };
    }

    /// Imports account from JSON
    pub fn importFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
        if (address_value != .string) return errors.SerializationError.InvalidFormat;
        const address = try Address.fromString(address_value.string, allocator);

        var account = try Self.init(allocator, address, null);
        errdefer account.deinit();

        if (obj.get("label")) |label_value| {
            switch (label_value) {
                .string => |str| account.label = try allocator.dupe(u8, str),
                .null => {},
                else => return errors.SerializationError.InvalidFormat,
            }
        }

        const is_default_value = obj.get("isDefault") orelse return errors.SerializationError.InvalidFormat;
        if (is_default_value != .bool) return errors.SerializationError.InvalidFormat;
        account.is_default = is_default_value.bool;

        const lock_value = obj.get("lock") orelse return errors.SerializationError.InvalidFormat;
        if (lock_value != .bool) return errors.SerializationError.InvalidFormat;
        account.lock = lock_value.bool;

        if (obj.get("key")) |key_value| {
            switch (key_value) {
                .string => |str| account.encrypted_private_key = try allocator.dupe(u8, str),
                .null => {},
                else => return errors.SerializationError.InvalidFormat,
            }
        }

        if (obj.get("contract")) |contract_value| {
            if (contract_value == .null) {
                account.contract = null;
            } else {
                account.contract = try NEP6Contract.importFromJson(contract_value, allocator);
            }
        }

        if (obj.get("extra")) |extra_value| {
            account.extra = try json_utils.cloneValue(extra_value, allocator);
        }

        return account;
    }
};

/// NEP-6 contract information
pub const NEP6Contract = struct {
    script: []const u8,
    parameters: []const NEP6ParameterInfo,
    deployed: bool,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.script);

        for (self.parameters) |param| {
            param.deinit(allocator);
        }
        allocator.free(self.parameters);
    }

    pub fn exportToJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var contract_obj = std.json.ObjectMap.init(allocator);
        errdefer json_utils.freeValue(std.json.Value{ .object = contract_obj }, allocator);

        const script_hex = try @import("../utils/bytes.zig").toHex(self.script, allocator);
        json_utils.putOwnedKey(&contract_obj, allocator, "script", std.json.Value{ .string = script_hex }) catch |e| {
            allocator.free(script_hex);
            return e;
        };
        try json_utils.putOwnedKey(&contract_obj, allocator, "deployed", std.json.Value{ .bool = self.deployed });

        var params_array = ArrayList(std.json.Value).init(allocator);
        var params_cleanup = true;
        defer if (params_cleanup) {
            for (params_array.items) |item| json_utils.freeValue(item, allocator);
            params_array.deinit();
        };
        for (self.parameters) |param| {
            try params_array.append(try param.exportToJson(allocator));
        }
        try json_utils.putOwnedKey(&contract_obj, allocator, "parameters", std.json.Value{ .array = params_array });
        params_cleanup = false;

        return std.json.Value{ .object = contract_obj };
    }

    pub fn importFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NEP6Contract {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const script_value = obj.get("script") orelse return errors.SerializationError.InvalidFormat;
        if (script_value != .string) return errors.SerializationError.InvalidFormat;
        const script = try @import("../utils/bytes.zig").fromHex(script_value.string, allocator);
        errdefer allocator.free(script);

        const deployed_value = obj.get("deployed") orelse return errors.SerializationError.InvalidFormat;
        if (deployed_value != .bool) return errors.SerializationError.InvalidFormat;
        const deployed = deployed_value.bool;

        var parameters = ArrayList(NEP6ParameterInfo).init(allocator);
        errdefer {
            for (parameters.items) |param| param.deinit(allocator);
            parameters.deinit();
        }
        if (obj.get("parameters")) |params_array| {
            if (params_array != .array) return errors.SerializationError.InvalidFormat;
            for (params_array.array.items) |param_json| {
                try parameters.append(try NEP6ParameterInfo.importFromJson(param_json, allocator));
            }
        }

        return NEP6Contract{
            .script = script,
            .parameters = try parameters.toOwnedSlice(),
            .deployed = deployed,
        };
    }
};

/// NEP-6 parameter information
pub const NEP6ParameterInfo = struct {
    name: []const u8,
    parameter_type: []const u8,

    const Self = @This();

    pub fn init(name: []const u8, parameter_type: []const u8) Self {
        return Self{
            .name = name,
            .parameter_type = parameter_type,
        };
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.parameter_type);
    }

    pub fn exportToJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var param_obj = std.json.ObjectMap.init(allocator);
        errdefer json_utils.freeValue(std.json.Value{ .object = param_obj }, allocator);

        const name_copy = try allocator.dupe(u8, self.name);
        json_utils.putOwnedKey(&param_obj, allocator, "name", std.json.Value{ .string = name_copy }) catch |e| {
            allocator.free(name_copy);
            return e;
        };

        const type_copy = try allocator.dupe(u8, self.parameter_type);
        json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = type_copy }) catch |e| {
            allocator.free(type_copy);
            return e;
        };
        return std.json.Value{ .object = param_obj };
    }

    pub fn importFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
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

        return Self.init(name, param_type);
    }
};

/// Creates verification script for account
fn createVerificationScript(public_key: PublicKey, allocator: std.mem.Allocator) ![]u8 {
    var script = ArrayList(u8).init(allocator);
    defer script.deinit();

    // PUSHDATA public_key
    try script.append(0x0C); // PUSHDATA1
    try script.append(@intCast(public_key.toSlice().len));
    try script.appendSlice(public_key.toSlice());

    // SYSCALL CheckSig
    try script.append(0x41); // SYSCALL
    const syscall_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, constants.InteropServices.SYSTEM_CRYPTO_CHECK_SIG));
    try script.appendSlice(&syscall_bytes);

    return try script.toOwnedSlice();
}

// Tests
test "CompleteNEP6Wallet creation and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var wallet = CompleteNEP6Wallet.init(allocator, "Production Test Wallet");
    defer wallet.deinit();

    // Test account creation
    const account = try wallet.createAccount("test_password_123", "Test Account");
    try testing.expect(account.encrypted_private_key != null);
    try testing.expectEqualStrings("Test Account", account.label.?);

    // Test account import from private key
    const private_key = @import("../crypto/keys.zig").PrivateKey.generate();
    const imported_account = try wallet.importAccount(private_key, "import_password", "Imported Account");
    try testing.expect(imported_account.encrypted_private_key != null);

    try testing.expectEqual(@as(usize, 2), wallet.accounts.items.len);
}

test "NEP-6 JSON import/export" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var wallet = CompleteNEP6Wallet.init(allocator, "JSON Test Wallet");
    defer wallet.deinit();

    _ = try wallet.createAccount("password123", "JSON Test Account");

    // Test JSON export
    const json_value = try wallet.exportToJson();
    defer json_utils.freeValue(json_value, allocator);

    // Test JSON import
    const imported_wallet = try CompleteNEP6Wallet.importFromJson(json_value, allocator);
    defer {
        var mutable_imported = imported_wallet;
        mutable_imported.deinit();
    }

    try testing.expectEqualStrings(wallet.name, imported_wallet.name);
    try testing.expectEqual(wallet.accounts.items.len, imported_wallet.accounts.items.len);
}

test "NEP-2 integration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var wallet = CompleteNEP6Wallet.init(allocator, "NEP-2 Test Wallet");
    defer wallet.deinit();

    const password = "nep2_integration_test";
    const account = try wallet.createAccount(password, "NEP-2 Account");

    // Test that we can decrypt the private key
    const decrypted_key = try account.getPrivateKey(password, wallet.scrypt);
    try testing.expect(decrypted_key.isValid());

    // Test wrong password fails
    try testing.expectError(errors.WalletError.InvalidPassword, account.getPrivateKey("wrong_password", wallet.scrypt));
}
