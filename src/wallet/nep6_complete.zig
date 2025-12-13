//! Complete NEP-6 Wallet Implementation
//!
//! Production-ready NEP-6 wallet format with full import/export capability
//! Handles complete wallet lifecycle and standard compliance.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const Address = @import("../types/address.zig").Address;
const PrivateKey = @import("../crypto/keys.zig").PrivateKey;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const KeyPair = @import("../crypto/keys.zig").KeyPair;
const NEP2 = @import("../crypto/nep2.zig").NEP2;
const json_utils = @import("../utils/json_utils.zig");
const secure = @import("../utils/secure.zig");

/// Complete NEP-6 wallet implementation
pub const CompleteNEP6Wallet = struct {
    name: []const u8,
    version: []const u8,
    scrypt: ScryptParams,
    accounts: ArrayList(CompleteNEP6Account),
    extra: ?std.json.Value,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates complete NEP-6 wallet
    pub fn init(allocator: std.mem.Allocator, name: []const u8) Self {
        return Self{
            .name = name,
            .version = "3.0",
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
        
        if (self.extra) |extra| {
            extra.deinit();
        }
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
        
        try wallet_obj.put("name", std.json.Value{ .string = self.name });
        try wallet_obj.put("version", std.json.Value{ .string = self.version });
        try wallet_obj.put("scrypt", try self.scrypt.toJson(self.allocator));
        
        // Export accounts
        var accounts_array = ArrayList(std.json.Value).init(self.allocator);
        for (self.accounts.items) |account| {
            try accounts_array.append(try account.exportToJson());
        }
        try wallet_obj.put("accounts", std.json.Value{ .array = accounts_array });
        
        if (self.extra) |extra| {
            try wallet_obj.put("extra", extra);
        }
        
        return std.json.Value{ .object = wallet_obj };
    }
    
    /// Imports from NEP-6 JSON format
    pub fn importFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const name = try allocator.dupe(u8, obj.get("name").?.string);
        const version = try allocator.dupe(u8, obj.get("version").?.string);
        const scrypt = try ScryptParams.fromJson(obj.get("scrypt").?, allocator);
        
        var wallet = Self{
            .name = name,
            .version = version,
            .scrypt = scrypt,
            .accounts = ArrayList(CompleteNEP6Account).init(allocator),
            .extra = obj.get("extra"),
            .allocator = allocator,
        };
        
        // Import accounts
        if (obj.get("accounts")) |accounts_array| {
            for (accounts_array.array) |account_json| {
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
            contract.deinit();
        }
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
        
        self.contract = NEP6Contract{
            .script = try self.allocator.dupe(u8, verification_script),
            .parameters = try self.allocator.dupe(NEP6ParameterInfo, &[_]NEP6ParameterInfo{
                NEP6ParameterInfo.init("signature", "Signature"),
            }),
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
        
        const address_str = try self.address.toString(self.allocator);
        defer self.allocator.free(address_str);
        
        try account_obj.put("address", std.json.Value{ .string = address_str });
        
        if (self.label) |label| {
            try account_obj.put("label", std.json.Value{ .string = label });
        }
        
        try account_obj.put("isDefault", std.json.Value{ .bool = self.is_default });
        try account_obj.put("lock", std.json.Value{ .bool = self.lock });
        
        if (self.encrypted_private_key) |key| {
            try account_obj.put("key", std.json.Value{ .string = key });
        }
        
        if (self.contract) |contract| {
            try account_obj.put("contract", try contract.exportToJson(self.allocator));
        }
        
        if (self.extra) |extra| {
            try account_obj.put("extra", extra);
        }
        
        return std.json.Value{ .object = account_obj };
    }
    
    /// Imports account from JSON
    pub fn importFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const address_str = obj.get("address").?.string;
        const address = try Address.fromString(address_str, allocator);
        
        var account = try Self.init(allocator, address, null);
        
        if (obj.get("label")) |label_value| {
            account.label = try allocator.dupe(u8, label_value.string);
        }
        
        account.is_default = obj.get("isDefault").?.bool;
        account.lock = obj.get("lock").?.bool;
        
        if (obj.get("key")) |key_value| {
            account.encrypted_private_key = try allocator.dupe(u8, key_value.string);
        }
        
        if (obj.get("contract")) |contract_value| {
            account.contract = try NEP6Contract.importFromJson(contract_value, allocator);
        }
        
        account.extra = obj.get("extra");
        
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
        
        const script_hex = try @import("../utils/bytes.zig").toHex(self.script, allocator);
        defer allocator.free(script_hex);
        
        try contract_obj.put("script", std.json.Value{ .string = script_hex });
        try contract_obj.put("deployed", std.json.Value{ .bool = self.deployed });
        
        var params_array = ArrayList(std.json.Value).init(allocator);
        for (self.parameters) |param| {
            try params_array.append(try param.exportToJson(allocator));
        }
        try contract_obj.put("parameters", std.json.Value{ .array = params_array });
        
        return std.json.Value{ .object = contract_obj };
    }
    
    pub fn importFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NEP6Contract {
        const obj = json_value.object;
        
        const script_hex = obj.get("script").?.string;
        const script = try @import("../utils/bytes.zig").fromHex(script_hex, allocator);
        const deployed = obj.get("deployed").?.bool;
        
        var parameters = ArrayList(NEP6ParameterInfo).init(allocator);
        if (obj.get("parameters")) |params_array| {
            for (params_array.array) |param_json| {
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
        try param_obj.put("name", std.json.Value{ .string = self.name });
        try param_obj.put("type", std.json.Value{ .string = self.parameter_type });
        return std.json.Value{ .object = param_obj };
    }
    
    pub fn importFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        return Self.init(
            try allocator.dupe(u8, obj.get("name").?.string),
            try allocator.dupe(u8, obj.get("type").?.string),
        );
    }
};

/// Scrypt parameters for NEP-6
pub const ScryptParams = struct {
    n: u32,
    r: u32,
    p: u32,
    
    pub fn init(n: u32, r: u32, p: u32) ScryptParams {
        return ScryptParams{ .n = n, .r = r, .p = p };
    }
    
    pub fn toJson(self: ScryptParams, allocator: std.mem.Allocator) !std.json.Value {
        var scrypt_obj = std.json.ObjectMap.init(allocator);
        try scrypt_obj.put("n", std.json.Value{ .integer = @intCast(self.n) });
        try scrypt_obj.put("r", std.json.Value{ .integer = @intCast(self.r) });
        try scrypt_obj.put("p", std.json.Value{ .integer = @intCast(self.p) });
        return std.json.Value{ .object = scrypt_obj };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ScryptParams {
        _ = allocator;
        const obj = json_value.object;
        
        return ScryptParams.init(
            @intCast(obj.get("n").?.integer),
            @intCast(obj.get("r").?.integer),
            @intCast(obj.get("p").?.integer),
        );
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
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        account.getPrivateKey("wrong_password", wallet.scrypt)
    );
}
