//! Neo Wallet implementation
//!
//! Complete conversion from NeoSwift Wallet.swift
//! Maintains full API compatibility with Swift wallet system.

const std = @import("std");
const ArrayList = std.array_list.Managed;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const Address = @import("../types/address.zig").Address;
const PrivateKey = @import("../crypto/keys.zig").PrivateKey;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const KeyPair = @import("../crypto/keys.zig").KeyPair;

/// Wallet manages a collection of accounts (converted from Swift Wallet class)
pub const Wallet = struct {
    /// Default wallet name (matches Swift DEFAULT_WALLET_NAME)
    pub const DEFAULT_WALLET_NAME = "NeoSwiftWallet";
    
    /// Current wallet version (matches Swift CURRENT_VERSION)
    pub const CURRENT_VERSION = "3.0";
    
    allocator: std.mem.Allocator,
    name_field: []const u8,
    version_field: []const u8,
    scrypt_params_field: ScryptParams,
    accounts_map: std.HashMap(Hash160, Account, Hash160Context, std.hash_map.default_max_load_percentage),
    default_account_hash: ?Hash160,
    
    const Self = @This();
    
    /// Creates new wallet (equivalent to Swift init())
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .name_field = DEFAULT_WALLET_NAME,
            .version_field = CURRENT_VERSION,
            .scrypt_params_field = ScryptParams.DEFAULT,
            .accounts_map = std.HashMap(Hash160, Account, Hash160Context, std.hash_map.default_max_load_percentage).init(allocator),
            .default_account_hash = null,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        var iterator = self.accounts_map.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.accounts_map.deinit();
    }
    
    /// Gets wallet name (equivalent to Swift name property)
    pub fn getName(self: Self) []const u8 {
        return self.name_field;
    }
    
    /// Sets wallet name (equivalent to Swift name(_ name: String))
    pub fn name(self: *Self, wallet_name: []const u8) *Self {
        self.name_field = wallet_name;
        return self;
    }
    
    /// Gets wallet version (equivalent to Swift version property)
    pub fn getVersion(self: Self) []const u8 {
        return self.version_field;
    }
    
    /// Sets wallet version (equivalent to Swift version(_ version: String))
    pub fn version(self: *Self, wallet_version: []const u8) *Self {
        self.version_field = wallet_version;
        return self;
    }
    
    /// Gets scrypt parameters (equivalent to Swift scryptParams property)
    pub fn getScryptParams(self: Self) ScryptParams {
        return self.scrypt_params_field;
    }
    
    /// Sets scrypt parameters (equivalent to Swift scryptParams(_ scryptParams: ScryptParams))
    pub fn scryptParams(self: *Self, params: ScryptParams) *Self {
        self.scrypt_params_field = params;
        return self;
    }
    
    /// Gets all accounts sorted by script hash (equivalent to Swift accounts property)
    pub fn getAccounts(self: Self, allocator: std.mem.Allocator) ![]Account {
        var accounts = ArrayList(Account).init(allocator);
        defer accounts.deinit();
        
        var iterator = self.accounts_map.iterator();
        while (iterator.next()) |entry| {
            try accounts.append(entry.value_ptr.*);
        }
        
        // Sort by script hash (matches Swift sorted behavior)
        std.sort.block(Account, accounts.items, {}, accountLessThan);
        
        return try accounts.toOwnedSlice();
    }
    
    /// Gets default account (equivalent to Swift defaultAccount property)
    pub fn getDefaultAccount(self: Self) ?Account {
        if (self.default_account_hash) |hash| {
            return self.accounts_map.get(hash);
        }
        return null;
    }
    
    /// Sets default account by account (equivalent to Swift defaultAccount(_ account: Account))
    pub fn defaultAccount(self: *Self, account: Account) !*Self {
        return try self.defaultAccountByHash(account.getScriptHash());
    }
    
    /// Sets default account by script hash (equivalent to Swift defaultAccount(_ accountHash160: Hash160))
    pub fn defaultAccountByHash(self: *Self, account_hash: Hash160) !*Self {
        if (!self.accounts_map.contains(account_hash)) {
            return errors.throwIllegalArgument("Wallet does not contain account with specified script hash");
        }
        
        self.default_account_hash = account_hash;
        return self;
    }
    
    /// Checks if account is default (equivalent to Swift isDefault(_ account: Account))
    pub fn isDefault(self: Self, account: Account) bool {
        return self.isDefaultByHash(account.getScriptHash());
    }
    
    /// Checks if account hash is default (equivalent to Swift isDefault(_ accountHash: Hash160?))
    pub fn isDefaultByHash(self: Self, account_hash: ?Hash160) bool {
        if (self.default_account_hash == null or account_hash == null) return false;
        return self.default_account_hash.?.eql(account_hash.?);
    }
    
    /// Adds accounts to wallet (equivalent to Swift addAccounts(_ accounts: [Account]))
    pub fn addAccounts(self: *Self, accounts: []const Account) !*Self {
        for (accounts) |account| {
            _ = try self.addAccount(account);
        }
        return self;
    }
    
    /// Adds single account (equivalent to Swift addAccount(_ account: Account))
    pub fn addAccount(self: *Self, account: Account) !*Self {
        const script_hash = account.getScriptHash();
        
        // Check if account already exists
        if (self.accounts_map.contains(script_hash)) {
            return errors.throwIllegalArgument("Account with this script hash already exists");
        }
        
        try self.accounts_map.put(script_hash, account);
        
        // Set as default if it's the first account
        if (self.default_account_hash == null) {
            self.default_account_hash = script_hash;
        }
        
        return self;
    }
    
    /// Removes account (equivalent to Swift removeAccount(_ account: Account))
    pub fn removeAccount(self: *Self, account: Account) !*Self {
        return try self.removeAccountByHash(account.getScriptHash());
    }
    
    /// Removes account by hash (equivalent to Swift removeAccount(_ accountHash: Hash160))
    pub fn removeAccountByHash(self: *Self, account_hash: Hash160) !*Self {
        if (!self.accounts_map.contains(account_hash)) {
            return errors.WalletError.AccountNotFound;
        }
        
        // Remove account
        var removed_account = self.accounts_map.fetchRemove(account_hash).?.value;
        removed_account.deinit();
        
        // Update default account if necessary
        if (self.default_account_hash != null and self.default_account_hash.?.eql(account_hash)) {
            self.default_account_hash = null;
            
            // Set new default to first remaining account
            var iterator = self.accounts_map.iterator();
            if (iterator.next()) |first_entry| {
                self.default_account_hash = first_entry.key_ptr.*;
            }
        }
        
        return self;
    }
    
    /// Checks if wallet contains account (equivalent to Swift containsAccount)
    pub fn containsAccount(self: Self, account: Account) bool {
        return self.containsAccountByHash(account.getScriptHash());
    }
    
    /// Checks if wallet contains account by hash
    pub fn containsAccountByHash(self: Self, account_hash: Hash160) bool {
        return self.accounts_map.contains(account_hash);
    }
    
    /// Gets account by script hash (equivalent to Swift getAccount)
    pub fn getAccount(self: Self, script_hash: Hash160) ?Account {
        return self.accounts_map.get(script_hash);
    }
    
    /// Gets account count
    pub fn getAccountCount(self: Self) u32 {
        return @intCast(self.accounts_map.count());
    }
    
    /// Creates new account in wallet (equivalent to Swift createAccount)
    pub fn createAccount(self: *Self, label: ?[]const u8) !Account {
        const key_pair = try KeyPair.generate(true);
        const account = try Account.initFromKeyPair(self.allocator, key_pair, label);
        _ = try self.addAccount(account);
        return account;
    }
    
    /// Imports account from private key (equivalent to Swift methods)
    pub fn importAccount(
        self: *Self,
        private_key: PrivateKey,
        password: []const u8,
        label: ?[]const u8,
    ) !Account {
        const public_key = try private_key.getPublicKey(true);
        var account = try Account.initFromKeys(self.allocator, private_key, public_key, label);
        
        // Encrypt private key with password
        try account.encryptPrivateKey(password, private_key, public_key);
        
        _ = try self.addAccount(account);
        return account;
    }
    
    /// Imports account from WIF (equivalent to Swift importAccountFromWIF)
    pub fn importAccountFromWIF(
        self: *Self,
        wif: []const u8,
        password: []const u8,
        label: ?[]const u8,
    ) !Account {
        const wif_result = try @import("../crypto/wif.zig").decode(wif, self.allocator);
        return try self.importAccount(wif_result.private_key, password, label);
    }
};

/// Account sorting helper
fn accountLessThan(context: void, a: Account, b: Account) bool {
    _ = context;
    return a.getScriptHash().compare(b.getScriptHash()) == .lt;
}

/// Hash160 context for HashMap
pub const Hash160Context = struct {
    pub fn hash(self: @This(), key: Hash160) u64 {
        _ = self;
        return key.hash();
    }
    
    pub fn eql(self: @This(), a: Hash160, b: Hash160) bool {
        _ = self;
        return a.eql(b);
    }
};

/// Scrypt parameters (converted from Swift ScryptParams)
pub const ScryptParams = struct {
    n: u32,
    r: u32,
    p: u32,
    
    /// Default scrypt parameters (matches Swift .DEFAULT)
    pub const DEFAULT: ScryptParams = ScryptParams{
        .n = 16384,  // 2^14
        .r = 8,
        .p = 8,
    };
    
    /// Light parameters for testing
    pub const LIGHT: ScryptParams = ScryptParams{
        .n = 512,    // 2^9
        .r = 1,
        .p = 1,
    };
    
    pub fn init(n: u32, r: u32, p: u32) ScryptParams {
        return ScryptParams{ .n = n, .r = r, .p = p };
    }
};

/// Account (converted from Swift Account)
pub const Account = struct {
    allocator: std.mem.Allocator,
    address: Address,
    label: ?[]const u8,
    is_locked: bool,
    encrypted_private_key: ?[]const u8,
    contract_info: ?ContractInfo,
    
    const Self = @This();
    
    /// Creates account from key pair (equivalent to Swift Account creation)
    pub fn initFromKeyPair(allocator: std.mem.Allocator, key_pair: KeyPair, label: ?[]const u8) !Self {
        const address = try key_pair.public_key.toAddress(constants.AddressConstants.ADDRESS_VERSION);
        
        return Self{
            .allocator = allocator,
            .address = address,
            .label = label,
            .is_locked = false,
            .encrypted_private_key = null,
            .contract_info = null,
        };
    }
    
    /// Creates account from private/public keys
    pub fn initFromKeys(
        allocator: std.mem.Allocator,
        private_key: PrivateKey,
        public_key: PublicKey,
        label: ?[]const u8,
    ) !Self {
        _ = private_key;
        const address = try public_key.toAddress(constants.AddressConstants.ADDRESS_VERSION);
        
        return Self{
            .allocator = allocator,
            .address = address,
            .label = label,
            .is_locked = false,
            .encrypted_private_key = null,
            .contract_info = null,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        if (self.encrypted_private_key) |key| {
            self.allocator.free(key);
        }
        if (self.contract_info) |*info| {
            info.deinit();
        }
    }
    
    /// Gets script hash (equivalent to Swift getScriptHash())
    pub fn getScriptHash(self: Self) Hash160 {
        return self.address.toHash160();
    }
    
    /// Gets address (equivalent to Swift getAddress())
    pub fn getAddress(self: Self) Address {
        return self.address;
    }
    
    /// Gets label (equivalent to Swift getLabel())
    pub fn getLabel(self: Self) ?[]const u8 {
        return self.label;
    }
    
    /// Checks if account is locked (equivalent to Swift isLocked property)
    pub fn isLocked(self: Self) bool {
        return self.is_locked;
    }
    
    /// Locks the account (equivalent to Swift lock methods)
    pub fn lock(self: *Self) void {
        self.is_locked = true;
    }
    
    /// Unlocks the account (equivalent to Swift unlock methods)
    pub fn unlock(self: *Self) void {
        self.is_locked = false;
    }
    
    /// Checks if account has private key (equivalent to Swift hasPrivateKey)
    pub fn hasPrivateKey(self: Self) bool {
        return self.encrypted_private_key != null;
    }
    
    /// Encrypts and stores private key (equivalent to Swift NEP-2 encryption)
    pub fn encryptPrivateKey(self: *Self, password: []const u8, private_key: PrivateKey, public_key: PublicKey) !void {
        // Use actual NEP-2 encryption implementation
        const key_pair = KeyPair.init(private_key, public_key);
        
        const nep2 = @import("../crypto/nep2.zig");
        const encrypted_key = try nep2.NEP2.encrypt(
            password,
            key_pair,
            ScryptParams.DEFAULT,
            self.allocator,
        );
        
        if (self.encrypted_private_key) |old_key| {
            self.allocator.free(old_key);
        }
        
        self.encrypted_private_key = encrypted_key;
    }
    
    /// Decrypts private key (equivalent to Swift getPrivateKey with password)
    pub fn getPrivateKey(self: Self, password: []const u8) !PrivateKey {
        const encrypted_key = self.encrypted_private_key orelse return errors.WalletError.AccountNotFound;
        
        // Use actual NEP-2 decryption implementation
        const nep2 = @import("../crypto/nep2.zig");
        const decrypted_key_pair = try nep2.NEP2.decrypt(
            password,
            encrypted_key,
            ScryptParams.DEFAULT,
            self.allocator,
        );
        
        return decrypted_key_pair.private_key;
    }
    
    /// Gets private key without password (for testing)
    pub fn getPrivateKeyUnsafe(self: Self) !PrivateKey {
        return try self.getPrivateKey("");
    }
    
    /// Creates verification script (equivalent to Swift contract creation)
    pub fn createVerificationScript(self: Self, allocator: std.mem.Allocator) ![]u8 {
        // Get public key and create single-sig verification script
        const private_key = try self.getPrivateKeyUnsafe();
        const public_key = try private_key.getPublicKey(true);
        
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
};

/// Contract information (converted from Swift contract data)
pub const ContractInfo = struct {
    script: []const u8,
    parameters: []const ContractParameterType,
    deployed: bool,
    
    const Self = @This();
    
    pub fn init(script: []const u8, parameters: []const ContractParameterType, deployed: bool) Self {
        return Self{
            .script = script,
            .parameters = parameters,
            .deployed = deployed,
        };
    }
    
    pub fn deinit(self: *Self) void {
        // Cleanup would happen here if needed
        _ = self;
    }
};

// Import after definitions to avoid circular dependencies
const ContractParameterType = @import("../types/contract_parameter.zig").ContractParameterType;

// Tests (converted from Swift WalletTests)
test "Wallet creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = Wallet.init(allocator);
    defer wallet.deinit();
    
    // Test default properties (matches Swift tests)
    try testing.expectEqualStrings(Wallet.DEFAULT_WALLET_NAME, wallet.getName());
    try testing.expectEqualStrings(Wallet.CURRENT_VERSION, wallet.getVersion());
    
    // Test name and version setting (matches Swift builder pattern)
    _ = wallet.name("Test Wallet").version("3.1");
    try testing.expectEqualStrings("Test Wallet", wallet.getName());
    try testing.expectEqualStrings("3.1", wallet.getVersion());
}

test "Wallet account management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = Wallet.init(allocator);
    defer wallet.deinit();
    
    try testing.expectEqual(@as(u32, 0), wallet.getAccountCount());
    try testing.expect(wallet.getDefaultAccount() == null);
}

test "Wallet account lookup and removal" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = Wallet.init(allocator);
    defer wallet.deinit();
    try testing.expect(wallet.getAccount(Hash160.ZERO) == null);
    try testing.expectError(errors.WalletError.AccountNotFound, wallet.removeAccountByHash(Hash160.ZERO));
}

test "ScryptParams configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = Wallet.init(allocator);
    defer wallet.deinit();
    
    // Test default scrypt params (matches Swift .DEFAULT)
    const default_params = wallet.getScryptParams();
    try testing.expectEqual(@as(u32, 16384), default_params.n);
    try testing.expectEqual(@as(u32, 8), default_params.r);
    try testing.expectEqual(@as(u32, 8), default_params.p);
    
    // Test custom scrypt params (matches Swift scryptParams method)
    const custom_params = ScryptParams.init(1024, 4, 4);
    _ = wallet.scryptParams(custom_params);
    
    const updated_params = wallet.getScryptParams();
    try testing.expectEqual(@as(u32, 1024), updated_params.n);
    try testing.expectEqual(@as(u32, 4), updated_params.r);
    try testing.expectEqual(@as(u32, 4), updated_params.p);
}
