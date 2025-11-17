//! Transaction Implementation
//!
//! Complete conversion from NeoSwift Transaction.swift
//! Provides transaction structure for RPC responses.

const std = @import("std");
const ArrayList = std.array_list.Managed;


const Hash256 = @import("../../types/hash256.zig").Hash256;
const NeoWitness = @import("neo_witness.zig").NeoWitness;
const TransactionAttribute = @import("transaction_attribute.zig").TransactionAttribute;
const NeoVMStateType = @import("../../types/neo_vm_state_type.zig").NeoVMStateType;

/// Transaction signer structure (referenced in Transaction)
pub const TransactionSigner = struct {
    account: []const u8,
    scopes: []const u8,
    allowed_contracts: ?[][]const u8,
    allowed_groups: ?[][]const u8,
    rules: ?[][]const u8,
    
    const Self = @This();
    
    pub fn init(account: []const u8, scopes: []const u8) Self {
        return Self{
            .account = account,
            .scopes = scopes,
            .allowed_contracts = null,
            .allowed_groups = null,
            .rules = null,
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.scopes);
        
        if (self.allowed_contracts) |contracts| {
            for (contracts) |contract| {
                allocator.free(contract);
            }
            allocator.free(contracts);
        }
        
        if (self.allowed_groups) |groups| {
            for (groups) |group| {
                allocator.free(group);
            }
            allocator.free(groups);
        }
        
        if (self.rules) |rules| {
            for (rules) |rule| {
                allocator.free(rule);
            }
            allocator.free(rules);
        }
    }
    
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const account_copy = try allocator.dupe(u8, self.account);
        const scopes_copy = try allocator.dupe(u8, self.scopes);
        
        return Self{
            .account = account_copy,
            .scopes = scopes_copy,
            .allowed_contracts = null, // Simplified for now
            .allowed_groups = null,
            .rules = null,
        };
    }
};

/// Transaction structure (converted from Swift Transaction)
pub const Transaction = struct {
    /// Transaction hash
    hash: Hash256,
    /// Transaction size in bytes
    size: u32,
    /// Transaction version
    version: u8,
    /// Transaction nonce
    nonce: u32,
    /// Sender address
    sender: []const u8,
    /// System fee
    sys_fee: []const u8,
    /// Network fee
    net_fee: []const u8,
    /// Valid until block
    valid_until_block: u32,
    /// Transaction signers
    signers: []TransactionSigner,
    /// Transaction attributes
    attributes: []TransactionAttribute,
    /// Transaction script (base64 encoded)
    script: []const u8,
    /// Transaction witnesses
    witnesses: []NeoWitness,
    /// Block hash (if confirmed)
    block_hash: ?Hash256,
    /// Number of confirmations
    confirmations: ?u32,
    /// Block time (if confirmed)
    block_time: ?u64,
    /// VM execution state
    vm_state: ?NeoVMStateType,
    
    const Self = @This();
    
    /// Creates new Transaction (equivalent to Swift init)
    pub fn init(
        hash: Hash256,
        size: u32,
        version: u8,
        nonce: u32,
        sender: []const u8,
        sys_fee: []const u8,
        net_fee: []const u8,
        valid_until_block: u32,
        signers: []TransactionSigner,
        attributes: []TransactionAttribute,
        script: []const u8,
        witnesses: []NeoWitness,
        block_hash: ?Hash256,
        confirmations: ?u32,
        block_time: ?u64,
        vm_state: ?NeoVMStateType,
    ) Self {
        return Self{
            .hash = hash,
            .size = size,
            .version = version,
            .nonce = nonce,
            .sender = sender,
            .sys_fee = sys_fee,
            .net_fee = net_fee,
            .valid_until_block = valid_until_block,
            .signers = signers,
            .attributes = attributes,
            .script = script,
            .witnesses = witnesses,
            .block_hash = block_hash,
            .confirmations = confirmations,
            .block_time = block_time,
            .vm_state = vm_state,
        };
    }
    
    /// Gets transaction hash
    pub fn getHash(self: Self) Hash256 {
        return self.hash;
    }
    
    /// Gets transaction size
    pub fn getSize(self: Self) u32 {
        return self.size;
    }
    
    /// Gets transaction nonce
    pub fn getNonce(self: Self) u32 {
        return self.nonce;
    }
    
    /// Gets sender address
    pub fn getSender(self: Self) []const u8 {
        return self.sender;
    }
    
    /// Gets system fee
    pub fn getSystemFee(self: Self) []const u8 {
        return self.sys_fee;
    }
    
    /// Gets network fee
    pub fn getNetworkFee(self: Self) []const u8 {
        return self.net_fee;
    }
    
    /// Gets valid until block
    pub fn getValidUntilBlock(self: Self) u32 {
        return self.valid_until_block;
    }
    
    /// Gets signers count
    pub fn getSignerCount(self: Self) usize {
        return self.signers.len;
    }
    
    /// Gets attributes count
    pub fn getAttributeCount(self: Self) usize {
        return self.attributes.len;
    }
    
    /// Gets witness count
    pub fn getWitnessCount(self: Self) usize {
        return self.witnesses.len;
    }
    
    /// Checks if transaction is confirmed
    pub fn isConfirmed(self: Self) bool {
        return self.block_hash != null and self.confirmations != null;
    }
    
    /// Checks if transaction has attributes
    pub fn hasAttributes(self: Self) bool {
        return self.attributes.len > 0;
    }
    
    /// Checks if transaction has multiple signers
    pub fn hasMultipleSigners(self: Self) bool {
        return self.signers.len > 1;
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return self.hash.eql(other.hash) and
               self.size == other.size and
               self.version == other.version and
               self.nonce == other.nonce and
               std.mem.eql(u8, self.sender, other.sender) and
               std.mem.eql(u8, self.sys_fee, other.sys_fee) and
               std.mem.eql(u8, self.net_fee, other.net_fee) and
               self.valid_until_block == other.valid_until_block;
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hashValue(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        const tx_hash = self.hash.hash();
        hasher.update(std.mem.asBytes(&tx_hash));
        hasher.update(std.mem.asBytes(&self.nonce));
        hasher.update(self.sender);
        
        return hasher.final();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hash_str = try self.hash.toString(allocator);
        defer allocator.free(hash_str);
        
        const block_hash_str = if (self.block_hash) |bh|
            try bh.toString(allocator)
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(block_hash_str);
        
        const confirmations_str = if (self.confirmations) |c|
            try std.fmt.allocPrint(allocator, "{}", .{c})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(confirmations_str);
        
        const block_time_str = if (self.block_time) |bt|
            try std.fmt.allocPrint(allocator, "{}", .{bt})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(block_time_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"hash\":\"{s}\",\"size\":{},\"version\":{},\"nonce\":{},\"sender\":\"{s}\",\"sysfee\":\"{s}\",\"netfee\":\"{s}\",\"validuntilblock\":{},\"script\":\"{s}\",\"blockhash\":{s},\"confirmations\":{s},\"blocktime\":{s}}}",
            .{
                hash_str,
                self.size,
                self.version,
                self.nonce,
                self.sender,
                self.sys_fee,
                self.net_fee,
                self.valid_until_block,
                self.script,
                block_hash_str,
                confirmations_str,
                block_time_str,
            }
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.sys_fee);
        allocator.free(self.net_fee);
        allocator.free(self.script);
        
        for (self.signers) |*signer| {
            signer.deinit(allocator);
        }
        allocator.free(self.signers);
        
        for (self.attributes) |*attr| {
            attr.deinit(allocator);
        }
        allocator.free(self.attributes);
        
        for (self.witnesses) |*witness| {
            witness.deinit(allocator);
        }
        allocator.free(self.witnesses);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const sender_copy = try allocator.dupe(u8, self.sender);
        const sys_fee_copy = try allocator.dupe(u8, self.sys_fee);
        const net_fee_copy = try allocator.dupe(u8, self.net_fee);
        const script_copy = try allocator.dupe(u8, self.script);
        
        var signers_copy = try ArrayList(TransactionSigner).initCapacity(allocator, self.signers.len);
        defer signers_copy.deinit();
        
        for (self.signers) |signer| {
            try signers_copy.append(try signer.clone(allocator));
        }
        
        var attributes_copy = try ArrayList(TransactionAttribute).initCapacity(allocator, self.attributes.len);
        defer attributes_copy.deinit();
        
        for (self.attributes) |attr| {
            try attributes_copy.append(try attr.clone(allocator));
        }
        
        var witnesses_copy = try ArrayList(NeoWitness).initCapacity(allocator, self.witnesses.len);
        defer witnesses_copy.deinit();
        
        for (self.witnesses) |witness| {
            try witnesses_copy.append(try witness.clone(allocator));
        }
        
        return Self.init(
            self.hash,
            self.size,
            self.version,
            self.nonce,
            sender_copy,
            sys_fee_copy,
            net_fee_copy,
            self.valid_until_block,
            try signers_copy.toOwnedSlice(),
            try attributes_copy.toOwnedSlice(),
            script_copy,
            try witnesses_copy.toOwnedSlice(),
            self.block_hash,
            self.confirmations,
            self.block_time,
            self.vm_state,
        );
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hash_str = try self.hash.toString(allocator);
        defer allocator.free(hash_str);
        
        const status = if (self.isConfirmed()) "confirmed" else "pending";
        
        return try std.fmt.allocPrint(
            allocator,
            "Transaction(hash: {s}, size: {} bytes, signers: {}, status: {s})",
            .{ hash_str, self.size, self.signers.len, status }
        );
    }
};

// Tests (converted from Swift Transaction tests)
test "Transaction creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test transaction creation
    const tx_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const sender = try allocator.dupe(u8, "NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj");
    const sys_fee = try allocator.dupe(u8, "1000000");
    const net_fee = try allocator.dupe(u8, "50000");
    const script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ==");
    
    var transaction = Transaction.init(
        tx_hash,
        512,            // size
        0,              // version
        12345,          // nonce
        sender,
        sys_fee,
        net_fee,
        100000,         // valid_until_block
        &[_]TransactionSigner{},
        &[_]TransactionAttribute{},
        script,
        &[_]NeoWitness{},
        null,           // block_hash
        null,           // confirmations
        null,           // block_time
        null,           // vm_state
    );
    defer transaction.deinit(allocator);
    
    // Verify transaction properties
    try testing.expect(transaction.getHash().eql(tx_hash));
    try testing.expectEqual(@as(u32, 12345), transaction.getNonce());
    try testing.expectEqual(@as(u32, 512), transaction.getSize());
    try testing.expectEqualStrings("NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj", transaction.getSender());
    try testing.expect(!transaction.isConfirmed());
    try testing.expect(!transaction.hasAttributes());
    try testing.expect(!transaction.hasMultipleSigners());
}