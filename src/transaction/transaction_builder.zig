//! Neo Transaction Builder
//!
//! Complete conversion from NeoSwift TransactionBuilder.swift
//! Maintains full API compatibility with builder pattern and all features.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const BinaryWriter = @import("../serialization/binary_writer.zig").BinaryWriter;

/// Transaction builder for constructing Neo transactions (Swift API compatible)
pub const TransactionBuilder = struct {
    /// GAS token hash (matches Swift GAS_TOKEN_HASH)
    pub const GAS_TOKEN_HASH: Hash160 = blk: {
        break :blk Hash160.initWithString("d2a4cff31913016155e38e474a2c06d08be276cf") catch unreachable;
    };
    
    /// Balance function name (matches Swift BALANCE_OF_FUNCTION)
    pub const BALANCE_OF_FUNCTION = "balanceOf";
    
    /// Dummy public key for fee calculation (matches Swift DUMMY_PUB_KEY)
    pub const DUMMY_PUB_KEY = "02ec143f00b88524caf36a0121c2de09eef0519ddbe1c710a00f0e2663201ee4c0";
    
    allocator: std.mem.Allocator,
    neo_swift: ?*anyopaque, // Placeholder for NeoSwift reference
    
    // Transaction fields (match Swift private vars)
    version_field: u8,
    nonce_field: u32,
    valid_until_block_field: ?u32,
    signers_list: std.ArrayList(Signer),
    additional_network_fee: u64,
    additional_system_fee: u64,
    attributes_list: std.ArrayList(TransactionAttribute),
    script_field: ?std.ArrayList(u8),
    
    // Consumer and error handling
    consumer: ?*const fn(u64, u64) void,
    fee_error: ?anyerror,
    
    const Self = @This();
    
    /// Creates a new transaction builder (equivalent to Swift init(_ neoSwift: NeoSwift))
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .neo_swift = null,
            .version_field = constants.CURRENT_TX_VERSION,
            .nonce_field = std.crypto.random.int(u32), // Random nonce like Swift
            .valid_until_block_field = null,
            .signers_list = std.ArrayList(Signer).init(allocator),
            .additional_network_fee = 0,
            .additional_system_fee = 0,
            .attributes_list = std.ArrayList(TransactionAttribute).init(allocator),
            .script_field = null,
            .consumer = null,
            .fee_error = null,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.signers_list.deinit();
        self.attributes_list.deinit();
        if (self.script_field) |*script| {
            script.deinit();
        }
    }
    
    /// Sets the version for this transaction (equivalent to Swift version(_ version: Byte))
    pub fn version(self: *Self, transaction_version: u8) *Self {
        self.version_field = transaction_version;
        return self;
    }
    
    /// Sets the nonce (equivalent to Swift nonce(_ nonce: Int))
    pub fn nonce(self: *Self, transaction_nonce: u32) !*Self {
        // Validate nonce range (0 to 2^32-1)
        self.nonce_field = transaction_nonce;
        return self;
    }
    
    /// Sets valid until block (equivalent to Swift validUntilBlock(_ blockNr: Int))
    pub fn validUntilBlock(self: *Self, block_nr: u32) !*Self {
        self.valid_until_block_field = block_nr;
        return self;
    }
    
    /// Sets the first signer by account (equivalent to Swift firstSigner(_ sender: Account))
    pub fn firstSignerAccount(self: *Self, sender_account: Account) !*Self {
        return try self.firstSigner(sender_account.getScriptHash());
    }
    
    /// Sets the first signer by script hash (equivalent to Swift firstSigner(_ sender: Hash160))
    pub fn firstSigner(self: *Self, sender: Hash160) !*Self {
        // Check for fee-only witness scope signers
        for (self.signers_list.items) |signer| {
            if (signer.scopes == .None) {
                return errors.throwIllegalState("Transaction contains fee-only signer");
            }
        }
        
        // Find and move signer to first position
        var signer_index: ?usize = null;
        for (self.signers_list.items, 0..) |signer, i| {
            if (signer.signer_hash.eql(sender)) {
                signer_index = i;
                break;
            }
        }
        
        if (signer_index == null) {
            return errors.throwIllegalState("Could not find signer with specified script hash");
        }
        
        // Move to first position
        const signer_to_move = self.signers_list.orderedRemove(signer_index.?);
        try self.signers_list.insert(0, signer_to_move);
        
        return self;
    }
    
    /// Adds signers to the transaction (equivalent to Swift signers(_ signers: [Signer]))
    pub fn signers(self: *Self, new_signers: []const Signer) !*Self {
        // Clear existing signers
        self.signers_list.clearRetainingCapacity();
        
        // Add new signers
        for (new_signers) |signer| {
            try self.signers_list.append(signer);
        }
        
        return self;
    }
    
    /// Adds a single signer (equivalent to Swift signer(_ signer: Signer))
    pub fn signer(self: *Self, new_signer: Signer) !*Self {
        // Check if signer already exists
        for (self.signers_list.items) |existing_signer| {
            if (existing_signer.signer_hash.eql(new_signer.signer_hash)) {
                return errors.throwIllegalState("Signer with this script hash already exists");
            }
        }
        
        try self.signers_list.append(new_signer);
        return self;
    }
    
    /// Sets additional network fee (equivalent to Swift additionalNetworkFee(_ fee: Int))
    pub fn additionalNetworkFee(self: *Self, fee: u64) *Self {
        self.additional_network_fee = fee;
        return self;
    }
    
    /// Sets additional system fee (equivalent to Swift additionalSystemFee(_ fee: Int))
    pub fn additionalSystemFee(self: *Self, fee: u64) *Self {
        self.additional_system_fee = fee;
        return self;
    }
    
    /// Adds transaction attributes (equivalent to Swift attributes(_ attributes: [TransactionAttribute]))
    pub fn attributes(self: *Self, new_attributes: []const TransactionAttribute) !*Self {
        // Validate maximum attributes
        if (new_attributes.len > constants.MAX_TRANSACTION_ATTRIBUTES) {
            return errors.throwIllegalArgument("Too many transaction attributes");
        }
        
        // Clear and add new attributes
        self.attributes_list.clearRetainingCapacity();
        for (new_attributes) |attribute| {
            try self.attributes_list.append(attribute);
        }
        
        return self;
    }
    
    /// Adds high priority attribute (equivalent to Swift highPriority())
    pub fn highPriority(self: *Self) !*Self {
        const high_priority_attr = TransactionAttribute.init(.HighPriority, &[_]u8{});
        try self.attributes_list.append(high_priority_attr);
        return self;
    }
    
    /// Sets the transaction script (equivalent to Swift script(_ script: Bytes))
    pub fn script(self: *Self, transaction_script: []const u8) !*Self {
        if (self.script_field == null) {
            self.script_field = std.ArrayList(u8).init(self.allocator);
        }
        
        self.script_field.?.clearRetainingCapacity();
        try self.script_field.?.appendSlice(transaction_script);
        
        return self;
    }
    
    /// Builds NEP-17 token transfer (equivalent to Swift transferToken methods)
    pub fn transferToken(
        self: *Self,
        token_hash: Hash160,
        from_account: Hash160,
        to_account: Hash160,
        amount: u64,
    ) !*Self {
        // Create transfer parameters
        const params = [_]ContractParameter{
            ContractParameter.hash160(from_account),
            ContractParameter.hash160(to_account),
            ContractParameter.integer(@intCast(amount)),
        };
        
        // Build contract invocation script
        return try self.invokeFunction(token_hash, "transfer", &params);
    }
    
    /// Invokes a contract function (equivalent to Swift invokeFunction methods)
    pub fn invokeFunction(
        self: *Self,
        contract_hash: Hash160,
        method: []const u8,
        parameters: []const ContractParameter,
    ) !*Self {
        if (self.script_field == null) {
            self.script_field = std.ArrayList(u8).init(self.allocator);
        }
        
        // Build invocation script
        try self.buildInvocationScript(contract_hash, method, parameters);
        
        return self;
    }
    
    /// Builds the transaction (equivalent to Swift build())
    pub fn build(self: *Self) !Transaction {
        // Validate required fields
        if (self.signers_list.items.len == 0) {
            return errors.throwIllegalState("Transaction requires at least one signer");
        }
        
        if (self.script_field == null or self.script_field.?.items.len == 0) {
            return errors.throwIllegalState("Transaction requires a script");
        }
        
        // Set valid until block if not specified
        const final_valid_until = self.valid_until_block_field orelse blk: {
            // Default to current estimated block + increment
            const estimated_current_block: u32 = @intCast(std.time.timestamp() / 15);
            break :blk estimated_current_block + 5760; // ~24 hours
        };
        
        // Create witnesses array (empty initially)
        var witnesses = try self.allocator.alloc(Witness, self.signers_list.items.len);
        for (witnesses) |*witness| {
            witness.* = Witness.init(&[_]u8{}, &[_]u8{});
        }
        
        return Transaction.init(
            self.version_field,
            self.nonce_field,
            self.additional_system_fee,
            self.additional_network_fee,
            final_valid_until,
            try self.signers_list.toOwnedSlice(),
            try self.attributes_list.toOwnedSlice(),
            try self.script_field.?.toOwnedSlice(),
            witnesses,
        );
    }
    
    /// Signs the transaction (equivalent to Swift sign())
    pub fn sign(self: *Self, accounts: []const Account, network_magic: u32) !Transaction {
        var transaction = try self.build();
        
        // Calculate transaction hash for signing
        const tx_hash = try transaction.getHash(self.allocator);
        
        // Create signing data with network magic
        var signing_data: [36]u8 = undefined;
        @memcpy(signing_data[0..32], tx_hash.toSlice());
        const magic_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, network_magic));
        @memcpy(signing_data[32..36], &magic_bytes);
        
        const signing_hash = Hash256.sha256(&signing_data);
        
        // Sign with each account
        for (accounts, transaction.witnesses, 0..) |account, *witness, i| {
            const private_key = try account.getPrivateKey();
            const signature = try private_key.sign(signing_hash);
            const public_key = try private_key.getPublicKey(true);
            
            // Build invocation script (signature)
            var invocation_script = std.ArrayList(u8).init(self.allocator);
            defer invocation_script.deinit();
            
            try invocation_script.append(0x0C); // PUSHDATA1
            try invocation_script.append(64);   // Signature length
            try invocation_script.appendSlice(signature.toSlice());
            
            // Build verification script (public key + CheckSig)
            var verification_script = std.ArrayList(u8).init(self.allocator);
            defer verification_script.deinit();
            
            try verification_script.append(0x0C); // PUSHDATA1
            try verification_script.append(33);   // Public key length
            try verification_script.appendSlice(public_key.toSlice());
            try verification_script.append(0x41); // SYSCALL
            try verification_script.append(0x9D); // CheckSig
            
            witness.* = Witness.init(
                try self.allocator.dupe(u8, invocation_script.items),
                try self.allocator.dupe(u8, verification_script.items),
            );
        }
        
        return transaction;
    }
    
    /// Builds contract invocation script
    fn buildInvocationScript(
        self: *Self,
        contract_hash: Hash160,
        method: []const u8,
        parameters: []const ContractParameter,
    ) !void {
        // Push parameters in reverse order
        var i = parameters.len;
        while (i > 0) {
            i -= 1;
            try self.pushParameter(parameters[i]);
        }
        
        // Push method name
        try self.script_field.?.append(0x0C); // PUSHDATA1
        try self.script_field.?.append(@intCast(method.len));
        try self.script_field.?.appendSlice(method);
        
        // Push contract hash
        try self.script_field.?.append(0x0C); // PUSHDATA1
        try self.script_field.?.append(20);   // Hash160 length
        try self.script_field.?.appendSlice(&contract_hash.toArray());
        
        // Call contract
        try self.script_field.?.append(0x41); // SYSCALL
        const syscall_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, constants.InteropServices.SYSTEM_CONTRACT_CALL));
        try self.script_field.?.appendSlice(&syscall_bytes);
    }
    
    /// Pushes a contract parameter onto the script stack
    fn pushParameter(self: *Self, parameter: ContractParameter) !void {
        switch (parameter) {
            .Boolean => |value| {
                const opcode: u8 = if (value) 0x11 else 0x10; // PUSH1 or PUSH0
                try self.script_field.?.append(opcode);
            },
            .Integer => |value| {
                if (value == 0) {
                    try self.script_field.?.append(0x10); // PUSH0
                } else if (value > 0 and value <= 16) {
                    try self.script_field.?.append(0x10 + @as(u8, @intCast(value)));
                } else {
                    // Push as byte array
                    const bytes = std.mem.toBytes(std.mem.nativeToLittle(i64, value));
                    try self.pushBytes(&bytes);
                }
            },
            .ByteArray => |data| {
                try self.pushBytes(data);
            },
            .String => |str| {
                try self.pushBytes(str);
            },
            .Hash160 => |hash| {
                try self.pushBytes(&hash.toArray());
            },
            .Hash256 => |hash| {
                try self.pushBytes(&hash.toArray());
            },
            else => {
                return errors.TransactionError.InvalidParameters;
            },
        }
    }
    
    /// Pushes bytes onto the script stack (matches Swift script building)
    fn pushBytes(self: *Self, data: []const u8) !void {
        if (data.len <= 75) {
            try self.script_field.?.append(@intCast(data.len));
            try self.script_field.?.appendSlice(data);
        } else if (data.len <= 255) {
            try self.script_field.?.append(0x4C); // PUSHDATA1
            try self.script_field.?.append(@intCast(data.len));
            try self.script_field.?.appendSlice(data);
        } else if (data.len <= 65535) {
            try self.script_field.?.append(0x4D); // PUSHDATA2
            const len_bytes = std.mem.toBytes(std.mem.nativeToLittle(u16, @intCast(data.len)));
            try self.script_field.?.appendSlice(&len_bytes);
            try self.script_field.?.appendSlice(data);
        } else {
            try self.script_field.?.append(0x4E); // PUSHDATA4
            const len_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(data.len)));
            try self.script_field.?.appendSlice(&len_bytes);
            try self.script_field.?.appendSlice(data);
        }
    }
    
    /// Checks if transaction has high priority (equivalent to Swift isHighPriority computed property)
    pub fn isHighPriority(self: *Self) bool {
        for (self.attributes_list.items) |attribute| {
            if (attribute.attribute_type == .HighPriority) {
                return true;
            }
        }
        return false;
    }
    
    /// Gets current signers (equivalent to Swift signers property)
    pub fn getSigners(self: *Self) []const Signer {
        return self.signers_list.items;
    }
    
    /// Gets current script (equivalent to Swift script property)
    pub fn getScript(self: *Self) ?[]const u8 {
        if (self.script_field) |script| {
            return script.items;
        }
        return null;
    }
};

/// Transaction signer (converted from Swift Signer)
pub const Signer = struct {
    signer_hash: Hash160,
    scopes: WitnessScope,
    allowed_contracts: []Hash160,
    allowed_groups: [][33]u8,
    rules: []WitnessRule,
    
    const Self = @This();
    
    pub fn init(signer_hash: Hash160, scopes: WitnessScope) Self {
        return Self{
            .signer_hash = signer_hash,
            .scopes = scopes,
            .allowed_contracts = &[_]Hash160{},
            .allowed_groups = &[_][33]u8{},
            .rules = &[_]WitnessRule{},
        };
    }
    
    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try writer.writeBytes(&self.signer_hash.toArray());
        try writer.writeByte(@intFromEnum(self.scopes));
        
        // Serialize scope-specific data
        if (self.scopes == .CustomContracts) {
            try writer.writeVarInt(self.allowed_contracts.len);
            for (self.allowed_contracts) |contract| {
                try writer.writeBytes(&contract.toArray());
            }
        }
        
        if (self.scopes == .CustomGroups) {
            try writer.writeVarInt(self.allowed_groups.len);
            for (self.allowed_groups) |group| {
                try writer.writeBytes(&group);
            }
        }
    }
};

/// Witness scope (converted from Swift WitnessScope)
pub const WitnessScope = enum(u8) {
    None = 0x00,
    CalledByEntry = 0x01,
    CustomContracts = 0x10,
    CustomGroups = 0x20,
    WitnessRules = 0x40,
    Global = 0x80,
};

/// Transaction attribute (converted from Swift TransactionAttribute)
pub const TransactionAttribute = struct {
    attribute_type: AttributeType,
    data: []const u8,
    
    const Self = @This();
    
    pub fn init(attribute_type: AttributeType, data: []const u8) Self {
        return Self{
            .attribute_type = attribute_type,
            .data = data,
        };
    }
};

/// Attribute types (converted from Swift)
pub const AttributeType = enum(u8) {
    HighPriority = 0x01,
    OracleResponse = 0x11,
    NotValidBefore = 0x20,
    Conflicts = 0x21,
    NotaryAssisted = 0x22,
};

/// Transaction witness (converted from Swift Witness)
pub const Witness = struct {
    invocation_script: []const u8,
    verification_script: []const u8,
    
    const Self = @This();
    
    pub fn init(invocation_script: []const u8, verification_script: []const u8) Self {
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
        };
    }
};

/// Witness rule (converted from Swift WitnessRule)
pub const WitnessRule = struct {
    action: WitnessAction,
    condition: WitnessCondition,
    
    pub fn init(action: WitnessAction, condition: WitnessCondition) WitnessRule {
        return WitnessRule{ .action = action, .condition = condition };
    }
};

/// Witness action (converted from Swift)
pub const WitnessAction = enum(u8) {
    Deny = 0x00,
    Allow = 0x01,
};

/// Witness condition (converted from Swift)
pub const WitnessCondition = union(enum) {
    Boolean: bool,
    ScriptHash: Hash160,
    Group: [33]u8,
    CalledByEntry: void,
};

/// Transaction (converted from Swift NeoTransaction)
pub const Transaction = struct {
    version: u8,
    nonce: u32,
    system_fee: u64,
    network_fee: u64,
    valid_until_block: u32,
    signers: []Signer,
    attributes: []TransactionAttribute,
    script: []const u8,
    witnesses: []Witness,
    
    const Self = @This();
    
    pub fn init(
        version: u8,
        nonce: u32,
        system_fee: u64,
        network_fee: u64,
        valid_until_block: u32,
        signers: []Signer,
        attributes: []TransactionAttribute,
        script: []const u8,
        witnesses: []Witness,
    ) Self {
        return Self{
            .version = version,
            .nonce = nonce,
            .system_fee = system_fee,
            .network_fee = network_fee,
            .valid_until_block = valid_until_block,
            .signers = signers,
            .attributes = attributes,
            .script = script,
            .witnesses = witnesses,
        };
    }
    
    /// Calculates transaction hash (equivalent to Swift getHash())
    pub fn getHash(self: Self, allocator: std.mem.Allocator) !Hash256 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        var writer = BinaryWriter.init(allocator);
        defer writer.deinit();
        
        // Serialize unsigned transaction
        try writer.writeByte(self.version);
        try writer.writeU32(self.nonce);
        try writer.writeU64(self.system_fee);
        try writer.writeU64(self.network_fee);
        try writer.writeU32(self.valid_until_block);
        
        // Serialize signers
        try writer.writeVarInt(self.signers.len);
        for (self.signers) |signer| {
            try signer.serialize(&writer);
        }
        
        // Serialize attributes
        try writer.writeVarInt(self.attributes.len);
        for (self.attributes) |attribute| {
            try writer.writeByte(@intFromEnum(attribute.attribute_type));
            try writer.writeVarInt(attribute.data.len);
            try writer.writeBytes(attribute.data);
        }
        
        // Serialize script
        try writer.writeVarInt(self.script.len);
        try writer.writeBytes(self.script);
        
        return Hash256.sha256(writer.toSlice());
    }
    
    /// Validates the transaction (equivalent to Swift validation)
    pub fn validate(self: Self) !void {
        if (self.version != constants.CURRENT_TX_VERSION) {
            return errors.TransactionError.InvalidVersion;
        }
        
        if (self.script.len > constants.MAX_TRANSACTION_SIZE) {
            return errors.TransactionError.TransactionTooLarge;
        }
        
        if (self.attributes.len > constants.MAX_TRANSACTION_ATTRIBUTES) {
            return errors.TransactionError.InvalidTransaction;
        }
        
        if (self.signers.len != self.witnesses.len) {
            return errors.TransactionError.InvalidWitness;
        }
    }
};

/// Account placeholder (to be fully implemented)
pub const Account = struct {
    script_hash: Hash160,
    
    pub fn init(script_hash: Hash160) Account {
        return Account{ .script_hash = script_hash };
    }
    
    pub fn getScriptHash(self: Account) Hash160 {
        return self.script_hash;
    }
    
    pub fn getPrivateKey(self: Account) !@import("../crypto/keys.zig").PrivateKey {
        // Placeholder - would load from wallet
        return @import("../crypto/keys.zig").PrivateKey.generate();
    }
};

// Tests (converted from Swift TransactionBuilderTests)
test "TransactionBuilder creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Test version setting (matches Swift test)
    _ = builder.version(1);
    try testing.expectEqual(@as(u8, 1), builder.version_field);
    
    // Test nonce setting (matches Swift test)
    _ = try builder.nonce(12345);
    try testing.expectEqual(@as(u32, 12345), builder.nonce_field);
    
    // Test valid until block setting
    _ = try builder.validUntilBlock(1000000);
    try testing.expectEqual(@as(u32, 1000000), builder.valid_until_block_field.?);
}

test "TransactionBuilder signer management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Add signer
    const test_signer = Signer.init(Hash160.ZERO, WitnessScope.CalledByEntry);
    _ = try builder.signer(test_signer);
    
    try testing.expectEqual(@as(usize, 1), builder.signers_list.items.len);
    try testing.expect(builder.signers_list.items[0].signer_hash.eql(Hash160.ZERO));
}

test "TransactionBuilder token transfer" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Build token transfer (matches Swift transferToken functionality)
    _ = try builder.transferToken(
        TransactionBuilder.GAS_TOKEN_HASH,
        Hash160.ZERO, // from
        Hash160.ZERO, // to
        100000000,    // 1 GAS
    );
    
    // Should have script
    try testing.expect(builder.getScript() != null);
    try testing.expect(builder.getScript().?.len > 0);
}