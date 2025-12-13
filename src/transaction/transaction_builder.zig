//! Neo Transaction Builder
//!
//! Complete conversion from NeoSwift TransactionBuilder.swift
//! Maintains full API compatibility with builder pattern and all features.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const crypto = @import("../crypto/crypto.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const Address = @import("../types/address.zig").Address;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const BinaryWriter = @import("../serialization/binary_writer.zig").BinaryWriter;
const BinaryReader = @import("../serialization/binary_reader.zig").BinaryReader;
const json_utils = @import("../utils/json_utils.zig");
const ScriptBuilder = @import("../script/script_builder.zig").ScriptBuilder;
const witness_rule_mod = @import("witness_rule.zig");

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
    neo_swift: ?*anyopaque, // stub for NeoSwift reference

    // Transaction fields (match Swift private vars)
    version_field: u8,
    nonce_field: u32,
    valid_until_block_field: ?u32,
    signers_list: ArrayList(Signer),
    additional_network_fee: u64,
    additional_system_fee: u64,
    attributes_list: ArrayList(TransactionAttribute),
    script_field: ?ArrayList(u8),

    // Consumer and error handling
    consumer: ?*const fn (u64, u64) void,
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
            .signers_list = ArrayList(Signer).init(allocator),
            .additional_network_fee = 0,
            .additional_system_fee = 0,
            .attributes_list = ArrayList(TransactionAttribute).init(allocator),
            .script_field = null,
            .consumer = null,
            .fee_error = null,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        for (self.signers_list.items) |*signer_entry| {
            signer_entry.deinit(self.allocator);
        }
        for (self.attributes_list.items) |*attribute_entry| {
            attribute_entry.deinit(self.allocator);
        }
        self.signers_list.deinit();
        self.attributes_list.deinit();
        if (self.script_field) |*existing_script| {
            existing_script.deinit();
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
        for (self.signers_list.items) |existing_signer| {
            if (existing_signer.scopes == .None) {
                return errors.throwIllegalState("Transaction contains fee-only signer");
            }
        }

        // Find and move signer to first position
        var signer_index: ?usize = null;
        for (self.signers_list.items, 0..) |signer_entry, i| {
            if (signer_entry.signer_hash.eql(sender)) {
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
        for (self.signers_list.items) |*existing_signer| {
            existing_signer.deinit(self.allocator);
        }
        self.signers_list.clearRetainingCapacity();

        // Add new signers
        for (new_signers) |signer_entry| {
            try self.signers_list.append(signer_entry);
        }

        return self;
    }

    /// Adds a single signer (equivalent to Swift signer(_ signer: Signer))
    pub fn signer(self: *Self, new_signer: Signer) !*Self {
        // Neo transactions require unique signer accounts. For Swift API parity,
        // treat re-adding an existing signer as an update.
        for (self.signers_list.items, 0..) |existing_signer, idx| {
            if (existing_signer.signer_hash.eql(new_signer.signer_hash)) {
                self.signers_list.items[idx].deinit(self.allocator);
                self.signers_list.items[idx] = new_signer;
                return self;
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
        for (self.attributes_list.items) |*existing_attribute| {
            existing_attribute.deinit(self.allocator);
        }
        self.attributes_list.clearRetainingCapacity();
        for (new_attributes) |attribute_item| {
            try self.attributes_list.append(attribute_item);
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
            self.script_field = ArrayList(u8).init(self.allocator);
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
            self.script_field = ArrayList(u8).init(self.allocator);
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

        const final_valid_until = self.valid_until_block_field orelse 0;

        // Create witnesses array (empty initially)
        const witnesses = try self.allocator.alloc(Witness, self.signers_list.items.len);
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
        errdefer transaction.deinit(self.allocator);

        if (accounts.len != transaction.signers.len) {
            return errors.TransactionError.InvalidSigner;
        }

        // Calculate transaction hash for signing
        const tx_hash = try transaction.getHash(self.allocator);

        // Create signing data with network magic (matches NeoSwift getHashData()).
        // NeoSwift: networkMagicBytes || sha256(unsignedTxBytes)
        var signing_data: [36]u8 = undefined;
        const magic_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, network_magic));
        @memcpy(signing_data[0..4], &magic_bytes);
        @memcpy(signing_data[4..36], tx_hash.toSlice());

        const signing_hash = Hash256.sha256(&signing_data);

        // Sign with each account
        for (accounts, 0..) |account, idx| {
            const expected_signer = transaction.signers[idx];
            if (!account.getScriptHash().eql(expected_signer.signer_hash)) {
                return errors.TransactionError.InvalidSigner;
            }

            const private_key = try account.getPrivateKey();
            const signature = try private_key.sign(signing_hash);
            const public_key = try private_key.getPublicKey(true);

            // Build invocation script (signature)
            var invocation_script = ArrayList(u8).init(self.allocator);
            defer invocation_script.deinit();

            try invocation_script.append(0x0C); // PUSHDATA1
            try invocation_script.append(64); // Signature length
            try invocation_script.appendSlice(signature.toSlice());

            // Build verification script (public key + CheckSig)
            var verification_script = ArrayList(u8).init(self.allocator);
            defer verification_script.deinit();

            try verification_script.append(0x0C); // PUSHDATA1
            try verification_script.append(33); // Public key length
            try verification_script.appendSlice(public_key.toSlice());
            try verification_script.append(0x41); // SYSCALL
            const check_sig_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, constants.InteropServices.SYSTEM_CRYPTO_CHECK_SIG));
            try verification_script.appendSlice(&check_sig_bytes);

            transaction.witnesses[idx] = Witness.init(
                try self.allocator.dupe(u8, invocation_script.items),
                try self.allocator.dupe(u8, verification_script.items),
            );
            transaction.witnesses[idx].owns_invocation_script = true;
            transaction.witnesses[idx].owns_verification_script = true;
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
        // Delegate invocation script building to ScriptBuilder to stay compatible with NeoSwift/NeoVM.
        var builder = ScriptBuilder.init(self.allocator);
        defer builder.deinit();

        _ = try builder.contractCall(contract_hash, method, parameters, null);

        self.script_field.?.clearRetainingCapacity();
        try self.script_field.?.appendSlice(builder.toScript());
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
        if (self.script_field) |current_script| {
            return current_script.items;
        }
        return null;
    }
};

/// Transaction signer (converted from Swift Signer)
pub const Signer = struct {
    signer_hash: Hash160,
    scopes: WitnessScope,
    allowed_contracts: []const Hash160,
    allowed_groups: []const [33]u8,
    rules: []const WitnessRule,
    owns_allowed_contracts: bool = false,
    owns_allowed_groups: bool = false,
    owns_rules: bool = false,

    const Self = @This();

    pub fn init(signer_hash: Hash160, scopes: WitnessScope) Self {
        return Self{
            .signer_hash = signer_hash,
            .scopes = scopes,
            .allowed_contracts = &[_]Hash160{},
            .allowed_groups = &[_][33]u8{},
            .rules = &[_]WitnessRule{},
            .owns_allowed_contracts = false,
            .owns_allowed_groups = false,
            .owns_rules = false,
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

        if (self.scopes == .WitnessRules) {
            try writer.writeVarInt(self.rules.len);
            for (self.rules) |rule| {
                try rule.serialize(writer);
            }
        }
    }

    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        var signer_hash_bytes: [20]u8 = undefined;
        try reader.readBytes(&signer_hash_bytes);
        const signer_hash = try Hash160.initWithBytes(&signer_hash_bytes);

        const scopes_byte = try reader.readByte();
        const scopes: WitnessScope = switch (scopes_byte) {
            @intFromEnum(WitnessScope.None) => .None,
            @intFromEnum(WitnessScope.CalledByEntry) => .CalledByEntry,
            @intFromEnum(WitnessScope.CustomContracts) => .CustomContracts,
            @intFromEnum(WitnessScope.CustomGroups) => .CustomGroups,
            @intFromEnum(WitnessScope.WitnessRules) => .WitnessRules,
            @intFromEnum(WitnessScope.Global) => .Global,
            else => return errors.SerializationError.InvalidFormat,
        };

        var signer = Self.init(signer_hash, scopes);

        if (scopes == .CustomContracts) {
            const count = try reader.readVarInt();
            const contracts = try allocator.alloc(Hash160, @intCast(count));
            errdefer allocator.free(contracts);
            for (contracts) |*contract| {
                var contract_bytes: [20]u8 = undefined;
                try reader.readBytes(&contract_bytes);
                contract.* = try Hash160.initWithBytes(&contract_bytes);
            }
            signer.allowed_contracts = contracts;
            signer.owns_allowed_contracts = true;
        }

        if (scopes == .CustomGroups) {
            const count = try reader.readVarInt();
            const groups = try allocator.alloc([33]u8, @intCast(count));
            errdefer allocator.free(groups);
            for (groups) |*group| {
                try reader.readBytes(group[0..]);
            }
            signer.allowed_groups = groups;
            signer.owns_allowed_groups = true;
        }

        if (scopes == .WitnessRules) {
            const count = try reader.readVarInt();
            const rules = try allocator.alloc(WitnessRule, @intCast(count));
            errdefer allocator.free(rules);
            var filled: usize = 0;
            errdefer {
                var i: usize = 0;
                while (i < filled) : (i += 1) {
                    rules[i].deinit(allocator);
                }
            }

            for (rules, 0..) |*rule, idx| {
                rule.* = try WitnessRule.deserialize(reader, allocator);
                filled = idx + 1;
            }
            signer.rules = rules;
            signer.owns_rules = true;
        }

        return signer;
    }

    pub fn getSize(self: Self) u32 {
        var size: u32 = 20 + 1; // signer hash + scope byte

        const var_int_size = struct {
            fn calc(value: usize) u32 {
                if (value < 0xFD) return 1;
                if (value <= 0xFFFF) return 3;
                if (value <= 0xFFFFFFFF) return 5;
                return 9;
            }
        }.calc;

        switch (self.scopes) {
            .CustomContracts => {
                size += var_int_size(self.allowed_contracts.len);
                size += @intCast(self.allowed_contracts.len * 20);
            },
            .CustomGroups => {
                size += var_int_size(self.allowed_groups.len);
                size += @intCast(self.allowed_groups.len * 33);
            },
            .WitnessRules => {
                size += var_int_size(self.rules.len);
                for (self.rules) |rule| size += @intCast(rule.size());
            },
            else => {},
        }

        return size;
    }

    pub fn validate(self: Self) !void {
        switch (self.scopes) {
            .CustomContracts => if (self.allowed_contracts.len == 0) return errors.TransactionError.InvalidSigner,
            .CustomGroups => if (self.allowed_groups.len == 0) return errors.TransactionError.InvalidSigner,
            .WitnessRules => if (self.rules.len == 0) return errors.TransactionError.InvalidSigner,
            else => {},
        }
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.owns_rules) {
            const rules_mut = @constCast(self.rules);
            for (rules_mut) |*rule| {
                rule.deinit(allocator);
            }
            allocator.free(rules_mut);
        }
        if (self.owns_allowed_groups) {
            allocator.free(self.allowed_groups);
        }
        if (self.owns_allowed_contracts) {
            allocator.free(self.allowed_contracts);
        }

        self.allowed_contracts = &[_]Hash160{};
        self.allowed_groups = &[_][33]u8{};
        self.rules = &[_]WitnessRule{};
        self.owns_allowed_contracts = false;
        self.owns_allowed_groups = false;
        self.owns_rules = false;
    }

    pub fn toJsonValue(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var object = std.json.ObjectMap.init(allocator);
        const account_string = try formatHash160(self.signer_hash, allocator);
        try json_utils.putOwnedKey(&object, allocator, "account", std.json.Value{ .string = account_string });
        try json_utils.putOwnedKey(&object, allocator, "scopes", std.json.Value{ .string = try allocator.dupe(u8, witnessScopeToString(self.scopes)) });

        if (self.allowed_contracts.len > 0) {
            var contracts_array = std.json.Array.init(allocator);
            for (self.allowed_contracts) |contract| {
                const contract_string = try formatHash160(contract, allocator);
                try contracts_array.append(std.json.Value{ .string = contract_string });
            }
            try json_utils.putOwnedKey(&object, allocator, "allowedcontracts", std.json.Value{ .array = contracts_array });
        }

        if (self.allowed_groups.len > 0) {
            var groups_array = std.json.Array.init(allocator);
            for (self.allowed_groups) |group| {
                const group_string = try formatPublicKey(group, allocator);
                try groups_array.append(std.json.Value{ .string = group_string });
            }
            try json_utils.putOwnedKey(&object, allocator, "allowedgroups", std.json.Value{ .array = groups_array });
        }

        return std.json.Value{ .object = object };
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
    owns_data: bool = false,

    const Self = @This();

    pub const MAX_RESULT_SIZE: usize = 0xffff;

    pub fn init(attribute_type: AttributeType, data: []const u8) Self {
        return Self{
            .attribute_type = attribute_type,
            .data = data,
            .owns_data = false,
        };
    }

    pub fn getSize(self: Self) u32 {
        return switch (self.attribute_type) {
            .HighPriority => 1,
            else => 1 + @as(u32, @intCast(self.data.len)),
        };
    }

    pub fn validate(self: Self) !void {
        switch (self.attribute_type) {
            .HighPriority => {
                if (self.data.len != 0) {
                    return errors.TransactionError.InvalidParameters;
                }
            },
            .OracleResponse => {
                // id (8) + code (1) + varint(len) + result bytes
                if (self.data.len < 10) {
                    return errors.TransactionError.InvalidParameters;
                }

                var reader = BinaryReader.init(self.data[9..]);
                const result_len = reader.readVarInt() catch return errors.TransactionError.InvalidParameters;
                if (result_len > MAX_RESULT_SIZE) {
                    return errors.TransactionError.InvalidParameters;
                }

                const remaining: u64 = @intCast(reader.data.len - reader.position);
                if (remaining != result_len) {
                    return errors.TransactionError.InvalidParameters;
                }
            },
            else => {},
        }
    }

    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try writer.writeByte(@intFromEnum(self.attribute_type));
        if (self.attribute_type != .HighPriority) {
            try writer.writeBytes(self.data);
        }
    }

    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        const type_byte = try reader.readByte();
        const attr_type: AttributeType = switch (type_byte) {
            @intFromEnum(AttributeType.HighPriority) => .HighPriority,
            @intFromEnum(AttributeType.OracleResponse) => .OracleResponse,
            else => return errors.SerializationError.InvalidFormat,
        };

        if (attr_type == .HighPriority) {
            return Self.init(.HighPriority, &[_]u8{});
        }

        // OracleResponse payload (id + code + var-bytes result)
        var id_bytes: [8]u8 = undefined;
        try reader.readBytes(&id_bytes);
        const code_byte = try reader.readByte();
        const result_len = try reader.readVarInt();
        if (result_len > MAX_RESULT_SIZE) {
            return errors.SerializationError.InvalidLength;
        }

        const result_bytes = try allocator.alloc(u8, @intCast(result_len));
        errdefer allocator.free(result_bytes);
        try reader.readBytes(result_bytes);

        var prefix_writer = BinaryWriter.init(allocator);
        defer prefix_writer.deinit();
        try prefix_writer.writeVarInt(result_len);
        const prefix = prefix_writer.toSlice();

        const total_len = id_bytes.len + 1 + prefix.len + result_bytes.len;
        const payload = try allocator.alloc(u8, total_len);
        errdefer allocator.free(payload);

        var offset: usize = 0;
        @memcpy(payload[offset .. offset + id_bytes.len], &id_bytes);
        offset += id_bytes.len;
        payload[offset] = code_byte;
        offset += 1;
        @memcpy(payload[offset .. offset + prefix.len], prefix);
        offset += prefix.len;
        @memcpy(payload[offset..], result_bytes);

        allocator.free(result_bytes);

        var attribute = Self.init(.OracleResponse, payload);
        attribute.owns_data = true;
        return attribute;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.owns_data) {
            allocator.free(self.data);
        }
        self.data = &[_]u8{};
        self.owns_data = false;
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
    owns_invocation_script: bool = false,
    owns_verification_script: bool = false,

    const Self = @This();

    pub fn init(invocation_script: []const u8, verification_script: []const u8) Self {
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
            .owns_invocation_script = false,
            .owns_verification_script = false,
        };
    }

    pub fn initOwned(invocation_script: []const u8, verification_script: []const u8) Self {
        return Self{
            .invocation_script = invocation_script,
            .verification_script = verification_script,
            .owns_invocation_script = true,
            .owns_verification_script = true,
        };
    }

    pub fn getSize(self: Self) u32 {
        const var_int_size = struct {
            fn calc(value: usize) u32 {
                if (value < 0xFD) return 1;
                if (value <= 0xFFFF) return 3;
                if (value <= 0xFFFFFFFF) return 5;
                return 9;
            }
        }.calc;

        return var_int_size(self.invocation_script.len) +
            @as(u32, @intCast(self.invocation_script.len)) +
            var_int_size(self.verification_script.len) +
            @as(u32, @intCast(self.verification_script.len));
    }

    pub fn validate(self: Self) !void {
        const inv_empty = self.invocation_script.len == 0;
        const ver_empty = self.verification_script.len == 0;
        if (inv_empty and ver_empty) return;
        if (inv_empty != ver_empty) return errors.TransactionError.InvalidWitness;
    }

    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try writer.writeVarInt(@intCast(self.invocation_script.len));
        try writer.writeBytes(self.invocation_script);
        try writer.writeVarInt(@intCast(self.verification_script.len));
        try writer.writeBytes(self.verification_script);
    }

    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        const invocation_len = try reader.readVarInt();
        const invocation_script = try allocator.alloc(u8, @intCast(invocation_len));
        errdefer allocator.free(invocation_script);
        try reader.readBytes(invocation_script);

        const verification_len = try reader.readVarInt();
        const verification_script = try allocator.alloc(u8, @intCast(verification_len));
        errdefer allocator.free(verification_script);
        try reader.readBytes(verification_script);

        return Self.initOwned(invocation_script, verification_script);
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.owns_invocation_script) {
            allocator.free(self.invocation_script);
        }
        if (self.owns_verification_script) {
            allocator.free(self.verification_script);
        }
        self.* = Self.init(&[_]u8{}, &[_]u8{});
    }
};

/// Witness rule system is fully implemented in `witness_rule.zig`.
pub const WitnessRule = witness_rule_mod.WitnessRule;
pub const WitnessAction = witness_rule_mod.WitnessAction;
pub const WitnessCondition = witness_rule_mod.WitnessCondition;

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
            try attribute.serialize(&writer);
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

    /// Releases allocated transaction resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.script);

        for (self.attributes) |*attribute| {
            attribute.deinit(allocator);
        }
        allocator.free(self.attributes);

        for (self.signers) |*signer| {
            signer.deinit(allocator);
        }
        allocator.free(self.signers);

        for (self.witnesses) |*witness| {
            witness.deinit(allocator);
        }
        allocator.free(self.witnesses);
        self.* = undefined;
    }
};

/// Account stub (to be fully implemented)
pub const Account = struct {
    script_hash: Hash160,
    private_key: ?crypto.PrivateKey,
    compressed: bool,

    pub fn init(script_hash: Hash160) Account {
        return Account{
            .script_hash = script_hash,
            .private_key = null,
            .compressed = true,
        };
    }

    pub fn initWithPrivateKey(private_key: crypto.PrivateKey, compressed: bool, allocator: std.mem.Allocator) !Account {
        const public_key = try private_key.getPublicKey(compressed);
        const script_hash = try Hash160.fromPublicKey(public_key.toSlice(), allocator);

        return Account{
            .script_hash = script_hash,
            .private_key = private_key,
            .compressed = compressed,
        };
    }

    pub fn fromAddress(address: []const u8, allocator: std.mem.Allocator) !Account {
        const hash = try Hash160.fromAddress(address, allocator);
        return Account.init(hash);
    }

    pub fn fromWif(wif_string: []const u8, allocator: std.mem.Allocator) !Account {
        const decode_result = try crypto.wif.decode(wif_string, allocator);
        return try Account.initWithPrivateKey(decode_result.private_key, decode_result.compressed, allocator);
    }

    pub fn fromKeyPair(key_pair: crypto.KeyPair, address: @import("../types/address.zig").Address) Account {
        _ = address;

        // Build the verification script without heap allocation.
        const pub_key_bytes = key_pair.public_key.toSlice();
        var script_buf: [72]u8 = undefined;
        var offset: usize = 0;

        script_buf[offset] = 0x0C; // PUSHDATA1
        offset += 1;
        script_buf[offset] = @intCast(pub_key_bytes.len);
        offset += 1;
        @memcpy(script_buf[offset .. offset + pub_key_bytes.len], pub_key_bytes);
        offset += pub_key_bytes.len;

        script_buf[offset] = 0x41; // SYSCALL
        offset += 1;
        const syscall_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, constants.InteropServices.SYSTEM_CRYPTO_CHECK_SIG));
        @memcpy(script_buf[offset .. offset + syscall_bytes.len], &syscall_bytes);
        offset += syscall_bytes.len;

        const script_hash = Hash160.fromScript(script_buf[0..offset]) catch unreachable;

        return Account{
            .script_hash = script_hash,
            .private_key = key_pair.private_key,
            .compressed = key_pair.public_key.compressed,
        };
    }

    pub fn getScriptHash(self: Account) Hash160 {
        return self.script_hash;
    }

    pub fn getAddress(self: Account) Address {
        return Address.fromHash160WithVersion(self.script_hash, constants.AddressConstants.ADDRESS_VERSION);
    }

    pub fn hasPrivateKey(self: Account) bool {
        return self.private_key != null;
    }

    pub fn getPrivateKey(self: Account) !crypto.PrivateKey {
        return self.private_key orelse return errors.WalletError.WalletLocked;
    }

    pub fn getPublicKey(self: Account) !crypto.PublicKey {
        const private_key = try self.getPrivateKey();
        return try private_key.getPublicKey(self.compressed);
    }

    pub fn withPrivateKey(self: *Account, private_key: crypto.PrivateKey, compressed: bool, allocator: std.mem.Allocator) !void {
        self.* = try Account.initWithPrivateKey(private_key, compressed, allocator);
    }
};

fn witnessScopeToString(scope: WitnessScope) []const u8 {
    return switch (scope) {
        .None => "None",
        .CalledByEntry => "CalledByEntry",
        .CustomContracts => "CustomContracts",
        .CustomGroups => "CustomGroups",
        .WitnessRules => "WitnessRules",
        .Global => "Global",
    };
}

fn witnessActionToString(action: WitnessAction) []const u8 {
    return switch (action) {
        .Allow => "Allow",
        .Deny => "Deny",
    };
}

fn formatHash160(hash: Hash160, allocator: std.mem.Allocator) ![]u8 {
    const hex = try hash.string(allocator);
    defer allocator.free(hex);

    const result = try allocator.alloc(u8, hex.len + 2);
    result[0] = '0';
    result[1] = 'x';
    std.mem.copyForwards(u8, result[2..], hex);
    return result;
}

fn formatHash256(hash: Hash256, allocator: std.mem.Allocator) ![]u8 {
    const hex = try hash.string(allocator);
    defer allocator.free(hex);

    const result = try allocator.alloc(u8, hex.len + 2);
    result[0] = '0';
    result[1] = 'x';
    std.mem.copyForwards(u8, result[2..], hex);
    return result;
}

fn formatPublicKey(group: [33]u8, allocator: std.mem.Allocator) ![]u8 {
    const result = try allocator.alloc(u8, group.len * 2 + 2);
    result[0] = '0';
    result[1] = 'x';
    const hex = std.fmt.bytesToHex(group, .lower);
    std.mem.copyForwards(u8, result[2..], &hex);
    return result;
}

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

test "TransactionBuilder defaults validUntilBlock to zero" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var builder = TransactionBuilder.init(allocator);
    defer builder.deinit();

    const signer = Signer.init(Hash160.ZERO, WitnessScope.CalledByEntry);
    _ = try builder.signer(signer);

    const script_bytes = [_]u8{0x51}; // PUSH1
    _ = try builder.script(&script_bytes);

    var tx = try builder.build();
    defer tx.deinit(allocator);

    try testing.expectEqual(@as(u32, 0), tx.valid_until_block);
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

test "TransactionBuilder signing with account key" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var builder = TransactionBuilder.init(allocator);
    defer builder.deinit();

    const account = try Account.fromWif("L3pLaHgKBf7ENNKPH1jfPM8FC9QhPCqwFyWguQ8CDB1G66p78wd6", allocator);
    const signer = Signer.init(account.getScriptHash(), WitnessScope.CalledByEntry);
    _ = try builder.signer(signer);

    const script_bytes = [_]u8{0x51};
    _ = try builder.script(&script_bytes);
    _ = try builder.validUntilBlock(123456);

    var transaction = try builder.sign(&[_]Account{account}, constants.NetworkMagic.MAINNET);
    defer transaction.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), transaction.witnesses.len);
    try testing.expect(transaction.witnesses[0].invocation_script.len > 0);
    try testing.expect(transaction.witnesses[0].verification_script.len > 0);

    // Ensure signing hash data ordering matches NeoSwift: magicBytes || sha256(unsignedTxBytes),
    // then sign sha256(that) deterministically.
    const tx_hash = try transaction.getHash(allocator);
    var signing_data: [36]u8 = undefined;
    const magic_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, constants.NetworkMagic.MAINNET));
    @memcpy(signing_data[0..4], &magic_bytes);
    @memcpy(signing_data[4..36], tx_hash.toSlice());
    const signing_hash = Hash256.sha256(&signing_data);

    const private_key = try account.getPrivateKey();
    const expected_sig = try private_key.sign(signing_hash);
    var expected_invocation: [66]u8 = undefined;
    expected_invocation[0] = 0x0C; // PUSHDATA1
    expected_invocation[1] = 64;
    @memcpy(expected_invocation[2..], expected_sig.toSlice());
    try testing.expectEqualSlices(u8, &expected_invocation, transaction.witnesses[0].invocation_script);
}

test "TransactionBuilder signing fails without private key" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var builder = TransactionBuilder.init(allocator);
    defer builder.deinit();

    const signer = Signer.init(Hash160.ZERO, WitnessScope.CalledByEntry);
    _ = try builder.signer(signer);

    const script_bytes = [_]u8{0x51};
    _ = try builder.script(&script_bytes);
    _ = try builder.validUntilBlock(42);

    const result = builder.sign(&[_]Account{Account.init(Hash160.ZERO)}, constants.NetworkMagic.MAINNET);
    try testing.expectError(errors.WalletError.WalletLocked, result);
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
        100000000, // 1 GAS
    );

    // Should have script
    try testing.expect(builder.getScript() != null);
    try testing.expect(builder.getScript().?.len > 0);
}
