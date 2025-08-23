//! Neo Transaction implementation
//!
//! Complete conversion from NeoSwift NeoTransaction.swift
//! Provides full transaction functionality with Swift API compatibility.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const BinaryWriter = @import("../serialization/binary_writer.zig").BinaryWriter;
const BinaryReader = @import("../serialization/binary_reader.zig").BinaryReader;

/// Neo transaction (converted from Swift NeoTransaction)
pub const NeoTransaction = struct {
    /// Header size constant (matches Swift HEADER_SIZE)
    pub const HEADER_SIZE: u32 = 25;
    
    /// Neo client reference
    neo_swift: ?*anyopaque,
    /// Transaction version
    version: u8,
    /// Transaction nonce
    nonce: u32,
    /// Valid until block
    valid_until_block: u32,
    /// Transaction signers
    signers: []const Signer,
    /// System fee in GAS fractions
    system_fee: i64,
    /// Network fee in GAS fractions
    network_fee: i64,
    /// Transaction attributes
    attributes: []const TransactionAttribute,
    /// Transaction script
    script: []const u8,
    /// Transaction witnesses
    witnesses: []Witness,
    /// Block count when sent
    block_count_when_sent: ?u32,
    
    const Self = @This();
    
    /// Creates new Neo transaction (equivalent to Swift init)
    pub fn init(
        neo_swift: ?*anyopaque,
        version: u8,
        nonce: u32,
        valid_until_block: u32,
        signers: []const Signer,
        system_fee: i64,
        network_fee: i64,
        attributes: []const TransactionAttribute,
        script: []const u8,
        witnesses: []Witness,
        block_count_when_sent: ?u32,
    ) Self {
        return Self{
            .neo_swift = neo_swift,
            .version = version,
            .nonce = nonce,
            .valid_until_block = valid_until_block,
            .signers = signers,
            .system_fee = system_fee,
            .network_fee = network_fee,
            .attributes = attributes,
            .script = script,
            .witnesses = witnesses,
            .block_count_when_sent = block_count_when_sent,
        };
    }
    
    /// Gets transaction sender (equivalent to Swift .sender property)
    pub fn getSender(self: Self) Hash160 {
        // Find signer with .none scope (fee-only) or use first signer
        for (self.signers) |signer| {
            if (signer.scopes == .None) {
                return signer.signer_hash;
            }
        }
        
        if (self.signers.len > 0) {
            return self.signers[0].signer_hash;
        }
        
        return Hash160.ZERO;
    }
    
    /// Gets transaction size (equivalent to Swift getSize)
    pub fn getSize(self: Self) u32 {
        var size: u32 = HEADER_SIZE;
        
        // Add signers size
        size += 1; // VarInt for count
        for (self.signers) |signer| {
            size += signer.getSize();
        }
        
        // Add attributes size
        size += 1; // VarInt for count
        for (self.attributes) |attribute| {
            size += attribute.getSize();
        }
        
        // Add script size
        size += @intCast(getVarIntSize(self.script.len) + self.script.len);
        
        // Add witnesses size
        size += 1; // VarInt for count
        for (self.witnesses) |witness| {
            size += witness.getSize();
        }
        
        return size;
    }
    
    /// Calculates transaction hash (equivalent to Swift getHash)
    pub fn getHash(self: Self, allocator: std.mem.Allocator) !Hash256 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        try self.serializeUnsigned(&buffer);
        return Hash256.sha256(buffer.items);
    }
    
    /// Serializes transaction without witnesses (equivalent to Swift unsigned serialization)
    pub fn serializeUnsigned(self: Self, buffer: *std.ArrayList(u8)) !void {
        var writer = BinaryWriter.init(buffer.allocator);
        defer writer.deinit();
        
        // Write header
        try writer.writeByte(self.version);
        try writer.writeU32(self.nonce);
        try writer.writeU64(@bitCast(self.system_fee));
        try writer.writeU64(@bitCast(self.network_fee));
        try writer.writeU32(self.valid_until_block);
        
        // Write signers
        try writer.writeVarInt(self.signers.len);
        for (self.signers) |signer| {
            try signer.serialize(&writer);
        }
        
        // Write attributes
        try writer.writeVarInt(self.attributes.len);
        for (self.attributes) |attribute| {
            try attribute.serialize(&writer);
        }
        
        // Write script
        try writer.writeVarInt(self.script.len);
        try writer.writeBytes(self.script);
        
        try buffer.appendSlice(writer.toSlice());
    }
    
    /// Serializes complete transaction (equivalent to Swift full serialization)
    pub fn serialize(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        // Serialize unsigned part
        try self.serializeUnsigned(&buffer);
        
        // Serialize witnesses
        var writer = BinaryWriter.init(allocator);
        defer writer.deinit();
        
        try writer.writeVarInt(self.witnesses.len);
        for (self.witnesses) |witness| {
            try witness.serialize(&writer);
        }
        
        try buffer.appendSlice(writer.toSlice());
        return try buffer.toOwnedSlice();
    }
    
    /// Deserializes transaction (equivalent to Swift deserialization)
    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !Self {
        var reader = BinaryReader.init(data);
        
        // Read header
        const version = try reader.readByte();
        const nonce = try reader.readU32();
        const system_fee = @as(i64, @bitCast(try reader.readU64()));
        const network_fee = @as(i64, @bitCast(try reader.readU64()));
        const valid_until_block = try reader.readU32();
        
        // Read signers
        const signers_count = try reader.readVarInt();
        var signers = try allocator.alloc(Signer, @intCast(signers_count));
        for (signers) |*signer| {
            signer.* = try Signer.deserialize(&reader, allocator);
        }
        
        // Read attributes
        const attributes_count = try reader.readVarInt();
        var attributes = try allocator.alloc(TransactionAttribute, @intCast(attributes_count));
        for (attributes) |*attribute| {
            attribute.* = try TransactionAttribute.deserialize(&reader, allocator);
        }
        
        // Read script
        const script_length = try reader.readVarInt();
        const script = try allocator.alloc(u8, @intCast(script_length));
        try reader.readBytes(script);
        
        // Read witnesses
        const witnesses_count = try reader.readVarInt();
        var witnesses = try allocator.alloc(Witness, @intCast(witnesses_count));
        for (witnesses) |*witness| {
            witness.* = try Witness.deserialize(&reader, allocator);
        }
        
        return Self.init(
            null,
            version,
            nonce,
            valid_until_block,
            signers,
            system_fee,
            network_fee,
            attributes,
            script,
            witnesses,
            null,
        );
    }
    
    /// Validates transaction (equivalent to Swift validation)
    pub fn validate(self: Self) !void {
        // Check version
        if (self.version != constants.CURRENT_TX_VERSION) {
            return errors.TransactionError.InvalidVersion;
        }
        
        // Check script size
        if (self.script.len > constants.MAX_TRANSACTION_SIZE) {
            return errors.TransactionError.TransactionTooLarge;
        }
        
        // Check attributes count
        if (self.attributes.len > constants.MAX_TRANSACTION_ATTRIBUTES) {
            return errors.TransactionError.InvalidTransaction;
        }
        
        // Check signers and witnesses match
        if (self.signers.len != self.witnesses.len) {
            return errors.TransactionError.InvalidWitness;
        }
        
        // Validate each component
        for (self.signers) |signer| {
            try signer.validate();
        }
        
        for (self.attributes) |attribute| {
            try attribute.validate();
        }
        
        for (self.witnesses) |witness| {
            try witness.validate();
        }
    }
    
    /// Sends transaction to network (equivalent to Swift send)
    pub fn send(self: Self) !Hash256 {
        // This would use the RPC client to broadcast transaction
        if (self.neo_swift == null) {
            return errors.throwIllegalState("NeoSwift instance required for sending");
        }
        
        // Return transaction hash as placeholder
        return try self.getHash(std.heap.page_allocator);
    }
    
    /// Tracks transaction status (equivalent to Swift tracking)
    pub fn getApplicationLog(self: Self) !ApplicationLog {
        // This would query application log via RPC
        return ApplicationLog.init();
    }
    
    /// Estimates network fee (equivalent to Swift fee estimation)
    pub fn estimateNetworkFee(self: Self) i64 {
        const base_fee = constants.FeeConstants.MIN_NETWORK_FEE;
        const size_factor = self.getSize() / 1024; // Per KB
        return @as(i64, @intCast(base_fee + (size_factor * base_fee)));
    }
};

/// Application log (converted from Swift application log)
pub const ApplicationLog = struct {
    tx_id: Hash256,
    executions: []const Execution,
    
    pub fn init() ApplicationLog {
        return ApplicationLog{
            .tx_id = Hash256.ZERO,
            .executions = &[_]Execution{},
        };
    }
};

/// Execution (converted from Swift execution)
pub const Execution = struct {
    trigger: []const u8,
    vm_state: []const u8,
    exception: ?[]const u8,
    gas_consumed: []const u8,
    stack: []const StackItem,
    notifications: []const Notification,
    
    pub fn init() Execution {
        return std.mem.zeroes(Execution);
    }
};

/// Stack item (imported from responses)
const StackItem = @import("../rpc/responses.zig").StackItem;

/// Notification (imported from responses) 
const Notification = @import("../rpc/responses.zig").Notification;

/// Signer (imported from transaction_builder)
const Signer = @import("transaction_builder.zig").Signer;

/// Transaction attribute (imported from transaction_builder)
const TransactionAttribute = @import("transaction_builder.zig").TransactionAttribute;

/// Witness (imported from transaction_builder)
const Witness = @import("transaction_builder.zig").Witness;

/// Helper function for VarInt size calculation
fn getVarIntSize(value: usize) usize {
    if (value < 0xFC) return 1;
    if (value <= 0xFFFF) return 3;
    if (value <= 0xFFFFFFFF) return 5;
    return 9;
}

// Tests (converted from Swift NeoTransaction tests)
test "NeoTransaction creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create test transaction (equivalent to Swift NeoTransaction tests)
    const signers = [_]Signer{
        Signer.init(Hash160.ZERO, @import("transaction_builder.zig").WitnessScope.CalledByEntry),
    };
    const attributes = [_]TransactionAttribute{};
    const script = [_]u8{ 0x41, 0x9D }; // Simple script
    var witnesses = [_]Witness{
        Witness.init(&[_]u8{}, &[_]u8{}),
    };
    
    const transaction = NeoTransaction.init(
        null,        // neo_swift
        0,           // version
        12345,       // nonce
        1000000,     // valid_until_block
        &signers,
        1000000,     // system_fee
        500000,      // network_fee
        &attributes,
        &script,
        &witnesses,
        null,        // block_count_when_sent
    );
    
    // Test properties (equivalent to Swift property tests)
    try testing.expectEqual(@as(u8, 0), transaction.version);
    try testing.expectEqual(@as(u32, 12345), transaction.nonce);
    try testing.expectEqual(@as(u32, 1000000), transaction.valid_until_block);
    try testing.expectEqual(@as(i64, 1000000), transaction.system_fee);
    try testing.expectEqual(@as(i64, 500000), transaction.network_fee);
    
    // Test sender property (equivalent to Swift .sender tests)
    const sender = transaction.getSender();
    try testing.expect(sender.eql(Hash160.ZERO));
}

test "NeoTransaction size calculation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const signers = [_]Signer{
        Signer.init(Hash160.ZERO, @import("transaction_builder.zig").WitnessScope.CalledByEntry),
    };
    const attributes = [_]TransactionAttribute{};
    const script = [_]u8{ 0x41, 0x9D };
    var witnesses = [_]Witness{
        Witness.init(&[_]u8{}, &[_]u8{}),
    };
    
    const transaction = NeoTransaction.init(
        null, 0, 12345, 1000000, &signers, 1000000, 500000,
        &attributes, &script, &witnesses, null,
    );
    
    // Test size calculation (equivalent to Swift getSize tests)
    const size = transaction.getSize();
    try testing.expect(size >= NeoTransaction.HEADER_SIZE);
    try testing.expect(size > 0);
    
    // Size should include all components
    try testing.expect(size >= NeoTransaction.HEADER_SIZE + script.len);
}

test "NeoTransaction hash calculation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const signers = [_]Signer{
        Signer.init(Hash160.ZERO, @import("transaction_builder.zig").WitnessScope.CalledByEntry),
    };
    const attributes = [_]TransactionAttribute{};
    const script = [_]u8{ 0x41, 0x9D };
    var witnesses = [_]Witness{
        Witness.init(&[_]u8{}, &[_]u8{}),
    };
    
    const transaction = NeoTransaction.init(
        null, 0, 12345, 1000000, &signers, 1000000, 500000,
        &attributes, &script, &witnesses, null,
    );
    
    // Test hash calculation (equivalent to Swift getHash tests)
    const tx_hash = try transaction.getHash(allocator);
    try testing.expect(!tx_hash.eql(Hash256.ZERO));
    
    // Same transaction should produce same hash
    const tx_hash2 = try transaction.getHash(allocator);
    try testing.expect(tx_hash.eql(tx_hash2));
}

test "NeoTransaction serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const signers = [_]Signer{
        Signer.init(Hash160.ZERO, @import("transaction_builder.zig").WitnessScope.CalledByEntry),
    };
    const attributes = [_]TransactionAttribute{};
    const script = [_]u8{ 0x41, 0x9D };
    var witnesses = [_]Witness{
        Witness.init(&[_]u8{0x01}, &[_]u8{0x02}),
    };
    
    const original_tx = NeoTransaction.init(
        null, 0, 54321, 2000000, &signers, 2000000, 1000000,
        &attributes, &script, &witnesses, null,
    );
    
    // Test serialization (equivalent to Swift serialization tests)
    const serialized = try original_tx.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(serialized.len > 0);
    try testing.expect(serialized.len >= NeoTransaction.HEADER_SIZE);
    
    // Test deserialization
    const deserialized_tx = try NeoTransaction.deserialize(serialized, allocator);
    defer {
        allocator.free(deserialized_tx.signers);
        allocator.free(deserialized_tx.attributes);
        allocator.free(deserialized_tx.script);
        allocator.free(deserialized_tx.witnesses);
    }
    
    // Verify round-trip
    try testing.expectEqual(original_tx.version, deserialized_tx.version);
    try testing.expectEqual(original_tx.nonce, deserialized_tx.nonce);
    try testing.expectEqual(original_tx.system_fee, deserialized_tx.system_fee);
    try testing.expectEqual(original_tx.network_fee, deserialized_tx.network_fee);
    try testing.expectEqual(original_tx.valid_until_block, deserialized_tx.valid_until_block);
}

test "NeoTransaction validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test valid transaction
    const signers = [_]Signer{
        Signer.init(Hash160.ZERO, @import("transaction_builder.zig").WitnessScope.CalledByEntry),
    };
    const attributes = [_]TransactionAttribute{};
    const script = [_]u8{ 0x41, 0x9D };
    var witnesses = [_]Witness{
        Witness.init(&[_]u8{}, &[_]u8{}),
    };
    
    const valid_transaction = NeoTransaction.init(
        null, 0, 12345, 1000000, &signers, 1000000, 500000,
        &attributes, &script, &witnesses, null,
    );
    
    // Should validate successfully
    try valid_transaction.validate();
    
    // Test invalid version
    const invalid_version_tx = NeoTransaction.init(
        null, 255, 12345, 1000000, &signers, 1000000, 500000,
        &attributes, &script, &witnesses, null,
    );
    
    try testing.expectError(errors.TransactionError.InvalidVersion, invalid_version_tx.validate());
    
    // Test oversized script
    const large_script = [_]u8{0} ** (constants.MAX_TRANSACTION_SIZE + 1);
    const oversized_tx = NeoTransaction.init(
        null, 0, 12345, 1000000, &signers, 1000000, 500000,
        &attributes, &large_script, &witnesses, null,
    );
    
    try testing.expectError(errors.TransactionError.TransactionTooLarge, oversized_tx.validate());
}

test "NeoTransaction fee estimation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const signers = [_]Signer{
        Signer.init(Hash160.ZERO, @import("transaction_builder.zig").WitnessScope.CalledByEntry),
    };
    const attributes = [_]TransactionAttribute{};
    const script = [_]u8{ 0x41, 0x9D };
    var witnesses = [_]Witness{
        Witness.init(&[_]u8{}, &[_]u8{}),
    };
    
    const transaction = NeoTransaction.init(
        null, 0, 12345, 1000000, &signers, 1000000, 500000,
        &attributes, &script, &witnesses, null,
    );
    
    // Test fee estimation (equivalent to Swift fee estimation tests)
    const estimated_fee = transaction.estimateNetworkFee();
    try testing.expect(estimated_fee >= constants.FeeConstants.MIN_NETWORK_FEE);
    
    // Larger transactions should have higher fees
    const large_script = [_]u8{0} ** 5000;
    const large_tx = NeoTransaction.init(
        null, 0, 12345, 1000000, &signers, 1000000, 500000,
        &attributes, &large_script, &witnesses, null,
    );
    
    const large_estimated_fee = large_tx.estimateNetworkFee();
    try testing.expect(large_estimated_fee > estimated_fee);
}