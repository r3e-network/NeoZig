//! Transaction Broadcasting
//!
//! Production transaction broadcasting and network submission
//! Handles complete transaction lifecycle from building to confirmation.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;
const NeoTransaction = @import("neo_transaction.zig").NeoTransaction;
const HttpClient = @import("../rpc/http_client.zig").HttpClient;

/// Transaction broadcaster for network submission
pub const TransactionBroadcaster = struct {
    http_client: HttpClient,
    network_magic: u32,
    
    const Self = @This();
    
    /// Creates transaction broadcaster
    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8, network_magic: u32) Self {
        return Self{
            .http_client = HttpClient.init(allocator, endpoint),
            .network_magic = network_magic,
        };
    }
    
    /// Broadcasts transaction to network
    pub fn broadcastTransaction(self: Self, transaction: NeoTransaction) !Hash256 {
        // Serialize transaction to hex
        const serialized = try transaction.serialize(self.http_client.allocator);
        defer self.http_client.allocator.free(serialized);
        
        const hex_transaction = try @import("../utils/bytes.zig").toHex(serialized, self.http_client.allocator);
        defer self.http_client.allocator.free(hex_transaction);
        
        // Build RPC request
        const params = std.json.Value{ .array = &[_]std.json.Value{
            std.json.Value{ .string = hex_transaction },
        }};
        
        // Send transaction
        const result = try self.http_client.jsonRpcRequest("sendrawtransaction", params, 1);
        defer result.deinit();
        
        // Parse result - should contain transaction hash
        const response_obj = result.object;
        if (response_obj.get("hash")) |hash_value| {
            return try Hash256.initWithString(hash_value.string);
        }
        
        // Some nodes return boolean success
        if (response_obj.get("result")) |success_value| {
            if (success_value.bool) {
                return try transaction.getHash(self.http_client.allocator);
            }
        }
        
        return errors.NetworkError.InvalidResponse;
    }
    
    /// Validates transaction before broadcasting
    pub fn validateTransactionForBroadcast(self: Self, transaction: NeoTransaction) !void {
        // Validate transaction structure
        try transaction.validate();
        
        // Check transaction size
        const size = transaction.getSize();
        if (size > constants.MAX_TRANSACTION_SIZE) {
            return errors.TransactionError.TransactionTooLarge;
        }
        
        // Validate network magic (would check against node)
        _ = self.network_magic; // Future: validate against node network
        
        // Check transaction expiry
        if (transaction.valid_until_block < getCurrentBlockHeight(self)) {
            return errors.TransactionError.TransactionExpired;
        }
        
        // Validate witnesses match signers
        if (transaction.signers.len != transaction.witnesses.len) {
            return errors.TransactionError.InvalidWitness;
        }
    }
    
    /// Estimates transaction fees before broadcasting
    pub fn estimateTransactionFees(self: Self, transaction: NeoTransaction) !TransactionFees {
        const hex_transaction = blk: {
            const serialized = try transaction.serialize(self.http_client.allocator);
            defer self.http_client.allocator.free(serialized);
            
            break :blk try @import("../utils/bytes.zig").toHex(serialized, self.http_client.allocator);
        };
        defer self.http_client.allocator.free(hex_transaction);
        
        // Calculate network fee
        const params = std.json.Value{ .array = &[_]std.json.Value{
            std.json.Value{ .string = hex_transaction },
        }};
        
        const result = try self.http_client.jsonRpcRequest("calculatenetworkfee", params, 1);
        defer result.deinit();
        
        const network_fee = @as(u64, @intCast(result.object.get("networkfee").?.integer));
        
        return TransactionFees{
            .network_fee = network_fee,
            .system_fee = @bitCast(transaction.system_fee),
            .total_fee = network_fee + @as(u64, @bitCast(transaction.system_fee)),
        };
    }
    
    /// Waits for transaction confirmation
    pub fn waitForConfirmation(
        self: Self,
        tx_hash: Hash256,
        max_wait_ms: u32,
        poll_interval_ms: u32,
    ) !TransactionStatus {
        const start_time = std.time.milliTimestamp();
        
        while ((std.time.milliTimestamp() - start_time) < max_wait_ms) {
            const status = try self.getTransactionStatus(tx_hash);
            
            switch (status) {
                .Confirmed => return status,
                .Failed => return status,
                .Pending => {
                    std.time.sleep(poll_interval_ms * std.time.ns_per_ms);
                    continue;
                },
                .NotFound => {
                    std.time.sleep(poll_interval_ms * std.time.ns_per_ms);
                    continue;
                },
            }
        }
        
        return TransactionStatus.Timeout;
    }
    
    /// Gets transaction status from network
    pub fn getTransactionStatus(self: Self, tx_hash: Hash256) !TransactionStatus {
        const hash_hex = try tx_hash.string(self.http_client.allocator);
        defer self.http_client.allocator.free(hash_hex);
        
        // Try to get transaction
        const params = std.json.Value{ .array = &[_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .integer = 1 }, // Verbose
        }};
        
        const result = self.http_client.jsonRpcRequest("getrawtransaction", params, 1) catch |err| {
            return switch (err) {
                error.RPCError => TransactionStatus.NotFound,
                else => err,
            };
        };
        defer result.deinit();
        
        // If we get a response, transaction exists
        const tx_obj = result.object;
        const confirmations = @as(u32, @intCast(tx_obj.get("confirmations").?.integer));
        
        if (confirmations == 0) {
            return TransactionStatus.Pending;
        } else if (confirmations > 0) {
            return TransactionStatus.Confirmed;
        }
        
        return TransactionStatus.NotFound;
    }
    
    /// Gets current block height
    fn getCurrentBlockHeight(self: Self) u32 {
        const result = self.http_client.jsonRpcRequest(
            "getblockcount",
            std.json.Value{ .array = &[_]std.json.Value{} },
            1,
        ) catch return 0;
        defer result.deinit();
        
        return @intCast(result.integer);
    }
};

/// Transaction fees structure
pub const TransactionFees = struct {
    network_fee: u64,
    system_fee: u64,
    total_fee: u64,
    
    /// Formats fees as GAS amounts
    pub fn formatAsGas(self: TransactionFees, allocator: std.mem.Allocator) !TransactionFeesFormatted {
        const network_gas = @as(f64, @floatFromInt(self.network_fee)) / 100000000.0;
        const system_gas = @as(f64, @floatFromInt(self.system_fee)) / 100000000.0;
        const total_gas = @as(f64, @floatFromInt(self.total_fee)) / 100000000.0;
        
        return TransactionFeesFormatted{
            .network_fee_gas = network_gas,
            .system_fee_gas = system_gas,
            .total_fee_gas = total_gas,
        };
    }
};

/// Formatted transaction fees
pub const TransactionFeesFormatted = struct {
    network_fee_gas: f64,
    system_fee_gas: f64,
    total_fee_gas: f64,
};

/// Transaction status enumeration
pub const TransactionStatus = enum {
    Pending,
    Confirmed,
    Failed,
    NotFound,
    Timeout,
    
    pub fn isSuccess(self: TransactionStatus) bool {
        return self == .Confirmed;
    }
    
    pub fn isFailure(self: TransactionStatus) bool {
        return self == .Failed or self == .Timeout;
    }
    
    pub fn isPending(self: TransactionStatus) bool {
        return self == .Pending;
    }
};

/// Broadcasting utilities
pub const BroadcastUtils = struct {
    /// Creates broadcaster for MainNet
    pub fn mainnet(allocator: std.mem.Allocator) TransactionBroadcaster {
        return TransactionBroadcaster.init(
            allocator,
            "https://mainnet1.neo.coz.io:443",
            constants.NetworkMagic.MAINNET,
        );
    }
    
    /// Creates broadcaster for TestNet
    pub fn testnet(allocator: std.mem.Allocator) TransactionBroadcaster {
        return TransactionBroadcaster.init(
            allocator,
            "https://testnet1.neo.coz.io:443",
            constants.NetworkMagic.TESTNET,
        );
    }
    
    /// Creates broadcaster for local node
    pub fn localhost(allocator: std.mem.Allocator, port: ?u16) TransactionBroadcaster {
        const actual_port = port orelse 20332;
        const endpoint = std.fmt.allocPrint(
            allocator,
            "http://localhost:{d}",
            .{actual_port},
        ) catch "http://localhost:20332";
        
        return TransactionBroadcaster.init(allocator, endpoint, constants.NetworkMagic.MAINNET);
    }
};

// Tests
test "TransactionBroadcaster creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const broadcaster = TransactionBroadcaster.init(
        allocator,
        "http://localhost:20332",
        constants.NetworkMagic.MAINNET,
    );
    
    try testing.expectEqualStrings("http://localhost:20332", broadcaster.http_client.endpoint);
    try testing.expectEqual(constants.NetworkMagic.MAINNET, broadcaster.network_magic);
}

test "TransactionStatus operations" {
    const testing = std.testing;
    
    // Test status classification
    try testing.expect(TransactionStatus.Confirmed.isSuccess());
    try testing.expect(!TransactionStatus.Pending.isSuccess());
    
    try testing.expect(TransactionStatus.Failed.isFailure());
    try testing.expect(TransactionStatus.Timeout.isFailure());
    try testing.expect(!TransactionStatus.Confirmed.isFailure());
    
    try testing.expect(TransactionStatus.Pending.isPending());
    try testing.expect(!TransactionStatus.Confirmed.isPending());
}

test "BroadcastUtils factory methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const mainnet_broadcaster = BroadcastUtils.mainnet(allocator);
    try testing.expect(std.mem.containsAtLeast(u8, mainnet_broadcaster.http_client.endpoint, 1, "mainnet"));
    try testing.expectEqual(constants.NetworkMagic.MAINNET, mainnet_broadcaster.network_magic);
    
    const testnet_broadcaster = BroadcastUtils.testnet(allocator);
    try testing.expect(std.mem.containsAtLeast(u8, testnet_broadcaster.http_client.endpoint, 1, "testnet"));
    try testing.expectEqual(constants.NetworkMagic.TESTNET, testnet_broadcaster.network_magic);
    
    const localhost_broadcaster = BroadcastUtils.localhost(allocator, null);
    try testing.expect(std.mem.containsAtLeast(u8, localhost_broadcaster.http_client.endpoint, 1, "localhost"));
}