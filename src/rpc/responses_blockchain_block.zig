const std = @import("std");
const ArrayList = std.ArrayList;

const Hash256 = @import("../types/hash256.zig").Hash256;
const tx = @import("responses_blockchain_transaction.zig");

const NeoWitness = tx.NeoWitness;
const Transaction = tx.Transaction;

/// Neo block response
pub const NeoBlock = struct {
    hash: Hash256,
    size: u32,
    version: u32,
    prev_block_hash: Hash256,
    merkle_root_hash: Hash256,
    time: u64,
    index: u32,
    primary: ?u32,
    next_consensus: []const u8,
    witnesses: ?[]NeoWitness,
    transactions: ?[]Transaction,
    confirmations: u32,
    next_block_hash: ?Hash256,

    const Self = @This();

    pub fn init(
        hash: Hash256,
        size: u32,
        version: u32,
        prev_block_hash: Hash256,
        merkle_root_hash: Hash256,
        time: u64,
        index: u32,
        primary: ?u32,
        next_consensus: []const u8,
        witnesses: ?[]NeoWitness,
        transactions: ?[]Transaction,
        confirmations: u32,
        next_block_hash: ?Hash256,
    ) Self {
        return Self{
            .hash = hash,
            .size = size,
            .version = version,
            .prev_block_hash = prev_block_hash,
            .merkle_root_hash = merkle_root_hash,
            .time = time,
            .index = index,
            .primary = primary,
            .next_consensus = next_consensus,
            .witnesses = witnesses,
            .transactions = transactions,
            .confirmations = confirmations,
            .next_block_hash = next_block_hash,
        };
    }

    pub fn initDefault() Self {
        return Self{
            .hash = Hash256.ZERO,
            .size = 0,
            .version = 0,
            .prev_block_hash = Hash256.ZERO,
            .merkle_root_hash = Hash256.ZERO,
            .time = 0,
            .index = 0,
            .primary = null,
            .next_consensus = "",
            .witnesses = null,
            .transactions = null,
            .confirmations = 0,
            .next_block_hash = null,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const hash = try Hash256.initWithString(obj.get("hash").?.string);
        const size = @as(u32, @intCast(obj.get("size").?.integer));
        const version = @as(u32, @intCast(obj.get("version").?.integer));
        const prev_hash = try Hash256.initWithString(obj.get("previousblockhash").?.string);
        const merkle_root = try Hash256.initWithString(obj.get("merkleroot").?.string);
        const time = @as(u64, @intCast(obj.get("time").?.integer));
        const index = @as(u32, @intCast(obj.get("index").?.integer));

        const primary = if (obj.get("primary")) |primary_value|
            switch (primary_value) {
                .integer => |i| @as(u32, @intCast(i)),
                .null => null,
                else => null,
            }
        else
            null;

        const next_consensus = try allocator.dupe(u8, obj.get("nextconsensus").?.string);
        const confirmations = @as(u32, @intCast(obj.get("confirmations").?.integer));

        const next_block_hash = if (obj.get("nextblockhash")) |next_hash_value|
            switch (next_hash_value) {
                .string => |s| try Hash256.initWithString(s),
                .null => null,
                else => null,
            }
        else
            null;

        var witnesses_slice: ?[]NeoWitness = null;
        if (obj.get("witnesses")) |witnesses_value| {
            var witnesses_list = ArrayList(NeoWitness).init(allocator);
            defer witnesses_list.deinit();

            for (witnesses_value.array.items) |witness_json| {
                try witnesses_list.append(try NeoWitness.fromJson(witness_json, allocator));
            }

            witnesses_slice = try witnesses_list.toOwnedSlice();
        }

        var transactions_slice: ?[]Transaction = null;
        if (obj.get("tx")) |tx_value| {
            var tx_list = ArrayList(Transaction).init(allocator);
            defer tx_list.deinit();

            for (tx_value.array.items) |tx_json| {
                try tx_list.append(try Transaction.fromJson(tx_json, allocator));
            }

            transactions_slice = try tx_list.toOwnedSlice();
        } else if (obj.get("transactions")) |tx_value| {
            var tx_list = ArrayList(Transaction).init(allocator);
            defer tx_list.deinit();

            for (tx_value.array.items) |tx_json| {
                try tx_list.append(try Transaction.fromJson(tx_json, allocator));
            }

            transactions_slice = try tx_list.toOwnedSlice();
        }

        return Self.init(
            hash,
            size,
            version,
            prev_hash,
            merkle_root,
            time,
            index,
            primary,
            next_consensus,
            witnesses_slice,
            transactions_slice,
            confirmations,
            next_block_hash,
        );
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.next_consensus.len > 0) {
            allocator.free(@constCast(self.next_consensus));
            self.next_consensus = "";
        }

        if (self.witnesses) |witnesses_slice| {
            for (witnesses_slice) |*witness| {
                witness.deinit(allocator);
            }
            allocator.free(@constCast(witnesses_slice));
            self.witnesses = null;
        }

        if (self.transactions) |transactions_slice| {
            for (transactions_slice) |*transaction_entry| {
                transaction_entry.deinit(allocator);
            }
            allocator.free(transactions_slice);
            self.transactions = null;
        }
    }
};
