const std = @import("std");

const Hash256 = @import("../types/hash256.zig").Hash256;
const Transaction = @import("../transaction/transaction_builder.zig").Transaction;
const NeoBlock = @import("responses.zig").NeoBlock;
const NeoVersion = @import("responses.zig").NeoVersion;
const RpcParam = @import("rpc_operation.zig").RpcParam;
const RpcRequest = @import("rpc_operation.zig").RpcRequest;

pub fn mixin(comptime Client: type) type {
    return struct {
        pub fn getBestBlockHash(self: *Client) !RpcRequest(Hash256) {
            return RpcRequest(Hash256).init(self.allocator, &self.service, "getbestblockhash", &[_]RpcParam{});
        }

        pub fn getBlockHash(self: *Client, block_index: u32) !RpcRequest(Hash256) {
            const params = [_]RpcParam{RpcParam.initInt(block_index)};
            return RpcRequest(Hash256).init(self.allocator, &self.service, "getblockhash", &params);
        }

        pub fn getBlock(self: *Client, block_hash: Hash256, full_transactions: bool) !RpcRequest(NeoBlock) {
            const hash_str = try block_hash.string(self.allocator);
            defer self.allocator.free(hash_str);

            const verbose = if (full_transactions) @as(i32, 1) else @as(i32, 0);
            const params = [_]RpcParam{
                RpcParam.initString(hash_str),
                RpcParam.initInt(verbose),
            };
            return RpcRequest(NeoBlock).init(self.allocator, &self.service, "getblock", &params);
        }

        pub fn getBlockByIndex(self: *Client, block_index: u32, full_transactions: bool) !RpcRequest(NeoBlock) {
            const verbose = if (full_transactions) @as(i32, 1) else @as(i32, 0);
            const params = [_]RpcParam{
                RpcParam.initInt(block_index),
                RpcParam.initInt(verbose),
            };
            return RpcRequest(NeoBlock).init(self.allocator, &self.service, "getblock", &params);
        }

        pub fn getRawBlock(self: *Client, block_hash: Hash256) !RpcRequest([]const u8) {
            const hash_str = try block_hash.string(self.allocator);
            defer self.allocator.free(hash_str);

            const params = [_]RpcParam{
                RpcParam.initString(hash_str),
                RpcParam.initInt(0),
            };
            return RpcRequest([]const u8).init(self.allocator, &self.service, "getblock", &params);
        }

        pub fn getBlockCount(self: *Client) !RpcRequest(u32) {
            return RpcRequest(u32).init(self.allocator, &self.service, "getblockcount", &[_]RpcParam{});
        }

        pub fn getTransaction(self: *Client, tx_hash: Hash256) !RpcRequest(Transaction) {
            const hash_str = try tx_hash.string(self.allocator);
            defer self.allocator.free(hash_str);

            const params = [_]RpcParam{
                RpcParam.initString(hash_str),
                RpcParam.initInt(1),
            };
            return RpcRequest(Transaction).init(self.allocator, &self.service, "getrawtransaction", &params);
        }

        pub fn getConnectionCount(self: *Client) !RpcRequest(u32) {
            return RpcRequest(u32).init(self.allocator, &self.service, "getconnectioncount", &[_]RpcParam{});
        }

        pub fn getVersion(self: *Client) !RpcRequest(NeoVersion) {
            return RpcRequest(NeoVersion).init(self.allocator, &self.service, "getversion", &[_]RpcParam{});
        }
    };
}
