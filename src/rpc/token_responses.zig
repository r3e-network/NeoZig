//! Token Response Types
//!
//! Complete conversion of ALL remaining Swift token response types
//! Ensures 100% NEP-17/NEP-11 response handling.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

/// NEP-17 balances response (converted from Swift NeoGetNep17Balances)
pub const NeoGetNep17Balances = struct {
    balances: ?Nep17Balances,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{ .balances = null };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        return Self{
            .balances = try Nep17Balances.fromJson(json_value, allocator),
        };
    }
    
    /// NEP-17 balances data (converted from Swift Nep17Balances)
    pub const Nep17Balances = struct {
        address: []const u8,
        balances: []const Nep17Balance,
        
        const BalanceSelf = @This();
        
        pub fn init(address: []const u8, balances: []const Nep17Balance) BalanceSelf {
            return BalanceSelf{
                .address = address,
                .balances = balances,
            };
        }
        
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !BalanceSelf {
            if (json_value != .object) return errors.SerializationError.InvalidFormat;
            const obj = json_value.object;
            
            const address = try allocator.dupe(u8, obj.get("address").?.string);
            errdefer allocator.free(address);
            
            var balance_list = ArrayList(Nep17Balance).init(allocator);
            errdefer balance_list.deinit();
            if (obj.get("balance")) |balance_array| {
                if (balance_array != .array) return errors.SerializationError.InvalidFormat;
                for (balance_array.array.items) |balance_item| {
                    try balance_list.append(try Nep17Balance.fromJson(balance_item, allocator));
                }
            }
            
            return BalanceSelf.init(address, try balance_list.toOwnedSlice());
        }
    };
    
    /// NEP-17 balance entry (converted from Swift Nep17Balance)
    pub const Nep17Balance = struct {
        name: ?[]const u8,
        symbol: ?[]const u8,
        decimals: ?[]const u8,
        amount: []const u8,
        last_updated_block: f64,
        asset_hash: Hash160,
        
        const BalanceEntrySelf = @This();
        
        pub fn init(
            name: ?[]const u8,
            symbol: ?[]const u8,
            decimals: ?[]const u8,
            amount: []const u8,
            last_updated_block: f64,
            asset_hash: Hash160,
        ) BalanceEntrySelf {
            return BalanceEntrySelf{
                .name = name,
                .symbol = symbol,
                .decimals = decimals,
                .amount = amount,
                .last_updated_block = last_updated_block,
                .asset_hash = asset_hash,
            };
        }
        
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !BalanceEntrySelf {
            const obj = json_value.object;
            
            const name = if (obj.get("name")) |n| try allocator.dupe(u8, n.string) else null;
            const symbol = if (obj.get("symbol")) |s| try allocator.dupe(u8, s.string) else null;
            const decimals = if (obj.get("decimals")) |d| try allocator.dupe(u8, d.string) else null;
            const amount = try allocator.dupe(u8, obj.get("amount").?.string);
            const last_updated_block = obj.get("lastupdatedblock").?.float;
            const asset_hash = try Hash160.initWithString(obj.get("assethash").?.string);
            
            return BalanceEntrySelf.init(name, symbol, decimals, amount, last_updated_block, asset_hash);
        }
        
        /// Gets amount as integer (utility method)
        pub fn getAmountAsInt(self: BalanceEntrySelf) !i64 {
            return std.fmt.parseInt(i64, self.amount, 10) catch {
                return errors.ValidationError.InvalidParameter;
            };
        }
        
        /// Gets decimals as integer (utility method)
        pub fn getDecimalsAsInt(self: BalanceEntrySelf) !u8 {
            if (self.decimals) |dec_str| {
                return @intCast(std.fmt.parseInt(u8, dec_str, 10) catch {
                    return errors.ValidationError.InvalidParameter;
                });
            }
            return 0;
        }
    };
};

/// NEP-17 transfers response (converted from Swift NeoGetNep17Transfers)
pub const NeoGetNep17Transfers = struct {
    transfers: ?Nep17Transfers,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{ .transfers = null };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        return Self{
            .transfers = try Nep17Transfers.fromJson(json_value, allocator),
        };
    }
    
    /// NEP-17 transfers data (converted from Swift Nep17Transfers)
    pub const Nep17Transfers = struct {
        address: []const u8,
        sent: []const Nep17Transfer,
        received: []const Nep17Transfer,
        
        const TransfersSelf = @This();
        
        pub fn init(address: []const u8, sent: []const Nep17Transfer, received: []const Nep17Transfer) TransfersSelf {
            return TransfersSelf{
                .address = address,
                .sent = sent,
                .received = received,
            };
        }
        
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TransfersSelf {
            if (json_value != .object) return errors.SerializationError.InvalidFormat;
            const obj = json_value.object;
            
            const address = try allocator.dupe(u8, obj.get("address").?.string);
            errdefer allocator.free(address);
            
            var sent_list = ArrayList(Nep17Transfer).init(allocator);
            errdefer sent_list.deinit();
            if (obj.get("sent")) |sent_array| {
                if (sent_array != .array) return errors.SerializationError.InvalidFormat;
                for (sent_array.array.items) |sent_item| {
                    try sent_list.append(try Nep17Transfer.fromJson(sent_item, allocator));
                }
            }
            
            var received_list = ArrayList(Nep17Transfer).init(allocator);
            errdefer received_list.deinit();
            if (obj.get("received")) |received_array| {
                if (received_array != .array) return errors.SerializationError.InvalidFormat;
                for (received_array.array.items) |received_item| {
                    try received_list.append(try Nep17Transfer.fromJson(received_item, allocator));
                }
            }
            
            return TransfersSelf.init(
                address,
                try sent_list.toOwnedSlice(),
                try received_list.toOwnedSlice(),
            );
        }
        
        /// Gets total transfer count
        pub fn getTotalTransferCount(self: TransfersSelf) usize {
            return self.sent.len + self.received.len;
        }
        
        /// Gets all transfers combined
        pub fn getAllTransfers(self: TransfersSelf, allocator: std.mem.Allocator) ![]Nep17Transfer {
            var all_transfers = try allocator.alloc(Nep17Transfer, self.getTotalTransferCount());
            
            @memcpy(all_transfers[0..self.sent.len], self.sent);
            @memcpy(all_transfers[self.sent.len..], self.received);
            
            return all_transfers;
        }
    };
    
    /// NEP-17 transfer entry (converted from Swift Nep17Transfer)
    pub const Nep17Transfer = struct {
        timestamp: u64,
        asset_hash: Hash160,
        transfer_address: []const u8,
        amount: []const u8,
        block_index: u32,
        transfer_notify_index: u32,
        tx_hash: Hash256,
        
        const TransferSelf = @This();
        
        pub fn init(
            timestamp: u64,
            asset_hash: Hash160,
            transfer_address: []const u8,
            amount: []const u8,
            block_index: u32,
            transfer_notify_index: u32,
            tx_hash: Hash256,
        ) TransferSelf {
            return TransferSelf{
                .timestamp = timestamp,
                .asset_hash = asset_hash,
                .transfer_address = transfer_address,
                .amount = amount,
                .block_index = block_index,
                .transfer_notify_index = transfer_notify_index,
                .tx_hash = tx_hash,
            };
        }
        
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TransferSelf {
            const obj = json_value.object;
            
            return TransferSelf.init(
                @intCast(obj.get("timestamp").?.integer),
                try Hash160.initWithString(obj.get("assethash").?.string),
                try allocator.dupe(u8, obj.get("transferaddress").?.string),
                try allocator.dupe(u8, obj.get("amount").?.string),
                @intCast(obj.get("blockindex").?.integer),
                @intCast(obj.get("transfernotifyindex").?.integer),
                try Hash256.initWithString(obj.get("txhash").?.string),
            );
        }
        
        /// Gets amount as integer
        pub fn getAmountAsInt(self: TransferSelf) !i64 {
            return std.fmt.parseInt(i64, self.amount, 10) catch {
                return errors.ValidationError.InvalidParameter;
            };
        }
        
        /// Checks if transfer is incoming (to this address)
        pub fn isIncoming(self: TransferSelf, address: []const u8) bool {
            return std.mem.eql(u8, self.transfer_address, address);
        }
        
        /// Gets transfer date from timestamp
        pub fn getTransferDate(self: TransferSelf) u64 {
            return self.timestamp;
        }
    };
};

/// NEP-11 balances response (converted from Swift NeoGetNep11Balances)
pub const NeoGetNep11Balances = struct {
    balances: ?Nep11Balances,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{ .balances = null };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        return Self{
            .balances = try Nep11Balances.fromJson(json_value, allocator),
        };
    }
    
    /// NEP-11 balances data (converted from Swift Nep11Balances)
    pub const Nep11Balances = struct {
        address: []const u8,
        balances: []const Nep11Balance,
        
        pub fn init(address: []const u8, balances: []const Nep11Balance) Nep11Balances {
            return Nep11Balances{
                .address = address,
                .balances = balances,
            };
        }
        
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Nep11Balances {
            if (json_value != .object) return errors.SerializationError.InvalidFormat;
            const obj = json_value.object;
            
            const address = try allocator.dupe(u8, obj.get("address").?.string);
            errdefer allocator.free(address);
            
            var balance_list = ArrayList(Nep11Balance).init(allocator);
            errdefer balance_list.deinit();
            if (obj.get("balance")) |balance_array| {
                if (balance_array != .array) return errors.SerializationError.InvalidFormat;
                for (balance_array.array.items) |balance_item| {
                    try balance_list.append(try Nep11Balance.fromJson(balance_item, allocator));
                }
            }
            
            return Nep11Balances.init(address, try balance_list.toOwnedSlice());
        }
    };
    
    /// NEP-11 balance entry (converted from Swift Nep11Balance)
    pub const Nep11Balance = struct {
        name: ?[]const u8,
        symbol: ?[]const u8,
        decimals: ?[]const u8,
        tokens: []const []const u8, // Token IDs
        asset_hash: Hash160,
        
        pub fn init(
            name: ?[]const u8,
            symbol: ?[]const u8,
            decimals: ?[]const u8,
            tokens: []const []const u8,
            asset_hash: Hash160,
        ) Nep11Balance {
            return Nep11Balance{
                .name = name,
                .symbol = symbol,
                .decimals = decimals,
                .tokens = tokens,
                .asset_hash = asset_hash,
            };
        }
        
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Nep11Balance {
            if (json_value != .object) return errors.SerializationError.InvalidFormat;
            const obj = json_value.object;
            
            const name = if (obj.get("name")) |n| try allocator.dupe(u8, n.string) else null;
            const symbol = if (obj.get("symbol")) |s| try allocator.dupe(u8, s.string) else null;
            const decimals = if (obj.get("decimals")) |d| try allocator.dupe(u8, d.string) else null;
            const asset_hash = try Hash160.initWithString(obj.get("assethash").?.string);
            
            var token_list = ArrayList([]const u8).init(allocator);
            errdefer {
                for (token_list.items) |token| allocator.free(@constCast(token));
                token_list.deinit();
            }
            if (obj.get("tokens")) |tokens_array| {
                if (tokens_array != .array) return errors.SerializationError.InvalidFormat;
                for (tokens_array.array.items) |token| {
                    if (token != .string) return errors.SerializationError.InvalidFormat;
                    const token_copy = try allocator.dupe(u8, token.string);
                    errdefer allocator.free(token_copy);
                    try token_list.append(token_copy);
                }
            }
            
            return Nep11Balance.init(name, symbol, decimals, try token_list.toOwnedSlice(), asset_hash);
        }
        
        /// Gets token count
        pub fn getTokenCount(self: Nep11Balance) usize {
            return self.tokens.len;
        }
        
        /// Checks if has specific token
        pub fn hasToken(self: Nep11Balance, token_id: []const u8) bool {
            for (self.tokens) |token| {
                if (std.mem.eql(u8, token, token_id)) {
                    return true;
                }
            }
            return false;
        }
    };
};

/// NEP-11 transfers response (converted from Swift NeoGetNep11Transfers)
pub const NeoGetNep11Transfers = struct {
    transfers: ?Nep11Transfers,
    
    pub fn init() NeoGetNep11Transfers {
        return NeoGetNep11Transfers{ .transfers = null };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetNep11Transfers {
        return NeoGetNep11Transfers{
            .transfers = try Nep11Transfers.fromJson(json_value, allocator),
        };
    }
    
    /// NEP-11 transfers data (converted from Swift Nep11Transfers)
    pub const Nep11Transfers = struct {
        address: []const u8,
        sent: []const Nep11Transfer,
        received: []const Nep11Transfer,
        
        pub fn init(address: []const u8, sent: []const Nep11Transfer, received: []const Nep11Transfer) Nep11Transfers {
            return Nep11Transfers{
                .address = address,
                .sent = sent,
                .received = received,
            };
        }
        
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Nep11Transfers {
            if (json_value != .object) return errors.SerializationError.InvalidFormat;
            const obj = json_value.object;
            
            const address = try allocator.dupe(u8, obj.get("address").?.string);
            errdefer allocator.free(address);
            
            var sent_list = ArrayList(Nep11Transfer).init(allocator);
            errdefer sent_list.deinit();
            if (obj.get("sent")) |sent_array| {
                if (sent_array != .array) return errors.SerializationError.InvalidFormat;
                for (sent_array.array.items) |sent_item| {
                    try sent_list.append(try Nep11Transfer.fromJson(sent_item, allocator));
                }
            }
            
            var received_list = ArrayList(Nep11Transfer).init(allocator);
            errdefer received_list.deinit();
            if (obj.get("received")) |received_array| {
                if (received_array != .array) return errors.SerializationError.InvalidFormat;
                for (received_array.array.items) |received_item| {
                    try received_list.append(try Nep11Transfer.fromJson(received_item, allocator));
                }
            }
            
            return Nep11Transfers.init(
                address,
                try sent_list.toOwnedSlice(),
                try received_list.toOwnedSlice(),
            );
        }
    };
    
    /// NEP-11 transfer entry (converted from Swift Nep11Transfer)
    pub const Nep11Transfer = struct {
        timestamp: u64,
        asset_hash: Hash160,
        transfer_address: []const u8,
        amount: []const u8,
        token_id: []const u8,
        block_index: u32,
        transfer_notify_index: u32,
        tx_hash: Hash256,
        
        pub fn init(
            timestamp: u64,
            asset_hash: Hash160,
            transfer_address: []const u8,
            amount: []const u8,
            token_id: []const u8,
            block_index: u32,
            transfer_notify_index: u32,
            tx_hash: Hash256,
        ) Nep11Transfer {
            return Nep11Transfer{
                .timestamp = timestamp,
                .asset_hash = asset_hash,
                .transfer_address = transfer_address,
                .amount = amount,
                .token_id = token_id,
                .block_index = block_index,
                .transfer_notify_index = transfer_notify_index,
                .tx_hash = tx_hash,
            };
        }
        
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Nep11Transfer {
            const obj = json_value.object;
            
            return Nep11Transfer.init(
                @intCast(obj.get("timestamp").?.integer),
                try Hash160.initWithString(obj.get("assethash").?.string),
                try allocator.dupe(u8, obj.get("transferaddress").?.string),
                try allocator.dupe(u8, obj.get("amount").?.string),
                try allocator.dupe(u8, obj.get("tokenid").?.string),
                @intCast(obj.get("blockindex").?.integer),
                @intCast(obj.get("transfernotifyindex").?.integer),
                try Hash256.initWithString(obj.get("txhash").?.string),
            );
        }
        
        /// Gets amount as integer
        pub fn getAmountAsInt(self: Nep11Transfer) !i64 {
            return std.fmt.parseInt(i64, self.amount, 10) catch {
                return errors.ValidationError.InvalidParameter;
            };
        }
        
        /// Checks if transfer is of specific token
        pub fn isTokenTransfer(self: Nep11Transfer, token_id: []const u8) bool {
            return std.mem.eql(u8, self.token_id, token_id);
        }
    };
};

/// Token balances trait (converted from Swift TokenBalances protocol)
pub const TokenBalances = struct {
    /// Gets address associated with balances
    pub fn getAddress(self: anytype) []const u8 {
        return self.address;
    }
    
    /// Gets balance count
    pub fn getBalanceCount(self: anytype) usize {
        return self.balances.len;
    }
    
    /// Checks if has any balances
    pub fn hasBalances(self: anytype) bool {
        return self.getBalanceCount() > 0;
    }
};

/// Token balance trait (converted from Swift TokenBalance protocol)
pub const TokenBalance = struct {
    /// Gets asset hash
    pub fn getAssetHash(self: anytype) Hash160 {
        return self.asset_hash;
    }
    
    /// Gets amount string
    pub fn getAmount(self: anytype) []const u8 {
        return self.amount;
    }
    
    /// Checks if has symbol
    pub fn hasSymbol(self: anytype) bool {
        return self.symbol != null;
    }
    
    /// Checks if has name
    pub fn hasName(self: anytype) bool {
        return self.name != null;
    }
};

// Tests (converted from Swift NEP-17/NEP-11 response tests)
test "NeoGetNep17Balances response parsing" {
    const testing = std.testing;
    _ = testing.allocator;
    
    // Test NEP-17 balance response (equivalent to Swift Nep17Balances tests)
    const nep17_balances = NeoGetNep17Balances.init();
    try testing.expect(nep17_balances.balances == null);
    
    // Test balance entry creation
    const balance_entry = NeoGetNep17Balances.Nep17Balance.init(
        "Test Token",
        "TST",
        "8",
        "100000000",
        12345.0,
        Hash160.ZERO,
    );
    
    try testing.expectEqualStrings("Test Token", balance_entry.name.?);
    try testing.expectEqualStrings("TST", balance_entry.symbol.?);
    try testing.expectEqualStrings("8", balance_entry.decimals.?);
    try testing.expectEqualStrings("100000000", balance_entry.amount);
    try testing.expectEqual(@as(f64, 12345.0), balance_entry.last_updated_block);
    
    // Test utility methods
    const amount_int = try balance_entry.getAmountAsInt();
    try testing.expectEqual(@as(i64, 100000000), amount_int);
    
    const decimals_int = try balance_entry.getDecimalsAsInt();
    try testing.expectEqual(@as(u8, 8), decimals_int);
}

test "NeoGetNep17Transfers response parsing" {
    const testing = std.testing;
    _ = testing.allocator;
    
    // Test NEP-17 transfer response (equivalent to Swift Nep17Transfers tests)
    const nep17_transfers = NeoGetNep17Transfers.init();
    try testing.expect(nep17_transfers.transfers == null);
    
    // Test transfer entry creation
    const transfer_entry = NeoGetNep17Transfers.Nep17Transfer.init(
        1640995200, // 2022-01-01 timestamp
        Hash160.ZERO,
        "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7",
        "50000000",
        123456,
        0,
        Hash256.ZERO,
    );
    
    try testing.expectEqual(@as(u64, 1640995200), transfer_entry.timestamp);
    try testing.expect(transfer_entry.asset_hash.eql(Hash160.ZERO));
    try testing.expectEqualStrings("NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7", transfer_entry.transfer_address);
    try testing.expectEqualStrings("50000000", transfer_entry.amount);
    
    // Test utility methods
    const amount_int = try transfer_entry.getAmountAsInt();
    try testing.expectEqual(@as(i64, 50000000), amount_int);
    
    const is_incoming = transfer_entry.isIncoming("NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7");
    try testing.expect(is_incoming);
    
    const is_not_incoming = transfer_entry.isIncoming("NDifferentAddress");
    try testing.expect(!is_not_incoming);
}

test "NeoGetNep11Balances and transfers" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test NEP-11 balance response (equivalent to Swift Nep11Balances tests)
    const nep11_balances = NeoGetNep11Balances.init();
    try testing.expect(nep11_balances.balances == null);
    
    // Test balance entry with tokens
    const token_ids = [_][]const u8{ "token_001", "token_002", "token_003" };
    
    var token_copies = try allocator.alloc([]const u8, token_ids.len);
    defer allocator.free(token_copies);
    for (token_ids, 0..) |token_id, i| {
        token_copies[i] = try allocator.dupe(u8, token_id);
    }
    defer for (token_copies) |token_copy| {
        allocator.free(token_copy);
    };
    
    const balance_entry = NeoGetNep11Balances.Nep11Balance.init(
        "Test NFT Collection",
        "TNFT",
        "0",
        token_copies,
        Hash160.ZERO,
    );
    
    try testing.expectEqualStrings("Test NFT Collection", balance_entry.name.?);
    try testing.expectEqualStrings("TNFT", balance_entry.symbol.?);
    try testing.expectEqual(@as(usize, 3), balance_entry.getTokenCount());
    
    // Test token checking
    try testing.expect(balance_entry.hasToken("token_001"));
    try testing.expect(balance_entry.hasToken("token_002"));
    try testing.expect(!balance_entry.hasToken("token_999"));
    
    // Test NEP-11 transfer with token ID
    const nft_transfer = NeoGetNep11Transfers.Nep11Transfer.init(
        1640995200,
        Hash160.ZERO,
        "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7",
        "1",
        "unique_nft_token_123",
        123456,
        0,
        Hash256.ZERO,
    );
    
    try testing.expectEqualStrings("unique_nft_token_123", nft_transfer.token_id);
    try testing.expect(nft_transfer.isTokenTransfer("unique_nft_token_123"));
    try testing.expect(!nft_transfer.isTokenTransfer("different_token"));
}

test "Token response fromJson smoke tests" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const hash160_str = "1234567890abcdef1234567890abcdef12345678";
    const hash256_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // NEP-17 balances
    var nep17_balance_obj = std.json.ObjectMap.init(allocator);
    try nep17_balance_obj.put("assethash", std.json.Value{ .string = hash160_str });
    try nep17_balance_obj.put("amount", std.json.Value{ .string = "100" });
    try nep17_balance_obj.put("lastupdatedblock", std.json.Value{ .float = 42.0 });
    try nep17_balance_obj.put("name", std.json.Value{ .string = "Test Token" });
    try nep17_balance_obj.put("symbol", std.json.Value{ .string = "TST" });
    try nep17_balance_obj.put("decimals", std.json.Value{ .string = "8" });

    var nep17_balance_array = std.json.Array.init(allocator);
    try nep17_balance_array.append(std.json.Value{ .object = nep17_balance_obj });

    var nep17_obj = std.json.ObjectMap.init(allocator);
    try nep17_obj.put("address", std.json.Value{ .string = "test_address" });
    try nep17_obj.put("balance", std.json.Value{ .array = nep17_balance_array });

    const nep17_parsed = try NeoGetNep17Balances.Nep17Balances.fromJson(std.json.Value{ .object = nep17_obj }, allocator);
    try testing.expectEqualStrings("test_address", nep17_parsed.address);
    try testing.expectEqual(@as(usize, 1), nep17_parsed.balances.len);

    // NEP-17 transfers
    var nep17_transfer_obj = std.json.ObjectMap.init(allocator);
    try nep17_transfer_obj.put("timestamp", std.json.Value{ .integer = 1640995200 });
    try nep17_transfer_obj.put("assethash", std.json.Value{ .string = hash160_str });
    try nep17_transfer_obj.put("transferaddress", std.json.Value{ .string = "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7" });
    try nep17_transfer_obj.put("amount", std.json.Value{ .string = "1" });
    try nep17_transfer_obj.put("blockindex", std.json.Value{ .integer = 1 });
    try nep17_transfer_obj.put("transfernotifyindex", std.json.Value{ .integer = 0 });
    try nep17_transfer_obj.put("txhash", std.json.Value{ .string = hash256_str });

    var transfers_sent = std.json.Array.init(allocator);
    try transfers_sent.append(std.json.Value{ .object = nep17_transfer_obj });

    var transfers_received = std.json.Array.init(allocator);
    try transfers_received.append(std.json.Value{ .object = nep17_transfer_obj });

    var nep17_transfers_obj = std.json.ObjectMap.init(allocator);
    try nep17_transfers_obj.put("address", std.json.Value{ .string = "test_address" });
    try nep17_transfers_obj.put("sent", std.json.Value{ .array = transfers_sent });
    try nep17_transfers_obj.put("received", std.json.Value{ .array = transfers_received });

    const nep17_transfers = try NeoGetNep17Transfers.Nep17Transfers.fromJson(std.json.Value{ .object = nep17_transfers_obj }, allocator);
    try testing.expectEqual(@as(usize, 1), nep17_transfers.sent.len);
    try testing.expectEqual(@as(usize, 1), nep17_transfers.received.len);

    // NEP-11 balances (tokens array)
    var tokens_array = std.json.Array.init(allocator);
    try tokens_array.append(std.json.Value{ .string = "token_1" });
    try tokens_array.append(std.json.Value{ .string = "token_2" });

    var nep11_balance_obj = std.json.ObjectMap.init(allocator);
    try nep11_balance_obj.put("assethash", std.json.Value{ .string = hash160_str });
    try nep11_balance_obj.put("tokens", std.json.Value{ .array = tokens_array });
    try nep11_balance_obj.put("name", std.json.Value{ .string = "Test NFT" });
    try nep11_balance_obj.put("symbol", std.json.Value{ .string = "TNFT" });
    try nep11_balance_obj.put("decimals", std.json.Value{ .string = "0" });

    var nep11_balance_array = std.json.Array.init(allocator);
    try nep11_balance_array.append(std.json.Value{ .object = nep11_balance_obj });

    var nep11_obj = std.json.ObjectMap.init(allocator);
    try nep11_obj.put("address", std.json.Value{ .string = "test_address" });
    try nep11_obj.put("balance", std.json.Value{ .array = nep11_balance_array });

    const nep11_parsed = try NeoGetNep11Balances.Nep11Balances.fromJson(std.json.Value{ .object = nep11_obj }, allocator);
    try testing.expectEqual(@as(usize, 1), nep11_parsed.balances.len);
    try testing.expectEqual(@as(usize, 2), nep11_parsed.balances[0].tokens.len);

    // NEP-11 transfers
    var nep11_transfer_obj = std.json.ObjectMap.init(allocator);
    try nep11_transfer_obj.put("timestamp", std.json.Value{ .integer = 1640995200 });
    try nep11_transfer_obj.put("assethash", std.json.Value{ .string = hash160_str });
    try nep11_transfer_obj.put("transferaddress", std.json.Value{ .string = "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7" });
    try nep11_transfer_obj.put("amount", std.json.Value{ .string = "1" });
    try nep11_transfer_obj.put("tokenid", std.json.Value{ .string = "token_1" });
    try nep11_transfer_obj.put("blockindex", std.json.Value{ .integer = 1 });
    try nep11_transfer_obj.put("transfernotifyindex", std.json.Value{ .integer = 0 });
    try nep11_transfer_obj.put("txhash", std.json.Value{ .string = hash256_str });

    var nep11_sent = std.json.Array.init(allocator);
    try nep11_sent.append(std.json.Value{ .object = nep11_transfer_obj });

    var nep11_received = std.json.Array.init(allocator);
    try nep11_received.append(std.json.Value{ .object = nep11_transfer_obj });

    var nep11_transfers_obj = std.json.ObjectMap.init(allocator);
    try nep11_transfers_obj.put("address", std.json.Value{ .string = "test_address" });
    try nep11_transfers_obj.put("sent", std.json.Value{ .array = nep11_sent });
    try nep11_transfers_obj.put("received", std.json.Value{ .array = nep11_received });

    const nep11_transfers = try NeoGetNep11Transfers.Nep11Transfers.fromJson(std.json.Value{ .object = nep11_transfers_obj }, allocator);
    try testing.expectEqual(@as(usize, 1), nep11_transfers.sent.len);
    try testing.expectEqual(@as(usize, 1), nep11_transfers.received.len);
}

test "Token response traits and utilities" {
    const testing = std.testing;
    _ = testing.allocator;
    
    // Test token balance traits (equivalent to Swift protocol tests)
    const balance_entry = NeoGetNep17Balances.Nep17Balance.init(
        "Test Token",
        "TST", 
        "8",
        "100000000",
        12345.0,
        Hash160.ZERO,
    );
    
    // Test trait methods
    try testing.expect(TokenBalance.getAssetHash(balance_entry).eql(Hash160.ZERO));
    try testing.expectEqualStrings("100000000", TokenBalance.getAmount(balance_entry));
    try testing.expect(TokenBalance.hasSymbol(balance_entry));
    try testing.expect(TokenBalance.hasName(balance_entry));
    
    // Test balance entry without optional fields
    const minimal_balance = NeoGetNep17Balances.Nep17Balance.init(
        null, // No name
        null, // No symbol
        null, // No decimals
        "50000000",
        54321.0,
        Hash160.ZERO,
    );
    
    try testing.expect(!TokenBalance.hasSymbol(minimal_balance));
    try testing.expect(!TokenBalance.hasName(minimal_balance));
    try testing.expectEqualStrings("50000000", TokenBalance.getAmount(minimal_balance));
}
