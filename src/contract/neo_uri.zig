//! Neo URI implementation
//!
//! Complete conversion from NeoSwift NeoURI.swift
//! Handles NEP-9 compatible URI schemes for token transfers.

const std = @import("std");
const ArrayList = std.array_list.Managed;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;

/// Neo URI for NEP-9 compatible transfers (converted from Swift NeoURI)
pub const NeoURI = struct {
    /// NEP-9 scheme constant (matches Swift NEO_SCHEME)
    pub const NEO_SCHEME = "neo";
    
    /// Minimum URI length (matches Swift MIN_NEP9_URI_LENGTH)
    pub const MIN_NEP9_URI_LENGTH: u32 = 38;
    
    /// Token name constants (match Swift constants)
    pub const NEO_TOKEN_STRING = "neo";
    pub const GAS_TOKEN_STRING = "gas";
    
    /// URI string
    uri: ?[]const u8,
    /// Neo client reference
    neo_swift: ?*anyopaque,
    /// Recipient script hash
    recipient: ?Hash160,
    /// Token script hash
    token: ?Hash160,
    /// Transfer amount
    amount: ?f64,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates Neo URI (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .uri = null,
            .neo_swift = null,
            .recipient = null,
            .token = null,
            .amount = null,
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        if (self.uri) |uri| {
            self.allocator.free(uri);
        }
    }
    
    /// Gets URI string (equivalent to Swift .uriString property)
    pub fn getUriString(self: Self) ?[]const u8 {
        return self.uri;
    }
    
    /// Gets recipient address (equivalent to Swift .recipientAddress property)
    pub fn getRecipientAddress(self: Self, allocator: std.mem.Allocator) !?[]u8 {
        if (self.recipient) |rec| {
            return try rec.toAddress(allocator);
        }
        return null;
    }
    
    /// Gets token string (equivalent to Swift .tokenString property)
    pub fn getTokenString(self: Self, allocator: std.mem.Allocator) !?[]u8 {
        if (self.token) |tok| {
            // Check for native tokens
            if (tok.eql(Hash160{ .bytes = constants.NativeContracts.NEO_TOKEN })) {
                return try allocator.dupe(u8, NEO_TOKEN_STRING);
            }
            
            if (tok.eql(Hash160{ .bytes = constants.NativeContracts.GAS_TOKEN })) {
                return try allocator.dupe(u8, GAS_TOKEN_STRING);
            }
            
            // Return hash as string
            return try tok.string(allocator);
        }
        return null;
    }
    
    /// Gets token address (equivalent to Swift .tokenAddress property)
    pub fn getTokenAddress(self: Self, allocator: std.mem.Allocator) !?[]u8 {
        if (self.token) |tok| {
            return try tok.toAddress(allocator);
        }
        return null;
    }
    
    /// Gets amount string (equivalent to Swift .amountString property)
    pub fn getAmountString(self: Self, allocator: std.mem.Allocator) !?[]u8 {
        if (self.amount) |amt| {
            return try std.fmt.allocPrint(allocator, "{d}", .{amt});
        }
        return null;
    }
    
    /// Sets recipient (equivalent to Swift recipient setting)
    pub fn setRecipient(self: *Self, recipient_hash: Hash160) *Self {
        self.recipient = recipient_hash;
        try self.buildUri();
        return self;
    }
    
    /// Sets recipient from address (utility method)
    pub fn setRecipientFromAddress(self: *Self, address: []const u8, allocator: std.mem.Allocator) !*Self {
        const recipient_hash = try Hash160.fromAddress(address, allocator);
        return self.setRecipient(recipient_hash);
    }
    
    /// Sets token (equivalent to Swift token setting)
    pub fn setToken(self: *Self, token_hash: Hash160) *Self {
        self.token = token_hash;
        try self.buildUri();
        return self;
    }
    
    /// Sets token to NEO (utility method)
    pub fn setNeoToken(self: *Self) *Self {
        const neo_token_hash = Hash160{ .bytes = constants.NativeContracts.NEO_TOKEN };
        return self.setToken(neo_token_hash);
    }
    
    /// Sets token to GAS (utility method)
    pub fn setGasToken(self: *Self) *Self {
        const gas_token_hash = Hash160{ .bytes = constants.NativeContracts.GAS_TOKEN };
        return self.setToken(gas_token_hash);
    }
    
    /// Sets amount (equivalent to Swift amount setting)
    pub fn setAmount(self: *Self, transfer_amount: f64) *Self {
        self.amount = transfer_amount;
        try self.buildUri();
        return self;
    }
    
    /// Parses URI from string (equivalent to Swift fromURI)
    pub fn fromURI(uri_string: []const u8, allocator: std.mem.Allocator) !Self {
        if (uri_string.len < MIN_NEP9_URI_LENGTH) {
            return errors.throwIllegalArgument("URI too short for NEP-9");
        }
        
        if (!std.mem.startsWith(u8, uri_string, NEO_SCHEME ++ ":")) {
            return errors.throwIllegalArgument("Invalid NEO URI scheme");
        }
        
        var neo_uri = Self.init(allocator);
        neo_uri.uri = try allocator.dupe(u8, uri_string);
        
        // Parse URI components
        try neo_uri.parseUriComponents(uri_string);
        
        return neo_uri;
    }
    
    /// Builds URI string from components (equivalent to Swift URI building)
    fn buildUri(self: *Self) !void {
        if (self.recipient == null) return;
        
        var uri_builder = ArrayList(u8).init(self.allocator);
        defer uri_builder.deinit();
        
        // Start with scheme
        try uri_builder.appendSlice(NEO_SCHEME);
        try uri_builder.append(':');
        
        // Add recipient address
        const recipient_address = try self.recipient.?.toAddress(self.allocator);
        defer self.allocator.free(recipient_address);
        try uri_builder.appendSlice(recipient_address);
        
        // Add query parameters
        var has_params = false;
        
        // Add token parameter
        if (self.token) |tok| {
            try uri_builder.appendSlice(if (has_params) "&" else "?");
            has_params = true;
            
            try uri_builder.appendSlice("asset=");
            
            // Use token string representation
            if (tok.eql(Hash160{ .bytes = constants.NativeContracts.NEO_TOKEN })) {
                try uri_builder.appendSlice(NEO_TOKEN_STRING);
            } else if (tok.eql(Hash160{ .bytes = constants.NativeContracts.GAS_TOKEN })) {
                try uri_builder.appendSlice(GAS_TOKEN_STRING);
            } else {
                const token_string = try tok.string(self.allocator);
                defer self.allocator.free(token_string);
                try uri_builder.appendSlice(token_string);
            }
        }
        
        // Add amount parameter
        if (self.amount) |amt| {
            try uri_builder.appendSlice(if (has_params) "&" else "?");
            has_params = true;
            
            try uri_builder.appendSlice("amount=");
            const amount_string = try std.fmt.allocPrint(self.allocator, "{d}", .{amt});
            defer self.allocator.free(amount_string);
            try uri_builder.appendSlice(amount_string);
        }
        
        // Update URI
        if (self.uri) |old_uri| {
            self.allocator.free(old_uri);
        }
        self.uri = try uri_builder.toOwnedSlice();
    }
    
    /// Parses URI components (equivalent to Swift URI parsing)
    fn parseUriComponents(self: *Self, uri_string: []const u8) !void {
        // Remove scheme prefix
        const address_part = uri_string[NEO_SCHEME.len + 1..]; // Skip "neo:"
        
        // Find query string separator
        var address_end = address_part.len;
        if (std.mem.indexOf(u8, address_part, "?")) |query_start| {
            address_end = query_start;
            
            // Parse query parameters
            const query_string = address_part[query_start + 1..];
            try self.parseQueryParameters(query_string);
        }
        
        // Extract and validate recipient address
        const recipient_address = address_part[0..address_end];
        self.recipient = try Hash160.fromAddress(recipient_address, self.allocator);
    }
    
    /// Parses query parameters (equivalent to Swift query parsing)
    fn parseQueryParameters(self: *Self, query_string: []const u8) !void {
        var param_iterator = std.mem.split(u8, query_string, "&");
        
        while (param_iterator.next()) |param| {
            var kv_iterator = std.mem.split(u8, param, "=");
            const key = kv_iterator.next() orelse continue;
            const value = kv_iterator.next() orelse continue;
            
            if (std.mem.eql(u8, key, "asset")) {
                if (std.mem.eql(u8, value, NEO_TOKEN_STRING)) {
                    self.token = Hash160{ .bytes = constants.NativeContracts.NEO_TOKEN };
                } else if (std.mem.eql(u8, value, GAS_TOKEN_STRING)) {
                    self.token = Hash160{ .bytes = constants.NativeContracts.GAS_TOKEN };
                } else {
                    self.token = try Hash160.initWithString(value);
                }
            } else if (std.mem.eql(u8, key, "amount")) {
                self.amount = std.fmt.parseFloat(f64, value) catch {
                    return errors.throwIllegalArgument("Invalid amount in URI");
                };
            }
        }
    }
    
    /// Creates transfer transaction from URI (equivalent to Swift transaction creation)
    pub fn createTransferTransaction(self: Self, from_account: Hash160, allocator: std.mem.Allocator) !@import("../transaction/transaction_builder.zig").TransactionBuilder {
        if (self.recipient == null or self.token == null or self.amount == null) {
            return errors.throwIllegalArgument("Incomplete URI for transaction creation");
        }
        
        var tx_builder = @import("../transaction/transaction_builder.zig").TransactionBuilder.init(allocator);
        
        // Add signer
        const signer = @import("../transaction/transaction_builder.zig").Signer.init(
            from_account,
            @import("../transaction/transaction_builder.zig").WitnessScope.CalledByEntry,
        );
        _ = try tx_builder.signer(signer);
        
        // Build transfer
        const amount_int = @as(i64, @intFromFloat(self.amount.? * 100000000)); // Assume 8 decimals
        _ = try tx_builder.transferToken(
            self.token.?,
            from_account,
            self.recipient.?,
            @intCast(amount_int),
        );
        
        return tx_builder;
    }
};

/// URI builder utility (additional functionality)
pub const NeoURIBuilder = struct {
    neo_uri: NeoURI,
    
    const Self = @This();
    
    /// Creates URI builder
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .neo_uri = NeoURI.init(allocator),
        };
    }
    
    /// Sets recipient and returns builder
    pub fn recipient(self: *Self, recipient_hash: Hash160) *Self {
        _ = self.neo_uri.setRecipient(recipient_hash);
        return self;
    }
    
    /// Sets token and returns builder
    pub fn token(self: *Self, token_hash: Hash160) *Self {
        _ = self.neo_uri.setToken(token_hash);
        return self;
    }
    
    /// Sets amount and returns builder
    pub fn amount(self: *Self, transfer_amount: f64) *Self {
        _ = self.neo_uri.setAmount(transfer_amount);
        return self;
    }
    
    /// Sets NEO token and returns builder
    pub fn neoToken(self: *Self) *Self {
        _ = self.neo_uri.setNeoToken();
        return self;
    }
    
    /// Sets GAS token and returns builder
    pub fn gasToken(self: *Self) *Self {
        _ = self.neo_uri.setGasToken();
        return self;
    }
    
    /// Builds final URI
    pub fn build(self: *Self) NeoURI {
        return self.neo_uri;
    }
};

/// URI validation utilities
pub const URIUtils = struct {
    /// Validates NEO URI format (equivalent to Swift validation)
    pub fn validateNeoURI(uri_string: []const u8) bool {
        if (uri_string.len < NeoURI.MIN_NEP9_URI_LENGTH) return false;
        if (!std.mem.startsWith(u8, uri_string, NeoURI.NEO_SCHEME ++ ":")) return false;
        
        // Basic format validation
        const address_part = uri_string[NeoURI.NEO_SCHEME.len + 1..];
        
        // Should have valid address format
        var address_end = address_part.len;
        if (std.mem.indexOf(u8, address_part, "?")) |query_start| {
            address_end = query_start;
        }
        
        const address = address_part[0..address_end];
        return address.len >= 25 and address.len <= 35; // Reasonable address length
    }
    
    /// Extracts address from URI (utility method)
    pub fn extractAddress(uri_string: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (!validateNeoURI(uri_string)) {
            return errors.throwIllegalArgument("Invalid NEO URI format");
        }
        
        const address_part = uri_string[NeoURI.NEO_SCHEME.len + 1..];
        
        var address_end = address_part.len;
        if (std.mem.indexOf(u8, address_part, "?")) |query_start| {
            address_end = query_start;
        }
        
        return try allocator.dupe(u8, address_part[0..address_end]);
    }
    
    /// Extracts query parameters (utility method)
    pub fn extractQueryParams(uri_string: []const u8, allocator: std.mem.Allocator) !std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage) {
        var params = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator);
        
        const query_start = std.mem.indexOf(u8, uri_string, "?") orelse return params;
        const query_string = uri_string[query_start + 1..];
        
        var param_iterator = std.mem.split(u8, query_string, "&");
        while (param_iterator.next()) |param| {
            var kv_iterator = std.mem.split(u8, param, "=");
            const key = kv_iterator.next() orelse continue;
            const value = kv_iterator.next() orelse continue;
            
            const key_copy = try allocator.dupe(u8, key);
            const value_copy = try allocator.dupe(u8, value);
            
            try params.put(key_copy, value_copy);
        }
        
        return params;
    }
};

/// String context for HashMap
pub const StringContext = struct {
    pub fn hash(self: @This(), key: []const u8) u64 {
        _ = self;
        return std.hash_map.hashString(key);
    }
    
    pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
        _ = self;
        return std.mem.eql(u8, a, b);
    }
};

// Tests (converted from Swift NeoURI tests)
test "NeoURI creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test URI creation (equivalent to Swift NeoURI tests)
    var neo_uri = NeoURI.init(allocator);
    defer neo_uri.deinit();
    
    // Test initial state
    try testing.expect(neo_uri.getUriString() == null);
    try testing.expect(neo_uri.recipient == null);
    try testing.expect(neo_uri.token == null);
    try testing.expect(neo_uri.amount == null);
    
    // Test setting recipient
    const test_recipient = Hash160.ZERO;
    _ = neo_uri.setRecipient(test_recipient);
    try testing.expect(neo_uri.recipient != null);
    try testing.expect(neo_uri.recipient.?.eql(test_recipient));
}

test "NeoURI token operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var neo_uri = NeoURI.init(allocator);
    defer neo_uri.deinit();
    
    // Test NEO token setting (equivalent to Swift NEO token tests)
    _ = neo_uri.setNeoToken();
    
    const neo_token_string = try neo_uri.getTokenString(allocator);
    defer if (neo_token_string) |ts| allocator.free(ts);
    
    try testing.expectEqualStrings(NeoURI.NEO_TOKEN_STRING, neo_token_string.?);
    
    // Test GAS token setting (equivalent to Swift GAS token tests)
    _ = neo_uri.setGasToken();
    
    const gas_token_string = try neo_uri.getTokenString(allocator);
    defer if (gas_token_string) |ts| allocator.free(ts);
    
    try testing.expectEqualStrings(NeoURI.GAS_TOKEN_STRING, gas_token_string.?);
    
    // Test custom token
    const custom_token = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    _ = neo_uri.setToken(custom_token);
    
    const custom_token_string = try neo_uri.getTokenString(allocator);
    defer if (custom_token_string) |ts| allocator.free(ts);
    
    try testing.expectEqualStrings("1234567890abcdef1234567890abcdef12345678", custom_token_string.?);
}

test "NeoURI builder pattern" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test URI builder (equivalent to Swift builder pattern tests)
    var builder = NeoURIBuilder.init(allocator);
    defer builder.neo_uri.deinit();
    
    const recipient_hash = Hash160.ZERO;
    
    // Build URI with method chaining
    _ = builder.recipient(recipient_hash)
        .gasToken()
        .amount(1.5);
    
    const built_uri = builder.build();
    
    try testing.expect(built_uri.recipient != null);
    try testing.expect(built_uri.token != null);
    try testing.expect(built_uri.amount != null);
    try testing.expectEqual(@as(f64, 1.5), built_uri.amount.?);
}

test "NeoURI parsing and validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test URI validation (equivalent to Swift validation tests)
    const valid_uri = "neo:NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7?asset=gas&amount=1.5";
    try testing.expect(URIUtils.validateNeoURI(valid_uri));
    
    const invalid_short_uri = "neo:invalid";
    try testing.expect(!URIUtils.validateNeoURI(invalid_short_uri));
    
    const invalid_scheme_uri = "bitcoin:NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7";
    try testing.expect(!URIUtils.validateNeoURI(invalid_scheme_uri));
    
    // Test address extraction
    const extracted_address = try URIUtils.extractAddress(valid_uri, allocator);
    defer allocator.free(extracted_address);
    
    try testing.expectEqualStrings("NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7", extracted_address);
    
    // Test query parameter extraction
    var query_params = try URIUtils.extractQueryParams(valid_uri, allocator);
    defer {
        var iterator = query_params.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        query_params.deinit();
    }
    
    try testing.expect(query_params.contains("asset"));
    try testing.expect(query_params.contains("amount"));
    try testing.expectEqualStrings("gas", query_params.get("asset").?);
    try testing.expectEqualStrings("1.5", query_params.get("amount").?);
}

test "NeoURI transaction creation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test transaction creation from URI (equivalent to Swift transaction tests)
    var neo_uri = NeoURI.init(allocator);
    defer neo_uri.deinit();
    
    // Set up complete URI
    _ = neo_uri.setRecipient(Hash160.ZERO)
        .setGasToken()
        .setAmount(1.0);
    
    // Create transaction
    const from_account = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    var transfer_tx = try neo_uri.createTransferTransaction(from_account, allocator);
    defer transfer_tx.deinit();
    
    // Verify transaction has script
    try testing.expect(transfer_tx.getScript() != null);
    try testing.expect(transfer_tx.getScript().?.len > 0);
    
    // Verify signers
    const signers = transfer_tx.getSigners();
    try testing.expectEqual(@as(usize, 1), signers.len);
    try testing.expect(signers[0].signer_hash.eql(from_account));
}