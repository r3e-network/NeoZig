//! RPC Response Types
//!
//! Complete conversion from NeoSwift protocol response types
//! Handles all Neo RPC response parsing and serialization.

const std = @import("std");
const ArrayList = std.ArrayList;
const json_utils = @import("../utils/json_utils.zig");

const constants = @import("../core/constants.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const errors = @import("../core/errors.zig");
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const NeoVMStateType = @import("../types/neo_vm_state_type.zig").NeoVMStateType;
const StringUtils = @import("../utils/string_extensions.zig").StringUtils;
pub const StackItem = @import("../types/stack_item.zig").StackItem;

fn stringifyJsonValue(value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
    return try std.json.stringifyAlloc(allocator, value, .{});
}

fn jsonValueToOwnedString(value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
    return switch (value) {
        .string => |str| try allocator.dupe(u8, str),
        .integer => |i| try std.fmt.allocPrint(allocator, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(allocator, "{g}", .{f}),
        .bool => |b| try allocator.dupe(u8, if (b) "true" else "false"),
        .null => try allocator.dupe(u8, ""),
        else => try stringifyJsonValue(value, allocator),
    };
}

fn parseIntFromJson(comptime T: type, value: std.json.Value) !T {
    return switch (value) {
        .integer => |i| @as(T, @intCast(i)),
        .string => |str| std.fmt.parseInt(T, str, 10) catch errors.SerializationError.InvalidFormat,
        else => errors.SerializationError.InvalidFormat,
    };
}

/// Neo block response (converted from Swift NeoBlock)
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

    /// Creates new block (equivalent to Swift init)
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

    /// Default initialization
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

    /// Parses from JSON (equivalent to Swift Codable)
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
            for (transactions_slice) |*tx| {
                tx.deinit(allocator);
            }
            allocator.free(transactions_slice);
            self.transactions = null;
        }
    }
};

/// Neo witness (converted from Swift NeoWitness)
pub const NeoWitness = struct {
    invocation: []const u8,
    verification: []const u8,

    const Self = @This();

    pub fn init(invocation: []const u8, verification: []const u8) Self {
        return Self{
            .invocation = invocation,
            .verification = verification,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        const invocation = try allocator.dupe(u8, obj.get("invocation").?.string);
        const verification = try allocator.dupe(u8, obj.get("verification").?.string);
        return Self.init(invocation, verification);
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.invocation));
        allocator.free(@constCast(self.verification));
    }
};

/// Transaction response (converted from Swift Transaction)
pub const Transaction = struct {
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

    const Self = @This();

    pub fn init() Self {
        return std.mem.zeroes(Self);
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const hash = try Hash256.initWithString(obj.get("hash").?.string);
        const size = @as(u32, @intCast(obj.get("size").?.integer));
        const version = @as(u8, @intCast(obj.get("version").?.integer));
        const nonce = @as(u32, @intCast(obj.get("nonce").?.integer));
        const sender = try allocator.dupe(u8, obj.get("sender").?.string);
        const sys_fee = try allocator.dupe(u8, obj.get("sysfee").?.string);
        const net_fee = try allocator.dupe(u8, obj.get("netfee").?.string);
        const valid_until_block = @as(u32, @intCast(obj.get("validuntilblock").?.integer));

        var signers_list = ArrayList(TransactionSigner).init(allocator);
        defer signers_list.deinit();
        if (obj.get("signers")) |signers_json| {
            for (signers_json.array.items) |signer_json| {
                try signers_list.append(try TransactionSigner.fromJson(signer_json, allocator));
            }
        }

        var attributes_list = ArrayList(TransactionAttribute).init(allocator);
        defer attributes_list.deinit();
        if (obj.get("attributes")) |attributes_json| {
            for (attributes_json.array.items) |attr_json| {
                try attributes_list.append(try TransactionAttribute.fromJson(attr_json, allocator));
            }
        }

        const script = try allocator.dupe(u8, obj.get("script").?.string);

        var witnesses_list = ArrayList(NeoWitness).init(allocator);
        defer witnesses_list.deinit();
        if (obj.get("witnesses")) |witnesses_json| {
            for (witnesses_json.array.items) |witness_json| {
                try witnesses_list.append(try NeoWitness.fromJson(witness_json, allocator));
            }
        }

        const block_hash = if (obj.get("blockhash")) |bh|
            switch (bh) {
                .string => |s| try Hash256.initWithString(s),
                .null => null,
                else => null,
            }
        else
            null;

        const confirmations = if (obj.get("confirmations")) |c|
            switch (c) {
                .integer => |i| @as(u32, @intCast(i)),
                .null => null,
                else => null,
            }
        else
            null;

        const block_time = if (obj.get("blocktime")) |bt|
            switch (bt) {
                .integer => |i| @as(u64, @intCast(i)),
                .null => null,
                else => null,
            }
        else
            null;

        const vm_state = if (obj.get("vmstate")) |vs|
            NeoVMStateType.decodeFromJson(vs) catch null
        else
            null;

        return Self{
            .hash = hash,
            .size = size,
            .version = version,
            .nonce = nonce,
            .sender = sender,
            .sys_fee = sys_fee,
            .net_fee = net_fee,
            .valid_until_block = valid_until_block,
            .signers = try signers_list.toOwnedSlice(),
            .attributes = try attributes_list.toOwnedSlice(),
            .script = script,
            .witnesses = try witnesses_list.toOwnedSlice(),
            .block_hash = block_hash,
            .confirmations = confirmations,
            .block_time = block_time,
            .vm_state = vm_state,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.sys_fee);
        allocator.free(self.net_fee);
        allocator.free(self.script);

        if (self.signers.len > 0) {
            for (self.signers) |*signer| {
                signer.deinit(allocator);
            }
            allocator.free(self.signers);
        }

        if (self.attributes.len > 0) {
            for (self.attributes) |*attribute| {
                attribute.deinit(allocator);
            }
            allocator.free(self.attributes);
        }

        if (self.witnesses.len > 0) {
            for (self.witnesses) |*witness| {
                witness.deinit(allocator);
            }
            allocator.free(self.witnesses);
        }
    }
};

/// Transaction signer (converted from Swift TransactionSigner)
pub const TransactionSigner = struct {
    account: Hash160,
    scopes: []const u8,
    allowed_contracts: ?[]Hash160,
    allowed_groups: ?[] [33]u8,
    rules: ?[]WitnessRule,

    const Self = @This();

    pub fn init() TransactionSigner {
        return std.mem.zeroes(TransactionSigner);
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const account = try Hash160.initWithString(obj.get("account").?.string);
        const scopes = try allocator.dupe(u8, obj.get("scopes").?.string);

        var allowed_contracts_slice: ?[]Hash160 = null;
        if (obj.get("allowedcontracts")) |contracts_json| {
            var contracts_list = ArrayList(Hash160).init(allocator);
            defer contracts_list.deinit();

            for (contracts_json.array.items) |contract_json| {
                try contracts_list.append(try Hash160.initWithString(contract_json.string));
            }

            allowed_contracts_slice = try contracts_list.toOwnedSlice();
        }

        var allowed_groups_slice: ?[] [33]u8 = null;
        if (obj.get("allowedgroups")) |groups_json| {
            var groups_list = ArrayList([33]u8).init(allocator);
            defer groups_list.deinit();

            for (groups_json.array.items) |group_json| {
                const group_str = group_json.string;
                if (group_str.len != 66) return errors.ValidationError.InvalidLength;
                var group_bytes: [33]u8 = undefined;
                _ = try std.fmt.hexToBytes(&group_bytes, group_str);
                try groups_list.append(group_bytes);
            }

            allowed_groups_slice = try groups_list.toOwnedSlice();
        }

        var rules_slice: ?[]WitnessRule = null;
        if (obj.get("rules")) |rules_json| {
            var rules_list = ArrayList(WitnessRule).init(allocator);
            defer rules_list.deinit();

            for (rules_json.array.items) |rule_json| {
                try rules_list.append(try WitnessRule.fromJson(rule_json, allocator));
            }

            rules_slice = try rules_list.toOwnedSlice();
        }

        return Self{
            .account = account,
            .scopes = scopes,
            .allowed_contracts = allowed_contracts_slice,
            .allowed_groups = allowed_groups_slice,
            .rules = rules_slice,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.scopes);

        if (self.allowed_contracts) |contracts| {
            allocator.free(contracts);
        }

        if (self.allowed_groups) |groups| {
            allocator.free(groups);
        }

        if (self.rules) |rules| {
            for (rules) |*rule| {
                rule.deinit(allocator);
            }
            allocator.free(rules);
        }
    }
};

/// Transaction attribute (converted from Swift TransactionAttribute)
pub const TransactionAttribute = struct {
    attribute_type: []const u8,
    value: []const u8,

    const Self = @This();

    pub fn init() TransactionAttribute {
        return TransactionAttribute{ .attribute_type = "", .value = "" };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        const attribute_type = try allocator.dupe(u8, obj.get("type").?.string);
        const value_json = obj.get("value") orelse std.json.Value{ .string = "" };

        const value = switch (value_json) {
            .string => |str| try allocator.dupe(u8, str),
            else => try stringifyJsonValue(value_json, allocator),
        };

        return TransactionAttribute{ .attribute_type = attribute_type, .value = value };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.attribute_type);
        allocator.free(self.value);
    }
};

/// Witness rule (converted from Swift WitnessRule)
pub const WitnessRule = struct {
    action: []const u8,
    condition: WitnessCondition,

    const Self = @This();

    pub fn init() WitnessRule {
        return WitnessRule{ .action = "", .condition = WitnessCondition.init() };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        const action = try allocator.dupe(u8, obj.get("action").?.string);
        const condition = try WitnessCondition.fromJson(obj.get("condition").?, allocator);
        return WitnessRule{ .action = action, .condition = condition };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.action);
        self.condition.deinit(allocator);
    }
};

/// Witness condition (converted from Swift WitnessCondition)
pub const WitnessCondition = struct {
    condition_type: []const u8,
    value: []const u8,

    const Self = @This();

    pub fn init() WitnessCondition {
        return WitnessCondition{ .condition_type = "", .value = "" };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        const condition_type = try allocator.dupe(u8, obj.get("type").?.string);
        const value_json = obj.get("value") orelse std.json.Value{ .string = "" };
        const value = switch (value_json) {
            .string => |str| try allocator.dupe(u8, str),
            else => try stringifyJsonValue(value_json, allocator),
        };
        return WitnessCondition{ .condition_type = condition_type, .value = value };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.condition_type);
        allocator.free(self.value);
    }
};

/// Invocation result (converted from Swift InvocationResult)
pub const InvocationResult = struct {
    script: []const u8,
    state: NeoVMStateType,
    gas_consumed: []const u8,
    exception: ?[]const u8,
    stack: []StackItem,
    session: ?[]const u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .script = "",
            .state = .None,
            .gas_consumed = "",
            .exception = null,
            .stack = &[_]StackItem{},
            .session = null,
        };
    }

    /// Gets first stack item (equivalent to Swift getFirstStackItem)
    pub fn getFirstStackItem(self: Self) !StackItem {
        if (self.stack.len == 0) {
            return errors.throwIllegalState("Stack is empty");
        }
        return self.stack[0];
    }

    /// Checks if invocation faulted (equivalent to Swift state checking)
    pub fn hasFaulted(self: Self) bool {
        return self.state == .Fault;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const script = try allocator.dupe(u8, obj.get("script").?.string);
        const state_value = obj.get("state") orelse return errors.SerializationError.InvalidFormat;
        const state = try NeoVMStateType.decodeFromJson(state_value);
        const gas_consumed = try allocator.dupe(u8, obj.get("gasconsumed").?.string);
        const exception = if (obj.get("exception")) |ex| try allocator.dupe(u8, ex.string) else null;

        // Parse stack items
        var stack_items = ArrayList(StackItem).init(allocator);
        defer stack_items.deinit();
        if (obj.get("stack")) |stack_array| {
            if (stack_array != .array) return errors.SerializationError.InvalidFormat;
            for (stack_array.array.items) |item| {
                var parsed_item = try StackItem.decodeFromJson(item, allocator);
                var item_guard = true;
                defer if (item_guard) parsed_item.deinit(allocator);
                try stack_items.append(parsed_item);
                item_guard = false;
            }
        }

        return Self{
            .script = script,
            .state = state,
            .gas_consumed = gas_consumed,
            .exception = exception,
            .stack = try stack_items.toOwnedSlice(),
            .session = if (obj.get("session")) |s| try allocator.dupe(u8, s.string) else null,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.script.len > 0) allocator.free(@constCast(self.script));
        if (self.gas_consumed.len > 0) allocator.free(@constCast(self.gas_consumed));

        if (self.exception) |ex| {
            if (ex.len > 0) allocator.free(@constCast(ex));
        }

        if (self.stack.len > 0) {
            for (self.stack) |*item| {
                item.deinit(allocator);
            }
            allocator.free(self.stack);
        }

        if (self.session) |sess| {
            if (sess.len > 0) allocator.free(@constCast(sess));
        }
    }
};

/// Neo version response (converted from Swift NeoGetVersion)
pub const NeoVersion = struct {
    tcp_port: u16,
    ws_port: u16,
    nonce: u32,
    user_agent: []const u8,
    protocol: ?ProtocolConfiguration,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .tcp_port = 0,
            .ws_port = 0,
            .nonce = 0,
            .user_agent = "",
            .protocol = null,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        return Self{
            .tcp_port = @intCast(obj.get("tcpport").?.integer),
            .ws_port = @intCast(obj.get("wsport").?.integer),
            .nonce = @intCast(obj.get("nonce").?.integer),
            .user_agent = try allocator.dupe(u8, obj.get("useragent").?.string),
            .protocol = if (obj.get("protocol")) |p| try ProtocolConfiguration.fromJson(p, allocator) else null,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.user_agent.len > 0) {
            allocator.free(@constCast(self.user_agent));
            self.user_agent = "";
        }
        self.protocol = null;
    }
};

/// Protocol configuration (converted from Swift protocol data)
pub const ProtocolConfiguration = struct {
    network: u32,
    address_version: u8,

    pub fn init() ProtocolConfiguration {
        return ProtocolConfiguration{
            .network = 0,
            .address_version = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ProtocolConfiguration {
        _ = allocator;
        const obj = json_value.object;

        return ProtocolConfiguration{
            .network = @intCast(obj.get("network").?.integer),
            .address_version = @intCast(obj.get("addressversion").?.integer),
        };
    }
};

/// NEP-17 balances response (converted from Swift NeoGetNep17Balances)
pub const Nep17Balances = struct {
    balance: []const TokenBalance,
    address: []const u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .balance = &[_]TokenBalance{},
            .address = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const address = try allocator.dupe(u8, obj.get("address").?.string);

        var balances = ArrayList(TokenBalance).init(allocator);
        if (obj.get("balance")) |balance_array| {
            for (balance_array.array.items) |balance_item| {
                try balances.append(try TokenBalance.fromJson(balance_item, allocator));
            }
        }

        return Self{
            .balance = try balances.toOwnedSlice(),
            .address = address,
        };
    }
};

/// Token balance (converted from Swift token balance)
pub const TokenBalance = struct {
    asset_hash: Hash160,
    amount: []const u8,
    last_updated_block: u32,

    pub fn init() TokenBalance {
        return TokenBalance{
            .asset_hash = Hash160.ZERO,
            .amount = "0",
            .last_updated_block = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TokenBalance {
        const obj = json_value.object;

        return TokenBalance{
            .asset_hash = try Hash160.initWithString(obj.get("assethash").?.string),
            .amount = try allocator.dupe(u8, obj.get("amount").?.string),
            .last_updated_block = @intCast(obj.get("lastupdatedblock").?.integer),
        };
    }
};

/// NEP-17 transfers response (converted from Swift NeoGetNep17Transfers)
pub const Nep17Transfers = struct {
    sent: []const TokenTransfer,
    received: []const TokenTransfer,
    address: []const u8,

    pub fn init() Nep17Transfers {
        return Nep17Transfers{
            .sent = &[_]TokenTransfer{},
            .received = &[_]TokenTransfer{},
            .address = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Nep17Transfers {
        const obj = json_value.object;

        const address = try allocator.dupe(u8, obj.get("address").?.string);

        var sent = ArrayList(TokenTransfer).init(allocator);
        if (obj.get("sent")) |sent_array| {
            for (sent_array.array.items) |item| {
                try sent.append(try TokenTransfer.fromJson(item, allocator));
            }
        }

        var received = ArrayList(TokenTransfer).init(allocator);
        if (obj.get("received")) |received_array| {
            for (received_array.array.items) |item| {
                try received.append(try TokenTransfer.fromJson(item, allocator));
            }
        }

        return Nep17Transfers{
            .sent = try sent.toOwnedSlice(),
            .received = try received.toOwnedSlice(),
            .address = address,
        };
    }
};

/// Token transfer (converted from Swift token transfer)
pub const TokenTransfer = struct {
    timestamp: u64,
    asset_hash: Hash160,
    transfer_address: []const u8,
    amount: []const u8,
    block_index: u32,
    transfer_notify_index: u32,
    tx_hash: Hash256,

    pub fn init() TokenTransfer {
        return std.mem.zeroes(TokenTransfer);
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TokenTransfer {
        const obj = json_value.object;

        return TokenTransfer{
            .timestamp = @intCast(obj.get("timestamp").?.integer),
            .asset_hash = try Hash160.initWithString(obj.get("assethash").?.string),
            .transfer_address = try allocator.dupe(u8, obj.get("transferaddress").?.string),
            .amount = try allocator.dupe(u8, obj.get("amount").?.string),
            .block_index = @intCast(obj.get("blockindex").?.integer),
            .transfer_notify_index = @intCast(obj.get("transfernotifyindex").?.integer),
            .tx_hash = try Hash256.initWithString(obj.get("txhash").?.string),
        };
    }
};

/// Application log response (converted from Swift NeoApplicationLog)
pub const NeoApplicationLog = struct {
    tx_id: Hash256,
    executions: []Execution,

    pub fn init() NeoApplicationLog {
        return NeoApplicationLog{
            .tx_id = Hash256.ZERO,
            .executions = &[_]Execution{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoApplicationLog {
        const obj = json_value.object;

        const tx_id = try Hash256.initWithString(obj.get("txid").?.string);

        var executions = ArrayList(Execution).init(allocator);
        defer executions.deinit();
        if (obj.get("executions")) |exec_array| {
            if (exec_array != .array) return errors.SerializationError.InvalidFormat;
            for (exec_array.array.items) |item| {
                var execution = try Execution.fromJson(item, allocator);
                var execution_guard = true;
                defer if (execution_guard) execution.deinit(allocator);
                try executions.append(execution);
                execution_guard = false;
            }
        }

        return NeoApplicationLog{
            .tx_id = tx_id,
            .executions = try executions.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *NeoApplicationLog, allocator: std.mem.Allocator) void {
        if (self.executions.len > 0) {
            for (self.executions) |*execution| {
                execution.deinit(allocator);
            }
            allocator.free(self.executions);
        }
    }
};

/// Execution (converted from Swift execution data)
pub const Execution = struct {
    trigger: []const u8,
    vm_state: NeoVMStateType,
    exception: ?[]const u8,
    gas_consumed: []const u8,
    stack: []StackItem,
    notifications: []Notification,

    pub fn init() Execution {
        return Execution{
            .trigger = "",
            .vm_state = .None,
            .exception = null,
            .gas_consumed = "",
            .stack = &[_]StackItem{},
            .notifications = &[_]Notification{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Execution {
        const obj = json_value.object;

        const trigger = try allocator.dupe(u8, obj.get("trigger").?.string);
        const vm_state_value = obj.get("vmstate") orelse return errors.SerializationError.InvalidFormat;
        const vm_state = try NeoVMStateType.decodeFromJson(vm_state_value);
        const gas_consumed = try allocator.dupe(u8, obj.get("gasconsumed").?.string);

        const exception = if (obj.get("exception")) |ex|
            switch (ex) {
                .string => |value| try allocator.dupe(u8, value),
                .null => null,
                else => try stringifyJsonValue(ex, allocator),
            }
        else
            null;

        var stack_items = ArrayList(StackItem).init(allocator);
        defer stack_items.deinit();
        if (obj.get("stack")) |stack_value| {
            if (stack_value != .array) return errors.SerializationError.InvalidFormat;
            for (stack_value.array.items) |entry| {
                var parsed_item = try StackItem.decodeFromJson(entry, allocator);
                var item_guard = true;
                defer if (item_guard) parsed_item.deinit(allocator);
                try stack_items.append(parsed_item);
                item_guard = false;
            }
        }

        var notifications_list = ArrayList(Notification).init(allocator);
        defer notifications_list.deinit();
        if (obj.get("notifications")) |notifications_value| {
            if (notifications_value != .array) return errors.SerializationError.InvalidFormat;
            for (notifications_value.array.items) |notification_value| {
                var notification = try Notification.fromJson(notification_value, allocator);
                var notification_guard = true;
                defer if (notification_guard) notification.deinit(allocator);
                try notifications_list.append(notification);
                notification_guard = false;
            }
        }

        return Execution{
            .trigger = trigger,
            .vm_state = vm_state,
            .exception = exception,
            .gas_consumed = gas_consumed,
            .stack = try stack_items.toOwnedSlice(),
            .notifications = try notifications_list.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *Execution, allocator: std.mem.Allocator) void {
        if (self.trigger.len > 0) allocator.free(@constCast(self.trigger));
        if (self.gas_consumed.len > 0) allocator.free(@constCast(self.gas_consumed));
        if (self.exception) |ex| {
            if (ex.len > 0) allocator.free(@constCast(ex));
        }

        if (self.stack.len > 0) {
            for (self.stack) |*item| {
                item.deinit(allocator);
            }
            allocator.free(self.stack);
        }

        if (self.notifications.len > 0) {
            for (self.notifications) |*notification| {
                notification.deinit(allocator);
            }
            allocator.free(self.notifications);
        }
    }
};

/// Notification (converted from Swift Notification)
pub const Notification = struct {
    contract: Hash160,
    event_name: []const u8,
    state: StackItem,

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Notification {
        const obj = json_value.object;

        const contract = try Hash160.initWithString(obj.get("contract").?.string);
        const event_name = try allocator.dupe(u8, obj.get("eventname").?.string);
        const state_value = obj.get("state") orelse return errors.SerializationError.InvalidFormat;
        var state = try StackItem.decodeFromJson(state_value, allocator);
        errdefer state.deinit(allocator);

        return Notification{
            .contract = contract,
            .event_name = event_name,
            .state = state,
        };
    }

    pub fn deinit(self: *Notification, allocator: std.mem.Allocator) void {
        if (self.event_name.len > 0) allocator.free(@constCast(self.event_name));
        self.state.deinit(allocator);
    }
};

/// Contract state response (converted from Swift ContractState)
pub const ContractState = struct {
    id: i32,
    update_counter: u32,
    hash: Hash160,
    nef: ContractNef,
    manifest: ContractManifest,

    pub fn init() ContractState {
        return ContractState{
            .id = 0,
            .update_counter = 0,
            .hash = Hash160.ZERO,
            .nef = ContractNef.init(),
            .manifest = ContractManifest.init(),
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractState {
        const obj = json_value.object;

        var nef = try ContractNef.fromJson(obj.get("nef").?, allocator);
        errdefer nef.deinit(allocator);

        var manifest = try ContractManifest.fromJson(obj.get("manifest").?, allocator);
        errdefer manifest.deinit(allocator);

        return ContractState{
            .id = try parseIntFromJson(i32, obj.get("id").?),
            .update_counter = try parseIntFromJson(u32, obj.get("updatecounter").?),
            .hash = try Hash160.initWithString(obj.get("hash").?.string),
            .nef = nef,
            .manifest = manifest,
        };
    }

    pub fn deinit(self: *ContractState, allocator: std.mem.Allocator) void {
        self.nef.deinit(allocator);
        self.manifest.deinit(allocator);
    }
};

/// Contract NEF (converted from Swift ContractNef)
pub const ContractNef = struct {
    magic: u32,
    compiler: []const u8,
    source: ?[]const u8,
    script: []const u8,
    checksum: u32,

    pub fn init() ContractNef {
        return ContractNef{
            .magic = 0,
            .compiler = "",
            .source = null,
            .script = &[_]u8{},
            .checksum = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractNef {
        const obj = json_value.object;

        const magic = try parseIntFromJson(u32, obj.get("magic").?);
        const compiler = try allocator.dupe(u8, obj.get("compiler").?.string);

        const source = if (obj.get("source")) |source_value|
            switch (source_value) {
                .string => |str| try allocator.dupe(u8, str),
                .null => null,
                else => try stringifyJsonValue(source_value, allocator),
            }
        else
            null;

        const script_field = obj.get("script") orelse return errors.SerializationError.InvalidFormat;
        const script = switch (script_field) {
            .string => |str| try allocator.dupe(u8, str),
            else => return errors.SerializationError.InvalidFormat,
        };

        const checksum = try parseIntFromJson(u32, obj.get("checksum").?);

        return ContractNef{
            .magic = magic,
            .compiler = compiler,
            .source = source,
            .script = script,
            .checksum = checksum,
        };
    }

    pub fn deinit(self: *ContractNef, allocator: std.mem.Allocator) void {
        if (self.compiler.len > 0) allocator.free(@constCast(self.compiler));
        if (self.script.len > 0) allocator.free(@constCast(self.script));
        if (self.source) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
        }
    }
};

/// Contract manifest (converted from Swift ContractManifest)
pub const ContractManifest = struct {
    name: ?[]const u8,
    groups: []const ContractGroup,
    supported_standards: []const []const u8,
    abi: ?ContractABI,
    permissions: []const ContractPermission,
    trusts: []const []const u8,
    extra: ?[]const u8,

    pub fn init() ContractManifest {
        return ContractManifest{
            .name = null,
            .groups = &[_]ContractGroup{},
            .supported_standards = &[_][]const u8{},
            .abi = null,
            .permissions = &[_]ContractPermission{},
            .trusts = &[_][]const u8{},
            .extra = null,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractManifest {
        const obj = json_value.object;

        const name = if (obj.get("name")) |name_value|
            switch (name_value) {
                .string => |str| try allocator.dupe(u8, str),
                .null => null,
                else => try stringifyJsonValue(name_value, allocator),
            }
        else
            null;

        var groups = ArrayList(ContractGroup).init(allocator);
        var groups_cleanup = TrueFlag{};
        defer if (groups_cleanup.value) {
            for (groups.items) |*group| group.deinit(allocator);
            groups.deinit();
        };
        if (obj.get("groups")) |groups_value| {
            if (groups_value != .array) return errors.SerializationError.InvalidFormat;
            for (groups_value.array.items) |group_value| {
                try groups.append(try ContractGroup.fromJson(group_value, allocator));
            }
        }

        var standards = ArrayList([]const u8).init(allocator);
        var standards_cleanup = TrueFlag{};
        defer if (standards_cleanup.value) {
            for (standards.items) |standard| {
                if (standard.ptr != null) allocator.free(@constCast(standard));
            }
            standards.deinit();
        };
        if (obj.get("supportedstandards")) |standards_value| {
            if (standards_value != .array) return errors.SerializationError.InvalidFormat;
            for (standards_value.array.items) |entry| {
                if (entry != .string) return errors.SerializationError.InvalidFormat;
                try standards.append(try allocator.dupe(u8, entry.string));
            }
        }

        var permissions = ArrayList(ContractPermission).init(allocator);
        var permissions_cleanup = TrueFlag{};
        defer if (permissions_cleanup.value) {
            for (permissions.items) |*permission| permission.deinit(allocator);
            permissions.deinit();
        };
        if (obj.get("permissions")) |permissions_value| {
            if (permissions_value != .array) return errors.SerializationError.InvalidFormat;
            for (permissions_value.array.items) |permission_value| {
                try permissions.append(try ContractPermission.fromJson(permission_value, allocator));
            }
        }

        var trusts = ArrayList([]const u8).init(allocator);
        var trusts_cleanup = TrueFlag{};
        defer if (trusts_cleanup.value) {
            for (trusts.items) |trust| {
                if (trust.ptr != null) allocator.free(@constCast(trust));
            }
            trusts.deinit();
        };
        if (obj.get("trusts")) |trusts_value| {
            if (trusts_value != .array) return errors.SerializationError.InvalidFormat;
            for (trusts_value.array.items) |trust_value| {
                try trusts.append(try jsonValueToOwnedString(trust_value, allocator));
            }
        }

        var abi_opt: ?ContractABI = null;
        errdefer if (abi_opt) |*abi_value| abi_value.deinit(allocator);
        if (obj.get("abi")) |abi_value| {
            abi_opt = try ContractABI.fromJson(abi_value, allocator);
        }

        const extra = if (obj.get("extra")) |extra_value|
            switch (extra_value) {
                .null => null,
                else => try stringifyJsonValue(extra_value, allocator),
            }
        else
            null;

        const groups_slice = try groups.toOwnedSlice();
        groups_cleanup.value = false;

        const standards_slice = try standards.toOwnedSlice();
        standards_cleanup.value = false;

        const permissions_slice = try permissions.toOwnedSlice();
        permissions_cleanup.value = false;

        const trusts_slice = try trusts.toOwnedSlice();
        trusts_cleanup.value = false;

        return ContractManifest{
            .name = name,
            .groups = groups_slice,
            .supported_standards = standards_slice,
            .abi = abi_opt,
            .permissions = permissions_slice,
            .trusts = trusts_slice,
            .extra = extra,
        };
    }

    pub fn deinit(self: *ContractManifest, allocator: std.mem.Allocator) void {
        if (self.name) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
        }

        if (self.groups.len > 0) {
            for (self.groups) |*group| group.deinit(allocator);
            allocator.free(@constCast(self.groups));
        }

        if (self.supported_standards.len > 0) {
            for (self.supported_standards) |standard| {
                if (standard.len > 0) allocator.free(@constCast(standard));
            }
            allocator.free(@constCast(self.supported_standards));
        }

        if (self.abi) |*abi_value| {
            abi_value.deinit(allocator);
        }

        if (self.permissions.len > 0) {
            for (self.permissions) |*permission| permission.deinit(allocator);
            allocator.free(@constCast(self.permissions));
        }

        if (self.trusts.len > 0) {
            for (self.trusts) |trust| {
                if (trust.len > 0) allocator.free(@constCast(trust));
            }
            allocator.free(@constCast(self.trusts));
        }

        if (self.extra) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
        }
    }
};

/// Helper wrapper so we can toggle a bool inside a defer block.
const TrueFlag = struct {
    value: bool = true,
};

pub const ContractGroup = struct {
    public_key: []const u8,
    signature: []const u8,

    pub fn init() ContractGroup {
        return ContractGroup{
            .public_key = "",
            .signature = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractGroup {
        const obj = json_value.object;

        const pub_key_value = obj.get("pubkey") orelse obj.get("pubKey") orelse return errors.SerializationError.InvalidFormat;
        if (pub_key_value != .string) return errors.SerializationError.InvalidFormat;
        const cleaned_pub_key = StringUtils.cleanedHexPrefix(pub_key_value.string);

        const pub_key_bytes = try StringUtils.bytesFromHex(cleaned_pub_key, allocator);
        defer allocator.free(pub_key_bytes);
        if (pub_key_bytes.len != constants.PUBLIC_KEY_SIZE_COMPRESSED) {
            return errors.ValidationError.InvalidLength;
        }

        const public_key = try allocator.dupe(u8, cleaned_pub_key);

        const signature_value = obj.get("signature") orelse return errors.SerializationError.InvalidFormat;
        if (signature_value != .string) return errors.SerializationError.InvalidFormat;
        const decoded_signature = try StringUtils.base64Decoded(signature_value.string, allocator);
        defer allocator.free(decoded_signature);
        if (decoded_signature.len == 0) {
            return errors.ValidationError.InvalidLength;
        }

        const signature = try allocator.dupe(u8, signature_value.string);

        return ContractGroup{
            .public_key = public_key,
            .signature = signature,
        };
    }

    pub fn deinit(self: *ContractGroup, allocator: std.mem.Allocator) void {
        if (self.public_key.len > 0) allocator.free(@constCast(self.public_key));
        if (self.signature.len > 0) allocator.free(@constCast(self.signature));
    }
};

pub const ContractParameterDefinition = struct {
    name: []const u8,
    parameter_type: []const u8,

    pub fn init() ContractParameterDefinition {
        return ContractParameterDefinition{
            .name = "",
            .parameter_type = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractParameterDefinition {
        const obj = json_value.object;
        return ContractParameterDefinition{
            .name = try allocator.dupe(u8, obj.get("name").?.string),
            .parameter_type = try allocator.dupe(u8, obj.get("type").?.string),
        };
    }

    pub fn deinit(self: *ContractParameterDefinition, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.parameter_type.len > 0) allocator.free(@constCast(self.parameter_type));
    }
};

pub const ContractMethod = struct {
    name: []const u8,
    parameters: []const ContractParameterDefinition,
    return_type: []const u8,
    offset: ?u32,
    safe: bool,

    pub fn init() ContractMethod {
        return ContractMethod{
            .name = "",
            .parameters = &[_]ContractParameterDefinition{},
            .return_type = "",
            .offset = null,
            .safe = false,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractMethod {
        const obj = json_value.object;

        const name = try allocator.dupe(u8, obj.get("name").?.string);
        const return_type = try allocator.dupe(u8, obj.get("returntype").?.string);
        const offset = if (obj.get("offset")) |offset_value| try parseIntFromJson(u32, offset_value) else null;

        const safe = if (obj.get("safe")) |safe_value|
            switch (safe_value) {
                .bool => safe_value.bool,
                .string => std.mem.eql(u8, safe_value.string, "true"),
                else => false,
            }
        else
            false;

        var parameters = ArrayList(ContractParameterDefinition).init(allocator);
        var params_cleanup = TrueFlag{};
        defer if (params_cleanup.value) {
            for (parameters.items) |*param| param.deinit(allocator);
            parameters.deinit();
        };
        if (obj.get("parameters")) |params_value| {
            if (params_value != .array) return errors.SerializationError.InvalidFormat;
            for (params_value.array.items) |param_value| {
                try parameters.append(try ContractParameterDefinition.fromJson(param_value, allocator));
            }
        }

        const parameters_slice = try parameters.toOwnedSlice();
        params_cleanup.value = false;

        return ContractMethod{
            .name = name,
            .parameters = parameters_slice,
            .return_type = return_type,
            .offset = offset,
            .safe = safe,
        };
    }

    pub fn deinit(self: *ContractMethod, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.return_type.len > 0) allocator.free(@constCast(self.return_type));
        if (self.parameters.len > 0) {
            for (self.parameters) |*param| param.deinit(allocator);
            allocator.free(@constCast(self.parameters));
        }
    }
};

pub const ContractEvent = struct {
    name: []const u8,
    parameters: []const ContractParameterDefinition,

    pub fn init() ContractEvent {
        return ContractEvent{
            .name = "",
            .parameters = &[_]ContractParameterDefinition{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractEvent {
        const obj = json_value.object;

        const name = try allocator.dupe(u8, obj.get("name").?.string);

        var parameters = ArrayList(ContractParameterDefinition).init(allocator);
        var params_cleanup = TrueFlag{};
        defer if (params_cleanup.value) {
            for (parameters.items) |*param| param.deinit(allocator);
            parameters.deinit();
        };
        if (obj.get("parameters")) |params_value| {
            if (params_value != .array) return errors.SerializationError.InvalidFormat;
            for (params_value.array.items) |param_value| {
                try parameters.append(try ContractParameterDefinition.fromJson(param_value, allocator));
            }
        }

        const parameters_slice = try parameters.toOwnedSlice();
        params_cleanup.value = false;

        return ContractEvent{
            .name = name,
            .parameters = parameters_slice,
        };
    }

    pub fn deinit(self: *ContractEvent, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.parameters.len > 0) {
            for (self.parameters) |*param| param.deinit(allocator);
            allocator.free(@constCast(self.parameters));
        }
    }
};

pub const ContractABI = struct {
    methods: []const ContractMethod,
    events: []const ContractEvent,

    pub fn init() ContractABI {
        return ContractABI{
            .methods = &[_]ContractMethod{},
            .events = &[_]ContractEvent{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractABI {
        const obj = json_value.object;

        var methods = ArrayList(ContractMethod).init(allocator);
        var methods_cleanup = TrueFlag{};
        defer if (methods_cleanup.value) {
            for (methods.items) |*method| method.deinit(allocator);
            methods.deinit();
        };
        if (obj.get("methods")) |methods_value| {
            if (methods_value != .array) return errors.SerializationError.InvalidFormat;
            for (methods_value.array.items) |method_value| {
                try methods.append(try ContractMethod.fromJson(method_value, allocator));
            }
        }

        var events = ArrayList(ContractEvent).init(allocator);
        var events_cleanup = TrueFlag{};
        defer if (events_cleanup.value) {
            for (events.items) |*event| event.deinit(allocator);
            events.deinit();
        };
        if (obj.get("events")) |events_value| {
            if (events_value != .array) return errors.SerializationError.InvalidFormat;
            for (events_value.array.items) |event_value| {
                try events.append(try ContractEvent.fromJson(event_value, allocator));
            }
        }

        const methods_slice = try methods.toOwnedSlice();
        methods_cleanup.value = false;

        const events_slice = try events.toOwnedSlice();
        events_cleanup.value = false;

        return ContractABI{
            .methods = methods_slice,
            .events = events_slice,
        };
    }

    pub fn deinit(self: *ContractABI, allocator: std.mem.Allocator) void {
        if (self.methods.len > 0) {
            for (self.methods) |*method| method.deinit(allocator);
            allocator.free(@constCast(self.methods));
        }

        if (self.events.len > 0) {
            for (self.events) |*event| event.deinit(allocator);
            allocator.free(@constCast(self.events));
        }
    }
};

pub const ContractPermission = struct {
    contract: []const u8,
    methods: []const []const u8,

    pub fn init() ContractPermission {
        return ContractPermission{
            .contract = "",
            .methods = &[_][]const u8{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractPermission {
        const obj = json_value.object;

        const contract_value = obj.get("contract") orelse return errors.SerializationError.InvalidFormat;
        const contract = try jsonValueToOwnedString(contract_value, allocator);

        var methods = ArrayList([]const u8).init(allocator);
        var methods_cleanup = TrueFlag{};
        defer if (methods_cleanup.value) {
            for (methods.items) |method| {
                if (method.ptr != null) allocator.free(@constCast(method));
            }
            methods.deinit();
        };
        if (obj.get("methods")) |methods_value| {
            switch (methods_value) {
                .array => |method_array| {
                    for (method_array) |entry| {
                        if (entry != .string) return errors.SerializationError.InvalidFormat;
                        try methods.append(try allocator.dupe(u8, entry.string));
                    }
                },
                .string => |method_name| {
                    try methods.append(try allocator.dupe(u8, method_name));
                },
                else => return errors.SerializationError.InvalidFormat,
            }
        }

        const methods_slice = try methods.toOwnedSlice();
        methods_cleanup.value = false;

        return ContractPermission{
            .contract = contract,
            .methods = methods_slice,
        };
    }

    pub fn deinit(self: *ContractPermission, allocator: std.mem.Allocator) void {
        if (self.contract.len > 0) allocator.free(@constCast(self.contract));
        if (self.methods.len > 0) {
            for (self.methods) |method| {
                if (method.len > 0) allocator.free(@constCast(method));
            }
            allocator.free(@constCast(self.methods));
        }
    }
};

/// Network fee response (converted from Swift network fee responses)
pub const NetworkFeeResponse = struct {
    network_fee: u64,

    pub fn init() NetworkFeeResponse {
        return NetworkFeeResponse{ .network_fee = 0 };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NetworkFeeResponse {
        _ = allocator;
        return switch (json_value) {
            .integer => |value| NetworkFeeResponse{ .network_fee = @intCast(value) },
            .string => |str| NetworkFeeResponse{ .network_fee = try parseFee(str) },
            .object => |obj| blk: {
                const field = obj.get("networkfee") orelse return errors.SerializationError.InvalidFormat;
                break :blk NetworkFeeResponse{ .network_fee = switch (field) {
                    .integer => |value| @intCast(value),
                    .string => |str| try parseFee(str),
                    else => return errors.SerializationError.InvalidFormat,
                } };
            },
            else => errors.SerializationError.InvalidFormat,
        };
    }

    fn parseFee(str: []const u8) !u64 {
        return std.fmt.parseInt(u64, str, 10) catch errors.SerializationError.InvalidFormat;
    }
};

/// Send transaction response (converted from Swift send responses)
pub const SendRawTransactionResponse = struct {
    success: bool,
    hash: ?Hash256,

    pub fn init() SendRawTransactionResponse {
        return SendRawTransactionResponse{ .success = false, .hash = null };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !SendRawTransactionResponse {
        _ = allocator;
        return switch (json_value) {
            .bool => |value| SendRawTransactionResponse{ .success = value, .hash = null },
            .string => |str| SendRawTransactionResponse{
                .success = true,
                .hash = try Hash256.initWithString(str),
            },
            .object => |obj| blk: {
                if (obj.get("hash")) |hash_value| {
                    const hash = switch (hash_value) {
                        .string => |str| try Hash256.initWithString(str),
                        else => return errors.SerializationError.InvalidFormat,
                    };
                    break :blk SendRawTransactionResponse{ .success = true, .hash = hash };
                }
                if (obj.get("success")) |success_value| {
                    const success = switch (success_value) {
                        .bool => |b| b,
                        else => return errors.SerializationError.InvalidFormat,
                    };
                    break :blk SendRawTransactionResponse{ .success = success, .hash = null };
                }
                return errors.SerializationError.InvalidFormat;
            },
            else => errors.SerializationError.InvalidFormat,
        };
    }
};

// Import after definitions
// Tests (converted from Swift response tests)
test "NeoBlock response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test default block creation
    const block = NeoBlock.initDefault();
    try testing.expect(block.hash.eql(Hash256.ZERO));
    try testing.expectEqual(@as(u32, 0), block.size);
    try testing.expectEqual(@as(u32, 0), block.index);
}

test "InvocationResult parsing and operations" {
    const testing = std.testing;
    _ = testing.allocator;

    var invocation_result = InvocationResult.init();

    // Test fault state checking (equivalent to Swift state tests)
    try testing.expect(!invocation_result.hasFaulted());

    // Test with faulted state
    invocation_result.state = .Fault;
    try testing.expect(invocation_result.hasFaulted());

    // Test empty stack handling
    try testing.expectError(errors.NeoError.IllegalState, invocation_result.getFirstStackItem());
}

test "NetworkFeeResponse parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const string_value = std.json.Value{ .string = "1000" };
    const parsed_string = try NetworkFeeResponse.fromJson(string_value, allocator);
    try testing.expectEqual(@as(u64, 1000), parsed_string.network_fee);

    var object_map = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&object_map, allocator, "networkfee", std.json.Value{ .string = try allocator.dupe(u8, "42") });
    const object_value = std.json.Value{ .object = object_map };
    defer json_utils.freeValue(object_value, allocator);
    const parsed_object = try NetworkFeeResponse.fromJson(object_value, allocator);
    try testing.expectEqual(@as(u64, 42), parsed_object.network_fee);
}

test "SendRawTransactionResponse parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const bool_value = std.json.Value{ .bool = true };
    const parsed_bool = try SendRawTransactionResponse.fromJson(bool_value, allocator);
    try testing.expect(parsed_bool.success);
    try testing.expect(parsed_bool.hash == null);

    const hash_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const string_value = std.json.Value{ .string = hash_str };
    const parsed_string = try SendRawTransactionResponse.fromJson(string_value, allocator);
    try testing.expect(parsed_string.success);
    const expected_hash = try Hash256.initWithString(hash_str);
    try testing.expect(parsed_string.hash.?.eql(expected_hash));
}
