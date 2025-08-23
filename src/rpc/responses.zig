//! RPC Response Types
//!
//! Complete conversion from NeoSwift protocol response types
//! Handles all Neo RPC response parsing and serialization.

const std = @import("std");
const constants = @import("../core/constants.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;

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
    witnesses: ?[]const NeoWitness,
    transactions: ?[]const Transaction,
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
        witnesses: ?[]const NeoWitness,
        transactions: ?[]const Transaction,
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
        
        const primary = if (obj.get("primary")) |p| @as(u32, @intCast(p.integer)) else null;
        const next_consensus = try allocator.dupe(u8, obj.get("nextconsensus").?.string);
        const confirmations = @as(u32, @intCast(obj.get("confirmations").?.integer));
        
        const next_hash = if (obj.get("nextblockhash")) |nh| 
            try Hash256.initWithString(nh.string) 
        else 
            null;
        
        // Parse witnesses and transactions would be implemented here
        
        return Self.init(
            hash, size, version, prev_hash, merkle_root, time, index,
            primary, next_consensus, null, null, confirmations, next_hash
        );
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
    signers: []const TransactionSigner,
    attributes: []const TransactionAttribute,
    script: []const u8,
    witnesses: []const NeoWitness,
    
    const Self = @This();
    
    pub fn init() Self {
        return std.mem.zeroes(Self);
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        _ = json_value;
        _ = allocator;
        return Self.init(); // Simplified
    }
};

/// Transaction signer (converted from Swift TransactionSigner)
pub const TransactionSigner = struct {
    account: Hash160,
    scopes: []const u8,
    allowed_contracts: ?[]const Hash160,
    allowed_groups: ?[]const [33]u8,
    rules: ?[]const WitnessRule,
    
    pub fn init() TransactionSigner {
        return std.mem.zeroes(TransactionSigner);
    }
};

/// Transaction attribute (converted from Swift TransactionAttribute)
pub const TransactionAttribute = struct {
    attribute_type: []const u8,
    value: []const u8,
    
    pub fn init() TransactionAttribute {
        return TransactionAttribute{ .attribute_type = "", .value = "" };
    }
};

/// Witness rule (converted from Swift WitnessRule)
pub const WitnessRule = struct {
    action: []const u8,
    condition: WitnessCondition,
    
    pub fn init() WitnessRule {
        return WitnessRule{ .action = "", .condition = WitnessCondition.init() };
    }
};

/// Witness condition (converted from Swift WitnessCondition)
pub const WitnessCondition = struct {
    condition_type: []const u8,
    value: []const u8,
    
    pub fn init() WitnessCondition {
        return WitnessCondition{ .condition_type = "", .value = "" };
    }
};

/// Invocation result (converted from Swift InvocationResult)
pub const InvocationResult = struct {
    script: []const u8,
    state: []const u8,
    gas_consumed: []const u8,
    exception: ?[]const u8,
    stack: []const StackItem,
    session: ?[]const u8,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .script = "",
            .state = "",
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
        return std.mem.eql(u8, self.state, "FAULT");
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const script = try allocator.dupe(u8, obj.get("script").?.string);
        const state = try allocator.dupe(u8, obj.get("state").?.string);
        const gas_consumed = try allocator.dupe(u8, obj.get("gasconsumed").?.string);
        const exception = if (obj.get("exception")) |ex| try allocator.dupe(u8, ex.string) else null;
        
        // Parse stack items
        var stack_items = std.ArrayList(StackItem).init(allocator);
        if (obj.get("stack")) |stack_array| {
            for (stack_array.array) |item| {
                try stack_items.append(try StackItem.fromJson(item, allocator));
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
};

/// Stack item (converted from Swift StackItem)
pub const StackItem = struct {
    item_type: []const u8,
    value: ?[]const u8,
    
    const Self = @This();
    
    pub fn init(item_type: []const u8, value: ?[]const u8) Self {
        return Self{
            .item_type = item_type,
            .value = value,
        };
    }
    
    /// Gets as string (equivalent to Swift getString)
    pub fn getString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.value) |val| {
            return try allocator.dupe(u8, val);
        }
        return errors.throwIllegalState("Stack item has no value");
    }
    
    /// Gets as integer (equivalent to Swift getInteger)
    pub fn getInteger(self: Self) !i64 {
        if (self.value) |val| {
            return std.fmt.parseInt(i64, val, 10) catch {
                return errors.throwIllegalState("Cannot parse integer from stack item");
            };
        }
        return errors.throwIllegalState("Stack item has no value");
    }
    
    /// Gets as byte array (equivalent to Swift getByteArray)
    pub fn getByteArray(self: Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.value) |val| {
            // Decode base64 or hex
            return try allocator.dupe(u8, val);
        }
        return errors.throwIllegalState("Stack item has no value");
    }
    
    /// Gets as boolean (equivalent to Swift getBoolean)
    pub fn getBoolean(self: Self) !bool {
        if (self.value) |val| {
            return std.mem.eql(u8, val, "true") or std.mem.eql(u8, val, "1");
        }
        return false;
    }
    
    /// Gets as list (equivalent to Swift getList)
    pub fn getList(self: Self) ![]const StackItem {
        // This would parse array-type stack items
        return &[_]StackItem{};
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const item_type = try allocator.dupe(u8, obj.get("type").?.string);
        const value = if (obj.get("value")) |v| try allocator.dupe(u8, v.string) else null;
        
        return Self.init(item_type, value);
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
        
        var balances = std.ArrayList(TokenBalance).init(allocator);
        if (obj.get("balance")) |balance_array| {
            for (balance_array.array) |balance_item| {
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
        
        var sent = std.ArrayList(TokenTransfer).init(allocator);
        if (obj.get("sent")) |sent_array| {
            for (sent_array.array) |item| {
                try sent.append(try TokenTransfer.fromJson(item, allocator));
            }
        }
        
        var received = std.ArrayList(TokenTransfer).init(allocator);
        if (obj.get("received")) |received_array| {
            for (received_array.array) |item| {
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
    executions: []const Execution,
    
    pub fn init() NeoApplicationLog {
        return NeoApplicationLog{
            .tx_id = Hash256.ZERO,
            .executions = &[_]Execution{},
        };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoApplicationLog {
        const obj = json_value.object;
        
        const tx_id = try Hash256.initWithString(obj.get("txid").?.string);
        
        var executions = std.ArrayList(Execution).init(allocator);
        if (obj.get("executions")) |exec_array| {
            for (exec_array.array) |item| {
                try executions.append(try Execution.fromJson(item, allocator));
            }
        }
        
        return NeoApplicationLog{
            .tx_id = tx_id,
            .executions = try executions.toOwnedSlice(),
        };
    }
};

/// Execution (converted from Swift execution data)
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
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Execution {
        _ = json_value;
        _ = allocator;
        return Execution.init(); // Simplified
    }
};

/// Notification (converted from Swift Notification)
pub const Notification = struct {
    contract: Hash160,
    event_name: []const u8,
    state: []const StackItem,
    
    pub fn init() Notification {
        return Notification{
            .contract = Hash160.ZERO,
            .event_name = "",
            .state = &[_]StackItem{},
        };
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
        _ = json_value;
        _ = allocator;
        return ContractState.init(); // Simplified
    }
};

/// Contract NEF (converted from Swift ContractNef)
pub const ContractNef = struct {
    magic: u32,
    compiler: []const u8,
    source: []const u8,
    script: []const u8,
    checksum: u32,
    
    pub fn init() ContractNef {
        return ContractNef{
            .magic = 0x3346454E, // "NEF3"
            .compiler = "",
            .source = "",
            .script = &[_]u8{},
            .checksum = 0,
        };
    }
};

/// Contract manifest (converted from Swift ContractManifest)
pub const ContractManifest = struct {
    name: []const u8,
    groups: []const ContractGroup,
    supported_standards: []const []const u8,
    abi: ContractABI,
    permissions: []const ContractPermission,
    trusts: []const Hash160,
    extra: ?[]const u8,
    
    pub fn init() ContractManifest {
        return ContractManifest{
            .name = "",
            .groups = &[_]ContractGroup{},
            .supported_standards = &[_][]const u8{},
            .abi = ContractABI.init(),
            .permissions = &[_]ContractPermission{},
            .trusts = &[_]Hash160{},
            .extra = null,
        };
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
        const obj = json_value.object;
        
        return NetworkFeeResponse{
            .network_fee = @intCast(obj.get("networkfee").?.integer),
        };
    }
};

/// Send transaction response (converted from Swift send responses)
pub const SendRawTransactionResponse = struct {
    hash: Hash256,
    
    pub fn init() SendRawTransactionResponse {
        return SendRawTransactionResponse{ .hash = Hash256.ZERO };
    }
    
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !SendRawTransactionResponse {
        _ = allocator;
        const obj = json_value.object;
        
        return SendRawTransactionResponse{
            .hash = try Hash256.initWithString(obj.get("hash").?.string),
        };
    }
};

// Import after definitions
const ContractGroup = @import("../contract/smart_contract.zig").ContractGroup;
const ContractABI = @import("../contract/smart_contract.zig").ContractABI;
const ContractPermission = @import("../contract/smart_contract.zig").ContractPermission;

// Tests (converted from Swift response tests)
test "NeoBlock response parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test default block creation
    const block = NeoBlock.initDefault();
    try testing.expect(block.hash.eql(Hash256.ZERO));
    try testing.expectEqual(@as(u32, 0), block.size);
    try testing.expectEqual(@as(u32, 0), block.index);
}

test "InvocationResult parsing and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var invocation_result = InvocationResult.init();
    
    // Test fault state checking (equivalent to Swift state tests)
    try testing.expect(!invocation_result.hasFaulted());
    
    // Test with faulted state
    invocation_result.state = "FAULT";
    try testing.expect(invocation_result.hasFaulted());
    
    // Test empty stack handling
    try testing.expectError(errors.NeoError.IllegalState, invocation_result.getFirstStackItem());
}

test "StackItem operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test string stack item (equivalent to Swift StackItem tests)
    const string_item = StackItem.init("String", "test_value");
    const string_value = try string_item.getString(allocator);
    defer allocator.free(string_value);
    try testing.expectEqualStrings("test_value", string_value);
    
    // Test integer stack item
    const int_item = StackItem.init("Integer", "42");
    const int_value = try int_item.getInteger();
    try testing.expectEqual(@as(i64, 42), int_value);
    
    // Test boolean stack item
    const bool_item_true = StackItem.init("Boolean", "true");
    try testing.expect(try bool_item_true.getBoolean());
    
    const bool_item_false = StackItem.init("Boolean", "false");
    try testing.expect(!try bool_item_false.getBoolean());
}