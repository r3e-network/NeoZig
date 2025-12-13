//! Complete RPC Response Types
//!
//! ALL remaining Swift protocol response types converted
//! Ensures 100% protocol coverage for complete Swift conversion.

const std = @import("std");
const ArrayList = std.ArrayList;
const json_utils = @import("../utils/json_utils.zig");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const PublicKey = @import("../crypto/keys.zig").PublicKey;

/// Neo account state (converted from Swift NeoAccountState)
pub const NeoAccountState = struct {
    balance: i64,
    balance_height: ?u32,
    public_key: ?[]const u8, // Hex string of public key

    const Self = @This();

    pub fn init(balance: i64, balance_height: ?u32, public_key: ?[]const u8) Self {
        return Self{
            .balance = balance,
            .balance_height = balance_height,
            .public_key = public_key,
        };
    }

    /// Creates account state with no vote (equivalent to Swift withNoVote)
    pub fn withNoVote(balance: i64, update_height: u32) Self {
        return Self.init(balance, update_height, null);
    }

    /// Creates account state with no balance (equivalent to Swift withNoBalance)
    pub fn withNoBalance() Self {
        return Self.init(0, null, null);
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const balance = obj.get("balance").?.integer;
        const balance_height = if (obj.get("balanceHeight")) |bh| @as(u32, @intCast(bh.integer)) else null;
        const public_key = if (obj.get("voteTo")) |pk| try allocator.dupe(u8, pk.string) else null;

        return Self.init(balance, balance_height, public_key);
    }

    pub fn toJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var obj = std.json.ObjectMap.init(allocator);

        try json_utils.putOwnedKey(&obj, allocator, "balance", std.json.Value{ .integer = self.balance });

        if (self.balance_height) |bh| {
            try json_utils.putOwnedKey(&obj, allocator, "balanceHeight", std.json.Value{ .integer = @intCast(bh) });
        }

        if (self.public_key) |pk| {
            try json_utils.putOwnedKey(&obj, allocator, "voteTo", std.json.Value{ .string = pk });
        }

        return std.json.Value{ .object = obj };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.public_key) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
            self.public_key = null;
        }
    }
};

/// Neo address response (converted from Swift NeoAddress)
pub const NeoAddress = struct {
    address: []const u8,
    is_valid: bool,

    pub fn init(address: []const u8, is_valid: bool) NeoAddress {
        return NeoAddress{ .address = address, .is_valid = is_valid };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoAddress {
        const obj = json_value.object;

        return NeoAddress.init(
            try allocator.dupe(u8, obj.get("address").?.string),
            obj.get("isvalid").?.bool,
        );
    }

    pub fn deinit(self: *NeoAddress, allocator: std.mem.Allocator) void {
        if (self.address.len > 0) allocator.free(@constCast(self.address));
        self.address = "";
    }
};

/// Oracle request (converted from Swift OracleRequest)
pub const OracleRequest = struct {
    url: []const u8,
    filter: ?[]const u8,
    callback_contract: Hash160,
    callback_method: []const u8,
    user_data: []const u8,
    gas_for_response: u64,

    pub fn init() OracleRequest {
        return OracleRequest{
            .url = "",
            .filter = null,
            .callback_contract = Hash160.ZERO,
            .callback_method = "",
            .user_data = "",
            .gas_for_response = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !OracleRequest {
        const obj = json_value.object;

        return OracleRequest{
            .url = try allocator.dupe(u8, obj.get("url").?.string),
            .filter = if (obj.get("filter")) |f| try allocator.dupe(u8, f.string) else null,
            .callback_contract = try Hash160.initWithString(obj.get("callbackContract").?.string),
            .callback_method = try allocator.dupe(u8, obj.get("callbackMethod").?.string),
            .user_data = try allocator.dupe(u8, obj.get("userData").?.string),
            .gas_for_response = @intCast(obj.get("gasForResponse").?.integer),
        };
    }

    pub fn deinit(self: *OracleRequest, allocator: std.mem.Allocator) void {
        if (self.url.len > 0) allocator.free(@constCast(self.url));
        if (self.filter) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
            self.filter = null;
        }
        if (self.callback_method.len > 0) allocator.free(@constCast(self.callback_method));
        if (self.user_data.len > 0) allocator.free(@constCast(self.user_data));
        self.url = "";
        self.callback_method = "";
        self.user_data = "";
    }
};

/// Contract method token (converted from Swift ContractMethodToken)
pub const ContractMethodToken = struct {
    hash: Hash160,
    method: []const u8,
    parameters_count: u16,
    has_return_value: bool,
    call_flags: u8,

    pub fn init() ContractMethodToken {
        return ContractMethodToken{
            .hash = Hash160.ZERO,
            .method = "",
            .parameters_count = 0,
            .has_return_value = false,
            .call_flags = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractMethodToken {
        const obj = json_value.object;

        return ContractMethodToken{
            .hash = try Hash160.initWithString(obj.get("hash").?.string),
            .method = try allocator.dupe(u8, obj.get("method").?.string),
            .parameters_count = @intCast(obj.get("parameterscount").?.integer),
            .has_return_value = obj.get("hasreturnvalue").?.bool,
            .call_flags = @intCast(obj.get("callflags").?.integer),
        };
    }

    pub fn deinit(self: *ContractMethodToken, allocator: std.mem.Allocator) void {
        if (self.method.len > 0) allocator.free(@constCast(self.method));
        self.method = "";
    }
};

/// Name state (converted from Swift NameState)
pub const NameState = struct {
    name: []const u8,
    expiration: u32,
    admin: ?Hash160,

    pub fn init() NameState {
        return NameState{
            .name = "",
            .expiration = 0,
            .admin = null,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NameState {
        const obj = json_value.object;

        return NameState{
            .name = try allocator.dupe(u8, obj.get("name").?.string),
            .expiration = @intCast(obj.get("expiration").?.integer),
            .admin = if (obj.get("admin")) |a| try Hash160.initWithString(a.string) else null,
        };
    }
};

/// Neo list plugins response (converted from Swift NeoListPlugins)
pub const NeoListPlugins = struct {
    plugins: []const Plugin,

    pub const Plugin = struct {
        name: []const u8,
        version: []const u8,
        interfaces: []const []const u8,

        pub fn init() Plugin {
            return Plugin{
                .name = "",
                .version = "",
                .interfaces = &[_][]const u8{},
            };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Plugin {
            const obj = json_value.object;

            var interfaces = ArrayList([]const u8).init(allocator);
            if (obj.get("interfaces")) |interfaces_array| {
                for (interfaces_array.array) |interface| {
                    try interfaces.append(try allocator.dupe(u8, interface.string));
                }
            }

            return Plugin{
                .name = try allocator.dupe(u8, obj.get("name").?.string),
                .version = try allocator.dupe(u8, obj.get("version").?.string),
                .interfaces = try interfaces.toOwnedSlice(),
            };
        }

        pub fn deinit(self: *Plugin, allocator: std.mem.Allocator) void {
            if (self.name.len > 0) allocator.free(@constCast(self.name));
            if (self.version.len > 0) allocator.free(@constCast(self.version));
            if (self.interfaces.len > 0) {
                for (self.interfaces) |iface| {
                    if (iface.len > 0) allocator.free(@constCast(iface));
                }
                allocator.free(@constCast(self.interfaces));
                self.interfaces = &[_][]const u8{};
            }
            self.name = "";
            self.version = "";
        }
    };

    pub fn init() NeoListPlugins {
        return NeoListPlugins{
            .plugins = &[_]Plugin{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoListPlugins {
        const array = json_value.array;

        var plugins = ArrayList(Plugin).init(allocator);
        for (array) |plugin_item| {
            try plugins.append(try Plugin.fromJson(plugin_item, allocator));
        }

        return NeoListPlugins{
            .plugins = try plugins.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *NeoListPlugins, allocator: std.mem.Allocator) void {
        if (self.plugins.len > 0) {
            for (self.plugins) |*plugin| {
                plugin.deinit(allocator);
            }
            allocator.free(@constCast(self.plugins));
            self.plugins = &[_]Plugin{};
        }
    }
};

/// Transaction send token (converted from Swift TransactionSendToken)
pub const TransactionSendToken = struct {
    asset: Hash160,
    value: i64,
    address: []const u8,

    pub fn init(asset: Hash160, value: i64, address: []const u8) TransactionSendToken {
        return TransactionSendToken{
            .asset = asset,
            .value = value,
            .address = address,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !TransactionSendToken {
        const obj = json_value.object;

        return TransactionSendToken.init(
            try Hash160.initWithString(obj.get("asset").?.string),
            obj.get("value").?.integer,
            try allocator.dupe(u8, obj.get("address").?.string),
        );
    }

    pub fn toJson(self: TransactionSendToken, allocator: std.mem.Allocator) !std.json.Value {
        var obj = std.json.ObjectMap.init(allocator);

        const asset_hex = try self.asset.string(allocator);
        defer allocator.free(asset_hex);

        try json_utils.putOwnedKey(&obj, allocator, "asset", std.json.Value{ .string = asset_hex });
        try json_utils.putOwnedKey(&obj, allocator, "value", std.json.Value{ .integer = self.value });
        try json_utils.putOwnedKey(&obj, allocator, "address", std.json.Value{ .string = self.address });

        return std.json.Value{ .object = obj };
    }
};

/// Neo get unclaimed GAS (converted from Swift NeoGetUnclaimedGas)
pub const NeoGetUnclaimedGas = struct {
    unclaimed: []const u8,
    address: []const u8,

    pub fn init() NeoGetUnclaimedGas {
        return NeoGetUnclaimedGas{
            .unclaimed = "0",
            .address = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetUnclaimedGas {
        const obj = json_value.object;

        return NeoGetUnclaimedGas{
            .unclaimed = try allocator.dupe(u8, obj.get("unclaimed").?.string),
            .address = try allocator.dupe(u8, obj.get("address").?.string),
        };
    }

    pub fn deinit(self: *NeoGetUnclaimedGas, allocator: std.mem.Allocator) void {
        if (self.unclaimed.len > 0) allocator.free(@constCast(self.unclaimed));
        if (self.address.len > 0) allocator.free(@constCast(self.address));
        self.unclaimed = "0";
        self.address = "";
    }
};

/// Neo get next block validators (converted from Swift NeoGetNextBlockValidators)
pub const NeoGetNextBlockValidators = struct {
    validators: []const Validator,

    pub const Validator = struct {
        public_key: []const u8,
        votes: []const u8,
        active: bool,

        pub fn init() Validator {
            return Validator{
                .public_key = "",
                .votes = "0",
                .active = false,
            };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Validator {
            const obj = json_value.object;

            return Validator{
                .public_key = try allocator.dupe(u8, obj.get("publickey").?.string),
                .votes = try allocator.dupe(u8, obj.get("votes").?.string),
                .active = obj.get("active").?.bool,
            };
        }

        pub fn deinit(self: *Validator, allocator: std.mem.Allocator) void {
            if (self.public_key.len > 0) allocator.free(@constCast(self.public_key));
            if (self.votes.len > 0) allocator.free(@constCast(self.votes));
            self.public_key = "";
            self.votes = "0";
        }
    };

    pub fn init() NeoGetNextBlockValidators {
        return NeoGetNextBlockValidators{
            .validators = &[_]Validator{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetNextBlockValidators {
        const array = json_value.array;

        var validators = ArrayList(Validator).init(allocator);
        for (array) |validator_item| {
            try validators.append(try Validator.fromJson(validator_item, allocator));
        }

        return NeoGetNextBlockValidators{
            .validators = try validators.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *NeoGetNextBlockValidators, allocator: std.mem.Allocator) void {
        if (self.validators.len > 0) {
            for (self.validators) |*validator| {
                validator.deinit(allocator);
            }
            allocator.free(@constCast(self.validators));
            self.validators = &[_]Validator{};
        }
    }
};

/// Neo get state height (converted from Swift NeoGetStateHeight)
pub const NeoGetStateHeight = struct {
    local_root_index: u32,
    validated_root_index: u32,

    pub fn init() NeoGetStateHeight {
        return NeoGetStateHeight{
            .local_root_index = 0,
            .validated_root_index = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetStateHeight {
        _ = allocator;
        const obj = json_value.object;

        return NeoGetStateHeight{
            .local_root_index = @intCast(obj.get("localrootindex").?.integer),
            .validated_root_index = @intCast(obj.get("validatedrootindex").?.integer),
        };
    }
};

/// Neo get state root (converted from Swift NeoGetStateRoot)
pub const NeoGetStateRoot = struct {
    version: u8,
    index: u32,
    root_hash: Hash256,
    witnesses: []const NeoWitness,

    pub fn init() NeoGetStateRoot {
        return NeoGetStateRoot{
            .version = 0,
            .index = 0,
            .root_hash = Hash256.ZERO,
            .witnesses = &[_]NeoWitness{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetStateRoot {
        const obj = json_value.object;

        var witnesses = ArrayList(NeoWitness).init(allocator);
        if (obj.get("witnesses")) |witnesses_array| {
            for (witnesses_array.array) |witness| {
                try witnesses.append(try NeoWitness.fromJson(witness, allocator));
            }
        }

        return NeoGetStateRoot{
            .version = @intCast(obj.get("version").?.integer),
            .index = @intCast(obj.get("index").?.integer),
            .root_hash = try Hash256.initWithString(obj.get("roothash").?.string),
            .witnesses = try witnesses.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *NeoGetStateRoot, allocator: std.mem.Allocator) void {
        if (self.witnesses.len > 0) {
            for (self.witnesses) |*witness| {
                witness.deinit(allocator);
            }
            allocator.free(@constCast(self.witnesses));
            self.witnesses = &[_]NeoWitness{};
        }
    }
};

/// Neo witness (converted from Swift NeoWitness)
pub const NeoWitness = struct {
    invocation: []const u8,
    verification: []const u8,

    pub fn init(invocation: []const u8, verification: []const u8) NeoWitness {
        return NeoWitness{
            .invocation = invocation,
            .verification = verification,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoWitness {
        const obj = json_value.object;

        return NeoWitness.init(
            try allocator.dupe(u8, obj.get("invocation").?.string),
            try allocator.dupe(u8, obj.get("verification").?.string),
        );
    }

    pub fn toJson(self: NeoWitness, allocator: std.mem.Allocator) !std.json.Value {
        var obj = std.json.ObjectMap.init(allocator);

        try json_utils.putOwnedKey(&obj, allocator, "invocation", std.json.Value{ .string = self.invocation });
        try json_utils.putOwnedKey(&obj, allocator, "verification", std.json.Value{ .string = self.verification });

        return std.json.Value{ .object = obj };
    }

    pub fn deinit(self: *NeoWitness, allocator: std.mem.Allocator) void {
        if (self.invocation.len > 0) allocator.free(@constCast(self.invocation));
        if (self.verification.len > 0) allocator.free(@constCast(self.verification));
        self.invocation = "";
        self.verification = "";
    }
};

/// NEP-17 contract (converted from Swift Nep17Contract)
pub const Nep17Contract = struct {
    script_hash: Hash160,
    symbol: []const u8,
    decimals: u8,

    pub fn init(script_hash: Hash160, symbol: []const u8, decimals: u8) Nep17Contract {
        return Nep17Contract{
            .script_hash = script_hash,
            .symbol = symbol,
            .decimals = decimals,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Nep17Contract {
        const obj = json_value.object;

        return Nep17Contract.init(
            try Hash160.initWithString(obj.get("scripthash").?.string),
            try allocator.dupe(u8, obj.get("symbol").?.string),
            @intCast(obj.get("decimals").?.integer),
        );
    }

    pub fn deinit(self: *Nep17Contract, allocator: std.mem.Allocator) void {
        if (self.symbol.len > 0) allocator.free(@constCast(self.symbol));
        self.symbol = "";
    }
};

/// Oracle response code (converted from Swift OracleResponseCode)
pub const OracleResponseCode = enum(u8) {
    Success = 0x00,
    ProtocolNotSupported = 0x10,
    ConsensusUnreachable = 0x12,
    NotFound = 0x14,
    Timeout = 0x16,
    Forbidden = 0x18,
    ResponseTooLarge = 0x1a,
    InsufficientFunds = 0x1c,
    ContentTypeNotSupported = 0x1f,
    Error = 0xff,

    const Self = @This();

    pub fn getByte(self: Self) u8 {
        return @intFromEnum(self);
    }

    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .Success => "Success",
            .ProtocolNotSupported => "ProtocolNotSupported",
            .ConsensusUnreachable => "ConsensusUnreachable",
            .NotFound => "NotFound",
            .Timeout => "Timeout",
            .Forbidden => "Forbidden",
            .ResponseTooLarge => "ResponseTooLarge",
            .InsufficientFunds => "InsufficientFunds",
            .ContentTypeNotSupported => "ContentTypeNotSupported",
            .Error => "Error",
        };
    }

    pub fn fromByte(byte_value: u8) ?Self {
        return switch (byte_value) {
            0x00 => .Success,
            0x10 => .ProtocolNotSupported,
            0x12 => .ConsensusUnreachable,
            0x14 => .NotFound,
            0x16 => .Timeout,
            0x18 => .Forbidden,
            0x1a => .ResponseTooLarge,
            0x1c => .InsufficientFunds,
            0x1f => .ContentTypeNotSupported,
            0xff => .Error,
            else => null,
        };
    }

    pub fn fromJsonValue(json_value: []const u8) ?Self {
        if (std.mem.eql(u8, json_value, "Success")) return .Success;
        if (std.mem.eql(u8, json_value, "NotFound")) return .NotFound;
        if (std.mem.eql(u8, json_value, "Timeout")) return .Timeout;
        if (std.mem.eql(u8, json_value, "Forbidden")) return .Forbidden;
        if (std.mem.eql(u8, json_value, "Error")) return .Error;
        return null;
    }
};

/// Neo network fee (converted from Swift NeoNetworkFee)
pub const NeoNetworkFee = struct {
    network_fee: u64,

    pub fn init() NeoNetworkFee {
        return NeoNetworkFee{ .network_fee = 0 };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoNetworkFee {
        _ = allocator;
        const obj = json_value.object;

        return NeoNetworkFee{
            .network_fee = @intCast(obj.get("networkfee").?.integer),
        };
    }
};

/// Neo validate address (converted from Swift NeoValidateAddress)
pub const NeoValidateAddress = struct {
    address: []const u8,
    is_valid: bool,

    pub fn init() NeoValidateAddress {
        return NeoValidateAddress{
            .address = "",
            .is_valid = false,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoValidateAddress {
        const obj = json_value.object;

        return NeoValidateAddress{
            .address = try allocator.dupe(u8, obj.get("address").?.string),
            .is_valid = obj.get("isvalid").?.bool,
        };
    }
};

/// Populated blocks (converted from Swift PopulatedBlocks)
pub const PopulatedBlocks = struct {
    count: u32,
    blocks: []const u32,

    pub fn init() PopulatedBlocks {
        return PopulatedBlocks{
            .count = 0,
            .blocks = &[_]u32{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !PopulatedBlocks {
        const obj = json_value.object;

        var blocks = ArrayList(u32).init(allocator);
        if (obj.get("blocks")) |blocks_array| {
            for (blocks_array.array) |block| {
                try blocks.append(@intCast(block.integer));
            }
        }

        return PopulatedBlocks{
            .count = @intCast(obj.get("count").?.integer),
            .blocks = try blocks.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *PopulatedBlocks, allocator: std.mem.Allocator) void {
        if (self.blocks.len > 0) allocator.free(@constCast(self.blocks));
        self.blocks = &[_]u32{};
    }
};

/// Record state (converted from Swift RecordState)
pub const RecordState = struct {
    name: []const u8,
    record_type: []const u8,
    data: []const u8,

    pub fn init() RecordState {
        return RecordState{
            .name = "",
            .record_type = "",
            .data = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !RecordState {
        const obj = json_value.object;

        return RecordState{
            .name = try allocator.dupe(u8, obj.get("name").?.string),
            .record_type = try allocator.dupe(u8, obj.get("type").?.string),
            .data = try allocator.dupe(u8, obj.get("data").?.string),
        };
    }

    pub fn deinit(self: *RecordState, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.record_type.len > 0) allocator.free(@constCast(self.record_type));
        if (self.data.len > 0) allocator.free(@constCast(self.data));
        self.name = "";
        self.record_type = "";
        self.data = "";
    }
};

/// Native contract state (converted from Swift NativeContractState)
pub const NativeContractState = struct {
    id: i32,
    hash: Hash160,
    nef: ContractNef,
    manifest: ContractManifest,
    update_history: []const u32,

    pub fn init() NativeContractState {
        return NativeContractState{
            .id = 0,
            .hash = Hash160.ZERO,
            .nef = ContractNef.init(),
            .manifest = ContractManifest.init(),
            .update_history = &[_]u32{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NativeContractState {
        const obj = json_value.object;

        var update_history = ArrayList(u32).init(allocator);
        if (obj.get("updatehistory")) |history_array| {
            for (history_array.array) |item| {
                try update_history.append(@intCast(item.integer));
            }
        }

        return NativeContractState{
            .id = @intCast(obj.get("id").?.integer),
            .hash = try Hash160.initWithString(obj.get("hash").?.string),
            .nef = try ContractNef.fromJson(obj.get("nef").?, allocator),
            .manifest = try ContractManifest.fromJson(obj.get("manifest").?, allocator),
            .update_history = try update_history.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *NativeContractState, allocator: std.mem.Allocator) void {
        self.nef.deinit(allocator);
        self.manifest.deinit(allocator);
        if (self.update_history.len > 0) allocator.free(@constCast(self.update_history));
        self.update_history = &[_]u32{};
    }
};

/// Express contract state (converted from Swift ExpressContractState)
pub const ExpressContractState = struct {
    hash: Hash160,
    manifest: ContractManifest,

    pub fn init() ExpressContractState {
        return ExpressContractState{
            .hash = Hash160.ZERO,
            .manifest = ContractManifest.init(),
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ExpressContractState {
        const obj = json_value.object;

        return ExpressContractState{
            .hash = try Hash160.initWithString(obj.get("hash").?.string),
            .manifest = try ContractManifest.fromJson(obj.get("manifest").?, allocator),
        };
    }

    pub fn deinit(self: *ExpressContractState, allocator: std.mem.Allocator) void {
        self.manifest.deinit(allocator);
    }
};

/// Express shutdown (converted from Swift ExpressShutdown)
pub const ExpressShutdown = struct {
    process_id: u32,

    pub fn init() ExpressShutdown {
        return ExpressShutdown{ .process_id = 0 };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ExpressShutdown {
        _ = allocator;
        const obj = json_value.object;

        return ExpressShutdown{
            .process_id = @intCast(obj.get("processId").?.integer),
        };
    }
};

/// Diagnostics (converted from Swift Diagnostics)
pub const Diagnostics = struct {
    invocation_id: []const u8,
    invocation_counter: u32,

    pub fn init() Diagnostics {
        return Diagnostics{
            .invocation_id = "",
            .invocation_counter = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Diagnostics {
        const obj = json_value.object;

        return Diagnostics{
            .invocation_id = try allocator.dupe(u8, obj.get("invocationId").?.string),
            .invocation_counter = @intCast(obj.get("invocationCounter").?.integer),
        };
    }

    pub fn deinit(self: *Diagnostics, allocator: std.mem.Allocator) void {
        if (self.invocation_id.len > 0) allocator.free(@constCast(self.invocation_id));
        self.invocation_id = "";
    }
};

// Import dependencies
const ContractManifest = @import("protocol_responses.zig").ContractManifest;
const ContractNef = @import("protocol_responses.zig").ContractNef;
pub const ContractStorageEntry = @import("protocol_responses.zig").ContractStorageEntry;

// Tests (converted from ALL Swift response tests)
test "NeoAccountState response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test account state creation (equivalent to Swift NeoAccountState tests)
    const account_state = NeoAccountState.init(100000000, 12345, "02b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816");

    try testing.expectEqual(@as(i64, 100000000), account_state.balance);
    try testing.expectEqual(@as(u32, 12345), account_state.balance_height.?);
    try testing.expect(account_state.public_key != null);

    // Test factory methods
    const no_vote_state = NeoAccountState.withNoVote(50000000, 54321);
    try testing.expectEqual(@as(i64, 50000000), no_vote_state.balance);
    try testing.expect(no_vote_state.public_key == null);

    const no_balance_state = NeoAccountState.withNoBalance();
    try testing.expectEqual(@as(i64, 0), no_balance_state.balance);
    try testing.expect(no_balance_state.balance_height == null);
}

test "Oracle response types" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test oracle request (equivalent to Swift OracleRequest tests)
    const oracle_request = OracleRequest.init();
    try testing.expectEqual(@as(usize, 0), oracle_request.url.len);
    try testing.expect(oracle_request.filter == null);

    // Test oracle response codes (equivalent to Swift OracleResponseCode tests)
    try testing.expectEqual(@as(u8, 0x00), OracleResponseCode.Success.getByte());
    try testing.expectEqual(@as(u8, 0x14), OracleResponseCode.NotFound.getByte());
    try testing.expectEqual(@as(u8, 0xff), OracleResponseCode.Error.getByte());

    try testing.expectEqualStrings("Success", OracleResponseCode.Success.getJsonValue());
    try testing.expectEqualStrings("NotFound", OracleResponseCode.NotFound.getJsonValue());

    // Test enum from byte conversion
    try testing.expectEqual(OracleResponseCode.Success, OracleResponseCode.fromByte(0x00).?);
    try testing.expectEqual(OracleResponseCode.NotFound, OracleResponseCode.fromByte(0x14).?);
    try testing.expectEqual(@as(?OracleResponseCode, null), OracleResponseCode.fromByte(0x99));
}

test "Validator and network response types" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test validator response (equivalent to Swift validator tests)
    const validator = NeoGetNextBlockValidators.Validator.init();
    try testing.expectEqual(@as(usize, 0), validator.public_key.len);
    try testing.expectEqualStrings("0", validator.votes);
    try testing.expect(!validator.active);

    // Test validators response
    const validators = NeoGetNextBlockValidators.init();
    try testing.expectEqual(@as(usize, 0), validators.validators.len);

    // Test state height response
    const state_height = NeoGetStateHeight.init();
    try testing.expectEqual(@as(u32, 0), state_height.local_root_index);
    try testing.expectEqual(@as(u32, 0), state_height.validated_root_index);
}

test "Transaction and contract response types" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test transaction send token (equivalent to Swift TransactionSendToken tests)
    const send_token = TransactionSendToken.init(
        Hash160.ZERO,
        100000000,
        "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7",
    );

    try testing.expect(send_token.asset.eql(Hash160.ZERO));
    try testing.expectEqual(@as(i64, 100000000), send_token.value);

    // Test contract method token
    const method_token = ContractMethodToken.init();
    try testing.expect(method_token.hash.eql(Hash160.ZERO));
    try testing.expectEqual(@as(usize, 0), method_token.method.len);
    try testing.expectEqual(@as(u16, 0), method_token.parameters_count);

    // Test NEP-17 contract
    const nep17_contract = Nep17Contract.init(Hash160.ZERO, "TEST", 8);
    try testing.expectEqualStrings("TEST", nep17_contract.symbol);
    try testing.expectEqual(@as(u8, 8), nep17_contract.decimals);
}

test "State and diagnostic response types" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test state root response (equivalent to Swift state root tests)
    const state_root = NeoGetStateRoot.init();
    try testing.expectEqual(@as(u8, 0), state_root.version);
    try testing.expectEqual(@as(u32, 0), state_root.index);
    try testing.expect(state_root.root_hash.eql(Hash256.ZERO));

    // Test record state
    const record_state = RecordState.init();
    try testing.expectEqual(@as(usize, 0), record_state.name.len);
    try testing.expectEqual(@as(usize, 0), record_state.record_type.len);

    // Test diagnostics
    const diagnostics = Diagnostics.init();
    try testing.expectEqual(@as(usize, 0), diagnostics.invocation_id.len);
    try testing.expectEqual(@as(u32, 0), diagnostics.invocation_counter);
}
