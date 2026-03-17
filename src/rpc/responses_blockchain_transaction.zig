const std = @import("std");
const ArrayList = std.ArrayList;

const common = @import("responses_common.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const NeoVMStateType = @import("../types/neo_vm_state_type.zig").NeoVMStateType;
const TransactionAttribute = @import("../protocol/response/transaction_attribute.zig").TransactionAttribute;

const stringifyJsonValue = common.stringifyJsonValue;

/// Neo witness
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

/// Transaction response
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

/// Transaction signer
pub const TransactionSigner = struct {
    account: Hash160,
    scopes: []const u8,
    allowed_contracts: ?[]Hash160,
    allowed_groups: ?[][33]u8,
    rules: ?[]WitnessRule,

    const Self = @This();

    pub fn init() Self {
        return std.mem.zeroes(Self);
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

        var allowed_groups_slice: ?[][33]u8 = null;
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

/// Witness rule
pub const WitnessRule = struct {
    action: []const u8,
    condition: WitnessCondition,

    const Self = @This();

    pub fn init() Self {
        return Self{ .action = "", .condition = WitnessCondition.init() };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        const action = try allocator.dupe(u8, obj.get("action").?.string);
        const condition = try WitnessCondition.fromJson(obj.get("condition").?, allocator);
        return Self{ .action = action, .condition = condition };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.action);
        self.condition.deinit(allocator);
    }
};

/// Witness condition
pub const WitnessCondition = struct {
    condition_type: []const u8,
    value: []const u8,

    const Self = @This();

    pub fn init() Self {
        return Self{ .condition_type = "", .value = "" };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        const condition_type = try allocator.dupe(u8, obj.get("type").?.string);
        const value_json = obj.get("value") orelse std.json.Value{ .string = "" };
        const value = switch (value_json) {
            .string => |str| try allocator.dupe(u8, str),
            else => try stringifyJsonValue(value_json, allocator),
        };
        return Self{ .condition_type = condition_type, .value = value };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.condition_type);
        allocator.free(self.value);
    }
};
