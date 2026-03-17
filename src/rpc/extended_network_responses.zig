const std = @import("std");
const ArrayList = std.ArrayList;
const json_utils = @import("../utils/json_utils.zig");

const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;

/// Neo get next block validators
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
        if (json_value != .array) return errors.SerializationError.InvalidFormat;
        const array = json_value.array;

        var validators = ArrayList(Validator).init(allocator);
        errdefer {
            for (validators.items) |*validator| validator.deinit(allocator);
            validators.deinit();
        }
        for (array.items) |validator_item| {
            var validator = try Validator.fromJson(validator_item, allocator);
            errdefer validator.deinit(allocator);
            try validators.append(validator);
        }

        return NeoGetNextBlockValidators{ .validators = try validators.toOwnedSlice() };
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

/// Neo get state height
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

/// Neo witness
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
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const invocation_value = obj.get("invocation") orelse return errors.SerializationError.InvalidFormat;
        if (invocation_value != .string) return errors.SerializationError.InvalidFormat;
        const invocation = try allocator.dupe(u8, invocation_value.string);
        errdefer allocator.free(invocation);

        const verification_value = obj.get("verification") orelse return errors.SerializationError.InvalidFormat;
        if (verification_value != .string) return errors.SerializationError.InvalidFormat;
        const verification = try allocator.dupe(u8, verification_value.string);
        errdefer allocator.free(verification);

        return NeoWitness.init(invocation, verification);
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

/// Neo get state root
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
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var witnesses = ArrayList(NeoWitness).init(allocator);
        errdefer {
            for (witnesses.items) |*witness| witness.deinit(allocator);
            witnesses.deinit();
        }
        if (obj.get("witnesses")) |witnesses_array| {
            if (witnesses_array != .array) return errors.SerializationError.InvalidFormat;
            for (witnesses_array.array.items) |witness| {
                var parsed = try NeoWitness.fromJson(witness, allocator);
                errdefer parsed.deinit(allocator);
                try witnesses.append(parsed);
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

/// Neo network fee
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

/// Populated blocks
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
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var blocks = ArrayList(u32).init(allocator);
        errdefer blocks.deinit();
        if (obj.get("blocks")) |blocks_array| {
            if (blocks_array != .array) return errors.SerializationError.InvalidFormat;
            for (blocks_array.array.items) |block| {
                if (block != .integer) return errors.SerializationError.InvalidFormat;
                try blocks.append(@intCast(block.integer));
            }
        }

        return PopulatedBlocks{ .count = @intCast(obj.get("count").?.integer), .blocks = try blocks.toOwnedSlice() };
    }

    pub fn deinit(self: *PopulatedBlocks, allocator: std.mem.Allocator) void {
        if (self.blocks.len > 0) allocator.free(@constCast(self.blocks));
        self.blocks = &[_]u32{};
    }
};
