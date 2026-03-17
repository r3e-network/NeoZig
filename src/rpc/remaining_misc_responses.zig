const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const StackItem = @import("../types/stack_item.zig").StackItem;
const responses = @import("responses.zig");
const extended_responses = @import("extended_responses.zig");
const token_responses = @import("token_responses.zig");
const node = @import("remaining_node_responses.zig");
const transaction_attribute_mod = @import("../protocol/response/transaction_attribute.zig");

/// Transaction attribute response (typed)
pub const TransactionAttributeResponse = transaction_attribute_mod.TransactionAttribute;

/// Notification response
pub const NotificationResponse = struct {
    contract: Hash160,
    event_name: []const u8,
    state: []StackItem,

    pub fn init() NotificationResponse {
        return NotificationResponse{
            .contract = Hash160.ZERO,
            .event_name = "",
            .state = &[_]StackItem{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NotificationResponse {
        const obj = json_value.object;

        const contract = try Hash160.initWithString(obj.get("contract").?.string);
        const event_name = try allocator.dupe(u8, obj.get("eventname").?.string);
        errdefer allocator.free(event_name);

        var state_list = ArrayList(StackItem).init(allocator);
        errdefer {
            for (state_list.items) |*item| item.deinit(allocator);
            state_list.deinit();
        }
        if (obj.get("state")) |state_array| {
            if (state_array != .array) return errors.SerializationError.InvalidFormat;
            for (state_array.array.items) |state_item| {
                var decoded = try StackItem.decodeFromJson(state_item, allocator);
                var decoded_guard = true;
                defer if (decoded_guard) decoded.deinit(allocator);
                try state_list.append(decoded);
                decoded_guard = false;
            }
        }

        return NotificationResponse{
            .contract = contract,
            .event_name = event_name,
            .state = try state_list.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *NotificationResponse, allocator: std.mem.Allocator) void {
        if (self.event_name.len > 0) allocator.free(@constCast(self.event_name));
        if (self.state.len > 0) {
            for (self.state) |*item| {
                item.deinit(allocator);
            }
            allocator.free(self.state);
        }
    }
};

/// Response aliases and specialized types
pub const ResponseAliases = struct {
    // Blockchain response aliases
    pub const NeoBlockHash = Hash256;
    pub const NeoBlockCount = u32;
    pub const NeoBlockHeaderCount = u32;
    pub const NeoConnectionCount = u32;

    // Transaction response aliases
    pub const NeoGetRawTransaction = []const u8;
    pub const NeoGetRawBlock = []const u8;
    pub const NeoSubmitBlock = bool;
    pub const NeoCalculateNetworkFee = u64;

    // Wallet response aliases
    pub const NeoCloseWallet = bool;
    pub const NeoDumpPrivKey = []const u8;
    pub const NeoGetNewAddress = []const u8;
    pub const NeoGetWalletUnclaimedGas = []const u8;
    pub const NeoImportPrivKey = extended_responses.NeoAddress;
    pub const NeoOpenWallet = bool;
    pub const NeoSendFrom = responses.Transaction;
    pub const NeoSendMany = responses.Transaction;
    pub const NeoSendToAddress = responses.Transaction;

    // Contract response aliases
    pub const NeoGetContractState = responses.ContractState;
    pub const NeoGetNativeContracts = []const extended_responses.NativeContractState;
    pub const NeoInvokeFunction = responses.InvocationResult;
    pub const NeoInvokeScript = responses.InvocationResult;
    pub const NeoInvokeContractVerify = responses.InvocationResult;
    pub const NeoTraverseIterator = []StackItem;
    pub const NeoTerminateSession = bool;

    // State service aliases
    pub const NeoGetStorage = []const u8;
    pub const NeoGetTransactionHeight = u32;
    pub const NeoGetProof = []const u8;
    pub const NeoVerifyProof = []const u8;
    pub const NeoGetState = []const u8;

    // Utility aliases
    pub const NeoGetCommittee = []const []const u8;

    /// Type registry for response parsing
    pub const ResponseTypeRegistry = struct {
        /// Gets response type by method name
        pub fn getResponseType(method: []const u8) type {
            if (std.mem.eql(u8, method, "getbestblockhash")) return NeoBlockHash;
            if (std.mem.eql(u8, method, "getblockcount")) return NeoBlockCount;
            if (std.mem.eql(u8, method, "getconnectioncount")) return NeoConnectionCount;
            if (std.mem.eql(u8, method, "getversion")) return node.NeoGetVersion;
            if (std.mem.eql(u8, method, "getnep17balances")) return token_responses.NeoGetNep17Balances;
            if (std.mem.eql(u8, method, "getnep11balances")) return token_responses.NeoGetNep11Balances;
            if (std.mem.eql(u8, method, "invokefunction")) return NeoInvokeFunction;
            if (std.mem.eql(u8, method, "sendrawtransaction")) return node.NeoSendRawTransaction;
            if (std.mem.eql(u8, method, "calculatenetworkfee")) return NeoCalculateNetworkFee;

            // Default to generic JSON value
            return std.json.Value;
        }

        /// Checks if method is supported
        pub fn isMethodSupported(method: []const u8) bool {
            const supported_methods = [_][]const u8{
                "getbestblockhash",  "getblockcount",     "getconnectioncount",  "getversion",
                "getblock",          "getblockhash",      "getrawtransaction",   "sendrawtransaction",
                "invokefunction",    "invokescript",      "getnep17balances",    "getnep11balances",
                "getnep17transfers", "getnep11transfers", "calculatenetworkfee", "validateaddress",
                "listplugins",       "getapplicationlog",
            };

            for (supported_methods) |supported| {
                if (std.mem.eql(u8, method, supported)) {
                    return true;
                }
            }

            return false;
        }
    };
};

/// Express shutdown response
pub const ExpressShutdownResponse = struct {
    process_id: u32,
    message: []const u8,

    pub fn init() ExpressShutdownResponse {
        return ExpressShutdownResponse{
            .process_id = 0,
            .message = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ExpressShutdownResponse {
        const obj = json_value.object;

        return ExpressShutdownResponse{
            .process_id = @intCast(obj.get("processId").?.integer),
            .message = try allocator.dupe(u8, obj.get("message").?.string),
        };
    }
};

/// Diagnostics response (extended from basic diagnostics)
pub const DiagnosticsResponse = struct {
    invocation_id: []const u8,
    invocation_counter: u32,
    execution_time: u64,
    gas_consumed: []const u8,

    pub fn init() DiagnosticsResponse {
        return DiagnosticsResponse{
            .invocation_id = "",
            .invocation_counter = 0,
            .execution_time = 0,
            .gas_consumed = "0",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !DiagnosticsResponse {
        const obj = json_value.object;

        return DiagnosticsResponse{
            .invocation_id = try allocator.dupe(u8, obj.get("invocationId").?.string),
            .invocation_counter = @intCast(obj.get("invocationCounter").?.integer),
            .execution_time = @intCast(obj.get("executionTime").?.integer),
            .gas_consumed = try allocator.dupe(u8, obj.get("gasConsumed").?.string),
        };
    }
};
