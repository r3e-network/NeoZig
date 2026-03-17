//! Complete Protocol Response Types
//!
//! Protocol response types
//! for complete RPC functionality.

const std = @import("std");
const json_utils = @import("../utils/json_utils.zig");

pub const contract = @import("protocol_contract_responses.zig");
pub const network = @import("protocol_network_responses.zig");
pub const wallet = @import("protocol_wallet_responses.zig");

pub const ContractNef = contract.ContractNef;
pub const ContractManifest = contract.ContractManifest;
pub const ContractGroup = contract.ContractGroup;
pub const ContractABI = contract.ContractABI;
pub const ContractMethodInfo = contract.ContractMethodInfo;
pub const ContractParameterDefinition = contract.ContractParameterDefinition;
pub const ContractEventInfo = contract.ContractEventInfo;
pub const ContractPermission = contract.ContractPermission;
pub const ContractStorageEntry = contract.ContractStorageEntry;

pub const NeoGetMemPool = network.NeoGetMemPool;
pub const NeoGetPeers = network.NeoGetPeers;
pub const Peer = network.Peer;

pub const NeoGetWalletBalance = wallet.NeoGetWalletBalance;
pub const NeoGetClaimable = wallet.NeoGetClaimable;
pub const ClaimableTransaction = wallet.ClaimableTransaction;

test "protocol responses module exposes category namespaces" {
    const testing = std.testing;

    try testing.expect(contract.ContractManifest == ContractManifest);
    try testing.expect(network.NeoGetPeers == NeoGetPeers);
    try testing.expect(wallet.NeoGetClaimable == NeoGetClaimable);
}

test "ContractManifest parsing and operations" {
    const testing = std.testing;
    _ = testing.allocator;

    const manifest = ContractManifest.init(
        "TestContract",
        &[_]ContractGroup{},
        null,
        &[_][]const u8{},
        null,
        &[_]ContractPermission{},
        &[_][]const u8{},
        null,
    );

    try testing.expectEqualStrings("TestContract", manifest.name.?);
    try testing.expectEqual(@as(usize, 0), manifest.groups.len);
}

test "ContractGroup validation" {
    const testing = std.testing;
    _ = testing.allocator;

    const valid_pub_key = "02b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    const valid_signature = "dGVzdF9zaWduYXR1cmU=";

    const group = ContractGroup.init(valid_pub_key, valid_signature);
    try testing.expectEqualStrings(valid_pub_key, group.pub_key);
    try testing.expectEqualStrings(valid_signature, group.signature);
}

test "Memory pool response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    const mempool = NeoGetMemPool.init();
    try testing.expectEqual(@as(u32, 0), mempool.height);
    try testing.expectEqual(@as(usize, 0), mempool.verified.len);
    try testing.expectEqual(@as(usize, 0), mempool.unverified.len);
}

test "Peers response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    const peers = NeoGetPeers.init();
    try testing.expectEqual(@as(usize, 0), peers.connected.len);
    try testing.expectEqual(@as(usize, 0), peers.unconnected.len);
    try testing.expectEqual(@as(usize, 0), peers.bad.len);

    const peer = Peer.init("127.0.0.1", 20333);
    try testing.expectEqualStrings("127.0.0.1", peer.address);
    try testing.expectEqual(@as(u16, 20333), peer.port);
}

test "Protocol response fromJson smoke tests" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var features_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&features_obj, allocator, "featureA", std.json.Value{ .bool = true });

    var standards_array = std.json.Array.init(allocator);
    try standards_array.append(std.json.Value{ .string = "NEP-17" });

    var trusts_array = std.json.Array.init(allocator);
    try trusts_array.append(std.json.Value{ .string = "*" });

    var methods_array = std.json.Array.init(allocator);
    try methods_array.append(std.json.Value{ .string = "transfer" });

    var permission_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&permission_obj, allocator, "contract", std.json.Value{ .string = "*" });
    try json_utils.putOwnedKey(&permission_obj, allocator, "methods", std.json.Value{ .array = methods_array });

    var permissions_array = std.json.Array.init(allocator);
    try permissions_array.append(std.json.Value{ .object = permission_obj });

    var manifest_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&manifest_obj, allocator, "name", std.json.Value{ .string = "TestContract" });
    try json_utils.putOwnedKey(&manifest_obj, allocator, "features", std.json.Value{ .object = features_obj });
    try json_utils.putOwnedKey(&manifest_obj, allocator, "supportedstandards", std.json.Value{ .array = standards_array });
    try json_utils.putOwnedKey(&manifest_obj, allocator, "permissions", std.json.Value{ .array = permissions_array });
    try json_utils.putOwnedKey(&manifest_obj, allocator, "trusts", std.json.Value{ .array = trusts_array });

    var parsed_manifest = try ContractManifest.fromJson(std.json.Value{ .object = manifest_obj }, allocator);
    try testing.expect(parsed_manifest.name != null);
    parsed_manifest.deinit(allocator);

    const abi_obj = std.json.ObjectMap.init(allocator);
    var parsed_abi = try ContractABI.fromJson(std.json.Value{ .object = abi_obj }, allocator);
    defer parsed_abi.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), parsed_abi.methods.len);
    try testing.expectEqual(@as(usize, 0), parsed_abi.events.len);
}
