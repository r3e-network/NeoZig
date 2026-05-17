//! Aggregator for protocol response models (network + wallet categories).

const std = @import("std");

pub const network = @import("protocol_network_responses.zig");
pub const wallet = @import("protocol_wallet_responses.zig");

pub const NeoGetMemPool = network.NeoGetMemPool;
pub const NeoGetPeers = network.NeoGetPeers;
pub const Peer = network.Peer;

pub const NeoGetWalletBalance = wallet.NeoGetWalletBalance;
pub const NeoGetClaimable = wallet.NeoGetClaimable;
pub const ClaimableTransaction = wallet.ClaimableTransaction;

test "protocol responses module exposes submodule namespaces" {
    const testing = std.testing;
    try testing.expect(network.NeoGetPeers == NeoGetPeers);
    try testing.expect(wallet.NeoGetClaimable == NeoGetClaimable);
}
