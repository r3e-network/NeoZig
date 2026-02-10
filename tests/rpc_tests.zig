//! RPC tests
//!
//! Complete conversion of NeoClient RPC test suite.

const std = @import("std");

const neo = @import("neo-zig");

// Tests RPC client creation
test "NeoClient client creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test client creation
    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");

    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test configuration properties
    try testing.expectEqual(@as(u32, 15000), client.getBlockInterval());
    try testing.expectEqual(@as(u32, 15000), client.getPollingInterval());
    try testing.expectEqual(@as(u32, 5760), client.getMaxValidUntilBlockIncrement());

    // Test NNS resolver
    const nns_resolver = client.getNnsResolver();
    try testing.expect(nns_resolver.eql(neo.rpc.NeoConfig.MAINNET_NNS_CONTRACT_HASH));
}

// Tests client configuration methods
test "NeoClient client configuration methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test fault transmission setting
    client.allowTransmissionOnFault();
    try testing.expect(client.config.allows_transmission_on_fault);

    client.preventTransmissionOnFault();
    try testing.expect(!client.config.allows_transmission_on_fault);

    // Test NNS resolver setting
    const test_resolver = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    client.setNNSResolver(test_resolver);
    try testing.expect(client.getNnsResolver().eql(test_resolver));
}

// Tests RPC request creation
test "RPC request creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test blockchain method requests
    const best_block_request = try client.getBestBlockHash();
    try testing.expectEqualStrings("getbestblockhash", best_block_request.method);

    const block_count_request = try client.getBlockCount();
    try testing.expectEqualStrings("getblockcount", block_count_request.method);

    const connection_count_request = try client.getConnectionCount();
    try testing.expectEqualStrings("getconnectioncount", connection_count_request.method);

    const version_request = try client.getVersion();
    try testing.expectEqualStrings("getversion", version_request.method);
}

// Tests parameterized RPC requests
test "RPC parameterized requests" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test block hash request
    const block_hash_request = try client.getBlockHash(12345);
    try testing.expectEqualStrings("getblockhash", block_hash_request.method);

    // Test block request with parameters
    const test_hash = try neo.Hash256.initWithString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const block_request = try client.getBlock(test_hash, true);
    try testing.expectEqualStrings("getblock", block_request.method);

    const block_by_index_request = try client.getBlockByIndex(12345, false);
    try testing.expectEqualStrings("getblock", block_by_index_request.method);
}

// Tests contract invocation requests
test "RPC contract invocation requests" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test contract function invocation
    const contract_hash = neo.Hash160.ZERO;
    const params = [_]neo.ContractParameter{
        neo.ContractParameter.string("test_param"),
        neo.ContractParameter.integer(42),
    };
    const signers = [_]neo.transaction.Signer{};

    const invoke_request = try client.invokeFunction(contract_hash, "testMethod", &params, &signers);
    try testing.expectEqualStrings("invokefunction", invoke_request.method);

    // Test script invocation
    const script_hex = "0c21036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29641419ed9d4";
    const script_invoke_request = try client.invokeScript(script_hex, &signers);
    try testing.expectEqualStrings("invokescript", script_invoke_request.method);
}

// Tests wallet RPC methods
test "RPC wallet methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test NEP-17 balance request
    const test_script_hash = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const balances_request = try client.getNep17Balances(test_script_hash);
    try testing.expectEqualStrings("getnep17balances", balances_request.method);

    // Test NEP-17 transfers request
    const transfers_request = try client.getNep17Transfers(test_script_hash, null, null);
    try testing.expectEqualStrings("getnep17transfers", transfers_request.method);

    // Test transfers with time parameters
    const from_time: u64 = 1609459200; // 2021-01-01
    const to_time: u64 = 1640995200; // 2022-01-01
    const transfers_with_time = try client.getNep17Transfers(test_script_hash, from_time, to_time);
    try testing.expectEqualStrings("getnep17transfers", transfers_with_time.method);
}

// Tests transaction RPC methods
test "RPC transaction methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test transaction retrieval
    const test_tx_hash = try neo.Hash256.initWithString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const tx_request = try client.getTransaction(test_tx_hash);
    try testing.expectEqualStrings("getrawtransaction", tx_request.method);

    // Test raw transaction sending
    const raw_tx_hex = "00d1001b0c14aa8acf859bbcd2bed27f5165eae0d3f3c1935e890c1441766430";
    const send_request = try client.sendRawTransaction(raw_tx_hex);
    try testing.expectEqualStrings("sendrawtransaction", send_request.method);

    // Test network fee calculation
    const fee_request = try client.calculateNetworkFee(raw_tx_hex);
    try testing.expectEqualStrings("calculatenetworkfee", fee_request.method);
}

// Tests utility RPC methods
test "RPC utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test address validation
    const test_address = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNn";
    const validate_request = try client.validateAddress(test_address);
    try testing.expectEqualStrings("validateaddress", validate_request.method);
}

// Tests network magic handling
test "network magic number handling" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const expected_magic: u32 = 0x01020304;
    var config = neo.rpc.NeoConfig.init();
    _ = config.setNetworkMagic(expected_magic);
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    // Test network magic retrieval
    const magic_number = try client.getNetworkMagicNumber();
    try testing.expectEqual(expected_magic, magic_number);

    // Test magic number as bytes
    const magic_bytes = try client.getNetworkMagicNumberBytes();
    try testing.expectEqual(@as(usize, 4), magic_bytes.len);
    try testing.expectEqual(std.mem.toBytes(std.mem.nativeToBig(u32, expected_magic)), magic_bytes);
}

// Tests response type initialization
test "RPC response type validation" {
    const testing = std.testing;

    // Test response type creation
    const block = neo.rpc.NeoBlock.initDefault();
    try testing.expectEqual(neo.Hash256.ZERO, block.hash);

    const version = neo.rpc.NeoVersion.init();
    try testing.expectEqual(@as(u16, 0), version.tcp_port);

    const invocation_result = neo.rpc.InvocationResult.init();
    try testing.expectEqual(@as(usize, 0), invocation_result.script.len);

    const balances = neo.rpc.Nep17Balances.init();
    try testing.expectEqual(@as(usize, 0), balances.balance.len);

    const transfers = neo.rpc.Nep17Transfers.init();
    try testing.expectEqual(@as(usize, 0), transfers.sent.len);
}

test "NeoVersion.fromJson parses real getversion payload shape" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Representative sample from a Neo N3 node (`getversion`), with `wsport` omitted.
    const json =
        \\{
        \\  "tcpport": 20333,
        \\  "nonce": 4022420097,
        \\  "useragent": "/NEO-GO:0.112.0/",
        \\  "protocol": {
        \\    "addressversion": 53,
        \\    "network": 894710606,
        \\    "msperblock": 3000,
        \\    "maxtraceableblocks": 2102400,
        \\    "maxvaliduntilblockincrement": 5760,
        \\    "maxtransactionsperblock": 5000,
        \\    "memorypoolmaxtransactions": 50000,
        \\    "validatorscount": 7,
        \\    "initialgasdistribution": 5200000000000000
        \\  }
        \\}
    ;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    var version = try neo.rpc.NeoVersion.fromJson(parsed.value, allocator);
    defer version.deinit(allocator);

    try testing.expectEqual(@as(u16, 20333), version.tcp_port);
    try testing.expectEqual(@as(u16, 0), version.ws_port);
    try testing.expectEqual(@as(u32, 4022420097), version.nonce);

    try testing.expect(version.protocol != null);
    const protocol = version.protocol.?;
    try testing.expectEqual(@as(u8, 53), protocol.address_version);
    try testing.expectEqual(@as(u32, 894710606), protocol.network);
    try testing.expectEqual(@as(?u32, 3000), protocol.ms_per_block);
    try testing.expectEqual(@as(?u32, 5760), protocol.max_valid_until_block_increment);
}
