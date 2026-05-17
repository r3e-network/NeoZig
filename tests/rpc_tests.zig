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

test "NeoConfig and NeoClient builders expose sdk-style configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const resolver = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const config = try neo.rpc.NeoConfig.builder()
        .networkMagic(894710606)
        .blockInterval(3000)
        .pollingInterval(1500)
        .allowTransmissionOnFault(true)
        .nnsResolver(resolver)
        .build();

    try testing.expectEqual(@as(u32, 3000), config.block_interval);
    try testing.expectEqual(@as(u32, 1500), config.polling_interval);
    try testing.expect(config.allows_transmission_on_fault);
    try testing.expect(config.nns_resolver.eql(resolver));

    var client = try neo.rpc.NeoClient.builder(allocator)
        .endpoint("http://localhost:20332")
        .config(config)
        .includeRawResponses(true)
        .timeoutMs(15000)
        .maxRetries(5)
        .maxResponseBytes(1024 * 1024)
        .build();
    defer client.deinit();

    try testing.expectEqual(@as(u32, 3000), client.getBlockInterval());
    try testing.expectEqual(@as(u32, 1500), client.getPollingInterval());
    try testing.expect(client.config.allows_transmission_on_fault);
    try testing.expectEqual(@as(u32, 15000), client.service.service_impl.http_service.http_client.timeout_ms);
    try testing.expectEqual(@as(u32, 5), client.service.service_impl.http_service.http_client.max_retries);
    try testing.expectEqual(@as(usize, 1024 * 1024), client.service.service_impl.http_service.http_client.max_response_bytes);
    try testing.expect(client.service.service_impl.http_service.include_raw_responses);

    var from_endpoint_client = try neo.rpc.NeoClient.fromEndpoint(
        allocator,
        "http://localhost:20332",
        config,
    );
    defer from_endpoint_client.deinit();

    try testing.expectEqual(@as(u32, 3000), from_endpoint_client.getBlockInterval());
    try testing.expect(std.mem.eql(u8, "http://localhost:20332", from_endpoint_client.service.service_impl.http_service.url));
}

test "rpc module exposes flat aliases over legacy types" {
    const testing = std.testing;
    const allocator = testing.allocator;

    try testing.expect(neo.rpc.Client == neo.rpc.NeoClient);
    try testing.expect(neo.rpc.Config == neo.rpc.NeoConfig);
    try testing.expect(neo.rpc.Service == neo.rpc.NeoService);

    const config = try neo.rpc.Config.builder()
        .blockInterval(4000)
        .pollingInterval(2000)
        .build();

    var client = try neo.rpc.Client.builder(allocator)
        .endpoint("http://localhost:20332")
        .config(config)
        .build();
    defer client.deinit();

    try testing.expectEqual(@as(u32, 4000), client.getBlockInterval());

    const version = neo.rpc.types.NeoVersion.init();
    try testing.expectEqual(@as(u16, 0), version.tcp_port);
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
    var best_block_request = try client.getBestBlockHash();
    defer best_block_request.deinit();
    try testing.expectEqualStrings("getbestblockhash", best_block_request.method);

    var block_count_request = try client.getBlockCount();
    defer block_count_request.deinit();
    try testing.expectEqualStrings("getblockcount", block_count_request.method);

    var connection_count_request = try client.getConnectionCount();
    defer connection_count_request.deinit();
    try testing.expectEqualStrings("getconnectioncount", connection_count_request.method);

    var version_request = try client.getVersion();
    defer version_request.deinit();
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
    var block_hash_request = try client.getBlockHash(12345);
    defer block_hash_request.deinit();
    try testing.expectEqualStrings("getblockhash", block_hash_request.method);

    // Test block request with parameters
    const test_hash = try neo.Hash256.initWithString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    var block_request = try client.getBlock(test_hash, true);
    defer block_request.deinit();
    try testing.expectEqualStrings("getblock", block_request.method);

    var block_by_index_request = try client.getBlockByIndex(12345, false);
    defer block_by_index_request.deinit();
    try testing.expectEqualStrings("getblock", block_by_index_request.method);
}

test "RPC requests own parameter memory after method returns" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    const test_hash = try neo.Hash256.initWithString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const expected_hash = try test_hash.string(allocator);
    defer allocator.free(expected_hash);

    var block_request = try client.getBlock(test_hash, true);
    defer block_request.deinit();

    const scratch = try allocator.alloc(u8, expected_hash.len);
    defer allocator.free(scratch);
    @memset(scratch, 0xaa);

    try testing.expectEqual(@as(usize, 2), block_request.params.len);
    try testing.expectEqualStrings(expected_hash, block_request.params[0].String);
    try testing.expectEqual(@as(i64, 1), block_request.params[1].Integer);

    const script_hash = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const expected_address = try script_hash.toAddress(allocator);
    defer allocator.free(expected_address);

    var transfer_request = try client.getNep17Transfers(script_hash, 1, 2);
    defer transfer_request.deinit();

    const address_scratch = try allocator.alloc(u8, expected_address.len);
    defer allocator.free(address_scratch);
    @memset(address_scratch, 0xbb);

    try testing.expectEqual(@as(usize, 3), transfer_request.params.len);
    try testing.expectEqualStrings(expected_address, transfer_request.params[0].String);
    try testing.expectEqual(@as(i64, 1), transfer_request.params[1].Integer);
    try testing.expectEqual(@as(i64, 2), transfer_request.params[2].Integer);
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

    var invoke_request = try client.invokeFunction(contract_hash, "testMethod", &params, &signers);
    defer invoke_request.deinit();
    try testing.expectEqualStrings("invokefunction", invoke_request.method);

    // Test script invocation
    const script_hex = "0c21036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29641419ed9d4";
    var script_invoke_request = try client.invokeScript(script_hex, &signers);
    defer script_invoke_request.deinit();
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
    var balances_request = try client.getNep17Balances(test_script_hash);
    defer balances_request.deinit();
    try testing.expectEqualStrings("getnep17balances", balances_request.method);

    // Test NEP-17 transfers request
    var transfers_request = try client.getNep17Transfers(test_script_hash, null, null);
    defer transfers_request.deinit();
    try testing.expectEqualStrings("getnep17transfers", transfers_request.method);

    // Test transfers with time parameters
    const from_time: u64 = 1609459200; // 2021-01-01
    const to_time: u64 = 1640995200; // 2022-01-01
    var transfers_with_time = try client.getNep17Transfers(test_script_hash, from_time, to_time);
    defer transfers_with_time.deinit();
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
    var tx_request = try client.getTransaction(test_tx_hash);
    defer tx_request.deinit();
    try testing.expectEqualStrings("getrawtransaction", tx_request.method);

    // Test raw transaction sending
    const raw_tx_hex = "00d1001b0c14aa8acf859bbcd2bed27f5165eae0d3f3c1935e890c1441766430";
    var send_request = try client.sendRawTransaction(raw_tx_hex);
    defer send_request.deinit();
    try testing.expectEqualStrings("sendrawtransaction", send_request.method);

    // Test network fee calculation
    var fee_request = try client.calculateNetworkFee(raw_tx_hex);
    defer fee_request.deinit();
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
    var validate_request = try client.validateAddress(test_address);
    defer validate_request.deinit();
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
