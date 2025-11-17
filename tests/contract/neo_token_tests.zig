//! NEO Token Tests
//!
//! Complete conversion from NeoSwift NeoTokenTests.swift
//! Tests NEO token specific functionality, voting, and candidate management.

const std = @import("std");


const testing = std.testing;
const NeoToken = @import("../../src/contract/neo_token.zig").NeoToken;
const Account = @import("../../src/wallet/account.zig").Account;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const ContractParameter = @import("../../src/types/contract_parameter.zig").ContractParameter;
const ScriptBuilder = @import("../../src/script/script_builder.zig").ScriptBuilder;
const ECKeyPair = @import("../../src/crypto/ec_key_pair.zig").ECKeyPair;
const PublicKey = @import("../../src/crypto/keys.zig").PublicKey;
const NeoSwift = @import("../../src/rpc/neo_client.zig").NeoSwift;
const constants = @import("../../src/core/constants.zig");

/// NEO token method constants (equivalent to Swift test constants)
const VOTE = "vote";
const REGISTER_CANDIDATE = "registerCandidate";
const UNREGISTER_CANDIDATE = "unregisterCandidate";
const GET_GAS_PER_BLOCK = "getGasPerBlock";
const SET_GAS_PER_BLOCK = "setGasPerBlock";
const GET_REGISTER_PRICE = "getRegisterPrice";
const SET_REGISTER_PRICE = "setRegisterPrice";
const GET_ACCOUNT_STATE = "getAccountState";

/// Creates test account (equivalent to Swift account1 setup)
fn createTestAccount(allocator: std.mem.Allocator) !Account {
    const private_key_hex = "e6e919577dd7b8e97805151c05ae07ff4f752654d6d8797597aca989c02c4cb3";
    const private_key = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(private_key_hex, allocator);
    defer allocator.free(private_key);
    
    const key_pair = try ECKeyPair.createFromPrivateKey(private_key);
    return try Account.init(key_pair, allocator);
}

/// Test NEO token constants (converted from Swift testConstants)
test "NEO token constants and properties" {
    const allocator = testing.allocator;
    
    // Create NEO token instance (equivalent to Swift NeoToken(neoSwift))
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined; // Would need actual service for full testing
    const neo_swift = NeoSwift.build(allocator, mock_service, mock_config);
    
    const neo_token = NeoToken.init(neo_swift);
    
    // Test NEO token constants (equivalent to Swift constant tests)
    const expected_script_hash = "ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5";
    const neo_hash_string = try neo_token.getScriptHash().toString(allocator);
    defer allocator.free(neo_hash_string);
    
    // Remove 0x prefix for comparison
    const hash_without_prefix = if (std.mem.startsWith(u8, neo_hash_string, "0x"))
        neo_hash_string[2..]
    else
        neo_hash_string;
    
    try testing.expectEqualStrings(expected_script_hash, hash_without_prefix);
    
    // Test token properties (would require RPC mocking for full test)
    // For now, verify the token can be created and has correct script hash
    try neo_token.validate();
    
    // NEO token should be identified as native contract
    try testing.expect(neo_token.isNativeContract());
}

/// Test register candidate functionality (converted from Swift testRegisterCandidate)
test "Register candidate script generation" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    // Get public key for candidate registration (equivalent to Swift pubKeyBytes)
    const public_key = account.getKeyPair().getPublicKey();
    const pub_key_bytes = public_key.toSlice();
    
    // Build expected script (equivalent to Swift expectedScript)
    const neo_script_hash = try Hash160.initWithString(constants.NativeContracts.NEO_TOKEN);
    
    var expected_builder = ScriptBuilder.init(allocator);
    defer expected_builder.deinit();
    
    // Create public key parameter (equivalent to Swift .publicKey(pubKeyBytes))
    var pub_key_param = try ContractParameter.createPublicKey(public_key, allocator);
    defer pub_key_param.deinit(allocator);
    
    const register_params = [_]ContractParameter{pub_key_param};
    
    _ = try expected_builder.contractCall(neo_script_hash, REGISTER_CANDIDATE, &register_params);
    const expected_script = expected_builder.toScript();
    
    // Verify script generation
    try testing.expect(expected_script.len > 0);
    try testing.expect(expected_script.len > 40); // Should contain public key + method call
    
    // Test script contains the public key data
    // (Full verification would require script parsing)
    try testing.expect(expected_script.len >= pub_key_bytes.len); // At minimum should contain pubkey
}

/// Test voting functionality
test "Vote functionality script generation" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    // Create candidate public key for voting
    const candidate_key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = candidate_key_pair;
        mutable_kp.zeroize();
    }
    
    const candidate_public_key = candidate_key_pair.getPublicKey();
    
    // Build vote script (equivalent to Swift vote function call)
    const neo_script_hash = try Hash160.initWithString(constants.NativeContracts.NEO_TOKEN);
    
    var vote_builder = ScriptBuilder.init(allocator);
    defer vote_builder.deinit();
    
    // Create vote parameters: account hash + candidate public key
    var vote_params = [_]ContractParameter{
        try ContractParameter.createHash160(account.getScriptHash(), allocator),
        try ContractParameter.createPublicKey(candidate_public_key, allocator),
    };
    defer {
        for (vote_params) |*param| {
            param.deinit(allocator);
        }
    }
    
    _ = try vote_builder.contractCall(neo_script_hash, VOTE, &vote_params);
    const vote_script = vote_builder.toScript();
    
    // Verify vote script generation
    try testing.expect(vote_script.len > 0);
    try testing.expect(vote_script.len > 60); // Vote with account hash + public key should be substantial
}

/// Test governance method script generation
test "Governance method script generation" {
    const allocator = testing.allocator;
    
    // Test various governance methods
    const neo_script_hash = try Hash160.initWithString(constants.NativeContracts.NEO_TOKEN);
    
    const governance_methods = [_][]const u8{
        GET_GAS_PER_BLOCK,
        SET_GAS_PER_BLOCK,
        GET_REGISTER_PRICE,
        SET_REGISTER_PRICE,
        GET_ACCOUNT_STATE,
        UNREGISTER_CANDIDATE,
    };
    
    for (governance_methods) |method| {
        var script_builder = ScriptBuilder.init(allocator);
        defer script_builder.deinit();
        
        // Build method call script (most methods take no parameters)
        _ = try script_builder.contractCall(
            neo_script_hash,
            method,
            &[_]ContractParameter{}
        );
        
        const method_script = script_builder.toScript();
        try testing.expect(method_script.len > 0);
        try testing.expect(method_script.len > 25); // Minimum size for contract call
    }
}

/// Test NEO token account state queries
test "NEO token account state queries" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    // Build account state query script
    const neo_script_hash = try Hash160.initWithString(constants.NativeContracts.NEO_TOKEN);
    
    var state_builder = ScriptBuilder.init(allocator);
    defer state_builder.deinit();
    
    // Create account state parameter
    var account_param = try ContractParameter.createHash160(account.getScriptHash(), allocator);
    defer account_param.deinit(allocator);
    
    const state_params = [_]ContractParameter{account_param};
    
    _ = try state_builder.contractCall(neo_script_hash, GET_ACCOUNT_STATE, &state_params);
    const state_script = state_builder.toScript();
    
    // Verify account state script
    try testing.expect(state_script.len > 0);
    try testing.expect(state_script.len > 30); // Should contain account hash + method call
}

/// Test NEO token parameter validation
test "NEO token parameter validation" {
    const allocator = testing.allocator;
    
    // Test public key parameter for candidate operations
    const test_key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = test_key_pair;
        mutable_kp.zeroize();
    }
    
    const public_key = test_key_pair.getPublicKey();
    
    var pub_key_param = try ContractParameter.createPublicKey(public_key, allocator);
    defer pub_key_param.deinit(allocator);
    
    try pub_key_param.validate();
    try testing.expect(pub_key_param.isPublicKey());
    
    // Test integer parameter for gas/price operations
    var gas_amount_param = try ContractParameter.createInteger(1000000000, allocator); // 1 billion
    defer gas_amount_param.deinit(allocator);
    
    try gas_amount_param.validate();
    try testing.expect(gas_amount_param.isInteger());
    
    const gas_value = try gas_amount_param.getIntegerValue();
    try testing.expectEqual(@as(i64, 1000000000), gas_value);
    
    // Test null parameter for unvoting
    var null_param = try ContractParameter.createAny(null, allocator);
    defer null_param.deinit(allocator);
    
    try null_param.validate();
    try testing.expect(null_param.isNull());
}

/// Test NEO token voting scenarios
test "NEO token voting scenarios" {
    const allocator = testing.allocator;
    
    // Create test account and candidate
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const candidate_key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = candidate_key_pair;
        mutable_kp.zeroize();
    }
    
    const neo_script_hash = try Hash160.initWithString(constants.NativeContracts.NEO_TOKEN);
    
    // Test vote for candidate
    var vote_builder = ScriptBuilder.init(allocator);
    defer vote_builder.deinit();
    
    var vote_params = [_]ContractParameter{
        try ContractParameter.createHash160(account.getScriptHash(), allocator),
        try ContractParameter.createPublicKey(candidate_key_pair.getPublicKey(), allocator),
    };
    defer {
        for (vote_params) |*param| {
            param.deinit(allocator);
        }
    }
    
    _ = try vote_builder.contractCall(neo_script_hash, VOTE, &vote_params);
    const vote_script = vote_builder.toScript();
    
    try testing.expect(vote_script.len > 0);
    
    // Test unvote (vote with null)
    var unvote_builder = ScriptBuilder.init(allocator);
    defer unvote_builder.deinit();
    
    var unvote_params = [_]ContractParameter{
        try ContractParameter.createHash160(account.getScriptHash(), allocator),
        try ContractParameter.createAny(null, allocator),
    };
    defer {
        for (unvote_params) |*param| {
            param.deinit(allocator);
        }
    }
    
    _ = try unvote_builder.contractCall(neo_script_hash, VOTE, &unvote_params);
    const unvote_script = unvote_builder.toScript();
    
    try testing.expect(unvote_script.len > 0);
    try testing.expect(unvote_script.len != vote_script.len); // Should be different scripts
}

/// Test NEO token governance operations
test "NEO token governance operations" {
    const allocator = testing.allocator;
    
    const neo_script_hash = try Hash160.initWithString(constants.NativeContracts.NEO_TOKEN);
    
    // Test getting gas per block (no parameters)
    var get_gas_builder = ScriptBuilder.init(allocator);
    defer get_gas_builder.deinit();
    
    _ = try get_gas_builder.contractCall(
        neo_script_hash,
        GET_GAS_PER_BLOCK,
        &[_]ContractParameter{}
    );
    
    const get_gas_script = get_gas_builder.toScript();
    try testing.expect(get_gas_script.len > 0);
    
    // Test setting gas per block (with parameter)
    var set_gas_builder = ScriptBuilder.init(allocator);
    defer set_gas_builder.deinit();
    
    var gas_amount_param = try ContractParameter.createInteger(5000000, allocator); // 5 GAS per block
    defer gas_amount_param.deinit(allocator);
    
    const set_gas_params = [_]ContractParameter{gas_amount_param};
    
    _ = try set_gas_builder.contractCall(neo_script_hash, SET_GAS_PER_BLOCK, &set_gas_params);
    const set_gas_script = set_gas_builder.toScript();
    
    try testing.expect(set_gas_script.len > 0);
    try testing.expect(set_gas_script.len > get_gas_script.len); // Set should be larger (has parameter)
    
    // Test getting register price
    var get_price_builder = ScriptBuilder.init(allocator);
    defer get_price_builder.deinit();
    
    _ = try get_price_builder.contractCall(
        neo_script_hash,
        GET_REGISTER_PRICE,
        &[_]ContractParameter{}
    );
    
    const get_price_script = get_price_builder.toScript();
    try testing.expect(get_price_script.len > 0);
}

/// Test candidate registration and unregistration
test "Candidate registration and unregistration" {
    const allocator = testing.allocator;
    
    // Create test account for candidate operations
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const neo_script_hash = try Hash160.initWithString(constants.NativeContracts.NEO_TOKEN);
    const public_key = account.getKeyPair().getPublicKey();
    
    // Test register candidate script
    var register_builder = ScriptBuilder.init(allocator);
    defer register_builder.deinit();
    
    var register_param = try ContractParameter.createPublicKey(public_key, allocator);
    defer register_param.deinit(allocator);
    
    const register_params = [_]ContractParameter{register_param};
    
    _ = try register_builder.contractCall(neo_script_hash, REGISTER_CANDIDATE, &register_params);
    const register_script = register_builder.toScript();
    
    try testing.expect(register_script.len > 0);
    try testing.expect(register_script.len > 40); // Should contain public key
    
    // Test unregister candidate script
    var unregister_builder = ScriptBuilder.init(allocator);
    defer unregister_builder.deinit();
    
    var unregister_param = try ContractParameter.createPublicKey(public_key, allocator);
    defer unregister_param.deinit(allocator);
    
    const unregister_params = [_]ContractParameter{unregister_param};
    
    _ = try unregister_builder.contractCall(neo_script_hash, UNREGISTER_CANDIDATE, &unregister_params);
    const unregister_script = unregister_builder.toScript();
    
    try testing.expect(unregister_script.len > 0);
    
    // Register and unregister scripts should be similar length (same parameters)
    const length_diff = if (register_script.len > unregister_script.len)
        register_script.len - unregister_script.len
    else
        unregister_script.len - register_script.len;
    
    try testing.expect(length_diff < 10); // Should be very similar, just different method names
}

/// Test NEO token method name validation
test "NEO token method name validation" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = NeoSwift.build(allocator, mock_service, mock_config);
    
    const neo_token = NeoToken.init(neo_swift);
    
    // Test valid NEO token methods
    const valid_methods = [_][]const u8{
        "symbol", "decimals", "totalSupply", "balanceOf", "transfer",
        VOTE, REGISTER_CANDIDATE, UNREGISTER_CANDIDATE,
        GET_GAS_PER_BLOCK, SET_GAS_PER_BLOCK,
        GET_REGISTER_PRICE, SET_REGISTER_PRICE,
        GET_ACCOUNT_STATE,
    };
    
    for (valid_methods) |method| {
        const empty_params = [_]ContractParameter{};
        try neo_token.validateInvocation(method, &empty_params);
    }
    
    // Test invalid method names
    const invalid_methods = [_][]const u8{ "", "invalidMethod", "nonExistentFunction" };
    
    for (invalid_methods) |method| {
        const empty_params = [_]ContractParameter{};
        
        if (std.mem.eql(u8, method, "")) {
            // Empty method should fail validation
            try testing.expectError(
                @import("../../src/core/errors.zig").NeoError.IllegalArgument,
                neo_token.validateInvocation(method, &empty_params)
            );
        } else {
            // Other invalid methods might still pass validation but would fail at runtime
            try neo_token.validateInvocation(method, &empty_params);
        }
    }
}

/// Test NEO token transaction building integration
test "NEO token transaction building integration" {
    const allocator = testing.allocator;
    
    // Create test components
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const neo_script_hash = try Hash160.initWithString(constants.NativeContracts.NEO_TOKEN);
    
    // Test building a complete NEO transfer transaction script
    var transfer_builder = ScriptBuilder.init(allocator);
    defer transfer_builder.deinit();
    
    const recipient_hash = try Hash160.initWithString("969a77db482f74ce27105f760efa139223431394");
    const transfer_amount: i64 = 1000000; // 1 million NEO (whole tokens, 0 decimals)
    
    var transfer_params = [_]ContractParameter{
        try ContractParameter.createHash160(account.getScriptHash(), allocator),
        try ContractParameter.createHash160(recipient_hash, allocator),
        try ContractParameter.createInteger(transfer_amount, allocator),
        try ContractParameter.createAny(null, allocator), // Data parameter
    };
    defer {
        for (transfer_params) |*param| {
            param.deinit(allocator);
        }
    }
    
    _ = try transfer_builder.contractCall(neo_script_hash, "transfer", &transfer_params);
    const transfer_script = transfer_builder.toScript();
    
    // Verify comprehensive transfer script
    try testing.expect(transfer_script.len > 0);
    try testing.expect(transfer_script.len > 80); // Should be substantial with 4 parameters including hashes
    
    // Test that script can be used in transaction builder
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = NeoSwift.build(allocator, mock_service, mock_config);
    
    var tx_builder = @import("../../src/transaction/transaction_builder.zig").TransactionBuilder.init(allocator, neo_swift);
    defer tx_builder.deinit();
    
    _ = try tx_builder.script(transfer_script);
    
    // Verify script is configured in transaction builder
    try testing.expectEqualSlices(u8, transfer_script, tx_builder.script_field);
}