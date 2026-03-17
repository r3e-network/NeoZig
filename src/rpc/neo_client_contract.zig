const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const InvocationResult = @import("responses.zig").InvocationResult;
const NetworkFeeResponse = @import("responses.zig").NetworkFeeResponse;
const SendRawTransactionResponse = @import("responses.zig").SendRawTransactionResponse;
const RpcParam = @import("rpc_operation.zig").RpcParam;
const RpcRequest = @import("rpc_operation.zig").RpcRequest;

pub fn mixin(comptime Client: type) type {
    return struct {
        pub fn invokeFunction(
            self: *Client,
            contract_hash: Hash160,
            function_name: []const u8,
            params: []const ContractParameter,
            signers: []const Signer,
        ) !RpcRequest(InvocationResult) {
            const contract_str = try contract_hash.string(self.allocator);
            defer self.allocator.free(contract_str);

            const rpc_params = [_]RpcParam{
                RpcParam.initString(contract_str),
                RpcParam.initString(function_name),
                RpcParam.initArray(params),
                RpcParam.initArray(signers),
            };

            return RpcRequest(InvocationResult).init(self.allocator, &self.service, "invokefunction", &rpc_params);
        }

        pub fn invokeScript(
            self: *Client,
            script_hex: []const u8,
            signers: []const Signer,
        ) !RpcRequest(InvocationResult) {
            const rpc_params = [_]RpcParam{
                RpcParam.initString(script_hex),
                RpcParam.initArray(signers),
            };

            return RpcRequest(InvocationResult).init(self.allocator, &self.service, "invokescript", &rpc_params);
        }

        pub fn sendRawTransaction(self: *Client, raw_transaction_hex: []const u8) !RpcRequest(SendRawTransactionResponse) {
            const params = [_]RpcParam{RpcParam.initString(raw_transaction_hex)};
            return RpcRequest(SendRawTransactionResponse).init(self.allocator, &self.service, "sendrawtransaction", &params);
        }

        pub fn calculateNetworkFee(self: *Client, transaction_hex: []const u8) !RpcRequest(NetworkFeeResponse) {
            const params = [_]RpcParam{RpcParam.initString(transaction_hex)};
            return RpcRequest(NetworkFeeResponse).init(self.allocator, &self.service, "calculatenetworkfee", &params);
        }
    };
}
