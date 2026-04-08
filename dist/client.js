import { x402Client, wrapAxiosWithPayment } from "@x402/axios";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import axios from "axios";
const BASE_URL = "https://netintel-production-440c.up.railway.app";
export async function createClient() {
    const key = process.env.EVM_PRIVATE_KEY;
    if (!key) {
        throw new Error("EVM_PRIVATE_KEY environment variable is required. " +
            "Set it to your wallet private key (with USDC on Base mainnet).");
    }
    const client = new x402Client();
    const signer = privateKeyToAccount(key);
    registerExactEvmScheme(client, { signer });
    return wrapAxiosWithPayment(axios.create({ baseURL: BASE_URL }), client);
}
