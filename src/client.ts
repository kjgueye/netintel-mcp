import { x402Client, wrapAxiosWithPayment } from "@x402/axios";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http, formatUnits } from "viem";
import { base } from "viem/chains";
import axios, { type AxiosInstance } from "axios";

// Canonical domain. The legacy netintel-production-440c.up.railway.app host
// still serves the same app as a fallback, but new clients target netintel.dev.
const BASE_URL = "https://netintel.dev";

/** USDC on Base mainnet — the asset every NetIntel price is quoted in. */
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;

/** Tools that work with NO wallet: NetIntel's free tier (per-client quota, then the normal price). */
export const FREE_TOOLS = [
  "netintel_dns_lookup",
  "netintel_ssl_cert",
  "netintel_whois_lookup",
  "netintel_subnet_calc",
  "netintel_email_auth",
] as const;

let walletAddress: `0x${string}` | null = null;

/** The configured agent wallet's address, or null when the server runs wallet-less. */
export function configuredWallet(): `0x${string}` | null {
  return walletAddress;
}

/**
 * The HTTP client every tool uses. With EVM_PRIVATE_KEY set, responses that
 * demand payment are paid automatically (x402) and retried; without it, the
 * server still starts — the free-tier tools work as-is and paid tools return
 * an explanation of what a call costs and how to fund a wallet, instead of
 * failing to boot for everyone who installed the plugin before funding one.
 */
export async function createClient(): Promise<AxiosInstance> {
  const key = process.env.EVM_PRIVATE_KEY?.trim();
  const plain = axios.create({ baseURL: BASE_URL });
  if (!key) {
    console.error(
      "[netintel-mcp] No EVM_PRIVATE_KEY set — running wallet-less. Free-tier tools work " +
        `(${FREE_TOOLS.join(", ")}); paid tools will explain how to fund an agent wallet.`
    );
    return plain;
  }
  const signer = privateKeyToAccount(key as `0x${string}`);
  walletAddress = signer.address;
  const client = new x402Client();
  registerExactEvmScheme(client, { signer });
  return wrapAxiosWithPayment(plain, client);
}

/** USDC balance of the configured wallet on Base (keyless public RPC). */
export async function walletUsdcBalance(): Promise<string | null> {
  if (!walletAddress) return null;
  const pc = createPublicClient({ chain: base, transport: http() });
  const raw = await pc.readContract({
    address: USDC_BASE,
    abi: [{ type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ name: "a", type: "address" }], outputs: [{ type: "uint256" }] }],
    functionName: "balanceOf",
    args: [walletAddress],
  });
  return formatUnits(raw as bigint, 6);
}
