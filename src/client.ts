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

/**
 * Spending limits, enforced INSIDE the x402 client immediately before a payment
 * payload is signed — the only place a limit can be real, because with a wallet
 * configured every 402 (including a free-tier route past its quota) is paid
 * automatically. The listed per-call prices are what a route costs, not a cap.
 *   NETINTEL_MAX_PER_CALL_USD  — refuse any single payment above this (default $0.25)
 *   NETINTEL_MAX_SESSION_USD   — refuse once this MCP server process has authorized
 *                                this much in total (default $5.00)
 * A refusal aborts the payment (nothing is signed or sent) and the tool returns
 * "SPEND_LIMIT: …" telling the agent which limit and how to raise it. Session
 * spend counts every authorized payment, whether or not the call then succeeds
 * (conservative: a payment that settles for a failed call is not charged by
 * NetIntel, but the signature was still handed out).
 */
const SPEND_LIMIT = "SPEND_LIMIT";
function limit(envName: string, fallback: number): number {
  const n = Number(process.env[envName]);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}
export const MAX_PER_CALL_USD = limit("NETINTEL_MAX_PER_CALL_USD", 0.25);
export const MAX_SESSION_USD = limit("NETINTEL_MAX_SESSION_USD", 5);
let sessionAuthorizedUsd = 0;
let refusedPayments = 0;

/** What the limits are and how much this server process has authorized so far. */
export function spendStatus() {
  return {
    max_per_call_usd: MAX_PER_CALL_USD,
    max_session_usd: MAX_SESSION_USD,
    session_authorized_usd: Number(sessionAuthorizedUsd.toFixed(6)),
    session_remaining_usd: Number(Math.max(0, MAX_SESSION_USD - sessionAuthorizedUsd).toFixed(6)),
    refused_payments: refusedPayments,
    configure: "NETINTEL_MAX_PER_CALL_USD / NETINTEL_MAX_SESSION_USD (env, or the Claude Code plugin config); limits are per MCP server process",
  };
}

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
  client.onBeforePaymentCreation(async (context) => {
    const req = (context as { selectedRequirements?: { amount?: unknown } } | undefined)?.selectedRequirements;
    const atomic = Number(req?.amount);
    const usd = atomic / 1_000_000;
    if (!Number.isFinite(usd) || usd < 0) {
      refusedPayments += 1;
      return { abort: true, reason: `${SPEND_LIMIT}: the payment requirements carry no usable amount (got ${JSON.stringify(req?.amount)}); refusing to sign` };
    }
    if (usd > MAX_PER_CALL_USD) {
      refusedPayments += 1;
      return { abort: true, reason: `${SPEND_LIMIT}: this call costs ${usd} — above the per-call limit of ${MAX_PER_CALL_USD}. Ask the user; to allow it, raise NETINTEL_MAX_PER_CALL_USD (env or plugin config) and restart the server` };
    }
    if (sessionAuthorizedUsd + usd > MAX_SESSION_USD) {
      refusedPayments += 1;
      return { abort: true, reason: `${SPEND_LIMIT}: this call costs ${usd} and this session has already authorized ${sessionAuthorizedUsd.toFixed(3)} of its ${MAX_SESSION_USD} limit. Ask the user; to continue, raise NETINTEL_MAX_SESSION_USD (env or plugin config) and restart the server` };
    }
    sessionAuthorizedUsd += usd;
    return undefined;
  });
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
