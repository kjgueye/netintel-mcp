import axios, { type InternalAxiosRequestConfig } from "axios";

// Wallet-less mode: hand the agent a request it can pay with a wallet it
// already has, instead of a dead end.
//
// Most people who install this server never paste a private key (2,000
// installs/month, zero paid calls). Agents increasingly carry their own funded
// wallet — AgentCash (MCP `fetch`), Coinbase Agentic Wallet (`awal` CLI) or
// Coinbase Wallet MCP (`initiate_x402_request`) — and every one of them pays a
// plain x402 URL. So when no key is configured, a paid tool answers with the
// exact request it would have made (URL incl. query, method, JSON body), its
// price, and the one call per wallet that buys it. The wallet's own spending
// limits apply; this server never signs anything in this mode.

/** USDC on Base — the only rail all three wallets pay on. */
const BASE = "eip155:8453";

/**
 * Tells NetIntel's paid-call ledger which integration the call came from; the
 * buyer's own client otherwise shows only a generic UA (AgentCash = "node").
 * Changes nothing about the call or its price.
 */
export const VIA_HEADER = "X-NetIntel-Via";
export const VIA_HANDOFF = "mcp-handoff";

export interface PayableRequest {
  url: string;
  method: "GET" | "POST";
  /** JSON body of a POST, as sent. */
  body?: unknown;
  headers: Record<string, string>;
  /** Exact price from the 402, in USD and in USDC atomic units (6 decimals). */
  price_usd?: number;
  max_amount_atomic?: string;
}

interface Accept { network?: string; amount?: unknown; price?: unknown }

/** The Base quote from a 402 body (v2 `amount` atomic, v1 `price` "$0.002"). */
export function priceFrom402(body: unknown): { usd: number; atomic: string } | undefined {
  const accepts = (body as { accepts?: Accept[] } | undefined)?.accepts;
  if (!Array.isArray(accepts) || !accepts.length) return undefined;
  const a = accepts.find((x) => x?.network === BASE) ?? accepts[0];
  if (/^\d+$/.test(String(a?.amount ?? ""))) return { usd: Number(a!.amount) / 1_000_000, atomic: String(a!.amount) };
  const m = /^\$?(\d+(?:\.\d+)?)$/.exec(String(a?.price ?? "").trim());
  if (m) {
    const usd = Number(m[1]);
    return { usd, atomic: String(Math.round(usd * 1_000_000)) };
  }
  return undefined;
}

/** Rebuild the exact request an axios call made (absolute URL with its query, method, body). */
export function requestFromAxios(config: InternalAxiosRequestConfig | undefined, body402?: unknown): PayableRequest | undefined {
  if (!config?.url) return undefined;
  const url = axios.getUri(config);
  if (!/^https:\/\//.test(url)) return undefined;
  const method = String(config.method ?? "get").toUpperCase() === "POST" ? "POST" : "GET";
  let body: unknown;
  if (method === "POST" && config.data !== undefined) {
    try { body = typeof config.data === "string" ? JSON.parse(config.data) : config.data; } catch { body = config.data; }
  }
  const price = priceFrom402(body402);
  return { url, method, ...(body !== undefined ? { body } : {}), headers: { [VIA_HEADER]: VIA_HANDOFF }, ...(price ? { price_usd: price.usd, max_amount_atomic: price.atomic } : {}) };
}

/** Single-quote for a POSIX shell (agents paste these into a terminal). */
const sq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** The agent-facing text: price, then one exact call per wallet, then setup if it has none. */
export function payHandoffText(r: PayableRequest): string {
  const usd = r.price_usd !== undefined ? `$${r.price_usd}` : undefined;
  const json = r.body !== undefined ? JSON.stringify(r.body) : undefined;
  // Each wallet takes headers in its own shape: AgentCash "Name: value" strings,
  // awal a JSON object string, Wallet MCP an object.
  const fetchArgs = { url: r.url, method: r.method, ...(json ? { body: json } : {}), headers: Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`) };
  const awal = [
    "npx awal@latest x402 pay", sq(r.url),
    ...(r.method === "POST" ? ["-X POST"] : []),
    ...(json ? ["-d", sq(json)] : []),
    "-h", sq(JSON.stringify(r.headers)),
    ...(r.max_amount_atomic ? ["--max-amount", r.max_amount_atomic] : []),
  ].join(" ");
  const initiate = {
    url: r.url, method: r.method,
    ...(r.body !== undefined ? { body: r.body } : {}),
    headers: r.headers,
    maxPayment: r.price_usd !== undefined ? String(r.price_usd) : "0.01",
  };
  return [
    `Payment required — this call costs ${usd ?? "a listed price"} (USDC on Base). No NetIntel wallet key is set here, so pay it with a wallet you already have; tell the user the price first.`,
    `• AgentCash: call its \`fetch\` tool with ${JSON.stringify(fetchArgs)}`,
    `• Coinbase Agentic Wallet (shell): ${awal}`,
    `• Coinbase Wallet MCP: \`initiate_x402_request\` with ${JSON.stringify(initiate)}, ask the user to approve the payment, then \`complete_x402_request\` with the requestId.`,
    "No wallet yet? The quickest are AgentCash (`claude mcp add agentcash --scope user -- npx -y agentcash@latest`, then fund it) or Coinbase Agentic Wallet (`npx awal@latest auth login <email>`, then fund it). Or set EVM_PRIVATE_KEY to a dedicated wallet holding USDC on Base and this server pays directly. Never ask the user to paste a private key into the chat.",
  ].join("\n");
}
