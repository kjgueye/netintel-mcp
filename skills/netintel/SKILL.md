---
name: netintel
description: Pay-per-call lookups for agents via NetIntel (x402, USDC on Base or Solana, no API key) — use when a task needs DNS records, SSL/TLS certificate checks, WHOIS/RDAP, domain age or availability, vetting a domain name, IP geolocation or IP reputation, email verification or SPF/DKIM/DMARC checks, fetching a URL or PDF as text or JSON, web search with citations, an OpenAI-compatible chat model, embeddings, structured extraction or classification of text, or crypto, FX and prediction-market prices. Each call costs $0.001–$0.65 and is paid from the agent's wallet; failed calls are never charged.
license: MIT
---

# NetIntel — paid lookups an agent can make without an account

NetIntel is a catalog of 141 HTTP endpoints at `https://netintel.dev`. There is no signup and
no API key: every endpoint answers `402 Payment Required` with an x402 challenge that states
the exact price, and returns the result once the payment settles (USDC on Base `eip155:8453`,
or Solana). A call that fails (HTTP ≥ 400) is never charged.

Use it when you need a fact you cannot compute yourself: what a domain resolves to, whether a
certificate is valid, who registered a domain, whether an IP is malicious, whether an email
address exists, what a web page or PDF says, what the web says about a question, or a current
price.

## How to call

**If the `netintel` MCP server is available** (this plugin installs it), call its tools —
they are named `netintel_<endpoint>` (`netintel_dns_lookup`, `netintel_ssl_cert`,
`netintel_web_fetch`, …) and pay automatically from the configured wallet. Prefer them.

**Otherwise, pay with any x402 client.** The wallet key must come from the environment —
never ask the user to paste it into the conversation.

```ts
import { x402Client } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";
import { wrapFetchWithPayment } from "@x402/fetch";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";

const account = privateKeyToAccount(process.env.EVM_PRIVATE_KEY as `0x${string}`);
const signer = toClientEvmSigner(account, createPublicClient({ chain: base, transport: http() }));
const client = new x402Client();
registerExactEvmScheme(client, { signer });
const fetchWithPay = wrapFetchWithPayment(fetch, client);

const res = await fetchWithPay("https://netintel.dev/dns/lookup?domain=example.com");
console.log(await res.json());
```

To see the price and the input shape before paying, read the unpaid response:

```bash
curl -sS -H "Accept: application/json" "https://netintel.dev/dns/lookup?domain=example.com"
# → 402 with accepts[0].price ("$0.002"), the input schema and a real example request/response
```

Request conventions: `GET` endpoints take query parameters, `POST` endpoints take a JSON body.
Common field aliases are accepted (`domain`/`host`, `ip`/`address`, `url`/`link`), and a bad
request returns a `400` that names the missing field — not a charge.

## Which endpoint

| Task | Endpoint | Price |
|---|---|---|
| Resolve DNS records (A/AAAA/MX/TXT/NS/CNAME/SOA, SPF/DMARC parsed) | `GET /dns/lookup?domain=` | $0.002 |
| Check an SSL/TLS certificate (expiry, chain, issuer) | `GET /ssl/cert?domain=` | $0.003 |
| Full TLS analysis (protocols, ciphers, weaknesses) | `GET /ssl/analyze?domain=` | $0.007 |
| WHOIS / RDAP registration data | `GET /whois-rdap/lookup?domain=` | $0.003 |
| Is a domain available to register | `GET /domain-availability/check?domain=` | $0.01 |
| Domain age | `GET /domain-age/check?domain=` | $0.03 |
| Vet candidate domain names (availability, quality, typosquats, collisions) | `POST /domain/vet` | $0.20 |
| Email deliverability & SPF/DKIM/DMARC | `GET /email-auth?domain=` | $0.002 |
| Verify an email address exists | `GET /email/verify?email=` | $0.001 |
| IP geolocation | `GET /ip-geo/locate?ip=` | $0.002 |
| IP reputation / malicious-IP check (AbuseIPDB + OTX) | `GET /ip-reputation/analyze?ip=` | $0.05 |
| Fetch a URL and get the raw body (JSON parsed, else text) | `POST /web/fetch {"url"}` | $0.003 |
| Extract a page or PDF as clean Markdown | `POST /web/extract {"url"}` | $0.003 |
| Web search (results + snippets) | `POST /web/search {"query"}` | $0.01 |
| Answer a question from the web, with citations | `POST /exa/answer {"query"}` | $0.01 |
| OpenAI-compatible chat completions (15 models) | `POST /v1/chat/completions` | $0.005–$0.65 by model |
| GPT-4o with up to 4 image URLs | `POST /openai/gpt-4o` | $0.10 |
| Embeddings (384-dim, multilingual) | `POST /embeddings {"input"}` | $0.001 |
| Extract structured JSON from text with your own schema | `POST /schema-parse/extract` | $0.01 |
| Classify text into your own categories | `POST /classify` | $0.005 |
| Crypto prices (up to 25 coins in one call) | `GET /crypto/price?ids=` | $0.005 |
| Currency conversion (fiat and crypto) | `GET /currency-exchange/convert?from=&to=&amount=` | $0.01 |
| Prediction-market odds | `GET /prediction/markets?q=` | $0.005 |

The full catalog with every endpoint, its price and a real example is machine-readable at
`https://netintel.dev/.well-known/x402`, as OpenAPI at `https://netintel.dev/openapi.json`,
and as prose at `https://netintel.dev/llms.txt`.

## Spend-aware usage

- Read the price from the 402 before paying and keep a per-task budget; most lookups are
  $0.001–$0.01. Composite reports (`/domain-report/full` $0.25, `/ip-report/full` $0.20,
  `/email-report/full` $0.15) bundle several lookups — use one of them only when you need most
  of what it returns; otherwise call the single endpoint.
- `/dns/lookup` already returns every common record type in one call — do not call it once per
  record type.
- Verify cheap first: `/email/verify` ($0.001) before `/email-report/full`; `/ssl/cert`
  ($0.003) before `/ssl/analyze`.
- `/web/fetch` for data APIs and JSON; `/web/extract` for articles and PDFs you want as
  Markdown; `/web/search` when you do not have a URL.
- Never retry a `402` in a loop: if the wallet has no USDC the payment cannot settle. Report
  "wallet needs funding on Base" to the user instead.

## Wallet setup (one time)

An agent wallet is an ordinary EVM key holding USDC on Base mainnet. Fund it with a few
dollars (there is no gas to pay — settlement is sponsored). Keep the key in the environment
(`EVM_PRIVATE_KEY`) or in the plugin's secure configuration; never in prompts, files or logs.
Solana (USDC) is accepted by the API as well for clients that pay on Solana.
