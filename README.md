# netintel-mcp

MCP server for NetIntel — 124 network intelligence tools for AI agents.
DNS, SSL, WHOIS, email security, cloud fingerprinting, OSINT and more.
Pay-per-call via x402 — the NetIntel API accepts USDC on Base or Solana. No API keys, and no private key to paste: pay from the wallet your agent already has (AgentCash, Coinbase Agentic Wallet or Coinbase Wallet MCP), or give this server a dedicated wallet key.
Plus 3 router tools that find the best x402 endpoint for a job from **any** provider — [details below](#find-the-right-x402-endpoint-from-any-provider).

## Install as a Claude Code plugin (recommended)

The plugin installs the MCP server **and** a skill that knows which NetIntel endpoint fits a task, what it costs and how to pay it. It never holds a private key and never signs a payment: each paid tool hands the exact request and its price to the agent's own wallet (below), which pays it under that wallet's own approvals and limits. Nothing to configure:

```
/plugin marketplace add kjgueye/netintel-mcp
/plugin install netintel@netintel
```

Then just ask — "is this IP malicious?", "does this domain have DMARC?", "fetch this URL as JSON" — and each call is paid from your wallet.

## Pay with the wallet you already have

With no `EVM_PRIVATE_KEY` set, every paid tool answers with the exact request — URL, method, body — and its price, ready for the agent's own wallet:

- **AgentCash** — the agent calls its `fetch` tool with that request. Install: `claude mcp add agentcash --scope user -- npx -y agentcash@latest`.
- **Coinbase Agentic Wallet** — `npx awal@latest x402 pay '<url>' [-X POST -d '<json>'] --max-amount <atomic>`. Log in once with `npx awal@latest auth login <email>`.
- **Coinbase Wallet MCP** — `initiate_x402_request`, approve the payment in Coinbase Wallet, then `complete_x402_request`.

That wallet's own spending limits apply. The bundled skill (`skills/netintel/SKILL.md`) calls NetIntel the same way even without this server.

## What it connects to

The tools call only NetIntel's own hosts: netintel.dev (the API) and router.netintel.dev (the router tools). Requests carry the tool's input and, when this server pays with its own key, an x402 payment signature; nothing else from your machine is sent. With a key configured, `netintel_wallet_status` also reads that wallet's USDC balance from Base's public node, mainnet.base.org.

Privacy policy: [https://netintel.dev/privacy](https://netintel.dev/privacy)

Terms of service: [https://netintel.dev/terms](https://netintel.dev/terms)

## Install

```bash
# pay from AgentCash, Coinbase Agentic Wallet or Coinbase Wallet MCP
claude mcp add netintel -- npx -y netintel-mcp
# or let this server pay from a dedicated wallet (direct install only; the plugin never takes a key)
claude mcp add netintel -e EVM_PRIVATE_KEY=0xYOUR_PRIVATE_KEY -- npx -y netintel-mcp
```

Or add manually to your Claude Desktop config (the `env` block is optional — leave it out to pay from your own wallet as above):
```json
{
  "mcpServers": {
    "netintel": {
      "command": "npx",
      "args": ["-y", "netintel-mcp"],
      "env": {
        "EVM_PRIVATE_KEY": "0xYOUR_PRIVATE_KEY"
      }
    }
  }
}
```

## Requirements
- **None to start.** Without a key every paid tool hands back a ready-to-pay request (see above), and `netintel_wallet_status` explains the options.
- **Optional:** `EVM_PRIVATE_KEY` — a dedicated agent wallet holding USDC on Base mainnet (gasless; a few dollars is plenty). With it, this server pays every tool's listed price automatically.
- **Spending limits (≥1.1.55):** with a key, the server refuses to sign a payment above `NETINTEL_MAX_PER_CALL_USD` (default $0.25) or once it has authorized `NETINTEL_MAX_SESSION_USD` (default $5) in total per process; a refusal returns `SPEND_LIMIT: …` and nothing is paid. Listed prices are what a call costs, not a cap — with a key configured every 402 is paid automatically, so authorize paid calls with your user first.

## Tools

124 pay-per-call tools across DNS, SSL/TLS, WHOIS & domains, email security, IP intelligence, web & content, OSINT, AI text processing, and bundled reports.

| Tool | Description | Price |
|------|-------------|-------|
| netintel_dns_lookup | DNS lookup for any domain — resolve A, AAAA, MX, TXT, NS, CNAME, SOA… | $0.002 |
| netintel_ssl_analyze | Performs a TLS handshake to inspect the certificate chain, probes… | $0.007 |
| netintel_redirect_trace | Follows a URL through its full redirect chain (up to 20 hops)… | $0.01 |
| netintel_security_headers | Fetches a URL and evaluates 10 security-critical response headers (CSP… | $0.01 |
| netintel_email_auth | Email deliverability & domain security check — validates SPF, DKIM… | $0.002 |
| netintel_cloud_fingerprint | Fingerprints a domain's cloud infrastructure — DNS records, HTTP… | $0.01 |
| netintel_schema_parse | Extract structured data from any unstructured text into your own JSON… | $0.01 |
| netintel_asn_lookup | Resolves an IP address or domain to its Autonomous System Number (ASN)… | $0.03 |
| netintel_whois_lookup | WHOIS domain lookup via RDAP — domain registration data: registrar… | $0.003 |
| netintel_cert_transparency | Query the crt.sh certificate transparency log database to enumerate all… | $0.01 |
| netintel_subnet_calc | Calculates IPv4/IPv6 subnet details from CIDR notation —… | $0.005 |
| netintel_dns_propagation | Query a domain's DNS record across 10 geographically distributed public… | $0.03 |
| netintel_dnssec_validate | Validate a domain's DNSSEC configuration over DNS-over-HTTPS: DS… | $0.03 |
| netintel_ip_blacklist | Check an IP address against 15 major DNS blacklists (Spamhaus… | $0.05 |
| netintel_tech_fingerprint | Fetch a URL and detect the full technology stack from HTTP response… | $0.05 |
| netintel_breach_check | Check if a password has appeared in known data breaches using the… | $0.01 |
| netintel_domain_availability | Check if a domain name is available for registration by querying RDAP… | $0.01 |
| netintel_email_intel | Email verification & deliverability check (email validator / verifier)… | $0.005 |
| netintel_og_scraper | Fetch any public URL and extract structured metadata — Open Graph tags… | $0.01 |
| netintel_page_extract | Fetch any article or web page and extract clean readable text stripped… | $0.05 |
| netintel_phone_intel | Parse and validate any phone number in any format, identify its country… | $0.05 |
| netintel_robots_txt | Fetch and parse a domain's robots.txt file — returns all crawl rules by… | $0.01 |
| netintel_rss_parser | Fetch and parse any RSS 2.0 or Atom feed URL and return structured… | $0.01 |
| netintel_username_check | Check username availability across 20+ social platforms and developer… | $0.03 |
| netintel_wayback_lookup | Query the Internet Archive Wayback Machine to check if a URL has ever… | $0.01 |
| netintel_ip_reputation | IP reputation and malicious-IP check — screens an address against… | $0.05 |
| netintel_cron_parser | Parse any cron expression into a human-readable explanation, validate… | $0.03 |
| netintel_currency_exchange | Convert any amount between 32 fiat currencies (live European Central… | $0.01 |
| netintel_github_intel | Fetch public metadata for any GitHub repository — stars, forks, open… | $0.03 |
| netintel_holidays | Look up public holidays for any country and year, check whether a… | $0.005 |
| netintel_ip_geo | IP geolocation lookup (geoip / IP location API) — geolocate any IPv4 or… | $0.002 |
| netintel_jwt_inspector | Decode and inspect any JWT token — extracts header algorithm, payload… | $0.005 |
| netintel_lang_detect | Detect the language of any text input using stopword-set matching and… | $0.005 |
| netintel_npm_intel | Fetch metadata for any npm package — download counts, latest version… | $0.01 |
| netintel_sitemap_parser | Fetch and parse any XML sitemap or sitemap index file — returns URLs… | $0.01 |
| netintel_url_safety | Check a URL against URLhaus malware database and heuristic phishing… | $0.01 |
| netintel_domain_age | Determine a domain's age from registration data and archival history —… | $0.03 |
| netintel_bulk_domain | Check availability of many domain names across multiple TLDs in a… | $0.10 |
| netintel_domain_appraise | Estimate the market value tier of a domain name using transparent… | $0.03 |
| netintel_domain_report | One call returns a complete intelligence profile for a domain — WHOIS… | $0.10 |
| netintel_ip_risk | One call returns a complete risk profile for an IP address —… | $0.10 |
| netintel_name_gen | Generate brandable startup/product names from a keyword using prefixes… | $0.05 |
| netintel_tld_price | Reference registration/renewal/transfer pricing from a curated table of… | $0.01 |
| netintel_typosquat | Generate common typo and look-alike variations of a domain and check… | $0.05 |
| netintel_classify | Classify text into your own categories — zero-shot: supply 2–20 labels… | $0.005 |
| netintel_content_moderate | Moderate text content using Claude Haiku — flags categories like… | $0.005 |
| netintel_entity_extract | Extract named entities from text using Claude Haiku — people… | $0.05 |
| netintel_sentiment | Sentiment analysis API — analyze sentiment of text and get a text… | $0.002 |
| netintel_text_summarize | Summarize text, articles or documents — condense raw text, Markdown, or… | $0.005 |
| netintel_translate | Translate up to 2000 words between languages using Claude Haiku —… | $0.02 |
| netintel_translate_short | Translate text between languages — text translation API for short… | $0.01 |
| netintel_domain_due_diligence | One call combines domain availability, heuristic value appraisal, and… | $0.20 |
| netintel_domain_report_full | One premium call returns a complete six-part domain profile — DNS… | $0.25 |
| netintel_email_report | One call combines domain email authentication (SPF/DKIM/DMARC)… | $0.15 |
| netintel_ip_report | One premium call returns a complete five-part IP profile — geolocation… | $0.20 |
| netintel_url_safety_full | One call vets a URL end to end — traces its full redirect chain, checks… | $0.15 |
| netintel_extract | Parse and normalize a freeform address string using Claude Haiku —… | $0.01 |
| netintel_extract_contact | Extract structured contact details from text, an email signature, or… | $0.01 |
| netintel_extract_invoice | Extract structured data from invoice or receipt text — or directly from… | $0.02 |
| netintel_extract_resume | Extract structured data from resume/CV text using Claude Haiku —… | $0.02 |
| netintel_extract_table | Extract tabular data from messy text or HTML using Claude Haiku —… | $0.02 |
| netintel_markdown | Convert messy HTML or text into clean, well-structured Markdown using… | $0.03 |
| netintel_normalize | Conform messy or inconsistent JSON to a target schema using Claude… | $0.05 |
| netintel_text_to_json | Turn unstructured text into structured JSON matching a caller-supplied… | $0.05 |
| netintel_web | Extract web content from any page or PDF as clean Markdown — web page… | $0.003 |
| netintel_money | Normalize any messy money string into a typed decimal amount plus ISO… | $0.01 |
| netintel_calendar | Turn event fields into a valid RFC 5545 .ics calendar file — handles… | $0.005 |
| netintel_event_classify | Cheap, fast "is this a dateable event?" filter for social and web text… | $0.02 |
| netintel_event_extract | Event extraction / event parsing — turn any caption, announcement… | $0.05 |
| netintel_messages | OpenAI-compatible chat completions over x402, answered by Claude Sonnet… | $0.06 |
| netintel_ai_image | Generate agent-ready image assets (icons, logos, social graphics… | $0.25 |
| netintel_convert | Convert any physical measurement — length, mass, volume, temperature… | $0.01 |
| netintel_domain | Composite 0-100 trust/risk score for a domain in one call — blends… | $0.10 |
| netintel_translate_structured | Translate structured content — JSON, HTML, Markdown, templates, UI… | $0.02 |
| netintel_translate_batch | Translate many independent strings in one request — each with a caller… | $0.05 |
| netintel_json | Repair malformed JSON into valid JSON — fixes code fences, trailing… | $0.02 |
| netintel_schema | Validate data against a supplied schema — checks required fields… | $0.02 |
| netintel_schema_map | Transform a source object into a target schema — matches fields by… | $0.04 |
| netintel_domain_vet | Vet and pick a domain in one call — give candidate names, get back a… | $0.20 |
| netintel_openai | Call OpenAI's gpt-4o via a single pay-per-call x402 endpoint — no… | $0.10 |
| netintel_openai_gpt_4_1 | Call OpenAI's gpt-4.1 via a single pay-per-call x402 endpoint — no… | $0.09 |
| netintel_openai_gpt_4_1_mini | Call OpenAI's gpt-4.1-mini via a single pay-per-call x402 endpoint — no… | $0.005 |
| netintel_openai_gpt_4o_mini | Call OpenAI's gpt-4o-mini via a single pay-per-call x402 endpoint — no… | $0.005 |
| netintel_openai_gpt_4_1_nano | Call OpenAI's gpt-4.1-nano via a single pay-per-call x402 endpoint — no… | $0.005 |
| netintel_openai_gpt_5_5 | Call OpenAI's gpt-5.5 via a single pay-per-call x402 endpoint — no… | $0.65 |
| netintel_openai_gpt_5_4 | Call OpenAI's gpt-5.4 via a single pay-per-call x402 endpoint — no… | $0.25 |
| netintel_openai_gpt_5_4_mini | Call OpenAI's gpt-5.4-mini via a single pay-per-call x402 endpoint — no… | $0.04 |
| netintel_openai_gpt_5_4_nano | Call OpenAI's gpt-5.4-nano via a single pay-per-call x402 endpoint — no… | $0.005 |
| netintel_openai_gpt_5_1 | Call OpenAI's gpt-5.1 via a single pay-per-call x402 endpoint — no… | $0.15 |
| netintel_openai_gpt_5_nano | Call OpenAI's gpt-5-nano via a single pay-per-call x402 endpoint — no… | $0.005 |
| netintel_openai_gpt_5_2 | Call OpenAI's gpt-5.2 via a single pay-per-call x402 endpoint — no… | $0.20 |
| netintel_openai_gpt_5_6_sol | Call OpenAI's gpt-5.6-sol via a single pay-per-call x402 endpoint — no… | $0.65 |
| netintel_openai_gpt_5_6_terra | Call OpenAI's gpt-5.6-terra via a single pay-per-call x402 endpoint —… | $0.25 |
| netintel_openai_gpt_5_6_luna | Call OpenAI's gpt-5.6-luna via a single pay-per-call x402 endpoint — no… | $0.06 |
| netintel_v1_embeddings | OpenAI-compatible text embeddings API — standard /v1/embeddings request… | $0.005 |
| netintel_semantic_rank | Semantic similarity ranking — send a query plus up to 100 candidate… | $0.02 |
| netintel_v1_chat_completions | OpenAI-compatible chat completions gateway — standard… | $0.005 |
| netintel_crypto_market | Structured live crypto market data for ~50 top assets in one JSON call:… | $0.005 |
| netintel_gas_price | Live gas prices across Base, Ethereum, Arbitrum, Optimism, and Polygon… | $0.002 |
| netintel_crypto_price | Crypto prices for up to 25 coins in one call — live cryptocurrency spot… | $0.005 |
| netintel_crypto_ohlc | Historical OHLC candles for any major crypto asset — hourly or daily… | $0.02 |
| netintel_currency_exchange_batch | Convert one base currency to up to 30 targets in a single call — fiat… | $0.02 |
| netintel_currency_exchange_history | Daily historical exchange-rate series for any currency pair — fiat via… | $0.02 |
| netintel_token_info | Full profile for any ERC-20 token by contract address — name, symbol… | $0.02 |
| netintel_wallet_balance | Token balance for any wallet — native coin, USDC and any ERC-20 on… | $0.005 |
| netintel_wallet_intel | Counterparty due-diligence for any Base or Ethereum wallet — age… | $0.05 |
| netintel_iban_validate | Validate any IBAN offline — mod-97 check digits, per-country structure… | $0.005 |
| netintel_market_snapshot | One-call market briefing for agents — BTC/ETH/SOL spot + 24h moves… | $0.05 |
| netintel_web_fetch | Fetch any URL and get the raw body back — JSON parsed, everything else… | $0.003 |
| netintel_weather_current | Current weather for any city or lat/lon worldwide, plus a 3-day… | $0.002 |
| netintel_weather_forecast | Multi-day weather forecast for any city or lat/lon worldwide — up to 16… | $0.003 |
| netintel_prediction_markets | Live prediction market odds from Polymarket — list the top active… | $0.005 |
| netintel_prediction_market | Full detail for ONE Polymarket prediction market by id or slug —… | $0.003 |
| netintel_ssl_cert | SSL certificate check for any domain — issuer, subject, SANs, valid… | $0.003 |
| netintel_text_chunk | Split text into overlapping chunks for RAG ingestion — by characters or… | $0.001 |
| netintel_text_stats | Instant text statistics — characters (with/without spaces), words… | $0.001 |
| netintel_embeddings | Multilingual text embeddings (384-dim) served in-house, no OpenAI… | $0.001 |
| netintel_email_verify | Validate an email address — email verification before you send: syntax… | $0.001 |
| netintel_exa_search | Exa neural web search for AI agents — POST or GET a query, get ranked… | $0.01 |
| netintel_web_search | Web search for AI agents — one query in, ranked live results out… | $0.01 |
| netintel_exa_contents | Clean page text for up to 3 URLs in one call via Exa's index + live… | $0.005 |
| netintel_exa_answer | Ask a question, get a direct answer grounded in a live web search, with… | $0.01 |
| netintel_pdf_parse | Parse a PDF to text and Markdown: send a PDF url or base64 file, get… | $0.005 |
| netintel_lead_check | Check a sales lead before outreach — one call verifies the email… | $0.005 |

## Find the right x402 endpoint from any provider

These tools answer "which x402 endpoint should I call?" over the whole Coinbase Bazaar catalog — every provider, not only NetIntel — ranked by fit, real paying demand, health and price, with the reasons. They call the NetIntel Router (https://router.netintel.dev) with the same wallet and spending limits. NetIntel's own endpoints are labeled and get no boost. Daily rankings for 40 common agent tasks: https://router.netintel.dev/rankings

| Tool | Description | Price |
|------|-------------|-------|
| netintel_route_search | Find which x402 pay-per-call API endpoint fits a job, from ANY provider… | free |
| netintel_route_recommend | Get the 3 best x402 endpoints for a job, from three different… | $0.005 |
| netintel_route_vet | Check one x402 endpoint before relying on it: give its URL as the… | $0.002 |

## Payment
All tools pay automatically via x402 in USDC on Base mainnet.
Your wallet is charged per call. No subscriptions, no API keys.
(The NetIntel API itself also accepts USDC on Solana — call it directly
over x402 with a Solana wallet if you prefer that rail.)

## Links
- Website: https://netintel.dev
- API manifest: https://netintel.dev/.well-known/x402
- OpenAPI spec: https://netintel.dev/openapi.json
- Agent catalog: https://netintel.dev/llms.txt
- Router (which x402 endpoint to call; daily rankings): https://router.netintel.dev/rankings
- Source: https://github.com/kjgueye/netintel-mcp
