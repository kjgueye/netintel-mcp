# netintel-mcp

MCP server for NetIntel — 94 network intelligence tools for AI agents.
DNS, SSL, WHOIS, email security, cloud fingerprinting, OSINT and more.
Pay-per-call via x402 — the NetIntel API accepts USDC on Base or Solana; this MCP server pays on Base. No API keys needed — just a wallet with USDC.

## Install

```bash
claude mcp add netintel-mcp -- --env EVM_PRIVATE_KEY=0xYOUR_PRIVATE_KEY
```

Or add manually to your Claude Desktop config:
```json
{
  "mcpServers": {
    "netintel": {
      "command": "npx",
      "args": ["netintel-mcp"],
      "env": {
        "EVM_PRIVATE_KEY": "0xYOUR_PRIVATE_KEY"
      }
    }
  }
}
```

## Requirements
- A wallet private key with USDC on Base mainnet
- EVM_PRIVATE_KEY environment variable set

## Tools

94 pay-per-call tools across DNS, SSL/TLS, WHOIS & domains, email security, IP intelligence, web & content, OSINT, AI text processing, and bundled reports.

| Tool | Description | Price |
|------|-------------|-------|
| netintel_dns_lookup | DNS lookup / nslookup / dig API — resolve the common DNS record types… | ? |
| netintel_ssl_analyze | Performs a TLS handshake to inspect the certificate chain, probes… | ? |
| netintel_redirect_trace | Follows a URL through its full redirect chain (up to 20 hops)… | ? |
| netintel_security_headers | Fetches a URL and evaluates 10 security-critical response headers (CSP… | ? |
| netintel_email_auth | Email deliverability & domain security check — validates SPF, DKIM… | ? |
| netintel_cloud_fingerprint | Fingerprints a domain's cloud infrastructure by probing DNS records… | ? |
| netintel_schema_parse | Extract structured data from any unstructured text into your own JSON… | ? |
| netintel_asn_lookup | Resolves an IP address or domain to its Autonomous System Number (ASN)… | ? |
| netintel_whois_lookup | WHOIS domain lookup via RDAP — registrar, creation/expiry/updated… | ? |
| netintel_cert_transparency | Query the crt.sh certificate transparency log database to enumerate all… | ? |
| netintel_subnet_calc | Calculates IPv4/IPv6 subnet details from CIDR notation —… | ? |
| netintel_dns_propagation | Query a domain's DNS record across 10 geographically distributed public… | ? |
| netintel_dnssec_validate | Validate a domain's DNSSEC configuration by checking for DS records at… | ? |
| netintel_ip_blacklist | Check an IP address against 15 major DNS blacklists (Spamhaus… | ? |
| netintel_tech_fingerprint | Fetch a URL and detect the full technology stack from HTTP response… | ? |
| netintel_breach_check | Check if a password has appeared in known data breaches using the… | ? |
| netintel_domain_availability | Check if a domain name is available for registration by querying RDAP… | ? |
| netintel_email_intel | Email verification & deliverability check (email validator / verifier)… | ? |
| netintel_og_scraper | Fetch any public URL and extract structured metadata — Open Graph tags… | ? |
| netintel_page_extract | Fetch any article or web page and extract clean readable text stripped… | ? |
| netintel_phone_intel | Parse and validate any phone number in any format, identify its country… | ? |
| netintel_robots_txt | Fetch and parse a domain's robots.txt file — returns all crawl rules by… | ? |
| netintel_rss_parser | Fetch and parse any RSS 2.0 or Atom feed URL and return structured… | ? |
| netintel_username_check | Check username availability across 20+ social platforms and developer… | ? |
| netintel_wayback_lookup | Query the Internet Archive Wayback Machine to check if a URL has ever… | ? |
| netintel_ip_reputation | Check an IP address against AbuseIPDB and AlienVault OTX threat feeds… | ? |
| netintel_cron_parser | Parse any cron expression into a human-readable explanation, validate… | ? |
| netintel_currency_exchange | Convert any amount between 32 fiat currencies (live European Central… | ? |
| netintel_github_intel |  | ? |
| netintel_holidays | Look up public holidays for any country and year, check whether a… | ? |
| netintel_ip_geo | IP geolocation lookup (geoip / IP location API) — geolocate any IPv4 or… | ? |
| netintel_jwt_inspector | Decode and inspect any JWT token — extracts header algorithm, payload… | ? |
| netintel_lang_detect | Detect the language of any text input using stopword-set matching and… | ? |
| netintel_npm_intel | Fetch metadata for any npm package — download counts, latest version… | ? |
| netintel_sitemap_parser | Fetch and parse any XML sitemap or sitemap index file — returns URLs… | ? |
| netintel_url_safety | Check a URL against URLhaus malware database and heuristic phishing… | ? |
| netintel_domain_age | Determine a domain's age from registration data and archival history —… | ? |
| netintel_bulk_domain | Check availability of many domain names across multiple TLDs in a… | ? |
| netintel_domain_appraise | Estimate the market value tier of a domain name using transparent… | ? |
| netintel_domain_report | One call returns a complete intelligence profile for a domain — WHOIS… | ? |
| netintel_ip_risk | One call returns a complete risk profile for an IP address —… | ? |
| netintel_name_gen | Generate brandable startup/product names from a keyword using prefixes… | ? |
| netintel_tld_price | Reference registration/renewal/transfer pricing from a curated table of… | ? |
| netintel_typosquat | Generate common typo and look-alike variations of a domain and check… | ? |
| netintel_classify | Text classification API — zero-shot text classifier / categorization:… | ? |
| netintel_content_moderate | Moderate text content using Claude Haiku — flags categories like… | ? |
| netintel_entity_extract | Extract named entities from text using Claude Haiku — people… | ? |
| netintel_sentiment | Sentiment analysis API — analyze sentiment of text and get a text… | ? |
| netintel_text_summarize | Text summarizer / summarization API — condense text, Markdown, or a URL… | ? |
| netintel_translate | Translate up to 2000 words between languages using Claude Haiku —… | ? |
| netintel_translate_short | Translate text between languages — text translation API for short… | ? |
| netintel_domain_due_diligence | One call combines domain availability, heuristic value appraisal, and… | ? |
| netintel_domain_report_full | One premium call returns a complete six-part domain profile — DNS… | ? |
| netintel_email_report | One call combines domain email authentication (SPF/DKIM/DMARC)… | ? |
| netintel_ip_report | One premium call returns a complete five-part IP profile — geolocation… | ? |
| netintel_url_safety_full | One call vets a URL end to end — traces its full redirect chain, checks… | ? |
| netintel_extract | Parse and normalize a freeform address string using Claude Haiku —… | ? |
| netintel_extract_contact | Extract structured contact details from text, an email signature, or… | ? |
| netintel_extract_invoice | Extract structured data from invoice or receipt text — or directly from… | ? |
| netintel_extract_resume | Extract structured data from resume/CV text using Claude Haiku —… | ? |
| netintel_extract_table | Extract tabular data from messy text or HTML using Claude Haiku —… | ? |
| netintel_markdown | Convert messy HTML or text into clean, well-structured Markdown using… | ? |
| netintel_normalize | Conform messy or inconsistent JSON to a target schema using Claude… | ? |
| netintel_text_to_json | Turn unstructured text into structured JSON matching a caller-supplied… | ? |
| netintel_web | Extract article / main content from any URL or PDF to clean, LLM-ready… | ? |
| netintel_money | Normalize any messy money string into a typed decimal amount plus ISO… | ? |
| netintel_calendar | Turn event fields into a valid RFC 5545 .ics calendar file — handles… | ? |
| netintel_event_classify | Cheap, fast "is this a dateable event?" filter for social and web text… | ? |
| netintel_event_extract | Event extraction / event parsing — turn any caption, announcement… | ? |
| netintel_messages | OpenAI-compatible chat completions over x402, answered by Claude Sonnet… | ? |
| netintel_ai_image | Generate agent-ready image assets (icons, logos, social graphics… | ? |
| netintel_convert | Convert any physical measurement — length, mass, volume, temperature… | ? |
| netintel_domain | Composite 0-100 trust/risk score for a domain in one call — blends… | ? |
| netintel_translate_structured | Translate structured content — JSON, HTML, Markdown, templates, UI… | ? |
| netintel_translate_batch | Translate many independent strings in one request — each with a caller… | ? |
| netintel_json | Repair malformed JSON into valid JSON — fixes code fences, trailing… | ? |
| netintel_schema | Validate data against a supplied schema — checks required fields… | ? |
| netintel_schema_map | Transform a source object into a target schema — matches fields by… | ? |
| netintel_domain_vet | Vet and pick a domain in one call — give candidate names, get back a… | ? |
| netintel_openai | Call OpenAI's gpt-4o via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_4_1 | Call OpenAI's gpt-4.1 via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_4_1_mini | Call OpenAI's gpt-4.1-mini via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_4o_mini | Call OpenAI's gpt-4o-mini via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_4_1_nano | Call OpenAI's gpt-4.1-nano via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_5 | Call OpenAI's gpt-5.5 via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_4 | Call OpenAI's gpt-5.4 via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_4_mini | Call OpenAI's gpt-5.4-mini via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_4_nano | Call OpenAI's gpt-5.4-nano via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_1 | Call OpenAI's gpt-5.1 via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_nano | Call OpenAI's gpt-5-nano via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_2 | Call OpenAI's gpt-5.2 via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_6_sol | Call OpenAI's gpt-5.6-sol via a single pay-per-call x402 endpoint — no… | ? |
| netintel_openai_gpt_5_6_terra | Call OpenAI's gpt-5.6-terra via a single pay-per-call x402 endpoint —… | ? |
| netintel_openai_gpt_5_6_luna | Call OpenAI's gpt-5.6-luna via a single pay-per-call x402 endpoint — no… | ? |

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
- Source: https://github.com/kjgueye/netintel-mcp
