# netintel-mcp

MCP server for NetIntel — 69 network intelligence tools for AI agents.
DNS, SSL, WHOIS, email security, cloud fingerprinting, OSINT and more.
Pay-per-call via x402 on Base mainnet. No API keys needed — just a wallet with USDC.

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

69 pay-per-call tools across DNS, SSL/TLS, WHOIS & domains, email security, IP intelligence, web & content, OSINT, AI text processing, and bundled reports.

| Tool | Description | Price |
|------|-------------|-------|
| netintel_dns_lookup | Resolves all DNS record types for a domain, parses SPF/DKIM/DMARC from… | $0.03 |
| netintel_ssl_analyze | Performs a TLS handshake to inspect the certificate chain, probes… | $0.03 |
| netintel_redirect_trace | Follows a URL through its full redirect chain (up to 20 hops)… | $0.01 |
| netintel_security_headers | Fetches a URL and evaluates 10 security-critical response headers (CSP… | $0.01 |
| netintel_email_auth | Validates SPF, DKIM, and DMARC records for a domain, probes multiple… | $0.03 |
| netintel_cloud_fingerprint | Fingerprints a domain's cloud infrastructure by probing DNS records… | $0.01 |
| netintel_schema_parse | Accepts unstructured text and a JSON Schema, then uses an LLM to… | $0.10 |
| netintel_asn_lookup | Resolves an IP address or domain to its Autonomous System Number (ASN)… | $0.03 |
| netintel_whois_lookup | Look up domain registration metadata via RDAP — returns registrar… | $0.01 |
| netintel_cert_transparency | Query the crt.sh certificate transparency log database to enumerate all… | $0.01 |
| netintel_subnet_calc | Calculates IPv4/IPv6 subnet details from CIDR notation including… | $0.005 |
| netintel_dns_propagation | Query a domain's DNS record across 10 geographically distributed public… | $0.03 |
| netintel_dnssec_validate | Validate a domain's DNSSEC configuration by checking for DS records at… | $0.03 |
| netintel_ip_blacklist | Check an IP address against 15 major DNS blacklists (Spamhaus… | $0.05 |
| netintel_tech_fingerprint | Fetch a URL and detect the full technology stack from HTTP response… | $0.05 |
| netintel_breach_check | Check if a password has appeared in known data breaches using the… | $0.01 |
| netintel_domain_availability | Check if a domain name is available for registration by querying RDAP… | $0.05 |
| netintel_email_intel | Validate an email address for deliverability, detect… | $0.05 |
| netintel_og_scraper | Fetch any public URL and extract structured metadata — Open Graph tags… | $0.01 |
| netintel_page_extract | Fetch any article or web page and extract clean readable text stripped… | $0.05 |
| netintel_phone_intel | Parse and validate any phone number in any format, identify its… | $0.05 |
| netintel_robots_txt | Fetch and parse a domain's robots.txt file — returns all crawl rules by… | $0.01 |
| netintel_rss_parser | Fetch and parse any RSS 2.0 or Atom feed URL and return structured… | $0.01 |
| netintel_username_check | Check username availability across 20+ social platforms and developer… | $0.03 |
| netintel_wayback_lookup | Query the Internet Archive Wayback Machine to check if a URL has ever… | $0.01 |
| netintel_ip_reputation | Check an IP address against AbuseIPDB and AlienVault OTX threat feeds… | $0.05 |
| netintel_cron_parser | Parse any cron expression into a human-readable explanation, validate… | $0.03 |
| netintel_currency_exchange | Convert any amount between 33 fiat currencies (live European Central… | $0.01 |
| netintel_github_intel | Fetch public metadata for any GitHub repository — stars, forks, open… | $0.03 |
| netintel_holidays | Look up public holidays for any country and year, check whether a… | $0.005 |
| netintel_ip_geo | Geolocate any IPv4 or IPv6 address to city, region, country… | $0.03 |
| netintel_jwt_inspector | Decode and inspect any JWT token — extracts header algorithm, payload… | $0.005 |
| netintel_lang_detect | Detect the language of any text input using character frequency… | $0.005 |
| netintel_npm_intel | Fetch metadata for any npm package — download counts, latest version… | $0.01 |
| netintel_sitemap_parser | Fetch and parse any XML sitemap or sitemap index file — returns all… | $0.01 |
| netintel_url_safety | Check a URL against URLhaus malware database and heuristic phishing… | $0.05 |
| netintel_domain_age | Determine a domain's age from registration data and archival history —… | $0.03 |
| netintel_bulk_domain | Check availability of many domain names across multiple TLDs in a… | $0.10 |
| netintel_domain_appraise | Estimate the market value tier of a domain name using transparent… | $0.03 |
| netintel_domain_report | One call returns a complete intelligence profile for a domain — WHOIS… | $0.10 |
| netintel_ip_risk | One call returns a complete risk profile for an IP address —… | $0.10 |
| netintel_name_gen | Generate brandable startup/product names from a keyword using prefixes… | $0.05 |
| netintel_tld_price | Compare registration, renewal, and transfer prices for a TLD across… | $0.01 |
| netintel_typosquat | Generate common typo and look-alike variations of a domain and check… | $0.05 |
| netintel_classify | Classify text into caller-supplied categories using Claude Haiku —… | $0.03 |
| netintel_content_moderate | Moderate text content using Claude Haiku — flags categories like… | $0.05 |
| netintel_entity_extract | Extract named entities from text using Claude Haiku — people… | $0.05 |
| netintel_sentiment | Analyze the sentiment of text using Claude Haiku — returns overall… | $0.03 |
| netintel_text_summarize | Summarize any text or web page into a concise summary plus key bullet… | $0.05 |
| netintel_translate | Translate up to 2000 words between languages using Claude Haiku —… | $0.08 |
| netintel_translate_short | Translate up to 500 words between languages using Claude Haiku —… | $0.03 |
| netintel_domain_due_diligence | One call combines domain availability, heuristic value appraisal, and… | $0.20 |
| netintel_domain_report_full | One premium call returns a complete six-part domain profile — DNS… | $0.25 |
| netintel_email_report | One call combines domain email authentication (SPF/DKIM/DMARC)… | $0.15 |
| netintel_ip_report | One premium call returns a complete five-part IP profile — geolocation… | $0.20 |
| netintel_url_safety_full | One call vets a URL end to end — traces its full redirect chain, checks… | $0.15 |
| netintel_extract | Parse and normalize a freeform address string using Claude Haiku —… | $0.03 |
| netintel_extract_contact | Extract structured contact details from text, an email signature, or… | $0.05 |
| netintel_extract_invoice | Extract structured data from invoice or receipt text using Claude Haiku… | $0.10 |
| netintel_extract_resume | Extract structured data from resume/CV text using Claude Haiku —… | $0.08 |
| netintel_extract_table | Extract tabular data from messy text or HTML using Claude Haiku —… | $0.05 |
| netintel_markdown | Convert messy HTML or text into clean, well-structured Markdown using… | $0.03 |
| netintel_normalize | Conform messy or inconsistent JSON to a target schema using Claude… | $0.05 |
| netintel_text_to_json | Turn unstructured text into structured JSON matching a caller-supplied… | $0.05 |
| netintel_web | Fetch any web page or PDF and convert it to clean, structured Markdown… | $0.02 |
| netintel_money | Normalize any messy money string into a typed decimal amount plus ISO… | $0.01 |
| netintel_calendar | Turn event fields into a valid RFC 5545 .ics calendar file — handles… | $0.005 |
| netintel_event_classify | Cheap, fast "is this a dateable event?" filter for social and web text… | $0.02 |
| netintel_event_extract | Extract a normalized calendar event from any caption, announcement, or… | $0.10 |

## Payment
All tools pay automatically via x402 on Base mainnet (USDC).
Your wallet is charged per call. No subscriptions, no API keys.

## Links
- Website: https://netintel.dev
- API manifest: https://netintel.dev/.well-known/x402
- OpenAPI spec: https://netintel.dev/openapi.json
- Agent catalog: https://netintel.dev/llms.txt
- Source: https://github.com/kjgueye/netintel-mcp
