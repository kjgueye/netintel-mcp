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
| netintel_dns_lookup | Resolve all DNS records | $0.030 |
| netintel_ssl_analyze | TLS certificate analysis | $0.030 |
| netintel_redirect_trace | Follow redirect chains | $0.010 |
| netintel_security_headers | Audit security headers | $0.010 |
| netintel_email_auth | Validate SPF/DKIM/DMARC | $0.030 |
| netintel_cloud_fingerprint | Detect CDN/WAF/hosting | $0.010 |
| netintel_schema_parse | Extract structured data from text | $0.100 |
| netintel_asn_lookup | IP/domain to ASN lookup | $0.030 |
| netintel_whois_lookup | Domain registration via RDAP | $0.010 |
| netintel_cert_transparency | Certificate transparency logs | $0.010 |
| netintel_subnet_calc | CIDR subnet calculator | $0.005 |
| netintel_dns_propagation | Global DNS propagation check | $0.030 |
| netintel_dnssec_validate | DNSSEC chain of trust | $0.030 |
| netintel_ip_blacklist | IP blacklist check (15 lists) | $0.050 |
| netintel_tech_fingerprint | Website tech stack detection | $0.050 |
| netintel_breach_check | HaveIBeenPwned password check | $0.010 |
| netintel_domain_availability | Domain availability across TLDs | $0.050 |
| netintel_email_intel | Email address validation | $0.050 |
| netintel_og_scraper | Open Graph metadata extraction | $0.010 |
| netintel_page_extract | Clean text extraction from URLs | $0.050 |
| netintel_phone_intel | Phone number parsing/validation | $0.050 |
| netintel_robots_txt | Robots.txt parser | $0.010 |
| netintel_rss_parser | RSS/Atom feed parser | $0.010 |
| netintel_username_check | Username availability (20+ platforms) | $0.030 |
| netintel_wayback_lookup | Wayback Machine snapshots | $0.010 |
| netintel_ip_reputation | IP reputation via AbuseIPDB + AlienVault OTX | $0.050 |
| netintel_cron_parser | Parse cron expressions, explain schedule | $0.030 |
| netintel_currency_exchange | Convert between 32 currencies | $0.010 |
| netintel_github_intel | GitHub repo metrics and maintenance score | $0.030 |
| netintel_holidays | Public holidays by country | $0.005 |
| netintel_ip_geo | IP geolocation — country, city, ISP, ASN | $0.030 |
| netintel_jwt_inspector | Decode JWT tokens, flag security issues | $0.005 |
| netintel_lang_detect | Detect language with confidence scoring | $0.005 |
| netintel_npm_intel | npm package analysis and quality score | $0.010 |
| netintel_sitemap_parser | Parse XML sitemaps, extract URL metadata | $0.010 |
| netintel_url_safety | Check URL against URLhaus + heuristics | $0.050 |
| netintel_domain_age | Determine a domain's age from registration data and archival | $0.030 |
| netintel_bulk_domain | Check availability of many domain names across multiple TLDs | $0.100 |
| netintel_domain_appraise | Estimate the market value tier of a domain name | $0.030 |
| netintel_domain_report | One call returns a complete intelligence profile for a domain | $0.100 |
| netintel_ip_risk | One call: complete risk profile for an IP address | $0.100 |
| netintel_name_gen | Generate brandable startup/product names from a keyword | $0.050 |
| netintel_tld_price | Compare registration, renewal, and transfer prices for a TLD | $0.010 |
| netintel_typosquat | Generate common typo and look-alike variations of a domain | $0.050 |
| netintel_classify | Classify text into caller-supplied categories (Claude) | $0.030 |
| netintel_content_moderate | Moderate text, flag unsafe categories (Claude) | $0.050 |
| netintel_entity_extract | Extract named entities (people, orgs, places) from text (Claude) | $0.050 |
| netintel_sentiment | Analyze sentiment of text, return score and label (Claude) | $0.030 |
| netintel_text_summarize | Summarize text or a web page with key points (Claude) | $0.050 |
| netintel_translate | Translate up to 2000 words between languages using Claude | $0.080 |
| netintel_translate_short | Translate up to 500 words between languages using Claude Haiku | $0.030 |
| netintel_domain_due_diligence | Bundle: availability + value estimate + DNS/SSL diligence | $0.200 |
| netintel_domain_report_full | Premium bundle: complete six-part domain profile | $0.250 |
| netintel_email_report | Bundle: email auth + domain + breach exposure | $0.150 |
| netintel_ip_report | Premium bundle: complete five-part IP profile | $0.200 |
| netintel_url_safety_full | Bundle: redirects + reputation + threat verdict for a URL | $0.150 |
| netintel_extract | Parse a freeform address into structured fields (Claude) | $0.030 |
| netintel_extract_contact | Extract structured contact details from text (Claude) | $0.050 |
| netintel_extract_invoice | Extract structured data from invoice or receipt text | $0.100 |
| netintel_extract_resume | Extract structured data from resume/CV text using Claude Haiku | $0.080 |
| netintel_extract_table | Extract tabular data from messy text or HTML using Claude | $0.050 |
| netintel_markdown | Convert messy HTML or text into clean Markdown (Claude) | $0.030 |
| netintel_normalize | Conform messy or inconsistent JSON to a target schema | $0.050 |
| netintel_text_to_json | Turn unstructured text into structured JSON | $0.050 |

## Payment
All tools pay automatically via x402 on Base mainnet (USDC).
Your wallet is charged per call. No subscriptions, no API keys.

## Links
- Website: https://netintel.dev
- API manifest: https://netintel.dev/.well-known/x402
- Source: https://github.com/kjgueye/netintel-api
