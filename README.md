# netintel-mcp

MCP server for NetIntel — 36 network intelligence tools for AI agents.
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

| Tool | Description | Price |
|------|-------------|-------|
| netintel_dns_lookup | Resolve all DNS records | $0.001 |
| netintel_ssl_analyze | TLS certificate analysis | $0.001 |
| netintel_redirect_trace | Follow redirect chains | $0.001 |
| netintel_security_headers | Audit security headers | $0.001 |
| netintel_email_auth | Validate SPF/DKIM/DMARC | $0.004 |
| netintel_cloud_fingerprint | Detect CDN/WAF/hosting | $0.002 |
| netintel_schema_parse | Extract structured data from text | $0.005 |
| netintel_asn_lookup | IP/domain to ASN lookup | $0.001 |
| netintel_whois_lookup | Domain registration via RDAP | $0.001 |
| netintel_cert_transparency | Certificate transparency logs | $0.002 |
| netintel_subnet_calc | CIDR subnet calculator | $0.001 |
| netintel_dns_propagation | Global DNS propagation check | $0.003 |
| netintel_dnssec_validate | DNSSEC chain of trust | $0.002 |
| netintel_ip_blacklist | IP blacklist check (15 lists) | $0.003 |
| netintel_tech_fingerprint | Website tech stack detection | $0.002 |
| netintel_breach_check | HaveIBeenPwned password check | $0.001 |
| netintel_domain_availability | Domain availability across TLDs | $0.002 |
| netintel_email_intel | Email address validation | $0.002 |
| netintel_og_scraper | Open Graph metadata extraction | $0.001 |
| netintel_page_extract | Clean text extraction from URLs | $0.002 |
| netintel_phone_intel | Phone number parsing/validation | $0.001 |
| netintel_robots_txt | Robots.txt parser | $0.001 |
| netintel_rss_parser | RSS/Atom feed parser | $0.001 |
| netintel_username_check | Username availability (20+ platforms) | $0.003 |
| netintel_wayback_lookup | Wayback Machine snapshots | $0.001 |
| netintel_ip_reputation | IP reputation via AbuseIPDB + AlienVault OTX | $0.010 |
| netintel_cron_parser | Parse cron expressions, explain schedule | $0.001 |
| netintel_currency_exchange | Convert between 32 currencies | $0.001 |
| netintel_github_intel | GitHub repo metrics and maintenance score | $0.001 |
| netintel_holidays | Public holidays by country | $0.001 |
| netintel_ip_geo | IP geolocation — country, city, ISP, ASN | $0.001 |
| netintel_jwt_inspector | Decode JWT tokens, flag security issues | $0.001 |
| netintel_lang_detect | Detect language with confidence scoring | $0.001 |
| netintel_npm_intel | npm package analysis and quality score | $0.001 |
| netintel_sitemap_parser | Parse XML sitemaps, extract URL metadata | $0.001 |
| netintel_url_safety | Check URL against URLhaus + heuristics | $0.002 |

## Payment
All tools pay automatically via x402 on Base mainnet (USDC).
Your wallet is charged per call. No subscriptions, no API keys.

## Links
- API manifest: https://netintel-production-440c.up.railway.app/.well-known/x402
- Docs: https://github.com/kjgueye/netintel-api
