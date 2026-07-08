#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createClient } from "./client.js";
import type { AxiosInstance } from "axios";

function ok(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
}

function err(e: unknown) {
  const ax = e as { response?: { status?: number }; message?: string };
  const status = ax.response?.status ?? "unknown";
  const msg = ax.message ?? String(e);
  return {
    content: [{ type: "text" as const, text: `Error (${status}): ${msg}` }],
    isError: true,
  };
}

function params(obj: Record<string, unknown>): Record<string, unknown> {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) clean[k] = v;
  }
  return clean;
}

function registerTools(server: McpServer, api: AxiosInstance) {
  // 1. DNS Lookup
  server.tool(
    "netintel_dns_lookup",
    "Resolve all DNS records for a domain including A, MX, TXT, SPF, DKIM, DMARC. Returns propagation consistency across Google, Cloudflare and Quad9 resolvers.",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/dns/lookup", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 2. SSL Analyze
  server.tool(
    "netintel_ssl_analyze",
    "Analyze TLS certificate chain, supported protocols (TLS 1.0-1.3), key strength, and return an overall security grade A-F.",
    { domain: z.string(), port: z.number().optional() },
    async ({ domain, port }) => {
      try {
        const res = await api.get("/ssl/analyze", { params: params({ domain, port }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 3. Redirect Trace
  server.tool(
    "netintel_redirect_trace",
    "Follow a URL through its full redirect chain recording status codes, timing, TLS status per hop. Returns a redirect health grade A-F and detects protocol downgrades.",
    { url: z.string(), max_hops: z.number().optional() },
    async ({ url, max_hops }) => {
      try {
        const res = await api.get("/redirect/trace", { params: params({ url, max_hops }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 4. Security Headers
  server.tool(
    "netintel_security_headers",
    "Audit 10 security-critical HTTP response headers (CSP, HSTS, X-Frame-Options, etc). Detects anti-patterns and returns a security grade A-F.",
    { target: z.string() },
    async ({ target }) => {
      try {
        const res = await api.get("/security-headers/analyze", { params: { target } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 5. Email Auth (POST)
  server.tool(
    "netintel_email_auth",
    "Validate SPF, DKIM, and DMARC records for a domain. Probes multiple DKIM selectors and returns an email security grade A-F.",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.post("/email-auth", { domain });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 6. Cloud Fingerprint
  server.tool(
    "netintel_cloud_fingerprint",
    "Detect CDN, WAF, hosting provider, DNS provider, and email provider for a domain with confidence scores and an infrastructure security grade.",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/cloud-fingerprint/analyze", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 7. Schema Parse (POST)
  server.tool(
    "netintel_schema_parse",
    "Extract structured data from any unstructured text using LLM. Pass any JSON Schema and get back a typed object. Works on emails, invoices, resumes, contracts, anything.",
    { raw_text: z.string(), target_schema: z.record(z.any()) },
    async ({ raw_text, target_schema }) => {
      try {
        const res = await api.post("/schema-parse/extract", { raw_text, target_schema });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 8. ASN Lookup
  server.tool(
    "netintel_asn_lookup",
    "Resolve an IP or domain to its ASN, network owner, country, and hosting/cloud classification with a trust score.",
    { target: z.string() },
    async ({ target }) => {
      try {
        const res = await api.get("/asn-lookup/analyze", { params: { target } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 9. WHOIS Lookup
  server.tool(
    "netintel_whois_lookup",
    "Look up domain registration via RDAP — registrar, creation date, expiry date, nameservers, and domain trustworthiness score.",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/whois-rdap/lookup", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 10. Cert Transparency
  server.tool(
    "netintel_cert_transparency",
    "Query crt.sh certificate transparency logs to enumerate all SSL certs ever issued for a domain. Returns discovered subdomains, issuers, and flags wildcard or suspicious certs.",
    {
      domain: z.string(),
      include_subdomains: z.boolean().optional(),
      limit: z.number().optional(),
    },
    async ({ domain, include_subdomains, limit }) => {
      try {
        const res = await api.get("/cert-transparency/lookup", {
          params: params({ domain, include_subdomains, limit }),
        });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 11. Subnet Calc
  server.tool(
    "netintel_subnet_calc",
    "Calculate IPv4/IPv6 subnet details from CIDR notation — network address, broadcast, netmask, usable host range, supernet. Pass multiple CIDRs comma-separated to detect overlaps.",
    { cidr: z.string() },
    async ({ cidr }) => {
      try {
        const res = await api.get("/subnet/calc", { params: { cidr } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 12. DNS Propagation
  server.tool(
    "netintel_dns_propagation",
    "Check DNS propagation across 10 global resolvers simultaneously. Returns what each resolver sees, propagation percentage, and flags divergent resolvers.",
    { domain: z.string(), record_type: z.string().optional() },
    async ({ domain, record_type }) => {
      try {
        const res = await api.get("/dns-propagation/check", {
          params: params({ domain, record_type }),
        });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 13. DNSSEC Validate
  server.tool(
    "netintel_dnssec_validate",
    "Validate DNSSEC configuration — checks DS records, DNSKEY, RRSIG signatures, and NSEC/NSEC3. Returns full chain-of-trust assessment.",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/dnssec/validate", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 14. IP Blacklist
  server.tool(
    "netintel_ip_blacklist",
    "Check an IP address against 15 major DNS blacklists (Spamhaus, Barracuda, SORBS, etc). Returns threat level and which lists it appears on.",
    { ip: z.string() },
    async ({ ip }) => {
      try {
        const res = await api.get("/ip-blacklist/check", { params: { ip } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 15. Tech Fingerprint
  server.tool(
    "netintel_tech_fingerprint",
    "Detect the full technology stack of a website — CMS, framework, CDN, analytics, security tools — from HTTP headers and HTML.",
    { url: z.string() },
    async ({ url }) => {
      try {
        const res = await api.get("/tech-fingerprint/analyze", { params: { url } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 16. Breach Check
  server.tool(
    "netintel_breach_check",
    "Check if a password has appeared in known data breaches using HaveIBeenPwned k-anonymity API. The full password is never transmitted — only a 5-char SHA-1 prefix.",
    { password: z.string() },
    async ({ password }) => {
      try {
        const res = await api.get("/breach-check/password", { params: { password } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 17. Domain Availability
  server.tool(
    "netintel_domain_availability",
    "Check if a domain is available for registration across 10 TLDs simultaneously using RDAP and DNS. Returns availability status, registrar, and expiry for each TLD.",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/domain-availability/check", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 18. Email Intel
  server.tool(
    "netintel_email_intel",
    "Validate an email address — check deliverability, detect disposable domains, identify role-based addresses, verify MX records.",
    { email: z.string() },
    async ({ email }) => {
      try {
        const res = await api.get("/email-intel/analyze", { params: { email } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 19. OG Scraper
  server.tool(
    "netintel_og_scraper",
    "Extract Open Graph tags, Twitter Card tags, canonical URL, title, description, favicon, JSON-LD structured data, and article metadata from any public URL.",
    { url: z.string() },
    async ({ url }) => {
      try {
        const res = await api.get("/og-scraper/extract", { params: { url } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 20. Page Extract
  server.tool(
    "netintel_page_extract",
    "Fetch any article or web page and extract clean readable text stripped of ads and boilerplate. Returns content, word count, reading time, and language.",
    { url: z.string() },
    async ({ url }) => {
      try {
        const res = await api.get("/page-extract/read", { params: { url } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 21. Phone Intel
  server.tool(
    "netintel_phone_intel",
    "Parse and validate any phone number in any format. Returns country, line type (mobile/landline/VOIP/toll-free), carrier region, and all standard format variants.",
    { phone: z.string(), country_hint: z.string().optional() },
    async ({ phone, country_hint }) => {
      try {
        const res = await api.get("/phone-intel/analyze", {
          params: params({ phone, country_hint }),
        });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 22. Robots.txt
  server.tool(
    "netintel_robots_txt",
    "Fetch and parse a domain's robots.txt. Returns all crawl rules, sitemap URLs, crawl delay settings, and checks if a specific path is allowed for a given bot.",
    { domain: z.string(), path: z.string().optional(), user_agent: z.string().optional() },
    async ({ domain, path, user_agent }) => {
      try {
        const res = await api.get("/robots-txt/analyze", {
          params: params({ domain, path, user_agent }),
        });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 23. RSS Parser
  server.tool(
    "netintel_rss_parser",
    "Fetch and parse any RSS 2.0 or Atom feed. Returns structured articles with title, link, description, author, publish date, and categories.",
    { url: z.string(), limit: z.number().optional() },
    async ({ url, limit }) => {
      try {
        const res = await api.get("/rss-parser/fetch", { params: params({ url, limit }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 24. Username Check
  server.tool(
    "netintel_username_check",
    "Check username availability across 20+ platforms simultaneously — GitHub, Twitter, Instagram, npm, and more. Returns taken/available/unknown status per platform.",
    { username: z.string() },
    async ({ username }) => {
      try {
        const res = await api.get("/username-check/lookup", { params: { username } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 25. Wayback Lookup
  server.tool(
    "netintel_wayback_lookup",
    "Query the Wayback Machine for archived snapshots of a URL. Returns first/last capture dates, total snapshot count, and the closest snapshot to an optional target date.",
    { url: z.string(), timestamp: z.string().optional() },
    async ({ url, timestamp }) => {
      try {
        const res = await api.get("/wayback/lookup", { params: params({ url, timestamp }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 26. IP Reputation
  server.tool(
    "netintel_ip_reputation",
    "Check IP against AbuseIPDB and AlienVault OTX. Returns composite risk score, threat categories, and malware families.",
    { ip: z.string() },
    async ({ ip }) => {
      try {
        const res = await api.get("/ip-reputation/analyze", { params: { ip } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 27. Cron Parser
  server.tool(
    "netintel_cron_parser",
    "Parse a cron expression, explain the schedule in plain English, and compute the next 5 run times.",
    { expression: z.string() },
    async ({ expression }) => {
      try {
        const res = await api.get("/cron-parser/explain", { params: { expression } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 28. Currency Exchange
  server.tool(
    "netintel_currency_exchange",
    "Convert between 32 currencies with real-time or historical rates. Pass a date (YYYY-MM-DD) for historical lookup.",
    { from: z.string(), to: z.string(), amount: z.number().optional(), date: z.string().optional() },
    async ({ from, to, amount, date }) => {
      try {
        const res = await api.get("/currency-exchange/convert", {
          params: params({ from, to, amount, date }),
        });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 29. GitHub Intel
  server.tool(
    "netintel_github_intel",
    "Analyze a GitHub repo — stars, forks, activity, license, open issues, maintenance score. Pass owner/repo format.",
    { repo: z.string() },
    async ({ repo }) => {
      try {
        const res = await api.get("/github-intel/analyze", { params: { repo } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 30. Holidays
  server.tool(
    "netintel_holidays",
    "Get public holidays by country. Check if a date is a business day or weekend. ISO 3166-1 alpha-2 country codes.",
    { country: z.string(), year: z.number().optional(), month: z.number().optional() },
    async ({ country, year, month }) => {
      try {
        const res = await api.get("/holidays/check", {
          params: params({ country, year, month }),
        });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 31. IP Geo
  server.tool(
    "netintel_ip_geo",
    "Geolocate an IP address — country, city, coordinates, ISP, ASN, timezone.",
    { ip: z.string() },
    async ({ ip }) => {
      try {
        const res = await api.get("/ip-geo/locate", { params: { ip } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 32. JWT Inspector
  server.tool(
    "netintel_jwt_inspector",
    "Decode a JWT token — inspect header and payload, check expiry, flag security issues like weak algorithms.",
    { token: z.string() },
    async ({ token }) => {
      try {
        const res = await api.get("/jwt-inspector/decode", { params: { token } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 33. Lang Detect (POST)
  server.tool(
    "netintel_lang_detect",
    "Detect the language of any text with confidence scoring. Supports 50+ languages.",
    { text: z.string() },
    async ({ text }) => {
      try {
        const res = await api.post("/lang-detect/analyze", { text });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 34. npm Intel
  server.tool(
    "netintel_npm_intel",
    "Analyze an npm package — versions, weekly downloads, maintainers, dependencies, quality and maintenance score.",
    { package: z.string() },
    async (args) => {
      try {
        const res = await api.get("/npm-intel/analyze", { params: { package: args.package } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 35. Sitemap Parser
  server.tool(
    "netintel_sitemap_parser",
    "Parse an XML sitemap or auto-discover it from a domain. Returns all URLs with metadata including lastmod and priority.",
    { url: z.string() },
    async ({ url }) => {
      try {
        const res = await api.get("/sitemap-parser/fetch", { params: { url } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 36. URL Safety
  server.tool(
    "netintel_url_safety",
    "Check a URL against URLhaus malware database and heuristic analysis. Returns threat classification and risk score.",
    { url: z.string() },
    async ({ url }) => {
      try {
        const res = await api.get("/url-safety/check", { params: { url } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );
  // 37. Domain Age
  server.tool(
    "netintel_domain_age",
    "Determine a domain's age from registration data and archival history — returns creation date, age in years, first Wayback Machine capture, total archived snapshots, and a maturity signal so agents can assess domain trustworthiness and…",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/domain-age/check", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 38. Bulk Domain (POST)
  server.tool(
    "netintel_bulk_domain",
    "Check availability of many domain names across multiple TLDs in a single call — submit up to 50 name/TLD combinations and get back per-domain registration status, registrar, and expiry concurrently, so agents can scan an entire naming…",
    { names: z.array(z.string()), tlds: z.array(z.string()).optional() },
    async ({ names, tlds }) => {
      try {
        const res = await api.post("/bulk-domain/check", { names, tlds });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 39. Domain Appraise
  server.tool(
    "netintel_domain_appraise",
    "Estimate the market value tier of a domain name using transparent heuristics — length, TLD premium, dictionary-word presence, pronounceability, keyword value, and numeric/hyphen penalties — returns a value tier and 0-100 quality score so…",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/domain-appraise/estimate", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 40. Domain Report
  server.tool(
    "netintel_domain_report",
    "One call returns a complete intelligence profile for a domain — WHOIS registration, DNS records, SSL certificate, detected tech stack, and blacklist status — aggregated into a single risk-scored report so agents can fully vet a domain…",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/domain-report/analyze", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 41. Ip Risk
  server.tool(
    "netintel_ip_risk",
    "One call returns a complete risk profile for an IP address — geolocation, ASN/network owner, blacklist status across multiple DNSBLs, and proxy/VPN/hosting classification — aggregated into a single verdict so agents can make a block/allow…",
    { ip: z.string() },
    async ({ ip }) => {
      try {
        const res = await api.get("/ip-risk/score", { params: { ip } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 42. Name Gen
  server.tool(
    "netintel_name_gen",
    "Generate brandable startup/product names from a keyword using prefixes, suffixes, blends, and phonetic patterns, then check .com (or any TLD) availability for each via DNS — returns available names ranked by a brandability heuristic so…",
    { keyword: z.string(), tld: z.string().optional(), limit: z.number().optional() },
    async ({ keyword, tld, limit }) => {
      try {
        const res = await api.get("/name-gen/suggest", { params: params({ keyword, tld, limit }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 43. Tld Price
  server.tool(
    "netintel_tld_price",
    "Compare registration, renewal, and transfer prices for a TLD across major registrars, or for a single domain name across many TLDs — returns sorted reference pricing so agents can find the cheapest place to register, budget domain…",
    { tld: z.string().optional(), name: z.string().optional() },
    async ({ tld, name }) => {
      try {
        const res = await api.get("/tld-price/compare", { params: params({ tld, name }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 44. Typosquat
  server.tool(
    "netintel_typosquat",
    "Generate common typo and look-alike variations of a domain and check which are already registered — catches character swaps, omissions, additions, homoglyphs, and alternate TLDs so agents can detect typosquatting and brand-impersonation…",
    { domain: z.string(), limit: z.number().optional() },
    async ({ domain, limit }) => {
      try {
        const res = await api.get("/typosquat/scan", { params: params({ domain, limit }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 45. Classify (POST)
  server.tool(
    "netintel_classify",
    "Classify text into caller-supplied categories using Claude Haiku — zero-shot classification where the agent provides the label set and gets back the best-matching category with confidence and per-label scores, so agents can route, tag, and…",
    { text: z.string(), labels: z.array(z.string()), multi_label: z.boolean().optional() },
    async ({ text, labels, multi_label }) => {
      try {
        const res = await api.post("/classify", { text, labels, multi_label });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 46. Content Moderate (POST)
  server.tool(
    "netintel_content_moderate",
    "Moderate text content using Claude Haiku — flags categories like harassment, hate, sexual content, violence, self-harm, and spam with per-category severity and an overall allow/flag/block recommendation, so agents can screen user-generated…",
    { text: z.string() },
    async ({ text }) => {
      try {
        const res = await api.post("/content-moderate", { text });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 47. Entity Extract (POST)
  server.tool(
    "netintel_entity_extract",
    "Extract named entities from text using Claude Haiku — people, organizations, locations, dates, emails, URLs, money amounts, and products — returned as structured typed arrays so agents can pull structured signals out of unstructured text…",
    { text: z.string(), types: z.array(z.string()).optional() },
    async ({ text, types }) => {
      try {
        const res = await api.post("/entity-extract", { text, types });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 48. Sentiment (POST)
  server.tool(
    "netintel_sentiment",
    "Analyze the sentiment of text using Claude Haiku — returns overall polarity (positive/negative/neutral/mixed), a -1 to +1 score, detected emotions, and optional per-aspect sentiment, so agents can gauge tone in reviews, messages, and…",
    { text: z.string(), aspects: z.array(z.string()).optional() },
    async ({ text, aspects }) => {
      try {
        const res = await api.post("/sentiment/analyze", { text, aspects });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 49. Text Summarize (POST)
  server.tool(
    "netintel_text_summarize",
    "Summarize any text or web page into a concise summary plus key bullet points using Claude Haiku — accepts raw text or a URL (which it fetches and extracts), enforces an input cap, and returns a clean structured summary so agents can…",
    { text: z.string().optional(), url: z.string().optional(), max_points: z.number().optional() },
    async ({ text, url, max_points }) => {
      try {
        const res = await api.post("/text-summarize", { text, url, max_points });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 50. Translate (POST)
  server.tool(
    "netintel_translate",
    "Translate up to 2000 words between languages using Claude Haiku — auto-detects source, supports 30+ target languages, preserves formatting, for larger documents and articles. For short snippets use the cheaper /translate/short.",
    { text: z.string(), target: z.string(), source: z.string().optional() },
    async ({ text, target, source }) => {
      try {
        const res = await api.post("/translate/long", { text, target, source });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 51. Translate (POST)
  server.tool(
    "netintel_translate_short",
    "Translate up to 500 words between languages using Claude Haiku — auto-detects source language, supports 30+ target languages, preserves formatting, and returns the translation with detected source so agents can localize short content…",
    { text: z.string(), target: z.string(), source: z.string().optional() },
    async ({ text, target, source }) => {
      try {
        const res = await api.post("/translate/short", { text, target, source });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 52. Domain Due Diligence
  server.tool(
    "netintel_domain_due_diligence",
    "One call combines domain availability, heuristic value appraisal, and TLD pricing into a single acquisition brief — tells an agent whether a name is available, what it's worth, and what it costs across TLDs, concurrently and with graceful…",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/domain-due-diligence", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 53. Domain Report
  server.tool(
    "netintel_domain_report_full",
    "One premium call returns a complete six-part domain profile — DNS records, SSL certificate, WHOIS registration, cloud fingerprint, technology stack, and security headers — each section run concurrently with graceful partial-failure…",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.get("/domain-report/full", { params: { domain } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 54. Email Report
  server.tool(
    "netintel_email_report",
    "One call combines domain email authentication (SPF/DKIM/DMARC), email-address intelligence (deliverability, disposable/role detection), and an optional password breach check into a single email-trust report — each section run concurrently…",
    { email: z.string(), password: z.string().optional() },
    async ({ email, password }) => {
      try {
        const res = await api.get("/email-report/full", { params: params({ email, password }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 55. Ip Report
  server.tool(
    "netintel_ip_report",
    "One premium call returns a complete five-part IP profile — geolocation, ASN/network ownership, multi-DNSBL blacklist status, threat reputation, and an aggregate risk verdict — run concurrently with graceful partial-failure handling, so…",
    { ip: z.string() },
    async ({ ip }) => {
      try {
        const res = await api.get("/ip-report/full", { params: { ip } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 56. Url Safety
  server.tool(
    "netintel_url_safety_full",
    "One call vets a URL end to end — traces its full redirect chain, checks it against malware/phishing databases, audits its security headers, and inspects its SSL certificate — concurrent with graceful partial-failure handling, so agents get…",
    { url: z.string() },
    async ({ url }) => {
      try {
        const res = await api.get("/url-safety/full", { params: { url } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 57. Extract (POST)
  server.tool(
    "netintel_extract",
    "Parse and normalize a freeform address string using Claude Haiku — splits it into street, city, state/region, postal code, and country, plus a normalized single-line form, so agents can clean and standardize messy address data for…",
    { address: z.string() },
    async ({ address }) => {
      try {
        const res = await api.post("/extract/address", { address });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 58. Extract (POST)
  server.tool(
    "netintel_extract_contact",
    "Extract structured contact details from text, an email signature, or webpage text using Claude Haiku — returns name, title, company, email, phone, and address as clean JSON so agents can turn unstructured contact blocks into CRM-ready…",
    { text: z.string() },
    async ({ text }) => {
      try {
        const res = await api.post("/extract/contact", { text });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 59. Extract (POST)
  server.tool(
    "netintel_extract_invoice",
    "Extract structured data from invoice or receipt text using Claude Haiku — returns vendor, invoice number, dates, line items, subtotal, tax, total, and currency as clean JSON so agents can automate accounts-payable, expense processing, and…",
    { text: z.string() },
    async ({ text }) => {
      try {
        const res = await api.post("/extract/invoice", { text });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 60. Extract (POST)
  server.tool(
    "netintel_extract_resume",
    "Extract structured data from resume/CV text using Claude Haiku — returns name, contact info, skills, work experience, and education as clean JSON arrays so agents can automate applicant screening, candidate databases, and recruiting…",
    { text: z.string() },
    async ({ text }) => {
      try {
        const res = await api.post("/extract/resume", { text });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 61. Extract (POST)
  server.tool(
    "netintel_extract_table",
    "Extract tabular data from messy text or HTML using Claude Haiku — detects columns and rows in unstructured content and returns clean structured JSON (columns + rows) so agents can turn pasted tables, HTML tables, and delimited text into…",
    { text: z.string() },
    async ({ text }) => {
      try {
        const res = await api.post("/extract/table", { text });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 62. Markdown (POST)
  server.tool(
    "netintel_markdown",
    "Convert messy HTML or text into clean, well-structured Markdown using Claude Haiku — strips boilerplate, fixes heading hierarchy, normalizes lists and links, and returns readable Markdown so agents can feed clean docs into downstream…",
    { text: z.string() },
    async ({ text }) => {
      try {
        const res = await api.post("/markdown/clean", { text });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 63. Normalize (POST)
  server.tool(
    "netintel_normalize",
    "Conform messy or inconsistent JSON to a target schema using Claude Haiku — renames keys, coerces types (string→number, \"true\"→boolean, etc.), and fills missing fields with null, returning JSON that matches the exact shape the caller…",
    { data: z.string(), schema: z.record(z.any()) },
    async ({ data, schema }) => {
      try {
        const res = await api.post("/normalize/json", { data, schema });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 64. Text To Json (POST)
  server.tool(
    "netintel_text_to_json",
    "Turn unstructured text into structured JSON matching a caller-supplied schema using Claude Haiku — the agent declares the fields and types it wants, and gets back populated JSON with values pulled from the text and coerced to the right…",
    { text: z.string(), schema: z.record(z.any()) },
    async ({ text, schema }) => {
      try {
        const res = await api.post("/text-to-json", { text, schema });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 65. Web
  server.tool(
    "netintel_web",
    "Fetch any web page or PDF and convert it to clean, structured Markdown — strips scripts, nav, ads, and boilerplate while preserving headings, links, lists, tables, code blocks, and blockquotes; extracts the text layer from PDFs. Returns…",
    { url: z.string() },
    async ({ url }) => {
      try {
        const res = await api.get("/web/extract", { params: { url } });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 66. Money (POST)
  server.tool(
    "netintel_money",
    "Normalize any messy money string into a typed decimal amount plus ISO 4217 currency — handles symbols, locale separators ($1,234.56 vs €1.234,56), magnitude suffixes (1.2M), accounting notation, and natural-language amounts — so agents can…",
    { text: z.string(), locale_hint: z.string().optional(), default_currency: z.string().optional(), allow_llm: z.boolean().optional() },
    async ({ text, locale_hint, default_currency, allow_llm }) => {
      try {
        const res = await api.post("/money/parse", { text, locale_hint, default_currency, allow_llm });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 67. Calendar (POST)
  server.tool(
    "netintel_calendar",
    "Turn event fields into a valid RFC 5545 .ics calendar file — handles timed and all-day events, escaping, line folding, and a deterministic UID for idempotent re-import — so agents can publish events that import cleanly into Google, Apple…",
    { title: z.string(), starts_at: z.string(), ends_at: z.string().optional(), all_day: z.boolean().optional(), timezone: z.string().optional(), location: z.string().optional(), description: z.string().optional(), url: z.string().optional(), organizer: z.string().optional() },
    async ({ title, starts_at, ends_at, all_day, timezone, location, description, url, organizer }) => {
      try {
        const res = await api.post("/calendar/ics", { title, starts_at, ends_at, all_day, timezone, location, description, url, organizer });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 68. Event Classify (POST)
  server.tool(
    "netintel_event_classify",
    "Cheap, fast \"is this a dateable event?\" filter for social and web text — one tiny Haiku call returns is_event, confidence, and a one-line reason, so agents can screen every post for free-ish and only pay for full extraction on the ones…",
    { text: z.string(), posted_at: z.string().optional(), timezone: z.string().optional() },
    async ({ text, posted_at, timezone }) => {
      try {
        const res = await api.post("/event-classify", { text, posted_at, timezone });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 69. Event Extract (POST)
  server.tool(
    "netintel_event_extract",
    "Extract a normalized calendar event from any caption, announcement, or page text using Claude Haiku — resolves relative dates (\"this Saturday 7pm\") against the post time and timezone, handles all-day and multi-day events, and returns…",
    { text: z.string(), posted_at: z.string().optional(), timezone: z.string().optional(), city: z.string().optional() },
    async ({ text, posted_at, timezone, city }) => {
      try {
        const res = await api.post("/event-extract", { text, posted_at, timezone, city });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 70. Messages (POST)
  server.tool(
    "netintel_messages",
    "OpenAI-compatible chat completions over x402, answered by Claude Sonnet 4.6 — send a messages array and get an assistant reply for Q&A, reasoning, agent planning, coding help, summarization, extraction, classification, and chatbot…",
    { model: z.string().optional(), messages: z.array(z.any()), max_tokens: z.number().optional(), temperature: z.number().optional(), top_p: z.number().optional() },
    async ({ model, messages, max_tokens, temperature, top_p }) => {
      try {
        const res = await api.post("/messages", { model, messages, max_tokens, temperature, top_p });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 71. Ai Image Assets (POST)
  server.tool(
    "netintel_ai_image_assets",
    "Generate agent-ready image assets — app icons, logos, social graphics, blog thumbnails, product mockups, banners, OG/web images. Claude first does prompt-engineering for the chosen use case (folding in style and brand colors), screens for…",
    { prompt: z.string(), use_case: z.string().optional(), style: z.string().optional(), brand_colors: z.array(z.string()).optional(), aspect_ratio: z.string().optional(), quality: z.string().optional(), n: z.number().optional(), provider: z.string().optional() },
    async ({ prompt, use_case, style, brand_colors, aspect_ratio, quality, n, provider }) => {
      try {
        const res = await api.post("/ai-image-assets/generate", { prompt, use_case, style, brand_colors, aspect_ratio, quality, n, provider });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 72. Ai Image (POST)
  server.tool(
    "netintel_ai_image",
    "Generate agent-ready image assets (icons, logos, social graphics, thumbnails, banners) with gpt-image-1. Claude refines the prompt, screens content, adds alt text and a score. Returns image_url as a base64 PNG data URI. Flat $0.25; n=1…",
    { prompt: z.string(), use_case: z.string().optional(), aspect_ratio: z.string().optional(), style: z.string().optional(), brand_colors: z.array(z.string()).optional() },
    async ({ prompt, use_case, aspect_ratio, style, brand_colors }) => {
      try {
        const res = await api.post("/ai-image/generate", { prompt, use_case, aspect_ratio, style, brand_colors });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 73. Convert
  server.tool(
    "netintel_convert",
    "Convert any physical measurement to another — length, mass, volume, temperature, area, speed, pressure, energy, time, data, and angle. Auto-detects the unit category, handles US/imperial ambiguity, and returns the exact converted value…",
    { value: z.number(), from: z.string(), to: z.string(), system: z.string().optional(), base: z.string().optional() },
    async ({ value, from, to, system, base }) => {
      try {
        const res = await api.get("/convert", { params: params({ value, from, to, system, base }) });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

  // 74. Domain (POST)
  server.tool(
    "netintel_domain",
    "Composite 0-100 trust/risk score for a domain in one call — blends domain age, SSL/TLS, DNS health, email auth (SPF/DKIM/DMARC), IP reputation, and certificate transparency into a single \"safe to do business with this domain?\" verdict with…",
    { domain: z.string() },
    async ({ domain }) => {
      try {
        const res = await api.post("/domain/vendor-risk", { domain });
        return ok(res.data);
      } catch (e) { return err(e); }
    }
  );

}

async function main() {
  const api = await createClient();

  const server = new McpServer({
    name: "netintel-mcp",
    version: "1.1.0",
  });

  registerTools(server, api);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal:", error);
  process.exit(1);
});
