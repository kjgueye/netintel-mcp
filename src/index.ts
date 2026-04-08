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
}

async function main() {
  const api = await createClient();

  const server = new McpServer({
    name: "netintel-mcp",
    version: "1.0.0",
  });

  registerTools(server, api);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal:", error);
  process.exit(1);
});
