// Live check of wallet-less mode against https://netintel.dev (no payment is made:
// the server runs with NO key, so every paid call stops at its 402).
//   npm run test:live
// Boots the BUILT server over stdio exactly as an MCP client would, calls a GET
// tool, a POST tool and wallet_status, prints each payload + reply, then proves
// every handed-off request is really payable: replaying it unpaid returns the
// same 402 at the same Base price.
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const env = { ...process.env };
delete env.EVM_PRIVATE_KEY;
const transport = new StdioClientTransport({ command: process.execPath, args: ["dist/index.js"], env, stderr: "ignore" });
const client = new Client({ name: "walletless-live", version: "1" });
await client.connect(transport);

const calls = [
  ["netintel_dns_lookup", { domain: "example.com" }],
  ["netintel_email_auth", { domain: "example.com" }],
  ["netintel_web_search", { query: "x402 payments" }],
];
let failures = 0;
for (const [name, args] of calls) {
  const res = await client.callTool({ name, arguments: args });
  const [text, json] = res.content.map((c) => c.text);
  console.log(`\n── ${name} ${JSON.stringify(args)}\n${text}\n${json}`);
  try {
    assert.equal(res.isError, true);
    const req = JSON.parse(json).pay_with_your_wallet;
    assert.match(req.url, /^https:\/\/netintel\.dev\//);
    assert.ok(Number(req.max_amount_atomic) > 0, "price present");
    // Replay the exact request unpaid: it must be the same 402 at the same Base price.
    const r = await fetch(req.url, { method: req.method, headers: { "content-type": "application/json", accept: "application/json" }, ...(req.body !== undefined ? { body: JSON.stringify(req.body) } : {}) });
    const body = await r.json();
    const baseAmt = body.accepts?.find((a) => a.network === "eip155:8453")?.amount;
    assert.equal(r.status, 402);
    assert.equal(baseAmt, req.max_amount_atomic);
    console.log(`   ✔ replay → 402, Base amount ${baseAmt} matches the handoff`);
  } catch (e) { failures++; console.log(`   ✘ ${e.message}`); }
}
const status = await client.callTool({ name: "netintel_wallet_status", arguments: {} });
console.log(`\n── netintel_wallet_status\n${status.content[0].text}`);
try {
  const s = JSON.parse(status.content[0].text);
  assert.equal(s.wallet_configured, false);
  assert.match(s.pay_with_your_own_wallet, /AgentCash/);
} catch (e) { failures++; console.log(`   ✘ ${e.message}`); }
await client.close();
console.log(failures ? `\nFAIL (${failures})` : "\nPASS — wallet-less mode hands back payable requests");
process.exit(failures ? 1 : 0);
