// Unit tests for the wallet-less pay handoff (src/pay-handoff.ts, run against dist/).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { requestFromAxios, payHandoffText, priceFrom402 } from "../dist/pay-handoff.js";

const BASE = "https://netintel.dev";
const challenge = (...accepts) => ({ x402Version: 2, accepts });
const sol = { network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", amount: "1500" };
const base = (amount) => ({ network: "eip155:8453", amount });

test("GET: rebuilds the absolute URL with its query and takes the Base price", () => {
  const r = requestFromAxios({ baseURL: BASE, url: "/dns/lookup", method: "get", params: { domain: "example.com" } }, challenge(sol, base("2000")));
  assert.deepEqual(r, { url: `${BASE}/dns/lookup?domain=example.com`, method: "GET", price_usd: 0.002, max_amount_atomic: "2000" });
});

test("POST: carries the JSON body as an object", () => {
  const r = requestFromAxios({ baseURL: BASE, url: "/web/search", method: "post", data: JSON.stringify({ query: "x402 sellers" }) }, challenge(base("10000")));
  assert.equal(r.method, "POST");
  assert.deepEqual(r.body, { query: "x402 sellers" });
  assert.equal(r.price_usd, 0.01);
});

test("absolute URLs on another host (the router) are kept as-is", () => {
  const r = requestFromAxios({ baseURL: BASE, url: "https://router.netintel.dev/route/vet", method: "get", params: { url: "https://a.example/x" } }, challenge(base("2000")));
  // Exactly what axios puts on the wire (it leaves ":" unescaped); what matters is the round trip.
  const u = new URL(r.url);
  assert.equal(u.origin + u.pathname, "https://router.netintel.dev/route/vet");
  assert.equal(u.searchParams.get("url"), "https://a.example/x");
});

test("v1 bodies quote a dollar price", () => {
  assert.deepEqual(priceFrom402({ accepts: [{ price: "$0.003" }] }), { usd: 0.003, atomic: "3000" });
});

test("no usable request → undefined (caller falls back to the generic message)", () => {
  assert.equal(requestFromAxios(undefined, challenge(base("1000"))), undefined);
  assert.equal(requestFromAxios({ url: "/dns/lookup", method: "get" }, challenge(base("1000"))), undefined); // not absolute https
  assert.equal(priceFrom402({}), undefined);
});

test("the text gives one exact call per wallet and never asks for a key in chat", () => {
  const r = requestFromAxios({ baseURL: BASE, url: "/classify", method: "post", data: JSON.stringify({ text: "hi", labels: ["a", "b"] }) }, challenge(base("5000")));
  const t = payHandoffText(r);
  assert.match(t, /costs \$0\.005/);
  assert.match(t, /AgentCash: call its `fetch` tool with \{"url":"https:\/\/netintel\.dev\/classify","method":"POST","body":"\{\\"text\\":\\"hi\\"/);
  assert.match(t, /npx awal@latest x402 pay 'https:\/\/netintel\.dev\/classify' -X POST -d '.+' --max-amount 5000/);
  assert.match(t, /initiate_x402_request` with \{"url":"https:\/\/netintel\.dev\/classify","method":"POST","body":\{"text":"hi","labels":\["a","b"\]\},"maxPayment":"0\.005"\}/);
  assert.match(t, /Never ask the user to paste a private key into the chat/);
});

test("the awal command survives a real shell, quotes and all", () => {
  const body = { text: "it's a \"test\" $HOME `x` ; rm -rf /" };
  const r = requestFromAxios({ baseURL: BASE, url: "/sentiment/analyze", method: "post", data: JSON.stringify(body) }, challenge(base("2000")));
  const line = payHandoffText(r).split("\n").find((l) => l.includes("npx awal@latest"));
  const cmd = line.slice(line.indexOf("npx awal@latest"));
  // Replace the program with printf so the shell only parses the arguments.
  const argv = execFileSync("bash", ["-c", `printf '%s\\n' ${cmd.replace(/^npx awal@latest x402 pay /, "")}`], { encoding: "utf8" }).split("\n");
  assert.equal(argv[0], "https://netintel.dev/sentiment/analyze");
  assert.deepEqual(argv.slice(1, 3), ["-X", "POST"]);
  assert.equal(argv[3], "-d");
  assert.deepEqual(JSON.parse(argv[4]), body);
});
