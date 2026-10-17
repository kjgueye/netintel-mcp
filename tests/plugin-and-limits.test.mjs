// Guards for the Claude Code plugin manifest and the spending-limit parser.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

const json = (p) => JSON.parse(readFileSync(new URL(`../${p}`, import.meta.url), "utf8"));
const pkg = json("package.json");
const plugin = json(".claude-plugin/plugin.json");
const market = json(".claude-plugin/marketplace.json");
const server = plugin.mcpServers.netintel;

test("the plugin is wallet-handoff only: no key prompt, and it forces an empty key", () => {
  // An empty EVM_PRIVATE_KEY in the plugin's env overrides any key in the user's
  // shell (measured 2026-10-17), so the plugin's server can never sign.
  assert.equal(server.env.EVM_PRIVATE_KEY, "");
  assert.equal(plugin.userConfig, undefined, "no userConfig: nothing to prompt for (Cowork ignores a server whose option has no default)");
  assert.doesNotMatch(JSON.stringify(plugin), /user_config/);
});

test("the launcher is pinned to the exact version in package.json (directory blocks unpinned npx)", () => {
  assert.equal(server.command, "npx");
  assert.deepEqual(server.args, ["-y", `netintel-mcp@${pkg.version}`]);
});

test("plugin and marketplace agree on the plugin version", () => {
  assert.equal(market.metadata.version, plugin.version);
  assert.equal(market.plugins[0].name, plugin.name);
});

const limitsWith = (env) =>
  JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e",
    "const c = await import('./dist/client.js'); console.log(JSON.stringify([c.MAX_PER_CALL_USD, c.MAX_SESSION_USD]))"],
  { cwd: new URL("..", import.meta.url), env: { ...process.env, ...env }, encoding: "utf8" }));

test("an empty or blank limit means the default, never $0", () => {
  assert.deepEqual(limitsWith({ NETINTEL_MAX_PER_CALL_USD: "", NETINTEL_MAX_SESSION_USD: "  " }), [0.25, 5]);
});

test("explicit limits still apply, including an explicit 0 and junk falling back", () => {
  assert.deepEqual(limitsWith({ NETINTEL_MAX_PER_CALL_USD: "0.05", NETINTEL_MAX_SESSION_USD: "0" }), [0.05, 0]);
  assert.deepEqual(limitsWith({ NETINTEL_MAX_PER_CALL_USD: "abc", NETINTEL_MAX_SESSION_USD: "-1" }), [0.25, 5]);
});
