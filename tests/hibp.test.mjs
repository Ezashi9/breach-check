import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { checkPassword, parseRange, sha1Hex, RANGE_URL } from "../docs/hibp.js";

const PASSWORD = "password123";
const FULL = createHash("sha1").update(PASSWORD).digest("hex").toUpperCase();

function fakeFetch(body, status = 200) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    return { ok: status === 200, status, text: async () => body };
  };
  fn.calls = calls;
  return fn;
}

test("browser hashing matches SHA-1", async () => {
  assert.equal(await sha1Hex(PASSWORD), FULL);
  assert.equal(await sha1Hex("pässwörd"), createHash("sha1").update("pässwörd", "utf8").digest("hex").toUpperCase());
});

test("only the 5-character prefix is sent, with padding requested", async () => {
  const fetch = fakeFetch("");
  await checkPassword(PASSWORD, fetch);
  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0].url, RANGE_URL + FULL.slice(0, 5));
  assert.ok(!fetch.calls[0].url.includes(PASSWORD));
  assert.ok(!fetch.calls[0].url.includes(FULL.slice(5)), "suffix must never be sent");
  assert.equal(fetch.calls[0].opts.headers["Add-Padding"], "true");
});

test("finds a breached password and counts decoys", async () => {
  const body = `${FULL.slice(5)}:2266543\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\nBBB:4\r\n`;
  const r = await checkPassword(PASSWORD, fakeFetch(body));
  assert.equal(r.count, 2266543);
  assert.equal(r.hashesReturned, 3);
  assert.equal(r.decoys, 1);
  assert.equal(r.keptLocally, 35);
});

test("padding decoy with the real suffix does not count as a breach", async () => {
  const r = await checkPassword(PASSWORD, fakeFetch(`${FULL.slice(5)}:0\n`));
  assert.equal(r.count, 0);
});

test("API errors are reported, not treated as 'not found'", async () => {
  await assert.rejects(checkPassword(PASSWORD, fakeFetch("", 503)), /HTTP 503/);
});

test("parseRange ignores blank lines", () => {
  const { total, counts } = parseRange("\nABC:1\n\n");
  assert.equal(total, 1);
  assert.equal(counts.get("ABC"), 1);
});

test("page security: strict CSP, single allowed server, no HTML injection sinks", () => {
  const html = readFileSync(new URL("../docs/index.html", import.meta.url), "utf8");
  const csp = html.match(/Content-Security-Policy"\s+content="([^"]+)"/)[1];
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /connect-src https:\/\/api\.pwnedpasswords\.com;/);
  assert.match(csp, /form-action 'none'/);
  assert.doesNotMatch(csp, /unsafe-inline/);
  for (const file of ["app.js", "hibp.js"]) {
    const src = readFileSync(new URL(`../docs/${file}`, import.meta.url), "utf8");
    for (const sink of ["innerHTML", "localStorage", "sessionStorage", "document.cookie", "console.log"]) {
      assert.ok(!src.includes(sink), `${file} must not use ${sink}`);
    }
  }
});
