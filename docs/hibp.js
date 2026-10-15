export const RANGE_URL = "https://api.pwnedpasswords.com/range/";
export const PREFIX_LEN = 5;

export async function sha1Hex(text) {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export function parseRange(body) {
  const counts = new Map();
  let total = 0;
  let decoys = 0;
  for (const raw of body.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    total += 1;
    const [suffix, count] = line.split(":");
    const n = Number.parseInt(count, 10);
    if (n > 0) counts.set(suffix.toUpperCase(), n);
    else decoys += 1;
  }
  return { counts, total, decoys };
}

export async function checkPassword(password, fetchFn = fetch) {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, PREFIX_LEN);
  const suffix = hash.slice(PREFIX_LEN);
  // Add-Padding mixes zero-count decoys into the reply so its size can't reveal the prefix.
  const res = await fetchFn(RANGE_URL + prefix, {
    headers: { "Add-Padding": "true" },
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  if (!res.ok) throw new Error(`Have I Been Pwned returned HTTP ${res.status}`);
  const { counts, total, decoys } = parseRange(await res.text());
  return { count: counts.get(suffix) ?? 0, prefix, keptLocally: suffix.length, hashesReturned: total, decoys };
}
