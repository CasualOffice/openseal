// Admin's list of websites that may embed the workspace's views (VS-09): the
// `embedding_origins` setting as the server checks it (`casual-sign-server`
// `src/embed.rs` `origin`), so the form says what is wrong before saving. Pure; tests
// run it under Node.

/// At most this many websites (the server's `MAX_ORIGINS`).
export const MAX_ORIGINS = 20;

/// Whether `host` (lower case, no port, IPv6 in brackets) is a private-network host, for
/// which plain `http` is taken (owner instruction 81; the server's `private_host`): a
/// loopback, RFC 1918, link-local or IPv6 unique-local address, `localhost`, a
/// single-label name, or a name under `.local`, `.internal`, `.lan`, `.localhost`, `.test`.
export function privateHost(host) {
  const v6 = /^\[([0-9a-f:]+)\]$/.exec(host);
  if (v6) {
    const a = v6[1];
    if (a === "::1") return true;
    const first = a.startsWith("::") ? 0 : Number.parseInt(a.split(":")[0], 16);
    return Number.isFinite(first) && ((first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80);
  }
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (v4.slice(1).some((x) => Number(x) > 255)) return false;
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  if (/^[\d.]+$/.test(host)) return false;
  return !host.includes(".") || [".local", ".internal", ".lan", ".localhost", ".test"].some((t) => host.endsWith(t));
}

/// The origin `s` names as a browser compares it (`scheme://host[:port]`, lower case, no
/// default port), or null: a path, query, fragment, user name or wildcard; a scheme
/// other than `https`, or `http` but to a public host.
export function normalOrigin(s) {
  if (typeof s !== "string") return null;
  const v = s.trim();
  if (!v || v.length > 255) return null;
  const m = /^(https?):\/\/(\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::(\d{1,5}))?$/i.exec(v);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  const host = m[2].toLowerCase();
  const port = m[3] || "";
  if (port && (Number(port) < 1 || Number(port) > 65535)) return null;
  if (scheme === "http" && !privateHost(host)) return null;
  const dflt = (scheme === "https" && port === "443") || (scheme === "http" && port === "80");
  return `${scheme}://${host}${port && !dflt ? `:${port}` : ""}`;
}

/// The setting from a textarea (one website per line, blank lines skipped, duplicates
/// once): `{origins}`, or `{bad}` naming the first line it cannot take, or `{tooMany}`.
export function parseOrigins(text) {
  const origins = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    const o = normalOrigin(line);
    if (!o) return { bad: line.trim() };
    if (!origins.includes(o)) origins.push(o);
  }
  if (origins.length > MAX_ORIGINS) return { tooMany: MAX_ORIGINS };
  return { origins };
}
