// Admin's list of websites that may embed the workspace's views (VS-09): the
// `embedding_origins` setting as the server checks it (`casual-sign-server`
// `src/embed.rs` `origin`), so the form says what is wrong before saving. Pure; tests
// run it under Node.

/// At most this many websites (the server's `MAX_ORIGINS`).
export const MAX_ORIGINS = 20;

const DEV = (host) => host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host.endsWith(".localhost") || host.endsWith(".test");

/// The origin `s` names as a browser compares it (`scheme://host[:port]`, lower case, no
/// default port), or null: a path, query, fragment, user name or wildcard; a scheme
/// other than `https`, or `http` but to a development host.
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
  if (scheme === "http" && !DEV(host)) return null;
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
