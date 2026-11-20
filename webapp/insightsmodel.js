// Insights figures (FG-141, DocuSign's Insights). Pure: no DOM, so Node tests it. The
// server answers counts, percentiles, days and senders (`GET /insights`); this module
// turns them into what the dashboard draws: a gap-free series by day or by week, the
// completion rate, durations in a readable unit, and a chart scale.

const DAY = 86_400_000;
/// Longer than this many days, the series is drawn by week.
export const WEEKLY_AFTER = 92;
/// At most this many points are drawn (about two years by week).
export const MAX_POINTS = 120;

const ymd = (ms) => new Date(ms).toISOString().slice(0, 10);
const dayMs = (s) => Date.parse(`${s}T00:00:00Z`);

/// Completed as a whole percentage of sent; null when nothing was sent.
export function completionRate(totals) {
  const sent = Number(totals?.sent) || 0;
  if (!sent) return null;
  return Math.round(((Number(totals.completed) || 0) / sent) * 100);
}

/// A duration in seconds as `{n, unit}` for a message: minutes under an hour, hours
/// (one decimal) under two days, else days (one decimal). null stays null.
export function duration(seconds) {
  if (seconds == null || !Number.isFinite(Number(seconds)) || Number(seconds) < 0) return null;
  const s = Number(seconds);
  if (s < 3600) return { n: Math.max(1, Math.round(s / 60)), unit: "minutes" };
  if (s < 2 * 86_400) return { n: Math.round((s / 3600) * 10) / 10, unit: "hours" };
  return { n: Math.round((s / 86_400) * 10) / 10, unit: "days" };
}

/// The Monday (UTC date) of the week holding day `s` (`YYYY-MM-DD`).
export function weekOf(s) {
  const t = dayMs(s);
  const dow = (new Date(t).getUTCDay() + 6) % 7; // Monday 0
  return ymd(t - dow * DAY);
}

/// The series the chart draws: every day from `first` to `last` (`YYYY-MM-DD`, the
/// window's own days when given, else the days present), zeros where the server sent
/// none; by week (Monday first) when longer than `WEEKLY_AFTER` days. At most
/// `MAX_POINTS` points, the newest kept. `{unit: "day" | "week", points: [{day, sent,
/// completed}]}`.
export function series(days, { first = null, last = null } = {}) {
  const list = (days || []).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d?.day || ""));
  const byDay = new Map(list.map((d) => [d.day, { sent: Number(d.sent) || 0, completed: Number(d.completed) || 0 }]));
  const sorted = [...byDay.keys()].sort();
  const lo = first || sorted[0];
  const hi = last || sorted[sorted.length - 1];
  if (!lo || !hi || dayMs(hi) < dayMs(lo)) return { unit: "day", points: [] };
  const span = Math.round((dayMs(hi) - dayMs(lo)) / DAY) + 1;
  const weekly = span > WEEKLY_AFTER;
  const out = new Map();
  // Never walk more days than the points kept need (an open window can start in 1970).
  const keepDays = weekly ? MAX_POINTS * 7 : MAX_POINTS;
  const start = Math.max(dayMs(lo), dayMs(hi) - (keepDays - 1) * DAY);
  for (let t = start; t <= dayMs(hi); t += DAY) {
    const d = ymd(t);
    const key = weekly ? weekOf(d) : d;
    const v = byDay.get(d) || { sent: 0, completed: 0 };
    const p = out.get(key) || { day: key, sent: 0, completed: 0 };
    p.sent += v.sent;
    p.completed += v.completed;
    out.set(key, p);
  }
  return { unit: weekly ? "week" : "day", points: [...out.values()].slice(-MAX_POINTS) };
}

/// The window's first and last day as the series takes them: `{first, last}` from the
/// RFC 3339 bounds shifted by `offsetMinutes` (the caller's day), `last` the day before
/// `to` (exclusive) or today; an open `from` leaves `first` to the data.
export function windowDays({ from, to } = {}, offsetMinutes = 0, now = Date.now()) {
  const shift = offsetMinutes * 60_000;
  const first = from ? ymd(Date.parse(from) + shift) : null;
  const last = to ? ymd(Date.parse(to) + shift - 1) : ymd(now + shift);
  return { first, last };
}

/// A round axis maximum at or above `max` (1, 2, 5 × 10ⁿ), at least 1.
export function niceMax(max) {
  const m = Math.max(1, Number(max) || 0);
  const p = 10 ** Math.floor(Math.log10(m));
  for (const f of [1, 2, 5, 10]) if (f * p >= m) return f * p;
  return 10 * p;
}

/// The caller's offset from UTC in minutes, as the server takes it (east positive).
export const utcOffsetMinutes = (date = new Date()) => -date.getTimezoneOffset();

/// The series as CSV rows (one per day or week).
export function seriesCsvRows(s) {
  return (s?.points || []).map((p) => ({ [s.unit === "week" ? "week_of" : "day"]: p.day, sent: p.sent, completed: p.completed }));
}
