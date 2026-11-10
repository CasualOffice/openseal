// Light, dark, or the system's choice (WEB-01). The choice is a per-browser
// convenience in localStorage; without storage the app follows the system.

const KEY = "openseal.theme";

export function getTheme() {
  try { return localStorage.getItem(KEY) || "system"; } catch { return "system"; }
}

function apply(theme) {
  const root = document.documentElement;
  if (theme === "light" || theme === "dark") root.dataset.theme = theme;
  else delete root.dataset.theme;
}

export function setTheme(theme) {
  try {
    if (theme === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch { /* storage off: this page only */ }
  apply(theme);
}

/// Flip between light and dark from whatever is showing now.
export function toggleTheme() {
  const cur = getTheme();
  const dark = cur === "dark" || (cur === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  setTheme(dark ? "light" : "dark");
}

export function initTheme() {
  apply(getTheme());
}
