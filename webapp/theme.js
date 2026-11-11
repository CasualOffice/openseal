// Light, dark, or the system's choice (WEB-01). Light is the default, as in the
// products OpenSeal follows (WEB-02); the choice is a per-browser convenience in
// localStorage, and without storage the app is light.

const KEY = "openseal.theme";

export function getTheme() {
  try { return localStorage.getItem(KEY) || "light"; } catch { return "light"; }
}

function apply(theme) {
  const root = document.documentElement;
  if (theme === "system") delete root.dataset.theme;
  else root.dataset.theme = theme === "dark" ? "dark" : "light";
}

export function setTheme(theme) {
  try {
    localStorage.setItem(KEY, theme);
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
