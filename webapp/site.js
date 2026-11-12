// The site page (index.html): in mock mode (`?mock=1` on a loopback host, remembered
// for the tab by api.js), its links into the app keep `?mock=1`, so following them
// never lands on a page that calls a server that is not there. The theme is the app's
// (theme.js: light unless the person chose otherwise), so the site and the app match.
import { isMockMode } from "./api.js";
import { initTheme } from "./theme.js";

initTheme();
if (isMockMode()) {
  for (const a of document.querySelectorAll("a[href$='.html']")) a.href = `${a.getAttribute("href")}?mock=1`;
}
