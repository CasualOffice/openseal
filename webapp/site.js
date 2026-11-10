// The site page (index.html): in mock mode (`?mock=1` on a loopback host, remembered
// for the tab by api.js), its links into the app keep `?mock=1`, so following them
// never lands on a page that calls a server that is not there.
import { isMockMode } from "./api.js";

if (isMockMode()) {
  for (const a of document.querySelectorAll("a[href$='.html']")) a.href = `${a.getAttribute("href")}?mock=1`;
}
