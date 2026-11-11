// Runs before the page paints (a classic script, no inline code under the CSP): the
// remembered theme, and the `js` class that lets scroll reveals hide content only when
// a script will show it again. Same storage key as the web app (webapp/theme.js).
(function () {
  var root = document.documentElement;
  root.classList.add("js");
  try {
    var t = localStorage.getItem("openseal.theme");
    if (t === "light" || t === "dark") root.dataset.theme = t;
  } catch (e) { /* storage off: follow the OS */ }
})();
