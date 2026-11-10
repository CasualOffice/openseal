// Files handed from one screen to another within the page (WEB-02): the Home drop
// zone passes the PDFs it was given to the send editor, which takes them once. Held in
// memory only; a reload drops them.

let pending = null;

/// Leave `files` for the next screen that asks.
export function handFiles(files) {
  pending = files && files.length ? [...files] : null;
}

/// The files left, once; null when there are none.
export function takeFiles() {
  const f = pending;
  pending = null;
  return f;
}
