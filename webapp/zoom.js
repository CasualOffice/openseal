// Zoom for the signing page on phones (WEB-03): pinch and buttons scale the pages,
// and the field in use grows to a usable size. Pure: no DOM, so Node tests it.

export const MIN_ZOOM = 0.75;
export const MAX_ZOOM = 3;
export const ZOOM_STEP = 1.25;

/// `z` kept between MIN_ZOOM and MAX_ZOOM, rounded to 2 places (so repeated steps
/// land on the same values); a non-number is 1.
export function clampZoom(z) {
  if (!Number.isFinite(z)) return 1;
  return Math.round(Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, z)) * 100) / 100;
}

/// The zoom after a pinch: the zoom at its start times how far the fingers spread.
export function pinchZoom(startZoom, startDistance, distance) {
  if (!(startDistance > 0) || !(distance > 0)) return clampZoom(startZoom);
  return clampZoom(startZoom * (distance / startDistance));
}

/// Distance between two pointers `{x, y}`.
export function distance(a, b) {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

/// How much a field of `width`×`height` CSS px grows while in use on a phone: enough
/// for a 44 px tall target (WCAG 2.5.5) and 16 px text, never wider than `room` px
/// (the screen less its margins), never smaller than it is.
export function enlargeFor(width, height, room, target = 44) {
  if (!(width > 0) || !(height > 0)) return 1;
  const want = target / height;
  const fits = room > 0 ? room / width : want;
  return Math.round(Math.max(1, Math.min(want, fits, 4)) * 100) / 100;
}
