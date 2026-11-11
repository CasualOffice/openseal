// Signing order with parallel groups (WEB-09; docs/47 §Send editor, DocuSign's "Set
// signing order"): each recipient has a routing order, and recipients who share one
// are a group that receives the envelope at the same time; the next group starts when
// every member of the one before has acted (docs/24 §4). Pure functions over an array
// of orders aligned with the recipients, so Node tests every rule.
//
// Orders are kept compact (1, 2, 3 … with no gaps): every function returns compact
// orders, which is what the API is sent.

/// The orders renumbered 1…k in the same relative order, gaps closed.
export function compact(orders) {
  const steps = [...new Set(orders)].sort((a, b) => a - b);
  const at = new Map(steps.map((o, i) => [o, i + 1]));
  return orders.map((o) => at.get(o));
}

/// Orders from routing orders as the API has them: anything not a positive integer
/// counts as 1, then compacted.
export function fromServer(orders) {
  return compact(orders.map((o) => (Number.isInteger(o) && o > 0 ? o : 1)));
}

/// The groups in order: `[{order, members: [index…]}]`, members in list order.
export function groups(orders) {
  const out = new Map();
  orders.forEach((o, i) => { if (!out.has(o)) out.set(o, []); out.get(o).push(i); });
  return [...out.entries()].sort((a, b) => a[0] - b[0]).map(([order, members]) => ({ order, members }));
}

/// Move recipient `i` one step earlier (`dir` -1) or later (+1): a recipient who shares
/// a step leaves it for a step of their own just before (after) it; one who is alone
/// trades places with the step before (after), whole. So "down" on A in {A}{B C} gives
/// {B C}{A}, and "up" on C in {B C} gives {C}{B}. Joining a step is the number box or a
/// drop on the group. At the first (last) step alone, nothing moves.
export function stepMove(orders, i, dir) {
  const o = orders[i];
  if (o === undefined || (dir !== -1 && dir !== 1)) return orders.slice();
  const shared = orders.filter((x) => x === o).length > 1;
  const max = Math.max(...orders);
  if (shared) {
    // Make room: every later step (and, going up, the rest of this one) moves back one.
    return compact(orders.map((x, j) => {
      if (j === i) return dir < 0 ? o : o + 1;
      if (dir < 0) return x >= o ? x + 1 : x;
      return x > o ? x + 1 : x;
    }));
  }
  if ((dir < 0 && o === 1) || (dir > 0 && o === max)) return orders.slice();
  return moveGroup(orders, o, dir);
}

/// Whether `stepMove(orders, i, dir)` would change anything.
export function canStep(orders, i, dir) {
  const o = orders[i];
  if (orders.filter((x) => x === o).length > 1) return true;
  return dir < 0 ? o > 1 : o < Math.max(...orders);
}

/// Swap the group at `order` with the one before (`dir` -1) or after (+1).
export function moveGroup(orders, order, dir) {
  const other = order + dir;
  if (!orders.includes(order) || !orders.includes(other)) return orders.slice();
  return orders.map((x) => (x === order ? other : x === other ? order : x));
}

/// Put recipient `i` in the group at `order` (joining it).
export function joinGroup(orders, i, order) {
  return compact(orders.map((x, j) => (j === i ? order : x)));
}

/// Give recipient `i` a step of its own just before the group at `order` (or after the
/// last group, when `order` is past it).
export function newStepBefore(orders, i, order) {
  return compact(orders.map((x, j) => (j === i ? order - 0.5 : x)));
}

/// Set recipient `i`'s order to `n` as typed (DocuSign's number box): a number that
/// another recipient has joins them; a larger one makes a new last step.
export function setOrder(orders, i, n) {
  if (!Number.isInteger(n) || n < 1) return orders.slice();
  return compact(orders.map((x, j) => (j === i ? n : x)));
}

/// The indices sorted by order, stable within a group: the list order the editor shows.
export function byOrder(orders) {
  return orders.map((o, i) => [o, i]).sort((a, b) => a[0] - b[0] || a[1] - b[1]).map(([, i]) => i);
}

/// Whether the orders mean "everyone at once" as the editor's switch draws it: more
/// than one signer, all at one step, and every other recipient after them.
export function isAllAtOnce(orders, isSigner) {
  const s = orders.filter((_, i) => isSigner(i));
  if (s.length < 2 || new Set(s).size !== 1) return false;
  return orders.every((o, i) => isSigner(i) || o > s[0]);
}
