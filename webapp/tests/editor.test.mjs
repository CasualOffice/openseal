// The send editor's pure rules (WEB-09): signing steps with parallel groups (routing.js)
// and snapping guides (guides.js). Run: cd webapp && npm test
import test from "node:test";
import assert from "node:assert/strict";

import { compact, fromServer, groups, stepMove, canStep, moveGroup, joinGroup, newStepBefore, setOrder, byOrder, isAllAtOnce } from "../routing.js";
import { snapRect, touching, nextStop, bounds, intersects, fromCorners, stops } from "../guides.js";
import { suggestionsFrom } from "../detect.js";
import { FIELD_TYPES, FIELD_GROUPS, takesInput, requiredByDefault, validationFrom, optionsFrom } from "../geometry.js";
import { FIELD_TYPES_READY } from "../api.js";

// ---- signing steps ---------------------------------------------------------------------------
test("orders stay compact; the API's are read leniently", () => {
  assert.deepEqual(compact([5, 2, 2, 9]), [2, 1, 1, 3]);
  assert.deepEqual(fromServer([1, 0, null, 3, 3]), [1, 1, 1, 2, 2]);
  assert.deepEqual(groups([2, 1, 2, 3]), [{ order: 1, members: [1] }, { order: 2, members: [0, 2] }, { order: 3, members: [3] }]);
  assert.deepEqual(byOrder([2, 1, 2, 1]), [1, 3, 0, 2]);
});

test("a step move: alone it trades places with the next step; shared it leaves for a step of its own", () => {
  // A B C one after another: B up trades with A.
  assert.deepEqual(stepMove([1, 2, 3], 1, -1), [2, 1, 3]);
  // A down past the step {B C}.
  assert.deepEqual(stepMove([1, 2, 2], 0, 1), [2, 1, 1]);
  // C shares step 2 with B: up gives C a step of its own just before B's.
  assert.deepEqual(stepMove([1, 2, 2], 2, -1), [1, 3, 2]);
  // … and down, just after it.
  assert.deepEqual(stepMove([1, 2, 2], 1, 1), [1, 3, 2]);
  // At the ends alone, nothing moves, and the buttons say so.
  assert.deepEqual(stepMove([1, 2], 0, -1), [1, 2]);
  assert.deepEqual(stepMove([1, 2], 1, 1), [1, 2]);
  assert.equal(canStep([1, 2], 0, -1), false);
  assert.equal(canStep([1, 1], 0, -1), true);
  assert.equal(canStep([1, 2], 1, 1), false);
});

test("joining, a new step, a typed number and moving a whole step", () => {
  assert.deepEqual(joinGroup([1, 2, 3], 2, 1), [1, 2, 1]);
  assert.deepEqual(newStepBefore([1, 1, 2], 1, 1), [2, 1, 3]);
  assert.deepEqual(newStepBefore([1, 2], 0, 3), [2, 1], "after the last step");
  assert.deepEqual(setOrder([1, 2, 3], 2, 2), [1, 2, 2]);
  assert.deepEqual(setOrder([1, 2, 3], 0, 9), [3, 1, 2]);
  assert.deepEqual(setOrder([1, 2], 0, 0), [1, 2], "not a step number");
  assert.deepEqual(moveGroup([1, 2, 2, 3], 2, -1), [2, 1, 1, 3]);
  assert.deepEqual(moveGroup([1, 2], 2, 1), [1, 2], "no step after the last");
});

test("the switch is off only for signers all at once with copies after them", () => {
  const signer = (types) => (i) => types[i] === "signer";
  assert.equal(isAllAtOnce([1, 1, 2], signer(["signer", "signer", "cc"])), true);
  assert.equal(isAllAtOnce([1, 1, 1], signer(["signer", "signer", "cc"])), false);
  assert.equal(isAllAtOnce([1, 2], signer(["signer", "signer"])), false);
  assert.equal(isAllAtOnce([1], signer(["signer"])), false);
});

// ---- snapping guides ---------------------------------------------------------------------------
const page = { width: 612, height: 792 };

test("a moving field snaps its edges or centre to the page and to other fields, within tolerance", () => {
  const other = { key: "a", x: 100, y: 200, width: 160, height: 40 };
  // Left edge 3 points from the other's left edge: snaps, a vertical guide at 100.
  const r = snapRect({ x: 103, y: 400, width: 80, height: 20 }, [other], page, 4);
  assert.equal(r.rect.x, 100);
  assert.ok(r.guides.some((g) => g.axis === "x" && g.at === 100));
  // Centre to the page's centre.
  const c = snapRect({ x: 264, y: 50, width: 80, height: 20 }, [], page, 4);
  assert.equal(c.rect.x + c.rect.width / 2, 306);
  // Too far: nothing moves, no guide.
  const far = snapRect({ x: 120, y: 400, width: 80, height: 20 }, [other], page, 4);
  assert.deepEqual([far.rect.x, far.guides.filter((g) => g.axis === "x")], [120, []]);
  // Bottom edge to the other's top edge (fields stacked).
  const y = snapRect({ x: 300, y: 157, width: 80, height: 40 }, [other], page, 4);
  assert.equal(y.rect.y + y.rect.height, 200);
});

test("a resize snaps the moving corner only and keeps the top-left", () => {
  const other = { key: "a", x: 100, y: 200, width: 160, height: 40 };
  const r = snapRect({ x: 100, y: 300, width: 158, height: 30 }, [other], page, 4, "resize");
  assert.deepEqual([r.rect.x, r.rect.y, r.rect.width], [100, 300, 160]);
});

test("touching lists every guide a placed field lies on (keyboard moves show them)", () => {
  const other = { key: "a", x: 100, y: 200, width: 160, height: 40 };
  const g = touching({ x: 100, y: 240, width: 160, height: 20 }, [other], page);
  assert.ok(g.some((x) => x.axis === "x" && x.at === 100));
  assert.ok(g.some((x) => x.axis === "x" && x.at === 260));
  assert.ok(g.some((x) => x.axis === "y" && x.at === 240));
});

test("Alt+Shift+arrow goes to the next stop in that direction, then the page edge, then nowhere", () => {
  const other = { key: "a", x: 100, y: 200, width: 160, height: 40 };
  const r = { x: 300, y: 400, width: 80, height: 20 };
  // Going left from x=300, the first stop reached: its centre (340) on the page centre (306).
  const x = nextStop(r, [other], page, "x", -1);
  assert.equal(x, 266);
  assert.equal(nextStop({ ...r, x: 266 }, [other], page, "x", -1), 260, "then its left edge on the other's right edge");
  assert.equal(nextStop({ ...r, x: 0 }, [other], page, "x", -1), null);
  assert.equal(nextStop({ ...r, x: 532 }, [], page, "x", 1), null);
  assert.equal(nextStop({ ...r, x: 500 }, [], page, "x", 1), 532, "to the right page edge");
  assert.ok(stops([other], page, "y").some((s) => s.at === 220));
});

test("marquee helpers: corners in any order, what intersects, a group's box", () => {
  assert.deepEqual(fromCorners(50, 80, 10, 20), { x: 10, y: 20, width: 40, height: 60 });
  assert.equal(intersects({ x: 0, y: 0, width: 10, height: 10 }, { x: 9, y: 9, width: 5, height: 5 }), true);
  assert.equal(intersects({ x: 0, y: 0, width: 10, height: 10 }, { x: 10, y: 0, width: 5, height: 5 }), false);
  assert.deepEqual(bounds([{ x: 10, y: 20, width: 5, height: 5 }, { x: 0, y: 30, width: 50, height: 10 }]), { x: 0, y: 20, width: 50, height: 20 });
});

// ---- field detection ------------------------------------------------------------------------------
test("suggestions become ghost fields the editor can place, skipping ones on placed fields", () => {
  const docs = [{ key: "d1", id: "doc-1", pages: [{ width: 612, height: 792 }, { width: 612, height: 792 }] }];
  const placed = [{ docKey: "d1", page: 1, x: 70, y: 680, width: 160, height: 44 }];
  const items = [
    { document_id: "doc-1", type: "signature", page: 1, x: "72", y: "680", width: "180", height: "40", source: "underline", cue: "Signature", confidence: 82 },
    { document_id: "doc-1", type: "company", page: 2, x: "72", y: "100", width: "180", height: "22", source: "label", cue: "Company name", confidence: 70 },
    { document_id: "doc-1", type: "date_signed", page: 3, x: "72", y: "100", width: "120", height: "22", source: "label", confidence: 50 },
    { document_id: "other", type: "text", page: 1, x: "1", y: "1", width: "9", height: "9", source: "box", confidence: 10 },
    { document_id: "doc-1", type: "text", page: 2, x: "-4", y: "1", width: "9", height: "9", source: "box", confidence: 10 },
  ];
  const out = suggestionsFrom(items, docs, placed, () => "k");
  assert.equal(out.length, 1, "on a placed field, past the last page, another document, or unreadable: left out");
  // A company suggestion is a company field now the editor places that type (UX-05).
  assert.deepEqual([out[0].type, out[0].label, out[0].page, out[0].docKey], ["company", "Company name", 2, "d1"]);
  // A type the editor does not place becomes a text field labelled with its cue.
  const other = suggestionsFrom([{ document_id: "doc-1", type: "ssn", page: 2, x: "72", y: "300", width: "120", height: "22", cue: "SSN" }], docs, [], () => "k");
  assert.deepEqual([other[0].type, other[0].label], ["text", "SSN"]);
});

// ---- field kinds and properties (UX-05) -------------------------------------------------------
test("the palette places exactly the kinds the ceremony fills, each in one group", () => {
  assert.deepEqual([...FIELD_TYPES].sort(), [...FIELD_TYPES_READY].sort());
  assert.deepEqual(FIELD_GROUPS.flatMap(([, ts]) => ts).sort(), [...FIELD_TYPES].sort());
  assert.equal(takesInput("note"), false);
  assert.equal(takesInput("dropdown"), true);
  assert.equal(requiredByDefault("text"), true);
  assert.equal(requiredByDefault("checkbox"), false);
});

test("a validation preset becomes the engine's rule; settings not typed leave it out", () => {
  assert.equal(validationFrom(""), null);
  assert.deepEqual(validationFrom("email", { message: " Work email " }), { kind: "email", message: "Work email" });
  assert.deepEqual(validationFrom("number", { min: "1", max: "99.50", maxLength: "4" }), { kind: "number", min: "1", max: "99.50" });
  assert.deepEqual(validationFrom("number", { min: "one" }), { kind: "number" });
  assert.equal(validationFrom("regex", { pattern: "" }), null);
  assert.deepEqual(validationFrom("regex", { pattern: "^a$" }), { kind: "regex", pattern: "^a$" });
  assert.deepEqual(validationFrom("length", { maxLength: "12" }), { kind: "length", max: 12 });
  assert.equal(validationFrom("length", { maxLength: "-1" }), null);
  assert.equal(validationFrom("credit_card"), null);
});

test("options typed one per line: trimmed, blanks and repeats dropped, at most 500", () => {
  assert.deepEqual(optionsFrom(" Red\r\n\nGreen\nRed \nBlue"), ["Red", "Green", "Blue"]);
  assert.equal(optionsFrom(Array.from({ length: 600 }, (_, i) => `o${i}`).join("\n")).length, 500);
  assert.deepEqual(optionsFrom(""), []);
});
