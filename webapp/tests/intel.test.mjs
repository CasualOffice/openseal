// WEB-18: the rules behind Admin › Document intelligence (intelmodel.js).
import { test } from "node:test";
import assert from "node:assert/strict";

import { FEATURES, SETTING_KEYS, pageState, notInPlan, cards, onCount, withSetting, sizeText, shortHash, modelRows, cardModel, packChips } from "../intelmodel.js";

const ALL_ON = { ocr: true, template_matching: true, extraction: true, personal_data: true };

test("the canvas's five cards, four of them settings the page may change", () => {
  assert.deepEqual(FEATURES.map((f) => f.id), ["ocr", "detect", "templates", "extract", "pii"]);
  assert.deepEqual(SETTING_KEYS, ["ocr", "template_matching", "extraction", "personal_data"]);
});

test("a server without models, or one that does not serve the settings, is 'not installed'", () => {
  assert.equal(pageState({ error: { status: 404, code: "CS-API-0002" } }).kind, "not-installed");
  assert.equal(pageState({ error: { status: 0, code: "CS-NET-0002" } }).kind, "not-installed");
  assert.equal(pageState({ settings: { ...ALL_ON, installed: false } }).kind, "not-installed");
});

test("the plan refusing ML disables every card with 'not in your plan'", () => {
  const st = pageState({ error: { status: 403, code: "CS-ML-0011" } });
  assert.equal(st.kind, "no-plan");
  const list = cards(st);
  assert.ok(list.every((c) => c.disabled && c.reason === "plan" && !c.on));
  assert.equal(onCount(list), 0);
});

test("another refusal is 'forbidden'; a server error offers a retry", () => {
  assert.equal(pageState({ error: { status: 403, code: "CS-AUTH-0006" } }).kind, "forbidden");
  assert.equal(pageState({ error: { status: 500, code: "CS-API-0500" } }).kind, "error");
});

test("cards follow the settings; Detect fields follows Read scanned pages and has no switch of its own", () => {
  const st = pageState({ settings: { ...ALL_ON, personal_data: false } });
  const list = cards(st);
  assert.deepEqual(list.map((c) => c.on), [true, true, true, true, false]);
  assert.equal(onCount(list), 4);
  const detect = list.find((c) => c.id === "detect");
  assert.equal(detect.disabled, true);
  assert.equal(detect.reason, "follows");
  assert.equal(detect.key, null);
  const off = cards(pageState({ settings: { ...ALL_ON, ocr: false } }));
  assert.equal(off.find((c) => c.id === "detect").on, false);
  assert.equal(onCount(off), 3);
});

test("a feature the plan lacks is off and disabled even if the stored setting says on", () => {
  const st = pageState({ settings: { ...ALL_ON, not_in_plan: ["extraction", "bogus"] } });
  assert.deepEqual(notInPlan(st), ["extraction"]);
  const ex = cards(st).find((c) => c.id === "extract");
  assert.deepEqual([ex.on, ex.disabled, ex.reason], [false, true, "plan"]);
});

test("withSetting changes one key, copies, and refuses a key the page does not own", () => {
  const s = { ...ALL_ON };
  const out = withSetting(s, "personal_data", false);
  assert.equal(out.personal_data, false);
  assert.equal(s.personal_data, true);
  assert.throws(() => withSetting(s, "reread_scanner_text", true));
  assert.throws(() => withSetting(s, "detect", true));
});

test("sizes and hashes as the canvas writes them", () => {
  assert.equal(sizeText(30_000_000), "30 MB");
  assert.equal(sizeText(700_000_000), "700 MB");
  assert.equal(sizeText(1_480_000_000), "1.5 GB");
  assert.equal(sizeText(512_000), "512 KB");
  assert.equal(sizeText(null), "");
  assert.equal(shortHash("9c41" + "0".repeat(56) + "e07a"), "9c41…e07a");
  assert.equal(shortHash("pending"), null);
  assert.equal(shortHash("9C41" + "0".repeat(56) + "E07A"), "9c41…e07a");
});

test("model rows: dropped without an id, unknown status reads failed, name falls back to the id", () => {
  const rows = modelRows({ models: [
    { id: "e5-small", name: "multilingual-e5-small", profile: "templates", status: "ready", licence: "MIT", bytes: 470e6, sha256: "1f8b" + "a".repeat(56) + "44d2" },
    { id: "arabic", status: "installing", licence: "Apache-2.0", bytes: 11e6 },
    { id: "", status: "ready" },
    { id: "odd", status: "exploded" },
    null,
  ] });
  assert.deepEqual(rows.map((r) => [r.id, r.name, r.status, r.hash]), [
    ["e5-small", "multilingual-e5-small", "ready", "1f8b…44d2"],
    ["arabic", "arabic", "installing", null],
    ["odd", "odd", "failed", null],
  ]);
  assert.deepEqual(modelRows({}), []);
  assert.deepEqual(cardModel("templates", rows), { name: "multilingual-e5-small", status: null });
  assert.deepEqual(cardModel("extract", rows), { name: "gliner_multi-v2.1", status: null });
  assert.deepEqual(cardModel("detect", rows), { name: "rules + OCR", status: null });
  // A listed model that is not ready is said on its card.
  const busy = modelRows({ models: [{ id: "g", profile: "extraction", status: "installing" }] });
  assert.deepEqual(cardModel("extract", busy), { name: "gliner_multi-v2.1", status: "installing" });
});

test("OCR script chips: installed together, then each installing pack, then each missing one", () => {
  const chips = packChips({ ocr_packs: [
    { script: "latin", state: "installed" }, { script: "cjk", state: "installed" },
    { script: "arabic", state: "installing" }, { script: "devanagari", state: "missing" }, { script: "x", state: "weird" },
  ] });
  assert.deepEqual(chips, [
    { state: "installed", scripts: ["latin", "cjk"] },
    { state: "installing", scripts: ["arabic"] },
    { state: "missing", scripts: ["devanagari"] },
  ]);
  // Without the packs member, the chosen scripts count as installed.
  assert.deepEqual(packChips({ ocr_scripts: ["latin"] }), [{ state: "installed", scripts: ["latin"] }]);
  assert.deepEqual(packChips({}), []);
});
