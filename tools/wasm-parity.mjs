// WASM parity (`WASM-01`, Phase 1 exit item 6): the WebAssembly build of casual-sign-wasm
// must give byte-identical canonical JSON to the native build, for every job.
//
//   node tools/wasm-parity.mjs --pkg DIR --parity-pkg DIR --native BIN [--corpus DIR] [--out DIR]
//
// --pkg         wasm-pack `--target web` output of the shipped module (no features)
// --parity-pkg  the same with `--features parity` (adds parity_cases); runs the case table
// --native      the native_parity example binary (crates/casual-sign-wasm/examples)
// --corpus      the real-file corpus (fixtures/corpus/files); skipped when absent
// --out         where differences are written (default target/wasm-parity/diff)
//
// Jobs: every PDF of fixtures/signed, fixtures/sealed, fixtures/hostile and the corpus
// through admit, extract_text, place_anchor and verify; every envelope of
// crates/casual-sign-wasm/parity/envelopes.json through evaluate_envelope; and the
// 225-case field-rule table (parity_cases), which must also equal
// crates/casual-sign-fields/tests/parity/expected.txt. Native answers come back as
// SHA-256 and length; on a difference the native answer is fetched whole and the first
// differing byte is shown. Exits 1 on any difference, 2 on a usage or setup problem.
// `tools/wasm-parity.sh` builds the modules and the binary and runs this.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = resolve(import.meta.dirname, "..");
const VALIDATION_AT = 1_796_083_200; // 2026-12-01T00:00:00Z, as fixtures/signed/gen.py
const ANCHORS = JSON.stringify([
  { text: "the" },
  { text: "Signature", case_sensitive: true, whole_word: true, offset_x: "5.5", offset_y: "-2",
    units: "millimetres", width: "120.25", height: "18" },
  { text: "date", matching: "first", units: "pixels", offset_x: "10" },
  { text: "Agreement", units: "inches", offset_y: "0.5", width: "33.3333" },
  { text: "zz-not-in-any-file-zz", ignore_if_absent: true },
  { text: "zz-not-in-any-file-zz" },
]);

function die(msg) {
  console.error(`wasm-parity: ${msg}`);
  process.exit(2);
}

function args() {
  const a = { out: join(ROOT, "target/wasm-parity/diff") };
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i].replace(/^--/, "").replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (argv[i + 1] === undefined) die(`${argv[i]} needs a value`);
    a[k] = resolve(argv[i + 1]);
  }
  for (const k of ["pkg", "parityPkg", "native"]) if (!a[k]) die(`--${k} is required`);
  return a;
}

function pdfs(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((n) => n.toLowerCase().endsWith(".pdf"))
    .sort()
    .map((n) => join(dir, n))
    .filter((p) => statSync(p).isFile());
}

function trust(rootDer) {
  const t = { validation_time: VALIDATION_AT };
  if (rootDer) t.anchors = [readFileSync(rootDer).toString("base64")];
  return JSON.stringify(t);
}

function jobs(a) {
  const out = [];
  const groups = [
    ["signed", pdfs(join(ROOT, "fixtures/signed")), join(ROOT, "fixtures/signed/trust-root.der")],
    ["sealed", pdfs(join(ROOT, "fixtures/sealed")), join(ROOT, "fixtures/sealed/trust-root.der")],
    ["hostile", pdfs(join(ROOT, "fixtures/hostile")), null],
    ["corpus", a.corpus ? pdfs(a.corpus) : [], null],
  ];
  for (const [group, files, root] of groups) {
    const t = trust(root);
    for (const file of files) {
      const id = `${group}/${basename(file)}`;
      out.push({ id: `${id}#admit`, group, fn: "admit", file });
      out.push({ id: `${id}#extract_text`, group, fn: "extract_text", file });
      out.push({ id: `${id}#place_anchor`, group, fn: "place_anchor", file, anchors: ANCHORS });
      out.push({ id: `${id}#verify`, group, fn: "verify", file, trust: t });
    }
  }
  const envelopes = JSON.parse(readFileSync(join(ROOT, "crates/casual-sign-wasm/parity/envelopes.json"), "utf8"));
  for (const e of envelopes) {
    out.push({ id: `envelopes/${e.name}#evaluate_envelope`, group: "envelopes", fn: "evaluate_envelope",
      fields: JSON.stringify(e.fields), values: JSON.stringify(e.values) });
  }
  out.push({ id: "table#parity_cases", group: "table", fn: "parity_cases" });
  return out;
}

let generation = 0;
async function load(pkg) {
  // A fresh module instance (new glue state, new memory) on every call: after a trap the
  // old instance must not be reused.
  const glue = await import(`${pathToFileURL(join(pkg, "casual_sign_wasm.js"))}?g=${generation++}`);
  glue.initSync({ module: readFileSync(join(pkg, "casual_sign_wasm_bg.wasm")) });
  return glue;
}

function call(m, job) {
  const read = () => readFileSync(job.file);
  switch (job.fn) {
    case "admit": return m.admit(read());
    case "extract_text": return m.extract_text(read());
    case "place_anchor": return m.place_anchor(read(), job.anchors);
    case "verify": return m.verify(read(), job.trust);
    case "evaluate_envelope": return m.evaluate_envelope(job.fields, job.values);
    case "parity_cases": return m.parity_cases();
    default: throw new Error(`unknown fn ${job.fn}`);
  }
}

function digest(s) {
  const b = Buffer.from(s, "utf8");
  return { len: b.length, sha256: createHash("sha256").update(b).digest("hex"), bytes: b };
}

function nativeDump(a, jobFile, id) {
  const r = spawnSync(a.native, [jobFile, "--dump", id], { maxBuffer: 2 ** 31 - 1 });
  return r.status === 0 ? r.stdout : Buffer.from(`native failed: ${r.stderr}`);
}

function firstDifference(x, y) {
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return i;
  return x.length === y.length ? -1 : n;
}

async function main() {
  const a = args();
  const all = jobs(a);
  mkdirSync(a.out, { recursive: true });
  const jobFile = join(a.out, "..", "jobs.json");
  writeFileSync(jobFile, JSON.stringify(all));

  const t0 = performance.now();
  const r = spawnSync(a.native, [jobFile], { maxBuffer: 2 ** 31 - 1, encoding: "utf8" });
  if (r.status !== 0) die(`native harness failed (${r.status}): ${r.stderr.slice(-2000)}`);
  const native = new Map(r.stdout.trim().split("\n").map((l) => JSON.parse(l)).map((x) => [x.id, x]));
  const tNative = performance.now() - t0;

  let shipped = await load(a.pkg);
  let parity = await load(a.parityPkg);
  const counts = {};
  const differences = [];
  const t1 = performance.now();
  for (const job of all) {
    const c = (counts[`${job.group} ${job.fn}`] ??= { jobs: 0, identical: 0, different: 0 });
    c.jobs++;
    let answer;
    try {
      answer = call(job.fn === "parity_cases" ? parity : shipped, job);
    } catch (e) {
      answer = `wasm threw: ${e && e.message}`;
      if (job.fn === "parity_cases") parity = await load(a.parityPkg);
      else shipped = await load(a.pkg);
    }
    const w = digest(answer);
    const n = native.get(job.id);
    let same = n && n.len === w.len && n.sha256 === w.sha256;
    let why = n ? "" : "no native answer";
    if (same && job.fn === "parity_cases") {
      const want = readFileSync(join(ROOT, "crates/casual-sign-fields/tests/parity/expected.txt"), "utf8")
        .replace(/\r\n/g, "\n");
      if (answer !== want) {
        same = false;
        why = "native and WASM agree but differ from expected.txt";
      }
      c.cases = answer.split("\n").filter((l) => l).length;
    }
    if (same) {
      c.identical++;
      continue;
    }
    c.different++;
    const nb = nativeDump(a, jobFile, job.id);
    const at = firstDifference(nb, w.bytes);
    const safe = job.id.replace(/[^A-Za-z0-9._#-]/g, "_");
    writeFileSync(join(a.out, `${safe}.native.json`), nb);
    writeFileSync(join(a.out, `${safe}.wasm.json`), w.bytes);
    const ctx = (b) => b.subarray(Math.max(0, at - 60), at + 60).toString("utf8");
    differences.push({ id: job.id, why, at, native: ctx(nb), wasm: ctx(w.bytes) });
  }
  const tWasm = performance.now() - t1;

  const wasmBytes = readFileSync(join(a.pkg, "casual_sign_wasm_bg.wasm"));
  const { gzipSync } = await import("node:zlib");
  console.log("group\tfn\tjobs\tidentical\tdifferent");
  for (const [k, c] of Object.entries(counts)) {
    const [group, fn] = k.split(" ");
    console.log(`${group}\t${fn}\t${c.jobs}\t${c.identical}\t${c.different}${c.cases ? `\t(${c.cases} cases)` : ""}`);
  }
  const total = Object.values(counts).reduce((s, c) => ({ jobs: s.jobs + c.jobs, identical: s.identical + c.identical,
    different: s.different + c.different }), { jobs: 0, identical: 0, different: 0 });
  const files = new Set(all.filter((j) => j.file).map((j) => j.file)).size;
  console.log(`\n${files} PDFs, ${total.jobs} jobs: ${total.identical} identical, ${total.different} different`);
  console.log(`module: ${wasmBytes.length} bytes, ${gzipSync(wasmBytes, { level: 9 }).length} gzipped`);
  console.log(`time: native ${(tNative / 1000).toFixed(1)} s, wasm ${(tWasm / 1000).toFixed(1)} s`);
  for (const d of differences) {
    console.error(`\nDIFFERENT ${d.id}${d.why ? ` (${d.why})` : ""} at byte ${d.at}`);
    console.error(`  native: ${JSON.stringify(d.native)}`);
    console.error(`  wasm:   ${JSON.stringify(d.wasm)}`);
  }
  if (differences.length) {
    console.error(`\nwasm-parity: ${differences.length} differences; both answers are in ${a.out}`);
    process.exit(1);
  }
  if (!counts["table parity_cases"] || counts["table parity_cases"].cases < 225) die("the case table did not run");
  console.log("wasm-parity: native and WASM agree byte for byte");
}

await main();
