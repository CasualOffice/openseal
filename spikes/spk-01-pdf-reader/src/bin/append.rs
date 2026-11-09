//! `append <fixtures-dir> <outdir>`: item 3 of SPK-01. Append one incremental update
//! (a new object, plus a changed catalog for lopdf) with each library and check:
//! byte-prefix equality with the original, the new xref section's form against the
//! original's, `/Prev` pointing at the original `startxref`, determinism (two saves equal),
//! and that every reader (lopdf strict, pdf, our sketch) re-opens the result.

use lopdf::{dictionary, Object};
use std::path::Path;

fn startxref(b: &[u8]) -> Option<i64> {
    let i = b.windows(9).rposition(|w| w == b"startxref")?;
    let s: String = b[i + 9..].iter().skip_while(|c| c.is_ascii_whitespace()).take_while(|c| c.is_ascii_digit()).map(|c| *c as char).collect();
    s.parse().ok()
}

fn form(b: &[u8]) -> &'static str {
    let off = startxref(b).unwrap_or(0) as usize;
    match b.get(off..off + 4) {
        Some(b"xref") => "table",
        Some(_) => "stream",
        None => "bad startxref",
    }
}

fn prev_of_last(b: &[u8]) -> Option<i64> {
    let i = b.windows(5).rposition(|w| w == b"/Prev")?;
    let s: String = b[i + 5..].iter().skip_while(|c| c.is_ascii_whitespace()).take_while(|c| c.is_ascii_digit()).map(|c| *c as char).collect();
    s.parse().ok()
}

fn lopdf_update(orig: &[u8]) -> Result<Vec<u8>, String> {
    let doc = lopdf::Document::load_mem(orig).map_err(|e| e.to_string())?;
    let mut inc = lopdf::IncrementalDocument::create_from(orig.to_vec(), doc);
    let note = inc.new_document.add_object(dictionary! { "Type" => "Annot", "Subtype" => "Text", "Contents" => Object::string_literal("spike") });
    let root = inc.get_prev_documents().trailer.get(b"Root").and_then(Object::as_reference).map_err(|e| e.to_string())?;
    inc.opt_clone_object_to_new_document(root).map_err(|e| e.to_string())?;
    inc.new_document.get_object_mut(root).and_then(Object::as_dict_mut).map_err(|e| e.to_string())?.set("SpikeNote", Object::Reference(note));
    let mut out = Vec::new();
    inc.save_to(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn pdf_update(orig: &[u8]) -> Result<Vec<u8>, String> {
    use pdf::object::Updater;
    let mut file = pdf::file::FileOptions::uncached().load(orig.to_vec()).map_err(|e| e.to_string())?;
    file.create(pdf::primitive::Primitive::Integer(42)).map_err(|e| e.to_string())?;
    file.storage.save(&mut file.trailer).map_err(|e| e.to_string())?;
    Ok(file.storage.into_inner())
}

/// pdf-rs errors embed the build machine's source paths; keep the crate-relative tail.
fn clean(e: String) -> String {
    let e = match e.rfind("/registry/src/") {
        Some(i) => e[i + 14..].split_once('/').map(|(_, t)| t.to_string()).unwrap_or_default(),
        None => e,
    };
    e.replace('\n', " ").chars().take(90).collect()
}

fn check(name: &str, orig: &[u8], out: Result<Vec<u8>, String>, again: Result<Vec<u8>, String>, dir: &Path) {
    let out = match out {
        Ok(o) => o,
        Err(e) => return println!("| {name} | error: {} | | | | | |", clean(e)),
    };
    let tail = &out[orig.len().min(out.len())..];
    let header_again = tail.windows(5).any(|w| w == b"%PDF-");
    let lopdf_ok = lopdf::Document::load_mem_with_options(&out, lopdf::LoadOptions { strict: true, ..Default::default() })
        .map(|d| format!("{} pages, SpikeNote={}", d.get_pages().len(), d.catalog().map(|c| c.has(b"SpikeNote")).unwrap_or(false)))
        .unwrap_or_else(|e| format!("ERR {e}"));
    let pdf_ok = pdf::file::FileOptions::uncached().load(out.clone()).map(|f| format!("{} pages", f.pages().filter(|p| p.is_ok()).count())).unwrap_or_else(|e| format!("ERR {}", clean(e.to_string())));
    let own_ok = spk01_own::Reader::open(&out, spk01_own::Limits::default()).and_then(|r| Ok(format!("{} pages, recovered={}", r.page_count()?, r.recovered))).unwrap_or_else(|e| format!("ERR {e:?}"));
    println!(
        "| {name} | prefix={} appended={}B | orig {} / new {} | /Prev={:?} (orig startxref {:?}) | 2nd %PDF header: {header_again} | deterministic={} | lopdf-strict: {lopdf_ok}; pdf: {pdf_ok}; own: {own_ok} |",
        out.starts_with(orig), tail.len(), form(orig), form(&out), prev_of_last(tail), startxref(orig), again.map(|a| a == out).unwrap_or(false)
    );
    let _ = std::fs::write(dir.join(format!("{name}.pdf")), &out);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = Path::new(&args[2]);
    std::fs::create_dir_all(dir).expect("outdir");
    println!("| Case | Prefix kept | xref form | /Prev | Header | Deterministic | Re-open |");
    println!("| --- | --- | --- | --- | --- | --- | --- |");
    for input in ["valid.pdf", "valid_xrefstream.pdf", "broken_xref_offsets.pdf"] {
        let orig = std::fs::read(Path::new(&args[1]).join(input)).expect("fixture");
        let stem = input.trim_end_matches(".pdf");
        check(&format!("lopdf-{stem}"), &orig, lopdf_update(&orig), lopdf_update(&orig), dir);
        check(&format!("pdf-{stem}"), &orig, pdf_update(&orig), pdf_update(&orig), dir);
    }
}
