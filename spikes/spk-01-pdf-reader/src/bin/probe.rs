//! `probe <lopdf|pdf|own> <file>`: parse, count pages, then decode every page's content
//! stream (what flattening and anchor search will do). Prints one line:
//! `OK pages=N decoded=B ms=T heap=H` or `ERR <first 160 chars of the error> ms=T heap=H`.
//! A panic is caught and printed as `PANIC <msg>`; the harness sees aborts and stack
//! overflows by signal.

use spk01_pdf_reader::{peak_heap, Capped};
use std::time::Instant;

#[global_allocator]
static A: Capped = Capped;

/// Per-stream decode bound handed to libraries that accept one (docs/21: 256 MiB).
const STREAM_CAP: usize = 256 << 20;

fn lopdf_run(bytes: &[u8], strict: bool) -> Result<(usize, usize, String), String> {
    let opts = lopdf::LoadOptions { strict, ..Default::default() };
    let doc = lopdf::Document::load_mem_with_options(bytes, opts).map_err(|e| format!("{e}"))?;
    let pages = doc.get_pages();
    let (mut decoded, mut ops) = (0, 0);
    for (_, id) in pages.iter() {
        let data = doc.get_page_content_with_limit(*id, STREAM_CAP).map_err(|e| format!("content: {e}"))?;
        decoded += data.len();
        ops += lopdf::content::Content::decode(&data).map_err(|e| format!("ops: {e}"))?.operations.len();
    }
    let note = match &doc.xref_recovery {
        Some(r) => format!(" ops={ops} recovered={r:?}").chars().take(80).collect(),
        None => format!(" ops={ops}"),
    };
    Ok((pages.len(), decoded, note))
}

fn pdf_run(bytes: &[u8]) -> Result<(usize, usize, String), String> {
    let file = pdf::file::FileOptions::uncached().load(bytes.to_vec()).map_err(|e| format!("{e}"))?;
    let resolver = file.resolver();
    let (mut n, mut decoded, mut ops) = (0, 0, 0);
    for page in file.pages() {
        let page = page.map_err(|e| format!("page {n}: {e}"))?;
        n += 1;
        if let Some(c) = &page.contents {
            for part in &c.parts {
                decoded += part.data(&resolver).map_err(|e| format!("content: {e}"))?.len();
            }
            ops += c.operations(&resolver).map_err(|e| format!("ops: {e}"))?.len();
        }
    }
    Ok((n, decoded, format!(" ops={ops} count_claimed={}", file.num_pages())))
}

fn own_run(bytes: &[u8]) -> Result<(usize, usize, String), String> {
    let mut lim = spk01_own::Limits::default();
    if let Some(n) = std::env::var("OWN_MAX_OBJECTS").ok().and_then(|v| v.parse().ok()) {
        lim.max_objects = n;
    }
    let r = spk01_own::Reader::open(bytes, lim).map_err(|e| format!("{e:?}"))?;
    let n = r.page_count().map_err(|e| format!("{e:?}"))?;
    Ok((n, 0, format!(" objects={} recovered={}", r.object_count(), r.recovered)))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (which, path) = (args[1].clone(), args[2].clone());
    let bytes = std::fs::read(&path).expect("read fixture");
    std::panic::set_hook(Box::new(|i| eprintln!("panic at {:?}", i.location())));
    let t = Instant::now();
    let out = std::panic::catch_unwind(|| match which.as_str() {
        "lopdf" => lopdf_run(&bytes, false),
        "lopdf-strict" => lopdf_run(&bytes, true),
        "pdf" => pdf_run(&bytes),
        "own" => own_run(&bytes),
        _ => Err("unknown candidate".into()),
    });
    let ms = t.elapsed().as_millis();
    let heap = peak_heap() >> 20;
    match out {
        Ok(Ok((p, d, note))) => println!("OK pages={p} decoded={d}{note} ms={ms} heapMiB={heap}"),
        Ok(Err(e)) => println!("ERR {} ms={ms} heapMiB={heap}", e.chars().take(160).collect::<String>().replace('\n', " ")),
        Err(p) => {
            let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()));
            println!("PANIC {} ms={ms} heapMiB={heap}", msg.unwrap_or_default().chars().take(160).collect::<String>());
        }
    }
}
