//! Shared helpers: a tiny PDF builder and the hostile-fixture generator hook.
// Not every test binary uses every helper.
#![allow(dead_code)]
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

pub fn never() -> bool {
    false
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn hostile_dir() -> PathBuf {
    repo_root().join("fixtures/hostile")
}

/// Manifest rows: (file, limit, strict_code, default, note).
pub fn manifest() -> Vec<[String; 5]> {
    let text = std::fs::read_to_string(hostile_dir().join("manifest.tsv")).unwrap();
    text.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let c: Vec<String> = l.split('\t').map(str::to_string).collect();
            assert_eq!(c.len(), 5, "manifest row: {l}");
            [
                c[0].clone(),
                c[1].clone(),
                c[2].clone(),
                c[3].clone(),
                c[4].clone(),
            ]
        })
        .collect()
}

/// Generate the hostile fixtures once if any is missing. `false` when python3 is absent.
pub fn ensure_hostile() -> bool {
    static DONE: OnceLock<bool> = OnceLock::new();
    *DONE.get_or_init(|| {
        let missing = manifest()
            .iter()
            .any(|r| !hostile_dir().join(&r[0]).exists());
        if !missing {
            return true;
        }
        match Command::new("python3")
            .args(["-I", "fixtures/tools/generate.py"])
            .current_dir(repo_root())
            .output()
        {
            Ok(out) => {
                assert!(
                    out.status.success(),
                    "generate.py failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                true
            }
            Err(e) => {
                eprintln!("SKIPPED: python3 not available to generate fixtures/hostile ({e})");
                false
            }
        }
    })
}

pub fn zlib(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

pub fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut v = format!("<<{dict}/Length {}>>\nstream\n", data.len()).into_bytes();
    v.extend_from_slice(data);
    v.extend_from_slice(b"\nendstream");
    v
}

/// A file with a classic xref. Objects are (number, body). Object 1 is the root.
pub fn classic(objs: &[(u32, Vec<u8>)], trailer_extra: &str) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offs = std::collections::BTreeMap::new();
    for (n, body) in objs {
        offs.insert(*n, out.len());
        out.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let size = offs.keys().max().unwrap() + 1;
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for n in 1..size {
        match offs.get(&n) {
            Some(o) => out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes()),
            None => out.extend_from_slice(b"0000000000 65535 f \n"),
        }
    }
    out.extend_from_slice(
        format!("trailer\n<</Size {size}/Root 1 0 R{trailer_extra}>>\nstartxref\n{xref}\n%%EOF\n")
            .as_bytes(),
    );
    out
}

/// Catalog, a page tree with `n` pages, each with a small content stream.
pub fn pages(n: u32) -> Vec<(u32, Vec<u8>)> {
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 3 + 2 * i)).collect();
    let mut objs = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (
            2,
            format!("<</Type/Pages/Kids[{}]/Count {n}>>", kids.join(" ")).into_bytes(),
        ),
    ];
    for i in 0..n {
        objs.push((
            3 + 2 * i,
            format!(
                "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents {} 0 R>>",
                4 + 2 * i
            )
            .into_bytes(),
        ));
        objs.push((
            4 + 2 * i,
            stream(
                "/Filter/FlateDecode",
                &zlib(format!("BT /F1 12 Tf 72 720 Td (Page {i}) Tj ET").as_bytes()),
            ),
        ));
    }
    objs
}

/// A file with an xref stream (Flate with PNG Up predictor, W [1 4 2]) in which
/// `compressed` objects live in object stream `stm`.
pub fn xref_stream_file(
    objs: &[(u32, Vec<u8>)],
    compressed: &[(u32, Vec<u8>)],
    stm: u32,
) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offs = std::collections::BTreeMap::new();
    let mut put = |out: &mut Vec<u8>, n: u32, body: &[u8]| {
        offs.insert(n, out.len());
        out.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    };
    for (n, body) in objs {
        put(&mut out, *n, body);
    }
    if !compressed.is_empty() {
        let mut head = String::new();
        let mut data = Vec::new();
        for (n, body) in compressed {
            head.push_str(&format!("{n} {} ", data.len()));
            data.extend_from_slice(body);
            data.push(b' ');
        }
        let mut payload = head.clone().into_bytes();
        payload.extend_from_slice(&data);
        let body = stream(
            &format!(
                "/Type/ObjStm/N {}/First {}/Filter/FlateDecode",
                compressed.len(),
                head.len()
            ),
            &zlib(&payload),
        );
        put(&mut out, stm, &body);
    }
    let max = offs
        .keys()
        .chain(compressed.iter().map(|(n, _)| n))
        .max()
        .copied()
        .unwrap();
    let xnum = max + 1;
    let xpos = out.len();
    let size = xnum + 1;
    let mut rows = Vec::new();
    let mut prev = vec![0u8; 7];
    for n in 0..size {
        let row: Vec<u8> = if let Some(i) = compressed.iter().position(|(c, _)| *c == n) {
            [
                vec![2],
                stm.to_be_bytes().to_vec(),
                (i as u16).to_be_bytes().to_vec(),
            ]
            .concat()
        } else if n == xnum {
            [vec![1], (xpos as u32).to_be_bytes().to_vec(), vec![0, 0]].concat()
        } else if let Some(o) = offs.get(&n) {
            [vec![1], (*o as u32).to_be_bytes().to_vec(), vec![0, 0]].concat()
        } else {
            vec![0, 0, 0, 0, 0, 0xff, 0xff]
        };
        rows.push(2u8); // PNG Up
        rows.extend(row.iter().zip(prev.iter()).map(|(c, p)| c.wrapping_sub(*p)));
        prev = row;
    }
    let dict = format!(
        "/Type/XRef/Size {size}/W[1 4 2]/Root 1 0 R/Filter/FlateDecode/DecodeParms<</Predictor 12/Columns 7>>"
    );
    out.extend_from_slice(format!("{xnum} 0 obj\n").as_bytes());
    out.extend_from_slice(&stream(&dict, &zlib(&rows)));
    out.extend_from_slice(format!("\nendobj\nstartxref\n{xpos}\n%%EOF\n").as_bytes());
    out
}

/// Append an incremental update replacing `objs`, with a classic xref and `/Prev`.
pub fn append_update(base: &[u8], objs: &[(u32, Vec<u8>)], size: u32) -> Vec<u8> {
    let prev = {
        let s = std::str::from_utf8(&base[base.len().saturating_sub(40)..]).unwrap_or("");
        let after = s.rsplit("startxref").next().unwrap();
        after
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap()
    };
    let mut out = base.to_vec();
    let mut entries = Vec::new();
    for (n, body) in objs {
        entries.push((*n, out.len()));
        out.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(b"xref\n");
    for (n, o) in entries {
        out.extend_from_slice(format!("{n} 1\n{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<</Size {size}/Root 1 0 R/Prev {prev}>>\nstartxref\n{xref}\n%%EOF\n")
            .as_bytes(),
    );
    out
}
