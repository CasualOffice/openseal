//! The incremental writer (`T-1B`, docs/30 §9): prefix, numbering, xref form,
//! determinism, and refusal of unsound or DocMDP-locked files.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_pdf::{
    Change, Dictionary, IncrementalUpdate, Limits, Object, XrefKind, admit, admit_strict,
};
use common::{classic, never, pages, stream, xref_stream_file, zlib};

/// Replace every occurrence of `from` with `to` (the files are binary).
fn subst(hay: &[u8], from: &str, to: &str) -> Vec<u8> {
    let (from, to) = (from.as_bytes(), to.as_bytes());
    let mut out = Vec::new();
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

fn find(hay: &[u8], needle: &str) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .unwrap()
}

fn info_update(bytes: &[u8]) -> Vec<u8> {
    let a = admit_strict(bytes, &Limits::default(), &never).unwrap();
    let mut u = IncrementalUpdate::new(&a, Change::FillAndSign).unwrap();
    let mut info = Dictionary::new();
    info.insert(b"Producer", Object::String(b"OpenSeal test".to_vec()));
    let r = u.add(Object::Dictionary(info)).unwrap();
    u.set_info(r);
    u.finish().unwrap()
}

#[test]
fn update_to_a_classic_file_appends_a_table() {
    let base = classic(&pages(2), "");
    let out = info_update(&base);
    assert!(out.starts_with(&base));
    let a = admit_strict(&out, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.revisions.len(), 2);
    assert_eq!(a.report.revisions[1].kind, XrefKind::Table);
    assert_eq!(a.report.page_count, 2);
    let info = a.document.trailer().get(b"Info").unwrap().as_ref().unwrap();
    // pages(2) uses objects 1 to 6, /Size 7: the first new number is 7.
    assert_eq!(info.num, 7);
    let tail = String::from_utf8_lossy(&out[base.len()..]).into_owned();
    assert!(tail.contains("/Prev "), "{tail}");
    let lopdf = lopdf::Document::load_mem(&out).unwrap();
    assert_eq!(lopdf.get_pages().len(), 2);
}

#[test]
fn update_to_an_xref_stream_file_appends_an_xref_stream() {
    let p = pages(1);
    let (direct, compressed): (Vec<_>, Vec<_>) = p.into_iter().partition(|(n, _)| *n == 4);
    let base = xref_stream_file(&direct, &compressed, 10);
    let out = info_update(&base);
    assert!(out.starts_with(&base));
    let a = admit_strict(&out, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.revisions.len(), 2);
    assert_eq!(a.report.revisions[1].kind, XrefKind::Stream);
    assert_eq!(a.report.page_count, 1);
    let lopdf = lopdf::Document::load_mem(&out).unwrap();
    assert_eq!(lopdf.get_pages().len(), 1);
}

#[test]
fn new_numbers_start_after_size_and_the_highest_object() {
    // /Size 50 above every object: the first new number is 50.
    let base = subst(&classic(&pages(1), ""), "/Size 5/", "/Size 50/");
    let a = admit_strict(&base, &Limits::default(), &never).unwrap();
    let mut u = IncrementalUpdate::new(&a, Change::Other).unwrap();
    assert_eq!(u.add(Object::Null).unwrap().num, 50);
    assert_eq!(u.add(Object::Integer(1)).unwrap().num, 51);
}

#[test]
fn object_numbers_above_8388607_are_refused() {
    let base = subst(&classic(&pages(1), ""), "/Size 5/", "/Size 8388607/");
    let a = admit_strict(&base, &Limits::default(), &never).unwrap();
    let mut u = IncrementalUpdate::new(&a, Change::Other).unwrap();
    assert_eq!(u.add(Object::Null).unwrap().num, 8_388_607);
    assert_eq!(u.add(Object::Null).unwrap_err().code(), "CS-WRT-0002");
}

#[test]
fn replaced_objects_keep_their_number_and_generation() {
    let mut objs = pages(1);
    // Page content as generation 3, written by hand.
    let base = subst(
        &subst(&classic(&objs, ""), "4 0 obj", "4 3 obj"),
        " 00000 n \ntrailer",
        " 00003 n \ntrailer",
    );
    objs.clear();
    let a = admit_strict(&base, &Limits::default(), &never).unwrap();
    let mut u = IncrementalUpdate::new(&a, Change::Other).unwrap();
    let mut d = Dictionary::new();
    d.insert(b"Filter", Object::Name(b"FlateDecode".to_vec()));
    u.replace_stream(4, d, zlib(b"0 0 m 10 10 l S")).unwrap();
    assert_eq!(
        u.replace(99, Object::Null).unwrap_err().code(),
        "CS-WRT-0005"
    );
    let out = u.finish().unwrap();
    assert!(out.starts_with(&base));
    let tail = String::from_utf8_lossy(&out[base.len()..]).into_owned();
    assert!(tail.starts_with("4 3 obj\n"), "{tail}");
    let mut a = admit_strict(&out, &Limits::default(), &never).unwrap();
    assert_eq!(
        a.document.decode_stream(4, &never).unwrap(),
        b"0 0 m 10 10 l S"
    );
}

#[test]
fn same_input_and_objects_give_the_same_bytes() {
    let base = classic(&pages(3), "");
    assert_eq!(info_update(&base), info_update(&base));
}

#[test]
fn a_stream_read_from_the_file_is_copied() {
    let base = classic(&pages(1), "");
    let mut a = admit_strict(&base, &Limits::default(), &never).unwrap();
    let content = a.document.object(4, &never).unwrap();
    let mut u = IncrementalUpdate::new(&a, Change::Other).unwrap();
    let r = u.add(content).unwrap();
    let out = u.finish().unwrap();
    let mut b = admit_strict(&out, &Limits::default(), &never).unwrap();
    assert_eq!(
        b.document.decode_stream(r.num, &never).unwrap(),
        b.document.decode_stream(4, &never).unwrap()
    );
}

#[test]
fn a_repaired_file_is_refused_until_normalized() {
    // Every offset shifted: the default reader corrects them (CS-PDF-0101).
    let good = classic(&pages(1), "");
    let mut bytes = good.clone();
    for n in 1..=4 {
        let off = find(&good, &format!("\n{n} 0 obj")) + 1;
        bytes = subst(
            &bytes,
            &format!("{off:010} 00000 n"),
            &format!("{:010} 00000 n", off + 3),
        );
    }
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    assert!(a.report.repaired);
    assert_eq!(
        IncrementalUpdate::new(&a, Change::Other)
            .unwrap_err()
            .code(),
        "CS-WRT-0003"
    );
    let n = casual_sign_pdf::normalize(
        &mut a,
        &casual_sign_pdf::NormalizeOptions::default(),
        &never,
    )
    .unwrap();
    let out = info_update(&n.bytes);
    assert!(out.starts_with(&n.bytes));
}

/// A file certified with DocMDP level `p`.
fn certified(p: u8) -> Vec<u8> {
    let mut objs = pages(1);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/Perms<</DocMDP 10 0 R>>>>".to_vec();
    objs.push((
        10,
        format!(
            "<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/ETSI.CAdES.detached/ByteRange[0 1 2 3]\
/Contents<00>/Reference[<</Type/SigRef/TransformMethod/DocMDP/TransformParams<</P {p}/V/1.2>>>>]>>"
        )
        .into_bytes(),
    ));
    classic(&objs, "")
}

#[test]
fn docmdp_decides_which_changes_may_be_appended() {
    let cases = [
        (1, Change::FillAndSign, Some("CS-WRT-0004")),
        (2, Change::FillAndSign, None),
        (2, Change::Annotate, Some("CS-WRT-0004")),
        (3, Change::Annotate, None),
        (3, Change::Other, Some("CS-WRT-0004")),
    ];
    for (p, change, want) in cases {
        let bytes = certified(p);
        let a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
        assert_eq!(a.report.docmdp, Some(p));
        let got = IncrementalUpdate::new(&a, change).err().map(|e| e.code());
        assert_eq!(got, want, "DocMDP {p}, {change:?}");
    }
}

#[test]
fn update_without_a_trailing_newline_still_starts_with_the_input() {
    let mut base = classic(&pages(1), "");
    assert_eq!(base.pop(), Some(b'\n'));
    let out = info_update(&base);
    assert!(out.starts_with(&base));
    admit_strict(&out, &Limits::default(), &never).unwrap();
}

#[test]
fn many_new_objects_in_runs() {
    let base = classic(&pages(1), "");
    let a = admit_strict(&base, &Limits::default(), &never).unwrap();
    let mut u = IncrementalUpdate::new(&a, Change::Other).unwrap();
    for i in 0..300 {
        u.add(Object::Integer(i)).unwrap();
    }
    u.add_stream(Dictionary::new(), stream("", b"x")).unwrap();
    u.replace(
        2,
        Object::Dictionary({
            let mut d = Dictionary::new();
            d.insert(b"Type", Object::Name(b"Pages".to_vec()));
            d.insert(
                b"Kids",
                Object::Array(vec![Object::Reference(casual_sign_pdf::ObjRef {
                    num: 3,
                    generation: 0,
                })]),
            );
            d.insert(b"Count", Object::Integer(1));
            d
        }),
    )
    .unwrap();
    let out = u.finish().unwrap();
    let mut b = admit_strict(&out, &Limits::default(), &never).unwrap();
    assert_eq!(
        b.document.object(5 + 299, &never).unwrap(),
        Object::Integer(299)
    );
    assert_eq!(b.report.page_count, 1);
}
