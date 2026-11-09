//! Each limit and each structural feature on small documents built here, so every
//! guard has a fast test that fails when the guard is removed (docs/04 rule 8).
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod common;

use std::cell::Cell;

use casual_sign_pdf::{
    ActionKind, FieldType, FindingKind, Limits, PdfError, XrefKind, admit, admit_strict,
};
use common::{classic, never, pages, stream, xref_stream_file, zlib};

fn code_both(bytes: &[u8], limits: &Limits) -> (String, String) {
    let s = admit_strict(bytes, limits, &never)
        .map(|_| "ok".to_string())
        .unwrap_or_else(|e| e.code().into());
    let d = admit(bytes, limits, &never)
        .map(|_| "ok".to_string())
        .unwrap_or_else(|e| e.code().into());
    (s, d)
}

// ----- limits ---------------------------------------------------------------------

#[test]
fn depth_limit_refuses_in_both_modes() {
    let mut objs = pages(1);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/D [[[[[1]]]]]>>".to_vec();
    let bytes = classic(&objs, "");
    let at = |d: u16| Limits {
        max_depth: d,
        ..Limits::default()
    };
    assert_eq!(code_both(&bytes, &at(6)), ("ok".into(), "ok".into()));
    assert_eq!(
        code_both(&bytes, &at(5)),
        ("CS-PDF-0004".into(), "CS-PDF-0004".into())
    );
}

#[test]
fn object_limit_refuses_in_both_modes() {
    let bytes = classic(&pages(3), "");
    // 8 objects: catalog, page tree, three pages and three contents.
    assert_eq!(
        code_both(
            &bytes,
            &Limits {
                max_objects: 8,
                ..Limits::default()
            }
        ),
        ("ok".into(), "ok".into())
    );
    let l = Limits {
        max_objects: 6,
        ..Limits::default()
    };
    assert_eq!(
        code_both(&bytes, &l),
        ("CS-PDF-0002".into(), "CS-PDF-0002".into())
    );
    // The same cap holds when the xref is rebuilt by scanning.
    let broken = [&bytes[..bytes.len() - 30], b"garbage"].concat();
    assert_eq!(
        admit(&broken, &l, &never).unwrap_err().code(),
        "CS-PDF-0002"
    );
}

#[test]
fn revision_limit_refuses_in_both_modes() {
    let mut bytes = classic(&pages(1), "");
    for k in 0..4 {
        bytes = common::append_update(
            &bytes,
            &[(
                1,
                format!("<</Type/Catalog/Pages 2 0 R/Rev {k}>>").into_bytes(),
            )],
            5,
        );
    }
    let ok = admit_strict(
        &bytes,
        &Limits {
            max_revisions: 5,
            ..Limits::default()
        },
        &never,
    )
    .unwrap();
    assert_eq!(ok.report.revisions.len(), 5);
    let l = Limits {
        max_revisions: 4,
        ..Limits::default()
    };
    assert_eq!(
        code_both(&bytes, &l),
        ("CS-PDF-0006".into(), "CS-PDF-0006".into())
    );
}

#[test]
fn page_tree_cycle_refuses_in_both_modes() {
    let objs = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (2, b"<</Type/Pages/Kids[3 0 R]>>".to_vec()),
        (3, b"<</Type/Pages/Kids[5 0 R 2 0 R]>>".to_vec()),
        (5, b"<</Type/Page/MediaBox[0 0 10 10]>>".to_vec()),
    ];
    let bytes = classic(&objs, "");
    assert_eq!(
        code_both(&bytes, &Limits::default()),
        ("CS-PDF-0007".into(), "CS-PDF-0007".into())
    );
}

#[test]
fn page_limit_refuses_in_both_modes() {
    let bytes = classic(&pages(4), "");
    assert_eq!(
        code_both(
            &bytes,
            &Limits {
                max_pages: 4,
                ..Limits::default()
            }
        ),
        ("ok".into(), "ok".into())
    );
    let l = Limits {
        max_pages: 3,
        ..Limits::default()
    };
    assert_eq!(
        code_both(&bytes, &l),
        ("CS-PDF-0007".into(), "CS-PDF-0007".into())
    );
}

/// A document whose three object streams each decode to `each` bytes of zeros.
fn objstm_bombs(each: usize) -> Vec<u8> {
    let mut objs = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (2, b"<</Type/Pages/Kids[3 0 R]>>".to_vec()),
        (3, b"<</Type/Page/MediaBox[0 0 10 10]>>".to_vec()),
    ];
    let mut compressed = Vec::new();
    for k in 0..3u32 {
        let head = format!("{} 0 ", 10 + k);
        let mut payload = head.clone().into_bytes();
        payload.extend_from_slice(b"null");
        payload.resize(each, b' ');
        objs.push((
            20 + k,
            stream(
                &format!("/Type/ObjStm/N 1/First {}/Filter/FlateDecode", head.len()),
                &zlib(&payload),
            ),
        ));
        compressed.push((10 + k, 20 + k));
    }
    // Hand-written xref stream naming the compressed objects.
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offs = std::collections::BTreeMap::new();
    for (n, body) in &objs {
        offs.insert(*n, out.len());
        out.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xnum = 30u32;
    let xpos = out.len();
    let mut rows = Vec::new();
    for n in 0..=xnum {
        if let Some((_, s)) = compressed.iter().find(|(c, _)| *c == n) {
            rows.extend([2u8]);
            rows.extend(s.to_be_bytes());
            rows.extend([0u8, 0]);
        } else if let Some(o) = offs.get(&n).copied().or((n == xnum).then_some(xpos)) {
            rows.extend([1u8]);
            rows.extend((o as u32).to_be_bytes());
            rows.extend([0u8, 0]);
        } else {
            rows.extend([0u8, 0, 0, 0, 0, 0, 0]);
        }
    }
    out.extend_from_slice(format!("{xnum} 0 obj\n").as_bytes());
    out.extend_from_slice(&stream(
        &format!("/Type/XRef/Size {}/W[1 4 2]/Root 1 0 R", xnum + 1),
        &rows,
    ));
    out.extend_from_slice(format!("\nendobj\nstartxref\n{xpos}\n%%EOF\n").as_bytes());
    out
}

#[test]
fn document_decode_budget_refuses_in_both_modes() {
    let bytes = objstm_bombs(1 << 20);
    let roomy = Limits {
        max_total_decoded_bytes: 4 << 20,
        ..Limits::default()
    };
    assert_eq!(code_both(&bytes, &roomy), ("ok".into(), "ok".into()));
    let tight = Limits {
        max_total_decoded_bytes: (5 << 20) / 2,
        ..Limits::default()
    };
    for e in [
        admit(&bytes, &tight, &never).unwrap_err(),
        admit_strict(&bytes, &tight, &never).unwrap_err(),
    ] {
        assert!(matches!(e, PdfError::DecodeBudget { .. }), "{e}");
    }
}

#[test]
fn single_stream_cap_drops_content_by_default_and_refuses_strict() {
    let mut objs = pages(1);
    objs[3].1 = stream("/Filter/FlateDecode", &zlib(&vec![b' '; 2 << 20]));
    let bytes = classic(&objs, "");
    let l = Limits {
        max_stream_bytes: 1 << 20,
        ..Limits::default()
    };
    assert!(matches!(
        admit_strict(&bytes, &l, &never).unwrap_err(),
        PdfError::StreamTooLarge { object: 4, .. }
    ));
    let a = admit(&bytes, &l, &never).unwrap();
    assert!(
        a.report
            .findings
            .iter()
            .any(|f| f.code == "CS-PDF-0003" && f.object == Some(4) && f.page == Some(0))
    );
}

#[test]
fn decode_ratio_drops_content_by_default_and_refuses_strict() {
    let twice = zlib(&zlib(&vec![0u8; 8 << 20]));
    let mut objs = pages(1);
    objs[3].1 = stream("/Filter[/FlateDecode/FlateDecode]", &twice);
    let bytes = classic(&objs, "");
    let e = admit_strict(&bytes, &Limits::default(), &never).unwrap_err();
    assert!(matches!(e, PdfError::DecodeRatio { object: 4, .. }), "{e}");
    let a = admit(&bytes, &Limits::default(), &never).unwrap();
    assert!(a.report.has_code("CS-PDF-0003"));
    // With the ratio lifted the same stream decodes.
    let lifted = Limits {
        max_decode_ratio: u32::MAX,
        ..Limits::default()
    };
    assert!(admit_strict(&bytes, &lifted, &never).is_ok());
}

#[test]
fn cancellation_stops_the_read_in_both_modes() {
    let bytes = classic(&pages(20), "");
    for strict in [false, true] {
        // Cancel after a given number of checks: every point must stop with 0013.
        let total = {
            let calls = Cell::new(0u32);
            let count = || {
                calls.set(calls.get() + 1);
                false
            };
            let r = if strict {
                admit_strict(&bytes, &Limits::default(), &count)
            } else {
                admit(&bytes, &Limits::default(), &count)
            };
            assert!(r.is_ok());
            calls.get()
        };
        assert!(
            total > 20,
            "the predicate is checked in the loops ({total} calls)"
        );
        for after in [0, 1, total / 2, total - 1] {
            let calls = Cell::new(0u32);
            let stop = || {
                calls.set(calls.get() + 1);
                calls.get() > after
            };
            let r = if strict {
                admit_strict(&bytes, &Limits::default(), &stop)
            } else {
                admit(&bytes, &Limits::default(), &stop)
            };
            assert_eq!(
                r.unwrap_err(),
                PdfError::Cancelled,
                "cancel after {after} of {total} (strict {strict})"
            );
        }
    }
}

#[test]
fn filter_chain_cap() {
    let mut objs = pages(1);
    let mut data = b"BT ET".to_vec();
    for _ in 0..3 {
        data = [hex(&data).as_bytes(), b">"].concat();
    }
    objs[3].1 = stream("/Filter[/AHx/AHx/AHx]", &data);
    let bytes = classic(&objs, "");
    assert!(
        admit_strict(
            &bytes,
            &Limits {
                max_filter_chain: 3,
                ..Limits::default()
            },
            &never
        )
        .is_ok()
    );
    let l = Limits {
        max_filter_chain: 2,
        ..Limits::default()
    };
    assert_eq!(
        admit_strict(&bytes, &l, &never).unwrap_err().code(),
        "CS-PDF-0011"
    );
    assert!(
        admit(&bytes, &l, &never)
            .unwrap()
            .report
            .has_code("CS-PDF-0011")
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

#[test]
fn unsupported_filter_is_reported_not_decoded() {
    let mut objs = pages(1);
    objs[3].1 = stream("/Filter/LZWDecode", b"\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01");
    let bytes = classic(&objs, "");
    assert_eq!(
        admit_strict(&bytes, &Limits::default(), &never)
            .unwrap_err()
            .code(),
        "CS-PDF-0011"
    );
    let a = admit(&bytes, &Limits::default(), &never).unwrap();
    assert!(
        a.report
            .findings
            .iter()
            .any(|f| f.code == "CS-PDF-0011" && f.object == Some(4))
    );
}

#[test]
fn reference_depth_limit() {
    let mut objs = pages(1);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/C 10 0 R>>".to_vec();
    objs.extend((10..14).map(|n| (n, format!("{} 0 R", n + 1).into_bytes())));
    objs.push((14, b"(end)".to_vec()));
    let bytes = classic(&objs, "");
    // Object 10 needs four hops (11..14).
    assert!(
        admit_strict(
            &bytes,
            &Limits {
                max_ref_depth: 4,
                ..Limits::default()
            },
            &never
        )
        .is_ok()
    );
    let l = Limits {
        max_ref_depth: 3,
        ..Limits::default()
    };
    assert!(matches!(
        admit_strict(&bytes, &l, &never).unwrap_err(),
        PdfError::ReferenceTooDeep { object: 10 }
    ));
    let a = admit(&bytes, &l, &never).unwrap();
    assert!(
        a.report
            .findings
            .iter()
            .any(|f| f.code == "CS-PDF-0004" && f.object == Some(10))
    );
}

#[test]
fn content_operator_limit() {
    let bytes = classic(&pages(2), "");
    // Each page: BT Tf Td Tj ET = 5 operators.
    assert!(
        admit_strict(
            &bytes,
            &Limits {
                max_content_ops: 5,
                ..Limits::default()
            },
            &never
        )
        .is_ok()
    );
    let l = Limits {
        max_content_ops: 4,
        ..Limits::default()
    };
    assert_eq!(
        admit_strict(&bytes, &l, &never).unwrap_err(),
        PdfError::TooManyContentOps { page: 0 }
    );
    let a = admit(&bytes, &l, &never).unwrap();
    let pages_flagged: Vec<_> = a
        .report
        .findings
        .iter()
        .filter(|f| f.code == "CS-PDF-0013")
        .map(|f| f.page)
        .collect();
    assert_eq!(pages_flagged, vec![Some(0), Some(1)]);
}

#[test]
fn string_and_name_caps() {
    let mut objs = pages(1);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/S (abcdefgh) /Nnnnnnnnnnnn 1>>".to_vec();
    let bytes = classic(&objs, "");
    assert!(
        admit_strict(
            &bytes,
            &Limits {
                max_string_bytes: 8,
                max_name_bytes: 12,
                ..Limits::default()
            },
            &never
        )
        .is_ok()
    );
    let s = Limits {
        max_string_bytes: 7,
        ..Limits::default()
    };
    assert_eq!(
        admit_strict(&bytes, &s, &never).unwrap_err().code(),
        "CS-PDF-0008"
    );
    let n = Limits {
        max_name_bytes: 11,
        ..Limits::default()
    };
    assert_eq!(
        admit_strict(&bytes, &n, &never).unwrap_err().code(),
        "CS-PDF-0008"
    );
    assert!(
        admit(&bytes, &n, &never)
            .unwrap()
            .report
            .has_code("CS-PDF-0008")
    );
}

// ----- structure --------------------------------------------------------------------

#[test]
fn xref_stream_with_object_stream_and_predictor() {
    let objs = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (4, stream("/Filter/FlateDecode", &zlib(b"BT ET"))),
    ];
    let compressed = vec![
        (
            2,
            b"<</Type/Pages/Kids[3 0 R 6 0 R]/MediaBox[0 0 595 842]>>".to_vec(),
        ),
        (
            3,
            b"<</Type/Page/Parent 2 0 R/Contents 4 0 R/Rotate -90/UserUnit 2>>".to_vec(),
        ),
        (
            6,
            b"<</Type/Page/Parent 2 0 R/CropBox[10 10 900 900]>>".to_vec(),
        ),
    ];
    let bytes = xref_stream_file(&objs, &compressed, 5);
    let a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    let r = &a.report;
    assert_eq!(r.page_count, 2);
    assert_eq!(r.revisions[0].kind, XrefKind::Stream);
    let p0 = r.pages[0];
    assert_eq!(
        (p0.media_box.urx, p0.media_box.ury),
        (595.0, 842.0),
        "inherited MediaBox"
    );
    assert_eq!(p0.rotate, 270);
    assert_eq!(p0.user_unit, 2.0);
    let p1 = r.pages[1];
    assert_eq!(
        (p1.crop_box.llx, p1.crop_box.urx, p1.crop_box.ury),
        (10.0, 595.0, 842.0),
        "crop clipped"
    );
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}

#[test]
fn incremental_updates_are_counted_with_their_end_offsets() {
    let base = classic(&pages(1), "");
    let one = common::append_update(
        &base,
        &[(1, b"<</Type/Catalog/Pages 2 0 R/V 1>>".to_vec())],
        5,
    );
    let two = common::append_update(
        &one,
        &[(
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 200]>>".to_vec(),
        )],
        5,
    );
    let a = admit_strict(&two, &Limits::default(), &never).unwrap();
    let ends: Vec<u64> = a.report.revisions.iter().map(|r| r.end_offset).collect();
    assert_eq!(
        ends,
        vec![base.len() as u64, one.len() as u64, two.len() as u64]
    );
    assert_eq!(
        a.report.pages[0].media_box.ury, 200.0,
        "newest revision wins"
    );
}

#[test]
fn hybrid_file_reads_compressed_objects_from_xrefstm() {
    // Table lists 1, 2, 4 and leaves 3 free; the XRefStm puts 3 in object stream 5.
    let mut out = b"%PDF-1.5\n".to_vec();
    let mut offs = std::collections::BTreeMap::new();
    let page = b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 400]>>";
    let head = b"3 0 ";
    let mut payload = head.to_vec();
    payload.extend_from_slice(page);
    let bodies: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (2, b"<</Type/Pages/Kids[3 0 R]>>".to_vec()),
        (
            5,
            stream(
                &format!("/Type/ObjStm/N 1/First {}/Filter/FlateDecode", head.len()),
                &zlib(&payload),
            ),
        ),
    ];
    for (n, b) in &bodies {
        offs.insert(*n, out.len());
        out.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        out.extend_from_slice(b);
        out.extend_from_slice(b"\nendobj\n");
    }
    let stm_pos = out.len();
    let rows = [2u8, 0, 0, 0, 5, 0, 0];
    out.extend_from_slice(b"6 0 obj\n");
    out.extend_from_slice(&stream("/Type/XRef/Size 7/Index[3 1]/W[1 4 2]", &rows));
    out.extend_from_slice(b"\nendobj\n");
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \n");
    for n in 1..7u32 {
        match (n, offs.get(&n)) {
            (6, _) => out.extend_from_slice(format!("{stm_pos:010} 00000 n \n").as_bytes()),
            (_, Some(o)) => out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes()),
            _ => out.extend_from_slice(b"0000000000 65535 f \n"),
        }
    }
    out.extend_from_slice(
        format!("trailer\n<</Size 7/Root 1 0 R/XRefStm {stm_pos}>>\nstartxref\n{xref}\n%%EOF\n")
            .as_bytes(),
    );
    let a = admit_strict(&out, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.revisions[0].kind, XrefKind::Hybrid);
    assert_eq!(a.report.pages[0].media_box.ury, 400.0);
}

#[test]
fn indirect_and_wrong_lengths() {
    let mut objs = pages(1);
    let data = zlib(b"BT ET");
    let mut body = b"<</Filter/FlateDecode/Length 9 0 R>>\nstream\n".to_vec();
    body.extend_from_slice(&data);
    body.extend_from_slice(b"\nendstream");
    objs[3].1 = body;
    objs.push((9, format!("{}", data.len()).into_bytes()));
    let bytes = classic(&objs, "");
    let a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.stream_lengths_corrected, 0);
    // A wrong length is corrected from `endstream`.
    let mut objs = pages(1);
    let mut body = b"<</Filter/FlateDecode/Length 3>>\nstream\n".to_vec();
    body.extend_from_slice(&data);
    body.extend_from_slice(b"\nendstream");
    objs[3].1 = body;
    let fixed = classic(&objs, "");
    let a = admit(&fixed, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.stream_lengths_corrected, 1);
    // A /Length naming its own stream is a cycle, recovered the same way.
    let mut objs = pages(1);
    let mut body = b"<</Filter/FlateDecode/Length 4 0 R>>\nstream\n".to_vec();
    body.extend_from_slice(&data);
    body.extend_from_slice(b"\nendstream");
    objs[3].1 = body;
    assert!(admit_strict(&classic(&objs, ""), &Limits::default(), &never).is_ok());
}

#[test]
fn absurd_size_in_a_table_is_refused_strict_and_rebuilt_by_default() {
    let bytes = classic(&pages(1), "");
    let with_size = |size: &str| {
        let at = bytes.windows(8).position(|w| w == b"/Size 5/").unwrap();
        [
            &bytes[..at],
            format!("/Size {size}/").as_bytes(),
            &bytes[at + 8..],
        ]
        .concat()
    };
    let bad = with_size("8388608");
    assert_eq!(
        admit_strict(&bad, &Limits::default(), &never)
            .unwrap_err()
            .code(),
        "CS-PDF-0002"
    );
    let a = admit(&bad, &Limits::default(), &never).unwrap();
    assert!(a.report.repaired);
    assert!(
        a.report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::XrefRebuilt)
    );
    assert!(admit_strict(&with_size("8388607"), &Limits::default(), &never).is_ok());
}

// ----- classification ---------------------------------------------------------------

#[test]
fn fields_signatures_and_docmdp() {
    let mut objs = pages(1);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/AcroForm 10 0 R/Perms<</DocMDP 13 0 R>>>>".to_vec();
    objs.extend([
        (10, b"<</Fields[11 0 R 12 0 R 14 0 R]>>".to_vec()),
        (11, b"<</FT/Tx/T(name)/Rect[10 20 110 40]/P 3 0 R>>".to_vec()),
        (12, b"<</FT/Sig/T(sig)/V 13 0 R/Rect[0 0 0 0]>>".to_vec()),
        (13, b"<</Type/Sig/SubFilter/ETSI.CAdES.detached/ByteRange[0 1 2 3]/Contents<00>/Reference[<</TransformMethod/DocMDP/TransformParams<</P 1>>>>]>>".to_vec()),
        (14, b"<</T(group)/FT/Btn/Ff 32768/Kids[15 0 R]>>".to_vec()),
        (15, b"<</T(choice)/Kids[16 0 R 17 0 R]>>".to_vec()),
        (16, b"<</Subtype/Widget/Rect[0 0 5 5]>>".to_vec()),
        (17, b"<</Subtype/Widget/Rect[5 5 0 0]>>".to_vec()),
    ]);
    let bytes = classic(&objs, "");
    let a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    let r = &a.report;
    let names: Vec<(&str, FieldType, usize)> = r
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.field_type, f.widgets.len()))
        .collect();
    assert_eq!(
        names,
        vec![
            ("name", FieldType::Text, 1),
            ("sig", FieldType::Signature, 1),
            ("group.choice", FieldType::Radio, 2)
        ]
    );
    assert_eq!(r.fields[0].widgets[0].page, Some(0));
    assert_eq!(r.signatures.len(), 1);
    assert_eq!(
        r.signatures[0].sub_filter.as_deref(),
        Some("ETSI.CAdES.detached")
    );
    assert!(r.has_perms);
    assert_eq!(r.docmdp, Some(1));
    assert!(r.has_code("CS-PDF-0106"));
    assert!(r.has_code("CS-PDF-0107"));

    // The same signed file with a broken xref is refused, never repaired.
    let broken = [&bytes[..bytes.len() - 25], b"garbage\n"].concat();
    assert_eq!(
        admit(&broken, &Limits::default(), &never)
            .unwrap_err()
            .code(),
        "CS-PDF-0014"
    );
}

#[test]
fn active_content_and_carriers() {
    let mut objs = pages(1);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/OpenAction 10 0 R/OCProperties<<>>/Names<</JavaScript 12 0 R>>>>".to_vec();
    objs[2].1 = b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Annots[11 0 R 13 0 R 14 0 R]>>".to_vec();
    objs.extend([
        (10, b"<</S/URI/URI(https://example.invalid/)>>".to_vec()),
        (11, b"<</Subtype/Link/A<</S/URI/URI(https://example.invalid/b)>>/AA<</E<</S/Launch/F(x)>>>>>>".to_vec()),
        (12, b"<</Names[(a) 15 0 R]>>".to_vec()),
        (13, b"<</Subtype/RichMedia>>".to_vec()),
        (14, b"<</Subtype/Link/A<</S/GoToR/F(other.pdf)/D[0 /Fit]>>>>".to_vec()),
        (15, b"<</S/JavaScript/JS(1)>>".to_vec()),
        (16, stream("/F(external.dat)", b"")),
    ]);
    let bytes = classic(&objs, "");
    let a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    let r = &a.report;
    let has = |code: &str, kind: FindingKind, obj: u32| {
        r.findings
            .iter()
            .any(|f| f.code == code && f.kind == kind && f.object == Some(obj))
    };
    assert!(
        has(
            "CS-PDF-0105",
            FindingKind::ExternalReference(ActionKind::Uri),
            10
        ),
        "URI on open"
    );
    assert!(
        has("CS-PDF-0103", FindingKind::Action(ActionKind::Launch), 11),
        "Launch in /AA"
    );
    assert!(has(
        "CS-PDF-0103",
        FindingKind::Action(ActionKind::JavaScript),
        15
    ));
    assert!(has("CS-PDF-0104", FindingKind::RichMedia, 13));
    assert!(has(
        "CS-PDF-0105",
        FindingKind::ExternalReference(ActionKind::GoToR),
        14
    ));
    assert!(has("CS-PDF-0105", FindingKind::ExternalStream, 16));
    assert!(has("CS-PDF-0108", FindingKind::OptionalContent, 0) || r.has_code("CS-PDF-0108"));
    // A link's URI is inventory, not a finding: it runs only on a click.
    assert!(!r.findings.iter().any(
        |f| f.kind == FindingKind::ExternalReference(ActionKind::Uri) && f.object == Some(11)
    ));
    assert!(
        r.actions
            .iter()
            .any(|a| a.object == 11 && a.kind == ActionKind::Uri && !a.automatic)
    );
}

#[test]
fn encryption_and_dynamic_xfa_are_refused() {
    let enc = classic(
        &[
            pages(1),
            vec![(9, b"<</Filter/Standard/V 4/R 4>>".to_vec())],
        ]
        .concat(),
        "/Encrypt 9 0 R",
    );
    assert_eq!(
        code_both(&enc, &Limits::default()),
        ("CS-PDF-0009".into(), "CS-PDF-0009".into())
    );
    let pk = classic(
        &[
            pages(1),
            vec![(
                9,
                b"<</Filter/Adobe.PubSec/SubFilter/adbe.pkcs7.s5>>".to_vec(),
            )],
        ]
        .concat(),
        "/Encrypt 9 0 R",
    );
    assert_eq!(
        code_both(&pk, &Limits::default()),
        ("CS-PDF-0010".into(), "CS-PDF-0010".into())
    );
    let mut objs = pages(1);
    objs[0].1 =
        b"<</Type/Catalog/Pages 2 0 R/NeedsRendering true/AcroForm<</Fields[]/XFA 9 0 R>>>>"
            .to_vec();
    objs.push((9, stream("", b"<xdp/>")));
    assert_eq!(
        code_both(&classic(&objs, ""), &Limits::default()),
        ("CS-PDF-0012".into(), "CS-PDF-0012".into())
    );
    // Static XFA (a normal rendering exists) opens with a finding.
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[]/XFA 9 0 R>>>>".to_vec();
    let bytes = classic(&objs, "");
    let a = admit(&bytes, &Limits::default(), &never).unwrap();
    assert!(a.report.has_xfa && a.report.findings.iter().any(|f| f.kind == FindingKind::Xfa));
}

#[test]
fn not_a_pdf() {
    assert_eq!(
        code_both(b"", &Limits::default()),
        ("CS-PDF-0005".into(), "CS-PDF-0005".into())
    );
    assert_eq!(
        code_both(b"\x89PNG\r\n\x1a\n not a pdf", &Limits::default()),
        ("CS-PDF-0005".into(), "CS-PDF-0005".into())
    );
}

#[test]
fn output_is_deterministic() {
    let bytes = classic(&pages(3), "");
    let a = admit(&bytes, &Limits::default(), &never).unwrap().report;
    let b = admit(&bytes, &Limits::default(), &never).unwrap().report;
    assert_eq!(a, b);
}
