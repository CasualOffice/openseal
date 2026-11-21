//! The revisions of a document with remote-provider signatures (ADR-046 §3.2), built
//! with the engine alone: final values flattened, the lock point's form materialized
//! (R0), each remote signer's fill-in-place revision and their signature through
//! `prepare`/`complete` (the test key standing in for the provider's `signHash`), later
//! fills, and the platform seal last. Shared by `tests/remote_revisions.rs` and the
//! `gen_sealed` example (`fixtures/sealed/remote-csc-*.pdf`), each including it beside
//! `common` (it needs `casual-sign-flatten`, which other users of `common` lack).

use std::collections::BTreeMap;

use casual_sign_crypto::KeyProvider;
use casual_sign_flatten::{
    Art, Capture, FillMaterialized, FlattenInput, FlattenOptions, FontSet, SignatureAppearance,
    SignatureSlot, SlotAppearance, fill_materialized, flatten, materialize,
};
use casual_sign_model::{Field, FieldType, FieldValue, Id, Placement, Points, Text};
use casual_sign_pdf::{Limits, admit};
use casual_sign_seal::{
    Appearance, CompleteOptions, ExternalSigner, Profile, Rect, SealRequest, Sealed,
    TimestampSource, Visible, complete, prepare, seal,
};
use rust_decimal::Decimal;

use crate::common::*;

fn never() -> bool {
    false
}

fn pts(v: i64) -> Points {
    Points::new(Decimal::from(v)).unwrap()
}

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

/// A field of `kind` for `recipient` at displayed `(x, y)`, `w` × `h`, on page 1.
pub fn field(fid: &str, recipient: &str, kind: FieldType, at: (i64, i64, i64, i64)) -> Field {
    let mut f = Field::new(
        id(fid),
        id("doc-1"),
        kind,
        Placement::new(1, pts(at.0), pts(at.1), pts(at.2), pts(at.3)).unwrap(),
    );
    f.recipient_id = Some(id(recipient));
    f
}

/// Which envelope to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// r0 simple (finished before the lock point), r1 remote, r2 simple.
    SimpleRemoteSimple,
    /// r1 remote, r2 simple, r3 remote.
    TwoRemote,
}

/// What the build left at each step, for assertions.
pub struct Built {
    /// The final file.
    pub bytes: Vec<u8>,
    /// The file right after the first remote signature (and its DSS).
    pub after_first_remote: Vec<u8>,
    /// A materialized field of a later signer, for tampering tests.
    pub later_field: Field,
}

fn captures(names: &[(&str, &str)]) -> BTreeMap<Id, Capture> {
    names
        .iter()
        .map(|(cap, name)| {
            (
                id(cap),
                Capture {
                    art: Art::Typed {
                        text: (*name).to_owned(),
                        style: 0,
                    },
                    signed_by: Some((*name).to_owned()),
                    reason: None,
                },
            )
        })
        .collect()
}

fn text(s: &str) -> FieldValue {
    FieldValue::Text(Text::new(s).unwrap())
}

fn fill(
    bytes: &[u8],
    fields: &[Field],
    values: &BTreeMap<Id, FieldValue>,
    caps: &BTreeMap<Id, Capture>,
    signature: Option<SignatureAppearance<'_>>,
    fonts: &FontSet,
) -> casual_sign_flatten::Filled {
    let mut a = admit(bytes, &Limits::default(), &never).unwrap();
    fill_materialized(
        &mut a,
        &FillMaterialized {
            fields,
            values,
            captures: caps,
            envelope_id: None,
            signature,
        },
        fonts,
        &FlattenOptions::default(),
        &never,
    )
    .unwrap()
}

/// A remote signature on the unsigned field `slot`: prepare, the "provider" signs the
/// prepared attributes, complete at B-LT (B-T then the DSS at once, ADR-046 §3.6).
pub fn remote_sign(
    bytes: &[u8],
    slot: &str,
    appearance: Option<SlotAppearance>,
    key: &TestProvider,
    tsa: &dyn TimestampSource,
    rev: &TestRevocation,
) -> Sealed {
    let mut r = SealRequest::new(Profile::BaselineLt, slot, SIGNING_TIME);
    r.trust = trust();
    r.visible = appearance.map(|a| Visible {
        page: 0,
        rect: Rect {
            llx: 0.0,
            lly: 0.0,
            urx: 0.0,
            ury: 0.0,
        },
        appearance: Appearance::Content {
            content: a.content(),
            resources: Some(a.resources()),
        },
    });
    let signer = ExternalSigner {
        chain: key.certificate_chain().to_vec(),
        algorithm: key.algorithm(),
    };
    let p = prepare(bytes, &r, &signer, tsa.token_len_bound()).unwrap();
    let value = key.sign(&p.signed_attributes).unwrap();
    complete(
        &p,
        value.as_bytes(),
        tsa,
        rev,
        &CompleteOptions {
            trust: trust(),
            limits: Limits::default(),
        },
    )
    .unwrap()
}

/// Build `scenario`, the platform seal at `platform` last.
pub fn build(scenario: Scenario, platform: Profile) -> Built {
    let fonts = FontSet::bundled();
    let tsa = TestTsa::new(SIGNING_TIME);
    let rev = TestRevocation::default();
    let input = one_page("Agreement between the parties");
    let caps = captures(&[
        ("cap-r0", "Ada Simple"),
        ("cap-r1", "Ben Remote"),
        ("cap-r2", "Cy Simple"),
        ("cap-r3", "Di Remote"),
    ]);
    let sig = |cap: &str| FieldValue::Signature(id(cap));

    // The first remote signer, the later ones, and the fields of each.
    let r0 = [
        field("r0-name", "r0", FieldType::Text, (72, 60, 200, 18)),
        field("r0-sig", "r0", FieldType::Signature, (300, 50, 180, 40)),
    ];
    let r1_sig = field("r1-sig", "r1", FieldType::Signature, (72, 120, 180, 40));
    let r1_date = field("r1-note", "r1", FieldType::Text, (300, 130, 200, 18));
    let r2 = [
        field("r2-name", "r2", FieldType::Text, (72, 200, 200, 18)),
        field("r2-sig", "r2", FieldType::Signature, (300, 190, 180, 40)),
        field("r2-ok", "r2", FieldType::Checkbox, (72, 230, 14, 14)),
    ];
    let r3_sig = field("r3-sig", "r3", FieldType::Signature, (72, 280, 180, 40));
    let r3_title = field("r3-title", "r3", FieldType::Text, (300, 290, 200, 18));

    let mut values: BTreeMap<Id, FieldValue> = BTreeMap::new();
    values.insert(id("r0-name"), text("Ada Simple"));
    values.insert(id("r0-sig"), sig("cap-r0"));
    values.insert(id("r1-note"), text("Approved for Ben"));
    values.insert(id("r2-name"), text("Cy Simple"));
    values.insert(id("r2-sig"), sig("cap-r2"));
    values.insert(id("r2-ok"), FieldValue::Checked(true));
    values.insert(id("r3-title"), text("Director"));

    // R0, first half: every value already final flattened into page content: the
    // finished simple signer's, and the lock-point signer's own fields other than the
    // signature their widget shows.
    let mut final_fields: Vec<Field> = vec![r1_date.clone()];
    if scenario == Scenario::SimpleRemoteSimple {
        final_fields.extend(r0.iter().cloned());
    }
    let flat = {
        let mut a = admit(&input, &Limits::default(), &never).unwrap();
        flatten(
            &mut a,
            &FlattenInput {
                fields: &final_fields,
                values: &values,
                captures: &caps,
                envelope_id: None,
                acroform: None,
            },
            &fonts,
            &FlattenOptions::default(),
            &never,
        )
        .unwrap()
        .bytes
    };
    // R0, second half: the unfinished fields materialized, an unsigned signature field
    // per remote signer.
    let mut later: Vec<Field> = r2.to_vec();
    let mut slots = vec![SignatureSlot {
        name: "Remote_r1",
        at: Some(&r1_sig),
    }];
    if scenario == Scenario::TwoRemote {
        later.push(r3_title.clone());
        slots.push(SignatureSlot {
            name: "Remote_r3",
            at: Some(&r3_sig),
        });
    }
    let r0_bytes = {
        let mut a = admit(&flat, &Limits::default(), &never).unwrap();
        materialize(&mut a, &later, &slots, &never).unwrap()
    };

    // R1: the first remote signer's widget, then their signature.
    let cap_r1 = id("cap-r1");
    let r1_fill = fill(
        &r0_bytes,
        &[],
        &values,
        &caps,
        Some(SignatureAppearance {
            slot: "Remote_r1",
            field: &r1_sig,
            capture: &cap_r1,
        }),
        &fonts,
    );
    let after_first_remote = remote_sign(
        &r1_fill.bytes,
        "Remote_r1",
        r1_fill.signature,
        &p256(),
        &tsa,
        &rev,
    )
    .bytes;

    // r2 finishes; in the two-remote envelope r3 signs next, with r2's values filled in
    // the same revision as r3's own.
    let mut bytes = after_first_remote.clone();
    if scenario == Scenario::TwoRemote {
        let cap_r3 = id("cap-r3");
        let mut filled: Vec<Field> = r2.to_vec();
        filled.push(r3_title.clone());
        let r3_fill = fill(
            &bytes,
            &filled,
            &values,
            &caps,
            Some(SignatureAppearance {
                slot: "Remote_r3",
                field: &r3_sig,
                capture: &cap_r3,
            }),
            &fonts,
        );
        bytes = remote_sign(
            &r3_fill.bytes,
            "Remote_r3",
            r3_fill.signature,
            &rsa(),
            &tsa,
            &rev,
        )
        .bytes;
    } else {
        // At completion: the last fill, for values after the last remote signature.
        bytes = fill(&bytes, &r2, &values, &caps, None, &fonts).bytes;
    }
    // The platform seal, last, over everything.
    let mut r = SealRequest::new(platform, "OpenSealSeal", SIGNING_TIME);
    r.name = Some("OpenSeal test platform".into());
    r.reason = Some("Agreement completed".into());
    r.trust = trust();
    let sealed = seal(&bytes, &r, &p256_below_root(), &tsa, &rev).unwrap();
    Built {
        bytes: sealed.bytes,
        after_first_remote,
        later_field: r2[0].clone(),
    }
}

/// Draw `field`'s value into page content after a remote signature: the change every
/// validator must refuse (ADR-046 §1 fact 2).
pub fn page_content_change(bytes: &[u8], field: &Field) -> Vec<u8> {
    let fonts = FontSet::bundled();
    let mut values = BTreeMap::new();
    values.insert(field.id.clone(), text("Changed after signing"));
    let caps = BTreeMap::new();
    let mut a = admit(bytes, &Limits::default(), &never).unwrap();
    let mut options = FlattenOptions::default();
    options.mode = casual_sign_flatten::FormMode::FillInPlace;
    flatten(
        &mut a,
        &FlattenInput {
            fields: core::slice::from_ref(field),
            values: &values,
            captures: &caps,
            envelope_id: None,
            acroform: None,
        },
        &fonts,
        &options,
        &never,
    )
    .unwrap()
    .bytes
}
