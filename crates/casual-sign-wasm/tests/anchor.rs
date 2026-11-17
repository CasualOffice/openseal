//! `verify_anchor` (`FG-158`, docs/32 §5): the Verify page's anchor-proof check over
//! `fixtures/anchor` (written by `casual-sign-sdk`'s `gen_anchor` example). A valid proof
//! passes with its TSA's name and time, a tampered one fails with the check that caught
//! it, and every verdict is the facade's (`verify_anchor_proof`, what `openseal anchor
//! verify` runs), so the browser cannot say more than the CLI.

// Tests may unwrap and index their own fixtures (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use casual_sign_sdk::TrustStore;
use casual_sign_sdk::anchor::{AnchorOutcome, verify_anchor_proof};
use casual_sign_wasm::api::verify_anchor;
use serde_json::Value;

const PROOF: &[u8] = include_bytes!("../../../fixtures/anchor/anchor-proof.json");
const TRAIL: &[u8] = include_bytes!("../../../fixtures/anchor/audit-trail.json");
const ROOT_PEM: &str = include_str!("../../../fixtures/anchor/trust-root.pem");
const ROOT_DER: &[u8] = include_bytes!("../../../fixtures/anchor/trust-root.der");

/// The PEM's base64 body: the trust JSON's anchor.
fn root_b64() -> String {
    ROOT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect()
}

fn trust_json(with_root: bool) -> String {
    if with_root {
        format!(r#"{{"validation_time":0,"anchors":["{}"]}}"#, root_b64())
    } else {
        r#"{"validation_time":0}"#.to_owned()
    }
}

/// `verify_anchor`'s answer under `ok`, after checking the facade gives the same outcome.
fn checked(proof: &[u8], trail: &[u8], with_root: bool) -> Value {
    let out: Value =
        serde_json::from_str(&verify_anchor(proof, trail, &trust_json(with_root))).unwrap();
    let ok = out.get("ok").unwrap_or_else(|| panic!("{out}")).clone();
    let mut trust = TrustStore::new();
    if with_root {
        trust.add_anchor(ROOT_DER).unwrap();
    }
    let sdk = verify_anchor_proof(proof, (!trail.is_empty()).then_some(trail), &trust).unwrap();
    let want = match sdk.outcome() {
        AnchorOutcome::Passed => "passed",
        AnchorOutcome::Failed => "failed",
        AnchorOutcome::Indeterminate => "indeterminate",
    };
    assert_eq!(ok["outcome"], want, "the facade's verdict: {ok}");
    assert_eq!(
        ok["tsa_time"].as_u64(),
        sdk.timestamp.gen_time.map(|d| d.as_secs())
    );
    ok
}

fn text(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

#[test]
fn a_valid_proof_passes_with_its_trail_and_names_the_tsa_and_its_time() {
    let v = checked(PROOF, TRAIL, true);
    assert_eq!(v["outcome"], "passed");
    assert_eq!(v["inclusion"]["status"], "passed");
    assert_eq!(v["timestamp"]["status"], "passed");
    assert_eq!(v["tsa_chain"]["status"], "passed");
    assert_eq!(v["trail"]["status"], "passed");
    assert_eq!(v["envelope_id"], "0193f000-0000-7000-8000-00000000e001");
    assert_eq!(v["anchor"]["period"], "2026-11-16");
    assert_eq!(v["tsa_name"], "T-1G Test TSA");
    // 2026-11-17T00:10:00Z, the token's own time.
    assert_eq!(v["tsa_time"], 1_794_874_200);
    // Without the trail it still passes; the trail check did not run.
    let v = checked(PROOF, b"", true);
    assert_eq!(v["outcome"], "passed");
    assert_eq!(v["trail"]["status"], "not_run");
}

#[test]
fn without_a_trusted_root_the_proof_is_indeterminate() {
    let v = checked(PROOF, TRAIL, false);
    assert_eq!(v["outcome"], "indeterminate");
    assert_eq!(v["timestamp"]["status"], "passed");
    assert_eq!(v["tsa_chain"]["status"], "failed");
    assert_eq!(v["tsa_chain"]["code"], "CS-VER-0004");
}

#[test]
fn a_tampered_head_fails_inclusion_and_the_trail() {
    let p = text(PROOF);
    let head = serde_json::from_str::<Value>(&p).unwrap()["head"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut forged_head = head.clone().into_bytes();
    let last = forged_head.len() - 1;
    forged_head[last] = if forged_head[last] == b'0' {
        b'1'
    } else {
        b'0'
    };
    let forged = p.replace(&head, std::str::from_utf8(&forged_head).unwrap());
    assert_ne!(forged, p);
    let v = checked(forged.as_bytes(), TRAIL, true);
    assert_eq!(v["outcome"], "failed");
    assert_eq!(v["inclusion"]["code"], "CS-AUD-0009");
    assert_eq!(v["trail"]["code"], "CS-AUD-0012");
}

#[test]
fn a_proof_for_another_event_of_the_trail_fails_the_trail_check() {
    let p = text(PROOF);
    let v: Value = serde_json::from_str(&p).unwrap();
    let seq = v["seq"].as_u64().unwrap();
    let forged = p.replace(&format!("\"seq\":{seq}"), "\"seq\":0");
    assert_ne!(forged, p);
    let v = checked(forged.as_bytes(), TRAIL, true);
    assert_eq!(v["outcome"], "failed");
    assert_eq!(v["inclusion"]["status"], "passed");
    assert_eq!(v["trail"]["code"], "CS-AUD-0012");
}

#[test]
fn a_tampered_token_fails_the_timestamp() {
    let p = text(PROOF);
    let v: Value = serde_json::from_str(&p).unwrap();
    let token = v["anchor"]["timestamp_token"].as_str().unwrap();
    // Flip one hex digit in the token's signature (its last bytes).
    let mut t = token.as_bytes().to_vec();
    let i = t.len() - 3;
    t[i] = if t[i] == b'a' { b'b' } else { b'a' };
    let forged = p.replace(token, std::str::from_utf8(&t).unwrap());
    assert_ne!(forged, p);
    let v = checked(forged.as_bytes(), b"", true);
    assert_eq!(v["outcome"], "failed");
    assert_eq!(v["timestamp"]["status"], "failed");
    assert_eq!(v["tsa_name"], Value::Null);
}

#[test]
fn a_file_that_is_not_a_proof_is_refused_with_a_code() {
    for (proof, trust) in [
        (&b"not json"[..], trust_json(true)),
        (
            &br#"{"format":"openseal.anchor","v":1}"#[..],
            trust_json(true),
        ),
        (PROOF, r#"{"validation_time":0,"extra":1}"#.to_owned()),
    ] {
        let out = verify_anchor(proof, b"", &trust);
        let v: Value = serde_json::from_str(&out).unwrap();
        let code = v["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("{out}"));
        assert!(
            code.starts_with("CS-AUD-") || code == "CS-API-0001",
            "{out}"
        );
    }
}
