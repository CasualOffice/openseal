//! The commands. Each returns an exit code (see [`HELP`]); messages go to stderr,
//! reports to stdout.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use casual_sign_sdk::model::{Field, FieldType, FieldValue, Id, Text};
use casual_sign_sdk::{
    Art, Capture, Credentials, DocMdp, Engine, Fill, FlattenOptions, FontSet, FormMode, Hash256,
    Indication, Limits, NoRevocation, NoTimestamps, Profile, SdkError, SealKind, TrailOptions,
    TrustStore,
};
use serde_json::Value;

use crate::args::Parsed;
use crate::key::{DEV_REASON, FileKey, certificates};
use crate::net::{Http, HttpRevocation, HttpTsa};
use crate::output;

/// Success: admitted, written, sealed, every signature `TOTAL_PASSED`, chain valid.
pub(crate) const OK: u8 = 0;
/// Verification failed: a signature `TOTAL_FAILED`, a document error, no signature, or
/// an invalid audit chain.
pub(crate) const FAILED: u8 = 1;
/// Usage: bad arguments, an unreadable or unwritable file, a refused key file.
pub(crate) const USAGE: u8 = 2;
/// The engine refused the input; the `CS-*` code is printed.
pub(crate) const REFUSED: u8 = 3;
/// Verification indeterminate: nothing failed, but not every signature passed (no trust
/// anchor, no revocation data, an unsupported algorithm).
pub(crate) const INDETERMINATE: u8 = 4;

pub(crate) const HELP: &str = "\
openseal: the OpenSeal engine on the command line (Apache-2.0)

USAGE
  openseal admit FILE [--password P]... [--json]
      Admit FILE within docs/21's limits and print what it contains. Passwords open an
      encrypted file (each is tried as user and owner password).
  openseal normalize IN OUT [--password P]... [--json]
      Write IN as the document delivered to signers: a fresh, unencrypted file with active
      content, embedded files and external references removed. Prints its SHA-256.
      Signed input is refused (CS-PDF-0014): seal it as it is.
  openseal fill IN OUT --values values.json [--fields fields.json] [--in-place]
                [--require-complete] [--envelope-id ID] [--json]
      Convert IN's AcroForm fields, give them the values in values.json, and flatten them
      into IN as one incremental update (IN should be `normalize` output). values.json is
      an object from a field's name (its AcroForm full name, or an id from fields.json) to
      its value: a string (text, the chosen option, or a typed signature), true/false for
      a checkbox; or {\"values\": {...}, \"fields\": [...]} with OpenSeal fields placed by
      geometry (docs/22 §6 JSON). --in-place fills the form and keeps it fillable instead.
      --require-complete refuses an empty required field (CS-FLD-0001).
  openseal seal IN OUT --key KEY.pem --cert CHAIN.pem --insecure-file-key
                [--profile b-b|b-t|b-lt|b-lta] [--tsa URL]... [--trust ROOT.pem]...
                [--field NAME] [--certify p1|p2|p3] [--json]
      Seal IN with PAdES at the profile (default b-t), as an incremental update. KEY.pem
      is a PKCS#8, SEC1 or PKCS#1 key for the first certificate of CHAIN.pem (ECDSA P-256
      or P-384, or RSA). Key files are for development: refused without
      --insecure-file-key, and every such seal carries /Reason \"Development key \u{2014} not
      for production\" (docs/31 \u{a7}5). b-t and above need --tsa (RFC 3161 over HTTP;
      several are tried in order); b-lt and b-lta fetch OCSP (or CRLs) for the chain from
      the certificates' AIA and CRL distribution points. --trust roots make the self-check
      also verify the chains (TSA root included). The signing time is the system clock.
  openseal verify FILE [--trust ROOT.pem]... [--crl FILE]... [--ocsp FILE]...
                [--at UNIX_SECONDS] [--json]
      Verify every signature and document timestamp of FILE, ours or not: byte ranges,
      digests, CMS, chains to the --trust roots, revocation (DSS or the files given),
      timestamps, and every revision after each signature. Validation time: now, or --at.
  openseal audit verify TRAIL.json [--head HEX] [--envelope ID] [--count N] [--json]
      Verify an audit-trail.json: every hash, link, sequence number and time, and the head
      and count when given.
  openseal help | --help | -h      This text.
  openseal --version               The version.

EXIT CODES
  0  success (verify: every signature TOTAL_PASSED and the last covers the whole file)
  1  verification failed (a signature TOTAL_FAILED, a document error, no signature; an
     invalid audit chain)
  2  usage error (arguments, unreadable or unwritable file, refused key file)
  3  the engine refused the input: the CS-* code (docs/20) is printed
  4  verification indeterminate (nothing failed, not every signature passed)

JSON (--json, one object on stdout)
  admit:     {file, admitted, code, version, pages, revisions, objects, repaired, signed,
              docmdp, encrypted, fields, signatures, javascript_or_actions, embedded_files,
              xfa, findings:[CS-PDF codes], findings_count}; refused: {file, admitted:false,
              code, message}
  normalize: {output, sha256, objects_written, unreachable_dropped,
              removed:[{code, object}], optional_content_kept}
  fill:      {output, converted, placed, filled_in_place, drawn, not_drawn, issues:[{field,
              code}], sha256}
  seal:      {output, profile, field, byte_range, signature_timestamp, revisions_added,
              self_check, sha256}
  verify:    {file, outcome (passed|failed|indeterminate), error, revisions,
              covered_by_last_signature, signatures:[{field, value, sub_filter,
              kind:{type, docmdp}, byte_range, signed_revision, covers_whole_document,
              verdict:{indication, subindication, code}, checks:{byte_range, digest,
              signature, timestamp, chain, revocation, modifications: \"passed\" |
              \"not_run\" | {failed, code}}, validation_time, time_source, timestamp,
              modifications_after:[{revision, allowed, classes}]}]}
  audit:     {file, valid, events, envelope_id, head, problems:[{index, kind}],
              problems_dropped, unrecognised}
  error:     {error: {code, message}} with exit 2 or 3
";

fn engine() -> Engine {
    Engine::new(Limits::default(), FontSet::bundled())
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

fn read(path: &str) -> Result<Vec<u8>, u8> {
    std::fs::read(path).map_err(|e| usage(&format!("cannot read {path}: {e}")))
}

fn write(path: &str, bytes: &[u8]) -> Result<(), u8> {
    std::fs::write(path, bytes).map_err(|e| usage(&format!("cannot write {path}: {e}")))
}

fn usage(message: &str) -> u8 {
    eprintln!("openseal: {message}");
    USAGE
}

fn refused(json: bool, e: &SdkError) -> u8 {
    if json {
        println!(
            "{}",
            serde_json::json!({ "error": { "code": e.code(), "message": e.to_string() } })
        );
    }
    eprintln!("openseal: refused: {e}");
    if let SdkError::Fields(issues) = e {
        for i in issues {
            eprintln!("  field {}: {}", i.field_id.as_str(), i.code());
        }
    }
    REFUSED
}

fn credentials(p: &Parsed) -> Credentials {
    p.all("password")
        .into_iter()
        .fold(Credentials::new(), |c, pw| c.with_password(pw))
}

fn hex(h: &Hash256) -> String {
    h.hex()
}

/// Run the command line `argv` (without the program name).
pub(crate) fn run(argv: Vec<String>) -> u8 {
    let Some((cmd, rest)) = argv.split_first() else {
        eprint!("{HELP}");
        return USAGE;
    };
    let result = match cmd.as_str() {
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(OK)
        }
        "--version" | "-V" => {
            println!("openseal {}", env!("CARGO_PKG_VERSION"));
            Ok(OK)
        }
        "admit" => admit(rest),
        "normalize" => normalize(rest),
        "fill" => fill(rest),
        "seal" => seal(rest),
        "verify" => verify(rest),
        "audit" => match rest.split_first() {
            Some((sub, rest)) if sub == "verify" => audit_verify(rest),
            _ => Err(usage("expected `openseal audit verify TRAIL.json`")),
        },
        other => Err(usage(&format!(
            "unknown command `{other}`; see `openseal help`"
        ))),
    };
    result.unwrap_or_else(|code| code)
}

fn parse(argv: &[String], valued: &[&str], switches: &[&str]) -> Result<Parsed, u8> {
    Parsed::parse(argv, valued, switches).map_err(|e| usage(&e))
}

fn admit(argv: &[String]) -> Result<u8, u8> {
    let p = parse(argv, &["password"], &["json"])?;
    let [file] = p.exactly(1, "FILE").map_err(|e| usage(&e))? else {
        return Err(USAGE);
    };
    let bytes = read(file)?;
    match engine().admit(&bytes, &credentials(&p)) {
        Ok(r) => {
            let v = output::admission(file, &r);
            if p.has("json") {
                println!("{v}");
            } else {
                println!(
                    "{file}: admitted: {} page(s), PDF {}, {} revision(s), signed {}, encrypted {}, {} field(s), {} signature(s), repaired {}",
                    r.page_count,
                    v.get("version").and_then(Value::as_str).unwrap_or("-"),
                    r.revisions.len(),
                    r.is_signed(),
                    r.encryption.is_some(),
                    r.fields.len(),
                    r.signatures.len(),
                    r.repaired
                );
                if let Some(codes) = v.get("findings").and_then(Value::as_array)
                    && !codes.is_empty()
                {
                    let c: Vec<&str> = codes.iter().filter_map(Value::as_str).collect();
                    println!("  findings: {}", c.join(" "));
                }
            }
            Ok(OK)
        }
        Err(e) => {
            if p.has("json") {
                println!(
                    "{}",
                    serde_json::json!({ "file": file, "admitted": false, "code": e.code(), "message": e.to_string() })
                );
            }
            eprintln!("openseal: {file}: refused: {e}");
            Ok(REFUSED)
        }
    }
}

fn normalize(argv: &[String]) -> Result<u8, u8> {
    let p = parse(argv, &["password"], &["json"])?;
    let [input, out] = p.exactly(2, "IN OUT").map_err(|e| usage(&e))? else {
        return Err(USAGE);
    };
    let bytes = read(input)?;
    let delivered = match engine().prepare(&bytes, &credentials(&p)) {
        Ok(d) => d,
        Err(e) => return Ok(refused(p.has("json"), &e)),
    };
    write(out, &delivered.bytes)?;
    let sha = hex(&delivered.hash);
    if let Some(r) = &delivered.normalization {
        if p.has("json") {
            println!("{}", output::normalization(out, &sha, r));
        } else {
            println!(
                "{out}: normalized, sha256 {sha}, {} object(s), {} removed",
                r.objects_written,
                r.removed.len()
            );
        }
    }
    Ok(OK)
}

/// values.json: a flat object, or `{values, fields}`.
fn values_file(v: &Value) -> Result<(BTreeMap<String, Value>, Vec<Field>), String> {
    let obj = v.as_object().ok_or("values.json is not a JSON object")?;
    let (values, fields) = if obj.contains_key("values") {
        (obj.get("values"), obj.get("fields"))
    } else {
        (Some(v), None)
    };
    let values = values
        .and_then(Value::as_object)
        .ok_or("`values` is not an object")?
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let fields = match fields {
        Some(f) => serde_json::from_value(f.clone()).map_err(|e| format!("`fields`: {e}"))?,
        None => Vec::new(),
    };
    Ok((values, fields))
}

fn fill(argv: &[String]) -> Result<u8, u8> {
    let p = parse(
        argv,
        &["values", "fields", "envelope-id"],
        &["in-place", "require-complete", "json"],
    )?;
    let [input, out] = p.exactly(2, "IN OUT").map_err(|e| usage(&e))? else {
        return Err(USAGE);
    };
    let values_path = p
        .one("values")
        .map_err(|e| usage(&e))?
        .ok_or_else(|| usage("fill needs --values values.json"))?;
    let raw: Value = serde_json::from_slice(&read(values_path)?)
        .map_err(|e| usage(&format!("{values_path}: {e}")))?;
    let (mut named, mut extra) = values_file(&raw).map_err(|e| usage(&e))?;
    if let Some(path) = p.one("fields").map_err(|e| usage(&e))? {
        let f: Value =
            serde_json::from_slice(&read(path)?).map_err(|e| usage(&format!("{path}: {e}")))?;
        let more: Vec<Field> =
            serde_json::from_value(f).map_err(|e| usage(&format!("{path}: {e}")))?;
        extra.extend(more);
    }
    let bytes = read(input)?;
    let e = engine();
    let fallback = Id::new("acroform").map_err(|_| USAGE)?;
    let mut n = 0u32;
    let mut next = || {
        n = n.saturating_add(1);
        Id::new(format!("acroform-{n}")).unwrap_or_else(|_| fallback.clone())
    };
    let doc = Id::new("doc").map_err(|_| USAGE)?;
    let conversion = match e.convert_form(&bytes, &doc, &mut next) {
        Ok(c) => c,
        Err(err) => return Ok(refused(p.has("json"), &err)),
    };
    let mut fields: Vec<Field> = conversion.fields.iter().map(|c| c.field.clone()).collect();
    let placed = extra.len();
    fields.extend(extra);
    let mut values = BTreeMap::new();
    let mut captures = BTreeMap::new();
    for f in &fields {
        let by_label = f.label.as_ref().and_then(|l| named.get(l.as_str()));
        let Some(v) = named.get(f.id.as_str()).or(by_label).cloned() else {
            continue;
        };
        let value = match (f.field_type, &v) {
            (FieldType::Checkbox, Value::Bool(b)) => FieldValue::Checked(*b),
            (FieldType::Checkbox, _) | (_, Value::Bool(_)) => {
                return Err(usage(&format!(
                    "`{}`: a checkbox takes true or false, and only a checkbox does",
                    f.label.as_ref().map_or(f.id.as_str(), |l| l.as_str())
                )));
            }
            (FieldType::Signature | FieldType::Initials | FieldType::Stamp, Value::String(s)) => {
                let cap = Id::new(format!("cap-{}", f.id.as_str())).map_err(|_| USAGE)?;
                captures.insert(
                    cap.clone(),
                    Capture {
                        art: Art::Typed {
                            text: s.clone(),
                            style: 0,
                        },
                        signed_by: None,
                        reason: None,
                    },
                );
                FieldValue::Signature(cap)
            }
            (FieldType::RadioGroup | FieldType::Dropdown, Value::String(s)) => FieldValue::Choice(
                Text::new(s.clone()).map_err(|_| usage("a value is over 4,000 bytes"))?,
            ),
            (_, Value::String(s)) => FieldValue::Text(
                Text::new(s.clone()).map_err(|_| usage("a value is over 4,000 bytes"))?,
            ),
            (_, Value::Number(x)) => FieldValue::Text(
                Text::new(x.to_string()).map_err(|_| usage("a value is too long"))?,
            ),
            _ => {
                return Err(usage(&format!(
                    "the value for `{}` does not suit a {:?} field",
                    f.label.as_ref().map_or(f.id.as_str(), |l| l.as_str()),
                    f.field_type
                )));
            }
        };
        values.insert(f.id.clone(), value);
    }
    for f in &fields {
        named.remove(f.id.as_str());
        if let Some(l) = &f.label {
            named.remove(l.as_str());
        }
    }
    if let Some(unknown) = named.keys().next() {
        return Err(usage(&format!(
            "values.json names no field of the document: `{unknown}`"
        )));
    }
    let mut options = FlattenOptions::default();
    if p.has("in-place") {
        options.mode = FormMode::FillInPlace;
    }
    let fill = Fill {
        fields: &fields,
        values: &values,
        captures: &captures,
        envelope_id: p.one("envelope-id").map_err(|e| usage(&e))?,
        acroform: (!conversion.fields.is_empty()).then_some(&conversion),
        require_complete: p.has("require-complete"),
    };
    let filled = match e.fill_and_flatten(&bytes, &fill, &options) {
        Ok(f) => f,
        Err(err) => return Ok(refused(p.has("json"), &err)),
    };
    write(out, &filled.bytes)?;
    let sha = Hash256::digest(&filled.bytes).hex();
    let issues: Vec<Value> = filled
        .outcome
        .issues
        .iter()
        .map(|i| serde_json::json!({ "field": i.field_id.as_str(), "code": i.code() }))
        .collect();
    if p.has("json") {
        println!(
            "{}",
            serde_json::json!({
                "output": out,
                "converted": conversion.fields.len(),
                "placed": placed,
                "filled_in_place": filled.report.filled.len(),
                "drawn": filled.report.drawn.len(),
                "not_drawn": filled.report.not_drawn.len(),
                "issues": issues,
                "sha256": sha,
            })
        );
    } else {
        println!(
            "{out}: {} field(s) converted, {placed} placed, {} drawn, {} filled in place, {} tolerated issue(s); sha256 {sha}",
            conversion.fields.len(),
            filled.report.drawn.len(),
            filled.report.filled.len(),
            issues.len()
        );
    }
    Ok(OK)
}

fn trust_store(paths: &[&str]) -> Result<TrustStore, u8> {
    let mut t = TrustStore::new();
    for path in paths {
        for c in certificates(&read(path)?).map_err(|e| usage(&format!("{path}: {e}")))? {
            let der = der::Encode::to_der(&c).map_err(|e| usage(&format!("{path}: {e}")))?;
            t.add_anchor(&der)
                .map_err(|e| usage(&format!("{path}: {}", e.code())))?;
        }
    }
    Ok(t)
}

fn seal(argv: &[String]) -> Result<u8, u8> {
    let p = parse(
        argv,
        &[
            "key", "cert", "profile", "tsa", "trust", "field", "certify", "reason",
        ],
        &["insecure-file-key", "json"],
    )?;
    let [input, out] = p.exactly(2, "IN OUT").map_err(|e| usage(&e))? else {
        return Err(USAGE);
    };
    let key_path = p
        .one("key")
        .map_err(|e| usage(&e))?
        .ok_or_else(|| usage("seal needs --key KEY.pem"))?;
    let cert_path = p
        .one("cert")
        .map_err(|e| usage(&e))?
        .ok_or_else(|| usage("seal needs --cert CHAIN.pem"))?;
    if !p.has("insecure-file-key") {
        return Err(usage(
            "refusing a key file: file keys are for development only (docs/31 \u{a7}5); production \
             seals use keyd with an HSM or KMS. Pass --insecure-file-key to seal with it anyway; \
             the seal will say \"Development key \u{2014} not for production\".",
        ));
    }
    if p.one("reason").map_err(|e| usage(&e))?.is_some() {
        return Err(usage(&format!(
            "--reason cannot be set with a file key: the /Reason is \"{DEV_REASON}\""
        )));
    }
    let profile = match p.one("profile").map_err(|e| usage(&e))?.unwrap_or("b-t") {
        "b-b" => Profile::BaselineB,
        "b-t" => Profile::BaselineT,
        "b-lt" => Profile::BaselineLt,
        "b-lta" => Profile::BaselineLta,
        other => {
            return Err(usage(&format!(
                "unknown profile `{other}` (b-b, b-t, b-lt, b-lta)"
            )));
        }
    };
    let tsas: Vec<String> = p.all("tsa").into_iter().map(str::to_owned).collect();
    if profile >= Profile::BaselineT && tsas.is_empty() {
        return Err(usage(
            "b-t and above need --tsa URL (or choose --profile b-b)",
        ));
    }
    let kind = match p.one("certify").map_err(|e| usage(&e))? {
        None => SealKind::Approval,
        Some("p1") => SealKind::Certification { docmdp: DocMdp::P1 },
        Some("p2") => SealKind::Certification { docmdp: DocMdp::P2 },
        Some("p3") => SealKind::Certification { docmdp: DocMdp::P3 },
        Some(other) => return Err(usage(&format!("unknown --certify `{other}` (p1, p2, p3)"))),
    };
    let chain = certificates(&read(cert_path)?).map_err(|e| usage(&format!("{cert_path}: {e}")))?;
    let key =
        FileKey::load(&read(key_path)?, chain).map_err(|e| usage(&format!("{key_path}: {e}")))?;
    let trust = trust_store(&p.all("trust"))?;
    let bytes = read(input)?;
    let e = engine();
    let base = p.one("field").map_err(|e| usage(&e))?.unwrap_or("OpenSeal");
    let field = match e.free_field_name(&bytes, base) {
        Ok(f) => f,
        Err(err) => return Ok(refused(p.has("json"), &err)),
    };
    let mut request = e.seal_request(profile, &field, now());
    request.kind = kind;
    request.reason = Some(DEV_REASON.to_owned());
    request.trust = trust;
    let http = Http::new();
    let tsa = HttpTsa::new(&http, tsas);
    let revocation = HttpRevocation::new(&http);
    let sealed = match (
        profile >= Profile::BaselineT,
        profile >= Profile::BaselineLt,
    ) {
        (false, _) => e.seal(&bytes, &request, &key, &NoTimestamps, &NoRevocation),
        (true, false) => e.seal(&bytes, &request, &key, &tsa, &NoRevocation),
        (true, true) => e.seal(&bytes, &request, &key, &tsa, &revocation),
    };
    let sealed = match sealed {
        Ok(s) => s,
        Err(err) => return Ok(refused(p.has("json"), &err)),
    };
    write(out, &sealed.bytes)?;
    let r = &sealed.report;
    let sha = Hash256::digest(&sealed.bytes).hex();
    let self_check = r
        .verification
        .signatures
        .last()
        .map_or_else(|| "-".to_owned(), |s| s.indication.to_string());
    if p.has("json") {
        println!(
            "{}",
            serde_json::json!({
                "output": out,
                "profile": profile.name(),
                "field": field,
                "byte_range": r.signature.map(|l| l.byte_range),
                "signature_timestamp": r.signature_timestamp.map(|t| t.as_secs()),
                "revisions_added": r.revisions_added,
                "self_check": self_check,
                "sha256": sha,
            })
        );
    } else {
        println!(
            "{out}: sealed {} in field {field}, {} revision(s) added; self-check: {self_check}; sha256 {sha}",
            profile.name(),
            r.revisions_added
        );
    }
    Ok(OK)
}

fn verify(argv: &[String]) -> Result<u8, u8> {
    let p = parse(argv, &["trust", "crl", "ocsp", "at"], &["json"])?;
    let [file] = p.exactly(1, "FILE").map_err(|e| usage(&e))? else {
        return Err(USAGE);
    };
    let trust = trust_store(&p.all("trust"))?;
    let e = engine();
    let at = match p.one("at").map_err(|e| usage(&e))? {
        Some(s) => Duration::from_secs(
            s.parse()
                .map_err(|_| usage("--at takes seconds since 1970-01-01T00:00:00Z"))?,
        ),
        None => now(),
    };
    let mut options = e.verify_options(at);
    for path in p.all("crl") {
        options.crls.push(read(path)?);
    }
    for path in p.all("ocsp") {
        options.ocsp_responses.push(read(path)?);
    }
    let bytes = read(file)?;
    let report = e.verify(&bytes, &trust, &options);
    let failed = report.error.is_some()
        || report.signatures.is_empty()
        || report
            .signatures
            .iter()
            .any(|s| matches!(s.indication, Indication::TotalFailed(_)));
    let (outcome, code) = if report.all_passed() {
        ("passed", OK)
    } else if failed || !report.covered_by_last_signature {
        ("failed", FAILED)
    } else {
        ("indeterminate", INDETERMINATE)
    };
    if p.has("json") {
        println!("{}", output::verification(file, &report, outcome));
    } else {
        print!("{}", output::verification_text(file, &report, outcome));
    }
    Ok(code)
}

fn audit_verify(argv: &[String]) -> Result<u8, u8> {
    let p = parse(argv, &["head", "envelope", "count"], &["json"])?;
    let [file] = p.exactly(1, "TRAIL.json").map_err(|e| usage(&e))? else {
        return Err(USAGE);
    };
    let bytes = read(file)?;
    if bytes.starts_with(b"%PDF") || Path::new(file).extension().is_some_and(|x| x == "pdf") {
        return Err(usage(
            "give the audit-trail.json, not the PDF (extract the embedded file first)",
        ));
    }
    let mut options = TrailOptions::default();
    if let Some(h) = p.one("head").map_err(|e| usage(&e))? {
        let h = if h.starts_with("sha256:") {
            h.to_owned()
        } else {
            format!("sha256:{h}")
        };
        options.expected_head =
            Some(Hash256::parse(&h).map_err(|_| usage("--head is 64 lower-case hex digits"))?);
    }
    if let Some(id) = p.one("envelope").map_err(|e| usage(&e))? {
        options.envelope_id = Some(Id::new(id).map_err(|_| usage("--envelope is not an id"))?);
    }
    if let Some(n) = p.one("count").map_err(|e| usage(&e))? {
        options.expected_count = Some(n.parse().map_err(|_| usage("--count is a number"))?);
    }
    let report = engine().verify_trail(&bytes, &options);
    if p.has("json") {
        println!("{}", output::chain(file, &report));
    } else if report.is_valid() {
        println!(
            "{file}: valid, {} event(s), head {}",
            report.events,
            report.head.map_or_else(|| "-".to_owned(), |h| h.hex())
        );
    } else {
        println!("{file}: INVALID, {} problem(s)", report.problems.len());
        for pr in &report.problems {
            println!(
                "  event {}: {:?}",
                pr.index.map_or_else(|| "-".to_owned(), |i| i.to_string()),
                pr.kind
            );
        }
    }
    Ok(if report.is_valid() { OK } else { FAILED })
}
