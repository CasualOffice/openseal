//! Canonical JSON: object keys sorted by their UTF-8 bytes, no whitespace, numbers and
//! strings as `serde_json` writes them. The same value gives the same bytes natively and
//! in WebAssembly, so verdicts can be compared byte for byte (WASM-01).

use serde_json::Value;

/// Write `v` canonically.
#[must_use]
pub(crate) fn to_canonical(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(k, out);
                out.push(':');
                if let Some(item) = map.get(k) {
                    write(item, out);
                }
            }
            out.push('}');
        }
    }
}

fn string(s: &str, out: &mut String) {
    // serde_json escapes a string the same way on every target; it cannot fail on a str.
    out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| String::from("\"\"")));
}

/// A finite `f64` as a JSON number, `null` otherwise (JSON has no NaN or infinity).
#[must_use]
pub(crate) fn float(x: f64) -> Value {
    serde_json::Number::from_f64(x).map_or(Value::Null, Value::Number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_at_every_depth_and_nothing_is_spaced() {
        let v = json!({"b": 1, "a": {"z": [true, null], "é": "x", "B": 2.5}});
        assert_eq!(
            to_canonical(&v),
            r#"{"a":{"B":2.5,"z":[true,null],"é":"x"},"b":1}"#
        );
    }

    #[test]
    fn non_finite_floats_become_null() {
        assert_eq!(float(f64::NAN), Value::Null);
        assert_eq!(float(f64::INFINITY), Value::Null);
        assert_eq!(to_canonical(&float(-0.0)), "-0.0");
        assert_eq!(to_canonical(&float(0.1)), "0.1");
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(to_canonical(&json!("a\"b\\\n\u{1}")), r#""a\"b\\\n\u0001""#);
    }
}
