//! Strict standard base64 (RFC 4648 §4, padded) for the DER blobs in a trust request.
//! Not cryptography: an encoding, kept here so the module gains no dependency.

fn sextet(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c.checked_sub(b'A')?,
        b'a'..=b'z' => c.checked_sub(b'a')?.checked_add(26)?,
        b'0'..=b'9' => c.checked_sub(b'0')?.checked_add(52)?,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decode `s`, or `None` when it is not canonical padded base64.
#[must_use]
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len());
    let chunks = b.chunks_exact(4);
    let last = chunks.len().checked_sub(1);
    for (i, c) in chunks.enumerate() {
        let &[c0, c1, c2, c3] = c else { return None };
        let pad = match (c2, c3) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            _ => 0,
        };
        if pad > 0 && Some(i) != last {
            return None;
        }
        let mut n = sextet(c0)? << 18 | sextet(c1)? << 12;
        if pad < 2 {
            n |= sextet(c2)? << 6;
        }
        if pad < 1 {
            n |= sextet(c3)?;
        }
        let [_, x, y, z] = n.to_be_bytes();
        out.push(x);
        match pad {
            0 => {
                out.push(y);
                out.push(z);
            }
            1 if z == 0 => out.push(y),
            2 if y == 0 && z == 0 => {}
            _ => return None, // non-zero bits under the padding: not canonical
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decodes_the_rfc_4648_vectors() {
        for (enc, dec) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(decode(enc).as_deref(), Some(dec.as_bytes()), "{enc}");
        }
        assert_eq!(decode("+/+/").as_deref(), Some(&[0xfb, 0xff, 0xbf][..]));
    }

    #[test]
    fn refuses_what_is_not_canonical() {
        for bad in [
            "Zg", "Zg=", "Zh==", "Zm9=", "Zg==Zg==", "Zm9v\n", "Z===", "Zm 9",
        ] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }
}
