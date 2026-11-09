//! Raw DER walking: find the exact bytes a signature covers without decoding and
//! re-encoding them (docs/31 §8: "hash signed attributes exactly as received"; `der` 0.8
//! sorts `SET OF` on decode, so a re-encoding verifier rejects a signer that wrote its set
//! out of order).

use der::{Decode, Header, Reader, SliceReader};

/// Exactly one TLV at the start of `input`; anything after it must be zero bytes (the
/// padding of a PDF `/Contents` string, docs/66 pitfall 6). Returns the TLV.
pub(crate) fn single_tlv_zero_padded(input: &[u8]) -> Option<&[u8]> {
    let mut r = SliceReader::new(input).ok()?;
    let tlv = r.tlv_bytes().ok()?;
    let rest = input.get(tlv.len()..)?;
    rest.iter().all(|&b| b == 0).then_some(tlv)
}

/// Exactly one TLV filling `input`, nothing after.
pub(crate) fn single_tlv(input: &[u8]) -> Option<&[u8]> {
    let mut r = SliceReader::new(input).ok()?;
    let tlv = r.tlv_bytes().ok()?;
    r.is_finished().then_some(tlv)
}

/// The TLVs inside one constructed TLV, in order, as raw slices of the input.
pub(crate) fn children(tlv: &[u8]) -> Option<Vec<&[u8]>> {
    let mut r = SliceReader::new(tlv).ok()?;
    let h = Header::decode(&mut r).ok()?;
    if !h.is_constructed() {
        return None;
    }
    let content = r.read_slice(h.length()).ok()?;
    if !r.is_finished() {
        return None;
    }
    let mut cr = SliceReader::new(content).ok()?;
    let mut out = Vec::new();
    while !cr.is_finished() {
        out.push(cr.tlv_bytes().ok()?);
    }
    Some(out)
}

/// The first child of a constructed TLV: the `tbs*` part of a signed X.509 structure
/// (certificate, CRL, OCSP `BasicOCSPResponse`), exactly as received.
pub(crate) fn first_child(tlv: &[u8]) -> Option<&[u8]> {
    children(tlv)?.first().copied()
}

/// The raw `[0] IMPLICIT SignedAttributes` of the only SignerInfo in a CMS
/// `ContentInfo`, retagged as `SET OF` (0x31) as RFC 5652 §5.4 requires for hashing.
/// `None` if the structure is not as expected or there are no signed attributes.
pub(crate) fn signed_attrs_as_received(content_info: &[u8]) -> Option<Vec<u8>> {
    let ci = children(content_info)?;
    let explicit = ci.get(1)?;
    let signed_data = first_child(explicit)?;
    let sd_items = children(signed_data)?;
    let signer_infos = sd_items.last()?;
    let infos = children(signer_infos)?;
    let [signer_info] = infos.as_slice() else {
        return None;
    };
    // SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs OPTIONAL, ...
    let si_items = children(signer_info)?;
    let attrs = si_items.get(3)?;
    let (&tag, rest) = attrs.split_first()?;
    if tag != 0xA0 {
        return None;
    }
    let mut v = Vec::with_capacity(attrs.len());
    v.push(0x31);
    v.extend_from_slice(rest);
    Some(v)
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_padding_is_ignored_other_trailers_refused() {
        let tlv = [0x04, 0x02, 0xAA, 0xBB];
        let mut padded = tlv.to_vec();
        padded.extend([0u8; 10]);
        assert_eq!(single_tlv_zero_padded(&padded), Some(&tlv[..]));
        padded.push(1);
        assert_eq!(single_tlv_zero_padded(&padded), None);
        assert_eq!(single_tlv(&tlv), Some(&tlv[..]));
        assert_eq!(single_tlv(&[0x04, 0x02, 0xAA, 0xBB, 0x00]), None);
    }

    #[test]
    fn children_of_primitive_is_none() {
        assert_eq!(children(&[0x04, 0x01, 0x00]), None);
        let seq = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        assert_eq!(
            children(&seq),
            Some(vec![&[0x02, 0x01, 0x01][..], &[0x02, 0x01, 0x02][..]])
        );
    }
}
