//! Bitcoin addresses: Base58Check (legacy P2PKH and P2SH) and Bech32/Bech32m (SegWit),
//! each with its own checksum, written from the Bitcoin specifications (Base58Check as
//! in Bitcoin Core's `base58.cpp` documentation; BIP 173 and BIP 350 for Bech32 and
//! Bech32m). Ethereum's EIP-55 checksum needs Keccak-256, which is not in the
//! workspace, so Ethereum addresses are not recognised (docs/33 §5.4).
//!
//! Each function takes a short ASCII candidate (at most 90 bytes by its pattern) and
//! returns `false`, never panics, on anything else.

use sha2::{Digest, Sha256};

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A legacy Bitcoin address: Base58 decoding to 25 bytes, version 0x00 (P2PKH) or
/// 0x05 (P2SH), and the first four bytes of SHA-256(SHA-256(version and payload)) as
/// its last four.
pub(crate) fn base58check(address: &[u8]) -> bool {
    if address.len() > 35 {
        return false;
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(25);
    for &c in address {
        let Some(v) = BASE58.iter().position(|&a| a == c) else {
            return false;
        };
        // Big-endian multiply by 58 and add; `carry` stays below 58 * 256 + 58.
        let mut carry = u32::try_from(v).unwrap_or(u32::MAX);
        for b in bytes.iter_mut().rev() {
            carry = carry.wrapping_add(u32::from(*b).wrapping_mul(58));
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
        if bytes.len() > 25 {
            return false;
        }
    }
    let zeros = address.iter().take_while(|&&c| c == b'1').count();
    let mut full = vec![0u8; zeros];
    full.extend_from_slice(&bytes);
    if full.len() != 25 || !matches!(full.first(), Some(0x00 | 0x05)) {
        return false;
    }
    let (payload, check) = full.split_at(21);
    let digest = Sha256::digest(Sha256::digest(payload));
    digest.get(..4) == Some(check)
}

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// A SegWit address on Bitcoin's main network (`bc1…`): one case throughout, at most
/// 90 characters, the Bech32 checksum for witness version 0 and Bech32m for 1 to 16,
/// and a witness program of the length its version requires (BIP 141, 173, 350).
pub(crate) fn segwit(address: &[u8]) -> bool {
    if address.len() > 90 || address.len() < 14 {
        return false;
    }
    let lower = address.iter().any(u8::is_ascii_lowercase);
    let upper = address.iter().any(u8::is_ascii_uppercase);
    if lower && upper {
        return false;
    }
    let addr: Vec<u8> = address.iter().map(u8::to_ascii_lowercase).collect();
    let Some(sep) = addr.iter().rposition(|&c| c == b'1') else {
        return false;
    };
    let (hrp, rest) = addr.split_at(sep);
    if hrp != b"bc" {
        return false;
    }
    let mut data = Vec::with_capacity(rest.len());
    for &c in rest.get(1..).unwrap_or(&[]) {
        let Some(v) = BECH32.iter().position(|&a| a == c) else {
            return false;
        };
        data.push(u8::try_from(v).unwrap_or(0));
    }
    if data.len() < 7 {
        return false;
    }
    let expanded = hrp
        .iter()
        .map(|c| c >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.iter().map(|c| c & 31))
        .chain(data.iter().copied());
    let constant = polymod(expanded);
    let Some((&version, body)) = data.split_first() else {
        return false;
    };
    let program_5bit = body.get(..body.len().saturating_sub(6)).unwrap_or(&[]);
    let wanted = if version == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };
    if version > 16 || constant != wanted {
        return false;
    }
    let Some(program_len) = program_bytes(program_5bit) else {
        return false;
    };
    match version {
        0 => program_len == 20 || program_len == 32,
        _ => (2..=40).contains(&program_len),
    }
}

/// The byte length of a 5-bit group sequence regrouped into 8-bit bytes, as BIP 173's
/// `convertbits` without padding: `None` when more than 4 bits are left over or the
/// leftover bits are not zero.
fn program_bytes(groups: &[u8]) -> Option<usize> {
    let bits = groups.len().checked_mul(5)?;
    let pad = bits % 8;
    if pad > 4 {
        return None;
    }
    if pad > 0 {
        let last = *groups.last()?;
        let mask = (1u8 << pad).wrapping_sub(1);
        if last & mask != 0 {
            return None;
        }
    }
    Some(bits / 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58check_known_values() {
        // The Bitcoin wiki's example addresses.
        assert!(base58check(b"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        assert!(base58check(b"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
        assert!(!base58check(b"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"));
        assert!(!base58check(b"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN0"));
        assert!(!base58check(b""));
    }

    #[test]
    fn segwit_known_values() {
        // BIP 173 and BIP 350 test vectors.
        assert!(segwit(b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(segwit(b"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"));
        assert!(segwit(
            b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        ));
        assert!(!segwit(b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"));
        assert!(!segwit(b"bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        // Version 0 with a Bech32m checksum (BIP 350 invalid vector).
        assert!(!segwit(b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"));
    }
}
