//! Text for the certificate: dates in the account's format, masked emails, and line
//! breaking for pagination.
//!
//! Line breaking here only decides how many lines a value takes, so pages can be cut
//! before the flattener draws them. It measures with the Helvetica widths (Liberation
//! Sans, the bundled sans face, is metric-compatible) or the monospaced 600, plus a
//! margin; a character outside the table counts as a full em. If a host's face is wider
//! than measured, the flattener shrinks that one line to fit its box: text is never
//! clipped or drawn outside it.

use casual_sign_audit::Timestamp;
use casual_sign_model::DateFormat;

use crate::input::{CertificateOptions, EmailMask};

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `±hh:mm` for an offset in minutes.
fn offset_label(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let m = minutes.unsigned_abs();
    format!("UTC{sign}{:02}:{:02}", m / 60, m % 60)
}

/// The zone as printed after times.
pub(crate) fn zone(options: &CertificateOptions) -> String {
    match &options.zone_label {
        Some(z) => format!("{z} ({})", offset_label(options.utc_offset_minutes)),
        None => offset_label(options.utc_offset_minutes),
    }
}

/// A date in the account's format.
pub(crate) fn date(t: Timestamp, options: &CertificateOptions) -> String {
    let Some(c) = t.civil(options.utc_offset_minutes) else {
        return t.to_string();
    };
    let mon = usize::try_from(c.month)
        .ok()
        .and_then(|m| m.checked_sub(1))
        .and_then(|m| MONTHS.get(m))
        .copied()
        .unwrap_or("?");
    match options.date_format {
        DateFormat::MmDdYyyy => format!("{:02}/{:02}/{:04}", c.month, c.day, c.year),
        DateFormat::DdMmYyyy => format!("{:02}/{:02}/{:04}", c.day, c.month, c.year),
        DateFormat::DdMmYyyyDot => format!("{:02}.{:02}.{:04}", c.day, c.month, c.year),
        DateFormat::DMmmYyyy => format!("{} {mon} {:04}", c.day, c.year),
        _ => format!("{:04}-{:02}-{:02}", c.year, c.month, c.day),
    }
}

/// Date and time of day to the second, with the zone.
pub(crate) fn datetime(t: Timestamp, options: &CertificateOptions) -> String {
    match t.civil(options.utc_offset_minutes) {
        Some(c) => format!(
            "{} {:02}:{:02}:{:02} {}",
            date(t, options),
            c.hour,
            c.minute,
            c.second,
            zone(options)
        ),
        None => t.to_string(),
    }
}

/// An optional time, or a dash.
pub(crate) fn maybe(t: Option<Timestamp>, options: &CertificateOptions) -> String {
    t.map_or_else(|| "\u{2014}".to_owned(), |t| datetime(t, options))
}

/// An email as the account shows it.
pub(crate) fn email(address: &str, mask: EmailMask) -> String {
    match mask {
        EmailMask::Show => address.to_owned(),
        EmailMask::Hidden => "(hidden)".to_owned(),
        _ => match address.rsplit_once('@') {
            Some((local, domain)) => {
                let first: String = local.chars().take(1).collect();
                format!("{first}***@{domain}")
            }
            None => "***".to_owned(),
        },
    }
}

/// Helvetica advance widths for U+0020..U+007E, thousandths of an em (Adobe's
/// Helvetica metrics, which Liberation Sans matches).
const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278,
    278, // ' '..'/'
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // '0'..'9'
    278, 278, 584, 584, 584, 556, 1015, // ':'..'@'
    667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667,
    611, 722, 667, 944, 667, 667, 611, // 'A'..'Z'
    278, 278, 278, 469, 556, 333, // '['..'`'
    556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
    278, 556, 500, 722, 500, 500, 500, // 'a'..'z'
    334, 260, 334, 584, // '{'..'~'
];

/// Which face measures a run of text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Face {
    /// Proportional sans (Helvetica metrics).
    Sans,
    /// Monospaced, 600 per character.
    Mono,
}

/// A character's estimated advance, thousandths of an em.
fn advance(c: char, face: Face) -> f64 {
    if face == Face::Mono {
        return 600.0;
    }
    let i = u32::from(c);
    if (0x20..=0x7e).contains(&i) {
        let k = usize::try_from(i.saturating_sub(0x20)).unwrap_or(0);
        return f64::from(HELVETICA.get(k).copied().unwrap_or(1000));
    }
    // Latin-1 letters are about the width of their base letter; anything else, an em.
    if (0xc0..=0x24f).contains(&i) {
        return 722.0;
    }
    1000.0
}

/// Estimated width of `s` at `size` points, with a 3% margin.
pub(crate) fn width(s: &str, size: f64, face: Face) -> f64 {
    let em: f64 = s.chars().map(|c| advance(c, face)).sum();
    em * size / 1000.0 * 1.03
}

/// Break `text` into lines no wider than `max` points at `size`: at spaces, hard
/// breaks kept, a word wider than a line broken between characters. Never empty.
pub(crate) fn wrap(text: &str, size: f64, max: f64, face: Face) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split(' ') {
            let candidate = if line.is_empty() {
                word.to_owned()
            } else {
                format!("{line} {word}")
            };
            if width(&candidate, size, face) <= max {
                line = candidate;
                continue;
            }
            if !line.is_empty() {
                out.push(core::mem::take(&mut line));
            }
            // The word alone; broken if still too wide.
            for c in word.chars() {
                let mut next = line.clone();
                next.push(c);
                if !line.is_empty() && width(&next, size, face) > max {
                    out.push(core::mem::take(&mut line));
                    line.push(c);
                } else {
                    line = next;
                }
            }
        }
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_follow_the_account_format_and_offset() {
        let t = Timestamp::parse("2026-03-07T23:30:05.000Z").unwrap();
        let mut o = CertificateOptions::default();
        assert_eq!(datetime(t, &o), "2026-03-07 23:30:05 UTC+00:00");
        o.date_format = DateFormat::DMmmYyyy;
        o.utc_offset_minutes = 60;
        o.zone_label = Some("Europe/Paris".into());
        assert_eq!(
            datetime(t, &o),
            "8 Mar 2026 00:30:05 Europe/Paris (UTC+01:00)"
        );
        o.date_format = DateFormat::MmDdYyyy;
        o.utc_offset_minutes = -330;
        o.zone_label = None;
        assert_eq!(datetime(t, &o), "03/07/2026 18:00:05 UTC-05:30");
        o.date_format = DateFormat::DdMmYyyyDot;
        assert_eq!(date(t, &o), "07.03.2026");
        o.date_format = DateFormat::DdMmYyyy;
        assert_eq!(date(t, &o), "07/03/2026");
    }

    #[test]
    fn emails_mask_per_setting() {
        assert_eq!(email("ada@example.com", EmailMask::Show), "ada@example.com");
        assert_eq!(
            email("ada@example.com", EmailMask::Partial),
            "a***@example.com"
        );
        assert_eq!(email("ada@example.com", EmailMask::Hidden), "(hidden)");
        assert_eq!(email("no-at-sign", EmailMask::Partial), "***");
    }

    #[test]
    fn wrapping_breaks_at_spaces_and_inside_long_words() {
        let lines = wrap(
            "aaaa bbbb cccc",
            10.0,
            width("aaaa bbbb", 10.0, Face::Sans),
            Face::Sans,
        );
        assert_eq!(lines, ["aaaa bbbb", "cccc"]);
        let hex = "0123456789abcdef".repeat(4);
        let lines = wrap(&hex, 10.0, width(&hex[..8], 10.0, Face::Mono), Face::Mono);
        assert_eq!(lines.len(), 8);
        assert!(lines.iter().all(|l| l.len() == 8));
        assert_eq!(wrap("a\n\nb", 9.0, 100.0, Face::Sans), ["a", "", "b"]);
    }
}
