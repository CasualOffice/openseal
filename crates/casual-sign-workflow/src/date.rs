//! `date_signed` text: the server's time in the recipient's zone, in a fixed format
//! (docs/22 §6). Our own formatting, never the operating system's locale.

use casual_sign_audit::Timestamp;
use casual_sign_model::DateFormat;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `at` shifted by `offset_minutes`, in `format`; `None` when the shift leaves years
/// 0000 to 9999.
pub(crate) fn format_date(
    at: Timestamp,
    offset_minutes: i16,
    format: DateFormat,
) -> Option<String> {
    let c = at.civil(i32::from(offset_minutes))?;
    let (y, m, d) = (c.year, c.month, c.day);
    Some(match format {
        DateFormat::YyyyMmDd => format!("{y:04}-{m:02}-{d:02}"),
        DateFormat::MmDdYyyy => format!("{m:02}/{d:02}/{y:04}"),
        DateFormat::DdMmYyyy => format!("{d:02}/{m:02}/{y:04}"),
        DateFormat::DdMmYyyyDot => format!("{d:02}.{m:02}.{y:04}"),
        DateFormat::DMmmYyyy => {
            let name = usize::try_from(m)
                .ok()
                .and_then(|m| m.checked_sub(1))
                .and_then(|i| MONTHS.get(i))?;
            format!("{d} {name} {y:04}")
        }
    })
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (CLAUDE.md): a failure here is the test failing.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn formats_in_the_recipients_zone() {
        // 2026-03-07T23:30:00Z
        let t = Timestamp::parse("2026-03-07T23:30:00.000Z").unwrap();
        assert_eq!(
            format_date(t, 0, DateFormat::YyyyMmDd).unwrap(),
            "2026-03-07"
        );
        // One hour east: already the 8th.
        assert_eq!(
            format_date(t, 60, DateFormat::MmDdYyyy).unwrap(),
            "03/08/2026"
        );
        assert_eq!(
            format_date(t, -300, DateFormat::DdMmYyyy).unwrap(),
            "07/03/2026"
        );
        assert_eq!(
            format_date(t, 0, DateFormat::DdMmYyyyDot).unwrap(),
            "07.03.2026"
        );
        assert_eq!(
            format_date(t, 0, DateFormat::DMmmYyyy).unwrap(),
            "7 Mar 2026"
        );
    }
}
