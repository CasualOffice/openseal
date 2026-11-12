//! English number words: cardinals ("one thousand two hundred fifty") and the
//! ordinals a day of the month is written with ("twenty-first"), plus the
//! "thirty (30)" form contracts use to state a count twice.

/// Cardinal words below twenty.
const SMALL: [&str; 20] = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
];

/// Cardinal tens, from twenty (index 2).
const TENS: [&str; 10] = [
    "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety",
];

/// Ordinal words below twenty, from "first" (index 1).
const SMALL_ORDINALS: [&str; 20] = [
    "",
    "first",
    "second",
    "third",
    "fourth",
    "fifth",
    "sixth",
    "seventh",
    "eighth",
    "ninth",
    "tenth",
    "eleventh",
    "twelfth",
    "thirteenth",
    "fourteenth",
    "fifteenth",
    "sixteenth",
    "seventeenth",
    "eighteenth",
    "nineteenth",
];

/// Scale words, largest first, with their value.
const SCALES: [(&str, u64); 3] = [
    ("billion", 1_000_000_000),
    ("million", 1_000_000),
    ("thousand", 1_000),
];

fn small(word: &str) -> Option<u64> {
    SMALL
        .iter()
        .position(|w| *w == word)
        .and_then(|i| u64::try_from(i).ok())
}

fn tens(word: &str) -> Option<u64> {
    TENS.iter()
        .position(|w| !w.is_empty() && *w == word)
        .and_then(|i| u64::try_from(i).ok())
        .and_then(|i| i.checked_mul(10))
}

/// Splits number words on spaces and hyphens, lower-cased.
pub(super) fn split_words(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == '-')
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// A cardinal in words below one trillion: "thirty", "one hundred and twenty",
/// "one thousand two hundred fifty", "a hundred". `None` for anything that is not
/// exactly one well-formed number ("thirty twenty", "hundred one" and "" are refused).
pub(super) fn cardinal(words: &[String]) -> Option<u64> {
    #[derive(Clone, Copy, PartialEq)]
    enum Last {
        Start,
        And,
        Small,
        Tens,
        Hundred,
        Scale,
    }
    let mut total: u64 = 0;
    let mut group: u64 = 0;
    let mut last = Last::Start;
    let mut smallest_scale = u64::MAX;
    let mut seen_word = false;
    for (index, word) in words.iter().enumerate() {
        let word = word.as_str();
        if word == "and" {
            // "one hundred and five", "one thousand and one": only after a hundred or a scale.
            if !matches!(last, Last::Hundred | Last::Scale) {
                return None;
            }
            last = Last::And;
            continue;
        }
        if (word == "a" || word == "an") && index == 0 {
            // "a hundred", "a thousand": the article stands for one before a multiplier.
            group = 1;
            last = Last::Small;
            continue;
        }
        if let Some(value) = small(word) {
            // A unit may follow a tens word only when it is 1..=9 ("thirty five").
            let allowed = match last {
                Last::Start | Last::And | Last::Hundred | Last::Scale => true,
                Last::Tens => (1..=9).contains(&value),
                Last::Small => false,
            };
            if !allowed || (value == 0 && (seen_word || words.len() > 1)) {
                return None;
            }
            group = group.checked_add(value)?;
            last = Last::Small;
        } else if let Some(value) = tens(word) {
            if !matches!(last, Last::Start | Last::And | Last::Hundred | Last::Scale) {
                return None;
            }
            group = group.checked_add(value)?;
            last = Last::Tens;
        } else if word == "hundred" {
            // Only "N hundred" with N in 1..=9 ("twelve hundred" is refused: rare in agreements).
            if last != Last::Small || !(1..=9).contains(&group) {
                return None;
            }
            group = group.checked_mul(100)?;
            last = Last::Hundred;
        } else if let Some(&(_, scale)) = SCALES.iter().find(|(w, _)| *w == word) {
            if !matches!(last, Last::Small | Last::Tens | Last::Hundred)
                || group == 0
                || group >= 1000
                || scale >= smallest_scale
            {
                return None;
            }
            total = total.checked_add(group.checked_mul(scale)?)?;
            group = 0;
            smallest_scale = scale;
            last = Last::Scale;
        } else {
            return None;
        }
        seen_word = true;
    }
    if !seen_word || last == Last::And {
        return None;
    }
    total.checked_add(group)
}

/// A day of the month in ordinal words: "first", "fifteenth", "twenty-first",
/// "thirtieth". `None` outside 1..=31.
pub(super) fn ordinal_day(words: &[String]) -> Option<u32> {
    let value = match words {
        [one] => {
            if let Some(i) = SMALL_ORDINALS
                .iter()
                .position(|w| !w.is_empty() && w == one)
            {
                u32::try_from(i).ok()?
            } else if one == "twentieth" {
                20
            } else if one == "thirtieth" {
                30
            } else {
                return None;
            }
        }
        [ten, unit] => {
            let base: u32 = match ten.as_str() {
                "twenty" => 20,
                "thirty" => 30,
                _ => return None,
            };
            let unit = SMALL_ORDINALS
                .iter()
                .take(10)
                .position(|w| !w.is_empty() && w == unit)?;
            base.checked_add(u32::try_from(unit).ok()?)?
        }
        _ => return None,
    };
    (1..=31).contains(&value).then_some(value)
}

/// ASCII digits only, at most `max_digits` of them, as a number.
pub(super) fn digits(text: &str, max_digits: usize) -> Option<u64> {
    if text.is_empty() || text.len() > max_digits || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A count as an agreement writes it: digits with optional `,` grouping ("1,000"),
/// words ("thirty"), or both ("thirty (30)", "30 (thirty)"). When both are given they
/// must agree: "thirty (31)" is refused rather than guessed.
pub(super) fn count(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(open) = text.find('(') {
        let outside = text.get(..open)?.trim();
        let rest = text.get(open.checked_add(1)?..)?;
        let inside = rest.strip_suffix(')')?.trim();
        if inside.contains(['(', ')']) || outside.contains(')') {
            return None;
        }
        let a = single_count(outside)?;
        let b = single_count(inside)?;
        return (a == b).then_some(a);
    }
    single_count(text)
}

fn single_count(text: &str) -> Option<u64> {
    if text.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return grouped_digits(text);
    }
    cardinal(&split_words(text))
}

/// "1000" or "1,000": commas only in threes after a head of one to three digits.
fn grouped_digits(text: &str) -> Option<u64> {
    if !text.contains(',') {
        return digits(text, 12);
    }
    let mut parts = text.split(',');
    let head = parts.next()?;
    if head.is_empty() || head.len() > 3 {
        return None;
    }
    let mut joined = head.to_owned();
    for part in parts {
        if part.len() != 3 {
            return None;
        }
        joined.push_str(part);
    }
    digits(&joined, 12)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(text: &str) -> Option<u64> {
        cardinal(&split_words(text))
    }

    #[test]
    fn cardinals_read_as_written() {
        for (text, value) in [
            ("zero", 0),
            ("one", 1),
            ("thirty", 30),
            ("thirty-five", 35),
            ("Thirty Five", 35),
            ("one hundred", 100),
            ("a hundred", 100),
            ("one hundred and twenty", 120),
            ("three hundred sixty-five", 365),
            ("one thousand two hundred fifty", 1250),
            ("one thousand and one", 1001),
            ("two million five hundred thousand", 2_500_000),
            ("nine hundred ninety-nine billion", 999_000_000_000),
        ] {
            assert_eq!(card(text), Some(value), "{text}");
        }
    }

    #[test]
    fn malformed_cardinals_are_refused() {
        for text in [
            "",
            "and",
            "thirty twenty",
            "hundred",
            "one two",
            "five thirty",
            "thousand one",
            "one thousand one million",
            "twelve hundred",
            "zero zero",
            "one and",
            "thirty zero",
            "thirtyfive",
        ] {
            assert_eq!(card(text), None, "{text}");
        }
    }

    #[test]
    fn ordinal_days_cover_one_to_thirty_one() {
        let w = |t: &str| ordinal_day(&split_words(t));
        assert_eq!(w("first"), Some(1));
        assert_eq!(w("twelfth"), Some(12));
        assert_eq!(w("twentieth"), Some(20));
        assert_eq!(w("twenty-first"), Some(21));
        assert_eq!(w("thirtieth"), Some(30));
        assert_eq!(w("thirty first"), Some(31));
        assert_eq!(w("thirty second"), None);
        assert_eq!(w("twenty tenth"), None);
        assert_eq!(w("fortieth"), None);
    }

    #[test]
    fn counts_stated_twice_must_agree() {
        assert_eq!(count("thirty (30)"), Some(30));
        assert_eq!(count("30 (thirty)"), Some(30));
        assert_eq!(count("one thousand (1,000)"), Some(1000));
        assert_eq!(count("thirty (31)"), None);
        assert_eq!(count("thirty (30"), None);
        assert_eq!(count("(30)"), None);
        assert_eq!(count("thirty ((30))"), None);
        assert_eq!(count("1,00"), None);
        assert_eq!(count("9999999999999"), None);
    }
}
