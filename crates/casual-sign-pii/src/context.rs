//! Context words: a match's score rises when one of its recogniser's words appears just
//! before it.
//!
//! Ported from Presidio's `LemmaContextAwareEnhancer` defaults: the five words before a
//! match (`context_prefix_count = 5`, none after), a boost of 0.35
//! (`context_similarity_factor`) and a floor of 0.4 with context
//! (`min_score_with_context_similarity`). Departures: words are runs of letters and
//! digits, lower-cased (no spaCy lemmas); a context entry matches whole words and may
//! span several ("date of birth"), Presidio's `whole_word` mode extended to phrases,
//! where its default substring mode would let "pan" match "company".

use crate::MAX_SCORE;

/// Words examined before a match.
const PREFIX_WORDS: usize = 5;
/// Bytes scanned backwards for those words, so a long word run costs a bounded amount.
const PREFIX_BYTES: usize = 160;
const BOOST: u16 = 350;
const FLOOR: u16 = 400;

/// The up-to-five words before byte `start`, lower-cased, as " w1 w2 … " with a space
/// at each end so a phrase matches as `" phrase "`.
pub(crate) fn window(text: &str, start: usize) -> String {
    let head = text.get(..start).unwrap_or("");
    let mut from = head.len().saturating_sub(PREFIX_BYTES);
    while !head.is_char_boundary(from) {
        from = from.saturating_add(1);
    }
    let scan = head.get(from..).unwrap_or("");
    let mut words: Vec<&str> = scan
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    // The first word may have been cut by the byte bound; drop it unless the scan
    // started at the beginning of the text.
    if from > 0 && !words.is_empty() {
        words.remove(0);
    }
    let keep = words.len().saturating_sub(PREFIX_WORDS);
    let mut out = String::from(" ");
    for w in words.iter().skip(keep) {
        for c in w.chars().flat_map(char::to_lowercase) {
            out.push(c);
        }
        out.push(' ');
    }
    out
}

/// Whether any of `phrases` (lower-case words separated by single spaces) appears as
/// whole words in `window`.
pub(crate) fn supports(window: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|p| {
        let mut needle = String::with_capacity(p.len().saturating_add(2));
        needle.push(' ');
        needle.push_str(p);
        needle.push(' ');
        window.contains(&needle)
    })
}

/// A pattern score raised by context, as Presidio does it.
pub(crate) fn boosted(score: u16) -> u16 {
    score.saturating_add(BOOST).clamp(FLOOR, MAX_SCORE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_five_words_before_lower_cased() {
        assert_eq!(
            window("one two three four five six seven X", 34),
            " three four five six seven "
        );
        assert_eq!(window("Date of Birth: X", 15), " date of birth ");
        assert_eq!(window("X", 0), " ");
    }

    #[test]
    fn phrases_match_whole_words_only() {
        let w = window("The company's D.O.B. field: X", 28);
        assert!(supports(&w, &["d o b"]));
        assert!(!supports(&w, &["pan"]));
        assert!(supports(
            " national insurance number ",
            &["national insurance"]
        ));
    }

    #[test]
    fn boost_and_floor() {
        assert_eq!(boosted(50), 400);
        assert_eq!(boosted(500), 850);
        assert_eq!(boosted(1000), 1000);
    }

    #[test]
    fn a_long_run_before_the_match_is_bounded() {
        let text = format!("ssn {} X", "a".repeat(10_000));
        let at = text.len() - 1;
        assert_eq!(window(&text, at), " ");
        let multibyte = format!("{}é X", "é".repeat(100));
        assert!(window(&multibyte, multibyte.len() - 1).len() < 200);
    }
}
