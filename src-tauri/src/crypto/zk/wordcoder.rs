//! WordCoder (idea from zkgram): every ciphertext byte becomes a short
//! dictionary word, so what travels through Telegram reads as a line of
//! ordinary words instead of an obvious base64 blob.

use super::wordcoder_dict::WORDS;
use std::collections::HashMap;
use std::sync::OnceLock;

fn reverse() -> &'static HashMap<&'static str, u8> {
    static MAP: OnceLock<HashMap<&'static str, u8>> = OnceLock::new();
    MAP.get_or_init(|| {
        WORDS
            .iter()
            .enumerate()
            .map(|(i, w)| (*w, i as u8))
            .collect()
    })
}

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 5);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(WORDS[*b as usize]);
    }
    out
}

/// Returns `None` as soon as one token is not a dictionary word, so normal
/// chat text is rejected cheaply.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let map = reverse();
    let mut out = Vec::with_capacity(text.len() / 4);
    for token in text.split_whitespace() {
        out.push(*map.get(token)?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
/// Telegram text length in characters for `n` payload bytes, worst case.
pub fn max_encoded_chars(n: usize) -> usize {
    // longest word has 6 chars plus one space
    n * 7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_is_a_bijection() {
        let mut seen = std::collections::HashSet::new();
        for w in WORDS.iter() {
            assert!(!w.contains(char::is_whitespace));
            assert!(seen.insert(*w), "duplicate word {}", w);
        }
    }

    #[test]
    fn roundtrip_all_bytes() {
        let bytes: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
        let text = encode(&bytes);
        assert_eq!(decode(&text).unwrap(), bytes);
        assert!(text.chars().count() <= max_encoded_chars(bytes.len()));
    }

    #[test]
    fn rejects_normal_text() {
        assert!(decode("привет, как дела?").is_none());
        assert!(decode("hello").is_none());
        assert!(decode("   ").is_none());
    }
}
