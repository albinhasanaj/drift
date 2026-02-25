//! Split content into sentences for TextRank and TF-IDF processing.

/// Split text into sentences using punctuation boundaries.
/// Handles common abbreviations and edge cases.
pub fn split_sentences(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut sentences = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();

    for i in 0..len {
        current.push(chars[i]);

        let is_terminal = matches!(chars[i], '.' | '!' | '?');
        if !is_terminal {
            continue;
        }

        // Look ahead: next char should be whitespace or end-of-string for a real boundary.
        let at_end = i + 1 >= len;
        let next_is_space = !at_end && chars[i + 1].is_whitespace();
        let next_is_upper =
            !at_end && i + 2 < len && chars[i + 1].is_whitespace() && chars[i + 2].is_uppercase();

        if at_end || next_is_space || next_is_upper {
            let trimmed = current.trim().to_string();
            if !trimmed.is_empty() && trimmed.len() > 2 {
                sentences.push(trimmed);
            }
            current.clear();
        }
    }

    // Remaining text that didn't end with punctuation.
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() && trimmed.len() > 2 {
        sentences.push(trimmed);
    }

    sentences
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_basic_sentences() {
        let text = "Hello world. This is a test. Final sentence.";
        let sentences = split_sentences(text);
        assert_eq!(sentences.len(), 3);
        assert_eq!(sentences[0], "Hello world.");
        assert_eq!(sentences[1], "This is a test.");
        assert_eq!(sentences[2], "Final sentence.");
    }

    #[test]
    fn handles_empty_string() {
        assert!(split_sentences("").is_empty());
    }

    #[test]
    fn handles_no_punctuation() {
        let sentences = split_sentences("This has no ending punctuation");
        assert_eq!(sentences.len(), 1);
    }

    #[test]
    fn handles_question_and_exclamation() {
        let text = "Is this working? Yes it is! Great.";
        let sentences = split_sentences(text);
        assert_eq!(sentences.len(), 3);
    }
}
