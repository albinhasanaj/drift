//! Content hashing via xxh3.

use xxhash_rust::xxh3::xxh3_64;

/// Compute the xxh3 64-bit hash of file content.
#[inline]
pub fn hash_content(content: &[u8]) -> u64 {
    xxh3_64(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hash() {
        let data = b"hello world";
        assert_eq!(hash_content(data), hash_content(data));
    }

    #[test]
    fn empty_content_hash() {
        let hash = hash_content(b"");
        // xxh3 of empty input is a known constant
        assert_ne!(hash, 0); // xxh3("") != 0
    }

    #[test]
    fn different_content_different_hash() {
        assert_ne!(hash_content(b"hello"), hash_content(b"world"));
    }
}
