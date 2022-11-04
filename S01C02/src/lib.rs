pub mod xor {
    use std::fmt;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum XorError {
        LengthMismatch(usize, usize),
    }

    impl fmt::Display for XorError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                XorError::LengthMismatch(a, b) => write!(f, "input lengths mismatch ({} ≠ {})", a, b),
            }
        }
    }

    impl std::error::Error for XorError {}

    pub fn bufxor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, XorError> {
        if a.len() != b.len() {
            return Err(XorError::LengthMismatch(a.len(), b.len()));
        }

        let mut out = Vec::with_capacity(a.len());
        out.extend((0..a.len()).map(|i| a[i] ^ b[i]));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::xor::*;
    use s01c01::hex::{hexencode, hexdecode};
    #[test]
    fn cryptopals() {
        let a = hexdecode("1c0111001f010100061a024b53535009181c").unwrap();
        let b = hexdecode("686974207468652062756c6c277320657965").unwrap();
        let c = bufxor(&a, &b).unwrap();
        assert_eq!(hexencode(&c), "746865206b696420646f6e277420706c6179");
    }
}
