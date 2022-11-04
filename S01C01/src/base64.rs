use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeBase64Error {
    BadLength(usize),
    ParseChar(u8),
}

impl fmt::Display for DecodeBase64Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeBase64Error::BadLength(len) => write!(f, "encoded string length ({}) is not a multiple of 4", len),
            DecodeBase64Error::ParseChar(ch) => write!(f, "invalid Base64 character ({})", *ch as char),
        }
    }
}

impl std::error::Error for DecodeBase64Error {}

const B64_MASK: u32 = 0x3f;
const B64_PAD: u8 = b'=';
const B64_A2B: [Option<u8>; 256] = [
        None,     None,     None,     None,     None,     None,     None,     None,  //  0- 7
        None,     None,     None,     None,     None,     None,     None,     None,  //  8- f
        None,     None,     None,     None,     None,     None,     None,     None,  // 10-17
        None,     None,     None,     None,     None,     None,     None,     None,  // 18-1f
        None,     None,     None,     None,     None,     None,     None,     None,  // 20-27
        None,     None,     None, Some(62),     None,     None,     None, Some(63),  // 28-2f
    Some(52), Some(53), Some(54), Some(55), Some(56), Some(57), Some(58), Some(59),  // 30-37
    Some(60), Some(61),     None,     None,     None,     None,     None,     None,  // 38-3f
        None,  Some(0),  Some(1),  Some(2),  Some(3),  Some(4),  Some(5),  Some(6),  // 40-47
     Some(7),  Some(8),  Some(9), Some(10), Some(11), Some(12), Some(13), Some(14),  // 48-4f
    Some(15), Some(16), Some(17), Some(18), Some(19), Some(20), Some(21), Some(22),  // 50-57
    Some(23), Some(24), Some(25),     None,     None,     None,     None,     None,  // 58-5f
        None, Some(26), Some(27), Some(28), Some(29), Some(30), Some(31), Some(32),  // 60-67
    Some(33), Some(34), Some(35), Some(36), Some(37), Some(38), Some(39), Some(40),  // 68-6f
    Some(41), Some(42), Some(43), Some(44), Some(45), Some(46), Some(47), Some(48),  // 70-77
    Some(49), Some(50), Some(51),     None,     None,     None,     None,     None,  // 78-7f
        None,     None,     None,     None,     None,     None,     None,     None,  // 80-87
        None,     None,     None,     None,     None,     None,     None,     None,  // 88-8f
        None,     None,     None,     None,     None,     None,     None,     None,  // 90-97
        None,     None,     None,     None,     None,     None,     None,     None,  // 98-9f
        None,     None,     None,     None,     None,     None,     None,     None,  // a0-a7
        None,     None,     None,     None,     None,     None,     None,     None,  // a8-af
        None,     None,     None,     None,     None,     None,     None,     None,  // b0-b7
        None,     None,     None,     None,     None,     None,     None,     None,  // b8-bf
        None,     None,     None,     None,     None,     None,     None,     None,  // c0-c7
        None,     None,     None,     None,     None,     None,     None,     None,  // c8-cf
        None,     None,     None,     None,     None,     None,     None,     None,  // d0-d7
        None,     None,     None,     None,     None,     None,     None,     None,  // d8-df
        None,     None,     None,     None,     None,     None,     None,     None,  // e0-e7
        None,     None,     None,     None,     None,     None,     None,     None,  // e8-ef
        None,     None,     None,     None,     None,     None,     None,     None,  // f0-f7
        None,     None,     None,     None,     None,     None,     None,     None,  // f8-ff
];
const B64_B2A: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
];

pub fn b64decode(string: &str) -> Result<Vec<u8>, DecodeBase64Error> {
    let string = string.as_bytes();
    if string.len() % 4 != 0 {
        return Err(DecodeBase64Error::BadLength(string.len()));
    }

    let bytes_len = 3 * string.len() / 4;
    let mut bytes = Vec::with_capacity(bytes_len);
    for chunk in string.chunks_exact(4) {
        let mut bits = 24;
        let mut padded = bytes.len() == bytes_len - 3;  // Padding can only occur for the last chunk.
        let mut dword = 0;
        // Parse chars from the end of the chunk so we can ignore padding.
        for i in (0..4).rev() {
            if !padded || chunk[i] != B64_PAD {
                padded = false;
                // Decode the char.
                let b = B64_A2B[chunk[i] as usize].ok_or(DecodeBase64Error::ParseChar(chunk[i]))? as u32;
                dword |= b << (24 - (i+1)*6);
            } else {
                // Padding character, less bits to decode.
                bits -= 6;
            }
        }
        // Reinterpret the dword as bytes, and tack the valid (not padded) ones to the back of
        // our decoded bytes.
        let nbytes = bits / 8;
        bytes.extend((0..nbytes).map(|i| (dword >> (24 - (i+1)*8)) as u8));
    }
    Ok(bytes)
}

pub fn b64encode(bytes: &[u8]) -> String {
    let mut string = String::with_capacity((bytes.len() * 4 + 2) / 3);
    for chunk in bytes.chunks(3) {
        let mut bits = 24;
        let a = chunk[0];
        // Each missing char (in the last chunk) reduces the amount of bits available.
        let b = if chunk.len() > 1 { chunk[1] } else {
            bits -= 8;
            0
        };
        let c = if chunk.len() > 2 { chunk[2] } else {
            bits -= 8;
            0
        };
        let dword = (c as u32) | ((b as u32) << 8) | ((a as u32) << 16);
        let nchars = (bits + 5) / 6;  // Round the number of chars up, otherwise we'd loose info on the last byte.
        string.extend((0..nchars).map(|i| B64_B2A[((dword >> (24 - (i+1)*6)) & B64_MASK) as usize]));
        string.extend((nchars..4).map(|_| '='));
    }
    string
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wikipedia_encode() {
        assert_eq!(b64encode(b"Many hands make light work."), "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");
    }

    #[test]
    fn wikipedia_encode_padding() {
        assert_eq!(b64encode(b"Man"), "TWFu");
        assert_eq!(b64encode(b"Ma"), "TWE=");
        assert_eq!(b64encode(b"M"), "TQ==");

        assert_eq!(b64encode(b"light work."), "bGlnaHQgd29yay4=");
        assert_eq!(b64encode(b"light work"), "bGlnaHQgd29yaw==");
        assert_eq!(b64encode(b"light wor"), "bGlnaHQgd29y");
        assert_eq!(b64encode(b"light wo"), "bGlnaHQgd28=");
        assert_eq!(b64encode(b"light w"), "bGlnaHQgdw==");
    }

    #[test]
    fn wikipedia_decode() {
        assert_eq!(&b64decode("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu").unwrap(), b"Many hands make light work.");
    }

    #[test]
    fn wikipedia_decode_padding() {
        assert_eq!(&b64decode("TWFu").unwrap(), b"Man");
        assert_eq!(&b64decode("TWE=").unwrap(), b"Ma");
        assert_eq!(&b64decode("TQ==").unwrap(), b"M");

        assert_eq!(&b64decode("bGlnaHQgd29yay4=").unwrap(), b"light work.");
        assert_eq!(&b64decode("bGlnaHQgd29yaw==").unwrap(), b"light work");
        assert_eq!(&b64decode("bGlnaHQgd29y").unwrap(), b"light wor");
        assert_eq!(&b64decode("bGlnaHQgd28=").unwrap(), b"light wo");
        assert_eq!(&b64decode("bGlnaHQgdw==").unwrap(), b"light w");
    }
}
