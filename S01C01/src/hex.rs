// taken from https://stackoverflow.com/a/52992629/3019933

use std::fmt::{self, Write};
use std::num;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeHexError {
    OddLength(usize),
    ParseInt(num::ParseIntError),
}

impl From<num::ParseIntError> for DecodeHexError {
    fn from(e: num::ParseIntError) -> Self {
        DecodeHexError::ParseInt(e)
    }
}

impl fmt::Display for DecodeHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeHexError::OddLength(len) => write!(f, "encoded string has an odd number of bytes ({})", len),
            DecodeHexError::ParseInt(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DecodeHexError {}

pub fn hexdecode(string: &str) -> Result<Vec<u8>, DecodeHexError> {
    if string.len() % 2 != 0 {
        return Err(DecodeHexError::OddLength(string.len()));
    }

    let mut bytes = Vec::with_capacity(string.len() / 2);
    for i in (0..string.len()).step_by(2) {
        let b = u8::from_str_radix(&string[i..i+2], 16).map_err(|e| DecodeHexError::from(e))?;
        bytes.push(b);
    }
    Ok(bytes)
}

pub fn hexencode(bytes: &[u8]) -> String {
    let mut string = String::with_capacity(2 * bytes.len());
    for b in bytes {
        write!(&mut string, "{:02x}", b).unwrap();
    }
    string
}
