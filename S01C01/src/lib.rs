pub mod hex;
pub mod base64;

#[cfg(test)]
mod tests {
    use crate::hex::hexdecode;
    use crate::base64::b64encode;

    #[test]
    fn cryptopals() {
        assert_eq!(b64encode(&hexdecode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap()),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }
}
