use std::io::Read;

use s01c01::hex::hexdecode;
use s01c02::xor::bufxor;

use whatlang::{self, Lang};

fn decrypt_attempt(key: &[u8], ct: &[u8]) -> Result<(String, f64), ()> {
    let pt = bufxor(key, ct).unwrap();
    let text = String::from_utf8(pt).map_err(|_| ())?;
    let info = whatlang::detect(&text).ok_or(())?;
    if info.lang() != Lang::Eng { return Err(()); }

    Ok((text, info.confidence()))
}

fn main() -> Result<(), ()> {
    let ct = hexdecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

    let mut best_pair = None;
    let mut best_confidence = 0f64;
    for x in 0..=255 {
        let mut key = Vec::with_capacity(ct.len());
        std::io::repeat(x).take(ct.len() as u64).read_to_end(&mut key).unwrap();

        if let Ok((text, confidence)) = decrypt_attempt(&key, &ct) {
            if best_confidence < confidence {
                best_confidence = confidence;
                best_pair = Some((x, text));
            }
        }
    }

    let (key, text) = best_pair.ok_or(())?;
    println!("Decoded ciphertext with xor key {:#x} (confidence: {}): {}", key, best_confidence, text);
    (&text == "Cooking MC's like a pound of bacon").then_some(()).ok_or(())
}
