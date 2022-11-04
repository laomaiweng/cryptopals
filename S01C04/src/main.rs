use std::error::Error;

use s01c01::hex::hexdecode;
use s01c03::charfreq::bruteforce_single_xor;

fn main() -> Result<(), Box<dyn Error>> {
    let ciphertexts: Vec<_> = std::fs::read_to_string("4.txt")?
                        .lines().map(hexdecode).collect::<Result<Vec<_>, _>>()?;
    let mut best_plaintext = None;
    let mut best_distance = 26f32;
    for (i, ct) in ciphertexts.iter().enumerate() {
        if let Some((key, plaintext, distance)) = bruteforce_single_xor(ct) {
            if distance < best_distance {
                best_distance = distance;
                best_plaintext = Some((i, key, plaintext, distance));
            }
        }
    }
    if let Some((num, key, plaintext, distance)) = best_plaintext {
        println!("Best plaintext (input {}/{}, key {:#04x}, distance: {}): {}", num, ciphertexts.len(), key, distance, plaintext);
    } else {
        println!("No best plaintext!");
    }
    Ok(())
}
