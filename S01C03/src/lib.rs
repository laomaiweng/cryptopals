#[macro_use]
extern crate lazy_static;

pub mod charfreq {
    use std::collections::HashMap;
    use std::io::Read;

    use s01c02::xor::bufxor;

    lazy_static! {
        // From: https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
        static ref MORSE_COUNT: HashMap<char, u32> = [
            ('e', 12000),
            ('t', 9000),
            ('a', 8000),
            ('i', 8000),
            ('n', 8000),
            ('o', 8000),
            ('s', 8000),
            ('h', 6400),
            ('r', 6200),
            ('d', 4400),
            ('l', 4000),
            ('u', 3400),
            ('c', 3000),
            ('m', 3000),
            ('f', 2500),
            ('w', 2000),
            ('y', 2000),
            ('g', 1700),
            ('p', 1700),
            ('b', 1600),
            ('v', 1200),
            ('k', 800),
            ('q', 500),
            ('j', 400),
            ('x', 400),
            ('z', 200),
        ].iter().copied().collect();
        pub static ref MORSE_FREQ: [f32; 26] = freq_distrib(&MORSE_COUNT);
    }

    pub fn letter_count(text: &str) -> HashMap<char, u32> {
        let mut count = HashMap::new();
        for ch in text.chars() {
            if ch.is_ascii_alphabetic() {
                let letter = ch.to_ascii_lowercase();
                *count.entry(letter).or_insert(0) += 1;
            }
        }
        count
    }

    pub fn freq_distrib(count: &HashMap<char, u32>) -> [f32; 26] {
        let mut distrib = [0f32; 26];
        let total = count.iter().fold(0, |sum, (_,c)| sum + c) as f32;
        for (letter, lcount) in count.iter() {
            let i = *letter as usize - 'a' as usize;
            distrib[i] = *lcount as f32 / total;
        }
        distrib
    }

    pub fn distrib_distance(distrib1: &[f32; 26], distrib2: &[f32; 26]) -> f32 {
        std::iter::zip(distrib1, distrib2).fold(0f32, |distance, (a, b)| distance + (a-b).powi(2))
    }

    fn xor_attempt(key: &[u8], ct: &[u8]) -> Option<(String, f32)> {
        let pt = bufxor(key, ct).ok()?;
        let text = String::from_utf8(pt).ok()?;
        let count = letter_count(&text);
        let freq = freq_distrib(&count);
        let mut distance = distrib_distance(&freq, &MORSE_FREQ);
        if text.contains(" ") {
            // Bonus if text contains spaces.
            distance /= 2.;
        }
        Some((text, distance))
    }

    pub fn bruteforce_single_xor(ciphertext: &[u8]) -> Option<(u8, String, f32)>{
        let mut best_plaintext = None;
        let mut best_distance = 26f32;
        for x in 0..=255 {
            let mut key = Vec::with_capacity(ciphertext.len());
            std::io::repeat(x).take(ciphertext.len() as u64).read_to_end(&mut key).unwrap();

            if let Some((plaintext, distance)) = xor_attempt(&key, &ciphertext) {
                if distance < best_distance {
                    best_distance = distance;
                    best_plaintext = Some((x, plaintext, distance));
                }
            }
        }
        best_plaintext
    }

    #[cfg(test)]
    mod tests {
        use s01c01::hex::hexdecode;
        use super::*;

        #[test]
        fn morse_freq() {
            for (i, freq) in MORSE_FREQ.iter().enumerate() {
                let letter = ('a' as u8 + i as u8) as char;
                println!("{}: {}", letter, freq);
            }
        }

        #[test]
        fn cryptopals() {
            let ct = hexdecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
            let (key, plaintext, distance) = bruteforce_single_xor(&ct).unwrap();
            println!("Decoded ciphertext with xor key {:#04x} (distance: {}): {}", key, distance, plaintext);
            assert_eq!(&plaintext, "Cooking MC's like a pound of bacon");
        }
    }
}
