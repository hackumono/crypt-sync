use rayon::prelude::*;
use ring::digest;
use ring::pbkdf2;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Error;
use std::num::NonZeroU32;

use crate::encoder::text_decoder::*;
use crate::util::*;

const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;

const PBKDF2_NUM_ITER: u32 = 1 << 17; // 2^17 = 131,072

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

// return a len-32 hash of the given key
#[inline]
pub fn hash_key(key: &str) -> Vec<u8> {
    hash_key_custom_iter(key, PBKDF2_NUM_ITER)
}

pub fn hash_key_custom_iter(key: &str, num_iter: u32) -> Vec<u8> {
    let mut to_store: Vec<u8> = (0..CREDENTIAL_LEN).map(|_| 0).collect(); // [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        PBKDF2_ALG,
        NonZeroU32::new(num_iter).unwrap(),
        &(0..16).collect::<Vec<_>>(),
        key.as_bytes(),
        &mut to_store[..],
    );
    debug_assert_eq!(64, to_store.len());
    to_store
}

#[inline]
pub fn hash_base64_pathsafe(key: &str) -> Result<String, Error> {
    let hash = hash_key(key);
    let encoding_type = Some(EncType::BASE64_PATHSAFE);
    TextEncoder::new(&hash[..], encoding_type)?.as_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_data() -> Vec<&'static str> {
        vec!["", "a", "asf", "123", "asfoij123r98!@$%#@$Q%#$T"]
    }

    #[test]
    fn hash_is_deterministic() {
        test_data().into_par_iter().for_each(|key| {
            let set: HashSet<_> = (0..4).map(|_| hash_key_custom_iter(key, 32)).collect();
            assert_eq!(64, set.iter().nth(0).unwrap().len());
            assert_eq!(1, set.len());
        });
    }
}
