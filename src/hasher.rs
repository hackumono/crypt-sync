use rayon::prelude::*;
use ring::digest;
use ring::pbkdf2;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Error;
use std::num::NonZeroU32;

use crate::encoder::text_decoder::*;
use crate::util::*;

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;
const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;

// return a len-32 hash of the given key
pub fn hash_key(key: &str) -> Vec<u8> {
    let mut to_store = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        PBKDF2_ALG,
        NonZeroU32::new(4096).unwrap(),
        &(0..16).collect::<Vec<_>>(),
        key.as_bytes(),
        &mut to_store,
    );
    to_store.into_iter().copied().collect()
}

#[inline]
pub fn hash_base64_filesafe(key: &str) -> Result<String, Error> {
    let hash = hash_key(key);
    TextEncoder::new(&hash[..], Some(EncType::BASE64))?.as_string()
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
            let set: HashSet<_> = (0..4).map(|_| hash_key(key)).collect();
            assert_eq!(64, set.iter().nth(0).unwrap().len());
            assert_eq!(1, set.len());
        });
    }
}
