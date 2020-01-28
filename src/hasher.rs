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

const DEFAULT_SALT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

const_assert!(CREDENTIAL_LEN == 64);

/// Hash input with default configs; calls `hash_custom` internally.
///
/// # Parameters
///
/// 1. `key`: the input bytes to hash
///
/// # Returns
///
/// `key` hashed with `DEFAULT_SALT` as salt, iterating `PBKDF2_NUM_ITER` times.
#[inline]
pub fn hash(key: &[u8]) -> Vec<u8> {
    hash_custom(key, None, None)
}

/// Hash input with custom configs, using PBKDF2 with SHA512 internally.
///
/// # Parameters
///
/// 1. `key`: the input bytes to hash
/// 1. `opt_salt`: salt to use; `DEFAULT_SALT` is used if `None`
/// 1. `opt_num_iter`: number of PBKDF2 iterations; `PBKDF2_NUM_ITER` is used if `None`
///
/// # Returns
///
/// `key` hashed optionally with `opt_salt` optionally `opt_num_iter` times.
pub fn hash_custom(key: &[u8], opt_salt: Option<&[u8]>, opt_num_iter: Option<u32>) -> Vec<u8> {
    let num_iter = opt_num_iter.unwrap_or(PBKDF2_NUM_ITER);

    // if salt is long enough, use the first 16 bytes
    // if salt is not long enough, hash it and use the first 16 bytes
    // else use default salt
    let salt: Vec<u8> = match opt_salt {
        Some(s) if s.len() >= 16 => Vec::from(&s[..16]),
        Some(s) => hash_custom(s, None, Some(1)).into_iter().take(16).collect(),
        None => Vec::from(&DEFAULT_SALT[..]),
    };
    debug_assert_eq!(16, salt.len());

    let mut to_store = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        PBKDF2_ALG,
        NonZeroU32::new(num_iter).unwrap(),
        &salt[..],
        key,
        &mut to_store[..],
    );

    Vec::from(&to_store[..])
}

/// Hash input with default configs and encode it with path-safe BASE64; calls `hash` internally.
///
/// Path-safe encoding here is BASE64 that conforms to RFC4648, https://tools.ietf.org/search/rfc4648,
/// with `/` replaced with `-`.
#[inline]
pub fn hash_base64_pathsafe(key: &[u8]) -> Result<String, Error> {
    let hash = hash(key);
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
            let set: HashSet<_> = (0..4)
                .map(|_| hash_custom(key.as_bytes(), None, Some(32)))
                .collect();
            assert_eq!(64, set.iter().nth(0).unwrap().len());
            assert_eq!(1, set.len());
        });
    }
}
