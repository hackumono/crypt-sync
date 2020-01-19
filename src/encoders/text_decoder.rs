use data_encoding::Encoding;
use data_encoding_macro::*;
use rayon::prelude::*;
use std::cmp::min;
use std::collections::VecDeque;
use std::io::Bytes;
use std::io::Error;
use std::io::Read;

use crate::crypt::crypt_encoder::*;
use crate::encoders::text_encoder::*;
use crate::util::*;

/// Customizable binary-to-text encoding
pub struct TextDecoder<T>
where
    T: Read,
{
    decoder: TextEncoder<T>,
}

impl<T> TextDecoder<T>
where
    T: Read,
{
    pub fn new(source: T, encoding: Option<&Encoding>) -> Result<Self, Error> {
        Ok(TextDecoder {
            decoder: TextEncoder::new_custom(
                source,
                encoding,
                Some(Box::new(|encoding, data| {
                    Ok(Vec::from(encoding.decode(data).map_err(io_err)?))
                })),
                Some(Box::new(|encoding| {
                    // check that the encoding has 2^n number of symbols for some n
                    let symbol_count = encoding.specification().symbols.len() as f64;
                    let symbol_count_log2 = symbol_count.log2();
                    debug_assert!(symbol_count_log2.fract() < 1e-10);

                    (symbol_count_log2 as usize) * 8
                })),
                None,
            )?,
        })
    }
}

impl<T> Read for TextDecoder<T>
where
    T: Read,
{
    fn read(&mut self, target: &mut [u8]) -> Result<usize, Error> {
        self.decoder.read(target)
    }
}

impl<T> CryptEncoder<T> for TextDecoder<T>
where
    T: Read,
{
    fn wrap(source: T, hash: Option<&[u8]>) -> Result<Self, Error> {
        debug_assert!(hash.is_none());
        TextDecoder::new(source, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BASE32, conforms to RFC4648; https://tools.ietf.org/search/rfc4648
    const BASE32: Encoding = new_encoding! {
        symbols: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        padding: '=',
    };

    // BASE64, conforms to RFC4648; https://tools.ietf.org/search/rfc4648
    const BASE64: Encoding = new_encoding! {
        symbols: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        padding: '=',
    };

    #[cfg(test)]
    mod base16 {
        use super::*;
        use std::str;

        fn get_test_data() -> Vec<(&'static str, &'static str)> {
            vec![
                ("", ""),
                ("a", "61"),
                ("b", "62"),
                ("ab", "6162"),
                (
                    "asoidjhxlkdjfad;:| !@$#^&*(_][",
                    "61736F69646A68786C6B646A6661643B3A7C20214024235E262A285F5D5B",
                ),
            ]
        }

        #[test]
        fn parametrized() {
            get_test_data().into_iter().for_each(|(expected, input)| {
                let input_bytes = input.as_bytes();
                let result = TextDecoder::new(input_bytes, None)
                    .unwrap()
                    .as_string()
                    .unwrap();

                assert_eq!(&result[..], expected);
            });
        }
    }

    #[cfg(test)]
    mod base32 {
        use super::*;
        use std::str;

        fn get_test_data() -> Vec<(&'static str, &'static str)> {
            // generated with base32 in GNU coreutils
            vec![
                ("a", "ME======"),
                ("b", "MI======"),
                ("ab", "MFRA===="),
                ("abc", "MFRGG==="),
                ("abcd", "MFRGGZA="),
                (
                    "asoidjhxlkdjfad;:| !@$#^&*(_][",
                    "MFZW62LENJUHQ3DLMRVGMYLEHM5HYIBBIASCGXRGFIUF6XK3",
                ),
            ]
        }

        #[test]
        fn parametrized() {
            get_test_data().into_iter().for_each(|(expected, input)| {
                let input_bytes = input.as_bytes();
                let result = TextDecoder::new(input_bytes, Some(&BASE32))
                    .unwrap()
                    .as_string()
                    .unwrap();

                assert_eq!(&result[..], expected);
            });
        }
    }

    #[cfg(test)]
    mod base64 {
        use super::*;
        use std::str;

        fn get_test_data() -> Vec<(&'static str, &'static str)> {
            // generated with base64 in GNU coreutils
            vec![
                ("a", "YQ=="),
                ("b", "Yg=="),
                ("ab", "YWI="),
                ("abc", "YWJj"),
                ("abcd", "YWJjZA=="),
                (
                    "asoidjhxlkdjfad;:| !@$#^&*(_][",
                    "YXNvaWRqaHhsa2RqZmFkOzp8ICFAJCNeJiooX11b",
                ),
            ]
        }

        #[test]
        fn parametrized() {
            get_test_data().into_iter().for_each(|(expected, input)| {
                let input_bytes = input.as_bytes();
                let result = TextDecoder::new(input_bytes, Some(&BASE64))
                    .unwrap()
                    .as_string()
                    .unwrap();

                assert_eq!(&result[..], expected);
            });
        }
    }
}
