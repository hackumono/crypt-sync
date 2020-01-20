use data_encoding::Encoding;
use data_encoding_macro::*;
use rayon::prelude::*;
use std::cmp::min;
use std::collections::VecDeque;
use std::io::Bytes;
use std::io::Error;
use std::io::Read;

pub use crate::crypt::crypt_encoder::*;
use crate::util::*;

pub enum EncType {
    BASE16,
    BASE32,
    BASE64,
}

// BASE16, conforms to RFC4648; https://tools.ietf.org/search/rfc4648
const BASE16: Encoding = new_encoding! {
    symbols: "0123456789ABCDEF",
    padding: None,
};

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

/// Customizable binary-to-text encoding
pub struct TextEncoder<T>
where
    T: Read,
{
    encoding: Encoding, // what does the acutal encoding
    encoder: Box<dyn Fn(&Encoding, &[u8]) -> Result<Vec<u8>, Error>>,
    block_size: usize, // min number of input bytes that encode to a pad-less output
    source: Bytes<T>,

    // buffers to hold leftovers from ...
    src_buf: VecDeque<u8>, // input bytes from the source
    enc_buf: VecDeque<u8>, // encoded output bytes

    // a `pull` from `src` to `src_buf` happend when when `src_buf.size < block_size`
    // `src_pull_size` is the max number of bytes we can pull without forcing `src_buf` to resize
    src_pull_size: usize,
    // `src_buf_pull_size` is the max number of bytes we can pull from `src_buf` and transfer the
    // encoded content to enc_buf, without forcing `enc_buf` to resize
    src_buf_pull_size: usize, // ... `src_buf` ...
}

impl<T> TextEncoder<T>
where
    T: Read,
{
    pub fn new(source: T, enc_type: EncType) -> Result<Self, Error> {
        TextEncoder::new_custom(
            source,
            Some(match enc_type {
                EncType::BASE16 => &BASE16,
                EncType::BASE32 => &BASE32,
                EncType::BASE64 => &BASE64,
            }),
            None,
            None,
            None,
        )
    }

    ///
    ///
    /// # Paramters
    ///
    /// 1. `source`: some struct that impl's the `std::io::Read` trait, from which the unencoded
    ///    data will be read.
    /// 1. `encoding`
    /// 1. `encoder`:
    /// 1. `encoding`
    /// 1. `buf_size`: size of the buffers, in bytes. If `None` then `2048` will be used.
    pub fn new_custom(
        source: T,
        encoding: Option<&Encoding>,
        encoder: Option<Box<dyn Fn(&Encoding, &[u8]) -> Result<Vec<u8>, Error>>>,
        block_sizer: Option<Box<dyn Fn(&Encoding) -> usize>>,
        buf_size: Option<usize>,
    ) -> Result<Self, Error> {
        let encoding = encoding.map(Encoding::clone).unwrap_or(BASE16.clone());
        let encoder = encoder.unwrap_or(Box::new(|encoding, data| {
            Ok(Vec::from(encoding.encode(data).as_bytes()))
        }));

        // either use the provided, or default if None
        let buf_size = buf_size.unwrap_or(2048);
        let block_size = block_sizer.map(|f| (f)(&encoding)).unwrap_or({
            // check that the encoding has 2^n number of symbols for some n
            let symbol_count = encoding.specification().symbols.len() as f64;
            let symbol_count_log2 = symbol_count.log2();
            debug_assert!(symbol_count_log2.fract() < 1e-10);

            symbol_count_log2 as usize
        });

        // assuming that pulling happens when size < block size,
        //
        // 1. we can always pull src_pull_size number of bytes into src_buf, without having to resize src_buf
        // 2. ... src_buf_pull_size ... without having to resize enc_buf
        let src_pull_size = buf_size - block_size;
        // base32 = 5 -> 8, so shuold only pull bufsize * 5/8
        let src_buf_pull_size = buf_size * block_size / 8;

        Ok(TextEncoder {
            block_size,
            encoding,
            encoder,
            source: source.bytes(),
            enc_buf: VecDeque::with_capacity(buf_size),
            src_buf: VecDeque::with_capacity(buf_size),
            src_pull_size,
            src_buf_pull_size,
        })
    }

    /// # Returns
    ///
    /// How many bytes were pulled into `self.src_buf`. 0 implies that we have reached the end of
    /// `self.source`.
    fn replenish_src_buf(&mut self) -> Result<usize, Error> {
        debug_assert!(self.src_buf.len() < self.block_size);
        match pull(&mut self.source, self.src_pull_size)? {
            None => Ok(0), // done reading
            Some(src_bytes) => Ok(src_bytes
                .into_iter()
                .map(|byte| self.src_buf.push_back(byte))
                .count()),
        }
    }

    /// # Returns
    ///
    /// How many bytes were pulled into `self.enc_buf`. 0 implies that we have reached the end of
    /// `self.source`.
    fn replenish_enc_buf(&mut self) -> Result<usize, Error> {
        let block_count = self.src_buf.len() / self.block_size;
        let bytes_to_pull = match block_count {
            // this implies that we
            0 => self.src_buf.len() + self.replenish_src_buf()?,
            _ => block_count * self.block_size, // bytes
        };

        let bytes_to_pull = min(bytes_to_pull, self.src_buf_pull_size);

        match bytes_to_pull {
            0 => Ok(0), // done reading
            _ => {
                let bytes: Vec<u8> = (0..bytes_to_pull)
                    .map(|_| self.src_buf.pop_front())
                    .map(Option::unwrap)
                    .collect();

                Ok((self.encoder)(&self.encoding, &bytes[..])?
                    .iter()
                    .map(|b| self.enc_buf.push_back(*b))
                    .count())
            }
        }
    }
}

// read 40 bits at a time, because base32 needs 5bit, whereas a byte is 8 bits
// read 5 bytes at a time
impl<T> Read for TextEncoder<T>
where
    T: Read,
{
    fn read(&mut self, target: &mut [u8]) -> Result<usize, Error> {
        let size = target.len();

        // try pushing enc buf
        if self.enc_buf.len() == 0 {
            // try populating enc_buf
            if self.src_buf.len() == 0 {
                self.replenish_src_buf()?;
            }
            self.replenish_enc_buf()?;
        }

        // transfer as much as possible from enc_buf to target
        match target.len() {
            0 => Ok(0), // we're done can't write any
            target_capacity => {
                // cannot write more than target's capacity or what's in enc buf
                let num_bytes_to_write = min(self.enc_buf.len(), target_capacity);
                Ok((0..num_bytes_to_write)
                    .map(|_| self.enc_buf.pop_front())
                    .map(Option::unwrap)
                    .enumerate()
                    .map(|(i, byte)| target[i] = byte)
                    .count())
            }
        }
    }
}

impl<T> CryptEncoder<T> for TextEncoder<T>
where
    T: Read,
{
    fn wrap(source: T, hash: Option<&[u8]>) -> Result<Self, Error> {
        debug_assert!(hash.is_none());
        TextEncoder::new(source, EncType::BASE16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            get_test_data()
                .into_par_iter()
                .for_each(|(input, expected)| {
                    let input_bytes = input.as_bytes();
                    let result = TextEncoder::new(input_bytes, EncType::BASE16)
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
            get_test_data()
                .into_par_iter()
                .for_each(|(input, expected)| {
                    let input_bytes = input.as_bytes();
                    let result = TextEncoder::new(input_bytes, EncType::BASE32)
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
            get_test_data()
                .into_par_iter()
                .for_each(|(input, expected)| {
                    let input_bytes = input.as_bytes();
                    let result = TextEncoder::new(input_bytes, EncType::BASE64)
                        .unwrap()
                        .as_string()
                        .unwrap();

                    assert_eq!(&result[..], expected);
                });
        }
    }
}
