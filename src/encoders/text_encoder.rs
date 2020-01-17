use data_encoding::{Encoding, Specification};
use openssl::symm::{Cipher, Crypter, Mode};
use rayon::prelude::*;
use std::cmp::min;
use std::collections::VecDeque;
use std::fs::{read_to_string, File};
use std::io::{Bytes, Error, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::str;

use crate::crypt::crypt_encoder::*;
use crate::encoders::cryptor::*;
use crate::util::*;

lazy_static! {
    static ref CUSTOM_ENCODING: Encoding = {
        let symbols = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
        debug_assert_eq!(32, symbols.len());
        make_encoding(symbols, Some('_'))
    };
}

pub struct TextEncoder<T>
where
    T: Read,
{
    encoding: Encoding,
    source: Bytes<T>,
    exchange_block_size: usize, // in bytes
    src_buf: VecDeque<u8>,
    enc_buf: VecDeque<u8>, // push_back, pop_front
}

impl<T> TextEncoder<T>
where
    T: Read,
{
    pub fn new(source: T, encoding: Option<&Encoding>) -> Result<Self, Error> {
        let encoding = match encoding {
            Some(enc) => enc.clone(),
            None => CUSTOM_ENCODING.clone(),
        };

        let number_of_symbols = encoding.specification().symbols.len(); // 32
        let symbol_size_in_bits = (number_of_symbols as f64).log2() as usize; // 5
        let exchange_block_size = symbol_size_in_bits; // 5

        Ok(TextEncoder {
            exchange_block_size,
            encoding,
            source: source.bytes(),
            enc_buf: VecDeque::with_capacity(4096),
            src_buf: VecDeque::with_capacity(4096),
        })
    }
}

// read 40 bits at a time, because base32 needs 5bit, whereas a byte is 8 bits
// read 5 bytes at a time
impl<T> Read for TextEncoder<T>
where
    T: Read,
{
    fn read(&mut self, mut target: &mut [u8]) -> Result<usize, Error> {
        let size = dbg!(target.len());

        // try pushing enc buf
        if dbg!(self.enc_buf.len()) == 0 {
            // try populating enc_buf
            if dbg!(self.src_buf.len()) == 0 {
                match dbg!(pull(&mut self.source, 4096))? {
                    // try pulling 4096 bytes
                    Some(src_bytes) => {
                        // push everything to the buffer
                        dbg!(src_bytes)
                            .into_iter()
                            .for_each(|byte| self.src_buf.push_back(byte));
                    }
                    None => return Ok(0), // done with everything
                }
            }

            // now that src_buf has been populated, populate enc buf
            let num_blocks = dbg!(self.src_buf.len() / self.exchange_block_size);
            let bytes_to_pull = dbg!(num_blocks * self.exchange_block_size);

            let bytes: Vec<u8> = dbg!(self.src_buf.iter().cloned().take(bytes_to_pull).collect());
            (0..bytes_to_pull).for_each(|_| {
                self.src_buf.pop_front().unwrap(); // unwrap should nevre fail
            });
            // populate enc buf now
            let encoded: String = dbg!(self.encoding.encode(&bytes[..]));
            (&encoded[..])
                .as_bytes()
                .iter()
                .for_each(|&b| self.enc_buf.push_back(b));
        }

        // transfer as much as possible from enc_buf to target
        match dbg!(target.len()) {
            0 => Ok(0), // we're done
            target_capacity => {
                // cannot write more than target's capacity or what's in enc buf
                let to_write = min(target_capacity, self.enc_buf.len());
                (0..to_write).for_each(|index| {
                    // unwrap here should never panic
                    target[index] = self.enc_buf.pop_front().unwrap();
                });
                Ok(to_write) // this many were written
            }
        }
    }
}

impl<T> CryptEncoder<T> for TextEncoder<T>
where
    T: Read,
{
    fn wrap(source: T, hash: Option<&[u8]>) -> Result<Self, Error> {
        unimplemented!()
        /*match hash {
            Some(key_hash) => Self::new(source, key_hash),
            None => panic!("aposkj"), // TODO later
        }*/
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod impl_read {
        use super::*;

        #[test]
        fn no_padding() {
            let src = "aspfoksd".as_bytes();
            let encoded = TextEncoder::new(src, None).unwrap().all_to_vec().unwrap();

            dbg!(str::from_utf8(&encoded));
            assert_eq!(vec![12], encoded);

            // pub fn new(source: T, encoding: Option<&Encoding>) -> Result<Self, Error> {
        }
    }
}
