use data_encoding::Encoding;
use data_encoding_macro::*;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use std::cmp::min;
use std::collections::VecDeque;
use std::io::Bytes;
use std::io::Error;
use std::io::Read;

use crate::crypt::crypt_encoder::*;
use crate::util::*;

const CUSTOM_ENCODING: Encoding = new_encoding! {
    symbols: "0123456789ABCDEFGHIJKLMNOPQRSTUV",
    padding: '_',
};

pub struct TextEncoder<T>
where
    T: Read,
{
    encoding: Encoding,
    block_size: usize, // in bytes
    source: Bytes<T>,

    // buffers to hold overflow data
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

        let symbols = encoding.specification().symbols;
        assert!((symbols.len() as f64).log2().fract() < 1e-10);

        let number_of_symbols = encoding.specification().symbols.len(); // 32
        let symbol_size_in_bits = (number_of_symbols as f64).log2() as usize; // 5
        let block_size = symbol_size_in_bits; // 5

        Ok(TextEncoder {
            block_size,
            encoding,
            source: source.bytes(),
            enc_buf: VecDeque::with_capacity(4096),
            src_buf: VecDeque::with_capacity(4096),
        })
    }

    /// # Returns
    ///
    /// How many bytes were pulled into `self.src_buf`. 0 implies that we have reached the end of
    /// `self.source`.
    fn replenish_src_buf(&mut self) -> Result<usize, Error> {
        match dbg!(pull(&mut self.source, 4096))? {
            // 4096 into some field
            // try pulling 4096 bytes
            Some(src_bytes) => {
                // push everything to the buffer
                let num_bytes = src_bytes.len();
                dbg!(src_bytes)
                    .into_iter()
                    .for_each(|byte| self.src_buf.push_back(byte));
                Ok(num_bytes)
            }
            None => Ok(0), // done reading
        }
    }

    fn replenish_enc_buf(&mut self) -> Result<usize, Error> {
        let block_count = self.src_buf.len() / self.block_size;
        let bytes_to_pull = match block_count {
            // this implies that we
            0 => self.src_buf.len() + self.replenish_src_buf()?,
            _ => block_count * self.block_size, // bytes
        };

        match bytes_to_pull {
            0 => Ok(0), // done reading
            _ => {
                let bytes: Vec<u8> = (0..bytes_to_pull)
                    .map(|_| self.src_buf.pop_front())
                    .map(Option::unwrap)
                    .collect();

                Ok(self
                    .encoding
                    .encode(&dbg!(bytes)[..])
                    .as_bytes()
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
        let size = dbg!(target.len());

        // try pushing enc buf
        if dbg!(self.enc_buf.len()) == 0 {
            // try populating enc_buf
            if dbg!(self.src_buf.len()) == 0 {
                self.replenish_src_buf()?;
            }
            self.replenish_enc_buf()?;
        }

        // transfer as much as possible from enc_buf to target
        match dbg!(target.len()) {
            0 => Ok(0), // we're done can't write any
            target_capacity => {
                // cannot write more than target's capacity or what's in enc buf
                let num_bytes_to_write = min(target_capacity, self.enc_buf.len());
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
        use std::str;

        #[test]
        fn no_padding() {
            let src = "aspfoksd".as_bytes();

            let enc: Vec<u8> = dbg!(TextEncoder::new(src, None).unwrap().all_to_vec().unwrap());
            let encoded_str = dbg!(str::from_utf8(&enc));

            assert_eq!(src.len() * 8 / 5, enc.len());
            assert!(false);
            // pub fn new(source: T, encoding: Option<&Encoding>) -> Result<Self, Error> {
        }
    }
}
