use std::io::BufReader;
use std::io::Error;
use std::io::Read;
use zstd::stream::read::Encoder;

use crate::crypt::crypt_encoder::*;

pub struct ZstdEncoder<R>
where
    R: Read,
{
    encoder: Encoder<BufReader<R>>,
}

impl<R> ZstdEncoder<R>
where
    R: Read,
{
    pub fn new(source: R) -> Result<Self, Error> {
        Self::new_custom(source, Some(3))
    }

    pub fn new_custom(source: R, opt_level: Option<i32>) -> Result<Self, Error> {
        let level = opt_level.unwrap_or(3);
        Ok(Self {
            encoder: Encoder::new(source, level)?,
        })
    }
}

impl<R> Read for ZstdEncoder<R>
where
    R: Read,
{
    fn read(&mut self, target: &mut [u8]) -> Result<usize, Error> {
        self.encoder.read(target)
    }
}

impl<R> CryptEncoder<R> for ZstdEncoder<R> where R: Read {}
