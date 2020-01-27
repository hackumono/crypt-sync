use std::io::BufReader;
use std::io::Error;
use std::io::Read;
use zstd::stream::read::Decoder;

use crate::crypt::crypt_encoder::*;

pub struct ZstdDecoder<R>
where
    R: Read,
{
    decoder: Decoder<BufReader<R>>,
}

impl<R> ZstdDecoder<R>
where
    R: Read,
{
    pub fn new(source: R) -> Result<Self, Error> {
        Ok(Self {
            decoder: Decoder::new(source)?,
        })
    }
}

impl<R> Read for ZstdDecoder<R>
where
    R: Read,
{
    fn read(&mut self, target: &mut [u8]) -> Result<usize, Error> {
        self.decoder.read(target)
    }
}

impl<R> CryptEncoder<R> for ZstdDecoder<R> where R: Read {}
