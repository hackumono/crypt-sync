use std::io::BufReader;
use std::io::Error;
use std::io::Read;
use zstd::stream::read::Decoder;

use crate::crypt::crypt_encoder::*;
use crate::encoder::zstd_encoder::*;

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
    pub fn new(source: R, _unused: Option<i32>) -> Result<Self, Error> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::zstd_encoder::*;
    use crate::util::*;
    use rayon::iter::ParallelBridge;
    use rayon::prelude::*;

    // make sure that f x = Decoder Encoder x = x
    #[test]
    fn parametrized() {
        (10..15)
            .map(|shl_by| 1 << shl_by)
            .par_bridge()
            .map(drng)
            .for_each(|input_bytes| {
                let result = compose_encoders!(
                    &input_bytes[..],
                    ZstdEncoder => None,
                    ZstdDecoder => None
                )
                .unwrap()
                .as_vec()
                .unwrap();

                assert_eq!(input_bytes, result);
            });
    }
}
