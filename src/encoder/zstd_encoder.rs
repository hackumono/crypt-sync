use std::io::BufReader;
use std::io::Error;
use std::io::Read;
use zstd::stream::read::Encoder;

use crate::crypt::crypt_encoder::*;

const DEFAULT_ZSTD_LEVEL: u8 = 3;

const_assert!(DEFAULT_ZSTD_LEVEL <= 22);

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
    pub fn new(source: R, opt_level: Option<u8>) -> Result<Self, Error> {
        let level = opt_level.unwrap_or(DEFAULT_ZSTD_LEVEL);
        assert!(0 <= level && level <= 22);
        Ok(Self {
            encoder: Encoder::new(source, level as i32)?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::*;
    use rayon::prelude::*;

    fn test_data() -> Vec<(Vec<u8>, usize)> {
        vec![
            (drng(1 << 12), 3419),
            (drng(1 << 13), 6790),
            (drng(1 << 14), 13555),
            (drng(1 << 15), 27077),
        ]
    }

    fn test(input_bytes: Vec<u8>, expected_output_len: usize) {
        let compressed = ZstdEncoder::new(&input_bytes[..], None)
            .unwrap()
            .as_vec()
            .unwrap();

        let compressed_len = compressed.len();
        assert_eq!(expected_output_len, compressed_len);

        let ratio = compressed_len as f64 / input_bytes.len() as f64;
        assert!(0.8 < ratio && ratio < 0.85);
    }

    #[test]
    fn parametrized() {
        test_data()
            .into_par_iter()
            .for_each(|(input_bytes, expected_output_len)| {
                test(input_bytes, expected_output_len);
            });
    }
}
