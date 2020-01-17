use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{Error, ErrorKind, Read, Write};

/// This trait helps make the encoding logic more functional.
///
/// Since `CryptEncoder` itself implements the `Read` trait, any struct that
/// impls the `Read` trait can be wrapped by in an arbitrarily many layers
/// of `CryptEncoder`s. The goal is to string together encoders much like
/// function compopsition.
///
/// For example encrypting the compressed content of a file may look something like
/// `Encryptor::wrap(Compressor::wrap(some_file))`.
pub trait CryptEncoder<T>: Read
where
    T: Read,
{
    /// Wrap another struct that implements `std::io::Read`.
    ///
    /// # Parameters
    /// 1. `source`
    /// 1. `key`
    fn wrap(source: T, key: Option<&[u8]>) -> Result<Self, Error>
    where
        Self: std::marker::Sized;

    fn write_all_to<U>(&mut self, target: &mut U, buf_size: Option<usize>) -> Result<usize, Error>
    where
        U: Write,
    {
        let buf_size = match buf_size {
            Some(0) | None => 4096,
            Some(bs) => bs,
        };
        let mut buffer: Vec<u8> = (0..buf_size).map(|us| us as u8).collect();
        let mut count = 0;
        loop {
            match self.read(&mut buffer[..])? {
                0 => break,
                bytes_read => {
                    target.write_all(&mut buffer[0..bytes_read])?;
                    count += bytes_read;
                }
            }
        }
        Ok(count)
    }

    fn all_to_vec(&mut self) -> Result<Vec<u8>, Error> {
        let mut result: Vec<u8> = Vec::new();
        self.write_all_to(&mut result, None)?;
        Ok(result)
    }
}
