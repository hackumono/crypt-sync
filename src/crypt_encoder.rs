use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{Error, ErrorKind, Read, Write};

pub trait CryptEncoder<T>: Read
where
    T: Read,
{
    /// Wrap another struct that implements `std::io::Read`.
    ///
    /// The idea is to use this wrapping functionality much like a function
    /// composition, so that we can do something like `source` is identical to
    /// `Decryptor::wrap(Encryptor::wrap(source, _), _)`.
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
}
