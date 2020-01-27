use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::str::from_utf8;

use crate::util::*;

/// This trait helps make the encoding logic more functional.
///
/// Since `CryptEncoder` itself implements the `Read` trait, any struct that
/// impls the `Read` trait can be wrapped by in an arbitrarily many layers
/// of `CryptEncoder`s. The goal is to string together encoders much like
/// function compopsition.
///
/// For example encrypting the compressed content of a file may look something like
/// `Encryptor::wrap(Compressor::wrap(some_file))`.
pub trait CryptEncoder<R>: Read
where
    R: Read,
{
    fn write_all_to<U>(&mut self, target: &mut U) -> Result<usize, Error>
    where
        U: Write,
    {
        const BUFFER_SIZE: usize = 4096;
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

        let mut count = 0;
        Ok(loop {
            match self.read(&mut buffer[..])? {
                0 => break count, // means we are done reading
                bytes_read => {
                    target.write_all(&buffer[0..bytes_read])?;
                    count += bytes_read
                }
            }
        })
    }

    fn as_vec(&mut self) -> Result<Vec<u8>, Error> {
        let mut result: Vec<u8> = Vec::new();
        self.write_all_to(&mut result)?;
        Ok(result)
    }

    fn as_string(&mut self) -> Result<String, Error> {
        let as_vec = self.as_vec()?;
        from_utf8(&as_vec).map(String::from).map_err(io_err)
    }
}
