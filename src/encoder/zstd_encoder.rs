// use rayon::prelude::*;
// use std::io::Bytes;
// use std::io::Error;
// use std::io::Read;
//
// pub use crate::crypt::crypt_encoder::*;
// use crate::util::*;
//
// pub struct ZstdEncoder<T>
// where
//     T: Read,
// {
//     source: Bytes<T>,
// }
//
// impl<T> ZstdEncoder<T> where T: Read {}
//
// impl<T> Read for ZstdEncoder<T>
// where
//     T: Read,
// {
//     fn read(&mut self, target: &mut [u8]) -> Result<usize, Error> {
//         todo!()
//     }
// }
//
// impl<T> CryptEncoder<T> for ZstdEncoder<T>
// where
//     T: Read,
// {
//     fn wrap(source: T, hash: Option<&[u8]>) -> Result<Self, Error> {
//         todo!()
//     }
// }
