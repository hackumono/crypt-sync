use openssl::symm::Cipher;
use openssl::symm::Crypter;
use openssl::symm::Mode;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use std::io::Bytes;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;

use crate::crypt::crypt_encoder::*;
use crate::encoder::text_encoder::*;
use crate::hasher::*;
use crate::util::*;

const INITIALIZATION_VECTOR: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// create Encryptor and Decryptor, because they differ only by the
/// struct name and the openssl::symm::Mode that is used
macro_rules! cryptor {
    // `$struct_name` => Encryptor | Decryptor | ..
    // `$crypter_mode` => MODE::Encrypt | MODE::Decrypt
    ( $struct_name:ident, $crypter_mode:expr ) => {
        pub struct $struct_name<T>
        where
            T: Read,
        {
            block_size: usize, // used by `openssl::symm::Crypter`
            encoder: Crypter,  // what does the actual work
            source: Bytes<T>,  // wrap around `T` as `Bytes` for ease of use
        }

        impl<T> $struct_name<T>
        where
            T: Read,
        {
            /// `wrap` just calls this method
            ///
            /// # Parameters
            ///
            /// - `source`: some struct that impls `std::io::Read` that this struct wraps around
            /// - `key_hash`: length-32 hash to be used as a key for (en|de)cryption
            pub fn new(source: T, key_hash: &[u8]) -> Result<Self, Error> {
                assert!(key_hash.len() >= 32);

                let cipher = Cipher::aes_256_cfb128();
                Ok(Self {
                    block_size: cipher.block_size(), // see `fn read` in `impl Read` for why this is needed
                    source: source.bytes(),          // using `Bytes` for convenience

                    encoder: Crypter::new(
                        cipher,
                        $crypter_mode, // one of openssl::symm::Mode
                        &key_hash[..32],
                        Some(&INITIALIZATION_VECTOR),
                    )
                    .map_err(|err| err!("{}", err))?,
                })
            }
        }

        impl<T> Read for $struct_name<T>
        where
            T: Read,
        {
            fn read(&mut self, target: &mut [u8]) -> Result<usize, Error> {
                // `update` panics if `output.len() < input.len() + block_size`
                //                    `output.len() - block_size  < input.len()`
                //  when target.len() - self.block_size == 0, input size is set to 1
                //  still don't understand the implications of target.len() being 1
                let input_size = std::cmp::max(1, target.len() - self.block_size);
                if input_size == 1 {
                    assert_eq!(1, self.block_size);
                }

                // assume that 4096 bytes always produce > 0 number of ciphertext bytes
                assert!(input_size > 0);
                match pull(&mut self.source, input_size)? {
                    None => Ok(0), // done reading
                    Some(buffer) => {
                        match self.encoder.update(&buffer, target).map_err(io_err)? {
                            0 => {
                                // if 0, assume that we are done so finalize the encoder
                                assert_eq!(None, pull(&mut self.source, input_size).unwrap());
                                self.encoder.finalize(&mut target[..]).map_err(io_err)
                            }
                            bytes_read => Ok(bytes_read),
                        }
                    }
                }
            }
        }

        impl<T> CryptEncoder<T> for $struct_name<T> where T: Read {}
    };
}

cryptor!(Encryptor, Mode::Encrypt);

cryptor!(Decryptor, Mode::Decrypt);

/// Compose multiple CryptEncoders, just like function composing.
///
/// # Examples
///
/// ```
/// #[macro_use]
/// extern crate cryptor;
///
/// // identity encoding, which decrypts what was just encrypted
/// let root: Vec<u8> = (0..64).collect();
/// let key: &[u8] = "some password".as_bytes();
/// let cryptor = compose_encoders!(
///     &root[..],
///     Encryptor => Some(key),
///     Decryptor => Some(key),
/// );
///
/// todo!();
/// ```
macro_rules! compose_encoders {
    ( $root:expr, $( $crypt_encoder:ident => $key:expr ),* ) => {{
        let cryptor = Ok($root);
        $(
            let cryptor = match cryptor {
                Ok(c) => $crypt_encoder::new(c, $key),
                Err(err) => Err(err),
            };
        )*
        cryptor
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::Path;

    const HASH_NUM_ITER: u32 = 1 << 8; // 2^8 = 256

    fn test_data() -> Vec<(&'static str, &'static str, Vec<u8>)> {
        vec![
            // empty key nonempty data
            (
                "",
                "1 !asd9-1!#$@",
                vec![33, 9, 248, 59, 13, 239, 43, 217, 185, 216, 192, 208, 187],
            ),
            // empty key empty data
            ("", "", vec![]),
            // nonempty key empty data
            ("12-39uaszASD!@ z", "", vec![]),
            // nonempty key nonempty data
            (
                "12-39uaszASD!@ z",
                "1 !asd9-1!#$@",
                vec![218, 83, 210, 197, 203, 154, 242, 186, 200, 27, 161, 220, 10],
            ),
            // nonempty key long data
            (
                "12-39uaszASD!@ z",
                "1 !asd9-1!#$@aoij!@#$ *((_Z!)  !@#$poaksfpokasopdkop12@#!@$@#&(Q%AWDSF(U",
                vec![
                    218, 83, 210, 197, 203, 154, 242, 186, 200, 27, 161, 220, 10, 12, 105, 153, 6,
                    221, 43, 132, 21, 227, 30, 63, 82, 180, 160, 20, 246, 62, 67, 97, 59, 0, 147,
                    118, 76, 226, 124, 167, 164, 119, 241, 241, 134, 24, 223, 151, 228, 90, 202,
                    81, 191, 150, 86, 27, 37, 183, 105, 242, 91, 179, 97, 77, 194, 20, 207, 194,
                    192, 193, 32, 132,
                ],
            ),
        ]
    }

    macro_rules! encoder_pure {
        ( $fn_name:ident, $( $crypt_encoder:ident ),* ) => {
            fn $fn_name(unhashed_key: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
                let key_hash = hash_key_custom_iter(unhashed_key, HASH_NUM_ITER);

                compose_encoders!(
                    data,
                    $( $crypt_encoder => &key_hash[..] ),*
                ).unwrap().as_vec()
            }
        };
    }

    encoder_pure!(encrypt_pure, Encryptor);

    encoder_pure!(decrypt_pure, Decryptor);

    encoder_pure!(identity_pure, Encryptor, Decryptor);

    #[test]
    fn parametrized_encrypt() {
        test_data()
            .into_par_iter()
            .for_each(|(unhashed_key, data, expected_ciphertext)| {
                let data_bytes = data.as_bytes();

                let ciphertext = encrypt_pure(unhashed_key, data_bytes).unwrap();
                assert_eq!(expected_ciphertext, ciphertext);
                if data_bytes.len() > 0 {
                    assert_ne!(data_bytes, &ciphertext[..]);
                }
            });
    }

    #[test]
    fn parametrized_decrypt() {
        test_data()
            .into_par_iter()
            .for_each(|(unhashed_key, data, expected_ciphertext)| {
                let data_bytes = data.as_bytes();
                if data_bytes.len() > 0 {
                    assert_ne!(data_bytes, &expected_ciphertext[..]);
                }

                let decrypted = decrypt_pure(unhashed_key, &expected_ciphertext[..]).unwrap();
                assert_eq!(data_bytes, &decrypted[..]);
            });
    }

    #[test]
    fn parametrized_wrap_identitity() {
        test_data()
            .into_par_iter()
            .for_each(|(unhashed_key, data, expected_ciphertext)| {
                let data_bytes = data.as_bytes();
                if data_bytes.len() > 0 {
                    assert_ne!(data_bytes, &expected_ciphertext[..]);
                }

                let result = identity_pure(unhashed_key, data_bytes).unwrap();
                assert_eq!(data_bytes, &result[..]);
            });
    }

    #[test]
    fn identitity() -> Result<(), Error> {
        let key_hash =
            hash_key_custom_iter(&format!("soamkle!$@random key{}", line!()), HASH_NUM_ITER);

        find(Path::new("./src/"))
            .par_bridge()
            .map(Result::unwrap)
            .filter(|path_buf| path_buf.as_path().is_file())
            .map(|src| -> Result<(), Error> {
                let cryptor = compose_encoders!(
                    File::open(&src).unwrap(),
                    Encryptor => &key_hash,
                    Decryptor => &key_hash
                );

                let result = cryptor?.as_vec()?;

                let mut expected = Vec::new();
                File::open(&src)?.read_to_end(&mut expected)?;

                Ok(assert_eq!(expected, result))
            })
            .for_each(Result::unwrap);
        Ok(())
    }
}
