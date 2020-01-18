use openssl::symm::Cipher;
use openssl::symm::Crypter;
use openssl::symm::Mode;
use std::io::Bytes;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;

use crate::crypt::crypt_encoder::*;
use crate::util::*;

lazy_static! {
    static ref INITIALIZATION_VECTOR: Vec<u8> = { (0..16).collect() };
}

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
            fn new(source: T, key_hash: &[u8]) -> Result<Self, Error> {
                assert_eq!(32, key_hash.len());

                let cipher = Cipher::aes_256_cfb128();
                Ok(Self {
                    block_size: cipher.block_size(), // see `fn read` in `impl Read` for why this is needed
                    source: source.bytes(),          // using `Bytes` for convenience

                    encoder: Crypter::new(
                        cipher,
                        $crypter_mode, // one of openssl::symm::Mode
                        key_hash,
                        Some(&INITIALIZATION_VECTOR), // declared with `lazy_static!` at the top
                    )
                    .map_err(|err| error_other!("{}", err))?,
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

        impl<T> CryptEncoder<T> for $struct_name<T>
        where
            T: Read,
        {
            fn wrap(source: T, hash: Option<&[u8]>) -> Result<Self, Error> {
                match hash {
                    Some(key_hash) => Self::new(source, key_hash),
                    None => panic!("aposkj"), // TODO later
                }
            }
        }
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
/// unimplemented!();
/// ```
macro_rules! compose_encoders {
    ( $root:expr, $( $crypt_encoder:ident => $key:expr ),* ) => {{
        let cryptor = $root;
        $(
            let cryptor = $crypt_encoder::wrap(cryptor, $key)?;
        )*
        cryptor
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::Path;

    fn test_data() -> Vec<(&'static str, &'static str, Vec<u8>)> {
        vec![
            // empty key nonempty data
            (
                "",
                "1 !asd9-1!#$@",
                vec![139, 251, 56, 203, 88, 150, 55, 76, 231, 180, 185, 217, 21],
            ),
            // empty key empty data
            ("", "", vec![]),
            // nonempty key empty data
            ("12-39uaszASD!@ z", "", vec![]),
            // nonempty key nonempty data
            (
                "12-39uaszASD!@ z",
                "1 !asd9-1!#$@",
                vec![72, 235, 159, 107, 95, 26, 136, 136, 180, 73, 27, 113, 180],
            ),
            // nonempty key long data
            (
                "12-39uaszASD!@ z",
                "1 !asd9-1!#$@aoij!@#$ *((_Z!)  !@#$poaksfpokasopdkop12@#!@$@#&(Q%AWDSF(U",
                vec![
                    72, 235, 159, 107, 95, 26, 136, 136, 180, 73, 27, 113, 180, 129, 175, 181, 16,
                    52, 181, 210, 40, 126, 227, 246, 105, 142, 50, 221, 101, 35, 240, 135, 85, 57,
                    123, 118, 20, 96, 91, 55, 181, 107, 149, 128, 181, 0, 22, 204, 239, 130, 146,
                    141, 159, 7, 209, 3, 16, 43, 182, 111, 1, 220, 7, 10, 191, 188, 141, 108, 73,
                    203, 15, 45,
                ],
            ),
        ]
    }

    macro_rules! encoder_pure {
        ( $fn_name:ident, $( $crypt_encoder:ident ),* ) => {
            fn $fn_name(unhashed_key: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
                let unhashed_key_bytes = unhashed_key.as_bytes();
                let key_hash = sha512_with_len(unhashed_key_bytes, 32).unwrap();

                let mut result = Vec::new();

                let mut cryptor = compose_encoders!(
                    data,
                    $( $crypt_encoder => Some(&key_hash[..]) ),*
                );

                cryptor.read_to_end(&mut result).unwrap();

                Ok(result)
            }
        };
    }

    encoder_pure!(encrypt_pure, Encryptor);

    encoder_pure!(decrypt_pure, Decryptor);

    encoder_pure!(identity_pure, Encryptor, Decryptor);

    #[test]
    fn parametrized_encrypt() {
        test_data()
            .into_iter()
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
            .into_iter()
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
            .into_iter()
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
        let key_hash = hash_key(&format!("soamkle!$@random key{}", line!()));
        let buffer_sizes: Vec<Option<usize>> = vec![
            None,
            Some(1),
            Some(8),
            Some(64),
            Some(128),
            Some(1423),
            Some(4096),
        ];

        find(Path::new("./src/"))
            .filter(|path_buf| path_buf.as_path().is_file())
            .flat_map(|path_buf| {
                // PathBuf -> PathBuf x Option<usize>
                // essentially create pairs of (pathbuf, buffer sizes), to test
                // various buffer sizes
                buffer_sizes
                    .iter()
                    .cloned()
                    .map(move |buf_size| (path_buf.clone(), buf_size))
            })
            .map(|(src, buf_size)| -> Result<(), Error> {
                let mut cryptor = compose_encoders!(
                    File::open(&src).unwrap(),
                    Encryptor => Some(&key_hash),
                    Decryptor => Some(&key_hash)
                );

                let result = cryptor.all_to_vec()?;

                let mut expected = Vec::new();
                File::open(&src)?.read_to_end(&mut expected)?;

                Ok(assert_eq!(expected, result))
            })
            .for_each(Result::unwrap);
        Ok(())
    }
}
