use data_encoding::{Encoding, Specification};
use rayon::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::str;

use crate::util::*;

#[derive(Clone, Debug)]
pub struct CryptSyncer {
    key_hash: Vec<u8>,
    encoding: Encoding,
}

lazy_static! {
    static ref CUSTOM_ENCODING: Encoding = {
        let symbols = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
        debug_assert_eq!(32, symbols.len());

        let mut spec = Specification::new();
        spec.symbols.push_str(symbols);
        spec.padding = Some('_');
        spec.encoding().unwrap()
    };
}

impl CryptSyncer {
    pub fn sync(src: &Path, dest_dir: &Path, key_hash: &[u8]) -> Result<(), Error> {
        assert!(src.exists());
        assert!(dest_dir.exists());
        debug_assert_eq!(16, key_hash.len());
        let syncer = CryptSyncer::new(key_hash, &CUSTOM_ENCODING);
        unimplemented!()
    }

    #[inline]
    fn new(key_hash: &[u8], encoding: &Encoding) -> Self {
        debug_assert_eq!(16, key_hash.len());
        Self {
            key_hash: Vec::from(key_hash),
            encoding: encoding.clone(),
        }
    }

    fn sync_file(src: &Path) -> Result<(), Error> {
        assert!(src.exists());
        unimplemented!()
    }

    /// encrypts the BASENAME
    /// path doesn't have to exist
    fn encrypt_path(&self, path: &Path) -> Result<String, Error> {
        unimplemented!()
        /*
        let basename: &[u8] = basename_bytes(path)?;
        debug_assert!(basename.len() > 0);
        let path_ciphertext: Vec<u8> =
            encrypt(&self.key_hash, basename).map_err(|err| error_other!("{}", err))?;
        debug_assert!(path_ciphertext.len() > 0);

        Ok(&path_ciphertext) // Result<&[u8], _>
            .map(|bytes| self.encoding.encode(bytes)) // Result<&[u8], _> -> Result<String, _>
            .map(|basename| format!("{}.csync", basename))
        */
    }

    /// path doesn't have to exist
    fn decrypt_path(&self, path: &str) -> Result<String, Error> {
        unimplemented!()
        /*
        assert!(path.ends_with(".csync")); // TODO properly handle later
        let path = path.replace(".csync", "");

        let basename: &[u8] = basename_bytes(Path::new(&path))?;
        assert!(basename.len() > 0);
        let path_ciphertext: Vec<u8> = self
            .encoding
            .decode(&basename) // -> Result<Vec<u8>, DecodeError>
            .map_err(|err| error_other!("{}", err))?; // Result<_, DecodeError> -> Result<_, Error>
        debug_assert!(path_ciphertext.len() > 0);
        let path_decrypted: Vec<u8> = decrypt(&self.key_hash, &path_ciphertext).unwrap();
        debug_assert!(path_decrypted.len() > 0);

        Ok(&path_decrypted[..]) // Result<&[u8], _>
            .map(str::from_utf8) // Result<&[u8], _> -> Result<Result<&str, _>, _>
            .map(Result::unwrap) // Result<Result<&str, _>, _> -> Result<&str, _>
            .map(String::from) // Result<&str, _> -> Result<PathBuf, _>
        */
    }

    fn encrypt_content(from: &Path, to: &Path) -> Result<(), Error> {
        assert!(from.exists());
        assert!(to.exists());
        unimplemented!()
    }

    fn decrypt_content(from: &Path, to: &Path) -> Result<(), Error> {
        assert!(from.exists());
        assert!(to.exists());
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod sync_file {
        use super::*;
    }

    fn test_data() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
        vec![
            (
                "crypt_syncer alpha!@#",
                "/a/bc/def/ghi.txt",
                "ghi.txt",
                "6QFBFS418VENIR9R5F1L6MD9I0______.csync",
            ),
            (
                "crypt_syncer qopiwjwepoasd !@#!    @$*(O@#",
                "abc1123_.txt",
                "abc1123_.txt",
                "QBO1C9I5QV2E685Q2EKDDLJO44______.csync",
            ),
            (
                "crypt_syncer qopiwjwepoasd !@#!    @$*(O@#",
                "./abc1123_.txt",
                "abc1123_.txt",
                "QBO1C9I5QV2E685Q2EKDDLJO44______.csync",
            ),
        ]
    }

    fn syncer_init(unhashed_key: &str) -> CryptSyncer {
        assert_ne!(0, unhashed_key.len());
        let key_hash = hash_key(unhashed_key);
        assert_eq!(16, key_hash.len());
        CryptSyncer::new(&key_hash, &CUSTOM_ENCODING)
    }

    /*
        #[test]
        fn encrypt_name() {
            test_data().par_iter().cloned().for_each(
                |(unhashed_key, full_path, _, expected_ciphertext)| {
                    let path_to_encrypt = Path::new(full_path);
                    let path_ciphertext = syncer_init(unhashed_key)
                        .encrypt_path(path_to_encrypt)
                        .unwrap();

                    let expected = String::from(expected_ciphertext);
                    (0..4).for_each(|_| assert_eq!(expected, path_ciphertext));
                },
            )
        }

        #[test]
        fn decrypt_name() {
            test_data()
                .par_iter()
                .cloned()
                .for_each(|(unhashed_key, _, basename, ciphertext)| {
                    let path_to_decrypt = String::from(ciphertext);
                    let basename_decrypted = syncer_init(unhashed_key)
                        .decrypt_path(&path_to_decrypt)
                        .unwrap();

                    let expected = String::from(basename);
                    (0..4).for_each(|_| assert_eq!(expected, basename_decrypted));
                })
        }
    */
    #[cfg(test)]
    mod encrypt_content {
        use super::*;
    }

    #[cfg(test)]
    mod decrypt_content {
        use super::*;
    }
}
