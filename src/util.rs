use openssl::error::ErrorStack;
use openssl::{hash, symm};
use std::env;
use std::fmt::Display;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::result::Result;
use tempfile::{self, NamedTempFile, TempDir};
use walkdir::WalkDir;

macro_rules! error_other {
    ( $message:expr ) => {
        Error::new(ErrorKind::Other, $message)
    };
    ( $message:expr, $($arg:expr),* ) => {
        Error::new(ErrorKind::Other, format!($message, $($arg),*))
    };
}

#[inline]
pub fn io_err(error: impl Display) -> Error {
    error_other!("{}", error)
}

#[inline]
pub fn basename_bytes(path: &Path) -> Result<&[u8], Error> {
    Ok(path
        .file_name()
        .ok_or(error_other!("failed to get basename for `{:?}`", path))?
        .to_str()
        .ok_or(error_other!("failed to &OsStr -> &str for `{:?}`", path))?
        .as_bytes())
}

#[inline]
pub fn walker(root: &Path) -> WalkDir {
    debug_assert!(root.exists());
    WalkDir::new(root).follow_links(false)
}

// analogous to `find` in Bash
#[inline]
pub fn find<'a>(root: &'a Path) -> impl Iterator<Item = PathBuf> + 'a {
    debug_assert!(root.exists());
    walker(root)
        .into_iter()
        .map(Result::unwrap)
        .map(walkdir::DirEntry::into_path)
}

// 0 <= length <= 64
#[inline]
pub fn sha512_with_len(data: &[u8], length: u8) -> Result<Vec<u8>, ErrorStack> {
    debug_assert!(length <= 64, "`{}` is not <= 64", length);
    Ok(hash::hash(hash::MessageDigest::sha512(), data)?
        .iter()
        .cloned()
        .take(length as usize)
        .collect())
}

// return a len-32 hash of the given key
#[inline]
pub fn hash_key(key: &str) -> Vec<u8> {
    sha512_with_len(key.as_bytes(), 32).unwrap()
}

#[inline]
pub fn exists(file: &File) -> bool {
    file.metadata().is_ok()
}

#[inline]
pub fn tempfile_custom(
    prefix: &str,
    suffix: &str,
    dest_dir: Option<&Path>,
) -> Result<NamedTempFile, Error> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempfile_in(dest_dir.unwrap_or(env::temp_dir().as_path()))
}

#[inline]
pub fn tempdir_custom(
    prefix: &str,
    suffix: &str,
    dest_dir: Option<&Path>,
) -> Result<TempDir, Error> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempdir_in(dest_dir.unwrap_or(env::temp_dir().as_path()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod sha512_with_len {
        // make sure each run of sha is deterministic and independent
        use super::*;

        fn check(data: &str, expected_hash: &Vec<u8>) {
            let result_hash = sha512_with_len(data.as_bytes(), 16).unwrap();
            assert_eq!(expected_hash, &result_hash);
            assert_ne!(data.as_bytes(), &result_hash[..]);
        }

        #[test]
        fn empty() {
            let data = "";
            let expected_hash: Vec<u8> = vec![
                207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7,
            ];
            (0..4).for_each(|_| check(data, &expected_hash));
        }
        #[test]
        fn simple() {
            let data = "jack choi";
            let expected_hash: Vec<u8> = vec![
                139, 206, 186, 165, 202, 113, 123, 222, 246, 203, 52, 183, 232, 136, 59, 239,
            ];
            (0..4).for_each(|_| check(data, &expected_hash));
        }
        #[test]
        fn complicated() {
            let data = "oija12; lp-1!@#$85%!&";
            let expected_hash: Vec<u8> = vec![
                180, 120, 231, 226, 248, 9, 106, 105, 212, 40, 106, 194, 164, 139, 234, 93,
            ];
            (0..4).for_each(|_| check(data, &expected_hash));
        }
    }
}
