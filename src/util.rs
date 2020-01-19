use data_encoding::Encoding;
use data_encoding::Specification;
use openssl::error::ErrorStack;
use openssl::hash;
use std::env;
use std::fmt::Display;
use std::fs::File;
use std::io::Bytes;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result;
use tempfile;
use tempfile::NamedTempFile;
use tempfile::TempDir;
use walkdir::WalkDir;

macro_rules! err {
    ( $message:expr ) => {
        Error::new(ErrorKind::Other, $message)
    };
    ( $message:expr, $($arg:expr),* ) => {
        Error::new(ErrorKind::Other, format!($message, $($arg),*))
    };
}

// trying to avoid bs buffer logic with this
// try to pull `size` number of bytes from source
// returns None instead of an empty vec because it looks cleaner when
// matching
pub fn pull<T>(
    //source: &mut impl Iterator<Item = Result<T, Error>>,
    source: &mut Bytes<T>,
    size: usize,
) -> Result<Option<Vec<u8>>, Error>
where
    T: Read,
{
    let mut buffer = Vec::with_capacity(size);

    // not using iter because ? doesn't look clean and short circuiting is hard
    // 1. try pulling n <= size bytes from source
    // 2. break if Err
    // 3. break if source is empty
    for _ in 0..size {
        match source.next() {
            Some(byte) => buffer.push(byte?),
            None => break,
        }
    }

    Ok(match buffer.len() {
        0 => None,
        _ => Some(buffer),
    })
}

#[inline]
pub fn make_encoding(symbols: &str, padding: Option<char>) -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str(symbols);
    if padding.is_some() {
        spec.padding = padding;
    }
    spec.encoding().unwrap()
}

#[inline]
pub fn io_err(error: impl Display) -> Error {
    err!("{}", error)
}

#[inline]
pub fn basename_bytes(path: &Path) -> Result<&[u8], Error> {
    Ok(path
        .file_name()
        .ok_or(err!("failed to get basename for `{:?}`", path))?
        .to_str()
        .ok_or(err!("failed to &OsStr -> &str for `{:?}`", path))?
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
pub fn mktemp_file(
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
pub fn mktemp_dir(prefix: &str, suffix: &str, dest_dir: Option<&Path>) -> Result<TempDir, Error> {
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
