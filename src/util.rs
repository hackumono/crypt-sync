use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::io::Bytes;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result;
use std::str;
use tempfile;
use tempfile::NamedTempFile;
use tempfile::TempDir;
use walkdir::WalkDir;

use crate::encoder::text_encoder::*;

macro_rules! err {
    ( $message:expr ) => {
        Error::new(ErrorKind::Other, $message)
    };
    ( $message:expr, $($arg:expr),* ) => {
        Error::new(ErrorKind::Other, format!($message, $($arg),*))
    };
}

macro_rules! eprintln_then_none {
    ( $message:expr, $($arg:expr),* ) => {{
        eprintln!("{}", format!($message, $($arg),*));
        None
    }};
}

/// # Parameters
///
/// 1. `dirs`:
///
/// # Returns
///
/// The "minimum" set of directory paths in a sense that calling `mkdir -p` on each element in the
/// set results in the minimum number of `mkdir` calls in order to create every directory in the
/// set.
pub fn min_mkdir_set<'a, T, U>(dirs: &'a T) -> HashSet<PathBuf>
where
    T: Fn() -> U,
    U: Iterator<Item = &'a Path>,
{
    dirs().fold(
        dirs().map(Path::to_path_buf).collect::<HashSet<PathBuf>>(),
        |mut acc, path| match acc.contains(path) {
            true => {
                // for each dir, remove all parent direcotries from acc
                let mut current: &Path = path;
                loop {
                    match current.parent() {
                        Some(parent) if acc.contains(parent) => {
                            acc.remove(parent);
                            current = parent;
                        }
                        _ => break acc,
                    }
                }
            }
            false => acc,
        },
    )
}

// trying to avoid bs buffer logic with this
// try to pull `size` number of bytes from source
// returns None instead of an empty vec because it looks cleaner when
// matching
pub fn pull<T>(source: &mut Bytes<T>, size: usize) -> Result<Option<Vec<u8>>, Error>
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
            Some(byte_result) => buffer.push(byte_result?),
            None => break,
        }
    }

    Ok(match buffer.len() {
        0 => None,
        _ => Some(buffer),
    })
}

#[inline]
pub fn io_err<T>(error: T) -> Error
where
    T: Debug,
{
    err!("{:?}", error)
}

#[inline]
pub fn basename_bytes(path: &Path) -> Result<&[u8], Error> {
    Ok(path
        .file_name()
        .ok_or(err!("failed to get the basename of `{:?}`", path))?
        .to_str()
        .ok_or(err!("`&OsStr -> &str` failed for `{:?}`", path))?
        .as_bytes())
}

#[inline]
pub fn walker(root: &Path) -> WalkDir {
    debug_assert!(root.exists());
    WalkDir::new(root).follow_links(false)
}

// analogous to `find` in Bash
#[inline]
pub fn find(root: &Path) -> impl Iterator<Item = Result<PathBuf, Error>> {
    debug_assert!(root.exists());
    walker(root)
        .into_iter()
        .map(|x| x.map(walkdir::DirEntry::into_path).map_err(io_err))
}

// /// 0 <= length <= 64
// #[inline]
// pub fn sha512_with_len(data: &[u8], length: u8) -> Result<Vec<u8>, ErrorStack> {
//     debug_assert!(length <= 64, "`{}` is not <= 64", length);
//     Ok(hash(MessageDigest::sha512(), data)?
//         .iter()
//         .cloned()
//         .take(length as usize)
//         .collect())
// }
//
// /// just like BASE64 that conforms to RFC4648; https://tools.ietf.org/search/rfc4648
// /// but '/' is replaced with '-' so that the resulting encoding can be used as
// /// a filepath
// #[inline]
// pub fn sha512_string(data: &[u8]) -> Result<String, Error> {
//     TextEncoder::new_custom(
//         &sha512_with_len(data, 64)?[..],
//         Some(&FILEPATH_SAFE_BASE64),
//         None,
//         None,
//         None,
//     )?
//     .as_string()
// }

// return a len-32 hash of the given key
#[inline]
pub fn hash_key(key: &str) -> Vec<u8> {
    hash_bytes(key.as_bytes())
}

// return a len-32 hash of the given key
#[inline]
pub fn hash_bytes(key: &[u8]) -> Vec<u8> {
    sha512_with_len(key, 32).unwrap()
}

#[inline]
pub fn mktemp_file(
    prefix: &str,
    suffix: &str,
    out_dir: Option<&Path>,
) -> Result<NamedTempFile, Error> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempfile_in(out_dir.unwrap_or(env::temp_dir().as_path()))
}

#[inline]
pub fn mktemp_dir(prefix: &str, suffix: &str, out_dir: Option<&Path>) -> Result<TempDir, Error> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempdir_in(out_dir.unwrap_or(env::temp_dir().as_path()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod sha512_with_len {
        // make sure each run of sha is deterministic and independent
        use super::*;
        use rayon::iter::ParallelBridge;
        use rayon::prelude::*;

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
            (0..4)
                .par_bridge()
                .for_each(|_| check(data, &expected_hash));
        }
        #[test]
        fn simple() {
            let data = "jack choi";
            let expected_hash: Vec<u8> = vec![
                139, 206, 186, 165, 202, 113, 123, 222, 246, 203, 52, 183, 232, 136, 59, 239,
            ];
            (0..4)
                .par_bridge()
                .for_each(|_| check(data, &expected_hash));
        }
        #[test]
        fn complicated() {
            let data = "oija12; lp-1!@#$85%!&";
            let expected_hash: Vec<u8> = vec![
                180, 120, 231, 226, 248, 9, 106, 105, 212, 40, 106, 194, 164, 139, 234, 93,
            ];
            (0..4)
                .par_bridge()
                .for_each(|_| check(data, &expected_hash));
        }
    }
}
