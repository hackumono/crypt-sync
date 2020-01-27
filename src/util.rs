use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::io::Bytes;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result;
use std::str;
use tempfile;
use tempfile::NamedTempFile;
use tempfile::TempDir;
use walkdir::WalkDir;

pub use std::io::Error;
pub use std::io::ErrorKind;

// use crate::encoder::text_encoder::*;

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
pub fn min_mkdir_set<'a, F, I>(dirs: &'a F) -> HashSet<PathBuf>
where
    F: Fn() -> I,
    I: Iterator<Item = &'a Path>,
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
pub fn pull<R>(source: &mut Bytes<R>, size: usize) -> Result<Option<Vec<u8>>, Error>
where
    R: Read,
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
pub fn io_err<D>(error: D) -> Error
where
    D: Debug,
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
