use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use std::cmp::Eq;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::metadata;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Error;
use std::io::ErrorKind;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::time::SystemTime;
use tempfile::TempDir;

use crate::encoder::cryptor::*;
use crate::encoder::text_encoder::*;
use crate::hasher::*;
use crate::util::*;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum CFileType {
    // TODO support symlink in the future maybe?
    DIR,
    FILE,
}

/// The BASENAME of a CryptFile, whether its source is a file or a directory, is the ciphertext of
/// its entire path whose root is the root CryptFile.
#[derive(Clone, Debug)]
pub struct CryptFile {
    // some temp location where the encrypted files will be stored before
    // being moved to their final locations
    arena: Arc<TempDir>,
    children: Option<Vec<CryptFile>>, // directory content, None if file
    file_type: CFileType,
    name_in_arena: String,    // temp name of its intermediate form in the arena
    src: PathBuf,             // path to the source file/dir
    src_modified: SystemTime, // time at which src was last modified
}

impl<'a> CryptFile {
    /// 1. for the root cfile,
    pub fn sync(&self, out_dir: &Path, key_hash: &[u8]) -> Result<(), Error> {
        let enc_basenames = basename_ciphertexts(&self.src, key_hash);
        let enc_paths = path_ciphertexts(&enc_basenames);
        println!("enc_basenames {:#?}", enc_basenames);
        println!("enc_paths {:#?}", enc_paths);
        todo!()
    }

    pub fn new(src: &Path) -> Result<Self, Error> {
        let arena = mktemp_dir("", "", None).map(Arc::new)?;
        CryptFile::new_internal(src, &arena)
    }

    // pass optional memo map
    fn new_internal(src: &Path, arena: &Arc<TempDir>) -> Result<Self, Error> {
        let meta = metadata(&src)?; // returns Err if symlink?

        let src = src.to_path_buf();
        let src_modified = meta.modified()?;

        let file_type = match &meta {
            _ if meta.is_file() => Ok(CFileType::FILE),
            _ if meta.is_dir() => Ok(CFileType::DIR),
            _ => Err(err!("symlinks not supported yet")),
        }?;

        // TODO right now just skips if IO error
        // change to failing
        Ok(Self {
            children: match &file_type {
                CFileType::FILE => None,
                CFileType::DIR => Some(
                    src.read_dir()?
                        .par_bridge()
                        .filter_map(|opt_src| match opt_src {
                            Ok(src) => Some(CryptFile::new_internal(src.path().as_path(), &arena)),
                            Err(message) => eprintln_then_none!("{}", message),
                        })
                        .filter_map(|opt_cfile| match opt_cfile {
                            Ok(cfile) => Some(cfile),
                            Err(message) => eprintln_then_none!("{}", message),
                        })
                        .collect(),
                ),
            },
            name_in_arena: format!(
                "{}_{}.csync",
                hash_base64_pathsafe(src.to_str().unwrap())?,
                SystemTime::now()
                    .duration_since(src_modified)
                    .map_err(io_err)?
                    .as_nanos()
            ),
            file_type,
            arena: arena.clone(),
            src,
            src_modified,
        })
    }

    #[inline]
    pub fn ls(&'a self) -> Option<impl ParallelIterator<Item = &'a CryptFile>> {
        self.children.as_ref().map(|cs| cs.par_iter())
    }

    #[inline]
    pub fn is_file(&self) -> bool {
        self.file_type == CFileType::FILE
    }

    #[inline]
    pub fn is_dir(&self) -> bool {
        self.file_type == CFileType::DIR
    }

    #[inline]
    pub fn modified(&self) -> SystemTime {
        self.src_modified.clone()
    }

    #[inline]
    pub fn source(&self) -> PathBuf {
        self.src.clone()
    }
}

impl Hash for CryptFile {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src.hash(state);
    }
}

impl PartialEq for CryptFile {
    fn eq(&self, other: &Self) -> bool {
        self.source() == other.source()
    }
}

impl Eq for CryptFile {}

/// Make a mapping from some `p: PathBuf` to its ciphertext form `c: PathBuf`.
///
/// # Parameters
///
/// 1. `basename_ciphertexts`: a mapping from some path to the ciphertext that will be used as its
///    encrypted basename
/// 2. `key_hash`: hash of the key to use, for symmetric encryption
///
/// # Returns
///
/// A mapping from a path to its ciphertext that will be used as its encrypted path.
///
/// For example given a `bc = basename_ciphertexts` and some path `p = "p1/p2/p3"` will return
/// `bc["p1"]/bc["p1/p2"]/bc["p1/p2/p3"]`.
fn path_ciphertexts(basename_ciphertexts: &HashMap<PathBuf, String>) -> HashMap<PathBuf, PathBuf> {
    basename_ciphertexts
        .keys()
        .par_bridge()
        .cloned()
        .map(|src_path_buf| {
            src_path_buf.components().fold(
                (PathBuf::new(), PathBuf::new()),
                |(mut acc, mut acc_ciphertext), comp| match comp {
                    Component::Normal(osstr) => {
                        acc.push(osstr);
                        match basename_ciphertexts.get(&acc) {
                            Some(value) => acc_ciphertext.push(value),
                            None => (),
                        };
                        (acc, acc_ciphertext)
                    }
                    _ => (acc, acc_ciphertext),
                },
            )
        })
        .collect()
}

/// Make a mapping from each file in `source`, including itself, to its corresponding ciphertext
/// that will be used to as its encrypted basename.
///
/// # Parameters
///
/// 1. `source`: the root of the search
/// 2. `key_hash`: hash of the key to use, for symmetric encryption
///
/// # Returns
///
/// Some mapping `bc` such that for some path `p = [p1, p2, ..., pn]`:
/// ```text
/// if p is source or p.parent == None
///     bc[p] = encrypt(pn, key_hash)
/// else
///     key = hash([p1, p2, ... p_{n-1}])
///     bc[p] = encrypt(pn, key)
/// ```
fn basename_ciphertexts(source: &Path, key_hash: &[u8]) -> HashMap<PathBuf, String> {
    // TODO standardize the error reports
    find(source)
        .par_bridge()
        .filter_map(|opt_path_buf| match opt_path_buf {
            // :: Result<PathBuf> -> Option<PathBuf>
            Ok(path_buf) => Some(path_buf),
            Err(err) => eprintln_then_none!("{}", err),
        })
        .map(|path_buf| match path_buf.file_name().map(OsStr::to_str) {
            // :: PathBuf -> Result<(PathBuf, SString)>
            Some(Some(basesname_str)) => {
                let opt_parent = path_buf.parent().map(Path::to_str);
                let parent_derived_hash = match opt_parent {
                    Some(Some(parent_str)) if &path_buf != source => hash_key(&parent_str),
                    _ => Vec::from(key_hash),
                };

                let ciphertext = compose_encoders!(
                    basesname_str.as_bytes(),
                    Encryptor => &parent_derived_hash,
                    TextEncoder => None
                )?
                .as_string()?;

                Ok((path_buf, ciphertext))
            }
            _ => Err(err!("`{:?}` contains non utf8 chars", path_buf)),
        })
        .filter_map(|res| match res {
            Ok(v) => Some(v),
            Err(err) => eprintln_then_none!("{}", err),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod new {
        use super::*;
        use rayon::prelude::*;
        use std::collections::HashSet;

        #[test]
        fn file() {
            // use line number to make each file unique
            let suffix = format!(".csync.crypt_file.{}", line!());
            let file = mktemp_file("", &suffix, None).unwrap();

            let src = file.path();
            assert!(src.exists());

            let cfile = CryptFile::new(&src).unwrap();

            assert!(cfile.ls().is_none());
            assert!(cfile.is_file());
            assert_eq!(src, cfile.source());
        }

        #[test]
        fn empty_dir() {
            // use line number to make each dir unique
            let suffix = format!(".csync.crypt_file.{}", line!());
            let dir = mktemp_dir("", &suffix, None).unwrap();

            let src = dir.path();
            assert!(src.exists());

            let cdir = CryptFile::new(&src).unwrap();

            assert_eq!(0, cdir.ls().unwrap().count());
            assert!(cdir.is_dir());
            assert_eq!(src, cdir.source());
        }

        #[test]
        fn nested_dir() {
            //   dir1
            //     |- file1
            //     |- dir2
            //          |- file2

            // unique suffixes for each file/dir
            let suffix_dir1 = format!(".csync.crypt_file.{}", line!());
            let suffix_dir2 = format!(".csync.crypt_file.{}", line!());
            let suffix_file1 = format!(".csync.crypt_file.{}", line!());
            let suffix_file2 = format!(".csync.crypt_file.{}", line!());

            // create each one as tempfile/tempdir
            let dir1 = mktemp_dir("", &suffix_dir1, None).unwrap();
            let dir1_dir2 = mktemp_dir("", &suffix_dir2, Some(dir1.path())).unwrap();
            let dir1_file1 = mktemp_file("", &suffix_file1, Some(dir1.path())).unwrap();
            let dir1_dir2_file2 = mktemp_file("", &suffix_file2, Some(dir1_dir2.path())).unwrap();

            // check that all temps have been created
            [
                dir1.path(),
                dir1_dir2.path(),
                dir1_file1.path(),
                dir1_dir2_file2.path(),
            ]
            .par_iter()
            .cloned()
            .for_each(|temp| assert!(temp.exists()));

            // check that cdir1 has been initialized correctly
            let cdir1 = CryptFile::new(&dir1.path()).unwrap();
            assert!(cdir1.is_dir());
            assert_eq!(dir1.path().to_path_buf(), cdir1.source());

            // check cdir1's ls children
            let cdir1_ls: HashSet<_> = cdir1.ls().unwrap().cloned().collect();
            assert_eq!(2, cdir1_ls.len());
            let cdir1_ls_bufs: HashSet<PathBuf> =
                cdir1_ls.par_iter().map(CryptFile::source).collect();
            let cdir1_expected_ls_bufs: HashSet<PathBuf> = [dir1_dir2.path(), dir1_file1.path()]
                .par_iter()
                .cloned()
                .map(Path::to_path_buf)
                .collect();
            assert_eq!(cdir1_expected_ls_bufs, cdir1_ls_bufs);

            // check dir1/file1
            let cfile1 = cdir1_ls
                .iter()
                .cloned()
                .filter(CryptFile::is_file)
                .nth(0)
                .unwrap();
            assert!(cfile1.is_file());
            assert!(cfile1.ls().is_none());
            assert_eq!(dir1_file1.path().to_path_buf(), cfile1.source());

            // check dir1/dir2
            let cdir2: CryptFile = cdir1_ls
                .iter()
                .cloned()
                .filter(CryptFile::is_dir)
                .nth(0)
                .unwrap();
            assert!(cdir2.is_dir());
            assert_eq!(dir1_dir2.path().to_path_buf(), cdir2.source());
            // check cdir1's children
            assert!(cdir2.ls().is_some());
            let cdir2_ls: HashSet<_> = cdir2.ls().unwrap().collect();
            assert_eq!(1, cdir2_ls.len());

            // check dir1/dir2/file2
            let cfile2 = cdir2_ls.iter().nth(0).unwrap();
            assert!(cfile2.is_file());
            assert!(cfile2.ls().is_none());
            assert_eq!(dir1_dir2_file2.path().to_path_buf(), cfile2.source());
        }
    }

    // #[test]
    // fn test() {
    //     let suffix = format!(".csync.crypt_file.{}", line!());
    //     let dir = mktemp_dir("", &suffix, None).unwrap();
    //
    //     let src = Path::new("src");
    //     assert!(src.exists());
    //     let key_hash = hash_key(&format!("soamkle!$@random key{}", line!())).unwrap();
    //
    //     let cfile = CryptFile::new(src).unwrap();
    //     cfile.sync(dir.path(), &key_hash).unwrap();
    //     todo!();
    // }
}
