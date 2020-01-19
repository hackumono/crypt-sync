use std::cmp::Eq;
use std::fs::metadata;
use std::fs::symlink_metadata;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Error;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tempfile::TempDir;

use crate::util::*;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum CFileType {
    // TODO support symlink in the future maybe?
    DIR,
    FILE,
}

#[derive(Clone, Debug)]
pub struct CryptFile {
    // some temp location where the encrypted files will be stored before
    // being moved to their final locations
    arena: Arc<TempDir>,
    cf_type: CFileType,
    children: Option<Vec<CryptFile>>, // directory content, None if file
    src: PathBuf,                     // path to the source file/dir
    src_modified: SystemTime,         // time at which src was last modified
}

macro_rules! eprintln_then_none {
    ( $message:expr, $($arg:expr),* ) => {{
        eprintln!("{}", format!($message, $($arg),*));
        None
    }};
}

impl<'a> CryptFile {
    /// # Parameters
    /// - `src` -> path to the original file to be encrypted
    pub fn sync(src: &Path, dest_dir: &Path) -> Result<(), Error> {
        unimplemented!()
    }

    fn new(src: &Path, arena: Option<&Arc<TempDir>>) -> Result<Self, Error> {
        let meta = metadata(&src)?; // returns Err if symlink?
                                    // Ok if file or dir, Err if symlink
        let cf_type = if meta.is_file() {
            Ok(CFileType::FILE)
        } else if meta.is_dir() {
            Ok(CFileType::DIR)
        } else {
            assert!(symlink_metadata(&src).is_ok()); // assume that it is symlink
            Err(err!("symlinks not supported yet"))
        }?;

        let arena = arena
            .map(Arc::clone)
            .unwrap_or(Arc::new(mktemp_dir("", "", None)?));

        // TODO right now just skips if IO error
        // change to failing
        Ok(Self {
            arena,
            children: match &cf_type {
                CFileType::FILE => None,
                CFileType::DIR => Some(
                    src.read_dir()?
                        .filter_map(|content| match content {
                            Ok(c) => Some(CryptFile::new(c.path().as_path(), None)),
                            Err(message) => eprintln_then_none!("{}", message),
                        })
                        .filter_map(|opt_cfile| match opt_cfile {
                            Ok(cfile) => Some(cfile),
                            Err(message) => eprintln_then_none!("{}", message),
                        })
                        .collect(),
                ),
            },
            cf_type,
            src: src.to_path_buf(),
            src_modified: meta.modified()?,
        })
    }

    #[inline]
    pub fn ls(&'a self) -> Option<impl Iterator<Item = CryptFile> + 'a> {
        self.children.as_ref().map(|cs| cs.iter().cloned())
    }

    #[inline]
    pub fn find(&'a self) -> impl Iterator<Item = PathBuf> + 'a {
        find(self.src.as_path())
    }

    #[inline]
    pub fn is_file(&self) -> bool {
        self.cf_type == CFileType::FILE
    }

    #[inline]
    pub fn is_dir(&self) -> bool {
        self.cf_type == CFileType::DIR
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
            let suffix = format!(".csync.{}", line!());
            let file = mktemp_file("", &suffix, None).unwrap();

            let src = file.path();
            assert!(src.exists());

            let cfile = CryptFile::new(&src, None).unwrap();

            assert!(cfile.ls().is_none());
            assert!(cfile.is_file());
            assert_eq!(src, cfile.source());
        }

        #[test]
        fn empty_dir() {
            // use line number to make each dir unique
            let suffix = format!(".csync.{}", line!());
            let dir = mktemp_dir("", &suffix, None).unwrap();

            let src = dir.path();
            assert!(src.exists());

            let cdir = CryptFile::new(&src, None).unwrap();

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
            let suffix_dir1 = format!(".csync.{}", line!());
            let suffix_dir2 = format!(".csync.{}", line!());
            let suffix_file1 = format!(".csync.{}", line!());
            let suffix_file2 = format!(".csync.{}", line!());

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
            let cdir1 = CryptFile::new(&dir1.path(), None).unwrap();
            assert!(cdir1.is_dir());
            assert_eq!(dir1.path().to_path_buf(), cdir1.source());
            // check cdir1's find children
            let cdir1_fd: HashSet<_> = cdir1.find().collect();
            let cdir1_fd_expected: HashSet<_> = [
                dir1.path(),
                dir1_dir2.path(),
                dir1_file1.path(),
                dir1_dir2_file2.path(),
            ]
            .par_iter()
            .cloned()
            .map(Path::to_path_buf)
            .collect();
            assert_eq!(cdir1_fd_expected, cdir1_fd);

            // check cdir1's ls children
            let cdir1_ls: HashSet<_> = cdir1.ls().unwrap().collect();
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
}
