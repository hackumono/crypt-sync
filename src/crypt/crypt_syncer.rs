use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use std::cmp::Eq;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::create_dir_all;
use std::fs::metadata;
use std::fs::rename;
use std::fs::File;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Error;
use std::io::ErrorKind;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tempfile::TempDir;

use crate::encoder::cryptor::*;
use crate::encoder::text_encoder::*;
use crate::encoder::zstd_encoder::*;
use crate::hasher::*;
use crate::util::*;

#[derive(Debug)]
pub struct CryptSyncer {
    // some temp location where the encrypted files will be stored before
    // being moved to their final locations
    arena: TempDir,
    source: PathBuf, // path to the source file/dir
}

impl<'a> CryptSyncer {
    /// 1. for the root cfile,
    pub fn sync(&self, out_dir: &Path, key_hash: &[u8]) -> Result<(), Error> {
        assert!(out_dir.exists());
        assert!(out_dir.is_dir());
        let src_to_target = {
            let src_to_target_basename = basename_ciphertexts(&self.source, key_hash);
            path_ciphertexts(&src_to_target_basename)
        };

        // create the directory structure in `out_dir`
        min_mkdir_set(&self.source)
            .into_par_iter()
            .map(|dir_path| src_to_target.get(&dir_path)) // encrypt
            .map(Option::unwrap)
            .map(|dir_path| out_dir.join(dir_path))   // put it in out_dir
            .map(create_dir_all)                      // create
            .for_each(Result::unwrap); // exit early

        src_to_target
            .par_iter()
            .filter(|(source, _)| source.is_file())
            .map(|(source, target_basename)| {
                let arena_basename = arena_basename(source)?;
                let arena_path = self.arena.path().join(arena_basename);
                let target = out_dir.join(target_basename);
                Ok((source, arena_path, target))
            })
            .filter_map(|res_tuple: Result<_, Error>| match res_tuple {
                Ok(tuple) => Some(tuple),
                Err(err) => eprintln_then_none!("{}", err),
            })
            .map(|(source, temp, target)| {
                let mut encoder = compose_encoders!(
                    File::open(source).unwrap(),
                    ZstdEncoder => None,
                    Encryptor => key_hash
                )
                .unwrap(); // TODO handle errors later
                encoder.write_all_to(&mut File::create(&temp).unwrap());
                (temp, target)
            })
            .for_each(|(temp, target)| {
                debug_assert!(temp.exists());
                debug_assert!(!target.exists());
                rename(temp, target).unwrap()
            });
        println!("src_to_target {:#?}", src_to_target);
        find(out_dir).for_each(|x| println!("in outdir: {:?}", x));
        todo!()
    }

    pub fn new(source: &Path) -> Result<Self, Error> {
        let arena = mktemp_dir("", "", None)?;
        Ok(CryptSyncer::new_internal(source, arena))
    }

    // pass optional memo map
    #[inline]
    fn new_internal(source: &Path, arena: TempDir) -> Self {
        Self {
            arena,
            source: source.to_path_buf(),
        }
    }
}

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
        .map(|source_path_buf| {
            source_path_buf.components().fold(
                // initial value: tuple (acc_src, acc_enc)
                (PathBuf::new(), PathBuf::new()),
                //
                |(mut acc_src, mut acc_enc), comp| match comp {
                    Component::Normal(component) => {
                        acc_src.push(component);
                        match basename_ciphertexts.get(&acc_src) {
                            Some(value) => acc_enc.push(value),
                            None => (),
                        };
                        (acc_src, acc_enc)
                    }
                    _ => (acc_src, acc_enc),
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
                    Some(Some(parent_str)) if &path_buf != source => {
                        hash_custom(key_hash, Some(parent_str.as_bytes()), Some(1))
                    }
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

#[inline]
fn modified(source: &Path) -> Result<SystemTime, Error> {
    metadata(source)?.modified()
}

fn arena_basename(source: &Path) -> Result<String, Error> {
    let bytes = source.to_str().ok_or(err!("{:?}", source))?.as_bytes();
    hash_base64_pathsafe(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp() {
        let key_hash = hash("aoisjfk1".as_bytes());
        let out_dir = mktemp_dir("", "", None).unwrap();
        let syncer = CryptSyncer::new(Path::new("src/")).unwrap();
        syncer.sync(&out_dir.path(), &key_hash[..]);
        assert!(false);
    }
}
