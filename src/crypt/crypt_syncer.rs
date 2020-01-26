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
use std::time::Duration;
use std::time::SystemTime;
use tempfile::TempDir;

use crate::encoder::cryptor::*;
use crate::encoder::text_encoder::*;
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
        let enc_basenames = basename_ciphertexts(&self.source, key_hash);
        let enc_paths = path_ciphertexts(&enc_basenames);
        println!("enc_basenames {:#?}", enc_basenames);
        println!("enc_paths {:#?}", enc_paths);
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
                (PathBuf::new(), PathBuf::new()),
                |(mut acc_source, mut acc_ciphertext), comp| match comp {
                    Component::Normal(osstr) => {
                        acc_source.push(osstr);
                        match basename_ciphertexts.get(&acc_source) {
                            Some(value) => acc_ciphertext.push(value),
                            None => (),
                        };
                        (acc_source, acc_ciphertext)
                    }
                    _ => (acc_source, acc_ciphertext),
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
                let ciphertext_filename = match ciphertext {
                    _ if path_buf.is_file() => format!("{}.csync", ciphertext),
                    _ => ciphertext,
                };

                Ok((path_buf, ciphertext_filename))
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

fn arena_name(source: &Path) -> Result<String, Error> {
    let source_str = source.to_str().ok_or(err!("{:?}", source))?;
    Ok(format!("{}.csync", hash_base64_pathsafe(source_str)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp() {
        let hash = hash_key_custom_iter("aoisjfk1", 16);
        let out_dir = mktemp_dir("", "", None).unwrap();
        let syncer = CryptSyncer::new(Path::new("src/")).unwrap();
        syncer.sync(&out_dir.path(), &hash[..]);
        assert!(false);
    }
}
