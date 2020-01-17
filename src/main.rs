#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate static_assertions;

#[macro_use]
mod util;

mod clargs;
mod crypt_encoder;
mod crypt_file;
mod crypt_syncer;
mod cryptor;

assert_cfg!(unix, "Only Unix systems are supported");

fn main() {
    /*
    let file = File::open("/bigfile.txt");
    let mut filesize = file.size();
    while filesize > 0 {
        aes_siv.encrypt(&file.read(1024));
        filesize -= 1024;
    }
    */
    // https://docs.rs/openssl/0.10.26/openssl/symm/index.html
    /*
        eprintln!("Enter your password:");
        let key: String = dbg!(read!("{}\n"));
        let key_bytes = key.as_bytes();
        let key_hash = dbg!(util::sha512_with_len(key_bytes, 16).unwrap());
        let data = dbg!(b"Some Crypto Text");
        let encrypted = dbg!(util::encrypt(&key_hash[..], data));
    */

    unimplemented!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_not_windows() {
        assert!(!cfg!(windows));
    }
}
