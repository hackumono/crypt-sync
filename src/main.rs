#[macro_use]
extern crate static_assertions;

#[macro_use]
mod util;

#[macro_use]
mod encoder;

mod clargs;
mod crypt;
mod hasher;

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
        let key: String = read!("{}\n");
        let key_bytes = key.as_bytes();
        // TODO also ask for confirmation
        let data = b"Some Crypto Text";
        let encrypted = util::encrypt(&key_hash[..], data);
    */

    todo!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_is_unix() {
        assert!(cfg!(unix));
    }
}
