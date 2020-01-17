#!/usr/bin/env bash

vim src/{cryptor,crypt_encoder,util,crypt_syncer,crypt_file,clargs,main}.rs Cargo.toml &&
  cargo fmt &&
  cargo test
