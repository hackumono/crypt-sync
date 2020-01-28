#!/usr/bin/env bash

function get-src {
  fd . src/ --type file |
    rg -i "$1"
}
  
vim $(get-src "$1") &&
  cargo fmt &&
  cargo check &&
  get-src "$1" | 
    parallel 'basename {.}' |
    while read f; do 
      cargo test "$f"
    done
