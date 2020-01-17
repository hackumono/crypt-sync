#!/usr/bin/env bash

function get-src {
  fd . src/ --type file |
    rg -i "$1"
}

vim $(get-src "$1") &&
  cargo fmt &&
  cargo check
