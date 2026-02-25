#!/bin/sh
exec /Users/swift/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/rust-lld -flavor link "$@"
