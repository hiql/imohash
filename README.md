# imohash

Fast hashing for large files

A rewritten version of [imohash](https://github.com/kalafut/imohash) in Rust.

## Usage

Add this to your Cargo.toml:

```toml
[dependencies]
imohash = "0.1"
```

then

```rust
use imohash::Hasher;

// Creates a new hasher using default sample parameters
let hasher = Hasher::new();
//or creates with custom sample parameters
let hasher = Hasher::with_sample_size_and_threshold(3, 45);

// Hashes a byte slice
let hash_value = hasher.sum("hello".as_bytes()).unwrap();

// Hashes a file
let hash_value = hasher.sum_file("samples/system.evtx").unwrap();
```

## Algorithm

Consult the [documentation](https://github.com/kalafut/imohash/blob/master/algorithm.md) for more information.

## Misuses

Because imohash only reads a small portion of a file's data, it is not suitable
for:

- file verification or integrity monitoring
- cases where fixed-size files are manipulated
- anything cryptographic

The original project created by
[Jim Kalafut](https://github.com/kalafut), check out https://github.com/kalafut/imohash

License: MIT
