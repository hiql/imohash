# imohash

Fast hashing for large files

A rewritten version of [imohash](https://github.com/kalafut/imohash) in Rust.

## Usage

Add `imohash` as a dependency:

```sh
cargo add imohash
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

<details>
  <summary>Advanced asynchronous usage example</summary>

```rust
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::path::{Path, PathBuf};
use imohash;

pub fn sum_files<P: AsRef<Path>>(
    file_paths: Vec<P>,
    sample_size: Option<u32>,
    sample_threshold: Option<u32>,
    threads_count: Option<u8>,
) -> std::sync::mpsc::Receiver<(u128, PathBuf)> {
    let sample_size = sample_size.unwrap_or(imohash::SAMPLE_SIZE);
    let sample_threshold = sample_threshold.unwrap_or(imohash::SAMPLE_THRESHOLD);
    let threads_count = threads_count.unwrap_or_else(|| {
        (thread::available_parallelism().unwrap().get() * 2) as u8 // two threads per core
    }) as usize;
    assert!(threads_count > 0);

    let hasher = Arc::new(imohash::Hasher::with_sample_size_and_threshold(
        sample_size,
        sample_threshold,
    ));

    let (sender, receiver): (
        std::sync::mpsc::Sender<(u128, PathBuf)>,
        std::sync::mpsc::Receiver<(u128, PathBuf)>,
    ) = std::sync::mpsc::channel();
    let sender = Arc::new(sender);

    let mut threads: Vec<JoinHandle<()>> = Vec::with_capacity(threads_count);
    let chunk_size = (file_paths.len() + threads_count - 1) / threads_count;

    for file_paths_chunk in file_paths.chunks(chunk_size) {
        let shared_hasher = Arc::clone(&hasher);
        let shared_sender = Arc::clone(&sender);
        let file_path_list: Vec<PathBuf> = file_paths_chunk
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect();

        let handle = thread::spawn(move || {
            for file_path in file_path_list {
                let hash = shared_hasher.sum_file(&file_path);
                match hash {
                    Err(_) => continue, // Path is directory
                    Ok(hash) => shared_sender.send((hash, file_path)).unwrap(),
                }
            }
        });

        threads.push(handle);
    }

    receiver
}

fn main() {
  let receiver: std::sync::mpsc::Receiver<(u128, PathBuf)> = sum_files(
      vec![
          PathBuf::from("/bin/cp"),
          PathBuf::from("/bin/mv"),
          PathBuf::from("/bin/rm"),
          // ...
      ],  // file_paths
      None,  // sample_size
      None,  // sample_threshold
      None  // threads_count
  );

  loop {
      let hash_result: Result<(u128, PathBuf), std::sync::mpsc::RecvError> = receiver.recv();
      match hash_result {
          // Since sender is not dropping explicitly, RecvError will occur, when no any Sender
          Err(std::sync::mpsc::RecvError) => break,
          Ok(hash_result) => {
              let (hash, file_path) = hash_result;
              println!("{}  {}", hash, file_path.as_path().to_str().unwrap())
          }
      }
  }
}
```

</details>

### CLI application

Component provides a CLI sample application to hash files, similar to md5sum.

#### Install

Install `imohash` binary with `cargo`:

```sh
cargo install --bin imohash imohash  # NAME_OF_BINARY PACKAGE_NAME
```

The installed binary will be located in `~/.cargo/bin/imohash` and will be available globally as `imohash`.  

#### Usage

```sh
imohash  # ... options and arguments
```

Application options and arguments:

- `-t` / `--sample-threshold` — Sample threshold value.
- `-s` / `--sample-size` — Sample size value. The entire file will be hashed (i.e. no sampling), if `sample_size < 1`
- `-f` / `--format` of `{ int | bytes | hex }` — Hash representation format. Default `hex`
- `-i` / `--interactive` — Interactive hash computation mode. **Conflicts with** `[file_path ...]` argument
- `--threads` — Count of threads to compute files sum in. **Conflicts with** `-i/--interactive` argument
- `[file_path ...]` — File paths to compute hash of. **Conflicts with** `-i/--interactive` argument

**Usage example:**

1. Compute hash sum of file or files:
   ```sh
   # echo example > /tmp/my_file
   imohash /tmp/my_file
   ```
   will print:
   ```
   0877d8731ad98e5ee1cc09c0a87772bf  /tmp/my_file
   ```
2. Compute hash sum of file(s) with `find` application result:
   ```sh
   # dd if=/dev/random of=/tmp/1.iso bs=1M count=64
   # dd if=/dev/random of=/tmp/2.iso bs=1M count=64
   # cp /tmp/1.iso /tmp/3.iso
   
   find /tmp -type f -iname '*.iso' -exec imohash {} \+
   ```
   will print:
   ```
   808080203afea9085df78cd992f28546  /tmp/1.iso
   8080802011cdd41fbddd9c1f853c1330  /tmp/2.iso
   808080203afea9085df78cd992f28546  /tmp/3.iso  # as same as #1 !
   ```
3. Compute hash of string content (as bytes data) interactively:
   ```sh
   imohash -i  # ... or implicitly: imohash
   ```

   ```
   Interactive mode (format: hex)
   > example
   07ce528a343b2b99d4bd1bcdd648d138
   > example 2
   09b17440da02c7feb0b54f89d4d7b142
   >
   ```

#### Benchmark

See [benchmark](docs/benchmark.md) for details:

[![performance comparison graphic](docs/_static/performance_comparison.svg)](docs/_static/performance_comparison.svg)

<details>
   <summary>Time per operation graphic</summary>
  
   [![performance comparison / time per operation graphic](docs/_static/time_per_operation.svg)](docs/_static/time_per_operation.svg)
   
</details>

Graphics analyze reveals:

1. optimal number of threads is equals to: `(number of process cores)` OR `(number of process cores) * 2`
2. multithreading increases processing performance up to 8-10x times

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

## [Changelog](CHANGELOG.md)
## [License (MIT)](LICENSE)
