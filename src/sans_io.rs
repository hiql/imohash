use std::ops::Range;

/// An implementation of the [crate::Hasher] that works on sources that aren't
/// byte slices or [std::fs::File]s.
///
/// Because of the API provided by [murmur3], this requires storing the entire value
/// to be hashed in memory.
/// Because `imohash` takes three samples --
/// from the start, the middle and the end of the file --
/// this will store as much as `3 * sample_size` bytes
/// by the end of the computation.
///
/// To use this, you need to run [SansIoHasher::wants_read] and
/// [SansIoHasher::feed] in a loop. Here's a simple usage example, reading
/// from a [std::fs::File]:
///
/// ```
/// use imohash::sans_io::SansIoHasher;
/// use std::io::{Read, Seek};
///
/// let path = "samples/system.evtx";
/// let mut file = std::fs::File::open(path)?;
/// let meta = std::fs::metadata(path)?;
/// let mut hasher = SansIoHasher::new(meta.len());
/// let hash = loop {
///     // It is safe to ignore the "end" parameter,
///     // though consider using it to avoid unnecessary reads.
///     // In this example, we'll use reads of 1k each time.
///     let read_from = hasher.wants_read().start;
///     file.seek(std::io::SeekFrom::Start(read_from))?;
///     let mut data = vec![0; 1024];
///     file.read_exact(&mut data)?;
///
///     // After data has been read, the hasher needs to be fed with this data.
///     // It returns either an Ok with the result,
///     // or Err with itself (indicating that it wants more data).
///     hasher = match hasher.feed(&data) {
///         Ok(hash) => break hash,
///         Err(h) => h,
///     };
/// };
///
/// assert_eq!(hash, 0x8de46d017667d62e70f5487dc944a080);
/// Ok::<_, std::io::Error>(())
/// ```
pub struct SansIoHasher {
    sample_size: u32,

    file_size: u64,

    /// The data that we're planning to feed to the inner hash function.
    hash_buffer: Vec<u8>,

    /// What piece of the file are we waiting for?
    current_phase: SansIoHasherPhase,

    /// The offsets inside the file that we still want to receive.
    current_missing_range: Range<u64>,
}

impl SansIoHasher {
    /// Initialize a hasher.
    /// Requires knowing the size of the source file.
    ///
    /// Uses default parameters for sample threshold and size.
    /// For custom parameters (as in [crate::Hasher::with_sample_size_and_threshold]),
    /// use [SansIoHasher::new_with_options].
    pub fn new(file_size: u64) -> Self {
        Self::new_with_options(file_size, crate::SAMPLE_SIZE, crate::SAMPLE_THRESHOLD)
    }

    /// Initialize a hasher, with custom `sample_size` and `sample_threshold` values.
    pub fn new_with_options(file_size: u64, sample_size: u32, sample_threshold: u32) -> Self {
        let current_phase =
            SansIoHasherPhase::get_init_phase(sample_size, sample_threshold, file_size);
        let current_missing_range = current_phase.get_file_range(sample_size, file_size);
        Self {
            sample_size,
            file_size,
            hash_buffer: Vec::new(),
            current_phase,
            current_missing_range,
        }
    }

    /// Returns a range that specifies where this hasher would like you to read the source file next.
    ///
    /// The `start` field is mandatory: you must read from this specific offset in the file.
    ///
    /// The `end` field is only informational: you're allowed to read more or less than the number of bytes implied,
    /// and extra bytes will be ignored.
    pub fn wants_read(&self) -> Range<u64> {
        self.current_missing_range.clone()
    }

    /// Provide a chunk of data to the hasher.
    /// The data must begin from the offset specified in the `start` field of [Self::wants_read].
    ///
    /// If the hasher wants more input, it will return the `Err` variant containing itself.
    /// If it's done, it will instead return a `u128` with the final hash result.
    pub fn feed(mut self, data: &[u8]) -> Result<u128, SansIoHasher> {
        // The user has given us some data starting at current_missing_range.
        // See if the amount of data is sufficient to cover the entire remaining range.
        let need_bytes_in_phase = self.current_missing_range.end - self.current_missing_range.start;
        if data.len() >= need_bytes_in_phase as usize {
            // If it is sufficient, then we insert the needed range,
            // then advance to the next phase.
            self.hash_buffer
                .extend_from_slice(&data[0..need_bytes_in_phase as usize]);

            if let Some(next_phase) = self.current_phase.get_next() {
                self.current_phase = next_phase;
                self.current_missing_range =
                    next_phase.get_file_range(self.sample_size, self.file_size);

                return Err(self);
            } else {
                // The current phase was the terminal phase,
                // and we've consumed all the input we need.
                // Therefore, we perform the hashing
                // and return the final result.
                let hash_result =
                    murmur3::murmur3_x64_128(&mut std::io::Cursor::new(&self.hash_buffer), 0)
                        .expect("hashing in memory should be infallible");
                let mut hash_bytes = hash_result.rotate_right(64).swap_bytes().to_le_bytes();
                crate::put_uvarint(&mut hash_bytes, self.file_size);
                return Ok(u128::from_le_bytes(hash_bytes));
            }
        }

        // Otherwise, we don't have enough data to fill the current requirement.
        // We advance the start cursor by the length of the data they've provided.
        self.current_missing_range.start += data.len() as u64;
        self.hash_buffer.extend_from_slice(data);

        Err(self)
    }
}

/// Represents a request to read some data from the source.
pub struct SansIoWantsRead {
    /// From what offset should you read from?
    /// A value of 0 indicates that the first byte should be read.
    pub whence: u64,

    /// How many bytes are to be read.
    pub size: u64,
}

/// Internal enum that tracks what piece of the file we're waiting for.
#[derive(Clone, Copy)]
enum SansIoHasherPhase {
    /// A sample at the start of the file.
    Start,

    /// A sample in the middle of the file.
    Middle,

    /// A sample at the end of the file.
    End,

    /// The entire file.
    Full,
}

impl SansIoHasherPhase {
    fn get_init_phase(sample_size: u32, sample_threshold: u32, file_size: u64) -> Self {
        if sample_size < 1
            || file_size < sample_threshold as u64
            || file_size < (4 * sample_size) as u64
        {
            Self::Full
        } else {
            Self::Start
        }
    }

    fn get_file_range(&self, sample_size: u32, file_size: u64) -> Range<u64> {
        let sample_size = sample_size as u64;
        match self {
            SansIoHasherPhase::Start => 0..sample_size,
            SansIoHasherPhase::Middle => (file_size / 2)..(file_size / 2 + sample_size),
            SansIoHasherPhase::End => file_size - sample_size..file_size,
            SansIoHasherPhase::Full => 0..file_size,
        }
    }

    fn get_next(&self) -> Option<Self> {
        match self {
            Self::Start => Some(Self::Middle),
            Self::Middle => Some(Self::End),
            Self::End => None,
            Self::Full => None,
        }
    }
}

#[cfg(test)]
mod test {

    use crate::sans_io::SansIoHasher;

    /// Copied from `crate::tests::test_sum`.
    #[test]
    fn test_sum_sansio() {
        let tests = [
            (16384, 131072, 0, "00000000000000000000000000000000"),
            (16384, 131072, 1, "01659e2ec0f3c75bf39e43a41adb5d4f"),
            (16384, 131072, 127, "7f47671cc79d4374404b807249f3166e"),
            (16384, 131072, 128, "800183e5dbea2e5199ef7c8ea963a463"),
            (16384, 131072, 4095, "ff1f770d90d3773949d89880efa17e60"),
            (16384, 131072, 4096, "802048c26d66de432dbfc71afca6705d"),
            (16384, 131072, 131072, "8080085a3d3af2cb4b3a957811cdf370"),
            (16384, 131073, 131072, "808008282d3f3b53e1fd132cc51fcc1d"),
            (16384, 131072, 500000, "a0c21e44a0ba3bddee802a9d1c5332ca"),
            (50, 131072, 300000, "e0a712edd8815c606344aed13c44adcf"),
            (0, 100, 999, "e7078bfc9bdf7d7706adbd21002bb752"),
            (50, 9999, 999, "e7078bfc9bdf7d7706adbd21002bb752"),
            (250, 20, 999, "e7078bfc9bdf7d7706adbd21002bb752"),
            (250, 20, 1000, "e807ae87d3dafb5eb6518a5a256297e9"),
        ];

        for test in tests {
            let hasher = SansIoHasher::new_with_options(test.2, test.0, test.1);
            let content = m(test.2 as usize);
            let hash = feed_hasher_with_slice(hasher, &content);
            let hash_str = hex::encode(hash.to_le_bytes()).to_owned();
            assert_eq!(test.3, hash_str);
        }
    }

    #[test]
    fn test_equivalent_sansio_and_classic() {
        for size in [999, 1024, 131072, 300000, 500000] {
            let data = m(size);
            let original_hash = crate::Hasher::new()
                .sum(&data)
                .expect("hashing from memory should be infallible");
            let hasher = SansIoHasher::new(data.len() as u64);
            let hash = feed_hasher_with_slice(hasher, &data);
            assert_eq!(original_hash, hash);
        }
    }

    fn feed_hasher_with_slice(mut hasher: SansIoHasher, data: &[u8]) -> u128 {
        loop {
            let source = hasher.wants_read();
            let chunk =
                &data[source.start as usize..(source.start as usize + 1024).min(data.len())];
            hasher = match hasher.feed(chunk) {
                Ok(final_res) => return final_res,
                Err(h) => h,
            }
        }
    }

    fn m(n: usize) -> Vec<u8> {
        use md5::Digest;
        let mut buffer: Vec<u8> = Vec::new();
        let mut md5 = md5::Md5::new();
        let mut input: Vec<u8> = vec![0u8; (n + 15) / 16];
        input.fill(b'A');
        for i in (0..n).step_by(16) {
            md5.update(&input[0..1 + i / 16]);
            let mut output: [u8; 16] = [0; 16];
            md5.finalize_into_reset((&mut output).into());
            buffer.append(&mut output[0..(n - i).min(16)].to_vec());
        }
        buffer
    }
}
