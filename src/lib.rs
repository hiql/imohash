//! Fast hashing for large files.
//!
//! It is based atop murmurhash3 and uses file size and sample data to construct the hash.

use std::fs::File;
use std::io::{BufReader, Cursor, Read, Result, Seek, SeekFrom};
use std::path::Path;

const SAMPLE_THRESHOLD: u32 = 128 * 1024;
const SAMPLE_SIZE: u32 = 16 * 1024;

/// A hasher which holds the custom sample parameters, and provides the APIs
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Hasher {
    sample_threshold: u32,
    sample_size: u32,
}

impl Hasher {
    /// Creates a new Hasher using the default sample size and sample threshhold values.
    pub fn new() -> Self {
        Self {
            sample_threshold: SAMPLE_THRESHOLD,
            sample_size: SAMPLE_SIZE,
        }
    }

    /// Creates a new Hasher using the provided sample size
    /// and sample threshhold values. The entire file will be hashed
    /// (i.e. no sampling), if sampleSize < 1.
    pub fn with_sample_size_and_threshold(size: u32, threshold: u32) -> Self {
        Self {
            sample_threshold: threshold,
            sample_size: size,
        }
    }

    /// Hashs a byte slice.
    pub fn sum(&self, data: &[u8]) -> Result<u128> {
        let mut reader = BufReader::new(Cursor::new(data));
        Ok(self.hash(&mut reader)?)
    }

    /// Hashs a file.
    pub fn sum_file(&self, path: &str) -> Result<u128> {
        let input_path = Path::new(path.trim());
        let path_canonicalized = input_path.canonicalize()?;
        let path_os_string = path_canonicalized.as_os_str();
        let f = File::open(path_os_string)?;
        let mut reader = BufReader::new(f);
        Ok(self.hash(&mut reader)?)
    }

    fn hash<R>(&self, reader: &mut R) -> Result<u128>
    where
        R: Read + Seek,
    {
        let mut buffer: Vec<u8> = Vec::new();
        let size = reader.seek(SeekFrom::End(0))?;
        reader.rewind()?;
        if size < self.sample_threshold as u64 || self.sample_size < 1u32 {
            reader.read_to_end(&mut buffer)?;
        } else {
            let mut first_buf = vec![0u8; self.sample_size as usize];
            reader.read(first_buf.as_mut_slice())?;
            reader.seek(SeekFrom::Start(size / 2))?;
            let mut middle_buf = vec![0u8; self.sample_size as usize];
            reader.read(middle_buf.as_mut_slice())?;
            reader.seek(SeekFrom::End(-(self.sample_size as i64)))?;
            let mut last_buf = vec![0u8; self.sample_size as usize];
            reader.read(last_buf.as_mut_slice())?;
            buffer.append(&mut first_buf);
            buffer.append(&mut middle_buf);
            buffer.append(&mut last_buf);
        }
        let hash_result = murmur3::murmur3_x64_128(&mut Cursor::new(buffer), 0)?;
        let mut hash_bytes = hash_result.rotate_right(64).swap_bytes().to_le_bytes();
        put_uvarint(&mut hash_bytes, size);
        Ok(u128::from_le_bytes(hash_bytes))
    }
}

fn put_uvarint(mut buffer: impl AsMut<[u8]>, x: u64) -> usize {
    let mut i = 0;
    let mut mx = x;
    let buf = buffer.as_mut();
    while mx >= 0x80 {
        buf[i] = mx as u8 | 0x80;
        mx >>= 7;
        i += 1;
    }
    buf[i] = mx as u8;
    i + 1
}

#[cfg(test)]
mod tests {

    use super::*;
    use md5::{Digest, Md5};

    #[test]
    fn test_put_uvarint() {
        let expected = [148u8, 145, 6, 0, 0, 0, 0, 0, 0, 0];
        let mut buffer = [0u8; 10];
        let actual = put_uvarint(&mut buffer[..], 100_500);
        assert_eq!(actual, 3);
        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_custom() {
        let hasher = Hasher::with_sample_size_and_threshold(3, 45);
        let actual = hasher.sum("hello".as_bytes()).unwrap();
        assert_eq!(
            "05d8a7b341bd9b025b1e906a48ae1d19",
            hex::encode(actual.to_le_bytes())
        );
    }

    #[test]
    fn test_sum_file() {
        let hasher = Hasher::new();
        let expected = "80a044c97d48f5702ed66776016de48d";
        let actual: u128 = hasher.sum_file("samples/system.evtx").unwrap();
        assert_eq!(expected, hex::encode(actual.to_le_bytes()));
    }

    #[test]
    fn test_sum() {
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
        ];

        for test in tests {
            let hasher = Hasher::with_sample_size_and_threshold(test.0, test.1);
            let content = m(test.2 as usize);
            let hash_str = format!(
                "{}",
                hex::encode(hasher.sum(content.as_slice()).unwrap().to_le_bytes())
            );
            assert_eq!(test.3, hash_str);
        }
    }

    fn m(n: usize) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut md5 = Md5::new();
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
