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
        self.hash(&mut reader)
    }

    /// Hashs a file.
    pub fn sum_file(&self, path: &str) -> Result<u128> {
        let input_path = Path::new(path.trim());
        let path_canonicalized = input_path.canonicalize()?;
        let path_os_string = path_canonicalized.as_os_str();
        let f = File::open(path_os_string)?;
        let mut reader = BufReader::new(f);
        self.hash(&mut reader)
    }

    fn hash<R>(&self, reader: &mut R) -> Result<u128>
    where
        R: Read + Seek,
    {
        let mut buffer: Vec<u8> = Vec::new();
        let size = reader.seek(SeekFrom::End(0))?;
        reader.rewind()?;
        if self.sample_size < 1
            || size < self.sample_threshold as u64
            || size < (4 * self.sample_size) as u64
        {
            reader.read_to_end(&mut buffer)?;
        } else {
            let mut first_buf = vec![0u8; self.sample_size as usize];
            reader.read_exact(first_buf.as_mut_slice())?;
            reader.seek(SeekFrom::Start(size / 2))?;
            let mut middle_buf = vec![0u8; self.sample_size as usize];
            reader.read_exact(middle_buf.as_mut_slice())?;
            reader.seek(SeekFrom::End(-(self.sample_size as i64)))?;
            let mut last_buf = vec![0u8; self.sample_size as usize];
            reader.read_exact(last_buf.as_mut_slice())?;
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

impl Default for Hasher {
    fn default() -> Self {
        Hasher::new()
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
    use std::{fs, path::PathBuf};

    #[test]
    fn test_put_uvarint() {
        let expected = [148u8, 145, 6, 0, 0, 0, 0, 0, 0, 0];
        let mut buffer = [0u8; 10];
        let actual = put_uvarint(&mut buffer[..], 100_500);
        assert_eq!(actual, 3);
        assert_eq!(buffer, expected);
    }

    fn test_data_file_path(name: &str) -> String {
        let test_data_dir = "test_data";

        if !Path::new(test_data_dir).exists() {
            fs::create_dir(test_data_dir).unwrap();
        }

        let mut path = PathBuf::new();
        path.push(test_data_dir);
        path.push(name);
        return path.to_str().unwrap().to_string();
    }

    #[test]
    fn test_default() {
        let sample_file = test_data_file_path("default_sample");
        let data = vec![100, 131071, 131072, 50000];

        for size in data {
            let custom_hasher: Hasher = Hasher::with_sample_size_and_threshold(16384, 131072);
            let default_hasher: Hasher = Hasher::new();
            let test_data: Vec<u8> = m(size);
            assert_eq!(
                default_hasher.sum(&test_data).unwrap(),
                custom_hasher.sum(&test_data).unwrap()
            );

            let empty_byte_array: Vec<u8> = Vec::new();
            fs::write(&sample_file, empty_byte_array).unwrap();
            let h1 = default_hasher.sum_file(&sample_file).unwrap();
            let h2 = custom_hasher.sum_file(&sample_file).unwrap();
            assert_eq!(h1, h2);
        }
    }

    #[test]
    fn test_custom() {
        let sample_file = test_data_file_path("sample");
        let sample_size: u32 = 3;
        let sample_threshold: u32 = 45;

        let custom_hasher = Hasher::with_sample_size_and_threshold(sample_size, sample_threshold);

        // empty file
        let empty_byte_array: Vec<u8> = Vec::new();
        fs::write(&sample_file, empty_byte_array).unwrap();
        let hash = custom_hasher.sum_file(&sample_file).unwrap();
        let empty_byte_array: Vec<u8> = vec![0; 16];
        assert_eq!(hash.to_le_bytes(), &empty_byte_array[..]);

        // small file
        fs::write(&sample_file, b"hello").unwrap();
        let hash = custom_hasher.sum_file(&sample_file).unwrap();
        assert_eq!(
            hex::encode(hash.to_le_bytes()),
            "05d8a7b341bd9b025b1e906a48ae1d19"
        );

        /* boundary tests using the custom sample size */
        let size = sample_threshold;

        // test that changing the gaps between sample zones does not affect the hash
        let mut data: Vec<u8> = vec![b'A'; size as usize];
        fs::write(&sample_file, &data[..]).unwrap();
        let h1 = custom_hasher.sum_file(&sample_file).unwrap();

        data[sample_size as usize] = b'B';
        data[(size - sample_size - 1) as usize] = b'B';
        fs::write(&sample_file, &data[..]).unwrap();
        let h2 = custom_hasher.sum_file(&sample_file).unwrap();
        assert_eq!(h1, h2);

        // test that changing a byte on the edge (but within) a sample zone
        // does change the hash
        let mut data: Vec<u8> = vec![b'A'; size as usize];
        data[sample_size as usize - 1] = b'B';
        fs::write(&sample_file, &data[..]).unwrap();
        let h3 = custom_hasher.sum_file(&sample_file).unwrap();
        assert_ne!(h1, h3);

        let mut data: Vec<u8> = vec![b'A'; size as usize];
        data[size as usize / 2] = b'B';
        fs::write(&sample_file, &data[..]).unwrap();
        let h4 = custom_hasher.sum_file(&sample_file).unwrap();
        assert_ne!(h1, h4);
        assert_ne!(h3, h4);

        let mut data: Vec<u8> = vec![b'A'; size as usize];
        data[(size / 2 + sample_size - 1) as usize] = b'B';
        fs::write(&sample_file, &data[..]).unwrap();
        let h5 = custom_hasher.sum_file(&sample_file).unwrap();
        assert_ne!(h1, h5);
        assert_ne!(h3, h5);
        assert_ne!(h4, h5);

        let mut data: Vec<u8> = vec![b'A'; size as usize];
        data[(size - sample_size) as usize] = b'B';
        fs::write(&sample_file, &data[..]).unwrap();
        let h6 = custom_hasher.sum_file(&sample_file).unwrap();
        assert_ne!(h1, h6);
        assert_ne!(h3, h6);
        assert_ne!(h4, h6);
        assert_ne!(h5, h6);

        // test that changing the size changes the hash
        let data: Vec<u8> = vec![b'A'; size as usize + 1];
        fs::write(&sample_file, &data[..]).unwrap();
        let h7 = custom_hasher.sum_file(&sample_file).unwrap();
        assert_ne!(h1, h7);
        assert_ne!(h3, h7);
        assert_ne!(h4, h7);
        assert_ne!(h5, h7);
        assert_ne!(h6, h7);

        // test sampleSize < 1
        let hasher = Hasher::with_sample_size_and_threshold(0, size);
        let data: Vec<u8> = vec![b'A'; size as usize];
        fs::write(&sample_file, &data[..]).unwrap();
        let hash = hasher.sum_file(&sample_file).unwrap();
        assert_eq!(
            hex::encode(hash.to_le_bytes()),
            "2d9123b54d37e9b8f94ab37a7eca6f40"
        )
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
            (0, 100, 999, "e7078bfc9bdf7d7706adbd21002bb752"),
            (50, 9999, 999, "e7078bfc9bdf7d7706adbd21002bb752"),
            (250, 20, 999, "e7078bfc9bdf7d7706adbd21002bb752"),
            (250, 20, 1000, "e807ae87d3dafb5eb6518a5a256297e9"),
        ];

        for test in tests {
            let hasher = Hasher::with_sample_size_and_threshold(test.0, test.1);
            let content = m(test.2 as usize);
            let hash_str =
                hex::encode(hasher.sum(content.as_slice()).unwrap().to_le_bytes()).to_owned();
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
