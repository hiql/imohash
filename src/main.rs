use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use hex;
use imohash;
use imohash::{Hasher, SAMPLE_SIZE, SAMPLE_THRESHOLD};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

/// Hashes a set of files, returns a channel
///
/// # Examples
///
/// ```rust
/// use std::path::PathBuf;
/// let receiver = imohash::sum_files(vec![
///     PathBuf::from("/bin/cp"),
///     PathBuf::from("/bin/mv"),
///     PathBuf::from("/bin/rm"),
/// ], None, None, None);
/// loop {
///     let hash_result = receiver.recv();
///     match hash_result {
///         // Since sender is not dropping explicitly, RecvError will occur, when no any Sender
///         Err(std::sync::mpsc::RecvError) => break,
///         Ok(hash_result) => {
///             let (hash, file_path) = hash_result;
///             println!("{}  {}", hash, file_path)
///         }
///     }
/// }
/// ```
pub fn sum_files<P: AsRef<Path>>(
    file_paths: Vec<P>,
    sample_size: Option<u32>,      // for forward-compatibility purpose
    sample_threshold: Option<u32>, // for forward-compatibility purpose
    threads_count: Option<u8>,
) -> std::sync::mpsc::Receiver<(u128, PathBuf)> {
    let sample_size = sample_size.unwrap_or(SAMPLE_SIZE);
    let sample_threshold = sample_threshold.unwrap_or(SAMPLE_THRESHOLD);
    let threads_count = threads_count.unwrap_or_else(|| {
        (thread::available_parallelism().unwrap().get() * 2) as u8 // two threads per core
    }) as usize;
    assert!(threads_count > 0);

    // todo remove after split Hasher into functions
    let hasher = Arc::new(Hasher::with_sample_size_and_threshold(
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
        let shared_hasher = Arc::clone(&hasher); // todo remove after split `Hasher` into functions
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

#[derive(Debug)]
pub struct Config {
    pub sample_threshold: u32,
    pub sample_size: u32,
    pub format: String,
    pub interactive: bool,
    pub file_paths: Vec<PathBuf>,
    pub threads: u8,
}

impl Config {
    pub fn from_args(args: Vec<String>) -> Result<Self, String> {
        let command: Command = create_cli_parser();
        let matches: ArgMatches = command.get_matches_from(&args);

        let sample_threshold: u32 = matches.get_one::<u32>("sample_threshold").unwrap().clone();
        let sample_size: u32 = matches.get_one::<u32>("sample_size").unwrap().clone();
        let threads: u8 = matches.get_one::<u8>("threads").unwrap().clone();
        let format: String = matches.get_one::<String>("format").unwrap().clone();
        let interactive: bool = matches.get_flag("interactive");
        let file_paths: Vec<PathBuf> = matches
            .get_many::<PathBuf>("file_path")
            .map(|v| v.cloned().collect())
            .unwrap_or_default();

        Ok(Self {
            sample_threshold,
            sample_size,
            format,
            interactive,
            file_paths,
            threads,
        })
    }
}

fn run_interactive(sample_size: u32, sample_threshold: u32, format: String) {
    // todo remove after split Hasher into functions
    let imohash = imohash::Hasher::with_sample_size_and_threshold(sample_size, sample_threshold);

    println!("Running in interactive mode (format: {})", format);
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => break, // EOF (Ctrl+D)
            Ok(_) => {
                let data = input.trim().as_bytes();
                let hash = imohash.sum(data);
                println!("{}", format_hash(hash.unwrap(), &*format));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => break, // Ctrl+C
            Err(e) => {
                eprintln!("Input error: {}", e);
                break;
            }
        }
    }
}

fn run_sum_files(
    file_paths: Vec<PathBuf>,
    sample_size: u32,
    sample_threshold: u32,
    format: String,
    threads_count: Option<u8>,
) {
    let receiver = sum_files(
        file_paths,
        Some(sample_size),
        Some(sample_threshold),
        threads_count,
    );

    loop {
        let hash_result = receiver.recv();
        match hash_result {
            // Since sender is not dropping explicitly, RecvError will occur, when no any Sender
            Err(std::sync::mpsc::RecvError) => break,
            Ok(hash_result) => {
                let (hash, file_path) = hash_result;
                println!(
                    "{}  {}",
                    format_hash(hash, &format),
                    file_path.to_str().unwrap()
                )
            }
        }
    }
}

fn format_hash(hash: u128, format: &str) -> String {
    match format {
        "int" => format!("{:?}", hash),
        "bytes" => format!("{:?}", hash.to_le_bytes()),
        "hex" => hex::encode(hash.to_le_bytes()),
        _ => panic!("Unknown format: {}", format),
    }
}

fn create_cli_parser() -> Command {
    Command::new("imohash")
        .about("imohash is a sample application to hash files, similar to md5sum.")
        .arg(
            Arg::new("sample_threshold")
                .short('t')
                .long("sample-threshold")
                .help("Sample threshold value")
                .default_value("131072")  // see `imohash::SAMPLE_THRESHOLD`
                .value_parser(value_parser!(u32))
        )
        .arg(
            Arg::new("sample_size")
                .short('s')
                .long("sample-size")
                .help("Sample size value. The entire file will be hashed (i.e. no sampling), if sample_size < 1.")
                .default_value("16384")  // see `imohash::SAMPLE_SIZE`
                .value_parser(value_parser!(u32))
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .help("Count of threads to compute files sum in")
                .default_value("4")
                .requires("file_path")
                .value_parser(value_parser!(u8))
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .help("Hash representation format")
                .value_parser(["int", "bytes", "hex"])
                .default_value("hex")
        )
        .arg(
            Arg::new("interactive")
                .short('i')
                .long("interactive")
                .help("Interactive hash computation mode. Conflicts with [file_path]... argument.")
                .action(ArgAction::SetTrue)
                .conflicts_with("file_path")
                .conflicts_with("threads")
        )
        .arg(
            Arg::new("file_path")
                .help("File paths to compute hash of. Conflict with `-i/--interactive` argument.")
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append)
                .num_args(0..)
        )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let config = Config::from_args(args)?;

    if config.file_paths.is_empty() {
        run_interactive(config.sample_threshold, config.sample_size, config.format);
        return Ok(());
    }

    run_sum_files(
        config.file_paths,
        config.sample_threshold,
        config.sample_size,
        config.format,
        Some(config.threads),
    );

    Ok(())
}
