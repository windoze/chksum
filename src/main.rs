mod error;
mod checksum;
mod cmd_line;

use std::fs::{OpenOptions, File};
use std::io::{Write, BufRead, BufReader, Read};
use std::path::{PathBuf, Path};
use std::sync::mpsc::channel;

use anyhow::Result;
use itertools::{join, Itertools};
use structopt::StructOpt;
use threadpool::ThreadPool;
use walkdir::{WalkDir, DirEntry};

use crate::checksum::{calculate_checksum, verify_checksum};
use crate::cmd_line::{AppArgs, Commands, GenerationOpt, VerificationOpt};
use crate::error::AppError;

fn output_checksum(entry: DirEntry, opts: &GenerationOpt) -> Result<(PathBuf, Vec<u8>)> {
    let path = entry.path();
    if path.is_dir() || !path.is_file() {
        return Err(AppError::InvalidFileError(path.to_path_buf()).into());
    }
    let c = calculate_checksum(path, opts.algorithm)?;
    Ok((path.to_owned(), c))
}

struct Exclusion {
    e: Vec<PathBuf>,
}

impl Exclusion {
    fn new(excludes: &Vec<PathBuf>, checksum_file: &PathBuf) -> Self {
        Self {
            e: excludes.iter().filter_map(|p| {
                if p.to_string_lossy() == "-" {
                    if checksum_file.to_string_lossy() == "-" {
                        None
                    } else {
                        checksum_file.canonicalize().ok()
                    }
                } else {
                    p.canonicalize().ok()
                }
            }).unique().collect()
        }
    }

    fn is_excluded(&self, path: &Path) -> bool {
        let c = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", e);
                return false;
            }
        };
        for p in self.e.iter() {
            if p == &c { return true; }
        }
        false
    }
}

fn generate_checksums(opts: &GenerationOpt) -> Result<bool> {
    let pool = ThreadPool::new(opts.num_threads.into());
    let dot_prefix = format!(".{}", std::path::MAIN_SEPARATOR);
    let mut all_succeeded: bool = true;
    {
        let (tx, rx) = channel();
        let mut count: usize = 0;
        let exclusion = Exclusion::new(&opts.exclude, &opts.checksum_file);
        for entry in opts.directory.iter().map(|d| WalkDir::new(d).follow_links(true).same_file_system(true)).flatten() {
            match entry {
                Ok(e) => {
                    if e.path().is_dir() || !e.path().is_file() || exclusion.is_excluded(e.path()) {
                        continue;
                    }
                    let tx = tx.clone();
                    let opts = opts.clone();
                    pool.execute(move || {
                        tx.send(output_checksum(e, &opts)).expect("Internal error.");
                    });
                }
                Err(e) => {
                    eprintln!("{}", e);
                }
            };
            count += 1;
        }


        let mut output: Box<dyn Write> = if opts.checksum_file == PathBuf::from("-") {
            Box::new(std::io::stdout())
        } else {
            Box::new(OpenOptions::new().create(true).write(true).truncate(true).open(&opts.checksum_file)?)
        };

        let mut results: Vec<(PathBuf, String)> = Vec::new();
        for _ in 0..count {
            match rx.iter().next().ok_or(AppError::UnknownError)? {
                Ok((path, checksum)) => {
                    let path = path.strip_prefix(&dot_prefix).unwrap_or(&path);
                    let checksum_str = join(checksum.into_iter().map(|b| format!("{:02x}", b)), "");
                    results.push((path.to_owned(), checksum_str));
                }
                Err(e) => {
                    eprintln!("{}", e);
                    all_succeeded = false
                }
            }
        }
        results.sort_by(|e1, e2| e1.0.partial_cmp(&e2.0).unwrap());
        for e in results.into_iter() {
            output.write(format!("{}  {}\n", e.1, e.0.display()).as_bytes())?;
        }
    }
    pool.join();
    Ok(all_succeeded)
}

macro_rules! next_part {
    ($parts:expr, $line:expr) => {
         match $parts.next().ok_or(AppError::InvalidHashValue($line.to_string())) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{:?}", e);
                    continue;
                }
            }.to_owned()
    }
}

fn verify_checksums(opts: &VerificationOpt) -> Result<bool> {
    let pool = ThreadPool::new(opts.num_threads.into());
    let mut all_succeeded: bool = true;
    {
        let input: Box<dyn Read> = if opts.checksum_file == PathBuf::from("-") {
            Box::new(std::io::stdin())
        } else {
            Box::new(File::open(&opts.checksum_file)?)
        };
        let (tx, rx) = channel();
        let mut count: usize = 0;
        for line in BufReader::new(input).lines() {
            let line = line?;
            let mut parts = line.split_whitespace();

            let checksum = next_part!(parts, line);
            let path = PathBuf::from(next_part!(parts, line));
            let algorithm = opts.algorithm;
            let tx = tx.clone();

            pool.execute(move || {
                tx.send(verify_checksum(&path, &checksum, algorithm)).expect("Internal error.");
            });
            count += 1;
        }

        for _ in 0..count {
            match rx.iter().next().ok_or(AppError::UnknownError)? {
                Ok((path, is_ok)) => {
                    if is_ok {
                        if !opts.quiet {
                            println!("{}: OK", path.display());
                        }
                    } else {
                        println!("{}: FAILED", path.display());
                    }
                    all_succeeded &= is_ok;
                }
                Err(e) => {
                    eprintln!("{}", e);
                }
            }
        }
    }
    pool.join();
    Ok(all_succeeded)
}

fn main() -> Result<()> {
    let args = AppArgs::from_args();
    match &args.cmd {
        Commands::G { generation_opts: opts } => {
            if !generate_checksums(opts)? {
                std::process::exit(1);
            }
        }
        Commands::V { verification_opts: opts } => {
            if !verify_checksums(opts)? {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
