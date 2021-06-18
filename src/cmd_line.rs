use std::path::PathBuf;
use std::num::ParseIntError;
use std::str::FromStr;
use structopt::StructOpt;
use crate::error::AppError;

#[derive(Debug, StructOpt)]
#[structopt(name = "chksum", about = "A tool to generate and verify file checksums.", rename_all = "kebab-case")]
pub struct AppArgs {
    #[structopt(subcommand)]  // Note that we mark a field as a subcommand
    pub cmd: Commands,
}

#[derive(Clone, Debug, StructOpt)]
pub struct GenerationOpt {
    #[structopt(name = "CHECKSUMS", short = "f", parse(from_os_str), default_value = "checksums.txt")]
    pub checksum_file: PathBuf,

    #[structopt(short, default_value)]
    pub algorithm: Algorithm,

    #[structopt(short, default_value)]
    pub num_threads: ThreadNum,

    #[structopt(name = "DIR", short = "d", parse(from_os_str), default_value = ".")]
    pub directory: PathBuf,

}

#[derive(Clone, Debug, StructOpt)]
pub struct VerificationOpt {
    #[structopt(name = "CHECKSUMS", short = "f", parse(from_os_str), default_value = "checksums.txt")]
    pub checksum_file: PathBuf,

    #[structopt(short)]
    pub algorithm: Option<Algorithm>,

    #[structopt(short, default_value)]
    pub num_threads: ThreadNum,

    #[structopt(short)]
    pub quiet: bool,
}

#[derive(Debug, StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub enum Commands {
    G {
        #[structopt(flatten)]
        generation_opts: GenerationOpt,
    },

    V {
        #[structopt(flatten)]
        verification_opts: VerificationOpt,
    },
}

#[derive(Copy, Clone, Debug)]
pub struct ThreadNum(pub usize);

impl Default for ThreadNum {
    fn default() -> Self {
        Self(num_cpus::get_physical())
    }
}

impl ToString for ThreadNum {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for ThreadNum {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        usize::from_str(s).map(|v| Self(v))
    }
}

impl Into<usize> for ThreadNum {
    fn into(self) -> usize {
        self.0
    }
}

impl From<usize> for ThreadNum {
    fn from(v: usize) -> Self {
        Self(v)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Algorithm {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::SHA256
    }
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match self {
            Algorithm::MD5 => "MD5",
            Algorithm::SHA1 => "SHA1",
            Algorithm::SHA224 => "SHA224",
            Algorithm::SHA256 => "SHA256",
            Algorithm::SHA384 => "SHA384",
            Algorithm::SHA512 => "SHA512",
        }.to_string()
    }
}

impl FromStr for Algorithm {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "MD5" => Algorithm::MD5,
            "SHA1" => Algorithm::SHA1,
            "SHA224" => Algorithm::SHA224,
            "SHA256" => Algorithm::SHA256,
            "SHA384" => Algorithm::SHA384,
            "SHA512" => Algorithm::SHA512,
            "SHA-1" => Algorithm::SHA1,
            "SHA-224" => Algorithm::SHA224,
            "SHA-256" => Algorithm::SHA256,
            "SHA-384" => Algorithm::SHA384,
            "SHA-512" => Algorithm::SHA512,
            _ => return Err(AppError::InvalidAlgorithmError(s.to_owned()))
        })
    }
}
