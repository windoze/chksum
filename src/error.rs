use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid algorithm '{0}'.")]
    InvalidAlgorithmError(String),

    #[error("'{0}' is inaccessible or not a file.")]
    InvalidFileError(PathBuf),

    #[error("Cannot guess algorithm with {0} bytes hash value.")]
    UnknownAlgorithmError(usize),

    #[error("Hash value '{0}' is invalid.")]
    InvalidHashValue(String),

    #[error("Unknown error.")]
    UnknownError,
}
