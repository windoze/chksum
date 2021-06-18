use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Read;
use anyhow::Result;
use digest::{Digest, DynDigest};
use crate::cmd_line::Algorithm;
use crate::error::AppError;

fn get_hasher(algorithm: Algorithm) -> Box<dyn DynDigest> {
    match algorithm {
        Algorithm::MD5 => Box::new(md5::Md5::new()),
        Algorithm::SHA1 => Box::new(sha1::Sha1::new()),
        Algorithm::SHA224 => Box::new(sha2::Sha224::new()),
        Algorithm::SHA256 => Box::new(sha2::Sha256::new()),
        Algorithm::SHA384 => Box::new(sha2::Sha384::new()),
        Algorithm::SHA512 => Box::new(sha2::Sha512::new()),
    }
}

fn guess_algorithm(hash_size: usize) -> Result<Algorithm> {
    match hash_size {
        16 => Ok(Algorithm::MD5),
        20 => Ok(Algorithm::SHA1),
        28 => Ok(Algorithm::SHA224),
        32 => Ok(Algorithm::SHA256),
        48 => Ok(Algorithm::SHA384),
        64 => Ok(Algorithm::SHA512),
        _ => Err(AppError::UnknownAlgorithmError(hash_size * 8))?
    }
}

fn str_to_bytes(s: &str) -> Result<Vec<u8>> {
    if s.len() / 2 * 2 != s.len() {
        Err(AppError::InvalidHashValue(s.to_owned()))?;
    }
    let mut buf = Vec::<u8>::with_capacity(s.len() / 2);
    for idx in (0..s.len()).step_by(2) {
        let u8 = u8::from_str_radix(&s[idx..idx + 2], 16).or(Err(AppError::InvalidHashValue(s.to_owned())))?;
        buf.push(u8);
    }
    Ok(buf)
}

pub fn calculate_checksum(path: &Path, algorithm: Algorithm) -> Result<Vec<u8>> {
    let mut hasher = get_hasher(algorithm);
    let mut buffer = [0; 4096];
    let mut f = File::open(path)?;
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        (*hasher).update(&buffer[0..n]);
    }
    Ok(Vec::from(hasher.finalize()))
}

pub fn verify_checksum(path: &Path, checksum: &str, algorithm: Option<Algorithm>) -> Result<(PathBuf, bool)> {
    let algorithm = algorithm.unwrap_or(guess_algorithm(checksum.len() / 2)?);
    let calculated = calculate_checksum(path, algorithm);
    Ok((path.to_owned(), str_to_bytes(checksum)? == calculated?))
}

#[cfg(test)]
mod test {
    use tempfile::NamedTempFile;
    use std::io::Write;
    use crate::checksum::verify_checksum;

    #[test]
    fn test_checksum() {
        let mut file = NamedTempFile::new().unwrap();
        file.write("abcdABCD1234".as_bytes()).unwrap();
        file.flush().unwrap();
        let path = file.path();
        assert!(verify_checksum(path, "bb057481a1b7abc93ad5d70d52e3a55f", None).unwrap().1);
        assert!(verify_checksum(path, "a9c0f8c056a19fdfd18db386039bdc90e680116c", None).unwrap().1);
        assert!(verify_checksum(path, "1815e1f3522b385698aec88f13f880e838264fbd3f90f6e25f22fd8e", None).unwrap().1);
        assert!(verify_checksum(path, "423df0dab6a97c46239d196ad6f610edf5484650e9e7085634045e8b3fc19d0b", None).unwrap().1);
        assert!(verify_checksum(path, "9732f0a3c0a4cb8d834111224681e516534e74d5062e67bc5f652e5c5684d5b01795781bd5e51fdf0aeb1e13abd5004e", None).unwrap().1);
        assert!(verify_checksum(path, "56e36f3eb1a36bef4d8665f17efe30a52f190bdbaff24be9f73ed18cdbab41b09eca3256967a1b5da04d2b501e7d3cd4b0fbe55a0e64ae905aefe8676a7aaa9d", None).unwrap().1);

        assert!(!verify_checksum(path, "0b057481a1b7abc93ad5d70d52e3a55f", None).unwrap().1);
        assert!(!verify_checksum(path, "09c0f8c056a19fdfd18db386039bdc90e680116c", None).unwrap().1);
        assert!(!verify_checksum(path, "0815e1f3522b385698aec88f13f880e838264fbd3f90f6e25f22fd8e", None).unwrap().1);
        assert!(!verify_checksum(path, "023df0dab6a97c46239d196ad6f610edf5484650e9e7085634045e8b3fc19d0b", None).unwrap().1);
        assert!(!verify_checksum(path, "0732f0a3c0a4cb8d834111224681e516534e74d5062e67bc5f652e5c5684d5b01795781bd5e51fdf0aeb1e13abd5004e", None).unwrap().1);
        assert!(!verify_checksum(path, "06e36f3eb1a36bef4d8665f17efe30a52f190bdbaff24be9f73ed18cdbab41b09eca3256967a1b5da04d2b501e7d3cd4b0fbe55a0e64ae905aefe8676a7aaa9d", None).unwrap().1);
    }
}
