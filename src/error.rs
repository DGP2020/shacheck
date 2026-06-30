use std::fmt;
use std::io;

#[derive(Debug)]
pub enum FsimError {
    Io(io::Error),
    Database(postgres::Error),
    InvalidPath(String),
    Notification(String),
}

impl fmt::Display for FsimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {  // fixed: was fmt::fmt::Result
        match self {
            FsimError::Io(err) => write!(f, "I/O Error: {}", err),
            FsimError::Database(err) => write!(f, "ShaktiDB Error: {}", err),
            FsimError::InvalidPath(path) => write!(f, "Invalid file path provided: {}", path),
            FsimError::Notification(msg) => write!(f, "Notification Error: {}", msg),
        }
    }
}

impl std::error::Error for FsimError {}

impl From<io::Error> for FsimError {
    fn from(err: io::Error) -> Self {
        FsimError::Io(err)
    }
}

impl From<postgres::Error> for FsimError {
    fn from(err: postgres::Error) -> Self {
        FsimError::Database(err)
    }
}
