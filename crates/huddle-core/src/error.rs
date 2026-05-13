use thiserror::Error;

#[derive(Debug, Error)]
pub enum HuddleError {
    #[error("identity error: {0}")]
    Identity(String),

    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("network error: {0}")]
    Network(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, HuddleError>;
