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

// huddle 2.0.4 (WS1.1): map the pure-layer error from `huddle-protocol` back to
// the matching `HuddleError` variant, so error kinds and messages are preserved
// across the crate boundary — a caller that `?`-propagates a `crypto` / `invite`
// / `identity` error sees exactly the variant it saw before the extraction.
impl From<huddle_protocol::ProtocolError> for HuddleError {
    fn from(e: huddle_protocol::ProtocolError) -> Self {
        use huddle_protocol::ProtocolError as P;
        match e {
            P::Identity(s) => HuddleError::Identity(s),
            P::Session(s) => HuddleError::Session(s),
            P::Serialization(e) => HuddleError::Serialization(e),
            P::Other(s) => HuddleError::Other(s),
        }
    }
}

pub type Result<T> = std::result::Result<T, HuddleError>;
