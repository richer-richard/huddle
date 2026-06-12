use thiserror::Error;

/// Errors from the pure protocol/crypto layer — a deliberate subset of the
/// client's `HuddleError` carrying only the variants the runtime-free
/// constructions actually produce (no storage / io / network). `huddle-core`
/// maps each of these to the matching `HuddleError` variant, so error kinds
/// and text are preserved across the crate boundary.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("identity error: {0}")]
    Identity(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
