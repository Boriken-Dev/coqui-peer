use std::fmt;
use std::io;

/// Failures of ids, key material and the trust store. No message holds key material or a
/// path.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A [`PeerId`](crate::PeerId) is malformed.
    InvalidId,
    /// An id is an MD5 digest, which is not supported.
    WeakDigest,
    /// A digest name is unknown; the name is carried.
    UnknownDigest(String),
    /// Stored key material is malformed, too large, or does not hash to its id.
    Material,
    /// The peer is not waiting for acceptance.
    NotWaiting,
    /// The peer was already accepted.
    AlreadyAccepted,
    /// A filesystem or stream operation failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId => formatter.write_str("peer id is invalid"),
            Self::WeakDigest => {
                formatter.write_str("peer id is an MD5 digest, which is not supported")
            }
            Self::UnknownDigest(name) => write!(
                formatter,
                "unknown digest {name:?}; supported: sha256, sha384, sha512, sha1"
            ),
            Self::Material => formatter.write_str("key material is invalid"),
            Self::NotWaiting => formatter.write_str("peer is not waiting for acceptance"),
            Self::AlreadyAccepted => formatter.write_str("peer is already accepted"),
            Self::Io(_) => formatter.write_str("storage or stream operation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
