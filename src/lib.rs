//! Who a peer is and whether we trust it, independent of how the peer authenticates.
//!
//! This crate has no TLS and no cryptographic transport. A method crate
//! (`coqui-peer-tls`, later `-psk`, `-noise`, `-ssh`) proves who the other side is; this
//! crate holds what every method shares.
//!
//! | Item | Purpose |
//! | --- | --- |
//! | [`PeerId`], [`Digest`] | A peer's id as `<alg>:<hash>` text, with the spellings people paste. |
//! | [`TrustStore`] | Accepted and waiting peers on disk; the pairing flow and its contract. |
//! | [`KeyMaterial`] | The public key bytes a method gives the store, tagged with its name. |
//! | [`Handshake`], [`Method`] | The sans-IO exchange a method implements, over any transport. |
//! | [`drive_stream`], [`drive_messages`] | Blocking loops that run a handshake. |
//! | [`complete_stream`], [`complete_messages`] | The same loops, leaving the finish to the caller. |
//!
//! # Features
//!
//! `default = []`. `serde` reads and writes [`PeerId`] and [`Digest`] as text. `tokio` adds
//! the [`asynch`] loops. Nothing here keeps process-global state, and nothing reads a file or
//! an environment variable unless the caller names a directory.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

#[cfg(feature = "tokio")]
pub mod asynch;
mod drive;
mod error;
mod id;
mod key;
mod method;
mod store;

pub use drive::{
    DriveError, MAX_MESSAGE, MessageTransport, complete_messages, complete_stream, drive_messages,
    drive_stream,
};
pub use error::Error;
pub use id::{Digest, PeerId};
pub use key::{KeyMaterial, MAX_KEY_BYTES};
pub use method::{Established, Framing, Handshake, Method};
pub use store::{FORMAT_VERSION, TrustStore, WaitingEntry, WaitingLimits};
