//! Blocking loops that run a [`Handshake`] over a transport.

use std::fmt;
use std::io::{self, Read, Write};

use crate::method::{Established, Framing, Handshake};

/// The longest message [`drive_stream`] frames or accepts, in bytes.
pub const MAX_MESSAGE: usize = 1 << 20;

const CHUNK: usize = 16 * 1024;

/// Why driving a handshake failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum DriveError<E> {
    /// The transport failed or closed before the handshake finished.
    Io(io::Error),
    /// The handshake refused the peer or failed.
    Handshake(E),
    /// A peer sent a frame longer than [`MAX_MESSAGE`].
    TooLong,
}

impl<E: std::error::Error + 'static> fmt::Display for DriveError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("transport failed during the handshake"),
            Self::Handshake(error) => write!(formatter, "handshake failed: {error}"),
            Self::TooLong => formatter.write_str("handshake message is too long"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for DriveError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Handshake(error) => Some(error),
            Self::TooLong => None,
        }
    }
}

/// A blocking transport of whole messages: WebSocket messages, datagrams, a shared-memory
/// queue.
pub trait MessageTransport {
    /// Sends one message.
    ///
    /// # Errors
    ///
    /// When the transport fails.
    fn send(&mut self, message: &[u8]) -> io::Result<()>;

    /// Receives the next message.
    ///
    /// # Errors
    ///
    /// When the transport fails or is closed.
    fn recv(&mut self) -> io::Result<Vec<u8>>;
}

/// Runs `handshake` to completion over a blocking byte stream.
///
/// A [`Framing::Stream`] handshake exchanges its bytes as they are; a [`Framing::Message`]
/// handshake has each message prefixed with its length, four big-endian bytes. Nothing is
/// read once the handshake is complete.
///
/// # Errors
///
/// [`DriveError`] when the stream fails or closes, or the handshake refuses the peer.
pub fn drive_stream<H, T>(
    mut handshake: H,
    io: &mut T,
) -> Result<Established<H::Output>, DriveError<H::Error>>
where
    H: Handshake,
    T: Read + Write,
{
    let framed = handshake.framing() == Framing::Message;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        while let Some(out) = handshake.transmit().map_err(DriveError::Handshake)? {
            if framed {
                let length = u32::try_from(out.len()).map_err(|_| DriveError::TooLong)?;
                io.write_all(&length.to_be_bytes())
                    .map_err(DriveError::Io)?;
            }
            io.write_all(&out).map_err(DriveError::Io)?;
        }
        io.flush().map_err(DriveError::Io)?;
        if handshake.is_complete() {
            return handshake.finish().map_err(DriveError::Handshake);
        }
        if framed {
            let mut length = [0u8; 4];
            io.read_exact(&mut length).map_err(DriveError::Io)?;
            let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
            if length > MAX_MESSAGE {
                return Err(DriveError::TooLong);
            }
            let mut message = vec![0u8; length];
            io.read_exact(&mut message).map_err(DriveError::Io)?;
            handshake.receive(&message).map_err(DriveError::Handshake)?;
        } else {
            let read = io.read(&mut buffer).map_err(DriveError::Io)?;
            if read == 0 {
                return Err(DriveError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            handshake
                .receive(&buffer[..read])
                .map_err(DriveError::Handshake)?;
        }
    }
}

/// Runs `handshake` to completion over a blocking message transport. Each message the
/// handshake sends is one transport message, and each received one is handed over whole,
/// for either [`Framing`].
///
/// Use a transport that delivers messages reliably and in order; a handshake does not
/// recover from a lost datagram.
///
/// # Errors
///
/// [`DriveError`] when the transport fails or the handshake refuses the peer.
pub fn drive_messages<H, T>(
    mut handshake: H,
    transport: &mut T,
) -> Result<Established<H::Output>, DriveError<H::Error>>
where
    H: Handshake,
    T: MessageTransport,
{
    loop {
        while let Some(out) = handshake.transmit().map_err(DriveError::Handshake)? {
            transport.send(&out).map_err(DriveError::Io)?;
        }
        if handshake.is_complete() {
            return handshake.finish().map_err(DriveError::Handshake);
        }
        let message = transport.recv().map_err(DriveError::Io)?;
        handshake.receive(&message).map_err(DriveError::Handshake)?;
    }
}
