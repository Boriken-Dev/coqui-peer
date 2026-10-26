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
    handshake: H,
    io: &mut T,
) -> Result<Established<H::Output>, DriveError<H::Error>>
where
    H: Handshake,
    T: Read + Write,
{
    complete_stream(handshake, io)?
        .finish()
        .map_err(DriveError::Handshake)
}

/// [`drive_stream`] without the final [`finish`](Handshake::finish): returns the handshake
/// once it [`is_complete`](Handshake::is_complete), with everything it queued sent.
///
/// For a method whose own way of finishing differs from [`Handshake::finish`], such as a TLS
/// server that does not authenticate its client at that layer and so has no verified peer to
/// name. The caller finishes it with the method's own call.
///
/// # Errors
///
/// As [`drive_stream`].
pub fn complete_stream<H, T>(mut handshake: H, io: &mut T) -> Result<H, DriveError<H::Error>>
where
    H: Handshake,
    T: Read + Write,
{
    let framed = handshake.framing() == Framing::Message;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        send_all(&mut handshake, io, framed)?;
        if handshake.is_complete() {
            return Ok(handshake);
        }
        let received = if framed {
            let mut length = [0u8; 4];
            io.read_exact(&mut length).map_err(DriveError::Io)?;
            let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
            if length > MAX_MESSAGE {
                return Err(DriveError::TooLong);
            }
            let mut message = vec![0u8; length];
            io.read_exact(&mut message).map_err(DriveError::Io)?;
            handshake.receive(&message)
        } else {
            let read = io.read(&mut buffer).map_err(DriveError::Io)?;
            if read == 0 {
                return Err(DriveError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            handshake.receive(&buffer[..read])
        };
        if let Err(error) = received {
            // A method may have queued a refusal to tell the peer (a TLS alert).
            let _ = send_all(&mut handshake, io, framed);
            return Err(DriveError::Handshake(error));
        }
    }
}

/// Sends everything the handshake has queued, framed when it is message-oriented.
fn send_all<H, T>(handshake: &mut H, io: &mut T, framed: bool) -> Result<(), DriveError<H::Error>>
where
    H: Handshake,
    T: Write,
{
    while let Some(out) = handshake.transmit().map_err(DriveError::Handshake)? {
        if framed {
            let length = u32::try_from(out.len()).map_err(|_| DriveError::TooLong)?;
            io.write_all(&length.to_be_bytes())
                .map_err(DriveError::Io)?;
        }
        io.write_all(&out).map_err(DriveError::Io)?;
    }
    io.flush().map_err(DriveError::Io)
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
    handshake: H,
    transport: &mut T,
) -> Result<Established<H::Output>, DriveError<H::Error>>
where
    H: Handshake,
    T: MessageTransport,
{
    complete_messages(handshake, transport)?
        .finish()
        .map_err(DriveError::Handshake)
}

/// [`drive_messages`] without the final [`finish`](Handshake::finish), as
/// [`complete_stream`] is to [`drive_stream`].
///
/// # Errors
///
/// As [`drive_messages`].
pub fn complete_messages<H, T>(
    mut handshake: H,
    transport: &mut T,
) -> Result<H, DriveError<H::Error>>
where
    H: Handshake,
    T: MessageTransport,
{
    loop {
        while let Some(out) = handshake.transmit().map_err(DriveError::Handshake)? {
            transport.send(&out).map_err(DriveError::Io)?;
        }
        if handshake.is_complete() {
            return Ok(handshake);
        }
        let message = transport.recv().map_err(DriveError::Io)?;
        handshake.receive(&message).map_err(DriveError::Handshake)?;
    }
}
