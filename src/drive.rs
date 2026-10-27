//! Blocking loops that run a [`Handshake`] over a transport.

use core::fmt;
use std::io::{self, Read, Write};

use crate::method::{Established, Framing, Handshake};

/// The longest message [`drive_stream`] frames or accepts, in bytes.
pub const MAX_MESSAGE: usize = 1 << 20;

const CHUNK: usize = 16 * 1024;

/// The marker inside the `io::Error` a frame function returns for a frame longer than
/// [`MAX_MESSAGE`], so the drivers can report it as [`DriveError::TooLong`].
#[derive(Debug)]
pub(crate) struct FrameTooLong;

impl fmt::Display for FrameTooLong {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("frame is longer than MAX_MESSAGE")
    }
}

impl core::error::Error for FrameTooLong {}

/// The four-byte big-endian length that opens a frame of `length` bytes.
pub(crate) fn frame_header(length: usize, kind: io::ErrorKind) -> io::Result<[u8; 4]> {
    match u32::try_from(length) {
        Ok(header) if length <= MAX_MESSAGE => Ok(header.to_be_bytes()),
        _ => Err(io::Error::new(kind, FrameTooLong)),
    }
}

/// The length a frame header declares, refused above [`MAX_MESSAGE`].
pub(crate) fn frame_length(header: [u8; 4]) -> io::Result<u64> {
    let length = u32::from_be_bytes(header);
    frame_header(
        usize::try_from(length).unwrap_or(usize::MAX),
        io::ErrorKind::InvalidData,
    )?;
    Ok(u64::from(length))
}

/// A short frame body: the stream ended inside it.
pub(crate) fn check_whole(message: &[u8], length: u64) -> io::Result<()> {
    if u64::try_from(message.len()).ok() == Some(length) {
        Ok(())
    } else {
        Err(io::ErrorKind::UnexpectedEof.into())
    }
}

/// The driver error for an `io::Error` from the transport or a frame function.
pub(crate) fn transport_error<E>(error: io::Error) -> DriveError<E> {
    if error
        .get_ref()
        .is_some_and(|inner| inner.is::<FrameTooLong>())
    {
        DriveError::TooLong
    } else {
        DriveError::Io(error)
    }
}

/// Writes `message` as one frame, its length first as four big-endian bytes, and flushes.
///
/// This is the framing [`drive_stream`] gives a [`Framing::Message`] handshake, for a method
/// that sends other messages over the same stream (a pairing exchange, an announcement).
///
/// # Errors
///
/// `InvalidInput` when `message` is longer than [`MAX_MESSAGE`]; otherwise the stream's error.
pub fn write_frame<W: Write + ?Sized>(io: &mut W, message: &[u8]) -> io::Result<()> {
    io.write_all(&frame_header(message.len(), io::ErrorKind::InvalidInput)?)?;
    io.write_all(message)?;
    io.flush()
}

/// Reads one frame written by [`write_frame`]. The buffer grows as bytes arrive, so a declared
/// length costs nothing until the peer sends it.
///
/// # Errors
///
/// `InvalidData` when the declared length is above [`MAX_MESSAGE`], `UnexpectedEof` when the
/// stream ends inside the frame; otherwise the stream's error.
pub fn read_frame<R: Read + ?Sized>(io: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    io.read_exact(&mut header)?;
    let length = frame_length(header)?;
    let mut message = Vec::new();
    io.take(length).read_to_end(&mut message)?;
    check_whole(&message, length)?;
    Ok(message)
}

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

impl<E: core::error::Error + 'static> fmt::Display for DriveError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("transport failed during the handshake"),
            Self::Handshake(error) => write!(formatter, "handshake failed: {error}"),
            Self::TooLong => formatter.write_str("handshake message is too long"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for DriveError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
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
            let message = read_frame(io).map_err(transport_error)?;
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
            write_frame(io, &out).map_err(transport_error)?;
        } else {
            io.write_all(&out).map_err(DriveError::Io)?;
        }
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
