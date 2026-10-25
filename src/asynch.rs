//! The loops of [`drive_stream`](crate::drive_stream) and
//! [`drive_messages`](crate::drive_messages) over tokio streams and async message transports.

use std::future::Future;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::drive::{DriveError, MAX_MESSAGE};
use crate::method::{Established, Framing, Handshake};

const CHUNK: usize = 16 * 1024;

/// An asynchronous transport of whole messages.
pub trait MessageTransport {
    /// Sends one message.
    fn send(&mut self, message: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// Receives the next message.
    fn recv(&mut self) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

/// [`drive_stream`](crate::drive_stream) over a tokio stream.
///
/// # Errors
///
/// [`DriveError`] when the stream fails or closes, or the handshake refuses the peer.
pub async fn drive_stream<H, T>(
    mut handshake: H,
    io: &mut T,
) -> Result<Established<H::Output>, DriveError<H::Error>>
where
    H: Handshake,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let framed = handshake.framing() == Framing::Message;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        send_all(&mut handshake, io, framed).await?;
        if handshake.is_complete() {
            return handshake.finish().map_err(DriveError::Handshake);
        }
        let received = if framed {
            let mut length = [0u8; 4];
            io.read_exact(&mut length).await.map_err(DriveError::Io)?;
            let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
            if length > MAX_MESSAGE {
                return Err(DriveError::TooLong);
            }
            let mut message = vec![0u8; length];
            io.read_exact(&mut message).await.map_err(DriveError::Io)?;
            handshake.receive(&message)
        } else {
            let read = io.read(&mut buffer).await.map_err(DriveError::Io)?;
            if read == 0 {
                return Err(DriveError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            handshake.receive(&buffer[..read])
        };
        if let Err(error) = received {
            // A method may have queued a refusal to tell the peer (a TLS alert).
            let _ = send_all(&mut handshake, io, framed).await;
            return Err(DriveError::Handshake(error));
        }
    }
}

/// Sends everything the handshake has queued, framed when it is message-oriented.
async fn send_all<H, T>(
    handshake: &mut H,
    io: &mut T,
    framed: bool,
) -> Result<(), DriveError<H::Error>>
where
    H: Handshake,
    T: AsyncWrite + Unpin,
{
    while let Some(out) = handshake.transmit().map_err(DriveError::Handshake)? {
        if framed {
            let length = u32::try_from(out.len()).map_err(|_| DriveError::TooLong)?;
            io.write_all(&length.to_be_bytes())
                .await
                .map_err(DriveError::Io)?;
        }
        io.write_all(&out).await.map_err(DriveError::Io)?;
    }
    io.flush().await.map_err(DriveError::Io)
}

/// [`drive_messages`](crate::drive_messages) over an async message transport.
///
/// # Errors
///
/// [`DriveError`] when the transport fails or the handshake refuses the peer.
pub async fn drive_messages<H, T>(
    mut handshake: H,
    transport: &mut T,
) -> Result<Established<H::Output>, DriveError<H::Error>>
where
    H: Handshake,
    T: MessageTransport,
{
    loop {
        while let Some(out) = handshake.transmit().map_err(DriveError::Handshake)? {
            transport.send(&out).await.map_err(DriveError::Io)?;
        }
        if handshake.is_complete() {
            return handshake.finish().map_err(DriveError::Handshake);
        }
        let message = transport.recv().await.map_err(DriveError::Io)?;
        if let Err(error) = handshake.receive(&message) {
            while let Ok(Some(out)) = handshake.transmit() {
                if transport.send(&out).await.is_err() {
                    break;
                }
            }
            return Err(DriveError::Handshake(error));
        }
    }
}
