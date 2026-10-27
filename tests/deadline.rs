//! The `_until` loops end at their deadline with `DriveError::TimedOut`, and finish as the plain
//! loops do when the peer answers in time.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use coqui_peer::{
    DriveError, Established, Framing, Handshake, MessageTransport, PeerId, ReadTimeout,
    complete_stream_until, drive_messages_until, drive_stream_until, read_frame, write_frame,
};

#[derive(Debug)]
struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("refused")
    }
}

impl std::error::Error for Refused {}

/// Sends one message and completes once it has received one.
struct Once {
    framing: Framing,
    sent: bool,
    received: bool,
}

impl Once {
    fn new(framing: Framing) -> Once {
        Once {
            framing,
            sent: false,
            received: false,
        }
    }
}

impl Handshake for Once {
    type Output = ();
    type Error = Refused;

    fn framing(&self) -> Framing {
        self.framing
    }

    fn receive(&mut self, input: &[u8]) -> Result<(), Refused> {
        self.received |= !input.is_empty();
        Ok(())
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, Refused> {
        if self.sent {
            return Ok(None);
        }
        self.sent = true;
        Ok(Some(b"hello".to_vec()))
    }

    fn is_complete(&self) -> bool {
        self.sent && self.received
    }

    fn finish(self) -> Result<Established<()>, Refused> {
        Ok(Established {
            peer: PeerId::of(b"peer"),
            key: None,
            session: (),
        })
    }
}

/// A connected pair; the far end is handed to `peer`, which runs on its own thread.
fn pair(peer: impl FnOnce(TcpStream) + Send + 'static) -> io::Result<TcpStream> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    thread::spawn(move || {
        if let Ok((socket, _)) = listener.accept() {
            peer(socket);
        }
    });
    TcpStream::connect(address)
}

/// Reads what it is sent and never answers, until the other side closes.
fn silent(mut socket: TcpStream) {
    let mut sink = [0u8; 64];
    while matches!(socket.read(&mut sink), Ok(read) if read > 0) {}
}

#[test]
fn a_silent_peer_ends_the_stream_loop_at_its_deadline() -> io::Result<()> {
    let mut socket = pair(silent)?;
    let started = Instant::now();
    let result = drive_stream_until(
        Once::new(Framing::Stream),
        &mut socket,
        started + Duration::from_millis(300),
    );
    assert!(matches!(result, Err(DriveError::TimedOut)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // The read timeout is cleared for whoever uses the stream next.
    assert_eq!(socket.read_timeout()?, None);
    Ok(())
}

#[test]
fn a_peer_that_answers_in_time_finishes_the_loop() -> io::Result<()> {
    let mut socket = pair(|mut socket| {
        let _ = read_frame(&mut socket).and_then(|_| write_frame(&mut socket, b"hi"));
    })?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let done = complete_stream_until(Once::new(Framing::Message), &mut socket, deadline);
    assert!(matches!(done, Ok(once) if once.is_complete()));
    Ok(())
}

#[test]
fn a_deadline_already_past_times_out_before_reading() -> io::Result<()> {
    let mut socket = pair(silent)?;
    let result = drive_stream_until(Once::new(Framing::Stream), &mut socket, Instant::now());
    assert!(matches!(result, Err(DriveError::TimedOut)), "{result:?}");
    Ok(())
}

/// Whole messages as frames over TCP.
struct Framed(TcpStream);

impl MessageTransport for Framed {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        write_frame(&mut self.0, message)
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        read_frame(&mut self.0)
    }
}

impl ReadTimeout for Framed {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }
}

#[test]
fn a_silent_peer_ends_the_message_loop_at_its_deadline() -> io::Result<()> {
    let mut transport = Framed(pair(silent)?);
    let started = Instant::now();
    let result = drive_messages_until(
        Once::new(Framing::Message),
        &mut transport,
        started + Duration::from_millis(300),
    );
    assert!(matches!(result, Err(DriveError::TimedOut)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    transport.0.flush()
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn the_async_loops_end_at_their_deadline() {
    let (mut near, far) = tokio::io::duplex(1024);
    let started = Instant::now();
    let result = coqui_peer::asynch::drive_stream_until(
        Once::new(Framing::Stream),
        &mut near,
        started + Duration::from_millis(200),
    )
    .await;
    assert!(matches!(result, Err(DriveError::TimedOut)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(far);
}
