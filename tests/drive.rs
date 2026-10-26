//! A toy method exercises the drivers over a byte stream (chunked and framed), a message
//! transport and tokio streams.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use coqui_peer::{
    DriveError, Established, Framing, Handshake, MessageTransport, PeerId, complete_messages,
    complete_stream, drive_messages, drive_stream,
};

#[derive(Debug)]
struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("refused")
    }
}

impl std::error::Error for Refused {}

/// Each side sends `hello <id>\n` and finishes when it has sent and received one.
struct Toy {
    framing: Framing,
    me: PeerId,
    dials: bool,
    sent: bool,
    buffer: Vec<u8>,
    peer: Option<PeerId>,
}

impl Toy {
    fn new(framing: Framing, name: &str, dials: bool) -> Toy {
        Toy {
            framing,
            me: PeerId::of(name.as_bytes()),
            dials,
            sent: false,
            buffer: Vec::new(),
            peer: None,
        }
    }
}

impl Handshake for Toy {
    type Output = ();
    type Error = Refused;

    fn framing(&self) -> Framing {
        self.framing
    }

    fn receive(&mut self, input: &[u8]) -> Result<(), Refused> {
        self.buffer.extend_from_slice(input);
        let whole = match self.framing {
            Framing::Message => true,
            Framing::Stream => self.buffer.ends_with(b"\n"),
        };
        if whole {
            let text = String::from_utf8(self.buffer.clone()).map_err(|_| Refused)?;
            let id = text.trim().strip_prefix("hello ").ok_or(Refused)?;
            self.peer = Some(id.parse().map_err(|_| Refused)?);
        }
        Ok(())
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, Refused> {
        if self.sent || (!self.dials && self.peer.is_none()) {
            return Ok(None);
        }
        self.sent = true;
        Ok(Some(format!("hello {}\n", self.me).into_bytes()))
    }

    fn is_complete(&self) -> bool {
        self.sent && self.peer.is_some()
    }

    fn finish(self) -> Result<Established<()>, Refused> {
        match self.peer {
            Some(peer) if self.sent => Ok(Established {
                peer,
                key: None,
                session: (),
            }),
            _ => Err(Refused),
        }
    }
}

/// Hands out at most one byte per read, as a slow stream can.
struct Trickle<T>(T);

impl<T: Read> Read for Trickle<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let limit = buf.len().min(1);
        self.0.read(&mut buf[..limit])
    }
}

impl<T: Write> Write for Trickle<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn over_tcp(framing: Framing) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut socket = Trickle(socket);
        drive_stream(Toy::new(framing, "server", false), &mut socket).unwrap()
    });
    let mut socket = Trickle(TcpStream::connect(address).unwrap());
    let seen = drive_stream(Toy::new(framing, "client", true), &mut socket).unwrap();
    assert_eq!(seen.peer, PeerId::of(b"server"));
    assert_eq!(server.join().unwrap().peer, PeerId::of(b"client"));
}

#[test]
fn a_stream_handshake_survives_one_byte_reads() {
    over_tcp(Framing::Stream);
}

#[test]
fn a_message_handshake_is_framed_over_a_stream() {
    over_tcp(Framing::Message);
}

struct Pipe {
    out: mpsc::Sender<Vec<u8>>,
    inbox: mpsc::Receiver<Vec<u8>>,
}

impl MessageTransport for Pipe {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        self.out
            .send(message.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
    fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.inbox
            .recv()
            .map_err(|_| io::ErrorKind::UnexpectedEof.into())
    }
}

#[test]
fn a_handshake_runs_over_messages() {
    let (to_server, server_inbox) = mpsc::channel();
    let (to_client, client_inbox) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut pipe = Pipe {
            out: to_client,
            inbox: server_inbox,
        };
        drive_messages(Toy::new(Framing::Message, "server", false), &mut pipe).unwrap()
    });
    let mut pipe = Pipe {
        out: to_server,
        inbox: client_inbox,
    };
    let seen = drive_messages(Toy::new(Framing::Message, "client", true), &mut pipe).unwrap();
    assert_eq!(seen.peer, PeerId::of(b"server"));
    assert_eq!(server.join().unwrap().peer, PeerId::of(b"client"));
}

/// The complete loops stop where the drive loops would call `finish`, everything sent, and
/// hand the handshake back for the caller to finish its own way.
#[test]
fn the_complete_loops_return_the_unfinished_handshake() {
    for framing in [Framing::Stream, Framing::Message] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            complete_stream(Toy::new(framing, "server", false), &mut socket).unwrap()
        });
        let mut socket = TcpStream::connect(address).unwrap();
        let seen = drive_stream(Toy::new(framing, "client", true), &mut socket).unwrap();
        assert_eq!(seen.peer, PeerId::of(b"server"));
        let served = server.join().unwrap();
        assert!(served.is_complete());
        assert_eq!(served.peer, Some(PeerId::of(b"client")));
        assert_eq!(served.finish().unwrap().peer, PeerId::of(b"client"));
    }

    let (to_server, server_inbox) = mpsc::channel();
    let (to_client, client_inbox) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut pipe = Pipe {
            out: to_client,
            inbox: server_inbox,
        };
        complete_messages(Toy::new(Framing::Message, "server", false), &mut pipe).unwrap()
    });
    let mut pipe = Pipe {
        out: to_server,
        inbox: client_inbox,
    };
    let dialed = complete_messages(Toy::new(Framing::Message, "client", true), &mut pipe).unwrap();
    assert_eq!(dialed.peer, Some(PeerId::of(b"server")));
    assert_eq!(server.join().unwrap().peer, Some(PeerId::of(b"client")));

    let refused = complete_messages(
        Toy::new(Framing::Message, "server", false),
        &mut Script(VecDeque::from(vec![
            b"nonsense
"
            .to_vec(),
        ])),
    );
    assert!(matches!(refused, Err(DriveError::Handshake(Refused))));
}

struct Script(VecDeque<Vec<u8>>);

impl MessageTransport for Script {
    fn send(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.0
            .pop_front()
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
}

#[test]
fn a_closed_transport_and_a_refusal_are_errors() {
    let closed = drive_messages(
        Toy::new(Framing::Message, "server", false),
        &mut Script(VecDeque::new()),
    );
    assert!(matches!(closed, Err(DriveError::Io(_))));

    let refused = drive_messages(
        Toy::new(Framing::Message, "server", false),
        &mut Script(VecDeque::from(vec![b"nonsense\n".to_vec()])),
    );
    assert!(matches!(refused, Err(DriveError::Handshake(Refused))));
}

#[cfg(feature = "tokio")]
mod asynchronous {
    use super::*;
    use coqui_peer::asynch;

    #[tokio::test]
    async fn framed_and_chunked_handshakes_run_over_tokio_streams() {
        for framing in [Framing::Stream, Framing::Message] {
            let (mut near, mut far) = tokio::io::duplex(64);
            let server = tokio::spawn(async move {
                asynch::drive_stream(Toy::new(framing, "server", false), &mut far)
                    .await
                    .unwrap()
                    .peer
            });
            let seen = asynch::drive_stream(Toy::new(framing, "client", true), &mut near)
                .await
                .unwrap();
            assert_eq!(seen.peer, PeerId::of(b"server"));
            assert_eq!(server.await.unwrap(), PeerId::of(b"client"));
        }
    }

    #[tokio::test]
    async fn the_complete_loops_run_over_tokio() {
        for framing in [Framing::Stream, Framing::Message] {
            let (mut near, mut far) = tokio::io::duplex(64);
            let server = tokio::spawn(async move {
                asynch::complete_stream(Toy::new(framing, "server", false), &mut far)
                    .await
                    .unwrap()
            });
            let seen = asynch::drive_stream(Toy::new(framing, "client", true), &mut near)
                .await
                .unwrap();
            assert_eq!(seen.peer, PeerId::of(b"server"));
            let served = server.await.unwrap();
            assert!(served.is_complete());
            assert_eq!(served.peer, Some(PeerId::of(b"client")));
        }
    }

    struct Channel {
        out: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        inbox: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    }

    impl asynch::MessageTransport for Channel {
        async fn send(&mut self, message: &[u8]) -> io::Result<()> {
            self.out
                .send(message.to_vec())
                .map_err(|_| io::ErrorKind::BrokenPipe.into())
        }
        async fn recv(&mut self) -> io::Result<Vec<u8>> {
            self.inbox
                .recv()
                .await
                .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
        }
    }

    #[tokio::test]
    async fn a_handshake_runs_over_async_messages() {
        let (to_server, server_inbox) = tokio::sync::mpsc::unbounded_channel();
        let (to_client, client_inbox) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut channel = Channel {
                out: to_client,
                inbox: server_inbox,
            };
            asynch::drive_messages(Toy::new(Framing::Message, "server", false), &mut channel)
                .await
                .unwrap()
                .peer
        });
        let mut channel = Channel {
            out: to_server,
            inbox: client_inbox,
        };
        let seen = asynch::drive_messages(Toy::new(Framing::Message, "client", true), &mut channel)
            .await
            .unwrap();
        assert_eq!(seen.peer, PeerId::of(b"server"));
        assert_eq!(server.await.unwrap(), PeerId::of(b"client"));
    }

    #[tokio::test]
    async fn the_complete_loop_runs_over_async_messages() {
        let (to_server, server_inbox) = tokio::sync::mpsc::unbounded_channel();
        let (to_client, client_inbox) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut channel = Channel {
                out: to_client,
                inbox: server_inbox,
            };
            asynch::complete_messages(Toy::new(Framing::Message, "server", false), &mut channel)
                .await
                .unwrap()
                .peer
        });
        let mut channel = Channel {
            out: to_server,
            inbox: client_inbox,
        };
        let dialed =
            asynch::complete_messages(Toy::new(Framing::Message, "client", true), &mut channel)
                .await
                .unwrap();
        assert_eq!(dialed.peer, Some(PeerId::of(b"server")));
        assert_eq!(server.await.unwrap(), Some(PeerId::of(b"client")));
    }
}
