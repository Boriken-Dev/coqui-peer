//! The `coqui-transport` feature: `PeerFrame` is `write_frame`'s and `read_frame`'s wire, and a
//! channel drives a handshake as a message transport.
#![cfg(feature = "coqui-transport")]

use std::io::{self, Cursor};
use std::thread;
use std::time::{Duration, Instant};

use coqui_peer::transport::{ChannelTransport, PeerFrame};
use coqui_peer::{
    DriveError, Established, Framing, Handshake, MAX_MESSAGE, MessageTransport, PeerId,
    ReadTimeout, drive_messages, drive_messages_until, read_frame, write_frame,
};
use coqui_transport::frame::{Codec, Decode, FrameError};
use coqui_transport::{Channel, StreamChannel, StreamChannelBuilder, memory};
use serde_json::Value;

const WAIT: Option<Duration> = Some(Duration::from_secs(10));

fn vectors() -> Value {
    let path = format!(
        "{}/tests/vectors/peer_frame.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cases<'a>(vectors: &'a Value, key: &str) -> &'a [Value] {
    vectors[key].as_array().unwrap()
}

fn name(case: &Value) -> &str {
    case["name"].as_str().unwrap()
}

fn max(case: &Value) -> usize {
    usize::try_from(case["max"].as_u64().unwrap()).unwrap()
}

fn flag(case: &Value, key: &str) -> bool {
    case.get(key).and_then(Value::as_bool) == Some(true)
}

fn body(case: &Value) -> Vec<u8> {
    match (case.get("text"), case.get("body")) {
        (Some(text), _) => text.as_str().unwrap().as_bytes().to_vec(),
        (None, Some(body)) => bytes(body.as_str().unwrap()),
        (None, None) => panic!("{}: no body", name(case)),
    }
}

fn chunks(case: &Value) -> Vec<Vec<u8>> {
    case["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|chunk| bytes(chunk.as_str().unwrap()))
        .collect()
}

fn messages(case: &Value) -> Vec<Vec<u8>> {
    case["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| bytes(message.as_str().unwrap()))
        .collect()
}

#[test]
fn the_vectors_are_the_peer_frame() {
    assert_eq!(vectors()["codec"], "PeerFrame");
}

#[test]
fn write_frame_and_peer_frame_write_every_vector_the_same() {
    for case in cases(&vectors(), "encode") {
        let message = body(case);
        let by_codec = PeerFrame.encode(&message, max(case));
        if flag(case, "error") {
            assert_eq!(by_codec, Err(FrameError::Size), "{}", name(case));
            continue;
        }
        let expected = bytes(case["hex"].as_str().unwrap());
        assert_eq!(by_codec.as_ref(), Ok(&expected), "{}", name(case));
        let mut by_function = Vec::new();
        write_frame(&mut by_function, &message).unwrap();
        assert_eq!(hex(&by_function), hex(&expected), "{}", name(case));
    }
}

/// `read_frame`'s messages from `wire`, up to its first failure.
fn read_all(wire: Vec<u8>) -> Vec<Vec<u8>> {
    let mut cursor = Cursor::new(wire);
    let mut got = Vec::new();
    while let Ok(message) = read_frame(&mut cursor) {
        got.push(message);
    }
    got
}

#[test]
fn read_frame_and_peer_frame_read_every_vector_the_same() {
    for case in cases(&vectors(), "decode") {
        let mut decoder = PeerFrame.decoder(max(case));
        let mut got = Vec::new();
        let mut failed = false;
        'chunks: for chunk in chunks(case) {
            decoder.push(&chunk);
            loop {
                match decoder.next_frame() {
                    Ok(Some(message)) => got.push(message),
                    Ok(None) => break,
                    Err(FrameError::Size) => {
                        failed = true;
                        break 'chunks;
                    }
                    Err(other) => panic!("{}: {other:?}", name(case)),
                }
            }
        }
        assert_eq!(got, messages(case), "{}", name(case));
        assert_eq!(failed, flag(case, "error"), "{}", name(case));
        assert_eq!(
            !failed && decoder.buffered() > 0,
            flag(case, "truncated"),
            "{}",
            name(case)
        );
        // read_frame's bound is a fixed 1 MiB: it reads what the codec reads wherever the case's
        // own bound is no tighter than that, or nothing in it is over the case's bound.
        if max(case) == MAX_MESSAGE || !failed {
            let wire: Vec<u8> = chunks(case).concat();
            assert_eq!(read_all(wire), messages(case), "{}", name(case));
        }
    }
}

#[test]
fn a_channel_on_peer_frame_and_the_frame_functions_read_each_others_bytes() {
    let (mine, theirs) = memory::pipe(1 << 16);
    let channel = StreamChannel::start(mine, PeerFrame).unwrap();
    let (mut reader, mut writer) = theirs.into_halves();

    write_frame(&mut writer, b"to the channel").unwrap();
    write_frame(&mut writer, b"").unwrap();
    assert_eq!(
        channel.receive(WAIT).unwrap(),
        Some(b"to the channel".to_vec())
    );
    assert_eq!(channel.receive(WAIT).unwrap(), Some(Vec::new()));

    channel.send(b"from the channel").unwrap();
    channel.send(b"").unwrap();
    assert_eq!(read_frame(&mut reader).unwrap(), b"from the channel");
    assert_eq!(read_frame(&mut reader).unwrap(), b"");
    channel.close();
}

/// A message-framed handshake: each side sends `hello <id>` and finishes with the other's.
struct Toy {
    me: PeerId,
    dials: bool,
    sent: bool,
    peer: Option<PeerId>,
}

impl Toy {
    fn new(name: &str, dials: bool) -> Toy {
        Toy {
            me: PeerId::of(name.as_bytes()),
            dials,
            sent: false,
            peer: None,
        }
    }
}

#[derive(Debug)]
struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("refused")
    }
}

impl std::error::Error for Refused {}

impl Handshake for Toy {
    type Output = ();
    type Error = Refused;

    fn framing(&self) -> Framing {
        Framing::Message
    }

    fn receive(&mut self, input: &[u8]) -> Result<(), Refused> {
        let text = std::str::from_utf8(input).map_err(|_| Refused)?;
        let id = text.trim().strip_prefix("hello ").ok_or(Refused)?;
        self.peer = Some(id.parse().map_err(|_| Refused)?);
        Ok(())
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, Refused> {
        if self.sent || (!self.dials && self.peer.is_none()) {
            return Ok(None);
        }
        self.sent = true;
        Ok(Some(format!("hello {}", self.me).into_bytes()))
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

#[test]
fn a_handshake_runs_over_a_channel() {
    let (one, other) = memory::pipe(1 << 16);
    let server = thread::spawn(move || {
        let mut transport = ChannelTransport::new(StreamChannel::start(other, PeerFrame).unwrap());
        let seen = drive_messages(Toy::new("server", false), &mut transport).unwrap();
        transport.channel().close();
        seen
    });
    let mut transport = ChannelTransport::new(StreamChannel::start(one, PeerFrame).unwrap());
    let seen = drive_messages(Toy::new("client", true), &mut transport).unwrap();
    transport.channel().close();
    assert_eq!(seen.peer, PeerId::of(b"server"));
    assert_eq!(server.join().unwrap().peer, PeerId::of(b"client"));
}

#[test]
fn a_boxed_channel_is_a_transport_too() {
    let (one, other) = memory::pipe(1 << 16);
    let one: Box<dyn Channel> = Box::new(StreamChannel::start(one, PeerFrame).unwrap());
    let other = StreamChannel::start(other, PeerFrame).unwrap();
    let mut transport = ChannelTransport::new(one);
    transport.send(b"through a box").unwrap();
    assert_eq!(
        other.receive(WAIT).unwrap(),
        Some(b"through a box".to_vec())
    );
    other.send(b"back").unwrap();
    assert_eq!(transport.recv().unwrap(), b"back");
}

#[test]
fn the_deadline_of_an_until_driver_ends_a_silent_peer() {
    let (one, _other) = memory::pipe(1 << 16);
    let mut transport = ChannelTransport::new(StreamChannel::start(one, PeerFrame).unwrap());
    let started = Instant::now();
    let result = drive_messages_until(
        Toy::new("client", false),
        &mut transport,
        Instant::now() + Duration::from_millis(200),
    );
    assert!(matches!(result, Err(DriveError::TimedOut)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_read_timeout_bounds_recv_and_the_channel_goes_on() {
    let (one, other) = memory::pipe(1 << 16);
    let mut transport = ChannelTransport::new(StreamChannel::start(one, PeerFrame).unwrap());
    transport
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert_eq!(
        transport.recv().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    let other = StreamChannel::start(other, PeerFrame).unwrap();
    other.send(b"late").unwrap();
    assert_eq!(transport.recv().unwrap(), b"late");
}

#[test]
fn a_channel_that_ended_in_order_is_an_unexpected_end() {
    let (one, other) = memory::pipe(1 << 16);
    let mut transport = ChannelTransport::new(StreamChannel::start(one, PeerFrame).unwrap());
    StreamChannel::start(other, PeerFrame).unwrap().close();
    assert_eq!(
        transport.recv().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

/// Two channels that take messages past the drivers' limit, so the transport's own bound is what ends it.
fn wide_pair() -> (StreamChannel, StreamChannel) {
    let (one, other) = memory::pipe(1 << 22);
    let wide = |stream| {
        StreamChannelBuilder::new()
            .max_message(2 * MAX_MESSAGE)
            .codec(PeerFrame)
            .stream(stream)
            .build()
            .unwrap()
    };
    (wide(one), wide(other))
}

#[test]
fn a_message_over_the_drivers_limit_is_refused_going_out() {
    let (one, _other) = wide_pair();
    let mut transport = ChannelTransport::new(one);
    let error = transport.send(&vec![0; MAX_MESSAGE + 1]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    transport.send(&vec![0; MAX_MESSAGE]).unwrap();
}

#[test]
fn a_message_over_the_drivers_limit_coming_in_ends_the_driver_with_invalid_data() {
    let (one, other) = wide_pair();
    let mut transport = ChannelTransport::new(one);
    other.send(&vec![0; MAX_MESSAGE + 1]).unwrap();
    let result = drive_messages(Toy::new("server", false), &mut transport);
    match result {
        Err(DriveError::Io(error)) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
        other => panic!("{other:?}"),
    }
}
