//! The frame format the drivers and method crates share: four big-endian length bytes, then the
//! message, at most `MAX_MESSAGE`.

use std::io::{self, Cursor};

use coqui_peer::{MAX_MESSAGE, read_frame, write_frame};

#[test]
fn a_frame_reads_back_as_written() -> io::Result<()> {
    let mut wire = Vec::new();
    write_frame(&mut wire, b"hello")?;
    write_frame(&mut wire, b"")?;
    assert_eq!(wire[..4], 5u32.to_be_bytes());
    let mut reader = Cursor::new(wire);
    assert_eq!(read_frame(&mut reader)?, b"hello");
    assert_eq!(read_frame(&mut reader)?, b"");
    assert_eq!(
        read_frame(&mut reader).map_err(|error| error.kind()),
        Err(io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}

#[test]
fn a_declared_length_above_the_limit_is_refused_before_reading_it() {
    let length = u32::try_from(MAX_MESSAGE + 1).expect("fits");
    let mut reader = Cursor::new(length.to_be_bytes().to_vec());
    assert_eq!(
        read_frame(&mut reader).map_err(|error| error.kind()),
        Err(io::ErrorKind::InvalidData)
    );
    let mut wire = Vec::new();
    assert_eq!(
        write_frame(&mut wire, &vec![0; MAX_MESSAGE + 1]).map_err(|error| error.kind()),
        Err(io::ErrorKind::InvalidInput)
    );
    assert!(wire.is_empty());
}

#[test]
fn a_frame_cut_short_is_an_unexpected_end() {
    // The header declares the largest frame; three bytes follow. The reader grows its buffer as
    // bytes arrive, so the declaration alone costs nothing.
    let mut wire = u32::try_from(MAX_MESSAGE)
        .expect("fits")
        .to_be_bytes()
        .to_vec();
    wire.extend_from_slice(b"abc");
    assert_eq!(
        read_frame(&mut Cursor::new(wire)).map_err(|error| error.kind()),
        Err(io::ErrorKind::UnexpectedEof)
    );
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn the_async_frame_functions_speak_the_same_format() -> io::Result<()> {
    let mut wire = Vec::new();
    coqui_peer::asynch::write_frame(&mut wire, b"hello").await?;
    let mut blocking = Vec::new();
    write_frame(&mut blocking, b"hello")?;
    assert_eq!(wire, blocking);
    let mut reader = wire.as_slice();
    assert_eq!(coqui_peer::asynch::read_frame(&mut reader).await?, b"hello");
    let length = u32::try_from(MAX_MESSAGE + 1).expect("fits").to_be_bytes();
    let mut reader = length.as_slice();
    assert_eq!(
        coqui_peer::asynch::read_frame(&mut reader)
            .await
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::InvalidData)
    );
    Ok(())
}
