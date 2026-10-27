//! `coqui_peer::file` and `coqui_peer::pem`: the writes and the block format the store uses,
//! exported for method crates.

use std::fs;
use std::io;
use std::sync::{Arc, Barrier};
use std::thread;

use coqui_peer::file::{self, Access};
use coqui_peer::pem;

fn names(directory: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("readable")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn write_new_creates_parents_and_never_replaces() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("a/b/identity.pem");
    file::write_new(&path, b"first", Access::OwnerOnly)?;
    assert_eq!(
        file::write_new(&path, b"second", Access::Default).map_err(|error| error.kind()),
        Err(io::ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read(&path)?, b"first");
    // No temporary file is left behind, whichever way a write ends.
    assert_eq!(names(&directory.path().join("a/b")), ["identity.pem"]);
    Ok(())
}

#[test]
fn of_concurrent_writers_exactly_one_wins() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = Arc::new(directory.path().join("once"));
    let start = Arc::new(Barrier::new(8));
    let writers: Vec<_> = (0..8u8)
        .map(|writer| {
            let (path, start) = (Arc::clone(&path), Arc::clone(&start));
            thread::spawn(move || {
                start.wait();
                file::write_new(&path, &[writer], Access::Default).is_ok()
            })
        })
        .collect();
    let wins = writers
        .into_iter()
        .map(|writer| writer.join())
        .filter(|won| matches!(won, Ok(true)))
        .count();
    assert_eq!(wins, 1);
    assert_eq!(names(directory.path()), ["once"]);
    Ok(())
}

#[test]
fn many_writes_in_one_instant_get_their_own_temporary_files() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    for index in 0..200 {
        file::write_new(
            &directory.path().join(format!("{index}")),
            b"x",
            Access::Default,
        )?;
    }
    assert_eq!(names(directory.path()).len(), 200);
    Ok(())
}

#[test]
fn replace_swaps_the_whole_file() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    file::replace(&path, b"one", Access::Default)?;
    file::replace(&path, b"two", Access::Default)?;
    assert_eq!(fs::read(&path)?, b"two");
    assert_eq!(names(directory.path()), ["state"]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn an_owner_only_file_is_mode_0600() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("secret");
    file::write_new(&path, b"key", Access::OwnerOnly)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    Ok(())
}

#[test]
fn a_pem_block_reads_back_with_its_headers() {
    let text = format!("Method: tls\n{}", pem::encode("CERTIFICATE", &[7; 100]));
    let block = pem::decode(&text).expect("a block");
    assert_eq!(block.headers, ["Method: tls"]);
    assert_eq!(block.label, "CERTIFICATE");
    assert_eq!(block.bytes, vec![7; 100]);
}
