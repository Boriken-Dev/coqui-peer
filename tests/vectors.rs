//! The committed vectors in `tests/vectors/` pin the id text forms and the store file
//! formats (versions 1 to 4) byte for byte, so implementations in other languages can check
//! themselves against the same files.
//!
//! Regenerating the version 4 tree is a format change:
//! `cargo test --all-features --test vectors -- --ignored regenerate`

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use coqui_peer::{
    Clock, InvitationOptions, KeyMaterial, PeerId, Random, Retiring, Successor, TrustStore,
};

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn read(name: &str) -> String {
    fs::read_to_string(vectors().join(name)).unwrap()
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The DER inside a certificate-only PEM file.
fn der(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    data_encoding::BASE64.decode(body.as_bytes()).unwrap()
}

fn certificate(name: &str) -> KeyMaterial {
    KeyMaterial::new("tls", "CERTIFICATE", der(&read(name))).unwrap()
}

fn example_key() -> KeyMaterial {
    KeyMaterial::new("example", "PUBLIC KEY", (0..32).collect::<Vec<u8>>()).unwrap()
}

#[test]
fn each_id_has_the_committed_text_in_every_spelling() {
    for (cert, id) in [("cert-a.pem", "identity-a"), ("cert-b.pem", "identity-b")] {
        let expected = read(&format!("{id}.fingerprint"));
        let lines: Vec<&str> = expected.lines().collect();
        assert_eq!(lines.len(), 3, "sha256 form, bare hex, grouped base32");
        let peer = certificate(cert).id();
        assert_eq!(peer.canonical(), lines[0]);
        assert_eq!(peer.hex(), lines[1]);
        assert_eq!(peer.to_base32_grouped(), lines[2]);
        for line in lines {
            assert_eq!(line.parse::<PeerId>().unwrap(), peer);
        }
    }
}

#[test]
fn every_store_version_reads_as_committed() {
    let (a, b) = (certificate("cert-a.pem"), certificate("cert-b.pem"));
    for version in ["store-v1", "store-v2", "store-v3"] {
        let directory = tempfile::tempdir().unwrap();
        copy_tree(&vectors().join(version), directory.path());
        let store = TrustStore::open(directory.path()).unwrap();
        assert!(store.is_accepted(&a.id()), "{version}");
        assert!(!store.is_accepted(&b.id()), "{version}");
        let waiting = store.waiting().unwrap();
        assert_eq!(waiting.len(), 1, "{version}");
        assert_eq!(waiting[0].id, b.id(), "{version}");
        // Version 1 recorded no source.
        let source = (version != "store-v1").then(|| "192.0.2.7:4000".parse().unwrap());
        assert_eq!(waiting[0].source, source, "{version}");
        // Files without a method line are TLS certificates.
        assert_eq!(store.accepted_key(&a.id()), Some(a.clone()), "{version}");
        store.accept(&b.id()).unwrap();
        assert_eq!(store.accepted_key(&b.id()), Some(b.clone()), "{version}");
    }
}

#[test]
fn a_version_3_store_holds_another_methods_key() {
    let directory = tempfile::tempdir().unwrap();
    copy_tree(&vectors().join("store-v3"), directory.path());
    let store = TrustStore::open(directory.path()).unwrap();
    let key = example_key();
    assert_eq!(read("example-key.id").trim(), key.id().canonical());
    assert_eq!(store.accepted_key(&key.id()), Some(key));
    assert_eq!(store.accepted().unwrap().len(), 2);
}

#[test]
fn the_store_writes_version_3_files_as_committed() {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    let (a, b) = (certificate("cert-a.pem"), certificate("cert-b.pem"));
    store.accept_key(&a).unwrap();
    store.accept_key(&example_key()).unwrap();
    store.record_waiting(&b, Some("192.0.2.7:4000".parse().unwrap()));
    let committed = vectors().join("store-v3/peers");
    for section in ["accepted", "waiting"] {
        for entry in fs::read_dir(committed.join(section)).unwrap() {
            let entry = entry.unwrap();
            let written = directory
                .path()
                .join("peers")
                .join(section)
                .join(entry.file_name());
            assert_eq!(
                fs::read(&written).unwrap(),
                fs::read(entry.path()).unwrap(),
                "{section}/{}",
                entry.file_name().to_string_lossy()
            );
        }
    }
}

/// The time the version 4 vectors are written at.
const T0: u64 = 1_800_000_000;

/// The secret of the committed invitation: bytes 0x40 to 0x5f.
fn secret() -> [u8; 32] {
    std::array::from_fn(|index| 0x40 + index as u8)
}

fn second_example_key() -> KeyMaterial {
    KeyMaterial::new("example", "PUBLIC KEY", (32..64).collect::<Vec<u8>>()).unwrap()
}

fn store_at(directory: &Path, seconds: u64) -> TrustStore {
    TrustStore::open(directory)
        .unwrap()
        .with_clock(Clock::from_fn(move || {
            UNIX_EPOCH + Duration::from_secs(seconds)
        }))
}

/// Writes the version 4 tree: certificate A with B announced as its pending successor, an
/// example key replaced by a second one and retiring, and a two-use invitation.
fn write_version_4(directory: &Path) {
    let store = store_at(directory, T0);
    let (a, b) = (certificate("cert-a.pem"), certificate("cert-b.pem"));
    store.accept_key(&a).unwrap();
    store.announce_successor(&a.id(), &b).unwrap();
    let (one, two) = (example_key(), second_example_key());
    store.accept_key(&one).unwrap();
    store.announce_successor(&one.id(), &two).unwrap();
    store.promote_successor(&two.id()).unwrap();
    let random = Random::from_fn(|out| {
        out.copy_from_slice(&secret()[..out.len()]);
        Ok(())
    });
    let options = InvitationOptions {
        uses: 2,
        ..InvitationOptions::default()
    };
    store.invite(&random, options, "kitchen tablet").unwrap();
}

/// Every file under `root`, as paths relative to it, sorted.
fn files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path.strip_prefix(root).unwrap().to_owned());
            }
        }
    }
    found.sort();
    found
}

#[test]
#[ignore = "rewrites the committed version 4 vectors"]
fn regenerate() {
    let target = vectors().join("store-v4");
    let _ = fs::remove_dir_all(&target);
    write_version_4(&target);
}

#[test]
fn the_store_writes_version_4_files_as_committed() {
    let directory = tempfile::tempdir().unwrap();
    write_version_4(directory.path());
    let committed = vectors().join("store-v4");
    assert_eq!(files(directory.path()), files(&committed));
    for name in files(&committed) {
        assert_eq!(
            fs::read(directory.path().join(&name)).unwrap(),
            fs::read(committed.join(&name)).unwrap(),
            "{}",
            name.display()
        );
    }
}

#[test]
fn a_version_4_store_reads_as_committed() {
    let directory = tempfile::tempdir().unwrap();
    copy_tree(&vectors().join("store-v4"), directory.path());
    let (a, b) = (certificate("cert-a.pem"), certificate("cert-b.pem"));
    let (one, two) = (example_key(), second_example_key());
    let retires = T0 + 24 * 3600;

    let store = store_at(directory.path(), retires - 1);
    assert!(store.is_accepted(&a.id()));
    assert!(!store.is_accepted(&b.id()));
    assert_eq!(store.successor_key(&b.id()), Some(b.clone()));
    assert_eq!(
        store.successors().unwrap(),
        [Successor {
            old: a.id(),
            new: b.id()
        }]
    );
    assert!(store.is_accepted(&one.id()));
    assert!(store.is_accepted(&two.id()));
    assert_eq!(
        store.retiring().unwrap(),
        [Retiring {
            id: one.id(),
            successor: Some(two.id()),
            retires: UNIX_EPOCH + Duration::from_secs(retires)
        }]
    );
    let invitations = store.invitations().unwrap();
    assert_eq!(invitations.len(), 1);
    assert_eq!(invitations[0].uses, 2);
    assert_eq!(invitations[0].label, "kitchen tablet");

    let later = store_at(directory.path(), retires);
    assert!(!later.is_accepted(&one.id()));
    assert_eq!(later.accepted().unwrap(), {
        let mut ids = vec![a.id(), two.id()];
        ids.sort();
        ids
    });
    let redeemed = store.redeem(&secret()).unwrap();
    assert_eq!(redeemed.uses, 1);
    assert_eq!(later.promote_successor(&b.id()).unwrap(), a.id());
}
