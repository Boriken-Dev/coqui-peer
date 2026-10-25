//! The waiting queue is bounded per source, remembers the source, and keeps each method's
//! key material as given.

use std::net::SocketAddr;
use std::time::Duration;

use coqui_peer::{Error, KeyMaterial, TrustStore, WaitingLimits};

fn store() -> (tempfile::TempDir, TrustStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    (directory, store)
}

fn key(method: &str, seed: u8) -> KeyMaterial {
    KeyMaterial::new(method, "PUBLIC KEY", vec![seed; 40]).unwrap()
}

fn record(store: &TrustStore, key: &KeyMaterial, source: &str) {
    let source: SocketAddr = source.parse().unwrap();
    store.record_waiting(key, Some(source));
}

#[test]
fn pairing_moves_a_waiting_peer_to_accepted() {
    let (_directory, store) = store();
    let peer = key("example", 1);
    record(&store, &peer, "192.0.2.1:1000");
    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].id, peer.id());
    assert_eq!(waiting[0].source, Some("192.0.2.1:1000".parse().unwrap()));
    assert!(!store.is_accepted(&peer.id()));

    store.accept(&peer.id()).unwrap();
    assert!(store.is_accepted(&peer.id()));
    assert!(store.waiting().unwrap().is_empty());
    assert_eq!(store.accepted_key(&peer.id()), Some(peer.clone()));
    assert!(matches!(
        store.accept(&peer.id()),
        Err(Error::AlreadyAccepted)
    ));
    assert!(store.remove(&peer.id()).unwrap());
    assert!(!store.is_accepted(&peer.id()));
    assert!(matches!(store.accept(&peer.id()), Err(Error::NotWaiting)));
}

#[test]
fn keys_of_several_methods_live_side_by_side() {
    let (_directory, store) = store();
    let (one, two) = (key("alpha", 1), key("beta", 2));
    store.accept_key(&one).unwrap();
    store.accept_key(&two).unwrap();
    assert_eq!(store.accepted().unwrap().len(), 2);
    assert_eq!(store.accepted_key(&one.id()).unwrap().method, "alpha");
    assert_eq!(store.accepted_key(&two.id()).unwrap().method, "beta");
}

#[test]
fn a_file_that_does_not_hash_to_its_name_is_not_accepted() {
    let (directory, store) = store();
    let (real, other) = (key("example", 1), key("example", 2));
    store.accept_key(&other).unwrap();
    let accepted = directory.path().join("peers/accepted");
    std::fs::rename(
        accepted.join(format!("{}.pem", other.id().hex())),
        accepted.join(format!("{}.pem", real.id().hex())),
    )
    .unwrap();
    assert!(!store.is_accepted(&real.id()));
    assert!(store.accepted_key(&real.id()).is_none());
}

#[test]
fn one_source_filling_its_cap_does_not_block_another() {
    let (_directory, store) = store();
    let store = store.with_limits(WaitingLimits {
        per_source: 2,
        total: 100,
        rerecord: Duration::from_secs(60),
    });
    let noisy: Vec<KeyMaterial> = (0..3).map(|seed| key("example", seed)).collect();
    for peer in &noisy {
        record(&store, peer, "192.0.2.1:1000");
    }
    let quiet = key("example", 9);
    record(&store, &quiet, "192.0.2.2:2000");

    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 3);
    let from = |ip: &str| {
        waiting
            .iter()
            .filter(|entry| entry.source.is_some_and(|s| s.ip().to_string() == ip))
            .count()
    };
    assert_eq!(from("192.0.2.1"), 2);
    assert_eq!(from("192.0.2.2"), 1);
    assert!(waiting.iter().all(|entry| entry.id != noisy[0].id()));
    assert!(waiting.iter().any(|entry| entry.id == quiet.id()));
}

#[test]
fn the_total_cap_stops_recording() {
    let (_directory, store) = store();
    let store = store.with_limits(WaitingLimits {
        per_source: 100,
        total: 2,
        rerecord: Duration::from_secs(60),
    });
    for seed in 0..5 {
        record(&store, &key("example", seed), "192.0.2.1:1000");
    }
    assert_eq!(store.waiting().unwrap().len(), 2);
}

#[test]
fn the_rerecord_interval_holds_per_source() {
    let (_directory, store) = store();
    let peer = key("example", 1);
    record(&store, &peer, "192.0.2.1:1000");
    store.remove(&peer.id()).unwrap();

    record(&store, &peer, "192.0.2.1:1001");
    assert!(store.waiting().unwrap().is_empty());
    record(&store, &peer, "192.0.2.2:2000");
    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].source, Some("192.0.2.2:2000".parse().unwrap()));
}

#[test]
fn oversized_or_malformed_keys_are_not_recorded() {
    let (_directory, store) = store();
    let huge = KeyMaterial {
        method: "example".to_owned(),
        label: "PUBLIC KEY".to_owned(),
        bytes: vec![1; coqui_peer::MAX_KEY_BYTES + 1],
    };
    store.record_waiting(&huge, None);
    let bad_method = KeyMaterial {
        method: "Bad Method".to_owned(),
        label: "PUBLIC KEY".to_owned(),
        bytes: vec![1; 8],
    };
    store.record_waiting(&bad_method, None);
    assert!(store.waiting().unwrap().is_empty());
    assert!(matches!(store.accept_key(&huge), Err(Error::Material)));
}
