//! The waiting queue is bounded per source, remembers the source, and keeps each method's
//! key material as given; invitations redeem once, and successor keys replace accepted ones.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use coqui_peer::{
    Clock, Error, InvitationOptions, KeyMaterial, PeerId, Random, Retiring, RotationEvent,
    RotationOptions, Successor, TrustStore, WaitingLimits,
};

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

/// The waiting entries after one peer is recorded from each of `sources`, two per source at most.
fn record_from_each(sources: &[&str]) -> Vec<coqui_peer::WaitingEntry> {
    let (_directory, store) = store();
    let store = store.with_limits(WaitingLimits {
        per_source: 2,
        total: 100,
        rerecord: Duration::from_secs(60),
    });
    for (seed, source) in (0u8..).zip(sources) {
        record(&store, &key("example", seed), source);
    }
    store.waiting().unwrap()
}

#[test]
fn ipv6_sources_in_one_64_share_a_cap() {
    let waiting = record_from_each(&[
        "[2001:db8:1:2::1]:1000",
        "[2001:db8:1:2::2]:1000",
        "[2001:db8:1:2:ffff::3]:1000",
        "[2001:db8:1:3::1]:1000",
    ]);
    assert_eq!(waiting.len(), 3);
    let in_first = waiting
        .iter()
        .filter(|entry| {
            entry
                .source
                .is_some_and(|s| s.ip().to_string().starts_with("2001:db8:1:2:"))
        })
        .count();
    assert_eq!(in_first, 2);
    // The full address is kept with each entry.
    assert!(
        waiting
            .iter()
            .any(|entry| entry.source == Some("[2001:db8:1:3::1]:1000".parse().unwrap()))
    );
}

#[test]
fn ipv4_sources_keep_a_cap_each() {
    let waiting = record_from_each(&[
        "192.0.2.1:1000",
        "192.0.2.2:1000",
        "192.0.2.3:1000",
        "192.0.2.4:1000",
    ]);
    assert_eq!(waiting.len(), 4);
}

#[test]
fn ipv4_mapped_ipv6_sources_count_as_ipv4() {
    let waiting = record_from_each(&[
        "[::ffff:192.0.2.1]:1000",
        "[::ffff:192.0.2.2]:1000",
        "[::ffff:192.0.2.3]:1000",
        "192.0.2.1:2000",
        "192.0.2.1:2001",
    ]);
    // Three mapped addresses are three IPv4 sources; the fourth and fifth entries share
    // 192.0.2.1 with the first, so that source keeps its newest two.
    assert_eq!(waiting.len(), 4);
}

#[test]
fn the_ipv6_prefix_is_configurable() {
    let (_directory, store) = store();
    let store = store
        .with_limits(WaitingLimits {
            per_source: 1,
            total: 100,
            rerecord: Duration::from_secs(60),
        })
        .with_ipv6_prefix(48);
    for (seed, source) in (0u8..).zip(["[2001:db8:1:2::1]:1000", "[2001:db8:1:3::1]:1000"]) {
        record(&store, &key("example", seed), source);
    }
    assert_eq!(store.waiting().unwrap().len(), 1);

    let (_directory, store) = self::store();
    let store = store
        .with_limits(WaitingLimits {
            per_source: 1,
            total: 100,
            rerecord: Duration::from_secs(60),
        })
        .with_ipv6_prefix(128);
    for (seed, source) in (0u8..).zip(["[2001:db8:1:2::1]:1000", "[2001:db8:1:2::2]:1000"]) {
        record(&store, &key("example", seed), source);
    }
    assert_eq!(store.waiting().unwrap().len(), 2);
}

/// A clock the test moves by hand, in seconds since the Unix epoch.
#[derive(Clone)]
struct Hand(Arc<AtomicU64>);

impl Hand {
    fn at(seconds: u64) -> Self {
        Self(Arc::new(AtomicU64::new(seconds)))
    }

    fn clock(&self) -> Clock {
        let now = self.0.clone();
        Clock::from_fn(move || UNIX_EPOCH + Duration::from_secs(now.load(Ordering::SeqCst)))
    }

    fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

/// A deterministic source, for tests only: a counter.
fn counting() -> Random {
    let next = Arc::new(AtomicU64::new(1));
    Random::from_fn(move |out| {
        for byte in out {
            *byte = next.fetch_add(1, Ordering::SeqCst) as u8;
        }
        Ok(())
    })
}

const T0: u64 = 1_800_000_000;

#[test]
fn an_invitation_redeems_once() {
    let (directory, store) = store();
    let hand = Hand::at(T0);
    let store = store.with_clock(hand.clock());
    let invitation = store
        .invite(&counting(), InvitationOptions::default(), "kitchen tablet")
        .unwrap();
    assert_eq!(invitation.uses, 1);
    assert_eq!(
        invitation.expires,
        UNIX_EPOCH + Duration::from_secs(T0 + 24 * 3600)
    );
    let listed = store.invitations().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, invitation.id());
    assert_eq!(listed[0].label, "kitchen tablet");
    // The secret is not written anywhere in the store.
    let text = std::fs::read_to_string(
        directory
            .path()
            .join(format!("peers/invitations/{}.inv", invitation.id())),
    )
    .unwrap();
    assert!(!text.contains(&PeerId::from_bytes(invitation.secret).hex()));

    let redeemed = store.redeem(&invitation.secret).unwrap();
    assert_eq!(redeemed.uses, 0);
    assert_eq!(redeemed.label, "kitchen tablet");
    assert!(matches!(
        store.redeem(&invitation.secret),
        Err(Error::NotInvited)
    ));
    assert!(store.invitations().unwrap().is_empty());
    assert!(matches!(store.redeem(&[9; 32]), Err(Error::NotInvited)));
}

#[test]
fn an_invitation_with_uses_counts_them_down() {
    let (_directory, store) = store();
    let options = InvitationOptions {
        uses: 2,
        ..InvitationOptions::default()
    };
    let invitation = store.invite(&counting(), options, "").unwrap();
    assert_eq!(store.redeem(&invitation.secret).unwrap().uses, 1);
    assert_eq!(store.invitations().unwrap()[0].uses, 1);
    assert_eq!(store.redeem(&invitation.secret).unwrap().uses, 0);
    assert!(store.redeem(&invitation.secret).is_err());
}

#[test]
fn concurrent_redemptions_of_one_use_succeed_once() {
    let (_directory, store) = store();
    // Many rounds: the race shows only now and then.
    for round in 0..50 {
        let invitation = store
            .invite(&counting(), InvitationOptions::default(), "")
            .unwrap();
        let wins: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| store.redeem(&invitation.secret).is_ok()))
                .collect();
            handles
                .into_iter()
                .map(|handle| usize::from(handle.join().unwrap()))
                .sum()
        });
        assert_eq!(wins, 1, "round {round}");
    }
}

#[test]
fn an_expired_invitation_is_refused_and_removed() {
    let (_directory, store) = store();
    let hand = Hand::at(T0);
    let store = store.with_clock(hand.clock());
    let options = InvitationOptions {
        valid_for: Duration::from_secs(600),
        uses: 1,
    };
    let invitation = store.invite(&counting(), options, "").unwrap();
    hand.advance(599);
    assert_eq!(store.invitations().unwrap().len(), 1);
    hand.advance(1);
    assert!(matches!(
        store.redeem(&invitation.secret),
        Err(Error::Expired)
    ));
    assert!(store.invitations().unwrap().is_empty());
}

#[test]
fn a_revoked_invitation_cannot_be_redeemed() {
    let (_directory, store) = store();
    let invitation = store
        .invite(&counting(), InvitationOptions::default(), "")
        .unwrap();
    assert!(store.revoke_invitation(&invitation.id()).unwrap());
    assert!(!store.revoke_invitation(&invitation.id()).unwrap());
    assert!(matches!(
        store.redeem(&invitation.secret),
        Err(Error::NotInvited)
    ));
}

#[test]
fn meaningless_invitation_options_are_errors() {
    let (_directory, store) = store();
    let zero_uses = InvitationOptions {
        uses: 0,
        ..InvitationOptions::default()
    };
    let zero_time = InvitationOptions {
        valid_for: Duration::ZERO,
        ..InvitationOptions::default()
    };
    for (options, label) in [
        (zero_uses, ""),
        (zero_time, ""),
        (InvitationOptions::default(), "two\nlines"),
        (InvitationOptions::default(), " padded"),
    ] {
        assert!(matches!(
            store.invite(&counting(), options, label),
            Err(Error::InvalidOptions)
        ));
    }
}

#[test]
fn a_successor_is_promoted_and_the_old_key_retires() {
    let (_directory, store) = store();
    let hand = Hand::at(T0);
    let store = store.with_clock(hand.clock());
    let (old, new) = (key("example", 1), key("example", 2));
    store.accept_key(&old).unwrap();
    assert!(store.successor_key(&new.id()).is_none());
    store.announce_successor(&old.id(), &new).unwrap();
    assert_eq!(store.successor_key(&new.id()), Some(new.clone()));
    assert!(!store.is_accepted(&new.id()));
    assert_eq!(
        store.successors().unwrap(),
        [Successor {
            old: old.id(),
            new: new.id(),
            proven: None,
        }]
    );

    store.prove_successor(&new.id()).unwrap();

    assert_eq!(store.promote_successor(&new.id()).unwrap(), old.id());
    assert!(store.is_accepted(&new.id()));
    assert!(store.is_accepted(&old.id()));
    assert!(store.successors().unwrap().is_empty());
    let retires = UNIX_EPOCH + Duration::from_secs(T0 + 24 * 3600);
    assert_eq!(
        store.retiring().unwrap(),
        [Retiring {
            id: old.id(),
            successor: Some(new.id()),
            retires
        }]
    );
    assert_eq!(
        store.take_rotation_events(),
        [
            RotationEvent::Announced {
                old: old.id(),
                new: new.id()
            },
            RotationEvent::Promoted {
                old: old.id(),
                new: new.id(),
                retires
            }
        ]
    );
    assert!(store.take_rotation_events().is_empty());

    hand.advance(24 * 3600 - 1);
    assert!(store.is_accepted(&old.id()));
    hand.advance(1);
    assert!(!store.is_accepted(&old.id()));
    assert!(store.accepted_key(&old.id()).is_none());
    assert_eq!(store.accepted().unwrap(), [new.id()]);
    // A retiring key announces nothing.
    assert!(matches!(
        store.announce_successor(&old.id(), &key("example", 3)),
        Err(Error::NotAccepted)
    ));
}

#[test]
fn the_retire_window_is_an_option() {
    let (_directory, store) = store();
    let hand = Hand::at(T0);
    let store = store
        .with_clock(hand.clock())
        .with_rotation(RotationOptions {
            retire_after: Duration::ZERO,
            require_approval: true,
            ..RotationOptions::default()
        });
    assert!(store.rotation().require_approval);
    let (old, new) = (key("example", 1), key("example", 2));
    store.accept_key(&old).unwrap();
    store.announce_successor(&old.id(), &new).unwrap();
    store.prove_successor(&new.id()).unwrap();
    store.promote_successor(&new.id()).unwrap();
    assert!(!store.is_accepted(&old.id()));
    assert!(store.is_accepted(&new.id()));
}

#[test]
fn removing_a_key_drops_its_pending_successor() {
    let (directory, store) = store();
    let (old, new) = (key("example", 1), key("example", 2));
    store.accept_key(&old).unwrap();
    store.announce_successor(&old.id(), &new).unwrap();
    assert!(store.remove(&old.id()).unwrap());
    assert!(store.successor_key(&new.id()).is_none());
    assert!(store.successors().unwrap().is_empty());
    assert!(
        !directory
            .path()
            .join(format!("peers/successors/{}.pem", new.id().hex()))
            .exists()
    );
    assert!(matches!(
        store.promote_successor(&new.id()),
        Err(Error::NoSuccessor)
    ));
}

#[test]
fn a_new_announcement_replaces_the_pending_successor() {
    let (_directory, store) = store();
    let (old, first, second) = (key("example", 1), key("example", 2), key("example", 3));
    store.accept_key(&old).unwrap();
    store.announce_successor(&old.id(), &first).unwrap();
    store.announce_successor(&old.id(), &second).unwrap();
    assert!(store.successor_key(&first.id()).is_none());
    assert_eq!(store.successor_key(&second.id()), Some(second));
    assert!(matches!(
        store.announce_successor(&key("example", 9).id(), &first),
        Err(Error::NotAccepted)
    ));
    assert!(matches!(
        store.announce_successor(&old.id(), &old),
        Err(Error::Material)
    ));
}

#[test]
fn an_accepted_key_cannot_claim_another_keys_successor() {
    let (_directory, store) = store();
    let hand = Hand::at(T0);
    let store = store.with_clock(hand.clock());
    let (rotating, other, successor) = (key("example", 1), key("example", 2), key("example", 3));
    store.accept_key(&rotating).unwrap();
    store.accept_key(&other).unwrap();
    store
        .announce_successor(&rotating.id(), &successor)
        .unwrap();
    // The other peer learned the successor and announces it as its own.
    assert!(matches!(
        store.announce_successor(&other.id(), &successor),
        Err(Error::SuccessorTaken)
    ));
    assert_eq!(
        store.successors().unwrap(),
        [Successor {
            old: rotating.id(),
            new: successor.id(),
            proven: None,
        }]
    );
    // Promotion retires the key that announced it, and only that one.
    store.prove_successor(&successor.id()).unwrap();
    assert_eq!(
        store.promote_successor(&successor.id()).unwrap(),
        rotating.id()
    );
    hand.advance(24 * 3600);
    assert!(!store.is_accepted(&rotating.id()));
    assert!(store.is_accepted(&other.id()));
}

#[test]
fn a_retired_key_that_pairs_again_is_accepted_again() {
    let (_directory, store) = store();
    let hand = Hand::at(T0);
    let store = store.with_clock(hand.clock());
    let (old, new) = (key("example", 1), key("example", 2));
    store.accept_key(&old).unwrap();
    store.announce_successor(&old.id(), &new).unwrap();
    store.prove_successor(&new.id()).unwrap();
    store.promote_successor(&new.id()).unwrap();
    hand.advance(24 * 3600);
    assert!(!store.is_accepted(&old.id()));
    // Accepting it again (a new pairing) makes it current, not a silent no-op.
    store.accept_key(&old).unwrap();
    assert!(store.is_accepted(&old.id()));
    assert!(store.retiring().unwrap().is_empty());
    assert!(matches!(
        store.accept_key(&old),
        Err(Error::AlreadyAccepted)
    ));
}

#[test]
fn a_revocation_wins_over_redemptions_in_flight() {
    let (_directory, store) = store();
    let options = InvitationOptions {
        uses: 1_000_000,
        ..InvitationOptions::default()
    };
    for round in 0..20 {
        let random = counting();
        // A different secret each round: skip the bytes earlier rounds drew.
        for _ in 0..round {
            random.fill(&mut [0u8; 32]).unwrap();
        }
        let invitation = store.invite(&random, options, "").unwrap();
        let wins = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..300 {
                        if store.redeem(&invitation.secret).is_ok() {
                            wins.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
            // Revoke while redemptions run; the spin is bounded so a lost invitation cannot
            // hang the test.
            for _ in 0..1_000_000 {
                if wins.load(Ordering::SeqCst) >= 3 {
                    break;
                }
                std::thread::yield_now();
            }
            store.revoke_invitation(&invitation.id()).unwrap();
        });
        assert!(
            matches!(store.redeem(&invitation.secret), Err(Error::NotInvited)),
            "round {round}"
        );
        assert!(store.invitations().unwrap().is_empty(), "round {round}");
    }
}

#[test]
fn a_successor_is_promoted_only_once_proven_unless_allowed() {
    let (_directory, store) = store();
    let hand = Hand::at(T0);
    let store = store.with_clock(hand.clock());
    let (old, new) = (key("example", 1), key("example", 2));
    store.accept_key(&old).unwrap();
    store.announce_successor(&old.id(), &new).unwrap();
    assert!(matches!(
        store.promote_successor(&new.id()),
        Err(Error::NotProven)
    ));
    assert_eq!(store.successors().unwrap()[0].proven, None);
    hand.advance(5);
    store.prove_successor(&new.id()).unwrap();
    hand.advance(5);
    store.prove_successor(&new.id()).unwrap();
    // The first proof's time is kept.
    assert_eq!(
        store.successors().unwrap()[0].proven,
        Some(UNIX_EPOCH + Duration::from_secs(T0 + 5))
    );
    assert_eq!(store.promote_successor(&new.id()).unwrap(), old.id());

    // An option promotes without a proof.
    let (old, new) = (key("example", 3), key("example", 4));
    let store = store.with_rotation(RotationOptions {
        allow_unproven: true,
        ..RotationOptions::default()
    });
    store.accept_key(&old).unwrap();
    store.announce_successor(&old.id(), &new).unwrap();
    assert_eq!(store.promote_successor(&new.id()).unwrap(), old.id());
    assert!(matches!(
        store.prove_successor(&key("example", 9).id()),
        Err(Error::NoSuccessor)
    ));
}
