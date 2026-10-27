//! `WaitingQueue`: the store's bounds on waiting peers, without the store.

use core::net::SocketAddr;
use core::time::Duration;
use std::time::Instant;

use coqui_peer::{PeerId, WaitingLimits, WaitingQueue};

fn id(n: u8) -> PeerId {
    PeerId::of(&[n])
}

fn from(text: &str) -> Option<SocketAddr> {
    Some(text.parse().expect("a socket address"))
}

fn limits(per_source: usize, total: usize) -> WaitingLimits {
    WaitingLimits {
        per_source,
        total,
        rerecord: Duration::from_secs(60),
    }
}

#[test]
fn a_source_past_its_share_gives_up_its_oldest_entries() {
    let mut queue = WaitingQueue::new(limits(2, 100));
    let now = Instant::now();
    for n in 1..=2 {
        let admitted = queue.admit(id(n), from("192.0.2.1:1"), 0, now);
        assert!(admitted.record && admitted.evict.is_empty());
    }
    let admitted = queue.admit(id(3), from("192.0.2.1:2"), 2, now);
    assert!(admitted.record);
    assert_eq!(admitted.evict, [id(1)]);
    // Another source has its own share.
    assert!(
        queue
            .admit(id(4), from("192.0.2.2:1"), 2, now)
            .evict
            .is_empty()
    );
}

#[test]
fn a_full_queue_records_nothing_and_drops_nothing() {
    let mut queue = WaitingQueue::new(limits(16, 3));
    let admitted = queue.admit(id(1), from("192.0.2.1:1"), 3, Instant::now());
    assert!(!admitted.record && admitted.evict.is_empty());
}

#[test]
fn the_same_peer_from_the_same_source_waits_out_the_rerecord_time() {
    let mut queue = WaitingQueue::new(limits(16, 100));
    let now = Instant::now();
    assert!(queue.admit(id(1), from("192.0.2.1:1"), 0, now).record);
    assert!(
        !queue
            .admit(id(1), from("192.0.2.1:9"), 0, now + Duration::from_secs(59))
            .record
    );
    assert!(
        queue
            .admit(id(1), from("192.0.2.1:9"), 0, now + Duration::from_secs(60))
            .record
    );
    // From another source it is recorded at once.
    assert!(queue.admit(id(2), from("192.0.2.1:1"), 0, now).record);
    assert!(queue.admit(id(2), from("192.0.2.2:1"), 0, now).record);
}

#[test]
fn ipv6_sources_count_by_prefix_and_mapped_ipv4_by_address() {
    let now = Instant::now();
    let mut queue = WaitingQueue::new(limits(1, 100));
    assert_eq!(queue.ipv6_prefix(), 64);
    assert!(queue.admit(id(1), from("[2001:db8::1]:1"), 0, now).record);
    // Another address in the same /64 is the same source.
    assert_eq!(
        queue.admit(id(2), from("[2001:db8::2]:1"), 1, now).evict,
        [id(1)]
    );
    assert!(
        queue
            .admit(id(3), from("192.0.2.1:1"), 1, now)
            .evict
            .is_empty()
    );
    assert_eq!(
        queue
            .admit(id(4), from("[::ffff:192.0.2.1]:1"), 2, now)
            .evict,
        [id(3)]
    );
    // Grouped by /128, each IPv6 address is a source of its own.
    let mut exact = WaitingQueue::new(limits(1, 100)).with_ipv6_prefix(200);
    assert_eq!(exact.ipv6_prefix(), 128);
    assert!(exact.admit(id(1), from("[2001:db8::1]:1"), 0, now).record);
    assert!(
        exact
            .admit(id(2), from("[2001:db8::2]:1"), 1, now)
            .evict
            .is_empty()
    );
}

#[test]
fn peers_with_no_address_share_one_source() {
    let mut queue = WaitingQueue::new(limits(1, 100));
    let now = Instant::now();
    assert!(queue.admit(id(1), None, 0, now).record);
    assert_eq!(queue.admit(id(2), None, 1, now).evict, [id(1)]);
}

#[test]
fn a_queue_seeded_from_stored_entries_applies_the_same_bounds() {
    let mut queue = WaitingQueue::new(limits(2, 100));
    let now = Instant::now();
    assert!(queue.remember(id(1), from("192.0.2.1:1"), now).is_empty());
    assert!(
        queue
            .remember(id(2), from("192.0.2.1:1"), now + Duration::from_secs(1))
            .is_empty()
    );
    // An older entry seeded late is placed by its time, and is the one forgotten.
    assert_eq!(
        queue.remember(id(3), from("192.0.2.1:1"), now - Duration::from_secs(1)),
        [id(3)]
    );
    assert!(
        !queue
            .admit(id(1), from("192.0.2.1:1"), 2, now + Duration::from_secs(2))
            .record
    );
    queue.forget(&id(1));
    assert!(
        queue
            .admit(id(1), from("192.0.2.1:1"), 1, now + Duration::from_secs(2))
            .record
    );
}
