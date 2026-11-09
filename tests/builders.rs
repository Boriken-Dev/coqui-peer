//! Each builder setter reaches what it builds, `settings` takes the whole, the last setter wins,
//! and the store takes new waiting settings.

use std::time::{Duration, UNIX_EPOCH};

use coqui_peer::pair::{DeskLimits, PairingDesk, PairingDeskSettings, PairingOptions};
use coqui_peer::{
    Clock, Random, RotationOptions, TrustStore, TrustStoreSettings, WaitingLimits, WaitingQueue,
    WaitingSettings, WhenFull,
};

fn limits(per_source: usize) -> WaitingLimits {
    let mut limits = WaitingLimits::default();
    limits.per_source = per_source;
    limits
}

fn rotation() -> RotationOptions {
    let mut rotation = RotationOptions::default();
    rotation.retire_after = Duration::from_secs(5);
    rotation
}

fn random() -> Random {
    Random::from_fn(|out| {
        out.fill(1);
        Ok(())
    })
}

#[test]
fn every_store_setter_reaches_the_store() {
    let directory = tempfile::tempdir().unwrap();
    let clock = Clock::from_fn(|| UNIX_EPOCH + Duration::from_secs(9));
    let store = TrustStore::builder(directory.path())
        .limits(limits(3))
        .ipv6_prefix(48)
        .when_full(WhenFull::ReplaceOldest)
        .record_interval(Duration::from_millis(5))
        .rotation(rotation())
        .clock(clock)
        .build()
        .unwrap();
    let settings = store.settings();
    assert_eq!(settings.waiting.limits.per_source, 3);
    assert_eq!(settings.waiting.ipv6_prefix, 48);
    assert_eq!(settings.waiting.when_full, WhenFull::ReplaceOldest);
    assert_eq!(settings.waiting.record_interval, Duration::from_millis(5));
    assert_eq!(settings.rotation.retire_after, Duration::from_secs(5));
    assert_eq!(store.rotation(), settings.rotation);
    assert_eq!(store.clock().now(), UNIX_EPOCH + Duration::from_secs(9));
    assert_eq!(store.non_defaults().len(), 5);
}

#[test]
fn a_store_takes_its_settings_whole_and_the_last_setter_wins() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = TrustStoreSettings::default();
    settings.waiting.limits.total = 9;
    settings.rotation.require_approval = true;
    let store = TrustStore::builder(directory.path())
        .ipv6_prefix(32)
        .settings(settings)
        .limits(limits(2))
        .limits(limits(7))
        .build()
        .unwrap();
    let built = store.settings();
    assert_eq!(built.waiting.ipv6_prefix, 64);
    assert_eq!(built.waiting.limits.total, WaitingLimits::default().total);
    assert_eq!(built.waiting.limits.per_source, 7);
    assert!(built.rotation.require_approval);
}

#[test]
fn open_is_the_builder_with_every_setting_at_its_default() {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    assert_eq!(store.settings(), TrustStoreSettings::default());
    assert!(store.non_defaults().is_empty());
}

#[test]
fn every_queue_setter_reaches_the_queue() {
    let queue = WaitingQueue::builder(limits(2))
        .ipv6_prefix(200)
        .when_full(WhenFull::ReplaceOldest)
        .record_interval(Duration::ZERO)
        .build();
    assert_eq!(queue.limits().per_source, 2);
    assert_eq!(queue.ipv6_prefix(), 128);
    assert_eq!(queue.when_full(), WhenFull::ReplaceOldest);
    assert_eq!(queue.record_interval(), Duration::ZERO);

    let mut settings = WaitingSettings::default();
    settings.limits = limits(5);
    settings.ipv6_prefix = 56;
    let queue = WaitingQueue::builder(limits(1)).settings(settings).build();
    assert_eq!(queue.settings(), settings);
    assert_eq!(WaitingQueue::new(limits(4)).limits().per_source, 4);
}

#[test]
fn every_desk_setter_reaches_the_desk() {
    let mut options = PairingOptions::default();
    options.pin_attempts = 4;
    let mut desk_limits = DeskLimits::default();
    desk_limits.pending = 3;
    let desk = PairingDesk::builder(random())
        .options(options.clone())
        .limits(desk_limits)
        .clock(Clock::from_fn(|| UNIX_EPOCH + Duration::from_secs(7)))
        .build()
        .unwrap();
    assert_eq!(desk.options().pin_attempts, 4);
    assert_eq!(desk.limits().pending, 3);
    assert_eq!(desk.settings().options, options);
    assert_eq!(
        desk.show_pin().unwrap().expires,
        UNIX_EPOCH + Duration::from_secs(7) + options.pin_ttl
    );
    assert_eq!(desk.non_defaults().len(), 2);

    let mut settings = PairingDeskSettings::default();
    settings.limits.pending = 11;
    let desk = PairingDesk::builder(random())
        .limits(desk_limits)
        .settings(settings)
        .build()
        .unwrap();
    assert_eq!(desk.limits().pending, 11);

    let mut meaningless = PairingOptions::default();
    meaningless.pin_attempts = 0;
    assert!(
        PairingDesk::builder(random())
            .options(meaningless)
            .build()
            .is_err()
    );
}

#[test]
fn a_store_takes_new_waiting_settings_with_an_empty_queue() {
    let directory = tempfile::tempdir().unwrap();
    let built = TrustStore::builder(directory.path())
        .limits(limits(3))
        .ipv6_prefix(48)
        .rotation(rotation())
        .build()
        .unwrap();
    let mut settings = built.settings().waiting;
    settings.limits = limits(5);
    settings.ipv6_prefix = 56;
    let replaced = built.waiting_queue(settings);
    assert_eq!(replaced.settings().waiting, settings);
    assert_eq!(replaced.settings().rotation, rotation());
    assert!(replaced.waiting().unwrap().is_empty());
}
