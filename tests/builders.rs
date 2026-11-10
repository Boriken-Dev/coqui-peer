//! Each builder setter reaches what it builds, a `Partial` fills the whole, the last write wins,
//! and the store takes new waiting settings.

use std::time::{Duration, UNIX_EPOCH};

use coqui_builder::Partial;
use coqui_builder::builder::BuildError;
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
    let store = TrustStore::builder()
        .state_dir(directory.path())
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
fn a_store_takes_a_partial_whole_and_the_last_write_wins() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = TrustStoreSettings::default();
    settings.waiting.limits.total = 9;
    settings.rotation.require_approval = true;
    let store = TrustStore::builder()
        .state_dir(directory.path())
        .ipv6_prefix(32)
        .fill(Partial::from(settings))
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
fn a_store_reads_its_settings_from_text_and_a_setter_after_it_wins() {
    let directory = tempfile::tempdir().unwrap();
    let partial: Partial<TrustStoreSettings> =
        toml::from_str("[waiting]\nipv6_prefix = 48\n[waiting.limits]\ntotal = 9\n").unwrap();
    let store = TrustStore::builder()
        .state_dir(directory.path())
        .fill(partial)
        .ipv6_prefix(56)
        .build()
        .unwrap();
    let built = store.settings();
    assert_eq!(built.waiting.ipv6_prefix, 56);
    assert_eq!(built.waiting.limits.total, 9);
    assert_eq!(built.waiting.limits.per_source, 16);
}

#[test]
fn the_directory_is_an_input_that_a_build_names_when_it_is_missing() {
    let missing = TrustStore::builder().build().unwrap_err();
    let BuildError::Missing(missing) = missing else {
        panic!("a store with no directory is missing an input");
    };
    assert_eq!(missing.inputs(), ["state_dir"]);
    assert!(missing.keys().is_empty());
}

#[test]
fn a_directory_that_cannot_be_made_is_the_stores_own_error() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, b"").unwrap();
    let error = TrustStore::builder().state_dir(&file).build().unwrap_err();
    assert!(matches!(
        error,
        BuildError::Failed(coqui_peer::Error::Io(_))
    ));
}

#[test]
fn a_builder_and_its_store_report_the_same_non_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let builder = TrustStore::builder()
        .state_dir(directory.path())
        .limits(limits(3))
        .rotation(rotation());
    let from_builder = builder.non_defaults();
    let store = builder.build().unwrap();
    assert_eq!(from_builder, store.non_defaults());
    let keys: Vec<_> = from_builder.iter().map(|found| &*found.setting).collect();
    assert_eq!(keys, ["rotation.retire_after", "waiting.limits.per_source"]);
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
    let queue = WaitingQueue::builder()
        .limits(limits(2))
        .ipv6_prefix(200)
        .when_full(WhenFull::ReplaceOldest)
        .record_interval(Duration::ZERO)
        .build()
        .unwrap();
    assert_eq!(queue.limits().per_source, 2);
    assert_eq!(queue.ipv6_prefix(), 128);
    assert_eq!(queue.when_full(), WhenFull::ReplaceOldest);
    assert_eq!(queue.record_interval(), Duration::ZERO);

    let mut settings = WaitingSettings::default();
    settings.limits = limits(5);
    settings.ipv6_prefix = 56;
    let queue = WaitingQueue::builder()
        .limits(limits(1))
        .fill(Partial::from(settings))
        .build()
        .unwrap();
    assert_eq!(queue.settings(), settings);
    assert_eq!(WaitingQueue::new(limits(4)).limits().per_source, 4);
    assert_eq!(queue.non_defaults().len(), 2);
}

#[test]
fn every_desk_setter_reaches_the_desk() {
    let mut options = PairingOptions::default();
    options.pin_attempts = 4;
    let mut desk_limits = DeskLimits::default();
    desk_limits.pending = 3;
    let desk = PairingDesk::builder()
        .random(random())
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
        UNIX_EPOCH + Duration::from_secs(7) + options.pin_ttl.unwrap()
    );
    assert_eq!(desk.non_defaults().len(), 2);

    let mut settings = PairingDeskSettings::default();
    settings.limits.pending = 11;
    let desk = PairingDesk::builder()
        .random(random())
        .limits(desk_limits)
        .fill(Partial::from(settings))
        .build()
        .unwrap();
    assert_eq!(desk.limits().pending, 11);

    let mut meaningless = PairingOptions::default();
    meaningless.pin_attempts = 0;
    assert!(
        PairingDesk::builder()
            .random(random())
            .options(meaningless)
            .build()
            .is_err()
    );
}

#[test]
fn a_desk_needs_its_random_source() {
    let BuildError::Missing(missing) = PairingDesk::builder().build().unwrap_err() else {
        panic!("a desk with no random source is missing an input");
    };
    assert_eq!(missing.inputs(), ["random"]);
}

#[test]
fn a_ttl_reads_never_from_text_as_none() {
    let partial: Partial<PairingDeskSettings> =
        toml::from_str("[options]\npin_ttl = \"never\"\ndevice_ttl = \"90s\"\n").unwrap();
    let desk = PairingDesk::builder()
        .random(random())
        .fill(partial)
        .build()
        .unwrap();
    assert_eq!(desk.options().pin_ttl, None);
    assert_eq!(desk.options().device_ttl, Some(Duration::from_secs(90)));
}

#[test]
fn a_store_takes_new_waiting_settings_with_an_empty_queue() {
    let directory = tempfile::tempdir().unwrap();
    let built = TrustStore::builder()
        .state_dir(directory.path())
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
