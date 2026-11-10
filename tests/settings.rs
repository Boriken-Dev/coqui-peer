//! The settings types as `Describe` values: read from TOML and JSON through a `Partial`, with the
//! defaults an absent key means, and the non-default settings they report.

use std::time::Duration;

use coqui_builder::describe::assert_round_trip;
use coqui_builder::{Describe, KeyPath, Leaf, NonDefault, Partial, differences, non_defaults};
use coqui_peer::pair::{CodeAlphabet, DeskLimits, PairingDeskSettings, PairingOptions};
use coqui_peer::{
    Digest, RotationOptions, TrustStoreSettings, WaitingLimits, WaitingSettings, WhenFull,
};

fn from_toml<T: Describe>(text: &str) -> Result<T, String>
where
    Partial<T>: for<'de> serde::Deserialize<'de>,
{
    toml::from_str::<Partial<T>>(text)
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|error| error.to_string())
}

/// The settings of a report as `(key, value, default)` texts.
fn lines(found: &[NonDefault]) -> Vec<(String, String, String)> {
    found
        .iter()
        .map(|found| {
            (
                found.setting.clone(),
                found.value.to_string(),
                found.default.to_string(),
            )
        })
        .collect()
}

fn line(setting: &str, value: &str, default: &str) -> (String, String, String) {
    (setting.to_owned(), value.to_owned(), default.to_owned())
}

#[test]
fn limits_read_from_toml_with_absent_keys_at_their_defaults() {
    let limits: WaitingLimits = from_toml("per_source = 4\nrerecord = 30\n").unwrap();
    assert_eq!(limits, {
        let mut value = WaitingLimits::default();
        value.per_source = 4;
        value.total = WaitingLimits::default().total;
        value.rerecord = Duration::from_secs(30);
        value
    });
    assert_eq!(
        from_toml::<WaitingLimits>("").unwrap(),
        WaitingLimits::default()
    );
}

#[test]
fn limits_read_from_json_and_a_duration_reads_with_its_unit() {
    let limits = serde_json::from_str::<Partial<WaitingLimits>>(
        r#"{"per_source": 3, "total": 50, "rerecord": "1500ms"}"#,
    )
    .unwrap()
    .build()
    .unwrap();
    assert_eq!(limits.per_source, 3);
    assert_eq!(limits.total, 50);
    assert_eq!(limits.rerecord, Duration::from_millis(1500));
}

#[test]
fn limits_refuse_an_unknown_key_and_a_value_of_the_wrong_kind() {
    assert!(from_toml::<WaitingLimits>("per_sourse = 1").is_err());
    assert!(from_toml::<WaitingLimits>("total = \"many\"").is_err());
}

#[test]
fn every_limit_has_a_default_the_description_states() {
    let description = WaitingLimits::description();
    for key in ["per_source", "total", "rerecord"] {
        let path: KeyPath = key.parse().unwrap();
        assert!(description.default_at(path.segments()).is_some(), "{key}");
    }
}

#[test]
fn a_digest_is_its_lowercase_name() {
    let all = [Digest::Sha256, Digest::Sha384, Digest::Sha512, Digest::Sha1];
    assert_round_trip(&all);
    for digest in all {
        assert_eq!(digest.to_text(), digest.name());
    }
    assert_eq!(Digest::from_text("sha384").unwrap(), Digest::Sha384);
    assert!(Digest::from_text("md5").is_err());
    assert!(Digest::from_text("SHA384").is_err());
}

#[test]
fn a_when_full_is_its_kebab_case_name() {
    assert_round_trip(&[WhenFull::Refuse, WhenFull::ReplaceOldest]);
    assert_eq!(WhenFull::ReplaceOldest.to_text(), "replace-oldest");
    assert!(WhenFull::from_text("sometimes").is_err());
}

#[test]
fn the_defaults_report_nothing_and_each_changed_key_reports_itself() {
    assert!(non_defaults(&WaitingLimits::default()).is_empty());
    let limits = {
        let mut value = WaitingLimits::default();
        value.per_source = 4;
        value.total = 2_000;
        value.rerecord = Duration::from_secs(5);
        value
    };
    assert_eq!(
        lines(&non_defaults(&limits)),
        [
            line("per_source", "usize(4)", "usize(16)"),
            line("rerecord", "Duration(5s)", "Duration(60s)"),
            line("total", "usize(2000)", "usize(1000)"),
        ]
    );
}

#[test]
fn trust_store_settings_read_nested_keys_over_the_defaults() {
    let text = "[waiting]\nipv6_prefix = 48\nwhen_full = \"replace-oldest\"\n\n[waiting.limits]\nper_source = 4\n\n[rotation]\nretire_after = 3600\n";
    let settings: TrustStoreSettings = from_toml(text).unwrap();
    assert_eq!(settings.waiting.ipv6_prefix, 48);
    assert_eq!(settings.waiting.when_full, WhenFull::ReplaceOldest);
    assert_eq!(settings.waiting.limits.per_source, 4);
    assert_eq!(
        settings.waiting.limits.total,
        WaitingLimits::default().total
    );
    assert_eq!(settings.rotation.retire_after, Duration::from_secs(3600));
    assert!(!settings.rotation.require_approval);
    assert_eq!(
        from_toml::<TrustStoreSettings>("").unwrap(),
        TrustStoreSettings::default()
    );
}

#[test]
fn a_directory_is_not_a_key() {
    assert!(from_toml::<TrustStoreSettings>("state_dir = \"/var/lib/app\"").is_err());
}

#[test]
fn desk_and_queue_settings_read_their_groups() {
    let desk: PairingDeskSettings = from_toml(
        "[options]\npin_attempts = 3\ndevice = false\n[limits]\napprover_window = \"5s\"\n[options.pin_alphabet]\nchars = \"01\"\nlen = 2\n",
    )
    .unwrap();
    assert_eq!(desk.options.pin_attempts, 3);
    assert!(!desk.options.device);
    assert_eq!(desk.options.pin_alphabet, CodeAlphabet::new("01", 2));
    assert_eq!(desk.limits.approver_window, Duration::from_secs(5));
    assert_eq!(desk.limits.pending, DeskLimits::default().pending);
    let queue: WaitingSettings =
        from_toml("ipv6_prefix = 128\nwhen_full = \"replace-oldest\"").unwrap();
    assert_eq!(queue.ipv6_prefix, 128);
    assert_eq!(queue.when_full, WhenFull::ReplaceOldest);
}

#[test]
fn a_half_given_alphabet_keeps_the_other_key_of_the_default() {
    let desk: PairingDeskSettings = from_toml(
        "[options.pin_alphabet]
len = 4",
    )
    .unwrap();
    assert_eq!(
        desk.options.pin_alphabet,
        CodeAlphabet::new("0123456789", 4)
    );
    let desk: PairingDeskSettings = from_toml(
        "[options.pin_alphabet]
chars = \"01\"",
    )
    .unwrap();
    assert_eq!(desk.options.pin_alphabet, CodeAlphabet::new("01", 6));
    assert_eq!(
        from_toml::<PairingDeskSettings>(
            "[options]
pin_attempts = 2"
        )
        .unwrap()
        .options
        .pin_alphabet,
        CodeAlphabet::pin()
    );
}

#[test]
fn the_ttls_read_never_as_no_bound() {
    let options: PairingOptions = from_toml("pin_ttl = \"never\"\ndevice_ttl = \"90s\"").unwrap();
    assert_eq!(options.pin_ttl, None);
    assert_eq!(options.device_ttl, Some(Duration::from_secs(90)));
    let absent: PairingOptions = from_toml("").unwrap();
    assert_eq!(absent.pin_ttl, Some(Duration::from_secs(600)));
    assert_eq!(absent.device_ttl, Some(Duration::from_secs(600)));
    assert_eq!(
        lines(&non_defaults(&options)),
        [
            line("device_ttl", "Duration(90s)", "Duration(600s)"),
            line("pin_ttl", "Duration(never)", "Duration(600s)"),
        ]
    );
}

#[test]
fn settings_refuse_unknown_keys_at_every_level() {
    assert!(from_toml::<TrustStoreSettings>("waitting = {}").is_err());
    assert!(from_toml::<TrustStoreSettings>("[waiting.limits]\nper_sourse = 1").is_err());
    assert!(from_toml::<PairingDeskSettings>("[options]\nattempts = 1").is_err());
    assert!(
        from_toml::<PairingDeskSettings>(
            "[options.pin_alphabet]\nchars = \"01\"\nlen = 2\nextra = 1"
        )
        .is_err()
    );
    assert!(from_toml::<WaitingSettings>("when_full = \"sometimes\"").is_err());
}

#[test]
fn the_defaults_report_nothing_and_each_changed_setting_is_named_by_its_key_path() {
    assert!(TrustStoreSettings::default().non_defaults().is_empty());
    assert!(PairingDeskSettings::default().non_defaults().is_empty());
    assert!(WaitingSettings::default().non_defaults().is_empty());
    assert!(PairingOptions::default().non_defaults().is_empty());
    assert!(DeskLimits::default().non_defaults().is_empty());

    let mut store = TrustStoreSettings::default();
    store.waiting.limits.per_source = 4;
    store.waiting.ipv6_prefix = 48;
    store.rotation = {
        let mut rotation = RotationOptions::default();
        rotation.allow_unproven = true;
        rotation
    };
    assert_eq!(
        lines(&store.non_defaults()),
        [
            line("rotation.allow_unproven", "bool(true)", "bool(false)"),
            line("waiting.ipv6_prefix", "u8(48)", "u8(64)"),
            line("waiting.limits.per_source", "usize(4)", "usize(16)"),
        ]
    );

    let mut options = PairingOptions::default();
    options.pin_attempts = 3;
    options.device = false;
    options.pin_alphabet = CodeAlphabet::new("0123456789", 4);
    assert_eq!(
        lines(&options.non_defaults()),
        [
            line("device", "bool(false)", "bool(true)"),
            line("pin_alphabet.len", "usize(4)", "usize(6)"),
            line("pin_attempts", "u32(3)", "u32(1)"),
        ]
    );
}

#[test]
fn a_report_against_a_baseline_names_what_differs_from_it() {
    let mut base = PairingOptions::default();
    base.pin_attempts = 3;
    let mut options = base.clone();
    options.pin_attempts = 5;
    let against = |value: &PairingOptions, baseline: &PairingOptions| -> Vec<NonDefault> {
        differences(&PairingOptions::description(), value, Some(baseline))
            .findings()
            .iter()
            .map(NonDefault::from)
            .collect()
    };
    assert_eq!(
        lines(&against(&options, &base)),
        [line("pin_attempts", "u32(5)", "u32(3)")]
    );
    assert!(against(&base, &base).is_empty());
}
