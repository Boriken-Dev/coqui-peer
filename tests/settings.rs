//! The settings types as guatiao values: read from TOML and JSON, round-tripped, with the
//! defaults an absent key means, and the non-default settings they report.

use std::time::Duration;

use coqui_peer::pair::{DeskLimits, PairingDeskSettings, PairingOptions};
use coqui_peer::{
    Digest, NonDefault, RotationOptions, TrustStoreSettings, WaitingLimits, WaitingSettings,
    WhenFull,
};
use guatiao::{FromValue, Schema, ToValue};
use guatiao_serde::Presentation;
use guatiao_serde::text::{json, toml};

fn plain() -> Presentation {
    Presentation::new()
}

#[test]
fn limits_read_from_toml_with_absent_keys_at_their_defaults() {
    let limits: WaitingLimits =
        toml::from_str_as("per_source = 4\nrerecord = 30\n", plain()).unwrap();
    assert_eq!(limits, {
        let mut value = WaitingLimits::default();
        value.per_source = 4;
        value.total = WaitingLimits::default().total;
        value.rerecord = Duration::from_secs(30);
        value
    });
    assert_eq!(
        toml::from_str_as::<WaitingLimits>("", plain()).unwrap(),
        WaitingLimits::default()
    );
}

#[test]
fn limits_round_trip_through_toml_and_json() {
    let limits = {
        let mut value = WaitingLimits::default();
        value.per_source = 3;
        value.total = 50;
        value.rerecord = Duration::from_millis(1500);
        value
    };
    let text = toml::to_string_of(&limits, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<WaitingLimits>(&text, plain()).unwrap(),
        limits
    );
    let text = json::to_string_pretty_of(&limits, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<WaitingLimits>(&text, plain()).unwrap(),
        limits
    );
    assert_eq!(
        WaitingLimits::from_value(&limits.to_value().unwrap()).unwrap(),
        limits
    );
}

#[test]
fn limits_refuse_an_unknown_key() {
    assert!(toml::from_str_as::<WaitingLimits>("per_sourse = 1", plain()).is_err());
    assert!(toml::from_str_as::<WaitingLimits>("total = \"many\"", plain()).is_err());
}

#[test]
fn limits_schema_defaults_are_the_real_defaults() {
    let schema = WaitingLimits::schema().unwrap();
    let schema = guatiao::schema::SchemaRef::new(&schema).unwrap();
    for key in ["per_source", "total", "rerecord"] {
        let field = schema.find(key).unwrap_or_else(|| panic!("{key}"));
        assert!(field.default().is_some(), "{key} has a default");
    }
}

#[test]
fn a_digest_is_its_lowercase_name() {
    for digest in [Digest::Sha256, Digest::Sha384, Digest::Sha512, Digest::Sha1] {
        let value = digest.to_value().unwrap();
        assert_eq!(String::from_value(&value).unwrap(), digest.name());
        assert_eq!(Digest::from_value(&value).unwrap(), digest);
    }
    let value = "sha384".to_value().unwrap();
    assert_eq!(Digest::from_value(&value).unwrap(), Digest::Sha384);
    assert!(Digest::from_value(&"md5".to_value().unwrap()).is_err());
}

fn reported(limits: &WaitingLimits) -> Vec<coqui_peer::NonDefault> {
    let schema = WaitingLimits::schema().unwrap();
    let schema = guatiao::schema::SchemaRef::new(&schema).unwrap();
    guatiao::schema::differences(schema, &limits.to_value().unwrap(), None, "***")
        .unwrap()
        .iter()
        .map(coqui_peer::NonDefault::from_difference)
        .collect()
}

#[test]
fn the_defaults_report_nothing_and_each_changed_key_reports_itself() {
    assert!(reported(&WaitingLimits::default()).is_empty());
    let limits = {
        let mut value = WaitingLimits::default();
        value.per_source = 4;
        value.total = 2_000;
        value.rerecord = Duration::from_secs(5);
        value
    };
    assert_eq!(
        reported(&limits),
        [
            coqui_peer::NonDefault::new("per_source", "4", "16"),
            coqui_peer::NonDefault::new("rerecord", "[5,0]", "[60,0]"),
            coqui_peer::NonDefault::new("total", "2000", "1000"),
        ]
    );
}

#[test]
fn a_text_value_is_its_text_and_a_missing_side_is_unset() {
    let value = guatiao::Value::from(guatiao::Text::new("sha384"));
    let difference = guatiao::schema::Difference {
        path: vec!["pin".to_owned(), "digest".to_owned()],
        value: Some(value),
        baseline: None,
    };
    assert_eq!(
        coqui_peer::NonDefault::from_difference(&difference),
        coqui_peer::NonDefault::new("pin.digest", "sha384", "unset")
    );
}

#[test]
fn trust_store_settings_read_nested_keys_over_the_defaults() {
    let text = "[waiting]\nipv6_prefix = 48\nwhen_full = \"replace-oldest\"\n\n[waiting.limits]\nper_source = 4\n\n[rotation]\nretire_after = 3600\n";
    let settings: TrustStoreSettings = toml::from_str_as(text, plain()).unwrap();
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
        toml::from_str_as::<TrustStoreSettings>("", plain()).unwrap(),
        TrustStoreSettings::default()
    );
}

#[test]
fn settings_round_trip_through_toml_and_json() {
    let mut store = TrustStoreSettings::default();
    store.waiting.record_interval = Duration::from_millis(250);
    store.waiting.limits.total = 7;
    store.rotation.allow_unproven = true;
    let mut desk = PairingDeskSettings::default();
    desk.options.pin_attempts = 3;
    desk.options.device = false;
    desk.limits.approver_window = Duration::from_secs(5);
    let mut queue = WaitingSettings::default();
    queue.ipv6_prefix = 128;
    queue.when_full = WhenFull::ReplaceOldest;

    let text = toml::to_string_of(&store, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<TrustStoreSettings>(&text, plain()).unwrap(),
        store
    );
    let text = json::to_string_pretty_of(&store, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<TrustStoreSettings>(&text, plain()).unwrap(),
        store
    );
    let text = toml::to_string_of(&desk, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<PairingDeskSettings>(&text, plain()).unwrap(),
        desk
    );
    let text = json::to_string_pretty_of(&queue, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<WaitingSettings>(&text, plain()).unwrap(),
        queue
    );
}

#[test]
fn settings_refuse_unknown_keys_at_every_level() {
    assert!(toml::from_str_as::<TrustStoreSettings>("waitting = {}", plain()).is_err());
    assert!(
        toml::from_str_as::<TrustStoreSettings>("[waiting.limits]\nper_sourse = 1", plain())
            .is_err()
    );
    assert!(toml::from_str_as::<PairingDeskSettings>("[options]\nattempts = 1", plain()).is_err());
    assert!(
        toml::from_str_as::<PairingDeskSettings>(
            "[options.pin_alphabet]\nchars = \"01\"\nlen = 2\nextra = 1",
            plain()
        )
        .is_err()
    );
    assert!(toml::from_str_as::<WaitingSettings>("when_full = \"sometimes\"", plain()).is_err());
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
        store.non_defaults(),
        [
            NonDefault::new("rotation.allow_unproven", "true", "false"),
            NonDefault::new("waiting.ipv6_prefix", "48", "64"),
            NonDefault::new("waiting.limits.per_source", "4", "16"),
        ]
    );

    let mut options = PairingOptions::default();
    options.pin_attempts = 3;
    options.device = false;
    options.pin_alphabet = coqui_peer::pair::CodeAlphabet::new("0123456789", 4);
    assert_eq!(
        options.non_defaults(),
        [
            NonDefault::new("device", "false", "true"),
            NonDefault::new("pin_alphabet.len", "4", "6"),
            NonDefault::new("pin_attempts", "3", "1"),
        ]
    );
}

#[test]
fn a_report_against_a_baseline_names_what_differs_from_it() {
    let mut base = PairingOptions::default();
    base.pin_attempts = 3;
    let mut options = base.clone();
    options.pin_attempts = 5;
    assert_eq!(
        NonDefault::of_settings_against(&options, &base),
        [NonDefault::new("pin_attempts", "5", "3")]
    );
    assert!(NonDefault::of_settings_against(&base, &base).is_empty());
}
