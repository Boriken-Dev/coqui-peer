//! `Digest` and `WaitingLimits` as guatiao values: read from TOML and JSON, round-tripped, with
//! the defaults an absent key means.
#![cfg(feature = "guatiao")]

use std::time::Duration;

use coqui_peer::{Digest, WaitingLimits};
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
    assert_eq!(
        limits,
        WaitingLimits {
            per_source: 4,
            total: WaitingLimits::default().total,
            rerecord: Duration::from_secs(30),
        }
    );
    assert_eq!(
        toml::from_str_as::<WaitingLimits>("", plain()).unwrap(),
        WaitingLimits::default()
    );
}

#[test]
fn limits_round_trip_through_toml_and_json() {
    let limits = WaitingLimits {
        per_source: 3,
        total: 50,
        rerecord: Duration::from_millis(1500),
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
    let limits = WaitingLimits {
        per_source: 4,
        total: 2_000,
        rerecord: Duration::from_secs(5),
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
