//! A setting that differs from its default, reported as data.

/// A setting whose value differs from its default, as plain data for the caller to show or log.
///
/// Every crate of the family reports its non-default settings this way: `pair`'s options and
/// limits here, a `coqui-peer-tls` `Policy` there. A non-default setting is never refused for
/// it; it is listed, and the application that knows the use case decides what it means.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonDefault {
    /// The setting's name, as its owner spells it (`pin_attempts`, `tls_versions`).
    pub setting: String,
    /// Its value, as text.
    pub value: String,
    /// The default value, as text.
    pub default: String,
}

impl NonDefault {
    /// A non-default `setting`, now `value`, against `default`.
    pub fn new(
        setting: impl Into<String>,
        value: impl Into<String>,
        default: impl Into<String>,
    ) -> Self {
        Self {
            setting: setting.into(),
            value: value.into(),
            default: default.into(),
        }
    }
}

/// The old name of [`NonDefault`], whose `strict` field is now `default`.
#[deprecated(
    since = "0.0.0",
    note = "renamed to `NonDefault`; its `strict` field is now `default`"
)]
pub type Weakening = NonDefault;
