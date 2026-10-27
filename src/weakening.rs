//! A setting looser than its strict default, reported as data.

/// A setting looser than its strict value, as plain data for the caller to show or log.
///
/// Every crate of the family reports its weakened settings this way: `pair`'s options and
/// limits here, a `coqui-peer-tls` `Policy` there. A setting that is weaker than strict is never
/// refused for it; it is listed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Weakening {
    /// The setting's name, as its owner spells it (`pin_attempts`, `tls_versions`).
    pub setting: String,
    /// Its value, as text.
    pub value: String,
    /// The strict value it is looser than (the default), as text.
    pub strict: String,
}

impl Weakening {
    /// A weakening of `setting`, now `value`, against `strict`.
    pub fn new(
        setting: impl Into<String>,
        value: impl Into<String>,
        strict: impl Into<String>,
    ) -> Self {
        Self {
            setting: setting.into(),
            value: value.into(),
            strict: strict.into(),
        }
    }
}
