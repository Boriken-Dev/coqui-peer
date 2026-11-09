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

#[cfg(feature = "guatiao")]
impl NonDefault {
    /// The non-default setting a guatiao [`Difference`](guatiao::schema::Difference) reports:
    /// `setting` is its [`key`](guatiao::schema::Difference::key) (`waiting.per_source`), and
    /// `value` and `default` are rendered by one rule.
    ///
    /// A text value is its text, any other value is its compact JSON (`true`, `16`, `[60,0]`,
    /// `["1.2","1.3"]`), and a side the difference has no value for is `unset`. A secret arrives as
    /// the placeholder the difference was made with, and is shown as that.
    pub fn from_difference(difference: &guatiao::schema::Difference) -> Self {
        Self::new(
            difference.key(),
            render(difference.value.as_ref()),
            render(difference.baseline.as_ref()),
        )
    }
}

#[cfg(feature = "guatiao")]
fn render(value: Option<&guatiao::Value>) -> String {
    use guatiao::FromValue;
    let Some(value) = value else {
        return "unset".to_owned();
    };
    String::from_value(value).unwrap_or_else(|_| {
        guatiao_serde::text::json::to_string(value, guatiao_serde::Presentation::new())
            .unwrap_or_else(|_| "unrepresentable".to_owned())
    })
}
