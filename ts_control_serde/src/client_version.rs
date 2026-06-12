use alloc::borrow::Cow;

use serde::Deserialize;
use url::Url;

/// Information about the latest Tailscale version that's available for this node's platform and
/// packaging type, including whether this node is already running it.
///
/// This type does not include a URL to download the latest version, as that varies by platform.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ClientVersion<'a> {
    /// If `true`, this Tailscale node is running the latest available version for this platform
    /// and package type.
    pub running_latest: bool,
    /// If populated, contains the latest semantic version available for download for this
    /// Tailscale node's platform and package type. This will be `None` only if
    /// [`ClientVersion::running_latest`] is `true`.
    #[serde(borrow)]
    pub latest_version: &'a str,
    /// Indicates this Tailscale node is missing an important security update. The update may be in
    /// [`ClientVersion::latest_version`] or any earlier version.
    ///
    /// This field should always be `false` if [`ClientVersion::running_latest`] is `true`.
    pub urgent_security_update: bool,
    /// Whether this Tailscale node should raise an OS-specific notification about a new version
    /// being available. The node must only raise a notification once for any given version,
    /// regardless of how many times it receives a [`ClientVersion`] with this field set to `true`
    /// for the same version. In other words, it's the node's job to track if it's already raised a
    /// notification for a specific version.
    ///
    /// This field should always be `false` if [`ClientVersion::running_latest`] is `true`.
    pub notify: bool,
    /// A [`Url`] to open in the platform's web browser when the user clicks on the notification.
    /// Only populated when [`ClientVersion::notify`] is `true`.
    pub notify_url: Option<Url>,
    /// The text to show in the notification. Only populated when [`ClientVersion::notify`] is
    /// `true`.
    #[serde(borrow)]
    pub notify_text: Option<Cow<'a, str>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ClientVersion::notify_text` is the human-facing notification body typed `Option<Cow<'a,
    /// str>>` so it tolerates JSON escapes. Go's `json.Marshal` HTML-escapes `&` → `&` by
    /// default, and the prose can carry a newline/quote; a bare `Option<&'a str>` cannot zero-copy-
    /// borrow a string serde must unescape and fails the WHOLE `ClientVersion` decode (`invalid
    /// type: string "...", expected a borrowed string`), masking the upgrade notice. With `Cow`,
    /// serde owns the unescaped value and the decode succeeds.
    #[test]
    fn notify_text_with_escape_sequence_decodes() {
        const TEST: &str = r#"{
            "RunningLatest": false,
            "LatestVersion": "1.84.0",
            "Notify": true,
            "NotifyText": "Update now:\n\"security & stability\" fixes\\n"
        }"#;
        let cv = serde_json::from_str::<ClientVersion>(TEST)
            .expect("ClientVersion with an escaped NotifyText must decode");
        assert_eq!(
            cv.notify_text.as_deref(),
            Some("Update now:\n\"security & stability\" fixes\\n")
        );
        assert!(cv.notify);
    }

    /// The no-escape fast path still decodes (and borrows zero-copy, though that is not observable
    /// from outside): a plain `NotifyText` yields its value unchanged.
    #[test]
    fn notify_text_without_escape_decodes() {
        const TEST: &str = r#"{
            "RunningLatest": false,
            "LatestVersion": "1.84.0",
            "Notify": true,
            "NotifyText": "A new version is available"
        }"#;
        let cv = serde_json::from_str::<ClientVersion>(TEST)
            .expect("ClientVersion with a plain NotifyText must decode");
        assert_eq!(
            cv.notify_text.as_deref(),
            Some("A new version is available")
        );
    }
}
