use alloc::borrow::Cow;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use url::Url;

/// A unique integer ID for a [`Login`]. This is not used by Tailscale node software, but is used
/// in the control plane.
pub type LoginId = i64;

/// A unique integer ID for a [`User`].
pub type UserId = i64;

/// Represents a [`User`] from a specific identity provider (IdP), not associated with any
/// particular Tailnet.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Login<'a> {
    /// The unique integer ID of this login. Unused on the Tailscale node-side, but used by the
    /// control plane.
    #[serde(rename = "ID")]
    pub id: LoginId,
    /// A string representation of the IdP itself, e.g. "google", "github", "okta_foo", etc.
    #[serde(borrow)]
    pub provider: &'a str,
    /// An email address or "email-ish" string (e.g. "alice@github") associated with this Tailscale
    /// user, according to the IdP.
    #[serde(borrow)]
    pub login_name: Cow<'a, str>,
    /// If populated, the display name of this Tailscale user, according to the IdP. Can be
    /// overridden by a value in the [`User::display_name`] field.
    #[serde(borrow, default)]
    pub display_name: Option<Cow<'a, str>>,
    /// If populated, a URL to a profile picture representing this Tailscale user, according to the
    /// IdP. Can be overridden by a value in the [`User::profile_pic_url`] field.
    #[serde(
        rename = "ProfilePicURL",
        deserialize_with = "crate::util::deserialize_string_option",
        default
    )]
    pub profile_pic_url: Option<Url>,
}

/// A Tailscale user.
///
/// A [`User`] can have multiple [`Login`]s associated with it (e.g. gmail and github oauth),
/// although as of 2019, none of the UIs support this.
///
/// Some fields are inherited from the [`Login`]s and can be overridden, such as
/// [`User::display_name`] and [`User::profile_pic_url`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct User<'a> {
    /// The unique integer ID of this Tailscale user.
    #[serde(rename = "ID")]
    pub id: UserId,
    /// If populated, the display name of this Tailscale user. Overrides the value in any IdP-
    /// provided [`Login::display_name`] field.
    #[serde(borrow, default)]
    pub display_name: Option<Cow<'a, str>>,
    /// If populated, a URL to a profile picture representing this Tailscale user. Overrides the
    /// IdP-provided value in any [`Login::profile_pic_url`] field.
    #[serde(
        rename = "ProfilePicURL",
        deserialize_with = "crate::util::deserialize_string_option",
        default
    )]
    pub profile_pic_url: Option<Url>,
    /// The date and time that this Tailscale user was created, in the UTC timezone.
    #[serde(default)]
    pub created: Option<DateTime<Utc>>,
}

/// Display-friendly data for a [`User`]. Includes the [`Login::login_name`] for display purposes.
/// but *not* the [`Login::provider`]. Also includes derived data from one of the [`Login`]s
/// associated with a [`User`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserProfile<'a> {
    /// The unique integer ID of this Tailscale user this [`UserProfile`] is associated with.
    #[serde(rename = "ID")]
    pub id: UserId,
    /// An email address or "email-ish" string (e.g. "alice@github") associated with this Tailscale
    /// user's [`UserProfile`], according to the IdP. For display purposes only.
    #[serde(borrow, default)]
    pub login_name: Cow<'a, str>,
    /// If populated, the display name of this Tailscale user (e.g. "Alice Smith"), according to
    /// the IdP.
    #[serde(borrow, default)]
    pub display_name: Option<Cow<'a, str>>,
    /// If populated, a URL to a profile picture representing this Tailscale user.
    #[serde(
        rename = "ProfilePicURL",
        deserialize_with = "crate::util::deserialize_string_option",
        default
    )]
    pub profile_pic_url: Option<Url>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Login::login_name` and `Login::display_name` are IdP-authored human text typed
    /// `Cow<'a, str>` / `Option<Cow<'a, str>>` so they tolerate JSON escapes. Go's `json.Marshal`
    /// HTML-escapes `&` → `&` by default, so a display name like `Tom & Jerry` arrives on the
    /// wire as `Tom & Jerry`. A bare `&'a str` cannot zero-copy-borrow a string serde must
    /// unescape and fails the WHOLE `Login` decode (`invalid type: string "...", expected a borrowed
    /// string`) — which silently drops the enclosing struct (the user, the netmap). With `Cow`,
    /// serde owns the unescaped value and the decode succeeds.
    #[test]
    fn login_with_go_html_escaped_display_name_decodes() {
        // Exactly what Go emits for `Tom & Jerry` (SetEscapeHTML(true) is the Marshal default).
        const TEST: &str = r#"{ "ID": 1, "Provider": "google", "LoginName": "a@b.com", "DisplayName": "Tom & Jerry" }"#;
        let login = serde_json::from_str::<Login>(TEST)
            .expect("Login with a Go-HTML-escaped DisplayName must decode");
        assert_eq!(login.login_name, "a@b.com");
        assert_eq!(login.display_name.as_deref(), Some("Tom & Jerry"));
    }

    /// The other escape forms (`\n`, `\"`, `\\`) on both the bare `login_name` and the
    /// `Option<Cow>` `display_name` decode and unescape too.
    #[test]
    fn login_with_control_escapes_decodes() {
        const TEST: &str = r#"{
            "ID": 1,
            "Provider": "google",
            "LoginName": "a\nb@\"c\\d.com",
            "DisplayName": "line1\nline2\"q\\z"
        }"#;
        let login = serde_json::from_str::<Login>(TEST)
            .expect("Login with control-character escapes must decode");
        assert_eq!(login.login_name, "a\nb@\"c\\d.com");
        assert_eq!(login.display_name.as_deref(), Some("line1\nline2\"q\\z"));
    }

    /// `UserProfile::login_name` (bare `Cow`) and `UserProfile::display_name` (`Option<Cow>`) — the
    /// display-facing identity joined onto a peer — also decode with a Go-HTML-escaped `&` and the
    /// control escapes. A failure here would drop the owning user's profile.
    #[test]
    fn user_profile_with_escaped_fields_decodes() {
        const TEST: &str = r#"{ "ID": 7, "LoginName": "a@b.com", "DisplayName": "Tom & Jerry" }"#;
        let profile = serde_json::from_str::<UserProfile>(TEST)
            .expect("UserProfile with an escaped DisplayName must decode");
        assert_eq!(profile.login_name, "a@b.com");
        assert_eq!(profile.display_name.as_deref(), Some("Tom & Jerry"));

        const TEST_CTRL: &str =
            r#"{ "ID": 7, "LoginName": "a\nb@c.com", "DisplayName": "x\"y\\z" }"#;
        let profile = serde_json::from_str::<UserProfile>(TEST_CTRL)
            .expect("UserProfile with control escapes must decode");
        assert_eq!(profile.login_name, "a\nb@c.com");
        assert_eq!(profile.display_name.as_deref(), Some("x\"y\\z"));
    }

    /// The no-escape fast path still decodes (and borrows zero-copy, though that is not observable
    /// from outside): plain values pass through unchanged.
    #[test]
    fn login_without_escape_decodes() {
        const TEST: &str = r#"{ "ID": 1, "Provider": "google", "LoginName": "alice@example.com", "DisplayName": "Alice Smith" }"#;
        let login =
            serde_json::from_str::<Login>(TEST).expect("Login with plain fields must decode");
        assert_eq!(login.login_name, "alice@example.com");
        assert_eq!(login.display_name.as_deref(), Some("Alice Smith"));
    }
}
