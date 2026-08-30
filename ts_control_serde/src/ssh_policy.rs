use alloc::{borrow::Cow, collections::BTreeMap, vec::Vec};
use core::net::SocketAddr;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::node::StableNodeId;

/// The policy for how incoming SSH connections should be handled, as pushed down to a Tailscale
/// node from the control plane (see [`MapResponse::ssh_policy`][crate::MapResponse::ssh_policy]).
///
/// Mirrors `tailcfg.SSHPolicy` in the Go client.
#[serde_with::apply(
    Vec => #[serde(default, deserialize_with = "crate::util::null_to_default")],
)]
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct SSHPolicy<'a> {
    /// The set of rules that apply to this node, evaluated in order. The first matching rule
    /// determines the outcome of an incoming SSH connection.
    #[serde(borrow, rename = "rules")]
    pub rules: Vec<SSHRule<'a>>,
}

/// A single rule within an [`SSHPolicy`]. Rules are evaluated in order; the first one whose
/// [`SSHRule::principals`] match the incoming connection determines its [`SSHRule::action`].
///
/// Mirrors `tailcfg.SSHRule` in the Go client.
#[serde_with::apply(
    Vec      => #[serde(default, deserialize_with = "crate::util::null_to_default")],
    BTreeMap => #[serde(default, deserialize_with = "crate::util::null_to_default")],
)]
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct SSHRule<'a> {
    /// An optional time at which this rule expires. After this time, the rule no longer matches.
    #[serde(default, rename = "ruleExpires")]
    pub rule_expires: Option<DateTime<Utc>>,

    /// The set of principals that this rule applies to. A connection matches this rule if it
    /// matches any of these principals.
    #[serde(borrow, rename = "principals")]
    pub principals: Vec<SSHPrincipal<'a>>,

    /// A map from incoming SSH usernames to the local Unix usernames they may run as. The special
    /// key `"*"` matches any incoming username (and the value is then used verbatim as the local
    /// username, unless it is itself `"="` meaning "use the incoming username as-is").
    #[serde(borrow, rename = "sshUsers")]
    pub ssh_users: BTreeMap<&'a str, &'a str>,

    /// The action to take when this rule matches. A `None` value means this rule does nothing.
    #[serde(default, borrow, rename = "action")]
    pub action: Option<SSHAction<'a>>,

    /// An optional allowlist of environment variable names that may be forwarded from the SSH
    /// client to the session.
    #[serde(borrow, rename = "acceptEnv")]
    pub accept_env: Vec<&'a str>,
}

/// A principal that an [`SSHRule`] may match against. A principal matches if any of its populated
/// fields match the incoming connection.
///
/// Mirrors `tailcfg.SSHPrincipal` in the Go client.
#[serde_with::apply(
    Vec => #[serde(default, deserialize_with = "crate::util::null_to_default")],
)]
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct SSHPrincipal<'a> {
    /// If populated, matches a specific node by its [`StableNodeId`].
    #[serde(default, borrow, rename = "node")]
    pub node: StableNodeId<'a>,

    /// If populated, matches a node by one of its Tailscale IP addresses (as a string).
    #[serde(default, borrow, rename = "nodeIP")]
    pub node_ip: &'a str,

    /// If populated, matches a node owned by a particular user login.
    #[serde(default, borrow, rename = "userLogin")]
    pub user_login: &'a str,

    /// If `true`, matches any source.
    #[serde(default, rename = "any")]
    pub any: bool,

    /// Deprecated. Does nothing. Mirrors the Go field `UnusedPubKeys` (JSON tag `pubKeys`), kept
    /// only so the field round-trips on the wire.
    #[serde(borrow, rename = "pubKeys")]
    #[deprecated = "does nothing; kept for wire compatibility"]
    pub unused_pub_keys: Vec<&'a str>,
}

/// The action to take when an [`SSHRule`] matches.
///
/// Mirrors `tailcfg.SSHAction` in the Go client.
#[serde_with::apply(
    Vec => #[serde(default, deserialize_with = "crate::util::null_to_default")],
)]
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct SSHAction<'a> {
    /// An optional message to show to the user when this action is applied.
    #[serde(default, borrow, rename = "message")]
    pub message: Cow<'a, str>,

    /// If `true`, the connection is rejected.
    #[serde(default, rename = "reject")]
    pub reject: bool,

    /// If `true`, the connection is accepted.
    #[serde(default, rename = "accept")]
    pub accept: bool,

    /// The maximum duration of the session, in **nanoseconds**. A value of `None`/`0` means no
    /// limit.
    ///
    /// Go's `tailcfg.SSHAction.SessionDuration` is a `time.Duration` tagged
    /// `json:"sessionDuration,omitempty"`, which `encoding/json` writes as an int64 nanosecond
    /// count. It briefly also carried a jsonv2 `format:nano` tag option, added to pin exactly that
    /// representation; upstream `82cfea90c` REMOVED the option, because Go 1.27's finalized
    /// `encoding/json` fails at runtime on the mere presence of a `format` tag — which broke the
    /// decode of every netmap carrying an SSH policy. The wire form did not change with it (Go 1.27
    /// sets `FormatDurationAsNano` in v1 mode), so this field did not change either; see
    /// `session_duration_is_int64_nanoseconds` below.
    #[serde(default, rename = "sessionDuration")]
    pub session_duration: Option<i64>,

    /// Whether to allow SSH agent forwarding for the session.
    #[serde(default, rename = "allowAgentForwarding")]
    pub allow_agent_forwarding: bool,

    /// If non-empty, the connection is held and the named URL is consulted to delegate the final
    /// action decision.
    #[serde(default, borrow, rename = "holdAndDelegate")]
    pub hold_and_delegate: &'a str,

    /// Whether to allow local port forwarding for the session.
    #[serde(default, rename = "allowLocalPortForwarding")]
    pub allow_local_port_forwarding: bool,

    /// Whether to allow remote port forwarding for the session.
    #[serde(default, rename = "allowRemotePortForwarding")]
    pub allow_remote_port_forwarding: bool,

    /// The list of session recorders (as `ip:port` socket addresses) that the session should be
    /// recorded to.
    #[serde(rename = "recorders")]
    pub recorders: Vec<SocketAddr>,

    /// What to do if session recording fails. A `None` value means recording failures are ignored
    /// (the session proceeds).
    #[serde(default, borrow, rename = "onRecordingFailure")]
    pub on_recording_failure: Option<SSHRecorderFailureAction<'a>>,
}

/// What to do when session recording fails for an [`SSHAction`] that has
/// [`SSHAction::recorders`] configured.
///
/// Mirrors `tailcfg.SSHRecorderFailureAction` in the Go client.
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct SSHRecorderFailureAction<'a> {
    /// If non-empty, the session is rejected with this message when recording cannot start.
    ///
    /// Go `tailcfg.SSHRecorderFailureAction.RejectSessionWithMessage` carries `json:",omitempty"`
    /// (an EMPTY name), so it marshals as the PascalCase field name — NOT lowerCamel. An earlier
    /// revision used `rejectSessionWithMessage`, which never matched control's wire key, so this
    /// field silently stayed empty.
    #[serde(default, borrow, rename = "RejectSessionWithMessage")]
    pub reject_session_with_message: Cow<'a, str>,

    /// If non-empty, an in-progress session is terminated with this message when recording fails.
    /// PascalCase on the wire (Go `json:",omitempty"`, empty name); see the field above.
    #[serde(default, borrow, rename = "TerminateSessionWithMessage")]
    pub terminate_session_with_message: Cow<'a, str>,

    /// If non-empty, a URL to notify (out of band) when recording fails.
    /// PascalCase on the wire (Go `json:",omitempty"`, empty name); see the fields above.
    #[serde(default, borrow, rename = "NotifyURL")]
    pub notify_url: Cow<'a, str>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ssh_policy_round_trip() {
        const TEST: &str = r#"{
            "rules": [
                {
                    "ruleExpires": "2026-06-05T12:00:00Z",
                    "principals": [
                        { "any": true },
                        {
                            "node": "n123456CNTRL",
                            "nodeIP": "100.64.0.1",
                            "userLogin": "alice@example.com"
                        }
                    ],
                    "sshUsers": {
                        "*": "ubuntu",
                        "root": "="
                    },
                    "action": {
                        "accept": true,
                        "sessionDuration": 900000000000,
                        "allowAgentForwarding": true,
                        "recorders": ["1.2.3.4:5678"],
                        "onRecordingFailure": {
                            "RejectSessionWithMessage": "recording required",
                            "NotifyURL": "https://example.com/notify"
                        }
                    },
                    "acceptEnv": ["LANG", "TERM"]
                }
            ]
        }"#;

        let policy = serde_json::from_str::<SSHPolicy>(TEST).unwrap();

        assert_eq!(policy.rules.len(), 1);
        let rule = &policy.rules[0];

        assert_eq!(
            rule.rule_expires,
            Some("2026-06-05T12:00:00Z".parse::<DateTime<Utc>>().unwrap())
        );

        assert_eq!(rule.principals.len(), 2);
        assert!(rule.principals[0].any);
        assert_eq!(rule.principals[1].node, StableNodeId("n123456CNTRL"));
        assert_eq!(rule.principals[1].node_ip, "100.64.0.1");
        assert_eq!(rule.principals[1].user_login, "alice@example.com");

        assert_eq!(rule.ssh_users.get("*"), Some(&"ubuntu"));
        assert_eq!(rule.ssh_users.get("root"), Some(&"="));

        assert_eq!(rule.accept_env, ["LANG", "TERM"]);

        let action = rule.action.as_ref().unwrap();
        assert!(action.accept);
        assert!(!action.reject);
        assert_eq!(action.session_duration, Some(900_000_000_000));
        assert!(action.allow_agent_forwarding);
        assert_eq!(action.recorders, ["1.2.3.4:5678".parse().unwrap()]);

        let orf = action.on_recording_failure.as_ref().unwrap();
        assert_eq!(orf.reject_session_with_message, "recording required");
        assert_eq!(orf.notify_url, "https://example.com/notify");
        assert_eq!(orf.terminate_session_with_message, "");
    }

    /// `SSHRecorderFailureAction`'s three fields are PascalCase on the wire (Go declares them with
    /// `json:",omitempty"` — an empty name — so they marshal as the Go field name). This pins that
    /// keying against a regression: a prior revision used lowerCamel keys, which never matched
    /// control's PascalCase wire form, so the sub-object silently decoded as all-empty. The fixture
    /// here uses control's real PascalCase keys; if a future change reverts to lowerCamel, these
    /// assertions fail (the fields would come back empty).
    #[test]
    fn recorder_failure_action_decodes_pascal_case_keys() {
        const WIRE: &str = r#"{
            "RejectSessionWithMessage": "reject msg",
            "TerminateSessionWithMessage": "terminate msg",
            "NotifyURL": "https://example.com/n"
        }"#;
        let orf = serde_json::from_str::<SSHRecorderFailureAction>(WIRE)
            .expect("SSHRecorderFailureAction must decode control's PascalCase keys");
        assert_eq!(orf.reject_session_with_message, "reject msg");
        assert_eq!(orf.terminate_session_with_message, "terminate msg");
        assert_eq!(orf.notify_url, "https://example.com/n");

        // The old lowerCamel keys must NOT decode (proving the fix, not just accepting both): a body
        // with the wrong-cased keys leaves every field empty.
        const WRONG: &str = r#"{
            "rejectSessionWithMessage": "x",
            "terminateSessionWithMessage": "y",
            "notifyURL": "z"
        }"#;
        let empty = serde_json::from_str::<SSHRecorderFailureAction>(WRONG)
            .expect("unknown lowerCamel keys are ignored, not an error");
        assert_eq!(empty.reject_session_with_message, "");
        assert_eq!(empty.terminate_session_with_message, "");
        assert_eq!(empty.notify_url, "");
    }

    /// `SSHAction.sessionDuration` is an int64 nanosecond count on the wire, and an absent key
    /// means "no limit". Upstream `82cfea90c` dropped the `format:nano` jsonv2 tag option from
    /// `tailcfg.SSHAction.SessionDuration` (Go 1.27's `encoding/json` rejects any `format` option
    /// outright) while keeping the encoding byte-for-byte identical, and locked that down with
    /// `TestSSHActionJSON` in `tailcfg/tailcfg_test.go`. This is the same assertion from the
    /// decoding side: the exact bytes upstream's test marshals must decode to the same duration
    /// here, so the tag change upstream is a no-op on this wire.
    #[test]
    fn session_duration_is_int64_nanoseconds() {
        // Byte-for-byte the `want` string of upstream's TestSSHActionJSON.
        const WIRE: &str = r#"{"accept":true,"sessionDuration":5000000000}"#;

        let action =
            serde_json::from_str::<SSHAction>(WIRE).expect("Go's SSHAction wire form must decode");
        assert!(action.accept);
        assert_eq!(
            action.session_duration,
            Some(5_000_000_000),
            "sessionDuration is an int64 count of NANOseconds (5s), not seconds or a string"
        );

        // `omitempty` on the Go side: a zero duration is not sent at all, and must read as "no
        // limit" rather than failing the decode.
        let unlimited = serde_json::from_str::<SSHAction>(r#"{"accept":true}"#)
            .expect("an SSHAction without sessionDuration must decode");
        assert_eq!(unlimited.session_duration, None);

        // A duration is never a string or a float on this wire; either would silently mean Go and
        // this client disagree about the representation.
        assert!(serde_json::from_str::<SSHAction>(r#"{"sessionDuration":"5s"}"#).is_err());
        assert!(serde_json::from_str::<SSHAction>(r#"{"sessionDuration":5.5}"#).is_err());
    }

    #[test]
    fn ssh_policy_empty_rules() {
        let policy = serde_json::from_str::<SSHPolicy>(r#"{}"#).unwrap();
        assert!(policy.rules.is_empty());
    }

    /// Go marshals empty `omitempty` slices/maps as `null`, so an SSH policy from such a control
    /// plane can carry `null` for `rules`, `principals`, `sshUsers`, `acceptEnv`, `recorders`, and
    /// `pubKeys` — each of which previously failed the decode and looped the map-poll stream.
    #[test]
    #[allow(deprecated)]
    fn null_collections_decode_as_empty() {
        let policy = serde_json::from_str::<SSHPolicy>(r#"{ "rules": null }"#)
            .expect("SSHPolicy with null rules must decode");
        assert!(policy.rules.is_empty());

        let rule = serde_json::from_str::<SSHRule>(
            r#"{
                "principals": null,
                "sshUsers": null,
                "acceptEnv": null,
                "action": { "accept": true, "recorders": null }
            }"#,
        )
        .expect("SSHRule with null collections must decode");
        assert!(rule.principals.is_empty());
        assert!(rule.ssh_users.is_empty());
        assert!(rule.accept_env.is_empty());
        assert!(rule.action.unwrap().recorders.is_empty());

        let principal = serde_json::from_str::<SSHPrincipal>(r#"{ "any": true, "pubKeys": null }"#)
            .expect("SSHPrincipal with null pubKeys must decode");
        assert!(principal.unused_pub_keys.is_empty());
    }

    /// `SSHAction::message` is admin-authored prose typed `Cow<'a, str>`, so a message containing
    /// newlines/quotes/backslashes (escaped on the wire) decodes and unescapes. A bare `&'a str`
    /// would fail the whole `SSHAction` decode (`expected a borrowed string`), silently dropping the
    /// SSH policy from the netmap.
    #[test]
    fn ssh_action_message_with_escape_sequence_decodes() {
        const TEST: &str = r#"{ "accept": true, "message": "line1\nline2 \"q\" \\done" }"#;
        let action = serde_json::from_str::<SSHAction>(TEST)
            .expect("SSHAction with an escaped message must decode");
        assert_eq!(action.message, "line1\nline2 \"q\" \\done");
        assert!(action.accept);
    }
}
