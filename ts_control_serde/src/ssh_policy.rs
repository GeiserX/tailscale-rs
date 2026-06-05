use alloc::{collections::BTreeMap, vec::Vec};
use core::net::SocketAddr;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::node::StableNodeId;

/// The policy for how incoming SSH connections should be handled, as pushed down to a Tailscale
/// node from the control plane (see [`MapResponse::ssh_policy`][crate::MapResponse::ssh_policy]).
///
/// Mirrors `tailcfg.SSHPolicy` in the Go client.
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct SSHPolicy<'a> {
    /// The set of rules that apply to this node, evaluated in order. The first matching rule
    /// determines the outcome of an incoming SSH connection.
    #[serde(default, borrow, rename = "rules")]
    pub rules: Vec<SSHRule<'a>>,
}

/// A single rule within an [`SSHPolicy`]. Rules are evaluated in order; the first one whose
/// [`SSHRule::principals`] match the incoming connection determines its [`SSHRule::action`].
///
/// Mirrors `tailcfg.SSHRule` in the Go client.
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct SSHRule<'a> {
    /// An optional time at which this rule expires. After this time, the rule no longer matches.
    #[serde(default, rename = "ruleExpires")]
    pub rule_expires: Option<DateTime<Utc>>,

    /// The set of principals that this rule applies to. A connection matches this rule if it
    /// matches any of these principals.
    #[serde(default, borrow, rename = "principals")]
    pub principals: Vec<SSHPrincipal<'a>>,

    /// A map from incoming SSH usernames to the local Unix usernames they may run as. The special
    /// key `"*"` matches any incoming username (and the value is then used verbatim as the local
    /// username, unless it is itself `"="` meaning "use the incoming username as-is").
    #[serde(default, borrow, rename = "sshUsers")]
    pub ssh_users: BTreeMap<&'a str, &'a str>,

    /// The action to take when this rule matches. A `None` value means this rule does nothing.
    #[serde(default, borrow, rename = "action")]
    pub action: Option<SSHAction<'a>>,

    /// An optional allowlist of environment variable names that may be forwarded from the SSH
    /// client to the session.
    #[serde(default, borrow, rename = "acceptEnv")]
    pub accept_env: Vec<&'a str>,
}

/// A principal that an [`SSHRule`] may match against. A principal matches if any of its populated
/// fields match the incoming connection.
///
/// Mirrors `tailcfg.SSHPrincipal` in the Go client.
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
    #[serde(default, borrow, rename = "pubKeys")]
    #[deprecated = "does nothing; kept for wire compatibility"]
    pub unused_pub_keys: Vec<&'a str>,
}

/// The action to take when an [`SSHRule`] matches.
///
/// Mirrors `tailcfg.SSHAction` in the Go client.
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct SSHAction<'a> {
    /// An optional message to show to the user when this action is applied.
    #[serde(default, borrow, rename = "message")]
    pub message: &'a str,

    /// If `true`, the connection is rejected.
    #[serde(default, rename = "reject")]
    pub reject: bool,

    /// If `true`, the connection is accepted.
    #[serde(default, rename = "accept")]
    pub accept: bool,

    /// The maximum duration of the session, in **nanoseconds**. Go marshals `time.Duration` with
    /// the `format:nano` tag as an integer nanosecond count. A value of `None`/`0` means no limit.
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
    #[serde(default, rename = "recorders")]
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
    #[serde(default, borrow, rename = "rejectSessionWithMessage")]
    pub reject_session_with_message: &'a str,

    /// If non-empty, an in-progress session is terminated with this message when recording fails.
    #[serde(default, borrow, rename = "terminateSessionWithMessage")]
    pub terminate_session_with_message: &'a str,

    /// If non-empty, a URL to notify (out of band) when recording fails.
    #[serde(default, borrow, rename = "notifyURL")]
    pub notify_url: &'a str,
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
                            "rejectSessionWithMessage": "recording required",
                            "notifyURL": "https://example.com/notify"
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

    #[test]
    fn ssh_policy_empty_rules() {
        let policy = serde_json::from_str::<SSHPolicy>(r#"{}"#).unwrap();
        assert!(policy.rules.is_empty());
    }
}
