//! Owned domain model + evaluation engine for Tailscale SSH policy.
//!
//! Control pushes an [`ts_control_serde::SSHPolicy`] down the netmap
//! ([`MapResponse::ssh_policy`][ts_control_serde::MapResponse::ssh_policy]). This module converts
//! the borrowed wire view into an owned [`SshPolicy`] and provides [`SshPolicy::evaluate`], a
//! faithful reimplementation of the Go client's `evalSSHPolicy` / `matchRule` / `mapLocalUser`
//! decision flow (`ssh/tailssh/tailssh.go`). An incoming SSH connection is allowed **only** when a
//! rule matches; the engine is **default-deny**.
//!
//! ## Go decision flow mirrored here
//!
//! `evalSSHPolicy` walks the rules in order and returns the outcome of the **first** rule that
//! matches (`matchRule` returns `Ok`). `matchRule`:
//! 1. requires a non-nil [`SshAction`] (a rule with no action never matches),
//! 2. rejects expired rules (`RuleExpires.Before(now)`),
//! 3. requires that **some** principal matches the connection identity, and
//! 4. for non-reject actions, requires a non-empty local-user mapping (else the rule is skipped
//!    with a "user match" failure — Go's `errUserMatch`).
//!
//! If no rule matches, the connection is denied. Go distinguishes a plain no-match
//! ([`SshDenyReason::NoRuleMatched`]) from "principals matched but no user mapping applied"
//! ([`SshDenyReason::NoUserMapping`]); both deny, the distinction is kept for diagnostics.
//!
//! ## `SSHUsers` map semantics (verbatim Go)
//!
//! [`SshRule::ssh_users`] maps a **requested** SSH username to the **local** user the session runs
//! as. Lookup is the requested user, falling back to the wildcard key `"*"`. A value of `"="` means
//! "use the requested username as-is"; an **empty-string** value means the rule does **not** apply
//! to that user (no mapping → skip the rule).

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::net::IpAddr;

use chrono::{DateTime, Utc};

/// The wildcard SSH-user key: matches any requested username.
const WILDCARD_USER: &str = "*";
/// The "use the requested username as-is" SSH-user mapping value.
const IDENTITY_MAP: &str = "=";

/// An owned Tailscale SSH policy. Mirrors `tailcfg.SSHPolicy`.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SshPolicy {
    /// Rules evaluated in order; the first matching rule decides the connection.
    pub rules: Vec<SshRule>,
}

/// A single SSH policy rule. Mirrors `tailcfg.SSHRule`.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SshRule {
    /// If set, the rule no longer matches once `now` is at/after this time.
    pub rule_expires: Option<DateTime<Utc>>,
    /// Principals; the rule matches a connection if **any** of these match it.
    pub principals: Vec<SshPrincipal>,
    /// Requested-SSH-user → local-user mapping. See module docs for `"*"` / `"="` / empty semantics.
    pub ssh_users: BTreeMap<String, String>,
    /// The action to take when this rule matches. `None` means the rule never matches.
    pub action: Option<SshAction>,
    /// Allowlist of environment variable names the client may forward.
    pub accept_env: Vec<String>,
}

/// A principal an [`SshRule`] matches against. Mirrors `tailcfg.SSHPrincipal`. A principal matches
/// if [`any`](SshPrincipal::any) is set, or any populated field matches the connection identity.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SshPrincipal {
    /// Match a specific node by its stable node id.
    pub node: String,
    /// Match a node by one of its Tailscale IPs (parsed from this string).
    pub node_ip: String,
    /// Match a node owned by a particular user login (email-ish).
    pub user_login: String,
    /// Match any source.
    pub any: bool,
}

/// The action taken when a rule matches. Mirrors `tailcfg.SSHAction`. Only the fields this fork
/// acts on are retained; recording (`Recorders`/`OnRecordingFailure`) and the interactive
/// `HoldAndDelegate` control round-trip are out of scope for basic `ListenSSH` parity.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SshAction {
    /// Optional message shown to the user.
    pub message: String,
    /// Reject the connection.
    pub reject: bool,
    /// Accept the connection.
    pub accept: bool,
    /// Max session duration in **nanoseconds** (`None`/`0` = unlimited).
    pub session_duration_nanos: Option<i64>,
    /// Allow SSH agent forwarding.
    pub allow_agent_forwarding: bool,
    /// Allow local port forwarding.
    pub allow_local_port_forwarding: bool,
    /// Allow remote port forwarding.
    pub allow_remote_port_forwarding: bool,
}

/// The identity of an incoming SSH connection, resolved from the connecting peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConnIdentity {
    /// The connecting node's stable node id.
    pub stable_id: String,
    /// The connection's tailnet source IP.
    pub src_ip: IpAddr,
    /// The login/email of the user that owns the connecting node, if known. `None` means no
    /// `userLogin` principal can match — fail-closed.
    pub user_login: Option<String>,
}

/// The outcome of evaluating an [`SshPolicy`] against a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshDecision {
    /// A rule matched with an accept action; allow the connection.
    Accept(SshAccept),
    /// The connection is denied. The server denies in every case; the reason aids logging.
    Deny(SshDenyReason),
}

/// Details of an accepted SSH connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAccept {
    /// The resolved local Unix user to run the session as.
    pub local_user: String,
    /// Environment variable names the client may forward.
    pub accept_env: Vec<String>,
    /// Max session duration in nanoseconds (`None`/`0` = unlimited).
    pub session_duration_nanos: Option<i64>,
    /// Whether SSH agent forwarding is permitted.
    pub allow_agent_forwarding: bool,
    /// Whether local port forwarding is permitted.
    pub allow_local_port_forwarding: bool,
    /// Whether remote port forwarding is permitted.
    pub allow_remote_port_forwarding: bool,
}

/// Why a connection was denied. Mirrors Go's `rejected` / `rejectedUser` results plus an explicit
/// reject action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshDenyReason {
    /// A rule matched with an explicit reject action (carries its message).
    ExplicitReject {
        /// The action's message, if any.
        message: String,
    },
    /// No rule matched the connection (Go `rejected`). Default-deny.
    NoRuleMatched,
    /// A rule's principals matched but no SSH-user mapping applied (Go `rejectedUser`).
    NoUserMapping,
}

/// Internal per-rule match failure, mirroring Go's `matchRule` error set. Only `UserMatch` is
/// surfaced (to distinguish [`SshDenyReason::NoUserMapping`]); the rest just skip the rule.
enum RuleSkip {
    /// Rule has no action, is expired, or no principal matched.
    NoMatch,
    /// Principals matched but the user-map produced no local user (Go `errUserMatch`).
    UserMatch,
}

impl SshPolicy {
    /// Build the owned policy from the borrowed wire view parsed off the netmap.
    pub fn from_serde(p: &ts_control_serde::SSHPolicy<'_>) -> Self {
        SshPolicy {
            rules: p.rules.iter().map(SshRule::from_serde).collect(),
        }
    }

    /// Evaluate this policy as of a wall-clock time given in **Unix seconds**.
    ///
    /// Convenience wrapper over [`evaluate`](Self::evaluate) for callers that cannot construct a
    /// `chrono::DateTime<Utc>` (the workspace pins `chrono` without its `clock` feature, so
    /// `Utc::now()` is unavailable outside crates that carry chrono). An out-of-range timestamp is
    /// clamped to the Unix epoch — for rule-expiry that at worst treats a rule as already-expired
    /// (fail-closed).
    pub fn evaluate_at_unix(
        &self,
        id: &SshConnIdentity,
        requested_user: &str,
        now_unix_secs: i64,
    ) -> SshDecision {
        // An out-of-`DateTime`-range timestamp (e.g. the `i64::MAX` a caller uses to signal an
        // unreadable clock) clamps to the far future so time-limited rules look expired — deny,
        // fail-closed. Do NOT clamp to the epoch (`unwrap_or_default`), which would make every
        // future-dated rule look live (fail-open).
        let now = DateTime::from_timestamp(now_unix_secs, 0).unwrap_or(DateTime::<Utc>::MAX_UTC);
        self.evaluate(id, requested_user, now)
    }

    /// Evaluate this policy against an incoming connection requesting `requested_user`, as of
    /// `now`. Returns the first matching rule's outcome, or a default-deny.
    ///
    /// This is the Rust analogue of Go `evalSSHPolicy`: first-match-wins over the ordered rules,
    /// default-deny when nothing matches.
    pub fn evaluate(
        &self,
        id: &SshConnIdentity,
        requested_user: &str,
        now: DateTime<Utc>,
    ) -> SshDecision {
        let mut failed_on_user = false;

        for rule in &self.rules {
            match rule.try_match(id, requested_user, now) {
                Ok(decision) => return decision,
                Err(RuleSkip::UserMatch) => failed_on_user = true,
                Err(RuleSkip::NoMatch) => {}
            }
        }

        SshDecision::Deny(if failed_on_user {
            SshDenyReason::NoUserMapping
        } else {
            SshDenyReason::NoRuleMatched
        })
    }
}

impl SshRule {
    fn from_serde(r: &ts_control_serde::SSHRule<'_>) -> Self {
        SshRule {
            rule_expires: r.rule_expires,
            principals: r.principals.iter().map(SshPrincipal::from_serde).collect(),
            ssh_users: r
                .ssh_users
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            action: r.action.as_ref().map(SshAction::from_serde),
            accept_env: r.accept_env.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Mirror of Go `matchRule`: validate action/expiry/principals/user-mapping in order.
    fn try_match(
        &self,
        id: &SshConnIdentity,
        requested_user: &str,
        now: DateTime<Utc>,
    ) -> Result<SshDecision, RuleSkip> {
        // A rule with no action never matches (Go `errNilAction`).
        let action = self.action.as_ref().ok_or(RuleSkip::NoMatch)?;

        // Expired rules never match (Go `ruleExpired`: nil never expires).
        if self.is_expired(now) {
            return Err(RuleSkip::NoMatch);
        }

        // Some principal must match the connection identity (Go `anyPrincipalMatches`).
        if !self.principals.iter().any(|p| p.matches(id)) {
            return Err(RuleSkip::NoMatch);
        }

        // An explicit reject short-circuits before user mapping (Go skips the user requirement for
        // reject actions).
        if action.reject {
            return Ok(SshDecision::Deny(SshDenyReason::ExplicitReject {
                message: action.message.clone(),
            }));
        }

        // Non-reject rules require a non-empty local-user mapping (Go `errUserMatch` otherwise).
        let local_user =
            map_local_user(&self.ssh_users, requested_user).ok_or(RuleSkip::UserMatch)?;

        Ok(SshDecision::Accept(SshAccept {
            local_user,
            accept_env: self.accept_env.clone(),
            session_duration_nanos: action.session_duration_nanos,
            allow_agent_forwarding: action.allow_agent_forwarding,
            allow_local_port_forwarding: action.allow_local_port_forwarding,
            allow_remote_port_forwarding: action.allow_remote_port_forwarding,
        }))
    }

    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match self.rule_expires {
            None => false,
            Some(expiry) => expiry < now,
        }
    }
}

impl SshPrincipal {
    fn from_serde(p: &ts_control_serde::SSHPrincipal<'_>) -> Self {
        SshPrincipal {
            node: p.node.0.to_string(),
            node_ip: p.node_ip.to_string(),
            user_login: p.user_login.to_string(),
            any: p.any,
        }
    }

    /// Mirror of Go `principalMatchesTailscaleIdentity`: `Any`, or any populated field matching the
    /// connection identity. Empty principal fields never match (so an all-empty principal that is
    /// not `any` matches nothing — fail-closed).
    fn matches(&self, id: &SshConnIdentity) -> bool {
        if self.any {
            return true;
        }
        if !self.node.is_empty() && self.node == id.stable_id {
            return true;
        }
        if !self.node_ip.is_empty()
            && self
                .node_ip
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip == id.src_ip)
        {
            return true;
        }
        if !self.user_login.is_empty()
            && id
                .user_login
                .as_deref()
                .is_some_and(|login| login == self.user_login)
        {
            return true;
        }
        false
    }
}

impl SshAction {
    fn from_serde(a: &ts_control_serde::SSHAction<'_>) -> Self {
        SshAction {
            message: a.message.to_string(),
            reject: a.reject,
            accept: a.accept,
            // Go marshals 0 as omitted; treat 0 as "no limit" too.
            session_duration_nanos: a.session_duration.filter(|d| *d != 0),
            allow_agent_forwarding: a.allow_agent_forwarding,
            allow_local_port_forwarding: a.allow_local_port_forwarding,
            allow_remote_port_forwarding: a.allow_remote_port_forwarding,
        }
    }
}

/// Mirror of Go `mapLocalUser`: look up the requested user, falling back to the `"*"` wildcard. A
/// `"="` value maps to the requested user verbatim; an empty-string value (or no entry) yields
/// `None` (no mapping → the rule does not apply to this user).
fn map_local_user(ssh_users: &BTreeMap<String, String>, requested_user: &str) -> Option<String> {
    let mapped = ssh_users
        .get(requested_user)
        .or_else(|| ssh_users.get(WILDCARD_USER))?;

    if mapped.is_empty() {
        return None;
    }
    if mapped == IDENTITY_MAP {
        return Some(requested_user.to_string());
    }
    Some(mapped.clone())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // A fixed "now" for evaluation; chrono's `clock` feature (Utc::now) isn't enabled here.
    fn now() -> DateTime<Utc> {
        "2026-06-05T00:00:00Z".parse().unwrap()
    }

    fn id(stable_id: &str, src: &str, login: Option<&str>) -> SshConnIdentity {
        SshConnIdentity {
            stable_id: stable_id.to_string(),
            src_ip: ip(src),
            user_login: login.map(|s| s.to_string()),
        }
    }

    fn accept_rule(principals: Vec<SshPrincipal>, ssh_users: &[(&str, &str)]) -> SshRule {
        SshRule {
            rule_expires: None,
            principals,
            ssh_users: ssh_users
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            action: Some(SshAction {
                accept: true,
                ..Default::default()
            }),
            accept_env: vec![],
        }
    }

    fn any_principal() -> SshPrincipal {
        SshPrincipal {
            any: true,
            ..Default::default()
        }
    }

    #[test]
    fn empty_policy_denies() {
        let pol = SshPolicy::default();
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        assert_eq!(d, SshDecision::Deny(SshDenyReason::NoRuleMatched));
    }

    #[test]
    fn any_principal_with_wildcard_user_accepts_identity_map() {
        let pol = SshPolicy {
            rules: vec![accept_rule(vec![any_principal()], &[("*", "=")])],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "ubuntu", now());
        match d {
            SshDecision::Accept(a) => assert_eq!(a.local_user, "ubuntu"),
            other => panic!("expected accept, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_user_with_fixed_local_user() {
        let pol = SshPolicy {
            rules: vec![accept_rule(vec![any_principal()], &[("*", "deploy")])],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "anything", now());
        match d {
            SshDecision::Accept(a) => assert_eq!(a.local_user, "deploy"),
            other => panic!("expected accept, got {other:?}"),
        }
    }

    #[test]
    fn empty_string_user_value_denies_as_no_user_mapping() {
        // An empty-string mapping means the rule does NOT apply to that user. Since principals
        // matched but no user mapping applied, the final deny reason is NoUserMapping.
        let pol = SshPolicy {
            rules: vec![accept_rule(vec![any_principal()], &[("root", "")])],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        assert_eq!(d, SshDecision::Deny(SshDenyReason::NoUserMapping));
    }

    #[test]
    fn no_matching_user_key_falls_through_to_no_user_mapping() {
        // Requested "root" with only a non-wildcard "alice" entry: no mapping, principals matched.
        let pol = SshPolicy {
            rules: vec![accept_rule(vec![any_principal()], &[("alice", "alice")])],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        assert_eq!(d, SshDecision::Deny(SshDenyReason::NoUserMapping));
    }

    #[test]
    fn specific_user_key_preferred_over_wildcard() {
        let pol = SshPolicy {
            rules: vec![accept_rule(
                vec![any_principal()],
                &[("root", "rootlocal"), ("*", "nobody")],
            )],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        match d {
            SshDecision::Accept(a) => assert_eq!(a.local_user, "rootlocal"),
            other => panic!("expected accept, got {other:?}"),
        }
    }

    #[test]
    fn principal_matches_by_stable_id() {
        let pol = SshPolicy {
            rules: vec![accept_rule(
                vec![SshPrincipal {
                    node: "nABC".to_string(),
                    ..Default::default()
                }],
                &[("*", "=")],
            )],
        };
        let yes = pol.evaluate(&id("nABC", "100.64.0.9", None), "u", now());
        assert!(matches!(yes, SshDecision::Accept(_)));
        let no = pol.evaluate(&id("nXYZ", "100.64.0.9", None), "u", now());
        assert_eq!(no, SshDecision::Deny(SshDenyReason::NoRuleMatched));
    }

    #[test]
    fn principal_matches_by_node_ip() {
        let pol = SshPolicy {
            rules: vec![accept_rule(
                vec![SshPrincipal {
                    node_ip: "100.64.0.7".to_string(),
                    ..Default::default()
                }],
                &[("*", "=")],
            )],
        };
        let yes = pol.evaluate(&id("n1", "100.64.0.7", None), "u", now());
        assert!(matches!(yes, SshDecision::Accept(_)));
        let no = pol.evaluate(&id("n1", "100.64.0.8", None), "u", now());
        assert_eq!(no, SshDecision::Deny(SshDenyReason::NoRuleMatched));
    }

    #[test]
    fn principal_matches_by_user_login() {
        let pol = SshPolicy {
            rules: vec![accept_rule(
                vec![SshPrincipal {
                    user_login: "alice@example.com".to_string(),
                    ..Default::default()
                }],
                &[("*", "=")],
            )],
        };
        let yes = pol.evaluate(
            &id("n1", "100.64.0.1", Some("alice@example.com")),
            "u",
            now(),
        );
        assert!(matches!(yes, SshDecision::Accept(_)));
        // Unknown login (None) can never match a userLogin principal — fail-closed.
        let no = pol.evaluate(&id("n1", "100.64.0.1", None), "u", now());
        assert_eq!(no, SshDecision::Deny(SshDenyReason::NoRuleMatched));
    }

    #[test]
    fn all_empty_non_any_principal_matches_nothing() {
        let pol = SshPolicy {
            rules: vec![accept_rule(vec![SshPrincipal::default()], &[("*", "=")])],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", Some("a@b")), "u", now());
        assert_eq!(d, SshDecision::Deny(SshDenyReason::NoRuleMatched));
    }

    #[test]
    fn explicit_reject_short_circuits_before_user_mapping() {
        // Reject rule with NO ssh_users mapping still rejects (user mapping is skipped for reject).
        let pol = SshPolicy {
            rules: vec![SshRule {
                principals: vec![any_principal()],
                action: Some(SshAction {
                    reject: true,
                    message: "go away".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        assert_eq!(
            d,
            SshDecision::Deny(SshDenyReason::ExplicitReject {
                message: "go away".to_string()
            })
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        // A reject rule before an accept rule wins.
        let pol = SshPolicy {
            rules: vec![
                SshRule {
                    principals: vec![any_principal()],
                    action: Some(SshAction {
                        reject: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                accept_rule(vec![any_principal()], &[("*", "=")]),
            ],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        assert!(matches!(
            d,
            SshDecision::Deny(SshDenyReason::ExplicitReject { .. })
        ));
    }

    #[test]
    fn rule_with_no_action_is_skipped() {
        let pol = SshPolicy {
            rules: vec![
                SshRule {
                    principals: vec![any_principal()],
                    action: None,
                    ..Default::default()
                },
                accept_rule(vec![any_principal()], &[("*", "=")]),
            ],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        assert!(matches!(d, SshDecision::Accept(_)));
    }

    #[test]
    fn expired_rule_is_skipped() {
        let past = "2000-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let pol = SshPolicy {
            rules: vec![SshRule {
                rule_expires: Some(past),
                ..accept_rule(vec![any_principal()], &[("*", "=")])
            }],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        assert_eq!(d, SshDecision::Deny(SshDenyReason::NoRuleMatched));
    }

    #[test]
    fn unexpired_rule_still_matches() {
        let future = "2999-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let pol = SshPolicy {
            rules: vec![SshRule {
                rule_expires: Some(future),
                ..accept_rule(vec![any_principal()], &[("*", "=")])
            }],
        };
        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "root", now());
        assert!(matches!(d, SshDecision::Accept(_)));
    }

    #[test]
    fn evaluate_at_unix_far_future_expires_time_limited_rules() {
        // A broken clock surfaces as i64::MAX seconds; a time-limited rule must then look expired
        // (deny) rather than perpetually-live — fail-closed expiry.
        let future = "2999-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let pol = SshPolicy {
            rules: vec![SshRule {
                rule_expires: Some(future),
                ..accept_rule(vec![any_principal()], &[("*", "=")])
            }],
        };
        let d = pol.evaluate_at_unix(&id("n1", "100.64.0.1", None), "root", i64::MAX);
        assert_eq!(d, SshDecision::Deny(SshDenyReason::NoRuleMatched));
    }

    #[test]
    fn session_duration_zero_is_unlimited() {
        let serde_action = ts_control_serde::SSHAction {
            accept: true,
            session_duration: Some(0),
            ..Default::default()
        };
        assert_eq!(
            SshAction::from_serde(&serde_action).session_duration_nanos,
            None
        );
    }

    #[test]
    fn from_serde_round_trips_a_policy() {
        let wire = r#"{
            "rules": [
                {
                    "principals": [{ "any": true }],
                    "sshUsers": { "*": "=" },
                    "action": { "accept": true, "allowAgentForwarding": true }
                }
            ]
        }"#;
        let serde_pol: ts_control_serde::SSHPolicy = serde_json::from_str(wire).unwrap();
        let pol = SshPolicy::from_serde(&serde_pol);

        let d = pol.evaluate(&id("n1", "100.64.0.1", None), "ubuntu", now());
        match d {
            SshDecision::Accept(a) => {
                assert_eq!(a.local_user, "ubuntu");
                assert!(a.allow_agent_forwarding);
            }
            other => panic!("expected accept, got {other:?}"),
        }
    }
}
