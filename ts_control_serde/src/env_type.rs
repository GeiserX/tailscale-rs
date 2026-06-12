use core::{convert::Infallible, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// Represents the type of runtime environment that this Tailscale node is running in/on.
///
/// On the wire, Go's `hostinfo.EnvType` is a free-form `string` encoding each known variant as a
/// short code (e.g. `"k8s"` for Kubernetes, `""` for unknown). Go never *fails* on an unrecognized
/// code — it simply carries the raw string — and Go adds new codes over time.
///
/// **Serialize** uses the `#[serde(rename = "…")]` on each variant to emit those exact Go codes
/// (without the renames serde would emit the Rust identifiers `"Kubernetes"`, … which control would
/// not understand). **Deserialize** is hand-written (see below) to route through the infallible
/// [`FromStr`] so an unknown/future code decodes to [`EnvType::Unknown`] instead of erroring: a
/// derived (strict) enum deserializer would reject any code outside the known set, and because
/// `HostInfo.env` is non-`Option`, that single rejection would fail the whole `MapResponse` decode
/// and silently drop **every** peer. The renames match the codes [`Display`][fmt::Display] and
/// [`FromStr`] already produce/accept.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub enum EnvType {
    /// Unknown environment.
    #[default]
    #[serde(rename = "")]
    Unknown,
    /// Running on knative.
    #[serde(rename = "kn")]
    KNative,
    /// Running on AWS lambda.
    #[serde(rename = "lm")]
    AWSLambda,
    /// Running on Heroku.
    #[serde(rename = "hr")]
    Heroku,
    /// Running on Azure App Service.
    #[serde(rename = "az")]
    AzureAppService,
    /// Running on AWS Fargate.
    #[serde(rename = "fg")]
    AWSFargate,
    /// Running on fly.io.
    #[serde(rename = "fly")]
    FlyDotIo,
    /// Running in kubernetes.
    #[serde(rename = "k8s")]
    Kubernetes,
    /// Running in Docker Desktop.
    #[serde(rename = "dde")]
    DockerDesktop,
    /// Running on repl.it.
    #[serde(rename = "repl")]
    Replit,
    /// Running in the Home Assistant addon.
    #[serde(rename = "haao")]
    HomeAssistantAddOn,
}

impl fmt::Display for EnvType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            EnvType::Unknown => "",
            EnvType::KNative => "kn",
            EnvType::AWSLambda => "lm",
            EnvType::Heroku => "hr",
            EnvType::AzureAppService => "az",
            EnvType::AWSFargate => "fg",
            EnvType::FlyDotIo => "fly",
            EnvType::Kubernetes => "k8s",
            EnvType::DockerDesktop => "dde",
            EnvType::Replit => "repl",
            EnvType::HomeAssistantAddOn => "haao",
        };
        write!(f, "{str}")
    }
}

impl FromStr for EnvType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = match s {
            "kn" => Self::KNative,
            "lm" => Self::AWSLambda,
            "hr" => Self::Heroku,
            "az" => Self::AzureAppService,
            "fg" => Self::AWSFargate,
            "fly" => Self::FlyDotIo,
            "k8s" => Self::Kubernetes,
            "dde" => Self::DockerDesktop,
            "repl" => Self::Replit,
            "haao" => Self::HomeAssistantAddOn,
            _ => Self::Unknown,
        };
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for EnvType {
    /// Decode the wire string through the infallible [`FromStr`], so an unknown/future Go code maps
    /// to [`EnvType::Unknown`] rather than failing the decode (and with it the whole `MapResponse`).
    ///
    /// Uses a `visit_str` visitor that captures no `'de` lifetime — `EnvType` owns no borrowed data
    /// (it is `Copy`), so it is `DeserializeOwned`. Borrowing the code (e.g. via `Cow<'de, str>`)
    /// would needlessly tie `EnvType: Deserialize<'de>` to the input lifetime and break borrowed
    /// parent structs ("implementation of Deserialize is not general enough").
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EnvTypeVisitor;

        impl serde::de::Visitor<'_> for EnvTypeVisitor {
            type Value = EnvType;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a hostinfo environment-type code string")
            }

            fn visit_str<E>(self, code: &str) -> Result<EnvType, E>
            where
                E: serde::de::Error,
            {
                // FromStr is Infallible (unknown codes fall through to Unknown).
                Ok(EnvType::from_str(code).unwrap_or_default())
            }
        }

        deserializer.deserialize_str(EnvTypeVisitor)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    /// Every variant's serde wire form must equal its [`Display`] code (the Go `hostinfo.EnvType`
    /// code) and round-trip back to the same variant. This is the byte-faithfulness guarantee: the
    /// serde path was previously emitting/accepting the Rust identifiers (`"Kubernetes"`, …), which
    /// do not match what control sends.
    #[test]
    fn serde_wire_form_matches_display_and_round_trips() {
        const ALL: &[EnvType] = &[
            EnvType::Unknown,
            EnvType::KNative,
            EnvType::AWSLambda,
            EnvType::Heroku,
            EnvType::AzureAppService,
            EnvType::AWSFargate,
            EnvType::FlyDotIo,
            EnvType::Kubernetes,
            EnvType::DockerDesktop,
            EnvType::Replit,
            EnvType::HomeAssistantAddOn,
        ];

        for &variant in ALL {
            let json = serde_json::to_string(&variant).unwrap();
            // serde emits a JSON string whose contents are exactly the Display code.
            let expected = alloc::format!("\"{}\"", variant);
            assert_eq!(json, expected, "serde form must equal Display code");
            // …and it round-trips back to the same variant.
            let back: EnvType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    /// A k8s-operator peer sends `"k8s"`; it must decode to [`EnvType::Kubernetes`].
    #[test]
    fn k8s_decodes_to_kubernetes() {
        let value: EnvType = serde_json::from_str("\"k8s\"").unwrap();
        assert_eq!(value, EnvType::Kubernetes);
        assert_eq!(
            serde_json::to_string(&EnvType::Kubernetes).unwrap(),
            "\"k8s\""
        );
        // Display agreement on the load-bearing variant.
        assert_eq!(EnvType::Kubernetes.to_string(), "k8s");
    }

    /// The empty string is the wire code for [`EnvType::Unknown`] (Go's zero value) and must
    /// round-trip both directions.
    #[test]
    fn unknown_round_trips_empty_string() {
        assert_eq!(serde_json::to_string(&EnvType::Unknown).unwrap(), "\"\"");
        let value: EnvType = serde_json::from_str("\"\"").unwrap();
        assert_eq!(value, EnvType::Unknown);
    }

    /// An unrecognized/future Go code (Go's `hostinfo.EnvType` is a free-form string and gains new
    /// codes over time) must decode to [`EnvType::Unknown`], NOT error. A strict (derived) decoder
    /// would reject it and, since `HostInfo.env` is non-`Option`, fail the whole `MapResponse`
    /// decode — silently dropping every peer. This is the regression guard for that.
    #[test]
    fn unknown_code_decodes_to_unknown_not_error() {
        for code in ["\"ecs\"", "\"nomad\"", "\"some-future-platform\""] {
            let value: EnvType =
                serde_json::from_str(code).expect("unknown env code must decode, not error");
            assert_eq!(value, EnvType::Unknown, "code {code} should map to Unknown");
        }
    }
}
