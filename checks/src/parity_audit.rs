//! Keep [`PARITY_AUDIT.json`]'s gate result readable as the verdict it is.
//!
//! `gate.detail` is prose inside a JSON field, so nothing else in the tree fails when it
//! contradicts the `gate.pass` boolean beside it. One kind of drift has actually happened and is
//! cheap to catch: a step the detail enumerated as one of the run's failures was labelled *the
//! bins/tests/benches/examples clippy pass*. There "pass" is the noun for a compiler run over a
//! target set, but sitting where the label of a failure goes it reads as the verdict *passed*, and
//! a reviewer of #326 read it that way and filed the gate result as wrong.
//!
//! So: when the gate did not pass, none of the failures the detail enumerates may be labelled with
//! a word that reads as success.
//!
//! [`PARITY_AUDIT.json`]: https://github.com/GeiserX/tailscale-rs/blob/main/PARITY_AUDIT.json

use crate::{Args, BoxResult};

/// The audit, relative to the repo root.
const AUDIT: &str = "PARITY_AUDIT.json";

/// Words that report success, and so may not label a failure.
const SUCCESS_WORDS: &[&str] = &[
    "pass",
    "passes",
    "passed",
    "passing",
    "succeeds",
    "succeeded",
];

/// The whole audit, of which only the gate result is checked here.
#[derive(serde::Deserialize)]
struct Audit {
    /// The result of the gate run the audit records.
    gate: Gate,
}

/// The gate result: a verdict, and the prose that explains it.
#[derive(serde::Deserialize)]
struct Gate {
    /// Whether the gate run passed.
    pass: bool,
    /// What the run did, and — when it did not pass — what failed, enumerated as `(1)`, `(2)`, ….
    detail: String,
}

/// Read the audit and report every way its gate result contradicts itself.
pub fn run(_args: &Args) -> BoxResult<()> {
    let text = std::fs::read_to_string(AUDIT)?;
    let audit: Audit = serde_json::from_str(&text)?;

    let problems = inconsistencies(&audit.gate);
    if problems.is_empty() {
        return Ok(());
    }

    for problem in &problems {
        println!("{AUDIT}: {problem}");
    }

    Err(format!(
        "{AUDIT} contradicts its own gate result in {} place(s)",
        problems.len()
    )
    .into())
}

/// Collect everything about `gate` that a reader would find wrong.
fn inconsistencies(gate: &Gate) -> Vec<String> {
    // A passing gate enumerates no failures, so there is no label to misread.
    if gate.pass {
        return Vec::new();
    }

    let mut problems = Vec::new();

    for (marker, label) in enumerated_labels(&gate.detail) {
        if let Some(word) = success_word(label) {
            problems.push(format!(
                "failure ({marker}) is labelled \"{label}\", and \"{word}\" there reads as the \
                 verdict that the step passed"
            ));
        }
    }

    problems
}

/// Every `(N) Label:` item the detail enumerates, as its `N` and its `Label`.
///
/// The label runs from the marker to the colon that introduces what went wrong, and is bounded by
/// the end of the sentence and by the next marker so that a colonless item cannot swallow the rest
/// of the detail.
fn enumerated_labels(detail: &str) -> Vec<(&str, &str)> {
    let mut items = Vec::new();

    for (start, _) in detail.match_indices('(') {
        let rest = &detail[start + 1..];
        let Some(close) = rest.find(')') else {
            continue;
        };
        let marker = &rest[..close];
        // `(fd7ed57dfd 2026-08-29)` and `(the anti-leak check)` are asides, not enumeration.
        if marker.is_empty() || !marker.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }

        let after = &rest[close + 1..];
        let end = [after.find(':'), after.find('.'), after.find('(')]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(after.len());
        items.push((marker, after[..end].trim()));
    }

    items
}

/// The first word of `label` that reports success, if it has one.
fn success_word(label: &str) -> Option<&str> {
    label
        .split(|c: char| !c.is_ascii_alphanumeric())
        .find(|word| SUCCESS_WORDS.contains(&word.to_ascii_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a gate result that failed, with `detail` as its prose.
    fn failed(detail: &str) -> Gate {
        Gate {
            pass: false,
            detail: detail.to_owned(),
        }
    }

    /// The wording the audit carries today has to pass.
    #[test]
    fn accepts_a_failure_labelled_as_a_failure() {
        let gate = failed(
            "bin/check on current main (7c39ae0, clean tree). Two failures. (1) Step 1, cargo \
             +nightly fmt --check: 22 import-granularity diffs. (2) The clippy run over bins, \
             tests, benches and examples fails: clippy::items_after_test_module.",
        );

        assert_eq!(inconsistencies(&gate), Vec::<String>::new());
    }

    /// The wording #326 shipped, which a reviewer read as the claim that the step passed.
    #[test]
    fn rejects_a_failure_labelled_with_a_success_word() {
        let gate = failed(
            "Two failures. (1) Step 1, cargo +nightly fmt --check: 22 import-granularity diffs. \
             (2) The bins/tests/benches/examples clippy pass: clippy::items_after_test_module.",
        );

        let problems = inconsistencies(&gate);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("failure (2)"), "{problems:?}");
    }

    /// A success word outside a failure's label is reporting a step that really did pass.
    #[test]
    fn ignores_a_success_word_outside_a_failure_label() {
        let gate = failed(
            "Two failures. (1) Step 1, cargo +nightly fmt --check: 22 diffs. (2) The clippy run \
             over bins, tests, benches and examples fails: items_after_test_module. Steps that \
             did pass when run individually past the set -e stop: cargo run -p checks and the \
             --lib clippy pass.",
        );

        assert_eq!(inconsistencies(&gate), Vec::<String>::new());
    }

    /// A parenthesised aside is not an enumerated failure, however it reads.
    #[test]
    fn ignores_parenthesised_asides() {
        let gate = failed(
            "local nightly rustfmt is 1.10.0-nightly (fd7ed57dfd 2026-08-29) and the pinned \
             stable one (rustfmt 1.9.0-stable) passes.",
        );

        assert_eq!(inconsistencies(&gate), Vec::<String>::new());
    }

    /// When the gate passed there is no failure to mislabel, so the prose is left alone.
    #[test]
    fn ignores_the_detail_of_a_gate_that_passed() {
        let gate = Gate {
            pass: true,
            detail: "(1) Every step: pass.".to_owned(),
        };

        assert_eq!(inconsistencies(&gate), Vec::<String>::new());
    }

    /// The real audit has to satisfy the invariant.
    #[test]
    fn the_real_audit_is_consistent() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../",
            "PARITY_AUDIT.json"
        ))
        .expect("PARITY_AUDIT.json");
        let audit: Audit = serde_json::from_str(&text).expect("PARITY_AUDIT.json parses");

        assert_eq!(inconsistencies(&audit.gate), Vec::<String>::new());
    }
}
