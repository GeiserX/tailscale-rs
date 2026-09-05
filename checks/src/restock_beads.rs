//! Keep [`docs/restock-beads.json`] honest about how much of its own title a bead covers.
//!
//! The file is the pickable backlog: one entry per parity row that opened at a ledger revision,
//! written for whoever picks it up next and never read by any code. So nothing in the tree fails
//! when an entry promises more than it means. One kind of drift has actually happened and is cheap
//! to catch: an entry whose title named two halves of an upstream change ("routes **and** peer
//! capabilities") while its description set one of them aside as something that "may reasonably be
//! split out", and never said which half closes the bead. A reviewer of #359 read that and could
//! not tell whether shipping the smaller half finishes the work.
//!
//! So: an entry that sets part of its own work aside has to say what closes it. Deferring is fine
//! — most of these rows are bigger than one pull request — but the deferral and the completion
//! criterion have to travel together, because the deferral is exactly what makes the criterion
//! non-obvious.
//!
//! [`docs/restock-beads.json`]: https://github.com/GeiserX/tailscale-rs/blob/main/docs/restock-beads.json

use crate::{Args, BoxResult};

/// The backlog, relative to the repo root.
const BEADS: &str = "docs/restock-beads.json";

/// Phrases that set part of an entry's work aside for someone else.
const DEFERRAL_MARKERS: &[&str] = &[
    "split out",
    "split off",
    "out of scope",
    "separate bead",
    "its own bead",
    "a follow-up",
    "deferred to",
];

/// Phrases that state what actually closes the entry.
const SCOPE_MARKERS: &[&str] = &[
    "closing this bead",
    "closes this bead",
    "this bead is closed",
    "this bead is done when",
    "done means",
];

/// The backlog file, of which only the entries are checked here.
#[derive(serde::Deserialize)]
struct Restock {
    /// The pickable entries.
    beads: Vec<Bead>,
}

/// One backlog entry.
#[derive(serde::Deserialize)]
struct Bead {
    /// The one-line summary, which is the scope a reader sees first.
    title: String,
    /// The full brief: what upstream does, what this tree does, and what closes the entry.
    description: String,
    /// The upstream file and pinned commit the entry was verified against.
    upstream: String,
}

/// Read the backlog and report every entry that leaves its own scope unstated.
pub fn run(_args: &Args) -> BoxResult<()> {
    let text = std::fs::read_to_string(BEADS)?;
    let restock: Restock = serde_json::from_str(&text)?;

    let problems = inconsistencies(&restock.beads);
    if problems.is_empty() {
        return Ok(());
    }

    for problem in &problems {
        println!("{BEADS}: {problem}");
    }

    Err(format!(
        "{BEADS} leaves its scope unstated in {} place(s)",
        problems.len()
    )
    .into())
}

/// Collect everything about `beads` that whoever picks one up would find wrong.
fn inconsistencies(beads: &[Bead]) -> Vec<String> {
    let mut problems = Vec::new();

    for bead in beads {
        let title = bead.title.trim();
        if title.is_empty() {
            problems.push("an entry has an empty title".to_owned());
            continue;
        }

        for (field, value) in [
            ("description", &bead.description),
            ("upstream", &bead.upstream),
        ] {
            if value.trim().is_empty() {
                problems.push(format!("\"{title}\" has an empty {field}"));
            }
        }

        let description = bead.description.to_lowercase();
        if let Some(marker) = DEFERRAL_MARKERS.iter().find(|m| description.contains(**m))
            && !SCOPE_MARKERS.iter().any(|m| description.contains(m))
        {
            problems.push(format!(
                "\"{title}\" sets work aside (\"{marker}\") without saying what closes the bead, \
                 so a reader cannot tell whether the smaller half finishes it"
            ));
        }
    }

    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry with the given description, and everything else filled in plausibly.
    fn bead(description: &str) -> Bead {
        Bead {
            title: "Withhold peer capabilities from an UnsignedPeerAPIOnly peer".to_owned(),
            description: description.to_owned(),
            upstream: "ipn/ipnlocal/node_backend.go @ 9ea7cba4459".to_owned(),
        }
    }

    /// The wording #359 shipped, which a reviewer could not read a completion criterion out of.
    #[test]
    fn rejects_a_deferral_with_no_completion_criterion() {
        let beads = [bead(
            "The minimum faithful port is the upgradeNode clamp: thread unsigned_peer_api_only \
             onto ts_control::Node. The peer-capability half needs a prior decision that is \
             already recorded as open in ts_runtime/src/peerapi.rs, and may reasonably be split \
             out.",
        )];

        let problems = inconsistencies(&beads);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("split out"), "{problems:?}");
    }

    /// Deferring is fine once the entry says which half closes it.
    #[test]
    fn accepts_a_deferral_that_names_what_closes_the_bead() {
        let beads = [bead(
            "Closing this bead means sites (2) and (3), the capability half, and nothing else. \
             The Taildrop file-send peer-cap check the same threading would unblock is explicitly \
             out of scope here.",
        )];

        assert_eq!(inconsistencies(&beads), Vec::<String>::new());
    }

    /// An entry that defers nothing needs no completion criterion: its title is the whole scope.
    #[test]
    fn ignores_an_entry_that_defers_nothing() {
        let beads = [bead(
            "Walk the parents, push a hash when message_kind is the checkpoint variant, and raise \
             the cap to 1000.",
        )];

        assert_eq!(inconsistencies(&beads), Vec::<String>::new());
    }

    /// An entry missing the upstream citation is not pickable, whatever its scope says.
    #[test]
    fn rejects_an_entry_with_no_upstream_citation() {
        let mut beads = [bead("Walk the parents and push a hash.")];
        beads[0].upstream = "  ".to_owned();

        let problems = inconsistencies(&beads);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("empty upstream"), "{problems:?}");
    }

    /// The real backlog has to satisfy the invariant.
    #[test]
    fn the_real_backlog_is_consistent() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../",
            "docs/restock-beads.json"
        ))
        .expect("docs/restock-beads.json");
        let restock: Restock = serde_json::from_str(&text).expect("docs/restock-beads.json parses");

        assert_eq!(inconsistencies(&restock.beads), Vec::<String>::new());
    }
}
