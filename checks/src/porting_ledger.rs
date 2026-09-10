//! Keep [`PORTING.md`]'s internal references honest.
//!
//! The ledger is prose, so nothing else in the tree fails when it drifts from itself. Two kinds
//! of drift have actually happened and are cheap to catch:
//!
//! 1. A `see §B, *Some subsection*` pointer that names no subsection, so the reader is sent
//!    somewhere that does not exist.
//! 2. A claim that a set of upstream packages is "in the mapping table" when some of them are
//!    documented in the *no counterpart here* list instead — a reader who trusts the sentence
//!    goes looking for a table row that was never there.
//!
//! A third invariant is the one the ledger's own sweep prose now rests on: every package in the
//! `for p in …` re-derivation loop has to be documented under *Package mapping*, in the table or
//! in the list of partials below it.
//!
//! A fourth is typographic, and it bites both a reader and this check: the ledger cites pull
//! requests as `#412`, and a paragraph that wraps so one of those lands at the start of a line
//! reads as a malformed heading. markdownlint reports it as MD018, and the anchor scan below
//! used to index it as a heading a `§B, *…*` pointer could legitimately name.
//!
//! [`PORTING.md`]: https://github.com/GeiserX/tailscale-rs/blob/main/PORTING.md

use std::collections::BTreeSet;

use crate::{Args, BoxResult};

/// The ledger, relative to the repo root.
const LEDGER: &str = "PORTING.md";

/// Heading that opens the package-mapping section.
const MAPPING_HEADING: &str = "## Package mapping";

/// Prose that promises a package is a row in the mapping table.
const MAPPING_CLAIM: &str = "mapping table";

/// Read the ledger and report every inconsistency it has with itself.
pub fn run(_args: &Args) -> BoxResult<()> {
    let text = std::fs::read_to_string(LEDGER)?;

    let problems = inconsistencies(&text);
    if problems.is_empty() {
        return Ok(());
    }

    for problem in &problems {
        println!("{LEDGER}: {problem}");
    }

    Err(format!("{LEDGER} contradicts itself in {} place(s)", problems.len()).into())
}

/// Collect everything about `text` that a reader would find wrong.
fn inconsistencies(text: &str) -> Vec<String> {
    let mut problems = Vec::new();

    let anchors = anchors(text);
    for name in section_refs(text) {
        if !anchors.contains(&name) {
            problems.push(format!(
                "cross-reference to \"{name}\" names no heading or bold label in the document"
            ));
        }
    }

    let swept = swept_packages(text);
    let in_table = mapping_table_packages(text);
    for paragraph in paragraphs(text) {
        if !paragraph.contains(MAPPING_CLAIM) {
            continue;
        }
        for pkg in backticked(paragraph).into_iter().collect::<BTreeSet<_>>() {
            if swept.contains(&pkg) && !in_table.contains(&pkg) {
                problems.push(format!(
                    "a paragraph claims `{pkg}` is in the mapping table, but it is documented \
                     outside it"
                ));
            }
        }
    }

    for (number, line) in prose_lines(text) {
        if !unclosed_hash_run(line) {
            continue;
        }
        problems.push(format!(
            "line {number} opens with `#` and no space closes it, so it reads as a malformed \
             heading (markdownlint MD018): \"{}\"",
            excerpt(line)
        ));
    }

    let documented = documented_packages(text);
    for pkg in &swept {
        if !documented.contains(pkg) {
            problems.push(format!(
                "`{pkg}` is swept by the re-derivation loop but is not documented under \
                 \"{MAPPING_HEADING}\""
            ));
        }
    }

    problems
}

/// Every `§X, *Name*` pointer in `text`, as the `Name` it points at.
fn section_refs(text: &str) -> Vec<String> {
    let mut refs = Vec::new();

    for after in text.split('§').skip(1) {
        // `§B, *Name*` — a bare `§B` in running prose points at the section, not a subsection.
        let Some(rest) = after.get(1..).and_then(|r| r.strip_prefix(", *")) else {
            continue;
        };
        let Some(end) = rest.find('*') else { continue };
        refs.push(rest[..end].to_owned());
    }

    refs
}

/// Every name a `§X, *Name*` pointer is allowed to land on: a heading, or the bold label that
/// opens a bullet in the gap list.
fn anchors(text: &str) -> BTreeSet<String> {
    let mut anchors = BTreeSet::new();

    for (_, line) in prose_lines(text) {
        // A `#` that no space closes is not a heading — it is a wrapped `#412` reference — so
        // nothing may point at it.
        if let Some(heading) = atx_heading(line) {
            anchors.insert(heading.to_owned());
            continue;
        }

        // Only bold that *opens* a bullet is a label a pointer may name; bold anywhere else is
        // emphasis in running prose, and the ledger is full of it.
        if let Some(rest) = line.trim_start().strip_prefix("- **")
            && let Some(end) = rest.find("**")
        {
            anchors.insert(rest[..end].to_owned());
        }
    }

    anchors
}

/// Every line of `text` that is prose, as a `(line number, line)` pair numbered from 1.
///
/// Fenced blocks are not prose: the re-derivation block is shell, where a `#` opens a comment
/// rather than a heading.
fn prose_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut fence: Option<(char, usize)> = None;

    text.lines().enumerate().filter_map(move |(index, line)| {
        if let Some((marker, length)) = fence_marker(line) {
            match fence {
                None => fence = Some((marker, length)),
                // A longer fence quotes shorter ones whole, so only a run of the same character
                // that is at least as long as the opening one closes the block.
                Some((open_marker, open_length))
                    if marker == open_marker && length >= open_length =>
                {
                    fence = None;
                }
                Some(_) => {}
            }
            return None;
        }

        fence.is_none().then_some((index + 1, line))
    })
}

/// The text of `line` if it is an ATX heading, with its hashes and surrounding space removed.
///
/// A heading's hash run is closed by a space or by the end of the line, and is indented by at
/// most three columns — four opens a code block, where the hashes are content.
fn atx_heading(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if line.len() - trimmed.len() > 3 {
        return None;
    }

    let rest = trimmed.trim_start_matches('#');
    if rest.len() == trimmed.len() {
        return None;
    }

    (rest.is_empty() || rest.starts_with(' ')).then(|| rest.trim())
}

/// Whether `line` opens with a hash run that no space closes, which markdownlint reports as
/// MD018.
///
/// Column zero only, which is where MD018 looks: an *indented* `#412` is a continuation line
/// inside a list item, and renders — and lints — as the prose it is.
fn unclosed_hash_run(line: &str) -> bool {
    line.starts_with('#') && atx_heading(line).is_none()
}

/// As much of `line` as names it in a report without quoting a whole wrapped paragraph back.
fn excerpt(line: &str) -> String {
    const WIDTH: usize = 32;

    let line = line.trim();
    match line.char_indices().nth(WIDTH) {
        Some((end, _)) => format!("{}…", &line[..end]),
        None => line.to_owned(),
    }
}

/// The fence delimiter a line runs, as the character it is made of and how long the run is.
///
/// A fence is three or more backticks or tildes; anything shorter is inline code, or prose. The
/// character matters as much as the length: a tilde fence is closed by tildes alone, so a
/// backtick run inside one is just content.
fn fence_marker(line: &str) -> Option<(char, usize)> {
    let line = line.trim_start();
    let marker = line.chars().next().filter(|c| *c == '`' || *c == '~')?;
    let length = line.chars().take_while(|c| *c == marker).count();

    (length >= 3).then_some((marker, length))
}

/// The upstream packages the re-derivation loop actually sweeps.
///
/// The loop is quoted in prose as well as written out in the shell block, so take the first
/// `for p in …; do` whose body is a bare list of packages — backticks or a paragraph break mean
/// the match was the prose one and the `; do` belongs to the real loop further down.
fn swept_packages(text: &str) -> BTreeSet<String> {
    for (start, needle) in text.match_indices("for p in ") {
        let list = &text[start + needle.len()..];
        let Some(end) = list.find("; do") else {
            continue;
        };

        let list = &list[..end];
        if list.contains('`') || list.contains("\n\n") {
            continue;
        }

        return list
            .split_whitespace()
            .filter(|token| *token != "\\")
            .map(str::to_owned)
            .collect();
    }

    BTreeSet::new()
}

/// Upstream packages that are rows of one of the mapping tables — the first column only, since
/// the second column names crates in this tree.
fn mapping_table_packages(text: &str) -> BTreeSet<String> {
    let mut packages = BTreeSet::new();

    for line in mapping_section(text).lines() {
        let Some(row) = line.strip_prefix('|') else {
            continue;
        };
        let Some((first_column, _)) = row.split_once('|') else {
            continue;
        };
        packages.extend(backticked(first_column));
    }

    packages
}

/// Every package named anywhere under *Package mapping*, table rows and the *no counterpart
/// here* list alike.
fn documented_packages(text: &str) -> BTreeSet<String> {
    backticked(mapping_section(text)).into_iter().collect()
}

/// The *Package mapping* section, from its heading to the next top-level heading.
fn mapping_section(text: &str) -> &str {
    let Some(start) = text.find(MAPPING_HEADING) else {
        return "";
    };
    let section = &text[start + MAPPING_HEADING.len()..];

    match section.find("\n## ") {
        Some(end) => &section[..end],
        None => section,
    }
}

/// Blank-line-separated blocks of `text`.
fn paragraphs(text: &str) -> impl Iterator<Item = &str> {
    text.split("\n\n")
}

/// Every backtick-quoted span in `s`.
fn backticked(s: &str) -> Vec<String> {
    s.split('`').skip(1).step_by(2).map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature ledger with the same shape as the real one.
    const SKELETON: &str = "\
## Package mapping

| Upstream Go | Here |
| --- | --- |
| `net/socks5` (as used by `tsnet.Server.Loopback`) | [`src/loopback.rs`](src/loopback.rs) |
| `tsnet` | the [`tailscale`](src/lib.rs) crate |

### Upstream packages with no counterpart here

- `ipn/localapi`, `client/local` — **partial**: one route only.

## Gap list

### B. Behaviour upstream changed in the window

- **c2n endpoints behind the declared capability version** — held below 126.

#### New at this revision

BODY

### Re-deriving this ledger

```sh
# What upstream touched per mapped package
for p in net/socks5 ipn/localapi tsnet; do
  echo \"== $p\"
done
```
";

    /// Build a ledger whose header row points at `reference` and whose sweep prose is `prose`.
    fn ledger(reference: &str, prose: &str) -> String {
        SKELETON.replace("BODY", prose).replace(
            "## Package mapping",
            &format!("| **Previous pin** | see §B, *{reference}* |\n\n## Package mapping"),
        )
    }

    /// The wording the ledger carries today has to pass.
    #[test]
    fn accepts_the_corrected_wording() {
        let text = ledger(
            "New at this revision",
            "`net/socks5`, `ipn/localapi` and `tsnet` are all covered by Package mapping above, \
             whether as a table row or as a *partial* entry.",
        );

        assert_eq!(inconsistencies(&text), Vec::<String>::new());
    }

    /// A `§B` pointer at a subsection that does not exist is the first finding.
    #[test]
    fn rejects_a_cross_reference_to_no_subsection() {
        let text = ledger(
            "New since the previous pin",
            "`net/socks5` and `tsnet` are all covered by Package mapping above.",
        );

        let problems = inconsistencies(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("New since the previous pin"),
            "{problems:?}"
        );
    }

    /// A bare `§B` in running prose points at the section itself, not at a subsection.
    #[test]
    fn ignores_a_bare_section_reference() {
        let text = ledger(
            "New at this revision",
            "Held below 126, see §B. `tsnet` is swept.",
        );

        assert_eq!(inconsistencies(&text), Vec::<String>::new());
    }

    /// A pointer may also land on the bold label that opens a gap-list bullet.
    #[test]
    fn accepts_a_reference_to_a_bold_bullet_label() {
        let text = ledger(
            "c2n endpoints behind the declared capability version",
            "Nothing here.",
        );

        assert_eq!(inconsistencies(&text), Vec::<String>::new());
    }

    /// A shell comment in the re-derivation block is not a heading, so nothing may point at it.
    #[test]
    fn rejects_a_cross_reference_to_a_shell_comment() {
        let text = ledger("What upstream touched per mapped package", "Nothing here.");

        let problems = inconsistencies(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("What upstream touched per mapped package"),
            "{problems:?}"
        );
    }

    /// A four-backtick fence quotes a three-backtick line without closing, so a shell comment
    /// after that inner line is still inside the block and no pointer may land on it.
    #[test]
    fn rejects_a_cross_reference_inside_a_longer_fence() {
        let text = ledger("Quoted heading", "Nothing here.").replace(
            "```sh",
            "````md\n# Not a heading\n\n```sh\n# Quoted heading\n```\n````\n\n```sh",
        );

        let problems = inconsistencies(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("Quoted heading"), "{problems:?}");
    }

    /// Tildes fence a block just as backticks do, and a backtick run does not close one.
    #[test]
    fn rejects_a_cross_reference_inside_a_tilde_fence() {
        let text = ledger("Quoted heading", "Nothing here.")
            .replace("```sh", "~~~md\n# Quoted heading\n~~~\n\n```sh");

        let problems = inconsistencies(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("Quoted heading"), "{problems:?}");
    }

    /// Bold emphasis in running prose is not a label, so nothing may point at it either.
    #[test]
    fn rejects_a_cross_reference_to_bold_prose() {
        let text = ledger(
            "held below 126",
            "The declaration is **held below 126**. `tsnet` is swept.",
        );

        let problems = inconsistencies(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("held below 126"), "{problems:?}");
    }

    /// Sweep prose may not promise a mapping-table row for a package documented as a partial.
    #[test]
    fn rejects_a_mapping_table_claim_for_a_package_outside_the_table() {
        let text = ledger(
            "New at this revision",
            "`net/socks5`, `ipn/localapi` and `tsnet` are all in the package-mapping table above.",
        );

        let problems = inconsistencies(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("`ipn/localapi`"), "{problems:?}");
    }

    /// Naming only real table rows next to the claim is fine.
    #[test]
    fn accepts_a_mapping_table_claim_that_holds() {
        let text = ledger(
            "New at this revision",
            "`net/socks5` and `tsnet` are in the mapping table.",
        );

        assert_eq!(inconsistencies(&text), Vec::<String>::new());
    }

    /// Widening the sweep loop without documenting the package is the drift the loop had before.
    #[test]
    fn rejects_a_swept_package_that_is_not_documented() {
        let text = ledger("New at this revision", "Nothing here.").replace(
            "for p in net/socks5",
            "for p in net/socks5 feature/remoteconfig",
        );

        let problems = inconsistencies(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("`feature/remoteconfig`"),
            "{problems:?}"
        );
    }

    /// A paragraph that wraps a `#412` reference onto the start of a line reads as a malformed
    /// heading, which is the shape markdownlint reports as MD018.
    #[test]
    fn rejects_a_reference_that_wraps_to_the_start_of_a_line() {
        let text = ledger(
            "New at this revision",
            "Four rows closed on tree movement alone (#404, #406,\n#412), six at the previous one.",
        );

        let problems = inconsistencies(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("MD018"), "{problems:?}");
    }

    /// A wrapped reference is prose, so a `§B, *…*` pointer may not land on it either.
    #[test]
    fn a_wrapped_reference_is_not_an_anchor() {
        let anchors = anchors("#412), six at the previous one\n");

        assert!(anchors.is_empty(), "{anchors:?}");
    }

    /// A reference indented as a continuation line inside a list item renders as prose and
    /// lints clean, so it is not a finding.
    #[test]
    fn ignores_an_indented_reference() {
        let text = ledger(
            "New at this revision",
            "- **A row**\n  (`ipn/ipnlocal/node_backend.go`) — **already covered**:\n  #412 landed \
             it after the previous revision was written.",
        );

        assert_eq!(inconsistencies(&text), Vec::<String>::new());
    }

    /// Inside the re-derivation block a `#` is shell, so a shebang is not a malformed heading.
    #[test]
    fn ignores_an_unclosed_hash_run_inside_a_fence() {
        let text = ledger("New at this revision", "Nothing here.")
            .replace("```sh\n", "```sh\n#!/usr/bin/env bash\n");

        assert_eq!(inconsistencies(&text), Vec::<String>::new());
    }

    /// The real ledger has to satisfy every invariant.
    #[test]
    fn the_real_ledger_is_consistent() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../", "PORTING.md"))
                .expect("PORTING.md");

        assert_eq!(inconsistencies(&text), Vec::<String>::new());
    }
}
