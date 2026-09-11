//! Minimal in-tree dudect harness: a timing runner plus Welch's t-test with percentile cropping.
//!
//! # Provenance
//!
//! The statistics here (percentile preparation, cropped-sample t-tests, Welch's t, `max_tau`, and
//! the summary line format) are vendored from `dudect-bencher` 0.7.0 —
//! <https://github.com/rozbb/dudect-bencher>, © Michael Rosenberg, dual-licensed
//! `MIT OR Apache-2.0` — with the crate's CLI, continuous mode, CSV output and Ctrl-C handling
//! dropped. The algorithm is unchanged, so `max_t` is directly comparable to numbers produced by
//! the upstream crate. See [`VENDOR.md`](../../../VENDOR.md).
//!
//! # Why vendored instead of depended on
//!
//! `dudect-bencher` 0.7.0 (its newest release) depends on `clap` 2 with default features, which
//! pulls `atty` 0.2.14 into `Cargo.lock`. `atty` is unmaintained with no patched release
//! (RUSTSEC-2021-0145 / GHSA-g98v-hv3f-hcfr), so no version bump removes it — only dropping the
//! dependency does. The harness this bench actually uses is ~200 lines, so it lives here instead.
//!
//! Losing the crate's `ctbench_main!` also removes its argument parser, which used to reject the
//! `--bench` flag `cargo bench` appends; a plain `cargo bench --bench constant_time` now works.

use std::{cmp::Ordering, fmt, hint::black_box, time::Instant};

/// Which of the two input distributions a timing sample was drawn from.
///
/// dudect times one operation under two input classes and tests whether the two timing
/// distributions differ. A difference is evidence of a timing side-channel.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Class {
    /// The first input distribution.
    Left,
    /// The second input distribution.
    Right,
}

/// Collects timed samples, tagged by [`Class`], for one bench function.
#[derive(Default)]
pub struct CtRunner {
    /// Runtimes of the left and right distributions, in nanoseconds.
    runtimes: (Vec<u64>, Vec<u64>),
}

impl CtRunner {
    /// Runs and times a single operation whose constant-timeness is in question.
    ///
    /// The closure's result is passed through [`black_box`] so the optimizer cannot delete the work
    /// being measured.
    pub fn run_one<T, F>(&mut self, class: Class, f: F)
    where
        F: Fn() -> T,
    {
        let start = Instant::now();
        black_box(f());
        let end = Instant::now();

        let runtime = {
            let dur = end.duration_since(start);
            dur.as_secs() * 1_000_000_000 + u64::from(dur.subsec_nanos())
        };

        self.push(class, runtime);
    }

    /// Records a raw nanosecond sample without timing anything. Used by [`self_check`].
    fn push(&mut self, class: Class, nanos: u64) {
        match class {
            Class::Left => self.runtimes.0.push(nanos),
            Class::Right => self.runtimes.1.push(nanos),
        }
    }

    /// Runs the t-test battery over every sample collected so far.
    ///
    /// # Panics
    ///
    /// Panics if no samples were recorded.
    #[must_use]
    pub fn summarize(&self) -> CtSummary {
        summarize(&self.runtimes)
    }
}

/// The result of one dudect run: the largest Welch t-statistic found across all crop thresholds.
///
/// The convention used in this repository is **`max_t` > 5 ⇒ likely leak**. A small `max_t` is
/// *not* proof of constant-timeness — dudect detects leaks, it never rules them out.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct CtSummary {
    /// Largest t-statistic (signed) over the uncropped and percentile-cropped tests.
    pub max_t: f64,
    /// `max_t` normalized by sample count, so runs of different lengths stay comparable.
    pub max_tau: f64,
    /// Number of samples backing the test that produced `max_t`.
    pub sample_size: usize,
}

impl fmt::Display for CtSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "n == {:+0.3}M, max t = {:+0.5}, max tau = {:+0.5}, (5/tau)^2 = {}",
            (self.sample_size as f64) / 1_000_000f64,
            self.max_t,
            self.max_tau,
            (5f64 / self.max_tau).powi(2) as usize
        )
    }
}

/// One running Welch t-test: online means, sums of squared differences, and counts per class.
#[derive(Copy, Clone, Debug, Default)]
struct CtTest {
    means: (f64, f64),
    sq_diffs: (f64, f64),
    sizes: (usize, usize),
}

/// Orders floats for `max_by`, treating NaN as smaller than everything.
fn local_cmp(x: f64, y: f64) -> Ordering {
    if y.is_nan() {
        Ordering::Greater
    } else if x.is_nan() || x < y {
        Ordering::Less
    } else if x == y {
        Ordering::Equal
    } else {
        Ordering::Greater
    }
}

/// Extracts the `pct` percentile of a sorted sample set by linear interpolation.
///
/// Returns a nonsensical value if the samples are not sorted.
fn percentile_of_sorted(sorted_samples: &[f64], pct: f64) -> f64 {
    assert!(!sorted_samples.is_empty());
    if sorted_samples.len() == 1 {
        return sorted_samples[0];
    }
    assert!((0f64..=100f64).contains(&pct));
    let length = (sorted_samples.len() - 1) as f64;
    let rank = (pct / 100f64) * length;
    let lrank = rank.floor();
    let d = rank - lrank;
    let n = lrank as usize;
    let lo = sorted_samples[n];
    let hi = sorted_samples[n + 1];
    lo + (hi - lo) * d
}

/// Returns the percentiles at `f(1), f(2), …, f(100)` of the runtime distribution, where
/// `f(k) = 1 - 0.5^(10k / 100)`.
///
/// These are the crop thresholds: dudect re-runs the t-test on the samples below each one, because
/// a leak is often visible only in the fast tail once the slow environmental outliers are removed.
fn prepare_percentiles(durations: &[u64]) -> Vec<f64> {
    let sorted: Vec<f64> = {
        let mut v = durations.to_vec();
        v.sort_unstable();
        v.into_iter().map(|d| d as f64).collect()
    };

    (0..100)
        .map(|i| {
            let pct = {
                let exp = f64::from(10 * (i + 1)) / 100f64;
                1f64 - 0.5f64.powf(exp)
            };
            percentile_of_sorted(&sorted, 100f64 * pct)
        })
        .collect()
}

/// Runs the uncropped test plus the 100 percentile-cropped tests and returns the largest `|t|`.
fn summarize((left_samples, right_samples): &(Vec<u64>, Vec<u64>)) -> CtSummary {
    let all_samples = {
        let mut v = left_samples.clone();
        v.extend_from_slice(right_samples);
        v
    };
    let percentiles = prepare_percentiles(&all_samples);
    let mut tests = vec![CtTest::default(); 101];

    let left_samples: Vec<f64> = left_samples.iter().map(|&n| n as f64).collect();
    let right_samples: Vec<f64> = right_samples.iter().map(|&n| n as f64).collect();

    // tests[0] is the uncropped test over every sample.
    for &left_sample in &left_samples {
        update_test_left(&mut tests[0], left_sample);
    }
    for &right_sample in &right_samples {
        update_test_right(&mut tests[0], right_sample);
    }

    // tests[1..=100] each drop the samples at or above one crop threshold.
    for (test, &pct) in tests.iter_mut().skip(1).zip(percentiles.iter()) {
        for &left_sample in left_samples.iter().filter(|&&x| x < pct) {
            update_test_left(test, left_sample);
        }
        for &right_sample in right_samples.iter().filter(|&&x| x < pct) {
            update_test_right(test, right_sample);
        }
    }

    let max_test = tests
        .iter()
        .max_by(|&x, &y| local_cmp(compute_t(x).abs(), compute_t(y).abs()))
        .expect("tests is never empty");
    let sample_size = max_test.sizes.0 + max_test.sizes.1;
    let max_t = compute_t(max_test);
    let max_tau = max_t / (sample_size as f64).sqrt();

    CtSummary {
        max_t,
        max_tau,
        sample_size,
    }
}

/// Welch's t-statistic for one test's two accumulated classes.
fn compute_t(test: &CtTest) -> f64 {
    let &CtTest {
        means,
        sq_diffs,
        sizes,
    } = test;
    let num = means.0 - means.1;
    let n0 = sizes.0 as f64;
    let n1 = sizes.1 as f64;
    let var0 = sq_diffs.0 / (n0 - 1f64);
    let var1 = sq_diffs.1 / (n1 - 1f64);
    let den = (var0 / n0 + var1 / n1).sqrt();

    num / den
}

/// Folds one left-class sample into a test using Welford's online mean/variance update.
fn update_test_left(test: &mut CtTest, datum: f64) {
    test.sizes.0 += 1;
    let diff = datum - test.means.0;
    test.means.0 += diff / (test.sizes.0 as f64);
    test.sq_diffs.0 += diff * (datum - test.means.0);
}

/// Folds one right-class sample into a test using Welford's online mean/variance update.
fn update_test_right(test: &mut CtTest, datum: f64) {
    test.sizes.1 += 1;
    let diff = datum - test.means.1;
    test.means.1 += diff / (test.sizes.1 as f64);
    test.sq_diffs.1 += diff * (datum - test.means.1);
}

/// Positive control for the detector itself, run before every bench.
///
/// A leak detector that can never report a leak is worthless, and a silently broken t-test would
/// look exactly like a clean result. So this feeds the same code path two *synthetic* sample sets
/// built from a fixed seed — one where both classes share a distribution, one where the right class
/// is shifted by 20ns — and requires the null case to stay under the `max_t` > 5 threshold and the
/// shifted case to blow past it. No timing is involved, so the outcome is deterministic.
///
/// # Panics
///
/// Panics if the detector fails to separate the two synthetic cases, which means every `max_t`
/// printed by this binary is untrustworthy.
pub fn self_check() {
    /// Samples per class in each synthetic set.
    const N: usize = 20_000;
    /// Deterministic jitter width, in nanoseconds, applied to both classes.
    const JITTER: u64 = 10;
    /// Nanoseconds added to the right class in the leaky case.
    const LEAK_NS: u64 = 20;

    // A tiny xorshift keeps the control free of any RNG dependency or version skew.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut jitter = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % JITTER
    };

    let mut null = CtRunner::default();
    let mut leaky = CtRunner::default();
    for _ in 0..N {
        let base = 100;
        null.push(Class::Left, base + jitter());
        null.push(Class::Right, base + jitter());
        leaky.push(Class::Left, base + jitter());
        leaky.push(Class::Right, base + LEAK_NS + jitter());
    }

    let null_t = null.summarize().max_t;
    let leaky_t = leaky.summarize().max_t;

    assert!(
        null_t.abs() < 5f64,
        "dudect self-check: detector reported a leak ({null_t:+.5}) on two identical synthetic \
         distributions, so its results here cannot be trusted"
    );
    assert!(
        leaky_t.abs() > 5f64,
        "dudect self-check: detector missed a deliberate {LEAK_NS}ns leak ({leaky_t:+.5}), so a \
         small max_t below would mean nothing"
    );

    println!(
        "self-check ... ok (null max t = {null_t:+.5}, injected-{LEAK_NS}ns max t = {leaky_t:+.5})"
    );
}
