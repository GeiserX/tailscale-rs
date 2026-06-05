#![doc = include_str!("../README.md")]

//! # Overview
//!
//! This crate is a small, dependency-free reimplementation of Go Tailscale's
//! `util/clientmetric`: a process-global registry of named counters and gauges that hot-path code
//! increments cheaply (a single relaxed atomic add), plus a [`write_prometheus`] exporter that
//! renders the whole registry in Prometheus text exposition format.
//!
//! A [`Metric`] is created once (typically in a `static`) via [`Metric::new_counter`] /
//! [`Metric::new_gauge`] and registered into the global registry at first use. Increment with
//! [`Metric::add`] (counters/gauges) or set an absolute value with [`Metric::set`] (gauges). The
//! exporter walks the registry in name-sorted order and emits, per metric:
//!
//! ```text
//! # TYPE <name> counter
//! <name> <value>
//! ```
//!
//! matching `clientmetric.WritePrometheusExpositionFormat`. Metric names are restricted to
//! `[A-Za-z0-9_]` (Go's `isIllegalMetricRune`); an invalid name panics at construction, since names
//! are compile-time constants.

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Whether a [`Metric`] is a monotonically-increasing counter or a free-moving gauge. Mirrors Go
/// `clientmetric.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    /// A value that only ever increases (e.g. packets sent).
    Counter,
    /// A value that may rise and fall (e.g. current peer count).
    Gauge,
}

impl MetricType {
    /// The Prometheus `# TYPE` token for this kind.
    fn prometheus_token(self) -> &'static str {
        match self {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
        }
    }
}

/// A single named metric: a name, a type, and an atomic value. Created once (usually in a `static`)
/// and registered into the process-global registry on construction.
///
/// Mirrors Go `clientmetric.Metric`. The value is an `i64` semantically (Go uses `int64`); it is
/// stored as an [`AtomicU64`] and reinterpreted, so a gauge may go negative.
#[derive(Debug)]
pub struct Metric {
    name: &'static str,
    typ: MetricType,
    value: AtomicU64,
}

impl Metric {
    /// Create and register a counter named `name`. `name` must match `[A-Za-z0-9_]+`.
    ///
    /// # Panics
    /// Panics if `name` is empty or contains a character outside `[A-Za-z0-9_]` (matching Go's
    /// `isIllegalMetricRune`). Names are constants, so this fails fast at startup, never in prod.
    pub fn new_counter(name: &'static str) -> &'static Metric {
        Self::register(name, MetricType::Counter)
    }

    /// Create and register a gauge named `name`. Same name rules as [`Metric::new_counter`].
    pub fn new_gauge(name: &'static str) -> &'static Metric {
        Self::register(name, MetricType::Gauge)
    }

    fn register(name: &'static str, typ: MetricType) -> &'static Metric {
        assert!(is_valid_name(name), "illegal metric name: {name:?}");
        registry().register(name, typ)
    }

    /// The metric's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The metric's type.
    pub fn metric_type(&self) -> MetricType {
        self.typ
    }

    /// Add `n` to the metric's value (wrapping, like an `int64` add). For a counter `n` is normally
    /// positive; a gauge may take a negative `n` to decrement.
    pub fn add(&self, n: i64) {
        self.value.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Increment a counter/gauge by 1.
    pub fn inc(&self) {
        self.add(1);
    }

    /// Set the metric's absolute value (mainly for gauges).
    pub fn set(&self, v: i64) {
        self.value.store(v as u64, Ordering::Relaxed);
    }

    /// The current value, reinterpreted as a signed `i64`.
    pub fn value(&self) -> i64 {
        self.value.load(Ordering::Relaxed) as i64
    }
}

/// The process-global metric registry. Holds `&'static Metric`s; metrics live for the process.
struct Registry {
    metrics: Mutex<Vec<&'static Metric>>,
}

impl Registry {
    fn register(&self, name: &'static str, typ: MetricType) -> &'static Metric {
        let mut metrics = self.metrics.lock().unwrap();
        // A duplicate name is a programming error; in Go it panics. Return the existing one instead
        // of leaking a second — but assert in debug to surface the mistake.
        if let Some(existing) = metrics.iter().find(|m| m.name == name) {
            debug_assert!(false, "duplicate metric registered: {name:?}");
            return existing;
        }
        let metric: &'static Metric = Box::leak(Box::new(Metric {
            name,
            typ,
            value: AtomicU64::new(0),
        }));
        metrics.push(metric);
        metric
    }

    /// Snapshot the registered metrics, sorted by name (stable, deterministic export order).
    fn snapshot(&self) -> Vec<&'static Metric> {
        let mut v = self.metrics.lock().unwrap().clone();
        v.sort_by_key(|m| m.name);
        v
    }
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        metrics: Mutex::new(Vec::new()),
    })
}

/// Validate a metric name against Go's `isIllegalMetricRune`: non-empty, only ASCII letters,
/// digits, and underscore.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Render every registered metric in Prometheus text exposition format, sorted by name. Mirrors Go
/// `clientmetric.WritePrometheusExpositionFormat`: per metric a `# TYPE <name> <kind>` line followed
/// by a `<name> <value>` line.
pub fn write_prometheus() -> String {
    let mut out = String::new();
    for m in registry().snapshot() {
        out.push_str("# TYPE ");
        out.push_str(m.name);
        out.push(' ');
        out.push_str(m.typ.prometheus_token());
        out.push('\n');
        out.push_str(m.name);
        out.push(' ');
        out.push_str(&m.value().to_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_add_and_export() {
        let c = Metric::new_counter("ts_metrics_test_counter_a");
        assert_eq!(c.value(), 0);
        c.add(3);
        c.inc();
        assert_eq!(c.value(), 4);

        let out = write_prometheus();
        assert!(out.contains("# TYPE ts_metrics_test_counter_a counter\n"));
        assert!(out.contains("ts_metrics_test_counter_a 4\n"));
    }

    #[test]
    fn gauge_set_and_negative() {
        let g = Metric::new_gauge("ts_metrics_test_gauge_b");
        g.set(10);
        assert_eq!(g.value(), 10);
        g.add(-4);
        assert_eq!(g.value(), 6);

        let out = write_prometheus();
        assert!(out.contains("# TYPE ts_metrics_test_gauge_b gauge\n"));
        assert!(out.contains("ts_metrics_test_gauge_b 6\n"));
    }

    #[test]
    fn export_is_name_sorted() {
        // Register out of alphabetical order; export must be sorted.
        let _z = Metric::new_counter("ts_metrics_test_zzz");
        let _a = Metric::new_counter("ts_metrics_test_aaa");
        let out = write_prometheus();
        let zpos = out.find("ts_metrics_test_zzz 0").unwrap();
        let apos = out.find("ts_metrics_test_aaa 0").unwrap();
        assert!(apos < zpos, "aaa must sort before zzz in the export");
    }

    #[test]
    fn name_validation() {
        assert!(is_valid_name("magicsock_send_udp"));
        assert!(is_valid_name("a1_B2"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("has space"));
        assert!(!is_valid_name("has-dash"));
        assert!(!is_valid_name("has/slash"));
        assert!(!is_valid_name("dot.name"));
    }

    #[test]
    #[should_panic(expected = "illegal metric name")]
    fn illegal_name_panics() {
        let _ = Metric::new_counter("bad name with spaces");
    }
}
