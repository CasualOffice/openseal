//! modeld's one log subscriber (`SEC-I05`, docs/33 §3.4, review defect 3).
//!
//! `oar-ocr` writes recognised text and boxes to `tracing` at debug level in some of its
//! pipelines, and ONNX Runtime's own log (routed through `ort`'s `tracing` feature) names
//! graph nodes at verbose level. Neither may reach a log. The filter here is fixed in
//! code:
//!
//! - every target is capped at WARN by default, and ONNX Runtime (`ort`) at ERROR;
//! - `RUST_LOG` may only *raise* the level of modeld's own targets
//!   (`casual_sign_modeld*`, or a bare level, which is read as modeld's): a directive for
//!   any other target, `oar_ocr`, `hayro` and `tokenizers` included, is ignored.
//!
//! The scrubber test (`tests/log_scrub.rs`) runs the ops at trace level and fails when a
//! third-party event below the cap, or the page's text, appears in the output.

use std::io::Write;

use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

/// modeld's own target prefix.
const OWN: &str = "casual_sign_modeld";

/// The fixed filter, given the value of `RUST_LOG` (if any).
#[must_use]
pub fn filter(rust_log: Option<&str>) -> Targets {
    let mut own = LevelFilter::WARN;
    let mut own_targets: Vec<(String, LevelFilter)> = Vec::new();
    for directive in rust_log.unwrap_or_default().split(',') {
        let d = directive.trim();
        // An empty directive would parse as a level (ERROR); it is no directive at all.
        if d.is_empty() {
            continue;
        }
        let (target, level) = match d.split_once('=') {
            Some((t, l)) => (Some(t.trim()), l.trim()),
            None => (None, d),
        };
        let Ok(level) = level.parse::<LevelFilter>() else {
            continue;
        };
        match target {
            None => own = level,
            Some(t) if t == OWN || t.starts_with("casual_sign_modeld::") => {
                own_targets.push((t.to_owned(), level));
            }
            // Any other target, third-party ones included, is never raised.
            Some(_) => {}
        }
    }
    let mut targets = Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("ort", LevelFilter::ERROR)
        .with_target(OWN, own);
    for (t, l) in own_targets {
        targets = targets.with_target(t, l);
    }
    targets
}

/// `writer` as the JSON layer's sink: one write per line.
struct WriterSink<W>(W);

impl<W> core::fmt::Debug for WriterSink<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WriterSink")
    }
}

impl<W> casual_sign_seclog::Sink for WriterSink<W>
where
    W: for<'w> MakeWriter<'w> + Send + Sync,
{
    fn write_line(&self, line: &str) {
        let mut buf = Vec::with_capacity(line.len().saturating_add(1));
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        let _ = self.0.make_writer().write_all(&buf);
    }
}

/// A subscriber writing OpenSeal's JSON line (`casual-sign-seclog`, `"service":"modeld"`,
/// ASVS-08) to `writer`, behind the fixed [`filter`].
pub fn subscriber<W>(writer: W, rust_log: Option<&str>) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::registry().with(
        casual_sign_seclog::JsonLayer::new(
            casual_sign_seclog::Service::Modeld,
            std::sync::Arc::new(WriterSink(writer)),
        )
        .with_filter(filter(rust_log)),
    )
}

/// Install the fixed subscriber for the daemon, writing to stderr, with `RUST_LOG` read
/// once. A second call does nothing.
pub fn init() {
    let rust_log = std::env::var("RUST_LOG").ok();
    let _ =
        tracing::subscriber::set_global_default(subscriber(std::io::stderr, rust_log.as_deref()));
    let _ = std::io::stderr().flush();
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tracing::level_filters::LevelFilter as L;

    fn level(t: &Targets, target: &str) -> Option<L> {
        // The most verbose level the filter lets through for `target`.
        [L::TRACE, L::DEBUG, L::INFO, L::WARN, L::ERROR]
            .into_iter()
            .find(|l| t.would_enable(target, &l.into_level().unwrap()))
    }

    #[test]
    fn rust_log_cannot_raise_a_third_party_target() {
        let t = filter(Some(
            "trace,oar_ocr=trace,oar_ocr_core=trace,ort=trace,hayro=debug,tokenizers=trace",
        ));
        assert_eq!(level(&t, "casual_sign_modeld::server"), Some(L::TRACE));
        for third in [
            "oar_ocr",
            "oar_ocr::oarocr::stitching",
            "oar_ocr_core::models",
            "hayro_interpret",
            "tokenizers",
            "image",
        ] {
            assert_eq!(level(&t, third), Some(L::WARN), "{third}");
        }
        assert_eq!(level(&t, "ort"), Some(L::ERROR));
        assert_eq!(level(&t, "ort::session"), Some(L::ERROR));
        // Unset or garbage: modeld at WARN too.
        assert_eq!(level(&filter(None), OWN), Some(L::WARN));
        assert_eq!(level(&filter(Some("loud,=,x=y")), OWN), Some(L::WARN));
        assert_eq!(
            level(
                &filter(Some("casual_sign_modeld::ocr=debug")),
                "casual_sign_modeld::ocr"
            ),
            Some(L::DEBUG)
        );
    }
}
