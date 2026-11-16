//! A `tracing` layer writing each event as the crate's one JSON line, for the hosts
//! that log through `tracing` (server, console, modeld). The event's message becomes
//! `event`, its target `target`, and its fields the line's fields; spans are not
//! recorded. Filtering stays the host's (`RUST_LOG`, modeld's fixed filter).

use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value as Json};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::{Level, Service, Sink, Stderr, line};

/// The layer.
#[derive(Debug, Clone)]
pub struct JsonLayer {
    service: Service,
    sink: Arc<dyn Sink>,
}

impl JsonLayer {
    /// Lines for `service` on standard error.
    #[must_use]
    pub fn stderr(service: Service) -> Self {
        Self::new(service, Arc::new(Stderr))
    }

    /// Lines for `service` into `sink`.
    #[must_use]
    pub fn new(service: Service, sink: Arc<dyn Sink>) -> Self {
        Self { service, sink }
    }
}

#[derive(Default)]
struct Fields(Map<String, Json>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().to_owned(), Json::String(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0
            .insert(field.name().to_owned(), Json::String(value.to_owned()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), Json::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), Json::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), Json::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().to_owned(), Json::from(value));
    }
}

impl<S: Subscriber> Layer<S> for JsonLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut f = Fields::default();
        event.record(&mut f);
        let message = match f.0.remove("message") {
            Some(Json::String(s)) => s,
            Some(other) => other.to_string(),
            None => meta.name().to_owned(),
        };
        let level = match *meta.level() {
            tracing::Level::ERROR => Level::Error,
            tracing::Level::WARN => Level::Warn,
            tracing::Level::INFO => Level::Info,
            _ => Level::Debug,
        };
        let mut m = Map::new();
        m.insert("target".into(), Json::from(meta.target()));
        m.extend(f.0);
        self.sink
            .write_line(&line(self.service, level, &message, m));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::Memory;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn a_tracing_event_becomes_one_json_line() {
        let m = Memory::new();
        let sub = tracing_subscriber::registry()
            .with(JsonLayer::new(Service::Console, Arc::new(m.clone())));
        tracing::subscriber::with_default(sub, || {
            tracing::info!(request_id = "r-1", status = 403_u64, "request");
        });
        let j = m.json();
        assert_eq!(j.len(), 1);
        assert_eq!(j[0]["service"], "console");
        assert_eq!(j[0]["level"], "INFO");
        assert_eq!(j[0]["event"], "request");
        assert_eq!(j[0]["status"], 403);
        assert_eq!(j[0]["request_id"], "r-1");
    }
}
