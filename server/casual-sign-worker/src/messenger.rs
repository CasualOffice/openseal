//! SMS and voice messages (slice 5, VS-05): the `Messenger` seam of docs/02 §Providers.
//!
//! The worker sends one-time codes by SMS (`sms_otp`) and speaks them in a voice call
//! (`voice_otp`) through a [`Messenger`]. Without one configured, such a job fails
//! `CS-WRK-0013` (no provider for the channel), as before slice 5.
//!
//! The one provider built in is [`HttpGateway`]: a JSON `POST` to an operator's HTTPS
//! gateway with a bearer secret, which any SMS or voice service (or the operator's own
//! relay to Twilio, Vonage or MessageBird) can sit behind. Provider-specific adapters
//! are row `MSG-01`.
//!
//! **Personal data (`SEC-D01`).** A [`Text`]'s number and body never reach a log, an
//! error or a `Debug` string; the body of a code message holds the code, which lives
//! only in the job function that drew it and in the message.

use std::sync::Arc;
use std::time::Duration;

use crate::error::{Result, WorkerError};

/// How a [`Text`] reaches its recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextChannel {
    /// A text message.
    Sms,
    /// A voice call that reads the body aloud.
    Voice,
}

impl TextChannel {
    /// The name on the wire: `sms` or `voice`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sms => "sms",
            Self::Voice => "voice",
        }
    }
}

/// One message to one phone number.
#[derive(Clone, PartialEq, Eq)]
pub struct Text {
    /// By SMS or voice call.
    pub channel: TextChannel,
    /// The number, E.164 (personal data).
    pub to: String,
    /// What the message says or the call reads (holds the code).
    pub body: String,
    /// A stable id derived from the job, so a provider that deduplicates can.
    pub id: String,
}

impl core::fmt::Debug for Text {
    /// The channel and id only: the number and the body are personal data or secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Text")
            .field("channel", &self.channel)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Sends SMS and voice messages. Blocking; the worker calls it on the blocking pool.
pub trait Messenger: Send + Sync + core::fmt::Debug {
    /// Send `text`.
    ///
    /// # Errors
    ///
    /// `CS-WRK-0017` when the provider does not accept it; `CS-WRK-0013` when this
    /// messenger has no route for the text's channel.
    fn send(&self, text: &Text) -> Result<()>;
}

/// The longest body sent: one code message, with room for the product's name.
pub const MAX_TEXT: usize = 480;

/// An operator's HTTPS gateway: `POST {url}` with
/// `{"channel": "sms"|"voice", "to": "+…", "text": "…", "id": "…"}` and
/// `Authorization: Bearer {secret}`; any 2xx is accepted, anything else fails.
pub struct HttpGateway {
    agent: ureq::Agent,
    url: String,
    secret: casual_sign_secrets::Secret,
}

impl core::fmt::Debug for HttpGateway {
    /// Never the secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpGateway").finish_non_exhaustive()
    }
}

impl HttpGateway {
    /// A gateway at `url` (HTTPS only), authenticated by `secret`.
    ///
    /// # Errors
    ///
    /// `CS-WRK-0001` (setting `OPENSEAL_SMS_GATEWAY_URL`) when `url` is not HTTPS.
    pub fn new(url: &str, secret: casual_sign_secrets::Secret) -> Result<Self> {
        if !url.starts_with("https://") {
            return Err(WorkerError::Config {
                setting: "OPENSEAL_SMS_GATEWAY_URL",
            });
        }
        let native = rustls_native_certs::load_native_certs();
        let roots: Vec<ureq::tls::Certificate<'static>> = native
            .certs
            .iter()
            .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
            .collect();
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
            .unversioned_rustls_crypto_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .build();
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(Duration::from_secs(15)))
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent("openseal-worker")
            .build()
            .into();
        Ok(Self {
            agent,
            url: url.to_owned(),
            secret,
        })
    }
}

impl Messenger for HttpGateway {
    fn send(&self, text: &Text) -> Result<()> {
        let body = serde_json::json!({
            "channel": text.channel.as_str(),
            "to": text.to,
            "text": text.body,
            "id": text.id,
        });
        let bytes =
            serde_json::to_vec(&body).map_err(|_| WorkerError::MessengerFailed { status: None })?;
        let answer = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Authorization", &format!("Bearer {}", self.secret.expose()))
            .send(&bytes[..])
            .map_err(|_| WorkerError::MessengerFailed { status: None })?;
        let status = answer.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(WorkerError::MessengerFailed {
                status: Some(status),
            })
        }
    }
}

/// The text of a one-time code message by `channel`: the code alone, with the product's
/// name, no link and no document content (`SEC-M01`). A voice call reads the digits one
/// by one, twice.
#[must_use]
pub fn code_text(channel: TextChannel, product: &str, code: &str) -> String {
    let product: String = product
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    match channel {
        TextChannel::Sms => format!(
            "{product}: your signing code is {code}. It works for 10 minutes. \
             Never share it."
        ),
        TextChannel::Voice => {
            let spoken = code
                .chars()
                .map(String::from)
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "This is {product}. Your signing code is {spoken}. Again: {spoken}. \
                 It works for 10 minutes."
            )
        }
    }
}

#[cfg(test)]
// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_text_never_shows_its_number_or_body() {
        let t = Text {
            channel: TextChannel::Sms,
            to: "+15550100".into(),
            body: "code 123456".into(),
            id: "j1".into(),
        };
        let d = format!("{t:?}");
        assert!(!d.contains("5550100") && !d.contains("123456"), "{d}");
    }

    #[test]
    fn a_voice_code_is_read_digit_by_digit() {
        let v = code_text(TextChannel::Voice, "OpenSeal", "042917");
        assert!(v.contains("0, 4, 2, 9, 1, 7"), "{v}");
        let s = code_text(TextChannel::Sms, "OpenSeal", "042917");
        assert!(s.contains("042917") && s.len() <= MAX_TEXT, "{s}");
    }

    #[test]
    fn the_gateway_is_https_only() {
        let e = HttpGateway::new(
            "http://gw.example.test/send",
            casual_sign_secrets::Secret::new("s".into()),
        )
        .unwrap_err();
        assert_eq!(e.code(), "CS-WRK-0001");
    }
}
