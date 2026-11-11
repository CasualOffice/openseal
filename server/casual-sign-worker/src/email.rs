//! Email: messages written here, sent over SMTP with `lettre` (rustls on aws-lc-rs).
//!
//! **Header injection (`SEC-M02`).** Every header value is either checked against a
//! strict grammar (addresses, the Message-ID) or RFC 2047 B-encoded (names, subjects),
//! and the body is base64: no byte a recipient, sender or subject supplies can end a
//! header or start a new one. Templates fix the content (`SEC-M01`); a recipient's name,
//! the sender's message and the envelope's subject are the only supplied text, and no
//! document content is ever in a message.
//!
//! **Idempotency.** A message's `Message-ID` is derived from the job and the recipient,
//! so the at-least-once window (the SMTP server accepted, the worker died before
//! recording it) produces a second copy with the same `Message-ID`, which receiving
//! systems collapse.
//!
//! Nothing here logs an address, a name or a subject.

use std::time::Duration;

use base64::Engine as _;
use lettre::address::Envelope;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Address, AsyncTransport, Tokio1Executor};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;

use crate::error::{Result, WorkerError};

/// Longest address accepted (RFC 5321 §4.5.3.1: 64 + 1 + 255).
pub const MAX_ADDRESS: usize = 320;
/// Longest display name or subject accepted, in bytes, before encoding.
pub const MAX_PHRASE: usize = 998;
/// Longest body accepted, in bytes, before encoding.
pub const MAX_BODY: usize = 256 * 1024;

/// One message, before it is written.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    /// The sender's address (the platform's, from configuration).
    pub from: String,
    /// The sender's display name.
    pub from_name: String,
    /// The recipient's address (personal data).
    pub to: String,
    /// The recipient's display name (personal data).
    pub to_name: String,
    /// The subject (may hold personal data).
    pub subject: String,
    /// The plain-text body (may hold personal data).
    pub body: String,
    /// `<local@domain>`, derived from the job.
    pub message_id: String,
    /// The `Date` header.
    pub date: OffsetDateTime,
}

impl core::fmt::Debug for Message {
    /// The Message-ID only: everything else may be personal data (`SEC-D01`).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Message")
            .field("message_id", &self.message_id)
            .finish_non_exhaustive()
    }
}

/// An address the SMTP envelope and the header can both carry: printable ASCII, no
/// whitespace, quotes, angle brackets, commas or semicolons, one `@`, and what `lettre`
/// parses.
///
/// # Errors
///
/// `CS-WRK-0005` naming `field`.
pub fn address(text: &str, field: &'static str) -> Result<Address> {
    let bad = WorkerError::BadHeader { field };
    if text.is_empty()
        || text.len() > MAX_ADDRESS
        || !text.bytes().all(|b| b.is_ascii_graphic())
        || text
            .bytes()
            .any(|b| matches!(b, b'"' | b'<' | b'>' | b',' | b';' | b'(' | b')' | b'\\'))
        || text.bytes().filter(|b| *b == b'@').count() != 1
    {
        return Err(bad);
    }
    text.parse::<Address>().map_err(|_| bad)
}

/// RFC 2047 B-encoded words for `text`, each at most 75 characters, joined by folding
/// whitespace. Characters are never split across words.
///
/// # Errors
///
/// `CS-WRK-0005` naming `field` for text over [`MAX_PHRASE`] bytes.
pub fn encoded_words(text: &str, field: &'static str) -> Result<String> {
    if text.len() > MAX_PHRASE {
        return Err(WorkerError::BadHeader { field });
    }
    // 75 − len("=?UTF-8?B?") − len("?=") = 63 characters of base64: 45 bytes of text.
    const CHUNK: usize = 45;
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if current.len().saturating_add(ch.len_utf8()) > CHUNK {
            words.push(core::mem::take(&mut current));
        }
        current.push(ch);
    }
    if !current.is_empty() || words.is_empty() {
        words.push(current);
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(words
        .iter()
        .map(|w| format!("=?UTF-8?B?{}?=", b64.encode(w.as_bytes())))
        .collect::<Vec<_>>()
        .join("\r\n "))
}

/// A Message-ID's local part and domain: `[A-Za-z0-9.-]` only.
fn message_id_ok(id: &str) -> bool {
    let Some(inner) = id.strip_prefix('<').and_then(|s| s.strip_suffix('>')) else {
        return false;
    };
    let mut parts = inner.split('@');
    let (Some(l), Some(d), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    };
    ok(l) && ok(d)
}

impl Message {
    /// The SMTP envelope and the RFC 5322 bytes.
    ///
    /// # Errors
    ///
    /// `CS-WRK-0005` for an address, name, subject or Message-ID that is refused, or a
    /// body over [`MAX_BODY`].
    pub fn write(&self) -> Result<(Envelope, Vec<u8>)> {
        let from = address(&self.from, "from")?;
        let to = address(&self.to, "to")?;
        if !message_id_ok(&self.message_id) {
            return Err(WorkerError::BadHeader {
                field: "message_id",
            });
        }
        if self.body.len() > MAX_BODY {
            return Err(WorkerError::BadHeader { field: "body" });
        }
        let date = self
            .date
            .format(&Rfc2822)
            .map_err(|_| WorkerError::BadHeader { field: "date" })?;
        let mailbox = |name: &str, addr: &Address, field| -> Result<String> {
            if name.is_empty() {
                Ok(format!("<{addr}>"))
            } else {
                Ok(format!("{} <{addr}>", encoded_words(name, field)?))
            }
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let encoded = b64.encode(self.body.as_bytes());
        let mut out = String::with_capacity(encoded.len().saturating_add(1024));
        out.push_str(&format!("Date: {date}\r\n"));
        out.push_str(&format!(
            "From: {}\r\n",
            mailbox(&self.from_name, &from, "from_name")?
        ));
        out.push_str(&format!("To: {}\r\n", mailbox(&self.to_name, &to, "name")?));
        out.push_str(&format!(
            "Subject: {}\r\n",
            encoded_words(&self.subject, "subject")?
        ));
        out.push_str(&format!("Message-ID: {}\r\n", self.message_id));
        out.push_str("MIME-Version: 1.0\r\n");
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        out.push_str("Content-Transfer-Encoding: base64\r\n");
        out.push_str("Auto-Submitted: auto-generated\r\n");
        out.push_str("\r\n");
        let bytes = encoded.as_bytes();
        for line in bytes.chunks(76) {
            out.push_str(core::str::from_utf8(line).unwrap_or_default());
            out.push_str("\r\n");
        }
        let envelope = Envelope::new(Some(from), vec![to])
            .map_err(|_| WorkerError::BadHeader { field: "to" })?;
        Ok((envelope, out.into_bytes()))
    }
}

/// How the SMTP connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SmtpSecurity {
    /// TLS from the first byte (port 465).
    Implicit,
    /// STARTTLS, required (port 587).
    StartTls,
    /// No TLS: a local relay or a test sink only. Refused unless configured explicitly.
    Plain,
}

/// The SMTP server.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// Host name (checked against its certificate).
    pub host: String,
    /// Port.
    pub port: u16,
    /// Security.
    pub security: SmtpSecurity,
    /// User name and password, when the relay needs them.
    pub credentials: Option<(String, casual_sign_secrets::Secret)>,
    /// The name this client greets with (EHLO).
    pub hello_name: String,
    /// Connect and command timeout.
    pub timeout: Duration,
}

/// What a send came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// The server accepted the message.
    Accepted,
    /// The server refused the recipient permanently (5xx): a bounce.
    Bounced,
}

/// An SMTP mailer.
#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl core::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mailer").finish_non_exhaustive()
    }
}

impl Mailer {
    /// A mailer for `config`.
    ///
    /// # Errors
    ///
    /// `CS-WRK-0001` when the TLS settings do not build.
    pub fn new(config: &SmtpConfig) -> Result<Self> {
        let bad = |setting| WorkerError::Config { setting };
        let tls = || {
            TlsParameters::builder(config.host.clone())
                .build_rustls()
                .map_err(|_| bad("smtp.tls"))
        };
        let builder = match config.security {
            SmtpSecurity::Implicit => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                    .tls(Tls::Wrapper(tls()?))
            }
            SmtpSecurity::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                    .tls(Tls::Required(tls()?))
            }
            SmtpSecurity::Plain => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host).tls(Tls::None)
            }
        };
        let mut builder = builder
            .port(config.port)
            .hello_name(ClientId::Domain(config.hello_name.clone()))
            .timeout(Some(config.timeout));
        if let Some((user, secret)) = &config.credentials {
            builder =
                builder.credentials(Credentials::new(user.clone(), secret.expose().to_owned()));
        }
        Ok(Self {
            transport: builder.build(),
        })
    }

    /// Send one message.
    ///
    /// # Errors
    ///
    /// `CS-WRK-0005` for a message that cannot be written; `CS-WRK-0006` when the
    /// server is unreachable or refuses for now.
    pub async fn send(&self, message: &Message) -> Result<Sent> {
        let (envelope, bytes) = message.write()?;
        match self.transport.send_raw(&envelope, &bytes).await {
            Ok(_) => Ok(Sent::Accepted),
            Err(e) if e.is_permanent() => Ok(Sent::Bounced),
            Err(_) => Err(WorkerError::SmtpTransient),
        }
    }
}

/// Which template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Template {
    /// Please sign (or act on) the documents.
    Invitation,
    /// A copy for your records (carbon copy).
    CopyInvitation,
    /// A reminder.
    Reminder,
    /// The envelope expires soon.
    ExpiryWarning,
    /// The completed documents are ready.
    Completed,
    /// The envelope was voided.
    Voided,
    /// A recipient declined.
    Declined,
    /// The envelope expired.
    Expired,
    /// A recipient is locked after failed authentication.
    AuthLocked,
    /// An invitation bounced.
    Bounced,
    /// An administrator invited a user to an account (WEB-06); `subject` is the
    /// account's name and the link sets a password once.
    UserInvitation,
    /// A correction changed what this recipient must do.
    Corrected,
    /// A recipient's email one-time code (SEC-A02): `link` carries the code.
    EmailOtp,
}

/// What fills a template: the only supplied text.
#[derive(Debug, Clone)]
pub struct Fill<'a> {
    /// The reader's name (personal data).
    pub name: &'a str,
    /// The envelope's subject (may hold personal data).
    pub subject: &'a str,
    /// The sender's message (personal data), for invitations.
    pub message: &'a str,
    /// The signing or download link, when the message carries one.
    pub link: Option<&'a str>,
    /// The operator's product name.
    pub product: &'a str,
    /// The operator's abuse-report address or page (`SEC-M01`).
    pub abuse: &'a str,
}

/// The subject and body of `template` (English; localisation is slice 27).
#[must_use]
pub fn render(template: Template, f: &Fill<'_>) -> (String, String) {
    let (subject, lead) = match template {
        Template::Invitation => (
            format!("Please review and sign: {}", f.subject),
            "You have been sent documents to review and sign.",
        ),
        Template::CopyInvitation => (
            format!("For your records: {}", f.subject),
            "You have been sent a copy of these documents for your records.",
        ),
        Template::Reminder => (
            format!("Reminder: {}", f.subject),
            "This is a reminder that documents are waiting for you.",
        ),
        Template::ExpiryWarning => (
            format!("Expires soon: {}", f.subject),
            "These documents expire soon. Please complete them before they do.",
        ),
        Template::Completed => (
            format!("Completed: {}", f.subject),
            "All parties have completed these documents. The sealed documents and the certificate of completion are available at the link below.",
        ),
        Template::Voided => (
            format!("Voided: {}", f.subject),
            "The sender voided these documents. No further action is needed.",
        ),
        Template::Declined => (
            format!("Declined: {}", f.subject),
            "A recipient declined to sign these documents.",
        ),
        Template::Expired => (
            format!("Expired: {}", f.subject),
            "These documents expired before every recipient completed them.",
        ),
        Template::AuthLocked => (
            format!("Recipient locked: {}", f.subject),
            "A recipient failed authentication too many times and is locked until the documents are re-sent.",
        ),
        Template::Bounced => (
            format!("Delivery failed: {}", f.subject),
            "An invitation could not be delivered. Check the recipient's address and correct it.",
        ),
        Template::Corrected => (
            format!("Corrected: {}", f.subject),
            "The sender corrected these documents. Please review them again.",
        ),
        Template::UserInvitation => (
            format!("You are invited to {} on {}", f.subject, f.product),
            "An administrator added you to this account. Set your password with the link below. It works once and expires in 7 days; if it has expired, ask the administrator to send it again.",
        ),
        Template::EmailOtp => (
            format!("Your verification code: {}", f.subject),
            "Enter this code on the signing page to open the documents. It works once and expires in 10 minutes. If you did not ask for it, ignore this email.",
        ),
    };
    let mut body = String::new();
    if !f.name.is_empty() {
        body.push_str(&format!("Hello {},\n\n", f.name));
    }
    body.push_str(lead);
    body.push_str("\n\n");
    if !f.message.is_empty() {
        body.push_str("Message from the sender:\n");
        body.push_str(f.message);
        body.push_str("\n\n");
    }
    if let Some(link) = f.link {
        if template == Template::EmailOtp {
            body.push_str("Your code: ");
        }
        body.push_str(link);
        body.push_str("\n\n");
    }
    let warning = if template == Template::EmailOtp {
        "Do not share this code: it opens the documents"
    } else {
        "Do not share this email: its link gives access to the documents"
    };
    body.push_str(&format!(
        "This message was sent by {}. {warning}.\nReport abuse: {}\n",
        f.product, f.abuse
    ));
    (subject, body)
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn msg() -> Message {
        Message {
            from: "no-reply@example.test".into(),
            from_name: "OpenSeal".into(),
            to: "ada@example.test".into(),
            to_name: "Ada".into(),
            subject: "Please sign".into(),
            body: "Hello".into(),
            message_id: "<job.1@example.test>".into(),
            date: OffsetDateTime::from_unix_timestamp(1_794_302_043).unwrap(),
        }
    }

    #[test]
    fn supplied_text_cannot_inject_headers() {
        let mut m = msg();
        m.to_name = "Ada\r\nBcc: victim@example.test".into();
        m.subject = "Hi\r\nX-Evil: 1\nContent-Type: text/html".into();
        m.body = "body\r\n.\r\nMAIL FROM:<x@y>".into();
        let (_, bytes) = m.write().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let (head, _) = text.split_once("\r\n\r\n").unwrap();
        for line in head.split("\r\n") {
            let name = line.split(':').next().unwrap();
            assert!(
                line.starts_with(' ')
                    || [
                        "Date",
                        "From",
                        "To",
                        "Subject",
                        "Message-ID",
                        "MIME-Version",
                        "Content-Type",
                        "Content-Transfer-Encoding",
                        "Auto-Submitted"
                    ]
                    .contains(&name),
                "unexpected header line {line:?}"
            );
        }
        assert!(!text.contains("Bcc"));
        assert!(!text.contains("X-Evil"));
    }

    #[test]
    fn bad_addresses_are_refused() {
        for a in [
            "",
            "no-at",
            "two@@x",
            "a b@x",
            "a@x\r\nBcc: b@y",
            "\"q\"@x",
            "<a@x>",
            "a@x,b@y",
        ] {
            let mut m = msg();
            m.to = a.into();
            assert_eq!(m.write().unwrap_err().code(), "CS-WRK-0005", "{a:?}");
        }
        let mut m = msg();
        m.message_id = "<a@b>\r\nX: y".into();
        assert_eq!(m.write().unwrap_err().code(), "CS-WRK-0005");
    }

    #[test]
    fn long_and_non_ascii_phrases_are_encoded_in_short_words() {
        let s = "Ünïcödé ".repeat(40);
        let w = encoded_words(&s, "subject").unwrap();
        for word in w.split("\r\n ") {
            assert!(word.len() <= 75, "{word}");
            assert!(word.starts_with("=?UTF-8?B?") && word.ends_with("?="));
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let back: String = w
            .split("\r\n ")
            .map(|x| String::from_utf8(b64.decode(&x[10..x.len() - 2]).unwrap()).unwrap())
            .collect();
        assert_eq!(back, s);
        assert!(encoded_words(&"x".repeat(MAX_PHRASE + 1), "subject").is_err());
    }
}
