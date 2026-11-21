//! A bounded XML reader (XML 1.0 subset) for OpenSeal: XFA packets (docs/30 §3,
//! `casual-sign-xfa`) and India eSign answers (ADR-047 §3.5, `casual-sign-esign`).
//!
//! Written here rather than taken from a crate (ADR-026; moved out of `casual-sign-xfa`
//! into its own crate by ADR-047): its consumers need elements, attributes, text, CDATA
//! and the five predefined entities with character references, and the reader must
//! refuse everything else that can make it do unbounded or outside work.
//!
//! - A document type declaration (`<!DOCTYPE`) or entity declaration (`<!ENTITY`) is
//!   refused ([`XmlError::Dtd`]): no external entity is ever resolved, no entity
//!   expands, so neither a billion-laughs nor an XXE input can do anything.
//! - Only `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;` and `&#…;` references are known;
//!   any other is malformed ([`XmlError::Malformed`]).
//! - Element nesting is limited ([`XmlError::TooDeep`]); so are the number of nodes,
//!   of elements and of attributes on one element ([`XmlError::TooManyNodes`]), and the
//!   input's size ([`XmlError::TooLarge`]). The parser is iterative: depth costs no
//!   stack.
//! - Comments are skipped.
//!
//! Every name keeps its local part ([`Node::name`]) as XFA reads it (`xfa:data` is
//! `data`); its prefix, its qualified attributes and the namespace declarations made on
//! it are kept beside ([`Node::prefix`], [`Node::attributes`], [`Node::namespaces`]), as
//! XML canonicalization needs them.
//!
//! [`Limits::strict`] is the mode for signed XML (an eSign answer): UTF-8 only, line
//! ends and attribute white space normalized as XML 1.0 §2.11 and §3.3.3 say, no
//! processing instruction but the XML declaration, no control characters, and every
//! prefix declared. The lenient mode keeps the XFA reader's behaviour byte for byte
//! (Latin-1 by declaration, processing instructions skipped).
//!
//! The crate is pure: no I/O, no time, no randomness; it compiles to
//! `wasm32-unknown-unknown`.

mod error;
mod reader;

pub use error::XmlError;
pub use reader::{Attribute, Dom, Limits, Node, NodeId, XML_NAMESPACE, parse};
