//! Revision classification (docs/31 §7; SEC-S01 shadow attacks, SEC-S02 incremental
//! saving attacks).
//!
//! Two consecutive revisions are compared object by object, as a reader of each would see
//! them (each revision is read on its own, from the file's prefix up to its end). Every
//! object of the older revision is given a role first (catalog, page, field, widget,
//! appearance stream, annotation, DSS, metadata, signature dictionary); a change is then
//! accepted only where its role has a rule that names the change. **Anything without such
//! a rule is disallowed**: this is a whitelist, so an object override the rules do not
//! foresee (a content stream, a font, a resource dictionary, an XObject, the page tree, an
//! object freed or a dangling reference filled in) fails closed.

use std::collections::{BTreeMap, BTreeSet};

use casual_sign_pdf::{Dictionary, Document, Object};

use crate::report::{Disallowed, ModificationClass};

/// Most objects visited when walking one structure (page tree, field tree, DSS).
const MAX_WALK: usize = 1_000_000;

fn no_cancel() -> bool {
    false
}

/// Fields locked by FieldMDP transforms of earlier signatures.
#[derive(Clone, Debug, Default)]
pub(crate) struct Locks {
    /// Every field is locked.
    pub(crate) all: bool,
    /// Fully qualified names locked (a name also locks its descendants).
    pub(crate) include: BTreeSet<Vec<u8>>,
    /// With `/Action /Exclude`: every field but these is locked.
    pub(crate) exclude: Option<BTreeSet<Vec<u8>>>,
}

impl Locks {
    fn covers(&self, name: &[u8]) -> bool {
        let matches = |set: &BTreeSet<Vec<u8>>| {
            set.iter().any(|n| {
                name == n.as_slice() || (name.starts_with(n) && name.get(n.len()) == Some(&b'.'))
            })
        };
        self.all || matches(&self.include) || self.exclude.as_ref().is_some_and(|e| !matches(e))
    }

    /// Add the FieldMDP (or `/Lock`) dictionary `params`.
    pub(crate) fn add(&mut self, params: &Dictionary) {
        let names: BTreeSet<Vec<u8>> = match params.get(b"Fields") {
            Some(Object::Array(a)) => a
                .iter()
                .filter_map(|o| match o {
                    Object::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => BTreeSet::new(),
        };
        match params.name(b"Action") {
            Some(b"All") => self.all = true,
            Some(b"Include") => self.include.extend(names),
            Some(b"Exclude") => {
                // Several Exclude locks: a field is free only if every lock excludes it.
                self.exclude = Some(match self.exclude.take() {
                    None => names,
                    Some(prev) => prev.intersection(&names).cloned().collect(),
                });
            }
            _ => {}
        }
    }
}

/// What an object of the older revision is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Role {
    Catalog,
    AcroForm,
    PageTreeNode,
    Page,
    /// An indirect `/Annots` array of a page.
    AnnotsArray,
    /// A form field (terminal or not), with its fully qualified name.
    Field(Vec<u8>),
    /// A widget that is not itself a field, with its field's name.
    Widget(Vec<u8>),
    /// An appearance stream (or appearance sub-dictionary) of a field or widget.
    FieldAppearance(Vec<u8>),
    /// A non-widget annotation or one of its appearance streams or popups.
    Annotation,
    Info,
    Metadata,
    Dss,
    SignatureDictionary,
}

/// Roles of the older revision's objects, and every object number it references.
struct Roles {
    roles: BTreeMap<u32, Role>,
    catalog: Option<u32>,
}

fn reference_num(o: Option<&Object>) -> Option<u32> {
    o.and_then(Object::as_ref).map(|r| r.num)
}

fn resolve(doc: &mut Document<'_>, o: &Object) -> Object {
    doc.resolve(o, &no_cancel).unwrap_or(Object::Null)
}

fn resolve_opt(doc: &mut Document<'_>, o: Option<&Object>) -> Object {
    match o {
        Some(o) => resolve(doc, o),
        None => Object::Null,
    }
}

fn is_sig_value(o: &Object) -> Option<ModificationClass> {
    let d = o.dict()?;
    if !d.contains(b"ByteRange") {
        return None;
    }
    match d.name(b"Type") {
        Some(b"DocTimeStamp") => Some(ModificationClass::DocumentTimestamp),
        Some(b"Sig") | None => Some(ModificationClass::Signature),
        _ => None,
    }
}

impl Roles {
    fn set(&mut self, num: u32, role: Role) {
        // The first role found wins, and the walks run strictest first.
        self.roles.entry(num).or_insert(role);
    }

    /// Appearance streams under an `/AP` dictionary.
    fn appearances(&mut self, doc: &mut Document<'_>, ap: Option<&Object>, role: &Role) {
        let Some(ap) = ap else { return };
        if let Some(n) = reference_num(Some(ap)) {
            self.set(n, role.clone());
        }
        let Object::Dictionary(ap) = resolve(doc, ap) else {
            return;
        };
        for key in [&b"N"[..], b"R", b"D"] {
            let Some(v) = ap.get(key) else { continue };
            if let Some(n) = reference_num(Some(v)) {
                self.set(n, role.clone());
            }
            if let Object::Dictionary(states) = resolve(doc, v) {
                for (_, s) in states.iter() {
                    if let Some(n) = reference_num(Some(s)) {
                        self.set(n, role.clone());
                    }
                }
            }
        }
    }

    fn build(doc: &mut Document<'_>) -> Self {
        let mut r = Self {
            roles: BTreeMap::new(),
            catalog: reference_num(doc.trailer().get(b"Root")),
        };
        let trailer = doc.trailer().clone();
        if let Some(n) = reference_num(trailer.get(b"Info")) {
            r.set(n, Role::Info);
        }
        let catalog = resolve_opt(doc, trailer.get(b"Root"));
        if let Some(n) = r.catalog {
            r.set(n, Role::Catalog);
        }
        let Some(cat) = catalog.dict().cloned() else {
            return r;
        };
        if let Some(n) = reference_num(cat.get(b"Metadata")) {
            r.set(n, Role::Metadata);
        }
        // Fields first: a widget merged with its field is a field.
        if let Some(af) = cat.get(b"AcroForm") {
            if let Some(n) = reference_num(Some(af)) {
                r.set(n, Role::AcroForm);
            }
            let af = resolve(doc, af);
            if let Some(Object::Array(fields)) = af.get(b"Fields").map(|f| resolve(doc, f)) {
                if let Some(n) = reference_num(af.get(b"Fields")) {
                    r.set(n, Role::AcroForm);
                }
                r.fields(doc, &fields);
            }
        }
        r.pages(doc, cat.get(b"Pages"));
        if let Some(dss) = cat.get(b"DSS") {
            r.dss(doc, dss);
        }
        r
    }

    fn fields(&mut self, doc: &mut Document<'_>, top: &[Object]) {
        let mut stack: Vec<(Object, Vec<u8>)> =
            top.iter().rev().map(|o| (o.clone(), Vec::new())).collect();
        let mut seen = BTreeSet::new();
        while let Some((o, parent_name)) = stack.pop() {
            if seen.len() >= MAX_WALK {
                break;
            }
            let Some(num) = reference_num(Some(&o)) else {
                continue;
            };
            if !seen.insert(num) {
                continue;
            }
            let Object::Dictionary(d) = resolve(doc, &o) else {
                continue;
            };
            let is_field = d.contains(b"T") || d.contains(b"FT") || d.contains(b"Kids");
            let name = match d.get(b"T") {
                Some(Object::String(t)) if parent_name.is_empty() => t.clone(),
                Some(Object::String(t)) => {
                    let mut n = parent_name.clone();
                    n.push(b'.');
                    n.extend_from_slice(t);
                    n
                }
                _ => parent_name.clone(),
            };
            let role = if is_field {
                Role::Field(name.clone())
            } else {
                Role::Widget(name.clone())
            };
            self.set(num, role);
            if let Some(v) = d.get(b"V")
                && let Some(n) = reference_num(Some(v))
                && is_sig_value(&resolve(doc, v)).is_some()
            {
                self.set(n, Role::SignatureDictionary);
            }
            self.appearances(doc, d.get(b"AP"), &Role::FieldAppearance(name.clone()));
            if let Some(Object::Array(kids)) = d.get(b"Kids").map(|k| resolve(doc, k)) {
                if let Some(n) = reference_num(d.get(b"Kids")) {
                    self.set(n, Role::Field(name.clone()));
                }
                for k in kids.iter().rev() {
                    stack.push((k.clone(), name.clone()));
                }
            }
        }
    }

    fn pages(&mut self, doc: &mut Document<'_>, root: Option<&Object>) {
        let Some(root) = root else { return };
        let mut stack = vec![root.clone()];
        let mut seen = BTreeSet::new();
        while let Some(o) = stack.pop() {
            if seen.len() >= MAX_WALK {
                break;
            }
            let Some(num) = reference_num(Some(&o)) else {
                continue;
            };
            if !seen.insert(num) {
                continue;
            }
            let Object::Dictionary(d) = resolve(doc, &o) else {
                continue;
            };
            if let Some(Object::Array(kids)) = d.get(b"Kids").map(|k| resolve(doc, k)) {
                self.set(num, Role::PageTreeNode);
                if let Some(n) = reference_num(d.get(b"Kids")) {
                    self.set(n, Role::PageTreeNode);
                }
                stack.extend(kids.into_iter().rev());
                continue;
            }
            self.set(num, Role::Page);
            let Some(annots) = d.get(b"Annots") else {
                continue;
            };
            if let Some(n) = reference_num(Some(annots)) {
                self.set(n, Role::AnnotsArray);
            }
            let Object::Array(annots) = resolve(doc, annots) else {
                continue;
            };
            for a in &annots {
                let Some(an) = reference_num(Some(a)) else {
                    continue;
                };
                let Object::Dictionary(ad) = resolve(doc, a) else {
                    continue;
                };
                if ad.name(b"Subtype") == Some(b"Widget") {
                    // A widget no field tree reached: its rules are a widget's, nameless.
                    self.set(an, Role::Widget(Vec::new()));
                    self.appearances(doc, ad.get(b"AP"), &Role::FieldAppearance(Vec::new()));
                } else {
                    self.set(an, Role::Annotation);
                    self.appearances(doc, ad.get(b"AP"), &Role::Annotation);
                    if let Some(p) = reference_num(ad.get(b"Popup")) {
                        self.set(p, Role::Annotation);
                    }
                }
            }
        }
    }

    fn dss(&mut self, doc: &mut Document<'_>, dss: &Object) {
        let mut stack = vec![dss.clone()];
        let mut seen = BTreeSet::new();
        while let Some(o) = stack.pop() {
            if seen.len() >= MAX_WALK {
                break;
            }
            let value = match &o {
                Object::Reference(r) => {
                    if !seen.insert(r.num) {
                        continue;
                    }
                    self.set(r.num, Role::Dss);
                    resolve(doc, &o)
                }
                other => other.clone(),
            };
            match value {
                Object::Array(a) => stack.extend(a),
                Object::Dictionary(d) => stack.extend(d.iter().map(|(_, v)| v.clone())),
                // Stream dictionaries (filters, lengths) hold nothing to follow.
                _ => {}
            }
        }
    }
}

/// Structural equality of two objects as their readers see them: streams compare by their
/// dictionaries (less `/Length`) and their encoded bytes.
fn same(a: &Object, b: &Object, bytes: &[u8]) -> bool {
    match (a, b) {
        (Object::Stream(x), Object::Stream(y)) => {
            same_dict(&x.dict, &y.dict, bytes, &[b"Length"])
                && bytes.get(x.data.clone()).is_some()
                && bytes.get(x.data.clone()) == bytes.get(y.data.clone())
        }
        (Object::Dictionary(x), Object::Dictionary(y)) => same_dict(x, y, bytes, &[]),
        (Object::Array(x), Object::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q, bytes))
        }
        (Object::Integer(x), Object::Real(y)) | (Object::Real(y), Object::Integer(x)) => {
            // Rounds above 2^53, which no meaningful PDF number reaches.
            #[allow(clippy::cast_precision_loss)]
            let x = *x as f64;
            x == *y
        }
        _ => a == b,
    }
}

fn same_dict(x: &Dictionary, y: &Dictionary, bytes: &[u8], ignore: &[&[u8]]) -> bool {
    let keys = |d: &Dictionary| -> BTreeSet<Vec<u8>> {
        d.iter()
            .map(|(k, _)| k.to_vec())
            .filter(|k| !ignore.contains(&k.as_slice()))
            .collect()
    };
    let kx = keys(x);
    kx == keys(y)
        && kx.iter().all(|k| match (x.get(k), y.get(k)) {
            (Some(p), Some(q)) => same(p, q, bytes),
            _ => false,
        })
}

/// Keys whose values differ between two dictionaries.
fn changed_keys(x: &Dictionary, y: &Dictionary, bytes: &[u8]) -> BTreeSet<Vec<u8>> {
    let mut keys: BTreeSet<Vec<u8>> = x.iter().map(|(k, _)| k.to_vec()).collect();
    keys.extend(y.iter().map(|(k, _)| k.to_vec()));
    keys.into_iter()
        .filter(|k| match (x.get(k), y.get(k)) {
            (Some(p), Some(q)) => !same(p, q, bytes),
            _ => true,
        })
        .collect()
}

/// Every reference inside `o`, depth-first.
fn references(o: &Object, out: &mut BTreeSet<u32>) {
    let mut stack = vec![o];
    while let Some(o) = stack.pop() {
        match o {
            Object::Reference(r) => {
                out.insert(r.num);
            }
            Object::Array(a) => stack.extend(a.iter()),
            Object::Dictionary(d) => stack.extend(d.iter().map(|(_, v)| v)),
            Object::Stream(s) => stack.extend(s.dict.iter().map(|(_, v)| v)),
            _ => {}
        }
    }
}

fn structural(o: &Object) -> bool {
    matches!(
        o.get(b"Type").and_then(Object::as_name),
        Some(b"XRef" | b"ObjStm")
    )
}

/// One revision's comparison.
pub(crate) struct Comparison<'d, 'a> {
    old: &'d mut Document<'a>,
    new: &'d mut Document<'a>,
    bytes: &'a [u8],
    locks: &'d Locks,
    out: BTreeSet<ModificationClass>,
}

/// Classify every change from `old` to `new` (two consecutive revisions of `bytes`).
/// `locks` are the FieldMDP locks in force. The result is sorted and de-duplicated; DocMDP
/// permissions are applied by the caller.
pub(crate) fn classify<'a>(
    old: &mut Document<'a>,
    new: &mut Document<'a>,
    bytes: &'a [u8],
    locks: &Locks,
) -> Vec<ModificationClass> {
    let roles = Roles::build(old);
    let mut c = Comparison {
        old,
        new,
        bytes,
        locks,
        out: BTreeSet::new(),
    };
    c.run(&roles);
    c.out.into_iter().collect()
}

impl Comparison<'_, '_> {
    fn deny(&mut self, why: Disallowed) {
        self.out.insert(ModificationClass::Disallowed(why));
    }

    fn allow(&mut self, class: ModificationClass) {
        self.out.insert(class);
    }

    fn run(&mut self, roles: &Roles) {
        let (ot, nt) = (self.old.trailer().clone(), self.new.trailer().clone());
        if reference_num(ot.get(b"Root")) != reference_num(nt.get(b"Root"))
            || (nt.contains(b"Encrypt") && !ot.contains(b"Encrypt"))
        {
            self.deny(Disallowed::TrailerChanged);
        }
        if reference_num(ot.get(b"Info")) != reference_num(nt.get(b"Info")) {
            self.allow(ModificationClass::Metadata);
        }

        let mut nums: BTreeSet<u32> = self.old.object_numbers().collect();
        nums.extend(self.new.object_numbers());
        let mut old_refs = BTreeSet::new();
        let mut added = Vec::new();
        for num in nums {
            let a = self.old.object(num, &no_cancel).unwrap_or(Object::Null);
            let b = self.new.object(num, &no_cancel).unwrap_or(Object::Null);
            references(&a, &mut old_refs);
            if same(&a, &b, self.bytes) {
                continue;
            }
            match (&a, &b) {
                (Object::Null, _) => added.push((num, b)),
                (_, Object::Null) if structural(&a) => {}
                (_, Object::Null) => self.deny(Disallowed::ObjectRemoved(num)),
                _ if structural(&a) && structural(&b) => {}
                _ => self.changed(num, roles.roles.get(&num), &a, &b),
            }
        }
        for (num, b) in added {
            if old_refs.contains(&num) {
                // Filled in where the signed revision already pointed: a shadow object.
                self.deny(Disallowed::ObjectChanged(num));
            } else if let Some(class) = is_sig_value(&b) {
                self.allow(class);
            }
        }
    }

    fn changed(&mut self, num: u32, role: Option<&Role>, a: &Object, b: &Object) {
        let (Some(x), Some(y)) = (a.dict(), b.dict()) else {
            match role {
                Some(Role::Dss) => self.allow(ModificationClass::DssUpdate),
                Some(Role::AnnotsArray) => self.annots_changed(num, a, b),
                Some(Role::AcroForm) => self.fields_array_changed(num, a, b),
                _ => self.deny(Disallowed::ObjectChanged(num)),
            }
            return;
        };
        let keys = changed_keys(x, y, self.bytes);
        match role {
            Some(Role::Catalog) => self.catalog(x, y, &keys),
            Some(Role::AcroForm) => self.acroform(num, x, y, &keys),
            Some(Role::Page) => {
                for k in &keys {
                    if k.as_slice() == b"Annots" {
                        let (p, q) = (
                            x.get(b"Annots").cloned().unwrap_or(Object::Null),
                            y.get(b"Annots").cloned().unwrap_or(Object::Null),
                        );
                        self.annots_changed(num, &p, &q);
                    } else {
                        self.deny(Disallowed::PageChanged(num));
                    }
                }
            }
            Some(Role::Field(name)) => self.field(num, name, x, y, &keys, true),
            Some(Role::Widget(name)) => self.field(num, name, x, y, &keys, false),
            Some(Role::FieldAppearance(name)) => self.fill(num, name),
            Some(Role::Annotation) => self.allow(ModificationClass::Annotation),
            Some(Role::Info | Role::Metadata) => self.allow(ModificationClass::Metadata),
            Some(Role::Dss) => self.allow(ModificationClass::DssUpdate),
            Some(Role::SignatureDictionary) => self.deny(Disallowed::SignatureChanged(num)),
            Some(Role::PageTreeNode | Role::AnnotsArray) | None => {
                if is_sig_value(a).is_some() {
                    self.deny(Disallowed::SignatureChanged(num));
                } else {
                    self.deny(Disallowed::ObjectChanged(num));
                }
            }
        }
    }

    fn catalog(&mut self, x: &Dictionary, y: &Dictionary, keys: &BTreeSet<Vec<u8>>) {
        for k in keys {
            match k.as_slice() {
                b"DSS" => self.allow(ModificationClass::DssUpdate),
                b"Extensions" | b"Version" | b"Metadata" => {
                    self.allow(ModificationClass::Metadata);
                }
                b"AcroForm" => match (x.get(b"AcroForm"), y.get(b"AcroForm")) {
                    (Some(Object::Dictionary(p)), Some(Object::Dictionary(q))) => {
                        let ks = changed_keys(p, q, self.bytes);
                        let (p, q) = (p.clone(), q.clone());
                        let num = reference_num(self.old.trailer().get(b"Root")).unwrap_or(0);
                        self.acroform(num, &p, &q, &ks);
                    }
                    (None, Some(q)) => {
                        // A form added where there was none: only signature fields.
                        let q = resolve(self.new, q);
                        let fields = q.get(b"Fields").map(|f| resolve(self.new, f));
                        let empty = Object::Array(Vec::new());
                        self.fields_array_changed(0, &empty, &fields.unwrap_or(Object::Null));
                    }
                    _ => self.deny(Disallowed::CatalogChanged),
                },
                _ => self.deny(Disallowed::CatalogChanged),
            }
        }
    }

    fn acroform(&mut self, num: u32, x: &Dictionary, y: &Dictionary, keys: &BTreeSet<Vec<u8>>) {
        for k in keys {
            match k.as_slice() {
                b"Fields" => {
                    let p = resolve_opt(self.old, x.get(b"Fields"));
                    let q = resolve_opt(self.new, y.get(b"Fields"));
                    self.fields_array_changed(num, &p, &q);
                }
                b"SigFlags" => self.allow(ModificationClass::Signature),
                b"DR" | b"DA" | b"NeedAppearances" => self.allow(ModificationClass::FormFill),
                _ => self.deny(Disallowed::ObjectChanged(num)),
            }
        }
    }

    /// The `/Fields` array: old entries kept, new ones only signature fields.
    fn fields_array_changed(&mut self, num: u32, a: &Object, b: &Object) {
        let (Object::Array(p), Object::Array(q)) = (a, b) else {
            self.deny(Disallowed::FieldChanged(num));
            return;
        };
        let old: BTreeSet<u32> = p.iter().filter_map(|o| reference_num(Some(o))).collect();
        let new: BTreeSet<u32> = q.iter().filter_map(|o| reference_num(Some(o))).collect();
        if !old.is_subset(&new) {
            self.deny(Disallowed::FieldChanged(num));
        }
        for n in new.difference(&old) {
            self.new_signature_field(*n);
        }
    }

    /// A field added to the form, or a widget added to a page: allowed only as a
    /// signature field (filled with a signature, a document timestamp, or empty).
    fn new_signature_field(&mut self, num: u32) {
        let o = self.new.object(num, &no_cancel).unwrap_or(Object::Null);
        let Some(d) = o.dict().cloned() else {
            self.deny(Disallowed::FieldChanged(num));
            return;
        };
        // A widget kid: judge its parent field.
        let field = if d.contains(b"FT") {
            d
        } else {
            match d.get(b"Parent").map(|p| resolve(self.new, p)) {
                Some(Object::Dictionary(p)) => p,
                _ => d,
            }
        };
        if field.name(b"FT") != Some(b"Sig") {
            self.deny(Disallowed::FieldChanged(num));
            return;
        }
        let class = match field.get(b"V").map(|v| resolve(self.new, v)) {
            Some(v) => is_sig_value(&v).unwrap_or(ModificationClass::Signature),
            None => ModificationClass::Signature,
        };
        self.allow(class);
    }

    /// A page's `/Annots`: old entries kept; new widgets must be signature fields, new
    /// other annotations are annotations.
    fn annots_changed(&mut self, page: u32, a: &Object, b: &Object) {
        let p = resolve(self.old, a);
        let q = resolve(self.new, b);
        let list = |o: &Object| -> Vec<u32> {
            match o {
                Object::Array(v) => v.iter().filter_map(|o| reference_num(Some(o))).collect(),
                _ => Vec::new(),
            }
        };
        let (old, new): (BTreeSet<u32>, BTreeSet<u32>) = (
            list(&p).into_iter().collect(),
            list(&q).into_iter().collect(),
        );
        if !matches!(q, Object::Array(_) | Object::Null)
            || matches!(b, Object::Array(v) if v.iter().any(|o| o.as_ref().is_none()))
        {
            // Direct annotation dictionaries cannot be told apart from the page; refuse.
            self.deny(Disallowed::PageChanged(page));
        }
        for gone in old.difference(&new) {
            self.deny(Disallowed::AnnotationRemoved(*gone));
        }
        for n in new.difference(&old) {
            let o = self.new.object(*n, &no_cancel).unwrap_or(Object::Null);
            if o.get(b"Subtype").and_then(Object::as_name) == Some(b"Widget") {
                self.new_signature_field(*n);
            } else {
                self.allow(ModificationClass::Annotation);
            }
        }
    }

    /// A field or widget dictionary changed.
    fn field(
        &mut self,
        num: u32,
        name: &[u8],
        x: &Dictionary,
        y: &Dictionary,
        keys: &BTreeSet<Vec<u8>>,
        is_field: bool,
    ) {
        for k in keys {
            match k.as_slice() {
                // Signing an empty signature field.
                b"V" if is_field
                    && x.get(b"V").is_none()
                    && y.name(b"FT").or(x.name(b"FT")) == Some(b"Sig") =>
                {
                    let v = resolve_opt(self.new, y.get(b"V"));
                    match is_sig_value(&v) {
                        Some(class) => self.allow(class),
                        None => self.deny(Disallowed::FieldChanged(num)),
                    }
                }
                b"V" if is_field => {
                    if x.name(b"FT").or(y.name(b"FT")) == Some(b"Sig") {
                        self.deny(Disallowed::SignatureChanged(num));
                    } else {
                        self.fill(num, name);
                    }
                }
                b"AS" | b"AP" | b"MK" => self.fill(num, name),
                _ => self.deny(Disallowed::FieldChanged(num)),
            }
        }
    }

    fn fill(&mut self, num: u32, name: &[u8]) {
        if self.locks.covers(name) {
            self.deny(Disallowed::LockedField(num));
        } else {
            self.allow(ModificationClass::FormFill);
        }
    }
}

/// Apply DocMDP: `permissions` is the certification level in force (`None`: no
/// certification signature). Classes the level forbids become disallowed.
pub(crate) fn apply_docmdp(
    classes: Vec<ModificationClass>,
    permissions: Option<u8>,
) -> Vec<ModificationClass> {
    let mut out: BTreeSet<ModificationClass> = BTreeSet::new();
    for c in classes {
        let ok = match c {
            ModificationClass::DssUpdate
            | ModificationClass::DocumentTimestamp
            | ModificationClass::Metadata
            | ModificationClass::Disallowed(_) => true,
            ModificationClass::Signature | ModificationClass::FormFill => {
                permissions.is_none_or(|p| p >= 2)
            }
            ModificationClass::Annotation => permissions.is_none_or(|p| p >= 3),
        };
        if ok {
            out.insert(c);
        } else {
            out.insert(ModificationClass::Disallowed(Disallowed::NotPermitted(
                permissions.unwrap_or(0),
            )));
        }
    }
    out.into_iter().collect()
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_cover_names_and_descendants() {
        let mut l = Locks::default();
        l.include.insert(b"a".to_vec());
        assert!(l.covers(b"a"));
        assert!(l.covers(b"a.b"));
        assert!(!l.covers(b"ab"));
        let mut e = Locks {
            exclude: Some([b"free".to_vec()].into_iter().collect()),
            ..Locks::default()
        };
        assert!(!e.covers(b"free"));
        assert!(e.covers(b"other"));
        e.all = true;
        assert!(e.covers(b"free"));
    }

    #[test]
    fn docmdp_levels() {
        use ModificationClass::*;
        let all = vec![
            DssUpdate,
            DocumentTimestamp,
            Metadata,
            Signature,
            FormFill,
            Annotation,
        ];
        let p1 = apply_docmdp(all.clone(), Some(1));
        assert!(p1.contains(&Disallowed(super::Disallowed::NotPermitted(1))));
        assert!(!p1.contains(&Signature));
        let p2 = apply_docmdp(all.clone(), Some(2));
        assert!(p2.contains(&FormFill) && !p2.contains(&Annotation));
        let p3 = apply_docmdp(all.clone(), Some(3));
        assert_eq!(p3, all);
        assert_eq!(apply_docmdp(all.clone(), None), all);
    }
}
