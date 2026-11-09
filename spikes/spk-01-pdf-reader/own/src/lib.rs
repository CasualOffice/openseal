//! SPK-01 sketch of our own bounded reader: lexer, iterative object parser, classic xref +
//! `/Prev` chain, recovery by scanning, page-tree walk. Written to estimate effort, not to
//! ship. Not covered (see docs/64 §6): xref streams, object streams, filters, encryption,
//! indirect `/Length`. No recursion anywhere: depth is a counter, so no stack overflow.
//! No allocation is sized by a number read from the file.
use std::collections::{BTreeMap, HashSet};

/// docs/21 defaults. Every loop that a file can lengthen is bounded by one of these.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_depth: usize,     // CS-PDF-0004
    pub max_ref_depth: usize, // CS-PDF-0004
    pub max_objects: usize,   // CS-PDF-0002
    pub max_revisions: usize, // CS-PDF-0006
    pub max_pages: usize,     // CS-PDF-0007
    pub max_string: usize,    // CS-PDF-0008
    pub max_name: usize,      // CS-PDF-0008
}
impl Default for Limits {
    fn default() -> Self {
        Limits { max_depth: 256, max_ref_depth: 64, max_objects: 1_000_000, max_revisions: 1000, max_pages: 5000, max_string: 16 << 20, max_name: 127 }
    }
}

/// Typed errors carrying offsets and object numbers only, never content.
#[derive(Debug, PartialEq, Eq)]
pub enum Error { Syntax(usize), Depth(usize), TooMany(&'static str), Missing(&'static str), Cycle(u64), Unsupported(&'static str) }
type R<T> = Result<T, Error>;
pub type Dict = Vec<(Vec<u8>, Obj)>;
#[derive(Clone, Debug, PartialEq)]
pub enum Obj { Null, Bool(bool), Int(i64), Real(f64), Str(Vec<u8>), Name(Vec<u8>), Array(Vec<Obj>), Dict(Dict), Ref(u32, u16), Stream(Dict, std::ops::Range<usize>) }
impl Obj {
    pub fn get(&self, k: &[u8]) -> Option<&Obj> {
        match self {
            Obj::Dict(d) | Obj::Stream(d, _) => d.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
enum Tok<'a> { Int(i64), Real(f64), Name(Vec<u8>), Str(Vec<u8>), AOpen, AClose, DOpen, DClose, Kw(&'a [u8]) }

fn ws(c: u8) -> bool { matches!(c, 0 | 9 | 10 | 12 | 13 | 32) }
fn delim(c: u8) -> bool { b"()<>[]{}/%".contains(&c) }
fn hexv(c: u8) -> Option<u8> { (c as char).to_digit(16).map(|v| v as u8) }

struct Lex<'a> { b: &'a [u8], pos: usize, lim: Limits }
impl<'a> Lex<'a> {
    fn peek(&self) -> Option<u8> { self.b.get(self.pos).copied() }
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if ws(c) { self.pos += 1 } else if c == b'%' {
                while let Some(c) = self.peek() { if c == b'\n' || c == b'\r' { break } self.pos += 1 }
            } else { break }
        }
    }
    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> &'a [u8] {
        let s = self.pos;
        while self.peek().is_some_and(&f) { self.pos += 1 }
        &self.b[s..self.pos]
    }
    fn next(&mut self) -> R<Option<Tok<'a>>> {
        self.skip_ws();
        let at = self.pos;
        let Some(c) = self.peek() else { return Ok(None) };
        self.pos += 1;
        let two = |s: &mut Self, n: u8| if s.peek() == Some(n) { s.pos += 1; true } else { false };
        Ok(Some(match c {
            b'[' => Tok::AOpen,
            b']' => Tok::AClose,
            b'<' if two(self, b'<') => Tok::DOpen,
            b'>' if two(self, b'>') => Tok::DClose,
            b'<' => {
                let raw = self.take_while(|c| c != b'>');
                if self.peek() != Some(b'>') { return Err(Error::Syntax(at)) }
                self.pos += 1;
                let digits: Vec<u8> = raw.iter().filter(|c| !ws(**c)).map(|c| hexv(*c).ok_or(Error::Syntax(at))).collect::<R<_>>()?;
                if digits.len() / 2 > self.lim.max_string { return Err(Error::TooMany("string")) }
                Tok::Str(digits.chunks(2).map(|p| p[0] << 4 | p.get(1).copied().unwrap_or(0)).collect())
            }
            b'(' => {
                let (mut out, mut depth) = (Vec::new(), 1usize);
                loop {
                    let c = self.peek().ok_or(Error::Syntax(at))?;
                    self.pos += 1;
                    match c {
                        b'(' => { depth += 1; out.push(c) }
                        b')' => { depth -= 1; if depth == 0 { break } out.push(c) }
                        b'\\' => {
                            let e = self.peek().ok_or(Error::Syntax(at))?;
                            self.pos += 1;
                            match e {
                                b'n' => out.push(b'\n'), b'r' => out.push(b'\r'), b't' => out.push(b'\t'),
                                b'b' => out.push(8), b'f' => out.push(12), b'\n' => {}
                                b'\r' => { two(self, b'\n'); }
                                b'0'..=b'7' => {
                                    let mut v = u32::from(e - b'0');
                                    for _ in 0..2 { match self.peek() { Some(d @ b'0'..=b'7') => { v = v * 8 + u32::from(d - b'0'); self.pos += 1 } _ => break } }
                                    out.push((v & 0xff) as u8)
                                }
                                other => out.push(other),
                            }
                        }
                        _ => out.push(c),
                    }
                    if out.len() > self.lim.max_string { return Err(Error::TooMany("string")) }
                }
                Tok::Str(out)
            }
            b'/' => {
                let raw = self.take_while(|c| !ws(c) && !delim(c));
                let mut n = Vec::with_capacity(raw.len().min(self.lim.max_name));
                let mut i = 0;
                while i < raw.len() {
                    match (raw[i], raw.get(i + 1).and_then(|c| hexv(*c)), raw.get(i + 2).and_then(|c| hexv(*c))) {
                        (b'#', Some(h), Some(l)) => { n.push(h << 4 | l); i += 3 }
                        (c, _, _) => { n.push(c); i += 1 }
                    }
                }
                if n.len() > self.lim.max_name { return Err(Error::TooMany("name")) }
                Tok::Name(n)
            }
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                self.pos = at;
                let s = std::str::from_utf8(self.take_while(|c| c.is_ascii_digit() || b"+-.".contains(&c))).map_err(|_| Error::Syntax(at))?;
                match s.parse::<i64>() { Ok(i) => Tok::Int(i), Err(_) => Tok::Real(s.parse().map_err(|_| Error::Syntax(at))?) }
            }
            _ => {
                self.pos = at;
                let k = self.take_while(|c| !ws(c) && !delim(c));
                if k.is_empty() { return Err(Error::Syntax(at)) }
                Tok::Kw(k)
            }
        }))
    }
    fn int(&mut self) -> Option<i64> { match self.next() { Ok(Some(Tok::Int(i))) => Some(i), _ => None } }
    fn kw(&mut self, k: &[u8]) -> bool { matches!(self.next(), Ok(Some(Tok::Kw(x))) if x == k) }

    /// One direct object, iteratively: an explicit stack, capped at `max_depth`.
    fn object(&mut self) -> R<Obj> {
        enum F { A(Vec<Obj>), D(Dict, Option<Vec<u8>>) }
        let mut st: Vec<F> = Vec::new();
        loop {
            let at = self.pos;
            let mut v = match self.next()?.ok_or(Error::Syntax(at))? {
                Tok::AOpen | Tok::DOpen if st.len() >= self.lim.max_depth => return Err(Error::Depth(at)),
                Tok::AOpen => { st.push(F::A(Vec::new())); continue }
                Tok::DOpen => { st.push(F::D(Vec::new(), None)); continue }
                Tok::AClose => match st.pop() { Some(F::A(a)) => Obj::Array(a), _ => return Err(Error::Syntax(at)) },
                Tok::DClose => match st.pop() { Some(F::D(d, None)) => Obj::Dict(d), _ => return Err(Error::Syntax(at)) },
                Tok::Int(i) => {
                    let save = self.pos;
                    match (self.int(), self.kw(b"R")) {
                        (Some(g), true) if (0..=i64::from(u32::MAX)).contains(&i) && (0..=65535).contains(&g) => Obj::Ref(i as u32, g as u16),
                        _ => { self.pos = save; Obj::Int(i) }
                    }
                }
                Tok::Real(r) => Obj::Real(r),
                Tok::Str(s) => Obj::Str(s),
                Tok::Name(n) => Obj::Name(n),
                Tok::Kw(b"true") => Obj::Bool(true),
                Tok::Kw(b"false") => Obj::Bool(false),
                Tok::Kw(b"null") => Obj::Null,
                Tok::Kw(_) => return Err(Error::Syntax(at)),
            };
            loop {
                match st.last_mut() {
                    None => return Ok(v),
                    Some(F::A(a)) => { a.push(v); break }
                    Some(F::D(_, k @ None)) => { let Obj::Name(n) = v else { return Err(Error::Syntax(at)) }; *k = Some(n); break }
                    Some(F::D(d, k)) => { if let Some(key) = k.take() { d.push((key, std::mem::replace(&mut v, Obj::Null))) } break }
                }
            }
        }
    }
}

/// The reader: an xref map (object number to offset), the newest trailer, and whether the
/// xref had to be rebuilt by scanning (CS-PDF-0101).
pub struct Reader<'a> { b: &'a [u8], lim: Limits, xref: BTreeMap<u32, usize>, trailer: Obj, pub recovered: bool }

impl<'a> Reader<'a> {
    pub fn open(b: &'a [u8], lim: Limits) -> R<Self> {
        let mut r = Reader { b, lim, xref: BTreeMap::new(), trailer: Obj::Null, recovered: false };
        // Read as written; if that fails or an entry does not point at its own header, rebuild.
        if r.read_chain().is_err() || !r.xref.keys().all(|n| r.header_ok(*n).is_ok()) {
            r.xref.clear();
            r.recover()?;
            r.recovered = true;
        }
        Ok(r)
    }
    fn lex(&self, pos: usize) -> Lex<'a> { Lex { b: self.b, pos, lim: self.lim } }
    pub fn object_count(&self) -> usize { self.xref.len() }

    fn read_chain(&mut self) -> R<()> {
        let tail = self.b.len().saturating_sub(1024);
        let sx = self.b[tail..].windows(9).rposition(|w| w == b"startxref").ok_or(Error::Missing("startxref"))?;
        let mut next = self.lex(tail + sx + 9).int().and_then(|o| usize::try_from(o).ok());
        let mut seen = HashSet::new();
        while let Some(off) = next {
            if !seen.insert(off) { return Err(Error::Cycle(off as u64)) } // CS-PDF-0006
            if seen.len() > self.lim.max_revisions { return Err(Error::TooMany("revisions")) }
            let mut lx = self.lex(off);
            if !lx.kw(b"xref") { return Err(Error::Unsupported("xref stream or bad offset")) }
            loop {
                let save = lx.pos;
                if lx.kw(b"trailer") { break }
                lx.pos = save;
                let (first, count) = (lx.int().ok_or(Error::Syntax(save))?, lx.int().ok_or(Error::Syntax(save))?);
                lx.skip_ws();
                // A count is believed only as far as the bytes present: never an allocation size.
                let need = usize::try_from(count).ok().and_then(|c| c.checked_mul(20)).ok_or(Error::Syntax(save))?;
                if need > self.b.len().saturating_sub(lx.pos) { return Err(Error::Syntax(save)) }
                for i in 0..count {
                    let e = &self.b[lx.pos..lx.pos + 20];
                    lx.pos += 20;
                    let num = u32::try_from(first + i).map_err(|_| Error::Syntax(save))?;
                    let pos = std::str::from_utf8(&e[..10]).ok().and_then(|s| s.parse::<usize>().ok()).ok_or(Error::Syntax(save))?;
                    if e[17] == b'n' && !self.xref.contains_key(&num) { self.xref.insert(num, pos); }
                    if self.xref.len() > self.lim.max_objects { return Err(Error::TooMany("objects")) }
                }
            }
            let t = lx.object()?;
            next = match t.get(b"Prev") { Some(Obj::Int(p)) => usize::try_from(*p).ok(), _ => None };
            if self.trailer == Obj::Null { self.trailer = t }
        }
        Ok(())
    }

    /// Rebuild by scanning line starts for `n g obj`; the last definition wins, as in readers.
    fn recover(&mut self) -> R<()> {
        let mut i = 0;
        while i < self.b.len() {
            if (i == 0 || matches!(self.b[i - 1], b'\n' | b'\r')) && self.b[i].is_ascii_digit() {
                let mut lx = self.lex(i);
                if let (Some(n), Some(_), true) = (lx.int(), lx.int(), lx.kw(b"obj")) {
                    if let Ok(n) = u32::try_from(n) { self.xref.insert(n, i); }
                    if self.xref.len() > self.lim.max_objects { return Err(Error::TooMany("objects")) }
                }
            }
            i += 1;
        }
        let cat = self.xref.keys().rev().copied().find(|n| matches!(self.get(*n).ok().and_then(|o| o.get(b"Type").cloned()), Some(Obj::Name(t)) if t == b"Catalog"));
        let cat = cat.ok_or(Error::Missing("catalog"))?;
        self.trailer = Obj::Dict(vec![(b"Root".to_vec(), Obj::Ref(cat, 0))]);
        Ok(())
    }

    /// The lexer just past `num g obj` at the xref offset, or an error if the header is wrong.
    fn header_ok(&self, num: u32) -> R<Lex<'a>> {
        let off = *self.xref.get(&num).ok_or(Error::Missing("object"))?;
        let mut lx = self.lex(off);
        if lx.int() != Some(i64::from(num)) || lx.int().is_none() || !lx.kw(b"obj") { return Err(Error::Syntax(off)) }
        Ok(lx)
    }

    /// Parse the object at its xref offset, checking the header names the right number.
    pub fn get(&self, num: u32) -> R<Obj> {
        let mut lx = self.header_ok(num)?;
        let o = lx.object()?;
        if matches!(o, Obj::Dict(_)) && lx.kw(b"stream") {
            let mut s = lx.pos;
            if self.b.get(s) == Some(&b'\r') { s += 1 }
            if self.b.get(s) == Some(&b'\n') { s += 1 }
            let len = match o.get(b"Length") { Some(Obj::Int(l)) => usize::try_from(*l).ok(), _ => None }.ok_or(Error::Unsupported("indirect /Length"))?;
            let end = s.checked_add(len).filter(|e| *e <= self.b.len()).ok_or(Error::Syntax(s))?;
            let Obj::Dict(d) = o else { unreachable!() };
            return Ok(Obj::Stream(d, s..end));
        }
        Ok(o)
    }

    /// Follow a reference chain up to `max_ref_depth`.
    pub fn resolve(&self, o: &Obj) -> R<Obj> {
        let mut cur = o.clone();
        for _ in 0..self.lim.max_ref_depth {
            match cur { Obj::Ref(n, _) => cur = self.get(n)?, other => return Ok(other) }
        }
        Err(Error::Depth(0))
    }

    /// Walk the page tree with a visited set and a page cap; never trusts `/Count`.
    pub fn page_count(&self) -> R<usize> {
        let root = self.resolve(self.trailer.get(b"Root").ok_or(Error::Missing("Root"))?)?;
        let mut stack = vec![(root.get(b"Pages").cloned().ok_or(Error::Missing("Pages"))?, 0usize)];
        let (mut seen, mut pages) = (HashSet::new(), 0usize);
        while let Some((node, depth)) = stack.pop() {
            if let Obj::Ref(n, _) = node { if !seen.insert(n) { return Err(Error::Cycle(u64::from(n))) } }
            if depth > self.lim.max_depth { return Err(Error::Depth(depth)) }
            let node = self.resolve(&node)?;
            match node.get(b"Kids").map(|k| self.resolve(k)).transpose()? {
                Some(Obj::Array(kids)) => stack.extend(kids.into_iter().rev().map(|k| (k, depth + 1))),
                _ => { pages += 1; if pages > self.lim.max_pages { return Err(Error::TooMany("pages")) } }
            }
        }
        Ok(pages)
    }
}
