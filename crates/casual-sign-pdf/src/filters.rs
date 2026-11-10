//! Stream filters with per-stream, ratio and per-document budgets (docs/21, `SEC-P01`).
//!
//! Every stage writes through a [`Sink`] that checks the caps before each chunk is
//! stored, so a bomb stops at the cap and never allocates past it. Flate is streamed
//! (`miniz_oxide`), so the inflater never holds more than one output chunk beyond what
//! the sink accepted.

use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use crate::Cancel;
use crate::error::{PdfError, Result};
use crate::limits::Limits;
use crate::object::{Dictionary, Object};

const CHUNK: usize = 64 * 1024;

/// A filter name with its (resolved) decode parameters.
#[derive(Debug, Clone)]
pub(crate) struct Filter {
    pub(crate) name: Vec<u8>,
    pub(crate) parms: Option<Dictionary>,
}

/// The running per-document decode total.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Budget {
    pub(crate) used: u64,
}

/// What one decode may spend.
pub(crate) struct Ctx<'x> {
    pub(crate) limits: &'x Limits,
    pub(crate) budget: &'x mut Budget,
    pub(crate) cancel: Cancel<'x>,
    pub(crate) object: u32,
}

/// Output of one stage, checked against every cap before it grows.
struct Sink<'s, 'x> {
    out: Vec<u8>,
    cap: u64,
    ratio_bound: bool,
    encoded: u64,
    ctx: &'s mut Ctx<'x>,
}

impl<'s, 'x> Sink<'s, 'x> {
    fn new(ctx: &'s mut Ctx<'x>, encoded: u64) -> Self {
        let l = ctx.limits;
        let ratio_cap = l
            .ratio_grace_bytes
            .saturating_add(encoded.saturating_mul(u64::from(l.max_decode_ratio)));
        let ratio_bound = ratio_cap < l.max_stream_bytes;
        Self {
            out: Vec::new(),
            cap: ratio_cap.min(l.max_stream_bytes),
            ratio_bound,
            encoded,
            ctx,
        }
    }

    fn extend(&mut self, chunk: &[u8]) -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        let add = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let object = self.ctx.object;
        let new_len = u64::try_from(self.out.len())
            .unwrap_or(u64::MAX)
            .saturating_add(add);
        if new_len > self.cap {
            return Err(if self.ratio_bound {
                PdfError::DecodeRatio {
                    object,
                    encoded: self.encoded,
                }
            } else {
                PdfError::StreamTooLarge {
                    object,
                    limit: self.cap,
                }
            });
        }
        let used = self.ctx.budget.used.saturating_add(add);
        if used > self.ctx.limits.max_total_decoded_bytes {
            return Err(PdfError::DecodeBudget {
                object,
                limit: self.ctx.limits.max_total_decoded_bytes,
            });
        }
        self.ctx.budget.used = used;
        self.out
            .try_reserve(chunk.len())
            .map_err(|_| PdfError::OutOfMemory)?;
        self.out.extend_from_slice(chunk);
        Ok(())
    }

    fn push(&mut self, b: u8) -> Result<()> {
        self.extend(&[b])
    }

    fn check_cancel(&self) -> Result<()> {
        if (self.ctx.cancel)() {
            Err(PdfError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Canonical filter names, with the inline-image abbreviations.
fn canonical(name: &[u8]) -> &[u8] {
    match name {
        b"Fl" => b"FlateDecode",
        b"AHx" => b"ASCIIHexDecode",
        b"A85" => b"ASCII85Decode",
        b"RL" => b"RunLengthDecode",
        b"LZW" => b"LZWDecode",
        other => other,
    }
}

/// True for the filters this reader decodes.
pub(crate) fn supported(name: &[u8]) -> bool {
    matches!(
        canonical(name),
        b"FlateDecode" | b"LZWDecode" | b"ASCIIHexDecode" | b"ASCII85Decode" | b"RunLengthDecode"
    )
}

/// Decode `raw` through `filters` in order.
pub(crate) fn decode(raw: &[u8], filters: &[Filter], ctx: &mut Ctx<'_>) -> Result<Vec<u8>> {
    let object = ctx.object;
    if filters.len() > usize::from(ctx.limits.max_filter_chain) {
        return Err(PdfError::FilterChainTooLong { object });
    }
    if filters.iter().any(|f| !supported(&f.name)) {
        return Err(PdfError::UnsupportedFilter { object });
    }
    let encoded = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    let mut current: Option<Vec<u8>> = None;
    for f in filters {
        let input: &[u8] = current.as_deref().unwrap_or(raw);
        let mut sink = Sink::new(ctx, encoded);
        match canonical(&f.name) {
            b"FlateDecode" => {
                flate(input, &mut sink)?;
                let out = predict(core::mem::take(&mut sink.out), f.parms.as_ref(), object)?;
                sink.out = out;
            }
            b"LZWDecode" => {
                let early = f
                    .parms
                    .as_ref()
                    .and_then(|p| p.get(b"EarlyChange"))
                    .and_then(Object::as_i64)
                    .unwrap_or(1);
                lzw(input, early != 0, &mut sink)?;
                let out = predict(core::mem::take(&mut sink.out), f.parms.as_ref(), object)?;
                sink.out = out;
            }
            b"ASCIIHexDecode" => ascii_hex(input, &mut sink)?,
            b"ASCII85Decode" => ascii85(input, &mut sink)?,
            b"RunLengthDecode" => run_length(input, &mut sink)?,
            _ => return Err(PdfError::UnsupportedFilter { object }),
        }
        current = Some(sink.out);
    }
    match current {
        Some(v) => Ok(v),
        None => {
            // No filter: the bytes as stored, still charged and capped.
            let mut sink = Sink::new(ctx, encoded);
            sink.extend(raw)?;
            Ok(sink.out)
        }
    }
}

fn flate(input: &[u8], sink: &mut Sink<'_, '_>) -> Result<()> {
    let produced = inflate_with(input, sink, DataFormat::ZLibIgnoreChecksum)?;
    if produced == 0 && !input.is_empty() {
        // Some producers write raw deflate with no zlib header.
        inflate_with(input, sink, DataFormat::Raw)?;
    }
    Ok(())
}

/// Inflate into the sink; returns bytes produced. Damage after some output keeps the
/// output so far, as common readers do.
fn inflate_with(input: &[u8], sink: &mut Sink<'_, '_>, format: DataFormat) -> Result<usize> {
    let mut state = InflateState::new_boxed(format);
    let mut buf = vec![0u8; CHUNK];
    let mut rest = input;
    let mut produced: usize = 0;
    loop {
        sink.check_cancel()?;
        let r = inflate(&mut state, rest, &mut buf, MZFlush::None);
        rest = rest.get(r.bytes_consumed..).unwrap_or_default();
        sink.extend(buf.get(..r.bytes_written).unwrap_or_default())?;
        produced = produced.saturating_add(r.bytes_written);
        match r.status {
            Ok(MZStatus::StreamEnd) => return Ok(produced),
            Ok(_) => {
                if r.bytes_consumed == 0 && r.bytes_written == 0 {
                    // Truncated: nothing more will come.
                    return Ok(produced);
                }
            }
            Err(MZError::Buf) => return Ok(produced),
            Err(_) => return Ok(produced),
        }
    }
}

/// LZW codes (ISO 32000-2 §7.4.4.2): 9 to 12 bits, most significant bit first.
const LZW_CLEAR: u16 = 256;
const LZW_EOD: u16 = 257;
const LZW_FIRST: u16 = 258;
const LZW_TABLE: usize = 4096;

/// One LZW table entry: the entry it extends, its last byte, its first byte and its
/// length. Strings are rebuilt by walking `prefix` back, never stored.
#[derive(Clone, Copy, Default)]
struct LzwEntry {
    prefix: u16,
    last: u8,
    first: u8,
    len: u16,
}

/// Decode LZW into the sink (ISO 32000-2 §7.4.4). The table is fixed at 4,096 entries
/// whatever the data says; every string goes through the sink's caps, so a bomb stops
/// there (each code can stand for up to 4,094 bytes, a ratio the per-stream ratio cap
/// catches). Damage after some output keeps the output so far, as with Flate.
fn lzw(input: &[u8], early_change: bool, sink: &mut Sink<'_, '_>) -> Result<()> {
    let mut table = [LzwEntry::default(); LZW_TABLE];
    for (i, e) in table.iter_mut().enumerate().take(256) {
        let b = u8::try_from(i).unwrap_or(0);
        *e = LzwEntry {
            prefix: 0,
            last: b,
            first: b,
            len: 1,
        };
    }
    let early = u16::from(early_change);
    let mut next: u16 = LZW_FIRST;
    let mut width: u32 = 9;
    let mut prev: Option<u16> = None;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut bytes = input.iter();
    let mut scratch = [0u8; LZW_TABLE];
    let mut codes: u32 = 0;
    loop {
        while bits < width {
            let Some(&b) = bytes.next() else {
                return Ok(());
            };
            acc = (acc << 8) | u32::from(b);
            bits = bits.saturating_add(8);
        }
        bits = bits.saturating_sub(width);
        let code =
            u16::try_from((acc >> bits) & ((1u32 << width).saturating_sub(1))).unwrap_or(LZW_EOD);
        acc &= (1u32 << bits).saturating_sub(1);
        codes = codes.wrapping_add(1);
        if codes.is_multiple_of(65_536) {
            sink.check_cancel()?;
        }
        if code == LZW_CLEAR {
            next = LZW_FIRST;
            width = 9;
            prev = None;
            continue;
        }
        if code == LZW_EOD {
            return Ok(());
        }
        let known = code < next && !(LZW_CLEAR..LZW_FIRST).contains(&code);
        let Some(p) = prev else {
            // The first code after a clear must name a single byte.
            if code >= LZW_CLEAR {
                return Ok(());
            }
            sink.push(u8::try_from(code).unwrap_or(0))?;
            prev = Some(code);
            continue;
        };
        let (Some(pe), current) = (table.get(usize::from(p)).copied(), code) else {
            return Ok(());
        };
        let first = if known {
            table.get(usize::from(current)).map_or(0, |e| e.first)
        } else if current == next {
            pe.first
        } else {
            // A code beyond the next free one: damage.
            return Ok(());
        };
        // Add prev + first byte of current, unless the table is full.
        if usize::from(next) < LZW_TABLE {
            if let Some(slot) = table.get_mut(usize::from(next)) {
                *slot = LzwEntry {
                    prefix: p,
                    last: first,
                    first: pe.first,
                    len: pe.len.saturating_add(1),
                };
            }
            next = next.saturating_add(1);
            if width < 12 && u32::from(next.saturating_add(early)) >= (1u32 << width) {
                width = width.saturating_add(1);
            }
        }
        lzw_emit(&table, current, &mut scratch, sink)?;
        prev = Some(current);
    }
}

/// Write the string of `code` through the sink.
fn lzw_emit(
    table: &[LzwEntry; LZW_TABLE],
    code: u16,
    scratch: &mut [u8; LZW_TABLE],
    sink: &mut Sink<'_, '_>,
) -> Result<()> {
    let Some(e) = table.get(usize::from(code)) else {
        return Ok(());
    };
    let len = usize::from(e.len).min(LZW_TABLE);
    let mut at = len;
    let mut cur = code;
    // Every entry's prefix is an older, shorter entry, so this ends within `len` steps.
    while at > 0 {
        let Some(e) = table.get(usize::from(cur)) else {
            break;
        };
        at = at.saturating_sub(1);
        if let Some(slot) = scratch.get_mut(at) {
            *slot = e.last;
        }
        if e.len <= 1 {
            break;
        }
        cur = e.prefix;
    }
    sink.extend(scratch.get(at..len).unwrap_or_default())
}

/// Undo a PNG or TIFF predictor (ISO 32000-2 §7.4.4.4).
fn predict(data: Vec<u8>, parms: Option<&Dictionary>, object: u32) -> Result<Vec<u8>> {
    let Some(p) = parms else { return Ok(data) };
    let int = |k: &[u8], d: i64| p.get(k).and_then(Object::as_i64).unwrap_or(d);
    let predictor = int(b"Predictor", 1);
    if predictor <= 1 {
        return Ok(data);
    }
    let unsupported = PdfError::UnsupportedFilter { object };
    let colors = usize::try_from(int(b"Colors", 1))
        .ok()
        .filter(|c| (1..=32).contains(c))
        .ok_or(unsupported.clone())?;
    let bpc = usize::try_from(int(b"BitsPerComponent", 8))
        .ok()
        .filter(|b| matches!(b, 1 | 2 | 4 | 8 | 16))
        .ok_or(unsupported.clone())?;
    let columns = usize::try_from(int(b"Columns", 1))
        .ok()
        .filter(|c| (1..=1 << 24).contains(c))
        .ok_or(unsupported.clone())?;
    let bits_per_pixel = colors.checked_mul(bpc).ok_or(unsupported.clone())?;
    let bpp = bits_per_pixel.div_ceil(8).max(1);
    let row = bits_per_pixel
        .checked_mul(columns)
        .ok_or(unsupported.clone())?
        .div_ceil(8);
    match predictor {
        2 if bpc == 8 => Ok(tiff(data, colors, row)),
        2 => Err(unsupported),
        10..=15 => Ok(png(&data, bpp, row)),
        _ => Err(unsupported),
    }
}

fn tiff(mut data: Vec<u8>, colors: usize, row: usize) -> Vec<u8> {
    for r in data.chunks_mut(row) {
        for i in colors..r.len() {
            let left = r.get(i.saturating_sub(colors)).copied().unwrap_or(0);
            if let Some(x) = r.get_mut(i) {
                *x = x.wrapping_add(left);
            }
        }
    }
    data
}

fn png(data: &[u8], bpp: usize, row: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = vec![0u8; row];
    let stride = row.saturating_add(1);
    for chunk in data.chunks(stride) {
        let Some((&kind, src)) = chunk.split_first() else {
            continue;
        };
        let mut cur = src.to_vec();
        for i in 0..cur.len() {
            let left = if i >= bpp {
                cur.get(i.saturating_sub(bpp)).copied().unwrap_or(0)
            } else {
                0
            };
            let up = prev.get(i).copied().unwrap_or(0);
            let up_left = if i >= bpp {
                prev.get(i.saturating_sub(bpp)).copied().unwrap_or(0)
            } else {
                0
            };
            let add = match kind {
                1 => left,
                2 => up,
                3 => {
                    let avg = (u16::from(left).saturating_add(u16::from(up))) >> 1;
                    avg.to_le_bytes().first().copied().unwrap_or(0)
                }
                4 => paeth(left, up, up_left),
                _ => 0,
            };
            if let Some(x) = cur.get_mut(i) {
                *x = x.wrapping_add(add);
            }
        }
        out.extend_from_slice(&cur);
        for (p, c) in prev.iter_mut().zip(cur.iter()) {
            *p = *c;
        }
    }
    out
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (ia, ib, ic) = (i16::from(a), i16::from(b), i16::from(c));
    let p = ia.saturating_add(ib).saturating_sub(ic);
    let pa = p.saturating_sub(ia).saturating_abs();
    let pb = p.saturating_sub(ib).saturating_abs();
    let pc = p.saturating_sub(ic).saturating_abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

fn ascii_hex(input: &[u8], sink: &mut Sink<'_, '_>) -> Result<()> {
    let mut high: Option<u8> = None;
    for (i, &c) in input.iter().enumerate() {
        if i % CHUNK == 0 {
            sink.check_cancel()?;
        }
        if c == b'>' {
            break;
        }
        if crate::lexer::is_ws(c) {
            continue;
        }
        let v = crate::lexer::hexval(c).ok_or(PdfError::Malformed {
            object: Some(sink.ctx.object),
            offset: 0,
        })?;
        match high.take() {
            None => high = Some(v),
            Some(h) => sink.push(h << 4 | v)?,
        }
    }
    if let Some(h) = high {
        sink.push(h << 4)?;
    }
    Ok(())
}

fn ascii85(input: &[u8], sink: &mut Sink<'_, '_>) -> Result<()> {
    let object = sink.ctx.object;
    let bad = PdfError::Malformed {
        object: Some(object),
        offset: 0,
    };
    let body = input.strip_prefix(b"<~").unwrap_or(input);
    let mut group: [u8; 5] = [0; 5];
    let mut n: usize = 0;
    for (i, &c) in body.iter().enumerate() {
        if i % CHUNK == 0 {
            sink.check_cancel()?;
        }
        if crate::lexer::is_ws(c) {
            continue;
        }
        if c == b'~' {
            break;
        }
        if c == b'z' && n == 0 {
            sink.extend(&[0, 0, 0, 0])?;
            continue;
        }
        if !(b'!'..=b'u').contains(&c) {
            return Err(bad);
        }
        if let Some(slot) = group.get_mut(n) {
            *slot = c.wrapping_sub(b'!');
        }
        n = n.saturating_add(1);
        if n == 5 {
            let v = a85_value(&group).ok_or(bad.clone())?;
            sink.extend(&v.to_be_bytes())?;
            n = 0;
        }
    }
    if n >= 2 {
        for slot in group.iter_mut().skip(n) {
            *slot = 84; // 'u' - '!'
        }
        let v = a85_value(&group).ok_or(bad)?;
        let bytes = v.to_be_bytes();
        sink.extend(bytes.get(..n.saturating_sub(1)).unwrap_or_default())?;
    }
    Ok(())
}

fn a85_value(g: &[u8; 5]) -> Option<u32> {
    g.iter().try_fold(0u32, |acc, &d| {
        acc.checked_mul(85)?.checked_add(u32::from(d))
    })
}

fn run_length(input: &[u8], sink: &mut Sink<'_, '_>) -> Result<()> {
    let mut i: usize = 0;
    let mut steps: usize = 0;
    while let Some(&len) = input.get(i) {
        steps = steps.saturating_add(1);
        if steps.is_multiple_of(4096) {
            sink.check_cancel()?;
        }
        i = i.saturating_add(1);
        match len {
            128 => break,
            0..=127 => {
                let n = usize::from(len).saturating_add(1);
                let end = i.saturating_add(n).min(input.len());
                sink.extend(input.get(i..end).unwrap_or_default())?;
                i = end;
            }
            _ => {
                let Some(&b) = input.get(i) else { break };
                i = i.saturating_add(1);
                let n = 257usize.saturating_sub(usize::from(len));
                let run = [b; 128];
                sink.extend(run.get(..n).unwrap_or_default())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests index and unwrap freely: a panic is the failure report.
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn never() -> bool {
        false
    }

    fn run(raw: &[u8], names: &[&[u8]], limits: &Limits, budget: &mut Budget) -> Result<Vec<u8>> {
        let filters: Vec<Filter> = names
            .iter()
            .map(|n| Filter {
                name: n.to_vec(),
                parms: None,
            })
            .collect();
        let mut ctx = Ctx {
            limits,
            budget,
            cancel: &never,
            object: 7,
        };
        decode(raw, &filters, &mut ctx)
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec_zlib(data, 9)
    }

    #[test]
    fn decodes_each_supported_filter() {
        let l = Limits::default();
        let mut b = Budget::default();
        assert_eq!(
            run(&zlib(b"hello"), &[b"FlateDecode"], &l, &mut b).unwrap(),
            b"hello"
        );
        assert_eq!(
            run(b"68 65 6c6C6>", &[b"ASCIIHexDecode"], &l, &mut b).unwrap(),
            b"hell`"
        );
        assert_eq!(
            run(b"87cURD]i,\"Ebo80~>", &[b"ASCII85Decode"], &l, &mut b).unwrap(),
            b"Hello World!"
        );
        assert_eq!(
            run(
                &[2, b'a', b'b', b'c', 254, b'z', 128],
                &[b"RunLengthDecode"],
                &l,
                &mut b
            )
            .unwrap(),
            b"abczzz"
        );
        let raw = miniz_oxide::deflate::compress_to_vec(b"raw deflate", 6);
        assert_eq!(
            run(&raw, &[b"FlateDecode"], &l, &mut b).unwrap(),
            b"raw deflate"
        );
    }

    #[test]
    fn png_up_predictor() {
        let rows = [2u8, 1, 2, 3, 2, 1, 1, 1];
        let parms = {
            let mut d = Dictionary::new();
            d.push(b"Predictor".to_vec(), Object::Integer(12));
            d.push(b"Columns".to_vec(), Object::Integer(3));
            d
        };
        let f = [Filter {
            name: b"FlateDecode".to_vec(),
            parms: Some(parms),
        }];
        let l = Limits::default();
        let mut b = Budget::default();
        let mut ctx = Ctx {
            limits: &l,
            budget: &mut b,
            cancel: &never,
            object: 1,
        };
        assert_eq!(
            decode(&zlib(&rows), &f, &mut ctx).unwrap(),
            vec![1, 2, 3, 2, 3, 4]
        );
    }

    #[test]
    fn per_stream_cap_stops_a_bomb() {
        let l = Limits {
            max_stream_bytes: 1 << 20,
            ratio_grace_bytes: 1 << 30,
            ..Limits::default()
        };
        let bomb = zlib(&vec![0u8; 4 << 20]);
        let e = run(&bomb, &[b"FlateDecode"], &l, &mut Budget::default()).unwrap_err();
        assert!(matches!(e, PdfError::StreamTooLarge { .. }), "{e:?}");
    }

    #[test]
    fn ratio_cap_stops_a_chained_bomb() {
        let l = Limits::default();
        let once = zlib(&vec![0u8; 8 << 20]);
        let twice = zlib(&once);
        let e = run(
            &twice,
            &[b"FlateDecode", b"FlateDecode"],
            &l,
            &mut Budget::default(),
        )
        .unwrap_err();
        assert!(matches!(e, PdfError::DecodeRatio { .. }), "{e:?}");
    }

    #[test]
    fn document_budget_is_shared_between_streams() {
        let l = Limits {
            max_total_decoded_bytes: 3 << 20,
            ..Limits::default()
        };
        let mut b = Budget::default();
        let s = zlib(&vec![1u8; 1 << 20]);
        for _ in 0..3 {
            run(&s, &[b"FlateDecode"], &l, &mut b).unwrap();
        }
        let e = run(&s, &[b"FlateDecode"], &l, &mut b).unwrap_err();
        assert!(matches!(e, PdfError::DecodeBudget { .. }), "{e:?}");
    }

    #[test]
    fn chain_cap_and_unsupported_filters() {
        let l = Limits::default();
        let nine: Vec<&[u8]> = vec![b"ASCIIHexDecode"; 9];
        assert!(matches!(
            run(b"", &nine, &l, &mut Budget::default()),
            Err(PdfError::FilterChainTooLong { .. })
        ));
        assert!(matches!(
            run(b"", &[b"JBIG2Decode"], &l, &mut Budget::default()),
            Err(PdfError::UnsupportedFilter { .. })
        ));
    }

    /// A test LZW encoder (ISO 32000-2 §7.4.4.2), with a clear code before the table
    /// fills. The code width follows the decoder's table, which lags the encoder's by
    /// one entry.
    pub(crate) fn lzw_encode(data: &[u8], early: bool) -> Vec<u8> {
        use std::collections::HashMap;
        struct Bits {
            out: Vec<u8>,
            acc: u64,
            n: u32,
            width: u32,
            dec_next: u32,
            first: bool,
            early: u32,
        }
        impl Bits {
            fn put(&mut self, code: u32) {
                self.acc = (self.acc << self.width) | u64::from(code);
                self.n += self.width;
                while self.n >= 8 {
                    self.n -= 8;
                    self.out.push((self.acc >> self.n) as u8);
                }
            }
            /// A data code: the decoder adds an entry after reading it (not after the
            /// first code following a clear) and may widen.
            fn code(&mut self, code: u32) {
                self.put(code);
                if !self.first && self.dec_next < 4096 {
                    self.dec_next += 1;
                    if self.dec_next + self.early >= (1 << self.width) && self.width < 12 {
                        self.width += 1;
                    }
                }
                self.first = false;
            }
            fn clear(&mut self) {
                self.put(256);
                self.width = 9;
                self.dec_next = 258;
                self.first = true;
            }
        }
        let mut b = Bits {
            out: Vec::new(),
            acc: 0,
            n: 0,
            width: 9,
            dec_next: 258,
            first: true,
            early: u32::from(early),
        };
        b.clear();
        // Keyed by (code of the prefix, next byte): linear time.
        let mut dict: HashMap<(u32, u8), u32> = HashMap::new();
        let mut next = 258u32;
        let mut w: Option<u32> = None;
        for &c in data {
            let Some(cur) = w else {
                w = Some(u32::from(c));
                continue;
            };
            if let Some(&code) = dict.get(&(cur, c)) {
                w = Some(code);
                continue;
            }
            b.code(cur);
            dict.insert((cur, c), next);
            next += 1;
            w = Some(u32::from(c));
            if next >= 4000 {
                b.code(u32::from(c));
                b.clear();
                dict.clear();
                next = 258;
                w = None;
            }
        }
        if let Some(cur) = w {
            b.code(cur);
        }
        b.put(257);
        if b.n > 0 {
            b.out.push((b.acc << (8 - b.n)) as u8);
        }
        b.out
    }

    fn lzw_filter(early: Option<i64>, predictor: Option<(i64, i64)>) -> Filter {
        let mut d = Dictionary::new();
        if let Some(e) = early {
            d.push(b"EarlyChange".to_vec(), Object::Integer(e));
        }
        if let Some((p, c)) = predictor {
            d.push(b"Predictor".to_vec(), Object::Integer(p));
            d.push(b"Columns".to_vec(), Object::Integer(c));
        }
        Filter {
            name: b"LZWDecode".to_vec(),
            parms: Some(d),
        }
    }

    fn decode_with(raw: &[u8], f: Filter, limits: &Limits) -> Result<Vec<u8>> {
        let mut b = Budget::default();
        let mut ctx = Ctx {
            limits,
            budget: &mut b,
            cancel: &never,
            object: 9,
        };
        decode(raw, &[f], &mut ctx)
    }

    #[test]
    fn lzw_decodes_the_specification_example() {
        // ISO 32000-2 §7.4.4.2: "-----A---B" is the codes 256 45 258 258 65 259 66 257.
        let raw = [0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        let l = Limits::default();
        assert_eq!(
            run(&raw, &[b"LZWDecode"], &l, &mut Budget::default()).unwrap(),
            b"-----A---B"
        );
        assert_eq!(
            run(&raw, &[b"LZW"], &l, &mut Budget::default()).unwrap(),
            b"-----A---B"
        );
    }

    #[test]
    fn lzw_round_trips_across_every_code_width_and_both_early_change_values() {
        // Enough varied data to pass 512, 1024 and 2048 entries and fill the table.
        let mut data = Vec::new();
        let mut x: u32 = 7;
        for i in 0..200_000u32 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            data.push(if i % 3 == 0 {
                (x >> 16) as u8
            } else {
                b'a' + (i % 7) as u8
            });
        }
        let l = Limits::default();
        for early in [true, false] {
            let raw = lzw_encode(&data, early);
            let parm = if early { None } else { Some(0) };
            let out = decode_with(&raw, lzw_filter(parm, None), &l).unwrap();
            assert_eq!(out.len(), data.len(), "early {early}");
            assert!(out == data, "early {early}");
        }
    }

    #[test]
    fn lzw_with_png_predictor() {
        let rows = [2u8, 1, 2, 3, 2, 1, 1, 1];
        let raw = lzw_encode(&rows, true);
        let out = decode_with(&raw, lzw_filter(None, Some((12, 3))), &Limits::default());
        assert_eq!(out.unwrap(), vec![1, 2, 3, 2, 3, 4]);
    }

    #[test]
    fn lzw_bomb_stops_at_the_ratio_and_stream_caps() {
        let bomb = lzw_encode(&vec![0u8; 16 << 20], true);
        // Default limits: the ratio cap (1:1000 after 1 MiB) stops it.
        let e = decode_with(&bomb, lzw_filter(None, None), &Limits::default()).unwrap_err();
        assert!(matches!(e, PdfError::DecodeRatio { .. }), "{e:?}");
        // With the ratio out of the way, the per-stream cap does.
        let l = Limits {
            max_stream_bytes: 1 << 20,
            ratio_grace_bytes: 1 << 30,
            ..Limits::default()
        };
        let e = decode_with(&bomb, lzw_filter(None, None), &l).unwrap_err();
        assert!(matches!(e, PdfError::StreamTooLarge { .. }), "{e:?}");
        // And the document budget.
        let l = Limits {
            max_total_decoded_bytes: 1 << 20,
            ratio_grace_bytes: 1 << 30,
            ..Limits::default()
        };
        let e = decode_with(&bomb, lzw_filter(None, None), &l).unwrap_err();
        assert!(matches!(e, PdfError::DecodeBudget { .. }), "{e:?}");
    }

    #[test]
    fn lzw_damage_keeps_what_was_decoded() {
        // A code beyond the next free entry after "ab": decoding stops there.
        let mut raw = lzw_encode(b"ab", true);
        raw.truncate(2);
        assert!(decode_with(&raw, lzw_filter(None, None), &Limits::default()).is_ok());
        assert_eq!(
            decode_with(
                &[0xFF, 0xFF, 0xFF],
                lzw_filter(None, None),
                &Limits::default()
            )
            .unwrap(),
            b""
        );
    }

    #[test]
    fn cancellation_stops_inflate() {
        let l = Limits::default();
        let mut b = Budget::default();
        let yes = || true;
        let f = [Filter {
            name: b"FlateDecode".to_vec(),
            parms: None,
        }];
        let mut ctx = Ctx {
            limits: &l,
            budget: &mut b,
            cancel: &yes,
            object: 1,
        };
        assert_eq!(
            decode(&zlib(b"abc"), &f, &mut ctx).unwrap_err(),
            PdfError::Cancelled
        );
    }
}
