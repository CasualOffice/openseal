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
        other => other,
    }
}

/// True for the filters this reader decodes.
pub(crate) fn supported(name: &[u8]) -> bool {
    matches!(
        canonical(name),
        b"FlateDecode" | b"ASCIIHexDecode" | b"ASCII85Decode" | b"RunLengthDecode"
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
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
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
            run(b"", &[b"LZWDecode"], &l, &mut Budget::default()),
            Err(PdfError::UnsupportedFilter { .. })
        ));
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
