//! `FILL-01`: values written into the document's own AcroForm fields, which stay
//! fillable. Each field gets `/V`; each widget gets a new normal appearance drawn with
//! an embedded subset face (`/DA`'s size, colour and family honoured), or, for check
//! boxes and radio buttons, its `/AS` state; `/NeedAppearances` is cleared so viewers
//! show these appearances rather than make their own.

use std::collections::BTreeMap;

use casual_sign_model::{Align, FontFamily};
use casual_sign_pdf::{Cancel, Dictionary, Document, FieldType as PdfFieldType, Object, PdfError};

use crate::canvas::{Canvas, Color, GlyphUse, num};
use casual_sign_fields::RadioChoice;

use crate::draw::{checkmark, dot};
use crate::error::FlattenError;
use crate::fonts::FontSet;
use crate::read::{self, FieldAttrs, WidgetInfo};
use crate::text::{Setting, map, set};

const FF_MULTILINE: i64 = 1 << 12;
const FF_PASSWORD: i64 = 1 << 13;
const FF_COMBO: i64 = 1 << 17;
const FF_COMB: i64 = 1 << 24;

/// The value a field is filled with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FillValue {
    Text(String),
    Checked(bool),
    /// A radio state or a choice's display text.
    Choice(String),
    /// A multi-select list's chosen display texts (ACRO-02).
    Choices(Vec<String>),
}

/// A new appearance stream for a widget.
#[derive(Debug)]
pub(crate) struct Appearance {
    pub widget: u32,
    pub canvas: Canvas,
    pub w: f64,
    pub h: f64,
    pub matrix: Option<[f64; 6]>,
    /// For a check box: the on-state name; the stream is its `/N /<on>` entry and an
    /// empty `/Off` is written beside it.
    pub on_state: Option<Vec<u8>>,
}

/// What filling changes.
#[derive(Debug, Default)]
pub(crate) struct FillPlan {
    /// Field and widget dictionaries, changed, by object number.
    pub edits: BTreeMap<u32, Dictionary>,
    pub appearances: Vec<Appearance>,
}

/// A PDF text string: PDFDocEncoding when printable ASCII, else UTF-16BE with a BOM.
pub(crate) fn text_string(s: &str) -> Vec<u8> {
    if s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return s.as_bytes().to_vec();
    }
    let mut out = vec![0xFE, 0xFF];
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}

/// What `/DA` says: font resource name, size (0 = automatic) and colour.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Da {
    pub font: Vec<u8>,
    pub size: f64,
    pub color: Color,
}

/// Parse a default appearance string (`/Helv 12 Tf 0 g`).
pub(crate) fn parse_da(da: &[u8]) -> Da {
    let mut out = Da {
        font: Vec::new(),
        size: 0.0,
        color: Color::BLACK,
    };
    let text = String::from_utf8_lossy(da);
    let tokens: Vec<&str> = text.split_whitespace().take(256).collect();
    let numbers = |end: usize, n: usize| -> Option<Vec<f64>> {
        let start = end.checked_sub(n)?;
        tokens
            .get(start..end)?
            .iter()
            .map(|t| t.parse::<f64>().ok().filter(|v| v.is_finite()))
            .collect()
    };
    for (i, t) in tokens.iter().enumerate() {
        match *t {
            "Tf" => {
                if let (Some(name), Some(size)) =
                    (i.checked_sub(2).and_then(|j| tokens.get(j)), numbers(i, 1))
                {
                    out.font = name.trim_start_matches('/').as_bytes().to_vec();
                    out.size = size.first().copied().unwrap_or(0.0).clamp(0.0, 1_000.0);
                }
            }
            "g" => {
                if let Some(v) = numbers(i, 1)
                    && let [g] = v.as_slice()
                {
                    out.color = Color([*g, *g, *g]);
                }
            }
            "rg" => {
                if let Some(v) = numbers(i, 3)
                    && let [r, g, b] = v.as_slice()
                {
                    out.color = Color([*r, *g, *b]);
                }
            }
            "k" => {
                if let Some(v) = numbers(i, 4)
                    && let [c, m, y, k] = v.as_slice()
                {
                    out.color = Color([
                        (1.0 - c) * (1.0 - k),
                        (1.0 - m) * (1.0 - k),
                        (1.0 - y) * (1.0 - k),
                    ]);
                }
            }
            _ => {}
        }
    }
    out
}

/// The family a `/DA` font name suggests.
fn family_of(font: &[u8]) -> FontFamily {
    let f = String::from_utf8_lossy(font).to_ascii_lowercase();
    if f.contains("cour") || f.contains("mono") {
        FontFamily::Courier
    } else if f.contains("tiro") || f.contains("times") || f.contains("serif") {
        FontFamily::Times
    } else {
        FontFamily::Helvetica
    }
}

/// The widget's box in its own orientation (`/MK /R`) and the matrix that turns it.
fn widget_box(w: &WidgetInfo) -> (f64, f64, Option<[f64; 6]>) {
    let (rw, rh) = (w.rect.urx - w.rect.llx, w.rect.ury - w.rect.lly);
    let rot = w
        .dict
        .get(b"MK")
        .and_then(Object::dict)
        .and_then(|mk| mk.get(b"R"))
        .and_then(Object::as_i64)
        .unwrap_or(0)
        .rem_euclid(360);
    match rot {
        90 => (rh, rw, Some([0.0, 1.0, -1.0, 0.0, rw, 0.0])),
        180 => (rw, rh, Some([-1.0, 0.0, 0.0, -1.0, rw, rh])),
        270 => (rh, rw, Some([0.0, -1.0, 1.0, 0.0, 0.0, rh])),
        _ => (rw, rh, None),
    }
}

/// Border width and the background/border colours from `/MK` and `/BS`.
fn frame(w: &WidgetInfo) -> (f64, Option<[f64; 3]>, Option<[f64; 3]>) {
    let mk = w.dict.get(b"MK").and_then(Object::dict);
    let bg = read::mk_color(mk.and_then(|m| m.get(b"BG")));
    let bc = read::mk_color(mk.and_then(|m| m.get(b"BC")));
    let bw = w
        .dict
        .get(b"BS")
        .and_then(Object::dict)
        .and_then(|bs| bs.get(b"W"))
        .and_then(Object::as_f64)
        .unwrap_or(1.0)
        .clamp(0.0, 12.0);
    (if bc.is_some() { bw } else { 0.0 }, bg, bc)
}

/// Background and border, as a widget shows them.
pub(crate) fn draw_frame(
    canvas: &mut Canvas,
    w: &WidgetInfo,
    width: f64,
    height: f64,
    round: bool,
) {
    let (bw, bg, bc) = frame(w);
    if let Some(bg) = bg {
        canvas.fill_color(Color(bg));
        if round {
            canvas.circle(width / 2.0, height / 2.0, width.min(height) / 2.0);
            canvas.line("f");
        } else {
            canvas.rect(0.0, 0.0, width, height, "f");
        }
    }
    if let Some(bc) = bc
        && bw > 0.0
    {
        canvas.stroke_color(Color(bc));
        canvas.line(&format!("{} w", num(bw)));
        if round {
            canvas.circle(width / 2.0, height / 2.0, (width.min(height) - bw) / 2.0);
            canvas.line("S");
        } else {
            canvas.rect(
                bw / 2.0,
                bw / 2.0,
                (width - bw).max(0.0),
                (height - bw).max(0.0),
                "S",
            );
        }
    }
}

/// The display texts and export values of `/Opt`.
fn options(
    doc: &mut Document<'_>,
    opt: &[Object],
    cancel: Cancel<'_>,
) -> Result<Vec<(Vec<u8>, String)>, PdfError> {
    let mut out = Vec::new();
    for o in opt.iter().take(1_000) {
        let o = read::local(doc.resolve(o, cancel))?;
        let pair = match &o {
            Some(Object::String(s)) => Some((s.clone(), s.clone())),
            Some(Object::Array(p)) => match (p.first(), p.get(1)) {
                (Some(Object::String(e)), Some(Object::String(d))) => Some((e.clone(), d.clone())),
                (Some(Object::String(e)), None) => Some((e.clone(), e.clone())),
                _ => None,
            },
            _ => None,
        };
        if let Some((export, display)) = pair {
            out.push((export, decode_text(&display)));
        }
    }
    Ok(out)
}

/// A PDF text string to Rust (UTF-16BE, UTF-8 with BOM, else PDFDocEncoding), exactly
/// as conversion decodes option texts, so a chosen text finds its export value.
pub(crate) fn decode_text(b: &[u8]) -> String {
    casual_sign_pdf::decode_text_string(b)
}

/// Inputs to filling one PDF field.
#[derive(Debug)]
pub(crate) struct Target<'a> {
    pub object: u32,
    pub kind: PdfFieldType,
    pub value: &'a FillValue,
    pub widgets: &'a [WidgetInfo],
    /// A radio group's choices ([`casual_sign_fields::radio_choices`]); empty otherwise.
    pub choices: &'a [RadioChoice],
    pub field_id: &'a casual_sign_model::Id,
}

/// Plan the changes for one field.
#[allow(clippy::too_many_arguments)] // Each argument is a distinct input of the plan.
pub(crate) fn plan_field(
    doc: &mut Document<'_>,
    plan: &mut FillPlan,
    uses: &mut GlyphUse,
    fonts: &FontSet,
    default_da: Option<&[u8]>,
    t: &Target<'_>,
    cancel: Cancel<'_>,
) -> Result<(), FlattenError> {
    let base = match plan.edits.get(&t.object) {
        Some(d) => Some(d.clone()),
        None => read::object_dict(doc, t.object, cancel)?,
    };
    let Some(mut field) = base else {
        return Ok(());
    };
    let attrs: FieldAttrs = read::field_attrs(doc, &field, cancel)?;
    let mismatch = || FlattenError::ValueMismatch {
        field: t.field_id.clone(),
    };
    match t.kind {
        PdfFieldType::CheckBox => {
            let FillValue::Checked(on) = t.value else {
                return Err(mismatch());
            };
            let first_on = t
                .widgets
                .iter()
                .find_map(|w| w.on_states.first().cloned())
                .unwrap_or_else(|| b"Yes".to_vec());
            field.insert(
                b"V",
                Object::Name(if *on {
                    first_on.clone()
                } else {
                    b"Off".to_vec()
                }),
            );
            plan.edits.insert(t.object, field);
            for w in t.widgets {
                // A box whose widgets have different on-states acts like a radio
                // group: only the widgets with the chosen state turn on.
                let state = first_on.clone();
                let shows = w.on_states.is_empty() || w.on_states.contains(&state);
                let mut wd = plan
                    .edits
                    .get(&w.object)
                    .cloned()
                    .unwrap_or_else(|| w.dict.clone());
                wd.insert(
                    b"AS",
                    Object::Name(if *on && shows {
                        state.clone()
                    } else {
                        b"Off".to_vec()
                    }),
                );
                plan.edits.insert(w.object, wd);
                if w.on_states.is_empty() {
                    let (bw, bh, matrix) = widget_box(w);
                    let mut canvas = Canvas::default();
                    draw_frame(&mut canvas, w, bw, bh, false);
                    checkmark(
                        &mut canvas,
                        bw,
                        bh,
                        parse_da(attrs.da.as_deref().or(default_da).unwrap_or(b"")).color,
                    );
                    plan.appearances.push(Appearance {
                        widget: w.object,
                        canvas,
                        w: bw,
                        h: bh,
                        matrix,
                        on_state: Some(state),
                    });
                }
            }
        }
        PdfFieldType::Radio => {
            let (FillValue::Choice(state) | FillValue::Text(state)) = t.value else {
                return Err(mismatch());
            };
            // The chosen option's state, in the document's own bytes (FLD-RADIO-NAME).
            let Some(choice) = t.choices.iter().find(|c| c.text == *state) else {
                return Err(mismatch());
            };
            let Some(name) = choice.widgets.first().map(|w| w.state.clone()) else {
                return Err(mismatch());
            };
            field.insert(b"V", Object::Name(name.clone()));
            plan.edits.insert(t.object, field);
            let color = parse_da(attrs.da.as_deref().or(default_da).unwrap_or(b"")).color;
            for w in t.widgets {
                let mut wd = plan
                    .edits
                    .get(&w.object)
                    .cloned()
                    .unwrap_or_else(|| w.dict.clone());
                let on = choice.widgets.iter().find(|c| c.widget == w.object);
                let s = if on.is_some() {
                    name.clone()
                } else {
                    b"Off".to_vec()
                };
                wd.insert(b"AS", Object::Name(s));
                plan.edits.insert(w.object, wd);
                // A button with no appearance for its state (FLD-RADIO-NOOPT): draw
                // the standard radio mark, a dot, as its `/N /<state>`.
                if on.is_some_and(|c| !c.has_appearance) {
                    let (bw, bh, matrix) = widget_box(w);
                    let mut canvas = Canvas::default();
                    draw_frame(&mut canvas, w, bw, bh, true);
                    dot(&mut canvas, bw, bh, color);
                    plan.appearances.push(Appearance {
                        widget: w.object,
                        canvas,
                        w: bw,
                        h: bh,
                        matrix,
                        on_state: Some(name.clone()),
                    });
                }
            }
        }
        PdfFieldType::Choice if matches!(t.value, FillValue::Choices(_)) => {
            let FillValue::Choices(chosen) = t.value else {
                return Err(mismatch());
            };
            plan_multi(
                doc, plan, uses, fonts, default_da, t, field, &attrs, chosen, cancel,
            )?;
        }
        PdfFieldType::Text | PdfFieldType::Choice => {
            let (FillValue::Text(text) | FillValue::Choice(text)) = t.value else {
                return Err(mismatch());
            };
            if text.len() > crate::limits::MAX_TEXT_BYTES {
                return Err(FlattenError::TextTooLong {
                    field: t.field_id.clone(),
                    bytes: text.len(),
                });
            }
            let opts = match &attrs.opt {
                Some(o) => options(doc, o, cancel)?,
                None => Vec::new(),
            };
            let export = opts
                .iter()
                .find(|(_, d)| d == text)
                .map_or_else(|| text_string(text), |(e, _)| e.clone());
            field.insert(b"V", Object::String(export));
            // A list's selected indices and a rich-text value would contradict /V.
            field.remove(b"I");
            field.remove(b"RV");
            plan.edits.insert(t.object, field);
            let da = parse_da(
                attrs
                    .da
                    .as_deref()
                    .or(default_da)
                    .unwrap_or(b"/Helv 0 Tf 0 g"),
            );
            let face = fonts.for_family(family_of(&da.font)).ok_or_else(|| {
                FlattenError::MissingGlyph {
                    field: t.field_id.clone(),
                }
            })?;
            let list_box = t.kind == PdfFieldType::Choice && attrs.ff & FF_COMBO == 0;
            let shown = if attrs.ff & FF_PASSWORD != 0 {
                text.chars().map(|_| '*').collect::<String>()
            } else {
                text.clone()
            };
            for w in t.widgets {
                plan.edits.entry(w.object).or_insert_with(|| w.dict.clone());
                let (bw, bh, matrix) = widget_box(w);
                let (border, _, _) = frame(w);
                let mut canvas = Canvas::default();
                draw_frame(&mut canvas, w, bw, bh, false);
                canvas.line("/Tx BMC");
                canvas.line("q");
                canvas.rect(
                    border,
                    border,
                    (bw - 2.0 * border).max(0.0),
                    (bh - 2.0 * border).max(0.0),
                    "W n",
                );
                let setting = |wrap: bool, comb: Option<u32>| Setting {
                    face,
                    size: (da.size > 0.0).then_some(da.size),
                    shrink: da.size <= 0.0,
                    wrap,
                    align: match attrs.q {
                        Some(1) => Align::Center,
                        Some(2) => Align::Right,
                        _ => Align::Left,
                    },
                    color: da.color,
                    padding: 2.0 + border,
                    comb,
                };
                if list_box && !opts.is_empty() {
                    list(
                        &mut canvas,
                        uses,
                        fonts,
                        &opts,
                        &[text.as_str()],
                        bw,
                        bh,
                        &setting(false, None),
                        t,
                    )?;
                } else {
                    let multiline = attrs.ff & FF_MULTILINE != 0;
                    let comb = (attrs.ff & FF_COMB != 0 && !multiline)
                        .then_some(attrs.max_len)
                        .flatten();
                    let mapped =
                        map(fonts, face, &shown).map_err(|()| FlattenError::MissingGlyph {
                            field: t.field_id.clone(),
                        })?;
                    set(
                        &mut canvas,
                        uses,
                        fonts,
                        &mapped,
                        bw,
                        bh,
                        &setting(multiline, comb),
                    );
                }
                canvas.line("Q");
                canvas.line("EMC");
                plan.appearances.push(Appearance {
                    widget: w.object,
                    canvas,
                    w: bw,
                    h: bh,
                    matrix,
                    on_state: None,
                });
            }
        }
        _ => return Err(mismatch()),
    }
    Ok(())
}

/// A multi-select list box filled in place (ACRO-02): `/V` the chosen options' export
/// values in `/Opt` order (one string for one, an array for several, absent for none),
/// `/I` their indices, and an appearance with each highlighted.
#[allow(clippy::too_many_arguments)] // Each argument is a distinct input of the plan.
fn plan_multi(
    doc: &mut Document<'_>,
    plan: &mut FillPlan,
    uses: &mut GlyphUse,
    fonts: &FontSet,
    default_da: Option<&[u8]>,
    t: &Target<'_>,
    mut field: Dictionary,
    attrs: &FieldAttrs,
    chosen: &[String],
    cancel: Cancel<'_>,
) -> Result<(), FlattenError> {
    let total: usize = chosen.iter().map(String::len).sum();
    if total > crate::limits::MAX_TEXT_BYTES {
        return Err(FlattenError::TextTooLong {
            field: t.field_id.clone(),
            bytes: total,
        });
    }
    let opts = match &attrs.opt {
        Some(o) => options(doc, o, cancel)?,
        None => Vec::new(),
    };
    let mut exports: Vec<Object> = Vec::new();
    let mut indices: Vec<Object> = Vec::new();
    for (i, (export, display)) in opts.iter().enumerate() {
        if chosen.iter().any(|c| c == display) {
            exports.push(Object::String(export.clone()));
            indices.push(Object::Integer(i64::try_from(i).unwrap_or(i64::MAX)));
        }
    }
    // A choice the document does not list (validation refuses these) keeps its text.
    for c in chosen {
        if !opts.iter().any(|(_, d)| d == c) {
            exports.push(Object::String(text_string(c)));
        }
    }
    match exports.len() {
        0 => {
            field.remove(b"V");
        }
        1 => {
            if let Some(v) = exports.pop() {
                field.insert(b"V", v);
            }
        }
        _ => {
            field.insert(b"V", Object::Array(exports));
        }
    }
    if indices.is_empty() {
        field.remove(b"I");
    } else {
        field.insert(b"I", Object::Array(indices));
    }
    field.remove(b"RV");
    plan.edits.insert(t.object, field);
    let da = parse_da(
        attrs
            .da
            .as_deref()
            .or(default_da)
            .unwrap_or(b"/Helv 0 Tf 0 g"),
    );
    let face = fonts
        .for_family(family_of(&da.font))
        .ok_or_else(|| FlattenError::MissingGlyph {
            field: t.field_id.clone(),
        })?;
    let chosen: Vec<&str> = chosen.iter().map(String::as_str).collect();
    for w in t.widgets {
        plan.edits.entry(w.object).or_insert_with(|| w.dict.clone());
        let (bw, bh, matrix) = widget_box(w);
        let (border, _, _) = frame(w);
        let mut canvas = Canvas::default();
        draw_frame(&mut canvas, w, bw, bh, false);
        canvas.line("/Tx BMC");
        canvas.line("q");
        canvas.rect(
            border,
            border,
            (bw - 2.0 * border).max(0.0),
            (bh - 2.0 * border).max(0.0),
            "W n",
        );
        let setting = Setting {
            face,
            size: (da.size > 0.0).then_some(da.size),
            shrink: da.size <= 0.0,
            wrap: false,
            align: match attrs.q {
                Some(1) => Align::Center,
                Some(2) => Align::Right,
                _ => Align::Left,
            },
            color: da.color,
            padding: 2.0 + border,
            comb: None,
        };
        list(
            &mut canvas,
            uses,
            fonts,
            &opts,
            &chosen,
            bw,
            bh,
            &setting,
            t,
        )?;
        canvas.line("Q");
        canvas.line("EMC");
        plan.appearances.push(Appearance {
            widget: w.object,
            canvas,
            w: bw,
            h: bh,
            matrix,
            on_state: None,
        });
    }
    Ok(())
}

/// A list box: options from the top, the chosen ones highlighted.
#[allow(clippy::too_many_arguments)] // The setting is shared with the caller's text path.
fn list(
    canvas: &mut Canvas,
    uses: &mut GlyphUse,
    fonts: &FontSet,
    opts: &[(Vec<u8>, String)],
    chosen: &[&str],
    w: f64,
    h: f64,
    s: &Setting,
    t: &Target<'_>,
) -> Result<(), FlattenError> {
    let size = s.size.unwrap_or(12.0).min(h);
    let row = size * 1.15;
    let rows = (h / row).floor().max(1.0);
    for (i, (_, display)) in opts.iter().enumerate() {
        if i as f64 >= rows {
            break;
        }
        let y = h - row * (i as f64 + 1.0);
        if chosen.contains(&display.as_str()) {
            canvas.fill_color(Color([0.6, 0.75, 0.9]));
            canvas.rect(0.0, y, w, row, "f");
        }
        let mapped = map(fonts, s.face, display).map_err(|()| FlattenError::MissingGlyph {
            field: t.field_id.clone(),
        })?;
        canvas.line("q");
        canvas.line(&format!("1 0 0 1 0 {} cm", num(y)));
        let one = Setting {
            size: Some(size),
            shrink: true,
            ..*s
        };
        set(canvas, uses, fonts, &mapped, w, row, &one);
        canvas.line("Q");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn da_strings_give_font_size_and_colour() {
        let da = parse_da(b"/Helv 10.5 Tf 1 0 0 rg");
        assert_eq!(da.font, b"Helv");
        assert_eq!(da.size, 10.5);
        assert_eq!(da.color, Color([1.0, 0.0, 0.0]));
        let auto = parse_da(b"0 g /Cour 0 Tf");
        assert_eq!(auto.size, 0.0);
        assert_eq!(family_of(&auto.font), FontFamily::Courier);
        assert_eq!(parse_da(b"Tf").size, 0.0);
    }

    #[test]
    fn text_strings_use_utf16_only_when_needed() {
        assert_eq!(text_string("Ada"), b"Ada");
        assert_eq!(text_string("é"), vec![0xFE, 0xFF, 0x00, 0xE9]);
        assert_eq!(decode_text(&text_string("Zoë")), "Zoë");
    }
}
