//! One field's marks, in the field's own coordinates: points, origin at the
//! bottom-left of the field as displayed, `w` × `h`. The caller places them on the page.

use std::collections::BTreeMap;

use casual_sign_model::{Align, DateFormat, Field, FieldType, FieldValue, FontFamily, Id, Text};

use crate::canvas::{Canvas, Color, GlyphUse, num, num_fine};
use crate::error::FlattenError;
use crate::fonts::FontSet;
use crate::image::{Image, ImageError, load};
use crate::limits::{MAX_INK_POINTS, MAX_TEXT_BYTES};
use crate::text::{Setting, map, set};
use crate::{Art, Capture, FlattenOptions, NotDrawn, ink};

/// Marks for one box, and the images they use (`/Im{n}` is `images[n]`).
#[derive(Debug, Default)]
pub(crate) struct Drawing {
    pub canvas: Canvas,
    pub images: Vec<Image>,
}

/// How the text of a drawing came out.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Fit {
    pub shrunk: bool,
    pub overflow: bool,
}

/// What drawing a field gave.
#[derive(Debug)]
pub(crate) enum Drawn {
    Marks(Drawing, Fit),
    Skip(NotDrawn),
}

/// Shared state while drawing.
#[derive(Debug)]
pub(crate) struct Ctx<'a> {
    pub fonts: &'a FontSet,
    pub uses: &'a mut GlyphUse,
    pub options: &'a FlattenOptions,
    pub envelope_id: Option<&'a str>,
    pub captures: &'a BTreeMap<Id, Capture>,
}

fn bounded<'s>(field: &Field, s: &'s str) -> Result<&'s str, FlattenError> {
    if s.len() > MAX_TEXT_BYTES {
        return Err(FlattenError::TextTooLong {
            field: field.id.clone(),
            bytes: s.len(),
        });
    }
    Ok(s)
}

fn color_of(field: &Field) -> Color {
    field
        .format
        .as_ref()
        .and_then(|f| f.color)
        .map_or(Color::BLACK, |c| Color::from_rgb(c.0))
}

/// The face index for the field's family.
fn face_of(ctx: &Ctx<'_>, field: &Field) -> Result<usize, FlattenError> {
    let family = field
        .format
        .as_ref()
        .and_then(|f| f.font_family)
        .unwrap_or(FontFamily::Helvetica);
    ctx.fonts
        .for_family(family)
        .ok_or_else(|| FlattenError::MissingGlyph {
            field: field.id.clone(),
        })
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `YYYY-MM-DD…` in `format`; any other text unchanged.
pub(crate) fn format_date(value: &str, format: DateFormat) -> String {
    let digits = |r: core::ops::Range<usize>| -> Option<u32> {
        let s = value.get(r)?;
        if s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    let parsed = (|| {
        if value.as_bytes().get(4) != Some(&b'-') || value.as_bytes().get(7) != Some(&b'-') {
            return None;
        }
        let (y, m, d) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
        let month = MONTHS.get(usize::try_from(m.checked_sub(1)?).ok()?)?;
        (1..=31).contains(&d).then_some((y, m, d, *month))
    })();
    let Some((y, m, d, mon)) = parsed else {
        return value.to_owned();
    };
    match format {
        DateFormat::MmDdYyyy => format!("{m:02}/{d:02}/{y:04}"),
        DateFormat::DdMmYyyy => format!("{d:02}/{m:02}/{y:04}"),
        DateFormat::DdMmYyyyDot => format!("{d:02}.{m:02}.{y:04}"),
        DateFormat::DMmmYyyy => format!("{d} {mon} {y:04}"),
        _ => format!("{y:04}-{m:02}-{d:02}"),
    }
}

/// Set `text` in the field's format.
pub(crate) fn text(
    ctx: &mut Ctx<'_>,
    field: &Field,
    text: &str,
    w: f64,
    h: f64,
) -> Result<Drawn, FlattenError> {
    let text = bounded(field, text)?;
    if text.trim().is_empty() {
        return Ok(Drawn::Skip(NotDrawn::NoValue));
    }
    let face = face_of(ctx, field)?;
    let format = field.format.clone().unwrap_or_default();
    let shown = if format.mask {
        let bullet = if ctx.fonts.resolve(face, '\u{2022}').is_some() {
            '\u{2022}'
        } else {
            '*'
        };
        text.chars()
            .filter(|c| !c.is_whitespace())
            .map(|_| bullet)
            .collect::<String>()
    } else {
        text.to_owned()
    };
    let mapped = map(ctx.fonts, face, &shown).map_err(|()| FlattenError::MissingGlyph {
        field: field.id.clone(),
    })?;
    let setting = Setting {
        face,
        size: format
            .font_size
            .map(|p| f64::try_from(p.get()).unwrap_or(crate::text::AUTO_SIZE)),
        shrink: ctx.options.shrink_fixed_sizes,
        wrap: true,
        align: format.align.unwrap_or(Align::Left),
        color: color_of(field),
        padding: 2.0,
        comb: None,
        // A multi-line box reads from its top, as the signer typed it (FG-057).
        top: format.multiline,
    };
    let mut d = Drawing::default();
    let r = set(&mut d.canvas, ctx.uses, ctx.fonts, &mapped, w, h, &setting);
    Ok(Drawn::Marks(
        d,
        Fit {
            shrunk: r.shrunk,
            overflow: r.overflow,
        },
    ))
}

/// A checkmark filling most of the smaller side, centred.
pub(crate) fn checkmark(canvas: &mut Canvas, w: f64, h: f64, color: Color) {
    let side = w.min(h) * 0.8;
    let (x0, y0) = ((w - side) / 2.0, (h - side) / 2.0);
    canvas.line("q");
    canvas.stroke_color(color);
    canvas.line(&format!("{} w 1 J 1 j", num((side * 0.12).max(0.5))));
    canvas.move_to(x0 + side * 0.18, y0 + side * 0.52);
    canvas.line_to(x0 + side * 0.42, y0 + side * 0.24);
    canvas.line_to(x0 + side * 0.84, y0 + side * 0.80);
    canvas.line("S");
    canvas.line("Q");
}

/// A filled dot, as a selected radio button.
pub(crate) fn dot(canvas: &mut Canvas, w: f64, h: f64, color: Color) {
    canvas.fill_color(color);
    canvas.circle(w / 2.0, h / 2.0, w.min(h) * 0.25);
    canvas.line("f");
}

/// A radio group drawn by the engine: one row per option, a ring and its label, the
/// chosen one with a dot.
fn radio_list(
    ctx: &mut Ctx<'_>,
    field: &Field,
    chosen: &str,
    w: f64,
    h: f64,
) -> Result<Drawn, FlattenError> {
    let options = field.options.as_slice();
    if options.is_empty() {
        return text(ctx, field, chosen, w, h);
    }
    let n = options.len() as f64;
    let row = h / n;
    let color = color_of(field);
    let face = face_of(ctx, field)?;
    let mut d = Drawing::default();
    let mut fit = Fit::default();
    let ring = (row * 0.7).min(12.0).min(w);
    for (i, opt) in options.iter().enumerate() {
        let y = h - row * (i as f64 + 1.0);
        let (cx, cy) = (ring / 2.0, y + row / 2.0);
        d.canvas.line("q");
        d.canvas.stroke_color(color);
        d.canvas.line(&format!("{} w", num((ring * 0.08).max(0.3))));
        d.canvas.circle(cx, cy, ring * 0.45);
        d.canvas.line("S");
        if opt.as_str() == chosen {
            d.canvas.fill_color(color);
            d.canvas.circle(cx, cy, ring * 0.22);
            d.canvas.line("f");
        }
        d.canvas.line("Q");
        let mapped =
            map(ctx.fonts, face, opt.as_str()).map_err(|()| FlattenError::MissingGlyph {
                field: field.id.clone(),
            })?;
        let setting = Setting {
            face,
            size: None,
            shrink: true,
            wrap: false,
            align: Align::Left,
            color,
            padding: 1.0,
            comb: None,
            top: false,
        };
        let lx = ring * 1.3;
        d.canvas.line("q");
        d.canvas.line(&format!("1 0 0 1 {} {} cm", num(lx), num(y)));
        let r = set(
            &mut d.canvas,
            ctx.uses,
            ctx.fonts,
            &mapped,
            (w - lx).max(0.1),
            row,
            &setting,
        );
        d.canvas.line("Q");
        fit.shrunk |= r.shrunk;
        fit.overflow |= r.overflow;
    }
    Ok(Drawn::Marks(d, fit))
}

/// The cm placing the unit square of an image with EXIF `orientation` upright in the
/// unit square.
fn orient(orientation: u8) -> [f64; 6] {
    match orientation {
        2 => [-1.0, 0.0, 0.0, 1.0, 1.0, 0.0],
        3 => [-1.0, 0.0, 0.0, -1.0, 1.0, 1.0],
        4 => [1.0, 0.0, 0.0, -1.0, 0.0, 1.0],
        5 => [0.0, -1.0, -1.0, 0.0, 1.0, 1.0],
        6 => [0.0, -1.0, 1.0, 0.0, 0.0, 1.0],
        7 => [0.0, 1.0, 1.0, 0.0, 0.0, 0.0],
        8 => [0.0, 1.0, -1.0, 0.0, 1.0, 0.0],
        _ => [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    }
}

fn cm(m: [f64; 6]) -> String {
    let [a, b, c, d, e, f] = m;
    format!(
        "{} {} {} {} {} {} cm",
        num_fine(a),
        num_fine(b),
        num_fine(c),
        num_fine(d),
        num_fine(e),
        num_fine(f)
    )
}

/// Draw `image` fitted (contained, centred) in the area.
fn place_image(d: &mut Drawing, image: Image, x0: f64, y0: f64, w: f64, h: f64) {
    let (iw, ih) = (f64::from(image.width), f64::from(image.height));
    let (dw, dh) = if image.orientation >= 5 {
        (ih, iw)
    } else {
        (iw, ih)
    };
    let scale = (w / dw).min(h / dh);
    let (sw, sh) = (dw * scale, dh * scale);
    let (x, y) = (x0 + (w - sw) / 2.0, y0 + (h - sh) / 2.0);
    let index = d.images.len();
    let o = orient(image.orientation);
    d.images.push(image);
    d.canvas.images.insert(index);
    d.canvas.line("q");
    d.canvas.line(&cm([sw, 0.0, 0.0, sh, x, y]));
    d.canvas.line(&cm(o));
    d.canvas.line(&format!("/Im{index} Do"));
    d.canvas.line("Q");
}

/// A signature, initials, stamp or drawing.
fn capture(
    ctx: &mut Ctx<'_>,
    field: &Field,
    id: &Id,
    w: f64,
    h: f64,
) -> Result<Drawn, FlattenError> {
    let captures = ctx.captures;
    let cap = captures
        .get(id)
        .ok_or_else(|| FlattenError::UnknownCapture {
            field: field.id.clone(),
        })?;
    let mut d = Drawing::default();
    let mut fit = Fit::default();
    // Captions belong to signatures and initials, not to stamps or drawings.
    let signs = matches!(field.field_type, FieldType::Signature | FieldType::Initials);
    let captioned = ctx.options.signed_by_line && signs;
    let mut caption: Vec<String> = Vec::new();
    if captioned {
        let by = match &cap.signed_by {
            Some(name) => format!("Signed by: {}", bounded(field, name)?),
            None => "Signed".to_owned(),
        };
        caption.push(by);
        if let Some(env) = ctx.envelope_id {
            caption.push(bounded(field, env)?.to_owned());
        }
    }
    if signs && let Some(reason) = &cap.reason {
        caption.push(format!("Reason: {}", bounded(field, reason)?));
    }
    let band = if caption.is_empty() {
        0.0
    } else {
        (h * 0.3).clamp(0.0, 8.0 * caption.len() as f64)
    };
    let (ax, ay, aw, ah) = (0.0, band, w, (h - band).max(0.1));
    match &cap.art {
        Art::Drawn(strokes) => {
            let n = ink::count(strokes).unwrap_or(usize::MAX);
            if n > MAX_INK_POINTS {
                return Err(FlattenError::TooManyPoints {
                    field: field.id.clone(),
                    points: n,
                });
            }
            ink::draw(&mut d.canvas, strokes, ax, ay, aw, ah);
        }
        Art::Image(bytes) => {
            let image = load(bytes).map_err(|e| match e {
                ImageError::TooLarge => FlattenError::ImageTooLarge {
                    field: field.id.clone(),
                },
                ImageError::Undecodable => FlattenError::ImageUndecodable {
                    field: field.id.clone(),
                },
            })?;
            place_image(&mut d, image, ax, ay, aw, ah);
        }
        Art::Typed { text, style } => {
            let text = bounded(field, text)?;
            let face = ctx
                .fonts
                .script(*style)
                .ok_or_else(|| FlattenError::MissingGlyph {
                    field: field.id.clone(),
                })?;
            let mapped = map(ctx.fonts, face, text).map_err(|()| FlattenError::MissingGlyph {
                field: field.id.clone(),
            })?;
            let setting = Setting {
                face,
                size: Some(ah * 0.8),
                shrink: true,
                wrap: false,
                align: Align::Center,
                color: color_of(field),
                padding: 1.0,
                comb: None,
                top: false,
            };
            d.canvas.line("q");
            d.canvas
                .line(&format!("1 0 0 1 {} {} cm", num(ax), num(ay)));
            let r = set(
                &mut d.canvas,
                ctx.uses,
                ctx.fonts,
                &mapped,
                aw,
                ah,
                &setting,
            );
            d.canvas.line("Q");
            fit.shrunk |= r.shrunk;
            fit.overflow |= r.overflow;
        }
    }
    if !caption.is_empty() {
        let face = ctx.fonts.for_family(FontFamily::Helvetica).ok_or_else(|| {
            FlattenError::MissingGlyph {
                field: field.id.clone(),
            }
        })?;
        let row = band / caption.len() as f64;
        for (i, line) in caption.iter().enumerate() {
            let mapped = map(ctx.fonts, face, line).map_err(|()| FlattenError::MissingGlyph {
                field: field.id.clone(),
            })?;
            let setting = Setting {
                face,
                size: Some((row * 0.85).min(7.0)),
                shrink: true,
                wrap: false,
                align: Align::Left,
                color: Color([0.25, 0.25, 0.25]),
                padding: 0.5,
                comb: None,
                top: false,
            };
            let y = band - row * (i as f64 + 1.0);
            d.canvas.line("q");
            d.canvas.line(&format!("1 0 0 1 0 {} cm", num(y)));
            set(
                &mut d.canvas,
                ctx.uses,
                ctx.fonts,
                &mapped,
                w,
                row,
                &setting,
            );
            d.canvas.line("Q");
        }
    }
    Ok(Drawn::Marks(d, fit))
}

/// The marks for `field` showing `value`, in a `w` × `h` box.
pub(crate) fn field(
    ctx: &mut Ctx<'_>,
    field: &Field,
    value: &FieldValue,
    w: f64,
    h: f64,
) -> Result<Drawn, FlattenError> {
    let mismatch = || FlattenError::ValueMismatch {
        field: field.id.clone(),
    };
    match field.field_type {
        FieldType::Attachment | FieldType::Approve | FieldType::Decline => {
            Ok(Drawn::Skip(NotDrawn::NoVisual))
        }
        FieldType::Signature | FieldType::Initials | FieldType::Stamp | FieldType::Drawing => {
            match value {
                FieldValue::Signature(id) | FieldValue::Attachment(id) => {
                    capture(ctx, field, id, w, h)
                }
                _ => Err(mismatch()),
            }
        }
        FieldType::Checkbox => match value {
            FieldValue::Checked(true) => {
                let mut d = Drawing::default();
                checkmark(&mut d.canvas, w, h, color_of(field));
                Ok(Drawn::Marks(d, Fit::default()))
            }
            FieldValue::Checked(false) => Ok(Drawn::Skip(NotDrawn::NoValue)),
            _ => Err(mismatch()),
        },
        FieldType::RadioGroup => match value {
            FieldValue::Choice(t) | FieldValue::Text(t) => {
                if t.is_empty() {
                    Ok(Drawn::Skip(NotDrawn::NoValue))
                } else {
                    radio_list(ctx, field, t.as_str(), w, h)
                }
            }
            _ => Err(mismatch()),
        },
        FieldType::DateSigned => match value {
            FieldValue::Text(t) => {
                let format = field
                    .format
                    .as_ref()
                    .and_then(|f| f.date_format)
                    .unwrap_or_default();
                let shown = format_date(t.as_str(), format);
                text(ctx, field, &shown, w, h)
            }
            _ => Err(mismatch()),
        },
        // The chosen options, one a line, in the field's order whatever order they were
        // chosen in (ACRO-02).
        FieldType::MultiSelect => match value {
            FieldValue::Choices(chosen) => {
                let offered = field.options.as_slice();
                let lines: Vec<&str> = offered
                    .iter()
                    .filter(|o| chosen.contains(o.as_str()))
                    .chain(
                        chosen
                            .as_slice()
                            .iter()
                            .filter(|c| !field.options.contains(c.as_str())),
                    )
                    .map(Text::as_str)
                    .collect();
                text(ctx, field, &lines.join("\n"), w, h)
            }
            _ => Err(mismatch()),
        },
        _ => match value {
            FieldValue::Text(t) | FieldValue::Choice(t) => text(ctx, field, t.as_str(), w, h),
            _ => Err(mismatch()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_take_the_field_format_and_other_text_is_kept() {
        assert_eq!(
            format_date("2026-03-07", DateFormat::DMmmYyyy),
            "7 Mar 2026"
        );
        assert_eq!(
            format_date("2026-03-07T10:00Z", DateFormat::MmDdYyyy),
            "03/07/2026"
        );
        assert_eq!(
            format_date("2026-03-07", DateFormat::DdMmYyyyDot),
            "07.03.2026"
        );
        assert_eq!(format_date("7 March", DateFormat::MmDdYyyy), "7 March");
        assert_eq!(
            format_date("2026-13-07", DateFormat::MmDdYyyy),
            "2026-13-07"
        );
    }

    #[test]
    fn every_orientation_maps_the_unit_square_onto_itself() {
        for o in 1..=8 {
            let [a, b, c, d, e, f] = orient(o);
            for (u, v) in [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)] {
                let (x, y) = (a * u + c * v + e, b * u + d * v + f);
                assert!((0.0..=1.0).contains(&x) && (0.0..=1.0).contains(&y), "{o}");
            }
        }
    }
}
