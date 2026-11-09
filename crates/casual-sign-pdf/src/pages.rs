//! Page tree walk (ISO 32000-2 §7.7.3): iterative, with a visited set, a page cap, a
//! depth cap and inherited attributes. `/Count` is never trusted.

use std::collections::BTreeSet;

use crate::Cancel;
use crate::document::Document;
use crate::error::{PdfError, Result};
use crate::object::{Dictionary, Object};
use crate::report::{Finding, PageInfo, Rect};

const LETTER: Rect = Rect {
    llx: 0.0,
    lly: 0.0,
    urx: 612.0,
    ury: 792.0,
};

#[derive(Debug, Clone, Copy, Default)]
struct Inherited {
    media: Option<Rect>,
    crop: Option<Rect>,
    rotate: Option<i64>,
}

/// A page found by the walk: its geometry and its `/Contents` value.
#[derive(Debug)]
pub(crate) struct Page {
    pub(crate) info: PageInfo,
    pub(crate) contents: Option<Object>,
}

/// Read a rectangle, resolving references inside it.
pub(crate) fn rect(
    doc: &mut Document<'_>,
    value: &Object,
    cancel: Cancel<'_>,
) -> Result<Option<Rect>> {
    let Object::Array(a) = doc.resolve(value, cancel)? else {
        return Ok(None);
    };
    if a.len() != 4 {
        return Ok(None);
    }
    let mut n = [0f64; 4];
    for (slot, v) in n.iter_mut().zip(a.iter()) {
        match doc.resolve(v, cancel)?.as_f64() {
            Some(x) if x.is_finite() => *slot = x,
            _ => return Ok(None),
        }
    }
    let [a0, a1, a2, a3] = n;
    Ok(Some(Rect {
        llx: a0.min(a2),
        lly: a1.min(a3),
        urx: a0.max(a2),
        ury: a1.max(a3),
    }))
}

fn own_attrs(
    doc: &mut Document<'_>,
    d: &Dictionary,
    inh: &mut Inherited,
    cancel: Cancel<'_>,
) -> Result<()> {
    if let Some(v) = d.get(b"MediaBox")
        && let Some(r) = rect(doc, v, cancel)?
    {
        inh.media = Some(r);
    }
    if let Some(v) = d.get(b"CropBox")
        && let Some(r) = rect(doc, v, cancel)?
    {
        inh.crop = Some(r);
    }
    if let Some(v) = d.get(b"Rotate") {
        let r = doc.resolve(v, cancel)?;
        if let Some(x) = r.as_i64() {
            inh.rotate = Some(x);
        }
    }
    Ok(())
}

fn geometry(
    doc: &mut Document<'_>,
    object: u32,
    d: &Dictionary,
    inh: &Inherited,
    cancel: Cancel<'_>,
) -> Result<PageInfo> {
    let media_box = inh.media.unwrap_or(LETTER);
    let crop = inh.crop.unwrap_or(media_box);
    let clipped = Rect {
        llx: crop.llx.max(media_box.llx),
        lly: crop.lly.max(media_box.lly),
        urx: crop.urx.min(media_box.urx),
        ury: crop.ury.min(media_box.ury),
    };
    let crop_box = if clipped.llx < clipped.urx && clipped.lly < clipped.ury {
        clipped
    } else {
        media_box
    };
    let rotate = match inh.rotate.unwrap_or(0).rem_euclid(360) {
        90 => 90,
        180 => 180,
        270 => 270,
        _ => 0,
    };
    let user_unit = match d.get(b"UserUnit") {
        Some(v) => doc
            .resolve(v, cancel)?
            .as_f64()
            .filter(|u| u.is_finite() && *u > 0.0)
            .unwrap_or(1.0),
        None => 1.0,
    };
    Ok(PageInfo {
        object,
        media_box,
        crop_box,
        rotate,
        user_unit,
        media_box_defaulted: inh.media.is_none(),
    })
}

/// Walk the tree under `root` (the catalog's `/Pages`). Errors on the root itself
/// always propagate; errors on a kid are findings in lenient mode.
pub(crate) fn walk(
    doc: &mut Document<'_>,
    root: &Object,
    strict: bool,
    cancel: Cancel<'_>,
) -> Result<Vec<Page>> {
    let max_pages = doc.limits().max_pages;
    let limits_pages = usize::try_from(max_pages).unwrap_or(usize::MAX);
    let max_depth = usize::from(doc.limits().max_depth);
    let mut pages: Vec<Page> = Vec::new();
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    // (node, inherited attributes, depth, is_root)
    let mut stack: Vec<(Object, Inherited, usize, bool)> =
        vec![(root.clone(), Inherited::default(), 0, true)];
    while let Some((node, inh, depth, is_root)) = stack.pop() {
        if cancel() {
            return Err(PdfError::Cancelled);
        }
        let (num, loaded) = match &node {
            Object::Reference(r) => {
                if !visited.insert(r.num) {
                    return Err(PdfError::PageTreeCycle { object: r.num });
                }
                (Some(r.num), doc.object(r.num, cancel))
            }
            other => (None, Ok(other.clone())),
        };
        let dict = match loaded {
            Ok(Object::Dictionary(d)) => d,
            Ok(_) => {
                let e = PdfError::Malformed {
                    object: num,
                    offset: 0,
                };
                if is_root || strict {
                    return Err(e);
                }
                doc.findings.push(Finding::limit(&e, num, None));
                continue;
            }
            Err(e) => {
                if is_root || strict || e.is_document_wide() {
                    return Err(e);
                }
                doc.findings.push(Finding::limit(&e, num, None));
                continue;
            }
        };
        let mut inh = inh;
        own_attrs(doc, &dict, &mut inh, cancel)?;
        let is_node = match dict.name(b"Type") {
            Some(b"Pages") => true,
            Some(b"Page") => false,
            _ => dict.contains(b"Kids"),
        };
        if is_node {
            if depth >= max_depth {
                return Err(PdfError::TooDeep { offset: 0 });
            }
            let kids = match dict.get(b"Kids") {
                Some(k) => match doc.resolve(k, cancel) {
                    Ok(Object::Array(a)) => a,
                    Ok(_) => Vec::new(),
                    Err(e) if strict || e.is_document_wide() => return Err(e),
                    Err(e) => {
                        doc.findings.push(Finding::limit(&e, num, None));
                        Vec::new()
                    }
                },
                None => Vec::new(),
            };
            // Kids beyond the page cap cannot all be pages; refuse before stacking them.
            let pending = stack
                .len()
                .saturating_add(kids.len())
                .saturating_add(pages.len());
            if pending > limits_pages.saturating_mul(2) {
                return Err(PdfError::TooManyPages { limit: max_pages });
            }
            let next = depth.saturating_add(1);
            for k in kids.into_iter().rev() {
                stack.push((k, inh, next, false));
            }
        } else {
            if pages.len() >= limits_pages {
                return Err(PdfError::TooManyPages { limit: max_pages });
            }
            let info = geometry(doc, num.unwrap_or(0), &dict, &inh, cancel)?;
            pages.push(Page {
                info,
                contents: dict.get(b"Contents").cloned(),
            });
        }
    }
    Ok(pages)
}
