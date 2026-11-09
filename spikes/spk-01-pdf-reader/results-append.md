| Case | Prefix kept | xref form | /Prev | Header | Deterministic | Re-open |
| --- | --- | --- | --- | --- | --- | --- |
| lopdf-valid | prefix=true appended=255B | orig table / new table | /Prev=Some(693) (orig startxref Some(693)) | 2nd %PDF header: false | deterministic=true | lopdf-strict: 3 pages, SpikeNote=true; pdf: 3 pages; own: 3 pages, recovered=false |
| pdf-valid | prefix=true appended=209B | orig table / new stream | /Prev=None (orig startxref Some(693)) | 2nd %PDF header: false | deterministic=true | lopdf-strict: 3 pages, SpikeNote=false; pdf: 3 pages; own: 3 pages, recovered=true |
| lopdf-valid_xrefstream | prefix=true appended=276B | orig stream / new stream | /Prev=Some(693) (orig startxref Some(693)) | 2nd %PDF header: false | deterministic=true | lopdf-strict: 3 pages, SpikeNote=true; pdf: 3 pages; own: 3 pages, recovered=true |
| pdf-valid_xrefstream | prefix=true appended=215B | orig stream / new stream | /Prev=None (orig startxref Some(693)) | 2nd %PDF header: false | deterministic=true | lopdf-strict: 3 pages, SpikeNote=false; pdf: 3 pages; own: 3 pages, recovered=true |
| lopdf-broken_xref_offsets | prefix=true appended=246B | orig table / new table | /Prev=None (orig startxref Some(693)) | 2nd %PDF header: false | deterministic=true | lopdf-strict: 0 pages, SpikeNote=true; pdf: ERR pdf-0.10.0/src/object/types/page.rs:83:20:, caused by   Shared, caused by   Tried to deref; own: ERR Missing("object") |
| pdf-broken_xref_offsets | error: pdf-0.10.0/src/file.rs:261:29:     r = PlainRef { id: 1, gen: 0 } , caused by   Error pars | | | | | |
