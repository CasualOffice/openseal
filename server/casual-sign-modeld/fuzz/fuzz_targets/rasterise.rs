//! Bytes into the page rasteriser (ML-02, `SEC-I01`, `SEC-I02`): what the raster child
//! does with a hostile PDF, in process. `hayro`'s parser, its JBIG2, JPX and CCITT
//! decoders and modeld's own pre-render checks (pixel cap, decoded image budget, Form
//! XObject depth) all run. Any panic, hang or out-of-memory is a finding: in modeld the
//! child would be killed, but the cap checks must refuse before that.
//!
//!   cd server/casual-sign-modeld/fuzz && cargo +nightly fuzz run rasterise seeds/rasterise -- -max_total_time=600
#![no_main]

use casual_sign_modeld::raster::render_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The lowest resolution modeld asks for keeps each run small; the caps are the same.
    let _ = render_bytes(data, 0, 100);
});
