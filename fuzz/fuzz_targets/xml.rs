//! Bytes into the bounded XML reader (`casual-sign-xml`, ADR-026, ADR-047 §3.5), in both
//! modes. Any panic or hang is a finding; a document read must hold exactly one root,
//! every node's parent must name it as a child, and the limits must hold.
#![no_main]

use casual_sign_xml::{Limits, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for limits in [Limits::esign(), Limits::lenient(64, 4096, 64)] {
        let Ok(dom) = parse(data, &limits, &|| false) else {
            continue;
        };
        assert!(dom.nodes.len() <= limits.max_nodes);
        assert_eq!(dom.elements(0).count(), 1);
        for (id, node) in dom.nodes.iter().enumerate().skip(1) {
            let parent = node
                .parent
                .expect("every node but the document has a parent");
            assert!(dom.node(parent).children.contains(&id));
            assert!(node.attrs.len() <= limits.max_attributes);
        }
        if limits.strict {
            for id in dom.descendants(0).into_iter().skip(1) {
                let n = dom.node(id);
                assert!(n.prefix.is_empty() || dom.namespace(id, &n.prefix).is_some());
            }
        }
    }
});
