| Fixture | Candidate | Outcome | Wall s | Peak RSS MiB | Detail |
| --- | --- | --- | ---: | ---: | --- |
| broken_startxref | lopdf | ok | 0.03 | 2 | `OK pages=3 decoded=114 ops=15 recovered=OffsetCorrected ms=0 heapMiB=0` |
| broken_startxref | lopdf-strict | error (typed) | 0.03 | 2 | `ERR couldn't parse input ms=0 heapMiB=0` |
| broken_startxref | pdf | error (typed) | 0.03 | 2 | `ERR pdf-0.10.0/src/file.rs:175:31:, caused by   Try at ~/.cargo/registry/src/i ms=0 heapMiB=0` |
| broken_startxref | own | ok | 0.03 | 2 | `OK pages=3 decoded=0 objects=8 recovered=true ms=0 heapMiB=0` |
| broken_xref_offsets | lopdf | ok | 0.03 | 2 | `OK pages=3 decoded=114 ops=15 recovered=Reconstructed ms=0 heapMiB=0` |
| broken_xref_offsets | lopdf-strict | error (typed) | 0.03 | 2 | `ERR invalid indirect object at byte offset 20 ms=0 heapMiB=0` |
| broken_xref_offsets | pdf | error (typed) | 0.03 | 2 | `ERR pdf-0.10.0/src/file.rs:801:23:, caused by   Can't parse field root of struct RcRef < C ms=0 heapMiB=0` |
| broken_xref_offsets | own | ok | 0.03 | 2 | `OK pages=3 decoded=0 objects=8 recovered=true ms=0 heapMiB=0` |
| deep_nesting | lopdf | ok | 0.02 | 3 | `OK pages=0 decoded=0 ops=0 ms=0 heapMiB=0` |
| deep_nesting | lopdf-strict | error (typed) | 0.03 | 2 | `ERR invalid indirect object at byte offset 15 ms=0 heapMiB=0` |
| deep_nesting | pdf | error (typed) | 0.03 | 3 | `ERR pdf-0.10.0/src/file.rs:801:23:, caused by   Can't parse field root of struct RcRef < C ms=0 heapMiB=0` |
| deep_nesting | own | error (typed) | 0.03 | 2 | `ERR Depth(311) ms=0 heapMiB=0` |
| deep_nesting_content | lopdf | error (typed) | 0.02 | 3 | `ERR ops: couldn't parse input ms=0 heapMiB=0` |
| deep_nesting_content | lopdf-strict | error (typed) | 0.03 | 3 | `ERR ops: couldn't parse input ms=0 heapMiB=0` |
| deep_nesting_content | pdf | ok | 0.10 | 3 | `OK pages=1 decoded=200003 ops=1 count_claimed=1 ms=90 heapMiB=0` |
| deep_nesting_content | own | ok | 0.03 | 2 | `OK pages=1 decoded=0 objects=4 recovered=false ms=0 heapMiB=0` |
| deep_nesting_dict | lopdf | ok | 0.03 | 3 | `OK pages=0 decoded=0 ops=0 ms=1 heapMiB=0` |
| deep_nesting_dict | lopdf-strict | error (typed) | 0.03 | 3 | `ERR invalid indirect object at byte offset 15 ms=0 heapMiB=0` |
| deep_nesting_dict | pdf | error (typed) | 0.03 | 4 | `ERR pdf-0.10.0/src/file.rs:801:23:, caused by   Can't parse field root of struct RcRef < C ms=0 heapMiB=1` |
| deep_nesting_dict | own | error (typed) | 0.03 | 3 | `ERR Depth(1330) ms=0 heapMiB=0` |
| flate_bomb_content | lopdf | error (typed) | 0.08 | 325 | `ERR content: couldn't decompress stream ms=49 heapMiB=511` |
| flate_bomb_content | lopdf-strict | error (typed) | 0.05 | 325 | `ERR content: couldn't decompress stream ms=41 heapMiB=511` |
| flate_bomb_content | pdf | CRASH SIGABRT alloc cap/abort | 0.45 | 1032 | `note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace` |
| flate_bomb_content | own | ok | 0.03 | 3 | `OK pages=1 decoded=0 objects=4 recovered=false ms=0 heapMiB=0` |
| flate_bomb_many | lopdf | ok | 1.02 | 2521 | `OK pages=1 decoded=0 ops=0 ms=989 heapMiB=501` |
| flate_bomb_many | lopdf-strict | ok | 1.05 | 2173 | `OK pages=1 decoded=0 ops=0 ms=1015 heapMiB=501` |
| flate_bomb_many | pdf | ok | 0.03 | 6 | `OK pages=1 decoded=0 ops=0 count_claimed=1 ms=0 heapMiB=3` |
| flate_bomb_many | own | ok | 0.03 | 4 | `OK pages=1 decoded=0 objects=12 recovered=true ms=0 heapMiB=1` |
| flate_bomb_objstm | lopdf | error (typed) | 0.05 | 325 | `ERR couldn't decompress stream ms=43 heapMiB=511` |
| flate_bomb_objstm | lopdf-strict | error (typed) | 0.05 | 325 | `ERR couldn't decompress stream ms=39 heapMiB=511` |
| flate_bomb_objstm | pdf | CRASH SIGABRT alloc cap/abort | 0.45 | 1032 | `note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace` |
| flate_bomb_objstm | own | error (typed) | 0.03 | 3 | `ERR Missing("object") ms=0 heapMiB=0` |
| many_objects | lopdf | ok | 0.27 | 485 | `OK pages=1 decoded=0 ops=0 ms=253 heapMiB=460` |
| many_objects | lopdf-strict | ok | 0.29 | 485 | `OK pages=1 decoded=0 ops=0 ms=259 heapMiB=460` |
| many_objects | pdf | error (typed) | 0.08 | 136 | `ERR pdf-0.10.0/src/file.rs:175:31:, caused by   too many objects ms=62 heapMiB=133` |
| many_objects | own | error (typed) | 0.19 | 85 | `ERR TooMany("objects") ms=186 heapMiB=80` |
| objstm_self | lopdf | ok | 0.03 | 2 | `OK pages=1 decoded=0 ops=0 recovered=Reconstructed ms=0 heapMiB=0` |
| objstm_self | lopdf-strict | ok | 0.03 | 2 | `OK pages=0 decoded=0 ops=0 ms=0 heapMiB=0` |
| objstm_self | pdf | error (typed) | 0.03 | 2 | `ERR pdf-0.10.0/src/file.rs:801:23:, caused by   Can't parse field root of struct RcRef < C ms=0 heapMiB=0` |
| objstm_self | own | error (typed) | 0.03 | 2 | `ERR Missing("object") ms=0 heapMiB=0` |
| page_tree_cycle | lopdf | ok | 0.03 | 2 | `OK pages=0 decoded=0 ops=0 ms=0 heapMiB=0` |
| page_tree_cycle | lopdf-strict | ok | 0.03 | 2 | `OK pages=0 decoded=0 ops=0 ms=0 heapMiB=0` |
| page_tree_cycle | pdf | error (typed) | 0.03 | 2 | `ERR page 0: page tree depth exeeded ms=0 heapMiB=0` |
| page_tree_cycle | own | error (typed) | 0.03 | 2 | `ERR Cycle(2) ms=0 heapMiB=0` |
| prev_loop | lopdf | ok | 0.03 | 2 | `OK pages=1 decoded=38 ops=5 ms=0 heapMiB=0` |
| prev_loop | lopdf-strict | ok | 0.03 | 2 | `OK pages=1 decoded=38 ops=5 ms=0 heapMiB=0` |
| prev_loop | pdf | error (typed) | 0.03 | 2 | `ERR pdf-0.10.0/src/file.rs:175:31:, caused by   xref offsets loop ms=0 heapMiB=0` |
| prev_loop | own | ok | 0.03 | 2 | `OK pages=1 decoded=0 objects=4 recovered=true ms=0 heapMiB=0` |
| prev_self_loop | lopdf | ok | 0.03 | 2 | `OK pages=1 decoded=38 ops=5 ms=0 heapMiB=0` |
| prev_self_loop | lopdf-strict | ok | 0.03 | 2 | `OK pages=1 decoded=38 ops=5 ms=0 heapMiB=0` |
| prev_self_loop | pdf | error (typed) | 0.03 | 2 | `ERR pdf-0.10.0/src/file.rs:175:31:, caused by   xref offsets loop ms=0 heapMiB=0` |
| prev_self_loop | own | ok | 0.03 | 2 | `OK pages=1 decoded=0 objects=4 recovered=true ms=0 heapMiB=0` |
| truncated | lopdf | ok | 0.03 | 2 | `OK pages=3 decoded=76 ops=10 recovered=Reconstructed ms=0 heapMiB=0` |
| truncated | lopdf-strict | error (typed) | 0.03 | 2 | `ERR failed parsing cross reference table ms=0 heapMiB=0` |
| truncated | pdf | error (typed) | 0.03 | 2 | `ERR pdf-0.10.0/src/file.rs:175:31:, caused by   Try at ~/.cargo/registry/src/i ms=0 heapMiB=0` |
| truncated | own | error (typed) | 0.03 | 2 | `ERR Syntax(559) ms=0 heapMiB=0` |
| valid | lopdf | ok | 0.03 | 2 | `OK pages=3 decoded=114 ops=15 ms=0 heapMiB=0` |
| valid | lopdf-strict | ok | 0.03 | 2 | `OK pages=3 decoded=114 ops=15 ms=0 heapMiB=0` |
| valid | pdf | ok | 0.03 | 2 | `OK pages=3 decoded=111 ops=15 count_claimed=3 ms=0 heapMiB=0` |
| valid | own | ok | 0.02 | 2 | `OK pages=3 decoded=0 objects=8 recovered=false ms=0 heapMiB=0` |
| valid_xrefstream | lopdf | ok | 0.03 | 2 | `OK pages=3 decoded=114 ops=15 ms=0 heapMiB=0` |
| valid_xrefstream | lopdf-strict | ok | 0.03 | 2 | `OK pages=3 decoded=114 ops=15 ms=0 heapMiB=0` |
| valid_xrefstream | pdf | ok | 0.03 | 2 | `OK pages=3 decoded=111 ops=15 count_claimed=3 ms=0 heapMiB=0` |
| valid_xrefstream | own | ok | 0.03 | 2 | `OK pages=3 decoded=0 objects=9 recovered=true ms=0 heapMiB=0` |
| xref_size_2g_stream | lopdf | ok | 0.03 | 2 | `OK pages=1 decoded=38 ops=5 recovered=Reconstructed ms=0 heapMiB=0` |
| xref_size_2g_stream | lopdf-strict | error (typed) | 0.03 | 2 | `ERR couldn't parse input ms=0 heapMiB=0` |
| xref_size_2g_stream | pdf | error (typed) | 0.03 | 2 | `ERR pdf-0.10.0/src/file.rs:175:31:, caused by   Try at ~/.cargo/registry/src/i ms=0 heapMiB=0` |
| xref_size_2g_stream | own | ok | 0.03 | 2 | `OK pages=1 decoded=0 objects=5 recovered=true ms=0 heapMiB=0` |
| xref_size_2g_table | lopdf | ok | 0.03 | 2 | `OK pages=3 decoded=114 ops=15 ms=0 heapMiB=0` |
| xref_size_2g_table | lopdf-strict | ok | 0.03 | 2 | `OK pages=3 decoded=114 ops=15 ms=0 heapMiB=0` |
| xref_size_2g_table | pdf | error (typed) | 0.03 | 2 | `ERR pdf-0.10.0/src/file.rs:175:31:, caused by   Try at ~/.cargo/registry/src/i ms=0 heapMiB=0` |
| xref_size_2g_table | own | ok | 0.03 | 2 | `OK pages=3 decoded=0 objects=8 recovered=false ms=0 heapMiB=0` |
