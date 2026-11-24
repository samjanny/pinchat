# Fuzzing the WebSocket transport

The relay speaks WebSocket through its own transport, `src/ws_transport.rs`.
This crate compiles that file in as it is and fuzzes it with libFuzzer
(cargo-fuzz). It is not part of the relay build and needs a nightly
toolchain:

    cargo install cargo-fuzz
    cd fuzz
    cargo +nightly fuzz run frames -- -max_total_time=600

Builds use AddressSanitizer, debug assertions and overflow checks.

## Targets

| Target   | Input                                                                 | What is checked |
|----------|-----------------------------------------------------------------------|-----------------|
| `frames` | arbitrary bytes from a peer, cut into reads of arbitrary sizes        | no panic or overflow; the reader always finishes; memory follows the bytes that arrived (peak and largest allocation bounded by twice the input), never the lengths frames announce; nothing left allocated and the inbound budget whole once it is dropped; nothing after a Close frame or an error |
| `model`  | sequences of valid and invalid frames                                  | the reader yields exactly what an independent model of RFC 6455 says (`model` in `src/lib.rs`): masking, reserved bits and opcodes, shortest length form, fragmentation, control frames between fragments, Close frame checks, UTF-8 (refused at the first bad byte), size and fragment limits, truncation |
| `budget` | up to five connections sharing small tiers of the inbound budget      | each connection reads what the model says whatever the others do; no set of connections waits on each other for good; tiers whole at the end |
| `writer` | frames to send, sends abandoned midway, then a closing handshake      | the peer receives exactly the frames whose send completed, in the shortest length form, final, unmasked, then at most the start of the abandoned one; nothing after a cut or a Close frame; refused frames leave no trace; the closing handshake writes one Close frame, shuts the sending side after it, and ends |

In every target the pending `next` or `send` future is dropped at arbitrary
points and the call started again, as `tokio::select!` and timeouts do in
the relay.

`python3 seeds.py` writes a seed corpus for `frames`; the other targets
start from nothing.

## Coverage

    cargo +nightly fuzz coverage frames
    llvm-cov report --instr-profile=coverage/frames/coverage.profdata \
        target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/frames \
        ../src/ws_transport.rs
