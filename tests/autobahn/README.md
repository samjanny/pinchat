# Autobahn conformance run for the WebSocket transport

`src/main.rs` is an echo server around the relay's own transport
(`src/ws_transport.rs`, compiled in as it is) with the relay's limits:
messages up to 5 594 460 bytes (what `MAX_IMAGE_SIZE=2MB` allows), the
inbound budget, the 90 s message deadline and the closing handshake. Text is
echoed, pings are answered, binary messages are read and dropped as the relay
drops them.

Run it on the loopback interface only, then the Autobahn fuzzing client in
Docker against it:

    cargo build --release
    ./target/release/pinchat-ws-conformance 127.0.0.1:9001 &
    docker run --rm --network host \
        -v "$PWD/config:/config" -v "$PWD/reports:/reports" \
        crossbario/autobahn-testsuite \
        wstest -m fuzzingclient -s /config/fuzzingclient.json

The report is `reports/index.html`; `reports/index.json` holds the outcome of
every case.

Run on 2026-11-20 with Autobahn Testsuite 25.10.1: 490 cases (every
section except the binary performance cases 9.2, 9.4, 9.6 and 9.8, which
fail by design for the reason below and only take long to do so): 257 OK,
3 informational, 216 unimplemented, 14 failed, 0 non-strict. Autobahn rates
the closing behaviour OK in every case except these 14 and the three
informational ones (7.1.6, 7.13.1, 7.13.2, answered with 1000, 1002, 1002).

Cases that report a failure by design:

* 1.2.1 to 1.2.8: binary messages are not echoed; the relay has no use for
  them. Autobahn then closes with 1001 and the server answers with 1001.
* 9.1.5 and 9.1.6: 8 and 16 MiB messages, above the limit. The server
  sends 1009 and lets the connection go after reading at most 64 KiB more;
  the client is still sending, so the reset can discard the Close frame
  before the client reads it.
* 9.3.1 to 9.3.4: 4 MiB sent as 65537, 16385, 4097 and 1025 frames, more
  than the 1024 a message may have (`MAX_MESSAGE_FRAMES`): closed with 1009.
* 12.x and 13.x: permessage-deflate is not negotiated, so the suite reports
  them as unimplemented; they close cleanly.
