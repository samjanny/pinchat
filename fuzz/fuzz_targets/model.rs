//! Sequences of frames, valid and invalid, read in arbitrary pieces with
//! the read abandoned at arbitrary points, and compared with a reference
//! model of RFC 6455 written apart from the transport (`model` in
//! src/lib.rs): masking, reserved bits and opcodes, the shortest length
//! form, fragmentation and continuation, control frames between fragments,
//! the checks of Close frames, UTF-8, the size and fragment limits, and the
//! end of the stream inside a message. The inbound budget, when there is
//! one, must not change what is read, and must be whole again afterwards.

#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use pinchat_ws_fuzz::ws_transport::{InboundBudget, InboundTier, WsReader};
use pinchat_ws_fuzz::{FrameSpec, LengthForm, Plan, ScriptedReader, drain, model};

#[derive(Arbitrary, Debug)]
enum Payload {
    Bytes(Vec<u8>),
    Text(String),
    Repeat(u8, u16),
    Close(u16, String),
    Cut(String, u8),
}

#[derive(Arbitrary, Debug)]
struct Spec {
    first: u8,
    flags: u8,
    mask: [u8; 4],
    payload: Payload,
}

#[derive(Arbitrary, Debug)]
struct Input {
    limit: u32,
    budget: Option<(u16, u16)>,
    frames: Vec<Spec>,
    repeat_empty: u16,
    plan: Vec<u8>,
}

/// Mostly opcodes a client may send, now and then a reserved one.
const OPCODES: [u8; 16] = [1, 0, 0, 2, 9, 10, 8, 1, 0, 1, 0, 9, 3, 11, 1, 0];
const LIMITS: [usize; 5] = [0, 125, 4096, 70_000, 1 << 20];

fn frame(spec: &Spec) -> FrameSpec {
    let payload = match &spec.payload {
        Payload::Bytes(bytes) => bytes.clone(),
        Payload::Text(text) => text.as_bytes().to_vec(),
        Payload::Repeat(byte, count) => vec![*byte; usize::from(*count)],
        Payload::Close(code, reason) => {
            let mut payload = code.to_be_bytes().to_vec();
            payload.extend_from_slice(reason.as_bytes());
            payload
        }
        // Valid text cut at an arbitrary byte, which may fall inside a
        // code point.
        Payload::Cut(text, at) => {
            let bytes = text.as_bytes();
            bytes[..usize::from(*at).min(bytes.len())].to_vec()
        }
    };
    FrameSpec {
        fin: spec.first & 0x80 != 0,
        rsv: if spec.flags & 0x30 == 0x30 {
            (spec.first >> 4) & 7
        } else {
            0
        },
        opcode: OPCODES[usize::from(spec.first & 0x0F)],
        masked: spec.flags & 0x07 != 0,
        mask: spec.mask,
        form: match spec.flags >> 6 {
            0 | 1 => LengthForm::Shortest,
            2 => LengthForm::Sixteen,
            _ => LengthForm::SixtyFour,
        },
        payload,
    }
}

fuzz_target!(|input: Input| {
    let limit = if input.limit & 1 == 0 {
        LIMITS[(input.limit as usize >> 1) % LIMITS.len()]
    } else {
        (input.limit >> 1) as usize % 200_000
    };
    let mut frames: Vec<FrameSpec> = input.frames.iter().map(frame).collect();
    // Now and then a long run of empty fragments, to reach the limit on
    // frames per message.
    if input.repeat_empty > 1000 {
        let at = usize::from(input.repeat_empty) % (frames.len() + 1);
        let empty = FrameSpec {
            fin: false,
            rsv: 0,
            opcode: 0,
            masked: true,
            mask: [1, 2, 3, 4],
            form: LengthForm::Shortest,
            payload: Vec::new(),
        };
        let count = usize::from(input.repeat_empty) % 1200;
        frames.splice(at..at, std::iter::repeat_n(empty, count));
    }
    let mut wire = Vec::new();
    for frame in &frames {
        frame.encode(&mut wire);
        if wire.len() > 2 << 20 {
            return;
        }
    }

    let tiers = input.budget.map(|(small, large)| {
        (
            InboundTier::new((usize::from(small) + 1) * 1024),
            InboundTier::new((usize::from(large) + 1) * 1024),
        )
    });
    let mut reader = WsReader::new(ScriptedReader::new(wire.clone(), Plan::new(&input.plan)), limit);
    if let Some((small, large)) = &tiers {
        reader = reader.with_budget(InboundBudget::new(vec![small.clone()], vec![large.clone()]));
    }
    let mut plan = Plan::new(&input.plan);
    let got = drain(&mut reader, &mut plan, 64 * (wire.len() + 16));
    let expected = model(&frames, limit);
    assert_eq!(got, expected, "frames: {frames:?}, limit {limit}");
    drop(reader);
    if let (Some((small, large)), Some((small_kib, large_kib))) = (&tiers, input.budget) {
        assert_eq!(small.available_bytes(), (usize::from(small_kib) + 1) * 1024);
        assert_eq!(large.available_bytes(), (usize::from(large_kib) + 1) * 1024);
    }
});
