#!/usr/bin/env python3
"""Write a seed corpus for the `frames` target into corpus/frames."""
import os
import struct

MASK = bytes([0x37, 0xFA, 0x21, 0x3D])


def frame(first, payload, form=None):
    n = len(payload)
    out = bytes([first])
    if form is None:
        form = 0 if n < 126 else (1 if n <= 65535 else 2)
    if form == 0:
        out += bytes([0x80 | n])
    elif form == 1:
        out += bytes([0x80 | 126]) + struct.pack('>H', n)
    else:
        out += bytes([0x80 | 127]) + struct.pack('>Q', n)
    return out + MASK + bytes(b ^ MASK[i & 3] for i, b in enumerate(payload))


SEEDS = {
    'basic': frame(0x81, b'hello') + frame(0x89, b'ping') + frame(0x8A, b'')
    + frame(0x88, b'\x03\xe8bye'),
    'fragments': frame(0x01, b'one ') + frame(0x89, b'x') + frame(0x00, b'two ')
    + frame(0x80, b'three'),
    'mid': frame(0x81, b'a' * 10000) + frame(0x81, b'b' * 200),
    'large16': frame(0x81, b'c' * 65535),
    'large64': frame(0x81, b'd' * 70000),
    'binary': frame(0x82, b'\x00\x01' * 300) + frame(0x02, b'x') + frame(0x80, b'y'),
    'utf8': frame(0x01, 'κόσμε'.encode()[:3]) + frame(0x80, 'κόσμε'.encode()[3:]),
    'badutf8': frame(0x81, b'\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80edited'),
    'close_bad': frame(0x88, b'\x03\xed'),
    'nonminimal': frame(0x81, b'x' * 10, form=1),
    'unmasked': bytes([0x81, 0x05]) + b'hello',
    'huge_announce': bytes([0x81, 0xFF]) + struct.pack('>Q', 1 << 40) + MASK,
    'partial': frame(0x01, b'p' * (63 * 1024))[:40000],
}

os.makedirs('corpus/frames', exist_ok=True)
for name, data in SEEDS.items():
    # The first four bytes pick the limit, the budget and the read pattern.
    for head in (bytes([5, 1, 2, 3]), bytes([12, 7, 0, 9]), bytes([3, 0, 0, 0])):
        with open(f'corpus/frames/seed-{name}-{head[0]}', 'wb') as out:
            out.write(head + data)
