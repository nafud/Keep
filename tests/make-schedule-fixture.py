#!/usr/bin/env python3
"""make-schedule-fixture.py: a test image with the key schedules of known XTS keys.

    python3 -I make-schedule-fixture.py [--format raw|elf|lime|avml] [--size MIB] OUT KEYFILE...

Each KEYFILE holds one XTS volume key, 64 bytes (two AES-256 keys) or 32 bytes (two AES-128
keys), as "cryptsetup luksDump --dump-volume-key --volume-key-file" writes it. Each key is laid
into random filler the way the kernel holds it (struct aesni_xts_ctx, kernel 7.0,
arch/x86/crypto/aesni-intel_glue.c): the schedule of the second half of the key (the tweak key)
first, and the schedule of the first half (the data key) 496 bytes after it.

The image also holds five traps for the scanner: one schedule at an odd address, one across
the scanner's 1 MiB read boundary, one across the border of the two ranges of the elf, lime and
avml formats, one schedule with a single wrong bit, which must not be reported, and one inside
a run of zeros. Their keys are random and are not written anywhere. Beside the zeros lies text
that repeats, so that the image is in part compressible as memory is.

The format avml is the compressed image of AVML (version 2, src/image.rs of AVML 0.21.0): per
range a header, the range as a framed Snappy stream, and the length of that stream. The Snappy
encoder and the CRC-32C here are written from the format descriptions of Snappy
(format_description.txt, framing_format.txt) and share no code with the scanner.

The key expansion here is written from FIPS-197 and shares no code with the scanner, so the
two check each other. Nothing but lengths, addresses and SHA-256 values is printed.
"""
import argparse
import hashlib
import os
import struct
import sys

CTX = 496           # sizeof(struct crypto_aes_ctx) is 484, aligned to 16
BASE = 0x100000000  # physical address of the first byte in the elf and lime formats


def sbox_table():
    box, p, q = [0] * 256, 1, 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q
        for r in (1, 2, 3, 4):
            x ^= ((q << r) | (q >> (8 - r))) & 0xFF
        box[p] = x ^ 0x63
        if p == 1:
            break
    box[0] = 0x63
    return box


SBOX = sbox_table()


def expand(key):
    """The AES key schedule of FIPS-197, section 5.2, as bytes."""
    nk = len(key) // 4
    rounds = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rc = 1
    for i in range(nk, 4 * (rounds + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[t[1]] ^ rc, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            rc = (rc << 1) ^ (0x11B if rc & 0x80 else 0)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return bytes(b for word in w for b in word)


def aes_ctx(key):
    """struct crypto_aes_ctx: key_enc[240], key_dec[240] (left as zeros), key_length."""
    return expand(key).ljust(240, b"\0") + bytes(240) + struct.pack("<I", len(key)) + bytes(12)


def crc32c_table():
    table = []
    for n in range(256):
        for _ in range(8):
            n = (n >> 1) ^ (0x82F63B78 if n & 1 else 0)     # the Castagnoli polynomial, reflected
        table.append(n)
    return table


CRC = crc32c_table()


def masked_crc32c(data):
    """The checksum of a chunk of the framed format (framing_format.txt, section 3)."""
    c = 0xFFFFFFFF
    for b in data:
        c = CRC[(c ^ b) & 0xFF] ^ (c >> 8)
    c ^= 0xFFFFFFFF
    return (((c >> 15) | (c << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def snappy_block(data):
    """DATA as one Snappy block (format_description.txt): a varint length, then literals and
    copies. A copy is taken where the four bytes at a place were seen before. All three kinds
    of copy are written, the one with a four-byte offset for every seventh copy, which no
    encoder needs inside 64 KiB and every decoder has to read."""
    out = bytearray()
    n = len(data)
    v = n
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)

    def literal(a, b):
        while a < b:
            k = min(b - a, 65536) - 1
            if k < 60:
                out.append(k << 2)
            elif k < 256:
                out.extend((60 << 2, k))
            else:
                out.extend((61 << 2, k & 0xFF, k >> 8))
            out.extend(data[a:a + k + 1])
            a += k + 1

    seen, i, lit, copies = {}, 0, 0, 0
    while i + 4 <= n:
        four = bytes(data[i:i + 4])
        j = seen.get(four)
        seen[four] = i
        if j is None:
            i += 1
            continue
        length = 4
        while length < 64 and i + length < n and data[j + length] == data[i + length]:
            length += 1
        literal(lit, i)
        offset = i - j
        copies += 1
        if copies % 7 == 0:
            out += bytes((((length - 1) << 2) | 3,)) + struct.pack("<I", offset)
        elif length <= 11 and offset < 2048:
            out += bytes((((offset >> 8) << 5) | ((length - 4) << 2) | 1, offset & 0xFF))
        else:
            out += bytes((((length - 1) << 2) | 2,)) + struct.pack("<H", offset)
        i += length
        lit = i
    literal(lit, n)
    return bytes(out)


def snappy_frames(data):
    """DATA as a framed Snappy stream: the stream identifier, then chunks of at most 64 KiB,
    compressed where that saves an eighth, as the encoder of AVML decides it."""
    out = bytearray(b"\xff\x06\x00\x00sNaPpY")
    for a in range(0, len(data), 65536):
        piece = bytes(data[a:a + 65536])
        packed = snappy_block(piece)
        kind, body = (0, packed) if len(packed) < len(piece) - len(piece) // 8 else (1, piece)
        out += bytes((kind,)) + struct.pack("<I", len(body) + 4)[:3] + struct.pack("<I", masked_crc32c(piece)) + body
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--format", choices=("raw", "elf", "lime", "avml"), default="raw")
    ap.add_argument("--size", type=int, default=4, help="size in MiB (default 4)")
    ap.add_argument("out")
    ap.add_argument("keyfile", nargs="+")
    a = ap.parse_args()

    assert expand(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))[-4:].hex() == "b6630ca6"
    assert expand(bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                                "1f352c073b6108d72d9810a30914dff4"))[-4:].hex() == "706c631e"

    size = a.size << 20
    img = bytearray(os.urandom(size))
    where = lambda off: off if a.format == "raw" else BASE + off

    off = 0x10000
    for path in a.keyfile:
        vk = open(path, "rb").read()
        if len(vk) not in (32, 64):
            sys.exit(f"{path}: {len(vk)} bytes, expected an XTS key of 32 or 64 bytes")
        half = len(vk) // 2
        data, tweak = vk[:half], vk[half:]
        img[off:off + 2 * CTX] = aes_ctx(tweak) + aes_ctx(data)
        print(f"{os.path.basename(path)}: 2 x AES-{half * 8}, tweak schedule at 0x{where(off):x}, "
              f"data schedule at 0x{where(off + CTX):x}, "
              f"sha256 of the volume key {hashlib.sha256(vk).hexdigest()}")
        off += 0x4000

    odd = expand(os.urandom(32))
    img[0x80001:0x80001 + 240] = odd
    print(f"trap 1: an AES-256 schedule at the odd address 0x{where(0x80001):x} (found only with step 1)")
    across = expand(os.urandom(16))
    img[0x100000 - 100:0x100000 - 100 + 176] = across
    print(f"trap 2: an AES-128 schedule across the 1 MiB boundary, at 0x{where(0x100000 - 100):x}")
    broken = bytearray(expand(os.urandom(32)))
    broken[200] ^= 0x10
    img[0xC0000:0xC0000 + 240] = broken
    print(f"trap 3: an AES-256 schedule with one wrong bit at 0x{where(0xC0000):x} (must not be reported)")

    border = expand(os.urandom(32))
    img[size // 2 - 120:size // 2 + 120] = border
    print(f"trap 4: an AES-256 schedule across the border of the two ranges, at 0x{where(size // 2 - 120):x}")

    # memory is full of zeros and of text that repeats: a run of zeros with a schedule in it,
    # text with a period below 2048 bytes and text with a period above it
    img[0xD0000:0xD8000] = bytes(0x8000)
    inside = expand(os.urandom(16))
    img[0xD4004:0xD4004 + 176] = inside
    print(f"trap 5: an AES-128 schedule inside a run of zeros, at 0x{where(0xD4004):x}")
    short, long = os.urandom(100), os.urandom(3000)
    img[0xD8000:0xE0000] = (short * 328)[:0x8000]
    img[0xE0000:0xE8000] = (long * 11)[:0x8000]

    with open(a.out, "wb") as f:
        if a.format == "elf":
            # ELF64 core laid out like /proc/kcore: a note, an area without a physical address
            # (vmalloc; it must be skipped, and its file range does not exist), two RAM segments
            # with kernel addresses, and the kernel text, which is a second view of RAM
            cut = size // 2
            phoff, phnum = 64, 5
            first = 0x1000
            virt = 0xFFFF888000000000 + BASE
            f.write(b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
                    + struct.pack("<HHIQQQIHHHHHH", 4, 62, 1, 0, phoff, 0, 0, 64, 56, phnum, 0, 0, 0))
            f.write(struct.pack("<IIQQQQQQ", 4, 0, 0x200, 0, 0, 16, 16, 0))
            f.write(struct.pack("<IIQQQQQQ", 1, 7, 1 << 40, 0xFFFFC90000000000, 2**64 - 1, 1 << 30, 1 << 30, 0))
            f.write(struct.pack("<IIQQQQQQ", 1, 7, first, virt, BASE, cut, cut, 0))
            f.write(struct.pack("<IIQQQQQQ", 1, 7, first + cut, virt + cut, BASE + cut, size - cut, size - cut, 0))
            f.write(struct.pack("<IIQQQQQQ", 1, 7, first + 0x10000, 0xFFFFFFFF81000000, BASE + 0x10000,
                                0x8000, 0x8000, 0))
            f.write(bytes(first - f.tell()))
            f.write(img)
        elif a.format == "lime":
            cut = size // 2
            f.write(struct.pack("<IIQQ8x", 0x4C694D45, 1, BASE, BASE + cut - 1) + img[:cut])
            f.write(struct.pack("<IIQQ8x", 0x4C694D45, 1, BASE + cut, BASE + size - 1) + img[cut:])
        elif a.format == "avml":
            cut = size // 2
            for start, part in ((BASE, img[:cut]), (BASE + cut, img[cut:])):
                frames = snappy_frames(part)
                f.write(struct.pack("<IIQQ8x", 0x4C4D5641, 2, start, start + len(part) - 1) + frames
                        + struct.pack("<Q", len(frames)))
        else:
            f.write(img)
    print(f"{a.out}: {a.format}, {os.path.getsize(a.out)} bytes")


if __name__ == "__main__":
    main()
