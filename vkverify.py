#!/usr/bin/env python3
"""vkverify.py: prove which key schedules found in memory are the volume key of a LUKS header.

The lab-side verifier of Keep.

    python3 -I vkverify.py CANDIDATES [HEADER...] [--image DISK]... [--truth DIR] [--out DIR]
                           [--json FILE] [--show-keys]

CANDIDATES is the output of kcore-keyscan, one line per schedule:
    AES-256 phys 0x... virt 0x... key <hex>
HEADER is a LUKS1 or LUKS2 header that starts at the beginning of the file: a file made by
"cryptsetup luksHeaderBackup", or the image of the encrypted partition.

--image DISK  read the headers from a disk image, for the case that no header backup exists.
              DISK is the image of a whole disk or of a partition. Every LUKS header in it is
              located by its magic at a sector boundary and named DISK@0xOFFSET. The image is
              only read. May be given more than once.

The proof. A LUKS header stores a digest of its volume key: PBKDF2 over the key, with the salt
and the iteration count of the header (LUKS1: 20 bytes in the binary header; LUKS2: the
"digests" object of the JSON area). A key that gives the stored digest is the volume key.

The search returns single AES keys. With aes-xts the volume key is two AES keys, the data key
followed by the tweak key, so every ordered pair of candidates of the right size is tested.
The kernel keeps the two schedules in one structure, the tweak schedule first and the data
schedule 496 bytes after it (struct aesni_xts_ctx), so pairs found at that distance are tried
first. The distance only sets the order of the attempts. The digest alone decides.

--truth DIR   compare with the ground truth of the test rig: NAME.vk, plain.key and
              vc.tcryptdump.txt in DIR. This also covers plain and VeraCrypt volumes, which
              have no header and so no digest.
--out DIR     write each proven volume key to DIR/NAME.vk (mode 600), for
              "cryptsetup open --volume-key-file".
--json FILE   write the result for a program (schema keep-report/1). A key is named in it
              by the first 16 digits of its SHA-256 and never written, also with --show-keys.
--show-keys   print the keys. Without it a key is named by the first 16 digits of its SHA-256.

Python standard library only.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import time

VERSION = "1.2.1"
XTS_DISTANCE = 496      # data schedule minus tweak schedule, struct aesni_xts_ctx
LINE = re.compile(r"^AES-(128|256) phys (0x[0-9a-f]+) virt (\S+) key ([0-9a-f]+)\s*$")
SHOW = False


def short_hash(key):
    return hashlib.sha256(key).hexdigest()[:16]


def name_of(key):
    return key.hex() if SHOW else "sha256 " + hashlib.sha256(key).hexdigest()[:16]


def read_candidates(path):
    """Return {key: [phys, ...]} for every schedule line of the scanner output."""
    found = {}
    for line in open(path, errors="replace"):
        m = LINE.match(line)
        if m and len(m.group(4)) == int(m.group(1)) // 4:
            found.setdefault(bytes.fromhex(m.group(4)), []).append(int(m.group(2), 16))
    return found


LUKS_MAGIC = b"LUKS\xba\xbe"


def read_header_at(f, base=0):
    """Return the digest parameters of the LUKS header at offset base in open file f."""
    f.seek(base)
    head = f.read(4096)
    if head[:6] != LUKS_MAGIC:
        raise ValueError("no LUKS header")
    version = struct.unpack(">H", head[6:8])[0]
    text = lambda b: b.split(b"\0")[0].decode()
    if version == 1:
        # LUKS1 on-disk format: hash-spec at 72, key-bytes at 108, mk-digest at 112,
        # mk-digest-salt at 132, mk-digest-iter at 164, uuid at 168
        return dict(version=1, uuid=text(head[168:208]),
                    cipher=text(head[8:40]) + "-" + text(head[40:72]),
                    hash=text(head[72:104]), key_size=struct.unpack(">I", head[108:112])[0],
                    digest=head[112:132], salt=head[132:164],
                    iterations=struct.unpack(">I", head[164:168])[0])
    if version == 2:
        # LUKS2: hdr_size at 8 (binary header and JSON area), uuid at 168, JSON at 4096
        hdr_size = struct.unpack(">Q", head[8:16])[0]
        if not 4096 < hdr_size <= 16 << 20:
            raise ValueError("LUKS2 header size out of range")
        f.seek(base + 4096)
        meta = json.loads(f.read(hdr_size - 4096).split(b"\0")[0])
        for d in meta["digests"].values():
            if d["type"] == "pbkdf2" and d["segments"]:
                slot = meta["keyslots"][d["keyslots"][0]]
                seg = meta["segments"][d["segments"][0]]
                return dict(version=2, uuid=text(head[168:208]), cipher=seg["encryption"],
                            hash=d["hash"], key_size=slot["key_size"],
                            digest=base64.b64decode(d["digest"]),
                            salt=base64.b64decode(d["salt"]), iterations=d["iterations"])
        raise ValueError("LUKS2 header without a pbkdf2 digest of a data segment")
    raise ValueError(f"LUKS version {version}")


def checked(h):
    """Refuse a header whose digest parameters cannot be those of a real header. The magic
    alone can occur in other data, and a header found by a scan must not stop the run."""
    if h["hash"] not in hashlib.algorithms_available:
        raise ValueError(f"unknown digest hash {h['hash']!r}")
    if not (1 <= h["key_size"] <= 512 and h["iterations"] >= 1 and h["digest"] and h["salt"]):
        raise ValueError("digest parameters out of range")
    return h


def read_header(path):
    """Return the digest parameters of a LUKS header file or partition (header at offset 0)."""
    with open(path, "rb") as f:
        return checked(read_header_at(f, 0))


def find_headers(path):
    """Locate LUKS headers in a disk image. Scan for the magic at a 512-aligned offset and
    return [(offset, header)] for each offset that parses as a LUKS1 or LUKS2 header. This
    finds the header whether the file is the LUKS partition itself or a whole-disk image."""
    chunk = 1 << 23                     # 8 MiB, a multiple of 512, so a magic cannot straddle it
    found, seen = [], set()
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        base = 0
        while base < size:
            f.seek(base)
            buf = f.read(chunk)
            i = buf.find(LUKS_MAGIC)
            while i >= 0:
                off = base + i
                if off % 512 == 0 and off not in seen:
                    try:
                        found.append((off, checked(read_header_at(f, off))))
                        seen.add(off)
                    except (OSError, ValueError, KeyError):
                        pass
                i = buf.find(LUKS_MAGIC, i + 1)
            base += chunk
    return sorted(found)


def proves(h, key):
    return hashlib.pbkdf2_hmac(h["hash"], key, h["salt"], h["iterations"], len(h["digest"])) == h["digest"]


def attempts(cand, key_size, cipher):
    """Keys to test for a header: with xts ordered pairs of halves, otherwise single keys first."""
    if "xts" not in cipher:
        for k in cand:
            if len(k) == key_size:
                yield k, None, None
    halves = [k for k in cand if len(k) * 2 == key_size]
    near, far = [], []
    for data in halves:
        for tweak in halves:
            if data is tweak:
                continue
            adjacent = any(d - t == XTS_DISTANCE for d in cand[data] for t in cand[tweak])
            (near if adjacent else far).append((data + tweak, data, tweak))
    yield from near
    yield from far


def truth_keys(d):
    """The ground-truth volume keys of the test rig, {name: key}."""
    keys = {}
    for f in sorted(os.listdir(d)):
        p = os.path.join(d, f)
        if f.endswith(".vk") or f == "plain.key":
            keys[f.rsplit(".", 1)[0]] = open(p, "rb").read()
        elif f == "vc.tcryptdump.txt":
            dump = open(p).read().split("MK dump:")[1]
            keys["vc"] = bytes.fromhex("".join(re.findall(r"\b[0-9a-f]{2}\b", dump)))
    return keys


def main():
    global SHOW
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("candidates")
    ap.add_argument("header", nargs="*")
    ap.add_argument("--image", action="append", metavar="DISK")
    ap.add_argument("--truth")
    ap.add_argument("--out")
    ap.add_argument("--json")
    ap.add_argument("--show-keys", action="store_true")
    a = ap.parse_args()
    SHOW = a.show_keys

    cand = read_candidates(a.candidates)
    print(f"candidates: {sum(map(len, cand.values()))} schedules, {len(cand)} different keys "
          f"({sum(len(k) == 16 for k in cand)} AES-128, {sum(len(k) == 32 for k in cand)} AES-256)")
    for k, where in sorted(cand.items(), key=lambda kv: min(kv[1])):
        print(f"  AES-{len(k) * 8}  {name_of(k)}  {len(where)} cop{'y' if len(where) == 1 else 'ies'}  "
              + " ".join(f"0x{p:x}" for p in sorted(where)[:4]) + (" ..." if len(where) > 4 else ""))

    report = dict(schema="keep-report/1", tool="vkverify.py " + VERSION,
                  started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  source=os.path.basename(a.candidates),
                  candidates=dict(schedules=sum(map(len, cand.values())), keys=len(cand),
                                  aes128=sum(len(k) == 16 for k in cand),
                                  aes256=sum(len(k) == 32 for k in cand)),
                  volumes=[])
    entry = {}
    proven = {}
    # the headers to prove against: files given as a header, and headers located in a disk image
    targets = []
    for path in a.header:
        name = os.path.basename(path).rsplit(".", 1)[0]
        try:
            targets.append((name, read_header(path)))
        except (OSError, ValueError, KeyError) as e:
            targets.append((name, e))
    for img in a.image or []:
        base = os.path.basename(img)
        try:
            located = find_headers(img)
        except OSError as e:
            targets.append((base, e))
            continue
        if not located:
            print(f"\n{base}: no LUKS header found in the image")
        for off, h in located:
            print(f"\n{base}: LUKS{h['version']} header at offset 0x{off:x}")
            targets.append((f"{base}@0x{off:x}", h))
    for name, h in targets:
        if isinstance(h, Exception):
            print(f"\n{name}: {h}")
            entry[name] = dict(name=name, type=None, cipher=None, key_bits=None, route=None,
                               verdict="unreadable header", key_sha256_16=None, note=str(h))
            report["volumes"].append(entry[name])
            continue
        print(f"\n{name}: LUKS{h['version']}, {h['cipher']}, key of {h['key_size'] * 8} bits, "
              f"UUID {h['uuid']}, digest pbkdf2-{h['hash']} with {h['iterations']} iterations")
        entry[name] = e = dict(name=name, type=f"LUKS{h['version']}", cipher=h["cipher"],
                               key_bits=h["key_size"] * 8, uuid=h["uuid"],
                               digest="pbkdf2-" + h["hash"], route=None, verdict="not proven",
                               key_sha256_16=None, note="")
        report["volumes"].append(e)
        if not h["cipher"].startswith("aes"):
            e["note"] = "the cipher is not AES, so the AES schedule search does not apply"
            print("  " + e["note"])
        t0, n = time.time(), 0
        for key, data, tweak in attempts(cand, h["key_size"], h["cipher"]):
            n += 1
            if not proves(h, key):
                continue
            proven[name] = key
            e.update(route="memory search", verdict="proven", key_sha256_16=short_hash(key),
                     attempts=n, note="gives the digest of the header")
            print(f"  PROVEN at attempt {n} after {time.time() - t0:.1f} s: "
                  f"the volume key is {name_of(key)}")
            if data is not None:
                pairs = sorted((t, d) for d in cand[data] for t in cand[tweak] if d - t == XTS_DISTANCE)
                e["adjacent_places"] = len(pairs)
                print(f"    data key   {name_of(data)}  {len(cand[data])} schedule(s) in memory")
                print(f"    tweak key  {name_of(tweak)}  {len(cand[tweak])} schedule(s) in memory")
                if pairs:
                    print(f"    {len(pairs)} place(s) with the tweak schedule first and the data "
                          f"schedule {XTS_DISTANCE} bytes after it: "
                          + " ".join(f"0x{t:x}" for t, _ in pairs[:4]))
                else:
                    print(f"    no place with the two schedules {XTS_DISTANCE} bytes apart")
            break
        else:
            print(f"  not proven: none of {n} candidate keys gives the digest "
                  f"({time.time() - t0:.1f} s)")
            e.update(attempts=n, note=e["note"] or f"none of {n} candidate keys gives the digest")

    if a.out:
        os.makedirs(a.out, exist_ok=True)
        for name, key in proven.items():
            p = os.path.join(a.out, name + ".vk")
            with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
                f.write(key)
            print(f"\nwritten: {p} ({len(key)} bytes)")

    if a.truth:
        print("\nground truth of the test rig:")
        for name, vk in truth_keys(a.truth).items():
            half = len(vk) // 2
            data, tweak = vk[:half], vk[half:]
            nd, nt = len(cand.get(data, [])), len(cand.get(tweak, []))
            pairs = [1 for d in cand.get(data, []) for t in cand.get(tweak, []) if d - t == XTS_DISTANCE]
            line = (f"  {name}: {len(vk) * 8} bits, sha256 {hashlib.sha256(vk).hexdigest()[:16]}, "
                    f"data key found {nd}x, tweak key found {nt}x, "
                    f"{len(pairs)} place(s) {XTS_DISTANCE} bytes apart")
            if name in proven:
                line += ", header proof " + ("EQUAL to the ground truth" if proven[name] == vk
                                             else "DIFFERENT from the ground truth")
                entry[name]["ground_truth"] = "equal" if proven[name] == vk else "different"
            elif name not in entry:     # plain and VeraCrypt: no header, so no digest
                report["volumes"].append(dict(
                    name=name, type="no header", cipher=None, key_bits=len(vk) * 8, route=None,
                    verdict="found in memory" if pairs else "not found", key_sha256_16=None,
                    adjacent_places=len(pairs),
                    note="compared with the ground truth, no header digest exists"))
            print(line)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"\nwritten: {a.json}")
    return 0 if targets and len(proven) == len(targets) else 1


if __name__ == "__main__":
    sys.exit(main())
