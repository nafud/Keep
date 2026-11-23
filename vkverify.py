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

              DISK may be the disk of a virtual machine. Such a file stores the disk in blocks
              with a table of where each block lies, and some of them compress the blocks, so
              a header does not lie in the file as it lies on the disk. These are read as the
              guest saw the disk, and OFFSET is the offset on that disk:
                qcow2   version 2 and 3, also with clusters compressed by zlib
                VMDK    the sparse extent (monolithicSparse, streamOptimized) and a descriptor
                        file with sparse, flat and zero extents beside it
                VDI     dynamic and fixed
                VHD     dynamic and fixed
                VHDX    dynamic and fixed, without a log to replay
              DISK may also be an EnCase image, E01, with its further segment files (E02 and
              so on) beside it. Its chunks are decompressed and, where they are stored as
              they are, compared with their checksums.
              What is recognised and not read is named and not searched as raw bytes: a qcow2
              image that is encrypted, has zstd clusters, extended L2 entries or an external
              data file, an ESXi sparse extent, a VHDX file with a log, QED, Parallels, an
              EnCase image of version 2 (Ex01) and AFF.
              "qemu-img convert -O raw" writes such a disk of a virtual machine as a raw image. A block that only a
              parent or backing image holds reads as zeros, and that image is named.

The proof. A LUKS header stores a digest of its volume key: PBKDF2 over the key, with the salt
and the iteration count of the header (LUKS1: 20 bytes in the binary header; LUKS2: the
"digests" object of the JSON area). A key that gives the stored digest is the volume key.

A header whose keyslots were erased ("cryptsetup erase") no longer opens with any passphrase, but
it keeps the digest, so a key from memory is still proven against it, and it is then the only
way into the volume. LUKS2 states the key size in the keyslots, so for such a header the size is
not known and keys of every size are tried.

A file that ends inside a header, or a header whose fields cannot be read, is reported as
"unreadable header" and the run goes on. Two headers with the same file name get apart by a
number: NAME and NAME-2.

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

With many candidates and no proof the pairs are many: n keys of one size give n * n pairs, each
one PBKDF2 run. The number of tests is printed at the start of each header, and while a header
takes long a line on standard error says how far the run is.
--json FILE   write the result for a program (schema keep-report/1). A key is named in it
              by the first 16 digits of its SHA-256 and never written, also with --show-keys.
--show-keys   print the keys. Without it a key is named by the first 16 digits of its SHA-256.

Python standard library only.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import struct
import sys
import time
import uuid
import zlib

VERSION = "1.5.0"
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
    """Return the digest parameters of the LUKS header at offset base in open file f. Whatever
    is wrong with the header is a ValueError, so that one bad header never stops the run."""
    try:
        return parse_header(f, base)
    except (KeyError, IndexError, TypeError, AttributeError, struct.error, binascii.Error) as e:
        raise ValueError(f"malformed LUKS header ({type(e).__name__}: {e})") from None


def parse_header(f, base):
    f.seek(base)
    head = f.read(4096)
    if head[:6] != LUKS_MAGIC:
        raise ValueError("no LUKS header")
    if len(head) < 208:                     # the last field read here, the UUID, ends at 208
        raise ValueError("the file ends inside the LUKS header")
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
        area = f.read(hdr_size - 4096)
        if len(area) < hdr_size - 4096:
            raise ValueError("the file ends inside the JSON area of the LUKS2 header")
        meta = json.loads(area.split(b"\0")[0])
        for d in meta["digests"].values():
            if d["type"] == "pbkdf2" and d["segments"]:
                seg = meta["segments"][d["segments"][0]]
                # The key size stands in the keyslots that the digest names. After "cryptsetup
                # erase" the digest names none, and the size is then not known (None).
                sizes = {meta["keyslots"][k]["key_size"] for k in d["keyslots"] if k in meta["keyslots"]}
                return dict(version=2, uuid=text(head[168:208]), cipher=seg["encryption"],
                            hash=d["hash"], key_size=sizes.pop() if len(sizes) == 1 else None,
                            digest=base64.b64decode(d["digest"]),
                            salt=base64.b64decode(d["salt"]), iterations=d["iterations"])
        raise ValueError("LUKS2 header without a pbkdf2 digest of a data segment")
    raise ValueError(f"LUKS version {version}")


def checked(h):
    """Refuse a header whose digest parameters cannot be those of a real header. The magic
    alone can occur in other data, and a header found by a scan must not stop the run."""
    if not isinstance(h["hash"], str) or h["hash"] not in hashlib.algorithms_available:
        raise ValueError(f"unknown digest hash {h['hash']!r}")
    size_ok = h["key_size"] is None or (isinstance(h["key_size"], int) and 1 <= h["key_size"] <= 512)
    if not (size_ok and isinstance(h["iterations"], int) and h["iterations"] >= 1
            and isinstance(h["cipher"], str) and h["digest"] and h["salt"]):
        raise ValueError("digest parameters out of range")
    return h


def read_header(path):
    """Return the digest parameters of a LUKS header file or partition (header at offset 0)."""
    with open(path, "rb") as f:
        return checked(read_header_at(f, 0))


class DiskError(ValueError):
    """A disk image of a kind that is recognised and cannot be read here."""


CONVERT = '"qemu-img convert -O raw" writes it as a raw image'


def need(f, off, n, what):
    """Exactly n bytes of open file f at offset off, or a DiskError that names what ended."""
    f.seek(off)
    data = f.read(n)
    if len(data) != n:
        raise DiskError(f"the file ends inside {what}")
    return data


class Raw:
    """A disk that lies in the file as it is: size bytes from the offset start on."""
    kind = "raw"

    def __init__(self, f, size, start=0, kind=None):
        self.f, self.size, self.start, self.notes = f, size, start, []
        if kind:
            self.kind = kind

    def read_at(self, off, n):
        n = max(0, min(n, self.size - off))
        self.f.seek(self.start + off)
        return self.f.read(n).ljust(n, b"\0")

    def has_data(self, off, n):
        return True


class Zeros(Raw):
    """A part of a disk that no file holds."""

    def __init__(self, size):
        self.size, self.notes = size, []

    def read_at(self, off, n):
        return bytes(max(0, min(n, self.size - off)))

    def has_data(self, off, n):
        return False


class Mapped:
    """A disk that the file stores in blocks, with a table of where each block lies. where(i)
    gives the place of block i: None for a block that the file does not hold, which reads as
    zeros, a file offset for a block that lies there as it is, or the bytes of a block that
    was compressed."""
    notes = ()

    def read_at(self, off, n):
        out, end = [], min(off + n, self.size)
        while off < end:
            i, skip = divmod(off, self.block)
            take = min(self.block - skip, end - off)
            at = self.where(i)
            if at is None:
                out.append(bytes(take))
            elif isinstance(at, bytes):
                out.append(at[skip:skip + take].ljust(take, b"\0"))
            else:
                self.f.seek(at + skip)
                out.append(self.f.read(take).ljust(take, b"\0"))
            off += take
        return b"".join(out)

    def has_data(self, off, n):
        last = (min(off + n, self.size) - 1) // self.block
        return any(self.stored(i) for i in range(off // self.block, last + 1))

    def stored(self, i):
        return self.where(i) is not None


class Qcow2(Mapped):
    """QEMU's qcow2, from docs/interop/qcow2.txt of QEMU: a header, an L1 table of L2 tables,
    and in each L2 table one 64-bit entry per cluster. All numbers are big-endian."""
    kind = "qcow2"

    def __init__(self, f, fsize):
        h = need(f, 0, 72, "the qcow2 header")
        (version, backing_off, backing_len, bits, self.size, crypt, l1_size,
         l1_off) = struct.unpack(">IQIIQIIQ", h[4:48])
        if version not in (2, 3):
            raise DiskError(f"qcow2 version {version} is not read")
        if not 9 <= bits <= 21:
            raise DiskError("qcow2 cluster size out of range")
        incompatible, length, self.zstd = 0, 72, False
        if version == 3:
            h += need(f, 72, 32, "the qcow2 header")
            incompatible, length = struct.unpack(">Q", h[72:80])[0], struct.unpack(">I", h[100:104])[0]
            if length > 104:
                self.zstd = need(f, 104, 1, "the qcow2 header")[0] == 1
        if crypt:
            raise DiskError("the qcow2 image is encrypted, and its clusters cannot be read without its key")
        if incompatible & 4:
            raise DiskError("the qcow2 image keeps its data in an external file. Give that file as the image")
        if incompatible & 16:
            raise DiskError(f"the qcow2 image has extended L2 entries, which are not read. {CONVERT}")
        if incompatible & ~0x1F:
            raise DiskError(f"the qcow2 image needs a feature that is not known here. {CONVERT}")
        self.f, self.bits, self.block = f, bits, 1 << bits
        self.per_l2 = self.block // 8
        if l1_size * 8 > fsize or l1_size * self.per_l2 * self.block < self.size:
            raise DiskError("the L1 table of the qcow2 image does not fit its size")
        self.l1 = struct.unpack(f">{l1_size}Q", need(f, l1_off, l1_size * 8, "the L1 table")) if l1_size else ()
        self.l2 = {}
        self.notes = []
        if backing_off and 0 < backing_len < 1024:
            name = need(f, backing_off, backing_len, "the name of the backing file").decode(errors="replace")
            self.notes.append(f"it has the backing file {name!r}: a cluster that only the backing file "
                              "holds reads as zeros, so give that file as an image too")
        if incompatible & 1:
            self.notes.append("it was not closed cleanly (dirty bit), as the disk of a running machine")
        if incompatible & 2:
            self.notes.append("it is marked as corrupt")

    def entry(self, i):
        a, b = divmod(i, self.per_l2)
        if a >= len(self.l1):
            return 0
        off = self.l1[a] & 0x00FFFFFFFFFFFE00
        if not off:
            return 0
        if a not in self.l2:
            if len(self.l2) > 64:
                self.l2.clear()
            self.l2[a] = struct.unpack(f">{self.per_l2}Q", need(self.f, off, self.block, "an L2 table"))
        return self.l2[a][b]

    def where(self, i):
        e = self.entry(i)
        if e & (1 << 62):                           # a compressed cluster
            if self.zstd:
                raise DiskError(f"the qcow2 image has clusters compressed with zstd, which are not read. {CONVERT}")
            x = 62 - (self.bits - 8)
            host = e & ((1 << x) - 1)
            sectors = (e >> x) & ((1 << (self.bits - 8)) - 1)
            self.f.seek(host)
            packed = self.f.read((sectors + 1) * 512 - (host & 511))
            try:
                return zlib.decompressobj(-15).decompress(packed, self.block)     # deflate without a header
            except zlib.error as err:
                raise DiskError(f"a compressed cluster of the qcow2 image cannot be decompressed ({err})") from None
        host = e & 0x00FFFFFFFFFFFE00
        return None if e & 1 or not host else host

    def stored(self, i):
        e = self.entry(i)
        return bool(e & (1 << 62)) or (not e & 1 and bool(e & 0x00FFFFFFFFFFFE00))


class VmdkSparse(Mapped):
    """A hosted sparse extent of VMware (Virtual Disk Format 1.1, "Hosted Sparse Extents"): a
    header, a grain directory of grain tables, and in each grain table one 32-bit sector
    number per grain. A stream-optimized extent has its grains compressed with zlib, each
    behind a marker with its length, and its grain directory named in a footer. Little-endian."""
    kind = "VMDK sparse extent"

    def __init__(self, f, fsize):
        h = need(f, 0, 512, "the header of the VMDK extent")
        if h[:4] != b"KDMV":
            raise DiskError("no sparse VMDK extent")
        (version, self.flags, capacity, grain, desc_off, desc_len, self.per_gt, _rgd, gd,
         _overhead) = struct.unpack("<IIQQQQIQQQ", h[4:72])
        if version not in (1, 2, 3):
            raise DiskError(f"VMDK sparse extent version {version} is not read")
        if gd == 0xFFFFFFFFFFFFFFFF:                # the grain directory is named in the footer
            foot = need(f, fsize - 1024, 512, "the footer of the VMDK extent") if fsize >= 1536 else b""
            if foot[:4] != b"KDMV":
                raise DiskError("the stream-optimized VMDK extent has no footer, it was not written to its end")
            gd = struct.unpack("<Q", foot[56:64])[0]
        if not grain or not self.per_gt or grain > 1 << 16 or self.per_gt > 1 << 20:
            raise DiskError("grain size of the VMDK extent out of range")
        self.f, self.block, self.size = f, grain * 512, capacity * 512
        self.packed = bool(self.flags & 0x10000)
        if self.packed:
            self.kind = "VMDK sparse extent with compressed grains"
        count = -(-capacity // (grain * self.per_gt))
        if count * 4 > fsize:
            raise DiskError("the grain directory of the VMDK extent does not fit the file")
        self.gd = struct.unpack(f"<{count}I", need(f, gd * 512, count * 4, "the grain directory")) if count else ()
        self.gt = {}
        self.notes = []
        if desc_off and desc_len:
            self.notes += vmdk_parent(need(f, desc_off * 512, min(desc_len * 512, 1 << 20), "the VMDK descriptor"))

    def entry(self, i):
        a, b = divmod(i, self.per_gt)
        if a >= len(self.gd) or not self.gd[a]:
            return 0
        if a not in self.gt:
            if len(self.gt) > 64:
                self.gt.clear()
            self.gt[a] = struct.unpack(f"<{self.per_gt}I", need(self.f, self.gd[a] * 512, self.per_gt * 4, "a grain table"))
        return self.gt[a][b]

    def where(self, i):
        e = self.entry(i)
        if e == 0 or (e == 1 and self.flags & 4):   # not stored, or a grain marked as zeros
            return None
        if not self.packed:
            return e * 512
        _lba, size = struct.unpack("<QI", need(self.f, e * 512, 12, "a grain marker"))
        try:
            return zlib.decompress(need(self.f, e * 512 + 12, size, "a compressed grain"))
        except zlib.error as err:
            raise DiskError(f"a compressed grain of the VMDK extent cannot be decompressed ({err})") from None

    def stored(self, i):
        e = self.entry(i)
        return not (e == 0 or (e == 1 and self.flags & 4))


def vmdk_parent(text):
    """The note for a VMDK descriptor that names a parent disk."""
    m = re.search(rb"^\s*parentCID\s*=\s*([0-9a-fA-F]+)", text, re.M)
    if m and m.group(1).lower() != b"ffffffff":
        hint = re.search(rb'^\s*parentFileNameHint\s*=\s*"([^"]*)"', text, re.M)
        name = hint.group(1).decode(errors="replace") if hint else "not named"
        return [f"it is a delta of the parent disk {name!r}: a grain that only the parent holds reads "
                "as zeros, so give the parent as an image too"]
    return []


class Parts:
    """A disk made of parts one after the other: the extents of a VMDK descriptor file."""

    def __init__(self, parts, kind, notes):
        self.parts, self.kind, self.notes = parts, kind, notes
        self.size = sum(p.size for p in parts)

    def pieces(self, off, n):
        for p in self.parts:
            if off < p.size and n > 0:
                take = min(n, p.size - off)
                yield p, off, take
                n -= take
                off = 0
            else:
                off -= p.size

    def read_at(self, off, n):
        return b"".join(p.read_at(o, k) for p, o, k in self.pieces(off, n))

    def has_data(self, off, n):
        return any(p.has_data(o, k) for p, o, k in self.pieces(off, n))


def vmdk_descriptor(path, text, files):
    """The disk that a VMDK descriptor file describes. Its extent files are taken from the
    directory of the descriptor by their file names alone, whatever path the descriptor gives."""
    here = os.path.dirname(os.path.abspath(path))
    parts = []
    for access, sectors, kind, name, start in re.findall(
            rb'^\s*(RW|RDONLY|NOACCESS)\s+(\d+)\s+(\w+)(?:\s+"([^"]*)")?(?:\s+(\d+))?', text, re.M):
        size, kind = int(sectors) * 512, kind.decode().upper()
        if kind == "ZERO":
            parts.append(Zeros(size))
            continue
        if kind not in ("SPARSE", "FLAT", "VMFS"):
            raise DiskError(f"the VMDK descriptor names an extent of the kind {kind}, which is not read. {CONVERT}")
        if not name:
            raise DiskError("the VMDK descriptor names an extent without a file")
        ext = os.path.join(here, os.path.basename(name.decode(errors="replace").replace("\\", "/")))
        try:
            f = open(ext, "rb")
        except OSError as err:
            raise DiskError(f"the extent {os.path.basename(ext)} of the VMDK descriptor cannot be read ({err.strerror})") from None
        files.append(f)
        if kind == "SPARSE":
            part = VmdkSparse(f, os.path.getsize(ext))
            part.size = min(part.size, size) if part.size else size
        else:
            part = Raw(f, size, int(start or 0) * 512)
        parts.append(part)
    if not parts:
        raise DiskError("the VMDK descriptor names no extent")
    notes = vmdk_parent(text) + [n for p in parts for n in p.notes]
    return Parts(parts, f"VMDK descriptor with {len(parts)} extent{'s' if len(parts) != 1 else ''}", notes)


class Vdi(Mapped):
    """VirtualBox's VDI (src/VBox/Storage/VDICore.h of VirtualBox): a text line, the signature
    0xBEDA107F at 64, the version at 68 and the header of version 1.1 at 72, then a map with
    one 32-bit number per block. Little-endian."""
    kind = "VDI"

    def __init__(self, f, fsize):
        h = need(f, 0, 400, "the VDI header")
        signature, version = struct.unpack("<II", h[64:72])
        if signature != 0xBEDA107F:
            raise DiskError("no VDI image")
        if version >> 16 != 1:
            raise DiskError(f"VDI version {version >> 16}.{version & 0xFFFF} is not read")
        kind = struct.unpack("<I", h[76:80])[0]
        off_map, self.off_data = struct.unpack("<II", h[340:348])
        self.size, self.block, self.extra, blocks = struct.unpack("<QIII", h[368:388])
        if not self.block or blocks * 4 > fsize or blocks * self.block < self.size:
            raise DiskError("the block map of the VDI image does not fit its size")
        self.f = f
        self.map = struct.unpack(f"<{blocks}I", need(f, off_map, blocks * 4, "the block map")) if blocks else ()
        self.notes = []
        if kind in (3, 4):
            self.notes.append("it is a differencing image: a block that only its parent holds reads as zeros, "
                              "so give the parent as an image too")

    def where(self, i):
        e = self.map[i] if i < len(self.map) else 0xFFFFFFFF
        if e >= 0xFFFFFFFE:                         # free, or a block of zeros
            return None
        return self.off_data + e * (self.block + self.extra) + self.extra


class Vhd(Mapped):
    """A dynamic VHD (Virtual Hard Disk Image Format Specification 1.0 of Microsoft): the
    footer, a dynamic disk header, a table with one 32-bit sector number per block, and each
    block behind a bitmap of its sectors. Big-endian."""
    kind = "VHD dynamic"

    def __init__(self, f, footer):
        data_off, self.size, kind = struct.unpack(">Q", footer[16:24])[0], struct.unpack(">Q", footer[48:56])[0], struct.unpack(">I", footer[60:64])[0]
        h = need(f, data_off, 1024, "the dynamic disk header of the VHD image")
        if h[:8] != b"cxsparse":
            raise DiskError("the VHD image has no dynamic disk header")
        table, entries, self.block = struct.unpack(">Q", h[16:24])[0], struct.unpack(">I", h[28:32])[0], struct.unpack(">I", h[32:36])[0]
        if not self.block or self.block % 512 or entries > 1 << 26 or entries * self.block < self.size:
            raise DiskError("the block table of the VHD image does not fit its size")
        self.f = f
        bits = -(-(self.block // 512) // 8)             # one bit per sector, in whole bytes
        self.bitmap = -(-bits // 512) * 512             # and in whole sectors
        self.bat = struct.unpack(f">{entries}I", need(f, table, entries * 4, "the block table")) if entries else ()
        self.notes = []
        if kind == 4:
            self.kind = "VHD differencing"
            self.notes.append("it is a differencing image: a block that only its parent holds reads as zeros, "
                              "so give the parent as an image too")

    def where(self, i):
        e = self.bat[i] if i < len(self.bat) else 0xFFFFFFFF
        return None if e == 0xFFFFFFFF else e * 512 + self.bitmap


class Vhdx(Mapped):
    """VHDX ([MS-VHDX] of Microsoft): two headers, a region table that names the block
    allocation table and the metadata region, and in the table one 64-bit entry per block,
    with an entry for a sector bitmap after every chunk of blocks. Little-endian."""
    kind = "VHDX"
    BAT = uuid.UUID("2dc27766-f623-4200-9d64-115e9bfd4a08")
    METADATA = uuid.UUID("8b7ca206-4790-4b9a-b8fe-575f050f886e")
    FILE_PARAMETERS = uuid.UUID("caa16737-fa36-4d43-b3b6-33f0aa44e76b")
    DISK_SIZE = uuid.UUID("2fa54224-cd1b-4876-b211-5dbed83bf4b8")
    SECTOR_SIZE = uuid.UUID("8141bf1d-a96f-4709-ba47-f233a8faab5f")

    def __init__(self, f, fsize):
        # the header with the higher sequence number is the current one
        heads = [h for h in (need(f, off, 4096, "a VHDX header") for off in (0x10000, 0x20000)) if h[:4] == b"head"]
        if not heads:
            raise DiskError("the VHDX image has no header")
        head = max(heads, key=lambda h: struct.unpack("<Q", h[8:16])[0])
        if head[48:64] != bytes(16):
            raise DiskError("the VHDX image has a log that was not replayed, so its tables may be out of date. "
                            "Hyper-V replays it when the disk is opened, and " + CONVERT)
        region = need(f, 0x30000, 65536, "the region table of the VHDX image")
        if region[:4] != b"regi":
            raise DiskError("the VHDX image has no region table")
        places = {}
        for k in range(min(struct.unpack("<I", region[8:12])[0], 2047)):
            e = region[16 + 32 * k:48 + 32 * k]
            places[uuid.UUID(bytes_le=e[:16])] = struct.unpack("<QI", e[16:28])
        if self.BAT not in places or self.METADATA not in places:
            raise DiskError("the VHDX image names no block allocation table or no metadata region")
        meta_off, meta_len = places[self.METADATA]
        meta = need(f, meta_off, min(meta_len, 1 << 20), "the metadata region of the VHDX image")
        if meta[:8] != b"metadata":
            raise DiskError("the VHDX image has no metadata table")
        items = {}
        for k in range(struct.unpack("<H", meta[10:12])[0]):
            e = meta[32 + 32 * k:64 + 32 * k]
            off, length = struct.unpack("<II", e[16:24])
            items[uuid.UUID(bytes_le=e[:16])] = meta[off:off + length]
        try:
            self.block, flags = struct.unpack("<II", items[self.FILE_PARAMETERS][:8])
            self.size = struct.unpack("<Q", items[self.DISK_SIZE][:8])[0]
            sector = struct.unpack("<I", items[self.SECTOR_SIZE][:4])[0]
        except (KeyError, struct.error):
            raise DiskError("the metadata of the VHDX image lack the block size, the disk size or the sector size") from None
        if not 1 << 20 <= self.block <= 1 << 28 or sector not in (512, 4096):
            raise DiskError("block size or sector size of the VHDX image out of range")
        self.f = f
        self.ratio = (1 << 23) * sector // self.block       # blocks per sector bitmap entry
        blocks = -(-self.size // self.block)
        entries = blocks + (blocks - 1) // self.ratio if blocks else 0
        bat_off, bat_len = places[self.BAT]
        if entries * 8 > bat_len:
            raise DiskError("the block allocation table of the VHDX image does not fit its size")
        self.bat = struct.unpack(f"<{entries}Q", need(f, bat_off, entries * 8, "the block allocation table")) if entries else ()
        self.notes = []
        if flags & 2:
            self.notes.append("it is a differencing image: a block that only its parent holds reads as zeros, "
                              "so give the parent as an image too")

    def where(self, i):
        k = i + i // self.ratio
        e = self.bat[k] if k < len(self.bat) else 0
        # state 6 is a block that is fully present, 7 one that is partly present in a differencing image
        return (e >> 20) << 20 if e & 7 in (6, 7) else None


class Ewf(Mapped):
    """An EnCase image, E01 (Expert Witness Compression Format, as libewf documents it): one or
    more segment files, each a 13-byte file header and a chain of sections. The volume section
    gives the size of a chunk and of the disk, and each table section one 32-bit entry per
    chunk: its offset in the file, with the highest bit set for a chunk compressed with zlib.
    A chunk that is stored as it is has its Adler-32 behind it. Little-endian."""
    kind = "EWF (E01)"

    def __init__(self, path, f, files):
        self.files, self.chunks, self.block, self.size = [], [], 0, 0
        self.notes = []
        number, name = 1, path
        while True:
            f.seek(0)
            head = f.read(13)
            if head[:8] != b"EVF\x09\x0d\x0a\xff\x00" or struct.unpack("<H", head[9:11])[0] != number:
                raise DiskError(f"{os.path.basename(name)} is not segment {number} of the EWF image"
                                + (". Give its first segment file, which ends in E01" if number == 1 else ""))
            self.files.append(f)
            last = self.sections(f, len(self.files) - 1, os.path.getsize(name))
            if last == b"done":
                break
            if last != b"next":
                raise DiskError(f"{os.path.basename(name)} ends without the section that closes a segment, it is cut")
            number += 1
            name = self.segment(path, number)
            try:
                f = open(name, "rb")
            except OSError:
                raise DiskError(f"segment {number} of the EWF image, {os.path.basename(name)}, is not beside the first one") from None
            files.append(f)
        if not self.block or not self.size:
            raise DiskError("the EWF image has no volume section")
        if len(self.chunks) * self.block < self.size:
            raise DiskError(f"the EWF image holds {len(self.chunks)} chunks, fewer than its disk of {self.size} bytes needs")
        if len(self.files) > 1:
            self.kind = f"EWF (E01) in {len(self.files)} segment files"

    @staticmethod
    def segment(path, number):
        """The file of a segment: .E01 to .E99, then .EAA, .EAB and so on, in the case of the first."""
        stem, first = path[:-2], path[-3]
        if number <= 99:
            return f"{stem}{number:02d}"
        n = number - 100
        letters = chr(ord(first.upper()) + n // 676) + chr(65 + n // 26 % 26) + chr(65 + n % 26)
        return path[:-3] + (letters if first.isupper() else letters.lower())

    def sections(self, f, index, fsize):
        """Walk the sections of one segment file and return the type of the last one."""
        off, kind = 13, b""
        while off + 76 <= fsize:
            d = need(f, off, 76, "a section of the EWF image")
            kind = d[:16].split(b"\0")[0]
            nxt, size = struct.unpack("<QQ", d[16:32])
            if kind in (b"volume", b"disk") and not self.block:
                v = need(f, off + 76, 24, "the volume section of the EWF image")
                chunks, per_chunk, sector = struct.unpack("<III", v[4:16])
                # the section of EnCase is 1052 bytes with a 64-bit number of sectors, that of
                # the older SMART format 94 bytes with a 32-bit one
                sectors = struct.unpack("<Q", v[16:24])[0] if size - 76 >= 1052 else struct.unpack("<I", v[16:20])[0]
                if not per_chunk or not sector or per_chunk * sector > 1 << 26:
                    raise DiskError("chunk size of the EWF image out of range")
                self.block, self.size = per_chunk * sector, sectors * sector
            elif kind == b"table":
                t = need(f, off + 76, 24, "a table of the EWF image")
                count, base = struct.unpack("<I", t[:4])[0], struct.unpack("<Q", t[8:16])[0]
                if count > 1 << 24 or count * 4 > fsize:
                    raise DiskError("a table of the EWF image does not fit the file")
                for e in struct.unpack(f"<{count}I", need(f, off + 100, count * 4, "a table of the EWF image")):
                    self.chunks.append((index, base + (e & 0x7FFFFFFF), bool(e >> 31)))
            if kind in (b"done", b"next") or nxt <= off:
                break
            off = nxt
        return kind

    def where(self, i):
        if i >= len(self.chunks):
            return None
        index, off, packed = self.chunks[i]
        f = self.files[index]
        want = min(self.block, self.size - i * self.block)
        f.seek(off)
        if packed:
            try:
                return zlib.decompressobj().decompress(f.read(self.block + 1024), self.block)
            except zlib.error as err:
                raise DiskError(f"chunk {i} of the EWF image cannot be decompressed ({err})") from None
        data = f.read(want + 4)
        if len(data) != want + 4 or zlib.adler32(data[:want]) != struct.unpack("<I", data[want:])[0]:
            raise DiskError(f"chunk {i} of the EWF image is cut or differs from its checksum")
        return data[:want]

    def stored(self, i):
        return True


def open_disk(path, files):
    """The disk in the image file at path, as the guest saw it. The kind is told from the first
    bytes of the file, and for a VHD from its last 512. Every file that is opened is added to
    files. A kind that is recognised and not read is a DiskError."""
    f = open(path, "rb")
    files.append(f)
    size = os.path.getsize(path)
    head = f.read(4096)
    if head[:8] == b"EVF\x09\x0d\x0a\xff\x00":
        return Ewf(path, f, files)
    if head[:8] == b"EVF2\x0d\x0a\x81\x00":
        raise DiskError('it is an EnCase image of version 2 (Ex01), which is not read. "ewfexport" of libewf writes it as a raw image')
    if head[:8] in (b"LVF\x09\x0d\x0a\xff\x00", b"LEF2\x0d\x0a\x81\x00"):
        raise DiskError("it is a logical evidence file of EnCase, which holds files and no disk")
    if head[:7] == b"AFF10\x0d\x0a":
        raise DiskError('it is an AFF image, which is not read. "affconvert -r" of AFFLIB writes it as a raw image')
    if head[:4] == b"QFI\xfb":
        return Qcow2(f, size)
    if head[:4] == b"KDMV":
        return VmdkSparse(f, size)
    if head[:4] == b"COWD":
        raise DiskError(f"it is a sparse extent of ESXi (COWD), which is not read. {CONVERT}")
    if head[:4] == b"\xbe\xba\xfe\xca":
        raise DiskError(f"it is a space-efficient sparse extent of ESXi (seSparse), which is not read. {CONVERT}")
    if head[:4] == b"QED\0":
        raise DiskError(f"it is a QED image, which is not read. {CONVERT}")
    if head[:16] in (b"WithoutFreeSpace", b"WithouFreSpacExt"):
        raise DiskError(f"it is a Parallels image, which is not read. {CONVERT}")
    if head[:8] == b"vhdxfile":
        return Vhdx(f, size)
    if len(head) >= 72 and struct.unpack("<I", head[64:68])[0] == 0xBEDA107F:
        return Vdi(f, size)
    if size < 1 << 20 and re.search(rb"^\s*createType\s*=", head, re.M):
        f.seek(0)
        return vmdk_descriptor(path, f.read(), files)
    if size >= 512:
        f.seek(size - 512)
        footer = f.read(512)
        if footer[:8] == b"conectix":
            kind = struct.unpack(">I", footer[60:64])[0]
            if kind == 2:                           # a fixed disk: the disk as it is, then the footer
                return Raw(f, size - 512, kind="VHD fixed")
            if kind in (3, 4):
                return Vhd(f, footer)
            raise DiskError(f"it is a VHD image of the disk type {kind}, which is not read")
    return Raw(f, size)


def find_headers(disk):
    """Locate LUKS headers on a disk. Scan for the magic at a 512-aligned offset and return
    [(offset, header)] for each offset that parses as a LUKS1 or LUKS2 header. This finds the
    header whether the disk is the LUKS partition itself or a whole disk. A stretch that the
    image file does not hold is zeros and is not read."""
    chunk = 1 << 23                     # 8 MiB, a multiple of 512, so a magic cannot straddle it
    found, seen = [], set()
    view = View(disk)
    base = 0
    while base < disk.size:
        if disk.has_data(base, chunk):
            buf = disk.read_at(base, chunk)
            i = buf.find(LUKS_MAGIC)
            while i >= 0:
                off = base + i
                if off % 512 == 0 and off not in seen:
                    try:
                        found.append((off, checked(read_header_at(view, off))))
                        seen.add(off)
                    except DiskError:
                        raise
                    except (OSError, ValueError, KeyError):
                        pass
                i = buf.find(LUKS_MAGIC, i + 1)
        base += chunk
    return sorted(found)


class View:
    """A disk with the seek and read of a file, for the header parser."""

    def __init__(self, disk):
        self.disk, self.pos = disk, 0

    def seek(self, pos):
        self.pos = pos

    def read(self, n):
        data = self.disk.read_at(self.pos, n)
        self.pos += len(data)
        return data


def proves(h, key):
    return hashlib.pbkdf2_hmac(h["hash"], key, h["salt"], h["iterations"], len(h["digest"])) == h["digest"]


def attempts(cand, key_size, cipher):
    """Return (count, keys): the number of keys to test for a header and a generator of them as
    (key, data half, tweak half). With xts these are ordered pairs of halves of one length,
    otherwise single keys first and then the pairs. key_size None stands for every size. The
    pairs whose schedules lie XTS_DISTANCE apart come first, by address, then every other pair
    and last a key with itself, which a random volume key never is."""
    singles = [] if "xts" in cipher else [k for k in cand if key_size in (None, len(k))]
    halves = [k for k in cand if key_size in (None, 2 * len(k))]
    count = len(singles) + sum(sum(len(k) == n for k in halves) ** 2 for n in {len(k) for k in halves})

    def keys():
        for k in singles:
            yield k, None, None
        at = {(len(k), p): k for k in halves for p in cand[k]}      # a schedule by size and address
        near = set()
        for (n, t), tweak in sorted(at.items()):
            data = at.get((n, t + XTS_DISTANCE))
            if data is not None and data != tweak and (data, tweak) not in near:
                near.add((data, tweak))
                yield data + tweak, data, tweak
        for same in (False, True):
            for data in halves:
                for tweak in halves:
                    if len(data) == len(tweak) and (data == tweak) == same and (data, tweak) not in near:
                        yield data + tweak, data, tweak
    return count, keys()


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
    # The headers to prove against: files given as a header, and headers located in a disk image.
    # A name is that of the file. It names the key file of --out, so a second header of the same
    # name gets a number.
    targets = []

    def target(name, where, header):
        unique, i = name, 1
        while any(unique == t[0] for t in targets):
            i += 1
            unique = f"{name}-{i}"
        targets.append((unique, where, header))

    for path in a.header:
        name = os.path.basename(path).rsplit(".", 1)[0]
        try:
            target(name, path, read_header(path))
        except (OSError, ValueError) as e:
            target(name, path, e)
    for img in a.image or []:
        base = os.path.basename(img)
        files = []
        try:
            disk = open_disk(img, files)
            if disk.kind != "raw":
                print(f"\n{base}: {disk.kind}, a disk of {disk.size} bytes ({disk.size / (1 << 30):.2f} GiB)")
                for note in disk.notes:
                    print(f"  note: {note}")
            located = find_headers(disk)
        except (OSError, ValueError, struct.error) as e:
            target(base, img, ValueError(f"the disk image cannot be read: {e}") if isinstance(e, DiskError) else e)
            continue
        finally:
            for f in files:
                f.close()
        if not located:
            print(f"\n{base}: no LUKS header found in the image")
        for off, h in located:
            print(f"\n{base}: LUKS{h['version']} header at offset 0x{off:x}")
            target(f"{base}@0x{off:x}", f"{img} at offset 0x{off:x}", h)
    for name, where, h in targets:
        if isinstance(h, Exception):
            print(f"\n{name}: {h}")
            entry[name] = dict(name=name, type=None, cipher=None, key_bits=None, device=where, route=None,
                               verdict="unreadable header", key_sha256_16=None, note=str(h))
            report["volumes"].append(entry[name])
            continue
        bits = None if h["key_size"] is None else h["key_size"] * 8
        print(f"\n{name}: LUKS{h['version']}, {h['cipher']}, "
              + ("key size not stated, no keyslot is left" if bits is None else f"key of {bits} bits")
              + f", UUID {h['uuid']}, digest pbkdf2-{h['hash']} with {h['iterations']} iterations")
        print(f"  from {where}")
        entry[name] = e = dict(name=name, type=f"LUKS{h['version']}", cipher=h["cipher"],
                               key_bits=bits, device=where, uuid=h["uuid"],
                               digest="pbkdf2-" + h["hash"], route=None, verdict="not proven",
                               key_sha256_16=None, note="")
        report["volumes"].append(e)
        if not h["cipher"].startswith("aes"):
            e["note"] = "the cipher is not AES, so the AES schedule search does not apply"
            print("  " + e["note"])
        count, keys = attempts(cand, h["key_size"], h["cipher"])
        print(f"  {count} candidate keys to test")
        t0, n, told = time.time(), 0, 10.0
        for key, data, tweak in keys:
            n += 1
            if time.time() - t0 >= told:        # a long run says where it is, every 10 seconds
                told += 10.0
                rest = (count - n) * (time.time() - t0) / n
                left = f"{rest:.0f} s" if rest < 120 else f"{rest / 60:.0f} min"
                print(f"    {name}: {n} of {count} tested, about {left} more if none proves",
                      file=sys.stderr, flush=True)
            if not proves(h, key):
                continue
            proven[name] = key
            e.update(route="memory search", verdict="proven", key_sha256_16=short_hash(key),
                     key_bits=len(key) * 8, attempts=n, note="gives the digest of the header")
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
        os.makedirs(a.out, mode=0o700, exist_ok=True)
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
