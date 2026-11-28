# Keep

Keep finds the keys of encrypted volumes. It is a decryption-readiness triage toolkit for digital
forensics. An investigator meets a running Linux machine whose encrypted storage is unlocked.
Powering it off turns the data back into ciphertext. Before power-off, Keep decides for every
open dm-crypt volume whether its volume key can be preserved as evidence and proven correct now,
whether a memory image must be taken first, or whether only a copy of the mounted files is
possible. Finding the keys is the main objective. Two options go with it: Keep can collect a
memory dump of the running system, and it can search a memory dump that exists for the keys and
prove them against a disk image.

Keep is for lawful examination of systems the examiner is authorised to examine. It is not a
general artefact collector and it depends on no other collector.

Keep is one static C program, `keep`, that starts no other program: an examiner copies one
file to the scene and starts it. The lab has one further tool, `vkverify.py`.

Before 2.0, Keep was a shell script, `keytriage.sh`, on a tool medium with a static bash,
busybox, the scanner and AVML, which used the `dmsetup` and the `cryptsetup` of the examined
system. While the program was written, the pipeline ran both on the same volumes, until the
program gave what the script gave on every system of the list. The script, its medium and
its driver for the lab are removed with 2.0-rc1. The history of the repository keeps them:
the last commit that has them is `8305ec0`, with `keytriage.sh` 1.5.1.

This file is the repository's description and the working rules for it. The repository has no
README.

## Layout

| File | Runs | Purpose |
|---|---|---|
| `src/`, `Makefile` | scene, as root, and lab | The program `keep`: the keys of the open volumes of the running system, a memory image after them, and the search of a memory dump that exists. `make` builds it statically against musl |
| `kcore-keyscan.c` | part of `keep`, and lab | The scanner. Finds AES-128 and AES-256 key schedules in `/proc/kcore` or in a memory image. `keep` links it, and a C compiler builds it as a program of its own |
| `vkverify.py` | lab | Verifier. Proves which scanner candidates are the volume key of a LUKS1 or LUKS2 header, also in the disk file of a virtual machine and in an EnCase image |
| `tests/make-schedule-fixture.py` | test | Writes a memory image with the schedules of known keys and five traps, as raw, ELF, LiME or compressed AVML |
| `tests/compat-check.sh` | test, throwaway guest only | Checks `keep` on real device-mapper against the `cryptsetup` and the `dmsetup` of that system: containers and mappings of known keys, the null cipher, LVM on LUKS, LUKS2 with integrity, a volume in re-encryption, the destination by default, on FAT and without room, a run that is asked to end, and the memory images against the image of AVML |
| `tests/compat-guest.sh` | test, workstation and pipeline | Boots a distribution's cloud image as a throwaway guest in QEMU, copies the programs into it, runs `compat-check.sh` there and prints its output |
| `tests/compat-images.txt` | test | The cloud images for `compat-guest.sh`: a name, the address of one dated build and its published SHA-256 or SHA-512 |
| `tests/get-avml.sh` | test, workstation and pipeline | Fetches the release binary of AVML 0.21.0 for the checks, and refuses it unless it has the SHA-256 that the script pins. AVML is no part of Keep: the checks hold the images of `keep` against it |
| `tests/selftest.sh` | test, workstation and pipeline | Runs the checks of the scanner and of the verifier, which need neither root nor device-mapper, and the static checks of every script, and ends with `RESULT: PASS` or `RESULT: FAIL` |
| `tests/unit-check.sh` | test, workstation and pipeline | Builds `keep` and its parts twice, statically and with the sanitizers of the compiler, and checks each against an independent source: `hashlib`, Python's `json`, `cryptsetup`, AVML |
| `tests/keep-unit.c` | test | Runs one part of the program at a time, for `unit-check.sh`, and counts the pages of a file or of a block device that lie in the page cache, for `compat-check.sh` as well |
| `docs/`, `overrides/`, `mkdocs.yml` | GitHub Pages | The pages of Keep, built with Material for MkDocs: the home page `index.md` and the sections `installation.md`, `usage.md` and `about.md`, the stylesheet `stylesheets/extra.css`, the page scripts in `javascripts/`, the fonts in `assets/fonts/`, and the templates in `overrides/` |
| `requirements.in`, `requirements.txt` | pipeline, workstation | The packages that build the pages: MkDocs and Material, and in the second file every package they bring along, each with its version and its SHA-256 |
| `tests/pages-check.sh` | test, workstation and pipeline | Builds the pages with `mkdocs build --strict` and reads what was built: the pages, the frame, that nothing is loaded from another host, the version, the references |
| `LICENSE` | | The MIT licence of Keep, with the name of its author |
| `.github/workflows/` | GitHub | `checks.yml` runs the self-test and the unit checks, builds and reads the pages, builds `keep` and keeps the file, and runs `compat-check.sh` on two runner images on every push. `distros.yml` runs it in guests of ten distribution releases. `pages.yml` builds the pages and publishes them from `main`. `release.yml` publishes a release: `keep` as the pipeline builds it from `main`, with its SHA-256 |

`kcore-keyscan.c` includes `src/keyscan.h`, and the `Makefile` at the root builds `keep` from
`src/` and from `kcore-keyscan.c`, so the scanner stays at the root. `vkverify.py` stands
alone.

## How it works

### The route ladder

`keep` asks the kernel for the mapped devices and for the table of each, which is what
`dmsetup ls` and `dmsetup table --showkeys` print (see "What the sources say"). A volume is a
mapped device with a crypt target in its table, or one whose crypt targets cryptsetup has put
into a helper device below it. Every name the kernel allows is taken, also `No` and a name
with a space. The type of a volume comes from the UUID of the mapping and from the header,
its cipher, the size of its key and where the key is from the table line, and its device from
`/sys/dev/block`. For each key of a volume, `keep` takes the first route that is open.

| Route | When | What happens |
|---|---|---|
| R1 table | The fifth field of the table line is the key in hexadecimal. This is the case for LUKS1, plain, tcrypt and for LUKS2 opened with `--disable-keyring` | The key is written to `keys/NAME.vk` and, for LUKS, proven against the header backup |
| R3 memory | The fifth field is a keyring reference, `:size:type:description`. This is the default for LUKS2, including systemd-homed | The scanner searches `/proc/kcore` once for all volumes. Candidates are proven against the header backup, and the key that is proven is written to `keys/NAME.vk`. The list of the schedules is kept in `keys/` also when there is no header backup |
| R5 live | No key route is open | Only a file-level copy of the mounted plaintext remains |

Beside its type and its backing device `keep` names what each volume carries, as the line
`in use` and the field `in_use`: where the volume and the devices that stand on it, such as the
logical volumes of LVM, are mounted or used as swap. It follows `holders/` in `/sys` upwards from
the mapping and reads `/proc/self/mountinfo` and `/proc/swaps`. Eight mounts are named and
further ones counted. This is what a copy of the mounted files has to cover, and it tells a
volume that holds the root file system from one that holds nothing in use.

A fifth field of `-` is a key of size 0 (`crypt_status` in `dm-crypt.c`), which is the null
cipher. Such a mapping has no key and gets the verdict `no key needed`. A field that is neither
hexadecimal nor a keyring reference is reported as not understood. The answer of the kernel
is read by the program itself and wiped, so the key passes no other program, and no file but
its own in `keys/`.

R2 and R4 are not steps of a key run. A memory image is the fourth route: `keep -m` takes it
after the keys, and `keep -s` searches it, on scene or in the lab.

The cipher is taken from the fourth field of the table line and sorted into three classes.
`aes-xts-*` and `capi:xts(aes)-*` are XTS, where the volume key is two AES keys. Any other
`aes-*` is a single AES key. Everything else has no AES schedule of the volume key, so the memory
route does not apply.

### Verdicts

A key run of `keep` prints exactly one of these per volume, and they are the values of
`verdict` in `verdict.json`.

| Verdict | Meaning |
|---|---|
| `captured and proven` | The key is written to the destination and opens the LUKS header |
| `captured, in use` | The key is read from the live table of a volume without a header digest (plain, tcrypt). Opening the image in the lab confirms it |
| `captured, not proven` | A key is read but there was no header backup, or the header refused it |
| `needs a memory read` | The key was not reached in this run. A memory image keeps the route open |
| `live copy only` | No key route is open: a non-AES cipher behind a keyring reference, lockdown `confidentiality`, or a refused read of `/proc/kcore` |
| `no key needed` | The mapping has no key: key size 0 in the table, the null cipher. The device holds the data as they are |

A key counts as captured only when it is written to the destination and flushed. When the write or
the flush fails, the verdict is `needs a memory read` and the run ends with status 1.

The search of a dump, `keep -s`, and `vkverify.py` write `proven`, `not proven` and `unreadable
header` for a header. `keep -s` also writes `found in memory, not proven` for a pair of
schedules that no header proves, and `vkverify.py` with `--truth` writes `found in memory` and
`not found` for volumes without a header.

### The proof

A candidate key counts only when it is proven. Nothing is reported as a volume key on the strength
of where it was found.

- A LUKS header stores a PBKDF2 digest of the volume key. LUKS1 keeps it in the binary header
  (hash name at offset 72, key bytes at 108, digest at 112, salt at 132, iteration count at 164,
  UUID at 168). LUKS2 keeps it in the `digests` object of the JSON area that starts at offset
  4096, with the header size at offset 8. A key whose PBKDF2 output equals the stored digest is
  the volume key.
- `keep` computes that itself, on scene and in the lab, with its own SHA-1, SHA-2, HMAC and
  PBKDF2 (`src/hash.c`, `src/luks.c`). It asks no cryptsetup. `tests/compat-check.sh` holds
  each proof against `cryptsetup open --test-passphrase OPTION KEYFILE HEADER` of the system
  it runs on, where `OPTION` is `--volume-key-file` where `cryptsetup --help` lists it (release
  2.5.0 and later) and `--master-key-file` otherwise.
- `vkverify.py` computes the same with `hashlib`, with no cryptsetup and no loop device, also
  for the hash functions that `hash.c` does not have (ripemd160, whirlpool).
- A header whose keyslots were erased (`cryptsetup erase`) keeps its digest, so a key from memory
  is still proven against it and is then the only way into the volume. LUKS2 states the key size
  in the keyslots, so for such a header `keep -s` and `vkverify.py` try keys of every size.
  Checked on headers erased by cryptsetup 2.7.0.

### Key schedules and the XTS pair

AES expands a key into round keys (FIPS-197, section 5.2). The kernel holds the expanded schedule,
and its first 16 or 32 bytes are the key. `kcore-keyscan` tests every position against the
expansion rule over the whole schedule, 176 bytes for AES-128 and 240 bytes for AES-256. The test
is exact, so a hit is a real schedule, though not necessarily one of a disk volume.

With `aes-xts` the volume key is the data key followed by the tweak key. On x86-64 with the AES-NI
family of drivers the kernel keeps both schedules in one `struct aesni_xts_ctx`
(`arch/x86/crypto/aesni-intel_glue.c`), the tweak schedule first and the data schedule 496 bytes
after it. 496 is `sizeof(struct crypto_aes_ctx)`, 484 bytes, aligned to 16.

- A key run of `keep` tries only pairs at that distance: for a tweak schedule at physical address
  P it takes the data schedule at P + 496 and builds the key as data then tweak. The number of
  proof attempts per key is limited by `-b` (default 64).
- `keep -s` and `vkverify.py` try pairs at that distance first and then every other ordered pair.
  The distance only orders the attempts. The digest decides. n keys of one size give n * n pairs,
  so their number is said before they begin, and a header that takes long says how far it is.

### `kcore-keyscan`

```bash
gcc -static -O2 -Wall -o kcore-keyscan kcore-keyscan.c
kcore-keyscan [-s STEP] [-r] [FILE]     # FILE defaults to /proc/kcore, -r reads it as raw bytes
```

These are the formats of a Linux memory image that Volatility 3 reads as well (its layers
`physical`, `elf`, `lime` and `avml`).

The input format is recognised from the first bytes.

| Format | Recognised by | What is read |
|---|---|---|
| ELF64 core | ELF magic, 64-bit, little-endian | Every `PT_LOAD` segment with a physical address. `/proc/kcore` gives the vmalloc and module areas the physical address -1, so those are skipped and RAM is read once. A dump that a hypervisor takes from outside is read the same way: checked with `dump-guest-memory` of QEMU 8.2.2 |
| LiME | `EMiL` at the start of each 32-byte range header | Each range, with its start and end address from offsets 8 and 16 of the header. This is what `keep -m` and AVML write |
| AVML compressed | `AVML` and version 2 at the start of each range header | Each range: the header, a framed Snappy stream and the length of that stream (`src/image.rs` and `src/io/snappy.rs` of AVML 0.21.0). Every chunk of at most 64 KiB is decompressed and compared with its CRC-32C. Ranges of both kinds may follow each other. This is what `keep -m -f avml` and `avml --compress` write |
| raw | anything else, or any file with `-r` | The whole file, with the file offset as the address. A `.vmem` file of VMware is such a file |
| refused | the first bytes of an AVML image of another version, of a kdump, diskdump or flattened makedumpfile file, or of a gzip, xz, zstd, bzip2 or lz4 file | Nothing. Such a file holds memory in another form. Searched as raw bytes, a gzip file gave 2 of 5 schedules with status 0. The `kdump-zlib` dump of QEMU 8.2.2 begins as a flattened makedumpfile file and is refused |

- One line per schedule goes to standard output: `AES-256 phys 0x... virt 0x... key <hex>`. The
  counts and the time go to standard error. The output therefore holds key material and is only
  ever redirected into a `keys/` directory. `keep` writes that list to `keys/kcore-candidates.txt`
  of a key run and to `keys/candidates.txt` of the search of a dump, and what the scanner said
  to `log/kcore-keyscan.txt` and to `scan.txt`.
- Data is read in 1 MiB chunks with the last 239 bytes carried over, and a range that begins where
  the previous one ended continues the same run, so a schedule across a chunk or range border is
  found.
- An unreadable stretch counts as zeros and is reported. A read of `/proc/kcore` that fails
  says nothing about the pages before the one it failed at, so its first page is then asked
  for by itself, and only a page that cannot be read alone is zeros. At most 4096 schedules
  are listed, and further ones are counted. A schedule is listed once for an address and a
  key.
- An image that is cut, as on a medium that ran full, or damaged is searched up to that place:
  a LiME image or an ELF core that ends inside a range or a segment, as one whose header
  states more memory than the file holds, and a compressed image whose stream ends or does not
  follow its format. The schedules before it are listed, the file offset and the number of
  bytes not searched are named, and the status is 1. A chunk that differs from its checksum is
  counted and its data searched as it is. Up to 1.2 only the compressed image was looked at
  in this way: a LiME image or an ELF core that was cut ended with status 0, with what was
  missing counted as zeros, and one with a range of 2^62 bytes was searched without end.
- A self-test against the two expansions of FIPS-197 appendix A runs at every start. Exit status
  0 is a completed scan, 1 an unreadable or refused input, an image that could not be read to
  its end or a list of the schedules that could not be written, 2 a usage error, 3 a failed
  self-test. The summary line names the version of the scanner.
- The program that links the search can end it before its end (`keyscan_until`): the
  schedules up to there are listed, the search names the file offset at which it ended, and
  its status is 1. `keep` does this when a run is asked to end. The scanner alone is ended by
  a signal at once.
- `/proc/kcore` needs root and is refused under kernel lockdown `confidentiality`.

### Headers from a disk image

`keep -s DUMP FILE...` reads each `FILE` as a header backup, the raw image of a partition or of a
whole disk, or a device: its start is read as a header, and behind it every sector that begins
with the magic of LUKS (see "The program"). The disk file of a virtual machine and an EnCase
image are read by `vkverify.py` alone.

`vkverify.py --image DISK` needs no header backup. It searches the image in 8 MiB chunks for the
magic `LUKS\xba\xbe` at offsets that are a multiple of 512, parses each place as a LUKS1 or LUKS2
header and names the volume `DISK@0xOFFSET`. A place is accepted only when its digest parameters
are plausible (a hash that `hashlib` knows, a key size of 1 to 512 bytes, at least one iteration,
a digest and a salt), so the bare magic inside other data does not stop the run. The image is only
read.

`DISK` may be the disk of a virtual machine. Such a file stores the disk in blocks with a table
of where each block lies, and some compress the blocks, so a header does not lie in the file as
it lies on the disk. Searched as raw bytes, an uncompressed qcow2, VMDK, VDI, VHD or VHDX file
gave both headers of a test disk at offsets of the file, and a compressed qcow2 file and a
stream-optimized VMDK file gave none, with no word about it. `vkverify.py` reads these as the
guest saw the disk, and `OFFSET` is the offset on that disk.

| Format | Read | From |
|---|---|---|
| qcow2 | Version 2 and 3, any cluster size, clusters compressed with zlib | `docs/interop/qcow2.txt` of QEMU |
| VMDK | The hosted sparse extent, also stream-optimized with compressed grains, and a descriptor file with sparse, flat and zero extents. The extent files are taken from the directory of the descriptor by their file names alone | Virtual Disk Format 1.1 of VMware |
| VDI | Dynamic and fixed | `VDICore.h` of VirtualBox |
| VHD | Dynamic and fixed | Virtual Hard Disk Image Format Specification 1.0 |
| VHDX | Dynamic and fixed, without a log to replay | [MS-VHDX] |

What is recognised and not read is named, counts as `unreadable header` and is not searched as
raw bytes: a qcow2 image that is encrypted, has clusters compressed with zstd, extended L2
entries or an external data file, a sparse extent of ESXi (COWD, seSparse), a VHDX file with a
log, QED and Parallels. `qemu-img convert -O raw` writes such a disk as a raw image. A block that
only a backing file or a parent disk holds reads as zeros, and that file is named.

`DISK` may also be an EnCase image, `E01` (Expert Witness Compression Format, as libewf
documents it), with its further segment files `E02` and so on beside it. Such a file is a chain
of sections, and the chunks of the disk lie in it compressed with zlib or as they are with an
Adler-32 behind each, at offsets that are no sector boundaries. Searched as raw bytes it gave no
header, also without compression. The chunks are decompressed, and a chunk that is stored as it
is is compared with its checksum. A missing or cut segment file and a chunk that differs from
its checksum end the reading of that image and are named. An image of version 2 (`Ex01`), a
logical evidence file and AFF are named as not read.

Each format is checked on images written from one test disk, by `qemu-img` 8.2.2 and by
`ewfacquirestream` of libewf 20140814: the reader gives the disk byte for byte and both keys are
proven. A memory dump and the two qcow2 disks of a running QEMU guest gave both volume keys of
that guest. Images that VMware, VirtualBox, Hyper-V or EnCase itself wrote are not checked.

A header file that ends inside the header, or whose fields cannot be read, is reported as
`unreadable header` and the run goes on. Two headers with the same file name are kept apart as
`NAME` and `NAME-2`, which are also the names of their key files with `--out`.

### The report, `keep-report/2`

`keep` writes `verdict.json`, and `vkverify.py --json` writes the same schema. A report never
holds a key. A key is named by `key_sha256_16`, the first 16 hexadecimal digits of its SHA-256.

- Top level of a key run: `schema`, `tool`, `host`, `kernel`, `os`, `other_filesystems`,
  `started_utc`, `finished_utc`, `interrupted`, `lockdown`, `secure_boot`, `source`,
  `destination`, `memory`, `volumes`.
- Each volume: `name`, `type`, `cipher`, `key_bits`, `key_location`, `device`, `in_use`,
  `header_backup`, `route`, `verdict`, `key_sha256_16`, `note`. A volume that has more than one
  key, which is a volume in re-encryption, also has `further_keys`: a list with `key_file`,
  `cipher`, `key_bits`, `key_location`, `route`, `verdict`, `key_sha256_16` and `note` for each
  key after the first. The fields of the volume itself are then those of its first key, and
  its `verdict` is that of the key that is least far.
- `destination` is the file system that holds the destination, as the screen names it: its
  source, its type and its mount point.
- `interrupted` is true for a run that a signal asked to end (see "The program").
- `memory` is `null` without `-m`, and else the image: `status` (`captured`, `skipped`, `failed`
  or `interrupted`), `file`, `format`, `bytes`, `seconds`, `sha256`, `direct_io`, `system_map`
  and `note`. `direct_io` is true for an image that was written with direct writes, false for
  one that went through the page cache, `null` where there is no file. With `-F`, which writes
  three images from one read, `memory` is the first and has `further_images`, a list with
  `status`, `file`, `format`, `bytes`, `sha256`, `direct_io` and `note` for each of the others.
- `keep -s` writes at top level `schema`, `tool`, `started_utc`, `finished_utc`, `interrupted`,
  `source`, `candidates`, `volumes`, `memory_pairs` and `further_memory_pairs`. A volume is a
  header: `name`, `type`, `device`, which is the file of the header, `offset` for where it lies
  in that file, `in_memory`, `uuid`, `cipher`, `key_bits`, `digest`, `route`, `key_sha256_16`,
  for a proven key `attempts` and `adjacent_places`, then `verdict`, `note`, and `further_keys`
  for the second key of a header in re-encryption. A
  header that was found in the dump itself has `in_memory` true and its address as `offset`.
  `memory_pairs` is a list with `key_file`, `key_bits`, `verdict` (`found in memory`),
  `key_sha256_16` and `tweak_schedule_at` for each pair that no header proves, and
  `further_memory_pairs` the number of those that are not written as files.
- `vkverify.py` names the file of the header in `device` and has `uuid`, `digest`, `attempts`,
  `adjacent_places` and, with `--truth`, `ground_truth` for a volume.
- No tool of Keep reads the report back. It is for the examiner's own programs and for the
  checks, and `triage.txt` beside it says the same for a reader. A change of a field name is a
  change of the schema string.
- `keep-report/1` was the schema up to 2.0-pre12, which `keytriage.sh` had defined. It had
  three fields that only that script could fill or that it named after a rule that is gone:
  `cryptsetup` and `binaries`, the programs of the examined system that the script ran, which
  were `null` and empty in every report of `keep`, and `evidence_medium`, which is
  `destination` now. `memory` had a field `tool` for the program that took the image, which
  is the `tool` of the report.

## Interaction

Keep has no full-screen interface, opens no window and asks no question. Every tool takes its
parameters as options and writes lines of text, so it works on a console, over SSH, on a serial
line and through a pipe. A dialogue (`keep-menu.sh`, with its launcher `keep.c`), a viewer in
a browser and a printer of the reports (`keep-report.py`) existed and were removed: options
say the same in one line, and `triage.txt` is the report for a reader.

- No cursor movement, no terminfo and no line editor. `vkverify.py` and the scanner alone
  write no escape sequence. `keep` gives a terminal colour, with the SGR sequences for bold and
  for the eight basic colours and with no other sequence, and one line of progress that it
  writes over with a carriage return (see "The program"). Through a pipe and in a file of
  a run it writes neither.
- A path is made absolute before it is used. A dump or an image must be a readable regular
  file, and a destination directory must exist and be writable.
- A wrong option ends with status 2 and the usage line.

## Build

```bash
sudo apt install make musl-tools
make                    # keep and tests/keep-unit, static against musl
sha256sum keep          # for the notes of the examination
```

- `keep` is C11 with the standard library, linked statically against musl with the warnings
  of the `Makefile` as errors. The build downloads nothing. A static program against musl
  needs nothing of the system it runs on. The licence of musl (MIT) lets the file be passed
  on and asks that its copyright notices go with a copy: of the files of musl, only the
  public headers and the start files may be used without them, as the `copyright` file of
  the package `musl-dev` 1.2.4-2 of Ubuntu 24.04 states the terms. A release has that file
  as `musl-copyright.txt`.
- `make san` builds the program and its parts once more against the C library of the
  workstation with the address and undefined-behaviour sanitizers, for the checks.
- The job `build` of `checks.yml` builds `keep` on every push and keeps the file with its
  SHA-256 as an artifact of that run, for 30 days. A release has the file as `release.yml`
  builds it (see "The pipeline and the page").
- The build gives one file for one compiler and one musl. Commit `519023c` gave the same
  file, with the SHA-256 `890e3923...612fedf5`, in the job `build` of the pipeline and in two
  directories of different names on another machine, each with gcc 13.3.0-6ubuntu2~24.04.1
  and musl-dev 1.2.4-2 of Ubuntu 24.04. Commit `4651f09`, the first with the version 2.0,
  gave in both places the file with the SHA-256
  `5cc732729ca0b1ca1a68a343231ef112b564bf19fb35005d679a070dc40f9167`. A commit that changes
  neither `src/`, the scanner nor the `Makefile` builds that file again. A build with another
  compiler or another musl was not compared with it.
- The examined system needs nothing installed: the program uses no `dmsetup`, no `cryptsetup`
  and no shell of that system.

## Use

On scene, with the medium of the examiner at `/media/tools` and the directory that is to take
the output at `DIR`:

```bash
sudo /media/tools/keep                      # the keys, into the current directory
sudo /media/tools/keep -d DIR -m            # the keys into DIR, then a memory image in LiME format
sudo /media/tools/keep -d DIR -m -f avml    # the image compressed
```

In the lab:

```bash
./keep -s DUMP [-d DIR] [FILE...]           # the keys of a dump, proven against the headers in the FILEs
python3 -I vkverify.py CANDIDATES [HEADER...] [--image DISK]... [--out DIR] [--json FILE]
```

- The destination is the directory of `-d`, or the current directory. Where it lies is the
  examiner's decision: `keep` does not test what medium holds it and refuses no place but one
  that is mounted read-only. It must exist and be writable. The report names the file system
  that holds it, with its source, its type and its mount point, as `destination` on the
  screen and in `verdict.json`.
- The output folder of a key run is `triage_<host>_<UTC time>/` with `triage.txt`,
  `verdict.json`, `headers/`, `keys/`, `log/` (the tables of the kernel with each key as zeros,
  and what the scanner said), `memory/` with `-m`, and `manifest.sha256`. That of the search
  of a dump is `scan_<dump>_<UTC time>/` with `triage.txt`, `scan.txt`, `verdict.json`,
  `manifest.sha256` and `keys/`.
- In the names of the folder and of the files every character of the host name or of a
  mapping name that is not a letter, a digit or one of `. _ + = @ , -` becomes `_`, and a
  point at the start as well, so that a name cannot leave the destination, no file is one
  that a listing does not show, and FAT and exFAT take it. Two mapping names that differ only
  by case are kept apart by a further `_`.
- Every file is created with `umask 077`. A header backup, the list of the schedules and a key
  are flushed with `fsync` as soon as they are written, and the run ends with `syncfs` on the
  file system of the destination.
- With `-m` the keys are taken first, because an event can close their window within seconds,
  and then the memory is written to `memory/`. Beside the image go the kernel banner, the
  release, `os-release` and `System.map`, which Volatility 3 needs for its symbol table. A
  `System.map` is kept only when it lists `_stext` or `linux_banner`, because some distributions
  keep a placeholder without symbols in `/boot`.
- `DUMP` is a raw dump, a LiME image, a compressed AVML image or an ELF core. The formats that
  the scanner refuses end the run. `FILE` is a header backup, a raw disk or partition image or
  a device. For the disk file of a virtual machine or an EnCase image, `vkverify.py` takes the
  list `keys/candidates.txt` that `keep -s DUMP` wrote and the image with `--image`.
- The exit status of `vkverify.py` is 0 only when at least one header was located and every
  located header is proven. That of `keep` is said in "The program".

## The program

`keep` is built from `src/` and from the scanner. It does by itself what the tool medium of
Keep 1 did with a static bash and busybox, the `dmsetup` and the `cryptsetup` of the examined
system, and AVML. It starts no other program and asks no question: what a run does is said
by its options.

```bash
sudo ./keep [-n] [-d DIR] [-b N]        # the keys of the running system
sudo ./keep -m [-f FORMAT | -F]         # the keys, then a memory image: lime (default), raw or avml, -F all three
./keep -s DUMP [-n] [-d DIR] [FILE...]  # the keys of a memory dump that exists, proven against the headers in the FILEs
./keep -h                               # the help, -V the version
```

- Without `-s` the program prints the characteristics of the system (host, system, kernel,
  lockdown, Secure Boot, memory, destination), a block for each open volume that ends with
  its verdict, and each key it holds by its file in `keys/`, its length and the first 16
  digits of its SHA-256.
- The screen of a run is a card of facts, as the fetch tools print one: the title of a block
  (the program, a volume, the memory image, the result) and below it one fact in a line, a
  label of at most 11 characters and its value from column 16. A line that the program puts
  together has at most 80 columns: a longer text goes on in the next line below its value,
  and only a word that is longer, as a path or a name of the examined system can be, makes
  a line longer. A line is broken at a space, and not at every one: a number is not parted
  from the word behind it, which is its unit, and the last line does not hold one word
  alone where the word before it can go with it. A block is printed while its work is
  done, so its last line is the verdict, and the block `result` at the end names every
  verdict once more, with the first 16 digits of the SHA-256 of each key that is held.
  `triage.txt` holds the same lines.
- On a terminal the titles are bold, the labels cyan, and the word that says how far a key
  or an image is has the look of its tone:
  - green for what is reached: `captured and proven`, `proven`, an image `captured`;
  - blue for what is held or can still be had and is not proven here: `captured, in use`,
    `captured, not proven`, `needs a memory read`, `found in memory, not proven`, `not
    proven` for a digest that only the dump holds, an image `skipped`;
  - bold without a colour for what was not reached: `live copy only`, `not proven` for a
    header of a file, `unreadable header`, an image `failed`, a write that `FAILED`;
  - nothing for `no key needed`.
  The look says nothing that the word does not. Red and yellow are not used.
- Colour is given where standard output is a terminal, `TERM` is set and not `dumb`, and
  `NO_COLOR` is not set to a value. On such a terminal a step that takes long (the search of
  memory, the read of an image, the attempts on a header) shows one line that is written
  over and taken away when the step is done. Through a pipe or into a file the screen has no
  escape sequence and no carriage return, and such a step prints a line every quarter of a
  minute. `-n` gives a terminal what a pipe gets. `triage.txt` never holds an escape
  sequence or a line of progress, and the last line of the screen, which says that every
  file is flushed, is written when the report is closed.
- A control character in a text of the examined system, as in the name of a mapping or of a
  file, is printed as a space.
- The line `in use` of a volume says what it carries. Where that could not be looked up, it
  says `unknown` and not `no`, and where nothing is found and the kernel counts the device
  as open, it says how often: something reads the device that leaves no trace in `/sys` and
  in the mount table.
- A digest of a header is computed up to 16777216 iterations. cryptsetup makes a digest to
  cost 125 ms, which is some hundred thousand, and a header can state up to 4294967295, with
  which one attempt takes from 21 minutes to more than an hour. A digest beyond the bound is named as
  one that is not computed here, like one with a function that `hash.c` does not have, and
  the key and the list of the schedules are kept for the lab.
- `-m` takes a memory image after the keys, into `memory/` of the folder of the run, as
  `memory.lime`. `-f` names another format: `raw`, where each byte lies at the file offset
  that is its physical address, or `avml`, the compressed format of AVML. `-F` writes all
  three from one read of the memory. An image that was asked for and is not there ends the
  run with status 1. An image is written with direct writes, which pass the page cache of
  the machine, where the file system of the destination has them, and when it is flushed
  the pages that the cache holds of it are let go. The run says which way each file was
  written.
- The header of a volume is read past the page cache of its device, as cryptsetup reads it,
  and its copy is written with direct writes and its pages are let go, so that a header
  takes no free memory of the machine on its way: 16 MiB for a LUKS2 header as cryptsetup
  makes it, for the device and once more for the copy. Where a device takes no direct reads
  or the file system of the destination no direct writes, the run says so in a line
  `header`. A copy that cannot be written to its end is removed, so that its part does not
  take the room of the keys.
- A run that has begun is brought to its end and to its status, whatever becomes of its
  screen. It goes on when the reader of a pipe goes away and when its terminal hangs up, as
  that of a session over a network that is lost: the lines are in `triage.txt`. A limit of
  the size of a file or of processor time that its shell had is taken off where the process
  may, which root may, and where it may not, a write beyond the limit fails like any write.
- An interrupt from the keyboard (`SIGINT`) and `SIGTERM` ask a run to end, and it ends in
  order. The first of either is noted, and the steps that take long end where they are and
  say so: the search of memory, the search of a `FILE` for headers, the attempts on a header
  and the read of an image. What costs no time is still done: a key that the table holds is
  taken and proven, also for a volume that comes after the search, and a header is still
  backed up. A key that the search or the attempts did not reach gets `needs a memory read`,
  and a header of a dump `not proven`, with a note that names the signal as the reason. The
  list of the schedules of the part that was searched is kept, and none of it is tried. An
  image whose read was ended is kept as the part that was read, with its SHA-256 in the
  manifest, and has the status `interrupted`: the raw image is shorter, the compressed image
  has fewer blocks, and the LiME image has a last range that ends before the end that its
  header states, unless the read ended between two ranges. An image that was not begun has
  that status and no file. Then the report and the manifest are written, a line says that
  the run was interrupted and by which signal, `interrupted` is true in `verdict.json`, and
  the status is 1. A second signal of the same kind ends the process at once: each key that
  was written before is flushed, `triage.txt` holds the lines up to there, and there is no
  `verdict.json` and no manifest. A signal that the process was started to ignore stays
  ignored, as `SIGINT` is for a command that a shell without job control starts in the
  background.
- `-s DUMP` searches a dump as `kcore-keyscan` does and proves which of the keys is the
  volume key of each LUKS header in the `FILE`s, as `vkverify.py` does. A `FILE` is a header
  backup, the raw image of a partition or of a whole disk, or a device: its start is read as a
  header, and behind it every sector that begins with the magic of LUKS. The pairs of
  schedules that lie as the kernel keeps the two keys of an XTS volume are tried first, then
  each key alone, then every other pair. Every header has the first two before any header
  has the third, which is the square of the number of keys and is counted on the screen
  before it begins. It writes `scan_<dump>_<time>/` into the destination,
  with `triage.txt`, `scan.txt`, `verdict.json`, `manifest.sha256` and `keys/`: the list
  `candidates.txt` and one `NAME.vk` for each proven key, where `NAME` is the name of the
  file, with `@0xOFFSET` for a header that does not lie at its start, and `-2` for the second
  key of a header in re-encryption.
- The dump itself is searched for what a machine can hold of a header: a LUKS1 header at the
  start of a page, and the object `digests` of the metadata of a LUKS2 header. Either proves
  a key as the header in a file does, and stands in the report as `memory@0xADDRESS`. So a key
  can be proven from a dump alone. A header that is among the `FILE`s is not taken from the
  memory as well. What the memory holds can be of a volume that was closed, so such a digest
  without a key does not count against the status.
- Where no header is found, in a `FILE` or in the dump, nothing can be proven, and the run
  says so. A pair of schedules that lies as the kernel keeps the two keys of a volume, and
  that no header proves, is written as `keys/memory-pair-N.vk` and named `found in memory,
  not proven`: it is a candidate for a volume whose header is not at hand, until a header
  accepts it. Sixteen are written and further ones counted.
- The status of a key run is 0 when the run completed and every file is flushed, 1 when it
  could not start, a write or a flush to the destination failed, an image that was asked for
  is not there or the run was asked to end, and 2 for a wrong option. With `-s` the status is
  that of the search of the dump, 1 also where a write failed or the run was asked to end,
  and with `FILE`s also 1 where they hold no header or a header has a key that is not proven.
- `-d DIR` is the destination of either run, by default the directory of the start, and `-n`
  the plain screen of either. `-b N` is for the running system only, and so are `-m`, `-f`
  and `-F`.
- A wrong option, an option without its value, an argument that belongs to no option and
  options that do not go together end with status 2 and the usage.
- The status of a run on the running system is 1 also where the table of a mapped device
  could not be read, so that a volume in it is not examined, and that of either run where a
  line of the report could not be put together for lack of memory. The line stands in the
  report as `(no memory for this line)`.

### What it does in place of which tool

| The tool | In `keep` | Checked against |
|---|---|---|
| `dmsetup ls --target crypt`, `dmsetup table --showkeys` | `src/dm.c`: the ioctls `DM_LIST_DEVICES` and `DM_TABLE_STATUS` of `/dev/mapper/control` | `dmsetup` 1.02.185 on kernel 6.8: the same devices, tables, UUIDs and keys |
| `cryptsetup status` | `src/triage.c` and `src/volume.c`: the type from the UUID of the mapping and the header, the cipher, the key size and the key location from the table line, the device from `/sys/dev/block`. Which devices are one volume, and where its header lies, is read off the tables as `_init_by_name_crypt` of cryptsetup does it | `cryptsetup status` of ten distributions and two runner images on the same mappings: the same type, key size, key location and device, and the cipher of `dmsetup table`. Up to 2.0-pre12 `keytriage.sh` on the same mappings: the same line of `verdict.json` for every volume. For a volume in re-encryption the keys that `dmsetup table --showkeys` shows |
| `cryptsetup luksHeaderBackup` | `src/luks.c`: the header and the keyslot area read from the backing device, past its page cache | `cryptsetup` 2.4.3 to 2.8.9: the same file byte for byte, for LUKS1 and LUKS2, read and written past the page cache and through it |
| `cryptsetup open --test-passphrase` | `src/luks.c` and `src/hash.c`: PBKDF2 of the key against the digest of the header backup | `cryptsetup` 2.4.3 to 2.8.9 on the same headers and keys, and Python's `hashlib` |
| `kcore-keyscan` | `kcore-keyscan.c` linked in without its `main` | the scanner before the change: the same output, messages and status on every format |
| `kcore-keyscan` with `vkverify.py`, for a header backup and a raw image | `src/dump.c`: the search of a dump, the headers of the files, and the proof of the candidate keys against each | `vkverify.py` on the same schedules and headers: the same verdicts and the same keys. On a guest, the keys of two open containers from the image that the program took of that machine |
| bash and the applets of busybox | C, with the standard library only | `tests/unit-check.sh` |
| AVML | `src/image.c`, `src/snappy.c` and `src/memory.c`: the RAM ranges of `/proc/iomem` read through `/proc/kcore`, written as a LiME image, a raw image or the compressed format of AVML | AVML 0.21.0 itself: it converts the compressed image to the LiME image of its blocks and the LiME image to the raw one, byte for byte the files that Python writes from the formats. On a guest, the image that AVML took of the same machine: the same amount of memory, and the key schedules at the same addresses |

### What the sources say

Read in Linux 4.18, 5.10, 6.12 and 6.18, cryptsetup 2.0.6, 2.3.7, 2.7.0 and 2.8.1, and LVM2
2.03.22:

- The kernel hands the table of a mapping to every caller with `CAP_SYS_ADMIN`, the key of a
  crypt target in hexadecimal included (`ctl_ioctl` and `retrieve_status` in `dm-ioctl.c`,
  `crypt_status` in `dm-crypt.c`). No flag asks for the key and lockdown does not withhold it.
  It is `dmsetup` that replaces the key by zeros (`_status` in `dmsetup.c`).
- A request states an interface version, and the kernel refuses one whose minor number is above
  its own (`check_version`). `dmsetup` states 4.0.0 for both requests, and so does `dm.c`.
- The structures of `dm-ioctl.h` have not changed their layout in these versions. They are
  written out in `dm.c`, so the build needs no kernel headers.
- With `DM_SECURE_DATA_FLAG` the kernel wipes its copy of the answer, which holds the key.
- `/dev/mapper/control` can exist where the module is not loaded (the alias
  `devname:mapper/control` of dm-mod), and opening it then loads the module. The program opens
  it only where `/sys/class/misc/device-mapper` exists.
- cryptsetup gives a mapping the UUID `CRYPT-<type>-<UUID without hyphens>-<name>`
  (`dm_prepare_uuid`) and reads the type back from it (`crypt_init_by_name_and_header`). For
  LUKS it then reads the header from the device of the table, and a header that is missing or
  has another UUID makes the mapping one without a type (`_init_by_name_crypt`,
  `crypt_uuid_cmp`).
- `luksHeaderBackup` writes, for LUKS1, the device up to the end of the last keyslot, with the
  unused stretch between the header and the first keyslot as zeros, to a multiple of the page
  size (`LUKS_hdr_backup`), and for LUKS2 both copies of the header and the keyslot area as
  they are (`LUKS2_hdr_backup`). The four releases write the same bytes.
- Where one copy of a LUKS2 header is damaged, cryptsetup writes it anew from the other when it
  reads the header. The program reads the copy that holds and writes nothing.
- A process that is not dumpable writes no core file (`do_coredump`).
- cryptsetup reads a header past the page cache where it can. It opens the device with
  `O_DIRECT`, reads a block as a test, and opens the device in the usual way where the open
  or that read is refused (`device_ready` and `device_read_test` in `lib/utils_device.c`).
  It reads whole blocks into aligned memory and copies out of them what was asked for
  (`read_lseek_blockwise` in `lib/utils_io.c`). This is so in the four releases.
- A direct read of a block device is whole blocks of the device: in Linux 4.18 its place,
  its length and the address of its memory are multiples of the logical block size
  (`blkdev_direct_IO` in `fs/block_dev.c`), in 6.12 its place and its length, and its memory
  as the device states it (`blkdev_dio_invalid` in `block/fops.c`).
- The kernel drops the page cache of a block device when its last opener closes it
  (`__blkdev_put` in `fs/block_dev.c` of Linux 4.18, `blkdev_flush_mapping` in `block/bdev.c`
  of 6.12). dm-crypt holds the device of an open volume open, so what is read from such a
  device in the usual way stays in the cache. Measured on Linux 6.18, with a loop device on
  a LUKS2 container that a second descriptor held open: after the header was copied in the
  usual way the cache held 5248 pages of the device, after direct reads none, and none
  either way once the last descriptor was closed.
- A signal whose default is to end the process ends a run in the middle (signal(7)). The
  kernel sends `SIGPIPE` to a process that writes to a pipe without a reader (`pipe_write`
  in `fs/pipe.c` of Linux 4.18 and 6.12), `SIGHUP` to the session leader and to the
  foreground processes of a terminal that hangs up (`tty_signal_session_leader` in
  `drivers/tty/tty_jobctrl.c` of 6.12), and `SIGXFSZ` to a process that writes at or beyond
  its limit of the size of a file (`generic_write_checks` in `mm/filemap.c` of 4.18,
  `generic_write_check_limits` in `fs/read_write.c` of 6.12). With the signal not taken the
  write fails with `EPIPE`, `EIO` or `EFBIG`. Seen with the program before 2.0-pre11: a
  reader that ended after one line, a hang-up and `ulimit -f 1` each ended the search of a
  dump with no key file or one, an empty or short `triage.txt` and no report.
- The kernel answers a request for the table of a mapped device that is not there with
  `ENXIO` (`find_device` and `table_status` in `dm-ioctl.c` of Linux 4.18 and 6.12), and
  states with every answer about a device how often it is open (`__dev_status`).
- `dmsetup table` replaces by zeros the key of a crypt target and the keys that a
  dm-integrity target can have behind `internal_hash:`, `journal_crypt:` and `journal_mac:`
  (`hide_key` and `_status` in `dmsetup.c` of LVM2 2.03.22).
- cryptsetup makes the digest of a header to cost 125 ms on the machine that formats
  (`LUKS_MKD_ITERATIONS_MS` in `lib/luks1/luks.h` and `lib/luks2/luks2_digest_pbkdf2.c`), with
  1000 iterations at least. Measured here with the SHA instructions: 4000000 iterations of
  PBKDF2 take 1.2 s with SHA-256, 3.8 s with SHA-512 and 3.9 s with SHA-1, so 125 ms are
  about 430000 iterations of SHA-256.
- A stream of the C library that cannot write drops what it held and remembers only that it
  could not. A later flush of what was written after it succeeds. Measured with musl and
  with glibc: after a write that failed, `fflush` returned 0 and `ferror` 1, and the file
  lacked the bytes. So a flush alone does not say that a file is whole.
- Memory that a process with `mlockall(MCL_FUTURE)` allocates is taken from the free memory
  of the machine at once, read or not. Measured: two buffers of 8 MiB that were never
  written raised the locked memory of a process from 216 kB to 16608 kB.
- LUKS2 with integrity is two mapped devices (`create_or_reload_device_with_integrity`): `NAME`
  with a crypt target on `NAME_dif`, and `NAME_dif` with one integrity target on the device.
  The header lies on that device, and cryptsetup finds it by the option
  `integrity:<tag size>:<algorithm>` of the crypt line and the single integrity target below
  (`_init_by_name_crypt`). The line of an integrity target begins with its device in Linux
  4.18, 5.10, 6.12 and 6.18. A LUKS2 volume on a dm-integrity device that stands alone has no
  such option, and its header is on that device.
- With `--integrity hmac-sha256` the volume key is the key of the cipher and then the key of
  HMAC, 96 bytes for `aes-xts-plain64` (`crypt_copy_authenckey` in `dm-crypt.c`), and the
  kernel names the cipher `capi:authenc(hmac(sha256),xts(aes))-plain64`. `cryptsetup status`
  turns that name back into `aes-xts-plain64` (`crypt_capi_to_cipher`).
- While cryptsetup re-encrypts an open volume, `NAME` is a linear target on `NAME-overlay`,
  which has the crypt targets of the new and the old key, and the part in work lies on
  `NAME-hotzone-forward` or `-backward` (`reencrypt_init_device_stack`,
  `reencrypt_make_targets`). The two helpers have the UUID
  `CRYPT-SUBDEV-<UUID of the volume>-<name>`. A volume that was interrupted or closed in that
  state has the crypt targets of both keys in the table of `NAME`
  (`LUKS2_assembly_multisegment_dmd`). Its header has a digest for each key and a third digest
  that names no data segment.
- `/proc/kcore` is an ELF64 core. A `PT_LOAD` segment of RAM and the one of the kernel text
  state the physical address they begin at, and every other segment the address -1
  (`kcore.c`). This is so in Linux 4.12, 4.18, 5.14 and 6.18; Linux 4.9 states 0 for every
  segment. The text of the kernel is offered twice, by its own segment and by the RAM
  segment that holds it.
- In Linux 5.14 and 6.18 a page of a RAM segment that is not in use as RAM, that is offline
  or that has a hardware error is handed out as zeros, with no error (`read_kcore`,
  `read_kcore_iter`). An image cannot tell such a page from one that holds zeros.
- Opening `/proc/kcore` needs `CAP_SYS_RAWIO` and is refused under lockdown in the mode
  `confidentiality` (`LOCKDOWN_KCORE` stands behind `LOCKDOWN_INTEGRITY_MAX` in
  `security.h`). `/dev/mem` is refused from the mode `integrity` on, and with
  `STRICT_DEVMEM` it hands out no page that is RAM (`devmem_is_allowed`), so it is no source.
- A RAM segment of `/proc/kcore` is whole pages: the kernel takes the start of a range of
  RAM up to the next page and its end down (`walk_system_ram_range` in `kernel/resource.c`
  of Linux 4.18, which `kcore_update_ram` calls). What the boot loader hands the kernel as
  setup data is a range of its own in the memory map, begins and ends where its bytes do,
  and is named `System RAM` like the memory around it (`e820__reserve_setup_data` and
  `e820_type_to_string` in `arch/x86/kernel/e820.c`). So a page in which one such range
  ends and the next begins is in no segment, and no reader of `/proc/kcore` has it.
- `/proc/iomem` names the ranges of physical addresses, each as `start-end : name` with the
  end included, and shows 0 for every address to a reader without `CAP_SYS_ADMIN` (`r_show`
  in `kernel/resource.c`). RAM is named `System RAM`. RAM that a driver added to the running
  system is named `System RAM (driver)`, from Linux 5.8 on (`add_memory_driver_managed`).
- AVML 0.21.0 takes the lines that end with ` : System RAM`, so not the RAM of a driver, and
  reads each range through the segments of `/proc/kcore` by their physical addresses
  (`iomem.rs`, `snapshot.rs`). It cuts a range into blocks of 16 MiB and leaves out a block
  that is all zeros, in both of its formats (`image.rs`). Its compressed format is, for each
  block, a header like that of LiME with the magic `AVML` and the version 2, a framed Snappy
  stream, and the length of that stream in 8 bytes (`io/snappy.rs`).
- A LiME image is a chain of ranges, each behind a header of 32 bytes: the magic
  `0x4C694D45`, the version 1, the first and the last address, and 8 bytes of zeros
  (`lime.h` of LiME).
- A framed Snappy stream is a chain of chunks of at most 64 KiB of data, each with the masked
  CRC-32C of its data, compressed or as it is. Which copies a compressor finds is its own
  matter, so two compressors write different streams of the same data
  (`format_description.txt` and `framing_format.txt` of Snappy 1.2.1).
- A file that is written in the usual way goes through the page cache: the kernel takes
  free memory for its pages, and what lay there is gone. A file that is opened with
  `O_DIRECT` is written from the memory of the program to the device. Read in Linux 4.18
  and 6.12, LiME 1.9.1 and coreutils 9.4:
  - Such a write must be whole blocks, at its place in the file, in its length and in the
    address of its memory (`__blockdev_direct_IO` in `fs/direct-io.c`). The program writes
    from a buffer at a page address, a mebibyte at a time.
  - A file system without such writes refuses the file at open with `EINVAL`
    (`open_check_o_direct` in Linux 4.18, `do_dentry_open` in 6.12). The file is made
    before that and stays, as a run on Linux 6.18 showed. ramfs is one in both (`ramfs_aops`,
    `ram_aops`), and tmpfs in 4.18. In 6.12 tmpfs opens such a file (`FMODE_CAN_ODIRECT` in
    `mm/shmem.c`), and keeps it in memory like any of its files.
  - FAT takes a direct write that makes the file longer through the page cache by itself
    (`fat_direct_IO`), and the kernel writes those pages out and drops them before the write
    returns (`direct_write_fallback` in `fs/libfs.c` of 6.12, `__generic_file_write_iter` in
    4.18). exFAT of 6.12 takes such a write as it is (`exfat_direct_IO`). Linux 4.18 has no
    exFAT.
  - btrfs takes every direct write to a file with checksums of its data through the page
    cache in the same way, from Linux 6.18 on (`btrfs_direct_write` in
    `fs/btrfs/direct-io.c` of 6.18, 7.0 and 7.2, not of 6.12). Every file has such checksums
    unless they are turned off. The kernel drops the pages that are free to go when the
    write returns (`invalidate_mapping_pages`), and not the others.
  - LiME writes with `O_DIRECT` where its option `dio` is given and a first write of that
    kind succeeds, and otherwise without (`setup_disk` in `disk.c`).
  - `dd` of GNU coreutils writes the last block of a file, which is no whole one, after it
    has taken `O_DIRECT` off the descriptor (`iwrite` in `dd.c`), and names the file to the
    kernel as one whose pages are not needed once it is flushed (`POSIX_FADV_DONTNEED` in
    `invalidate_cache`). The program does both.
  - A page that the cache lets go is free memory and keeps its bytes until it is used
    again. The kernel wipes a page that is freed only where `init_on_free` is on
    (`free_pages_prepare` in `mm/page_alloc.c` of Linux 6.12). Linux 4.18 has no such
    switch and writes over a freed page only with page poisoning, which is for debugging.
- Colour on a terminal is the SGR sequences of ECMA-48. Read in Linux 4.18 and 6.12, git
  2.43.0, sudo 1.9.15p5 and the text of no-color.org:
  - The console of Linux takes 1 for bold, 30 to 37 for the eight colours and 0 for the end
    of both (`csi_m` in `drivers/tty/vt/vt.c`), and shows a bold colour as the bright one.
    Its blue is `0000aa` and its bright blue `5555ff` (`default_red`, `default_grn`,
    `default_blu`), so the program writes blue bold only. A carriage return puts the cursor
    to the start of the line (`cr`).
  - git gives colour where the output is a terminal and `TERM` is set and not `dumb`
    (`check_auto_color` in `color.c`, `is_terminal_dumb` in `editor.c`).
  - `NO_COLOR`, set and not empty, asks a program for no colour.
  - sudo hands `NO_COLOR` on to no program unless it is configured to
    (`initial_keepenv_table` in `plugins/sudoers/env.c`), which is why there is an option
    as well.
- Nothing in the kernel keeps a LUKS header: dm-crypt is given the key and the cipher, and
  cryptsetup reads the header past the page cache where it can (`O_DIRECT`). What a machine
  holds of a header is what else read it. This is not from a source but from runs on a guest
  (Ubuntu 24.04.5, kernel 6.8.0-147-generic, cryptsetup 2.7.0, udisks2 2.10.1-6ubuntu1.5),
  with containers on loop devices with direct I/O and the images taken by AVML:
  - `udisksd` held the whole metadata of an open LUKS2 volume twice in its heap, a minute
    after the volume was opened. The metadata of a header with one keyslot have 731 bytes,
    and the object `digests` in them about 200, which fits a page.
  - After the caches were dropped and 85 % of the free memory was written over once, the
    image still held those metadata at 4 places. The LUKS1 header was gone in one run and
    was there at one place in another.
  - From such an image alone, with no file, `keep` proved the volume keys of both
    containers, and left a digest of a volume that an earlier check had closed as not
    proven.
- cryptsetup gives the key of digest N the keyring description `cryptsetup:<UUID>-d<N>`
  (`get_key_description_by_digest`, the same in 2.0.6, 2.7.0 and 2.8.1), so the reference in a
  table says which digest of the header its key gives.

### Its parts

| File | What it does |
|---|---|
| `src/main.c` | The options. Makes the process not dumpable, and one that the loss of its screen and a limit of its shell do not end |
| `src/dump.c` | The search of a memory dump that exists: its schedules, the LUKS headers of the files that are given, the proof of the keys against them, and the pairs that no header proves |
| `src/run.c` | The folder of a run: its screen and its report, which hold the same lines, its files, their flushing and the manifest |
| `src/memory.c` | The memory image of a run: the room it needs, its files, and what the lab needs beside it to name the kernel |
| `src/image.c` | What an image holds, from `/proc/iomem` and `/proc/kcore`, and the three formats. The memory is read once for all files, and written with direct writes |
| `src/snappy.c` | The framed Snappy format, written, with CRC-32C |
| `src/triage.c` | The run: destination, system, volumes, the ladder for each key, verdicts, `triage.txt`, `verdict.json`, `manifest.sha256`. Locks the memory of the process |
| `src/dm.c` | The list of the mapped devices and the table of one, from the kernel |
| `src/volume.c` | Which mapped devices are a volume, which further devices are part of it, which keys it has and where its header lies, read off the tables |
| `src/luks.c` | The header of LUKS1 and LUKS2: reading, past the page cache where the device has direct reads, the copy for the evidence, the proof of a key |
| `src/hash.c` | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, HMAC and PBKDF2, with a self-test against the examples of the standards at every start. SHA-256 with the SHA instructions of the processor where it has them |
| `src/json.c` | A reader of JSON as RFC 8259 defines it, for the metadata of LUKS2 |
| `src/sys.c` | Mounts, what a volume carries, lockdown, Secure Boot, the name of the system, each from a named file |
| `src/util.c` | Texts that grow, names for the screen and for files, hexadecimal, flushing, a file that is made for direct writes and written with them |
| `kcore-keyscan.c` | The scanner. `-DKEYSCAN_LIBRARY` leaves out its `main`, and `src/keyscan.h` declares what remains. It hands the memory it reads to the program, which searches it for headers, and says what its search read |
| `tests/keep-unit.c` | Runs one part at a time, for `tests/unit-check.sh` |

### Where it differs from `keytriage.sh` and from the tools it stands for

`keytriage.sh` is described here as its last version, 1.5.1, was. It is no longer in the
repository, and what it did is said for a reader of its reports and for the comparison
that was made.

- The screen is another one. `keytriage.sh` printed sentences, the routes as `R1 table` and `R3
  memory` and a line `VERDICT:`. `keep` prints the facts of a volume as labels and values (see
  above). The names of the routes stand in `verdict.json` alone. The keyring reference of a
  volume stands in `log/NAME.table.txt` and not on the screen. What the scanner said stands in
  `log/kcore-keyscan.txt` or, for a dump, in `scan.txt`: the screen gives the counts in lines
  of its own, and of a dump also what the scanner warns of.
- A name is shown as the kernel holds it. libdevmapper writes a character outside its list as
  `\xNN` into the name of a mapping, so a mapping that `dmsetup` shows as `name with space` is
  `name\x20with\x20space` in the kernel, in `/dev/mapper` and in `/sys`, and in the report.
- The report has no programs of the examined system to name, which `keytriage.sh` named with
  their paths and SHA-256. `tool` is `keep` and its version.
- `log/NAME.table.txt` holds what the kernel said about a mapping, its key replaced by zeros,
  in place of the output of `cryptsetup status`.
- The header is read before the type is named, and the proof is made against the backup after
  it is written and flushed. A candidate key is not written to the destination before it is
  proven.
- The digest functions are those of `hash.c`. A header with another one (ripemd160, whirlpool)
  is backed up, and its key gets `captured, not proven` on the table route and `needs a memory
  read` on the memory route, with the function named. `vkverify.py` proves it in the lab.
- The memory of the process is locked (`mlockall`), so that no key reaches the swap space, and
  the process is not dumpable. The lock is taken where it can hold: as root, or where the user
  has no limit of locked memory. A user with a limit, as in the lab, is told that the memory is
  not locked. `cryptsetup` creates no lock file in `/run/cryptsetup`, because
  it does not run.
- A LUKS2 volume with integrity gets the same verdicts from both. `keep` names its
  cipher as the kernel does, `capi:authenc(hmac(sha256),xts(aes))-plain64`, and `keytriage.sh`
  as `cryptsetup status` does, `aes-xts-plain64`. With the key in the keyring both end with
  `live copy only`: the volume key holds the key of HMAC, which is no AES key.
- A volume in re-encryption has two keys, one for the part that is done and one for the rest.
  `keep` lists the volume once, takes each key through the ladder, proves each against
  its own digest of the header and writes `keys/NAME.vk` and `keys/NAME-2.vk`, in the order of
  the table. A key from memory is the key of the digest that its keyring reference names. The
  verdict of the volume is that of the key that is least far. `keytriage.sh` takes the first
  key only and proves none, because `cryptsetup open --test-passphrase` refuses one volume key
  for such a header (seen with cryptsetup 2.7.0), and while cryptsetup works it lists
  `NAME-overlay` in place of the volume, without a header.
- `-b N` is the number of proof attempts for each key, which is that for each volume where a
  volume has one key.
- It asks cryptsetup nothing and takes none of its locks. `cryptsetup status` waited without
  end on a volume whose re-encryption was paused in a step, and `keep` read the same
  volume. A header that cryptsetup writes at that moment is read from the copy that holds.
- From 2.0-pre11 on the header is read past the page cache of the device, as cryptsetup
  reads it (see "What the sources say"), and its copy is written with direct writes, with
  its SHA-256 computed on the way, so that the manifest does not read the copy again. The
  copy is read back for the proof with direct reads, and what the cache holds of it is let
  go. Up to 2.0-pre10 the device was read in the usual way and the copy written in the
  usual way: after a key run the cache held the header twice, 16777216 bytes each for the
  LUKS2 headers of the installed guests, and an image that was taken afterwards held the
  metadata of the header whatever the machine had held of them before. `keytriage.sh`
  leaves the copy of `cryptsetup luksHeaderBackup` in the cache. The search of a dump
  reads the dump and its `FILE`s through the page cache: it is work of the lab.
- A copy of a header that cannot be written to its end, as on a destination without room
  for it, is removed, and the run ends with status 1. The key of the table and the list of
  the schedules are written all the same, without a proof on scene. `keytriage.sh` leaves
  what `cryptsetup luksHeaderBackup` leaves.
- The run is not ended by `SIGPIPE`, `SIGHUP` or `SIGXFSZ`, and takes the limits of the
  size of a file and of processor time off where it may. `keytriage.sh` was ended by each,
  and by an interrupt from the keyboard, which `keep` takes as a request to end in order.
- A table of a mapped device that cannot be read is named on the screen, and the run ends
  with status 1. Only a device that was removed since the list was read is passed over.
- A name that begins with a point has `_` in its place in a file name, so that no file of a
  run is one that a listing does not show. `keytriage.sh` keeps the point.
- The line `in use` says `unknown` where the look-up failed, and names the opens that the
  kernel counts where nothing else is found. `keytriage.sh` says `no` in both cases. The
  field `in_use` of the report is the same in both.
- `log/NAME.table.txt` has zeros also for the keys of a dm-integrity target, as `dmsetup
  table` prints them.
- A destination that `/proc/self/mountinfo` does not name, as in a root that is no mount
  point, is taken, and the report says that its file system is not known. `keytriage.sh`
  does not start there.
- A digest beyond 16777216 iterations is not computed (see above). `keytriage.sh` leaves
  the proof to cryptsetup, which computes what the header states.
- The search of a dump proves against header backups, raw images and devices. The disk file
  of a virtual machine and an EnCase image are read by `vkverify.py` only, and so is a header
  whose digest uses a function that `hash.c` does not compute.
- For a header in re-encryption the search of a dump proves both keys, each against its own
  digest. `vkverify.py` takes the first digest only.
- A dump is searched for headers as well, which `vkverify.py` does not do.
- With several headers every one has the attempts that cost little before any has every
  other pair of keys. `vkverify.py` ends one header before it begins the next.
- A LUKS2 header in the image of a disk is found by the magic of its first copy. One whose
  first copy is overwritten is found only where it lies at the start of the file.
- The memory image is read as AVML reads it, the RAM ranges of `/proc/iomem` through
  `/proc/kcore`, with these differences:
  - A LiME image has one record for each range of memory, also where the range is all
    zeros. AVML writes a record for each block of 16 MiB and leaves out a block of zeros,
    which a reader cannot tell from memory that is not there. The compressed image is
    written as AVML writes it, blocks of zeros left out.
  - RAM that a driver added (`System RAM (driver)`) is in the image. AVML leaves it out.
  - The raw format is offered: each byte at the offset that is its address, with what lies
    between the ranges not written. It is as long as the highest address of RAM.
  - `-F` writes all three formats from one read, so the files hold the same memory and one
    that is damaged later does not take the others with it. They lie on one medium, need
    about three times the room of the memory, and the read lasts as long as the slowest of
    them is written.
  - The SHA-256 of an image is computed while it is written, and the file is not read
    again. `keytriage.sh` reads it again for that.
  - An image is written with direct writes, which pass the page cache, so that the file of
    the image does not take the free memory that the image has yet to read. AVML writes
    through the cache, and `keytriage.sh` then reads the file through it once more. Where
    the file system of the destination has no direct writes, the image goes through the
    cache, and the run and `direct_io` of the report say so. What is left at the end of a
    file and is no whole block of 4096 bytes goes through the cache as well: one page. A
    file that is flushed has the pages that the cache holds of it let go, so that the
    cache keeps no copy of the image, which holds the keys. A page that is let go keeps
    its bytes until the kernel uses it again (see "What the sources say"), so this says
    less for an image that went through the cache than the direct writes do, which put
    no page of it there.
  - An image is started where the destination has room for it and 64 MiB more. A compressed
    image is started whatever room there is, as with `keytriage.sh`, except beside other
    images, where it must not take their room and needs room for the most it can take.
  - The run ends with status 1 where an image that was asked for is not there.
    `keytriage.sh` ends with 0.
  - What `/proc/iomem` names as RAM and `/proc/kcore` does not offer is counted on the
    screen. On a machine with BIOS it is the last part of the first range, which ends inside
    a page: 3072 bytes on the guest of the first run. On a guest with UEFI it was four
    pages, 16384 bytes (see "Where it has run").
  - A line on the screen every quarter of a minute says how far the read is.
  - The report names the format of a compressed image `avml compressed`, as `keytriage.sh`
    does, and has the further images of one read in `further_images` of `memory`.

### What the checks have found

Defects of `keep` were found by its checks and runs while it was written, and each
check stays. The first five: a copy of zero bytes from a null pointer in the hash code and a sort of an empty
list of volumes (the sanitizers), the devices that stand on a volume named in the order of the
directory and not of their names (the run beside `keytriage.sh` on LVM), the two keys of a
volume in re-encryption found in memory and each written as the key of the other part (a run on
a guest, now compared with the table in `compat-check.sh`), and a helper device listed as a
volume of its own in the moment before cryptsetup puts it below its volume (a run on a guest,
now a case of `unit-check.sh`). A sixth was found by running `unit-check.sh` as a user who is
not root: with the lock of the memory in force for what is allocated later, and the limit of
that user for locked memory, the search of a dump had no memory for the files it was to
read. The lock is now taken only where it can hold, and the check runs with a small limit.

One thing was found by a run by hand on a machine (see below) and is no defect of what the
program gave. The search of a dump spent 510 s on a digest without a key before it proved
the key of the header behind it: since 2.0-pre7 every header has the attempts that cost
little first, with a case of `unit-check.sh`.

The runs by hand on installed guests showed two lines of the screen that were broken
badly, and nothing wrong in what the program gave: `16777216` at the end of a line with
`bytes` below it, and `6.65 GiB` with `free` below it. Since 2.0-pre10 a line is broken by
the rule above. `unit-check.sh` has both lines as cases and compares 400 texts with the
rule as it is written there in Python.

Before 2.0 the code was read once more as a whole, by its author and by two readers that
had not written it, with the analyzers of gcc 13.3 (`-fanalyzer`), clang 18.1 and cppcheck
2.13, with valgrind 3.22, with every allocation of a search of a dump made to fail in its
turn, with a destination of 4 KiB to 40 KiB, and with the screen taken away. No read or
write outside a buffer and no fault was found: what the analyzers named was looked at and
is none. With one allocation failed, or every one from a place on, no run of 888 crashed,
and none ended with status 0 with a key, a report or a manifest missing. With a
destination that ran full every run ended with status 1 and said so. What was found, and
is corrected in 2.0-pre11 and 2.0-pre12, each with its check:

- Three signals ended a run in the middle (see "What the sources say"): `SIGPIPE`,
  `SIGHUP` and `SIGXFSZ`. A run now takes none of them.
- `triage.txt` was written a block at a time, so a run that was ended from outside left a
  report without its last lines, or an empty one. It is now written a line at a time.
- A line of the report that could not be put together for lack of memory was replaced by a
  note, and the run ended with status 0. It now ends with status 1.
- The copy of a header that could not be written to its end stayed as a part. On a
  destination without room for it, that part took the room of the keys. The run also
  ended with status 0 after such a write had failed. The part is now removed, and the
  status is 1.
- The table of a mapped device that could not be read was passed over without a word, as
  a device is that was removed since the list was read. It is now named, with status 1.
- The scanner took a LiME image or an ELF core that was cut for one that it had read to its
  end, with status 0, and searched a range of 2^62 bytes without end (see `kcore-keyscan`).
  It gave no status for a list of the schedules that could not be written, which
  `keytriage.sh` relied on. Of a read that failed it took the first 4096 bytes for
  unreadable, also where the page that failed lay behind them: with one such page late in a
  read of 1 MiB, the schedules before it in that read were not found. It is 1.3 now.
- A text file was read into memory of its largest size, whatever its own: 8 MiB for a mount
  table, twice for each volume, and 256 MiB for `System.map`, in memory that is locked and
  so taken from the machine at once. The memory now grows with the text.
- The reader of JSON gave every string the memory of the rest of the whole text. Metadata
  of 20000 members in 269 KiB needed an address space of 5.4 GiB, all of it locked in a
  run, and a header of that kind, which no cryptsetup writes, ended a run of one of the
  readers by the kernel's lack of memory. A string now has the memory of its own bytes,
  and those metadata are read in 8 MiB.
- A write of `verdict.json`, of the manifest or of a list of schedules that failed inside
  the C library was not seen, where the flush after it succeeded: with one such write the
  run ended with status 0 and a report that was no JSON. Every flush now asks the stream
  as well.
- A digest could state up to 4294967295 iterations, and an attempt was begun whatever it
  stated. There is a bound now (see above).
- The search of a dump took a read of a `FILE` that failed, or that gave less than was asked
  for, as the end of the file, and said nothing: a header behind an unreadable sector was not
  found. It now says where the read failed and ends with status 1, and goes on behind a
  read that gave less.
- A key that gave the digest of a header and whose file could not be written was reported
  as a key that was not found.
- `in use` said `no` where the look-up had failed.
- `verdict.json` could hold bytes that are no UTF-8: a longer form of a character, a
  surrogate or a number above 10FFFF in a name passed as it was, and the file was then no
  JSON for a reader that is strict.
- The table of a dm-integrity device in `log/` kept the keys that such a target can have.
  cryptsetup gives the device below a LUKS2 volume with integrity none, so this needed a
  stack made by hand.
- Of the memory that held keys or memory of the machine, four places were given back
  without a wipe: the window of the search of a dump, the buffers of a compressed range in
  the scanner, the last chunk of a compressed image, and the buffer of the C library for
  the list of the schedules.
- A run that could not go on for lack of memory after its folder was made left its report
  without a word of that.
- What the scanner warns of, and why a search read nothing, reached the screen by a second
  reading of the file that the scanner had written them to. The program now takes them from
  the search itself.

One defect of `keytriage.sh` was found on the way: it stated no key size for a LUKS2 volume
with integrity. It was corrected in 1.5.1.

The check on real device-mapper found one more defect, of 2.0-rc1 before it was on `main`:
the last line of a run that a signal had ended had 139 columns. `unit-check.sh` now looks at
every such line in the source.

With 2.0-rc1 the script and its medium were removed, and with them what was there for them
alone. The check on real device-mapper, which had held `keep` against the script, holds it
against `cryptsetup` and `dmsetup` themselves. The report lost three fields that only the
script could fill or that it had named (see "The report"), a function and a macro that
nothing used went, and two commands of `keep-unit` that no check ran. A run that is asked to
end now ends in order (see "The program"), where a signal had ended it at once, with no
report and no manifest.

### Where it has run

Up to 2.0-pre12 `keep` was run beside `keytriage.sh` 1.5.1 by `compat-check.sh`: before any
mapping is made, on the four mappings of the main run, with `-d` and a destination on FAT, on
LVM on LUKS and on LUKS2 with integrity, and alone on a volume in re-encryption. What follows
in this section up to the runs with 2.0-rc1 is from those runs. Beside `keytriage.sh` it gave the
same line of `verdict.json` for every volume, on the table route, the memory route, a mapping
without a type and the null cipher, and header backups and keys that are the same byte for
byte. On the volume in re-encryption it proved both keys, from memory and from the table, each
for its part. It took the memory image of each system, and the schedules of both volume keys
lay in every image at an address at which they lay in the image that AVML had taken. Searched
as a dump that exists, the first image of each run gave both volume keys, proven against the
headers in the images of the two containers. With 2.0-pre12, the last version that was run
beside the script, this held on the ten guests and on both runner images. The output of each
run with 2.0-pre9 was read line by line, of the runs with 2.0-pre11 that of Fedora 45, and of
the runs with 2.0-pre12 those of AlmaLinux 9.9 and of the two runner images:

| System | Kernel | cryptsetup | Where |
|---|---|---|---|
| Debian 13 | 6.12.117+deb13-amd64 | 2.7.5 | `distros.yml` |
| Debian 12 | 6.1.0-56-amd64 | 2.6.1 | `distros.yml` |
| Ubuntu 26.04.1 | 7.0.0-43-generic | 2.8.4 | `distros.yml` |
| Ubuntu 24.04.5 | 6.8.0-147-generic | 2.7.0 | `distros.yml` |
| Fedora 45 | 7.2.11-300.fc45.x86_64 | 2.8.8 | `distros.yml` |
| AlmaLinux 10.3 | 6.12.0-264.16.1.el10_3.x86_64 | 2.8.6 | `distros.yml` |
| AlmaLinux 9.9 | 5.14.0-741.22.1.el9_9.x86_64 | 2.8.6 | `distros.yml` |
| Rocky Linux 10.3 | 6.12.0-264.16.1.el10_3.x86_64 | 2.8.6 | `distros.yml` |
| openSUSE Leap 16.1 | 6.12.0-160100.9-default | 2.8.4 | `distros.yml`, without the part with integrity |
| Arch Linux | 7.3.4-arch1-2 | 2.8.9 | `distros.yml` |
| Ubuntu 24.04.5, runner image | 7.0.0-1014-aws | 2.7.0 | `checks.yml`, also the build with the sanitizers |
| Ubuntu 24.04.5, runner image | 7.0.0-1017-azure | 2.7.0 | `checks.yml`, with 2.0-pre5 and in part with 2.0-pre7, also the build with the sanitizers |
| Ubuntu 24.04.5, runner image | 7.0.0-1020-azure | 2.7.0 | `checks.yml`, with 2.0-pre12, also the build with the sanitizers |
| Ubuntu 22.04.5, runner image | 6.8.0-1070-azure | 2.4.3 | `checks.yml`, up to 2.0-pre8 and with 2.0-pre12, also the build with the sanitizers |
| Ubuntu 22.04.5, runner image | 6.8.0-1073-azure | 2.4.3 | `checks.yml`, also the build with the sanitizers |

On openSUSE Leap 16.1 cryptsetup could not make the container with integrity: the kernel
refused the table that the format loads (`reload ioctl ... failed: Invalid argument`). That
part is reported as skipped there, and LUKS2 with integrity is not checked on that system.

The memory image in these runs:

- Each of the ten guests has 2 GiB of memory, which the kernel names as 2 ranges of RAM. The
  LiME image has 2146938944 bytes, the 2146938880 bytes of the two ranges behind two headers,
  and the raw image 2147340288 bytes. Each was taken as LiME, raw and compressed, and then all
  three from one read, which gave the same list of schedules for the three files. The
  compressed image had 1.19 to 1.46 GB, 55 % to 68 % of the memory. Under KVM the read of
  one image took 2 to 11 seconds and that of all three 15 to 30.
- AVML converted every compressed image, and the scanner found in its LiME image what it
  found in the compressed one.
- The runner images have 16 GiB, in 5 or 6 ranges of RAM by the machine behind them. The
  LiME image of one had 17174331584 bytes and was read in 39 s in one run and in 70 s in
  another. The raw image had 17951621120 bytes on one machine and 20401094656 on another,
  where the ranges reach up to the address of 19 GiB, read in 64 s and 56 s. The compressed
  image had 7641445743 and 10101456970 bytes, read in 46 s and 44 s.
- AVML's own images of the same machines held less memory by whole blocks of 16 MiB, which
  are the blocks of zeros that it leaves out: one block on one guest, ten on another, and 56
  and 59 on the runner with the LiME image in two runs. On the other runner its compressed
  image held 83 blocks less than that of `keep` in one run, which leaves out such
  blocks as well.
- Searched with no file, the image of every guest and of both runners held 2 headers or
  digests of a header, and
  both volume keys were proven from them. This says little about a real machine: the
  containers of the check lie in files, and the cache of those files holds their headers.
  What a machine holds by itself was seen on the guest of the workstation (see "What the
  sources say").
- `keep` took its images after AVML had written one. That the later images hold fewer
  blocks of zeros fits a file that is written through the page cache: the cache takes free
  memory, and what lay there is overwritten. This was not measured by itself.
- From 2.0-pre7 on an image is written with direct writes, and the pages of each file that
  lay in the page cache after the run were counted before anything read the file. With
  2.0-pre7, of an image of 2 GiB with about 524000 pages: on nine guests one page of the
  LiME and of the compressed image, the end of the file, and none of the raw image. On
  Fedora 45, whose root file system is btrfs with compression, 65 to 512 pages of the LiME
  and the raw image and one of the compressed image: btrfs of Linux 7.2 takes a direct
  write through the cache (see "What the sources say"). On the runners, as far as that run
  came, one page of 4192953 of the LiME image and none of the raw image.
- With 2.0-pre8, which lets the pages of a flushed file go, no page of any image lay in the
  cache after the run: on the ten guests for each format and for the three of one read, on
  the runners for the LiME image of 17174331584 bytes (read in 42 s), the raw image of
  17951621120 bytes (73 s) and the compressed image of 10096333254 bytes (50 s).
- With 2.0-pre9, whose screen is another one, the same held on the ten guests and both
  runners, with images of the same sizes but the compressed one of a runner, 10117846686
  bytes. Every screen and every report that `keep` wrote in the check, 38 files on a
  guest, 36 on openSUSE Leap 16.1 and 36 and 42 on the runners, held no escape byte and no
  line of more than 80 columns without a word that needs them. These screens went to
  files: what a terminal is given was looked at by `unit-check.sh` alone (see "Not handled
  or not checked").
- With 2.0-pre11 and 2.0-pre12, which read a header past the page cache of its device and
  write its copy past it, no page of a device with a header and none of a copy lay in the
  cache after a run beside the script, on the ten guests and both runners. On AlmaLinux 9.9
  and on the runners these were 37369 pages in the main run, 107001 in the run on LVM and
  49657 in the run with integrity, and on FAT 505 pages of the copy of the LUKS1 header and
  4096 of that of the LUKS2 header.
- With 2.0-pre12 on the runners: the LiME image of 17174331584 bytes was read in 112 s, and
  the image of AVML of that machine held 57 blocks of 16 MiB less. On the other runner the
  raw image of 20401094656 bytes was read in 44 s and the compressed image of 13313681345
  bytes in 49 s. It held 17123999744 bytes of memory, and the compressed image of AVML
  15647604736, 88 blocks less, in 13702809426 bytes.

With 2.0-rc1 `compat-check.sh` holds `keep` against the tools of the system itself (see
"Checks before a commit"), and no script runs beside it. On the ten guests, with cryptsetup
2.6.1 to 2.8.9:

- In the main run the 4 volumes were those of `dmsetup ls --target crypt`, each with the type,
  the key size, the key location and the device of `cryptsetup status` and the cipher of its
  table, the 4 tables in `log/` were what `dmsetup` prints, the 2 header backups were the files
  of `cryptsetup luksHeaderBackup` byte for byte, cryptsetup accepted the 2 keys of the LUKS
  volumes for their headers, and the 2 keys of the table were what `dmsetup table --showkeys`
  shows. With LVM on LUKS these were 5 volumes, 5 tables, 3 header backups, 3 keys that
  cryptsetup accepted and 2 keys of the table, and with integrity 5, 5, 3, 2 and 3. No page
  of a device with a header or of a copy lay in the page cache after a run: 37369, 107001
  and 49657 pages.
- Sent `SIGTERM` while it searched the memory, `keep` ended the search, kept the keys of the
  table and wrote its report and its manifest, on every guest. Sent it while it read an
  image, it kept the part and named it as interrupted: the first 17424384 or 34201600 of
  2146938880 bytes of the memory, which is the first range and one or two blocks of 16 MiB of
  the second, in a file of 64 bytes more, the two headers. The scanner named such a file as
  one that ends inside a range.
- The LiME image of AVML held all 2146938880 bytes of the memory on seven guests, one block
  of 16 MiB less on two and ten blocks less on one. That of `keep` has 2146938944 bytes on
  every guest. Its compressed image had 853483619 to 1032725436 bytes, 40 % to 48 % of the
  memory, and 973572358 to 1425672055 bytes where it was one of three from one read. In the
  runs beside the script, where an image of AVML had been written and read through the page
  cache before, it had 55 % to 68 %. One image was read in 2 to 12 seconds and all three in
  14 to 35.
- The first run of the new check found two things, on the commit before. On all ten guests
  the last line of a run that a signal had ended had 139 columns, which the look at the
  screens named. On Arch Linux 22 of 16384 pages of the container that had just been opened
  lay in the page cache after the main run, and none on the nine others: the check had let
  the cache of the device go while the system still looked at the new device, which it does
  through the cache. With the script beside it, the run of the script had taken that time.
  The check now waits for udev first, and the run after that had none on all ten.
- The outputs of AlmaLinux 9.9 and of Arch Linux were read line by line. Of the eight others
  the lines of each kind were counted: 23 `PASS` and no other on seven, and on openSUSE Leap
  16.1 21 `PASS` and the one `SKIP` of the part with integrity.
- On the two runner images, with cryptsetup 2.4.3 and 2.7.0 and with the build with the
  sanitizers at the same places, the same held, with the same numbers of volumes, tables,
  header backups, keys and pages. The LiME image of 17174331584 bytes was read in 101 s, and
  the image of AVML of that machine held 58 blocks of 16 MiB less. On the other runner the
  raw image of 20401094656 bytes was read in 44 s and the compressed image of 13378372395
  bytes, 78 % of its 17107222528 bytes of memory, in 46 s. The compressed image of AVML
  held 84 blocks less. An image whose read was ended held the first 17428480 and 34205696
  of 17174331392 bytes. Both outputs were read line by line.
- This is the pipeline of commit `07f9d57`: `distros.yml` on the ten guests, and `checks.yml`
  with the self-test, the unit checks with AVML, the pages, the build and the two runner
  images.

2.0 is the program of 2.0-rc1 under its new name. The same check ran with it once more, on
the ten guests and on both runner images (the pipeline of commit `4651f09`):

- On the ten guests the kernel and the cryptsetup were those of the runs with 2.0-rc1 (see
  "Systems checked"), and each run named its tool as `keep 2.0`. Nine had 23 `PASS` and no
  other line, and openSUSE Leap 16.1 21 `PASS` and the one `SKIP` of the part with integrity.
  The numbers of volumes, tables, header backups, keys and pages were those above, and no
  page of an image lay in the page cache after a run.
- The LiME image of AVML held all 2146938880 bytes of the memory on eight guests, one block
  of 16 MiB less on Ubuntu 24.04.5 and ten less on Rocky Linux 10.3. The compressed image of
  `keep` had 821197033 to 1038426799 bytes, 38 % to 48 % of the memory, and 942255832 to
  1395531588 bytes where it was one of three from one read. On Rocky Linux 10.3 the
  compressed image that was taken alone held 2029498368 bytes of memory, seven blocks of
  16 MiB less than the LiME image before it: the blocks of zeros, which that format leaves
  out. One image was read in 3 to 13 seconds and all three in 23 to 37. An image whose read
  was ended held the first 17424384 or 34201600 bytes of the memory.
- The output of Debian 12 was read line by line. Of the nine others the head, the number of
  the lines of each kind and these figures were taken.
- On the two runner images, with the build with the sanitizers at the same places, every
  part passed and none was skipped, with the same numbers of volumes, tables, header
  backups, keys and pages. On Ubuntu 22.04.5, here with the kernel 6.8.0-1070-azure, the
  LiME image of 17174331584 bytes was read in 92 s, and the image of AVML of that machine
  held 58 blocks of 16 MiB less. On Ubuntu 24.04.5 the kernel chose `xts-aes-vaes-avx512`,
  where the run before had `xts-aes-vaes-avx2` on another machine. The raw image of
  20401094656 bytes was read in 79 s and the compressed image of 13344573170 bytes, 78 % of
  its 17107222528 bytes of memory, in 67 s. The compressed image of AVML held 85 blocks
  less. An image whose read was ended held the first 17428480 of 17174331392 bytes on both.
  The build with the sanitizers read the LiME image in 115 s and the raw one in 120 s. Both
  outputs were read line by line.

The tables of both kinds of volume were first seen on a guest emulated on the workstation
(Ubuntu 24.04.5, kernel 6.8.0-147-generic, cryptsetup 2.7.0), and `compat-check.sh` passed
there with every part. On that guest `tests/keep-unit` gave the list, the tables, the UUIDs and
the keys of `dmsetup` 1.02.185 for six mappings, a plain one and one with a space in its name
among them. The memory images were first taken there too, with every part of
`compat-check.sh`. The outputs of the guest are not kept.

On one machine that is no guest the program was run by hand, by its options and without the
check: Linux Mint 22.3, kernel 6.14.0-37-generic, 16 GiB of memory, Secure Boot on and with
it lockdown `integrity`. The screen and the report of each run were read:

- The LiME image of its 5 ranges of RAM had 16848920736 bytes and was written in 16 to 19 s,
  in three runs. `banners.Banners` of Volatility 3 2.28.2 read one of them and named the
  kernel that ran.
- A LUKS2 container on a loop device with direct I/O, its key in the keyring, got `captured
  and proven` on the memory route.
- AVML 0.21.0 took an image of the machine while the container was open, and that image was
  searched with no file. The digests of the header lay in it, and the volume key was proven
  from them at the first attempt: the key that the triage captured afterwards. The object
  `digests` began 6 bytes before the end of a page and went on in the page behind it. That
  fits a copy in the memory of a program and not the cache of the device, where the metadata
  begin with a page.
- A second digest lay in that image: that of the header of an earlier format of the same
  container, whose key was never in a mapping. It got `not proven`, after every pair of the
  90 keys of the image, 5108 attempts in 510 s, and only then was the header behind it
  looked at.

On a guest that was installed from the installer of its distribution, with the automatic
partitioning and the encryption that the installer offers, the program was run by hand in
the same way: under KVM with UEFI and Secure Boot on, with 4 GiB of memory. AVML 0.21.0 took
an image first, which was searched with no file, and then the program took the keys and an
image of its own:

- Red Hat Enterprise Linux 8.10, a Minimal Install, kernel 4.18.0-553.el8_10.x86_64,
  cryptsetup 2.3.7, lockdown `integrity`. It is the oldest kernel that the program has run
  on.
  - The root volume, LUKS2 on a partition with the volume group of the system on it, opened
    at boot, got `captured and proven` on the memory route. What it carries was named as
    `rhel-root at /, rhel-swap as swap`. The XTS driver was `xts-aes-aesni`, and the two
    schedules lay 496 bytes apart.
  - The image of AVML held the digests of the header at one place, and the key was proven
    from them at the first attempt: the key that the triage captured afterwards, its
    schedules at the same addresses. udisks2 2.9.0 is installed there, and its daemon was
    not running. The object `digests` began 473 bytes after the start of a page, which is
    where it lies in the block of the metadata on the partition. After a restart, before
    any tool had read the partition, the kernel named that block as one that its cache of
    the partition holds (`mincore` on a mapping of the device: the blocks 0, 1, 3 and 7 of
    its first eight). So it was the page cache that held the digests there. What had read
    the block at boot was not looked at.
  - The LiME image of the program had 4274385184 bytes in 9 ranges and was written with
    direct writes to xfs in 7 s. The `System.map` of `/boot` was kept beside it. kdump was
    on, and the 256 MiB that the kernel keeps for it lie in a range of the image.
  - 16384 bytes of RAM were in no segment of `/proc/kcore`: the four pages in which one
    range of `/proc/iomem` ends and the next begins, around three ranges that begin and end
    inside a page (see "What the sources say").
- Red Hat Enterprise Linux 9.9, a Minimal Install, kernel 5.14.0-741.20.1.el9_9.x86_64,
  cryptsetup 2.8.6, lockdown `integrity`, kdump on.
  - The root volume, laid out as on RHEL 8.10, got `captured and proven` on the memory
    route, with `rhel-root at /, rhel-swap as swap` and the driver `xts-aes-aesni`.
  - Before any tool had read the partition, the cache of the partition held the same
    blocks as on RHEL 8.10, the block of the metadata among them. The image of AVML held
    the digests at one place, 474 bytes after the start of a page as in that block, and
    the key was proven from them at the first attempt: the key of the triage. udisks2
    2.9.4 is installed, and its daemon was not running.
  - The triage named another address for the two schedules than the search of the image
    of AVML had, a lower one, and the search of `/proc/kcore` listed 86 schedules where
    the image had 58, as it had listed 85 for 56 on RHEL 8.10. The key is the same and is
    proven. What added the schedules was asked on RHEL 10.3 (below).
  - The LiME image of the program had 4274356544 bytes in 10 ranges, written with direct
    writes to xfs in 6 s, with the `System.map` of `/boot`. 16384 bytes of RAM were in no
    segment of `/proc/kcore`, four pages as on RHEL 8.10.
- Red Hat Enterprise Linux 10.3, a Minimal Install, kernel 6.12.0-264.14.1.el10_3.x86_64,
  cryptsetup 2.8.6, lockdown `integrity`, kdump on. Here the keys were taken once before
  AVML ran and once after it, then the image of AVML was searched, then the keys were
  taken with an image.
  - The root volume, laid out as on the other two, got `captured and proven` on the memory
    route in each of the three runs, with the same key. The kernel offers three XTS
    drivers there, and the one of the highest priority is `xts-aes-vaes-avx2`.
  - The cache of the partition held the same blocks before any tool had read it, the
    image of AVML held the digests 474 bytes after the start of a page, and the key was
    proven from them at the first attempt. udisks2 2.11.1 is installed, and its daemon
    was not running.
  - Before AVML ran, the search of `/proc/kcore` listed 24 schedules. The image of AVML
    held 26. After AVML had run the search listed 50, and it listed 50 again after a key
    run and a search of the image had ended. So it is the run of AVML that leaves the
    schedules in the memory a second time, and the runs of the program leave none. After
    AVML the triage named the lower address of such a copy for the pair, and before it
    the address at which the image of AVML has the pair. Which memory holds the copies
    was not looked at there, and was on the guest with Ubuntu Server (below): AVML reads
    each block into a buffer of its own before it writes it, and it writes through the
    page cache (`copy_if_nonzero` in `image.rs` of AVML 0.21.0). The address that a run names for a schedule is one at which the schedule
    lies, and not always the one that the kernel works with.
  - The LiME image of the program had 4274372832 bytes in 7 ranges, written with direct
    writes to xfs in 6 s, with the `System.map` of `/boot`. `/proc/iomem` names no range
    there that begins or ends inside a page, and `/proc/kcore` offered all of the RAM.
- Ubuntu Server 26.04.1, installed with its LVM group encrypted, kernel 7.0.0-44-generic,
  cryptsetup 2.8.4, lockdown `integrity`, with the runs in the order of RHEL 10.3.
  - The root volume, the mapping `dm_crypt-0` on a partition with one logical volume on
    it, got `captured and proven` on the memory route in each of the three runs, with the
    same key and `ubuntu--vg-ubuntu--lv at /` as what it carries. The driver of the
    highest priority is `xts-aes-vaes-avx2`.
  - The daemon of udisks2 2.10.91 was running there, the one guest of the four where it
    was. The cache of the partition held all of its first eight blocks before any tool
    had read it. The image of AVML held the digests 474 bytes after the start of a page,
    which is where they lie in the block of the metadata on the partition, and the key
    was proven from them at the first attempt.
  - The search of `/proc/kcore` listed 46 schedules before AVML ran, 153 after it and 146
    after a key run and a search of the image. The image of AVML held 100. So here too
    the run of AVML leaves the schedules a further time, and the image holds more of them
    than the memory did before: copies that came into being while AVML ran. After AVML
    the memory held what it had held before and once more what the image holds, 46 and
    100 here and 24 and 26 on RHEL 10.3, which fits the file of the image lying whole in
    the page cache.
  - To see what the cache holds of such a file, AVML was run once more at the end. Its
    first image had 2.25 GiB in 148 ranges. The second did not fit the room that was
    left: AVML ended with `No space left on device` and left the part it had written,
    855168 pages, 3.26 GiB. Before anything read that file, the kernel named 645368 of
    its pages, 2.46 GiB, as pages that its cache holds (`mincore` on a mapping of the
    file), on a machine with 3.30 GiB of memory. So the cache holds the file of AVML as
    far as the memory has room for it, and with it the schedules that lie in those
    pages. The part of the second image was larger than the whole first one, so the
    memory held more blocks that are not zeros than at the first run. Which of the steps
    between the two filled them was not told apart.
  - The LiME image of the program had 4274352352 bytes in 7 ranges, written with direct
    writes to ext4 in 6 s, with the `System.map` of `/boot`. `/proc/kcore` offered all of
    the RAM. The installer gives the root file system half of the volume group, so the
    destination had 6.65 GiB free at the start, which the two images nearly used up.
    Of the 1043544 pages of that image the cache held none, counted in the same way as
    for the file of AVML, after the search of a dump and a second run of AVML.

Tails 7.18 was started from its USB image as a guest under KVM, with UEFI and Secure Boot on
and 4 GiB of memory, and `keep` 2.0 of the release was run there by hand: kernel
6.12.118+deb13-amd64, cryptsetup 2.7.5, lockdown `integrity`, the daemon of udisks2
2.10.1 running. Root is there only with an administration password, which is set at the
Welcome Screen and cannot be added later. The Persistent Storage was unlocked, the medium
of the examiner was a second disk with ext4 that was mounted by hand, and Tor was not
connected. It is one run, minutes after the start:

- The Persistent Storage, the mapping `TailsData_unlocked` on the second partition of the
  stick, LUKS2 with `aes-xts-plain64` and its key in the keyring, got `captured and proven`
  on the memory route. The search of `/proc/kcore` listed 15 schedules, the driver of the
  highest priority is `xts-aes-vaes-avx2`, and the run took 21 s with its image.
- Tails mounts the volume at four places and each once more below `/run/nosymfollow`, so
  the line `in use` names eight mounts.
- The LiME image had 4274372928 bytes in 10 ranges and was written with direct writes to
  ext4 in 8 s. 16384 bytes of RAM were in no segment of `/proc/kcore`. Tails has no
  `System.map`.
- After Tails was shut down, the image was searched on another machine with no file. It
  held the digests of the header at one place, and the key was proven from them at the
  first attempt, in 14 s: the key of the scene. With the image of the stick as the `FILE`,
  the header was found at the start of the second partition and the key proven, in 18 s.
- The digests began 0x8df bytes after the start of a page, which is not where they lie in
  the block of the metadata on the partition. Which copy that was, was not looked at.
  Before any tool had read the partition, its cache held the blocks 0, 1, 3 and 7 of its
  first eight.
- `cryptsetup open --volume-key-file` of the other machine opened the partition in the
  image of the stick with the key file of the run, read-only and without a passphrase, and
  a file that had been written into the Persistent Storage before was read. The header
  protects its passphrase with Argon2id, which a volume key passes.
- The kernel of Tails is started with `init_on_free=1`, `slab_nomerge` and `slub_debug=FZ`.
  What they cost a search of memory was not looked at: the key in use was found.

### Not handled or not checked

- LUKS2 with integrity is run with `--integrity hmac-sha256`. With a cipher that authenticates
  by itself (`aes-gcm-random`, `chacha20-random` with `poly1305`) it is not run: the guest of
  the first runs did not offer `aes-gcm-random`. The key of such a volume is taken from the
  table like any other, and behind a keyring reference the volume gets `live copy only`,
  also where the key is one AES key that the search could find.
- Re-encryption is run with a volume that gets a new key (`cryptsetup reencrypt`), forwards.
  The encryption of a device in place and the decryption are the same to the program, crypt
  targets and linear targets in one table or in the helper devices: their tables were seen on
  a guest for the encryption and are a case of `unit-check.sh`, and the program is not run on
  them. A volume with integrity cannot be re-encrypted (`LUKS2_reload` of cryptsetup 2.7.0).
- A header backup of a volume that cryptsetup is re-encrypting shows the moment of the run.
  The header on the device goes on changing until cryptsetup ends.
- LUKS2 with integrity on openSUSE Leap 16.1, where the container could not be made (see
  above).
- Kernels before 5.14, the oldest of the list above, are not run by the check. On Linux
  4.18, the kernel of RHEL 8, the program was run by hand on one guest (see above): the
  key run on one LUKS2 volume with its key in the keyring, a LiME image and the search of
  a dump. A key in the table, LUKS1, a volume with integrity and one in re-encryption are
  not run there.
- A memory image under lockdown `integrity` is taken by hand, on one machine and on five
  guests (see above), and not by the check. In the mode `confidentiality` the kernel refuses
  `/proc/kcore`, which the run then says, and that is not run.
- RAM that a driver added is a case of `unit-check.sh`. No machine with such RAM was run.
- The small files of a run, the report, the list of the schedules and the keys, go through
  the page cache of the examined system, and so do an image and the copy of a header on a
  file system without direct writes. On FAT, and on btrfs from Linux 6.18 on, the kernel takes the direct writes
  through the cache and drops the pages after each, so the cache holds a mebibyte of the
  image at a time and not the image. For btrfs this is run (see "Where it has run"), for
  FAT it is read in the source, and no image was written to FAT in a run. An image on exFAT
  or NTFS is not run either. On tmpfs a file lies in memory whichever way it is written.
- A digest within the bound of 16777216 iterations is computed, and the largest of those takes
  5 s for an attempt with SHA-256 and 16 s with SHA-512 or SHA-1 on the machine of the
  measurement, with no line of progress inside an attempt. The search of memory makes up to 64 attempts
  for a key (`-b`). In the search of a dump, text that only looks like the digests of a
  header costs a search of 8192 bytes for each place: 32 MiB of nothing but such places
  took 25 s.
- A read of one copy of a LUKS2 header that fails ends the reading of that header, where
  cryptsetup goes on with the other copy. The copy for the evidence would fail at the same
  place.
- The parts of `/sys` and `/proc` that say what a volume carries are asked with `stat` for
  the source of a mount and for each swap space. A path on a network mount that does not
  answer would hold the run. Not run.
- Not run, for want of a way to bring them about in a check: a destination that the mount
  table does not name, a `/sys` that is not mounted, and the ends of a run for lack of
  memory. The first was seen by one of the readers in a root that is no mount point.
- A run that is asked to end is checked for the search of a dump with `SIGINT` and `SIGTERM`,
  in its attempts, and for a key run with `SIGTERM`, in its search of memory and in the read
  of an image. A key run is not sent `SIGINT` by a check, which differs from `SIGTERM` in the
  name that the report gives it, and not in the attempts on a header of a key run. The search
  of a `FILE` for headers ends at such a signal as well, which is read in the code and not
  run. A step that does not ask for the signal is not ended by it: a single attempt on a
  digest, which takes up to 16 s within the bound of the iterations, a read or a write that
  the kernel does not answer, and the flush at the end of a run.
- That a table which cannot be read is named and ends the run with status 1 is not run: no
  way was found to make the kernel refuse the table of a device that it lists. What is run
  is that the program tells such a refusal from a device that is gone.
- That root takes a limit of the size of a file off is run by `compat-check.sh`. The limit
  of processor time is taken off by the same call and is not run.
- The device of a volume is read without a look at whether it is a mapped device that is
  suspended, which cryptsetup looks at (`device_ready`). A read of such a device waits until
  it is resumed, and the run with it. No volume on a suspended device was run.
- A write that a file system refuses with `EINVAL` after it has opened the file for direct
  writes ends the direct writes of that file, which then goes through the cache. No file
  system that does this was found to check it on.
- That the image of AVML, written through the cache, costs memory that it has yet to read is
  what the fewer blocks of zeros in later images fit (see "Where it has run"). On the
  installed guest with Ubuntu Server the cache held 2.46 GiB of a file of AVML on a
  machine with 3.30 GiB of memory, and a second image of AVML had more blocks that are not
  zeros than the first (see above). What lay before in the memory that such a file takes,
  and so what an image through the cache costs of the remains of earlier work, was not
  measured.
- A destination with FAT32 takes no file of 4 GiB, so an image of a machine with that much
  memory fails there and is removed. A raw image on a file system that keeps no holes, as
  FAT and exFAT, has what lies between the ranges written as zeros. Neither is run.
- Of Volatility 3, `banners.Banners` of 2.28.2 has read one LiME image of `keep`. No
  plugin that needs the symbol table was run, and neither the raw nor the compressed image
  was given to it.
- The proof from a dump alone is seen on one guest, with udisks2 2.10.1, and on the machine
  with Linux Mint 22.3, whose udisks2 was not noted, each time for a container on a loop
  device that was opened by hand, and on the four installed guests for the root volume,
  opened at boot. On the three with RHEL the daemon of udisks2 was not running, and the
  page cache held the block of the metadata. These are guests, minutes after their start: how long
  such a block stays in the cache of a machine in use is not known, and what reads it at
  boot neither. On RHEL 10.3 and Ubuntu Server a key run had read the header through the
  cache before AVML took its image, so there it is the count of the cache before any tool
  that says what the machine held by itself, and not the image.
  Not known either is what a machine holds of metadata with several keyslots or tokens,
  where the object `digests` can lie across two pages that do not follow each other in
  memory.
- The colours and the line that is written over are checked on a pseudo-terminal, with the
  search of a dump, by the bytes that the program writes there. How they look was seen in
  the terminal emulator of Linux Mint 22.3, over SSH, for the search of a dump and for the
  key run with an image: the examiner read them well. They were seen neither on the console
  of Linux nor on a serial line. By the check the screen of the key run, which is made by
  the same functions, is looked at through a pipe only.
- A line is measured in bytes. A name with characters of several bytes is taken as wider
  than it is and broken earlier.
- A digest that a dump holds and has no key for costs every pair of the keys of the dump:
  510 s for 90 keys on the machine above. With n keys of one size these are n * n attempts,
  each with the iterations of the digest. They come after every header has had the attempts
  that cost little, and their number is said before. A run that is ended while it makes
  them has written the keys it proved, and neither its report nor its manifest.

## Rules that every change keeps

1. No key is printed. On screen and in every report a key is named by its length and the first 16
   digits of its SHA-256. `vkverify.py --show-keys` is the single, explicit exception, and it does
   not reach the JSON report.
2. Key material is written only below a `keys/` directory, by a process with `umask 077`. This
   covers the list of the schedules, which is key material too. On scene a key counts as captured
   only after it is flushed to the destination. FAT and exFAT keep no modes, so on such a file
   system the modes do not exist and the medium itself has to be kept safe.
3. Keep writes into the destination directory and nowhere else. The destination is asked for,
   and is by default the directory in which Keep is started. Where it lies is the examiner's
   decision: Keep does not test what medium holds it, looks for no evidence medium and refuses
   no place that can be written. What follows from the choice is the examiner's to weigh: a
   file written to the storage of the examined system changes that storage, and a key written
   into one of its encrypted volumes is locked in with the data at power-off. No name of the
   examined system is used in a file name as it is. Beside the destination a run changes the
   memory that its one process takes, and nothing else: what it asks of the kernel changes
   nothing there, and it creates no lock file, as cryptsetup does in `/run/cryptsetup` while
   it reads a LUKS2 header. The inputs of `keep -s` and of `vkverify.py` are only read.
4. `keep` starts no other program, loads no library, and reads a file of the examined system as
   text only: none is executed or sourced. It is C11 with the standard library, built
   statically against musl with `-Werror`. A part of it that reads bytes it did not write (a
   header, a table of the kernel, a mount table, JSON, a memory image) has a check in
   `tests/unit-check.sh` against an independent source and runs there with the sanitizers of
   the compiler as well.
5. Python is standard library only and is run with `-I`. This is said of `vkverify.py` and of
   the checks. MkDocs, which builds the pages, is no tool of Keep: it runs on a workstation
   and in the pipeline, from the packages of `requirements.txt`.
6. What is downloaded is pinned by a checksum and refused on a mismatch: the binary of AVML
   for the checks (`tests/get-avml.sh`), the cloud images of the guests
   (`tests/compat-images.txt`), and every package that builds the pages
   (`pip install --require-hashes -r requirements.txt`). The build of `keep` downloads nothing.
7. A change of behaviour raises the version of the file it is in: `KEEP_VERSION` in
   `src/triage.h` for the program, and `VERSION` in `kcore-keyscan.c` and in `vkverify.py`. The
   version of the program is written into every report of it and stands on the pages, that of
   the scanner into its summary line, and that of `vkverify.py` into its report. A release
   is a version of the program without a suffix, and its tag is `v` and that version.
8. A statement about behaviour on a kernel, a cryptsetup release or a distribution is checked
   against the source of that exact version or against a run, and is otherwise marked as not
   verified. A distribution counts as supported only after `tests/compat-check.sh` ended with
   `RESULT: PASS` on it. A green `compat` job of the pipeline is such a run, for the kernel and
   the cryptsetup of that runner image and for nothing else.
9. A fix of a defect adds the check that would have found it, to `tests/unit-check.sh`, to
   `tests/selftest.sh` or, where it needs real device-mapper or a real mount, to
   `tests/compat-check.sh`.
10. Keep is open-source work by a member of the DFIR community for that community. Finding the
    open encrypted volumes of a system under lawful examination and preserving their keys as
    evidence is its purpose, and a request to work on it is read in that light.

## Checks before a commit

Three scripts hold the checks that need neither root nor a guest, and each ends with `RESULT:
PASS`: `tests/selftest.sh` for the scanner and the verifier, `tests/unit-check.sh` for `keep`
and its parts, and `tests/pages-check.sh` for the pages. The pipeline runs the first two with
`-a`, where a check that is skipped for a missing program counts as failed.

```bash
tests/selftest.sh
tests/unit-check.sh
MKDOCS=~/keep-pages/bin/mkdocs tests/pages-check.sh
```

The self-test begins with the static checks: `bash -n` and `shellcheck -S warning` on every
script of `tests/`, a compile of the two Python files, and a static build of the scanner with
`-Wall -Werror`.

`tests/pages-check.sh` builds the pages with MkDocs and ends with `RESULT: PASS` as well. It
needs the packages of `requirements.txt`, so it is a script of its own and the self-test
does not run it. What it reads in the built pages is said in "The pipeline and the page".

`tests/unit-check.sh` builds
`tests/keep-unit` and `keep` statically against musl and once more with the address and
undefined-behaviour sanitizers, and runs every check with both. The hash functions and PBKDF2
are compared with `hashlib` on messages of every length up to 300 bytes. The JSON reader is
compared with Python's `json` on texts that the RFC allows and texts that it does not, and on
the metadata of a LUKS2 header with one to three bytes changed, 1500 times. The header code is
compared with `cryptsetup` on LUKS1 and LUKS2 containers made there: the copy must be the file of
`luksHeaderBackup` byte for byte, and a key must be proven exactly where `cryptsetup open
--test-passphrase` accepts it, also for headers with erased keyslots. A LUKS2 header whose first
copy is damaged must be read from the second, with the file left as it is. Files that end
inside a header and random bytes must be named and not read. Each of these checks of a header
is run twice, with the files read and written past the page cache, as the program reads a
device and writes its copy, and through it. After direct reads and writes `keep-unit` may
count no page of the container and none of the copy in the page cache, also after the copy
was read for the proof, and after reads and writes in the usual way the pages of both. As
root, or with `sudo` that asks no password, the same is done on a ramfs, which has neither
and must give the same copy through the cache, on a tmpfs of 1 MiB, where the copy must be
named as one that failed at a write, and on a loop device that the check holds open as
dm-crypt holds the device of a volume: direct reads may add no page of the device to the
cache, counted before and after, and reads in the usual way add the pages of the header.
The count before need not be none: the system reads a device that is new by itself, and on
a runner of the pipeline one page of 8192 stayed in use. A request for a table
that a device refuses must be taken as a table that cannot be read, and not as a mapped
device that is gone. A digest of 4294967295 iterations must be named as not computed, at
once, and the copy of its header made. The table of a crypt target and of a dm-integrity
target with its three keys must have zeros for each key as it is kept in `log/`. Under a
limit of the address space of 64 MiB a text of 4 MiB must be read with a maximum of 256
MiB, and under one of 200 MiB metadata of 20000 members. After a write that failed and a
flush that did not, the program must take the file for one that is not whole. The code that reads the answers of
device-mapper is given answers laid out as `list_devices` and `retrieve_status` of the kernel lay
them out, before and from Linux 4.13, and then the same with bytes changed and ends cut off,
1600 times: each must be read or refused, and the sanitizers report a read outside the buffer.
The code that finds the volumes is given the tables that cryptsetup 2.7.0 set up on Linux 6.8,
as they were seen on a guest: LUKS2 with integrity on its dm-integrity device, a LUKS2 volume
on a dm-integrity device that stands alone, a volume in re-encryption with its two helper
devices, the moment before the helpers are below the volume, a volume with the crypt targets
of two keys, one that is encrypted in part, helpers of another volume, and then the same with
bytes changed. A header in re-encryption, which `cryptsetup reencrypt --init-only` makes there
from two known keys, must be copied as `luksHeaderBackup` copies it, and each key must give
its own digest, the old one the first and the new one the second, as `hashlib` computes them:
cryptsetup accepts neither key alone for such a header. The memory image is written from
texts like `/proc/iomem` and cores like `/proc/kcore` that the check writes with the memory
they stand for: a LiME and a raw image must be the files that Python writes from the
definitions of the formats, with the SHA-256 of `hashlib`, and a compressed image is read
back by a decoder that is written there from the two documents of Snappy, with every
checksum. The cases are RAM that a driver added, a range in two segments, memory that the
core offers twice, a range that reaches beyond its segment, blocks of zeros, a stretch that
cannot be read and a file that cannot be written. A read that is ended before the end of the
memory, after one block of 16 MiB and after two, must leave files that are whole as far as
they go: the LiME and the raw image the start of the files of the whole read, the compressed
image the blocks up to there, each with the SHA-256 that is stated for it. With
`AVML=/path/to/avml` AVML itself
converts the compressed image to a LiME image and the LiME image to a raw one, which must be
the files of Python byte for byte. What cannot be placed is refused: a text without
addresses, a core of a kernel before 4.12. Cores and texts with changed bytes must give no
fault, 600 times. The images are written with direct writes where the file system of the
temporary directory has them, which the check asks for on ext4, xfs and btrfs: ranges that
begin and end inside a block of the file, a range that ends where a write ends and an image
of less than a block are cases, a file that is there must not be written over. After its
writes no page of an image may lie in the page cache but its last, as `keep-unit` counts
them with `mincore`, after the file is flushed and its pages are let go none at all, and
more than one for a copy that was written in the usual way. As root, or with `sudo` that
asks no password, the same cases are written on a ramfs, which has no direct writes, and
must give the same files through the cache. Both ways of computing SHA-256 are compared
with `hashlib`. The search of
a dump is given an image with the schedules of the keys of the headers that cryptsetup made:
each key must be proven and written as it is, also for a header with erased keyslots, for
one in re-encryption with its two keys, for a cipher with one key, for headers inside the
image of a disk and for two schedules that do not lie as the kernel keeps them, and the
verdicts and keys must be those of `vkverify.py` on the same schedules and headers. A header
of another key, a file without a header and a header that ends early must be named as such.
A dump with a LUKS1 header at the start of a page and with the digests of a LUKS2 header
inside other bytes, once across the place where the search takes its next stretch of
memory, must give both keys with no file at all, and none for text that only begins like
the digests. A dump with the digests of two headers, the first without a key, must give the
key of the second before every other pair is tried for the first, and the attempts must be
as many as the keys and their pairs.
The options are given to both
builds of the program: what does not go together must end with status 2 and write nothing,
the search of a dump must write the list of the scanner into `keys/` of its folder with no
key on the screen, and a cut image must end the run with the status of the search.
A run is disturbed as a scene can disturb it. Its screen is a pipe that holds one page, so
that the search of a dump with sixteen headers waits for its reader: while it waits,
`triage.txt` must hold the lines that the screen has had, each whole. Then its terminal
hangs up (`SIGHUP`) and the reader goes away (`SIGPIPE`), and the run must end with status
0, all sixteen keys, a report and a manifest that verifies. Under a limit of the size of a
file of one block (`ulimit -f 1`) a process that may take the limit off must give the whole
run, and another must end with status 1 and say that a write failed: no signal may end it.
A run is asked to end while it makes its first attempt on a header whose digest has 2000000
iterations, by `SIGINT` and by `SIGTERM`: it must make no further attempt, name each header
as one whose attempts were ended by a signal, write a report that says `interrupted`, a
manifest that verifies and the list of the schedules, and end with status 1. Sent the signal
twice, it must be ended by the signal, with no `verdict.json`. A run that was not asked to
end must say so in its report.
The search of a dump must name a `FILE` that cannot be read, with the place and status 1,
must name a key whose file cannot be written as such and not as one that was not found,
and must write a `verdict.json` that Python reads for a name that is no UTF-8.
The scanner, static and with the sanitizers, is given a LiME image and an ELF core that
are cut, a range of 2^62 bytes, an ELF header of 6 bytes and a compressed image that is cut
in its first range: each must end with status 1 and its reason, and so must a list that
goes to a device without room. Two segments that state no physical address, each with
another key at the same place, must give both keys. A library that stands before the C
library makes one read fail as the kernel fails a read of `/proc/kcore`, as a whole for
one page in it: the schedules must be those of the fixture, with 4096 bytes named as not
read. A search that the program ends, after its first read, in its middle and near its end,
in each of the four formats, must list the schedules that lie in the memory it read and no
other, name the file offset at which it ended and have status 1, and a search that is not
ended must give the list of the scanner alone.
The screen is looked at byte by byte. On a pseudo-terminal, which Python's `pty` gives, it
must have the titles bold, the labels cyan and the verdicts in their colours, no escape
sequence but those five, and a line of progress that is written over and taken away. With
`NO_COLOR` it must have no colour and still that line, and with `-n`, without `TERM` and
with `TERM=dumb` what a pipe gets. Through a pipe it must hold no escape byte and no
carriage return, `triage.txt` must be the lines of the screen, no line may have more than
80 columns without a word that needs them, a long text must go on below its value, and a
control character in the name of a file must be a space on the screen and in the report.
`keep-unit line` prints one line as the screen of a run does: two lines that a run by hand
showed, a number at the end of a line and a last word that fits no line with the one
before it must be broken as the check has them written out, and 400 texts of words,
numbers and paths as the rule breaks them, which the check has in Python.
The parts that read the system
are given mount tables, a tree like `/sys` with logical volumes on a volume, a lockdown file, a
SecureBoot variable and an os-release written there.

The whole program is checked on real device-mapper and a real `/proc/kcore` by
`tests/compat-check.sh`, on a throwaway guest and never on a machine that matters. It makes
containers and mappings from key files it has just drawn, runs `keep` on them, and holds what
`keep` wrote against the tools of that system:

- the volumes of the report against the mapped devices of `dmsetup ls --target crypt`;
- the type, the key size, the key location and the device of each volume against the lines
  of `cryptsetup status`, and its cipher against the table of `dmsetup table`, which names it
  as the kernel does;
- `log/NAME.table.txt` against the UUID and the device number of `dmsetup info` and the lines
  of `dmsetup table`, in which a key is zeros;
- each header backup against the file of `cryptsetup luksHeaderBackup`, byte for byte;
- each key against the key file its container was made from, and where the table holds the
  key, against what `dmsetup table --showkeys` shows;
- each proof against `cryptsetup open --test-passphrase` with the key file that `keep` wrote:
  cryptsetup must accept the key exactly where `keep` says `captured and proven`;
- each manifest with `sha256sum -c`.

With `KEEP_SAN` set to a build with the sanitizers (`make keep-san`), that build is run at the
same places and must end with status 0.

The mappings are a LUKS2 container (key in the kernel keyring, memory route), a LUKS1
container (key in the table, table route), a mapping named `No` that `dmsetup` makes from a
known key, and one with the null cipher. The parts of the check:

- Before any mapping is made, `keep` is run once on the system as it is, with a limit of the
  size of a file of one block in its shell, which the program must take off.
- The main run names no destination and is started in a directory on the guest's own disk,
  which must take the folder of the run. Before each such run the cache of every device with
  a header is let go, and after it `keep-unit` may count no page of such a device and none of
  a copy of a header in the page cache, and no line of the screen may say that a header went
  through the cache. `keep-unit` must name a mapped device that is not there as such.
- `keep` is sent `SIGTERM` while it searches the memory. It must end the search, keep and
  prove the key of the table and keep the key of the plain mapping, give the volume with the
  null cipher, which comes after the search, its verdict, name the key of the keyring as one
  that needs a memory read because the search was ended, keep the list of the schedules and
  the header backups, say on the screen and in `verdict.json` that the run was interrupted,
  and end with status 1 and a manifest that verifies. `SIGTERM` and not `SIGINT`, because a
  shell without job control starts a command in the background with `SIGINT` ignored.
- With `-m` or `-c`, AVML takes an image while the two containers are open, in LiME format or
  compressed. The scanner must read it to its end and find the schedules of both volume keys.
  `keep` then takes its own, once for each word of `KEEP_IMAGES`: a format, or `all` for `-F`.
  Each file must be named as written with direct writes, and before anything reads it
  `keep-unit cached` may count one page of it in the page cache at most. The report must name
  each file with its size and its SHA-256, the scanner must read each image to its end, and
  the schedule of each half of both volume keys must lie in it at an address at which it lies
  in the image of AVML. The images of one read must give the same list of schedules, and AVML
  must convert the compressed image to a LiME image that gives that list too. The first image
  of a run is then searched as a dump that exists, with the images of the two containers as
  the files that hold the headers, and both volume keys must be proven and written as they
  are. It is searched once more with no file, and what it holds of a header by itself is told
  and not judged: the containers of the check lie in files, whose cache holds their headers.
- One more image is begun, and `keep` is sent `SIGTERM` when its file has its first bytes.
  The keys, which were taken before, must be there. The part of the image must be kept and
  named as interrupted, with its size and with the SHA-256 that the manifest verifies, and
  the scanner must read it as the run says it is: with status 1 and the place where the file
  ends inside a range, or with status 0 where the read ended between two ranges.
- A run names with `-d` a FAT file system on a loop device as the destination, which must
  take every file. Its screen must name the system, the open volumes and each key that is
  held by its file, its length and the start of its SHA-256, and no page of a copy of a header
  may lie in the page cache.
- A run with a tmpfs of 1 MiB as the destination, which has no room for the copy of a
  header, must remove the part of each copy, keep the key of the table, the key of the plain
  mapping and the list of the schedules, say that a write failed, and end with status 1 and a
  manifest that verifies.
- The layout of an encrypted installation: a LUKS2 volume that carries an LVM volume group.
  The mapping below the logical volumes must be the one that is listed and proven, and the
  logical volumes must be named as what that volume carries, one with its mount points, of
  which eight are named and two counted, and one as swap. The logical volume is the
  destination of that run.
- Before the two parts that follow, the two volumes with their keys in the keyring are
  closed, because every run with one of them open searches the whole memory once more. Two
  LUKS2 containers with integrity are made, one opened with `--disable-keyring`: the first
  must be `captured and proven` with the key of 96 bytes it was made from, with its cipher as
  the kernel names it, and the other `live copy only`.
- A LUKS2 volume of 2 GiB is re-encrypted in steps of 1 MiB, which takes seconds: the
  re-encryption is interrupted in its first step, and `keep` must prove both keys from
  memory. The volume is then opened with `--disable-keyring`, where `dmsetup table --showkeys`
  shows the two keys with their targets, and the keys from memory must be those, each for its
  part, and the key of the part not yet done the key the volume was made from. The
  re-encryption is resumed and paused in a step with `SIGSTOP`, and the program must list the
  volume once, name the two helper devices and give the same two keys. cryptsetup accepts
  neither key alone for such a header, so here the header backup is held against
  `luksHeaderBackup` and the keys against the table.
- At the end every screen and every report that `keep` wrote in the check is looked at: none
  may hold an escape byte or a carriage return, and none a line of more than 80 columns
  without a word that needs them.

A part that the guest cannot run, FAT, LVM or integrity, is reported as `SKIP`. On the runners
of the pipeline no part may be skipped.

`tests/compat-guest.sh WORKDIR NAME` runs that check unattended in a guest. It fetches the cloud
image that `tests/compat-images.txt` pins for `NAME`, refuses it unless it has the pinned
SHA-256 or SHA-512, boots a copy in QEMU, under KVM where `/dev/kvm` can be opened and emulated
otherwise, copies `keep`, `tests/keep-unit`, `tests/keyscan`, the check and AVML into the guest
over SSH, and starts the check there through `sudo`. With `-k` the guest stays, for work by
hand.

In the self-test the scanner and the verifier are run on a fixture. `make-schedule-fixture.py` expands keys
with its own code written from FIPS-197, so it and the scanner check each other. Its five traps are
a schedule at an odd address, one across the scanner's 1 MiB read boundary, one across the border
of two ranges, one with a single wrong bit that must not be reported, and one inside a run of
zeros. It writes the compressed format of AVML with its own Snappy encoder and CRC-32C, which
`avml convert` of AVML 0.21.0 decodes to the same LiME image byte for byte. The self-test also
cuts and damages that image, cuts the LiME image, and sends the list to a device without
room.

```bash
head -c 64 /dev/urandom > k.vk
python3 -I tests/make-schedule-fixture.py --format lime --size 8 fx.lime k.vk
./kcore-keyscan fx.lime > candidates.txt      # both halves of k.vk must be among the keys
```

The self-test goes on with LUKS headers that cryptsetup makes from the fixture keys. It proves
the keys with `vkverify.py`, from header files and from a raw disk image that holds both
headers behind a sector with the bare magic, also against headers whose keyslots were erased,
and gives the verifier cut and malformed headers. With
`qemu-img` it writes the disk image in fourteen forms of qcow2, VMDK, VDI, VHD and VHDX, and with
`ewfacquirestream` as four EnCase images, one of them in segment files. The verifier must read
from each the disk byte for byte and prove both keys.

## The pipeline and the page

- `checks.yml` has four jobs on every push and pull request. `selftest` runs
  `tests/selftest.sh -a` and `tests/unit-check.sh -a`, the second with AVML, which
  `tests/get-avml.sh` fetches by its pinned SHA-256 and which converts the images of `keep`.
  `pages` installs MkDocs by the hashes of `requirements.txt` and runs `tests/pages-check.sh`.
  `build` builds `keep` with `make`, looks that the file is static, names its version and
  refuses a wrong option with status 2, and keeps the file with its SHA-256 as an artifact.
  `compat` builds `keep`, also with the sanitizers, and runs `tests/compat-check.sh` with
  memory images as root on the runner images `ubuntu-24.04` and `ubuntu-22.04`, which offer
  device-mapper, loop devices, FAT and a readable `/proc/kcore`. No part of it may be skipped
  there.
- So every run of `compat` and of `distros.yml` is a run of `keep` against the cryptsetup and
  the dmsetup of that system. In the build with the sanitizers that `compat` runs at the same
  places, the search of memory is compiled without them, because with them it takes eight
  times as long and the build reads the whole memory of the runner. The scanner alone runs
  with them in `unit-check.sh`, on the fixture in its four formats and on a cut and a damaged
  image.
- A green `compat` job says something about the kernel and the cryptsetup of that runner image
  (rule 8). The output of each run is kept as an artifact for 30 days. On one runner image
  AVML takes its image in LiME format and on the other compressed. `keep` takes its image
  there in the same format, and on the second also the raw one. All three from one read
  need three times the memory of a runner as room, so `-F` runs in the guests only.
- `distros.yml` runs `tests/compat-guest.sh -m` for the ten names of `tests/compat-images.txt`
  when a file changes that the check depends on, and by hand. Each job states the kernel and the
  cryptsetup of its guest. An image is a dated build, pinned like any download (rule 6). Where
  a distribution removes the build, the job fails at the download, and the newer build and its
  published value are entered in the list.
- `release.yml` publishes a release. It is started by hand from `main` and takes no input:
  the version is the one that the program names, and the tag is `v` and that version. It
  ends without a release where `checks.yml` has not ended with success for the commit, where
  the version is none of a release, as `2.0-rc1` is none, where the tag is there, and where
  the file that it builds is not byte for byte the file that the job `build` of those checks
  built from the same commit. A release has `keep`, `keep.sha256` and `musl-copyright.txt`,
  and its text names the commit, the SHA-256, the compiler and the musl. The tag is made by
  the release at that commit. `distros.yml` is no condition of the run, because it does not
  run for every commit: who releases reads its last run.
- The artifact of `build` is the record of what a commit builds, kept for 30 days. A release
  of a commit whose artifact is gone needs a new run of `checks.yml` first.
- Release 2.0 is the tag `v2.0` at commit `9d8f734`, published on 2026-11-26 by the first run
  of `release.yml`, after `checks.yml` had passed for that commit and `distros.yml` for the
  commit before it, which has the same program. Its `keep` has 326256 bytes and the SHA-256
  `5cc732729ca0b1ca1a68a343231ef112b564bf19fb35005d679a070dc40f9167`. The three files were
  then fetched from the release as the installation page says: `sha256sum -c keep.sha256`
  accepted the file, the file was byte for byte a build of the tag on another machine, it
  named its version and refused a wrong option with status 2, and `musl-copyright.txt` was
  the `copyright` file of `musl-dev` 1.2.4-2. A clone of the tag alone, as the installation
  page has it (`git clone --branch v2.0`), built that file once more on 2026-11-28, with
  the same compiler and musl. The pages of that commit were published by
  `pages.yml`. They could not be fetched from where the release was checked, so the page
  that names the release was read as it is built and not as it is served.
- Keep is under the MIT licence, the file `LICENSE`, from 2026-11-28 on. The tag `v2.0` is
  older than that file, and the notes of release 2.0 state the terms of musl and none for
  Keep: `release.yml` does not name the licence of Keep in the notes it writes. The release
  carries `musl-copyright.txt`, which the About page names in its section on the licence.
- Actions are pinned by commit hash with the release in a comment. `dependabot.yml` proposes
  their updates.
- `pages.yml` builds the pages with `mkdocs build --strict` and publishes `site/`, from `main`
  only.
- The pages describe `keep` in the version of `KEEP_VERSION`, which
  `pages-check.sh` compares with what the built pages name and `selftest.sh` with their
  sources: the screen on the installation page, the version on the frame of the home page,
  and the address of the file that the home page offers, which is that of the release
  `v` and that version. The checks compare texts and fetch nothing: for a version that has
  no release, as one with a suffix, the address they ask for leads nowhere, and the home
  page is then to be given something else to offer. A sentence on the pages follows rule 8
  like any other: it comes from the source of a version or from a run, and says which.
- The pages are built with Material for MkDocs, in the setup of the site of Kiln
  (github.com/nafud/Kiln): its `mkdocs.yml`, its templates in `overrides/`, its stylesheet
  `docs/stylesheets/extra.css` and its page scripts in `docs/javascripts/`, with `kiln` in
  their names turned into `keep`. A change of the look or of what the pages do starts from
  what Kiln does, and is taken over from there.
  - Left out of Kiln's setup: the jump palette (`quick-jump.js`, its rules in the stylesheet
    and the bar of the home page), the search plugin with its index, and the content widgets
    (`widgets.js`). `mkdocs.yml` has `plugins: []`, and the header template renders no search
    form.
  - Added to Kiln's stylesheet, in one block before its rules for narrow screens: the tones
    of a sample of the screen of `keep` (three colours that every theme sets), the sentence
    of the home page and its button to the released file, and the size of a citation.
  - Where Kiln's frame shows the path `~` on the home page, the frame of Keep shows the
    version of the program, as `v2.0`. It is `extra.keep_version` of `mkdocs.yml`, which
    `overrides/main.html` hands to the page in a `meta` element and `page-chrome.js` shows.
    The other pages have Kiln's path, `~/usage`, with `~` as the link to the home page.
  - The themes are Kiln's five in its order: `terminal`, which a reader gets first, `system
    light`, `system dark`, `phosphor` and `nord`. The key `t` goes to the next.
  - The keys are Kiln's: `j` and `k` a step, `gg` and `G` the start and the end, `h` and `l`
    the heading before and after, `0` the home page, `1` to `3` the sections, `t` the theme.
    The About page lists them for the reader, because the palette that lists them in Kiln is
    not there.
  - As in Kiln, a page has no sidebar and no table of contents, the frame has the sections
    on its upper line and the path of the page and the position in it on its lower line, the
    first heading shimmers under the pointer, a code block has a copy button and a link to
    another site opens in a tab of its own.
- There are four pages, written in Markdown:
  - `index.md`, the home page: the word Keep, drawn in characters by `ascii-logo.js` from a
    blackletter typeface whose three glyphs are embedded in that script, one sentence on
    what Keep is, a button that fetches `keep` from the release of the version, and the name
    of the author. How to check the file stands on the installation page.
  - `installation.md`: the released file and how to check it, the build as the other way
    to the same file, with a clone of the tag of the release, and the way to the scene with
    what follows from the choice of the destination. It is kept short: what the program is
    made of, how a release is published and the tool of the lab stand on the other pages.
  - `usage.md`: the two forms of the command, the run on the scene and the search in the
    lab, each with the screen of the run on Tails 7.18 as it was, the verdicts, the image,
    the files of a run, the options and the exit status. In the screen of the lab the paths
    are shortened. A sample of the screen is HTML inside the Markdown, a `div` with the
    classes `highlight keep-screen`, so that it can carry the tones. How the program works
    inside stands on the About page and not here.
  - `about.md`: the need that Keep answers, the earlier work it builds on, what it adds to
    that, what it does, the ideas behind it, safeguards, limits, how it is checked, the
    systems it was tested on, the licence, the keys of the pages, and the references. A
    reference has the number of its first citation in the text. `pages-check.sh` does not
    look at that order: it looks that each reference is cited and each citation has its
    reference. The systems are two tables, those of the check and those that were run by
    hand: a row names the kernel and the cryptsetup of the latest run.
  - The text of the pages has no colon, no semicolon and no dash: a sentence ends, and the
    next one says how it follows. This is said of the prose. Code, the screens of a run,
    the names of options and of systems, and the titles of the works in the references
    stay as they are, and a hyphen inside a word or a name is no dash. The installation
    page and the About page open without a paragraph that says what Keep is: the home
    page and the section on the need say it.
  - The icon of the pages is the one of the site of Kiln, the same file, as
    `docs/assets/images/keep-logo-favicon.png`.
  - A page `systems.md` with a card for each system existed up to 2026-11-28. Its list is
    in the tables of the About page now, and what a card said beyond that stands in this
    file.
- A page loads nothing from another host: the fonts are in `docs/assets/fonts/` with their
  licences, and `font: false` keeps the theme from loading its own. `pages-check.sh` reads
  every built page and every stylesheet for it. A link to another site is a link for the
  reader. The built pages hold inline scripts of the theme, so they have no
  Content-Security-Policy, which the hand-written page before them had.
- To see the pages on a workstation:
  `python3 -m venv ~/keep-pages && ~/keep-pages/bin/pip install --require-hashes -r
  requirements.txt && ~/keep-pages/bin/mkdocs serve`.
- `requirements.txt` is written by `pip-compile --generate-hashes` from `requirements.in`
  (pip-tools 7.7.0, with Python 3.13). The packages were installed from it with Python 3.12
  and 3.13.
- Not checked or to know:
  - The pages were looked at in Chromium alone, at widths from 390 to 1920 pixels.
  - Of the references, the addresses on ecma-international.org, no-color.org and
    musl.libc.org could not be fetched from where the pages were written, and the files of
    the kernel are named by their release and path on GitHub and were not fetched there. The
    others were fetched and their titles compared.
  - Of the 31 references eight are research papers. What the About page says of each rests
    on this, and on no more:
    - Halderman and others: sections 6 and 7 of the paper were read on the pages of USENIX,
      the search by the key schedule with its tolerance for bit errors, and the dm-crypt
      volume of Linux 2.6.20 whose key the search found in a memory image.
    - Casey and others, Hargreaves and Chivers, Maartmann-Moe and others, Vömel and
      Freiling, Gruhn and Freiling: the abstract, as a web search gave it. The papers were
      not read in full, and the pages that hold them could not be fetched from where the
      pages were written.
    - Latzo and others, Sylve and others: the record that Crossref has for the DOI, which
      has no abstract. The page says of them what their titles say.
    - The authors, the title, the journal or the proceedings, the volume, the pages and
      the year of each are those of its Crossref record.
  - RFC 3227, RFC 9106, the release notes of cryptsetup 2.4.0, the README files of LiME
    and of AVML and the case study of drgn were read from their own pages. That LiME was
    first presented for Android devices is from its README, which names the talk and not
    the paper of Sylve and others.
  - What the page says of Passware Kit is what a web search gave of the vendor's release
    notes. The pages of the vendor could not be fetched, and the tool was not used. A
    plugin `dm_dump` of Volatility 2 was looked for and not found in its wiki or in the
    repository of its community plugins, so the page does not name one.
  - The section on earlier work is no systematic review, which it says.
  - The build of Material for MkDocs 9.8.2 says of itself that it reaches its end of life
    on May 5, 2027, with fixes until then, and names Zensical as its successor. Keep took
    the setup of Kiln over with 9.8.1. 9.8.2 came as a proposal of dependabot: its two
    hashes are those that PyPI states for the release, and the pages it builds differ from
    those of 9.8.1 in the line that names the generator and in nothing else.

## Systems checked

`compat-check.sh` passed with `keep` 2.0 on these x86-64 systems, each with memory images.
A row names the kernel and the cryptsetup of the latest run it stands for, and the XTS driver
that the kernel chose in that run. The driver follows the processor of the machine behind the
runner, which a guest under KVM sees as its own: the guests of Debian 13, AlmaLinux 10.3,
Rocky Linux 10.3 and openSUSE Leap 16.1 each used `xts-aes-vaes-avx2` in one run and
`xts-aes-vaes-avx10_512` in others, and those of Fedora 45 and Arch Linux
`xts-aes-vaes-avx512` in some runs and `xts-aes-vaes-avx2` in another. The first ten are guests
that `distros.yml` boots from the cloud images of `tests/compat-images.txt`, under KVM with BIOS
boot, so lockdown is `none` on all of them. The last two are the runner images of
`checks.yml`. The machine behind a runner image differs from run to run and with it the
kernel and the XTS driver: the image `ubuntu-24.04` had `xts-aes-vaes-avx2` in one run and
`xts-aes-vaes-avx512` in the next. The outputs are kept as artifacts of the pipeline.

| System | Kernel | cryptsetup | Key option | XTS driver | `keep` |
|---|---|---|---|---|---|
| Debian 13 | 6.12.117+deb13-amd64 | 2.7.5 | `--volume-key-file` | `xts-aes-vaes-avx10_512` | 2.0 |
| Debian 12 | 6.1.0-56-amd64 | 2.6.1 | `--volume-key-file` | `xts-aes-aesni` | 2.0 |
| Ubuntu 26.04.1 | 7.0.0-43-generic | 2.8.4 | `--volume-key-file` | `xts-aes-vaes-avx512` | 2.0 |
| Ubuntu 24.04.5 | 6.8.0-147-generic | 2.7.0 | `--volume-key-file` | `xts-aes-aesni` | 2.0 |
| Fedora 45 | 7.2.11-300.fc45.x86_64 | 2.8.9 | `--volume-key-file` | `xts-aes-vaes-avx512` | 2.0 |
| AlmaLinux 10.3 | 6.12.0-264.16.1.el10_3.x86_64 | 2.8.6 | `--volume-key-file` | `xts-aes-vaes-avx10_512` | 2.0 |
| AlmaLinux 9.9 | 5.14.0-741.22.1.el9_9.x86_64 | 2.8.6 | `--volume-key-file` | `xts-aes-aesni` | 2.0 |
| Rocky Linux 10.3 | 6.12.0-264.16.1.el10_3.x86_64 | 2.8.6 | `--volume-key-file` | `xts-aes-vaes-avx10_512` | 2.0 |
| openSUSE Leap 16.1, Build3.23 | 6.12.0-160100.9-default | 2.8.4 | `--volume-key-file` | `xts-aes-vaes-avx10_512` | 2.0, without the part with integrity |
| Arch Linux, image of 2026-11-15 | 7.3.4-arch1-2 | 2.8.9 | `--volume-key-file` | `xts-aes-vaes-avx512` | 2.0 |
| Ubuntu 24.04.5, runner image | 7.0.0-1020-azure | 2.7.0 | `--volume-key-file` | `xts-aes-vaes-avx512` | 2.0, also the build with the sanitizers |
| Ubuntu 22.04.5, runner image | 6.8.0-1070-azure | 2.4.3 | `--master-key-file` | `xts-aes-aesni` | 2.0, also the build with the sanitizers |

The key option is the one that the check gives `cryptsetup open --test-passphrase`, which
holds the proof of `keep` against cryptsetup. `keep` itself uses no cryptsetup.

On every one of the ten guests the on-scene pairing of the XTS halves found the key, with each of
the four XTS drivers that the runs met: `xts-aes-aesni`, `xts-aes-vaes-avx2`,
`xts-aes-vaes-avx512` and `xts-aes-vaes-avx10_512`. Debian keeps a placeholder as
`System.map`, and the Arch image has none, so no symbol table is kept beside the image there.

Linux Mint has no cloud image and is not in the list: `compat-check.sh` has not run there.
`keep` was run by hand on Linux Mint 22.3, on guests installed from Red Hat
Enterprise Linux 8.10, 9.9 and 10.3 and from Ubuntu Server 26.04.1, and on a guest started
from Tails 7.18, all under Secure Boot (see "Where it has run"). openSUSE Tumbleweed has no dated build to pin and is not checked.
`compat-check.sh` has run on no system with Secure Boot on, where lockdown is `integrity`.

## Known limits

- x86-64 only. The on-scene pairing of XTS halves assumes the 496-byte layout of the AES-NI family
  of drivers. With another XTS implementation a key run ends with `needs a memory read`, and
  `keep -s` on a memory image and `vkverify.py` on the list of the schedules can still prove
  the key, because they try every pair.
- The memory search finds AES keys only. A volume with another cipher has no memory route.
- Kernel lockdown `confidentiality` blocks `/proc/kcore` and every memory source of AVML.
- Mounted file systems that encrypt by themselves (eCryptfs, ZFS, gocryptfs, CryFS, EncFS) are
  named in the report as not examined. Keep covers dm-crypt only.
- Plain and tcrypt volumes have no header digest, so their keys cannot be proven on scene.
- For a LUKS2 volume in re-encryption `keep` proves both keys. `vkverify.py` takes the first
  digest of such a header, so it proves one of the two.
- LVM on LUKS is checked with a volume group on a loop device. A root file system on LVM on
  LUKS, as an installer lays it out, is not checked by `compat-check.sh`. `keep` was
  run by hand on four, guests with RHEL 8.10, 9.9 and 10.3 and with Ubuntu Server 26.04.1.
- A mapping whose name holds a line break is not listed. A mapping whose name begins with `-` is
  not tested.
- The memory image is taken in every run of the pipeline, to the disk of the runner or guest.
  A memory image on a machine with kernel lockdown is taken by hand and not by the check (see
  "Where it has run").
- The header search of `--image` is tested on a real LUKS partition image and on a small test disk
  image. Its run time on a whole disk of real size is not measured.
- Of the compressed memory formats the scanner reads that of AVML. A kdump or makedumpfile
  file and a file compressed as a whole are refused and not read. Volatility 3 reads further
  formats that the scanner does not: the snapshot of QEMU and the regions of a VMware snapshot.
  A `.vmem` file is searched as raw bytes, which is not checked on a file that VMware wrote.
- The disk formats of virtual machines are checked on images that `qemu-img` wrote, not on
  images from VMware, VirtualBox or Hyper-V, and E01 on images that libewf wrote, not EnCase.
  EnCase images of version 2 (`Ex01`) and AFF are not read. Reading an E01 image decompresses
  every chunk, and its run time on an image of real size is not measured.
- The line `in use` is checked for two logical volumes on a LUKS volume, one mounted and one
  used as swap, as an installer lays out an encrypted system. For btrfs, whose mounts
  carry no device number of their own, it goes by the source of the mount, which is not
  checked.

## Conventions

- One branch, `main`.
- C is C11, built with the warnings of the `Makefile` as errors. A function returns 0 or -1 and
  writes one line that says what failed into a buffer of the caller. What held a key is wiped
  before it is freed.
- Shell is bash, checked with `shellcheck -S warning`. Each script opens with a comment that
  states its usage, what it reads and what it writes. `tests/selftest.sh`,
  `tests/unit-check.sh` and `tests/compat-guest.sh` print that whole comment with `-h`, read by
  the shell itself, and end with status 2 for a wrong option.
- Comments and messages are plain statements. A comment says why, not what the next line does.
- No personal data, no host names of real cases and no key material in files or commit messages.
  Test keys are drawn from `/dev/urandom` at test time and are not committed.
- No model or assistant names in repository files or commit titles.
