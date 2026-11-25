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

The scene side is being written anew as one static C program that starts no other program. Until
it gives what the scripts give on every system of the list, the scripts on the tool medium are
Keep. The section "The C program" says how far that work is.

This file is the repository's description and the working rules for it. The repository has no
README.

## Layout

| File | Runs | Purpose |
|---|---|---|
| `keytriage.sh` | scene, as root | The triage itself. Enumerates the open dm-crypt volumes, backs up LUKS headers, walks the route ladder, prints one verdict per volume, writes the folder of the run into the destination |
| `kcore-keyscan.c` | scene and lab | Static C scanner. Finds AES-128 and AES-256 key schedules in `/proc/kcore` or in a memory image |
| `src/`, `Makefile` | scene, in work | The C program `keep`, which is to take the place of the medium. `make` builds it statically against musl |
| `vkverify.py` | lab | Verifier. Proves which scanner candidates are the volume key of a LUKS1 or LUKS2 header |
| `offline-keyscan.sh` | lab | Driver for a dump collected earlier. Runs the scanner on the dump and `vkverify.py` against disk images |
| `build-toolkit.sh` | workstation | Assembles the scene tool medium and writes it as an ISO |
| `tests/make-schedule-fixture.py` | test | Writes a memory image with the schedules of known keys and five traps, as raw, ELF, LiME or compressed AVML |
| `tests/compat-check.sh` | test, throwaway guest only | Checks `keytriage.sh` on real device-mapper: containers and mappings of known keys, the null cipher, LVM on LUKS, LUKS2 with integrity, the memory image, and the destination by default and on FAT. Runs the C program beside it, and alone on a volume in re-encryption |
| `tests/compat-guest.sh` | test, workstation and pipeline | Boots a distribution's cloud image as a throwaway guest in QEMU, runs `compat-check.sh` in it and prints its output |
| `tests/compat-images.txt` | test | The cloud images for `compat-guest.sh`: a name, the address of one dated build and its published SHA-256 or SHA-512 |
| `tests/make-compat-vm.sh` | test, workstation | Starts a libvirt guest that stays, from a distribution's cloud image, for work by hand |
| `tests/selftest.sh` | test, workstation and pipeline | Runs every check that needs neither root nor device-mapper, `keytriage.sh` included on stand-ins for the examined system, and ends with `RESULT: PASS` or `RESULT: FAIL` |
| `tests/unit-check.sh` | test, workstation and pipeline | Builds the parts of the C program twice, statically and with the sanitizers of the compiler, and checks each against an independent source: `hashlib`, Python's `json`, `cryptsetup` |
| `tests/keep-unit.c` | test | Runs one part of the C program at a time, for `unit-check.sh` and for a comparison with `dmsetup` on a guest, and counts the pages of a file that lie in the page cache |
| `docs/` | GitHub Pages | The page of Keep: `index.html`, `assets/keep.css`, `assets/keep.js` and the fonts |
| `.github/workflows/` | GitHub | `checks.yml` runs the self-test, builds the medium and runs `compat-check.sh` on two runner images on every push. `distros.yml` runs it in guests of ten distribution releases. `pages.yml` publishes `docs/` from `main` |

The five files at the root must stay siblings. `build-toolkit.sh` takes `keytriage.sh` and
`kcore-keyscan.c` from its own directory. `offline-keyscan.sh` looks for `vkverify.py` beside
itself. `kcore-keyscan.c` includes `src/keyscan.h`, and the `Makefile` at the root builds the C
program `keep` from `src/` and from `kcore-keyscan.c`.

## How it works

### The route ladder of `keytriage.sh`

For each mapping of `dmsetup ls --target crypt` the script reads `cryptsetup status` and the
kernel's own table line (`dmsetup table --showkeys`), then takes the first route that is open.
A mapping is a line of the listing with a name, a tab and the device number in parentheses
(`_display_name` in `dmsetup.c`), so every name the kernel allows is taken, also `No` and a name
with a space. The key size is the line `keysize:` of `cryptsetup status`. A LUKS2 volume with
integrity has a second line, `integrity keysize:`, which a version before 1.5.1 took as well
and then stated no key size.

| Route | When | What happens |
|---|---|---|
| R1 table | The fifth field of the table line is the key in hexadecimal. This is the case for LUKS1, plain, tcrypt and for LUKS2 opened with `--disable-keyring` | The key is written to `keys/NAME.vk` and, for LUKS, proven against the header backup |
| R3 memory | The fifth field is a keyring reference, `:size:type:description`. This is the default for LUKS2, including systemd-homed | `kcore-keyscan` searches `/proc/kcore` once for all volumes. Candidates are proven against the header backup. The list is kept in `keys/` also when there is no header backup |
| R5 live | No key route is open | Only a file-level copy of the mounted plaintext remains |

Beside its type and its backing device the script names what each volume carries, as the line
`in use:` and the field `in_use`: where the volume and the devices that stand on it, such as the
logical volumes of LVM, are mounted or used as swap. It follows `holders/` in `/sys` upwards from
the mapping and reads `/proc/self/mountinfo` and `/proc/swaps`. Eight mounts are named and
further ones counted. This is what a copy of the mounted files has to cover, and it tells a
volume that holds the root file system from one that holds nothing in use.

A fifth field of `-` is a key of size 0 (`crypt_status` in `dm-crypt.c`), which is the null
cipher. Such a mapping has no key and gets the verdict `no key needed`. A field that is neither
hexadecimal nor a keyring reference is reported as not understood. The table line is read by the
shell through a pipe, so the key passes no other program and no file.

R2 and R4 are not steps of the script. A memory image is the fourth route and is searched in the
lab with the same scanner (`offline-keyscan.sh`, or `kcore-keyscan` and `vkverify.py` by hand).

The cipher is taken from the fourth field of the table line and sorted into three classes.
`aes-xts-*` and `capi:xts(aes)-*` are XTS, where the volume key is two AES keys. Any other
`aes-*` is a single AES key. Everything else has no AES schedule of the volume key, so the memory
route does not apply.

### Verdicts

`keytriage.sh` prints exactly one of these per volume, and they are the values of `verdict` in
`verdict.json`.

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

`vkverify.py` writes `proven`, `not proven` and `unreadable header`, and with `--truth` also
`found in memory` and `not found` for volumes without a header.

### The proof

A candidate key counts only when it is proven. Nothing is reported as a volume key on the strength
of where it was found.

- On scene the proof is `cryptsetup open --test-passphrase OPTION KEYFILE HEADERBACKUP` with the
  examined system's own cryptsetup. `OPTION` is `--volume-key-file` where `cryptsetup --help`
  lists it (release 2.5.0 and later) and `--master-key-file` otherwise.
- In the lab `vkverify.py` computes the proof itself, with no cryptsetup and no loop device. A LUKS
  header stores a PBKDF2 digest of the volume key. LUKS1 keeps it in the binary header (hash name
  at offset 72, key bytes at 108, digest at 112, salt at 132, iteration count at 164, UUID at 168).
  LUKS2 keeps it in the `digests` object of the JSON area that starts at offset 4096, with the
  header size at offset 8. A key whose PBKDF2 output equals the stored digest is the volume key.
- A header whose keyslots were erased (`cryptsetup erase`) keeps its digest, so a key from memory
  is still proven against it and is then the only way into the volume. LUKS2 states the key size
  in the keyslots, so for such a header `vkverify.py` tries keys of every size. Checked on
  headers erased by cryptsetup 2.7.0.

### Key schedules and the XTS pair

AES expands a key into round keys (FIPS-197, section 5.2). The kernel holds the expanded schedule,
and its first 16 or 32 bytes are the key. `kcore-keyscan` tests every position against the
expansion rule over the whole schedule, 176 bytes for AES-128 and 240 bytes for AES-256. The test
is exact, so a hit is a real schedule, though not necessarily one of a disk volume.

With `aes-xts` the volume key is the data key followed by the tweak key. On x86-64 with the AES-NI
family of drivers the kernel keeps both schedules in one `struct aesni_xts_ctx`
(`arch/x86/crypto/aesni-intel_glue.c`), the tweak schedule first and the data schedule 496 bytes
after it. 496 is `sizeof(struct crypto_aes_ctx)`, 484 bytes, aligned to 16.

- `keytriage.sh` tries only pairs at that distance: for a tweak schedule at physical address P it
  takes the data schedule at P + 496 and builds the key as data then tweak. The number of proof
  attempts per volume is limited by `-b` (default 64).
- `vkverify.py` tries pairs at that distance first and then every other ordered pair. The distance
  only orders the attempts. The digest decides. n keys of one size give n * n pairs, so the
  number of tests is printed, and a header that takes long reports on standard error how far it
  is.

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
| LiME | `EMiL` at the start of each 32-byte range header | Each range, with its start and end address from offsets 8 and 16 of the header. This is what AVML writes |
| AVML compressed | `AVML` and version 2 at the start of each range header | Each range: the header, a framed Snappy stream and the length of that stream (`src/image.rs` and `src/io/snappy.rs` of AVML 0.21.0). Every chunk of at most 64 KiB is decompressed and compared with its CRC-32C. Ranges of both kinds may follow each other. This is what `avml --compress` and `keytriage.sh -m -c` write |
| raw | anything else, or any file with `-r` | The whole file, with the file offset as the address. A `.vmem` file of VMware is such a file |
| refused | the first bytes of an AVML image of another version, of a kdump, diskdump or flattened makedumpfile file, or of a gzip, xz, zstd, bzip2 or lz4 file | Nothing. Such a file holds memory in another form. Searched as raw bytes, a gzip file gave 2 of 5 schedules with status 0. The `kdump-zlib` dump of QEMU 8.2.2 begins as a flattened makedumpfile file and is refused |

- One line per schedule goes to standard output: `AES-256 phys 0x... virt 0x... key <hex>`. The
  counts and the time go to standard error. The output therefore holds key material and is only
  ever redirected into a `keys/` directory.
- Data is read in 1 MiB chunks with the last 239 bytes carried over, and a range that begins where
  the previous one ended continues the same run, so a schedule across a chunk or range border is
  found.
- An unreadable stretch counts as zeros and is reported. At most 4096 schedules are listed, and
  further ones are counted.
- A LiME or compressed image that is cut, as on a medium that ran full, or damaged is searched
  up to that place. The schedules before it are listed, the file offset and the number of bytes
  not searched are named, and the status is 1. A chunk that differs from its checksum is counted
  and its data searched as it is.
- A self-test against the two expansions of FIPS-197 appendix A runs at every start. Exit status
  0 is a completed scan, 1 an unreadable or refused input or an image that could not be read to
  its end, 2 a usage error, 3 a failed self-test. The summary line names the version of the
  scanner.
- `/proc/kcore` needs root and is refused under kernel lockdown `confidentiality`.

### Headers from a disk image

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

### The report, `keep-report/1`

`keytriage.sh` writes `verdict.json` and `vkverify.py --json` writes the same schema. A report
never holds a key. A key is named by `key_sha256_16`, the first 16 hexadecimal digits of its
SHA-256.

- Top level from `keytriage.sh`: `schema`, `tool`, `host`, `kernel`, `os`, `cryptsetup`,
  `other_filesystems`, `started_utc`, `finished_utc`, `lockdown`, `secure_boot`, `source`,
  `evidence_medium`, `memory`, `binaries`, `volumes`.
- Each volume: `name`, `type`, `cipher`, `key_bits`, `key_location`, `device`, `in_use`,
  `header_backup`, `route`, `verdict`, `key_sha256_16`, `note`. `vkverify.py` names the file of the header in
  `device` and adds `uuid`, `digest`, `attempts`, `adjacent_places` and, with `--truth`,
  `ground_truth`.
- The C program adds `further_keys` to a volume that has more than one key, which is a volume
  in re-encryption: a list with `key_file`, `cipher`, `key_bits`, `key_location`, `route`,
  `verdict`, `key_sha256_16` and `note` for each key after the first. The fields of the volume
  itself are then those of its first key, and its `verdict` is that of the key that is least
  far.
- `keep -s` writes the fields of `vkverify.py` for each header, with `offset` for where it lies
  in its file, and `further_keys` for the second key of a header in re-encryption. Beside
  `volumes` it has `memory_pairs`, a list with `key_file`, `key_bits`, `verdict` (`found in
  memory`), `key_sha256_16` and `tweak_schedule_at` for each pair that no header proves, and
  `further_memory_pairs`, the number of those that are not written as files. A header that
  was found in the dump itself has `in_memory` true and its address as `offset`.
- With `-F` the C program writes three images from one read. `memory` is then the first, with
  the fields above, and has `further_images`, a list with `status`, `file`, `format`,
  `bytes`, `sha256`, `direct_io` and `note` for each of the others.
- The C program adds `direct_io` to `memory`: true for an image that was written with direct
  writes, false for one that went through the page cache, `null` where there is no file.
- No tool of Keep reads the report back. It is for the examiner's own programs and for the
  checks, and `triage.txt` beside it says the same for a reader. A change of a field name is a
  change of the schema string.

## Interaction

Keep has no full-screen interface, opens no window and asks no question. Every tool takes its
parameters as options and writes lines of text, so it works on a console, over SSH, on a serial
line and through a pipe. A dialogue (`keep-menu.sh`, with its launcher `keep.c`), a viewer in
a browser and a printer of the reports (`keep-report.py`) existed and were removed: options
say the same in one line, and `triage.txt` is the report for a reader.

- No escape sequence, no cursor movement, no colour, no terminfo and no line editor.
- A path is made absolute before it is used. A dump or an image must be a readable regular
  file, and a destination directory must exist and be writable.
- A wrong option ends with status 2 and the usage line.

## The scene medium

`build-toolkit.sh OUTDIR` writes `OUTDIR/tools/` and `OUTDIR/tools.iso` (Rock Ridge and Joliet,
volume label `KEEPTOOLS`).

```bash
sudo apt install bash-static busybox-static xorriso gcc make musl-tools curl file
./build-toolkit.sh /path/to/work
```

- `bin/bash` is `bash-static`, `bin/busybox` is `busybox-static` with one symlink per applet,
  `bin/kcore-keyscan` is built statically from this repository, and `bin/avml` is the release
  binary of Microsoft AVML v0.21.0, accepted only when its SHA-256 equals the value pinned in the
  script.
- `keytriage.sh` is copied beside `bin/` and is started in the shell of the medium,
  `bin/bash -p keytriage.sh`, so the shell of the examined system takes no part in the start.
  The medium carries no Python, so `vkverify.py` and `offline-keyscan.sh` are lab tools.
- The build refuses a binary that is not statically linked, and writes `VERSIONS.txt` and
  `MANIFEST.sha256`.
- `c/keep` is the C program, built by `make` against musl, and `c/keep-unit` the program of
  its unit checks. Both are on the medium only for the checks: the first is run beside the
  scripts, the second counts the pages of an image that lie in the page cache.
- `dmsetup` and `cryptsetup` are not on the medium. The examined system's own are used, and their
  resolved paths and SHA-256 are recorded in the report so they can be checked against the
  distribution's packages afterwards.
- The bash of the medium is the `bash-static` of the build workstation. `VERSIONS.txt` on the
  medium names its version, and the `compat` job of the pipeline prints it for each runner image.

## Use

On scene, with the medium at `/media/tools`, started in the directory that is to take the
output:

```bash
sudo /media/tools/bin/bash -p /media/tools/keytriage.sh              # keys, into the current directory
sudo /media/tools/bin/bash -p /media/tools/keytriage.sh -d DIR -m    # keys into DIR, then a memory image
sudo /media/tools/bin/bash -p /media/tools/keytriage.sh -d DIR -m -c # the image compressed
```

- `keytriage.sh` starts only under `bash -p`, and on the medium only in its own `bin/bash`.
  Without `-p` bash runs the file that `BASH_ENV` names, takes functions from the
  environment and obeys `SHELLOPTS`, all before the first line of a script. `sudo` removes these
  variables (`initial_badenv_table` in its `env.c`), a root shell does not.
- The destination is the directory of `-d`, or the current directory. Where it lies is the
  examiner's decision: `keytriage.sh` does not test what medium holds it and refuses no place.
  It must exist and be writable. The report names the file system that holds it, with its
  source, its type and its mount point, as `destination:` on the screen and as
  `evidence_medium` in `verdict.json`, a field name that is kept with the schema.
- `-p DIRS` names the directories of the examined system's `dmsetup` and `cryptsetup`, by default
  `/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin`. `-b N` limits the proof attempts
  per volume on the memory route.
- Exit status of `keytriage.sh`: 0 when the run completed and was flushed, 1 when it could not
  start or a write or a flush to the destination failed, 2 for a wrong option.

The output folder is `triage_<host>_<UTC time>/` with `triage.txt`, `verdict.json`, `headers/`,
`keys/`, `log/` (what `cryptsetup status`, the scanner and AVML wrote), `memory/` with `-m`, and
`manifest.sha256`. In the names of the folder and of the files every character of the host name
or of a mapping name that is not a letter, a digit or one of `. _ + = @ , -` becomes `_`, so
that a name cannot leave the destination and FAT and exFAT take it. Two mapping names
that differ only by case are kept apart by a further `_`.

Every file is created with `umask 077`. A header backup, the candidate list and a key are
flushed with `fsync` as soon as they are written (`sync FILE` of busybox, which reports a
failure), and the run ends with `syncfs` on the file system of the destination (`sync -f`).

With `-m` the keys are taken first, because an event can close their window within seconds, and
then AVML writes `memory/memory.lime`. Beside the image go the kernel banner, the release,
`os-release` and `System.map`, which Volatility 3 needs for its symbol table. A `System.map` is
kept only when it lists `_stext` or `linux_banner`, because some distributions keep a placeholder
without symbols in `/boot`. The image is skipped when the destination has less free space than
the machine has RAM plus 64 MiB.

With `-m -c` AVML writes its compressed format to `memory/memory.avml`, for a destination with
less free space than the machine has memory. The scanner reads it, and Volatility 3 reads it where
the Snappy library is installed. Its size is known only at the end, so it is started whatever
space is free. How much it saves depends on what the memory holds: in the five runs of the
pipeline that took it, on runners with 16 GiB, the image had 85 % to 87 % of the size of the
memory (twice 13.7 GB for 15.7 GB, and three times 11.3 GB for 13.3 GB). Where AVML cannot finish it, the part that was written is removed, so that the
report still has room, and the image counts as failed.

In the lab:

```bash
./offline-keyscan.sh [-k KIT] DUMP IMAGE...                # dump collected earlier, headers from disk images
python3 -I vkverify.py CANDIDATES [HEADER...] [--image DISK]... [--out DIR] [--json FILE]
```

`offline-keyscan.sh` writes `scan_<dump>_<UTC time>/` in the current directory with `triage.txt`,
`scan.txt`, `verdict.json`, `manifest.sha256` and `keys/`. Its exit status and that of
`vkverify.py` are 0 only when at least one header was located and every located header is proven.
`DUMP` is a raw dump, a LiME image, a compressed AVML image or an ELF core. The formats that the
scanner refuses end the run. Any other container format is searched as raw bytes, which is not
tested. `IMAGE` is a raw disk or partition image, a header backup, the disk file of a virtual
machine or an EnCase image.

## The C program

The scene side of Keep is being written anew as one static C program, `keep`, built from `src/`.
It is to take the place of the tool medium: of `keytriage.sh`, the bash and busybox of the
medium, the examined system's `dmsetup` and `cryptsetup`, and AVML. An examiner then copies one
file to the system and starts it. The program starts no other program and asks no question:
what a run does is said by its options.

Until it gives what `keytriage.sh` gives on every system of the list below, `keytriage.sh` on the
medium is Keep, and everything in this file outside this section describes it. The lab tools
stay in Python.

```bash
sudo apt install make musl-tools
make                                    # keep and tests/keep-unit, static against musl
sudo ./keep [-d DIR] [-b N]             # the keys of the running system: the work of keytriage.sh
sudo ./keep -m [-f FORMAT | -F]         # the keys, then a memory image: lime (default), raw or avml, -F all three
./keep -s DUMP [-d DIR] [FILE...]       # the keys of a memory dump that exists, proven against the headers in the FILEs
./keep -h                               # the help, -V the version
```

- Without `-s` the program prints the characteristics of the system (host, system, kernel,
  lockdown, Secure Boot, memory, destination) and one verdict per open volume, and under the
  verdicts each key it holds by its file in `keys/`, its length and the first 16 digits of
  its SHA-256.
- `-m` takes a memory image after the keys, into `memory/` of the folder of the run, as
  `memory.lime`. `-f` names another format: `raw`, where each byte lies at the file offset
  that is its physical address, or `avml`, the compressed format of AVML. `-F` writes all
  three from one read of the memory. An image that was asked for and is not there ends the
  run with status 1. An image is written with direct writes, which pass the page cache of
  the machine, where the file system of the destination has them, and the run says which
  way each file was written.
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
- With `-s` the status is that of the search of the dump, and with `FILE`s also 1 where they
  hold no header or a header has a key that is not proven.
- `-d DIR` is the destination of either run, by default the directory of the start. `-b N`
  is for the running system only, and so are `-m`, `-f` and `-F`.
- A wrong option, an option without its value, an argument that belongs to no option and
  options that do not go together end with status 2 and the usage. The commands `triage` and
  `scan` and the dialogue of the versions before 2.0-pre4 are gone.

### What stands in whose place

| In the medium | In the C program | Checked against |
|---|---|---|
| `dmsetup ls --target crypt`, `dmsetup table --showkeys` | `src/dm.c`: the ioctls `DM_LIST_DEVICES` and `DM_TABLE_STATUS` of `/dev/mapper/control` | `dmsetup` 1.02.185 on kernel 6.8: the same devices, tables, UUIDs and keys |
| `cryptsetup status` | `src/triage.c` and `src/volume.c`: the type from the UUID of the mapping and the header, the cipher, the key size and the key location from the table line, the device from `/sys/dev/block`. Which devices are one volume, and where its header lies, is read off the tables as `_init_by_name_crypt` of cryptsetup does it | `keytriage.sh` on the same mappings: the same line of `verdict.json` for every volume. For a volume in re-encryption, where `keytriage.sh` gives less, the keys that `dmsetup table --showkeys` shows |
| `cryptsetup luksHeaderBackup` | `src/luks.c`: the header and the keyslot area read from the backing device | `cryptsetup` 2.4.3 and 2.7.0: the same file byte for byte, for LUKS1 and LUKS2 |
| `cryptsetup open --test-passphrase` | `src/luks.c` and `src/hash.c`: PBKDF2 of the key against the digest of the header backup | `cryptsetup` 2.7.0 on the same headers and keys, and Python's `hashlib` |
| `kcore-keyscan` | `kcore-keyscan.c` linked in without its `main` | the scanner before the change: the same output, messages and status on every format |
| `offline-keyscan.sh` and `vkverify.py`, for a header backup and a raw image | `src/dump.c`: the search of a dump, the headers of the files, and the proof of the candidate keys against each | `vkverify.py` on the same schedules and headers: the same verdicts and the same keys. On a guest, the keys of two open containers from the image that the program took of that machine |
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
  - LiME writes with `O_DIRECT` where its option `dio` is given and a first write of that
    kind succeeds, and otherwise without (`setup_disk` in `disk.c`).
  - `dd` of GNU coreutils writes the last block of a file, which is no whole one, after it
    has taken `O_DIRECT` off the descriptor (`iwrite` in `dd.c`). The program does the same.
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
  - From such an image alone, with no file, the C program proved the volume keys of both
    containers, and left a digest of a volume that an earlier check had closed as not
    proven.
- cryptsetup gives the key of digest N the keyring description `cryptsetup:<UUID>-d<N>`
  (`get_key_description_by_digest`, the same in 2.0.6, 2.7.0 and 2.8.1), so the reference in a
  table says which digest of the header its key gives.

### Its parts

| File | What it does |
|---|---|
| `src/main.c` | The options. Makes the process not dumpable |
| `src/dump.c` | The search of a memory dump that exists: its schedules, the LUKS headers of the files that are given, the proof of the keys against them, and the pairs that no header proves |
| `src/run.c` | The folder of a run: its report, its files, their flushing and the manifest |
| `src/memory.c` | The memory image of a run: the room it needs, its files, and what the lab needs beside it to name the kernel |
| `src/image.c` | What an image holds, from `/proc/iomem` and `/proc/kcore`, and the three formats. The memory is read once for all files, and written with direct writes |
| `src/snappy.c` | The framed Snappy format, written, with CRC-32C |
| `src/triage.c` | The run: destination, system, volumes, the ladder for each key, verdicts, `triage.txt`, `verdict.json`, `manifest.sha256`. Locks the memory of the process |
| `src/dm.c` | The list of the mapped devices and the table of one, from the kernel |
| `src/volume.c` | Which mapped devices are a volume, which further devices are part of it, which keys it has and where its header lies, read off the tables |
| `src/luks.c` | The header of LUKS1 and LUKS2: reading, the copy for the evidence, the proof of a key |
| `src/hash.c` | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, HMAC and PBKDF2, with a self-test against the examples of the standards at every start. SHA-256 with the SHA instructions of the processor where it has them |
| `src/json.c` | A reader of JSON as RFC 8259 defines it, for the metadata of LUKS2 |
| `src/sys.c` | Mounts, what a volume carries, lockdown, Secure Boot, the name of the system, each from a named file |
| `src/util.c` | Texts that grow, names for the screen and for files, hexadecimal, flushing |
| `kcore-keyscan.c` | The scanner. `-DKEYSCAN_LIBRARY` leaves out its `main`, and `src/keyscan.h` declares what remains. It hands the memory it reads to the program, which searches it for headers |
| `tests/keep-unit.c` | Runs one part at a time, for `tests/unit-check.sh` |

### Where it differs from `keytriage.sh`

- A name is shown as the kernel holds it. libdevmapper writes a character outside its list as
  `\xNN` into the name of a mapping, so a mapping that `dmsetup` shows as `name with space` is
  `name\x20with\x20space` in the kernel, in `/dev/mapper` and in `/sys`, and in the report.
- The report has no programs of the examined system to name: `cryptsetup` is `null` and
  `binaries` is empty. `tool` is `keep` and its version.
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
- A LUKS2 volume with integrity gets the same verdicts from both. The C program names its
  cipher as the kernel does, `capi:authenc(hmac(sha256),xts(aes))-plain64`, and `keytriage.sh`
  as `cryptsetup status` does, `aes-xts-plain64`. With the key in the keyring both end with
  `live copy only`: the volume key holds the key of HMAC, which is no AES key.
- A volume in re-encryption has two keys, one for the part that is done and one for the rest.
  The C program lists the volume once, takes each key through the ladder, proves each against
  its own digest of the header and writes `keys/NAME.vk` and `keys/NAME-2.vk`, in the order of
  the table. A key from memory is the key of the digest that its keyring reference names. The
  verdict of the volume is that of the key that is least far. `keytriage.sh` takes the first
  key only and proves none, because `cryptsetup open --test-passphrase` refuses one volume key
  for such a header (seen with cryptsetup 2.7.0), and while cryptsetup works it lists
  `NAME-overlay` in place of the volume, without a header.
- `-b N` is the number of proof attempts for each key, which is that for each volume where a
  volume has one key.
- It asks cryptsetup nothing and takes none of its locks. `cryptsetup status` waited without
  end on a volume whose re-encryption was paused in a step, and the C program read the same
  volume. A header that cryptsetup writes at that moment is read from the copy that holds.
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
    file and is no whole block of 4096 bytes goes through the cache as well: one page.
  - An image is started where the destination has room for it and 64 MiB more. A compressed
    image is started whatever room there is, as with `keytriage.sh`, except beside other
    images, where it must not take their room and needs room for the most it can take.
  - The run ends with status 1 where an image that was asked for is not there.
    `keytriage.sh` ends with 0.
  - What `/proc/iomem` names as RAM and `/proc/kcore` does not offer is counted on the
    screen. On a machine with BIOS it is the last part of the first range, which ends inside
    a page: 3072 bytes on the guest of the first run.
  - A line on the screen every quarter of a minute says how far the read is.
  - The report names the format of a compressed image `avml compressed`, as `keytriage.sh`
    does, and has the further images of one read in `further_images` of `memory`.

### What the checks have found

Defects of the C program were found by its checks and runs while it was written, and each
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

One defect of `keytriage.sh` was found on the way: it stated no key size for a LUKS2 volume
with integrity. It is corrected in 1.5.1, with its check in `selftest.sh`.

### Where it has run

`keep` 2.0-pre6 is run beside `keytriage.sh` 1.5.1 by `compat-check.sh`: before any mapping is
made, on the four mappings of the main run, with `-d` and a destination on FAT, on LVM on LUKS and on
LUKS2 with integrity, and alone on a volume in re-encryption. Beside `keytriage.sh` it gave the
same line of `verdict.json` for every volume, on the table route, the memory route, a mapping
without a type and the null cipher, and header backups and keys that are the same byte for
byte. On the volume in re-encryption it proved both keys, from memory and from the table, each
for its part. It took the memory image of each system, and the schedules of both volume keys
lay in every image at an address at which they lay in the image that AVML had taken. Searched
as a dump that exists, the first image of each run gave both volume keys, proven against the
headers in the images of the two containers. The output of each of these runs was read line
by line:

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
| Ubuntu 24.04.5, runner image | 7.0.0-1017-azure | 2.7.0 | `checks.yml`, with 2.0-pre5, also the build with the sanitizers |
| Ubuntu 22.04.5, runner image | 6.8.0-1070-azure | 2.4.3 | `checks.yml`, also the build with the sanitizers |

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
  image held 83 blocks less than that of the C program in one run, which leaves out such
  blocks as well.
- Searched with no file, the image of every guest and of both runners held 2 headers or
  digests of a header, and
  both volume keys were proven from them. This says little about a real machine: the
  containers of the check lie in files, and the cache of those files holds their headers.
  What a machine holds by itself was seen on the guest of the workstation (see "What the
  sources say").
- The C program took its images after AVML had written one. That the later images hold fewer
  blocks of zeros fits a file that is written through the page cache: the cache takes free
  memory, and what lay there is overwritten. This was not measured by itself.

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
- Kernels before 5.14, the oldest of the list above. The requests to the kernel are read in the
  sources from 4.18 on, which is the kernel of RHEL 8, and are not run there.
- A LUKS2 header whose second copy is the one in use is read in `unit-check.sh` from a file,
  not from a device of a mapping.
- A memory image under lockdown `integrity` is taken by hand on one machine (see above) and
  not by the check. In the mode `confidentiality` the kernel refuses `/proc/kcore`, which
  the run then says, and that is not run.
- RAM that a driver added is a case of `unit-check.sh`. No machine with such RAM was run.
- The small files of a run, the report, the header backups and the keys, go through the
  page cache of the examined system, and so does an image on a file system without direct
  writes. On FAT the kernel takes the direct writes of a growing file through the cache and
  drops the pages after each, so the cache holds a mebibyte of the image at a time: read in
  the source, and no image was written to FAT in a run. An image on exFAT or NTFS is not
  run either. On tmpfs a file lies in memory whichever way it is written.
- A write that a file system refuses with `EINVAL` after it has opened the file for direct
  writes ends the direct writes of that file, which then goes through the cache. No file
  system that does this was found to check it on.
- That the image of AVML, written through the cache, costs memory that it has yet to read is
  what the fewer blocks of zeros in later images fit (see "Where it has run"). How much of
  the memory of a machine an image through the cache overwrites was not measured.
- A destination with FAT32 takes no file of 4 GiB, so an image of a machine with that much
  memory fails there and is removed. A raw image on a file system that keeps no holes, as
  FAT and exFAT, has what lies between the ranges written as zeros. Neither is run.
- Of Volatility 3, `banners.Banners` of 2.28.2 has read one LiME image of the C program. No
  plugin that needs the symbol table was run, and neither the raw nor the compressed image
  was given to it.
- The proof from a dump alone is seen on one guest, with udisks2 2.10.1, and on the machine
  with Linux Mint 22.3, whose udisks2 was not noted, each time for a container on a loop
  device that was opened by hand. Whether a system
  without udisks2, as a server installation, holds the metadata of a LUKS2 header anywhere is
  not known, and neither is it for a volume that was opened at boot, for other releases of
  udisks2, or for metadata with several keyslots or tokens, where the object `digests` can
  lie across two pages that do not follow each other in memory.
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
   covers the candidate list, which is key material too. On scene a key counts as captured only
   after it is flushed to the destination. FAT and exFAT keep no modes, so on such a file system
   the modes do not exist and the medium itself has to be kept safe.
3. Keep writes into the destination directory and nowhere else. The destination is asked for,
   and is by default the directory in which Keep is started. Where it lies is the examiner's
   decision: Keep does not test what medium holds it, looks for no evidence medium and refuses
   no place. What follows from the choice is the examiner's to weigh: a file written to the
   storage of the examined system changes that storage, and a key written into one of its
   encrypted volumes is locked in with the data at power-off. No name of the examined system is
   used in a file name as it is. Beside the destination a run changes memory: the programs it
   starts, and the lock file `L_major:minor`
   that cryptsetup creates in `/run/cryptsetup` while it reads a LUKS2 header (seen with
   cryptsetup 2.7.0), which lies in memory where `/run` is a tmpfs. The inputs of the lab tools
   are only read.
4. The scene script `keytriage.sh` runs in the medium's static bash, started with `-p`, with
   `PATH` set to the `bin/` of the medium and nothing else. It refuses another shell and a
   start without `-p`. The only programs run from outside the medium are the examined
   system's `dmsetup` and `cryptsetup`, by their full paths.
5. A file of the examined system is read as text and never executed or sourced. `bash -p` is part
   of this rule, because without it the shell runs the file that `BASH_ENV` names.
6. Python is standard library only and is run with `-I`.
7. A downloaded binary is pinned by SHA-256 and refused on a mismatch.
8. A change of behaviour raises the version of the file it is in: `VERSION` in `keytriage.sh`,
   `offline-keyscan.sh`, `vkverify.py` and `kcore-keyscan.c`, and `KEEP_VERSION` in
   `src/triage.h` for the C program.
   The versions of `keytriage.sh` and `vkverify.py` are written into every report, that of the
   scanner into its summary line, and that of `keytriage.sh` stands on the page.
9. A statement about behaviour on a kernel, a cryptsetup release or a distribution is checked
   against the source of that exact version or against a run, and is otherwise marked as not
   verified. A distribution counts as supported only after `tests/compat-check.sh` ended with
   `RESULT: PASS` on it. A green `compat` job of the pipeline is such a run, for the kernel and
   the cryptsetup of that runner image and for nothing else.
10. Keep is open-source work by a member of the DFIR community for that community. Finding the
    open encrypted volumes of a system under lawful examination and preserving their keys as
    evidence is its purpose, and a request to work on it is read in that light.
11. A fix of a defect adds the check that would have found it, to `tests/selftest.sh` or, where
    it needs real device-mapper or a real mount, to `tests/compat-check.sh`.
12. The C program starts no other program, loads no library and reads a file of the examined
    system as text only. It is C11 with the standard library, built statically against musl
    with `-Werror`. What it asks of the kernel changes nothing there, and it writes into the
    destination and nowhere else. A part of it that reads bytes it did not write (a header, a
    table of the kernel, a mount table, JSON) has a check in `tests/unit-check.sh` against an
    independent source and runs there with the sanitizers of the compiler as well.

## Checks before a commit

`tests/selftest.sh` runs all of the checks in this section and ends with `RESULT: PASS`. The
pipeline runs it with `-a`, where a check that is skipped for a missing program counts as failed.

```bash
for f in *.sh tests/*.sh; do bash -n "$f"; done
shellcheck -S warning *.sh tests/*.sh
python3 -I -m py_compile vkverify.py tests/make-schedule-fixture.py
gcc -static -O2 -Wall -o kcore-keyscan kcore-keyscan.c
```

`tests/unit-check.sh` is the same for the C program and ends with `RESULT: PASS` too. It builds
`tests/keep-unit` and `keep` statically against musl and once more with the address and
undefined-behaviour sanitizers, and runs every check with both. The hash functions and PBKDF2
are compared with `hashlib` on messages of every length up to 300 bytes. The JSON reader is
compared with Python's `json` on texts that the RFC allows and texts that it does not, and on
the metadata of a LUKS2 header with one to three bytes changed, 1500 times. The header code is
compared with `cryptsetup` on LUKS1 and LUKS2 containers made there: the copy must be the file of
`luksHeaderBackup` byte for byte, and a key must be proven exactly where `cryptsetup open
--test-passphrase` accepts it, also for headers with erased keyslots. A LUKS2 header whose first
copy is damaged must be read from the second, with the file left as it is. Files that end
inside a header and random bytes must be named and not read. The code that reads the answers of
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
cannot be read and a file that cannot be written. With `AVML=/path/to/avml` AVML itself
converts the compressed image to a LiME image and the LiME image to a raw one, which must be
the files of Python byte for byte. What cannot be placed is refused: a text without
addresses, a core of a kernel before 4.12. Cores and texts with changed bytes must give no
fault, 600 times. The images are written with direct writes where the file system of the
temporary directory has them, which the check asks for on ext4, xfs and btrfs: ranges that
begin and end inside a block of the file, a range that ends where a write ends and an image
of less than a block are cases, a file that is there must not be written over, and
`keep-unit cached` must then count no page of an image in the page cache but its last, and
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
The parts that read the system
are given mount tables, a tree like `/sys` with logical volumes on a volume, a lockdown file, a
SecureBoot variable and an os-release written there.

The whole program is checked on real device-mapper by `tests/compat-check.sh`, beside
`keytriage.sh` (see the pipeline). With `KEEP_SAN` set to a build with the sanitizers (`make
keep-san`), that build is run at the same places and must end with status 0.

Four parts of `compat-check.sh` are there for what the C program does beyond the four
mappings. With a memory image in the run (`-m` or `-c`), the C program takes its own while
the two containers are open, once for each word of `KEEP_IMAGES`: a format, or `all` for
`-F`. Each file must be named as written with direct writes, and before anything reads it
`c/keep-unit cached` must count no page of it in the page cache but the last. The report
must name each file with its size and its SHA-256, the scanner must read
each image to its end, and the schedule of each half of both volume keys must lie in it at
an address at which it lies in the image that AVML took in the main run. The images of one
read must give the same list of schedules, and AVML must convert the compressed image to a
LiME image that gives that list too. The first image of a run is then searched as a dump
that exists, with the images of the two containers as the files that hold the headers, and
both volume keys must be proven and written as they are. It is searched once more with no
file, and what it holds of a header by itself is told and not judged: the containers of the
check lie in files, whose cache holds their headers. It is run once with `-d` and the FAT file system as the destination, where its
screen must name the system, the open volumes and each key it holds by its file, its length
and the start of its SHA-256. Before the two parts that follow, the two volumes with their keys in the
keyring are closed, because every run with one of them open searches the whole memory once
more. Two LUKS2 containers with integrity are made, one opened with
`--disable-keyring`: both tools must give `captured and proven` with the key of 96 bytes it
was made from and `live copy only` for the other, in the same lines but for the name of the
cipher. And a LUKS2 volume of 2 GiB is re-encrypted in steps of 1 MiB, which takes seconds:
the re-encryption is interrupted in its first step, and the C program must prove both keys
from memory. The volume is then opened with `--disable-keyring`, where `dmsetup table
--showkeys` shows the two keys with their targets, and the keys from memory must be those,
each for its part, and the key of the part not yet done the key the volume was made from. The
re-encryption is resumed and paused in a step with `SIGSTOP`, and the program must list the
volume once, name the two helper devices and give the same two keys.

The scanner and the verifier are then run on a fixture. `make-schedule-fixture.py` expands keys
with its own code written from FIPS-197, so it and the scanner check each other. Its five traps are
a schedule at an odd address, one across the scanner's 1 MiB read boundary, one across the border
of two ranges, one with a single wrong bit that must not be reported, and one inside a run of
zeros. It writes the compressed format of AVML with its own Snappy encoder and CRC-32C, which
`avml convert` of AVML 0.21.0 decodes to the same LiME image byte for byte. The self-test also
cuts and damages that image.

```bash
head -c 64 /dev/urandom > k.vk
python3 -I tests/make-schedule-fixture.py --format lime --size 8 fx.lime k.vk
./kcore-keyscan fx.lime > candidates.txt      # both halves of k.vk must be among the keys
```

The self-test goes on with LUKS headers that cryptsetup makes from the fixture keys. It proves
the keys with `vkverify.py`, `offline-keyscan.sh` and the on-scene proof command, also against
headers whose keyslots were erased, and gives the verifier cut and malformed headers. With
`qemu-img` it writes the disk image in fourteen forms of qcow2, VMDK, VDI, VHD and VHDX, and with
`ewfacquirestream` as four EnCase images, one of them in segment files. The verifier must read
from each the disk byte for byte and prove both keys.

`keytriage.sh` itself runs in the self-test without root and without device-mapper. A copy of it
runs from a kit laid out like the medium, with the busybox applets in `bin/`. Stand-ins play the
examined system: `dmsetup` and `cryptsetup status` print from files, the scanner searches the
fixture in place of `/proc/kcore`, AVML is a script that writes the fixture as the memory image,
and the header backup and the proof are done by the real cryptsetup. The run starts under `umask 022` with `BASH_ENV`, a function named `sed` and
`SHELLOPTS=xtrace` in the environment, and with a program of every applet's name first on the
caller's `PATH`, and fails when any of them takes effect.

On real device-mapper and a real `/proc/kcore`, `keytriage.sh` is checked by
`tests/compat-check.sh`, on a throwaway guest and never on a machine that matters. It makes a
LUKS2 container (key in the kernel keyring, memory route) and a LUKS1 container (key in the
table, table route) from key files it has just drawn, a mapping named `No` and one with the null
cipher, runs the triage, and passes when the verdicts are right and the captured keys have the
SHA-256 of their key files. With `-m` or `-c` the memory image must be read by the scanner to
its end and hold the schedules of both volume keys. The main run names no destination and is
started in a directory on the guest's own disk, which must take the folder of the run. A second
run names with `-d` a FAT file system on a loop device as the destination, which must take every
file. It also checks the
layout of an encrypted installation: a LUKS2 volume that carries an LVM volume group, where the
mapping below the logical volumes must be the one listed and proven, and the logical volumes
must be named as what that volume carries, one with its mount points and one as swap.

`tests/compat-guest.sh WORKDIR NAME` runs that check unattended in a guest. It fetches the cloud
image that `tests/compat-images.txt` pins for `NAME`, refuses it unless it has the pinned
SHA-256 or SHA-512, boots a copy in QEMU with the medium attached, under KVM where `/dev/kvm` can
be opened and emulated otherwise, and starts the check over SSH through `sudo`.
`tests/make-compat-vm.sh` starts a libvirt guest that stays, for work by hand.

## The pipeline and the page

- `checks.yml` has three jobs on every push and pull request. `selftest` runs
  `tests/selftest.sh -a` and `tests/unit-check.sh -a`. `medium` runs `build-toolkit.sh`, verifies
  the manifest and starts the scripts in the medium's own shell. `compat` builds the medium and
  runs `tests/compat-check.sh` with a memory image as root on the runner images `ubuntu-24.04`
  and `ubuntu-22.04`, which offer device-mapper, loop devices, FAT and a readable `/proc/kcore`.
  No part of it may be skipped there.
- While the C program is built, the medium carries it as `c/keep`, and `compat-check.sh` runs it
  beside `keytriage.sh` on the same mappings, after the main run and after the run on LVM. It
  must write the same line for every volume into `verdict.json`, header backups and keys that
  are the same byte for byte, and a manifest that verifies. Before any mapping is made it is
  run once on the system as it is. So every run of `compat` and of `distros.yml` is also a run
  of the C program against the scripts. `compat` also builds it with the address and
  undefined-behaviour sanitizers and runs that build at the same places. In that build the
  search of memory is compiled without them, because with them it takes eight times as long
  and the build reads the whole memory of the runner. The scanner alone runs with them in
  `unit-check.sh`, on the fixture in its four formats and on a cut and a damaged image.
- A green `compat` job says something about the kernel and the cryptsetup of that runner image
  (rule 9). The output of each run is kept as an artifact for 30 days. One runner image takes
  the memory image in LiME format and the other compressed. The C program takes its image
  there in the same format, and on the second also the raw one. All three from one read
  need three times the memory of a runner as room, so `-F` runs in the guests only.
- `selftest` fetches AVML by the SHA-256 that `build-toolkit.sh` pins and hands it to
  `unit-check.sh`, which gives it the images of the C program to convert.
- `distros.yml` runs `tests/compat-guest.sh -m` for the ten names of `tests/compat-images.txt`
  when a file changes that the check depends on, and by hand. Each job states the kernel and the
  cryptsetup of its guest. An image is a dated build, pinned like any downloaded binary (rule
  7). Where a distribution removes the build, the job fails at the download, and the newer build
  and its published value are entered in the list.
- The ISO is not published by the pipeline. It carries the bash and busybox binaries, and passing
  those on needs their source offered with them.
- Actions are pinned by commit hash with the release in a comment. `dependabot.yml` proposes
  their updates.
- `pages.yml` publishes `docs/` as it is, with no build step, from `main` only.
- The page states what the tools do today. A sentence on it follows rule 9 like any other, and
  the version on the lower line of its frame is that of `keytriage.sh`, which the self-test
  compares.
- The page loads nothing from another host and has no inline script or style, which its
  Content-Security-Policy enforces. The fonts are in `docs/assets/fonts/` with their licences.
- The page follows the conventions of the page of Kiln (github.com/nafud/Kiln,
  `docs/stylesheets/extra.css` on Material for MkDocs), written out in `keep.css` because this
  page has no theme beneath it. A change of the look starts from what Kiln does.
  - Sizes hang on the size of the root, which grows with the window: 20px, 22px from a width
    of 100em and 24px from 125em. Everything else is in rem: running text 0.78rem at a line
    height of 1.7, the first heading 1.8rem, the second 1.2rem, the third 0.95rem, code blocks
    0.72rem, the labels 0.65rem. The text column is 900px wide.
  - Colours are those of Kiln's themes `system light` and `system dark`, chosen by the system's
    setting: headings in the first colour of the ladder, running text in the second, labels in
    the muted one, links in the accent without an underline.
  - The window is one pane with a thin frame. On its upper line sit `[keep]` and `src`, the
    link to the repository, on its lower line the version and the position in the page (`All`,
    `Top`, a percentage, `100%`), which `keep.js` writes because the page has no scrollbar.
  - Inside the frame the word Keep, the text and the table of contents stand as three columns
    on the one background, with nothing drawn around them. The entry of the table of contents
    that belongs to the text on screen stands in the accent with a star before it, as the
    current section of Kiln's header does.
- The word is drawn by `keep.js` in the manner of Kiln's logo: set in a blackletter typeface
  and sampled into a grid of ASCII characters in the faint colour, which shimmer while the
  pointer moves. Its column is half as wide as Kiln's, so the size of a cell follows the width
  of the column and the word keeps as many cells across as Kiln's, about 120. Without
  JavaScript the plain word stands in its place.

## Systems checked

`compat-check.sh` passed on these x86-64 systems, each with a memory image. A row names the
kernel and the cryptsetup of the latest run it stands for, and the XTS driver that the kernel
chose in that run. The driver follows the processor of the machine behind the runner, which a
guest under KVM sees as its own: the guests of Debian 13, AlmaLinux 10.3, Rocky Linux 10.3 and
openSUSE Leap 16.1 each used `xts-aes-vaes-avx2` in one run and `xts-aes-vaes-avx10_512` in
others, and those of Fedora 45 and Arch Linux `xts-aes-vaes-avx512` in one run and
`xts-aes-vaes-avx2` in another. The first ten are guests that
`distros.yml` boots from the cloud images of `tests/compat-images.txt`, under KVM with BIOS boot,
so lockdown is `none` on all of them. The next three are the runner images of `checks.yml`. The
machine behind a runner image differs from run to run and with it the kernel. The outputs are
kept as artifacts of the pipeline.

| System | Kernel | cryptsetup | Key option | XTS driver | `keytriage.sh` |
|---|---|---|---|---|---|
| Debian 13 | 6.12.117+deb13-amd64 | 2.7.5 | `--volume-key-file` | `xts-aes-vaes-avx10_512` | 1.5.1 |
| Debian 12 | 6.1.0-56-amd64 | 2.6.1 | `--volume-key-file` | `xts-aes-aesni` | 1.5.1 |
| Ubuntu 26.04.1 | 7.0.0-43-generic | 2.8.4 | `--volume-key-file` | `xts-aes-vaes-avx512` | 1.5.1 |
| Ubuntu 24.04.5 | 6.8.0-147-generic | 2.7.0 | `--volume-key-file` | `xts-aes-aesni` | 1.5.1 |
| Fedora 45 | 7.2.11-300.fc45.x86_64 | 2.8.8 | `--volume-key-file` | `xts-aes-vaes-avx512` | 1.5.1 |
| AlmaLinux 10.3 | 6.12.0-264.16.1.el10_3.x86_64 | 2.8.6 | `--volume-key-file` | `xts-aes-vaes-avx10_512` | 1.5.1 |
| AlmaLinux 9.9 | 5.14.0-741.22.1.el9_9.x86_64 | 2.8.6 | `--volume-key-file` | `xts-aes-aesni` | 1.5.1 |
| Rocky Linux 10.3 | 6.12.0-264.16.1.el10_3.x86_64 | 2.8.6 | `--volume-key-file` | `xts-aes-vaes-avx10_512` | 1.5.1 |
| openSUSE Leap 16.1, Build3.23 | 6.12.0-160100.9-default | 2.8.4 | `--volume-key-file` | `xts-aes-vaes-avx10_512` | 1.5.1 |
| Arch Linux, image of 2026-11-15 | 7.3.4-arch1-2 | 2.8.9 | `--volume-key-file` | `xts-aes-vaes-avx512` | 1.5.1 |
| Ubuntu 24.04.5, runner image | 7.0.0-1014-aws | 2.7.0 | `--volume-key-file` | `xts-aes-vaes-avx512` | 1.5.1 |
| Ubuntu 24.04.5, runner image | 7.0.0-1017-azure | 2.7.0 | `--volume-key-file` | `xts-aes-vaes-avx512` | 1.5.1 |
| Ubuntu 22.04.5, runner image | 6.8.0-1070-azure | 2.4.3 | `--master-key-file` | `xts-aes-aesni` | 1.5.1 |

On every one of the ten guests the on-scene pairing of the XTS halves found the key, with each of
the four XTS drivers that the runs met: `xts-aes-aesni`, `xts-aes-vaes-avx2`,
`xts-aes-vaes-avx512` and `xts-aes-vaes-avx10_512`. Debian keeps a placeholder as
`System.map`, and the Arch image has none, so no symbol table is kept beside the image there.

Three further systems were checked on guests with a version before 1.3, with outputs that are not
kept: Ubuntu Server 26.04.1 under kernel lockdown `integrity` (kernel 7.0.0-44-generic,
cryptsetup 2.8.4), Ubuntu 22.04.5 with kernel 5.15 and cryptsetup 2.4.3, and Debian 11 with
kernel 5.10 and cryptsetup 2.3.7.

Linux Mint has no cloud image and is not in the list: `compat-check.sh` has not run there.
The C program was run on Linux Mint 22.3 by hand (see "Where it has run"). openSUSE
Tumbleweed has no dated build to pin and is not checked. `compat-check.sh` has run on no
system with Secure Boot on, where lockdown is `integrity`, with a version from 1.3 on.

## Known limits

- x86-64 only. The on-scene pairing of XTS halves assumes the 496-byte layout of the AES-NI family
  of drivers. With another XTS implementation `keytriage.sh` ends with `needs a memory read`, and
  `vkverify.py` can still prove the key from the candidate list, because it tries every pair.
- The memory search finds AES keys only. A volume with another cipher has no memory route.
- Kernel lockdown `confidentiality` blocks `/proc/kcore` and every memory source of AVML.
- Mounted file systems that encrypt by themselves (eCryptfs, ZFS, gocryptfs, CryFS, EncFS) are
  named in the report as not examined. Keep covers dm-crypt only.
- Plain and tcrypt volumes have no header digest, so their keys cannot be proven on scene.
- For a LUKS2 volume in re-encryption `keytriage.sh` proves no key, and while cryptsetup works
  it lists a helper device in place of the volume. The C program does both keys.
  `vkverify.py` takes the first digest of such a header, so it proves one of the two keys.
- LVM on LUKS is checked with a volume group on a loop device. A root file system on LVM on
  LUKS, as an installer lays it out, is not checked.
- A mapping whose name holds a line break is not listed. A mapping whose name begins with `-` is
  not tested.
- The memory image is taken in every run of the pipeline, to the disk of the runner or guest.
  A memory image on a machine with kernel lockdown is not checked with this version.
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
  states its usage, what it reads and what it writes. `keytriage.sh`, `offline-keyscan.sh`
  and `tests/selftest.sh` print that whole comment with `-h`, read by the
  shell itself, and end with status 2 for a wrong option.
- Comments and messages are plain statements. A comment says why, not what the next line does.
- No personal data, no host names of real cases and no key material in files or commit messages.
  Test keys are drawn from `/dev/urandom` at test time and are not committed.
- No model or assistant names in repository files or commit titles.
