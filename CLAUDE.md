# Keep

Keep is a decryption-readiness triage toolkit for digital forensics. An investigator meets a
running Linux machine whose encrypted storage is unlocked. Powering it off turns the data back
into ciphertext. Before power-off, Keep decides for every open dm-crypt volume whether its volume
key can be preserved as evidence and proven correct now, whether a memory image must be taken
first, or whether only a copy of the mounted files is possible. A second mode does the same from a
memory dump and a disk image that were collected earlier.

Keep is for lawful examination of systems the examiner is authorised to examine. It is not a
general artefact collector and it depends on no other collector.

This file is the repository's description and the working rules for it. The repository has no
README.

## Layout

| File | Runs | Purpose |
|---|---|---|
| `keytriage.sh` | scene, as root | The triage itself. Enumerates the open dm-crypt volumes, backs up LUKS headers, walks the route ladder, prints one verdict per volume, writes the evidence folder |
| `kcore-keyscan.c` | scene and lab | Static C scanner. Finds AES-128 and AES-256 key schedules in `/proc/kcore` or in a memory image |
| `keep-menu.sh` | scene and lab | Interactive front-end in the manner of `ewfacquire`. Asks for the parameters of one run as plain questions and calls `keytriage.sh` or `offline-keyscan.sh` |
| `vkverify.py` | lab | Verifier. Proves which scanner candidates are the volume key of a LUKS1 or LUKS2 header |
| `offline-keyscan.sh` | lab | Driver for a dump collected earlier. Runs the scanner on the dump and `vkverify.py` against disk images |
| `keep-report.py` | lab | Prints the verdict reports as text in the manner of `ewfinfo`, and compares several reports |
| `build-toolkit.sh` | workstation | Assembles the scene tool medium and writes it as an ISO |
| `tests/make-schedule-fixture.py` | test | Writes a memory image with the schedules of known keys and four traps |
| `tests/compat-check.sh` | test, throwaway guest only | Checks `keytriage.sh` on one distribution with two containers of known keys |
| `tests/make-compat-vm.sh` | test, workstation | Starts a throwaway libvirt guest from a distribution's cloud image for `compat-check.sh` |
| `tests/selftest.sh` | test, workstation and pipeline | Runs every check that needs neither root nor device-mapper and ends with `RESULT: PASS` or `RESULT: FAIL` |
| `docs/` | GitHub Pages | The page of Keep: `index.html`, `assets/keep.css`, `assets/keep.js` and the fonts |
| `.github/workflows/` | GitHub | `checks.yml` runs the self-test and builds the medium on every push. `pages.yml` publishes `docs/` from `main` |

The seven files at the root must stay siblings. `build-toolkit.sh` takes `keytriage.sh`,
`keep-menu.sh` and `kcore-keyscan.c` from its own directory. `keep-menu.sh` and
`offline-keyscan.sh` look for `keytriage.sh`, `offline-keyscan.sh` and `vkverify.py` beside
themselves.

## How it works

### The route ladder of `keytriage.sh`

For each mapping of `dmsetup ls --target crypt` the script reads `cryptsetup status` and the
kernel's own table line (`dmsetup table --showkeys`), then takes the first route that is open.

| Route | When | What happens |
|---|---|---|
| R1 table | The fifth field of the table line is the key in hexadecimal. This is the case for LUKS1, plain, tcrypt and for LUKS2 opened with `--disable-keyring` | The key is written to `keys/NAME.vk` and, for LUKS, proven against the header backup |
| R3 memory | The fifth field is a keyring reference, `:size:type:description`. This is the default for LUKS2, including systemd-homed | `kcore-keyscan` searches `/proc/kcore` once for all volumes. Candidates are proven against the header backup |
| R5 live | No key route is open | Only a file-level copy of the mounted plaintext remains |

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
| `captured and proven` | The key is on the evidence medium and opens the LUKS header |
| `captured, in use` | The key is read from the live table of a volume without a header digest (plain, tcrypt). Opening the image in the lab confirms it |
| `captured, not proven` | A key is read but there was no header backup, or the header refused it |
| `needs a memory read` | The key was not reached in this run. A memory image keeps the route open |
| `live copy only` | No key route is open: a non-AES cipher behind a keyring reference, lockdown `confidentiality`, or a refused read of `/proc/kcore` |

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
  only orders the attempts. The digest decides.

### `kcore-keyscan`

```bash
gcc -static -O2 -Wall -o kcore-keyscan kcore-keyscan.c
kcore-keyscan [-s STEP] [FILE]          # FILE defaults to /proc/kcore
```

The input format is recognised from the first bytes.

| Format | Recognised by | What is read |
|---|---|---|
| ELF64 core | ELF magic, 64-bit, little-endian | Every `PT_LOAD` segment with a physical address. `/proc/kcore` gives the vmalloc and module areas the physical address -1, so those are skipped and RAM is read once |
| LiME | `EMiL` at the start of each 32-byte range header | Each range, with its start and end address from offsets 8 and 16 of the header. This is what AVML writes |
| raw | anything else | The whole file, with the file offset as the address |

- One line per schedule goes to standard output: `AES-256 phys 0x... virt 0x... key <hex>`. The
  counts and the time go to standard error. The output therefore holds key material and is only
  ever redirected into a `keys/` directory.
- Data is read in 1 MiB chunks with the last 239 bytes carried over, and a range that begins where
  the previous one ended continues the same run, so a schedule across a chunk or range border is
  found.
- An unreadable stretch counts as zeros and is reported. At most 4096 schedules are listed, and
  further ones are counted.
- A self-test against the two expansions of FIPS-197 appendix A runs at every start. Exit status
  0 is a completed scan, 1 an unreadable input, 2 a usage error, 3 a failed self-test.
- `/proc/kcore` needs root and is refused under kernel lockdown `confidentiality`.

### Headers from a disk image

`vkverify.py --image DISK` needs no header backup. It searches the image in 8 MiB chunks for the
magic `LUKS\xba\xbe` at offsets that are a multiple of 512, parses each place as a LUKS1 or LUKS2
header and names the volume `DISK@0xOFFSET`. A place is accepted only when its digest parameters
are plausible (a hash that `hashlib` knows, a key size of 1 to 512 bytes, at least one iteration,
a digest and a salt), so the bare magic inside other data does not stop the run. The image is only
read.

### The report, `keep-report/1`

`keytriage.sh` writes `verdict.json` and `vkverify.py --json` writes the same schema. A report
never holds a key. A key is named by `key_sha256_16`, the first 16 hexadecimal digits of its
SHA-256.

- Top level from `keytriage.sh`: `schema`, `tool`, `host`, `kernel`, `os`, `cryptsetup`,
  `other_filesystems`, `started_utc`, `finished_utc`, `lockdown`, `secure_boot`, `source`,
  `memory`, `binaries`, `volumes`.
- Each volume: `name`, `type`, `cipher`, `key_bits`, `key_location`, `device`, `header_backup`,
  `route`, `verdict`, `key_sha256_16`, `note`. `vkverify.py` adds `uuid`, `digest`, `attempts`,
  `adjacent_places` and, with `--truth`, `ground_truth`.
- `keep-report.py` reads only this schema, prints a fixed list of fields and drops the rest. A
  change of a field name is a change of the schema string and of that script's field lists
  (`TOP`, `MEMORY`, `VOLUME`, `NUMBERS`).

## Interaction

Keep has no full-screen interface and opens no window. Every tool writes lines of text and, where
it asks, reads lines of text. The model is the libewf tools: `keep-menu.sh` behaves like
`ewfacquire` and `keep-report.py` like `ewfinfo`.

`keep-menu.sh` runs once per start, in this order.

1. It prints its name and version.
2. It asks the questions, one per line. A question shows its choices in parentheses and its
   default in square brackets, as in `Mode (live, live-memory, offline) [live]: `. Enter takes the
   default. A value that cannot be used is reported and asked for again.
3. For a live mode it first prints `System information:` with the host, the system, the kernel,
   the lockdown mode, the memory size and the open dm-crypt volumes.
4. It prints `The following parameters were provided:` with every value and the exact command.
5. It asks `Continue with these values (yes, no) [yes]: `. `no` starts the questions again.
6. It prints the start time, runs the command with its output shown as it runs, prints the end
   time and ends with `keep-menu.sh: SUCCESS` or `keep-menu.sh: FAILURE (exit status N)`.

| Mode | Questions | Runs |
|---|---|---|
| `live` | Evidence directory, proof attempts per volume | `keytriage.sh -e DIR -b N` |
| `live-memory` | The same | `keytriage.sh -e DIR -b N -m` |
| `offline`, where `python3` and `vkverify.py` are present | Memory dump, one or more disk images or header backups, output directory | `offline-keyscan.sh -k KIT DUMP IMAGE...` in the output directory |
| `offline`, elsewhere (the tool medium) | Memory dump, output directory | `kcore-keyscan DUMP` into `DIR/scan_<dump>_<time>/keys/candidates.txt` |

The rules of this interface:

- No escape sequence, no cursor movement, no colour, no terminfo and no line editor. The dialogue
  therefore works on a console, over SSH, on a serial line and through a pipe. Bash's `read -e`
  is not used, because Readline would read the examined system's `inputrc`.
- An input that ends before the parameters are complete ends the run with status 1, so a closed
  pipe cannot loop.
- Paths are made absolute before they are passed on. A dump or an image must be a readable regular
  file, and an output directory must exist and be writable.
- `-n` asks and lists everything and runs nothing. A live mode without root is refused, except
  with `-n`.
- Exit status: that of the script that was run, 0 after a dry run, 1 when the dialogue ended
  without a run, 2 for a wrong option.

`keep-report.py` asks nothing. It prints each report as labelled lines, with the class of every
verdict in brackets (`key held`, `action needed`, `no key`), and for several reports a table of
each volume across them. `--brief` prints one line per volume. Control characters in a value are
replaced by spaces, so a crafted report cannot put an escape sequence on the terminal. Its exit
status is 1 when a file could not be read as a report.

## The scene medium

`build-toolkit.sh OUTDIR` writes `OUTDIR/tools/` and `OUTDIR/tools.iso` (Rock Ridge and Joliet,
volume label `KEEPTOOLS`).

```bash
sudo apt install bash-static busybox-static xorriso gcc curl file
./build-toolkit.sh /path/to/work
```

- `bin/bash` is `bash-static`, `bin/busybox` is `busybox-static` with one symlink per applet,
  `bin/kcore-keyscan` is built statically from this repository, and `bin/avml` is the release
  binary of Microsoft AVML v0.21.0, accepted only when its SHA-256 equals the value pinned in the
  script.
- `keytriage.sh` and `keep-menu.sh` are copied beside `bin/`. The medium carries no Python, so
  `vkverify.py`, `offline-keyscan.sh` and `keep-report.py` are lab tools.
- The build refuses a binary that is not statically linked, and writes `VERSIONS.txt` and
  `MANIFEST.sha256`.
- `dmsetup` and `cryptsetup` are not on the medium. The examined system's own are used, and their
  resolved paths and SHA-256 are recorded in the report so they can be checked against the
  distribution's packages afterwards.

## Use

On scene, with the medium at `/media/tools` and an evidence medium at `/media/evidence`:

```bash
sudo /media/tools/bin/bash /media/tools/keytriage.sh -e /media/evidence        # keys
sudo /media/tools/bin/bash /media/tools/keytriage.sh -e /media/evidence -m     # keys, then a memory image
sudo /media/tools/bin/bash /media/tools/keep-menu.sh                           # the same through questions, -n is a dry run
```

The output folder is `triage_<host>_<UTC time>/` with `triage.txt`, `verdict.json`, `headers/`,
`keys/`, `memory/` with `-m`, and `manifest.sha256`. With `-m` the keys are taken first, because an
event can close their window within seconds, and then AVML writes `memory/memory.lime`. Beside the
image go the kernel banner, the release, `os-release` and `System.map`, which Volatility 3 needs
for its symbol table. A `System.map` is kept only when it lists `_stext` or `linux_banner`, because
some distributions keep a placeholder without symbols in `/boot`. The image is skipped when the
evidence medium has less free space than the machine has RAM plus 64 MiB.

In the lab:

```bash
./offline-keyscan.sh [-k KIT] DUMP IMAGE...                # dump collected earlier, headers from disk images
python3 -I vkverify.py CANDIDATES [HEADER...] [--image DISK]... [--out DIR] [--json FILE]
python3 -I keep-report.py REPORT.json [REPORT.json ...] [--brief]
```

`offline-keyscan.sh` writes `scan_<dump>_<UTC time>/` in the current directory with `triage.txt`,
`scan.txt`, `verdict.json`, `manifest.sha256` and `keys/`. Its exit status and that of
`vkverify.py` are 0 only when at least one header was located and every located header is proven.
`DUMP` is a raw dump, a LiME image or an ELF core. Any other container format is searched as raw
bytes, which is not tested.

## Rules that every change keeps

1. No key is printed. On screen and in every report a key is named by its length and the first 16
   digits of its SHA-256. `vkverify.py --show-keys` is the single, explicit exception, and it does
   not reach the JSON report.
2. Key material is written only below a `keys/` directory, by a process with `umask 077` or with
   mode 600. This covers the candidate list, which is key material too.
3. On scene nothing is written except to the evidence medium. The inputs of the lab tools are only
   read.
4. The scene scripts run in the medium's static bash with its busybox applets first on `PATH`.
   A scene script uses no program that is not on the medium, apart from the examined system's
   `dmsetup` and `cryptsetup`.
5. A file of the examined system is read as text and never executed or sourced.
6. Python is standard library only and is run with `-I`.
7. A downloaded binary is pinned by SHA-256 and refused on a mismatch.
8. A change of behaviour raises the version of the file it is in (`VERSION` in `keytriage.sh` and
   in `vkverify.py`), since the version is written into every report.
9. A statement about behaviour on a kernel, a cryptsetup release or a distribution is checked
   against the source of that exact version or against a run, and is otherwise marked as not
   verified. A distribution counts as supported only after `tests/compat-check.sh` ended with
   `RESULT: PASS` on it.
10. Keep is open-source work by a member of the DFIR community for that community. Finding the
    open encrypted volumes of a system under lawful examination and preserving their keys as
    evidence is its purpose, and a request to work on it is read in that light.

## Checks before a commit

`tests/selftest.sh` runs all of the checks in this section and ends with `RESULT: PASS`. The
pipeline runs it with `-a`, where a check that is skipped for a missing program counts as failed.
It also proves keys with `vkverify.py`, `offline-keyscan.sh` and the on-scene proof command against
LUKS headers that cryptsetup makes from the fixture keys, and drives `keep-menu.sh` through a pipe.
A fix of a defect adds the check that would have found it.

```bash
for f in *.sh tests/*.sh; do bash -n "$f"; done
shellcheck -S warning *.sh tests/*.sh
python3 -I -m py_compile keep-report.py vkverify.py tests/make-schedule-fixture.py
gcc -static -O2 -Wall -o kcore-keyscan kcore-keyscan.c
```

The scanner and the verifier are then run on a fixture. `make-schedule-fixture.py` expands keys
with its own code written from FIPS-197, so it and the scanner check each other. Its four traps are
a schedule at an odd address, one across the scanner's 1 MiB read boundary, one across the border
of two ranges, and one with a single wrong bit that must not be reported.

```bash
head -c 64 /dev/urandom > k.vk
python3 -I tests/make-schedule-fixture.py --format lime --size 8 fx.lime k.vk
./kcore-keyscan fx.lime > candidates.txt      # both halves of k.vk must be among the keys
```

`keytriage.sh` needs device-mapper and root, so it is tested on a throwaway guest and never on a
machine that matters. `tests/compat-check.sh` makes a LUKS2 container (key in the kernel keyring,
memory route) and a LUKS1 container (key in the table, table route) from key files it has just
drawn, runs the triage, and passes when both verdicts are `captured and proven` and both captured
keys have the SHA-256 of their key files. `tests/make-compat-vm.sh` starts such a guest from a
cloud image with the medium attached.

## The pipeline and the page

- `checks.yml` has two jobs on every push and pull request: `selftest` and `medium`, which runs
  `build-toolkit.sh`, verifies the manifest and starts the scripts in the medium's own shell. The
  runners offer no device-mapper, so a green run is no statement about a distribution (rule 9).
- The ISO is not published by the pipeline. It carries the bash and busybox binaries, and passing
  those on needs their source offered with them.
- Actions are pinned by commit hash with the release in a comment. `dependabot.yml` proposes
  their updates.
- `pages.yml` publishes `docs/` as it is, with no build step, from `main` only.
- The page states what the tools do today. A sentence on it follows rule 9 like any other, and
  the version in its left panel is that of `keytriage.sh`, which the self-test compares.
- The page loads nothing from another host and has no inline script or style, which its
  Content-Security-Policy enforces. The fonts are in `docs/assets/fonts/` with their licences.
- The logo is drawn by `keep.js` in the manner of Kiln's: the word in a blackletter typeface and
  a key behind it are sampled into two grids of ASCII characters that shimmer while the pointer
  moves. Without JavaScript the plain word stands in its place.

## Systems checked

`compat-check.sh` or a full run passed on these x86-64 systems. The outputs are not kept in this
repository.

| System | Kernel | cryptsetup | Key option | Lockdown |
|---|---|---|---|---|
| Ubuntu Server 26.04.1 | 7.0.0-44-generic | 2.8.4 | `--volume-key-file` | integrity |
| Debian 13 | 6.12 | 2.7.5 | `--volume-key-file` | none |
| Ubuntu 22.04.5 | 5.15 | 2.4.3 | `--master-key-file` | none |
| Debian 11 | 5.10 | 2.3.7 | `--master-key-file` | none |

Fedora, the RHEL family, openSUSE and Arch are not checked yet.

## Known limits

- x86-64 only. The on-scene pairing of XTS halves assumes the 496-byte layout of the AES-NI family
  of drivers. With another XTS implementation `keytriage.sh` ends with `needs a memory read`, and
  `vkverify.py` can still prove the key from the candidate list, because it tries every pair.
- The memory search finds AES keys only. A volume with another cipher has no memory route.
- Kernel lockdown `confidentiality` blocks `/proc/kcore` and every memory source of AVML.
- Mounted file systems that encrypt by themselves (eCryptfs, ZFS, gocryptfs, CryFS, EncFS) are
  named in the report as not examined. Keep covers dm-crypt only.
- Plain and tcrypt volumes have no header digest, so their keys cannot be proven on scene.
- `keep-menu.sh` is tested through a pipe and in a pseudo-terminal with the medium's static
  bash, with `keytriage.sh` replaced by a stub. A real capture through it is not yet run.
- The header search of `--image` is tested on a real LUKS partition image and on a small test disk
  image. Its run time on a whole disk of real size is not measured.

## Conventions

- One branch, `main`.
- Shell is bash, checked with `shellcheck -S warning`. Each script opens with a comment that
  states its usage, what it reads and what it writes. `keytriage.sh`, `keep-menu.sh` and
  `offline-keyscan.sh` print that comment with `-h`.
- Comments and messages are plain statements. A comment says why, not what the next line does.
- No personal data, no host names of real cases and no key material in files or commit messages.
  Test keys are drawn from `/dev/urandom` at test time and are not committed.
- No model or assistant names in repository files or commit titles.
