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
| `tests/compat-check.sh` | test, throwaway guest only | Checks `keytriage.sh` on real device-mapper: containers and mappings of known keys, the null cipher, and where the evidence directory may lie |
| `tests/make-compat-vm.sh` | test, workstation | Starts a throwaway libvirt guest from a distribution's cloud image for `compat-check.sh` |
| `tests/selftest.sh` | test, workstation and pipeline | Runs every check that needs neither root nor device-mapper, `keytriage.sh` included on stand-ins for the examined system, and ends with `RESULT: PASS` or `RESULT: FAIL` |
| `docs/` | GitHub Pages | The page of Keep: `index.html`, `assets/keep.css`, `assets/keep.js` and the fonts |
| `.github/workflows/` | GitHub | `checks.yml` runs the self-test, builds the medium and runs `compat-check.sh` on two runner images on every push. `pages.yml` publishes `docs/` from `main` |

The seven files at the root must stay siblings. `build-toolkit.sh` takes `keytriage.sh`,
`keep-menu.sh` and `kcore-keyscan.c` from its own directory. `keep-menu.sh` and
`offline-keyscan.sh` look for `keytriage.sh`, `offline-keyscan.sh` and `vkverify.py` beside
themselves.

## How it works

### The route ladder of `keytriage.sh`

For each mapping of `dmsetup ls --target crypt` the script reads `cryptsetup status` and the
kernel's own table line (`dmsetup table --showkeys`), then takes the first route that is open.
A mapping is a line of the listing with a name, a tab and the device number in parentheses
(`_display_name` in `dmsetup.c`), so every name the kernel allows is taken, also `No` and a name
with a space.

| Route | When | What happens |
|---|---|---|
| R1 table | The fifth field of the table line is the key in hexadecimal. This is the case for LUKS1, plain, tcrypt and for LUKS2 opened with `--disable-keyring` | The key is written to `keys/NAME.vk` and, for LUKS, proven against the header backup |
| R3 memory | The fifth field is a keyring reference, `:size:type:description`. This is the default for LUKS2, including systemd-homed | `kcore-keyscan` searches `/proc/kcore` once for all volumes. Candidates are proven against the header backup. The list is kept in `keys/` also when there is no header backup |
| R5 live | No key route is open | Only a file-level copy of the mounted plaintext remains |

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
| `captured and proven` | The key is on the evidence medium and opens the LUKS header |
| `captured, in use` | The key is read from the live table of a volume without a header digest (plain, tcrypt). Opening the image in the lab confirms it |
| `captured, not proven` | A key is read but there was no header backup, or the header refused it |
| `needs a memory read` | The key was not reached in this run. A memory image keeps the route open |
| `live copy only` | No key route is open: a non-AES cipher behind a keyring reference, lockdown `confidentiality`, or a refused read of `/proc/kcore` |
| `no key needed` | The mapping has no key: key size 0 in the table, the null cipher. The device holds the data as they are |

A key counts as captured only when it is on the evidence medium and flushed. When the write or
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

The input format is recognised from the first bytes.

| Format | Recognised by | What is read |
|---|---|---|
| ELF64 core | ELF magic, 64-bit, little-endian | Every `PT_LOAD` segment with a physical address. `/proc/kcore` gives the vmalloc and module areas the physical address -1, so those are skipped and RAM is read once |
| LiME | `EMiL` at the start of each 32-byte range header | Each range, with its start and end address from offsets 8 and 16 of the header. This is what AVML writes |
| raw | anything else, or any file with `-r` | The whole file, with the file offset as the address |
| refused | the first bytes of a compressed AVML image (`AVML`, version 2), of a kdump, diskdump or flattened makedumpfile file, or of a gzip, xz, zstd, bzip2 or lz4 file | Nothing. Such a file holds memory in another form. Searched as raw bytes, a compressed AVML image gave 3 of 5 schedules and a gzip file 2 of 5, with status 0. `avml convert` turns the first into a LiME image |

- One line per schedule goes to standard output: `AES-256 phys 0x... virt 0x... key <hex>`. The
  counts and the time go to standard error. The output therefore holds key material and is only
  ever redirected into a `keys/` directory.
- Data is read in 1 MiB chunks with the last 239 bytes carried over, and a range that begins where
  the previous one ended continues the same run, so a schedule across a chunk or range border is
  found.
- An unreadable stretch counts as zeros and is reported. At most 4096 schedules are listed, and
  further ones are counted.
- A self-test against the two expansions of FIPS-197 appendix A runs at every start. Exit status
  0 is a completed scan, 1 an unreadable or refused input, 2 a usage error, 3 a failed self-test.
  The summary line names the version of the scanner.
- `/proc/kcore` needs root and is refused under kernel lockdown `confidentiality`.

### Headers from a disk image

`vkverify.py --image DISK` needs no header backup. It searches the image in 8 MiB chunks for the
magic `LUKS\xba\xbe` at offsets that are a multiple of 512, parses each place as a LUKS1 or LUKS2
header and names the volume `DISK@0xOFFSET`. A place is accepted only when its digest parameters
are plausible (a hash that `hashlib` knows, a key size of 1 to 512 bytes, at least one iteration,
a digest and a salt), so the bare magic inside other data does not stop the run. The image is only
read.

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
- Each volume: `name`, `type`, `cipher`, `key_bits`, `key_location`, `device`, `header_backup`,
  `route`, `verdict`, `key_sha256_16`, `note`. `vkverify.py` names the file of the header in
  `device` and adds `uuid`, `digest`, `attempts`, `adjacent_places` and, with `--truth`,
  `ground_truth`.
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
   time and ends with `keep-menu.sh: SUCCESS` or `keep-menu.sh: FAILURE (exit status N)`. The
   script is started in the shell that runs the menu, with `-p`, and not through its `#!` line,
   which would name the bash of the examined system.

| Mode | Questions | Runs |
|---|---|---|
| `live` | Evidence directory, proof attempts per volume | `bash -p keytriage.sh -e DIR -b N` |
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
verdict in brackets (`key held`, `no key needed`, `action needed`, `no key`), and for several
reports a table of each volume across them. `--brief` prints one line per volume. Control characters in a value are
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
- The bash of the medium is the `bash-static` of the build workstation. `VERSIONS.txt` on the
  medium names its version, and the `compat` job of the pipeline prints it for each runner image.

## Use

On scene, with the medium at `/media/tools` and an evidence medium at `/media/evidence`:

```bash
sudo /media/tools/bin/bash -p /media/tools/keytriage.sh -e /media/evidence        # keys
sudo /media/tools/bin/bash -p /media/tools/keytriage.sh -e /media/evidence -m     # keys, then a memory image
sudo /media/tools/bin/bash -p /media/tools/keep-menu.sh                           # the same through questions, -n is a dry run
```

- `keytriage.sh` and `keep-menu.sh` start only under `bash -p`, and on the medium only in its own
  `bin/bash`. Without `-p` bash runs the file that `BASH_ENV` names, takes functions from the
  environment and obeys `SHELLOPTS`, all before the first line of a script. `sudo` removes these
  variables (`initial_badenv_table` in its `env.c`), a root shell does not.
- The evidence directory must lie on a medium of its own. `keytriage.sh` finds the mount that
  holds it in `/proc/self/mountinfo` and the whole disks beneath it in `/sys` (a partition lies in
  the directory of its disk, a device-mapper or md device lists what it stands on in `slaves/`).
  A directory on the root file system, or on a disk that also carries the root file system, is
  refused. `-f` accepts it for a test. A directory on an open dm-crypt volume is accepted with a
  note, because an encrypted evidence medium is one too.
- `-p DIRS` names the directories of the examined system's `dmsetup` and `cryptsetup`, by default
  `/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin`. `-b N` limits the proof attempts
  per volume on the memory route.
- Exit status of `keytriage.sh`: 0 when the run completed and was flushed, 1 when it could not
  start or a write or a flush to the medium failed, 2 for a wrong option.

The output folder is `triage_<host>_<UTC time>/` with `triage.txt`, `verdict.json`, `headers/`,
`keys/`, `log/` (what `cryptsetup status`, the scanner and AVML wrote), `memory/` with `-m`, and
`manifest.sha256`. In the names of the folder and of the files every character of the host name
or of a mapping name that is not a letter, a digit or one of `. _ + = @ , -` becomes `_`, so
that a name cannot leave the evidence directory and FAT and exFAT take it. Two mapping names
that differ only by case are kept apart by a further `_`.

Every file is created with `umask 077`. A header backup, the candidate list and a key are
flushed with `fsync` as soon as they are written (`sync FILE` of busybox, which reports a
failure), and the run ends with `syncfs` on the evidence medium (`sync -f`).

With `-m` the keys are taken first, because an event can close their window within seconds, and
then AVML writes `memory/memory.lime`. Beside the image go the kernel banner, the release,
`os-release` and `System.map`, which Volatility 3 needs for its symbol table. A `System.map` is
kept only when it lists `_stext` or `linux_banner`, because some distributions keep a placeholder
without symbols in `/boot`. The image is skipped when the evidence medium has less free space than
the machine has RAM plus 64 MiB.

In the lab:

```bash
./offline-keyscan.sh [-k KIT] DUMP IMAGE...                # dump collected earlier, headers from disk images
python3 -I vkverify.py CANDIDATES [HEADER...] [--image DISK]... [--out DIR] [--json FILE]
python3 -I keep-report.py REPORT.json [REPORT.json ...] [--brief]
```

`offline-keyscan.sh` writes `scan_<dump>_<UTC time>/` in the current directory with `triage.txt`,
`scan.txt`, `verdict.json`, `manifest.sha256` and `keys/`. Its exit status and that of
`vkverify.py` are 0 only when at least one header was located and every located header is proven.
`DUMP` is a raw dump, a LiME image or an ELF core. The compressed formats that the scanner
refuses end the run. Any other container format is searched as raw bytes, which is not tested.

## Rules that every change keeps

1. No key is printed. On screen and in every report a key is named by its length and the first 16
   digits of its SHA-256. `vkverify.py --show-keys` is the single, explicit exception, and it does
   not reach the JSON report.
2. Key material is written only below a `keys/` directory, by a process with `umask 077`. This
   covers the candidate list, which is key material too. On scene a key counts as captured only
   after it is flushed to the medium. FAT and exFAT keep no modes, so on such a medium the modes
   do not exist and the medium itself has to be kept safe.
3. On scene nothing is written to the storage of the examined system. `keytriage.sh` writes into
   the evidence directory and nowhere else, refuses an evidence directory on the root file system
   or on a disk that carries it, and uses no name of the examined system in a file name as it is.
   What a run still changes is memory: the programs it starts, and the lock file `L_major:minor`
   that cryptsetup creates in `/run/cryptsetup` while it reads a LUKS2 header (seen with
   cryptsetup 2.7.0), which lies in memory where `/run` is a tmpfs. The inputs of the lab tools
   are only read.
4. The scene scripts, `keytriage.sh` and `keep-menu.sh`, run in the medium's static bash, started
   with `-p`, with `PATH` set to the `bin/` of the medium and nothing else. They refuse another
   shell and a start without `-p`. The only programs run from outside the medium are the examined
   system's `dmsetup` and `cryptsetup`, by their full paths.
5. A file of the examined system is read as text and never executed or sourced. `bash -p` is part
   of this rule, because without it the shell runs the file that `BASH_ENV` names.
6. Python is standard library only and is run with `-I`.
7. A downloaded binary is pinned by SHA-256 and refused on a mismatch.
8. A change of behaviour raises the version of the file it is in: `VERSION` in `keytriage.sh`,
   `keep-menu.sh`, `offline-keyscan.sh`, `vkverify.py`, `keep-report.py` and `kcore-keyscan.c`.
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

## Checks before a commit

`tests/selftest.sh` runs all of the checks in this section and ends with `RESULT: PASS`. The
pipeline runs it with `-a`, where a check that is skipped for a missing program counts as failed.

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

The self-test goes on with LUKS headers that cryptsetup makes from the fixture keys. It proves
the keys with `vkverify.py`, `offline-keyscan.sh` and the on-scene proof command, also against
headers whose keyslots were erased, and gives the verifier cut and malformed headers. It drives
`keep-menu.sh` through a pipe.

`keytriage.sh` itself runs in the self-test without root and without device-mapper. A copy of it
runs from a kit laid out like the medium, with the busybox applets in `bin/`. Stand-ins play the
examined system: `dmsetup` and `cryptsetup status` print from files, the scanner searches the
fixture in place of `/proc/kcore`, and the header backup and the proof are done by the real
cryptsetup. The run starts under `umask 022` with `BASH_ENV`, a function named `sed` and
`SHELLOPTS=xtrace` in the environment, and with a program of every applet's name first on the
caller's `PATH`, and fails when any of them takes effect.

On real device-mapper and a real `/proc/kcore`, `keytriage.sh` is checked by
`tests/compat-check.sh`, on a throwaway guest and never on a machine that matters. It makes a
LUKS2 container (key in the kernel keyring, memory route) and a LUKS1 container (key in the
table, table route) from key files it has just drawn, a mapping named `No` and one with the null
cipher, runs the triage, and passes when the verdicts are right and the captured keys have the
SHA-256 of their key files. It also checks that an evidence directory on the guest's own disk is
refused and that a FAT evidence medium on a loop device is accepted. `tests/make-compat-vm.sh`
starts such a guest from a cloud image with the medium attached.

## The pipeline and the page

- `checks.yml` has three jobs on every push and pull request. `selftest` runs
  `tests/selftest.sh -a`. `medium` runs `build-toolkit.sh`, verifies the manifest and starts the
  scripts in the medium's own shell. `compat` builds the medium and runs `tests/compat-check.sh`
  with `-m` as root on the runner images `ubuntu-24.04` and `ubuntu-22.04`, which offer
  device-mapper, loop devices, FAT and a readable `/proc/kcore`. No part of it may be skipped
  there.
- A green `compat` job says something about the kernel and the cryptsetup of that runner image
  (rule 9). The output of each run is kept as an artifact for 30 days.
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

`compat-check.sh` or a full run passed on these x86-64 systems. The first three rows are the
runner images of the pipeline, where the check runs on every push and its output is kept as an
artifact. The machine behind a runner image differs from run to run and with it the kernel, so a
row names the kernel of the run it stands for. The other four systems were checked on guests
with a version before 1.3, and their outputs are not kept.

| System | Kernel | cryptsetup | Key option | Lockdown | XTS driver | `keytriage.sh` |
|---|---|---|---|---|---|---|
| Ubuntu 24.04.5, runner image | 7.0.0-1014-aws | 2.7.0 | `--volume-key-file` | none | `xts-aes-vaes-avx512` | 1.3.1 |
| Ubuntu 24.04.5, runner image | 7.0.0-1017-azure | 2.7.0 | `--volume-key-file` | none | `xts-aes-vaes-avx512` | 1.3.0 |
| Ubuntu 22.04.5, runner image | 6.8.0-1070-azure | 2.4.3 | `--master-key-file` | none | `xts-aes-aesni` | 1.3.1 |
| Ubuntu Server 26.04.1 | 7.0.0-44-generic | 2.8.4 | `--volume-key-file` | integrity | not recorded | before 1.3 |
| Debian 13 | 6.12 | 2.7.5 | `--volume-key-file` | none | not recorded | before 1.3 |
| Ubuntu 22.04.5 | 5.15 | 2.4.3 | `--master-key-file` | none | not recorded | before 1.3 |
| Debian 11 | 5.10 | 2.3.7 | `--master-key-file` | none | not recorded | before 1.3 |

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
- The test of the evidence directory knows the disks only where the kernel names a block device
  for a file system. For a network share, tmpfs or ZFS only the test against the root file system
  applies, and a loop device counts as a disk of its own. The step from a partition to its disk
  is checked on the runners, where `/boot/efi` is refused as lying on the disk of the root file
  system. On the runner with the kernel 7.0.0-1014-aws the root file system was the
  device-mapper device `/dev/mapper/cow-root`, so there the step through `slaves/` was taken as
  well. A stack of LVM over dm-crypt is not checked.
- A mapping whose name holds a line break is not listed. A mapping whose name begins with `-` is
  not tested.
- The memory image with `-m` is taken in the `compat` job on both runner images, to the disk of
  the runner with `-f`. A memory image on a machine with kernel lockdown is not checked with this
  version.
- `keep-menu.sh` is tested through a pipe and in a pseudo-terminal with the medium's static
  bash, with `keytriage.sh` replaced by a stand-in. A real capture through it is not yet run.
- The header search of `--image` is tested on a real LUKS partition image and on a small test disk
  image. Its run time on a whole disk of real size is not measured.
- The scanner refuses the compressed formats it knows by their first bytes. It does not read
  them. A compressed AVML image has to be converted with `avml convert` first.

## Conventions

- One branch, `main`.
- Shell is bash, checked with `shellcheck -S warning`. Each script opens with a comment that
  states its usage, what it reads and what it writes. `keytriage.sh`, `keep-menu.sh`,
  `offline-keyscan.sh` and `tests/selftest.sh` print that whole comment with `-h`, read by the
  shell itself, and end with status 2 for a wrong option.
- Comments and messages are plain statements. A comment says why, not what the next line does.
- No personal data, no host names of real cases and no key material in files or commit messages.
  Test keys are drawn from `/dev/urandom` at test time and are not committed.
- No model or assistant names in repository files or commit titles.
