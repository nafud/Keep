# Usage

```text
sudo ./keep [-n] [-d DIR] [-b N] [-m [-f FORMAT | -F]]
./keep -s DUMP [-n] [-d DIR] [FILE...]
```

The first form runs on the examined system. It takes the keys of the open volumes and, with `-m`, a memory image as well. The second form needs no root and searches a memory dump for those keys. Keep asks no question and starts no other program. It runs on x86-64 Linux, and [About](about.md#tested) lists the systems it was tested on.

## On scene { #keys }

```bash
sudo ./keep -m -d /media/evidence
```

Keep lists the open dm-crypt volumes and backs up each LUKS header. It then takes each volume key, proves it against the header and writes it to the destination, which is the directory given with `-d` or otherwise the current directory. With `-m` it takes a memory image afterwards. The screen below is from a run on Tails 7.18 with its Persistent Storage unlocked, started with `-m -d /mnt/out`.

<div class="highlight keep-screen"><pre><code><b>keep 2.0 (2026-11)</b>

  <i>host</i>         amnesia
  <i>system</i>       Tails
  <i>kernel</i>       6.12.118+deb13-amd64
  <i>lockdown</i>     integrity
  <i>secure boot</i>  enabled
  <i>memory</i>       3.81 GiB
  <i>started</i>      2026-11-27T09:16:42Z
  <i>output</i>       /mnt/out/triage_amnesia_20261127_091642
  <i>destination</i>  /dev/sdb, ext4, mounted at /mnt, 11.09 GiB free
  <i>volumes</i>      1 open dm-crypt volume: TailsData_unlocked

<b>TailsData_unlocked</b>
  <i>type</i>         LUKS2, aes-xts-plain64, 512-bit key
  <i>device</i>       /dev/sda2
  <i>in use</i>       TailsData_unlocked at /live/persistence/TailsData_unlocked,
               TailsData_unlocked at
               /run/nosymfollow/live/persistence/TailsData_unlocked,
               TailsData_unlocked at /run/nosymfollow/home/amnesia/Persistent,
               TailsData_unlocked at /home/amnesia/Persistent,
               TailsData_unlocked at /run/nosymfollow/var/cache/apt/archives,
               TailsData_unlocked at /var/cache/apt/archives, TailsData_unlocked
               at /run/nosymfollow/var/lib/apt/lists, TailsData_unlocked
               at /var/lib/apt/lists
  <i>header</i>       headers/TailsData_unlocked.hdr, 16777216 bytes
  <i>key</i>          in the kernel keyring, not in the table
  <i>search</i>       /proc/kcore, 15 AES schedules in keys/kcore-candidates.txt
  <i>candidates</i>   15 schedules of AES-256
  <i>found</i>        tweak schedule at 0x10845d030, data schedule at 0x10845d220
  <i>key file</i>     keys/TailsData_unlocked.vk, 64 bytes, sha256 40ceae6c565886e1
  <i>verdict</i>      <span class="reached">captured and proven</span>, opens the header

<b>memory image</b>
  <i>source</i>       /proc/kcore, 10 ranges of RAM, 3.98 GiB
  <i>not offered</i>  16384 bytes of the RAM ranges of /proc/iomem are in no segment of
               /proc/kcore and in no image
  <i>memory.lime</i>  <span class="reached">captured</span>, 4274372928 bytes, 8 s
  <i>sha256</i>       b8857c0c368d73b2b841cf13e442ca6b5c88a820882cf58386dd0623b975893f
  <i>written</i>      direct (O_DIRECT), pages released from the page cache
  <i>beside it</i>    the kernel banner, the release and os-release
  <i>symbols</i>      no System.map found on this system

<b>result</b>
  TailsData_unlocked  <span class="reached">captured and proven</span>  40ceae6c565886e1
  memory.lime         <span class="reached">captured</span>             memory/memory.lime

finished 2026-11-27T09:17:03Z, 21 s
keep: every file of this run is flushed to the destination</code></pre></div>

- **No key is printed.** A key is named by its file, its length and the first 16 digits of its SHA-256.
- **`in use`** shows where the volume is mounted or used as swap, which is what a copy of the mounted files would have to cover. Tails mounts each place twice, so the line is long here.
- **`verdict`** is the last line of each volume and states what was achieved for its key.
- **Ctrl-C** ends a run in an orderly way. What is already held is kept, the report is written and the exit status is 1. A second Ctrl-C ends the run at once.

## Verdicts { #verdicts }

| Verdict | Meaning |
|---|---|
| <span class="reached">captured and proven</span> | The key is written to the destination and produces the digest stored in the LUKS header. |
| <span class="open">captured, in use</span> | The key is read from the live table of a volume that has no header digest, such as a plain or tcrypt volume. Opening the image in the lab confirms it. |
| <span class="open">captured, not proven</span> | A key is read, but there was no header backup or the header refused it. |
| <span class="open">needs a memory read</span> | The key was not reached in this run. A memory image keeps the route open. |
| <span class="not">live copy only</span> | No key route is open. The cause is a cipher other than AES behind a keyring reference, kernel lockdown in the mode `confidentiality`, or a refused read of `/proc/kcore`. Only a copy of the mounted files remains. |
| no key needed | The mapping has no key because it uses the null cipher. The device holds the data as they are. |

A key counts as captured only once it is written to the destination and flushed. A volume that cryptsetup is re-encrypting has two keys. Both are proven and written as `keys/NAME.vk` and `keys/NAME-2.vk`.

## Memory image { #image }

| Option | File | Format |
|---|---|---|
| `-m` | `memory.lime` | LiME. |
| `-m -f raw` | `memory.raw` | Each byte at the file offset that is its physical address. |
| `-m -f avml` | `memory.avml` | The compressed format of AVML, for a destination with less room than the machine has memory. |
| `-m -F` | all three | Written from one read of the memory. Together they need about three times its room. |

- The keys are taken first, because their window can close within seconds.
- An image needs room for the memory of the machine plus 64 MiB and is skipped otherwise. A compressed image is started whatever room there is.
- Kernel lockdown in the mode `confidentiality` refuses the image. The mode `integrity`, which Secure Boot enables on many systems, does not.
- Where the system has a `System.map`, it is kept beside the image for the symbol table of Volatility 3.

## In the lab { #dump }

```bash
./keep -s memory.lime -d /case disk.img
```

`-s` searches a memory dump for AES key schedules and proves which key opens each LUKS header. It needs no root and only reads its inputs.

| Argument | What is read |
|---|---|
| `DUMP` | A LiME image, a compressed AVML image, an ELF core or raw bytes. A kdump or makedumpfile file and a file compressed as a whole are refused. |
| `FILE` | A header backup, the raw image of a partition or of a whole disk, or a device. |

The screen below shows the image from the run above, searched with no `FILE` at all. The paths are shortened.

<div class="highlight keep-screen"><pre><code><b>keep 2.0 (2026-11)</b>

  <i>dump</i>         /case/memory.lime
  <i>started</i>      2026-11-27T09:19:14Z
  <i>output</i>       /case/scan_memory.lime_20261127_091914
  <i>format</i>       LiME, 10 ranges of memory, 3.98 GiB
  <i>search</i>       15 AES schedules, 9 different keys, 14 s
  <i>keys</i>         0 of AES-128, 9 of AES-256, in keys/candidates.txt
  <i>headers</i>      1 in the dump itself

<b>memory@0x10d28df</b>
  <i>found</i>        in the dump at 0x10d28df, the digests of a LUKS2 header
  <i>digest</i>       pbkdf2-sha256, 1000 iterations, key size not stated
  <i>proof</i>        attempt 1, a pair of schedules in place
  <i>schedules</i>    tweak at 0x10845d030, data at 0x10845d220
  <i>key file</i>     keys/memory@0x10d28df.vk, 64 bytes, sha256 40ceae6c565886e1
  <i>verdict</i>      <span class="reached">proven</span>

<b>result</b>
  memory@0x10d28df  <span class="reached">proven</span>  40ceae6c565886e1

finished 2026-11-27T09:19:28Z, 14 s
keep: every file of this run is flushed to the destination</code></pre></div>

The image itself held the digests of the header, so the key is proven from memory alone. Its fingerprint, `40ceae6c565886e1`, is the one from the scene. Where the memory holds no digest, a `FILE` with the header is needed.

| Verdict | Meaning |
|---|---|
| <span class="reached">proven</span> | A key of the dump produces the digest of the header and is written as `keys/NAME.vk`. |
| <span class="not">not proven</span> | No key of the dump produces the digest. |
| <span class="not">unreadable header</span> | The file ends inside the header, or its fields cannot be read. |
| <span class="open">found in memory, not proven</span> | A pair of schedules laid out as the kernel keeps the two keys of a volume, with no header at hand to prove it. |

### Open the volume { #lab }

```bash
sudo cryptsetup open --readonly --volume-key-file keys/NAME.vk DEVICE NAME
```

A `.vk` file holds the volume key as raw bytes, so cryptsetup asks for no passphrase. Releases before 2.5.0 call the option `--master-key-file`.

### EnCase images and disks of virtual machines { #formats }

```bash
python3 -I vkverify.py keys/candidates.txt --image disk.E01 --out keys
```

Some inputs are not read by `keep -s`. For an EnCase image (`E01`), the disk file of a virtual machine (qcow2, VMDK, VDI, VHD, VHDX) or a header whose digest uses ripemd160 or whirlpool, use `vkverify.py` from the [repository](https://github.com/nafud/Keep). It takes the list of schedules written by a run of Keep and needs only Python 3.

## Files of a run { #files }

```text
triage_<host>_<UTC time>/       the keys of the running system
  triage.txt                    the lines of the screen, without colour
  verdict.json                  the same for a program, schema keep-report/2
  headers/NAME.hdr              the LUKS header backups
  keys/NAME.vk                  the volume keys
  keys/kcore-candidates.txt     the key schedules that the search of memory found
  log/                          the kernel's table of each mapping, keys as zeros
  memory/                       with -m, the image and what names its kernel
  manifest.sha256               the SHA-256 of all of them

scan_<dump>_<UTC time>/         the search of a dump
  triage.txt  verdict.json  scan.txt  manifest.sha256
  keys/candidates.txt           the key schedules of the dump
  keys/NAME.vk                  one for each proven key
```

Everything below `keys/` is key material, including the lists of schedules. A report never holds a key. Every file is created under `umask 077` and flushed before the run ends.

## Options { #options }

| Option | Meaning |
|---|---|
| `-d DIR` | The destination directory. By default the current directory. |
| `-m` | Take a memory image of the running system after the keys. |
| `-f FORMAT` | The format of the image, which is `lime` by default and can be `raw` or `avml`. |
| `-F` | The image in every format, from one read of the memory. |
| `-b N` | Proof attempts per key in the search of memory. By default 64. |
| `-s DUMP` | Search this memory dump instead of the running system. |
| `-n` | A plain screen with no colour and no progress line that is written over. A pipe gets this automatically. |
| `-h`, `-V` | The help and the version. |

## Exit status { #status }

| Status | Meaning |
|---|---|
| 0 | The run completed and every file is flushed. With `-s` and `FILE`s, every header in them is also proven. |
| 1 | The run could not start or was asked to end, a write failed, or a requested image is missing. With `-s`, the dump is refused or cut, or the `FILE`s hold no header or one that is not proven. |
| 2 | A wrong option. The usage is printed and nothing is written. |

A verdict is not an exit status. A run that ends with <span class="not">live copy only</span> has done its work and exits with 0.
