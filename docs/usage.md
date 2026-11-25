# Usage

Keep has three runs: the keys of the running system, a memory image after the keys, and the search of a memory dump that exists. A run is said by its options. Keep asks no question, opens no window and starts no other program, so it works on a console, over SSH, on a serial line and through a pipe.

```text
sudo ./keep [-n] [-d DIR] [-b N] [-m [-f FORMAT | -F]]
./keep -s DUMP [-n] [-d DIR] [FILE...]
```

## The keys of the running system { #keys }

Started as root without an option, Keep lists the open dm-crypt volumes of the system, backs up each LUKS header, takes each volume key by the first route that is open, proves it against the header and writes it to the destination. The destination is the directory of `-d`, or the one in which Keep is started.

```bash
sudo ./keep -d /media/evidence
```

The screen is a card of facts: the system, then a block for each volume that ends with its verdict, then every verdict once more. An example with `-m`, with illustrative values:

<div class="highlight keep-screen"><pre><code><b>keep 2.0-pre9 (2026-11)</b>

  <i>host</i>         ws01
  <i>system</i>       Linux Mint 22.3
  <i>kernel</i>       6.14.0-37-generic
  <i>lockdown</i>     integrity
  <i>secure boot</i>  enabled
  <i>memory</i>       15.31 GiB
  <i>started</i>      2026-11-25T10:57:59Z
  <i>output</i>       /media/evidence/triage_ws01_20261125_105759
  <i>destination</i>  /dev/sdb1, ext4, mounted at /media/evidence, 348.49 GiB free
  <i>volumes</i>      1 open dm-crypt volume: nvme0n1p3_crypt

<b>nvme0n1p3_crypt</b>
  <i>type</i>         LUKS2, aes-xts-plain64, 512-bit key
  <i>device</i>       /dev/nvme0n1p3
  <i>in use</i>       vg-root at /, vg-swap as swap
  <i>header</i>       headers/nvme0n1p3_crypt.hdr, 16777216 bytes
  <i>key</i>          in the kernel keyring, not in the table
  <i>search</i>       /proc/kcore, 174 AES schedules in keys/kcore-candidates.txt
  <i>candidates</i>   140 schedules of AES-256
  <i>found</i>        tweak schedule at 0x5c257f10, data schedule at 0x5c258100
  <i>key file</i>     keys/nvme0n1p3_crypt.vk, 64 bytes, sha256 63ad5d7aa9009877
  <i>verdict</i>      <span class="reached">captured and proven</span>, opens the header

<b>memory image</b>
  <i>source</i>       /proc/kcore, 5 ranges of RAM, 15.69 GiB
  <i>memory.lime</i>  <span class="reached">captured</span>, 16848920736 bytes, 16 s
  <i>sha256</i>       78937a2cacba541488434900ef90fe9a3da927a99524bf6d7ceea0cc2c4001b7
  <i>written</i>      direct (O_DIRECT), pages released from the page cache
  <i>beside it</i>    the kernel banner, the release and os-release
  <i>symbols</i>      System.map from /boot/System.map-6.14.0-37-generic

<b>result</b>
  nvme0n1p3_crypt  <span class="reached">captured and proven</span>  63ad5d7aa9009877
  memory.lime      <span class="reached">captured</span>             memory/memory.lime

finished 2026-11-25T10:59:04Z, 65 s
keep: every file of this run is flushed to the destination</code></pre></div>

No key is printed. A key is named by its file in `keys/`, its length and the first 16 digits of its SHA-256. The line `in use` says what the volume carries: where it and the devices that stand on it, such as logical volumes, are mounted or used as swap. This is what a copy of the mounted files has to cover.

`-b N` limits the proof attempts for each key in the search of memory, 64 by default.

## Verdicts { #verdicts }

Keep prints exactly one of these for each volume. They are also the values of `verdict` in the report. On a terminal the word has the look of the table: green for what is reached, blue for what is held or can still be had and is not proven here, bold for what was not reached.

| Verdict | Meaning |
|---|---|
| <span class="reached">captured and proven</span> | The key is written to the destination and gives the digest of the LUKS header. |
| <span class="open">captured, in use</span> | The key is read from the live table of a volume without a header digest (plain, tcrypt). Opening the image in the lab confirms it. |
| <span class="open">captured, not proven</span> | A key is read, but there was no header backup or the header refused it. |
| <span class="open">needs a memory read</span> | The key was not reached in this run. A memory image keeps the route open. |
| <span class="not">live copy only</span> | No key route is open: a cipher that is not AES behind a keyring reference, kernel lockdown `confidentiality`, or a refused read of `/proc/kcore`. Only a copy of the mounted files remains. |
| no key needed | The mapping has no key: its table names a key of size 0, which is the null cipher. The device holds the data as they are. |

A key counts as captured only when it is written to the destination and flushed. When the write or the flush fails, the verdict is <span class="open">needs a memory read</span> and the run ends with status 1.

A volume that cryptsetup is re-encrypting has two keys, one for the part that is done and one for the rest. Keep lists the volume once, proves each key against its own digest of the header and writes `keys/NAME.vk` and `keys/NAME-2.vk`. The verdict of the volume is that of the key that is least far.

## A memory image { #image }

With `-m` the memory of the machine is taken after the keys, because an event can close the window of the keys within seconds and an image of a large machine takes longer. It goes into `memory/` of the folder of the run.

```bash
sudo ./keep -m -d /media/evidence
```

| Option | File | Format |
|---|---|---|
| `-m` | `memory.lime` | LiME: each range of memory behind a header of 32 bytes with its first and last address. |
| `-m -f raw` | `memory.raw` | Each byte at the file offset that is its physical address. What lies between the ranges is not written, so the file is as long as the highest address of RAM. |
| `-m -f avml` | `memory.avml` | The compressed format of AVML, for a destination with less room than the machine has memory. In the runs of the pipeline it had 55 % to 68 % of the memory on guests of 2 GiB. |
| `-m -F` | all three | Written from one read of the memory, so the files hold the same memory. They need about three times its room. |

- The memory is read through `/proc/kcore`, the ranges that `/proc/iomem` names as RAM. Kernel lockdown in the mode `confidentiality` refuses that file and with it every image. In the mode `integrity`, which Secure Boot brings on many systems, the image is taken.
- An image is started where the destination has room for it and 64 MiB more, and is otherwise named as skipped. A compressed image is started whatever room there is, because its size is known only at its end. One that cannot be written to its end is removed and counts as failed.
- An image is written with direct writes, which pass the page cache, where the file system of the destination has them, so that the file does not take the free memory that the image has yet to read. The screen says which way each file was written.
- The SHA-256 of an image is computed while it is written and stands on the screen, in the report and in the manifest.
- Beside the image go the kernel banner, the release, `os-release` and `System.map`, which Volatility 3 needs to find the symbol table of exactly this kernel. A `System.map` is kept only when it lists symbols: some distributions keep a placeholder in `/boot`.
- An image that was asked for and is not there ends the run with status 1.

## A memory dump that exists { #dump }

`-s DUMP` searches a dump that was taken earlier, by Keep or by another tool, for AES key schedules, and proves which of the keys is the volume key of each LUKS header in the `FILE`s. It needs no root and only reads its inputs.

```bash
./keep -s memory.lime -d /case disk.img
```

| Argument | What is read |
|---|---|
| `DUMP` | A LiME image, a compressed AVML image, an ELF core such as the dump that a hypervisor takes of a guest, or raw bytes. A kdump or makedumpfile file and a file that is compressed as a whole are refused: searched as raw bytes they would give a part of the schedules or none. |
| `FILE` | A header backup, the raw image of a partition or of a whole disk, or a device. Its start is read as a header, and behind it every sector that begins with the magic of LUKS. |

A run on a test image of 64 MiB and a container that was made for it, with the paths shortened:

<div class="highlight keep-screen"><pre><code><b>keep 2.0-pre9 (2026-11)</b>

  <i>dump</i>         /case/memory.lime
  <i>started</i>      2026-11-25T18:07:05Z
  <i>output</i>       /case/scan_memory.lime_20261125_180705
  <i>format</i>       LiME, 2 ranges of memory, 64.00 MiB
  <i>search</i>       6 AES schedules, 6 different keys, 0 s
  <i>keys</i>         2 of AES-128, 4 of AES-256, in keys/candidates.txt
  <i>headers</i>      1 in 1 file

<b>data.img</b>
  <i>file</i>         /case/data.img
  <i>header</i>       LUKS2, aes-xts-plain64, 512-bit key
  <i>uuid</i>         84e364e7-d975-42e0-aff2-a488f36de533
  <i>digest</i>       pbkdf2-sha256, 1000 iterations
  <i>proof</i>        attempt 1, a pair of schedules in place
  <i>schedules</i>    tweak at 0x100010000, data at 0x1000101f0
  <i>key file</i>     keys/data.img.vk, 64 bytes, sha256 c07493a5a009e740
  <i>verdict</i>      <span class="reached">proven</span>

<b>result</b>
  data.img  <span class="reached">proven</span>  c07493a5a009e740

finished 2026-11-25T18:07:06Z, 1 s
keep: every file of this run is flushed to the destination</code></pre></div>

- The dump itself is searched for what a machine can hold of a header: a LUKS1 header at the start of a page, and the digests of a LUKS2 header. Either proves a key as the header in a file does and stands in the report as `memory@0xADDRESS`. So a key can be proven from a dump alone, where the memory still holds them.
- The pairs of schedules that lie as the kernel keeps the two keys of an XTS volume are tried first, then each key alone, then every other pair. Every header has the first two before any header has the third, which is the square of the number of keys and is counted on the screen before it begins.
- Where no header is found, nothing can be proven, and the run says so. A pair of schedules in place that no header proves is written as `keys/memory-pair-N.vk` and named <span class="open">found in memory, not proven</span>: a candidate for a volume whose header is not at hand.

| Verdict | Meaning |
|---|---|
| <span class="reached">proven</span> | A key of the dump gives the digest of the header and is written as `keys/NAME.vk`. |
| <span class="not">not proven</span> | No key of the dump gives the digest. For a digest that only the dump holds the word is blue: it can be of a volume that was closed before the dump was taken. |
| <span class="not">unreadable header</span> | The file ends inside the header, or its fields cannot be read. |
| <span class="open">found in memory, not proven</span> | A pair of schedules in place for which no header is at hand. |

## What a run leaves behind { #files }

One folder in the destination, with every file created under `umask 077`:

```text
triage_<host>_<UTC time>/       the keys of the running system
  triage.txt                    the lines of the screen, without colour
  verdict.json                  the same for a program, schema keep-report/1
  headers/NAME.hdr              the LUKS header backups
  keys/NAME.vk                  the volume keys
  keys/kcore-candidates.txt     the key schedules that the search of memory found
  log/NAME.table.txt            what the kernel said about a mapping, its key as zeros
  log/kcore-keyscan.txt         what the search of memory said
  memory/                       with -m: the image, banner.txt, kernel-release.txt,
                                os-release, System.map
  manifest.sha256               the SHA-256 of all of them

scan_<dump>_<UTC time>/         the search of a dump
  triage.txt  verdict.json  scan.txt  manifest.sha256
  keys/candidates.txt           the key schedules of the dump
  keys/NAME.vk                  one for each proven key
  keys/memory-pair-N.vk         pairs in place that no header proves
```

A header backup, the list of schedules and a key are flushed to the medium as soon as they are written, and the run ends with a flush of the whole file system of the destination, because the machine may lose power the moment the verdict is read. In the names of the folder and of the files, a character of the host name or of a mapping name that is not a letter, a digit or one of `. _ + = @ , -` becomes `_`.

A report never holds a key. Everything below `keys/` is key material, the lists of schedules included.

## Options { #options }

| Option | Meaning |
|---|---|
| `-d DIR` | The destination directory. By default the current directory. |
| `-m` | Take a memory image of the running system, after the keys. |
| `-f FORMAT` | The format of the image: `lime` (default), `raw` or `avml`. |
| `-F` | The image in every format, from one read of the memory. |
| `-b N` | Proof attempts per key in the search of memory. By default 64. |
| `-s DUMP` | Search this memory dump, not the running system. |
| `-n` | A plain screen: no colour and no line of progress that is written over. |
| `-h`, `-V` | The help, and the version. |

Colour is given where standard output is a terminal, `TERM` is set and not `dumb`, and `NO_COLOR` is not set to a value. `sudo` hands `NO_COLOR` on to no program unless it is configured to, which is why there is `-n` as well. Through a pipe or into a file the screen has no escape sequence, and a step that takes long prints a line every quarter of a minute. The colours say nothing that the words do not.

## Exit status { #status }

| Status | The running system | A dump, with `-s` |
|---|---|---|
| 0 | The run completed and every file is flushed. | The dump was read to its end, and with `FILE`s every header in them is proven. |
| 1 | The run could not start, a write or a flush to the destination failed, or an image that was asked for is not there. | The dump is refused, unreadable or cut. With `FILE`s also: they hold no header, or a header has a key that is not proven. |
| 2 | A wrong option, an option without its value, or options that do not go together. The usage is printed and nothing is written. | The same. |

A verdict is no status: a run that ends with <span class="not">live copy only</span> for a volume has done its work and ends with 0.

## In the lab { #lab }

A file `keys/NAME.vk` is the volume key as bytes, which is what cryptsetup takes to open the volume in an image without a passphrase. Releases before 2.5.0 name the option `--master-key-file`.

```bash
sudo cryptsetup open --readonly --volume-key-file keys/NAME.vk DEVICE NAME
```

`keep -s` reads header backups, raw images and devices. Two things are read by the Python tools of the repository alone:

- The disk file of a virtual machine (qcow2, VMDK, VDI, VHD, VHDX) and an EnCase image (`E01`). Such a file does not hold a header as the disk holds it, so `vkverify.py` reads it as the guest saw the disk. It takes the list of schedules that a run of Keep wrote.
- A header whose digest uses a hash function that Keep does not compute (ripemd160, whirlpool).

```bash
python3 -I vkverify.py keys/candidates.txt --image disk.E01 --out keys
```

A LiME image of Keep was read by `banners.Banners` of Volatility 3 2.28.2, which named the kernel that ran. No plugin that needs the symbol table was run on an image of Keep.
