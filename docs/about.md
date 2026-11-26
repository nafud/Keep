# About

An investigator meets a running Linux machine whose encrypted storage is unlocked. Powering it off turns the data back into ciphertext. Keep runs before power-off and decides, for every open dm-crypt volume, one of three things: the volume key can be preserved as evidence and proven correct now, a memory image must be taken first, or only a copy of the mounted files is possible.

Finding the keys is what Keep is for. Two options go with it: Keep can take a memory image of the running system, and it can search a memory dump that exists for the keys and prove them against a disk image.

Keep is not a general artefact collector. It is made to run beside one, such as UAC, and depends on none. It is open-source work for the DFIR community, for lawful examination of systems the examiner is authorised to examine.

## What it does { #does }

- It lists every open dm-crypt volume of the system: LUKS1, LUKS2, plain and tcrypt, also LUKS2 with integrity, a volume that cryptsetup is re-encrypting and a volume that carries LVM. For each it says what the volume carries: where it and the devices on it are mounted or used as swap.
- It backs up each LUKS header, byte for byte the file that `cryptsetup luksHeaderBackup` writes.
- It takes each volume key, from the table of the kernel or from memory, and proves it against the header.
- It takes the memory of the machine as a LiME image, a raw image or the compressed format of AVML, with its SHA-256.
- It searches a memory dump that exists for keys and proves them against the headers in disk images, or against what the dump itself holds of a header.
- It writes what it found for a reader, `triage.txt`, and for a program, `verdict.json`, with the SHA-256 of every file of the run. A terminal gets the screen in colour, by the SGR sequences for bold and the eight colours alone, and a pipe gets plain lines.<sup><a href="#ref-20">[20]</a></sup>

## The ideas behind it { #ideas }

### The kernel hands out the key { #table }

The kernel hands the table of a mapped device to every caller with `CAP_SYS_ADMIN`, the key of a crypt target in hexadecimal included. No flag asks for the key and kernel lockdown does not withhold it. It is `dmsetup` that shows zeros in its place unless it is asked.<sup><a href="#ref-10">[10]</a> <a href="#ref-18">[18]</a></sup> Keep makes the two requests of `dmsetup` itself, which change nothing in the kernel.

For LUKS1, plain and tcrypt volumes, and for LUKS2 opened with `--disable-keyring`, the table holds the key. This is the first route, and it needs nothing but root.

### A key in the keyring is still in memory { #memory }

By default cryptsetup gives the key of a LUKS2 volume to the kernel keyring, and the table shows a reference to it. The cipher still needs the key for every block. AES expands a key into round keys,<sup><a href="#ref-1">[1]</a></sup> and the kernel holds that expanded schedule as long as the volume is open. Its first 16 or 32 bytes are the key.

A schedule can be found without knowing the key, because each of its words follows from earlier ones by the rule of the expansion. Halderman and others showed this for memory images in 2008, with a search that allows for bits that have decayed.<sup><a href="#ref-2">[2]</a></sup> Keep reads the memory of a running machine, where no bit has decayed, so its test is exact: every position is tested over the whole schedule, 176 bytes for AES-128 and 240 bytes for AES-256. A hit is a real schedule, though not necessarily one of a disk volume.

With `aes-xts` the volume key is two AES keys, the data key and the tweak key. On x86-64 with the AES-NI family of drivers the kernel keeps both schedules in one structure, the tweak schedule first and the data schedule 496 bytes after it.<sup><a href="#ref-12">[12]</a></sup> Keep pairs the schedules by that distance, and in the search of a dump it tries every other pair after those.

The memory is read through `/proc/kcore`, which needs root and is refused under kernel lockdown in the mode `confidentiality`.<sup><a href="#ref-11">[11]</a></sup>

### Only a proven key counts { #proof }

Nothing is reported as a volume key on the strength of where it was found. A LUKS header stores a PBKDF2 digest of the volume key: LUKS1 in its binary header, LUKS2 in the object `digests` of its metadata, which are JSON.<sup><a href="#ref-3">[3]</a> <a href="#ref-4">[4]</a> <a href="#ref-6">[6]</a> <a href="#ref-9">[9]</a></sup> A key whose PBKDF2 output equals the stored digest is the volume key. Keep computes that itself, with its own SHA-1, SHA-2 and HMAC,<sup><a href="#ref-7">[7]</a> <a href="#ref-8">[8]</a></sup> which it tests against the examples of the standards at every start.

A header whose keyslots were erased with `cryptsetup erase` keeps its digest. A key from memory is still proven against it, and is then the only way into the volume. Plain and tcrypt volumes have no digest, so their keys are captured and cannot be proven on scene.

### A header can lie in memory too { #header }

Nothing in the kernel keeps a LUKS header: dm-crypt is given the key and the cipher, and cryptsetup reads the header past the page cache where it can.<sup><a href="#ref-5">[5]</a> <a href="#ref-10">[10]</a></sup> What a machine holds of a header is what else read it. On a guest with Ubuntu 24.04.5, `udisksd` held the whole metadata of an open LUKS2 volume in its memory a minute after the volume was opened.

So the search of a dump looks for a LUKS1 header at the start of a page and for the digests of a LUKS2 header, and proves keys against them. From such a dump alone, with no disk image, Keep proved the volume keys of the open containers. This is seen on one guest and on one machine with Linux Mint 22.3, for a container that was opened by hand, and on four installed guests for the root volume, opened at boot.

On three of those four, minimal installations of Red Hat Enterprise Linux 8.10, 9.9 and 10.3, `udisksd` was not running. There the page cache of the partition held the block of the metadata before any tool had read the partition, and the digests lay in the dump where they lie in that block. What reads the block at boot was not looked at, and how long it stays in the cache of a machine in use is not known.

### The keys first, then the image { #order }

An event can close the window of the keys within seconds. An image of the memory takes longer, 16 s for 16 GiB on one machine and up to 73 s on the machines of the pipeline. So the keys are taken first. A key counts as captured only when it is written to the destination and flushed, because the machine may lose power the moment the verdict is read.

### An image that does not overwrite what it reads { #direct }

A file that is written in the usual way goes through the page cache: the kernel takes free memory for its pages, and what lay there is gone. Free memory is where the remains of earlier work lie, and an image of a large machine is a large file. Keep writes an image with direct writes, from the memory of the program to the device, where the file system of the destination has them, and lets the pages of a flushed file go.<sup><a href="#ref-13">[13]</a></sup> In the runs of the pipeline no page of any image lay in the cache after the run. Of a file that AVML wrote through the cache on a guest with 3.30 GiB of memory, the cache held 2.46 GiB.

The header of a volume goes the same way. cryptsetup reads a header past the page cache, and so does Keep, and the copy of the header is written with direct writes.<sup><a href="#ref-5">[5]</a></sup> A LUKS2 header as cryptsetup makes it has 16 MiB, which a read in the usual way leaves in the cache of the device for as long as the volume is open, and a write in the usual way once more for the copy.

The memory is read as AVML reads it, the ranges that `/proc/iomem` names as RAM through `/proc/kcore`, and the formats are those of LiME and AVML with the framed Snappy stream.<sup><a href="#ref-14">[14]</a> <a href="#ref-15">[15]</a> <a href="#ref-16">[16]</a></sup> AVML itself converts the images of Keep, byte for byte to the files that the formats define. `banners.Banners` of Volatility 3 has read one of its LiME images.<sup><a href="#ref-17">[17]</a></sup>

### One file that starts nothing { #one }

Keep is one program, linked statically against musl.<sup><a href="#ref-19">[19]</a></sup> It starts no other program, loads no library and reads a file of the examined system as text only. The programs of the examined system, which an examiner cannot trust, take no part in the run, and the run adds one process to the memory it is about to image.

Because it asks cryptsetup nothing, it takes none of its locks. On a volume whose re-encryption was paused in a step, `cryptsetup status` waited without end, and Keep read the same volume and proved both of its keys.

## Safeguards { #safeguards }

- No key is printed. On screen and in every report a key is named by its length and the first 16 digits of its SHA-256.
- Volume keys and the lists of schedules, which are key material too, are written only below a `keys/` directory, with `umask 077`.
- Keep writes into the destination directory and nowhere else, and what it asks of the kernel changes nothing there. No name of the examined system is used in a file name as it is.
- The memory of the process is locked, so that no key reaches the swap space, and the process writes no core file.
- A run is not ended by the loss of its screen: it goes on when the reader of a pipe goes away and when its terminal hangs up. A limit of the size of a file that the shell of the examined system had is taken off, so that it does not cut an image.
- A control character in a text of the examined system, as in the name of a mapping, is printed as a space.
- The search of a dump and the lab tools only read the dump and the images they are given.

## Known limits { #limits }

- x86-64 only. The pairing of the XTS halves on scene assumes the layout of the AES-NI family of drivers. With another implementation of XTS the run ends with <span class="open">needs a memory read</span>, and the search of the image tries every pair.
- The search of memory finds AES keys only. A volume with another cipher has no memory route.
- Kernel lockdown in the mode `confidentiality` blocks `/proc/kcore`, and with it the memory route and every image.
- Keep covers dm-crypt only. Mounted file systems that encrypt by themselves (eCryptfs, ZFS, gocryptfs, CryFS, EncFS) are named in the report as not examined.
- A LUKS2 volume with integrity whose key is in the keyring ends with <span class="not">live copy only</span>: its volume key holds the key of HMAC, which is no AES key. With the key in the table it is captured and proven.
- A header whose digest uses ripemd160 or whirlpool is backed up, and its key is proven in the lab by `vkverify.py`, not by Keep.
- The search of a dump reads header backups, raw images and devices. The disk file of a virtual machine and an EnCase image are read by `vkverify.py`.
- A digest that a dump holds and has no key for costs every pair of the keys of the dump: 510 s for 90 keys on one machine. These attempts come last, and their number is said before they begin.
- A header backup of a volume that cryptsetup is re-encrypting shows the moment of the run. The header on the device goes on changing until cryptsetup ends.

## How it is checked { #checks }

Every part of the program that reads bytes it did not write is compared with an independent source, and runs with the address and undefined-behaviour sanitizers of the compiler as well: the hash functions with Python's `hashlib`, the JSON reader with Python's `json`, the header code and the proof with `cryptsetup`, the images with AVML and with files that Python writes from the formats.

```bash
tests/unit-check.sh
```

The whole program is checked on real device-mapper and a real `/proc/kcore`, with volumes made from known keys, on a throwaway guest and never on a machine that matters. The pipeline runs this on every change, on its own two machines and in guests of ten distribution releases. [Systems](systems.md) has a card for each.

```bash
tests/compat-guest.sh -m /path/to/work fedora-45
```

A statement on these pages about a kernel, a cryptsetup release or a distribution comes from the source of that version or from a run, and says which.

## Version 1 and version 2 { #versions }

Keep 1 is a shell script, `keytriage.sh`, on a tool medium with a static bash, busybox, the scanner and AVML. It uses the `dmsetup` and the `cryptsetup` of the examined system. Keep 2 is the one C program of these pages, which does the work of that medium and starts no program.

Version 2.0 is not released. These pages describe `keep` 2.0-pre11. The script is in the repository beside it, and the pipeline runs both on the same volumes: the C program must write the same line of the report for every volume, and header backups and keys that are the same byte for byte.

## The keys of these pages { #keys }

The pages have no scrollbar and no menu. The position stands on the lower line of the frame, and the keys are those of vim.

| Key | What it does |
|---|---|
| `j` `k` | Down and up by a step. |
| `gg` `G` | To the start and to the end of the page. |
| `h` `l` | To the heading before and after. |
| `0` | The home page. |
| `1` to `4` | Installation, usage, systems, about. |
| `t` | The next theme: terminal, system light, system dark, phosphor, nord. |

## References { #references }

1. <span id="ref-1"></span>National Institute of Standards and Technology: [FIPS 197, Advanced Encryption Standard (AES)](https://doi.org/10.6028/NIST.FIPS.197-upd1), 2001, updated 2023. The key expansion is section 5.2, its examples are appendix A.
2. <span id="ref-2"></span>J. A. Halderman, S. D. Schoen, N. Heninger, W. Clarkson, W. Paul, J. A. Calandrino, A. J. Feldman, J. Appelbaum and E. W. Felten: [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/conference/17th-usenix-security-symposium/lest-we-remember-cold-boot-attacks-encryption-keys). 17th USENIX Security Symposium, 2008. Section 6, Identifying Keys in Memory.
3. <span id="ref-3"></span>C. Fruhwirth: [LUKS1 On-Disk Format Specification](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf), version 1.2.3, 2018.
4. <span id="ref-4"></span>The cryptsetup project: [LUKS2-docs](https://gitlab.com/cryptsetup/LUKS2-docs), the documentation of the LUKS2 format.
5. <span id="ref-5"></span>The cryptsetup project: [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup), the sources of the releases 2.0.6, 2.3.7, 2.7.0 and 2.8.1.
6. <span id="ref-6"></span>K. Moriarty, B. Kaliski and A. Rusch: [RFC 8018, PKCS #5: Password-Based Cryptography Specification Version 2.1](https://www.rfc-editor.org/rfc/rfc8018), 2017. PBKDF2 is its section 5.2.
7. <span id="ref-7"></span>H. Krawczyk, M. Bellare and R. Canetti: [RFC 2104, HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104), 1997.
8. <span id="ref-8"></span>National Institute of Standards and Technology: [FIPS 180-4, Secure Hash Standard (SHS)](https://doi.org/10.6028/NIST.FIPS.180-4), 2015.
9. <span id="ref-9"></span>T. Bray: [RFC 8259, The JavaScript Object Notation (JSON) Data Interchange Format](https://www.rfc-editor.org/rfc/rfc8259), 2017.
10. <span id="ref-10"></span>The Linux kernel, read in the releases 4.18, 5.10, 6.12 and 6.18: [`drivers/md/dm-crypt.c`](https://github.com/torvalds/linux/blob/v6.12/drivers/md/dm-crypt.c) and [`drivers/md/dm-ioctl.c`](https://github.com/torvalds/linux/blob/v6.12/drivers/md/dm-ioctl.c).
11. <span id="ref-11"></span>The Linux kernel: [`fs/proc/kcore.c`](https://github.com/torvalds/linux/blob/v6.18/fs/proc/kcore.c), [`kernel/resource.c`](https://github.com/torvalds/linux/blob/v6.18/kernel/resource.c) and [`include/linux/security.h`](https://github.com/torvalds/linux/blob/v6.18/include/linux/security.h).
12. <span id="ref-12"></span>The Linux kernel: [`arch/x86/crypto/aesni-intel_glue.c`](https://github.com/torvalds/linux/blob/v6.12/arch/x86/crypto/aesni-intel_glue.c).
13. <span id="ref-13"></span>The Linux kernel, read in the releases 4.18 and 6.12: [`mm/filemap.c`](https://github.com/torvalds/linux/blob/v6.12/mm/filemap.c), [`fs/libfs.c`](https://github.com/torvalds/linux/blob/v6.12/fs/libfs.c) and the direct writes of the file systems, and [`fs/btrfs/direct-io.c`](https://github.com/torvalds/linux/blob/v6.18/fs/btrfs/direct-io.c) of 6.18.
14. <span id="ref-14"></span>Microsoft: [AVML, Acquire Volatile Memory for Linux](https://github.com/microsoft/avml), release 0.21.0.
15. <span id="ref-15"></span>[LiME, Linux Memory Extractor](https://github.com/504ensicsLabs/LiME), release 1.9.1.
16. <span id="ref-16"></span>Google: [Snappy compressed format description](https://github.com/google/snappy/blob/main/format_description.txt) and [Snappy framing format description](https://github.com/google/snappy/blob/main/framing_format.txt).
17. <span id="ref-17"></span>The Volatility Foundation: [Volatility 3](https://github.com/volatilityfoundation/volatility3).
18. <span id="ref-18"></span>The LVM team: [LVM2](https://gitlab.com/lvmteam/lvm2), release 2.03.22, which holds `dmsetup` and libdevmapper.
19. <span id="ref-19"></span>[musl](https://musl.libc.org/), the C library against which Keep is linked.
20. <span id="ref-20"></span>Ecma International: [ECMA-48, Control Functions for Coded Character Sets](https://ecma-international.org/publications-and-standards/standards/ecma-48/), and [NO_COLOR](https://no-color.org/).
