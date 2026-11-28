# About

An investigator meets a running Linux machine whose encrypted storage is unlocked. Powering it off turns the data back into ciphertext. Keep runs before power-off and decides, for every open dm-crypt volume, one of three things: the volume key can be preserved as evidence and proven correct now, a memory image must be taken first, or only a copy of the mounted files is possible.

Finding the keys is what Keep is for. Two options go with it: Keep can take a memory image of the running system, and it can search a memory dump that exists for the keys and prove them against a disk image.

Keep is not a general artefact collector. It is made to run beside one, such as UAC, and depends on none. It is open-source work for the DFIR community, for lawful examination of systems the examiner is authorised to examine.

## The need { #need }

Full disk encryption keeps an examiner from the data of a machine that is switched off. Casey, Fellows, Geiger and Stellatos wrote in 2011 that shutting a computer down is no acceptable practice where its storage is encrypted, because all of its data may become inaccessible, and that investigators need capabilities on scene to detect and preserve encryption before the plug is pulled.<sup><a href="#ref-1">[1]</a></sup> RFC 3227 gives the same order for evidence in general: from the volatile to the less volatile, and no shutdown before the collection is complete.<sup><a href="#ref-2">[2]</a></sup>

On Linux such storage is a dm-crypt volume, which the installers of Red Hat Enterprise Linux 8.10, 9.9 and 10.3 and of Ubuntu Server 26.04.1, and Tails 7.18 for its Persistent Storage, set up with a LUKS2 header. The passphrase does not encrypt the data. It unlocks the volume key through Argon2, a memory-hard function for password hashing, which is the default of cryptsetup for LUKS2, as Argon2id from release 2.4.0 on.<sup><a href="#ref-3">[3]</a> <a href="#ref-4">[4]</a></sup> While the volume is open the kernel holds the volume key, and with that key the image of the disk is opened in the lab without the passphrase.

So the examiner at the scene has two questions for each open volume, and little time: is its key in hand, and is it the right key?

## Earlier work { #work }

**Keys in a memory image.** Halderman and others showed in 2008 that an AES key can be found in memory without knowing it, by the structure of its key schedule, and found the key of a dm-crypt volume in a memory image in this way.<sup><a href="#ref-5">[5]</a></sup> In the same year Hargreaves and Chivers tried the bytes at every position of a memory dump as the key of an encrypted container, and recovered the keys of TrueCrypt on Windows XP.<sup><a href="#ref-6">[6]</a></sup> Maartmann-Moe, Thorkildsen and Årnes presented Interrogate in 2009, which finds the keys of AES, Serpent and Twofish in a dump.<sup><a href="#ref-7">[7]</a></sup> A commercial tool, Passware Kit, states that it decrypts LUKS2 volumes with a memory image.<sup><a href="#ref-8">[8]</a></sup>

**The key on the running system.** Sandoval described in 2024 how he recovered the key of an open dm-crypt volume whose passphrase was lost: with the debugger drgn he followed the structures of the kernel from the mapped device to the key, on Linux 6.7.<sup><a href="#ref-9">[9]</a></sup>

**Memory images.** Latzo, Palutke and Freiling give a taxonomy and a survey of the ways to acquire memory.<sup><a href="#ref-10">[10]</a></sup> For Linux, LiME is a kernel module that was first presented for Android devices,<sup><a href="#ref-11">[11]</a> <a href="#ref-12">[12]</a></sup> and AVML is a static program that reads the memory through `/proc/kcore`, `/dev/crash` or `/dev/mem`.<sup><a href="#ref-13">[13]</a></sup> Vömel and Freiling defined what makes an image sound: correctness, atomicity and integrity.<sup><a href="#ref-14">[14]</a></sup> Gruhn and Freiling measured twelve tools on Windows 7 by these criteria: the acquisition software that runs in the kernel of the machine it reads showed smear from the activity of that machine.<sup><a href="#ref-15">[15]</a></sup>

What these leave open is the moment at the scene. With the tools of the lab the examiner takes an image and learns later whether it holds the key of the volume. The way through the structures of the kernel needs a debugger and its script on the examined system. This is the work that Keep builds on, and no systematic review.

## What Keep adds { #adds }

- **A verdict for each volume, before power-off.** Every open volume gets one of six [verdicts](usage.md#verdicts), so that the decision to switch off, to take an image first or to copy the mounted files rests on what is in hand.
- **The proof, on scene.** A key counts only when it gives the digest that the LUKS header stores of the volume key. Keep computes that itself, against the header backup it has just written. See [Only a proven key counts](#proof).
- **The key behind a keyring reference.** Keep searches the memory of the running system for key schedules with an exact test, and pairs the two halves of an XTS key by where the kernel keeps them, with no debugger and no kernel module. See [A key in the keyring is still in memory](#memory).
- **The proof from a memory image alone.** An image can hold the digests of a LUKS2 header. From such an image, with no disk at hand, Keep proved the volume key on seven systems. See [A header can lie in memory too](#header).
- **An image that does not write over what it has yet to read.** Keep writes its image past the page cache. See [An image that does not overwrite what it reads](#direct).
- **One file, held against cryptsetup.** Keep is one static program that starts no other. What it writes is compared with what `cryptsetup` and `dmsetup` give on the same volumes, on twelve systems. See [Tested on](#tested).

On Tails 7.18, with Secure Boot on and the kernel in lockdown `integrity`, one run of 21 s took the key of the Persistent Storage, proved it and wrote a memory image of 3.98 GiB. After shutdown, `cryptsetup` on another machine opened the image of the stick with that key and without the passphrase. [Usage](usage.md#keys) shows the screen of that run.

## What it does { #does }

- It lists every open dm-crypt volume of the system: LUKS1 and LUKS2, also LUKS2 with integrity, a volume that cryptsetup is re-encrypting and a volume that carries LVM, and a mapping without a header. For each it says what the volume carries: where it and the devices on it are mounted or used as swap.
- It backs up each LUKS header, byte for byte the file that `cryptsetup luksHeaderBackup` writes.
- It takes each volume key, from the table of the kernel or from memory, and proves it against the header.
- It takes the memory of the machine as a LiME image, a raw image or the compressed format of AVML, with its SHA-256.
- It searches a memory dump that exists for keys and proves them against the headers in disk images, or against what the dump itself holds of a header.
- It writes what it found for a reader, `triage.txt`, and for a program, `verdict.json`, with the SHA-256 of every file of the run. A terminal gets the screen in colour, by the SGR sequences for bold and the eight colours alone, and a pipe gets plain lines.<sup><a href="#ref-16">[16]</a></sup>

## The ideas behind it { #ideas }

### The kernel hands out the key { #table }

The kernel hands the table of a mapped device to every caller with `CAP_SYS_ADMIN`, the key of a crypt target in hexadecimal included. No flag asks for the key and kernel lockdown does not withhold it. It is `dmsetup` that shows zeros in its place unless it is asked.<sup><a href="#ref-17">[17]</a> <a href="#ref-18">[18]</a></sup> Keep makes the two requests of `dmsetup` itself, which change nothing in the kernel.

For LUKS1, plain and tcrypt volumes, and for LUKS2 opened with `--disable-keyring`, the table holds the key. This is the first route, and it needs nothing but root.

### A key in the keyring is still in memory { #memory }

By default cryptsetup gives the key of a LUKS2 volume to the kernel keyring, and the table shows a reference to it. The cipher still needs the key for every block. AES expands a key into round keys,<sup><a href="#ref-19">[19]</a></sup> and the kernel holds that expanded schedule as long as the volume is open. Its first 16 or 32 bytes are the key.

A schedule can be found without knowing the key, because each of its words follows from earlier ones by the rule of the expansion. The search of Halderman and others allows for bits that have decayed.<sup><a href="#ref-5">[5]</a></sup> Keep reads the memory of a running machine, where no bit has decayed, so its test is exact: every position is tested over the whole schedule, 176 bytes for AES-128 and 240 bytes for AES-256. A hit is a real schedule, though not necessarily one of a disk volume.

With `aes-xts` the volume key is two AES keys, the data key and the tweak key. On x86-64 with the AES-NI family of drivers the kernel keeps both schedules in one structure, the tweak schedule first and the data schedule 496 bytes after it.<sup><a href="#ref-20">[20]</a></sup> Keep pairs the schedules by that distance, and in the search of a dump it tries every other pair after those.

The memory is read through `/proc/kcore`, which needs root and is refused under kernel lockdown in the mode `confidentiality`.<sup><a href="#ref-21">[21]</a></sup>

### Only a proven key counts { #proof }

Nothing is reported as a volume key on the strength of where it was found. A LUKS header stores a PBKDF2 digest of the volume key: LUKS1 in its binary header, LUKS2 in the object `digests` of its metadata, which are JSON.<sup><a href="#ref-22">[22]</a> <a href="#ref-23">[23]</a> <a href="#ref-24">[24]</a> <a href="#ref-25">[25]</a></sup> A key whose PBKDF2 output equals the stored digest is the volume key. Keep computes that itself, with its own SHA-1, SHA-2 and HMAC,<sup><a href="#ref-26">[26]</a> <a href="#ref-27">[27]</a></sup> which it tests against the examples of the standards at every start.

A header whose keyslots were erased with `cryptsetup erase` keeps its digest. A key from memory is still proven against it, and is then the only way into the volume. Plain and tcrypt volumes have no digest, so their keys are captured and cannot be proven on scene.

### A header can lie in memory too { #header }

Nothing in the kernel keeps a LUKS header: dm-crypt is given the key and the cipher, and cryptsetup reads the header past the page cache where it can.<sup><a href="#ref-4">[4]</a> <a href="#ref-17">[17]</a></sup> What a machine holds of a header is what else read it. On a guest with Ubuntu 24.04.5, `udisksd` held the whole metadata of an open LUKS2 volume in its memory a minute after the volume was opened.

So the search of a dump looks for a LUKS1 header at the start of a page and for the digests of a LUKS2 header, and proves keys against them. From such a dump alone, with no disk image, Keep proved the volume keys of the open containers. This is seen on one guest and on one machine with Linux Mint 22.3, for a container that was opened by hand, on four installed guests for the root volume, opened at boot, and on Tails 7.18 for its Persistent Storage.

On three of those four, minimal installations of Red Hat Enterprise Linux 8.10, 9.9 and 10.3, `udisksd` was not running. There the page cache of the partition held the block of the metadata before any tool had read the partition, and the digests lay in the dump where they lie in that block. What reads the block at boot was not looked at, and how long it stays in the cache of a machine in use is not known.

### The keys first, then the image { #order }

An event can close the window of the keys within seconds. An image of the memory takes longer, 16 s for 16 GiB on one machine and up to 112 s on the machines of the pipeline. So the keys are taken first. A key counts as captured only when it is written to the destination and flushed, because the machine may lose power the moment the verdict is read.

An image that is read on the running machine is also not atomic, because the machine goes on working while it is read.<sup><a href="#ref-14">[14]</a> <a href="#ref-15">[15]</a></sup> A key that is proven on scene does not rest on the image.

### An image that does not overwrite what it reads { #direct }

A file that is written in the usual way goes through the page cache: the kernel takes free memory for its pages, and what lay there is gone. Free memory is where the remains of earlier work lie, and an image of a large machine is a large file. Keep writes an image with direct writes, from the memory of the program to the device, where the file system of the destination has them, and lets the pages of a flushed file go.<sup><a href="#ref-28">[28]</a></sup> In the runs of the pipeline no page of any image lay in the cache after the run. Of a file that AVML wrote through the cache on a guest with 3.30 GiB of memory, the cache held 2.46 GiB.

The header of a volume goes the same way. cryptsetup reads a header past the page cache, and so does Keep, and the copy of the header is written with direct writes.<sup><a href="#ref-4">[4]</a></sup> A LUKS2 header as cryptsetup makes it has 16 MiB, which a read in the usual way leaves in the cache of the device for as long as the volume is open, and a write in the usual way once more for the copy.

The memory is read as AVML reads it, the ranges that `/proc/iomem` names as RAM through `/proc/kcore`, and the formats are those of LiME and AVML with the framed Snappy stream.<sup><a href="#ref-13">[13]</a> <a href="#ref-11">[11]</a> <a href="#ref-29">[29]</a></sup> AVML itself converts the images of Keep, byte for byte to the files that the formats define. `banners.Banners` of Volatility 3 has read one of its LiME images.<sup><a href="#ref-30">[30]</a></sup>

### One file that starts nothing { #one }

Keep is one program, linked statically against musl.<sup><a href="#ref-31">[31]</a></sup> It starts no other program, loads no library and reads a file of the examined system as text only. The programs of the examined system, which an examiner cannot trust, take no part in the run, and the run adds one process to the memory it is about to image.

Because it asks cryptsetup nothing, it takes none of its locks. On a volume whose re-encryption was paused in a step, `cryptsetup status` waited without end, and Keep read the same volume and proved both of its keys.

## Safeguards { #safeguards }

- No key is printed. On screen and in every report a key is named by its length and the first 16 digits of its SHA-256.
- Volume keys and the lists of schedules, which are key material too, are written only below a `keys/` directory, with `umask 077`.
- Keep writes into the destination directory and nowhere else, and what it asks of the kernel changes nothing there. No name of the examined system is used in a file name as it is.
- The memory of the process is locked, so that no key reaches the swap space, and the process writes no core file.
- A run is not ended by the loss of its screen: it goes on when the reader of a pipe goes away and when its terminal hangs up. A limit of the size of a file that the shell of the examined system had is taken off, so that it does not cut an image.
- An interrupt from the keyboard ends the long steps of a run and not the run: the keys that cost no time are still taken, and the report and the manifest are written.
- A control character in a text of the examined system, as in the name of a mapping, is printed as a space.
- The search of a dump and the lab tools only read the dump and the images they are given.

## Known limits { #limits }

- Keep needs root: the table of a volume and `/proc/kcore` are for root alone. On Tails root exists only where an administration password was set at the Welcome Screen. Without root only a copy of the mounted files remains.
- x86-64 only. The pairing of the XTS halves on scene assumes the layout of the AES-NI family of drivers. With another implementation of XTS the run ends with <span class="open">needs a memory read</span>, and the search of the image tries every pair.
- The search of memory finds AES keys only. A volume with another cipher has no memory route.
- Kernel lockdown in the mode `confidentiality` blocks `/proc/kcore`, and with it the memory route and every image.
- A tcrypt volume (TrueCrypt, VeraCrypt) and a plain volume as cryptsetup opens it are not verified: no check runs one. The checks make a mapping without a header from a table line, with `dmsetup`.
- A memory image is read on the running machine and is not atomic.<sup><a href="#ref-14">[14]</a></sup>
- Keep covers dm-crypt only. Mounted file systems that encrypt by themselves (eCryptfs, ZFS, gocryptfs, CryFS, EncFS) are named in the report as not examined.
- A LUKS2 volume with integrity whose key is in the keyring ends with <span class="not">live copy only</span>: its volume key holds the key of HMAC, which is no AES key. With the key in the table it is captured and proven.
- A header whose digest uses ripemd160 or whirlpool is backed up, and its key is proven in the lab by `vkverify.py`, not by Keep.
- The search of a dump reads header backups, raw images and devices. The disk file of a virtual machine and an EnCase image are read by `vkverify.py`.
- A digest that a dump holds and has no key for costs every pair of the keys of the dump: 510 s for 90 keys on one machine. These attempts come last, and their number is said before they begin.
- A digest of a header is computed up to 16777216 iterations. cryptsetup makes a digest to cost 125 ms, which is some hundred thousand, and a header can state up to 4294967295, with which one attempt takes from 21 minutes to more than an hour.<sup><a href="#ref-4">[4]</a></sup> A digest beyond the bound is named as one that is not computed here, and the key and the list of the schedules are kept for the lab.
- A header backup of a volume that cryptsetup is re-encrypting shows the moment of the run. The header on the device goes on changing until cryptsetup ends.

## How it is checked { #checks }

Every part of the program that reads bytes it did not write is compared with an independent source, and runs with the address and undefined-behaviour sanitizers of the compiler as well: the hash functions with Python's `hashlib`, the JSON reader with Python's `json`, the header code and the proof with `cryptsetup`, the images with AVML and with files that Python writes from the formats.

```bash
tests/unit-check.sh
```

The whole program is checked on real device-mapper and a real `/proc/kcore`, with volumes made from known keys, on a throwaway guest and never on a machine that matters. What it writes is held against the tools of that system: the volumes and their tables against `dmsetup`, the type, the key size and the device of a volume against `cryptsetup status`, a header backup against the file of `cryptsetup luksHeaderBackup`, a key against the key the volume was made from and against `cryptsetup open --test-passphrase`, and a memory image against the image that AVML takes of the same machine. The pipeline runs this on its own two machines on every change, and in guests of ten distribution releases whenever the program or its checks change.

```bash
tests/compat-guest.sh -m /path/to/work fedora-45
```

A statement on these pages about a kernel, a cryptsetup release or a distribution comes from the source of that version or from a run, and says which.

## Tested on { #tested }

Keep was run on these x86-64 systems, on kernels from 4.18 to 7.3.

**By the check.** The pipeline runs `tests/compat-check.sh` with 2.0 in a guest booted from the cloud image of each distribution, and on its own two runners: volumes made from known keys, every result held against `cryptsetup` and `dmsetup`, with memory images. On openSUSE Leap 16.1 the part with LUKS2 integrity was not run.

<table>
<colgroup><col style="width: 38%"><col style="width: 42%"><col style="width: 20%"></colgroup>
<thead><tr><th>System</th><th>Kernel</th><th>cryptsetup</th></tr></thead>
<tbody>
<tr><td>Debian 13</td><td>6.12.117+deb13-amd64</td><td>2.7.5</td></tr>
<tr><td>Debian 12</td><td>6.1.0-56-amd64</td><td>2.6.1</td></tr>
<tr><td>Ubuntu 26.04.1</td><td>7.0.0-43-generic</td><td>2.8.4</td></tr>
<tr><td>Ubuntu 24.04.5</td><td>6.8.0-147-generic</td><td>2.7.0</td></tr>
<tr><td>Fedora 45</td><td>7.2.11-300.fc45.x86_64</td><td>2.8.9</td></tr>
<tr><td>AlmaLinux 10.3</td><td>6.12.0-264.16.1.el10_3.x86_64</td><td>2.8.6</td></tr>
<tr><td>AlmaLinux 9.9</td><td>5.14.0-741.22.1.el9_9.x86_64</td><td>2.8.6</td></tr>
<tr><td>Rocky Linux 10.3</td><td>6.12.0-264.16.1.el10_3.x86_64</td><td>2.8.6</td></tr>
<tr><td>openSUSE Leap 16.1</td><td>6.12.0-160100.9-default</td><td>2.8.4</td></tr>
<tr><td>Arch Linux</td><td>7.3.4-arch1-2</td><td>2.8.9</td></tr>
<tr><td>Ubuntu 24.04.5, runner</td><td>7.0.0-1020-azure</td><td>2.7.0</td></tr>
<tr><td>Ubuntu 22.04.5, runner</td><td>6.8.0-1070-azure</td><td>2.4.3</td></tr>
</tbody>
</table>

**By hand.** Systems with Secure Boot on and kernel lockdown `integrity`. On each, a LUKS2 volume with its key in the kernel keyring got <span class="reached">captured and proven</span>, a memory image was taken, and the key was proven once more from a memory image alone. These runs were made with 2.0 on Tails and with pre-releases of 2.0 on the others.

<table>
<colgroup><col style="width: 38%"><col style="width: 42%"><col style="width: 20%"></colgroup>
<thead><tr><th>System</th><th>Kernel</th><th>cryptsetup</th></tr></thead>
<tbody>
<tr><td>Red Hat Enterprise Linux 8.10</td><td>4.18.0-553.el8_10.x86_64</td><td>2.3.7</td></tr>
<tr><td>Red Hat Enterprise Linux 9.9</td><td>5.14.0-741.20.1.el9_9.x86_64</td><td>2.8.6</td></tr>
<tr><td>Red Hat Enterprise Linux 10.3</td><td>6.12.0-264.14.1.el10_3.x86_64</td><td>2.8.6</td></tr>
<tr><td>Ubuntu Server 26.04.1</td><td>7.0.0-44-generic</td><td>2.8.4</td></tr>
<tr><td>Linux Mint 22.3</td><td>6.14.0-37-generic</td><td>not noted</td></tr>
<tr><td>Tails 7.18</td><td>6.12.118+deb13-amd64</td><td>2.7.5</td></tr>
</tbody>
</table>

The runs met four XTS drivers of the kernel, and the two halves of the key lay 496 bytes apart with each: `xts-aes-aesni`, `xts-aes-vaes-avx2`, `xts-aes-vaes-avx512` and `xts-aes-vaes-avx10_512`.

## Version 1 and version 2 { #versions }

Keep 1 was a shell script, `keytriage.sh`, on a tool medium with a static bash, busybox, the scanner and AVML. It used the `dmsetup` and the `cryptsetup` of the examined system. Keep 2 is the one C program of these pages, which does the work of that medium and starts no program.

While the C program was written, the pipeline ran both on the same volumes, on its two machines and in the ten guests: the C program wrote the same line of the report for every volume, and header backups and keys that were the same byte for byte. With that shown, the script and its medium were taken out of the repository, where its history keeps them, and the program is now held against `cryptsetup` and `dmsetup` themselves.

These pages describe `keep` 2.0. [Installation](installation.md#release) says where the file of that release is.

## Licence { #licence }

Keep is released under the [MIT licence](https://github.com/nafud/Keep/blob/main/LICENSE). The released file holds code of musl, which is under the MIT licence as well, and a release carries its copyright notices as `musl-copyright.txt`.<sup><a href="#ref-31">[31]</a></sup>

## The keys of these pages { #keys }

The pages have no scrollbar and no menu. The position stands on the lower line of the frame, and the keys are those of vim.

| Key | What it does |
|---|---|
| `j` `k` | Down and up by a step. |
| `gg` `G` | To the start and to the end of the page. |
| `h` `l` | To the heading before and after. |
| `0` | The home page. |
| `1` to `3` | Installation, usage, about. |
| `t` | The next theme: terminal, system light, system dark, phosphor, nord. |

## References { #references }

1. <span id="ref-1"></span>E. Casey, G. Fellows, M. Geiger and G. Stellatos: [The growing impact of full disk encryption on digital forensics](https://doi.org/10.1016/j.diin.2011.09.005). Digital Investigation 8(2), 2011, pages 129 to 134.
2. <span id="ref-2"></span>D. Brezinski and T. Killalea: [RFC 3227, Guidelines for Evidence Collection and Archiving](https://www.rfc-editor.org/rfc/rfc3227), BCP 55, 2002. The order of volatility is its section 2.1.
3. <span id="ref-3"></span>A. Biryukov, D. Dinu, D. Khovratovich and S. Josefsson: [RFC 9106, Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications](https://www.rfc-editor.org/rfc/rfc9106), 2021.
4. <span id="ref-4"></span>The cryptsetup project: [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup), the sources of the releases 2.0.6, 2.3.7, 2.7.0 and 2.8.1, and the release notes of 2.4.0.
5. <span id="ref-5"></span>J. A. Halderman, S. D. Schoen, N. Heninger, W. Clarkson, W. Paul, J. A. Calandrino, A. J. Feldman, J. Appelbaum and E. W. Felten: [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/conference/17th-usenix-security-symposium/lest-we-remember-cold-boot-attacks-encryption-keys). 17th USENIX Security Symposium, 2008. Section 6, Identifying Keys in Memory, and section 7, Attacking Encrypted Disks.
6. <span id="ref-6"></span>C. Hargreaves and H. Chivers: [Recovery of Encryption Keys from Memory Using a Linear Scan](https://doi.org/10.1109/ARES.2008.109). Third International Conference on Availability, Reliability and Security (ARES), IEEE, 2008, pages 1369 to 1376.
7. <span id="ref-7"></span>C. Maartmann-Moe, S. E. Thorkildsen and A. Årnes: [The persistence of memory: Forensic identification and extraction of cryptographic keys](https://doi.org/10.1016/j.diin.2009.06.002). Digital Investigation 6, supplement, 2009, pages S132 to S140. Proceedings of DFRWS 2009.
8. <span id="ref-8"></span>Passware: [What's new in Passware Kit 2022 v1](https://support.passware.com/hc/en-us/articles/4415995073431-What-s-new-in-Passware-Kit-2022-v1). The release notes of a commercial tool.
9. <span id="ref-9"></span>O. Sandoval: [Recovering a dm-crypt Encryption Key](https://drgn.readthedocs.io/en/latest/case_studies/dm_crypt_key.html). A case study in the documentation of the debugger drgn, 2024.
10. <span id="ref-10"></span>T. Latzo, R. Palutke and F. Freiling: [A universal taxonomy and survey of forensic memory acquisition techniques](https://doi.org/10.1016/j.diin.2019.01.001). Digital Investigation 28, 2019, pages 56 to 69.
11. <span id="ref-11"></span>[LiME, Linux Memory Extractor](https://github.com/504ensicsLabs/LiME), release 1.9.1.
12. <span id="ref-12"></span>J. Sylve, A. Case, L. Marziale and G. G. Richard: [Acquisition and analysis of volatile memory from android devices](https://doi.org/10.1016/j.diin.2011.10.003). Digital Investigation 8(3-4), 2012, pages 175 to 184.
13. <span id="ref-13"></span>Microsoft: [AVML, Acquire Volatile Memory for Linux](https://github.com/microsoft/avml), release 0.21.0.
14. <span id="ref-14"></span>S. Vömel and F. C. Freiling: [Correctness, atomicity, and integrity: Defining criteria for forensically-sound memory acquisition](https://doi.org/10.1016/j.diin.2012.04.005). Digital Investigation 9(2), 2012, pages 125 to 137.
15. <span id="ref-15"></span>M. Gruhn and F. C. Freiling: [Evaluating atomicity, and integrity of correct memory acquisition methods](https://doi.org/10.1016/j.diin.2016.01.003). Digital Investigation 16, supplement, 2016, pages S1 to S10. Proceedings of DFRWS EU 2016.
16. <span id="ref-16"></span>Ecma International: [ECMA-48, Control Functions for Coded Character Sets](https://ecma-international.org/publications-and-standards/standards/ecma-48/), and [NO_COLOR](https://no-color.org/).
17. <span id="ref-17"></span>The Linux kernel, read in the releases 4.18, 5.10, 6.12 and 6.18: [`drivers/md/dm-crypt.c`](https://github.com/torvalds/linux/blob/v6.12/drivers/md/dm-crypt.c) and [`drivers/md/dm-ioctl.c`](https://github.com/torvalds/linux/blob/v6.12/drivers/md/dm-ioctl.c).
18. <span id="ref-18"></span>The LVM team: [LVM2](https://gitlab.com/lvmteam/lvm2), release 2.03.22, which holds `dmsetup` and libdevmapper.
19. <span id="ref-19"></span>National Institute of Standards and Technology: [FIPS 197, Advanced Encryption Standard (AES)](https://doi.org/10.6028/NIST.FIPS.197-upd1), 2001, updated 2023. The key expansion is section 5.2, its examples are appendix A.
20. <span id="ref-20"></span>The Linux kernel: [`arch/x86/crypto/aesni-intel_glue.c`](https://github.com/torvalds/linux/blob/v6.12/arch/x86/crypto/aesni-intel_glue.c).
21. <span id="ref-21"></span>The Linux kernel: [`fs/proc/kcore.c`](https://github.com/torvalds/linux/blob/v6.18/fs/proc/kcore.c), [`kernel/resource.c`](https://github.com/torvalds/linux/blob/v6.18/kernel/resource.c) and [`include/linux/security.h`](https://github.com/torvalds/linux/blob/v6.18/include/linux/security.h).
22. <span id="ref-22"></span>C. Fruhwirth: [LUKS1 On-Disk Format Specification](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf), version 1.2.3, 2018.
23. <span id="ref-23"></span>The cryptsetup project: [LUKS2-docs](https://gitlab.com/cryptsetup/LUKS2-docs), the documentation of the LUKS2 format.
24. <span id="ref-24"></span>K. Moriarty, B. Kaliski and A. Rusch: [RFC 8018, PKCS #5: Password-Based Cryptography Specification Version 2.1](https://www.rfc-editor.org/rfc/rfc8018), 2017. PBKDF2 is its section 5.2.
25. <span id="ref-25"></span>T. Bray: [RFC 8259, The JavaScript Object Notation (JSON) Data Interchange Format](https://www.rfc-editor.org/rfc/rfc8259), 2017.
26. <span id="ref-26"></span>H. Krawczyk, M. Bellare and R. Canetti: [RFC 2104, HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104), 1997.
27. <span id="ref-27"></span>National Institute of Standards and Technology: [FIPS 180-4, Secure Hash Standard (SHS)](https://doi.org/10.6028/NIST.FIPS.180-4), 2015.
28. <span id="ref-28"></span>The Linux kernel, read in the releases 4.18 and 6.12: [`mm/filemap.c`](https://github.com/torvalds/linux/blob/v6.12/mm/filemap.c), [`fs/libfs.c`](https://github.com/torvalds/linux/blob/v6.12/fs/libfs.c) and the direct writes of the file systems, and [`fs/btrfs/direct-io.c`](https://github.com/torvalds/linux/blob/v6.18/fs/btrfs/direct-io.c) of 6.18.
29. <span id="ref-29"></span>Google: [Snappy compressed format description](https://github.com/google/snappy/blob/main/format_description.txt) and [Snappy framing format description](https://github.com/google/snappy/blob/main/framing_format.txt).
30. <span id="ref-30"></span>The Volatility Foundation: [Volatility 3](https://github.com/volatilityfoundation/volatility3).
31. <span id="ref-31"></span>[musl](https://musl.libc.org/), the C library against which Keep is linked, under the MIT licence.
