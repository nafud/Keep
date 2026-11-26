# Installation

Keep is one file, `keep`. It is linked statically, so it needs no library and no program of the system it runs on, and it is not installed there. It is built once on a workstation, copied to the medium that goes to the scene, and started from that medium.

## What it needs { #requirements }

| Where | What |
|---|---|
| Workstation | Ubuntu or Linux Mint with `git`, `make` and `musl-tools`, the package of `musl-gcc`. The build runs in the pipeline on Ubuntu 24.04 and 22.04 and was made by hand on Linux Mint 22.3. Debian has the same package. A build there, or on another distribution with `make` and `musl-gcc`, is not checked. |
| Examined system | Linux on x86-64, and root. Nothing is installed and no package is needed. The [systems](systems.md) on which the file was run are listed with their kernels. |
| Destination | A directory that exists and can be written, with room for what the run is to keep: some megabytes for the keys and the header backups, and for a memory image about the size of the memory of the machine. |

## Build { #build }

```bash
sudo apt install git make musl-tools
```

```bash
git clone https://github.com/nafud/Keep.git
```

```bash
cd Keep
```

```bash
make
```

`make` writes `keep`, a file of about 300 kB, and `tests/keep-unit`, which runs the parts of the program one at a time for its checks. The build is C11 against musl with the warnings as errors, and it downloads nothing.

```bash
./keep -V
```

```text
keep 2.0-rc1 (2026-11)
```

This is the release candidate of 2.0. A built file is not published yet, so the file is built from the source.

## Check the build { #check }

The checks of the program are part of the repository. One script builds its parts a second time with the address and undefined-behaviour sanitizers of the compiler and compares each with an independent source: the hash functions with Python's `hashlib`, the reader of LUKS headers and the proof of a key with `cryptsetup`, the memory image with files that Python writes from the definitions of the formats. It needs Python 3, `cryptsetup` and a C compiler, takes some minutes and ends with `RESULT: PASS`.

```bash
tests/unit-check.sh
```

## Take it to the scene { #scene }

The file is copied to the medium that the examiner carries, and its SHA-256 is noted, so that the notes of the examination name the program that ran.

```bash
sha256sum keep
```

On the examined system the medium is mounted and the file is started from it as root. The medium must be mounted so that a program on it can be started, which the mount option `noexec` forbids.

```bash
sudo /media/tools/keep -d /media/evidence
```

Keep writes into the destination, the directory of `-d` or the current one, and nowhere else. Where the destination lies is the examiner's decision, and Keep does not test it. What follows from the choice is the examiner's to weigh:

- A file written to the storage of the examined system changes that storage.
- A key written into one of its encrypted volumes is locked in with the data at power-off.
- FAT and exFAT keep no file modes, so on such a medium the key files are protected by the medium alone. FAT32 takes no file of 4 GiB, so a memory image of a machine with that much memory fails there.

## The lab tool { #lab }

The same clone holds the tool of the lab that is written in Python: `vkverify.py`, which proves keys against LUKS headers in the disk files of virtual machines and in EnCase images. It needs Python 3 with its standard library, takes the list of key schedules that a run of Keep wrote, and only reads its inputs. [Usage](usage.md#lab) says when it is needed.
