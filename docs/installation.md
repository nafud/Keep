# Installation

Keep is one file, `keep`. It is linked statically, so it needs no library and no program of the system it runs on, and it is not installed there. It is taken from the release or built once on a workstation, copied to the medium that goes to the scene, and started from that medium.

## What it needs { #requirements }

| Where | What |
|---|---|
| Workstation | For the released file, nothing but a way to fetch it. For a build, Ubuntu or Linux Mint with `git`, `make` and `musl-tools`, the package of `musl-gcc`. The build runs in the pipeline on Ubuntu 24.04 and 22.04 and was made by hand on Linux Mint 22.3. Debian has the same package. A build there, or on another distribution with `make` and `musl-gcc`, is not checked. |
| Examined system | Linux on x86-64, and root. Nothing is installed and no package is needed. The [systems](systems.md) on which the file was run are listed with their kernels. |
| Destination | A directory that exists and can be written, with room for what the run is to keep: some megabytes for the keys and the header backups, and for a memory image about the size of the memory of the machine. |

## The released file { #release }

[Release 2.0](https://github.com/nafud/Keep/releases/tag/v2.0) has three files:

| File | What it is |
|---|---|
| `keep` | The program. |
| `keep.sha256` | Its SHA-256, as `sha256sum -c` reads it. |
| `musl-copyright.txt` | The copyright notices of musl, the C library that is linked into the program. They go with the file where it is passed on. |

```bash
wget https://github.com/nafud/Keep/releases/download/v2.0/keep
```

```bash
wget https://github.com/nafud/Keep/releases/download/v2.0/keep.sha256
```

```bash
sha256sum -c keep.sha256
```

```text
keep: OK
```

```bash
chmod +x keep
```

The pipeline builds the file from the commit that the tag `v2.0` names, and publishes it only where the checks of that commit have passed and the file is, byte for byte, the one that those checks had built in a run of their own. The SHA-256 beside the file says that the download is whole. It comes from the same place as the file, so it says no more than that: who wants to rely on the source alone builds the file.

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
keep 2.0 (2026-11)
```

The build gives one file for one compiler and one musl: the pipeline and a second machine, each with gcc 13.3.0 and musl 1.2.4 of Ubuntu 24.04, built the same file byte for byte from one commit. A build with another compiler or another musl was not compared with it.

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
