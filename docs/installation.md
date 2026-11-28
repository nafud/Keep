# Installation

`keep` is one static binary for x86-64 Linux. Download or build it, check it, and carry it on your own medium. Nothing is installed on the examined system.

## Download { #release }

```bash
wget https://github.com/nafud/Keep/releases/download/v2.0/keep
wget https://github.com/nafud/Keep/releases/download/v2.0/keep.sha256
sha256sum -c keep.sha256
chmod +x keep
```

`sha256sum` must answer `keep: OK`. The SHA-256 of `keep` in [release 2.0](https://github.com/nafud/Keep/releases/tag/v2.0) is:

```text
5cc732729ca0b1ca1a68a343231ef112b564bf19fb35005d679a070dc40f9167
```

The checksum file comes from the same place as the binary, so it shows only that the download is whole. To rely on the source alone, build the file.

## Or build it { #build }

```bash
sudo apt install git make musl-tools
git clone --branch v2.0 https://github.com/nafud/Keep.git
cd Keep
make
./keep -V
```

```text
keep 2.0 (2026-11)
```

On Ubuntu 24.04 (gcc 13.3.0, musl 1.2.4) the build gives the released file byte for byte. Other toolchains were not compared. `tests/unit-check.sh` runs the checks of the program: it needs Python 3 and `cryptsetup`, and ends with `RESULT: PASS`.

## On scene { #scene }

Copy `keep` to your medium and note its SHA-256 for the record of the examination:

```bash
sha256sum keep
```

On the examined system, mount the medium without `noexec` and start the file as root:

```bash
sudo /media/tools/keep -d /media/evidence
```

It needs x86-64 Linux and root, and nothing else. [Systems](systems.md) lists where it has run.

Keep writes into the destination only: the directory of `-d`, or the current one. Where that lies is the examiner's decision, and Keep does not test it:

- **Room.** About 16 MiB for each LUKS2 header backup, and for a memory image the size of the machine's memory.
- **The system's own storage.** A file written there changes that storage.
- **An encrypted volume of the system.** A key written into it is locked in with the data at power-off.
- **FAT and exFAT.** They keep no file permissions, so the key files are protected by the medium alone. FAT32 holds no file of 4 GiB or more, so a memory image of that size fails there.
