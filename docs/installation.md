# Installation

## Download { #release }

```bash
wget https://github.com/nafud/Keep/releases/download/v2.0/keep
wget https://github.com/nafud/Keep/releases/download/v2.0/keep.sha256
sha256sum -c keep.sha256
chmod +x keep
```

`sha256sum` must answer `keep: OK`. The SHA-256 of `keep` in [release 2.0](https://github.com/nafud/Keep/releases/tag/v2.0) is shown below.

```text
5cc732729ca0b1ca1a68a343231ef112b564bf19fb35005d679a070dc40f9167
```

The checksum file comes from the same place as the binary, so it only shows that the download is complete. To rely on the source alone, build the file yourself.

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

On Ubuntu 24.04 with gcc 13.3.0 and musl 1.2.4, the build produces the released file byte for byte. Other toolchains were not compared. The checks of the program are run by `tests/unit-check.sh`, which needs Python 3 and `cryptsetup` and ends with `RESULT: PASS`.

## On scene { #scene }

Copy `keep` to your own medium and note its SHA-256 for the examination record.

```bash
sha256sum keep
```

On the examined system, mount the medium without `noexec` and start the file as root.

```bash
sudo /media/tools/keep -d /media/evidence
```

Keep needs x86-64 Linux and root, and nothing else. [About](about.md#tested) lists the systems it was tested on.

Keep writes only into the destination, which is the directory given with `-d` or otherwise the current directory. The examiner chooses that place and Keep does not test it, so four points are worth weighing beforehand.

- **Room.** Each LUKS2 header backup takes about 16 MiB, and a memory image takes as much room as the machine has memory.
- **The system's own storage.** A file written there changes that storage.
- **An encrypted volume of the system.** A key written into it is locked in with the data at power-off.
- **FAT and exFAT.** These keep no file permissions, so only the medium itself protects the key files. FAT32 also holds no file of 4 GiB or more, so a memory image of that size fails there.
