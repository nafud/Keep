# Systems

Keep is one static file, so it is the same file on every distribution, and so are its commands. What differs from system to system is the kernel, and what the system keeps for the lab. Each system on which Keep was run has a card here with what that run showed.

A card names the kernel and the cryptsetup of the latest run it stands for, and whether the system has a `System.map` that Keep keeps beside a memory image, for the symbol table of Volatility 3. The XTS driver is the implementation of `xts(aes)` that the kernel chose in that run. It follows the processor of the machine and not the distribution, so it differs between runs on the same system.

## Checked in the pipeline { #pipeline }

The pipeline on GitHub boots each of these ten systems as a guest from the distribution's own cloud image, pinned by its published checksum, and runs `tests/compat-check.sh` in it with `keep` 2.0-pre9. The check makes volumes from keys it has just drawn: LUKS2 with the key in the kernel keyring, LUKS1 with the key in the table, a mapping without a type, one with the null cipher, LVM on LUKS, LUKS2 with integrity and a volume in re-encryption. Keep must give the right verdict for each and keys that are the known ones byte for byte. It then takes the memory of the guest in each format, and the search of that image must prove both volume keys again.

The guests have 2 GiB of memory and boot with BIOS under KVM, so kernel lockdown is `none` on all of them.

<div class="home-grid">
<div class="system-card">
<span class="system-card-title">Debian 13</span>
<dl>
<dt>kernel</dt><dd>6.12.117+deb13-amd64</dd>
<dt>cryptsetup</dt><dd>2.7.5</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx10_512</code></dd>
<dt>symbols</dt><dd>none: a placeholder in <code>/boot</code></dd>
</dl>
</div>
<div class="system-card">
<span class="system-card-title">Debian 12</span>
<dl>
<dt>kernel</dt><dd>6.1.0-56-amd64</dd>
<dt>cryptsetup</dt><dd>2.6.1</dd>
<dt>xts driver</dt><dd><code>xts-aes-aesni</code></dd>
<dt>symbols</dt><dd>none: a placeholder in <code>/boot</code></dd>
</dl>
</div>
<div class="system-card">
<span class="system-card-title">Ubuntu 26.04.1</span>
<dl>
<dt>kernel</dt><dd>7.0.0-43-generic</dd>
<dt>cryptsetup</dt><dd>2.8.4</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx512</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
</div>
<div class="system-card">
<span class="system-card-title">Ubuntu 24.04.5</span>
<dl>
<dt>kernel</dt><dd>6.8.0-147-generic</dd>
<dt>cryptsetup</dt><dd>2.7.0</dd>
<dt>xts driver</dt><dd><code>xts-aes-aesni</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
</div>
<div class="system-card">
<span class="system-card-title">Fedora 45</span>
<dl>
<dt>kernel</dt><dd>7.2.11-300.fc45.x86_64</dd>
<dt>cryptsetup</dt><dd>2.8.8</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx512</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
<p>The root file system is btrfs, which takes the direct writes of an image through the page cache from Linux 6.18 on. The pages are let go when the file is flushed: none lay in the cache after the run.</p>
</div>
<div class="system-card">
<span class="system-card-title">AlmaLinux 10.3</span>
<dl>
<dt>kernel</dt><dd>6.12.0-264.16.1.el10_3.x86_64</dd>
<dt>cryptsetup</dt><dd>2.8.6</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx10_512</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
</div>
<div class="system-card">
<span class="system-card-title">AlmaLinux 9.9</span>
<dl>
<dt>kernel</dt><dd>5.14.0-741.22.1.el9_9.x86_64</dd>
<dt>cryptsetup</dt><dd>2.8.6</dd>
<dt>xts driver</dt><dd><code>xts-aes-aesni</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
<p>The oldest kernel that the check runs on.</p>
</div>
<div class="system-card">
<span class="system-card-title">Rocky Linux 10.3</span>
<dl>
<dt>kernel</dt><dd>6.12.0-264.16.1.el10_3.x86_64</dd>
<dt>cryptsetup</dt><dd>2.8.6</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx10_512</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
</div>
<div class="system-card">
<span class="system-card-title">openSUSE Leap 16.1</span>
<dl>
<dt>kernel</dt><dd>6.12.0-160100.9-default</dd>
<dt>cryptsetup</dt><dd>2.8.4</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx2</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
<p>Without the part with integrity: cryptsetup could not make the LUKS2 container with integrity there, because the kernel refused its table. LUKS2 with integrity is not checked on this system.</p>
</div>
<div class="system-card">
<span class="system-card-title">Arch Linux</span>
<dl>
<dt>kernel</dt><dd>7.3.4-arch1-2</dd>
<dt>cryptsetup</dt><dd>2.8.9</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx2</code></dd>
<dt>symbols</dt><dd>none: no System.map there</dd>
</dl>
<p>The cloud image of 2026-11-15.</p>
</div>
</div>

## The machines of the pipeline { #runners }

The same check runs on the two runner images of the pipeline itself, on every change. These machines have 16 GiB of memory, which makes their images the largest that the check takes. The machine behind a runner image differs from run to run, and with it the kernel.

<div class="home-grid">
<div class="system-card">
<span class="system-card-title">Ubuntu 24.04.5, runner image</span>
<dl>
<dt>kernel</dt><dd>7.0.0-1014-aws</dd>
<dt>cryptsetup</dt><dd>2.7.0</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx512</code></dd>
<dt>memory</dt><dd>16 GiB</dd>
</dl>
<p>The raw image, 17951621120 bytes, was read in 73 s and the compressed one, 10117846686 bytes, in 50 s. The build with the sanitizers runs here too.</p>
</div>
<div class="system-card">
<span class="system-card-title">Ubuntu 22.04.5, runner image</span>
<dl>
<dt>kernel</dt><dd>6.8.0-1073-azure</dd>
<dt>cryptsetup</dt><dd>2.4.3</dd>
<dt>xts driver</dt><dd><code>xts-aes-aesni</code></dd>
<dt>memory</dt><dd>16 GiB</dd>
</dl>
<p>The LiME image, 17174331584 bytes, was read in 42 s. The build with the sanitizers runs here too.</p>
</div>
</div>

## Run by hand { #hand }

On these systems Keep was run by its options, without the check, and the screen and the report of each run were read. All of them have Secure Boot on, and with it kernel lockdown in the mode `integrity`.

One is a machine that is no guest.

<div class="home-grid">
<div class="system-card">
<span class="system-card-title">Linux Mint 22.3</span>
<dl>
<dt>kernel</dt><dd>6.14.0-37-generic</dd>
<dt>secure boot</dt><dd>enabled</dd>
<dt>lockdown</dt><dd>integrity</dd>
<dt>memory</dt><dd>16 GiB, 5 ranges of RAM</dd>
</dl>
<p>A LUKS2 container with its key in the kernel keyring got <span class="reached">captured and proven</span> from memory. The LiME image, 16848920736 bytes, was written in 16 to 19 s in three runs, and <code>banners.Banners</code> of Volatility 3 2.28.2 named the kernel from it. An image that AVML took of the machine gave the same key with no file at all, from the digests of the header that lay in memory.</p>
</div>
</div>

Four are guests under KVM with UEFI and 4 GiB of memory, each installed from the installer of its distribution, with the automatic partitioning and the encryption that the installer offers: a LUKS2 partition that holds the volume group of the system and is opened at boot. On each of them the root volume, its key in the kernel keyring, got <span class="reached">captured and proven</span> from memory, and Keep named the logical volumes on it as what it carries. An image that AVML took of the guest gave the same key with no file at all. The image of Keep was written with direct writes in 6 to 7 s.

<div class="home-grid">
<div class="system-card">
<span class="system-card-title">Red Hat Enterprise Linux 8.10</span>
<dl>
<dt>kernel</dt><dd>4.18.0-553.el8_10.x86_64</dd>
<dt>cryptsetup</dt><dd>2.3.7</dd>
<dt>xts driver</dt><dd><code>xts-aes-aesni</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
<p>A Minimal Install, and the oldest kernel on which Keep was run. Four pages of RAM, 16384 bytes, are in no segment of <code>/proc/kcore</code> there, which the run counts: pages in which one range of the memory map ends and the next begins.</p>
</div>
<div class="system-card">
<span class="system-card-title">Red Hat Enterprise Linux 9.9</span>
<dl>
<dt>kernel</dt><dd>5.14.0-741.20.1.el9_9.x86_64</dd>
<dt>cryptsetup</dt><dd>2.8.6</dd>
<dt>xts driver</dt><dd><code>xts-aes-aesni</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
<p>A Minimal Install. Four pages of RAM are in no segment of <code>/proc/kcore</code> here too.</p>
</div>
<div class="system-card">
<span class="system-card-title">Red Hat Enterprise Linux 10.3</span>
<dl>
<dt>kernel</dt><dd>6.12.0-264.14.1.el10_3.x86_64</dd>
<dt>cryptsetup</dt><dd>2.8.6</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx2</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
<p>A Minimal Install. The keys were taken before AVML ran and after it, with the same key each time.</p>
</div>
<div class="system-card">
<span class="system-card-title">Ubuntu Server 26.04.1</span>
<dl>
<dt>kernel</dt><dd>7.0.0-44-generic</dd>
<dt>cryptsetup</dt><dd>2.8.4</dd>
<dt>xts driver</dt><dd><code>xts-aes-vaes-avx2</code></dd>
<dt>symbols</dt><dd>System.map kept</dd>
</dl>
<p>Installed with its LVM group encrypted. The installer names the mapping <code>dm_crypt-0</code> and gives the root file system half of the volume group, so there is less room for an image than the disk suggests.</p>
</div>
</div>

A search of `/proc/kcore` after AVML had run listed more key schedules than one before it: 50 where it had listed 24 on RHEL 10.3, and 153 for 46 on Ubuntu Server. AVML writes its image through the page cache, and of a file that it wrote on the guest with Ubuntu Server the cache held 645368 of 855168 pages. The runs of Keep added none. So after such an image an address that a run names for a schedule can be that of a copy.

## The drivers of XTS { #drivers }

On x86-64 the kernel keeps the two key schedules of an `aes-xts` volume in one structure, the tweak schedule first and the data schedule 496 bytes after it. Keep pairs the schedules it finds in memory by that distance. The runs met four implementations, and with each of them the two halves of the key lay at that distance: `xts-aes-aesni`, `xts-aes-vaes-avx2`, `xts-aes-vaes-avx512` and `xts-aes-vaes-avx10_512`.

## Not checked { #not }

- Red Hat Enterprise Linux in the pipeline, which runs AlmaLinux and Rocky Linux, made to be compatible with it. On RHEL itself Keep was run by hand, on one LUKS2 volume with its key in the keyring.
- Kernels before 5.14 in the pipeline. On Linux 4.18, the kernel of RHEL 8, Keep was run by hand on one guest: the keys of such a volume, an image and the search of a dump. A key in the table, LUKS1, a volume with integrity and one in re-encryption are not run there.
- Linux Mint, which has no cloud image, and every system with Secure Boot on are run by hand and not by the check.
- openSUSE Tumbleweed, which has no dated build to pin.
- Kernel lockdown in the mode `confidentiality`, which refuses `/proc/kcore`. Keep then says so and ends with <span class="not">live copy only</span> for a volume whose key is in the keyring. This is read in the source of the kernel and not run.
- Any processor that is not x86-64.

A report of a system where Keep passes or fails is welcome as an issue on [GitHub](https://github.com/nafud/Keep/issues).
