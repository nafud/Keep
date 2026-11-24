/*
 * sys.h: what the running system says about itself, read from /proc, /sys and /etc as text.
 *
 * Every function names the file it reads, so that the checks can hand it a file of their own.
 * Nothing of the examined system is executed.
 */
#ifndef KEEP_SYS_H
#define KEEP_SYS_H

#include <stddef.h>

struct sys_mount {
    char *source, *type, *point;        /* of the file system: its device, its type, where it is mounted */
    int readonly;
};

/* The mount that holds PATH according to MOUNTINFO (/proc/self/mountinfo): the one with the
   longest mount point that is a prefix of PATH, and of two at one mount point the later line,
   which lies on top. Returns 0, or -1 where no line holds the path. */
int sys_mount_of(const char *mountinfo, const char *path, struct sys_mount *m);
void sys_mount_free(struct sys_mount *m);

/* What the block device MAJOR:MINOR carries, as one line: where it and the devices that stand
   on it, such as the logical volumes of LVM, are mounted or used as swap. Eight mounts are
   named and further ones counted. Empty where nothing is. The caller frees it. */
char *sys_in_use(const char *sysfs, const char *mountinfo, const char *swaps, unsigned major, unsigned minor);

/* The types of the mounted file systems that can encrypt by themselves (eCryptfs, ZFS,
   gocryptfs, CryFS, EncFS), sorted, each once, with spaces between. The caller frees it. */
char *sys_other_filesystems(const char *mounts);

/* The mode in brackets in /sys/kernel/security/lockdown. Empty where the file is missing. */
void sys_lockdown(const char *path, char *out, size_t outlen);
/* The value of the UEFI variable SecureBoot as a number, from DIR (/sys/firmware/efi/efivars).
   Empty where there is no such variable. */
void sys_secure_boot(const char *dir, char *out, size_t outlen);
/* PRETTY_NAME of the first of the two os-release files that can be read. */
void sys_os_name(const char *first, const char *second, char *out, size_t outlen);

/* The path of the node of a block device in /dev, as cryptsetup names it: /dev/mapper/NAME for
   a mapped device, else /dev/ and the name of the kernel. Returns 0, or -1 where /sys does not
   know the device. */
int sys_device_path(const char *sysfs, unsigned major, unsigned minor, char *out, size_t outlen);

#endif
