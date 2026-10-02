.. SPDX-License-Identifier: GPL-2.0

=================================
The Linux NTFS filesystem driver
=================================


.. Table of contents

   - Overview
   - Utilities support
   - Upgrading NTFS 1.2 volumes
   - Supported mount options


Overview
========

NTFS is a Linux kernel filesystem driver that provides full read and write
support for NTFS volumes. It is designed for high performance, modern
kernel infrastructure (iomap, folio), and stable long-term maintenance.


Utilities support
=================

The NTFS utilities project, called ntfsprogs-plus, provides mkfs.ntfs,
fsck.ntfs, and other related tools (e.g., ntfsinfo, ntfsclone, etc.) for
creating, checking, and managing NTFS volumes. These utilities can be used
for filesystem testing with xfstests as well as for recovering corrupted
NTFS devices.

The project is available at:

  https://github.com/ntfsprogs-plus/ntfsprogs-plus


Upgrading NTFS 1.2 volumes
==========================

A read-write mount upgrades supported NTFS 1.2 volumes to NTFS 3.0 only when
``UPGRADE_ON_MOUNT`` (0x0004) is set in the volume flags. Conversion finishes
before making the filesystem available and is synchronous: normal I/O must
not observe a mixture of old and new metadata. Without the flag, the volume
retains its NTFS 1.2 format. Read-only mounts do not upgrade the volume. To
upgrade a flagged volume mounted read-only, unmount it and mount it
read-write. A read-only to read-write remount does not convert it.

The conversion creates ``$Secure`` in MFT record 9, ``$Extend`` in record 11,
and ``$Quota``, ``$ObjId`` and ``$Reparse`` below ``$Extend``. It also updates
``$AttrDef`` and converts legacy mapping pairs that encode holes. Existing
file data, per-file security descriptors and 48-byte standard information
attributes are retained. NTFS 3.0 is the target because it can retain the
old MFT record headers. Converting to 3.1 would require relocating the
update sequence array in existing records.

A flagged volume already containing the NTFS 3.x system files but still
reporting version 1.2 is checked before finishing its conversion. The
``UPGRADE_ON_MOUNT`` flag is cleared after successful conversion. Existing
NTFS 3.0 and 3.1 volumes are not converted.

The driver checks allocated MFT records before starting the upgrade. It
rejects populated legacy ``$Quota`` files, reserved records with unexpected
uses, legacy volume-version or symbolic-link attributes, and other layouts
it cannot convert. Dirty volumes, damaged metadata and Windows hibernation
also prevent conversion. Before writing upgrade metadata, unsupported
layouts or insufficient space cause the requested read-write mount to fall
back to read-only. Space checks include the new files, MFT records, the
MFT metadata reserve and growth of the MFT data and bitmap attributes.
Damaged metadata, read errors and memory allocation failures abort the
mount. Unsupported layouts can be upgraded using Windows.

The dirty and upgrade flags are persisted before modifying metadata.
Metadata and allocation bitmaps are flushed before the final version
update. This is not a journaled transaction: an interrupted conversion or
I/O failure can leave a partially converted, dirty volume. A failed
conversion after upgrade writes have started aborts the mount. Repair the
volume using Windows ``chkdsk`` before attempting another read-write mount.
The prepared-layout check is not automatic recovery for an interrupted
upgrade. It does not bypass the dirty-volume checks.

Regression testing should use disposable images and cover conversion,
data and stream contents, compressed holes, read-only mounts, dirty volumes
and unchanged format when the upgrade flag is absent. Keep backups before
upgrading existing volumes.


Supported mount options
=======================

The NTFS driver supports the following mount options:

======================= ====================================================
iocharset=name          Character set to use for converting between
                        the encoding is used for user visible filename and
                        16 bit Unicode characters.

nls=name                Deprecated option.  Still supported but please use
                        iocharset=name in the future.

uid=
gid=
umask=                  Provide default owner, group, and access mode mask.
                        These options work as documented in mount(8).  By
                        default, the files/directories are owned by root
                        and he/she has read and write permissions, as well
                        as browse permission for directories.  No one else
                        has any access permissions.  I.e. the mode on all
                        files is by default rw------- and
                        for directories rwx------, a consequence of
                        the default fmask=0177 and dmask=0077.
                        Using a umask of zero will grant all permissions to
                        everyone, i.e. all files and directories will have
                        mode rwxrwxrwx.

fmask=
dmask=                  Instead of specifying umask which applies both to
                        files and directories, fmask applies only to files
                        and dmask only to directories.

showmeta=<BOOL>
show_sys_files=<BOOL>   If show_sys_files is specified, show the system
                        files in directory listings.  Otherwise the default
                        behaviour is to hide the system files.
                        Note that even when show_sys_files is specified,
                        "$MFT" will not be visible due to bugs/mis-features
                        in glibc. Further, note that irrespective of
                        show_sys_files, all files are accessible by name,
                        i.e. you can always do "ls -l \$UpCase" for example
                        to specifically show the system file containing
                        the Unicode upcase table.

case_sensitive=<BOOL>   If case_sensitive is specified, treat all filenames
                        as case sensitive and create file names in
                        the POSIX namespace (default behavior). Note,
                        the Linux NTFS driver will never create short
                        filenames and will remove them on rename/delete of
                        the corresponding long file name. Note that files
                        remain accessible via their short file name, if it
                        exists.

nocase=<BOOL>           If nocase is specified, treat filenames
                        case-insensitively.

disable_sparse=<BOOL>   If disable_sparse is specified, creation of sparse
                        regions, i.e. holes, inside files is disabled for
                        the volume (for the duration of this mount only).
                        By default, creation of sparse regions is enabled,
                        which is consistent with the behaviour of
                        traditional Unix filesystems.

errors=opt              Specify NTFS behavior on critical errors: panic,
                        remount the partition in read-only mode or
                        continue without doing anything (default behavior).

mft_zone_multiplier=    Set the MFT zone multiplier for the volume (this
                        setting is not persistent across mounts and can be
                        changed from mount to mount but cannot be changed
                        on remount).  Values of 1 to 4 are allowed, 1 being
                        the default.  The MFT zone multiplier determines
                        how much space is reserved for the MFT on the
                        volume.  If all other space is used up, then the
                        MFT zone will be shrunk dynamically, so this has no
                        impact on the amount of free space.  However, it
                        can have an impact on performance by affecting
                        fragmentation of the MFT. In general use the
                        default.  If you have a lot of small files then use
                        a higher value.  The values have the following
                        meaning:

                        =====   =================================
                        Value   MFT zone size (% of volume size)
                        =====   =================================
                          1             12.5%
                          2             25%
                          3             37.5%
                          4             50%
                        =====   =================================

                        Note this option is irrelevant for read-only mount.

preallocated_size=      Set preallocated size to optimize runlist merge
                        overhead with small chunck size.(64KB size by
                        default)

acl=<BOOL>              Enable POSIX ACL support. When specified, POSIX
                        ACLs stored in extended attributes are enforced.
                        Default is off. Requires kernel config
                        NTFS_FS_POSIX_ACL enabled.

sys_immutable=<BOOL>    Make NTFS system files (e.g. $MFT, $LogFile,
                        $Bitmap, $UpCase, etc.) immutable to user initiated
                        modifications for extra safety. Default is off.

nohidden=<BOOL>         Hide files and directories marked with the Windows
                        "hidden" attribute. By default hidden items are
                        shown.

hide_dot_files=<BOOL>   Hide names beginning with a dot ("."). By default
                        dot files are shown. When enabled, files and
                        directories created with a leading '.' will be
                        hidden from directory listings.

windows_names=<BOOL>    Refuse creation/rename of files with characters or
                        reserved device names disallowed on Windows (e.g.
                        CON, NUL, AUX, COM1, LPT1, etc.). Default is off.
discard=<BOOL>          Issue block device discard for clusters freed on
                        file deletion/truncation to inform underlying
                        storage.

native_symlink=raw|rel  Configure how absolute symbolic links and mount
                        points (junctions) are handled. Under "raw"
                        (default), the absolute target path is returned
                        as-is without translation. Under "rel", it is
                        rewritten as a relative path anchored at
                        the volume root.

symlink=wsl|native      Configure how symbolic links are created. Under
                        "wsl" (default), WSL (Windows Subsystem for
                        Linux) compatible symlinks are created. Under
                        "native", Windows native symbolic links are
                        created.

streams_interface=      Select the named-stream pathname interface:
                        "none" (default) treats ':' as an ordinary filename
                        character, while "windows" interprets the final
                        component of a path such as "file:stream" as a named
                        $DATA stream. In "windows" mode, filenames containing
                        ':' are hidden from directory listings and cannot be
                        addressed through the pathname interface. Only the
                        file:stream form is recognized. Typed forms such
                        as file::$DATA and file:stream:$DATA are not
                        supported. The ioctl interface is available in both
                        modes. The base file or directory must already exist
                        before a pathname stream can be created. Creating
                        file:stream does not create file. Removing a stream
                        while it is open fails with -EBUSY. Removing the base
                        file while a stream is open detaches the stream from
                        the namespace; NTFS has no orphan-stream list, so a
                        crash can leave that stream's data unreachable on
                        disk.
======================= ====================================================

Named-stream ioctls
===================

The named-stream ioctl interface is available regardless of
streams_interface. Open the base regular file or directory and use
NTFS_IOC_STREAM_READ and NTFS_IOC_STREAM_WRITE with a
struct ntfs_stream request. The request contains the stream name,
byte offset, and transfer length. Write requests create the stream when it
does not exist. A failed write can leave a newly created empty stream; use
NTFS_IOC_STREAM_REMOVE to remove it. This ioctl removes streams, and
NTFS_IOC_LIST_STREAMS enumerates streams. Stream names are encoded with
the mounted NLS by default. Set NTFS_STREAM_FL_UTF16 to pass or receive
raw UTF-16LE names. These ioctls transfer stream data directly and do not
return a separate stream file descriptor.
