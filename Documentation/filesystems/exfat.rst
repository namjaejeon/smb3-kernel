.. SPDX-License-Identifier: GPL-2.0

==================================
The Linux exFAT filesystem driver
==================================


.. Table of contents

   - Overview
   - Utilities support
   - Supported mount options


Overview
========

exFAT is a filesystem designed for removable storage and other devices that
need to store large files.  The Linux exFAT filesystem driver provides read
and write support for exFAT volumes.

To mount an exFAT volume, use the ``exfat`` filesystem type::

  mount -t exfat /dev/sdX1 /mnt


Utilities support
=================

The exfatprogs project provides userspace utilities for creating, checking,
repairing, inspecting, and tuning exFAT filesystems.  Use exfatprogs when
creating or checking an exFAT filesystem.  For example, use ``mkfs.exfat``
to create a filesystem and ``fsck.exfat`` to check or repair one.

The project is available at:

  https://github.com/exfatprogs/exfatprogs


Supported mount options
=======================

The exFAT driver supports the following mount options:

======================= ====================================================
uid=
gid=                    Set the owner and group of all files and
                        directories.  The default is the uid and gid of
                        the process mounting the filesystem.

umask=                  Set the permission mask for files and directories.
                        The default is the umask of the process mounting
                        the filesystem.

dmask=                  Set the permission mask for directories.

fmask=                  Set the permission mask for files.

allow_utime=            Control the permission check for changing file
                        timestamps.  Only permission bits 0022 are used.
                        Permission bit 0020 allows members of the file's
                        group to change timestamps, and permission bit 0002
                        allows other users to change timestamps.  The
                        default is derived from dmask (``~dmask & 0022``).

iocharset=name          Character set used to convert between user-visible
                        filenames and the UTF-16 character encoding used by
                        exFAT.  The default is
                        CONFIG_EXFAT_DEFAULT_IOCHARSET, which is ``utf8``
                        unless changed at kernel configuration time.  Use
                        ``iocharset=utf8`` for UTF-8 filename handling.

errors=                 Specify exFAT behavior on filesystem errors.  The
                        value must be ``panic``, ``continue``, or
                        ``remount-ro``.  These respectively panic, continue
                        without changing the filesystem, or remount the
                        filesystem read-only.  The default is
                        ``remount-ro``.

discard                 Issue discard/TRIM requests to the block device
                        when clusters are freed.  This is disabled by
                        default.  ``nodiscard`` disables it explicitly.

keep_last_dots          Keep trailing periods in path components during
                        lookup.  Without this option, trailing periods are
                        stripped.  Existing entries with trailing periods
                        can be accessed when this option is enabled, but
                        creating new entries with trailing periods is
                        rejected.

sys_tz                  Use the system timezone as the UTC offset when an
                        exFAT timestamp does not contain a valid timezone
                        offset.  This takes precedence over time_offset.

time_offset=minutes     Set the UTC offset, in minutes, used when an exFAT
                        timestamp does not contain a valid timezone offset.
                        Values from -1440 to 1440 are accepted.  The default
                        is 0.  This option is ignored when sys_tz is set.

zero_size_dir           Create directories with zero size and without
                        allocating a cluster.  This is disabled by default;
                        the default behavior allocates a cluster for a new
                        directory.  ``nozero_size_dir`` disables it
                        explicitly.
======================= ====================================================


Deprecated mount options
------------------------

The following options are accepted for compatibility but should not be used:

``utf8``
  Deprecated.  Use ``iocharset=utf8`` instead.

``debug``, ``namecase=``, ``codepage=``
  Deprecated and ignored by the exFAT driver.


Online allocation queries and relocation
=======================================

The UAPI in ``linux/exfat.h`` defines native Linux ioctls for querying the
volume bitmap, querying file extents and relocating file clusters. Issue them
on an open file/directory in mounted exFAT, not on its block device. They
require ``CAP_SYS_ADMIN`` in the initial user namespace. These operations
correspond to Windows defragmentation FSCTLs, using a native Linux binary ABI.

LCNs are zero-based offsets in the cluster heap: LCN zero is on-disk cluster
two. VCNs are zero-based cluster offsets within a file. Positions and quantities
are in clusters except explicitly named byte fields. All flags and reserved
fields must be zero. Fixed-width fields and aligned 64-bit user pointers
preserve the layout for compat ioctls.

``EXFAT_IOC_GET_VOLUME_BITMAP``
  Pass ``struct exfat_volume_bitmap`` on any exFAT file or directory fd.
  ``start_lcn`` is rounded down to a byte boundary, except that a request at
  ``total_clusters`` returns zero bytes. ``bitmap`` points to a byte array and
  ``bitmap_bytes`` is its capacity, from 1 through 1 MiB. The least significant
  bit represents the first cluster; one means allocated. Last-byte padding is
  allocated. The header reports the actual start, total clusters, bytes
  returned, cluster size and maximum clusters per move. Continue at
  ``start_lcn + bytes_returned * 8`` until reaching the volume's end.

``EXFAT_IOC_GET_RETRIEVAL_POINTERS``
  Pass ``struct exfat_retrieval_pointers`` on a regular file fd. ``start_vcn``
  selects the first cluster. ``extents`` points to an array of
  ``struct exfat_extent`` and ``extent_capacity`` is from 1 through 4096.
  Each extent gives its VCN, LCN and cluster count. The first starts at the
  requested VCN; adjacent physical clusters are coalesced. Continue at
  ``next_vcn`` while less than ``total_clusters``. Empty files return no extents;
  allocation beyond VDL is included.

``EXFAT_IOC_MOVE_FILE``
  Pass ``struct exfat_move_file`` on a writable, linked regular file fd. Move
  ``cluster_count`` clusters at ``start_vcn`` to the free range at ``target_lcn``.
  ``expected_lcn`` must match the current first source cluster or the request
  fails with ``ESTALE``. An occupied destination fails with ``EBUSY``.
  A move is bounded to 32 MiB; split larger ranges using the bitmap query's
  ``max_move_clusters``. Partial FAT-chain and NoFatChain moves are supported
  regardless of the complete allocation's size. Before a partial NoFatChain
  move, the kernel materialises the original FAT chain in batches of at most
  64 KiB of FAT entries. The stream remains NoFatChain until the complete chain
  is durable. Construction takes time proportional to the file's allocated
  clusters, uses bounded memory and can be interrupted before the flag update.
  Later partial moves reuse the FAT chain.
  Moving the complete allocation in one request publishes a NoFatChain stream
  directly, without materialising either the source or destination FAT chain.
  Directories, swap files, unlinked files, vendor-extension files, TexFAT,
  read-only mounts and persistent dirty/media failure flags are rejected.
  An identical source/destination range is a no-op.

``EXFAT_IOC_SET_NO_FAT_CHAIN``
  Takes no argument and requires a writable, linked regular file fd. The kernel
  verifies the complete allocation, including the FAT end marker, while holding
  the inode and filesystem locks. If contiguous, it commits the NoFatChain flag
  and directory checksum without moving data or clearing existing FAT entries.
  An empty or already NoFatChain file is a no-op. A fragmented allocation returns
  ``EAGAIN`` without changing its representation. The restrictions on files
  eligible for relocation also apply to this operation.

  Call once after a placement plan has produced a single extent, including when
  the plan required several bounded moves. Verification takes time proportional
  to the file's allocated clusters; it is not repeated by individual moves and
  can be interrupted before the metadata update. A stale userspace extent
  snapshot cannot cause a fragmented file to acquire the NoFatChain flag.

Queries are snapshots. Different pages can observe different states as files
change. Callers must handle stale mappings, changed sizes and newly occupied
destinations. The driver revalidates moves and reserves exact destinations.

Relocation takes the inode lock, waits for direct I/O, and holds the mapping's
invalidate lock while revoking mmap PTEs, writing back and invalidating folios.
Renames, allocation and FAT/directory updates are serialised by ``s_lock``;
bitmap changes also use ``bitmap_lock``. Large NoFatChain FAT construction
releases ``s_lock`` between durable batches, retaining the inode and mapping
locks to keep the source allocation fixed. Destination data and allocation are
flushed before switching the file reference. The reference is flushed before
releasing source bitmap bits. FAT caches and inode hints are invalidated.
Source blocks are not discarded by this operation.

No on-disk journal is added. This does not make exFAT transactional or guarantee
atomic recovery from power loss or torn sectors. Interruption can leave orphan
allocations or a directory checksum requiring fsck. Once publication may have
started, an I/O error keeps both allocations. Metadata I/O errors preserve
VolumeDirty and force filesystem shutdown to prevent further writes. Unmount
and run fsck before reuse. An ioctl error does not prove that no metadata
reached disk.

If a directory entry write or flush fails, the driver tries once to complete
the same entry set. Destination data and allocation are already durable at
publication, or the entry still names the original allocation during
NoFatChain conversion. This bounded repair includes the checksum, since fsck
can delete an entry with an invalid checksum. It does not release uncertain
allocations, suppress the original error or allow further filesystem writes.
Persistent failures and power loss can still damage directory entries.

The exfatprogs defrag.exfat utility supplies placement policy.
