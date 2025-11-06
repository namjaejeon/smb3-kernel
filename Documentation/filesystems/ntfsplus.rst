.. SPDX-License-Identifier: GPL-2.0

=================================
The Linux NTFS+ filesystem driver
=================================


.. Table of contents

   - Overview
   - Features
   - Utilities support
   - Supported mount options


Overview
========

The ntfsplus is an implementation that supports write and the current
trends(iomap, no buffer-head) based on read-only classic NTFS.
The old read-only ntfs code is much cleaner, with extensive comments,
offers readability that makes understanding NTFS easier. This is why
ntfsplus was developed on old read-only NTFS base.
The target is to provide current trends(iomap, no buffer head, folio),
enhanced performance, stable maintenance, utility support including fsck.

Features
========

- Write support:
   Implement write support on classic read-only NTFS. Additionally,
   integrate delayed allocation to enhance write performance through
   multi-cluster allocation and minimized fragmentation of cluster bitmap.

- Switch to using iomap:
   Use iomap for buffered IO writes, reads, direct IO, file extent mapping,
   readpages, writepages operations.

- Stop using the buffer head:
   The use of buffer head in old ntfs and switched to use folio instead.
   As a result, CONFIG_BUFFER_HEAD option enable is removed in Kconfig also.

- Performance Enhancements:
  write, file list browsing, mount performance are improved with
  the following.
     - Use iomap aops.
     - Delayed allocation support.
     - Optimize zero out for newly allocated clusters.
     - Optimize runlist merge overhead with small chunck size.
     - pre-load mft(inode) blocks and index(dentry) blocks to improve
       readdir + stat performance.
     - Load lcn bitmap on background.

- Stability improvement:
   a. Pass more xfstests tests:
      ntfsplus implement fallocate, idmapped mount and permission, etc,
      resulting in a significantly high number(287) of xfstests pass.
   b. Bonnie++ issue[3]:
      The Bonnie++ benchmark fails on ntfs3 with a "Directory not empty"
      error during file deletion. ntfs3 currently iterates directory
      entries by reading index blocks one by one. When entries are deleted
      concurrently, index block merging or entry relocation can cause
      readdir() to skip some entries, leaving files undeleted in
      workloads(bonnie++) that mix unlink and directory scans.
      ntfsplus implement leaf chain traversal in readdir to avoid entry skip
      on deletion.


Utilities support
=================

While ntfs-3g includes ntfsprogs as a component, it notably lacks
the fsck implementation. So we have launched a new ntfs utilitiies
project called ntfsprogs-plus by forking from ntfs-3g after removing
unnecessary ntfs fuse implementation. fsck.ntfs can be used for ntfs
testing with xfstests as well as for recovering corrupted NTFS device.
Download the following ntfsplus-plus and can use mkfs.ntfs and fsck.ntfs.

  https://github.com/ntfsprogs-plus/ntfsprogs-plus


Supported mount options
=======================

The NTFS+ driver supports the following mount options:

======================= =======================================================
iocharset=name		Deprecated option.  Still supported but please use
			nls=name in the future.  See description for nls=name.

nls=name		Character set to use when returning file names.
			Unlike VFAT, NTFS suppresses names that contain
			unconvertible characters.  Note that most character
			sets contain insufficient characters to represent all
			possible Unicode characters that can exist on NTFS.
			To be sure you are not missing any files, you are
			advised to use nls=utf8 which is capable of
			representing all Unicode characters.

uid=
gid=
umask=			Provide default owner, group, and access mode mask.
			These options work as documented in mount(8).  By
			default, the files/directories are owned by root and
			he/she has read and write permissions, as well as
			browse permission for directories.  No one else has any
			access permissions.  I.e. the mode on all files is by
			default rw------- and for directories rwx------, a
			consequence of the default fmask=0177 and dmask=0077.
			Using a umask of zero will grant all permissions to
			everyone, i.e. all files and directories will have mode
			rwxrwxrwx.

fmask=
dmask=			Instead of specifying umask which applies both to
			files and directories, fmask applies only to files and
			dmask only to directories.

showmeta=<BOOL>
show_sys_files=<BOOL>	If show_sys_files is specified, show the system files
			in directory listings.  Otherwise the default behaviour
			is to hide the system files.
			Note that even when show_sys_files is specified, "$MFT"
			will not be visible due to bugs/mis-features in glibc.
			Further, note that irrespective of show_sys_files, all
			files are accessible by name, i.e. you can always do
			"ls -l \$UpCase" for example to specifically show the
			system file containing the Unicode upcase table.

case_sensitive=<BOOL>	If case_sensitive is specified, treat all file names as
			case sensitive and create file names in the POSIX
			namespace.  Otherwise the default behaviour is to treat
			file names as case insensitive and to create file names
			in the WIN32/LONG name space.  Note, the Linux NTFS
			driver will never create short file names and will
			remove them on rename/delete of the corresponding long
			file name.
			Note that files remain accessible via their short file
			name, if it exists.  If case_sensitive, you will need
			to provide the correct case of the short file name.

disable_sparse=<BOOL>	If disable_sparse is specified, creation of sparse
			regions, i.e. holes, inside files is disabled for the
			volume (for the duration of this mount only).  By
			default, creation of sparse regions is enabled, which
			is consistent with the behaviour of traditional Unix
			filesystems.

errors=opt		Specify NTFS+ behavior on critical errors: panic,
                        remount the partition in read-only mode or continue
                        without doing anything (default behavior).

mft_zone_multiplier=	Set the MFT zone multiplier for the volume (this
			setting is not persistent across mounts and can be
			changed from mount to mount but cannot be changed on
			remount).  Values of 1 to 4 are allowed, 1 being the
			default.  The MFT zone multiplier determines how much
			space is reserved for the MFT on the volume.  If all
			other space is used up, then the MFT zone will be
			shrunk dynamically, so this has no impact on the
			amount of free space.  However, it can have an impact
			on performance by affecting fragmentation of the MFT.
			In general use the default.  If you have a lot of small
			files then use a higher value.  The values have the
			following meaning:

			      =====	    =================================
			      Value	     MFT zone size (% of volume size)
			      =====	    =================================
				1		12.5%
				2		25%
				3		37.5%
				4		50%
			      =====	    =================================

			Note this option is irrelevant for read-only mounts.

preallocated_size=	Set preallocated size to optimize runlist merge
                        overhead with small chunck size.(64KB size by default)

acl=<BOOL>		Enable POSIX ACL support. When specified, POSIX ACLs stored
			in extended attributes are enforced. Default is off.
			Requires kernel config NTFSPLUS_FS_POSIX_ACL enabled.

sys_immutable=<BOOL>	Make NTFS system files (e.g. $MFT, $LogFile, $Bitmap,
			$UpCase, etc.) immutable to user initiated modifications
			for extra safety. Default is off.

nohidden=<BOOL>		Hide files and directories marked with the Windows
			"hidden" attribute. By default hidden items are shown.

hide_dot_files=<BOOL>	Hide names beginning with a dot ("."). By default dot
			files are shown. When enabled, files and directories created
			with a leading '.' will be hidden from directory listings.

windows_names=<BOOL>	Refuse creation/rename of files with characters or
			reserved device names disallowed on Windows (e.g. CON,
			NUL, AUX, COM1, LPT1, etc.). Default is off.
======================= =======================================================
