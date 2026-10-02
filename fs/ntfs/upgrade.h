/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_NTFS_UPGRADE_H
#define _LINUX_NTFS_UPGRADE_H

struct ntfs_volume;

int ntfs_upgrade_volume(struct ntfs_volume *vol);

#endif /* _LINUX_NTFS_UPGRADE_H */
