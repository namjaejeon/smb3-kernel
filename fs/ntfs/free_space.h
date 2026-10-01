/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_NTFS_FREE_SPACE_H
#define _LINUX_NTFS_FREE_SPACE_H

#include <linux/rbtree.h>
#include <linux/types.h>

struct ntfs_volume;

/* Protected by the volume's lcnbmp_lock. */
struct ntfs_free_space {
	struct rb_root by_start;
	struct rb_root by_length;
	unsigned int nr_extents;
	bool complete;
};

void ntfs_free_space_destroy(struct ntfs_free_space *space);
void ntfs_free_space_add(struct ntfs_free_space *space, s64 start, s64 length);
void ntfs_free_space_remove(struct ntfs_free_space *space, s64 start, s64 length);
void ntfs_free_space_add_bitmap(struct ntfs_free_space *space,
		const unsigned long *bitmap, s64 start, unsigned int bits);
int ntfs_free_space_find_at(struct ntfs_volume *vol, s64 hint, s64 end,
		s64 count, s64 *length);
int ntfs_free_space_find(struct ntfs_volume *vol, s64 begin, s64 end,
		s64 count, s64 *start, s64 *length);

#endif /* _LINUX_NTFS_FREE_SPACE_H */
