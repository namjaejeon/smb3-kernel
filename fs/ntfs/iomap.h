/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#ifndef _LINUX_NTFS_IOMAP_H
#define _LINUX_NTFS_IOMAP_H

#include <linux/pagemap.h>
#include <linux/iomap.h>

#include "volume.h"
#include "inode.h"

struct ntfs_ordered_io;

bool ntfs_iomap_can_share_delalloc(struct ntfs_inode *ni);
void ntfs_maybe_writeback_delalloc(struct ntfs_volume *vol);
DECLARE_IOMAP_ITER_NEXT(ntfs_append_iomap_next);
DECLARE_IOMAP_ITER_NEXT(ntfs_ordered_append_iomap_next);
DECLARE_IOMAP_ITER_NEXT(ntfs_write_iomap_next);
DECLARE_IOMAP_ITER_NEXT(ntfs_read_iomap_next);
DECLARE_IOMAP_ITER_NEXT(ntfs_seek_iomap_next);
DECLARE_IOMAP_ITER_NEXT(ntfs_dio_iomap_next);
int ntfs_iomap_page_mkwrite(struct vm_fault *vmf);
int ntfs_writeback_prepare_folio(struct inode *inode, struct folio *folio);
struct ntfs_writepage_ctx {
	struct iomap_writepage_ctx wpc;
	struct ntfs_ordered_io *ordered;
};
extern const struct iomap_writeback_ops ntfs_writeback_ops;
extern const struct iomap_write_ops ntfs_iomap_folio_ops;
extern int ntfs_dio_zero_range(struct inode *inode, loff_t offset, loff_t length);
#endif /* _LINUX_NTFS_IOMAP_H */
