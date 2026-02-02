/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Defines for NTFS kernel address space operations and page cache
 * handling.
 *
 * Copyright (c) 2001-2004 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#ifndef _LINUX_NTFS_AOPS_H
#define _LINUX_NTFS_AOPS_H

#include <linux/pagemap.h>
#include <linux/iomap.h>

#include "volume.h"
#include "inode.h"

void mark_ntfs_record_dirty(struct folio *folio);
#endif /* _LINUX_NTFS_AOPS_H */
