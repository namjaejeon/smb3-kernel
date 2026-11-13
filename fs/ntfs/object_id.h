/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2008-2021 Jean-Pierre Andre
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#ifndef _LINUX_NTFS_OBJECT_ID_H
#define _LINUX_NTFS_OBJECT_ID_H

extern __le16 objid_index_name[];

struct ntfs_system_index_ctx;

int ntfs_object_id_index_remove_log_credits(struct ntfs_inode *ni);
int ntfs_object_id_index_check_unlinked(struct ntfs_inode *ni);
int ntfs_prepare_object_id_index_remove(struct ntfs_inode *ni,
			struct ntfs_system_index_ctx *ctx);
int ntfs_delete_object_id_index_transacted(
			struct ntfs_log_handle *handle, struct ntfs_inode *ni,
			struct ntfs_system_index_ctx *ctx);
int ntfs_delete_object_id_index(struct ntfs_inode *ni);

#endif /* _LINUX_NTFS_OBJECT_ID_H */
