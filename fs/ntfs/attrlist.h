/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Exports for attribute list attribute handling.
 *
 * Copyright (c) 2004 Anton Altaparmakov
 * Copyright (c) 2004 Yura Pakhuchiy
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#ifndef _NTFS_ATTRLIST_H
#define _NTFS_ATTRLIST_H

#include "attrib.h"

int ntfs_attrlist_need(struct ntfs_inode *ni);
int ntfs_attrlist_entry_add(struct ntfs_inode *ni, struct attr_record *attr);
/* Worst-case reservation for list create/grow, extent create, and MFT alloc. */
int ntfs_attrlist_extent_log_credits(struct ntfs_volume *vol);
int ntfs_attrlist_nonresident_log_credits(struct ntfs_volume *vol);
int ntfs_attrlist_shrink_log_credits(struct ntfs_volume *vol, u32 max_bytes);
int ntfs_attrlist_base_move_limit(struct ntfs_volume *vol);
/* Entry growth converts a full resident list into an allocated stream. */
int ntfs_inode_add_attrlist_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni);
int ntfs_attrlist_entry_add_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, struct attr_record *attr);
int ntfs_attrlist_entry_move_transacted(struct ntfs_log_handle *handle,
		struct ntfs_attr_search_ctx *ctx, __le64 mft_reference,
		__le16 instance, u8 *pending_list, u32 pending_size);
int ntfs_attrlist_pending_entry_move(const struct attr_record *attr,
		u8 *pending_list, u32 pending_size, __le64 old_mft_reference,
		__le16 old_instance, __le64 new_mft_reference,
		__le16 new_instance);
int ntfs_attrlist_entry_rm_transacted(struct ntfs_log_handle *handle,
		struct ntfs_attr_search_ctx *ctx);
int ntfs_attrlist_remove_resident_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni);
int ntfs_attrlist_remove_nonresident_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni);
int ntfs_attrlist_entry_rm(struct ntfs_attr_search_ctx *ctx);
int ntfs_attrlist_update(struct ntfs_inode *base_ni);
int ntfs_attrlist_update_locked(struct ntfs_inode *base_ni,
				struct ntfs_inode *locked_ni);

#endif /* defined _NTFS_ATTRLIST_H */
