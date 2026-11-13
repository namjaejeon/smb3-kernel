/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2008-2021 Jean-Pierre Andre
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#ifndef _LINUX_NTFS_REPARSE_H
#define _LINUX_NTFS_REPARSE_H

extern __le16 reparse_index_name[];

struct ntfs_system_index_ctx;

int ntfs_parse_reparse(struct ntfs_inode *ni, unsigned int *mode);
unsigned int ntfs_reparse_tag_dt_types(struct ntfs_volume *vol, unsigned long mref);
int ntfs_translate_symlink_path(struct dentry *dentry, const char *target,
				char **translated);
int ntfs_reparse_set_wsl_symlink(struct ntfs_inode *ni,
				 const char *target, int target_len);
int ntfs_reparse_set_native_symlink(struct ntfs_inode *ni,
				    const char *symname, int symlen);
int ntfs_reparse_set_native_symlink_transacted(
			struct ntfs_log_handle *handle, struct ntfs_inode *ni,
			const char *symname, int symlen, char **converted_target);
int ntfs_reparse_set_wsl_not_symlink(struct ntfs_inode *ni, mode_t mode);
int ntfs_reparse_wsl_symlink_log_credits(struct ntfs_inode *ni,
			int target_len);
int ntfs_reparse_native_symlink_log_credits(struct ntfs_inode *ni,
			int target_len);
int ntfs_reparse_wsl_not_symlink_log_credits(struct ntfs_inode *ni);
int ntfs_reparse_set_wsl_symlink_transacted(
			struct ntfs_log_handle *handle, struct ntfs_inode *ni,
			const char *target, int target_len, char **converted_target);
int ntfs_reparse_set_wsl_not_symlink_transacted(
			struct ntfs_log_handle *handle, struct ntfs_inode *ni,
			mode_t mode);
int ntfs_reparse_index_remove_log_credits(struct ntfs_inode *ni);
int ntfs_reparse_index_check_unlinked(struct ntfs_inode *ni);
int ntfs_prepare_reparse_index_remove(struct ntfs_inode *ni,
			struct ntfs_system_index_ctx *ctx);
int ntfs_delete_reparse_index_transacted(
			struct ntfs_log_handle *handle, struct ntfs_inode *ni,
			struct ntfs_system_index_ctx *ctx);
int ntfs_delete_reparse_index(struct ntfs_inode *ni);
int ntfs_remove_ntfs_reparse_data(struct ntfs_inode *ni);

#endif /* _LINUX_NTFS_REPARSE_H */
