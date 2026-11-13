// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Pocessing of object ids
 *
 * Part of this file is based on code from the NTFS-3G.
 *
 * Copyright (c) 2009-2019 Jean-Pierre Andre
 * Copyright (c) 2026 LG Electronics Co., Ltd.
 */

#include "ntfs.h"
#include "index.h"
#include "logfile.h"
#include "object_id.h"

struct object_id_index_key {
	union {
		u32 alignment;
		struct guid guid;
	} object_id;
} __packed;

struct object_id_index_data {
	__le64 file_id;
	struct guid birth_volume_id;
	struct guid birth_object_id;
	struct guid domain_id;
} __packed;

/* Index entry in $Extend/$ObjId */
struct object_id_index {
	struct index_entry_header header;
	struct object_id_index_key key;
	struct object_id_index_data data;
} __packed;

__le16 objid_index_name[] = {cpu_to_le16('$'), cpu_to_le16('O'), 0};

/*
 * open_object_id_index - Open the $Extend/$ObjId file and its index
 * @vol: NTFS volume structure
 *
 * Opens the $ObjId system file and retrieves its index context.
 *
 * Return: The index context if opened successfully, or NULL if an error
 *	   occurred.
 */
static struct ntfs_index_context *open_object_id_index(struct ntfs_volume *vol)
{
	struct inode *dir_vi, *vi;
	struct ntfs_inode *dir_ni;
	struct ntfs_index_context *xo = NULL;
	struct ntfs_name *name = NULL;
	u64 mref;
	int uname_len;
	__le16 *uname;

	uname_len = ntfs_nlstoucs(vol, "$ObjId", 6, &uname,
			NTFS_MAX_NAME_LEN);
	if (uname_len < 0)
		return NULL;

	/* do not use path_name_to inode - could reopen root */
	dir_vi = ntfs_iget(vol->sb, FILE_Extend);
	if (IS_ERR(dir_vi)) {
		kmem_cache_free(ntfs_name_cache, uname);
		return NULL;
	}
	dir_ni = NTFS_I(dir_vi);

	mutex_lock_nested(&dir_ni->mrec_lock, NTFS_EXTEND_MUTEX_PARENT);
	mref = ntfs_lookup_inode_by_name(dir_ni, uname, uname_len, &name);
	mutex_unlock(&dir_ni->mrec_lock);
	kfree(name);
	kmem_cache_free(ntfs_name_cache, uname);
	if (IS_ERR_MREF(mref))
		goto put_dir_vi;

	vi = ntfs_iget(vol->sb, MREF(mref));
	if (IS_ERR(vi))
		goto put_dir_vi;

	xo = ntfs_index_ctx_get(NTFS_I(vi), objid_index_name, 2);
	if (!xo)
		iput(vi);
put_dir_vi:
	iput(dir_vi);
	return xo;
}

int ntfs_object_id_index_check_unlinked(struct ntfs_inode *ni)
{
	struct ntfs_index_context *xo;
	struct ntfs_inode *xoni;
	int err;

	xo = open_object_id_index(ni->vol);
	if (!xo)
		return -EIO;
	xoni = xo->idx_ni;
	mutex_lock_nested(&xoni->mrec_lock, NTFS_EXTEND_MUTEX_PARENT);
	err = ntfs_index_check_unlinked(xo, ni->mft_no,
			NTFS_SYSTEM_INDEX_OBJECT_ID);
	ntfs_index_ctx_put(xo);
	mutex_unlock(&xoni->mrec_lock);
	iput(VFS_I(xoni));
	return err;
}


/*
 * remove_object_id_index - Remove an object id index entry if attribute present
 * @ni: NTFS inode structure containing the attribute
 * @xo:	Index context for the object id index
 *
 * Reads the existing object ID attribute and removes it from the index.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
static int remove_object_id_index(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, struct ntfs_index_context *xo)
{
	struct object_id_index_key key = {0};
	s64 size;

	if (ni->data_size == 0)
		return -ENODATA;

	/* read the existing object id attribute */
	size = ntfs_inode_attr_pread(VFS_I(ni), 0, sizeof(struct guid),
				     (char *)&key);
	if (size != sizeof(struct guid))
		return -ENODATA;

	if (!ntfs_index_lookup(&key, sizeof(struct object_id_index_key), xo)) {
		if (handle)
			return ntfs_index_entry_remove_transacted(handle, xo);
		return ntfs_index_rm(xo);
	}

	return 0;
}

static int object_id_index_remove_log_credits(struct ntfs_inode *ni,
		struct ntfs_index_context *xo)
{
	int credits;
	int extra_credits;

	if (!ni || !xo)
		return -EINVAL;
	credits = ntfs_index_node_remove_log_credits(ni->vol,
			xo->block_size);
	if (credits < 0)
		return credits;
	if (!NInoAttrList(xo->idx_ni))
		return credits;
	extra_credits = ntfs_index_attrlist_log_credits(ni->vol, 1);
	if (extra_credits < 0 || check_add_overflow(credits, extra_credits,
			&credits))
		return extra_credits < 0 ? extra_credits : -EOVERFLOW;
	return credits;
}

int ntfs_object_id_index_remove_log_credits(struct ntfs_inode *ni)
{
	struct ntfs_index_context *xo;
	struct ntfs_inode *xoni;
	int credits;

	if (!ni)
		return -EINVAL;
	if (!ntfs_attr_exist(ni, AT_OBJECT_ID, AT_UNNAMED, 0))
		return 0;
	xo = open_object_id_index(ni->vol);
	if (!xo)
		return -EINVAL;
	xoni = xo->idx_ni;
	credits = object_id_index_remove_log_credits(ni, xo);
	ntfs_index_ctx_put(xo);
	iput(VFS_I(xoni));
	return credits;
}

int ntfs_prepare_object_id_index_remove(struct ntfs_inode *ni,
		struct ntfs_system_index_ctx *ctx)
{
	struct ntfs_index_context *xo;
	struct inode *attr_vi;

	if (!ni || !ctx)
		return -EINVAL;
	lockdep_assert_held(&ni->vol->system_index_lock);
	attr_vi = ntfs_attr_iget(VFS_I(ni), AT_OBJECT_ID, AT_UNNAMED, 0);
	if (IS_ERR(attr_vi))
		return PTR_ERR(attr_vi) == -ENOENT ? 0 : PTR_ERR(attr_vi);
	xo = open_object_id_index(ni->vol);
	if (!xo) {
		iput(attr_vi);
		return -EINVAL;
	}
	ctx->attr = attr_vi;
	ctx->index = xo;
	return 0;
}

int ntfs_delete_object_id_index_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		struct ntfs_system_index_ctx *ctx)
{
	struct ntfs_inode *xoni;
	int err;

	if (!handle || !ni || !ctx)
		return -EINVAL;
	lockdep_assert_held(&ni->vol->system_index_lock);
	lockdep_assert_held(&ni->mrec_lock);
	if (!ctx->index)
		return 0;
	xoni = ctx->index->idx_ni;
	mutex_lock_nested(&xoni->mrec_lock, NTFS_EXTEND_MUTEX_PARENT);
	err = remove_object_id_index(handle, NTFS_I(ctx->attr), ctx->index);
	ntfs_index_ctx_reinit(ctx->index);
	mutex_unlock(&xoni->mrec_lock);
	return err;
}

/*
 * ntfs_delete_object_id_index - Delete an object_id index entry
 * @ni:	NTFS inode structure
 *
 * Opens the object ID index and removes the entry corresponding to the inode.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int ntfs_delete_object_id_index(struct ntfs_inode *ni)
{
	struct ntfs_index_context *xo;
	struct ntfs_inode *xoni;
	struct ntfs_log_handle *handle = NULL;
	struct inode *attr_vi;
	bool system_index_locked = false;
	int ret = 0;

	attr_vi = ntfs_attr_iget(VFS_I(ni), AT_OBJECT_ID, AT_UNNAMED, 0);
	if (IS_ERR(attr_vi))
		return PTR_ERR(attr_vi);

	/*
	 * read the existing object id and un-index it
	 */
	xo = open_object_id_index(ni->vol);
	if (!xo) {
		iput(attr_vi);
		return -EIO;
	}
	if (xo) {
		xoni = xo->idx_ni;
		if (ni->vol->journal) {
			int credits;

			credits = object_id_index_remove_log_credits(ni, xo);
			if (credits < 0) {
				ret = credits;
				goto put_index;
			}
			handle = ntfs_log_begin(ni->vol, credits);
			if (IS_ERR(handle)) {
				ret = PTR_ERR(handle);
				handle = NULL;
				goto put_index;
			}
			mutex_lock(&ni->vol->system_index_lock);
			system_index_locked = true;
		}
		mutex_lock_nested(&xoni->mrec_lock, NTFS_EXTEND_MUTEX_PARENT);
		ret = remove_object_id_index(handle, NTFS_I(attr_vi), xo);
		if (!ret && handle) {
			ret = ntfs_log_commit(handle);
			handle = NULL;
		} else if (!ret) {
			ntfs_index_entry_mark_dirty(xo);
			mark_mft_record_dirty(xoni);
		}
		if (ret && handle) {
			int abort_err = ntfs_log_abort(handle);

			handle = NULL;
			if (abort_err)
				ret = abort_err;
		}
		ntfs_index_ctx_put(xo);
		mutex_unlock(&xoni->mrec_lock);
		if (system_index_locked)
			mutex_unlock(&ni->vol->system_index_lock);
		iput(VFS_I(xoni));
	}

	iput(attr_vi);
	return ret;

put_index:
	ntfs_index_ctx_put(xo);
	iput(VFS_I(xoni));
	iput(attr_vi);
	return ret;
}
