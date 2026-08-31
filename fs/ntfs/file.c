// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS kernel file operations.
 *
 * Copyright (c) 2001-2015 Anton Altaparmakov and Tuxera Inc.
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/uio.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/compat.h>
#include <linux/falloc.h>
#include <linux/file.h>
#include <linux/overflow.h>
#include <linux/security.h>
#include <uapi/linux/ntfs.h>

#include "lcnalloc.h"
#include "ntfs.h"
#include "reparse.h"
#include "ea.h"
#include "iomap.h"
#include "bitmap.h"
#include "volume.h"
#include "mft.h"

#include <linux/filelock.h>

/*
 * ntfs_file_open - called when an inode is about to be opened
 * @vi:		inode to be opened
 * @filp:	file structure describing the inode
 *
 * Limit file size to the page cache limit on architectures where unsigned long
 * is 32-bits. This is the most we can do for now without overflowing the page
 * cache page index. Doing it this way means we don't run into problems because
 * of existing too large files. It would be better to allow the user to read
 * the beginning of the file but I doubt very much anyone is going to hit this
 * check on a 32-bit architecture, so there is no point in adding the extra
 * complexity required to support this.
 *
 * On 64-bit architectures, the check is hopefully optimized away by the
 * compiler.
 *
 * After the check passes, just call generic_file_open() to do its work.
 */
static int ntfs_file_open(struct inode *vi, struct file *filp)
{
	struct ntfs_inode *ni = NTFS_I(vi);

	if (NVolShutdown(ni->vol))
		return -EIO;

	if (sizeof(unsigned long) < 8) {
		if (i_size_read(vi) > MAX_LFS_FILESIZE)
			return -EOVERFLOW;
	}

	filp->f_mode |= FMODE_NOWAIT | FMODE_CAN_ODIRECT;

	return generic_file_open(vi, filp);
}

/*
 * Trim preallocated space on file release.
 *
 * When the preallo_size mount option is set (default 64KB), writes extend
 * allocated_size and runlist in units of preallocated size to reduce
 * runlist merge overhead for small writes. This can leave
 * allocated_size > data_size if not all preallocated space is used.
 *
 * We perform the trim here because ->release() is called only when
 * the file is no longer open. At this point, no further writes can occur,
 * so it is safe to reclaim the unused preallocated space.
 *
 * Returns 0 on success, or negative error on failure.
 */
static int ntfs_trim_prealloc(struct inode *vi)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_inode *mrec_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct runlist_element *rl;
	s64 aligned_data_size;
	s64 vcn_ds, vcn_tr;
	ssize_t rc;
	int err = 0;

	inode_lock(vi);
	mutex_lock(&mrec_ni->mrec_lock);
	down_write(&ni->runlist.lock);

	aligned_data_size = round_up(ni->data_size, vol->cluster_size);
	if (aligned_data_size >= ni->allocated_size)
		goto out_unlock;

	vcn_ds = ntfs_bytes_to_cluster(vol, aligned_data_size);
	vcn_tr = -1;
	rc = ni->runlist.count - 2;
	rl = ni->runlist.rl;

	while (rc >= 0 && rl[rc].lcn == LCN_HOLE && vcn_ds <= rl[rc].vcn) {
		vcn_tr = rl[rc].vcn;
		rc--;
	}

	if (vcn_tr >= 0) {
		err = ntfs_rl_truncate_nolock(vol, &ni->runlist, vcn_tr);
		if (err) {
			kvfree(ni->runlist.rl);
			ni->runlist.rl = NULL;
			ntfs_error(vol->sb, "Preallocated block rollback failed");
		} else {
			ni->allocated_size = ntfs_cluster_to_bytes(vol, vcn_tr);
			err = ntfs_attr_update_mapping_pairs_locked(
					ni, 0, ni);
			if (err)
				ntfs_error(vol->sb,
					   "Failed to rollback mapping pairs for prealloc");
		}
	}

out_unlock:
	up_write(&ni->runlist.lock);
	mutex_unlock(&mrec_ni->mrec_lock);
	inode_unlock(vi);

	return err;
}

static int ntfs_file_release(struct inode *vi, struct file *filp)
{
	if (!NInoCompressed(NTFS_I(vi)) &&
	    !NInoWofCompressed(NTFS_I(vi)))
		return ntfs_trim_prealloc(vi);

	return 0;
}

/*
 * ntfs_file_fsync - sync a file to disk
 * @filp:	file to be synced
 * @start:	start offset to be synced
 * @end:	end offset to be synced
 * @datasync:	if non-zero only flush user data and not metadata
 *
 * Data integrity sync of a file to disk.  Used for fsync, fdatasync, and msync
 * system calls.  This function is inspired by fs/buffer.c::file_fsync().
 *
 * If @datasync is false, write the mft record and all associated extent mft
 * records as well as the $DATA attribute and then sync the block device.
 *
 * If @datasync is true and the attribute is non-resident, we skip the writing
 * of the mft record and all associated extent mft records (this might still
 * happen due to the write_inode_now() call).
 *
 * Also, if @datasync is true, we do not wait on the inode to be written out
 * but we always wait on the page cache pages to be written out.
 */
static int ntfs_file_fsync(struct file *filp, loff_t start, loff_t end,
			   int datasync)
{
	struct inode *vi = filp->f_mapping->host;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	int err, ret = 0;
	struct inode *parent_vi, *ia_vi;
	struct ntfs_attr_search_ctx *ctx;
	bool non_resident, stream;

	ntfs_debug("Entering for inode 0x%llx.", ni->mft_no);

	if (NVolShutdown(vol))
		return -EIO;

	err = file_write_and_wait_range(filp, start, end);
	if (err)
		return err;

	stream = ntfs_inode_is_named_stream(ni);
	non_resident = NInoNonResident(ni);
	if (stream) {
		ni = ni->ext.base_ntfs_ino;
		vi = VFS_I(ni);
	}

	if (!datasync || !non_resident)
		ret = __ntfs_write_inode(vi, 1);
	write_inode_now(vi, !datasync);

	/*
	 * file_write_and_wait_range() already flushed this stream mapping.
	 * Do not walk sibling attribute mappings while holding the base MFT
	 * lock; ordinary file fsync retains its existing behavior below.
	 */
	if (stream)
		goto sync_volume;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return -ENOMEM;

	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL_CHILD);
	while (!(err = ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx))) {
		if (ctx->attr->type == AT_FILE_NAME) {
			struct file_name_attr *fn = (struct file_name_attr *)((u8 *)ctx->attr +
					le16_to_cpu(ctx->attr->data.resident.value_offset));

			parent_vi = ntfs_iget(vi->i_sb, MREF_LE(fn->parent_directory));
			if (IS_ERR(parent_vi))
				continue;
			mutex_lock_nested(&NTFS_I(parent_vi)->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
			ia_vi = ntfs_index_iget(parent_vi, I30, 4);
			mutex_unlock(&NTFS_I(parent_vi)->mrec_lock);
			if (IS_ERR(ia_vi)) {
				iput(parent_vi);
				continue;
			}
			write_inode_now(ia_vi, 1);
			iput(ia_vi);
			write_inode_now(parent_vi, 1);
			iput(parent_vi);
		} else if (ctx->attr->non_resident) {
			struct inode *attr_vi;
			__le16 *name;

			name = (__le16 *)((u8 *)ctx->attr + le16_to_cpu(ctx->attr->name_offset));
			if (ctx->attr->type == AT_DATA && ctx->attr->name_length == 0)
				continue;

			attr_vi = ntfs_attr_iget(vi, ctx->attr->type,
						 name, ctx->attr->name_length);
			if (IS_ERR(attr_vi))
				continue;
			spin_lock(&attr_vi->i_lock);
			if (inode_state_read_once(attr_vi) & I_DIRTY_PAGES) {
				spin_unlock(&attr_vi->i_lock);
				filemap_write_and_wait(attr_vi->i_mapping);
			} else {
				spin_unlock(&attr_vi->i_lock);
			}
			iput(attr_vi);
		}
	}
	mutex_unlock(&ni->mrec_lock);
	ntfs_attr_put_search_ctx(ctx);

sync_volume:
	write_inode_now(vol->mftbmp_ino, 1);
	down_write(&vol->lcnbmp_lock);
	write_inode_now(vol->lcnbmp_ino, 1);
	up_write(&vol->lcnbmp_lock);
	write_inode_now(vol->mft_ino, 1);

	/*
	 * NOTE: If we were to use mapping->private_list (see ext2 and
	 * fs/buffer.c) for dirty blocks then we could optimize the below to be
	 * sync_mapping_buffers(vi->i_mapping).
	 */
	err = sync_blockdev(vi->i_sb->s_bdev);
	if (unlikely(err && !ret))
		ret = err;
	if (likely(!ret))
		ntfs_debug("Done.");
	else
		ntfs_warning(vi->i_sb,
				"Failed to f%ssync inode 0x%llx.  Error %u.",
				datasync ? "data" : "", ni->mft_no, -ret);
	if (!ret)
		blkdev_issue_flush(vi->i_sb->s_bdev);
	return ret;
}

static int ntfs_setattr_size(struct inode *vi, struct iattr *attr)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	struct inode *time_vi = vi;
	bool stream = ntfs_inode_is_named_stream(ni);
	int err;
	loff_t old_size = vi->i_size;

	if (stream && NVolShutdown(ni->vol))
		return -EIO;

	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni)) {
		ntfs_warning(
			vi->i_sb,
			"Changes in inode size are not supported yet for %s files.",
			NInoEncrypted(ni) ? "encrypted" : "compressed");
		return -EOPNOTSUPP;
	}

	err = inode_newsize_ok(vi, attr->ia_size);
	if (err)
		return err;

	inode_dio_wait(vi);

	/*
	 * Serialize with page faults and pagecache instantiation so that
	 * readers cannot observe the size change until the attribute
	 * updates below have completed.
	 */
	if (stream) {
		filemap_invalidate_lock(vi->i_mapping);
		err = filemap_write_and_wait(vi->i_mapping);
		if (err)
			goto out_unlock_mapping;

		mutex_lock(&base_ni->mrec_lock);
		err = ntfs_stream_inode_validate(vi);
		if (err)
			goto out_unlock_mrec;
		time_vi = VFS_I(base_ni);
	} else {
		filemap_invalidate_lock(vi->i_mapping);
	}

	if (attr->ia_size > old_size) {
		truncate_pagecache(vi, old_size);
		i_size_write(vi, attr->ia_size);
		pagecache_isize_extended(vi, old_size, attr->ia_size);
	} else {
		truncate_setsize(vi, attr->ia_size);
	}

	if (stream)
		err = __ntfs_attr_truncate_vfs(ni, attr->ia_size, old_size);
	else
		err = ntfs_truncate_vfs(vi, attr->ia_size, old_size);
	if (err) {
		i_size_write(vi, old_size);
		goto out_unlock_mrec;
	}

	if (stream) {
		inode_set_mtime_to_ts(time_vi,
				inode_set_ctime_current(time_vi));
		mark_inode_dirty(time_vi);
	}

out_unlock_mrec:
	if (stream)
		mutex_unlock(&base_ni->mrec_lock);
out_unlock_mapping:
	filemap_invalidate_unlock(vi->i_mapping);

	return err;
}

/*
 * ntfs_setattr
 *
 * Called from notify_change() when an attribute is being changed.
 *
 * NOTE: Changes in inode size are not supported yet for compressed or
 * encrypted files.
 */
int ntfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
		 struct iattr *attr)
{
	struct inode *vi = d_inode(dentry);
	int err;
	unsigned int ia_valid = attr->ia_valid;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;

	if (NVolShutdown(vol))
		return -EIO;

	err = setattr_prepare(idmap, dentry, attr);
	if (err)
		goto out;

	if ((ia_valid & ATTR_SIZE) &&
	    (NInoCompressed(ni) || NInoEncrypted(ni) ||
	     NInoWofCompressed(ni))) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	if (ia_valid & ATTR_SIZE) {
		err = ntfs_setattr_size(vi, attr);
		if (err)
			goto out;

		ia_valid |= ATTR_MTIME | ATTR_CTIME;
	}

	setattr_copy(idmap, vi, attr);

	if (vol->sb->s_flags & SB_POSIXACL && !S_ISLNK(vi->i_mode)) {
		err = posix_acl_chmod(idmap, dentry, vi->i_mode);
		if (err)
			goto out;
	}

	if (0222 & vi->i_mode)
		ni->flags &= ~FILE_ATTR_READONLY;
	else
		ni->flags |= FILE_ATTR_READONLY;

	if (ia_valid & (ATTR_UID | ATTR_GID | ATTR_MODE)) {
		unsigned int flags = 0;

		if (ia_valid & ATTR_UID)
			flags |= NTFS_EA_UID;
		if (ia_valid & ATTR_GID)
			flags |= NTFS_EA_GID;
		if (ia_valid & ATTR_MODE)
			flags |= NTFS_EA_MODE;

		mutex_lock(&ni->mrec_lock);
		err = ntfs_ea_set_wsl_inode(vi, 0, NULL, flags);
		mutex_unlock(&ni->mrec_lock);
		if (err)
			goto out;

	}

	mark_inode_dirty(vi);
out:
	return err;
}

int ntfs_getattr(struct mnt_idmap *idmap, const struct path *path,
		struct kstat *stat, unsigned int request_mask,
		unsigned int query_flags)
{
	struct inode *inode = d_backing_inode(path->dentry);
	struct ntfs_inode *ni = NTFS_I(inode);

	generic_fillattr(idmap, request_mask, inode, stat);

	stat->blksize = NTFS_SB(inode->i_sb)->cluster_size;
	stat->blocks = (((u64)NTFS_I(inode)->i_dealloc_clusters <<
			NTFS_SB(inode->i_sb)->cluster_size_bits) >> 9) + inode->i_blocks;
	stat->result_mask |= STATX_BTIME;
	stat->btime = NTFS_I(inode)->i_crtime;

	if (NInoCompressed(ni) || NInoWofCompressed(ni))
		stat->attributes |= STATX_ATTR_COMPRESSED;

	if (NInoEncrypted(ni))
		stat->attributes |= STATX_ATTR_ENCRYPTED;

	if (inode->i_flags & S_IMMUTABLE)
		stat->attributes |= STATX_ATTR_IMMUTABLE;

	if (inode->i_flags & S_APPEND)
		stat->attributes |= STATX_ATTR_APPEND;

	stat->attributes_mask |= STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED |
				 STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND;

	/*
	 * If it's a compressed or encrypted file, NTFS currently
	 * does not support DIO. For normal files, we report the bdev
	 * logical block size.
	 */
	if (request_mask & STATX_DIOALIGN && S_ISREG(inode->i_mode)) {
		unsigned int align =
			bdev_logical_block_size(inode->i_sb->s_bdev);

		stat->result_mask |= STATX_DIOALIGN;
		if (!NInoCompressed(ni) && !NInoEncrypted(ni) &&
		    !NInoWofCompressed(ni)) {
			stat->dio_mem_align = align;
			stat->dio_offset_align = align;
		}
	}

	return 0;
}

static struct dentry *ntfs_stream_base_dentry(struct inode *inode)
{
	struct inode *base_vi =
		VFS_I(NTFS_I(inode)->ext.base_ntfs_ino);
	struct dentry *dentry;

	dentry = d_find_alias(base_vi);
	if (dentry)
		return dentry;
	if (!igrab(base_vi))
		return ERR_PTR(-ESTALE);
	return d_obtain_alias(base_vi);
}

static int ntfs_stream_validate_for_mutation(struct inode *inode)
{
	struct ntfs_inode *base_ni = NTFS_I(inode)->ext.base_ntfs_ino;
	int err;

	mutex_lock(&base_ni->mrec_lock);
	err = ntfs_stream_inode_validate(inode);
	mutex_unlock(&base_ni->mrec_lock);
	return err;
}

static int ntfs_stream_needs_remove_privs(struct mnt_idmap *idmap,
		struct dentry *base_dentry)
{
	struct inode *base_vi = d_inode(base_dentry);
	int kill;

	if (IS_NOSEC(base_vi))
		return 0;

	/*
	 * Let notify_change() perform the LSM killpriv check through the
	 * exported VFS interface.
	 */
	kill = setattr_should_drop_suidgid(idmap, base_vi);
	return kill | ATTR_KILL_PRIV;
}

static int ntfs_stream_file_modified(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct inode *base_vi =
		VFS_I(NTFS_I(inode)->ext.base_ntfs_ino);
	struct ntfs_inode *base_ni = NTFS_I(base_vi);
	struct dentry *base_dentry;
	struct iattr attr = {};
	int err, kill;

	base_dentry = ntfs_stream_base_dentry(inode);
	if (IS_ERR(base_dentry))
		return PTR_ERR(base_dentry);

	inode_lock(base_vi);
	err = ntfs_stream_validate_for_mutation(inode);
	if (err)
		goto out_unlock;

	kill = ntfs_stream_needs_remove_privs(file_mnt_idmap(file),
			base_dentry);
	if (kill < 0) {
		err = kill;
		goto out_unlock;
	}
	if (kill) {
		err = ntfs_stream_validate_for_mutation(inode);
		if (err)
			goto out_unlock;
		attr.ia_valid = ATTR_FORCE | kill;
		err = notify_change(file_mnt_idmap(file), base_dentry, &attr,
				NULL);
		if (err)
			goto out_unlock;
		inode_has_no_xattr(base_vi);
	}

	if (!IS_NOCMTIME(base_vi) &&
	    !(file->f_mode & FMODE_NOCMTIME)) {
		mutex_lock(&base_ni->mrec_lock);
		if (NVolShutdown(base_ni->vol))
			err = -EIO;
		else
			err = generic_update_time(base_vi, FS_UPD_CMTIME, 0);
		mutex_unlock(&base_ni->mrec_lock);
	}

out_unlock:
	inode_unlock(base_vi);
	dput(base_dentry);
	return err;
}

static int ntfs_file_modified(struct file *file)
{
	if (ntfs_inode_is_named_stream(NTFS_I(file_inode(file))))
		return ntfs_stream_file_modified(file);
	return file_modified(file);
}

static int ntfs_stream_claim(struct inode *inode)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_inode *base_ni = ni->ext.base_ntfs_ino;
	int err;

	mutex_lock(&base_ni->mrec_lock);
	if (NInoStreamUnlinked(ni))
		err = -ESTALE;
	else
		err = ntfs_stream_inode_validate(inode);
	if (!err) {
		if (atomic_read(&ni->stream_open_count) < 0)
			err = -ESTALE;
		else
			atomic_inc(&ni->stream_open_count);
	}
	mutex_unlock(&base_ni->mrec_lock);
	return err;
}

static int ntfs_stream_permission(struct mnt_idmap *idmap,
		struct inode *inode, int mask)
{
	return inode_permission(idmap,
			VFS_I(NTFS_I(inode)->ext.base_ntfs_ino), mask);
}

static int ntfs_stream_getattr(struct mnt_idmap *idmap,
		const struct path *path, struct kstat *stat,
		unsigned int request_mask, unsigned int query_flags)
{
	struct inode *inode = d_backing_inode(path->dentry);
	struct ntfs_inode *ni = NTFS_I(inode);
	struct inode *base_vi = VFS_I(ni->ext.base_ntfs_ino);

	generic_fillattr(idmap, request_mask, base_vi, stat);
	stat->size = i_size_read(inode);
	stat->blocks = (((u64)ni->i_dealloc_clusters <<
			NTFS_SB(inode->i_sb)->cluster_size_bits) >> 9) +
			inode->i_blocks;
	stat->blksize = NTFS_SB(inode->i_sb)->cluster_size;
	stat->result_mask |= STATX_BTIME;
	stat->btime = NTFS_I(base_vi)->i_crtime;

	if (NInoCompressed(ni))
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (NInoEncrypted(ni))
		stat->attributes |= STATX_ATTR_ENCRYPTED;
	if (base_vi->i_flags & S_IMMUTABLE)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (base_vi->i_flags & S_APPEND)
		stat->attributes |= STATX_ATTR_APPEND;
	stat->attributes_mask |= STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED |
			STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND;

	if (request_mask & STATX_DIOALIGN) {
		unsigned int align =
			bdev_logical_block_size(inode->i_sb->s_bdev);

		stat->result_mask |= STATX_DIOALIGN;
		if (!NInoCompressed(ni) && !NInoEncrypted(ni)) {
			stat->dio_mem_align = align;
			stat->dio_offset_align = align;
		}
	}

	return 0;
}

static int ntfs_stream_setattr_common(struct mnt_idmap *idmap,
		struct inode *inode, struct iattr *attr)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct inode *base_vi = VFS_I(ni->ext.base_ntfs_ino);
	struct dentry *base_dentry = NULL;
	struct iattr base_attr = *attr;
	int err;

	if (attr->ia_valid & ATTR_SIZE) {
		err = inode_permission(idmap, base_vi, MAY_WRITE);
		if (err)
			goto out;
		if (IS_APPEND(base_vi) || IS_IMMUTABLE(base_vi)) {
			err = -EPERM;
			goto out;
		}
		if (!(ni->vol->vol_flags & VOLUME_IS_DIRTY)) {
			err = ntfs_set_volume_flags(ni->vol, VOLUME_IS_DIRTY);
			if (err)
				goto out;
		}
		base_attr.ia_valid &= ~ATTR_SIZE;
	}

	if ((attr->ia_valid & ATTR_SIZE) || base_attr.ia_valid) {
		int kill = 0;

		base_dentry = ntfs_stream_base_dentry(inode);
		if (IS_ERR(base_dentry)) {
			err = PTR_ERR(base_dentry);
			base_dentry = NULL;
			goto out;
		}
		inode_lock(base_vi);
		if ((attr->ia_valid & ATTR_SIZE) ||
		    (base_attr.ia_valid &
		     (ATTR_KILL_SUID | ATTR_KILL_SGID | ATTR_KILL_PRIV))) {
			kill = ntfs_stream_needs_remove_privs(idmap,
					base_dentry);
			if (kill < 0) {
				err = kill;
				inode_unlock(base_vi);
				goto out;
			}
			base_attr.ia_valid &= ~(ATTR_KILL_SUID |
					ATTR_KILL_SGID | ATTR_KILL_PRIV);
			base_attr.ia_valid |= kill;
		}
		err = ntfs_stream_validate_for_mutation(inode);
		if (err) {
			inode_unlock(base_vi);
			goto out;
		}
		if (base_attr.ia_valid)
			err = notify_change(idmap, base_dentry, &base_attr,
					NULL);
		else
			err = 0;
		inode_unlock(base_vi);
		if (err)
			goto out;
	}

	if (attr->ia_valid & ATTR_SIZE)
		err = ntfs_setattr_size(inode, attr);
	else
		err = 0;
out:
	dput(base_dentry);
	return err;
}

static int ntfs_stream_setattr(struct mnt_idmap *idmap,
		struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct ntfs_inode *ni = NTFS_I(inode);
	bool claimed = false;
	int err;

	if (NVolShutdown(ni->vol))
		return -EIO;

	if (!(attr->ia_valid & ATTR_FILE)) {
		err = ntfs_stream_claim(inode);
		if (err)
			return err;
		claimed = true;
	}

	err = ntfs_stream_setattr_common(idmap, inode, attr);
	if (claimed)
		ntfs_stream_put(inode);
	return err;
}

static int ntfs_stream_truncate_file(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct iattr attr = {
		.ia_size = 0,
		.ia_valid = ATTR_SIZE | ATTR_MTIME | ATTR_CTIME | ATTR_FILE,
		.ia_file = file,
	};
	int err;

	if (NVolShutdown(NTFS_SB(inode->i_sb)))
		return -EIO;

	/*
	 * The common setattr helper performs stream permission, privilege,
	 * validation, page-cache, and NTFS attribute handling. ATTR_FILE
	 * avoids taking a second stream claim.
	 */
	err = inode_lock_killable(inode);
	if (err)
		return err;
	err = ntfs_stream_setattr_common(file_mnt_idmap(file), inode, &attr);
	inode_unlock(inode);
	return err;
}

static int ntfs_stream_update_time(struct inode *inode,
		enum fs_update_time type, unsigned int flags)
{
	struct ntfs_inode *base_ni = NTFS_I(inode)->ext.base_ntfs_ino;
	struct inode *base_vi = VFS_I(base_ni);
	int err;

	if (NVolShutdown(base_ni->vol))
		return -EIO;

	inode_lock(base_vi);
	mutex_lock(&base_ni->mrec_lock);
	err = ntfs_stream_inode_validate(inode);
	if (!err)
		err = generic_update_time(base_vi, type, flags);
	mutex_unlock(&base_ni->mrec_lock);
	inode_unlock(base_vi);
	return err;
}

static ssize_t ntfs_stream_listxattr(struct dentry *dentry, char *buffer,
		size_t size)
{
	return -EOPNOTSUPP;
}

#ifdef CONFIG_NTFS_FS_POSIX_ACL
static struct posix_acl *ntfs_stream_get_acl(struct mnt_idmap *idmap,
		struct dentry *dentry, int type)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static int ntfs_stream_set_acl(struct mnt_idmap *idmap,
		struct dentry *dentry, struct posix_acl *acl, int type)
{
	return -EOPNOTSUPP;
}
#endif

static loff_t ntfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;

	if (NInoWofCompressed(NTFS_I(inode)) &&
	    (whence == SEEK_HOLE || whence == SEEK_DATA))
		return -EOPNOTSUPP;

	switch (whence) {
	case SEEK_HOLE:
		inode_lock_shared(inode);
		offset = iomap_seek_hole(inode, offset, &ntfs_seek_iomap_ops);
		inode_unlock_shared(inode);
		break;
	case SEEK_DATA:
		inode_lock_shared(inode);
		offset = iomap_seek_data(inode, offset, &ntfs_seek_iomap_ops);
		inode_unlock_shared(inode);
		break;
	default:
		return generic_file_llseek_size(file, offset, whence,
						inode->i_sb->s_maxbytes,
						i_size_read(inode));
	}
	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, inode->i_sb->s_maxbytes);
}

static ssize_t ntfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *vi = file_inode(iocb->ki_filp);
	struct super_block *sb = vi->i_sb;
	ssize_t ret;

	if (NVolShutdown(NTFS_SB(sb)))
		return -EIO;

	if ((NInoCompressed(NTFS_I(vi)) || NInoWofCompressed(NTFS_I(vi))) &&
	    iocb->ki_flags & IOCB_DIRECT)
		return -EOPNOTSUPP;

	inode_lock_shared(vi);

	if (iocb->ki_flags & IOCB_DIRECT) {
		size_t count = iov_iter_count(to);

		if ((iocb->ki_pos | count) & (sb->s_blocksize - 1)) {
			ret = -EINVAL;
			goto inode_unlock;
		}

		file_accessed(iocb->ki_filp);
		ret = iomap_dio_rw(iocb, to, &ntfs_read_iomap_ops, NULL, 0,
				NULL, 0);
	} else {
		ret = generic_file_read_iter(iocb, to);
	}

inode_unlock:
	inode_unlock_shared(vi);

	return ret;
}

static int ntfs_file_write_dio_end_io(struct kiocb *iocb, ssize_t size,
		int error, unsigned int flags)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	if (error)
		return error;

	if (size) {
		if (i_size_read(inode) < iocb->ki_pos + size) {
			i_size_write(inode, iocb->ki_pos + size);
			if (ntfs_inode_is_named_stream(NTFS_I(inode)))
				mark_inode_dirty(VFS_I(
					NTFS_I(inode)->ext.base_ntfs_ino));
			else
				mark_inode_dirty(inode);
		}
	}

	return 0;
}

static const struct iomap_dio_ops ntfs_write_dio_ops = {
	.end_io			= ntfs_file_write_dio_end_io,
};

static ssize_t ntfs_dio_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;

	ret = iomap_dio_rw(iocb, from, &ntfs_dio_iomap_ops,
			&ntfs_write_dio_ops, 0, NULL, 0);
	if (ret == -ENOTBLK)
		ret = 0;
	else if (ret < 0)
		goto out;

	if (iov_iter_count(from)) {
		loff_t offset, end;
		ssize_t written;
		int ret2;

		offset = iocb->ki_pos;
		iocb->ki_flags &= ~IOCB_DIRECT;
		written = iomap_file_buffered_write(iocb, from,
				&ntfs_write_iomap_ops, &ntfs_iomap_folio_ops,
				NULL);
		if (written < 0) {
			ret = written;
			goto out;
		}

		ret += written;
		end = iocb->ki_pos + written - 1;
		ret2 = filemap_write_and_wait_range(iocb->ki_filp->f_mapping,
				offset, end);
		if (ret2) {
			ret = -EIO;
			goto out;
		}
		invalidate_mapping_pages(iocb->ki_filp->f_mapping,
					 offset >> PAGE_SHIFT,
					 end >> PAGE_SHIFT);
	}

out:
	return ret;
}

static int ntfs_expand_for_write(struct ntfs_inode *ni, loff_t end)
{
	struct ntfs_volume *vol = ni->vol;
	struct ntfs_inode *mrec_ni = ntfs_base_inode(ni);
	loff_t prealloc_size = 0;
	int err;

	if (end <= ni->data_size)
		return 0;

	if (NInoCompressed(ni)) {
		if (end > ni->allocated_size)
			prealloc_size = round_up(end,
						 ni->itype.compressed.block_size);
	} else if (end > ni->allocated_size &&
		   end < ni->allocated_size + vol->preallocated_size) {
		prealloc_size = ni->allocated_size + vol->preallocated_size;
	}

	mutex_lock(&mrec_ni->mrec_lock);
	err = ntfs_attr_expand(ni, end, prealloc_size);
	mutex_unlock(&mrec_ni->mrec_lock);

	return err;
}

static ssize_t ntfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *vi = file->f_mapping->host;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	ssize_t ret;
	ssize_t count;
	loff_t pos, end;
	int err;
	loff_t old_data_size, old_init_size;

	if (NVolShutdown(vol))
		return -EIO;

	if (NInoWofCompressed(ni))
		return -EOPNOTSUPP;

	if (NInoEncrypted(ni)) {
		ntfs_error(vi->i_sb, "Writing for %s files is not supported yet",
			   NInoCompressed(ni) ? "Compressed" : "Encrypted");
		return -EOPNOTSUPP;
	}

	if (NInoCompressed(ni) && iocb->ki_flags & IOCB_DIRECT)
		return -EOPNOTSUPP;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock(vi))
			return -EAGAIN;
	} else
		inode_lock(vi);

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out_lock;

	err = ntfs_file_modified(iocb->ki_filp);
	if (err) {
		ret = err;
		goto out_lock;
	}

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	pos = iocb->ki_pos;
	count = ret;
	end = pos + count;

	old_data_size = ni->data_size;
	old_init_size = ni->initialized_size;

	if (end > old_data_size) {
		ret = ntfs_expand_for_write(ni, end);
		if (ret < 0)
			goto out;
	}

	if (NInoNonResident(ni) && !NInoCompressed(ni) &&
	    end > old_init_size) {
		ret = ntfs_extend_initialized_size(vi, pos, end);
		if (ret < 0)
			goto out;
	}

	if (NInoNonResident(ni) && NInoCompressed(ni)) {
		ret = ntfs_compress_write(ni, pos, count, from);
		if (ret > 0)
			iocb->ki_pos += ret;
		goto out;
	}

	if (NInoNonResident(ni) && iocb->ki_flags & IOCB_DIRECT)
		ret = ntfs_dio_write_iter(iocb, from);
	else
		ret = iomap_file_buffered_write(iocb, from, &ntfs_write_iomap_ops,
				&ntfs_iomap_folio_ops, NULL);
out:
	if (ret < 0 && ret != -EIOCBQUEUED) {
		if (ni->initialized_size != old_init_size) {
			struct ntfs_inode *mrec_ni =
				ntfs_base_inode(ni);

			mutex_lock(&mrec_ni->mrec_lock);
			ntfs_attr_set_initialized_size(ni, old_init_size);
			mutex_unlock(&mrec_ni->mrec_lock);
		}
		if (ni->data_size != old_data_size) {
			struct ntfs_inode *mrec_ni =
				ntfs_base_inode(ni);

			truncate_setsize(vi, old_data_size);
			mutex_lock(&mrec_ni->mrec_lock);
			ntfs_attr_truncate(ni, old_data_size);
			mutex_unlock(&mrec_ni->mrec_lock);
		}
	}
out_lock:
	inode_unlock(vi);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}

static vm_fault_t ntfs_filemap_page_mkwrite(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct address_space *mapping = inode->i_mapping;
	bool stream = ntfs_inode_is_named_stream(NTFS_I(inode));
	int err;
	vm_fault_t ret;

	if (NInoWofCompressed(NTFS_I(inode)))
		return VM_FAULT_SIGBUS;

	sb_start_pagefault(inode->i_sb);
	if (stream) {
		err = ntfs_stream_file_modified(vmf->vma->vm_file);
		if (err) {
			ret = vmf_error(err);
			goto out;
		}
	} else {
		file_update_time(vmf->vma->vm_file);
	}

	/*
	 * Serialize against truncate/fallocate which hold the lock
	 * exclusively while invalidating pagecache and changing extents.
	 */
	filemap_invalidate_lock_shared(mapping);
	ret = iomap_page_mkwrite(vmf, &ntfs_page_mkwrite_iomap_ops, NULL);
	filemap_invalidate_unlock_shared(mapping);

out:
	sb_end_pagefault(inode->i_sb);
	return ret;
}

static const struct vm_operations_struct ntfs_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= ntfs_filemap_page_mkwrite,
};

static int ntfs_file_mmap_prepare(struct vm_area_desc *desc)
{
	struct file *file = desc->file;
	struct inode *inode = file_inode(file);

	if (NVolShutdown(NTFS_SB(file->f_mapping->host->i_sb)))
		return -EIO;

	if (NInoCompressed(NTFS_I(inode)) || NInoWofCompressed(NTFS_I(inode)))
		return -EOPNOTSUPP;

	if (vma_desc_test_all(desc, VMA_SHARED_BIT, VMA_MAYWRITE_BIT)) {
		struct inode *inode = file_inode(file);
		loff_t from, to;
		int err;

		from = ((loff_t)desc->pgoff << PAGE_SHIFT);
		to = min_t(loff_t, i_size_read(inode),
			   from + desc->end - desc->start);

		if (NTFS_I(inode)->initialized_size < to) {
			err = ntfs_extend_initialized_size(inode, to, to);
			if (err)
				return err;
		}
	}


	file_accessed(file);
	desc->vm_ops = &ntfs_file_vm_ops;
	return 0;
}

static int ntfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 len)
{
	if (NInoWofCompressed(NTFS_I(inode)))
		return -EOPNOTSUPP;

	return iomap_fiemap(inode, fieinfo, start, len, &ntfs_read_iomap_ops);
}

static const char *ntfs_get_link(struct dentry *dentry, struct inode *inode,
		struct delayed_call *done)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	char *target;
	int err;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	if (!ni->target)
		return ERR_PTR(-EINVAL);

	if (ni->reparse_tag == IO_REPARSE_TAG_MOUNT_POINT ||
	    (ni->reparse_tag == IO_REPARSE_TAG_SYMLINK &&
	     !(ni->reparse_flags & cpu_to_le32(SYMLINK_FLAG_RELATIVE)))) {
		if (NVolNativeSymlinkRel(ni->vol)) {
			err = ntfs_translate_symlink_path(dentry, ni->target, &target);
			if (err < 0)
				return ERR_PTR(err);
			set_delayed_call(done, kfree_link, target);
			return target;
		}
	}

	return ni->target;
}

static ssize_t ntfs_file_splice_read(struct file *in, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	if (NVolShutdown(NTFS_SB(in->f_mapping->host->i_sb)))
		return -EIO;

	return filemap_splice_read(in, ppos, pipe, len, flags);
}

static int ntfs_ioctl_shutdown(struct super_block *sb, unsigned long arg)
{
	u32 flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(flags, (__u32 __user *)arg))
		return -EFAULT;

	return ntfs_force_shutdown(sb, flags);
}

static int ntfs_ioctl_get_volume_label(struct file *filp, unsigned long arg)
{
	struct ntfs_volume *vol = NTFS_SB(file_inode(filp)->i_sb);
	char __user *buf = (char __user *)arg;
	char label[FSLABEL_MAX];
	ssize_t len;

	mutex_lock(&vol->volume_label_lock);
	if (!vol->volume_label) {
		label[0] = '\0';
		len = 0;
	} else {
		len = strscpy(label, vol->volume_label, sizeof(label));
		if (len == -E2BIG)
			len = FSLABEL_MAX - 1;
	}
	mutex_unlock(&vol->volume_label_lock);

	if (copy_to_user(buf, label, len + 1))
		return -EFAULT;
	return 0;
}

static int ntfs_ioctl_set_volume_label(struct file *filp, unsigned long arg)
{
	struct ntfs_volume *vol = NTFS_SB(file_inode(filp)->i_sb);
	char *label;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	label = strndup_user((const char __user *)arg, FSLABEL_MAX);
	if (IS_ERR(label))
		return PTR_ERR(label);

	ret = mnt_want_write_file(filp);
	if (ret)
		goto out;

	ret = ntfs_write_volume_label(vol, label);
	mnt_drop_write_file(filp);
out:
	kfree(label);
	return ret;
}

static int ntfs_ioctl_fitrim(struct ntfs_volume *vol, unsigned long arg)
{
	struct fstrim_range __user *user_range;
	struct fstrim_range range;
	struct block_device *dev;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	dev = vol->sb->s_bdev;
	if (!bdev_max_discard_sectors(dev))
		return -EOPNOTSUPP;

	user_range = (struct fstrim_range __user *)arg;
	if (copy_from_user(&range, user_range, sizeof(range)))
		return -EFAULT;

	if (range.len == 0)
		return -EINVAL;

	if (range.len < vol->cluster_size)
		return -EINVAL;

	range.minlen = max_t(u32, range.minlen, bdev_discard_granularity(dev));

	err = ntfs_trim_fs(vol, &range);
	if (err < 0)
		return err;

	if (copy_to_user(user_range, &range, sizeof(range)))
		return -EFAULT;

	return 0;
}

#define NTFS_STREAM_OPEN_ALLOWED_FLAGS \
	(O_ACCMODE | O_APPEND | O_CLOEXEC | O_CREAT | O_DIRECT | O_DSYNC | \
	 O_EXCL | O_LARGEFILE | O_NOATIME | O_NONBLOCK | O_SYNC | O_TRUNC)

static int ntfs_stream_finish_remove(struct inode *attr_vi)
{
	struct ntfs_inode *attr_ni = NTFS_I(attr_vi);
	struct ntfs_inode *ni = attr_ni->ext.base_ntfs_ino;
	int err;

	mutex_lock(&ni->mrec_lock);
	if (!NInoStreamUnlinked(attr_ni) ||
	    atomic_cmpxchg(&attr_ni->stream_open_count, 0, -1)) {
		err = 0;
		goto out_unlock;
	}
	if (NInoBeingDeleted(ni) || !VFS_I(ni)->i_nlink) {
		remove_inode_hash(attr_vi);
		err = 0;
		goto out_unlock;
	}
	mutex_unlock(&ni->mrec_lock);

	truncate_inode_pages(attr_vi->i_mapping, 0);

	mutex_lock(&ni->mrec_lock);
	if (NVolShutdown(ni->vol)) {
		err = -EIO;
		goto out_unlock;
	}
	if (NInoBeingDeleted(ni) || !VFS_I(ni)->i_nlink) {
		remove_inode_hash(attr_vi);
		err = 0;
		goto out_unlock;
	}
	err = ntfs_attr_rm(attr_ni);
	if (!err) {
		NInoClearDirty(attr_ni);
		remove_inode_hash(attr_vi);
	} else {
		NInoSetBeingDeleted(attr_ni);
		remove_inode_hash(attr_vi);
		NVolSetErrors(ni->vol);
		NVolSetShutdown(ni->vol);
	}

out_unlock:
	mutex_unlock(&ni->mrec_lock);
	return err;
}

int ntfs_stream_put(struct inode *vi)
{
	struct ntfs_inode *ni = NTFS_I(vi);

	if (atomic_dec_and_test(&ni->stream_open_count) &&
	    NInoStreamUnlinked(ni))
		return ntfs_stream_finish_remove(vi);
	return 0;
}

/*
 * ntfs_remove_named_stream - Remove a named $DATA stream.
 *
 * @ni:		NTFS inode
 * @uname:	Stream name
 * @uname_len:	Name length in Unicode characters
 *
 * Return:	0 on success, negative error
 *              -ENOENT if stream not found
 */
int ntfs_remove_named_stream(struct ntfs_inode *ni, __le16 *uname,
		u32 uname_len, struct inode *expected_vi)
{
	struct inode *attr_vi;
	struct ntfs_inode *attr_ni;
	int err;

	if (!ni || !uname || uname_len == 0)
		return -EINVAL;
	if (NVolShutdown(ni->vol))
		return -EIO;
	if (IS_APPEND(VFS_I(ni)) || IS_IMMUTABLE(VFS_I(ni)))
		return -EPERM;
	if (!(ni->vol->vol_flags & VOLUME_IS_DIRTY)) {
		err = ntfs_set_volume_flags(ni->vol, VOLUME_IS_DIRTY);
		if (err)
			return err;
	}

	mutex_lock(&ni->mrec_lock);
	if (NInoBeingDeleted(ni) || !VFS_I(ni)->i_nlink) {
		err = -ENOENT;
		goto out_unlock;
	}
	attr_vi = ntfs_attr_iget(VFS_I(ni), AT_DATA, uname, uname_len);
	if (IS_ERR(attr_vi)) {
		err = PTR_ERR(attr_vi);
		goto out_unlock;
	}
	if (expected_vi && attr_vi != expected_vi) {
		err = -ESTALE;
		goto out_iput;
	}

	attr_ni = NTFS_I(attr_vi);
	if (NInoStreamUnlinked(attr_ni)) {
		err = -ENOENT;
		goto out_iput;
	}
	err = ntfs_stream_inode_validate(attr_vi);
	if (err)
		goto out_iput;

	NInoSetStreamUnlinked(attr_ni);
	clear_nlink(attr_vi);
	inode_set_mtime_to_ts(VFS_I(ni),
			inode_set_ctime_current(VFS_I(ni)));
	mark_inode_dirty(VFS_I(ni));
	mutex_unlock(&ni->mrec_lock);

	err = ntfs_stream_finish_remove(attr_vi);
	iput(attr_vi);
	return err;

out_iput:
	iput(attr_vi);
out_unlock:
	mutex_unlock(&ni->mrec_lock);
	return err;
}

static int ntfs_stream_file_open(struct inode *inode, struct file *file)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_inode *base_ni = ni->ext.base_ntfs_ino;
	struct inode *base_vi = VFS_I(base_ni);
	int mask = MAY_OPEN;
	int err;

	if (file->f_mode & FMODE_READ)
		mask |= MAY_READ;
	if (file->f_mode & FMODE_WRITE)
		mask |= MAY_WRITE;
	err = inode_permission(file_mnt_idmap(file), base_vi, mask);
	if (err)
		return err;

	mutex_lock(&base_ni->mrec_lock);
	if (NInoStreamUnlinked(ni))
		err = -ENOENT;
	else
		err = ntfs_stream_inode_validate(inode);
	if (err)
		goto out_unlock;
	if ((file->f_mode & FMODE_WRITE) &&
	    (IS_IMMUTABLE(base_vi) ||
	     (IS_APPEND(base_vi) && !(file->f_flags & O_APPEND)))) {
		err = -EPERM;
		goto out_unlock;
	}
	if ((file->f_flags & O_TRUNC) && IS_APPEND(base_vi)) {
		err = -EPERM;
		goto out_unlock;
	}
	if ((file->f_flags & O_NOATIME) &&
	    !inode_owner_or_capable(file_mnt_idmap(file), base_vi)) {
		err = -EPERM;
		goto out_unlock;
	}
	err = ntfs_file_open(inode, file);
	if (err)
		goto out_unlock;
	if (file->f_mode & FMODE_WRITE) {
		err = get_write_access(base_vi);
		if (err)
			goto out_unlock;
		file->private_data = base_vi;
	}

	atomic_inc(&ni->stream_open_count);
out_unlock:
	mutex_unlock(&base_ni->mrec_lock);
	return err;
}

static int ntfs_stream_file_release(struct inode *inode, struct file *file)
{
	int err, remove_err;

	err = ntfs_file_release(inode, file);
	if (file->private_data) {
		put_write_access(file->private_data);
		file->private_data = NULL;
	}
	remove_err = ntfs_stream_put(inode);
	if (!err)
		err = remove_err;
	return err;
}

static int ntfs_stream_open_access(struct file *filp, int flags)
{
	struct inode *inode = file_inode(filp);
	struct mnt_idmap *idmap = file_mnt_idmap(filp);
	int mask = MAY_OPEN;
	int err;

	switch (flags & O_ACCMODE) {
	case O_RDONLY:
		mask |= MAY_READ;
		break;
	case O_WRONLY:
		mask |= MAY_WRITE;
		break;
	case O_RDWR:
		mask |= MAY_READ | MAY_WRITE;
		break;
	default:
		return -EINVAL;
	}
	if (flags & (O_CREAT | O_TRUNC))
		mask |= MAY_WRITE;

	err = inode_permission(idmap, inode, mask);
	if (err)
		return err;
	if (IS_APPEND(inode)) {
		if ((flags & O_ACCMODE) != O_RDONLY && !(flags & O_APPEND))
			return -EPERM;
		if (flags & O_TRUNC)
			return -EPERM;
	}
	if ((flags & O_NOATIME) && !inode_owner_or_capable(idmap, inode))
		return -EPERM;
	return 0;
}

static long ntfs_ioctl_stream_open(struct file *filp, unsigned long arg)
{
	struct inode *base_vi = file_inode(filp);
	struct ntfs_inode *ni = NTFS_I(base_vi);
	struct ntfs_stream_open hdr;
	struct ntfs_stream_open *req;
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct inode *attr_vi = NULL;
	struct dentry *stream_dentry;
	struct file *stream_file;
	struct path stream_path;
	__le16 *uname = NULL, *sname;
	size_t total_size;
	int sname_len, err, fd;
	bool got_write = false, utf16;

	if (NVolShutdown(ni->vol))
		return -EIO;
	if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr)))
		return -EFAULT;

	if ((hdr.flags & ~NTFS_STREAM_FL_UTF16_NAME) || hdr.reserved ||
		(hdr.open_flags & ~NTFS_STREAM_OPEN_ALLOWED_FLAGS))
		return -EINVAL;

	if (!hdr.name_len)
		return -EINVAL;
	utf16 = hdr.flags & NTFS_STREAM_FL_UTF16_NAME;
	if (utf16) {
		if ((hdr.name_len & 1) ||
		    hdr.name_len > NTFS_MAX_NAME_LEN * sizeof(__le16))
			return -EINVAL;
	} else if (hdr.name_len >
			NTFS_MAX_NAME_LEN * NLS_MAX_CHARSET_SIZE) {
		return -EINVAL;
	}

	if ((hdr.open_flags & O_ACCMODE) == O_ACCMODE ||
		((hdr.open_flags & O_ACCMODE) != O_RDONLY &&
		 !(filp->f_mode & FMODE_WRITE)) ||
		((hdr.open_flags & O_ACCMODE) != O_WRONLY &&
		 !(filp->f_mode & FMODE_READ)) ||
		((hdr.open_flags & (O_CREAT | O_TRUNC)) &&
		 !(filp->f_mode & FMODE_WRITE)) ||
		((hdr.open_flags & O_TRUNC) &&
		 !(hdr.open_flags & O_ACCMODE)) ||
		((hdr.open_flags & O_EXCL) && !(hdr.open_flags & O_CREAT)))
		return -EBADF;

	err = ntfs_stream_open_access(filp, hdr.open_flags);
	if (err)
		return err;

	if (check_add_overflow(sizeof(hdr), (size_t)hdr.name_len, &total_size))
		return -EOVERFLOW;

	req = memdup_user((void __user *)arg, total_size);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (req->name_len != hdr.name_len || req->flags != hdr.flags ||
		req->open_flags != hdr.open_flags || req->reserved) {
		err = -EINVAL;
		goto out_free_req;
	}
	if (force_o_largefile())
		hdr.open_flags |= O_LARGEFILE;

	if (!utf16 && memchr(req->name, '\0', req->name_len)) {
		err = -EINVAL;
		goto out_free_req;
	}

	if (utf16) {
		sname = (__le16 *)req->name;
		sname_len = req->name_len / sizeof(__le16);
	} else {
		sname_len = ntfs_nlstoucs(ni->vol, req->name, req->name_len,
				&uname, NTFS_MAX_NAME_LEN);
		if (sname_len < 0) {
			err = sname_len;
			goto out_free_req;
		}
		sname = uname;
	}

	if (hdr.open_flags & (O_CREAT | O_TRUNC)) {
		err = mnt_want_write_file(filp);
		if (err)
			goto out_free_req;
		got_write = true;
	}
	if ((hdr.open_flags & O_CREAT) &&
	    !(ni->vol->vol_flags & VOLUME_IS_DIRTY)) {
		err = ntfs_set_volume_flags(ni->vol, VOLUME_IS_DIRTY);
		if (err)
			goto out_free_req;
	}

	mutex_lock(&ni->mrec_lock);
	if (NVolShutdown(ni->vol)) {
		err = -EIO;
		goto out_unlock;
	}
	if (NInoBeingDeleted(ni) || !base_vi->i_nlink) {
		err = -ENOENT;
		goto out_unlock;
	}
	if ((hdr.open_flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) &&
	    IS_IMMUTABLE(base_vi)) {
		err = -EPERM;
		goto out_unlock;
	}
	if (IS_APPEND(base_vi) &&
	    (((hdr.open_flags & O_ACCMODE) != O_RDONLY &&
	      !(hdr.open_flags & O_APPEND)) ||
	     (hdr.open_flags & O_TRUNC))) {
		err = -EPERM;
		goto out_unlock;
	}

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unlock;
	}

	err = ntfs_attr_lookup(AT_DATA, sname, sname_len, CASE_SENSITIVE,
		0, NULL, 0, ctx);
	if (!err) {
		if ((hdr.open_flags & (O_CREAT | O_EXCL)) ==
				(O_CREAT | O_EXCL)) {
			err = -EEXIST;
			goto out_put_ctx;
		}
	} else if (err == -ENOENT && (hdr.open_flags & O_CREAT)) {
		if (NVolShutdown(ni->vol)) {
			err = -EIO;
			goto out_put_ctx;
		}
		err = ntfs_attr_add(ni, AT_DATA, sname, sname_len, NULL, 0);
		if (err)
			goto out_put_ctx;
		mark_mft_record_dirty(ni);
		inode_set_mtime_to_ts(base_vi,
				inode_set_ctime_current(base_vi));
		mark_inode_dirty(base_vi);
	} else if (err) {
		goto out_put_ctx;
	}

	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	attr_vi = ntfs_attr_iget(base_vi, AT_DATA, sname, sname_len);
	if (!IS_ERR(attr_vi)) {
		if (NInoStreamUnlinked(NTFS_I(attr_vi)))
			err = (hdr.open_flags & O_CREAT) ? -EBUSY : -ENOENT;
		else
			err = ntfs_stream_inode_validate(attr_vi);
		if (err) {
			iput(attr_vi);
			attr_vi = ERR_PTR(err);
		}
	}
out_unlock:
	mutex_unlock(&ni->mrec_lock);
	if (IS_ERR(attr_vi)) {
		err = PTR_ERR(attr_vi);
		attr_vi = NULL;
		goto out_free_req;
	}
	if (!attr_vi)
		goto out_free_req;

	if (uname)
		kmem_cache_free(ntfs_name_cache, uname);
	kfree(req);
	uname = NULL;
	req = NULL;

	attr_vi->i_op = &ntfs_stream_inode_ops;
	attr_vi->i_fop = &ntfs_stream_file_ops;
	stream_dentry = d_obtain_alias(attr_vi);
	attr_vi = NULL;
	if (IS_ERR(stream_dentry)) {
		err = PTR_ERR(stream_dentry);
		goto out;
	}

	stream_path.mnt = mntget(filp->f_path.mnt);
	stream_path.dentry = stream_dentry;
	stream_file = dentry_open(&stream_path, hdr.open_flags, current_cred());
	path_put(&stream_path);
	if (IS_ERR(stream_file)) {
		err = PTR_ERR(stream_file);
		goto out;
	}
	err = security_file_post_open(stream_file,
			(stream_file->f_mode & FMODE_READ ? MAY_READ : 0) |
			(stream_file->f_mode & FMODE_WRITE ? MAY_WRITE : 0));
	if (err)
		goto out_fput;

	if (hdr.open_flags & O_TRUNC) {
		err = ntfs_stream_truncate_file(stream_file);
		if (err)
			goto out_fput;
	}

	stream_file->f_flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
	fd = get_unused_fd_flags(hdr.open_flags & O_CLOEXEC);
	if (fd < 0) {
		err = fd;
		goto out_fput;
	}
	if (got_write) {
		mnt_drop_write_file(filp);
		got_write = false;
	}
	fd_install(fd, stream_file);
	return fd;

out_fput:
	fput(stream_file);
out:
	if (attr_vi)
		iput(attr_vi);
out_free_req:
	if (ctx) {
		ntfs_attr_put_search_ctx(ctx);
		mutex_unlock(&ni->mrec_lock);
	}
	if (got_write)
		mnt_drop_write_file(filp);
	if (uname)
		kmem_cache_free(ntfs_name_cache, uname);
	kfree(req);
	return err;

out_put_ctx:
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	goto out_unlock;
}

static long ntfs_ioctl_stream_remove(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_stream_remove __user *ureq =
		(struct ntfs_stream_remove __user *)arg;
	struct ntfs_stream_remove *req;
	size_t header_size = sizeof(struct ntfs_stream_remove);
	size_t total_size;
	char *kname;
	__le16 *uname = NULL, *sname;
	int err, sname_len;
	bool utf16;
	struct ntfs_stream_remove hdr;

	if (NVolShutdown(ni->vol))
		return -EIO;

	/* First copy fixed header */
	if (copy_from_user(&hdr, ureq, header_size))
		return -EFAULT;

	if (!(filp->f_mode & FMODE_WRITE) ||
	    (hdr.flags & ~NTFS_STREAM_FL_UTF16_NAME) || hdr.reserved)
		return -EINVAL;

	utf16 = hdr.flags & NTFS_STREAM_FL_UTF16_NAME;

	if (hdr.name_len == 0)
		return -EINVAL;
	if (utf16) {
		/* UTF-16LE byte count: must be even and within the limit. */
		if ((hdr.name_len & 1) ||
		    hdr.name_len > NTFS_MAX_NAME_LEN * sizeof(__le16))
			return -EINVAL;
	} else if (hdr.name_len >
			NTFS_MAX_NAME_LEN * NLS_MAX_CHARSET_SIZE) {
		return -EINVAL;
	}

	if (check_add_overflow(header_size, (size_t)hdr.name_len, &total_size))
		return -EOVERFLOW;

	req = memdup_user(ureq, total_size);
	if (IS_ERR(req))
		return PTR_ERR(req);

	kname = (char *)req->name;

	if (req->name_len != hdr.name_len || req->flags != hdr.flags ||
	    req->reserved) {
		err = -EINVAL;
		goto out_free;
	}

	if (utf16) {
		/* Name is already on-disk UTF-16LE; use it in place. */
		sname = (__le16 *)kname;
		sname_len = req->name_len / sizeof(__le16);
	} else {
		if (memchr(kname, '\0', req->name_len)) {
			err = -EINVAL;
			goto out_free;
		}
		sname_len = ntfs_nlstoucs(ni->vol, kname, req->name_len,
				&uname, NTFS_MAX_NAME_LEN);
		if (sname_len < 0) {
			err = sname_len;
			goto out_free;
		}
		sname = uname;
	}

	err = inode_permission(file_mnt_idmap(filp), inode, MAY_WRITE);
	if (err)
		goto out_free;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode)) {
		err = -EPERM;
		goto out_free;
	}

	err = mnt_want_write_file(filp);
	if (!err) {
		err = ntfs_remove_named_stream(ni, sname, sname_len, NULL);
		mnt_drop_write_file(filp);
	}

out_free:
	if (uname)
		kmem_cache_free(ntfs_name_cache, uname);
	kfree(req);
	return err;
}

static int ntfs_ioctl_list_streams(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_list_streams hdr;
	struct ntfs_stream_entry *entry, *last_entry = NULL;
	size_t required = 0;
	void *kbuf = NULL;
	void __user *ubuf;
	struct attr_record *a;
	struct ntfs_attr_search_ctx *actx;
	int ret = 0, err, count = 0;
	size_t entry_size, offset = 0;
	const size_t name_offset = offsetof(struct ntfs_stream_entry, name);
	unsigned int name_len;
	unsigned char *sn;
	bool utf16;

	if (NVolShutdown(ni->vol))
		return -EIO;

	if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr)))
		return -EFAULT;

	if ((hdr.flags & ~NTFS_STREAM_FL_UTF16_NAME) || hdr.reserved)
		return -EINVAL;

	utf16 = hdr.flags & NTFS_STREAM_FL_UTF16_NAME;

	ubuf = (void __user *)arg + sizeof(hdr);

	mutex_lock(&ni->mrec_lock);
	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		mutex_unlock(&ni->mrec_lock);
		return -ENOMEM;
	}

	while ((err = ntfs_attrs_walk(actx)) == 0) {
		a = actx->attr;
		if (a->type != AT_DATA || !a->name_length)
			continue;
		if (a->non_resident &&
		    a->data.non_resident.lowest_vcn)
			continue;
		if (ntfs_stream_is_unlinked(ni,
				(__le16 *)((u8 *)a +
				le16_to_cpu(a->name_offset)),
				a->name_length))
			continue;

		if (utf16) {
			name_len = a->name_length * sizeof(__le16);
		} else {
			sn = ntfs_attr_name_get(ni->vol,
					(__le16 *)((u8 *)a + le16_to_cpu(a->name_offset)),
					a->name_length);
			if (!sn) {
				ret = -EIO;
				goto out;
			}
			name_len = strlen(sn);
			ntfs_attr_name_free(&sn);
		}

		entry_size = ALIGN(name_offset + name_len, 8);

		if (required > SIZE_MAX - entry_size) {
			ret = -EOVERFLOW;
			goto out;
		}
		required += entry_size;
		count++;
	}
	if (err != -ENOENT) {
		ret = err;
		goto out;
	}

	hdr.stream_count = count;
	hdr.bytes_returned = required;

	if (!count)
		goto out;

	if (hdr.buffer_size < required) {
		ret = -ENOSPC;
		goto out;
	}

	kbuf = kvzalloc(required, GFP_NOFS);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out;
	}

	ntfs_attr_reinit_search_ctx(actx);
	while ((err = ntfs_attrs_walk(actx)) == 0) {
		a = actx->attr;
		if (a->type != AT_DATA || !a->name_length)
			continue;
		if (a->non_resident &&
		    a->data.non_resident.lowest_vcn)
			continue;
		if (ntfs_stream_is_unlinked(ni,
				(__le16 *)((u8 *)a +
				le16_to_cpu(a->name_offset)),
				a->name_length))
			continue;
		if (utf16) {
			sn = NULL;
			name_len = a->name_length * sizeof(__le16);
		} else {
			sn = ntfs_attr_name_get(ni->vol,
					(__le16 *)((u8 *)a + le16_to_cpu(a->name_offset)),
					a->name_length);
			if (!sn) {
				ret = -EIO;
				goto out;
			}
			name_len = strlen(sn);
		}

		entry_size = ALIGN(name_offset + name_len, 8);
		if (offset > required - entry_size) {
			ret = -EOVERFLOW;
			ntfs_attr_name_free(&sn);
			goto out;
		}

		entry = (struct ntfs_stream_entry *)(kbuf + offset);

		if (a->non_resident) {
			entry->size = le64_to_cpu(a->data.non_resident.data_size);
			entry->alloc_size =
				le64_to_cpu(a->data.non_resident.allocated_size);

		} else {
			entry->size = le32_to_cpu(a->data.resident.value_length);
			entry->alloc_size = le32_to_cpu(a->length) -
				le16_to_cpu(a->data.resident.value_offset);
		}

		entry->name_len = name_len;
		entry->name_offset = name_offset;
		if (utf16)
			memcpy(entry->name,
			       (u8 *)a + le16_to_cpu(a->name_offset), name_len);
		else
			memcpy(entry->name, sn, name_len);
		ntfs_attr_name_free(&sn);

		entry->next_entry_off = entry_size;
		last_entry = entry;
		offset += entry_size;
	}
	if (err != -ENOENT) {
		ret = err;
	} else {
		/* The chain terminates at the last entry. */
		if (last_entry)
			last_entry->next_entry_off = 0;
		hdr.bytes_returned = offset;
	}

out:
	ntfs_attr_put_search_ctx(actx);
	mutex_unlock(&ni->mrec_lock);

	if (ret && ret != -ENOSPC)
		goto out_free;

	if (!ret && kbuf && copy_to_user(ubuf, kbuf, hdr.bytes_returned)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (copy_to_user((void __user *)arg, &hdr, sizeof(hdr)))
		ret = -EFAULT;

out_free:
	kvfree(kbuf);
	return ret;
}

long ntfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC_SHUTDOWN:
		return ntfs_ioctl_shutdown(file_inode(filp)->i_sb, arg);
	case FS_IOC_GETFSLABEL:
		return ntfs_ioctl_get_volume_label(filp, arg);
	case FS_IOC_SETFSLABEL:
		return ntfs_ioctl_set_volume_label(filp, arg);
	case FITRIM:
		return ntfs_ioctl_fitrim(NTFS_SB(file_inode(filp)->i_sb), arg);
	case NTFS_IOC_STREAM_REMOVE:
		return ntfs_ioctl_stream_remove(filp, arg);
	case NTFS_IOC_LIST_STREAMS:
		return ntfs_ioctl_list_streams(filp, arg);
	case NTFS_IOC_STREAM_OPEN:
		return ntfs_ioctl_stream_open(filp, arg);
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long ntfs_compat_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg)
{
	return ntfs_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static int ntfs_allocate_range(struct ntfs_inode *ni, int mode, loff_t offset,
		loff_t len)
{
	struct inode *vi = VFS_I(ni);
	struct ntfs_volume *vol = ni->vol;
	s64 need_space;
	loff_t old_size, new_size;
	s64 start_vcn, end_vcn;
	int err;

	old_size = i_size_read(vi);
	new_size = max_t(loff_t, old_size, offset + len);
	start_vcn = ntfs_bytes_to_cluster(vol, offset);
	end_vcn = ntfs_bytes_to_cluster(vol, offset + len - 1) + 1;

	err = inode_newsize_ok(vi, new_size);
	if (err)
		goto out;

	need_space = ntfs_bytes_to_cluster(vol, ni->allocated_size);
	if (need_space > start_vcn)
		need_space = end_vcn - need_space;
	else
		need_space = end_vcn - start_vcn;
	if (need_space > 0 &&
	    need_space > (atomic64_read(&vol->free_clusters) -
			  atomic64_read(&vol->dirty_clusters))) {
		err = -ENOSPC;
		goto out;
	}

	err = ntfs_attr_fallocate(ni, offset, len,
			mode & FALLOC_FL_KEEP_SIZE ? true : false);

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size != old_size)
		i_size_write(vi, ni->data_size);
out:
	return err;
}

static int ntfs_punch_hole(struct ntfs_inode *ni, int mode, loff_t offset,
		loff_t len)
{
	struct ntfs_volume *vol = ni->vol;
	struct inode *vi = VFS_I(ni);
	loff_t end_offset;
	s64 start_vcn, end_vcn;
	int err = 0;

	loff_t offset_down = round_down(offset, max_t(unsigned int,
				vol->cluster_size, PAGE_SIZE));

	if (NVolDisableSparse(vol)) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (offset >= ni->data_size)
		goto out;

	if (offset + len > ni->data_size)
		end_offset = ni->data_size;
	else
		end_offset = offset + len;

	err = filemap_write_and_wait_range(vi->i_mapping, offset_down, LLONG_MAX);
	if (err)
		goto out;
	truncate_pagecache(vi, offset_down);

	start_vcn = ntfs_bytes_to_cluster(vol, offset);
	end_vcn = ntfs_bytes_to_cluster(vol, end_offset - 1) + 1;

	if (offset & vol->cluster_size_mask) {
		if (offset < ni->initialized_size) {
			loff_t to;

			to = min_t(loff_t,
				   ntfs_cluster_to_bytes(vol, start_vcn + 1),
				   end_offset);
			err = iomap_zero_range(vi, offset, to - offset,
					       NULL, &ntfs_seek_iomap_ops,
					       &ntfs_iomap_folio_ops, NULL);
			if (err < 0)
				goto out;
		}
		if (end_vcn - start_vcn == 1)
			goto out;
		start_vcn++;
	}

	if (end_offset & vol->cluster_size_mask) {
		loff_t from;

		from = ntfs_cluster_to_bytes(vol, end_vcn - 1);
		if (from < ni->initialized_size) {
			err = iomap_zero_range(vi, from, end_offset - from,
					       NULL, &ntfs_seek_iomap_ops,
					       &ntfs_iomap_folio_ops, NULL);
			if (err < 0)
				goto out;
		}
		if (end_vcn - start_vcn == 1)
			goto out;
		end_vcn--;
	}

	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	err = ntfs_non_resident_attr_punch_hole(ni, start_vcn,
			end_vcn - start_vcn);
	mutex_unlock(&ni->mrec_lock);
out:
	return err;
}

static int ntfs_collapse_range(struct ntfs_inode *ni, loff_t offset, loff_t len)
{
	struct ntfs_volume *vol = ni->vol;
	struct inode *vi = VFS_I(ni);
	loff_t old_size, new_size;
	s64 start_vcn, end_vcn;
	int err;

	loff_t offset_down = round_down(offset,
			max_t(unsigned long, vol->cluster_size, PAGE_SIZE));

	if ((offset & vol->cluster_size_mask) ||
	    (len & vol->cluster_size_mask) ||
	    offset >= ni->allocated_size) {
		err = -EINVAL;
		goto out;
	}

	old_size = i_size_read(vi);
	start_vcn = ntfs_bytes_to_cluster(vol, offset);
	end_vcn = ntfs_bytes_to_cluster(vol, offset + len - 1) + 1;

	if (ntfs_cluster_to_bytes(vol, end_vcn) > ni->allocated_size)
		end_vcn = (round_up(ni->allocated_size - 1,
			   vol->cluster_size) >> vol->cluster_size_bits) + 1;
	new_size = old_size - ntfs_cluster_to_bytes(vol, end_vcn - start_vcn);
	if (new_size < 0)
		new_size = 0;
	err = filemap_write_and_wait_range(vi->i_mapping,
			offset_down, LLONG_MAX);
	if (err)
		goto out;

	truncate_pagecache(vi, offset_down);

	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	err = ntfs_non_resident_attr_collapse_range(ni, start_vcn,
			end_vcn - start_vcn);
	mutex_unlock(&ni->mrec_lock);

	if (new_size != old_size)
		i_size_write(vi, ni->data_size);
out:
	return err;
}

static int ntfs_insert_range(struct ntfs_inode *ni, loff_t offset, loff_t len)
{
	struct ntfs_volume *vol = ni->vol;
	struct inode *vi = VFS_I(ni);
	loff_t offset_down = round_down(offset,
			max_t(unsigned long, vol->cluster_size, PAGE_SIZE));
	loff_t alloc_size, end_offset = offset + len;
	loff_t old_size, new_size;
	s64 start_vcn, end_vcn;
	int err;

	if (NVolDisableSparse(vol)) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if ((offset & vol->cluster_size_mask) ||
	    (len & vol->cluster_size_mask) ||
	     offset >= ni->allocated_size) {
		err = -EINVAL;
		goto out;
	}

	old_size = i_size_read(vi);
	start_vcn = ntfs_bytes_to_cluster(vol, offset);
	end_vcn = ntfs_bytes_to_cluster(vol, end_offset - 1) + 1;

	new_size = old_size + ntfs_cluster_to_bytes(vol, end_vcn - start_vcn);
	alloc_size = ni->allocated_size +
		ntfs_cluster_to_bytes(vol, end_vcn - start_vcn);
	if (alloc_size < 0) {
		err = -EFBIG;
		goto out;
	}
	err = inode_newsize_ok(vi, alloc_size);
	if (err)
		goto out;

	err = filemap_write_and_wait_range(vi->i_mapping,
			offset_down, LLONG_MAX);
	if (err)
		goto out;

	truncate_pagecache(vi, offset_down);

	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	err = ntfs_non_resident_attr_insert_range(ni, start_vcn,
			end_vcn - start_vcn);
	mutex_unlock(&ni->mrec_lock);

	if (new_size != old_size)
		i_size_write(vi, ni->data_size);
out:
	return err;
}

#define NTFS_FALLOC_FL_SUPPORTED					\
		(FALLOC_FL_ALLOCATE_RANGE | FALLOC_FL_KEEP_SIZE |	\
		 FALLOC_FL_INSERT_RANGE | FALLOC_FL_PUNCH_HOLE |	\
		 FALLOC_FL_COLLAPSE_RANGE)

static long ntfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *vi = file_inode(file);
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	int err = 0;
	loff_t old_size;

	if (mode & ~(NTFS_FALLOC_FL_SUPPORTED))
		return -EOPNOTSUPP;

	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni))
		return -EOPNOTSUPP;

	if (!NVolFreeClusterKnown(vol))
		wait_event(vol->free_waitq, NVolFreeClusterKnown(vol));

	if ((ni->vol->mft_zone_end - ni->vol->mft_zone_start) == 0)
		return -ENOSPC;

	if (NInoNonResident(ni) && !NInoFullyMapped(ni)) {
		down_write(&ni->runlist.lock);
		err = ntfs_attr_map_whole_runlist(ni);
		up_write(&ni->runlist.lock);
		if (err)
			return err;
	}

	if (!(vol->vol_flags & VOLUME_IS_DIRTY)) {
		err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
		if (err)
			return err;
	}

	old_size = i_size_read(vi);

	inode_lock(vi);
	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni)) {
		inode_unlock(vi);
		return -EOPNOTSUPP;
	}

	inode_dio_wait(vi);
	/* Take invalidate_lock for all fallocate operations to prevent races */
	filemap_invalidate_lock(vi->i_mapping);

	switch (mode & FALLOC_FL_MODE_MASK) {
	case FALLOC_FL_ALLOCATE_RANGE:
	case FALLOC_FL_KEEP_SIZE:
		err = ntfs_allocate_range(ni, mode, offset, len);
		break;
	case FALLOC_FL_PUNCH_HOLE:
		err = ntfs_punch_hole(ni, mode, offset, len);
		break;
	case FALLOC_FL_COLLAPSE_RANGE:
		err = ntfs_collapse_range(ni, offset, len);
		break;
	case FALLOC_FL_INSERT_RANGE:
		err = ntfs_insert_range(ni, offset, len);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	if (err)
		goto out;

	err = file_modified(file);
out:
	if (!err && mode == 0 && NInoNonResident(ni) &&
	    offset > old_size) {
		truncate_pagecache(vi, old_size);
		pagecache_isize_extended(vi, old_size, offset);
	}

	filemap_invalidate_unlock(vi->i_mapping);

	if (!err) {
		NInoSetFileNameDirty(ni);
		inode_set_mtime_to_ts(vi, inode_set_ctime_current(vi));
		mark_inode_dirty(vi);
	}

	inode_unlock(vi);
	return err;
}

const struct file_operations ntfs_stream_file_ops = {
	.llseek		= ntfs_file_llseek,
	.read_iter	= ntfs_file_read_iter,
	.write_iter	= ntfs_file_write_iter,
	.fsync		= ntfs_file_fsync,
	.mmap_prepare	= ntfs_file_mmap_prepare,
	.open		= ntfs_stream_file_open,
	.release	= ntfs_stream_file_release,
	.splice_read	= ntfs_file_splice_read,
	.splice_write	= iter_file_splice_write,
};

const struct file_operations ntfs_file_ops = {
	.llseek		= ntfs_file_llseek,
	.read_iter	= ntfs_file_read_iter,
	.write_iter	= ntfs_file_write_iter,
	.fsync		= ntfs_file_fsync,
	.mmap_prepare	= ntfs_file_mmap_prepare,
	.open		= ntfs_file_open,
	.release	= ntfs_file_release,
	.splice_read	= ntfs_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.unlocked_ioctl	= ntfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ntfs_compat_ioctl,
#endif
	.fallocate	= ntfs_fallocate,
	.setlease	= generic_setlease,
};

const struct inode_operations ntfs_file_inode_ops = {
	.setattr	= ntfs_setattr,
	.getattr	= ntfs_getattr,
	.listxattr	= ntfs_listxattr,
	.get_acl	= ntfs_get_acl,
	.set_acl	= ntfs_set_acl,
	.fiemap		= ntfs_fiemap,
};

const struct inode_operations ntfs_stream_inode_ops = {
	.permission	= ntfs_stream_permission,
	.setattr	= ntfs_stream_setattr,
	.getattr	= ntfs_stream_getattr,
	.listxattr	= ntfs_stream_listxattr,
#ifdef CONFIG_NTFS_FS_POSIX_ACL
	.get_acl	= ntfs_stream_get_acl,
	.set_acl	= ntfs_stream_set_acl,
#endif
	.update_time	= ntfs_stream_update_time,
	.fiemap		= ntfs_fiemap,
};

const struct inode_operations ntfs_symlink_inode_operations = {
	.get_link	= ntfs_get_link,
	.setattr	= ntfs_setattr,
	.listxattr	= ntfs_listxattr,
};

const struct inode_operations ntfs_special_inode_operations = {
	.setattr	= ntfs_setattr,
	.getattr	= ntfs_getattr,
	.listxattr	= ntfs_listxattr,
	.get_acl	= ntfs_get_acl,
	.set_acl	= ntfs_set_acl,
};

const struct file_operations ntfs_empty_file_ops = {};

const struct inode_operations ntfs_empty_inode_ops = {};
