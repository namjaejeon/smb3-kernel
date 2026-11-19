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
#include <linux/fileattr.h>
#include <linux/file.h>
#include <linux/filelock.h>
#include <linux/list.h>
#include <linux/overflow.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <uapi/linux/ntfs.h>
#include <linux/rmap.h>
#include <linux/sizes.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "lcnalloc.h"
#include "attrib.h"
#include "logfile.h"
#include "ntfs.h"
#include "reparse.h"
#include "ea.h"
#include "iomap.h"
#include "bitmap.h"
#include "volume.h"
#include "mft.h"
#include "stream.h"

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
int ntfs_file_open(struct inode *vi, struct file *filp)
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

	/*
	 * Journaled append keeps its bounded, physical, zeroed tail. Explicit
	 * truncate (also to the same EOF) and deletion reclaim that allocation.
	 */
	if (vol->journal)
		return 0;

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

int ntfs_file_release(struct inode *vi, struct file *filp)
{
	if (!NInoCompressed(NTFS_I(vi)) &&
	    !NInoWofCompressed(NTFS_I(vi)))
		return ntfs_trim_prealloc(vi);

	return 0;
}

int ntfs_fsync_write_and_wait_range(struct file *filp, loff_t start,
		loff_t end)
{
	struct ntfs_volume *vol = NTFS_I(filp->f_mapping->host)->vol;
	int err;

	err = file_write_and_wait_range(filp, start, end);
	if (err != -EAGAIN || !vol->journal)
		return err;

	err = ntfs_log_reclaim(vol);
	if (err)
		return err;

	return file_write_and_wait_range(filp, start, end);
}

static int ntfs_sync_pending_empty_eof(struct ntfs_inode *ni)
{
	struct ntfs_log_handle *handle;
	struct runlist_element *rl;
	s64 last_vcn;
	int abort_err;
	int credits;
	int err = 0;

	if (!NInoPendingEmptyEof(ni))
		return 0;
	credits = ntfs_attr_logical_grow_log_credits(ni->vol,
			NInoSparse(ni) || NInoCompressed(ni));
	if (credits < 0)
		return credits;
	handle = ntfs_log_begin_bounded(ni->vol, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	mutex_lock(&ni->mrec_lock);
	if (!NInoPendingEmptyEof(ni))
		goto finish;
	if (NInoEmptyBufferedWrite(ni)) {
		err = -EAGAIN;
		goto finish;
	}
	if (!ni->data_size) {
		err = -EIO;
		goto finish;
	}
	last_vcn = ntfs_bytes_to_cluster(ni->vol, ni->data_size - 1);
	/* A concurrent write may have reserved more delayed data after writeback. */
	down_read(&ni->runlist.lock);
	rl = ni->runlist.rl;
	if (!rl)
		err = -EIO;
	for (; !err && rl->length && rl->vcn <= last_vcn; rl++) {
		if (rl->lcn == LCN_DELALLOC)
			err = -EAGAIN;
		else if (rl->lcn < LCN_HOLE)
			err = -EIO;
	}
	up_read(&ni->runlist.lock);
	if (!err)
		err = ntfs_attr_publish_pending_empty_eof(handle, ni);
finish:
	if (err) {
		abort_err = ntfs_log_abort(handle);
		if (abort_err)
			err = abort_err;
	} else {
		err = ntfs_log_commit(handle);
	}
	mutex_unlock(&ni->mrec_lock);
	return err;
}

/*
 * ntfs_fileattr_get - inode_operations::fileattr_get
 * @dentry: dentry to report the flags of
 * @fa: filled in with the flags of @dentry
 */
int ntfs_fileattr_get(struct dentry *dentry, struct file_kattr *fa)
{
	struct inode *vi = d_inode(dentry);
	struct ntfs_inode *ni = NTFS_I(vi);
	u32 flags = 0;

	if (NVolShutdown(ni->vol))
		return -EIO;

	if (NInoCompressed(ni) || NInoWofCompressed(ni))
		flags |= FS_COMPR_FL;
	if (NInoEncrypted(ni))
		flags |= FS_ENCRYPT_FL;
	if (vi->i_flags & S_IMMUTABLE)
		flags |= FS_IMMUTABLE_FL;
	if (vi->i_flags & S_APPEND)
		flags |= FS_APPEND_FL;
	if (vi->i_flags & S_NOATIME)
		flags |= FS_NOATIME_FL;
	if (ni->linuxflags & NTFS_LINUXFLAGS_NODUMP)
		flags |= FS_NODUMP_FL;
	if (!NVolCaseSensitive(ni->vol))
		flags |= FS_CASEFOLD_FL;

	fileattr_fill_flags(fa, flags);
	return 0;
}

static bool ntfs_is_forced_immutable(struct inode *vi)
{
	struct ntfs_inode *ni = NTFS_I(vi);

	if (ni->mft_no < FILE_first_user && S_ISREG(vi->i_mode))
		return true;

	return NVolSysImmutable(ni->vol) &&
	       (ni->flags & FILE_ATTR_SYSTEM) &&
	       !S_ISFIFO(vi->i_mode) && !S_ISSOCK(vi->i_mode) &&
	       !S_ISLNK(vi->i_mode);
}

/*
 * ntfs_fileattr_set - inode_operations::fileattr_set
 * @idmap:	idmap of the mount @dentry was found from
 * @dentry:	dentry to set the flags of
 * @fa:		flags to set
 */
int ntfs_fileattr_set(const struct mnt_idmap *idmap, struct dentry *dentry,
		      struct file_kattr *fa)
{
	struct inode *vi = d_inode(dentry);
	struct ntfs_inode *ni = NTFS_I(vi);
	u32 allowed = FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL |
		      FS_NOATIME_FL;
	u32 readonly = 0;
	u32 linuxflags = ni->linuxflags & ~NTFS_LINUXFLAGS_MASK;
	unsigned int new_fl = 0;
	bool forced_immutable;
	int err;

	if (NVolShutdown(ni->vol))
		return -EIO;

	if (fileattr_has_fsx(fa))
		return -EOPNOTSUPP;

	/* chattr passes the unchanged read-only flags back to us too. */
	if (NInoCompressed(ni) || NInoWofCompressed(ni))
		readonly |= FS_COMPR_FL;
	if (NInoEncrypted(ni))
		readonly |= FS_ENCRYPT_FL;
	if ((fa->flags ^ readonly) & (FS_COMPR_FL | FS_ENCRYPT_FL))
		return -EOPNOTSUPP;
	allowed |= readonly;

	/* Case folding is a read-only, mount-wide property. */
	if (!NVolCaseSensitive(ni->vol))
		allowed |= FS_CASEFOLD_FL;
	if (fa->flags & ~allowed)
		return -EOPNOTSUPP;

	forced_immutable = ntfs_is_forced_immutable(vi);
	if (!(fa->flags & FS_IMMUTABLE_FL) && forced_immutable)
		return -EPERM;

	if (fa->flags & FS_IMMUTABLE_FL) {
		new_fl |= S_IMMUTABLE;
		/* Do not persist an immutable bit derived from the mount. */
		if (!forced_immutable ||
		    (ni->linuxflags & NTFS_LINUXFLAGS_IMMUTABLE))
			linuxflags |= NTFS_LINUXFLAGS_IMMUTABLE;
	}
	if (fa->flags & FS_APPEND_FL) {
		new_fl |= S_APPEND;
		linuxflags |= NTFS_LINUXFLAGS_APPEND;
	}
	if (fa->flags & FS_NODUMP_FL)
		linuxflags |= NTFS_LINUXFLAGS_NODUMP;
	if (fa->flags & FS_NOATIME_FL) {
		new_fl |= S_NOATIME;
		linuxflags |= NTFS_LINUXFLAGS_NOATIME;
	}

	err = ntfs_ea_set_linuxflags(vi, linuxflags);
	if (err)
		return err;

	inode_set_flags(vi, new_fl, S_IMMUTABLE | S_APPEND | S_NOATIME);
	inode_set_ctime_current(vi);
	mark_inode_dirty(vi);
	return 0;
}

struct ntfs_fsync_attr {
	struct list_head list;
	struct inode *inode;
};

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
 * With a journal, publish the inode metadata (also for fdatasync), then make
 * the WAL and file data durable.  Recovery covers the parent indices and
 * allocation bitmaps without writing their home inodes here.
 *
 * Without a journal:
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
int ntfs_file_fsync(struct file *filp, loff_t start, loff_t end,
			   int datasync)
{
	struct inode *vi = filp->f_mapping->host;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	int err, ret = 0;
	struct inode *parent_vi, *ia_vi;
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_fsync_attr *attr, *next;
	LIST_HEAD(attrs);
	bool non_resident, stream;
	bool sync_empty;

	ntfs_debug("Entering for inode 0x%llx.", ni->mft_no);

	if (NVolShutdown(vol))
		return -EIO;

	/* A range sync must also resolve the mapping that protects deferred EOF. */
	sync_empty = NInoPendingEmptyEof(ni);
	err = ntfs_fsync_write_and_wait_range(filp, sync_empty ? 0 : start,
			sync_empty ? LLONG_MAX : end);
	if (err)
		return err;
	if (NInoPendingEmptyEof(ni)) {
		if (!sync_empty) {
			err = ntfs_fsync_write_and_wait_range(filp, 0, LLONG_MAX);
			if (err)
				return err;
		}
		err = ntfs_sync_pending_empty_eof(ni);
		if (err)
			return err;
	}

	stream = ntfs_inode_is_named_stream(ni);
	non_resident = NInoNonResident(ni);
	if (stream) {
		ni = ni->ext.base_ntfs_ino;
		vi = VFS_I(ni);
	}

	if (vol->journal || !datasync || !non_resident) {
		ret = __ntfs_write_inode(vi, 1);
		if (ret == -EAGAIN && vol->journal) {
			err = ntfs_log_reclaim(vol);
			ret = err ? err : __ntfs_write_inode(vi, 1);
		}
	}
	/*
	 * Never enter inode writeback under mrec_lock or lcnbmp_lock: an active
	 * transaction can need either lock while a checkpoint blocks new readers.
	 */
	if (!vol->journal)
		write_inode_now(vi, !datasync);

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return -ENOMEM;

	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL_CHILD);
	while (!(err = ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx))) {
		if (ctx->attr->type == AT_FILE_NAME) {
			struct file_name_attr *fn = (struct file_name_attr *)((u8 *)ctx->attr +
					le16_to_cpu(ctx->attr->data.resident.value_offset));

			if (vol->journal)
				continue;
			if (MREF_LE(fn->parent_directory) == ni->mft_no)
				continue;

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
			if (ctx->attr->type == AT_DATA &&
			    ntfs_stream_unlinked(ni, name, ctx->attr->name_length))
				continue;

			attr = kmalloc_obj(*attr, GFP_NOFS);
			if (!attr) {
				err = -ENOMEM;
				break;
			}
			attr_vi = ntfs_attr_iget(vi, ctx->attr->type,
						 name, ctx->attr->name_length);
			if (IS_ERR(attr_vi)) {
				kfree(attr);
				continue;
			}
			if (ntfs_inode_is_named_stream(NTFS_I(attr_vi)))
				atomic_inc(&NTFS_I(attr_vi)->stream_open_count);
			attr->inode = attr_vi;
			list_add_tail(&attr->list, &attrs);
		}
	}
	mutex_unlock(&ni->mrec_lock);
	ntfs_attr_put_search_ctx(ctx);
	if (err != -ENOENT && !ret)
		ret = err;

	/* Attribute writeback takes the base inode's MFT record lock. */
	list_for_each_entry_safe(attr, next, &attrs, list) {
		struct inode *attr_vi = attr->inode;

		err = filemap_write_and_wait(attr_vi->i_mapping);
		if (err && !ret)
			ret = err;
		if (ntfs_inode_is_named_stream(NTFS_I(attr_vi))) {
			err = ntfs_stream_put(attr_vi);
			if (err && !ret)
				ret = err;
		}
		iput(attr_vi);
		list_del(&attr->list);
		kfree(attr);
	}

	/* Attribute writeback may have updated the base mapping pairs. */
	if (vol->journal) {
		err = __ntfs_write_inode(vi, 1);
		if (err == -EAGAIN) {
			err = ntfs_log_reclaim(vol);
			if (!err)
				err = __ntfs_write_inode(vi, 1);
		}
	} else {
		err = write_inode_now(vi, 1);
	}
	if (err && !ret)
		ret = err;
	if (vol->journal)
		goto out;

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
out:
	if (likely(!ret))
		ntfs_debug("Done.");
	else
		ntfs_warning(vi->i_sb,
				"Failed to f%ssync inode 0x%llx.  Error %u.",
				datasync ? "data" : "", ni->mft_no, -ret);
	if (!ret)
		ret = ntfs_log_flush(vol);
	if (!ret)
		ret = blkdev_issue_flush(vi->i_sb->s_bdev);
	return ret;
}

static void ntfs_pagecache_extend(struct inode *vi, loff_t from, loff_t to)
{
	pagecache_isize_extended(vi, from, to);

	/*
	 * NTFS initialized_size is byte-granular, so a partial old-EOF page
	 * must stay write-protected until page_mkwrite() updates it. The
	 * generic helper skips this when the block size is at least a page,
	 * the extension ends before the rounded block boundary, or that
	 * boundary is page-aligned.
	 */
	if (from < to && from & (PAGE_SIZE - 1))
		unmap_mapping_range(vi->i_mapping, round_down(from, PAGE_SIZE),
				    PAGE_SIZE, 0);
}

static void ntfs_protect_mmap_eof(struct inode *vi, loff_t old_size)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	struct folio *folio;

	if (!NInoEverMapped(ni) || IS_ALIGNED(old_size, PAGE_SIZE))
		return;
	folio = filemap_lock_folio(vi->i_mapping, old_size >> PAGE_SHIFT);
	if (IS_ERR_OR_NULL(folio))
		return;
	if (folio_mkclean(folio))
		folio_mark_dirty(folio);
	folio_unlock(folio);
	folio_put(folio);
}

static bool ntfs_truncate_has_delalloc(struct ntfs_inode *ni, loff_t size)
{
	const struct runlist_element *rl;
	s64 last_vcn = ntfs_bytes_to_cluster(ni->vol, size - 1);
	bool found = false;

	down_read(&ni->runlist.lock);
	if (ni->i_dealloc_clusters) {
		for (rl = ni->runlist.rl; rl && rl->length && rl->vcn <= last_vcn;
		     rl++) {
			if (rl->lcn == LCN_DELALLOC) {
				found = true;
				break;
			}
		}
	}
	up_read(&ni->runlist.lock);
	return found;
}

int ntfs_setattr_size(struct inode *vi, struct iattr *attr)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	bool stream = ntfs_inode_is_named_stream(ni);
	int err;
	loff_t old_size = vi->i_size;
	loff_t kept_size = min(old_size, attr->ia_size);

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
		mutex_unlock(&base_ni->mrec_lock);
		if (err)
			goto out_unlock_mapping;
	} else {
		filemap_invalidate_lock(vi->i_mapping);
	}
	/*
	 * Materialize delayed allocations retained by the new EOF. Ordinary
	 * overwrites of initialized clusters can follow normal writeback.
	 */
	if (!stream && ni->vol->journal && S_ISREG(vi->i_mode) &&
	    NInoNonResident(ni) && kept_size &&
	    (NInoPendingEmptyEof(ni) ||
	     ntfs_truncate_has_delalloc(ni, kept_size))) {
		err = filemap_write_and_wait_range(vi->i_mapping, 0, kept_size - 1);
		if (err)
			goto out_unlock_mapping;
	}
	if (attr->ia_size > old_size)
		ntfs_protect_mmap_eof(vi, old_size);

	if (attr->ia_size > old_size) {
		truncate_pagecache(vi, old_size);
		if (!ni->vol->journal) {
			i_size_write(vi, attr->ia_size);
			ntfs_pagecache_extend(vi, old_size, attr->ia_size);
		}
	} else {
		truncate_setsize(vi, attr->ia_size);
	}

	err = ntfs_truncate_vfs(vi, attr->ia_size, old_size);
	/* Truncate may discard the only delayed data, leaving a stable hole EOF. */
	if (!err && NInoPendingEmptyEof(ni))
		err = ntfs_sync_pending_empty_eof(ni);
	/* Earlier truncate chunks may have committed before a later failure. */
	if (err)
		i_size_write(vi, ni->vol->journal ? ni->data_size : old_size);
	else if (ni->vol->journal && attr->ia_size > old_size)
		ntfs_pagecache_extend(vi, old_size, attr->ia_size);
out_unlock_mapping:
	filemap_invalidate_unlock(vi->i_mapping);
	if (!err && stream)
		ntfs_stream_update_base_time(base_ni);

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
int ntfs_setattr(const struct mnt_idmap *idmap, struct dentry *dentry,
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

		if (S_ISDIR(vi->i_mode))
			vi->i_mode &= ~vol->dmask;
		else
			vi->i_mode &= ~vol->fmask;

		if (vol->journal) {
			err = ntfs_ea_set_wsl_inode_journaled(vi, 0, NULL,
					flags);
		} else {
			mutex_lock(&ni->mrec_lock);
			err = ntfs_ea_set_wsl_inode(vi, 0, NULL, flags);
			mutex_unlock(&ni->mrec_lock);
		}
		if (err)
			goto out;
	}

	mark_inode_dirty(vi);
out:
	return err;
}

int ntfs_getattr(const struct mnt_idmap *idmap, const struct path *path,
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
	if (ni->linuxflags & NTFS_LINUXFLAGS_NODUMP)
		stat->attributes |= STATX_ATTR_NODUMP;

	stat->attributes_mask |= STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED |
				 STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND |
				 STATX_ATTR_NODUMP;

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

/*
 * Validate a stream before VFS write handling removes privileges or updates
 * timestamps on its base inode.
 */
static int ntfs_file_modified(struct kiocb *iocb)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	int err;

	if (ntfs_inode_is_named_stream(NTFS_I(inode))) {
		err = ntfs_stream_validate_for_mutation(inode,
				iocb->ki_flags & IOCB_NOWAIT);
		if (err)
			return err;
	}
	return kiocb_modified(iocb);
}

loff_t ntfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;

	if (NInoWofCompressed(NTFS_I(inode)) &&
	    (whence == SEEK_HOLE || whence == SEEK_DATA))
		return -EOPNOTSUPP;

	switch (whence) {
	case SEEK_HOLE:
		inode_lock_shared(inode);
		offset = iomap_seek_hole(inode, offset, ntfs_seek_iomap_next);
		inode_unlock_shared(inode);
		break;
	case SEEK_DATA:
		inode_lock_shared(inode);
		offset = iomap_seek_data(inode, offset, ntfs_seek_iomap_next);
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

ssize_t ntfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *vi = file_inode(iocb->ki_filp);
	struct super_block *sb = vi->i_sb;
	ssize_t ret;

	if (NVolShutdown(NTFS_SB(sb)))
		return -EIO;

	if ((NInoCompressed(NTFS_I(vi)) || NInoWofCompressed(NTFS_I(vi)) ||
	     NInoEncrypted(NTFS_I(vi))) && iocb->ki_flags & IOCB_DIRECT)
		return -EOPNOTSUPP;

	inode_lock_shared(vi);

	if (NVolShutdown(NTFS_SB(sb))) {
		ret = -EIO;
	} else if (iocb->ki_flags & IOCB_DIRECT) {
		size_t count = iov_iter_count(to);

		if ((iocb->ki_pos | count) & (sb->s_blocksize - 1)) {
			ret = -EINVAL;
			goto inode_unlock;
		}

		file_accessed(iocb->ki_filp);
		ret = iomap_dio_rw(iocb, to, ntfs_read_iomap_next, NULL, 0,
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

	ret = iomap_dio_rw(iocb, from, ntfs_dio_iomap_next,
			&ntfs_write_dio_ops, 0, NULL, 0);
	if (ret == -ENOTBLK)
		ret = 0;
	else if (ret < 0)
		goto out;

	if (iov_iter_count(from)) {
		loff_t offset, end;
		ssize_t written;
		int ret2;

		if (iocb->ki_flags & IOCB_NOWAIT) {
			if (!ret)
				ret = -EAGAIN;
			goto out;
		}

		offset = iocb->ki_pos;
		iocb->ki_flags &= ~IOCB_DIRECT;

		/*
		 * Prevent concurrent direct I/O and buffered I/O to the same file
		 * range. Wait for in-flight DIO to finish before dirtying pages.
		 */
		inode_dio_wait(file_inode(iocb->ki_filp));

		written = iomap_file_buffered_write(iocb, from,
				ntfs_write_iomap_next, &ntfs_iomap_folio_ops,
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

static int ntfs_expand_for_write(struct ntfs_inode *ni, loff_t pos, loff_t end)
{
	struct ntfs_volume *vol = ni->vol;
	struct ntfs_inode *mrec_ni = ntfs_base_inode(ni);
	loff_t prealloc_size = 0;
	int err;

	if (end <= ni->data_size)
		return 0;

	if (vol->journal && !NInoCompressed(ni)) {
		if (pos > ni->data_size)
			return ntfs_truncate_vfs(VFS_I(ni), end,
					i_size_read(VFS_I(ni)));
		return ntfs_extend_vfs(VFS_I(ni), end);
	}

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

static ssize_t ntfs_buffered_write(struct kiocb *iocb, struct iov_iter *from,
		iomap_iter_next_fn next)
{
	ssize_t ret;

	ret = iomap_file_buffered_write(iocb, from, next,
			&ntfs_iomap_folio_ops, NULL);
	return ret;
}

static int ntfs_zero_append_gap(struct inode *vi, loff_t start, loff_t end)
{
	return iomap_zero_range(vi, start, end - start, NULL,
			ntfs_seek_iomap_next, &ntfs_iomap_folio_ops, NULL);
}

struct ntfs_ordered_append_undo {
	struct inode *vi;
	loff_t old_size;
};

static int ntfs_ordered_append_restore(void *data)
{
	struct ntfs_ordered_append_undo *undo = data;

	/* Wait for submitted I/O and discard dirty pages before freeing clusters. */
	truncate_setsize(undo->vi, undo->old_size);
	return 0;
}

static void ntfs_ordered_append_release(void *data)
{
	struct ntfs_ordered_append_undo *undo = data;

	iput(undo->vi);
	kfree(undo);
}

static int ntfs_ordered_append_register_undo(struct ntfs_log_handle *handle,
		struct inode *vi, loff_t old_size)
{
	struct ntfs_ordered_append_undo *undo;
	int err;

	undo = kmalloc(sizeof(*undo), GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->vi = igrab(vi);
	if (!undo->vi) {
		kfree(undo);
		return -EIO;
	}
	undo->old_size = old_size;
	err = ntfs_log_register_home_undo(handle, ntfs_ordered_append_restore,
			ntfs_ordered_append_release, undo);
	if (err)
		ntfs_ordered_append_release(undo);
	return err;
}

/* inode_lock is held. The iomap path cannot allocate or start another transaction. */
static ssize_t ntfs_buffered_append(struct kiocb *iocb, struct iov_iter *from,
		bool *retry_regular, bool ordered)
{
	struct inode *vi = file_inode(iocb->ki_filp);
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_log_handle *handle;
	loff_t pos = iocb->ki_pos;
	loff_t end = pos + iov_iter_count(from);
	loff_t old_size = ni->data_size;
	u64 required_clusters = 0, grow_clusters = 0;
	s64 allocation_size;
	ssize_t written;
	int credits, size_credits, err, abort_err;
	struct ntfs_ordered_io *ordered_io = NULL;
	bool ordered_entered = false;

	size_credits = ntfs_attr_logical_grow_log_credits(ni->vol, false);
	if (size_credits < 0)
		return size_credits;
	if (end > ni->allocated_size) {
		u64 allocated_clusters = ni->allocated_size >>
				ni->vol->cluster_size_bits;
		u64 end_clusters = DIV_ROUND_UP_ULL((u64)end,
				ni->vol->cluster_size);

		required_clusters = end_clusters - allocated_clusters;
		grow_clusters = required_clusters;
		if (ni->vol->preallocated_size > 0) {
			u64 prealloc_size = min_t(u64,
					ni->vol->preallocated_size, SZ_64K);
			u64 prealloc_clusters;

			/*
			 * Scale the default tail only for sustained sequential
			 * writes. Explicit preallocation settings keep their limit.
			 */
			if (!ni->vol->preallocated_size_set &&
			    ntfs_can_speculate_allocation(ni->vol) &&
			    prealloc_size == SZ_64K &&
			    ni->allocated_size >= SZ_1M && pos == old_size &&
			    iov_iter_count(from) >= SZ_64K)
				prealloc_size = ni->allocated_size >= SZ_2M ?
						SZ_1M : SZ_256K;
			prealloc_clusters = prealloc_size >>
					ni->vol->cluster_size_bits;

			/* Align the tail to file offsets, not the old allocation. */
			if (prealloc_clusters) {
				u64 prealloc_end = roundup(end_clusters,
						prealloc_clusters);

				if (prealloc_end <= ((u64)S64_MAX >>
						ni->vol->cluster_size_bits))
					grow_clusters = prealloc_end -
							allocated_clusters;
			}
			if (prealloc_size == SZ_1M &&
			    grow_clusters > required_clusters &&
			    NVolFreeClusterKnown(ni->vol)) {
				s64 available = ntfs_available_clusters(ni->vol);

				/* A stale count only affects this optional tail. */
				if (available < 0 || (u64)available < grow_clusters)
					grow_clusters = required_clusters;
			}
		}
	}
retry:
	credits = size_credits;
	if (grow_clusters) {
		err = ntfs_attr_physical_grow_log_credits(ni->vol, grow_clusters);
		if (err == -EOVERFLOW && grow_clusters > required_clusters) {
			grow_clusters = required_clusters;
			goto retry;
		}
		if (err < 0)
			goto retry_minimum;
		/*
		 * The estimate includes worst-case extent/list growth. Ordinary
		 * handles start small and enforce the ring's actual u32 ceiling as
		 * records are appended. A legacy u16 estimate limit would reduce
		 * every 64-KiB batch to a single cluster on a normal volume.
		 */
		if (check_add_overflow(credits, err, &credits)) {
			err = -E2BIG;
			goto retry_minimum;
		}
		if (check_add_overflow(ni->allocated_size,
				ntfs_cluster_to_bytes(ni->vol, grow_clusters),
				&allocation_size)) {
			err = -EFBIG;
			goto retry_minimum;
		}
	}
	/* Reserve before locking folios or MFT records: admission can checkpoint. */
	handle = ntfs_log_begin(ni->vol, credits);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto retry_minimum;
	}
	if (ordered) {
		if (!ntfs_ordered_append_enter(ni)) {
			abort_err = ntfs_log_abort(handle);
			if (abort_err)
				return abort_err;
			*retry_regular = true;
			return 0;
		}
		ordered_entered = true;
	}
	if (grow_clusters) {
		mutex_lock(&ni->mrec_lock);
		if (ordered)
			err = ntfs_attr_physical_prealloc_transacted(handle, ni,
					allocation_size, grow_clusters);
		else
			err = ntfs_attr_append_prealloc_transacted(handle, ni,
					allocation_size, grow_clusters);
		mutex_unlock(&ni->mrec_lock);
		if (err) {
			abort_err = ntfs_log_abort(handle);
			if (abort_err) {
				written = abort_err;
				goto out_ordered;
			}
			goto retry_minimum;
		}
	}
	if (ordered) {
		err = ntfs_ordered_append_register_undo(handle, vi, old_size);
		if (err) {
			abort_err = ntfs_log_abort(handle);
			written = abort_err ? abort_err : err;
			goto out_ordered;
		}
		ordered_io = ntfs_log_ordered_io_begin(handle, vi);
		if (IS_ERR(ordered_io)) {
			err = PTR_ERR(ordered_io);
			abort_err = ntfs_log_abort(handle);
			written = abort_err ? abort_err : err;
			goto out_ordered;
		}
		/* Pair with the ordered writeback and iomap acquire loads. */
		smp_store_release(&ni->ordered_io, ordered_io);
	}
	if (pos > old_size) {
		err = ntfs_zero_append_gap(vi, old_size, pos);
		if (err) {
			abort_err = ntfs_log_abort(handle);
			written = abort_err ? abort_err : err;
			goto out_ordered;
		}
	}
	written = ntfs_buffered_write(iocb, from, ordered ?
			ntfs_ordered_append_iomap_next : ntfs_append_iomap_next);
	if (written <= 0) {
		if (ordered) {
			err = ntfs_log_ordered_io_cancel(ordered_io, vi,
					pos, end - 1);
			/* Cancellation has drained and released the group. */
			smp_store_release(&ni->ordered_io, NULL);
			if (err)
				written = err;
		}
		abort_err = ntfs_log_abort(handle);
		if (abort_err)
			written = abort_err;
		goto out_ordered;
	}
	if (pos > old_size || ordered) {
		/* Pair with mmap setup before it observes the enlarged i_size. */
		smp_mb();
		if (NInoEverMapped(ni)) {
			if (ordered) {
				err = ntfs_log_ordered_io_cancel(ordered_io, vi,
						pos, pos + written - 1);
				/* Cancellation has drained and released the group. */
				smp_store_release(&ni->ordered_io, NULL);
				if (err) {
					abort_err = ntfs_log_abort(handle);
					iocb->ki_pos = pos;
					written = abort_err ? abort_err : err;
					goto out_ordered;
				}
			}
			truncate_setsize(vi, old_size);
			iocb->ki_pos = pos;
			abort_err = ntfs_log_abort(handle);
			if (abort_err) {
				written = abort_err;
				goto out_ordered;
			}
			iov_iter_revert(from, written);
			*retry_regular = true;
			written = 0;
			goto out_ordered;
		}
	}
	if (ordered) {
		err = ntfs_log_ordered_io_submit(handle, vi, pos,
				pos + written - 1, ordered_io);
		/* Submission transferred ownership or released the group. */
		smp_store_release(&ni->ordered_io, NULL);
		if (err) {
			abort_err = ntfs_log_abort(handle);
			iocb->ki_pos = pos;
			written = abort_err ? abort_err : err;
			goto out_ordered;
		}
	}
	mutex_lock(&ni->mrec_lock);
	err = ntfs_attr_append_grow_transacted(handle, ni, pos + written, ordered);
	mutex_unlock(&ni->mrec_lock);
	if (err) {
		abort_err = ntfs_log_abort(handle);
		if (abort_err)
			err = abort_err;
	} else {
		err = ntfs_log_commit(handle);
	}
	if (err) {
		/* Undo snapshots are taken after iomap temporarily advanced i_size. */
		truncate_setsize(vi, old_size);
		iocb->ki_pos = pos;
		written = err;
	}
out_ordered:
	if (ordered_entered)
		ntfs_ordered_append_exit(ni);
	return written;
retry_minimum:
	if (ordered_entered) {
		ntfs_ordered_append_exit(ni);
		ordered_entered = false;
	}
	/* No user data was copied. A failed speculative tail is fully undone. */
	if (grow_clusters > required_clusters &&
	    (err == -ENOSPC || err == -E2BIG)) {
		grow_clusters = required_clusters;
		goto retry;
	}
	return err;
}

static ssize_t ntfs_buffered_gap_append(struct kiocb *iocb,
		struct iov_iter *from, bool *retry_regular, bool ordered)
{
	struct ntfs_inode *ni = NTFS_I(file_inode(iocb->ki_filp));
	ssize_t ret;

	NInoSetGapAppend(ni);
	/* A racing mmap must observe this bit or be seen by the check below. */
	smp_mb__after_atomic();
	if (NInoEverMapped(ni)) {
		*retry_regular = true;
		ret = 0;
	} else {
		ret = ntfs_buffered_append(iocb, from, retry_regular, ordered);
	}
	/* Publish the final sizes before mmap faults proceed. */
	smp_mb__before_atomic();
	NInoClearGapAppend(ni);
	return ret;
}

/*
 * Extend an eligible buffered append, including a small gap, with holes.
 * Iomap reserves or allocates the new clusters as space permits. A physical
 * partial-EOF cluster must still be zeroed before initialized size is published.
 */
static bool ntfs_begin_delalloc_append(struct ntfs_inode *ni,
		unsigned int ki_flags, loff_t pos, loff_t end,
		loff_t *physical_tail)
{
	struct inode *vi = VFS_I(ni);
	struct ntfs_volume *vol = ni->vol;
	loff_t old_size = ni->data_size;
	bool empty_holes = !old_size && ni->allocated_size > 0 &&
		NInoSparse(ni) && !ni->itype.compressed.size;
	s64 lcn;

	*physical_tail = 0;
	if (!ntfs_iomap_can_share_delalloc(ni) || !S_ISREG(vi->i_mode) ||
	    !vi->i_nlink || NVolDisableSparse(vol) ||
	    NInoSparseDisabled(ni) || vol->major_ver < 3 ||
	    (ki_flags & (IOCB_DIRECT | IOCB_NOWAIT)) ||
	    pos < old_size || old_size != ni->initialized_size ||
	    old_size != i_size_read(vi) || end <= pos || NInoEverMapped(ni))
		return false;
	if (pos > old_size &&
	    (!NInoNonResident(ni) || pos - old_size >= vol->cluster_size ||
	     (old_size >> PAGE_SHIFT) != ((pos - 1) >> PAGE_SHIFT)))
		return false;

	if (NInoNonResident(ni)) {
		if (old_size > S64_MAX - vol->cluster_size_mask ||
		    (ni->allocated_size != round_up(old_size, vol->cluster_size) &&
		     !empty_holes))
			return false;
		if (!IS_ALIGNED(old_size, vol->cluster_size)) {
			down_read(&ni->runlist.lock);
			lcn = ni->runlist.rl ?
				ntfs_rl_vcn_to_lcn(ni->runlist.rl,
						ntfs_bytes_to_cluster(vol, old_size)) :
				LCN_RL_NOT_MAPPED;
			up_read(&ni->runlist.lock);
			if (lcn != LCN_DELALLOC) {
				loff_t tail_end = min(end, ni->allocated_size);

				if (lcn < 0)
					return false;
				/* Keep the existing prezeroed physical fast paths. */
				if (!NInoSparse(ni) &&
				    ((end <= ni->allocated_size &&
				      ni->zeroed_size >= end) ||
				     (pos > old_size && pos <= ni->allocated_size &&
				      ni->zeroed_size == ni->allocated_size)))
					return false;
				if (ni->zeroed_size < tail_end)
					*physical_tail = tail_end;
			}
		}
	}

	NInoSetGapAppend(ni);
	/* A racing mmap must observe the gate or be seen by this check. */
	smp_mb__after_atomic();
	if (NInoEverMapped(ni)) {
		/* Publish the abort before mmap faults proceed. */
		smp_mb__before_atomic();
		NInoClearGapAppend(ni);
		return false;
	}
	return true;
}

static int ntfs_defer_empty_eof(struct ntfs_inode *ni, loff_t end)
{
	struct runlist_element *rl;
	s64 last_vcn = ntfs_bytes_to_cluster(ni->vol, end - 1);
	int err;

	mutex_lock(&ni->mrec_lock);
	down_write(&ni->runlist.lock);
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		goto out;
	/* Preallocation entirely beyond the new EOF cannot protect it. */
	for (rl = ni->runlist.rl; rl && rl->length && rl->vcn <= last_vcn; rl++) {
		if (rl->lcn >= 0)
			goto out;
		if (rl->lcn != LCN_HOLE && rl->lcn != LCN_DELALLOC) {
			err = -EIO;
			goto out;
		}
	}
	NInoSetPendingEmptyEof(ni);
out:
	up_write(&ni->runlist.lock);
	mutex_unlock(&ni->mrec_lock);
	return err;
}


ssize_t ntfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *vi = file->f_mapping->host;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	ssize_t ret;
	ssize_t count;
	loff_t pos, end, physical_tail;
	int err;
	loff_t old_data_size, old_init_size;
	bool append_gap, retry_regular, ordered_append = false;
	bool delalloc_append;
	bool empty_buffered_write;
	bool retry_initialization = false;
	bool retried_initialization = false;

retry:
	retry_initialization = false;
	delalloc_append = false;
	empty_buffered_write = false;
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

	if (!(iocb->ki_flags & IOCB_NOWAIT))
		ntfs_maybe_writeback_delalloc(vol);

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock(vi))
			return -EAGAIN;
	} else
		inode_lock(vi);

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out_lock;

	err = ntfs_file_modified(iocb);
	if (err) {
		ret = err;
		goto out_lock;
	}

	/*
	 * The volume must be marked dirty before the modification is made,
	 * without an unlocked check of the in-memory flag: the dirty bit
	 * is only cleared at the quiescent transitions, under the same
	 * $Volume mrec_lock this call takes, so an unlocked skip could
	 * lose the set to one of them.
	 */
	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	pos = iocb->ki_pos;
	count = ret;
	end = pos + count;

	old_data_size = ni->data_size;
	old_init_size = ni->initialized_size;
	append_gap = pos > old_data_size &&
		pos - old_data_size < vol->cluster_size &&
		(old_data_size >> PAGE_SHIFT) == ((pos - 1) >> PAGE_SHIFT) &&
		pos <= ni->allocated_size && !NInoEverMapped(ni);

	ordered_append = pos == old_data_size &&
		old_init_size == old_data_size && ni->zeroed_size >= old_data_size &&
		end > ni->zeroed_size && pos <= ni->allocated_size &&
		!NInoEverMapped(ni) && !mapping_large_folio_support(vi->i_mapping) &&
		count <= SZ_1M &&
		IS_ALIGNED(pos, PAGE_SIZE) && IS_ALIGNED(count, PAGE_SIZE) &&
		IS_ALIGNED(pos, vol->cluster_size) &&
		IS_ALIGNED(count, vol->cluster_size) &&
		(end <= ni->allocated_size ||
		 (end <= S64_MAX - SZ_64K &&
		  DIV_ROUND_UP_ULL((u64)end, vol->cluster_size) -
			(ni->allocated_size >> vol->cluster_size_bits) <=
				NTFS_ATTR_GROW_MAX_CLUSTERS));

	if ((iocb->ki_flags & IOCB_NOWAIT) && !NInoCompressed(ni) &&
	    end > old_init_size) {
		ret = -EAGAIN;
		goto out_lock;
	}

	if (!old_data_size && ntfs_iomap_can_share_delalloc(ni) && S_ISREG(vi->i_mode) &&
	    vi->i_nlink && !(iocb->ki_flags & (IOCB_DIRECT | IOCB_NOWAIT))) {
		NInoSetEmptyBufferedWrite(ni);
		empty_buffered_write = true;
		if (NInoNonResident(ni) && NInoSparse(ni)) {
			ret = ntfs_defer_empty_eof(ni, end);
			if (ret)
				goto out_lock;
		}
	}

	delalloc_append = ntfs_begin_delalloc_append(ni, iocb->ki_flags,
			pos, end, &physical_tail);
	if (!delalloc_append && vol->journal && NInoNonResident(ni) && !NInoAttr(ni) &&
	    !NInoCompressed(ni) && !NInoSparse(ni) &&
	    !(iocb->ki_flags & (IOCB_DIRECT | IOCB_NOWAIT)) &&
	    (pos == old_data_size || append_gap) &&
	    old_init_size == old_data_size &&
	    end > pos &&
	    (ordered_append ||
	     (end <= ni->allocated_size && end <= ni->zeroed_size) ||
	     (end > ni->allocated_size &&
	      ((pos == ni->allocated_size && pos == old_data_size) ||
	       (append_gap && ni->zeroed_size == ni->allocated_size)) &&
	      DIV_ROUND_UP_ULL((u64)end, vol->cluster_size) -
		(ni->allocated_size >> vol->cluster_size_bits) <=
			NTFS_ATTR_GROW_MAX_CLUSTERS &&
	      end <= S64_MAX - 64 * 1024))) {
		retry_regular = false;
		if (append_gap || ordered_append)
			ret = ntfs_buffered_gap_append(iocb, from, &retry_regular,
					ordered_append);
		else
			ret = ntfs_buffered_append(iocb, from, &retry_regular, false);
		if (!retry_regular)
			goto out;
	}


	if (end > old_data_size) {
		if (delalloc_append && NInoNonResident(ni) && !physical_tail) {
			loff_t zero_end = min(pos, ni->allocated_size);

			if (old_data_size < zero_end) {
				ret = ntfs_zero_append_gap(vi, old_data_size,
						zero_end);
				/* Older iomap_zero_range() can extend i_size. */
				i_size_write(vi, old_data_size);
				if (ret < 0) {
					retry_initialization = ret == -EAGAIN &&
						vol->journal && !current_work();
					goto out;
				}
			}
			ret = ntfs_extend_delalloc_vfs(vi, end);
		} else {
			ret = delalloc_append ?
				ntfs_truncate_vfs(vi, end, i_size_read(vi)) :
				ntfs_expand_for_write(ni, pos, end);
		}
		if (ret < 0)
			goto out;
	}

	if (NInoNonResident(ni) && !NInoCompressed(ni) &&
	    end > ni->initialized_size) {
		ret = 0;
		if (delalloc_append && physical_tail) {
			ret = ntfs_extend_initialized_size(vi, pos,
					physical_tail, true);
		}
		/*
		 * New clusters are holes. Writeback zeroes their media before
		 * journaled DELALLOC conversion can publish a physical mapping.
		 */
		if (!ret)
			ret = ntfs_extend_initialized_size(vi, pos, end,
					!delalloc_append &&
					(vol->journal ||
					 (iocb->ki_flags & IOCB_SYNC) ||
					 iocb_is_dsync(iocb)));
		if (ret < 0) {
			retry_initialization = ret == -EAGAIN && vol->journal &&
				!(iocb->ki_flags & IOCB_NOWAIT) && !current_work();
			goto out;
		}
	}

	if (NInoNonResident(ni) && NInoCompressed(ni)) {
		ret = ntfs_compress_write(ni, pos, count, from);
		if (ret > 0) {
			err = ntfs_set_initialized_size_journaled(ni,
					min_t(loff_t, pos + ret, ni->data_size));
			if (err) {
				ret = err;
				goto out;
			}
			iocb->ki_pos += ret;
		}
		goto out;
	}

	if (NInoNonResident(ni) && iocb->ki_flags & IOCB_DIRECT)
		ret = ntfs_dio_write_iter(iocb, from);
	else
		ret = iomap_file_buffered_write(iocb, from, ntfs_write_iomap_next,
				&ntfs_iomap_folio_ops, NULL);
out:
	if (delalloc_append) {
		loff_t final_size = ret > 0 ? pos + ret : old_data_size;

		if (ret != -EIOCBQUEUED && ret < count &&
		    ni->data_size != final_size) {
			loff_t speculative_size = i_size_read(vi);

			/* Discard uncopied cache before releasing reservations. */
			filemap_invalidate_lock(vi->i_mapping);
			truncate_setsize(vi, final_size);
			err = ntfs_truncate_vfs(vi, final_size, speculative_size);
			if (err) {
				i_size_write(vi, ni->data_size);
				iocb->ki_pos = pos;
				ret = err;
				retry_initialization = false;
			}
			filemap_invalidate_unlock(vi->i_mapping);
		}
		/* Publish the final sizes before mmap faults proceed. */
		smp_mb__before_atomic();
		NInoClearGapAppend(ni);
	} else if (ret != -EIOCBQUEUED &&
		   (ret < 0 || (!ret && !old_data_size &&
				NInoPendingEmptyEof(ni)))) {
		int init_err = 0;

		filemap_invalidate_lock(vi->i_mapping);
		/* Deferred initialization did not publish its size. */
		if (!retry_initialization &&
		    ni->initialized_size != old_init_size &&
		    NInoNonResident(ni)) {
			init_err = ntfs_set_initialized_size_journaled(ni,
					old_init_size);
			if (init_err) {
				ret = init_err;
				retry_initialization = false;
			}
		}
		if (ni->data_size != old_data_size && !init_err) {
			loff_t speculative_size = i_size_read(vi);

			truncate_setsize(vi, old_data_size);
			err = ntfs_truncate_vfs(vi, old_data_size,
					speculative_size);
			if (err) {
				i_size_write(vi, ni->data_size);
				ret = err;
				retry_initialization = false;
			}
		}

		if (init_err)
			NVolSetErrors(vol);
		filemap_invalidate_unlock(vi->i_mapping);
	}
	if (!ni->data_size)
		NInoClearPendingEmptyEof(ni);
out_lock:
	if (empty_buffered_write)
		NInoClearEmptyBufferedWrite(ni);
	inode_unlock(vi);
	if (retry_initialization && !retried_initialization) {
		/* The speculative size is restored. Reclaim without the inode lock. */
		err = ntfs_log_reclaim(vol);
		if (err)
			return err;
		retried_initialization = true;
		goto retry;
	}
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}

static vm_fault_t ntfs_filemap_page_mkwrite(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct ntfs_inode *ni = NTFS_I(inode);
	struct address_space *mapping = inode->i_mapping;
	bool stream = ntfs_inode_is_named_stream(ni);
	int err;
	vm_fault_t ret;
	loff_t new_init_size, mmap_init_size;
	bool retried = false;
	bool reclaimed = false;

	if (NInoWofCompressed(ni))
		return VM_FAULT_SIGBUS;
	mmap_init_size = ((loff_t)vmf->pgoff + 1) << PAGE_SHIFT;

	if (NInoGapAppend(ni)) {
		cond_resched();
		return VM_FAULT_NOPAGE;
	}
	ntfs_maybe_writeback_delalloc(ni->vol);
	/* Observe the size after a completed or aborted gap append. */
	smp_rmb();

	/*
	 * Serialize against truncate/fallocate which hold the lock
	 * exclusively while invalidating pagecache and changing extents.
	 */
	for (;;) {
		bool exclusive = false;

		sb_start_pagefault(inode->i_sb);
		if (stream) {
			err = ntfs_stream_validate_for_mutation(inode, false);
			if (err) {
				sb_end_pagefault(inode->i_sb);
				break;
			}
		}
		if (!retried) {
			err = file_update_time(vmf->vma->vm_file);
			if (err && stream) {
				sb_end_pagefault(inode->i_sb);
				break;
			}
		}
		filemap_invalidate_lock_shared(mapping);
		new_init_size = min(mmap_init_size, i_size_read(inode));
		if (ni->initialized_size < new_init_size) {
			/* Serialize initialized-size changes by concurrent faults. */
			filemap_invalidate_unlock_shared(mapping);
			filemap_invalidate_lock(mapping);
			exclusive = true;
			new_init_size = min(mmap_init_size, i_size_read(inode));
		}
		if (exclusive && ni->initialized_size < new_init_size) {
			loff_t zeroed_end = new_init_size;
			bool ordered_data = false;

			/* Zeroing beyond EOF can extend i_size on older kernels. */
			if (ni->zeroed_size < new_init_size) {
				loff_t zero_start = ni->zeroed_size;

				err = iomap_zero_range(inode, zero_start,
						new_init_size - zero_start, NULL,
						ntfs_seek_iomap_next,
						&ntfs_iomap_folio_ops, NULL);
				if (err < 0)
					goto out_fault;
				if (ni->vol->journal) {
					err = ntfs_write_and_wait_range(inode,
							zero_start, new_init_size - 1);
					if (err)
						goto out_fault;
					ordered_data = true;
					/*
					 * Writeback zeroes the rest of the EOF
					 * block before submitting it.
					 */
					zeroed_end = round_up(new_init_size,
							1UL << inode->i_blkbits);
				}
			}

			err = ntfs_set_initialized_size_fault(ni, new_init_size,
					ordered_data);
			if (err)
				goto out_fault;
			if (ordered_data && ni->zeroed_size < zeroed_end)
				ni->zeroed_size = zeroed_end;
		}

		err = ntfs_iomap_page_mkwrite(vmf);
out_fault:
		if (exclusive)
			filemap_invalidate_unlock(mapping);
		else
			filemap_invalidate_unlock_shared(mapping);
		sb_end_pagefault(inode->i_sb);
		if ((err != -EAGAIN && err != -EBUSY) || !ni->vol->journal ||
		    (err == -EAGAIN && reclaimed))
			break;

		/* Freeze holds s_umount while draining pagefault writers. */
		retried = true;
		if (err == -EBUSY) {
			err = ntfs_log_wait_ready(ni->vol);
		} else {
			reclaimed = true;
			err = ntfs_log_reclaim(ni->vol);
		}
		if (err) {
			ntfs_error(inode->i_sb,
				"Journal retry for mmap fault failed (error %d).",
				err);
			break;
		}
		cond_resched();
	}
	ret = err ? vmf_fs_error(err) : VM_FAULT_LOCKED;

	return ret;
}

static const struct vm_operations_struct ntfs_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= ntfs_filemap_page_mkwrite,
};

int ntfs_file_mmap_prepare(struct vm_area_desc *desc)
{
	struct file *file = desc->file;
	struct inode *inode = file_inode(file);

	if (NVolShutdown(NTFS_SB(file->f_mapping->host->i_sb)))
		return -EIO;

	if (NInoCompressed(NTFS_I(inode)) || NInoWofCompressed(NTFS_I(inode)))
		return -EOPNOTSUPP;

	NInoSetEverMapped(NTFS_I(inode));
	/* Pair with the append path's i_size publication and flag check. */
	smp_mb__after_atomic();

	if (vma_desc_test_all(desc, VMA_SHARED_BIT, VMA_MAYWRITE_BIT)) {
		struct inode *inode = file_inode(file);
		loff_t from, to;
		bool gap_append;
		int err = 0;

		filemap_invalidate_lock(inode->i_mapping);
		gap_append = NInoGapAppend(NTFS_I(inode));
		/* Observe the size after a completed or aborted gap append. */
		smp_rmb();
		from = ((loff_t)desc->pgoff << PAGE_SHIFT);
		to = min_t(loff_t, i_size_read(inode),
			   from + desc->end - desc->start);

		/* The append owns initialization until it drops the gate. */
		if (!gap_append && NTFS_I(inode)->initialized_size < to)
			err = ntfs_extend_initialized_size_locked(inode, to, to,
					!!NTFS_I(inode)->vol->journal);
		filemap_invalidate_unlock(inode->i_mapping);
		if (err)
			return err;
	}


	file_accessed(file);
	desc->vm_ops = &ntfs_file_vm_ops;
	return 0;
}

int ntfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 len)
{
	if (NInoWofCompressed(NTFS_I(inode)))
		return -EOPNOTSUPP;

	return iomap_fiemap(inode, fieinfo, start, len, ntfs_read_iomap_next);
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

ssize_t ntfs_file_splice_read(struct file *in, loff_t *ppos,
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

	range.minlen = max_t(u64, range.minlen, bdev_discard_granularity(dev));

	err = ntfs_trim_fs(vol, &range);
	if (err < 0)
		return err;

	if (copy_to_user(user_range, &range, sizeof(range)))
		return -EFAULT;

	return 0;
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
	case NTFS_IOC_STREAM_READ:
		return ntfs_ioctl_stream_read(filp, arg);
	case NTFS_IOC_STREAM_WRITE:
		return ntfs_ioctl_stream_write(filp, arg);
	case NTFS_IOC_STREAM_REMOVE:
		return ntfs_ioctl_stream_remove(filp, arg);
	case NTFS_IOC_LIST_STREAMS:
		return ntfs_ioctl_list_streams(filp, arg);
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
	loff_t range_end;
	s64 start_vcn, end_vcn;
	int err;

	if (offset < 0 || len <= 0 ||
	    check_add_overflow(offset, len, &range_end))
		return -EINVAL;
	old_size = i_size_read(vi);
	new_size = max_t(loff_t, old_size, range_end);
	start_vcn = ntfs_bytes_to_cluster(vol, offset);
	end_vcn = ntfs_bytes_to_cluster(vol, range_end - 1) + 1;

	err = inode_newsize_ok(vi, new_size);
	if (err)
		goto out;

	need_space = ntfs_bytes_to_cluster(vol, ni->allocated_size);
	if (need_space > start_vcn)
		need_space = end_vcn - need_space;
	else
		need_space = end_vcn - start_vcn;
	if (need_space > 0 && need_space > ntfs_available_clusters(vol)) {
		err = -ENOSPC;
		goto out;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > old_size)
		ntfs_protect_mmap_eof(vi, old_size);
	err = ntfs_attr_fallocate(ni, offset, len,
			mode & FALLOC_FL_KEEP_SIZE ? true : false);

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size != old_size) {
		if (!err && NInoNonResident(ni) && offset > old_size)
			truncate_pagecache(vi, old_size);
		i_size_write(vi, ni->data_size);
		pagecache_isize_extended(vi, old_size, ni->data_size);
		if (!err && NInoNonResident(ni) &&
		    ni->initialized_size == old_size &&
		    ni->data_size > old_size &&
		    ni->data_size <= ni->zeroed_size) {
			err = ntfs_extend_initialized_size_locked(vi, ni->data_size,
					ni->data_size, false);
			/* Initialization failure must not undo the committed EOF. */
			if (err)
				i_size_write(vi, ni->data_size);
		}
	}
out:
	return err;
}

static int ntfs_punch_hole(struct ntfs_inode *ni, int mode, loff_t offset,
		loff_t len)
{
	struct ntfs_inode *mrec_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct inode *vi = VFS_I(ni);
	loff_t end_offset;
	loff_t range_end;
	s64 start_vcn, end_vcn;
	struct ntfs_log_handle *handle = NULL;
	int abort_err;
	int credits;
	int err = 0;

	loff_t offset_down = round_down(offset, max_t(unsigned int,
				vol->cluster_size, PAGE_SIZE));

	if (NVolDisableSparse(vol)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	if (offset < 0 || len <= 0 ||
	    check_add_overflow(offset, len, &range_end)) {
		err = -EINVAL;
		goto out;
	}

	if (offset >= ni->data_size)
		goto out;

	if (range_end > ni->data_size)
		end_offset = ni->data_size;
	else
		end_offset = range_end;

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
					       NULL, ntfs_seek_iomap_next,
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
					       NULL, ntfs_seek_iomap_next,
					       &ntfs_iomap_folio_ops, NULL);
			if (err < 0)
				goto out;
		}
		if (end_vcn - start_vcn == 1)
			goto out;
		end_vcn--;
	}

	if (vol->journal) {
		credits = ntfs_attr_range_update_log_credits_for_inode(ni,
				end_vcn - start_vcn, false, true);
		if (credits < 0) {
			err = credits;
			goto out;
		}
		handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			handle = NULL;
			goto out;
		}
	}
	mutex_lock_nested(&mrec_ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	if (handle)
		err = ntfs_non_resident_attr_punch_hole_transacted(handle, ni,
				start_vcn, end_vcn - start_vcn);
	else
		err = ntfs_non_resident_attr_punch_hole(ni, start_vcn,
				end_vcn - start_vcn);
	if (handle) {
		if (err) {
			abort_err = ntfs_log_abort(handle);
			if (abort_err)
				err = abort_err;
		} else {
			err = ntfs_log_commit(handle);
		}
	}
	mutex_unlock(&mrec_ni->mrec_lock);
out:
	return err;
}

static int ntfs_collapse_range(struct ntfs_inode *ni, loff_t offset, loff_t len)
{
	struct ntfs_inode *mrec_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct inode *vi = VFS_I(ni);
	loff_t old_size, new_size;
	loff_t range_end;
	s64 start_vcn, end_vcn;
	struct ntfs_log_handle *handle = NULL;
	int abort_err;
	int credits;
	int err;

	loff_t offset_down = round_down(offset,
			max_t(unsigned long, vol->cluster_size, PAGE_SIZE));

	if (offset < 0 || len <= 0 ||
	    check_add_overflow(offset, len, &range_end) ||
	    (offset & vol->cluster_size_mask) ||
	    (len & vol->cluster_size_mask) ||
	    offset >= ni->allocated_size) {
		err = -EINVAL;
		goto out;
	}

	old_size = i_size_read(vi);
	start_vcn = ntfs_bytes_to_cluster(vol, offset);
	end_vcn = ntfs_bytes_to_cluster(vol, range_end - 1) + 1;

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

	if (vol->journal) {
		credits = ntfs_attr_range_update_log_credits_for_inode(ni,
				end_vcn - start_vcn, false, true);
		if (credits < 0) {
			err = credits;
			goto out;
		}
		handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			handle = NULL;
			goto out;
		}
	}
	mutex_lock_nested(&mrec_ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	if (handle)
		err = ntfs_non_resident_attr_collapse_range_transacted(handle,
				ni, start_vcn, end_vcn - start_vcn);
	else
		err = ntfs_non_resident_attr_collapse_range(ni, start_vcn,
				end_vcn - start_vcn);
	if (handle) {
		if (err) {
			abort_err = ntfs_log_abort(handle);
			if (abort_err)
				err = abort_err;
		} else {
			err = ntfs_log_commit(handle);
		}
	}
	mutex_unlock(&mrec_ni->mrec_lock);

	if (new_size != old_size)
		i_size_write(vi, ni->data_size);
out:
	return err;
}

static int ntfs_insert_range(struct ntfs_inode *ni, loff_t offset, loff_t len)
{
	struct ntfs_inode *mrec_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct inode *vi = VFS_I(ni);
	loff_t offset_down = round_down(offset,
			max_t(unsigned long, vol->cluster_size, PAGE_SIZE));
	loff_t alloc_size, end_offset;
	loff_t old_size, new_size;
	loff_t range_bytes;
	s64 start_vcn, end_vcn;
	struct ntfs_log_handle *handle = NULL;
	int abort_err;
	int credits;
	int err;

	if (NVolDisableSparse(vol)) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (offset < 0 || len <= 0 ||
	    check_add_overflow(offset, len, &end_offset) ||
	    (offset & vol->cluster_size_mask) ||
	    (len & vol->cluster_size_mask) ||
	     offset >= ni->allocated_size) {
		err = -EINVAL;
		goto out;
	}

	old_size = i_size_read(vi);
	start_vcn = ntfs_bytes_to_cluster(vol, offset);
	end_vcn = ntfs_bytes_to_cluster(vol, end_offset - 1) + 1;

	range_bytes = ntfs_cluster_to_bytes(vol, end_vcn - start_vcn);
	if (range_bytes < 0 || check_add_overflow(old_size, range_bytes,
			&new_size) || check_add_overflow(ni->allocated_size,
			range_bytes, &alloc_size)) {
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

	if (vol->journal) {
		credits = ntfs_attr_range_update_log_credits_for_inode(ni,
				end_vcn - start_vcn, false, false);
		if (credits < 0) {
			err = credits;
			goto out;
		}
		handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			handle = NULL;
			goto out;
		}
	}
	mutex_lock_nested(&mrec_ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	if (handle)
		err = ntfs_non_resident_attr_insert_range_transacted(handle, ni,
				start_vcn, end_vcn - start_vcn);
	else
		err = ntfs_non_resident_attr_insert_range(ni, start_vcn,
				end_vcn - start_vcn);
	if (handle) {
		if (err) {
			abort_err = ntfs_log_abort(handle);
			if (abort_err)
				err = abort_err;
		} else {
			err = ntfs_log_commit(handle);
		}
	}
	mutex_unlock(&mrec_ni->mrec_lock);

	if (new_size != old_size)
		i_size_write(vi, ni->data_size);
out:
	return err;
}

#define NTFS_FALLOC_FL_SUPPORTED					\
		(FALLOC_FL_ALLOCATE_RANGE | FALLOC_FL_KEEP_SIZE |	\
		 FALLOC_FL_INSERT_RANGE | FALLOC_FL_PUNCH_HOLE |	\
		 FALLOC_FL_COLLAPSE_RANGE)

long ntfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *vi = file_inode(file);
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	bool stream = ntfs_inode_is_named_stream(ni);
	int err = 0;
	loff_t old_size, new_size;

	if (mode & ~(NTFS_FALLOC_FL_SUPPORTED))
		return -EOPNOTSUPP;

	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni))
		return -EOPNOTSUPP;

	if (!NVolFreeClusterKnown(vol))
		wait_event(vol->free_waitq, NVolFreeClusterKnown(vol));

	if (NInoNonResident(ni) && !NInoFullyMapped(ni)) {
		down_write(&ni->runlist.lock);
		err = ntfs_attr_map_whole_runlist(ni);
		up_write(&ni->runlist.lock);
		if (err)
			return err;
	}

	err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
	if (err)
		return err;

	inode_lock(vi);
	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni)) {
		inode_unlock(vi);
		return -EOPNOTSUPP;
	}
	if (stream) {
		err = ntfs_stream_validate_for_mutation(vi, false);
		if (err) {
			inode_unlock(vi);
			return err;
		}
	}
	old_size = i_size_read(vi);

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
	if (!err && mode == 0 && NInoNonResident(ni)) {
		new_size = i_size_read(vi);
		if (new_size > old_size) {
			truncate_pagecache(vi, old_size);
			ntfs_pagecache_extend(vi, old_size, new_size);
		}
	}

	filemap_invalidate_unlock(vi->i_mapping);

	if (!err) {
		if (stream) {
			ntfs_stream_update_base_time(base_ni);
		} else {
			NInoSetFileNameDirty(ni);
			inode_set_mtime_to_ts(vi, inode_set_ctime_current(vi));
			mark_inode_dirty(vi);
		}
	}

	inode_unlock(vi);
	return err;
}

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
	.fileattr_get	= ntfs_fileattr_get,
	.fileattr_set	= ntfs_fileattr_set,
	.listxattr	= ntfs_listxattr,
	.get_acl	= ntfs_get_acl,
	.set_acl	= ntfs_set_acl,
	.fiemap		= ntfs_fiemap,
};

const struct inode_operations ntfs_symlink_inode_operations = {
	.get_link	= ntfs_get_link,
	.setattr	= ntfs_setattr,
	.getattr	= ntfs_getattr,
	.listxattr	= ntfs_listxattr,
	.fileattr_get	= ntfs_fileattr_get,
	.fileattr_set	= ntfs_fileattr_set,
};

const struct inode_operations ntfs_special_inode_operations = {
	.setattr	= ntfs_setattr,
	.getattr	= ntfs_getattr,
	.listxattr	= ntfs_listxattr,
	.fileattr_get	= ntfs_fileattr_get,
	.fileattr_set	= ntfs_fileattr_set,
	.get_acl	= ntfs_get_acl,
	.set_acl	= ntfs_set_acl,
};

const struct file_operations ntfs_empty_file_ops = {};

const struct inode_operations ntfs_empty_inode_ops = {};
