// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS kernel index handling.
 *
 * Copyright (c) 2004-2005 Anton Altaparmakov
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 *
 * Part of this file is based on code from the NTFS-3G.
 * and is copyrighted by the respective authors below:
 * Copyright (c) 2004-2005 Anton Altaparmakov
 * Copyright (c) 2004-2005 Richard Russon
 * Copyright (c) 2005-2006 Yura Pakhuchiy
 * Copyright (c) 2005-2008 Szabolcs Szakacsits
 * Copyright (c) 2007-2021 Jean-Pierre Andre
 */

#include <linux/overflow.h>
#include <linux/blkdev.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/xarray.h>

#include "collate.h"
#include "index.h"
#include "ntfs.h"
#include "attrlist.h"
#include "lcnalloc.h"
#include "logfile.h"

#define ntfs_index_kvmemdup kvmemdup

#define MAX_RETIRED_INDEX_VCNS	(MAX_PARENT_VCN + 1)

static int ntfs_index_entries_validate(struct index_header *ih, bool node);

/*
 * ntfs_index_entry_inconsistent - Check the consistency of an index entry
 *
 * Make sure data and key do not overflow from entry.
 * As a side effect, an entry with zero length is rejected.
 * This entry must be a full one (no INDEX_ENTRY_END flag), and its
 * length must have been checked beforehand to not overflow from the
 * index record.
 */
static int ntfs_index_entry_inconsistent(const struct ntfs_volume *vol,
					 const struct index_entry *ie,
					 __le32 collation_rule, u64 inum)
{
	if (ie->key_length &&
	    ((le16_to_cpu(ie->key_length) + offsetof(struct index_entry, key)) >
	     le16_to_cpu(ie->length))) {
		ntfs_error(vol->sb, "Overflow from index entry in inode %lld\n",
				(long long)inum);
		return -EIO;

	} else {
		if (collation_rule == COLLATION_FILE_NAME) {
			if (le16_to_cpu(ie->key_length) <
			    offsetof(struct file_name_attr, file_name) ||
			    (offsetof(struct file_name_attr, file_name) +
			     ie->key.file_name.file_name_length * sizeof(__le16)) >
					le16_to_cpu(ie->key_length)) {
				ntfs_error(vol->sb,
					"File name overflow from index entry in inode %lld\n",
					(long long)inum);
				return -EIO;
			}
		} else {
			if (ie->data.vi.data_length &&
			    ((le16_to_cpu(ie->data.vi.data_offset) +
			      le16_to_cpu(ie->data.vi.data_length)) >
			     le16_to_cpu(ie->length))) {
				ntfs_error(vol->sb,
					"Data overflow from index entry in inode %lld\n",
					(long long)inum);
				return -EIO;
			}
		}
	}

	return 0;
}

/*
 * ntfs_index_entry_mark_dirty - mark an index entry dirty
 * @ictx:	ntfs index context describing the index entry
 *
 * Mark the index entry described by the index entry context @ictx dirty.
 *
 * If the index entry is in the index root attribute, simply mark the inode
 * containing the index root attribute dirty.  This ensures the mftrecord, and
 * hence the index root attribute, will be written out to disk later.
 *
 * If the index entry is in an index block belonging to the index allocation
 * attribute, set ib_dirty to true, thus index block will be updated during
 * ntfs_index_ctx_put.
 */
void ntfs_index_entry_mark_dirty(struct ntfs_index_context *ictx)
{
	if (ictx->is_in_root)
		mark_mft_record_dirty(ictx->actx->ntfs_ino);
	else if (ictx->ib)
		ictx->ib_dirty = true;
}

static s64 ntfs_ib_vcn_to_pos(struct ntfs_index_context *icx, s64 vcn)
{
	return vcn << icx->vcn_size_bits;
}

static s64 ntfs_ib_pos_to_vcn(struct ntfs_index_context *icx, s64 pos)
{
	return pos >> icx->vcn_size_bits;
}

/* Open the index allocation inode if no earlier step of the operation did. */
static int ntfs_icx_ia_ensure(struct ntfs_index_context *icx)
{
	if (!icx->ia_ni) {
		icx->ia_ni = ntfs_ia_open(icx, icx->idx_ni);
		if (!icx->ia_ni)
			return -EIO;
	}
	/* Without $INDEX_ALLOCATION the index inode is an empty resident stub. */
	if (!NInoNonResident(icx->ia_ni))
		return -EIO;
	return 0;
}

struct ntfs_index_block_home_undo {
	struct inode *vi;
	s64 pos;
	u32 block_size;
	u8 block[];
};

struct ntfs_index_bitmap_byte_home_undo {
	struct inode *vi;
	u64 dev_off;
	s64 byte_pos;
	u8 old_byte;
};

struct ntfs_index_allocation_home_undo {
	struct inode *vi;
	struct inode *base_vi;
	struct runlist_element *runlist;
	size_t runlist_count;
	int runlist_hint;
	s64 allocated_size;
	s64 data_size;
	s64 initialized_size;
	s64 zeroed_size;
	loff_t i_size;
	blkcnt_t vi_i_blocks;
	blkcnt_t i_blocks;
};

struct ntfs_index_state_home_undo {
	struct inode *vi;
	bool index_alloc_present;
};

struct ntfs_index_inode_state_home_undo {
	struct inode *vi;
	unsigned long state;
	__le32 type;
	blkcnt_t i_blocks;
	unsigned int nlink;
};

struct ntfs_index_attr_size_home_undo {
	struct inode *vi;
	s64 allocated_size;
	s64 data_size;
	s64 initialized_size;
	s64 zeroed_size;
	loff_t i_size;
};

static int ntfs_index_state_home_restore(void *data)
{
	struct ntfs_index_state_home_undo *undo = data;
	struct ntfs_inode *ni = NTFS_I(undo->vi);

	if (undo->index_alloc_present)
		NInoSetIndexAllocPresent(ni);
	else
		NInoClearIndexAllocPresent(ni);
	return 0;
}

static void ntfs_index_state_home_release(void *data)
{
	struct ntfs_index_state_home_undo *undo = data;

	iput(undo->vi);
	kfree(undo);
}

static int ntfs_index_state_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_index_state_home_undo *undo;
	struct inode *vi;
	int err;

	if (!handle || !ni)
		return -EINVAL;
	undo = kmalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	vi = VFS_I(ni);
	ihold(vi);
	undo->vi = vi;
	undo->index_alloc_present = NInoIndexAllocPresent(ni);
	err = ntfs_log_register_home_undo(handle,
			ntfs_index_state_home_restore,
			ntfs_index_state_home_release, undo);
	if (err)
		ntfs_index_state_home_release(undo);
	return err;
}

static int ntfs_index_inode_state_home_restore(void *data)
{
	struct ntfs_index_inode_state_home_undo *undo = data;
	struct ntfs_inode *ni = NTFS_I(undo->vi);

	ni->state = undo->state;
	ni->type = undo->type;
	undo->vi->i_blocks = undo->i_blocks;
	set_nlink(undo->vi, undo->nlink);
	return 0;
}

static void ntfs_index_inode_state_home_release(void *data)
{
	struct ntfs_index_inode_state_home_undo *undo = data;

	iput(undo->vi);
	kfree(undo);
}

static int ntfs_index_inode_state_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_index_inode_state_home_undo *undo;
	struct inode *vi;
	int err;

	if (!handle || !ni)
		return -EINVAL;
	undo = kmalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	vi = VFS_I(ni);
	ihold(vi);
	undo->vi = vi;
	undo->state = ni->state;
	undo->type = ni->type;
	undo->i_blocks = vi->i_blocks;
	undo->nlink = vi->i_nlink;
	err = ntfs_log_register_home_undo(handle,
			ntfs_index_inode_state_home_restore,
			ntfs_index_inode_state_home_release, undo);
	if (err)
		ntfs_index_inode_state_home_release(undo);
	return err;
}

static int ntfs_index_allocation_home_restore(void *data)
{
	struct ntfs_index_allocation_home_undo *undo = data;
	struct ntfs_inode *ni = NTFS_I(undo->vi);

	down_write(&ni->runlist.lock);
	kvfree(ni->runlist.rl);
	ni->runlist.rl = undo->runlist;
	undo->runlist = NULL;
	ni->runlist.count = undo->runlist_count;
	ni->runlist.rl_hint = undo->runlist_hint;
	ni->allocated_size = undo->allocated_size;
	ni->data_size = undo->data_size;
	ni->initialized_size = undo->initialized_size;
	ni->zeroed_size = undo->zeroed_size;
	i_size_write(undo->vi, undo->i_size);
	undo->vi->i_blocks = undo->vi_i_blocks;
	undo->base_vi->i_blocks = undo->i_blocks;
	up_write(&ni->runlist.lock);
	return 0;
}

static int ntfs_index_attr_size_home_restore(void *data)
{
	struct ntfs_index_attr_size_home_undo *undo = data;
	struct ntfs_inode *ni = NTFS_I(undo->vi);

	ni->allocated_size = undo->allocated_size;
	ni->data_size = undo->data_size;
	ni->initialized_size = undo->initialized_size;
	ni->zeroed_size = undo->zeroed_size;
	i_size_write(undo->vi, undo->i_size);
	return 0;
}

static void ntfs_index_attr_size_home_release(void *data)
{
	struct ntfs_index_attr_size_home_undo *undo = data;

	iput(undo->vi);
	kfree(undo);
}

static int ntfs_index_attr_size_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_index_attr_size_home_undo *undo;
	struct inode *vi;
	int err;

	if (!handle || !ni)
		return -EINVAL;
	undo = kmalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	vi = VFS_I(ni);
	ihold(vi);
	undo->vi = vi;
	undo->allocated_size = ni->allocated_size;
	undo->data_size = ni->data_size;
	undo->initialized_size = ni->initialized_size;
	undo->zeroed_size = ni->zeroed_size;
	undo->i_size = i_size_read(vi);
	err = ntfs_log_register_home_undo(handle,
			ntfs_index_attr_size_home_restore,
			ntfs_index_attr_size_home_release, undo);
	if (err)
		ntfs_index_attr_size_home_release(undo);
	return err;
}

static void ntfs_index_allocation_home_release(void *data)
{
	struct ntfs_index_allocation_home_undo *undo = data;

	kvfree(undo->runlist);
	iput(undo->base_vi);
	iput(undo->vi);
	kfree(undo);
}

static int ntfs_index_allocation_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_index_allocation_home_undo *undo;
	struct ntfs_inode *base_ni;
	struct inode *vi;
	struct inode *base_vi;
	size_t bytes;
	int err;

	if (!handle || !ni || (ni->runlist.count && !ni->runlist.rl))
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	if (ni->runlist.count &&
	    check_mul_overflow(ni->runlist.count,
		    sizeof(*ni->runlist.rl), &bytes))
		return -EOVERFLOW;
	undo = kzalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	if (ni->runlist.count) {
		undo->runlist = ntfs_index_kvmemdup(ni->runlist.rl, bytes,
				GFP_NOFS);
		if (!undo->runlist) {
			kfree(undo);
			return -ENOMEM;
		}
	}
	vi = VFS_I(ni);
	base_vi = VFS_I(base_ni);
	ihold(vi);
	ihold(base_vi);
	undo->vi = vi;
	undo->base_vi = base_vi;
	undo->runlist_count = ni->runlist.count;
	undo->runlist_hint = ni->runlist.rl_hint;
	undo->allocated_size = ni->allocated_size;
	undo->data_size = ni->data_size;
	undo->initialized_size = ni->initialized_size;
	undo->zeroed_size = ni->zeroed_size;
	undo->i_size = i_size_read(vi);
	undo->vi_i_blocks = vi->i_blocks;
	undo->i_blocks = base_vi->i_blocks;
	err = ntfs_log_register_home_undo(handle,
			ntfs_index_allocation_home_restore,
			ntfs_index_allocation_home_release, undo);
	if (err)
		ntfs_index_allocation_home_release(undo);
	return err;
}

/*
 * Reinitialize a cached index-allocation inode after the on-disk stream was
 * removed and a new empty stream was created in the same transaction.  Index
 * inodes are cached by base inode and name, so an inode from an earlier
 * allocation can survive while ntfs_attr_exist() quite correctly reports no
 * current attribute.  Keep the old in-memory state undoable, then make the
 * inode describe the newly-created empty stream.
 */
static int ntfs_index_allocation_reset_empty_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_inode *base_ni;
	struct inode *vi;
	bool stale;
	int err;

	if (!handle || !ni || !NInoAttr(ni))
		return -EINVAL;
	base_ni = ni->ext.base_ntfs_ino;
	if (!base_ni)
		return -EIO;
	vi = VFS_I(ni);
	stale = ni->runlist.rl || ni->runlist.count ||
		ni->allocated_size || ni->data_size || ni->initialized_size ||
		ni->zeroed_size || i_size_read(vi) || vi->i_blocks ||
		NInoNonResident(ni) || NInoIndexAllocPresent(ni) ||
		NInoFullyMapped(ni) || NInoCompressed(ni) ||
		NInoEncrypted(ni) || NInoSparse(ni) || NInoRunlistDirty(ni);
	if (!stale)
		return 0;

	err = ntfs_index_allocation_register_home_undo(handle, ni);
	if (err)
		return err;

	down_write(&ni->runlist.lock);
	kvfree(ni->runlist.rl);
	ni->runlist.rl = NULL;
	ni->runlist.count = 0;
	ni->runlist.rl_hint = -1;
	ni->allocated_size = 0;
	ni->data_size = 0;
	ni->initialized_size = 0;
	ni->zeroed_size = 0;
	i_size_write(vi, 0);
	vi->i_blocks = 0;
	VFS_I(base_ni)->i_blocks = 0;
	NInoClearNonResident(ni);
	NInoClearIndexAllocPresent(ni);
	NInoClearFullyMapped(ni);
	NInoClearCompressed(ni);
	NInoClearEncrypted(ni);
	NInoClearSparse(ni);
	NInoClearRunlistDirty(ni);
	ni->itype.compressed.size = 0;
	up_write(&ni->runlist.lock);
	truncate_inode_pages(vi->i_mapping, 0);
	return 0;
}

static int ntfs_index_block_home_restore(void *data)
{
	struct ntfs_index_block_home_undo *undo = data;
	s64 ret;

	ret = pre_write_mst_fixup((struct ntfs_record *)undo->block,
			undo->block_size);
	if (ret)
		return -EIO;
	ret = ntfs_inode_attr_pwrite(undo->vi, undo->pos, undo->block_size,
			undo->block, false);
	if (ret == undo->block_size)
		return 0;
	return ret < 0 ? ret : -EIO;
}

static void ntfs_index_block_home_release(void *data)
{
	struct ntfs_index_block_home_undo *undo = data;

	iput(undo->vi);
	kvfree(undo);
}

static int ntfs_index_block_register_buffer_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		const struct index_block *ib)
{
	struct ntfs_index_block_home_undo *undo;
	struct inode *vi;
	s64 vcn;
	s64 pos;
	int err;

	if (!handle || !icx || !icx->ia_ni || !ib)
		return -EINVAL;
	vcn = le64_to_cpu(ib->index_block_vcn);
	if (vcn < 0 || check_shl_overflow(vcn, icx->vcn_size_bits, &pos))
		return -EOVERFLOW;

	undo = kvzalloc(struct_size(undo, block, icx->block_size), GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	vi = VFS_I(icx->ia_ni);
	ihold(vi);
	undo->vi = vi;
	undo->pos = pos;
	undo->block_size = icx->block_size;
	memcpy(undo->block, ib, icx->block_size);
	err = ntfs_log_register_home_undo(handle,
			ntfs_index_block_home_restore,
			ntfs_index_block_home_release, undo);
	if (err)
		ntfs_index_block_home_release(undo);
	return err;
}

static int ntfs_index_block_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx)
{
	return ntfs_index_block_register_buffer_home_undo(handle, icx,
			icx ? icx->ib : NULL);
}

static int ntfs_ib_write(struct ntfs_index_context *icx, struct index_block *ib)
{
	s64 ret, vcn = le64_to_cpu(ib->index_block_vcn);

	/* Buffered INDX writes are gated by the attribute inode's writeback LSN. */
	if (icx->sync_write) {
		ret = ntfs_log_wait_lsn(icx->ia_ni->vol, le64_to_cpu(ib->lsn));
		if (ret)
			return ret;
	}
	ntfs_debug("vcn: %lld\n", vcn);

	ret = ntfs_icx_ia_ensure(icx);
	if (ret)
		return ret;

	ret = pre_write_mst_fixup((struct ntfs_record *)ib, icx->block_size);
	if (ret)
		return -EIO;

	ret = ntfs_inode_attr_pwrite(VFS_I(icx->ia_ni),
			ntfs_ib_vcn_to_pos(icx, vcn), icx->block_size,
			(u8 *)ib, icx->sync_write);

	/* Perform data restoration before returning */
	post_write_mst_fixup((struct ntfs_record *)ib);

	if (ret != icx->block_size) {
		ntfs_debug("Failed to write index block %lld, inode %llu",
				vcn, (unsigned long long)icx->idx_ni->mft_no);
		return ret;
	}

	return 0;
}

static int ntfs_icx_ib_write(struct ntfs_index_context *icx)
{
	int err;

	err = ntfs_ib_write(icx, icx->ib);
	if (err)
		return err;

	icx->ib_dirty = false;

	return 0;
}

int ntfs_icx_ib_sync_write(struct ntfs_index_context *icx)
{
	int ret;

	if (icx->ib_dirty == false)
		return 0;

	icx->sync_write = true;

	ret = ntfs_ib_write(icx, icx->ib);
	if (!ret) {
		kvfree(icx->ib);
		icx->ib = NULL;
		icx->ib_dirty = false;
	} else {
		icx->sync_write = false;
	}

	return ret;
}

/*
 * ntfs_index_ctx_get - allocate and initialize a new index context
 * @ni:		ntfs inode with which to initialize the context
 * @name:	name of the which context describes
 * @name_len:	length of the index name
 *
 * Allocate a new index context, initialize it with @ni and return it.
 * Return NULL if allocation failed.
 */
struct ntfs_index_context *ntfs_index_ctx_get(struct ntfs_inode *ni,
		__le16 *name, u32 name_len)
{
	struct ntfs_index_context *icx;

	ntfs_debug("Entering\n");

	if (!ni)
		return NULL;

	if (ni->nr_extents == -1)
		ni = ni->ext.base_ntfs_ino;

	icx = kmem_cache_alloc(ntfs_index_ctx_cache, GFP_NOFS);
	if (icx)
		*icx = (struct ntfs_index_context) {
			.idx_ni = ni,
			.name = name,
			.name_len = name_len,
		};
	return icx;
}

static void ntfs_index_ctx_free(struct ntfs_index_context *icx)
{
	ntfs_debug("Entering\n");

	if (icx->actx) {
		ntfs_attr_put_search_ctx(icx->actx);
		icx->actx = NULL;
	}

	if (!icx->is_in_root) {
		if (icx->ib_dirty)
			ntfs_ib_write(icx, icx->ib);
		kvfree(icx->ib);
		icx->ib = NULL;
	}

	if (icx->ia_ni) {
		iput(VFS_I(icx->ia_ni));
		icx->ia_ni = NULL;
	}
}

/*
 * ntfs_index_ctx_put - release an index context
 * @icx:	index context to free
 *
 * Release the index context @icx, releasing all associated resources.
 */
void ntfs_index_ctx_put(struct ntfs_index_context *icx)
{
	ntfs_index_ctx_free(icx);
	kmem_cache_free(ntfs_index_ctx_cache, icx);
}

void ntfs_system_index_ctx_put(struct ntfs_system_index_ctx *ctx)
{
	if (ctx->index) {
		struct inode *vi = VFS_I(ctx->index->idx_ni);

		ntfs_index_ctx_put(ctx->index);
		iput(vi);
		ctx->index = NULL;
	}
	if (ctx->attr) {
		iput(ctx->attr);
		ctx->attr = NULL;
	}
}

/*
 * ntfs_index_ctx_reinit - reinitialize an index context
 * @icx:	index context to reinitialize
 *
 * Reinitialize the index context @icx so it can be used for ntfs_index_lookup.
 */
void ntfs_index_ctx_reinit(struct ntfs_index_context *icx)
{
	ntfs_debug("Entering\n");

	ntfs_index_ctx_free(icx);

	*icx = (struct ntfs_index_context) {
		.idx_ni = icx->idx_ni,
		.name = icx->name,
		.name_len = icx->name_len,
	};
}

static __le64 *ntfs_ie_get_vcn_addr(struct index_entry *ie)
{
	return (__le64 *)((u8 *)ie + le16_to_cpu(ie->length) - sizeof(s64));
}

/*
 *  Get the subnode vcn to which the index entry refers.
 */
static s64 ntfs_ie_get_vcn(struct index_entry *ie)
{
	return le64_to_cpup(ntfs_ie_get_vcn_addr(ie));
}

static int ntfs_index_entry_vcn_inconsistent(const struct ntfs_volume *vol,
					     struct index_entry *ie,
					     u8 vcn_size_bits, u64 inum)
{
	s64 vcn, pos;

	if (le16_to_cpu(ie->length) <
	    sizeof(struct index_entry_header) + sizeof(s64)) {
		ntfs_error(vol->sb,
			   "Index entry with node flag has no VCN in inode %llu.",
			   (unsigned long long)inum);
		return -EIO;
	}

	vcn = ntfs_ie_get_vcn(ie);
	if (vcn < 0 ||
	    check_shl_overflow(vcn, vcn_size_bits, &pos)) {
		ntfs_error(vol->sb,
			   "Invalid index entry VCN %lld in inode %llu.",
			   vcn, (unsigned long long)inum);
		return -EIO;
	}

	return 0;
}

static struct index_entry *ntfs_ie_get_first(struct index_header *ih)
{
	return (struct index_entry *)((u8 *)ih + le32_to_cpu(ih->entries_offset));
}

static struct index_entry *ntfs_ie_get_next(struct index_entry *ie)
{
	return (struct index_entry *)((char *)ie + le16_to_cpu(ie->length));
}

static u8 *ntfs_ie_get_end(struct index_header *ih)
{
	return (u8 *)ih + le32_to_cpu(ih->index_length);
}

static int ntfs_ie_end(struct index_entry *ie)
{
	return ie->flags & INDEX_ENTRY_END || !ie->length;
}

static int ntfs_index_header_inconsistent(struct ntfs_volume *vol,
					  const struct index_header *ih,
					  u32 bytes_available, u64 inum)
{
	u32 entries_offset, index_length, allocated_size;

	if (bytes_available < sizeof(struct index_header)) {
		ntfs_error(vol->sb,
			   "index block in inode %llu is smaller than an index header.",
			   (unsigned long long)inum);
		return -EIO;
	}

	entries_offset = le32_to_cpu(ih->entries_offset);
	index_length = le32_to_cpu(ih->index_length);
	allocated_size = le32_to_cpu(ih->allocated_size);

	if (entries_offset < sizeof(struct index_header) ||
	    entries_offset > bytes_available) {
		ntfs_error(vol->sb,
			   "Invalid index entry offset in inode %llu.",
			   (unsigned long long)inum);
		return -EIO;
	}

	if (index_length <= entries_offset) {
		ntfs_error(vol->sb,
			   "No space for index entries in inode %llu.",
			   (unsigned long long)inum);
		return -EIO;
	}

	if (allocated_size < index_length) {
		ntfs_error(vol->sb,
			   "Index entries overflow in inode %llu.",
			   (unsigned long long)inum);
		return -EIO;
	}

	if (allocated_size > bytes_available || index_length > bytes_available) {
		ntfs_error(vol->sb,
			   "Index entries in inode %llu exceed the available buffer.",
			   (unsigned long long)inum);
		return -EIO;
	}

	return 0;
}

int ntfs_index_entries_inconsistent(const struct ntfs_volume *vol,
				    const struct index_header *ih,
				    u32 block_size,
				    __le32 collation_rule, u64 inum)
{
	struct index_entry *ie;
	u8 *index_end = (u8 *)ih + le32_to_cpu(ih->index_length);
	u8 vcn_size_bits = vol->cluster_size <= block_size ?
			vol->cluster_size_bits : NTFS_BLOCK_SIZE_BITS;

	for (ie = ntfs_ie_get_first((struct index_header *)ih);
	      ; ie = ntfs_ie_get_next(ie)) {
		if ((u8 *)ie + sizeof(struct index_entry_header) > index_end ||
		    (u8 *)ie + le16_to_cpu(ie->length) > index_end) {
			ntfs_error(vol->sb,
				   "Index entry out of bounds in inode %llu.",
				   (unsigned long long)inum);
			return -EIO;
		}

		if (le16_to_cpu(ie->length) < sizeof(struct index_entry_header)) {
			ntfs_error(vol->sb,
				   "Index entry too small in inode %llu.",
				   inum);
			return -EIO;
		}

		if ((ie->flags & INDEX_ENTRY_NODE) &&
		    ntfs_index_entry_vcn_inconsistent(vol, ie,
						      vcn_size_bits, inum))
			return -EIO;

		if (ntfs_ie_end(ie))
			break;

		if (!ie->key_length)
			return -EIO;

		if (ntfs_index_entry_inconsistent(vol, ie,
						  collation_rule, inum))
			return -EIO;
	}

	return 0;
}

/*
 *  Find the last entry in the index block
 */
static struct index_entry *ntfs_ie_get_last(struct index_entry *ie, char *ies_end)
{
	ntfs_debug("Entering\n");

	while ((char *)ie < ies_end && !ntfs_ie_end(ie))
		ie = ntfs_ie_get_next(ie);

	return ie;
}

static struct index_entry *ntfs_ie_get_by_pos(struct index_header *ih, int pos)
{
	struct index_entry *ie;

	ntfs_debug("pos: %d\n", pos);

	ie = ntfs_ie_get_first(ih);

	while (pos-- > 0)
		ie = ntfs_ie_get_next(ie);

	return ie;
}

static struct index_entry *ntfs_ie_prev(struct index_header *ih, struct index_entry *ie)
{
	struct index_entry *ie_prev = NULL;
	struct index_entry *tmp;

	ntfs_debug("Entering\n");

	tmp = ntfs_ie_get_first(ih);

	while (tmp != ie) {
		ie_prev = tmp;
		tmp = ntfs_ie_get_next(tmp);
	}

	return ie_prev;
}

static int ntfs_ih_numof_entries(struct index_header *ih)
{
	int n;
	struct index_entry *ie;
	u8 *end;

	ntfs_debug("Entering\n");

	end = ntfs_ie_get_end(ih);
	ie = ntfs_ie_get_first(ih);
	for (n = 0; !ntfs_ie_end(ie) && (u8 *)ie < end; n++)
		ie = ntfs_ie_get_next(ie);
	return n;
}

static int ntfs_ih_one_entry(struct index_header *ih)
{
	return (ntfs_ih_numof_entries(ih) == 1);
}

static int ntfs_ih_zero_entry(struct index_header *ih)
{
	return (ntfs_ih_numof_entries(ih) == 0);
}

static void ntfs_ie_delete(struct index_header *ih, struct index_entry *ie)
{
	u32 new_size;

	ntfs_debug("Entering\n");

	new_size = le32_to_cpu(ih->index_length) - le16_to_cpu(ie->length);
	ih->index_length = cpu_to_le32(new_size);
	memmove(ie, (u8 *)ie + le16_to_cpu(ie->length),
			new_size - ((u8 *)ie - (u8 *)ih));
}

static void ntfs_ie_set_vcn(struct index_entry *ie, s64 vcn)
{
	*ntfs_ie_get_vcn_addr(ie) = cpu_to_le64(vcn);
}

/*
 *  Insert @ie index entry at @pos entry. Used @ih values should be ok already.
 */
static void ntfs_ie_insert(struct index_header *ih, struct index_entry *ie,
		struct index_entry *pos)
{
	int ie_size = le16_to_cpu(ie->length);

	ntfs_debug("Entering\n");

	ih->index_length = cpu_to_le32(le32_to_cpu(ih->index_length) + ie_size);
	memmove((u8 *)pos + ie_size, pos,
			le32_to_cpu(ih->index_length) - ((u8 *)pos - (u8 *)ih) - ie_size);
	memcpy(pos, ie, ie_size);
}

static struct index_entry *ntfs_ie_dup(struct index_entry *ie)
{
	ntfs_debug("Entering\n");

	return kmemdup(ie, le16_to_cpu(ie->length), GFP_NOFS);
}

static struct index_entry *ntfs_ie_dup_novcn(struct index_entry *ie)
{
	struct index_entry *dup;
	int size = le16_to_cpu(ie->length);

	ntfs_debug("Entering\n");

	if (ie->flags & INDEX_ENTRY_NODE)
		size -= sizeof(s64);

	dup = kmemdup(ie, size, GFP_NOFS);
	if (dup) {
		dup->flags &= ~INDEX_ENTRY_NODE;
		dup->length = cpu_to_le16(size);
	}
	return dup;
}

/* Offset of the first entry in an index block created by ntfs_ib_alloc(). */
static u32 ntfs_ib_canonical_entries_offset(u32 block_size)
{
	u32 usa_count = block_size / NTFS_BLOCK_SIZE + 1;

	return (sizeof(struct index_header) + usa_count * 2 + 7) & ~7;
}

/*
 * Check the consistency of an index block
 *
 * Make sure the index block does not overflow from the index record.
 * The size of block is assumed to have been checked to be what is
 * defined in the index root.
 *
 * Returns 0 if no error was found, -EIO otherwise
 *
 * |<--->|  offsetof(struct index_block, index)
 * |     |<--->|  sizeof(struct index_header)
 * |     |     |
 * |     |     | seq          index entries         unused
 * |=====|=====|=====|===========================|==============|
 * |     |           |                           |              |
 * |     |<--------->| entries_offset            |              |
 * |     |<---------------- index_length ------->|              |
 * |     |<--------------------- allocated_size --------------->|
 * |<--------------------------- block_size ------------------->|
 *
 * size(struct index_header) <= ent_offset < ind_length <= alloc_size < bk_size
 */
int ntfs_index_block_inconsistent(struct ntfs_volume *vol,
				  const struct index_block *ib,
				  u32 block_size, s64 vcn, __le32 cr,
				  u64 inum)
{
	u32 ib_size = (unsigned int)le32_to_cpu(ib->index.allocated_size) +
		offsetof(struct index_block, index);
	struct super_block *sb = vol->sb;

	ntfs_debug("Entering\n");

	if (!ntfs_is_indx_record(ib->magic)) {
		ntfs_error(sb, "Corrupt index block signature: vcn %lld inode %llu\n",
			   vcn, (unsigned long long)inum);
		return -EIO;
	}

	if (le64_to_cpu(ib->index_block_vcn) != vcn) {
		ntfs_error(sb,
			"Corrupt index block: s64 (%lld) is different from expected s64 (%lld) in inode %llu\n",
			(long long)le64_to_cpu(ib->index_block_vcn),
			vcn, inum);
		return -EIO;
	}

	if (ib_size != block_size) {
		ntfs_error(sb,
			   "Corrupt index block : s64 (%lld) of inode %llu has a size (%u) differing from the index specified size (%u)\n",
			   vcn, inum, ib_size, block_size);
		return -EIO;
	}

	if (ntfs_index_header_inconsistent(vol, &ib->index,
					   block_size -
					   offsetof(struct index_block, index),
					   inum))
		return -EIO;

	if (le32_to_cpu(ib->index.entries_offset) <
	    ntfs_ib_canonical_entries_offset(block_size)) {
		ntfs_error(sb,
			   "Index block: entries offset %u is below the minimum for a %u-byte block: vcn %lld inode %llu\n",
			   le32_to_cpu(ib->index.entries_offset), block_size,
			   vcn, inum);
		return -EIO;
	}

	if (ntfs_index_entries_inconsistent(vol, &ib->index, block_size,
					    cr, inum))
		return -EIO;
	return 0;
}

int ntfs_index_root_inconsistent(struct ntfs_volume *vol,
				 const struct attr_record *a,
				 const struct index_root *ir, u64 inum)
{
	u32 value_length = le32_to_cpu(a->data.resident.value_length);

	if (value_length < offsetof(struct index_root, index)) {
		ntfs_error(vol->sb, "$INDEX_ROOT in inode %llu is too small.",
			   (unsigned long long)inum);
		return -EIO;
	}

	return ntfs_index_header_inconsistent(vol, &ir->index,
					      value_length -
					      offsetof(struct index_root, index),
					      inum);
}

static struct index_root *ntfs_ir_lookup(struct ntfs_inode *ni, __le16 *name,
		u32 name_len, struct ntfs_attr_search_ctx **ctx)
{
	struct attr_record *a;
	struct index_root *ir = NULL;

	ntfs_debug("Entering\n");
	*ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!*ctx) {
		ntfs_error(ni->vol->sb, "%s, Failed to get search context", __func__);
		return NULL;
	}

	if (ntfs_attr_lookup(AT_INDEX_ROOT, name, name_len, CASE_SENSITIVE,
				0, NULL, 0, *ctx)) {
		ntfs_error(ni->vol->sb, "Failed to lookup $INDEX_ROOT");
		goto err_out;
	}

	a = (*ctx)->attr;
	if (a->non_resident) {
		ntfs_error(ni->vol->sb, "Non-resident $INDEX_ROOT detected");
		goto err_out;
	}

	ir = (struct index_root *)((char *)a + le16_to_cpu(a->data.resident.value_offset));
err_out:
	if (!ir) {
		ntfs_attr_put_search_ctx(*ctx);
		*ctx = NULL;
	}
	return ir;
}

static struct index_root *ntfs_ir_lookup2(struct ntfs_inode *ni, __le16 *name, u32 len)
{
	struct ntfs_attr_search_ctx *ctx;
	struct index_root *ir;

	ir = ntfs_ir_lookup(ni, name, len, &ctx);
	if (ir)
		ntfs_attr_put_search_ctx(ctx);
	return ir;
}

static int ntfs_ir_move_to_base(struct ntfs_index_context *icx)
{
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct index_root *ir;
	bool moved = false;
	int ret = 0;

	ir = ntfs_ir_lookup(icx->idx_ni, icx->name, icx->name_len, &ctx);
	if (!ir)
		return -ENOENT;

	if (ctx->ntfs_ino->mft_no != icx->idx_ni->mft_no) {
		ret = ntfs_attr_record_move_to(ctx, icx->idx_ni);
		if (!ret) {
			moved = true;
			ret = ntfs_attrlist_update(icx->idx_ni);
		}
	}

	ntfs_attr_put_search_ctx(ctx);
	if (!ret && moved)
		ret = ntfs_inode_free_empty_extents(icx->idx_ni);
	return ret;
}

/*
 * Find a key in the index block.
 */
static int ntfs_ie_lookup(const void *key, const u32 key_len,
		struct ntfs_index_context *icx, struct index_header *ih,
		s64 *vcn, struct index_entry **ie_out)
{
	struct index_entry *ie;
	u8 *index_end;
	int rc, item = 0;

	ntfs_debug("Entering\n");

	index_end = ntfs_ie_get_end(ih);

	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (ie = ntfs_ie_get_first(ih); ; ie = ntfs_ie_get_next(ie)) {
		/* Bounds checks. */
		if ((u8 *)ie + sizeof(struct index_entry_header) > index_end ||
				(u8 *)ie + le16_to_cpu(ie->length) > index_end) {
			ntfs_error(icx->idx_ni->vol->sb,
					"Index entry out of bounds in inode %llu.\n",
					(unsigned long long)icx->idx_ni->mft_no);
			return -ERANGE;
		}

		/*
		 * The last entry cannot contain a key.  It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ntfs_ie_end(ie))
			break;

		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate(icx->idx_ni->vol, icx->cr, key, key_len, &ie->key,
				le16_to_cpu(ie->key_length));
		if (rc == -EINVAL) {
			ntfs_error(icx->idx_ni->vol->sb,
				"Collation error. Perhaps a filename contains invalid characters?\n");
			return -ERANGE;
		}
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;

		if (!rc) {
			*ie_out = ie;
			icx->parent_pos[icx->pindex] = item;
			return 0;
		}

		item++;
	}
	/*
	 * We have finished with this index block without success. Check for the
	 * presence of a child node and if not present return with errno ENOENT,
	 * otherwise we will keep searching in another index block.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ntfs_debug("Index entry wasn't found.\n");
		*ie_out = ie;
		return -ENOENT;
	}

	/* Get the starting vcn of the index_block holding the child node. */
	*vcn = ntfs_ie_get_vcn(ie);
	if (*vcn < 0) {
		ntfs_error(icx->idx_ni->vol->sb, "Negative vcn in inode %llu\n",
				(unsigned long long)icx->idx_ni->mft_no);
		return -EINVAL;
	}

	ntfs_debug("Parent entry number %d\n", item);
	icx->parent_pos[icx->pindex] = item;

	return -EAGAIN;
}

struct ntfs_inode *ntfs_ia_open(struct ntfs_index_context *icx, struct ntfs_inode *ni)
{
	struct inode *ia_vi;

	ia_vi = ntfs_index_iget(VFS_I(ni), icx->name, icx->name_len);
	if (IS_ERR(ia_vi)) {
		ntfs_error(icx->idx_ni->vol->sb,
				"Failed to open index allocation of inode %llu",
				(unsigned long long)ni->mft_no);
		return NULL;
	}

	return NTFS_I(ia_vi);
}

static int ntfs_ib_read(struct ntfs_index_context *icx, s64 vcn, struct index_block *dst)
{
	s64 pos, ret;

	ntfs_debug("vcn: %lld\n", vcn);

	ret = ntfs_icx_ia_ensure(icx);
	if (ret)
		return ret;

	pos = ntfs_ib_vcn_to_pos(icx, vcn);

	ret = ntfs_inode_attr_pread(VFS_I(icx->ia_ni), pos, icx->block_size, (u8 *)dst);
	if (ret != icx->block_size) {
		if (ret == -1)
			ntfs_error(icx->idx_ni->vol->sb, "Failed to read index block");
		else
			ntfs_error(icx->idx_ni->vol->sb,
				"Failed to read full index block at %lld\n", pos);
		return -EIO;
	}

	post_read_mst_fixup((struct ntfs_record *)((u8 *)dst), icx->block_size);
	if (ntfs_index_block_inconsistent(icx->idx_ni->vol, dst,
					  icx->block_size, vcn, icx->cr,
					  icx->idx_ni->mft_no))
		return -EIO;
	return 0;
}

static int ntfs_icx_parent_inc(struct ntfs_index_context *icx)
{
	if (icx->pindex >= MAX_PARENT_VCN - 1) {
		ntfs_error(icx->idx_ni->vol->sb, "Index is over %d level deep", MAX_PARENT_VCN);
		return -EOPNOTSUPP;
	}
	icx->pindex++;
	return 0;
}

static int ntfs_icx_parent_dec(struct ntfs_index_context *icx)
{
	icx->pindex--;
	if (icx->pindex < 0) {
		ntfs_error(icx->idx_ni->vol->sb, "Corrupt index pointer (%d)", icx->pindex);
		return -EINVAL;
	}
	return 0;
}

/*
 * ntfs_index_lookup - find a key in an index and return its index entry
 * @key:	key for which to search in the index
 * @key_len:	length of @key in bytes
 * @icx:	context describing the index and the returned entry
 *
 * Before calling ntfs_index_lookup(), @icx must have been obtained from a
 * call to ntfs_index_ctx_get().
 *
 * Look for the @key in the index specified by the index lookup context @icx.
 * ntfs_index_lookup() walks the contents of the index looking for the @key.
 *
 * If the @key is found in the index, 0 is returned and @icx is setup to
 * describe the index entry containing the matching @key.  @icx->entry is the
 * index entry and @icx->data and @icx->data_len are the index entry data and
 * its length in bytes, respectively.
 *
 * If the @key is not found in the index, -ENOENT is returned and
 * @icx is setup to describe the index entry whose key collates immediately
 * after the search @key, i.e. this is the position in the index at which
 * an index entry with a key of @key would need to be inserted.
 *
 * If the index cannot be searched, a negative error code other than -ENOENT
 * is returned and @icx does not describe a valid index entry.
 *
 * When finished with the entry and its data, call ntfs_index_ctx_put() to free
 * the context and other associated resources.
 *
 * If the index entry was modified, call ntfs_index_entry_mark_dirty() before
 * the call to ntfs_index_ctx_put() to ensure that the changes are written
 * to disk.
 */
int ntfs_index_lookup(const void *key, const u32 key_len, struct ntfs_index_context *icx)
{
	s64 old_vcn, vcn;
	struct ntfs_inode *ni = icx->idx_ni;
	struct super_block *sb = ni->vol->sb;
	struct index_root *ir;
	struct index_entry *ie;
	struct index_block *ib = NULL;
	int err = 0;

	ntfs_debug("Entering\n");

	if (!key) {
		ntfs_error(sb, "key: %p  key_len: %d", key, key_len);
		return -EINVAL;
	}

	ir = ntfs_ir_lookup(ni, icx->name, icx->name_len, &icx->actx);
	if (!ir)
		return -EIO;

	icx->block_size = le32_to_cpu(ir->index_block_size);
	if (icx->block_size < NTFS_BLOCK_SIZE) {
		err = -EINVAL;
		ntfs_error(sb,
			"Index block size (%d) is smaller than the sector size (%d)",
			icx->block_size, NTFS_BLOCK_SIZE);
		goto err_out;
	}

	if (ni->vol->cluster_size <= icx->block_size)
		icx->vcn_size_bits = ni->vol->cluster_size_bits;
	else
		icx->vcn_size_bits = NTFS_BLOCK_SIZE_BITS;

	icx->cr = ir->collation_rule;
	if (!ntfs_is_collation_rule_supported(icx->cr)) {
		err = -EOPNOTSUPP;
		ntfs_error(sb, "Unknown collation rule 0x%x",
				(unsigned int)le32_to_cpu(icx->cr));
		goto err_out;
	}

	old_vcn = VCN_INDEX_ROOT_PARENT;
	err = ntfs_ie_lookup(key, key_len, icx, &ir->index, &vcn, &ie);
	if (err == -ERANGE || err == -EINVAL)
		goto err_out;

	icx->ir = ir;
	if (err != -EAGAIN) {
		icx->is_in_root = true;
		icx->parent_vcn[icx->pindex] = old_vcn;
		goto done;
	}

	/* Child node present, descend into it. */
	icx->ia_ni = ntfs_ia_open(icx, ni);
	if (!icx->ia_ni) {
		err = -EIO;
		goto err_out;
	}

	ib = kvzalloc(icx->block_size, GFP_NOFS);
	if (!ib) {
		err = -ENOMEM;
		goto err_out;
	}

descend_into_child_node:
	icx->parent_vcn[icx->pindex] = old_vcn;
	if (ntfs_icx_parent_inc(icx)) {
		err = -EIO;
		goto err_out;
	}
	old_vcn = vcn;

	ntfs_debug("Descend into node with s64 %lld.\n", vcn);

	if (ntfs_ib_read(icx, vcn, ib)) {
		err = -EIO;
		goto err_out;
	}
	err = ntfs_ie_lookup(key, key_len, icx, &ib->index, &vcn, &ie);
	if (err != -EAGAIN) {
		if (err == -EINVAL || err == -ERANGE)
			goto err_out;

		icx->is_in_root = false;
		icx->ib = ib;
		icx->parent_vcn[icx->pindex] = vcn;
		goto done;
	}

	if ((ib->index.flags & NODE_MASK) == LEAF_NODE) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Index entry with child node found in a leaf node in inode 0x%llx.\n",
			(unsigned long long)ni->mft_no);
		goto err_out;
	}

	goto descend_into_child_node;
err_out:
	if (icx->actx) {
		ntfs_attr_put_search_ctx(icx->actx);
		icx->actx = NULL;
	}
	kvfree(ib);
	if (!err)
		err = -EIO;
	return err;
done:
	icx->entry = ie;
	icx->data = (u8 *)ie + offsetof(struct index_entry, key);
	icx->data_len = le16_to_cpu(ie->key_length);
	ntfs_debug("Done.\n");
	return err;

}

static struct index_block *ntfs_ib_alloc(s64 ib_vcn, u32 ib_size,
		u8 node_type)
{
	struct index_block *ib;
	int ih_size = sizeof(struct index_header);

	ntfs_debug("Entering ib_vcn = %lld ib_size = %u\n", ib_vcn, ib_size);

	ib = kvzalloc(ib_size, GFP_NOFS);
	if (!ib)
		return NULL;

	ib->magic = magic_INDX;
	ib->usa_ofs = cpu_to_le16(sizeof(struct index_block));
	ib->usa_count = cpu_to_le16(ib_size / NTFS_BLOCK_SIZE + 1);
	/* Set USN to 1 */
	*(__le16 *)((char *)ib + le16_to_cpu(ib->usa_ofs)) = cpu_to_le16(1);
	ib->lsn = 0;
	ib->index_block_vcn = cpu_to_le64(ib_vcn);
	ib->index.entries_offset =
		cpu_to_le32(ntfs_ib_canonical_entries_offset(ib_size));
	ib->index.index_length = 0;
	ib->index.allocated_size = cpu_to_le32(ib_size -
			(sizeof(struct index_block) - ih_size));
	ib->index.flags = node_type;

	return ib;
}

int ntfs_index_block_initialize_log_credits(struct ntfs_volume *vol,
		u32 block_size)
{
	return ntfs_log_index_allocation_initialize_credits(vol, block_size);
}

int ntfs_index_allocation_extend_log_credits(struct ntfs_volume *vol,
		s64 old_allocated_size, s64 new_size)
{
	u64 old_clusters;
	u64 new_clusters;
	u64 cluster_count;
	int allocation_credits;
	int attribute_credits;
	int credits;

	if (!vol || old_allocated_size < 0 || new_size < 0)
		return -EINVAL;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	if (new_size <= old_allocated_size)
		return ntfs_attr_update_mapping_pairs_log_credits(vol,
				vol->mft_record_size, vol->mft_record_size, 0, 0);
	old_clusters = DIV_ROUND_UP_ULL(old_allocated_size, vol->cluster_size);
	new_clusters = DIV_ROUND_UP_ULL(new_size, vol->cluster_size);
	cluster_count = new_clusters - old_clusters;
	if (cluster_count > S64_MAX)
		return -EOVERFLOW;
	allocation_credits = ntfs_cluster_alloc_log_credits(cluster_count);
	if (allocation_credits < 0)
		return allocation_credits;
	/* Pessimistically allow one new extent per newly allocated cluster. */
	attribute_credits = ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size,
			cluster_count, 0);
	if (attribute_credits < 0)
		return attribute_credits;
	if (check_add_overflow(allocation_credits, attribute_credits,
			&credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_index_allocation_extend_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx, s64 new_size)
{
	struct runlist_element *allocated_rl;
	struct runlist_element *merged_rl;
	struct runlist_element *rl;
	struct ntfs_inode *base_ni;
	struct ntfs_inode *ni;
	struct ntfs_volume *vol;
	u64 old_clusters;
	u64 new_clusters;
	s64 lcn_hint = -1;
	s64 cluster_count;
	size_t new_rl_count;
	int err;

	if (!handle || !icx || !icx->ia_ni || new_size < 0 ||
	    icx->block_size < NTFS_BLOCK_SIZE ||
	    !is_power_of_2(icx->block_size) ||
	    !IS_ALIGNED(new_size, icx->block_size))
		return -EINVAL;
	ni = icx->ia_ni;
	vol = ni->vol;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni || !NInoNonResident(ni) ||
	    NInoCompressed(ni) || NInoSparse(ni) || NInoEncrypted(ni))
		return -EOPNOTSUPP;
	if (ni->allocated_size < 0 || ni->data_size < 0 ||
	    ni->initialized_size < 0 || ni->zeroed_size < 0 ||
	    ni->data_size != ni->initialized_size ||
	    ni->data_size > ni->allocated_size)
		return -EIO;
	if (new_size <= ni->initialized_size)
		return 0;
	err = ntfs_index_allocation_register_home_undo(handle, ni);
	if (err)
		return err;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err) {
		if (err == -EOPNOTSUPP)
			ntfs_error(vol->sb,
				   "Index allocation runlist mapping is unsupported for inode %llu.",
				  (unsigned long long)base_ni->mft_no);
		return err;
	}

	down_write(&ni->runlist.lock);
	if (new_size <= ni->allocated_size) {
		ni->data_size = new_size;
		ni->initialized_size = new_size;
		ni->zeroed_size = new_size;
		i_size_write(VFS_I(ni), new_size);
		err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
		goto out_unlock;
	}
	old_clusters = DIV_ROUND_UP_ULL(ni->allocated_size,
			vol->cluster_size);
	new_clusters = DIV_ROUND_UP_ULL(new_size, vol->cluster_size);
	if (new_clusters <= old_clusters) {
		err = -EOPNOTSUPP;
		goto out_unlock;
	}
	cluster_count = new_clusters - old_clusters;
	if (cluster_count <= 0) {
		err = -EOVERFLOW;
		goto out_unlock;
	}
	for (rl = ni->runlist.rl; rl && rl->length; rl++) {
		if (rl->lcn >= 0)
			lcn_hint = rl->lcn + rl->length;
	}
	allocated_rl = ntfs_cluster_alloc_transacted(handle, vol,
			old_clusters, cluster_count, lcn_hint, DATA_ZONE, true,
			false, false);
	if (IS_ERR(allocated_rl)) {
		err = PTR_ERR(allocated_rl);
		goto out_unlock;
	}
	merged_rl = ntfs_runlists_merge(&ni->runlist, allocated_rl, 0,
			&new_rl_count);
	if (IS_ERR(merged_rl)) {
		err = PTR_ERR(merged_rl);
		kvfree(allocated_rl);
		goto out_unlock;
	}
	ni->runlist.rl = merged_rl;
	ni->runlist.count = new_rl_count;
	ni->runlist.rl_hint = -1;
	ni->allocated_size = ntfs_cluster_to_bytes(vol, new_clusters);
	ni->data_size = new_size;
	ni->initialized_size = new_size;
	ni->zeroed_size = new_size;
	i_size_write(VFS_I(ni), new_size);
	VFS_I(base_ni)->i_blocks = ni->allocated_size >> 9;
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
out_unlock:
	up_write(&ni->runlist.lock);
	if (err == -EOPNOTSUPP)
		ntfs_error(vol->sb,
			   "Index allocation mapping update is unsupported for inode %llu.",
				  (unsigned long long)base_ni->mft_no);
	return err;
}

int ntfs_index_block_initialize_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx, struct index_block *ib)
{
	s64 byte_pos;
	s64 vcn;
	u64 operation_lsn;
	int err;

	if (!handle || !icx || !icx->ia_ni || !ib ||
	    icx->block_size < NTFS_BLOCK_SIZE || icx->block_size > U16_MAX)
		return -EINVAL;
	vcn = le64_to_cpu(ib->index_block_vcn);
	if (vcn < 0 || check_shl_overflow(vcn, icx->vcn_size_bits,
			&byte_pos))
		return -EOVERFLOW;
	/* Stream growth and its mapping-pairs update are a later stage. */
	if (byte_pos > icx->ia_ni->initialized_size ||
	    icx->block_size > icx->ia_ni->initialized_size - byte_pos)
		return -EOPNOTSUPP;

	err = ntfs_log_index_allocation_initialize(handle,
			VFS_I(icx->ia_ni), icx->block_size, byte_pos, ib,
			&operation_lsn);
	if (err)
		return err;
	ib->lsn = cpu_to_le64(operation_lsn);
	return ntfs_ib_write(icx, ib);
}

static int ntfs_index_block_update_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		const struct index_block *old_ib, struct index_block *new_ib)
{
	s64 byte_pos;
	s64 old_vcn;
	s64 new_vcn;
	u64 operation_lsn;
	int err;

	if (!handle || !icx || !icx->ia_ni || !old_ib || !new_ib ||
	    icx->block_size < NTFS_BLOCK_SIZE || icx->block_size > U16_MAX)
		return -EINVAL;
	old_vcn = le64_to_cpu(old_ib->index_block_vcn);
	new_vcn = le64_to_cpu(new_ib->index_block_vcn);
	if (old_vcn < 0 || new_vcn != old_vcn ||
	    check_shl_overflow(old_vcn, icx->vcn_size_bits, &byte_pos))
		return -EINVAL;
	err = ntfs_log_index_allocation_update(handle, VFS_I(icx->ia_ni),
			icx->block_size, byte_pos, old_ib, new_ib,
			&operation_lsn);
	if (err)
		return err;
	err = ntfs_index_block_register_buffer_home_undo(handle, icx, old_ib);
	if (err)
		return err;
	new_ib->lsn = cpu_to_le64(operation_lsn);
	return ntfs_ib_write(icx, new_ib);
}

int ntfs_index_block_allocation_log_credits(struct ntfs_volume *vol,
		u32 block_size)
{
	int bitmap_credits;
	int initialize_credits;
	int credits;

	bitmap_credits = ntfs_index_bitmap_log_credits(vol);
	if (bitmap_credits < 0)
		return bitmap_credits;
	initialize_credits = ntfs_index_block_initialize_log_credits(vol,
			block_size);
	if (initialize_credits < 0)
		return initialize_credits;
	if (check_add_overflow(bitmap_credits, initialize_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_index_root_reparent_log_credits(struct ntfs_volume *vol,
		u32 block_size)
{
	int attrlist_credits;
	int credits;
	int operation_credits;

	if (!vol)
		return -EINVAL;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	/* Resize the resident $INDEX_ROOT value. */
	credits = ntfs_log_mft_attribute_credits(vol, vol->mft_record_size,
			vol->mft_record_size);
	if (credits < 0)
		return credits;
	/* Create resident $BITMAP and empty nonresident $INDEX_ALLOCATION. */
	operation_credits = ntfs_log_mft_attribute_credits(vol, 0,
			vol->mft_record_size);
	if (operation_credits < 0)
		return operation_credits;
	if (check_add_overflow(credits, operation_credits, &credits) ||
	    check_add_overflow(credits, operation_credits, &credits))
		return -EOVERFLOW;
	/* The first resident attribute-list may need repeated extent moves. */
	attrlist_credits = ntfs_attrlist_extent_log_credits(vol);
	if (attrlist_credits < 0)
		return attrlist_credits;
	if (check_add_overflow(credits, attrlist_credits, &credits))
		return -EOVERFLOW;
	operation_credits = ntfs_index_allocation_extend_log_credits(vol, 0,
			block_size);
	if (operation_credits < 0)
		return operation_credits;
	if (check_add_overflow(credits, operation_credits, &credits))
		return -EOVERFLOW;
	operation_credits = ntfs_index_block_allocation_log_credits(vol,
			block_size);
	if (operation_credits < 0)
		return operation_credits;
	if (check_add_overflow(credits, operation_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_index_leaf_split_log_credits(struct ntfs_volume *vol,
		u32 block_size)
{
	int per_level;
	int credits;
	int operation_credits;

	if (!vol)
		return -EINVAL;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	/* Grow and rewrite the resident root parent. */
	credits = ntfs_log_mft_attribute_credits(vol, vol->mft_record_size,
			vol->mft_record_size);
	if (credits < 0)
		return credits;
	per_level = ntfs_index_bitmap_log_credits(vol);
	if (per_level < 0)
		return per_level;
	operation_credits = ntfs_index_allocation_extend_log_credits(vol, 0,
			block_size);
	if (operation_credits < 0)
		return operation_credits;
	if (check_add_overflow(per_level, operation_credits, &per_level))
		return -EOVERFLOW;
	operation_credits = ntfs_index_block_initialize_log_credits(vol,
			block_size);
	if (operation_credits < 0)
		return operation_credits;
	if (check_add_overflow(per_level, operation_credits, &per_level))
		return -EOVERFLOW;
	operation_credits = ntfs_log_index_allocation_update_credits(vol,
			block_size);
	if (operation_credits < 0)
		return operation_credits;
	if (check_add_overflow(per_level, operation_credits, &per_level))
		return -EOVERFLOW;
	/* Every allocation level may split before the median reaches the root. */
	if (check_mul_overflow(per_level, MAX_PARENT_VCN, &per_level) ||
	    check_add_overflow(credits, per_level, &credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_index_leaf_remove_log_credits(struct ntfs_volume *vol,
		u32 block_size)
{
	int bitmap_credits;
	int block_credits;
	int credits;
	int delete_credits;
	int free_credits;
	int recursive_credits;
	int root_credits;
	int terminal_credits;
	int truncate_credits;

	credits = ntfs_index_leaf_split_log_credits(vol, block_size);
	if (credits < 0)
		return credits;
	bitmap_credits = ntfs_index_bitmap_log_credits(vol);
	if (bitmap_credits < 0)
		return bitmap_credits;
	if (check_mul_overflow(bitmap_credits, MAX_RETIRED_INDEX_VCNS,
			&bitmap_credits) ||
	    check_add_overflow(credits, bitmap_credits, &credits))
		return -EOVERFLOW;
	block_credits = ntfs_log_index_allocation_update_credits(vol,
			block_size);
	if (block_credits < 0)
		return block_credits;
	/* Internal balancing may add a second full-block update per level. */
	recursive_credits = block_credits;
	if (check_mul_overflow(recursive_credits, MAX_PARENT_VCN,
			&recursive_credits) ||
	    check_add_overflow(credits, recursive_credits, &credits))
		return -EOVERFLOW;
	root_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, vol->mft_record_size);
	if (root_credits < 0)
		return root_credits;
	terminal_credits = max(block_credits, root_credits);
	if (check_add_overflow(credits, terminal_credits, &credits))
		return -EOVERFLOW;
	truncate_credits = ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size, 0,
			MAX_RETIRED_INDEX_VCNS);
	if (truncate_credits < 0)
		return truncate_credits;
	if (check_add_overflow(credits, truncate_credits, &credits))
		return -EOVERFLOW;
	free_credits = ntfs_cluster_free_log_credits(
			MAX_RETIRED_INDEX_VCNS);
	if (free_credits < 0)
		return free_credits;
	if (check_add_overflow(credits, free_credits, &credits))
		return -EOVERFLOW;
	delete_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, 0);
	if (delete_credits < 0)
		return delete_credits;
	/* Empty $INDEX_ALLOCATION and $BITMAP may both be removed. */
	if (check_mul_overflow(delete_credits, 2, &delete_credits) ||
	    check_add_overflow(credits, delete_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_index_node_remove_log_credits(struct ntfs_volume *vol,
		u32 block_size)
{
	int credits;
	int split_credits;

	credits = ntfs_index_leaf_remove_log_credits(vol, block_size);
	if (credits < 0)
		return credits;
	/* The replacement block and the retirement reinsertion may both split. */
	split_credits = ntfs_index_leaf_split_log_credits(vol, block_size);
	if (split_credits < 0)
		return split_credits;
	if (check_add_overflow(credits, split_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_index_attrlist_log_credits(struct ntfs_volume *vol,
		unsigned int entries)
{
	unsigned int credits;
	int extent_credits;
	int list_credits;
	int remove_credits;

	if (!vol || !entries)
		return -EINVAL;
	extent_credits = ntfs_attrlist_extent_log_credits(vol);
	if (extent_credits < 0)
		return extent_credits;
	list_credits = ntfs_attrlist_nonresident_log_credits(vol);
	if (list_credits < 0)
		return list_credits;
	if (check_mul_overflow(max(extent_credits, list_credits), 2,
			&list_credits))
		return -EOVERFLOW;
	remove_credits = ntfs_attr_rm_empty_log_credits(vol, true, true);
	if (remove_credits < 0)
		return remove_credits;
	if (check_mul_overflow(remove_credits, 2, &remove_credits))
		return -EOVERFLOW;
	if (check_mul_overflow((unsigned int)max(list_credits,
			remove_credits), entries, &credits) || credits > INT_MAX)
		return -EOVERFLOW;
	return credits;
}

int ntfs_index_block_allocate_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx, u8 node_type,
		struct index_block **block_out)
{
	struct index_block *ib;
	s64 vcn;
	int err;

	if (!handle || !icx || !block_out)
		return -EINVAL;
	*block_out = NULL;
	vcn = ntfs_index_bitmap_get_free_transacted(handle, icx);
	if (vcn < 0)
		return vcn;
	ib = ntfs_ib_alloc(vcn, icx->block_size, node_type);
	if (!ib)
		return -ENOMEM;
	err = ntfs_index_block_initialize_transacted(handle, icx, ib);
	if (err) {
		kvfree(ib);
		return err;
	}
	/* ntfs_ib_write() leaves its caller-owned buffer MST-protected. */
	post_write_mst_fixup((struct ntfs_record *)ib);
	*block_out = ib;
	return 0;
}

/*
 *  Find the median by going through all the entries
 */
static struct index_entry *ntfs_ie_get_median(struct index_header *ih)
{
	struct index_entry *ie, *ie_start;
	u8 *ie_end;
	int i = 0, median;

	ntfs_debug("Entering\n");

	ie = ie_start = ntfs_ie_get_first(ih);
	ie_end = (u8 *)ntfs_ie_get_end(ih);

	while ((u8 *)ie < ie_end && !ntfs_ie_end(ie)) {
		ie = ntfs_ie_get_next(ie);
		i++;
	}
	/*
	 * NOTE: this could be also the entry at the half of the index block.
	 */
	median = i / 2 - 1;

	ntfs_debug("Entries: %d  median: %d\n", i, median);

	for (i = 0, ie = ie_start; i <= median; i++)
		ie = ntfs_ie_get_next(ie);

	return ie;
}

static u64 ntfs_ibm_vcn_to_pos(struct ntfs_index_context *icx, s64 vcn)
{
	u64 pos = ntfs_ib_vcn_to_pos(icx, vcn);

	do_div(pos, icx->block_size);
	return pos;
}

static s64 ntfs_ibm_pos_to_vcn(struct ntfs_index_context *icx, s64 pos)
{
	return ntfs_ib_pos_to_vcn(icx, pos * icx->block_size);
}

static struct address_space *ntfs_index_bdev_mapping(struct super_block *sb)
{
	return sb->s_bdev->bd_mapping;
}

static void ntfs_index_bitmap_invalidate(struct inode *vi, s64 byte_pos)
{
	loff_t start = byte_pos & PAGE_MASK;

	truncate_inode_pages_range(vi->i_mapping, start,
			start + PAGE_SIZE - 1);
}

static int ntfs_index_bitmap_prepare_raw_write(struct inode *vi,
		s64 byte_pos, u64 dev_off, u32 bytes)
{
	struct address_space *mapping;
	u64 dev_end;
	pgoff_t first;
	pgoff_t last;
	int err;

	if (!vi || byte_pos < 0 || !bytes ||
	    check_add_overflow(dev_off, (u64)bytes - 1, &dev_end) ||
	    dev_end > LLONG_MAX)
		return -EINVAL;
	/* Keep any older bitmap changes held by its attribute page cache. */
	err = filemap_write_and_wait_range(vi->i_mapping, byte_pos,
			byte_pos + bytes - 1);
	if (err)
		return err;
	/* Refresh the raw-device page so a sub-page write cannot copy stale data. */
	mapping = ntfs_index_bdev_mapping(vi->i_sb);
	err = filemap_write_and_wait_range(mapping, dev_off, dev_end);
	if (err)
		return err;
	first = dev_off >> PAGE_SHIFT;
	last = dev_end >> PAGE_SHIFT;
	return invalidate_inode_pages2_range(mapping, first, last);
}

static int ntfs_index_bdev_write_ordered(struct inode *vi, const u8 *buffer,
		u64 dev_off, u32 bytes, bool wait_log)
{
	struct ntfs_volume *vol;
	struct address_space *mapping;
	u64 dev_end;
	u64 started;
	int err;

	if (!vi || !buffer || !bytes ||
	    check_add_overflow(dev_off, (u64)bytes - 1, &dev_end) ||
	    dev_end > LLONG_MAX)
		return -EINVAL;
	vol = NTFS_I(vi)->vol;
	if (!vol)
		return -EINVAL;
	if (wait_log) {
		err = ntfs_log_wait_inode(vi);
		if (err)
			return err;
	}
	mapping = ntfs_index_bdev_mapping(vol->sb);
	err = ntfs_bdev_write(vol->sb, (u8 *)buffer, dev_off, bytes);
	if (err)
		return err;
	err = filemap_write_and_wait_range(mapping, dev_off, dev_end);
	if (err)
		return err;
	started = ktime_get_ns();
	err = blkdev_issue_flush(vol->sb->s_bdev);
	ntfs_log_account_metadata_home_flush(ktime_get_ns() - started);
	return err;
}

static int ntfs_index_bitmap_resolve_dev_off(struct ntfs_inode *ni,
		s64 byte_pos, u32 bytes, u64 *dev_off)
{
	struct runlist_element *rl;
	u64 cluster_off;
	u64 lcn;
	s64 vcn;
	int err;

	if (!ni || byte_pos < 0 || !bytes || !dev_off ||
	    byte_pos > ni->allocated_size ||
	    bytes > ni->allocated_size - byte_pos)
		return -EINVAL;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	vcn = byte_pos >> ni->vol->cluster_size_bits;
	cluster_off = byte_pos & ni->vol->cluster_size_mask;
	if (bytes > ni->vol->cluster_size - cluster_off)
		return -EOPNOTSUPP;

	down_write(&ni->runlist.lock);
	rl = ntfs_attr_find_vcn_nolock(ni, vcn, NULL);
	if (IS_ERR(rl)) {
		err = PTR_ERR(rl);
		goto out;
	}
	if (rl->lcn < 0 || vcn < rl->vcn || vcn >= rl->vcn + rl->length ||
	    check_add_overflow((u64)rl->lcn, (u64)(vcn - rl->vcn), &lcn) ||
	    check_shl_overflow(lcn, ni->vol->cluster_size_bits, dev_off) ||
	    check_add_overflow(*dev_off, cluster_off, dev_off)) {
		err = -EIO;
		goto out;
	}
	err = 0;
out:
	up_write(&ni->runlist.lock);
	return err;
}

static int ntfs_index_bitmap_byte_home_restore(void *data)
{
	struct ntfs_index_bitmap_byte_home_undo *undo = data;
	int err;

	err = ntfs_index_bitmap_prepare_raw_write(undo->vi, undo->byte_pos,
			undo->dev_off, sizeof(undo->old_byte));
	if (err)
		return err;
	err = ntfs_index_bdev_write_ordered(undo->vi, &undo->old_byte,
			undo->dev_off, sizeof(undo->old_byte), false);
	if (!err)
		ntfs_index_bitmap_invalidate(undo->vi, undo->byte_pos);
	return err;
}

static void ntfs_index_bitmap_byte_home_release(void *data)
{
	struct ntfs_index_bitmap_byte_home_undo *undo = data;

	iput(undo->vi);
	kfree(undo);
}

static int ntfs_index_bitmap_byte_register_home_undo(
		struct ntfs_log_handle *handle, struct inode *vi, s64 byte_pos,
		u64 dev_off, u8 old_byte)
{
	struct ntfs_index_bitmap_byte_home_undo *undo;
	int err;

	if (!handle || !vi || byte_pos < 0)
		return -EINVAL;
	undo = kmalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	ihold(vi);
	undo->vi = vi;
	undo->dev_off = dev_off;
	undo->byte_pos = byte_pos;
	undo->old_byte = old_byte;
	err = ntfs_log_register_home_undo(handle,
			ntfs_index_bitmap_byte_home_restore,
			ntfs_index_bitmap_byte_home_release, undo);
	if (err)
		ntfs_index_bitmap_byte_home_release(undo);
	return err;
}

/*
 * Write newly allocated attribute storage before publishing its mapping pairs.
 * A device-cache flush after waiting for the block-device page cache provides
 * the ordered-data boundary required by the following MFT log operations.
 */
static int ntfs_index_runlist_write_ordered(struct ntfs_volume *vol,
		const struct runlist_element *rl, const u8 *buffer, u64 bytes)
{
	struct address_space *mapping;
	u64 done = 0;
	u64 started;
	int err;

	if (!vol || !rl || !buffer || !bytes ||
	    !IS_ALIGNED(bytes, vol->cluster_size))
		return -EINVAL;
	mapping = ntfs_index_bdev_mapping(vol->sb);
	for (; rl->length; rl++) {
		u64 dev_off;
		u64 dev_end;
		u64 run_bytes;

		if (rl->lcn < 0 || rl->length <= 0 ||
		    check_shl_overflow((u64)rl->length,
			    vol->cluster_size_bits, &run_bytes) ||
		    run_bytes > bytes - done ||
		    check_shl_overflow((u64)rl->lcn,
			    vol->cluster_size_bits, &dev_off) ||
		    check_add_overflow(dev_off, run_bytes - 1, &dev_end) ||
		    dev_end > LLONG_MAX || run_bytes > SIZE_MAX)
			return -EIO;
		err = ntfs_bdev_write(vol->sb, (u8 *)buffer + done,
				dev_off, run_bytes);
		if (err)
			return err;
		err = filemap_write_and_wait_range(mapping, dev_off, dev_end);
		if (err)
			return err;
		done += run_bytes;
	}
	if (done != bytes)
		return -EIO;
	started = ktime_get_ns();
	err = blkdev_issue_flush(vol->sb->s_bdev);
	ntfs_log_account_metadata_home_flush(ktime_get_ns() - started);
	return err;
}

int ntfs_index_bitmap_log_credits(struct ntfs_volume *vol)
{
	int allocation_credits;
	int bitmap_credits;
	int conversion_credits;
	int create_credits;
	int delete_credits;
	int mapping_credits;
	int nonresident_credits;
	int physical_credits;
	int resident_credits;
	int size_credits;
	u64 clusters;

	if (!vol)
		return -EINVAL;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	/* A set may grow the resident bitmap and log its complete old/new value. */
	resident_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size,
			vol->mft_record_size);
	if (resident_credits < 0)
		return resident_credits;
	/*
	 * If the MFT record cannot hold that growth, the old resident bitmap is
	 * replaced by a nonresident attribute after allocating enough clusters
	 * for the largest resident value that can reach this path.
	 */
	clusters = DIV_ROUND_UP_ULL(vol->mft_record_size, vol->cluster_size);
	if (!clusters || clusters > S64_MAX)
		return -EOVERFLOW;
	allocation_credits = ntfs_cluster_alloc_log_credits(clusters);
	if (allocation_credits < 0)
		return allocation_credits;
	delete_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, 0);
	if (delete_credits < 0)
		return delete_credits;
	create_credits = ntfs_log_mft_attribute_credits(vol, 0,
			vol->mft_record_size);
	if (create_credits < 0)
		return create_credits;
	if (check_add_overflow(allocation_credits, delete_credits,
			&conversion_credits) ||
	    check_add_overflow(conversion_credits, create_credits,
			&conversion_credits))
		return -EOVERFLOW;
	bitmap_credits = ntfs_log_bitmap_update_credits(0, 1);
	if (bitmap_credits < 0)
		return bitmap_credits;
	nonresident_credits = bitmap_credits;
	size_credits = ntfs_log_mft_attribute_sizes_credits(vol, false);
	if (size_credits < 0)
		return size_credits;
	if (check_add_overflow(nonresident_credits, size_credits,
			&nonresident_credits))
		return -EOVERFLOW;
	allocation_credits = ntfs_cluster_alloc_log_credits(1);
	if (allocation_credits < 0)
		return allocation_credits;
	mapping_credits = ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size, 1, 0);
	if (mapping_credits < 0)
		return mapping_credits;
	if (check_add_overflow(allocation_credits, bitmap_credits,
			&physical_credits) ||
	    check_add_overflow(physical_credits, mapping_credits,
			&physical_credits))
		return -EOVERFLOW;
	return max(max3(resident_credits, conversion_credits,
			nonresident_credits), physical_credits);
}

static int ntfs_ibm_add(struct ntfs_index_context *icx)
{
	u8 bmp[8];
	int ret;

	ntfs_debug("Entering\n");

	if (ntfs_attr_exist(icx->idx_ni, AT_BITMAP, icx->name, icx->name_len))
		return 0;
	/*
	 * AT_BITMAP must be at least 8 bytes.
	 */
	memset(bmp, 0, sizeof(bmp));
	ret = ntfs_attr_add(icx->idx_ni, AT_BITMAP, icx->name, icx->name_len,
			    bmp, sizeof(bmp));
	if (ret) {
		if (ret != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb, "Failed to add AT_BITMAP");
		return ret;
	}

	return 0;
}

static int ntfs_ibm_make_nonresident_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		struct ntfs_attr_search_ctx *actx, u32 bpos, u8 mask,
		u32 new_value_len)
{
	struct ntfs_inode *base_ni = icx->idx_ni;
	struct ntfs_volume *vol = base_ni->vol;
	struct mft_record *mrec = actx->mrec;
	struct attr_record *attr = actx->attr;
	struct attr_record *new_attr = NULL;
	struct attr_record *old_attr = NULL;
	struct runlist_element *allocated_rl = NULL;
	struct runlist_element *cursor;
	struct ntfs_inode *bmp_ni;
	struct inode *bmp_vi = NULL;
	u8 *storage = NULL;
	u64 allocated_size;
	u64 operation_lsn;
	u64 cluster_count;
	u32 attr_len;
	u32 mrec_allocated;
	u32 mrec_used;
	u32 name_bytes;
	u32 name_ofs;
	u32 mp_ofs;
	u32 new_attr_len;
	u32 value_len;
	u16 name_old_ofs;
	u16 value_off;
	ptrdiff_t record_off;
	size_t runlist_count;
	unsigned long flags;
	int mp_size;
	int err;

	if (!handle || !icx || !actx || !mrec || !attr ||
	    attr->non_resident || attr->type != AT_BITMAP ||
	    !new_value_len || bpos >= new_value_len)
		return -EINVAL;
	record_off = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	name_old_ofs = le16_to_cpu(attr->name_offset);
	name_bytes = attr->name_length * sizeof(__le16);
	mrec_used = le32_to_cpu(mrec->bytes_in_use);
	mrec_allocated = le32_to_cpu(mrec->bytes_allocated);
	if (record_off < 0 || record_off > U16_MAX ||
	    !IS_ALIGNED(record_off, 8) || attr_len > U16_MAX ||
	    value_off > attr_len || value_len > attr_len - value_off ||
	    new_value_len <= value_len || new_value_len > U16_MAX ||
	    new_value_len > vol->mft_record_size ||
	    name_old_ofs > attr_len || name_bytes > attr_len - name_old_ofs ||
	    mrec_used > mrec_allocated || record_off > mrec_used ||
	    attr_len > mrec_used - record_off ||
	    attr->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_SPARSE |
		    ATTR_IS_ENCRYPTED))
		return -EIO;

	cluster_count = DIV_ROUND_UP_ULL(new_value_len, vol->cluster_size);
	if (!cluster_count || cluster_count > S64_MAX ||
	    check_shl_overflow(cluster_count, vol->cluster_size_bits,
		    &allocated_size) || allocated_size > SIZE_MAX)
		return -EOVERFLOW;
	allocated_rl = ntfs_cluster_alloc_transacted(handle, vol, 0,
			cluster_count, -1, DATA_ZONE, true, false, false);
	if (IS_ERR(allocated_rl)) {
		err = PTR_ERR(allocated_rl);
		allocated_rl = NULL;
		return err;
	}

	mp_size = ntfs_get_size_for_mapping_pairs(vol, allocated_rl, 0, -1,
			-1);
	if (mp_size < 0) {
		err = mp_size;
		goto out;
	}
	name_ofs = ALIGN(offsetof(struct attr_record,
			data.non_resident.compressed_size), 8);
	if (check_add_overflow(name_ofs, name_bytes, &mp_ofs)) {
		err = -EOVERFLOW;
		goto out;
	}
	mp_ofs = ALIGN(mp_ofs, 8);
	if (check_add_overflow(mp_ofs, (u32)mp_size, &new_attr_len)) {
		err = -EOVERFLOW;
		goto out;
	}
	new_attr_len = ALIGN(new_attr_len, 8);
	if (new_attr_len > U16_MAX || new_attr_len > mrec_allocated ||
	    new_attr_len > mrec_allocated - (mrec_used - attr_len)) {
		err = -ENOSPC;
		goto out;
	}

	old_attr = ntfs_index_kvmemdup(attr, attr_len, GFP_NOFS);
	new_attr = kvzalloc(new_attr_len, GFP_NOFS);
	storage = kvzalloc(allocated_size, GFP_NOFS);
	if (!old_attr || !new_attr || !storage) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(storage, (u8 *)attr + value_off, value_len);
	storage[bpos] |= mask;
	new_attr->type = attr->type;
	new_attr->length = cpu_to_le32(new_attr_len);
	new_attr->non_resident = 1;
	new_attr->name_length = attr->name_length;
	new_attr->name_offset = cpu_to_le16(name_ofs);
	new_attr->flags = attr->flags;
	new_attr->instance = attr->instance;
	new_attr->data.non_resident.lowest_vcn = 0;
	new_attr->data.non_resident.highest_vcn =
			cpu_to_le64(cluster_count - 1);
	new_attr->data.non_resident.mapping_pairs_offset = cpu_to_le16(mp_ofs);
	new_attr->data.non_resident.compression_unit = 0;
	new_attr->data.non_resident.allocated_size =
			cpu_to_le64(allocated_size);
	new_attr->data.non_resident.data_size = cpu_to_le64(new_value_len);
	new_attr->data.non_resident.initialized_size =
			cpu_to_le64(new_value_len);
	if (name_bytes)
		memcpy((u8 *)new_attr + name_ofs,
				(u8 *)attr + name_old_ofs, name_bytes);
	err = ntfs_mapping_pairs_build(vol, (s8 *)new_attr + mp_ofs,
			new_attr_len - mp_ofs, allocated_rl, 0, -1,
			NULL, NULL, NULL);
	if (err)
		goto out;

	/* The newly allocated contents must be durable before the new mapping. */
	err = ntfs_index_runlist_write_ordered(vol, allocated_rl, storage,
			allocated_size);
	if (err)
		goto out;

	bmp_vi = ntfs_attr_iget(VFS_I(base_ni), AT_BITMAP, icx->name,
			icx->name_len);
	if (IS_ERR(bmp_vi)) {
		err = PTR_ERR(bmp_vi);
		bmp_vi = NULL;
		goto out;
	}
	bmp_ni = NTFS_I(bmp_vi);
	if (NInoNonResident(bmp_ni) || NInoCompressed(bmp_ni) ||
	    NInoSparse(bmp_ni) || NInoEncrypted(bmp_ni) ||
	    bmp_ni->data_size != value_len ||
	    bmp_ni->initialized_size != value_len) {
		err = -EIO;
		goto out;
	}
	err = ntfs_index_allocation_register_home_undo(handle, bmp_ni);
	if (err)
		goto out;
	err = ntfs_index_inode_state_register_home_undo(handle, bmp_ni);
	if (err)
		goto out;
	err = ntfs_attr_mft_register_home_undo(handle, actx->ntfs_ino, mrec);
	if (err)
		goto out;

	err = ntfs_log_mft_attribute_delete(handle, actx->ntfs_ino->mft_no,
			record_off, old_attr, attr_len, NULL);
	if (err)
		goto out;
	err = ntfs_log_mft_attribute_create(handle, actx->ntfs_ino->mft_no,
			record_off, new_attr, new_attr_len, &operation_lsn);
	if (err)
		goto out;
	err = ntfs_attr_record_resize(mrec, attr, new_attr_len);
	if (WARN_ON_ONCE(err)) {
		err = -EIO;
		goto out;
	}
	memcpy(attr, new_attr, new_attr_len);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(actx->ntfs_ino);

	/* No operation below this point can fail. */
	down_write(&bmp_ni->runlist.lock);
	kvfree(bmp_ni->runlist.rl);
	bmp_ni->runlist.rl = allocated_rl;
	allocated_rl = NULL;
	for (cursor = bmp_ni->runlist.rl, runlist_count = 1;
	     cursor->length; cursor++)
		runlist_count++;
	bmp_ni->runlist.count = runlist_count;
	bmp_ni->runlist.rl_hint = -1;
	write_lock_irqsave(&bmp_ni->size_lock, flags);
	bmp_ni->allocated_size = allocated_size;
	bmp_ni->data_size = new_value_len;
	bmp_ni->initialized_size = new_value_len;
	bmp_ni->zeroed_size = new_value_len;
	i_size_write(bmp_vi, new_value_len);
	bmp_vi->i_blocks = allocated_size >> 9;
	write_unlock_irqrestore(&bmp_ni->size_lock, flags);
	truncate_inode_pages(bmp_vi->i_mapping, 0);
	NInoSetNonResident(bmp_ni);
	NInoSetFullyMapped(bmp_ni);
	up_write(&bmp_ni->runlist.lock);
	err = 0;
out:
	if (bmp_vi)
		iput(bmp_vi);
	if (allocated_rl)
		kvfree(allocated_rl);
	kvfree(storage);
	kvfree(new_attr);
	kvfree(old_attr);
	return err;
}

static int ntfs_ibm_grow_nonresident_transacted(
		struct ntfs_log_handle *handle, struct inode *bmp_vi,
		u64 bit_pos, u32 bpos, u8 mask, u64 new_size)
{
	struct ntfs_inode *bmp_ni = NTFS_I(bmp_vi);
	struct ntfs_volume *vol = bmp_ni->vol;
	struct runlist_element *allocated_rl = NULL;
	struct runlist_element *merged_rl;
	struct runlist_element *rl;
	u8 *storage = NULL;
	u64 allocated_size;
	u64 dev_off;
	u64 new_clusters;
	u64 old_clusters;
	s64 lcn_hint = -1;
	size_t new_rl_count;
	int err;

	if (!handle || !bmp_vi || !NInoNonResident(bmp_ni) ||
	    NInoCompressed(bmp_ni) || NInoSparse(bmp_ni) ||
	    NInoEncrypted(bmp_ni) || new_size <= bmp_ni->allocated_size ||
	    bmp_ni->data_size != bmp_ni->initialized_size ||
	    bmp_ni->data_size != bmp_ni->allocated_size ||
	    bpos < bmp_ni->data_size || bpos >= new_size)
		return -EINVAL;
	allocated_size = bmp_ni->allocated_size;
	old_clusters = allocated_size >> vol->cluster_size_bits;
	new_clusters = DIV_ROUND_UP_ULL(new_size, vol->cluster_size);
	/* An index bitmap grows by one aligned 8-byte unit at a time. */
	if (!old_clusters || new_clusters != old_clusters + 1 ||
	    bpos - allocated_size >= vol->cluster_size)
		return -EOPNOTSUPP;
	storage = kvzalloc(vol->cluster_size, GFP_NOFS);
	if (!storage)
		return -ENOMEM;
	storage[bpos - allocated_size] |= mask;

	err = ntfs_attr_map_whole_runlist(bmp_ni);
	if (err)
		goto out;
	down_read(&bmp_ni->runlist.lock);
	for (rl = bmp_ni->runlist.rl; rl && rl->length; rl++) {
		if (rl->lcn < 0 || check_add_overflow(rl->lcn, rl->length,
				&lcn_hint)) {
			err = -EIO;
			break;
		}
	}
	up_read(&bmp_ni->runlist.lock);
	if (err || lcn_hint < 0)
		goto out;

	allocated_rl = ntfs_cluster_alloc_transacted(handle, vol,
			old_clusters, 1, lcn_hint, DATA_ZONE, true, false, false);
	if (IS_ERR(allocated_rl)) {
		err = PTR_ERR(allocated_rl);
		allocated_rl = NULL;
		goto out;
	}
	if (allocated_rl->vcn != old_clusters || allocated_rl->lcn < 0 ||
	    allocated_rl->length != 1 || allocated_rl[1].length ||
	    allocated_rl[1].vcn != old_clusters + 1 ||
	    allocated_rl[1].lcn != LCN_ENOENT ||
	    check_shl_overflow((u64)allocated_rl->lcn,
			vol->cluster_size_bits, &dev_off)) {
		err = -EIO;
		goto out;
	}
	err = ntfs_index_bitmap_prepare_raw_write(bmp_vi, allocated_size,
			dev_off, vol->cluster_size);
	if (err)
		goto out;
	err = ntfs_index_runlist_write_ordered(vol, allocated_rl, storage,
			vol->cluster_size);
	if (err)
		goto out;
	err = ntfs_index_allocation_register_home_undo(handle, bmp_ni);
	if (err)
		goto out;

	down_write(&bmp_ni->runlist.lock);
	merged_rl = ntfs_runlists_merge(&bmp_ni->runlist, allocated_rl, 0,
			&new_rl_count);
	if (IS_ERR(merged_rl)) {
		err = PTR_ERR(merged_rl);
		up_write(&bmp_ni->runlist.lock);
		goto out;
	}
	allocated_rl = NULL;
	bmp_ni->runlist.rl = merged_rl;
	bmp_ni->runlist.count = new_rl_count;
	bmp_ni->runlist.rl_hint = -1;
	bmp_ni->allocated_size = ntfs_cluster_to_bytes(vol, new_clusters);
	bmp_ni->data_size = new_size;
	bmp_ni->initialized_size = new_size;
	bmp_ni->zeroed_size = new_size;
	i_size_write(bmp_vi, new_size);
	bmp_vi->i_blocks = bmp_ni->allocated_size >> 9;
	up_write(&bmp_ni->runlist.lock);
	ntfs_index_bitmap_invalidate(bmp_vi, allocated_size);

	err = ntfs_log_bitmap_update(handle, bmp_vi, bit_pos, 1, true);
	if (err)
		goto out;
	down_write(&bmp_ni->runlist.lock);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, bmp_ni);
	up_write(&bmp_ni->runlist.lock);
out:
	if (allocated_rl)
		kvfree(allocated_rl);
	kvfree(storage);
	return err;
}

static int ntfs_ibm_modify_nonresident_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		struct ntfs_attr_search_ctx *actx, u64 bit_pos, u32 bpos,
		u8 mask, bool set)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct attr_record *attr = actx->attr;
	struct mft_record *mrec = actx->mrec;
	struct ntfs_inode *bmp_ni;
	struct inode *bmp_vi = NULL;
	u8 new_bytes[8] = { };
	u64 allocated_size;
	u64 data_size;
	u64 initialized_size;
	u64 operation_lsn;
	u64 dev_off;
	u64 new_size;
	ptrdiff_t record_pos;
	u32 attr_len;
	u32 mrec_allocated;
	u32 mrec_used;
	u16 mapping_off;
	u16 record_off;
	u8 old_byte;
	u8 new_byte;
	int err;

	if (!handle || !icx || !actx || !attr || !mrec ||
	    !attr->non_resident || attr->type != AT_BITMAP)
		return -EINVAL;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off =
			le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	mrec_used = le32_to_cpu(mrec->bytes_in_use);
	mrec_allocated = le32_to_cpu(mrec->bytes_allocated);
	allocated_size = le64_to_cpu(attr->data.non_resident.allocated_size);
	data_size = le64_to_cpu(attr->data.non_resident.data_size);
	initialized_size =
			le64_to_cpu(attr->data.non_resident.initialized_size);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    attr_len < offsetof(struct attr_record,
		    data.non_resident.compressed_size) ||
	    !IS_ALIGNED(mapping_off, 8) ||
	    mapping_off < offsetof(struct attr_record,
		    data.non_resident.compressed_size) ||
	    mapping_off >= attr_len || mrec_used > mrec_allocated ||
	    record_pos > mrec_used || attr_len > mrec_used - record_pos ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    attr->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_SPARSE |
		    ATTR_IS_ENCRYPTED) ||
	    !data_size || !IS_ALIGNED(data_size, 8) ||
	    initialized_size != data_size || data_size > allocated_size ||
	    !IS_ALIGNED(allocated_size, icx->idx_ni->vol->cluster_size))
		return -EIO;
	record_off = record_pos;

	bmp_vi = ntfs_attr_iget(VFS_I(icx->idx_ni), AT_BITMAP, icx->name,
			icx->name_len);
	if (IS_ERR(bmp_vi))
		return PTR_ERR(bmp_vi);
	bmp_ni = NTFS_I(bmp_vi);
	if (!NInoNonResident(bmp_ni) || NInoCompressed(bmp_ni) ||
	    NInoSparse(bmp_ni) || NInoEncrypted(bmp_ni) ||
	    bmp_ni->allocated_size != allocated_size ||
	    bmp_ni->data_size != data_size ||
	    bmp_ni->initialized_size != initialized_size ||
	    i_size_read(bmp_vi) != data_size) {
		err = -EIO;
		goto out;
	}

	if (bpos < data_size) {
		if (ntfs_inode_attr_pread(bmp_vi, bpos, 1, &old_byte) != 1) {
			err = -EIO;
			goto out;
		}
		new_byte = set ? old_byte | mask : old_byte & ~mask;
		if (new_byte == old_byte) {
			err = 0;
			goto out;
		}
		err = ntfs_index_bitmap_resolve_dev_off(bmp_ni, bpos, 1,
				&dev_off);
		if (err)
			goto out;
		err = ntfs_index_bitmap_prepare_raw_write(bmp_vi, bpos, dev_off,
				1);
		if (err)
			goto out;
		err = ntfs_index_bitmap_byte_register_home_undo(handle, bmp_vi,
				bpos, dev_off, old_byte);
		if (err)
			goto out;
		err = ntfs_log_bitmap_update(handle, bmp_vi, bit_pos, 1, set);
		if (err)
			goto out;
		err = ntfs_index_bdev_write_ordered(bmp_vi, &new_byte,
				dev_off, sizeof(new_byte), true);
		if (err)
			goto out;
		ntfs_index_bitmap_invalidate(bmp_vi, bpos);
		err = 0;
		goto out;
	}

	if (!set || check_add_overflow((u64)bpos, 1ULL, &new_size)) {
		err = !set ? -EIO : -EOVERFLOW;
		goto out;
	}
	new_size = ALIGN(new_size, 8);
	if (new_size != data_size + sizeof(new_bytes)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	if (new_size > allocated_size) {
		err = ntfs_ibm_grow_nonresident_transacted(handle, bmp_vi,
				bit_pos, bpos, mask, new_size);
		goto out;
	}
	new_bytes[bpos - data_size] |= mask;
	err = ntfs_index_bitmap_resolve_dev_off(bmp_ni, data_size,
			sizeof(new_bytes), &dev_off);
	if (err)
		goto out;
	err = ntfs_index_bitmap_prepare_raw_write(bmp_vi, data_size, dev_off,
			sizeof(new_bytes));
	if (err)
		goto out;
	err = ntfs_index_attr_size_register_home_undo(handle, bmp_ni);
	if (err)
		goto out;
	err = ntfs_attr_mft_register_home_undo(handle, actx->ntfs_ino, mrec);
	if (err)
		goto out;
	/* New initialized bytes are ordered before the MFT size publication. */
	err = ntfs_index_bdev_write_ordered(bmp_vi, new_bytes, dev_off,
			sizeof(new_bytes), true);
	if (err)
		goto out;
	ntfs_index_bitmap_invalidate(bmp_vi, data_size);
	err = ntfs_log_bitmap_update(handle, bmp_vi, bit_pos, 1, true);
	if (err)
		goto out;

	old_sizes.alloc_size = attr->data.non_resident.allocated_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	new_sizes.alloc_size = old_sizes.alloc_size;
	new_sizes.valid_size = cpu_to_le64(new_size);
	new_sizes.data_size = cpu_to_le64(new_size);
	err = ntfs_log_mft_attribute_sizes_update(handle,
			actx->ntfs_ino->mft_no, record_off, &old_sizes, &new_sizes,
			false, &operation_lsn);
	if (err)
		goto out;
	attr->data.non_resident.initialized_size = new_sizes.valid_size;
	attr->data.non_resident.data_size = new_sizes.data_size;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(actx->ntfs_ino);
	bmp_ni->data_size = new_size;
	bmp_ni->initialized_size = new_size;
	bmp_ni->zeroed_size = new_size;
	i_size_write(bmp_vi, new_size);
	err = 0;
out:
	iput(bmp_vi);
	return err;
}

static int ntfs_ibm_modify_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		s64 vcn, bool set)
{
	struct ntfs_attr_search_ctx *actx;
	struct ntfs_inode *bmp_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	struct inode *bmp_vi = NULL;
	u64 operation_lsn;
	u64 pos;
	u32 attr_len;
	u32 mrec_allocated;
	u32 mrec_used;
	u32 new_attr_len;
	u32 new_mrec_used;
	u32 new_value_len;
	u32 value_len;
	u32 bpos;
	u16 value_off;
	ptrdiff_t record_off;
	u32 attr_off;
	u8 *new_value = NULL;
	u8 *value;
	u8 old_byte;
	u8 new_byte;
	u8 mask;
	int err;

	if (!handle || !icx || !icx->idx_ni || vcn < 0)
		return -EINVAL;
	pos = ntfs_ibm_vcn_to_pos(icx, vcn);
	if (pos > U32_MAX * 8ULL)
		return -E2BIG;
	bpos = pos >> 3;
	mask = 1U << (pos & 7);

	actx = ntfs_attr_get_search_ctx(icx->idx_ni, NULL);
	if (!actx)
		return -ENOMEM;
	err = ntfs_attr_lookup(AT_BITMAP, icx->name, icx->name_len,
			CASE_SENSITIVE, 0, NULL, 0, actx);
	if (err)
		goto out;

	attr = actx->attr;
	mrec = actx->mrec;
	if (!mrec || !attr || attr->type != AT_BITMAP) {
		err = -EIO;
		goto out;
	}
	if (attr->non_resident) {
		err = ntfs_ibm_modify_nonresident_transacted(handle, icx, actx,
				pos, bpos, mask, set);
		goto out;
	}
	record_off = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mrec_used = le32_to_cpu(mrec->bytes_in_use);
	mrec_allocated = le32_to_cpu(mrec->bytes_allocated);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (record_off < 0 || record_off > U16_MAX ||
	    !IS_ALIGNED(record_off, 8) || value_off > attr_len ||
	    !value_len || !IS_ALIGNED(value_len, 8) || value_len > U16_MAX ||
	    value_len > attr_len - value_off || mrec_used > mrec_allocated ||
	    record_off > mrec_used || attr_len > mrec_used - record_off) {
		err = -EIO;
		goto out;
	}

	value = (u8 *)attr + value_off;
	if (bpos >= value_len) {
		if (!set || check_add_overflow(bpos, 1U, &new_value_len) ||
		    check_add_overflow(new_value_len, 7U, &new_value_len)) {
			err = !set ? -EIO : -EOVERFLOW;
			goto out;
		}
		new_value_len = ALIGN_DOWN(new_value_len, 8);
		if (new_value_len > U16_MAX ||
		    check_add_overflow((u32)value_off, new_value_len,
			    &new_attr_len)) {
			err = -E2BIG;
			goto out;
		}
		new_attr_len = ALIGN(new_attr_len, 8);
		if (new_attr_len < attr_len ||
		    check_add_overflow(mrec_used, new_attr_len - attr_len,
			    &new_mrec_used)) {
			err = -EOVERFLOW;
			goto out;
		}
		if (new_mrec_used > mrec_allocated) {
			err = ntfs_ibm_make_nonresident_transacted(handle, icx,
					actx, bpos, mask, new_value_len);
			goto out;
		}
		new_value = kvzalloc(new_value_len, GFP_NOFS);
		if (!new_value) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(new_value, value, value_len);
		new_value[bpos] |= mask;

		bmp_vi = ntfs_attr_iget(VFS_I(icx->idx_ni), AT_BITMAP,
				icx->name, icx->name_len);
		if (IS_ERR(bmp_vi)) {
			err = PTR_ERR(bmp_vi);
			bmp_vi = NULL;
			goto out;
		}
		bmp_ni = NTFS_I(bmp_vi);
		if (NInoNonResident(bmp_ni) || NInoCompressed(bmp_ni) ||
		    NInoSparse(bmp_ni) || NInoEncrypted(bmp_ni) ||
		    bmp_ni->data_size != value_len ||
		    bmp_ni->initialized_size != value_len) {
			err = -EIO;
			goto out;
		}
		err = ntfs_index_attr_size_register_home_undo(handle,
				bmp_ni);
		if (err)
			goto out;
		err = ntfs_attr_mft_register_home_undo(handle,
				actx->ntfs_ino, mrec);
		if (err)
			goto out;
		err = ntfs_log_mft_resident_update(handle,
				actx->ntfs_ino->mft_no, record_off, value_off,
				value, value_len, new_value, new_value_len,
				&operation_lsn);
		if (err)
			goto out;
		err = ntfs_resident_attr_value_resize(mrec, attr,
				new_value_len);
		if (WARN_ON_ONCE(err)) {
			err = -EIO;
			goto out;
		}
		memcpy((u8 *)attr + value_off, new_value, new_value_len);
		bmp_ni->allocated_size = ALIGN(new_value_len, 8);
		bmp_ni->data_size = new_value_len;
		bmp_ni->initialized_size = new_value_len;
		bmp_ni->zeroed_size = new_value_len;
		i_size_write(bmp_vi, new_value_len);
		mrec->lsn = cpu_to_le64(operation_lsn);
		mark_mft_record_dirty(actx->ntfs_ino);
		err = 0;
		goto out;
	}
	if (check_add_overflow((u32)value_off, bpos, &attr_off) ||
	    attr_off > U16_MAX) {
		err = -EIO;
		goto out;
	}
	old_byte = value[bpos];
	new_byte = set ? old_byte | mask : old_byte & ~mask;
	if (new_byte == old_byte) {
		err = 0;
		goto out;
	}
	err = ntfs_attr_mft_register_home_undo(handle, actx->ntfs_ino, mrec);
	if (err)
		goto out;
	err = ntfs_log_mft_resident_update(handle, actx->ntfs_ino->mft_no,
			record_off, attr_off, &old_byte, sizeof(old_byte),
			&new_byte, sizeof(new_byte), &operation_lsn);
	if (err)
		goto out;

	value[bpos] = new_byte;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(actx->ntfs_ino);
out:
	if (bmp_vi)
		iput(bmp_vi);
	kvfree(new_value);
	ntfs_attr_put_search_ctx(actx);
	return err;
}

int ntfs_index_bitmap_modify_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx, s64 vcn, bool set)
{
	return ntfs_ibm_modify_transacted(handle, icx, vcn, set);
}

static int ntfs_index_tail_runlist(struct ntfs_inode *ni, s64 start_vcn,
		s64 end_vcn, struct runlist_element **tail_out)
{
	struct runlist_element *rl;
	struct runlist_element *tail;
	s64 copied = 0;
	s64 expected;
	s64 from;
	s64 lcn;
	s64 run_end;
	s64 run_off;
	size_t i;
	size_t nr = 0;
	bool terminated = false;

	if (!ni || !tail_out || start_vcn < 0 || end_vcn <= start_vcn ||
	    !ni->runlist.rl || !ni->runlist.count)
		return -EINVAL;
	tail = kvmalloc_array(ni->runlist.count, sizeof(*tail), GFP_NOFS);
	if (!tail)
		return -ENOMEM;
	rl = ni->runlist.rl;
	for (i = 0; i < ni->runlist.count; i++) {
		if (!rl[i].length) {
			terminated = true;
			break;
		}
		if (rl[i].length < 0 ||
		    check_add_overflow(rl[i].vcn, rl[i].length, &run_end)) {
			kvfree(tail);
			return -EIO;
		}
		if (run_end <= start_vcn)
			continue;
		if (rl[i].vcn >= end_vcn)
			break;
		if (rl[i].lcn < 0) {
			kvfree(tail);
			return -EOPNOTSUPP;
		}
		from = max(rl[i].vcn, start_vcn);
		run_end = min(run_end, end_vcn);
		run_off = from - rl[i].vcn;
		if (check_add_overflow(start_vcn, copied, &expected) ||
		    from != expected || run_end <= from ||
		    check_add_overflow(rl[i].lcn, run_off, &lcn) ||
		    check_add_overflow(copied, run_end - from, &copied)) {
			kvfree(tail);
			return -EIO;
		}
		tail[nr].vcn = from;
		tail[nr].lcn = lcn;
		tail[nr].length = run_end - from;
		nr++;
	}
	if (!terminated || !nr || copied != end_vcn - start_vcn ||
	    nr >= ni->runlist.count) {
		kvfree(tail);
		return -EIO;
	}
	tail[nr].vcn = end_vcn;
	tail[nr].lcn = LCN_ENOENT;
	tail[nr].length = 0;
	*tail_out = tail;
	return 0;
}

static int ntfs_index_allocation_truncate_tail_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx)
{
	struct ntfs_attr_search_ctx *actx;
	struct ntfs_inode *base_ni;
	struct ntfs_inode *ni;
	struct attr_record *attr;
	struct runlist_element *tail = NULL;
	u8 *bitmap;
	u64 block_count;
	u64 new_size_u64;
	u64 old_clusters;
	u64 required_clusters;
	u64 target_clusters;
	s64 new_size;
	u32 attr_len;
	u32 byte;
	u32 value_len;
	u16 value_off;
	int bit;
	int err;

	if (!handle || !icx || !icx->idx_ni)
		return -EINVAL;
	if (!icx->ia_ni)
		return 0;
	ni = icx->ia_ni;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni || !NInoNonResident(ni) ||
	    NInoCompressed(ni) || NInoSparse(ni) || NInoEncrypted(ni))
		return 0;

	actx = ntfs_attr_get_search_ctx(icx->idx_ni, NULL);
	if (!actx)
		return -ENOMEM;
	err = ntfs_attr_lookup(AT_BITMAP, icx->name, icx->name_len,
			CASE_SENSITIVE, 0, NULL, 0, actx);
	if (err)
		goto out_ctx;
	attr = actx->attr;
	if (!attr || attr->non_resident || attr->type != AT_BITMAP) {
		err = 0;
		goto out_ctx;
	}
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (value_off > attr_len || value_len > attr_len - value_off) {
		err = -EIO;
		goto out_ctx;
	}
	bitmap = (u8 *)attr + value_off;
	block_count = 0;
	for (byte = value_len; byte; byte--) {
		if (!bitmap[byte - 1])
			continue;
		bit = fls(bitmap[byte - 1]) - 1;
		block_count = (u64)(byte - 1) * 8 + bit + 1;
		break;
	}
	if (check_mul_overflow(block_count, (u64)icx->block_size,
			&new_size_u64) || new_size_u64 > S64_MAX) {
		err = -EOVERFLOW;
		goto out_ctx;
	}
	new_size = new_size_u64;
	err = 0;
out_ctx:
	ntfs_attr_put_search_ctx(actx);
	if (err)
		return err;
	if (ni->allocated_size < 0 || ni->data_size < 0 ||
	    ni->initialized_size < 0 || ni->zeroed_size < 0 ||
	    ni->data_size != ni->initialized_size ||
	    !IS_ALIGNED(ni->data_size, icx->block_size) ||
	    !IS_ALIGNED(ni->allocated_size, ni->vol->cluster_size) ||
	    ni->data_size > ni->allocated_size || new_size > ni->data_size)
		return -EIO;
	old_clusters = ni->allocated_size >> ni->vol->cluster_size_bits;
	required_clusters = DIV_ROUND_UP_ULL(new_size,
			ni->vol->cluster_size);
	if (required_clusters > old_clusters)
		return -EIO;
	target_clusters = old_clusters > MAX_RETIRED_INDEX_VCNS ?
		old_clusters - MAX_RETIRED_INDEX_VCNS : 0;
	target_clusters = max(target_clusters, required_clusters);
	if (new_size == ni->data_size && target_clusters == old_clusters)
		return 0;

	err = ntfs_index_allocation_register_home_undo(handle, ni);
	if (err)
		return err;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	down_write(&ni->runlist.lock);
	if (target_clusters < old_clusters) {
		err = ntfs_index_tail_runlist(ni, target_clusters, old_clusters,
				&tail);
		if (err)
			goto out_unlock;
		err = ntfs_rl_truncate_nolock(ni->vol, &ni->runlist,
				target_clusters);
		if (err)
			goto out_unlock;
		ni->runlist.rl_hint = -1;
		ni->allocated_size = ntfs_cluster_to_bytes(ni->vol,
				target_clusters);
		VFS_I(base_ni)->i_blocks = ni->allocated_size >> 9;
	}
	ni->data_size = new_size;
	ni->initialized_size = new_size;
	ni->zeroed_size = min(ni->zeroed_size, new_size);
	i_size_write(VFS_I(ni), new_size);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
out_unlock:
	up_write(&ni->runlist.lock);
	if (!err && tail)
		err = ntfs_cluster_free_from_rl_transacted(handle, ni->vol, tail);
	kvfree(tail);
	return err;
}

static int ntfs_index_empty_allocation_remove_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx)
{
	struct ntfs_attr_search_ctx *actx;
	struct ntfs_inode *bmp_ni;
	struct attr_record *attr;
	struct inode *bmp_vi;
	u8 *bitmap;
	u32 attr_len;
	u32 byte;
	u32 value_len;
	u16 value_off;
	bool empty = true;
	int err;

	if (!handle || !icx || !icx->idx_ni)
		return -EINVAL;
	if (!icx->ia_ni || !icx->ir || icx->ib_dirty ||
	    NInoIndexAllocPresent(icx->idx_ni) ||
	    (icx->ir->index.flags & NODE_MASK) != SMALL_INDEX)
		return 0;
	if (ntfs_index_entries_validate(&icx->ir->index, false))
		return -EIO;
	if (!NInoNonResident(icx->ia_ni) ||
	    icx->ia_ni->allocated_size || icx->ia_ni->data_size ||
	    icx->ia_ni->initialized_size || icx->ia_ni->zeroed_size ||
	    i_size_read(VFS_I(icx->ia_ni)))
		return 0;

	actx = ntfs_attr_get_search_ctx(icx->idx_ni, NULL);
	if (!actx)
		return -ENOMEM;
	err = ntfs_attr_lookup(AT_BITMAP, icx->name, icx->name_len,
			CASE_SENSITIVE, 0, NULL, 0, actx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out_ctx;
	}
	attr = actx->attr;
	if (!attr || attr->non_resident || attr->type != AT_BITMAP) {
		err = -EIO;
		goto out_ctx;
	}
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (!value_len || !IS_ALIGNED(value_len, 8) || value_off > attr_len ||
	    value_len > attr_len - value_off) {
		err = -EIO;
		goto out_ctx;
	}
	bitmap = (u8 *)attr + value_off;
	for (byte = 0; byte < value_len; byte++) {
		if (bitmap[byte]) {
			empty = false;
			break;
		}
	}
	err = 0;
out_ctx:
	ntfs_attr_put_search_ctx(actx);
	if (err || !empty)
		return err;

	bmp_vi = ntfs_attr_iget(VFS_I(icx->idx_ni), AT_BITMAP, icx->name,
			icx->name_len);
	if (IS_ERR(bmp_vi))
		return PTR_ERR(bmp_vi);
	bmp_ni = NTFS_I(bmp_vi);
	if (NInoNonResident(bmp_ni) || bmp_ni->data_size != value_len ||
	    bmp_ni->initialized_size != value_len) {
		err = -EIO;
		goto out_bmp;
	}

	err = ntfs_index_inode_state_register_home_undo(handle, icx->ia_ni);
	if (err)
		goto out_bmp;
	err = ntfs_index_inode_state_register_home_undo(handle, bmp_ni);
	if (err)
		goto out_bmp;
	actx = ntfs_attr_get_search_ctx(icx->idx_ni, NULL);
	if (!actx) {
		err = -ENOMEM;
		goto out_bmp;
	}
	err = ntfs_attr_lookup(AT_BITMAP, icx->name, icx->name_len,
			CASE_SENSITIVE, 0, NULL, 0, actx);
	if (!err)
		err = ntfs_attr_record_rm_transacted(handle, actx);
	ntfs_attr_put_search_ctx(actx);
	if (err)
		goto out_bmp;
	err = ntfs_attr_rm_empty_transacted(handle, icx->ia_ni);
	if (err)
		goto out_bmp;

	NInoClearIndexAllocPresent(icx->ia_ni);
	icx->ia_ni->type = AT_UNUSED;
	VFS_I(icx->ia_ni)->i_blocks = 0;
	clear_nlink(VFS_I(icx->ia_ni));
	bmp_ni->type = AT_UNUSED;
	clear_nlink(bmp_vi);
out_bmp:
	iput(bmp_vi);
	return err;
}

static int ntfs_ibm_modify(struct ntfs_index_context *icx, s64 vcn, int set)
{
	u8 byte;
	u64 pos = ntfs_ibm_vcn_to_pos(icx, vcn);
	u32 bpos = pos / 8;
	u32 bit = 1 << (pos % 8);
	struct ntfs_inode *bmp_ni;
	struct inode *bmp_vi;
	int ret = 0;

	ntfs_debug("%s vcn: %lld\n", set ? "set" : "clear", vcn);

	bmp_vi = ntfs_attr_iget(VFS_I(icx->idx_ni), AT_BITMAP, icx->name, icx->name_len);
	if (IS_ERR(bmp_vi)) {
		ntfs_error(icx->idx_ni->vol->sb, "Failed to open $BITMAP attribute");
		return PTR_ERR(bmp_vi);
	}

	bmp_ni = NTFS_I(bmp_vi);

	if (set) {
		if (bmp_ni->data_size < bpos + 1) {
			ret = ntfs_attr_truncate(bmp_ni, (bmp_ni->data_size + 8) & ~7);
			if (ret) {
				if (ret != -ENOSPC)
					ntfs_error(icx->idx_ni->vol->sb,
						   "Failed to truncate AT_BITMAP");
				goto err;
			}
			i_size_write(bmp_vi, (loff_t)bmp_ni->data_size);
		}
	}

	if (ntfs_inode_attr_pread(bmp_vi, bpos, 1, &byte) != 1) {
		ret = -EIO;
		ntfs_error(icx->idx_ni->vol->sb, "Failed to read $BITMAP");
		goto err;
	}

	if (set)
		byte |= bit;
	else
		byte &= ~bit;

	if (ntfs_inode_attr_pwrite(bmp_vi, bpos, 1, &byte, false) != 1) {
		ret = -EIO;
		ntfs_error(icx->idx_ni->vol->sb, "Failed to write $Bitmap");
		goto err;
	}

err:
	iput(bmp_vi);
	return ret;
}

static int ntfs_ibm_set(struct ntfs_index_context *icx, s64 vcn)
{
	return ntfs_ibm_modify(icx, vcn, 1);
}

static int ntfs_ibm_clear(struct ntfs_index_context *icx, s64 vcn)
{
	return ntfs_ibm_modify(icx, vcn, 0);
}

static s64 ntfs_ibm_get_free_core(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx)
{
	u8 *bm;
	int bit;
	int ret;
	s64 vcn, byte, size;

	ntfs_debug("Entering\n");

	bm = ntfs_attr_readall(icx->idx_ni, AT_BITMAP,  icx->name, icx->name_len,
			&size);
	if (IS_ERR(bm))
		return PTR_ERR(bm);

	for (byte = 0; byte < size; byte++) {
		if (bm[byte] == 255)
			continue;

		for (bit = 0; bit < 8; bit++) {
			if (!(bm[byte] & (1 << bit))) {
				vcn = ntfs_ibm_pos_to_vcn(icx, byte * 8 + bit);
				goto out;
			}
		}
	}

	vcn = ntfs_ibm_pos_to_vcn(icx, size * 8);
out:
	ntfs_debug("allocated vcn: %lld\n", vcn);

	if (handle) {
		ret = ntfs_ibm_modify_transacted(handle, icx, vcn,
				true);
	} else {
		ret = ntfs_ibm_set(icx, vcn);
	}

	kvfree(bm);
	if (ret)
		return ret;

	return vcn;
}

static s64 ntfs_ibm_get_free(struct ntfs_index_context *icx)
{
	return ntfs_ibm_get_free_core(NULL, icx);
}

s64 ntfs_index_bitmap_get_free_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx)
{
	if (!handle)
		return -EINVAL;
	return ntfs_ibm_get_free_core(handle, icx);
}

static struct index_block *ntfs_ir_to_ib(struct index_root *ir, s64 ib_vcn)
{
	struct index_block *ib;
	struct index_entry *ie_last;
	char *ies_start, *ies_end;
	int i;
	u32 ib_cap;

	ntfs_debug("Entering\n");

	ib = ntfs_ib_alloc(ib_vcn, le32_to_cpu(ir->index_block_size), LEAF_NODE);
	if (!ib)
		return NULL;

	ies_start = (char *)ntfs_ie_get_first(&ir->index);
	ies_end   = (char *)ntfs_ie_get_end(&ir->index);
	ie_last   = ntfs_ie_get_last((struct index_entry *)ies_start, ies_end);
	/*
	 * Copy all entries, including the termination entry
	 * as well, which can never have any data.
	 */
	i = (char *)ie_last - ies_start + le16_to_cpu(ie_last->length);

	/* Entries must fit in the allocated index block */
	ib_cap = le32_to_cpu(ib->index.allocated_size) -
			le32_to_cpu(ib->index.entries_offset);
	if ((u32)i > ib_cap) {
		ntfs_error(NULL, "Entries (%d B) exceed IB capacity", i);
		kvfree(ib);
		return NULL;
	}

	memcpy(ntfs_ie_get_first(&ib->index), ies_start, i);

	ib->index.flags = ir->index.flags;
	ib->index.index_length = cpu_to_le32(i +
			le32_to_cpu(ib->index.entries_offset));
	return ib;
}

static void ntfs_ir_nill(struct index_root *ir)
{
	struct index_entry *ie_last;
	char *ies_start, *ies_end;

	ntfs_debug("Entering\n");

	ies_start = (char *)ntfs_ie_get_first(&ir->index);
	ies_end   = (char *)ntfs_ie_get_end(&ir->index);
	ie_last   = ntfs_ie_get_last((struct index_entry *)ies_start, ies_end);
	/*
	 * Move the index root termination entry forward
	 */
	if ((char *)ie_last > ies_start) {
		memmove((char *)ntfs_ie_get_first(&ir->index),
			(char *)ie_last, le16_to_cpu(ie_last->length));
		ie_last = (struct index_entry *)ies_start;
	}
}

static int ntfs_ib_copy_tail(struct ntfs_index_context *icx, struct index_block *src,
		struct index_entry *median, s64 new_vcn)
{
	u8 *ies_end;
	struct index_entry *ie_head;		/* first entry after the median */
	int tail_size, ret;
	struct index_block *dst;

	ntfs_debug("Entering\n");

	dst = ntfs_ib_alloc(new_vcn, icx->block_size,
			src->index.flags & NODE_MASK);
	if (!dst)
		return -ENOMEM;

	ie_head = ntfs_ie_get_next(median);

	ies_end = (u8 *)ntfs_ie_get_end(&src->index);
	tail_size = ies_end - (u8 *)ie_head;
	memcpy(ntfs_ie_get_first(&dst->index), ie_head, tail_size);

	dst->index.index_length = cpu_to_le32(tail_size +
			le32_to_cpu(dst->index.entries_offset));
	ret = ntfs_ib_write(icx, dst);

	kvfree(dst);
	return ret;
}

static int ntfs_ib_cut_tail(struct ntfs_index_context *icx, struct index_block *ib,
		struct index_entry *ie)
{
	char *ies_start, *ies_end;
	struct index_entry *ie_last;
	int ret;

	ntfs_debug("Entering\n");

	ies_start = (char *)ntfs_ie_get_first(&ib->index);
	ies_end   = (char *)ntfs_ie_get_end(&ib->index);

	ie_last   = ntfs_ie_get_last((struct index_entry *)ies_start, ies_end);
	if (ie_last->flags & INDEX_ENTRY_NODE)
		ntfs_ie_set_vcn(ie_last, ntfs_ie_get_vcn(ie));

	unsafe_memcpy(ie, ie_last, le16_to_cpu(ie_last->length),
			/* alloc is larger than ie_last->length, see ntfs_ie_get_last() */);

	ib->index.index_length = cpu_to_le32(((char *)ie - ies_start) +
			le16_to_cpu(ie->length) + le32_to_cpu(ib->index.entries_offset));

	ret = ntfs_ib_write(icx, ib);
	return ret;
}

static int ntfs_ia_add(struct ntfs_index_context *icx)
{
	int ret;

	ntfs_debug("Entering\n");

	ret = ntfs_ibm_add(icx);
	if (ret)
		return ret;

	if (!ntfs_attr_exist(icx->idx_ni, AT_INDEX_ALLOCATION, icx->name, icx->name_len)) {
		ret = ntfs_attr_add(icx->idx_ni, AT_INDEX_ALLOCATION, icx->name,
					icx->name_len, NULL, 0);
		if (ret) {
			if (ret != -ENOSPC)
				ntfs_error(icx->idx_ni->vol->sb,
					   "Failed to add AT_INDEX_ALLOCATION");
			return ret;
		}
	}

	icx->ia_ni = ntfs_ia_open(icx, icx->idx_ni);
	if (!icx->ia_ni)
		return -ENOENT;

	return 0;
}

static int ntfs_ir_reparent(struct ntfs_index_context *icx)
{
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct index_root *ir;
	struct index_entry *ie;
	struct index_block *ib = NULL;
	s64 new_ib_vcn;
	u32 index_length;
	u32 old_value_length;
	int ix_root_size;
	int ret = 0;

	ntfs_debug("Entering\n");

	ir = ntfs_ir_lookup2(icx->idx_ni, icx->name, icx->name_len);
	if (!ir) {
		ret = -ENOENT;
		goto out;
	}

	if ((ir->index.flags & NODE_MASK) == SMALL_INDEX) {
		ret = ntfs_ia_add(icx);
		if (ret)
			goto out;
	}

	new_ib_vcn = ntfs_ibm_get_free(icx);
	if (new_ib_vcn < 0) {
		ret = (int)new_ib_vcn;
		goto out;
	}

	ir = ntfs_ir_lookup2(icx->idx_ni, icx->name, icx->name_len);
	if (!ir) {
		ret = -ENOENT;
		goto clear_bmp;
	}

	ib = ntfs_ir_to_ib(ir, new_ib_vcn);
	if (ib == NULL) {
		ret = -EIO;
		ntfs_error(icx->idx_ni->vol->sb, "Failed to move index root to index block");
		goto clear_bmp;
	}

	ret = ntfs_ib_write(icx, ib);
	if (ret)
		goto clear_bmp;

retry:
	ir = ntfs_ir_lookup(icx->idx_ni, icx->name, icx->name_len, &ctx);
	if (!ir) {
		ret = -ENOENT;
		goto clear_bmp;
	}

	old_value_length = le32_to_cpu(ctx->attr->data.resident.value_length);
	index_length = le32_to_cpu(ir->index.entries_offset) +
		sizeof(struct index_entry_header) + sizeof(s64);
	ix_root_size = offsetof(struct index_root, index) + index_length;
	/* Grow the resident value before publishing the larger root header. */
	if (ix_root_size > old_value_length) {
		ret = ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr, ix_root_size);
		if (ret)
			goto resize_failed;

		icx->idx_ni->data_size = ix_root_size;
		icx->idx_ni->initialized_size = ix_root_size;
		icx->idx_ni->allocated_size = (ix_root_size + 7) & ~7;
	}

	ntfs_ir_nill(ir);

	ie = ntfs_ie_get_first(&ir->index);
	ie->flags |= INDEX_ENTRY_NODE;
	ie->length = cpu_to_le16(sizeof(struct index_entry_header) + sizeof(s64));

	ir->index.flags = LARGE_INDEX;
	NInoSetIndexAllocPresent(icx->idx_ni);
	ir->index.index_length = cpu_to_le32(index_length);
	ir->index.allocated_size = ir->index.index_length;

	if (ix_root_size <= old_value_length) {
		ret = ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr, ix_root_size);
		if (ret)
			goto resize_failed;

		icx->idx_ni->data_size = ix_root_size;
		icx->idx_ni->initialized_size = ix_root_size;
		icx->idx_ni->allocated_size = (ix_root_size + 7) & ~7;
	}
	ntfs_ie_set_vcn(ie, new_ib_vcn);
	goto err_out;

resize_failed:
	/*
	 * When there is no space to build a non-resident
	 * index, we may have to move the root to an extent
	 */
	if (ret == -ENOSPC) {
		if (!ctx->al_entry) {
			ret = ntfs_inode_add_attrlist(icx->idx_ni);
			if (ret)
				goto clear_bmp;

			ntfs_attr_put_search_ctx(ctx);
			ctx = NULL;
			goto retry;
		}

		if (ctx->ntfs_ino->mft_no != icx->idx_ni->mft_no)
			goto clear_bmp;

		ret = ntfs_attr_record_move_away(ctx, ix_root_size -
				le32_to_cpu(ctx->attr->data.resident.value_length));
		if (ret)
			goto clear_bmp;

		ret = ntfs_attrlist_update(icx->idx_ni);
		if (ret) {
			int rollback_ret;

			ntfs_attr_put_search_ctx(ctx);
			ctx = NULL;
			rollback_ret = ntfs_ir_move_to_base(icx);
			if (rollback_ret)
				ntfs_error(icx->idx_ni->vol->sb,
					   "Failed to roll back INDEX_ROOT relocation: %d",
					   rollback_ret);
			goto clear_bmp;
		}

		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
		goto retry;
	}
clear_bmp:
	ntfs_ibm_clear(icx, new_ib_vcn);
	goto err_out;
err_out:
	kvfree(ib);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
out:
	return ret;
}

/*
 * ntfs_ir_truncate - Truncate index root attribute
 * @icx: index context
 * @data_size: new data size for the index root
 */
static int ntfs_ir_truncate(struct ntfs_index_context *icx, int data_size)
{
	int ret;
	u32 old_allocated_size;
	bool shrink;

	ntfs_debug("Entering\n");

	old_allocated_size = le32_to_cpu(icx->ir->index.allocated_size);
	shrink = data_size < old_allocated_size;
	if (shrink)
		icx->ir->index.allocated_size = cpu_to_le32(data_size);

	/*
	 *  INDEX_ROOT must be resident and its entries can be moved to
	 *  struct index_block, so ENOSPC isn't a real error.
	 */
	ret = ntfs_attr_truncate(icx->idx_ni, data_size + offsetof(struct index_root, index));
	if (!ret) {
		i_size_write(VFS_I(icx->idx_ni), icx->idx_ni->initialized_size);
		icx->ir = ntfs_ir_lookup2(icx->idx_ni, icx->name, icx->name_len);
		if (!icx->ir)
			return -ENOENT;

		if (!shrink)
			icx->ir->index.allocated_size = cpu_to_le32(data_size);
	} else {
		if (shrink)
			icx->ir->index.allocated_size = cpu_to_le32(old_allocated_size);
		if (ret != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb, "Failed to truncate INDEX_ROOT");
	}

	return ret;
}

/*
 * ntfs_ir_make_space - Make more space for the index root attribute
 * @icx: index context
 * @data_size: required data size for the index root
 */
static int ntfs_ir_make_space(struct ntfs_index_context *icx, int data_size)
{
	int ret;

	ntfs_debug("Entering\n");

	ret = ntfs_ir_truncate(icx, data_size);
	if (ret == -ENOSPC) {
		ret = ntfs_ir_reparent(icx);
		if (!ret)
			ret = -EAGAIN;
		else if (ret != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb, "Failed to modify INDEX_ROOT");
	}

	return ret;
}

/*
 * NOTE: 'ie' must be a copy of a real index entry.
 */
static int ntfs_ie_add_vcn(struct index_entry **ie)
{
	struct index_entry *p, *old = *ie;

	old->length = cpu_to_le16(le16_to_cpu(old->length) + sizeof(s64));
	p = krealloc(old, le16_to_cpu(old->length), GFP_NOFS);
	if (!p)
		return -ENOMEM;

	p->flags |= INDEX_ENTRY_NODE;
	*ie = p;
	return 0;
}

static int ntfs_ih_insert(struct index_header *ih, struct index_entry *orig_ie, s64 new_vcn,
		int pos)
{
	struct index_entry *ie_node, *ie;
	int ret = 0;
	s64 old_vcn;

	ntfs_debug("Entering\n");
	ie = ntfs_ie_dup(orig_ie);
	if (!ie)
		return -ENOMEM;

	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ret = ntfs_ie_add_vcn(&ie);
		if (ret)
			goto out;
	}

	ie_node = ntfs_ie_get_by_pos(ih, pos);
	old_vcn = ntfs_ie_get_vcn(ie_node);
	ntfs_ie_set_vcn(ie_node, new_vcn);
	ntfs_ie_set_vcn(ie, old_vcn);

	ntfs_ie_insert(ih, ie, ie_node);
out:
	kfree(ie);
	return ret;
}

static s64 ntfs_icx_parent_vcn(struct ntfs_index_context *icx)
{
	return icx->parent_vcn[icx->pindex];
}

static s64 ntfs_icx_parent_pos(struct ntfs_index_context *icx)
{
	return icx->parent_pos[icx->pindex];
}

static int ntfs_ir_insert_median(struct ntfs_index_context *icx, struct index_entry *median,
		s64 new_vcn)
{
	u32 new_size;
	int ret;

	ntfs_debug("Entering\n");

	icx->ir = ntfs_ir_lookup2(icx->idx_ni, icx->name, icx->name_len);
	if (!icx->ir)
		return -ENOENT;

	new_size = le32_to_cpu(icx->ir->index.index_length) +
		le16_to_cpu(median->length);
	if (!(median->flags & INDEX_ENTRY_NODE))
		new_size += sizeof(s64);

	ret = ntfs_ir_make_space(icx, new_size);
	if (ret)
		return ret;

	icx->ir = ntfs_ir_lookup2(icx->idx_ni, icx->name, icx->name_len);
	if (!icx->ir)
		return -ENOENT;

	return ntfs_ih_insert(&icx->ir->index, median, new_vcn,
			ntfs_icx_parent_pos(icx));
}

static int ntfs_ib_split(struct ntfs_index_context *icx, struct index_block *ib);

struct split_info {
	struct list_head entry;
	s64 new_vcn;
	struct index_block *ib;
};

static int ntfs_ib_insert(struct ntfs_index_context *icx, struct index_entry *ie, s64 new_vcn,
		struct split_info *si)
{
	struct index_block *ib;
	u32 idx_size, allocated_size;
	int err;
	s64 old_vcn;

	ntfs_debug("Entering\n");

	ib = kvzalloc(icx->block_size, GFP_NOFS);
	if (!ib)
		return -ENOMEM;

	old_vcn = ntfs_icx_parent_vcn(icx);

	err = ntfs_ib_read(icx, old_vcn, ib);
	if (err)
		goto err_out;

	idx_size = le32_to_cpu(ib->index.index_length);
	allocated_size = le32_to_cpu(ib->index.allocated_size);
	if (idx_size + le16_to_cpu(ie->length) + sizeof(s64) > allocated_size) {
		si->ib = ib;
		si->new_vcn = new_vcn;
		return -EAGAIN;
	}

	err = ntfs_ih_insert(&ib->index, ie, new_vcn, ntfs_icx_parent_pos(icx));
	if (err)
		goto err_out;

	err = ntfs_ib_write(icx, ib);

err_out:
	kvfree(ib);
	return err;
}

/*
 * ntfs_ib_split - Split an index block
 * @icx: index context
 * @ib: index block to split
 */
static int ntfs_ib_split(struct ntfs_index_context *icx, struct index_block *ib)
{
	struct index_entry *median;
	s64 new_vcn;
	int ret;
	struct split_info *si;
	LIST_HEAD(ntfs_cut_tail_list);

	ntfs_debug("Entering\n");

resplit:
	ret = ntfs_icx_parent_dec(icx);
	if (ret)
		goto out;

	median  = ntfs_ie_get_median(&ib->index);
	new_vcn = ntfs_ibm_get_free(icx);
	if (new_vcn < 0) {
		ret = (int)new_vcn;
		goto out;
	}

	ret = ntfs_ib_copy_tail(icx, ib, median, new_vcn);
	if (ret) {
		ntfs_ibm_clear(icx, new_vcn);
		goto out;
	}

	if (ntfs_icx_parent_vcn(icx) == VCN_INDEX_ROOT_PARENT) {
		ret = ntfs_ir_insert_median(icx, median, new_vcn);
		if (ret) {
			ntfs_ibm_clear(icx, new_vcn);
			goto out;
		}
	} else {
		si = kzalloc_obj(struct split_info, GFP_NOFS);
		if (!si) {
			ntfs_ibm_clear(icx, new_vcn);
			ret = -ENOMEM;
			goto out;
		}

		ret = ntfs_ib_insert(icx, median, new_vcn, si);
		if (ret == -EAGAIN) {
			list_add_tail(&si->entry, &ntfs_cut_tail_list);
			ib = si->ib;
			goto resplit;
		} else if (ret) {
			kvfree(si->ib);
			kfree(si);
			ntfs_ibm_clear(icx, new_vcn);
			goto out;
		}
		kfree(si);
	}

	ret = ntfs_ib_cut_tail(icx, ib, median);

out:
	while (!list_empty(&ntfs_cut_tail_list)) {
		si = list_last_entry(&ntfs_cut_tail_list, struct split_info, entry);
		ntfs_ibm_clear(icx, si->new_vcn);
		kvfree(si->ib);
		list_del(&si->entry);
		kfree(si);
		if (!ret)
			ret = -EAGAIN;
	}

	return ret;
}

int ntfs_ie_add(struct ntfs_index_context *icx, struct index_entry *ie)
{
	struct index_header *ih;
	int allocated_size, new_size;
	int ret;

	while (1) {
		ret = ntfs_index_lookup(&ie->key, le16_to_cpu(ie->key_length), icx);
		if (!ret) {
			ret = -EEXIST;
			ntfs_error(icx->idx_ni->vol->sb, "Index already have such entry");
			goto err_out;
		}
		if (ret != -ENOENT) {
			ntfs_error(icx->idx_ni->vol->sb, "Failed to find place for new entry");
			goto err_out;
		}
		ret = 0;

		if (icx->is_in_root)
			ih = &icx->ir->index;
		else
			ih = &icx->ib->index;

		allocated_size = le32_to_cpu(ih->allocated_size);
		new_size = le32_to_cpu(ih->index_length) + le16_to_cpu(ie->length);

		if (new_size <= allocated_size)
			break;

		ntfs_debug("index block sizes: allocated: %d  needed: %d\n",
				allocated_size, new_size);

		if (icx->is_in_root)
			ret = ntfs_ir_make_space(icx, new_size);
		else
			ret = ntfs_ib_split(icx, icx->ib);
		if (ret && ret != -EAGAIN)
			goto err_out;

		mark_mft_record_dirty(icx->actx->ntfs_ino);
		ntfs_index_ctx_reinit(icx);
	}

	ntfs_ie_insert(ih, ie, icx->entry);
	ntfs_index_entry_mark_dirty(icx);

err_out:
	ntfs_debug("%s\n", ret ? "Failed" : "Done");
	return ret;
}

static int ntfs_index_allocation_metadata(struct ntfs_index_context *icx,
		struct index_header **ih_out, u64 *byte_pos_out,
		u16 *attr_off_out)
{
	struct index_header *ih;
	u32 entries_off;
	u32 index_len;
	u32 allocated_size;
	u32 first_entry;
	u32 used_end;
	u16 entry_len;
	s64 byte_pos;
	s64 vcn;
	ptrdiff_t attr_off;

	if (!icx || !icx->idx_ni || !icx->ia_ni || !icx->ib ||
	    !icx->entry || icx->is_in_root)
		return -EINVAL;
	if (icx->block_size < NTFS_BLOCK_SIZE || icx->block_size > U16_MAX ||
	    !is_power_of_2(icx->block_size))
		return -EOPNOTSUPP;

	ih = &icx->ib->index;
	entries_off = le32_to_cpu(ih->entries_offset);
	index_len = le32_to_cpu(ih->index_length);
	allocated_size = le32_to_cpu(ih->allocated_size);
	if (!IS_ALIGNED(entries_off, 8) || !IS_ALIGNED(index_len, 8) ||
	    !IS_ALIGNED(allocated_size, 8) || entries_off > index_len ||
	    index_len > allocated_size ||
	    allocated_size > icx->block_size -
			offsetof(struct index_block, index))
		return -EIO;

	first_entry = offsetof(struct index_block, index) + entries_off;
	used_end = offsetof(struct index_block, index) + index_len;
	attr_off = (u8 *)icx->entry - (u8 *)icx->ib;
	entry_len = le16_to_cpu(icx->entry->length);
	if (attr_off < first_entry || attr_off > U16_MAX ||
	    attr_off > used_end - sizeof(struct index_entry_header) ||
	    entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8) || entry_len > used_end - attr_off)
		return -EIO;

	vcn = le64_to_cpu(icx->ib->index_block_vcn);
	if (vcn < 0 || check_shl_overflow(vcn, icx->vcn_size_bits,
			&byte_pos))
		return -EOVERFLOW;
	*ih_out = ih;
	*byte_pos_out = byte_pos;
	*attr_off_out = attr_off;
	return 0;
}

static void ntfs_index_root_update_size(struct ntfs_index_context *icx,
		u32 value_len);
static int ntfs_index_root_context_refresh(struct ntfs_index_context *icx);
static int ntfs_index_root_resize_check(const struct mft_record *mrec,
		const struct attr_record *attr, u32 new_value_len);
static int ntfs_index_root_move_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx);

static int ntfs_index_entries_validate(struct index_header *ih, bool node)
{
	struct index_entry *ie;
	u8 *end;
	u16 entry_len;
	u16 key_len;
	u16 min_len;

	if (!ih || ((ih->flags & NODE_MASK) == INDEX_NODE) != node)
		return -EIO;
	ie = ntfs_ie_get_first(ih);
	end = ntfs_ie_get_end(ih);
	min_len = sizeof(struct index_entry_header) +
		(node ? sizeof(s64) : 0);
	for (;;) {
		if ((u8 *)ie + sizeof(struct index_entry_header) > end)
			return -EIO;
		entry_len = le16_to_cpu(ie->length);
		key_len = le16_to_cpu(ie->key_length);
		if (entry_len < min_len || !IS_ALIGNED(entry_len, 8) ||
		    entry_len > end - (u8 *)ie ||
		    !!(ie->flags & INDEX_ENTRY_NODE) != node)
			return -EIO;
		if (ie->flags & INDEX_ENTRY_END)
			return key_len || (u8 *)ie + entry_len != end ? -EIO : 0;
		if (key_len > entry_len - min_len)
			return -EIO;
		ie = ntfs_ie_get_next(ie);
	}
}

static int ntfs_index_entry_check_unlinked(const struct index_entry *ie,
		u64 mft_no, enum ntfs_system_index index)
{
	__le64 file_id;
	u16 key_len = le16_to_cpu(ie->key_length);
	u16 entry_len = le16_to_cpu(ie->length);
	u16 data_off, data_len;
	u16 trailer = (ie->flags & INDEX_ENTRY_NODE) ? sizeof(s64) : 0;

	if (index == NTFS_SYSTEM_INDEX_REPARSE) {
		if (key_len != sizeof(struct reparse_index_key) ||
		    ie->data.vi.data_length)
			return -EIO;
		memcpy(&file_id, &ie->key.reparse.file_id, sizeof(file_id));
	} else if (index == NTFS_SYSTEM_INDEX_OBJECT_ID) {
		data_off = le16_to_cpu(ie->data.vi.data_offset);
		data_len = le16_to_cpu(ie->data.vi.data_length);
		if (key_len != sizeof(struct guid) ||
		    data_off < offsetof(struct index_entry, key) + key_len ||
		    data_len < sizeof(file_id) || entry_len < trailer ||
		    data_off > entry_len - trailer ||
		    data_len > entry_len - trailer - data_off)
			return -EIO;
		memcpy(&file_id, (const u8 *)ie + data_off, sizeof(file_id));
	} else {
		return -EINVAL;
	}

	return (le64_to_cpu(file_id) & MFT_REF_MASK_CPU) == mft_no ?
		-EUCLEAN : 0;
}

/*
 * Check every reachable system-index entry before retiring an orphan.  The
 * indexed attribute may already have been reclaimed, so its original key
 * cannot be used for a lookup.
 */
int ntfs_index_check_unlinked(struct ntfs_index_context *icx, u64 mft_no,
		enum ntfs_system_index index)
{
	struct {
		struct index_entry *next;
		struct index_block *block;
	} frames[MAX_PARENT_VCN] = {};
	DEFINE_XARRAY(visited);
	struct ntfs_volume *vol;
	struct ntfs_attr_search_ctx *ctx;
	struct attr_record *attr;
	struct mft_record *mrec;
	struct index_root *ir;
	struct index_entry *ie;
	struct index_block *block;
	ptrdiff_t record_off;
	u32 record_used, record_allocated, attr_len, value_off, value_len;
	u64 pos;
	s64 vcn;
	unsigned int depth = 0, i;
	int err = -EIO;

	if (!icx || !icx->idx_ni ||
	    (index != NTFS_SYSTEM_INDEX_REPARSE &&
	     index != NTFS_SYSTEM_INDEX_OBJECT_ID))
		return -EINVAL;
	vol = icx->idx_ni->vol;
	ir = ntfs_ir_lookup(icx->idx_ni, icx->name, icx->name_len, &icx->actx);
	if (!ir)
		return -EIO;
	icx->is_in_root = true;
	ctx = icx->actx;
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || attr->type != AT_INDEX_ROOT || attr->non_resident)
		goto out;
	record_off = (u8 *)attr - (u8 *)mrec;
	record_used = le32_to_cpu(mrec->bytes_in_use);
	record_allocated = le32_to_cpu(mrec->bytes_allocated);
	attr_len = le32_to_cpu(attr->length);
	if (record_off < 0 || record_used > record_allocated ||
	    record_allocated > vol->mft_record_size ||
	    record_off > record_used || attr_len > record_used - record_off ||
	    attr_len < offsetof(struct attr_record, data.resident) +
			sizeof(attr->data.resident))
		goto out;
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (value_off < offsetof(struct attr_record, data.resident) +
			sizeof(attr->data.resident) ||
	    value_off > attr_len || value_len > attr_len - value_off ||
	    value_len < sizeof(*ir) ||
	    ir != (struct index_root *)((u8 *)attr + value_off) ||
	    ir->type || ir->collation_rule != COLLATION_NTOFS_ULONGS)
		goto out;
	if (ntfs_index_root_inconsistent(vol, attr, ir, icx->idx_ni->mft_no) ||
	    ntfs_index_entries_inconsistent(vol, &ir->index,
			le32_to_cpu(ir->index_block_size),
			ir->collation_rule, icx->idx_ni->mft_no) ||
	    ntfs_index_entries_validate(&ir->index,
			(ir->index.flags & NODE_MASK) == INDEX_NODE))
		goto out;

	icx->block_size = le32_to_cpu(ir->index_block_size);
	if (icx->block_size < NTFS_BLOCK_SIZE || icx->block_size > PAGE_SIZE ||
	    !is_power_of_2(icx->block_size))
		goto out;
	icx->vcn_size_bits = vol->cluster_size <= icx->block_size ?
		vol->cluster_size_bits : vol->sector_size_bits;
	if (icx->vcn_size_bits >= 63)
		goto out;
	icx->cr = ir->collation_rule;
	frames[0].next = ntfs_ie_get_first(&ir->index);
	while (frames[0].next || depth) {
		ie = frames[depth].next;
		if (!ie) {
			kvfree(frames[depth].block);
			frames[depth].block = NULL;
			depth--;
			cond_resched();
			continue;
		}
		frames[depth].next = (ie->flags & INDEX_ENTRY_END) ?
			NULL : ntfs_ie_get_next(ie);
		if (!(ie->flags & INDEX_ENTRY_END)) {
			err = ntfs_index_entry_check_unlinked(ie, mft_no, index);
			if (err)
				goto out;
		}
		if (!(ie->flags & INDEX_ENTRY_NODE))
			continue;
		vcn = ntfs_ie_get_vcn(ie);
		if (vcn < 0 || (u64)vcn > ULONG_MAX ||
		    vcn > (S64_MAX >> icx->vcn_size_bits) ||
		    depth + 1 >= ARRAY_SIZE(frames)) {
			err = -EIO;
			goto out;
		}
		if (!icx->ia_ni) {
			icx->ia_ni = ntfs_ia_open(icx, icx->idx_ni);
			if (!icx->ia_ni) {
				err = -EIO;
				goto out;
			}
		}
		pos = (u64)vcn << icx->vcn_size_bits;
		if (!IS_ALIGNED(pos, icx->block_size) ||
		    icx->ia_ni->data_size < 0 ||
		    pos > (u64)icx->ia_ni->data_size ||
		    icx->block_size > (u64)icx->ia_ni->data_size - pos) {
			err = -EIO;
			goto out;
		}
		err = xa_insert(&visited, (unsigned long)vcn, xa_mk_value(1),
				GFP_NOFS);
		if (err) {
			if (err == -EBUSY)
				err = -EUCLEAN;
			goto out;
		}
		block = kvzalloc(icx->block_size, GFP_NOFS);
		if (!block) {
			err = -ENOMEM;
			goto out;
		}
		frames[++depth].block = block;
		err = ntfs_ib_read(icx, vcn, block);
		if (err)
			goto out;
		if (ntfs_index_entries_validate(&block->index,
				(block->index.flags & NODE_MASK) == INDEX_NODE)) {
			err = -EIO;
			goto out;
		}
		frames[depth].next = ntfs_ie_get_first(&block->index);
	}
	err = 0;
out:
	for (i = 1; i < ARRAY_SIZE(frames); i++)
		kvfree(frames[i].block);
	xa_destroy(&visited);
	return err;
}

static int ntfs_index_parent_entry(struct index_header *ih, int pos,
		s64 child_vcn, struct index_entry **entry_out, u32 *offset_out)
{
	struct index_entry *ie;
	int i;

	if (!ih || pos < 0 || child_vcn < 0 || !entry_out)
		return -EINVAL;
	if (ntfs_index_entries_validate(ih, true))
		return -EIO;
	ie = ntfs_ie_get_first(ih);
	for (i = 0; i < pos; i++) {
		if (ie->flags & INDEX_ENTRY_END)
			return -EIO;
		ie = ntfs_ie_get_next(ie);
	}
	if (ntfs_ie_get_vcn(ie) != child_vcn)
		return -EIO;
	if (offset_out)
		*offset_out = (u8 *)ie - (u8 *)ntfs_ie_get_first(ih);
	*entry_out = ie;
	return 0;
}

static int ntfs_index_split_allocate_vcn_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		s64 *vcn_out)
{
	s64 byte_pos;
	s64 new_end;
	s64 vcn;
	int err;

	if (!handle || !icx || !icx->ia_ni || !vcn_out)
		return -EINVAL;
	vcn = ntfs_index_bitmap_get_free_transacted(handle, icx);
	if (vcn < 0)
		return vcn;
	if (check_shl_overflow(vcn, icx->vcn_size_bits, &byte_pos) ||
	    check_add_overflow(byte_pos, (s64)icx->block_size, &new_end))
		return -EOVERFLOW;
	if (new_end > icx->ia_ni->initialized_size) {
		if (byte_pos != icx->ia_ni->initialized_size)
			return -EOPNOTSUPP;
		err = ntfs_index_allocation_extend_transacted(handle, icx,
				new_end);
		if (err)
			return err;
	}
	*vcn_out = vcn;
	return 0;
}

static int ntfs_index_root_replace_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		struct index_root *new_root, u32 new_root_len);

/* A resident root has a hard size limit, even in an otherwise empty extent. */
static int ntfs_index_root_raise_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx, struct index_root *expanded)
{
	struct index_block *child;
	struct index_entry *end;
	u32 entries_len, child_off, root_len;
	s64 vcn;
	int err;

	if (icx->pindex >= MAX_PARENT_VCN - 1)
		return -EOPNOTSUPP;
	entries_len = le32_to_cpu(expanded->index.index_length) -
		le32_to_cpu(expanded->index.entries_offset);
	child = ntfs_ib_alloc(0, icx->block_size, INDEX_NODE);
	if (!child)
		return -ENOMEM;
	child_off = le32_to_cpu(child->index.entries_offset);
	if (entries_len > le32_to_cpu(child->index.allocated_size) - child_off) {
		err = -EOPNOTSUPP;
		goto out;
	}
	memcpy(ntfs_ie_get_first(&child->index),
			ntfs_ie_get_first(&expanded->index), entries_len);
	child->index.index_length = cpu_to_le32(child_off + entries_len);
	err = ntfs_index_split_allocate_vcn_transacted(handle, icx, &vcn);
	if (err)
		goto out;
	child->index_block_vcn = cpu_to_le64(vcn);
	err = ntfs_index_block_initialize_transacted(handle, icx, child);
	if (err)
		goto out;

	/* The new root contains only an end entry pointing to the old level. */
	ntfs_ir_nill(expanded);
	end = ntfs_ie_get_first(&expanded->index);
	ntfs_ie_set_vcn(end, vcn);
	expanded->index.index_length = cpu_to_le32(
		le32_to_cpu(expanded->index.entries_offset) +
		le16_to_cpu(end->length));
	expanded->index.allocated_size = expanded->index.index_length;
	root_len = offsetof(struct index_root, index) +
		le32_to_cpu(expanded->index.index_length);
	/* Allocation growth can move resident attributes. Reacquire the root. */
	err = ntfs_index_root_context_refresh(icx);
	if (!err)
		err = ntfs_index_root_replace_transacted(handle, icx, expanded,
				root_len);
out:
	kvfree(child);
	return err;
}

static int ntfs_index_root_insert_median_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		struct index_entry *promoted, s64 right_vcn, int parent_pos)
{
	struct index_entry *parent_entry;
	struct index_root *new_root = NULL;
	struct index_root *old_root;
	struct index_header *ih;
	struct attr_record *attr;
	struct mft_record *mrec;
	ptrdiff_t record_pos;
	u64 operation_lsn;
	u32 attr_len;
	u32 entries_off;
	u32 new_allocated;
	u32 new_index_len;
	u32 new_root_len;
	u32 old_allocated;
	u32 old_index_len;
	u32 old_root_len;
	u16 promoted_len;
	u16 record_off;
	u16 value_off;
	int err;

	if (!handle || !icx || !promoted || right_vcn < 0 || parent_pos < 0)
		return -EINVAL;
	promoted_len = le16_to_cpu(promoted->length);
	if (!(promoted->flags & INDEX_ENTRY_NODE) ||
	    promoted->flags & INDEX_ENTRY_END ||
	    promoted_len < sizeof(struct index_entry_header) + sizeof(s64) ||
	    !IS_ALIGNED(promoted_len, 8))
		return -EIO;

	/* Split allocation can move resident attributes and invalidate the lookup. */
	err = ntfs_index_root_context_refresh(icx);
	if (err)
		return err;

	attr = icx->actx ? icx->actx->attr : NULL;
	mrec = icx->actx ? icx->actx->mrec : NULL;
	old_root = icx->ir;
	if (!attr || !mrec || !old_root || attr->type != AT_INDEX_ROOT ||
	    attr->non_resident ||
	    (old_root->index.flags & NODE_MASK) != LARGE_INDEX)
		return -EOPNOTSUPP;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	old_root_len = le32_to_cpu(attr->data.resident.value_length);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || value_off > attr_len ||
	    old_root_len > attr_len - value_off || old_root_len > U16_MAX ||
	    old_root != (struct index_root *)((u8 *)attr + value_off))
		return -EIO;
	record_off = record_pos;
	ih = &old_root->index;
	entries_off = le32_to_cpu(ih->entries_offset);
	old_index_len = le32_to_cpu(ih->index_length);
	old_allocated = le32_to_cpu(ih->allocated_size);
	if (entries_off < sizeof(struct index_header) ||
	    !IS_ALIGNED(entries_off, 8) || !IS_ALIGNED(old_index_len, 8) ||
	    !IS_ALIGNED(old_allocated, 8) || entries_off > old_index_len ||
	    old_index_len > old_allocated ||
	    old_root_len != offsetof(struct index_root, index) +
			old_allocated ||
	    ntfs_index_entries_validate(ih, true))
		return -EIO;
	if (check_add_overflow(old_index_len, (u32)promoted_len,
			&new_index_len))
		return -EOVERFLOW;
	new_allocated = max(old_allocated, new_index_len);
	if (check_add_overflow((u32)offsetof(struct index_root, index),
			new_allocated, &new_root_len) || new_root_len > U16_MAX)
		return -EOVERFLOW;
	new_root = kzalloc(new_root_len, GFP_NOFS);
	if (!new_root)
		return -ENOMEM;
	memcpy(new_root, old_root, old_root_len);
	new_root->index.allocated_size = cpu_to_le32(new_allocated);
	err = ntfs_index_parent_entry(&new_root->index, parent_pos,
			ntfs_ie_get_vcn(promoted), &parent_entry, NULL);
	if (err)
		goto out;
	ntfs_ie_set_vcn(parent_entry, right_vcn);
	ntfs_ie_insert(&new_root->index, promoted, parent_entry);
	WARN_ON_ONCE(le32_to_cpu(new_root->index.index_length) !=
			new_index_len);
	err = ntfs_index_root_resize_check(mrec, attr, new_root_len);
	if (err == -ENOSPC && !mrec->base_mft_record) {
		/*
		 * A large root can outgrow the base record even though the root
		 * attribute itself is still resident.  Move the attribute first,
		 * then redo the metadata lookup so the journal update targets the
		 * new extent record.
		 */
		err = ntfs_index_root_move_transacted(handle, icx);
		if (err) {
			if (err != -ENOSPC)
				ntfs_error(icx->idx_ni->vol->sb,
					"Transacted index root move failed for inode %llu before parent insertion (error %d).",
					(unsigned long long)icx->idx_ni->mft_no, err);
			goto out;
		}
		attr = icx->actx ? icx->actx->attr : NULL;
		mrec = icx->actx ? icx->actx->mrec : NULL;
		old_root = icx->ir;
		if (!attr || !mrec || !old_root || attr->type != AT_INDEX_ROOT ||
			attr->non_resident ||
			le32_to_cpu(attr->data.resident.value_length) != old_root_len ||
			old_root != (struct index_root *)((u8 *)attr +
				le16_to_cpu(attr->data.resident.value_offset))) {
			err = -EIO;
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted index root move returned invalid metadata for inode %llu (error %d).",
				(unsigned long long)icx->idx_ni->mft_no, err);
			goto out;
		}
		record_pos = (u8 *)attr - (u8 *)mrec;
		attr_len = le32_to_cpu(attr->length);
		value_off = le16_to_cpu(attr->data.resident.value_offset);
		if (record_pos < 0 || record_pos > U16_MAX ||
			!IS_ALIGNED(record_pos, 8) || value_off > attr_len ||
			old_root_len > attr_len - value_off) {
			err = -EIO;
			goto out;
		}
		record_off = record_pos;
		err = ntfs_index_root_resize_check(mrec, attr, new_root_len);
	}
	if (err == -ENOSPC) {
		err = ntfs_index_root_raise_transacted(handle, icx, new_root);
		goto out;
	}
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index root resize check failed for inode %llu (old value %u, new value %u, error %d).",
			(unsigned long long)icx->idx_ni->mft_no, old_root_len,
			new_root_len, err);
		goto out;
	}

	err = ntfs_index_state_register_home_undo(handle, icx->idx_ni);
	if (err)
		goto out;
	err = ntfs_attr_mft_register_home_undo(handle,
			icx->actx->ntfs_ino, mrec);
	if (err)
		goto out;
	err = ntfs_log_mft_resident_update(handle,
			icx->actx->ntfs_ino->mft_no,
			record_off, value_off, old_root, old_root_len,
			new_root, new_root_len, &operation_lsn);
	if (err)
		goto out;
	err = ntfs_resident_attr_value_resize(mrec, attr, new_root_len);
	if (err)
		goto out;
	memcpy((u8 *)attr + value_off, new_root, new_root_len);
	ntfs_index_root_update_size(icx, new_root_len);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(icx->actx->ntfs_ino);
out:
	kfree(new_root);
	return err;
}

static int ntfs_index_parent_insert_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		int depth, struct index_entry *promoted, s64 right_vcn)
{
	struct index_entry *end_entry;
	struct index_entry *left_end;
	struct index_entry *median;
	struct index_entry *parent_entry;
	struct index_entry *promoted_up = NULL;
	struct index_block *expanded = NULL;
	struct index_block *left = NULL;
	struct index_block *parent_new = NULL;
	struct index_block *parent_old = NULL;
	struct index_block *right = NULL;
	struct index_header *ih;
	s64 new_vcn;
	s64 parent_vcn;
	s64 source_vcn;
	size_t expanded_size;
	u32 allocated;
	u32 entries_off;
	u32 entry_off;
	u32 index_len;
	u32 left_index_len;
	u32 median_len;
	u32 median_off;
	u32 new_index_len;
	u32 right_index_len;
	u32 tail_len;
	u16 end_len;
	u16 promoted_len;
	int err;

	if (!handle || !icx || !promoted || depth < 0 ||
	    depth >= MAX_PARENT_VCN)
		return -EINVAL;
	parent_vcn = icx->parent_vcn[depth];
	if (parent_vcn == VCN_INDEX_ROOT_PARENT) {
		err = ntfs_index_root_insert_median_transacted(handle, icx,
				promoted, right_vcn, icx->parent_pos[depth]);
		if (err && err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted index root parent insertion failed for inode %llu (depth %d, right VCN %lld, error %d).",
				(unsigned long long)icx->idx_ni->mft_no, depth,
				right_vcn, err);
		return err;
	}
	if (parent_vcn < 0 || depth == 0)
		return -EIO;
	promoted_len = le16_to_cpu(promoted->length);
	if (!(promoted->flags & INDEX_ENTRY_NODE) ||
	    promoted->flags & INDEX_ENTRY_END ||
	    promoted_len < sizeof(struct index_entry_header) + sizeof(s64) ||
	    !IS_ALIGNED(promoted_len, 8))
		return -EIO;

	parent_old = kvzalloc(icx->block_size, GFP_NOFS);
	if (!parent_old)
		return -ENOMEM;
	err = ntfs_ib_read(icx, parent_vcn, parent_old);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index parent read failed for inode %llu (depth %d, VCN %lld, error %d).",
			(unsigned long long)icx->idx_ni->mft_no, depth, parent_vcn,
			err);
		goto out;
	}
	ih = &parent_old->index;
	entries_off = le32_to_cpu(ih->entries_offset);
	index_len = le32_to_cpu(ih->index_length);
	allocated = le32_to_cpu(ih->allocated_size);
	if (entries_off < sizeof(struct index_header) ||
	    !IS_ALIGNED(entries_off, 8) || !IS_ALIGNED(index_len, 8) ||
	    !IS_ALIGNED(allocated, 8) || entries_off > index_len ||
	    index_len > allocated ||
	    allocated > icx->block_size -
			offsetof(struct index_block, index) ||
	    ntfs_index_entries_validate(ih, true)) {
		err = -EIO;
		goto out;
	}
	source_vcn = ntfs_ie_get_vcn(promoted);
	err = ntfs_index_parent_entry(ih, icx->parent_pos[depth], source_vcn,
			&parent_entry, &entry_off);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index parent entry lookup failed for inode %llu (depth %d, VCN %lld, error %d).",
			(unsigned long long)icx->idx_ni->mft_no, depth, parent_vcn,
			err);
		goto out;
	}
	if (check_add_overflow(index_len, (u32)promoted_len,
			&new_index_len)) {
		err = -EOVERFLOW;
		goto out;
	}
	if (new_index_len <= allocated) {
		parent_new = ntfs_index_kvmemdup(parent_old, icx->block_size,
				GFP_NOFS);
		if (!parent_new) {
			err = -ENOMEM;
			goto out;
		}
		parent_entry = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(&parent_new->index) + entry_off);
		ntfs_ie_set_vcn(parent_entry, right_vcn);
		ntfs_ie_insert(&parent_new->index, promoted, parent_entry);
		WARN_ON_ONCE(le32_to_cpu(parent_new->index.index_length) !=
				new_index_len);
		err = ntfs_index_block_update_transacted(handle, icx,
				parent_old, parent_new);
		if (err)
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted index parent update failed for inode %llu (depth %d, VCN %lld, error %d).",
				(unsigned long long)icx->idx_ni->mft_no, depth,
				parent_vcn, err);
		goto out;
	}

	if (check_add_overflow((size_t)icx->block_size,
			(size_t)promoted_len, &expanded_size)) {
		err = -EOVERFLOW;
		goto out;
	}
	expanded = kvzalloc(expanded_size, GFP_NOFS);
	if (!expanded) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(expanded, parent_old, icx->block_size);
	expanded->index.allocated_size = cpu_to_le32(allocated + promoted_len);
	parent_entry = (struct index_entry *)
		((u8 *)ntfs_ie_get_first(&expanded->index) + entry_off);
	ntfs_ie_set_vcn(parent_entry, right_vcn);
	ntfs_ie_insert(&expanded->index, promoted, parent_entry);
	if (WARN_ON_ONCE(le32_to_cpu(expanded->index.index_length) !=
			new_index_len)) {
		err = -EIO;
		goto out;
	}
	if (ntfs_index_entries_validate(&expanded->index, true)) {
		err = -EIO;
		goto out;
	}

	median = ntfs_ie_get_median(&expanded->index);
	median_off = (u8 *)median -
		(u8 *)ntfs_ie_get_first(&expanded->index);
	median_len = le16_to_cpu(median->length);
	if (median->flags & INDEX_ENTRY_END ||
	    !(median->flags & INDEX_ENTRY_NODE) ||
	    median_len < sizeof(struct index_entry_header) + sizeof(s64) ||
	    !IS_ALIGNED(median_len, 8) ||
	    median_off > new_index_len - entries_off ||
	    median_len > new_index_len - entries_off - median_off) {
		err = -EIO;
		goto out;
	}
	end_entry = ntfs_ie_get_last(ntfs_ie_get_first(&expanded->index),
			(char *)ntfs_ie_get_end(&expanded->index));
	end_len = le16_to_cpu(end_entry->length);
	if (!(end_entry->flags & INDEX_ENTRY_END) ||
	    !(end_entry->flags & INDEX_ENTRY_NODE) ||
	    end_len < sizeof(struct index_entry_header) + sizeof(s64) ||
	    !IS_ALIGNED(end_len, 8) ||
	    (u8 *)end_entry + end_len != ntfs_ie_get_end(&expanded->index)) {
		err = -EIO;
		goto out;
	}
	left_index_len = entries_off + median_off + end_len;
	tail_len = new_index_len - entries_off - median_off - median_len;
	left = ntfs_index_kvmemdup(parent_old, icx->block_size, GFP_NOFS);
	right = ntfs_ib_alloc(0, icx->block_size, INDEX_NODE);
	promoted_up = kmemdup(median, median_len, GFP_NOFS);
	if (!left || !right || !promoted_up) {
		err = -ENOMEM;
		goto out;
	}
	if (left_index_len > allocated ||
	    le32_to_cpu(right->index.entries_offset) + tail_len >
			le32_to_cpu(right->index.allocated_size)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	memcpy(ntfs_ie_get_first(&left->index),
			ntfs_ie_get_first(&expanded->index), median_off);
	left_end = (struct index_entry *)
		((u8 *)left + offsetof(struct index_block, index) +
		 entries_off + median_off);
	memcpy(left_end, end_entry, end_len);
	ntfs_ie_set_vcn(left_end, ntfs_ie_get_vcn(median));
	left->index.index_length = cpu_to_le32(left_index_len);
	memcpy(ntfs_ie_get_first(&right->index), ntfs_ie_get_next(median),
			tail_len);
	right_index_len = le32_to_cpu(right->index.entries_offset) + tail_len;
	right->index.index_length = cpu_to_le32(right_index_len);
	ntfs_ie_set_vcn(promoted_up, parent_vcn);

	err = ntfs_index_split_allocate_vcn_transacted(handle, icx, &new_vcn);
	if (err) {
		if (err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted index parent split VCN allocation failed for inode %llu (depth %d, parent VCN %lld, error %d).",
				(unsigned long long)icx->idx_ni->mft_no, depth, parent_vcn,
				err);
		goto out;
	}
	right->index_block_vcn = cpu_to_le64(new_vcn);
	err = ntfs_index_block_initialize_transacted(handle, icx, right);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index parent split block initialization failed for inode %llu (depth %d, VCN %lld, error %d).",
			(unsigned long long)icx->idx_ni->mft_no, depth, new_vcn, err);
		goto out;
	}
	err = ntfs_index_parent_insert_transacted(handle, icx, depth - 1,
			promoted_up, new_vcn);
	if (err) {
		if (err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted index parent recursive insertion failed for inode %llu (depth %d, parent VCN %lld, new VCN %lld, error %d).",
				(unsigned long long)icx->idx_ni->mft_no, depth, parent_vcn,
				new_vcn, err);
		goto out;
	}
	err = ntfs_index_block_update_transacted(handle, icx, parent_old, left);
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index parent left update failed for inode %llu (depth %d, VCN %lld, error %d).",
			(unsigned long long)icx->idx_ni->mft_no, depth, parent_vcn,
			err);
out:
	kfree(promoted_up);
	kvfree(right);
	kvfree(parent_new);
	kvfree(left);
	kvfree(expanded);
	kvfree(parent_old);
	return err;
}

static int ntfs_index_internal_block_split_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		int depth, struct index_block *old_ib,
		struct index_block *expanded)
{
	struct index_entry *end_entry;
	struct index_entry *left_end;
	struct index_entry *median;
	struct index_entry *promoted = NULL;
	struct index_block *left = NULL;
	struct index_block *right = NULL;
	s64 new_vcn;
	s64 old_vcn;
	u32 allocated;
	u32 entries_off;
	u32 left_index_len;
	u32 median_len;
	u32 median_off;
	u32 new_index_len;
	u32 right_index_len;
	u32 tail_len;
	u16 end_len;
	int err;

	if (!handle || !icx || !old_ib || !expanded || depth < 1 ||
	    depth >= MAX_PARENT_VCN)
		return -EINVAL;
	old_vcn = le64_to_cpu(old_ib->index_block_vcn);
	allocated = le32_to_cpu(old_ib->index.allocated_size);
	entries_off = le32_to_cpu(old_ib->index.entries_offset);
	new_index_len = le32_to_cpu(expanded->index.index_length);
	if (old_vcn < 0 ||
	    le64_to_cpu(expanded->index_block_vcn) != old_vcn ||
	    (old_ib->index.flags & NODE_MASK) != INDEX_NODE ||
	    (expanded->index.flags & NODE_MASK) != INDEX_NODE ||
	    entries_off != le32_to_cpu(expanded->index.entries_offset) ||
	    entries_off < sizeof(struct index_header) ||
	    !IS_ALIGNED(entries_off, 8) || !IS_ALIGNED(allocated, 8) ||
	    allocated > icx->block_size -
			offsetof(struct index_block, index) ||
	    new_index_len <= allocated ||
	    ntfs_index_entries_validate(&old_ib->index, true) ||
	    ntfs_index_entries_validate(&expanded->index, true))
		return -EIO;

	median = ntfs_ie_get_median(&expanded->index);
	median_off = (u8 *)median -
		(u8 *)ntfs_ie_get_first(&expanded->index);
	median_len = le16_to_cpu(median->length);
	if (median->flags & INDEX_ENTRY_END ||
	    !(median->flags & INDEX_ENTRY_NODE) ||
	    median_len < sizeof(struct index_entry_header) + sizeof(s64) ||
	    !IS_ALIGNED(median_len, 8) ||
	    median_off > new_index_len - entries_off ||
	    median_len > new_index_len - entries_off - median_off)
		return -EIO;
	end_entry = ntfs_ie_get_last(ntfs_ie_get_first(&expanded->index),
			(char *)ntfs_ie_get_end(&expanded->index));
	end_len = le16_to_cpu(end_entry->length);
	if (!(end_entry->flags & INDEX_ENTRY_END) ||
	    !(end_entry->flags & INDEX_ENTRY_NODE) ||
	    end_len < sizeof(struct index_entry_header) + sizeof(s64) ||
	    !IS_ALIGNED(end_len, 8) ||
	    (u8 *)end_entry + end_len != ntfs_ie_get_end(&expanded->index))
		return -EIO;

	left_index_len = entries_off + median_off + end_len;
	tail_len = new_index_len - entries_off - median_off - median_len;
	left = ntfs_index_kvmemdup(old_ib, icx->block_size, GFP_NOFS);
	right = ntfs_ib_alloc(0, icx->block_size, INDEX_NODE);
	promoted = kmemdup(median, median_len, GFP_NOFS);
	if (!left || !right || !promoted) {
		err = -ENOMEM;
		goto out;
	}
	if (left_index_len > allocated ||
	    le32_to_cpu(right->index.entries_offset) + tail_len >
			le32_to_cpu(right->index.allocated_size)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	memcpy(ntfs_ie_get_first(&left->index),
			ntfs_ie_get_first(&expanded->index), median_off);
	left_end = (struct index_entry *)
		((u8 *)left + offsetof(struct index_block, index) +
		 entries_off + median_off);
	memcpy(left_end, end_entry, end_len);
	ntfs_ie_set_vcn(left_end, ntfs_ie_get_vcn(median));
	left->index.index_length = cpu_to_le32(left_index_len);
	memcpy(ntfs_ie_get_first(&right->index), ntfs_ie_get_next(median),
			tail_len);
	right_index_len = le32_to_cpu(right->index.entries_offset) + tail_len;
	right->index.index_length = cpu_to_le32(right_index_len);
	ntfs_ie_set_vcn(promoted, old_vcn);

	err = ntfs_index_split_allocate_vcn_transacted(handle, icx, &new_vcn);
	if (err)
		goto out;
	right->index_block_vcn = cpu_to_le64(new_vcn);
	err = ntfs_index_block_initialize_transacted(handle, icx, right);
	if (err)
		goto out;
	err = ntfs_index_parent_insert_transacted(handle, icx, depth - 1,
			promoted, new_vcn);
	if (err)
		goto out;
	err = ntfs_index_block_update_transacted(handle, icx, old_ib, left);
out:
	kfree(promoted);
	kvfree(right);
	kvfree(left);
	return err;
}

static int ntfs_index_leaf_split_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		struct index_entry *new_entry)
{
	struct index_entry *left_end;
	struct index_entry *left_insert;
	struct index_entry *median;
	struct index_entry *promoted = NULL;
	struct index_entry *right_insert;
	struct index_block *left = NULL;
	struct index_block *right = NULL;
	struct index_header *source_ih;
	s64 new_vcn;
	s64 source_byte_pos;
	u32 block_allocated;
	u32 entries_off;
	u32 insert_off;
	u32 left_index_len;
	u32 median_len;
	u32 median_off;
	u32 old_entries_len;
	u32 promoted_len;
	u32 right_insert_off;
	u32 right_index_len;
	u32 tail_len;
	u16 entry_len;
	u16 source_attr_off;
	int err;

	if (!handle || !icx || !new_entry || !icx->actx || !icx->ir ||
	    icx->pindex < 1)
		return -EOPNOTSUPP;
	err = ntfs_index_allocation_metadata(icx, &source_ih,
			&source_byte_pos, &source_attr_off);
	if (err)
		return err;
	if ((source_ih->flags & NODE_MASK) != LEAF_NODE)
		return -EOPNOTSUPP;
	if (ntfs_index_entries_validate(source_ih, false))
		return -EIO;
	entry_len = le16_to_cpu(new_entry->length);
	if (entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8) ||
	    new_entry->flags & (INDEX_ENTRY_NODE | INDEX_ENTRY_END))
		return -EINVAL;

	entries_off = le32_to_cpu(source_ih->entries_offset);
	old_entries_len = le32_to_cpu(source_ih->index_length) - entries_off;
	block_allocated = le32_to_cpu(source_ih->allocated_size);
	insert_off = (u8 *)icx->entry -
		(u8 *)ntfs_ie_get_first(source_ih);
	median = ntfs_ie_get_median(source_ih);
	median_off = (u8 *)median - (u8 *)ntfs_ie_get_first(source_ih);
	median_len = le16_to_cpu(median->length);
	if (median->flags & (INDEX_ENTRY_NODE | INDEX_ENTRY_END) ||
	    median_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(median_len, 8) || median_off > old_entries_len ||
	    median_len > old_entries_len - median_off ||
	    insert_off > old_entries_len ||
	    check_add_overflow(median_len, (u32)sizeof(s64),
			&promoted_len) || promoted_len > U16_MAX) {
		err = -EIO;
		goto out;
	}

	left = ntfs_index_kvmemdup(icx->ib, icx->block_size, GFP_NOFS);
	right = ntfs_ib_alloc(0, icx->block_size, LEAF_NODE);
	promoted = kzalloc(promoted_len, GFP_NOFS);
	if (!left || !right || !promoted) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(promoted, median, median_len);
	promoted->length = cpu_to_le16(promoted_len);
	promoted->flags |= INDEX_ENTRY_NODE;
	ntfs_ie_set_vcn(promoted, le64_to_cpu(icx->ib->index_block_vcn));

	left_end = ntfs_ie_get_last(ntfs_ie_get_first(&left->index),
			(char *)ntfs_ie_get_end(&left->index));
	if (!(left_end->flags & INDEX_ENTRY_END) ||
	    le16_to_cpu(left_end->length) < sizeof(struct index_entry_header)) {
		err = -EIO;
		goto out;
	}
	memmove((u8 *)ntfs_ie_get_first(&left->index) + median_off, left_end,
			le16_to_cpu(left_end->length));
	left_index_len = entries_off + median_off +
		le16_to_cpu(left_end->length);
	left->index.index_length = cpu_to_le32(left_index_len);

	tail_len = old_entries_len - median_off - median_len;
	if (le32_to_cpu(right->index.entries_offset) + tail_len >
	    le32_to_cpu(right->index.allocated_size)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	memcpy(ntfs_ie_get_first(&right->index),
			(u8 *)ntfs_ie_get_first(source_ih) + median_off + median_len,
			tail_len);
	right_index_len = le32_to_cpu(right->index.entries_offset) + tail_len;
	right->index.index_length = cpu_to_le32(right_index_len);

	if (insert_off <= median_off) {
		if (entry_len > block_allocated - left_index_len) {
			err = -EOPNOTSUPP;
			goto out;
		}
		left_insert = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(&left->index) + insert_off);
		ntfs_ie_insert(&left->index, new_entry, left_insert);
	} else {
		right_insert_off = insert_off - median_off - median_len;
		if (right_insert_off > tail_len ||
		    entry_len > le32_to_cpu(right->index.allocated_size) -
				right_index_len) {
			err = -EOPNOTSUPP;
			goto out;
		}
		right_insert = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(&right->index) +
			 right_insert_off);
		ntfs_ie_insert(&right->index, new_entry, right_insert);
	}

	err = ntfs_index_split_allocate_vcn_transacted(handle, icx, &new_vcn);
	if (err) {
		if (err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted index leaf split VCN allocation failed for inode %llu (error %d).",
				(unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	right->index_block_vcn = cpu_to_le64(new_vcn);
	err = ntfs_index_block_initialize_transacted(handle, icx, right);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index leaf split block initialization failed for inode %llu (VCN %lld, error %d).",
			(unsigned long long)icx->idx_ni->mft_no, new_vcn, err);
		goto out;
	}
	err = ntfs_index_parent_insert_transacted(handle, icx,
			icx->pindex - 1, promoted, new_vcn);
	if (err) {
		if (err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted index leaf split parent insertion failed for inode %llu (VCN %lld, error %d).",
				(unsigned long long)icx->idx_ni->mft_no, new_vcn, err);
		goto out;
	}
	err = ntfs_index_block_update_transacted(handle, icx, icx->ib, left);
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index leaf split left block update failed for inode %llu (VCN %lld, error %d).",
			(unsigned long long)icx->idx_ni->mft_no, new_vcn, err);
out:
	kfree(promoted);
	kvfree(right);
	kvfree(left);
	return err;
}

static int ntfs_index_allocation_add_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		struct index_entry *ie)
{
	struct index_header *ih;
	u32 index_len;
	u32 allocated_size;
	u32 new_index_len;
	u64 operation_lsn;
	u64 byte_pos;
	u16 attr_off;
	u16 entry_len;
	int err;

	if (!handle || !ie)
		return -EINVAL;
	entry_len = le16_to_cpu(ie->length);
	if (entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8) ||
	    le16_to_cpu(ie->key_length) >
			entry_len - sizeof(struct index_entry_header) ||
	    (ie->flags & (INDEX_ENTRY_NODE | INDEX_ENTRY_END)))
		return -EINVAL;
	err = ntfs_index_allocation_metadata(icx, &ih, &byte_pos, &attr_off);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index allocation metadata failed for inode %llu (error %d).",
			(unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}

	index_len = le32_to_cpu(ih->index_length);
	allocated_size = le32_to_cpu(ih->allocated_size);
	if (check_add_overflow(index_len, (u32)entry_len, &new_index_len))
		return -EOVERFLOW;
	if (new_index_len > allocated_size) {
		err = ntfs_index_leaf_split_transacted(handle, icx, ie);
		if (err && err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted index allocation leaf split failed for inode %llu (index length %u, allocated %u, entry %u, error %d).",
				(unsigned long long)icx->idx_ni->mft_no, index_len,
				allocated_size, entry_len, err);
		return err;
	}

	err = ntfs_log_index_allocation_add(handle, VFS_I(icx->ia_ni),
			icx->block_size, byte_pos, attr_off, ie, entry_len,
			&operation_lsn);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index allocation journal append failed for inode %llu (VCN %lld, error %d).",
			(unsigned long long)icx->idx_ni->mft_no,
			le64_to_cpu(icx->ib->index_block_vcn), err);
		return err;
	}
	err = ntfs_index_block_register_home_undo(handle, icx);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index allocation undo registration failed for inode %llu (error %d).",
			(unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}

	ntfs_ie_insert(ih, ie, icx->entry);
	WARN_ON_ONCE(le32_to_cpu(ih->index_length) != new_index_len);
	icx->ib->lsn = cpu_to_le64(operation_lsn);
	err = ntfs_icx_ib_write(icx);
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted index allocation block write failed for inode %llu (VCN %lld, error %d).",
			(unsigned long long)icx->idx_ni->mft_no,
			le64_to_cpu(icx->ib->index_block_vcn), err);
	return err;
}

static int ntfs_index_single_leaf_remove_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx);
static int ntfs_index_leaf_balance_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		bool *handled);

static int ntfs_index_allocation_remove_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx)
{
	struct index_header *ih;
	u32 index_len;
	u32 new_index_len;
	u64 operation_lsn;
	u64 byte_pos;
	u16 attr_off;
	u16 entry_len;
	bool handled;
	int err;

	if (!handle)
		return -EINVAL;
	err = ntfs_index_allocation_metadata(icx, &ih, &byte_pos, &attr_off);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index leaf metadata validation failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}
	if (icx->entry->flags & (INDEX_ENTRY_NODE | INDEX_ENTRY_END)) {
		err = -EOPNOTSUPP;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index leaf entry has invalid flags for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return -EOPNOTSUPP;
	}
	if (ntfs_ih_one_entry(ih)) {
		err = ntfs_index_single_leaf_remove_transacted(handle, icx);
		if (err)
			ntfs_error(icx->idx_ni->vol->sb,
				   "Single-leaf index removal failed for inode %llu (error %d).",
				   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}
	err = ntfs_index_leaf_balance_transacted(handle, icx, &handled);
	if (err || handled) {
		if (err)
			ntfs_error(icx->idx_ni->vol->sb,
				   "Index leaf balancing failed for inode %llu (error %d).",
				   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}

	entry_len = le16_to_cpu(icx->entry->length);
	index_len = le32_to_cpu(ih->index_length);
	if (index_len < entry_len) {
		err = -EIO;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index leaf length underflow for inode %llu (index %u entry %u, error %d).",
			   (unsigned long long)icx->idx_ni->mft_no,
			   index_len, entry_len, err);
		return -EIO;
	}
	new_index_len = index_len - entry_len;

	err = ntfs_log_index_allocation_delete(handle, VFS_I(icx->ia_ni),
			icx->block_size, byte_pos, attr_off, icx->entry, entry_len,
			&operation_lsn);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index leaf delete journal failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}
	err = ntfs_index_block_register_home_undo(handle, icx);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index leaf delete undo registration failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}

	ntfs_ie_delete(ih, icx->entry);
	WARN_ON_ONCE(le32_to_cpu(ih->index_length) != new_index_len);
	icx->ib->lsn = cpu_to_le64(operation_lsn);
	err = ntfs_icx_ib_write(icx);
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index leaf delete write failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
	return err;
}

static int ntfs_index_root_metadata(struct ntfs_index_context *icx,
		struct mft_record **mrec_out, struct attr_record **attr_out,
		struct index_header **ih_out, u16 *record_off_out,
		u16 *attr_off_out)
{
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_header *ih;
	u32 value_off, value_len, attr_len;
	u32 entries_off, index_len, allocated_size;
	u32 record_used, record_allocated;
	u32 index_base, first_entry, used_end;
	u16 current_entry_len;
	ptrdiff_t record_off, attr_off;

	if (!icx || !icx->idx_ni || !icx->entry)
		return -EINVAL;
	if (!icx->is_in_root)
		return -EOPNOTSUPP;
	if (!icx->ir || !icx->actx || !icx->actx->mrec ||
	    !icx->actx->attr || !icx->actx->ntfs_ino)
		return -EIO;
	mrec = icx->actx->mrec;
	attr = icx->actx->attr;
	if (attr->type != AT_INDEX_ROOT || attr->non_resident)
		return -EIO;

	record_off = (u8 *)attr - (u8 *)mrec;
	attr_off = (u8 *)icx->entry - (u8 *)attr;
	if (record_off < 0 || record_off > U16_MAX ||
	    !IS_ALIGNED(record_off, 8) || attr_off < 0 || attr_off > U16_MAX)
		return -EIO;

	record_used = le32_to_cpu(mrec->bytes_in_use);
	record_allocated = le32_to_cpu(mrec->bytes_allocated);
	attr_len = le32_to_cpu(attr->length);
	if (record_used > record_allocated || record_off > record_used ||
	    !IS_ALIGNED(attr_len, 8) ||
	    attr_len > record_used - record_off)
		return -EIO;

	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (value_off > attr_len || value_len > attr_len - value_off ||
	    value_len < sizeof(struct index_root) ||
	    icx->ir != (struct index_root *)((u8 *)attr + value_off))
		return -EIO;

	ih = &icx->ir->index;
	if ((ih->flags & NODE_MASK) != SMALL_INDEX)
		return -EOPNOTSUPP;
	entries_off = le32_to_cpu(ih->entries_offset);
	index_len = le32_to_cpu(ih->index_length);
	allocated_size = le32_to_cpu(ih->allocated_size);
	if (!IS_ALIGNED(entries_off, 8) || !IS_ALIGNED(index_len, 8) ||
	    index_len != allocated_size || entries_off > index_len ||
	    allocated_size != value_len - offsetof(struct index_root, index))
		return -EIO;

	index_base = value_off + offsetof(struct index_root, index);
	current_entry_len = le16_to_cpu(icx->entry->length);
	if (check_add_overflow(index_base, entries_off, &first_entry) ||
	    check_add_overflow(index_base, index_len, &used_end) ||
	    first_entry > used_end || attr_off < first_entry ||
	    attr_off > used_end || used_end > attr_len ||
	    used_end - attr_off < sizeof(struct index_entry_header) ||
	    current_entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(current_entry_len, 8) ||
	    current_entry_len > used_end - attr_off)
		return -EIO;

	*mrec_out = mrec;
	*attr_out = attr;
	*ih_out = ih;
	*record_off_out = record_off;
	*attr_off_out = attr_off;
	return 0;
}

static void ntfs_index_root_update_size(struct ntfs_index_context *icx,
		u32 value_len)
{
	icx->idx_ni->data_size = value_len;
	icx->idx_ni->initialized_size = value_len;
	if (icx->idx_ni->zeroed_size < value_len)
		icx->idx_ni->zeroed_size = value_len;
	icx->idx_ni->allocated_size = ALIGN(value_len, 8);
	i_size_write(VFS_I(icx->idx_ni), value_len);
}

/*
 * Refresh the root after resident attributes move or grow.
 * Attribute-list growth changes the MFT layout, and root relocation changes
 * the owning record and list reference, so cached pointers must be reacquired.
 */
static int ntfs_index_root_context_refresh(struct ntfs_index_context *icx)
{
	struct attr_record *attr;
	int err;

	if (!icx || !icx->idx_ni)
		return -EINVAL;
	if (icx->actx) {
		ntfs_attr_put_search_ctx(icx->actx);
		icx->actx = NULL;
	}
	icx->ir = NULL;
	icx->actx = ntfs_attr_get_search_ctx(icx->idx_ni, NULL);
	if (!icx->actx)
		return -ENOMEM;
	err = ntfs_attr_lookup(AT_INDEX_ROOT, icx->name, icx->name_len,
			CASE_SENSITIVE, 0, NULL, 0, icx->actx);
	if (err)
		goto err_out;
	attr = icx->actx->attr;
	if (!attr || attr->type != AT_INDEX_ROOT || attr->non_resident)
		goto err_eio;
	if (le16_to_cpu(attr->data.resident.value_offset) >
			le32_to_cpu(attr->length) ||
		le32_to_cpu(attr->data.resident.value_length) <
			sizeof(struct index_root) ||
		le32_to_cpu(attr->data.resident.value_length) >
			le32_to_cpu(attr->length) -
			le16_to_cpu(attr->data.resident.value_offset))
		goto err_eio;
	icx->ir = (struct index_root *)((u8 *)attr +
			le16_to_cpu(attr->data.resident.value_offset));
	return 0;

err_eio:
	err = -EIO;
err_out:
	ntfs_attr_put_search_ctx(icx->actx);
	icx->actx = NULL;
	icx->ir = NULL;
	return err;
}

/* Return whether a resident root value can grow in its current MFT record. */
static int ntfs_index_root_resize_check(const struct mft_record *mrec,
		const struct attr_record *attr, u32 new_value_len)
{
	u32 attr_len;
	u32 new_attr_len;
	u32 used;
	u32 allocated;
	u32 new_used;
	u16 value_off;

	if (!mrec || !attr || attr->type != AT_INDEX_ROOT || attr->non_resident)
		return -EINVAL;
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	if (!IS_ALIGNED(attr_len, 8) || value_off > attr_len ||
		used > allocated || attr_len > used ||
		check_add_overflow((u32)value_off, new_value_len, &new_attr_len))
		return -EIO;
	new_attr_len = ALIGN(new_attr_len, 8);
	if (new_attr_len <= attr_len)
		return 0;
	if (check_add_overflow(used - attr_len, new_attr_len, &new_used))
		return -EOVERFLOW;
	if (new_used > allocated)
		return -ENOSPC;
	/* Keep the base-record root headroom rule as ntfs_attr_record_resize(). */
	if (!le64_to_cpu(mrec->base_mft_record) && allocated >= 120 &&
		allocated - new_used < 120 &&
		allocated - used >= 120)
		return -ENOSPC;
	return 0;
}

/* Move a full resident root to an extent before growing it in a transaction. */
static int ntfs_index_root_move_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx)
{
	struct ntfs_inode *base_ni;
	struct ntfs_inode *target_ni = NULL;
	struct mft_record *target_mrec = NULL;
	int err;

	if (!handle || !icx || !icx->idx_ni || !icx->actx ||
		!icx->actx->attr || icx->actx->attr->type != AT_INDEX_ROOT)
		return -EINVAL;
	base_ni = NInoAttr(icx->idx_ni) ? icx->idx_ni->ext.base_ntfs_ino :
		icx->idx_ni;
	if (!base_ni)
		return -EINVAL;
	if (!NInoAttrList(base_ni)) {
		/* Publish the initial list before moving the root itself. */
		ntfs_attr_put_search_ctx(icx->actx);
		icx->actx = NULL;
		icx->ir = NULL;
		err = ntfs_inode_add_attrlist_transacted(handle, base_ni);
		if (err)
			return err;
		err = ntfs_index_root_context_refresh(icx);
		if (err)
			return err;
	}
	if (icx->actx->ntfs_ino != base_ni)
		return 0;
	if (!icx->actx->al_entry)
		return -EOPNOTSUPP;
	err = ntfs_mft_record_alloc_transacted(handle, base_ni->vol,
			&target_ni, base_ni, &target_mrec);
	if (err)
		return err;
	err = ntfs_attr_record_move_to_new_extent_transacted(handle,
			icx->actx, target_ni, target_mrec, NULL, 0);
	unmap_mft_record(target_ni);
	if (err)
		return err;
	return ntfs_index_root_context_refresh(icx);
}

static int ntfs_index_root_reparent_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		struct index_entry *new_entry, struct mft_record *mrec,
		struct attr_record *attr, u16 record_off)
{
	struct index_entry *block_entry;
	struct index_entry *root_entry;
	struct index_block *ib = NULL;
	struct index_root *new_root = NULL;
	struct index_root *old_root = icx->ir;
	u8 bitmap[8] = { };
	u64 operation_lsn;
	u32 block_index_len;
	u32 entry_pos;
	u32 entries_off;
	u32 new_root_len;
	u32 old_root_len;
	u32 root_buffer_len;
	u32 block_allocated;
	ptrdiff_t insertion_pos;
	ptrdiff_t record_pos;
	u16 entry_len;
	u16 value_off;
	int err;

	if (!old_root || !icx->entry || !icx->actx ||
	    icx->block_size < NTFS_BLOCK_SIZE ||
	    icx->block_size > U16_MAX ||
	    !is_power_of_2(icx->block_size) ||
	    ntfs_attr_exist(icx->idx_ni, AT_INDEX_ALLOCATION, icx->name,
			icx->name_len) ||
	    ntfs_attr_exist(icx->idx_ni, AT_BITMAP, icx->name,
			icx->name_len))
		return -EOPNOTSUPP;

	entry_len = le16_to_cpu(new_entry->length);
	entries_off = le32_to_cpu(old_root->index.entries_offset);
	old_root_len = le32_to_cpu(attr->data.resident.value_length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	insertion_pos = (u8 *)icx->entry -
		(u8 *)ntfs_ie_get_first(&old_root->index);
	if (insertion_pos < 0 || insertion_pos > U32_MAX ||
	    insertion_pos > le32_to_cpu(old_root->index.index_length) -
			entries_off)
		return -EIO;
	entry_pos = insertion_pos;

	ib = ntfs_ir_to_ib(old_root, 0);
	if (!ib) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index reparent could not build VCN 0 block for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, -ENOMEM);
		return -ENOMEM;
	}
	block_index_len = le32_to_cpu(ib->index.index_length);
	block_allocated = le32_to_cpu(ib->index.allocated_size);
	if (block_index_len > block_allocated ||
	    entry_len > block_allocated - block_index_len) {
		err = -EOPNOTSUPP;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index reparent cannot fit VCN 0 entry for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	block_entry = (struct index_entry *)
		((u8 *)ntfs_ie_get_first(&ib->index) + entry_pos);
	ntfs_ie_insert(&ib->index, new_entry, block_entry);

	if (check_add_overflow(entries_off,
			(u32)sizeof(struct index_entry_header) + sizeof(s64),
			&block_index_len) ||
	    check_add_overflow((u32)offsetof(struct index_root, index),
			block_index_len, &new_root_len) ||
	    new_root_len > U16_MAX || old_root_len > U16_MAX) {
		err = -EOVERFLOW;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index reparent root size overflow for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	err = ntfs_index_root_resize_check(mrec, attr, new_root_len);
	if (err == -ENOSPC && !mrec->base_mft_record) {
		err = ntfs_index_root_move_transacted(handle, icx);
		if (err)
			goto out;
		attr = icx->actx ? icx->actx->attr : NULL;
		mrec = icx->actx ? icx->actx->mrec : NULL;
		old_root = icx->ir;
		if (!attr || !mrec || !old_root || attr->type != AT_INDEX_ROOT ||
		    attr->non_resident ||
		    le32_to_cpu(attr->data.resident.value_length) != old_root_len ||
		    old_root != (struct index_root *)((u8 *)attr +
				le16_to_cpu(attr->data.resident.value_offset))) {
			err = -EIO;
			goto out;
		}
		record_pos = (u8 *)attr - (u8 *)mrec;
		value_off = le16_to_cpu(attr->data.resident.value_offset);
		if (record_pos < 0 || record_pos > U16_MAX ||
		    !IS_ALIGNED(record_pos, 8) ||
		    value_off > le32_to_cpu(attr->length) ||
		    old_root_len > le32_to_cpu(attr->length) - value_off) {
			err = -EIO;
			goto out;
		}
		record_off = record_pos;
		err = ntfs_index_root_resize_check(mrec, attr, new_root_len);
	}
	if (err)
		goto out;
	root_buffer_len = max(old_root_len, new_root_len);
	new_root = kzalloc(root_buffer_len, GFP_NOFS);
	if (!new_root) {
		err = -ENOMEM;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index reparent root allocation failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	memcpy(new_root, old_root, old_root_len);
	ntfs_ir_nill(new_root);
	root_entry = ntfs_ie_get_first(&new_root->index);
	root_entry->flags |= INDEX_ENTRY_NODE;
	root_entry->length = cpu_to_le16(sizeof(struct index_entry_header) +
			sizeof(s64));
	ntfs_ie_set_vcn(root_entry, 0);
	new_root->index.flags = LARGE_INDEX;
	new_root->index.index_length = cpu_to_le32(block_index_len);
	new_root->index.allocated_size = cpu_to_le32(block_index_len);

	err = ntfs_index_state_register_home_undo(handle, icx->idx_ni);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index reparent state undo registration failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	icx->ia_ni = ntfs_ia_open(icx, icx->idx_ni);
	if (!icx->ia_ni) {
		err = -ENOENT;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index reparent could not open index allocation for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	err = ntfs_index_inode_state_register_home_undo(handle, icx->ia_ni);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index reparent allocation state undo registration failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	err = ntfs_attr_mft_register_home_undo(handle,
			icx->actx->ntfs_ino, mrec);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index root undo registration failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	err = ntfs_log_mft_resident_update(handle,
			icx->actx->ntfs_ino->mft_no,
			record_off, value_off, old_root, old_root_len,
			new_root, new_root_len, &operation_lsn);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index root journal failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	err = ntfs_resident_attr_value_resize(mrec, attr, new_root_len);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index root resize failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	memcpy((u8 *)attr + value_off, new_root, new_root_len);
	ntfs_index_root_update_size(icx, new_root_len);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(icx->actx->ntfs_ino);

	ntfs_attr_put_search_ctx(icx->actx);
	icx->actx = NULL;
	icx->ir = NULL;
	icx->entry = NULL;

	err = ntfs_attr_add_transacted(handle, icx->idx_ni,
			AT_INDEX_ALLOCATION, icx->name, icx->name_len, NULL, 0);
	if (err) {
		if (err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				   "Initial index reparent failed at index allocation attribute for inode %llu (error %d).",
				   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	err = ntfs_attr_add_transacted(handle, icx->idx_ni, AT_BITMAP,
			icx->name, icx->name_len, bitmap, sizeof(bitmap));
	if (err) {
		if (err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				   "Initial index reparent failed at index bitmap attribute for inode %llu (error %d).",
				   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}

	/*
	 * The index inode was opened before the new attribute was added.  It can
	 * therefore be a cached inode from an earlier allocation, rather than the
	 * empty stream just created above.
	 */
	err = ntfs_index_allocation_reset_empty_transacted(handle, icx->ia_ni);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index reparent could not refresh the allocation inode for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	/* The inode was opened before the new on-disk attribute existed. */
	NInoSetNonResident(icx->ia_ni);
	NInoSetIndexAllocPresent(icx->ia_ni);
	icx->ia_ni->type = AT_INDEX_ALLOCATION;
	err = ntfs_index_allocation_extend_transacted(handle, icx,
			icx->block_size);
	if (err) {
		if (err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				   "Initial index allocation growth failed for inode %llu (error %d).",
				   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	VFS_I(icx->ia_ni)->i_blocks = icx->ia_ni->allocated_size >> 9;
	err = ntfs_index_bitmap_modify_transacted(handle, icx, 0, true);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index bitmap update failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	err = ntfs_index_block_initialize_transacted(handle, icx, ib);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Initial index block initialization failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}

	NInoSetIndexAllocPresent(icx->idx_ni);
	err = 0;
out:
	kfree(new_root);
	kvfree(ib);
	return err;
}

static int ntfs_index_root_add_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx, struct index_entry *ie)
{
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_header *ih;
	u32 record_used, record_allocated, free_space, attr_len, value_len;
	u32 index_len, allocated_size, new_attr_len, new_value_len;
	u32 new_index_len, new_allocated_size;
	u64 operation_lsn;
	u16 record_off, attr_off, entry_len;
	int err;

	if (!handle || !icx || !ie)
		return -EINVAL;
	entry_len = le16_to_cpu(ie->length);
	if (entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8) ||
	    le16_to_cpu(ie->key_length) >
		entry_len - sizeof(struct index_entry_header) ||
	    (ie->flags & (INDEX_ENTRY_NODE | INDEX_ENTRY_END)))
		return -EINVAL;

	err = ntfs_index_lookup(&ie->key, le16_to_cpu(ie->key_length), icx);
	if (!err)
		return -EEXIST;
	if (err != -ENOENT) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted filename index lookup failed for inode %llu (error %d).",
			(unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}

	err = ntfs_index_root_metadata(icx, &mrec, &attr, &ih,
			&record_off, &attr_off);
	if (err && (err != -EOPNOTSUPP || icx->is_in_root)) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted filename index root metadata failed for inode %llu (error %d).",
			(unsigned long long)icx->idx_ni->mft_no, err);
	}
	if (err)
		return err;

	record_used = le32_to_cpu(mrec->bytes_in_use);
	record_allocated = le32_to_cpu(mrec->bytes_allocated);
	free_space = record_allocated - record_used;
	attr_len = le32_to_cpu(attr->length);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	index_len = le32_to_cpu(ih->index_length);
	allocated_size = le32_to_cpu(ih->allocated_size);
	if (check_add_overflow(attr_len, (u32)entry_len, &new_attr_len) ||
	    check_add_overflow(value_len, (u32)entry_len, &new_value_len) ||
	    check_add_overflow(index_len, (u32)entry_len, &new_index_len) ||
	    check_add_overflow(allocated_size, (u32)entry_len,
			&new_allocated_size))
		return -EOVERFLOW;

	if (entry_len > free_space ||
		(entry_len + 120 > free_space && free_space >= 120)) {
		err = ntfs_index_root_reparent_transacted(handle, icx, ie,
				mrec, attr, record_off);
		if (err && err != -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				"Transacted filename index root reparent failed for inode %llu (entry %u, free %u, error %d).",
				(unsigned long long)icx->idx_ni->mft_no, entry_len,
				free_space, err);
		return err;
	}
	if (new_attr_len > U16_MAX || new_value_len > U16_MAX)
		return -E2BIG;

	err = ntfs_index_state_register_home_undo(handle, icx->idx_ni);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted filename index state undo registration failed for inode %llu (error %d).",
			(unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}
	err = ntfs_attr_mft_register_home_undo(handle,
		icx->actx->ntfs_ino, mrec);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted filename index MFT undo registration failed for inode %llu (error %d).",
			(unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}
	err = ntfs_log_index_root_add(handle, icx->actx->ntfs_ino->mft_no,
			record_off, attr_off, ie, entry_len, &operation_lsn);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted filename index root journal failed for inode %llu (error %d).",
			(unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}

	err = ntfs_attr_record_resize(mrec, attr, new_attr_len);
	if (WARN_ON_ONCE(err)) {
		ntfs_error(icx->idx_ni->vol->sb,
			"Transacted filename index root resize failed for inode %llu (new attr length %u, free %u, error %d).",
			(unsigned long long)icx->idx_ni->mft_no, new_attr_len,
			free_space, err);
		return -EIO;
	}
	attr->data.resident.value_length = cpu_to_le32(new_value_len);
	ih->allocated_size = cpu_to_le32(new_allocated_size);
	ntfs_ie_insert(ih, ie, icx->entry);
	WARN_ON_ONCE(le32_to_cpu(ih->index_length) != new_index_len);

	ntfs_index_root_update_size(icx, new_value_len);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(icx->actx->ntfs_ino);
	return 0;
}

/*
 * ntfs_index_add_filename - add filename to directory index
 * @ni:		ntfs inode describing directory to which index add filename
 * @fn:		FILE_NAME attribute to add
 * @mref:	reference of the inode which @fn describes
 */
static int __ntfs_index_add_filename(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, struct file_name_attr *fn, u64 mref)
{
	struct index_entry *ie;
	struct ntfs_index_context *icx;
	int fn_size, ie_size, err;

	ntfs_debug("Entering\n");

	if (!ni || !fn)
		return -EINVAL;

	fn_size = (fn->file_name_length * sizeof(__le16)) +
		sizeof(struct file_name_attr);
	ie_size = (sizeof(struct index_entry_header) + fn_size + 7) & ~7;

	ie = kzalloc(ie_size, GFP_NOFS);
	if (!ie)
		return -ENOMEM;

	ie->data.dir.indexed_file = cpu_to_le64(mref);
	ie->length	 = cpu_to_le16(ie_size);
	ie->key_length	 = cpu_to_le16(fn_size);

	unsafe_memcpy(&ie->key, fn, fn_size,
		      /* "fn_size" was correctly calculated above */);

	icx = ntfs_index_ctx_get(ni, I30, 4);
	if (!icx) {
		err = -ENOMEM;
		goto out;
	}

	if (handle) {
		err = ntfs_index_root_add_transacted(handle, icx, ie);
		if (err == -EOPNOTSUPP && !icx->is_in_root && icx->ib)
			err = ntfs_index_allocation_add_transacted(handle, icx, ie);
	} else
		err = ntfs_ie_add(icx, ie);
	if (err && err != -ENOSPC && handle)
		ntfs_error(ni->vol->sb,
			"Transacted filename index insertion failed for inode %llu (in_root %d, error %d).",
			(unsigned long long)ni->mft_no, icx->is_in_root, err);
	ntfs_index_ctx_put(icx);
out:
	kfree(ie);
	return err;
}

int ntfs_index_add_filename(struct ntfs_inode *ni, struct file_name_attr *fn,
		u64 mref)
{
	return __ntfs_index_add_filename(NULL, ni, fn, mref);
}

int ntfs_index_add_filename_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, struct file_name_attr *fn, u64 mref)
{
	if (!handle)
		return -EINVAL;
	return __ntfs_index_add_filename(handle, ni, fn, mref);
}

int ntfs_index_entry_add_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx, struct index_entry *ie)
{
	int err;

	if (!handle || !icx || !ie)
		return -EINVAL;
	err = ntfs_index_root_add_transacted(handle, icx, ie);
	if (err == -EOPNOTSUPP && !icx->is_in_root && icx->ib)
		err = ntfs_index_allocation_add_transacted(handle, icx, ie);
	return err;
}

static int ntfs_index_root_replace_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		struct index_root *new_root, u32 new_root_len)
{
	struct index_root *old_root;
	struct attr_record *attr;
	struct mft_record *mrec;
	ptrdiff_t record_pos;
	u64 operation_lsn;
	u32 attr_len;
	u32 entries_off;
	u32 index_len;
	u32 new_allocated;
	u32 old_root_len;
	u16 record_off;
	u16 value_off;
	bool node;
	int err;

	if (!handle || !icx || !new_root)
		return -EINVAL;
	attr = icx->actx ? icx->actx->attr : NULL;
	mrec = icx->actx ? icx->actx->mrec : NULL;
	old_root = icx->ir;
	if (!attr || !mrec || !old_root || attr->type != AT_INDEX_ROOT ||
	    attr->non_resident)
		return -EOPNOTSUPP;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	old_root_len = le32_to_cpu(attr->data.resident.value_length);
	entries_off = le32_to_cpu(new_root->index.entries_offset);
	index_len = le32_to_cpu(new_root->index.index_length);
	new_allocated = le32_to_cpu(new_root->index.allocated_size);
	node = (new_root->index.flags & NODE_MASK) == LARGE_INDEX;
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || value_off > attr_len ||
	    old_root_len > attr_len - value_off || old_root_len > U16_MAX ||
	    new_root_len > U16_MAX ||
	    old_root != (struct index_root *)((u8 *)attr + value_off) ||
	    entries_off < sizeof(struct index_header) ||
	    !IS_ALIGNED(entries_off, 8) || !IS_ALIGNED(index_len, 8) ||
	    !IS_ALIGNED(new_allocated, 8) || entries_off > index_len ||
	    index_len > new_allocated ||
	    new_root_len != offsetof(struct index_root, index) +
			new_allocated ||
	    ntfs_index_entries_validate(&new_root->index, node))
		return -EIO;
	err = ntfs_index_root_resize_check(mrec, attr, new_root_len);
	if (err == -ENOSPC && node) {
		err = ntfs_index_root_raise_transacted(handle, icx, new_root);
		if (err)
			ntfs_error(icx->idx_ni->vol->sb,
				   "Index root growth could not fit the resident MFT record and root raise failed for inode %llu (new size %u, error %d).",
				   (unsigned long long)icx->idx_ni->mft_no,
				   new_root_len, err);
		return err;
	}
	if (err) {
		if (err == -ENOSPC)
			ntfs_error(icx->idx_ni->vol->sb,
				   "Resident index root growth does not fit the MFT record for inode %llu (new size %u, error %d).",
				   (unsigned long long)icx->idx_ni->mft_no,
				   new_root_len, err);
		return err;
	}
	record_off = record_pos;
	err = ntfs_index_state_register_home_undo(handle, icx->idx_ni);
	if (err)
		return err;
	err = ntfs_attr_mft_register_home_undo(handle,
			icx->actx->ntfs_ino, mrec);
	if (err)
		return err;
	err = ntfs_log_mft_resident_update(handle,
			icx->actx->ntfs_ino->mft_no,
			record_off, value_off, old_root, old_root_len,
			new_root, new_root_len, &operation_lsn);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root replacement journal update failed for inode %llu (old size %u, new size %u, error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, old_root_len,
			   new_root_len, err);
		return err;
	}
	err = ntfs_resident_attr_value_resize(mrec, attr, new_root_len);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root resident resize failed after preflight for inode %llu (old size %u, new size %u, error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, old_root_len,
			   new_root_len, err);
		return err;
	}
	memcpy((u8 *)attr + value_off, new_root, new_root_len);
	ntfs_index_root_update_size(icx, new_root_len);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(icx->actx->ntfs_ino);
	return 0;
}

static int ntfs_index_root_collapse_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		s64 *retired_vcns, unsigned int *retired_count)
{
	struct index_entry *root_entry;
	struct index_block *child = NULL;
	struct index_header *child_ih;
	struct index_header *root_ih;
	struct index_root *new_root = NULL;
	struct index_root *old_root;
	struct attr_record *attr;
	struct mft_record *mrec;
	s64 child_vcn;
	u32 attr_len;
	u32 child_allocated;
	u32 child_entries_len;
	u32 child_entries_off;
	u32 child_index_len;
	u32 mrec_allocated;
	u32 mrec_used;
	u32 new_allocated;
	u32 new_attr_len;
	u32 new_mrec_used;
	u32 new_root_len;
	u32 old_root_len;
	u32 root_allocated;
	u32 root_entries_off;
	u32 root_index_len;
	u16 value_off;
	unsigned int i;
	bool child_node;
	int err = 0;

	if (!handle || !icx || !retired_vcns || !retired_count)
		return -EINVAL;
	if (*retired_count >= MAX_RETIRED_INDEX_VCNS)
		return 0;
	attr = icx->actx ? icx->actx->attr : NULL;
	mrec = icx->actx ? icx->actx->mrec : NULL;
	old_root = icx->ir;
	if (!attr || !mrec || !old_root ||
	    attr->type != AT_INDEX_ROOT || attr->non_resident)
		return -EIO;
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	old_root_len = le32_to_cpu(attr->data.resident.value_length);
	mrec_used = le32_to_cpu(mrec->bytes_in_use);
	mrec_allocated = le32_to_cpu(mrec->bytes_allocated);
	if (value_off > attr_len || old_root_len > attr_len - value_off ||
	    old_root_len > U16_MAX || mrec_used > mrec_allocated ||
	    old_root != (struct index_root *)((u8 *)attr + value_off))
		return -EIO;
	root_ih = &old_root->index;
	root_entries_off = le32_to_cpu(root_ih->entries_offset);
	root_index_len = le32_to_cpu(root_ih->index_length);
	root_allocated = le32_to_cpu(root_ih->allocated_size);
	/*
	 * Detaching the only child can leafify the root before this helper is
	 * called.  There is then no remaining root parent to collapse. The
	 * retired child is still handled by the caller's bitmap/tail cleanup.
	 */
	if ((root_ih->flags & NODE_MASK) == SMALL_INDEX)
		return 0;
	if ((root_ih->flags & NODE_MASK) != LARGE_INDEX ||
	    root_entries_off < sizeof(struct index_header) ||
	    !IS_ALIGNED(root_entries_off, 8) ||
	    !IS_ALIGNED(root_index_len, 8) ||
	    !IS_ALIGNED(root_allocated, 8) ||
	    root_entries_off > root_index_len ||
	    root_index_len > root_allocated ||
	    old_root_len != offsetof(struct index_root, index) +
			root_allocated ||
	    ntfs_index_entries_validate(root_ih, true))
		return -EIO;
	if (!ntfs_ih_zero_entry(root_ih))
		return 0;
	if (!icx->ia_ni)
		return -EIO;
	root_entry = ntfs_ie_get_first(root_ih);
	child_vcn = ntfs_ie_get_vcn(root_entry);
	if (child_vcn < 0)
		return -EIO;
	for (i = 0; i < *retired_count; i++) {
		if (retired_vcns[i] == child_vcn)
			return -EIO;
	}

	child = kvzalloc(icx->block_size, GFP_NOFS);
	if (!child)
		return -ENOMEM;
	if (ntfs_ib_read(icx, child_vcn, child) ||
	    le64_to_cpu(child->index_block_vcn) != child_vcn) {
		err = -EIO;
		goto out;
	}
	child_ih = &child->index;
	child_entries_off = le32_to_cpu(child_ih->entries_offset);
	child_index_len = le32_to_cpu(child_ih->index_length);
	child_allocated = le32_to_cpu(child_ih->allocated_size);
	child_node = (child_ih->flags & NODE_MASK) == INDEX_NODE;
	if (child_entries_off < sizeof(struct index_header) ||
	    !IS_ALIGNED(child_entries_off, 8) ||
	    !IS_ALIGNED(child_index_len, 8) ||
	    !IS_ALIGNED(child_allocated, 8) ||
	    child_entries_off > child_index_len ||
	    child_index_len > child_allocated ||
	    child_allocated > icx->block_size -
			offsetof(struct index_block, index) ||
	    ntfs_index_entries_validate(child_ih, child_node)) {
		err = -EIO;
		goto out;
	}
	child_entries_len = child_index_len - child_entries_off;
	if (check_add_overflow(root_entries_off, child_entries_len,
			&new_allocated) ||
	    check_add_overflow((u32)offsetof(struct index_root, index),
			new_allocated, &new_root_len) ||
	    new_root_len > U16_MAX ||
	    check_add_overflow((u32)value_off, new_root_len, &new_attr_len))
		goto out;
	new_attr_len = ALIGN(new_attr_len, 8);
	if (new_attr_len > attr_len) {
		if (check_add_overflow(mrec_used, new_attr_len - attr_len,
				&new_mrec_used) || new_mrec_used > mrec_allocated)
			goto out;
		if (new_mrec_used + 120 > mrec_allocated &&
		    mrec_used + 120 <= mrec_allocated)
			goto out;
	}

	new_root = kvzalloc(new_root_len, GFP_NOFS);
	if (!new_root) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(new_root, old_root, offsetof(struct index_root, index) +
			sizeof(struct index_header));
	new_root->index.index_length = cpu_to_le32(new_allocated);
	new_root->index.allocated_size = cpu_to_le32(new_allocated);
	new_root->index.flags = child_node ? LARGE_INDEX : SMALL_INDEX;
	memcpy(ntfs_ie_get_first(&new_root->index),
			ntfs_ie_get_first(child_ih), child_entries_len);
	if (ntfs_index_entries_validate(&new_root->index, child_node)) {
		err = -EIO;
		goto out;
	}
	if (!child_node) {
		err = ntfs_index_state_register_home_undo(handle, icx->idx_ni);
		if (err)
			goto out;
	}
	err = ntfs_index_root_replace_transacted(handle, icx, new_root,
			new_root_len);
	if (err)
		goto out;
	if (!child_node)
		NInoClearIndexAllocPresent(icx->idx_ni);
	retired_vcns[(*retired_count)++] = child_vcn;
out:
	kvfree(new_root);
	kvfree(child);
	return err;
}

static int ntfs_index_leaf_redistribution_pivot(u8 *entries,
		u32 entries_len, u32 entries_off, u32 left_allocated,
		u32 right_allocated, u16 left_end_len, u32 *pivot_off)
{
	struct index_entry *entry;
	u32 best_off = 0;
	u32 best_score = U32_MAX;
	u32 end_off;
	u32 entry_len;
	u32 key_len;
	u32 left_len;
	u32 left_used;
	u32 node_len;
	u32 off = 0;
	u32 right_len;
	u32 right_used;
	u32 score;

	if (!entries || entries_len < sizeof(struct index_entry_header) ||
	    !pivot_off)
		return -EINVAL;
	for (;;) {
		if (off > entries_len - sizeof(struct index_entry_header))
			return -EIO;
		entry = (struct index_entry *)(entries + off);
		entry_len = le16_to_cpu(entry->length);
		key_len = le16_to_cpu(entry->key_length);
		if (entry_len < sizeof(struct index_entry_header) ||
		    !IS_ALIGNED(entry_len, 8) || entry_len > entries_len - off ||
		    entry->flags & INDEX_ENTRY_NODE ||
		    key_len > entry_len - sizeof(struct index_entry_header))
			return -EIO;
		if (entry->flags & INDEX_ENTRY_END) {
			if (key_len || off + entry_len != entries_len)
				return -EIO;
			end_off = off;
			break;
		}
		off += entry_len;
	}

	for (off = 0; off < end_off; off += entry_len) {
		entry = (struct index_entry *)(entries + off);
		entry_len = le16_to_cpu(entry->length);
		if (!off || off + entry_len >= end_off ||
		    check_add_overflow(entry_len, (u32)sizeof(s64), &node_len) ||
		    node_len > U16_MAX)
			continue;
		if (check_add_overflow(entries_off, off, &left_len) ||
		    check_add_overflow(left_len, (u32)left_end_len, &left_len) ||
		    check_add_overflow(entries_off,
			entries_len - off - entry_len, &right_len))
			return -EOVERFLOW;
		if (left_len > left_allocated || right_len > right_allocated)
			continue;
		left_used = left_len - entries_off;
		right_used = right_len - entries_off;
		score = left_used > right_used ? left_used - right_used :
			right_used - left_used;
		if (score < best_score) {
			best_score = score;
			best_off = off;
		}
	}
	if (best_score == U32_MAX)
		return -ENOSPC;
	*pivot_off = best_off;
	return 0;
}

static int ntfs_index_internal_redistribution_pivot(u8 *entries,
		u32 entries_len, u32 entries_off, u32 left_allocated,
		u32 right_allocated, u16 left_end_len, u32 *pivot_off)
{
	struct index_entry *entry;
	u32 best_off = 0;
	u32 best_score = U32_MAX;
	u32 end_off;
	u32 entry_len;
	u32 key_len;
	u32 left_len;
	u32 left_used;
	u32 off = 0;
	u32 right_len;
	u32 right_used;
	u32 score;

	if (!entries || entries_len < sizeof(struct index_entry_header) ||
	    !pivot_off)
		return -EINVAL;
	for (;;) {
		if (off > entries_len - sizeof(struct index_entry_header))
			return -EIO;
		entry = (struct index_entry *)(entries + off);
		entry_len = le16_to_cpu(entry->length);
		key_len = le16_to_cpu(entry->key_length);
		if (entry_len < sizeof(struct index_entry_header) + sizeof(s64) ||
		    !IS_ALIGNED(entry_len, 8) || entry_len > entries_len - off ||
		    !(entry->flags & INDEX_ENTRY_NODE) ||
		    key_len > entry_len - sizeof(struct index_entry_header) -
				sizeof(s64))
			return -EIO;
		if (entry->flags & INDEX_ENTRY_END) {
			if (key_len || off + entry_len != entries_len)
				return -EIO;
			end_off = off;
			break;
		}
		off += entry_len;
	}

	for (off = 0; off < end_off; off += entry_len) {
		entry = (struct index_entry *)(entries + off);
		entry_len = le16_to_cpu(entry->length);
		if (!off || off + entry_len >= end_off)
			continue;
		if (check_add_overflow(entries_off, off, &left_len) ||
		    check_add_overflow(left_len, (u32)left_end_len, &left_len) ||
		    check_add_overflow(entries_off,
			entries_len - off - entry_len, &right_len))
			return -EOVERFLOW;
		if (left_len > left_allocated || right_len > right_allocated)
			continue;
		left_used = left_len - entries_off;
		right_used = right_len - entries_off;
		score = left_used > right_used ? left_used - right_used :
			right_used - left_used;
		if (score < best_score) {
			best_score = score;
			best_off = off;
		}
	}
	if (best_score == U32_MAX)
		return -ENOSPC;
	*pivot_off = best_off;
	return 0;
}

static int ntfs_index_internal_merge_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		int depth, s64 current_vcn, s64 *retired_vcns,
		unsigned int *retired_count)
{
	struct index_entry *left_end;
	struct index_entry *left_end_copy = NULL;
	struct index_entry *next_entry;
	struct index_entry *parent_entry;
	struct index_entry *pivot;
	struct index_entry *promoted = NULL;
	struct index_entry *separator;
	struct index_entry *separator_down = NULL;
	struct index_block *current_ib = NULL;
	struct index_block *left_new = NULL;
	struct index_block *left_old;
	struct index_block *parent_new = NULL;
	struct index_block *parent_old = NULL;
	struct index_block *right_new = NULL;
	struct index_block *right_old;
	struct index_block *sibling = NULL;
	struct index_header *current_ih;
	struct index_header *parent_ih;
	struct index_root *new_root = NULL;
	struct index_root *old_root;
	struct attr_record *attr;
	u8 *combined_entries = NULL;
	size_t parent_buffer_size;
	s64 left_vcn;
	s64 parent_vcn;
	s64 right_vcn;
	s64 sibling_vcn;
	u32 allocated;
	u32 attr_len;
	u32 combined_entries_len;
	u32 combined_len;
	u32 entries_capacity;
	u32 entries_off;
	u32 expanded_allocated;
	u32 index_len;
	u32 left_end_len;
	u32 left_prefix_len;
	u32 new_parent_index_len;
	u32 new_root_len = 0;
	u32 next_off;
	u32 old_root_len = 0;
	u32 parent_allocated;
	u32 parent_delta;
	u32 parent_entries_off;
	u32 parent_index_len;
	u32 pivot_len;
	u32 pivot_off;
	u32 promoted_len;
	u32 right_entries_len;
	u32 right_tail_len;
	u32 separator_off;
	u16 old_separator_len;
	u16 separator_len;
	u16 value_off;
	int entry_count;
	int err = 0;
	int parent_pos;
	bool current_is_left;
	bool fallback_left;
	bool parent_is_root;
	bool parent_split = false;
	bool try_left = false;

	if (!handle || !icx || !retired_vcns || !retired_count ||
	    depth < 1 || depth >= MAX_PARENT_VCN || current_vcn < 0)
		return -EINVAL;
	current_ib = kvzalloc(icx->block_size, GFP_NOFS);
	if (!current_ib)
		return -ENOMEM;
	if (ntfs_ib_read(icx, current_vcn, current_ib)) {
		err = -EIO;
		goto out;
	}
	current_ih = &current_ib->index;
	entries_off = le32_to_cpu(current_ih->entries_offset);
	index_len = le32_to_cpu(current_ih->index_length);
	allocated = le32_to_cpu(current_ih->allocated_size);
	if ((current_ih->flags & NODE_MASK) != INDEX_NODE ||
	    entries_off > index_len || index_len > allocated ||
	    ntfs_index_entries_validate(current_ih, true)) {
		err = -EIO;
		goto out;
	}
	entries_capacity = allocated - entries_off;
	if (index_len - entries_off >= DIV_ROUND_UP(entries_capacity, 2))
		goto out;

	parent_vcn = icx->parent_vcn[depth - 1];
	parent_is_root = parent_vcn == VCN_INDEX_ROOT_PARENT;
	if (!parent_is_root && parent_vcn < 0) {
		err = -EIO;
		goto out;
	}
	if (parent_is_root) {
		attr = icx->actx ? icx->actx->attr : NULL;
		old_root = icx->ir;
		if (!attr || !old_root || attr->non_resident ||
		    attr->type != AT_INDEX_ROOT) {
			err = -EOPNOTSUPP;
			goto out;
		}
		attr_len = le32_to_cpu(attr->length);
		value_off = le16_to_cpu(attr->data.resident.value_offset);
		old_root_len = le32_to_cpu(attr->data.resident.value_length);
		if (value_off > attr_len || old_root_len > U16_MAX ||
		    old_root_len > attr_len - value_off ||
		    old_root != (struct index_root *)((u8 *)attr + value_off)) {
			err = -EIO;
			goto out;
		}
		parent_ih = &old_root->index;
	} else {
		if (depth == 1) {
			err = -EIO;
			goto out;
		}
		parent_old = kvzalloc(icx->block_size, GFP_NOFS);
		if (!parent_old) {
			err = -ENOMEM;
			goto out;
		}
		if (ntfs_ib_read(icx, parent_vcn, parent_old)) {
			err = -EIO;
			goto out;
		}
		parent_ih = &parent_old->index;
	}
	parent_entries_off = le32_to_cpu(parent_ih->entries_offset);
	parent_index_len = le32_to_cpu(parent_ih->index_length);
	parent_allocated = le32_to_cpu(parent_ih->allocated_size);
	if ((parent_ih->flags & NODE_MASK) != INDEX_NODE ||
	    parent_entries_off < sizeof(struct index_header) ||
	    parent_entries_off > parent_index_len ||
	    parent_index_len > parent_allocated ||
	    (parent_is_root &&
	     old_root_len != offsetof(struct index_root, index) +
			parent_allocated) ||
	    (!parent_is_root &&
	     parent_allocated > icx->block_size -
			offsetof(struct index_block, index)) ||
	    ntfs_index_entries_validate(parent_ih, true)) {
		err = -EIO;
		goto out;
	}
	parent_pos = icx->parent_pos[depth - 1];
	err = ntfs_index_parent_entry(parent_ih, parent_pos, current_vcn,
			&parent_entry, NULL);
	if (err)
		goto out;
	entry_count = ntfs_ih_numof_entries(parent_ih);
	if (!entry_count)
		goto out;
	fallback_left = parent_pos > 0 &&
		!(parent_entry->flags & INDEX_ENTRY_END);

select_sibling:
	if (!try_left && !(parent_entry->flags & INDEX_ENTRY_END)) {
		separator = parent_entry;
		next_entry = ntfs_ie_get_next(parent_entry);
		left_vcn = current_vcn;
		right_vcn = ntfs_ie_get_vcn(next_entry);
		current_is_left = true;
	} else {
		separator = ntfs_ie_prev(parent_ih, parent_entry);
		if (!separator)
			goto out;
		next_entry = parent_entry;
		left_vcn = ntfs_ie_get_vcn(separator);
		right_vcn = current_vcn;
		current_is_left = false;
	}
	if (separator->flags & INDEX_ENTRY_END ||
	    !(separator->flags & INDEX_ENTRY_NODE) ||
	    !(next_entry->flags & INDEX_ENTRY_NODE) ||
	    left_vcn < 0 || right_vcn < 0 || left_vcn == right_vcn) {
		err = -EIO;
		goto out;
	}
	separator_off = (u8 *)separator -
		(u8 *)ntfs_ie_get_first(parent_ih);
	next_off = (u8 *)next_entry - (u8 *)ntfs_ie_get_first(parent_ih);
	sibling_vcn = current_is_left ? right_vcn : left_vcn;
	sibling = kvzalloc(icx->block_size, GFP_NOFS);
	if (!sibling) {
		err = -ENOMEM;
		goto out;
	}
	if (ntfs_ib_read(icx, sibling_vcn, sibling) ||
	    (sibling->index.flags & NODE_MASK) != INDEX_NODE ||
	    ntfs_index_entries_validate(&sibling->index, true)) {
		err = -EIO;
		goto out;
	}
	left_old = current_is_left ? current_ib : sibling;
	right_old = current_is_left ? sibling : current_ib;
	if (le64_to_cpu(left_old->index_block_vcn) != left_vcn ||
	    le64_to_cpu(right_old->index_block_vcn) != right_vcn ||
	    le32_to_cpu(left_old->index.entries_offset) !=
			le32_to_cpu(right_old->index.entries_offset)) {
		err = -EIO;
		goto out;
	}
	left_new = ntfs_index_kvmemdup(left_old, icx->block_size, GFP_NOFS);
	separator_down = ntfs_ie_dup(separator);
	if (!left_new || !separator_down) {
		err = -ENOMEM;
		goto out;
	}
	left_end = ntfs_ie_get_last(ntfs_ie_get_first(&left_new->index),
			(char *)ntfs_ie_get_end(&left_new->index));
	left_end_len = le16_to_cpu(left_end->length);
	separator_len = le16_to_cpu(separator_down->length);
	if (!(left_end->flags & INDEX_ENTRY_END) ||
	    !(left_end->flags & INDEX_ENTRY_NODE) ||
	    le32_to_cpu(left_new->index.index_length) <
			le32_to_cpu(left_new->index.entries_offset) + left_end_len) {
		err = -EIO;
		goto out;
	}
	ntfs_ie_set_vcn(separator_down, ntfs_ie_get_vcn(left_end));
	left_prefix_len = le32_to_cpu(left_new->index.index_length) -
		le32_to_cpu(left_new->index.entries_offset) - left_end_len;
	right_entries_len = le32_to_cpu(right_old->index.index_length) -
		le32_to_cpu(right_old->index.entries_offset);
	if (check_add_overflow(le32_to_cpu(left_new->index.entries_offset),
			left_prefix_len, &combined_len) ||
	    check_add_overflow(combined_len, (u32)separator_len,
			&combined_len) ||
	    check_add_overflow(combined_len, right_entries_len,
			&combined_len)) {
		err = -EOVERFLOW;
		goto out;
	}
	if (combined_len > le32_to_cpu(left_new->index.allocated_size)) {
		if (fallback_left && !try_left) {
			try_left = true;
			kfree(separator_down);
			separator_down = NULL;
			kvfree(left_new);
			left_new = NULL;
			kvfree(sibling);
			sibling = NULL;
			goto select_sibling;
		}
		combined_entries_len = combined_len -
			le32_to_cpu(left_new->index.entries_offset);
		combined_entries = kvmalloc(combined_entries_len, GFP_NOFS);
		right_new = ntfs_index_kvmemdup(right_old, icx->block_size,
				GFP_NOFS);
		left_end_copy = kmemdup(left_end, left_end_len, GFP_NOFS);
		if (!combined_entries || !right_new || !left_end_copy) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(combined_entries, ntfs_ie_get_first(&left_new->index),
				left_prefix_len);
		memcpy(combined_entries + left_prefix_len, separator_down,
				separator_len);
		memcpy(combined_entries + left_prefix_len + separator_len,
				ntfs_ie_get_first(&right_old->index),
				right_entries_len);
		old_separator_len = le16_to_cpu(separator->length);
		err = ntfs_index_internal_redistribution_pivot(
				combined_entries, combined_entries_len,
				le32_to_cpu(left_new->index.entries_offset),
				le32_to_cpu(left_new->index.allocated_size),
				le32_to_cpu(right_new->index.allocated_size),
				left_end_len, &pivot_off);
		if (err == -ENOSPC) {
			err = 0;
			goto out;
		}
		if (err)
			goto out;
		pivot = (struct index_entry *)(combined_entries + pivot_off);
		pivot_len = le16_to_cpu(pivot->length);
		promoted_len = max_t(u32, pivot_len, old_separator_len);
		promoted = kzalloc(promoted_len, GFP_NOFS);
		if (!promoted) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(promoted, pivot, pivot_len - sizeof(s64));
		promoted->length = cpu_to_le16(promoted_len);
		promoted->flags |= INDEX_ENTRY_NODE;
		ntfs_ie_set_vcn(promoted, left_vcn);
		ntfs_ie_set_vcn(left_end_copy, ntfs_ie_get_vcn(pivot));

		memcpy(ntfs_ie_get_first(&left_new->index), combined_entries,
				pivot_off);
		memcpy((u8 *)ntfs_ie_get_first(&left_new->index) + pivot_off,
				left_end_copy, left_end_len);
		left_new->index.index_length = cpu_to_le32(
				le32_to_cpu(left_new->index.entries_offset) +
				pivot_off + left_end_len);
		right_tail_len = combined_entries_len - pivot_off - pivot_len;
		memcpy(ntfs_ie_get_first(&right_new->index),
				combined_entries + pivot_off + pivot_len,
				right_tail_len);
		right_new->index.index_length = cpu_to_le32(
				le32_to_cpu(right_new->index.entries_offset) +
				right_tail_len);
		if (ntfs_index_entries_validate(&left_new->index, true) ||
		    ntfs_index_entries_validate(&right_new->index, true)) {
			err = -EIO;
			goto out;
		}

		parent_delta = promoted_len - old_separator_len;
		if (check_add_overflow(parent_index_len, parent_delta,
				&new_parent_index_len)) {
			err = -EOVERFLOW;
			goto out;
		}
		if (parent_is_root) {
			if (check_add_overflow(parent_allocated, parent_delta,
					&expanded_allocated) ||
			    check_add_overflow(old_root_len, parent_delta,
					&new_root_len) || new_root_len > U16_MAX) {
				err = -EOVERFLOW;
				goto out;
			}
			new_root = kvzalloc(new_root_len, GFP_NOFS);
			if (!new_root) {
				err = -ENOMEM;
				goto out;
			}
			memcpy(new_root, old_root, old_root_len);
			parent_ih = &new_root->index;
			parent_ih->allocated_size =
				cpu_to_le32(expanded_allocated);
		} else {
			if (new_parent_index_len > parent_allocated) {
				if (check_add_overflow(parent_allocated,
						parent_delta, &expanded_allocated) ||
				    check_add_overflow((size_t)icx->block_size,
						(size_t)parent_delta,
						&parent_buffer_size)) {
					err = -EOVERFLOW;
					goto out;
				}
				parent_split = true;
			} else {
				parent_buffer_size = icx->block_size;
			}
			parent_new = kvzalloc(parent_buffer_size, GFP_NOFS);
			if (!parent_new) {
				err = -ENOMEM;
				goto out;
			}
			memcpy(parent_new, parent_old, icx->block_size);
			parent_ih = &parent_new->index;
			if (parent_split)
				parent_ih->allocated_size =
					cpu_to_le32(expanded_allocated);
		}
		separator = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(parent_ih) + separator_off);
		if (le16_to_cpu(separator->length) != old_separator_len) {
			err = -EIO;
			goto out;
		}
		ntfs_ie_delete(parent_ih, separator);
		ntfs_ie_insert(parent_ih, promoted, separator);
		if (WARN_ON_ONCE(le32_to_cpu(parent_ih->index_length) !=
				new_parent_index_len) ||
		    ntfs_index_entries_validate(parent_ih, true)) {
			err = -EIO;
			goto out;
		}

		err = ntfs_index_block_update_transacted(handle, icx, left_old,
				left_new);
		if (err)
			goto out;
		err = ntfs_index_block_update_transacted(handle, icx, right_old,
				right_new);
		if (err)
			goto out;
		if (parent_is_root)
			err = ntfs_index_root_replace_transacted(handle, icx,
					new_root, new_root_len);
		else if (parent_split)
			err = ntfs_index_internal_block_split_transacted(handle,
					icx, depth - 1, parent_old, parent_new);
		else
			err = ntfs_index_block_update_transacted(handle, icx,
					parent_old, parent_new);
		goto out;
	}
	memcpy((u8 *)ntfs_ie_get_first(&left_new->index) + left_prefix_len,
			separator_down, separator_len);
	memcpy((u8 *)ntfs_ie_get_first(&left_new->index) + left_prefix_len +
			separator_len, ntfs_ie_get_first(&right_old->index),
			right_entries_len);
	left_new->index.index_length = cpu_to_le32(combined_len);
	if (ntfs_index_entries_validate(&left_new->index, true)) {
		err = -EIO;
		goto out;
	}

	separator_len = le16_to_cpu(separator->length);
	if (parent_allocated < separator_len ||
	    parent_index_len < separator_len) {
		err = -EIO;
		goto out;
	}
	if (parent_is_root) {
		if (old_root_len < separator_len) {
			err = -EIO;
			goto out;
		}
		new_root_len = old_root_len - separator_len;
		new_root = ntfs_index_kvmemdup(old_root, old_root_len, GFP_NOFS);
		if (!new_root) {
			err = -ENOMEM;
			goto out;
		}
		parent_ih = &new_root->index;
		parent_ih->allocated_size =
			cpu_to_le32(parent_allocated - separator_len);
	} else {
		parent_new = ntfs_index_kvmemdup(parent_old, icx->block_size,
				GFP_NOFS);
		if (!parent_new) {
			err = -ENOMEM;
			goto out;
		}
		parent_ih = &parent_new->index;
	}
	separator = (struct index_entry *)
		((u8 *)ntfs_ie_get_first(parent_ih) + separator_off);
	next_entry = (struct index_entry *)
		((u8 *)ntfs_ie_get_first(parent_ih) + next_off);
	ntfs_ie_set_vcn(next_entry, left_vcn);
	ntfs_ie_delete(parent_ih, separator);
	if (ntfs_index_entries_validate(parent_ih, true)) {
		err = -EIO;
		goto out;
	}
	if (*retired_count >= MAX_RETIRED_INDEX_VCNS) {
		err = -EOVERFLOW;
		goto out;
	}

	err = ntfs_index_block_update_transacted(handle, icx, left_old,
			left_new);
	if (err)
		goto out;
	if (parent_is_root)
		err = ntfs_index_root_replace_transacted(handle, icx, new_root,
				new_root_len);
	else
		err = ntfs_index_block_update_transacted(handle, icx, parent_old,
				parent_new);
	if (err)
		goto out;
	retired_vcns[(*retired_count)++] = right_vcn;
	if (!parent_is_root)
		err = ntfs_index_internal_merge_transacted(handle, icx,
				depth - 1, parent_vcn, retired_vcns,
				retired_count);
out:
	kfree(promoted);
	kfree(left_end_copy);
	kfree(separator_down);
	kvfree(combined_entries);
	kvfree(new_root);
	kvfree(right_new);
	kvfree(left_new);
	kvfree(sibling);
	kvfree(parent_new);
	kvfree(parent_old);
	kvfree(current_ib);
	return err;
}

static int ntfs_index_leaf_balance_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		bool *handled)
{
	struct index_entry *current_entry;
	struct index_entry *left_end;
	struct index_entry *left_end_copy = NULL;
	struct index_entry *next_entry;
	struct index_entry *parent_entry;
	struct index_entry *pivot;
	struct index_entry *promoted = NULL;
	struct index_entry *separator;
	struct index_entry *separator_leaf = NULL;
	struct index_block *left_new = NULL;
	struct index_block *left_old;
	struct index_block *parent_new = NULL;
	struct index_block *parent_old = NULL;
	struct index_block *right_new = NULL;
	struct index_block *right_old;
	struct index_block *sibling = NULL;
	struct index_header *current_ih;
	struct index_header *parent_ih;
	struct index_root *new_root = NULL;
	struct index_root *old_root;
	struct attr_record *attr;
	u8 *combined_entries = NULL;
	ptrdiff_t current_entry_off;
	size_t parent_buffer_size;
	s64 current_vcn;
	s64 left_vcn;
	s64 parent_vcn;
	s64 retired_vcns[MAX_RETIRED_INDEX_VCNS];
	s64 right_vcn;
	s64 sibling_vcn;
	unsigned int i;
	unsigned int retired_count = 0;
	u32 allocated;
	u32 attr_len;
	u32 combined_entries_len;
	u32 combined_len;
	u32 current_entries_off;
	u32 current_index_len;
	u32 current_used_after;
	u32 entries_capacity;
	u32 expanded_allocated;
	u32 left_entries_off;
	u32 left_index_len;
	u32 left_prefix_len;
	u32 new_root_len = 0;
	u32 new_parent_index_len;
	u32 next_off;
	u32 old_root_len = 0;
	u32 parent_allocated;
	u32 parent_delta;
	u32 parent_entries_off;
	u32 parent_index_len;
	u32 pivot_len;
	u32 pivot_off;
	u32 promoted_len;
	u32 right_entries_len;
	u32 right_tail_len;
	u32 separator_off;
	u16 current_entry_len;
	u16 left_end_len;
	u16 old_separator_len;
	u16 separator_len;
	u16 value_off;
	int depth;
	int entry_count;
	int err = 0;
	int parent_pos;
	bool current_is_left;
	bool fallback_left;
	bool parent_is_root;
	bool parent_split = false;
	bool try_left = false;

	if (!handle || !icx || !icx->ib || !icx->entry || !handled ||
	    icx->is_in_root || icx->pindex < 1)
		return -EINVAL;
	*handled = false;
	current_ih = &icx->ib->index;
	if ((current_ih->flags & NODE_MASK) != LEAF_NODE ||
	    ntfs_index_entries_validate(current_ih, false))
		return -EIO;
	current_entries_off = le32_to_cpu(current_ih->entries_offset);
	current_index_len = le32_to_cpu(current_ih->index_length);
	allocated = le32_to_cpu(current_ih->allocated_size);
	current_entry_len = le16_to_cpu(icx->entry->length);
	if (current_index_len < current_entries_off ||
	    current_entry_len > current_index_len - current_entries_off ||
	    allocated < current_index_len)
		return -EIO;
	current_used_after = current_index_len - current_entries_off -
		current_entry_len;
	entries_capacity = allocated - current_entries_off;
	if (current_used_after >= DIV_ROUND_UP(entries_capacity, 2))
		return 0;

	current_vcn = le64_to_cpu(icx->ib->index_block_vcn);
	depth = icx->pindex - 1;
	parent_vcn = icx->parent_vcn[depth];
	parent_is_root = parent_vcn == VCN_INDEX_ROOT_PARENT;
	if (current_vcn < 0 || (!parent_is_root && parent_vcn < 0))
		return -EIO;
	if (parent_is_root) {
		attr = icx->actx ? icx->actx->attr : NULL;
		old_root = icx->ir;
		if (!attr || !old_root || attr->non_resident ||
		    attr->type != AT_INDEX_ROOT) {
			err = -EIO;
			goto out;
		}
		attr_len = le32_to_cpu(attr->length);
		value_off = le16_to_cpu(attr->data.resident.value_offset);
		old_root_len = le32_to_cpu(attr->data.resident.value_length);
		if (value_off > attr_len || old_root_len > U16_MAX ||
		    old_root_len > attr_len - value_off ||
		    old_root != (struct index_root *)((u8 *)attr + value_off)) {
			err = -EIO;
			goto out;
		}
		parent_ih = &old_root->index;
	} else {
		if (depth == 0)
			return -EIO;
		parent_old = kvzalloc(icx->block_size, GFP_NOFS);
		if (!parent_old)
			return -ENOMEM;
		if (ntfs_ib_read(icx, parent_vcn, parent_old)) {
			err = -EIO;
			goto out;
		}
		parent_ih = &parent_old->index;
	}

	parent_allocated = le32_to_cpu(parent_ih->allocated_size);
	parent_entries_off = le32_to_cpu(parent_ih->entries_offset);
	parent_index_len = le32_to_cpu(parent_ih->index_length);
	if ((parent_ih->flags & NODE_MASK) != INDEX_NODE ||
	    parent_entries_off < sizeof(struct index_header) ||
	    !IS_ALIGNED(parent_entries_off, 8) ||
	    !IS_ALIGNED(parent_index_len, 8) ||
	    !IS_ALIGNED(parent_allocated, 8) ||
	    parent_entries_off > parent_index_len ||
	    parent_index_len > parent_allocated ||
	    (parent_is_root &&
	     old_root_len != offsetof(struct index_root, index) +
			parent_allocated) ||
	    (!parent_is_root &&
	     parent_allocated > icx->block_size -
			offsetof(struct index_block, index)) ||
	    ntfs_index_entries_validate(parent_ih, true)) {
		err = -EIO;
		goto out;
	}
	parent_pos = icx->parent_pos[depth];
	err = ntfs_index_parent_entry(parent_ih, parent_pos,
			current_vcn, &parent_entry, NULL);
	if (err)
		goto out;
	entry_count = ntfs_ih_numof_entries(parent_ih);
	if (!entry_count)
		goto out;
	fallback_left = parent_pos > 0 &&
		!(parent_entry->flags & INDEX_ENTRY_END);

select_sibling:
	if (!try_left && !(parent_entry->flags & INDEX_ENTRY_END)) {
		separator = parent_entry;
		next_entry = ntfs_ie_get_next(parent_entry);
		left_vcn = current_vcn;
		right_vcn = ntfs_ie_get_vcn(next_entry);
		current_is_left = true;
	} else {
		separator = ntfs_ie_prev(parent_ih, parent_entry);
		if (!separator)
			goto out;
		next_entry = parent_entry;
		left_vcn = ntfs_ie_get_vcn(separator);
		right_vcn = current_vcn;
		current_is_left = false;
	}
	if (separator->flags & INDEX_ENTRY_END ||
	    !(separator->flags & INDEX_ENTRY_NODE) ||
	    !(next_entry->flags & INDEX_ENTRY_NODE) ||
	    left_vcn < 0 || right_vcn < 0 || left_vcn == right_vcn) {
		err = -EIO;
		goto out;
	}
	separator_off = (u8 *)separator -
		(u8 *)ntfs_ie_get_first(parent_ih);
	next_off = (u8 *)next_entry - (u8 *)ntfs_ie_get_first(parent_ih);
	sibling_vcn = current_is_left ? right_vcn : left_vcn;
	sibling = kvzalloc(icx->block_size, GFP_NOFS);
	if (!sibling) {
		err = -ENOMEM;
		goto out;
	}
	if (ntfs_ib_read(icx, sibling_vcn, sibling) ||
	    (sibling->index.flags & NODE_MASK) != LEAF_NODE ||
	    ntfs_index_entries_validate(&sibling->index, false)) {
		err = -EIO;
		goto out;
	}
	left_old = current_is_left ? icx->ib : sibling;
	right_old = current_is_left ? sibling : icx->ib;
	if (le64_to_cpu(left_old->index_block_vcn) != left_vcn ||
	    le64_to_cpu(right_old->index_block_vcn) != right_vcn ||
	    le32_to_cpu(left_old->index.entries_offset) !=
			le32_to_cpu(right_old->index.entries_offset)) {
		err = -EIO;
		goto out;
	}

	left_new = ntfs_index_kvmemdup(left_old, icx->block_size, GFP_NOFS);
	right_new = ntfs_index_kvmemdup(right_old, icx->block_size, GFP_NOFS);
	separator_leaf = ntfs_ie_dup_novcn(separator);
	if (!left_new || !right_new || !separator_leaf) {
		err = -ENOMEM;
		goto out;
	}
	current_entry_off = (u8 *)icx->entry - (u8 *)icx->ib;
	if (current_entry_off < 0 || current_entry_off > U16_MAX) {
		err = -EIO;
		goto out;
	}
	current_entry = (struct index_entry *)
		((u8 *)(current_is_left ? left_new : right_new) +
		 current_entry_off);
	ntfs_ie_delete(current_is_left ? &left_new->index : &right_new->index,
			current_entry);
	if (ntfs_index_entries_validate(&left_new->index, false) ||
	    ntfs_index_entries_validate(&right_new->index, false)) {
		err = -EIO;
		goto out;
	}

	left_entries_off = le32_to_cpu(left_new->index.entries_offset);
	left_index_len = le32_to_cpu(left_new->index.index_length);
	left_end = ntfs_ie_get_last(ntfs_ie_get_first(&left_new->index),
			(char *)ntfs_ie_get_end(&left_new->index));
	left_end_len = le16_to_cpu(left_end->length);
	separator_len = le16_to_cpu(separator_leaf->length);
	if (!(left_end->flags & INDEX_ENTRY_END) ||
	    left_index_len < left_entries_off + left_end_len) {
		err = -EIO;
		goto out;
	}
	left_prefix_len = left_index_len - left_entries_off - left_end_len;
	right_entries_len = le32_to_cpu(right_new->index.index_length) -
		left_entries_off;
	if (check_add_overflow(left_entries_off, left_prefix_len,
			&combined_len) ||
	    check_add_overflow(combined_len, (u32)separator_len,
			&combined_len) ||
	    check_add_overflow(combined_len, right_entries_len,
			&combined_len)) {
		err = -EOVERFLOW;
		goto out;
	}
	if (combined_len > le32_to_cpu(left_new->index.allocated_size)) {
		if (fallback_left && !try_left) {
			try_left = true;
			kfree(separator_leaf);
			separator_leaf = NULL;
			kvfree(right_new);
			right_new = NULL;
			kvfree(left_new);
			left_new = NULL;
			kvfree(sibling);
			sibling = NULL;
			goto select_sibling;
		}
		combined_entries_len = combined_len - left_entries_off;
		combined_entries = kvmalloc(combined_entries_len, GFP_NOFS);
		left_end_copy = kmemdup(left_end, left_end_len, GFP_NOFS);
		if (!combined_entries || !left_end_copy) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(combined_entries,
				ntfs_ie_get_first(&left_new->index), left_prefix_len);
		memcpy(combined_entries + left_prefix_len, separator_leaf,
				separator_len);
		memcpy(combined_entries + left_prefix_len + separator_len,
				ntfs_ie_get_first(&right_new->index),
				right_entries_len);
		err = ntfs_index_leaf_redistribution_pivot(combined_entries,
				combined_entries_len, left_entries_off,
				le32_to_cpu(left_new->index.allocated_size),
				le32_to_cpu(right_new->index.allocated_size),
				left_end_len, &pivot_off);
		if (err == -ENOSPC) {
			err = 0;
			goto out;
		}
		if (err)
			goto out;
		pivot = (struct index_entry *)(combined_entries + pivot_off);
		pivot_len = le16_to_cpu(pivot->length);
		old_separator_len = le16_to_cpu(separator->length);
		if (check_add_overflow(pivot_len, (u32)sizeof(s64),
				&promoted_len) || promoted_len > U16_MAX) {
			err = -EOVERFLOW;
			goto out;
		}
		promoted_len = max(promoted_len, (u32)old_separator_len);
		promoted = kzalloc(promoted_len, GFP_NOFS);
		if (!promoted) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(promoted, pivot, pivot_len);
		promoted->length = cpu_to_le16(promoted_len);
		promoted->flags |= INDEX_ENTRY_NODE;
		ntfs_ie_set_vcn(promoted, left_vcn);

		memcpy(ntfs_ie_get_first(&left_new->index), combined_entries,
				pivot_off);
		memcpy((u8 *)ntfs_ie_get_first(&left_new->index) + pivot_off,
				left_end_copy, left_end_len);
		left_new->index.index_length = cpu_to_le32(left_entries_off +
				pivot_off + left_end_len);
		right_tail_len = combined_entries_len - pivot_off - pivot_len;
		memcpy(ntfs_ie_get_first(&right_new->index),
				combined_entries + pivot_off + pivot_len,
				right_tail_len);
		right_new->index.index_length = cpu_to_le32(left_entries_off +
				right_tail_len);
		if (ntfs_index_entries_validate(&left_new->index, false) ||
		    ntfs_index_entries_validate(&right_new->index, false)) {
			err = -EIO;
			goto out;
		}

		parent_delta = promoted_len - old_separator_len;
		if (check_add_overflow(parent_index_len, parent_delta,
				&new_parent_index_len)) {
			err = -EOVERFLOW;
			goto out;
		}
		if (parent_is_root) {
			if (check_add_overflow(parent_allocated, parent_delta,
					&expanded_allocated) ||
			    check_add_overflow(old_root_len, parent_delta,
					&new_root_len) || new_root_len > U16_MAX) {
				err = -EOVERFLOW;
				goto out;
			}
			new_root = kvzalloc(new_root_len, GFP_NOFS);
			if (!new_root) {
				err = -ENOMEM;
				goto out;
			}
			memcpy(new_root, old_root, old_root_len);
			parent_ih = &new_root->index;
			parent_ih->allocated_size =
				cpu_to_le32(expanded_allocated);
		} else {
			if (new_parent_index_len > parent_allocated) {
				if (check_add_overflow(parent_allocated,
						parent_delta, &expanded_allocated) ||
				    check_add_overflow((size_t)icx->block_size,
						(size_t)parent_delta,
						&parent_buffer_size)) {
					err = -EOVERFLOW;
					goto out;
				}
				parent_split = true;
			} else {
				parent_buffer_size = icx->block_size;
			}
			parent_new = kvzalloc(parent_buffer_size, GFP_NOFS);
			if (!parent_new) {
				err = -ENOMEM;
				goto out;
			}
			memcpy(parent_new, parent_old, icx->block_size);
			parent_ih = &parent_new->index;
			if (parent_split)
				parent_ih->allocated_size =
					cpu_to_le32(expanded_allocated);
		}
		separator = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(parent_ih) + separator_off);
		ntfs_ie_delete(parent_ih, separator);
		ntfs_ie_insert(parent_ih, promoted, separator);
		if (WARN_ON_ONCE(le32_to_cpu(parent_ih->index_length) !=
				new_parent_index_len) ||
		    ntfs_index_entries_validate(parent_ih, true)) {
			err = -EIO;
			goto out;
		}

		err = ntfs_index_block_update_transacted(handle, icx, left_old,
				left_new);
		if (err)
			goto out;
		err = ntfs_index_block_update_transacted(handle, icx, right_old,
				right_new);
		if (err)
			goto out;
		if (parent_is_root)
			err = ntfs_index_root_replace_transacted(handle, icx,
					new_root, new_root_len);
		else if (parent_split)
			err = ntfs_index_internal_block_split_transacted(handle,
					icx, depth, parent_old, parent_new);
		else
			err = ntfs_index_block_update_transacted(handle, icx,
					parent_old, parent_new);
		if (!err)
			*handled = true;
		goto out;
	}
	memcpy((u8 *)ntfs_ie_get_first(&left_new->index) + left_prefix_len,
			separator_leaf, separator_len);
	memcpy((u8 *)ntfs_ie_get_first(&left_new->index) + left_prefix_len +
			separator_len, ntfs_ie_get_first(&right_new->index),
			right_entries_len);
	left_new->index.index_length = cpu_to_le32(combined_len);
	if (ntfs_index_entries_validate(&left_new->index, false)) {
		err = -EIO;
		goto out;
	}

	separator_len = le16_to_cpu(separator->length);
	if (parent_allocated < separator_len ||
	    parent_index_len < separator_len) {
		err = -EIO;
		goto out;
	}
	if (parent_is_root) {
		if (old_root_len < separator_len) {
			err = -EIO;
			goto out;
		}
		new_root_len = old_root_len - separator_len;
		new_root = ntfs_index_kvmemdup(old_root, old_root_len, GFP_NOFS);
		if (!new_root) {
			err = -ENOMEM;
			goto out;
		}
		parent_ih = &new_root->index;
		parent_ih->allocated_size =
			cpu_to_le32(parent_allocated - separator_len);
	} else {
		parent_new = ntfs_index_kvmemdup(parent_old, icx->block_size,
				GFP_NOFS);
		if (!parent_new) {
			err = -ENOMEM;
			goto out;
		}
		parent_ih = &parent_new->index;
	}
	separator = (struct index_entry *)
		((u8 *)ntfs_ie_get_first(parent_ih) + separator_off);
	next_entry = (struct index_entry *)
		((u8 *)ntfs_ie_get_first(parent_ih) + next_off);
	ntfs_ie_set_vcn(next_entry, left_vcn);
	ntfs_ie_delete(parent_ih, separator);
	if (ntfs_index_entries_validate(parent_ih, true)) {
		err = -EIO;
		goto out;
	}

	err = ntfs_index_block_update_transacted(handle, icx, left_old,
			left_new);
	if (err)
		goto out;
	if (parent_is_root)
		err = ntfs_index_root_replace_transacted(handle, icx, new_root,
				new_root_len);
	else
		err = ntfs_index_block_update_transacted(handle, icx, parent_old,
				parent_new);
	if (err)
		goto out;
	retired_vcns[retired_count++] = right_vcn;
	if (!parent_is_root) {
		err = ntfs_index_internal_merge_transacted(handle, icx, depth,
				parent_vcn, retired_vcns, &retired_count);
		if (err)
			goto out;
	}
	err = ntfs_index_root_collapse_transacted(handle, icx, retired_vcns,
			&retired_count);
	if (err)
		goto out;
	for (i = 0; i < retired_count; i++) {
		err = ntfs_index_bitmap_modify_transacted(handle, icx,
				retired_vcns[i], false);
		if (err)
			goto out;
	}
	err = ntfs_index_allocation_truncate_tail_transacted(handle, icx);
	if (err)
		goto out;
	err = ntfs_index_empty_allocation_remove_transacted(handle, icx);
	if (err)
		goto out;
	*handled = true;
out:
	kfree(promoted);
	kfree(left_end_copy);
	kfree(separator_leaf);
	kvfree(combined_entries);
	kvfree(new_root);
	kvfree(right_new);
	kvfree(left_new);
	kvfree(sibling);
	kvfree(parent_new);
	kvfree(parent_old);
	return err;
}

static int ntfs_index_detach_empty_child_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx,
		int depth, s64 child_vcn, s64 *retired_vcns,
		unsigned int *retired_count, struct index_entry **roam_out)
{
	struct index_entry *parent_entry;
	struct index_entry *previous;
	struct index_entry *roam = NULL;
	struct index_block *parent_new = NULL;
	struct index_block *parent_old = NULL;
	struct index_header *ih;
	struct index_root *new_root = NULL;
	struct index_root *old_root;
	struct attr_record *attr;
	u32 allocated;
	u32 entries_off;
	u32 entry_off;
	u32 index_len;
	u32 new_root_len;
	u32 old_root_len;
	u32 previous_off;
	u16 removed_len;
	s64 parent_vcn;
	bool leafify = false;
	int err;

	if (!handle || !icx || depth < 0 || depth >= MAX_PARENT_VCN ||
	    child_vcn < 0 || !retired_vcns || !retired_count || !roam_out)
		return -EINVAL;
	if (*retired_count >= MAX_RETIRED_INDEX_VCNS)
		return -EOVERFLOW;
	retired_vcns[(*retired_count)++] = child_vcn;
	parent_vcn = icx->parent_vcn[depth];
	if (parent_vcn == VCN_INDEX_ROOT_PARENT) {
		attr = icx->actx ? icx->actx->attr : NULL;
		old_root = icx->ir;
		if (!attr || !old_root || attr->non_resident ||
		    attr->type != AT_INDEX_ROOT)
			return -EOPNOTSUPP;
		old_root_len = le32_to_cpu(attr->data.resident.value_length);
		if (old_root_len > U16_MAX || old_root_len < sizeof(*old_root))
			return -EIO;
		ih = &old_root->index;
		entries_off = le32_to_cpu(ih->entries_offset);
		index_len = le32_to_cpu(ih->index_length);
		allocated = le32_to_cpu(ih->allocated_size);
		if ((ih->flags & NODE_MASK) != LARGE_INDEX ||
		    entries_off < sizeof(struct index_header) ||
		    !IS_ALIGNED(entries_off, 8) || !IS_ALIGNED(index_len, 8) ||
		    !IS_ALIGNED(allocated, 8) || entries_off > index_len ||
		    index_len > allocated ||
		    old_root_len != offsetof(struct index_root, index) +
				allocated ||
		    ntfs_index_entries_validate(ih, true))
			return -EIO;
		err = ntfs_index_parent_entry(ih, icx->parent_pos[depth],
				child_vcn, &parent_entry, &entry_off);
		if (err)
			return err;
		new_root = ntfs_index_kvmemdup(old_root, old_root_len, GFP_NOFS);
		if (!new_root)
			return -ENOMEM;
		ih = &new_root->index;
		parent_entry = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(ih) + entry_off);
		if (!(parent_entry->flags & INDEX_ENTRY_END)) {
			roam = ntfs_ie_dup_novcn(parent_entry);
			if (!roam) {
				err = -ENOMEM;
				goto root_out;
			}
			removed_len = le16_to_cpu(parent_entry->length);
			ntfs_ie_delete(ih, parent_entry);
		} else if (ntfs_ih_zero_entry(ih)) {
			removed_len = sizeof(s64);
			if (le16_to_cpu(parent_entry->length) <
					sizeof(struct index_entry_header) + removed_len) {
				err = -EIO;
				goto root_out;
			}
			parent_entry->flags &= ~INDEX_ENTRY_NODE;
			parent_entry->length = cpu_to_le16(
					le16_to_cpu(parent_entry->length) - removed_len);
			ih->index_length = cpu_to_le32(index_len - removed_len);
			ih->flags = SMALL_INDEX;
			leafify = true;
		} else {
			previous = ntfs_ie_prev(ih, parent_entry);
			if (!previous) {
				err = -EIO;
				goto root_out;
			}
			roam = ntfs_ie_dup_novcn(previous);
			if (!roam) {
				err = -ENOMEM;
				goto root_out;
			}
			removed_len = le16_to_cpu(previous->length);
			ntfs_ie_set_vcn(parent_entry, ntfs_ie_get_vcn(previous));
			ntfs_ie_delete(ih, previous);
		}
		if (allocated < removed_len || old_root_len < removed_len) {
			err = -EIO;
			goto root_out;
		}
		ih->allocated_size = cpu_to_le32(allocated - removed_len);
		new_root_len = old_root_len - removed_len;
		if (leafify) {
			err = ntfs_index_state_register_home_undo(handle,
					icx->idx_ni);
			if (err)
				goto root_out;
		}
		err = ntfs_index_root_replace_transacted(handle, icx, new_root,
				new_root_len);
		if (err)
			goto root_out;
		if (leafify)
			NInoClearIndexAllocPresent(icx->idx_ni);
		*roam_out = roam;
		roam = NULL;
root_out:
		kfree(roam);
		kvfree(new_root);
		return err;
	}
	if (parent_vcn < 0 || depth == 0)
		return -EIO;

	parent_old = kvzalloc(icx->block_size, GFP_NOFS);
	if (!parent_old)
		return -ENOMEM;
	if (ntfs_ib_read(icx, parent_vcn, parent_old)) {
		err = -EIO;
		goto out;
	}
	ih = &parent_old->index;
	entries_off = le32_to_cpu(ih->entries_offset);
	index_len = le32_to_cpu(ih->index_length);
	allocated = le32_to_cpu(ih->allocated_size);
	if ((ih->flags & NODE_MASK) != INDEX_NODE ||
	    entries_off < sizeof(struct index_header) ||
	    !IS_ALIGNED(entries_off, 8) || !IS_ALIGNED(index_len, 8) ||
	    !IS_ALIGNED(allocated, 8) || entries_off > index_len ||
	    index_len > allocated ||
	    allocated > icx->block_size -
			offsetof(struct index_block, index) ||
	    ntfs_index_entries_validate(ih, true)) {
		err = -EIO;
		goto out;
	}
	err = ntfs_index_parent_entry(ih, icx->parent_pos[depth], child_vcn,
			&parent_entry, &entry_off);
	if (err)
		goto out;
	if ((parent_entry->flags & INDEX_ENTRY_END) &&
	    ntfs_ih_zero_entry(ih)) {
		err = ntfs_index_detach_empty_child_transacted(handle, icx,
				depth - 1, parent_vcn, retired_vcns,
				retired_count, roam_out);
		goto out;
	}

	parent_new = ntfs_index_kvmemdup(parent_old, icx->block_size, GFP_NOFS);
	if (!parent_new) {
		err = -ENOMEM;
		goto out;
	}
	ih = &parent_new->index;
	parent_entry = (struct index_entry *)
		((u8 *)ntfs_ie_get_first(ih) + entry_off);
	if (!(parent_entry->flags & INDEX_ENTRY_END)) {
		roam = ntfs_ie_dup_novcn(parent_entry);
		if (!roam) {
			err = -ENOMEM;
			goto out;
		}
		ntfs_ie_delete(ih, parent_entry);
	} else {
		previous = ntfs_ie_prev(ih, parent_entry);
		if (!previous) {
			err = -EIO;
			goto out;
		}
		previous_off = (u8 *)previous - (u8 *)ntfs_ie_get_first(ih);
		roam = ntfs_ie_dup_novcn(previous);
		if (!roam) {
			err = -ENOMEM;
			goto out;
		}
		parent_entry = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(ih) + entry_off);
		previous = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(ih) + previous_off);
		ntfs_ie_set_vcn(parent_entry, ntfs_ie_get_vcn(previous));
		ntfs_ie_delete(ih, previous);
	}
	err = ntfs_index_block_update_transacted(handle, icx, parent_old,
			parent_new);
	if (err)
		goto out;
	*roam_out = roam;
	roam = NULL;
out:
	kfree(roam);
	kvfree(parent_new);
	kvfree(parent_old);
	return err;
}

static int ntfs_index_single_leaf_remove_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx)
{
	struct index_entry *roam = NULL;
	s64 retired_vcns[MAX_RETIRED_INDEX_VCNS];
	s64 source_vcn;
	unsigned int retired_count = 0;
	unsigned int i;
	int err;

	if (!handle || !icx || !icx->ib || icx->pindex < 1)
		return -EINVAL;
	source_vcn = le64_to_cpu(icx->ib->index_block_vcn);
	if (source_vcn < 0) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Single-leaf removal found invalid source VCN for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, -EIO);
		return -EIO;
	}
	err = ntfs_index_detach_empty_child_transacted(handle, icx,
			icx->pindex - 1, source_vcn, retired_vcns,
			&retired_count, &roam);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Single-leaf parent detach failed for inode %llu (source VCN %lld, error %d).",
			   (unsigned long long)icx->idx_ni->mft_no,
			   (long long)source_vcn, err);
		goto out;
	}
	/* Keep retired VCNs allocated until reinsertion can no longer reuse them. */
	if (roam) {
		ntfs_index_ctx_reinit(icx);
		err = ntfs_index_root_add_transacted(handle, icx, roam);
		if (err == -EOPNOTSUPP && !icx->is_in_root && icx->ib)
			err = ntfs_index_allocation_add_transacted(handle, icx,
					roam);
		if (err) {
			ntfs_error(icx->idx_ni->vol->sb,
				   "Single-leaf roam reinsertion failed for inode %llu (error %d).",
				   (unsigned long long)icx->idx_ni->mft_no, err);
			goto out;
		}
	}
	err = ntfs_index_root_collapse_transacted(handle, icx, retired_vcns,
			&retired_count);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Single-leaf root collapse failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	for (i = 0; i < retired_count; i++) {
		err = ntfs_index_bitmap_modify_transacted(handle, icx,
				retired_vcns[i], false);
		if (err) {
			ntfs_error(icx->idx_ni->vol->sb,
				   "Single-leaf bitmap clear failed for inode %llu (VCN %lld, error %d).",
				   (unsigned long long)icx->idx_ni->mft_no,
				   (long long)retired_vcns[i], err);
			goto out;
		}
	}
	err = ntfs_index_allocation_truncate_tail_transacted(handle, icx);
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			   "Single-leaf allocation tail truncation failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
	else
		err = ntfs_index_empty_allocation_remove_transacted(handle, icx);
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			   "Single-leaf empty allocation removal failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
out:
	kfree(roam);
	return err;
}

static int ntfs_ih_takeout(struct ntfs_index_context *icx, struct index_header *ih,
		struct index_entry *ie, struct index_block *ib)
{
	struct index_entry *ie_roam;
	int freed_space;
	bool full;
	int ret = 0;

	ntfs_debug("Entering\n");

	full = ih->index_length == ih->allocated_size;
	ie_roam = ntfs_ie_dup_novcn(ie);
	if (!ie_roam)
		return -ENOMEM;

	ntfs_ie_delete(ih, ie);

	if (ntfs_icx_parent_vcn(icx) == VCN_INDEX_ROOT_PARENT) {
		/*
		 * Recover the space which may have been freed
		 * while deleting an entry from root index
		 */
		freed_space = le32_to_cpu(ih->allocated_size) -
			le32_to_cpu(ih->index_length);
		if (full && (freed_space > 0) && !(freed_space & 7)) {
			ntfs_ir_truncate(icx, le32_to_cpu(ih->index_length));
			/* do nothing if truncation fails */
		}

		mark_mft_record_dirty(icx->actx->ntfs_ino);
	} else {
		ret = ntfs_ib_write(icx, ib);
		if (ret)
			goto out;
	}

	ntfs_index_ctx_reinit(icx);

	ret = ntfs_ie_add(icx, ie_roam);
out:
	kfree(ie_roam);
	return ret;
}

/*
 *  Used if an empty index block to be deleted has END entry as the parent
 *  in the INDEX_ROOT which is the only one there.
 */
static void ntfs_ir_leafify(struct ntfs_index_context *icx, struct index_header *ih)
{
	struct index_entry *ie;

	ntfs_debug("Entering\n");

	ie = ntfs_ie_get_first(ih);
	ie->flags &= ~INDEX_ENTRY_NODE;
	ie->length = cpu_to_le16(le16_to_cpu(ie->length) - sizeof(s64));

	ih->index_length = cpu_to_le32(le32_to_cpu(ih->index_length) - sizeof(s64));
	ih->flags &= ~LARGE_INDEX;
	NInoClearIndexAllocPresent(icx->idx_ni);

	/* Not fatal error */
	ntfs_ir_truncate(icx, le32_to_cpu(ih->index_length));
}

/*
 *  Used if an empty index block to be deleted has END entry as the parent
 *  in the INDEX_ROOT which is not the only one there.
 */
static int ntfs_ih_reparent_end(struct ntfs_index_context *icx, struct index_header *ih,
		struct index_block *ib)
{
	struct index_entry *ie, *ie_prev;

	ntfs_debug("Entering\n");

	ie = ntfs_ie_get_by_pos(ih, ntfs_icx_parent_pos(icx));
	ie_prev = ntfs_ie_prev(ih, ie);
	if (!ie_prev)
		return -EIO;
	ntfs_ie_set_vcn(ie, ntfs_ie_get_vcn(ie_prev));

	return ntfs_ih_takeout(icx, ih, ie_prev, ib);
}

static int ntfs_index_rm_leaf(struct ntfs_index_context *icx)
{
	struct index_block *ib = NULL;
	struct index_header *parent_ih;
	struct index_entry *ie;
	int ret;

	ntfs_debug("pindex: %d\n", icx->pindex);

	ret = ntfs_icx_parent_dec(icx);
	if (ret)
		return ret;

	ret = ntfs_ibm_clear(icx, icx->parent_vcn[icx->pindex + 1]);
	if (ret)
		return ret;

	if (ntfs_icx_parent_vcn(icx) == VCN_INDEX_ROOT_PARENT)
		parent_ih = &icx->ir->index;
	else {
		ib = kvzalloc(icx->block_size, GFP_NOFS);
		if (!ib)
			return -ENOMEM;

		ret = ntfs_ib_read(icx, ntfs_icx_parent_vcn(icx), ib);
		if (ret)
			goto out;

		parent_ih = &ib->index;
	}

	ie = ntfs_ie_get_by_pos(parent_ih, ntfs_icx_parent_pos(icx));
	if (!ntfs_ie_end(ie)) {
		ret = ntfs_ih_takeout(icx, parent_ih, ie, ib);
		goto out;
	}

	if (ntfs_ih_zero_entry(parent_ih)) {
		if (ntfs_icx_parent_vcn(icx) == VCN_INDEX_ROOT_PARENT) {
			ntfs_ir_leafify(icx, parent_ih);
			goto out;
		}

		ret = ntfs_index_rm_leaf(icx);
		goto out;
	}

	ret = ntfs_ih_reparent_end(icx, parent_ih, ib);
out:
	kvfree(ib);
	return ret;
}

static int ntfs_index_rm_node(struct ntfs_index_context *icx)
{
	int entry_pos, pindex;
	s64 vcn;
	struct index_block *ib = NULL;
	struct index_entry *ie_succ, *ie, *entry = icx->entry;
	struct index_header *ih;
	u32 new_size;
	int delta, ret;

	ntfs_debug("Entering\n");

	if (!icx->ia_ni) {
		icx->ia_ni = ntfs_ia_open(icx, icx->idx_ni);
		if (!icx->ia_ni)
			return -EINVAL;
	}

	ib = kvzalloc(icx->block_size, GFP_NOFS);
	if (!ib)
		return -ENOMEM;

	ie_succ = ntfs_ie_get_next(icx->entry);
	entry_pos = icx->parent_pos[icx->pindex]++;
	pindex = icx->pindex;
descend:
	vcn = ntfs_ie_get_vcn(ie_succ);
	ret = ntfs_ib_read(icx, vcn, ib);
	if (ret)
		goto out;

	ie_succ = ntfs_ie_get_first(&ib->index);

	ret = ntfs_icx_parent_inc(icx);
	if (ret)
		goto out;

	icx->parent_vcn[icx->pindex] = vcn;
	icx->parent_pos[icx->pindex] = 0;

	if ((ib->index.flags & NODE_MASK) == INDEX_NODE)
		goto descend;

	if (ntfs_ih_zero_entry(&ib->index)) {
		ret = -EIO;
		ntfs_error(icx->idx_ni->vol->sb, "Empty index block");
		goto out;
	}

	ie = ntfs_ie_dup(ie_succ);
	if (!ie) {
		ret = -ENOMEM;
		goto out;
	}

	ret = ntfs_ie_add_vcn(&ie);
	if (ret)
		goto out2;

	ntfs_ie_set_vcn(ie, ntfs_ie_get_vcn(icx->entry));

	if (icx->is_in_root)
		ih = &icx->ir->index;
	else
		ih = &icx->ib->index;

	delta = le16_to_cpu(ie->length) - le16_to_cpu(icx->entry->length);
	new_size = le32_to_cpu(ih->index_length) + delta;
	if (delta > 0) {
		if (icx->is_in_root) {
			ret = ntfs_ir_make_space(icx, new_size);
			if (ret != 0)
				goto out2;

			ih = &icx->ir->index;
			entry = ntfs_ie_get_by_pos(ih, entry_pos);

		} else if (new_size > le32_to_cpu(ih->allocated_size)) {
			icx->pindex = pindex;
			ret = ntfs_ib_split(icx, icx->ib);
			if (!ret)
				ret = -EAGAIN;
			goto out2;
		}
	}

	ntfs_ie_delete(ih, entry);
	ntfs_ie_insert(ih, ie, entry);

	if (icx->is_in_root)
		ret = ntfs_ir_truncate(icx, new_size);
	else
		ret = ntfs_icx_ib_write(icx);
	if (ret)
		goto out2;

	ntfs_ie_delete(&ib->index, ie_succ);

	if (ntfs_ih_zero_entry(&ib->index))
		ret = ntfs_index_rm_leaf(icx);
	else
		ret = ntfs_ib_write(icx, ib);

out2:
	kfree(ie);
out:
	kvfree(ib);
	return ret;
}

/*
 * ntfs_index_rm - remove entry from the index
 * @icx:	index context describing entry to delete
 *
 * Delete entry described by @icx from the index. Index context is always
 * reinitialized after use of this function, so it can be used for index
 * lookup once again.
 */
int ntfs_index_rm(struct ntfs_index_context *icx)
{
	struct index_header *ih;
	int ret = 0;

	ntfs_debug("Entering\n");

	if (!icx || (!icx->ib && !icx->ir) || ntfs_ie_end(icx->entry)) {
		ret = -EINVAL;
		goto err_out;
	}
	if (icx->is_in_root)
		ih = &icx->ir->index;
	else
		ih = &icx->ib->index;

	if (icx->entry->flags & INDEX_ENTRY_NODE) {
		ret = ntfs_index_rm_node(icx);
		if (ret)
			goto err_out;
	} else if (icx->is_in_root || !ntfs_ih_one_entry(ih)) {
		ntfs_ie_delete(ih, icx->entry);

		if (icx->is_in_root)
			ret = ntfs_ir_truncate(icx, le32_to_cpu(ih->index_length));
		else
			ret = ntfs_icx_ib_write(icx);
		if (ret)
			goto err_out;
	} else {
		ret = ntfs_index_rm_leaf(icx);
		if (ret)
			goto err_out;
	}

	return 0;
err_out:
	return ret;
}

static int ntfs_index_root_remove_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx)
{
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_header *ih;
	u32 attr_len, value_len, index_len, allocated_size;
	u32 new_value_len, new_index_len, new_allocated_size;
	u64 operation_lsn;
	u16 record_off, attr_off, entry_len;
	int err;

	if (!handle)
		return -EINVAL;
	err = ntfs_index_root_metadata(icx, &mrec, &attr, &ih,
			&record_off, &attr_off);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root metadata validation failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}
	if (icx->entry->flags & (INDEX_ENTRY_NODE | INDEX_ENTRY_END)) {
		err = -EOPNOTSUPP;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root entry has invalid flags for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return -EOPNOTSUPP;
	}

	entry_len = le16_to_cpu(icx->entry->length);
	attr_len = le32_to_cpu(attr->length);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	index_len = le32_to_cpu(ih->index_length);
	allocated_size = le32_to_cpu(ih->allocated_size);
	if (entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8) || attr_len < entry_len ||
	    value_len < entry_len || index_len < entry_len ||
	    allocated_size < entry_len) {
		err = -EIO;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root entry length underflow for inode %llu (entry %u value %u index %u allocated %u, error %d).",
			   (unsigned long long)icx->idx_ni->mft_no,
			   entry_len, value_len, index_len, allocated_size, err);
		return -EIO;
	}
	new_value_len = value_len - entry_len;
	new_index_len = index_len - entry_len;
	new_allocated_size = allocated_size - entry_len;

	err = ntfs_index_state_register_home_undo(handle, icx->idx_ni);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root delete state undo registration failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}
	err = ntfs_attr_mft_register_home_undo(handle,
			icx->actx->ntfs_ino, mrec);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root delete undo registration failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}
	err = ntfs_log_index_root_delete(handle, icx->actx->ntfs_ino->mft_no,
			record_off, attr_off, icx->entry, entry_len,
			&operation_lsn);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root delete journal failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return err;
	}

	ntfs_ie_delete(ih, icx->entry);
	attr->data.resident.value_length = cpu_to_le32(new_value_len);
	ih->allocated_size = cpu_to_le32(new_allocated_size);
	WARN_ON_ONCE(le32_to_cpu(ih->index_length) != new_index_len);
	err = ntfs_attr_record_resize(mrec, attr, attr_len - entry_len);
	if (WARN_ON_ONCE(err)) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index root delete resize failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		return -EIO;
	}

	ntfs_index_root_update_size(icx, new_value_len);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(icx->actx->ntfs_ino);
	return 0;
}

static int ntfs_index_node_successor_leaf(
		struct ntfs_index_context *icx, struct index_block **ib_out,
		struct index_entry **entry_out)
{
	struct index_entry *entry;
	struct index_block *ib = NULL;
	struct index_header *ih;
	s64 vcn;
	bool node;
	int err;

	if (!icx || !icx->entry || !icx->ir || !ib_out || !entry_out ||
	    icx->pindex < 0 || icx->pindex >= MAX_PARENT_VCN ||
	    (!icx->is_in_root && !icx->ib) ||
	    !(icx->entry->flags & INDEX_ENTRY_NODE) ||
	    icx->entry->flags & INDEX_ENTRY_END)
		return -EINVAL;
	*ib_out = NULL;
	*entry_out = NULL;
	ih = icx->is_in_root ? &icx->ir->index : &icx->ib->index;
	if (ntfs_index_entries_validate(ih, true))
		return -EIO;
	entry = ntfs_ie_get_next(icx->entry);
	if ((u8 *)entry + sizeof(struct index_entry_header) >
			ntfs_ie_get_end(ih) ||
	    !(entry->flags & INDEX_ENTRY_NODE) ||
	    icx->parent_pos[icx->pindex] < 0 ||
	    icx->parent_pos[icx->pindex] == INT_MAX)
		return -EIO;

	if (!icx->ia_ni) {
		icx->ia_ni = ntfs_ia_open(icx, icx->idx_ni);
		if (!icx->ia_ni)
			return -ENOENT;
	}
	icx->parent_pos[icx->pindex]++;
	ib = kvzalloc(icx->block_size, GFP_NOFS);
	if (!ib)
		return -ENOMEM;
	for (;;) {
		vcn = ntfs_ie_get_vcn(entry);
		if (vcn < 0 || ntfs_ib_read(icx, vcn, ib)) {
			err = -EIO;
			goto out;
		}
		node = (ib->index.flags & NODE_MASK) == INDEX_NODE;
		if (ntfs_index_entries_validate(&ib->index, node)) {
			err = -EIO;
			goto out;
		}
		err = ntfs_icx_parent_inc(icx);
		if (err)
			goto out;
		icx->parent_vcn[icx->pindex] = vcn;
		icx->parent_pos[icx->pindex] = 0;
		entry = ntfs_ie_get_first(&ib->index);
		if (!node)
			break;
	}
	if (entry->flags & (INDEX_ENTRY_NODE | INDEX_ENTRY_END)) {
		err = -EIO;
		goto out;
	}
	*ib_out = ib;
	*entry_out = entry;
	return 0;
out:
	kvfree(ib);
	return err;
}

static int ntfs_index_node_successor_relookup(
		struct ntfs_index_context *icx, struct index_entry *replacement,
		struct index_block **ib_out, struct index_entry **entry_out)
{
	struct index_entry *entry;
	struct index_block *ib;
	u16 key_len;
	u16 replacement_len;
	int err;

	if (!icx || !replacement || !ib_out || !entry_out)
		return -EINVAL;
	*ib_out = NULL;
	*entry_out = NULL;
	replacement_len = le16_to_cpu(replacement->length);
	key_len = le16_to_cpu(replacement->key_length);
	if (!(replacement->flags & INDEX_ENTRY_NODE) ||
	    replacement->flags & INDEX_ENTRY_END ||
	    replacement_len < sizeof(struct index_entry_header) + sizeof(s64) ||
	    key_len > replacement_len - sizeof(struct index_entry_header) -
			sizeof(s64))
		return -EIO;

	ntfs_index_ctx_reinit(icx);
	err = ntfs_index_lookup(&replacement->key, key_len, icx);
	if (err)
		return err;
	if (!(icx->entry->flags & INDEX_ENTRY_NODE) ||
	    icx->entry->flags & INDEX_ENTRY_END)
		return -EIO;
	err = ntfs_index_node_successor_leaf(icx, &ib, &entry);
	if (err)
		return err;
	if (le16_to_cpu(entry->key_length) != key_len ||
	    memcmp(&entry->key, &replacement->key, key_len)) {
		kvfree(ib);
		return -EIO;
	}
	*ib_out = ib;
	*entry_out = entry;
	return 0;
}

static int ntfs_index_node_remove_transacted(
		struct ntfs_log_handle *handle, struct ntfs_index_context *icx)
{
	struct index_entry *original_entry;
	struct index_entry *replacement = NULL;
	struct index_entry *successor_entry;
	struct index_block *original_new = NULL;
	struct index_block *successor_ib = NULL;
	struct index_header *original_ih;
	struct index_root *new_root = NULL;
	struct index_root *old_root;
	struct attr_record *root_attr;
	s64 original_child_vcn;
	size_t expanded_size;
	u32 allocated;
	u32 delta;
	u32 expanded_allocated;
	u32 index_len;
	u32 new_allocated;
	u32 new_index_len;
	u32 new_root_len;
	u32 old_root_len;
	u32 original_entry_off;
	u32 root_buffer_len;
	u16 original_len;
	u16 replacement_len;
	bool original_is_root;
	bool successor_path_rebuild = false;
	int err;
	int original_depth;

	if (!handle || !icx || !icx->entry || !icx->ir || !icx->actx ||
	    !(icx->entry->flags & INDEX_ENTRY_NODE) ||
	    icx->entry->flags & INDEX_ENTRY_END)
		return -EINVAL;
	original_is_root = icx->is_in_root;
	original_entry = icx->entry;
	original_ih = original_is_root ? &icx->ir->index : &icx->ib->index;
	if (ntfs_index_entries_validate(original_ih, true))
		return -EIO;
	original_entry_off = (u8 *)original_entry -
		(u8 *)ntfs_ie_get_first(original_ih);
	original_len = le16_to_cpu(original_entry->length);
	original_child_vcn = ntfs_ie_get_vcn(original_entry);
	original_depth = icx->pindex;
	err = ntfs_index_node_successor_leaf(icx, &successor_ib,
			&successor_entry);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index node successor lookup failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	replacement = ntfs_ie_dup(successor_entry);
	if (!replacement) {
		err = -ENOMEM;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index node successor allocation failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	err = ntfs_ie_add_vcn(&replacement);
	if (err) {
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index node successor VCN expansion failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
		goto out;
	}
	ntfs_ie_set_vcn(replacement, original_child_vcn);
	replacement_len = le16_to_cpu(replacement->length);
	successor_path_rebuild = original_is_root &&
		replacement_len > original_len;

	index_len = le32_to_cpu(original_ih->index_length);
	allocated = le32_to_cpu(original_ih->allocated_size);
	if (index_len < original_len || allocated < index_len) {
		err = -EIO;
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index node entry length underflow for inode %llu (index %u entry %u allocated %u, error %d).",
			   (unsigned long long)icx->idx_ni->mft_no,
			   index_len, original_len, allocated, err);
		goto out;
	}
	if (replacement_len >= original_len) {
		delta = replacement_len - original_len;
		if (check_add_overflow(index_len, delta, &new_index_len)) {
			err = -EOVERFLOW;
			goto out;
		}
	} else {
		delta = original_len - replacement_len;
		new_index_len = index_len - delta;
	}
	if (original_is_root) {
		root_attr = icx->actx->attr;
		old_root = icx->ir;
		if (!root_attr || root_attr->non_resident ||
		    root_attr->type != AT_INDEX_ROOT) {
			err = -EOPNOTSUPP;
			goto out;
		}
		old_root_len = le32_to_cpu(
				root_attr->data.resident.value_length);
		if (old_root_len != offsetof(struct index_root, index) +
				allocated) {
			err = -EIO;
			goto out;
		}
		if (replacement_len >= original_len) {
			if (check_add_overflow(allocated, delta, &new_allocated)) {
				err = -EOVERFLOW;
				goto out;
			}
		} else {
			new_allocated = allocated - delta;
		}
		if (check_add_overflow((u32)offsetof(struct index_root, index),
				new_allocated, &new_root_len) ||
		    new_root_len > U16_MAX) {
			err = -EOVERFLOW;
			goto out;
		}
		root_buffer_len = max(old_root_len, new_root_len);
		new_root = kvzalloc(root_buffer_len, GFP_NOFS);
		if (!new_root) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(new_root, old_root, old_root_len);
		new_root->index.allocated_size = cpu_to_le32(new_allocated);
		original_entry = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(&new_root->index) +
			 original_entry_off);
		ntfs_ie_delete(&new_root->index, original_entry);
		ntfs_ie_insert(&new_root->index, replacement, original_entry);
		WARN_ON_ONCE(le32_to_cpu(new_root->index.index_length) !=
				new_index_len);
		err = ntfs_index_root_replace_transacted(handle, icx, new_root,
				new_root_len);
	} else {
		if (new_index_len > allocated) {
			successor_path_rebuild = true;
			if (check_add_overflow(allocated, delta,
					&expanded_allocated) ||
			    check_add_overflow((size_t)icx->block_size,
					(size_t)delta, &expanded_size)) {
				err = -EOVERFLOW;
				goto out;
			}
			original_new = kvzalloc(expanded_size, GFP_NOFS);
			if (!original_new) {
				err = -ENOMEM;
				goto out;
			}
			memcpy(original_new, icx->ib, icx->block_size);
			original_new->index.allocated_size =
				cpu_to_le32(expanded_allocated);
		} else {
			original_new = ntfs_index_kvmemdup(icx->ib, icx->block_size,
					GFP_NOFS);
			if (!original_new) {
				err = -ENOMEM;
				goto out;
			}
		}
		original_entry = (struct index_entry *)
			((u8 *)ntfs_ie_get_first(&original_new->index) +
			 original_entry_off);
		ntfs_ie_delete(&original_new->index, original_entry);
		ntfs_ie_insert(&original_new->index, replacement,
				original_entry);
		WARN_ON_ONCE(le32_to_cpu(original_new->index.index_length) !=
				new_index_len);
		if (new_index_len > allocated) {
			if (ntfs_index_entries_validate(&original_new->index,
					true)) {
				err = -EIO;
				goto out;
			}
			err = ntfs_index_internal_block_split_transacted(handle, icx,
					original_depth, icx->ib, original_new);
		} else {
			err = ntfs_index_block_update_transacted(handle, icx,
					icx->ib, original_new);
		}
	}
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index node replacement update failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
	if (err)
		goto out;

	if (successor_path_rebuild) {
		kvfree(successor_ib);
		successor_ib = NULL;
		successor_entry = NULL;
		err = ntfs_index_node_successor_relookup(icx, replacement,
				&successor_ib, &successor_entry);
		if (err) {
			ntfs_error(icx->idx_ni->vol->sb,
				   "Index node successor relookup failed for inode %llu (error %d).",
				   (unsigned long long)icx->idx_ni->mft_no, err);
			goto out;
		}
	}
	if (!icx->is_in_root) {
		kvfree(icx->ib);
		icx->ib = NULL;
	}
	icx->ib = successor_ib;
	successor_ib = NULL;
	icx->entry = successor_entry;
	icx->is_in_root = false;
	err = ntfs_index_allocation_remove_transacted(handle, icx);
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			   "Index node successor removal failed for inode %llu (error %d).",
			   (unsigned long long)icx->idx_ni->mft_no, err);
out:
	kvfree(new_root);
	kvfree(original_new);
	kfree(replacement);
	kvfree(successor_ib);
	return err;
}

static int __ntfs_index_remove(struct ntfs_log_handle *handle,
		struct ntfs_inode *dir_ni, const void *key, const u32 keylen)
{
	int ret = 0;
	struct ntfs_index_context *icx;

	if (!dir_ni || !key)
		return -EINVAL;

	icx = ntfs_index_ctx_get(dir_ni, I30, 4);
	if (!icx)
		return -EINVAL;
	if (handle) {
		ret = ntfs_index_lookup(key, keylen, icx);
		if (ret) {
			ntfs_error(dir_ni->vol->sb,
				   "Transacted index lookup failed for inode %llu (error %d).",
				   (unsigned long long)dir_ni->mft_no, ret);
		} else {
			ret = ntfs_index_entry_remove_transacted(handle, icx);
		}
		goto out;
	}

	while (1) {
		ret = ntfs_index_lookup(key, keylen, icx);
		if (ret)
			goto err_out;

		ret = ntfs_index_rm(icx);
		if (ret && ret != -EAGAIN)
			goto err_out;
		else if (!ret)
			break;

		mark_mft_record_dirty(icx->actx->ntfs_ino);
		ntfs_index_ctx_reinit(icx);
	}

	mark_mft_record_dirty(icx->actx->ntfs_ino);

	ret = 0;
out:
	ntfs_index_ctx_put(icx);
	if (ret)
		ntfs_error(dir_ni->vol->sb,
			   "Delete failed (error %d, transacted %d).", ret,
			   !!handle);
	return ret;
err_out:
	goto out;
}

int ntfs_index_entry_update_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx, const struct index_entry *new_ie)
{
	struct index_block *new_ib = NULL;
	struct index_header *ih;
	struct index_root *new_root = NULL;
	struct attr_record *attr;
	ptrdiff_t entry_off;
	ptrdiff_t record_off;
	u32 allocated_len;
	u32 attr_len;
	u32 entries_off;
	u32 index_len;
	u32 root_len;
	u32 used_off;
	u32 value_off;
	u16 entry_len;
	u16 key_len;
	bool key_compatible;
	int err;

	if (!handle || !icx || !icx->entry || !new_ie ||
	    (icx->is_in_root ? !icx->ir : !icx->ib) ||
	    ntfs_ie_end(icx->entry))
		return -EINVAL;
	ih = icx->is_in_root ? &icx->ir->index : &icx->ib->index;
	entry_len = le16_to_cpu(icx->entry->length);
	key_len = le16_to_cpu(icx->entry->key_length);
	entries_off = le32_to_cpu(ih->entries_offset);
	index_len = le32_to_cpu(ih->index_length);
	allocated_len = le32_to_cpu(ih->allocated_size);
	entry_off = (u8 *)icx->entry - (u8 *)ih;
	if (entries_off < sizeof(*ih) || !IS_ALIGNED(entries_off, 8) ||
	    !IS_ALIGNED(index_len, 8) || !IS_ALIGNED(allocated_len, 8) ||
	    entries_off > index_len || index_len > allocated_len ||
	    entry_off < entries_off || entry_off > index_len ||
	    entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8) ||
	    entry_len > index_len - entry_off ||
	    key_len > entry_len - sizeof(struct index_entry_header))
		return -EIO;
	if (le16_to_cpu(new_ie->length) != entry_len ||
	    le16_to_cpu(new_ie->key_length) != key_len ||
	    new_ie->flags != icx->entry->flags)
		return -EINVAL;
	used_off = entry_off;
	key_compatible = !memcmp(&new_ie->key, &icx->entry->key, key_len);
	if (!key_compatible && icx->cr == COLLATION_FILE_NAME &&
	    key_len >= sizeof(struct file_name_attr)) {
		const struct file_name_attr *old_fn = &icx->entry->key.file_name;
		const struct file_name_attr *new_fn = &new_ie->key.file_name;
		u32 name_bytes = old_fn->file_name_length * sizeof(__le16);

		key_compatible = old_fn->parent_directory ==
				new_fn->parent_directory &&
			old_fn->file_name_length == new_fn->file_name_length &&
			old_fn->file_name_type == new_fn->file_name_type &&
			name_bytes <= key_len - sizeof(struct file_name_attr) &&
			!memcmp(old_fn->file_name, new_fn->file_name, name_bytes);
	}
	if (!key_compatible)
		return -EINVAL;

	if (icx->is_in_root) {
		attr = icx->actx ? icx->actx->attr : NULL;
		if (!attr || !icx->actx->mrec || attr->non_resident ||
		    attr->type != AT_INDEX_ROOT)
			return -EIO;
		record_off = (u8 *)attr - (u8 *)icx->actx->mrec;
		attr_len = le32_to_cpu(attr->length);
		value_off = le16_to_cpu(attr->data.resident.value_offset);
		root_len = le32_to_cpu(attr->data.resident.value_length);
		if (record_off < 0 || record_off > icx->idx_ni->vol->mft_record_size ||
		    attr_len > icx->idx_ni->vol->mft_record_size - record_off ||
		    value_off > attr_len || root_len > attr_len - value_off ||
		    root_len < offsetof(struct index_root, index) ||
		    allocated_len != root_len -
				offsetof(struct index_root, index) ||
		    icx->ir != (struct index_root *)((u8 *)attr + value_off))
			return -EIO;
		new_root = ntfs_index_kvmemdup(icx->ir, root_len, GFP_NOFS);
		if (!new_root)
			return -ENOMEM;
		memcpy((u8 *)new_root + offsetof(struct index_root, index) +
				used_off, new_ie, entry_len);
		err = ntfs_index_root_replace_transacted(handle, icx, new_root,
				root_len);
	} else {
		if (icx->block_size < offsetof(struct index_block, index) ||
		    allocated_len > icx->block_size -
				offsetof(struct index_block, index))
			return -EIO;
		new_ib = ntfs_index_kvmemdup(icx->ib, icx->block_size, GFP_NOFS);
		if (!new_ib)
			return -ENOMEM;
		memcpy((u8 *)new_ib + offsetof(struct index_block, index) +
				used_off, new_ie, entry_len);
		if (ntfs_index_entries_validate(&new_ib->index,
				(new_ib->index.flags & NODE_MASK) == INDEX_NODE))
			err = -EIO;
		else
			err = ntfs_index_block_update_transacted(handle, icx,
					icx->ib, new_ib);
	}
	kvfree(new_ib);
	kvfree(new_root);
	return err;
}

int ntfs_index_entry_remove_transacted(struct ntfs_log_handle *handle,
		struct ntfs_index_context *icx)
{
	int err;

	if (!handle || !icx || !icx->entry ||
		(!icx->is_in_root && !icx->ib) || ntfs_ie_end(icx->entry))
		return -EINVAL;
	if (icx->entry->flags & INDEX_ENTRY_NODE)
		err = ntfs_index_node_remove_transacted(handle, icx);
	else if (icx->is_in_root)
		err = ntfs_index_root_remove_transacted(handle, icx);
	else
		err = ntfs_index_allocation_remove_transacted(handle, icx);
	if (err)
		ntfs_error(icx->idx_ni->vol->sb,
			   "Transacted index entry removal failed for inode %llu (%s, pindex %d, error %d).",
			   (unsigned long long)icx->idx_ni->mft_no,
			   icx->is_in_root ? "root" :
			   ((icx->entry->flags & INDEX_ENTRY_NODE) ? "node" : "leaf"),
			   icx->pindex, err);
	return err;
}

int ntfs_index_remove(struct ntfs_inode *dir_ni, const void *key,
		const u32 keylen)
{
	return __ntfs_index_remove(NULL, dir_ni, key, keylen);
}

int ntfs_index_remove_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *dir_ni, const void *key, const u32 keylen)
{
	if (!handle)
		return -EINVAL;
	return __ntfs_index_remove(handle, dir_ni, key, keylen);
}

/*
 * ntfs_index_walk_down - walk down the index tree (leaf bound)
 * until there are no subnode in the first index entry returns
 * the entry at the bottom left in subnode
 */
struct index_entry *ntfs_index_walk_down(struct index_entry *ie, struct ntfs_index_context *ictx)
{
	struct index_entry *entry;
	struct index_block *ib;
	int err;
	s64 vcn;

	entry = ie;
	do {
		vcn = ntfs_ie_get_vcn(entry);
		if (ictx->is_in_root) {
			ib = kvzalloc(ictx->block_size, GFP_NOFS);
			if (!ib)
				return ERR_PTR(-ENOMEM);
			/*
			 * Descending from root index (level 0) to the first
			 * child level. is_in_root == true implies pindex == 0,
			 * so advance to level 1.
			 */
			ictx->pindex = 1;
			ictx->ir = NULL;
			ictx->ib = ib;
			ictx->is_in_root = false;
		} else {
			/* down from non-zero level */
			err = ntfs_icx_parent_inc(ictx);
			if (err)
				return ERR_PTR(err);
		}

		ictx->parent_pos[ictx->pindex] = 0;
		ictx->parent_vcn[ictx->pindex] = vcn;
		if (!ntfs_ib_read(ictx, vcn, ictx->ib)) {
			ictx->entry = ntfs_ie_get_first(&ictx->ib->index);
			entry = ictx->entry;
		} else
			entry = ERR_PTR(-EIO);
	} while (!IS_ERR(entry) && (entry->flags & INDEX_ENTRY_NODE));

	return entry;
}

/*
 * ntfs_index_walk_up - walk up the index tree (root bound) until
 * there is a valid data entry in parent returns the parent entry
 * or NULL if no more parent.
 * @ie: current index entry
 * @ictx: index context
 */
static struct index_entry *ntfs_index_walk_up(struct index_entry *ie,
		struct ntfs_index_context *ictx)
{
	struct index_entry *entry = ie;
	s64 vcn;

	if (ictx->pindex <= 0)
		return NULL;

	do {
		ictx->pindex--;
		if (!ictx->pindex) {
			/* we have reached the root */
			kfree(ictx->ib);
			ictx->ib = NULL;
			ictx->is_in_root = true;
			/* a new search context is to be allocated */
			if (ictx->actx)
				ntfs_attr_put_search_ctx(ictx->actx);
			ictx->ir = ntfs_ir_lookup(ictx->idx_ni, ictx->name,
						  ictx->name_len, &ictx->actx);
			if (ictx->ir)
				entry = ntfs_ie_get_by_pos(
					&ictx->ir->index,
					ictx->parent_pos[ictx->pindex]);
			else
				entry = NULL;
		} else {
			/* up into non-root node */
			vcn = ictx->parent_vcn[ictx->pindex];
			if (!ntfs_ib_read(ictx, vcn, ictx->ib)) {
				entry = ntfs_ie_get_by_pos(
					&ictx->ib->index,
					ictx->parent_pos[ictx->pindex]);
			} else
				entry = NULL;
		}
		ictx->entry = entry;
	} while (entry && (ictx->pindex > 0) &&
		 (entry->flags & INDEX_ENTRY_END));
	return entry;
}

/*
 * ntfs_index_next - get next entry in an index according to collating sequence.
 * Returns next entry or NULL if none.
 *
 * Sample layout :
 *
 *                 +---+---+---+---+---+---+---+---+    n ptrs to subnodes
 *                 |   |   | 10| 25| 33|   |   |   |    n-1 keys in between
 *                 +---+---+---+---+---+---+---+---+    no key in last entry
 *                              | A | A
 *                              | | | +-------------------------------+
 *   +--------------------------+ | +-----+                           |
 *   |                            +--+    |                           |
 *   V                               |    V                           |
 * +---+---+---+---+---+---+---+---+ |  +---+---+---+---+---+---+---+---+
 * | 11| 12| 13| 14| 15| 16| 17|   | |  | 26| 27| 28| 29| 30| 31| 32|   |
 * +---+---+---+---+---+---+---+---+ |  +---+---+---+---+---+---+---+---+
 *                               |   |
 *       +-----------------------+   |
 *       |                           |
 *     +---+---+---+---+---+---+---+---+
 *     | 18| 19| 20| 21| 22| 23| 24|   |
 *     +---+---+---+---+---+---+---+---+
 *
 * @ie: current index entry
 * @ictx: index context
 */
struct index_entry *ntfs_index_next(struct index_entry *ie, struct ntfs_index_context *ictx)
{
	struct index_entry *next;
	__le16 flags;

	/*
	 * lookup() may have returned an invalid node
	 * when searching for a partial key
	 * if this happens, walk up
	 */
	if (ie->flags & INDEX_ENTRY_END)
		next = ntfs_index_walk_up(ie, ictx);
	else {
		/*
		 * get next entry in same node
		 * there is always one after any entry with data
		 */
		next = (struct index_entry *)((char *)ie + le16_to_cpu(ie->length));
		++ictx->parent_pos[ictx->pindex];
		flags = next->flags;

		/* walk down if it has a subnode */
		if (flags & INDEX_ENTRY_NODE) {
			if (!ictx->ia_ni) {
				ictx->ia_ni = ntfs_ia_open(ictx, ictx->idx_ni);
				if (!ictx->ia_ni)
					return ERR_PTR(-EIO);
			}

			next = ntfs_index_walk_down(next, ictx);
			if (IS_ERR(next))
				return next;
		} else {

			/* walk up it has no subnode, nor data */
			if (flags & INDEX_ENTRY_END)
				next = ntfs_index_walk_up(next, ictx);
		}
	}

	/* return NULL if stuck at end of a block */
	if (next && (next->flags & INDEX_ENTRY_END))
		next = NULL;

	return next;
}
