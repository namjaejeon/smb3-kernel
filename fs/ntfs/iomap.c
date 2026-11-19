// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * iomap callack functions
 *
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/writeback.h>

#include "attrib.h"
#include "logfile.h"
#include "mft.h"
#include "ntfs.h"
#include "iomap.h"

#define NTFS_IOMAP_NEED_ALLOC	1

static void ntfs_report_write_enospc(struct inode *inode, const char *stage,
		loff_t offset, loff_t length, int err)
{
	struct ntfs_inode *ni;
	struct ntfs_volume *vol;

	if (err >= 0 || !inode || !inode->i_sb)
		return;
	ni = NTFS_I(inode);
	vol = ni->vol;
	if (!vol)
		return;
	ntfs_error(inode->i_sb,
		"Write path returned error %d at %s (inode %llu, offset %lld, length %lld, data size %lld, allocated size %lld, free clusters %lld, dirty clusters %lld).",
		err,
		stage, (unsigned long long)ni->mft_no,
		(long long)offset, (long long)length,
		(long long)ni->data_size, (long long)ni->allocated_size,
		(long long)atomic64_read(&vol->free_clusters),
		(long long)atomic64_read(&vol->dirty_clusters));
}

/*
 * iomap_zero_range is called for an area beyond the initialized size,
 * garbage values can be read, so zeroing out is needed.
 */
static void ntfs_iomap_put_folio_non_resident(struct inode *inode, loff_t pos,
					      unsigned int len, struct folio *folio)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	unsigned long sector_size = 1UL << inode->i_blkbits;
	loff_t start_down, end_up, init;

	start_down = round_down(pos, sector_size);
	end_up = (pos + len - 1) | (sector_size - 1);
	init = ni->initialized_size;

	if (init >= start_down && init <= end_up) {
		if (init < pos) {
			loff_t offset = offset_in_folio(folio, pos + len);

			if (offset == 0)
				offset = folio_size(folio);
			folio_zero_segments(folio,
					    offset_in_folio(folio, init),
					    offset_in_folio(folio, pos),
					    offset,
					    folio_size(folio));

		} else  {
			loff_t offset = max_t(loff_t, pos + len, init);

			offset = offset_in_folio(folio, offset);
			if (offset == 0)
				offset = folio_size(folio);
			folio_zero_segment(folio,
					   offset,
					   folio_size(folio));
		}
	} else if (init <= pos) {
		loff_t offset = 0, offset2 = offset_in_folio(folio, pos + len);

		if ((init >> folio_shift(folio)) == (pos >> folio_shift(folio)))
			offset = offset_in_folio(folio, init);
		if (offset2 == 0)
			offset2 = folio_size(folio);
		folio_zero_segments(folio,
				    offset,
				    offset_in_folio(folio, pos),
				    offset2,
				    folio_size(folio));
	}
	folio_unlock(folio);
	folio_put(folio);
}

/*
 * iomap_zero_range is called for an area beyond the initialized size,
 * garbage values can be read, so zeroing out is needed.
 */
static void ntfs_iomap_put_folio(struct inode *inode, loff_t pos,
		unsigned int len, struct folio *folio)
{
	if (NInoNonResident(NTFS_I(inode)))
		return ntfs_iomap_put_folio_non_resident(inode, pos,
							 len, folio);
	folio_unlock(folio);
	folio_put(folio);
}

const struct iomap_write_ops ntfs_iomap_folio_ops = {
	.put_folio = ntfs_iomap_put_folio,
};

static int ntfs_read_iomap_begin_resident(struct inode *inode, loff_t offset, loff_t length,
		unsigned int flags, struct iomap *iomap, bool keep_mrec_lock)
{
	struct ntfs_inode *base_ni, *ni = NTFS_I(inode);
	struct ntfs_attr_search_ctx *ctx;
	loff_t i_size;
	u32 attr_len;
	int err = 0;
	char *kattr;

	base_ni = ntfs_base_inode(ni);
	mutex_lock(&base_ni->mrec_lock);

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}

	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err))
		goto out;

	attr_len = le32_to_cpu(ctx->attr->data.resident.value_length);
	if (unlikely(attr_len > ni->initialized_size))
		attr_len = ni->initialized_size;
	i_size = i_size_read(inode);

	if (unlikely(attr_len > i_size)) {
		/* Race with shrinking truncate. */
		attr_len = i_size;
	}

	if (offset >= attr_len) {
		if (flags & IOMAP_REPORT)
			err = -ENOENT;
		else {
			iomap->type = IOMAP_HOLE;
			iomap->offset = offset;
			iomap->length = length;
		}
		goto out;
	}

	kattr = (u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset);

	iomap->type = IOMAP_INLINE;
	iomap->inline_data = kattr;
	iomap->offset = 0;
	iomap->length = attr_len;

out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);

	if (!err && keep_mrec_lock &&
	    iomap->type == IOMAP_INLINE) {
		iomap->private = base_ni;
		return 0;
	}

	mutex_unlock(&base_ni->mrec_lock);

	return err;
}

/*
 * ntfs_read_iomap_begin_non_resident - map non-resident NTFS file data
 * @inode:		inode to map
 * @offset:		file offset to map
 * @length:		length of mapping
 * @flags:		IOMAP flags
 * @iomap:		iomap structure to fill
 * @need_unwritten:	true if UNWRITTEN extent type is needed
 *
 * Map a range of a non-resident NTFS file to an iomap extent.
 *
 * NTFS UNWRITTEN extent handling:
 * ================================
 * The concept of an unwritten extent in NTFS is slightly different from
 * that of other filesystems. NTFS conceptually manages only a single
 * continuous unwritten region, which is strictly defined based on
 * initialized_size.
 *
 * File offset layout:
 *   0                        initialized_size                   i_size(EOF)
 *   |----------#0----------|----------#1----------|----------#2----------|
 *   | Actual data          | Pre-allocated        | Pre-allocated        |
 *   | (user written)       | (within initialized) | (initialized ~ EOF)  |
 *   |----------------------|----------------------|----------------------|
 *   MAPPED                 MAPPED                 UNWRITTEN (conditionally)
 *
 * Region #0: User-written data, initialized and valid.
 * Region #1: Pre-allocated within initialized_size, must be zero-initialized
 *            by the filesystem before exposure to userspace.
 * Region #2: Pre-allocated beyond initialized_size, does not need initialization.
 *
 * The @need_unwritten parameter controls whether region #2 is mapped as
 * IOMAP_UNWRITTEN or IOMAP_MAPPED:
 * - For seek operations (SEEK_DATA/SEEK_HOLE): IOMAP_MAPPED is needed to
 *   prevent iomap_seek_data from incorrectly interpreting pre-allocated
 *   space as a hole. Since NTFS does not support multiple unwritten extents,
 *   all pre-allocated regions should be treated as data, not holes.
 * - For zero_range operations: IOMAP_MAPPED is needed to be zeroed out.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int ntfs_read_iomap_begin_non_resident(struct inode *inode, loff_t offset,
		loff_t length, unsigned int flags, struct iomap *iomap,
		bool need_unwritten)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	s64 vcn;
	s64 lcn;
	struct runlist_element *rl;
	struct ntfs_volume *vol = ni->vol;
	loff_t vcn_ofs;
	loff_t rl_length;

	vcn = ntfs_bytes_to_cluster(vol, offset);
	vcn_ofs = ntfs_bytes_to_cluster_off(vol, offset);

	down_write(&ni->runlist.lock);
	rl = ntfs_attr_vcn_to_rl(ni, vcn, &lcn);
	if (IS_ERR(rl)) {
		up_write(&ni->runlist.lock);
		return PTR_ERR(rl);
	}

	if (flags & IOMAP_REPORT) {
		if (lcn < LCN_HOLE) {
			up_write(&ni->runlist.lock);
			return -ENOENT;
		}
	} else if (lcn < LCN_ENOENT) {
		up_write(&ni->runlist.lock);
		return -EINVAL;
	}

	iomap->bdev = inode->i_sb->s_bdev;
	iomap->offset = offset;

	if (lcn <= LCN_DELALLOC) {
		if (lcn == LCN_DELALLOC)
			iomap->type = IOMAP_DELALLOC;
		else
			iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
	} else {
		if (need_unwritten && offset >= ni->initialized_size)
			iomap->type = IOMAP_UNWRITTEN;
		else
			iomap->type = IOMAP_MAPPED;
		iomap->addr = ntfs_cluster_to_bytes(vol, lcn) + vcn_ofs;
	}

	rl_length = ntfs_cluster_to_bytes(vol, rl->length - (vcn - rl->vcn));

	if (rl_length == 0 && rl->lcn > LCN_DELALLOC) {
		ntfs_error(inode->i_sb,
				"runlist(vcn : %lld, length : %lld, lcn : %lld) is corrupted\n",
				rl->vcn, rl->length, rl->lcn);
		up_write(&ni->runlist.lock);
		return -EIO;
	}

	if (rl_length && length > rl_length - vcn_ofs)
		iomap->length = rl_length - vcn_ofs;
	else
		iomap->length = length;
	up_write(&ni->runlist.lock);

	if (!(flags & IOMAP_ZERO) &&
			iomap->type == IOMAP_MAPPED &&
			iomap->offset < ni->initialized_size &&
			iomap->offset + iomap->length > ni->initialized_size) {
		iomap->length = round_up(ni->initialized_size, 1 << inode->i_blkbits) -
			iomap->offset;
	}
	iomap->flags |= IOMAP_F_MERGED;

	return 0;
}

static int __ntfs_read_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		unsigned int flags, struct iomap *iomap, struct iomap *srcmap,
		bool need_unwritten, bool keep_mrec_lock)
{
	if (NVolShutdown(NTFS_I(inode)->vol))
		return -EIO;
	if (NInoNonResident(NTFS_I(inode)))
		return ntfs_read_iomap_begin_non_resident(inode, offset, length,
				flags, iomap, need_unwritten);
	return ntfs_read_iomap_begin_resident(inode, offset, length,
					     flags, iomap, keep_mrec_lock);
}

static int ntfs_read_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		unsigned int flags, struct iomap *iomap, struct iomap *srcmap)
{
	return __ntfs_read_iomap_begin(inode, offset, length, flags, iomap,
			srcmap, true, true);
}

static int ntfs_read_iomap_end(struct inode *inode, loff_t pos, loff_t length,
		ssize_t written, unsigned int flags, struct iomap *iomap)
{
	struct ntfs_inode *base_ni = iomap->private;

	if (base_ni)
		mutex_unlock(&base_ni->mrec_lock);
	return written;
}

DEFINE_IOMAP_ITER_NEXT_END(ntfs_read_iomap_next, ntfs_read_iomap_begin,
		ntfs_read_iomap_end);

/*
 * Check that the cached iomap still matches the NTFS runlist before
 * iomap_zero_range() is called. if the runlist changes while iomap is
 * iterating a cached iomap, iomap_zero_range() may overwrite folios
 * that have been already written with valid data.
 */
static bool ntfs_iomap_valid(struct inode *inode, const struct iomap *iomap)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct runlist_element *rl;
	s64 vcn, lcn;

	if (!NInoNonResident(ni))
		return false;

	vcn = iomap->offset >> ni->vol->cluster_size_bits;

	down_read(&ni->runlist.lock);
	rl = __ntfs_attr_find_vcn_nolock(&ni->runlist, vcn);
	if (IS_ERR(rl)) {
		up_read(&ni->runlist.lock);
		return false;
	}
	lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
	up_read(&ni->runlist.lock);
	return lcn == LCN_DELALLOC;
}

static const struct iomap_write_ops ntfs_zero_iomap_folio_ops = {
	.put_folio = ntfs_iomap_put_folio,
	.iomap_valid = ntfs_iomap_valid,
};

static int ntfs_seek_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		unsigned int flags, struct iomap *iomap, struct iomap *srcmap)
{
	return __ntfs_read_iomap_begin(inode, offset, length, flags, iomap,
			srcmap, false, false);
}

static int ntfs_zero_read_iomap_end(struct inode *inode, loff_t pos, loff_t length,
		ssize_t written, unsigned int flags, struct iomap *iomap)
{
	if ((flags & IOMAP_ZERO) && (iomap->flags & IOMAP_F_STALE))
		return -EPERM;
	return written;
}

static DEFINE_IOMAP_ITER_NEXT_END(ntfs_zero_read_iomap_next,
		ntfs_seek_iomap_begin, ntfs_zero_read_iomap_end);

DEFINE_IOMAP_ITER_NEXT(ntfs_seek_iomap_next, ntfs_seek_iomap_begin);

int ntfs_dio_zero_range(struct inode *inode, loff_t offset, loff_t length)
{
	if ((offset | length) & (SECTOR_SIZE - 1))
		return -EINVAL;

	return  blkdev_issue_zeroout(inode->i_sb->s_bdev,
				     offset >> SECTOR_SHIFT,
				     length >> SECTOR_SHIFT,
				     GFP_NOFS,
				     BLKDEV_ZERO_NOUNMAP);
}

static int ntfs_zero_range(struct inode *inode, loff_t offset, loff_t length)
{
	return iomap_zero_range(inode,
				offset, length,
				NULL,
				ntfs_zero_read_iomap_next,
				&ntfs_zero_iomap_folio_ops,
				NULL);
}

bool ntfs_iomap_can_share_delalloc(struct ntfs_inode *ni)
{
	return ni->vol->journal && !NInoAttr(ni) &&
		ni->type == AT_DATA && ni->name == AT_UNNAMED &&
		ni->mft_no >= FILE_first_user &&
		!NInoCompressed(ni) && !NInoEncrypted(ni) &&
		ni->vol->cluster_size <= PAGE_SIZE;
}

void ntfs_maybe_writeback_delalloc(struct ntfs_volume *vol)
{
	s64 free, dirty;

	if (!NVolFreeClusterKnown(vol))
		return;
	free = atomic64_read(&vol->free_clusters);
	dirty = atomic64_read(&vol->dirty_clusters);
	if (dirty > 0 && (free - dirty < dirty ||
			  dirty >= ntfs_delalloc_limit(vol, free)))
		try_to_writeback_inodes_sb(vol->sb, WB_REASON_FS_FREE_SPACE);
}

static int ntfs_write_simple_iomap_begin_non_resident(struct inode *inode, loff_t offset,
						      loff_t length, struct iomap *iomap)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_inode *mrec_ni = ntfs_inode_is_named_stream(ni) ?
			ntfs_base_inode(ni) : ni;
	struct ntfs_volume *vol = ni->vol;
	loff_t vcn_ofs, rl_length;
	struct runlist_element *rl, *rlc;
	bool is_retry = false;
	int err = 0, map_err = 0;
	s64 vcn, lcn;
	s64 max_clu_count =
		ntfs_bytes_to_cluster(vol, round_up(length, vol->cluster_size));

	vcn = ntfs_bytes_to_cluster(vol, offset);
	vcn_ofs = ntfs_bytes_to_cluster_off(vol, offset);

	down_read(&ni->runlist.lock);
	rl = ni->runlist.rl;
	if (!rl) {
		up_read(&ni->runlist.lock);
		err = ntfs_map_runlist(ni, vcn);
		if (err) {
			mutex_unlock(&mrec_ni->mrec_lock);
			return -ENOENT;
		}
		down_read(&ni->runlist.lock);
		rl = ni->runlist.rl;
	}
	up_read(&ni->runlist.lock);

	down_write(&ni->runlist.lock);
remap_rl:
	/* Seek to element containing target vcn. */
	rl = __ntfs_attr_find_vcn_nolock(&ni->runlist, vcn);
	if (IS_ERR(rl)) {
		up_write(&ni->runlist.lock);
		mutex_unlock(&mrec_ni->mrec_lock);
		return -EIO;
	}
	lcn = ntfs_rl_vcn_to_lcn(rl, vcn);

	if (lcn <= LCN_RL_NOT_MAPPED && is_retry == false) {
		is_retry = true;
		map_err = ntfs_map_runlist_nolock(ni, vcn, NULL);
		if (!map_err) {
			rl = ni->runlist.rl;
			goto remap_rl;
		}
	}

	/*
	 * As in ntfs_attr_vcn_to_rl(): a runlist fragment that could not be
	 * mapped is not a hole.  Treating it as one would put a delalloc
	 * extent over clusters that are allocated on disk but unknown to us.
	 */
	if (lcn == LCN_RL_NOT_MAPPED) {
		up_write(&ni->runlist.lock);
		mutex_unlock(&mrec_ni->mrec_lock);
		return map_err == -ENOMEM ? -ENOMEM : -EIO;
	}

	max_clu_count = min(max_clu_count, rl->length - (vcn - rl->vcn));
	if (max_clu_count <= 0 || lcn < LCN_HOLE) {
		ntfs_error(inode->i_sb,
				"runlist(vcn : %lld, length : %lld) is corrupted\n",
				rl->vcn, rl->length);
		up_write(&ni->runlist.lock);
		mutex_unlock(&mrec_ni->mrec_lock);
		return -EIO;
	}

	iomap->bdev = inode->i_sb->s_bdev;
	iomap->offset = offset;

	if (lcn <= LCN_DELALLOC) {
		if (lcn < LCN_DELALLOC) {
			max_clu_count =
				ntfs_reserve_dirty_clusters(vol, max_clu_count);
			if (max_clu_count < 0) {
				err = max_clu_count;
				ntfs_report_write_enospc(inode,
					"delayed allocation availability", offset,
					length, err);
				up_write(&ni->runlist.lock);
				mutex_unlock(&mrec_ni->mrec_lock);
				return err;
			}
			if (!max_clu_count) {
				up_write(&ni->runlist.lock);
				mutex_unlock(&mrec_ni->mrec_lock);
				return NTFS_IOMAP_NEED_ALLOC;
			}
		}

		iomap->type = IOMAP_DELALLOC;
		iomap->addr = IOMAP_NULL_ADDR;

		if (lcn <= LCN_HOLE) {
			size_t new_rl_count;

			rlc = kmalloc(sizeof(struct runlist_element) * 2,
					GFP_NOFS);
			if (!rlc) {
				ntfs_release_dirty_clusters(vol, max_clu_count);
				up_write(&ni->runlist.lock);
				mutex_unlock(&mrec_ni->mrec_lock);
				return -ENOMEM;
			}

			rlc->vcn = vcn;
			rlc->lcn = LCN_DELALLOC;
			rlc->length = max_clu_count;

			rlc[1].vcn = vcn + max_clu_count;
			rlc[1].lcn = LCN_RL_NOT_MAPPED;
			rlc[1].length = 0;

			rl = ntfs_runlists_merge(&ni->runlist, rlc, 0,
					&new_rl_count);
			if (IS_ERR(rl)) {
				ntfs_error(vol->sb, "Failed to merge runlists");
				ntfs_release_dirty_clusters(vol, max_clu_count);
				up_write(&ni->runlist.lock);
				mutex_unlock(&mrec_ni->mrec_lock);
				kfree(rlc);
				return PTR_ERR(rl);
			}

			ni->runlist.rl = rl;
			ni->runlist.count = new_rl_count;
			ni->i_dealloc_clusters += max_clu_count;
		}
		up_write(&ni->runlist.lock);
		mutex_unlock(&mrec_ni->mrec_lock);

		rl_length = ntfs_cluster_to_bytes(vol, max_clu_count);
		if (length > rl_length - vcn_ofs)
			iomap->length = rl_length - vcn_ofs;
		else
			iomap->length = length;

		iomap->flags = IOMAP_F_NEW;
		/*
		 * A shared DELALLOC run may already contain mmap stores. Iomap
		 * initializes partial blocks under the folio lock and journaled
		 * conversion zeroes new media before writeback.
		 */
		if (lcn <= LCN_HOLE && !ntfs_iomap_can_share_delalloc(ni)) {
			loff_t end = offset + length;

			if (vcn_ofs || ((vol->cluster_size > iomap->length) &&
					end < ni->initialized_size)) {
				loff_t z_start, z_end;

				z_start = vcn << vol->cluster_size_bits;
				z_end = min_t(loff_t, z_start + vol->cluster_size,
					      i_size_read(inode));
				if (z_end > z_start)
					err = ntfs_zero_range(inode,
							      z_start,
							      z_end - z_start);
			}
			if ((!err || err == -EPERM) &&
			    max_clu_count > 1 &&
			    (iomap->length & vol->cluster_size_mask &&
			     end < ni->initialized_size)) {
				loff_t z_start, z_end;

				z_start = (vcn + max_clu_count - 1) <<
					vol->cluster_size_bits;
				z_end = min_t(loff_t, z_start + vol->cluster_size,
					      i_size_read(inode));
				if (z_end > z_start)
					err = ntfs_zero_range(inode,
							      z_start,
							      z_end - z_start);
			}

			if (err == -EPERM)
				err = 0;
			if (err) {
				ntfs_report_write_enospc(inode,
					"delayed allocation zeroing", offset,
					length, err);
				return err;
			}
		}
	} else {
		up_write(&ni->runlist.lock);
		mutex_unlock(&mrec_ni->mrec_lock);

		iomap->type = IOMAP_MAPPED;
		iomap->addr = ntfs_cluster_to_bytes(vol, lcn) + vcn_ofs;

		rl_length = ntfs_cluster_to_bytes(vol, max_clu_count);
		if (length > rl_length - vcn_ofs)
			iomap->length = rl_length - vcn_ofs;
		else
			iomap->length = length;
	}

	return 0;
}

#define NTFS_IOMAP_FLAGS_BEGIN		BIT(1)
#define NTFS_IOMAP_FLAGS_DIO		BIT(2)
#define	NTFS_IOMAP_FLAGS_MKWRITE	BIT(3)
#define	NTFS_IOMAP_FLAGS_WRITEBACK	BIT(4)
#define NTFS_IOMAP_FLAGS_NODELALLOC	BIT(5)

static void ntfs_report_iomap_error(struct inode *inode, const char *stage,
		loff_t offset, loff_t length, int err, int ntfs_iomap_flags)
{
	if ((err == -EAGAIN || err == -EBUSY) &&
	    (ntfs_iomap_flags & NTFS_IOMAP_FLAGS_MKWRITE))
		return;
	ntfs_report_write_enospc(inode, stage, offset, length, err);
}

static struct ntfs_log_handle *ntfs_iomap_log_begin(struct ntfs_volume *vol,
		unsigned int credits, int flags)
{
	if (flags & NTFS_IOMAP_FLAGS_WRITEBACK)
		return ntfs_log_begin_writeback(vol, credits);
	if (flags & NTFS_IOMAP_FLAGS_MKWRITE)
		return ntfs_log_begin_locked(vol, credits);
	return ntfs_log_begin(vol, credits);
}

static int ntfs_write_da_iomap_begin_non_resident(struct inode *inode,
		loff_t offset, loff_t length, unsigned int flags,
		struct iomap *iomap, int ntfs_iomap_flags,
		struct ntfs_log_handle *log_handle)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_inode *mrec_ni = ntfs_inode_is_named_stream(ni) ?
			ntfs_base_inode(ni) : ni;
	struct ntfs_volume *vol = ni->vol;
	loff_t vcn_ofs, rl_length;
	s64 vcn, start_lcn, lcn_count;
	bool balloc = false, update_mp;
	bool was_delalloc = false;
	int abort_err;
	int err;
	s64 max_clu_count =
		ntfs_bytes_to_cluster(vol, round_up(length, vol->cluster_size));
	if (log_handle)
		max_clu_count = min_t(s64, max_clu_count,
				NTFS_ATTR_GROW_MAX_CLUSTERS);

	vcn = ntfs_bytes_to_cluster(vol, offset);
	vcn_ofs = ntfs_bytes_to_cluster_off(vol, offset);

	update_mp = ntfs_iomap_flags & (NTFS_IOMAP_FLAGS_DIO |
			NTFS_IOMAP_FLAGS_MKWRITE | NTFS_IOMAP_FLAGS_NODELALLOC) ||
			NInoAttr(ni) || ni->mft_no < FILE_first_user;
	down_write(&ni->runlist.lock);
	if (log_handle)
		err = ntfs_attr_map_cluster_transacted(log_handle, ni, vcn,
				&start_lcn, &lcn_count, max_clu_count, &balloc,
				ntfs_iomap_flags & NTFS_IOMAP_FLAGS_WRITEBACK,
				&was_delalloc, max_clu_count);
	else
		err = ntfs_attr_map_cluster(ni, vcn, &start_lcn, &lcn_count,
				max_clu_count, &balloc, update_mp,
				ntfs_iomap_flags & NTFS_IOMAP_FLAGS_WRITEBACK,
				ntfs_iomap_flags & NTFS_IOMAP_FLAGS_NODELALLOC);
	up_write(&ni->runlist.lock);
	if (err) {
		if (err != -ENOSPC ||
		    (ntfs_iomap_flags & NTFS_IOMAP_FLAGS_WRITEBACK))
			ntfs_report_iomap_error(inode, "cluster mapping", offset,
					length, err, ntfs_iomap_flags);
		/* Abort restores DELALLOC, so retain its dirty-cluster charge. */
		if (!log_handle)
			mutex_unlock(&mrec_ni->mrec_lock);
		goto out_abort;
	}

	iomap->bdev = inode->i_sb->s_bdev;
	iomap->offset = offset;

	rl_length = ntfs_cluster_to_bytes(vol, lcn_count);
	if (length > rl_length - vcn_ofs)
		iomap->length = rl_length - vcn_ofs;
	else
		iomap->length = length;

	if (start_lcn == LCN_HOLE)
		iomap->type = IOMAP_HOLE;
	else
		iomap->type = IOMAP_MAPPED;
	if (balloc == true)
		iomap->flags = IOMAP_F_NEW;

	iomap->addr = ntfs_cluster_to_bytes(vol, start_lcn) + vcn_ofs;
	if (log_handle &&
	    (ntfs_iomap_flags & NTFS_IOMAP_FLAGS_MKWRITE) &&
	    iomap->offset + iomap->length > ni->initialized_size)
		err = ntfs_attr_initialized_grow_transacted(log_handle, ni,
				iomap->offset + iomap->length);
	if (!log_handle)
		mutex_unlock(&mrec_ni->mrec_lock);
	if (err)
		ntfs_report_iomap_error(inode,
			"initialized-size update", offset, length, err,
			ntfs_iomap_flags);
	if (err)
		goto out_abort;

	if (balloc && !log_handle &&
	    !(ntfs_iomap_flags & NTFS_IOMAP_FLAGS_NODELALLOC)) {
		if (flags & IOMAP_DIRECT ||
		    ntfs_iomap_flags & NTFS_IOMAP_FLAGS_MKWRITE) {
			loff_t end = offset + length;

			if (vcn_ofs || ((vol->cluster_size > iomap->length) &&
					end < ni->initialized_size))
				err = ntfs_dio_zero_range(inode,
							  start_lcn <<
							  vol->cluster_size_bits,
							  vol->cluster_size);
			if (!err && lcn_count > 1 &&
			    (iomap->length & vol->cluster_size_mask &&
			     end < ni->initialized_size))
				err = ntfs_dio_zero_range(inode,
							  (start_lcn + lcn_count - 1) <<
							  vol->cluster_size_bits,
							  vol->cluster_size);
		}
		if (err < 0)
			ntfs_report_iomap_error(inode,
				"new-cluster zeroing", offset, length, err,
				ntfs_iomap_flags);
		if (err < 0)
			goto out_abort;
	}

	if (!log_handle &&
	    (ntfs_iomap_flags & NTFS_IOMAP_FLAGS_MKWRITE) &&
	    iomap->offset + iomap->length > ni->initialized_size) {
		err = ntfs_set_initialized_size_journaled(ni,
				iomap->offset + iomap->length);
	}

	if (log_handle) {
		/*
		 * Keep the attribute offsets and home-undo image stable until the
		 * transaction finishes. A concurrent link can move $DATA.
		 */
		err = ntfs_log_commit(log_handle);
		mutex_unlock(&mrec_ni->mrec_lock);
		if (err) {
			ntfs_report_iomap_error(inode,
				"transaction commit", offset, length, err,
				ntfs_iomap_flags);
			return err;
		}
	}
	return err;

out_abort:
	if (!log_handle)
		return err;
	abort_err = ntfs_log_abort(log_handle);
	mutex_unlock(&mrec_ni->mrec_lock);
	if (abort_err)
		ntfs_report_write_enospc(inode, "transaction abort", offset, length,
				abort_err);
	return abort_err ? abort_err : err;
}

static int ntfs_write_iomap_begin_resident(struct inode *inode, loff_t offset,
		struct iomap *iomap)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_inode *mrec_ni = ntfs_inode_is_named_stream(ni) ?
			ntfs_base_inode(ni) : ni;
	struct attr_record *a;
	struct ntfs_attr_search_ctx *ctx = NULL;
	u32 attr_len;
	int err = 0;
	char *kattr;
	void *copy = NULL;

	ctx = ntfs_attr_get_search_ctx(mrec_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}

	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out;
	}

	a = ctx->attr;
	/* The total length of the attribute value. */
	attr_len = le32_to_cpu(a->data.resident.value_length);
	kattr = (u8 *)a + le16_to_cpu(a->data.resident.value_offset);

	if (ni->vol->journal) {
		copy = kvmalloc(attr_len, GFP_NOFS);
		if (!copy) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(copy, kattr, attr_len);
	}
	iomap->type = IOMAP_INLINE;
	iomap->inline_data = copy ? copy : kattr;
	iomap->offset = 0;
	iomap->length = attr_len;
	iomap->private = copy ? copy : mrec_ni;

out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);

	if (err || copy)
		mutex_unlock(&mrec_ni->mrec_lock);

	return err;
}

static int ntfs_write_iomap_begin_non_resident(struct inode *inode, loff_t offset,
					       loff_t length, unsigned int flags,
					       struct iomap *iomap, int ntfs_iomap_flags)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_inode *mrec_ni = ntfs_inode_is_named_stream(ni) ?
			ntfs_base_inode(ni) : ni;
	struct ntfs_log_handle *log_handle = NULL;
	s64 max_clu_count;
	s64 mapped_lcn;
	int initialized_credits;
	int credits;
	int ret;

	/*
	 * A fault dirties a locked, uptodate folio. Reserve its holes like a
	 * buffered write and let writeback allocate a contiguous DELALLOC batch.
	 * Larger clusters retain synchronous zeroing outside the faulted folio.
	 */
	if (ntfs_iomap_can_share_delalloc(ni) &&
	    (ntfs_iomap_flags & NTFS_IOMAP_FLAGS_MKWRITE) &&
	    IS_ALIGNED(offset, ni->vol->cluster_size) &&
	    (IS_ALIGNED(length, ni->vol->cluster_size) ||
	     offset + length == i_size_read(inode))) {
		mutex_lock(&mrec_ni->mrec_lock);
		if (offset + length <= ni->initialized_size) {
			ret = ntfs_write_simple_iomap_begin_non_resident(inode,
					offset, length, iomap);
			if (ret != NTFS_IOMAP_NEED_ALLOC)
				return ret;
		} else {
			mutex_unlock(&mrec_ni->mrec_lock);
		}
	}

	if ((ntfs_iomap_flags & NTFS_IOMAP_FLAGS_WRITEBACK) &&
	    ni->vol->journal) {
		mutex_lock(&mrec_ni->mrec_lock);
		down_read(&ni->runlist.lock);
		mapped_lcn = ni->runlist.rl ?
			ntfs_rl_vcn_to_lcn(ni->runlist.rl,
					ntfs_bytes_to_cluster(ni->vol, offset)) :
			LCN_RL_NOT_MAPPED;
		up_read(&ni->runlist.lock);
		if (mapped_lcn >= 0 || mapped_lcn == LCN_HOLE)
			return ntfs_write_da_iomap_begin_non_resident(inode,
					offset, length, flags, iomap,
					ntfs_iomap_flags, NULL);
		mutex_unlock(&mrec_ni->mrec_lock);
	}

	if (ntfs_iomap_flags & (NTFS_IOMAP_FLAGS_BEGIN | NTFS_IOMAP_FLAGS_DIO) &&
	    offset + length > ni->initialized_size) {
		if (flags & IOMAP_NOWAIT)
			return -EAGAIN;
		ret = ntfs_extend_initialized_size(inode, offset,
						   offset + length, true);
		if (ret < 0) {
			ntfs_report_write_enospc(inode,
				"extend initialized size", offset, length, ret);
			return ret;
		}
	}

	if (ntfs_iomap_flags & NTFS_IOMAP_FLAGS_BEGIN) {
		mutex_lock(&mrec_ni->mrec_lock);
		ret = ntfs_write_simple_iomap_begin_non_resident(inode, offset,
				length, iomap);
		if (ret != NTFS_IOMAP_NEED_ALLOC)
			return ret;
		if (flags & IOMAP_NOWAIT)
			return -EAGAIN;
		ntfs_maybe_writeback_delalloc(ni->vol);
		ntfs_iomap_flags |= NTFS_IOMAP_FLAGS_NODELALLOC;
	}

	if (ni->vol->journal) {
		max_clu_count = ntfs_bytes_to_cluster(ni->vol,
				round_up(length, ni->vol->cluster_size));
		max_clu_count = min_t(s64, max_clu_count,
				NTFS_ATTR_GROW_MAX_CLUSTERS);
		credits = ntfs_attr_map_cluster_log_credits(ni->vol,
				max_clu_count);
		if (credits < 0) {
			ntfs_report_write_enospc(inode,
				"journal credit calculation", offset, length, credits);
			return credits;
		}
		if (ntfs_iomap_flags & NTFS_IOMAP_FLAGS_MKWRITE) {
			initialized_credits =
				ntfs_attr_initialized_grow_log_credits(ni->vol,
						NInoCompressed(ni) || NInoSparse(ni));
			if (initialized_credits < 0) {
				ntfs_report_write_enospc(inode,
					"initialized-size credit calculation", offset,
					length, initialized_credits);
				return initialized_credits;
			}
			if (check_add_overflow(credits, initialized_credits,
					&credits))
				return -EOVERFLOW;
		}
		/*
		 * Writeback must journal DELALLOC conversion as well.  Its
		 * reservation cannot synchronously checkpoint this worker.
		 */
		log_handle = ntfs_iomap_log_begin(ni->vol, credits,
				ntfs_iomap_flags);
		if (IS_ERR(log_handle)) {
			if (PTR_ERR(log_handle) != -EAGAIN ||
			    !(ntfs_iomap_flags & NTFS_IOMAP_FLAGS_WRITEBACK))
				ntfs_report_iomap_error(inode, "journal begin",
					offset, length, PTR_ERR(log_handle),
					ntfs_iomap_flags);
			return PTR_ERR(log_handle);
		}
	}

	mutex_lock(&mrec_ni->mrec_lock);
	return ntfs_write_da_iomap_begin_non_resident(inode, offset, length,
			flags, iomap, ntfs_iomap_flags, log_handle);
}

static int __ntfs_write_iomap_begin(struct inode *inode, loff_t offset,
				    loff_t length, unsigned int flags,
				    struct iomap *iomap, int ntfs_iomap_flags)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_inode *mrec_ni;
	loff_t end = offset + length;

	if (NVolShutdown(ni->vol))
		return -EIO;

	if (ntfs_iomap_flags & (NTFS_IOMAP_FLAGS_BEGIN | NTFS_IOMAP_FLAGS_DIO) &&
	    end > ni->data_size) {
		struct ntfs_volume *vol = ni->vol;
		int ret;

		if (vol->journal) {
			ret = ntfs_truncate_vfs(inode, end, i_size_read(inode));
		} else {
			mrec_ni = ntfs_inode_is_named_stream(ni) ?
					ntfs_base_inode(ni) : ni;
			mutex_lock(&mrec_ni->mrec_lock);
			if (end > ni->allocated_size &&
			    end < ni->allocated_size + vol->preallocated_size)
				ret = ntfs_attr_expand(ni, end,
						ni->allocated_size +
						vol->preallocated_size);
			else
				ret = ntfs_attr_expand(ni, end, 0);
			mutex_unlock(&mrec_ni->mrec_lock);
		}
		if (ret) {
			if (ret != -ENOSPC)
				ntfs_report_write_enospc(inode,
					"truncate/attribute expansion", offset, length, ret);
			return ret;
		}
	}

	if (!NInoNonResident(ni)) {
		mrec_ni = ntfs_inode_is_named_stream(ni) ?
				ntfs_base_inode(ni) : ni;
		mutex_lock(&mrec_ni->mrec_lock);
		return ntfs_write_iomap_begin_resident(inode, offset, iomap);
	}
	return  ntfs_write_iomap_begin_non_resident(inode, offset, length, flags,
						    iomap, ntfs_iomap_flags);
}

static int ntfs_write_iomap_begin(struct inode *inode, loff_t offset,
				  loff_t length, unsigned int flags,
				  struct iomap *iomap, struct iomap *srcmap)
{
	if (!(flags & IOMAP_NOWAIT))
		ntfs_maybe_writeback_delalloc(NTFS_I(inode)->vol);
	return __ntfs_write_iomap_begin(inode, offset, length, flags, iomap,
			NTFS_IOMAP_FLAGS_BEGIN);
}

/*
 * Buffered append into a prezeroed physical tail needs no allocation or
 * initialized-size transaction inside iomap. The caller publishes the actual
 * copied EOF and initialized size together after iomap has released its folios.
 */
static int ntfs_append_iomap_begin(struct inode *inode, loff_t offset,
		loff_t length, unsigned int flags, struct iomap *iomap,
		struct iomap *srcmap)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	int err;

	if (offset < ni->data_size || length <= 0 ||
	    offset > ni->zeroed_size || length > ni->zeroed_size - offset)
		return -EINVAL;
	err = ntfs_read_iomap_begin_non_resident(inode, offset, length,
			flags, iomap, false);
	if (!err && iomap->type != IOMAP_MAPPED)
		err = -EIO;
	return err;
}

DEFINE_IOMAP_ITER_NEXT_END(ntfs_append_iomap_next,
		ntfs_append_iomap_begin, ntfs_read_iomap_end);

static int ntfs_ordered_append_iomap_begin(struct inode *inode, loff_t offset,
		loff_t length, unsigned int flags, struct iomap *iomap,
		struct iomap *srcmap)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	int err;

	/* Pair with the owner's group publication before copying data. */
	if (!smp_load_acquire(&ni->ordered_io) ||
	    READ_ONCE(ni->ordered_owner) != current ||
	    offset < ni->data_size || offset > ni->allocated_size ||
	    length > ni->allocated_size - offset)
		return -EIO;
	err = __ntfs_read_iomap_begin(inode, offset, length, flags,
			iomap, srcmap, true, false);
	if (err)
		return err;
	if (iomap->type != IOMAP_UNWRITTEN)
		return -EIO;
	iomap->flags |= IOMAP_F_NEW;
	return 0;
}

DEFINE_IOMAP_ITER_NEXT_END(ntfs_ordered_append_iomap_next,
		ntfs_ordered_append_iomap_begin, ntfs_read_iomap_end);

static int ntfs_write_iomap_end_resident(struct inode *inode, loff_t pos,
					 loff_t length, ssize_t written,
					 unsigned int flags, struct iomap *iomap)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_inode *base_ni = ntfs_inode_is_named_stream(ni) ?
			ntfs_base_inode(ni) : ni;
	struct ntfs_log_handle *log_handle;
	int err;
	int abort_err;
	int credits;
	int ntfs_iomap_flags = flags & IOMAP_FAULT ?
		NTFS_IOMAP_FLAGS_MKWRITE : 0;

	if (!ni->vol->journal) {
		mark_mft_record_dirty(base_ni);
		mutex_unlock(&base_ni->mrec_lock);
		return written;
	}
	if (written <= 0)
		goto out_free;
	credits = ntfs_attr_pwrite_log_credits(ni->vol, written, false);
	if (credits < 0) {
		ntfs_report_write_enospc(inode,
			"resident journal credit calculation", pos,
			length, credits);
		written = credits;
		goto out_free;
	}
	log_handle = ntfs_iomap_log_begin(ni->vol, credits, ntfs_iomap_flags);
	if (IS_ERR(log_handle)) {
		ntfs_report_iomap_error(inode, "resident journal begin", pos,
			length, PTR_ERR(log_handle), ntfs_iomap_flags);
		written = PTR_ERR(log_handle);
		goto out_free;
	}
	mutex_lock(&base_ni->mrec_lock);
	err = ntfs_resident_attr_update_transacted(log_handle, ni, pos,
			iomap_inline_data(iomap, pos), written);
	if (err) {
		abort_err = ntfs_log_abort(log_handle);
		ntfs_report_iomap_error(inode,
			"resident transaction update", pos, length, err,
			ntfs_iomap_flags);
		if (abort_err)
			ntfs_report_write_enospc(inode,
				"resident transaction abort", pos, length,
				abort_err);
		written = abort_err ? abort_err : err;
	} else {
		err = ntfs_log_commit(log_handle);
		if (err) {
			ntfs_report_iomap_error(inode,
				"resident transaction commit", pos,
				length, err, ntfs_iomap_flags);
			written = err;
		}
	}
	mutex_unlock(&base_ni->mrec_lock);
out_free:
	kvfree(iomap->private);
	return written;
}

static int ntfs_write_iomap_end(struct inode *inode, loff_t pos, loff_t length,
				ssize_t written, unsigned int flags,
				struct iomap *iomap)
{
	if (iomap->type == IOMAP_INLINE)
		return ntfs_write_iomap_end_resident(inode, pos, length,
						     written, flags, iomap);
	return written;
}

DEFINE_IOMAP_ITER_NEXT_END(ntfs_write_iomap_next, ntfs_write_iomap_begin,
		ntfs_write_iomap_end);

/*
 * Keep the errno until the caller has released its invalidate lock.
 * In particular, iomap_end errors must not disappear after a mapped extent.
 */
int ntfs_iomap_page_mkwrite(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct folio *folio = page_folio(vmf->page);
	const unsigned int flags = IOMAP_WRITE | IOMAP_FAULT;
	loff_t pos, length;
	int err;

	folio_lock(folio);
	length = folio_mkwrite_check_truncate(folio, inode);
	pos = folio_pos(folio);
	if (length < 0) {
		err = length;
		goto out_unlock;
	}
	if (WARN_ON_ONCE(!folio_test_uptodate(folio))) {
		err = -EIO;
		goto out_unlock;
	}

	while (length) {
		struct iomap iomap = { };
		loff_t mapped;

		err = __ntfs_write_iomap_begin(inode, pos, length, flags, &iomap,
				NTFS_IOMAP_FLAGS_MKWRITE);
		if (err)
			goto out_unlock;
		if (WARN_ON_ONCE(iomap.offset > (u64)pos ||
				pos - iomap.offset >= iomap.length)) {
			ntfs_write_iomap_end(inode, pos, length, 0, flags, &iomap);
			err = -EIO;
			goto out_unlock;
		}
		mapped = min_t(u64, length,
				iomap.length - (pos - iomap.offset));
		folio_mark_dirty(folio);
		err = ntfs_write_iomap_end(inode, pos, mapped, mapped, flags,
				&iomap);
		if (err < 0)
			goto out_unlock;
		pos += mapped;
		length -= mapped;
	}
	folio_wait_stable(folio);
	return 0;

out_unlock:
	folio_unlock(folio);
	return err;
}

static int ntfs_dio_iomap_begin(struct inode *inode, loff_t offset,
				  loff_t length, unsigned int flags,
				  struct iomap *iomap, struct iomap *srcmap)
{
	int err;

	err = __ntfs_write_iomap_begin(inode, offset, length, flags, iomap,
			NTFS_IOMAP_FLAGS_DIO);
	/* Size or mapping metadata can have changed before this mapping. */
	if (!err)
		iomap->flags |= IOMAP_F_DIRTY;
	return err;
}

DEFINE_IOMAP_ITER_NEXT_END(ntfs_dio_iomap_next, ntfs_dio_iomap_begin,
		ntfs_write_iomap_end);

static ssize_t ntfs_writeback_range(struct iomap_writepage_ctx *wpc,
		struct folio *folio, u64 offset, unsigned int len, u64 end_pos)
{
	int error;

	if (offset < wpc->iomap.offset ||
	    offset >= wpc->iomap.offset + wpc->iomap.length) {
		error = __ntfs_write_iomap_begin(wpc->inode, offset,
				NTFS_I(wpc->inode)->allocated_size - offset,
				IOMAP_WRITE, &wpc->iomap,
				NTFS_IOMAP_FLAGS_WRITEBACK);
		if (error)
			return error;
	}

	return iomap_add_to_ioend(wpc, folio, offset, end_pos, len);
}

int ntfs_writeback_prepare_folio(struct inode *inode, struct folio *folio)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct iomap iomap = { };
	loff_t pos = folio_pos(folio);
	loff_t end = min_t(loff_t, pos + folio_size(folio),
			i_size_read(inode));
	int err;

	if (end > ni->data_size)
		end = ni->data_size;
	while (pos < end) {
		/* Match normal writeback's extent-sized DELALLOC conversion. */
		err = __ntfs_write_iomap_begin(inode, pos,
				ni->allocated_size - pos,
				IOMAP_WRITE, &iomap, NTFS_IOMAP_FLAGS_WRITEBACK);
		if (err)
			return err;
		if (!iomap.length || iomap.offset > (u64)pos ||
		    pos - iomap.offset >= iomap.length)
			return -EIO;
		pos += min_t(u64, end - pos,
				iomap.length - (pos - iomap.offset));
	}
	return 0;
}

static int ntfs_writeback_submit(struct iomap_writepage_ctx *wpc, int error)
{
	struct ntfs_writepage_ctx *ntfs_wpc =
		container_of(wpc, struct ntfs_writepage_ctx, wpc);

	return ntfs_log_ordered_writeback_submit(ntfs_wpc->ordered, wpc, error);
}

const struct iomap_writeback_ops ntfs_writeback_ops = {
	.writeback_range	= ntfs_writeback_range,
	.writeback_submit	= ntfs_writeback_submit,
};
