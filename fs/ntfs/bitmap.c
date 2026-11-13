// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS kernel bitmap handling.
 *
 * Copyright (c) 2004-2005 Anton Altaparmakov
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/slab.h>

#include "attrib.h"
#include "bitmap.h"
#include "logfile.h"
#include "ntfs.h"

/*
 * Check a $BadClus run against $Bitmap and optionally reserve its free bits.
 * This is only used during mount, before the free-space scan starts. The
 * scan will account for the repaired bits, so do not use the regular bitmap
 * setters, which wait for that scan and assume every bit changes state.
 * @free_bits counts only bits that were free, including on read-only mounts.
 */
int ntfs_bitmap_check_used(struct ntfs_volume *vol, s64 start, s64 count,
		bool repair, s64 *free_bits)
{
	struct address_space *mapping = vol->lcnbmp_ino->i_mapping;
	const unsigned int bits_per_page = PAGE_SIZE * BITS_PER_BYTE;
	struct folio *folio;
	u8 *bitmap;
	unsigned int bit, end, bits;
	s64 nr_free;

	if (start < 0 || count <= 0 || start >= vol->nr_clusters ||
	    count > vol->nr_clusters - start || NVolFreeClusterKnown(vol))
		return -EINVAL;
	if (repair && sb_rdonly(vol->sb))
		return -EROFS;

	while (count) {
		folio = ntfs_read_metadata_folio(mapping, start >> (PAGE_SHIFT + 3));
		if (IS_ERR(folio))
			return PTR_ERR(folio);

		folio_lock(folio);
		bitmap = kmap_local_folio(folio, 0);
		bit = start & (bits_per_page - 1);
		bits = min_t(s64, count, bits_per_page - bit);
		end = bit + bits;
		nr_free = 0;
		for (bit = find_next_zero_bit_le(bitmap, end, bit); bit < end;
		     bit = find_next_zero_bit_le(bitmap, end, bit + 1)) {
			nr_free++;
			if (repair)
				__set_bit_le(bit, bitmap);
		}
		kunmap_local(bitmap);
		if (repair && nr_free)
			folio_mark_dirty(folio);
		folio_unlock(folio);
		folio_put(folio);
		*free_bits += nr_free;
		start += bits;
		count -= bits;
	}
	return 0;
}

int ntfs_trim_fs(struct ntfs_volume *vol, struct fstrim_range *range)
{
	size_t buf_clusters;
	pgoff_t index, start_index, end_index;
	struct file_ra_state *ra;
	struct folio *folio;
	unsigned long *bitmap;
	char *kaddr;
	u64 end, trimmed = 0, start_buf, end_buf, end_cluster, page_cluster;
	u64 start_cluster = ntfs_bytes_to_cluster(vol, range->start);
	u32 dq = bdev_discard_granularity(vol->sb->s_bdev);
	int ret = 0;

	if (!dq)
		dq = vol->cluster_size;

	if (start_cluster >= vol->nr_clusters)
		return -EINVAL;

	if (range->len == (u64)-1)
		end_cluster = vol->nr_clusters;
	else {
		end_cluster = ntfs_bytes_to_cluster(vol,
				(range->start + range->len + vol->cluster_size - 1));
		if (end_cluster > vol->nr_clusters)
			end_cluster = vol->nr_clusters;
	}

	ra = kzalloc_obj(*ra, GFP_NOFS);
	if (!ra)
		return -ENOMEM;

	buf_clusters = PAGE_SIZE * 8;
	start_index = start_cluster / buf_clusters;
	end_index = DIV_ROUND_UP_ULL(end_cluster, buf_clusters);

	for (index = start_index; index < end_index; index++) {
		folio = ntfs_get_locked_folio(vol->lcnbmp_ino->i_mapping,
				index, end_index, ra);
		if (IS_ERR(folio)) {
			ret = PTR_ERR(folio);
			goto out_free;
		}

		kaddr = kmap_local_folio(folio, 0);
		bitmap = (unsigned long *)kaddr;

		page_cluster = (u64)index * buf_clusters;
		start_buf = max_t(u64, page_cluster, start_cluster);
		end_buf = min_t(u64, page_cluster + buf_clusters, end_cluster);

		end = start_buf;
		while (end < end_buf) {
			u64 aligned_start, aligned_end, aligned_count;
			u64 start = find_next_zero_bit(bitmap, end_buf - page_cluster,
					end - page_cluster) + page_cluster;
			if (start >= end_buf)
				break;

			end = find_next_bit(bitmap, end_buf - page_cluster,
					start - page_cluster) + page_cluster;

			aligned_start = ALIGN(ntfs_cluster_to_bytes(vol, start), dq);
			aligned_end = ALIGN_DOWN(ntfs_cluster_to_bytes(vol, end), dq);
			if (aligned_start >= aligned_end)
				continue;
			aligned_count = aligned_end - aligned_start;
			if (aligned_count >= range->minlen) {
				ret = blkdev_issue_discard(vol->sb->s_bdev, aligned_start >> 9,
						aligned_count >> 9, GFP_NOFS);
				if (ret)
					goto out_unmap;
				trimmed += aligned_count;
			}
		}

out_unmap:
		kunmap_local(kaddr);
		folio_unlock(folio);
		folio_put(folio);

		if (ret)
			goto out_free;
	}

	range->len = trimmed;

out_free:
	kfree(ra);
	return ret;
}

static int ntfs_bitmap_validate_mapping(struct ntfs_inode *ni, u64 start_bit,
		u64 end_bit)
{
	struct ntfs_volume *vol = ni->vol;
	s64 end_vcn = ((end_bit - 1) >> 3) >> vol->cluster_size_bits;
	s64 vcn = (start_bit >> 3) >> vol->cluster_size_bits;
	int err = 0;

	down_write(&ni->runlist.lock);
	while (vcn <= end_vcn) {
		struct runlist_element *rl;
		s64 clusters;
		s64 delta;
		s64 lcn;

		rl = ntfs_attr_find_vcn_nolock(ni, vcn, NULL);
		if (IS_ERR(rl)) {
			err = PTR_ERR(rl) == -ENOMEM ? -ENOMEM : -EIO;
			break;
		}
		delta = vcn - rl->vcn;
		if (rl->lcn < 0 || rl->length <= 0 || delta < 0 ||
		    delta >= rl->length ||
		    check_add_overflow(rl->lcn, delta, &lcn)) {
			err = -EIO;
			break;
		}
		clusters = min(end_vcn - vcn + 1, rl->length - delta);
		if (clusters <= 0 || clusters > vol->nr_clusters ||
		    lcn > vol->nr_clusters - clusters) {
			err = -EIO;
			break;
		}
		vcn += clusters;
	}
	up_write(&ni->runlist.lock);
	return err;
}

static int ntfs_bitmap_validate_run_core(struct inode *vi, s64 start_bit,
		s64 count, u8 value, s64 *first_mismatch)
{
	struct address_space *mapping;
	struct ntfs_inode *ni;
	unsigned long flags;
	u64 bitmap_bits;
	u64 bit_pos;
	u64 end_bit;
	u64 mismatch_bit;
	s64 bitmap_bytes;
	s64 remaining;

	if (!vi || start_bit < 0 || count < 0 || value > 1 ||
	    (count && start_bit > S64_MAX - count))
		return -EINVAL;
	if (!count)
		return 0;
	ni = NTFS_I(vi);
	read_lock_irqsave(&ni->size_lock, flags);
	bitmap_bytes = min_t(s64, i_size_read(vi), ni->initialized_size);
	bitmap_bytes = min(bitmap_bytes, ni->allocated_size);
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (bitmap_bytes < 0)
		return -EIO;
	if (check_mul_overflow((u64)bitmap_bytes, 8ULL, &bitmap_bits))
		return -E2BIG;
	end_bit = (u64)start_bit + count;
	if (end_bit > bitmap_bits)
		return -EIO;
	if (NInoNonResident(ni)) {
		int err = ntfs_bitmap_validate_mapping(ni, start_bit, end_bit);

		if (err)
			return err;
	}
	mapping = vi->i_mapping;
	bit_pos = start_bit;
	remaining = count;
	while (remaining) {
		unsigned long first = bit_pos & (PAGE_SIZE * 8 - 1);
		unsigned long bits = min_t(u64, remaining,
				PAGE_SIZE * 8 - first);
		unsigned long mismatch;
		unsigned long *bitmap;
		pgoff_t index = bit_pos >> (PAGE_SHIFT + 3);
		struct folio *folio;

		folio = read_mapping_folio(mapping, index, NULL);
		if (IS_ERR(folio))
			return PTR_ERR(folio);
		folio_lock(folio);
		/* Do not inspect a bitmap page while an older write is in flight. */
		folio_wait_writeback(folio);
		bitmap = kmap_local_folio(folio, 0);
		mismatch = value ?
			find_next_zero_bit(bitmap, first + bits, first) :
			find_next_bit(bitmap, first + bits, first);
		kunmap_local(bitmap);
		folio_unlock(folio);
		folio_put(folio);
		if (mismatch < first + bits) {
			mismatch_bit = bit_pos + mismatch - first;
			if (first_mismatch)
				*first_mismatch = mismatch_bit;
			return -EIO;
		}
		bit_pos += bits;
		remaining -= bits;
	}
	return 0;
}

int ntfs_bitmap_validate_run(struct inode *vi, s64 start_bit, s64 count,
		u8 value)
{
	return ntfs_bitmap_validate_run_core(vi, start_bit, count, value, NULL);
}

int ntfs_bitmap_validate_run_with_mismatch(struct inode *vi, s64 start_bit,
		s64 count, u8 value, s64 *first_mismatch)
{
	if (!first_mismatch)
		return -EINVAL;
	*first_mismatch = -1;
	return ntfs_bitmap_validate_run_core(vi, start_bit, count, value,
			first_mismatch);
}

/*
 * __ntfs_bitmap_set_bits_in_run - set a run of bits in a bitmap to a value
 * @vi:			vfs inode describing the bitmap
 * @start_bit:		first bit to set
 * @count:		number of bits to set
 * @value:		value to set the bits to (i.e. 0 or 1)
 * @is_rollback:	if 'true' this is a rollback operation
 *
 * Set @count bits starting at bit @start_bit in the bitmap described by the
 * vfs inode @vi to @value, where @value is either 0 or 1.
 *
 * @is_rollback should always be 'false', it is for internal use to rollback
 * errors.  You probably want to use ntfs_bitmap_set_bits_in_run() instead.
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_bitmap_set_bits_in_run_core(struct ntfs_log_handle *log_handle,
		struct inode *vi, const s64 start_bit, const s64 count,
		const u8 value, const bool is_rollback)
{
	bool own_log_handle = false;
	s64 cnt = count;
	pgoff_t index, end_index;
	struct address_space *mapping;
	struct folio *folio;
	u8 *kaddr;
	int pos, len, err, log_err;
	u8 bit;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;

	ntfs_debug("Entering for i_ino 0x%llx, start_bit 0x%llx, count 0x%llx, value %u.%s",
			ni->mft_no, (unsigned long long)start_bit,
			(unsigned long long)cnt, (unsigned int)value,
			is_rollback ? " (rollback)" : "");

	if (start_bit < 0 || cnt < 0 || value > 1 ||
	    (cnt && start_bit > S64_MAX - cnt))
		return -EINVAL;
	if (!cnt)
		return 0;

	if (!is_rollback && (vol->journal || log_handle)) {
		log_err = ntfs_bitmap_validate_run(vi, start_bit, count,
				value ? 0 : 1);
		if (log_err)
			return log_err;
		if (!vol->journal)
			return -EROFS;
		if (!log_handle) {
			log_err = ntfs_log_bitmap_update_credits(start_bit, count);
			if (log_err < 0)
				return log_err;
			log_handle = ntfs_log_begin_full_reservation(vol, log_err);
			if (IS_ERR(log_handle))
				return PTR_ERR(log_handle);
			own_log_handle = true;
		}
		log_err = ntfs_log_bitmap_update(log_handle, vi, start_bit,
				count, value);
		if (log_err) {
			if (own_log_handle)
				ntfs_log_abort(log_handle);
			return log_err;
		}
	}

	/*
	 * Calculate the indices for the pages containing the first and last
	 * bits, i.e. @start_bit and @start_bit + @cnt - 1, respectively.
	 */
	index = start_bit >> (3 + PAGE_SHIFT);
	end_index = (start_bit + cnt - 1) >> (3 + PAGE_SHIFT);

	/* Get the page containing the first bit (@start_bit). */
	mapping = vi->i_mapping;
	folio = ntfs_read_metadata_folio(mapping, index);
	if (IS_ERR(folio)) {
		if (!is_rollback)
			ntfs_error(vi->i_sb,
				"Failed to map first page (error %li), aborting.",
				PTR_ERR(folio));
		err = PTR_ERR(folio);
		goto rollback;
	}

	folio_lock(folio);
	/* Serialize a bitmap update with the previous page-cache write. */
	folio_wait_writeback(folio);
	kaddr = kmap_local_folio(folio, 0);

	/* Set @pos to the position of the byte containing @start_bit. */
	pos = (start_bit >> 3) & ~PAGE_MASK;

	/* Calculate the position of @start_bit in the first byte. */
	bit = start_bit & 7;

	/* If the first byte is partial, modify the appropriate bits in it. */
	if (bit) {
		u8 *byte = kaddr + pos;

		if (ni->mft_no == FILE_Bitmap)
			ntfs_set_lcn_empty_bits(vol, index, value, min_t(s64, 8 - bit, cnt));
		while ((bit & 7) && cnt) {
			cnt--;
			if (value)
				*byte |= 1 << bit++;
			else
				*byte &= ~(1 << bit++);
		}
		/* If we are done, unmap the page and return success. */
		if (!cnt)
			goto done;

		/* Update @pos to the new position. */
		pos++;
	}
	/*
	 * Depending on @value, modify all remaining whole bytes in the page up
	 * to @cnt.
	 */
	len = min_t(s64, cnt >> 3, PAGE_SIZE - pos);
	memset(kaddr + pos, value ? 0xff : 0, len);
	cnt -= len << 3;
	if (ni->mft_no == FILE_Bitmap)
		ntfs_set_lcn_empty_bits(vol, index, value, len << 3);

	/* Update @len to point to the first not-done byte in the page. */
	if (cnt < 8)
		len += pos;

	/* If we are not in the last page, deal with all subsequent pages. */
	while (index < end_index) {
		if (cnt <= 0) {
			err = -EIO;
			goto rollback;
		}

		/* Update @index and get the next folio. */
		folio_mark_dirty(folio);
		folio_unlock(folio);
		kunmap_local(kaddr);
		folio_put(folio);
		folio = ntfs_read_metadata_folio(mapping, ++index);
		if (IS_ERR(folio)) {
			ntfs_error(vi->i_sb,
				   "Failed to map subsequent page (error %li), aborting.",
				   PTR_ERR(folio));
			err = PTR_ERR(folio);
			goto rollback;
		}

		folio_lock(folio);
		folio_wait_writeback(folio);
		kaddr = kmap_local_folio(folio, 0);
		/*
		 * Depending on @value, modify all remaining whole bytes in the
		 * page up to @cnt.
		 */
		len = min_t(s64, cnt >> 3, PAGE_SIZE);
		memset(kaddr, value ? 0xff : 0, len);
		cnt -= len << 3;
		if (ni->mft_no == FILE_Bitmap)
			ntfs_set_lcn_empty_bits(vol, index, value, len << 3);
	}
	/*
	 * The currently mapped page is the last one.  If the last byte is
	 * partial, modify the appropriate bits in it.  Note, @len is the
	 * position of the last byte inside the page.
	 */
	if (cnt) {
		u8 *byte;

		WARN_ON(cnt > 7);

		bit = cnt;
		byte = kaddr + len;
		if (ni->mft_no == FILE_Bitmap)
			ntfs_set_lcn_empty_bits(vol, index, value, bit);
		while (bit--) {
			if (value)
				*byte |= 1 << bit;
			else
				*byte &= ~(1 << bit);
		}
	}
done:
	/* We are done.  Unmap the folio and return success. */
	folio_mark_dirty(folio);
	folio_unlock(folio);
	kunmap_local(kaddr);
	folio_put(folio);
	ntfs_debug("Done.");
	if (own_log_handle) {
		log_err = ntfs_log_commit(log_handle);
		if (log_err) {
			pos = ntfs_bitmap_set_bits_in_run_core(NULL, vi, start_bit,
					count, value ? 0 : 1, true);
			if (pos) {
				ntfs_error(vi->i_sb,
					"Failed to rollback bitmap after journal commit error %i (rollback error %i).",
					log_err, pos);
				NVolSetErrors(vol);
			}
			return log_err;
		}
	}
	return 0;
rollback:
	/*
	 * Current state:
	 *	- no pages are mapped
	 *	- @count - @cnt is the number of bits that have been modified
	 */
	if (is_rollback)
		return err;
	if (count != cnt)
		pos = ntfs_bitmap_set_bits_in_run_core(NULL, vi, start_bit,
				count - cnt, value ? 0 : 1, true);
	else
		pos = 0;
	if (!pos) {
		/* Rollback was successful. */
		ntfs_error(vi->i_sb,
			"Failed to map subsequent page (error %i), aborting.",
			err);
	} else {
		/* Rollback failed. */
		ntfs_error(vi->i_sb,
			"Failed to map subsequent page (error %i) and rollback failed (error %i). Aborting and leaving inconsistent metadata. Unmount and run chkdsk.",
			err, pos);
		NVolSetErrors(NTFS_SB(vi->i_sb));
	}
	if (own_log_handle) {
		log_err = ntfs_log_abort(log_handle);
		if (log_err) {
			ntfs_error(vi->i_sb,
				"Failed to abort bitmap journal transaction (error %i).",
				log_err);
			NVolSetErrors(vol);
		}
	}
	return err;
}

int __ntfs_bitmap_set_bits_in_run(struct inode *vi, const s64 start_bit,
		const s64 count, const u8 value, const bool is_rollback)
{
	return ntfs_bitmap_set_bits_in_run_core(NULL, vi, start_bit, count,
			value, is_rollback);
}

int ntfs_bitmap_set_bits_in_run_transacted(struct ntfs_log_handle *handle,
		struct inode *vi, s64 start_bit, s64 count, u8 value)
{
	if (!handle || !vi)
		return -EINVAL;
	return ntfs_bitmap_set_bits_in_run_core(handle, vi, start_bit, count,
			value, false);
}
