// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Cluster (de)allocation code.
 *
 * Copyright (c) 2004-2005 Anton Altaparmakov
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 *
 * Part of this file is based on code from the NTFS-3G.
 * and is copyrighted by the respective authors below:
 * Copyright (c) 2002-2004 Anton Altaparmakov
 * Copyright (c) 2004 Yura Pakhuchiy
 * Copyright (c) 2004-2008 Szabolcs Szakacsits
 * Copyright (c) 2008-2009 Jean-Pierre Andre
 */

#include <linux/blkdev.h>
#include <linux/sort.h>

#include "lcnalloc.h"
#include "bitmap.h"
#include "logfile.h"
#include "ntfs.h"

struct ntfs_cluster_alloc_undo {
	struct ntfs_volume *vol;
	s64 delayed_clusters;
	struct runlist_element rl[];
};

struct ntfs_cluster_free_undo {
	struct ntfs_volume *vol;
	unsigned int nr_runs;
	unsigned int nr_logged;
	struct runlist_element rl[];
};

#define NTFS_CLUSTER_FREE_MAX_RUNS	1024

static int ntfs_cluster_free_run_compare(const void *left, const void *right)
{
	const struct runlist_element *a = left;
	const struct runlist_element *b = right;

	if (a->lcn < b->lcn)
		return -1;
	if (a->lcn > b->lcn)
		return 1;
	if (a->length < b->length)
		return -1;
	return a->length > b->length;
}

static int ntfs_cluster_free_from_rl_nolock_core(struct ntfs_volume *vol,
		const struct runlist_element *rl, bool is_rollback);

static int ntfs_cluster_alloc_home_restore(void *data)
{
	struct ntfs_cluster_alloc_undo *undo = data;

	if (!undo || !undo->vol)
		return -EINVAL;
	/*
	 * Restore the DELALLOC charge before the runlist is restored. The
	 * allocated bits remain unavailable until the CLR is durable.
	 */
	if (undo->delayed_clusters) {
		down_write(&undo->vol->lcnbmp_lock);
		ntfs_hold_dirty_clusters(undo->vol, undo->delayed_clusters);
		undo->delayed_clusters = 0;
		up_write(&undo->vol->lcnbmp_lock);
	}
	return 0;
}

static int ntfs_cluster_alloc_home_abort(void *data)
{
	struct ntfs_cluster_alloc_undo *undo = data;
	unsigned int memalloc_flags;
	s64 first_mismatch = -1;
	const struct runlist_element *rl;
	int err = 0;

	if (!undo || !undo->vol)
		return -EINVAL;
	memalloc_flags = memalloc_nofs_save();
	down_write(&undo->vol->lcnbmp_lock);
	for (rl = undo->rl; rl->length; rl++) {
		err = ntfs_bitmap_validate_run_with_mismatch(
				undo->vol->lcnbmp_ino, rl->lcn, rl->length, 1,
				&first_mismatch);
		if (err) {
			if (first_mismatch >= 0)
				ntfs_error(undo->vol->sb,
					   "Aborted cluster-allocation bitmap validation failed for LCN %lld, length %lld (first mismatched LCN %lld, error %d).",
					   (long long)rl->lcn,
					   (long long)rl->length,
					   (long long)first_mismatch, err);
			else
				ntfs_error(undo->vol->sb,
					   "Aborted cluster-allocation bitmap validation failed for LCN %lld, length %lld (error %d).",
					   (long long)rl->lcn,
					   (long long)rl->length, err);
			goto out_unlock;
		}
	}
	err = ntfs_cluster_free_from_rl_nolock_core(undo->vol, undo->rl,
			true);
out_unlock:
	up_write(&undo->vol->lcnbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	return err;
}

static void ntfs_cluster_alloc_home_release(void *data)
{
	kfree(data);
}

static int ntfs_cluster_register_alloc_undo(struct ntfs_log_handle *handle,
		struct ntfs_volume *vol, const struct runlist_element *rl,
		int nr_runs, s64 delayed_clusters)
{
	struct ntfs_cluster_alloc_undo *undo;
	size_t bytes;
	int err;

	if (!handle || !vol || !rl || nr_runs <= 0 || delayed_clusters < 0)
		return -EINVAL;
	lockdep_assert_held_write(&vol->lcnbmp_lock);
	bytes = struct_size(undo, rl, nr_runs + 1);
	undo = kmalloc(bytes, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->vol = vol;
	undo->delayed_clusters = delayed_clusters;
	memcpy(undo->rl, rl, (nr_runs + 1) * sizeof(*rl));
	if (delayed_clusters &&
	    !ntfs_consume_dirty_clusters(vol, delayed_clusters)) {
		ntfs_error(vol->sb,
			   "Insufficient delayed allocation charge for %lld allocated clusters.",
			   (long long)delayed_clusters);
		NVolSetErrors(vol);
		ntfs_cluster_alloc_home_release(undo);
		return -EIO;
	}
	err = ntfs_log_register_home_undo_with_abort(handle,
			ntfs_cluster_alloc_home_restore,
			ntfs_cluster_alloc_home_abort,
			ntfs_cluster_alloc_home_release, undo);
	if (err) {
		if (delayed_clusters)
			ntfs_hold_dirty_clusters(vol, delayed_clusters);
		ntfs_cluster_alloc_home_release(undo);
	}
	return err;
}

static int ntfs_cluster_free_home_restore(void *data)
{
	if (!data)
		return -EINVAL;
	/*
	 * Freed bits stay allocated in the home bitmap until commit, so abort
	 * has no bitmap state to restore.
	 */
	return 0;
}

static int ntfs_cluster_free_home_commit(void *data)
{
	struct ntfs_cluster_free_undo *undo = data;
	unsigned int memalloc_flags;
	s64 freed = 0;
	s64 first_mismatch = -1;
	unsigned int i;
	int err = 0;

	if (!undo || !undo->vol)
		return -EINVAL;
	if (undo->nr_logged != undo->nr_runs) {
		ntfs_error(undo->vol->sb,
			   "Committed cluster-free transaction logged %u of %u runs.",
			   undo->nr_logged, undo->nr_runs);
		return -EIO;
	}
	memalloc_flags = memalloc_nofs_save();
	down_write(&undo->vol->lcnbmp_lock);
	for (i = 0; i < undo->nr_logged; i++) {
		err = ntfs_bitmap_validate_run_with_mismatch(
				undo->vol->lcnbmp_ino, undo->rl[i].lcn,
				undo->rl[i].length, 1, &first_mismatch);
		if (err) {
			ntfs_error(undo->vol->sb,
				   "Committed cluster-free bitmap validation failed for LCN %lld, length %lld (first mismatched LCN %lld, error %d).",
				   (long long)undo->rl[i].lcn,
				   (long long)undo->rl[i].length,
				   (long long)first_mismatch, err);
			goto out_unlock;
		}
	}
	for (i = 0; i < undo->nr_logged; i++) {
		err = __ntfs_bitmap_set_bits_in_run(undo->vol->lcnbmp_ino,
				undo->rl[i].lcn, undo->rl[i].length, 0, true);
		if (err) {
			ntfs_error(undo->vol->sb,
				   "Failed to apply committed cluster free for LCN %lld, length %lld (error %d).",
				   (long long)undo->rl[i].lcn,
				   (long long)undo->rl[i].length, err);
			goto out_unlock;
		}
		freed += undo->rl[i].length;
	}
	ntfs_inc_free_clusters(undo->vol, freed);
out_unlock:
	up_write(&undo->vol->lcnbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	return err;
}

static void ntfs_cluster_free_home_release(void *data)
{
	kvfree(data);
}

static int ntfs_cluster_register_free_undo(struct ntfs_log_handle *handle,
		struct ntfs_volume *vol, const struct runlist_element *rl,
		unsigned int nr_runs, struct ntfs_cluster_free_undo **undo_out)
{
	struct ntfs_cluster_free_undo *undo;
	size_t bytes;
	u64 units = 0;
	unsigned int i;
	int err;

	if (!handle || !vol || !rl || !nr_runs || !undo_out)
		return -EINVAL;
	bytes = struct_size(undo, rl, nr_runs);
	undo = kvmalloc(bytes, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->vol = vol;
	undo->nr_runs = nr_runs;
	undo->nr_logged = 0;
	memcpy(undo->rl, rl, nr_runs * sizeof(*rl));
	sort(undo->rl, nr_runs, sizeof(*undo->rl),
			ntfs_cluster_free_run_compare, NULL);
	for (i = 0; i < nr_runs; i++) {
		if (undo->rl[i].length <= 0 ||
		    check_add_overflow(units, (u64)undo->rl[i].length, &units)) {
			ntfs_error(vol->sb, "Invalid cluster-free run length.");
			ntfs_cluster_free_home_release(undo);
			return -EIO;
		}
	}
	for (i = 1; i < nr_runs; i++) {
		s64 previous_end;

		if (check_add_overflow(undo->rl[i - 1].lcn,
				undo->rl[i - 1].length, &previous_end)) {
			ntfs_error(vol->sb,
				   "Invalid cluster-free run at LCN %lld, length %lld.",
				   (long long)undo->rl[i - 1].lcn,
				   (long long)undo->rl[i - 1].length);
			ntfs_cluster_free_home_release(undo);
			return -EIO;
		}
		if (undo->rl[i].lcn < previous_end) {
			ntfs_error(vol->sb,
				   "Overlapping cluster-free runs at LCN %lld (previous run ends at %lld).",
				   (long long)undo->rl[i].lcn,
				   (long long)previous_end);
			ntfs_cluster_free_home_release(undo);
			return -EIO;
		}
	}
	err = ntfs_log_register_deferred_free(handle,
			ntfs_cluster_free_home_restore,
			ntfs_cluster_free_home_commit,
			ntfs_cluster_free_home_release, undo,
			NTFS_LOG_DEFERRED_CLUSTERS, units, bytes);
	if (err) {
		ntfs_cluster_free_home_release(undo);
		return err;
	}
	*undo_out = undo;
	return 0;
}

/*
 * ntfs_cluster_free_from_rl_nolock - free clusters from runlist
 * @vol:	mounted ntfs volume on which to free the clusters
 * @rl:		runlist describing the clusters to free
 *
 * Free all the clusters described by the runlist @rl on the volume @vol.  In
 * the case of an error being returned, at least some of the clusters were not
 * freed.
 *
 * Return 0 on success and -errno on error.
 *
 * Locking: - The volume lcn bitmap must be locked for writing on entry and is
 *	      left locked on return.
 */
static int ntfs_cluster_free_from_rl_nolock_core(struct ntfs_volume *vol,
		const struct runlist_element *rl, bool is_rollback)
{
	struct inode *lcnbmp_vi = vol->lcnbmp_ino;
	int ret = 0;
	s64 nr_freed = 0;

	ntfs_debug("Entering.");
	if (!rl)
		return 0;

	if (!NVolFreeClusterKnown(vol))
		wait_event(vol->free_waitq, NVolFreeClusterKnown(vol));

	for (; rl->length; rl++) {
		int err;

		if (rl->lcn < 0)
			continue;
		err = __ntfs_bitmap_set_bits_in_run(lcnbmp_vi, rl->lcn,
				rl->length, 0, is_rollback);
		if (unlikely(err)) {
			if (!ret || ret == -ENOMEM)
				ret = err;
		} else {
			nr_freed += rl->length;
		}
	}
	ntfs_inc_free_clusters(vol, nr_freed);
	ntfs_debug("Done.");
	return ret;
}

int ntfs_cluster_free_from_rl_nolock(struct ntfs_volume *vol,
		const struct runlist_element *rl)
{
	if (!vol)
		return -EINVAL;
	if (vol->journal)
		return -EOPNOTSUPP;
	return ntfs_cluster_free_from_rl_nolock_core(vol, rl, false);
}

static s64 max_empty_bit_range(const unsigned char *buf, int start, int end)
{
	int pos = start, run = 0;
	int max_range = 0;
	s64 start_pos = -1;

	ntfs_debug("Entering\n");

	while (pos < end) {
		int bits = min_t(int, 8 - (pos & 7), end - pos);
		unsigned int mask = ((1U << bits) - 1) << (pos & 7);
		unsigned int used = buf[pos >> 3] & mask;

		if (!used) {
			run += bits;
			pos += bits;
		} else if (used == mask) {
			if (run > max_range) {
				max_range = run;
				start_pos = pos - run;
			}
			run = 0;
			pos += bits;
		} else {
			int last = pos + bits;

			while (pos < last) {
				if (buf[pos >> 3] & (1U << (pos & 7))) {
					if (run > max_range) {
						max_range = run;
						start_pos = pos - run;
					}
					run = 0;
				} else {
					run++;
				}
				pos++;
			}
		}
	}

	if (run > max_range)
		start_pos = end - run;

	return start_pos;
}

/*
 * ntfs_cluster_alloc_core - allocate clusters on an ntfs volume
 *
 * @log_handle: caller-owned journal transaction or NULL
 * @vol:		mounted ntfs volume on which to allocate clusters
 * @start_vcn:		vcn of the first allocated cluster
 * @count:		number of clusters to allocate
 * @min_count:		minimum number of clusters accepted for a partial allocation
 * @start_lcn:		starting lcn at which to allocate the clusters or -1 if none
 * @zone:		zone from which to allocate (MFT_ZONE or DATA_ZONE)
 * @is_extension:	if true, the caller is extending an attribute
 * @is_contig:		if true, require contiguous allocation
 * @is_dealloc:		if true, the allocation is for deallocation purposes
 * @max_runs:		maximum runs for partial allocation, or zero for no limit
 * @max_bitmap_updates:	maximum logged bitmap ranges, or zero for no limit
 *
 * A transactional caller may set @min_count below @count to accept a shorter
 * allocation after the selected zones are exhausted.  If fewer than
 * @min_count clusters are found, the caller must abort the handle.
 *
 * Allocate @count clusters preferably starting at cluster @start_lcn or at the
 * current allocator position if @start_lcn is -1, on the mounted ntfs volume
 * @vol. @zone is either DATA_ZONE for allocation of normal clusters or
 * MFT_ZONE for allocation of clusters for the master file table, i.e. the
 * $MFT/$DATA attribute.
 *
 * @start_vcn specifies the vcn of the first allocated cluster.  This makes
 * merging the resulting runlist with the old runlist easier.
 *
 * If @is_extension is 'true', the caller is allocating clusters to extend an
 * attribute and if it is 'false', the caller is allocating clusters to fill a
 * hole in an attribute.  Practically the difference is that if @is_extension
 * is 'true' the returned runlist will be terminated with LCN_ENOENT and if
 * @is_extension is 'false' the runlist will be terminated with
 * LCN_RL_NOT_MAPPED.
 *
 * You need to check the return value with IS_ERR().  If this is false, the
 * function was successful and the return value is a runlist describing the
 * allocated cluster(s).  If IS_ERR() is true, the function failed and
 * PTR_ERR() gives you the error code.
 *
 * Notes on the allocation algorithm
 * =================================
 *
 * There are two data zones.  First is the area between the end of the mft zone
 * and the end of the volume, and second is the area between the start of the
 * volume and the start of the mft zone.  On unmodified/standard NTFS 1.x
 * volumes, the second data zone does not exist due to the mft zone being
 * expanded to cover the start of the volume in order to reserve space for the
 * mft bitmap attribute.
 *
 * This is not the prettiest function but the complexity stems from the need of
 * implementing the mft vs data zoned approach and from the fact that we have
 * access to the lcn bitmap in portions of up to 8192 bytes at a time, so we
 * need to cope with crossing over boundaries of two buffers.  Further, the
 * fact that the allocator allows for caller supplied hints as to the location
 * of where allocation should begin and the fact that the allocator keeps track
 * of where in the data zones the next natural allocation should occur,
 * contribute to the complexity of the function.  But it should all be
 * worthwhile, because this allocator should: 1) be a full implementation of
 * the MFT zone approach used by Windows NT, 2) cause reduction in
 * fragmentation, and 3) be speedy in allocations (the code is not optimized
 * for speed, but the algorithm is, so further speed improvements are probably
 * possible).
 *
 * Locking: - The volume lcn bitmap must be unlocked on entry and is unlocked
 *	      on return.
 *	    - This function takes the volume lcn bitmap lock for writing and
 *	      modifies the bitmap contents.
 *
 * Return: Runlist describing the allocated cluster(s) on success, error pointer
 *         on failure.
 */
static struct runlist_element *ntfs_cluster_alloc_core(
		struct ntfs_log_handle *log_handle, struct ntfs_volume *vol,
		const s64 start_vcn,
		const s64 count, const s64 min_count, const s64 start_lcn,
		const int zone,
		const bool is_extension,
		const bool is_contig,
		const bool is_dealloc,
		const unsigned int max_runs,
		const unsigned int max_bitmap_updates)
{
	s64 zone_start, zone_end, bmp_pos, bmp_initial_pos, last_read_pos, lcn;
	s64 prev_lcn = 0, prev_run_len = 0, mft_zone_size;
	s64 clusters, free_clusters, allocation_count;
	loff_t i_size;
	struct inode *lcnbmp_vi;
	struct runlist_element *rl = NULL;
	struct address_space *mapping;
	struct folio *folio = NULL;
	u8 *buf = NULL, *byte;
	int err = 0, rlpos, rlsize, buf_size, pg_off, buf_first;
	int run_len, run_limit, run_off;
	u8 pass, done_zones, search_zone, need_writeback = 0, bit;
	unsigned int bitmap_updates = max_bitmap_updates;
	unsigned int memalloc_flags;
	u8 has_guess, used_zone_pos;
	pgoff_t index;
	bool exhausted = false;

	ntfs_debug("Entering for start_vcn 0x%llx, count 0x%llx, start_lcn 0x%llx, zone %s_ZONE.",
			start_vcn, count, start_lcn,
			zone == MFT_ZONE ? "MFT" : "DATA");

	lcnbmp_vi = vol->lcnbmp_ino;
	if (start_vcn < 0 || start_lcn < LCN_HOLE ||
	    zone < FIRST_ZONE || zone > LAST_ZONE)
		return ERR_PTR(-EINVAL);

	/* Return NULL if @count is zero. */
	if (count <= 0 || min_count <= 0 || min_count > count ||
	    (max_runs && (!log_handle || min_count > max_runs)) ||
	    (max_bitmap_updates && (!log_handle || min_count > max_bitmap_updates)))
		return ERR_PTR(-EINVAL);

	memalloc_flags = memalloc_nofs_save();

	if (!NVolFreeClusterKnown(vol))
		wait_event(vol->free_waitq, NVolFreeClusterKnown(vol));
	if (READ_ONCE(vol->journal)) {
		s64 available = atomic64_read(&vol->free_clusters);

		if (!is_dealloc)
			available = ntfs_available_clusters(vol);
		/*
		 * A one-cluster minimum can use any free run.  Wait for
		 * pending frees when space is short or when a multi-cluster
		 * contiguous request might need a larger free run.
		 */
		err = ntfs_log_reclaim_deferred(vol,
				NTFS_LOG_DEFERRED_CLUSTERS, available, min_count,
				is_contig && min_count > 1);
		if (err)
			goto out_memalloc;
	}

	/* Take the lcnbmp lock for writing. */
	down_write(&vol->lcnbmp_lock);
	free_clusters = atomic64_read(&vol->free_clusters);
	if (!is_dealloc)
		free_clusters -= atomic64_read(&vol->dirty_clusters);

	if (free_clusters < min_count) {
		err = -ENOSPC;
		ntfs_debug(
			"Cluster allocation reports no space (free clusters %lld, dirty clusters %lld, requested %lld, minimum %lld, total clusters %lld, zone %s).",
			(long long)atomic64_read(&vol->free_clusters),
			(long long)atomic64_read(&vol->dirty_clusters),
			(long long)count, (long long)min_count,
			(long long)vol->nr_clusters,
			zone == MFT_ZONE ? "MFT" : "DATA");
		goto out_restore;
	}

	/*
	 * If no specific @start_lcn was requested, use the current data zone
	 * position, otherwise use the requested @start_lcn but make sure it
	 * lies outside the mft zone.  Also set done_zones to 0 (no zones done)
	 * and pass depending on whether we are starting inside a zone (1) or
	 * at the beginning of a zone (2).  If requesting from the MFT_ZONE,
	 * we either start at the current position within the mft zone or at
	 * the specified position.  If the latter is out of bounds then we start
	 * at the beginning of the MFT_ZONE.
	 */
	done_zones = 0;
	pass = 1;
	/*
	 * zone_start and zone_end are the current search range.  search_zone
	 * is 1 for mft zone, 2 for data zone 1 (end of mft zone till end of
	 * volume) and 4 for data zone 2 (start of volume till start of mft
	 * zone).
	 */
	has_guess = 1;
	zone_start = start_lcn;

	if (zone_start < 0) {
		if (zone == DATA_ZONE)
			zone_start = vol->data1_zone_pos;
		else
			zone_start = vol->mft_zone_pos;
		if (!zone_start) {
			/*
			 * Zone starts at beginning of volume which means a
			 * single pass is sufficient.
			 */
			pass = 2;
		}
		has_guess = 0;
	}

	used_zone_pos = has_guess ? 0 : 1;

	if (!zone_start || zone_start == vol->mft_zone_start ||
			zone_start == vol->mft_zone_end)
		pass = 2;

	if (zone_start < vol->mft_zone_start) {
		zone_end = vol->mft_zone_start;
		search_zone = 4;
		/* Skip searching the mft zone. */
		done_zones |= 1;
	} else if (zone_start < vol->mft_zone_end) {
		zone_end = vol->mft_zone_end;
		search_zone = 1;
	} else {
		zone_end = vol->nr_clusters;
		search_zone = 2;
		/* Skip searching the mft zone. */
		done_zones |= 1;
	}

	/*
	 * bmp_pos is the current bit position inside the bitmap.  We use
	 * bmp_initial_pos to determine whether or not to do a zone switch.
	 */
	bmp_pos = bmp_initial_pos = zone_start;

	/* Loop until all clusters are allocated, i.e. clusters == 0. */
	allocation_count = min_t(s64, count, free_clusters);
	clusters = allocation_count;
	rlpos = rlsize = 0;
	mapping = lcnbmp_vi->i_mapping;
	/*
	 * lcn_empty_bits_per_page is sized from nr_clusters, but $Bitmap can
	 * cover more clusters than that; bound the scan by the array.
	 */
	i_size = min_t(s64, i_size_read(lcnbmp_vi),
		       ((s64)vol->nr_clusters + 7) >> 3);
	while (1) {
		ntfs_debug("Start of outer while loop: done_zones 0x%x, search_zone %i, pass %i, zone_start 0x%llx, zone_end 0x%llx, bmp_initial_pos 0x%llx, bmp_pos 0x%llx, rlpos %i, rlsize %i.",
				done_zones, search_zone, pass,
				zone_start, zone_end, bmp_initial_pos,
				bmp_pos, rlpos, rlsize);
		/* Loop until we run out of free clusters. */
		last_read_pos = bmp_pos >> 3;
		ntfs_debug("last_read_pos 0x%llx.", last_read_pos);
		if (last_read_pos >= i_size) {
			ntfs_debug("End of attribute reached. Skipping to zone_pass_done.");
			goto zone_pass_done;
		}
		if (likely(folio)) {
			if (need_writeback) {
				ntfs_debug("Marking page dirty.");
				folio_mark_dirty(folio);
				need_writeback = 0;
			}
			folio_unlock(folio);
			kunmap_local(buf);
			folio_put(folio);
			folio = NULL;
		}

		index = last_read_pos >> PAGE_SHIFT;
		pg_off = last_read_pos & ~PAGE_MASK;
		buf_size = PAGE_SIZE - pg_off;
		if (unlikely(last_read_pos + buf_size > i_size))
			buf_size = i_size - last_read_pos;
		buf_size <<= 3;
		lcn = bmp_pos & 7;
		buf_first = lcn;
		bmp_pos &= ~(s64)7;

		if (vol->lcn_empty_bits_per_page[index] == 0)
			goto next_bmp_pos;

		folio = ntfs_read_metadata_folio(mapping, index);
		if (IS_ERR(folio)) {
			err = PTR_ERR(folio);
			ntfs_error(vol->sb, "Failed to map page.");
			goto out;
		}

		folio_lock(folio);
		folio_wait_writeback(folio);
		buf = kmap_local_folio(folio, 0) + pg_off;
		ntfs_debug("Before inner while loop: buf_size %i, lcn 0x%llx, bmp_pos 0x%llx, need_writeback %i.",
				buf_size, lcn, bmp_pos, need_writeback);
		while (lcn < buf_size && lcn + bmp_pos < zone_end) {
			byte = buf + (lcn >> 3);
			ntfs_debug("In inner while loop: buf_size %i, lcn 0x%llx, bmp_pos 0x%llx, need_writeback %i, byte ofs 0x%x, *byte 0x%x.",
					buf_size, lcn, bmp_pos, need_writeback,
					(unsigned int)(lcn >> 3),
					(unsigned int)*byte);
			bit = 1 << (lcn & 7);
			ntfs_debug("bit 0x%x.", bit);

			if (has_guess) {
				if (*byte & bit) {
					if (is_contig == true && prev_run_len > 0)
						goto done;

					has_guess = 0;
					if (!used_zone_pos)
						break;
					/* Other free runs can share this page. */
					continue;
				}
			} else {
				int end = min_t(s64, buf_size, zone_end - bmp_pos);

				lcn = max_empty_bit_range(buf, buf_first, end);
				if (lcn < 0)
					break;
				has_guess = 1;
				continue;
			}
			/* Zone wraps and skipped bitmap pages can break a run. */
			if (is_contig && rlpos &&
			    prev_lcn + prev_run_len != lcn + bmp_pos)
				goto out;
			if (max_runs && (unsigned int)rlpos >= max_runs &&
			    prev_lcn + prev_run_len != lcn + bmp_pos)
				goto out;
			/*
			 * A contiguous request gets a single run.  The scan can
			 * move on without testing the clusters after the run
			 * (past a bitmap page that is full, to pass 2 or to
			 * another zone), so return the run when this cluster
			 * does not follow it.
			 */
			if (is_contig && rlpos &&
			    lcn + bmp_pos != prev_lcn + prev_run_len)
				goto out;
			/*
			 * Allocate more memory if needed, including space for
			 * the terminator element.
			 * kvzalloc() operates on whole pages only.
			 */
			if ((rlpos + 2) * sizeof(*rl) > rlsize) {
				struct runlist_element *rl2;

				ntfs_debug("Reallocating memory.");
				if (!rl)
					ntfs_debug("First free bit is at s64 0x%llx.",
							lcn + bmp_pos);
				rl2 = kvzalloc(rlsize + PAGE_SIZE, GFP_NOFS);
				if (unlikely(!rl2)) {
					err = -ENOMEM;
					ntfs_error(vol->sb, "Failed to allocate memory.");
					goto out;
				}
				memcpy(rl2, rl, rlsize);
				kvfree(rl);
				rl = rl2;
				rlsize += PAGE_SIZE;
				ntfs_debug("Reallocated memory, rlsize 0x%x.",
						rlsize);
			}
			/*
			 * The bitmap page and allocation lock keep this range free
			 * until it is logged and marked.  Log one page-bounded run
			 * instead of issuing an operation for every cluster.
			 */
			run_len = 1;
			if (log_handle) {
				run_limit = min_t(s64, buf_size - lcn,
						zone_end - bmp_pos - lcn);
				run_limit = min_t(s64, run_limit, clusters);
				while (run_len < run_limit) {
					s64 next = lcn + run_len;

					if (buf[next >> 3] & (1U << (next & 7)))
						break;
					run_len++;
				}
				err = ntfs_log_bitmap_update(log_handle, lcnbmp_vi,
						lcn + bmp_pos, run_len, 1);
				if (err)
					goto out;
				if (max_bitmap_updates)
					bitmap_updates--;
			}
			for (run_off = 0; run_off < run_len; run_off++) {
				s64 next = lcn + run_off;

				buf[next >> 3] |= 1U << (next & 7);
			}
			/* We need to write this bitmap page to disk. */
			need_writeback = 1;
			ntfs_debug("*byte 0x%x, need_writeback is set.",
					(unsigned int)*byte);
			ntfs_dec_free_clusters(vol, run_len);
			ntfs_set_lcn_empty_bits(vol, index, 1, run_len);

			/*
			 * Coalesce with previous run if adjacent LCNs.
			 * Otherwise, append a new run.
			 */
			ntfs_debug("Adding run (lcn 0x%llx, len 0x%llx), prev_lcn 0x%llx, lcn 0x%llx, bmp_pos 0x%llx, prev_run_len 0x%llx, rlpos %i.",
					lcn + bmp_pos, (unsigned long long)run_len, prev_lcn,
					lcn, bmp_pos, prev_run_len, rlpos);
			if (prev_lcn == lcn + bmp_pos - prev_run_len && rlpos) {
				ntfs_debug("Coalescing to run (lcn 0x%llx, len 0x%llx).",
						rl[rlpos - 1].lcn,
						rl[rlpos - 1].length);
				prev_run_len += run_len;
				rl[rlpos - 1].length = prev_run_len;
				ntfs_debug("Run now (lcn 0x%llx, len 0x%llx), prev_run_len 0x%llx.",
						rl[rlpos - 1].lcn,
						rl[rlpos - 1].length,
						prev_run_len);
			} else {
				if (likely(rlpos)) {
					ntfs_debug("Adding new run, (previous run lcn 0x%llx, len 0x%llx).",
							rl[rlpos - 1].lcn, rl[rlpos - 1].length);
					rl[rlpos].vcn = rl[rlpos - 1].vcn +
							prev_run_len;
				} else {
					ntfs_debug("Adding new run, is first run.");
					rl[rlpos].vcn = start_vcn;
				}
				rl[rlpos].lcn = prev_lcn = lcn + bmp_pos;
				rl[rlpos].length = prev_run_len = run_len;
				rlpos++;
			}
			/* Done? */
			clusters -= run_len;
			if (!clusters || (max_bitmap_updates && !bitmap_updates)) {
				s64 tc;

				lcn += run_len - 1;
done:
				if (!used_zone_pos)
					goto out;
				/*
				 * Update the current zone position.  Positions
				 * of already scanned zones have been updated
				 * during the respective zone switches.
				 */
				tc = lcn + bmp_pos + 1;
				ntfs_debug("Done. Updating current zone position, tc 0x%llx, search_zone %i.",
						tc, search_zone);
				switch (search_zone) {
				case 1:
					ntfs_debug("Before checks, vol->mft_zone_pos 0x%llx.",
							vol->mft_zone_pos);
					if (tc >= vol->mft_zone_end) {
						vol->mft_zone_pos =
								vol->mft_lcn;
						if (!vol->mft_zone_end)
							vol->mft_zone_pos = 0;
					} else if ((bmp_initial_pos >=
							vol->mft_zone_pos ||
							tc > vol->mft_zone_pos)
							&& tc >= vol->mft_lcn)
						vol->mft_zone_pos = tc;
					ntfs_debug("After checks, vol->mft_zone_pos 0x%llx.",
							vol->mft_zone_pos);
					break;
				case 2:
					ntfs_debug("Before checks, vol->data1_zone_pos 0x%llx.",
							vol->data1_zone_pos);
					if (tc >= vol->nr_clusters)
						vol->data1_zone_pos =
							     vol->mft_zone_end;
					else if ((bmp_initial_pos >=
						    vol->data1_zone_pos ||
						    tc > vol->data1_zone_pos)
						    && tc >= vol->mft_zone_end)
						vol->data1_zone_pos = tc;
					ntfs_debug("After checks, vol->data1_zone_pos 0x%llx.",
							vol->data1_zone_pos);
					break;
				case 4:
					ntfs_debug("Before checks, vol->data2_zone_pos 0x%llx.",
							vol->data2_zone_pos);
					if (tc >= vol->mft_zone_start)
						vol->data2_zone_pos = 0;
					else if (bmp_initial_pos >=
						      vol->data2_zone_pos ||
						      tc > vol->data2_zone_pos)
						vol->data2_zone_pos = tc;
					ntfs_debug("After checks, vol->data2_zone_pos 0x%llx.",
							vol->data2_zone_pos);
					break;
				default:
					WARN_ON(1);
				}
				ntfs_debug("Finished.  Going to out.");
				goto out;
			}
			lcn += run_len;
		}

		if (!used_zone_pos) {
			/*
			 * Continue a contiguous hinted run on the next bitmap
			 * page, but do not switch zones after finding a run.
			 */
			if (is_contig && rlpos) {
				if (lcn == buf_size && bmp_pos + lcn < zone_end) {
					bmp_pos += buf_size;
					continue;
				}
				goto out;
			}
			/*
			 * Leaving @start_lcn for the zone position starts the
			 * zone over as if no hint had been given, even if the
			 * search had already reached pass 2, whose range ends
			 * at @start_lcn.
			 */
			used_zone_pos = 1;
			has_guess = 0;
			pass = 1;
			if (search_zone == 1) {
				zone_start = vol->mft_zone_pos;
				zone_end = vol->mft_zone_end;
			} else if (search_zone == 2) {
				zone_start = vol->data1_zone_pos;
				zone_end = vol->nr_clusters;
			} else {
				zone_start = vol->data2_zone_pos;
				zone_end = vol->mft_zone_start;
			}

			if (!zone_start || zone_start == vol->mft_zone_start ||
			    zone_start == vol->mft_zone_end)
				pass = 2;
			bmp_pos = zone_start;
		} else {
next_bmp_pos:
			bmp_pos += buf_size;
		}

		ntfs_debug("After inner while loop: buf_size 0x%x, lcn 0x%llx, bmp_pos 0x%llx, need_writeback %i.",
				buf_size, lcn, bmp_pos, need_writeback);
		if (bmp_pos < zone_end) {
			ntfs_debug("Continuing outer while loop, bmp_pos 0x%llx, zone_end 0x%llx.",
					bmp_pos, zone_end);
			continue;
		}
zone_pass_done:	/* Finished with the current zone pass. */
		ntfs_debug("At zone_pass_done, pass %i.", pass);
		if (pass == 1) {
			/*
			 * Now do pass 2, scanning the first part of the zone
			 * we omitted in pass 1.
			 */
			pass = 2;
			zone_end = zone_start;
			switch (search_zone) {
			case 1: /* mft_zone */
				zone_start = vol->mft_zone_start;
				break;
			case 2: /* data1_zone */
				zone_start = vol->mft_zone_end;
				break;
			case 4: /* data2_zone */
				zone_start = 0;
				break;
			default:
				WARN_ON(1);
			}
			/* Sanity check. */
			if (zone_end < zone_start)
				zone_end = zone_start;
			bmp_pos = zone_start;
			ntfs_debug("Continuing outer while loop, pass 2, zone_start 0x%llx, zone_end 0x%llx, bmp_pos 0x%llx.",
					zone_start, zone_end, bmp_pos);
			continue;
		} /* pass == 2 */
done_zones_check:
		ntfs_debug("At done_zones_check, search_zone %i, done_zones before 0x%x, done_zones after 0x%x.",
				search_zone, done_zones,
				done_zones | search_zone);
		done_zones |= search_zone;
		if (done_zones < 7) {
			ntfs_debug("Switching zone.");
			/* Now switch to the next zone we haven't done yet. */
			pass = 1;
			switch (search_zone) {
			case 1:
				ntfs_debug("Switching from mft zone to data1 zone.");
				/* Update mft zone position. */
				if (rlpos && used_zone_pos) {
					s64 tc;

					ntfs_debug("Before checks, vol->mft_zone_pos 0x%llx.",
							vol->mft_zone_pos);
					tc = rl[rlpos - 1].lcn +
							rl[rlpos - 1].length;
					if (tc >= vol->mft_zone_end) {
						vol->mft_zone_pos =
								vol->mft_lcn;
						if (!vol->mft_zone_end)
							vol->mft_zone_pos = 0;
					} else if ((bmp_initial_pos >=
							vol->mft_zone_pos ||
							tc > vol->mft_zone_pos)
							&& tc >= vol->mft_lcn)
						vol->mft_zone_pos = tc;
					ntfs_debug("After checks, vol->mft_zone_pos 0x%llx.",
							vol->mft_zone_pos);
				}
				/* Switch from mft zone to data1 zone. */
switch_to_data1_zone:		search_zone = 2;
				zone_start = bmp_initial_pos =
						vol->data1_zone_pos;
				zone_end = vol->nr_clusters;
				if (zone_start == vol->mft_zone_end)
					pass = 2;
				if (zone_start >= zone_end) {
					vol->data1_zone_pos = zone_start =
							vol->mft_zone_end;
					pass = 2;
				}
				break;
			case 2:
				ntfs_debug("Switching from data1 zone to data2 zone.");
				/* Update data1 zone position. */
				if (rlpos && used_zone_pos) {
					s64 tc;

					ntfs_debug("Before checks, vol->data1_zone_pos 0x%llx.",
							vol->data1_zone_pos);
					tc = rl[rlpos - 1].lcn +
							rl[rlpos - 1].length;
					if (tc >= vol->nr_clusters)
						vol->data1_zone_pos =
							     vol->mft_zone_end;
					else if ((bmp_initial_pos >=
						    vol->data1_zone_pos ||
						    tc > vol->data1_zone_pos)
						    && tc >= vol->mft_zone_end)
						vol->data1_zone_pos = tc;
					ntfs_debug("After checks, vol->data1_zone_pos 0x%llx.",
							vol->data1_zone_pos);
				}
				/* Switch from data1 zone to data2 zone. */
				search_zone = 4;
				zone_start = bmp_initial_pos =
						vol->data2_zone_pos;
				zone_end = vol->mft_zone_start;
				if (!zone_start)
					pass = 2;
				if (zone_start >= zone_end) {
					vol->data2_zone_pos = zone_start =
							bmp_initial_pos = 0;
					pass = 2;
				}
				break;
			case 4:
				ntfs_debug("Switching from data2 zone to data1 zone.");
				/* Update data2 zone position. */
				if (rlpos && used_zone_pos) {
					s64 tc;

					ntfs_debug("Before checks, vol->data2_zone_pos 0x%llx.",
							vol->data2_zone_pos);
					tc = rl[rlpos - 1].lcn +
							rl[rlpos - 1].length;
					if (tc >= vol->mft_zone_start)
						vol->data2_zone_pos = 0;
					else if (bmp_initial_pos >=
						      vol->data2_zone_pos ||
						      tc > vol->data2_zone_pos)
						vol->data2_zone_pos = tc;
					ntfs_debug("After checks, vol->data2_zone_pos 0x%llx.",
							vol->data2_zone_pos);
				}
				/* Switch from data2 zone to data1 zone. */
				goto switch_to_data1_zone;
			default:
				WARN_ON(1);
			}
			ntfs_debug("After zone switch, search_zone %i, pass %i, bmp_initial_pos 0x%llx, zone_start 0x%llx, zone_end 0x%llx.",
					search_zone, pass,
					bmp_initial_pos,
					zone_start,
					zone_end);
			bmp_pos = zone_start;
			if (zone_start == zone_end) {
				ntfs_debug("Empty zone, going to done_zones_check.");
				/* Empty zone. Don't bother searching it. */
				goto done_zones_check;
			}
			ntfs_debug("Continuing outer while loop.");
			continue;
		} /* done_zones == 7 */
		ntfs_debug("All zones are finished.");
		/*
		 * All zones are finished!  If DATA_ZONE, shrink mft zone.  If
		 * MFT_ZONE, we have really run out of space.
		 */
		mft_zone_size = vol->mft_zone_end - vol->mft_zone_start;
		ntfs_debug("vol->mft_zone_start 0x%llx, vol->mft_zone_end 0x%llx, mft_zone_size 0x%llx.",
				vol->mft_zone_start, vol->mft_zone_end,
				mft_zone_size);
		if (zone == MFT_ZONE || mft_zone_size <= 0) {
			ntfs_debug("No free clusters left, going to out.");
			/* Really no more space left on device. */
			exhausted = true;
			err = -ENOSPC;
			if (min_count == count)
				ntfs_debug(
					"Cluster allocation exhausted all zones (free clusters %lld, dirty clusters %lld, requested %lld, total clusters %lld, zone %s).",
					(long long)atomic64_read(
							&vol->free_clusters),
					(long long)atomic64_read(
							&vol->dirty_clusters),
					(long long)count,
					(long long)vol->nr_clusters,
					zone == MFT_ZONE ? "MFT" : "DATA");
			goto out;
		} /* zone == DATA_ZONE && mft_zone_size > 0 */
		ntfs_debug("Shrinking mft zone.");
		zone_end = vol->mft_zone_end;
		mft_zone_size >>= 1;
		if (mft_zone_size > 0)
			vol->mft_zone_end = vol->mft_zone_start + mft_zone_size;
		else /* mft zone and data2 zone no longer exist. */
			vol->data2_zone_pos = vol->mft_zone_start =
					vol->mft_zone_end = 0;
		if (vol->mft_zone_pos >= vol->mft_zone_end) {
			vol->mft_zone_pos = vol->mft_lcn;
			if (!vol->mft_zone_end)
				vol->mft_zone_pos = 0;
		}
		bmp_pos = zone_start = bmp_initial_pos =
				vol->data1_zone_pos = vol->mft_zone_end;
		search_zone = 2;
		pass = 2;
		done_zones &= ~2;
		ntfs_debug("After shrinking mft zone, mft_zone_size 0x%llx, vol->mft_zone_start 0x%llx, vol->mft_zone_end 0x%llx, vol->mft_zone_pos 0x%llx, search_zone 2, pass 2, dones_zones 0x%x, zone_start 0x%llx, zone_end 0x%llx, vol->data1_zone_pos 0x%llx, continuing outer while loop.",
				mft_zone_size, vol->mft_zone_start,
				vol->mft_zone_end, vol->mft_zone_pos,
				done_zones, zone_start, zone_end,
				vol->data1_zone_pos);
	}
	ntfs_debug("After outer while loop.");
out:
	ntfs_debug("At out.");
	/* Add runlist terminator element. */
	if (likely(rl && rlpos)) {
		rl[rlpos].vcn = rl[rlpos - 1].vcn + rl[rlpos - 1].length;
		rl[rlpos].lcn = is_extension ? LCN_ENOENT : LCN_RL_NOT_MAPPED;
		rl[rlpos].length = 0;
	} else if (rl) {
		kvfree(rl);
		rl = NULL;
	}
	if (!IS_ERR_OR_NULL(folio)) {
		if (need_writeback) {
			ntfs_debug("Marking page dirty.");
			folio_mark_dirty(folio);
			need_writeback = 0;
		}
		folio_unlock(folio);
		kunmap_local(buf);
		folio_put(folio);
	}
	if (err == -ENOSPC && exhausted &&
	    allocation_count - clusters >= min_count) {
		ntfs_debug("Returning partial cluster allocation (requested %lld, allocated %lld, minimum %lld, zone %s).",
				(long long)count,
				(long long)(allocation_count - clusters),
				(long long)min_count,
				zone == MFT_ZONE ? "MFT" : "DATA");
		err = 0;
	} else if (err == -ENOSPC && exhausted && min_count < count) {
		ntfs_debug(
			"Cluster allocation exhausted all zones below its minimum (free clusters %lld, dirty clusters %lld, requested %lld, allocated %lld, minimum %lld, total clusters %lld, zone %s).",
			(long long)atomic64_read(&vol->free_clusters),
			(long long)atomic64_read(&vol->dirty_clusters),
			(long long)count, (long long)(allocation_count - clusters),
			(long long)min_count, (long long)vol->nr_clusters,
			zone == MFT_ZONE ? "MFT" : "DATA");
	}
	if (likely(!err)) {
		if (!rl) {
			err = -EIO;
			goto out_restore;
		}
		if (log_handle) {
			err = ntfs_cluster_register_alloc_undo(log_handle, vol, rl,
					rlpos, is_dealloc ?
					allocation_count - clusters : 0);
			if (err)
				goto rollback_alloc;
		}
		if (is_dealloc && !log_handle)
			ntfs_release_dirty_clusters(vol, rl->length);
		ntfs_debug("Done.");
		goto out_restore;
	}
rollback_alloc:
	if (err != -ENOSPC)
		ntfs_error(vol->sb,
			"Failed to allocate clusters, aborting (error %i).",
			err);
	if (rl) {
		int err2;

		if (err == -ENOSPC)
			ntfs_debug("Not enough space to complete allocation, err -ENOSPC, first free lcn 0x%llx, could allocate up to 0x%llx clusters.",
					rl[0].lcn, allocation_count - clusters);
		if (log_handle) {
			/*
			 * Keep partially allocated bits reserved until the
			 * transaction's abort records are durable.  Clearing
			 * them here lets another transaction reuse them before
			 * this handle's CLR can be replayed.
			 */
			err2 = ntfs_cluster_register_alloc_undo(log_handle, vol,
					rl, rlpos, is_dealloc ?
					allocation_count - clusters : 0);
			if (err2) {
				ntfs_error(vol->sb,
					"Failed to register partial cluster-allocation rollback (error %i). Leaving clusters reserved; unmount and run chkdsk.",
					err2);
				NVolSetErrors(vol);
				err = err2;
			}
		} else {
			/* No caller-owned transaction can replay this allocation. */
			ntfs_debug("Attempting non-transacted allocation rollback...");
			err2 = ntfs_cluster_free_from_rl_nolock_core(vol, rl,
					true);
			if (err2) {
				ntfs_error(vol->sb,
					"Failed to rollback (error %i). Leaving inconsistent metadata! Unmount and run chkdsk.",
					err2);
				NVolSetErrors(vol);
			}
		}
		/* Free the runlist. */
		kvfree(rl);
	} else if (err == -ENOSPC)
		ntfs_debug("No space left at all, err = -ENOSPC, first free lcn = 0x%llx.",
				vol->data1_zone_pos);
out_restore:
	up_write(&vol->lcnbmp_lock);
out_memalloc:
	memalloc_nofs_restore(memalloc_flags);

	return err < 0 ? ERR_PTR(err) : rl;
}

int ntfs_cluster_alloc_log_credits(s64 count)
{
	if (count <= 0)
		return -EINVAL;
	/* One open-attribute record and one bitmap operation per chosen bit. */
	if (count >= INT_MAX)
		return -E2BIG;
	return count + 1;
}

int ntfs_cluster_free_log_credits(s64 count)
{
	if (count < 0)
		return -EINVAL;
	if (!count)
		return 0;
	/* One open-attribute record and at most one bitmap record per cluster. */
	if (count >= INT_MAX)
		return -E2BIG;
	return count + 1;
}

int ntfs_cluster_free_from_rl_log_credits(
		const struct runlist_element *rl)
{
	u64 credits = 1;
	unsigned int nr_runs = 0;
	int run_credits;

	if (!rl)
		return -EINVAL;
	if (!rl->length)
		return 0;
	while (rl[nr_runs].length) {
		if (rl[nr_runs].lcn < 0 || rl[nr_runs].length <= 0 ||
		    nr_runs >= INT_MAX)
			return -EIO;
		run_credits = ntfs_log_bitmap_update_credits(rl[nr_runs].lcn,
				rl[nr_runs].length);
		if (run_credits < 0)
			return run_credits;
		if (check_add_overflow(credits, (u64)run_credits - 1,
				&credits) || credits > INT_MAX)
			return -E2BIG;
		nr_runs++;
	}
	return credits;
}

int ntfs_cluster_free_from_rl_preflight_with_mismatch(struct ntfs_volume *vol,
		const struct runlist_element *rl, s64 *first_mismatch)
{
	unsigned int memalloc_flags;
	unsigned int i;
	int err = 0;

	if (!vol || !rl || !first_mismatch)
		return -EINVAL;
	*first_mismatch = -1;
	for (i = 0; rl[i].length; i++) {
		if (rl[i].lcn < 0 || rl[i].length <= 0 ||
		    rl[i].lcn > vol->nr_clusters - rl[i].length ||
		    i >= INT_MAX) {
			ntfs_error(vol->sb,
				   "Invalid cluster-free run at index %u (LCN %lld, length %lld, volume clusters %lld).",
				   i, (long long)rl[i].lcn,
				   (long long)rl[i].length,
				   (long long)vol->nr_clusters);
			return -EIO;
		}
	}
	memalloc_flags = memalloc_nofs_save();
	down_read(&vol->lcnbmp_lock);
	for (i = 0; rl[i].length; i++) {
		err = ntfs_bitmap_validate_run_with_mismatch(vol->lcnbmp_ino,
				rl[i].lcn, rl[i].length, 1, first_mismatch);
		if (err) {
			ntfs_error(vol->sb,
				   "Cluster-free bitmap preflight failed for LCN %lld, length %lld (first mismatched LCN %lld, error %d).",
				   (long long)rl[i].lcn,
				   (long long)rl[i].length,
				   (long long)*first_mismatch, err);
			break;
		}
	}
	up_read(&vol->lcnbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	return err;
}

int ntfs_cluster_free_from_rl_preflight(struct ntfs_volume *vol,
		const struct runlist_element *rl)
{
	s64 first_mismatch;

	return ntfs_cluster_free_from_rl_preflight_with_mismatch(vol, rl,
			&first_mismatch);
}

struct runlist_element *ntfs_cluster_alloc(struct ntfs_volume *vol,
		const s64 start_vcn, const s64 count, const s64 start_lcn,
		const int zone, const bool is_extension, const bool is_contig,
		const bool is_dealloc)
{
	return ntfs_cluster_alloc_core(NULL, vol, start_vcn, count, count,
			start_lcn, zone, is_extension, is_contig, is_dealloc,
			0, 0);
}

struct runlist_element *ntfs_cluster_alloc_data_partial(struct ntfs_volume *vol,
		s64 start_vcn, s64 count, s64 start_lcn, bool is_dealloc)
{
	return ntfs_cluster_alloc_core(NULL, vol, start_vcn, count, 1,
			start_lcn, DATA_ZONE, false, true, is_dealloc, 0, 0);
}

struct runlist_element *ntfs_cluster_alloc_transacted(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		const s64 start_vcn, const s64 count, const s64 start_lcn,
		const int zone, const bool is_extension, const bool is_contig,
		const bool is_dealloc)
{
	if (!handle || is_dealloc)
		return ERR_PTR(!handle ? -EINVAL : -EOPNOTSUPP);
	return ntfs_cluster_alloc_core(handle, vol, start_vcn, count,
			count, start_lcn, zone, is_extension, is_contig, false,
			0, 0);
}

struct runlist_element *ntfs_cluster_alloc_transacted_partial(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		const s64 start_vcn, const s64 count, const s64 min_count,
		const s64 start_lcn, const int zone, const bool is_extension,
		const bool is_contig, const bool is_dealloc,
		const unsigned int max_runs, const unsigned int max_bitmap_updates)
{
	if (!handle)
		return ERR_PTR(-EINVAL);
	return ntfs_cluster_alloc_core(handle, vol, start_vcn, count,
			min_count, start_lcn, zone, is_extension, is_contig,
			is_dealloc, max_runs, max_bitmap_updates);
}

static int ntfs_cluster_free_from_rl_transaction(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		const struct runlist_element *rl, bool packed)
{
	struct ntfs_cluster_free_undo *undo;
	struct runlist_element *free_rl = NULL;
	unsigned int memalloc_flags;
	unsigned int nr_entries = 0;
	unsigned int nr_runs = 0;
	unsigned int dst;
	unsigned int i;
	int err;

	if (!handle || !vol || !rl)
		return -EINVAL;
	while (rl[nr_entries].length) {
		if (rl[nr_entries].length <= 0 || nr_entries >= INT_MAX)
			return -EIO;
		if (rl[nr_entries].lcn != LCN_HOLE) {
			if (rl[nr_entries].lcn < 0 ||
			    rl[nr_entries].length > vol->nr_clusters ||
			    rl[nr_entries].lcn >
				vol->nr_clusters - rl[nr_entries].length)
				return -EIO;
			nr_runs++;
		}
		nr_entries++;
	}
	if (!nr_runs)
		return 0;
	/* Punch/collapse runlists include holes, which have no bitmap bits. */
	if (nr_entries != nr_runs) {
		free_rl = kvmalloc_array(nr_runs, sizeof(*free_rl), GFP_NOFS);
		if (!free_rl)
			return -ENOMEM;
		for (i = 0, dst = 0; i < nr_entries; i++)
			if (rl[i].lcn >= 0)
				free_rl[dst++] = rl[i];
		rl = free_rl;
	}
	err = ntfs_cluster_register_free_undo(handle, vol, rl, nr_runs,
			&undo);
	kvfree(free_rl);
	if (err)
		return err;

	memalloc_flags = memalloc_nofs_save();
	down_write(&vol->lcnbmp_lock);
	for (i = 0; i < undo->nr_runs; i++) {
		err = ntfs_bitmap_validate_run(vol->lcnbmp_ino,
				undo->rl[i].lcn, undo->rl[i].length, 1);
		if (err)
			goto out_unlock;
	}
	if (packed) {
		err = ntfs_log_bitmap_clear_runs(handle, vol->lcnbmp_ino,
				undo->rl, undo->nr_runs);
		if (!err)
			undo->nr_logged = undo->nr_runs;
	} else {
		for (i = 0; i < undo->nr_runs; i++) {
			err = ntfs_log_bitmap_update(handle, vol->lcnbmp_ino,
					undo->rl[i].lcn, undo->rl[i].length, 0);
			if (err)
				break;
			undo->nr_logged++;
		}
	}
out_unlock:
	up_write(&vol->lcnbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	return err;
}

int ntfs_cluster_free_from_rl_transacted(struct ntfs_log_handle *handle,
		struct ntfs_volume *vol, const struct runlist_element *rl)
{
	return ntfs_cluster_free_from_rl_transaction(handle, vol, rl, false);
}

int ntfs_cluster_free_from_rl_packed(struct ntfs_log_handle *handle,
		struct ntfs_volume *vol, const struct runlist_element *rl)
{
	return ntfs_cluster_free_from_rl_transaction(handle, vol, rl, true);
}

static int ntfs_cluster_free_batch(const struct runlist_element *rl,
		size_t nr_runs, int limit,
		struct runlist_element *batch, unsigned int *nr_batch)
{
	s64 clusters = 0;
	unsigned int nr = 0;
	int credits = 1;

	if (limit < 2)
		return -E2BIG;
	while (nr < nr_runs && nr < NTFS_CLUSTER_FREE_MAX_RUNS) {
		s64 length = rl[nr].length;
		int extra;

		for (;;) {
			extra = ntfs_log_bitmap_update_credits(rl[nr].lcn,
					length);
			if (extra < 0 && extra != -E2BIG)
				return extra;
			if (extra >= 0 && extra - 1 <= limit - credits)
				break;
			if (nr)
				goto done;
			if (length == 1)
				return extra < 0 ? extra : -E2BIG;
			length >>= 1;
		}
		batch[nr] = rl[nr];
		batch[nr].vcn = clusters;
		batch[nr].length = length;
		clusters += length;
		credits += extra - 1;
		nr++;
		if (length != rl[nr - 1].length)
			break;
	}
done:
	batch[nr] = (struct runlist_element) {
		.vcn = clusters,
		.lcn = LCN_ENOENT,
	};
	*nr_batch = nr;
	return credits;
}

int ntfs_cluster_free_from_rl(struct ntfs_volume *vol,
		const struct runlist_element *rl)
{
	struct runlist_element *free_rl = NULL;
	struct runlist_element *batch = NULL;
	struct ntfs_log_handle *handle;
	size_t nr_runs = 0;
	size_t i, dst;
	unsigned int memalloc_flags;
	unsigned int nr_batch;
	unsigned int j;
	int limit;
	int credits;
	int err = 0;

	if (!vol)
		return -EINVAL;
	if (!rl)
		return 0;

	memalloc_flags = memalloc_nofs_save();
	if (!vol->journal) {
		down_write(&vol->lcnbmp_lock);
		err = ntfs_cluster_free_from_rl_nolock(vol, rl);
		up_write(&vol->lcnbmp_lock);
		goto out;
	}

	for (i = 0; rl[i].length; i++) {
		if (rl[i].length < 0) {
			err = -EIO;
			goto out;
		}
		if (rl[i].lcn < 0)
			continue;
		if (rl[i].lcn >= vol->nr_clusters ||
		    rl[i].length > vol->nr_clusters - rl[i].lcn) {
			err = -EIO;
			goto out;
		}
		if (nr_runs == INT_MAX) {
			err = -E2BIG;
			goto out;
		}
		nr_runs++;
	}
	if (!nr_runs)
		goto out;
	limit = ntfs_log_transaction_credits_limit(vol);
	if (limit < 0) {
		err = limit;
		goto out;
	}

	free_rl = kvmalloc_array(nr_runs, sizeof(*free_rl), GFP_NOFS);
	if (!free_rl) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0, dst = 0; rl[i].length; i++) {
		if (rl[i].lcn < 0)
			continue;
		free_rl[dst] = rl[i];
		free_rl[dst++].vcn = 0;
	}
	sort(free_rl, nr_runs, sizeof(*free_rl),
			ntfs_cluster_free_run_compare, NULL);
	for (i = 1; i < nr_runs; i++) {
		s64 previous_end;

		if (check_add_overflow(free_rl[i - 1].lcn,
				free_rl[i - 1].length, &previous_end)) {
			ntfs_error(vol->sb,
				   "Invalid cluster-free run at LCN %lld, length %lld.",
				   (long long)free_rl[i - 1].lcn,
				   (long long)free_rl[i - 1].length);
			err = -EIO;
			goto out;
		}
		if (free_rl[i].lcn < previous_end) {
			ntfs_error(vol->sb,
				   "Overlapping cluster-free runs at LCN %lld (previous run ends at %lld).",
				   (long long)free_rl[i].lcn,
				   (long long)previous_end);
			err = -EIO;
			goto out;
		}
	}
	for (i = 0, dst = 0; i < nr_runs; i++) {
		if (dst && free_rl[dst - 1].lcn + free_rl[dst - 1].length ==
				free_rl[i].lcn)
			free_rl[dst - 1].length += free_rl[i].length;
		else
			free_rl[dst++] = free_rl[i];
	}
	nr_runs = dst;
	batch = kvmalloc_array(min_t(size_t, nr_runs,
			NTFS_CLUSTER_FREE_MAX_RUNS) + 1, sizeof(*batch), GFP_NOFS);
	if (!batch) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < nr_runs; ) {
		int abort_err;

		credits = ntfs_cluster_free_batch(free_rl + i, nr_runs - i,
				limit, batch, &nr_batch);
		if (credits < 0) {
			err = credits;
			break;
		}
		handle = ntfs_log_begin_full_reservation(vol, credits);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			if (err == -ENOSPC && limit > 2) {
				limit = max(2, limit / 2);
				continue;
			}
			break;
		}
		err = ntfs_cluster_free_from_rl_transacted(handle, vol, batch);
		if (err) {
			abort_err = ntfs_log_abort(handle);
			if (abort_err)
				err = abort_err;
			break;
		}
		err = ntfs_log_commit(handle);
		if (err)
			break;
		for (j = 0; j < nr_batch; j++) {
			free_rl[i].lcn += batch[j].length;
			free_rl[i].length -= batch[j].length;
			if (!free_rl[i].length)
				i++;
		}
		cond_resched();
	}
out:
	kvfree(batch);
	kvfree(free_rl);
	memalloc_nofs_restore(memalloc_flags);
	return err;
}

/*
 * __ntfs_cluster_free - free clusters on an ntfs volume
 * @ni:		ntfs inode whose runlist describes the clusters to free
 * @start_vcn:	vcn in the runlist of @ni at which to start freeing clusters
 * @count:	number of clusters to free or -1 for all clusters
 * @ctx:	active attribute search context if present or NULL if not
 * @is_rollback:	true if this is a rollback operation
 *
 * Free @count clusters starting at the cluster @start_vcn in the runlist
 * described by the vfs inode @ni.
 *
 * If @count is -1, all clusters from @start_vcn to the end of the runlist are
 * deallocated.  Thus, to completely free all clusters in a runlist, use
 * @start_vcn = 0 and @count = -1.
 *
 * If @ctx is specified, it is an active search context of @ni and its base mft
 * record.  This is needed when __ntfs_cluster_free() encounters unmapped
 * runlist fragments and allows their mapping.  If you do not have the mft
 * record mapped, you can specify @ctx as NULL and __ntfs_cluster_free() will
 * perform the necessary mapping and unmapping.
 *
 * Note, __ntfs_cluster_free() saves the state of @ctx on entry and restores it
 * before returning.  Thus, @ctx will be left pointing to the same attribute on
 * return as on entry.  However, the actual pointers in @ctx may point to
 * different memory locations on return, so you must remember to reset any
 * cached pointers from the @ctx, i.e. after the call to __ntfs_cluster_free(),
 * you will probably want to do:
 *	m = ctx->mrec;
 *	a = ctx->attr;
 * Assuming you cache ctx->attr in a variable @a of type attr_record * and that
 * you cache ctx->mrec in a variable @m of type struct mft_record *.
 *
 * @is_rollback should always be 'false', it is for internal use to rollback
 * errors.  You probably want to use ntfs_cluster_free() instead.
 *
 * Note, __ntfs_cluster_free() does not modify the runlist, so you have to
 * remove from the runlist or mark sparse the freed runs later.
 *
 * Return the number of deallocated clusters (not counting sparse ones) on
 * success and -errno on error.
 *
 * WARNING: If @ctx is supplied, regardless of whether success or failure is
 *	    returned, you need to check IS_ERR(@ctx->mrec) and if 'true' the @ctx
 *	    is no longer valid, i.e. you need to either call
 *	    ntfs_attr_reinit_search_ctx() or ntfs_attr_put_search_ctx() on it.
 *	    In that case PTR_ERR(@ctx->mrec) will give you the error code for
 *	    why the mapping of the old inode failed.
 *
 * Locking: - The runlist described by @ni must be locked for writing on entry
 *	      and is locked on return.  Note the runlist may be modified when
 *	      needed runlist fragments need to be mapped.
 *	    - The volume lcn bitmap must be unlocked on entry and is unlocked
 *	      on return.
 *	    - This function takes the volume lcn bitmap lock for writing and
 *	      modifies the bitmap contents.
 *	    - If @ctx is NULL, the base mft record of @ni must not be mapped on
 *	      entry and it will be left unmapped on return.
 *	    - If @ctx is not NULL, the base mft record must be mapped on entry
 *	      and it will be left mapped on return.
 */
s64 __ntfs_cluster_free(struct ntfs_inode *ni, const s64 start_vcn, s64 count,
		struct ntfs_attr_search_ctx *ctx, const bool is_rollback)
{
	s64 delta, to_free, total_freed, real_freed;
	struct ntfs_volume *vol;
	struct inode *lcnbmp_vi;
	struct runlist_element *rl;
	int err;
	unsigned int memalloc_flags;

	ntfs_debug("Entering for i_ino 0x%llx, start_vcn 0x%llx, count 0x%llx.%s",
			ni->mft_no, start_vcn, count,
			is_rollback ? " (rollback)" : "");
	vol = ni->vol;
	lcnbmp_vi = vol->lcnbmp_ino;
	if (start_vcn < 0 || count < -1)
		return -EINVAL;

	if (!NVolFreeClusterKnown(vol))
		wait_event(vol->free_waitq, NVolFreeClusterKnown(vol));

	/*
	 * Lock the lcn bitmap for writing but only if not rolling back.  We
	 * must hold the lock all the way including through rollback otherwise
	 * rollback is not possible because once we have cleared a bit and
	 * dropped the lock, anyone could have set the bit again, thus
	 * allocating the cluster for another use.
	 */
	if (likely(!is_rollback)) {
		memalloc_flags = memalloc_nofs_save();
		down_write(&vol->lcnbmp_lock);
	}

	total_freed = real_freed = 0;

	rl = ntfs_attr_find_vcn_nolock(ni, start_vcn, ctx);
	if (IS_ERR(rl)) {
		err = PTR_ERR(rl);
		if (err == -ENOENT) {
			if (likely(!is_rollback)) {
				up_write(&vol->lcnbmp_lock);
				memalloc_nofs_restore(memalloc_flags);
			}
			return 0;
		}

		if (!is_rollback)
			ntfs_error(vol->sb,
				"Failed to find first runlist element (error %d), aborting.",
				err);
		goto err_out;
	}
	if (unlikely(rl->lcn < LCN_HOLE)) {
		if (!is_rollback)
			ntfs_error(vol->sb, "First runlist element has invalid lcn, aborting.");
		err = -EIO;
		goto err_out;
	}
	/* Find the starting cluster inside the run that needs freeing. */
	delta = start_vcn - rl->vcn;

	/* The number of clusters in this run that need freeing. */
	to_free = rl->length - delta;
	if (count >= 0 && to_free > count)
		to_free = count;

	if (likely(rl->lcn >= 0)) {
		/* Do the actual freeing of the clusters in this run. */
		err = ntfs_bitmap_set_bits_in_run(lcnbmp_vi, rl->lcn + delta,
				to_free, likely(!is_rollback) ? 0 : 1);
		if (unlikely(err)) {
			if (!is_rollback)
				ntfs_error(vol->sb,
					"Failed to clear first run (error %i), aborting.",
					err);
			goto err_out;
		}
		/* We have freed @to_free real clusters. */
		real_freed = to_free;
	}
	/* Go to the next run and adjust the number of clusters left to free. */
	++rl;
	if (count >= 0)
		count -= to_free;

	/* Keep track of the total "freed" clusters, including sparse ones. */
	total_freed = to_free;
	/*
	 * Loop over the remaining runs, using @count as a capping value, and
	 * free them.
	 */
	for (; rl->length && count != 0; ++rl) {
		if (unlikely(rl->lcn < LCN_HOLE)) {
			s64 vcn;

			/* Attempt to map runlist. */
			vcn = rl->vcn;
			rl = ntfs_attr_find_vcn_nolock(ni, vcn, ctx);
			if (IS_ERR(rl)) {
				err = PTR_ERR(rl);
				if (!is_rollback)
					ntfs_error(vol->sb,
						"Failed to map runlist fragment or failed to find subsequent runlist element.");
				goto err_out;
			}
			if (unlikely(rl->lcn < LCN_HOLE)) {
				if (!is_rollback)
					ntfs_error(vol->sb,
						"Runlist element has invalid lcn (0x%llx).",
						rl->lcn);
				err = -EIO;
				goto err_out;
			}
		}
		/* The number of clusters in this run that need freeing. */
		to_free = rl->length;
		if (count >= 0 && to_free > count)
			to_free = count;

		if (likely(rl->lcn >= 0)) {
			/* Do the actual freeing of the clusters in the run. */
			err = ntfs_bitmap_set_bits_in_run(lcnbmp_vi, rl->lcn,
					to_free, likely(!is_rollback) ? 0 : 1);
			if (unlikely(err)) {
				if (!is_rollback)
					ntfs_error(vol->sb, "Failed to clear subsequent run.");
				goto err_out;
			}
			/* We have freed @to_free real clusters. */
			real_freed += to_free;
		}
		/* Adjust the number of clusters left to free. */
		if (count >= 0)
			count -= to_free;

		/* Update the total done clusters. */
		total_freed += to_free;
	}
	ntfs_inc_free_clusters(vol, real_freed);
	if (likely(!is_rollback)) {
		up_write(&vol->lcnbmp_lock);
		memalloc_nofs_restore(memalloc_flags);
	}

	WARN_ON(count > 0);

	if (NVolDiscard(vol) && !is_rollback) {
		s64 total_discarded = 0, rl_off;
		u32 gran = bdev_discard_granularity(vol->sb->s_bdev);

		rl = ntfs_attr_find_vcn_nolock(ni, start_vcn, ctx);
		if (IS_ERR(rl))
			return real_freed;
		rl_off = start_vcn - rl->vcn;
		while (rl->length && total_discarded < total_freed) {
			s64 to_discard = rl->length - rl_off;

			if (to_discard + total_discarded > total_freed)
				to_discard = total_freed - total_discarded;
			if (rl->lcn >= 0) {
				sector_t start_sector, end_sector;
				int ret;

				start_sector = ALIGN(NTFS_CLU_TO_B(vol, rl->lcn + rl_off),
						     gran) >> SECTOR_SHIFT;
				end_sector = ALIGN_DOWN(NTFS_CLU_TO_B(vol,
							rl->lcn + rl_off + to_discard),
							gran) >> SECTOR_SHIFT;
				if (start_sector < end_sector) {
					ret = blkdev_issue_discard(vol->sb->s_bdev, start_sector,
								   end_sector - start_sector,
								   GFP_NOFS);
					if (ret)
						break;
				}
			}

			total_discarded += to_discard;
			++rl;
			rl_off = 0;
		}
	}

	/* We are done.  Return the number of actually freed clusters. */
	ntfs_debug("Done.");
	return real_freed;
err_out:
	if (is_rollback)
		return err;
	/* If no real clusters were freed, no need to rollback. */
	if (!real_freed) {
		up_write(&vol->lcnbmp_lock);
		memalloc_nofs_restore(memalloc_flags);
		return err;
	}
	/*
	 * Attempt to rollback and if that succeeds just return the error code.
	 * If rollback fails, set the volume errors flag, emit an error
	 * message, and return the error code.
	 */
	delta = __ntfs_cluster_free(ni, start_vcn, total_freed, ctx, true);
	if (delta < 0) {
		ntfs_error(vol->sb,
			"Failed to rollback (error %i).  Leaving inconsistent metadata!  Unmount and run chkdsk.",
			(int)delta);
		NVolSetErrors(vol);
	} else {
		ntfs_dec_free_clusters(vol, delta);
	}
	up_write(&vol->lcnbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	ntfs_error(vol->sb, "Aborting (error %i).", err);
	return err;
}
