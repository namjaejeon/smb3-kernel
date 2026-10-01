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

#include "lcnalloc.h"
#include "bitmap.h"
#include "ntfs.h"

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
int ntfs_cluster_free_from_rl_nolock(struct ntfs_volume *vol,
		const struct runlist_element *rl)
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
		err = ntfs_bitmap_clear_run(lcnbmp_vi, rl->lcn, rl->length);
		if (likely(!err))
			nr_freed += rl->length;
		else if (!ret || ret == -ENOMEM)
			ret = err;
	}
	ntfs_inc_free_clusters(vol, nr_freed);
	ntfs_debug("Done.");
	return ret;
}

static void ntfs_update_cluster_hint(struct ntfs_volume *vol, s64 start,
		s64 length)
{
	s64 end = start + length;

	if (start >= vol->mft_zone_start && start < vol->mft_zone_end) {
		vol->mft_zone_pos = end < vol->mft_zone_end ? end :
				   vol->mft_zone_start;
	} else if (start >= vol->mft_zone_end) {
		vol->data1_zone_pos = end < vol->nr_clusters ? end :
				     vol->mft_zone_end;
	} else {
		vol->data2_zone_pos = end < vol->mft_zone_start ? end : 0;
	}
}

static bool ntfs_shrink_mft_zone(struct ntfs_volume *vol)
{
	s64 length = vol->mft_zone_end - vol->mft_zone_start;

	if (!length)
		return false;
	length >>= 1;
	if (length) {
		vol->mft_zone_end = vol->mft_zone_start + length;
		if (vol->mft_zone_pos >= vol->mft_zone_end)
			vol->mft_zone_pos = vol->mft_zone_start;
	} else {
		vol->mft_zone_start = vol->mft_zone_end = 0;
		vol->mft_zone_pos = vol->data2_zone_pos = 0;
	}
	vol->data1_zone_pos = vol->mft_zone_end;
	return true;
}

/*
 * ntfs_cluster_alloc - allocate clusters, preferring adjacent or large extents
 * @vol: volume on which to allocate clusters
 * @start_vcn: first VCN of the allocation
 * @count: requested number of clusters
 * @start_lcn: preferred LCN, or -1 to use the zone's allocation hint
 * @zone: MFT_ZONE or DATA_ZONE
 * @is_extension: terminate the runlist with LCN_ENOENT rather than
 *                LCN_RL_NOT_MAPPED
 * @is_contig: return only one contiguous run, which may be shorter than @count
 * @is_dealloc: consume delayed-allocation reservations
 *
 * Search the free extent cache before scanning the bitmap. MFT allocations
 * prefer the reserved zone and may fall back to data space. Data allocations
 * use the reserved zone only after exhausting data space and shrinking the
 * reservation. Mark bitmap ranges and update counters once per extent.
 *
 * Return: allocated runlist, or an error pointer. All committed extents are
 * rolled back on failure. The caller must not hold lcnbmp_lock.
 */
struct runlist_element *ntfs_cluster_alloc(struct ntfs_volume *vol,
		const s64 start_vcn, const s64 count, const s64 start_lcn,
		const int zone, const bool is_extension, const bool is_contig,
		const bool is_dealloc)
{
	struct runlist_element *rl = NULL;
	s64 allocated = 0, free_clusters, hint = start_lcn;
	size_t nr_runs = 0, capacity = 0;
	unsigned int memalloc_flags;
	int err = 0;

	if (start_vcn < 0 || count <= 0 || count > S64_MAX - start_vcn ||
	    start_lcn < LCN_HOLE ||
	    zone < FIRST_ZONE || zone > LAST_ZONE)
		return ERR_PTR(-EINVAL);

	memalloc_flags = memalloc_nofs_save();
	if (!NVolFreeClusterKnown(vol))
		wait_event(vol->free_waitq, NVolFreeClusterKnown(vol));
	down_write(&vol->lcnbmp_lock);
	free_clusters = atomic64_read(&vol->free_clusters);
	if (!is_dealloc)
		free_clusters -= atomic64_read(&vol->dirty_clusters);
	if (free_clusters < count) {
		err = -ENOSPC;
		goto out;
	}
	if (hint < 0)
		hint = zone == MFT_ZONE ? vol->mft_zone_pos : vol->data1_zone_pos;

	while (allocated < count) {
		s64 start, length;

		err = ntfs_free_space_find(vol, zone, hint, count - allocated,
					   &start, &length);
		if (err)
			goto rollback;
		if (!length && zone == MFT_ZONE) {
			err = ntfs_free_space_find(vol, DATA_ZONE, hint,
						   count - allocated, &start, &length);
			if (err)
				goto rollback;
		}
		if (!length) {
			if (zone == DATA_ZONE && ntfs_shrink_mft_zone(vol))
				continue;
			err = -ENOSPC;
			goto rollback;
		}

		/* Reserve space for a new run and its terminator before marking. */
		if (capacity < 2 * sizeof(*rl) ||
		    nr_runs >= capacity / sizeof(*rl) - 1) {
			struct runlist_element *new_rl;
			size_t new_capacity;

			if (capacity > SIZE_MAX / 2) {
				err = -ENOMEM;
				goto rollback;
			}
			new_capacity = capacity ? capacity * 2 : PAGE_SIZE;
			new_rl = kvrealloc(rl, new_capacity, GFP_NOFS);
			if (!new_rl) {
				err = -ENOMEM;
				goto rollback;
			}
			rl = new_rl;
			capacity = new_capacity;
			rl[nr_runs].length = 0;
		}

		err = ntfs_bitmap_set_run(vol->lcnbmp_ino, start, length);
		if (err)
			goto rollback;
		ntfs_dec_free_clusters(vol, length);

		if (nr_runs && rl[nr_runs - 1].lcn +
		    rl[nr_runs - 1].length == start) {
			rl[nr_runs - 1].length += length;
		} else {
			rl[nr_runs].vcn = start_vcn + allocated;
			rl[nr_runs].lcn = start;
			rl[nr_runs].length = length;
			nr_runs++;
		}
		allocated += length;
		rl[nr_runs].vcn = start_vcn + allocated;
		rl[nr_runs].lcn = is_extension ? LCN_ENOENT : LCN_RL_NOT_MAPPED;
		rl[nr_runs].length = 0;
		ntfs_update_cluster_hint(vol, start, length);
		hint = start + length;
		if (is_contig)
			break;
	}
	if (is_dealloc)
		ntfs_release_dirty_clusters(vol, allocated);
	goto out;

rollback:
	if (nr_runs) {
		int rollback_err = ntfs_cluster_free_from_rl_nolock(vol, rl);

		if (rollback_err) {
			ntfs_error(vol->sb,
				   "Failed to roll back cluster allocation (error %d)",
				   rollback_err);
			NVolSetErrors(vol);
		}
	}
	kvfree(rl);
	rl = NULL;
out:
	up_write(&vol->lcnbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	return err ? ERR_PTR(err) : rl;
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
