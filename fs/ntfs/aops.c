// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS kernel address space operations and page cache handling.
 *
 * Copyright (c) 2001-2014 Anton Altaparmakov and Tuxera Inc.
 * Copyright (c) 2002 Richard Russon
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/swap.h>
#include <linux/writeback.h>

#include "attrib.h"
#include "logfile.h"
#include "mft.h"
#include "ntfs.h"
#include "debug.h"
#include "iomap.h"

static void ntfs_iomap_read_end_io(struct bio *bio)
{
	int error = blk_status_to_errno(bio->bi_status);
	struct folio_iter iter;

	bio_for_each_folio_all(iter, bio) {
		struct folio *folio = iter.folio;
		struct ntfs_inode *ni = NTFS_I(folio->mapping->host);
		s64 init_size;
		loff_t pos = folio_pos(folio);

		init_size = ni->initialized_size;
		if (pos + iter.offset < init_size &&
		    pos + iter.offset + iter.length > init_size)
			folio_zero_segment(folio, offset_in_folio(folio, init_size),
					   iter.offset + iter.length);

		iomap_finish_folio_read(folio, iter.offset, iter.length, error);
	}
	bio_put(bio);
}

static void ntfs_iomap_bio_submit_read(const struct iomap_iter *iter,
		struct iomap_read_folio_ctx *ctx)
{
	iomap_bio_submit_read_endio(iter, ctx, ntfs_iomap_read_end_io);
}

static const struct iomap_read_ops ntfs_iomap_bio_read_ops = {
	.read_folio_range	= iomap_bio_read_folio_range,
	.submit_read		= ntfs_iomap_bio_submit_read,
};

/*
 * ntfs_read_folio - Read data for a folio from the device
 * @file:	open file to which the folio @folio belongs or NULL
 * @folio:	page cache folio to fill with data
 *
 * This function handles reading data into the page cache. It first checks
 * for specific ntfs attribute type like encryption and compression.
 *
 * - If the attribute is encrypted, access is denied (-EACCES) because
 *   decryption is not supported in this path.
 * - If the attribute is non-resident and compressed, the read operation is
 *   delegated to ntfs_read_compressed_block().
 * - For normal resident or non-resident attribute, it utilizes the generic
 *   iomap infrastructure via iomap_bio_read_folio() to perform the I/O.
 *
 * Return: 0 on success, or -errno on error.
 */
static int ntfs_read_folio(struct file *file, struct folio *folio)
{
	struct ntfs_inode *ni = NTFS_I(folio->mapping->host);
	struct iomap_read_folio_ctx ctx = {
		.cur_folio = folio,
		.ops = &ntfs_iomap_bio_read_ops,
	};

	/*
	 * Only $DATA attributes can be encrypted and only unnamed $DATA
	 * attributes can be compressed.  Index root can have the flags set but
	 * this means to create compressed/encrypted files, not that the
	 * attribute is compressed/encrypted.  Note we need to check for
	 * AT_INDEX_ALLOCATION since this is the type of both directory and
	 * index inodes.
	 */
	if (ni->type != AT_INDEX_ALLOCATION) {
		/*
		 * EFS-encrypted files are not supported.
		 * (decryption/encryption is not implemented yet)
		 */
		if (NInoEncrypted(ni)) {
			folio_unlock(folio);
			return -EOPNOTSUPP;
		}
		if (NInoWofCompressed(ni)) {
#ifdef CONFIG_NTFS_FS_WOF_COMPRESSION
			return ntfs_read_wof_compressed_block(folio);
#else
			folio_unlock(folio);
			return -EOPNOTSUPP;
#endif
		}
		/* Compressed data streams are handled in compress.c. */
		if (NInoNonResident(ni) && NInoCompressed(ni))
			return ntfs_read_compressed_block(folio);
	}

	iomap_read_folio(ntfs_read_iomap_next, &ctx, NULL);
	return 0;
}

/*
 * ntfs_bmap - map logical file block to physical device block
 * @mapping:	address space mapping to which the block to be mapped belongs
 * @block:	logical block to map to its physical device block
 *
 * For regular, non-resident files (i.e. not compressed and not encrypted), map
 * the logical @block belonging to the file described by the address space
 * mapping @mapping to its physical device block.
 *
 * The size of the block is equal to the @s_blocksize field of the super block
 * of the mounted file system which is guaranteed to be smaller than or equal
 * to the cluster size thus the block is guaranteed to fit entirely inside the
 * cluster which means we do not need to care how many contiguous bytes are
 * available after the beginning of the block.
 *
 * Return the physical device block if the mapping succeeded or 0 if the block
 * is sparse or there was an error.
 *
 * Note: This is a problem if someone tries to run bmap() on $Boot system file
 * as that really is in block zero but there is nothing we can do.  bmap() is
 * just broken in that respect (just like it cannot distinguish sparse from
 * not available or error).
 */
static sector_t ntfs_bmap(struct address_space *mapping, sector_t block)
{
	s64 ofs, size;
	loff_t i_size;
	s64 lcn;
	unsigned long blocksize, flags;
	struct ntfs_inode *ni = NTFS_I(mapping->host);
	struct ntfs_volume *vol = ni->vol;
	unsigned int delta;
	unsigned char blocksize_bits;

	ntfs_debug("Entering for mft_no 0x%llx, logical block 0x%llx.",
			ni->mft_no, (unsigned long long)block);
	if (ni->type != AT_DATA || !NInoNonResident(ni) || NInoEncrypted(ni) ||
	    NInoWofCompressed(ni) || NInoMstProtected(ni)) {
		ntfs_error(vol->sb, "BMAP does not make sense for %s attributes, returning 0.",
				(ni->type != AT_DATA) ? "non-data" :
				(!NInoNonResident(ni) ? "resident" :
				(NInoWofCompressed(ni) ? "WOF-compressed" :
				"encrypted")));
		return 0;
	}
	/* None of these can happen. */
	blocksize = vol->sb->s_blocksize;
	blocksize_bits = vol->sb->s_blocksize_bits;
	ofs = (s64)block << blocksize_bits;
	read_lock_irqsave(&ni->size_lock, flags);
	size = ni->initialized_size;
	i_size = i_size_read(VFS_I(ni));
	read_unlock_irqrestore(&ni->size_lock, flags);
	/*
	 * If the offset is outside the initialized size or the block straddles
	 * the initialized size then pretend it is a hole unless the
	 * initialized size equals the file size.
	 */
	if (unlikely(ofs >= size || (ofs + blocksize > size && size < i_size)))
		goto hole;
	down_read(&ni->runlist.lock);
	lcn = ntfs_attr_vcn_to_lcn_nolock(ni, ntfs_bytes_to_cluster(vol, ofs),
			false);
	up_read(&ni->runlist.lock);
	if (unlikely(lcn < LCN_HOLE)) {
		/*
		 * Step down to an integer to avoid gcc doing a long long
		 * comparision in the switch when we know @lcn is between
		 * LCN_HOLE and LCN_EIO (i.e. -1 to -5).
		 *
		 * Otherwise older gcc (at least on some architectures) will
		 * try to use __cmpdi2() which is of course not available in
		 * the kernel.
		 */
		switch ((int)lcn) {
		case LCN_ENOENT:
			/*
			 * If the offset is out of bounds then pretend it is a
			 * hole.
			 */
			goto hole;
		case LCN_ENOMEM:
			ntfs_error(vol->sb,
				"Not enough memory to complete mapping for inode 0x%llx. Returning 0.",
				ni->mft_no);
			break;
		default:
			ntfs_error(vol->sb,
				"Failed to complete mapping for inode 0x%llx.  Run chkdsk. Returning 0.",
				ni->mft_no);
			break;
		}
		return 0;
	}
	if (lcn < 0) {
		/* It is a hole. */
hole:
		ntfs_debug("Done (returning hole).");
		return 0;
	}
	/*
	 * The block is really allocated and fullfils all our criteria.
	 * Convert the cluster to units of block size and return the result.
	 */
	delta = ofs & vol->cluster_size_mask;
	if (unlikely(sizeof(block) < sizeof(lcn))) {
		block = lcn = (ntfs_cluster_to_bytes(vol, lcn) + delta) >>
				blocksize_bits;
		/* If the block number was truncated return 0. */
		if (unlikely(block != lcn)) {
			ntfs_error(vol->sb,
				"Physical block 0x%llx is too large to be returned, returning 0.",
				(long long)lcn);
			return 0;
		}
	} else
		block = (ntfs_cluster_to_bytes(vol, lcn) + delta) >>
				blocksize_bits;
	ntfs_debug("Done (returning block 0x%llx).", (unsigned long long)lcn);
	return block;
}

static void ntfs_readahead(struct readahead_control *rac)
{
	struct address_space *mapping = rac->mapping;
	struct inode *inode = mapping->host;
	struct ntfs_inode *ni = NTFS_I(inode);
	struct iomap_read_folio_ctx ctx = {
		.ops = &ntfs_iomap_bio_read_ops,
		.rac = rac,
	};

	/*
	 * Resident files are not cached in the page cache, readahead is not
	 * implemented for compressed files, and ntfs_read_folio() refuses
	 * encrypted files because decryption is not implemented.
	 */
	if (!NInoNonResident(ni) || NInoEncrypted(ni) || NInoCompressed(ni) ||
	    NInoWofCompressed(ni))
		return;
	iomap_readahead(ntfs_read_iomap_next, &ctx, NULL);
}

static int ntfs_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ntfs_writepage_ctx ntfs_wpc = {
		.wpc = {
			.inode	= mapping->host,
			.wbc	= wbc,
			.ops	= &ntfs_writeback_ops,
		},
	};
	struct iomap_writepage_ctx *wpc = &ntfs_wpc.wpc;
	bool deferred = false;
	bool need_iput = false;
	bool bitmap_locked = false;
	bool metadata_deferred = false;
	bool check_wal = NInoAttr(ni) || inode == ni->vol->lcnbmp_ino;
	bool ordered_wb_user = false;
	int ret;

	if (NVolShutdown(ni->vol))
		return -EIO;

	if (ni->vol->journal) {
		ntfs_wpc.metadata = ni->type != AT_DATA ||
				    ni->mft_no < FILE_first_user;
		while (!ntfs_ordered_writeback_enter(ni, &ntfs_wpc.ordered)) {
			if (wbc->sync_mode != WB_SYNC_ALL)
				return 0;
			/* The owner has already acquired its journal transaction. */
			wait_event(ni->ordered_wait,
					!READ_ONCE(ni->ordered_active));
			if (NVolShutdown(ni->vol))
				return -EIO;
		}
		ordered_wb_user = true;
	}

	if (!NInoNonResident(ni)) {
		ret = 0;
		goto out_bitmap;
	}

	/*
	 * $Bitmap is a base inode, not an attribute inode.  Serialize its
	 * writeback with allocation so the WAL check covers the submitted bits.
	 * Avoid waiting here: a caller may already hold the bitmap lock.
	 */
	if (inode == ni->vol->lcnbmp_ino && ni->vol->journal) {
		if (!down_read_trylock(&ni->vol->lcnbmp_lock)) {
			metadata_deferred = true;
			ret = wbc->sync_mode == WB_SYNC_ALL ? -EAGAIN : 0;
			goto out_bitmap;
		}
		bitmap_locked = true;
	}

	/*
	 * Journaled metadata streams stay dirty until their WAL batch commits.
	 * Do this before iomap starts clearing folio dirty ranges: returning from
	 * inside ->map_blocks would otherwise lose the deferred dirty state.
	 * Ordinary file data is allowed to reach disk before metadata commit, as
	 * required by ordered-data semantics.
	 */
	if (check_wal) {
		int err = ntfs_log_writeback_inode(inode,
				wbc->sync_mode == WB_SYNC_ALL);

		if (err) {
			metadata_deferred = err == -EAGAIN;
			ret = err == -EAGAIN && wbc->sync_mode == WB_SYNC_NONE ?
				0 : err;
			goto out_bitmap;
		}
	}

	/*
	 * EFS-encrypted files are not supported.
	 * (decryption/encryption is not implemented yet)
	 */
	if (NInoEncrypted(ni)) {
		ntfs_debug("Encrypted I/O not supported");
		ret = -EOPNOTSUPP;
		goto out_bitmap;
	}

	/*
	 * Prevent eviction in writeback to avoid deadlock in
	 * ntfs_drop_big_inode().
	 */
	if ((ni->type == AT_DATA || ni->type == AT_INDEX_ALLOCATION) &&
	    igrab(inode))
		need_iput = true;

	if (ni->vol->journal) {
		struct folio *folio = NULL;
		int error = 0;
		int first_error = 0;

		while ((folio = writeback_iter(mapping, wbc, folio, &error))) {
			/* A metadata writer may have advanced the WAL since entry. */
			error = check_wal ?
				ntfs_log_writeback_inode(inode, false) : 0;
			if (!error)
				error = ntfs_writeback_prepare_folio(inode, folio);
			if (error) {
				folio_redirty_for_writepage(wbc, folio);
				iomap_dirty_folio(mapping, folio);
				if (error == -EAGAIN) {
					deferred = true;
					metadata_deferred = ntfs_wpc.metadata;
				} else if (error != -ENOMEM) {
					mapping_set_error(mapping, error);
				}
			} else {
				error = iomap_writeback_folio(wpc, folio);
				if (error == -EAGAIN) {
					folio_redirty_for_writepage(wbc, folio);
					iomap_dirty_folio(mapping, folio);
					deferred = true;
					metadata_deferred = ntfs_wpc.metadata;
				}
			}
			if (error && error != -EAGAIN && !first_error)
				first_error = error;
			folio_unlock(folio);
		}
		if (wpc->wb_ctx) {
			int submit_err;

			/* Submit the ranges already mapped for this ioend. */
			submit_err = wpc->ops->writeback_submit(wpc, 0);
			if (submit_err && !first_error)
				first_error = submit_err;
		}
		ret = first_error ? first_error :
			(deferred && wbc->sync_mode == WB_SYNC_ALL ? -EAGAIN : error);
		if (deferred && ret == -EAGAIN && wbc->sync_mode == WB_SYNC_NONE)
			ret = 0;
	} else {
		ret = iomap_writepages(wpc);
	}
	if (ret && (ret != -EAGAIN || !deferred))
		ntfs_error(inode->i_sb,
			"%s: writeback returned %d for inode %llu.",
			__func__, ret, (unsigned long long)ni->mft_no);

out_bitmap:
	if (ordered_wb_user)
		ntfs_ordered_writeback_exit(ni);
	if (bitmap_locked)
		up_read(&ni->vol->lcnbmp_lock);
	if (ret && ntfs_wpc.metadata) {
		metadata_deferred = true;
		if (ret != -EAGAIN && ret != -ENOMEM)
			NVolSetErrors(ni->vol);
	}
	if (metadata_deferred)
		ntfs_log_inode_writeback_deferred(ni->vol);
	if (need_iput)
		iput(inode);
	return ret;
}

static int ntfs_swap_activate(struct swap_info_struct *sis,
		struct file *swap_file, sector_t *span)
{
	if (NInoWofCompressed(NTFS_I(file_inode(swap_file))))
		return -EOPNOTSUPP;

	return iomap_swapfile_activate(sis, swap_file, span,
			ntfs_read_iomap_next);
}

/**
 * ntfs_read_metadata_folio - read a metadata folio, ignoring fatal signals
 * @mapping:	address space of the metadata inode or block device
 * @index:	page cache index to read
 *
 * Like read_mapping_folio(), but the wait for the read cannot be interrupted,
 * so a fatal signal cannot fail a metadata read in the middle of an update.
 * The caller must not hold the lock of the folio at @index.
 *
 * Return: the uptodate folio with a reference held, or an ERR_PTR().
 */
struct folio *ntfs_read_metadata_folio(struct address_space *mapping,
				       pgoff_t index)
{
	struct folio *folio;
	int err;

	folio = filemap_get_folio(mapping, index);
	if (!IS_ERR(folio)) {
		if (folio_test_uptodate(folio))
			goto out;
		folio_put(folio);
	}
repeat:
	folio = __filemap_get_folio(mapping, index, FGP_LOCK | FGP_CREAT,
				    mapping_gfp_mask(mapping));
	if (IS_ERR(folio))
		return folio;
	/* $MFT updates clear uptodate under the folio lock, so check it locked. */
	if (folio_test_uptodate(folio))
		goto unlock;

	/* ->read_folio() unlocks the folio when the read completes. */
	err = mapping->a_ops->read_folio(NULL, folio);
	if (err) {
		folio_put(folio);
		if (err == AOP_TRUNCATED_PAGE)
			goto repeat;
		return ERR_PTR(err);
	}
	folio_lock(folio);
	if (folio->mapping != mapping) {
		/* Truncated while the read was in flight. */
		folio_unlock(folio);
		folio_put(folio);
		goto repeat;
	}
	if (!folio_test_uptodate(folio)) {
		folio_unlock(folio);
		folio_put(folio);
		return ERR_PTR(-EIO);
	}
unlock:
	folio_unlock(folio);
out:
	folio_mark_accessed(folio);
	return folio;
}

const struct address_space_operations ntfs_aops = {
	.read_folio		= ntfs_read_folio,
	.readahead		= ntfs_readahead,
	.writepages		= ntfs_writepages,
	.dirty_folio		= iomap_dirty_folio,
	.bmap			= ntfs_bmap,
	.migrate_folio		= filemap_migrate_folio,
	.is_partially_uptodate	= iomap_is_partially_uptodate,
	.error_remove_folio	= generic_error_remove_folio,
	.release_folio		= iomap_release_folio,
	.invalidate_folio	= iomap_invalidate_folio,
	.swap_activate          = ntfs_swap_activate,
};

const struct address_space_operations ntfs_mft_aops = {
	.read_folio		= ntfs_read_folio,
	.readahead		= ntfs_readahead,
	.writepages		= ntfs_mft_writepages,
	.dirty_folio		= iomap_dirty_folio,
	.bmap			= ntfs_bmap,
	.migrate_folio		= filemap_migrate_folio,
	.is_partially_uptodate	= iomap_is_partially_uptodate,
	.error_remove_folio	= generic_error_remove_folio,
	.release_folio		= iomap_release_folio,
	.invalidate_folio	= iomap_invalidate_folio,
};
