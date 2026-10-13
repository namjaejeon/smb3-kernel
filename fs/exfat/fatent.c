// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>

#include "exfat_raw.h"
#include "exfat_fs.h"
#include "iomap.h"

static int exfat_mirror_bh(struct super_block *sb, struct buffer_head *bh)
{
	struct buffer_head *c_bh;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	sector_t sec = bh->b_blocknr;
	sector_t sec2;
	int err = 0;

	if (sbi->FAT2_start_sector != sbi->FAT1_start_sector) {
		sec2 = sec - sbi->FAT1_start_sector + sbi->FAT2_start_sector;
		c_bh = sb_getblk(sb, sec2);
		if (!c_bh)
			return -ENOMEM;
		memcpy(c_bh->b_data, bh->b_data, sb->s_blocksize);
		err = exfat_update_bh(c_bh, sb->s_flags & SB_SYNCHRONOUS);
		brelse(c_bh);
	}

	return err;
}

static int exfat_end_bh(struct super_block *sb, struct buffer_head *bh)
{
	int err;

	err = exfat_update_bh(bh, sb->s_flags & SB_SYNCHRONOUS);
	if (!err)
		err = exfat_mirror_bh(sb, bh);
	brelse(bh);
	return err;
}

static int __exfat_ent_get(struct super_block *sb, unsigned int loc,
		unsigned int *content, struct buffer_head **cache)
{
	unsigned int off;
	sector_t sec;
	struct buffer_head *bh = *cache;

	sec = FAT_ENT_OFFSET_SECTOR(sb, loc);
	off = FAT_ENT_OFFSET_BYTE_IN_SECTOR(sb, loc);

	if (!bh || bh->b_blocknr != sec || !buffer_uptodate(bh)) {
		brelse(bh);
		bh = sb_bread(sb, sec);
		*cache = bh;
		if (unlikely(!bh))
			return -EIO;
	}

	*content = le32_to_cpu(*(__le32 *)(&bh->b_data[off]));

	/* remap reserved clusters to simplify code */
	if (*content > EXFAT_BAD_CLUSTER)
		*content = EXFAT_EOF_CLUSTER;

	return 0;
}

static int __exfat_ent_set(struct super_block *sb, unsigned int loc,
		unsigned int content, struct buffer_head **cache)
{
	sector_t sec;
	__le32 *fat_entry;
	struct buffer_head *bh = cache ? *cache : NULL;
	unsigned int off;

	sec = FAT_ENT_OFFSET_SECTOR(sb, loc);
	off = FAT_ENT_OFFSET_BYTE_IN_SECTOR(sb, loc);

	if (!bh || bh->b_blocknr != sec || !buffer_uptodate(bh)) {
		if (bh)
			exfat_end_bh(sb, bh);
		bh = sb_bread(sb, sec);
		if (cache)
			*cache = bh;
		if (unlikely(!bh))
			return -EIO;
	}

	fat_entry = (__le32 *)&(bh->b_data[off]);
	*fat_entry = cpu_to_le32(content);
	if (!cache)
		exfat_end_bh(sb, bh);
	return 0;
}

int exfat_ent_set(struct super_block *sb, unsigned int loc,
		unsigned int content)
{
	return __exfat_ent_set(sb, loc, content, NULL);
}

/*
 * Caller must release the buffer_head if no error return.
 */
int exfat_ent_get(struct super_block *sb, unsigned int loc,
		unsigned int *content, struct buffer_head **cache)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (!is_valid_cluster(sbi, loc)) {
		exfat_fs_error_ratelimit(sb,
			"invalid access to FAT (entry 0x%08x)",
			loc);
		goto err;
	}

	if (unlikely(__exfat_ent_get(sb, loc, content, cache))) {
		exfat_fs_error_ratelimit(sb,
			"failed to access to FAT (entry 0x%08x)",
			loc);
		goto err;
	}

	if (unlikely(*content == EXFAT_FREE_CLUSTER)) {
		exfat_fs_error_ratelimit(sb,
			"invalid access to FAT free cluster (entry 0x%08x)",
			loc);
		goto err;
	}

	if (unlikely(*content == EXFAT_BAD_CLUSTER)) {
		exfat_fs_error_ratelimit(sb,
			"invalid access to FAT bad cluster (entry 0x%08x)",
			loc);
		goto err;
	}

	if (*content != EXFAT_EOF_CLUSTER && !is_valid_cluster(sbi, *content)) {
		exfat_fs_error_ratelimit(sb,
			"invalid access to FAT (entry 0x%08x) bogus content (0x%08x)",
			loc, *content);
		goto err;
	}

	return 0;

err:
	/* Avoid double release */
	brelse(*cache);
	*cache = NULL;
	return -EIO;
}

int exfat_blk_readahead(struct super_block *sb, sector_t sec,
		sector_t *ra, blkcnt_t *ra_cnt, sector_t end)
{
	struct blk_plug plug;

	if (sec < *ra)
		return 0;

	*ra += *ra_cnt;

	/* No blocks left (or only the last block), skip readahead. */
	if (*ra >= end)
		return 0;

	*ra_cnt = min(end - *ra + 1, EXFAT_BLK_RA_SIZE(sb));
	if (*ra_cnt == 0) {
		/* Move 'ra' to the end to disable readahead. */
		*ra = end;
		return 0;
	}

	blk_start_plug(&plug);
	for (unsigned int i = 0; i < *ra_cnt; i++)
		sb_breadahead(sb, *ra + i);
	blk_finish_plug(&plug);
	return 0;
}

int exfat_chain_cont_cluster(struct super_block *sb, unsigned int chain,
		unsigned int len)
{
	struct buffer_head *bh = NULL;
	sector_t sec, end, ra;
	blkcnt_t ra_cnt = 0;

	if (!len)
		return 0;

	ra = FAT_ENT_OFFSET_SECTOR(sb, chain);
	end = FAT_ENT_OFFSET_SECTOR(sb, chain + len - 1);

	while (len > 1) {
		sec = FAT_ENT_OFFSET_SECTOR(sb, chain);
		exfat_blk_readahead(sb, sec, &ra, &ra_cnt, end);

		if (__exfat_ent_set(sb, chain, chain + 1, &bh))
			return -EIO;
		chain++;
		len--;
	}

	if (__exfat_ent_set(sb, chain, EXFAT_EOF_CLUSTER, &bh))
		return -EIO;

	exfat_end_bh(sb, bh);
	return 0;
}

static inline void exfat_discard_cluster(struct super_block *sb,
		unsigned int clu, unsigned int num_clusters)
{
	int ret;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	ret = sb_issue_discard(sb, exfat_cluster_to_sector(sbi, clu),
			sbi->sect_per_clus * num_clusters, GFP_NOFS, 0);
	if (ret == -EOPNOTSUPP) {
		exfat_err(sb, "discard not supported by device, disabling");
		sbi->options.discard = 0;
	}
}

/* This function must be called with bitmap_lock held */
static int __exfat_free_cluster(struct inode *inode, struct exfat_chain *p_chain)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	int cur_cmap_i, next_cmap_i;
	unsigned int num_clusters = 0;
	unsigned int clu;

	/* invalid cluster number */
	if (p_chain->dir == EXFAT_FREE_CLUSTER ||
	    p_chain->dir == EXFAT_EOF_CLUSTER ||
	    p_chain->dir < EXFAT_FIRST_CLUSTER)
		return 0;

	/* no cluster to truncate */
	if (p_chain->size == 0)
		return 0;

	/* check cluster validation */
	if (!is_valid_cluster(sbi, p_chain->dir)) {
		exfat_err(sb, "invalid start cluster (%u)", p_chain->dir);
		return -EIO;
	}

	clu = p_chain->dir;

	cur_cmap_i = next_cmap_i =
		BITMAP_OFFSET_SECTOR_INDEX(sb, CLUSTER_TO_BITMAP_ENT(clu));

	if (p_chain->flags == ALLOC_NO_FAT_CHAIN) {
		int err;
		unsigned int last_cluster = p_chain->dir + p_chain->size - 1;

		do {
			bool sync = false;

			if (clu < last_cluster)
				next_cmap_i =
				  BITMAP_OFFSET_SECTOR_INDEX(sb, CLUSTER_TO_BITMAP_ENT(clu+1));

			/* flush bitmap only if index would be changed or for last cluster */
			if (clu == last_cluster || cur_cmap_i != next_cmap_i) {
				sync = true;
				cur_cmap_i = next_cmap_i;
			}

			err = exfat_clear_bitmap(sb, clu, (sync && IS_DIRSYNC(inode)));
			if (err)
				break;
			clu++;
			num_clusters++;
		} while (num_clusters < p_chain->size);

		if (sbi->options.discard)
			exfat_discard_cluster(sb, p_chain->dir, p_chain->size);
	} else {
		unsigned int nr_clu = 1;

		do {
			bool sync = false;
			unsigned int n_clu = clu;
			int err = exfat_get_next_cluster(sb, &n_clu);

			if (err || n_clu == EXFAT_EOF_CLUSTER)
				sync = true;
			else
				next_cmap_i =
				  BITMAP_OFFSET_SECTOR_INDEX(sb, CLUSTER_TO_BITMAP_ENT(n_clu));

			if (cur_cmap_i != next_cmap_i) {
				sync = true;
				cur_cmap_i = next_cmap_i;
			}

			if (exfat_clear_bitmap(sb, clu, (sync && IS_DIRSYNC(inode))))
				break;

			if (sbi->options.discard) {
				if (n_clu == clu + 1)
					nr_clu++;
				else {
					exfat_discard_cluster(sb, clu - nr_clu + 1, nr_clu);
					nr_clu = 1;
				}
			}

			clu = n_clu;
			num_clusters++;

			if (err)
				break;

			if (num_clusters >= sbi->num_clusters - EXFAT_FIRST_CLUSTER) {
				/*
				 * The cluster chain includes a loop, scan the
				 * bitmap to get the number of used clusters.
				 */
				exfat_count_used_clusters(sb, &sbi->used_clusters);

				return 0;
			}
		} while (clu != EXFAT_EOF_CLUSTER);
	}

	sbi->used_clusters -= num_clusters;
	return 0;
}

int exfat_free_cluster(struct inode *inode, struct exfat_chain *p_chain)
{
	int ret = 0;

	mutex_lock(&EXFAT_SB(inode->i_sb)->bitmap_lock);
	ret = __exfat_free_cluster(inode, p_chain);
	mutex_unlock(&EXFAT_SB(inode->i_sb)->bitmap_lock);

	return ret;
}

int exfat_find_last_cluster(struct super_block *sb, struct exfat_chain *p_chain,
		unsigned int *ret_clu)
{
	struct buffer_head *bh = NULL;
	unsigned int clu, next;
	unsigned int count = 0;

	next = p_chain->dir;
	if (p_chain->flags == ALLOC_NO_FAT_CHAIN) {
		*ret_clu = next + p_chain->size - 1;
		return 0;
	}

	do {
		count++;
		clu = next;
		if (exfat_ent_get(sb, clu, &next, &bh))
			return -EIO;
	} while (next != EXFAT_EOF_CLUSTER && count <= p_chain->size);

	brelse(bh);
	if (p_chain->size != count) {
		exfat_fs_error(sb,
			"bogus directory size (clus : ondisk(%d) != counted(%d))",
			p_chain->size, count);
		return -EIO;
	}

	*ret_clu = clu;
	return 0;
}

int exfat_zeroed_cluster(struct inode *dir, unsigned int clu)
{
	struct super_block *sb = dir->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;
	sector_t blknr, last_blknr, i;

	blknr = exfat_cluster_to_sector(sbi, clu);
	last_blknr = blknr + sbi->sect_per_clus;

	if (last_blknr > sbi->num_sectors && sbi->num_sectors > 0) {
		exfat_fs_error_ratelimit(sb,
			"%s: out of range(sect:%llu len:%u)",
			__func__, (unsigned long long)blknr,
			sbi->sect_per_clus);
		return -EIO;
	}

	/* Zeroing the unused blocks on this cluster */
	for (i = blknr; i < last_blknr; i++) {
		bh = sb_getblk(sb, i);
		if (!bh)
			return -ENOMEM;

		memset(bh->b_data, 0, sb->s_blocksize);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		brelse(bh);
	}

	if (IS_DIRSYNC(dir))
		return sync_blockdev_range(sb->s_bdev,
				exfat_block_to_bytes(sb, blknr),
				exfat_block_to_bytes(sb, last_blknr) - 1);

	return 0;
}

/*
 * Newly allocated clusters may still have dirty buffer_heads in the block
 * device mapping, e.g. the dentries of a directory that was just removed.
 * File data does not go through those buffers, so drop them; otherwise a
 * later flush of the block device writes them over the new data.
 */
static void exfat_clean_bdev_aliases(struct super_block *sb,
				     unsigned int clu, unsigned int count)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	clean_bdev_aliases(sb->s_bdev, exfat_cluster_to_sector(sbi, clu),
			   (sector_t)count << sbi->sect_per_clus_bits);
}

/* Reserve a contiguous run without dirtying either the bitmap or the FAT. */
int exfat_reserve_dio_alloc(struct exfat_dio *dio, unsigned int count)
{
	struct inode *inode = file_inode(dio->iocb.ki_filp);
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_dio_alloc *alloc, *last;
	unsigned int hint, clu, mapped = 1;
	int err = 0;

	alloc = kzalloc_obj(*alloc, GFP_NOFS);
	if (!alloc)
		return -ENOMEM;

	mutex_lock(&sbi->s_lock);
	if (list_empty(&dio->allocs)) {
		if (dio->old_clusters) {
			err = exfat_map_cluster(inode, dio->old_clusters - 1,
						&dio->last_clu, &mapped, 0, NULL);
			if (err)
				goto out_unlock;
		}
		hint = dio->last_clu == EXFAT_EOF_CLUSTER ?
			sbi->clu_srch_ptr : dio->last_clu + 1;
	} else {
		last = list_last_entry(&dio->allocs, struct exfat_dio_alloc, list);
		hint = last->clu + last->count;
	}
	if (!is_valid_cluster(sbi, hint))
		hint = EXFAT_FIRST_CLUSTER;

	mutex_lock(&sbi->bitmap_lock);
	if (unlikely(sbi->used_clusters > EXFAT_DATA_CLUSTER_COUNT(sbi))) {
		err = -EIO;
		goto out_bitmap;
	}
	if (count > EXFAT_DATA_CLUSTER_COUNT(sbi) - sbi->used_clusters) {
		err = -ENOSPC;
		goto out_bitmap;
	}
	clu = exfat_find_free_bitmap(sb, hint);
	if (clu == EXFAT_EOF_CLUSTER) {
		err = -ENOSPC;
		goto out_bitmap;
	}
	alloc->clu = clu;
	while (alloc->count < count && is_valid_cluster(sbi, clu)) {
		if (exfat_test_bitmap(sb, clu) ||
		    xa_load(&sbi->dio_reservations, clu))
			break;
		err = xa_insert(&sbi->dio_reservations, clu, xa_mk_value(1),
				GFP_NOFS);
		if (err)
			goto undo;
		alloc->count++;
		sbi->used_clusters++;
		clu++;
	}
	sbi->clu_srch_ptr = is_valid_cluster(sbi, clu) ? clu : EXFAT_FIRST_CLUSTER;
	exfat_clean_bdev_aliases(sb, alloc->clu, alloc->count);
	list_add_tail(&alloc->list, &dio->allocs);
	mutex_unlock(&sbi->bitmap_lock);
	mutex_unlock(&sbi->s_lock);
	return 0;

undo:
	while (alloc->count) {
		xa_erase(&sbi->dio_reservations, alloc->clu + --alloc->count);
		sbi->used_clusters--;
	}
out_bitmap:
	mutex_unlock(&sbi->bitmap_lock);
out_unlock:
	mutex_unlock(&sbi->s_lock);
	kfree(alloc);
	return err;
}

void exfat_release_dio_alloc(struct exfat_dio *dio)
{
	struct super_block *sb = file_inode(dio->iocb.ki_filp)->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_dio_alloc *alloc, *next;
	unsigned int i;

	if (list_empty(&dio->allocs))
		return;
	mutex_lock(&sbi->s_lock);
	mutex_lock(&sbi->bitmap_lock);
	list_for_each_entry_safe(alloc, next, &dio->allocs, list) {
		sbi->clu_srch_ptr = alloc->clu;
		for (i = 0; i < alloc->count; i++) {
			xa_erase(&sbi->dio_reservations, alloc->clu + i);
			sbi->used_clusters--;
		}
		list_del(&alloc->list);
		kfree(alloc);
	}
	mutex_unlock(&sbi->bitmap_lock);
	mutex_unlock(&sbi->s_lock);
}

/*
 * Called after all data bios have completed, with s_lock held. Prepare the
 * private chain and any old NoFatChain conversion before changing the live
 * file. A preparation error leaves only unused FAT entries in free clusters.
 *
 * Prefetch both copies of the old tail's FAT sector before publishing bitmap
 * bits, so no allocation or read failure can interrupt the in-memory attach.
 * Final FAT/bitmap/stream-entry persistence is the normal non-journaled exFAT
 * update; this does not make that final metadata update crash atomic.
 */
int exfat_commit_dio_alloc(struct exfat_dio *dio, loff_t end)
{
	struct inode *inode = file_inode(dio->iocb.ki_filp);
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_dio_alloc *alloc, *next;
	struct buffer_head *tail_bh = NULL, *mirror_bh = NULL;
	unsigned int count = exfat_bytes_to_cluster_round_up(sbi, end);
	unsigned int remaining, n, prev = dio->last_clu, first, i;
	bool fat = dio->old_clusters && ei->flags == ALLOC_FAT_CHAIN;
	int err = 0;

	lockdep_assert_held(&sbi->s_lock);
	if (count <= dio->old_clusters)
		return 0;
	count -= dio->old_clusters;
	remaining = count;
	list_for_each_entry(alloc, &dio->allocs, list) {
		n = min(alloc->count, remaining);
		if (prev != EXFAT_EOF_CLUSTER && alloc->clu != prev + 1)
			fat = true;
		prev = alloc->clu + n - 1;
		remaining -= n;
		if (!remaining)
			break;
	}
	if (WARN_ON_ONCE(remaining))
		return -EIO;
	alloc = list_first_entry(&dio->allocs, struct exfat_dio_alloc, list);
	first = alloc->clu;
	exfat_set_volume_dirty(sb);
	if (fat) {
		if (dio->old_clusters && ei->flags == ALLOC_NO_FAT_CHAIN) {
			err = exfat_chain_cont_cluster(sb, ei->start_clu,
						       dio->old_clusters);
			if (err)
				return err;
		}
		remaining = count;
		prev = EXFAT_EOF_CLUSTER;
		list_for_each_entry(alloc, &dio->allocs, list) {
			n = min(alloc->count, remaining);
			err = exfat_chain_cont_cluster(sb, alloc->clu, n);
			if (err)
				return err;
			if (prev != EXFAT_EOF_CLUSTER) {
				err = exfat_ent_set(sb, prev, alloc->clu);
				if (err)
					return err;
			}
			prev = alloc->clu + n - 1;
			remaining -= n;
			if (!remaining)
				break;
		}
		if (dio->old_clusters) {
			sector_t sec = FAT_ENT_OFFSET_SECTOR(sb, dio->last_clu);

			tail_bh = sb_bread(sb, sec);
			if (!tail_bh)
				return -EIO;
			if (sbi->FAT2_start_sector != sbi->FAT1_start_sector) {
				sec += sbi->FAT2_start_sector - sbi->FAT1_start_sector;
				mirror_bh = sb_getblk(sb, sec);
				if (!mirror_bh) {
					brelse(tail_bh);
					return -ENOMEM;
				}
			}
		}
	}

	mutex_lock(&sbi->bitmap_lock);
	remaining = count;
	list_for_each_entry_safe(alloc, next, &dio->allocs, list) {
		n = min(alloc->count, remaining);
		for (i = 0; i < n; i++) {
			exfat_set_bitmap(sb, alloc->clu + i, inode_needs_sync(inode));
			xa_erase(&sbi->dio_reservations, alloc->clu + i);
		}
		alloc->clu += n;
		alloc->count -= n;
		if (!alloc->count) {
			list_del(&alloc->list);
			kfree(alloc);
		}
		remaining -= n;
		if (!remaining)
			break;
	}
	/* used_clusters already accounts for the reservations. */
	mutex_unlock(&sbi->bitmap_lock);

	if (tail_bh) {
		unsigned int off = FAT_ENT_OFFSET_BYTE_IN_SECTOR(sb, dio->last_clu);

		*(__le32 *)(tail_bh->b_data + off) = cpu_to_le32(first);
		if (mirror_bh)
			memcpy(mirror_bh->b_data, tail_bh->b_data, sb->s_blocksize);
	}
	if (!dio->old_clusters)
		ei->start_clu = first;
	ei->flags = fat ? ALLOC_FAT_CHAIN : ALLOC_NO_FAT_CHAIN;
	inode->i_blocks += exfat_cluster_to_sectors(sbi, count);
	dio->committed = true;

	if (tail_bh) {
		err = exfat_update_bh(tail_bh, sb->s_flags & SB_SYNCHRONOUS);
		brelse(tail_bh);
	}
	if (mirror_bh) {
		int ret = exfat_update_bh(mirror_bh, sb->s_flags & SB_SYNCHRONOUS);

		if (!err)
			err = ret;
		brelse(mirror_bh);
	}
	return err;
}

int exfat_alloc_cluster(struct inode *inode, unsigned int num_alloc,
		struct exfat_chain *p_chain, bool sync_bmap, bool contig)
{
	int ret = -ENOSPC;
	unsigned int total_cnt;
	unsigned int hint_clu, new_clu, last_clu = EXFAT_EOF_CLUSTER;
	unsigned int run_clu = EXFAT_EOF_CLUSTER, run_len = 0;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	mutex_lock(&sbi->bitmap_lock);

	total_cnt = EXFAT_DATA_CLUSTER_COUNT(sbi);

	if (unlikely(total_cnt < sbi->used_clusters)) {
		exfat_fs_error_ratelimit(sb,
			"%s: invalid used clusters(t:%u,u:%u)\n",
			__func__, total_cnt, sbi->used_clusters);
		ret = -EIO;
		goto unlock;
	}

	if (num_alloc > total_cnt - sbi->used_clusters) {
		ret = -ENOSPC;
		goto unlock;
	}

	hint_clu = p_chain->dir;
	/* find new cluster */
	if (hint_clu == EXFAT_EOF_CLUSTER) {
		if (sbi->clu_srch_ptr < EXFAT_FIRST_CLUSTER) {
			exfat_err(sb, "sbi->clu_srch_ptr is invalid (%u)",
				  sbi->clu_srch_ptr);
			sbi->clu_srch_ptr = EXFAT_FIRST_CLUSTER;
		}

		hint_clu = exfat_find_free_bitmap(sb, sbi->clu_srch_ptr);
		if (hint_clu == EXFAT_EOF_CLUSTER) {
			ret = -ENOSPC;
			goto unlock;
		}
	}

	/* check cluster validation */
	if (!is_valid_cluster(sbi, hint_clu)) {
		if (hint_clu != sbi->num_clusters)
			exfat_err(sb, "hint_cluster is invalid (%u), rewind to the first cluster",
					hint_clu);
		hint_clu = EXFAT_FIRST_CLUSTER;
		p_chain->flags = ALLOC_FAT_CHAIN;
	}

	p_chain->dir = EXFAT_EOF_CLUSTER;

	while ((new_clu = exfat_find_free_bitmap(sb, hint_clu)) !=
	       EXFAT_EOF_CLUSTER) {
		if (new_clu != hint_clu) {
			if (p_chain->flags == ALLOC_NO_FAT_CHAIN) {
				if (exfat_chain_cont_cluster(sb, p_chain->dir,
							     p_chain->size)) {
					ret = -EIO;
					goto free_cluster;
				}
				p_chain->flags = ALLOC_FAT_CHAIN;
			}

			if (contig && p_chain->size > 0) {
				hint_clu = last_clu;
				goto done;
			}
		}

		/* update allocation bitmap */
		if (exfat_set_bitmap(sb, new_clu, sync_bmap)) {
			ret = -EIO;
			goto free_cluster;
		}

		/* update FAT table */
		if (p_chain->flags == ALLOC_FAT_CHAIN) {
			if (exfat_ent_set(sb, new_clu, EXFAT_EOF_CLUSTER)) {
				ret = -EIO;
				goto free_cluster;
			}
		}

		if (p_chain->dir == EXFAT_EOF_CLUSTER) {
			p_chain->dir = new_clu;
		} else if (p_chain->flags == ALLOC_FAT_CHAIN) {
			if (exfat_ent_set(sb, last_clu, new_clu)) {
				ret = -EIO;
				goto free_cluster;
			}
		}
		p_chain->size++;
		sbi->used_clusters++;

		/* clean stale buffers once per contiguous run of clusters */
		if (run_len && new_clu == run_clu + run_len) {
			run_len++;
		} else {
			if (run_len)
				exfat_clean_bdev_aliases(sb, run_clu, run_len);
			run_clu = new_clu;
			run_len = 1;
		}

		last_clu = new_clu;

		if (p_chain->size == num_alloc) {
done:
			exfat_clean_bdev_aliases(sb, run_clu, run_len);
			sbi->clu_srch_ptr = hint_clu;
			ret = 0;
			goto unlock;
		}

		hint_clu = new_clu + 1;
		if (hint_clu >= sbi->num_clusters) {
			hint_clu = EXFAT_FIRST_CLUSTER;

			if (p_chain->flags == ALLOC_NO_FAT_CHAIN) {
				if (exfat_chain_cont_cluster(sb, p_chain->dir,
						p_chain->size)) {
					ret = -EIO;
					goto free_cluster;
				}
				p_chain->flags = ALLOC_FAT_CHAIN;
			}
		}
	}
free_cluster:
	__exfat_free_cluster(inode, p_chain);
unlock:
	mutex_unlock(&sbi->bitmap_lock);
	return ret;
}

int exfat_count_num_clusters(struct super_block *sb,
		struct exfat_chain *p_chain, unsigned int *ret_count)
{
	unsigned int i, count;
	unsigned int clu;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh = NULL;

	if (!p_chain->dir || p_chain->dir == EXFAT_EOF_CLUSTER) {
		*ret_count = 0;
		return 0;
	}

	if (p_chain->flags == ALLOC_NO_FAT_CHAIN) {
		*ret_count = p_chain->size;
		return 0;
	}

	clu = p_chain->dir;
	count = 0;
	for (i = EXFAT_FIRST_CLUSTER; i < sbi->num_clusters; i++) {
		count++;
		if (exfat_ent_get(sb, clu, &clu, &bh))
			return -EIO;
		if (clu == EXFAT_EOF_CLUSTER)
			break;
	}

	brelse(bh);
	*ret_count = count;

	/*
	 * since exfat_count_used_clusters() is not called, sbi->used_clusters
	 * cannot be used here.
	 */
	if (unlikely(i == sbi->num_clusters && clu != EXFAT_EOF_CLUSTER)) {
		exfat_fs_error(sb, "The cluster chain has a loop");
		return -EIO;
	}

	return 0;
}
