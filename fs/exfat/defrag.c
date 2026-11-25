// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Namjae Jeon <linkinjeon@kernel.org>
 *
 * Online allocation queries and bounded copy-update-free relocation.
 */
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/folio_batch.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/sizes.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <linux/vmalloc.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

#define EXFAT_MOVE_MAX_BYTES	SZ_32M
#define EXFAT_BITMAP_MAX_BYTES	SZ_1M
#define EXFAT_EXTENTS_MAX	4096
#define EXFAT_COPY_BYTES		SZ_64K
#define EXFAT_FAT_BATCH_BYTES	SZ_64K

static unsigned int exfat_max_move_clusters(struct exfat_sb_info *sbi)
{
	return EXFAT_MOVE_MAX_BYTES >> sbi->cluster_size_bits;
}

long exfat_ioctl_get_volume_bitmap(struct file *file, void __user *arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_volume_bitmap map;
	unsigned char *bitmap;
	u64 start, total = EXFAT_DATA_CLUSTER_COUNT(sbi);
	unsigned int bytes, done = 0, index, offset, len;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (exfat_forced_shutdown(sb))
		return -EIO;
	if (copy_from_user(&map, arg, sizeof(map)))
		return -EFAULT;
	if (map.flags || map.reserved || !map.bitmap_bytes ||
	    map.bitmap_bytes > EXFAT_BITMAP_MAX_BYTES || map.start_lcn > total)
		return -EINVAL;
	start = map.start_lcn == total ? total : round_down(map.start_lcn, 8);
	bytes = min_t(u64, map.bitmap_bytes, DIV_ROUND_UP_ULL(total - start, 8));
	bitmap = kvmalloc(max(bytes, 1U), GFP_KERNEL);
	if (!bitmap)
		return -ENOMEM;

	mutex_lock(&sbi->bitmap_lock);
	while (done < bytes) {
		index = (start / 8 + done) >> sb->s_blocksize_bits;
		offset = (start / 8 + done) & (sb->s_blocksize - 1);
		len = min(bytes - done, (unsigned int)sb->s_blocksize - offset);
		memcpy(bitmap + done, sbi->vol_amap[index]->b_data + offset, len);
		done += len;
	}
	mutex_unlock(&sbi->bitmap_lock);
	if (bytes && start + (u64)bytes * 8 > total)
		bitmap[bytes - 1] |= 0xffU << (total & 7);

	map.start_lcn = start;
	map.total_clusters = total;
	map.bytes_returned = bytes;
	map.cluster_size = sbi->cluster_size;
	map.max_move_clusters = exfat_max_move_clusters(sbi);
	if ((bytes && copy_to_user(u64_to_user_ptr(map.bitmap), bitmap, bytes)) ||
	    copy_to_user(arg, &map, sizeof(map)))
		ret = -EFAULT;
	kvfree(bitmap);
	return ret;
}

static int exfat_cluster_at(struct inode *inode, unsigned int vcn,
			    unsigned int *cluster)
{
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	unsigned int count = 1, last;
	int ret;

	if (ei->flags == ALLOC_NO_FAT_CHAIN) {
		if (!is_valid_cluster(sbi, ei->start_clu) ||
		    vcn >= sbi->num_clusters - ei->start_clu)
			return -EIO;
		*cluster = ei->start_clu + vcn;
		return 0;
	}
	ret = exfat_get_cluster(inode, vcn, cluster, &count, &last);
	if (!ret && (!count || !is_valid_cluster(sbi, *cluster)))
		ret = -EIO;
	return ret;
}

long exfat_ioctl_get_retrieval_pointers(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_retrieval_pointers map;
	struct exfat_extent *extents, *extent;
	struct buffer_head *fat_bh = NULL;
	unsigned int cluster, next, vcn, total;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;
	if (copy_from_user(&map, arg, sizeof(map)))
		return -EFAULT;
	if (map.flags || map.reserved || !map.extent_capacity ||
	    map.extent_capacity > EXFAT_EXTENTS_MAX)
		return -EINVAL;
	extents = kvmalloc_objs(*extents, map.extent_capacity, GFP_KERNEL);
	if (!extents)
		return -ENOMEM;

	/* The shared inode lock protects the regular file's allocation. */
	inode_lock_shared(inode);
	if (exfat_forced_shutdown(inode->i_sb)) {
		ret = -EIO;
		goto unlock;
	}
	total = exfat_bytes_to_cluster(sbi, exfat_ondisk_size(inode));
	if (map.start_vcn > total) {
		ret = -EINVAL;
		goto unlock;
	}
	map.extent_count = 0;
	map.total_clusters = total;
	map.next_vcn = vcn = map.start_vcn;
	if (vcn == total)
		goto unlock;
	ret = exfat_cluster_at(inode, vcn, &cluster);
	if (ret)
		goto unlock;
	if (ei->flags == ALLOC_NO_FAT_CHAIN) {
		if (total - vcn > sbi->num_clusters - cluster) {
			ret = -EIO;
			goto unlock;
		}
		extents[0].vcn = vcn;
		extents[0].lcn = cluster - EXFAT_RESERVED_CLUSTERS;
		extents[0].cluster_count = total - vcn;
		map.extent_count = 1;
		map.next_vcn = total;
		goto unlock;
	}
	while (vcn < total) {
		if (signal_pending(current)) {
			ret = -EINTR;
			goto unlock;
		}
		if (!is_valid_cluster(sbi, cluster)) {
			ret = -EIO;
			goto unlock;
		}
		extent = map.extent_count ? &extents[map.extent_count - 1] : NULL;
		if (extent && extent->lcn + extent->cluster_count ==
		    cluster - EXFAT_RESERVED_CLUSTERS) {
			extent->cluster_count++;
		} else {
			if (map.extent_count == map.extent_capacity)
				break;
			extent = &extents[map.extent_count++];
			extent->vcn = vcn;
			extent->lcn = cluster - EXFAT_RESERVED_CLUSTERS;
			extent->cluster_count = 1;
		}
		vcn++;
		if (vcn == total)
			break;
		ret = exfat_ent_get(inode->i_sb, cluster, &next, &fat_bh);
		if (ret)
			goto unlock;
		cluster = next;
		cond_resched();
	}
	map.next_vcn = vcn;
unlock:
	brelse(fat_bh);
	if (!ret && exfat_forced_shutdown(inode->i_sb))
		ret = -EIO;
	inode_unlock_shared(inode);
	if (!ret &&
	    ((map.extent_count && copy_to_user(u64_to_user_ptr(map.extents),
				extents, map.extent_count * sizeof(*extents))) ||
	     copy_to_user(arg, &map, sizeof(map))))
		ret = -EFAULT;
	kvfree(extents);
	return ret;
}

struct exfat_move {
	struct inode *inode;
	struct exfat_entry_set_cache es;
	struct folio **folios;
	unsigned int nr_folios;
	unsigned int *source;
	unsigned int *sorted;
	unsigned int count;
	unsigned int total;
	unsigned int target;
	unsigned int previous;
	unsigned int after;
	void *buffer;
	bool have_entries;
	bool reserved;
	bool publishing;
	bool metadata_error;
	bool no_fat_chain;
};

static int exfat_compare_cluster(const void *a, const void *b)
{
	unsigned int ca = *(const unsigned int *)a;
	unsigned int cb = *(const unsigned int *)b;

	return (ca > cb) - (ca < cb);
}

/* Batch FAT entries by sector, checking every metadata write's result. */
static int exfat_move_fat_set(struct super_block *sb, unsigned int cluster,
			     unsigned int next, struct buffer_head **cache)
{
	sector_t sector = FAT_ENT_OFFSET_SECTOR(sb, cluster);
	struct buffer_head *bh = *cache;
	int ret;

	if (bh && bh->b_blocknr != sector) {
		ret = exfat_update_bh(bh, true);
		brelse(bh);
		*cache = bh = NULL;
		if (ret)
			return ret;
	}
	if (!bh) {
		bh = sb_bread(sb, sector);
		if (!bh)
			return -EIO;
		*cache = bh;
	}
	put_unaligned_le32(next, bh->b_data +
			  FAT_ENT_OFFSET_BYTE_IN_SECTOR(sb, cluster));
	mark_buffer_dirty(bh);
	return 0;
}

static int exfat_move_fat_finish(struct super_block *sb,
				struct buffer_head *bh, int ret)
{
	if (bh) {
		if (!ret)
			ret = exfat_update_bh(bh, true);
		brelse(bh);
	}
	if (!ret)
		ret = blkdev_issue_flush(sb->s_bdev);
	return ret;
}

static int exfat_move_fat_run(struct super_block *sb, unsigned int first,
			     unsigned int count, unsigned int after)
{
	struct buffer_head *bh = NULL;
	unsigned int i;
	int ret = 0;

	for (i = 0; i < count; i++) {
		ret = exfat_move_fat_set(sb, first + i,
				i + 1 < count ? first + i + 1 : after, &bh);
		if (ret)
			break;
		cond_resched();
	}
	return exfat_move_fat_finish(sb, bh, ret);
}

/* Commit secondary sectors before the primary sector's entry-set checksum. */
static int exfat_move_write_entries(struct exfat_move *move)
{
	struct super_block *sb = move->inode->i_sb;
	struct exfat_entry_set_cache *es = &move->es;
	unsigned int i;
	int ret = 0;

	for (i = 1; i < es->num_bh; i++) {
		ret = exfat_update_bh(es->bh[i], true);
		if (ret)
			goto out;
	}
	if (es->num_bh > 1) {
		ret = blkdev_issue_flush(sb->s_bdev);
		if (ret)
			goto out;
	}
	ret = exfat_update_bh(es->bh[0], true);
	if (!ret)
		ret = blkdev_issue_flush(sb->s_bdev);
out:
	return ret;
}

static int exfat_move_commit_entries(struct exfat_move *move)
{
	int ret;

	exfat_update_dir_chksum(&move->es);
	ret = exfat_move_write_entries(move);
	if (ret) {
		/*
		 * A secondary sector may already contain the new stream while
		 * the primary still has the old checksum. Both mappings here
		 * name durable data. Try once to finish this exact entry set;
		 * fsck otherwise deletes a file with a mismatched checksum.
		 * Still report the error, retain allocations and shut down.
		 */
		move->metadata_error = true;
		if (exfat_move_write_entries(move))
			exfat_err(move->inode->i_sb,
				  "relocation entry-set repair failed");
	}
	move->es.modified = false;
	return ret;
}

static int exfat_move_read_source(struct exfat_move *move,
				  const struct exfat_move_file *req)
{
	struct inode *inode = move->inode;
	struct super_block *sb = inode->i_sb;
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh = NULL;
	unsigned int cluster, i;
	int ret;

	ret = exfat_cluster_at(inode, req->start_vcn, &cluster);
	if (ret)
		return ret;
	if (cluster - EXFAT_RESERVED_CLUSTERS != req->expected_lcn)
		return -ESTALE;
	move->previous = 0;
	if (req->start_vcn) {
		ret = exfat_cluster_at(inode, req->start_vcn - 1, &move->previous);
		if (ret)
			return ret;
	}
	for (i = 0; i < move->count; i++) {
		if (!is_valid_cluster(sbi, cluster)) {
			ret = -EIO;
			goto out;
		}
		move->source[i] = cluster;
		if (ei->flags == ALLOC_NO_FAT_CHAIN) {
			cluster = req->start_vcn + i + 1 < move->total ?
					cluster + 1 : EXFAT_EOF_CLUSTER;
		} else {
			ret = exfat_ent_get(sb, cluster, &cluster, &bh);
			if (ret)
				goto out;
		}
		cond_resched();
	}
	move->after = cluster;
	if (req->start_vcn + move->count == move->total) {
		if (cluster != EXFAT_EOF_CLUSTER) {
			ret = -EIO;
			goto out;
		}
	} else if (!is_valid_cluster(sbi, cluster)) {
		ret = -EIO;
		goto out;
	}
	memcpy(move->sorted, move->source, move->count * sizeof(*move->source));
	sort(move->sorted, move->count, sizeof(*move->sorted),
	     exfat_compare_cluster, NULL);
	for (i = 0; i < move->count; i++) {
		if ((i && move->sorted[i] == move->sorted[i - 1]) ||
		    move->sorted[i] == move->previous ||
		    move->sorted[i] == move->after) {
			ret = -EIO;
			goto out;
		}
	}
	ret = 0;
out:
	brelse(bh);
	return ret;
}

static int exfat_move_get_entries(struct exfat_move *move)
{
	struct inode *inode = move->inode;
	struct exfat_entry_set_cache *es = &move->es;
	struct exfat_dentry *ep;
	unsigned int i, type;
	u16 checksum = 0, expected;
	int ret;

	ret = exfat_get_dentry_set_by_ei(es, inode->i_sb, EXFAT_I(inode));
	if (ret)
		return ret;
	move->have_entries = true;
	ep = exfat_get_dentry_cached(es, ES_IDX_FILE);
	expected = le16_to_cpu(ep->dentry.file.checksum);
	for (i = 0; i < es->num_entries; i++) {
		ep = exfat_get_dentry_cached(es, i);
		type = exfat_get_entry_type(ep);
		if (type == TYPE_VENDOR_ALLOC || type == TYPE_VENDOR_EXT)
			return -EOPNOTSUPP;
		checksum = exfat_calc_chksum16(ep, DENTRY_SIZE, checksum,
					       i ? CS_DEFAULT : CS_DIR_ENTRY);
	}
	return checksum == expected ? 0 : -EUCLEAN;
}

static int exfat_move_reserve(struct exfat_move *move)
{
	struct super_block *sb = move->inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int i;
	int ret = 0;

	mutex_lock(&sbi->bitmap_lock);
	for (i = 0; i < move->count; i++) {
		if (!exfat_test_bitmap(sb, move->source[i])) {
			ret = -EUCLEAN;
			goto unlock;
		}
		if (exfat_test_bitmap(sb, move->target + i)) {
			ret = -EBUSY;
			goto unlock;
		}
	}
	exfat_set_volume_dirty(sb);
	if (buffer_write_io_error(sbi->boot_bh)) {
		ret = -EIO;
		move->metadata_error = true;
		goto unlock;
	}
	ret = blkdev_issue_flush(sb->s_bdev);
	if (ret) {
		move->metadata_error = true;
		goto unlock;
	}
	for (i = 0; i < move->count; i++)
		exfat_set_bitmap(sb, move->target + i, false);
	sbi->used_clusters += move->count;
	move->reserved = true;
unlock:
	mutex_unlock(&sbi->bitmap_lock);
	return ret;
}

static int exfat_move_sync_bitmap(struct exfat_move *move, bool destination)
{
	struct super_block *sb = move->inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int i, cluster, index, previous = UINT_MAX;
	int ret;

	mutex_lock(&sbi->bitmap_lock);
	for (i = 0; i < move->count; i++) {
		cluster = destination ? move->target + i : move->sorted[i];
		index = BITMAP_OFFSET_SECTOR_INDEX(sb, CLUSTER_TO_BITMAP_ENT(cluster));
		if (index == previous)
			continue;
		ret = exfat_update_bh(sbi->vol_amap[index], true);
		if (ret)
			goto unlock;
		previous = index;
	}
	ret = blkdev_issue_flush(sb->s_bdev);
unlock:
	mutex_unlock(&sbi->bitmap_lock);
	return ret;
}

/* This path deliberately does not discard blocks: keep old data on I/O error. */
static int exfat_move_release(struct exfat_move *move, bool destination)
{
	struct super_block *sb = move->inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int i, cluster;
	int ret = 0;

	mutex_lock(&sbi->bitmap_lock);
	for (i = 0; i < move->count; i++) {
		cluster = destination ? move->target + i : move->source[i];
		ret = exfat_clear_bitmap(sb, cluster, false);
		if (ret)
			goto unlock;
		sbi->used_clusters--;
	}
unlock:
	mutex_unlock(&sbi->bitmap_lock);
	if (!ret)
		ret = exfat_move_sync_bitmap(move, destination);
	return ret;
}

static int exfat_move_copy(struct exfat_move *move, unsigned int start_vcn)
{
	struct super_block *sb = move->inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	loff_t valid = exfat_get_valid_size(EXFAT_I(move->inode));
	u64 done = 0, bytes = exfat_cluster_to_bytes(sbi, move->count);
	u64 file_offset, source_offset, target_offset;
	unsigned int i, end, len, initialized;
	int ret;

	clean_bdev_aliases(sb->s_bdev, exfat_cluster_to_sector(sbi, move->target),
			  (sector_t)move->count << sbi->sect_per_clus_bits);
	while (done < bytes) {
		if (signal_pending(current))
			return -EINTR;
		i = done >> sbi->cluster_size_bits;
		end = i + 1;
		while (end < move->count &&
		       exfat_cluster_to_bytes(sbi, end - i) < EXFAT_COPY_BYTES &&
		       move->source[end] == move->source[end - 1] + 1)
			end++;
		len = min_t(u64, EXFAT_COPY_BYTES,
			    exfat_cluster_to_bytes(sbi, end) - done);
		file_offset = exfat_cluster_to_bytes(sbi, start_vcn) + done;
		initialized = file_offset < valid ?
				min_t(u64, len, valid - file_offset) : 0;
		source_offset = exfat_cluster_to_phys_bytes(sbi, move->source[i]) +
				exfat_cluster_offset(sbi, done);
		target_offset = exfat_cluster_to_phys_bytes(sbi, move->target) + done;
		if (initialized) {
			ret = bdev_rw_virt(sb->s_bdev, source_offset >> SECTOR_SHIFT,
					   move->buffer, len, REQ_OP_READ);
			if (ret)
				return ret;
		}
		memset(move->buffer + initialized, 0, len - initialized);
		ret = bdev_rw_virt(sb->s_bdev, target_offset >> SECTOR_SHIFT,
				   move->buffer, len, REQ_OP_WRITE);
		if (ret)
			return ret;
		done += len;
		cond_resched();
	}
	return blkdev_issue_flush(sb->s_bdev);
}

static int exfat_move_check_inode(struct inode *inode);

/* Keep the stream NoFatChain until every source FAT entry is durable. */
static int exfat_move_materialize_chain(struct exfat_move *move)
{
	struct inode *inode = move->inode;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	unsigned int first = ei->start_clu, done = 0, count, i, after;
	int ret;

	if (!is_valid_cluster(sbi, first) || move->total > sbi->num_clusters - first)
		return -EIO;
	/* Do not retain a directory entry set across the s_lock handoffs. */
	exfat_put_dentry_set(&move->es, false);
	move->have_entries = false;
	while (done < move->total) {
		ret = exfat_move_check_inode(inode);
		if (ret) {
			if (exfat_forced_shutdown(sb) || sb_rdonly(sb))
				move->metadata_error = true;
			return ret;
		}
		if (signal_pending(current))
			return -EINTR;
		if (ei->flags != ALLOC_NO_FAT_CHAIN || ei->start_clu != first ||
		    exfat_bytes_to_cluster(sbi, exfat_ondisk_size(inode)) != move->total)
			return -ESTALE;
		count = min_t(unsigned int, move->total - done,
			      EXFAT_FAT_BATCH_BYTES / sizeof(__le32));
		ret = 0;
		mutex_lock(&sbi->bitmap_lock);
		for (i = 0; i < count; i++) {
			if (!exfat_test_bitmap(sb, first + done + i)) {
				ret = -EUCLEAN;
				break;
			}
		}
		mutex_unlock(&sbi->bitmap_lock);
		if (ret)
			return ret;
		after = done + count < move->total ? first + done + count : EXFAT_EOF_CLUSTER;
		ret = exfat_move_fat_run(sb, first + done, count, after);
		if (ret) {
			move->metadata_error = true;
			return ret;
		}
		done += count;
		if (done < move->total) {
			/* inode_lock and invalidate_lock keep this allocation fixed. */
			mutex_unlock(&sbi->s_lock);
			cond_resched();
			mutex_lock(&sbi->s_lock);
		}
	}
	if (signal_pending(current))
		return -EINTR;
	ret = exfat_move_check_inode(inode);
	if (ret && (exfat_forced_shutdown(sb) || sb_rdonly(sb)))
		move->metadata_error = true;
	return ret;
}

static int exfat_move_convert_chain(struct exfat_move *move)
{
	struct inode *inode = move->inode;
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_dentry *stream;
	int ret;

	if (ei->flags != ALLOC_NO_FAT_CHAIN)
		return 0;
	ret = exfat_move_materialize_chain(move);
	if (ret)
		return ret;
	ret = exfat_move_get_entries(move);
	if (ret) {
		if (ret == -EIO)
			move->metadata_error = true;
		return ret;
	}
	stream = exfat_get_dentry_cached(&move->es, ES_IDX_STREAM);
	stream->dentry.stream.flags = ALLOC_FAT_CHAIN;
	ret = exfat_move_commit_entries(move);
	/* Both representations map the same source allocation at this point. */
	ei->flags = ALLOC_FAT_CHAIN;
	return ret;
}

static int exfat_move_publish(struct exfat_move *move)
{
	struct inode *inode = move->inode;
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_dentry *stream;
	struct buffer_head *bh = NULL;
	int ret;

	move->publishing = true;
	if (move->previous) {
		ret = exfat_move_fat_set(inode->i_sb, move->previous,
					 move->target, &bh);
		ret = exfat_move_fat_finish(inode->i_sb, bh, ret);
	} else {
		stream = exfat_get_dentry_cached(&move->es, ES_IDX_STREAM);
		stream->dentry.stream.start_clu = cpu_to_le32(move->target);
		if (move->no_fat_chain)
			stream->dentry.stream.flags = ALLOC_NO_FAT_CHAIN;
		ret = exfat_move_commit_entries(move);
		ei->start_clu = move->target;
		if (move->no_fat_chain)
			ei->flags = ALLOC_NO_FAT_CHAIN;
	}
	exfat_cache_inval_inode(inode);
	ei->hint_bmap.off = 0;
	ei->hint_bmap.clu = ei->start_clu;
	return ret;
}

static int exfat_move_check_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (exfat_forced_shutdown(sb))
		return -EIO;
	if (sb_rdonly(sb))
		return -EROFS;
	if (!inode->i_nlink || EXFAT_I(inode)->dir.dir == DIR_DELETED)
		return -ENOENT;
	if (IS_SWAPFILE(inode) || IS_IMMUTABLE(inode) || IS_APPEND(inode))
		return -EPERM;
	if (sbi->FAT1_start_sector != sbi->FAT2_start_sector)
		return -EOPNOTSUPP;
	if (sbi->vol_flags_persistent & (VOLUME_DIRTY | MEDIA_FAILURE))
		return -EUCLEAN;
	return 0;
}

static int exfat_move_locked(struct exfat_move *move,
			     const struct exfat_move_file *req)
{
	struct inode *inode = move->inode;
	struct super_block *sb = inode->i_sb;
	unsigned int i;
	int ret, cleanup;

	ret = exfat_move_check_inode(inode);
	if (ret)
		return ret;
	ret = exfat_move_read_source(move, req);
	if (ret)
		return ret;
	for (i = 0; i < move->count; i++)
		if (move->source[i] != move->target + i)
			break;
	if (i == move->count)
		return 0;
	move->no_fat_chain = !req->start_vcn && move->count == move->total;
	ret = exfat_move_get_entries(move);
	if (ret)
		return ret;
	ret = exfat_move_reserve(move);
	if (ret)
		goto out;
	ret = exfat_move_copy(move, req->start_vcn);
	if (ret)
		goto out;
	if (signal_pending(current)) {
		ret = -EINTR;
		goto out;
	}
	if (!move->no_fat_chain) {
		ret = exfat_move_convert_chain(move);
		if (ret)
			goto out;
	}
	if (signal_pending(current)) {
		ret = -EINTR;
		goto out;
	}
	ret = 0;
	if (!move->no_fat_chain)
		ret = exfat_move_fat_run(sb, move->target, move->count, move->after);
	if (!ret)
		ret = exfat_move_sync_bitmap(move, true);
	if (ret) {
		move->metadata_error = true;
		goto out;
	}
	ret = exfat_move_publish(move);
	if (ret) {
		move->metadata_error = true;
		goto out;
	}
	ret = exfat_move_release(move, false);
	if (ret)
		move->metadata_error = true;
out:
	/* An uncertain publication must keep both allocations, even on error. */
	if (ret && move->reserved && !move->publishing && !move->metadata_error) {
		cleanup = exfat_move_release(move, true);
		if (cleanup) {
			ret = cleanup;
			move->metadata_error = true;
		}
	}
	return ret;
}

/* Check once after a placement plan, rather than after every bounded move. */
static int exfat_set_no_fat_chain_locked(struct exfat_move *move)
{
	struct inode *inode = move->inode;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_dentry *stream;
	struct buffer_head *bh = NULL;
	unsigned int total, i, next, expected;
	int ret;

	ret = exfat_move_check_inode(inode);
	if (ret)
		return ret;
	if (ei->flags == ALLOC_NO_FAT_CHAIN)
		return 0;
	total = exfat_bytes_to_cluster(sbi, exfat_ondisk_size(inode));
	if (!total)
		return 0;
	if (!is_valid_cluster(sbi, ei->start_clu))
		return -EIO;
	if (total > sbi->num_clusters - ei->start_clu)
		return -EAGAIN;

	/* The inode lock keeps the allocation fixed during the FAT scan. */
	mutex_unlock(&sbi->s_lock);
	for (i = 0; i < total; i++) {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		ret = exfat_ent_get(sb, ei->start_clu + i, &next, &bh);
		if (ret)
			break;
		expected = i + 1 < total ? ei->start_clu + i + 1 : EXFAT_EOF_CLUSTER;
		if (next != expected) {
			ret = -EAGAIN;
			break;
		}
		cond_resched();
	}
	brelse(bh);
	mutex_lock(&sbi->s_lock);
	if (ret)
		return ret;
	ret = exfat_move_check_inode(inode);
	if (ret)
		return ret;
	ret = exfat_move_get_entries(move);
	if (ret)
		return ret;
	if (signal_pending(current))
		return -EINTR;
	exfat_set_volume_dirty(sb);
	ret = buffer_write_io_error(sbi->boot_bh) ? -EIO :
		blkdev_issue_flush(sb->s_bdev);
	if (ret) {
		move->metadata_error = true;
		return ret;
	}
	stream = exfat_get_dentry_cached(&move->es, ES_IDX_STREAM);
	stream->dentry.stream.flags = ALLOC_NO_FAT_CHAIN;
	ret = exfat_move_commit_entries(move);
	/* Both representations name the same clusters, including on write error. */
	ei->flags = ALLOC_NO_FAT_CHAIN;
	exfat_cache_inval_inode(inode);
	ei->hint_bmap.off = 0;
	ei->hint_bmap.clu = ei->start_clu;
	return ret;
}

/*
 * Iomap folios cache file contents by offset. Keep them attached and locked
 * so writeback cannot resolve their blocks until the cluster move finishes.
 */
static int exfat_move_lock_folios(struct exfat_move *move, unsigned int vcn)
{
	struct inode *inode = move->inode;
	struct address_space *mapping = inode->i_mapping;
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	loff_t start = exfat_cluster_to_bytes(sbi, vcn);
	loff_t end = min(start + exfat_cluster_to_bytes(sbi, move->count),
			 i_size_read(inode));
	pgoff_t index, last;
	struct folio_batch fbatch;
	unsigned int i, nr;

	if (start >= end)
		return 0;
	index = start >> PAGE_SHIFT;
	last = (end - 1) >> PAGE_SHIFT;
	folio_batch_init(&fbatch);
	while ((nr = filemap_get_folios(mapping, &index, last, &fbatch))) {
		for (i = 0; i < nr; i++) {
			struct folio *folio = fbatch.folios[i];

			if (!folio_trylock(folio))
				break;
			if (folio->mapping != mapping || folio_test_writeback(folio) ||
			    folio_test_dirty(folio) || folio_mapped(folio) ||
			    folio_maybe_dma_pinned(folio)) {
				folio_unlock(folio);
				break;
			}
			folio_get(folio);
			move->folios[move->nr_folios++] = folio;
		}
		folio_batch_release(&fbatch);
		if (i < nr)
			return -EBUSY;
		cond_resched();
	}
	return 0;
}

static long exfat_ioctl_relocate(struct file *file, void __user *arg, bool convert)
{
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	struct exfat_move_file req;
	struct exfat_move move = { .inode = inode };
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;
	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!convert) {
		unsigned int nr_pages;
		loff_t bytes;

		if (copy_from_user(&req, arg, sizeof(req)))
			return -EFAULT;
		if (req.flags || req.reserved || !req.cluster_count ||
		    req.cluster_count > exfat_max_move_clusters(sbi) ||
		    req.target_lcn >= EXFAT_DATA_CLUSTER_COUNT(sbi) ||
		    req.cluster_count > EXFAT_DATA_CLUSTER_COUNT(sbi) - req.target_lcn)
			return -EINVAL;

		move.count = req.cluster_count;
		move.target = req.target_lcn + EXFAT_RESERVED_CLUSTERS;
		bytes = exfat_cluster_to_bytes(sbi, move.count);
		/* A cluster range may start partway through a page. */
		nr_pages = DIV_ROUND_UP_ULL(bytes + PAGE_SIZE - 1, PAGE_SIZE);
		move.folios = kvmalloc_objs(*move.folios, nr_pages, GFP_KERNEL);
		move.source = kvmalloc_objs(*move.source, move.count, GFP_KERNEL);
		move.sorted = kvmalloc_objs(*move.sorted, move.count, GFP_KERNEL);
		move.buffer = kmalloc(EXFAT_COPY_BYTES, GFP_KERNEL);
		if (!move.folios || !move.source || !move.sorted || !move.buffer) {
			ret = -ENOMEM;
			goto free;
		}
	}
	ret = mnt_want_write_file(file);
	if (ret)
		goto free;
	inode_lock(inode);
	inode_dio_wait(inode);
	filemap_invalidate_lock(mapping);
	if (!convert) {
		move.total = exfat_bytes_to_cluster(sbi, exfat_ondisk_size(inode));
		if (req.start_vcn >= move.total ||
		    req.cluster_count > move.total - req.start_vcn) {
			ret = -EINVAL;
			goto unlock;
		}
		/* Revoke writable PTEs before flushing and locking the folios. */
		unmap_mapping_range(mapping, 0, 0, 0);
	}
	ret = filemap_write_and_wait(mapping);
	if (ret)
		goto unlock;
	ret = write_inode_now(inode, 1);
	if (ret)
		goto unlock;
	ret = sync_blockdev(inode->i_sb->s_bdev);
	if (ret)
		goto unlock;
	ret = blkdev_issue_flush(inode->i_sb->s_bdev);
	if (ret)
		goto unlock;
	if (!convert) {
		ret = exfat_move_lock_folios(&move, req.start_vcn);
		if (ret)
			goto unlock;
	}

	mutex_lock(&sbi->s_lock);
	ret = convert ? exfat_set_no_fat_chain_locked(&move) :
		exfat_move_locked(&move, &req);
	if (move.metadata_error) {
		sbi->vol_flags_persistent |= VOLUME_DIRTY;
		exfat_force_shutdown(inode->i_sb, EXFAT_GOING_DOWN_NOSYNC);
		exfat_fs_error(inode->i_sb,
			       "relocation metadata write failed; run fsck before reuse");
	}
	if (move.have_entries)
		exfat_put_dentry_set(&move.es, false);
	mutex_unlock(&sbi->s_lock);
unlock:
	while (move.nr_folios) {
		struct folio *folio = move.folios[--move.nr_folios];

		folio_unlock(folio);
		folio_put(folio);
	}
	filemap_invalidate_unlock(mapping);
	inode_unlock(inode);
	mnt_drop_write_file(file);
free:
	kfree(move.buffer);
	kvfree(move.folios);
	kvfree(move.sorted);
	kvfree(move.source);
	return ret;
}

long exfat_ioctl_move_file(struct file *file, void __user *arg)
{
	return exfat_ioctl_relocate(file, arg, false);
}

long exfat_ioctl_set_no_fat_chain(struct file *file)
{
	return exfat_ioctl_relocate(file, NULL, true);
}
