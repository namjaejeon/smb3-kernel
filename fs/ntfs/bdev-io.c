// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS block device I/O.
 *
 * Copyright (c) 2026 LG Electronics Co., Ltd.
 */

#include <linux/blkdev.h>

#include "ntfs.h"

/*
 * ntfs_bdev_read - Read data directly from block device using bio
 * @bdev:	block device to read from
 * @data:	destination buffer
 * @start:	starting byte offset on the block device
 * @size:	number of bytes to read
 *
 * Reads @size bytes starting from byte offset @start directly from the block
 * device using one or more BIOs. This function bypasses the page cache
 * completely and performs synchronous I/O with REQ_META | REQ_SYNC flags set.
 *
 * The @start offset must be sector-aligned (512 bytes). If it is not aligned,
 * the function will return -EINVAL.
 *
 * If the destination buffer @data is not a vmalloc address, it falls back
 * to the more efficient bdev_rw_virt() helper.
 *
 * Return: 0 on success, negative error code on failure.
 */
int ntfs_bdev_read(struct block_device *bdev, char *data, loff_t start, size_t size)
{
	unsigned int done = 0, added;
	int error;
	struct bio *bio;
	blk_opf_t op;
	sector_t sector = ntfs_bytes_to_bio_sector(start);

	if (start & (SECTOR_SIZE - 1))
		return -EINVAL;

	op = REQ_OP_READ | REQ_META | REQ_SYNC;
	if (!is_vmalloc_addr(data))
		return bdev_rw_virt(bdev, sector, data, size, op);

	bio = bio_alloc(bdev,
			bio_max_segs(DIV_ROUND_UP(size, PAGE_SIZE)),
			op, GFP_KERNEL);
	bio->bi_iter.bi_sector = sector;

	do {
		added = bio_add_vmalloc_chunk(bio, data + done, size - done);
		if (!added) {
			struct bio	*prev = bio;

			bio = bio_alloc(prev->bi_bdev,
					bio_max_segs(DIV_ROUND_UP(size - done, PAGE_SIZE)),
					prev->bi_opf, GFP_KERNEL);
			bio->bi_iter.bi_sector = bio_end_sector(prev);
			bio_chain(prev, bio);
			submit_bio(prev);
		}
		done += added;
	} while (done < size);

	error = submit_bio_wait(bio);
	bio_put(bio);

	if ((op & REQ_OP_MASK) == REQ_OP_READ)
		invalidate_kernel_vmap_range(data, size);
	return error;
}

static int ntfs_bdev_check_range(loff_t start, size_t size, loff_t *end)
{
	if (start < 0 || size > S64_MAX - start)
		return -EINVAL;
	*end = start + size;
	if (size && (u64)(*end - 1) >> PAGE_SHIFT > ULONG_MAX)
		return -EFBIG;
	return 0;
}

/*
 * Read through the block-device page cache so that replay observes earlier
 * writes that have not yet reached the device.
 */
int ntfs_bdev_read_cached(struct super_block *sb, void *buf, loff_t start,
		size_t size)
{
	struct address_space *mapping = sb->s_bdev->bd_mapping;
	u8 *dst = buf;
	pgoff_t idx, last;
	loff_t offset, end;
	size_t buf_off = 0;
	u32 from, to;
	struct folio *folio;
	int err;

	err = ntfs_bdev_check_range(start, size, &end);
	if (err || !size)
		return err;
	idx = start >> PAGE_SHIFT;
	last = (end - 1) >> PAGE_SHIFT;
	from = start & ~PAGE_MASK;

	for (;; idx++, from = 0) {
		u32 len;

		offset = (loff_t)idx << PAGE_SHIFT;
		to = min_t(loff_t, end - offset, PAGE_SIZE);
		len = to - from;
retry:
		folio = read_mapping_folio(mapping, idx, NULL);
		if (IS_ERR(folio)) {
			ntfs_error(sb, "Unable to read %lu page", idx);
			return PTR_ERR(folio);
		}
		folio_lock(folio);
		if (unlikely(folio->mapping != mapping ||
			     !folio_test_uptodate(folio))) {
			folio_unlock(folio);
			folio_put(folio);
			goto retry;
		}
		memcpy_from_folio(dst + buf_off, folio,
				offset - folio_pos(folio) + from, len);
		buf_off += len;
		folio_unlock(folio);
		folio_put(folio);
		if (idx == last)
			break;
	}
	return 0;
}

/*
 * ntfs_bdev_write - Update block device contents via page cache
 * @sb:		super block of the mounted NTFS filesystem
 * @buf:	source buffer containing data to write
 * @start:	starting byte offset on the block device
 * @size:	number of bytes to write
 *
 * Writes @size bytes from @buf to the block device (sb->s_bdev) starting
 * at byte offset @start. The write is performed entirely through the page
 * cache of the block device's address space. Full-page overwrites do not
 * need to read the old contents. Partial writes keep the remaining bytes.
 */
int ntfs_bdev_write(struct super_block *sb, void *buf, loff_t start, size_t size)
{
	struct address_space *mapping = sb->s_bdev->bd_mapping;
	const u8 *src = buf;
	pgoff_t idx, last;
	loff_t offset, end;
	size_t buf_off = 0;
	u32 from, to;
	struct folio *folio;
	int err;

	err = ntfs_bdev_check_range(start, size, &end);
	if (err || !size)
		return err;
	idx = start >> PAGE_SHIFT;
	last = (end - 1) >> PAGE_SHIFT;
	from = start & ~PAGE_MASK;

	for (;; idx++, from = 0) {
		u32 len;

		offset = (loff_t)idx << PAGE_SHIFT;
		to = min_t(loff_t, end - offset, PAGE_SIZE);
		len = to - from;

retry:
		if (len == PAGE_SIZE) {
			folio = filemap_grab_folio(mapping, idx);
			if (IS_ERR(folio))
				goto error;
			/* Never mark unwritten parts of a large folio uptodate. */
			if (folio_size(folio) == PAGE_SIZE ||
			    folio_test_uptodate(folio))
				goto copy;
			folio_unlock(folio);
			folio_put(folio);
		}
		folio = ntfs_read_metadata_folio(mapping, idx);
		if (IS_ERR(folio))
			goto error;
		folio_lock(folio);
		if (unlikely(folio->mapping != mapping ||
			     !folio_test_uptodate(folio))) {
			folio_unlock(folio);
			folio_put(folio);
			goto retry;
		}
copy:
		folio_wait_writeback(folio);
		memcpy_to_folio(folio, offset - folio_pos(folio) + from,
				src + buf_off, len);
		buf_off += len;
		folio_mark_uptodate(folio);
		folio_mark_dirty(folio);
		folio_unlock(folio);
		folio_put(folio);
		if (idx == last)
			break;
	}

	return 0;
error:
	ntfs_error(sb, "Unable to get %lu page", idx);
	return PTR_ERR(folio);
}
