// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Read LFS client records from the circular NTFS journal.
 */

#include <linux/log2.h>
#include <linux/slab.h>

#include "logfile_internal.h"
#include "ntfs.h"

static bool ntfs_log_read_layout_valid(const struct ntfs_logfile_layout *layout)
{
	if (!layout || !is_power_of_2(layout->page_size) ||
	    layout->page_size < NTFS_BLOCK_SIZE ||
	    layout->page_mask != layout->page_size - 1 ||
	    layout->seq_num_bits <= 3 || layout->seq_num_bits >= 64 ||
	    layout->seq_num_bits != 67 - fls64(layout->log_size) ||
	    layout->file_data_bits != 64 - layout->seq_num_bits ||
	    !IS_ALIGNED(layout->first_page, layout->page_size) ||
	    layout->first_page >= layout->log_size ||
	    layout->page_size > layout->log_size - layout->first_page ||
	    layout->data_off < sizeof(struct ntfs_record_page_hdr) ||
	    !IS_ALIGNED(layout->data_off, 8) ||
	    layout->data_off >= layout->page_size ||
	    layout->record_header_len < sizeof(struct ntfs_lfs_record_hdr) ||
	    !IS_ALIGNED(layout->record_header_len, 8) ||
	    layout->record_header_len > layout->page_size - layout->data_off)
		return false;
	return true;
}

static int ntfs_log_read_page(struct inode *log_vi,
		const struct ntfs_logfile_layout *layout, u64 page_off, void *page)
{
	struct ntfs_record_page_hdr *hdr = page;
	u32 usa_off, usa_count, usa_end;
	s64 got;

	if (page_off < layout->first_page || page_off >= layout->log_size ||
	    page_off > S64_MAX)
		return -EINVAL;
	got = ntfs_inode_mapping_pread(log_vi, page_off, layout->page_size, page);
	if (got != layout->page_size)
		return got < 0 ? (int)got : -EIO;
	if (!ntfs_is_rcrd_recordp((__le32 *)page))
		return -EINVAL;
	usa_off = le16_to_cpu(hdr->rhdr.usa_ofs);
	usa_count = le16_to_cpu(hdr->rhdr.usa_count);
	usa_end = usa_off + usa_count * sizeof(__le16);
	if (usa_off < sizeof(*hdr) || !IS_ALIGNED(usa_off, sizeof(__le16)) ||
	    usa_count != 1 + layout->page_size / NTFS_BLOCK_SIZE ||
	    usa_end > layout->data_off ||
	    usa_end > NTFS_BLOCK_SIZE - sizeof(__le16) ||
	    post_read_mst_fixup((struct ntfs_record *)page, layout->page_size))
		return -EINVAL;
	return 0;
}

static int ntfs_log_record_position(const struct ntfs_logfile_layout *layout,
		u64 lsn, u64 *byte_off, u64 *page_off, u32 *off)
{
	int err;

	err = ntfs_lsn_to_byte_off(layout, lsn, byte_off);
	if (err)
		return err;
	*page_off = *byte_off & ~((u64)layout->page_mask);
	*off = *byte_off & layout->page_mask;
	if (*page_off < layout->first_page || *page_off >= layout->log_size ||
	    *off < layout->data_off ||
	    layout->record_header_len > layout->page_size - *off)
		return -EINVAL;
	return 0;
}

static int ntfs_log_read_payload(struct inode *log_vi,
		const struct ntfs_logfile_layout *layout, u64 lsn,
		const struct ntfs_lfs_record_hdr *hdr, u64 page_off, u32 off,
		void *payload)
{
	struct ntfs_record_page_hdr *page;
	u8 *dst = payload;
	u32 remaining = le32_to_cpu(hdr->client_data_len);
	int err;

	page = kmalloc(layout->page_size, GFP_NOFS);
	if (!page)
		return -ENOMEM;
	off += layout->record_header_len;
	for (;;) {
		u32 len = min(remaining, layout->page_size - off);

		err = ntfs_log_read_page(log_vi, layout, page_off, page);
		if (err)
			break;
		if (lsn > le64_to_cpu(page->rhdr.lsn)) {
			err = -EINVAL;
			break;
		}
		memcpy(dst, (u8 *)page + off, len);
		dst += len;
		remaining -= len;
		if (!remaining) {
			if (!(page->rflags & LOG_PAGE_LOG_RECORD_END) ||
			    lsn > le64_to_cpu(page->record_hdr.last_end_lsn))
				err = -EINVAL;
			break;
		}
		if (!(hdr->flags & LOG_RECORD_MULTI_PAGE) ||
		    page->rhdr.lsn == page->record_hdr.last_end_lsn) {
			err = -EINVAL;
			break;
		}
		page_off = ntfs_next_page_off(layout, page_off);
		off = layout->data_off;
	}
	kfree(page);
	return err;
}

int ntfs_log_read_client_record(struct inode *log_vi,
		const struct ntfs_logfile_layout *layout, u64 lsn,
		struct ntfs_lfs_record_hdr *hdr, void **payload, u32 *payload_len)
{
	struct ntfs_record_page_hdr *page;
	u64 byte_off, page_off, record_bytes;
	void *data;
	u32 off, len;
	int err;

	if (!log_vi || !hdr || !payload || !payload_len ||
	    !ntfs_log_read_layout_valid(layout))
		return -EINVAL;
	*payload = NULL;
	*payload_len = 0;
	if (!lsn || lsn < layout->oldest_lsn || lsn > layout->current_lsn)
		return -EINVAL;
	err = ntfs_log_record_position(layout, lsn, &byte_off, &page_off, &off);
	if (err)
		return err;
	page = kmalloc(layout->page_size, GFP_NOFS);
	if (!page)
		return -ENOMEM;
	err = ntfs_log_read_page(log_vi, layout, page_off, page);
	if (err)
		goto out_page;
	memcpy(hdr, (u8 *)page + off, sizeof(*hdr));
	if (le64_to_cpu(hdr->this_lsn) != lsn ||
	    le16_to_cpu(hdr->client_seq) != layout->client_seq ||
	    le16_to_cpu(hdr->client_idx) != layout->client_idx) {
		err = -EINVAL;
		goto out_page;
	}
	len = le32_to_cpu(hdr->client_data_len);
	record_bytes = (u64)layout->record_header_len + len;
	if (!len || record_bytes >= ntfs_log_total_avail(layout) ||
	    (!(hdr->flags & LOG_RECORD_MULTI_PAGE) &&
	     record_bytes > layout->page_size - off)) {
		err = -EINVAL;
		goto out_page;
	}
	data = kmalloc(len, GFP_NOFS);
	if (!data) {
		err = -ENOMEM;
		goto out_page;
	}
	err = ntfs_log_read_payload(log_vi, layout, lsn, hdr, page_off, off, data);
	if (err)
		kfree(data);
	else {
		*payload = data;
		*payload_len = len;
	}
out_page:
	kfree(page);
	return err;
}

static void ntfs_log_record_end(const struct ntfs_logfile_layout *layout,
		u64 page_off, u32 off, u32 data_len, u64 *end_page, u64 *end_off)
{
	u64 remaining = (u64)layout->record_header_len + data_len;
	u32 capacity = layout->page_size - off;

	if (remaining > capacity) {
		remaining -= capacity;
		capacity = layout->page_size - layout->data_off;
		do {
			page_off = ntfs_next_page_off(layout, page_off);
			off = layout->data_off;
			if (remaining <= capacity)
				break;
			remaining -= capacity;
		} while (true);
	}
	*end_page = page_off;
	*end_off = page_off + off + remaining;
}

int ntfs_log_next_lsn(struct inode *log_vi,
		const struct ntfs_logfile_layout *layout, u64 lsn,
		const struct ntfs_lfs_record_hdr *hdr, u64 *next_lsn)
{
	struct ntfs_record_page_hdr *page;
	u64 byte_off, page_off, end_page, end_off, next_off, seq;
	u32 off, len;
	int err;

	if (!log_vi || !hdr || !next_lsn ||
	    !ntfs_log_read_layout_valid(layout))
		return -EINVAL;
	*next_lsn = 0;
	if (!lsn || lsn < layout->oldest_lsn || lsn > layout->current_lsn ||
	    le64_to_cpu(hdr->this_lsn) != lsn)
		return -EINVAL;
	err = ntfs_log_record_position(layout, lsn, &byte_off, &page_off, &off);
	if (err)
		return err;
	len = le32_to_cpu(hdr->client_data_len);
	if (!len || (u64)layout->record_header_len + len >=
	    ntfs_log_total_avail(layout))
		return -EINVAL;
	ntfs_log_record_end(layout, page_off, off, len, &end_page, &end_off);
	page = kmalloc(layout->page_size, GFP_NOFS);
	if (!page)
		return -ENOMEM;
	err = ntfs_log_read_page(log_vi, layout, end_page, page);
	if (err)
		goto out;
	seq = lsn >> layout->file_data_bits;
	if (end_off <= byte_off)
		seq++;
	if (lsn == le64_to_cpu(page->rhdr.lsn)) {
		next_off = ntfs_next_page_off(layout, end_page);
		if (next_off == layout->first_page)
			seq++;
		next_off += layout->data_off;
	} else {
		next_off = ALIGN(end_off, 8);
	}
	if (seq > (U64_MAX >> layout->file_data_bits)) {
		err = -EINVAL;
		goto out;
	}
	*next_lsn = ntfs_byte_off_to_lsn(layout, next_off, seq);
	if (*next_lsn > layout->current_lsn)
		*next_lsn = 0;
	else if (*next_lsn <= lsn || *next_lsn < layout->oldest_lsn) {
		*next_lsn = 0;
		err = -EINVAL;
	}
out:
	kfree(page);
	return err;
}

int ntfs_log_checkpoint_dump_data(const struct ntfs_lfs_record_hdr *hdr,
		const void *payload, u32 payload_len, u16 expected_op,
		u32 expected_len, const void **data, u32 *data_len)
{
	const struct ntfs_log_rec_hdr *lrh = payload;
	u32 redo_off, actual_len;

	if (!hdr || !payload || !data || !data_len ||
	    hdr->record_type != LFS_CLIENT_RECORD ||
	    payload_len < sizeof(*lrh) ||
	    !ntfs_log_validate_record(lrh, payload_len,
		    le32_to_cpu(hdr->transact_id), hdr->flags))
		return -EINVAL;

	redo_off = le16_to_cpu(lrh->redo_off);
	actual_len = payload_len - redo_off;
	/* Older carriers may omit the final quadword padding. */
	if (le16_to_cpu(lrh->redo_op) != expected_op ||
	    le16_to_cpu(lrh->undo_op) != Noop ||
	    le16_to_cpu(lrh->undo_len) ||
	    le16_to_cpu(lrh->undo_off) != redo_off ||
	    le16_to_cpu(lrh->lcns_follow) ||
	    actual_len < expected_len ||
	    (actual_len != expected_len &&
	     (!IS_ALIGNED(payload_len, 8) || actual_len - expected_len >= 8)) ||
	    le16_to_cpu(lrh->redo_len) != min_t(u32, expected_len, U16_MAX))
		return -EINVAL;

	*data = (const u8 *)payload + redo_off;
	*data_len = expected_len;
	return 0;
}
