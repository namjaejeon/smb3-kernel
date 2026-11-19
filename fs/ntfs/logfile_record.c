// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS $LogFile recording codec.
 *
 * This file builds canonical version 1.1 restart pages, checkpoint tables,
 * and RCRD images.  It also owns the journal writer
 * lifecycle and the semantic record helpers used by metadata mutation paths.
 */

#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/iomap.h>
#include <linux/log2.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/sched/cputime.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/wait_bit.h>
#include <linux/writeback.h>

#include "attrib.h"
#include "logfile_internal.h"
#include "ntfs.h"

#define ntfs_log_kvmemdup kvmemdup


/* Version 1.1 reserves four pages before the circular RCRD area. */
#define NTFS_LOG_V1_FIRST_PAGE	4
#define NTFS_LOG_V1_MINOR	1
#define NTFS_LOG_V1_MAJOR	1
#define NTFS_LOG_CLIENT_ARRAY_OFF 0x40
/* Ordinary transactions may never consume the final marker/checkpoint pages. */
#define NTFS_LOG_EMERGENCY_PAGES	2
/*
 * Structural estimates can cover every possible tree split.  Ordinary handles
 * start small. Foreground growth uses shared slack, not a ceiling per handle.
 */
#define NTFS_LOG_INITIAL_TRANSACTION_CREDITS	32
/* Bound the memory retained while committed frees wait for a batch marker. */
#define NTFS_LOG_DEFERRED_MAX_ENTRIES	1024
#define NTFS_LOG_DEFERRED_MAX_BYTES	SZ_4M
#define NTFS_LOG_DEFERRED_FLUSH_MS	100

/* Buffered operations finish without imposing an fsync on every syscall. */
static bool journal_async_commit = true;
module_param(journal_async_commit, bool, 0444);
MODULE_PARM_DESC(journal_async_commit,
	"Batch buffered journal commits (default Y; N forces synchronous commits)");

/* Match JBD2's default maximum running-transaction age. */
static unsigned int journal_commit_interval = 5;
module_param(journal_commit_interval, uint, 0444);
MODULE_PARM_DESC(journal_commit_interval,
	"Maximum buffered journal commit age in seconds (default 5)");

static u64 ntfs_log_task_cpu_time(void)
{
	u64 system;
	u64 user;

	if (!ntfs_log_recording_stats_enabled())
		return 0;
	task_cputime_adjusted(current, &user, &system);
	return user + system;
}

int ntfs_log_init_v1_layout(u64 log_size, u32 page_size,
		struct ntfs_logfile_layout *layout)
{
	u32 usa_count;
	u32 data_off;
	u32 file_bits;

	if (!layout || !is_power_of_2(page_size) ||
	    page_size < NTFS_BLOCK_SIZE || page_size > U16_MAX ||
	    !IS_ALIGNED(log_size, page_size) || log_size > MaxLogFileSize)
		return -EINVAL;

	if (log_size < (u64)(NTFS_LOG_V1_FIRST_PAGE + MinLogRecordPages) *
			page_size)
		return -EINVAL;

	usa_count = 1 + page_size / NTFS_BLOCK_SIZE;
	data_off = ALIGN(sizeof(struct ntfs_record_page_hdr) +
			usa_count * sizeof(__le16), 8);
	if (data_off >= page_size || data_off > U16_MAX)
		return -EINVAL;

	file_bits = fls64(log_size);
	if (!file_bits || file_bits >= 64 || file_bits >= 67)
		return -EINVAL;

	memset(layout, 0, sizeof(*layout));
	layout->system_page_size = page_size;
	layout->page_size = page_size;
	layout->page_mask = page_size - 1;
	layout->log_size = log_size;
	layout->first_page = (u64)NTFS_LOG_V1_FIRST_PAGE * page_size;
	layout->seq_num_bits = 67 - file_bits;
	if (layout->seq_num_bits <= 3 || layout->seq_num_bits >= 64)
		return -EINVAL;
	layout->file_data_bits = 64 - layout->seq_num_bits;
	layout->record_header_len = sizeof(struct ntfs_lfs_record_hdr);
	layout->data_off = data_off;
	layout->client_idx = 0;
	layout->client_seq = 0;
	return 0;
}

static int ntfs_log_prepare_record_buffer(
		const struct ntfs_logfile_layout *layout,
		const struct ntfs_log_record_desc *desc, u16 nr_pages,
		void **record_out, u32 *record_bytes_out)
{
	struct ntfs_lfs_record_hdr *hdr;
	void *record;
	u32 record_bytes;
	u16 flags = desc->flags;

	if (check_add_overflow((u32)layout->record_header_len,
			desc->payload_len, &record_bytes))
		return -EOVERFLOW;

	record = kvzalloc(record_bytes, GFP_NOFS);
	if (!record)
		return -ENOMEM;

	hdr = record;
	hdr->this_lsn = cpu_to_le64(desc->this_lsn);
	hdr->client_prev_lsn = cpu_to_le64(desc->client_prev_lsn);
	hdr->client_undo_next_lsn = cpu_to_le64(desc->client_undo_next_lsn);
	hdr->client_data_len = cpu_to_le32(desc->payload_len);
	hdr->client_seq = cpu_to_le16(desc->client_seq);
	hdr->client_idx = cpu_to_le16(desc->client_idx);
	hdr->record_type = cpu_to_le32(desc->record_type);
	hdr->transact_id = cpu_to_le32(desc->transact_id);
	if (nr_pages > 1)
		flags |= le16_to_cpu(LOG_RECORD_MULTI_PAGE);
	hdr->flags = cpu_to_le16(flags);

	if (desc->payload_len)
		memcpy((u8 *)record + layout->record_header_len,
			desc->payload, desc->payload_len);

	*record_out = record;
	*record_bytes_out = record_bytes;
	return 0;
}

int ntfs_log_build_record_pages(const struct ntfs_logfile_layout *layout,
		const struct ntfs_log_record_desc *desc,
		struct ntfs_log_record_pages *pages)
{
	struct ntfs_record_page_hdr *page;
	void *record = NULL;
	void *data;
	u64 byte_off;
	size_t allocation_size;
	u32 record_bytes;
	u32 record_off = 0;
	u32 page_capacity;
	u32 usa_count;
	u32 nr_pages32;
	u16 nr_pages;
	u16 i;
	int err;

	if (!layout || !desc || !pages || !desc->this_lsn ||
	    !desc->payload_len ||
	    (desc->payload_len && !desc->payload) ||
	    layout->record_header_len < sizeof(struct ntfs_lfs_record_hdr) ||
	    layout->data_off < sizeof(struct ntfs_record_page_hdr) ||
	    layout->data_off >= layout->page_size ||
	    !IS_ALIGNED(layout->data_off, 8))
		return -EINVAL;

	err = ntfs_lsn_to_byte_off(layout, desc->this_lsn, &byte_off);
	if (err)
		return err;
	if ((byte_off & layout->page_mask) != layout->data_off ||
	    byte_off < layout->first_page)
		return -EINVAL;

	page_capacity = layout->page_size - layout->data_off;
	if (desc->payload_len > U32_MAX - layout->record_header_len)
		return -EOVERFLOW;
	record_bytes = layout->record_header_len + desc->payload_len;
	nr_pages32 = DIV_ROUND_UP(record_bytes, page_capacity);
	if (!nr_pages32 || nr_pages32 > U16_MAX)
		return -E2BIG;
	nr_pages = nr_pages32;

	usa_count = 1 + layout->page_size / NTFS_BLOCK_SIZE;
	if (sizeof(struct ntfs_record_page_hdr) +
			usa_count * sizeof(__le16) > layout->data_off)
		return -EINVAL;

	if (check_mul_overflow((size_t)nr_pages, (size_t)layout->page_size,
			&allocation_size))
		return -EOVERFLOW;
	data = kvzalloc(allocation_size, GFP_NOFS);
	if (!data)
		return -ENOMEM;

	err = ntfs_log_prepare_record_buffer(layout, desc, nr_pages,
			&record, &record_bytes);
	if (err)
		goto out_data;

	for (i = 0; i < nr_pages; i++) {
		u32 copied = min(record_bytes - record_off, page_capacity);
		u32 next_record_off = ALIGN(layout->data_off + copied, 8);
		bool last = i == nr_pages - 1;
		__le16 *usa;

		page = (struct ntfs_record_page_hdr *)
			((u8 *)data + (size_t)i * layout->page_size);
		page->rhdr.magic = magic_RCRD;
		page->rhdr.usa_ofs = cpu_to_le16(sizeof(*page));
		page->rhdr.usa_count = cpu_to_le16(usa_count);
		page->rhdr.lsn = cpu_to_le64(desc->this_lsn);
		page->rflags = last ? LOG_PAGE_LOG_RECORD_END : 0;
		page->page_count = cpu_to_le16(nr_pages);
		page->page_pos = cpu_to_le16(i + 1);
		page->record_hdr.next_record_off = cpu_to_le16(next_record_off);
		page->record_hdr.last_end_lsn = last ?
			cpu_to_le64(desc->this_lsn) : 0;

		usa = (__le16 *)((u8 *)page + sizeof(*page));
		*usa = cpu_to_le16(1);
		memcpy((u8 *)page + layout->data_off,
			(u8 *)record + record_off, copied);
		record_off += copied;

		err = pre_write_mst_fixup((struct ntfs_record *)page,
				layout->page_size);
		if (err)
			goto out_record;
	}

	kvfree(record);
	pages->data = data;
	pages->nr_pages = nr_pages;
	pages->page_size = layout->page_size;
	return 0;

out_record:
	kvfree(record);
out_data:
	kvfree(data);
	return err;
}

void ntfs_log_free_record_pages(struct ntfs_log_record_pages *pages)
{
	if (!pages)
		return;

	kvfree(pages->data);
	memset(pages, 0, sizeof(*pages));
}

int ntfs_log_build_operation_payload(
		const struct ntfs_log_operation_desc *desc,
		struct ntfs_log_payload *payload)
{
	struct ntfs_log_rec_hdr *lrh;
	void *data;
	u32 header_len;
	u32 undo_off;
	u32 redo_off;
	u32 payload_len;
	u16 inline_undo_len;
	u16 i;

	if (!desc || !payload || desc->redo_op > ZeroEndOfFileRecord ||
	    desc->undo_op > ZeroEndOfFileRecord ||
	    desc->target_vcn > S64_MAX ||
	    (desc->lcns_follow && desc->target_vcn >
		    S64_MAX - desc->lcns_follow + 1) ||
	    (desc->lcns_follow && !desc->page_lcns) ||
	    (desc->undo_op != CompensationLogRecord &&
	     desc->undo_len && !desc->undo_data) ||
	    (desc->redo_len && !desc->redo_data))
		return -EINVAL;
	for (i = 0; i < desc->lcns_follow; i++) {
		if (desc->page_lcns[i] > S64_MAX)
			return -EINVAL;
	}

	header_len = struct_size(lrh, page_lcns,
			max_t(u16, 1, desc->lcns_follow));
	inline_undo_len = desc->undo_op == CompensationLogRecord ?
			0 : desc->undo_len;
	undo_off = ALIGN(header_len, 8);
	if (check_add_overflow(undo_off, (u32)inline_undo_len, &redo_off))
		return -EOVERFLOW;
	redo_off = ALIGN(redo_off, 8);
	if (check_add_overflow(redo_off, (u32)desc->redo_len, &payload_len) ||
	    undo_off > U16_MAX || redo_off > U16_MAX)
		return -EOVERFLOW;

	/* Include quadword padding so native replay can traverse packed records. */
	payload_len = ALIGN(payload_len, 8);
	data = kvzalloc(payload_len, GFP_NOFS);
	if (!data)
		return -ENOMEM;

	lrh = data;
	lrh->redo_op = cpu_to_le16(desc->redo_op);
	lrh->undo_op = cpu_to_le16(desc->undo_op);
	lrh->redo_off = cpu_to_le16(redo_off);
	lrh->redo_len = cpu_to_le16(desc->redo_len);
	lrh->undo_off = cpu_to_le16(undo_off);
	lrh->undo_len = cpu_to_le16(desc->undo_len);
	lrh->target_attr = cpu_to_le16(desc->target_attr);
	lrh->lcns_follow = cpu_to_le16(desc->lcns_follow);
	lrh->record_off = cpu_to_le16(desc->record_off);
	lrh->attr_off = cpu_to_le16(desc->attr_off);
	lrh->cluster_off = cpu_to_le16(desc->cluster_off);
	lrh->target_vcn = cpu_to_le64(desc->target_vcn);
	for (i = 0; i < desc->lcns_follow; i++)
		lrh->page_lcns[i] = cpu_to_le64(desc->page_lcns[i]);

	if (inline_undo_len)
		memcpy((u8 *)data + undo_off, desc->undo_data,
			inline_undo_len);
	if (desc->redo_len)
		memcpy((u8 *)data + redo_off, desc->redo_data,
			desc->redo_len);

	payload->data = data;
	payload->len = payload_len;
	return 0;
}

void ntfs_log_free_payload(struct ntfs_log_payload *payload)
{
	if (!payload)
		return;

	kvfree(payload->data);
	memset(payload, 0, sizeof(*payload));
}

void ntfs_log_build_empty_checkpoint(struct ntfs_log_checkpoint *checkpoint)
{
	if (!checkpoint)
		return;

	memset(checkpoint, 0, sizeof(*checkpoint));
	checkpoint->major_ver = cpu_to_le32(1);
	checkpoint->minor_ver = cpu_to_le32(1);
}

int ntfs_log_build_restart_page_v1(const struct ntfs_logfile_layout *layout,
		u64 current_lsn, u64 client_restart_lsn, u64 oldest_lsn,
		u32 restart_log_open_count, bool clean, void **page_out)
{
	struct restart_page_header *rp;
	struct log_client_record *client;
	struct restart_area *ra;
	void *page;
	u32 usa_count;
	u32 restart_area_off;
	u32 restart_area_len;
	__le16 *usa;
	int err;

	if (!layout || !page_out ||
	    layout->system_page_size < NTFS_BLOCK_SIZE ||
	    !IS_ALIGNED(layout->system_page_size, NTFS_BLOCK_SIZE) ||
	    layout->system_page_size > U16_MAX ||
	    layout->page_size < NTFS_BLOCK_SIZE ||
	    2ULL * layout->system_page_size > layout->first_page ||
	    layout->record_header_len != sizeof(struct ntfs_lfs_record_hdr) ||
	    layout->first_page !=
			(u64)NTFS_LOG_V1_FIRST_PAGE * layout->page_size)
		return -EINVAL;

	usa_count = 1 + layout->system_page_size / NTFS_BLOCK_SIZE;
	restart_area_off = ALIGN(sizeof(*rp) + usa_count * sizeof(__le16), 8);
	restart_area_len = NTFS_LOG_CLIENT_ARRAY_OFF + sizeof(*client);
	if (restart_area_off + restart_area_len > layout->system_page_size ||
	    restart_area_off > U16_MAX || restart_area_len > U16_MAX)
		return -EINVAL;

	page = kvzalloc(layout->system_page_size, GFP_NOFS);
	if (!page)
		return -ENOMEM;

	rp = page;
	rp->magic = magic_RSTR;
	rp->usa_ofs = cpu_to_le16(sizeof(*rp));
	rp->usa_count = cpu_to_le16(usa_count);
	rp->system_page_size = cpu_to_le32(layout->system_page_size);
	rp->log_page_size = cpu_to_le32(layout->page_size);
	rp->restart_area_offset = cpu_to_le16(restart_area_off);
	rp->minor_ver = cpu_to_le16(NTFS_LOG_V1_MINOR);
	rp->major_ver = cpu_to_le16(NTFS_LOG_V1_MAJOR);

	usa = (__le16 *)((u8 *)page + sizeof(*rp));
	*usa = cpu_to_le16(1);

	ra = (struct restart_area *)((u8 *)page + restart_area_off);
	ra->current_lsn = cpu_to_le64(current_lsn);
	ra->log_clients = cpu_to_le16(1);
	ra->client_free_list = LOGFILE_NO_CLIENT;
	ra->client_in_use_list = cpu_to_le16(0);
	ra->flags = clean ? RESTART_VOLUME_IS_CLEAN : 0;
	ra->seq_number_bits = cpu_to_le32(layout->seq_num_bits);
	ra->restart_area_length = cpu_to_le16(restart_area_len);
	ra->client_array_offset = cpu_to_le16(NTFS_LOG_CLIENT_ARRAY_OFF);
	ra->file_size = cpu_to_le64(layout->log_size);
	ra->last_lsn_data_length = cpu_to_le32(sizeof(struct ntfs_log_checkpoint));
	ra->log_record_header_length = cpu_to_le16(layout->record_header_len);
	ra->log_page_data_offset = cpu_to_le16(layout->data_off);
	ra->restart_log_open_count = cpu_to_le32(restart_log_open_count);

	client = (struct log_client_record *)((u8 *)ra +
			NTFS_LOG_CLIENT_ARRAY_OFF);
	client->oldest_lsn = cpu_to_le64(oldest_lsn);
	client->client_restart_lsn = cpu_to_le64(client_restart_lsn);
	client->prev_client = LOGFILE_NO_CLIENT;
	client->next_client = LOGFILE_NO_CLIENT;
	client->seq_number = cpu_to_le16(layout->client_seq);
	client->client_name_length = cpu_to_le32(8);
	client->client_name[0] = cpu_to_le16('N');
	client->client_name[1] = cpu_to_le16('T');
	client->client_name[2] = cpu_to_le16('F');
	client->client_name[3] = cpu_to_le16('S');

	err = pre_write_mst_fixup((struct ntfs_record *)page,
			layout->system_page_size);
	if (err) {
		kvfree(page);
		return err;
	}

	*page_out = page;
	return 0;
}

static bool ntfs_log_restart_slot_valid(u32 off, u16 size, u16 used)
{
	if (!off)
		return true;
	if (off < sizeof(struct ntfs_log_restart_table))
		return false;
	off -= sizeof(struct ntfs_log_restart_table);
	return !(off % size) && off / size < used;
}

bool ntfs_log_validate_restart_table(const struct ntfs_log_restart_table *table,
		size_t bytes)
{
	size_t span;
	u16 size;
	u16 used;
	u16 i;

	if (!table || bytes < sizeof(*table))
		return false;
	size = le16_to_cpu(table->size);
	used = le16_to_cpu(table->used);
	span = sizeof(*table) + (size_t)size * used;
	if (size < sizeof(__le32) || span > bytes ||
	    le16_to_cpu(table->total) > used ||
	    !ntfs_log_restart_slot_valid(le32_to_cpu(table->first_free),
			size, used) ||
	    !ntfs_log_restart_slot_valid(le32_to_cpu(table->last_free),
			size, used))
		return false;
	for (i = 0; i < used; i++) {
		u32 next = get_unaligned_le32((const u8 *)table +
				sizeof(*table) + (size_t)i * size);

		if (next != RESTART_ENTRY_ALLOCATED_LE32 &&
		    !ntfs_log_restart_slot_valid(next, size, used))
			return false;
	}
	return true;
}

static bool ntfs_log_target_required(u16 op)
{
	static const u8 required[] = { 0xfc, 0xfb, 0xff, 0x10, 0x06 };

	if (op == UpdateRelativeDataIndex || op == UpdateRelativeDataAllocation)
		return true;
	return op <= UpdateRecordDataAllocation &&
		(required[op >> 3] & (1U << (op & 7)));
}

bool ntfs_log_validate_record(const struct ntfs_log_rec_hdr *lrh, u32 bytes,
		u32 transact_id, __le16 flags)
{
	u16 redo_op;
	u16 undo_op;
	u16 redo_off;
	u16 redo_len;
	u16 undo_off;
	u16 undo_len;
	u16 target_attr;

	if (!lrh || bytes < sizeof(*lrh) ||
	    transact_id < sizeof(struct ntfs_log_restart_table) ||
	    (transact_id - sizeof(struct ntfs_log_restart_table)) %
		    sizeof(struct ntfs_transaction_entry))
		return false;

	redo_op = le16_to_cpu(lrh->redo_op);
	undo_op = le16_to_cpu(lrh->undo_op);
	redo_off = le16_to_cpu(lrh->redo_off);
	redo_len = le16_to_cpu(lrh->redo_len);
	undo_off = le16_to_cpu(lrh->undo_off);
	undo_len = le16_to_cpu(lrh->undo_len);
	target_attr = le16_to_cpu(lrh->target_attr);
	if (redo_op > ZeroEndOfFileRecord || undo_op > ZeroEndOfFileRecord ||
	    !IS_ALIGNED(redo_off, 8) || !IS_ALIGNED(undo_off, 8) ||
	    redo_off > bytes || undo_off > bytes ||
	    (!(flags & LOG_RECORD_REDO_NOT_INLINE) &&
	     redo_op != ZeroEndOfFileRecord && redo_len > bytes - redo_off) ||
	    (!(flags & LOG_RECORD_UNDO_NOT_INLINE) && undo_op != Noop &&
	     undo_op != CompensationLogRecord && undo_len > bytes - undo_off) ||
	    ntfs_log_rec_length(lrh) > bytes)
		return false;
	if (!target_attr)
		return !ntfs_log_target_required(redo_op) &&
			!ntfs_log_target_required(undo_op);
	return target_attr >= sizeof(struct ntfs_log_restart_table);
}

static struct address_space *ntfs_log_bdev_mapping(struct super_block *sb)
{
	return sb->s_bdev->bd_mapping;
}

/* flush_lock must be held. Only the detached batch writes device pages. */
static void ntfs_log_note_bdev_range(struct ntfs_log *log,
		u64 start, u32 bytes)
{
	u64 end;

	if (!bytes || check_add_overflow(start, (u64)bytes, &end) ||
		!end) {
		log->pending_bdev_range_valid = true;
		log->pending_bdev_range_full = true;
		return;
	}
	if (!log->pending_bdev_range_valid) {
		log->pending_bdev_start = start;
		log->pending_bdev_end = end;
		log->pending_bdev_range_valid = true;
		log->pending_bdev_range_full = false;
		return;
	}
	if (log->pending_bdev_range_full)
		return;
	log->pending_bdev_start = min(log->pending_bdev_start, start);
	log->pending_bdev_end = max(log->pending_bdev_end, end);
}

/*
 * Flush only pages belonging to $LogFile.  The recording path writes log
 * pages through the block-device mapping, so sync_blockdev() is correct but
 * needlessly scans every dirty page on the device (including unrelated home
 * metadata).  The caller still issues the device cache flush separately. This
 * helper only makes the pending log pages reach the request queue.
 *
 * append_lock is not required.  The runlist is protected independently and
 * remains stable for the lifetime of the mounted $LogFile inode.
 */
static int ntfs_log_sync_logfile_pages(struct ntfs_log *log)
{
	struct ntfs_inode *log_ni;
	struct address_space *mapping;
	struct runlist_element *rl;
	struct ntfs_volume *vol;
	int err = 0;

	if (!log || !log->vol || !log->vol->logfile_ino)
		return -EINVAL;
	vol = log->vol;
	log_ni = NTFS_I(vol->logfile_ino);
	mapping = ntfs_log_bdev_mapping(vol->sb);
	if (log->pending_bdev_range_valid &&
	    !log->pending_bdev_range_full) {
		u64 start = log->pending_bdev_start;
		u64 end = log->pending_bdev_end;

		if (end > start)
			err = filemap_write_and_wait_range(mapping, start, end - 1);
		else
			err = -EOVERFLOW;
		if (!err) {
			log->pending_bdev_range_valid = false;
			log->pending_bdev_range_full = false;
		}
		return err;
	}

	down_read(&log_ni->runlist.lock);
	for (rl = log_ni->runlist.rl; rl && rl->length; rl++) {
		u64 start;
		u64 bytes;
		u64 end;

		if (rl->lcn < 0 || rl->length < 0 ||
		    (u64)rl->lcn > (U64_MAX >> vol->cluster_size_bits) ||
		    (u64)rl->length > (U64_MAX >> vol->cluster_size_bits)) {
			err = -EIO;
			break;
		}
		start = (u64)rl->lcn << vol->cluster_size_bits;
		bytes = (u64)rl->length << vol->cluster_size_bits;
		if (!bytes || check_add_overflow(start, bytes, &end) || !end) {
			err = -EOVERFLOW;
			break;
		}
		err = filemap_write_and_wait_range(mapping, start, end - 1);
		if (err)
			break;
	}
	up_read(&log_ni->runlist.lock);
	if (!err) {
		log->pending_bdev_range_valid = false;
		log->pending_bdev_range_full = false;
	}
	return err;
}

static void ntfs_log_abort_writer(struct ntfs_log *log, int err)
{
	if (!log || log->aborted)
		return;

	log->aborted = true;
	log->running = false;
	wake_up_all(&log->durable_wait);
	NVolSetErrors(log->vol);
	NVolSetShutdown(log->vol);
	log->vol->sb->s_flags |= SB_RDONLY;
	ntfs_error(log->vol->sb, "$LogFile writer aborted (error %d).", -err);
}

static bool ntfs_log_lsn_before_eq(const struct ntfs_logfile_layout *layout,
		u64 first_lsn, u64 second_lsn)
{
	u64 sequence_mask;
	u64 first_sequence;
	u64 second_sequence;
	u64 sequence_delta;

	first_sequence = first_lsn >> layout->file_data_bits;
	second_sequence = second_lsn >> layout->file_data_bits;
	if (first_sequence == second_sequence)
		return first_lsn <= second_lsn;
	sequence_mask = (1ULL << layout->seq_num_bits) - 1;
	sequence_delta = (second_sequence - first_sequence) & sequence_mask;
	return sequence_delta && sequence_delta <= sequence_mask / 2;
}

static bool ntfs_log_lsn_reached(const struct ntfs_log *log,
		u64 required_lsn)
{
	u64 durable_lsn = READ_ONCE(log->durable_lsn);

	return !required_lsn || (durable_lsn &&
		ntfs_log_lsn_before_eq(&log->layout, required_lsn,
			durable_lsn));
}

static bool ntfs_log_lsn_in_writer_epoch(struct ntfs_log *log, u64 required_lsn)
{
	u64 head_lsn;
	bool in_epoch;

	mutex_lock(&log->append_lock);
	head_lsn = log->head_lsn;
	in_epoch = log->oldest_lsn && head_lsn &&
		ntfs_log_lsn_before_eq(&log->layout, log->oldest_lsn, required_lsn) &&
		ntfs_log_lsn_before_eq(&log->layout, required_lsn, head_lsn);
	mutex_unlock(&log->append_lock);
	return in_epoch;
}

static int ntfs_log_flush_group(struct ntfs_log *log, u64 required_lsn,
		bool allow_delay);
static void ntfs_log_aggregate_reset(struct ntfs_log *log);
static void ntfs_log_promote_deferred(struct ntfs_log *log,
		const unsigned long *batch_retired);
static void ntfs_log_defer_handle_frees(struct ntfs_log_handle *handle,
		unsigned int slot);

/* Capture the tail under append_lock. Never wait while holding that lock. */
int ntfs_log_flush(struct ntfs_volume *vol)
{
	struct ntfs_log *log;
	u64 lsn;
	int err = 0;

	down_read(&vol->journal_lock);
	log = vol->journal;
	if (!log)
		goto out;
	mutex_lock(&log->append_lock);
	lsn = log->last_client_lsn;
	if (log->aborted)
		err = -EROFS;
	mutex_unlock(&log->append_lock);
	if (!err && lsn)
		err = ntfs_log_flush_group(log, lsn, false);
out:
	up_read(&vol->journal_lock);
	return err;
}

static void ntfs_log_flush_work(struct work_struct *work)
{
	struct ntfs_log *log = container_of(to_delayed_work(work),
			struct ntfs_log, flush_work);

	/* stop cancels this work before detaching the writer. */
	ntfs_log_recording_account(NTFS_LOG_RECORDING_COMMIT_WORKER, 1);
	ntfs_log_flush(log->vol);

	/*
	 * Appenders may create the next batch after flush_group() freezes this
	 * one.  A queue attempt while this callback was running is not a reliable
	 * substitute for self-rearming, so guarantee an age deadline for any tail
	 * that remains after I/O.
	 */
	mutex_lock(&log->append_lock);
	if (log->running && !log->aborted && !log->stopping && log->pending_lsn)
		queue_delayed_work(system_long_wq, &log->flush_work,
				log->commit_interval);
	mutex_unlock(&log->append_lock);
}

static void ntfs_log_deferred_flush_work(struct work_struct *work)
{
	struct ntfs_log *log = container_of(to_delayed_work(work),
			struct ntfs_log, deferred_flush_work);
	unsigned int kind;
	bool pending = false;
	int err;

	err = ntfs_log_flush(log->vol);
	mutex_lock(&log->append_lock);
	if (err && !log->aborted)
		ntfs_log_abort_writer(log, err);
	for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++)
		pending |= !list_empty(&log->deferred[kind].pending);
	if (log->running && !log->aborted && !log->stopping && pending)
		queue_delayed_work(system_long_wq, &log->deferred_flush_work,
				msecs_to_jiffies(NTFS_LOG_DEFERRED_FLUSH_MS));
	mutex_unlock(&log->append_lock);
}

/* The caller pins log and does not hold the corresponding bitmap lock. */
static int ntfs_log_drain_deferred_queue(struct ntfs_log *log,
		enum ntfs_log_deferred_kind kind)
{
	struct ntfs_log_deferred_queue *queue = &log->deferred[kind];
	u64 lsn;
	bool pending;
	int err = 0;

	mutex_lock(&log->append_lock);
	pending = !list_empty(&queue->pending);
	lsn = log->last_client_lsn;
	if (log->aborted)
		err = -EROFS;
	mutex_unlock(&log->append_lock);
	if (!err && pending)
		err = ntfs_log_flush_group(log, lsn, false);
	if (!err)
		flush_work(&queue->work);
	if (!err && READ_ONCE(log->aborted))
		err = -EROFS;
	return err;
}

static int ntfs_log_pin_deferred(struct ntfs_volume *vol,
		struct ntfs_log **log_out)
{
	struct ntfs_log *log;
	int err = 0;

	down_read(&vol->journal_lock);
	log = vol->journal;
	if (log) {
		mutex_lock(&log->append_lock);
		if (!log->running || log->aborted || log->stopping)
			err = -EROFS;
		else
			atomic_inc(&log->deferred_users);
		mutex_unlock(&log->append_lock);
	}
	up_read(&vol->journal_lock);
	*log_out = err ? NULL : log;
	return err;
}

static void ntfs_log_unpin_deferred(struct ntfs_log *log)
{
	mutex_lock(&log->append_lock);
	if (atomic_dec_and_test(&log->deferred_users))
		wake_up_all(&log->deferred_wait);
	mutex_unlock(&log->append_lock);
}

int ntfs_log_reclaim_deferred(struct ntfs_volume *vol,
		enum ntfs_log_deferred_kind kind, s64 available, s64 needed,
		bool force)
{
	struct ntfs_log_deferred_queue *queue;
	struct ntfs_log *log;
	bool drain = false;
	int err;

	if (!vol || kind >= NTFS_LOG_DEFERRED_KINDS || needed < 0)
		return -EINVAL;
	err = ntfs_log_pin_deferred(vol, &log);
	if (err || !log)
		return err;

	queue = &log->deferred[kind];
	mutex_lock(&log->append_lock);
	if (queue->queued &&
	    (force || available < needed ||
	     (u64)(available - needed) < queue->units))
		drain = true;
	mutex_unlock(&log->append_lock);
	if (drain) {
		ntfs_log_recording_account(NTFS_LOG_RECORDING_DEFERRED_PRESSURE, 1);
		err = ntfs_log_drain_deferred_queue(log, kind);
	}
	ntfs_log_unpin_deferred(log);
	return err;
}

static int ntfs_log_snapshot_free_count(struct ntfs_log *log,
		enum ntfs_log_deferred_kind kind, atomic64_t *counter, s64 *result)
{
	struct ntfs_log_deferred_queue *queue = &log->deferred[kind];
	s64 count;
	int err = 0;

	/*
	 * The worker changes the bitmap counter and removes queued units while
	 * holding free_count_lock, so neither transition is counted twice.
	 */
	mutex_lock(&queue->free_count_lock);
	mutex_lock(&log->append_lock);
	if (log->aborted) {
		err = -EROFS;
	} else if (queue->queued_units > S64_MAX ||
		   check_add_overflow(atomic64_read(counter),
				      (s64)queue->queued_units, &count)) {
		ntfs_error(log->vol->sb, "Invalid deferred free space count.");
		err = -EOVERFLOW;
	} else {
		*result = count;
	}
	mutex_unlock(&log->append_lock);
	mutex_unlock(&queue->free_count_lock);
	return err;
}

int ntfs_log_get_free_counts(struct ntfs_volume *vol, s64 *clusters,
		s64 *mft_records)
{
	struct ntfs_log *log;
	int err;

	if (!vol || !clusters || !mft_records)
		return -EINVAL;
	err = ntfs_log_pin_deferred(vol, &log);
	if (err)
		return err;
	if (!log) {
		*clusters = atomic64_read(&vol->free_clusters);
		*mft_records = atomic64_read(&vol->free_mft_records);
		return 0;
	}
	err = ntfs_log_snapshot_free_count(log, NTFS_LOG_DEFERRED_CLUSTERS,
			&vol->free_clusters, clusters);
	if (!err)
		err = ntfs_log_snapshot_free_count(log, NTFS_LOG_DEFERRED_MFT,
				&vol->free_mft_records, mft_records);
	ntfs_log_unpin_deferred(log);
	return err;
}

/* append_lock must be held. */
static bool ntfs_log_has_deferred_free(const struct ntfs_log *log)
{
	unsigned int kind;

	for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++)
		if (log->deferred[kind].reserved)
			return true;
	return false;
}

/*
 * Call after data/zero BIO completion, BEFORE appending metadata that exposes
 * it. A batch device preflush makes these writes durable before any such log
 * page can reach disk. No reference to a mutable inode mapping is retained.
 */
int ntfs_log_ordered_data(struct ntfs_log_handle *handle)
{
	struct ntfs_log *log;
	int err = 0;

	if (!handle || !handle->active || current != handle->owner)
		return -EINVAL;
	log = handle->log;
	mutex_lock(&log->append_lock);
	if (log->aborted)
		err = -EROFS;
	else
		log->pending_ordered_data = true;
	mutex_unlock(&log->append_lock);
	return err;
}

struct ntfs_ordered_io {
	struct list_head list;
	struct ntfs_log *log;
	struct completion done;
	atomic_t pending;
	atomic_t error;
	errseq_t wb_err;
};

#define NTFS_ORDERED_IO_POOL_SIZE	8

struct ntfs_ordered_ioend {
	struct work_struct work;
	struct ntfs_ordered_io *ordered;
	struct iomap_ioend *ioend;
	int error;
};

static void ntfs_ordered_io_complete(struct ntfs_ordered_io *ordered)
{
	if (atomic_dec_and_test(&ordered->pending))
		complete(&ordered->done);
}

static void ntfs_ordered_ioend_work(struct work_struct *work)
{
	struct ntfs_ordered_ioend *entry =
		container_of(work, struct ntfs_ordered_ioend, work);
	struct ntfs_ordered_io *ordered = entry->ordered;
	struct ntfs_log *log = ordered->log;
	int error = entry->error;

	if (error) {
		atomic_cmpxchg(&ordered->error, 0, error);
		/*
		 * Prevent a failed newly allocated block from being read after its
		 * folio leaves writeback but before the journal discovers the error.
		 */
		mutex_lock(&log->append_lock);
		ntfs_log_abort_writer(log, error);
		mutex_unlock(&log->append_lock);
	}
	iomap_finish_ioends(entry->ioend, error);
	mempool_free(entry, log->ordered_io_pool);
	ntfs_ordered_io_complete(ordered);
}

static void ntfs_ordered_ioend_end_io(struct bio *bio)
{
	struct iomap_ioend *ioend = iomap_ioend_from_bio(bio);
	struct ntfs_ordered_ioend *entry = ioend->io_private;

	entry->error = blk_status_to_errno(bio->bi_status);
	queue_work(entry->ordered->log->ordered_io_wq, &entry->work);
}

int ntfs_log_ordered_writeback_submit(struct ntfs_ordered_io *ordered,
		struct iomap_writepage_ctx *wpc, int error)
{
	struct iomap_ioend *ioend = wpc->wb_ctx;
	struct ntfs_ordered_ioend *entry;

	if (!ordered)
		return iomap_ioend_writeback_submit(wpc, error);
	if (WARN_ON_ONCE(ioend->io_private || ioend->io_bio.bi_end_io)) {
		error = -EIO;
		goto abort_untracked;
	}
	entry = mempool_alloc(ordered->log->ordered_io_pool, GFP_NOFS);
	if (!entry) {
		error = -ENOMEM;
		goto abort_untracked;
	}
	INIT_WORK(&entry->work, ntfs_ordered_ioend_work);
	entry->ordered = ordered;
	entry->ioend = ioend;
	entry->error = 0;
	atomic_inc(&ordered->pending);
	ioend->io_private = entry;
	ioend->io_bio.bi_end_io = ntfs_ordered_ioend_end_io;
	return iomap_ioend_writeback_submit(wpc, error);

abort_untracked:
	/* No failed new block may become readable after writeback ends. */
	mutex_lock(&ordered->log->append_lock);
	ntfs_log_abort_writer(ordered->log, error);
	mutex_unlock(&ordered->log->append_lock);
	return iomap_ioend_writeback_submit(wpc, error);
}

struct ntfs_ordered_io *ntfs_log_ordered_io_begin(
		struct ntfs_log_handle *handle, struct inode *inode)
{
	struct ntfs_ordered_io *ordered;

	if (!handle || !handle->active || current != handle->owner ||
	    !inode || inode->i_sb != handle->log->vol->sb)
		return ERR_PTR(-EINVAL);
	ordered = kmalloc(sizeof(*ordered), GFP_NOFS);
	if (!ordered)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&ordered->list);
	ordered->log = handle->log;
	init_completion(&ordered->done);
	atomic_set(&ordered->pending, 1);
	atomic_set(&ordered->error, 0);
	ordered->wb_err = filemap_sample_wb_err(inode->i_mapping);
	return ordered;
}

static int ntfs_ordered_io_wait(struct ntfs_ordered_io *ordered)
{
	wait_for_completion(&ordered->done);
	return atomic_read(&ordered->error);
}

static int ntfs_ordered_io_wait_mapping(struct ntfs_ordered_io *ordered,
		struct inode *inode, loff_t start, loff_t end)
{
	int err, wb_err;

	err = filemap_fdatawait_range_keep_errors(inode->i_mapping, start, end);
	wb_err = filemap_check_wb_err(inode->i_mapping, ordered->wb_err);
	return err ? err : wb_err;
}

int ntfs_log_ordered_io_cancel(struct ntfs_ordered_io *ordered,
		struct inode *inode, loff_t start, loff_t end)
{
	int err, wait_err;

	ntfs_ordered_io_complete(ordered);
	err = ntfs_ordered_io_wait_mapping(ordered, inode, start, end);
	wait_err = ntfs_ordered_io_wait(ordered);
	kfree(ordered);
	return err ? err : wait_err;
}

int ntfs_log_ordered_io_submit(struct ntfs_log_handle *handle,
		struct inode *inode, loff_t start, loff_t end,
		struct ntfs_ordered_io *ordered)
{
	struct ntfs_log *log = handle->log;
	int err, wait_err;

	err = filemap_fdatawrite_range(inode->i_mapping, start, end);
	ntfs_ordered_io_complete(ordered);
	if (err) {
		wait_err = ntfs_ordered_io_wait_mapping(ordered, inode, start, end);
		if (wait_err && err == -EAGAIN)
			err = wait_err;
	}
	if (!err) {
		mutex_lock(&log->append_lock);
		if (!log->running || log->aborted)
			err = atomic_read(&ordered->error) ?: -EROFS;
		else {
			list_add_tail(&ordered->list, &log->pending_ordered_io);
			log->pending_ordered_data = true;
		}
		mutex_unlock(&log->append_lock);
	}
	if (err) {
		wait_err = ntfs_ordered_io_wait(ordered);
		kfree(ordered);
		if (wait_err)
			err = wait_err;
	}
	return err;
}

static int ntfs_log_wait_ordered_io(struct list_head *ordered_io)
{
	struct ntfs_ordered_io *ordered, *next;
	int err = 0;

	list_for_each_entry_safe(ordered, next, ordered_io, list) {
		int wait_err = ntfs_ordered_io_wait(ordered);

		if (!err && wait_err)
			err = wait_err;
		list_del(&ordered->list);
		kfree(ordered);
	}
	return err;
}

/*
 * The caller pins the writer with journal_lock or an active transaction.
 */
static int ntfs_log_wait_lsn_pinned(struct ntfs_log *log, u64 required_lsn)
{
	u64 byte_off;
	int err;

	/* LSNs from an older or foreign log epoch impose no writer dependency. */
	if (ntfs_lsn_to_byte_off(&log->layout, required_lsn, &byte_off)) {
		err = 0;
		goto out;
	}
	if (!ntfs_log_lsn_in_writer_epoch(log, required_lsn))
		goto out_success;
	if (!ntfs_log_lsn_reached(log, required_lsn)) {
		ntfs_log_recording_account(NTFS_LOG_RECORDING_LSN_WAIT, 1);
		err = ntfs_log_flush_group(log, required_lsn, true);
		if (err && !ntfs_log_lsn_reached(log, required_lsn))
			goto out;
	}
	if (ntfs_log_lsn_reached(log, required_lsn))
		goto out_success;
	err = -EROFS;
	goto out;

out_success:
	err = 0;
out:
	return err;
}

int ntfs_log_wait_lsn(struct ntfs_volume *vol, u64 required_lsn)
{
	struct ntfs_log *log;
	int err = 0;

	if (!vol || !required_lsn)
		return 0;
	down_read(&vol->journal_lock);
	log = vol->journal;
	if (log)
		err = ntfs_log_wait_lsn_pinned(log, required_lsn);
	up_read(&vol->journal_lock);
	return err;
}

/*
 * Background home writeback must not turn itself into a journal commit
 * leader.  Leave the home buffer dirty until the periodic/space-pressure
 * worker commits its WAL.  Ordinary synchronous writeback and fsync still
 * request the exact LSN.  A checkpoint, however, deliberately collects all
 * writeback-generated WAL first and commits that generation as one batch.
 */
int ntfs_log_writeback_lsn(struct ntfs_volume *vol, u64 required_lsn,
		bool sync)
{
	struct ntfs_log *log;
	u64 byte_off;
	int err = 0;

	if (!vol || !required_lsn)
		return 0;

	/*
	 * MFT writeback can hold mrec_lock (or the MFT folio) here, while a
	 * transaction holds journal_lock and waits for that metadata.  Defer
	 * rather than wait for a writer of journal_lock under those locks.
	 */
	if (!down_read_trylock(&vol->journal_lock))
		return -EAGAIN;
	log = vol->journal;
	if (!log)
		goto out;
	if (sync && !READ_ONCE(log->checkpoint_collecting)) {
		err = ntfs_log_wait_lsn_pinned(log, required_lsn);
		goto out;
	}
	/* LSNs outside this writer epoch do not pin current home writeback. */
	if (ntfs_lsn_to_byte_off(&log->layout, required_lsn, &byte_off))
		goto out;
	if (!ntfs_log_lsn_in_writer_epoch(log, required_lsn) ||
	    ntfs_log_lsn_reached(log, required_lsn))
		goto out;
	if (READ_ONCE(log->aborted) || !READ_ONCE(log->running)) {
		err = -EROFS;
		goto out;
	}
	ntfs_log_recording_account(NTFS_LOG_RECORDING_WRITEBACK_DEFER, 1);
	/* queue_delayed_work() keeps an already-earlier commit deadline. */
	if (!READ_ONCE(log->stopping))
		queue_delayed_work(system_long_wq, &log->flush_work,
				log->commit_interval);
	err = -EAGAIN;
out:
	up_read(&vol->journal_lock);
	return err;
}

int ntfs_log_track_inode(struct ntfs_log_handle *handle, struct inode *vi,
		u64 required_lsn)
{
	struct ntfs_inode *ni;
	unsigned long flags;
	u64 current_lsn;

	if (!handle || !handle->active || !vi || !required_lsn)
		return -EINVAL;
	ni = NTFS_I(vi);
	if (!ni->vol || ni->vol != handle->log->vol)
		return -EXDEV;

	spin_lock_irqsave(&ni->journal_lsn_lock, flags);
	current_lsn = ni->journal_lsn;
	if (!current_lsn || ntfs_log_lsn_before_eq(&handle->log->layout,
			current_lsn, required_lsn))
		ni->journal_lsn = required_lsn;
	spin_unlock_irqrestore(&ni->journal_lsn_lock, flags);
	return 0;
}

int ntfs_log_wait_inode(struct inode *vi)
{
	struct ntfs_inode *ni;
	unsigned long flags;
	u64 required_lsn;

	if (!vi)
		return -EINVAL;
	ni = NTFS_I(vi);
	spin_lock_irqsave(&ni->journal_lsn_lock, flags);
	required_lsn = ni->journal_lsn;
	spin_unlock_irqrestore(&ni->journal_lsn_lock, flags);
	return ntfs_log_wait_lsn(ni->vol, required_lsn);
}

int ntfs_log_writeback_inode(struct inode *vi, bool sync)
{
	struct ntfs_inode *ni;
	unsigned long flags;
	u64 required_lsn;

	if (!vi)
		return -EINVAL;
	ni = NTFS_I(vi);
	spin_lock_irqsave(&ni->journal_lsn_lock, flags);
	required_lsn = ni->journal_lsn;
	spin_unlock_irqrestore(&ni->journal_lsn_lock, flags);
	return ntfs_log_writeback_lsn(ni->vol, required_lsn, sync);
}

static int ntfs_log_resequence_mst(struct ntfs_log *log, void *page,
		u32 page_size)
{
	struct ntfs_log_page_hdr *hdr = page;
	__le16 *usa;
	u16 usa_count = le16_to_cpu(hdr->usa_count);
	u16 usa_ofs = le16_to_cpu(hdr->usa_ofs);
	u16 i;

	if (usa_count != 1 + page_size / NTFS_BLOCK_SIZE ||
	    usa_ofs < sizeof(*hdr) ||
	    usa_ofs + usa_count * sizeof(*usa) > page_size)
		return -EINVAL;

	log->usa_seq++;
	if (!log->usa_seq)
		log->usa_seq++;
	usa = (__le16 *)((u8 *)page + usa_ofs);
	usa[0] = cpu_to_le16(log->usa_seq);
	for (i = 1; i < usa_count; i++)
		*(__le16 *)((u8 *)page + i * NTFS_BLOCK_SIZE - sizeof(__le16)) =
			cpu_to_le16(log->usa_seq);
	return 0;
}

/*
 * Write a fixed nonresident $LogFile range through its runlist.  This avoids
 * the normal attribute writer, and therefore cannot recurse into journaling
 * once metadata hooks are enabled.
 */
static int ntfs_log_raw_write(struct ntfs_log *log, u64 file_off,
		const void *buffer, u32 bytes, bool wait)
{
	struct ntfs_inode *log_ni = NTFS_I(log->vol->logfile_ino);
	struct address_space *bdev_mapping =
		ntfs_log_bdev_mapping(log->vol->sb);
	const u8 *src = buffer;
	u64 end_off;
	u32 done = 0;
	int err = 0;

	if (!bytes || !buffer ||
	    check_add_overflow(file_off, (u64)bytes, &end_off) ||
	    end_off > log->layout.log_size)
		return -EINVAL;

	/* A prior buffered read must not hide the new raw device contents. */
	truncate_inode_pages_range(log->vol->logfile_ino->i_mapping,
			file_off, end_off - 1);

	down_write(&log_ni->runlist.lock);
	while (done < bytes) {
		struct runlist_element *rl;
		u64 pos = file_off + done;
		u64 cluster_off = pos & log->vol->cluster_size_mask;
		s64 vcn = pos >> log->vol->cluster_size_bits;
		s64 run_clusters;
		u64 run_bytes;
		loff_t dev_off;
		u32 len;

		rl = ntfs_attr_find_vcn_nolock(log_ni, vcn, NULL);
		if (IS_ERR(rl)) {
			err = PTR_ERR(rl);
			break;
		}
		if (rl->lcn < 0 || vcn < rl->vcn || vcn >= rl->vcn + rl->length) {
			err = -EIO;
			break;
		}

		run_clusters = rl->length - (vcn - rl->vcn);
		run_bytes = (u64)run_clusters << log->vol->cluster_size_bits;
		if (run_bytes <= cluster_off) {
			err = -EIO;
			break;
		}
		len = min_t(u64, bytes - done, run_bytes - cluster_off);
		dev_off = NTFS_CLU_TO_B(log->vol,
				rl->lcn + vcn - rl->vcn) + cluster_off;

		err = ntfs_bdev_write(log->vol->sb, (void *)(src + done),
				dev_off, len);
		if (err) {
			ntfs_error(log->vol->sb,
				"LogFile raw write failed at byte offset 0x%llx, length 0x%x (error %d).",
				(unsigned long long)dev_off, len, err);
				break;
		}
		if (!wait)
			ntfs_log_note_bdev_range(log, dev_off, len);
		if (wait) {
			err = filemap_write_and_wait_range(bdev_mapping, dev_off,
					dev_off + len - 1);
			if (err) {
				ntfs_error(log->vol->sb,
					"LogFile raw writeback failed at byte offset 0x%llx, length 0x%x (error %d).",
					(unsigned long long)dev_off, len, err);
				break;
			}
		}
		done += len;
	}
	up_write(&log_ni->runlist.lock);

	if (!err)
		truncate_inode_pages_range(log->vol->logfile_ino->i_mapping,
				file_off, end_off - 1);
	return err;
}

/*
 * Publish a restart page as the durable commit block for the checkpoint batch.
 * The final PREFLUSH makes previously submitted checkpoint/home writes stable.
 * FUA then makes the restart page stable in the same block-layer sequence.
 * A private direct-mapped copy is used because bdev_rw_virt() cannot consume a
 * vmalloc address and the block-device page cache must not retain stale data.
 */
static int ntfs_log_raw_write_fua(struct ntfs_log *log, u64 file_off,
		const void *buffer, u32 bytes, bool preflush)
{
	struct ntfs_inode *log_ni = NTFS_I(log->vol->logfile_ino);
	struct address_space *mapping = ntfs_log_bdev_mapping(log->vol->sb);
	u8 *data;
	u64 end_off;
	u32 done = 0;
	int err = 0;

	if (!bytes || !buffer || !IS_ALIGNED(bytes, SECTOR_SIZE) ||
	    !IS_ALIGNED(file_off, SECTOR_SIZE) ||
	    check_add_overflow(file_off, (u64)bytes, &end_off) ||
	    end_off > log->layout.log_size)
		return -EINVAL;
	data = kmemdup(buffer, bytes, GFP_NOFS);
	if (!data)
		return -ENOMEM;

	truncate_inode_pages_range(log->vol->logfile_ino->i_mapping,
			file_off, end_off - 1);
	down_write(&log_ni->runlist.lock);
	while (done < bytes) {
		struct runlist_element *rl;
		u64 pos = file_off + done;
		u64 cluster_off = pos & log->vol->cluster_size_mask;
		s64 vcn = pos >> log->vol->cluster_size_bits;
		s64 run_clusters;
		u64 run_bytes;
		loff_t dev_off;
		u32 len;
		enum req_op op = REQ_OP_WRITE | REQ_META | REQ_SYNC;

		rl = ntfs_attr_find_vcn_nolock(log_ni, vcn, NULL);
		if (IS_ERR(rl)) {
			err = PTR_ERR(rl);
			break;
		}
		if (rl->lcn < 0 || vcn < rl->vcn ||
		    vcn >= rl->vcn + rl->length) {
			err = -EIO;
			break;
		}
		run_clusters = rl->length - (vcn - rl->vcn);
		run_bytes = (u64)run_clusters << log->vol->cluster_size_bits;
		if (run_bytes <= cluster_off) {
			err = -EIO;
			break;
		}
		len = min_t(u64, bytes - done, run_bytes - cluster_off);
		dev_off = NTFS_CLU_TO_B(log->vol,
				rl->lcn + vcn - rl->vcn) + cluster_off;
		if (!IS_ALIGNED(dev_off, SECTOR_SIZE) ||
		    !IS_ALIGNED(len, SECTOR_SIZE)) {
			err = -EINVAL;
			break;
		}

		/* Drain and invalidate any older cached restart-page image. */
		err = filemap_write_and_wait_range(mapping, dev_off,
				dev_off + len - 1);
		if (err)
			break;
		err = invalidate_inode_pages2_range(mapping,
				dev_off >> PAGE_SHIFT,
				(dev_off + len - 1) >> PAGE_SHIFT);
		if (err)
			break;

		/* The final extent also makes any earlier extents durable. */
		if (done + len == bytes)
			op |= REQ_FUA | ((preflush || done) ? REQ_PREFLUSH : 0);
		err = bdev_rw_virt(log->vol->sb->s_bdev,
				dev_off >> SECTOR_SHIFT, data + done, len, op);
		if (err)
			break;
		invalidate_inode_pages2_range(mapping, dev_off >> PAGE_SHIFT,
				(dev_off + len - 1) >> PAGE_SHIFT);
		done += len;
	}
	up_write(&log_ni->runlist.lock);
	truncate_inode_pages_range(log->vol->logfile_ino->i_mapping,
			file_off, end_off - 1);
	kfree(data);
	return err;
}

static int ntfs_log_advance_lsn(const struct ntfs_logfile_layout *layout,
		u64 lsn, u32 nr_pages, u64 *next_lsn)
{
	u64 byte_off;
	u64 page_off;
	u64 seq;
	u64 seq_mask;
	u32 i;
	int err;

	err = ntfs_lsn_to_byte_off(layout, lsn, &byte_off);
	if (err)
		return err;
	page_off = byte_off & ~((u64)layout->page_mask);
	seq = lsn >> layout->file_data_bits;
	seq_mask = (1ULL << layout->seq_num_bits) - 1;
	for (i = 0; i < nr_pages; i++) {
		u64 old_page = page_off;

		page_off = ntfs_next_page_off(layout, page_off);
		if (page_off == layout->first_page && old_page != page_off) {
			seq = (seq + 1) & seq_mask;
			if (!seq)
				seq = 1;
		}
	}
	*next_lsn = ntfs_byte_off_to_lsn(layout,
			page_off + layout->data_off, seq);
	return 0;
}

/* append_lock must be held. */
static int ntfs_log_reserve_pages(struct ntfs_log *log, u32 nr_pages,
		u64 *record_lsn, u64 *next_lsn)
{
	const struct ntfs_logfile_layout *layout = &log->layout;
	u64 oldest_off = U64_MAX;
	u64 available = U64_MAX;
	u64 bytes;
	u64 off;
	u64 seq;
	bool advance_sequence;
	int err;

	if (!nr_pages ||
	    nr_pages >= (layout->log_size - layout->first_page) /
			layout->page_size)
		return -ENOSPC;

	if (log->oldest_lsn) {
		err = ntfs_lsn_to_byte_off(layout, log->oldest_lsn,
				&oldest_off);
		if (err)
			return err;
		oldest_off &= ~((u64)layout->page_mask);
	}

	/* Keep the page walker for an unaligned restart-area file size. */
	if (layout->log_size & layout->page_mask) {
		u64 candidate = log->head_lsn;
		u32 i;

		for (i = 0; i < nr_pages; i++) {
			err = ntfs_lsn_to_byte_off(layout, candidate, &off);
			if (err)
				return err;
			if ((off & ~((u64)layout->page_mask)) == oldest_off)
				return -ENOSPC;
			err = ntfs_log_advance_lsn(layout, candidate, 1,
					&candidate);
			if (err)
				return err;
		}
		*record_lsn = log->head_lsn;
		*next_lsn = candidate;
		return 0;
	}

	err = ntfs_lsn_to_byte_off(layout, log->head_lsn, &off);
	if (err)
		return err;
	off &= ~((u64)layout->page_mask);
	bytes = (u64)nr_pages * layout->page_size;
	/*
	 * The reservation spans less than one data ring.  Count the distance
	 * to the oldest page instead of walking the entire reservation under
	 * append_lock.  Its final cursor may equal oldest, but no reserved page
	 * may include it.  A prefix page behind head is never visited on wrap.
	 */
	if (oldest_off != U64_MAX) {
		if (oldest_off >= off)
			available = oldest_off - off;
		else if (oldest_off >= layout->first_page)
			available = layout->log_size - off +
					oldest_off - layout->first_page;
	}
	if (bytes > available)
		return -ENOSPC;

	/* Match advance_lsn when entering first_page from either direction. */
	seq = log->head_lsn >> layout->file_data_bits;
	advance_sequence = off < layout->first_page &&
			bytes >= layout->first_page - off;
	off += bytes;
	if (off >= layout->log_size) {
		off = layout->first_page + off - layout->log_size;
		advance_sequence = true;
	}
	if (advance_sequence) {
		seq = (seq + 1) & ((1ULL << layout->seq_num_bits) - 1);
		if (!seq)
			seq = 1;
	}

	*record_lsn = log->head_lsn;
	*next_lsn = ntfs_byte_off_to_lsn(layout, off + layout->data_off, seq);
	return 0;
}

/* append_lock must be held. No page-cache access or I/O on the append path. */
static int ntfs_log_queue_page(struct ntfs_log *log, u64 file_off,
		const void *data, bool has_terminal)
{
	struct ntfs_log_sealed_page *page;

	page = kvmalloc(sizeof(*page) + log->layout.page_size, GFP_NOFS);
	if (!page)
		return -ENOMEM;
	page->file_off = file_off;
	page->has_terminal = has_terminal;
	memcpy(page->data, data, log->layout.page_size);
	list_add_tail(&page->list, &log->sealed_pages);
	log->sealed_bytes += log->layout.page_size;
	return 0;
}

static void ntfs_log_free_sealed_pages(struct list_head *pages)
{
	struct ntfs_log_sealed_page *page, *next;

	list_for_each_entry_safe(page, next, pages, list) {
		list_del(&page->list);
		kvfree(page);
	}
}

/* append_lock must be held. */
static int ntfs_log_write_record_pages(struct ntfs_log *log, u64 lsn,
		const struct ntfs_log_record_pages *pages)
{
	u64 page_lsn = lsn;
	u16 i;
	int err;

	for (i = 0; i < pages->nr_pages; i++) {
		u64 file_off;
		void *page = (u8 *)pages->data +
			(size_t)i * pages->page_size;

		err = ntfs_log_resequence_mst(log, page, pages->page_size);
		if (err)
			return err;
		err = ntfs_lsn_to_byte_off(&log->layout, page_lsn, &file_off);
		if (err)
			return err;
		file_off &= ~((u64)log->layout.page_mask);
		err = ntfs_log_queue_page(log, file_off, page, false);
		if (err)
			return err;
		err = ntfs_log_advance_lsn(&log->layout, page_lsn, 1,
				&page_lsn);
		if (err)
			return err;
	}

	ntfs_log_recording_account(NTFS_LOG_RECORDING_PAGE, pages->nr_pages);
	return 0;
}

/* append_lock must be held and page must still be deprotected. */
static int ntfs_log_pack_record(struct ntfs_log *log,
		const struct ntfs_log_record_desc *desc, u32 record_off)
{
	struct ntfs_record_page_hdr *page = log->pending_page;
	void *record = NULL;
	u32 next_record_off;
	u32 record_bytes;
	u32 usa_count;
	__le16 *usa;
	int err;

	if (!page || !IS_ALIGNED(record_off, 8) ||
	    record_off < log->layout.data_off)
		return -EINVAL;

	err = ntfs_log_prepare_record_buffer(&log->layout, desc, 1, &record,
			&record_bytes);
	if (err)
		return err;
	if (record_bytes > log->layout.page_size - record_off) {
		err = -ENOSPC;
		goto out;
	}

	if (!log->pending_page_records) {
		usa_count = 1 + log->layout.page_size / NTFS_BLOCK_SIZE;
		page->rhdr.magic = magic_RCRD;
		page->rhdr.usa_ofs = cpu_to_le16(sizeof(*page));
		page->rhdr.usa_count = cpu_to_le16(usa_count);
		page->page_count = cpu_to_le16(1);
		page->page_pos = cpu_to_le16(1);
		usa = (__le16 *)((u8 *)page + sizeof(*page));
		*usa = cpu_to_le16(1);
	}

	memcpy((u8 *)page + record_off, record, record_bytes);
	next_record_off = ALIGN(record_off + record_bytes, 8);
	page->rhdr.lsn = cpu_to_le64(desc->this_lsn);
	page->rflags = LOG_PAGE_LOG_RECORD_END;
	page->record_hdr.next_record_off = cpu_to_le16(next_record_off);
	page->record_hdr.last_end_lsn = cpu_to_le64(desc->this_lsn);
	log->pending_page_records++;
	err = 0;
out:
	kvfree(record);
	return err;
}

/* Seal a batch-local page so no durable RCRD page is ever modified again. */
static int ntfs_log_seal_pending_page(struct ntfs_log *log)
{
	u64 head_off;
	u64 next_lsn;
	void *page;
	int err;

	if (!log->pending_page)
		return 0;
	page = log->pending_page;
	err = pre_write_mst_fixup((struct ntfs_record *)page,
			log->layout.page_size);
	if (err)
		return err;
	err = ntfs_log_resequence_mst(log, page, log->layout.page_size);
	if (err)
		return err;
	err = ntfs_log_queue_page(log, log->pending_page_off, page,
				 log->pending_page_has_terminal);
	if (err)
		return err;

	err = ntfs_lsn_to_byte_off(&log->layout, log->head_lsn, &head_off);
	if (err)
		return err;
	if ((head_off & ~((u64)log->layout.page_mask)) ==
	    log->pending_page_off) {
		err = ntfs_log_advance_lsn(&log->layout, log->head_lsn, 1,
				&next_lsn);
		if (err)
			return err;
		log->head_lsn = next_lsn;
	}

	kvfree(log->pending_page);
	log->pending_page = NULL;
	log->pending_page_off = 0;
	log->pending_page_records = 0;
	log->pending_page_has_terminal = false;
	ntfs_log_recording_account(NTFS_LOG_RECORDING_PAGE, 1);
	return 0;
}

static u32 ntfs_log_spare_credits(const struct ntfs_log_handle *handle)
{
	u64 required;

	if (!handle)
		return 0;
	/* Reserve the parent's possible CLRs, Commit and Forget. */
	required = (u64)handle->used_credits * 2 + 2;
	return required < handle->reserved_credits ?
		handle->reserved_credits - required : 0;
}

static void ntfs_log_independent_reservation(
		const struct ntfs_log_handle *parent, bool full_reservation,
		u32 *reserved, u32 *borrowed)
{
	u32 spare = ntfs_log_spare_credits(parent);

	if (!full_reservation)
		*reserved = min(*reserved, max(spare, 4U));
	*borrowed = min(*reserved, spare);
}

static int ntfs_log_reservation_pages(u32 reserved_pages, u32 additional_pages,
		u32 operation_credits, bool writeback, u32 growth_headroom,
		u32 *required_pages)
{
	u32 headroom = NTFS_LOG_EMERGENCY_PAGES;

	/* Growth slack is separate from protected checkpoint/writeback space. */
	if ((!writeback &&
	     (check_add_overflow(headroom, operation_credits, &headroom) ||
	      check_add_overflow(headroom, growth_headroom, &headroom))) ||
	    check_add_overflow(reserved_pages, additional_pages, required_pages) ||
	    check_add_overflow(*required_pages, headroom, required_pages))
		return -EOVERFLOW;
	return 0;
}

static u32 ntfs_log_growth_headroom(const struct ntfs_log_handle *handle,
		u32 pages)
{
	if (handle->writeback)
		return 0;
	return handle->operation_credits - min_t(u64,
			handle->operation_credits,
			(u64)handle->log->growth_credits + pages);
}

/* append_lock must be held. */
static void ntfs_log_charge_growth(struct ntfs_log_handle *handle, u32 pages)
{
	handle->log->growth_credits = min_t(u64, handle->operation_credits,
			(u64)handle->log->growth_credits + pages);
}

/* Batch markers have no handle reservation and occupy their own page. */
static void ntfs_log_charge_batch_marker(struct ntfs_log *log)
{
	struct ntfs_log_handle *handle;

	if (list_empty(&log->active_handles))
		return;
	handle = list_first_entry(&log->active_handles,
			struct ntfs_log_handle, active_list);
	ntfs_log_charge_growth(handle, 1);
}

static int ntfs_log_grow_reservation(struct ntfs_log_handle *handle, u32 grow,
		u32 *growth_headroom)
{
	struct ntfs_log *log = handle->log;
	u32 borrowed = min(grow, ntfs_log_spare_credits(handle->parent));
	u32 added = grow - borrowed;
	u32 required_pages;
	u64 ignored_lsn;
	u64 ignored_next;
	int err;

	*growth_headroom = ntfs_log_growth_headroom(handle, added);
	/* Borrowing already funded credits does not need more ring space. */
	if (added) {
		err = ntfs_log_reservation_pages(log->reserved_pages, added,
				handle->operation_credits, handle->writeback,
				*growth_headroom, &required_pages);
		if (!err)
			err = ntfs_log_reserve_pages(log, required_pages, &ignored_lsn,
					&ignored_next);
		if (err)
			return err;
	}
	if (borrowed)
		handle->parent->reserved_credits -= borrowed;
	ntfs_log_charge_growth(handle, added);
	log->reserved_pages += added;
	handle->reserved_credits += grow;
	ntfs_log_recording_account(NTFS_LOG_RECORDING_RESERVATION_GROW, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_RESERVATION_PAGES, added);
	return 0;
}

static int ntfs_log_record_reservation(u32 used, u32 pages, bool save_undo,
		u16 redo_op, u32 *needed)
{
	u32 terminal_pages = 2;

	if (redo_op == CommitTransaction)
		terminal_pages = 1;
	else if (redo_op == ForgetTransaction)
		terminal_pages = 0;

	if (check_add_overflow(used, pages, needed) ||
	    (save_undo && check_mul_overflow(*needed, 2U, needed)) ||
	    check_add_overflow(*needed, terminal_pages, needed))
		return -EOVERFLOW;
	return 0;
}

static bool ntfs_log_forward_fits(const struct ntfs_log_handle *handle,
		u32 pages)
{
	u32 limit = handle->bounded_credits ?: handle->operation_credits;

	return pages <= limit && handle->used_credits <= limit - pages;
}

/* append_lock must be held. Never run home writeback under a caller's locks. */
static void ntfs_log_request_checkpoint(struct ntfs_log *log)
{
	if (log->running && !log->aborted && !log->stopping)
		mod_delayed_work(system_long_wq, &log->reclaim_work, 0);
}

/* append_lock must be held. */
static int ntfs_log_append_record(struct ntfs_log *log,
		struct ntfs_log_handle *handle, u32 transaction_id, u32 record_type,
		u64 undo_next_lsn, void *payload, u32 payload_len,
		bool save_undo, u64 *record_lsn)
{
	struct ntfs_log_record_pages pages = { };
	struct ntfs_log_record_desc desc = { };
	u32 page_capacity = log->layout.page_size - log->layout.data_off;
	u32 record_bytes;
	u32 nr_pages32;
	u32 charged_pages;
	u64 byte_off;
	u64 sequence;
	u64 next_lsn;
	u64 lsn;
	u16 redo_op = Noop;
	int err;

	if (!payload || !payload_len ||
	    check_add_overflow((u32)log->layout.record_header_len,
			payload_len, &record_bytes))
		return -EINVAL;
	nr_pages32 = DIV_ROUND_UP(record_bytes, page_capacity);
	if (!nr_pages32 || nr_pages32 > U16_MAX)
		return -E2BIG;
	if (record_type == le32_to_cpu(LFS_CLIENT_RECORD) &&
	    payload_len >= sizeof(struct ntfs_log_rec_hdr))
		redo_op = le16_to_cpu(((struct ntfs_log_rec_hdr *)payload)->redo_op);
	charged_pages = nr_pages32;
	if (handle && handle->packed) {
		struct ntfs_log_packed_append *packed = handle->packed;

		if (nr_pages32 != 1)
			return -E2BIG;
		err = ntfs_lsn_to_byte_off(&log->layout, log->head_lsn,
				&byte_off);
		if (err)
			return err;
		if (packed->started && log->pending_page &&
		    packed->page_off == log->pending_page_off &&
		    (byte_off & ~((u64)log->layout.page_mask)) ==
			    packed->page_off &&
		    record_bytes <= log->layout.page_size -
			    (byte_off & log->layout.page_mask))
			charged_pages = 0;
		else if (!packed->started && save_undo)
			/* The first CLR page may already contain other records. */
			charged_pages++;
	}
	if (handle) {
		u32 growth_headroom = 0;
		u32 needed;
		int reserve_err;

		if (save_undo && !ntfs_log_forward_fits(handle, charged_pages)) {
			if (log->vol && log->vol->sb)
				ntfs_error(log->vol->sb,
					"Journal transaction exceeded physical credit limit (record pages %u, used %u, limit %u, error -ENOSPC).",
					nr_pages32, handle->used_credits,
					handle->bounded_credits ?:
						handle->operation_credits);
			return -ENOSPC;
		}

		/*
		 * Keep room for CLRs and the terminal records. The batch marker
		 * uses emergency ring space.
		 */
		reserve_err = ntfs_log_record_reservation(handle->used_credits,
				charged_pages, save_undo, redo_op, &needed);
		if (reserve_err || needed > handle->reserved_credits) {
			if (!reserve_err)
				reserve_err = ntfs_log_grow_reservation(handle,
						needed - handle->reserved_credits,
						&growth_headroom);
			if (reserve_err) {
				ntfs_log_recording_account(
					NTFS_LOG_RECORDING_RESERVATION_FAILURE, 1);
				if (reserve_err == -ENOSPC)
					ntfs_log_request_checkpoint(log);
				if (reserve_err == -ENOSPC && handle->nowait) {
					reserve_err = -EAGAIN;
					ntfs_log_recording_account(
						NTFS_LOG_RECORDING_LOCKED_BEGIN_DEFER, 1);
				}
				if (reserve_err != -EAGAIN && log->vol && log->vol->sb)
					ntfs_error(log->vol->sb,
						"Journal transaction reservation growth failed (txid %u, caller %pS, credit limit %u, checkpoint headroom %u, growth headroom %u, growth credits %u, record pages %u, used %u, reserved %u, log reserved %u, head LSN 0x%llx, oldest LSN 0x%llx, error %d).",
						handle->transaction_id, (void *)handle->caller_ip,
						handle->operation_credits,
						handle->writeback ? 0 : handle->operation_credits,
						growth_headroom, log->growth_credits,
						nr_pages32,
						handle->used_credits, handle->reserved_credits,
						log->reserved_pages,
						(unsigned long long)log->head_lsn,
						(unsigned long long)log->oldest_lsn, reserve_err);
				return reserve_err;
			}
		}
	}
	/* Multi-page records start on a fresh page and keep the old serializer. */
	if (nr_pages32 > 1) {
		err = ntfs_log_seal_pending_page(log);
		if (err)
			goto out_abort;
	} else if (log->pending_page) {
		err = ntfs_lsn_to_byte_off(&log->layout, log->head_lsn,
				&byte_off);
		if (err)
			goto out_abort;
		if ((byte_off & ~((u64)log->layout.page_mask)) !=
		    log->pending_page_off ||
		    record_bytes > log->layout.page_size -
			    (byte_off & log->layout.page_mask)) {
			err = ntfs_log_seal_pending_page(log);
			if (err)
				goto out_abort;
		}
	}

	err = ntfs_log_reserve_pages(log, nr_pages32, &lsn, &next_lsn);
	if (err) {
		if (err == -ENOSPC && log->vol && log->vol->sb)
			ntfs_error(log->vol->sb,
				"Journal record ring reservation failed (record pages %u, reserved pages %u, head LSN 0x%llx, oldest LSN 0x%llx, error %d).",
				nr_pages32, log->reserved_pages,
				(unsigned long long)log->head_lsn,
				(unsigned long long)log->oldest_lsn, err);
		return err;
	}
	if (record_type == le32_to_cpu(LFS_CLIENT_RECORD) &&
	    payload_len >= sizeof(struct ntfs_log_rec_hdr)) {
		struct ntfs_log_rec_hdr *lrh = payload;
		u16 redo_off = le16_to_cpu(lrh->redo_off);

		if (le16_to_cpu(lrh->redo_op) == OpenNonresidentAttribute &&
		    redo_off <= payload_len &&
		    sizeof(struct ntfs_open_attr_entry_disk) <=
			    payload_len - redo_off) {
			struct ntfs_open_attr_entry_disk *disk;

			disk = (void *)((u8 *)payload + redo_off);
			disk->open_record_lsn = cpu_to_le64(lsn);
		}
	}

	desc.this_lsn = lsn;
	desc.client_prev_lsn = log->last_client_lsn;
	desc.client_undo_next_lsn = undo_next_lsn;
	desc.record_type = record_type;
	desc.transact_id = handle ? handle->transaction_id : transaction_id;
	desc.client_seq = log->layout.client_seq;
	desc.client_idx = log->layout.client_idx;
	desc.payload = payload;
	desc.payload_len = payload_len;

	if (nr_pages32 > 1) {
		err = ntfs_log_build_record_pages(&log->layout, &desc, &pages);
		if (err)
			return err;
	} else {
		bool packed = log->pending_page_records != 0;

		err = ntfs_lsn_to_byte_off(&log->layout, lsn, &byte_off);
		if (err)
			return err;
		if (!log->pending_page) {
			log->pending_page = kvzalloc(log->layout.page_size,
					GFP_NOFS);
			if (!log->pending_page)
				return -ENOMEM;
			log->pending_page_off = byte_off &
					~((u64)log->layout.page_mask);
		}
		err = ntfs_log_pack_record(log, &desc,
				byte_off & log->layout.page_mask);
		if (err)
			return err;
		if (redo_op == CommitTransaction || redo_op == ForgetTransaction)
			log->pending_page_has_terminal = true;
		if (packed)
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_PACKED_RECORD, 1);
	}

	/* Consume the reservation before I/O. An uncertain tail aborts writer. */
	if (handle) {
		if (charged_pages > handle->reserved_credits ||
		    handle->used_credits >
			    handle->reserved_credits - charged_pages ||
		    log->reserved_pages < charged_pages) {
			if (log->vol && log->vol->sb)
				ntfs_error(log->vol->sb,
					"Journal reservation accounting underflow (record pages %u, used %u, handle reserved %u, log reserved %u, error -ENOSPC).",
					nr_pages32, handle->used_credits,
					handle->reserved_credits, log->reserved_pages);
			ntfs_log_free_record_pages(&pages);
			return -ENOSPC;
		}
		handle->used_credits += charged_pages;
		log->reserved_pages -= charged_pages;
		if (handle->packed) {
			handle->packed->page_off = log->pending_page_off;
			handle->packed->started = true;
		}
	}
	if (nr_pages32 > 1) {
		log->head_lsn = next_lsn;
		err = ntfs_log_write_record_pages(log, lsn, &pages);
		ntfs_log_free_record_pages(&pages);
		if (err)
			goto out_abort;
	} else {
		sequence = lsn >> log->layout.file_data_bits;
		byte_off += ALIGN(record_bytes, 8);
		if ((byte_off & log->layout.page_mask) == 0 ||
		    byte_off >= log->layout.log_size) {
			err = ntfs_log_advance_lsn(&log->layout, lsn, 1,
					&log->head_lsn);
			if (err)
				goto out_abort;
		} else {
			log->head_lsn = ntfs_byte_off_to_lsn(&log->layout,
					byte_off, sequence);
		}
	}

	log->last_client_lsn = lsn;
	if (!log->pending_records)
		log->pending_first_lsn = lsn;
	log->pending_lsn = lsn;
	log->pending_records++;
	if (log->flush_inflight)
		ntfs_log_recording_account(NTFS_LOG_RECORDING_APPEND_DURING_FLUSH, 1);
	/*
	 * Bound journal staging memory without forcing an early commit merely
	 * because this is a small on-disk ring.  Ring reservations independently
	 * trigger a synchronous checkpoint before overwrite, while the periodic
	 * worker supplies the age bound.  Keeping these policies separate avoids
	 * a commit every quarter-ring on the common 1.3MiB $LogFile.
	 */
	if (log->async_commit && log->running && !log->stopping &&
	    log->sealed_bytes >= log->staging_limit)
		mod_delayed_work(system_long_wq, &log->flush_work, 0);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_RECORD, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_BYTE, record_bytes);
	*record_lsn = lsn;
	return 0;

out_abort:
	ntfs_log_abort_writer(log, err);
	return err;
}

/* append_lock must be held.  The returned LSN is the batch's commit point. */
static int ntfs_log_append_batch_commit(struct ntfs_log *log,
		const unsigned long *committed_transactions, u16 flags,
		u64 *lsn_out)
{
	struct ntfs_log_batch_transactions *transactions;
	struct ntfs_log_batch_commit *commit;
	struct ntfs_log_operation_desc operation = { };
	struct ntfs_log_payload payload = { };
	size_t redo_len;
	unsigned int committed_count;
	unsigned int index;
	u64 generation;
	u64 last_lsn;
	u64 lsn;
	u32 records;
	int err;

	if (!committed_transactions ||
	    flags & ~NTFS_LOG_BATCH_COMMIT_RESTART_REQUIRED ||
	    !log->pending_first_lsn || !log->pending_lsn ||
	    !log->pending_records)
		return -EINVAL;
	redo_len = sizeof(*commit) + sizeof(*transactions) +
			NTFS_LOG_TRANSACTION_BITMAP_BYTES;
	if (redo_len > U16_MAX)
		return -E2BIG;
	commit = kzalloc(redo_len, GFP_NOFS);
	if (!commit)
		return -ENOMEM;
	last_lsn = log->pending_lsn;
	records = log->pending_records;
	generation = ++log->batch_generation;
	if (!generation)
		generation = ++log->batch_generation;
	commit->magic = cpu_to_le64(NTFS_LOG_BATCH_COMMIT_MAGIC);
	commit->magic_inv = cpu_to_le64(~NTFS_LOG_BATCH_COMMIT_MAGIC);
	commit->generation = cpu_to_le64(generation);
	commit->generation_inv = cpu_to_le64(~generation);
	commit->first_lsn = cpu_to_le64(log->pending_first_lsn);
	commit->last_lsn = cpu_to_le64(last_lsn);
	commit->record_count = cpu_to_le32(records);
	commit->version = cpu_to_le16(NTFS_LOG_BATCH_COMMIT_VERSION);
	commit->flags = cpu_to_le16(flags);
	transactions = (void *)(commit + 1);
	transactions->bitmap_bytes =
			cpu_to_le16(NTFS_LOG_TRANSACTION_BITMAP_BYTES);
	transactions->bitmap_bits =
			cpu_to_le16(NTFS_LOG_TRANSACTION_SLOT_COUNT);
	committed_count = bitmap_weight(committed_transactions,
			NTFS_LOG_TRANSACTION_SLOT_COUNT);
	transactions->committed_count = cpu_to_le32(committed_count);
	for_each_set_bit(index, committed_transactions,
			NTFS_LOG_TRANSACTION_SLOT_COUNT)
		transactions->bitmap[index >> 3] |= BIT(index & 7);
	operation.redo_op = Noop;
	operation.undo_op = Noop;
	operation.redo_data = commit;
	operation.redo_len = redo_len;
	err = ntfs_log_build_operation_payload(&operation, &payload);
	if (err)
		goto out;
	err = ntfs_log_append_record(log, NULL,
			sizeof(struct ntfs_log_restart_table),
			le32_to_cpu(LFS_CLIENT_RECORD), 0, payload.data,
			payload.len, false, &lsn);
	ntfs_log_free_payload(&payload);
	if (err)
		goto out;
	ntfs_log_charge_batch_marker(log);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_BATCH_MARKER, 1);
	ntfs_log_recording_account(
			NTFS_LOG_RECORDING_BATCH_COMMITTED_TRANSACTION,
			committed_count);
	*lsn_out = lsn;
out:
	kfree(commit);
	return err;
}

/*
 * Build the pre-commit image of a marker page.  Its page/MST framing remains
 * valid, but the inverse magic is deliberately wrong.  After this image and
 * every preceding log page have reached the request queue, one sector-sized
 * PREFLUSH|FUA rewrite changes it to the valid sealed image atomically.
 */
static int ntfs_log_build_incomplete_batch_page(struct ntfs_log *log,
		const struct ntfs_log_sealed_page *marker_page, u64 marker_lsn,
		u32 commit_bytes, void **page_out)
{
	struct ntfs_log_batch_commit *commit;
	struct ntfs_lfs_record_hdr *hdr;
	struct ntfs_log_rec_hdr *lrh;
	const struct ntfs_log_batch_commit *valid;
	void *page;
	u32 payload_len;
	u16 redo_off;
	u64 commit_end;

	if (!log || !marker_page || !page_out ||
	    commit_bytes < SECTOR_SIZE || commit_bytes > log->layout.page_size ||
	    !is_power_of_2(commit_bytes) ||
	    log->layout.data_off > commit_bytes - sizeof(*hdr))
		return -EINVAL;
	hdr = (void *)(marker_page->data + log->layout.data_off);
	payload_len = le32_to_cpu(hdr->client_data_len);
	if (le64_to_cpu(hdr->this_lsn) != marker_lsn ||
	    hdr->record_type != LFS_CLIENT_RECORD ||
	    payload_len < sizeof(*lrh) ||
	    payload_len > log->layout.page_size - log->layout.data_off -
			sizeof(*hdr))
		return -EINVAL;
	lrh = (void *)((u8 *)hdr + sizeof(*hdr));
	valid = ntfs_log_batch_commit_payload(lrh, payload_len);
	if (!valid)
		return -EINVAL;
	redo_off = le16_to_cpu(lrh->redo_off);
	commit_end = log->layout.data_off + sizeof(*hdr) + redo_off +
			sizeof(*valid);
	if (commit_end > commit_bytes)
		return -E2BIG;

	page = kmemdup(marker_page->data, log->layout.page_size, GFP_NOFS);
	if (!page)
		return -ENOMEM;
	hdr = (void *)((u8 *)page + log->layout.data_off);
	lrh = (void *)((u8 *)hdr + sizeof(*hdr));
	commit = (void *)((u8 *)lrh + redo_off);
	commit->magic_inv = commit->magic;
	*page_out = page;
	return 0;
}

static int ntfs_log_write_restart_copy(struct ntfs_log *log, u16 slot,
		u64 current_lsn, u64 restart_lsn, u64 oldest_lsn, bool clean,
		bool flush, bool preflush)
{
	void *page = NULL;
	u64 started;
	int err;

	err = ntfs_log_build_restart_page_v1(&log->layout, current_lsn,
			restart_lsn, oldest_lsn,
			log->restart_log_open_count, clean, &page);
	if (err)
		return err;
	mutex_lock(&log->append_lock);
	err = ntfs_log_resequence_mst(log, page,
			log->layout.system_page_size);
	mutex_unlock(&log->append_lock);
	if (err)
		goto out;

	started = ktime_get_ns();
	if (flush)
		err = ntfs_log_raw_write_fua(log,
				(u64)slot * log->layout.system_page_size,
				page, log->layout.system_page_size, preflush);
	else
		err = ntfs_log_raw_write(log,
				(u64)slot * log->layout.system_page_size,
				page, log->layout.system_page_size, true);
	ntfs_log_recording_account(flush ?
			NTFS_LOG_RECORDING_RESTART_CACHE_FLUSH_NS :
			NTFS_LOG_RECORDING_RESTART_WRITE_NS,
			ktime_get_ns() - started);
	if (!err) {
		ntfs_log_recording_account(NTFS_LOG_RECORDING_RESTART_WRITE, 1);
		if (flush) {
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_RESTART_FLUSH, 1);
		}
	}
out:
	kvfree(page);
	return err;
}

/* flush_lock must be held. Restart-copy I/O must not hold append_lock. */
static int ntfs_log_publish_restart(struct ntfs_log *log, u64 current_lsn,
		u64 restart_lsn, u64 oldest_lsn, bool clean,
		bool batch_preflushed)
{
	bool refresh_fallback = log->restart_slot_valid &&
		oldest_lsn != log->oldest_lsn;
	u16 slot;
	int err;

	if (!log->restart_slot_valid) {
		u16 durable_slot;

		slot = log->restart_slot;
		err = ntfs_log_write_restart_copy(log, slot, current_lsn,
				restart_lsn, oldest_lsn, clean, true,
				!batch_preflushed);
		if (err)
			return err;
		durable_slot = slot;
		slot ^= 1;
		err = ntfs_log_write_restart_copy(log, slot, current_lsn,
				restart_lsn, oldest_lsn, clean, false, false);
		if (err)
			return err;
		log->restart_slot = durable_slot;
		log->restart_slot_valid = true;
		return 0;
	}
	slot = log->restart_slot ^ 1;
	err = ntfs_log_write_restart_copy(log, slot, current_lsn,
			restart_lsn, oldest_lsn, clean, true,
			!batch_preflushed);
	if (err)
		return err;

	log->restart_slot = slot;
	/*
	 * Reclaim must not overwrite records referenced by the fallback copy.
	 * Once the new checkpoint and this copy are durable, the previous copy can
	 * be overwritten safely. Its write must reach the device before reclaim,
	 * so recovery cannot observe an old restart record after newer log pages,
	 * but a second cache flush is unnecessary: the first copy remains the
	 * known-durable anchor. Keep restart_slot on that anchor so the next
	 * publication overwrites the unconfirmed copy first.
	 */
	if (refresh_fallback) {
		u16 durable_slot = slot;

		slot ^= 1;
		err = ntfs_log_write_restart_copy(log, slot, current_lsn,
				restart_lsn, oldest_lsn, clean, false, false);
		if (err)
			return err;
		log->restart_slot = durable_slot;
	}
	return 0;
}

/* Called without append_lock so concurrent appenders can join this batch. */
static int ntfs_log_flush_group(struct ntfs_log *log, u64 required_lsn,
		bool allow_delay)
{
	LIST_HEAD(pages);
	LIST_HEAD(ordered_io);
	DECLARE_BITMAP(batch_retired, NTFS_LOG_TRANSACTION_SLOT_COUNT);
	struct ntfs_log_sealed_page *page;
	struct ntfs_log_sealed_page *marker_page;
	void *incomplete_marker = NULL;
	u64 started = ktime_get_ns();
	u64 restart_lsn;
	u64 oldest_lsn;
	u64 marker_lsn;
	u16 marker_flags;
	bool clean;
	bool publish;
	bool ordered;
	u64 pending_lsn;
	u32 pending_records;
	u32 marker_write_bytes;
	u64 phase_started;
	int err = 0;

	mutex_lock(&log->flush_lock);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_FLUSH_LOCK_WAIT_NS,
			ktime_get_ns() - started);
	if (ntfs_log_lsn_reached(log, required_lsn))
		goto out_flush;
	if (allow_delay)
		usleep_range(200, 400);

	mutex_lock(&log->append_lock);
	if (ntfs_log_lsn_reached(log, required_lsn))
		goto out_append;
	if (!log->running || log->aborted) {
		err = -EROFS;
		goto out_append;
	}
	pending_lsn = log->pending_lsn;
	pending_records = log->pending_records;
	if (!pending_lsn || !pending_records ||
	    !ntfs_log_lsn_before_eq(&log->layout, required_lsn, pending_lsn)) {
		err = -EIO;
		goto out_abort;
	}
	publish = log->pending_checkpoint_lsn != 0 || !log->restart_slot_valid;
	restart_lsn = log->pending_checkpoint_lsn ?
		log->pending_checkpoint_lsn : log->checkpoint_lsn;
	oldest_lsn = log->pending_checkpoint_lsn ?
		log->pending_oldest_lsn : log->oldest_lsn;
	clean = log->pending_checkpoint_lsn && log->pending_clean;
	ordered = log->pending_ordered_data;
	marker_flags = publish ? NTFS_LOG_BATCH_COMMIT_RESTART_REQUIRED : 0;
	marker_write_bytes = bdev_logical_block_size(log->vol->sb->s_bdev);
	/* No merge state may outlive the mutable pages being detached below. */
	ntfs_log_aggregate_reset(log);
	/* Put the marker alone at the beginning of a page and within one sector. */
	err = ntfs_log_seal_pending_page(log);
	if (err)
		goto out_abort;
	/* Commit state is frozen into the same generation marker. */
	bitmap_copy(batch_retired, log->retired_transaction_ids,
			NTFS_LOG_TRANSACTION_SLOT_COUNT);
	err = ntfs_log_append_batch_commit(log, batch_retired, marker_flags,
			&marker_lsn);
	if (err)
		goto out_abort;
	pending_lsn = marker_lsn;
	pending_records = log->pending_records;
	err = ntfs_log_seal_pending_page(log);
	if (err)
		goto out_abort;
	if (WARN_ON_ONCE(list_empty(&log->sealed_pages))) {
		err = -EIO;
		goto out_abort;
	}
	marker_page = list_last_entry(&log->sealed_pages,
			struct ntfs_log_sealed_page, list);
	err = ntfs_log_build_incomplete_batch_page(log, marker_page,
			marker_lsn, marker_write_bytes, &incomplete_marker);
	if (err)
		goto out_abort;

	/* Freeze this batch. New appenders cannot modify any of its pages. */
	log->pending_ordered_data = false;
	list_splice_init(&log->pending_ordered_io, &ordered_io);
	log->pending_checkpoint_lsn = 0;
	log->pending_oldest_lsn = 0;
	log->pending_clean = false;
	list_splice_init(&log->sealed_pages, &pages);
	log->sealed_bytes = 0;
	log->pending_lsn = 0;
	log->pending_first_lsn = 0;
	log->pending_records = 0;
	log->flush_inflight = true;
	mutex_unlock(&log->append_lock);

	/* Only completed data BIOs can precede this generation's commit marker. */
	err = ntfs_log_wait_ordered_io(&ordered_io);
	if (err)
		goto out_io;
	phase_started = ktime_get_ns();
	list_for_each_entry(page, &pages, list) {
		const void *data = page == marker_page ? incomplete_marker :
			page->data;

		if (page->has_terminal) {
			bool buffered = log->pending_bdev_range_valid;
			bool preflush = buffered || list_is_first(&page->list, &pages);

			/*
			 * Other readers can act on these records before the batch
			 * marker. The first preflush orders any data writes, then
			 * consecutive FUA writes keep the log prefix durable.
			 */
			if (buffered)
				err = ntfs_log_sync_logfile_pages(log);
			if (!err)
				err = ntfs_log_raw_write_fua(log, page->file_off, data,
							   log->layout.page_size,
							   preflush);
		} else {
			err = ntfs_log_raw_write(log, page->file_off, data,
						log->layout.page_size, false);
		}
		if (err)
			goto out_io;
	}
	if (!err)
		err = ntfs_log_sync_logfile_pages(log);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_LOG_WRITEBACK_NS,
			ktime_get_ns() - phase_started);
	if (err)
		goto out_io;
	/*
	 * A normal generation ends with the marker sector's PREFLUSH|FUA.  A
	 * checkpoint generation instead writes its restart-required marker without
	 * FUA, then uses the restart page's PREFLUSH|FUA as the single durability
	 * barrier.  Recovery cannot accept that marker through an older restart,
	 * so a crash before the final preflush never exposes reordered log data.
	 */
	phase_started = ktime_get_ns();
	if (publish) {
		err = ntfs_log_raw_write(log, marker_page->file_off,
				marker_page->data, marker_write_bytes, true);
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_BATCH_MARKER_WRITE_NS,
				ktime_get_ns() - phase_started);
		if (err)
			goto out_io;
		phase_started = ktime_get_ns();
		err = ntfs_log_publish_restart(log, pending_lsn, restart_lsn,
				oldest_lsn, clean, false);
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_BATCH_MARKER_FLUSH_NS,
				ktime_get_ns() - phase_started);
		if (!err)
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_COMBINED_CHECKPOINT_FLUSH,
					1);
	} else {
		err = ntfs_log_raw_write_fua(log, marker_page->file_off,
				marker_page->data, marker_write_bytes, true);
		phase_started = ktime_get_ns() - phase_started;
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_RECORD_CACHE_FLUSH_NS,
				phase_started);
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_BATCH_MARKER_FLUSH_NS,
				phase_started);
		ntfs_log_recording_account(NTFS_LOG_RECORDING_RESTART_SKIPPED, 1);
	}
	if (err)
		goto out_io;
	if (ordered)
		ntfs_log_recording_account(NTFS_LOG_RECORDING_ORDERED_FLUSH, 1);
	/* The marker or restart commit block made the generation durable. */
	ntfs_log_recording_account(NTFS_LOG_RECORDING_RECORD_FLUSH, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_FLUSHED_RECORD,
			pending_records);
out_io:
	mutex_lock(&log->append_lock);
	log->flush_inflight = false;
	if (err)
		goto out_abort;
	if (log->aborted) {
		err = -EROFS;
		goto out_append;
	}
	bitmap_andnot(log->retired_transaction_ids,
			log->retired_transaction_ids, batch_retired,
			NTFS_LOG_TRANSACTION_SLOT_COUNT);
	if (publish) {
		WRITE_ONCE(log->checkpoint_lsn, restart_lsn);
		WRITE_ONCE(log->oldest_lsn, oldest_lsn);
		log->layout.oldest_lsn = oldest_lsn;
		log->layout.current_lsn = pending_lsn;
	}
	/* Home writeback may proceed only after replay can discover this LSN. */
	WRITE_ONCE(log->durable_lsn, pending_lsn);
	ntfs_log_promote_deferred(log, batch_retired);
	wake_up_all(&log->durable_wait);
	goto out_append;

out_abort:
	ntfs_log_abort_writer(log, err);
out_append:
	mutex_unlock(&log->append_lock);
out_flush:
	kfree(incomplete_marker);
	ntfs_log_free_sealed_pages(&pages);
	mutex_unlock(&log->flush_lock);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_FLUSH_NS,
			ktime_get_ns() - started);
	return err;
}

static void ntfs_log_clear_open_attrs(struct ntfs_log *log)
{
	struct ntfs_log_open_attr *entry;
	struct ntfs_log_open_attr *next;

	list_for_each_entry_safe(entry, next, &log->open_attrs, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	log->next_open_attr_slot = sizeof(struct ntfs_log_restart_table);
}

static void ntfs_log_clear_dirty_pages(struct ntfs_log *log)
{
	struct ntfs_log_dirty_page *entry;
	struct ntfs_log_dirty_page *next;

	list_for_each_entry_safe(entry, next, &log->dirty_pages, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

/* append_lock must be held. */
static int ntfs_log_track_dirty_page(struct ntfs_log *log,
		const struct ntfs_log_operation_desc *operation, u64 lsn)
{
	struct ntfs_log_dirty_page *entry;
	u64 transfer_len;
	size_t size;

	if (!operation->lcns_follow)
		return 0;
	list_for_each_entry(entry, &log->dirty_pages, list) {
		if (entry->target_attr != operation->target_attr ||
		    entry->vcn != operation->target_vcn ||
		    entry->lcns_follow != operation->lcns_follow)
			continue;
		memcpy(entry->page_lcns, operation->page_lcns,
				operation->lcns_follow * sizeof(*entry->page_lcns));
		entry->latest_lsn = lsn;
		return 0;
	}

	transfer_len = (u64)operation->lcns_follow <<
			log->vol->cluster_size_bits;
	if (transfer_len > U32_MAX ||
	    check_mul_overflow((size_t)operation->lcns_follow, sizeof(u64),
		    &size) || check_add_overflow(sizeof(*entry), size, &size))
		return -EOVERFLOW;
	entry = kzalloc(size, GFP_NOFS);
	if (!entry)
		return -ENOMEM;
	entry->target_attr = operation->target_attr;
	entry->transfer_len = transfer_len;
	entry->lcns_follow = operation->lcns_follow;
	entry->vcn = operation->target_vcn;
	entry->oldest_lsn = lsn;
	entry->latest_lsn = lsn;
	memcpy(entry->page_lcns, operation->page_lcns,
			operation->lcns_follow * sizeof(*entry->page_lcns));
	INIT_LIST_HEAD(&entry->list);
	list_add_tail(&entry->list, &log->dirty_pages);
	return 0;
}

struct ntfs_log_checkpoint_dumps {
	struct ntfs_log_payload open_attrs;
	struct ntfs_log_payload attr_names;
	struct ntfs_log_payload transactions;
	struct ntfs_log_payload dirty_pages;
	u64 open_attrs_lsn;
	u64 attr_names_lsn;
	u64 transactions_lsn;
	u64 dirty_pages_lsn;
	u64 checkpoint_start;
	u64 oldest_lsn;
	u32 open_attr_entries;
	u32 dirty_page_entries;
	u32 transaction_entries;
};

static void ntfs_log_free_checkpoint_dumps(
		struct ntfs_log_checkpoint_dumps *dumps)
{
	ntfs_log_free_payload(&dumps->open_attrs);
	ntfs_log_free_payload(&dumps->attr_names);
	ntfs_log_free_payload(&dumps->transactions);
	ntfs_log_free_payload(&dumps->dirty_pages);
}

/* open_attr_lock must be held. */
static int ntfs_log_build_open_attr_dumps(struct ntfs_log *log,
		struct ntfs_log_checkpoint_dumps *dumps)
{
	struct ntfs_log_restart_table *table;
	struct ntfs_log_open_attr *entry;
	u32 names_len = 0;
	u32 table_len;
	u32 names_off = 0;
	u16 expected_slot;
	u16 total = 0;
	void *names = NULL;
	void *data;

	list_for_each_entry(entry, &log->open_attrs, list) {
		u32 entry_len;

		if (total == U16_MAX)
			return -E2BIG;
		if (entry->name_len &&
		    check_add_overflow((u32)sizeof(struct ntfs_attr_name_entry),
			    (u32)(entry->name_len + 1) * sizeof(__le16),
			    &entry_len))
			return -EOVERFLOW;
		if (entry->name_len &&
		    check_add_overflow(names_len, entry_len, &names_len))
			return -EOVERFLOW;
		total++;
	}
	if (!total)
		return 0;

	table_len = sizeof(*table) +
			total * sizeof(struct ntfs_open_attr_entry_disk);
	data = kvzalloc(table_len, GFP_NOFS);
	if (!data)
		return -ENOMEM;
	if (names_len) {
		names = kvzalloc(names_len, GFP_NOFS);
		if (!names) {
			kvfree(data);
			return -ENOMEM;
		}
	}

	table = data;
	table->size = cpu_to_le16(sizeof(struct ntfs_open_attr_entry_disk));
	table->used = cpu_to_le16(total);
	table->total = cpu_to_le16(total);
	table->free_goal = cpu_to_le32(sizeof(*table));
	expected_slot = sizeof(*table);
	list_for_each_entry(entry, &log->open_attrs, list) {
		struct ntfs_open_attr_entry_disk *disk;

		if (entry->slot != expected_slot) {
			kvfree(names);
			kvfree(data);
			return -EUCLEAN;
		}
		disk = (void *)((u8 *)data + entry->slot);
		disk->next = RESTART_ENTRY_ALLOCATED_LE;
		disk->bytes_per_index = cpu_to_le32(entry->bytes_per_index);
		disk->type = cpu_to_le32(entry->type);
		disk->is_dirty_pages = entry->is_dirty_pages;
		disk->is_attr_name = !!entry->name_len;
		disk->name_len = entry->name_len;
		disk->mref = cpu_to_le64(entry->mref);
		disk->open_record_lsn = cpu_to_le64(entry->open_record_lsn);
		expected_slot += sizeof(*disk);

		if (entry->name_len) {
			struct ntfs_attr_name_entry *name_entry;
			u16 name_bytes = entry->name_len * sizeof(__le16);

			name_entry = (void *)((u8 *)names + names_off);
			name_entry->off = cpu_to_le16(entry->slot);
			name_entry->name_bytes = cpu_to_le16(name_bytes);
			memcpy(name_entry->name, entry->name, name_bytes);
			names_off += sizeof(*name_entry) + name_bytes +
					sizeof(__le16);
		}
	}
	if (expected_slot != log->next_open_attr_slot || names_off != names_len) {
		kvfree(names);
		kvfree(data);
		return -EUCLEAN;
	}

	dumps->open_attrs.data = data;
	dumps->open_attrs.len = table_len;
	dumps->attr_names.data = names;
	dumps->attr_names.len = names_len;
	dumps->open_attr_entries = total;
	return 0;
}

/* append_lock must be held. */
static int ntfs_log_build_transaction_dump(struct ntfs_log *log,
		struct ntfs_log_checkpoint_dumps *dumps)
{
	struct ntfs_log_restart_table *table;
	struct ntfs_log_handle *handle;
	struct ntfs_transaction_entry *disk;
	struct ntfs_log_undo_entry *undo;
	u32 first = sizeof(*table);
	u32 stride = sizeof(*disk);
	u32 max_slot = 0;
	u32 table_len;
	u32 prev_free = 0;
	u32 slot;
	u16 total = 0;
	u16 used;
	void *data;

	list_for_each_entry(handle, &log->active_handles, active_list) {
		if (handle->forget_recorded)
			continue;
		if (total == U16_MAX)
			return -E2BIG;
		if (handle->transaction_id < first ||
		    (handle->transaction_id - first) % stride)
			return -EUCLEAN;
		max_slot = max(max_slot, handle->transaction_id);
		total++;
		if (handle->first_lsn && (!dumps->checkpoint_start ||
		    ntfs_log_lsn_before_eq(&log->layout, handle->first_lsn,
			    dumps->checkpoint_start)))
			dumps->checkpoint_start = handle->first_lsn;
	}
	if (!total)
		return 0;

	used = (max_slot - first) / stride + 1;
	table_len = first + (u32)used * stride;
	if (table_len > U16_MAX)
		return -E2BIG;
	data = kvzalloc(table_len, GFP_NOFS);
	if (!data)
		return -ENOMEM;
	table = data;
	table->size = cpu_to_le16(stride);
	table->used = cpu_to_le16(used);
	table->total = cpu_to_le16(total);
	table->free_goal = cpu_to_le32(first);

	list_for_each_entry(handle, &log->active_handles, active_list) {
		u32 undo_len = 0;
		u32 undo_records = 0;

		if (handle->forget_recorded)
			continue;
		disk = (void *)((u8 *)data + handle->transaction_id);
		disk->next = RESTART_ENTRY_ALLOCATED_LE;
		disk->transact_state = handle->commit_recorded ?
				TransactionCommitted : TransactionActive;
		disk->first_lsn = cpu_to_le64(handle->first_lsn);
		disk->prev_lsn = cpu_to_le64(handle->prev_lsn);
		disk->undo_next_lsn = cpu_to_le64(handle->undo_next_lsn);
		list_for_each_entry(undo, &handle->undo_entries, list) {
			if (check_add_overflow(undo_len,
				    (u32)undo->operation.undo_len, &undo_len)) {
				kvfree(data);
				return -EOVERFLOW;
			}
			undo_records++;
		}
		disk->undo_records = cpu_to_le32(undo_records);
		disk->undo_len = cpu_to_le32(undo_len);
	}

	for (slot = first; slot <= max_slot; slot += stride) {
		__le32 *next = (void *)((u8 *)data + slot);

		if (*next == RESTART_ENTRY_ALLOCATED_LE)
			continue;
		if (!table->first_free)
			table->first_free = cpu_to_le32(slot);
		if (prev_free)
			*(__le32 *)((u8 *)data + prev_free) = cpu_to_le32(slot);
		prev_free = slot;
	}
	if (prev_free)
		table->last_free = cpu_to_le32(prev_free);

	dumps->transactions.data = data;
	dumps->transactions.len = table_len;
	dumps->transaction_entries = total;
	return 0;
}

/* append_lock must be held. */
static int ntfs_log_build_dirty_page_dump(struct ntfs_log *log,
		struct ntfs_log_checkpoint_dumps *dumps)
{
	struct ntfs_log_dirty_page *entry;
	struct ntfs_log_restart_table *table;
	struct ntfs_dirty_page_entry *disk;
	u32 max_lcns = 0;
	u32 table_len;
	u32 stride;
	u16 total = 0;
	void *data;

	list_for_each_entry(entry, &log->dirty_pages, list) {
		if (total == U16_MAX)
			return -E2BIG;
		max_lcns = max_t(u32, max_lcns, entry->lcns_follow);
		total++;
		if (!dumps->checkpoint_start ||
		    ntfs_log_lsn_before_eq(&log->layout, entry->oldest_lsn,
			    dumps->checkpoint_start))
			dumps->checkpoint_start = entry->oldest_lsn;
	}
	if (!total)
		return 0;
	if (check_mul_overflow(max_lcns, (u32)sizeof(__le64), &stride) ||
	    check_add_overflow(stride, (u32)sizeof(*disk), &stride))
		return -EOVERFLOW;
	stride = ALIGN(stride, 8);
	if (stride > U16_MAX ||
	    check_mul_overflow((u32)total, stride, &table_len) ||
	    check_add_overflow(table_len, (u32)sizeof(*table), &table_len))
		return -EOVERFLOW;
	data = kvzalloc(table_len, GFP_NOFS);
	if (!data)
		return -ENOMEM;
	table = data;
	table->size = cpu_to_le16(stride);
	table->used = cpu_to_le16(total);
	table->total = cpu_to_le16(total);
	table->free_goal = cpu_to_le32(sizeof(*table));
	disk = (void *)((u8 *)data + sizeof(*table));
	list_for_each_entry(entry, &log->dirty_pages, list) {
		u16 index;

		disk->next = RESTART_ENTRY_ALLOCATED_LE;
		disk->target_attr = cpu_to_le32(entry->target_attr);
		disk->transfer_len = cpu_to_le32(entry->transfer_len);
		disk->lcns_follow = cpu_to_le32(entry->lcns_follow);
		disk->vcn = cpu_to_le64(entry->vcn);
		disk->oldest_lsn = cpu_to_le64(entry->oldest_lsn);
		for (index = 0; index < entry->lcns_follow; index++)
			disk->page_lcns[index] =
					cpu_to_le64(entry->page_lcns[index]);
		disk = (void *)((u8 *)disk + stride);
	}
	dumps->dirty_pages.data = data;
	dumps->dirty_pages.len = table_len;
	dumps->dirty_page_entries = total;
	return 0;
}

int ntfs_log_build_checkpoint_dump_payload(u16 operation,
		const struct ntfs_log_payload *dump,
		struct ntfs_log_payload *payload)
{
	struct ntfs_log_rec_hdr *lrh;
	u32 header_len = struct_size(lrh, page_lcns, 1);
	u32 payload_len;
	void *data;

	if (!dump || !dump->data || !dump->len || !payload)
		return -EINVAL;
	if (check_add_overflow(header_len, dump->len, &payload_len) ||
	    check_add_overflow(payload_len, 7U, &payload_len))
		return -EOVERFLOW;
	/* Include padding in the carrier length, not the checkpoint dump size. */
	payload_len &= ~7U;
	data = kvzalloc(payload_len, GFP_NOFS);
	if (!data)
		return -ENOMEM;

	lrh = data;
	lrh->redo_op = cpu_to_le16(operation);
	lrh->undo_op = cpu_to_le16(Noop);
	lrh->redo_off = cpu_to_le16(header_len);
	lrh->redo_len = cpu_to_le16(min_t(u32, dump->len, U16_MAX));
	lrh->undo_off = cpu_to_le16(header_len);
	memcpy((u8 *)data + header_len, dump->data, dump->len);
	payload->data = data;
	payload->len = payload_len;
	return 0;
}

/* append_lock must be held. */
static int ntfs_log_append_checkpoint_dump(struct ntfs_log *log, u16 operation,
		const struct ntfs_log_payload *dump, u64 *lsn)
{
	struct ntfs_log_payload payload = { };
	int err;

	if (!dump->len)
		return 0;
	err = ntfs_log_build_checkpoint_dump_payload(operation, dump, &payload);
	if (err)
		return err;
	err = ntfs_log_append_record(log, NULL,
			sizeof(struct ntfs_log_restart_table),
			le32_to_cpu(LFS_CLIENT_RECORD), 0, payload.data,
			payload.len, false, lsn);
	ntfs_log_free_payload(&payload);
	return err;
}

/* append_lock must be held and all dump buffers must be immutable. */
static int ntfs_log_append_checkpoint_records(struct ntfs_log *log,
		struct ntfs_log_checkpoint_dumps *dumps, u64 *checkpoint_lsn,
		u64 *oldest_lsn)
{
	struct ntfs_log_checkpoint checkpoint;
	int err;

	ntfs_log_build_empty_checkpoint(&checkpoint);
	err = ntfs_log_append_checkpoint_dump(log, OpenAttributeTableDump,
			&dumps->open_attrs, &dumps->open_attrs_lsn);
	if (err)
		return err;
	err = ntfs_log_append_checkpoint_dump(log, AttributeNamesDump,
			&dumps->attr_names, &dumps->attr_names_lsn);
	if (err)
		return err;
	err = ntfs_log_append_checkpoint_dump(log, DirtyPageTableDump,
			&dumps->dirty_pages, &dumps->dirty_pages_lsn);
	if (err)
		return err;
	err = ntfs_log_append_checkpoint_dump(log, TransactionTableDump,
			&dumps->transactions, &dumps->transactions_lsn);
	if (err)
		return err;

	checkpoint.open_attr_table_lsn = cpu_to_le64(dumps->open_attrs_lsn);
	checkpoint.attr_names_lsn = cpu_to_le64(dumps->attr_names_lsn);
	checkpoint.dirty_pages_table_lsn =
			cpu_to_le64(dumps->dirty_pages_lsn);
	checkpoint.transact_table_lsn = cpu_to_le64(dumps->transactions_lsn);
	checkpoint.open_attr_len = cpu_to_le32(dumps->open_attrs.len);
	checkpoint.attr_names_len = cpu_to_le32(dumps->attr_names.len);
	checkpoint.dirty_pages_len = cpu_to_le32(dumps->dirty_pages.len);
	checkpoint.transact_table_len = cpu_to_le32(dumps->transactions.len);
	checkpoint.check_point_start = cpu_to_le64(dumps->checkpoint_start);
	dumps->oldest_lsn = dumps->open_attrs_lsn ? dumps->open_attrs_lsn :
			dumps->attr_names_lsn;
	if (!dumps->oldest_lsn)
		dumps->oldest_lsn = dumps->dirty_pages_lsn;
	if (!dumps->oldest_lsn)
		dumps->oldest_lsn = dumps->transactions_lsn;
	if (dumps->checkpoint_start && (!dumps->oldest_lsn ||
	    ntfs_log_lsn_before_eq(&log->layout, dumps->checkpoint_start,
		    dumps->oldest_lsn)))
		dumps->oldest_lsn = dumps->checkpoint_start;
	err = ntfs_log_append_record(log, NULL, 0,
			le32_to_cpu(LFS_CLIENT_RESTART), 0,
			&checkpoint, sizeof(checkpoint), false, checkpoint_lsn);
	if (err)
		return err;
	*oldest_lsn = dumps->oldest_lsn ? dumps->oldest_lsn :
			*checkpoint_lsn;
	log->pending_checkpoint_lsn = *checkpoint_lsn;
	log->pending_oldest_lsn = *oldest_lsn;
	log->pending_clean = false;
	return 0;
}

static int ntfs_log_checkpoint_space(struct ntfs_log *log,
		const struct ntfs_log_checkpoint_dumps *dumps)
{
	const struct ntfs_log_payload *payloads[] = {
		&dumps->open_attrs, &dumps->attr_names,
		&dumps->dirty_pages, &dumps->transactions,
	};
	u32 page_capacity = log->layout.page_size - log->layout.data_off;
	u32 operation_header = sizeof(struct ntfs_log_rec_hdr) + sizeof(__le64);
	u32 required_pages;
	u32 credits = 0;
	u64 ignored_lsn;
	u64 ignored_next;
	u32 index;

	for (index = 0; index < ARRAY_SIZE(payloads); index++) {
		u32 record_bytes;

		if (!payloads[index]->len)
			continue;
		if (check_add_overflow(operation_header,
			    payloads[index]->len, &record_bytes) ||
		    check_add_overflow(record_bytes, 7U, &record_bytes))
			return -EOVERFLOW;
		record_bytes &= ~7U;
		if (check_add_overflow(record_bytes,
			    (u32)log->layout.record_header_len, &record_bytes) ||
		    check_add_overflow(credits,
			    DIV_ROUND_UP(record_bytes, page_capacity), &credits))
			return -EOVERFLOW;
	}
	if (check_add_overflow((u32)log->layout.record_header_len,
		    (u32)sizeof(struct ntfs_log_checkpoint), &operation_header) ||
	    check_add_overflow(credits,
		    DIV_ROUND_UP(operation_header, page_capacity), &credits) ||
	    check_add_overflow(log->reserved_pages, credits, &required_pages))
		return -EOVERFLOW;
	return ntfs_log_reserve_pages(log, required_pages, &ignored_lsn,
			&ignored_next);
}

static int __ntfs_log_checkpoint(struct ntfs_log *log, bool clean,
		bool allow_stopping, bool *clean_published)
{
	struct ntfs_volume *vol = log->vol;
	struct ntfs_log_checkpoint_dumps dumps = { };
	u64 commit_lsn;
	u64 home_generation;
	u64 writeback_generation;
	u64 writeback_pass_generation;
	u64 oldest_lsn;
	u64 checkpoint_lsn;
	u64 cpu_started;
	bool collect_home = !allow_stopping || clean;
	bool home_clean = false;
	bool publish_clean;
	unsigned int passes = 0;
	int err, mft_err;

	if (clean_published)
		*clean_published = false;
	/* Keep producers out of the checkpoint snapshot and publication. */
	down_write(&log->admission_lock);
	mutex_lock(&log->append_lock);
	if (NVolShutdown(vol)) {
		err = -EIO;
		mutex_unlock(&log->append_lock);
		goto out_checkpoint;
	}
	if (!log->running || log->aborted ||
	    (log->stopping && !allow_stopping)) {
		err = -EROFS;
		mutex_unlock(&log->append_lock);
		goto out_checkpoint;
	}
	mutex_unlock(&log->append_lock);

	/*
	 * Writeback itself records STANDARD_INFORMATION and FILE_NAME changes.
	 * Collect those records without letting each WB_SYNC_ALL callback force its
	 * own log flush.  Once all active writeback transactions have drained,
	 * commit their common tail once, then run writeback again to install the
	 * now-durable metadata at home.  This is the same essential split as a
	 * JBD2 commit followed by checkpoint I/O.
	 *
	 * Drop the admission gate while waiting for writeback: a task holding a
	 * folio may need to begin a transaction before writeback can lock it.
	 * Reacquire the gate before sampling each home generation.  A second
	 * writeback pass can discover another dirty inode, so compare generations
	 * and retry a bounded number of times.  Under sustained writes retain
	 * dirty-page history instead of waiting indefinitely for an empty
	 * checkpoint.
	 */
	writeback_generation = atomic64_read(&log->inode_writeback_generation);
	if (collect_home) {
		WRITE_ONCE(log->checkpoint_collecting, true);
		for (;;) {
			ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT_SYNC, 1);
			commit_lsn = ktime_get_ns();
			cpu_started = ntfs_log_task_cpu_time();
			up_write(&log->admission_lock);
			sync_inodes_sb(vol->sb);
			down_write(&log->admission_lock);
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_CHECKPOINT_WRITEBACK_CPU_NS,
					ntfs_log_task_cpu_time() - cpu_started);
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_CHECKPOINT_INODE_SYNC_NS,
					ktime_get_ns() - commit_lsn);
			down_write(&log->transaction_lock);
			if (NVolShutdown(vol)) {
				err = -EIO;
				goto out_transaction;
			}
			home_generation = atomic64_read(&log->home_generation);
			mutex_lock(&log->append_lock);
			/*
			 * A restart page also seeds last_client_lsn. Only this
			 * writer's pending tail belongs to the collection batch.
			 */
			commit_lsn = log->pending_lsn;
			if (!log->running || log->aborted ||
			    (log->stopping && !allow_stopping)) {
				err = -EROFS;
				mutex_unlock(&log->append_lock);
				goto out_transaction;
			}
			mutex_unlock(&log->append_lock);
			if (commit_lsn) {
				err = ntfs_log_flush_group(log, commit_lsn, false);
				if (err)
					goto out_transaction;
			}
			writeback_pass_generation =
				atomic64_read(&log->home_writeback_generation);
			up_write(&log->transaction_lock);

			ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT_SYNC, 1);
			commit_lsn = ktime_get_ns();
			cpu_started = ntfs_log_task_cpu_time();
			up_write(&log->admission_lock);
			sync_inodes_sb(vol->sb);
			mft_err = filemap_write_and_wait(vol->mft_ino->i_mapping);
			down_write(&log->admission_lock);
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_CHECKPOINT_WRITEBACK_CPU_NS,
					ntfs_log_task_cpu_time() - cpu_started);
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_CHECKPOINT_INODE_SYNC_NS,
					ktime_get_ns() - commit_lsn);
			down_write(&log->transaction_lock);
			/*
			 * sync_inodes_sb() does not report writeback errors.
			 * Shutdown may have prevented bitmap or index pages from
			 * reaching home without changing the generation counters.
			 */
			if (NVolShutdown(vol)) {
				err = -EIO;
				goto out_transaction;
			}
			if (mft_err && mft_err != -EAGAIN && mft_err != -ENOMEM) {
				err = mft_err;
				ntfs_log_abort_writer(log, err);
				goto out_transaction;
			}
			mutex_lock(&log->append_lock);
			home_clean = !mft_err &&
				!mapping_tagged(vol->mft_ino->i_mapping,
						PAGECACHE_TAG_DIRTY) &&
				!mapping_tagged(vol->mft_ino->i_mapping,
						PAGECACHE_TAG_WRITEBACK) &&
				!ntfs_log_has_deferred_free(log) &&
				home_generation ==
				atomic64_read(&log->home_generation) &&
				writeback_pass_generation ==
				atomic64_read(&log->home_writeback_generation);
			mutex_unlock(&log->append_lock);
			if (home_clean || ++passes == 3)
				break;
			up_write(&log->transaction_lock);
			cond_resched();
			mutex_lock(&log->append_lock);
			if (!log->running || log->aborted ||
			    (log->stopping && !allow_stopping)) {
				err = -EROFS;
				mutex_unlock(&log->append_lock);
				goto out_checkpoint;
			}
			mutex_unlock(&log->append_lock);
		}
	} else {
		down_write(&log->transaction_lock);
	}
	WRITE_ONCE(log->checkpoint_collecting, false);
	commit_lsn = ktime_get_ns();
	err = sync_blockdev(vol->sb->s_bdev);
	ntfs_log_recording_account(
			NTFS_LOG_RECORDING_CHECKPOINT_HOME_WRITEBACK_NS,
			ktime_get_ns() - commit_lsn);
	if (NVolShutdown(vol)) {
		err = -EIO;
		goto out_transaction;
	}
	if (!err && collect_home) {
		/* Inode BIO errors are recorded separately from blockdev errors. */
		err = errseq_check(&vol->sb->s_wb_err, log->home_wb_err);
		if (!err && NVolErrors(vol))
			err = -EIO;
	}
	if (err) {
		ntfs_log_abort_writer(log, err);
		goto out_transaction;
	}
	mutex_lock(&log->append_lock);
	if (!log->running || log->aborted ||
	    (log->stopping && !allow_stopping)) {
		err = -EROFS;
		goto out_unlock;
	}

	/* Only a stable home generation permits an empty, reclaiming checkpoint. */
	if (WARN_ON_ONCE(!list_empty(&log->active_handles))) {
		err = -EUCLEAN;
		goto out_abort;
	}
	if (!home_clean) {
		/* transaction_lock excludes open-attribute and dirty-page updates. */
		err = ntfs_log_build_open_attr_dumps(log, &dumps);
		if (!err)
			err = ntfs_log_build_dirty_page_dump(log, &dumps);
		if (err)
			goto out_abort;
	}
	err = ntfs_log_checkpoint_space(log, &dumps);
	if (err == -ENOSPC)
		goto out_unlock;
	if (err)
		goto out_abort;
	err = ntfs_log_append_checkpoint_records(log, &dumps, &checkpoint_lsn,
			&oldest_lsn);
	if (err)
		goto out_abort;

	/*
	 * sync_blockdev() above submitted and waited for all home writes, but did
	 * not need a separate device-cache flush.  The checkpoint record batch's
	 * global cache flush makes both those home writes and this checkpoint
	 * durable before publish_restart() can expose it.  Keep the previous
	 * restart copy intact until its replacement points at that durable
	 * checkpoint.  Do not delay this batch.
	 */
	publish_clean = clean && home_clean &&
		writeback_generation ==
			atomic64_read(&log->inode_writeback_generation);
	log->pending_clean = publish_clean;
	mutex_unlock(&log->append_lock);
	err = ntfs_log_flush_group(log, checkpoint_lsn, false);
	mutex_lock(&log->append_lock);
	if (err)
		goto out_abort;
	if (clean_published)
		*clean_published = publish_clean;

	if (home_clean) {
		/* The exclusive transaction lock excludes open-attribute writers. */
		lockdep_assert_held_write(&log->transaction_lock);
		ntfs_log_clear_open_attrs(log);
		ntfs_log_clear_dirty_pages(log);
		log->growth_credits = 0;
	}
	log->checkpointed_home_generation =
			atomic64_read(&log->home_generation);
	log->checkpointed_generation_valid = true;
	if (collect_home && writeback_generation ==
			atomic64_read(&log->inode_writeback_generation))
		log->checkpointed_inode_writeback_generation =
				writeback_generation;
	log->checkpoint_generation++;
	NVolClearLogFileEmpty(vol);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT, 1);
	err = 0;
	goto out_unlock;

out_abort:
	ntfs_log_abort_writer(log, err);
out_unlock:
	mutex_unlock(&log->append_lock);
out_transaction:
	WRITE_ONCE(log->checkpoint_collecting, false);
	up_write(&log->transaction_lock);
out_checkpoint:
	WRITE_ONCE(log->checkpoint_collecting, false);
	up_write(&log->admission_lock);
	ntfs_log_free_checkpoint_dumps(&dumps);
	return err;
}

/*
 * An explicit sync after an unchanged generation needs neither another set of
 * checkpoint records nor a restart-page barrier.  Both locks close the race
 * with foreground and checkpoint-writeback transactions while the generation
 * and pending tail are sampled.
 */
static bool ntfs_log_skip_unchanged_checkpoint(struct ntfs_log *log)
{
	bool skip;

	down_write(&log->admission_lock);
	down_write(&log->transaction_lock);
	mutex_lock(&log->append_lock);
	skip = log->running && !log->aborted && !log->stopping &&
		!NVolErrors(log->vol) &&
		log->checkpointed_generation_valid && !log->pending_lsn &&
		!log->pending_checkpoint_lsn &&
		!ntfs_log_has_deferred_free(log) &&
		list_empty(&log->active_handles) &&
		atomic64_read(&log->inode_writeback_generation) ==
			log->checkpointed_inode_writeback_generation &&
		atomic64_read(&log->home_generation) ==
			log->checkpointed_home_generation;
	mutex_unlock(&log->append_lock);
	up_write(&log->transaction_lock);
	up_write(&log->admission_lock);
	return skip;
}

static int ntfs_log_checkpoint_reason(struct ntfs_volume *vol, bool clean,
		enum ntfs_log_recording_stat reason)
{
	struct ntfs_log *log;
	u64 checkpoint_generation;
	unsigned int kind;
	unsigned int passes = 0;
	bool skip = false;
	int err;

	if (!vol)
		return -EINVAL;
	down_read(&vol->journal_lock);
	log = vol->journal;
	if (!log) {
		err = -EINVAL;
		up_read(&vol->journal_lock);
		return err;
	}
	mutex_lock(&log->append_lock);
	if (log->stopping) {
		mutex_unlock(&log->append_lock);
		up_read(&vol->journal_lock);
		return -EROFS;
	}
	checkpoint_generation = log->checkpoint_generation;
	mutex_unlock(&log->append_lock);
	mutex_lock(&log->checkpoint_lock);
	up_read(&vol->journal_lock);
	if (!clean && reason == NTFS_LOG_RECORDING_SPACE_CHECKPOINT) {
		mutex_lock(&log->append_lock);
		skip = log->running && !log->aborted && !log->stopping &&
			!NVolShutdown(vol) && !NVolErrors(vol) &&
			!ntfs_log_has_deferred_free(log) &&
			log->checkpoint_generation != checkpoint_generation;
		mutex_unlock(&log->append_lock);
	}
	if (!clean && reason == NTFS_LOG_RECORDING_EXPLICIT_CHECKPOINT &&
	    ntfs_log_skip_unchanged_checkpoint(log)) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_EXPLICIT_CHECKPOINT_SKIP, 1);
		skip = true;
	}
	if (skip) {
		ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT_SKIP, 1);
		ntfs_log_recording_account(reason, 1);
		mutex_unlock(&log->checkpoint_lock);
		return 0;
	}
	for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++) {
		err = ntfs_log_drain_deferred_queue(log, kind);
		if (err) {
			mutex_unlock(&log->checkpoint_lock);
			return err;
		}
	}
	for (;;) {
		err = __ntfs_log_checkpoint(log, clean, false, NULL);
		if (err || reason != NTFS_LOG_RECORDING_EXPLICIT_CHECKPOINT ||
		    atomic64_read(&log->inode_writeback_generation) ==
				log->checkpointed_inode_writeback_generation)
			break;
		/* Reclaim made space for inode metadata deferred during collection. */
		if (++passes == 3) {
			err = -EAGAIN;
			break;
		}
		cond_resched();
	}
	mutex_unlock(&log->checkpoint_lock);
	if (!err)
		ntfs_log_recording_account(reason, 1);
	return err;
}

int ntfs_log_checkpoint(struct ntfs_volume *vol, bool clean)
{
	return ntfs_log_checkpoint_reason(vol, clean,
			NTFS_LOG_RECORDING_EXPLICIT_CHECKPOINT);
}

void ntfs_log_inode_writeback_deferred(struct ntfs_volume *vol)
{
	down_read(&vol->journal_lock);
	if (vol->journal) {
		atomic64_inc(&vol->journal->inode_writeback_generation);
		atomic64_inc(&vol->journal->home_writeback_generation);
	}
	up_read(&vol->journal_lock);
}

void ntfs_log_end_inode_writeback(struct ntfs_log *log, bool home_deferred)
{
	atomic64_inc(&log->inode_writeback_generation);
	if (home_deferred)
		atomic64_inc(&log->home_writeback_generation);
	up_read(&log->transaction_lock);
}

static int ntfs_log_pin_reclaim(struct ntfs_volume *vol)
{
	struct super_block *sb;

	if (!vol || !vol->sb)
		return -EINVAL;
	sb = vol->sb;
	for (;;) {
		down_read(&sb->s_umount);
		if (READ_ONCE(sb->s_writers.frozen) < SB_FREEZE_PAGEFAULT)
			break;
		up_read(&sb->s_umount);
		/* Thaw needs s_umount exclusive. Wait without the read pin. */
		wait_var_event(&sb->s_writers.frozen,
				READ_ONCE(sb->s_writers.frozen) == SB_UNFROZEN);
	}
	return 0;
}

int ntfs_log_wait_ready(struct ntfs_volume *vol)
{
	struct ntfs_log *log;
	int err;

	err = ntfs_log_pin_reclaim(vol);
	if (err)
		return err;
	down_read(&vol->journal_lock);
	log = vol->journal;
	if (!log) {
		err = -EROFS;
		goto out_journal;
	}
	down_read(&log->admission_lock);
	down_read(&log->transaction_lock);
	mutex_lock(&log->append_lock);
	if (NVolShutdown(vol))
		err = -EIO;
	else if (!log->running || log->aborted || log->stopping)
		err = -EROFS;
	else
		err = 0;
	mutex_unlock(&log->append_lock);
	up_read(&log->transaction_lock);
	up_read(&log->admission_lock);
out_journal:
	up_read(&vol->journal_lock);
	up_read(&vol->sb->s_umount);
	return err;
}

int ntfs_log_reclaim_locked(struct ntfs_volume *vol)
{
	return ntfs_log_checkpoint_reason(vol, false,
			NTFS_LOG_RECORDING_SPACE_CHECKPOINT);
}

int ntfs_log_reclaim(struct ntfs_volume *vol)
{
	int err;

	err = ntfs_log_pin_reclaim(vol);
	if (err)
		return err;
	err = ntfs_log_reclaim_locked(vol);
	up_read(&vol->sb->s_umount);
	return err;
}

int ntfs_log_mount_checkpoint(struct ntfs_volume *vol)
{
	const enum ntfs_log_recording_stat combined_stat =
		NTFS_LOG_RECORDING_MOUNT_DIRTY_COMBINED_FLUSH;
	int err;

	err = ntfs_log_checkpoint_reason(vol, false,
					 NTFS_LOG_RECORDING_MOUNT_CHECKPOINT);
	if (!err)
		ntfs_log_recording_account(combined_stat, 1);
	return err;
}

#define NTFS_LOG_BACKGROUND_CHECKPOINT_DELAY	(30 * HZ)

static int ntfs_log_background_checkpoint(struct ntfs_log *log)
{
	struct ntfs_log_checkpoint_dumps dumps = { };
	u64 checkpoint_lsn = 0;
	u64 oldest_lsn = 0;
	int err;

	mutex_lock(&log->checkpoint_lock);
	mutex_lock(&log->open_attr_lock);
	mutex_lock(&log->append_lock);
	if (!log->running || log->aborted || log->stopping) {
		err = -EROFS;
		goto out_unlock_append;
	}
	if (log->last_client_lsn == log->checkpoint_lsn && !log->pending_lsn) {
		err = -EALREADY;
		goto out_unlock_append;
	}
	err = ntfs_log_build_open_attr_dumps(log, &dumps);
	if (err)
		goto out_unlock_append;
	err = ntfs_log_build_transaction_dump(log, &dumps);
	if (err)
		goto out_unlock_append;
	err = ntfs_log_build_dirty_page_dump(log, &dumps);
	if (err)
		goto out_unlock_append;
	err = ntfs_log_checkpoint_space(log, &dumps);
	if (err)
		goto out_unlock_append;
	err = ntfs_log_append_checkpoint_records(log, &dumps,
			&checkpoint_lsn, &oldest_lsn);
	if (err)
		goto out_unlock_append;
	mutex_unlock(&log->append_lock);
	mutex_unlock(&log->open_attr_lock);

	err = ntfs_log_flush_group(log, checkpoint_lsn, false);
	if (err)
		goto out_checkpoint;
	NVolClearLogFileEmpty(log->vol);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_BACKGROUND_CHECKPOINT, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT_OPEN_ATTR,
			dumps.open_attr_entries);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT_DIRTY_PAGE,
			dumps.dirty_page_entries);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT_TRANSACTION,
			dumps.transaction_entries);
	goto out_checkpoint;

out_unlock_append:
	mutex_unlock(&log->append_lock);
	mutex_unlock(&log->open_attr_lock);
out_checkpoint:
	mutex_unlock(&log->checkpoint_lock);
	ntfs_log_free_checkpoint_dumps(&dumps);
	return err;
}

static void ntfs_log_checkpoint_work(struct work_struct *work)
{
	struct ntfs_log *log = container_of(to_delayed_work(work),
			struct ntfs_log, checkpoint_work);
	int err;

	err = ntfs_log_background_checkpoint(log);
	if (err == -ENOSPC || err == -E2BIG || err == -ENOMEM)
		ntfs_log_recording_account(NTFS_LOG_RECORDING_CHECKPOINT_SKIP, 1);
	if (READ_ONCE(log->running) && !READ_ONCE(log->aborted) &&
	    !READ_ONCE(log->stopping))
		queue_delayed_work(system_long_wq, &log->checkpoint_work,
				NTFS_LOG_BACKGROUND_CHECKPOINT_DELAY);
}

static void ntfs_log_reclaim_work(struct work_struct *work)
{
	struct ntfs_log *log = container_of(to_delayed_work(work),
			struct ntfs_log, reclaim_work);
	struct ntfs_volume *vol = log->vol;
	int err;

	/* Unmount cancels this work under s_umount. It must not wait for us. */
	if (!down_read_trylock(&vol->sb->s_umount)) {
		mutex_lock(&log->append_lock);
		if (log->running && !log->aborted && !log->stopping)
			queue_delayed_work(system_long_wq, &log->reclaim_work, HZ);
		mutex_unlock(&log->append_lock);
		return;
	}
	err = ntfs_log_checkpoint_reason(vol, false,
			NTFS_LOG_RECORDING_SPACE_CHECKPOINT);
	up_read(&vol->sb->s_umount);
	if (err && err != -EROFS)
		ntfs_error(vol->sb,
				"Journal space-pressure checkpoint failed (error %d).",
				err);
}

static bool ntfs_log_operation_has_undo(u16 operation)
{
	return operation != Noop && operation != CompensationLogRecord;
}

static void ntfs_log_free_undo_entry(struct ntfs_log_undo_entry *entry)
{
	list_del_init(&entry->list);
	kfree(entry);
}

static void ntfs_log_free_home_undo_entry(struct ntfs_log_home_undo *entry)
{
	list_del_init(&entry->list);
	entry->release(entry->data);
	if (!entry->embedded)
		kfree(entry);
}

/* append_lock protects the reservation through active, pending and ready. */
static void ntfs_log_unreserve_deferred(struct ntfs_log *log,
		struct ntfs_log_home_undo *entry)
{
	struct ntfs_log_deferred_queue *queue;

	if (!entry->deferred)
		return;
	queue = &log->deferred[entry->deferred_kind];
	if (WARN_ON_ONCE(!queue->reserved ||
	    queue->units < entry->deferred_units ||
	    queue->bytes < entry->deferred_bytes)) {
		ntfs_log_abort_writer(log, -EUCLEAN);
		return;
	}
	queue->reserved--;
	queue->units -= entry->deferred_units;
	queue->bytes -= entry->deferred_bytes;
	entry->deferred = false;
}

/* CommitTransaction and this handoff share append_lock with batch sealing. */
static void ntfs_log_defer_handle_frees(struct ntfs_log_handle *handle,
		unsigned int slot)
{
	struct ntfs_log_home_undo *entry, *next;
	struct ntfs_log *log = handle->log;

	list_for_each_entry_safe(entry, next, &handle->home_undo_entries, list) {
		struct ntfs_log_deferred_queue *queue;

		if (!entry->deferred)
			continue;
		queue = &log->deferred[entry->deferred_kind];
		entry->deferred_slot = slot;
		list_move_tail(&entry->list, &queue->pending);
		queue->queued++;
		queue->queued_units += entry->deferred_units;
		ntfs_log_recording_account(NTFS_LOG_RECORDING_DEFERRED_FREE, 1);
	}
}

/* Only slots in the marker just made durable may release their reservations. */
static void ntfs_log_promote_deferred(struct ntfs_log *log,
		const unsigned long *batch_retired)
{
	unsigned int kind;

	for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++) {
		struct ntfs_log_deferred_queue *queue = &log->deferred[kind];
		struct ntfs_log_home_undo *entry, *next;
		bool ready = false;

		list_for_each_entry_safe(entry, next, &queue->pending, list) {
			if (!test_bit(entry->deferred_slot, batch_retired))
				continue;
			list_move_tail(&entry->list, &queue->ready);
			ready = true;
		}
		if (ready)
			queue_work(queue->workqueue, &queue->work);
	}
}

static void ntfs_log_deferred_work(struct work_struct *work)
{
	struct ntfs_log_deferred_queue *queue =
		container_of(work, struct ntfs_log_deferred_queue, work);
	struct ntfs_log *log = queue->log;

	for (;;) {
		struct ntfs_log_home_undo *entry;
		bool apply;
		int err = 0;

		mutex_lock(&queue->free_count_lock);
		mutex_lock(&log->append_lock);
		if (list_empty(&queue->ready)) {
			mutex_unlock(&log->append_lock);
			mutex_unlock(&queue->free_count_lock);
			break;
		}
		entry = list_first_entry(&queue->ready,
				struct ntfs_log_home_undo, list);
		list_del_init(&entry->list);
		apply = log->running && !log->aborted &&
			!NVolShutdown(log->vol);
		mutex_unlock(&log->append_lock);

		if (apply)
			err = entry->commit(entry->data);
		mutex_lock(&log->append_lock);
		if (err) {
			ntfs_error(log->vol->sb,
				   "Failed to apply a durable deferred free (error %d).",
				   err);
			ntfs_log_abort_writer(log, err);
		} else if (apply) {
			atomic64_inc(&log->home_generation);
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_DEFERRED_RELEASE, 1);
		}
		if (WARN_ON_ONCE(!queue->queued ||
				 queue->queued_units < entry->deferred_units)) {
			ntfs_log_abort_writer(log, -EUCLEAN);
		} else {
			queue->queued--;
			queue->queued_units -= entry->deferred_units;
		}
		ntfs_log_unreserve_deferred(log, entry);
		mutex_unlock(&log->append_lock);
		mutex_unlock(&queue->free_count_lock);
		ntfs_log_free_home_undo_entry(entry);
	}
}

static int ntfs_log_restore_home_metadata(struct ntfs_log_handle *handle)
{
	struct ntfs_log_home_undo *entry;
	int err;

	list_for_each_entry_reverse(entry, &handle->home_undo_entries, list) {
		err = entry->restore(entry->data);
		if (err)
			return err;
	}
	return 0;
}

static int ntfs_log_commit_home_metadata(struct ntfs_log_handle *handle)
{
	struct ntfs_log_home_undo *entry;
	int err;

	list_for_each_entry(entry, &handle->home_undo_entries, list) {
		if (!entry->commit)
			continue;
		err = entry->commit(entry->data);
		if (err)
			return err;
	}
	return 0;
}

static int ntfs_log_abort_home_metadata(struct ntfs_log_handle *handle)
{
	struct ntfs_log_home_undo *entry;
	int err;

	list_for_each_entry_reverse(entry, &handle->home_undo_entries, list) {
		if (!entry->abort)
			continue;
		err = entry->abort(entry->data);
		if (err)
			return err;
	}
	return 0;
}

static void ntfs_log_free_handle_entries(struct list_head *home_undo_entries,
		struct list_head *undo_entries)
{
	struct ntfs_log_home_undo *home_entry;
	struct ntfs_log_home_undo *home_next;
	struct ntfs_log_undo_entry *entry;
	struct ntfs_log_undo_entry *next;

	list_for_each_entry_safe(home_entry, home_next,
			home_undo_entries, list)
		ntfs_log_free_home_undo_entry(home_entry);
	list_for_each_entry_safe(entry, next, undo_entries, list)
		ntfs_log_free_undo_entry(entry);
}

static void ntfs_log_free_handle(struct ntfs_log_handle *handle)
{
	LIST_HEAD(home_undo_entries);
	LIST_HEAD(undo_entries);

	list_splice_init(&handle->home_undo_entries, &home_undo_entries);
	list_splice_init(&handle->undo_entries, &undo_entries);
	ntfs_log_free_handle_entries(&home_undo_entries, &undo_entries);
	kfree(handle);
}

static struct ntfs_log_undo_entry *ntfs_log_save_undo(
		const struct ntfs_log_operation_desc *operation, u64 undo_next_lsn)
{
	struct ntfs_log_undo_entry *entry;
	size_t size;
	void *undo_data;

	if (check_mul_overflow((size_t)operation->lcns_follow, sizeof(u64),
			&size) ||
	    check_add_overflow(sizeof(*entry), size, &size) ||
	    check_add_overflow(size, (size_t)operation->undo_len, &size))
		return ERR_PTR(-EOVERFLOW);

	entry = kzalloc(size, GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&entry->list);
	entry->operation = *operation;
	entry->undo_next_lsn = undo_next_lsn;
	if (operation->lcns_follow) {
		memcpy(entry->page_lcns, operation->page_lcns,
				operation->lcns_follow * sizeof(u64));
		entry->operation.page_lcns = entry->page_lcns;
	}
	undo_data = (u8 *)entry->page_lcns +
			operation->lcns_follow * sizeof(u64);
	if (operation->undo_len) {
		memcpy(undo_data, operation->undo_data, operation->undo_len);
		entry->operation.undo_data = undo_data;
	}
	entry->operation.redo_data = NULL;
	return entry;
}

static int ntfs_log_transaction_id_index(u32 id);

static bool ntfs_log_same_overwrite_target(
		const struct ntfs_log_operation_desc *first,
		const struct ntfs_log_operation_desc *next)
{
	bool bitmap = next->redo_op == SetBitsInNonresidentBitMap ||
		next->redo_op == ClearBitsInNonresidentBitMap;

	if (next->redo_op != next->undo_op &&
	    !(bitmap && ((next->redo_op == SetBitsInNonresidentBitMap &&
		next->undo_op == ClearBitsInNonresidentBitMap) ||
	       (next->redo_op == ClearBitsInNonresidentBitMap &&
		next->undo_op == SetBitsInNonresidentBitMap))))
		return false;
	switch (next->redo_op) {
	case UpdateResidentValue:
	case UpdateNonresidentValue:
	case UpdateMappingPairs:
	case SetNewAttributeSizes:
	case SetIndexEntryVcnRoot:
	case SetIndexEntryVcnAllocation:
	case UpdateFileNameRoot:
	case UpdateFileNameAllocation:
	case UpdateRecordDataRoot:
	case UpdateRecordDataAllocation:
	case UpdateRelativeDataIndex:
	case UpdateRelativeDataAllocation:
	case SetBitsInNonresidentBitMap:
	case ClearBitsInNonresidentBitMap:
		break;
	default:
		return false;
	}
	if (first->redo_op != next->redo_op || first->undo_op != next->undo_op ||
	    first->target_attr != next->target_attr ||
	    first->record_off != next->record_off ||
	    first->attr_off != next->attr_off ||
	    first->cluster_off != next->cluster_off ||
	    first->target_vcn != next->target_vcn ||
	    first->lcns_follow != next->lcns_follow ||
	    first->redo_len != next->redo_len ||
	    !next->redo_len || !next->redo_data)
		return false;
	if (first->lcns_follow &&
	    memcmp(first->page_lcns, next->page_lcns,
		    first->lcns_follow * sizeof(*first->page_lcns)))
		return false;
	/* Bitmap redo describes a mutation, not a replacement byte image. */
	return !bitmap || (first->undo_len == next->undo_len &&
		first->undo_data && next->undo_data &&
		!memcmp(first->undo_data, next->undo_data,
			first->undo_len));
}

/*
 * Return a hash for the containing home-metadata unit, not for the exact log
 * operation.  Every operation on that unit replaces the hash tail and thus
 * acts as an ordering barrier for an earlier, otherwise mergeable overwrite.
 */
static u32 ntfs_log_aggregate_unit_hash(
		const struct ntfs_log_operation_desc *operation)
{
	u64 value;
	u32 hash = 2166136261U;

#define NTFS_LOG_AGGREGATE_MIX(v) do { \
	value = (u64)(v); \
	hash = (hash ^ lower_32_bits(value)) * 16777619U; \
	hash = (hash ^ upper_32_bits(value)) * 16777619U; \
} while (0)
	NTFS_LOG_AGGREGATE_MIX(operation->target_attr);
	NTFS_LOG_AGGREGATE_MIX(operation->cluster_off);
	NTFS_LOG_AGGREGATE_MIX(operation->target_vcn);
	/* The first physical LCN disambiguates a reused open-attribute slot. */
	if (operation->lcns_follow)
		NTFS_LOG_AGGREGATE_MIX(operation->page_lcns[0]);
#undef NTFS_LOG_AGGREGATE_MIX
	return hash & (NTFS_LOG_AGGREGATE_HASH_SIZE - 1);
}

static bool ntfs_log_same_aggregate_unit(
		const struct ntfs_log_operation_desc *first,
		const struct ntfs_log_operation_desc *next)
{
	/*
	 * target_vcn plus cluster_off identifies the first 512-byte home block.
	 * Conservatively treat different-length records beginning there as one
	 * unit. This prevents a full-image operation from being reordered with a
	 * field update in the same MFT/INDX record or bitmap page.
	 */
	return first->target_attr == next->target_attr &&
		first->target_vcn == next->target_vcn &&
		first->cluster_off == next->cluster_off &&
		first->lcns_follow && next->lcns_follow &&
		first->page_lcns[0] == next->page_lcns[0];
}

static bool ntfs_log_aggregate_trackable(
		const struct ntfs_log_operation_desc *operation)
{
	return operation && operation->target_attr && operation->lcns_follow &&
		operation->page_lcns;
}

static struct ntfs_log_aggregate_record *
ntfs_log_aggregate_alloc(const struct ntfs_log_operation_desc *operation,
		u32 client_data_len, u32 record_header_len, u32 page_capacity)
{
	struct ntfs_log_aggregate_record *record;
	bool bitmap;
	bool initializer;
	bool mergeable;
	size_t bitmap_len = 0;
	size_t image_len = 0;
	size_t size;
	void *bitmap_data;

	if (!ntfs_log_aggregate_trackable(operation))
		return NULL;
	/* Multi-page records remain tracked as ordering barriers. */
	mergeable = ntfs_log_same_overwrite_target(operation, operation);
	if (record_header_len > U32_MAX - client_data_len ||
	    record_header_len + client_data_len > page_capacity) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_FALLBACK, 1);
		mergeable = false;
	}
	/* Bitmap equality needs a private copy of its range descriptor. */
	bitmap = mergeable &&
		(operation->redo_op == SetBitsInNonresidentBitMap ||
		 operation->redo_op == ClearBitsInNonresidentBitMap);
	if (bitmap)
		bitmap_len = operation->undo_len;
	initializer = operation->redo_op == InitializeFileRecordSegment &&
		operation->undo_op == DeallocateFileRecordSegment &&
		operation->redo_data && operation->redo_len;
	if (initializer)
		image_len = operation->redo_len;
	if (check_mul_overflow((size_t)operation->lcns_follow, sizeof(u64),
			&size) ||
	    check_add_overflow(sizeof(*record), size, &size) ||
	    check_add_overflow(size, bitmap_len, &size) ||
	    check_add_overflow(size, image_len, &size))
		return NULL;
	record = kzalloc(size, GFP_NOFS);
	if (!record)
		return NULL;
	INIT_LIST_HEAD(&record->batch_list);
	INIT_LIST_HEAD(&record->handle_list);
	INIT_HLIST_NODE(&record->hash_node);
	record->operation = *operation;
	record->allocation_size = size;
	record->mergeable = mergeable;
	if (operation->lcns_follow) {
		memcpy(record->page_lcns, operation->page_lcns,
				operation->lcns_follow * sizeof(u64));
		record->operation.page_lcns = record->page_lcns;
	}
	/* redo_data is only a non-NULL eligibility flag after append. */
	record->operation.redo_data = record;
	if (bitmap_len) {
		bitmap_data = (u8 *)record->page_lcns +
				operation->lcns_follow * sizeof(u64);
		memcpy(bitmap_data, operation->undo_data, bitmap_len);
		record->operation.undo_data = bitmap_data;
	} else {
		record->operation.undo_data = NULL;
	}
	if (image_len) {
		record->redo_image = (u8 *)record->page_lcns +
				operation->lcns_follow * sizeof(u64) + bitmap_len;
		memcpy(record->redo_image, operation->redo_data, image_len);
	}
	return record;
}

/* append_lock must be held. */
static void ntfs_log_aggregate_add(struct ntfs_log *log,
		struct ntfs_log_handle *handle,
		struct ntfs_log_aggregate_record *record, u64 lsn)
{
	struct ntfs_log_aggregate_record *tail;
	struct hlist_head *bucket;
	u32 hash;

	if (!record)
		return;
	if (!log->aggregate_hash) {
		kfree(record);
		return;
	}
	/*
	 * Aggregation is an optional optimization.  If its bounded shadow-image
	 * budget is exhausted, discard all mutable merge state.  Keeping an old
	 * hash tail while dropping this intervening operation could otherwise
	 * allow a later overwrite to be folded across an ordering barrier.
	 */
	if (log->aggregate_bytes >= log->aggregate_limit ||
	    record->allocation_size >
			log->aggregate_limit - log->aggregate_bytes) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_FALLBACK, 1);
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_MEMORY_RESET, 1);
		ntfs_log_aggregate_reset(log);
		kfree(record);
		return;
	}
	hash = ntfs_log_aggregate_unit_hash(&record->operation);
	bucket = &log->aggregate_hash[hash];
	hlist_for_each_entry(tail, bucket, hash_node) {
		if (ntfs_log_same_aggregate_unit(&tail->operation,
				&record->operation)) {
			hlist_del_init(&tail->hash_node);
			break;
		}
	}
	record->lsn = lsn;
	record->transaction_id = handle->transaction_id;
	hlist_add_head(&record->hash_node, bucket);
	list_add_tail(&record->batch_list, &log->aggregate_records);
	list_add_tail(&record->handle_list, &handle->aggregate_records);
	log->aggregate_bytes += record->allocation_size;
	ntfs_log_recording_account(NTFS_LOG_RECORDING_AGGREGATE_TOUCH, 1);
}

struct ntfs_log_record_location {
	void *page;
	u32 record_off;
	bool protected;
};

/* append_lock must be held. */
static int ntfs_log_find_mutable_record(struct ntfs_log *log, u64 lsn,
		struct ntfs_log_record_location *location)
{
	struct ntfs_log_sealed_page *page;
	u64 byte_off;
	u64 page_off;
	int err;

	err = ntfs_lsn_to_byte_off(&log->layout, lsn, &byte_off);
	if (err)
		return err;
	page_off = byte_off & ~((u64)log->layout.page_mask);
	location->record_off = byte_off & log->layout.page_mask;
	if (log->pending_page && log->pending_page_off == page_off) {
		location->page = log->pending_page;
		location->protected = false;
		return 0;
	}
	list_for_each_entry(page, &log->sealed_pages, list) {
		if (page->file_off == page_off) {
			location->page = page->data;
			location->protected = true;
			return 0;
		}
	}
	return -ENOENT;
}

static struct ntfs_log_rec_hdr *ntfs_log_aggregate_record_header(
		struct ntfs_log *log, void *page, u32 record_off,
		const struct ntfs_log_aggregate_record *record)
{
	struct ntfs_lfs_record_hdr *lfs;
	struct ntfs_log_rec_hdr *lrh;
	u32 operation_header_len;
	u32 client_len;
	u16 index;
	u16 redo_off;

	if (record_off < log->layout.data_off ||
	    record_off > log->layout.page_size - sizeof(*lfs))
		return NULL;
	lfs = (void *)((u8 *)page + record_off);
	client_len = le32_to_cpu(lfs->client_data_len);
	if (le64_to_cpu(lfs->this_lsn) != record->lsn ||
	    le32_to_cpu(lfs->transact_id) != record->transaction_id ||
	    lfs->record_type != LFS_CLIENT_RECORD ||
	    (lfs->flags & LOG_RECORD_MULTI_PAGE) ||
	    client_len < sizeof(*lrh) ||
	    client_len > log->layout.page_size - record_off - sizeof(*lfs))
		return NULL;
	lrh = (void *)((u8 *)lfs + sizeof(*lfs));
	operation_header_len = struct_size(lrh, page_lcns,
			max_t(u16, 1, record->operation.lcns_follow));
	redo_off = le16_to_cpu(lrh->redo_off);
	if (le16_to_cpu(lrh->redo_op) != record->operation.redo_op ||
	    le16_to_cpu(lrh->undo_op) != record->operation.undo_op ||
	    le16_to_cpu(lrh->redo_len) != record->operation.redo_len ||
	    le16_to_cpu(lrh->target_attr) != record->operation.target_attr ||
	    le16_to_cpu(lrh->record_off) != record->operation.record_off ||
	    le16_to_cpu(lrh->attr_off) != record->operation.attr_off ||
	    le16_to_cpu(lrh->cluster_off) != record->operation.cluster_off ||
	    le64_to_cpu(lrh->target_vcn) != record->operation.target_vcn ||
	    le16_to_cpu(lrh->lcns_follow) != record->operation.lcns_follow ||
	    operation_header_len > client_len || redo_off > client_len ||
	    record->operation.redo_len > client_len - redo_off)
		return NULL;
	for (index = 0; index < record->operation.lcns_follow; index++)
		if (le64_to_cpu(lrh->page_lcns[index]) !=
		    record->operation.page_lcns[index])
			return NULL;
	return lrh;
}

static int ntfs_log_aggregate_prepare_page(struct ntfs_log *log,
		const struct ntfs_log_record_location *location, void **copy)
{
	*copy = ntfs_log_kvmemdup(location->page, log->layout.page_size,
			GFP_NOFS);
	if (!*copy)
		return -ENOMEM;
	if (location->protected &&
	    post_read_mst_fixup((struct ntfs_record *)*copy,
			log->layout.page_size)) {
		kvfree(*copy);
		*copy = NULL;
		return -EIO;
	}
	return 0;
}

static bool ntfs_log_mft_record_has_boundary(const struct mft_record *mrec,
		u32 record_size, u16 wanted)
{
	u32 offset;
	u32 used;

	if (!mrec || mrec->magic != magic_FILE)
		return false;
	used = le32_to_cpu(mrec->bytes_in_use);
	offset = le16_to_cpu(mrec->attrs_offset);
	if (!IS_ALIGNED(offset, 8) || used > record_size || offset > used ||
	    wanted < offset || wanted > used || !IS_ALIGNED(wanted, 8))
		return false;
	for (;;) {
		const struct attr_record *attr =
				(const void *)((const u8 *)mrec + offset);
		u32 length;

		if (offset == wanted)
			return true;
		/* AT_END is intentionally truncated to its four-byte type. */
		if (offset > used || sizeof(attr->type) > used - offset)
			return false;
		if (attr->type == AT_END)
			return false;
		if (sizeof(attr->type) + sizeof(attr->length) > used - offset)
			return false;
		length = le32_to_cpu(attr->length);
		if (length < offsetof(struct attr_record, data) ||
		    !IS_ALIGNED(length, 8) || length > used - offset)
			return false;
		offset += length;
	}
}

/*
 * Fold attributes created immediately after a brand-new MFT initializer into
 * that initializer's full after-image.  Its DeallocateFileRecordSegment undo
 * already covers every folded attribute.  Requiring the same handle and the
 * global mutable tail avoids reordering any unrelated metadata dependency.
 */
static bool ntfs_log_aggregate_fold_mft_create(struct ntfs_log *log,
		struct ntfs_log_handle *handle,
		const struct ntfs_log_operation_desc *operation,
		u32 client_data_len, u64 *lsn_out)
{
	struct ntfs_log_aggregate_record *record;
	struct ntfs_log_record_location location;
	struct ntfs_log_rec_hdr *lrh;
	struct ntfs_lfs_record_hdr *lfs;
	struct ntfs_record_page_hdr *page;
	struct mft_record *mrec;
	const struct attr_record *new_attr;
	void *page_copy = NULL;
	void *image_copy = NULL;
	u32 attr_len;
	u32 allocated;
	u32 used;
	u16 redo_off;
	u16 instance;
	u32 hash;

	if (!operation || operation->redo_op != CreateAttribute ||
	    operation->undo_op != DeleteAttribute || !operation->redo_data ||
	    operation->redo_len < sizeof(struct attr_record) ||
	    !operation->target_attr || !operation->lcns_follow ||
	    !operation->page_lcns || !log->aggregate_hash)
		return false;
	ntfs_log_recording_account(
			NTFS_LOG_RECORDING_AGGREGATE_MFT_FOLD_ATTEMPT, 1);
	hash = ntfs_log_aggregate_unit_hash(operation);
	hlist_for_each_entry(record, &log->aggregate_hash[hash], hash_node) {
		if (ntfs_log_same_aggregate_unit(&record->operation, operation))
			goto found;
	}
	ntfs_log_recording_account(
			NTFS_LOG_RECORDING_AGGREGATE_MFT_NO_ANCHOR, 1);
	return false;

found:
	if (record->transaction_id != handle->transaction_id ||
	    record->committed || !record->redo_image ||
	    record->operation.redo_op != InitializeFileRecordSegment ||
	    record->operation.undo_op != DeallocateFileRecordSegment ||
	    record->operation.redo_len != log->vol->mft_record_size) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_MFT_NO_ANCHOR, 1);
		return false;
	}
	if (record->lsn != handle->prev_lsn ||
	    record->lsn != log->last_client_lsn) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_MFT_NOT_TAIL, 1);
		return false;
	}
	if (ntfs_log_find_mutable_record(log, record->lsn, &location) ||
	    location.protected || location.page != log->pending_page) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_MFT_IMMUTABLE, 1);
		return false;
	}

	image_copy = kmemdup(record->redo_image,
			record->operation.redo_len, GFP_NOFS);
	if (!image_copy)
		return false;
	mrec = image_copy;
	new_attr = operation->redo_data;
	attr_len = le32_to_cpu(new_attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = min_t(u32, le32_to_cpu(mrec->bytes_allocated),
			record->operation.redo_len);
	if (attr_len != operation->redo_len || !IS_ALIGNED(attr_len, 8) ||
	    !ntfs_log_mft_record_has_boundary(mrec,
		    record->operation.redo_len, operation->record_off) ||
	    operation->record_off > used || used > allocated ||
	    attr_len > allocated - used)
		goto out_invalid;
	memmove((u8 *)mrec + operation->record_off + attr_len,
			(u8 *)mrec + operation->record_off,
			used - operation->record_off);
	memcpy((u8 *)mrec + operation->record_off, new_attr, attr_len);
	mrec->bytes_in_use = cpu_to_le32(used + attr_len);
	instance = le16_to_cpu(new_attr->instance);
	if (le16_to_cpu(mrec->next_attr_instance) <= instance)
		mrec->next_attr_instance = cpu_to_le16(instance + 1);
	if (!new_attr->non_resident &&
	    new_attr->data.resident.flags & RESIDENT_ATTR_IS_INDEXED)
		le16_add_cpu(&mrec->link_count, 1);

	if (ntfs_log_aggregate_prepare_page(log, &location, &page_copy))
		goto out_immutable;
	lrh = ntfs_log_aggregate_record_header(log, page_copy,
			location.record_off, record);
	if (!lrh)
		goto out_invalid;
	lfs = (void *)((u8 *)page_copy + location.record_off);
	redo_off = le16_to_cpu(lrh->redo_off);
	if (redo_off > le32_to_cpu(lfs->client_data_len) ||
	    record->operation.redo_len >
		    le32_to_cpu(lfs->client_data_len) - redo_off)
		goto out_invalid;
	memcpy((u8 *)lrh + redo_off, image_copy,
			record->operation.redo_len);
	page = location.page;
	memcpy(page, page_copy, log->layout.page_size);
	memcpy(record->redo_image, image_copy, record->operation.redo_len);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_COALESCE_ATTEMPT, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_COALESCE_HIT, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_COALESCE_BYTE,
			operation->redo_len);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_AGGREGATE_MFT_FOLD, 1);
	ntfs_log_recording_account(
			NTFS_LOG_RECORDING_AGGREGATE_RECLAIM_BYTE,
			ALIGN(log->layout.record_header_len + client_data_len, 8));
	*lsn_out = record->lsn;
	kvfree(page_copy);
	kfree(image_copy);
	return true;
out_immutable:
	ntfs_log_recording_account(
			NTFS_LOG_RECORDING_AGGREGATE_MFT_IMMUTABLE, 1);
	goto out;
out_invalid:
	ntfs_log_recording_account(
			NTFS_LOG_RECORDING_AGGREGATE_MFT_INVALID, 1);
out:
	kvfree(page_copy);
	kfree(image_copy);
	return false;
}

/* Keep each transaction's before and after images independent. */
static void ntfs_log_aggregate_commit_handle(struct ntfs_log_handle *handle)
{
	struct ntfs_log_aggregate_record *record, *next;

	list_for_each_entry_safe(record, next, &handle->aggregate_records,
				handle_list) {
		record->committed = true;
		list_del_init(&record->handle_list);
	}
}

/* append_lock must be held. Active handles lose only optional merge state. */
static void ntfs_log_aggregate_reset(struct ntfs_log *log)
{
	struct ntfs_log_aggregate_record *record;
	struct ntfs_log_aggregate_record *next;

	list_for_each_entry_safe(record, next, &log->aggregate_records,
			batch_list) {
		if (!list_empty(&record->handle_list))
			list_del_init(&record->handle_list);
		if (!hlist_unhashed(&record->hash_node))
			hlist_del_init(&record->hash_node);
		list_del(&record->batch_list);
		kfree(record);
	}
	log->aggregate_bytes = 0;
}

/* append_lock must be held. Records stay batch-visible but not handle-owned. */
static void ntfs_log_aggregate_release_handle(struct ntfs_log_handle *handle)
{
	struct ntfs_log_aggregate_record *record;
	struct ntfs_log_aggregate_record *next;

	list_for_each_entry_safe(record, next, &handle->aggregate_records,
			handle_list)
		list_del_init(&record->handle_list);
}

static bool ntfs_log_merge_bitmap_ranges(
		const struct ntfs_log_operation_desc *first,
		const struct ntfs_log_operation_desc *next,
		struct ntfs_bitmap_range *merged)
{
	/* Saved undo entries intentionally do not retain a redo_data pointer. */
	const struct ntfs_bitmap_range *first_range = first->undo_data;
	const struct ntfs_bitmap_range *first_undo = first->undo_data;
	const struct ntfs_bitmap_range *next_range = next->redo_data;
	const struct ntfs_bitmap_range *next_undo = next->undo_data;
	u64 first_start;
	u64 first_end;
	u64 next_start;
	u32 first_bits;
	u32 next_bits;
	u16 index;

	if (!merged ||
	    (next->redo_op != SetBitsInNonresidentBitMap &&
	     next->redo_op != ClearBitsInNonresidentBitMap) ||
	    first->redo_op != next->redo_op || first->undo_op != next->undo_op ||
	    first->target_attr != next->target_attr ||
	    first->target_vcn != next->target_vcn ||
	    first->cluster_off != next->cluster_off ||
	    first->lcns_follow != next->lcns_follow ||
	    !first->lcns_follow || !first->page_lcns || !next->page_lcns ||
	    first->redo_len != sizeof(*first_range) ||
	    first->undo_len != sizeof(*first_range) ||
	    next->redo_len != sizeof(*next_range) ||
	    next->undo_len != sizeof(*next_range) ||
	    !first_range || !first_undo || !next_range || !next_undo ||
	    memcmp(first_range, first_undo, sizeof(*first_range)) ||
	    memcmp(next_range, next_undo, sizeof(*next_range)))
		return false;
	for (index = 0; index < first->lcns_follow; index++)
		if (first->page_lcns[index] != next->page_lcns[index])
			return false;

	if (le32_to_cpu(first_range->bitmap_off) >= 8 ||
	    le32_to_cpu(next_range->bitmap_off) >= 8)
		return false;
	first_bits = le32_to_cpu(first_range->bits);
	next_bits = le32_to_cpu(next_range->bits);
	if (!first_bits || !next_bits)
		return false;
	first_start = ((u64)first->record_off << 3) +
			le32_to_cpu(first_range->bitmap_off);
	next_start = ((u64)next->record_off << 3) +
			le32_to_cpu(next_range->bitmap_off);
	if (check_add_overflow(first_start, (u64)first_bits, &first_end) ||
	    first_end != next_start || first_bits > U32_MAX - next_bits)
		return false;

	merged->bitmap_off = first_range->bitmap_off;
	merged->bits = cpu_to_le32(first_bits + next_bits);
	return true;
}

/* append_lock must be held. Keep the cross-transaction key canonical. */
static void ntfs_log_aggregate_update_bitmap(struct ntfs_log_handle *handle,
		u64 lsn, const struct ntfs_bitmap_range *range)
{
	struct ntfs_log_aggregate_record *record;

	list_for_each_entry(record, &handle->aggregate_records, handle_list) {
		if (record->lsn != lsn)
			continue;
		if (record->operation.undo_data &&
		    record->operation.undo_len == sizeof(*range))
			*(struct ntfs_bitmap_range *)record->operation.undo_data =
					*range;
		return;
	}
}

/*
 * Coalesce only the globally latest, still mutable overwrite record.  This
 * keeps transaction ordering and rollback isolation: the first before
 * image remains in the undo list while only its redo image is replaced.
 * append_lock must be held.
 */
static bool ntfs_log_try_coalesce(struct ntfs_log *log,
		struct ntfs_log_handle *handle,
		const struct ntfs_log_operation_desc *operation,
		u32 new_client_len, u64 *lsn_out)
{
	struct ntfs_log_aggregate_record *aggregate;
	struct ntfs_log_undo_entry *candidate;
	struct ntfs_log_undo_entry *entry = NULL;
	struct ntfs_lfs_record_hdr *hdr;
	struct ntfs_log_rec_hdr *lrh;
	u64 byte_off;
	u64 page_off;
	u32 off;
	u32 client_len;
	struct ntfs_bitmap_range bitmap_range;
	bool bitmap_merge;
	bool exact_merge;
	u16 redo_off;
	u16 undo_off;

	ntfs_log_recording_account(NTFS_LOG_RECORDING_COALESCE_ATTEMPT, 1);
	if (list_empty(&handle->undo_entries))
		return false;
	/*
	 * Compile a transaction's write set rather than requiring adjacency in
	 * the global record stream.  Different metadata units commute inside one
	 * atomic transaction.  The first operation on this unit is a hard barrier
	 * unless it is the exact overwrite/range that can absorb this update.
	 */
	list_for_each_entry_reverse(candidate, &handle->undo_entries, list) {
		if (ntfs_log_same_overwrite_target(&candidate->operation,
				operation) ||
		    ntfs_log_merge_bitmap_ranges(&candidate->operation, operation,
				&bitmap_range)) {
			entry = candidate;
			break;
		}
		if (ntfs_log_same_aggregate_unit(&candidate->operation, operation))
			return false;
	}
	if (!entry || !entry->record_lsn || !log->aggregate_hash)
		return false;
	/* Another transaction touching this unit is an ordering barrier. */
	hlist_for_each_entry(aggregate,
			&log->aggregate_hash[ntfs_log_aggregate_unit_hash(operation)],
			hash_node) {
		if (!ntfs_log_same_aggregate_unit(&aggregate->operation, operation))
			continue;
		if (aggregate->lsn != entry->record_lsn)
			return false;
		goto latest_unit_writer;
	}
	return false;

latest_unit_writer:
	exact_merge = ntfs_log_same_overwrite_target(&entry->operation,
			operation);
	bitmap_merge = ntfs_log_merge_bitmap_ranges(&entry->operation,
			operation, &bitmap_range);
	if ((!exact_merge && !bitmap_merge) ||
	    ntfs_lsn_to_byte_off(&log->layout, entry->record_lsn, &byte_off))
		return false;
	page_off = byte_off & ~((u64)log->layout.page_mask);
	off = byte_off & log->layout.page_mask;
	if (!log->pending_page || log->pending_page_off != page_off ||
	    off > log->layout.page_size - sizeof(*hdr))
		return false;
	hdr = (void *)((u8 *)log->pending_page + off);
	if (le64_to_cpu(hdr->this_lsn) != entry->record_lsn ||
	    le32_to_cpu(hdr->transact_id) != handle->transaction_id ||
	    hdr->record_type != LFS_CLIENT_RECORD ||
	    (hdr->flags & LOG_RECORD_MULTI_PAGE) ||
	    le32_to_cpu(hdr->client_data_len) < sizeof(*lrh) ||
	    le32_to_cpu(hdr->client_data_len) >
			log->layout.page_size - off - sizeof(*hdr))
		return false;
	lrh = (void *)((u8 *)hdr + sizeof(*hdr));
	client_len = le32_to_cpu(hdr->client_data_len);
	redo_off = le16_to_cpu(lrh->redo_off);
	undo_off = le16_to_cpu(lrh->undo_off);
	if (le16_to_cpu(lrh->redo_len) != operation->redo_len ||
	    redo_off > client_len || operation->redo_len > client_len - redo_off)
		return false;
	if (bitmap_merge) {
		struct ntfs_bitmap_range *disk_redo;
		struct ntfs_bitmap_range *disk_undo;

		if (le16_to_cpu(lrh->undo_len) != sizeof(bitmap_range) ||
		    undo_off > client_len ||
		    sizeof(bitmap_range) > client_len - undo_off ||
		    !entry->operation.undo_data)
			return false;
		disk_redo = (void *)((u8 *)lrh + redo_off);
		disk_undo = (void *)((u8 *)lrh + undo_off);
		if (memcmp(disk_redo, entry->operation.undo_data,
				sizeof(bitmap_range)) ||
		    memcmp(disk_undo, entry->operation.undo_data,
				sizeof(bitmap_range)))
			return false;
		*disk_redo = bitmap_range;
		*disk_undo = bitmap_range;
		*(struct ntfs_bitmap_range *)entry->operation.undo_data =
				bitmap_range;
		ntfs_log_aggregate_update_bitmap(handle, entry->record_lsn,
				&bitmap_range);
		ntfs_log_recording_account(NTFS_LOG_RECORDING_COALESCE_HIT, 1);
		ntfs_log_recording_account(NTFS_LOG_RECORDING_COALESCE_BYTE,
				operation->redo_len);
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_BITMAP_MERGE, 1);
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_RECLAIM_BYTE,
				ALIGN(log->layout.record_header_len + new_client_len, 8));
		if (entry->record_lsn != handle->prev_lsn)
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_GENERATION_METADATA_COALESCE,
					1);
		*lsn_out = entry->record_lsn;
		return true;
	}

	memcpy((u8 *)lrh + redo_off, operation->redo_data,
			operation->redo_len);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_COALESCE_HIT, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_COALESCE_BYTE,
			operation->redo_len);
	ntfs_log_recording_account(
			NTFS_LOG_RECORDING_AGGREGATE_RECLAIM_BYTE,
			ALIGN(log->layout.record_header_len + new_client_len, 8));
	if (entry->record_lsn != handle->prev_lsn)
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_GENERATION_METADATA_COALESCE, 1);
	*lsn_out = entry->record_lsn;
	return true;
}

static int __ntfs_log_write_operation(struct ntfs_log_handle *handle,
		const struct ntfs_log_operation_desc *operation,
		u64 undo_next_lsn, bool save_undo, bool wait_durable,
		u64 *lsn_out)
{
	struct ntfs_log_aggregate_record *aggregate_record = NULL;
	struct ntfs_log_undo_entry *undo_entry = NULL;
	struct ntfs_log_payload payload = { };
	struct ntfs_log *log;
	bool packed;
	u64 started;
	u64 lsn;
	int err;

	if (!handle || !operation || !handle->log)
		return -EINVAL;
	log = handle->log;
	if (!handle->active || handle->committed ||
	    handle->aborted || current != handle->owner)
		return -EPERM;
	packed = handle->packed != NULL;
	if (packed && wait_durable)
		return -EINVAL;
	if (operation->target_attr &&
	    (operation->target_attr < sizeof(struct ntfs_log_restart_table) ||
	     (operation->target_attr - sizeof(struct ntfs_log_restart_table)) %
			sizeof(struct ntfs_open_attr_entry_disk)))
		return -EINVAL;

	started = ntfs_log_task_cpu_time();
	err = ntfs_log_build_operation_payload(operation, &payload);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_RECORD_BUILD_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	if (err)
		return err;
	aggregate_record = ntfs_log_aggregate_alloc(operation, payload.len,
			log->layout.record_header_len,
			log->layout.page_size - log->layout.data_off);
	if (save_undo && ntfs_log_operation_has_undo(operation->undo_op)) {
		undo_entry = ntfs_log_save_undo(operation, undo_next_lsn);
		if (IS_ERR(undo_entry)) {
			err = PTR_ERR(undo_entry);
			undo_entry = NULL;
			goto out_payload;
		}
	}

	if (packed)
		lockdep_assert_held(&log->append_lock);
	else
		mutex_lock(&log->append_lock);
	if (!log->running || log->aborted) {
		err = -EROFS;
		goto out_unlock;
	}
	started = ntfs_log_task_cpu_time();
	if (!packed && save_undo && undo_entry &&
	    ntfs_log_aggregate_fold_mft_create(log, handle, operation,
		    payload.len, &lsn)) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_LOOKUP_CPU_NS,
				ntfs_log_task_cpu_time() - started);
		mutex_unlock(&log->append_lock);
		if (lsn_out)
			*lsn_out = lsn;
		goto out_entry;
	}
	if (!packed && save_undo && undo_entry &&
	    ntfs_log_try_coalesce(log, handle, operation, payload.len, &lsn)) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_LOOKUP_CPU_NS,
				ntfs_log_task_cpu_time() - started);
		mutex_unlock(&log->append_lock);
		if (lsn_out)
			*lsn_out = lsn;
		goto out_entry;
	}
	ntfs_log_recording_account(NTFS_LOG_RECORDING_AGGREGATE_LOOKUP_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	started = ntfs_log_task_cpu_time();
	err = ntfs_log_append_record(log, handle, 0,
			le32_to_cpu(LFS_CLIENT_RECORD), undo_next_lsn,
			payload.data, payload.len,
			save_undo, &lsn);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_RECORD_APPEND_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	if (err)
		goto out_unlock;
	err = ntfs_log_track_dirty_page(log, operation, lsn);
	if (err) {
		ntfs_log_abort_writer(log, err);
		goto out_unlock;
	}
	/* OOM/overflow in optional tracking must leave no stale ordering tail. */
	if (ntfs_log_aggregate_trackable(operation) && !aggregate_record) {
		ntfs_log_recording_account(
				NTFS_LOG_RECORDING_AGGREGATE_FALLBACK, 1);
		ntfs_log_aggregate_reset(log);
	}
	ntfs_log_recording_account_operation(operation->redo_op, payload.len);
	if (!handle->first_lsn)
		handle->first_lsn = lsn;
	handle->prev_lsn = lsn;
	if (operation->undo_op == CompensationLogRecord)
		handle->undo_next_lsn = undo_next_lsn;
	else if (ntfs_log_operation_has_undo(operation->undo_op))
		handle->undo_next_lsn = lsn;
	if (undo_entry) {
		undo_entry->record_lsn = lsn;
		undo_entry->packed_group = packed ? handle->packed->group : 0;
		undo_entry->packed_page_off = packed ?
				handle->packed->page_off : 0;
		list_add_tail(&undo_entry->list, &handle->undo_entries);
		undo_entry = NULL;
	}
	started = ntfs_log_task_cpu_time();
	ntfs_log_aggregate_add(log, handle, aggregate_record, lsn);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_AGGREGATE_LOOKUP_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	aggregate_record = NULL;
	/* A checkpoint may run before this caller returns from its flush. */
	if (operation->redo_op == CommitTransaction) {
		handle->commit_recorded = true;
		ntfs_log_aggregate_commit_handle(handle);
	} else if (operation->redo_op == ForgetTransaction) {
		handle->forget_recorded = true;
		if (handle->commit_recorded) {
			int index = ntfs_log_transaction_id_index(handle->transaction_id);

			if (WARN_ON_ONCE(index < 0)) {
				err = -EINVAL;
				ntfs_log_abort_writer(log, err);
				goto out_unlock;
			}
			set_bit(index, log->retired_transaction_ids);
			if (handle->queue_deferred_free)
				ntfs_log_defer_handle_frees(handle, index);
		}
	}
	if (!packed)
		mutex_unlock(&log->append_lock);
	if (wait_durable) {
		err = ntfs_log_flush_group(log, lsn, true);
		if (err)
			goto out_entry;
	}

	if (lsn_out)
		*lsn_out = lsn;
	goto out_entry;
out_unlock:
	if (!packed)
		mutex_unlock(&log->append_lock);
out_entry:
	kfree(aggregate_record);
	kfree(undo_entry);
out_payload:
	ntfs_log_free_payload(&payload);
	return err;
}

int ntfs_log_write_operation(struct ntfs_log_handle *handle,
		const struct ntfs_log_operation_desc *operation, u64 *lsn_out)
{
	return __ntfs_log_write_operation(handle, operation,
			handle ? handle->undo_next_lsn : 0, true, false, lsn_out);
}

static int ntfs_log_register_home_undo_with_callbacks(
		struct ntfs_log_handle *handle, int (*restore)(void *data),
		int (*commit)(void *data), int (*abort)(void *data),
		void (*release)(void *data), void *data,
		enum ntfs_log_deferred_kind kind, u64 units, size_t bytes)
{
	struct ntfs_log_home_undo *entry;
	struct ntfs_log_deferred_queue *queue;
	struct ntfs_log *log;

	if (!handle || !handle->log || !restore || !release || !data)
		return -EINVAL;
	if (kind < NTFS_LOG_DEFERRED_KINDS &&
	    (!commit || !units || !bytes ||
	     check_add_overflow(bytes, sizeof(*entry), &bytes)))
		return -EINVAL;
	entry = kmalloc_obj(*entry, GFP_NOFS);
	if (!entry)
		return -ENOMEM;
	*entry = (struct ntfs_log_home_undo) {
		.restore = restore,
		.commit = commit,
		.abort = abort,
		.release = release,
		.data = data,
	};
	INIT_LIST_HEAD(&entry->list);

	/* Registration and teardown must serialize ownership of this list. */
	log = handle->log;
	mutex_lock(&log->append_lock);
	if (!handle->active || handle->committed ||
	    handle->aborted || current != handle->owner) {
		mutex_unlock(&log->append_lock);
		kfree(entry);
		return -EPERM;
	}
	if (kind < NTFS_LOG_DEFERRED_KINDS) {
		queue = &log->deferred[kind];
		if (log->async_commit && !handle->independent &&
		    !handle->force_durable_commit &&
		    !(log->vol->sb->s_flags & (SB_SYNCHRONOUS | SB_DIRSYNC)) &&
		    queue->reserved < NTFS_LOG_DEFERRED_MAX_ENTRIES &&
		    bytes <= NTFS_LOG_DEFERRED_MAX_BYTES - queue->bytes &&
		    units <= U64_MAX - queue->units) {
			entry->deferred = true;
			entry->deferred_kind = kind;
			entry->deferred_units = units;
			entry->deferred_bytes = bytes;
			queue->reserved++;
			queue->units += units;
			queue->bytes += bytes;
			handle->has_deferred_free = true;
		} else {
			handle->force_durable_commit = true;
			ntfs_log_recording_account(
					NTFS_LOG_RECORDING_DEFERRED_FALLBACK, 1);
		}
	} else if (commit) {
		handle->force_durable_commit = true;
	}
	list_add_tail(&entry->list, &handle->home_undo_entries);
	mutex_unlock(&log->append_lock);
	return 0;
}

int ntfs_log_register_home_undo_with_commit(struct ntfs_log_handle *handle,
		int (*restore)(void *data), int (*commit)(void *data),
		void (*release)(void *data), void *data)
{
	return ntfs_log_register_home_undo_with_callbacks(handle, restore,
			commit, NULL, release, data,
			NTFS_LOG_DEFERRED_KINDS, 0, 0);
}

int ntfs_log_register_deferred_free(struct ntfs_log_handle *handle,
		int (*restore)(void *data), int (*commit)(void *data),
		void (*release)(void *data), void *data,
		enum ntfs_log_deferred_kind kind, u64 units, size_t bytes)
{
	if (kind >= NTFS_LOG_DEFERRED_KINDS)
		return -EINVAL;
	return ntfs_log_register_home_undo_with_callbacks(handle, restore,
			commit, NULL, release, data, kind, units, bytes);
}

int ntfs_log_register_home_undo_with_abort(struct ntfs_log_handle *handle,
		int (*restore)(void *data), int (*abort)(void *data),
		void (*release)(void *data), void *data)
{
	return ntfs_log_register_home_undo_with_callbacks(handle, restore,
			NULL, abort, release, data,
			NTFS_LOG_DEFERRED_KINDS, 0, 0);
}

int ntfs_log_register_home_undo(struct ntfs_log_handle *handle,
		int (*restore)(void *data), void (*release)(void *data),
		void *data)
{
	return ntfs_log_register_home_undo_with_callbacks(handle, restore,
			NULL, NULL, release, data,
			NTFS_LOG_DEFERRED_KINDS, 0, 0);
}

int ntfs_log_register_home_undo_buffer(struct ntfs_log_handle *handle,
		int (*restore)(void *data), void (*release)(void *data),
		const void *data, size_t bytes)
{
	struct ntfs_log_home_undo *entry;
	int err = 0;

	if (!handle || !handle->log || !restore || !release || !data || !bytes)
		return -EINVAL;
	mutex_lock(&handle->log->append_lock);
	if (!handle->active || handle->committed || handle->aborted ||
	    current != handle->owner) {
		err = -EPERM;
		goto out;
	}
	if (bytes > sizeof(handle->home_undo_buffer) ||
	    handle->home_undo_buffer_used) {
		err = -EOPNOTSUPP;
		goto out;
	}
	entry = &handle->buffered_home_undo;
	memcpy(handle->home_undo_buffer, data, bytes);
	*entry = (struct ntfs_log_home_undo) {
		.restore = restore,
		.release = release,
		.data = handle->home_undo_buffer,
		.embedded = true,
	};
	INIT_LIST_HEAD(&entry->list);
	list_add_tail(&entry->list, &handle->home_undo_entries);
	handle->home_undo_buffer_used = true;
out:
	mutex_unlock(&handle->log->append_lock);
	return err;
}

static int ntfs_log_write_marker(struct ntfs_log_handle *handle, u16 marker,
		bool wait_durable)
{
	struct ntfs_log_operation_desc operation = { };

	operation.redo_op = marker;
	operation.undo_op = Noop;
	return __ntfs_log_write_operation(handle, &operation,
			handle->undo_next_lsn, false, wait_durable, NULL);
}

static int ntfs_log_transaction_id_index(u32 id)
{
	return ntfs_log_transaction_slot_index(id);
}

/* append_lock must be held. */
static int ntfs_log_alloc_transaction_id(struct ntfs_log *log, u32 *id)
{
	const u32 first = sizeof(struct ntfs_log_restart_table);
	const u32 stride = sizeof(struct ntfs_transaction_entry);
	struct ntfs_log_handle *handle;
	u32 candidate;
	u32 start;
	bool used;

	if (!id)
		return -EINVAL;
	candidate = log->next_transaction_id;
	if (candidate < first || candidate > U16_MAX - stride ||
	    (candidate - first) % stride)
		candidate = first;
	start = candidate;
	do {
		int index = ntfs_log_transaction_id_index(candidate);

		used = index == 0;
		if (index < 0)
			return index;
		if (test_bit(index, log->retired_transaction_ids))
			used = true;
		list_for_each_entry(handle, &log->active_handles, active_list) {
			if (handle->transaction_id == candidate) {
				used = true;
				break;
			}
		}
		if (!used) {
			*id = candidate;
			candidate += stride;
			if (candidate > U16_MAX - stride)
				candidate = first;
			log->next_transaction_id = candidate;
			return 0;
		}
		candidate += stride;
		if (candidate > U16_MAX - stride)
			candidate = first;
	} while (candidate != start);

	return -ENOSPC;
}

static int ntfs_log_transaction_reservation(const struct ntfs_log *log,
					    unsigned int requested,
					    bool full_reservation,
					    u32 *operation_credits,
					    u32 *reserved_credits)
{
	u64 data_pages;
	u64 max_credits;
	u32 initial_credits;

	if (!log || !operation_credits || !reserved_credits ||
	    !log->layout.page_size || log->layout.log_size <=
			log->layout.first_page)
		return -EINVAL;
	data_pages = div_u64(log->layout.log_size - log->layout.first_page,
			     log->layout.page_size);
	if (data_pages <= NTFS_LOG_EMERGENCY_PAGES + 3)
		return -E2BIG;
	/*
	 * Forward records and their CLRs share at most half of the data ring.
	 * Keep the other half available for the current tail, checkpoints, and
	 * transactions that were admitted concurrently.
	 */
	max_credits = (data_pages - NTFS_LOG_EMERGENCY_PAGES - 3) / 4;
	max_credits = min_t(u64, max_credits, (U32_MAX - 2) / 2);
	if (full_reservation && (!max_credits || requested > max_credits))
		return -E2BIG;
	/*
	 * Keep the physical ceiling independent of the caller's worst-case
	 * estimate.  Ordinary transactions reserve a small initial budget and
	 * grow from shared foreground slack as records are appended.  Charging
	 * every large estimate the ceiling can make even two handles exceed the
	 * entire ring.  Full reservations still validate and fund their bound.
	 */
	*operation_credits = max_credits;
	if (full_reservation) {
		initial_credits = max_t(u32, requested, 1);
	} else {
		initial_credits = clamp_t(u64, requested, 1,
				NTFS_LOG_INITIAL_TRANSACTION_CREDITS);
		initial_credits = min_t(u64, initial_credits, max_credits);
	}
	*reserved_credits = initial_credits * 2 + 2;
	return 0;
}

int ntfs_log_transaction_credits_limit(struct ntfs_volume *vol)
{
	struct ntfs_log *log;
	u32 credits;
	u32 reserved;
	int err;

	if (!vol)
		return -EINVAL;
	down_read(&vol->journal_lock);
	log = vol->journal;
	if (!log) {
		err = -EROFS;
		goto out_journal;
	}
	mutex_lock(&log->append_lock);
	if (NVolShutdown(vol))
		err = -EIO;
	else if (!log->running || log->aborted || log->stopping)
		err = -EROFS;
	else
		err = ntfs_log_transaction_reservation(log, 1, true,
				&credits, &reserved);
	mutex_unlock(&log->append_lock);
out_journal:
	up_read(&vol->journal_lock);
	if (err)
		return err;
	return credits;
}

static bool ntfs_log_in_workqueue(void)
{
	/*
	 * Begin can run in the writeback that a checkpoint would wait for.
	 * Defer reclaim rather than checkpoint beneath those caller locks.
	 * The dedicated reclaim worker starts without such locks. Any nested
	 * begin in its writeback callbacks must still defer another checkpoint.
	 * The exact writeback callback is not exported, so use workqueue context
	 * as the stable boundary here.
	 */
	return current_work();
}

struct ntfs_log *ntfs_log_try_pin_size_update(struct ntfs_volume *vol)
{
	struct ntfs_log *log;

	if (!vol || NVolShutdown(vol) || ntfs_log_in_workqueue() ||
	    !down_read_trylock(&vol->journal_lock))
		return NULL;
	log = vol->journal;
	if (!log || !log->async_commit || READ_ONCE(log->stopping) ||
	    !READ_ONCE(log->running) || READ_ONCE(log->aborted) ||
	    (vol->sb->s_flags & (SB_SYNCHRONOUS | SB_DIRSYNC)) ||
	    !down_read_trylock(&log->admission_lock))
		goto out_journal;
	if (!down_read_trylock(&log->transaction_lock))
		goto out_admission;
	up_read(&vol->journal_lock);
	return log;

out_admission:
	up_read(&log->admission_lock);
out_journal:
	up_read(&vol->journal_lock);
	return NULL;
}

void ntfs_log_unpin_size_update(struct ntfs_log *log)
{
	up_read(&log->transaction_lock);
	up_read(&log->admission_lock);
}

enum ntfs_log_begin_flags {
	NTFS_LOG_BEGIN_NOWAIT = 1U << 0,
	NTFS_LOG_BEGIN_MOUNT_LOCKED = 1U << 1,
	NTFS_LOG_BEGIN_BOUNDED = 1U << 2,
};

static struct ntfs_log_handle *__ntfs_log_begin(struct ntfs_volume *vol,
		unsigned int credits, bool writeback, bool full_reservation,
		unsigned int flags, unsigned long caller_ip,
		struct ntfs_log_handle *parent,
		struct ntfs_log **deferred_log)
{
	struct ntfs_log_handle *handle;
	struct ntfs_log *log;
	bool nowait = flags & NTFS_LOG_BEGIN_NOWAIT;
	bool mount_locked = flags & NTFS_LOG_BEGIN_MOUNT_LOCKED;
	bool bounded = flags & NTFS_LOG_BEGIN_BOUNDED;
	u64 ignored_lsn;
	u64 ignored_next;
	u64 reclaim_oldest_lsn = 0;
	u64 reclaim_home_generation = 0;
	u64 reclaim_id_lsn = 0;
	u32 borrowed = 0;
	u32 growth_headroom = 0;
	u32 required_pages;
	u32 reserved = 0;
	bool reclaimed = false;
	bool id_retried = false;
	bool reuse_growth;
	int err;

	if (deferred_log)
		*deferred_log = NULL;
	if (!vol)
		return ERR_PTR(-EROFS);
	if (bounded && (!full_reservation || parent || writeback || !credits))
		return ERR_PTR(-EINVAL);
	if (NVolShutdown(vol))
		return ERR_PTR(-EIO);
	if (mount_locked)
		lockdep_assert_held_write(&vol->sb->s_umount);
	if (parent && (!parent->active || !parent->log ||
	    parent->log->vol != vol || parent->owner != current ||
	    parent->committed || parent->aborted))
		return ERR_PTR(-EPERM);

	handle = kzalloc(sizeof(*handle), GFP_NOFS);
	if (!handle)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&handle->undo_entries);
	INIT_LIST_HEAD(&handle->home_undo_entries);
	INIT_LIST_HEAD(&handle->aggregate_records);
	INIT_LIST_HEAD(&handle->active_list);
	handle->owner = current;
	handle->parent = parent;
	handle->caller_ip = caller_ip;
	handle->independent = parent != NULL;
	handle->bounded_credits = bounded ? credits : 0;
	handle->writeback = writeback || (parent && parent->writeback);
	handle->nowait = nowait || (parent && parent->nowait);
	handle->force_durable_commit = parent != NULL;

retry:
	reuse_growth = false;
	if (parent) {
		log = parent->log;
	} else {
		if (nowait) {
			if (!down_read_trylock(&vol->journal_lock)) {
				err = -EBUSY;
				goto out_free;
			}
		} else {
			down_read(&vol->journal_lock);
		}
		log = vol->journal;
	}
	if (!log) {
		err = -EROFS;
		goto out_journal;
	}
	handle->log = log;
	if (!parent && !writeback && !ntfs_log_in_workqueue()) {
		if (nowait) {
			if (!down_read_trylock(&log->admission_lock)) {
				err = -EBUSY;
				goto out_journal;
			}
		} else {
			down_read(&log->admission_lock);
		}
		handle->admitted = true;
	}
	if (!parent) {
		if (nowait) {
			if (!down_read_trylock(&log->transaction_lock)) {
				err = -EBUSY;
				goto out_admission;
			}
		} else {
			down_read(&log->transaction_lock);
		}
	}
	mutex_lock(&log->append_lock);
	if (NVolShutdown(vol)) {
		err = -EIO;
		goto out_unlock;
	}
	if (!log->running || log->aborted ||
	    (log->stopping && !parent && !(writeback &&
			READ_ONCE(log->checkpoint_collecting)))) {
		err = -EROFS;
		goto out_unlock;
	}
	err = ntfs_log_transaction_reservation(log, credits,
					       full_reservation,
					       &handle->operation_credits,
					       &reserved);
	if (err) {
		ntfs_error(vol->sb,
			"Journal transaction reservation failed (requested %u, log size %llu, page size %u, error %d).",
			credits, (unsigned long long)log->layout.log_size,
			log->layout.page_size, err);
		goto out_unlock;
	}
	if (parent)
		ntfs_log_independent_reservation(parent, full_reservation,
				&reserved, &borrowed);
	handle->reserved_credits = reserved;
	growth_headroom = handle->writeback ? 0 : handle->operation_credits;
	if (parent)
		growth_headroom = ntfs_log_growth_headroom(handle, reserved - borrowed);
	else if (full_reservation) {
		struct ntfs_log_handle *active;
		bool growing = false;

		/* Strict bounds are funded separately, not from shared growth. */
		list_for_each_entry(active, &log->active_handles, active_list) {
			if (!bounded || !active->bounded_credits) {
				growing = true;
				break;
			}
		}
		growth_headroom = growing ?
			ntfs_log_growth_headroom(handle, 0) : 0;
	}
	err = ntfs_log_reservation_pages(log->reserved_pages, reserved - borrowed,
			handle->operation_credits, handle->writeback,
			growth_headroom, &required_pages);
	if (err) {
		ntfs_error(vol->sb,
			"Journal transaction reservation overflow (requested %u, operation credits %u, reserved credits %u, log reserved pages %u).",
			credits, handle->operation_credits, reserved,
			log->reserved_pages);
		goto out_unlock;
	}
	err = reserved == borrowed ? 0 :
		ntfs_log_reserve_pages(log, required_pages, &ignored_lsn,
				&ignored_next);
	if (err == -ENOSPC &&
	    (parent || writeback || nowait || ntfs_log_in_workqueue())) {
		ntfs_log_request_checkpoint(log);
		err = -EAGAIN;
		goto out_unlock;
	}
	/*
	 * A checkpoint can retain dirty history when concurrent writes changed
	 * the home generation during collection.  One successful checkpoint
	 * therefore need not have reclaimed enough space for this reservation.
	 * Keep collecting while home writeback or the recovery tail advances.
	 * Stop if a successful checkpoint made no progress at either boundary.
	 */
	if (err == -ENOSPC && (!reclaimed ||
	    reclaim_oldest_lsn != log->oldest_lsn ||
	    reclaim_home_generation != atomic64_read(&log->home_generation))) {
		reclaimed = true;
		reclaim_oldest_lsn = log->oldest_lsn;
		reclaim_home_generation = atomic64_read(&log->home_generation);
		mutex_unlock(&log->append_lock);
		up_read(&log->transaction_lock);
		if (handle->admitted) {
			up_read(&log->admission_lock);
			handle->admitted = false;
		}
		up_read(&vol->journal_lock);
		if (!mount_locked)
			down_read(&vol->sb->s_umount);
		err = ntfs_log_checkpoint_reason(vol, false,
				NTFS_LOG_RECORDING_SPACE_CHECKPOINT);
		if (!mount_locked)
			up_read(&vol->sb->s_umount);
		if (!err)
			goto retry;
		goto out_free;
	}
	/*
	 * If reclamation stalled, charge the initial reservation against any
	 * existing growth headroom rather than requiring a full refill.  Keep
	 * the remaining pool and checkpoint headroom protected for other handles.
	 */
	if (err == -ENOSPC && reclaimed && !full_reservation) {
		growth_headroom = ntfs_log_growth_headroom(handle, reserved);
		err = ntfs_log_reservation_pages(log->reserved_pages, reserved,
				handle->operation_credits, false, growth_headroom,
				&required_pages);
		if (!err)
			err = ntfs_log_reserve_pages(log, required_pages,
					&ignored_lsn, &ignored_next);
		if (!err)
			reuse_growth = true;
	}
	if (err)
		if (err != -EAGAIN)
			ntfs_error(vol->sb,
				"Journal transaction page reservation failed (requested %u, operation credits %u, reserved credits %u, checkpoint headroom %u, growth headroom %u, growth credits %u, required pages %u, log reserved pages %u, head LSN 0x%llx, oldest LSN 0x%llx, error %d).",
				credits, handle->operation_credits, reserved,
				handle->writeback ? 0 : handle->operation_credits,
				growth_headroom, log->growth_credits,
				required_pages, log->reserved_pages,
				(unsigned long long)log->head_lsn,
				(unsigned long long)log->oldest_lsn, err);
	if (err)
		goto out_unlock;
	err = ntfs_log_alloc_transaction_id(log, &handle->transaction_id);
	if (err == -ENOSPC && nowait) {
		if (log->pending_lsn)
			mod_delayed_work(system_long_wq, &log->flush_work, 0);
		err = -EAGAIN;
		goto out_unlock;
	}
	/* Concurrent producers may consume the slots released by our flush. */
	if (err == -ENOSPC && (!id_retried ||
	    reclaim_id_lsn != READ_ONCE(log->durable_lsn)) &&
	    (log->pending_lsn || log->flush_inflight)) {
		id_retried = true;
		reclaim_id_lsn = READ_ONCE(log->durable_lsn);
		if (parent) {
			u64 flush_lsn = log->last_client_lsn;

			mutex_unlock(&log->append_lock);
			err = ntfs_log_flush_group(log, flush_lsn, false);
			if (!err)
				goto retry;
			goto out_free;
		}
		if (writeback || nowait || ntfs_log_in_workqueue()) {
			if (log->pending_lsn)
				mod_delayed_work(system_long_wq,
						&log->flush_work, 0);
			err = -EAGAIN;
			goto out_unlock;
		}
		mutex_unlock(&log->append_lock);
		up_read(&log->transaction_lock);
		if (handle->admitted) {
			up_read(&log->admission_lock);
			handle->admitted = false;
		}
		up_read(&vol->journal_lock);
		ntfs_log_recording_account(NTFS_LOG_RECORDING_ID_PRESSURE_FLUSH, 1);
		err = ntfs_log_flush(vol);
		if (!err)
			goto retry;
		ntfs_error(vol->sb,
			"Journal flush after transaction ID exhaustion failed (error %d).",
			err);
		goto out_free;
	}
	if (err) {
		ntfs_error(vol->sb,
			"Journal transaction ID allocation failed (requested %u, pending LSN 0x%llx, flush in flight %u, retired IDs %u, error %d).",
			credits, (unsigned long long)log->pending_lsn,
			log->flush_inflight,
			bitmap_weight(log->retired_transaction_ids,
					NTFS_LOG_TRANSACTION_SLOT_COUNT), err);
		goto out_unlock;
	}

	/* All outstanding reservations were included when funding this pool. */
	if (!parent && !handle->writeback && !full_reservation && !reuse_growth)
		log->growth_credits = 0;
	else if (!reuse_growth && list_empty(&log->active_handles))
		log->growth_credits = handle->operation_credits;
	if (borrowed)
		parent->reserved_credits -= borrowed;
	if (parent || handle->writeback || reuse_growth)
		ntfs_log_charge_growth(handle, reserved - borrowed);
	log->reserved_pages += reserved - borrowed;
	handle->active = true;
	list_add_tail(&handle->active_list, &log->active_handles);
	mutex_unlock(&log->append_lock);
	if (!parent)
		up_read(&vol->journal_lock);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_BEGIN, 1);
	return handle;

out_unlock:
	mutex_unlock(&log->append_lock);
	if (!parent) {
		if (writeback && err == -EAGAIN && deferred_log)
			*deferred_log = log;
		else
			up_read(&log->transaction_lock);
	}
out_admission:
	if (handle->admitted)
		up_read(&log->admission_lock);
out_journal:
	if (!parent)
		up_read(&vol->journal_lock);
out_free:
	ntfs_log_free_handle(handle);
	if (nowait && (err == -EAGAIN || err == -EBUSY))
		ntfs_log_recording_account(NTFS_LOG_RECORDING_LOCKED_BEGIN_DEFER, 1);
	return ERR_PTR(err);
}

struct ntfs_log_handle *ntfs_log_begin(struct ntfs_volume *vol,
		unsigned int credits)
{
	struct ntfs_log_handle *handle;
	u64 started = ntfs_log_task_cpu_time();

	handle = __ntfs_log_begin(vol, credits, false, false, 0, _RET_IP_, NULL, NULL);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	return handle;
}

struct ntfs_log_handle *ntfs_log_begin_locked(struct ntfs_volume *vol,
		unsigned int credits)
{
	struct ntfs_log_handle *handle;
	u64 started = ntfs_log_task_cpu_time();

	handle = __ntfs_log_begin(vol, credits, false, false,
				  NTFS_LOG_BEGIN_NOWAIT, _RET_IP_, NULL, NULL);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	return handle;
}

struct ntfs_log_handle *ntfs_log_begin_full_reservation(
		struct ntfs_volume *vol, unsigned int credits)
{
	struct ntfs_log_handle *handle;
	u64 started = ntfs_log_task_cpu_time();

	handle = __ntfs_log_begin(vol, credits, false, true, 0, _RET_IP_, NULL, NULL);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	return handle;
}

struct ntfs_log_handle *ntfs_log_begin_bounded(struct ntfs_volume *vol,
		unsigned int credits)
{
	struct ntfs_log_handle *handle;
	u64 started = ntfs_log_task_cpu_time();

	handle = __ntfs_log_begin(vol, credits, false, true,
				  NTFS_LOG_BEGIN_BOUNDED, _RET_IP_, NULL, NULL);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	return handle;
}

struct ntfs_log_handle *ntfs_log_begin_mount_full(struct ntfs_volume *vol,
						  unsigned int credits)
{
	struct ntfs_log_handle *handle;
	u64 started = ntfs_log_task_cpu_time();

	handle = __ntfs_log_begin(vol, credits, false, true,
				  NTFS_LOG_BEGIN_MOUNT_LOCKED, _RET_IP_, NULL, NULL);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
				   ntfs_log_task_cpu_time() - started);
	return handle;
}

static struct ntfs_log_handle *ntfs_log_begin_independent_common(
		struct ntfs_log_handle *parent, unsigned int credits,
		bool full_reservation)
{
	struct ntfs_log_handle *handle;
	u64 started = ntfs_log_task_cpu_time();

	if (!parent || !parent->log)
		return ERR_PTR(-EINVAL);
	handle = __ntfs_log_begin(parent->log->vol, credits, false,
			full_reservation,
			parent->nowait ? NTFS_LOG_BEGIN_NOWAIT : 0,
			_RET_IP_, parent, NULL);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	return handle;
}

struct ntfs_log_handle *ntfs_log_begin_independent(
		struct ntfs_log_handle *parent, unsigned int credits)
{
	return ntfs_log_begin_independent_common(parent, credits, false);
}

struct ntfs_log_handle *ntfs_log_begin_independent_full(
		struct ntfs_log_handle *parent, unsigned int credits)
{
	return ntfs_log_begin_independent_common(parent, credits, true);
}

struct ntfs_log_handle *ntfs_log_begin_independent_writeback(
		struct ntfs_log_handle *parent, unsigned int credits)
{
	struct ntfs_log_handle *handle;
	u64 started = ntfs_log_task_cpu_time();

	if (!parent || !parent->log || !parent->writeback || parent->prev_lsn ||
	    !list_empty(&parent->undo_entries) ||
	    !list_empty(&parent->home_undo_entries))
		return ERR_PTR(-EINVAL);
	handle = __ntfs_log_begin(parent->log->vol, credits, false, false,
			parent->nowait ? NTFS_LOG_BEGIN_NOWAIT : 0,
			_RET_IP_, parent, NULL);
	if (!IS_ERR(handle))
		handle->force_durable_commit = false;
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	return handle;
}

static struct ntfs_log_handle *ntfs_log_begin_writeback_pinned(
		struct ntfs_volume *vol, unsigned int credits,
		unsigned long caller_ip, struct ntfs_log **deferred_log)
{
	struct ntfs_log_handle *handle;
	u64 started = ntfs_log_task_cpu_time();

	handle = __ntfs_log_begin(vol, credits, true, false, 0, caller_ip, NULL, deferred_log);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	return handle;
}

/* Writeback must progress while a checkpoint quiesces producers. */
struct ntfs_log_handle *ntfs_log_begin_writeback(struct ntfs_volume *vol,
		unsigned int credits)
{
	return ntfs_log_begin_writeback_pinned(vol, credits, _RET_IP_, NULL);
}

struct ntfs_log_handle *ntfs_log_begin_inode_writeback(struct ntfs_volume *vol,
		unsigned int credits, struct ntfs_log **deferred_log)
{
	return ntfs_log_begin_writeback_pinned(vol, credits, _RET_IP_, deferred_log);
}

static struct ntfs_log_open_attr *ntfs_log_find_open_attr(struct ntfs_log *log,
		u64 mref, u32 type, u32 bytes_per_index, const __le16 *name,
		u8 name_len, bool is_dirty_pages)
{
	struct ntfs_log_open_attr *entry;

	list_for_each_entry(entry, &log->open_attrs, list) {
		if (entry->mref == mref && entry->type == type &&
		    entry->bytes_per_index == bytes_per_index &&
		    entry->name_len == name_len &&
		    entry->is_dirty_pages == is_dirty_pages &&
		    (!name_len || !memcmp(entry->name, name,
				name_len * sizeof(*name))))
			return entry;
	}
	return NULL;
}

int ntfs_log_open_attribute(struct ntfs_log_handle *handle, u64 mref,
		u32 type, u32 bytes_per_index, const __le16 *name, u8 name_len,
		bool is_dirty_pages, u16 *target_attr)
{
	struct ntfs_log_operation_desc operation = { };
	struct ntfs_open_attr_entry_disk disk = { };
	struct ntfs_log_open_attr *entry;
	struct ntfs_log *log;
	size_t size;
	u64 open_record_lsn;
	u16 slot;
	int err;

	if (!handle || !handle->log || !target_attr || (name_len && !name))
		return -EINVAL;
	log = handle->log;
	if (!handle->active || current != handle->owner)
		return -EPERM;

	mutex_lock(&log->open_attr_lock);
	entry = ntfs_log_find_open_attr(log, mref, type, bytes_per_index,
			name, name_len, is_dirty_pages);
	if (entry) {
		*target_attr = entry->slot;
		err = 0;
		goto out_unlock;
	}

	slot = log->next_open_attr_slot;
	if (slot > U16_MAX - sizeof(struct ntfs_open_attr_entry_disk)) {
		if (log->vol && log->vol->sb)
			ntfs_error(log->vol->sb, "Journal open attribute table exhausted.");
		err = -ENOSPC;
		goto out_unlock;
	}
	size = struct_size(entry, name, name_len);
	entry = kzalloc(size, GFP_NOFS);
	if (!entry) {
		err = -ENOMEM;
		goto out_unlock;
	}
	entry->mref = mref;
	entry->type = type;
	entry->bytes_per_index = bytes_per_index;
	entry->slot = slot;
	entry->name_len = name_len;
	entry->is_dirty_pages = is_dirty_pages;
	if (name_len)
		memcpy(entry->name, name, name_len * sizeof(*name));

	disk.next = RESTART_ENTRY_ALLOCATED_LE;
	disk.bytes_per_index = cpu_to_le32(bytes_per_index);
	disk.type = cpu_to_le32(type);
	disk.is_dirty_pages = is_dirty_pages;
	disk.is_attr_name = !!name_len;
	disk.name_len = name_len;
	disk.mref = cpu_to_le64(mref);
	operation.redo_op = OpenNonresidentAttribute;
	operation.undo_op = Noop;
	operation.target_attr = slot;
	operation.undo_data = name;
	operation.undo_len = name_len * sizeof(*name);
	operation.redo_data = &disk;
	operation.redo_len = sizeof(disk);
	err = ntfs_log_write_operation(handle, &operation, &open_record_lsn);
	if (err) {
		kfree(entry);
		goto out_unlock;
	}

	INIT_LIST_HEAD(&entry->list);
	entry->open_record_lsn = open_record_lsn;
	list_add_tail(&entry->list, &log->open_attrs);
	log->next_open_attr_slot += sizeof(struct ntfs_open_attr_entry_disk);
	*target_attr = slot;
out_unlock:
	mutex_unlock(&log->open_attr_lock);
	return err;
}

/* A bitmap page can cover at most this many 512-byte NTFS blocks/clusters. */
#define NTFS_LOG_BITMAP_MAX_LCNS \
	DIV_ROUND_UP(PAGE_SIZE + NTFS_BLOCK_SIZE - 1, NTFS_BLOCK_SIZE)
#define NTFS_LOG_NONRESIDENT_CHUNK_SIZE	4096U

static int ntfs_log_stream_lcns_locked(struct ntfs_inode *ni, s64 target_vcn,
				       u16 nr_lcns, u64 *lcns)
{
	u16 i;

	if (!ni || !ni->vol || target_vcn < 0 || !nr_lcns || !lcns)
		return -EINVAL;
	lockdep_assert_held_write(&ni->runlist.lock);
	if (target_vcn > S64_MAX - (s64)nr_lcns + 1)
		return -EOVERFLOW;
	if (ni->vol->nr_clusters <= 0)
		return -EIO;
	for (i = 0; i < nr_lcns; i++) {
		struct runlist_element *rl;
		s64 vcn = target_vcn + i;
		s64 delta;
		s64 lcn;

		rl = ntfs_attr_find_vcn_nolock(ni, vcn, NULL);
		if (IS_ERR(rl))
			return PTR_ERR(rl);
		delta = vcn - rl->vcn;
		if (rl->lcn < 0 || rl->length <= 0 || delta < 0 ||
		    delta >= rl->length ||
		    check_add_overflow(rl->lcn, delta, &lcn) ||
		    lcn >= ni->vol->nr_clusters)
			return -EIO;
		lcns[i] = lcn;
	}
	return 0;
}

static int ntfs_log_stream_lcns(struct ntfs_inode *ni, s64 target_vcn,
				u16 nr_lcns, u64 *lcns)
{
	int err;

	if (!ni)
		return -EINVAL;
	down_write(&ni->runlist.lock);
	err = ntfs_log_stream_lcns_locked(ni, target_vcn, nr_lcns, lcns);
	up_write(&ni->runlist.lock);
	return err;
}

static int __ntfs_log_nonresident_value_update(struct ntfs_log_handle *handle,
		struct inode *vi, u64 byte_pos, const u8 *old_data,
		const u8 *new_data, u32 bytes, u64 *lsn_out)
{
	struct ntfs_inode *base_ni;
	struct ntfs_inode *ni;
	unsigned long flags;
	u64 operation_lsn = 0;
	u16 target_attr;
	s64 allocated_size;
	u32 done = 0;
	int err;

	if (!handle || !vi || (!old_data && !new_data))
		return -EINVAL;
	if (!bytes)
		return 0;
	ni = NTFS_I(vi);
	if (!ni->vol || ni->vol->cluster_size < NTFS_BLOCK_SIZE ||
	    !NInoNonResident(ni) || ni->name_len > U8_MAX ||
	    byte_pos > S64_MAX)
		return -EINVAL;
	read_lock_irqsave(&ni->size_lock, flags);
	allocated_size = ni->allocated_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (allocated_size < 0 || byte_pos > (u64)allocated_size ||
	    bytes > (u64)allocated_size - byte_pos)
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	err = ntfs_log_open_attribute(handle,
			MK_MREF(base_ni->mft_no, base_ni->seq_no),
			le32_to_cpu(ni->type), 0, ni->name, ni->name_len, true,
			&target_attr);
	if (err)
		return err;

	while (done < bytes) {
		struct ntfs_log_operation_desc operation = { };
		u64 page_lcns[NTFS_LOG_BITMAP_MAX_LCNS];
		u64 pos = byte_pos + done;
		u64 cluster_byte_off;
		u64 nr_lcns;
		u32 chunk;
		u16 lcns_follow;

		chunk = min_t(u32, bytes - done,
				NTFS_LOG_NONRESIDENT_CHUNK_SIZE -
				(pos & (NTFS_LOG_NONRESIDENT_CHUNK_SIZE - 1)));
		cluster_byte_off = pos & ni->vol->cluster_size_mask;
		if ((cluster_byte_off >> NTFS_BLOCK_SIZE_BITS) > U16_MAX)
			return -E2BIG;
		nr_lcns = DIV_ROUND_UP(cluster_byte_off + chunk,
				ni->vol->cluster_size);
		if (!nr_lcns || nr_lcns > ARRAY_SIZE(page_lcns))
			return -E2BIG;
		lcns_follow = nr_lcns;
		err = ntfs_log_stream_lcns(ni,
				pos >> ni->vol->cluster_size_bits,
				lcns_follow, page_lcns);
		if (err)
			return err;
		operation.redo_op = new_data ? UpdateNonresidentValue : Noop;
		operation.undo_op = old_data ? UpdateNonresidentValue : Noop;
		operation.target_attr = target_attr;
		operation.record_off = cluster_byte_off &
				(NTFS_BLOCK_SIZE - 1);
		operation.cluster_off = cluster_byte_off >>
				NTFS_BLOCK_SIZE_BITS;
		operation.target_vcn = pos >> ni->vol->cluster_size_bits;
		operation.page_lcns = page_lcns;
		operation.lcns_follow = lcns_follow;
		if (new_data) {
			operation.redo_data = new_data + done;
			operation.redo_len = chunk;
		}
		if (old_data) {
			operation.undo_data = old_data + done;
			operation.undo_len = chunk;
		}
		err = ntfs_log_write_operation(handle, &operation,
				&operation_lsn);
		if (err)
			return err;
		done += chunk;
	}
	err = ntfs_log_track_inode(handle, vi, operation_lsn);
	if (!err && lsn_out)
		*lsn_out = operation_lsn;
	return err;
}

int ntfs_log_nonresident_value_update(struct ntfs_log_handle *handle,
		struct inode *vi, u64 byte_pos, const u8 *old_data,
		const u8 *new_data, u32 bytes, u64 *lsn_out)
{
	if (!new_data)
		return -EINVAL;
	return __ntfs_log_nonresident_value_update(handle, vi, byte_pos,
			old_data, new_data, bytes, lsn_out);
}

int ntfs_log_nonresident_value_undo(struct ntfs_log_handle *handle,
		struct inode *vi, u64 byte_pos, const u8 *old_data, u32 bytes)
{
	if (!old_data)
		return -EINVAL;
	return __ntfs_log_nonresident_value_update(handle, vi, byte_pos,
			old_data, NULL, bytes, NULL);
}

/*
 * Log a bitmap mutation as page-bounded SetBits/ClearBits operations.
 *
 * Each operation describes the physical clusters covering the changed bytes.
 * Replay can therefore repair the bitmap even when the owning attribute's
 * mapping-pairs update is itself part of the recovery stream.
 */
int ntfs_log_bitmap_update_credits(s64 start_bit, s64 count)
{
	u64 last_bit;
	u64 pages;

	if (start_bit < 0 || count < 0)
		return -EINVAL;
	if (!count)
		return 0;
	if (check_add_overflow((u64)start_bit, (u64)count - 1, &last_bit))
		return -EOVERFLOW;
	pages = (last_bit >> (PAGE_SHIFT + 3)) -
		((u64)start_bit >> (PAGE_SHIFT + 3)) + 1;
	/* One OpenNonresidentAttribute record plus one record per bitmap page. */
	if (pages >= INT_MAX)
		return -E2BIG;
	return pages + 1;
}

struct ntfs_log_bitmap_operation {
	struct ntfs_log_operation_desc operation;
	struct ntfs_bitmap_range range;
	u64 page_lcns[NTFS_LOG_BITMAP_MAX_LCNS];
};

static u32 ntfs_log_bitmap_records_per_page(
		const struct ntfs_logfile_layout *layout, u32 cluster_size)
{
	u32 max_lcns;
	u32 payload_len;
	u32 record_len;
	u32 capacity;

	if (layout->data_off >= layout->page_size)
		return 0;
	capacity = layout->page_size - layout->data_off;
	max_lcns = NTFS_LOG_BITMAP_MAX_LCNS;
	if (is_power_of_2(cluster_size) &&
	    (IS_ALIGNED(PAGE_SIZE, cluster_size) ||
	     IS_ALIGNED(cluster_size, PAGE_SIZE)))
		max_lcns = max_t(u32, 1, PAGE_SIZE / cluster_size);
	payload_len = ALIGN(sizeof(struct ntfs_log_rec_hdr) +
			max_lcns * sizeof(__le64), 8);
	payload_len = ALIGN(payload_len + sizeof(struct ntfs_bitmap_range), 8) +
			sizeof(struct ntfs_bitmap_range);
	record_len = ALIGN(layout->record_header_len + payload_len, 8);
	if (!record_len || record_len > capacity)
		return 0;
	return capacity / record_len;
}

static bool ntfs_log_bitmap_use_packing(
		const struct ntfs_logfile_layout *layout, u32 cluster_size,
		u64 records)
{
	u32 per_page = ntfs_log_bitmap_records_per_page(layout, cluster_size);

	return per_page && 2 + DIV_ROUND_UP_ULL(records, per_page) < records;
}

int ntfs_log_bitmap_packed_credits(struct ntfs_volume *vol,
		unsigned int records)
{
	struct ntfs_log *log;
	u64 credits;
	u32 per_page;
	int err;

	if (!vol)
		return -EINVAL;
	if (!records)
		return 0;
	down_read(&vol->journal_lock);
	log = vol->journal;
	if (!log || !log->running || log->aborted || log->stopping) {
		err = -EROFS;
		goto out;
	}
	per_page = ntfs_log_bitmap_records_per_page(&log->layout,
			vol->cluster_size);
	if (!ntfs_log_bitmap_use_packing(&log->layout, vol->cluster_size,
			records))
		credits = (u64)records + 1;
	else
		/* OpenAttribute, a partial first page, and one CLR spare. */
		credits = 3 + DIV_ROUND_UP_ULL((u64)records, per_page);
	err = credits > INT_MAX ? -E2BIG : credits;
out:
	up_read(&vol->journal_lock);
	return err;
}

static int ntfs_log_prepare_bitmap_operation(struct ntfs_inode *ni, s64 bit,
		u32 bits, u16 target_attr, u8 value,
		struct ntfs_log_bitmap_operation *item)
{
	struct ntfs_log_operation_desc *operation = &item->operation;
	u64 byte_pos = bit >> 3;
	u64 cluster_byte_off = byte_pos & ni->vol->cluster_size_mask;
	u64 nr_lcns;
	u32 bytes;
	int err;

	memset(item, 0, sizeof(*item));
	if ((cluster_byte_off >> NTFS_BLOCK_SIZE_BITS) > U16_MAX)
		return -E2BIG;
	operation->cluster_off = cluster_byte_off >> NTFS_BLOCK_SIZE_BITS;
	bytes = DIV_ROUND_UP((bit & 7) + bits, 8);
	nr_lcns = DIV_ROUND_UP(cluster_byte_off + bytes,
			ni->vol->cluster_size);
	if (!nr_lcns || nr_lcns > ARRAY_SIZE(item->page_lcns))
		return -E2BIG;
	err = ntfs_log_stream_lcns(ni,
			byte_pos >> ni->vol->cluster_size_bits, nr_lcns,
			item->page_lcns);
	if (err)
		return err;

	item->range.bitmap_off = cpu_to_le32(
			((cluster_byte_off & (NTFS_BLOCK_SIZE - 1)) << 3) |
			(bit & 7));
	item->range.bits = cpu_to_le32(bits);
	operation->redo_op = value ? SetBitsInNonresidentBitMap :
			ClearBitsInNonresidentBitMap;
	operation->undo_op = value ? ClearBitsInNonresidentBitMap :
			SetBitsInNonresidentBitMap;
	operation->target_attr = target_attr;
	operation->target_vcn = byte_pos >> ni->vol->cluster_size_bits;
	operation->page_lcns = item->page_lcns;
	operation->lcns_follow = nr_lcns;
	operation->undo_data = &item->range;
	operation->undo_len = sizeof(item->range);
	operation->redo_data = &item->range;
	operation->redo_len = sizeof(item->range);
	return 0;
}

int ntfs_log_bitmap_update(struct ntfs_log_handle *handle, struct inode *vi,
		s64 start_bit, s64 count, u8 value)
{
	struct ntfs_inode *ni;
	struct ntfs_inode *base_ni;
	unsigned long flags;
	u64 last_byte;
	u64 operation_lsn = 0;
	u16 target_attr;
	s64 bitmap_bytes;
	s64 bit;
	s64 remaining;
	int err;

	if (!handle || !vi || start_bit < 0 || count < 0 || value > 1)
		return -EINVAL;
	if (!count)
		return 0;
	if (start_bit > S64_MAX - count)
		return -EOVERFLOW;

	ni = NTFS_I(vi);
	if (!NInoNonResident(ni) || ni->name_len > U8_MAX)
		return -EINVAL;
	if (!ni->vol || ni->vol->cluster_size < NTFS_BLOCK_SIZE)
		return -EINVAL;
	last_byte = ((u64)start_bit + count - 1) >> 3;
	read_lock_irqsave(&ni->size_lock, flags);
	bitmap_bytes = min_t(s64, i_size_read(vi), ni->initialized_size);
	bitmap_bytes = min(bitmap_bytes, ni->allocated_size);
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (bitmap_bytes < 0 || last_byte >= (u64)bitmap_bytes)
		return -EIO;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;

	err = ntfs_log_open_attribute(handle,
			MK_MREF(base_ni->mft_no, base_ni->seq_no),
			le32_to_cpu(ni->type), 0, ni->name, ni->name_len,
			true, &target_attr);
	if (err)
		return err;

	bit = start_bit;
	remaining = count;
	while (remaining) {
		struct ntfs_log_bitmap_operation item;
		u64 page_end_bit;
		u32 bits;

		page_end_bit = ((u64)(bit >> (PAGE_SHIFT + 3)) + 1) <<
			(PAGE_SHIFT + 3);
		bits = min_t(u64, remaining, page_end_bit - bit);
		err = ntfs_log_prepare_bitmap_operation(ni, bit, bits,
				target_attr, value, &item);
		if (err)
			return err;
		err = ntfs_log_write_operation(handle, &item.operation,
				&operation_lsn);
		if (err)
			return err;

		bit += bits;
		remaining -= bits;
	}
	return ntfs_log_track_inode(handle, vi, operation_lsn);
}

int ntfs_log_bitmap_clear_runs(struct ntfs_log_handle *handle,
		struct inode *vi, const struct runlist_element *runs,
		unsigned int nr_runs)
{
	struct ntfs_log_bitmap_operation *items;
	struct ntfs_log_packed_append packed = { };
	struct ntfs_inode *base_ni;
	struct ntfs_inode *ni;
	struct ntfs_log *log;
	unsigned long flags;
	u64 operation_lsn = 0;
	u64 last_byte = 0;
	u64 records = 0;
	s64 bitmap_bytes;
	unsigned int i;
	unsigned int j = 0;
	u16 target_attr;
	int extra;
	int err;

	if (!handle || !handle->log || !vi || !runs || !nr_runs ||
	    current != handle->owner || !handle->active || handle->packed)
		return -EINVAL;
	log = handle->log;
	ni = NTFS_I(vi);
	if (!ni->vol || ni->vol != log->vol ||
	    ni->vol->cluster_size < NTFS_BLOCK_SIZE ||
	    !NInoNonResident(ni) || ni->name_len > U8_MAX)
		return -EINVAL;
	for (i = 0; i < nr_runs; i++) {
		u64 end;

		if (runs[i].lcn < 0 || runs[i].length <= 0 ||
		    runs[i].lcn > S64_MAX - runs[i].length)
			return -EIO;
		end = (u64)runs[i].lcn + runs[i].length - 1;
		last_byte = max(last_byte, end >> 3);
		extra = ntfs_log_bitmap_update_credits(runs[i].lcn,
				runs[i].length);
		if (extra < 0)
			return extra;
		if (check_add_overflow(records, (u64)extra - 1, &records) ||
		    records > INT_MAX)
			return -E2BIG;
	}
	read_lock_irqsave(&ni->size_lock, flags);
	bitmap_bytes = min_t(s64, i_size_read(vi), ni->initialized_size);
	bitmap_bytes = min(bitmap_bytes, ni->allocated_size);
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (bitmap_bytes < 0 || last_byte >= (u64)bitmap_bytes)
		return -EIO;
	if (!ntfs_log_bitmap_use_packing(&log->layout, ni->vol->cluster_size,
			records)) {
		for (i = 0; i < nr_runs; i++) {
			err = ntfs_log_bitmap_update(handle, vi, runs[i].lcn,
					runs[i].length, 0);
			if (err)
				return err;
		}
		return 0;
	}
	items = kvmalloc_array(records, sizeof(*items), GFP_NOFS);
	if (!items)
		return -ENOMEM;
	for (i = 0; i < nr_runs; i++) {
		s64 bit = runs[i].lcn;
		s64 remaining = runs[i].length;

		while (remaining) {
			u64 page_end = ((u64)(bit >> (PAGE_SHIFT + 3)) + 1) <<
					(PAGE_SHIFT + 3);
			u32 bits = min_t(u64, remaining, page_end - bit);

			if (WARN_ON_ONCE(j >= records)) {
				err = -EIO;
				goto out;
			}
			err = ntfs_log_prepare_bitmap_operation(ni, bit, bits,
					0, 0, &items[j++]);
			if (err)
				goto out;
			bit += bits;
			remaining -= bits;
		}
	}
	if (WARN_ON_ONCE(j != records)) {
		err = -EIO;
		goto out;
	}
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni) {
		err = -EINVAL;
		goto out;
	}
	err = ntfs_log_open_attribute(handle,
			MK_MREF(base_ni->mft_no, base_ni->seq_no),
			le32_to_cpu(ni->type), 0, ni->name, ni->name_len,
			true, &target_attr);
	if (err)
		goto out;

	mutex_lock(&log->append_lock);
	if (handle->next_packed_group == U32_MAX) {
		err = -EOVERFLOW;
		goto out_unlock;
	}
	packed.group = ++handle->next_packed_group;
	handle->packed = &packed;
	for (i = 0; i < records; i++) {
		items[i].operation.target_attr = target_attr;
		err = ntfs_log_write_operation(handle, &items[i].operation,
				&operation_lsn);
		if (err)
			break;
	}
	handle->packed = NULL;
out_unlock:
	mutex_unlock(&log->append_lock);
	if (!err)
		err = ntfs_log_track_inode(handle, vi, operation_lsn);
out:
	kvfree(items);
	return err;
}

static int ntfs_log_mft_record_geometry(struct ntfs_volume *vol, u64 mft_no,
		u64 *target_vcn, u16 *cluster_off, u16 *lcns_follow)
{
	u64 byte_pos;
	u64 cluster_byte_off;
	u64 nr_lcns;

	if (!vol || !target_vcn || !cluster_off || !lcns_follow ||
	    check_shl_overflow(mft_no, vol->mft_record_size_bits, &byte_pos))
		return -EOVERFLOW;
	cluster_byte_off = byte_pos & vol->cluster_size_mask;
	if (!IS_ALIGNED(cluster_byte_off, NTFS_BLOCK_SIZE))
		return -EINVAL;
	if ((cluster_byte_off >> NTFS_BLOCK_SIZE_BITS) > U16_MAX)
		return -E2BIG;
	if ((byte_pos >> vol->cluster_size_bits) > S64_MAX)
		return -E2BIG;
	nr_lcns = DIV_ROUND_UP(cluster_byte_off + vol->mft_record_size,
			vol->cluster_size);
	if (!nr_lcns || nr_lcns > U16_MAX)
		return -E2BIG;

	*target_vcn = byte_pos >> vol->cluster_size_bits;
	*cluster_off = cluster_byte_off >> NTFS_BLOCK_SIZE_BITS;
	*lcns_follow = nr_lcns;
	return 0;
}

static int ntfs_log_nonresident_operation_credits(struct ntfs_volume *vol,
		u16 lcns_follow, u16 undo_len, u16 redo_len)
{
	struct ntfs_log *log;
	u32 operation_header;
	u32 undo_off;
	u32 redo_off;
	u32 payload_len;
	u32 record_len;
	u32 page_capacity;
	int credits;

	if (!vol || !lcns_follow)
		return -EROFS;
	down_read(&vol->journal_lock);
	log = vol->journal;
	if (!log) {
		credits = -EROFS;
		goto out;
	}
	operation_header = struct_size((struct ntfs_log_rec_hdr *)NULL,
			page_lcns, max_t(u16, 1, lcns_follow));
	undo_off = ALIGN(operation_header, 8);
	if (check_add_overflow(undo_off, (u32)undo_len, &redo_off)) {
		credits = -EOVERFLOW;
		goto out;
	}
	redo_off = ALIGN(redo_off, 8);
	if (check_add_overflow(redo_off, (u32)redo_len, &payload_len) ||
	    undo_off > U16_MAX || redo_off > U16_MAX) {
		credits = -EOVERFLOW;
		goto out;
	}
	if (check_add_overflow(log->layout.record_header_len, payload_len,
			&record_len)) {
		credits = -EOVERFLOW;
		goto out;
	}
	page_capacity = log->layout.page_size - log->layout.data_off;
	/* One OpenNonresidentAttribute record plus the MFT operation pages. */
	credits = 1 + DIV_ROUND_UP(record_len, page_capacity);
out:
	up_read(&vol->journal_lock);
	return credits;
}

int ntfs_log_nonresident_value_update_credits(struct ntfs_volume *vol,
		u32 bytes, bool has_undo)
{
	u64 chunks;
	u64 credits;
	u64 nr_lcns;
	int operation_credits;

	if (!bytes)
		return 0;
	if (!vol || vol->cluster_size < NTFS_BLOCK_SIZE)
		return -EINVAL;
	chunks = DIV_ROUND_UP_ULL((u64)bytes +
			NTFS_LOG_NONRESIDENT_CHUNK_SIZE - 1,
			NTFS_LOG_NONRESIDENT_CHUNK_SIZE);
	nr_lcns = DIV_ROUND_UP_ULL(vol->cluster_size - 1ULL +
			NTFS_LOG_NONRESIDENT_CHUNK_SIZE, vol->cluster_size);
	if (!nr_lcns || nr_lcns > U16_MAX)
		return -E2BIG;
	operation_credits = ntfs_log_nonresident_operation_credits(vol,
			nr_lcns,
			has_undo ? NTFS_LOG_NONRESIDENT_CHUNK_SIZE : 0,
			NTFS_LOG_NONRESIDENT_CHUNK_SIZE);
	if (operation_credits < 0)
		return operation_credits;
	/* The open-attribute record is shared by all chunks. */
	if (check_mul_overflow(chunks, (u64)operation_credits - 1,
			&credits) || check_add_overflow(credits, 1ULL, &credits) ||
	    credits > INT_MAX)
		return -EOVERFLOW;
	return credits;
}

int ntfs_log_nonresident_value_prefix_credits(struct ntfs_volume *vol,
		u32 max_bytes)
{
	u64 chunks;
	u64 credits;
	u64 nr_lcns;
	u32 chunk_size;
	int operation_credits;

	if (!max_bytes)
		return 0;
	if (!vol || vol->cluster_size < NTFS_BLOCK_SIZE)
		return -EINVAL;
	chunk_size = min(max_bytes, NTFS_LOG_NONRESIDENT_CHUNK_SIZE);
	chunks = DIV_ROUND_UP_ULL((u64)max_bytes,
			NTFS_LOG_NONRESIDENT_CHUNK_SIZE);
	nr_lcns = DIV_ROUND_UP_ULL(vol->cluster_size - 1ULL + chunk_size,
			vol->cluster_size);
	if (!nr_lcns || nr_lcns > U16_MAX)
		return -E2BIG;
	operation_credits = ntfs_log_nonresident_operation_credits(vol,
			nr_lcns, chunk_size, chunk_size);
	if (operation_credits < 0)
		return operation_credits;
	if (check_mul_overflow(chunks, (u64)operation_credits - 1,
			&credits) || check_add_overflow(credits, 1ULL, &credits) ||
	    credits > INT_MAX)
		return -EOVERFLOW;
	return credits;
}

static int ntfs_log_mft_operation_credits(struct ntfs_volume *vol,
		u16 undo_len, u16 redo_len)
{
	u64 target_vcn;
	u16 cluster_off;
	u16 lcns_follow;
	int err;

	err = ntfs_log_mft_record_geometry(vol, 0, &target_vcn,
			&cluster_off, &lcns_follow);
	if (err)
		return err;
	return ntfs_log_nonresident_operation_credits(vol, lcns_follow,
			undo_len, redo_len);
}

int ntfs_log_mft_record_credits(struct ntfs_volume *vol)
{
	if (!vol || !vol->journal)
		return -EROFS;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;

	return ntfs_log_mft_operation_credits(vol, vol->mft_record_size, 0);
}

int ntfs_log_mft_attribute_credits(struct ntfs_volume *vol, u16 undo_len,
		u16 redo_len)
{
	return ntfs_log_mft_operation_credits(vol, undo_len, redo_len);
}

static int ntfs_log_mft_operation_common(struct ntfs_log_handle *handle,
					 u64 mft_no, u16 record_off, u16 attr_off, u16 redo_op,
					 const void *redo_data, u16 redo_len, u16 undo_op,
					 const void *undo_data, u16 undo_len,
					 bool mft_runlist_locked, u64 *lsn_out)
{
	struct ntfs_log_operation_desc operation = { };
	struct ntfs_volume *vol;
	struct ntfs_inode *mft_ni;
	u64 *page_lcns;
	u64 single_lcn;
	u64 target_vcn;
	u16 target_attr;
	u16 cluster_off;
	u16 lcns_follow;
	int err;

	if (!handle || !handle->log || (redo_len && !redo_data) ||
	    (undo_len && !undo_data))
		return -EINVAL;
	vol = handle->log->vol;
	mft_ni = NTFS_I(vol->mft_ino);
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	if (record_off > vol->mft_record_size ||
	    attr_off > vol->mft_record_size - record_off ||
	    redo_len > vol->mft_record_size - record_off - attr_off ||
	    undo_len > vol->mft_record_size - record_off - attr_off)
		return -EINVAL;
	err = ntfs_log_mft_record_geometry(vol, mft_no, &target_vcn,
			&cluster_off, &lcns_follow);
	if (err)
		return err;

	page_lcns = &single_lcn;
	if (lcns_follow > 1) {
		page_lcns = kmalloc_array(lcns_follow, sizeof(*page_lcns), GFP_NOFS);
		if (!page_lcns)
			return -ENOMEM;
	}
	if (mft_runlist_locked)
		err = ntfs_log_stream_lcns_locked(mft_ni, target_vcn,
						  lcns_follow, page_lcns);
	else
		err = ntfs_log_stream_lcns(mft_ni, target_vcn, lcns_follow,
					   page_lcns);
	if (err)
		goto out;
	err = ntfs_log_open_attribute(handle,
			MK_MREF(mft_ni->mft_no, mft_ni->seq_no),
			le32_to_cpu(AT_DATA), 0, NULL, 0, true, &target_attr);
	if (err)
		goto out;

	operation.redo_op = redo_op;
	operation.undo_op = undo_op;
	operation.target_attr = target_attr;
	operation.record_off = record_off;
	operation.attr_off = attr_off;
	operation.cluster_off = cluster_off;
	operation.target_vcn = target_vcn;
	operation.page_lcns = page_lcns;
	operation.lcns_follow = lcns_follow;
	operation.redo_data = redo_data;
	operation.redo_len = redo_len;
	operation.undo_data = undo_data;
	operation.undo_len = undo_len;
	err = ntfs_log_write_operation(handle, &operation, lsn_out);
out:
	if (page_lcns != &single_lcn)
		kfree(page_lcns);
	return err;
}

static int ntfs_log_mft_operation(struct ntfs_log_handle *handle, u64 mft_no,
				  u16 record_off, u16 attr_off, u16 redo_op, const void *redo_data,
				  u16 redo_len, u16 undo_op, const void *undo_data, u16 undo_len,
				  u64 *lsn_out)
{
	return ntfs_log_mft_operation_common(handle, mft_no, record_off,
			attr_off, redo_op, redo_data, redo_len, undo_op, undo_data,
			undo_len, false, lsn_out);
}

int ntfs_log_mft_record_initialize(struct ntfs_log_handle *handle, u64 mft_no,
		const struct mft_record *record, u64 *lsn_out)
{
	if (!handle || !handle->log || !record)
		return -EINVAL;
	if (handle->log->vol->mft_record_size > U16_MAX)
		return -E2BIG;

	return ntfs_log_mft_operation(handle, mft_no, 0, 0,
			InitializeFileRecordSegment, record,
			handle->log->vol->mft_record_size,
			DeallocateFileRecordSegment, NULL, 0, lsn_out);
}

/* Log before and after images of an existing MFT record. */
int ntfs_log_mft_record_update(struct ntfs_log_handle *handle, u64 mft_no,
		const struct mft_record *before, const struct mft_record *after,
		u64 *lsn_out)
{
	u32 bytes;

	if (!handle || !handle->log || !before || !after)
		return -EINVAL;
	bytes = handle->log->vol->mft_record_size;
	if (bytes > U16_MAX)
		return -E2BIG;
	return ntfs_log_mft_operation(handle, mft_no, 0, 0,
			InitializeFileRecordSegment, after, bytes,
			InitializeFileRecordSegment, before, bytes, lsn_out);
}

int ntfs_log_mft_record_deallocate(struct ntfs_log_handle *handle, u64 mft_no,
		const struct mft_record *record, u64 *lsn_out)
{
	if (!handle || !handle->log || !record)
		return -EINVAL;
	if (handle->log->vol->mft_record_size > U16_MAX)
		return -E2BIG;

	return ntfs_log_mft_operation(handle, mft_no, 0, 0,
			DeallocateFileRecordSegment, NULL, 0,
			InitializeFileRecordSegment, record,
			handle->log->vol->mft_record_size, lsn_out);
}

static int ntfs_log_validate_attribute(struct ntfs_volume *vol,
		u16 record_off, const struct attr_record *attr, u16 attr_len)
{
	u16 header_len;

	if (!vol || !attr)
		return -EINVAL;
	header_len = offsetof(struct attr_record, data) +
		(attr->non_resident ? sizeof(attr->data.non_resident) :
		 sizeof(attr->data.resident));
	if (attr_len < header_len || !IS_ALIGNED(attr_len, 8) ||
	    le32_to_cpu(attr->length) != attr_len ||
	    !IS_ALIGNED(record_off, 8) ||
	    record_off > vol->mft_record_size ||
	    attr_len > vol->mft_record_size - record_off)
		return -EINVAL;
	return 0;
}

int ntfs_log_mft_attribute_create(struct ntfs_log_handle *handle, u64 mft_no,
		u16 record_off, const struct attr_record *attr, u16 attr_len,
		u64 *lsn_out)
{
	int err;

	if (!handle || !handle->log)
		return -EINVAL;
	err = ntfs_log_validate_attribute(handle->log->vol, record_off, attr,
			attr_len);
	if (err)
		return err;

	return ntfs_log_mft_operation(handle, mft_no, record_off, 0,
			CreateAttribute, attr, attr_len, DeleteAttribute, NULL, 0,
			lsn_out);
}

int ntfs_log_mft_attribute_delete(struct ntfs_log_handle *handle, u64 mft_no,
		u16 record_off, const struct attr_record *attr, u16 attr_len,
		u64 *lsn_out)
{
	int err;

	if (!handle || !handle->log)
		return -EINVAL;
	err = ntfs_log_validate_attribute(handle->log->vol, record_off, attr,
			attr_len);
	if (err)
		return err;

	return ntfs_log_mft_operation(handle, mft_no, record_off, 0,
			DeleteAttribute, NULL, 0, CreateAttribute, attr, attr_len,
			lsn_out);
}

int ntfs_log_mft_resident_update(struct ntfs_log_handle *handle, u64 mft_no,
		u16 record_off, u16 attr_off, const void *old_data, u16 old_len,
		const void *new_data, u16 new_len, u64 *lsn_out)
{
	/*
	 * Equal lengths describe an in-place overwrite.  Differing lengths
	 * describe a resize whose old/new value ends are attr_off + old/new_len.
	 * Callers must therefore pass the complete changed tail in that case.
	 */
	if (!handle || !handle->log || !IS_ALIGNED(record_off, 8))
		return -EINVAL;

	return ntfs_log_mft_operation(handle, mft_no, record_off, attr_off,
			UpdateResidentValue, new_data, new_len,
			UpdateResidentValue, old_data, old_len, lsn_out);
}

int ntfs_log_mft_mapping_pairs_credits(struct ntfs_volume *vol,
		u16 old_len, u16 new_len)
{
	if (!old_len || !new_len)
		return -EINVAL;
	return ntfs_log_mft_operation_credits(vol, old_len, new_len);
}

static u64 ntfs_log_mapping_pair_unsigned(const u8 *bytes, u8 width)
{
	u64 value = 0;

	while (width)
		value = (value << 8) | bytes[--width];
	return value;
}

static s64 ntfs_log_mapping_pair_signed(const u8 *bytes, u8 width)
{
	u64 value = ntfs_log_mapping_pair_unsigned(bytes, width);

	if (width < sizeof(s64) && (bytes[width - 1] & 0x80))
		value |= U64_MAX << (width * 8);
	return value;
}

static int ntfs_log_validate_mapping_pairs(const void *pairs, u16 len)
{
	const u8 *bytes = pairs;
	s64 current_lcn = 0;
	u64 next_vcn = 0;
	u16 pos = 0;

	if (!pairs || !len)
		return -EINVAL;
	while (pos < len && bytes[pos]) {
		u8 length_bytes = bytes[pos] & 0xf;
		u8 offset_bytes = bytes[pos] >> 4;
		u64 run_length;
		u16 entry_len = 1 + length_bytes + offset_bytes;

		if (!length_bytes || length_bytes > sizeof(u64) ||
		    offset_bytes > sizeof(s64) ||
		    entry_len > len - pos)
			return -EINVAL;
		run_length = ntfs_log_mapping_pair_unsigned(bytes + pos + 1,
				length_bytes);
		if (!run_length || check_add_overflow(next_vcn, run_length,
				&next_vcn) || next_vcn > S64_MAX)
			return -EINVAL;
		if (offset_bytes) {
			s64 delta = ntfs_log_mapping_pair_signed(bytes + pos + 1 +
					length_bytes, offset_bytes);

			if (check_add_overflow(current_lcn, delta, &current_lcn) ||
			    current_lcn < 0)
				return -EINVAL;
		}
		pos += entry_len;
	}
	if (pos == len)
		return -EINVAL;
	return 0;
}

static int ntfs_log_mft_mapping_pairs_common(struct ntfs_log_handle *handle,
					     u64 mft_no, u16 record_off, u16 attr_off,
					     const void *old_pairs, u16 old_len,
					     const void *new_pairs, u16 new_len,
					     bool mft_runlist_locked, u64 *lsn_out)
{
	int err;

	if (!handle || !handle->log || !IS_ALIGNED(record_off, 8) ||
	    !IS_ALIGNED(attr_off, 8) ||
	    attr_off < offsetof(struct attr_record,
			data.non_resident.compressed_size))
		return -EINVAL;
	err = ntfs_log_validate_mapping_pairs(old_pairs, old_len);
	if (err)
		return err;
	err = ntfs_log_validate_mapping_pairs(new_pairs, new_len);
	if (err)
		return err;

	return ntfs_log_mft_operation_common(handle, mft_no, record_off,
			attr_off, UpdateMappingPairs, new_pairs, new_len,
			UpdateMappingPairs, old_pairs, old_len, mft_runlist_locked,
			lsn_out);
}

int ntfs_log_mft_mapping_pairs_update(struct ntfs_log_handle *handle,
				      u64 mft_no, u16 record_off, u16 attr_off,
		const void *old_pairs, u16 old_len,
		const void *new_pairs, u16 new_len, u64 *lsn_out)
{
	return ntfs_log_mft_mapping_pairs_common(handle, mft_no,
			record_off, attr_off, old_pairs, old_len, new_pairs,
			new_len, false, lsn_out);
}

int ntfs_log_mft_mapping_pairs_locked(struct ntfs_log_handle *handle,
				      u64 mft_no, u16 record_off, u16 attr_off,
				      const void *old_pairs, u16 old_len, const void *new_pairs,
				      u16 new_len, u64 *lsn_out)
{
	return ntfs_log_mft_mapping_pairs_common(handle, mft_no,
			record_off, attr_off, old_pairs, old_len, new_pairs,
			new_len, true, lsn_out);
}

int ntfs_log_mft_attribute_sizes_credits(struct ntfs_volume *vol,
		bool has_compressed_size)
{
	u16 len = has_compressed_size ?
		sizeof(struct ntfs_new_attribute_sizes) :
		offsetof(struct ntfs_new_attribute_sizes, total_size);

	return ntfs_log_mft_operation_credits(vol, len, len);
}

static int ntfs_log_validate_attribute_sizes(
		struct ntfs_volume *vol,
		const struct ntfs_new_attribute_sizes *sizes,
		bool has_compressed_size)
{
	if (!vol || !vol->cluster_size || !sizes ||
	    le64_to_cpu(sizes->alloc_size) > S64_MAX ||
	    !IS_ALIGNED(le64_to_cpu(sizes->alloc_size), vol->cluster_size) ||
	    le64_to_cpu(sizes->data_size) > S64_MAX ||
	    (has_compressed_size &&
	     (le64_to_cpu(sizes->total_size) > S64_MAX ||
	      !IS_ALIGNED(le64_to_cpu(sizes->total_size),
		      vol->cluster_size))) ||
	    le64_to_cpu(sizes->valid_size) >
			le64_to_cpu(sizes->data_size))
		return -EINVAL;
	return 0;
}

/* append_lock must be held. Only the unsealed packing page is mutable here. */
static bool ntfs_log_aggregate_coalesce_sizes(
		struct ntfs_log *log, struct ntfs_log_aggregate_record *tail,
		const struct ntfs_log_operation_desc *operation, u64 current_lsn,
		u64 *lsn_out)
{
	struct ntfs_log_handle *active;
	struct ntfs_lfs_record_hdr *lfs;
	struct ntfs_log_rec_hdr *lrh;
	u64 byte_off;
	u64 head_lsn;
	u64 result_lsn;
	u32 client_len;
	u32 header_len;
	u16 redo_off;
	u16 undo_off;
	u16 undo_len;

	if (!tail->committed || !tail->mergeable ||
	    !ntfs_log_same_overwrite_target(&tail->operation, operation))
		return false;
	list_for_each_entry(active, &log->active_handles, active_list)
		if (active->transaction_id == tail->transaction_id)
			return false;
	if (!log->pending_page ||
	    ntfs_lsn_to_byte_off(&log->layout, tail->lsn, &byte_off) ||
	    (byte_off & ~((u64)log->layout.page_mask)) != log->pending_page_off)
		return false;
	lrh = ntfs_log_aggregate_record_header(log, log->pending_page,
			byte_off & log->layout.page_mask, tail);
	if (!lrh)
		return false;
	lfs = (void *)((u8 *)log->pending_page +
			(byte_off & log->layout.page_mask));
	client_len = le32_to_cpu(lfs->client_data_len);
	header_len = struct_size(lrh, page_lcns,
			max_t(u16, 1, operation->lcns_follow));
	redo_off = le16_to_cpu(lrh->redo_off);
	undo_off = le16_to_cpu(lrh->undo_off);
	undo_len = le16_to_cpu(lrh->undo_len);
	if (redo_off < header_len || undo_off < header_len ||
	    undo_len != operation->undo_len || undo_off > client_len ||
	    undo_len > client_len - undo_off ||
	    (redo_off < undo_off + undo_len &&
	     undo_off < redo_off + operation->redo_len) ||
	    memcmp((u8 *)lrh + redo_off, operation->undo_data,
			operation->undo_len))
		return false;

	head_lsn = log->head_lsn;
	result_lsn = tail->lsn;
	if (current_lsn && log->oldest_lsn && head_lsn &&
	    ntfs_log_lsn_before_eq(&log->layout, log->oldest_lsn, current_lsn) &&
	    ntfs_log_lsn_before_eq(&log->layout, current_lsn, head_lsn) &&
	    ntfs_log_lsn_before_eq(&log->layout, tail->lsn, current_lsn))
		result_lsn = current_lsn;
	memcpy((u8 *)lrh + redo_off, operation->redo_data, operation->redo_len);
	*lsn_out = result_lsn;
	return true;
}

/*
 * The two redo records must belong to the same committed transaction and
 * still describe the current MFT image.  Validate both before changing either.
 */
static bool ntfs_log_aggregate_coalesce_mapping_sizes(struct ntfs_log *log,
		struct ntfs_log_aggregate_record *tail,
		const struct ntfs_log_operation_desc *sizes,
		const struct ntfs_log_operation_desc *mapping,
		u64 current_lsn, u64 *lsn_out)
{
	struct ntfs_log_aggregate_record *map_anchor;
	struct ntfs_lfs_record_hdr *lfs;
	struct ntfs_log_rec_hdr *lrh;
	u64 byte_off;
	u32 client_len;
	u32 header_len;
	u16 redo_off;
	u16 undo_off;
	u16 undo_len;

	if (!mapping->undo_data || !mapping->redo_data ||
	    mapping->undo_len != mapping->redo_len ||
	    tail->batch_list.prev == &log->aggregate_records)
		return false;
	map_anchor = list_entry(tail->batch_list.prev,
			struct ntfs_log_aggregate_record, batch_list);
	if (!map_anchor->committed || !map_anchor->mergeable ||
	    map_anchor->transaction_id != tail->transaction_id ||
	    !ntfs_log_same_overwrite_target(&map_anchor->operation, mapping) ||
	    !log->pending_page ||
	    ntfs_lsn_to_byte_off(&log->layout, map_anchor->lsn, &byte_off) ||
	    (byte_off & ~((u64)log->layout.page_mask)) != log->pending_page_off)
		return false;
	lrh = ntfs_log_aggregate_record_header(log, log->pending_page,
			byte_off & log->layout.page_mask, map_anchor);
	if (!lrh)
		return false;
	lfs = (void *)((u8 *)log->pending_page +
			(byte_off & log->layout.page_mask));
	client_len = le32_to_cpu(lfs->client_data_len);
	header_len = struct_size(lrh, page_lcns,
			max_t(u16, 1, mapping->lcns_follow));
	redo_off = le16_to_cpu(lrh->redo_off);
	undo_off = le16_to_cpu(lrh->undo_off);
	undo_len = le16_to_cpu(lrh->undo_len);
	if (redo_off < header_len || undo_off < header_len || !undo_len ||
	    undo_len != map_anchor->operation.undo_len ||
	    undo_off > client_len || undo_len > client_len - undo_off ||
	    (redo_off < undo_off + undo_len &&
	     undo_off < redo_off + mapping->redo_len) ||
	    memcmp((u8 *)lrh + redo_off, mapping->undo_data,
			mapping->undo_len))
		return false;
	if (!ntfs_log_aggregate_coalesce_sizes(log, tail, sizes, current_lsn,
			lsn_out))
		return false;
	memcpy((u8 *)lrh + redo_off, mapping->redo_data, mapping->redo_len);
	return true;
}

static int __ntfs_log_mft_attribute_sizes_coalesce(struct ntfs_log *log, u64 mft_no,
		u16 record_off, const struct ntfs_new_attribute_sizes *old_sizes,
		const struct ntfs_new_attribute_sizes *new_sizes,
		bool has_compressed_size, u64 current_lsn, u64 *lsn_out,
		u16 mapping_off, const void *old_pairs, const void *new_pairs,
		u16 pairs_len)
{
	struct ntfs_log_operation_desc operation = { };
	struct ntfs_log_operation_desc mapping;
	struct ntfs_log_aggregate_record *tail;
	struct ntfs_log_open_attr *entry;
	struct ntfs_volume *vol = log->vol;
	struct ntfs_inode *mft_ni = NTFS_I(vol->mft_ino);
	u64 target_vcn;
	u64 lcn;
	u16 cluster_off;
	u16 lcns_follow;
	u16 len;
	int err = -EAGAIN;

	if (!lsn_out || !IS_ALIGNED(record_off, 8) ||
	    ntfs_log_validate_attribute_sizes(vol, old_sizes, has_compressed_size) ||
	    ntfs_log_validate_attribute_sizes(vol, new_sizes, has_compressed_size))
		return -EAGAIN;
	len = has_compressed_size ? sizeof(*old_sizes) :
		offsetof(struct ntfs_new_attribute_sizes, total_size);
	if (record_off > vol->mft_record_size ||
	    len > vol->mft_record_size - record_off ||
	    ntfs_log_mft_record_geometry(vol, mft_no, &target_vcn,
			&cluster_off, &lcns_follow) || lcns_follow != 1 ||
	    ntfs_log_stream_lcns(mft_ni, target_vcn, 1, &lcn))
		return -EAGAIN;

	mutex_lock(&log->open_attr_lock);
	entry = ntfs_log_find_open_attr(log,
			MK_MREF(mft_ni->mft_no, mft_ni->seq_no),
			le32_to_cpu(AT_DATA), 0, NULL, 0, true);
	if (entry)
		operation.target_attr = entry->slot;
	mutex_unlock(&log->open_attr_lock);
	if (!operation.target_attr)
		return -EAGAIN;

	operation.redo_op = operation.undo_op = SetNewAttributeSizes;
	operation.record_off = record_off;
	operation.cluster_off = cluster_off;
	operation.target_vcn = target_vcn;
	operation.page_lcns = &lcn;
	operation.lcns_follow = 1;
	operation.undo_data = old_sizes;
	operation.undo_len = len;
	operation.redo_data = new_sizes;
	operation.redo_len = len;
	if (old_pairs) {
		mapping = operation;
		mapping.redo_op = mapping.undo_op = UpdateMappingPairs;
		mapping.attr_off = mapping_off;
		mapping.undo_data = old_pairs;
		mapping.undo_len = pairs_len;
		mapping.redo_data = new_pairs;
		mapping.redo_len = pairs_len;
	}
	mutex_lock(&log->append_lock);
	if (NVolShutdown(vol) || !log->running || log->aborted ||
	    log->stopping || !log->pending_lsn || !log->aggregate_hash)
		goto out_unlock;
	hlist_for_each_entry(tail,
			&log->aggregate_hash[ntfs_log_aggregate_unit_hash(&operation)],
			hash_node) {
		if (!ntfs_log_same_aggregate_unit(&tail->operation, &operation))
			continue;
		if (old_pairs ?
		    ntfs_log_aggregate_coalesce_mapping_sizes(log, tail, &operation,
				&mapping, current_lsn, lsn_out) :
		    ntfs_log_aggregate_coalesce_sizes(log, tail, &operation,
				current_lsn, lsn_out)) {
			atomic64_inc(&log->home_generation);
			ntfs_log_recording_account(NTFS_LOG_RECORDING_SIZE_COALESCE, 1);
			if (old_pairs)
				ntfs_log_recording_account(
						NTFS_LOG_RECORDING_MAPPING_COALESCE, 1);
			queue_delayed_work(system_long_wq, &log->flush_work,
					log->commit_interval);
			err = 0;
		}
		break;
	}
out_unlock:
	mutex_unlock(&log->append_lock);
	return err;
}

int ntfs_log_mft_attribute_sizes_coalesce(struct ntfs_log *log, u64 mft_no,
		u16 record_off, const struct ntfs_new_attribute_sizes *old_sizes,
		const struct ntfs_new_attribute_sizes *new_sizes,
		bool has_compressed_size, u64 current_lsn, u64 *lsn_out)
{
	return __ntfs_log_mft_attribute_sizes_coalesce(log, mft_no, record_off,
			old_sizes, new_sizes, has_compressed_size, current_lsn,
			lsn_out, 0, NULL, NULL, 0);
}

int ntfs_log_mft_mapping_sizes_coalesce(struct ntfs_log *log, u64 mft_no,
		u16 record_off, u16 mapping_off, const void *old_pairs,
		const void *new_pairs, u16 pairs_len,
		const struct ntfs_new_attribute_sizes *old_sizes,
		const struct ntfs_new_attribute_sizes *new_sizes,
		u64 current_lsn, u64 *lsn_out)
{
	struct ntfs_volume *vol = log->vol;

	if (!IS_ALIGNED(mapping_off, 8) ||
	    mapping_off < offsetof(struct attr_record,
			data.non_resident.compressed_size) + sizeof(__le64) ||
	    record_off > vol->mft_record_size ||
	    mapping_off > vol->mft_record_size - record_off ||
	    pairs_len > vol->mft_record_size - record_off - mapping_off ||
	    ntfs_log_validate_mapping_pairs(old_pairs, pairs_len) ||
	    ntfs_log_validate_mapping_pairs(new_pairs, pairs_len))
		return -EAGAIN;
	return __ntfs_log_mft_attribute_sizes_coalesce(log, mft_no, record_off,
			old_sizes, new_sizes, true, current_lsn, lsn_out,
			mapping_off, old_pairs, new_pairs, pairs_len);
}

static int ntfs_log_mft_attribute_sizes_common(struct ntfs_log_handle *handle,
					       u64 mft_no, u16 record_off,
					       const struct ntfs_new_attribute_sizes *old_sizes,
					       const struct ntfs_new_attribute_sizes *new_sizes,
					       bool has_compressed_size, bool mft_runlist_locked,
					       u64 *lsn_out)
{
	u16 len;
	int err;

	if (!handle || !handle->log || !IS_ALIGNED(record_off, 8))
		return -EINVAL;
	err = ntfs_log_validate_attribute_sizes(handle->log->vol, old_sizes,
			has_compressed_size);
	if (err)
		return err;
	err = ntfs_log_validate_attribute_sizes(handle->log->vol, new_sizes,
			has_compressed_size);
	if (err)
		return err;
	len = has_compressed_size ? sizeof(*old_sizes) :
		offsetof(struct ntfs_new_attribute_sizes, total_size);

	return ntfs_log_mft_operation_common(handle, mft_no, record_off, 0,
			SetNewAttributeSizes, new_sizes, len,
			SetNewAttributeSizes, old_sizes, len,
			mft_runlist_locked, lsn_out);
}

int ntfs_log_mft_attribute_sizes_update(struct ntfs_log_handle *handle,
					u64 mft_no, u16 record_off,
		const struct ntfs_new_attribute_sizes *old_sizes,
		const struct ntfs_new_attribute_sizes *new_sizes,
		bool has_compressed_size, u64 *lsn_out)
{
	return ntfs_log_mft_attribute_sizes_common(handle, mft_no,
			record_off, old_sizes, new_sizes, has_compressed_size,
			false, lsn_out);
}

int ntfs_log_mft_attribute_sizes_locked(struct ntfs_log_handle *handle,
					u64 mft_no, u16 record_off,
					const struct ntfs_new_attribute_sizes *old_sizes,
					const struct ntfs_new_attribute_sizes *new_sizes,
					bool has_compressed_size, u64 *lsn_out)
{
	return ntfs_log_mft_attribute_sizes_common(handle, mft_no,
			record_off, old_sizes, new_sizes, has_compressed_size,
			true, lsn_out);
}

int ntfs_log_index_root_credits(struct ntfs_volume *vol, u16 entry_len)
{
	if (entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8))
		return -EINVAL;
	return ntfs_log_mft_operation_credits(vol, 0, entry_len);
}

static int ntfs_log_validate_index_entry(const struct index_entry *entry,
		u16 entry_len)
{
	u32 minimum_len;

	if (!entry || entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8) || le16_to_cpu(entry->length) != entry_len)
		return -EINVAL;
	minimum_len = sizeof(struct index_entry_header) +
		le16_to_cpu(entry->key_length);
	if (entry->flags & INDEX_ENTRY_NODE)
		minimum_len += sizeof(__le64);
	if (minimum_len > entry_len)
		return -EINVAL;
	return 0;
}

int ntfs_log_index_root_add(struct ntfs_log_handle *handle, u64 mft_no,
		u16 record_off, u16 attr_off, const struct index_entry *entry,
		u16 entry_len, u64 *lsn_out)
{
	int err;

	err = ntfs_log_validate_index_entry(entry, entry_len);
	if (err)
		return err;
	if (!IS_ALIGNED(record_off, 8) || !IS_ALIGNED(attr_off, 8))
		return -EINVAL;

	return ntfs_log_mft_operation(handle, mft_no, record_off, attr_off,
			AddIndexEntryRoot, entry, entry_len,
			DeleteIndexEntryRoot, NULL, 0, lsn_out);
}

int ntfs_log_index_root_delete(struct ntfs_log_handle *handle, u64 mft_no,
		u16 record_off, u16 attr_off, const struct index_entry *entry,
		u16 entry_len, u64 *lsn_out)
{
	int err;

	err = ntfs_log_validate_index_entry(entry, entry_len);
	if (err)
		return err;
	if (!IS_ALIGNED(record_off, 8) || !IS_ALIGNED(attr_off, 8))
		return -EINVAL;

	return ntfs_log_mft_operation(handle, mft_no, record_off, attr_off,
			DeleteIndexEntryRoot, NULL, 0,
			AddIndexEntryRoot, entry, entry_len, lsn_out);
}

static int ntfs_log_index_block_geometry(struct ntfs_volume *vol,
		u32 bytes_per_index, u64 byte_pos, u64 *target_vcn,
		u16 *cluster_off, u16 *record_off, u16 *lcns_follow)
{
	u64 cluster_byte_off;
	u64 nr_lcns;

	if (!vol || !target_vcn || !cluster_off || !record_off ||
	    !lcns_follow || vol->cluster_size < NTFS_BLOCK_SIZE ||
	    bytes_per_index < NTFS_BLOCK_SIZE ||
	    bytes_per_index > U16_MAX ||
	    !is_power_of_2(bytes_per_index) ||
	    !IS_ALIGNED(byte_pos, NTFS_BLOCK_SIZE))
		return -EINVAL;

	cluster_byte_off = byte_pos & vol->cluster_size_mask;
	nr_lcns = DIV_ROUND_UP(cluster_byte_off + bytes_per_index,
			vol->cluster_size);
	if (!nr_lcns || nr_lcns > U16_MAX ||
	    (cluster_byte_off >> NTFS_BLOCK_SIZE_BITS) > U16_MAX)
		return -E2BIG;
	if ((byte_pos >> vol->cluster_size_bits) > S64_MAX)
		return -E2BIG;

	*target_vcn = byte_pos >> vol->cluster_size_bits;
	*cluster_off = cluster_byte_off >> NTFS_BLOCK_SIZE_BITS;
	*record_off = cluster_byte_off & (NTFS_BLOCK_SIZE - 1);
	*lcns_follow = nr_lcns;
	return 0;
}

int ntfs_log_index_allocation_credits(struct ntfs_volume *vol,
		u32 bytes_per_index, u16 entry_len)
{
	u64 max_cluster_off;
	u64 nr_lcns;

	if (entry_len < sizeof(struct index_entry_header) ||
	    !IS_ALIGNED(entry_len, 8))
		return -EINVAL;
	if (!vol || !vol->journal)
		return -EROFS;
	if (vol->cluster_size < NTFS_BLOCK_SIZE ||
	    bytes_per_index < NTFS_BLOCK_SIZE ||
	    bytes_per_index > U16_MAX || !is_power_of_2(bytes_per_index))
		return -EOPNOTSUPP;

	max_cluster_off = vol->cluster_size - NTFS_BLOCK_SIZE;
	nr_lcns = DIV_ROUND_UP(max_cluster_off + bytes_per_index,
			vol->cluster_size);
	if (!nr_lcns || nr_lcns > U16_MAX)
		return -E2BIG;
	return ntfs_log_nonresident_operation_credits(vol, nr_lcns, 0,
			entry_len);
}

static int ntfs_log_index_allocation_operation(
		struct ntfs_log_handle *handle, struct inode *vi,
		u32 bytes_per_index, u64 byte_pos, u16 attr_off,
		const struct index_entry *entry, u16 entry_len, bool add,
		u64 *lsn_out)
{
	struct ntfs_log_operation_desc operation = { };
	struct ntfs_inode *base_ni;
	struct ntfs_inode *ni;
	u64 *page_lcns;
	u64 target_vcn;
	u64 operation_lsn;
	u16 target_attr;
	u16 cluster_off;
	u16 record_off;
	u16 lcns_follow;
	int err;

	if (!handle || !handle->log || !vi)
		return -EINVAL;
	err = ntfs_log_validate_index_entry(entry, entry_len);
	if (err)
		return err;
	if (!IS_ALIGNED(attr_off, 8) ||
	    attr_off < offsetof(struct index_block, index) +
			sizeof(struct index_header) ||
	    attr_off > bytes_per_index || entry_len > bytes_per_index - attr_off)
		return -EINVAL;

	ni = NTFS_I(vi);
	if (!NInoNonResident(ni) || ni->type != AT_INDEX_ALLOCATION ||
	    ni->name_len > U8_MAX)
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	err = ntfs_log_index_block_geometry(ni->vol, bytes_per_index,
			byte_pos, &target_vcn, &cluster_off, &record_off,
			&lcns_follow);
	if (err)
		return err;

	page_lcns = kmalloc_array(lcns_follow, sizeof(*page_lcns), GFP_NOFS);
	if (!page_lcns)
		return -ENOMEM;
	err = ntfs_log_stream_lcns(ni, target_vcn, lcns_follow, page_lcns);
	if (err)
		goto out;
	err = ntfs_log_open_attribute(handle,
			MK_MREF(base_ni->mft_no, base_ni->seq_no),
			le32_to_cpu(AT_INDEX_ALLOCATION), bytes_per_index,
			ni->name, ni->name_len, true, &target_attr);
	if (err)
		goto out;

	operation.redo_op = add ? AddIndexEntryAllocation :
		DeleteIndexEntryAllocation;
	operation.undo_op = add ? DeleteIndexEntryAllocation :
		AddIndexEntryAllocation;
	operation.target_attr = target_attr;
	operation.record_off = record_off;
	operation.attr_off = attr_off;
	operation.cluster_off = cluster_off;
	operation.target_vcn = target_vcn;
	operation.page_lcns = page_lcns;
	operation.lcns_follow = lcns_follow;
	if (add) {
		operation.redo_data = entry;
		operation.redo_len = entry_len;
	} else {
		operation.undo_data = entry;
		operation.undo_len = entry_len;
	}
	err = ntfs_log_write_operation(handle, &operation, &operation_lsn);
	if (!err)
		err = ntfs_log_track_inode(handle, vi, operation_lsn);
	if (!err && lsn_out)
		*lsn_out = operation_lsn;
out:
	kfree(page_lcns);
	return err;
}

int ntfs_log_index_allocation_add(struct ntfs_log_handle *handle,
		struct inode *vi, u32 bytes_per_index, u64 byte_pos, u16 attr_off,
		const struct index_entry *entry, u16 entry_len, u64 *lsn_out)
{
	return ntfs_log_index_allocation_operation(handle, vi,
			bytes_per_index, byte_pos, attr_off, entry, entry_len, true,
			lsn_out);
}

int ntfs_log_index_allocation_delete(struct ntfs_log_handle *handle,
		struct inode *vi, u32 bytes_per_index, u64 byte_pos, u16 attr_off,
		const struct index_entry *entry, u16 entry_len, u64 *lsn_out)
{
	return ntfs_log_index_allocation_operation(handle, vi,
			bytes_per_index, byte_pos, attr_off, entry, entry_len, false,
			lsn_out);
}

int ntfs_log_index_allocation_initialize_credits(struct ntfs_volume *vol,
		u32 bytes_per_index)
{
	u64 nr_lcns;

	if (!vol || !vol->journal)
		return -EROFS;
	if (vol->cluster_size < NTFS_BLOCK_SIZE ||
	    bytes_per_index < NTFS_BLOCK_SIZE ||
	    bytes_per_index > U16_MAX || !is_power_of_2(bytes_per_index))
		return -EOPNOTSUPP;
	nr_lcns = DIV_ROUND_UP(vol->cluster_size - NTFS_BLOCK_SIZE +
			bytes_per_index, vol->cluster_size);
	if (!nr_lcns || nr_lcns > U16_MAX)
		return -E2BIG;
	return ntfs_log_nonresident_operation_credits(vol, nr_lcns, 0,
			bytes_per_index);
}

int ntfs_log_index_allocation_update_credits(struct ntfs_volume *vol,
		u32 bytes_per_index)
{
	u64 nr_lcns;

	if (!vol || !vol->journal)
		return -EROFS;
	if (vol->cluster_size < NTFS_BLOCK_SIZE ||
	    bytes_per_index < NTFS_BLOCK_SIZE ||
	    bytes_per_index > U16_MAX || !is_power_of_2(bytes_per_index))
		return -EOPNOTSUPP;
	nr_lcns = DIV_ROUND_UP(vol->cluster_size - NTFS_BLOCK_SIZE +
			bytes_per_index, vol->cluster_size);
	if (!nr_lcns || nr_lcns > U16_MAX)
		return -E2BIG;
	return ntfs_log_nonresident_operation_credits(vol, nr_lcns,
			bytes_per_index, bytes_per_index);
}

static int ntfs_log_index_allocation_full_update(
		struct ntfs_log_handle *handle, struct inode *vi,
		u32 bytes_per_index, u64 byte_pos,
		const struct index_block *old_block,
		const struct index_block *new_block, u64 *lsn_out)
{
	struct ntfs_log_operation_desc operation = { };
	struct ntfs_inode *base_ni;
	struct ntfs_inode *ni;
	u64 *page_lcns;
	u64 target_vcn;
	u64 operation_lsn;
	u16 target_attr;
	u16 cluster_off;
	u16 record_off;
	u16 lcns_follow;
	int err;

	if (!handle || !handle->log || !vi || !new_block ||
	    new_block->magic != magic_INDX ||
	    (old_block && old_block->magic != magic_INDX))
		return -EINVAL;
	ni = NTFS_I(vi);
	if (!NInoNonResident(ni) || ni->type != AT_INDEX_ALLOCATION ||
	    ni->name_len > U8_MAX)
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	err = ntfs_log_index_block_geometry(ni->vol, bytes_per_index,
			byte_pos, &target_vcn, &cluster_off, &record_off,
			&lcns_follow);
	if (err)
		return err;

	page_lcns = kmalloc_array(lcns_follow, sizeof(*page_lcns), GFP_NOFS);
	if (!page_lcns)
		return -ENOMEM;
	err = ntfs_log_stream_lcns(ni, target_vcn, lcns_follow, page_lcns);
	if (err)
		goto out;
	err = ntfs_log_open_attribute(handle,
			MK_MREF(base_ni->mft_no, base_ni->seq_no),
			le32_to_cpu(AT_INDEX_ALLOCATION), bytes_per_index,
			ni->name, ni->name_len, true, &target_attr);
	if (err)
		goto out;

	operation.redo_op = UpdateNonresidentValue;
	operation.undo_op = old_block ? UpdateNonresidentValue : Noop;
	operation.target_attr = target_attr;
	operation.record_off = record_off;
	operation.cluster_off = cluster_off;
	operation.target_vcn = target_vcn;
	operation.page_lcns = page_lcns;
	operation.lcns_follow = lcns_follow;
	operation.redo_data = new_block;
	operation.redo_len = bytes_per_index;
	if (old_block) {
		operation.undo_data = old_block;
		operation.undo_len = bytes_per_index;
	}
	err = ntfs_log_write_operation(handle, &operation, &operation_lsn);
	if (!err)
		err = ntfs_log_track_inode(handle, vi, operation_lsn);
	if (!err && lsn_out)
		*lsn_out = operation_lsn;
out:
	kfree(page_lcns);
	return err;
}

int ntfs_log_index_allocation_initialize(struct ntfs_log_handle *handle,
		struct inode *vi, u32 bytes_per_index, u64 byte_pos,
		const struct index_block *block, u64 *lsn_out)
{
	return ntfs_log_index_allocation_full_update(handle, vi,
			bytes_per_index, byte_pos, NULL, block, lsn_out);
}

int ntfs_log_index_allocation_update(struct ntfs_log_handle *handle,
		struct inode *vi, u32 bytes_per_index, u64 byte_pos,
		const struct index_block *old_block,
		const struct index_block *new_block, u64 *lsn_out)
{
	if (!old_block)
		return -EINVAL;
	return ntfs_log_index_allocation_full_update(handle, vi,
			bytes_per_index, byte_pos, old_block, new_block, lsn_out);
}

static int ntfs_log_finish_transaction(struct ntfs_log_handle *handle,
		int result)
{
	struct ntfs_log_home_undo *home_entry;
	struct ntfs_log *log = handle->log;
	LIST_HEAD(home_undo_entries);
	LIST_HEAD(undo_entries);
	bool has_home_undo;
	u32 remaining;

	mutex_lock(&log->append_lock);
	ntfs_log_aggregate_release_handle(handle);
	if (WARN_ON_ONCE(handle->used_credits > handle->reserved_credits))
		remaining = 0;
	else
		remaining = handle->reserved_credits - handle->used_credits;
	if (handle->parent)
		handle->parent->reserved_credits += remaining;
	else if (WARN_ON_ONCE(log->reserved_pages < remaining))
		log->reserved_pages = 0;
	else
		log->reserved_pages -= remaining;
	if (!WARN_ON_ONCE(!handle->active)) {
		list_del_init(&handle->active_list);
		handle->active = false;
	}
	has_home_undo = !list_empty(&handle->home_undo_entries);
	list_for_each_entry(home_entry, &handle->home_undo_entries, list)
		ntfs_log_unreserve_deferred(log, home_entry);
	/* Release callbacks run after append_lock is dropped. */
	list_splice_init(&handle->home_undo_entries, &home_undo_entries);
	list_splice_init(&handle->undo_entries, &undo_entries);
	mutex_unlock(&log->append_lock);
	if (handle->prev_lsn || has_home_undo)
		atomic64_inc(&log->home_generation);
	if (!handle->independent)
		up_read(&log->transaction_lock);
	if (handle->admitted)
		up_read(&log->admission_lock);
	ntfs_log_free_handle_entries(&home_undo_entries, &undo_entries);
	kfree(handle);
	return result;
}

static int __ntfs_log_commit(struct ntfs_log_handle *handle)
{
	bool wait_durable;
	int err;
	int restore_err;

	if (!handle || !handle->log || current != handle->owner ||
	    !handle->active)
		return -EPERM;
	if (handle->log->aborted) {
		restore_err = ntfs_log_restore_home_metadata(handle);
		return ntfs_log_finish_transaction(handle,
				restore_err ? restore_err : -EROFS);
	}

	/* Inode writeback often finds that timestamps have not changed. */
	if (!handle->prev_lsn && list_empty(&handle->home_undo_entries)) {
		ntfs_log_recording_account(NTFS_LOG_RECORDING_EMPTY_COMMIT, 1);
		ntfs_log_recording_account(NTFS_LOG_RECORDING_COMMIT, 1);
		return ntfs_log_finish_transaction(handle, 0);
	}

	wait_durable = handle->force_durable_commit ||
		!handle->log->async_commit ||
		(handle->log->vol->sb->s_flags & (SB_SYNCHRONOUS | SB_DIRSYNC));
	handle->queue_deferred_free = !wait_durable && handle->has_deferred_free;
	err = ntfs_log_write_marker(handle, CommitTransaction, false);
	if (!err)
		err = ntfs_log_write_marker(handle, ForgetTransaction, wait_durable);
	if (err) {
		ntfs_error(handle->log->vol->sb,
			"Journal commit failed (transaction %u, first LSN 0x%llx, last LSN 0x%llx, error %d).",
			handle->transaction_id,
			(unsigned long long)handle->first_lsn,
			(unsigned long long)handle->prev_lsn, err);
		ntfs_log_abort_writer(handle->log, err);
		restore_err = ntfs_log_restore_home_metadata(handle);
		return ntfs_log_finish_transaction(handle,
				restore_err ? restore_err : err);
	}
	handle->committed = true;
	err = ntfs_log_commit_home_metadata(handle);
	if (err) {
		ntfs_error(handle->log->vol->sb,
			"Committed transaction %u failed to apply home metadata (error %d).",
			handle->transaction_id, err);
		ntfs_log_abort_writer(handle->log, err);
		return ntfs_log_finish_transaction(handle, err);
	}
	if (!wait_durable) {
		mutex_lock(&handle->log->append_lock);
		if (!handle->log->stopping) {
			if (handle->queue_deferred_free)
				queue_delayed_work(system_long_wq,
					&handle->log->deferred_flush_work,
					msecs_to_jiffies(NTFS_LOG_DEFERRED_FLUSH_MS));
			else
				queue_delayed_work(system_long_wq,
					&handle->log->flush_work,
					handle->log->commit_interval);
		}
		mutex_unlock(&handle->log->append_lock);
	}
	ntfs_log_recording_account(NTFS_LOG_RECORDING_COMMIT, 1);
	return ntfs_log_finish_transaction(handle, 0);
}

int ntfs_log_commit(struct ntfs_log_handle *handle)
{
	u64 started = ntfs_log_task_cpu_time();
	int err;

	err = __ntfs_log_commit(handle);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_TRANSACTION_COMMIT_CPU_NS,
			ntfs_log_task_cpu_time() - started);
	return err;
}

static void ntfs_log_init_compensation(
		struct ntfs_log_operation_desc *clr,
		const struct ntfs_log_operation_desc *operation)
{
	u16 redo_len = operation->redo_len;

	*clr = *operation;
	clr->redo_op = operation->undo_op;
	clr->undo_op = CompensationLogRecord;
	clr->redo_data = operation->undo_data;
	clr->redo_len = operation->undo_len;
	clr->undo_data = NULL;
	clr->undo_len = clr->redo_op == UpdateResidentValue ? redo_len : 0;
}

int ntfs_log_abort(struct ntfs_log_handle *handle)
{
	struct ntfs_log_undo_entry *entry;
	struct ntfs_log_operation_desc clr;
	struct ntfs_log_packed_append packed = { };
	u64 packed_source_page = 0;
	u32 packed_group = 0;
	int err = 0;

	if (!handle || !handle->log || current != handle->owner ||
	    !handle->active)
		return -EPERM;
	/* Resident-to-nonresident preflight often abandons an untouched handle. */
	if (!handle->prev_lsn && list_empty(&handle->home_undo_entries)) {
		if (handle->log->aborted)
			return ntfs_log_finish_transaction(handle, -EROFS);
		ntfs_log_recording_account(NTFS_LOG_RECORDING_ABORT, 1);
		return ntfs_log_finish_transaction(handle, 0);
	}
	if (!handle->log->aborted && handle->prev_lsn) {
		err = ntfs_log_wait_lsn_pinned(handle->log,
				handle->prev_lsn);
		if (err)
			ntfs_log_abort_writer(handle->log, err);
	}
	err = ntfs_log_restore_home_metadata(handle);
	if (err) {
		ntfs_log_abort_writer(handle->log, err);
		return ntfs_log_finish_transaction(handle, err);
	}
	if (handle->log->aborted)
		return ntfs_log_finish_transaction(handle, -EROFS);

	list_for_each_entry_reverse(entry, &handle->undo_entries, list) {
		if (entry->packed_group != packed_group) {
			if (packed_group) {
				handle->packed = NULL;
				mutex_unlock(&handle->log->append_lock);
			}
			packed_group = entry->packed_group;
			if (packed_group) {
				packed = (struct ntfs_log_packed_append) {
					.group = packed_group,
				};
				mutex_lock(&handle->log->append_lock);
				handle->packed = &packed;
				packed_source_page = entry->packed_page_off;
			}
		} else if (packed_group &&
			   packed_source_page != entry->packed_page_off) {
			/* Each original page's smaller CLRs fit on a fresh page. */
			err = ntfs_log_seal_pending_page(handle->log);
			if (err)
				break;
			packed.started = false;
			packed_source_page = entry->packed_page_off;
		}
		ntfs_log_init_compensation(&clr, &entry->operation);
		err = __ntfs_log_write_operation(handle, &clr,
				entry->undo_next_lsn, false, false, NULL);
		if (err)
			break;
	}
	if (packed_group) {
		handle->packed = NULL;
		mutex_unlock(&handle->log->append_lock);
	}
	if (err) {
		ntfs_log_abort_writer(handle->log, err);
		return ntfs_log_finish_transaction(handle, err);
	}

	err = ntfs_log_write_marker(handle, ForgetTransaction, true);
	if (err)
		ntfs_log_abort_writer(handle->log, err);
	if (!err) {
		handle->aborted = true;
		ntfs_log_recording_account(NTFS_LOG_RECORDING_ABORT, 1);
		err = ntfs_log_abort_home_metadata(handle);
		if (err) {
			ntfs_error(handle->log->vol->sb,
				   "Failed to apply aborted transaction home metadata (transaction %u, error %d).",
				   handle->transaction_id, err);
			ntfs_log_abort_writer(handle->log, err);
		}
	}
	return ntfs_log_finish_transaction(handle, err);
}

/* Quick formats leave old record LSNs behind in unallocated clusters. */
static u64 ntfs_log_fresh_lsn(const struct ntfs_logfile_layout *layout)
{
	u64 seq = get_random_u64() & ((1ULL << (layout->seq_num_bits - 1)) - 1);

	/* Keep the initial LSN positive and leave room for subsequent wraps. */
	if (!seq)
		seq = 1;
	return ntfs_byte_off_to_lsn(layout,
			layout->first_page + layout->data_off, seq);
}

static int ntfs_log_layout_from_restart(struct ntfs_volume *vol,
		const struct restart_page_header *rp, struct ntfs_log *log)
{
	const struct log_client_record *clients;
	const struct log_client_record *client;
	const struct restart_area *ra;
	struct ntfs_logfile_layout *layout = &log->layout;
	u64 current_lsn;
	u64 current_off;
	u64 next_off;
	u64 seq;
	u16 client_idx;
	int err;

	if (!ntfs_is_rstr_record(rp->magic) ||
	    le16_to_cpu(rp->major_ver) != NTFS_LOG_V1_MAJOR ||
	    le16_to_cpu(rp->minor_ver) != NTFS_LOG_V1_MINOR)
		return -EOPNOTSUPP;

	ra = (const struct restart_area *)((const u8 *)rp +
			le16_to_cpu(rp->restart_area_offset));
	memset(layout, 0, sizeof(*layout));
	layout->system_page_size = le32_to_cpu(rp->system_page_size);
	layout->page_size = le32_to_cpu(rp->log_page_size);
	layout->page_mask = layout->page_size - 1;
	layout->log_size = le64_to_cpu(ra->file_size);
	layout->first_page = (u64)NTFS_LOG_V1_FIRST_PAGE * layout->page_size;
	layout->seq_num_bits = le32_to_cpu(ra->seq_number_bits);
	layout->file_data_bits = 64 - layout->seq_num_bits;
	layout->record_header_len = le16_to_cpu(ra->log_record_header_length);
	layout->data_off = le16_to_cpu(ra->log_page_data_offset);
	layout->current_lsn = le64_to_cpu(ra->current_lsn);

	if (!is_power_of_2(layout->system_page_size) ||
	    layout->system_page_size < NTFS_BLOCK_SIZE ||
	    layout->system_page_size > U16_MAX ||
	    !is_power_of_2(layout->page_size) ||
	    layout->page_size < NTFS_BLOCK_SIZE ||
	    layout->page_size > U16_MAX ||
	    layout->log_size > i_size_read(vol->logfile_ino) ||
	    layout->first_page >= layout->log_size ||
	    layout->seq_num_bits <= 3 || layout->seq_num_bits >= 64 ||
	    layout->record_header_len != sizeof(struct ntfs_lfs_record_hdr) ||
	    layout->data_off >= layout->page_size ||
	    !IS_ALIGNED(layout->data_off, 8))
		return -EINVAL;

	clients = (const struct log_client_record *)((const u8 *)ra +
			le16_to_cpu(ra->client_array_offset));
	client_idx = le16_to_cpu(ra->client_in_use_list);
	if (client_idx == LOGFILE_NO_CLIENT_CPU)
		client_idx = 0;
	if (client_idx >= le16_to_cpu(ra->log_clients))
		return -EINVAL;
	client = clients + client_idx;
	layout->client_idx = client_idx;
	layout->client_seq = le16_to_cpu(client->seq_number);
	log->usa_seq = le16_to_cpu(*(__le16 *)((const u8 *)rp +
			le16_to_cpu(rp->usa_ofs)));
	layout->oldest_lsn = le64_to_cpu(client->oldest_lsn);
	log->oldest_lsn = layout->oldest_lsn;
	log->checkpoint_lsn = le64_to_cpu(client->client_restart_lsn);
	if (vol->journal_recovery_lsn) {
		u64 recovery_off;

		if (vol->journal_recovery_lsn < layout->current_lsn ||
		    ntfs_lsn_to_byte_off(layout, vol->journal_recovery_lsn,
			    &recovery_off))
			return -EUCLEAN;
		layout->current_lsn = vol->journal_recovery_lsn;
	}
	log->last_client_lsn = layout->current_lsn;
	log->restart_log_open_count =
		le32_to_cpu(ra->restart_log_open_count) + 1;

	current_lsn = layout->current_lsn;
	if (!current_lsn) {
		log->head_lsn = ntfs_log_fresh_lsn(layout);
		return 0;
	}

	err = ntfs_lsn_to_byte_off(layout, current_lsn, &current_off);
	if (err)
		return err;
	next_off = ntfs_next_page_off(layout, current_off);
	seq = current_lsn >> layout->file_data_bits;
	if (next_off == layout->first_page)
		seq = (seq + 1) & ((1ULL << layout->seq_num_bits) - 1);
	if (!seq)
		seq = 1;
	log->head_lsn = ntfs_byte_off_to_lsn(layout,
			next_off + layout->data_off, seq);
	if (!log->oldest_lsn)
		log->oldest_lsn = current_lsn;
	return 0;
}

static void ntfs_log_destroy_deferred_workqueues(struct ntfs_log *log)
{
	unsigned int kind;

	for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++) {
		struct ntfs_log_deferred_queue *queue = &log->deferred[kind];

		if (queue->workqueue) {
			destroy_workqueue(queue->workqueue);
			queue->workqueue = NULL;
		}
	}
}

static int ntfs_log_alloc_deferred_workqueues(struct ntfs_log *log)
{
	unsigned int kind;

	/*
	 * Reclaim-capable writeback can drain these queues.  Keep the bitmap
	 * kinds and ordered I/O separate so unrelated work cannot occupy their
	 * reclaim rescuers.
	 */
	for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++) {
		struct ntfs_log_deferred_queue *queue = &log->deferred[kind];

		queue->workqueue = alloc_workqueue("ntfs-free-%u",
				WQ_UNBOUND | WQ_MEM_RECLAIM, 0, kind);
		if (!queue->workqueue) {
			ntfs_log_destroy_deferred_workqueues(log);
			return -ENOMEM;
		}
	}
	return 0;
}

int ntfs_log_start(struct ntfs_volume *vol,
		const struct restart_page_header *rp)
{
	struct ntfs_log *log;
	u64 log_size;
	u32 i;
	int err;

	if (!vol || !vol->logfile_ino)
		return -EINVAL;
	down_read(&vol->journal_lock);
	if (vol->journal)
		err = -EINVAL;
	else
		err = 0;
	up_read(&vol->journal_lock);
	if (err)
		return err;

	log = kzalloc(sizeof(*log), GFP_NOFS);
	if (!log)
		return -ENOMEM;
	log->retired_transaction_ids = bitmap_zalloc(
			NTFS_LOG_TRANSACTION_SLOT_COUNT, GFP_NOFS);
	if (!log->retired_transaction_ids) {
		kfree(log);
		return -ENOMEM;
	}
	log->aggregate_hash = kcalloc(NTFS_LOG_AGGREGATE_HASH_SIZE,
			sizeof(*log->aggregate_hash), GFP_NOFS);
	if (!log->aggregate_hash) {
		bitmap_free(log->retired_transaction_ids);
		kfree(log);
		return -ENOMEM;
	}
	log->vol = vol;
	init_rwsem(&log->transaction_lock);
	init_rwsem(&log->admission_lock);
	mutex_init(&log->append_lock);
	mutex_init(&log->flush_lock);
	mutex_init(&log->open_attr_lock);
	mutex_init(&log->checkpoint_lock);
	INIT_DELAYED_WORK(&log->checkpoint_work, ntfs_log_checkpoint_work);
	INIT_DELAYED_WORK(&log->reclaim_work, ntfs_log_reclaim_work);
	INIT_DELAYED_WORK(&log->flush_work, ntfs_log_flush_work);
	INIT_DELAYED_WORK(&log->deferred_flush_work,
			ntfs_log_deferred_flush_work);
	for (i = 0; i < NTFS_LOG_DEFERRED_KINDS; i++) {
		struct ntfs_log_deferred_queue *queue = &log->deferred[i];

		INIT_LIST_HEAD(&queue->pending);
		INIT_LIST_HEAD(&queue->ready);
		INIT_WORK(&queue->work, ntfs_log_deferred_work);
		mutex_init(&queue->free_count_lock);
		queue->log = log;
	}
	atomic_set(&log->deferred_users, 0);
	init_waitqueue_head(&log->deferred_wait);
	log->async_commit = journal_async_commit;
	log->commit_interval = clamp_t(unsigned int,
			journal_commit_interval, 1, 3600) * HZ;
	init_waitqueue_head(&log->durable_wait);
	log->home_wb_err = errseq_sample(&vol->sb->s_wb_err);
	atomic64_set(&log->home_generation, 0);
	atomic64_set(&log->inode_writeback_generation, 0);
	atomic64_set(&log->home_writeback_generation, 0);
	INIT_LIST_HEAD(&log->open_attrs);
	INIT_LIST_HEAD(&log->active_handles);
	INIT_LIST_HEAD(&log->dirty_pages);
	INIT_LIST_HEAD(&log->sealed_pages);
	INIT_LIST_HEAD(&log->aggregate_records);
	err = ntfs_log_alloc_deferred_workqueues(log);
	if (err)
		goto out_free;
	INIT_LIST_HEAD(&log->pending_ordered_io);
	log->ordered_io_wq = alloc_workqueue("ntfs-ordered",
			WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!log->ordered_io_wq) {
		err = -ENOMEM;
		goto out_free;
	}
	log->ordered_io_pool = mempool_create_kmalloc_pool(
			NTFS_ORDERED_IO_POOL_SIZE,
			sizeof(struct ntfs_ordered_ioend));
	if (!log->ordered_io_pool) {
		err = -ENOMEM;
		goto out_free;
	}
	for (i = 0; i < NTFS_LOG_AGGREGATE_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&log->aggregate_hash[i]);
	log->next_open_attr_slot = sizeof(struct ntfs_log_restart_table);
	log->next_transaction_id = sizeof(struct ntfs_log_restart_table);

	if (rp) {
		err = ntfs_log_layout_from_restart(vol, rp, log);
	} else {
		log_size = round_down((u64)i_size_read(vol->logfile_ino),
				(u64)DefaultLogPageSize);
		err = ntfs_log_init_v1_layout(log_size, DefaultLogPageSize,
				&log->layout);
		if (!err) {
			log->head_lsn = ntfs_log_fresh_lsn(&log->layout);
			log->restart_log_open_count = 1;
		}
	}
	if (err)
		goto out_free;
	/*
	 * The size trigger controls memory/I/O batch size, not durability age.
	 * queue_delayed_work() below still keeps the first transaction's
	 * fixed commit deadline.  Large logs can therefore amortize barriers
	 * without extending the default five-second exposure window.
	 */
	log->staging_limit = clamp_t(u64, log->layout.log_size >> 4,
			SZ_1M, SZ_8M);
	log->aggregate_limit = clamp_t(u64,
			ntfs_log_total_avail(&log->layout) >> 3,
			SZ_1M, SZ_8M);

	log->running = true;
	down_write(&vol->journal_lock);
	if (vol->journal) {
		up_write(&vol->journal_lock);
		err = -EBUSY;
		goto out_free;
	}
	vol->journal = log;
	up_write(&vol->journal_lock);
	vol->journal_recovery_lsn = 0;
	queue_delayed_work(system_long_wq, &log->checkpoint_work,
			NTFS_LOG_BACKGROUND_CHECKPOINT_DELAY);
	return 0;

out_free:
	if (log->ordered_io_wq)
		destroy_workqueue(log->ordered_io_wq);
	if (log->ordered_io_pool)
		mempool_destroy(log->ordered_io_pool);
	ntfs_log_destroy_deferred_workqueues(log);
	ntfs_log_aggregate_reset(log);
	ntfs_log_free_sealed_pages(&log->sealed_pages);
	kvfree(log->pending_page);
	kfree(log->aggregate_hash);
	bitmap_free(log->retired_transaction_ids);
	kfree(log);
	return err;
}

static int ntfs_log_finish_clean_checkpoint(struct ntfs_log *log,
		bool *checkpointed)
{
	unsigned int attempts;

	for (attempts = 0; attempts < 3; attempts++) {
		u64 oldest_lsn = READ_ONCE(log->oldest_lsn);
		bool clean_published;
		unsigned int kind;
		int err;

		for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++) {
			err = ntfs_log_drain_deferred_queue(log, kind);
			if (err)
				return err;
		}
		err = __ntfs_log_checkpoint(log, true, true, &clean_published);
		if (err)
			return err;
		*checkpointed = true;
		if (clean_published)
			return 0;
		if (oldest_lsn == READ_ONCE(log->oldest_lsn))
			break;
	}
	return -EAGAIN;
}

static int __ntfs_log_stop(struct ntfs_volume *vol, bool clean, bool clear_dirty)
{
	const enum ntfs_log_recording_stat clean_flush_stat =
		NTFS_LOG_RECORDING_UNMOUNT_CLEAN_COMBINED_FLUSH;
	struct ntfs_log *log;
	unsigned int kind;
	bool checkpointed = false;
	int checkpoint_err = 0;
	int drain_err = 0;
	int err = 0;

	if (!vol)
		return 0;
	down_write(&vol->journal_lock);
	log = vol->journal;
	if (!log) {
		up_write(&vol->journal_lock);
		return 0;
	}
	mutex_lock(&log->append_lock);
	log->stopping = true;
	mutex_unlock(&log->append_lock);
	up_write(&vol->journal_lock);

	/* No new external drainer can pin the writer after stopping is set. */
	wait_event(log->deferred_wait, !atomic_read(&log->deferred_users));
	/* Pair with the final drainer's wakeup before freeing the writer. */
	mutex_lock(&log->append_lock);
	mutex_unlock(&log->append_lock);
	cancel_delayed_work_sync(&log->checkpoint_work);
	cancel_delayed_work_sync(&log->reclaim_work);
	cancel_delayed_work_sync(&log->flush_work);
	cancel_delayed_work_sync(&log->deferred_flush_work);
	/* Transactions admitted before stopping can still enqueue their frees. */
	down_write(&log->transaction_lock);
	up_write(&log->transaction_lock);
	mutex_lock(&log->checkpoint_lock);
	if (log->running && !log->aborted && !NVolShutdown(vol)) {
		for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++) {
			drain_err = ntfs_log_drain_deferred_queue(log, kind);
			if (drain_err)
				break;
		}
		/*
		 * Clear the volume dirty bit before collecting the clean
		 * generation.  Its MFT home write is submitted by the checkpoint
		 * passes and the restart PREFLUSH makes it durable before the clean
		 * restart page.  A failed clean publication restores the dirty bit.
		 */
		if (!drain_err && clear_dirty)
			err = ntfs_sync_volume_dirty_state(vol);
		if (drain_err) {
			err = drain_err;
		} else if (!err && clean) {
			checkpoint_err = ntfs_log_finish_clean_checkpoint(log,
					&checkpointed);
		} else {
			checkpoint_err = __ntfs_log_checkpoint(log, false, true,
					NULL);
			checkpointed = !checkpoint_err;
		}
		if (!err)
			err = checkpoint_err;
	} else if (log->aborted || NVolShutdown(vol)) {
		err = -EROFS;
	}
	if (checkpointed) {
		ntfs_log_recording_account(NTFS_LOG_RECORDING_UNMOUNT_CHECKPOINT,
					   1);
		if (clear_dirty && !err)
			ntfs_log_recording_account(clean_flush_stat, 1);
	}
	if (clear_dirty && err) {
		int dirty_err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

		if (dirty_err)
			err = dirty_err;
	}

	/* The detached log can now be drained even when the writer aborted. */
	down_write(&log->transaction_lock);
	mutex_lock(&log->flush_lock);
	mutex_lock(&log->append_lock);
	log->running = false;
	ntfs_log_aggregate_reset(log);
	mutex_unlock(&log->append_lock);
	mutex_unlock(&log->flush_lock);
	wake_up_all(&log->durable_wait);
	up_write(&log->transaction_lock);

	/*
	 * Checkpoint entry takes journal_lock before checkpoint_lock.  Drop the
	 * latter before detaching the drained writer to keep that order.
	 */
	mutex_unlock(&log->checkpoint_lock);
	/* No handle or LSN waiter can need this writer after the drain. */
	down_write(&vol->journal_lock);
	if (vol->journal == log)
		vol->journal = NULL;
	up_write(&vol->journal_lock);
	for (kind = 0; kind < NTFS_LOG_DEFERRED_KINDS; kind++) {
		struct ntfs_log_deferred_queue *queue = &log->deferred[kind];
		struct ntfs_log_home_undo *entry, *next;

		cancel_work_sync(&queue->work);
		list_for_each_entry_safe(entry, next, &queue->pending, list)
			ntfs_log_free_home_undo_entry(entry);
		list_for_each_entry_safe(entry, next, &queue->ready, list)
			ntfs_log_free_home_undo_entry(entry);
	}
	ntfs_log_destroy_deferred_workqueues(log);
	ntfs_log_clear_open_attrs(log);
	ntfs_log_clear_dirty_pages(log);
	{
		int ordered_err = ntfs_log_wait_ordered_io(
				&log->pending_ordered_io);

		if (!err)
			err = ordered_err;
		destroy_workqueue(log->ordered_io_wq);
		mempool_destroy(log->ordered_io_pool);
	}
	ntfs_log_free_sealed_pages(&log->sealed_pages);
	kvfree(log->pending_page);
	kfree(log->aggregate_hash);
	bitmap_free(log->retired_transaction_ids);
	kfree(log);
	return err;
}

int ntfs_log_stop(struct ntfs_volume *vol, bool clean)
{
	return __ntfs_log_stop(vol, clean, clean);
}

int ntfs_log_finish_replay(struct ntfs_volume *vol,
			   const struct restart_page_header *rp)
{
	int err;

	err = ntfs_log_start(vol, rp);
	if (err)
		return err;
	/* The caller persisted the dirty flag. Orphan cleanup has not run. */
	return __ntfs_log_stop(vol, true, false);
}
