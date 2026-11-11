// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS journal recording codec.
 *
 * Builds version 1.1 restart pages, checkpoints and RCRD images.
 */

#include <linux/log2.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/unaligned.h>

#include "logfile_internal.h"
#include "ntfs.h"

/* Version 1.1 reserves four pages before the circular RCRD area. */
#define NTFS_LOG_V1_FIRST_PAGE	4
#define NTFS_LOG_V1_MINOR	1
#define NTFS_LOG_V1_MAJOR	1
#define NTFS_LOG_CLIENT_ARRAY_OFF 0x40

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
	if (!file_bits || file_bits >= 64)
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
	u16 i;

	if (!desc || !payload || desc->redo_op > ZeroEndOfFileRecord ||
	    desc->undo_op > ZeroEndOfFileRecord ||
	    desc->target_vcn > S64_MAX ||
	    (desc->lcns_follow && desc->target_vcn >
		    S64_MAX - desc->lcns_follow + 1) ||
	    (desc->lcns_follow && !desc->page_lcns) ||
	    (desc->undo_len && !desc->undo_data) ||
	    (desc->redo_len && !desc->redo_data))
		return -EINVAL;
	for (i = 0; i < desc->lcns_follow; i++) {
		if (desc->page_lcns[i] > S64_MAX)
			return -EINVAL;
	}

	header_len = struct_size(lrh, page_lcns,
			max_t(u16, 1, desc->lcns_follow));
	undo_off = ALIGN(header_len, 8);
	if (check_add_overflow(undo_off, (u32)desc->undo_len, &redo_off))
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

	if (desc->undo_len)
		memcpy((u8 *)data + undo_off, desc->undo_data,
			desc->undo_len);
	if (desc->redo_len)
		memcpy((u8 *)data + redo_off, desc->redo_data,
			desc->redo_len);

	payload->data = data;
	payload->len = payload_len;
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
