/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Internal NTFS journal definitions shared by replay and recording.
 */

#ifndef _LINUX_NTFS_LOGFILE_INTERNAL_H
#define _LINUX_NTFS_LOGFILE_INTERNAL_H

#include <linux/kernel.h>
#include <linux/types.h>

#include "logfile.h"

#define LFS_CLIENT_RECORD	cpu_to_le32(1)
#define LFS_CLIENT_RESTART	cpu_to_le32(2)

#define LOG_RECORD_MULTI_PAGE	cpu_to_le16(1)
#define LOG_RECORD_REDO_NOT_INLINE cpu_to_le16(2)
#define LOG_RECORD_UNDO_NOT_INLINE cpu_to_le16(4)

#define LOG_PAGE_LOG_RECORD_END	cpu_to_le32(1)

#define RESTART_ENTRY_ALLOCATED_LE32 0xffffffff
#define RESTART_ENTRY_ALLOCATED_LE cpu_to_le32(RESTART_ENTRY_ALLOCATED_LE32)

enum ntfs_log_operation {
	Noop = 0x00,
	CompensationLogRecord = 0x01,
	InitializeFileRecordSegment = 0x02,
	DeallocateFileRecordSegment = 0x03,
	WriteEndOfFileRecordSegment = 0x04,
	CreateAttribute = 0x05,
	DeleteAttribute = 0x06,
	UpdateResidentValue = 0x07,
	UpdateNonresidentValue = 0x08,
	UpdateMappingPairs = 0x09,
	DeleteDirtyClusters = 0x0A,
	SetNewAttributeSizes = 0x0B,
	AddIndexEntryRoot = 0x0C,
	DeleteIndexEntryRoot = 0x0D,
	AddIndexEntryAllocation = 0x0E,
	DeleteIndexEntryAllocation = 0x0F,
	WriteEndOfIndexBuffer = 0x10,
	SetIndexEntryVcnRoot = 0x11,
	SetIndexEntryVcnAllocation = 0x12,
	UpdateFileNameRoot = 0x13,
	UpdateFileNameAllocation = 0x14,
	SetBitsInNonresidentBitMap = 0x15,
	ClearBitsInNonresidentBitMap = 0x16,
	HotFix = 0x17,
	EndTopLevelAction = 0x18,
	PrepareTransaction = 0x19,
	CommitTransaction = 0x1A,
	ForgetTransaction = 0x1B,
	OpenNonresidentAttribute = 0x1C,
	OpenAttributeTableDump = 0x1D,
	AttributeNamesDump = 0x1E,
	DirtyPageTableDump = 0x1F,
	TransactionTableDump = 0x20,
	UpdateRecordDataRoot = 0x21,
	UpdateRecordDataAllocation = 0x22,
	UpdateRelativeDataIndex = 0x23,
	UpdateRelativeDataAllocation = 0x24,
	ZeroEndOfFileRecord = 0x25,
};

/* LFS header at the front of every client record. */
struct ntfs_lfs_record_hdr {
	__le64 this_lsn;
	__le64 client_prev_lsn;
	__le64 client_undo_next_lsn;
	__le32 client_data_len;
	__le16 client_seq;
	__le16 client_idx;
	__le32 record_type;
	__le32 transact_id;
	__le16 flags;
	u8 reserved[6];
} __packed;

/* NTFS redo/undo descriptor at the front of a normal client payload. */
struct ntfs_log_rec_hdr {
	__le16 redo_op;
	__le16 undo_op;
	__le16 redo_off;
	__le16 redo_len;
	__le16 undo_off;
	__le16 undo_len;
	__le16 target_attr;
	__le16 lcns_follow;
	__le16 record_off;
	__le16 attr_off;
	__le16 cluster_off;
	__le16 reserved;
	__le64 target_vcn;
	__le64 page_lcns[];
} __packed;

struct ntfs_page_record_hdr {
	__le16 next_record_off;
	u8 reserved[6];
	__le64 last_end_lsn;
} __packed;

struct ntfs_log_page_hdr {
	__le32 magic;
	__le16 usa_ofs;
	__le16 usa_count;
	__le64 lsn;
} __packed;

struct ntfs_record_page_hdr {
	struct ntfs_log_page_hdr rhdr;
	__le32 rflags;
	__le16 page_count;
	__le16 page_pos;
	struct ntfs_page_record_hdr record_hdr;
} __packed;

struct ntfs_log_restart_table {
	__le16 size;
	__le16 used;
	__le16 total;
	__le16 reserved0;
	__le16 reserved1;
	__le16 reserved2;
	__le32 free_goal;
	__le32 first_free;
	__le32 last_free;
} __packed;

struct ntfs_transaction_entry {
	__le32 next;
	u8 transact_state;
	u8 reserved[3];
	__le64 first_lsn;
	__le64 prev_lsn;
	__le64 undo_next_lsn;
	__le32 undo_records;
	__le32 undo_len;
} __packed;

struct ntfs_log_checkpoint {
	__le32 major_ver;
	__le32 minor_ver;
	__le64 check_point_start;
	__le64 open_attr_table_lsn;
	__le64 attr_names_lsn;
	__le64 dirty_pages_table_lsn;
	__le64 transact_table_lsn;
	__le32 open_attr_len;
	__le32 attr_names_len;
	__le32 dirty_pages_len;
	__le32 transact_table_len;
} __packed;

/* Geometry and LSN bounds used by both the replay reader and page writer. */
struct ntfs_logfile_layout {
	u32 system_page_size;
	u32 page_size;
	u32 page_mask;
	u64 log_size;
	u64 first_page;
	u32 seq_num_bits;
	u32 file_data_bits;
	u16 record_header_len;
	u16 data_off;
	u64 current_lsn;
	u64 oldest_lsn;
	u16 client_seq;
	u16 client_idx;
};

static_assert(sizeof(struct ntfs_lfs_record_hdr) == 0x30);
static_assert(sizeof(struct ntfs_log_rec_hdr) == 0x20);
static_assert(sizeof(struct ntfs_record_page_hdr) == 0x28);
static_assert(sizeof(struct ntfs_log_restart_table) == 0x18);
static_assert(sizeof(struct ntfs_transaction_entry) == 0x28);
static_assert(sizeof(struct ntfs_log_checkpoint) == 0x40);

static inline u32 ntfs_log_rec_length(const struct ntfs_log_rec_hdr *lrh)
{
	u16 lcns = le16_to_cpu(lrh->lcns_follow);

	return struct_size(lrh, page_lcns, max_t(u16, 1, lcns));
}

static inline u64 ntfs_log_total_avail(const struct ntfs_logfile_layout *layout)
{
	u64 pages;

	if (layout->log_size <= layout->first_page ||
	    layout->page_size <= layout->data_off)
		return 0;

	pages = (layout->log_size - layout->first_page) / layout->page_size;
	return pages * (layout->page_size - layout->data_off);
}

static inline int ntfs_lsn_to_byte_off(const struct ntfs_logfile_layout *layout,
		u64 lsn, u64 *byte_off)
{
	u64 t;

	if (!layout || !byte_off || !layout->seq_num_bits ||
	    layout->seq_num_bits <= 3 || layout->seq_num_bits >= 64)
		return -EINVAL;

	t = lsn << layout->seq_num_bits;
	t >>= layout->seq_num_bits - 3;
	if (t >= layout->log_size)
		return -EINVAL;

	*byte_off = t;
	return 0;
}

static inline u64 ntfs_next_page_off(const struct ntfs_logfile_layout *layout,
		u64 page_off)
{
	page_off = (page_off & ~((u64)layout->page_mask)) + layout->page_size;
	return page_off >= layout->log_size ? layout->first_page : page_off;
}

static inline u64 ntfs_byte_off_to_lsn(const struct ntfs_logfile_layout *layout,
		u64 byte_off, u64 seq)
{
	return (byte_off >> 3) + (seq << layout->file_data_bits);
}

/* Inputs to the record-page serializer. */
struct ntfs_log_record_desc {
	u64 this_lsn;
	u64 client_prev_lsn;
	u64 client_undo_next_lsn;
	u32 record_type;
	u32 transact_id;
	u16 client_seq;
	u16 client_idx;
	u16 flags;
	const void *payload;
	u32 payload_len;
};

struct ntfs_log_record_pages {
	void *data;
	u16 nr_pages;
	u32 page_size;
};

struct ntfs_log_operation_desc {
	u16 redo_op;
	u16 undo_op;
	u16 target_attr;
	u16 record_off;
	u16 attr_off;
	u16 cluster_off;
	u64 target_vcn;
	const u64 *page_lcns;
	u16 lcns_follow;
	const void *undo_data;
	u16 undo_len;
	const void *redo_data;
	u16 redo_len;
};

struct ntfs_log_payload {
	void *data;
	u32 len;
};

int ntfs_log_init_v1_layout(u64 log_size, u32 page_size,
		struct ntfs_logfile_layout *layout);
int ntfs_log_build_record_pages(const struct ntfs_logfile_layout *layout,
		const struct ntfs_log_record_desc *desc,
		struct ntfs_log_record_pages *pages);
void ntfs_log_free_record_pages(struct ntfs_log_record_pages *pages);
int ntfs_log_build_operation_payload(
		const struct ntfs_log_operation_desc *desc,
		struct ntfs_log_payload *payload);
void ntfs_log_free_payload(struct ntfs_log_payload *payload);
int ntfs_log_build_restart_page_v1(const struct ntfs_logfile_layout *layout,
		u64 current_lsn, u64 client_restart_lsn, u64 oldest_lsn,
		u32 restart_log_open_count, bool clean, void **page_out);
void ntfs_log_build_empty_checkpoint(struct ntfs_log_checkpoint *checkpoint);
bool ntfs_log_validate_restart_table(const struct ntfs_log_restart_table *table,
		size_t bytes);
bool ntfs_log_validate_record(const struct ntfs_log_rec_hdr *lrh, u32 bytes,
		u32 transact_id, __le16 flags);

#endif /* _LINUX_NTFS_LOGFILE_INTERNAL_H */
