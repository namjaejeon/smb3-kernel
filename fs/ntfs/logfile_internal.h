/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Internal NTFS $LogFile definitions shared by replay and recording.
 */

#ifndef _LINUX_NTFS_LOGFILE_INTERNAL_H
#define _LINUX_NTFS_LOGFILE_INTERNAL_H

#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/jump_label.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "logfile.h"

#define LFS_CLIENT_RECORD	cpu_to_le32(1)
#define LFS_CLIENT_RESTART	cpu_to_le32(2)

#define LOG_RECORD_MULTI_PAGE	cpu_to_le16(1)
#define LOG_RECORD_REDO_NOT_INLINE cpu_to_le16(2)
#define LOG_RECORD_UNDO_NOT_INLINE cpu_to_le16(4)

#define LOG_PAGE_LOG_RECORD_END	cpu_to_le32(1)

#define RESTART_ENTRY_ALLOCATED_LE32 0xffffffff
#define RESTART_ENTRY_ALLOCATED_LE cpu_to_le32(RESTART_ENTRY_ALLOCATED_LE32)

/* Backwards-skippable Noop payload used as this writer's durable batch fence. */
#define NTFS_LOG_BATCH_COMMIT_MAGIC	0x54494d4d4f435442ULL /* BTCOMMIT */
#define NTFS_LOG_BATCH_COMMIT_VERSION_V1	1
#define NTFS_LOG_BATCH_COMMIT_VERSION		2

/* The marker is committed only by a restart page whose current_lsn covers it. */
#define NTFS_LOG_BATCH_COMMIT_RESTART_REQUIRED	0x0001

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

enum ntfs_transact_state {
	TransactionUninitialized = 0,
	TransactionActive,
	TransactionPrepared,
	TransactionCommitted,
};

enum ntfs_log_recording_stat {
	NTFS_LOG_RECORDING_BEGIN,
	NTFS_LOG_RECORDING_COMMIT,
	NTFS_LOG_RECORDING_ABORT,
	NTFS_LOG_RECORDING_RECORD,
	NTFS_LOG_RECORDING_PAGE,
	NTFS_LOG_RECORDING_PACKED_RECORD,
	NTFS_LOG_RECORDING_BYTE,
	NTFS_LOG_RECORDING_RECORD_FLUSH,
	NTFS_LOG_RECORDING_FLUSHED_RECORD,
	NTFS_LOG_RECORDING_RESTART_WRITE,
	NTFS_LOG_RECORDING_RESTART_FLUSH,
	NTFS_LOG_RECORDING_CHECKPOINT,
	NTFS_LOG_RECORDING_BACKGROUND_CHECKPOINT,
	NTFS_LOG_RECORDING_EXPLICIT_CHECKPOINT,
	NTFS_LOG_RECORDING_SPACE_CHECKPOINT,
	NTFS_LOG_RECORDING_MOUNT_CHECKPOINT,
	NTFS_LOG_RECORDING_UNMOUNT_CHECKPOINT,
	NTFS_LOG_RECORDING_MOUNT_DIRTY_COMBINED_FLUSH,
	NTFS_LOG_RECORDING_UNMOUNT_CLEAN_COMBINED_FLUSH,
	NTFS_LOG_RECORDING_UNMOUNT_FINAL_FLUSH,
	NTFS_LOG_RECORDING_UNMOUNT_FINAL_FLUSH_NS,
	NTFS_LOG_RECORDING_LIFECYCLE_FALLBACK_FLUSH,
	NTFS_LOG_RECORDING_LIFECYCLE_FALLBACK_FLUSH_NS,
	NTFS_LOG_RECORDING_CHECKPOINT_SKIP,
	NTFS_LOG_RECORDING_EXPLICIT_CHECKPOINT_SKIP,
	NTFS_LOG_RECORDING_CHECKPOINT_OPEN_ATTR,
	NTFS_LOG_RECORDING_CHECKPOINT_DIRTY_PAGE,
	NTFS_LOG_RECORDING_CHECKPOINT_TRANSACTION,
	NTFS_LOG_RECORDING_LSN_WAIT,
	NTFS_LOG_RECORDING_RESERVATION_GROW,
	NTFS_LOG_RECORDING_RESERVATION_PAGES,
	NTFS_LOG_RECORDING_RESERVATION_FAILURE,
	NTFS_LOG_RECORDING_EMPTY_COMMIT,
	NTFS_LOG_RECORDING_FLUSH_NS,
	NTFS_LOG_RECORDING_CHECKPOINT_SYNC,
	NTFS_LOG_RECORDING_ORDERED_FLUSH,
	NTFS_LOG_RECORDING_RESTART_SKIPPED,
	NTFS_LOG_RECORDING_APPEND_DURING_FLUSH,
	NTFS_LOG_RECORDING_WRITEBACK_DEFER,
	NTFS_LOG_RECORDING_LOCKED_BEGIN_DEFER,
	NTFS_LOG_RECORDING_COMMIT_WORKER,
	NTFS_LOG_RECORDING_FLUSH_LOCK_WAIT_NS,
	NTFS_LOG_RECORDING_ORDERED_FLUSH_NS,
	NTFS_LOG_RECORDING_LOG_WRITEBACK_NS,
	NTFS_LOG_RECORDING_RECORD_CACHE_FLUSH_NS,
	NTFS_LOG_RECORDING_RESTART_WRITE_NS,
	NTFS_LOG_RECORDING_RESTART_CACHE_FLUSH_NS,
	NTFS_LOG_RECORDING_CHECKPOINT_INODE_SYNC_NS,
	NTFS_LOG_RECORDING_CHECKPOINT_HOME_WRITEBACK_NS,
	NTFS_LOG_RECORDING_CHECKPOINT_HOME_FLUSH_NS,
	NTFS_LOG_RECORDING_BATCH_MARKER,
	NTFS_LOG_RECORDING_BATCH_MARKER_FLUSH_NS,
	NTFS_LOG_RECORDING_BATCH_MARKER_WRITE_NS,
	NTFS_LOG_RECORDING_COMBINED_CHECKPOINT_FLUSH,
	NTFS_LOG_RECORDING_GENERATION_COMMIT,
	NTFS_LOG_RECORDING_COMMIT_RECORD_ELIDED,
	NTFS_LOG_RECORDING_BATCH_COMMITTED_TRANSACTION,
	NTFS_LOG_RECORDING_GENERATION_METADATA_COALESCE,
	NTFS_LOG_RECORDING_FORGET_ELIDED,
	NTFS_LOG_RECORDING_COALESCE_ATTEMPT,
	NTFS_LOG_RECORDING_COALESCE_HIT,
	NTFS_LOG_RECORDING_COALESCE_BYTE,
	NTFS_LOG_RECORDING_METADATA_HOME_FLUSH,
	NTFS_LOG_RECORDING_METADATA_HOME_FLUSH_NS,
	NTFS_LOG_RECORDING_AGGREGATE_TOUCH,
	NTFS_LOG_RECORDING_AGGREGATE_UNIQUE,
	NTFS_LOG_RECORDING_AGGREGATE_MERGE,
	NTFS_LOG_RECORDING_AGGREGATE_BYTE,
	NTFS_LOG_RECORDING_AGGREGATE_RECLAIM_BYTE,
	NTFS_LOG_RECORDING_ELIDED_RECORD,
	NTFS_LOG_RECORDING_ELIDED_TRANSACTION,
	NTFS_LOG_RECORDING_SIZE_COALESCE,
	NTFS_LOG_RECORDING_MAPPING_COALESCE,
	NTFS_LOG_RECORDING_ID_PRESSURE_FLUSH,
	NTFS_LOG_RECORDING_AGGREGATE_BITMAP_MERGE,
	NTFS_LOG_RECORDING_AGGREGATE_MFT_FOLD_ATTEMPT,
	NTFS_LOG_RECORDING_AGGREGATE_MFT_FOLD,
	NTFS_LOG_RECORDING_AGGREGATE_MFT_NO_ANCHOR,
	NTFS_LOG_RECORDING_AGGREGATE_MFT_NOT_TAIL,
	NTFS_LOG_RECORDING_AGGREGATE_MFT_IMMUTABLE,
	NTFS_LOG_RECORDING_AGGREGATE_MFT_INVALID,
	NTFS_LOG_RECORDING_AGGREGATE_MEMORY_RESET,
	NTFS_LOG_RECORDING_AGGREGATE_FALLBACK,
	NTFS_LOG_RECORDING_GENERATION_COMPILE_ATTEMPT,
	NTFS_LOG_RECORDING_GENERATION_COMPILE,
	NTFS_LOG_RECORDING_GENERATION_COMPILE_BYTE,
	NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS,
	NTFS_LOG_RECORDING_TRANSACTION_COMMIT_CPU_NS,
	NTFS_LOG_RECORDING_RECORD_BUILD_CPU_NS,
	NTFS_LOG_RECORDING_RECORD_APPEND_CPU_NS,
	NTFS_LOG_RECORDING_AGGREGATE_LOOKUP_CPU_NS,
	NTFS_LOG_RECORDING_GENERATION_COMPILE_CPU_NS,
	NTFS_LOG_RECORDING_CHECKPOINT_WRITEBACK_CPU_NS,
	NTFS_LOG_RECORDING_DEFERRED_FREE,
	NTFS_LOG_RECORDING_DEFERRED_RELEASE,
	NTFS_LOG_RECORDING_DEFERRED_FALLBACK,
	NTFS_LOG_RECORDING_DEFERRED_PRESSURE,
	NTFS_LOG_RECORDING_STAT_COUNT,
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

struct ntfs_log_batch_commit {
	__le64 magic;
	__le64 magic_inv;
	__le64 generation;
	__le64 generation_inv;
	__le64 first_lsn;
	__le64 last_lsn;
	__le32 record_count;
	__le16 version;
	__le16 flags;
} __packed;

struct ntfs_log_batch_transactions {
	__le16 bitmap_bytes;
	__le16 bitmap_bits;
	__le32 committed_count;
	u8 bitmap[];
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

/* Version 1.1 open-attribute restart-table entry. */
struct ntfs_open_attr_entry_disk {
	__le32 next;
	__le32 bytes_per_index;
	__le32 type;
	u8 is_dirty_pages;
	u8 is_attr_name;
	u8 name_len;
	u8 reserved;
	__le64 mref;
	__le64 open_record_lsn;
	__le64 ptr;
} __packed;

/* Variable-length name entry referenced by an open-attribute table slot. */
struct ntfs_attr_name_entry {
	__le16 off;
	__le16 name_bytes;
	__le16 name[];
} __packed;

/* Version 1.1 dirty-page restart-table entry followed by physical LCNs. */
struct ntfs_dirty_page_entry {
	__le32 next;
	__le32 target_attr;
	__le32 transfer_len;
	__le32 lcns_follow;
	__le64 vcn;
	__le64 oldest_lsn;
	__le64 page_lcns[];
} __packed;

/* Version 1.1 transaction restart-table entry. */
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

int ntfs_log_read_client_record(struct inode *log_vi,
		const struct ntfs_logfile_layout *layout, u64 lsn,
		struct ntfs_lfs_record_hdr *hdr, void **payload, u32 *payload_len);
int ntfs_log_next_lsn(struct inode *log_vi,
		const struct ntfs_logfile_layout *layout, u64 lsn,
		const struct ntfs_lfs_record_hdr *hdr, u64 *next_lsn);
int ntfs_log_checkpoint_dump_data(const struct ntfs_lfs_record_hdr *hdr,
		const void *payload, u32 payload_len, u16 expected_op,
		u32 expected_len, const void **data, u32 *data_len);

static_assert(sizeof(struct ntfs_lfs_record_hdr) == 0x30);
static_assert(sizeof(struct ntfs_log_rec_hdr) == 0x20);
static_assert(sizeof(struct ntfs_record_page_hdr) == 0x28);
static_assert(sizeof(struct ntfs_log_restart_table) == 0x18);
static_assert(sizeof(struct ntfs_log_checkpoint) == 0x40);
static_assert(sizeof(struct ntfs_open_attr_entry_disk) == 0x28);
static_assert(sizeof(struct ntfs_transaction_entry) == 0x28);

#define NTFS_LOG_TRANSACTION_SLOT_COUNT \
	DIV_ROUND_UP(U16_MAX - sizeof(struct ntfs_log_restart_table), \
			sizeof(struct ntfs_transaction_entry))
#define NTFS_LOG_TRANSACTION_BITMAP_BYTES \
	DIV_ROUND_UP(NTFS_LOG_TRANSACTION_SLOT_COUNT, 8)

static inline int ntfs_log_transaction_slot_index(u32 id)
{
	const u32 first = sizeof(struct ntfs_log_restart_table);
	const u32 stride = sizeof(struct ntfs_transaction_entry);
	u32 index;

	if (id < first || (id - first) % stride)
		return -EINVAL;
	index = (id - first) / stride;
	return index < NTFS_LOG_TRANSACTION_SLOT_COUNT ? index : -EINVAL;
}

static inline const struct ntfs_log_batch_commit *
ntfs_log_batch_commit_candidate(const struct ntfs_log_rec_hdr *lrh, u32 bytes)
{
	const struct ntfs_log_batch_commit *commit;
	u16 redo_len;
	u16 off;

	if (!lrh || le16_to_cpu(lrh->redo_op) != Noop ||
	    le16_to_cpu(lrh->undo_op) != Noop ||
	    le16_to_cpu(lrh->target_attr) || le16_to_cpu(lrh->lcns_follow) ||
	    le16_to_cpu(lrh->undo_len))
		return NULL;
	redo_len = le16_to_cpu(lrh->redo_len);
	if (redo_len < sizeof(*commit))
		return NULL;
	off = le16_to_cpu(lrh->redo_off);
	if (off > bytes || redo_len > bytes - off)
		return NULL;
	commit = (const void *)((const u8 *)lrh + off);
	/*
	 * The incomplete on-disk form deliberately retains magic while its
	 * inverse is invalid.  Recovery recognizes it as a hard tail boundary.
	 */
	if (commit->magic != cpu_to_le64(NTFS_LOG_BATCH_COMMIT_MAGIC))
		return NULL;
	return commit;
}

static inline const struct ntfs_log_batch_commit *
ntfs_log_batch_commit_payload(const struct ntfs_log_rec_hdr *lrh, u32 bytes)
{
	const struct ntfs_log_batch_transactions *transactions;
	const struct ntfs_log_batch_commit *commit;
	u32 committed = 0;
	u16 redo_len;
	u16 version;
	u16 flags;
	u64 generation;
	unsigned int i;

	commit = ntfs_log_batch_commit_candidate(lrh, bytes);
	if (!commit)
		return NULL;
	generation = le64_to_cpu(commit->generation);
	version = le16_to_cpu(commit->version);
	flags = le16_to_cpu(commit->flags);
	redo_len = le16_to_cpu(lrh->redo_len);
	if (commit->magic_inv != cpu_to_le64(~NTFS_LOG_BATCH_COMMIT_MAGIC) ||
	    !generation || le64_to_cpu(commit->generation_inv) != ~generation ||
	    !le64_to_cpu(commit->first_lsn) ||
	    !le64_to_cpu(commit->last_lsn) || !commit->record_count)
		return NULL;
	if (version == NTFS_LOG_BATCH_COMMIT_VERSION_V1)
		return !flags && redo_len == sizeof(*commit) ? commit : NULL;
	if (version != NTFS_LOG_BATCH_COMMIT_VERSION ||
	    flags & ~NTFS_LOG_BATCH_COMMIT_RESTART_REQUIRED ||
	    redo_len != sizeof(*commit) + sizeof(*transactions) +
			NTFS_LOG_TRANSACTION_BITMAP_BYTES)
		return NULL;
	transactions = (const void *)(commit + 1);
	if (le16_to_cpu(transactions->bitmap_bytes) !=
			NTFS_LOG_TRANSACTION_BITMAP_BYTES ||
	    le16_to_cpu(transactions->bitmap_bits) !=
			NTFS_LOG_TRANSACTION_SLOT_COUNT)
		return NULL;
	for (i = 0; i < NTFS_LOG_TRANSACTION_BITMAP_BYTES; i++)
		committed += hweight8(transactions->bitmap[i]);
	/* Refuse set bits that do not name a real transaction-table slot. */
	if (NTFS_LOG_TRANSACTION_SLOT_COUNT & 7) {
		u8 valid = (1U << (NTFS_LOG_TRANSACTION_SLOT_COUNT & 7)) - 1;

		if (transactions->bitmap[NTFS_LOG_TRANSACTION_BITMAP_BYTES - 1] &
		    ~valid)
			return NULL;
	}
	if (committed != le32_to_cpu(transactions->committed_count))
		return NULL;
	return commit;
}

static inline bool ntfs_log_batch_commits_transaction(
		const struct ntfs_log_batch_commit *commit, unsigned int index)
{
	const struct ntfs_log_batch_transactions *transactions;

	if (!commit || le16_to_cpu(commit->version) !=
			NTFS_LOG_BATCH_COMMIT_VERSION ||
	    index >= NTFS_LOG_TRANSACTION_SLOT_COUNT)
		return false;
	transactions = (const void *)(commit + 1);
	return transactions->bitmap[index >> 3] & BIT(index & 7);
}

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

/* Inputs to the standalone record-page serializer and batch page packer. */
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

/* Payload shared by SetBits/ClearBits recording and replay. */
struct ntfs_bitmap_range {
	__le32 bitmap_off;
	__le32 bits;
} __packed;

struct ntfs_log_payload {
	void *data;
	u32 len;
};

struct ntfs_log_open_attr {
	struct list_head list;
	u64 mref;
	u32 type;
	u32 bytes_per_index;
	u64 open_record_lsn;
	u16 slot;
	u8 name_len;
	bool is_dirty_pages;
	__le16 name[];
};

struct ntfs_log_home_undo {
	struct list_head list;
	int (*restore)(void *data);
	int (*commit)(void *data);
	int (*abort)(void *data);
	void (*release)(void *data);
	void *data;
	u64 deferred_units;
	size_t deferred_bytes;
	u32 deferred_slot;
	enum ntfs_log_deferred_kind deferred_kind;
	bool deferred;
	bool embedded;
};

struct ntfs_log_deferred_queue {
	struct list_head pending;
	struct list_head ready;
	struct work_struct work;
	struct workqueue_struct *workqueue;
	struct ntfs_log *log;
	struct mutex free_count_lock;
	u64 units;
	/* Committed pending, ready, and in-flight units. Protected by append_lock. */
	u64 queued_units;
	size_t bytes;
	unsigned int reserved;
	unsigned int queued;
};

struct ntfs_log_undo_entry {
	struct list_head list;
	struct ntfs_log_operation_desc operation;
	u64 undo_next_lsn;
	u64 record_lsn;
	u64 packed_page_off;
	u32 packed_group;
	u64 page_lcns[];
};

struct ntfs_log_packed_append {
	u64 page_off;
	u32 group;
	bool started;
};

#define NTFS_LOG_AGGREGATE_HASH_BITS	8
#define NTFS_LOG_AGGREGATE_HASH_SIZE	(1U << NTFS_LOG_AGGREGATE_HASH_BITS)

/*
 * One overwrite-like operation that is still mutable in the current flush
 * batch.  The hash contains only the newest record for each exact target.
 * @previous links the target's append order and @anchor names the record whose
 * redo image represents all already-merged successors.
 */
struct ntfs_log_aggregate_record {
	struct list_head batch_list;
	struct list_head handle_list;
	struct hlist_node hash_node;
	struct ntfs_log_operation_desc operation;
	void *redo_image;
	size_t allocation_size;
	u64 lsn;
	u32 transaction_id;
	bool committed;
	bool mergeable;
	u64 page_lcns[];
};

struct ntfs_log_dirty_page {
	struct list_head list;
	u32 target_attr;
	u32 transfer_len;
	u16 lcns_follow;
	u64 vcn;
	u64 oldest_lsn;
	u64 latest_lsn;
	u64 page_lcns[];
};

struct ntfs_log_handle {
	struct ntfs_log *log;
	struct ntfs_log_handle *parent;
	struct task_struct *owner;
	struct list_head active_list;
	struct list_head undo_entries;
	struct list_head home_undo_entries;
	struct list_head aggregate_records;
	u64 first_lsn;
	u64 prev_lsn;
	u64 undo_next_lsn;
	unsigned long caller_ip;
	u32 transaction_id;
	u32 operation_credits;
	u32 bounded_credits;
	u32 reserved_credits;
	u32 used_credits;
	u32 next_packed_group;
	struct ntfs_log_packed_append *packed;
	bool active;
	bool admitted;
	bool independent;
	bool writeback;
	bool nowait;
	bool committed;
	bool force_durable_commit;
	bool has_deferred_free;
	bool queue_deferred_free;
	/* Checkpoint-visible state, changed with the corresponding append. */
	bool commit_recorded;
	bool forget_recorded;
	bool aborted;
	struct ntfs_log_home_undo buffered_home_undo;
	u64 home_undo_buffer[NTFS_LOG_HOME_UNDO_BUFFER_BYTES / sizeof(u64)];
	bool home_undo_buffer_used;
};

/* Immutable, MST-protected page owned by append or by one flush batch. */
struct ntfs_log_sealed_page {
	struct list_head list;
	bool has_terminal;
	u64 file_off;
	u8 data[];
};

/* Per-volume state for the journal writer. */
struct ntfs_log {
	struct ntfs_volume *vol;
	struct rw_semaphore transaction_lock;
	/* Quiesce foreground producers while checkpoint writeback still logs. */
	struct rw_semaphore admission_lock;
	struct mutex append_lock;
	struct mutex flush_lock;
	struct mutex open_attr_lock;
	struct mutex checkpoint_lock;
	struct delayed_work checkpoint_work;
	struct delayed_work reclaim_work;
	struct delayed_work flush_work;
	struct delayed_work deferred_flush_work;
	struct ntfs_log_deferred_queue deferred[NTFS_LOG_DEFERRED_KINDS];
	atomic_t deferred_users;
	wait_queue_head_t deferred_wait;
	wait_queue_head_t durable_wait;
	/* Changes whenever a transaction can leave home metadata dirty. */
	atomic64_t home_generation;
	u64 checkpointed_home_generation;
	bool checkpointed_generation_valid;
	/* Inode or metadata-page writeback deferred during a checkpoint pass. */
	atomic64_t inode_writeback_generation;
	/* Deferred writeback of an existing journaled home image. */
	atomic64_t home_writeback_generation;
	u64 checkpointed_inode_writeback_generation;
	/* Successful full checkpoints, sampled and advanced under append_lock. */
	u64 checkpoint_generation;
	struct ntfs_logfile_layout layout;
	u64 head_lsn;
	u64 durable_lsn;
	u64 pending_lsn;
	u64 pending_first_lsn;
	u64 oldest_lsn;
	u64 checkpoint_lsn;
	/* Checkpoint appended but not yet published in a restart copy. */
	u64 pending_checkpoint_lsn;
	u64 pending_oldest_lsn;
	bool pending_clean;
	bool pending_ordered_data;
	struct list_head pending_ordered_io;
	struct workqueue_struct *ordered_io_wq;
	mempool_t *ordered_io_pool;
	bool flush_inflight;
	u64 last_client_lsn;
	u32 restart_log_open_count;
	u16 restart_slot;
	u16 usa_seq;
	u16 next_open_attr_slot;
	u32 next_transaction_id;
	u64 batch_generation;
	u32 reserved_pages;
	/* Shared slack spent. Fully charged when no ordinary begin funded it. */
	u32 growth_credits;
	u32 pending_records;
	/* A committed slot is reusable only after its containing batch is safe. */
	unsigned long *retired_transaction_ids;
	struct list_head sealed_pages;
	struct list_head aggregate_records;
	struct hlist_head *aggregate_hash;
	size_t aggregate_bytes;
	size_t aggregate_limit;
	u64 sealed_bytes;
	u64 staging_limit;
	void *pending_page;
	u64 pending_page_off;
	u32 pending_page_records;
	bool pending_page_has_terminal;
	u64 pending_bdev_start;
	u64 pending_bdev_end;
	bool pending_bdev_range_valid;
	bool pending_bdev_range_full;
	struct list_head open_attrs;
	struct list_head active_handles;
	struct list_head dirty_pages;
	bool running;
	bool aborted;
	bool stopping;
	bool restart_slot_valid;
	bool async_commit;
	/* Checkpoint is collecting WAL before its batched home-data pass. */
	bool checkpoint_collecting;
	unsigned long commit_interval;
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
int ntfs_log_build_checkpoint_dump_payload(u16 operation,
		const struct ntfs_log_payload *dump,
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
int ntfs_log_write_operation(struct ntfs_log_handle *handle,
		const struct ntfs_log_operation_desc *operation, u64 *lsn_out);
extern struct static_key_false ntfs_log_recording_stats_key;

static inline bool ntfs_log_recording_stats_enabled(void)
{
	return static_branch_unlikely(&ntfs_log_recording_stats_key);
}

void __ntfs_log_recording_account(enum ntfs_log_recording_stat stat, u64 count);
void __ntfs_log_recording_account_operation(u16 operation, u32 bytes);

static inline void ntfs_log_recording_account(
		enum ntfs_log_recording_stat stat, u64 count)
{
	if (ntfs_log_recording_stats_enabled())
		__ntfs_log_recording_account(stat, count);
}

static inline void ntfs_log_recording_account_operation(u16 operation, u32 bytes)
{
	if (ntfs_log_recording_stats_enabled())
		__ntfs_log_recording_account_operation(operation, bytes);
}

#endif /* _LINUX_NTFS_LOGFILE_INTERNAL_H */
