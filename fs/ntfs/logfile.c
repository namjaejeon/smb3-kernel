// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS kernel journal handling.
 *
 * Copyright (c) 2002-2007 Anton Altaparmakov
 */

#include <linux/blkdev.h>
#include <linux/debugfs.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/unaligned.h>

#include "attrib.h"
#include "inode.h"
#include "logfile.h"
#include "logfile_internal.h"
#include "mft.h"
#include "ntfs.h"
#include "runlist.h"

#define CREATE_TRACE_POINTS
#include "logfile_trace.h"

#define NTFS_LOG_REPLAY_OPCODE_COUNT (ZeroEndOfFileRecord + 1)

enum ntfs_log_replay_phase {
	NTFS_LOG_REPLAY_REDO,
	NTFS_LOG_REPLAY_UNDO,
	NTFS_LOG_REPLAY_PHASE_COUNT,
};

enum ntfs_log_replay_outcome {
	NTFS_LOG_REPLAY_SEEN,
	NTFS_LOG_REPLAY_DISPATCHED,
	NTFS_LOG_REPLAY_SKIP_ACTION,
	NTFS_LOG_REPLAY_SKIP_NO_LCNS,
	NTFS_LOG_REPLAY_SKIP_DIRTY_PAGE,
	NTFS_LOG_REPLAY_SKIP_OLD_LSN,
	NTFS_LOG_REPLAY_FAILED,
	NTFS_LOG_REPLAY_OUTCOME_COUNT,
};

static atomic64_t ntfs_log_replay_stats[NTFS_LOG_REPLAY_PHASE_COUNT]
	[NTFS_LOG_REPLAY_OPCODE_COUNT][NTFS_LOG_REPLAY_OUTCOME_COUNT];
static atomic64_t ntfs_log_recording_stats[NTFS_LOG_RECORDING_STAT_COUNT];
DEFINE_STATIC_KEY_FALSE(ntfs_log_recording_stats_key);
/* Keep the profiling mode fixed while an operation's timers are running. */
static bool journal_stats;
module_param(journal_stats, bool, 0444);
MODULE_PARM_DESC(journal_stats,
	"Collect journal counters and CPU timings (default N)");
static atomic64_t ntfs_log_recording_operation_count[
		NTFS_LOG_REPLAY_OPCODE_COUNT];
static atomic64_t ntfs_log_recording_operation_bytes[
		NTFS_LOG_REPLAY_OPCODE_COUNT];
static struct dentry *ntfs_log_replay_debugfs_dir;

static const char * const ntfs_log_recording_stat_names[] = {
	[NTFS_LOG_RECORDING_BEGIN] = "transactions_begin",
	[NTFS_LOG_RECORDING_COMMIT] = "transactions_commit",
	[NTFS_LOG_RECORDING_ABORT] = "transactions_abort",
	[NTFS_LOG_RECORDING_RECORD] = "records",
	[NTFS_LOG_RECORDING_PAGE] = "record_pages",
	[NTFS_LOG_RECORDING_PACKED_RECORD] = "packed_records",
	[NTFS_LOG_RECORDING_BYTE] = "record_bytes",
	[NTFS_LOG_RECORDING_RECORD_FLUSH] = "record_flushes",
	[NTFS_LOG_RECORDING_FLUSHED_RECORD] = "records_flushed",
	[NTFS_LOG_RECORDING_RESTART_WRITE] = "restart_writes",
	[NTFS_LOG_RECORDING_RESTART_FLUSH] = "restart_flushes",
	[NTFS_LOG_RECORDING_CHECKPOINT] = "checkpoints",
	[NTFS_LOG_RECORDING_BACKGROUND_CHECKPOINT] = "background_checkpoints",
	[NTFS_LOG_RECORDING_EXPLICIT_CHECKPOINT] = "explicit_checkpoints",
	[NTFS_LOG_RECORDING_SPACE_CHECKPOINT] = "space_pressure_checkpoints",
	[NTFS_LOG_RECORDING_MOUNT_CHECKPOINT] = "mount_checkpoints",
	[NTFS_LOG_RECORDING_UNMOUNT_CHECKPOINT] = "unmount_checkpoints",
	[NTFS_LOG_RECORDING_MOUNT_DIRTY_COMBINED_FLUSH] =
			"mount_dirty_combined_flushes",
	[NTFS_LOG_RECORDING_UNMOUNT_CLEAN_COMBINED_FLUSH] =
			"unmount_clean_combined_flushes",
	[NTFS_LOG_RECORDING_UNMOUNT_FINAL_FLUSH] =
			"unmount_final_flushes",
	[NTFS_LOG_RECORDING_UNMOUNT_FINAL_FLUSH_NS] =
			"unmount_final_flush_nanoseconds",
	[NTFS_LOG_RECORDING_LIFECYCLE_FALLBACK_FLUSH] =
			"lifecycle_fallback_flushes",
	[NTFS_LOG_RECORDING_LIFECYCLE_FALLBACK_FLUSH_NS] =
			"lifecycle_fallback_flush_nanoseconds",
	[NTFS_LOG_RECORDING_CHECKPOINT_SKIP] = "checkpoint_skips",
	[NTFS_LOG_RECORDING_EXPLICIT_CHECKPOINT_SKIP] =
			"explicit_checkpoint_skips",
	[NTFS_LOG_RECORDING_CHECKPOINT_OPEN_ATTR] = "checkpoint_open_attrs",
	[NTFS_LOG_RECORDING_CHECKPOINT_DIRTY_PAGE] = "checkpoint_dirty_pages",
	[NTFS_LOG_RECORDING_CHECKPOINT_TRANSACTION] =
			"checkpoint_transactions",
	[NTFS_LOG_RECORDING_LSN_WAIT] = "lsn_waits",
	[NTFS_LOG_RECORDING_RESERVATION_GROW] = "reservation_grows",
	[NTFS_LOG_RECORDING_RESERVATION_PAGES] = "reservation_growth_pages",
	[NTFS_LOG_RECORDING_RESERVATION_FAILURE] =
			"reservation_growth_failures",
	[NTFS_LOG_RECORDING_EMPTY_COMMIT] = "empty_commits",
	[NTFS_LOG_RECORDING_FLUSH_NS] = "flush_nanoseconds",
	[NTFS_LOG_RECORDING_CHECKPOINT_SYNC] = "checkpoint_sync_passes",
	[NTFS_LOG_RECORDING_ORDERED_FLUSH] = "ordered_data_flushes",
	[NTFS_LOG_RECORDING_RESTART_SKIPPED] = "restart_writes_skipped",
	[NTFS_LOG_RECORDING_APPEND_DURING_FLUSH] = "appends_during_flush",
	[NTFS_LOG_RECORDING_WRITEBACK_DEFER] = "writeback_deferrals",
	[NTFS_LOG_RECORDING_LOCKED_BEGIN_DEFER] = "locked_begin_deferrals",
	[NTFS_LOG_RECORDING_COMMIT_WORKER] = "commit_worker_flushes",
	[NTFS_LOG_RECORDING_FLUSH_LOCK_WAIT_NS] =
			"flush_lock_wait_nanoseconds",
	[NTFS_LOG_RECORDING_ORDERED_FLUSH_NS] =
			"ordered_flush_nanoseconds",
	[NTFS_LOG_RECORDING_LOG_WRITEBACK_NS] =
			"log_writeback_nanoseconds",
	[NTFS_LOG_RECORDING_RECORD_CACHE_FLUSH_NS] =
			"record_cache_flush_nanoseconds",
	[NTFS_LOG_RECORDING_RESTART_WRITE_NS] =
			"restart_write_nanoseconds",
	[NTFS_LOG_RECORDING_RESTART_CACHE_FLUSH_NS] =
			"restart_cache_flush_nanoseconds",
	[NTFS_LOG_RECORDING_CHECKPOINT_INODE_SYNC_NS] =
			"checkpoint_inode_sync_nanoseconds",
	[NTFS_LOG_RECORDING_CHECKPOINT_HOME_WRITEBACK_NS] =
			"checkpoint_home_writeback_nanoseconds",
	[NTFS_LOG_RECORDING_CHECKPOINT_HOME_FLUSH_NS] =
			"checkpoint_home_flush_nanoseconds",
	[NTFS_LOG_RECORDING_BATCH_MARKER] = "batch_commit_markers",
	[NTFS_LOG_RECORDING_BATCH_MARKER_FLUSH_NS] =
			"batch_marker_flush_nanoseconds",
	[NTFS_LOG_RECORDING_BATCH_MARKER_WRITE_NS] =
			"batch_marker_write_nanoseconds",
	[NTFS_LOG_RECORDING_COMBINED_CHECKPOINT_FLUSH] =
			"combined_checkpoint_flushes",
	[NTFS_LOG_RECORDING_GENERATION_COMMIT] = "generation_commits",
	[NTFS_LOG_RECORDING_COMMIT_RECORD_ELIDED] =
			"commit_records_elided",
	[NTFS_LOG_RECORDING_BATCH_COMMITTED_TRANSACTION] =
			"batch_committed_transactions",
	[NTFS_LOG_RECORDING_GENERATION_METADATA_COALESCE] =
			"generation_metadata_coalesces",
	[NTFS_LOG_RECORDING_FORGET_ELIDED] = "forget_records_elided",
	[NTFS_LOG_RECORDING_COALESCE_ATTEMPT] =
			"metadata_coalesce_attempts",
	[NTFS_LOG_RECORDING_COALESCE_HIT] = "metadata_coalesce_hits",
	[NTFS_LOG_RECORDING_COALESCE_BYTE] = "metadata_coalesced_bytes",
	[NTFS_LOG_RECORDING_METADATA_HOME_FLUSH] = "metadata_home_flushes",
	[NTFS_LOG_RECORDING_METADATA_HOME_FLUSH_NS] =
			"metadata_home_flush_nanoseconds",
	[NTFS_LOG_RECORDING_AGGREGATE_TOUCH] = "aggregate_touches",
	[NTFS_LOG_RECORDING_AGGREGATE_UNIQUE] = "aggregate_unique_records",
	[NTFS_LOG_RECORDING_AGGREGATE_MERGE] = "aggregate_merged_records",
	[NTFS_LOG_RECORDING_AGGREGATE_BYTE] = "aggregate_merged_bytes",
	[NTFS_LOG_RECORDING_AGGREGATE_RECLAIM_BYTE] =
			"aggregate_reclaimed_bytes",
	[NTFS_LOG_RECORDING_ELIDED_RECORD] = "records_elided",
	[NTFS_LOG_RECORDING_ELIDED_TRANSACTION] = "transactions_elided",
	[NTFS_LOG_RECORDING_SIZE_COALESCE] = "size_updates_precoalesced",
	[NTFS_LOG_RECORDING_MAPPING_COALESCE] = "mapping_updates_precoalesced",
	[NTFS_LOG_RECORDING_ID_PRESSURE_FLUSH] = "id_pressure_flushes",
	[NTFS_LOG_RECORDING_AGGREGATE_BITMAP_MERGE] =
			"aggregate_bitmap_merges",
	[NTFS_LOG_RECORDING_AGGREGATE_MFT_FOLD_ATTEMPT] =
			"aggregate_mft_fold_attempts",
	[NTFS_LOG_RECORDING_AGGREGATE_MFT_FOLD] =
			"aggregate_mft_folds",
	[NTFS_LOG_RECORDING_AGGREGATE_MFT_NO_ANCHOR] =
			"aggregate_mft_no_anchor",
	[NTFS_LOG_RECORDING_AGGREGATE_MFT_NOT_TAIL] =
			"aggregate_mft_not_tail",
	[NTFS_LOG_RECORDING_AGGREGATE_MFT_IMMUTABLE] =
			"aggregate_mft_immutable",
	[NTFS_LOG_RECORDING_AGGREGATE_MFT_INVALID] =
			"aggregate_mft_invalid",
	[NTFS_LOG_RECORDING_AGGREGATE_MEMORY_RESET] =
			"aggregate_memory_resets",
	[NTFS_LOG_RECORDING_AGGREGATE_FALLBACK] = "aggregate_fallback_records",
	[NTFS_LOG_RECORDING_GENERATION_COMPILE_ATTEMPT] =
			"generation_compile_attempts",
	[NTFS_LOG_RECORDING_GENERATION_COMPILE] =
			"generation_compiled_records",
	[NTFS_LOG_RECORDING_GENERATION_COMPILE_BYTE] =
			"generation_compiled_bytes",
	[NTFS_LOG_RECORDING_TRANSACTION_BEGIN_CPU_NS] =
			"transaction_begin_cpu_nanoseconds",
	[NTFS_LOG_RECORDING_TRANSACTION_COMMIT_CPU_NS] =
			"transaction_commit_cpu_nanoseconds",
	[NTFS_LOG_RECORDING_RECORD_BUILD_CPU_NS] =
			"record_build_cpu_nanoseconds",
	[NTFS_LOG_RECORDING_RECORD_APPEND_CPU_NS] =
			"record_append_cpu_nanoseconds",
	[NTFS_LOG_RECORDING_AGGREGATE_LOOKUP_CPU_NS] =
			"aggregate_lookup_cpu_nanoseconds",
	[NTFS_LOG_RECORDING_GENERATION_COMPILE_CPU_NS] =
			"generation_compile_cpu_nanoseconds",
	[NTFS_LOG_RECORDING_CHECKPOINT_WRITEBACK_CPU_NS] =
			"checkpoint_writeback_cpu_nanoseconds",
	[NTFS_LOG_RECORDING_DEFERRED_FREE] = "deferred_frees",
	[NTFS_LOG_RECORDING_DEFERRED_RELEASE] = "deferred_releases",
	[NTFS_LOG_RECORDING_DEFERRED_FALLBACK] = "deferred_fallbacks",
	[NTFS_LOG_RECORDING_DEFERRED_PRESSURE] = "deferred_pressure_drains",
};

static const char * const ntfs_log_operation_names[NTFS_LOG_REPLAY_OPCODE_COUNT] = {
	[Noop] = "Noop",
	[CompensationLogRecord] = "CompensationLogRecord",
	[InitializeFileRecordSegment] = "InitializeFileRecordSegment",
	[DeallocateFileRecordSegment] = "DeallocateFileRecordSegment",
	[WriteEndOfFileRecordSegment] = "WriteEndOfFileRecordSegment",
	[CreateAttribute] = "CreateAttribute",
	[DeleteAttribute] = "DeleteAttribute",
	[UpdateResidentValue] = "UpdateResidentValue",
	[UpdateNonresidentValue] = "UpdateNonresidentValue",
	[UpdateMappingPairs] = "UpdateMappingPairs",
	[DeleteDirtyClusters] = "DeleteDirtyClusters",
	[SetNewAttributeSizes] = "SetNewAttributeSizes",
	[AddIndexEntryRoot] = "AddIndexEntryRoot",
	[DeleteIndexEntryRoot] = "DeleteIndexEntryRoot",
	[AddIndexEntryAllocation] = "AddIndexEntryAllocation",
	[DeleteIndexEntryAllocation] = "DeleteIndexEntryAllocation",
	[WriteEndOfIndexBuffer] = "WriteEndOfIndexBuffer",
	[SetIndexEntryVcnRoot] = "SetIndexEntryVcnRoot",
	[SetIndexEntryVcnAllocation] = "SetIndexEntryVcnAllocation",
	[UpdateFileNameRoot] = "UpdateFileNameRoot",
	[UpdateFileNameAllocation] = "UpdateFileNameAllocation",
	[SetBitsInNonresidentBitMap] = "SetBitsInNonresidentBitMap",
	[ClearBitsInNonresidentBitMap] = "ClearBitsInNonresidentBitMap",
	[HotFix] = "HotFix",
	[EndTopLevelAction] = "EndTopLevelAction",
	[PrepareTransaction] = "PrepareTransaction",
	[CommitTransaction] = "CommitTransaction",
	[ForgetTransaction] = "ForgetTransaction",
	[OpenNonresidentAttribute] = "OpenNonresidentAttribute",
	[OpenAttributeTableDump] = "OpenAttributeTableDump",
	[AttributeNamesDump] = "AttributeNamesDump",
	[DirtyPageTableDump] = "DirtyPageTableDump",
	[TransactionTableDump] = "TransactionTableDump",
	[UpdateRecordDataRoot] = "UpdateRecordDataRoot",
	[UpdateRecordDataAllocation] = "UpdateRecordDataAllocation",
	[UpdateRelativeDataIndex] = "UpdateRelativeDataIndex",
	[UpdateRelativeDataAllocation] = "UpdateRelativeDataAllocation",
	[ZeroEndOfFileRecord] = "ZeroEndOfFileRecord",
};

static const char * const ntfs_log_replay_phase_names[] = {
	[NTFS_LOG_REPLAY_REDO] = "redo",
	[NTFS_LOG_REPLAY_UNDO] = "undo",
};

static void ntfs_log_replay_reset_stats(void)
{
	u16 op;
	u8 phase;
	u8 outcome;

	for (phase = 0; phase < NTFS_LOG_REPLAY_PHASE_COUNT; phase++)
		for (op = 0; op < NTFS_LOG_REPLAY_OPCODE_COUNT; op++)
			for (outcome = 0; outcome < NTFS_LOG_REPLAY_OUTCOME_COUNT;
			     outcome++)
				atomic64_set(&ntfs_log_replay_stats[phase][op][outcome], 0);
}

static void ntfs_log_recording_reset_stats(void)
{
	u16 operation;
	u8 stat;

	for (stat = 0; stat < NTFS_LOG_RECORDING_STAT_COUNT; stat++)
		atomic64_set(&ntfs_log_recording_stats[stat], 0);
	for (operation = 0; operation < NTFS_LOG_REPLAY_OPCODE_COUNT;
	     operation++) {
		atomic64_set(&ntfs_log_recording_operation_count[operation], 0);
		atomic64_set(&ntfs_log_recording_operation_bytes[operation], 0);
	}
}

void __ntfs_log_recording_account(enum ntfs_log_recording_stat stat, u64 count)
{
	if (stat < NTFS_LOG_RECORDING_STAT_COUNT)
		atomic64_add(count, &ntfs_log_recording_stats[stat]);
}

void __ntfs_log_recording_account_operation(u16 operation, u32 bytes)
{
	if (operation >= NTFS_LOG_REPLAY_OPCODE_COUNT)
		return;
	atomic64_inc(&ntfs_log_recording_operation_count[operation]);
	atomic64_add(bytes, &ntfs_log_recording_operation_bytes[operation]);
}

void ntfs_log_account_metadata_home_flush(u64 nanoseconds)
{
	ntfs_log_recording_account(NTFS_LOG_RECORDING_METADATA_HOME_FLUSH, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_METADATA_HOME_FLUSH_NS,
			nanoseconds);
}

void ntfs_log_account_unmount_final_flush(u64 nanoseconds)
{
	ntfs_log_recording_account(NTFS_LOG_RECORDING_UNMOUNT_FINAL_FLUSH, 1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_UNMOUNT_FINAL_FLUSH_NS,
				   nanoseconds);
}

void ntfs_log_account_lifecycle_fallback_flush(u64 nanoseconds)
{
	ntfs_log_recording_account(NTFS_LOG_RECORDING_LIFECYCLE_FALLBACK_FLUSH,
				   1);
	ntfs_log_recording_account(NTFS_LOG_RECORDING_LIFECYCLE_FALLBACK_FLUSH_NS,
				   nanoseconds);
}

static int ntfs_log_recording_stats_show(struct seq_file *m, void *unused)
{
	u16 operation;
	u8 stat;

	seq_puts(m, "# write 'reset' to this file to clear all counters\n");
	seq_printf(m, "# journal_stats=%c (reload with journal_stats=Y to profile)\n",
		   journal_stats ? 'Y' : 'N');
	for (stat = 0; stat < NTFS_LOG_RECORDING_STAT_COUNT; stat++)
		seq_printf(m, "%-24s %lld\n",
				ntfs_log_recording_stat_names[stat],
				atomic64_read(&ntfs_log_recording_stats[stat]));
	for (operation = 0; operation < NTFS_LOG_REPLAY_OPCODE_COUNT;
	     operation++) {
		s64 count = atomic64_read(
				&ntfs_log_recording_operation_count[operation]);

		if (!count)
			continue;
		seq_printf(m, "record_op_%-14s %lld %lld\n",
				ntfs_log_operation_names[operation], count,
				atomic64_read(
				&ntfs_log_recording_operation_bytes[operation]));
	}
	return 0;
}

static int ntfs_log_recording_stats_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, ntfs_log_recording_stats_show,
			inode->i_private);
}

static ssize_t ntfs_log_recording_stats_write(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	char command[16];
	size_t len = min(count, sizeof(command) - 1);

	if (copy_from_user(command, buf, len))
		return -EFAULT;
	command[len] = '\0';
	if (!sysfs_streq(command, "reset"))
		return -EINVAL;
	ntfs_log_recording_reset_stats();
	return count;
}

static const struct file_operations ntfs_log_recording_stats_fops = {
	.owner = THIS_MODULE,
	.open = ntfs_log_recording_stats_open,
	.read = seq_read,
	.write = ntfs_log_recording_stats_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int ntfs_log_replay_stats_show(struct seq_file *m, void *unused)
{
	u16 op;
	u8 phase;

	seq_puts(m, "# write 'reset' to this file to clear all counters\n");
	seq_puts(m, "# phase opcode name seen dispatched skip_action skip_no_lcns skip_dirty_page skip_old_lsn failed\n");
	for (phase = 0; phase < NTFS_LOG_REPLAY_PHASE_COUNT; phase++) {
		for (op = 0; op < NTFS_LOG_REPLAY_OPCODE_COUNT; op++) {
			seq_printf(m, "%s 0x%02x %-34s %lld %lld %lld %lld %lld %lld %lld\n",
				   ntfs_log_replay_phase_names[phase], op,
				   ntfs_log_operation_names[op],
				   atomic64_read(&ntfs_log_replay_stats[phase][op]
					   [NTFS_LOG_REPLAY_SEEN]),
				   atomic64_read(&ntfs_log_replay_stats[phase][op]
					   [NTFS_LOG_REPLAY_DISPATCHED]),
				   atomic64_read(&ntfs_log_replay_stats[phase][op]
					   [NTFS_LOG_REPLAY_SKIP_ACTION]),
				   atomic64_read(&ntfs_log_replay_stats[phase][op]
					   [NTFS_LOG_REPLAY_SKIP_NO_LCNS]),
				   atomic64_read(&ntfs_log_replay_stats[phase][op]
					   [NTFS_LOG_REPLAY_SKIP_DIRTY_PAGE]),
				   atomic64_read(&ntfs_log_replay_stats[phase][op]
					   [NTFS_LOG_REPLAY_SKIP_OLD_LSN]),
				   atomic64_read(&ntfs_log_replay_stats[phase][op]
					   [NTFS_LOG_REPLAY_FAILED]));
		}
	}
	return 0;
}

static int ntfs_log_replay_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, ntfs_log_replay_stats_show, inode->i_private);
}

static ssize_t ntfs_log_replay_stats_write(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	char command[16];
	size_t len = min(count, sizeof(command) - 1);

	if (copy_from_user(command, buf, len))
		return -EFAULT;
	command[len] = '\0';
	if (!sysfs_streq(command, "reset"))
		return -EINVAL;

	ntfs_log_replay_reset_stats();
	return count;
}

static const struct file_operations ntfs_log_replay_stats_fops = {
	.owner = THIS_MODULE,
	.open = ntfs_log_replay_stats_open,
	.read = seq_read,
	.write = ntfs_log_replay_stats_write,
	.llseek = seq_lseek,
	.release = single_release,
};

int ntfs_log_replay_stats_init(void)
{
	struct dentry *file;

	if (journal_stats)
		static_branch_enable(&ntfs_log_recording_stats_key);
	ntfs_log_replay_reset_stats();
	ntfs_log_recording_reset_stats();
	ntfs_log_replay_debugfs_dir = debugfs_create_dir("ntfs", NULL);
	if (IS_ERR(ntfs_log_replay_debugfs_dir)) {
		ntfs_log_replay_debugfs_dir = NULL;
		return 0;
	}

	file = debugfs_create_file("log_replay_stats", 0600,
			ntfs_log_replay_debugfs_dir, NULL,
			&ntfs_log_replay_stats_fops);
	if (IS_ERR_OR_NULL(file)) {
		debugfs_remove_recursive(ntfs_log_replay_debugfs_dir);
		ntfs_log_replay_debugfs_dir = NULL;
		return 0;
	}
	file = debugfs_create_file("log_recording_stats", 0600,
			ntfs_log_replay_debugfs_dir, NULL,
			&ntfs_log_recording_stats_fops);
	if (IS_ERR_OR_NULL(file)) {
		debugfs_remove_recursive(ntfs_log_replay_debugfs_dir);
		ntfs_log_replay_debugfs_dir = NULL;
		return 0;
	}
	return 0;
}

void ntfs_log_replay_stats_exit(void)
{
	debugfs_remove_recursive(ntfs_log_replay_debugfs_dir);
	ntfs_log_replay_debugfs_dir = NULL;
}

/*
 * struct ntfs_log_replay_ctx - Restart-derived state shared across replay passes
 *
 * Stores the minimal checkpoint and dirty-volume state that prepare/analyze
 * decode up front and that redo/undo consume later without reparsing restart
 * pages again.
 *
 * @valid:                True once the restart page has been parsed into this
 *                        context without structural errors.
 * @needs_replay:         True when the restart area says the volume was not
 *                        cleanly unmounted and redo/undo must run.
 * @is_clean:             True when the restart page reports a clean volume or
 *                        when the restart page itself is the CHKD variant.
 * @analysis_ready:       True after the analysis pass has reconstructed the
 *                        checkpoint-derived replay window and table counts.
 * @major_ver:            Major $LogFile version from the restart page.
 * @minor_ver:            Minor $LogFile version from the restart page.
 * @restart_flags:        Restart-area flags such as RESTART_VOLUME_IS_CLEAN.
 * @client_in_use:        Client slot index taken from client_in_use_list.
 * @current_lsn:          Current LSN recorded by the restart page / area.
 * @oldest_lsn:           Oldest LSN the replay code chooses to keep in
 *                        the current run.
 * @checkpoint_lsn:       LSN of the checkpoint record reached through the
 *                        active client record.
 * @oldest_dirty_page_lsn:
 *                        Earliest dirty-page LSN discovered in the checkpoint
 *                        dirty-page table.
 * @transaction_entries:  Number of active entries reconstructed from the
 *                        checkpoint transaction table.
 * @dirty_page_entries:   Number of dirty-page slots seen in the checkpoint
 *                        dirty-page table.
 */
struct ntfs_log_replay_ctx {
	bool valid;
	bool needs_replay;
	bool is_clean;
	bool analysis_ready;
	u16 major_ver;
	u16 minor_ver;
	u16 restart_flags;
	u16 client_in_use;
	u64 current_lsn;
	u64 oldest_lsn;
	u64 checkpoint_lsn;
	u64 oldest_dirty_page_lsn;
	u32 transaction_entries;
	u32 dirty_page_entries;
};

/*
 * struct ntfs_dirty_page_entry - One dirty-page slot from the checkpoint dump
 *
 * Records which attribute/page range was dirty and the oldest LSN whose data
 * may still need to be replayed for that page.
 *
 * @next:                 Restart-table link / bookkeeping field for the next
 *                        slot.
 * @target_attr:          Open-attribute table slot for the dirty attribute.
 * @transfer_len:         Length of the dirty range represented by this entry.
 * @lcns_follow:          Number of trailing LCN values that belong to the
 *                        serialized entry.
 * @vcn:                  Starting VCN of the dirty range.
 * @oldest_lsn:           Earliest LSN whose contents may still be needed to
 *                        refresh this page.
 */
static void ntfs_log_replay_account(const struct ntfs_volume *vol,
		const struct ntfs_lfs_record_hdr *hdr, u8 phase, u16 op,
		u8 outcome, int error)
{
	const char *device = vol && vol->sb ? vol->sb->s_id : "unknown";
	u64 lsn = hdr ? le64_to_cpu(hdr->this_lsn) : 0;
	u32 transaction_id = hdr ? le32_to_cpu(hdr->transact_id) : 0;

	if (phase < NTFS_LOG_REPLAY_PHASE_COUNT &&
	    op < NTFS_LOG_REPLAY_OPCODE_COUNT &&
	    outcome < NTFS_LOG_REPLAY_OUTCOME_COUNT)
		atomic64_inc(&ntfs_log_replay_stats[phase][op][outcome]);

	trace_ntfs_log_replay_record(device, phase, op, lsn, transaction_id,
			outcome, error);
}

static int ntfs_log_replay_dispatch_result(const struct ntfs_volume *vol,
		const struct ntfs_lfs_record_hdr *hdr, u8 phase, u16 op, int error)
{
	ntfs_log_replay_account(vol, hdr, phase, op,
			error ? NTFS_LOG_REPLAY_FAILED : NTFS_LOG_REPLAY_DISPATCHED,
			error);
	return error;
}

struct ntfs_open_attr_entry_disk32 {
	__le32 next;
	__le32 ptr;
	__le64 mref;
	__le64 open_record_lsn;
	u8 is_dirty_pages;
	u8 is_attr_name;
	u8 reserved0[2];
	__le32 type;
	u8 name_len;
	u8 reserved1[3];
	__le32 attribute_name;
	__le32 bytes_per_index;
} __packed;

static_assert(sizeof(struct ntfs_open_attr_entry_disk32) == 0x2c);

struct ntfs_dirty_page_entry32 {
	__le32 next;
	__le32 target_attr;
	__le32 transfer_len;
	__le32 lcns_follow;
	__le32 reserved;
	__le32 vcn_low;
	__le32 vcn_high;
	__le32 oldest_lsn_low;
	__le32 oldest_lsn_high;
	__le32 page_lcns[];
} __packed;

static_assert(sizeof(struct ntfs_dirty_page_entry32) == 0x24);

/*
 * struct ntfs_attr_name_entry - Variable-length attribute-name table entry
 *
 * Binds a UTF-16 attribute name blob to an open-attribute entry offset inside
 * the checkpoint dump.
 *
 * @off:                  Offset of the owning open-attribute entry inside the
 *                        serialized open-attribute table.
 * @name_bytes:           Length in bytes of the trailing UTF-16 name buffer.
 * @name:                 Flexible UTF-16 attribute name payload.
 */
struct ntfs_lcn_range {
	__le64 lcn;
	__le64 len;
} __packed;

/*
 * struct ntfs_file_name_dup_info - Logged $FILE_NAME duplicate-info subset
 *
 * Matches the timestamp, size, and attribute portion of a FILE_NAME attribute
 * that certain rename/index update records need to copy into directory entries.
 *
 * @creation_time:        File creation timestamp.
 * @last_data_change_time:
 *                        Last data modification timestamp.
 * @last_mft_change_time: Last metadata change timestamp.
 * @last_access_time:     Last access timestamp.
 * @allocated_size:       Allocated size copied into the directory entry.
 * @data_size:            Logical data size copied into the directory entry.
 * @file_attributes:      FILE_ATTR_* bitmask copied into the directory entry.
 * @type.ea.packed_ea_size:
 *                        Packed EA size when the duplicate-info represents EA
 *                        metadata.
 * @type.ea.reserved:     Reserved padding in the EA view.
 * @type.rp.reparse_point_tag:
 *                        Reparse point tag when the duplicate-info describes a
 *                        reparse point entry.
 */
struct ntfs_file_name_dup_info {
	__le64 creation_time;
	__le64 last_data_change_time;
	__le64 last_mft_change_time;
	__le64 last_access_time;
	__le64 allocated_size;
	__le64 data_size;
	__le32 file_attributes;
	union {
		struct {
			__le16 packed_ea_size;
			__le16 reserved;
		} __packed ea;
		struct {
			__le32 reparse_point_tag;
		} __packed rp;
	} __packed type;
} __packed;

/*
 * struct ntfs_redo_open_attr - In-memory expansion of one open-attribute slot
 *
 * Caches the attribute identity and decoded name information that redo/undo
 * use when locating target attributes inside MFT records.
 *
 * @list:                 Link in env->open_attrs.
 * @offset:               Offset of the original on-disk checkpoint slot.
 * @type:                 NTFS attribute type code.
 * @mref:                 MFT reference of the file owning the attribute.
 * @bytes_per_index:      Index block size for index-related attributes.
 * @is_dirty_pages:       True when this entry refers to the dirty-pages stream.
 * @name:                 Heap-allocated UTF-16 attribute name buffer.
 * @name_len:             Number of UTF-16 code units in @name.
 */
struct ntfs_redo_open_attr {
	struct list_head list;
	struct ntfs_redo_env *env;
	u16 offset;
	__le32 type;
	__le64 mref;
	u32 bytes_per_index;
	bool is_dirty_pages;
	bool expects_name;
	u8 expected_name_len;
	__le16 *name;
	u16 name_len;
};

static bool ntfs_checkpoint_dump_ref_valid(__le64 lsn, __le32 len)
{
	return !!le64_to_cpu(lsn) == !!le32_to_cpu(len);
}

static bool ntfs_redo_undo_next_valid(const struct ntfs_logfile_layout *layout,
		u64 current_lsn, u64 next_lsn)
{
	return next_lsn && next_lsn < current_lsn &&
		next_lsn >= layout->oldest_lsn &&
		next_lsn <= layout->current_lsn;
}

/*
 * struct ntfs_redo_transaction - In-memory transaction state for replay walks
 *
 * Tracks transaction slots that remain relevant after checkpoint loading so
 * undo can follow the correct chains later.
 *
 * @list:                 Link in env->transactions.
 * @slot:                 Original checkpoint slot number for the transaction.
 * @state:                Current transaction state from enum ntfs_transact_state.
 * @first_lsn:            First LSN belonging to the transaction.
 * @undo_next_lsn:        Next LSN undo should consume for the transaction.
 */
struct ntfs_redo_transaction {
	struct list_head list;
	u32 slot;
	u8 state;
	u64 first_lsn;
	u64 undo_next_lsn;
};

/*
 * struct ntfs_redo_dirty_page - In-memory dirty-page checkpoint/prepass state
 *
 * Tracks the LCN array associated with one dirty-page slot so analysis-like
 * prepass updates such as DeleteDirtyClusters and HotFix can refine the
 * earliest redo LSN before the real redo walk begins.
 *
 * @list:                 Link in env->dirty_pages.
 * @target_attr:          Open-attribute slot referenced by this dirty page.
 * @transfer_len:         Serialized byte span represented by the slot.
 * @lcns_follow:          Number of valid LCNs in @page_lcns.
 * @vcn:                  Starting VCN of the dirty page range.
 * @oldest_lsn:           Earliest LSN still required to refresh this page.
 * @page_lcns:            Current LCNs associated with the dirty pages.
 */
struct ntfs_redo_dirty_page {
	struct list_head list;
	u32 target_attr;
	u32 transfer_len;
	u32 lcns_follow;
	u64 vcn;
	u64 oldest_lsn;
	u64 *page_lcns;
};

/*
 * struct ntfs_redo_attr_state - Cached size state for one target attribute
 *
 * Lets multi-step redo helpers update allocated, logical, and initialized
 * sizes consistently while they replay a record sequence.
 *
 * @allocated_size:       Cached allocated size in bytes.
 * @data_size:            Cached logical size in bytes.
 * @initialized_size:     Cached initialized-data length in bytes.
 */
struct ntfs_redo_attr_state {
	s64 allocated_size;
	s64 data_size;
	s64 initialized_size;
};

/*
 * struct ntfs_redo_env - Shared working set for redo/undo helper routines
 *
 * Owns the decoded log geometry, checkpoint tables rebuilt in memory, and the
 * transaction/open-attribute lists used while walking the log.
 *
 * @ctx:                  Immutable replay context prepared from restart data.
 * @layout:               Decoded $LogFile geometry and replay cursor bounds.
 * @restart:              Checkpoint payload copied out of the restart dump.
 * @oldest_dirty_page_lsn:
 *                        Earliest oldest_lsn among dirty-page slots that are
 *                        still live after checkpoint/bootstrap/prepass.
 * @oldest_transaction_lsn:
 *                        Earliest LSN among active transactions reconstructed
 *                        from the checkpoint table.
 * @dirty_pages_loaded:   True once the checkpoint dirty-page dump has been
 *                        loaded into @dirty_pages for prepass updates.
 * @undo_needed:          True once prepass detects incomplete transactions
 *                        that require the undo walk.
 * @dirty_pages:          In-memory list of checkpoint dirty-page slots.
 * @open_attrs:           In-memory list of reconstructed open-attribute slots.
 * @transactions:         In-memory list of active transactions.
 * @fn_sync:              Caller-owned tree collecting MFT records whose
 *                        $FILE_NAME copies may need a post-recovery refresh.
 */
struct ntfs_redo_env {
	const struct ntfs_log_replay_ctx *ctx;
	struct ntfs_logfile_layout layout;
	struct ntfs_log_checkpoint restart;
	u64 checkpoint_record_lsn;
	u64 oldest_dirty_page_lsn;
	u64 oldest_transaction_lsn;
	bool dirty_pages_loaded;
	bool undo_needed;
	u16 open_attr_entry_size;
	struct list_head dirty_pages;
	struct list_head open_attrs;
	struct list_head transactions;
	struct rb_root *fn_sync;
};

/*
 * struct ntfs_redo_fn_sync - One MFT record whose $FILE_NAME copies are stale
 *
 * @node:     Link in ntfs_redo_env.fn_sync.
 * @mft_no:   MFT record number to refresh after recovery finishes.
 */
struct ntfs_redo_fn_sync {
	struct rb_node node;
	u64 mft_no;
};

typedef int (*ntfs_redo_walk_fn)(struct ntfs_volume *vol,
		struct ntfs_redo_env *env,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh,
		u32 rec_len);

/* Forward declaration because both root-side and nonresident helpers reuse it. */
static int ntfs_redo_locate_attr(struct mft_record *mrec,
		const struct ntfs_redo_open_attr *entry, u16 record_off,
		struct attr_record **attr_out);

/* Return the byte span occupied by the live portion of a restart table dump. */
static inline u32 ntfs_restart_table_bytes(const struct ntfs_log_restart_table *restart_table)
{
	return (u32)le16_to_cpu(restart_table->used) *
		le16_to_cpu(restart_table->size) + sizeof(*restart_table);
}

static void ntfs_log_dump_lfs_record(const char *tag,
		const struct ntfs_lfs_record_hdr *hdr, u32 payload_len)
{
	pr_err("ntfs: %s: lfs this_lsn=%llu prev_lsn=%llu undo_next=%llu "
	       "data_len=%u payload_len=%u client_seq=%u client_idx=%u "
	       "record_type=0x%x transact_id=0x%x flags=0x%x\n",
	       tag,
	       (unsigned long long)le64_to_cpu(hdr->this_lsn),
	       (unsigned long long)le64_to_cpu(hdr->client_prev_lsn),
	       (unsigned long long)le64_to_cpu(hdr->client_undo_next_lsn),
	       le32_to_cpu(hdr->client_data_len), payload_len,
	       le16_to_cpu(hdr->client_seq), le16_to_cpu(hdr->client_idx),
	       le32_to_cpu(hdr->record_type), le32_to_cpu(hdr->transact_id),
	       le16_to_cpu(hdr->flags));
}

static void ntfs_log_dump_redo_record(const char *tag,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh, u32 rec_len)
{
	pr_err("ntfs: %s: lsn=%llu rec_len=%u redo_op=0x%x undo_op=0x%x "
	       "redo_off=%u redo_len=%u undo_off=%u undo_len=%u "
	       "target_attr=0x%x lcns_follow=%u record_off=%u attr_off=%u "
	       "cluster_off=%u target_vcn=%llu transact_id=0x%x\n",
	       tag, (unsigned long long)le64_to_cpu(hdr->this_lsn), rec_len,
	       le16_to_cpu(lrh->redo_op), le16_to_cpu(lrh->undo_op),
	       le16_to_cpu(lrh->redo_off), le16_to_cpu(lrh->redo_len),
	       le16_to_cpu(lrh->undo_off), le16_to_cpu(lrh->undo_len),
	       le16_to_cpu(lrh->target_attr), le16_to_cpu(lrh->lcns_follow),
	       le16_to_cpu(lrh->record_off), le16_to_cpu(lrh->attr_off),
	       le16_to_cpu(lrh->cluster_off),
	       (unsigned long long)le64_to_cpu(lrh->target_vcn),
	       le32_to_cpu(hdr->transact_id));
}

/*
 * Per-record trace variants used inside the discovery and redo/undo walk loops.
 * These fire once per log record, so they go through ntfs_debug() and compile
 * out entirely unless the driver is built with -DDEBUG. Otherwise they would
 * flood the kernel log during replay of a large journal.
 */
static void ntfs_log_debug_lfs_record(const char *tag,
		const struct ntfs_lfs_record_hdr *hdr, u32 payload_len)
{
	ntfs_debug("%s: lfs this_lsn=%llu prev_lsn=%llu undo_next=%llu "
	       "data_len=%u payload_len=%u client_seq=%u client_idx=%u "
	       "record_type=0x%x transact_id=0x%x flags=0x%x",
	       tag,
	       (unsigned long long)le64_to_cpu(hdr->this_lsn),
	       (unsigned long long)le64_to_cpu(hdr->client_prev_lsn),
	       (unsigned long long)le64_to_cpu(hdr->client_undo_next_lsn),
	       le32_to_cpu(hdr->client_data_len), payload_len,
	       le16_to_cpu(hdr->client_seq), le16_to_cpu(hdr->client_idx),
	       le32_to_cpu(hdr->record_type), le32_to_cpu(hdr->transact_id),
	       le16_to_cpu(hdr->flags));
}

static void ntfs_log_debug_redo_record(const char *tag,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh, u32 rec_len)
{
	ntfs_debug("%s: lsn=%llu rec_len=%u redo_op=0x%x undo_op=0x%x "
	       "redo_off=%u redo_len=%u undo_off=%u undo_len=%u "
	       "target_attr=0x%x lcns_follow=%u record_off=%u attr_off=%u "
	       "cluster_off=%u target_vcn=%llu transact_id=0x%x",
	       tag, (unsigned long long)le64_to_cpu(hdr->this_lsn), rec_len,
	       le16_to_cpu(lrh->redo_op), le16_to_cpu(lrh->undo_op),
	       le16_to_cpu(lrh->redo_off), le16_to_cpu(lrh->redo_len),
	       le16_to_cpu(lrh->undo_off), le16_to_cpu(lrh->undo_len),
	       le16_to_cpu(lrh->target_attr), le16_to_cpu(lrh->lcns_follow),
	       le16_to_cpu(lrh->record_off), le16_to_cpu(lrh->attr_off),
	       le16_to_cpu(lrh->cluster_off),
	       (unsigned long long)le64_to_cpu(lrh->target_vcn),
	       le32_to_cpu(hdr->transact_id));
}

static bool ntfs_redo_skip_action(u16 op);

static bool ntfs_log_action_supported(u16 op)
{
	if (ntfs_redo_skip_action(op))
		return true;

	switch (op) {
	case InitializeFileRecordSegment:
	case DeallocateFileRecordSegment:
	case WriteEndOfFileRecordSegment:
	case CreateAttribute:
	case DeleteAttribute:
	case UpdateResidentValue:
	case UpdateNonresidentValue:
	case UpdateMappingPairs:
	case SetNewAttributeSizes:
	case AddIndexEntryRoot:
	case DeleteIndexEntryRoot:
	case AddIndexEntryAllocation:
	case DeleteIndexEntryAllocation:
	case WriteEndOfIndexBuffer:
	case SetIndexEntryVcnRoot:
	case SetIndexEntryVcnAllocation:
	case UpdateFileNameRoot:
	case UpdateFileNameAllocation:
	case SetBitsInNonresidentBitMap:
	case ClearBitsInNonresidentBitMap:
	case UpdateRecordDataRoot:
	case UpdateRecordDataAllocation:
	case ZeroEndOfFileRecord:
		return true;
	default:
		return false;
	}
}

/* Iterate only allocated restart-table entries, skipping free-list bookkeeping. */
static void *ntfs_next_restart_table_entry(const struct ntfs_log_restart_table *restart_table,
		const void *cur)
{
	__le32 *entry;
	u16 rec_size;
	u32 bytes;

	if (!restart_table)
		return NULL;

	rec_size = le16_to_cpu(restart_table->size);
	if (!rec_size)
		return NULL;

	if (!cur) {
		if (!le16_to_cpu(restart_table->total))
			return NULL;
		entry = (__le32 *)((u8 *)restart_table + sizeof(*restart_table));
	} else {
		entry = (__le32 *)((u8 *)cur + rec_size);
	}

	bytes = ntfs_restart_table_bytes(restart_table);
	for (; (u8 *)entry < (u8 *)restart_table + bytes;
	     entry = (__le32 *)((u8 *)entry + rec_size)) {
		if (*entry == RESTART_ENTRY_ALLOCATED_LE)
			return entry;
	}

	return NULL;
}

static int ntfs_redo_discover_current_lsn(struct ntfs_volume *vol,
		struct ntfs_logfile_layout *layout, u64 start_lsn)
{
	struct ntfs_lfs_record_hdr hdr;
	void *payload = NULL;
	u64 saved_current;
	u64 committed_lsn;
	u64 last_lsn = 0;
	u64 previous_lsn = 0;
	u64 next_lsn;
	u64 lsn;
	u64 max_records;
	u64 records = 0;
	u32 payload_len;
	bool marker_protocol = false;
	int err;

	if (!start_lsn)
		return 0;

	saved_current = layout->current_lsn;
	committed_lsn = saved_current;
	layout->current_lsn = U64_MAX;
	max_records = ntfs_log_total_avail(layout) / 8;
	ntfs_debug("ntfs: %s: start_lsn=%llu saved_current=%llu oldest=%llu max_records=%llu\n",
	       __func__, (unsigned long long)start_lsn,
	       (unsigned long long)saved_current,
	       (unsigned long long)layout->oldest_lsn,
	       (unsigned long long)max_records);
	for (lsn = start_lsn; lsn && records++ < max_records; lsn = next_lsn) {
		err = ntfs_log_read_client_record(vol->logfile_ino, layout, lsn,
				&hdr, &payload, &payload_len);
		if (err) {
			ntfs_debug("ntfs: %s: stop/error lsn=%llu last_lsn=%llu saved_current=%llu records=%llu err=%d\n",
			       __func__, (unsigned long long)lsn,
			       (unsigned long long)last_lsn,
			       (unsigned long long)saved_current,
			       (unsigned long long)records, err);
			if (!last_lsn || lsn <= saved_current ||
			    (err != -EINVAL && err != -EOPNOTSUPP))
				goto out_restore;
			break;
		}
		ntfs_log_debug_lfs_record("discover-current-lsn", &hdr, payload_len);
		if (hdr.record_type == LFS_CLIENT_RECORD &&
		    payload_len >= sizeof(struct ntfs_log_rec_hdr)) {
			const struct ntfs_log_rec_hdr *lrh = payload;
			const struct ntfs_log_batch_commit *candidate;
			const struct ntfs_log_batch_commit *commit;

			candidate = ntfs_log_batch_commit_candidate(lrh,
					payload_len);
			commit = ntfs_log_batch_commit_payload(lrh, payload_len);
			if (candidate && (!commit || !previous_lsn ||
			    le64_to_cpu(commit->last_lsn) != previous_lsn ||
			    le64_to_cpu(commit->first_lsn) > previous_lsn)) {
				/* An incomplete or misplaced marker terminates the tail. */
				marker_protocol = true;
				kfree(payload);
				payload = NULL;
				break;
			}
			if (commit) {
				marker_protocol = true;
				/*
				 * This marker was deliberately written without FUA and is
				 * committed only by a restart page covering its LSN.  An
				 * older restart must treat an early/reordered marker write as
				 * an incomplete tail.
				 */
				if ((le16_to_cpu(commit->flags) &
				     NTFS_LOG_BATCH_COMMIT_RESTART_REQUIRED) &&
				    lsn > saved_current) {
					kfree(payload);
					payload = NULL;
					break;
				}
				if (lsn > committed_lsn)
					committed_lsn = lsn;
			}
		}

		last_lsn = lsn;
		previous_lsn = lsn;
		err = ntfs_log_next_lsn(vol->logfile_ino, layout, lsn,
				&hdr, &next_lsn);
		kfree(payload);
		payload = NULL;
		if (err)
			goto out_restore;
	}

	if (records > max_records) {
		err = -EINVAL;
		pr_err("ntfs: %s: record walk exceeded max records=%llu max_records=%llu\n",
		       __func__, (unsigned long long)records,
		       (unsigned long long)max_records);
		goto out_restore;
	}
	/*
	 * Legacy logs have no marker and retain the old complete-record scan.
	 * Once a marker is observed, an otherwise valid but unfenced tail is an
	 * incomplete batch and must not become visible to redo/undo.
	 */
	layout->current_lsn = marker_protocol ? committed_lsn :
		max(saved_current, last_lsn);
	ntfs_debug("ntfs: %s: discovered current_lsn=%llu last_lsn=%llu saved_current=%llu batch_markers=%d\n",
	       __func__, (unsigned long long)layout->current_lsn,
	       (unsigned long long)last_lsn,
	       (unsigned long long)saved_current, marker_protocol);
	return 0;

out_restore:
	kfree(payload);
	layout->current_lsn = saved_current;
	return err;
}

/* Release one reconstructed open-attribute entry. */
static void ntfs_redo_free_open_attr(struct ntfs_redo_open_attr *entry)
{
	kfree(entry->name);
	kfree(entry);
}

/* Drop all reconstructed open-attribute entries at the end of a replay pass. */
static void ntfs_redo_clear_open_attrs(struct ntfs_redo_env *env)
{
	struct ntfs_redo_open_attr *entry;
	struct ntfs_redo_open_attr *next;

	list_for_each_entry_safe(entry, next, &env->open_attrs, list) {
		list_del(&entry->list);
		ntfs_redo_free_open_attr(entry);
	}
}

static void ntfs_redo_free_dirty_page(struct ntfs_redo_dirty_page *entry)
{
	kfree(entry->page_lcns);
	kfree(entry);
}

static bool ntfs_redo_dirty_page_is_live(const struct ntfs_redo_dirty_page *entry)
{
	u32 index;

	for (index = 0; index < entry->lcns_follow; index++) {
		if (entry->page_lcns[index])
			return true;
	}

	return false;
}

static void ntfs_redo_recalc_dirty_pages(struct ntfs_redo_env *env)
{
	struct ntfs_redo_dirty_page *entry;

	env->oldest_dirty_page_lsn = 0;
	list_for_each_entry(entry, &env->dirty_pages, list) {
		if (!ntfs_redo_dirty_page_is_live(entry))
			continue;
		if (!env->oldest_dirty_page_lsn ||
		    entry->oldest_lsn < env->oldest_dirty_page_lsn)
			env->oldest_dirty_page_lsn = entry->oldest_lsn;
	}
}

static void ntfs_redo_clear_dirty_pages(struct ntfs_redo_env *env)
{
	struct ntfs_redo_dirty_page *entry;
	struct ntfs_redo_dirty_page *next;

	list_for_each_entry_safe(entry, next, &env->dirty_pages, list) {
		list_del(&entry->list);
		ntfs_redo_free_dirty_page(entry);
	}
	env->oldest_dirty_page_lsn = 0;
	env->dirty_pages_loaded = false;
}

/* Drop all reconstructed transaction-table entries at the end of a replay pass. */
static void ntfs_redo_clear_transactions(struct ntfs_redo_env *env)
{
	struct ntfs_redo_transaction *entry;
	struct ntfs_redo_transaction *next;

	list_for_each_entry_safe(entry, next, &env->transactions, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	env->oldest_transaction_lsn = 0;
	env->undo_needed = false;
}

static void ntfs_redo_recalc_transactions(struct ntfs_redo_env *env)
{
	struct ntfs_redo_transaction *entry;

	env->oldest_transaction_lsn = 0;
	env->undo_needed = false;
	list_for_each_entry(entry, &env->transactions, list) {
		if (entry->first_lsn && (!env->oldest_transaction_lsn ||
		    entry->first_lsn < env->oldest_transaction_lsn))
			env->oldest_transaction_lsn = entry->first_lsn;
		if (entry->state == TransactionActive && entry->undo_next_lsn)
			env->undo_needed = true;
	}
}

static struct ntfs_redo_transaction *ntfs_redo_find_transaction(
		const struct ntfs_redo_env *env, u32 slot)
{
	struct ntfs_redo_transaction *entry;

	list_for_each_entry(entry, &env->transactions, list) {
		if (entry->slot == slot)
			return entry;
	}

	return NULL;
}

static struct ntfs_redo_transaction *ntfs_redo_get_transaction(
		struct ntfs_redo_env *env, u32 slot, u64 first_lsn)
{
	struct ntfs_redo_transaction *entry;

	entry = ntfs_redo_find_transaction(env, slot);
	if (entry)
		return entry;

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return NULL;

	entry->slot = slot;
	entry->state = TransactionActive;
	entry->first_lsn = first_lsn;
	entry->undo_next_lsn = first_lsn;
	INIT_LIST_HEAD(&entry->list);
	list_add_tail(&entry->list, &env->transactions);
	return entry;
}

/* Materialize one transaction-table slot into an in-memory replay record. */
static int ntfs_redo_add_transaction(struct ntfs_redo_env *env, u32 slot,
		const struct ntfs_transaction_entry *disk)
{
	struct ntfs_redo_transaction *entry;

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return -ENOMEM;

	entry->slot = slot;
	entry->state = disk->transact_state;
	entry->first_lsn = le64_to_cpu(disk->first_lsn);
	entry->undo_next_lsn = le64_to_cpu(disk->undo_next_lsn);
	INIT_LIST_HEAD(&entry->list);
	list_add_tail(&entry->list, &env->transactions);
	ntfs_redo_recalc_transactions(env);

	return 0;
}

/* Skip actions handled during prepass or intentionally ignored by replay. */
static bool ntfs_redo_skip_action(u16 op)
{
	switch (op) {
	case Noop:
	case CompensationLogRecord:
	case DeleteDirtyClusters:
	case HotFix:
	case EndTopLevelAction:
	case PrepareTransaction:
	case CommitTransaction:
	case ForgetTransaction:
	case OpenNonresidentAttribute:
	case OpenAttributeTableDump:
	case AttributeNamesDump:
	case DirtyPageTableDump:
	case TransactionTableDump:
		return true;
	case UpdateRelativeDataIndex:
	case UpdateRelativeDataAllocation:
		return true;
	default:
		return false;
	}
}

/* Find the reconstructed open-attribute entry referenced by target_attr. */
static struct ntfs_redo_open_attr *ntfs_redo_find_open_attr(
		const struct ntfs_redo_env *env, u16 offset)
{
	struct ntfs_redo_open_attr *entry;

	list_for_each_entry(entry, &env->open_attrs, list) {
		if (entry->offset == offset)
			return entry;
	}

	return NULL;
}

/* Return an existing open-attribute entry or allocate a new one on demand. */
static struct ntfs_redo_open_attr *ntfs_redo_get_open_attr(
		struct ntfs_redo_env *env, u16 offset)
{
	struct ntfs_redo_open_attr *entry;

	entry = ntfs_redo_find_open_attr(env, offset);
	if (entry)
		return entry;

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return NULL;

	entry->offset = offset;
	entry->env = env;
	INIT_LIST_HEAD(&entry->list);
	list_add_tail(&entry->list, &env->open_attrs);
	return entry;
}

/* Replace the cached attribute name for an open-attribute entry. */
static int ntfs_redo_set_open_attr_name(struct ntfs_redo_open_attr *entry,
		const __le16 *name, u16 name_bytes)
{
	__le16 *new_name;

	if (name_bytes & 1) {
		return -EINVAL;
	}

	if (!name_bytes) {
		kfree(entry->name);
		entry->name = NULL;
		entry->name_len = 0;
		return 0;
	}

	new_name = kmemdup(name, name_bytes, GFP_NOFS);
	if (!new_name) {
		return -ENOMEM;
	}

	kfree(entry->name);
	entry->name = new_name;
	entry->name_len = name_bytes / sizeof(*name);
	return 0;
}

/* Copy one on-disk OPEN_ATTR table slot into the replay environment. */
static int ntfs_redo_apply_open_attr_entry(struct ntfs_redo_env *env, u16 offset,
		const void *disk_entry)
{
	const struct ntfs_open_attr_entry_disk *disk = disk_entry;
	const struct ntfs_open_attr_entry_disk32 *disk32 = disk_entry;
	struct ntfs_redo_open_attr *entry;

	entry = ntfs_redo_get_open_attr(env, offset);
	if (!entry)
		return -ENOMEM;

	if (env->open_attr_entry_size == sizeof(*disk32)) {
		entry->type = disk32->type;
		entry->mref = disk32->mref;
		entry->bytes_per_index = le32_to_cpu(disk32->bytes_per_index);
		entry->is_dirty_pages = disk32->is_dirty_pages;
		entry->expects_name = disk32->is_attr_name;
		entry->expected_name_len = disk32->name_len;
	} else {
		entry->type = disk->type;
		entry->mref = disk->mref;
		entry->bytes_per_index = le32_to_cpu(disk->bytes_per_index);
		entry->is_dirty_pages = disk->is_dirty_pages;
		entry->expects_name = disk->is_attr_name;
		entry->expected_name_len = disk->name_len;
	}

	kfree(entry->name);
	entry->name = NULL;
	entry->name_len = 0;
	return 0;
}

/* Rebuild the in-memory open-attribute table from the checkpoint dump. */
static int ntfs_redo_apply_open_attr_dump(struct ntfs_redo_env *env,
		const void *buf, u32 bytes)
{
	const struct ntfs_log_restart_table *restart_table = buf;
	const void *cur = NULL;

	if (bytes < sizeof(*restart_table) ||
	    !ntfs_log_validate_restart_table(restart_table, bytes) ||
	    ntfs_restart_table_bytes(restart_table) != bytes ||
	    le16_to_cpu(restart_table->size) < env->open_attr_entry_size)
		return -EINVAL;

	/* The checkpoint dump is authoritative, so start from a clean in-memory table. */
	ntfs_redo_clear_open_attrs(env);

	while ((cur = ntfs_next_restart_table_entry(restart_table, cur))) {
		u16 offset = (const u8 *)cur - (const u8 *)restart_table;
		const struct ntfs_open_attr_entry_disk *disk = cur;
		int err;

		err = ntfs_redo_apply_open_attr_entry(env, offset, disk);
		if (err)
			return err;
	}

	return 0;
}

/* Apply the separate attribute-name dump to the already reconstructed entries. */
static int ntfs_redo_apply_attr_names_dump(struct ntfs_redo_env *env,
		const void *buf, u32 bytes)
{
	struct ntfs_redo_open_attr *entry;
	u32 off = 0;

	while (off < bytes) {
		const struct ntfs_attr_name_entry *ane = (const void *)((const u8 *)buf + off);
		u16 offset;
		u16 name_bytes;
		int err;

		if (bytes - off < sizeof(*ane))
			return -EINVAL;
		offset = le16_to_cpu(ane->off);
		if (!offset)
			return -EINVAL;

		name_bytes = le16_to_cpu(ane->name_bytes);
		off += sizeof(*ane);
		if (!name_bytes || (name_bytes & 1) ||
		    name_bytes > bytes - off ||
		    bytes - off - name_bytes < sizeof(__le16) ||
		    memchr_inv((const u8 *)buf + off + name_bytes, 0,
			    sizeof(__le16)))
			return -EINVAL;

		entry = ntfs_redo_find_open_attr(env, offset);
		if (!entry)
			return -EUCLEAN;
		if (!entry->expects_name ||
		    entry->expected_name_len != name_bytes / sizeof(__le16) ||
		    entry->name)
			return -EINVAL;

		err = ntfs_redo_set_open_attr_name(entry, ane->name, name_bytes);
		if (err)
			return err;

		/*
		 * Each name is followed by a trailing UTF-16 NUL terminator.
		 * Skip it too, otherwise it is misread as the next entry's
		 * zero @off and every name after the first is silently dropped.
		 */
		off += name_bytes;
		off += sizeof(__le16);
	}

	list_for_each_entry(entry, &env->open_attrs, list) {
		if (entry->expects_name &&
		    entry->name_len != entry->expected_name_len)
			return -EINVAL;
	}

	return 0;
}

static struct ntfs_redo_dirty_page *ntfs_redo_find_dirty_page(
		const struct ntfs_redo_env *env, u32 target_attr, u64 target_vcn,
		u32 lcns_follow)
{
	struct ntfs_redo_dirty_page *entry;

	list_for_each_entry(entry, &env->dirty_pages, list) {
		if (entry->target_attr != target_attr)
			continue;
		if (target_vcn < entry->vcn)
			continue;
		if (target_vcn - entry->vcn >= entry->lcns_follow)
			continue;
		if (lcns_follow > entry->lcns_follow -
		    (target_vcn - entry->vcn))
			continue;
		return entry;
	}

	return NULL;
}

static int ntfs_redo_track_dirty_page(struct ntfs_volume *vol,
		struct ntfs_redo_env *env,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh)
{
	struct ntfs_redo_dirty_page *entry;
	const struct ntfs_redo_open_attr *attr;
	u32 target_attr = le16_to_cpu(lrh->target_attr);
	u32 lcns_follow = le16_to_cpu(lrh->lcns_follow);
	u64 target_vcn = le64_to_cpu(lrh->target_vcn);
	u64 lsn = le64_to_cpu(hdr->this_lsn);
	u64 index;
	u32 i;

	if (!lcns_follow)
		return 0;

	entry = ntfs_redo_find_dirty_page(env, target_attr, target_vcn,
			lcns_follow);
	if (!entry) {
		entry = kzalloc_obj(struct ntfs_redo_dirty_page, GFP_NOFS);
		if (!entry)
			return -ENOMEM;

		entry->page_lcns = kcalloc(lcns_follow,
				sizeof(*entry->page_lcns), GFP_NOFS);
		if (!entry->page_lcns) {
			kfree(entry);
			return -ENOMEM;
		}

		entry->target_attr = target_attr;
		entry->transfer_len = lcns_follow << vol->cluster_size_bits;
		entry->lcns_follow = lcns_follow;
		entry->vcn = target_vcn;
		entry->oldest_lsn = lsn;
		INIT_LIST_HEAD(&entry->list);
		list_add_tail(&entry->list, &env->dirty_pages);
	}

	/* Retain initialization and the incremental changes that depend on it. */
	attr = ntfs_redo_find_open_attr(env, target_attr);
	if (le16_to_cpu(lrh->redo_op) == InitializeFileRecordSegment ||
	    (le16_to_cpu(lrh->redo_op) == UpdateNonresidentValue &&
	     le16_to_cpu(lrh->undo_op) == Noop && attr &&
	     attr->type == AT_INDEX_ALLOCATION && attr->bytes_per_index &&
	     le16_to_cpu(lrh->redo_len) == attr->bytes_per_index))
		entry->oldest_lsn = min(entry->oldest_lsn, lsn);

	index = target_vcn - entry->vcn;
	if (index > entry->lcns_follow ||
	    lcns_follow > entry->lcns_follow - index)
		return -EINVAL;

	for (i = 0; i < lcns_follow; i++)
		entry->page_lcns[index + i] = le64_to_cpu(lrh->page_lcns[i]);

	env->dirty_pages_loaded = true;
	ntfs_redo_recalc_dirty_pages(env);
	return 0;
}

static int ntfs_redo_apply_dirty_page_dump(struct ntfs_redo_env *env,
		const void *buf, u32 bytes)
{
	const struct ntfs_log_restart_table *restart_table = buf;
	const void *cur = NULL;
	u16 rec_size;

	if (bytes < sizeof(*restart_table) ||
	    !ntfs_log_validate_restart_table(restart_table, bytes) ||
	    ntfs_restart_table_bytes(restart_table) != bytes)
		return -EINVAL;

	rec_size = le16_to_cpu(restart_table->size);
	if (rec_size < (env->open_attr_entry_size ==
		    sizeof(struct ntfs_open_attr_entry_disk32) ?
		    sizeof(struct ntfs_dirty_page_entry32) :
		    sizeof(struct ntfs_dirty_page_entry)))
		return -EINVAL;

	ntfs_redo_clear_dirty_pages(env);
	INIT_LIST_HEAD(&env->dirty_pages);

	while ((cur = ntfs_next_restart_table_entry(restart_table, cur))) {
		const struct ntfs_dirty_page_entry *disk = cur;
		const struct ntfs_dirty_page_entry32 *disk32 = cur;
		const __le64 *lcns = (const void *)((const u8 *)disk + sizeof(*disk));
		struct ntfs_redo_dirty_page *entry;
		u32 lcns_follow = le32_to_cpu(disk->lcns_follow);
		u32 avail_lcns;
		u32 index;

		if (env->open_attr_entry_size ==
		    sizeof(struct ntfs_open_attr_entry_disk32)) {
			lcns_follow = le32_to_cpu(disk32->lcns_follow);
			avail_lcns = (rec_size - sizeof(*disk32)) / sizeof(*lcns);
		} else {
			avail_lcns = (rec_size - sizeof(*disk)) / sizeof(*lcns);
		}
		if (lcns_follow > avail_lcns)
			return -EINVAL;

		entry = kzalloc(sizeof(*entry), GFP_NOFS);
		if (!entry)
			return -ENOMEM;

		entry->target_attr = le32_to_cpu(disk->target_attr);
		entry->transfer_len = le32_to_cpu(disk->transfer_len);
		entry->lcns_follow = lcns_follow;
		if (env->open_attr_entry_size ==
		    sizeof(struct ntfs_open_attr_entry_disk32)) {
			const __le32 *lcns32 = disk32->page_lcns;

			entry->vcn = le32_to_cpu(disk32->vcn_low) |
				((u64)le32_to_cpu(disk32->vcn_high) << 32);
			entry->oldest_lsn = le32_to_cpu(disk32->oldest_lsn_low) |
				((u64)le32_to_cpu(disk32->oldest_lsn_high) << 32);
			lcns = (const __le64 *)lcns32;
		} else {
			entry->vcn = le64_to_cpu(disk->vcn);
			entry->oldest_lsn = le64_to_cpu(disk->oldest_lsn);
		}
		if (lcns_follow) {
			entry->page_lcns = kcalloc(lcns_follow,
					sizeof(*entry->page_lcns), GFP_NOFS);
			if (!entry->page_lcns) {
				ntfs_redo_free_dirty_page(entry);
				return -ENOMEM;
			}
			for (index = 0; index < lcns_follow; index++) {
				if (env->open_attr_entry_size ==
				    sizeof(struct ntfs_open_attr_entry_disk32)) {
					const __le32 *lcns32 = (const __le32 *)lcns;

					entry->page_lcns[index] =
						le32_to_cpu(lcns32[index * 2]) |
						((u64)le32_to_cpu(lcns32[index * 2 + 1]) << 32);
				} else {
					entry->page_lcns[index] = le64_to_cpu(lcns[index]);
				}
			}
		}

		INIT_LIST_HEAD(&entry->list);
		list_add_tail(&entry->list, &env->dirty_pages);
	}

	env->dirty_pages_loaded = true;
	ntfs_redo_recalc_dirty_pages(env);
	return 0;
}

static int ntfs_redo_load_dirty_page_table(struct ntfs_volume *vol,
		struct ntfs_redo_env *env)
{
	struct ntfs_lfs_record_hdr hdr;
	const void *dump;
	void *payload = NULL;
	u32 dump_len;
	u32 payload_len = 0;
	int err;

	if (!le32_to_cpu(env->restart.dirty_pages_len) ||
	    !le64_to_cpu(env->restart.dirty_pages_table_lsn))
		return 0;
	ntfs_debug("ntfs: %s: read dirty-page table lsn=%llu len=%u\n",
	       __func__,
	       (unsigned long long)le64_to_cpu(env->restart.dirty_pages_table_lsn),
	       le32_to_cpu(env->restart.dirty_pages_len));

	err = ntfs_log_read_client_record(vol->logfile_ino, &env->layout,
			le64_to_cpu(env->restart.dirty_pages_table_lsn),
			&hdr, &payload, &payload_len);
	if (err) {
		return err;
	}

	err = ntfs_log_checkpoint_dump_data(&hdr, payload, payload_len,
			DirtyPageTableDump,
			le32_to_cpu(env->restart.dirty_pages_len),
			&dump, &dump_len);
	if (err) {
		ntfs_log_dump_lfs_record("dirty-page invalid log record lfs", &hdr,
				payload_len);
		goto out;
	}

	err = ntfs_redo_apply_dirty_page_dump(env, dump, dump_len);
out:
	kfree(payload);
	return err;
}

/*
 * OpenNonresidentAttribute records can extend or override checkpoint state, so
 * the prepass consumes them before any redo/undo handler needs stream metadata.
 */
static int ntfs_redo_open_nonresident_attr(struct ntfs_redo_env *env,
		const struct ntfs_log_rec_hdr *lrh, u32 rec_len)
{
	const struct ntfs_open_attr_entry_disk *disk;
	struct ntfs_redo_open_attr *entry;
	u16 offset = le16_to_cpu(lrh->target_attr);
	u16 redo_off = le16_to_cpu(lrh->redo_off);
	u16 undo_off = le16_to_cpu(lrh->undo_off);
	u16 undo_len = le16_to_cpu(lrh->undo_len);
	int err;

	if (redo_off > rec_len || rec_len - redo_off < sizeof(*disk)) {
		return -EINVAL;
	}

	disk = (const void *)((const u8 *)lrh + redo_off);
	err = ntfs_redo_apply_open_attr_entry(env, offset, disk);
	if (err)
		return err;

	entry = ntfs_redo_find_open_attr(env, offset);
	if (!entry) {
		return -EINVAL;
	}

	if (!undo_len)
		return 0;

	if (undo_off > rec_len || undo_len > rec_len - undo_off) {
		return -EINVAL;
	}

	return ntfs_redo_set_open_attr_name(entry,
			(const __le16 *)((const u8 *)lrh + undo_off), undo_len);
}

static int ntfs_redo_track_transaction(struct ntfs_redo_env *env,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh)
{
	const struct ntfs_log_batch_commit *batch;
	struct ntfs_redo_transaction *entry;
	struct ntfs_redo_transaction *next;
	u32 slot = le32_to_cpu(hdr->transact_id);
	u64 lsn = le64_to_cpu(hdr->this_lsn);
	u16 op = le16_to_cpu(lrh->redo_op);

	/* A v2 batch bitmap replaces both Commit and Forget records. */
	batch = ntfs_log_batch_commit_payload(lrh,
			le32_to_cpu(hdr->client_data_len));
	if (batch) {
		list_for_each_entry_safe(entry, next, &env->transactions, list) {
			int index = ntfs_log_transaction_slot_index(entry->slot);

			if (le16_to_cpu(batch->version) ==
			    NTFS_LOG_BATCH_COMMIT_VERSION) {
				if (index < 0 ||
				    !ntfs_log_batch_commits_transaction(batch, index))
					continue;
			} else if (entry->state != TransactionCommitted) {
				continue;
			}
			list_del(&entry->list);
			kfree(entry);
		}
		ntfs_redo_recalc_transactions(env);
		return 0;
	}

	entry = ntfs_redo_get_transaction(env, slot, lsn);
	if (!entry)
		return -ENOMEM;

	entry->undo_next_lsn = lsn;
	if (le16_to_cpu(lrh->undo_op) == CompensationLogRecord)
		entry->undo_next_lsn = le64_to_cpu(hdr->client_undo_next_lsn);

	switch (op) {
	case EndTopLevelAction:
		entry->undo_next_lsn = le64_to_cpu(hdr->client_undo_next_lsn);
		break;
	case PrepareTransaction:
		entry->state = TransactionPrepared;
		break;
	case CommitTransaction:
		entry->state = TransactionCommitted;
		break;
	case ForgetTransaction:
		list_del(&entry->list);
		kfree(entry);
		break;
	default:
		break;
	}

	ntfs_redo_recalc_transactions(env);
	return 0;
}

static int ntfs_redo_apply_delete_dirty_clusters(struct ntfs_redo_env *env,
		const struct ntfs_log_rec_hdr *lrh, u32 rec_len)
{
	const struct ntfs_lcn_range *ranges;
	struct ntfs_redo_dirty_page *entry;
	u16 redo_off = le16_to_cpu(lrh->redo_off);
	u16 redo_len = le16_to_cpu(lrh->redo_len);
	u32 range_count;
	u32 range_index;

	if (!env->dirty_pages_loaded)
		return 0;
	if (redo_off > rec_len || redo_len > rec_len - redo_off)
		return -EINVAL;
	if (redo_len % sizeof(*ranges))
		return -EINVAL;

	ranges = (const void *)((const u8 *)lrh + redo_off);
	range_count = redo_len / sizeof(*ranges);
	for (range_index = 0; range_index < range_count; range_index++) {
		u64 lcn = le64_to_cpu(ranges[range_index].lcn);
		u64 len = le64_to_cpu(ranges[range_index].len);
		u64 last_lcn;

		if (!len)
			continue;
		last_lcn = lcn + len - 1;
		list_for_each_entry(entry, &env->dirty_pages, list) {
			u32 index;

			for (index = 0; index < entry->lcns_follow; index++) {
				u64 page_lcn = entry->page_lcns[index];

				if (page_lcn >= lcn && page_lcn <= last_lcn)
					entry->page_lcns[index] = 0;
			}
		}
	}

	ntfs_redo_recalc_dirty_pages(env);
	return 0;
}

static int ntfs_redo_apply_hotfix(struct ntfs_redo_env *env,
		const struct ntfs_log_rec_hdr *lrh)
{
	struct ntfs_redo_dirty_page *entry;
	u32 target_attr = le16_to_cpu(lrh->target_attr);
	u32 lcns_follow = le16_to_cpu(lrh->lcns_follow);
	u64 target_vcn = le64_to_cpu(lrh->target_vcn);
	u64 index;

	if (!env->dirty_pages_loaded || !lcns_follow)
		return 0;

	entry = ntfs_redo_find_dirty_page(env, target_attr, target_vcn,
			lcns_follow);
	if (!entry)
		return 0;

	index = target_vcn - entry->vcn;
	if (index >= entry->lcns_follow)
		return 0;
	if (entry->page_lcns[index])
		entry->page_lcns[index] = le64_to_cpu(lrh->page_lcns[0]);

	return 0;
}

/* Invalidate cached stream sizes and runlists after metadata replay mutates them. */
static void ntfs_redo_invalidate_inode(struct inode *vi,
		const struct ntfs_redo_attr_state *state)
{
	struct ntfs_inode *ni;
	unsigned long flags;

	if (!vi || IS_ERR(vi))
		return;

	ni = NTFS_I(vi);

	/*
	 * $MFT's data stream backs every inode mapping on the volume.  Its
	 * runlist and sizes are established at mount from the on-disk base
	 * record and reflect the clusters actually allocated to $MFT.  A redo
	 * record may replay a historical, smaller $MFT size that was later
	 * superseded by growth. Writing that smaller size into the live $MFT
	 * inode would push records that physically exist "beyond the end of the
	 * mft" and make them unreadable for the rest of replay.  Likewise,
	 * tearing down the live $MFT runlist would leave every later MFT-record
	 * write unable to map its record number to a disk cluster
	 * ("$MFT runlist is not present").  Keep this larger mapping during
	 * recovery. Finalization restores the sizes after all undo is complete.
	 */
	if (ni->mft_no == FILE_MFT && !NInoAttr(ni)) {
		write_lock_irqsave(&ni->size_lock, flags);
		if (state->allocated_size > ni->allocated_size)
			ni->allocated_size = state->allocated_size;
		if (state->data_size > ni->data_size)
			ni->data_size = state->data_size;
		if (state->initialized_size > ni->initialized_size)
			ni->initialized_size = state->initialized_size;
		write_unlock_irqrestore(&ni->size_lock, flags);
		if (i_size_read(vi) < ni->data_size)
			i_size_write(vi, ni->data_size);
		return;
	}

	if (NInoNonResident(ni)) {
		down_write(&ni->runlist.lock);
		kvfree(ni->runlist.rl);
		ni->runlist.rl = NULL;
		ni->runlist.count = 0;
		ni->runlist.rl_hint = -1;
		up_write(&ni->runlist.lock);
		NInoClearFullyMapped(ni);
	}

	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = state->allocated_size;
	ni->data_size = state->data_size;
	ni->initialized_size = state->initialized_size;
	write_unlock_irqrestore(&ni->size_lock, flags);
	i_size_write(vi, state->data_size);
}

/* Refresh any already-instantiated VFS inode that mirrors the replayed stream. */
static int ntfs_redo_refresh_stream(struct ntfs_volume *vol,
		u64 mft_no, const struct mft_record *mrec,
		const struct attr_record *attr,
		const struct ntfs_redo_attr_state *state)
{
	struct ntfs_attr na = { .type = AT_UNUSED };
	struct inode *base_vi;
	struct inode *stream_vi;
	u16 name_off = le16_to_cpu(attr->name_offset);
	u32 attr_len = le32_to_cpu(attr->length);

	if (attr->name_length && (name_off > attr_len ||
	    attr->name_length * sizeof(__le16) > attr_len - name_off))
		return -EINVAL;
	na.mft_no = mrec->base_mft_record ? MREF_LE(mrec->base_mft_record) :
		mft_no;

	/* The logged open attribute is the $MFT container, not this stream. */
	base_vi = ilookup5(vol->sb, na.mft_no, ntfs_test_inode, &na);
	if (!base_vi)
		return 0;

	if (attr->type == AT_DATA && !attr->name_length)
		ntfs_redo_invalidate_inode(base_vi, state);

	na.type = attr->type;
	na.name_len = attr->name_length;
	na.name = na.name_len ? (__le16 *)((u8 *)attr + name_off) : NULL;
	/* New streams will read their final state after recovery has completed. */
	stream_vi = ilookup5(vol->sb, na.mft_no, ntfs_test_inode, &na);
	if (stream_vi) {
		ntfs_redo_invalidate_inode(stream_vi, state);
		iput(stream_vi);
	}
	iput(base_vi);
	return 0;
}

/* Open the base inode and the exact named stream referenced by an OPEN_ATTR entry. */
static int ntfs_redo_seed_stream_runlist(
		const struct ntfs_redo_open_attr *open_attr,
		struct inode *stream_vi)
{
	struct ntfs_redo_dirty_page *dirty_page;
	struct ntfs_inode *ni = NTFS_I(stream_vi);
	struct runlist_element *merged;
	u64 max_size = 0;
	unsigned long flags;

	if (!open_attr->env || !NInoNonResident(ni))
		return 0;

	/*
	 * $MFT's data runlist is mapped in full at mount and is required to
	 * locate every MFT record for the entire replay.  Never replace it
	 * with the partial dirty-page seed (which also carries LCN_ENOENT
	 * sentinels): a later map_mft_record() would try to extend the partial
	 * runlist from the on-disk mapping pairs and trip "Run lists overlap.
	 * Cannot merge!", and the sentinel would be used as a bogus LCN.
	 */
	if (ni->mft_no == FILE_MFT)
		return 0;

	down_write(&ni->runlist.lock);
	kvfree(ni->runlist.rl);
	ni->runlist.rl = NULL;
	ni->runlist.count = 0;
	ni->runlist.rl_hint = -1;

	list_for_each_entry(dirty_page, &open_attr->env->dirty_pages, list) {
		u32 i;

		if (dirty_page->target_attr != open_attr->offset)
			continue;

		for (i = 0; i < dirty_page->lcns_follow; i++) {
			struct runlist_element *source;
			s64 lcn;
			s64 vcn;
			u64 size;

			if (!dirty_page->page_lcns[i])
				continue;
			vcn = dirty_page->vcn + i;
			/* A larger bitmap update can overlap an earlier dirty range. */
			lcn = ntfs_rl_vcn_to_lcn(ni->runlist.rl, vcn);
			if (lcn >= 0 && (u64)lcn == dirty_page->page_lcns[i])
				continue;
			source = kmalloc_array(2, sizeof(*source), GFP_NOFS);
			if (!source) {
				up_write(&ni->runlist.lock);
				return -ENOMEM;
			}
			source[0].vcn = vcn;
			source[0].lcn = dirty_page->page_lcns[i];
			source[0].length = 1;
			source[1].vcn = vcn + 1;
			source[1].lcn = LCN_ENOENT;
			source[1].length = 0;

			merged = ntfs_runlists_merge(&ni->runlist, source, 2,
					&ni->runlist.count);
			if (IS_ERR(merged)) {
				kfree(source);
				up_write(&ni->runlist.lock);
				return PTR_ERR(merged);
			}
			ni->runlist.rl = merged;
			size = (u64)(vcn + 1) << ni->vol->cluster_size_bits;
			if (size > max_size)
				max_size = size;
		}
	}
	ni->runlist.rl_hint = -1;
	up_write(&ni->runlist.lock);
	NInoClearFullyMapped(ni);

	if (max_size) {
		write_lock_irqsave(&ni->size_lock, flags);
		if (ni->allocated_size < max_size)
			ni->allocated_size = max_size;
		if (ni->data_size < max_size)
			ni->data_size = max_size;
		if (ni->initialized_size < max_size)
			ni->initialized_size = max_size;
		write_unlock_irqrestore(&ni->size_lock, flags);
		if (i_size_read(stream_vi) < max_size)
			i_size_write(stream_vi, max_size);
	}

	return 0;
}

static int ntfs_redo_open_stream(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		struct inode **base_vi, struct inode **stream_vi)
{
	struct inode *base;
	struct inode *stream;

	if (!entry || !base_vi || !stream_vi) {
		return -EINVAL;
	}

	base = ntfs_iget(vol->sb, MREF_LE(entry->mref));
	if (IS_ERR(base)) {
		return PTR_ERR(base);
	}

	if (entry->type == AT_INDEX_ALLOCATION)
		stream = ntfs_index_iget(base, entry->name, entry->name_len);
	else
		stream = ntfs_attr_iget(base, entry->type,
				entry->name, entry->name_len);

	if (IS_ERR(stream)) {
		int err = PTR_ERR(stream);

		iput(base);
		return err;
	}

	if (entry->env->dirty_pages_loaded) {
		int err = ntfs_redo_seed_stream_runlist(entry, stream);

		if (err) {
			iput(stream);
			iput(base);
			return err;
		}
	}

	*base_vi = base;
	*stream_vi = stream;
	return 0;
}

/* Translate the log record's VCN + cluster offset pair into a byte address. */
static inline u64 ntfs_redo_stream_base_pos(const struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh)
{
	return (le64_to_cpu(lrh->target_vcn) << vol->cluster_size_bits) +
		((u64)le16_to_cpu(lrh->cluster_off) << NTFS_BLOCK_SIZE_BITS);
}

/* Report how many bytes of real stream data the current log record covers. */
static inline u64 ntfs_redo_stream_covered_bytes(const struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh)
{
	u64 covered = (u64)le16_to_cpu(lrh->lcns_follow) << vol->cluster_size_bits;
	u64 cluster_off = (u64)le16_to_cpu(lrh->cluster_off) << NTFS_BLOCK_SIZE_BITS;

	if (cluster_off > covered)
		return 0;

	return covered - cluster_off;
}

/*
 * Replay index-allocation records through the LCN array stored in the log
 * record.  Do not use the normal inode read/write helpers here: during replay
 * the cached runlist may be seeded from dirty-page table entries while the MFT
 * mapping-pairs attribute is being replayed, and merging those two views can
 * report false runlist overlaps.
 */
static int ntfs_redo_rw_lcns(struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh, u64 offset, u8 *buffer,
		u32 bytes, bool write)
{
	u64 cluster_off = (u64)le16_to_cpu(lrh->cluster_off) << NTFS_BLOCK_SIZE_BITS;
	u64 pos = cluster_off + offset;
	u32 done = 0;

	if (!bytes || offset > ntfs_redo_stream_covered_bytes(vol, lrh) ||
	    bytes > ntfs_redo_stream_covered_bytes(vol, lrh) - offset) {
		return -EINVAL;
	}

	while (done < bytes) {
		u64 lcn_index = pos >> vol->cluster_size_bits;
		u32 lcn_off = pos & vol->cluster_size_mask;
		u32 len = min_t(u32, bytes - done, vol->cluster_size - lcn_off);
		s64 lcn;
		loff_t dev_pos;
		int err;

		if (lcn_index >= le16_to_cpu(lrh->lcns_follow)) {
			return -EINVAL;
		}

		lcn = le64_to_cpu(lrh->page_lcns[lcn_index]);
		if (lcn < 0) {
			return -EINVAL;
		}

		dev_pos = NTFS_CLU_TO_B(vol, lcn) + lcn_off;
		if (write) {
			err = ntfs_bdev_write(vol->sb, buffer + done, dev_pos, len);
		} else {
			err = ntfs_bdev_read_cached(vol->sb, buffer + done, dev_pos, len);
		}
		if (err)
			return err;

		done += len;
		pos += len;
	}

	return 0;
}

/* Size the temporary I/O buffer large enough to include the target INDX block. */
static inline u32 ntfs_redo_index_io_bytes(const struct ntfs_redo_open_attr *entry,
		u16 record_off)
{
	return ALIGN(record_off + entry->bytes_per_index, NTFS_BLOCK_SIZE);
}

/*
 * Read an INDEX_ALLOCATION buffer, validate its bounds, and undo MST fixups so
 * mutation helpers can treat it like an in-memory INDX record.
 */
static int ntfs_redo_load_index_block(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn,
		struct inode **base_vi, struct inode **stream_vi,
		u8 **buffer, u32 *bytes)
{
	u64 covered_bytes;
	u32 io_bytes;
	u16 record_off;
	int err;

	if (!entry || entry->type != AT_INDEX_ALLOCATION || !entry->bytes_per_index ||
	    !base_vi || !stream_vi || !buffer || !bytes)
		return -EINVAL;

	record_off = le16_to_cpu(lrh->record_off);
	covered_bytes = ntfs_redo_stream_covered_bytes(vol, lrh);
	io_bytes = ntfs_redo_index_io_bytes(entry, record_off);
	if (!covered_bytes || io_bytes > covered_bytes)
		return -EINVAL;

	err = ntfs_redo_open_stream(vol, entry, base_vi, stream_vi);
	if (err)
		return err;

	*buffer = kmalloc(io_bytes, GFP_NOFS);
	if (!*buffer) {
		err = -ENOMEM;
		goto out_close;
	}

	err = ntfs_redo_rw_lcns(vol, lrh, 0, *buffer, io_bytes, false);
	if (err)
		goto out_free;

	/* Replay mutates the de-fixed view, so convert the on-disk sector tails first. */
	if (post_read_mst_fixup((struct ntfs_record *)(*buffer + record_off),
		    entry->bytes_per_index) ||
	    !ntfs_is_indx_recordp((__le32 *)(*buffer + record_off)) ||
	    ntfs_is_baad_recordp((__le32 *)(*buffer + record_off))) {
		err = -EINVAL;
		goto out_free;
	}

	if (replay_lsn && replay_lsn <= le64_to_cpu(
		    ((struct index_block *)(*buffer + record_off))->lsn) &&
	    le64_to_cpu(((struct index_block *)(*buffer + record_off))->lsn) <=
		    entry->env->layout.current_lsn) {
		err = -EALREADY;
		goto out_free;
	}
	if (replay_lsn)
		((struct index_block *)(*buffer + record_off))->lsn =
			cpu_to_le64(replay_lsn);

	*bytes = io_bytes;
	return 0;

out_free:
	kfree(*buffer);
	*buffer = NULL;
out_close:
	iput(*stream_vi);
	iput(*base_vi);
	*stream_vi = NULL;
	*base_vi = NULL;
	return err;
}

/* Re-apply MST fixups and write the modified INDX buffer back to disk. */
static int ntfs_redo_store_index_block(struct inode *stream_vi,
		const struct ntfs_redo_open_attr *entry, const struct ntfs_log_rec_hdr *lrh,
		u8 *buffer, u32 bytes)
{
	struct ntfs_volume *vol = NTFS_I(stream_vi)->vol;
	u16 record_off = le16_to_cpu(lrh->record_off);

	if (pre_write_mst_fixup((struct ntfs_record *)(buffer + record_off),
		    entry->bytes_per_index))
		return -EINVAL;

	return ntfs_redo_rw_lcns(vol, lrh, 0, buffer, bytes, true);
}

/* Locate and bounds-check the specific index entry referenced by attr_off. */
static int ntfs_redo_get_index_entry(u8 *buffer, u32 bytes,
		const struct ntfs_log_rec_hdr *lrh,
		struct index_block **ib_out, struct index_header **hdr_out,
		struct index_entry **ie_out)
{
	struct index_block *ib;
	struct index_header *hdr;
	struct index_entry *ie;
	u32 used;
	u32 total;
	u32 first_entry;
	u16 record_off = le16_to_cpu(lrh->record_off);
	u16 attr_off = le16_to_cpu(lrh->attr_off);
	u16 ie_len;

	if (!buffer || !ib_out || !hdr_out || !ie_out || record_off >= bytes)
		return -EINVAL;

	if (bytes - record_off < sizeof(*ib))
		return -EINVAL;

	ib = (struct index_block *)(buffer + record_off);
	hdr = &ib->index;
	total = le32_to_cpu(hdr->allocated_size);
	used = le32_to_cpu(hdr->index_length);
	first_entry = offsetof(struct index_block, index) +
		le32_to_cpu(hdr->entries_offset);

	if (used > total || first_entry > offsetof(struct index_block, index) + used ||
	    record_off + offsetof(struct index_block, index) + total > bytes)
		return -EINVAL;

	if (attr_off < first_entry ||
	    attr_off > offsetof(struct index_block, index) + used -
		    sizeof(struct index_entry_header))
		return -EINVAL;

	ie = (struct index_entry *)((u8 *)ib + attr_off);
	ie_len = le16_to_cpu(ie->length);
	if (ie_len < sizeof(struct index_entry_header) ||
	    attr_off + ie_len > offsetof(struct index_block, index) + used)
		return -EINVAL;

	*ib_out = ib;
	*hdr_out = hdr;
	*ie_out = ie;
	return 0;
}

/* Return the enclosing INDX block plus its size accounting for entry insertion/removal. */
static int ntfs_redo_get_index_block(u8 *buffer, u32 bytes,
		const struct ntfs_log_rec_hdr *lrh,
		struct index_block **ib_out, struct index_header **hdr_out,
		u32 *used_out, u32 *total_out, u32 *first_entry_out)
{
	struct index_block *ib;
	struct index_header *hdr;
	u32 used;
	u32 total;
	u32 first_entry;
	u16 record_off = le16_to_cpu(lrh->record_off);

	if (!buffer || !ib_out || !hdr_out || !used_out || !total_out ||
	    !first_entry_out || record_off >= bytes)
		return -EINVAL;

	if (bytes - record_off < sizeof(*ib))
		return -EINVAL;

	ib = (struct index_block *)(buffer + record_off);
	hdr = &ib->index;
	total = le32_to_cpu(hdr->allocated_size);
	used = le32_to_cpu(hdr->index_length);
	first_entry = offsetof(struct index_block, index) +
		le32_to_cpu(hdr->entries_offset);

	if (used > total || first_entry > offsetof(struct index_block, index) + used ||
	    record_off + offsetof(struct index_block, index) + total > bytes)
		return -EINVAL;

	*ib_out = ib;
	*hdr_out = hdr;
	*used_out = used;
	*total_out = total;
	*first_entry_out = first_entry;
	return 0;
}

/* Return the trailing child-VCN field of an internal index entry. */
static __le64 *ntfs_redo_index_entry_vcn_ptr(struct index_entry *ie)
{
	u16 ie_len;

	if (!ie || !(ie->flags & INDEX_ENTRY_NODE))
		return NULL;

	ie_len = le16_to_cpu(ie->length);
	if (ie_len < sizeof(struct index_entry_header) + sizeof(__le64))
		return NULL;

	return (__le64 *)((u8 *)ie + ie_len - sizeof(__le64));
}

/*
 * Resize a resident attribute in-place by shifting every following attribute
 * inside the MFT record.
 */
static int ntfs_redo_resize_resident_attr(struct mft_record *mrec,
		struct attr_record *attr, u32 new_len)
{
	u32 used;
	u32 old_len;
	u32 alloc;
	u32 record_off;
	int delta;

	if (!mrec || !attr)
		return -EINVAL;

	used = le32_to_cpu(mrec->bytes_in_use);
	old_len = le32_to_cpu(attr->length);
	alloc = le32_to_cpu(mrec->bytes_allocated);
	record_off = (u8 *)attr - (u8 *)mrec;
	if (new_len < sizeof(*attr) || record_off > used || used - record_off < old_len)
		return -EINVAL;

	if (new_len > old_len && new_len - old_len > alloc - used)
		return -EINVAL;

	/* Keep all trailing attributes while growing or shrinking this resident value. */
	memmove((u8 *)attr + new_len, (u8 *)attr + old_len,
		used - record_off - old_len);
	delta = (int)new_len - (int)old_len;
	mrec->bytes_in_use = cpu_to_le32(used + delta);
	attr->length = cpu_to_le32(new_len);
	return 0;
}

static struct ntfs_inode *ntfs_redo_get_mft_record_inode(struct ntfs_volume *vol,
		u64 mft_no, struct inode **vi_out);

static void ntfs_redo_put_mft_record_inode(struct ntfs_inode *ni,
		struct inode *vi)
{
	if (vi)
		iput(vi);
	else
		ntfs_clear_extent_inode(ni);
}

/* Open an INDEX_ROOT resident value and return its mutable header and bounds. */
static int ntfs_redo_open_index_root(struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn,
		struct ntfs_inode **ni_out, struct inode **vi_out,
		struct mft_record **mrec_out,
		struct attr_record **attr_out, struct index_root **root_out,
		struct index_header **hdr_out)
{
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_root *root;
	struct index_header *hdr;
	u64 mft_no;
	u32 value_len;
	u32 total;
	u32 used;
	u32 first_entry;
	u16 value_off;
	int err;

	if (!vol || !lrh || !ni_out || !vi_out || !mrec_out || !attr_out ||
	    !root_out || !hdr_out)
		return -EINVAL;

	mft_no = ntfs_redo_stream_base_pos(vol, lrh) >> vol->mft_record_size_bits;
	ni = ntfs_redo_get_mft_record_inode(vol, mft_no, &vi);
	if (IS_ERR(ni))
		return PTR_ERR(ni);

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out_put;
	}

	if (replay_lsn && replay_lsn <= le64_to_cpu(mrec->lsn)) {
		err = -EALREADY;
		goto out_unmap;
	}
	if (replay_lsn)
		mrec->lsn = cpu_to_le64(replay_lsn);

	err = ntfs_redo_locate_attr(mrec, NULL, le16_to_cpu(lrh->record_off),
			&attr);
	if (err || attr->type != AT_INDEX_ROOT || attr->non_resident) {
		if (!err)
			err = -EINVAL;
		goto out_unmap;
	}

	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (value_off > le32_to_cpu(attr->length) ||
	    value_len > le32_to_cpu(attr->length) - value_off ||
	    value_len < sizeof(*root)) {
		err = -EINVAL;
		goto out_unmap;
	}

	root = (struct index_root *)((u8 *)attr + value_off);
	hdr = &root->index;
	total = le32_to_cpu(hdr->allocated_size);
	used = le32_to_cpu(hdr->index_length);
	first_entry = offsetof(struct index_root, index) +
		le32_to_cpu(hdr->entries_offset);

	if (value_len < offsetof(struct index_root, index) + total || used > total ||
		first_entry > offsetof(struct index_root, index) + used) {
		err = -EINVAL;
		goto out_unmap;
	}

	*ni_out = ni;
	*vi_out = vi;
	*mrec_out = mrec;
	*attr_out = attr;
	*root_out = root;
	*hdr_out = hdr;
	return 0;

out_unmap:
	unmap_mft_record(ni);
out_put:
	ntfs_redo_put_mft_record_inode(ni, vi);
	return err;
}

/* Locate one entry inside an INDEX_ROOT payload using the log record's attr_off. */
static int ntfs_redo_get_root_index_entry(struct attr_record *attr,
		const struct index_header *hdr, u16 attr_off,
		struct index_entry **ie_out)
{
	struct index_entry *ie;
	u32 used;
	u32 base;
	u32 first_entry;
	u16 ie_len;

	if (!attr || !hdr || !ie_out)
		return -EINVAL;

	/*
	 * attr_off is measured from the start of the attribute record, while
	 * the index header offsets are measured from the start of the resident
	 * INDEX_ROOT value.  Rebase the header offsets onto the attribute by
	 * adding the resident value_offset so they share attr_off's origin.
	 */
	base = le16_to_cpu(attr->data.resident.value_offset) +
		offsetof(struct index_root, index);
	used = le32_to_cpu(hdr->index_length);
	first_entry = base + le32_to_cpu(hdr->entries_offset);
	if (attr_off < first_entry ||
	    attr_off > base + used - sizeof(struct index_entry_header))
		return -EINVAL;

	ie = (struct index_entry *)((u8 *)attr + attr_off);
	ie_len = le16_to_cpu(ie->length);
	if (ie_len < sizeof(struct index_entry_header) ||
	    attr_off + ie_len > base + used)
		return -EINVAL;

	*ie_out = ie;
	return 0;
}

/* Commit one modified MFT record that contains an INDEX_ROOT update. */
static int ntfs_redo_write_index_root(struct ntfs_inode *ni,
		struct mft_record *mrec)
{
	int err;

	err = ntfs_prepare_mft_record_write(ni);
	if (err)
		return err;

	mark_mft_record_dirty(ni);
	return write_mft_record(ni, mrec, 1);
}

/* Insert a resident index entry into INDEX_ROOT at the offset named by attr_off. */
static int ntfs_redo_apply_add_index_entry_root(struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	const struct index_entry *new_ie;
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_root *root;
	struct index_header *hdr;
	u32 used;
	u32 total;
	u32 base;
	u32 first_entry;
	u32 used_end;
	u32 value_len;
	u32 attr_len;
	u16 attr_off = le16_to_cpu(lrh->attr_off);
	u16 new_len;
	int err;

	if (data_off > rec_len ||
	    data_len < sizeof(struct index_entry_header) ||
	    data_len > rec_len - data_off) {
		return -EINVAL;
	}

	new_ie = (const void *)((const u8 *)lrh + data_off);
	new_len = le16_to_cpu(new_ie->length);
	if (new_len < sizeof(struct index_entry_header) || new_len > data_len) {
		return -EINVAL;
	}

	err = ntfs_redo_open_index_root(vol, lrh, replay_lsn,
			&ni, &vi, &mrec, &attr, &root, &hdr);
	if (err == -EALREADY)
		return 0;
	if (err) {
		return err;
	}

	/*
	 * attr_off counts from the attribute record. The index header offsets
	 * count from the resident INDEX_ROOT value.  Rebase the latter onto the
	 * attribute by adding value_offset so the bounds check and the memmove
	 * length below share attr_off's origin.
	 */
	base = le16_to_cpu(attr->data.resident.value_offset) +
		offsetof(struct index_root, index);
	total = le32_to_cpu(hdr->allocated_size);
	used = le32_to_cpu(hdr->index_length);
	first_entry = base + le32_to_cpu(hdr->entries_offset);
	used_end = base + used;
	if (attr_off < first_entry || attr_off > used_end) {
		err = -EINVAL;
		goto out;
	}

	value_len = le32_to_cpu(attr->data.resident.value_length);
	attr_len = le32_to_cpu(attr->length);
	err = ntfs_redo_resize_resident_attr(mrec, attr, attr_len + new_len);
	if (err) {
		goto out;
	}

	/* Shift later entries forward to make room for the inserted resident entry. */
	memmove((u8 *)attr + attr_off + new_len, (u8 *)attr + attr_off,
		used_end - attr_off);
	memcpy((u8 *)attr + attr_off, new_ie, new_len);
	attr->data.resident.value_length = cpu_to_le32(value_len + new_len);
	hdr->index_length = cpu_to_le32(used + new_len);
	hdr->allocated_size = cpu_to_le32(total + new_len);
	err = ntfs_redo_write_index_root(ni, mrec);
out:
	unmap_mft_record(ni);
	ntfs_redo_put_mft_record_inode(ni, vi);
	return err;
}

/* Remove one resident INDEX_ROOT entry and shrink the containing attribute. */
static int ntfs_redo_apply_delete_index_entry_root(struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn)
{
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_root *root;
	struct index_header *hdr;
	struct index_entry *ie;
	u32 used;
	u32 total;
	u32 used_end;
	u32 value_len;
	u32 attr_len;
	u16 attr_off = le16_to_cpu(lrh->attr_off);
	u16 ie_len;
	int err;

	err = ntfs_redo_open_index_root(vol, lrh, replay_lsn,
			&ni, &vi, &mrec, &attr, &root, &hdr);
	if (err == -EALREADY)
		return 0;
	if (err)
		return err;

	total = le32_to_cpu(hdr->allocated_size);
	used = le32_to_cpu(hdr->index_length);
	err = ntfs_redo_get_root_index_entry(attr, hdr, attr_off, &ie);
	if (err)
		goto out;

	ie_len = le16_to_cpu(ie->length);
	/* Rebase the index-value-relative end onto the attribute (see above). */
	used_end = le16_to_cpu(attr->data.resident.value_offset) +
		offsetof(struct index_root, index) + used;
	value_len = le32_to_cpu(attr->data.resident.value_length);
	attr_len = le32_to_cpu(attr->length);
	if (attr_len < ie_len || value_len < ie_len || total < ie_len || attr_off + ie_len > used_end) {
		err = -EINVAL;
		goto out;
	}

	/* Close the gap left by the deleted entry before shrinking the resident value. */
	memmove((u8 *)attr + attr_off, (u8 *)attr + attr_off + ie_len,
		used_end - attr_off - ie_len);
	attr->data.resident.value_length = cpu_to_le32(value_len - ie_len);
	hdr->index_length = cpu_to_le32(used - ie_len);
	hdr->allocated_size = cpu_to_le32(total - ie_len);
	err = ntfs_redo_resize_resident_attr(mrec, attr, attr_len - ie_len);
	if (err)
		goto out;

	err = ntfs_redo_write_index_root(ni, mrec);
out:
	unmap_mft_record(ni);
	ntfs_redo_put_mft_record_inode(ni, vi);
	return err;
}

/* Update the child VCN stored in a resident internal index entry. */
static int ntfs_redo_apply_set_index_entry_vcn_root(struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_root *root;
	struct index_header *hdr;
	struct index_entry *ie;
	__le64 *vcn_ptr;
	int err;

	if (data_off > rec_len || data_len != sizeof(__le64) || data_len > rec_len - data_off)
		return -EINVAL;

	err = ntfs_redo_open_index_root(vol, lrh, replay_lsn,
			&ni, &vi, &mrec, &attr, &root, &hdr);
	if (err == -EALREADY)
		return 0;
	if (err)
		return err;

	err = ntfs_redo_get_root_index_entry(attr, hdr, le16_to_cpu(lrh->attr_off),
			&ie);
	if (err)
		goto out;

	vcn_ptr = ntfs_redo_index_entry_vcn_ptr(ie);
	if (!vcn_ptr) {
		err = -EINVAL;
		goto out;
	}

	memcpy(vcn_ptr, (const u8 *)lrh + data_off, data_len);
	err = ntfs_redo_write_index_root(ni, mrec);
out:
	unmap_mft_record(ni);
	ntfs_redo_put_mft_record_inode(ni, vi);
	return err;
}

/* Overwrite the duplicated FILE_NAME metadata carried inside a root index entry. */
static int ntfs_redo_apply_update_file_name_root(struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_root *root;
	struct index_header *hdr;
	struct index_entry *ie;
	u16 ie_len;
	int err;

	if (data_off > rec_len || data_len != sizeof(struct ntfs_file_name_dup_info) ||
	    data_len > rec_len - data_off)
		return -EINVAL;

	err = ntfs_redo_open_index_root(vol, lrh, replay_lsn,
			&ni, &vi, &mrec, &attr, &root, &hdr);
	if (err == -EALREADY)
		return 0;
	if (err)
		return err;

	err = ntfs_redo_get_root_index_entry(attr, hdr, le16_to_cpu(lrh->attr_off),
			&ie);
	if (err)
		goto out;

	ie_len = le16_to_cpu(ie->length);
	if (offsetof(struct index_entry, key.file_name) +
	    offsetof(struct file_name_attr, creation_time) + data_len > ie_len) {
		err = -EINVAL;
		goto out;
	}

	memcpy((u8 *)&ie->key.file_name +
		offsetof(struct file_name_attr, creation_time),
		(const u8 *)lrh + data_off, data_len);
	err = ntfs_redo_write_index_root(ni, mrec);
out:
	unmap_mft_record(ni);
	ntfs_redo_put_mft_record_inode(ni, vi);
	return err;
}

/* Overwrite the variable data payload referenced by a resident index entry. */
static int ntfs_redo_apply_update_record_data_root(struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	struct index_root *root;
	struct index_header *hdr;
	struct index_entry *ie;
	u16 payload_off;
	u16 ie_len;
	int err;

	if (data_off > rec_len || data_len > rec_len - data_off)
		return -EINVAL;

	err = ntfs_redo_open_index_root(vol, lrh, replay_lsn,
			&ni, &vi, &mrec, &attr, &root, &hdr);
	if (err == -EALREADY)
		return 0;
	if (err)
		return err;

	err = ntfs_redo_get_root_index_entry(attr, hdr, le16_to_cpu(lrh->attr_off),
			&ie);
	if (err)
		goto out;

	payload_off = le16_to_cpu(ie->data.vi.data_offset);
	ie_len = le16_to_cpu(ie->length);
	if (!payload_off || payload_off > ie_len || data_len > ie_len - payload_off) {
		err = -EINVAL;
		goto out;
	}

	memcpy((u8 *)ie + payload_off, (const u8 *)lrh + data_off, data_len);
	err = ntfs_redo_write_index_root(ni, mrec);
out:
	unmap_mft_record(ni);
	ntfs_redo_put_mft_record_inode(ni, vi);
	return err;
}

/* Set or clear a contiguous bit range inside an on-disk little-endian bitmap. */
static void ntfs_redo_set_bits_le(u8 *bitmap, u32 start_bit, u32 count, bool set_bits)
{
	u32 bit;

	for (bit = 0; bit < count; bit++) {
		u32 index = start_bit + bit;
		u8 mask = 1u << (index & 7);

		if (set_bits)
			bitmap[index >> 3] |= mask;
		else
			bitmap[index >> 3] &= ~mask;
	}
}

/* Insert one entry into an INDEX_ALLOCATION buffer. */
static int ntfs_redo_apply_add_index_entry_allocation(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	const struct index_entry *new_ie;
	struct inode *base_vi;
	struct inode *stream_vi;
	struct index_block *ib;
	struct index_header *hdr;
	u8 *buffer = NULL;
	u32 bytes;
	u32 used;
	u32 total;
	u32 first_entry;
	u32 used_end;
	u16 attr_off = le16_to_cpu(lrh->attr_off);
	u16 new_len;
	int err;

	if (data_off > rec_len ||
	    data_len < sizeof(struct index_entry_header) ||
	    data_len > rec_len - data_off)
		return -EINVAL;

	new_ie = (const void *)((const u8 *)lrh + data_off);
	new_len = le16_to_cpu(new_ie->length);
	if (new_len < sizeof(struct index_entry_header) || new_len > data_len) {
		return -EINVAL;
	}

	err = ntfs_redo_load_index_block(vol, entry, lrh, replay_lsn,
			&base_vi, &stream_vi,
			&buffer, &bytes);
	if (err == -EALREADY)
		return 0;
	if (err) {
		return err;
	}

	err = ntfs_redo_get_index_block(buffer, bytes, lrh, &ib, &hdr, &used,
			&total, &first_entry);
	if (err) {
		goto out;
	}

	used_end = offsetof(struct index_block, index) + used;
	if (attr_off < first_entry || attr_off > used_end || used + new_len > total) {
		err = -EINVAL;
		goto out;
	}

	memmove((u8 *)ib + attr_off + new_len, (u8 *)ib + attr_off,
		used_end - attr_off);
	memcpy((u8 *)ib + attr_off, new_ie, new_len);
	hdr->index_length = cpu_to_le32(used + new_len);
	err = ntfs_redo_store_index_block(stream_vi, entry, lrh, buffer, bytes);
out:
	kfree(buffer);
	iput(stream_vi);
	iput(base_vi);
	return err;
}

/* Delete one entry from an INDEX_ALLOCATION buffer. */
static int ntfs_redo_apply_delete_index_entry_allocation(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	struct inode *base_vi;
	struct inode *stream_vi;
	struct index_block *ib;
	struct index_header *hdr;
	struct index_entry *ie;
	u8 *buffer = NULL;
	u32 bytes;
	u32 used;
	u32 total;
	u32 first_entry;
	u32 used_end;
	u16 attr_off = le16_to_cpu(lrh->attr_off);
	u16 ie_len;
	int err;

	if (data_off > rec_len || data_len > rec_len - data_off)
		return -EINVAL;

	err = ntfs_redo_load_index_block(vol, entry, lrh, replay_lsn,
			&base_vi, &stream_vi,
			&buffer, &bytes);
	if (err == -EALREADY)
		return 0;
	if (err)
		return err;

	err = ntfs_redo_get_index_block(buffer, bytes, lrh, &ib, &hdr, &used,
			&total, &first_entry);
	if (err)
		goto out;

	err = ntfs_redo_get_index_entry(buffer, bytes, lrh, &ib, &hdr, &ie);
	if (err)
		goto out;

	used_end = offsetof(struct index_block, index) + used;
	ie_len = le16_to_cpu(ie->length);
	if (attr_off < first_entry || attr_off + ie_len > used_end) {
		err = -EINVAL;
		goto out;
	}

	memmove((u8 *)ib + attr_off, (u8 *)ib + attr_off + ie_len,
		used_end - attr_off - ie_len);
	hdr->index_length = cpu_to_le32(used - ie_len);
	err = ntfs_redo_store_index_block(stream_vi, entry, lrh, buffer, bytes);
out:
	kfree(buffer);
	iput(stream_vi);
	iput(base_vi);
	return err;
}

/* Replace the tail marker entry that terminates an INDEX_ALLOCATION buffer. */
static int ntfs_redo_apply_write_end_of_index_buffer(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	struct inode *base_vi;
	struct inode *stream_vi;
	struct index_block *ib;
	struct index_header *hdr;
	u8 *buffer = NULL;
	u32 bytes;
	u32 used;
	u32 total;
	u32 first_entry;
	u16 attr_off = le16_to_cpu(lrh->attr_off);
	int err;

	if (data_off > rec_len || data_len > rec_len - data_off ||
	    data_len < sizeof(struct index_entry_header))
		return -EINVAL;

	err = ntfs_redo_load_index_block(vol, entry, lrh, replay_lsn,
			&base_vi, &stream_vi,
			&buffer, &bytes);
	if (err == -EALREADY)
		return 0;
	if (err)
		return err;

	err = ntfs_redo_get_index_block(buffer, bytes, lrh, &ib, &hdr, &used,
			&total, &first_entry);
	if (err)
		goto out;

	if (attr_off < first_entry ||
	    attr_off + data_len > offsetof(struct index_block, index) + total) {
		err = -EINVAL;
		goto out;
	}

	memcpy((u8 *)ib + attr_off, (const u8 *)lrh + data_off, data_len);
	hdr->index_length = cpu_to_le32(data_len + attr_off -
			offsetof(struct index_block, index));
	err = ntfs_redo_store_index_block(stream_vi, entry, lrh, buffer, bytes);
out:
	kfree(buffer);
	iput(stream_vi);
	iput(base_vi);
	return err;
}

/* Apply SetBits/ClearBits log actions to the referenced nonresident stream. */
static int ntfs_redo_apply_bitmap_range(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u32 rec_len,
		u16 data_off, u16 data_len, bool set_bits)
{
	const struct ntfs_bitmap_range *range;
	struct inode *base_vi;
	struct inode *stream_vi;
	u8 *buffer;
	u64 covered_bytes;
	u32 bit_off;
	u32 bits;
	u32 byte_count;
	u16 record_off = le16_to_cpu(lrh->record_off);
	int err;

	if (!entry) {
		return -EINVAL;
	}

	if (data_off > rec_len || data_len < sizeof(*range) || data_len > rec_len - data_off) {
		return -EINVAL;
	}

	range = (const void *)((const u8 *)lrh + data_off);
	bit_off = le32_to_cpu(range->bitmap_off);
	bits = le32_to_cpu(range->bits);
	if (!bits)
		return 0;

	byte_count = DIV_ROUND_UP(bit_off + bits, 8);
	covered_bytes = ntfs_redo_stream_covered_bytes(vol, lrh);
	if (!covered_bytes || record_off + byte_count > covered_bytes) {
		return -EINVAL;
	}

	err = ntfs_redo_open_stream(vol, entry, &base_vi, &stream_vi);
	if (err) {
		return err;
	}

	buffer = kmalloc(byte_count, GFP_NOFS);
	if (!buffer) {
		err = -ENOMEM;
		goto out_close;
	}

	/*
	 * Read and write the bitmap bytes through the log record's LCN array
	 * rather than the inode I/O helpers.  During replay the cached runlist
	 * may be seeded from the dirty-page table while the owning attribute's
	 * mapping pairs are still being replayed. The normal inode path merges
	 * those two views and can report a false runlist overlap (see
	 * ntfs_redo_rw_lcns).  The record covers only part of the bitmap, so
	 * seek to that exact byte range via @record_off.
	 */
	err = ntfs_redo_rw_lcns(vol, lrh, record_off, buffer, byte_count, false);
	if (err) {
		goto out_free;
	}

	ntfs_redo_set_bits_le(buffer, bit_off, bits, set_bits);
	err = ntfs_redo_rw_lcns(vol, lrh, record_off, buffer, byte_count, true);
	if (err) {
		goto out_free;
	}

	err = 0;
out_free:
	kfree(buffer);
out_close:
	iput(stream_vi);
	iput(base_vi);
	return err;
}

/* Update FILE_NAME duplicate-info inside an INDEX_ALLOCATION entry. */
static int ntfs_redo_apply_update_file_name_allocation(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	struct inode *base_vi;
	struct inode *stream_vi;
	struct index_block *ib;
	struct index_header *hdr;
	struct index_entry *ie;
	u8 *buffer = NULL;
	u32 bytes;
	u16 ie_len;
	int err;

	if (data_off > rec_len || data_len > rec_len - data_off ||
	    data_len != sizeof(struct ntfs_file_name_dup_info)) {
		return -EINVAL;
	}

	err = ntfs_redo_load_index_block(vol, entry, lrh, replay_lsn,
			&base_vi, &stream_vi,
			&buffer, &bytes);
	if (err == -EALREADY)
		return 0;
	if (err) {
		return err;
	}

	err = ntfs_redo_get_index_entry(buffer, bytes, lrh, &ib, &hdr, &ie);
	if (err) {
		goto out;
	}

	ie_len = le16_to_cpu(ie->length);
	if (offsetof(struct index_entry, key.file_name.creation_time) + data_len > ie_len) {
		err = -EINVAL;
		goto out;
	}

	memcpy((u8 *)&ie->key.file_name +
		offsetof(struct file_name_attr, creation_time),
		(const u8 *)lrh + data_off, data_len);
	err = ntfs_redo_store_index_block(stream_vi, entry, lrh, buffer, bytes);
out:
	kfree(buffer);
	iput(stream_vi);
	iput(base_vi);
	return err;
}

/* Update the child VCN stored in an INDEX_ALLOCATION internal entry. */
static int ntfs_redo_apply_set_index_entry_vcn_allocation(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	struct inode *base_vi;
	struct inode *stream_vi;
	struct index_block *ib;
	struct index_header *hdr;
	struct index_entry *ie;
	u8 *buffer = NULL;
	u32 bytes;
	u16 ie_len;
	int err;

	if (data_off > rec_len || data_len != sizeof(__le64) || data_len > rec_len - data_off)
		return -EINVAL;

	err = ntfs_redo_load_index_block(vol, entry, lrh, replay_lsn,
			&base_vi, &stream_vi,
			&buffer, &bytes);
	if (err == -EALREADY)
		return 0;
	if (err)
		return err;

	err = ntfs_redo_get_index_entry(buffer, bytes, lrh, &ib, &hdr, &ie);
	if (err)
		goto out;

	ie_len = le16_to_cpu(ie->length);
	if (!(ie->flags & INDEX_ENTRY_NODE) || ie_len < sizeof(struct index_entry_header) + sizeof(__le64)) {
		err = -EINVAL;
		goto out;
	}

	memcpy((u8 *)ie + ie_len - sizeof(__le64), (const u8 *)lrh + data_off,
		data_len);
	err = ntfs_redo_store_index_block(stream_vi, entry, lrh, buffer, bytes);
out:
	kfree(buffer);
	iput(stream_vi);
	iput(base_vi);
	return err;
}

/* Update the variable payload referenced by an INDEX_ALLOCATION entry. */
static int ntfs_redo_apply_update_record_data_allocation(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	struct inode *base_vi;
	struct inode *stream_vi;
	struct index_block *ib;
	struct index_header *hdr;
	struct index_entry *ie;
	u8 *buffer = NULL;
	u32 bytes;
	u16 ie_len;
	u16 payload_off;
	int err;

	if (data_off > rec_len || data_len > rec_len - data_off)
		return -EINVAL;

	err = ntfs_redo_load_index_block(vol, entry, lrh, replay_lsn,
			&base_vi, &stream_vi,
			&buffer, &bytes);
	if (err == -EALREADY)
		return 0;
	if (err)
		return err;

	err = ntfs_redo_get_index_entry(buffer, bytes, lrh, &ib, &hdr, &ie);
	if (err)
		goto out;

	ie_len = le16_to_cpu(ie->length);
	payload_off = le16_to_cpu(ie->data.vi.data_offset);
	if (!payload_off || payload_off > ie_len || data_len > ie_len - payload_off) {
		err = -EINVAL;
		goto out;
	}

	memcpy((u8 *)ie + payload_off, (const u8 *)lrh + data_off, data_len);
	err = ntfs_redo_store_index_block(stream_vi, entry, lrh, buffer, bytes);
out:
	kfree(buffer);
	iput(stream_vi);
	iput(base_vi);
	return err;
}

/* Recompute highest_vcn after mapping-pairs replay changes a nonresident runlist. */
static int ntfs_redo_calc_highest_vcn(const struct attr_record *attr, u64 *highest_vcn)
{
	const u8 *buf;
	const u8 *end;
	u64 vcn;

	if (!attr || !attr->non_resident || !highest_vcn)
		return -EINVAL;

	vcn = le64_to_cpu(attr->data.non_resident.lowest_vcn);
	buf = (const u8 *)attr + le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	end = (const u8 *)attr + le32_to_cpu(attr->length);
	if (buf < (const u8 *)attr || buf > end)
		return -EINVAL;

	while (buf < end && *buf) {
		u8 len_len = *buf & 0xf;
		u8 off_len = *buf >> 4;
		s64 run_len = 0;
		u8 i;

		if (!len_len || buf + 1 + len_len + off_len > end)
			return -EINVAL;

		for (i = 0; i < len_len; i++)
			run_len |= (s64)buf[1 + i] << (i * 8);
		if (run_len < 0)
			return -EINVAL;

		vcn += run_len;
		buf += 1 + len_len + off_len;
	}

	if (buf >= end)
		return -EINVAL;

	/* An empty extent ends immediately before its lowest VCN. */
	*highest_vcn = vcn - 1;
	return 0;
}

static int ntfs_redo_record_attr_at(struct mft_record *mrec, u16 record_off,
		bool allow_end, struct attr_record **attr)
{
	struct attr_record *a;
	u32 off;
	u32 used;
	u32 len;

	if (!mrec || !attr)
		return -EINVAL;

	used = le32_to_cpu(mrec->bytes_in_use);
	off = le16_to_cpu(mrec->attrs_offset);
	if (off > record_off || record_off > used ||
	    used - record_off < sizeof_field(struct attr_record, type)) {
		return -EINVAL;
	}

	a = (struct attr_record *)((u8 *)mrec + off);
	while (off < record_off) {
		len = le32_to_cpu(a->length);
		if (a->type == AT_END ||
		    len < (offsetof(struct attr_record, data.resident.reserved) +
			   sizeof(a->data.resident.reserved)) ||
		    len > used - off) {
			return -EINVAL;
		}
		off += len;
		a = (struct attr_record *)((u8 *)mrec + off);
	}
	if (off != record_off || (!allow_end && a->type == AT_END)) {
		return -EINVAL;
	}
	*attr = a;
	return 0;
}

/* Locate an attribute record in an MFT entry and optionally validate its identity. */
static int ntfs_redo_locate_attr(struct mft_record *mrec,
		const struct ntfs_redo_open_attr *entry,
		u16 record_off, struct attr_record **attr)
{
	struct attr_record *a;
	u32 used;
	u32 len;
	u16 name_off;
	int err;

	err = ntfs_redo_record_attr_at(mrec, record_off, false, &a);
	if (err) {
		return err;
	}

	used = le32_to_cpu(mrec->bytes_in_use);
	len = le32_to_cpu(a->length);
	/*
	 * sizeof(struct attr_record) is the maximum template size (it includes
	 * the resident/non-resident union). A valid attribute only needs the
	 * resident header, which is far smaller -- an empty resident attribute
	 * (e.g. an unnamed $DATA placeholder) is just 24 bytes.  Using the full
	 * struct size as the minimum wrongly refuses such attributes, so a
	 * DeleteAttribute targeting one is silently skipped, leaving it behind
	 * and diverging the record.  Require only the resident header.
	 */
	if (len < offsetof(struct attr_record, data.resident.reserved) +
			sizeof(a->data.resident.reserved) ||
	    record_off + len > used) {
		return -EINVAL;
	}

	if (!ntfs_is_file_record(mrec->magic) || a->type == AT_END) {
		return -EINVAL;
	}

	if (entry) {
		if (a->type != entry->type)
			return -EINVAL;

		if (entry->name_len) {
			name_off = le16_to_cpu(a->name_offset);
			if (name_off > len || entry->name_len * sizeof(__le16) > len - name_off) {
				return -EINVAL;
			}
			if (memcmp((u8 *)a + name_off, entry->name,
				    entry->name_len * sizeof(__le16))) {
				return -EINVAL;
			}
		}
	}

	*attr = a;
	return 0;
}

/* Structural replay must also map records with temporarily missing attributes. */
static struct ntfs_inode *ntfs_redo_get_mft_record_inode(struct ntfs_volume *vol,
		u64 mft_no, struct inode **vi_out)
{
	struct ntfs_attr na = {
		.mft_no = mft_no,
		.type = AT_UNUSED,
	};
	struct ntfs_inode *ni;
	struct inode *vi;

	/* Keep the record view of any inode already pinned during mount. */
	vi = ilookup5(vol->sb, mft_no, ntfs_test_inode, &na);
	*vi_out = vi;
	if (vi)
		return NTFS_I(vi);
	ni = ntfs_new_extent_inode(vol->sb, mft_no);
	if (!ni)
		return ERR_PTR(-ENOMEM);
	ni->nr_extents = -1;
	ni->ext.base_ntfs_ino = NTFS_I(vol->mft_ino);
	return ni;
}


/* Replay SetNewAttributeSizes onto a nonresident attribute header in the MFT. */
static int ntfs_redo_apply_set_new_sizes(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	const struct ntfs_new_attribute_sizes *sizes;
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	struct ntfs_redo_attr_state state = { };
	u64 mft_pos;
	u64 mft_no;
	u16 record_off = le16_to_cpu(lrh->record_off);
	int err;

	if (data_off > rec_len || data_len > rec_len - data_off ||
	    (data_len != offsetof(struct ntfs_new_attribute_sizes, total_size) &&
	     data_len != sizeof(*sizes))) {
		return -EINVAL;
	}

	sizes = (const void *)((const u8 *)lrh + data_off);
	mft_pos = (le64_to_cpu(lrh->target_vcn) << vol->cluster_size_bits) +
		((u64)le16_to_cpu(lrh->cluster_off) << NTFS_BLOCK_SIZE_BITS);
	mft_no = mft_pos >> vol->mft_record_size_bits;

	ni = ntfs_redo_get_mft_record_inode(vol, mft_no, &vi);
	if (IS_ERR(ni))
		return PTR_ERR(ni);

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out_iput;
	}
	if (replay_lsn && replay_lsn <= le64_to_cpu(mrec->lsn)) {
		err = 0;
		goto out_unmap;
	}
	if (replay_lsn)
		mrec->lsn = cpu_to_le64(replay_lsn);

	/*
	 * The open attribute (entry) is only the dirty-page context here -- for
	 * $MFT it is the unnamed $DATA stream even when the record actually
	 * resizes $BITMAP -- so do not type-check against it.  record_off
	 * alone identifies the target attribute.
	 */
	err = ntfs_redo_locate_attr(mrec, NULL, record_off, &attr);
	if (err) {
		goto out_unmap;
	}

	if (!attr->non_resident) {
		err = -EINVAL;
		goto out_unmap;
	}
	if (data_len == sizeof(*sizes) &&
	    le16_to_cpu(attr->data.non_resident.mapping_pairs_offset) <
		offsetof(struct attr_record, data.non_resident.compressed_size) +
			sizeof(attr->data.non_resident.compressed_size)) {
		err = -EINVAL;
		goto out_unmap;
	}
	if (le64_to_cpu(sizes->valid_size) >
	    le64_to_cpu(sizes->data_size)) {
		err = -EINVAL;
		goto out_unmap;
	}

	attr->data.non_resident.allocated_size = sizes->alloc_size;
	attr->data.non_resident.data_size = sizes->data_size;
	attr->data.non_resident.initialized_size = sizes->valid_size;
	if (data_len >= sizeof(*sizes))
		attr->data.non_resident.compressed_size = sizes->total_size;

	state.allocated_size = le64_to_cpu(attr->data.non_resident.allocated_size);
	state.data_size = le64_to_cpu(attr->data.non_resident.data_size);
	state.initialized_size = le64_to_cpu(attr->data.non_resident.initialized_size);

	err = ntfs_prepare_mft_record_write(ni);
	if (err) {
		goto out_unmap;
	}

	mark_mft_record_dirty(ni);
	err = write_mft_record(ni, mrec, 1);
	if (!err)
		err = ntfs_redo_refresh_stream(vol, mft_no, mrec, attr, &state);
out_unmap:
	unmap_mft_record(ni);
out_iput:
	if (vi)
		iput(vi);
	else
		ntfs_clear_extent_inode(ni);
	return err;
}

/*
 * Mapping pairs precede the matching size update in a growth transaction.
 * Decode a private header with enough allocation for those pairs, and retain
 * any later MFT allocation already read from disk.  Historical redo must not
 * discard the mapping needed to locate subsequent MFT records.
 */
static int ntfs_redo_refresh_mft_runlist(struct ntfs_inode *ni,
		const struct attr_record *attr)
{
	struct ntfs_volume *vol = ni->vol;
	struct attr_record *copy;
	struct runlist_element *source;
	struct runlist_element *merged = NULL;
	u64 highest = le64_to_cpu(attr->data.non_resident.highest_vcn);
	s64 end;
	size_t count;
	size_t head = 0;
	size_t used;
	size_t i;
	int err = 0;

	if (attr->data.non_resident.lowest_vcn ||
	    highest >= (S64_MAX >> vol->cluster_size_bits))
		return -EINVAL;
	copy = kmemdup(attr, le32_to_cpu(attr->length), GFP_NOFS);
	if (!copy)
		return -ENOMEM;
	copy->data.non_resident.allocated_size = cpu_to_le64(max_t(u64,
			le64_to_cpu(copy->data.non_resident.allocated_size),
			(highest + 1) << vol->cluster_size_bits));
	source = ntfs_mapping_pairs_decompress(vol, copy, NULL, &count);
	kfree(copy);
	if (IS_ERR(source))
		return PTR_ERR(source);
	while (head < count - 1 && source[head].lcn >= 0)
		head++;
	if (!head || source[0].vcn ||
	    source[head - 1].vcn + source[head - 1].length != highest + 1) {
		err = -EINVAL;
		goto out_source;
	}
	end = highest + 1;
	down_write(&ni->runlist.lock);
	merged = kvmalloc_array(count + ni->runlist.count,
			sizeof(*merged), GFP_NOFS);
	if (!merged) {
		err = -ENOMEM;
		goto out_unlock;
	}
	memcpy(merged, source, head * sizeof(*merged));
	used = head;
	for (i = 0; i + 1 < ni->runlist.count; i++) {
		struct runlist_element tail = ni->runlist.rl[i];
		s64 tail_end = tail.vcn + tail.length;

		if (tail_end <= end)
			continue;
		if (tail.vcn > end || tail.lcn < 0) {
			err = -EINVAL;
			goto out_unlock;
		}
		tail.lcn += end - tail.vcn;
		tail.length = tail_end - end;
		tail.vcn = end;
		merged[used++] = tail;
		end = tail_end;
	}
	merged[used++] = (struct runlist_element) {
		.vcn = end,
		.lcn = LCN_ENOENT,
	};
	kvfree(ni->runlist.rl);
	ni->runlist.rl = merged;
	ni->runlist.count = used;
	ni->runlist.rl_hint = -1;
	NInoSetFullyMapped(ni);
	merged = NULL;
out_unlock:
	up_write(&ni->runlist.lock);
	kvfree(merged);
out_source:
	kvfree(source);
	return err;
}

/* Replay UpdateMappingPairs by replacing the mapping-pairs array inside the MFT. */
static int ntfs_redo_apply_mapping_pairs(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	const u8 *data;
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	struct ntfs_redo_attr_state state = { };
	u64 mft_pos;
	u64 mft_no;
	u64 highest_vcn;
	u32 asize;
	u32 nsize;
	u32 used;
	u16 record_off = le16_to_cpu(lrh->record_off);
	u16 attr_off = le16_to_cpu(lrh->attr_off);
	int err;

	if (data_off > rec_len || data_len > rec_len - data_off)
		return -EINVAL;

	data = (const u8 *)lrh + data_off;
	mft_pos = (le64_to_cpu(lrh->target_vcn) << vol->cluster_size_bits) +
		((u64)le16_to_cpu(lrh->cluster_off) << NTFS_BLOCK_SIZE_BITS);
	mft_no = mft_pos >> vol->mft_record_size_bits;

	ni = ntfs_redo_get_mft_record_inode(vol, mft_no, &vi);
	if (IS_ERR(ni))
		return PTR_ERR(ni);

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out_iput;
	}
	if (replay_lsn && replay_lsn <= le64_to_cpu(mrec->lsn)) {
		err = 0;
		goto out_unmap;
	}
	if (replay_lsn)
		mrec->lsn = cpu_to_le64(replay_lsn);

	/*
	 * As in ntfs_redo_apply_set_new_sizes(), the open attribute is only the
	 * dirty-page context (for $MFT the unnamed $DATA even when the record
	 * updates $BITMAP's mapping pairs), so do not type-check against it.
	 * record_off identifies the target attribute and drives the resize
	 * arithmetic below.
	 */
	err = ntfs_redo_locate_attr(mrec, NULL, record_off, &attr);
	if (err)
		goto out_unmap;

	if (!attr->non_resident) {
		err = -EINVAL;
		goto out_unmap;
	}

	asize = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	if (attr_off < le16_to_cpu(attr->data.non_resident.mapping_pairs_offset) ||
	    attr_off > asize || used < record_off + asize) {
		err = -EINVAL;
		goto out_unmap;
	}

	nsize = ALIGN(attr_off + data_len, 8);
	if (nsize > asize && nsize - asize > le32_to_cpu(mrec->bytes_allocated) - used) {
		err = -EINVAL;
		goto out_unmap;
	}

	/* Grow or shrink the containing attribute so the new mapping-pairs array fits exactly. */
	memmove((u8 *)attr + nsize, (u8 *)attr + asize,
		used - record_off - asize);
	mrec->bytes_in_use = cpu_to_le32(used + nsize - asize);
	attr->length = cpu_to_le32(nsize);
	memcpy((u8 *)attr + attr_off, data, data_len);

	err = ntfs_redo_calc_highest_vcn(attr, &highest_vcn);
	if (err)
		goto out_unmap;

	attr->data.non_resident.highest_vcn = cpu_to_le64(highest_vcn);
	state.allocated_size = le64_to_cpu(attr->data.non_resident.allocated_size);
	state.data_size = le64_to_cpu(attr->data.non_resident.data_size);
	state.initialized_size = le64_to_cpu(attr->data.non_resident.initialized_size);

	err = ntfs_prepare_mft_record_write(ni);
	if (err)
		goto out_unmap;

	mark_mft_record_dirty(ni);
	err = write_mft_record(ni, mrec, 1);
	if (!err && mft_no == FILE_MFT && attr->type == AT_DATA &&
	    !attr->name_length)
		err = ntfs_redo_refresh_mft_runlist(ni, attr);
	if (!err)
		err = ntfs_redo_refresh_stream(vol, mft_no, mrec, attr, &state);
out_unmap:
	unmap_mft_record(ni);
out_iput:
	if (vi)
		iput(vi);
	else
		ntfs_clear_extent_inode(ni);
	return err;
}

/* Check an old image without reporting stale allocation contents as corruption. */
static bool ntfs_redo_index_mst_valid(const struct index_block *ib, u32 bytes)
{
	const u8 *data = (const u8 *)ib;
	u16 usa_ofs = le16_to_cpu(ib->usa_ofs);
	u16 usa_count = le16_to_cpu(ib->usa_count);
	u16 usn;
	u32 i;

	if (ib->magic != magic_INDX ||
	    !IS_ALIGNED(bytes, NTFS_BLOCK_SIZE) || !IS_ALIGNED(usa_ofs, 2) ||
	    usa_count != 1 + (bytes >> NTFS_BLOCK_SIZE_BITS) ||
	    usa_ofs < sizeof(struct ntfs_record) ||
	    usa_ofs + usa_count * sizeof(__le16) > bytes)
		return false;

	usn = get_unaligned_le16(data + usa_ofs);
	for (i = 1; i < usa_count; i++) {
		if (get_unaligned_le16(data + i * NTFS_BLOCK_SIZE - 2) != usn)
			return false;
	}
	return true;
}

/*
 * Replay UpdateNonresidentValue either into a generic stream byte range or,
 * for INDX buffers, through an MST-fixed temporary buffer.
 */
static int ntfs_redo_apply_nonresident_value(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u32 rec_len,
		u16 data_off, u16 data_len)
{
	const u8 *data;
	u16 record_off = le16_to_cpu(lrh->record_off);
	int err;

	if (!entry) {
		return -EINVAL;
	}

	if (data_off > rec_len || data_len > rec_len - data_off) {
		return -EINVAL;
	}

	data = (const u8 *)lrh + data_off;

	/*
	 * The write goes straight to the clusters named by the log record's LCN
	 * array (ntfs_redo_rw_lcns), and bytes_per_index comes from the open
	 * attribute, so no stream inode is needed.  Do not open one: during
	 * replay the target index can be mid-rebuild (its $INDEX_ROOT was just
	 * deleted before the new one is created), which would make
	 * ntfs_index_iget()/ntfs_attr_iget() fail with -ENOENT.
	 */

	if (entry->type == AT_INDEX_ALLOCATION && entry->bytes_per_index) {
		struct index_block *ib;
		u32 bytes = ntfs_redo_index_io_bytes(entry, record_off);
		u8 *buffer;
		bool full_image = data_len == entry->bytes_per_index &&
			data_len >= sizeof(*ib) &&
			((const struct index_block *)data)->magic == magic_INDX;
		bool valid_image;

		buffer = kmalloc(bytes, GFP_NOFS);
		if (!buffer) {
			err = -ENOMEM;
			goto out_close;
		}

		err = ntfs_redo_rw_lcns(vol, lrh, 0, buffer, bytes, false);
		if (err) {
			kfree(buffer);
			goto out_close;
		}

		ib = (struct index_block *)(buffer + record_off);
		/*
		 * Full images also initialize newly allocated clusters, whose
		 * previous contents need not have valid magic or MST protection.
		 * Partial changes still require a valid, deprotected old image.
		 */
		valid_image = ntfs_redo_index_mst_valid(ib, entry->bytes_per_index);
		if (!full_image &&
		    (post_read_mst_fixup((struct ntfs_record *)ib,
				entry->bytes_per_index) ||
		     !ntfs_is_indx_recordp(&ib->magic))) {
			err = -EINVAL;
			kfree(buffer);
			goto out_close;
		}
		if (valid_image && replay_lsn &&
		    replay_lsn <= le64_to_cpu(ib->lsn) &&
		    le64_to_cpu(ib->lsn) <= entry->env->layout.current_lsn) {
			err = 0;
			kfree(buffer);
			goto out_close;
		}
		memcpy(buffer + record_off, data, data_len);
		ib = (struct index_block *)(buffer + record_off);
		if (replay_lsn)
			ib->lsn = cpu_to_le64(replay_lsn);
		if (pre_write_mst_fixup((struct ntfs_record *)(buffer + record_off),
			    entry->bytes_per_index)) {
			err = -EINVAL;
			kfree(buffer);
			goto out_close;
		}

		err = ntfs_redo_rw_lcns(vol, lrh, 0, buffer, bytes, true);
		kfree(buffer);
		if (err) {
			goto out_close;
		}
	} else {
		/*
		 * Write straight to the clusters named by the log record's LCN
		 * array instead of going through the inode, which would merge
		 * the dirty-page-seeded runlist with the attribute's mapping
		 * pairs and can report a false overlap (see ntfs_redo_rw_lcns).
		 */
		err = ntfs_redo_rw_lcns(vol, lrh, record_off, (u8 *)data,
				data_len, true);
		if (err) {
			goto out_close;
		}
	}

	err = 0;
out_close:
	return err;
}

static int ntfs_redo_load_restart(struct ntfs_volume *vol,
		const struct restart_page_header *rp,
		struct ntfs_redo_env *env)
{
	const struct restart_area *ra;
	const struct log_client_record *client_array;
	const struct log_client_record *client_record;
	struct ntfs_lfs_record_hdr hdr;
	void *payload = NULL;
	u32 payload_len = 0;
	u16 client_idx;
	u64 lsn;
	int err;

	/* Decode the on-disk log geometry once so every later helper can share it. */
	ra = (const struct restart_area *)((const u8 *)rp +
			le16_to_cpu(rp->restart_area_offset));

	env->layout.page_size = le32_to_cpu(rp->log_page_size);
	if (!is_power_of_2(env->layout.page_size) || env->layout.page_size < NTFS_BLOCK_SIZE) {
		return -EINVAL;
	}

	env->layout.page_mask = env->layout.page_size - 1;
	env->layout.log_size = le64_to_cpu(ra->file_size);
	env->layout.first_page = env->ctx->major_ver >= 2 ?
		0x22ULL * env->layout.page_size : 4ULL * env->layout.page_size;
	env->layout.seq_num_bits = le32_to_cpu(ra->seq_number_bits);
	if (!env->layout.seq_num_bits || env->layout.seq_num_bits >= 64) {
		return -EINVAL;
	}
	env->layout.file_data_bits = 64 - env->layout.seq_num_bits;
	env->layout.record_header_len = le16_to_cpu(ra->log_record_header_length);
	env->layout.data_off = le16_to_cpu(ra->log_page_data_offset);
	/* Prefer the already-parsed current_lsn from analysis when it is available. */
	env->layout.current_lsn = env->ctx->current_lsn ?
		env->ctx->current_lsn : le64_to_cpu(ra->current_lsn);

	if (!env->layout.log_size || env->layout.log_size > i_size_read(vol->logfile_ino) ||
	    env->layout.first_page >= env->layout.log_size ||
	    env->layout.record_header_len < sizeof(struct ntfs_lfs_record_hdr) ||
	    env->layout.data_off >= env->layout.page_size) {
		return -EINVAL;
	}

	client_idx = le16_to_cpu(ra->client_in_use_list);
	if (client_idx == LOGFILE_NO_CLIENT_CPU)
		return 0;

	if (client_idx >= le16_to_cpu(ra->log_clients)) {
		return -EINVAL;
	}

	client_array = (const struct log_client_record *)((const u8 *)ra +
			le16_to_cpu(ra->client_array_offset));
	client_record = client_array + client_idx;
	env->layout.oldest_lsn = le64_to_cpu(client_record->oldest_lsn);
	env->layout.client_seq = le16_to_cpu(client_record->seq_number);
	env->layout.client_idx = client_idx;
	lsn = le64_to_cpu(client_record->client_restart_lsn);
	env->checkpoint_record_lsn = lsn;
	ntfs_debug("ntfs: %s: layout page_size=%u data_off=%u record_header_len=%u log_size=%llu first_page=%llu seq_bits=%u file_data_bits=%u current_lsn=%llu oldest_lsn=%llu client_seq=%u client_idx=%u restart_lsn=%llu\n",
	       __func__, env->layout.page_size, env->layout.data_off,
	       env->layout.record_header_len,
	       (unsigned long long)env->layout.log_size,
	       (unsigned long long)env->layout.first_page,
	       env->layout.seq_num_bits, env->layout.file_data_bits,
	       (unsigned long long)env->layout.current_lsn,
	       (unsigned long long)env->layout.oldest_lsn,
	       env->layout.client_seq, env->layout.client_idx,
	       (unsigned long long)lsn);
	if (!lsn)
		return 0;

	err = ntfs_log_read_client_record(vol->logfile_ino, &env->layout, lsn,
			&hdr, &payload, &payload_len);
	if (err) {
		return err;
	}

	if ((hdr.record_type != LFS_CLIENT_RECORD &&
	     hdr.record_type != LFS_CLIENT_RESTART) ||
	    payload_len < sizeof(env->restart)) {
		err = -EINVAL;
		ntfs_log_dump_lfs_record("redo-load-restart invalid restart record", &hdr,
				payload_len);
		goto out;
	}

	memcpy(&env->restart, payload, sizeof(env->restart));
	if (!ntfs_checkpoint_dump_ref_valid(
			env->restart.open_attr_table_lsn,
			env->restart.open_attr_len) ||
	    !ntfs_checkpoint_dump_ref_valid(env->restart.attr_names_lsn,
			env->restart.attr_names_len) ||
	    !ntfs_checkpoint_dump_ref_valid(
			env->restart.dirty_pages_table_lsn,
			env->restart.dirty_pages_len) ||
	    !ntfs_checkpoint_dump_ref_valid(env->restart.transact_table_lsn,
			env->restart.transact_table_len)) {
		err = -EINVAL;
		goto out;
	}
	if (le32_to_cpu(env->restart.major_ver) > 1) {
		ntfs_error(vol->sb,
			"LogFile checkpoint table version %u is not supported.",
			le32_to_cpu(env->restart.major_ver));
		err = -EOPNOTSUPP;
		goto out;
	}
	env->open_attr_entry_size = le32_to_cpu(env->restart.major_ver) ?
		sizeof(struct ntfs_open_attr_entry_disk) :
		sizeof(struct ntfs_open_attr_entry_disk32);
	ntfs_debug("ntfs: %s: checkpoint_start=%llu open_attr_lsn=%llu attr_names_lsn=%llu dirty_pages_lsn=%llu transact_lsn=%llu open_attr_len=%u attr_names_len=%u dirty_pages_len=%u transact_len=%u checkpoint_ver=%u.%u\n",
	       __func__,
	       (unsigned long long)le64_to_cpu(env->restart.check_point_start),
	       (unsigned long long)le64_to_cpu(env->restart.open_attr_table_lsn),
	       (unsigned long long)le64_to_cpu(env->restart.attr_names_lsn),
	       (unsigned long long)le64_to_cpu(env->restart.dirty_pages_table_lsn),
	       (unsigned long long)le64_to_cpu(env->restart.transact_table_lsn),
	       le32_to_cpu(env->restart.open_attr_len),
	       le32_to_cpu(env->restart.attr_names_len),
	       le32_to_cpu(env->restart.dirty_pages_len),
	       le32_to_cpu(env->restart.transact_table_len),
	       le32_to_cpu(env->restart.major_ver),
	       le32_to_cpu(env->restart.minor_ver));
	err = ntfs_redo_discover_current_lsn(vol, &env->layout, lsn);
	if (err) {
		goto out;
	}
	/* Keep the durable tail that may be newer than both restart copies. */
	if (env->layout.current_lsn > vol->journal_recovery_lsn)
		vol->journal_recovery_lsn = env->layout.current_lsn;
	err = 0;
out:
	kfree(payload);
	return err;
}

/* Load the checkpoint transaction table so redo can find undo chains later. */
static int ntfs_redo_load_transaction_table(struct ntfs_volume *vol,
		struct ntfs_redo_env *env)
{
	struct ntfs_lfs_record_hdr hdr;
	const struct ntfs_log_restart_table *restart_table;
	const void *cur = NULL;
	const void *dump;
	void *payload = NULL;
	u32 dump_len;
	u32 payload_len = 0;
	int err;

	if (!le32_to_cpu(env->restart.transact_table_len) ||
	    !le64_to_cpu(env->restart.transact_table_lsn))
		return 0;
	ntfs_debug("ntfs: %s: read transaction table lsn=%llu len=%u\n",
	       __func__,
	       (unsigned long long)le64_to_cpu(env->restart.transact_table_lsn),
	       le32_to_cpu(env->restart.transact_table_len));

	err = ntfs_log_read_client_record(vol->logfile_ino, &env->layout,
			le64_to_cpu(env->restart.transact_table_lsn),
			&hdr, &payload, &payload_len);
	if (err) {
		return err;
	}

	err = ntfs_log_checkpoint_dump_data(&hdr, payload, payload_len,
			TransactionTableDump,
			le32_to_cpu(env->restart.transact_table_len),
			&dump, &dump_len);
	if (err) {
		ntfs_log_dump_lfs_record("transaction-table invalid log record lfs", &hdr,
				payload_len);
		goto out;
	}

	restart_table = dump;
	if (dump_len < sizeof(*restart_table)) {
		err = -EINVAL;
		goto out;
	}
	if (!ntfs_log_validate_restart_table(restart_table, dump_len) ||
	    ntfs_restart_table_bytes(restart_table) != dump_len ||
	    le16_to_cpu(restart_table->size) < sizeof(struct ntfs_transaction_entry)) {
		pr_err("ntfs: %s: invalid transaction restart table dump_len=%u table_size=%u table_used=%u table_total=%u\n",
		       __func__, dump_len,
		       le16_to_cpu(restart_table->size),
		       le16_to_cpu(restart_table->used),
		       le16_to_cpu(restart_table->total));
		err = -EINVAL;
		goto out;
	}

	while ((cur = ntfs_next_restart_table_entry(restart_table, cur))) {
		const struct ntfs_transaction_entry *tr = cur;
		u32 slot = (const u8 *)cur - (const u8 *)restart_table;

		err = ntfs_redo_add_transaction(env, slot, tr);
		if (err) {
			goto out;
		}
	}

	err = 0;
out:
	kfree(payload);
	return err;
}

/* Rebuild the checkpoint OPEN_ATTR table and the separate attribute-name dump. */
static int ntfs_redo_bootstrap_open_attrs(struct ntfs_volume *vol,
		struct ntfs_redo_env *env)
{
	struct ntfs_lfs_record_hdr hdr;
	const void *dump;
	void *payload = NULL;
	u32 dump_len;
	u32 payload_len = 0;
	int err;

	if (le32_to_cpu(env->restart.open_attr_len) &&
	    le64_to_cpu(env->restart.open_attr_table_lsn)) {
		ntfs_debug("ntfs: %s: read open-attr table lsn=%llu len=%u\n",
		       __func__,
		       (unsigned long long)le64_to_cpu(env->restart.open_attr_table_lsn),
		       le32_to_cpu(env->restart.open_attr_len));
		err = ntfs_log_read_client_record(vol->logfile_ino, &env->layout,
				le64_to_cpu(env->restart.open_attr_table_lsn),
				&hdr, &payload, &payload_len);
		if (err) {
			return err;
		}

		err = ntfs_log_checkpoint_dump_data(&hdr, payload, payload_len,
				OpenAttributeTableDump,
				le32_to_cpu(env->restart.open_attr_len),
				&dump, &dump_len);
		if (err) {
			ntfs_log_dump_lfs_record("open-attr invalid log record lfs", &hdr,
					payload_len);
			goto out;
		}

		err = ntfs_redo_apply_open_attr_dump(env, dump, dump_len);
		if (err) {
			goto out;
		}

		kfree(payload);
		payload = NULL;
	}

	if (le32_to_cpu(env->restart.attr_names_len) &&
	    le64_to_cpu(env->restart.attr_names_lsn)) {
		ntfs_debug("ntfs: %s: read attr-names table lsn=%llu len=%u\n",
		       __func__,
		       (unsigned long long)le64_to_cpu(env->restart.attr_names_lsn),
		       le32_to_cpu(env->restart.attr_names_len));
		err = ntfs_log_read_client_record(vol->logfile_ino, &env->layout,
				le64_to_cpu(env->restart.attr_names_lsn),
				&hdr, &payload, &payload_len);
		if (err) {
			return err;
		}

		err = ntfs_log_checkpoint_dump_data(&hdr, payload, payload_len,
				AttributeNamesDump,
				le32_to_cpu(env->restart.attr_names_len),
				&dump, &dump_len);
		if (err) {
			ntfs_log_dump_lfs_record("attr-names invalid log record lfs", &hdr,
					payload_len);
			goto out;
		}

		err = ntfs_redo_apply_attr_names_dump(env, dump, dump_len);
		if (err) {
			goto out;
		}
	}

	err = 0;
out:
	kfree(payload);
	return err;
}

/* Walk log records in LSN order and hand each decoded record to the selected pass. */
static int ntfs_redo_walk_log(struct ntfs_volume *vol,
		struct ntfs_redo_env *env, u64 start_lsn,
		ntfs_redo_walk_fn fn)
{
	struct ntfs_lfs_record_hdr hdr;
	struct ntfs_log_rec_hdr *lrh;
	void *payload = NULL;
	u32 payload_len = 0;
	u64 lsn = start_lsn;
	u64 next_lsn;
	int err;

	if (!lsn)
		return 0;

	ntfs_debug("ntfs: %s: start_lsn=%llu current_lsn=%llu oldest_lsn=%llu fn=%ps\n",
	       __func__, (unsigned long long)start_lsn,
	       (unsigned long long)env->layout.current_lsn,
	       (unsigned long long)env->layout.oldest_lsn, fn);
	while (lsn && lsn <= env->layout.current_lsn) {
		err = ntfs_log_read_client_record(vol->logfile_ino, &env->layout, lsn,
				&hdr, &payload, &payload_len);
		if (err) {
			pr_err("ntfs: %s: read client record failed lsn=%llu current_lsn=%llu oldest_lsn=%llu fn=%ps err=%d\n",
			       __func__, (unsigned long long)lsn,
			       (unsigned long long)env->layout.current_lsn,
			       (unsigned long long)env->layout.oldest_lsn, fn, err);
			goto out;
		}
		ntfs_log_debug_lfs_record("redo-walk lfs", &hdr, payload_len);

		if (hdr.record_type == LFS_CLIENT_RECORD) {
			if (payload_len < sizeof(*lrh)) {
				err = -EINVAL;
				ntfs_log_dump_lfs_record("redo-walk short payload", &hdr,
						payload_len);
				goto out;
			}

			lrh = payload;
			if (!ntfs_log_validate_record(lrh, payload_len,
					le32_to_cpu(hdr.transact_id), hdr.flags)) {
				err = -EINVAL;
				ntfs_log_dump_lfs_record("redo-walk invalid log record lfs",
						&hdr, payload_len);
				ntfs_log_dump_redo_record("redo-walk invalid log record",
						&hdr, lrh, payload_len);
				goto out;
			}
			ntfs_log_debug_redo_record("redo-walk record", &hdr, lrh,
					payload_len);

			/* Stop immediately on the first decode/apply failure to avoid replaying on bad state. */
			err = fn(vol, env, &hdr, lrh, payload_len);
			if (err) {
				pr_err("ntfs: %s: walk callback failed lsn=%llu fn=%ps err=%d\n",
				       __func__,
				       (unsigned long long)le64_to_cpu(hdr.this_lsn),
				       fn, err);
				ntfs_log_dump_redo_record("failed replay record",
						&hdr, lrh, payload_len);
				goto out;
			}
		}

		err = ntfs_log_next_lsn(vol->logfile_ino, &env->layout, lsn,
				&hdr, &next_lsn);
		if (err) {
			pr_err("ntfs: %s: next lsn failed lsn=%llu fn=%ps err=%d\n",
			       __func__, (unsigned long long)lsn, fn, err);
			goto out;
		}

		kfree(payload);
		payload = NULL;
		if (!next_lsn)
			break;
		lsn = next_lsn;
	}

	err = 0;
out:
	kfree(payload);
	ntfs_debug("ntfs: %s: done start_lsn=%llu last_lsn=%llu fn=%ps err=%d\n",
	       __func__, (unsigned long long)start_lsn,
	       (unsigned long long)lsn, fn, err);
	return err;
}

static bool ntfs_redo_needs_fn_sync(u16 op,
		const struct ntfs_log_rec_hdr *lrh)
{
	return op == SetNewAttributeSizes ||
		(op == UpdateResidentValue && lrh->redo_len != lrh->undo_len);
}

static int ntfs_redo_note_fn_sync(struct ntfs_volume *vol,
		struct ntfs_redo_env *env, const struct ntfs_log_rec_hdr *lrh);

/* Prepass rebuilds replay state and collects possible stale filename copies. */
static int ntfs_redo_prepass_record(struct ntfs_volume *vol,
		struct ntfs_redo_env *env,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh,
		u32 rec_len)
{
	u16 redo_op = le16_to_cpu(lrh->redo_op);
	u16 undo_op = le16_to_cpu(lrh->undo_op);
	int err;

	if (hdr->record_type != LFS_CLIENT_RECORD)
		return 0;
	if (le16_to_cpu(lrh->target_attr) &&
	    (le16_to_cpu(lrh->target_attr) <
		    sizeof(struct ntfs_log_restart_table) ||
	     (le16_to_cpu(lrh->target_attr) -
		    sizeof(struct ntfs_log_restart_table)) %
		    env->open_attr_entry_size)) {
		return -EINVAL;
	}

	/* Stop the whole replay before redo writes anything to disk. */
	if (!ntfs_log_action_supported(redo_op) ||
	    !ntfs_log_action_supported(undo_op)) {
		ntfs_error(vol->sb,
			"LogFile operation redo=0x%x undo=0x%x is not supported.",
			redo_op, undo_op);
		return -EOPNOTSUPP;
	}
	/* Checkpoint dump records do not belong to their carrier slot. */
	if (redo_op == OpenAttributeTableDump ||
	    redo_op == AttributeNamesDump ||
	    redo_op == DirtyPageTableDump ||
	    redo_op == TransactionTableDump)
		return 0;

	/*
	 * The MFT update may already be on disk even when its filename copy is
	 * stale.  Collect it before dirty-page/LSN filtering in the redo pass.
	 */
	if (le16_to_cpu(lrh->lcns_follow) &&
	    ntfs_redo_needs_fn_sync(redo_op, lrh)) {
		err = ntfs_redo_note_fn_sync(vol, env, lrh);
		if (err)
			return err;
	}

	err = ntfs_redo_track_transaction(env, hdr, lrh);
	if (err) {
		return err;
	}

	if (redo_op == OpenNonresidentAttribute)
		return ntfs_redo_open_nonresident_attr(env, lrh, rec_len);
	if (redo_op == DeleteDirtyClusters)
		return ntfs_redo_apply_delete_dirty_clusters(env, lrh, rec_len);
	if (redo_op == HotFix)
		return ntfs_redo_apply_hotfix(env, lrh);

	if (!ntfs_redo_skip_action(redo_op))
		return ntfs_redo_track_dirty_page(vol, env, hdr, lrh);

	return 0;
}

static int ntfs_redo_validate_record(struct ntfs_volume *vol,
		struct ntfs_redo_env *env,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh,
		u32 rec_len)
{
	const struct ntfs_redo_dirty_page *dirty_page;
	u32 lcns_follow = le16_to_cpu(lrh->lcns_follow);
	u64 target_vcn = le64_to_cpu(lrh->target_vcn);
	u64 index;
	u16 redo_op = le16_to_cpu(lrh->redo_op);
	u16 undo_op = le16_to_cpu(lrh->undo_op);

	if (!ntfs_log_action_supported(redo_op) ||
	    !ntfs_log_action_supported(undo_op)) {
		ntfs_error(vol->sb,
			"LogFile operation redo=0x%x undo=0x%x is not supported.",
			redo_op, undo_op);
		return -EOPNOTSUPP;
	}

	if (!lcns_follow || ntfs_redo_skip_action(redo_op))
		return 0;

	dirty_page = ntfs_redo_find_dirty_page(env,
			le16_to_cpu(lrh->target_attr), target_vcn, lcns_follow);
	if (!dirty_page ||
	    le64_to_cpu(hdr->this_lsn) < dirty_page->oldest_lsn)
		return 0;

	index = target_vcn - dirty_page->vcn;
	if (index > dirty_page->lcns_follow ||
	    lcns_follow > dirty_page->lcns_follow - index) {
		return -EINVAL;
	}

	return 0;
}

/* Zero the exact tail range at the end of an MFT record, matching Win10Action37. */
static int ntfs_redo_apply_zero_end_of_file_record(struct ntfs_volume *vol,
		const struct ntfs_log_rec_hdr *lrh, u64 replay_lsn, u16 data_len)
{
	struct inode *vi;
	struct mft_record *mrec;
	u64 mft_no;
	u16 zero_off;
	int err;

	if (!data_len)
		return 0;

	mft_no = ntfs_redo_stream_base_pos(vol, lrh) >>
		vol->mft_record_size_bits;
	zero_off = le16_to_cpu(lrh->record_off) + le16_to_cpu(lrh->attr_off);
	/* This operation is only valid when the redo length exactly reaches record end. */
	if (zero_off >= vol->mft_record_size ||
	    data_len != vol->mft_record_size - zero_off)
		return -EINVAL;

	vi = ntfs_iget(vol->sb, mft_no);
	if (IS_ERR(vi))
		return PTR_ERR(vi);

	mrec = map_mft_record(NTFS_I(vi));
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out_iput;
	}
	if (replay_lsn && replay_lsn <= le64_to_cpu(mrec->lsn)) {
		err = 0;
		goto out_unmap;
	}
	if (replay_lsn)
		mrec->lsn = cpu_to_le64(replay_lsn);

	memset((u8 *)mrec + zero_off, 0, data_len);
	err = ntfs_prepare_mft_record_write(NTFS_I(vi));
	if (err)
		goto out_unmap;

	mark_mft_record_dirty(NTFS_I(vi));
	err = write_mft_record(NTFS_I(vi), mrec, 1);
out_unmap:
	unmap_mft_record(NTFS_I(vi));
out_iput:
	iput(vi);
	return err;
}


static int ntfs_redo_apply_mft_record(struct ntfs_volume *vol,
		const struct ntfs_redo_open_attr *entry,
		const struct ntfs_log_rec_hdr *lrh, u16 op, u64 replay_lsn,
		u64 current_lsn, u32 rec_len, u16 data_off, u16 data_len)
{
	const u8 *data;
	const struct attr_record *new_attr;
	struct ntfs_inode *ni;
	struct inode *vi;
	struct mft_record *mrec;
	struct attr_record *attr;
	u64 mft_no;
	u32 used;
	u32 attr_len;
	u32 new_len;
	u16 record_off = le16_to_cpu(lrh->record_off);
	u16 attr_off = le16_to_cpu(lrh->attr_off);
	u16 instance;
	bool not_inline;
	int err;

	if (data_off > rec_len)
		return -EINVAL;
	/*
	 * A not-inline payload has no data bytes after the header: data_len is
	 * the nominal region size only.  This reaches the MFT-record path solely
	 * for UpdateResidentValue (the dispatcher drops the other not-inline
	 * ops), which zero-fills the region rather than copying.  @data must not
	 * be dereferenced in that case.
	 */
	not_inline = data_len > rec_len - data_off;
	data = not_inline ? NULL : (const u8 *)lrh + data_off;
	mft_no = ntfs_redo_stream_base_pos(vol, lrh) >>
		vol->mft_record_size_bits;

	ni = ntfs_redo_get_mft_record_inode(vol, mft_no, &vi);
	if (IS_ERR(ni))
		return PTR_ERR(ni);

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		/*
		 * Deallocating a record that cannot be mapped is a no-op: a
		 * record with no FILE magic (for example one whose allocating
		 * InitializeFileRecordSegment landed in a torn log tail and was
		 * never made durable) is already not in use, so undoing its
		 * allocation has nothing to do.  Treat it as success so the undo
		 * chain of the incomplete transaction can finish instead of
		 * aborting the whole replay.
		 */
		if (op == DeallocateFileRecordSegment)
			err = 0;
		goto out_iput;
	}

	/*
	 * A record with no FILE magic was never durably initialised -- its
	 * allocating InitializeFileRecordSegment landed in a torn log tail and
	 * was never made durable, so the record is still all zeroes on disk.
	 * Undoing its allocation has nothing to do: it is already free.  During
	 * the undo pass NVolReplaying() is set, so map_mft_record() accepts such
	 * a record leniently (see map_mft_record_folio()) rather than failing,
	 * which means the map-failure no-op above no longer catches this case.
	 * Skip the deallocation here instead of stamping a bogus sequence number
	 * into an otherwise-zero record and writing it back.
	 */
	if (op == DeallocateFileRecordSegment &&
	    !ntfs_is_file_record(mrec->magic)) {
		err = 0;
		goto out_unmap;
	}

	if (op != InitializeFileRecordSegment &&
	    op != DeallocateFileRecordSegment &&
	    ntfs_mft_record_check(vol, mrec, mft_no)) {
		err = -EINVAL;
		goto out_unmap;
	}
	/*
	 * Newly allocated MFT clusters can still contain an earlier volume's
	 * records or arbitrary file data.  Such bytes are not a newer home
	 * image: WAL forbids a valid record LSN beyond the durable log tail.
	 * In particular, do not let their bogus LSN suppress initialization.
	 */
	if (replay_lsn && ntfs_is_file_record(mrec->magic) &&
	    le64_to_cpu(mrec->lsn) <= current_lsn) {
		u64 home_lsn = le64_to_cpu(mrec->lsn);

		/*
		 * CreateAttribute records may be folded into a new record's
		 * initializer without advancing its LSN.  The shared MFT folio
		 * can still contain the earlier, empty image at that same LSN.
		 */
		if (replay_lsn < home_lsn ||
		    (replay_lsn == home_lsn &&
		     (op != InitializeFileRecordSegment ||
		      le16_to_cpu(lrh->undo_op) !=
					DeallocateFileRecordSegment))) {
			err = 0;
			goto out_unmap;
		}
	}

	used = le32_to_cpu(mrec->bytes_in_use);
	switch (op) {
	case InitializeFileRecordSegment:
		if (record_off > vol->mft_record_size ||
		    data_len > vol->mft_record_size - record_off) {
			err = -EINVAL;
			goto out_unmap;
		}
		memcpy((u8 *)mrec + record_off, data, data_len);
		break;

	case DeallocateFileRecordSegment:
		if (!(mrec->flags & MFT_RECORD_IN_USE))
			break;
		mrec->flags &= ~MFT_RECORD_IN_USE;
		le16_add_cpu(&mrec->sequence_number, 1);
		if (!mrec->sequence_number)
			mrec->sequence_number = cpu_to_le16(1);
		break;

	case WriteEndOfFileRecordSegment:
		if (record_off > vol->mft_record_size ||
		    data_len > vol->mft_record_size - record_off) {
			err = -EINVAL;
			goto out_unmap;
		}
		err = ntfs_redo_record_attr_at(mrec, record_off, true, &attr);
		if (err) {
			goto out_unmap;
		}
		memcpy((u8 *)mrec + record_off, data, data_len);
		mrec->bytes_in_use = cpu_to_le32(ALIGN(record_off + data_len, 8));
		break;

	case CreateAttribute:
		if (data_len < offsetof(struct attr_record, data.resident) +
				sizeof(new_attr->data.resident)) {
			err = -EINVAL;
			goto out_unmap;
		}
		new_attr = (const struct attr_record *)data;
		attr_len = le32_to_cpu(new_attr->length);
		err = ntfs_redo_record_attr_at(mrec, record_off, true, &attr);
		if (err) {
			goto out_unmap;
		}
		if (!IS_ALIGNED(attr_len, 8) || attr_len > data_len ||
		    record_off > used || attr_len > vol->mft_record_size - used) {
			err = -EINVAL;
			goto out_unmap;
		}
		memmove((u8 *)mrec + record_off + attr_len,
			(u8 *)mrec + record_off, used - record_off);
		memcpy((u8 *)mrec + record_off, new_attr, attr_len);
		mrec->bytes_in_use = cpu_to_le32(used + attr_len);
		instance = le16_to_cpu(new_attr->instance);
		if (le16_to_cpu(mrec->next_attr_instance) <= instance)
			mrec->next_attr_instance = cpu_to_le16(instance + 1);
		if (!new_attr->non_resident &&
		    new_attr->data.resident.flags & RESIDENT_ATTR_IS_INDEXED)
			le16_add_cpu(&mrec->link_count, 1);
		break;

	case DeleteAttribute:
		/*
		 * For structural MFT-record ops the log record's open attribute
		 * is the $MFT $DATA container that anchors dirty-page tracking,
		 * not the attribute being deleted, so do not type-check against
		 * it -- record_off alone identifies the target attribute.
		 */
		err = ntfs_redo_locate_attr(mrec, NULL, record_off, &attr);
		if (err) {
			/*
			 * No valid attribute at @record_off means the on-disk
			 * record already reflects the deletion (or a later state
			 * that superseded it).  Redo must be idempotent:
			 * re-deleting an already-absent attribute is a no-op,
			 * not a reason to abort the whole replay.
			 */
			if (err == -EINVAL)
				err = 0;
			goto out_unmap;
		}
		attr_len = le32_to_cpu(attr->length);
		if (record_off > used || attr_len > used - record_off) {
			err = -EINVAL;
			goto out_unmap;
		}
		if (!attr->non_resident &&
		    attr->data.resident.flags & RESIDENT_ATTR_IS_INDEXED)
			le16_add_cpu(&mrec->link_count, -1);
		memmove(attr, (u8 *)attr + attr_len,
			used - record_off - attr_len);
		mrec->bytes_in_use = cpu_to_le32(used - attr_len);
		break;

	case UpdateResidentValue:
		/*
		 * As for DeleteAttribute, the open attribute here is the $MFT
		 * $DATA container, not the resident attribute being updated
		 * (which may be $STANDARD_INFORMATION, $FILE_NAME, ...).  Locate
		 * the target by record_off only, without a type check.
		 */
		err = ntfs_redo_locate_attr(mrec, NULL, record_off, &attr);
		if (err) {
			goto out_unmap;
		}
		if (attr->non_resident || attr_off <
		    le16_to_cpu(attr->data.resident.value_offset)) {
			err = -EINVAL;
			goto out_unmap;
		}
		attr_len = le32_to_cpu(attr->length);
		new_len = ALIGN(attr_off + data_len, 8);
		if (le16_to_cpu(lrh->redo_len) == le16_to_cpu(lrh->undo_len)) {
			if (attr_off + data_len > attr_len) {
				err = -EINVAL;
				goto out_unmap;
			}
		} else {
			err = ntfs_attr_record_resize(mrec, attr, new_len);
			if (err) {
				goto out_unmap;
			}
		}
		/*
		 * For a not-inline redo the log holds no data: the attribute was
		 * grown to hold contents that had not been written before the
		 * crash, so the recovered region is zero.  Inline redos copy the
		 * logged bytes as usual.
		 */
		if (not_inline)
			memset((u8 *)attr + attr_off, 0, data_len);
		else
			memmove((u8 *)attr + attr_off, data, data_len);
		/*
		 * Only a resizing update (redo_len != undo_len) changes the
		 * resident value's length.  A pure in-place overwrite
		 * (redo_len == undo_len) must keep value_length: recomputing
		 * it from this write's end offset would truncate the value
		 * whenever the update touches a byte before the end.  A directory
		 * index $BITMAP is updated one byte at a time. If the last such
		 * byte sits before the end, the bitmap would shrink and become
		 * too small for its (larger) index allocation, breaking directory
		 * lookups after replay ("Index bitmap too small ...").
		 */
		if (le16_to_cpu(lrh->redo_len) != le16_to_cpu(lrh->undo_len))
			attr->data.resident.value_length =
				cpu_to_le32(attr_off + data_len -
				    le16_to_cpu(attr->data.resident.value_offset));
		break;

	default:
		err = -EINVAL;
		goto out_unmap;
	}

	if (replay_lsn)
		mrec->lsn = cpu_to_le64(replay_lsn);

	err = ntfs_prepare_mft_record_write(ni);
	if (err) {
		goto out_unmap;
	}

	mark_mft_record_dirty(ni);
	err = write_mft_record(ni, mrec, 1);
out_unmap:
	unmap_mft_record(ni);
out_iput:
	if (vi)
		iput(vi);
	else
		ntfs_clear_extent_inode(ni);
	return err;
}

/*
 * Remember an MFT record whose attribute sizes may need a $FILE_NAME refresh.
 *
 * $FILE_NAME keeps a copy of the unnamed $DATA sizes so a directory listing does
 * not have to open every file record.  Windows does not refresh that copy inside
 * the transaction that resizes the attribute. It emits UpdateFileNameAllocation
 * in a later one, typically when the file is closed.  A crash between the two
 * leaves the copy stale, and replaying the log faithfully reproduces that state
 * because the refresh was never logged.  Collect the records here and fix their
 * $FILE_NAME copies once recovery has settled.  A resident update targets the
 * $MFT stream rather than the individual attribute, so conservatively collect
 * all resident resizes.
 */
static int ntfs_redo_note_fn_sync(struct ntfs_volume *vol,
		struct ntfs_redo_env *env, const struct ntfs_log_rec_hdr *lrh)
{
	struct ntfs_redo_fn_sync *node;
	struct rb_node **link, *parent = NULL;
	u64 mft_no;

	if (!env || !env->fn_sync)
		return -EINVAL;

	mft_no = ntfs_redo_stream_base_pos(vol, lrh) >> vol->mft_record_size_bits;
	if (mft_no < FILE_first_user)
		return 0;

	link = &env->fn_sync->rb_node;
	while (*link) {
		parent = *link;
		node = rb_entry(parent, struct ntfs_redo_fn_sync, node);
		if (mft_no < node->mft_no)
			link = &parent->rb_left;
		else if (mft_no > node->mft_no)
			link = &parent->rb_right;
		else
			return 0;
	}

	node = kmalloc(sizeof(*node), GFP_NOFS);
	if (!node) {
		ntfs_warning(vol->sb,
			"Failed to queue filename recovery for MFT record %llu.",
			(unsigned long long)mft_no);
		return -ENOMEM;
	}

	node->mft_no = mft_no;
	rb_link_node(&node->node, parent, link);
	rb_insert_color(&node->node, env->fn_sync);
	return 0;
}

/* A resized DATA attribute may live in an extent. Filenames belong to its base. */
static struct inode *ntfs_redo_filename_inode(struct ntfs_volume *vol,
		u64 mft_no)
{
	struct ntfs_inode *ni;
	struct mft_record *mrec;
	struct inode *vi;
	__le64 reference = 0;
	bool is_extent = false;
	int err = 0;

	/* Recovery may have rolled back MFT growth that contained this record. */
	if (mft_no >= ((u64)i_size_read(vol->mft_ino) >>
			vol->mft_record_size_bits))
		return ERR_PTR(-ENOENT);

	ni = ntfs_redo_get_mft_record_inode(vol, mft_no, &vi);
	if (IS_ERR(ni))
		return ERR_CAST(ni);
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out_put;
	}
	if (!(mrec->flags & MFT_RECORD_IN_USE) ||
	    (!mrec->base_mft_record && !mrec->link_count)) {
		err = -ENOENT;
	} else {
		is_extent = !!mrec->base_mft_record;
		reference = mrec->base_mft_record ? mrec->base_mft_record :
			MK_LE_MREF(mft_no, le16_to_cpu(mrec->sequence_number));
	}
	unmap_mft_record(ni);
out_put:
	if (vi)
		iput(vi);
	else
		ntfs_clear_extent_inode(ni);
	if (err)
		return ERR_PTR(err);

	/* An extent can outlive its last filename together with its base. */
	if (is_extent) {
		ni = ntfs_redo_get_mft_record_inode(vol, MREF_LE(reference), &vi);
		if (IS_ERR(ni))
			return ERR_CAST(ni);
		mrec = map_mft_record(ni);
		if (IS_ERR(mrec)) {
			err = PTR_ERR(mrec);
		} else {
			if (!(mrec->flags & MFT_RECORD_IN_USE) ||
			    !mrec->link_count)
				err = -ENOENT;
			else if (mrec->base_mft_record ||
				 le16_to_cpu(mrec->sequence_number) !=
					MSEQNO_LE(reference))
				err = -EIO;
			unmap_mft_record(ni);
		}
		if (vi)
			iput(vi);
		else
			ntfs_clear_extent_inode(ni);
		if (err)
			return ERR_PTR(err);
	}

	vi = ntfs_iget(vol->sb, MREF_LE(reference));
	if (IS_ERR(vi))
		return vi;
	if (NTFS_I(vi)->seq_no != MSEQNO_LE(reference)) {
		iput(vi);
		return ERR_PTR(-EIO);
	}
	return vi;
}

/*
 * Refresh the $FILE_NAME size copies of every record collected above.
 *
 * Runs after undo, so the sizes it propagates are the ones recovery settled on
 * rather than an intermediate value redo happened to write.  Failures here only
 * leave the copy stale, which fsck repairs, so none of them abort the mount.
 */
static void ntfs_redo_sync_file_names(struct ntfs_volume *vol,
		struct rb_root *fn_sync)
{
	struct ntfs_redo_fn_sync *node;
	struct rb_node *rb;
	struct mft_record *mrec;
	struct ntfs_inode *ni;
	struct inode *vi;

	for (rb = rb_first(fn_sync); rb; rb = rb_next(rb)) {
		node = rb_entry(rb, struct ntfs_redo_fn_sync, node);
		vi = ntfs_redo_filename_inode(vol, node->mft_no);
		if (IS_ERR(vi)) {
			if (PTR_ERR(vi) != -ENOENT)
				ntfs_warning(vol->sb,
					"Failed to resolve filename base for replayed inode %llu (error %ld).",
					(unsigned long long)node->mft_no,
					PTR_ERR(vi));
			continue;
		}
		if (is_bad_inode(vi)) {
			iput(vi);
			continue;
		}

		ni = NTFS_I(vi);
		if (ntfs_inode_sync_filename(ni)) {
			iput(vi);
			continue;
		}

		/*
		 * The index copies were written by the sync above, but the
		 * $FILE_NAME inside this record is only marked dirty.  The mount
		 * has not set SB_ACTIVE yet, so iput() may evict the inode
		 * without writing it. Commit the record here instead.
		 */
		mrec = map_mft_record(ni);
		if (!IS_ERR(mrec)) {
			if (!ntfs_prepare_mft_record_write(ni)) {
				mark_mft_record_dirty(ni);
				write_mft_record(ni, mrec, 1);
			}
			unmap_mft_record(ni);
		}
		iput(vi);
	}
}

static void ntfs_redo_free_fn_sync(struct rb_root *fn_sync)
{
	struct ntfs_redo_fn_sync *node;
	struct rb_node *rb;

	while ((rb = rb_first(fn_sync))) {
		node = rb_entry(rb, struct ntfs_redo_fn_sync, node);
		rb_erase(rb, fn_sync);
		kfree(node);
	}
}

/* Dispatch one redo opcode to the helper that mutates the referenced metadata. */
static int ntfs_redo_apply_record(struct ntfs_volume *vol,
		struct ntfs_redo_env *env,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh,
		u32 rec_len)
{
	const struct ntfs_redo_dirty_page *dirty_page;
	const struct ntfs_redo_open_attr *entry;
	u32 data_len;
	u32 original_len;
	u32 value_off;
	u32 i;
	u64 lsn;
	u16 op;
	int err;

	if (hdr->record_type != LFS_CLIENT_RECORD)
		return 0;

	op = le16_to_cpu(lrh->redo_op);
	lsn = le64_to_cpu(hdr->this_lsn);
	entry = ntfs_redo_find_open_attr(env, le16_to_cpu(lrh->target_attr));
	ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_REDO, op,
			NTFS_LOG_REPLAY_SEEN, 0);

	/* Marker and dump records have already been handled during analysis/prepass. */
	if (ntfs_redo_skip_action(op)) {
		ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_REDO, op,
				NTFS_LOG_REPLAY_SKIP_ACTION, 0);
		return 0;
	}

	/*
	 * Redo only pages that were dirty at the checkpoint.  Reapplying records
	 * for pages absent from the dirty-page table can overwrite newer metadata
	 * that reached disk before the crash.
	 */
	if (!le16_to_cpu(lrh->lcns_follow)) {
		ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_REDO, op,
				NTFS_LOG_REPLAY_SKIP_NO_LCNS, 0);
		return 0;
	}
	if (ntfs_redo_needs_fn_sync(op, lrh)) {
		err = ntfs_redo_note_fn_sync(vol, env, lrh);
		if (err)
			return ntfs_log_replay_dispatch_result(vol, hdr,
					NTFS_LOG_REPLAY_REDO, op, err);
	}
	dirty_page = ntfs_redo_find_dirty_page(env,
			le16_to_cpu(lrh->target_attr),
			le64_to_cpu(lrh->target_vcn),
			le16_to_cpu(lrh->lcns_follow));
	if (!dirty_page) {
		ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_REDO, op,
				NTFS_LOG_REPLAY_SKIP_DIRTY_PAGE, 0);
		return 0;
	}
	/*
	 * The dirty-page table's oldest LSN normally lets us skip records whose
	 * effect already reached disk.  InitializeFileRecordSegment is special:
	 * it (re)establishes the whole baseline of an MFT record, so a later
	 * incremental update to the same record cannot be applied unless the
	 * initializing record was replayed first.  When a page was newly
	 * allocated mid-transaction its on-disk image can still be zero even
	 * though the dirty-page entry advanced past the initialize, so always
	 * replay the initialize and rely on the per-record on-disk LSN check in
	 * ntfs_redo_apply_mft_record() to avoid clobbering newer data.
	 */
	if (lsn < dirty_page->oldest_lsn &&
	    op != InitializeFileRecordSegment) {
		ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_REDO, op,
				NTFS_LOG_REPLAY_SKIP_OLD_LSN, 0);
		return 0;
	}

	data_len = original_len = le16_to_cpu(lrh->redo_len);
	value_off = le16_to_cpu(lrh->record_off) +
		le16_to_cpu(lrh->attr_off) +
		((u32)le16_to_cpu(lrh->cluster_off) << NTFS_BLOCK_SIZE_BITS);
	for (i = le16_to_cpu(lrh->lcns_follow); i; i--) {
		u64 index = le64_to_cpu(lrh->target_vcn) - dirty_page->vcn;
		u32 allocated;

		if (dirty_page->page_lcns[index + i - 1])
			break;
		allocated = (i - 1) << vol->cluster_size_bits;
		if (value_off >= allocated)
			data_len = 0;
		else if (value_off + data_len > allocated)
			data_len = allocated - value_off;
	}
	if (!data_len && original_len) {
		ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_REDO, op,
				NTFS_LOG_REPLAY_SKIP_DIRTY_PAGE, 0);
		return 0;
	}

	/*
	 * A not-inline redo payload carries no data bytes in the log: when
	 * redo_off + redo_len overruns the client data length, redo_len is only
	 * the nominal size of the affected region and the bytes are absent
	 * because the operation defines them implicitly.  Two ops must still run
	 * in that case because their effect is defined without logged data:
	 *
	 *  - UpdateResidentValue grows a resident attribute to redo_len whose
	 *    contents had not been written when the volume crashed, so the helper
	 *    zero-fills the region to reach the recorded length.
	 *  - ZeroEndOfFileRecord clears [record_off .. end of MFT record] to zero.
	 *    Its handler memsets the region and needs no logged bytes.  Windows
	 *    (and ntfs3) apply it. Dropping it here left stale bytes in the MFT
	 *    record slack, diverging from the reference implementations.
	 *
	 * All other not-inline ops have nothing to apply and are no-ops here.
	 * Records with redo_len == 0 (e.g. DeleteAttribute) never reach this test.
	 */
	if ((u32)le16_to_cpu(lrh->redo_off) + original_len > rec_len &&
	    op != UpdateResidentValue && op != ZeroEndOfFileRecord) {
		ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_REDO, op,
				NTFS_LOG_REPLAY_SKIP_ACTION, 0);
		return 0;
	}

	switch (op) {
	case InitializeFileRecordSegment:
	case DeallocateFileRecordSegment:
	case WriteEndOfFileRecordSegment:
	case CreateAttribute:
	case DeleteAttribute:
	case UpdateResidentValue:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_mft_record(vol, entry, lrh, op, lsn,
				env->layout.current_lsn, rec_len, le16_to_cpu(lrh->redo_off),
				data_len));
	case AddIndexEntryRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_add_index_entry_root(vol, lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case DeleteIndexEntryRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_delete_index_entry_root(vol, lrh, lsn));
	case SetIndexEntryVcnRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_set_index_entry_vcn_root(vol, lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case UpdateFileNameRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_update_file_name_root(vol, lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case UpdateRecordDataRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_update_record_data_root(vol, lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case UpdateNonresidentValue:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_nonresident_value(vol, entry, lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case AddIndexEntryAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_add_index_entry_allocation(vol, entry, lrh,
				lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case DeleteIndexEntryAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_delete_index_entry_allocation(vol, entry,
				lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case WriteEndOfIndexBuffer:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_write_end_of_index_buffer(vol, entry, lrh,
				lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case UpdateMappingPairs:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_mapping_pairs(vol, entry, lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case SetNewAttributeSizes:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_set_new_sizes(vol, entry, lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case SetIndexEntryVcnAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_set_index_entry_vcn_allocation(vol, entry,
				lrh, lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case UpdateFileNameAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_update_file_name_allocation(vol, entry, lrh,
				lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case SetBitsInNonresidentBitMap:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_bitmap_range(vol, entry, lrh, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len, true));
	case ClearBitsInNonresidentBitMap:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_bitmap_range(vol, entry, lrh, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len, false));
	case UpdateRecordDataAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_update_record_data_allocation(vol, entry, lrh,
				lsn, rec_len,
				le16_to_cpu(lrh->redo_off),
				data_len));
	case ZeroEndOfFileRecord:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_REDO, op,
				ntfs_redo_apply_zero_end_of_file_record(vol, lrh, lsn,
				data_len));
	}

	ntfs_error(vol->sb,
		"LogFile redo opcode 0x%x is not supported by fs/ntfs replay path.",
		op);
	ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_REDO, op,
			NTFS_LOG_REPLAY_FAILED, -EOPNOTSUPP);
	return -EOPNOTSUPP;
}

/* Dispatch one undo opcode to the helper that rolls an active transaction back. */
static int ntfs_undo_apply_record(struct ntfs_volume *vol,
		struct ntfs_redo_env *env,
		const struct ntfs_lfs_record_hdr *hdr,
		const struct ntfs_log_rec_hdr *lrh,
		u32 rec_len)
{
	const struct ntfs_redo_open_attr *entry;
	u16 op;
	int err;

	if (hdr->record_type != LFS_CLIENT_RECORD)
		return 0;

	op = le16_to_cpu(lrh->undo_op);
	entry = ntfs_redo_find_open_attr(env, le16_to_cpu(lrh->target_attr));
	ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_UNDO, op,
			NTFS_LOG_REPLAY_SEEN, 0);

	if (ntfs_redo_skip_action(op)) {
		ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_UNDO, op,
				NTFS_LOG_REPLAY_SKIP_ACTION, 0);
		return 0;
	}

	if (ntfs_redo_needs_fn_sync(op, lrh)) {
		err = ntfs_redo_note_fn_sync(vol, env, lrh);
		if (err)
			return ntfs_log_replay_dispatch_result(vol, hdr,
					NTFS_LOG_REPLAY_UNDO, op, err);
	}

	switch (op) {
	case InitializeFileRecordSegment:
	case DeallocateFileRecordSegment:
	case WriteEndOfFileRecordSegment:
	case CreateAttribute:
	case DeleteAttribute:
	case UpdateResidentValue:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_mft_record(vol, entry, lrh, op, 0,
				env->layout.current_lsn, rec_len, le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case AddIndexEntryRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_add_index_entry_root(vol, lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case DeleteIndexEntryRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_delete_index_entry_root(vol, lrh, 0));
	case SetIndexEntryVcnRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_set_index_entry_vcn_root(vol, lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case UpdateFileNameRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_update_file_name_root(vol, lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case UpdateRecordDataRoot:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_update_record_data_root(vol, lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case UpdateNonresidentValue:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_nonresident_value(vol, entry, lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case AddIndexEntryAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_add_index_entry_allocation(vol, entry, lrh,
				0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case DeleteIndexEntryAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_delete_index_entry_allocation(vol, entry,
				lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case WriteEndOfIndexBuffer:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_write_end_of_index_buffer(vol, entry, lrh,
				0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case UpdateMappingPairs:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_mapping_pairs(vol, entry, lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case SetNewAttributeSizes:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_set_new_sizes(vol, entry, lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case SetIndexEntryVcnAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_set_index_entry_vcn_allocation(vol, entry,
				lrh, 0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case UpdateFileNameAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_update_file_name_allocation(vol, entry, lrh,
				0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case SetBitsInNonresidentBitMap:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_bitmap_range(vol, entry, lrh, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len), true));
	case ClearBitsInNonresidentBitMap:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_bitmap_range(vol, entry, lrh, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len), false));
	case UpdateRecordDataAllocation:
		return ntfs_log_replay_dispatch_result(vol, hdr,
				NTFS_LOG_REPLAY_UNDO, op,
				ntfs_redo_apply_update_record_data_allocation(vol, entry, lrh,
				0, rec_len,
				le16_to_cpu(lrh->undo_off),
				le16_to_cpu(lrh->undo_len)));
	case ZeroEndOfFileRecord:
		/* ntfs-3g treats the undo variant as a no-op, and we mirror that here. */
		ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_UNDO, op,
				NTFS_LOG_REPLAY_SKIP_ACTION, 0);
		return 0;
	}

	ntfs_error(vol->sb,
		"LogFile undo opcode 0x%x is not supported by fs/ntfs replay path.",
		op);
	ntfs_log_replay_account(vol, hdr, NTFS_LOG_REPLAY_UNDO, op,
			NTFS_LOG_REPLAY_FAILED, -EOPNOTSUPP);
	return -EOPNOTSUPP;
}

/* Apply one record from an active transaction's undo-next chain. */
static int ntfs_redo_walk_undo_chain(struct ntfs_volume *vol,
		struct ntfs_redo_env *env,
		struct ntfs_redo_transaction *tr)
{
	struct ntfs_lfs_record_hdr hdr;
	struct ntfs_log_rec_hdr *lrh;
	void *payload = NULL;
	u32 payload_len = 0;
	u64 lsn;
	u64 next_lsn;
	int err;

	if (!tr || tr->state != TransactionActive || !tr->undo_next_lsn)
		return 0;

	ntfs_debug("ntfs: %s: transaction slot=0x%x undo_start_lsn=%llu oldest_lsn=%llu current_lsn=%llu\n",
	       __func__, tr->slot, (unsigned long long)tr->undo_next_lsn,
	       (unsigned long long)env->layout.oldest_lsn,
	       (unsigned long long)env->layout.current_lsn);
	lsn = tr->undo_next_lsn;
	err = ntfs_log_read_client_record(vol->logfile_ino, &env->layout, lsn,
			&hdr, &payload, &payload_len);
	if (err) {
		pr_err("ntfs: %s: read undo record failed slot=0x%x lsn=%llu err=%d\n",
		       __func__, tr->slot, (unsigned long long)lsn, err);
		goto out;
	}
	ntfs_log_debug_lfs_record("undo-walk lfs", &hdr, payload_len);

	if (hdr.record_type != LFS_CLIENT_RECORD ||
	    le32_to_cpu(hdr.transact_id) != tr->slot ||
	    payload_len < sizeof(*lrh)) {
		err = -EINVAL;
		ntfs_log_dump_lfs_record("undo-walk invalid lfs record", &hdr,
				payload_len);
		pr_err("ntfs: %s: expected transaction slot=0x%x payload_len=%u min_payload=%zu\n",
		       __func__, tr->slot, payload_len, sizeof(*lrh));
		goto out;
	}

	lrh = payload;
	if (!ntfs_log_validate_record(lrh, payload_len,
			le32_to_cpu(hdr.transact_id), hdr.flags)) {
		err = -EINVAL;
		ntfs_log_dump_lfs_record("undo-walk invalid log record lfs", &hdr,
				payload_len);
		ntfs_log_dump_redo_record("undo-walk invalid log record", &hdr,
				lrh, payload_len);
		goto out;
	}
	ntfs_log_debug_redo_record("undo-walk record", &hdr, lrh, payload_len);

	next_lsn = le64_to_cpu(hdr.client_undo_next_lsn);
	/* Undo chains must move strictly backwards inside the replay window. */
	if (next_lsn &&
	    !ntfs_redo_undo_next_valid(&env->layout, lsn, next_lsn)) {
		err = -EINVAL;
		pr_err("ntfs: %s: invalid undo next_lsn slot=0x%x lsn=%llu next_lsn=%llu current_lsn=%llu\n",
		       __func__, tr->slot, (unsigned long long)lsn,
		       (unsigned long long)next_lsn,
		       (unsigned long long)env->layout.current_lsn);
		goto out;
	}

	err = ntfs_undo_apply_record(vol, env, &hdr, lrh, payload_len);
	if (err) {
		pr_err("ntfs: %s: undo apply failed slot=0x%x lsn=%llu err=%d\n",
		       __func__, tr->slot, (unsigned long long)lsn, err);
		goto out;
	}

	tr->undo_next_lsn = next_lsn;
	err = 0;
out:
	kfree(payload);
	ntfs_debug("ntfs: %s: done slot=0x%x last_lsn=%llu err=%d\n",
	       __func__, tr ? tr->slot : 0, (unsigned long long)lsn, err);
	return err;
}

/*
 * Interleaved transactions can change the layout of the same record.  Undo
 * their individual chains together, newest LSN first, using a max-heap.
 */
static int ntfs_redo_walk_undo_chains(struct ntfs_volume *vol,
		struct ntfs_redo_env *env)
{
	struct ntfs_redo_transaction **heap;
	struct ntfs_redo_transaction *tr, *tmp;
	size_t count = 0, pos, parent, child;
	u64 max_steps, steps = 0;
	int err = 0;

	list_for_each_entry(tr, &env->transactions, list) {
		if (tr->state == TransactionActive && tr->undo_next_lsn)
			count++;
	}
	if (!count)
		return 0;
	if (env->layout.log_size <= env->layout.first_page)
		return -EINVAL;
	max_steps = (env->layout.log_size - env->layout.first_page) >> 3;
	heap = kcalloc(count, sizeof(*heap), GFP_NOFS);
	if (!heap)
		return -ENOMEM;

	count = 0;
	list_for_each_entry(tr, &env->transactions, list) {
		if (tr->state != TransactionActive || !tr->undo_next_lsn)
			continue;
		pos = count++;
		while (pos) {
			parent = (pos - 1) / 2;
			if (heap[parent]->undo_next_lsn >= tr->undo_next_lsn)
				break;
			heap[pos] = heap[parent];
			pos = parent;
		}
		heap[pos] = tr;
	}
	while (count) {
		if (++steps > max_steps) {
			err = -ELOOP;
			break;
		}
		tr = heap[0];
		err = ntfs_redo_walk_undo_chain(vol, env, tr);
		if (err)
			break;
		if (!tr->undo_next_lsn)
			heap[0] = heap[--count];
		pos = 0;
		while (pos < count / 2) {
			child = pos * 2 + 1;
			if (child + 1 < count &&
			    heap[child + 1]->undo_next_lsn >
					heap[child]->undo_next_lsn)
				child++;
			if (heap[pos]->undo_next_lsn >=
			    heap[child]->undo_next_lsn)
				break;
			tmp = heap[pos];
			heap[pos] = heap[child];
			heap[child] = tmp;
			pos = child;
		}
	}
	kfree(heap);
	return err;
}

/*
 * Pick the LSN at which the prepass should start rebuilding dirty pages and
 * transactions.  The checkpoint's check_point_start normally points there, but
 * a checkpoint written while nothing was dirty (as a real Windows volume
 * routinely produces) leaves it zero.  In that case fall back to the LSN of the
 * checkpoint record itself: every durable record this client still cares about
 * was logged at or after it, so a scan from there sees the whole tail.
 */
static inline u64 ntfs_redo_prepass_start(const struct ntfs_redo_env *env)
{
	u64 lsn = le64_to_cpu(env->restart.check_point_start);

	return lsn ? lsn : env->checkpoint_record_lsn;
}

/*
 * Run the redo pass: reconstruct checkpoint tables, bootstrap stream metadata,
 * pre-scan OpenNonresidentAttribute, then apply records from the earliest
 * dirty-page or transaction LSN forward.
 */
static int ntfs_log_replay_run_redo(struct ntfs_volume *vol,
		const struct restart_page_header *rp,
		const struct ntfs_log_replay_ctx *ctx,
		struct rb_root *fn_sync)
{
	struct ntfs_redo_env env;
	u64 redo_start_lsn = 0;
	int err;

	if (!vol || !rp || !ctx || !ctx->analysis_ready)
		return -EINVAL;

	ntfs_debug("ntfs: %s: begin current_lsn=%llu checkpoint_lsn=%llu oldest_lsn=%llu oldest_dirty_page_lsn=%llu transaction_entries=%u dirty_page_entries=%u\n",
	       __func__, (unsigned long long)ctx->current_lsn,
	       (unsigned long long)ctx->checkpoint_lsn,
	       (unsigned long long)ctx->oldest_lsn,
	       (unsigned long long)ctx->oldest_dirty_page_lsn,
	       ctx->transaction_entries, ctx->dirty_page_entries);
	memset(&env, 0, sizeof(env));
	INIT_LIST_HEAD(&env.dirty_pages);
	INIT_LIST_HEAD(&env.open_attrs);
	INIT_LIST_HEAD(&env.transactions);
	env.ctx = ctx;
	env.fn_sync = fn_sync;

	err = ntfs_redo_load_restart(vol, rp, &env);
	if (err) {
		goto out;
	}

	err = ntfs_redo_load_transaction_table(vol, &env);
	if (err) {
		goto out;
	}

	err = ntfs_redo_load_dirty_page_table(vol, &env);
	if (err) {
		goto out;
	}

	err = ntfs_redo_bootstrap_open_attrs(vol, &env);
	if (err) {
		goto out;
	}

	err = ntfs_redo_walk_log(vol, &env, ntfs_redo_prepass_start(&env),
			ntfs_redo_prepass_record);
	if (err) {
		goto out;
	}

	/* Redo starts at the earliest metadata that could still be stale after a crash. */
	redo_start_lsn = env.dirty_pages_loaded ?
		env.oldest_dirty_page_lsn : ctx->oldest_dirty_page_lsn;
	if (!redo_start_lsn ||
	    (env.oldest_transaction_lsn && env.oldest_transaction_lsn < redo_start_lsn))
		redo_start_lsn = env.oldest_transaction_lsn;
	if (!redo_start_lsn)
		redo_start_lsn = ntfs_redo_prepass_start(&env);
	ntfs_debug("ntfs: %s: redo_start_lsn=%llu dirty_pages_loaded=%d env_oldest_dirty=%llu env_oldest_transaction=%llu checkpoint_start=%llu\n",
	       __func__, (unsigned long long)redo_start_lsn,
	       env.dirty_pages_loaded,
	       (unsigned long long)env.oldest_dirty_page_lsn,
	       (unsigned long long)env.oldest_transaction_lsn,
	       (unsigned long long)le64_to_cpu(env.restart.check_point_start));

	/* Validate the complete redo window before the first metadata write. */
	err = ntfs_redo_walk_log(vol, &env, redo_start_lsn,
			ntfs_redo_validate_record);
	if (err) {
		goto out;
	}

	/*
	 * The apply pass mutates MFT records that may be momentarily
	 * inconsistent (a half-built file with link_count 0 or no $DATA yet, a
	 * record mid-deletion, ...).  Flag the volume so ntfs_iget() does not
	 * cache such temporarily unavailable inodes or warn about them. They are
	 * re-read cleanly once replay has finished rebuilding the records.
	 */
	NVolSetReplaying(vol);
	err = ntfs_redo_walk_log(vol, &env, redo_start_lsn,
			ntfs_redo_apply_record);
	NVolClearReplaying(vol);

	/*
	 * Redo applied its writes through the block-device page cache
	 * (ntfs_bdev_write() -> sb->s_bdev->bd_mapping).  The filesystem's own
	 * data path reads via iomap/submit_bio straight from the device and
	 * bypasses that cache, so the replayed contents of freshly allocated
	 * clusters are invisible to later reads until the block-device cache is
	 * written back.  Flush it now so the on-disk state the driver reads
	 * matches what replay just produced.
	 */
	if (!err) {
		int serr = sync_blockdev(vol->sb->s_bdev);

		if (serr) {
			ntfs_error(vol->sb,
				"Failed to flush device after log replay (%d).",
				-serr);
			err = serr;
		}
	}

out:
	ntfs_redo_clear_dirty_pages(&env);
	ntfs_redo_clear_transactions(&env);
	ntfs_redo_clear_open_attrs(&env);
	ntfs_debug("ntfs: %s: done redo_start_lsn=%llu err=%d\n",
	       __func__, (unsigned long long)redo_start_lsn, err);
	return err;
}

/*
 * Run the undo pass by rebuilding the same checkpoint state and then following
 * the undo chain of every still-active transaction.
 */
static int ntfs_log_replay_run_undo(struct ntfs_volume *vol,
		const struct restart_page_header *rp,
		const struct ntfs_log_replay_ctx *ctx,
		struct rb_root *fn_sync)
{
	struct ntfs_redo_env env;
	int err;

	if (!vol || !rp || !ctx || !ctx->analysis_ready)
		return -EINVAL;

	ntfs_debug("ntfs: %s: begin current_lsn=%llu checkpoint_lsn=%llu oldest_lsn=%llu transaction_entries=%u\n",
	       __func__, (unsigned long long)ctx->current_lsn,
	       (unsigned long long)ctx->checkpoint_lsn,
	       (unsigned long long)ctx->oldest_lsn,
	       ctx->transaction_entries);
	memset(&env, 0, sizeof(env));
	INIT_LIST_HEAD(&env.dirty_pages);
	INIT_LIST_HEAD(&env.open_attrs);
	INIT_LIST_HEAD(&env.transactions);
	env.ctx = ctx;
	env.fn_sync = fn_sync;

	err = ntfs_redo_load_restart(vol, rp, &env);
	if (err) {
		goto out;
	}

	err = ntfs_redo_load_transaction_table(vol, &env);
	if (err) {
		goto out;
	}

	err = ntfs_redo_bootstrap_open_attrs(vol, &env);
	if (err) {
		goto out;
	}

	err = ntfs_redo_walk_log(vol, &env, ntfs_redo_prepass_start(&env),
			ntfs_redo_prepass_record);
	if (err) {
		goto out;
	}

	/* Prepass may discover new active transactions or close checkpoint ones. */
	if (!env.undo_needed) {
		err = 0;
		goto out;
	}

	/*
	 * Rolling an incomplete transaction back rewrites MFT records that may
	 * be momentarily inconsistent (an MFT record whose allocating
	 * InitializeFileRecordSegment landed in a torn log tail is still all
	 * zeroes when its DeallocateFileRecordSegment undo runs, a half-built
	 * file, a record mid-deletion, ...).  Flag the volume for the same
	 * reason the redo apply pass does, so ntfs_iget() does not cache such
	 * temporarily unavailable inodes and the driver does not emit
	 * "Marking corrupt inode as bad.  Run chkdsk." for what is a benign
	 * rollback.
	 */
	NVolSetReplaying(vol);
	err = ntfs_redo_walk_undo_chains(vol, &env);
	NVolClearReplaying(vol);
	/*
	 * Undo also writes index blocks through the block-device cache.  Flush
	 * those writes before filename recovery reads and updates the same
	 * blocks through the filesystem mapping, or later device writeback can
	 * overwrite the refreshed entries.
	 */
	if (!err) {
		err = sync_blockdev(vol->sb->s_bdev);
		if (err)
			ntfs_error(vol->sb, "Log undo flush failed (%d).", -err);
	}
out:
	ntfs_redo_clear_dirty_pages(&env);
	ntfs_redo_clear_transactions(&env);
	ntfs_redo_clear_open_attrs(&env);
	ntfs_debug("ntfs: %s: done undo_needed=%d err=%d\n",
	       __func__, env.undo_needed, err);
	return err;
}
/*
 * struct ntfs_log_replay_state - Small per-run progress tracker for replay
 *
 * Carries pass completion bits so the top-level driver can enforce the
 * analyze -> redo -> undo sequencing and grow a real finalize stage later.
 *
 * @ctx:                  Replay context shared across all passes in this run.
 * @analysis_done:        True once the checkpoint analysis pass completed.
 * @redo_done:            True once committed log records were replayed.
 * @undo_done:            True once incomplete transactions were rolled back.
 */
struct ntfs_log_replay_state {
	const struct ntfs_log_replay_ctx *ctx;
	bool analysis_done;
	bool redo_done;
	bool undo_done;
};

/*
 * Parse the restart page into the small context that the later passes share.
 * This is deliberately strict because every later offset and LSN trust this
 * decoded state.
 */
static int ntfs_log_replay_parse_restart(const struct restart_page_header *rp,
		const struct restart_area **ra,
		struct ntfs_log_replay_ctx *ctx)
{
	u16 ra_ofs;
	u32 sys_page_size;
	const struct restart_area *checkpoint;

	if (!rp || !ra || !ctx)
		return -EINVAL;

	if (ntfs_is_chkd_record(rp->magic)) {
		ctx->valid = true;
		ctx->is_clean = true;
		ctx->needs_replay = false;
		ctx->major_ver = le16_to_cpu(rp->major_ver);
		ctx->minor_ver = le16_to_cpu(rp->minor_ver);
		ctx->current_lsn = le64_to_cpu(rp->chkdsk_lsn);
		*ra = NULL;
		return 0;
	}

	if (!ntfs_is_rstr_record(rp->magic))
		return -EINVAL;

	sys_page_size = le32_to_cpu(rp->system_page_size);
	ra_ofs = le16_to_cpu(rp->restart_area_offset);

	if (!sys_page_size || ra_ofs >= sys_page_size)
		return -EINVAL;

	if (ra_ofs > sys_page_size - sizeof(*checkpoint))
		return -EINVAL;

	checkpoint = (const struct restart_area *)((const u8 *)rp + ra_ofs);
	*ra = checkpoint;

	ctx->major_ver = le16_to_cpu(rp->major_ver);
	ctx->minor_ver = le16_to_cpu(rp->minor_ver);
	ctx->restart_flags = le16_to_cpu(checkpoint->flags);
	ctx->client_in_use = le16_to_cpu(checkpoint->client_in_use_list);
	ctx->current_lsn = le64_to_cpu(checkpoint->current_lsn);
	ctx->oldest_lsn = 0;
	ctx->valid = true;

	if (checkpoint->client_in_use_list == LOGFILE_NO_CLIENT ||
	    (checkpoint->flags & RESTART_VOLUME_IS_CLEAN)) {
		ctx->is_clean = true;
		ctx->needs_replay = false;
	} else {
		ctx->is_clean = false;
		ctx->needs_replay = true;
	}

	return 0;
}

/*
 * Build the replay context from the restart page and also handle the trivial
 * "no restart page" and "clean volume" cases up front.
 */
static int ntfs_log_replay_prepare(const struct restart_page_header *rp,
		struct ntfs_log_replay_ctx *ctx)
{
	const struct restart_area *ra;

	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	if (!rp) {
		ctx->valid = true;
		ctx->is_clean = true;
		return 0;
	}

	return ntfs_log_replay_parse_restart(rp, &ra, ctx);
}

/*
 * Dirty-page entries tell us the earliest LSN whose contents might still need
 * redo, so keep the minimum oldest_lsn across the table.
 */
static int ntfs_parse_dirty_page_table(struct ntfs_log_restart_table *restart_table,
		u32 checkpoint_major, struct ntfs_log_replay_ctx *ctx)
{
	struct ntfs_dirty_page_entry *dirty_page = NULL;
	u16 rec_size;

	rec_size = le16_to_cpu(restart_table->size);
	if (rec_size < (checkpoint_major ? sizeof(*dirty_page) :
		    sizeof(struct ntfs_dirty_page_entry32)))
		return -EINVAL;

	while ((dirty_page = ntfs_next_restart_table_entry(restart_table, dirty_page))) {
		u64 oldest_lsn;

		if (checkpoint_major) {
			oldest_lsn = le64_to_cpu(dirty_page->oldest_lsn);
		} else {
			struct ntfs_dirty_page_entry32 *dirty_page32 =
				(void *)dirty_page;

			oldest_lsn = le32_to_cpu(dirty_page32->oldest_lsn_low) |
				((u64)le32_to_cpu(dirty_page32->oldest_lsn_high) << 32);
		}

		ctx->dirty_page_entries++;
		if (!ctx->oldest_dirty_page_lsn ||
		    oldest_lsn < ctx->oldest_dirty_page_lsn)
			ctx->oldest_dirty_page_lsn = oldest_lsn;
	}

	return 0;
}

/*
 * Extract the restart table that sits behind a log record header inside one of
 * the checkpoint dump records.
 */
static int ntfs_parse_restart_table_record(
		const struct ntfs_lfs_record_hdr *hdr, const void *payload,
		u32 payload_len, u16 expected_op, u32 expected_len,
		struct ntfs_log_restart_table **table, u32 *table_len)
{
	const void *dump;
	struct ntfs_log_restart_table *restart_table;
	u32 dump_len;
	int err;

	if (!table || !table_len)
		return -EINVAL;

	err = ntfs_log_checkpoint_dump_data(hdr, payload, payload_len,
			expected_op, expected_len, &dump, &dump_len);
	if (err)
		return err;
	restart_table = (struct ntfs_log_restart_table *)dump;
	if (dump_len < sizeof(*restart_table) ||
	    !ntfs_log_validate_restart_table(restart_table, dump_len) ||
	    ntfs_restart_table_bytes(restart_table) != dump_len)
		return -EINVAL;

	*table = restart_table;
	*table_len = dump_len;
	return 0;
}

/*
 * Rebuild the checkpoint-side state that later passes need: checkpoint_lsn,
 * transaction table size, and the oldest dirty-page LSN.
 */
static int ntfs_log_replay_run_analysis(struct ntfs_volume *vol,
		const struct restart_page_header *rp,
		struct ntfs_log_replay_ctx *ctx)
{
	const struct restart_area *ra;
	const struct log_client_record *client_array;
	const struct log_client_record *client_record;
	struct ntfs_logfile_layout layout;
	struct ntfs_lfs_record_hdr hdr;
	struct ntfs_log_checkpoint *checkpoint;
	struct ntfs_log_restart_table *restart_table;
	void *payload;
	u32 payload_len;
	u32 rt_len;
	u16 client_idx;
	u64 lsn;
	int err;

	if (!vol || !rp || !ctx) {
		return -EINVAL;
	}

	ra = (const struct restart_area *)((const u8 *)rp +
			le16_to_cpu(rp->restart_area_offset));

	layout.page_size = le32_to_cpu(rp->log_page_size);
	if (!is_power_of_2(layout.page_size) || layout.page_size < NTFS_BLOCK_SIZE) {
		return -EINVAL;
	}

	layout.page_mask = layout.page_size - 1;
	layout.log_size = le64_to_cpu(ra->file_size);
	layout.first_page = ctx->major_ver >= 2 ?
		0x22ULL * layout.page_size : 4ULL * layout.page_size;
	layout.seq_num_bits = le32_to_cpu(ra->seq_number_bits);
	if (!layout.seq_num_bits || layout.seq_num_bits >= 64) {
		return -EINVAL;
	}
	layout.file_data_bits = 64 - layout.seq_num_bits;
	layout.record_header_len = le16_to_cpu(ra->log_record_header_length);
	layout.data_off = le16_to_cpu(ra->log_page_data_offset);
	layout.current_lsn = ctx->current_lsn ?
		ctx->current_lsn : le64_to_cpu(ra->current_lsn);
	ntfs_debug("ntfs: %s: layout page_size=%u data_off=%u record_header_len=%u log_size=%llu first_page=%llu seq_bits=%u file_data_bits=%u current_lsn=%llu\n",
	       __func__, layout.page_size, layout.data_off,
	       layout.record_header_len, (unsigned long long)layout.log_size,
	       (unsigned long long)layout.first_page, layout.seq_num_bits,
	       layout.file_data_bits, (unsigned long long)layout.current_lsn);

	if (!layout.log_size || layout.log_size > i_size_read(vol->logfile_ino) ||
	    layout.first_page >= layout.log_size ||
	    layout.record_header_len < sizeof(struct ntfs_lfs_record_hdr) ||
	    layout.data_off >= layout.page_size) {
		return -EINVAL;
	}

	client_array = (const struct log_client_record *)((const u8 *)ra +
			le16_to_cpu(ra->client_array_offset));
	client_idx = le16_to_cpu(ra->client_in_use_list);

	if (client_idx == LOGFILE_NO_CLIENT_CPU)
		return 0;

	if (client_idx >= le16_to_cpu(ra->log_clients)) {
		return -EINVAL;
	}

	client_record = client_array + client_idx;
	layout.oldest_lsn = le64_to_cpu(client_record->oldest_lsn);
	layout.client_seq = le16_to_cpu(client_record->seq_number);
	layout.client_idx = client_idx;
	ctx->oldest_lsn = layout.oldest_lsn;
	lsn = le64_to_cpu(client_record->client_restart_lsn);
	ntfs_debug("ntfs: %s: client_idx=%u client_seq=%u oldest_lsn=%llu client_restart_lsn=%llu\n",
	       __func__, client_idx, layout.client_seq,
	       (unsigned long long)layout.oldest_lsn,
	       (unsigned long long)lsn);
	if (!lsn)
		return 0;

	err = ntfs_log_read_client_record(vol->logfile_ino, &layout, lsn, &hdr,
			&payload, &payload_len);
	if (err) {
		/*
		 * The client restart record could not be read.  This normally
		 * means its LSN sits past the durable tail of the log (the
		 * page that would hold it was never written), so the most
		 * recent checkpoint is not on disk and the journal cannot be
		 * replayed.  Propagate the error so the caller leaves the
		 * volume flagged dirty for an external repair tool.
		 */
		ntfs_error(vol->sb,
			"LogFile restart record (lsn 0x%llx) is not present in the durable log; $LogFile cannot be replayed.",
			(unsigned long long)lsn);
		return err;
	}

	if ((hdr.record_type != LFS_CLIENT_RECORD &&
	     hdr.record_type != LFS_CLIENT_RESTART) ||
	    payload_len < sizeof(struct ntfs_log_checkpoint)) {
		err = -EINVAL;
		ntfs_log_dump_lfs_record("analysis invalid checkpoint lfs", &hdr,
				payload_len);
		goto out_payload;
	}

	checkpoint = payload;
	ntfs_debug("ntfs: %s: checkpoint_start=%llu open_attr_lsn=%llu attr_names_lsn=%llu dirty_pages_lsn=%llu transact_lsn=%llu open_attr_len=%u attr_names_len=%u dirty_pages_len=%u transact_len=%u checkpoint_ver=%u.%u\n",
	       __func__,
	       (unsigned long long)le64_to_cpu(checkpoint->check_point_start),
	       (unsigned long long)le64_to_cpu(checkpoint->open_attr_table_lsn),
	       (unsigned long long)le64_to_cpu(checkpoint->attr_names_lsn),
	       (unsigned long long)le64_to_cpu(checkpoint->dirty_pages_table_lsn),
	       (unsigned long long)le64_to_cpu(checkpoint->transact_table_lsn),
	       le32_to_cpu(checkpoint->open_attr_len),
	       le32_to_cpu(checkpoint->attr_names_len),
	       le32_to_cpu(checkpoint->dirty_pages_len),
	       le32_to_cpu(checkpoint->transact_table_len),
	       le32_to_cpu(checkpoint->major_ver),
	       le32_to_cpu(checkpoint->minor_ver));
	if (!ntfs_checkpoint_dump_ref_valid(checkpoint->open_attr_table_lsn,
			checkpoint->open_attr_len) ||
	    !ntfs_checkpoint_dump_ref_valid(checkpoint->attr_names_lsn,
			checkpoint->attr_names_len) ||
	    !ntfs_checkpoint_dump_ref_valid(checkpoint->dirty_pages_table_lsn,
			checkpoint->dirty_pages_len) ||
	    !ntfs_checkpoint_dump_ref_valid(checkpoint->transact_table_lsn,
			checkpoint->transact_table_len)) {
		err = -EINVAL;
		goto out_payload;
	}
	if (le32_to_cpu(checkpoint->major_ver) > 1) {
		ntfs_error(vol->sb,
			"LogFile checkpoint table version %u is not supported.",
			le32_to_cpu(checkpoint->major_ver));
		err = -EOPNOTSUPP;
		goto out_payload;
	}
	ctx->checkpoint_lsn = le64_to_cpu(checkpoint->check_point_start);

	/* The transaction table size tells redo/undo how much active state exists. */
	if (le32_to_cpu(checkpoint->transact_table_len)) {
		void *tpayload;
		u32 tpayload_len;

		err = ntfs_log_read_client_record(vol->logfile_ino, &layout,
				le64_to_cpu(checkpoint->transact_table_lsn), &hdr,
				&tpayload, &tpayload_len);
		if (err) {
			goto out_payload;
		}

		err = ntfs_parse_restart_table_record(&hdr, tpayload,
				tpayload_len, TransactionTableDump,
				le32_to_cpu(checkpoint->transact_table_len),
				&restart_table, &rt_len);
		if (!err)
			ctx->transaction_entries = le16_to_cpu(restart_table->total);

		kfree(tpayload);
		if (err) {
			goto out_payload;
		}
	}

	/* The dirty-page table pins the earliest LSN whose data might be stale. */
	if (le32_to_cpu(checkpoint->dirty_pages_len)) {
		void *dpayload;
		u32 dpayload_len;

		err = ntfs_log_read_client_record(vol->logfile_ino, &layout,
				le64_to_cpu(checkpoint->dirty_pages_table_lsn), &hdr,
				&dpayload, &dpayload_len);
		if (err) {
			goto out_payload;
		}

		err = ntfs_parse_restart_table_record(&hdr, dpayload,
				dpayload_len, DirtyPageTableDump,
				le32_to_cpu(checkpoint->dirty_pages_len),
				&restart_table, &rt_len);
		if (!err)
			err = ntfs_parse_dirty_page_table(restart_table,
					le32_to_cpu(checkpoint->major_ver), ctx);

		kfree(dpayload);
		if (err) {
			goto out_payload;
		}
	}

	ctx->analysis_ready = true;
	err = 0;
out_payload:
	kfree(payload);
	ntfs_debug("ntfs: %s: done checkpoint_lsn=%llu oldest_lsn=%llu oldest_dirty_page_lsn=%llu transaction_entries=%u dirty_page_entries=%u err=%d\n",
	       __func__, (unsigned long long)ctx->checkpoint_lsn,
	       (unsigned long long)ctx->oldest_lsn,
	       (unsigned long long)ctx->oldest_dirty_page_lsn,
	       ctx->transaction_entries, ctx->dirty_page_entries, err);
	return err;
}

/*
 * Analysis reconstructs the checkpoint-derived tables that tell redo where to
 * start and whether undo work exists at all.
 */
static int ntfs_log_replay_analyze(struct ntfs_volume *vol,
		const struct restart_page_header *rp,
		struct ntfs_log_replay_state *st)
{
	int err;
	struct ntfs_log_replay_ctx *ctx;

	if (!vol || !rp || !st || !st->ctx) {
		return -EINVAL;
	}

	ctx = (struct ntfs_log_replay_ctx *)st->ctx;

	if (!((ctx->major_ver == 1 && ctx->minor_ver <= 1) ||
	      (ctx->major_ver == 2 && ctx->minor_ver == 0))) {
		ntfs_error(vol->sb,
			"LogFile version %u.%u is not supported by fs/ntfs replay path.",
			(unsigned int)ctx->major_ver,
			(unsigned int)ctx->minor_ver);
		return -EOPNOTSUPP;
	}

	err = ntfs_log_replay_run_analysis(vol, rp, ctx);
	if (err) {
		return err;
	}

	st->analysis_done = true;
	return 0;
}

/* Replay committed operations forward once analysis has identified the range. */
static int ntfs_log_replay_redo(struct ntfs_volume *vol,
		const struct restart_page_header *rp,
		struct ntfs_log_replay_state *st,
		struct rb_root *fn_sync)
{
	if (!vol || !rp || !st || !st->ctx)
		return -EINVAL;

	return ntfs_log_replay_run_redo(vol, rp, st->ctx, fn_sync);
}

/* Roll back incomplete transactions after redo has restored committed state. */
static int ntfs_log_replay_undo(struct ntfs_volume *vol,
		const struct restart_page_header *rp,
		struct ntfs_log_replay_state *st,
		struct rb_root *fn_sync)
{
	int err;

	if (!vol || !rp || !st || !st->ctx)
		return -EINVAL;

	err = ntfs_log_replay_run_undo(vol, rp, st->ctx, fn_sync);
	if (err)
		return err;

	st->undo_done = true;
	return 0;
}

/* Drop historical MFT growth retained to keep redo/undo records accessible. */
static int ntfs_log_replay_finalize_mft(struct ntfs_volume *vol)
{
	struct ntfs_inode *ni = NTFS_I(vol->mft_ino);
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_redo_attr_state state;
	struct mft_record *mrec;
	const struct attr_record *attr;
	unsigned long flags;
	s64 end_vcn;
	int err;

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	ctx = ntfs_attr_get_search_ctx(ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}
	err = ntfs_attr_lookup(AT_DATA, NULL, 0, CASE_SENSITIVE, 0,
			NULL, 0, ctx);
	if (err)
		goto out_ctx;
	attr = ctx->attr;
	if (!attr->non_resident || attr->data.non_resident.lowest_vcn) {
		err = -EINVAL;
		goto out_ctx;
	}
	state.allocated_size = le64_to_cpu(attr->data.non_resident.allocated_size);
	state.data_size = le64_to_cpu(attr->data.non_resident.data_size);
	state.initialized_size = le64_to_cpu(attr->data.non_resident.initialized_size);
	if (state.allocated_size <= 0 || state.initialized_size < 0 ||
	    state.initialized_size > state.data_size ||
	    state.data_size > state.allocated_size ||
	    !IS_ALIGNED(state.allocated_size, vol->cluster_size)) {
		err = -EINVAL;
		goto out_ctx;
	}
	end_vcn = state.allocated_size >> vol->cluster_size_bits;
	down_write(&ni->runlist.lock);
	if (!ni->runlist.rl || !ni->runlist.count ||
	    ni->runlist.rl[ni->runlist.count - 1].vcn < end_vcn)
		err = -EINVAL;
	else
		err = ntfs_rl_truncate_nolock(vol, &ni->runlist, end_vcn);
	ni->runlist.rl_hint = -1;
	up_write(&ni->runlist.lock);
	if (err)
		goto out_ctx;

	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = state.allocated_size;
	ni->data_size = state.data_size;
	ni->initialized_size = state.initialized_size;
	ni->zeroed_size = state.initialized_size;
	write_unlock_irqrestore(&ni->size_lock, flags);
	i_size_write(vol->mft_ino, state.data_size);
	vol->mft_ino->i_blocks = state.allocated_size >> 9;
out_ctx:
	ntfs_attr_put_search_ctx(ctx);
out_unmap:
	unmap_mft_record(ni);
	return err;
}

/* Verify that recovery reached a complete, writable on-disk state. */
static int ntfs_log_replay_finalize(struct ntfs_volume *vol,
		struct ntfs_log_replay_state *st)
{
	if (!vol || !st || !st->ctx)
		return -EINVAL;
	if (!st->analysis_done || !st->redo_done || !st->undo_done)
		return -EINVAL;

	return ntfs_log_replay_finalize_mft(vol);
}

/*
 * Execute the classic NTFS recovery sequence: analyze the checkpoint state,
 * roll committed metadata forward, and then back incomplete work out.
 */
static int ntfs_log_replay_execute(struct ntfs_volume *vol,
		const struct restart_page_header *rp,
		const struct ntfs_log_replay_ctx *ctx)
{
	struct ntfs_log_replay_state st;
	struct rb_root fn_sync = RB_ROOT;
	int err;

	if (!vol || !rp || !ctx || !ctx->valid)
		return -EINVAL;

	if (!ctx->needs_replay) {
		return 0;
	}

	memset(&st, 0, sizeof(st));
	st.ctx = ctx;

	/* Discover the replay window before touching any on-disk metadata. */
	err = ntfs_log_replay_analyze(vol, rp, &st);
	if (err) {
		ntfs_error(vol->sb,
			"LogFile replay failed in analysis stage (lsn=%llu, error %d).",
			(unsigned long long)ctx->current_lsn, err);
		return err;
	}

	/* Inspect recovery state only if mount has not enabled write access. */
	if (sb_rdonly(vol->sb))
		return 0;

	/* Redo reconstructs the committed metadata state expected after recovery. */
	err = ntfs_log_replay_redo(vol, rp, &st, &fn_sync);
	if (err) {
		ntfs_error(vol->sb,
			"LogFile replay failed in redo stage (lsn=%llu, flags=0x%x).",
			(unsigned long long)ctx->current_lsn,
			(unsigned int)ctx->restart_flags);
		goto out;
	}
	st.redo_done = true;

	/* Undo only visits transactions that analysis/prepass marked as active. */
	err = ntfs_log_replay_undo(vol, rp, &st, &fn_sync);
	if (err) {
		ntfs_error(vol->sb,
			"LogFile replay failed in undo stage (lsn=%llu, flags=0x%x).",
			(unsigned long long)ctx->current_lsn,
			(unsigned int)ctx->restart_flags);
		goto out;
	}

	err = ntfs_log_replay_finalize(vol, &st);
	if (err)
		goto out;

	/*
	 * Only now are the attribute sizes final, so refresh the $FILE_NAME
	 * copies of every record redo or undo resized.
	 */
	ntfs_redo_sync_file_names(vol, &fn_sync);
out:
	ntfs_redo_free_fn_sync(&fn_sync);
	return err;
}

bool ntfs_is_logfile_clean(const struct restart_page_header *rp)
{
	struct ntfs_log_replay_ctx ctx;

	if (ntfs_log_replay_prepare(rp, &ctx))
		return false;

	return ctx.is_clean;
}

int ntfs_replay_logfile(struct ntfs_volume *vol,
		const struct restart_page_header *rp)
{
	struct ntfs_log_replay_ctx ctx;
	int err;

	err = ntfs_log_replay_prepare(rp, &ctx);
	if (err)
		return err;

	return ntfs_log_replay_execute(vol, rp, &ctx);
}

/*
 * ntfs_check_restart_page_header - check the page header for consistency
 * @vi:		LogFile inode to which the restart page header belongs
 * @rp:		restart page header to check
 * @pos:	position in @vi at which the restart page header resides
 *
 * Check the restart page header @rp for consistency and return 'true' if it is
 * consistent and 'false' otherwise.
 *
 * This function only needs NTFS_BLOCK_SIZE bytes in @rp, i.e. it does not
 * require the full restart page.
 */
static bool ntfs_check_restart_page_header(struct inode *vi,
		struct restart_page_header *rp, s64 pos)
{
	u32 logfile_system_page_size, logfile_log_page_size;
	u32 ra_ofs, usa_count, usa_ofs, usa_end = 0;
	bool have_usa = true;

	ntfs_debug("Entering.");
	/*
	 * If the system or log page sizes are smaller than the ntfs block size
	 * or either is not a power of 2 we cannot handle this log file.
	 */
	logfile_system_page_size = le32_to_cpu(rp->system_page_size);
	logfile_log_page_size = le32_to_cpu(rp->log_page_size);
	if (logfile_system_page_size < NTFS_BLOCK_SIZE ||
			logfile_log_page_size < NTFS_BLOCK_SIZE ||
			logfile_system_page_size &
			(logfile_system_page_size - 1) ||
			!is_power_of_2(logfile_log_page_size)) {
		ntfs_error(vi->i_sb, "LogFile uses unsupported page size.");
		return false;
	}
	/*
	 * We must be either at !pos (1st restart page) or at pos = system page
	 * size (2nd restart page).
	 */
	if (pos && pos != logfile_system_page_size) {
		ntfs_error(vi->i_sb, "Found restart area in incorrect position in LogFile.");
		return false;
	}
	/* Replay supports the same on-disk log versions as ntfs3. */
	if (!((le16_to_cpu(rp->major_ver) == 1 &&
	       le16_to_cpu(rp->minor_ver) <= 1) ||
	      (le16_to_cpu(rp->major_ver) == 2 &&
	       le16_to_cpu(rp->minor_ver) == 0))) {
		ntfs_error(vi->i_sb,
			"LogFile version %i.%i is not supported.",
			(int)le16_to_cpu(rp->major_ver),
			(int)le16_to_cpu(rp->minor_ver));
		return false;
	}
	/*
	 * If chkdsk has been run the restart page may not be protected by an
	 * update sequence array.
	 */
	if (ntfs_is_chkd_record(rp->magic) && !le16_to_cpu(rp->usa_count)) {
		have_usa = false;
		goto skip_usa_checks;
	}
	/* Verify the size of the update sequence array. */
	usa_count = 1 + (logfile_system_page_size >> NTFS_BLOCK_SIZE_BITS);
	if (usa_count != le16_to_cpu(rp->usa_count)) {
		ntfs_error(vi->i_sb,
			"LogFile restart page specifies inconsistent update sequence array count.");
		return false;
	}
	/* Verify the position of the update sequence array. */
	usa_ofs = le16_to_cpu(rp->usa_ofs);
	usa_end = usa_ofs + usa_count * sizeof(u16);
	if (usa_ofs < sizeof(struct restart_page_header) ||
			usa_end > NTFS_BLOCK_SIZE - sizeof(u16)) {
		ntfs_error(vi->i_sb,
			"LogFile restart page specifies inconsistent update sequence array offset.");
		return false;
	}
skip_usa_checks:
	/*
	 * Verify the position of the restart area.  It must be:
	 *	- aligned to 8-byte boundary,
	 *	- after the update sequence array, and
	 *	- within the system page size.
	 */
	ra_ofs = le16_to_cpu(rp->restart_area_offset);
	if (ra_ofs & 7 || (have_usa ? ra_ofs < usa_end :
			ra_ofs < sizeof(struct restart_page_header)) ||
			ra_ofs > logfile_system_page_size) {
		ntfs_error(vi->i_sb,
			"LogFile restart page specifies inconsistent restart area offset.");
		return false;
	}
	/*
	 * Only restart pages modified by chkdsk are allowed to have chkdsk_lsn
	 * set.
	 */
	if (!ntfs_is_chkd_record(rp->magic) && le64_to_cpu(rp->chkdsk_lsn)) {
		ntfs_error(vi->i_sb,
			"LogFile restart page is not modified by chkdsk but a chkdsk LSN is specified.");
		return false;
	}
	ntfs_debug("Done.");
	return true;
}

/*
 * ntfs_check_restart_area - check the restart area for consistency
 * @vi:		LogFile inode to which the restart page belongs
 * @rp:		restart page whose restart area to check
 *
 * Check the restart area of the restart page @rp for consistency and return
 * 'true' if it is consistent and 'false' otherwise.
 *
 * This function assumes that the restart page header has already been
 * consistency checked.
 *
 * This function only needs NTFS_BLOCK_SIZE bytes in @rp, i.e. it does not
 * require the full restart page.
 */
static bool ntfs_check_restart_area(struct inode *vi, struct restart_page_header *rp)
{
	u64 file_size;
	struct restart_area *ra;
	u32 ra_ofs, ra_len, ca_ofs;
	u8 fs_bits;

	ntfs_debug("Entering.");
	ra_ofs = le16_to_cpu(rp->restart_area_offset);
	ra = (struct restart_area *)((u8 *)rp + ra_ofs);
	/*
	 * Everything before ra->file_size must be before the first word
	 * protected by an update sequence number.  This ensures that it is
	 * safe to access ra->client_array_offset.
	 */
	if (ra_ofs + offsetof(struct restart_area, file_size) >
			NTFS_BLOCK_SIZE - sizeof(u16)) {
		ntfs_error(vi->i_sb,
			"LogFile restart area specifies inconsistent file offset.");
		return false;
	}
	/*
	 * Now that we can access ra->client_array_offset, make sure everything
	 * up to the log client array is before the first word protected by an
	 * update sequence number.  This ensures we can access all of the
	 * restart area elements safely.  Also, the client array offset must be
	 * aligned to an 8-byte boundary.
	 */
	ca_ofs = le16_to_cpu(ra->client_array_offset);
	if (((ca_ofs + 7) & ~7) != ca_ofs ||
			ra_ofs + ca_ofs > NTFS_BLOCK_SIZE - sizeof(u16)) {
		ntfs_error(vi->i_sb,
			"LogFile restart area specifies inconsistent client array offset.");
		return false;
	}
	/*
	 * The restart area must end within the system page size both when
	 * calculated manually and as specified by ra->restart_area_length.
	 * Also, the calculated length must not exceed the specified length.
	 */
	ra_len = ca_ofs + le16_to_cpu(ra->log_clients) *
			sizeof(struct log_client_record);
	if (ra_ofs + ra_len > le32_to_cpu(rp->system_page_size) ||
			ra_ofs + le16_to_cpu(ra->restart_area_length) >
			le32_to_cpu(rp->system_page_size) ||
			ra_len > le16_to_cpu(ra->restart_area_length)) {
		ntfs_error(vi->i_sb,
			"LogFile restart area is out of bounds of the system page size specified by the restart page header and/or the specified restart area length is inconsistent.");
		return false;
	}
	/*
	 * The ra->client_free_list and ra->client_in_use_list must be either
	 * LOGFILE_NO_CLIENT or less than ra->log_clients or they are
	 * overflowing the client array.
	 */
	if ((ra->client_free_list != LOGFILE_NO_CLIENT &&
			le16_to_cpu(ra->client_free_list) >=
			le16_to_cpu(ra->log_clients)) ||
			(ra->client_in_use_list != LOGFILE_NO_CLIENT &&
			le16_to_cpu(ra->client_in_use_list) >=
			le16_to_cpu(ra->log_clients))) {
		ntfs_error(vi->i_sb,
			"LogFile restart area specifies overflowing client free and/or in use lists.");
		return false;
	}
	/*
	 * Check ra->seq_number_bits against ra->file_size for consistency.
	 * We cannot just use ffs() because the file size is not a power of 2.
	 */
	file_size = le64_to_cpu(ra->file_size);
	fs_bits = 0;
	while (file_size) {
		file_size >>= 1;
		fs_bits++;
	}
	if (le32_to_cpu(ra->seq_number_bits) != 67 - fs_bits) {
		ntfs_error(vi->i_sb,
			"LogFile restart area specifies inconsistent sequence number bits.");
		return false;
	}
	/* The log record header length must be a multiple of 8. */
	if (((le16_to_cpu(ra->log_record_header_length) + 7) & ~7) !=
			le16_to_cpu(ra->log_record_header_length)) {
		ntfs_error(vi->i_sb,
			"LogFile restart area specifies inconsistent log record header length.");
		return false;
	}
	/* Dito for the log page data offset. */
	if (((le16_to_cpu(ra->log_page_data_offset) + 7) & ~7) !=
			le16_to_cpu(ra->log_page_data_offset)) {
		ntfs_error(vi->i_sb,
			"LogFile restart area specifies inconsistent log page data offset.");
		return false;
	}
	ntfs_debug("Done.");
	return true;
}

/*
 * ntfs_check_log_client_array - check the log client array for consistency
 * @vi:		LogFile inode to which the restart page belongs
 * @rp:		restart page whose log client array to check
 *
 * Check the log client array of the restart page @rp for consistency and
 * return 'true' if it is consistent and 'false' otherwise.
 *
 * This function assumes that the restart page header and the restart area have
 * already been consistency checked.
 *
 * Unlike ntfs_check_restart_page_header() and ntfs_check_restart_area(), this
 * function needs @rp->system_page_size bytes in @rp, i.e. it requires the full
 * restart page and the page must be multi sector transfer deprotected.
 */
static bool ntfs_check_log_client_array(struct inode *vi,
		struct restart_page_header *rp)
{
	struct restart_area *ra;
	struct log_client_record *client_array, *client_record;
	u16 nr_clients, idx;
	bool in_free_list, idx_is_first;

	ntfs_debug("Entering.");
	ra = (struct restart_area *)((u8 *)rp + le16_to_cpu(rp->restart_area_offset));
	client_array = (struct log_client_record *)((u8 *)ra +
			le16_to_cpu(ra->client_array_offset));
	/*
	 * Check the ra->client_free_list first and then check the
	 * ra->client_in_use_list.  Check each of the log client records in
	 * each of the lists and check that the array does not overflow the
	 * ra->log_clients value.  Also keep track of the number of records
	 * visited as there cannot be more than ra->log_clients records and
	 * that way we detect eventual loops in within a list.
	 */
	nr_clients = le16_to_cpu(ra->log_clients);
	idx = le16_to_cpu(ra->client_free_list);
	in_free_list = true;
check_list:
	for (idx_is_first = true; idx != LOGFILE_NO_CLIENT_CPU; nr_clients--,
			idx = le16_to_cpu(client_record->next_client)) {
		if (!nr_clients || idx >= le16_to_cpu(ra->log_clients))
			goto err_out;
		/* Set @client_record to the current log client record. */
		client_record = client_array + idx;
		/* The first log client record must not have a prev_client. */
		if (idx_is_first) {
			if (client_record->prev_client != LOGFILE_NO_CLIENT)
				goto err_out;
			idx_is_first = false;
		}
	}
	/* Switch to and check the in use list if we just did the free list. */
	if (in_free_list) {
		in_free_list = false;
		idx = le16_to_cpu(ra->client_in_use_list);
		goto check_list;
	}
	ntfs_debug("Done.");
	return true;
err_out:
	ntfs_error(vi->i_sb, "LogFile log client array is corrupt.");
	return false;
}

/*
 * ntfs_check_and_load_restart_page - check the restart page for consistency
 * @vi:		LogFile inode to which the restart page belongs
 * @rp:		restart page to check
 * @pos:	position in @vi at which the restart page resides
 * @wrp:	[OUT] copy of the multi sector transfer deprotected restart page
 * @lsn:	[OUT] set to the current logfile lsn on success
 *
 * Check the restart page @rp for consistency and return 0 if it is consistent
 * and -errno otherwise.  The restart page may have been modified by chkdsk in
 * which case its magic is CHKD instead of RSTR.
 *
 * This function only needs NTFS_BLOCK_SIZE bytes in @rp, i.e. it does not
 * require the full restart page.
 *
 * If @wrp is not NULL, on success, *@wrp will point to a buffer containing a
 * copy of the complete multi sector transfer deprotected page.  On failure,
 * *@wrp is undefined.
 *
 * Simillarly, if @lsn is not NULL, on success *@lsn will be set to the current
 * logfile lsn according to this restart page.  On failure, *@lsn is undefined.
 *
 * The following error codes are defined:
 *	-EINVAL	- The restart page is inconsistent.
 *	-ENOMEM	- Not enough memory to load the restart page.
 *	-EIO	- Failed to reading from LogFile.
 */
static int ntfs_check_and_load_restart_page(struct inode *vi,
		struct restart_page_header *rp, s64 pos, struct restart_page_header **wrp,
		s64 *lsn)
{
	struct restart_area *ra;
	struct restart_page_header *trp;
	int size, err;

	ntfs_debug("Entering.");
	/* Check the restart page header for consistency. */
	if (!ntfs_check_restart_page_header(vi, rp, pos)) {
		/* Error output already done inside the function. */
		return -EINVAL;
	}
	/* Check the restart area for consistency. */
	if (!ntfs_check_restart_area(vi, rp)) {
		/* Error output already done inside the function. */
		return -EINVAL;
	}
	ra = (struct restart_area *)((u8 *)rp + le16_to_cpu(rp->restart_area_offset));
	/*
	 * Allocate a buffer to store the whole restart page so we can multi
	 * sector transfer deprotect it.
	 */
	trp = kvzalloc(le32_to_cpu(rp->system_page_size), GFP_NOFS);
	if (!trp) {
		ntfs_error(vi->i_sb, "Failed to allocate memory for LogFile restart page buffer.");
		return -ENOMEM;
	}
	/*
	 * Read the whole of the restart page into the buffer.  If it fits
	 * completely inside @rp, just copy it from there.  Otherwise map all
	 * the required pages and copy the data from them.
	 */
	size = PAGE_SIZE - (pos & ~PAGE_MASK);
	if (size >= le32_to_cpu(rp->system_page_size)) {
		memcpy(trp, rp, le32_to_cpu(rp->system_page_size));
	} else {
		pgoff_t idx;
		struct folio *folio;
		int have_read, to_read;

		/* First copy what we already have in @rp. */
		memcpy(trp, rp, size);
		/* Copy the remaining data one page at a time. */
		have_read = size;
		to_read = le32_to_cpu(rp->system_page_size) - size;
		idx = (pos + size) >> PAGE_SHIFT;
		do {
			folio = ntfs_read_metadata_folio(vi->i_mapping, idx);
			if (IS_ERR(folio)) {
				ntfs_error(vi->i_sb, "Error mapping LogFile page (index %lu).",
						idx);
				err = PTR_ERR(folio);
				if (err != -EIO && err != -ENOMEM)
					err = -EIO;
				goto err_out;
			}
			size = min_t(int, to_read, PAGE_SIZE);
			memcpy((u8 *)trp + have_read, folio_address(folio), size);
			folio_put(folio);
			have_read += size;
			to_read -= size;
			idx++;
		} while (to_read > 0);
	}
	/*
	 * Perform the multi sector transfer deprotection on the buffer if the
	 * restart page is protected.
	 */
	if ((!ntfs_is_chkd_record(trp->magic) || le16_to_cpu(trp->usa_count)) &&
	    post_read_mst_fixup((struct ntfs_record *)trp, le32_to_cpu(rp->system_page_size))) {
		/*
		 * A multi sector transfer error was detected.  We only need to
		 * abort if the restart page contents exceed the multi sector
		 * transfer fixup of the first sector.
		 */
		if (le16_to_cpu(rp->restart_area_offset) +
				le16_to_cpu(ra->restart_area_length) >
				NTFS_BLOCK_SIZE - sizeof(u16)) {
			ntfs_error(vi->i_sb,
				"Multi sector transfer error detected in LogFile restart page.");
			err = -EINVAL;
			goto err_out;
		}
	}
	/*
	 * If the restart page is modified by chkdsk or there are no active
	 * logfile clients, the logfile is consistent.  Otherwise, need to
	 * check the log client records for consistency, too.
	 */
	err = 0;
	if (ntfs_is_rstr_record(rp->magic) &&
			ra->client_in_use_list != LOGFILE_NO_CLIENT) {
		if (!ntfs_check_log_client_array(vi, trp)) {
			err = -EINVAL;
			goto err_out;
		}
	}
	if (lsn) {
		if (ntfs_is_rstr_record(rp->magic))
			*lsn = le64_to_cpu(ra->current_lsn);
		else /* if (ntfs_is_chkd_record(rp->magic)) */
			*lsn = le64_to_cpu(rp->chkdsk_lsn);
	}
	ntfs_debug("Done.");
	if (wrp)
		*wrp = trp;
	else {
err_out:
		kvfree(trp);
	}
	return err;
}

/*
 * ntfs_restart_record_is_durable - is a restart page's checkpoint on disk?
 * @log_vi:	LogFile inode the restart page belongs to
 * @rp:		restart page whose client restart record should be probed
 *
 * A volume can crash after NTFS has written a fresh restart page that points at
 * a new checkpoint but before that checkpoint record (and the log pages leading
 * up to it) have been flushed.  The newer restart page then references a
 * client_restart_lsn that sits past the durable tail of the log, so the record
 * it names simply is not there.  Recovery must fall back to the older restart
 * page in that case, and this probe lets ntfs_check_logfile() detect it: read
 * the client restart record the same way the replay analysis will.
 *
 * Returns true if the record is present (or if there is nothing to replay for
 * this client), false if it is missing/unreadable.  Any failure to build a
 * usable layout is treated as "durable" so this probe never refuses a page the
 * caller would otherwise have accepted.
 */
static bool ntfs_restart_record_is_durable(struct inode *log_vi,
		const struct restart_page_header *rp)
{
	const struct restart_area *ra;
	const struct log_client_record *client_array;
	const struct log_client_record *client_record;
	struct ntfs_logfile_layout layout;
	struct ntfs_lfs_record_hdr hdr;
	void *payload = NULL;
	u32 payload_len = 0;
	u16 client_idx;
	u64 lsn;
	int err;

	if (!log_vi || !rp || !ntfs_is_rstr_record(rp->magic))
		return true;

	memset(&layout, 0, sizeof(layout));
	ra = (const struct restart_area *)((const u8 *)rp +
			le16_to_cpu(rp->restart_area_offset));

	layout.page_size = le32_to_cpu(rp->log_page_size);
	if (!is_power_of_2(layout.page_size) ||
	    layout.page_size < NTFS_BLOCK_SIZE)
		return true;
	layout.page_mask = layout.page_size - 1;
	layout.log_size = le64_to_cpu(ra->file_size);
	layout.first_page = le16_to_cpu(rp->major_ver) >= 2 ?
		0x22ULL * layout.page_size : 4ULL * layout.page_size;
	layout.seq_num_bits = le32_to_cpu(ra->seq_number_bits);
	if (!layout.seq_num_bits || layout.seq_num_bits >= 64)
		return true;
	layout.file_data_bits = 64 - layout.seq_num_bits;
	layout.record_header_len = le16_to_cpu(ra->log_record_header_length);
	layout.data_off = le16_to_cpu(ra->log_page_data_offset);
	layout.current_lsn = le64_to_cpu(ra->current_lsn);

	if (!layout.log_size || layout.log_size > i_size_read(log_vi) ||
	    layout.first_page >= layout.log_size ||
	    layout.record_header_len < sizeof(struct ntfs_lfs_record_hdr) ||
	    layout.data_off >= layout.page_size)
		return true;

	client_array = (const struct log_client_record *)((const u8 *)ra +
			le16_to_cpu(ra->client_array_offset));
	client_idx = le16_to_cpu(ra->client_in_use_list);
	if (client_idx == LOGFILE_NO_CLIENT_CPU)
		return true;
	if (client_idx >= le16_to_cpu(ra->log_clients))
		return true;

	client_record = client_array + client_idx;
	layout.oldest_lsn = le64_to_cpu(client_record->oldest_lsn);
	layout.client_seq = le16_to_cpu(client_record->seq_number);
	layout.client_idx = client_idx;
	lsn = le64_to_cpu(client_record->client_restart_lsn);
	if (!lsn)
		return true;

	err = ntfs_log_read_client_record(log_vi, &layout, lsn, &hdr,
			&payload, &payload_len);
	if (err)
		return false;
	kfree(payload);
	return true;
}

/*
 * ntfs_check_logfile - check the journal for consistency
 * @log_vi:	struct inode of loaded journal LogFile to check
 * @rp:		[OUT] on success this is a copy of the current restart page
 * @restart_pos:	[OUT] offset of the selected restart page, or NULL
 *
 * Check the LogFile journal for consistency and return 'true' if it is
 * consistent and 'false' if not.  On success, the current restart page is
 * returned in *@rp.  Caller must call kvfree(*@rp) when finished with it.
 *
 * At present we only check the two restart pages and ignore the log record
 * pages.
 *
 * Note that the MstProtected flag is not set on the LogFile inode and hence
 * when reading pages they are not deprotected.  This is because we do not know
 * if the LogFile was created on a system with a different page size to ours
 * yet and mst deprotection would fail if our page size is smaller.
 */
bool ntfs_check_logfile(struct inode *log_vi, struct restart_page_header **rp,
		u64 *restart_pos)
{
	s64 size, pos;
	s64 rstr1_lsn, rstr2_lsn;
	u64 selected_pos = 0;
	struct ntfs_volume *vol = NTFS_SB(log_vi->i_sb);
	struct address_space *mapping = log_vi->i_mapping;
	struct folio *folio = NULL;
	u8 *kaddr = NULL, *kbase = NULL;
	struct restart_page_header *rstr1_ph = NULL;
	struct restart_page_header *rstr2_ph = NULL;
	int log_page_size, err;
	bool logfile_is_empty = true;
	u8 log_page_bits;

	ntfs_debug("Entering.");
	/* An empty LogFile must have been clean before it got emptied. */
	if (NVolLogFileEmpty(vol))
		goto is_empty;
	size = i_size_read(log_vi);
	/* Make sure the file doesn't exceed the maximum allowed size. */
	if (size > MaxLogFileSize)
		size = MaxLogFileSize;
	/*
	 * Truncate size to a multiple of the page cache size or the default
	 * log page size if the page cache size is between the default log page
	 * log page size if the page cache size is between the default log page
	 * size and twice that.
	 */
	if (DefaultLogPageSize <= PAGE_SIZE &&
	    DefaultLogPageSize * 2 <= PAGE_SIZE)
		log_page_size = DefaultLogPageSize;
	else
		log_page_size = PAGE_SIZE;
	/*
	 * Use ntfs_ffs() instead of ffs() to enable the compiler to
	 * optimize log_page_size and log_page_bits into constants.
	 */
	log_page_bits = ntfs_ffs(log_page_size) - 1;
	size &= ~(s64)(log_page_size - 1);
	/*
	 * Ensure the log file is big enough to store at least the two restart
	 * pages and the minimum number of log record pages.
	 */
	if (size < log_page_size * 2 || (size - log_page_size * 2) >>
			log_page_bits < MinLogRecordPages) {
		ntfs_error(vol->sb, "LogFile is too small.");
		return false;
	}
	/*
	 * Read through the file looking for a restart page.  Since the restart
	 * page header is at the beginning of a page we only need to search at
	 * what could be the beginning of a page (for each page size) rather
	 * than scanning the whole file byte by byte.  If all potential places
	 * contain empty and uninitialzed records, the log file can be assumed
	 * to be empty.
	 */
	for (pos = 0; pos < size; pos <<= 1) {
		pgoff_t idx = pos >> PAGE_SHIFT;

		if (!folio || folio->index != idx) {
			if (folio) {
				kunmap_local(kbase);
				folio_put(folio);
			}
			folio = ntfs_read_metadata_folio(mapping, idx);
			if (IS_ERR(folio)) {
				ntfs_error(vol->sb, "Error mapping LogFile page (index %lu).",
						idx);
				goto err_out;
			}
			kbase = kmap_local_folio(folio, 0);
		}
		kaddr = kbase + (pos & ~PAGE_MASK);
		/*
		 * A non-empty block means the logfile is not empty while an
		 * empty block after a non-empty block has been encountered
		 * means we are done.
		 */
		if (!ntfs_is_empty_recordp((__le32 *)kaddr))
			logfile_is_empty = false;
		else if (!logfile_is_empty)
			break;
		/*
		 * A log record page means there cannot be a restart page after
		 * this so no need to continue searching.
		 */
		if (ntfs_is_rcrd_recordp((__le32 *)kaddr))
			break;
		/* If not a (modified by chkdsk) restart page, continue. */
		if (!ntfs_is_rstr_recordp((__le32 *)kaddr) &&
				!ntfs_is_chkd_recordp((__le32 *)kaddr)) {
			if (!pos)
				pos = NTFS_BLOCK_SIZE >> 1;
			continue;
		}
		/*
		 * Check the (modified by chkdsk) restart page for consistency
		 * and get a copy of the complete multi sector transfer
		 * deprotected restart page.
		 */
		err = ntfs_check_and_load_restart_page(log_vi,
				(struct restart_page_header *)kaddr, pos,
				!rstr1_ph ? &rstr1_ph : &rstr2_ph,
				!rstr1_ph ? &rstr1_lsn : &rstr2_lsn);
		if (!err) {
			if (!rstr2_ph)
				selected_pos = pos;
			/*
			 * If we have now found the first (modified by chkdsk)
			 * restart page, continue looking for the second one.
			 */
			if (!pos) {
				pos = NTFS_BLOCK_SIZE >> 1;
				continue;
			}
			/*
			 * We have now found the second (modified by chkdsk)
			 * restart page, so we can stop looking.
			 */
			break;
		}
		/*
		 * Error output already done inside the function.  Note, we do
		 * not abort if the restart page was invalid as we might still
		 * find a valid one further in the file.
		 */
		if (err != -EINVAL) {
			kunmap_local(kbase);
			folio_put(folio);
			goto err_out;
		}
		/* Continue looking. */
		if (!pos)
			pos = NTFS_BLOCK_SIZE >> 1;
	}
	if (folio) {
		kunmap_local(kbase);
		folio_put(folio);
	}
	if (logfile_is_empty) {
		NVolSetLogFileEmpty(vol);
is_empty:
		ntfs_debug("Done.  (LogFile is empty.)");
		return true;
	}
	if (!rstr1_ph) {
		ntfs_error(vol->sb,
			"Did not find any restart pages in LogFile and it was not empty.");
		return false;
	}
	/*
	 * If both restart pages were found, use the more recent one -- but only
	 * if its checkpoint actually reached the disk.  A volume that crashed
	 * after the newer restart page was written but before its checkpoint
	 * record was flushed leaves that page referencing an LSN past the
	 * durable tail of the log. Recovery must then fall back to the older
	 * restart page, whose checkpoint is still present.
	 */
	if (rstr2_ph) {
		struct restart_page_header *newer, *older;

		if (rstr2_lsn > rstr1_lsn) {
			newer = rstr2_ph;
			older = rstr1_ph;
		} else {
			newer = rstr1_ph;
			older = rstr2_ph;
		}

		if (!ntfs_restart_record_is_durable(log_vi, newer) &&
		    ntfs_restart_record_is_durable(log_vi, older)) {
			ntfs_debug("More recent restart page is not durable; falling back to the older one.");
			swap(newer, older);
		}
		if (newer == rstr2_ph)
			selected_pos = pos;
		rstr1_ph = newer;
		kvfree(older);
	}
	/* All consistency checks passed. */
	if (restart_pos)
		*restart_pos = selected_pos;
	if (rp)
		*rp = rstr1_ph;
	else
		kvfree(rstr1_ph);
	ntfs_debug("Done.");
	return true;
err_out:
	kvfree(rstr1_ph);
	return false;
}

/*
 * ntfs_empty_logfile - empty the contents of the LogFile journal
 * @log_vi:	struct inode of loaded journal LogFile to empty
 *
 * Empty the contents of the LogFile journal @log_vi and return 'true' on
 * success and 'false' on error.
 *
 * The caller must have checked the journal with ntfs_check_logfile().  A dirty
 * journal may only be discarded at the user's explicit request. In that case
 * the caller must keep the volume dirty so that it is not mistaken for a
 * successfully recovered filesystem.
 */
bool ntfs_empty_logfile(struct inode *log_vi)
{
	s64 vcn, end_vcn;
	struct ntfs_inode *log_ni = NTFS_I(log_vi);
	struct ntfs_volume *vol = log_ni->vol;
	struct super_block *sb = vol->sb;
	struct runlist_element *rl;
	unsigned long flags;
	int err;
	bool should_wait = true;
	char *empty_buf = NULL;
	struct file_ra_state *ra = NULL;

	ntfs_debug("Entering.");
	if (NVolLogFileEmpty(vol)) {
		ntfs_debug("Done.");
		return true;
	}

	/*
	 * We cannot use ntfs_attr_set() because we may be still in the middle
	 * of a mount operation.  Thus we do the emptying by hand by first
	 * zapping the page cache pages for the LogFile/DATA attribute and
	 * then emptying each of the buffers in each of the clusters specified
	 * by the runlist by hand.
	 */
	vcn = 0;
	read_lock_irqsave(&log_ni->size_lock, flags);
	end_vcn = (log_ni->initialized_size + vol->cluster_size_mask) >>
			vol->cluster_size_bits;
	read_unlock_irqrestore(&log_ni->size_lock, flags);
	truncate_inode_pages(log_vi->i_mapping, 0);
	down_write(&log_ni->runlist.lock);
	rl = log_ni->runlist.rl;
	if (unlikely(!rl || vcn < rl->vcn || !rl->length)) {
map_vcn:
		err = ntfs_map_runlist_nolock(log_ni, vcn, NULL);
		if (err) {
			ntfs_error(sb, "Failed to map runlist fragment (error %d).", -err);
			goto err;
		}
		rl = log_ni->runlist.rl;
	}
	/* Seek to the runlist element containing @vcn. */
	while (rl->length && vcn >= rl[1].vcn)
		rl++;

	err = -ENOMEM;
	empty_buf = kvzalloc(vol->cluster_size, GFP_NOFS);
	if (!empty_buf)
		goto err;

	memset(empty_buf, 0xff, vol->cluster_size);

	ra = kzalloc_obj(*ra, GFP_NOFS);
	if (!ra)
		goto err;

	file_ra_state_init(ra, sb->s_bdev->bd_mapping);
	do {
		s64 lcn;
		loff_t start, end;
		s64 len;

		/*
		 * If this run is not mapped map it now and start again as the
		 * runlist will have been updated.
		 */
		lcn = rl->lcn;
		if (unlikely(lcn == LCN_RL_NOT_MAPPED)) {
			vcn = rl->vcn;
			kvfree(empty_buf);
			empty_buf = NULL;
			kfree(ra);
			ra = NULL;
			goto map_vcn;
		}
		/* If this run is not valid abort with an error. */
		if (unlikely(!rl->length || lcn < LCN_HOLE))
			goto rl_err;
		/* Skip holes. */
		if (lcn == LCN_HOLE)
			continue;
		start = NTFS_CLU_TO_B(vol, lcn);
		len = rl->length;
		if (rl[1].vcn > end_vcn)
			len = end_vcn - rl->vcn;
		end = NTFS_CLU_TO_B(vol, lcn + len);

		page_cache_sync_readahead(sb->s_bdev->bd_mapping, ra, NULL,
			start >> PAGE_SHIFT, (end - start) >> PAGE_SHIFT);

		do {
			err = ntfs_bdev_write(sb, empty_buf, start,
						  vol->cluster_size);
			if (err) {
				ntfs_error(sb, "ntfs_dev_write failed, err : %d\n", err);
				goto io_err;
			}

			/*
			 * Submit the buffer and wait for i/o to complete but
			 * only for the first buffer so we do not miss really
			 * serious i/o errors.  Once the first buffer has
			 * completed ignore errors afterwards as we can assume
			 * that if one buffer worked all of them will work.
			 */
			if (should_wait) {
				should_wait = false;
				err = filemap_write_and_wait_range(sb->s_bdev->bd_mapping,
						start, start + vol->cluster_size);
				if (err)
					goto io_err;
			}
			start += vol->cluster_size;
		} while (start < end);
	} while ((++rl)->vcn < end_vcn);
	up_write(&log_ni->runlist.lock);
	kvfree(empty_buf);
	kfree(ra);
	truncate_inode_pages(log_vi->i_mapping, 0);
	/* Set the flag so we do not have to do it again on remount. */
	NVolSetLogFileEmpty(vol);
	ntfs_debug("Done.");
	return true;
io_err:
	ntfs_error(sb, "Failed to write buffer.  Unmount and run chkdsk.");
	goto dirty_err;
rl_err:
	ntfs_error(sb, "Runlist is corrupt.  Unmount and run chkdsk.");
dirty_err:
	NVolSetErrors(vol);
	err = -EIO;
err:
	kvfree(empty_buf);
	kfree(ra);
	up_write(&log_ni->runlist.lock);
	ntfs_error(sb, "Failed to fill LogFile with 0xff bytes (error %d).",
			-err);
	return false;
}
