/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ntfs

#if !defined(_NTFS_LOGFILE_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _NTFS_LOGFILE_TRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(ntfs_log_replay_record,

	TP_PROTO(const char *device, u8 phase, u16 opcode, u64 lsn,
		 u32 transaction_id, u8 outcome, int error),

	TP_ARGS(device, phase, opcode, lsn, transaction_id, outcome, error),

	TP_STRUCT__entry(
		__array(char, device, 32)
		__field(u8, phase)
		__field(u16, opcode)
		__field(u64, lsn)
		__field(u32, transaction_id)
		__field(u8, outcome)
		__field(int, error)
	),

	TP_fast_assign(
		strscpy(__entry->device, device, sizeof(__entry->device));
		__entry->phase = phase;
		__entry->opcode = opcode;
		__entry->lsn = lsn;
		__entry->transaction_id = transaction_id;
		__entry->outcome = outcome;
		__entry->error = error;
	),

	TP_printk("dev=%s phase=%s op=0x%02x lsn=%llu txid=0x%x outcome=%s error=%d",
		  __entry->device,
		  __print_symbolic(__entry->phase,
			{ 0, "redo" },
			{ 1, "undo" }),
		  __entry->opcode, __entry->lsn, __entry->transaction_id,
		  __print_symbolic(__entry->outcome,
			{ 0, "seen" },
			{ 1, "dispatched" },
			{ 2, "skip_action" },
			{ 3, "skip_no_lcns" },
			{ 4, "skip_dirty_page" },
			{ 5, "skip_old_lsn" },
			{ 6, "failed" }),
		  __entry->error)
);

#endif /* _NTFS_LOGFILE_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE logfile_trace
#include <trace/define_trace.h>
