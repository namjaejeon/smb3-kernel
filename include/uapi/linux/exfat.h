/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2024 Unisoc Technologies Co., Ltd.
 * Copyright (C) 2026 Namjae Jeon <linkinjeon@kernel.org>
 */

#ifndef _UAPI_LINUX_EXFAT_H
#define _UAPI_LINUX_EXFAT_H
#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * exfat-specific ioctl commands
 */

#define EXFAT_IOC_SHUTDOWN _IOR('X', 125, __u32)

/*
 * Flags used by EXFAT_IOC_SHUTDOWN
 */

#define EXFAT_GOING_DOWN_DEFAULT	0x0	/* default with full sync */
#define EXFAT_GOING_DOWN_FULLSYNC	0x1     /* going down with full sync*/
#define EXFAT_GOING_DOWN_NOSYNC         0x2     /* going down */

/*
 * Cluster numbers below are zero-based offsets in the cluster heap (LCNs),
 * not exFAT's on-disk cluster numbers, which start at two.
 * All flags and reserved fields must be zero.
 */
struct exfat_volume_bitmap {
	__u64 start_lcn;		/* in/out: rounded down to a multiple of 8 */
	__u64 total_clusters;	/* out: clusters in the volume */
	__aligned_u64 bitmap;	/* in: userspace byte array */
	__u32 bitmap_bytes;	/* in: capacity, from 1 through 1 MiB */
	__u32 bytes_returned;	/* out: valid bytes, last-byte padding is 1 */
	__u32 cluster_size;	/* out: bytes per cluster */
	__u32 max_move_clusters;	/* out: maximum clusters per move */
	__u32 flags;
	__u32 reserved;
};

struct exfat_extent {
	__u64 vcn;
	__u64 lcn;
	__u64 cluster_count;
};

struct exfat_retrieval_pointers {
	__u64 start_vcn;		/* in: first virtual cluster to query */
	__u64 next_vcn;		/* out: continuation, or total_clusters */
	__u64 total_clusters;	/* out: allocated clusters in the file */
	__aligned_u64 extents;	/* in: userspace struct exfat_extent array */
	__u32 extent_capacity;	/* in: from 1 through 4096 */
	__u32 extent_count;	/* out: returned extents */
	__u32 flags;
	__u32 reserved;
};

struct exfat_move_file {
	__u64 start_vcn;
	__u64 target_lcn;
	__u64 cluster_count;
	__u64 expected_lcn;	/* source LCN at start_vcn; stale => ESTALE */
	__u32 flags;
	__u32 reserved;
};

/*
 * Issued on an open file/directory in the mounted filesystem, not its block
 * device. All require CAP_SYS_ADMIN. MOVE_FILE also requires a writable,
 * linked regular file. Bitmap snapshots can become stale immediately.
 */
#define EXFAT_IOC_GET_VOLUME_BITMAP \
	_IOWR('X', 126, struct exfat_volume_bitmap)
#define EXFAT_IOC_GET_RETRIEVAL_POINTERS \
	_IOWR('X', 127, struct exfat_retrieval_pointers)
#define EXFAT_IOC_MOVE_FILE _IOW('X', 128, struct exfat_move_file)

#endif /* _UAPI_LINUX_EXFAT_H */
