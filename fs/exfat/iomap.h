/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 Namjae Jeon <linkinjeon@kernel.org>
 */

#ifndef _LINUX_EXFAT_IOMAP_H
#define _LINUX_EXFAT_IOMAP_H

struct exfat_dio_alloc {
	struct list_head list;
	unsigned int clu;
	unsigned int count;
};

/* One synchronous, bounded batch; also used for native AIO callers. */
struct exfat_dio {
	struct kiocb iocb;
	struct list_head allocs;
	loff_t start;
	loff_t completed;
	unsigned int old_clusters;
	unsigned int alloc_start;
	unsigned int last_clu;
	bool committed;
};

int exfat_reserve_dio_alloc(struct exfat_dio *dio, unsigned int count);
int exfat_commit_dio_alloc(struct exfat_dio *dio, loff_t end);
void exfat_release_dio_alloc(struct exfat_dio *dio);

extern const struct iomap_ops exfat_dio_iomap_ops;
extern const struct iomap_ops exfat_iomap_ops;
extern const struct iomap_ops exfat_write_iomap_ops;
extern const struct iomap_write_ops exfat_iomap_write_ops;
extern const struct iomap_write_ops exfat_dio_gap_write_ops;
extern const struct iomap_writeback_ops exfat_writeback_ops;
extern const struct iomap_read_ops exfat_iomap_bio_read_ops;

int exfat_iomap_swap_activate(struct swap_info_struct *sis,
			       struct file *file, sector_t *span);

#endif /* _LINUX_EXFAT_IOMAP_H */
