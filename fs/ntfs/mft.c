// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS kernel mft record operations.
 * Part of this file is based on code from the NTFS-3G.
 *
 * Copyright (c) 2001-2012 Anton Altaparmakov and Tuxera Inc.
 * Copyright (c) 2002 Richard Russon
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/writeback.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/iomap.h>
#include <linux/math64.h>

#include "bitmap.h"
#include "lcnalloc.h"
#include "logfile_internal.h"
#include "mft.h"
#include "ntfs.h"

struct ntfs_mft_alloc_home_undo {
	struct ntfs_volume *vol;
	struct ntfs_inode *ni;
	u64 mft_no;
	bool counted;
	bool close_on_abort;
	bool lock_bitmap;
	u8 record[];
};

struct ntfs_mft_free_home_undo {
	struct ntfs_volume *vol;
	struct ntfs_inode *ni;
	bool aborted;
	bool close_on_commit;
	bool mft_dirty;
	u8 record[];
};

struct ntfs_mft_bitmap_home_undo {
	struct ntfs_volume *vol;
	s64 start_bit;
	s64 count;
	bool lock_bitmap;
};

struct ntfs_mft_count_home_undo {
	struct ntfs_volume *vol;
	s64 records;
	bool counted;
};

/*
 * An MFT record which is already mapped and protected by the caller.
 *
 * MFT record allocation holds the page-cache folio while it initializes a
 * newly allocated record.  Extent inode setup must be able to consume that
 * record without trying to acquire the same folio lock again.
 */
struct ntfs_mft_locked_record {
	struct mft_record *mrec;
	unsigned int ofs;
	struct folio *folio;
};

static int ntfs_mft_record_format(const struct ntfs_volume *vol,
		const s64 mft_no);
static int ntfs_mft_record_format_transacted(struct ntfs_log_handle *handle,
					     const struct ntfs_volume *vol,
					     s64 mft_no);
static int ntfs_mft_record_alloc_credits_batch(struct ntfs_volume *vol,
					      u32 batch_records);

static int ntfs_mft_count_home_restore(void *data)
{
	struct ntfs_mft_count_home_undo *undo = data;

	if (undo->counted) {
		ntfs_dec_free_mft_records(undo->vol, undo->records);
		undo->counted = false;
	}
	return 0;
}

static void ntfs_mft_count_home_release(void *data)
{
	kfree(data);
}

static int ntfs_mft_count_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		s64 records, struct ntfs_mft_count_home_undo **undo_out)
{
	struct ntfs_mft_count_home_undo *undo;
	int err;

	if (!handle || !vol || records <= 0 || !undo_out)
		return -EINVAL;
	undo = kzalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->vol = vol;
	undo->records = records;
	err = ntfs_log_register_home_undo(handle, ntfs_mft_count_home_restore,
			ntfs_mft_count_home_release, undo);
	if (err) {
		kfree(undo);
		return err;
	}
	*undo_out = undo;
	return 0;
}

static int ntfs_mft_free_home_restore(void *data)
{
	struct ntfs_mft_free_home_undo *undo = data;
	struct mft_record *m;
	int err;

	undo->aborted = true;
	m = map_mft_record(undo->ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
	} else {
		memcpy(m, undo->record, undo->vol->mft_record_size);
		err = ntfs_prepare_mft_record_write(undo->ni);
		if (!err) {
			NInoSetDirty(undo->ni);
			err = write_mft_record(undo->ni, m, 1);
			if (!err && undo->mft_dirty)
				NInoSetDirty(undo->ni);
		}
		unmap_mft_record(undo->ni);
	}
	return err;
}

static void ntfs_mft_free_home_release(void *data)
{
	struct ntfs_mft_free_home_undo *undo = data;

	if (!undo->aborted && undo->close_on_commit && undo->ni)
		ntfs_inode_close(undo->ni);
	kvfree(undo);
}

static int ntfs_mft_free_home_commit(void *data)
{
	struct ntfs_mft_free_home_undo *undo = data;
	struct ntfs_inode *ni;

	if (!undo || !undo->ni)
		return -EINVAL;
	if (!undo->close_on_commit)
		return 0;
	ni = undo->ni;
	undo->ni = NULL;
	undo->close_on_commit = false;
	return ntfs_inode_close(ni);
}

static int ntfs_mft_bitmap_home_restore(void *data)
{
	if (!data)
		return -EINVAL;
	/*
	 * MFT bitmap bits remain allocated until the durable commit callback.
	 */
	return 0;
}

static int ntfs_mft_bitmap_home_commit(void *data)
{
	struct ntfs_mft_bitmap_home_undo *undo = data;
	unsigned int memalloc_flags;
	s64 first_mismatch = -1;
	int err;

	if (!undo || !undo->vol)
		return -EINVAL;
	memalloc_flags = memalloc_nofs_save();
	if (undo->lock_bitmap)
		down_write(&undo->vol->mftbmp_lock);
	err = ntfs_bitmap_validate_run_with_mismatch(undo->vol->mftbmp_ino,
			undo->start_bit, undo->count, 1, &first_mismatch);
	if (!err)
		err = __ntfs_bitmap_set_bits_in_run(undo->vol->mftbmp_ino,
				undo->start_bit, undo->count, 0, true);
	if (!err)
		ntfs_inc_free_mft_records(undo->vol, undo->count);
	if (undo->lock_bitmap)
		up_write(&undo->vol->mftbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	if (err) {
		if (first_mismatch >= 0)
			ntfs_error(undo->vol->sb,
				   "Committed MFT bitmap free failed for records 0x%llx-0x%llx (first mismatched record 0x%llx, error %d).",
				   (unsigned long long)undo->start_bit,
				   (unsigned long long)(undo->start_bit +
						undo->count - 1),
				   (unsigned long long)first_mismatch, err);
		else
			ntfs_error(undo->vol->sb,
				   "Committed MFT bitmap free failed for records 0x%llx-0x%llx (error %d).",
				   (unsigned long long)undo->start_bit,
				   (unsigned long long)(undo->start_bit +
						undo->count - 1), err);
	}
	return err;
}

static void ntfs_mft_bitmap_home_release(void *data)
{
	kfree(data);
}

static int ntfs_mft_bitmap_register_free_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		s64 start_bit, s64 count, bool lock_bitmap)
{
	struct ntfs_mft_bitmap_home_undo *undo;
	int err;

	if (!handle || !vol || start_bit < 0 || count <= 0 ||
	    start_bit > S64_MAX - count)
		return -EINVAL;
	undo = kzalloc(sizeof(*undo), GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->vol = vol;
	undo->start_bit = start_bit;
	undo->count = count;
	undo->lock_bitmap = lock_bitmap;
	if (lock_bitmap)
		err = ntfs_log_register_deferred_free(handle,
				ntfs_mft_bitmap_home_restore,
				ntfs_mft_bitmap_home_commit,
				ntfs_mft_bitmap_home_release, undo,
				NTFS_LOG_DEFERRED_MFT, count, sizeof(*undo));
	else
		err = ntfs_log_register_home_undo_with_commit(handle,
				ntfs_mft_bitmap_home_restore,
				ntfs_mft_bitmap_home_commit,
				ntfs_mft_bitmap_home_release, undo);
	if (err)
		ntfs_mft_bitmap_home_release(undo);
	return err;
}

static int ntfs_mft_free_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		const struct mft_record *mrec, bool close_on_commit,
		struct ntfs_mft_free_home_undo **undo_out)
{
	struct ntfs_mft_free_home_undo *undo;
	int err;

	if (!handle || !ni || !mrec || !undo_out)
		return -EINVAL;
	undo = kvzalloc(struct_size(undo, record, ni->vol->mft_record_size),
			GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->vol = ni->vol;
	undo->ni = ni;
	undo->close_on_commit = close_on_commit;
	undo->mft_dirty = NInoDirty(ni);
	memcpy(undo->record, mrec, ni->vol->mft_record_size);
	if (close_on_commit)
		err = ntfs_log_register_home_undo_with_commit(handle,
				ntfs_mft_free_home_restore,
				ntfs_mft_free_home_commit,
				ntfs_mft_free_home_release, undo);
	else
		err = ntfs_log_register_home_undo(handle,
				ntfs_mft_free_home_restore,
				ntfs_mft_free_home_release, undo);
	if (err) {
		kvfree(undo);
		return err;
	}
	*undo_out = undo;
	return 0;
}

static int ntfs_mft_alloc_home_restore(void *data)
{
	struct ntfs_mft_alloc_home_undo *undo = data;
	struct mft_record *m;
	int err = 0;

	m = map_mft_record(undo->ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
	} else {
		memcpy(m, undo->record, undo->vol->mft_record_size);
		err = ntfs_prepare_mft_record_write(undo->ni);
		if (!err) {
			NInoSetDirty(undo->ni);
			err = write_mft_record(undo->ni, m, 1);
		}
		unmap_mft_record(undo->ni);
	}

	/* Extent callers drop their mapped hold before abort. */
	if (undo->close_on_abort) {
		ntfs_inode_close(undo->ni);
		undo->ni = NULL;
		undo->close_on_abort = false;
	}
	return err;
}

static int ntfs_mft_alloc_home_abort(void *data)
{
	struct ntfs_mft_alloc_home_undo *undo = data;
	unsigned int memalloc_flags;
	s64 first_mismatch = -1;
	int err;

	if (!undo || !undo->vol)
		return -EINVAL;
	/* Home restoration may have reopened attributes of this failed create. */
	if (undo->ni)
		ntfs_unhash_inode_attributes(undo->ni);
	memalloc_flags = memalloc_nofs_save();
	if (undo->lock_bitmap)
		down_write(&undo->vol->mftbmp_lock);
	err = ntfs_bitmap_validate_run_with_mismatch(undo->vol->mftbmp_ino,
			undo->mft_no, 1, 1, &first_mismatch);
	if (!err)
		err = __ntfs_bitmap_set_bits_in_run(undo->vol->mftbmp_ino,
				undo->mft_no, 1, 0, true);
	if (undo->lock_bitmap)
		up_write(&undo->vol->mftbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	if (err) {
		if (first_mismatch >= 0)
			ntfs_error(undo->vol->sb,
				   "Aborted MFT allocation bitmap update failed for record 0x%llx (first mismatched record 0x%llx, error %d).",
				   (unsigned long long)undo->mft_no,
				   (unsigned long long)first_mismatch, err);
		else
			ntfs_error(undo->vol->sb,
				   "Aborted MFT allocation bitmap update failed for record 0x%llx (error %d).",
				   (unsigned long long)undo->mft_no, err);
		return err;
	}
	if (undo->counted) {
		ntfs_inc_free_mft_records(undo->vol, 1);
		undo->counted = false;
	}
	return 0;
}

static void ntfs_mft_alloc_home_release(void *data)
{
	kvfree(data);
}

static int ntfs_mft_alloc_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		struct ntfs_inode *ni, u64 mft_no,
		const struct mft_record *disk_record, bool close_on_abort,
		struct ntfs_mft_alloc_home_undo **undo_out)
{
	struct ntfs_mft_alloc_home_undo *undo;
	int err;

	if (!handle || !vol || !ni || !disk_record || !undo_out)
		return -EINVAL;
	undo = kvzalloc(struct_size(undo, record, vol->mft_record_size),
			GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->vol = vol;
	undo->ni = ni;
	undo->mft_no = mft_no;
	undo->close_on_abort = close_on_abort;
	undo->lock_bitmap = mft_no != FILE_MFT;
	memcpy(undo->record, disk_record, vol->mft_record_size);
	if (post_read_mst_fixup((struct ntfs_record *)undo->record,
			vol->mft_record_size)) {
		kvfree(undo);
		return -EIO;
	}
	err = ntfs_log_register_home_undo_with_abort(handle,
			ntfs_mft_alloc_home_restore,
			ntfs_mft_alloc_home_abort,
			ntfs_mft_alloc_home_release, undo);
	if (err) {
		kvfree(undo);
		return err;
	}
	*undo_out = undo;
	return 0;
}

/*
 * ntfs_mft_record_check - Check the consistency of an MFT record
 *
 * Make sure its general fields are safe, then examine all its
 * attributes and apply generic checks to them.
 *
 * Returns 0 if the checks are successful. If not, return -EIO.
 */
int ntfs_mft_record_check(const struct ntfs_volume *vol, struct mft_record *m,
		u64 mft_no)
{
	struct attr_record *a;
	struct super_block *sb = vol->sb;
	u16 attrs_offset;
	u32 bytes_in_use;

	if (!ntfs_is_file_record(m->magic)) {
		ntfs_error(sb, "Record %llu has no FILE magic (0x%x)\n",
				mft_no, le32_to_cpu(*(__le32 *)m));
		goto err_out;
	}

	if (le16_to_cpu(m->usa_ofs) & 0x1 ||
	    (vol->mft_record_size >> NTFS_BLOCK_SIZE_BITS) + 1 != le16_to_cpu(m->usa_count) ||
	    le16_to_cpu(m->usa_ofs) + le16_to_cpu(m->usa_count) * 2 > vol->mft_record_size) {
		ntfs_error(sb, "Record %llu has corrupt fix-up values fields\n",
				mft_no);
		goto err_out;
	}

	if (le32_to_cpu(m->bytes_allocated) != vol->mft_record_size) {
		ntfs_error(sb, "Record %llu has corrupt allocation size (%u <> %u)\n",
				mft_no, vol->mft_record_size,
				le32_to_cpu(m->bytes_allocated));
		goto err_out;
	}

	if (le32_to_cpu(m->bytes_in_use) > vol->mft_record_size) {
		ntfs_error(sb, "Record %llu has corrupt in-use size (%u > %u)\n",
				mft_no, le32_to_cpu(m->bytes_in_use),
				vol->mft_record_size);
		goto err_out;
	}

	if (le16_to_cpu(m->attrs_offset) & 7) {
		ntfs_error(sb, "Attributes badly aligned in record %llu\n",
				mft_no);
		goto err_out;
	}

	attrs_offset = le16_to_cpu(m->attrs_offset);
	bytes_in_use = le32_to_cpu(m->bytes_in_use);

	if (attrs_offset > bytes_in_use ||
	    bytes_in_use - attrs_offset < sizeof_field(struct attr_record, type)) {
		ntfs_error(sb, "Record %llu has corrupt attribute offset\n", mft_no);
		goto err_out;
	}

	a = (struct attr_record *)((char *)m + attrs_offset);
	if ((char *)a < (char *)m || (char *)a > (char *)m + vol->mft_record_size) {
		ntfs_error(sb, "Record %llu is corrupt\n", mft_no);
		goto err_out;
	}

	return 0;

err_out:
	return -EIO;
}

/*
 * map_mft_record_folio - map the folio in which a specific mft record resides
 * @ni:		ntfs inode whose mft record page to map
 *
 * This maps the folio in which the mft record of the ntfs inode @ni is
 * situated.
 *
 * This allocates a new buffer (@ni->mrec), copies the MFT record data from
 * the mapped folio into this buffer, and applies the MST (Multi Sector
 * Transfer) fixups on the copy.
 *
 * The folio is pinned (referenced) in @ni->folio to ensure the data remains
 * valid in the page cache, but the returned pointer is the allocated copy.
 *
 * Return: A pointer to the allocated and fixed-up mft record (@ni->mrec).
 * The return value needs to be checked with IS_ERR(). If it is true,
 * PTR_ERR() contains the negative error code.
 */
static inline struct mft_record *map_mft_record_folio(struct ntfs_inode *ni)
{
	loff_t i_size;
	struct ntfs_volume *vol = ni->vol;
	struct inode *mft_vi = vol->mft_ino;
	struct folio *folio;
	unsigned long index, end_index;
	unsigned int ofs;

	WARN_ON(ni->folio);
	/*
	 * The index into the page cache and the offset within the page cache
	 * page of the wanted mft record.
	 */
	index = NTFS_MFT_NR_TO_PIDX(vol, ni->mft_no);
	ofs = NTFS_MFT_NR_TO_POFS(vol, ni->mft_no);

	i_size = i_size_read(mft_vi);
	/* Growth formats the new records before logging the final MFT EOF. */
	if (NVolReplaying(vol))
		i_size = max_t(loff_t, i_size, NTFS_I(mft_vi)->allocated_size);
	/* The maximum valid index into the page cache for $MFT's data. */
	end_index = i_size >> PAGE_SHIFT;

	/* If the wanted index is out of bounds the mft record doesn't exist. */
	if (unlikely(index >= end_index)) {
		if (index > end_index || (i_size & ~PAGE_MASK) < ofs +
				vol->mft_record_size) {
			folio = ERR_PTR(-ENOENT);
			ntfs_error(vol->sb,
				"Attempt to read mft record 0x%llx, which is beyond the end of the mft. This is probably a bug in the ntfs driver.",
				ni->mft_no);
			goto err_out;
		}
	}

	/* Read, map, and pin the folio. */
	folio = ntfs_read_metadata_folio(mft_vi->i_mapping, index);
	if (!IS_ERR(folio)) {
		u8 *addr;

		/*
		 * MFT writeback unlocks the folio before its private BIO snapshot
		 * completes.  Serialize the copy with both the page-cache update and
		 * the outstanding device write so a newly mapped inode cannot retain
		 * an older record image.
		 */
		folio_lock(folio);
		folio_wait_writeback(folio);
		ni->mrec = kmalloc(vol->mft_record_size, GFP_NOFS);
		if (!ni->mrec) {
			folio_unlock(folio);
			folio_put(folio);
			folio = ERR_PTR(-ENOMEM);
			goto err_out;
		}

		addr = kmap_local_folio(folio, 0);
		memcpy(ni->mrec, addr + ofs, vol->mft_record_size);
		post_read_mst_fixup((struct ntfs_record *)ni->mrec, vol->mft_record_size);

		/*
		 * Catch multi sector transfer fixup errors.  During $LogFile
		 * replay accept the record even if it is not (yet) a valid FILE
		 * record: InitializeFileRecordSegment redo maps a freshly
		 * allocated, still-zeroed record in order to write its initial
		 * contents.  Redo ops that need a valid record re-check the
		 * magic themselves (see ntfs_redo_apply_mft_record() and
		 * ntfs_is_file_record() in the locate helpers).
		 */
		if (NVolReplaying(vol) ||
		    !ntfs_mft_record_check(vol, (struct mft_record *)ni->mrec, ni->mft_no)) {
			kunmap_local(addr);
			folio_unlock(folio);
			ni->folio = folio;
			ni->folio_ofs = ofs;
			return ni->mrec;
		}
		kunmap_local(addr);
		folio_unlock(folio);
		folio_put(folio);
		kfree(ni->mrec);
		ni->mrec = NULL;
		folio = ERR_PTR(-EIO);
		NVolSetErrors(vol);
	}
err_out:
	ni->folio = NULL;
	ni->folio_ofs = 0;
	return (struct mft_record *)folio;
}

/*
 * Map an MFT record from a folio/page which the caller already owns and has
 * locked.  The caller's mapping reference is retained for the inode.
 */
static struct mft_record *map_mft_record_from_locked(
		struct ntfs_inode *ni,
		const struct ntfs_mft_locked_record *locked)
{
	struct ntfs_volume *vol = ni->vol;

	ni->mrec = kmalloc(vol->mft_record_size, GFP_NOFS);
	if (!ni->mrec)
		return ERR_PTR(-ENOMEM);
	memcpy(ni->mrec, locked->mrec, vol->mft_record_size);
	post_read_mst_fixup((struct ntfs_record *)ni->mrec,
			vol->mft_record_size);
	if (NVolReplaying(vol) ||
			!ntfs_mft_record_check(vol, (struct mft_record *)ni->mrec,
			ni->mft_no)) {
		folio_get(locked->folio);
		ni->folio = locked->folio;
		ni->folio_ofs = locked->ofs;
		/* Account for the mapping reference just installed above. */
		atomic_inc(&ni->count);
		return ni->mrec;
	}

	kfree(ni->mrec);
	ni->mrec = NULL;
	NVolSetErrors(vol);
	return ERR_PTR(-EIO);
}

/*
 * map_mft_record - map and pin an mft record
 * @ni:		ntfs inode whose MFT record to map
 *
 * This function ensures the MFT record for the given inode is mapped and
 * accessible.
 *
 * It increments the reference count of the ntfs inode. If the record is
 * already mapped (@ni->folio is set), it returns the cached record
 * immediately.
 *
 * Otherwise, it calls map_mft_record_folio() to read the folio from disk
 * (if necessary via read_mapping_folio), allocate a buffer, and copy the
 * record data.
 *
 * Return: A pointer to the mft record. You need to check the returned
 * pointer with IS_ERR().
 */
struct mft_record *map_mft_record(struct ntfs_inode *ni)
{
	struct mft_record *m;

	if (!ni)
		return ERR_PTR(-EINVAL);

	ntfs_debug("Entering for mft_no 0x%llx.", ni->mft_no);

	/* Make sure the ntfs inode doesn't go away. */
	atomic_inc(&ni->count);

	if (ni->folio)
		return (struct mft_record *)ni->mrec;

	m = map_mft_record_folio(ni);
	if (!IS_ERR(m))
		return m;

	atomic_dec(&ni->count);
	if (PTR_ERR(m) != -EINTR && PTR_ERR(m) != -ERESTARTSYS)
		ntfs_error(ni->vol->sb, "Failed with error code %lu.", -PTR_ERR(m));
	return m;
}

/*
 * unmap_mft_record - release a reference to a mapped mft record
 * @ni:		ntfs inode whose MFT record to unmap
 *
 * This decrements the reference count of the ntfs inode.
 *
 * It releases the caller's hold on the inode. If the reference count indicates
 * that there are still other users (count > 1), the function returns
 * immediately, keeping the resources (folio and mrec buffer) pinned for
 * those users.
 *
 * NOTE: If caller has modified the mft record, it is imperative to set the mft
 * record dirty BEFORE calling unmap_mft_record().
 */
void unmap_mft_record(struct ntfs_inode *ni)
{
	struct folio *folio;

	if (!ni)
		return;

	ntfs_debug("Entering for mft_no 0x%llx.", ni->mft_no);

	folio = ni->folio;
	if (atomic_dec_return(&ni->count) > 1)
		return;
	WARN_ON(!folio);
}

/*
 * map_extent_mft_record - load an extent inode and attach it to its base
 * @base_ni:	base ntfs inode
 * @mref:	mft reference of the extent inode to load
 * @ntfs_ino:	on successful return, pointer to the struct ntfs_inode structure
 *
 * Load the extent mft record @mref and attach it to its base inode @base_ni.
 * Return the mapped extent mft record if IS_ERR(result) is false.  Otherwise
 * PTR_ERR(result) gives the negative error code.
 *
 * On successful return, @ntfs_ino contains a pointer to the ntfs_inode
 * structure of the mapped extent inode.
 */
static struct mft_record *__map_extent_mft_record(struct ntfs_inode *base_ni,
		u64 mref, struct ntfs_inode **ntfs_ino,
		const struct ntfs_mft_locked_record *locked)
{
	struct mft_record *m;
	struct ntfs_inode *ni = NULL;
	struct ntfs_inode **extent_nis = NULL;
	int i;
	u64 mft_no = MREF(mref);
	u16 seq_no = MSEQNO(mref);
	bool destroy_ni = false;

	ntfs_debug("Mapping extent mft record 0x%llx (base mft record 0x%llx).",
			mft_no, base_ni->mft_no);
	/* Make sure the base ntfs inode doesn't go away. */
	atomic_inc(&base_ni->count);
	/*
	 * Check if this extent inode has already been added to the base inode,
	 * in which case just return it. If not found, add it to the base
	 * inode before returning it.
	 */
retry:
	mutex_lock(&base_ni->extent_lock);
	if (base_ni->nr_extents > 0) {
		extent_nis = base_ni->ext.extent_ntfs_inos;
		for (i = 0; i < base_ni->nr_extents; i++) {
			if (mft_no != extent_nis[i]->mft_no)
				continue;
			ni = extent_nis[i];
			/* Make sure the ntfs inode doesn't go away. */
			atomic_inc(&ni->count);
			break;
		}
	}
	if (likely(ni != NULL)) {
		mutex_unlock(&base_ni->extent_lock);
		atomic_dec(&base_ni->count);
		/* We found the record; just have to map and return it. */
		m = map_mft_record(ni);
		/* map_mft_record() has incremented this on success. */
		atomic_dec(&ni->count);
		if (!IS_ERR(m)) {
			/* Verify the sequence number. */
			if (likely(le16_to_cpu(m->sequence_number) == seq_no)) {
				ntfs_debug("Done 1.");
				*ntfs_ino = ni;
				return m;
			}
			unmap_mft_record(ni);
			ntfs_error(base_ni->vol->sb,
					"Found stale extent mft reference! Corrupt filesystem. Run chkdsk.");
			return ERR_PTR(-EIO);
		}
map_err_out:
		ntfs_error(base_ni->vol->sb,
				"Failed to map extent mft record, error code %ld.",
				-PTR_ERR(m));
		return m;
	}
	mutex_unlock(&base_ni->extent_lock);

	/* Record wasn't there. Get a new ntfs inode and initialize it. */
	ni = ntfs_new_extent_inode(base_ni->vol->sb, mft_no);
	if (unlikely(!ni)) {
		atomic_dec(&base_ni->count);
		return ERR_PTR(-ENOMEM);
	}
	ni->vol = base_ni->vol;
	ni->seq_no = seq_no;
	ni->nr_extents = -1;
	ni->ext.base_ntfs_ino = base_ni;
	/* Now map the record, reusing the caller's locked mapping if supplied. */
	if (locked)
		m = map_mft_record_from_locked(ni, locked);
	else
		m = map_mft_record(ni);
	if (IS_ERR(m)) {
		atomic_dec(&base_ni->count);
		ntfs_clear_extent_inode(ni);
		goto map_err_out;
	}
	/* Verify the sequence number if it is present. */
	if (seq_no && (le16_to_cpu(m->sequence_number) != seq_no)) {
		ntfs_error(base_ni->vol->sb,
				"Found stale extent mft reference! Corrupt filesystem. Run chkdsk.");
		destroy_ni = true;
		m = ERR_PTR(-EIO);
		goto unm_nolock_err_out;
	}

	mutex_lock(&base_ni->extent_lock);
	for (i = 0; i < base_ni->nr_extents; i++) {
		if (mft_no == extent_nis[i]->mft_no) {
			mutex_unlock(&base_ni->extent_lock);
			ntfs_clear_extent_inode(ni);
			goto retry;
		}
	}
	/* Attach extent inode to base inode, reallocating memory if needed. */
	if (!(base_ni->nr_extents & 3)) {
		struct ntfs_inode **tmp;
		int new_size = (base_ni->nr_extents + 4) * sizeof(struct ntfs_inode *);

		tmp = kvzalloc(new_size, GFP_NOFS);
		if (unlikely(!tmp)) {
			ntfs_error(base_ni->vol->sb, "Failed to allocate internal buffer.");
			destroy_ni = true;
			m = ERR_PTR(-ENOMEM);
			goto unm_err_out;
		}
		if (base_ni->nr_extents) {
			WARN_ON(!base_ni->ext.extent_ntfs_inos);
			memcpy(tmp, base_ni->ext.extent_ntfs_inos, new_size -
					4 * sizeof(struct ntfs_inode *));
			kvfree(base_ni->ext.extent_ntfs_inos);
		}
		base_ni->ext.extent_ntfs_inos = tmp;
	}
	base_ni->ext.extent_ntfs_inos[base_ni->nr_extents++] = ni;
	mutex_unlock(&base_ni->extent_lock);
	atomic_dec(&base_ni->count);
	ntfs_debug("Done 2.");
	*ntfs_ino = ni;
	return m;
unm_err_out:
	mutex_unlock(&base_ni->extent_lock);
unm_nolock_err_out:
	unmap_mft_record(ni);
	atomic_dec(&base_ni->count);
	/*
	 * If the extent inode was not attached to the base inode we need to
	 * release it or we will leak memory.
	 */
	if (destroy_ni)
		ntfs_clear_extent_inode(ni);
	return m;
}

static struct mft_record *map_extent_mft_record_from_locked(
		struct ntfs_inode *base_ni, u64 mref,
		struct ntfs_inode **ntfs_ino,
		const struct ntfs_mft_locked_record *locked)
{
	return __map_extent_mft_record(base_ni, mref, ntfs_ino, locked);
}

struct mft_record *map_extent_mft_record(struct ntfs_inode *base_ni, u64 mref,
		struct ntfs_inode **ntfs_ino)
{
	return __map_extent_mft_record(base_ni, mref, ntfs_ino, NULL);
}

/*
 * __mark_mft_record_dirty - mark the base vfs inode dirty
 * @ni:		ntfs inode describing the mapped mft record
 *
 * Internal function.  Users should call mark_mft_record_dirty() instead.
 *
 * This function determines the base ntfs inode (in case @ni is an extent
 * inode) and marks the corresponding VFS inode dirty.
 *
 * NOTE:  We only set I_DIRTY_DATASYNC (and not I_DIRTY_PAGES)
 * on the base vfs inode, because even though file data may have been modified,
 * it is dirty in the inode meta data rather than the data page cache of the
 * inode, and thus there are no data pages that need writing out.  Therefore, a
 * full mark_inode_dirty() is overkill.  A mark_inode_dirty_sync(), on the
 * other hand, is not sufficient, because ->write_inode needs to be called even
 * in case of fdatasync. This needs to happen or the file data would not
 * necessarily hit the device synchronously, even though the vfs inode has the
 * O_SYNC flag set.  Also, I_DIRTY_DATASYNC simply "feels" better than just
 * I_DIRTY_SYNC, since the file data has not actually hit the block device yet,
 * which is not what I_DIRTY_SYNC on its own would suggest.
 */
void __mark_mft_record_dirty(struct ntfs_inode *ni)
{
	struct ntfs_inode *base_ni;

	ntfs_debug("Entering for inode 0x%llx.", ni->mft_no);
	WARN_ON(NInoAttr(ni));
	/* Determine the base vfs inode and mark it dirty, too. */
	if (likely(ni->nr_extents >= 0))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	__mark_inode_dirty(VFS_I(base_ni), I_DIRTY_DATASYNC);
}

struct ntfs_mft_io_unit {
	sector_t sector;
	unsigned int folio_ofs;
	unsigned int len;
};

struct ntfs_mft_write_ctx {
	struct folio *folio;
	struct page *io_page;
	struct address_space *mapping;
	struct ntfs_volume *vol;
	struct completion *done;
	int error;
	bool writeback_started;
	struct bio bio;
};

static struct bio_set ntfs_mft_bioset;

int ntfs_mft_bioset_init(void)
{
	return bioset_init(&ntfs_mft_bioset, BIO_POOL_SIZE,
			   offsetof(struct ntfs_mft_write_ctx, bio),
			   BIOSET_NEED_BVECS);
}

void ntfs_mft_bioset_exit(void)
{
	bioset_exit(&ntfs_mft_bioset);
}

static void ntfs_mft_end_io(struct bio *bio)
{
	struct ntfs_mft_write_ctx *ctx =
		container_of(bio, struct ntfs_mft_write_ctx, bio);
	struct folio *folio = ctx->folio;
	struct completion *done = ctx->done;
	int err;

	if (bio->bi_status)
		err = blk_status_to_errno(bio->bi_status);
	else
		err = ctx->error;
	if (err) {
		mapping_set_error(ctx->mapping, err);
		NVolSetErrors(ctx->vol);
		ntfs_error(ctx->vol->sb, "I/O error while writing MFT: %d",
			   err);
	}

	__free_page(ctx->io_page);
	if (!done)
		bio_put(bio);
	folio_end_writeback(folio);
	folio_put(folio);
	if (done)
		complete(done);
}

static void ntfs_start_mft_writeback(struct ntfs_mft_write_ctx *ctx)
{
	if (ctx->writeback_started)
		return;

	inode_attach_wb(ctx->mapping->host, NULL);
	folio_get(ctx->folio);
	folio_start_writeback(ctx->folio);
	ctx->writeback_started = true;
}

static struct bio *ntfs_alloc_mft_parent_bio(struct ntfs_volume *vol,
					     struct folio *folio,
					     struct completion *done)
{
	struct ntfs_mft_write_ctx *ctx;
	struct bio *parent;

	parent = bio_alloc_bioset(vol->sb->s_bdev, 1, REQ_OP_WRITE, GFP_NOIO,
				  &ntfs_mft_bioset);
	if (!parent)
		return NULL;

	ctx = container_of(parent, struct ntfs_mft_write_ctx, bio);
	ctx->io_page = alloc_page(GFP_NOIO);
	if (!ctx->io_page) {
		bio_put(parent);
		return NULL;
	}
	copy_highpage(ctx->io_page, &folio->page);
	ctx->folio = folio;
	ctx->mapping = folio->mapping;
	ctx->vol = vol;
	ctx->done = done;
	ctx->error = 0;
	ctx->writeback_started = false;
	parent->bi_end_io = ntfs_mft_end_io;
	return parent;
}

static void ntfs_free_mft_parent_bio(struct bio *bio)
{
	struct ntfs_mft_write_ctx *ctx =
		container_of(bio, struct ntfs_mft_write_ctx, bio);

	__free_page(ctx->io_page);
	bio_put(bio);
}

/*
 * Write one MFT I/O unit to $MFTMirr.  The source folio contains the MST
 * protected image that will be written to $MFT.
 */
static int ntfs_sync_mft_mirror_unit(struct ntfs_volume *vol,
				     struct folio *source, u64 mirror_file_ofs,
				     const struct ntfs_mft_io_unit *unit)
{
	struct folio *mirror;
	struct bio_vec bvec;
	struct bio bio;
	u64 mirror_size;
	unsigned int mirror_ofs;
	u8 *src, *dst;
	int err;

	if (unlikely(!vol->mftmirr_ino))
		return -EIO;

	mirror_size = (u64)vol->mftmirr_size * vol->mft_record_size;
	if (mirror_file_ofs >= mirror_size ||
	    unit->len > mirror_size - mirror_file_ofs)
		return -EIO;
	if (unit->folio_ofs + unit->len > folio_size(source))
		return -EIO;

	mirror = ntfs_read_metadata_folio(vol->mftmirr_ino->i_mapping,
					  mirror_file_ofs >> PAGE_SHIFT);
	if (IS_ERR(mirror))
		return PTR_ERR(mirror);

	folio_lock(mirror);
	if (folio_test_writeback(mirror))
		folio_wait_writeback(mirror);
	mirror_ofs = mirror_file_ofs - folio_pos(mirror);
	if (mirror_ofs + unit->len > folio_size(mirror)) {
		err = -EIO;
		goto out_unlock;
	}

	folio_clear_uptodate(mirror);
	src = kmap_local_folio(source, unit->folio_ofs);
	dst = kmap_local_folio(mirror, mirror_ofs);
	memcpy(dst, src, unit->len);
	kunmap_local(dst);
	kunmap_local(src);

	bio_init(&bio, vol->sb->s_bdev, &bvec, 1, REQ_OP_WRITE);
	bio.bi_iter.bi_sector = ntfs_bytes_to_bio_sector(
		NTFS_CLU_TO_B(vol, vol->mftmirr_lcn) + mirror_file_ofs);
	if (!bio_add_folio(&bio, mirror, unit->len, mirror_ofs))
		err = -EIO;
	else
		err = submit_bio_wait(&bio);
	bio_uninit(&bio);

	/*
	 * The in-memory mirror is now valid because we just memcpy()'d the
	 * mst-protected mft record into it.  Mark the folio uptodate even on
	 * write error so a subsequent read_mapping_folio() does not refetch
	 * the stale on-disk mirror and overwrite this copy.  The error is
	 * propagated to the caller via @err.
	 */
	folio_mark_uptodate(mirror);

out_unlock:
	folio_unlock(mirror);
	folio_put(mirror);
	return err;
}

/* Restore the mirror from the primary MFT after journal replay. */
int ntfs_resync_mft_mirror(struct ntfs_volume *vol)
{
	struct address_space *mapping = vol->mft_ino->i_mapping;
	u64 bytes = (u64)vol->mftmirr_size * vol->mft_record_size;
	u64 pos;
	int err;

	err = filemap_write_and_wait(mapping);
	if (err)
		return err;
	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		return -EIO;

	for (pos = 0; pos < bytes; pos += PAGE_SIZE) {
		struct ntfs_mft_io_unit unit = {
			.len = min_t(u64, bytes - pos, PAGE_SIZE),
		};
		struct folio *folio;

		folio = ntfs_read_metadata_folio(mapping, pos >> PAGE_SHIFT);
		if (IS_ERR(folio))
			return PTR_ERR(folio);
		folio_lock(folio);
		folio_wait_writeback(folio);
		unit.folio_ofs = offset_in_folio(folio, pos);
		err = ntfs_sync_mft_mirror_unit(vol, folio, pos, &unit);
		folio_unlock(folio);
		folio_put(folio);
		if (err)
			return err;
	}
	return blkdev_issue_flush(vol->sb->s_bdev);
}

int ntfs_prepare_mft_record_write(struct ntfs_inode *ni)
{
	struct ntfs_inode *mft_ni = NTFS_I(ni->vol->mft_ino);
	int err;

	if (likely(ni->mft_lcn_count &&
		   ni->mft_lcn[0] != LCN_RL_NOT_MAPPED))
		return 0;

	down_read(&mft_ni->runlist.lock);
	err = ntfs_get_block_mft_record(mft_ni, ni);
	up_read(&mft_ni->runlist.lock);
	if (err)
		return err;

	if (WARN_ON_ONCE(!ni->mft_lcn_count))
		return -EIO;

	return 0;
}

static int ntfs_sync_mft_mirror_record(struct ntfs_volume *vol,
				       struct folio *source, const u64 mft_no)
{
	u64 mirror_file_ofs = (u64)mft_no * vol->mft_record_size;
	struct ntfs_mft_io_unit unit = {
		.folio_ofs = NTFS_MFT_NR_TO_POFS(vol, mft_no),
		.len = vol->mft_record_size,
	};

	mirror_file_ofs =
		round_down(mirror_file_ofs, (u64)vol->mft_io_unit_size);
	unit.folio_ofs = round_down(unit.folio_ofs, vol->mft_io_unit_size);
	unit.len = vol->mft_io_unit_size;

	return ntfs_sync_mft_mirror_unit(vol, source, mirror_file_ofs, &unit);
}

static int ntfs_prepare_mft_record_io_units(struct ntfs_inode *ni,
					    struct ntfs_mft_io_unit units[2])
{
	struct ntfs_volume *vol = ni->vol;
	u64 record_byte = (u64)ni->mft_no * vol->mft_record_size;
	u64 disk_byte;
	unsigned int nr_units = ni->mft_lcn_count;
	unsigned int cluster_ofs;
	unsigned int i;

	if (!nr_units || nr_units > ARRAY_SIZE(ni->mft_lcn))
		return -EIO;
	for (i = 0; i < nr_units; i++)
		if (ni->mft_lcn[i] < 0)
			return -EIO;

	cluster_ofs = ntfs_bytes_to_cluster_off(vol, record_byte);
	if (vol->mft_io_unit_size > vol->mft_record_size) {
		cluster_ofs = round_down(cluster_ofs, vol->mft_io_unit_size);
		disk_byte = NTFS_CLU_TO_B(vol, ni->mft_lcn[0]) + cluster_ofs;
		units[0] = (struct ntfs_mft_io_unit){
			.sector = ntfs_bytes_to_bio_sector(disk_byte),
			.folio_ofs = round_down(ni->folio_ofs,
						vol->mft_io_unit_size),
			.len = vol->mft_io_unit_size,
		};
		return 1;
	}

	disk_byte = NTFS_CLU_TO_B(vol, ni->mft_lcn[0]) + cluster_ofs;
	units[0] = (struct ntfs_mft_io_unit){
		.sector = ntfs_bytes_to_bio_sector(disk_byte),
		.folio_ofs = ni->folio_ofs,
		.len = vol->mft_record_size,
	};
	if (nr_units == 1)
		return 1;

	units[0].len = vol->cluster_size;
	disk_byte = NTFS_CLU_TO_B(vol, ni->mft_lcn[1]);
	units[1] = (struct ntfs_mft_io_unit){
		.sector = ntfs_bytes_to_bio_sector(disk_byte),
		.folio_ofs = ni->folio_ofs + vol->cluster_size,
		.len = vol->mft_record_size - vol->cluster_size,
	};
	return 2;
}

/*
 * write_mft_record_nolock - write out a mapped (extent) mft record
 * @ni:		ntfs inode describing the mapped (extent) mft record
 * @m:		mapped (extent) mft record to write
 * @sync:	if true, wait for i/o completion
 *
 * Write the mapped (extent) mft record @m described by the (regular or extent)
 * ntfs inode @ni to backing store.  If the mft record @m has a counterpart in
 * the mft mirror, that is also updated.
 *
 * We only write the mft record if the ntfs inode @ni is dirty.
 *
 * On success, clean the mft record and return 0.  On ENOMEM, redirty the
 * record so it can be retried.  Asynchronous callers return success after
 * redirtying while synchronous callers receive the error.  For other errors,
 * mark the volume with errors.
 *
 * The BIO uses a private snapshot, and PG_writeback serializes later writers
 * until the I/O completes.
 */
int write_mft_record_nolock(struct ntfs_inode *ni, struct mft_record *m, int sync)
{
	struct ntfs_volume *vol = ni->vol;
	struct folio *folio = ni->folio;
	DECLARE_COMPLETION_ONSTACK(done);
	struct ntfs_mft_io_unit units[2];
	struct ntfs_mft_write_ctx *ctx;
	struct bio *parent, *child = NULL;
	unsigned int nr_units;
	int err = 0;
	u8 *kaddr;
	struct mft_record *fixup_m;
	bool dirty;

	ntfs_debug("Entering for inode 0x%llx.", ni->mft_no);

	WARN_ON(NInoAttr(ni));
	WARN_ON(!folio_test_locked(folio));
	if (WARN_ON_ONCE(!ni->mft_lcn_count))
		return -EIO;

	if (folio_test_writeback(folio))
		folio_wait_writeback(folio);

	/*
	 * If the struct ntfs_inode is clean no need to do anything.  If it is dirty,
	 * mark it as clean now so that it can be redirtied later on if needed.
	 * There is no danger of races since the caller is holding the locks
	 * for the mft record @m and the page it is in.
	 */
	dirty = NInoTestClearDirty(ni);
	if (!dirty)
		goto done;

	err = ntfs_prepare_mft_record_io_units(ni, units);
	if (err < 0)
		goto err_out;
	nr_units = err;

	kaddr = kmap_local_folio(folio, 0);
	fixup_m = (struct mft_record *)(kaddr + ni->folio_ofs);
	memcpy(fixup_m, m, vol->mft_record_size);

	/* Apply the mst protection fixups. */
	err = pre_write_mst_fixup((struct ntfs_record *)fixup_m, vol->mft_record_size);
	if (err) {
		ntfs_error(vol->sb, "Failed to apply mst fixups!");
		goto unmap_err_out;
	}

	err = ntfs_log_writeback_lsn(vol, le64_to_cpu(m->lsn), sync);
	if (!err && units[0].len > vol->mft_record_size)
		err = ntfs_mft_wait_page_log(vol, kaddr, folio->index,
				units[0].folio_ofs, units[0].len, sync);
	if (err) {
		if (err == -EAGAIN) {
			folio_mark_dirty(folio);
			kunmap_local(kaddr);
			return 0;
		}
		mark_mft_record_dirty(ni);
		goto unmap_err_out;
	}

	parent = ntfs_alloc_mft_parent_bio(vol, folio, sync ? &done : NULL);
	if (!parent) {
		err = -ENOMEM;
		goto unmap_err_out;
	}
	ctx = container_of(parent, struct ntfs_mft_write_ctx, bio);

	parent->bi_iter.bi_sector = units[0].sector;
	if (!bio_add_page(parent, ctx->io_page, units[0].len,
			  units[0].folio_ofs)) {
		err = -EIO;
		goto put_bios_out;
	}

	if (nr_units == 2) {
		if (bio_end_sector(parent) != units[1].sector ||
		    !bio_add_page(parent, ctx->io_page, units[1].len,
				  units[1].folio_ofs)) {
			child = bio_alloc(vol->sb->s_bdev, 1, REQ_OP_WRITE,
					  GFP_NOIO);
			if (!child) {
				err = -ENOMEM;
				goto put_bios_out;
			}
			child->bi_iter.bi_sector = units[1].sector;
			if (!bio_add_page(child, ctx->io_page, units[1].len,
					  units[1].folio_ofs)) {
				err = -EIO;
				goto put_bios_out;
			}
		}
	}

	if (ni->mft_no < vol->mftmirr_size) {
		err = ntfs_sync_mft_mirror_record(vol, page_folio(ctx->io_page),
						  ni->mft_no);
		if (err)
			ctx->error = err;
	}

	kunmap_local(kaddr);

	ntfs_start_mft_writeback(ctx);
	if (child) {
		bio_chain(child, parent);
		submit_bio(child);
	}
	submit_bio(parent);

	if (sync) {
		wait_for_completion(&done);
		if (!err && parent->bi_status)
			err = blk_status_to_errno(parent->bi_status);
		bio_put(parent);
	}

	if (unlikely(err)) {
		/* I/O error during writing.  This is really bad! */
		ntfs_error(vol->sb,
			"I/O error while writing mft record 0x%llx!  Marking base inode as bad.  You should unmount the volume and run chkdsk.",
			ni->mft_no);
		return err;
	}
done:
	ntfs_debug("Done.");
	return 0;
put_bios_out:
	if (child)
		bio_put(child);
	ntfs_free_mft_parent_bio(parent);
unmap_err_out:
	kunmap_local(kaddr);
err_out:
	/*
	 * The caller should mark the base inode as bad so no more I/O
	 * happens. ->drop_inode() will still be invoked so all extent inodes
	 * and other allocated memory will be freed. ENOMEM is retried by
	 * redirtying the mft record below.
	 */
	if (err == -ENOMEM) {
		ntfs_error(vol->sb,
			"Not enough memory to write mft record. Redirtying so the write is retried later.");
		mark_mft_record_dirty(ni);
		if (!sync)
			err = 0;
	} else
		NVolSetErrors(vol);
	return err;
}

static int ntfs_test_inode_wb(struct inode *vi, u64 ino, void *data)
{
	struct ntfs_attr *na = data;

	if (!ntfs_test_inode(vi, na))
		return 0;

	/*
	 * An open unlinked inode can still have a committed, in-use image to
	 * checkpoint.  Pin it while writeback holds its mrec lock. The caller
	 * drops the reference only after releasing the MFT folio.
	 */
	if (NInoBeingDeleted(NTFS_I(vi))) {
		if (igrab(vi))
			return 1;
		na->state = NI_BeingDeleted;
		return -1;
	}

	/*
	 * This condition can prevent ntfs_write_mst_block()
	 * from applying/undo fixups while ntfs_create() being
	 * called
	 */
	spin_lock(&vi->i_lock);
	if (inode_state_read_once(vi) & I_CREATING) {
		spin_unlock(&vi->i_lock);
		na->state = NI_BeingCreated;
		return -1;
	}
	spin_unlock(&vi->i_lock);

	return igrab(vi) ? 1 : -1;
}

/*
 * ntfs_may_write_mft_record - check if an mft record may be written out
 * @vol:	[IN]  ntfs volume on which the mft record to check resides
 * @mft_no:	[IN]  mft record number of the mft record to check
 * @m:		[IN]  mapped mft record to check
 * @locked_ni:	[OUT] caller has to unlock this ntfs inode if one is returned
 * @ref_vi:	[OUT] caller has to drop this vfs inode if one is returned
 *
 * Check if the mapped (base or extent) mft record @m with mft record number
 * @mft_no belonging to the ntfs volume @vol may be written out.  If necessary
 * and possible the ntfs inode of the mft record is locked and the base vfs
 * inode is pinned.  The locked ntfs inode is then returned in @locked_ni.  The
 * caller is responsible for unlocking the ntfs inode and unpinning the base
 * vfs inode.
 *
 * To avoid deadlock when the caller holds a folio lock, if the function
 * returns @ref_vi it defers dropping the vfs inode reference by returning
 * it in @ref_vi instead of calling iput() directly.  The caller must call
 * iput() on @ref_vi after releasing the folio lock.
 *
 * Return 'true' if the mft record may be written out by this path and 'false'
 * if direct inode writeback owns it.
 *
 * The caller has locked the page and cleared the uptodate flag on it which
 * means that we can safely write out any dirty mft records that do not have
 * their inodes in icache as determined by find_inode_nowait().
 *
 * Here is a description of the tests we perform:
 *
 * If the inode is found in icache we know the mft record must be a base mft
 * record.  If it is dirty, we do not write it and return 'false' as the vfs
 * inode write paths will result in the access times being updated which would
 * cause the base mft record to be redirtied and written out again.
 *
 * If the inode is in icache and not dirty, we attempt to lock the mft record
 * and if we find the lock was already taken, it is not safe to write the mft
 * record and we return 'false'.
 *
 * If we manage to obtain the lock we have exclusive access to the mft record,
 * which also allows us safe writeout of the mft record.  We then set
 * @locked_ni to the locked ntfs inode and return 'true'.
 *
 * Note we cannot just lock the mft record and sleep while waiting for the lock
 * because this would deadlock due to lock reversal.
 *
 * If the inode is not in icache, the locked $MFT folio is the writeback
 * source.  This includes extent records whose asynchronous writes have
 * already staged a protected image there.
 */
static bool ntfs_may_write_mft_record(struct ntfs_volume *vol, const u64 mft_no,
		const struct mft_record *m, struct ntfs_inode **locked_ni,
		struct inode **ref_vi)
{
	struct super_block *sb = vol->sb;
	struct inode *mft_vi = vol->mft_ino;
	struct inode *vi;
	struct ntfs_inode *ni;
	struct ntfs_attr na = {0};

	ntfs_debug("Entering for inode 0x%llx.", mft_no);
	/*
	 * Normally we do not return a locked inode so set @locked_ni to NULL.
	 */
	*locked_ni = NULL;
	*ref_vi = NULL;
	/*
	 * A retired record is authoritative in the MFT page cache.  In
	 * particular, do not let an inode which is still being torn down (and
	 * whose mrec_lock may still be held by the retirement transaction) defer
	 * this free image indefinitely.  Leaving it dirty without submitting it
	 * allows the page to be reclaimed and exposes the old on-disk IN_USE
	 * image to the allocator.
	 */
	if (ntfs_is_file_record(m->magic) &&
			!(m->flags & MFT_RECORD_IN_USE)) {
		return true;
	}

	/*
	 * Check if the inode corresponding to this mft record is in the VFS
	 * inode cache and obtain a reference to it if it is.
	 */
	ntfs_debug("Looking for inode 0x%llx in icache.", mft_no);
	na.mft_no = mft_no;
	na.type = AT_UNUSED;
	/*
	 * Optimize inode 0, i.e. $MFT itself, since we have it in memory and
	 * we get here for it rather often.
	 */
	if (!mft_no) {
		/*
		 * During final iput(), write_inode_now() can write the $MFT
		 * mapping after the inode has entered I_WILL_FREE.  In that
		 * case igrab() must fail. The writeback itself keeps the inode
		 * alive and no other user can modify its private record.
		 */
		vi = igrab(mft_vi);
		if (!vi)
			return true;
	} else {
		/*
		 * Have to use find_inode_nowait() since ilookup5_nowait()
		 * waits for inode with I_FREEING, which causes ntfs to deadlock
		 * when inodes are unlinked concurrently
		 */
		vi = find_inode_nowait(sb, mft_no, ntfs_test_inode_wb, &na);
		if (na.state == NI_BeingCreated)
			return false;
		if (na.state == NI_BeingDeleted) {
			/*
			 * Do not write an old, still-in-use image from an inode which is
			 * being deleted.  The delete transaction may have cleared the
			 * page-cache image already, in which case raw writeback is safe,
			 * but writing the old image after the MFT bitmap was cleared can
			 * make a free record appear to be in use again.
			 */
			if (m->flags & MFT_RECORD_IN_USE)
				return false;
			return true;
		}
	}
	if (vi) {
		ntfs_debug("Base inode 0x%llx is in icache.", mft_no);
		/* The inode is in icache. */
		ni = NTFS_I(vi);
		/* Take a reference to the ntfs inode. */
		atomic_inc(&ni->count);
		/* If the inode is dirty, do not write this record. */
		if (NInoDirty(ni)) {
			ntfs_debug("Inode 0x%llx is dirty, do not write it.",
					mft_no);
			atomic_dec(&ni->count);
			*ref_vi = vi;
			return false;
		}
		ntfs_debug("Inode 0x%llx is not dirty.", mft_no);
		/* The inode is not dirty, try to take the mft record lock. */
		if (unlikely(!mutex_trylock(&ni->mrec_lock))) {
			ntfs_debug("Mft record 0x%llx is already locked, do not write it.", mft_no);
			atomic_dec(&ni->count);
			*ref_vi = vi;
			return false;
		}
		ntfs_debug("Managed to lock mft record 0x%llx, write it.",
				mft_no);
		/*
		 * The write has to occur while we hold the mft record lock so
		 * return the locked ntfs inode and its vfs inode reference.
		 */
		*locked_ni = ni;
		*ref_vi = vi;
		return true;
	}
	ntfs_debug("Inode 0x%llx is not in icache.", mft_no);
	/* The inode is not in icache. */
	/* Write the record if it is not a mft record (type "FILE"). */
	if (!ntfs_is_mft_record(m->magic)) {
		ntfs_debug("Mft record 0x%llx is not a FILE record, write it.",
				mft_no);
		return true;
	}
	/* Write the mft record if it is a base inode. */
	if (!m->base_mft_record) {
		ntfs_debug("Mft record 0x%llx is a base record, write it.",
				mft_no);
		return true;
	}
	/*
	 * Asynchronous extent writes stage their protected image in the $MFT
	 * folio and leave it dirty for this writeback path.  There is no VFS
	 * inode for an extent to find above, so skipping it here would prevent
	 * that staged image from ever reaching disk.  The caller holds the
	 * folio lock and submits a private BIO snapshot.
	 */
	ntfs_debug("Mft record 0x%llx is an extent record, write it.",
		   mft_no);
	return true;
}

static const char *es = "  Leaving inconsistent metadata.  Unmount and run chkdsk.";

#define FIRST_NORMAL_MFT_RECORD	24
#define MFT_RECORD_RESERVE	4
#define MFT_RECORD_INIT_BATCH	16
#define MFT_RECORD_INIT_MEDIUM_BATCH	64
#define MFT_RECORD_INIT_LARGE_BATCH	256
#define MFT_BITMAP_INIT_MIN_BYTES	8
#define MFT_GROWTH_MAX_RUNS	16

/* Keep optional initialization within both allocation and bitmap coverage. */
static s64 ntfs_mft_initialized_batch_end(s64 initialized_size,
		s64 required_size, s64 allocated_size, s64 bitmap_records,
		u8 record_size_bits, u32 batch_records)
{
	s64 initialized_records = initialized_size >> record_size_bits;
	s64 end_records = initialized_records + batch_records;

	end_records = min_t(s64, end_records,
			allocated_size >> record_size_bits);
	end_records = min_t(s64, end_records, bitmap_records);
	if (end_records <= initialized_records)
		return required_size;
	return max_t(s64, required_size, end_records << record_size_bits);
}

static u32 ntfs_mft_bitmap_initialized_bytes(s64 initialized_size,
		s64 allocated_size, u32 batch_records)
{
	u32 batch_bytes = max_t(u32, MFT_BITMAP_INIT_MIN_BYTES,
			batch_records >> 3);
	u32 bytes;

	if (initialized_size < 0 || allocated_size < initialized_size ||
	    allocated_size - initialized_size < MFT_BITMAP_INIT_MIN_BYTES ||
	    batch_bytes > MFT_RECORD_INIT_LARGE_BATCH / 8 ||
	    !is_power_of_2(batch_bytes))
		return 0;
	bytes = batch_bytes - ((u64)initialized_size & (batch_bytes - 1));
	bytes = max_t(u32, bytes, MFT_BITMAP_INIT_MIN_BYTES);
	return min_t(u64, bytes, allocated_size - initialized_size);
}

static s64 ntfs_mft_growth_aligned_clusters(s64 old_clusters, s64 preferred,
		s64 minimum, u64 batch_clusters)
{
	s64 end;

	/* Align the allocation end without exceeding the reserved growth. */
	if (old_clusters < 0 || minimum <= 0 || preferred < minimum ||
	    batch_clusters > S64_MAX || !is_power_of_2(batch_clusters) ||
	    check_add_overflow(old_clusters, preferred, &end))
		return preferred;
	end &= ~((s64)batch_clusters - 1);
	if (end < old_clusters || end - old_clusters < minimum)
		return preferred;
	return end - old_clusters;
}

/*
 * Records 12-15 are marked in use by Windows but normally have no name
 * and no links. Keep them as the last bootstrap option when a volume
 * mounted without an in-memory tail reserve needs its first $MFT metadata
 * extent.
 */
static bool mft_reserved_is_free(struct ntfs_volume *vol,
		struct ntfs_inode *mft_ni, s64 mft_no)
{
	struct attr_record *a;
	struct mft_record *m;
	struct folio *folio;
	void *mapped;
	pgoff_t index = NTFS_MFT_NR_TO_PIDX(vol, mft_no);
	unsigned int ofs = NTFS_MFT_NR_TO_POFS(vol, mft_no);
	u32 attrs_offset, bytes_in_use;
	bool available = false, have_std = false;
	int i;

	for (i = 0; i < mft_ni->nr_extents; i++) {
		if (mft_ni->ext.extent_ntfs_inos[i] &&
		    mft_ni->ext.extent_ntfs_inos[i]->mft_no == mft_no)
			return false;
	}
	m = kmalloc(vol->mft_record_size, GFP_NOFS);
	if (!m)
		return false;

	folio = ntfs_read_metadata_folio(vol->mft_ino->i_mapping, index);
	if (IS_ERR(folio))
		goto free_m;

	folio_lock(folio);
	mapped = kmap_local_folio(folio, 0);
	memcpy(m, (u8 *)mapped + ofs, vol->mft_record_size);
	kunmap_local(mapped);
	folio_unlock(folio);
	folio_put(folio);
	if (post_read_mst_fixup((struct ntfs_record *)m, vol->mft_record_size))
		goto free_m;

	if (!ntfs_is_mft_record(m->magic) ||
	    !(m->flags & MFT_RECORD_IN_USE) || m->base_mft_record ||
	    m->link_count)
		goto out;

	attrs_offset = le16_to_cpu(m->attrs_offset);
	bytes_in_use = le32_to_cpu(m->bytes_in_use);
	if (attrs_offset > bytes_in_use || bytes_in_use > vol->mft_record_size ||
	    bytes_in_use - attrs_offset < sizeof(a->type))
		goto out;

	for (a = (struct attr_record *)((u8 *)m + attrs_offset);
	     (u8 *)a + sizeof(a->type) <= (u8 *)m + bytes_in_use;) {
		u32 len;

		if (a->type == AT_END) {
			if ((u8 *)a + sizeof(a->type) + sizeof(a->length) >
			    (u8 *)m + bytes_in_use)
				break;
			/* Also accept a record emptied by an earlier bootstrap. */
			available = have_std ||
				    (u8 *)a == (u8 *)m + attrs_offset;
			break;
		}
		if (a->type == AT_FILE_NAME)
			break;
		len = le32_to_cpu(a->length);
		if (len < offsetof(struct attr_record, data) ||
		    (u8 *)a + len > (u8 *)m + bytes_in_use)
			break;
		if (a->type == AT_STANDARD_INFORMATION) {
			u32 value_len, value_ofs;

			if (have_std || a->non_resident ||
			    len < offsetof(struct attr_record,
					   data.resident.reserved) + 1)
				break;
			value_len = le32_to_cpu(a->data.resident.value_length);
			value_ofs = le16_to_cpu(a->data.resident.value_offset);
			if (value_ofs > len || value_len > len - value_ofs)
				break;
			have_std = true;
		}
		a = (struct attr_record *)((u8 *)a + len);
	}
out:
	kfree(m);
	return available;
free_m:
	kfree(m);
	return false;
}

static s64 mft_reserve_end(const u8 *buf, s64 buf_start, s64 buf_end,
			   s64 start, s64 pass_end, s64 initialized_mft_records)
{
	s64 end = start + 1;
	s64 limit = min_t(s64, start + MFT_RECORD_RESERVE, pass_end);

	if (limit > initialized_mft_records)
		limit = initialized_mft_records;
	if (limit > buf_end)
		limit = buf_end;
	while (end < limit &&
	       !(buf[(end - buf_start) >> 3] &
		 (1 << ((end - buf_start) & 7))))
		end++;
	return end;
}

/*
 * mft_bitmap_alloc_free_rec - find and allocate a free MFT record
 * @vol:	volume on which to search for a free mft record
 * @base_ni:	open base inode if allocating an extent mft record or NULL
 * @max_mft_no:	first record which must not be allocated, or -1
 * @new_reserve_end: if not NULL, end of a free run starting after the result
 *
 * Search for a free mft record in the mft bitmap attribute on the ntfs volume
 * @vol.
 *
 * If @base_ni is NULL start the search at the default allocator position.
 *
 * If @base_ni is not NULL start the search at the mft record after the base
 * mft record @base_ni.
 *
 * Return the free mft record on success and -errno on error.  An error code of
 * -ENOSPC means that there are no free mft records in the currently
 * initialized mft bitmap.
 *
 * Locking: Caller must hold vol->mftbmp_lock for writing.
 */
static s64 mft_bitmap_alloc_free_rec(struct ntfs_volume *vol,
				     struct ntfs_inode *base_ni,
				     s64 max_mft_no, s64 *new_reserve_end)
{
	s64 pass_end, ll, data_pos, pass_start, ofs, bit;
	s64 initialized_mft_records;
	unsigned long flags;
	struct address_space *mftbmp_mapping;
	u8 *buf = NULL, *byte;
	struct folio *folio;
	unsigned int folio_ofs, size;
	u8 pass, b;

	ntfs_debug("Searching for free mft record in the currently initialized mft bitmap.");
	mftbmp_mapping = vol->mftbmp_ino->i_mapping;
	/*
	 * Set the end of the pass making sure we do not overflow the mft
	 * bitmap.
	 */
	read_lock_irqsave(&NTFS_I(vol->mft_ino)->size_lock, flags);
	pass_end = NTFS_I(vol->mft_ino)->allocated_size >>
			vol->mft_record_size_bits;
	initialized_mft_records = NTFS_I(vol->mft_ino)->initialized_size >>
			vol->mft_record_size_bits;
	read_unlock_irqrestore(&NTFS_I(vol->mft_ino)->size_lock, flags);
	read_lock_irqsave(&NTFS_I(vol->mftbmp_ino)->size_lock, flags);
	ll = NTFS_I(vol->mftbmp_ino)->initialized_size << 3;
	read_unlock_irqrestore(&NTFS_I(vol->mftbmp_ino)->size_lock, flags);
	if (pass_end > ll)
		pass_end = ll;
	if (max_mft_no >= 0 && pass_end > max_mft_no)
		pass_end = max_mft_no;
	if (base_ni && base_ni->mft_no == FILE_MFT) {
		data_pos = FILE_first_user;
		pass = 2;
		if (data_pos >= pass_end)
			return -ENOSPC;
	} else {
		pass = 1;
		if (!base_ni)
			data_pos = vol->mft_data_pos;
		else
			data_pos = base_ni->mft_no + 1;
		if (data_pos < FIRST_NORMAL_MFT_RECORD)
			data_pos = FIRST_NORMAL_MFT_RECORD;
		if (data_pos >= pass_end) {
			data_pos = FIRST_NORMAL_MFT_RECORD;
			pass = 2;
			/* This happens on a freshly formatted volume. */
			if (data_pos >= pass_end)
				return -ENOSPC;
		}
	}

	pass_start = data_pos;
	ntfs_debug("Starting bitmap search: pass %u, pass_start 0x%llx, pass_end 0x%llx, data_pos 0x%llx.",
			pass, pass_start, pass_end, data_pos);
	/* Loop until a free mft record is found. */
	for (; pass <= 2;) {
		/* Cap size to pass_end. */
		ofs = data_pos >> 3;
		folio_ofs = ofs & ~PAGE_MASK;
		size = PAGE_SIZE - folio_ofs;
		ll = ((pass_end + 7) >> 3) - ofs;
		if (size > ll)
			size = ll;
		size <<= 3;
		/*
		 * If we are still within the active pass, search the next page
		 * for a zero bit.
		 */
		if (size) {
			folio = ntfs_read_metadata_folio(mftbmp_mapping,
							 ofs >> PAGE_SHIFT);
			if (IS_ERR(folio)) {
				ntfs_error(vol->sb, "Failed to read mft bitmap, aborting.");
				return PTR_ERR(folio);
			}
			folio_lock(folio);
			buf = (u8 *)kmap_local_folio(folio, 0) + folio_ofs;
			bit = data_pos & 7;
			data_pos &= ~7ull;
			ntfs_debug("Before inner for loop: size 0x%x, data_pos 0x%llx, bit 0x%llx",
					size, data_pos, bit);
			for (; bit < size && data_pos + bit < pass_end;
					bit &= ~7ull, bit += 8) {
				byte = buf + (bit >> 3);
				if (*byte == 0xff)
					continue;
				b = bit & 7;
				for (; b < 8; b++) {
					if (*byte & (1 << b))
						continue;
					ll = data_pos + (bit & ~7ull) + b;
					if (ll >= pass_end)
						break;
					/* Keep the dynamic tail reserve for $MFT metadata. */
					if ((!base_ni || base_ni->mft_no != FILE_MFT) &&
					    ll >= vol->mft_record_reserve_pos &&
					    ll < vol->mft_record_reserve_end)
						continue;
					if (unlikely(ll >= (1ll << 32))) {
						folio_unlock(folio);
						kunmap_local(buf);
						folio_put(folio);
						return -ENOSPC;
					}
					goto found;
				}
			}
			ntfs_debug("After inner for loop: size 0x%x, data_pos 0x%llx, bit 0x%llx",
					size, data_pos, bit);
			data_pos += size;
			folio_unlock(folio);
			kunmap_local(buf);
			folio_put(folio);
			/*
			 * If the end of the pass has not been reached yet,
			 * continue searching the mft bitmap for a zero bit.
			 */
			if (data_pos < pass_end)
				continue;
		}
		/* Do the next pass. */
		if (++pass == 2) {
			/*
			 * Starting the second pass, in which we scan the first
			 * part of the zone which we omitted earlier.
			 */
			pass_end = pass_start;
			data_pos = FIRST_NORMAL_MFT_RECORD;
			pass_start = FIRST_NORMAL_MFT_RECORD;
			ntfs_debug("pass %i, pass_start 0x%llx, pass_end 0x%llx.",
					pass, pass_start, pass_end);
			if (data_pos >= pass_end)
				break;
		}
	}
	/* No free mft records in currently initialized mft bitmap. */
	ntfs_debug("Done.  (No free mft records left in currently initialized mft bitmap.)");
	return -ENOSPC;
found:
	if (new_reserve_end)
		*new_reserve_end = mft_reserve_end(buf, data_pos,
						   data_pos + size, ll, pass_end,
						   initialized_mft_records);
	folio_unlock(folio);
	kunmap_local(buf);
	folio_put(folio);
	ntfs_debug("Done.  (Found free mft record 0x%llx.)", ll);
	return ll;
}

static int ntfs_mft_attr_extend(struct ntfs_inode *ni,
				struct ntfs_inode *locked_ni)
{
	int ret = 0;
	struct ntfs_inode *base_ni;

	if (NInoAttr(ni))
		base_ni = ni->ext.base_ntfs_ino;
	else
		base_ni = ni;

	if (!NInoAttrList(base_ni)) {
		ret = ntfs_inode_add_attrlist(base_ni);
		if (ret) {
			pr_err("Can not add attrlist\n");
			goto out;
		} else {
			ret = -EAGAIN;
			goto out;
		}
	}

	ret = ntfs_attr_update_mapping_pairs_locked(ni, 0, locked_ni);
	if (ret)
		pr_err("MP update failed\n");

out:
	return ret;
}

/*
 * ntfs_mft_bitmap_extend_allocation_nolock - extend mft bitmap by a cluster
 * @vol:	volume on which to extend the mft bitmap attribute
 *
 * Extend the mft bitmap attribute on the ntfs volume @vol by one cluster.
 *
 * Note: Only changes allocated_size, i.e. does not touch initialized_size or
 * data_size.
 *
 * Return 0 on success and -errno on error.
 *
 * Locking: - Caller must hold vol->mftbmp_lock for writing.
 *	    - This function takes NTFS_I(vol->mftbmp_ino)->runlist.lock for
 *	      writing and releases it before returning.
 *	    - This function takes vol->lcnbmp_lock for writing and releases it
 *	      before returning.
 */
static int ntfs_mft_bitmap_extend_allocation_nolock(struct ntfs_volume *vol)
{
	s64 lcn;
	s64 ll;
	unsigned long flags;
	struct folio *folio;
	struct ntfs_inode *mft_ni, *mftbmp_ni;
	struct runlist_element *rl, *rl2 = NULL;
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct mft_record *mrec;
	struct attr_record *a = NULL;
	int ret, mp_size;
	u32 old_alen = 0;
	u8 *b, tb;
	struct {
		u8 added_cluster:1;
		u8 added_run:1;
		u8 mp_rebuilt:1;
		u8 mp_extended:1;
	} status = { 0, 0, 0, 0 };
	size_t new_rl_count;

	ntfs_debug("Extending mft bitmap allocation.");
	/* The initial bitmap scan must finish before we lock or change a folio. */
	if (!NVolFreeClusterKnown(vol))
		wait_event(vol->free_waitq, NVolFreeClusterKnown(vol));

	mft_ni = NTFS_I(vol->mft_ino);
	mftbmp_ni = NTFS_I(vol->mftbmp_ino);
	/*
	 * Determine the last lcn of the mft bitmap.  The allocated size of the
	 * mft bitmap cannot be zero so we are ok to do this.
	 */
	down_write(&mftbmp_ni->runlist.lock);
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	ll = mftbmp_ni->allocated_size;
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	rl = ntfs_attr_find_vcn_nolock(mftbmp_ni,
			NTFS_B_TO_CLU(vol, ll - 1), NULL);
	if (IS_ERR(rl) || unlikely(!rl->length || rl->lcn < 0)) {
		up_write(&mftbmp_ni->runlist.lock);
		ntfs_error(vol->sb,
			"Failed to determine last allocated cluster of mft bitmap attribute.");
		if (!IS_ERR(rl))
			ret = -EIO;
		else
			ret = PTR_ERR(rl);
		return ret;
	}
	lcn = rl->lcn + rl->length;
	ntfs_debug("Last lcn of mft bitmap attribute is 0x%llx.",
			(long long)lcn);
	/* There is no adjacent cluster if the last run ends at the volume end. */
	if (lcn >= vol->nr_clusters) {
		lcn = -1;
		goto alloc_cluster;
	}
	/*
	 * Attempt to get the cluster following the last allocated cluster by
	 * hand as it may be in the MFT zone so the allocator would not give it
	 * to us.
	 */
	ll = lcn >> 3;
	folio = ntfs_read_metadata_folio(vol->lcnbmp_ino->i_mapping,
					 ll >> PAGE_SHIFT);
	if (IS_ERR(folio)) {
		up_write(&mftbmp_ni->runlist.lock);
		ntfs_error(vol->sb, "Failed to read from lcn bitmap.");
		return PTR_ERR(folio);
	}

	down_write(&vol->lcnbmp_lock);
	folio_lock(folio);
	b = (u8 *)kmap_local_folio(folio, 0) + (ll & ~PAGE_MASK);
	tb = 1 << (lcn & 7ull);
	/*
	 * A page skipped by the initial scan has no free bits recorded.
	 * Honor that and space reserved for delayed allocation.
	 */
	if (*b != 0xff && !(*b & tb) &&
	    vol->lcn_empty_bits_per_page[ll >> PAGE_SHIFT] &&
	    ntfs_available_clusters(vol) > 0) {
		/* Next cluster is free, allocate it. */
		*b |= tb;
		folio_mark_dirty(folio);
		ntfs_dec_free_clusters(vol, 1);
		ntfs_set_lcn_empty_bits(vol, ll >> PAGE_SHIFT, 1, 1);
		folio_unlock(folio);
		kunmap_local(b);
		folio_put(folio);
		up_write(&vol->lcnbmp_lock);
		/* Update the mft bitmap runlist. */
		rl->length++;
		rl[1].vcn++;
		status.added_cluster = 1;
		ntfs_debug("Appending one cluster to mft bitmap.");
	} else {
		folio_unlock(folio);
		kunmap_local(b);
		folio_put(folio);
		up_write(&vol->lcnbmp_lock);
alloc_cluster:
		/* Allocate a cluster from the DATA_ZONE. */
		rl2 = ntfs_cluster_alloc(vol, rl[1].vcn, 1, lcn, DATA_ZONE,
				true, false, false);
		if (IS_ERR(rl2)) {
			up_write(&mftbmp_ni->runlist.lock);
			ntfs_error(vol->sb,
					"Failed to allocate a cluster for the mft bitmap.");
			return PTR_ERR(rl2);
		}
		/* The adjacent cluster may have become available while unlocked. */
		status.added_cluster = rl2->lcn == lcn;
		rl = ntfs_runlists_merge(&mftbmp_ni->runlist, rl2, 0, &new_rl_count);
		if (IS_ERR(rl)) {
			up_write(&mftbmp_ni->runlist.lock);
			ntfs_error(vol->sb, "Failed to merge runlists for mft bitmap.");
			if (ntfs_cluster_free_from_rl(vol, rl2)) {
				ntfs_error(vol->sb, "Failed to deallocate allocated cluster.%s",
						es);
				NVolSetErrors(vol);
			}
			kvfree(rl2);
			return PTR_ERR(rl);
		}
		mftbmp_ni->runlist.rl = rl;
		mftbmp_ni->runlist.count = new_rl_count;
		status.added_run = !status.added_cluster;
		ntfs_debug("Allocated one cluster for mft bitmap.");
		/* Find the last run in the new runlist. */
		for (; rl[1].length; rl++)
			;
	}
	/*
	 * Update the attribute record as well.  Note: @rl is the last
	 * (non-terminator) runlist element of mft bitmap.
	 */
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		ntfs_error(vol->sb, "Failed to map mft record.");
		ret = PTR_ERR(mrec);
		goto undo_alloc;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.");
		ret = -ENOMEM;
		goto undo_alloc;
	}
	ret = ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, rl[1].vcn, NULL,
			0, ctx);
	if (unlikely(ret)) {
		ntfs_error(vol->sb,
			"Failed to find last attribute extent of mft bitmap attribute.");
		if (ret == -ENOENT)
			ret = -EIO;
		goto undo_alloc;
	}
	a = ctx->attr;
	ll = le64_to_cpu(a->data.non_resident.lowest_vcn);
	/* Search back for the previous last allocated cluster of mft bitmap. */
	for (rl2 = rl; rl2 > mftbmp_ni->runlist.rl; rl2--) {
		if (ll >= rl2->vcn)
			break;
	}
	WARN_ON(ll < rl2->vcn);
	WARN_ON(ll >= rl2->vcn + rl2->length);
	/* Get the size for the new mapping pairs array for this extent. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl2, ll, -1, -1);
	if (unlikely(mp_size <= 0)) {
		ntfs_error(vol->sb,
			"Get size for mapping pairs failed for mft bitmap attribute extent.");
		ret = mp_size;
		if (!ret)
			ret = -EIO;
		goto undo_alloc;
	}
	/* Expand the attribute record if necessary. */
	old_alen = le32_to_cpu(a->length);
	ret = ntfs_attr_record_resize(ctx->mrec, a, mp_size +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset));
	if (unlikely(ret)) {
		ret = ntfs_mft_attr_extend(mftbmp_ni, mftbmp_ni);
		if (!ret)
			goto extended_ok;
		if (ret != -EAGAIN)
			status.mp_extended = 1;
		goto undo_alloc;
	}
	status.mp_rebuilt = 1;
	/* Generate the mapping pairs array directly into the attr record. */
	ret = ntfs_mapping_pairs_build(vol, (u8 *)a +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset),
			mp_size, rl2, ll, -1, NULL, NULL, NULL);
	if (unlikely(ret)) {
		ntfs_error(vol->sb,
			"Failed to build mapping pairs array for mft bitmap attribute.");
		goto undo_alloc;
	}
	/* Update the highest_vcn. */
	a->data.non_resident.highest_vcn = cpu_to_le64(rl[1].vcn - 1);
	/*
	 * We now have extended the mft bitmap allocated_size by one cluster.
	 * Reflect this in the struct ntfs_inode structure and the attribute record.
	 */
	if (a->data.non_resident.lowest_vcn) {
		/*
		 * We are not in the first attribute extent, switch to it, but
		 * first ensure the changes will make it to disk later.
		 */
		mark_mft_record_dirty(ctx->ntfs_ino);
extended_ok:
		ntfs_attr_reinit_search_ctx(ctx);
		ret = ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
				mftbmp_ni->name_len, CASE_SENSITIVE, 0, NULL,
				0, ctx);
		if (unlikely(ret)) {
			ntfs_error(vol->sb,
				"Failed to find first attribute extent of mft bitmap attribute.");
			goto restore_undo_alloc;
		}
		a = ctx->attr;
	}

	write_lock_irqsave(&mftbmp_ni->size_lock, flags);
	mftbmp_ni->allocated_size += vol->cluster_size;
	a->data.non_resident.allocated_size =
			cpu_to_le64(mftbmp_ni->allocated_size);
	write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	/* Ensure the changes make it to disk. */
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
	up_write(&mftbmp_ni->runlist.lock);
	ntfs_debug("Done.");
	return 0;

restore_undo_alloc:
	ntfs_attr_reinit_search_ctx(ctx);
	if (ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, rl[1].vcn, NULL,
			0, ctx)) {
		ntfs_error(vol->sb,
			"Failed to find last attribute extent of mft bitmap attribute.%s", es);
		write_lock_irqsave(&mftbmp_ni->size_lock, flags);
		mftbmp_ni->allocated_size += vol->cluster_size;
		write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(mft_ni);
		up_write(&mftbmp_ni->runlist.lock);
		/*
		 * The only thing that is now wrong is ->allocated_size of the
		 * base attribute extent which chkdsk should be able to fix.
		 */
		NVolSetErrors(vol);
		return ret;
	}
	a = ctx->attr;
	a->data.non_resident.highest_vcn = cpu_to_le64(rl[1].vcn - 2);
undo_alloc:
	if (status.added_cluster) {
		/* Truncate the last run in the runlist by one cluster. */
		rl->length--;
		rl[1].vcn--;
	} else if (status.added_run) {
		lcn = rl->lcn;
		/* Remove the last run from the runlist. */
		rl->lcn = rl[1].lcn;
		rl->length = 0;
		mftbmp_ni->runlist.count--;
	}
	/* Deallocate the cluster. */
	down_write(&vol->lcnbmp_lock);
	if (ntfs_bitmap_clear_bit(vol->lcnbmp_ino, lcn)) {
		ntfs_error(vol->sb, "Failed to free allocated cluster.%s", es);
		NVolSetErrors(vol);
	} else
		ntfs_inc_free_clusters(vol, 1);
	up_write(&vol->lcnbmp_lock);
	if (status.mp_rebuilt) {
		if (ntfs_mapping_pairs_build(vol, (u8 *)a + le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset),
				old_alen - le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset),
				rl2, ll, -1, NULL, NULL, NULL)) {
			ntfs_error(vol->sb, "Failed to restore mapping pairs array.%s", es);
			NVolSetErrors(vol);
		}
		if (ntfs_attr_record_resize(ctx->mrec, a, old_alen)) {
			ntfs_error(vol->sb, "Failed to restore attribute record.%s", es);
			NVolSetErrors(vol);
		}
		mark_mft_record_dirty(ctx->ntfs_ino);
	} else if (status.mp_extended &&
		   ntfs_attr_update_mapping_pairs_locked(mftbmp_ni, 0,
							  mftbmp_ni)) {
		ntfs_error(vol->sb, "Failed to restore mapping pairs.%s", es);
		NVolSetErrors(vol);
	}
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (!IS_ERR(mrec))
		unmap_mft_record(mft_ni);
	up_write(&mftbmp_ni->runlist.lock);
	return ret;
}

/*
 * ntfs_mft_bitmap_extend_initialized_nolock - extend mftbmp initialized data
 * @vol:	volume on which to extend the mft bitmap attribute
 *
 * Extend the initialized portion of the mft bitmap attribute on the ntfs
 * volume @vol by 8 bytes.
 *
 * Note:  Only changes initialized_size and data_size, i.e. requires that
 * allocated_size is big enough to fit the new initialized_size.
 *
 * Return 0 on success and -error on error.
 *
 * Locking: Caller must hold vol->mftbmp_lock for writing.
 */
static int ntfs_mft_bitmap_extend_initialized_nolock(struct ntfs_volume *vol)
{
	s64 old_data_size, old_initialized_size;
	unsigned long flags;
	struct inode *mftbmp_vi;
	struct ntfs_inode *mft_ni, *mftbmp_ni;
	struct ntfs_attr_search_ctx *ctx;
	struct mft_record *mrec;
	struct attr_record *a;
	int ret;

	ntfs_debug("Extending mft bitmap initialized (and data) size.");
	mft_ni = NTFS_I(vol->mft_ino);
	mftbmp_vi = vol->mftbmp_ino;
	mftbmp_ni = NTFS_I(mftbmp_vi);
	/* Get the attribute record. */
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		ntfs_error(vol->sb, "Failed to map mft record.");
		return PTR_ERR(mrec);
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.");
		ret = -ENOMEM;
		goto unm_err_out;
	}
	ret = ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(ret)) {
		ntfs_error(vol->sb,
			"Failed to find first attribute extent of mft bitmap attribute.");
		if (ret == -ENOENT)
			ret = -EIO;
		goto put_err_out;
	}
	a = ctx->attr;
	write_lock_irqsave(&mftbmp_ni->size_lock, flags);
	old_data_size = i_size_read(mftbmp_vi);
	old_initialized_size = mftbmp_ni->initialized_size;
	/*
	 * We can simply update the initialized_size before filling the space
	 * with zeroes because the caller is holding the mft bitmap lock for
	 * writing which ensures that no one else is trying to access the data.
	 */
	mftbmp_ni->initialized_size += 8;
	a->data.non_resident.initialized_size =
			cpu_to_le64(mftbmp_ni->initialized_size);
	if (mftbmp_ni->initialized_size > old_data_size) {
		i_size_write(mftbmp_vi, mftbmp_ni->initialized_size);
		a->data.non_resident.data_size =
				cpu_to_le64(mftbmp_ni->initialized_size);
	}
	write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	/* Ensure the changes make it to disk. */
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
	/* Initialize the mft bitmap attribute value with zeroes. */
	ret = ntfs_attr_set(mftbmp_ni, old_initialized_size, 8, 0);
	if (likely(!ret)) {
		ntfs_debug("Done.  (Wrote eight initialized bytes to mft bitmap.");
		return 0;
	}
	ntfs_error(vol->sb, "Failed to write to mft bitmap.");
	/* Try to recover from the error. */
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		ntfs_error(vol->sb, "Failed to map mft record.%s", es);
		NVolSetErrors(vol);
		return ret;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.%s", es);
		NVolSetErrors(vol);
		goto unm_err_out;
	}
	if (ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		ntfs_error(vol->sb,
			"Failed to find first attribute extent of mft bitmap attribute.%s", es);
		NVolSetErrors(vol);
put_err_out:
		ntfs_attr_put_search_ctx(ctx);
unm_err_out:
		unmap_mft_record(mft_ni);
		goto err_out;
	}
	a = ctx->attr;
	write_lock_irqsave(&mftbmp_ni->size_lock, flags);
	mftbmp_ni->initialized_size = old_initialized_size;
	a->data.non_resident.initialized_size =
			cpu_to_le64(old_initialized_size);
	if (i_size_read(mftbmp_vi) != old_data_size) {
		i_size_write(mftbmp_vi, old_data_size);
		a->data.non_resident.data_size = cpu_to_le64(old_data_size);
	}
	write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
#ifdef DEBUG
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	ntfs_debug("Restored status of mftbmp: allocated_size 0x%llx, data_size 0x%llx, initialized_size 0x%llx.",
			mftbmp_ni->allocated_size, i_size_read(mftbmp_vi),
			mftbmp_ni->initialized_size);
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
#endif /* DEBUG */
err_out:
	return ret;
}

static int ntfs_mft_bitmap_extend_initialized_transacted_nolock(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		u32 batch_records)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct inode *mftbmp_vi;
	struct ntfs_inode *mft_ni;
	struct ntfs_inode *mftbmp_ni;
	struct ntfs_attr_search_ctx *ctx;
	struct mft_record *mrec;
	struct attr_record *attr;
	unsigned long flags;
	u64 operation_lsn;
	s64 allocated_size;
	s64 data_size;
	s64 initialized_size;
	ptrdiff_t record_pos;
	u32 attr_len;
	u32 bytes;
	u32 used;
	u16 record_off;
	u8 zeroes[MFT_RECORD_INIT_LARGE_BATCH / 8] = { };
	int err;

	if (!handle || !vol)
		return -EINVAL;
	mft_ni = NTFS_I(vol->mft_ino);
	mftbmp_vi = vol->mftbmp_ino;
	mftbmp_ni = NTFS_I(mftbmp_vi);
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}
	err = ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out_ctx;
	}
	attr = ctx->attr;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	allocated_size = mftbmp_ni->allocated_size;
	data_size = i_size_read(mftbmp_vi);
	initialized_size = mftbmp_ni->initialized_size;
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	bytes = ntfs_mft_bitmap_initialized_bytes(initialized_size,
			allocated_size, batch_records);
	if (!attr->non_resident || attr->flags ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    record_pos > used || attr_len > used - record_pos ||
	    allocated_size < 0 || data_size < 0 || initialized_size < 0 ||
	    initialized_size > data_size || data_size > allocated_size ||
	    !bytes ||
	    le64_to_cpu(attr->data.non_resident.allocated_size) !=
			allocated_size ||
	    le64_to_cpu(attr->data.non_resident.data_size) != data_size ||
	    le64_to_cpu(attr->data.non_resident.initialized_size) !=
			initialized_size) {
		err = -EIO;
		goto out_ctx;
	}
	record_off = record_pos;
	new_sizes.alloc_size = old_sizes.alloc_size =
			attr->data.non_resident.allocated_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	new_sizes.valid_size = cpu_to_le64(initialized_size + bytes);
	new_sizes.data_size = cpu_to_le64(max(data_size,
			initialized_size + (s64)bytes));
	err = ntfs_attr_size_register_home_undo(handle, mftbmp_ni);
	if (err)
		goto out_ctx;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out_ctx;
	err = ntfs_log_nonresident_value_update(handle, mftbmp_vi,
			initialized_size, NULL, zeroes, bytes, NULL);
	if (err)
		goto out_ctx;
	err = ntfs_log_mft_attribute_sizes_update(handle,
			ctx->ntfs_ino->mft_no, record_off, &old_sizes,
			&new_sizes, false, &operation_lsn);
	if (err)
		goto out_ctx;
	attr->data.non_resident.initialized_size = new_sizes.valid_size;
	attr->data.non_resident.data_size = new_sizes.data_size;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
	write_lock_irqsave(&mftbmp_ni->size_lock, flags);
	mftbmp_ni->initialized_size = initialized_size + bytes;
	mftbmp_ni->data_size = le64_to_cpu(new_sizes.data_size);
	mftbmp_ni->zeroed_size = mftbmp_ni->initialized_size;
	i_size_write(mftbmp_vi, mftbmp_ni->data_size);
	write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
	err = ntfs_attr_set(mftbmp_ni, initialized_size, bytes, 0);
	if (err)
		return err;
	return 0;

out_ctx:
	ntfs_attr_put_search_ctx(ctx);
out_unmap:
	unmap_mft_record(mft_ni);
	return err;
}

static int ntfs_mft_mapping_growth_preflight(struct ntfs_inode *ni,
		s64 old_clusters, u64 max_new_runs)
{
	struct ntfs_inode *base_ni;
	struct ntfs_attr_search_ctx *ctx;
	struct runlist_element *rl;
	struct attr_record *attr;
	struct mft_record *mrec;
	u64 extra;
	s64 lowest_vcn;
	ptrdiff_t record_pos;
	u32 allocated;
	u32 attr_len;
	u32 mapping_off;
	u32 required;
	u32 used;
	int mapping_size;
	int err;

	if (!ni || old_clusters <= 0 || !max_new_runs)
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, old_clusters - 1,
			NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out;
	}
	attr = ctx->attr;
	mrec = ctx->mrec;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off = le16_to_cpu(
			attr->data.non_resident.mapping_pairs_offset);
	lowest_vcn = le64_to_cpu(attr->data.non_resident.lowest_vcn);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	if (!attr->non_resident || attr->flags || lowest_vcn < 0 ||
	    le64_to_cpu(attr->data.non_resident.highest_vcn) !=
			old_clusters - 1 ||
	    record_pos < 0 || record_pos > used || attr_len > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(mapping_off, 8) ||
	    mapping_off >= attr_len || attr_len > used - record_pos ||
	    used > allocated) {
		err = -EIO;
		goto out;
	}
	down_read(&ni->runlist.lock);
	rl = ntfs_attr_find_vcn_nolock(ni, lowest_vcn, NULL);
	if (IS_ERR(rl)) {
		err = PTR_ERR(rl);
		goto out_unlock;
	}
	mapping_size = ntfs_get_size_for_mapping_pairs(ni->vol, rl,
			lowest_vcn, -1, -1);
	if (mapping_size <= 0) {
		err = mapping_size ? mapping_size : -EIO;
		goto out_unlock;
	}
	/* Each new run can add a header and two s64 fields. */
	if (check_mul_overflow(max_new_runs, 17ULL, &extra) ||
	    extra > U32_MAX) {
		err = -EOVERFLOW;
		goto out_unlock;
	}
	if (check_add_overflow(mapping_off, (u32)mapping_size, &required) ||
	    check_add_overflow(required, (u32)extra, &required)) {
		err = -EOVERFLOW;
		goto out_unlock;
	}
	required = ALIGN(required, 8);
	err = required <= attr_len + allocated - used && required <= U16_MAX ?
		0 : -EOPNOTSUPP;
out_unlock:
	up_read(&ni->runlist.lock);
out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

static int ntfs_mft_bitmap_extend_allocation_transacted_nolock(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol)
{
	struct runlist_element *allocated_rl = NULL;
	struct runlist_element *merged_rl;
	struct runlist_element *rl;
	struct ntfs_inode *base_ni;
	struct ntfs_inode *mftbmp_ni;
	unsigned long flags;
	s64 allocated_size;
	s64 lcn_hint = -1;
	s64 old_clusters;
	size_t new_rl_count;
	int err = 0;

	if (!handle || !vol)
		return -EINVAL;
	mftbmp_ni = NTFS_I(vol->mftbmp_ino);
	base_ni = mftbmp_ni->ext.base_ntfs_ino;
	if (!base_ni || !NInoNonResident(mftbmp_ni) ||
	    NInoCompressed(mftbmp_ni) || NInoSparse(mftbmp_ni) ||
	    NInoEncrypted(mftbmp_ni))
		return -EOPNOTSUPP;
	err = ntfs_attr_map_whole_runlist(mftbmp_ni);
	if (err)
		return err;
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	allocated_size = mftbmp_ni->allocated_size;
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	if (allocated_size <= 0 ||
	    !IS_ALIGNED(allocated_size, vol->cluster_size))
		return -EIO;
	old_clusters = allocated_size >> vol->cluster_size_bits;
	err = ntfs_mft_mapping_growth_preflight(mftbmp_ni, old_clusters, 1);
	if (err && err != -EOPNOTSUPP)
		return err;
	/*
	 * A full mapping-pairs record can be extended into a new attribute-list
	 * extent by ntfs_attr_update_mapping_pairs_transacted().  Keep the
	 * preflight as a corruption/state check, but do not refuse that valid
	 * tail-growth case here.
	 */
	down_read(&mftbmp_ni->runlist.lock);
	for (rl = mftbmp_ni->runlist.rl; rl && rl->length; rl++) {
		if (rl->lcn < 0 || rl->length <= 0 ||
		    check_add_overflow(rl->lcn, rl->length, &lcn_hint)) {
			err = -EIO;
			break;
		}
	}
	if (!err && (!rl || rl->vcn != old_clusters ||
		    rl->lcn != LCN_ENOENT))
		err = -EIO;
	up_read(&mftbmp_ni->runlist.lock);
	if (err)
		return err;
	allocated_rl = ntfs_cluster_alloc_transacted(handle, vol,
			old_clusters, 1, lcn_hint, DATA_ZONE, true, false, false);
	if (IS_ERR(allocated_rl))
		return PTR_ERR(allocated_rl);
	if (allocated_rl->vcn != old_clusters || allocated_rl->lcn < 0 ||
	    allocated_rl->length != 1 || allocated_rl[1].length ||
	    allocated_rl[1].vcn != old_clusters + 1 ||
	    allocated_rl[1].lcn != LCN_ENOENT) {
		err = -EIO;
		goto out;
	}
	down_write(&mftbmp_ni->runlist.lock);
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	err = mftbmp_ni->allocated_size == allocated_size ? 0 : -EAGAIN;
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	if (err)
		goto out_unlock;
	err = ntfs_attr_allocation_register_home_undo(handle, mftbmp_ni);
	if (err)
		goto out_unlock;
	merged_rl = ntfs_runlists_merge(&mftbmp_ni->runlist, allocated_rl, 0,
			&new_rl_count);
	if (IS_ERR(merged_rl)) {
		err = PTR_ERR(merged_rl);
		goto out_unlock;
	}
	allocated_rl = NULL;
	mftbmp_ni->runlist.rl = merged_rl;
	mftbmp_ni->runlist.count = new_rl_count;
	mftbmp_ni->runlist.rl_hint = -1;
	write_lock_irqsave(&mftbmp_ni->size_lock, flags);
	mftbmp_ni->allocated_size += vol->cluster_size;
	VFS_I(mftbmp_ni)->i_blocks = mftbmp_ni->allocated_size >> 9;
	VFS_I(base_ni)->i_blocks += vol->cluster_size >> 9;
	write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	up_write(&mftbmp_ni->runlist.lock);
	down_write(&mftbmp_ni->runlist.lock);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, mftbmp_ni);
	up_write(&mftbmp_ni->runlist.lock);
	return err;

out_unlock:
	up_write(&mftbmp_ni->runlist.lock);
out:
	kvfree(allocated_rl);
	return err;
}

static int ntfs_mft_data_extend_initialized_transacted_nolock(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		s64 new_initialized_size)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *mft_ni;
	struct mft_record *mrec;
	struct attr_record *attr;
	unsigned long flags;
	u64 operation_lsn;
	s64 allocated_size;
	s64 byte_pos;
	s64 data_size;
	s64 mft_data_size;
	s64 initialized_size;
	s64 last_mft_no;
	s64 mft_no;
	ptrdiff_t record_pos;
	u64 attr_allocated_size;
	u64 attr_data_size;
	u64 attr_initialized_size;
	u64 lowest_vcn;
	u32 attr_len;
	u32 used;
	u16 record_off;
	int err;

	if (!handle || !vol || new_initialized_size <= 0)
		return -EINVAL;
	mft_ni = NTFS_I(vol->mft_ino);
	read_lock_irqsave(&mft_ni->size_lock, flags);
	allocated_size = mft_ni->allocated_size;
	data_size = i_size_read(vol->mft_ino);
	mft_data_size = mft_ni->data_size;
	initialized_size = mft_ni->initialized_size;
	err = mft_data_size == data_size ? 0 : -EIO;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	if (err) {
		ntfs_error(vol->sb,
			   "In-memory $MFT::$DATA size mismatch before initialized-size extension to %lld (data_size %lld, i_size %lld, initialized_size %lld, allocated_size %lld).",
			   (long long)new_initialized_size,
			   (long long)mft_data_size, (long long)data_size,
			   (long long)initialized_size,
			   (long long)allocated_size);
		return err;
	}
	if (allocated_size < 0 || data_size < initialized_size ||
	    data_size > allocated_size ||
	    new_initialized_size <= initialized_size ||
	    new_initialized_size > allocated_size) {
		ntfs_error(vol->sb,
			   "Invalid $MFT::$DATA initialized-size extension range (allocated_size %lld, data_size %lld, initialized_size %lld, requested %lld).",
			   (long long)allocated_size, (long long)data_size,
			   (long long)initialized_size,
			   (long long)new_initialized_size);
		return -EOPNOTSUPP;
	}
	mft_no = initialized_size >> vol->mft_record_size_bits;
	if (check_shl_overflow(mft_no, vol->mft_record_size_bits,
			&byte_pos) || byte_pos != initialized_size) {
		ntfs_error(vol->sb,
			   "Invalid starting MFT record boundary for initialized-size extension (initialized_size %lld, record size bits %u).",
			   (long long)initialized_size,
			   vol->mft_record_size_bits);
		return -EOVERFLOW;
	}
	last_mft_no = (new_initialized_size >>
			vol->mft_record_size_bits) - 1;
	if (last_mft_no < mft_no ||
	    check_add_overflow(last_mft_no, 1, &byte_pos)) {
		ntfs_error(vol->sb,
			   "Invalid MFT record range for initialized-size extension (first record 0x%llx, last record 0x%llx, requested initialized_size %lld).",
			   (unsigned long long)mft_no,
			   (unsigned long long)last_mft_no,
			   (long long)new_initialized_size);
		return -EOVERFLOW;
	}
	if (check_shl_overflow(byte_pos, vol->mft_record_size_bits,
			       &byte_pos) || byte_pos != new_initialized_size) {
		ntfs_error(vol->sb,
			   "Invalid ending MFT record boundary for initialized-size extension (last record 0x%llx, requested initialized_size %lld, record size bits %u).",
			   (unsigned long long)last_mft_no,
			   (long long)new_initialized_size,
			   vol->mft_record_size_bits);
		return -EOVERFLOW;
	}
	err = ntfs_attr_size_register_home_undo(handle, mft_ni);
	if (err) {
		ntfs_error(vol->sb,
			   "Failed to register $MFT::$DATA size undo before formatting records 0x%llx-0x%llx (initialized_size %lld, requested %lld, error %d).",
			   (unsigned long long)mft_no,
			   (unsigned long long)last_mft_no,
			   (long long)initialized_size,
			   (long long)new_initialized_size, err);
		return err;
	}
	write_lock_irqsave(&mft_ni->size_lock, flags);
	if (new_initialized_size > i_size_read(vol->mft_ino))
		i_size_write(vol->mft_ino, new_initialized_size);
	write_unlock_irqrestore(&mft_ni->size_lock, flags);
	for (;;) {
		err = ntfs_mft_record_format_transacted(handle, vol, mft_no);
		if (err) {
			ntfs_error(vol->sb,
				   "Failed to format MFT record 0x%llx while extending $MFT::$DATA initialized_size from %lld to %lld (error %d).",
				   (unsigned long long)mft_no,
				   (long long)initialized_size,
				   (long long)new_initialized_size, err);
			return err;
		}
		if (mft_no == last_mft_no)
			break;
		mft_no++;
	}
	write_lock_irqsave(&mft_ni->size_lock, flags);
	mft_ni->initialized_size = new_initialized_size;
	mft_ni->data_size = max(data_size, new_initialized_size);
	mft_ni->zeroed_size = mft_ni->initialized_size;
	i_size_write(vol->mft_ino, mft_ni->data_size);
	write_unlock_irqrestore(&mft_ni->size_lock, flags);

	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		ntfs_error(vol->sb,
			   "Failed to map MFT record 0 while updating $MFT::$DATA initialized_size from %lld to %lld (error %d).",
			   (long long)initialized_size,
			   (long long)new_initialized_size, err);
		return err;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		ntfs_error(vol->sb,
			   "Failed to allocate attribute search context for $MFT::$DATA initialized-size update to %lld (error %d).",
			   (long long)new_initialized_size, err);
		goto out_unmap;
	}
	err = ntfs_attr_lookup(mft_ni->type, mft_ni->name, mft_ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		ntfs_error(vol->sb,
			   "Failed to find $MFT::$DATA while updating initialized_size from %lld to %lld (lookup error %d).",
			   (long long)initialized_size,
			   (long long)new_initialized_size, err);
		if (err == -ENOENT)
			err = -EIO;
		goto out_ctx;
	}
	attr = ctx->attr;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	lowest_vcn = 0;
	attr_allocated_size = 0;
	attr_data_size = 0;
	attr_initialized_size = 0;
	if (attr->non_resident) {
		lowest_vcn = le64_to_cpu(attr->data.non_resident.lowest_vcn);
		attr_allocated_size =
			le64_to_cpu(attr->data.non_resident.allocated_size);
		attr_data_size = le64_to_cpu(attr->data.non_resident.data_size);
		attr_initialized_size =
			le64_to_cpu(attr->data.non_resident.initialized_size);
	}
	if (!attr->non_resident || attr->flags ||
	    lowest_vcn ||
	    record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    record_pos > used || attr_len > used - record_pos ||
	    attr_allocated_size != (u64)allocated_size ||
	    attr_data_size != (u64)data_size ||
	    attr_initialized_size != (u64)initialized_size) {
		ntfs_error(vol->sb,
			   "Invalid $MFT::$DATA extent during initialized-size extension to %lld: non_resident %u, flags 0x%x, lowest_vcn 0x%llx, record offset %lld, attribute length 0x%x, bytes in use 0x%x; cached allocated/data/initialized sizes 0x%llx/0x%llx/0x%llx, attribute sizes 0x%llx/0x%llx/0x%llx.",
			   (long long)new_initialized_size,
			   (unsigned int)attr->non_resident,
			   (unsigned int)attr->flags,
			   (unsigned long long)lowest_vcn,
			   (long long)record_pos, attr_len, used,
			   (unsigned long long)allocated_size,
			   (unsigned long long)data_size,
			   (unsigned long long)initialized_size,
			   (unsigned long long)attr_allocated_size,
			   (unsigned long long)attr_data_size,
			   (unsigned long long)attr_initialized_size);
		err = -EIO;
		goto out_ctx;
	}
	record_off = record_pos;
	old_sizes.alloc_size = attr->data.non_resident.allocated_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	new_sizes.alloc_size = old_sizes.alloc_size;
	new_sizes.valid_size = cpu_to_le64(new_initialized_size);
	new_sizes.data_size = cpu_to_le64(max(data_size,
			new_initialized_size));
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err) {
		ntfs_error(vol->sb,
			   "Failed to register MFT record 0x%llx undo for $MFT::$DATA initialized-size update to %lld (error %d).",
			   (unsigned long long)ctx->ntfs_ino->mft_no,
			   (long long)new_initialized_size, err);
		goto out_ctx;
	}
	err = ntfs_log_mft_attribute_sizes_update(handle,
			ctx->ntfs_ino->mft_no, record_off, &old_sizes,
			&new_sizes, false, &operation_lsn);
	if (err) {
		ntfs_error(vol->sb,
			   "Failed to journal $MFT::$DATA size update for initialized-size extension from %lld to %lld (allocated_size 0x%llx, data_size 0x%llx, error %d).",
			   (long long)initialized_size,
			   (long long)new_initialized_size,
			   (unsigned long long)attr_allocated_size,
			   (unsigned long long)attr_data_size, err);
		goto out_ctx;
	}
	attr->data.non_resident.initialized_size = new_sizes.valid_size;
	attr->data.non_resident.data_size = new_sizes.data_size;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
out_ctx:
	ntfs_attr_put_search_ctx(ctx);
out_unmap:
	unmap_mft_record(mft_ni);
	return err;
}

static int ntfs_mft_data_extend_allocation_transacted_nolock(
		struct ntfs_log_handle *handle, struct ntfs_volume *vol,
		s64 required_size, u32 batch_records)
{
	struct runlist_element *allocated_rl = NULL;
	struct runlist_element *merged_rl;
	struct runlist_element *rl;
	struct ntfs_inode *mft_ni;
	unsigned long flags;
	u64 added_bytes;
	u64 batch_clusters;
	u64 growth_bytes;
	u64 new_bytes;
	s64 allocated_size;
	s64 expected_vcn;
	s64 lcn_hint = -1;
	s64 min_nr;
	s64 nr;
	s64 required_nr = 0;
	s64 allocated_nr;
	s64 new_clusters;
	s64 old_clusters;
	size_t new_rl_count;
	u64 runs;
	unsigned int max_runs = 0;
	int err = 0;

	if (!handle || !vol || required_size <= 0 || !batch_records)
		return -EINVAL;
	mft_ni = NTFS_I(vol->mft_ino);
	if (!NInoNonResident(mft_ni) || NInoCompressed(mft_ni) ||
	    NInoSparse(mft_ni) || NInoEncrypted(mft_ni)) {
		ntfs_error(vol->sb,
			   "Unsupported $MFT data state (nonresident %d, compressed %d, sparse %d, encrypted %d).",
			   NInoNonResident(mft_ni), NInoCompressed(mft_ni),
			   NInoSparse(mft_ni), NInoEncrypted(mft_ni));
		return -EOPNOTSUPP;
	}
	err = ntfs_attr_map_whole_runlist(mft_ni);
	if (err)
		return err;
	read_lock_irqsave(&mft_ni->size_lock, flags);
	allocated_size = mft_ni->allocated_size;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	if (allocated_size <= 0 ||
	    !IS_ALIGNED(allocated_size, vol->cluster_size))
		return -EIO;
	old_clusters = allocated_size >> vol->cluster_size_bits;
	min_nr = DIV_ROUND_UP_ULL(vol->mft_record_size, vol->cluster_size);
	if (required_size > allocated_size) {
		growth_bytes = required_size - allocated_size;
		required_nr = DIV_ROUND_UP_ULL(growth_bytes,
					       vol->cluster_size);
	}
	min_nr = max(min_nr, required_nr);
	growth_bytes = (u64)vol->mft_record_size * batch_records;
	batch_clusters = DIV_ROUND_UP_ULL(growth_bytes, vol->cluster_size);
	nr = batch_clusters;
	nr = max(nr, min_nr);
	if (batch_records > MFT_RECORD_INIT_BATCH)
		nr = ntfs_mft_growth_aligned_clusters(old_clusters, nr,
				min_nr, batch_clusters);
	if (check_shl_overflow((u64)nr, vol->cluster_size_bits,
			&added_bytes) ||
	    check_add_overflow((u64)allocated_size, added_bytes,
			&new_bytes) ||
	    (new_bytes >> vol->mft_record_size_bits) >= (1ULL << 32))
		nr = min_nr;
	if (check_shl_overflow((u64)nr, vol->cluster_size_bits,
			&added_bytes) ||
	    check_add_overflow((u64)allocated_size, added_bytes,
			&new_bytes) ||
	    (new_bytes >> vol->mft_record_size_bits) >= (1ULL << 32))
		return -ENOSPC;
	err = ntfs_mft_mapping_growth_preflight(mft_ni, old_clusters, nr);
	if (err == -EOPNOTSUPP && nr > MFT_GROWTH_MAX_RUNS &&
	    min_nr <= MFT_GROWTH_MAX_RUNS &&
	    batch_records > MFT_RECORD_INIT_BATCH) {
		/* Bound the actual run count to the mapping space preflighted. */
		err = ntfs_mft_mapping_growth_preflight(mft_ni, old_clusters,
				MFT_GROWTH_MAX_RUNS);
		if (!err)
			max_runs = MFT_GROWTH_MAX_RUNS;
	}
	if (err && nr != min_nr) {
		nr = min_nr;
		max_runs = 0;
		err = ntfs_mft_mapping_growth_preflight(mft_ni, old_clusters,
				nr);
	}
	if (err && err != -EOPNOTSUPP) {
		ntfs_error(vol->sb,
			   "Failed $MFT mapping growth preflight (error %d, old clusters %lld, new clusters %lld).",
			   err, old_clusters, nr);
		return err;
	}
	if (check_shl_overflow((u64)nr, vol->cluster_size_bits,
			&added_bytes) ||
	    check_add_overflow((u64)allocated_size, added_bytes,
			&new_bytes) || new_bytes > S64_MAX)
		return -EOVERFLOW;
	new_clusters = new_bytes >> vol->cluster_size_bits;
	down_read(&mft_ni->runlist.lock);
	for (rl = mft_ni->runlist.rl; rl && rl->length; rl++) {
		if (rl->lcn < 0 || rl->length <= 0 ||
		    check_add_overflow(rl->lcn, rl->length, &lcn_hint)) {
			err = -EIO;
			break;
		}
	}
	if (!err && (!rl || rl->vcn != old_clusters ||
		    rl->lcn != LCN_ENOENT))
		err = -EIO;
	up_read(&mft_ni->runlist.lock);
	if (err)
		return err;
	allocated_rl = ntfs_cluster_alloc_transacted_partial(handle, vol,
			old_clusters, nr, min_nr, lcn_hint, MFT_ZONE, true,
			false, false, max_runs);
	if (IS_ERR(allocated_rl)) {
		return PTR_ERR(allocated_rl);
	}
	expected_vcn = old_clusters;
	runs = 0;
	for (rl = allocated_rl; rl->length; rl++) {
		if (rl->vcn != expected_vcn || rl->lcn < 0 ||
		    rl->length <= 0 ||
		    check_add_overflow(expected_vcn, rl->length,
			    &expected_vcn) || ++runs > nr) {
			err = -EIO;
			goto out;
		}
	}
	if (expected_vcn <= old_clusters ||
	    expected_vcn - old_clusters < min_nr ||
	    expected_vcn - old_clusters > nr) {
		err = -EIO;
		goto out;
	}
	allocated_nr = expected_vcn - old_clusters;
	if (allocated_nr != nr) {
		nr = allocated_nr;
		if (check_shl_overflow((u64)nr, vol->cluster_size_bits,
				&added_bytes) ||
		    check_add_overflow((u64)allocated_size, added_bytes,
				&new_bytes) || new_bytes > S64_MAX) {
			err = -EOVERFLOW;
			goto out;
		}
		new_clusters = new_bytes >> vol->cluster_size_bits;
	}
	if (expected_vcn != new_clusters || rl->vcn != expected_vcn ||
	    rl->lcn != LCN_ENOENT) {
		err = -EIO;
		goto out;
	}
	down_write(&mft_ni->runlist.lock);
	read_lock_irqsave(&mft_ni->size_lock, flags);
	err = mft_ni->allocated_size == allocated_size ? 0 : -EAGAIN;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	if (err)
		goto out_unlock;
	err = ntfs_attr_allocation_register_home_undo(handle, mft_ni);
	if (err)
		goto out_unlock;
	merged_rl = ntfs_runlists_merge(&mft_ni->runlist, allocated_rl, 0,
			&new_rl_count);
	if (IS_ERR(merged_rl)) {
		err = PTR_ERR(merged_rl);
		goto out_unlock;
	}
	allocated_rl = NULL;
	mft_ni->runlist.rl = merged_rl;
	mft_ni->runlist.count = new_rl_count;
	mft_ni->runlist.rl_hint = -1;
	write_lock_irqsave(&mft_ni->size_lock, flags);
	mft_ni->allocated_size = new_bytes;
	VFS_I(mft_ni)->i_blocks += added_bytes >> 9;
	write_unlock_irqrestore(&mft_ni->size_lock, flags);
	up_write(&mft_ni->runlist.lock);
	down_write(&mft_ni->runlist.lock);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, mft_ni);
	up_write(&mft_ni->runlist.lock);
	if (err)
		ntfs_error(vol->sb,
			   "Failed to update grown $MFT mapping pairs (error %d).",
			   err);
	return err;

out_unlock:
	up_write(&mft_ni->runlist.lock);
out:
	kvfree(allocated_rl);
	return err;
}

/*
 * ntfs_mft_data_extend_allocation_nolock - extend mft data attribute
 * @vol:	volume on which to extend the mft data attribute
 *
 * Extend the mft data attribute on the ntfs volume @vol by 16 mft records
 * worth of clusters or if not enough space for this by two mft records worth
 * of clusters. Keeping at least two new records breaks the recursion between
 * extending $MFT and allocating a record for a new $MFT attribute extent.
 *
 * Note:  Only changes allocated_size, i.e. does not touch initialized_size or
 * data_size.
 *
 * Return 0 on success and -errno on error.
 *
 * Locking: - Caller must hold vol->mftbmp_lock for writing.
 *	    - This function takes NTFS_I(vol->mft_ino)->runlist.lock for
 *	      writing and releases it before returning.
 *	    - This function calls functions which take vol->lcnbmp_lock for
 *	      writing and release it before returning.
 */
static int ntfs_mft_data_extend_allocation_nolock(struct ntfs_volume *vol)
{
	s64 lcn;
	s64 old_last_vcn;
	s64 min_nr, nr, ll;
	unsigned long flags;
	struct ntfs_inode *mft_ni;
	struct runlist_element *rl, *rl2, *alloc_rl;
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct mft_record *mrec;
	struct attr_record *a = NULL;
	int ret, mp_size;
	u32 old_alen = 0;
	bool mp_rebuilt = false, mp_extended = false;
	size_t new_rl_count;

	ntfs_debug("Extending mft data allocation.");
	mft_ni = NTFS_I(vol->mft_ino);
	/*
	 * Determine the preferred allocation location, i.e. the last lcn of
	 * the mft data attribute.  The allocated size of the mft data
	 * attribute cannot be zero so we are ok to do this.
	 */
	down_write(&mft_ni->runlist.lock);
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ll = mft_ni->allocated_size;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	rl = ntfs_attr_find_vcn_nolock(mft_ni,
			NTFS_B_TO_CLU(vol, ll - 1), NULL);
	if (IS_ERR(rl) || unlikely(!rl->length || rl->lcn < 0)) {
		up_write(&mft_ni->runlist.lock);
		ntfs_error(vol->sb,
			"Failed to determine last allocated cluster of mft data attribute.");
		if (!IS_ERR(rl))
			ret = -EIO;
		else
			ret = PTR_ERR(rl);
		return ret;
	}
	lcn = rl->lcn + rl->length;
	ntfs_debug("Last lcn of mft data attribute is 0x%llx.", lcn);
	/* Keep room for the allocating record and at least one MFT reserve. */
	min_nr = DIV_ROUND_UP_ULL((u64)vol->mft_record_size * 2, vol->cluster_size);
	/* Want to allocate 16 mft records worth of clusters. */
	nr = vol->mft_record_size << 4 >> vol->cluster_size_bits;
	if (!nr)
		nr = min_nr;
	/* Ensure we do not go above 2^32-1 mft records. */
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ll = mft_ni->allocated_size;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	if (unlikely((ll + NTFS_CLU_TO_B(vol, nr)) >>
			vol->mft_record_size_bits >= (1ll << 32))) {
		nr = min_nr;
		if (unlikely((ll + NTFS_CLU_TO_B(vol, nr)) >>
				vol->mft_record_size_bits >= (1ll << 32))) {
			ntfs_warning(vol->sb,
				"Cannot allocate mft record because the maximum number of inodes (2^32) has already been reached.");
			up_write(&mft_ni->runlist.lock);
			return -ENOSPC;
		}
	}
	ntfs_debug("Trying mft data allocation with %s cluster count %lli.",
			nr > min_nr ? "default" : "minimal", (long long)nr);
	old_last_vcn = rl[1].vcn;
	/*
	 * We can release the mft_ni runlist lock, Because this function is
	 * the only one that expends $MFT data attribute and is called with
	 * mft_ni->mrec_lock.
	 * This is required for the lock order, vol->lcnbmp_lock =>
	 * mft_ni->runlist.lock.
	 */
	up_write(&mft_ni->runlist.lock);

	do {
		alloc_rl = ntfs_cluster_alloc(vol, old_last_vcn, nr, lcn,
				MFT_ZONE, true, false, false);
		if (!IS_ERR(alloc_rl))
			break;
		if (PTR_ERR(alloc_rl) != -ENOSPC || nr == min_nr) {
			ntfs_error(vol->sb,
				"Failed to allocate the minimal number of clusters (%lli) for the mft data attribute.",
				nr);
			return PTR_ERR(alloc_rl);
		}
		/*
		 * There is not enough space to do the allocation, but there
		 * might be enough space to do a minimal allocation so try that
		 * before failing.
		 */
		nr = min_nr;
		ntfs_debug("Retrying mft data allocation with minimal cluster count %lli.", nr);
	} while (1);

	/*
	 * Keep @alloc_rl until the extension is complete: it describes exactly
	 * the new clusters, which undo_alloc frees if a later step fails.
	 */
	down_write(&mft_ni->runlist.lock);
	rl = ntfs_runlists_merge_keep_src(&mft_ni->runlist, alloc_rl, 0,
			&new_rl_count);
	if (IS_ERR(rl)) {
		up_write(&mft_ni->runlist.lock);
		ntfs_error(vol->sb, "Failed to merge runlists for mft data attribute.");
		if (ntfs_cluster_free_from_rl(vol, alloc_rl)) {
			ntfs_error(vol->sb,
				"Failed to deallocate clusters from the mft data attribute.%s", es);
			NVolSetErrors(vol);
		}
		kvfree(alloc_rl);
		return PTR_ERR(rl);
	}
	mft_ni->runlist.rl = rl;
	mft_ni->runlist.count = new_rl_count;
	ntfs_debug("Allocated %lli clusters.", (long long)nr);
	/* Find the last run in the new runlist. */
	for (; rl[1].length; rl++)
		;
	up_write(&mft_ni->runlist.lock);

	/* Update the attribute record as well. */
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		ntfs_error(vol->sb, "Failed to map mft record.");
		ret = PTR_ERR(mrec);
		goto undo_alloc;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.");
		ret = -ENOMEM;
		goto undo_alloc;
	}
	ret = ntfs_attr_lookup(mft_ni->type, mft_ni->name, mft_ni->name_len,
			CASE_SENSITIVE, rl[1].vcn, NULL, 0, ctx);
	if (unlikely(ret)) {
		ntfs_error(vol->sb, "Failed to find last attribute extent of mft data attribute.");
		if (ret == -ENOENT)
			ret = -EIO;
		goto undo_alloc;
	}
	a = ctx->attr;
	ll = le64_to_cpu(a->data.non_resident.lowest_vcn);

	down_write(&mft_ni->runlist.lock);
	/* Search back for the previous last allocated cluster of mft bitmap. */
	for (rl2 = rl; rl2 > mft_ni->runlist.rl; rl2--) {
		if (ll >= rl2->vcn)
			break;
	}
	WARN_ON(ll < rl2->vcn);
	WARN_ON(ll >= rl2->vcn + rl2->length);
	/* Get the size for the new mapping pairs array for this extent. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl2, ll, -1, -1);
	if (unlikely(mp_size <= 0)) {
		ntfs_error(vol->sb,
			"Get size for mapping pairs failed for mft data attribute extent.");
		ret = mp_size;
		if (!ret)
			ret = -EIO;
		up_write(&mft_ni->runlist.lock);
		goto undo_alloc;
	}
	up_write(&mft_ni->runlist.lock);

	/* Expand the attribute record if necessary. */
	old_alen = le32_to_cpu(a->length);
	ret = ntfs_attr_record_resize(ctx->mrec, a, mp_size +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset));
	if (unlikely(ret)) {
		ret = ntfs_mft_attr_extend(mft_ni, NULL);
		if (!ret)
			goto extended_ok;
		if (ret != -EAGAIN)
			mp_extended = true;
		goto undo_alloc;
	}
	mp_rebuilt = true;
	/* Generate the mapping pairs array directly into the attr record. */
	ret = ntfs_mapping_pairs_build(vol, (u8 *)a +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset),
			mp_size, rl2, ll, -1, NULL, NULL, NULL);
	if (unlikely(ret)) {
		ntfs_error(vol->sb, "Failed to build mapping pairs array of mft data attribute.");
		goto undo_alloc;
	}
	/* Update the highest_vcn. */
	a->data.non_resident.highest_vcn = cpu_to_le64(rl[1].vcn - 1);
	/*
	 * We now have extended the mft data allocated_size by nr clusters.
	 * Reflect this in the struct ntfs_inode structure and the attribute record.
	 * @rl is the last (non-terminator) runlist element of mft data
	 * attribute.
	 */
	if (a->data.non_resident.lowest_vcn) {
		/*
		 * We are not in the first attribute extent, switch to it, but
		 * first ensure the changes will make it to disk later.
		 */
		mark_mft_record_dirty(ctx->ntfs_ino);
extended_ok:
		ntfs_attr_reinit_search_ctx(ctx);
		ret = ntfs_attr_lookup(mft_ni->type, mft_ni->name,
				mft_ni->name_len, CASE_SENSITIVE, 0, NULL, 0,
				ctx);
		if (unlikely(ret)) {
			ntfs_error(vol->sb,
				"Failed to find first attribute extent of mft data attribute.");
			goto restore_undo_alloc;
		}
		a = ctx->attr;
	}

	write_lock_irqsave(&mft_ni->size_lock, flags);
	mft_ni->allocated_size += NTFS_CLU_TO_B(vol, nr);
	a->data.non_resident.allocated_size =
			cpu_to_le64(mft_ni->allocated_size);
	write_unlock_irqrestore(&mft_ni->size_lock, flags);
	/* Ensure the changes make it to disk. */
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
	kvfree(alloc_rl);
	ntfs_debug("Done.");
	return 0;
restore_undo_alloc:
	ntfs_attr_reinit_search_ctx(ctx);
	if (ntfs_attr_lookup(mft_ni->type, mft_ni->name, mft_ni->name_len,
			CASE_SENSITIVE, rl[1].vcn, NULL, 0, ctx)) {
		ntfs_error(vol->sb,
			"Failed to find last attribute extent of mft data attribute.%s", es);
		write_lock_irqsave(&mft_ni->size_lock, flags);
		mft_ni->allocated_size += NTFS_CLU_TO_B(vol, nr);
		write_unlock_irqrestore(&mft_ni->size_lock, flags);
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(mft_ni);
		kvfree(alloc_rl);
		/*
		 * The only thing that is now wrong is ->allocated_size of the
		 * base attribute extent which chkdsk should be able to fix.
		 */
		NVolSetErrors(vol);
		return ret;
	}
	ctx->attr->data.non_resident.highest_vcn =
			cpu_to_le64(old_last_vcn - 1);
undo_alloc:
	/*
	 * Entered without the runlist lock.  Take the new runs off the
	 * runlist under it, and free their clusters from @alloc_rl once it
	 * is dropped, as lcnbmp_lock nests outside it (see above).
	 */
	down_write(&mft_ni->runlist.lock);
	if (ntfs_rl_truncate_nolock(vol, &mft_ni->runlist, old_last_vcn)) {
		ntfs_error(vol->sb, "Failed to truncate mft data attribute runlist.%s", es);
		NVolSetErrors(vol);
		/*
		 * The runlist may still reference the clusters, so leave them
		 * allocated until chkdsk.
		 */
		kvfree(alloc_rl);
		alloc_rl = NULL;
	}
	up_write(&mft_ni->runlist.lock);
	if (ntfs_cluster_free_from_rl(vol, alloc_rl)) {
		ntfs_error(vol->sb, "Failed to free clusters from mft data attribute.%s", es);
		NVolSetErrors(vol);
	}
	kvfree(alloc_rl);
	if (mp_extended && ntfs_attr_update_mapping_pairs(mft_ni, 0)) {
		ntfs_error(vol->sb, "Failed to restore mapping pairs.%s",
			   es);
		NVolSetErrors(vol);
	}
	if (ctx) {
		a = ctx->attr;
		if (mp_rebuilt && !IS_ERR(ctx->mrec)) {
			int err;

			down_read(&mft_ni->runlist.lock);
			err = ntfs_mapping_pairs_build(vol, (u8 *)a + le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset),
				old_alen - le16_to_cpu(
					a->data.non_resident.mapping_pairs_offset),
				mft_ni->runlist.rl, ll, -1, NULL, NULL, NULL);
			up_read(&mft_ni->runlist.lock);
			if (err) {
				ntfs_error(vol->sb, "Failed to restore mapping pairs array.%s", es);
				NVolSetErrors(vol);
			}
			if (ntfs_attr_record_resize(ctx->mrec, a, old_alen)) {
				ntfs_error(vol->sb, "Failed to restore attribute record.%s", es);
				NVolSetErrors(vol);
			}
			mark_mft_record_dirty(ctx->ntfs_ino);
		} else if (IS_ERR(ctx->mrec)) {
			ntfs_error(vol->sb, "Failed to restore attribute search context.%s", es);
			NVolSetErrors(vol);
		}
		ntfs_attr_put_search_ctx(ctx);
	}
	if (!IS_ERR(mrec))
		unmap_mft_record(mft_ni);
	return ret;
}

/*
 * ntfs_mft_record_layout - layout an mft record into a memory buffer
 * @vol:	volume to which the mft record will belong
 * @mft_no:	mft reference specifying the mft record number
 * @m:		destination buffer of size >= @vol->mft_record_size bytes
 *
 * Layout an empty, unused mft record with the mft record number @mft_no into
 * the buffer @m.  The volume @vol is needed because the mft record structure
 * was modified in NTFS 3.1 so we need to know which volume version this mft
 * record will be used on.
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_mft_record_layout(const struct ntfs_volume *vol, const s64 mft_no,
		struct mft_record *m)
{
	struct attr_record *a;

	ntfs_debug("Entering for mft record 0x%llx.", (long long)mft_no);
	if (mft_no >= (1ll << 32)) {
		ntfs_error(vol->sb, "Mft record number 0x%llx exceeds maximum of 2^32.",
				(long long)mft_no);
		return -ERANGE;
	}
	/* Start by clearing the whole mft record to gives us a clean slate. */
	memset(m, 0, vol->mft_record_size);
	/* Aligned to 2-byte boundary. */
	if (vol->major_ver < 3 || (vol->major_ver == 3 && !vol->minor_ver))
		m->usa_ofs = cpu_to_le16((sizeof(struct mft_record_old) + 1) & ~1);
	else {
		m->usa_ofs = cpu_to_le16((sizeof(struct mft_record) + 1) & ~1);
		/*
		 * Set the NTFS 3.1+ specific fields while we know that the
		 * volume version is 3.1+.
		 */
		m->reserved = 0;
		m->mft_record_number = cpu_to_le32((u32)mft_no);
	}
	m->magic = magic_FILE;
	if (vol->mft_record_size >= NTFS_BLOCK_SIZE)
		m->usa_count = cpu_to_le16(vol->mft_record_size /
				NTFS_BLOCK_SIZE + 1);
	else {
		m->usa_count = cpu_to_le16(1);
		ntfs_warning(vol->sb,
			"Sector size is bigger than mft record size.  Setting usa_count to 1.  If chkdsk reports this as corruption");
	}
	/* Set the update sequence number to 1. */
	*(__le16 *)((u8 *)m + le16_to_cpu(m->usa_ofs)) = cpu_to_le16(1);
	m->lsn = 0;
	m->sequence_number = cpu_to_le16(1);
	m->link_count = 0;
	/*
	 * Place the attributes straight after the update sequence array,
	 * aligned to 8-byte boundary.
	 */
	m->attrs_offset = cpu_to_le16((le16_to_cpu(m->usa_ofs) +
			(le16_to_cpu(m->usa_count) << 1) + 7) & ~7);
	m->flags = 0;
	/*
	 * Using attrs_offset plus eight bytes (for the termination attribute).
	 * attrs_offset is already aligned to 8-byte boundary, so no need to
	 * align again.
	 */
	m->bytes_in_use = cpu_to_le32(le16_to_cpu(m->attrs_offset) + 8);
	m->bytes_allocated = cpu_to_le32(vol->mft_record_size);
	m->base_mft_record = 0;
	m->next_attr_instance = 0;
	/* Add the termination attribute. */
	a = (struct attr_record *)((u8 *)m + le16_to_cpu(m->attrs_offset));
	a->type = AT_END;
	a->length = 0;
	ntfs_debug("Done.");
	return 0;
}

/*
 * ntfs_mft_record_format - format an mft record on an ntfs volume
 * @vol:	volume on which to format the mft record
 * @mft_no:	mft record number to format
 *
 * Format the mft record @mft_no in $MFT/$DATA, i.e. lay out an empty, unused
 * mft record into the appropriate place of the mft data attribute.  This is
 * used when extending the mft data attribute.
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_mft_record_format_common(struct ntfs_log_handle *handle,
					 const struct ntfs_volume *vol,
					 const s64 mft_no)
{
	loff_t i_size;
	struct inode *mft_vi = vol->mft_ino;
	struct folio *folio;
	struct mft_record *log_mrec;
	struct mft_record *m;
	pgoff_t index, end_index;
	unsigned int ofs;
	u64 operation_lsn;
	int err;

	if (handle) {
		log_mrec = kmalloc(vol->mft_record_size, GFP_NOFS);
		if (!log_mrec)
			return -ENOMEM;
		err = ntfs_mft_record_layout(vol, mft_no, log_mrec);
		if (!err)
			err = ntfs_log_mft_record_initialize(handle, mft_no,
							     log_mrec,
							     &operation_lsn);
		kfree(log_mrec);
		if (err) {
			ntfs_error(vol->sb,
				   "Failed to journal formatted mft record 0x%llx (error %d).",
				   (long long)mft_no, err);
			return err;
		}
	}
	ntfs_debug("Entering for mft record 0x%llx.", (long long)mft_no);
	/*
	 * The index into the page cache and the offset within the page cache
	 * page of the wanted mft record.
	 */
	index = NTFS_MFT_NR_TO_PIDX(vol, mft_no);
	ofs = NTFS_MFT_NR_TO_POFS(vol, mft_no);
	/* The maximum valid index into the page cache for $MFT's data. */
	i_size = i_size_read(mft_vi);
	end_index = i_size >> PAGE_SHIFT;
	if (unlikely(index >= end_index)) {
		if (unlikely(index > end_index ||
			     ofs + vol->mft_record_size > (i_size & ~PAGE_MASK))) {
			ntfs_error(vol->sb, "Tried to format non-existing mft record 0x%llx.",
					(long long)mft_no);
			return -ENOENT;
		}
	}

	/* Read, map, and pin the folio containing the mft record. */
	folio = ntfs_read_metadata_folio(mft_vi->i_mapping, index);
	if (IS_ERR(folio)) {
		ntfs_error(vol->sb, "Failed to map page containing mft record to format 0x%llx.",
				(long long)mft_no);
		return PTR_ERR(folio);
	}
	folio_lock(folio);
	if (folio_test_writeback(folio))
		folio_wait_writeback(folio);
	folio_clear_uptodate(folio);
	m = (struct mft_record *)((u8 *)kmap_local_folio(folio, 0) + ofs);
	err = ntfs_mft_record_layout(vol, mft_no, m);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Failed to layout mft record 0x%llx.",
				(long long)mft_no);

		folio_mark_uptodate(folio);
		folio_unlock(folio);
		kunmap_local(m);
		folio_put(folio);
		return err;
	}
	if (handle)
		m->lsn = cpu_to_le64(operation_lsn);
	pre_write_mst_fixup((struct ntfs_record *)m, vol->mft_record_size);
	folio_mark_uptodate(folio);
	/*
	 * Make sure the mft record is written out to disk.  We could use
	 * ilookup5() to check if an inode is in icache and so on but this is
	 * unnecessary as ntfs_writepage() will write the dirty record anyway.
	 */
	ntfs_mft_mark_dirty(folio);
	folio_unlock(folio);
	kunmap_local(m);
	folio_put(folio);
	ntfs_debug("Done.");
	return 0;
}

static int ntfs_mft_record_format(const struct ntfs_volume *vol,
				  const s64 mft_no)
{
	return ntfs_mft_record_format_common(NULL, vol, mft_no);
}

static int ntfs_mft_record_format_transacted(struct ntfs_log_handle *handle,
					     const struct ntfs_volume *vol,
					     s64 mft_no)
{
	if (!handle)
		return -EINVAL;
	return ntfs_mft_record_format_common(handle, vol, mft_no);
}

static struct ntfs_log_handle *ntfs_mft_growth_begin(
		struct ntfs_log_handle *parent, struct ntfs_volume *vol,
		u32 *batch_records)
{
	static const u32 batches[] = {
		MFT_RECORD_INIT_LARGE_BATCH, MFT_RECORD_INIT_MEDIUM_BATCH,
	};
	struct ntfs_log_handle *handle;
	int credits, i;

	if (!parent || !vol || !batch_records)
		return ERR_PTR(-EINVAL);
	*batch_records = MFT_RECORD_INIT_BATCH;
	if (!ntfs_can_speculate_allocation(vol))
		goto default_batch;

	/* Never start optional growth without funding its entire undo budget. */
	for (i = 0; i < ARRAY_SIZE(batches); i++) {
		credits = ntfs_mft_record_alloc_credits_batch(vol, batches[i]);
		if (credits < 0 && credits != -EOVERFLOW && credits != -E2BIG)
			return ERR_PTR(credits);
		if (credits < 0 || credits > parent->operation_credits)
			continue;
		handle = ntfs_log_begin_independent_full(parent, credits);
		if (!IS_ERR(handle)) {
			*batch_records = batches[i];
			return handle;
		}
		if (PTR_ERR(handle) != -EAGAIN)
			return handle;
	}

default_batch:
	credits = ntfs_mft_record_alloc_credits(vol);
	if (credits < 0)
		return ERR_PTR(credits);
	return ntfs_log_begin_independent(parent, credits);
}

/*
 * ntfs_mft_record_alloc - allocate an mft record on an ntfs volume
 * @vol:	[IN]  volume on which to allocate the mft record
 * @mode:	[IN]  mode if want a file or directory, i.e. base inode or 0
 * @ni:		[OUT] on success, set to the allocated ntfs inode
 * @base_ni:	[IN]  open base inode if allocating an extent mft record or NULL
 * @ni_mrec:	[OUT] on successful return this is the mapped mft record
 * @mft_data_vcn: [IN] lowest VCN of a new $MFT/$DATA extent, or -1
 *
 * Allocate an mft record in $MFT/$DATA of an open ntfs volume @vol.
 *
 * If @base_ni is NULL make the mft record a base mft record, i.e. a file or
 * direvctory inode, and allocate it at the default allocator position.  In
 * this case @mode is the file mode as given to us by the caller.  We in
 * particular use @mode to distinguish whether a file or a directory is being
 * created (S_IFDIR(mode) and S_IFREG(mode), respectively).
 *
 * If @base_ni is not NULL make the allocated mft record an extent record,
 * allocate it starting at the mft record after the base mft record and attach
 * the allocated and opened ntfs inode to the base inode @base_ni.  In this
 * case @mode must be 0 as it is meaningless for extent inodes.
 *
 * You need to check the return value with IS_ERR().  If false, the function
 * was successful and the return value is the now opened ntfs inode of the
 * allocated mft record.  *@mrec is then set to the allocated, mapped, pinned,
 * and locked mft record.  If IS_ERR() is true, the function failed and the
 * error code is obtained from PTR_ERR(return value).  *@mrec is undefined in
 * this case.
 *
 * Allocation strategy:
 *
 * To find a free mft record, we scan the mft bitmap for a zero bit.  To
 * optimize this we start scanning at the place specified by @base_ni or if
 * @base_ni is NULL we start where we last stopped and we perform wrap around
 * when we reach the end.  Note, we do not try to allocate mft records below
 * number 24 because numbers 0 to 15 are the defined system files and records
 * 16 to 23 are kept for metadata compatibility. Records reserved dynamically
 * at the initialized MFT tail are skipped by normal allocation and consumed by
 * $MFT metadata extent allocation.
 *
 * When scanning the mft bitmap, we only search up to the last allocated mft
 * record.  If there are no free records left in the range 24 to number of
 * allocated mft records, then we extend the $MFT/$DATA attribute in order to
 * create free mft records.  Non-journaled growth normally allocates 16 records
 * or one cluster at a time.  Journaled growth can reserve a larger batch when
 * its complete undo budget fits, and accepts a shorter allocation if necessary.
 *
 * When extending the initialized MFT tail, we also initialize up to four
 * additional records and reserve them in memory for future $MFT metadata
 * extents. Journaled growth initializes up to 16, 64, or 256 records per
 * transaction within the allocated space and initialized bitmap. The
 * remaining free records can be used without another durable growth commit.
 * If there are fewer than 24 mft records, records are initialized until record
 * 24, which is the first record used for normal files.
 *
 * If during any stage we overflow the initialized data in the mft bitmap, we
 * extend the initialized size (and data size), allocating another cluster if
 * required.  Non-journaled growth extends by 8 bytes. The largest journaled
 * batch extends by up to 32 bytes.  The bitmap data size has to cover the
 * number of mft records, but it can be bigger, in which case the superfluous
 * bits are padded with zeroes.
 *
 * Thus, when we return successfully (IS_ERR() is false), we will have:
 *	- initialized / extended the mft bitmap if necessary,
 *	- initialized / extended the mft data if necessary,
 *	- set the bit corresponding to the mft record being allocated in the
 *	  mft bitmap,
 *	- opened an struct ntfs_inode for the allocated mft record, and we will have
 *	- returned the struct ntfs_inode as well as the allocated mapped, pinned, and
 *	  locked mft record.
 *
 * On error, the volume will be left in a consistent state and no record will
 * be allocated.  If rolling back a partial operation fails, we may leave some
 * inconsistent metadata in which case we set NVolErrors() so the volume is
 * left dirty when unmounted.
 *
 * Note, this function cannot make use of most of the normal functions, like
 * for example for attribute resizing, etc, because when the run list overflows
 * the base mft record and an attribute list is used, it is very important that
 * the extension mft records used to store the $DATA attribute of $MFT can be
 * reached without having to read the information contained inside them, as
 * this would make it impossible to find them in the first place after the
 * volume is unmounted.  $MFT/$BITMAP probably does not need to follow this
 * rule because the bitmap is not essential for finding the mft records, but on
 * the other hand, handling the bitmap in this special way would make life
 * easier because otherwise there might be circular invocations of functions
 * when reading the bitmap.
 */
static int __ntfs_mft_record_alloc(struct ntfs_log_handle *caller_handle,
		struct ntfs_volume *vol, const int mode, struct ntfs_inode **ni,
		struct ntfs_inode *base_ni, struct mft_record **ni_mrec,
		const s64 mft_data_vcn)
{
	struct ntfs_log_handle *log_handle = caller_handle;
	struct ntfs_log_handle *growth_handle = NULL;
	struct ntfs_mft_alloc_home_undo *alloc_undo = NULL;
	struct ntfs_mft_count_home_undo *count_undo = NULL;
	struct mft_record *old_disk_mrec = NULL;
	struct mft_record *log_mrec = NULL;
	s64 ll, bit, old_data_initialized, old_data_size;
	s64 nr_new_mft_records = 0;
	s64 max_mft_no = -1, reserve_start = -1, reserve_end = -1;
	s64 candidate_reserve_end = -1;
	s64 *reserve_endp;
	u64 operation_lsn = 0;
	unsigned long flags;
	struct folio *folio;
	struct ntfs_inode *mft_ni, *mftbmp_ni;
	struct ntfs_attr_search_ctx *ctx;
	struct mft_record *m = NULL;
	struct attr_record *a;
	pgoff_t index;
	unsigned int ofs;
	int credits;
	int err;
	__le16 seq_no, usn;
	bool record_formatted = false, from_reserve = false, tail_alloc = false;
	bool reserve_created = false;
	bool forced_reserved_record = false;
	bool log_commit_failed = false;
	bool mft_allocation_grown = false;
	bool own_log_handle = false;
	bool corrupt_mft_record = false;
	u32 growth_batch_records = MFT_RECORD_INIT_BATCH;
	unsigned int memalloc_flags;

	if (!vol || !ni || (base_ni && *ni))
		return -EINVAL;
	if (NVolShutdown(vol))
		return -EIO;
	/* @mode and @base_ni are mutually exclusive. */
	if (mode && base_ni)
		return -EINVAL;
	if (mft_data_vcn >= 0 &&
	    (!base_ni || base_ni->mft_no != FILE_MFT))
		return -EINVAL;
	if (mft_data_vcn >= 0) {
		u64 vbo;

		if ((u64)mft_data_vcn > (U64_MAX >> vol->cluster_size_bits))
			return -EOVERFLOW;
		vbo = (u64)mft_data_vcn << vol->cluster_size_bits;
		/*
		 * The whole extent record must be reachable without this
		 * extent, including when an MFT record spans multiple clusters.
		 */
		max_mft_no = vbo >> vol->mft_record_size_bits;
	}

	if (base_ni)
		ntfs_debug("Entering (allocating an extent mft record for base mft record 0x%llx).",
				(long long)base_ni->mft_no);
	else
		ntfs_debug("Entering (allocating a base mft record).");

	/* $MFT's own extent allocation may already hold mftbmp_lock. */
	if (READ_ONCE(vol->journal) &&
	    (!base_ni || base_ni->mft_no != FILE_MFT)) {
		err = ntfs_log_reclaim_deferred(vol, NTFS_LOG_DEFERRED_MFT,
				atomic64_read(&vol->free_mft_records), 1, false);
		if (err)
			return err;
	}

	/* Reserve before taking allocator locks so checkpoint writeback cannot recurse. */
	if (!base_ni && vol->journal && !caller_handle) {
		credits = ntfs_mft_record_alloc_credits(vol);
		if (credits < 0)
			return credits;
		log_handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(log_handle))
			return PTR_ERR(log_handle);
		own_log_handle = true;
	}

	memalloc_flags = memalloc_nofs_save();

	mft_ni = NTFS_I(vol->mft_ino);
	if (!base_ni || base_ni->mft_no != FILE_MFT)
		mutex_lock(&mft_ni->mrec_lock);
	if (NVolShutdown(vol)) {
		err = -EIO;
		goto err_out;
	}
	mftbmp_ni = NTFS_I(vol->mftbmp_ino);
	from_reserve = false;
	reserve_created = false;
	candidate_reserve_end = -1;
	if (!base_ni || base_ni->mft_no != FILE_MFT)
		down_write(&vol->mftbmp_lock);
	if (base_ni && base_ni->mft_no == FILE_MFT &&
	    vol->mft_record_reserve_pos < vol->mft_record_reserve_end &&
	    (max_mft_no < 0 || vol->mft_record_reserve_pos < max_mft_no)) {
		bit = vol->mft_record_reserve_pos;
		if (log_handle)
			err = ntfs_bitmap_set_bits_in_run_transacted(log_handle,
					vol->mftbmp_ino, bit, 1, 1);
		else
			err = ntfs_bitmap_set_bit(vol->mftbmp_ino, bit);
		if (unlikely(err)) {
			ntfs_error(vol->sb,
				   "Failed to allocate reserved MFT record 0x%llx.",
				   bit);
			goto err_out;
		}
		vol->mft_record_reserve_pos++;
		from_reserve = true;
		ntfs_debug("Allocated MFT metadata record 0x%llx from tail reserve.",
			   bit);
		goto have_alloc_rec;
	}
	reserve_endp = vol->mft_record_reserve_pos >=
			vol->mft_record_reserve_end ? &candidate_reserve_end : NULL;
	bit = mft_bitmap_alloc_free_rec(vol, base_ni, max_mft_no, reserve_endp);
	if (bit >= 0) {
		if (candidate_reserve_end > bit + 1) {
			vol->mft_record_reserve_pos = bit + 1;
			vol->mft_record_reserve_end = candidate_reserve_end;
			reserve_created = true;
			ntfs_debug("Reserved free MFT records [0x%llx, 0x%llx) for metadata.",
				   bit + 1, candidate_reserve_end);
		}
		ntfs_debug("Found free record (#1), bit 0x%llx.",
				(long long)bit);
		goto found_free_rec;
	}
	if (bit != -ENOSPC) {
		err = bit;
		if (!base_ni || base_ni->mft_no != FILE_MFT)
			up_write(&vol->mftbmp_lock);
		if (own_log_handle) {
			int abort_err = ntfs_log_abort(log_handle);

			log_handle = NULL;
			if (abort_err)
				err = abort_err;
		}
		goto err_out;
	}
	if (base_ni && base_ni->mft_no == FILE_MFT) {
		static const u8 bootstrap_records[] = {
			FILE_reserved15, FILE_reserved12, FILE_reserved13,
			FILE_reserved14,
		};
		int i;

		for (i = 0; i < ARRAY_SIZE(bootstrap_records); i++) {
			if (max_mft_no >= 0 && bootstrap_records[i] >= max_mft_no)
				continue;
			if (!mft_reserved_is_free(vol, mft_ni,
						  bootstrap_records[i]))
				continue;
			bit = bootstrap_records[i];
			forced_reserved_record = true;
			ntfs_debug("Using reserved MFT record %lld to bootstrap metadata extension.",
				   bit);
			goto have_alloc_rec;
		}
		memalloc_nofs_restore(memalloc_flags);
		return bit;
	}

	/*
	 * No free mft records left.  If the mft bitmap already covers more
	 * than the currently used mft records, the next records are all free,
	 * so we can simply allocate the first unused mft record.
	 * Note: We also have to make sure that the mft bitmap at least covers
	 * the first 24 mft records as they are special and whilst they may not
	 * be in use, we do not allocate from them.
	 */
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ll = mft_ni->initialized_size >> vol->mft_record_size_bits;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	old_data_initialized = mftbmp_ni->initialized_size;
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	if (old_data_initialized << 3 > ll &&
	    old_data_initialized << 3 > FIRST_NORMAL_MFT_RECORD) {
		bit = ll;
		if (bit < FIRST_NORMAL_MFT_RECORD)
			bit = FIRST_NORMAL_MFT_RECORD;
		if (unlikely(bit >= (1ll << 32)))
			goto max_err_out;
		ntfs_debug("Found free record (#2), bit 0x%llx.",
				(long long)bit);
		goto found_free_rec;
	}
	/*
	 * The mft bitmap needs to be expanded until it covers the first unused
	 * mft record that we can allocate.
	 * Note: The smallest mft record we allocate is mft record 24.
	 */
	bit = old_data_initialized << 3;
	if (unlikely(bit >= (1ll << 32)))
		goto max_err_out;
	if (log_handle) {
		growth_handle = ntfs_mft_growth_begin(log_handle, vol,
				&growth_batch_records);
		if (IS_ERR(growth_handle)) {
			err = PTR_ERR(growth_handle);
			growth_handle = NULL;
			up_write(&vol->mftbmp_lock);
			goto err_out;
		}
	}
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	old_data_size = mftbmp_ni->allocated_size;
	ntfs_debug("Status of mftbmp before extension: allocated_size 0x%llx, data_size 0x%llx, initialized_size 0x%llx.",
			old_data_size, i_size_read(vol->mftbmp_ino),
			old_data_initialized);
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	if (old_data_initialized + 8 > old_data_size) {
		/* Need to extend bitmap by one more cluster. */
		ntfs_debug("mftbmp: initialized_size + 8 > allocated_size.");
		if (log_handle)
			err = ntfs_mft_bitmap_extend_allocation_transacted_nolock(
					growth_handle, vol);
		else
			err = ntfs_mft_bitmap_extend_allocation_nolock(vol);
		if (err == -EAGAIN)
			err = log_handle ?
				ntfs_mft_bitmap_extend_allocation_transacted_nolock(
					growth_handle, vol) :
				ntfs_mft_bitmap_extend_allocation_nolock(vol);

		if (unlikely(err)) {
			if (!base_ni || base_ni->mft_no != FILE_MFT)
				up_write(&vol->mftbmp_lock);
			ntfs_error(vol->sb,
				   "Failed to extend MFT bitmap allocation while allocating record for inode %llu (error %d).",
				   base_ni ? (unsigned long long)base_ni->mft_no :
					   (unsigned long long)FILE_MFT, err);
			goto err_out;
		}
#ifdef DEBUG
		read_lock_irqsave(&mftbmp_ni->size_lock, flags);
		ntfs_debug("Status of mftbmp after allocation extension: allocated_size 0x%llx, data_size 0x%llx, initialized_size 0x%llx.",
				mftbmp_ni->allocated_size,
				i_size_read(vol->mftbmp_ino),
				mftbmp_ni->initialized_size);
		read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
#endif /* DEBUG */
	}
	/*
	 * We now have sufficient allocated space, extend the initialized_size
	 * as well as the data_size if necessary and fill the new space with
	 * zeroes.
	 */
	if (log_handle)
		err = ntfs_mft_bitmap_extend_initialized_transacted_nolock(
				growth_handle, vol, growth_batch_records);
	else
		err = ntfs_mft_bitmap_extend_initialized_nolock(vol);
	if (unlikely(err)) {
		if (!base_ni || base_ni->mft_no != FILE_MFT)
			up_write(&vol->mftbmp_lock);
		ntfs_error(vol->sb,
			   "Failed to extend MFT bitmap initialized size while allocating record for inode %llu (error %d).",
			   base_ni ? (unsigned long long)base_ni->mft_no :
				   (unsigned long long)FILE_MFT, err);
		goto err_out;
	}
#ifdef DEBUG
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	ntfs_debug("Status of mftbmp after initialized extension: allocated_size 0x%llx, data_size 0x%llx, initialized_size 0x%llx.",
			mftbmp_ni->allocated_size,
			i_size_read(vol->mftbmp_ino),
			mftbmp_ni->initialized_size);
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
#endif /* DEBUG */
	ntfs_debug("Found free record (#3), bit 0x%llx.", (long long)bit);
found_free_rec:
	/* @bit is the found free mft record, allocate it in the mft bitmap. */
	ntfs_debug("At found_free_rec.");
	if (check_shl_overflow(bit + 1, vol->mft_record_size_bits, &ll)) {
		err = -EOVERFLOW;
		if (!base_ni || base_ni->mft_no != FILE_MFT)
			up_write(&vol->mftbmp_lock);
		goto err_out;
	}
	err = ntfs_bitmap_validate_run(vol->mftbmp_ino, bit, 1, 0);
	if (unlikely(err)) {
		ntfs_error(vol->sb,
				"Selected MFT bitmap bit is not free (error %d).",
				err);
		if (!base_ni || base_ni->mft_no != FILE_MFT)
			up_write(&vol->mftbmp_lock);
		goto err_out;
	}
	if (log_handle)
		err = ntfs_bitmap_set_bits_in_run_transacted(log_handle,
				vol->mftbmp_ino, bit, 1, 1);
	else
		err = ntfs_bitmap_set_bit(vol->mftbmp_ino, bit);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Failed to allocate bit in mft bitmap.");
		if (!base_ni || base_ni->mft_no != FILE_MFT)
			up_write(&vol->mftbmp_lock);
		goto err_out;
	}
	ntfs_debug("Set bit 0x%llx in mft bitmap.", (long long)bit);
	/*
	 * The mft bitmap is now uptodate.  Deal with mft data attribute now.
	 * Note, we keep hold of the mft bitmap lock for writing until all
	 * modifications to the mft data attribute are complete, too, as they
	 * will impact decisions for mft bitmap and mft record allocation done
	 * by a parallel allocation and if the lock is not maintained a
	 * parallel allocation could allocate the same mft record as this one.
	 */
have_alloc_rec:
	ll = (bit + 1) << vol->mft_record_size_bits;
	read_lock_irqsave(&mft_ni->size_lock, flags);
	old_data_initialized = mft_ni->initialized_size;
	old_data_size = i_size_read(vol->mft_ino);
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	tail_alloc = (!base_ni || base_ni->mft_no != FILE_MFT) &&
			bit >= (old_data_initialized >> vol->mft_record_size_bits) &&
			vol->mft_record_reserve_pos >= vol->mft_record_reserve_end;
	if (tail_alloc)
		ll = (bit + 2) << vol->mft_record_size_bits;
	if (ll <= old_data_initialized) {
		ntfs_debug("Allocated mft record already initialized.");
		goto mft_rec_already_initialized;
	}
	if (log_handle && !growth_handle &&
	    (!base_ni || base_ni->mft_no != FILE_MFT)) {
		growth_handle = ntfs_mft_growth_begin(log_handle, vol,
				&growth_batch_records);
		if (IS_ERR(growth_handle)) {
			err = PTR_ERR(growth_handle);
			growth_handle = NULL;
			goto undo_mftbmp_alloc_nolock;
		}
	}
	ntfs_debug("Initializing allocated mft record.");
	/*
	 * The mft record is outside the initialized data.  Extend the mft data
	 * attribute until it covers the allocated record.  The loop is only
	 * actually traversed more than once when a freshly formatted volume is
	 * first written to so it optimizes away nicely in the common case.
	 */
	if (!base_ni || base_ni->mft_no != FILE_MFT) {
		read_lock_irqsave(&mft_ni->size_lock, flags);
		ntfs_debug("Status of mft data before extension: allocated_size 0x%llx, data_size 0x%llx, initialized_size 0x%llx.",
				mft_ni->allocated_size, i_size_read(vol->mft_ino),
				mft_ni->initialized_size);
		while (ll > mft_ni->allocated_size) {
			read_unlock_irqrestore(&mft_ni->size_lock, flags);
			if (log_handle) {
				if (mft_allocation_grown) {
					read_lock_irqsave(&mft_ni->size_lock, flags);
					old_data_size = mft_ni->allocated_size;
					read_unlock_irqrestore(&mft_ni->size_lock,
							       flags);
					ntfs_error(vol->sb,
						   "$MFT allocation remained too small after journaled growth (required 0x%llx, allocated 0x%llx).",
						   ll, old_data_size);
					err = -EOPNOTSUPP;
				} else {
					err = ntfs_mft_data_extend_allocation_transacted_nolock(
						growth_handle, vol, ll,
						growth_batch_records);
					if (!err)
						mft_allocation_grown = true;
				}
			} else {
				err = ntfs_mft_data_extend_allocation_nolock(vol);
				if (err == -EAGAIN)
					err = ntfs_mft_data_extend_allocation_nolock(
						vol);
			}

			if (unlikely(err)) {
				if (err != -ENOSPC)
					ntfs_error(vol->sb,
						   "Failed to extend mft data allocation (error %d).",
						   err);
				goto undo_mftbmp_alloc_nolock;
			}
			read_lock_irqsave(&mft_ni->size_lock, flags);
			ntfs_debug("Status of mft data after allocation extension: allocated_size 0x%llx, data_size 0x%llx, initialized_size 0x%llx.",
					mft_ni->allocated_size, i_size_read(vol->mft_ino),
					mft_ni->initialized_size);
		}
		read_unlock_irqrestore(&mft_ni->size_lock, flags);
		if (tail_alloc) {
			s64 bitmap_records;

			read_lock_irqsave(&mft_ni->size_lock, flags);
			reserve_end = mft_ni->allocated_size >>
					vol->mft_record_size_bits;
			read_unlock_irqrestore(&mft_ni->size_lock, flags);
			read_lock_irqsave(&mftbmp_ni->size_lock, flags);
			bitmap_records = mftbmp_ni->initialized_size << 3;
			read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
			if (reserve_end > bitmap_records)
				reserve_end = bitmap_records;
			if (reserve_end > bit + 1 + MFT_RECORD_RESERVE)
				reserve_end = bit + 1 + MFT_RECORD_RESERVE;
			reserve_start = bit + 1;
			if (reserve_end > reserve_start) {
				ll = reserve_end << vol->mft_record_size_bits;
			} else {
				reserve_start = -1;
				reserve_end = -1;
				ll = (bit + 1) << vol->mft_record_size_bits;
			}
		}
	} else if (ll > mft_ni->allocated_size) {
		err = -ENOSPC;
		goto undo_mftbmp_alloc_nolock;
	}
	if (log_handle) {
		s64 allocated_size, bitmap_records;

		read_lock_irqsave(&mft_ni->size_lock, flags);
		allocated_size = mft_ni->allocated_size;
		read_unlock_irqrestore(&mft_ni->size_lock, flags);
		read_lock_irqsave(&mftbmp_ni->size_lock, flags);
		bitmap_records = mftbmp_ni->initialized_size << 3;
		read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
		ll = ntfs_mft_initialized_batch_end(old_data_initialized, ll,
				allocated_size, bitmap_records,
				vol->mft_record_size_bits, growth_batch_records);
		err = ntfs_mft_data_extend_initialized_transacted_nolock(
				growth_handle ? growth_handle : log_handle,
				vol, ll);
		if (err) {
			ntfs_error(vol->sb,
				   "Failed to extend mft data initialized size to 0x%llx (error %d).",
				   ll, err);
			goto undo_mftbmp_alloc_nolock;
		}
		record_formatted = true;
		goto mft_data_initialized;
	}
	/*
	 * Extend mft data initialized size (and data size of course) to reach
	 * the allocated mft record, formatting the mft records allong the way.
	 * Note: We only modify the struct ntfs_inode structure as that is all that is
	 * needed by ntfs_mft_record_format().  We will update the attribute
	 * record itself in one fell swoop later on.
	 */
	write_lock_irqsave(&mft_ni->size_lock, flags);
	old_data_initialized = mft_ni->initialized_size;
	old_data_size = vol->mft_ino->i_size;
	while (ll > mft_ni->initialized_size) {
		s64 new_initialized_size, mft_no;

		new_initialized_size = mft_ni->initialized_size +
				vol->mft_record_size;
		mft_no = mft_ni->initialized_size >> vol->mft_record_size_bits;
		if (new_initialized_size > i_size_read(vol->mft_ino))
			i_size_write(vol->mft_ino, new_initialized_size);
		write_unlock_irqrestore(&mft_ni->size_lock, flags);
		ntfs_debug("Initializing mft record 0x%llx.",
				(long long)mft_no);
		err = ntfs_mft_record_format(vol, mft_no);
		if (unlikely(err)) {
			ntfs_error(vol->sb, "Failed to format mft record.");
			goto undo_data_init;
		}
		write_lock_irqsave(&mft_ni->size_lock, flags);
		mft_ni->initialized_size = new_initialized_size;
	}
	write_unlock_irqrestore(&mft_ni->size_lock, flags);
	record_formatted = true;
	/* Update the mft data attribute record to reflect the new sizes. */
	m = map_mft_record(mft_ni);
	if (IS_ERR(m)) {
		ntfs_error(vol->sb, "Failed to map mft record.");
		err = PTR_ERR(m);
		goto undo_data_init;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, m);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.");
		err = -ENOMEM;
		unmap_mft_record(mft_ni);
		goto undo_data_init;
	}
	err = ntfs_attr_lookup(mft_ni->type, mft_ni->name, mft_ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Failed to find first attribute extent of mft data attribute.");
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(mft_ni);
		goto undo_data_init;
	}
	a = ctx->attr;
	read_lock_irqsave(&mft_ni->size_lock, flags);
	a->data.non_resident.initialized_size =
			cpu_to_le64(mft_ni->initialized_size);
	a->data.non_resident.data_size =
			cpu_to_le64(i_size_read(vol->mft_ino));
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	/* Ensure the changes make it to disk. */
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
mft_data_initialized:
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ntfs_debug("Status of mft data after mft record initialization: allocated_size 0x%llx, data_size 0x%llx, initialized_size 0x%llx.",
			mft_ni->allocated_size,	i_size_read(vol->mft_ino),
			mft_ni->initialized_size);
	WARN_ON(i_size_read(vol->mft_ino) > mft_ni->allocated_size);
	WARN_ON(mft_ni->initialized_size > i_size_read(vol->mft_ino));
	nr_new_mft_records = (i_size_read(vol->mft_ino) - old_data_size) >>
			     vol->mft_record_size_bits;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
mft_rec_already_initialized:
	/* Account for newly visible MFT records before dropping the lock. */
	if (nr_new_mft_records > 0) {
		if (log_handle) {
			err = ntfs_mft_count_register_home_undo(
					growth_handle ? growth_handle : log_handle, vol,
					nr_new_mft_records, &count_undo);
			if (err)
				goto undo_mftbmp_alloc_nolock;
		}
		ntfs_inc_free_mft_records(vol, nr_new_mft_records);
		if (count_undo)
			count_undo->counted = true;
	}
	if (growth_handle) {
		/*
		 * Keep the MFT mutex until growth is durable. Bitmap callbacks
		 * acquire mftbmp_lock themselves, so do not hold it at finish.
		 */
		up_write(&vol->mftbmp_lock);
		err = ntfs_log_commit(growth_handle);
		growth_handle = NULL;
		count_undo = NULL;
		down_write(&vol->mftbmp_lock);
		if (err)
			goto undo_mftbmp_alloc_nolock;
	}
	if (reserve_start >= 0 && reserve_end > reserve_start) {
		vol->mft_record_reserve_pos = reserve_start;
		vol->mft_record_reserve_end = reserve_end;
		ntfs_debug("Reserved MFT records [0x%llx, 0x%llx) for metadata.",
			   reserve_start, reserve_end);
	}
	/*
	 * We can finally drop the mft bitmap lock as the mft data attribute
	 * has been fully updated.  The only disparity left is that the
	 * allocated mft record still needs to be marked as in use to match the
	 * set bit in the mft bitmap but this is actually not a problem since
	 * this mft record is not referenced from anywhere yet and the fact
	 * that it is allocated in the mft bitmap means that no-one will try to
	 * allocate it either.
	 */
	if (!base_ni || base_ni->mft_no != FILE_MFT)
		up_write(&vol->mftbmp_lock);
	/*
	 * We now have allocated and initialized the mft record.  Calculate the
	 * index of and the offset within the page cache page the record is in.
	 */
	index = NTFS_MFT_NR_TO_PIDX(vol, bit);
	ofs = NTFS_MFT_NR_TO_POFS(vol, bit);
	/* Read, map, and pin the folio containing the mft record. */
	folio = ntfs_read_metadata_folio(vol->mft_ino->i_mapping, index);
	if (IS_ERR(folio)) {
		ntfs_error(vol->sb, "Failed to map page containing allocated mft record 0x%llx.",
				bit);
		err = PTR_ERR(folio);
		goto undo_mftbmp_alloc;
	}
	folio_lock(folio);
	if (folio_test_writeback(folio))
		folio_wait_writeback(folio);
	folio_clear_uptodate(folio);
	m = (struct mft_record *)((u8 *)kmap_local_folio(folio, 0) + ofs);
	if (log_handle) {
		old_disk_mrec = kmemdup(m, vol->mft_record_size, GFP_NOFS);
		if (!old_disk_mrec) {
			err = -ENOMEM;
			folio_mark_uptodate(folio);
			folio_unlock(folio);
			kunmap_local(m);
			folio_put(folio);
			goto undo_mftbmp_alloc;
		}
	}

	/* If we just formatted the mft record no need to do it again. */
	if (!record_formatted) {
		/* Sanity check that the mft record is really not in use. */
		if (!forced_reserved_record && ntfs_is_file_record(m->magic) &&
		    (m->flags & MFT_RECORD_IN_USE)) {
			bool mft_folio_dirty = folio_test_dirty(folio);

			ntfs_warning(vol->sb,
				"Mft record 0x%llx was marked free in mft bitmap but is marked used itself (flags 0x%x, sequence %u, LSN 0x%llx, base 0x%llx, MFT folio dirty %u). Unmount and run chkdsk.",
				bit, le16_to_cpu(m->flags),
				le16_to_cpu(m->sequence_number),
				(unsigned long long)le64_to_cpu(m->lsn),
				(unsigned long long)le64_to_cpu(m->base_mft_record),
				mft_folio_dirty);
			folio_mark_uptodate(folio);
			folio_unlock(folio);
			kunmap_local(m);
			folio_put(folio);
			NVolSetErrors(vol);
			corrupt_mft_record = true;
			err = -EIO;
			goto undo_mftbmp_alloc;
		}
		/*
		 * We need to (re-)format the mft record, preserving the
		 * sequence number if it is not zero as well as the update
		 * sequence number if it is not zero or -1 (0xffff).  This
		 * means we do not need to care whether or not something went
		 * wrong with the previous mft record.
		 */
		seq_no = m->sequence_number;
		/*
		 * The mft record still holds unvalidated, MST-protected on-disk
		 * bytes, so m->usa_ofs is untrusted here.  Only preserve the old
		 * update sequence number if that offset is in bounds; otherwise
		 * leave usn zero so it is not restored below.
		 */
		if (!(le16_to_cpu(m->usa_ofs) & 1) &&
		    le16_to_cpu(m->usa_ofs) + sizeof(usn) <= vol->mft_record_size)
			usn = *(__le16 *)((u8 *)m + le16_to_cpu(m->usa_ofs));
		else
			usn = 0;
		err = ntfs_mft_record_layout(vol, bit, m);
		if (unlikely(err)) {
			ntfs_error(vol->sb, "Failed to layout allocated mft record 0x%llx.",
					bit);
			if (old_disk_mrec)
				memcpy(m, old_disk_mrec, vol->mft_record_size);
			folio_mark_uptodate(folio);
			folio_unlock(folio);
			kunmap_local(m);
			folio_put(folio);
			goto undo_mftbmp_alloc;
		}
		if (seq_no)
			m->sequence_number = seq_no;
		if (usn && le16_to_cpu(usn) != 0xffff)
			*(__le16 *)((u8 *)m + le16_to_cpu(m->usa_ofs)) = usn;
		pre_write_mst_fixup((struct ntfs_record *)m, vol->mft_record_size);
	}
	/* Set the mft record itself in use. */
	m->flags |= MFT_RECORD_IN_USE;
	if (S_ISDIR(mode))
		m->flags |= MFT_RECORD_IS_DIRECTORY;
	folio_mark_uptodate(folio);
	if (base_ni) {
		/*
		 * Setup the base mft record in the extent mft record.  This
		 * completes initialization of the allocated extent mft record
		 * and we can simply use it with map_extent_mft_record().
		 */
		m->base_mft_record = MK_LE_MREF(base_ni->mft_no,
				base_ni->seq_no);
	}
	if (log_handle) {
		log_mrec = kmemdup(m, vol->mft_record_size, GFP_NOFS);
		if (!log_mrec) {
			err = -ENOMEM;
			goto restore_locked_record;
		}
		if (post_read_mst_fixup((struct ntfs_record *)log_mrec,
				vol->mft_record_size)) {
			err = -EIO;
			goto restore_locked_record;
		}
		err = ntfs_log_mft_record_initialize(log_handle, bit, log_mrec,
				&operation_lsn);
		if (err)
			goto restore_locked_record;
		m->lsn = cpu_to_le64(operation_lsn);
		kfree(log_mrec);
		log_mrec = NULL;
	}
	if (base_ni) {
		struct mft_record *m_tmp;
		struct ntfs_mft_locked_record locked = {
			.mrec = m,
			.ofs = ofs,
			.folio = folio,
		};

		/*
		 * Allocate an extent inode structure for the new mft record,
		 * attach it to the base inode @base_ni and map and pin the
		 * allocated mft record.  The folio is already locked here, so
		 * pass that mapping through instead of acquiring the lock again.
		 */
		m_tmp = map_extent_mft_record_from_locked(base_ni,
					      MK_MREF(bit, le16_to_cpu(m->sequence_number)),
					      ni, &locked);
		if (IS_ERR(m_tmp)) {
			ntfs_error(vol->sb, "Failed to map allocated extent mft record 0x%llx.",
					bit);
			err = PTR_ERR(m_tmp);
			if (forced_reserved_record) {
				m->base_mft_record = 0;
				m->flags |= MFT_RECORD_IN_USE;
			} else {
				/* Set the mft record itself not in use. */
				m->flags &= cpu_to_le16(~le16_to_cpu(MFT_RECORD_IN_USE));
			}
			/* Make sure the mft record is written out to disk. */
			ntfs_mft_mark_dirty(folio);
			folio_unlock(folio);
			kunmap_local(m);
			folio_put(folio);
			goto undo_mftbmp_alloc;
		}
		if (caller_handle) {
			err = ntfs_mft_alloc_register_home_undo(caller_handle, vol,
					*ni, bit, old_disk_mrec, true, &alloc_undo);
			if (err) {
				unmap_mft_record(*ni);
				ntfs_inode_close(*ni);
				*ni = NULL;
				goto restore_locked_record;
			}
		}

		/*
		 * Make sure the allocated mft record is written out to disk.
		 * No need to set the inode dirty because the caller is going
		 * to do that anyway after finishing with the new extent mft
		 * record (e.g. at a minimum a new attribute will be added to
		 * the mft record.
		 */
		ntfs_mft_mark_dirty(folio);
		folio_unlock(folio);
		/*
		 * Need to unmap the page since map_extent_mft_record() mapped
		 * it as well so we have it mapped twice at the moment.
		 */
		kunmap_local(m);
		folio_put(folio);
	} else {
		/*
		 * Manually map, pin, and lock the mft record as we already
		 * have its page mapped and it is very easy to do.
		 */
		(*ni)->seq_no = le16_to_cpu(m->sequence_number);
		/*
		 * Make sure the allocated mft record is written out to disk.
		 * NOTE: We do not set the ntfs inode dirty because this would
		 * fail in ntfs_write_inode() because the inode does not have a
		 * standard information attribute yet.  Also, there is no need
		 * to set the inode dirty because the caller is going to do
		 * that anyway after finishing with the new mft record (e.g. at
		 * a minimum some new attributes will be added to the mft
		 * record.
		 */

		(*ni)->mrec = kmemdup(m, vol->mft_record_size, GFP_NOFS);
		if (!(*ni)->mrec) {
			err = -ENOMEM;
			if (log_handle)
				goto restore_locked_record;
			folio_unlock(folio);
			kunmap_local(m);
			folio_put(folio);
			goto undo_mftbmp_alloc;
		}

		post_read_mst_fixup((struct ntfs_record *)(*ni)->mrec, vol->mft_record_size);
		if (caller_handle) {
			err = ntfs_mft_alloc_register_home_undo(caller_handle, vol,
					*ni, bit, old_disk_mrec, false, &alloc_undo);
			if (err)
				goto restore_locked_record;
			kfree(old_disk_mrec);
			old_disk_mrec = NULL;
		} else if (log_handle) {
			err = ntfs_log_commit(log_handle);
			log_handle = NULL;
			if (err) {
				log_commit_failed = true;
				goto restore_locked_record;
			}
			kfree(old_disk_mrec);
			old_disk_mrec = NULL;
		}
		ntfs_mft_mark_dirty(folio);
		folio_unlock(folio);
		(*ni)->folio = folio;
		(*ni)->folio_ofs = ofs;
		atomic_inc(&(*ni)->count);
		/* Update the default mft allocation position. */
		vol->mft_data_pos = bit + 1;
	}
	if (!base_ni || base_ni->mft_no != FILE_MFT)
		mutex_unlock(&mft_ni->mrec_lock);
	memalloc_nofs_restore(memalloc_flags);

	/*
	 * Return the opened, allocated inode of the allocated mft record as
	 * well as the mapped, pinned, and locked mft record.
	 */
	ntfs_debug("Returning opened, allocated %sinode 0x%llx.",
			base_ni ? "extent " : "", bit);
	(*ni)->mft_no = bit;
	if (ni_mrec)
		*ni_mrec = (*ni)->mrec;
	if (!forced_reserved_record) {
		ntfs_dec_free_mft_records(vol, 1);
		if (alloc_undo)
			alloc_undo->counted = true;
	}
	return 0;

restore_locked_record:
	kfree(log_mrec);
	log_mrec = NULL;
	if (old_disk_mrec)
		memcpy(m, old_disk_mrec, vol->mft_record_size);
	if (!base_ni && *ni) {
		kfree((*ni)->mrec);
		(*ni)->mrec = NULL;
	}
	folio_mark_uptodate(folio);
	folio_unlock(folio);
	kunmap_local(m);
	folio_put(folio);
	goto undo_mftbmp_alloc;
undo_data_init:
	write_lock_irqsave(&mft_ni->size_lock, flags);
	mft_ni->initialized_size = old_data_initialized;
	i_size_write(vol->mft_ino, old_data_size);
	write_unlock_irqrestore(&mft_ni->size_lock, flags);
	goto undo_mftbmp_alloc_nolock;
undo_mftbmp_alloc:
	if (!base_ni || base_ni->mft_no != FILE_MFT)
		down_write(&vol->mftbmp_lock);
undo_mftbmp_alloc_nolock:
	if (!forced_reserved_record &&
	    ((log_handle || log_commit_failed) ?
	     __ntfs_bitmap_set_bits_in_run(vol->mftbmp_ino, bit, 1, 0, true) :
	     ntfs_bitmap_clear_bit(vol->mftbmp_ino, bit))) {
		ntfs_error(vol->sb, "Failed to clear bit in mft bitmap.%s", es);
		NVolSetErrors(vol);
	}
	if ((from_reserve || reserve_created) &&
	    vol->mft_record_reserve_pos == bit + 1)
		vol->mft_record_reserve_pos = bit;
	if (!base_ni || base_ni->mft_no != FILE_MFT)
		up_write(&vol->mftbmp_lock);
err_out:
	if (growth_handle) {
		int abort_err = ntfs_log_abort(growth_handle);

		growth_handle = NULL;
		if (abort_err) {
			ntfs_error(vol->sb,
				"Failed to abort MFT growth transaction (error %i).",
				abort_err);
			NVolSetErrors(vol);
			err = abort_err;
		}
	}
	if (own_log_handle && log_handle) {
		int abort_err = ntfs_log_abort(log_handle);

		log_handle = NULL;
		if (abort_err) {
			ntfs_error(vol->sb,
				"Failed to abort MFT allocation transaction (error %i).",
				abort_err);
			NVolSetErrors(vol);
		}
	}
	kfree(log_mrec);
	kfree(old_disk_mrec);
	if (corrupt_mft_record) {
		NVolSetShutdown(vol);
		vol->sb->s_flags |= SB_RDONLY;
		ntfs_error(vol->sb,
			"Stopping writes: MFT record 0x%llx is in use but its bitmap bit is free.",
			(unsigned long long)bit);
	}
	if (!base_ni || base_ni->mft_no != FILE_MFT)
		mutex_unlock(&mft_ni->mrec_lock);
	memalloc_nofs_restore(memalloc_flags);
	return err;
max_err_out:
	ntfs_warning(vol->sb,
		"Cannot allocate mft record because the maximum number of inodes (2^32) has already been reached.");
	if (!base_ni || base_ni->mft_no != FILE_MFT) {
		up_write(&vol->mftbmp_lock);
		mutex_unlock(&mft_ni->mrec_lock);
	}
	memalloc_nofs_restore(memalloc_flags);
	return -ENOSPC;
}

static int ntfs_mft_record_alloc_credits_batch(struct ntfs_volume *vol,
		u32 batch_records)
{
	struct ntfs_inode *mft_ni;
	unsigned long flags;
	s64 allocated_size;
	s64 initialized_size;
	u64 credits;
	u64 growth_bytes;
	u64 mft_clusters;
	u64 record_count = 1 + MFT_RECORD_RESERVE;
	u64 record_range_credits;
	u64 required_bytes;
	u64 required_clusters = 0;
	int allocation_credits;
	int bitmap_credits;
	int data_allocation_credits;
	int mapping_credits;
	int record_credits;
	int size_credits;
	int value_credits;

	if (!vol || !vol->mft_ino || !batch_records)
		return -EINVAL;
	mft_ni = NTFS_I(vol->mft_ino);
	read_lock_irqsave(&mft_ni->size_lock, flags);
	allocated_size = mft_ni->allocated_size;
	initialized_size = mft_ni->initialized_size;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	if (allocated_size <= 0 || initialized_size < 0 ||
	    initialized_size > allocated_size)
		return -EIO;
	required_bytes = (u64)FIRST_NORMAL_MFT_RECORD + 1;
	if (check_shl_overflow(required_bytes, vol->mft_record_size_bits,
			       &required_bytes))
		return -EOVERFLOW;
	if (required_bytes > allocated_size) {
		growth_bytes = required_bytes - allocated_size;
		required_clusters = DIV_ROUND_UP_ULL(growth_bytes,
						     vol->cluster_size);
	}
	if (required_bytes > initialized_size) {
		growth_bytes = required_bytes - initialized_size;
		record_count = DIV_ROUND_UP_ULL(growth_bytes,
						vol->mft_record_size) +
				MFT_RECORD_RESERVE;
	}
	record_count = max_t(u64, record_count, batch_records);
	record_credits = ntfs_log_mft_record_credits(vol);
	if (record_credits < 0)
		return record_credits;
	if (!record_credits)
		return -EIO;
	if (check_mul_overflow(record_count, (u64)record_credits - 1,
			       &record_range_credits))
		return -EOVERFLOW;
	if (check_add_overflow(record_range_credits, 1,
			       &record_range_credits))
		return -EOVERFLOW;
	bitmap_credits = ntfs_log_bitmap_update_credits(0, 1);
	if (bitmap_credits < 0)
		return bitmap_credits;
	size_credits = ntfs_log_mft_attribute_sizes_credits(vol, false);
	if (size_credits < 0)
		return size_credits;
	value_credits = ntfs_log_nonresident_value_update_credits(vol,
			max_t(u32, MFT_BITMAP_INIT_MIN_BYTES,
			      batch_records >> 3), false);
	if (value_credits < 0)
		return value_credits;
	allocation_credits = ntfs_cluster_alloc_log_credits(1);
	if (allocation_credits < 0)
		return allocation_credits;
	mapping_credits = ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size, 0, 0);
	if (mapping_credits < 0)
		return mapping_credits;
	growth_bytes = (u64)vol->mft_record_size * batch_records;
	mft_clusters = DIV_ROUND_UP_ULL(growth_bytes, vol->cluster_size);
	mft_clusters = max(mft_clusters, required_clusters);
	data_allocation_credits = ntfs_cluster_alloc_log_credits(mft_clusters);
	if (data_allocation_credits < 0)
		return data_allocation_credits;
	credits = record_range_credits;
	if (check_add_overflow(credits, (u64)bitmap_credits, &credits) ||
	    check_add_overflow(credits, (u64)size_credits * 2, &credits) ||
	    check_add_overflow(credits, (u64)value_credits, &credits) ||
	    check_add_overflow(credits, (u64)allocation_credits, &credits) ||
	    check_add_overflow(credits, (u64)data_allocation_credits,
			&credits) ||
	    check_add_overflow(credits, (u64)mapping_credits * 2, &credits) ||
	    credits > INT_MAX)
		return -EOVERFLOW;
	return credits;
}

int ntfs_mft_record_alloc_credits(struct ntfs_volume *vol)
{
	return ntfs_mft_record_alloc_credits_batch(vol, MFT_RECORD_INIT_BATCH);
}

int ntfs_mft_record_free_credits(struct ntfs_volume *vol)
{
	int bitmap_credits;
	int record_credits;
	int credits;

	record_credits = ntfs_log_mft_record_credits(vol);
	if (record_credits < 0)
		return record_credits;
	bitmap_credits = ntfs_log_bitmap_update_credits(0, 1);
	if (bitmap_credits < 0)
		return bitmap_credits;
	if (check_add_overflow(record_credits, bitmap_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

static int ntfs_mft_retire_records_validate(
		const struct ntfs_mft_retire_record *records, u64 nr_records)
{
	u64 index;

	if (!records || !nr_records)
		return -EINVAL;
	for (index = 0; index < nr_records; index++) {
		if (!records[index].ni || records[index].mft_no >= S64_MAX ||
		    records[index].ni->mft_no != records[index].mft_no ||
		    (index && records[index].mft_no <=
			    records[index - 1].mft_no))
			return -EIO;
	}
	return 0;
}

static const struct ntfs_mft_retire_record *ntfs_mft_retire_record_find(
		const struct ntfs_mft_retire_record *records, u64 nr_records,
		u64 mft_no)
{
	u64 high = nr_records;
	u64 low = 0;

	while (low < high) {
		u64 middle = low + (high - low) / 2;

		if (records[middle].mft_no < mft_no)
			low = middle + 1;
		else
			high = middle;
	}
	if (low < nr_records && records[low].mft_no == mft_no)
		return &records[low];
	return NULL;
}

int ntfs_mft_records_retire_credits(struct ntfs_volume *vol,
		const struct ntfs_mft_retire_record *records, u64 nr_records)
{
	u64 bitmap_credits = 1;
	u64 bitmap_end;
	u64 credits;
	u64 index;
	int err;
	int record_credits;
	int range_credits;

	if (!vol)
		return -EINVAL;
	err = ntfs_mft_retire_records_validate(records, nr_records);
	if (err)
		return err;
	record_credits = ntfs_log_mft_record_credits(vol);
	if (record_credits < 0)
		return record_credits;
	if (!record_credits)
		return -EIO;
	/* Every image operation shares one MFT data open record. */
	if (check_mul_overflow(nr_records, (u64)record_credits - 1,
			&credits) ||
	    check_add_overflow(credits, 1ULL, &credits))
		return -E2BIG;
	for (index = 0; index < nr_records; index = bitmap_end) {
		for (bitmap_end = index + 1;
		     bitmap_end < nr_records &&
		     records[bitmap_end].mft_no ==
			     records[bitmap_end - 1].mft_no + 1;
		     bitmap_end++)
			;
		range_credits = ntfs_log_bitmap_update_credits(
				records[index].mft_no, bitmap_end - index);
		if (range_credits < 0)
			return range_credits;
		if (!range_credits ||
		    check_add_overflow(bitmap_credits,
				(u64)range_credits - 1, &bitmap_credits))
			return -E2BIG;
	}
	/* Every range operation shares one MFT bitmap open record. */
	if (check_add_overflow(credits, bitmap_credits, &credits) ||
	    credits > INT_MAX)
		return -E2BIG;
	return credits;
}

int ntfs_mft_record_alloc(struct ntfs_volume *vol, const int mode,
		struct ntfs_inode **ni, struct ntfs_inode *base_ni,
		struct mft_record **ni_mrec, const s64 mft_data_vcn)
{
	return __ntfs_mft_record_alloc(NULL, vol, mode, ni, base_ni, ni_mrec,
			mft_data_vcn);
}

int ntfs_mft_base_record_alloc_transacted(struct ntfs_log_handle *handle,
		struct ntfs_volume *vol, int mode, struct ntfs_inode **ni,
		struct mft_record **ni_mrec)
{
	if (!handle || !ni || !*ni || !mode)
		return -EINVAL;
	return __ntfs_mft_record_alloc(handle, vol, mode, ni, NULL, ni_mrec,
			-1);
}

/*
 * Allocate an already initialized extent record in a caller-owned journal
 * transaction.  The caller must unmap the returned record before commit or
 * abort.  Abort (including a failed commit) restores and detaches the extent.
 * Commit leaves it attached to the base inode.  Physical growth of $MFT or
 * its bitmap stays on this handle. Mapping-pairs tail growth may allocate a
 * further attribute-list extent before the new record is published.
 */
int ntfs_mft_record_alloc_transacted(struct ntfs_log_handle *handle,
		struct ntfs_volume *vol, struct ntfs_inode **ni,
		struct ntfs_inode *base_ni, struct mft_record **ni_mrec)
{
	int err;

	if (!handle || !vol || !base_ni)
		return -EINVAL;
	err = __ntfs_mft_record_alloc(handle, vol, 0, ni, base_ni, ni_mrec,
			-1);
	if (err && err != -ENOSPC)
		ntfs_error(vol->sb,
			   "Transacted extent MFT record allocation failed for inode %llu (error %d).",
			   (unsigned long long)base_ni->mft_no, err);
	return err;
}

static int ntfs_mft_record_free_image_validate(u64 mft_no,
		struct ntfs_inode *base_ni, const struct mft_record *mrec,
		bool require_empty)
{
	u32 attrs_off;
	u32 used;
	bool is_extent;

	if (!base_ni || !mrec)
		return -EINVAL;
	is_extent = !!mrec->base_mft_record;
	if ((is_extent &&
	     MREF_LE(mrec->base_mft_record) != base_ni->mft_no) ||
	    (!is_extent && mft_no != base_ni->mft_no))
		return -EINVAL;
	used = le32_to_cpu(mrec->bytes_in_use);
	attrs_off = le16_to_cpu(mrec->attrs_offset);
	if (!(mrec->flags & MFT_RECORD_IN_USE) || attrs_off > used ||
	    (require_empty && used - attrs_off != 8) ||
	    (!is_extent && mrec->link_count))
		return -EINVAL;
	return 0;
}

static int ntfs_mft_record_retire_image_preflight(struct ntfs_inode *ni,
		struct ntfs_inode *base_ni)
{
	struct mft_record *mrec;
	int err;

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	err = ntfs_mft_record_free_image_validate(ni->mft_no, base_ni, mrec,
			false);
	unmap_mft_record(ni);
	return err;
}

/* Retire an MFT record while retaining its live inode until transaction end. */
static int __ntfs_mft_record_free_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		bool require_empty, bool allow_base, bool update_bitmap)
{
	struct ntfs_mft_free_home_undo *undo;
	struct ntfs_inode *base_ni;
	struct mft_record *mrec;
	unsigned int memalloc_flags;
	u64 operation_lsn;
	u16 seq_no;
	bool close_on_commit;
	bool is_extent;
	int err;

	if (!handle || !ni)
		return -EINVAL;
	if (ni->nr_extents == -1) {
		base_ni = ni->ext.base_ntfs_ino;
		is_extent = true;
		if (!base_ni)
			return -EINVAL;
	} else {
		base_ni = ni;
		is_extent = false;
		if (!allow_base || NInoAttr(ni))
			return -EINVAL;
	}
	close_on_commit = is_extent && (require_empty || allow_base);
	if (!require_empty && !NInoBeingDeleted(base_ni))
		return -EOPNOTSUPP;
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	err = ntfs_mft_record_free_image_validate(ni->mft_no, base_ni, mrec,
			require_empty);
	if (err)
		goto out_unmap;
	err = ntfs_mft_free_register_home_undo(handle, ni, mrec,
			close_on_commit, &undo);
	if (err)
		goto out_unmap;
	err = ntfs_log_mft_record_deallocate(handle, ni->mft_no, mrec,
			&operation_lsn);
	if (err)
		goto out_unmap;
	mrec->flags &= ~MFT_RECORD_IN_USE;
	seq_no = le16_to_cpu(mrec->sequence_number);
	if (seq_no == 0xffff)
		seq_no = 1;
	else if (seq_no)
		seq_no++;
	mrec->sequence_number = cpu_to_le16(seq_no);
	mrec->lsn = cpu_to_le64(operation_lsn);
	err = ntfs_prepare_mft_record_write(ni);
	if (err)
		goto out_unmap;
	NInoSetDirty(ni);
	err = write_mft_record(ni, mrec, 0);
	if (err)
		goto out_unmap;
	unmap_mft_record(ni);

	if (!update_bitmap)
		return 0;
	memalloc_flags = memalloc_nofs_save();
	if (base_ni->mft_no != FILE_MFT)
		down_write(&ni->vol->mftbmp_lock);
	err = ntfs_bitmap_validate_run(ni->vol->mftbmp_ino, ni->mft_no, 1, 1);
	if (!err)
		err = ntfs_mft_bitmap_register_free_home_undo(handle,
				ni->vol, ni->mft_no, 1,
				base_ni->mft_no != FILE_MFT);
	if (!err)
		err = ntfs_log_bitmap_update(handle,
				ni->vol->mftbmp_ino, ni->mft_no, 1, 0);
	if (base_ni->mft_no != FILE_MFT)
		up_write(&ni->vol->mftbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	if (err)
		return err;
	return 0;
out_unmap:
	unmap_mft_record(ni);
	return err;
}

int ntfs_mft_record_free_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	return __ntfs_mft_record_free_transacted(handle, ni, true, false,
			true);
}

/* Retire a deleted base or attached extent record regardless of contents. */
int ntfs_mft_record_retire_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	return __ntfs_mft_record_free_transacted(handle, ni, false, true,
			true);
}

static int ntfs_mft_record_retire_image_transacted(
		struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	return __ntfs_mft_record_free_transacted(handle, ni, false, true,
			false);
}

static int ntfs_mft_records_bitmap_validate(
		struct ntfs_inode *base_ni,
		const struct ntfs_mft_retire_record *records, u64 nr_records)
{
	u64 bitmap_end;
	u64 index;
	int err;

	for (index = 0; index < nr_records; index = bitmap_end) {
		for (bitmap_end = index + 1;
		     bitmap_end < nr_records &&
		     records[bitmap_end].mft_no ==
			     records[bitmap_end - 1].mft_no + 1;
		     bitmap_end++)
			;
		err = ntfs_bitmap_validate_run(base_ni->vol->mftbmp_ino,
				records[index].mft_no, bitmap_end - index, 1);
		if (err) {
			ntfs_error(base_ni->vol->sb,
				   "MFT retirement bitmap preflight failed for records 0x%llx-0x%llx (base 0x%llx, error %d).",
				   (unsigned long long)records[index].mft_no,
				   (unsigned long long)records[bitmap_end - 1].mft_no,
				   (unsigned long long)base_ni->mft_no, err);
			return err;
		}
	}
	return 0;
}

static int ntfs_mft_records_bitmap_preflight(
		struct ntfs_inode *base_ni,
		const struct ntfs_mft_retire_record *records, u64 nr_records)
{
	unsigned int memalloc_flags;
	int err;

	memalloc_flags = memalloc_nofs_save();
	if (base_ni->mft_no != FILE_MFT)
		down_read(&base_ni->vol->mftbmp_lock);
	err = ntfs_mft_records_bitmap_validate(base_ni, records, nr_records);
	if (base_ni->mft_no != FILE_MFT)
		up_read(&base_ni->vol->mftbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	return err;
}

static int ntfs_mft_records_bitmap_free_transacted(
		struct ntfs_log_handle *handle,
		struct ntfs_inode *base_ni,
		const struct ntfs_mft_retire_record *records, u64 nr_records)
{
	unsigned int memalloc_flags;
	u64 bitmap_end;
	u64 index;
	int err = 0;

	if (!handle || !base_ni || !NInoBeingDeleted(base_ni))
		return -EINVAL;
	err = ntfs_mft_retire_records_validate(records, nr_records);
	if (err)
		return err;
	memalloc_flags = memalloc_nofs_save();
	if (base_ni->mft_no != FILE_MFT)
		down_write(&base_ni->vol->mftbmp_lock);
	err = ntfs_mft_records_bitmap_validate(base_ni, records, nr_records);
	if (err)
		goto out_unlock;
	for (index = 0; index < nr_records; index = bitmap_end) {
		for (bitmap_end = index + 1;
		     bitmap_end < nr_records &&
		     records[bitmap_end].mft_no ==
			     records[bitmap_end - 1].mft_no + 1;
		     bitmap_end++)
			;
		err = ntfs_mft_bitmap_register_free_home_undo(handle,
				base_ni->vol, records[index].mft_no,
				bitmap_end - index,
				base_ni->mft_no != FILE_MFT);
		if (err)
			break;
		err = ntfs_log_bitmap_update(handle,
				base_ni->vol->mftbmp_ino,
				records[index].mft_no,
				bitmap_end - index, 0);
		if (err)
			break;
	}
out_unlock:
	if (base_ni->mft_no != FILE_MFT)
		up_write(&base_ni->vol->mftbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	return err;
}

/* Validate a retirement snapshot while the caller holds base mrec_lock. */
int ntfs_mft_records_retire_preflight(struct ntfs_inode *base_ni,
		const struct ntfs_mft_retire_record *records, u64 nr_records)
{
	const struct ntfs_mft_retire_record *record;
	struct ntfs_inode *ext_ni;
	u64 index;
	int i;
	int err;

	if (!base_ni || !records || base_ni->nr_extents < 0 ||
	    nr_records != (u64)base_ni->nr_extents + 1 ||
	    !NInoBeingDeleted(base_ni))
		return -EINVAL;
	err = ntfs_mft_retire_records_validate(records, nr_records);
	if (err)
		return err;
	record = ntfs_mft_retire_record_find(records, nr_records,
			base_ni->mft_no);
	if (!record || record->ni != base_ni)
		return -EIO;
	for (i = 0; i < base_ni->nr_extents; i++) {
		ext_ni = base_ni->ext.extent_ntfs_inos[i];
		if (!ext_ni)
			return -EIO;
		record = ntfs_mft_retire_record_find(records, nr_records,
				ext_ni->mft_no);
		if (!record || record->ni != ext_ni || ext_ni->nr_extents != -1 ||
		    ext_ni->ext.base_ntfs_ino != base_ni)
			return -EIO;
	}
	for (index = 0; index < nr_records; index++) {
		err = ntfs_mft_record_retire_image_preflight(records[index].ni,
				base_ni);
		if (err) {
			ntfs_error(base_ni->vol->sb,
				   "MFT retirement image preflight failed for record 0x%llx (base 0x%llx, error %d).",
				   (unsigned long long)records[index].mft_no,
				   (unsigned long long)base_ni->mft_no, err);
			return err;
		}
	}
	return ntfs_mft_records_bitmap_preflight(base_ni, records,
			nr_records);
}

int ntfs_mft_records_retire_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *base_ni,
		const struct ntfs_mft_retire_record *records, u64 nr_records)
{
	u64 index;
	int err;

	if (!handle)
		return -EINVAL;
	err = ntfs_mft_records_retire_preflight(base_ni, records, nr_records);
	if (err)
		return err;
	for (index = 0; index < nr_records; index++) {
		if (records[index].ni == base_ni)
			continue;
		err = ntfs_mft_record_retire_image_transacted(handle,
				records[index].ni);
		if (err)
			return err;
	}
	err = ntfs_mft_record_retire_image_transacted(handle, base_ni);
	if (err)
		return err;
	return ntfs_mft_records_bitmap_free_transacted(handle, base_ni,
			records, nr_records);
}

/*
 * ntfs_mft_record_free - free an mft record on an ntfs volume
 * @vol:	volume on which to free the mft record
 * @ni:		open ntfs inode of the mft record to free
 *
 * Free the mft record of the open inode @ni on the mounted ntfs volume @vol.
 * Note that this function calls ntfs_inode_close() internally and hence you
 * cannot use the pointer @ni any more after this function returns success.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 */
int ntfs_mft_record_free(struct ntfs_volume *vol, struct ntfs_inode *ni)
{
	struct ntfs_log_handle *log_handle = NULL;
	struct mft_record *old_mrec = NULL;
	struct mft_record *ni_mrec;
	unsigned int memalloc_flags;
	struct ntfs_inode *base_ni;
	u64 operation_lsn = 0;
	u64 mft_no;
	bool bitmap_changed = false, keep_reserved;
	int rollback_err = 0;
	int credits;
	int err;
	u16 seq_no;

	if (!vol || !ni)
		return -EINVAL;

	ntfs_debug("Entering for inode 0x%llx.\n", (long long)ni->mft_no);
	mft_no = ni->mft_no;
	if (likely(ni->nr_extents >= 0))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	if (!base_ni)
		return -EINVAL;
	keep_reserved = mft_no >= FILE_reserved12 &&
			mft_no <= FILE_reserved15 &&
			base_ni->mft_no == FILE_MFT;
	memalloc_flags = memalloc_nofs_save();
	if (base_ni->mft_no != FILE_MFT)
		down_read(&vol->mftbmp_lock);
	err = ntfs_bitmap_validate_run(vol->mftbmp_ino, mft_no, 1, 1);
	if (base_ni->mft_no != FILE_MFT)
		up_read(&vol->mftbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	if (err)
		goto out_abort;

	ni_mrec = map_mft_record(ni);
	if (IS_ERR(ni_mrec))
		return -EIO;
	err = ntfs_mft_record_free_image_validate(mft_no, base_ni, ni_mrec,
			false);
	if (err)
		goto out_unmap_abort;
	old_mrec = kmemdup(ni_mrec, vol->mft_record_size, GFP_NOFS);
	if (!old_mrec) {
		err = -ENOMEM;
		goto out_unmap_abort;
	}
	if (!keep_reserved && vol->journal) {
		credits = ntfs_mft_record_free_credits(vol);
		if (credits < 0) {
			err = credits;
			goto out_unmap_abort;
		}
		log_handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(log_handle)) {
			err = PTR_ERR(log_handle);
			log_handle = NULL;
			goto out_unmap_abort;
		}
	}
	if (log_handle) {
		err = ntfs_log_mft_record_deallocate(log_handle, mft_no,
				old_mrec, &operation_lsn);
		if (err)
			goto out_unmap_abort;
	}

	if (keep_reserved) {
		/* Restore the special, unnamed form used by reserved records. */
		ni_mrec->base_mft_record = 0;
		ni_mrec->flags |= MFT_RECORD_IN_USE;
	} else {
		/* Mark the mft record as not in use. */
		ni_mrec->flags &= ~MFT_RECORD_IN_USE;
	}

	/* Increment the sequence number, skipping zero, if it is not zero. */
	seq_no = le16_to_cpu(ni_mrec->sequence_number);
	if (seq_no == 0xffff)
		seq_no = 1;
	else if (seq_no)
		seq_no++;
	ni_mrec->sequence_number = cpu_to_le16(seq_no);
	if (operation_lsn)
		ni_mrec->lsn = cpu_to_le64(operation_lsn);

	err = ntfs_prepare_mft_record_write(ni);
	if (err)
		goto restore_record;

	/*
	 * Set the ntfs inode dirty and write it out.  We do not need to worry
	 * about the base inode here since whatever caused the extent mft
	 * record to be freed is guaranteed to do it already.
	 */
	NInoSetDirty(ni);
	err = write_mft_record(ni, ni_mrec, 1);
	if (err)
		goto restore_record;

	if (keep_reserved) {
		unmap_mft_record(ni);
		kfree(old_mrec);
		return 0;
	}

	/* Clear the bit in the $MFT/$BITMAP corresponding to this record. */
	memalloc_flags = memalloc_nofs_save();
	if (base_ni->mft_no != FILE_MFT)
		down_write(&vol->mftbmp_lock);
	err = ntfs_bitmap_validate_run(vol->mftbmp_ino, mft_no, 1, 1);
	if (!err && log_handle)
		err = ntfs_bitmap_set_bits_in_run_transacted(log_handle,
				vol->mftbmp_ino, mft_no, 1, 0);
	else if (!err)
		err = ntfs_bitmap_clear_bit(vol->mftbmp_ino, mft_no);
	if (base_ni->mft_no != FILE_MFT)
		up_write(&vol->mftbmp_lock);
	memalloc_nofs_restore(memalloc_flags);
	if (err)
		goto restore_record;
	bitmap_changed = true;

	if (log_handle) {
		err = ntfs_log_commit(log_handle);
		log_handle = NULL;
		if (err)
			goto restore_record;
	}
	ntfs_inc_free_mft_records(vol, 1);
	if (base_ni->mft_no == FILE_MFT &&
	    mft_no + 1 == vol->mft_record_reserve_pos &&
	    mft_no < vol->mft_record_reserve_end)
		vol->mft_record_reserve_pos = mft_no;
	unmap_mft_record(ni);
	kfree(old_mrec);
	return 0;

	/* Restore home metadata before emitting compensation records. */
restore_record:
	if (bitmap_changed) {
		memalloc_flags = memalloc_nofs_save();
		if (base_ni->mft_no != FILE_MFT)
			down_write(&vol->mftbmp_lock);
		rollback_err = __ntfs_bitmap_set_bits_in_run(vol->mftbmp_ino,
				mft_no, 1, 1, true);
		if (base_ni->mft_no != FILE_MFT)
			up_write(&vol->mftbmp_lock);
		memalloc_nofs_restore(memalloc_flags);
	}
	memcpy(ni_mrec, old_mrec, vol->mft_record_size);
	NInoSetDirty(ni);
	if (write_mft_record(ni, ni_mrec, 0) && !rollback_err)
		rollback_err = -EIO;
	if (rollback_err) {
		ntfs_error(vol->sb,
			"Failed to rollback MFT record free (error %i).", rollback_err);
		NVolSetErrors(vol);
	}
out_unmap_abort:
	unmap_mft_record(ni);
out_abort:
	if (log_handle) {
		int abort_err = ntfs_log_abort(log_handle);

		if (abort_err) {
			ntfs_error(vol->sb,
				"Failed to abort MFT record free transaction (error %i).",
				abort_err);
			NVolSetErrors(vol);
		}
	}
	kfree(old_mrec);
	return err;
}

static bool ntfs_add_mft_io_unit(struct bio *bio, struct page *page,
				 const struct ntfs_mft_io_unit *unit)
{
	if (!bio->bi_iter.bi_size)
		bio->bi_iter.bi_sector = unit->sector;
	else if (bio_end_sector(bio) != unit->sector)
		return false;

	return bio_add_page(bio, page, unit->len, unit->folio_ofs);
}

static void ntfs_release_mft_write_refs(struct ntfs_inode **locked_nis,
					unsigned int nr_locked_nis,
					struct inode **ref_inos,
					unsigned int nr_ref_inos)
{
	while (nr_locked_nis-- > 0) {
		struct ntfs_inode *tni = locked_nis[nr_locked_nis];

		mutex_unlock(&tni->mrec_lock);
		atomic_dec(&tni->count);
	}

	while (nr_ref_inos-- > 0)
		iput(ref_inos[nr_ref_inos]);
}

static int ntfs_map_mft_io_locked(struct ntfs_inode *ni, u64 folio_byte,
				  struct ntfs_mft_io_unit *unit)
{
	struct ntfs_volume *vol = ni->vol;
	u64 file_ofs = folio_byte + unit->folio_ofs;
	s64 vcn, lcn;

	lockdep_assert_held(&ni->runlist.lock);
	if (!ni->runlist.rl)
		return -EIO;

	vcn = ntfs_bytes_to_cluster(vol, file_ofs);
	/*
	 * $MFT is fully mapped at mount time and extensions merge already
	 * mapped runs under the write lock. Do not remap here: the generic
	 * helper may drop this read lock while upgrading it.
	 */
	lcn = ntfs_rl_vcn_to_lcn(ni->runlist.rl, vcn);
	if (lcn == LCN_RL_NOT_MAPPED)
		return -EAGAIN;
	if (lcn < 0)
		return -EIO;
	if (ntfs_bytes_to_cluster_off(vol, file_ofs) + unit->len >
	    vol->cluster_size)
		return -EIO;

	unit->sector = ntfs_bytes_to_bio_sector(
		NTFS_CLU_TO_B(vol, lcn) +
		ntfs_bytes_to_cluster_off(vol, file_ofs));
	return 0;
}

static int ntfs_map_mft_io_for_folio(struct ntfs_inode *ni, u64 folio_byte,
				     struct ntfs_mft_io_unit *unit)
{
	int err;

	if (!down_read_trylock(&ni->runlist.lock))
		return -EAGAIN;
	err = ntfs_map_mft_io_locked(ni, folio_byte, unit);
	up_read(&ni->runlist.lock);
	return err;
}

static int ntfs_prepare_mft_folio_units(struct ntfs_inode *ni, u64 folio_byte,
					u64 file_limit,
					const unsigned long *record_selected,
					struct ntfs_mft_io_unit *units,
					unsigned int *nr_units,
					unsigned int max_units, bool *defer)
{
	struct ntfs_volume *vol = ni->vol;
	u64 folio_end = folio_byte + PAGE_SIZE;
	u64 unit_byte = folio_byte;

	while (unit_byte < folio_end && unit_byte < file_limit) {
		struct ntfs_mft_io_unit unit;
		u64 record_byte;
		u64 unit_end;
		u64 io_unit_end;
		u64 cluster_end;
		bool selected = false;
		int err;

		io_unit_end =
			round_down(unit_byte, (u64)vol->mft_io_unit_size) +
			vol->mft_io_unit_size;
		cluster_end = ntfs_cluster_to_bytes(
			vol, ntfs_bytes_to_cluster(vol, unit_byte) + 1);
		unit_end = min3(io_unit_end, cluster_end, folio_end);

		record_byte = round_down(unit_byte, (u64)vol->mft_record_size);
		while (record_byte < min(unit_end, file_limit)) {
			unsigned int record;

			record = div_u64(record_byte - folio_byte,
					 vol->mft_record_size);
			if (test_bit(record, record_selected)) {
				selected = true;
				break;
			}
			record_byte += vol->mft_record_size;
		}
		/*
		 * Direct inode writeback owns unselected records.  Their folio
		 * images are stable while this folio is locked, so a containing
		 * unit can preserve them when writing a selected record.
		 */
		if (!selected)
			goto next;

		unit = (struct ntfs_mft_io_unit){
			.folio_ofs = unit_byte - folio_byte,
			.len = unit_end - unit_byte,
		};
		err = ntfs_map_mft_io_for_folio(ni, folio_byte, &unit);
		if (err == -EAGAIN) {
			*defer = true;
			goto next;
		}
		if (err)
			return err;
		if (*nr_units >= max_units)
			return -EOVERFLOW;
		units[(*nr_units)++] = unit;
next:
		unit_byte = unit_end;
	}
	return 0;
}

static void ntfs_mft_write_error(struct ntfs_volume *vol,
				 struct address_space *mapping, int err)
{
	mapping_set_error(mapping, err);
	NVolSetErrors(vol);
	ntfs_error(vol->sb, "Error while writing MFT folio: %d", err);
}

/* Every MFT record in a submitted I/O unit must have durable WAL. */
int ntfs_mft_wait_page_log(struct ntfs_volume *vol, const u8 *data,
		pgoff_t index, u32 start, u32 len, bool sync)
{
	u32 off;
	int err;

	if (WARN_ON_ONCE(start > PAGE_SIZE || len > PAGE_SIZE - start ||
			 !IS_ALIGNED(start, vol->mft_record_size) ||
			 !IS_ALIGNED(len, vol->mft_record_size)))
		return -EINVAL;

	for (off = start; off < start + len;
	     off += vol->mft_record_size) {
		const struct mft_record *m = (const void *)(data + off);
		u64 mft_no = (((u64)index << PAGE_SHIFT) + off) >>
				vol->mft_record_size_bits;

		if ((mft_no == FILE_MFT || mft_no == FILE_AttrDef ||
		     mft_no == FILE_UpCase) &&
		    (!ntfs_is_file_record(m->magic) ||
		     !(m->flags & MFT_RECORD_IN_USE))) {
			ntfs_error(vol->sb,
				"Refusing to write invalid system MFT record 0x%llx (folio %lu, magic 0x%x, flags 0x%x).",
				(unsigned long long)mft_no, (unsigned long)index,
				le32_to_cpu(m->magic), le16_to_cpu(m->flags));
			NVolSetErrors(vol);
			NVolSetShutdown(vol);
			vol->sb->s_flags |= SB_RDONLY;
			return -EIO;
		}

		if (!ntfs_is_mft_record(m->magic))
			continue;
		err = ntfs_log_writeback_lsn(vol, le64_to_cpu(m->lsn), sync);
		if (err)
			return err;
	}
	return 0;
}

/*
 * ntfs_write_mft_block - Write back a folio containing MFT records
 * @folio:	The folio to write back (contains one or more MFT records)
 * @wbc:	Writeback control structure
 *
 * This function is called as part of the address_space_operations
 * .writepages implementation for the $MFT inode.  Despite its historical
 * name, it handles one folio containing MFT records.
 *
 * Return: 0 on success, or -errno on error.
 */
static int ntfs_write_mft_block(struct folio *folio, struct writeback_control *wbc)
{
	struct address_space *mapping = folio->mapping;
	struct inode *vi = mapping->host;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	struct ntfs_inode **locked_nis __free(kfree) =
		kmalloc_objs(struct ntfs_inode *, PAGE_SIZE / NTFS_BLOCK_SIZE,
			     GFP_NOFS);
	struct inode **ref_inos __free(kfree) =
		kmalloc_objs(struct inode *, PAGE_SIZE / NTFS_BLOCK_SIZE, GFP_NOFS);
	struct ntfs_mft_io_unit *units __free(kfree) = NULL;
	struct bio *parent = NULL, *child = NULL;
	struct ntfs_mft_write_ctx *ctx = NULL;
	u8 *kaddr = NULL;
	DECLARE_BITMAP(record_selected, PAGE_SIZE / NTFS_BLOCK_SIZE) = {};
	u64 folio_byte, file_limit, folio_end, mirror_size;
	unsigned int nr_records, nr_units = 0, max_units;
	unsigned int nr_locked_nis = 0, nr_ref_inos = 0;
	unsigned int record, unit_idx;
	unsigned long flags;
	loff_t i_size;
	s64 allocated_size;
	bool defer = false, redirty = false;
	int err = 0;

	read_lock_irqsave(&ni->size_lock, flags);
	i_size = i_size_read(vi);
	allocated_size = ni->allocated_size;
	read_unlock_irqrestore(&ni->size_lock, flags);

	ntfs_debug("Entering for inode 0x%llx, folio index 0x%lx.", ni->mft_no,
		   folio->index);
	WARN_ON(!folio_test_locked(folio));

	folio_byte = folio_pos(folio);
	folio_end = folio_byte + PAGE_SIZE;
	mirror_size = (u64)vol->mftmirr_size * vol->mft_record_size;

	if (i_size <= folio_byte)
		folio_zero_segment(folio, 0, PAGE_SIZE);
	else if ((u64)i_size < folio_end)
		folio_zero_segment(folio, i_size - folio_byte, PAGE_SIZE);

	file_limit = min_t(u64, i_size, allocated_size);
	nr_records = PAGE_SIZE / vol->mft_record_size;
	max_units = PAGE_SIZE / min(vol->cluster_size, vol->mft_record_size);
	units = kmalloc_objs(*units, max_units, GFP_NOFS);
	if (!locked_nis || !ref_inos || !units) {
		err = -ENOMEM;
		goto out_noio;
	}
	kaddr = kmap_local_folio(folio, 0);
	err = ntfs_mft_wait_page_log(vol, kaddr, folio->index, 0, PAGE_SIZE,
			wbc->sync_mode == WB_SYNC_ALL);
	if (err) {
		redirty = true;
		if (err == -EAGAIN) {
			defer = true;
			err = 0;
		}
		goto out_noio;
	}
	folio_clear_uptodate(folio);

	for (record = 0; record < nr_records; record++) {
		struct ntfs_inode *tni = NULL;
		struct inode *ref_vi = NULL;
		u64 record_byte =
			folio_byte + (u64)record * vol->mft_record_size;
		u64 mft_no;

		if (record_byte >= file_limit)
			continue;
		mft_no = record_byte >> vol->mft_record_size_bits;
		if (!ntfs_may_write_mft_record(
			    vol, mft_no,
			    (struct mft_record *)(kaddr +
						  record * vol->mft_record_size),
			    &tni, &ref_vi)) {
			defer = true;
			if (ref_vi)
				ref_inos[nr_ref_inos++] = ref_vi;
			continue;
		}
		if (ref_vi)
			ref_inos[nr_ref_inos++] = ref_vi;
		if (tni) {
			locked_nis[nr_locked_nis++] = tni;
			if (tni->nr_extents < 0 &&
			    tni->ext.base_ntfs_ino == NTFS_I(vol->mft_ino)) {
				defer = true;
				continue;
			}
		}
		__set_bit(record, record_selected);
	}

	err = ntfs_prepare_mft_folio_units(ni, folio_byte, file_limit,
					   record_selected, units, &nr_units,
					   max_units, &defer);
	if (err)
		goto out_noio;
	if (!nr_units) {
		if (defer)
			goto out_noio;
		folio_mark_uptodate(folio);
		kunmap_local(kaddr);
		folio_start_writeback(folio);
		folio_unlock(folio);
		folio_end_writeback(folio);
		ntfs_release_mft_write_refs(locked_nis, nr_locked_nis, ref_inos,
					    nr_ref_inos);
		return 0;
	}

	parent = ntfs_alloc_mft_parent_bio(vol, folio, NULL);
	if (!parent) {
		err = -ENOMEM;
		goto out_noio;
	}
	ctx = container_of(parent, struct ntfs_mft_write_ctx, bio);

	if (!ntfs_add_mft_io_unit(parent, ctx->io_page, &units[0])) {
		err = -EIO;
		goto out_noio;
	}

	for (unit_idx = 0; unit_idx < nr_units; unit_idx++) {
		struct ntfs_mft_io_unit *unit = &units[unit_idx];
		u64 file_ofs = folio_byte + unit->folio_ofs;

		if (unit_idx) {
			struct bio *target = child ? child : parent;

			if (!ntfs_add_mft_io_unit(target, ctx->io_page, unit)) {
				if (child) {
					ntfs_start_mft_writeback(ctx);
					bio_chain(child, parent);
					submit_bio(child);
					child = NULL;
				}
				child = bio_alloc(vol->sb->s_bdev, 1,
						  REQ_OP_WRITE, GFP_NOIO);
				if (!child) {
					defer = true;
					break;
				}
				if (!ntfs_add_mft_io_unit(child, ctx->io_page, unit)) {
					bio_put(child);
					child = NULL;
					if (!ctx->error)
						ctx->error = -EIO;
					redirty = true;
					err = -EIO;
					break;
				}
			}
		}
		if (file_ofs < mirror_size) {
			int mirror_err = ntfs_sync_mft_mirror_unit(
				vol, page_folio(ctx->io_page), file_ofs, unit);

			if (mirror_err && !ctx->error)
				ctx->error = mirror_err;
		}
	}

	if (child) {
		ntfs_start_mft_writeback(ctx);
		bio_chain(child, parent);
		submit_bio(child);
	}
	ntfs_start_mft_writeback(ctx);
	folio_mark_uptodate(folio);
	if (defer || redirty)
		folio_redirty_for_writepage(wbc, folio);
	kunmap_local(kaddr);
	kaddr = NULL;
	folio_unlock(folio);
	submit_bio(parent);
	ntfs_release_mft_write_refs(locked_nis, nr_locked_nis, ref_inos,
				    nr_ref_inos);

	return 0;

out_noio:
	if (kaddr) {
		folio_mark_uptodate(folio);
		kunmap_local(kaddr);
	}
	if (err && err != -ENOMEM)
		ntfs_mft_write_error(vol, mapping, err);
	if (parent)
		ntfs_free_mft_parent_bio(parent);
	if (redirty || defer || err == -ENOMEM)
		folio_redirty_for_writepage(wbc, folio);
	folio_unlock(folio);
	ntfs_release_mft_write_refs(locked_nis, nr_locked_nis, ref_inos,
				    nr_ref_inos);
	if (err == -ENOMEM || (defer && !err))
		return 0;
	return err;
}

/*
 * ntfs_mft_writepages - Write back dirty folios for the $MFT inode
 * @mapping:	address space of the $MFT inode
 * @wbc:	writeback control
 *
 * Writeback iterator for MFT records. Iterates over dirty folios and
 * delegates actual writing to ntfs_write_mft_block() for each folio.
 * Called from the address_space_operations .writepages vector of the
 * $MFT inode.
 *
 * Returns 0 on success, or the first error encountered.
 */
int ntfs_mft_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	struct folio *folio = NULL;
	int error;

	if (NVolShutdown(NTFS_I(mapping->host)->vol))
		return -EIO;

	while ((folio = writeback_iter(mapping, wbc, folio, &error)))
		error = ntfs_write_mft_block(folio, wbc);
	return error;
}

void ntfs_mft_mark_dirty(struct folio *folio)
{
	iomap_dirty_folio(folio->mapping, folio);
}
