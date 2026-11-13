// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Attribute list attribute handling code.
 * Part of this file is based on code from the NTFS-3G.
 *
 * Copyright (c) 2004-2005 Anton Altaparmakov
 * Copyright (c) 2004-2005 Yura Pakhuchiy
 * Copyright (c)      2006 Szabolcs Szakacsits
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "mft.h"
#include "attrib.h"
#include "attrlist.h"
#include "lcnalloc.h"
#include "logfile_internal.h"

#define ntfs_attrlist_kvmemdup kvmemdup

struct ntfs_attrlist_home_undo {
	struct ntfs_inode *ni;
	u8 *attr_list;
	u8 *mrec;
	u32 attr_list_size;
	bool has_attr_list;
	bool attr_list_dirty;
	bool attr_list_nonresident;
	bool mft_dirty;
};

struct ntfs_attrlist_stream_home_undo {
	struct inode *vi;
	bool vi_held;
	u8 *value;
	struct runlist_element *runlist;
	size_t runlist_count;
	int runlist_hint;
	u32 value_size;
	s64 allocated_size;
	s64 data_size;
	s64 initialized_size;
	s64 zeroed_size;
	loff_t i_size;
	blkcnt_t vi_i_blocks;
};

static int ntfs_attrlist_stream_validate_runlist(struct ntfs_volume *vol,
		const struct runlist_element *runlist, size_t runlist_count,
		int runlist_hint, s64 allocated_size);

static int ntfs_attrlist_stream_validate_sizes(struct inode *vi,
		s64 allocated_size, u32 value_size)
{
	struct ntfs_inode *ni;
	unsigned long flags;
	bool invalid;

	if (!vi || allocated_size <= 0 || allocated_size < value_size)
		return -EIO;
	ni = NTFS_I(vi);
	read_lock_irqsave(&ni->size_lock, flags);
	invalid = ni->allocated_size != allocated_size ||
		ni->data_size != value_size ||
		ni->initialized_size != value_size ||
		ni->zeroed_size != value_size || i_size_read(vi) != value_size;
	if (!invalid && (u64)vi->i_blocks != ((u64)allocated_size >> 9))
		invalid = true;
	read_unlock_irqrestore(&ni->size_lock, flags);
	return invalid ? -EIO : 0;
}

static int ntfs_attrlist_validate_allocated_runlist(
		struct ntfs_volume *vol, const struct runlist_element *runlist,
		s64 start_vcn, s64 cluster_count, size_t *runlist_count)
{
	s64 end_vcn;
	s64 expected_vcn;
	size_t i;

	if (!vol || !runlist || !runlist_count || vol->nr_clusters <= 0 ||
	    start_vcn < 0 ||
	    cluster_count <= 0 || cluster_count > SIZE_MAX - 1 ||
	    check_add_overflow(start_vcn, cluster_count, &end_vcn))
		return -EIO;
	expected_vcn = start_vcn;
	for (i = 0; i <= (size_t)cluster_count; i++) {
		const struct runlist_element *rl = &runlist[i];

		if (!rl->length) {
			if (!i || rl->vcn != end_vcn || rl->lcn != LCN_ENOENT ||
			    expected_vcn != end_vcn)
				return -EIO;
			*runlist_count = i + 1;
			return 0;
		}
		if (rl->vcn != expected_vcn || rl->lcn < 0 || rl->length < 0 ||
		    rl->length > end_vcn - expected_vcn ||
		    rl->lcn > vol->nr_clusters - rl->length)
			return -EIO;
		expected_vcn += rl->length;
	}
	return -EIO;
}

static int ntfs_attrlist_validate_value(const u8 *value, u32 value_size)
{
	const u8 *end;
	const u8 *pos;

	if (!value || !value_size || value_size > 256 * 1024)
		return -EIO;
	pos = value;
	end = value + value_size;
	while (pos < end) {
		const struct attr_list_entry *ale;
		u32 entry_len;
		u32 name_bytes;
		u32 remaining = end - pos;

		if (remaining < sizeof(*ale))
			return -EIO;
		ale = (const struct attr_list_entry *)pos;
		entry_len = le16_to_cpu(ale->length);
		name_bytes = ale->name_length * sizeof(__le16);
		if (entry_len < sizeof(*ale) || !IS_ALIGNED(entry_len, 8) ||
		    entry_len > remaining || ale->name_offset > entry_len ||
		    (ale->name_length && ale->name_offset <
			    offsetof(struct attr_list_entry, name)) ||
		    name_bytes > entry_len - ale->name_offset)
			return -EIO;
		pos += entry_len;
	}
	return pos == end ? 0 : -EIO;
}

static void ntfs_attrlist_changed_range(const u8 *old_value,
		const u8 *new_value, u32 bytes, u32 *start, u32 *end)
{
	u32 first = 0;
	u32 last = bytes;

	while (first < bytes && old_value[first] == new_value[first])
		first++;
	while (last > first && old_value[last - 1] == new_value[last - 1])
		last--;
	*start = first;
	*end = last;
}

static int ntfs_attrlist_stream_home_restore(void *data)
{
	struct ntfs_attrlist_stream_home_undo *undo = data;
	struct ntfs_inode *ni;
	unsigned long flags;
	s64 written;
	int err;

	if (!undo || !undo->vi || !undo->value || !undo->value_size ||
	    undo->value_size > 256 * 1024)
		return -EINVAL;
	ni = NTFS_I(undo->vi);
	if (!NInoNonResident(ni) ||
	    undo->allocated_size > 256 * 1024 ||
	    undo->allocated_size < (s64)undo->value_size ||
	    undo->data_size != undo->value_size ||
	    undo->initialized_size != undo->value_size ||
	    undo->zeroed_size != undo->value_size ||
	    undo->i_size != undo->value_size ||
	    (u64)undo->vi_i_blocks != ((u64)undo->allocated_size >> 9))
		return -EIO;
	err = ntfs_attrlist_validate_value(undo->value, undo->value_size);
	if (err)
		return err;
	err = ntfs_attrlist_stream_validate_runlist(ni->vol, undo->runlist,
			undo->runlist_count, undo->runlist_hint,
			undo->allocated_size);
	if (err)
		return err;
	err = ntfs_cluster_free_from_rl_preflight(ni->vol, undo->runlist);
	if (err)
		return err;

	down_write(&ni->runlist.lock);
	kvfree(ni->runlist.rl);
	ni->runlist.rl = undo->runlist;
	undo->runlist = NULL;
	ni->runlist.count = undo->runlist_count;
	ni->runlist.rl_hint = undo->runlist_hint;
	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = undo->allocated_size;
	ni->data_size = undo->data_size;
	ni->initialized_size = undo->initialized_size;
	ni->zeroed_size = undo->zeroed_size;
	i_size_write(undo->vi, undo->i_size);
	undo->vi->i_blocks = undo->vi_i_blocks;
	write_unlock_irqrestore(&ni->size_lock, flags);
	up_write(&ni->runlist.lock);
	truncate_inode_pages(undo->vi->i_mapping, undo->i_size);
	written = ntfs_inode_attr_pwrite(undo->vi, 0, undo->value_size,
			undo->value, true);
	if (written == undo->value_size)
		return 0;
	return written < 0 ? written : -EIO;
}

static void ntfs_attrlist_stream_home_release(void *data)
{
	struct ntfs_attrlist_stream_home_undo *undo = data;

	kvfree(undo->runlist);
	ntfs_home_undo_iput(undo->vi, undo->vi_held);
	kvfree(undo->value);
	kfree(undo);
}

static int ntfs_attrlist_stream_validate_runlist(struct ntfs_volume *vol,
		const struct runlist_element *runlist, size_t runlist_count,
		int runlist_hint, s64 allocated_size)
{
	u64 clusters;
	u64 expected_vcn = 0;
	size_t i;

	if (!vol || !runlist || runlist_count < 2 ||
	    runlist_count > INT_MAX || runlist_hint < -1 ||
	    runlist_hint >= (int)runlist_count - 1 || allocated_size <= 0 ||
	    !IS_ALIGNED(allocated_size, vol->cluster_size) ||
	    vol->nr_clusters <= 0)
		return -EIO;
	clusters = allocated_size >> vol->cluster_size_bits;
	for (i = 0; i < runlist_count; i++) {
		const struct runlist_element *rl = &runlist[i];
		s64 end_lcn;
		u64 next_vcn;

		if (!rl->length) {
			if (i + 1 != runlist_count || rl->vcn != clusters ||
			    rl->lcn != LCN_ENOENT || expected_vcn != clusters)
				return -EIO;
			return 0;
		}
		if (rl->vcn < 0 || rl->lcn < 0 || rl->length < 0 ||
		    (u64)rl->vcn != expected_vcn ||
		    check_add_overflow(rl->lcn, rl->length, &end_lcn) ||
		    end_lcn > vol->nr_clusters ||
		    check_add_overflow(expected_vcn, (u64)rl->length,
			    &next_vcn) || next_vcn > clusters)
			return -EIO;
		expected_vcn = next_vcn;
	}
	return -EIO;
}

static int ntfs_attrlist_stream_register_home_undo(
		struct ntfs_log_handle *handle, struct inode *vi,
		const u8 *value, u32 value_size)
{
	struct ntfs_attrlist_stream_home_undo *undo;
	struct ntfs_inode *base_ni;
	struct ntfs_inode *ni;
	unsigned long flags;
	size_t bytes;
	int err;

	if (!handle || !vi || !value || !value_size || value_size > 256 * 1024)
		return -EINVAL;
	err = ntfs_attrlist_validate_value(value, value_size);
	if (err)
		return err;
	undo = kzalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->value = ntfs_attrlist_kvmemdup(value, value_size, GFP_NOFS);
	if (!undo->value) {
		kfree(undo);
		return -ENOMEM;
	}
	ni = NTFS_I(vi);
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni) {
		kvfree(undo->value);
		kfree(undo);
		return -EINVAL;
	}
	down_read(&ni->runlist.lock);
	if ((ni->runlist.count && !ni->runlist.rl) ||
	    (ni->runlist.count && check_mul_overflow(ni->runlist.count,
			    sizeof(*ni->runlist.rl), &bytes))) {
		up_read(&ni->runlist.lock);
		kvfree(undo->value);
		kfree(undo);
		return -EOVERFLOW;
	}
	if (ni->runlist.count) {
		undo->runlist = ntfs_attrlist_kvmemdup(ni->runlist.rl, bytes,
				GFP_NOFS);
		if (!undo->runlist) {
			up_read(&ni->runlist.lock);
			kvfree(undo->value);
			kfree(undo);
			return -ENOMEM;
		}
	}
	undo->value_size = value_size;
	undo->runlist_count = ni->runlist.count;
	undo->runlist_hint = ni->runlist.rl_hint;
	read_lock_irqsave(&ni->size_lock, flags);
	undo->allocated_size = ni->allocated_size;
	undo->data_size = ni->data_size;
	undo->initialized_size = ni->initialized_size;
	undo->zeroed_size = ni->zeroed_size;
	undo->i_size = i_size_read(vi);
	undo->vi_i_blocks = vi->i_blocks;
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (!NInoNonResident(ni) ||
	    undo->allocated_size > 256 * 1024 ||
	    undo->allocated_size < (s64)value_size ||
	    undo->data_size != value_size ||
	    undo->initialized_size != value_size ||
	    undo->zeroed_size != value_size || undo->i_size != value_size) {
		up_read(&ni->runlist.lock);
		kvfree(undo->runlist);
		kvfree(undo->value);
		kfree(undo);
		return -EIO;
	}
	err = ntfs_attrlist_stream_validate_runlist(ni->vol, undo->runlist,
			undo->runlist_count, undo->runlist_hint,
			undo->allocated_size);
	if (!err && (u64)undo->vi_i_blocks !=
			((u64)undo->allocated_size >> 9))
		err = -EIO;
	if (!err)
		err = ntfs_cluster_free_from_rl_preflight(ni->vol,
				undo->runlist);
	if (err) {
		up_read(&ni->runlist.lock);
		kvfree(undo->runlist);
		kvfree(undo->value);
		kfree(undo);
		return err;
	}
	up_read(&ni->runlist.lock);
	undo->vi_held = ntfs_home_undo_igrab(vi);
	undo->vi = vi;
	err = ntfs_log_register_home_undo(handle,
			ntfs_attrlist_stream_home_restore,
			ntfs_attrlist_stream_home_release, undo);
	if (err)
		ntfs_attrlist_stream_home_release(undo);
	return err;
}

static int ntfs_attrlist_home_restore(void *data)
{
	struct ntfs_attrlist_home_undo *undo = data;
	struct ntfs_inode *ni = undo->ni;
	struct mft_record *mrec;
	int err;

	kvfree(ni->attr_list);
	ni->attr_list = undo->attr_list;
	undo->attr_list = NULL;
	ni->attr_list_size = undo->attr_list_size;
	if (undo->has_attr_list)
		NInoSetAttrList(ni);
	else
		NInoClearAttrList(ni);
	if (undo->attr_list_dirty)
		NInoSetAttrListDirty(ni);
	else
		NInoClearAttrListDirty(ni);
	if (undo->attr_list_nonresident)
		NInoSetAttrListNonResident(ni);
	else
		NInoClearAttrListNonResident(ni);

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	memcpy(mrec, undo->mrec, ni->vol->mft_record_size);
	err = ntfs_prepare_mft_record_write(ni);
	if (err)
		goto out_unmap;
	NInoSetDirty(ni);
	err = write_mft_record(ni, mrec, 1);
	if (!err && undo->mft_dirty)
		NInoSetDirty(ni);
out_unmap:
	unmap_mft_record(ni);
	return err;
}

static void ntfs_attrlist_home_release(void *data)
{
	struct ntfs_attrlist_home_undo *undo = data;

	kvfree(undo->attr_list);
	kfree(undo->mrec);
	kfree(undo);
}

static int ntfs_attrlist_register_home_undo(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	struct ntfs_attrlist_home_undo *undo;
	struct mft_record *mrec;
	int err;

	if (!handle || !ni || (ni->attr_list_size && !ni->attr_list))
		return -EINVAL;
	undo = kzalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	if (ni->attr_list_size) {
		undo->attr_list = ntfs_attrlist_kvmemdup(ni->attr_list,
				ni->attr_list_size, GFP_NOFS);
		if (!undo->attr_list) {
			kfree(undo);
			return -ENOMEM;
		}
	}
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out_release;
	}
	undo->mrec = kmemdup(mrec, ni->vol->mft_record_size, GFP_NOFS);
	unmap_mft_record(ni);
	if (!undo->mrec) {
		err = -ENOMEM;
		goto out_release;
	}
	undo->ni = ni;
	undo->attr_list_size = ni->attr_list_size;
	undo->has_attr_list = NInoAttrList(ni);
	undo->attr_list_dirty = NInoAttrListDirty(ni);
	undo->attr_list_nonresident = NInoAttrListNonResident(ni);
	undo->mft_dirty = NInoDirty(ni);
	err = ntfs_log_register_home_undo(handle, ntfs_attrlist_home_restore,
			ntfs_attrlist_home_release, undo);
	if (!err)
		return 0;
out_release:
	ntfs_attrlist_home_release(undo);
	return err;
}

static int ntfs_attrlist_build(struct ntfs_inode *ni, u8 **list_out,
		u32 *size_out)
{
	struct ntfs_attr_search_ctx *ctx;
	struct attr_list_entry *ale;
	struct mft_record *mrec;
	u8 *list = NULL;
	u32 list_size = 0;
	int err;

	if (!ni || !list_out || !size_out || NInoAttrList(ni) || ni->nr_extents)
		return -EINVAL;
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	ctx = ntfs_attr_get_search_ctx(ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}
	while (!(err = ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0,
			ctx))) {
		u32 entry_size = ALIGN(sizeof(*ale) +
				ctx->attr->name_length * sizeof(__le16), 8);

		if (ctx->attr->type == AT_ATTRIBUTE_LIST ||
		    check_add_overflow(list_size, entry_size, &list_size) ||
		    list_size > 256 * 1024) {
			err = -E2BIG;
			goto out_ctx;
		}
	}
	if (err != -ENOENT)
		goto out_ctx;
	if (!list_size) {
		err = -EIO;
		goto out_ctx;
	}
	list = kvzalloc(list_size, GFP_NOFS);
	if (!list) {
		err = -ENOMEM;
		goto out_ctx;
	}
	ntfs_attr_reinit_search_ctx(ctx);
	ale = (struct attr_list_entry *)list;
	while (!(err = ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0,
			ctx))) {
		u16 entry_size = ALIGN(sizeof(*ale) +
				ctx->attr->name_length * sizeof(__le16), 8);

		ale->type = ctx->attr->type;
		ale->length = cpu_to_le16(entry_size);
		ale->name_length = ctx->attr->name_length;
		ale->name_offset = offsetof(struct attr_list_entry, name);
		ale->lowest_vcn = ctx->attr->non_resident ?
			ctx->attr->data.non_resident.lowest_vcn : 0;
		ale->mft_reference = MK_LE_MREF(ni->mft_no,
				le16_to_cpu(mrec->sequence_number));
		ale->instance = ctx->attr->instance;
		if (ale->name_length)
			memcpy(ale->name, (u8 *)ctx->attr +
					le16_to_cpu(ctx->attr->name_offset),
					ale->name_length * sizeof(__le16));
		ale = (struct attr_list_entry *)((u8 *)ale + entry_size);
	}
	if (err != -ENOENT) {
		kvfree(list);
		goto out_ctx;
	}
	*list_out = list;
	*size_out = list_size;
	err = 0;
out_ctx:
	ntfs_attr_put_search_ctx(ctx);
out_unmap:
	unmap_mft_record(ni);
	return err;
}

/*
 * ntfs_attrlist_need - check whether inode need attribute list
 * @ni:	opened ntfs inode for which perform check
 *
 * Check whether all are attributes belong to one MFT record, in that case
 * attribute list is not needed.
 *
 * Return 1 if inode need attribute list, 0 if not, or -errno on error.
 */
int ntfs_attrlist_need(struct ntfs_inode *ni)
{
	struct attr_list_entry *ale;
	u32 entry_len;
	u32 name_bytes;
	u32 remaining;
	u8 *end;

	if (!ni) {
		ntfs_debug("Invalid arguments.\n");
		return -EINVAL;
	}
	ntfs_debug("Entering for inode 0x%llx.\n", (long long) ni->mft_no);

	if (!NInoAttrList(ni)) {
		ntfs_debug("Inode haven't got attribute list.\n");
		return -EINVAL;
	}

	if (!ni->attr_list) {
		ntfs_debug("Corrupt in-memory struct.\n");
		return -EINVAL;
	}

	ale = (struct attr_list_entry *)ni->attr_list;
	end = ni->attr_list + ni->attr_list_size;
	while ((u8 *)ale < end) {
		remaining = end - (u8 *)ale;
		if (remaining < sizeof(*ale))
			return -EIO;
		entry_len = le16_to_cpu(ale->length);
		name_bytes = ale->name_length * sizeof(__le16);
		if (entry_len < sizeof(*ale) || !IS_ALIGNED(entry_len, 8) ||
		    entry_len > remaining || ale->name_offset > entry_len ||
		    (ale->name_length && ale->name_offset <
			    offsetof(struct attr_list_entry, name)) ||
		    name_bytes > entry_len - ale->name_offset)
			return -EIO;
		if (MREF_LE(ale->mft_reference) != ni->mft_no)
			return 1;
		ale = (struct attr_list_entry *)((u8 *)ale + entry_len);
	}
	return 0;
}

/*
 * Repack the $MFT/$ATTRIBUTE_LIST data into one run.
 *
 * The mapping pairs for an $ATTRIBUTE_LIST must remain in the base MFT
 * record. Once that record has no room left, extending a fragmented list
 * can require one more mapping-pairs byte than the record can hold. There
 * is no attribute that can legally be moved out in that state: $STANDARD_
 * INFORMATION, $ATTRIBUTE_LIST, and the first $MFT/$DATA extent all have to
 * stay in the base record.  Move the list data to one contiguous run. The
 * caller supplies the minimum allocation size so a recovery can use the
 * smallest useful run while normal updates can still request the maximum
 * legal list size as a reserve.
 */
static int ntfs_attrlist_repack(struct inode *attr_vi,
		struct ntfs_inode *attr_ni, s64 min_alloc_size,
		struct ntfs_inode *locked_ni)
{
	struct ntfs_volume *vol = attr_ni->vol;
	struct runlist_element *old_rl, *new_rl;
	u8 *data = NULL;
	s64 data_size, alloc_size, nr_clusters, written;
	s64 old_alloc_size;
	size_t old_rl_count, new_rl_count;
	unsigned long flags;
	int err, restore_err;
	if (attr_ni->mft_no != FILE_MFT || !NInoNonResident(attr_ni) ||
		min_alloc_size < 0)
		return -EINVAL;
	/* The buffered I/O below can reacquire the attribute runlist lock. */
	if (attr_ni == locked_ni)
		return -ENOSPC;

	err = ntfs_attr_map_whole_runlist(attr_ni);
	if (err)
		return err;

	data_size = attr_ni->data_size;
	if (data_size < 0)
		return -EIO;

	if (data_size) {
		data = kvmalloc(data_size, GFP_NOFS);
		if (!data)
			return -ENOMEM;

		written = ntfs_inode_attr_pread(attr_vi, 0, data_size, data);
		if (written != data_size) {
			err = written < 0 ? (int)written : -EIO;
			goto out_free_data;
		}
	}

	old_alloc_size = attr_ni->allocated_size;
	alloc_size = max_t(s64, old_alloc_size, min_alloc_size);
	nr_clusters = ntfs_bytes_to_cluster(vol,
			alloc_size + vol->cluster_size - 1);
	if (nr_clusters <= 0) {
		err = -EFBIG;
		goto out_free_data;
	}

	/* A single run keeps the mapping pairs at the minimum size. */
	new_rl = ntfs_cluster_alloc(vol, 0, nr_clusters, -1, DATA_ZONE,
				    true, true, false);
	if (IS_ERR(new_rl)) {
		err = PTR_ERR(new_rl);
		goto out_free_data;
	}

	new_rl_count = 0;
	if (new_rl->vcn == 0 && new_rl->length == nr_clusters &&
		!new_rl[1].length)
		new_rl_count = 2;

	if (new_rl_count != 2) {
		ntfs_cluster_free_from_rl(vol, new_rl);
		kvfree(new_rl);
		err = -ENOSPC;
		goto out_free_data;
	}
	old_rl = attr_ni->runlist.rl;
	old_rl_count = attr_ni->runlist.count;
	down_write(&attr_ni->runlist.lock);
	attr_ni->runlist.rl = new_rl;
	attr_ni->runlist.count = new_rl_count;
	up_write(&attr_ni->runlist.lock);

	write_lock_irqsave(&attr_ni->size_lock, flags);
	attr_ni->allocated_size = ntfs_cluster_to_bytes(vol, nr_clusters);
	write_unlock_irqrestore(&attr_ni->size_lock, flags);

	/* Populate the replacement extent before publishing its mapping pairs. */
	if (data_size) {
		written = ntfs_inode_attr_pwrite(attr_vi, 0, data_size, data, true);
		if (written != data_size) {
			err = written < 0 ? (int)written : -EIO;
			goto restore_old_runlist;
		}
	}

	err = ntfs_attr_update_mapping_pairs_locked(attr_ni, 0, locked_ni);
	if (err)
		goto restore_old_runlist;

	/* The new mapping is now authoritative; release the old data runs. */
	if (ntfs_cluster_free_from_rl(vol, old_rl)) {
		ntfs_error(vol->sb,
			   "Failed to free old ATTRIBUTE_LIST extent: inode %#llx",
			   (long long)attr_ni->mft_no);
		NVolSetErrors(vol);
	}
	kvfree(old_rl);
	kvfree(data);
	return 0;

restore_old_runlist:
	/*
	 * Restore allocated_size before dropping the runlist lock:
	 * ntfs_attr_vcn_to_rl() fails a lookup below the allocated size that
	 * falls past the end of the runlist.
	 */
	down_write(&attr_ni->runlist.lock);
	attr_ni->runlist.rl = old_rl;
	attr_ni->runlist.count = old_rl_count;
	write_lock_irqsave(&attr_ni->size_lock, flags);
	attr_ni->allocated_size = old_alloc_size;
	write_unlock_irqrestore(&attr_ni->size_lock, flags);
	up_write(&attr_ni->runlist.lock);

	restore_err = ntfs_attr_update_mapping_pairs_locked(
			attr_ni, 0, locked_ni);
	if (restore_err) {
		ntfs_error(vol->sb, "Failed to restore ATTRIBUTE_LIST mapping pairs (%d)",
			   restore_err);
		NVolSetErrors(vol);
	}

	ntfs_cluster_free_from_rl(vol, new_rl);
	kvfree(new_rl);
	err = err ? err : restore_err;

out_free_data:
	kvfree(data);
	return err;
}

int ntfs_attrlist_remove_resident_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni)
{
	struct ntfs_attr_search_ctx *ctx;
	struct attr_record *attr;
	struct mft_record *mrec;
	u8 *old_list;
	u64 operation_lsn;
	u32 attr_len;
	u32 attrs_off;
	u32 used;
	u32 value_len;
	u16 record_off;
	u16 value_off;
	ptrdiff_t record_pos;
	int err;

	if (!handle || !base_ni || !NInoAttrList(base_ni) ||
	    NInoAttrListNonResident(base_ni) || !base_ni->attr_list ||
	    !base_ni->attr_list_size)
		return -EOPNOTSUPP;
	err = ntfs_attrlist_need(base_ni);
	if (err)
		return err > 0 ? -EOPNOTSUPP : err;
	mrec = map_mft_record(base_ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	ctx = ntfs_attr_get_search_ctx(base_ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}
	err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx);
	if (err)
		goto out_ctx;
	attr = ctx->attr;
	if (!attr) {
		err = -EIO;
		goto out_ctx;
	}
	attr_len = le32_to_cpu(attr->length);
	attrs_off = le16_to_cpu(mrec->attrs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	record_pos = (u8 *)attr - (u8 *)mrec;
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (attr->non_resident || record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    value_off > attr_len || value_len != base_ni->attr_list_size ||
	    value_len > attr_len - value_off || record_pos > used ||
	    attr_len > used - record_pos || attrs_off > used - attr_len ||
	    used - attr_len - attrs_off == 8 ||
	    memcmp((u8 *)attr + value_off, base_ni->attr_list, value_len)) {
		err = -EIO;
		goto out_ctx;
	}
	record_off = record_pos;
	err = ntfs_attrlist_register_home_undo(handle, base_ni);
	if (err)
		goto out_ctx;
	err = ntfs_log_mft_attribute_delete(handle, base_ni->mft_no,
			record_off, attr, attr_len, &operation_lsn);
	if (err)
		goto out_ctx;
	err = ntfs_attr_record_resize(mrec, attr, 0);
	if (err)
		goto out_ctx;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(base_ni);
	old_list = base_ni->attr_list;
	base_ni->attr_list = NULL;
	base_ni->attr_list_size = 0;
	NInoClearAttrList(base_ni);
	NInoClearAttrListDirty(base_ni);
	NInoClearAttrListNonResident(base_ni);
	kvfree(old_list);
	err = 0;
out_ctx:
	ntfs_attr_put_search_ctx(ctx);
out_unmap:
	unmap_mft_record(base_ni);
	return err;
}

int ntfs_attrlist_remove_nonresident_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni)
{
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct runlist_element *empty_rl = NULL;
	struct runlist_element *free_rl = NULL;
	struct runlist_element *old_rl;
	struct ntfs_inode *attr_ni;
	struct attr_record *attr;
	struct inode *attr_vi;
	struct mft_record *mrec;
	u8 *old_list;
	u64 operation_lsn;
	u64 clusters;
	loff_t vfs_size;
	s64 allocated_size;
	s64 data_size;
	s64 initialized_size;
	s64 zeroed_size;
	u32 attr_len;
	u32 attrs_off;
	u32 mapping_off;
	u32 used;
	u16 record_off;
	ptrdiff_t record_pos;
	size_t free_bytes;
	unsigned long flags;
	int err;

	if (!handle || !base_ni || !NInoAttrList(base_ni) ||
	    !NInoAttrListNonResident(base_ni) || !base_ni->attr_list ||
	    !base_ni->attr_list_size)
		return -EOPNOTSUPP;
	err = ntfs_attrlist_need(base_ni);
	if (err)
		return err > 0 ? -EOPNOTSUPP : err;
	attr_vi = ntfs_attr_iget(VFS_I(base_ni), AT_ATTRIBUTE_LIST,
			AT_UNNAMED, 0);
	if (IS_ERR(attr_vi))
		return PTR_ERR(attr_vi);
	attr_ni = NTFS_I(attr_vi);
	read_lock_irqsave(&attr_ni->size_lock, flags);
	allocated_size = attr_ni->allocated_size;
	data_size = attr_ni->data_size;
	initialized_size = attr_ni->initialized_size;
	zeroed_size = attr_ni->zeroed_size;
	vfs_size = i_size_read(attr_vi);
	read_unlock_irqrestore(&attr_ni->size_lock, flags);
	if (!NInoNonResident(attr_ni) || NInoCompressed(attr_ni) ||
	    NInoSparse(attr_ni) || NInoEncrypted(attr_ni) ||
	    NInoRunlistDirty(attr_ni) || allocated_size <= 0 ||
	    allocated_size > 256 * 1024 ||
	    !IS_ALIGNED(allocated_size, attr_ni->vol->cluster_size) ||
	    data_size != base_ni->attr_list_size ||
	    initialized_size != base_ni->attr_list_size ||
	    zeroed_size != base_ni->attr_list_size ||
	    vfs_size != base_ni->attr_list_size) {
		err = -EIO;
		goto out_iput;
	}
	err = ntfs_attr_map_whole_runlist(attr_ni);
	if (err)
		goto out_iput;
	clusters = allocated_size >> attr_ni->vol->cluster_size_bits;
	down_read(&attr_ni->runlist.lock);
	if ((u64)attr_vi->i_blocks != ((u64)allocated_size >> 9)) {
		err = -EIO;
		goto out_unlock;
	}
	err = ntfs_attrlist_stream_validate_runlist(attr_ni->vol,
			attr_ni->runlist.rl, attr_ni->runlist.count,
			attr_ni->runlist.rl_hint, allocated_size);
	if (err)
		goto out_unlock;
	if (check_mul_overflow(attr_ni->runlist.count,
			sizeof(*free_rl), &free_bytes)) {
		err = -EOVERFLOW;
		goto out_unlock;
	}
	free_rl = ntfs_attrlist_kvmemdup(attr_ni->runlist.rl, free_bytes,
			GFP_NOFS);
	if (!free_rl) {
		err = -ENOMEM;
		goto out_unlock;
	}
	up_read(&attr_ni->runlist.lock);
	empty_rl = kvmalloc_obj(*empty_rl, GFP_NOFS);
	if (!empty_rl) {
		err = -ENOMEM;
		goto out;
	}
	empty_rl->vcn = 0;
	empty_rl->lcn = LCN_ENOENT;
	empty_rl->length = 0;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}
	err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || !attr->non_resident || attr->flags ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    le64_to_cpu(attr->data.non_resident.highest_vcn) != clusters - 1 ||
	    le64_to_cpu(attr->data.non_resident.allocated_size) !=
		    allocated_size ||
	    le64_to_cpu(attr->data.non_resident.data_size) !=
		    base_ni->attr_list_size ||
	    le64_to_cpu(attr->data.non_resident.initialized_size) !=
		    base_ni->attr_list_size) {
		err = -EIO;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	attrs_off = le16_to_cpu(mrec->attrs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	mapping_off = le16_to_cpu(
			attr->data.non_resident.mapping_pairs_offset);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    !IS_ALIGNED(mapping_off, 8) ||
	    mapping_off < offsetof(struct attr_record,
		    data.non_resident.compressed_size) ||
	    mapping_off >= attr_len ||
	    record_pos > used || attr_len > used - record_pos ||
	    attrs_off > used - attr_len || used - attr_len - attrs_off == 8) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	err = ntfs_attrlist_stream_register_home_undo(handle, attr_vi,
			base_ni->attr_list, base_ni->attr_list_size);
	if (err)
		goto out;
	err = ntfs_attrlist_register_home_undo(handle, base_ni);
	if (err)
		goto out;
	err = ntfs_log_mft_attribute_delete(handle, base_ni->mft_no,
			record_off, attr, attr_len, &operation_lsn);
	if (err)
		goto out;
	err = ntfs_attr_record_resize(mrec, attr, 0);
	if (err)
		goto out;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(base_ni);
	old_list = base_ni->attr_list;
	base_ni->attr_list = NULL;
	base_ni->attr_list_size = 0;
	NInoClearAttrList(base_ni);
	NInoClearAttrListDirty(base_ni);
	NInoClearAttrListNonResident(base_ni);
	kvfree(old_list);
	down_write(&attr_ni->runlist.lock);
	old_rl = attr_ni->runlist.rl;
	attr_ni->runlist.rl = empty_rl;
	empty_rl = NULL;
	attr_ni->runlist.count = 1;
	attr_ni->runlist.rl_hint = -1;
	write_lock_irqsave(&attr_ni->size_lock, flags);
	attr_ni->allocated_size = 0;
	attr_ni->data_size = 0;
	attr_ni->initialized_size = 0;
	attr_ni->zeroed_size = 0;
	i_size_write(attr_vi, 0);
	write_unlock_irqrestore(&attr_ni->size_lock, flags);
	attr_vi->i_blocks = 0;
	truncate_inode_pages(attr_vi->i_mapping, 0);
	up_write(&attr_ni->runlist.lock);
	kvfree(old_rl);
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	err = ntfs_cluster_free_from_rl_transacted(handle, attr_ni->vol,
			free_rl);
	goto out;
out_unlock:
	up_read(&attr_ni->runlist.lock);
out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	kvfree(empty_rl);
	kvfree(free_rl);
out_iput:
	iput(attr_vi);
	return err;
}

int ntfs_attrlist_update_locked(struct ntfs_inode *base_ni,
				struct ntfs_inode *locked_ni)
{
	struct inode *attr_vi;
	struct ntfs_inode *attr_ni;
	unsigned long flags;
	s64 written;
	int err, retry_err;

	/*
	 * generic_shutdown_super() clears SB_ACTIVE before evicting cached
	 * inodes. Do not look up the attribute-list inode after SB_ACTIVE has
	 * been cleared; it may already be I_FREEING, and waiting on it can
	 * self-deadlock.
	 */
	if (!(VFS_I(base_ni)->i_sb->s_flags & SB_ACTIVE))
		return -EIO;

	attr_vi = ntfs_attr_iget(VFS_I(base_ni), AT_ATTRIBUTE_LIST, AT_UNNAMED, 0);
	if (IS_ERR(attr_vi)) {
		err = PTR_ERR(attr_vi);
		return err;
	}
	attr_ni = NTFS_I(attr_vi);
	/* Truncation and page-cache writes can reacquire this runlist lock. */
	if (attr_ni == locked_ni) {
		iput(attr_vi);
		return -ENOSPC;
	}

	err = ntfs_attr_truncate_i_locked(
			attr_ni, base_ni->attr_list_size, HOLES_NO, locked_ni);
	if (err == -ENOSPC && attr_ni->mft_no == FILE_MFT &&
		NInoNonResident(attr_ni)) {
		retry_err = ntfs_attrlist_repack(attr_vi, attr_ni,
					base_ni->attr_list_size, locked_ni);
		if (retry_err) {
			ntfs_error(base_ni->vol->sb, "Failed to repack attribute list");
			iput(attr_vi);
			return retry_err;
		}

		retry_err = ntfs_attr_truncate_i_locked(
				attr_ni, base_ni->attr_list_size,
				HOLES_NO, locked_ni);
		if (retry_err) {
			ntfs_error(base_ni->vol->sb,
				   "Failed to resize attribute list after repack");
			iput(attr_vi);
			return retry_err;
		}
	} else if (err) {
		iput(attr_vi);
		ntfs_error(base_ni->vol->sb,
			   "Failed to truncate attribute list of inode %#llx",
			   (long long)base_ni->mft_no);
		return err;
	}

	/* ntfs_attrlist_repack() below reads the list up to i_size. */
	write_lock_irqsave(&attr_ni->size_lock, flags);
	i_size_write(attr_vi, base_ni->attr_list_size);
	write_unlock_irqrestore(&attr_ni->size_lock, flags);

	/*
	 * Reserve the maximum legal list size while the MFT metadata area is
	 * still easy to allocate contiguously. This prevents a later list entry
	 * from needing another mapping-pairs byte in the full base MFT record.
	 * Failure to obtain the optional reserve must not reject the current
	 * metadata update; the repack retry above remains available if needed.
	 */
	if (base_ni->mft_no == FILE_MFT && NInoNonResident(attr_ni) &&
		attr_ni->allocated_size < NTFS_MAX_ATTR_LIST_SIZE) {
		retry_err = ntfs_attr_expand_locked(
				attr_ni, base_ni->attr_list_size,
				NTFS_MAX_ATTR_LIST_SIZE, locked_ni);
		if (retry_err == -ENOSPC) {
			retry_err = ntfs_attrlist_repack(
					attr_vi, attr_ni,
					NTFS_MAX_ATTR_LIST_SIZE, locked_ni);
			if (retry_err == -ENOSPC)
				retry_err = 0;
		}
		if (retry_err) {
			ntfs_error(base_ni->vol->sb,
				   "Failed to reserve attribute list space");
			iput(attr_vi);
			return retry_err;
		}
	}

	write_lock_irqsave(&attr_ni->size_lock, flags);
	i_size_write(attr_vi, base_ni->attr_list_size);
	write_unlock_irqrestore(&attr_ni->size_lock, flags);

	if (NInoNonResident(attr_ni) && !NInoAttrListNonResident(base_ni))
		NInoSetAttrListNonResident(base_ni);

	written = ntfs_inode_attr_pwrite(attr_vi, 0, base_ni->attr_list_size,
					 base_ni->attr_list, false);
	if (written != base_ni->attr_list_size) {
		err = written < 0 ? (int)written : -EIO;
		iput(attr_vi);
		ntfs_error(base_ni->vol->sb,
			   "Failed to write attribute list of inode %#llx",
			   (long long)base_ni->mft_no);
		return err;
	}

	NInoSetAttrListDirty(base_ni);
	iput(attr_vi);
	return 0;
}

int ntfs_attrlist_update(struct ntfs_inode *base_ni)
{
	return ntfs_attrlist_update_locked(base_ni, NULL);
}

int ntfs_attrlist_extent_log_credits(struct ntfs_volume *vol)
{
	int alloc_credits;
	int attr_credits;
	int credits;

	if (!vol)
		return -EINVAL;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	alloc_credits = ntfs_mft_record_alloc_credits(vol);
	if (alloc_credits < 0)
		return alloc_credits;
	/* Attr-list create, attr-list resize, and new extent attribute create. */
	attr_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, vol->mft_record_size);
	if (attr_credits < 0)
		return attr_credits;
	if (check_mul_overflow(attr_credits, 3, &credits) ||
	    check_add_overflow(credits, alloc_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

/*
 * Bound the number of attributes that can be moved out of one base record.
 *
 * A resident $ATTRIBUTE_LIST can require several moves when the base record
 * is nearly full.  The old mapping-pairs based bound described the size of a
 * single list entry and consequently returned one for normal (4 KiB cluster)
 * volumes.  Use the physical capacity of the MFT record instead: no more
 * than one minimum-sized resident attribute can be removed per iteration.
 * This is deliberately an upper bound. The mover still stops when no
 * eligible attribute remains.
 */
int ntfs_attrlist_base_move_limit(struct ntfs_volume *vol)
{
	u64 usa_bytes;
	u64 attrs_offset;
	u64 attr_bytes;
	u64 max_moves;
	u64 usa_count;
	u32 min_attr_size;

	if (!vol || !vol->mft_record_size)
		return -EINVAL;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	/* Match ntfs_mft_record_layout() for the current volume format. */
	if (vol->major_ver < 3 ||
			(vol->major_ver == 3 && !vol->minor_ver))
		attrs_offset = (sizeof(struct mft_record_old) + 1) & ~1U;
	else
		attrs_offset = (sizeof(struct mft_record) + 1) & ~1U;
	usa_count = vol->mft_record_size >= NTFS_BLOCK_SIZE ?
		vol->mft_record_size / NTFS_BLOCK_SIZE + 1 : 1;
	if (check_mul_overflow(usa_count, (u64)sizeof(__le16), &usa_bytes) ||
		check_add_overflow(attrs_offset, usa_bytes, &attrs_offset))
		return -EOVERFLOW;
	attrs_offset = ALIGN(attrs_offset, 8);
	if (attrs_offset >= vol->mft_record_size ||
			vol->mft_record_size - attrs_offset < 8)
		return -E2BIG;
	attr_bytes = vol->mft_record_size - attrs_offset - 8;
	min_attr_size = ALIGN(offsetof(struct attr_record,
			data.resident.reserved) +
			sizeof(((struct attr_record *)NULL)->
				data.resident.reserved), 8);
	if (!min_attr_size)
		return -EOVERFLOW;
	max_moves = div_u64(attr_bytes, min_attr_size);
	if (!max_moves || max_moves > INT_MAX)
		return -EOVERFLOW;
	return max_moves;
}

int ntfs_attrlist_shrink_log_credits(struct ntfs_volume *vol, u32 max_bytes)
{
	int resident_credits;
	int size_credits;
	int update_credits;
	int credits;

	if (!vol || !max_bytes || max_bytes > 256 * 1024)
		return -EINVAL;
	resident_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, vol->mft_record_size);
	if (resident_credits < 0)
		return resident_credits;
	update_credits = ntfs_log_nonresident_value_prefix_credits(vol,
			max_bytes);
	if (update_credits < 0)
		return update_credits;
	size_credits = ntfs_log_mft_attribute_sizes_credits(vol, false);
	if (size_credits < 0)
		return size_credits;
	if (check_add_overflow(update_credits, size_credits, &credits))
		return -EOVERFLOW;
	/* Shrinking retains the list's allocation and never relocates attributes. */
	return max(resident_credits, credits);
}

int ntfs_attrlist_nonresident_log_credits(struct ntfs_volume *vol)
{
	u64 max_clusters;
	int alloc_credits;
	int attr_credits;
	int conversion_credits;
	int mapping_credits;
	u32 max_entry_size;
	int move_alloc_credits;
	int move_credits;
	int move_limit;
	int move_list_credits;
	int size_credits;
	int tail_credits;
	int update_credits;
	int credits;

	if (!vol)
		return -EINVAL;
	if (vol->mft_record_size <= offsetof(struct attr_record,
			data.resident.reserved) + 1)
		return -E2BIG;
	conversion_credits = ntfs_attr_make_nonresident_log_credits(vol, 0,
			vol->mft_record_size - offsetof(struct attr_record,
				data.resident.reserved) - 1);
	if (conversion_credits < 0)
		return conversion_credits;
	update_credits = ntfs_log_nonresident_value_update_credits(vol,
			256 * 1024, true);
	if (update_credits < 0)
		return update_credits;
	max_entry_size = ALIGN(sizeof(struct attr_list_entry) +
			U8_MAX * sizeof(__le16), 8);
	tail_credits = ntfs_log_nonresident_value_update_credits(vol,
			max_entry_size, false);
	if (tail_credits < 0)
		return tail_credits;
	size_credits = ntfs_log_mft_attribute_sizes_credits(vol, false);
	if (size_credits < 0)
		return size_credits;
	if (!vol->cluster_size)
		return -EINVAL;
	max_clusters = DIV_ROUND_UP_ULL(max_entry_size, vol->cluster_size);
	alloc_credits = ntfs_cluster_alloc_log_credits(max_clusters);
	if (alloc_credits < 0)
		return alloc_credits;
	mapping_credits = ntfs_log_mft_mapping_pairs_credits(vol,
			vol->mft_record_size, vol->mft_record_size);
	if (mapping_credits < 0)
		return mapping_credits;
	/*
	 * Physical list growth may move base-record attributes to newly allocated
	 * extents: create + list reference rewrite + source delete for each move.
	 */
	move_limit = ntfs_attrlist_base_move_limit(vol);
	if (move_limit < 0)
		return move_limit;
	move_alloc_credits = ntfs_mft_record_alloc_credits(vol);
	if (move_alloc_credits < 0)
		return move_alloc_credits;
	attr_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, vol->mft_record_size);
	if (attr_credits < 0)
		return attr_credits;
	if (check_add_overflow(update_credits, size_credits,
			&move_list_credits))
		return -EOVERFLOW;
	move_list_credits = max(move_list_credits, attr_credits);
	if (check_mul_overflow(attr_credits, 2, &move_credits) ||
	    check_add_overflow(move_credits, move_alloc_credits,
			&move_credits) ||
	    check_add_overflow(move_credits, move_list_credits,
			&move_credits) ||
	    check_mul_overflow(move_credits, move_limit, &move_credits))
		return -EOVERFLOW;
	if (check_add_overflow(update_credits, tail_credits, &credits) ||
	    check_add_overflow(credits, size_credits, &credits) ||
	    check_add_overflow(credits, alloc_credits, &credits) ||
	    check_add_overflow(credits, mapping_credits, &credits) ||
	    check_add_overflow(credits, conversion_credits, &credits) ||
	    check_add_overflow(credits, move_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

static int ntfs_attrlist_make_nonresident_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni,
		u32 resident_allocation)
{
	struct ntfs_inode *attr_ni;
	struct inode *attr_vi;
	unsigned long flags;
	int err;

	err = ntfs_attrlist_register_home_undo(handle, base_ni);
	if (err)
		return err;
	attr_vi = ntfs_attr_iget(VFS_I(base_ni), AT_ATTRIBUTE_LIST,
			AT_UNNAMED, 0);
	if (IS_ERR(attr_vi))
		return PTR_ERR(attr_vi);
	attr_ni = NTFS_I(attr_vi);
	if (NInoNonResident(attr_ni)) {
		err = -EIO;
		goto out;
	}
	/* Resident list edits may have outgrown a cached attribute inode. */
	write_lock_irqsave(&attr_ni->size_lock, flags);
	attr_ni->allocated_size = resident_allocation;
	attr_ni->data_size = base_ni->attr_list_size;
	attr_ni->initialized_size = base_ni->attr_list_size;
	attr_ni->zeroed_size = base_ni->attr_list_size;
	i_size_write(attr_vi, base_ni->attr_list_size);
	attr_vi->i_blocks = resident_allocation >> 9;
	write_unlock_irqrestore(&attr_ni->size_lock, flags);
	err = ntfs_attr_make_nonresident_transacted(handle, attr_ni);
	if (err)
		goto out;
	NInoSetAttrListNonResident(base_ni);
	NInoSetAttrListDirty(base_ni);
out:
	iput(attr_vi);
	return err;
}

static int ntfs_attrlist_nonresident_update_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni,
		u8 *new_list, u32 new_size)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct ntfs_inode *attr_ni;
	struct ntfs_volume *vol;
	struct runlist new_runlist;
	struct runlist_element *allocated_rl = NULL;
	struct runlist_element *merged_rl;
	struct runlist_element *old_rl;
	struct runlist_element *rl;
	struct attr_record *attr;
	struct inode *attr_vi;
	struct mft_record *mrec;
	u8 *old_list;
	u64 old_allocated_size;
	u64 new_clusters;
	u64 old_clusters;
	u64 operation_lsn;
	u32 attr_len;
	u32 allocated;
	u32 changed_end;
	u32 changed_start;
	u32 common_size;
	u32 old_size;
	u32 required_attr_len;
	u32 required_free;
	u32 used;
	u32 write_end;
	u16 mapping_off;
	u16 record_off;
	ptrdiff_t record_pos;
	loff_t vfs_size;
	s64 cached_allocated_size;
	s64 cached_data_size;
	s64 cached_initialized_size;
	s64 cached_zeroed_size;
	s64 cluster_count;
	s64 lcn_hint = -1;
	s64 new_allocated_size;
	s64 written;
	size_t allocated_rl_count;
	size_t new_rl_count;
	size_t runlist_bytes;
	unsigned long flags;
	bool physical_grow = false;
	int mapping_size;
	int move_limit;
	int err;

	if (!handle || !base_ni || !new_list || !new_size ||
	    !NInoAttrList(base_ni) || !NInoAttrListNonResident(base_ni) ||
	    !base_ni->attr_list)
		return -EINVAL;
	ntfs_init_runlist(&new_runlist);
	old_size = base_ni->attr_list_size;
	old_list = base_ni->attr_list;
	err = ntfs_attrlist_validate_value(old_list, old_size);
	if (err)
		return err;
	err = ntfs_attrlist_validate_value(new_list, new_size);
	if (err)
		return err;
	if (base_ni->attr_list != old_list ||
	    base_ni->attr_list_size != old_size)
		return -EIO;
	attr_vi = ntfs_attr_iget(VFS_I(base_ni), AT_ATTRIBUTE_LIST,
			AT_UNNAMED, 0);
	if (IS_ERR(attr_vi))
		return PTR_ERR(attr_vi);
	attr_ni = NTFS_I(attr_vi);
	vol = attr_ni->vol;
	read_lock_irqsave(&attr_ni->size_lock, flags);
	cached_allocated_size = attr_ni->allocated_size;
	cached_data_size = attr_ni->data_size;
	cached_initialized_size = attr_ni->initialized_size;
	cached_zeroed_size = attr_ni->zeroed_size;
	vfs_size = i_size_read(attr_vi);
	read_unlock_irqrestore(&attr_ni->size_lock, flags);
	if (!NInoNonResident(attr_ni) || NInoCompressed(attr_ni) ||
	    NInoSparse(attr_ni) || NInoEncrypted(attr_ni) ||
	    cached_allocated_size <= 0 ||
	    !IS_ALIGNED(cached_allocated_size, vol->cluster_size) ||
	    cached_data_size != old_size ||
	    cached_initialized_size != old_size ||
	    cached_zeroed_size != old_size || vfs_size != old_size) {
		err = -EIO;
		goto out_iput;
	}
	err = ntfs_attr_map_whole_runlist(attr_ni);
	if (err)
		goto out_iput;
	down_read(&attr_ni->runlist.lock);
	err = ntfs_attrlist_stream_validate_sizes(attr_vi,
			cached_allocated_size, old_size);
	if (!err)
		err = ntfs_attrlist_stream_validate_runlist(attr_ni->vol,
				attr_ni->runlist.rl, attr_ni->runlist.count,
				attr_ni->runlist.rl_hint, cached_allocated_size);
	up_read(&attr_ni->runlist.lock);
	if (err)
		goto out_iput;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_iput;
	}
	err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || !attr->non_resident || attr->flags ||
	    attr->name_length || attr->data.non_resident.compression_unit ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn)) {
		err = -EIO;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off = le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    !IS_ALIGNED(mapping_off, 8) || mapping_off >= attr_len ||
	    used > allocated || record_pos > used ||
	    attr_len > used - record_pos ||
	    le64_to_cpu(attr->data.non_resident.allocated_size) !=
			cached_allocated_size ||
	    le64_to_cpu(attr->data.non_resident.highest_vcn) !=
			((u64)cached_allocated_size >>
			 vol->cluster_size_bits) - 1 ||
	    le64_to_cpu(attr->data.non_resident.data_size) != old_size ||
	    le64_to_cpu(attr->data.non_resident.initialized_size) != old_size) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	err = ntfs_attrlist_register_home_undo(handle, base_ni);
	if (err)
		goto out;
	err = ntfs_attrlist_stream_register_home_undo(handle, attr_vi,
			old_list, old_size);
	if (err)
		goto out;
	old_allocated_size = cached_allocated_size;
	new_allocated_size = old_allocated_size;
	if (new_size > old_allocated_size) {
		old_clusters = old_allocated_size >> vol->cluster_size_bits;
		new_clusters = DIV_ROUND_UP_ULL(new_size, vol->cluster_size);
		if (!old_clusters || new_clusters <= old_clusters ||
		    new_clusters >
			    ((u64)S64_MAX >> vol->cluster_size_bits)) {
			err = -EOVERFLOW;
			goto out;
		}
		cluster_count = new_clusters - old_clusters;
		down_read(&attr_ni->runlist.lock);
		err = ntfs_attrlist_stream_validate_runlist(vol,
				attr_ni->runlist.rl, attr_ni->runlist.count,
				attr_ni->runlist.rl_hint, old_allocated_size);
		if (!err)
			err = ntfs_attrlist_stream_validate_sizes(attr_vi,
					old_allocated_size, old_size);
		if (!err) {
			rl = &attr_ni->runlist.rl[attr_ni->runlist.count - 2];
			if (check_add_overflow(rl->lcn, rl->length, &lcn_hint))
				err = -EIO;
		}
		up_read(&attr_ni->runlist.lock);
		if (err || lcn_hint < 0)
			goto out;
		allocated_rl = ntfs_cluster_alloc_transacted(handle, vol,
				old_clusters, cluster_count, lcn_hint, DATA_ZONE, true,
				false, false);
		if (IS_ERR(allocated_rl)) {
			err = PTR_ERR(allocated_rl);
			allocated_rl = NULL;
			goto out;
		}
		err = ntfs_attrlist_validate_allocated_runlist(vol, allocated_rl,
				old_clusters, cluster_count, &allocated_rl_count);
		if (!err)
			err = ntfs_cluster_free_from_rl_preflight(vol, allocated_rl);
		if (err)
			goto out;
		down_write(&attr_ni->runlist.lock);
		err = ntfs_attrlist_stream_validate_runlist(vol,
				attr_ni->runlist.rl, attr_ni->runlist.count,
				attr_ni->runlist.rl_hint, old_allocated_size);
		if (!err)
			err = ntfs_attrlist_stream_validate_sizes(attr_vi,
					old_allocated_size, old_size);
		if (err) {
			up_write(&attr_ni->runlist.lock);
			goto out;
		}
		if (check_mul_overflow(attr_ni->runlist.count,
				sizeof(*attr_ni->runlist.rl), &runlist_bytes)) {
			err = -EOVERFLOW;
			up_write(&attr_ni->runlist.lock);
			goto out;
		}
		new_runlist.rl = ntfs_attrlist_kvmemdup(attr_ni->runlist.rl,
				runlist_bytes, GFP_NOFS);
		if (!new_runlist.rl) {
			err = -ENOMEM;
			up_write(&attr_ni->runlist.lock);
			goto out;
		}
		new_runlist.count = attr_ni->runlist.count;
		merged_rl = ntfs_runlists_merge(&new_runlist, allocated_rl,
				allocated_rl_count, &new_rl_count);
		if (IS_ERR(merged_rl)) {
			err = PTR_ERR(merged_rl);
			up_write(&attr_ni->runlist.lock);
			goto out;
		}
		allocated_rl = NULL;
		new_runlist.rl = merged_rl;
		new_runlist.count = new_rl_count;
		mapping_size = ntfs_get_size_for_mapping_pairs(vol, merged_rl,
				0, -1, -1);
		if (mapping_size <= 0 ||
		    check_add_overflow((u32)mapping_off, (u32)mapping_size,
				&required_attr_len)) {
			err = mapping_size < 0 ? mapping_size : -EIO;
			up_write(&attr_ni->runlist.lock);
			goto out;
		}
		required_attr_len = ALIGN(required_attr_len, 8);
		if (required_attr_len > U16_MAX) {
			err = -E2BIG;
			up_write(&attr_ni->runlist.lock);
			goto out;
		}
		required_free = required_attr_len > attr_len ?
			required_attr_len - attr_len : 0;
		if (required_free > allocated - used) {
			/*
			 * Relocation rewrites the current list. Keep its old
			 * allocation visible until those nested updates finish.
			 */
			up_write(&attr_ni->runlist.lock);
			ntfs_attr_put_search_ctx(ctx);
			ctx = NULL;
			move_limit = ntfs_attrlist_base_move_limit(vol);
			if (move_limit < 0) {
				err = move_limit;
				goto out;
			}
			err = ntfs_attr_make_base_record_space_transacted(handle,
					base_ni, required_free, move_limit,
					new_list, new_size);
			if (err)
				goto out;
			old_list = base_ni->attr_list;
			down_write(&attr_ni->runlist.lock);
		}
		new_allocated_size = ntfs_cluster_to_bytes(vol, new_clusters);
		err = ntfs_attrlist_stream_validate_sizes(attr_vi,
				old_allocated_size, old_size);
		if (!err)
			err = ntfs_attrlist_stream_validate_runlist(vol,
				new_runlist.rl, new_runlist.count,
				new_runlist.rl_hint,
				new_allocated_size);
		if (!err)
			err = ntfs_cluster_free_from_rl_preflight(vol,
					new_runlist.rl);
		if (err) {
			up_write(&attr_ni->runlist.lock);
			goto out;
		}
		old_rl = attr_ni->runlist.rl;
		attr_ni->runlist.rl = new_runlist.rl;
		attr_ni->runlist.count = new_runlist.count;
		attr_ni->runlist.rl_hint = -1;
		new_runlist.rl = NULL;
		kvfree(old_rl);
		write_lock_irqsave(&attr_ni->size_lock, flags);
		attr_ni->allocated_size = new_allocated_size;
		attr_vi->i_blocks = new_allocated_size >> 9;
		write_unlock_irqrestore(&attr_ni->size_lock, flags);
		up_write(&attr_ni->runlist.lock);
		physical_grow = true;
	}
	if (base_ni->attr_list != old_list ||
	    base_ni->attr_list_size != old_size) {
		err = -EIO;
		goto out;
	}
	down_read(&attr_ni->runlist.lock);
	err = ntfs_attrlist_stream_validate_sizes(attr_vi,
			new_allocated_size, old_size);
	if (!err)
		err = ntfs_attrlist_stream_validate_runlist(vol,
				attr_ni->runlist.rl, attr_ni->runlist.count,
				attr_ni->runlist.rl_hint, new_allocated_size);
	if (!err)
		err = ntfs_cluster_free_from_rl_preflight(vol,
				attr_ni->runlist.rl);
	up_read(&attr_ni->runlist.lock);
	if (err)
		goto out;

	common_size = min(old_size, new_size);
	ntfs_attrlist_changed_range(old_list, new_list, common_size,
			&changed_start, &changed_end);
	if (changed_start < changed_end) {
		err = ntfs_log_nonresident_value_update(handle, attr_vi,
				changed_start, old_list + changed_start,
				new_list + changed_start,
				changed_end - changed_start, NULL);
		if (err)
			goto out;
	}
	if (new_size > old_size) {
		err = ntfs_log_nonresident_value_update(handle, attr_vi, old_size,
				NULL, new_list + old_size, new_size - old_size, NULL);
		if (err)
			goto out;
	}
	write_end = new_size > old_size ? new_size : changed_end;

	write_lock_irqsave(&attr_ni->size_lock, flags);
	attr_ni->data_size = new_size;
	attr_ni->initialized_size = new_size;
	attr_ni->zeroed_size = new_size;
	i_size_write(attr_vi, new_size);
	write_unlock_irqrestore(&attr_ni->size_lock, flags);
	if (changed_start < write_end) {
		/* The attribute inode's LSN gates buffered metadata writeback. */
		written = ntfs_inode_attr_pwrite_existing(attr_vi, changed_start,
				write_end - changed_start, new_list + changed_start,
				false);
		if (written != write_end - changed_start) {
			err = written < 0 ? written : -EIO;
			goto out;
		}
	}
	down_read(&attr_ni->runlist.lock);
	err = ntfs_attrlist_stream_validate_sizes(attr_vi,
			new_allocated_size, new_size);
	if (!err)
		err = ntfs_attrlist_stream_validate_runlist(vol,
				attr_ni->runlist.rl, attr_ni->runlist.count,
				attr_ni->runlist.rl_hint, new_allocated_size);
	if (!err)
		err = ntfs_cluster_free_from_rl_preflight(vol,
				attr_ni->runlist.rl);
	up_read(&attr_ni->runlist.lock);
	if (err)
		goto out;

	if (physical_grow) {
		if (ctx) {
			ntfs_attr_put_search_ctx(ctx);
			ctx = NULL;
		}
		down_write(&attr_ni->runlist.lock);
		err = ntfs_attr_update_mapping_pairs_transacted(handle, attr_ni);
		up_write(&attr_ni->runlist.lock);
		if (err)
			goto out;
	} else {
		used = le32_to_cpu(mrec->bytes_in_use);
		allocated = le32_to_cpu(mrec->bytes_allocated);
		if (!ctx || ctx->ntfs_ino != base_ni || ctx->attr != attr ||
		    ctx->mrec != mrec || (u8 *)attr - (u8 *)mrec != record_off ||
		    le32_to_cpu(attr->length) != attr_len || used > allocated ||
		    record_off > used || attr_len > used - record_off) {
			err = -EIO;
			goto out;
		}
		old_sizes.alloc_size = attr->data.non_resident.allocated_size;
		old_sizes.valid_size = attr->data.non_resident.initialized_size;
		old_sizes.data_size = attr->data.non_resident.data_size;
		if (le64_to_cpu(old_sizes.alloc_size) != old_allocated_size ||
		    le64_to_cpu(old_sizes.valid_size) != old_size ||
		    le64_to_cpu(old_sizes.data_size) != old_size) {
			err = -EIO;
			goto out;
		}
		new_sizes.alloc_size = old_sizes.alloc_size;
		new_sizes.valid_size = cpu_to_le64(new_size);
		new_sizes.data_size = cpu_to_le64(new_size);
		err = ntfs_log_mft_attribute_sizes_update(handle,
				ctx->ntfs_ino->mft_no, record_off, &old_sizes,
				&new_sizes, false, &operation_lsn);
		if (err)
			goto out;
		attr->data.non_resident.initialized_size = new_sizes.valid_size;
		attr->data.non_resident.data_size = new_sizes.data_size;
		mrec->lsn = cpu_to_le64(operation_lsn);
		mark_mft_record_dirty(ctx->ntfs_ino);
	}
	if (base_ni->attr_list != old_list ||
	    base_ni->attr_list_size != old_size) {
		err = -EIO;
		goto out;
	}
	err = ntfs_attrlist_validate_value(new_list, new_size);
	if (err)
		goto out;
	down_read(&attr_ni->runlist.lock);
	err = ntfs_attrlist_stream_validate_sizes(attr_vi,
			new_allocated_size, new_size);
	if (!err)
		err = ntfs_attrlist_stream_validate_runlist(vol,
				attr_ni->runlist.rl, attr_ni->runlist.count,
				attr_ni->runlist.rl_hint, new_allocated_size);
	if (!err)
		err = ntfs_cluster_free_from_rl_preflight(vol,
				attr_ni->runlist.rl);
	up_read(&attr_ni->runlist.lock);
	if (err)
		goto out;
	base_ni->attr_list = new_list;
	base_ni->attr_list_size = new_size;
	kvfree(old_list);
	NInoSetAttrListDirty(base_ni);
	err = 0;
out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	kvfree(new_runlist.rl);
	kvfree(allocated_rl);
out_iput:
	iput(attr_vi);
	return err;
}

int ntfs_inode_add_attrlist_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	struct mft_record *mrec;
	u32 attr_al_len;
	u32 allocated;
	u32 used;
	u32 required_free;
	int move_limit;
	u8 *list = NULL;
	u32 list_size;
	int err;

	if (!handle || !ni)
		return -EINVAL;
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	if (!ni || NInoAttrList(ni) || ni->nr_extents) {
		if (ni)
			ntfs_error(ni->vol->sb,
				   "Cannot create initial attribute list for inode %llu (attr-list %d, extents %d).",
				   (unsigned long long)ni->mft_no,
				   NInoAttrList(ni), ni->nr_extents);
		return -EOPNOTSUPP;
	}
	err = ntfs_attrlist_build(ni, &list, &list_size);
	if (err) {
		ntfs_error(ni->vol->sb,
			   "Failed to build initial attribute list for inode %llu (error %d).",
			   (unsigned long long)ni->mft_no, err);
		return err;
	}
	err = ntfs_attrlist_register_home_undo(handle, ni);
	if (err) {
		ntfs_error(ni->vol->sb,
			   "Failed to register initial attribute-list undo for inode %llu (error %d).",
			   (unsigned long long)ni->mft_no, err);
		goto out;
	}
	if (check_add_overflow((u32)offsetof(struct attr_record,
			data.resident.reserved), 1U, &attr_al_len) ||
	    check_add_overflow(attr_al_len, ALIGN(list_size, 8),
			&attr_al_len) || attr_al_len > U16_MAX) {
		err = -E2BIG;
		goto out;
	}
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out;
	}
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	unmap_mft_record(ni);
	if (used > allocated || attr_al_len > allocated - used) {
		if (used > allocated) {
			err = -EIO;
			goto out;
		}
		/* There is no old list record, so its full length is the growth. */
		required_free = attr_al_len;
		move_limit = ntfs_attrlist_base_move_limit(ni->vol);
		if (move_limit < 0) {
			ntfs_error(ni->vol->sb,
				   "Failed to calculate initial attribute-list move limit for inode %llu (error %d).",
				   (unsigned long long)ni->mft_no, move_limit);
			err = move_limit;
			goto out;
		}
		err = ntfs_attr_make_base_record_space_initial_transacted(handle,
				ni, required_free, move_limit, list, list_size);
		if (err) {
			ntfs_error(ni->vol->sb,
				   "Failed to make room for initial attribute list on inode %llu (need %u bytes, move limit %d, error %d).",
				   (unsigned long long)ni->mft_no, required_free,
				   move_limit, err);
			goto out;
		}
	}
	err = ntfs_resident_attr_record_add_transacted(handle, ni,
			AT_ATTRIBUTE_LIST, AT_UNNAMED, 0, list, list_size, 0);
	if (err < 0) {
		ntfs_error(ni->vol->sb,
			   "Failed to add initial attribute-list record to inode %llu (error %d).",
			   (unsigned long long)ni->mft_no, err);
		goto out;
	}
	ni->attr_list = list;
	ni->attr_list_size = list_size;
	NInoSetAttrList(ni);
	NInoSetAttrListDirty(ni);
	NInoClearAttrListNonResident(ni);
	return 0;
out:
	kvfree(list);
	return err;
}

static int ntfs_attrlist_entry_prepare(struct ntfs_inode *ni,
		struct attr_record *attr, u8 **new_list_out, u32 *new_size_out)
{
	struct attr_list_entry *ale;
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct mft_record *mrec;
	__le64 mref;
	u8 *new_list;
	u32 entry_offset;
	u32 entry_size;
	u32 new_size;
	int err;

	if (!ni || !attr || !new_list_out || !new_size_out)
		return -EINVAL;
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	mref = MK_LE_MREF(ni->mft_no, le16_to_cpu(mrec->sequence_number));
	unmap_mft_record(ni);
	base_ni = ni->nr_extents == -1 ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni || !NInoAttrList(base_ni) || !base_ni->attr_list)
		return -EOPNOTSUPP;
	entry_size = ALIGN(sizeof(*ale) +
			attr->name_length * sizeof(__le16), 8);
	if (check_add_overflow(base_ni->attr_list_size, entry_size,
			&new_size) || new_size > 256 * 1024)
		return -E2BIG;

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(attr->type,
			attr->name_length ? (__le16 *)((u8 *)attr +
				le16_to_cpu(attr->name_offset)) : AT_UNNAMED,
			attr->name_length, CASE_SENSITIVE,
			attr->non_resident ?
				le64_to_cpu(attr->data.non_resident.lowest_vcn) : 0,
			attr->non_resident ? NULL : (u8 *)attr +
				le16_to_cpu(attr->data.resident.value_offset),
			attr->non_resident ? 0 :
				le32_to_cpu(attr->data.resident.value_length), ctx);
	if (!err) {
		if (ctx->al_entry->lowest_vcn ==
		    (attr->non_resident ?
		     attr->data.non_resident.lowest_vcn : 0)) {
			err = -EEXIST;
			goto out_ctx;
		}
		ale = (struct attr_list_entry *)((u8 *)ctx->al_entry +
				le16_to_cpu(ctx->al_entry->length));
	} else if (err == -ENOENT) {
		ale = ctx->al_entry;
	} else {
		goto out_ctx;
	}
	entry_offset = (u8 *)ale - base_ni->attr_list;
	if (entry_offset > base_ni->attr_list_size) {
		err = -EIO;
		goto out_ctx;
	}
	new_list = kvzalloc(new_size, GFP_NOFS);
	if (!new_list) {
		err = -ENOMEM;
		goto out_ctx;
	}
	memcpy(new_list, base_ni->attr_list, entry_offset);
	memcpy(new_list + entry_offset + entry_size,
			base_ni->attr_list + entry_offset,
			base_ni->attr_list_size - entry_offset);
	ale = (struct attr_list_entry *)(new_list + entry_offset);
	ale->type = attr->type;
	ale->length = cpu_to_le16(entry_size);
	ale->name_length = attr->name_length;
	ale->name_offset = offsetof(struct attr_list_entry, name);
	ale->lowest_vcn = attr->non_resident ?
		attr->data.non_resident.lowest_vcn : 0;
	ale->mft_reference = mref;
	ale->instance = attr->instance;
	if (ale->name_length)
		memcpy(ale->name, (u8 *)attr + le16_to_cpu(attr->name_offset),
				ale->name_length * sizeof(__le16));
	*new_list_out = new_list;
	*new_size_out = new_size;
	err = 0;
out_ctx:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

static int ntfs_attrlist_resident_replace_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni,
		u8 *new_list)
{
	struct ntfs_attr_search_ctx *ctx;
	struct attr_record *list_attr;
	struct mft_record *mrec;
	u8 *old_list;
	u64 operation_lsn;
	u32 attr_len;
	u32 list_size;
	u32 used;
	u16 record_off;
	u16 value_off;
	ptrdiff_t record_pos;
	int err;

	if (!handle || !base_ni || !new_list ||
	    !NInoAttrList(base_ni) || NInoAttrListNonResident(base_ni) ||
	    !base_ni->attr_list || !base_ni->attr_list_size)
		return -EINVAL;
	list_size = base_ni->attr_list_size;
	mrec = map_mft_record(base_ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	ctx = ntfs_attr_get_search_ctx(base_ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}
	err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx);
	if (err)
		goto out_ctx;
	list_attr = ctx->attr;
	if (!list_attr || list_attr->non_resident) {
		err = -EIO;
		goto out_ctx;
	}
	record_pos = (u8 *)list_attr - (u8 *)mrec;
	attr_len = le32_to_cpu(list_attr->length);
	value_off = le16_to_cpu(list_attr->data.resident.value_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || value_off > attr_len ||
	    list_size != le32_to_cpu(list_attr->data.resident.value_length) ||
	    list_size > attr_len - value_off || record_pos > used ||
	    attr_len > used - record_pos ||
	    memcmp((u8 *)list_attr + value_off, base_ni->attr_list,
			list_size)) {
		err = -EIO;
		goto out_ctx;
	}
	record_off = record_pos;
	err = ntfs_attrlist_register_home_undo(handle, base_ni);
	if (err)
		goto out_ctx;
	err = ntfs_log_mft_resident_update(handle, base_ni->mft_no,
			record_off, value_off, base_ni->attr_list, list_size,
			new_list, list_size, &operation_lsn);
	if (err)
		goto out_ctx;
	memcpy((u8 *)list_attr + value_off, new_list, list_size);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(base_ni);
	old_list = base_ni->attr_list;
	base_ni->attr_list = new_list;
	kvfree(old_list);
	NInoSetAttrListDirty(base_ni);
	err = 0;
out_ctx:
	ntfs_attr_put_search_ctx(ctx);
out_unmap:
	unmap_mft_record(base_ni);
	return err;
}

/*
 * Replace the file reference of one list entry without changing list size.
 * @pending_list is an optional not-yet-published resized copy prepared by the
 * caller. Keeping the matching entry in sync prevents a later list publish
 * from resurrecting the old reference.
 */
int ntfs_attrlist_entry_move_transacted(struct ntfs_log_handle *handle,
		struct ntfs_attr_search_ctx *ctx, __le64 mft_reference,
		__le16 instance, u8 *pending_list, u32 pending_size)
{
	struct attr_list_entry *pending_ale = NULL;
	struct attr_list_entry *ale;
	struct ntfs_inode *base_ni;
	u8 *entry_copy = NULL;
	u8 *new_list = NULL;
	u32 entry_len;
	u32 entry_off;
	u32 list_size;
	u32 off;
	int err;

	if (!handle || !ctx || !ctx->ntfs_ino || !ctx->al_entry)
		return -EINVAL;
	base_ni = ctx->base_ntfs_ino ? ctx->base_ntfs_ino : ctx->ntfs_ino;
	if (!NInoAttrList(base_ni) || !base_ni->attr_list)
		return -EOPNOTSUPP;
	ale = ctx->al_entry;
	list_size = base_ni->attr_list_size;
	if ((u8 *)ale < base_ni->attr_list)
		return -EIO;
	entry_off = (u8 *)ale - base_ni->attr_list;
	entry_len = le16_to_cpu(ale->length);
	if (!entry_len || !IS_ALIGNED(entry_len, 8) ||
	    entry_off > list_size || entry_len > list_size - entry_off)
		return -EIO;
	entry_copy = kmemdup(ale, entry_len, GFP_NOFS);
	new_list = ntfs_attrlist_kvmemdup(base_ni->attr_list, list_size,
			GFP_NOFS);
	if (!entry_copy || !new_list) {
		err = -ENOMEM;
		goto out;
	}
	if (pending_list) {
		if (!pending_size) {
			err = -EINVAL;
			goto out;
		}
		for (off = 0; off < pending_size; ) {
			ale = (struct attr_list_entry *)(pending_list + off);
			if (!le16_to_cpu(ale->length) ||
			    !IS_ALIGNED(le16_to_cpu(ale->length), 8) ||
			    le16_to_cpu(ale->length) > pending_size - off) {
				err = -EIO;
				goto out;
			}
			if (le16_to_cpu(ale->length) == entry_len &&
			    !memcmp(ale, entry_copy, entry_len)) {
				if (pending_ale) {
					err = -EIO;
					goto out;
				}
				pending_ale = ale;
			}
			off += le16_to_cpu(ale->length);
		}
		if (off != pending_size || !pending_ale) {
			err = -EIO;
			goto out;
		}
	}
	ale = (struct attr_list_entry *)(new_list + entry_off);
	ale->mft_reference = mft_reference;
	ale->instance = instance;
	if (NInoAttrListNonResident(base_ni))
		err = ntfs_attrlist_nonresident_update_transacted(handle, base_ni,
				new_list, list_size);
	else
		err = ntfs_attrlist_resident_replace_transacted(handle, base_ni,
				new_list);
	if (err)
		goto out;
	new_list = NULL;
	if (pending_ale) {
		pending_ale->mft_reference = mft_reference;
		pending_ale->instance = instance;
	}
out:
	kvfree(new_list);
	kfree(entry_copy);
	return err;
}

/*
 * Update an attribute-list image before the list attribute has been
 * published.  This is used while creating the first list: an attribute may
 * have to move to an extent to make room for the list in the base record.
 */
int ntfs_attrlist_pending_entry_move(const struct attr_record *attr,
		u8 *pending_list, u32 pending_size, __le64 old_mft_reference,
		__le16 old_instance, __le64 new_mft_reference,
		__le16 new_instance)
{
	struct attr_list_entry *ale = NULL;
	const __le16 *attr_name;
	u32 attr_len;
	u16 attr_name_offset;
	u32 off;
	u32 entry_len;
	u32 name_bytes;
	u64 lowest_vcn;
	u32 matches = 0;

	if (!attr || !pending_list || !pending_size)
		return -EINVAL;
	attr_len = le32_to_cpu(attr->length);
	attr_name_offset = le16_to_cpu(attr->name_offset);
	name_bytes = (u32)attr->name_length * sizeof(__le16);
	if (!attr_len || attr_len > U16_MAX || attr_name_offset > attr_len ||
		name_bytes > attr_len - attr_name_offset)
		return -EIO;
	attr_name = attr->name_length ? (const __le16 *)((u8 *)attr +
			attr_name_offset) : AT_UNNAMED;
	lowest_vcn = attr->non_resident ?
		le64_to_cpu(attr->data.non_resident.lowest_vcn) : 0;

	for (off = 0; off < pending_size; ) {
		const __le16 *entry_name;
		u16 entry_name_offset;

		if (pending_size - off < sizeof(*ale))
			return -EIO;
		ale = (struct attr_list_entry *)(pending_list + off);
		entry_len = le16_to_cpu(ale->length);
		entry_name_offset = le16_to_cpu(ale->name_offset);
		name_bytes = (u32)ale->name_length * sizeof(__le16);
		if (entry_len < sizeof(*ale) || !IS_ALIGNED(entry_len, 8) ||
			entry_len > pending_size - off ||
			entry_name_offset > entry_len ||
			name_bytes > entry_len - entry_name_offset)
			return -EIO;
		entry_name = ale->name_length ? (const __le16 *)((u8 *)ale +
				entry_name_offset) : AT_UNNAMED;
		if (ale->mft_reference == old_mft_reference &&
			ale->instance == old_instance && ale->type == attr->type &&
			le64_to_cpu(ale->lowest_vcn) == lowest_vcn &&
			ale->name_length == attr->name_length &&
			(!ale->name_length || !memcmp(entry_name, attr_name,
				ale->name_length * sizeof(__le16)))) {
			if (matches++)
				return -EIO;
			ale->mft_reference = new_mft_reference;
			ale->instance = new_instance;
		}
		off += entry_len;
	}
	if (off != pending_size || matches != 1)
		return -EIO;
	return 0;
}

int ntfs_attrlist_entry_add_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, struct attr_record *attr)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct attr_record *list_attr;
	struct mft_record *mrec;
	u8 *new_list = NULL;
	u8 *old_list;
	u64 operation_lsn;
	u32 attr_len;
	u32 allocated;
	u32 new_attr_len;
	u32 new_size;
	u32 old_size;
	u32 resident_allocation;
	u32 used;
	u32 free_bytes;
	u16 record_off;
	u16 value_off;
	ptrdiff_t record_pos;
	int err;

	if (!handle || !ni || !attr)
		return -EINVAL;
	base_ni = ni->nr_extents == -1 ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni || !NInoAttrList(base_ni))
		return -EOPNOTSUPP;
	err = ntfs_attrlist_entry_prepare(ni, attr, &new_list, &new_size);
	if (err)
		return err;
	if (NInoAttrListNonResident(base_ni)) {
		err = ntfs_attrlist_nonresident_update_transacted(handle, base_ni,
				new_list, new_size);
		if (!err)
			new_list = NULL;
		goto out;
	}
	mrec = map_mft_record(base_ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}
	err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx);
	if (err)
		goto out_ctx;
	list_attr = ctx->attr;
	if (!list_attr || list_attr->non_resident) {
		err = -EOPNOTSUPP;
		goto out_ctx;
	}
	record_pos = (u8 *)list_attr - (u8 *)mrec;
	attr_len = le32_to_cpu(list_attr->length);
	value_off = le16_to_cpu(list_attr->data.resident.value_offset);
	old_size = le32_to_cpu(list_attr->data.resident.value_length);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || value_off > attr_len ||
	    old_size != base_ni->attr_list_size ||
	    old_size > attr_len - value_off || used > allocated ||
	    memcmp((u8 *)list_attr + value_off, base_ni->attr_list,
			old_size)) {
		err = -EIO;
		goto out_ctx;
	}
	new_attr_len = ALIGN(value_off + new_size, 8);
	free_bytes = allocated - used;
	if (new_attr_len > attr_len &&
		new_attr_len - attr_len > free_bytes) {
		resident_allocation = attr_len - value_off;
		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
		unmap_mft_record(base_ni);
		err = ntfs_attrlist_make_nonresident_transacted(handle,
				base_ni, resident_allocation);
		if (err)
			goto out;
		err = ntfs_attrlist_nonresident_update_transacted(handle,
				base_ni, new_list, new_size);
		if (!err)
			new_list = NULL;
		goto out;
	}
	record_off = record_pos;
	err = ntfs_attrlist_register_home_undo(handle, base_ni);
	if (err)
		goto out_ctx;
	err = ntfs_log_mft_resident_update(handle, base_ni->mft_no,
			record_off, value_off, base_ni->attr_list, old_size,
			new_list, new_size, &operation_lsn);
	if (err)
		goto out_ctx;
	err = ntfs_resident_attr_value_resize(mrec, list_attr, new_size);
	if (err)
		goto out_ctx;
	memcpy((u8 *)list_attr + value_off, new_list, new_size);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(base_ni);
	old_list = base_ni->attr_list;
	base_ni->attr_list = new_list;
	base_ni->attr_list_size = new_size;
	new_list = NULL;
	kvfree(old_list);
	NInoSetAttrListDirty(base_ni);
	err = 0;
out_ctx:
	ntfs_attr_put_search_ctx(ctx);
out_unmap:
	unmap_mft_record(base_ni);
out:
	kvfree(new_list);
	return err;
}

int ntfs_attrlist_entry_rm_transacted(struct ntfs_log_handle *handle,
		struct ntfs_attr_search_ctx *ctx)
{
	struct ntfs_inode *base_ni;
	struct attr_list_entry *ale;
	struct ntfs_attr_search_ctx *list_ctx;
	struct attr_record *list_attr;
	struct mft_record *mrec;
	u8 *new_list = NULL;
	u8 *old_list;
	u64 operation_lsn;
	u32 attr_len;
	u32 entry_len;
	u32 entry_off;
	u32 new_size;
	u32 old_size;
	u16 record_off;
	u16 value_off;
	ptrdiff_t record_pos;
	int err;

	if (!handle || !ctx || !ctx->ntfs_ino || !ctx->al_entry)
		return -EINVAL;
	base_ni = ctx->base_ntfs_ino ? ctx->base_ntfs_ino : ctx->ntfs_ino;
	if (!NInoAttrList(base_ni) || !base_ni->attr_list)
		return -EOPNOTSUPP;
	ale = ctx->al_entry;
	if ((u8 *)ale < base_ni->attr_list)
		return -EIO;
	entry_off = (u8 *)ale - base_ni->attr_list;
	entry_len = le16_to_cpu(ale->length);
	old_size = base_ni->attr_list_size;
	if (!entry_len || !IS_ALIGNED(entry_len, 8) || entry_off > old_size ||
	    entry_len > old_size - entry_off)
		return -EIO;
	new_size = old_size - entry_len;
	if (!new_size)
		return -EIO;
	new_list = kvzalloc(new_size, GFP_NOFS);
	if (!new_list)
		return -ENOMEM;
	memcpy(new_list, base_ni->attr_list, entry_off);
	memcpy(new_list + entry_off,
			base_ni->attr_list + entry_off + entry_len,
			new_size - entry_off);
	if (NInoAttrListNonResident(base_ni)) {
		err = ntfs_attrlist_nonresident_update_transacted(handle, base_ni,
				new_list, new_size);
		if (!err)
			new_list = NULL;
		goto out;
	}

	mrec = map_mft_record(base_ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out;
	}
	list_ctx = ntfs_attr_get_search_ctx(base_ni, mrec);
	if (!list_ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}
	err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, CASE_SENSITIVE,
			0, NULL, 0, list_ctx);
	if (err)
		goto out_ctx;
	list_attr = list_ctx->attr;
	if (!list_attr || list_attr->non_resident) {
		err = -EOPNOTSUPP;
		goto out_ctx;
	}
	record_pos = (u8 *)list_attr - (u8 *)mrec;
	attr_len = le32_to_cpu(list_attr->length);
	value_off = le16_to_cpu(list_attr->data.resident.value_offset);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || value_off > attr_len ||
	    old_size != le32_to_cpu(list_attr->data.resident.value_length) ||
	    old_size > attr_len - value_off ||
	    memcmp((u8 *)list_attr + value_off, base_ni->attr_list, old_size)) {
		err = -EIO;
		goto out_ctx;
	}
	record_off = record_pos;
	err = ntfs_attrlist_register_home_undo(handle, base_ni);
	if (err)
		goto out_ctx;
	err = ntfs_log_mft_resident_update(handle, base_ni->mft_no,
			record_off, value_off, base_ni->attr_list, old_size,
			new_list, new_size, &operation_lsn);
	if (err)
		goto out_ctx;
	err = ntfs_resident_attr_value_resize(mrec, list_attr, new_size);
	if (err)
		goto out_ctx;
	memcpy((u8 *)list_attr + value_off, new_list, new_size);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(base_ni);
	old_list = base_ni->attr_list;
	base_ni->attr_list = new_list;
	base_ni->attr_list_size = new_size;
	new_list = NULL;
	kvfree(old_list);
	NInoSetAttrListDirty(base_ni);
	err = 0;
out_ctx:
	ntfs_attr_put_search_ctx(list_ctx);
out_unmap:
	unmap_mft_record(base_ni);
out:
	kvfree(new_list);
	return err;
}

/*
 * ntfs_attrlist_entry_add - add an attribute list attribute entry
 * @ni:	opened ntfs inode, which contains that attribute
 * @attr: attribute record to add to attribute list
 *
 * Return 0 on success and -errno on error.
 */
int ntfs_attrlist_entry_add(struct ntfs_inode *ni, struct attr_record *attr)
{
	struct attr_list_entry *ale;
	__le64 mref;
	struct ntfs_attr_search_ctx *ctx;
	u8 *new_al;
	int entry_len, entry_offset, err;
	struct mft_record *ni_mrec;
	u8 *old_al;
	__le64 lowest_vcn;

	if (!ni || !attr) {
		ntfs_debug("Invalid arguments.\n");
		return -EINVAL;
	}

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x.\n",
			ni->mft_no, (unsigned int) le32_to_cpu(attr->type));

	ni_mrec = map_mft_record(ni);
	if (IS_ERR(ni_mrec)) {
		ntfs_debug("Failed to map mft record.\n");
		return PTR_ERR(ni_mrec);
	}

	mref = MK_LE_MREF(ni->mft_no, le16_to_cpu(ni_mrec->sequence_number));
	unmap_mft_record(ni);

	if (ni->nr_extents == -1)
		ni = ni->ext.base_ntfs_ino;

	if (!NInoAttrList(ni)) {
		ntfs_debug("Attribute list isn't present.\n");
		return -ENOENT;
	}

	/* Determine size and allocate memory for new attribute list. */
	entry_len = (sizeof(struct attr_list_entry) + sizeof(__le16) *
			attr->name_length + 7) & ~7;
	new_al = kvzalloc(ni->attr_list_size + entry_len, GFP_NOFS);
	if (!new_al)
		return -ENOMEM;

	/* Find place for the new entry. */
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		ntfs_error(ni->vol->sb, "Failed to get search context");
		goto err_out;
	}
	if (attr->non_resident)
		lowest_vcn = attr->data.non_resident.lowest_vcn;
	else
		lowest_vcn = 0;

	err = ntfs_attr_lookup(attr->type, (attr->name_length) ? (__le16 *)
			((u8 *)attr + le16_to_cpu(attr->name_offset)) :
			AT_UNNAMED, attr->name_length,
			CASE_SENSITIVE,
			le64_to_cpu(lowest_vcn),
			(attr->non_resident) ? NULL : ((u8 *)attr +
			le16_to_cpu(attr->data.resident.value_offset)), (attr->non_resident) ?
			0 : le32_to_cpu(attr->data.resident.value_length), ctx);
	if (!err) {
		/* Found some extent, check it to be before new extent. */
		if (ctx->al_entry->lowest_vcn == lowest_vcn) {
			err = -EEXIST;
			ntfs_debug("Such attribute already present in the attribute list.\n");
			ntfs_attr_put_search_ctx(ctx);
			goto err_out;
		}
		/* Add new entry after this extent. */
		ale = (struct attr_list_entry *)((u8 *)ctx->al_entry +
				le16_to_cpu(ctx->al_entry->length));
	} else {
		/* Check for real errors. */
		if (err != -ENOENT) {
			ntfs_debug("Attribute lookup failed.\n");
			ntfs_attr_put_search_ctx(ctx);
			goto err_out;
		}
		/* No previous extents found. */
		ale = ctx->al_entry;
	}
	/* Don't need it anymore, @ctx->al_entry points to @ni->attr_list. */
	ntfs_attr_put_search_ctx(ctx);

	/* Determine new entry offset. */
	entry_offset = ((u8 *)ale - ni->attr_list);
	/* Set pointer to new entry. */
	ale = (struct attr_list_entry *)(new_al + entry_offset);
	memset(ale, 0, entry_len);
	/* Form new entry. */
	ale->type = attr->type;
	ale->length = cpu_to_le16(entry_len);
	ale->name_length = attr->name_length;
	ale->name_offset = offsetof(struct attr_list_entry, name);
	if (attr->non_resident)
		ale->lowest_vcn = attr->data.non_resident.lowest_vcn;
	else
		ale->lowest_vcn = 0;
	ale->mft_reference = mref;
	ale->instance = attr->instance;
	memcpy(ale->name, (u8 *)attr + le16_to_cpu(attr->name_offset),
			attr->name_length * sizeof(__le16));

	/* Copy entries from old attribute list to new. */
	memcpy(new_al, ni->attr_list, entry_offset);
	memcpy(new_al + entry_offset + entry_len, ni->attr_list +
			entry_offset, ni->attr_list_size - entry_offset);

	/* Set new runlist. */
	old_al = ni->attr_list;
	ni->attr_list = new_al;
	ni->attr_list_size = ni->attr_list_size + entry_len;

	err = ntfs_attrlist_update(ni);
	if (err) {
		ni->attr_list = old_al;
		ni->attr_list_size -= entry_len;
		goto err_out;
	}
	kvfree(old_al);
	return 0;
err_out:
	kvfree(new_al);
	return err;
}

/*
 * ntfs_attrlist_entry_rm - remove an attribute list attribute entry
 * @ctx:	attribute search context describing the attribute list entry
 *
 * Remove the attribute list entry @ctx->al_entry from the attribute list.
 *
 * Return 0 on success and -errno on error.
 */
int ntfs_attrlist_entry_rm(struct ntfs_attr_search_ctx *ctx)
{
	u8 *new_al;
	int new_al_len;
	struct ntfs_inode *base_ni;
	struct attr_list_entry *ale;

	if (!ctx || !ctx->ntfs_ino || !ctx->al_entry) {
		ntfs_debug("Invalid arguments.\n");
		return -EINVAL;
	}

	if (ctx->base_ntfs_ino)
		base_ni = ctx->base_ntfs_ino;
	else
		base_ni = ctx->ntfs_ino;
	ale = ctx->al_entry;

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x, lowest_vcn %lld.\n",
			(long long)ctx->ntfs_ino->mft_no,
			(unsigned int)le32_to_cpu(ctx->al_entry->type),
			(long long)le64_to_cpu(ctx->al_entry->lowest_vcn));

	if (!NInoAttrList(base_ni)) {
		ntfs_debug("Attribute list isn't present.\n");
		return -ENOENT;
	}

	/* Allocate memory for new attribute list. */
	new_al_len = base_ni->attr_list_size - le16_to_cpu(ale->length);
	new_al = kvzalloc(new_al_len, GFP_NOFS);
	if (!new_al)
		return -ENOMEM;

	/* Copy entries from old attribute list to new. */
	memcpy(new_al, base_ni->attr_list, (u8 *)ale - base_ni->attr_list);
	memcpy(new_al + ((u8 *)ale - base_ni->attr_list), (u8 *)ale + le16_to_cpu(
				ale->length), new_al_len - ((u8 *)ale - base_ni->attr_list));

	/* Set new runlist. */
	kvfree(base_ni->attr_list);
	base_ni->attr_list = new_al;
	base_ni->attr_list_size = new_al_len;

	return ntfs_attrlist_update(base_ni);
}
