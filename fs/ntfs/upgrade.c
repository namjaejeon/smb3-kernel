// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Synchronous NTFS 1.2 -> 3.0 conversion, before exposing the mount to I/O.
 *
 * Copyright (c) 2026 LG Electronics Co., Ltd.
 *
 * Keep the old per-file security descriptors and 48-byte standard information
 * attributes. NTFS 3.0 accepts both. Windows can migrate them lazily. Using
 * 3.0 also avoids relocating the USA and attributes in every MFT record, which
 * would be necessary for a conversion to the NTFS 3.1 record header.
 */

#include <linux/blkdev.h>
#include <linux/sched/signal.h>
#include <linux/unaligned.h>

#include "ntfs.h"
#include "attrib.h"
#include "bitmap.h"
#include "index.h"
#include "logfile.h"
#include "mft.h"
#include "time.h"
#include "upgrade.h"

#define UPGRADE_SECURITY_ID	0x100
#define SDS_BLOCK_SIZE		0x40000

struct upgrade_security_header {
	__le32 hash;
	__le32 security_id;
	__le64 offset;
	__le32 length;
} __packed;

enum upgrade_file {
	UPGRADE_SECURE,
	UPGRADE_EXTEND,
	UPGRADE_QUOTA,
	UPGRADE_OBJID,
	UPGRADE_REPARSE,
};

static const char * const upgrade_names[] = {
	"$Secure", "$Extend", "$Quota", "$ObjId", "$Reparse",
};

struct ntfs_upgrade {
	struct ntfs_volume *vol;
	struct ntfs_volume *target;
	struct ntfs_inode *slot[2];
	struct inode *secure;
	struct inode *extend;
	u8 *bitmap;
	u8 *pairs;
	u8 *sds;
	struct attr_def *attrdef;
	u64 nr_records;
	u32 sds_len;
	__le64 root_ref;
	__le64 now;
	bool prepared;
};

static unsigned int upgrade_unicode(__le16 *dst, const char *src)
{
	unsigned int len = 0;

	while (src[len]) {
		dst[len] = cpu_to_le16(src[len]);
		len++;
	}
	return len;
}

static bool upgrade_name_equal(const __le16 *name, unsigned int len,
			       const char *s)
{
	unsigned int i;

	if (len != strlen(s))
		return false;
	for (i = 0; i < len; i++) {
		if (name[i] != cpu_to_le16(s[i]))
			return false;
	}
	return true;
}

/* Only use this on a record whose attributes have already been checked. */
static struct attr_record *upgrade_find_attr(struct mft_record *m, __le32 type,
					     const char *name)
{
	struct attr_record *a = (void *)m + le16_to_cpu(m->attrs_offset);

	for (; a->type != AT_END; a = (void *)a + le32_to_cpu(a->length)) {
		if (a->type == type &&
		    upgrade_name_equal((void *)a + le16_to_cpu(a->name_offset),
				       a->name_length, name))
			return a;
	}
	return NULL;
}

static void *upgrade_value(struct attr_record *a)
{
	return (void *)a + le16_to_cpu(a->data.resident.value_offset);
}

/* Detached record mappings do not instantiate old reserved/system inodes. */
static struct ntfs_inode *upgrade_map_record(struct ntfs_volume *vol, u64 nr)
{
	struct ntfs_inode *ni;
	struct mft_record *m;

	ni = ntfs_new_extent_inode(vol->sb, nr);
	if (!ni)
		return ERR_PTR(-ENOMEM);
	ni->nr_extents = -1;
	ni->ext.base_ntfs_ino = NTFS_I(vol->mft_ino);
	m = map_mft_record(ni);
	if (IS_ERR(m)) {
		ntfs_clear_extent_inode(ni);
		return ERR_CAST(m);
	}
	return ni;
}

static void upgrade_unmap_record(struct ntfs_inode *ni)
{
	if (!ni || IS_ERR(ni))
		return;
	unmap_mft_record(ni);
	ntfs_clear_extent_inode(ni);
}

static int upgrade_write_record(struct ntfs_inode *ni)
{
	struct ntfs_inode *mft_ni = NTFS_I(ni->vol->mft_ino);
	int err;

	down_read(&mft_ni->runlist.lock);
	err = ntfs_get_block_mft_record(mft_ni, ni);
	up_read(&mft_ni->runlist.lock);
	if (err)
		return err;
	NInoSetDirty(ni);
	err = write_mft_record(ni, ni->mrec, 1);
	/* write_mft_record() redirties and hides ENOMEM for normal writeback. */
	if (!err && NInoDirty(ni))
		err = -ENOMEM;
	return err;
}

/* Bounds checking here is also required for unused reserved records. */
static int upgrade_check_record(struct ntfs_upgrade *u, struct ntfs_inode *ni)
{
	struct mft_record *m = ni->mrec;
	u32 pos = le16_to_cpu(m->attrs_offset);
	u32 used = le32_to_cpu(m->bytes_in_use);
	struct attr_record *a;
	u32 len, head, ofs, size, name_end;

	if (pos < sizeof(struct mft_record_old) ||
	    le16_to_cpu(m->usa_ofs) < sizeof(struct mft_record_old) ||
	    le16_to_cpu(m->usa_ofs) + 2 * le16_to_cpu(m->usa_count) > pos)
		return -EIO;
	while (pos <= used && used - pos >= sizeof(a->type)) {
		a = (void *)m + pos;
		if (a->type == AT_END)
			return used - pos >= 8 ? 0 : -EIO;
		if (used - pos < offsetof(struct attr_record, data))
			return -EIO;
		len = le32_to_cpu(a->length);
		head = a->non_resident ?
			offsetof(struct attr_record, data.non_resident.compressed_size) :
			offsetof(struct attr_record, data.resident.reserved) + 1;
		if (a->non_resident &&
		    (a->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_SPARSE)))
			head += sizeof(a->data.non_resident.compressed_size);
		if (a->non_resident > 1 || len < head || (len & 7) || len > used - pos)
			return -EIO;
		name_end = head;
		if (a->name_length) {
			ofs = le16_to_cpu(a->name_offset);
			size = a->name_length * sizeof(__le16);
			if (ofs < head || (ofs & 1) || ofs > len || size > len - ofs)
				return -EIO;
			name_end = ofs + size;
		}
		if (a->non_resident) {
			ofs = le16_to_cpu(a->data.non_resident.mapping_pairs_offset);
			if (ofs < name_end || ofs >= len ||
			    (s64)le64_to_cpu(a->data.non_resident.lowest_vcn) < 0 ||
			    (s64)le64_to_cpu(a->data.non_resident.allocated_size) < 0 ||
			    (s64)le64_to_cpu(a->data.non_resident.data_size) < 0 ||
			    (s64)le64_to_cpu(a->data.non_resident.initialized_size) < 0)
				return -EIO;
		} else {
			ofs = le16_to_cpu(a->data.resident.value_offset);
			size = le32_to_cpu(a->data.resident.value_length);
			if (ofs < name_end || ofs > len || size > len - ofs)
				return -EIO;
			if (a->type == AT_STANDARD_INFORMATION && size != 48 &&
			    size != sizeof(struct standard_information))
				return -EIO;
			if (a->type == AT_FILE_NAME) {
				struct file_name_attr *fn = upgrade_value(a);

				if (size < sizeof(*fn) ||
				    fn->file_name_length * sizeof(__le16) > size - sizeof(*fn))
					return -EIO;
			}
			if (a->type == AT_INDEX_ROOT) {
				struct index_root *ir = upgrade_value(a);

				if (size < sizeof(*ir) ||
				    ntfs_index_root_inconsistent(u->vol, a, ir, ni->mft_no))
					return -EIO;
			}
		}
		pos += len;
	}
	return -EIO;
}

/* Change old hole encodings without altering ordinary mappings or file data. */
static int upgrade_mapping_pairs(struct ntfs_upgrade *u, struct ntfs_inode *ni)
{
	struct mft_record *m = ni->mrec;
	struct attr_record *a = (void *)m + le16_to_cpu(m->attrs_offset);
	bool changed = false;
	int err;

	for (; a->type != AT_END; a = (void *)a + le32_to_cpu(a->length)) {
		struct runlist_element *rl;
		size_t count, i;
		bool has_holes = false;
		u32 ofs, len;
		s64 first, last;

		if (!a->non_resident)
			continue;
		rl = ntfs_mapping_pairs_decompress(u->vol, a, NULL, &count);
		if (IS_ERR(rl))
			return PTR_ERR(rl);
		for (i = 0; i < count && rl[i].length; i++) {
			if (rl[i].lcn == LCN_HOLE) {
				has_holes = true;
				break;
			}
		}
		if (!has_holes) {
			kvfree(rl);
			continue;
		}
		if (!(a->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_SPARSE)) &&
		    ni->mft_no != FILE_BadClus) {
			kvfree(rl);
			return -EOPNOTSUPP;
		}
		ofs = le16_to_cpu(a->data.non_resident.mapping_pairs_offset);
		len = le32_to_cpu(a->length) - ofs;
		first = le64_to_cpu(a->data.non_resident.lowest_vcn);
		last = le64_to_cpu(a->data.non_resident.highest_vcn);
		memset(u->pairs, 0, len);
		err = ntfs_mapping_pairs_build(u->target, (s8 *)u->pairs, len, rl,
					       first, last, NULL, NULL, NULL);
		kvfree(rl);
		if (err)
			return err;
		if (!memcmp((void *)a + ofs, u->pairs, len))
			continue;
		memcpy((void *)a + ofs, u->pairs, len);
		changed = true;
	}
	return changed;
}

static int upgrade_walk_mft(struct ntfs_upgrade *u, bool write)
{
	u64 nr;
	int err = 0;

	for (nr = 0; nr < u->nr_records; nr++) {
		struct ntfs_inode *ni;
		struct mft_record *m;
		struct attr_record *a;

		if (!(u->bitmap[nr >> 3] & BIT(nr & 7)))
			continue;
		if (write && (nr == FILE_Secure || nr == FILE_Extend))
			continue;
		if (!write && fatal_signal_pending(current))
			return -EINTR;
		ni = upgrade_map_record(u->vol, nr);
		if (IS_ERR(ni))
			return PTR_ERR(ni);
		m = ni->mrec;
		if (!(m->flags & MFT_RECORD_IN_USE)) {
			err = -EIO;
			goto put;
		}
		err = upgrade_check_record(u, ni);
		if (err)
			goto put;
		if (!write && !u->prepared) {
			for (a = (void *)m + le16_to_cpu(m->attrs_offset);
			     a->type != AT_END; a = (void *)a + le32_to_cpu(a->length)) {
				/* 0x40 and 0xc0 had different meanings before NTFS 3.0. */
				if (a->type == AT_OBJECT_ID || a->type == AT_REPARSE_POINT ||
				    le32_to_cpu(a->type) > le32_to_cpu(AT_EA)) {
					err = -EOPNOTSUPP;
					goto put;
				}
				if (a->type == AT_STANDARD_INFORMATION &&
				    (a->non_resident ||
				     le32_to_cpu(a->data.resident.value_length) != 48 ||
				     memchr_inv((u8 *)upgrade_value(a) + 36, 0, 12))) {
					err = -EOPNOTSUPP;
					goto put;
				}
			}
		}
		err = upgrade_mapping_pairs(u, ni);
		if (err > 0) {
			u64 base = m->base_mft_record ? MREF_LE(m->base_mft_record) : nr;
			struct ntfs_attr na = { .mft_no = base, .type = AT_UNUSED };
			struct inode *cached;

			/* Do not replace a record behind an already loaded runlist. */
			cached = ilookup5(u->vol->sb, base, ntfs_test_inode, &na);
			if (cached) {
				iput(cached);
				err = -EOPNOTSUPP;
			} else if (write) {
				err = upgrade_write_record(ni);
			} else {
				err = 0;
			}
		}
put:
		upgrade_unmap_record(ni);
		if (err) {
			if (!write && err == -EOPNOTSUPP)
				ntfs_warning(u->vol->sb,
					     "Cannot upgrade MFT record %llu (%d).", nr, err);
			else
				ntfs_error(u->vol->sb,
					   "Cannot upgrade MFT record %llu (%d).", nr, err);
			return err;
		}
		cond_resched();
	}
	return 0;
}

static u64 upgrade_lookup(struct inode *dir, const char *name)
{
	__le16 uname[8];
	struct ntfs_name *res = NULL;
	struct ntfs_inode *ni = NTFS_I(dir);
	u64 ref;

	mutex_lock(&ni->mrec_lock);
	ref = ntfs_lookup_inode_by_name(ni, uname, upgrade_unicode(uname, name), &res);
	mutex_unlock(&ni->mrec_lock);
	kfree(res);
	return ref;
}

static bool upgrade_record_named(struct mft_record *m, const char *name)
{
	struct attr_record *a = upgrade_find_attr(m, AT_FILE_NAME, "");
	struct file_name_attr *fn;

	if (!a || a->non_resident)
		return false;
	fn = upgrade_value(a);
	return upgrade_name_equal(fn->file_name, fn->file_name_length, name);
}

static int upgrade_check_slot(struct ntfs_upgrade *u, unsigned int slot)
{
	struct mft_record *m = u->slot[slot]->mrec;
	struct attr_record *a = (void *)m + le16_to_cpu(m->attrs_offset);
	unsigned int names = 0;

	if (m->base_mft_record || (m->flags & MFT_RECORD_IS_DIRECTORY))
		return -EOPNOTSUPP;
	/* An unused reserved record may retain attributes from an old file. */
	if (slot && !(m->flags & MFT_RECORD_IN_USE))
		return m->link_count ? -EOPNOTSUPP : 0;
	for (; a->type != AT_END; a = (void *)a + le32_to_cpu(a->length)) {
		if (!a->non_resident &&
		    (a->type == AT_STANDARD_INFORMATION || a->type == AT_SECURITY_DESCRIPTOR))
			continue;
		if (a->type == AT_DATA && !a->non_resident && !a->name_length &&
		    !a->data.resident.value_length)
			continue;
		if (!slot && a->type == AT_FILE_NAME &&
		    upgrade_record_named(m, "$Quota")) {
			struct file_name_attr *fn = upgrade_value(a);
			u64 ref = upgrade_lookup(u->vol->root_ino, "$Quota");

			if (fn->parent_directory != u->root_ref || IS_ERR_MREF(ref) ||
			    ref != MK_MREF(FILE_Secure, le16_to_cpu(m->sequence_number)))
				return -EIO;
			names++;
			continue;
		}
		/* Never discard a populated old $Quota or a reserved extent. */
		return -EOPNOTSUPP;
	}
	if (names > 1 || le16_to_cpu(m->link_count) != names)
		return -EOPNOTSUPP;
	return 0;
}

static int upgrade_check_index(struct ntfs_upgrade *u, struct inode *vi,
			       const char *name, __le32 type, __le32 rule)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	struct mft_record *m;
	struct attr_record *a;
	struct index_root *ir;
	int err;

	m = map_mft_record(ni);
	if (IS_ERR(m))
		return PTR_ERR(m);
	err = upgrade_check_record(u, ni);
	if (err)
		goto out;
	a = upgrade_find_attr(m, AT_INDEX_ROOT, name);
	if (!a || a->non_resident) {
		err = -EIO;
		goto out;
	}
	ir = upgrade_value(a);
	err = ir->type == type && ir->collation_rule == rule ? 0 : -EIO;
out:
	unmap_mft_record(ni);
	return err;
}

static int upgrade_check_prepared(struct ntfs_upgrade *u)
{
	static const char * const indexes[] = { "$Q", "$O", "$R" };
	static const __le32 rules[] = {
		COLLATION_NTOFS_ULONG, COLLATION_NTOFS_ULONGS, COLLATION_NTOFS_ULONGS,
	};
	struct inode *vi;
	struct mft_record *m = u->slot[0]->mrec;
	unsigned int i;
	unsigned int count = u->vol->attrdef_size / sizeof(struct attr_def);
	unsigned int found = 0;
	u64 ref;
	int err;

	/* A new system-file layout cannot use the old attribute type meanings. */
	for (i = 0; i < count; i++) {
		struct attr_def *ad = &u->vol->attrdef[i];
		const char *name;

		if (ad->type == AT_OBJECT_ID) {
			name = "$OBJECT_ID";
			found |= 1;
		} else if (ad->type == AT_REPARSE_POINT) {
			name = "$REPARSE_POINT";
			found |= 2;
		} else {
			continue;
		}
		if (!upgrade_name_equal(ad->name, strlen(name), name) ||
		    ad->name[strlen(name)])
			return -EOPNOTSUPP;
	}
	if (found != 3)
		return -EOPNOTSUPP;
	err = ntfs_attr_size_bounds_check(u->vol, AT_STANDARD_INFORMATION, 72);
	if (err)
		return err;
	if (!upgrade_find_attr(m, AT_DATA, "$SDS"))
		return -EIO;
	u->secure = ntfs_iget(u->vol->sb, FILE_Secure);
	if (IS_ERR(u->secure))
		return PTR_ERR(u->secure);
	u->extend = ntfs_iget(u->vol->sb, FILE_Extend);
	if (IS_ERR(u->extend))
		return PTR_ERR(u->extend);
	ref = upgrade_lookup(u->vol->root_ino, "$Secure");
	if (IS_ERR_MREF(ref) || ref != MK_MREF(FILE_Secure, NTFS_I(u->secure)->seq_no))
		return -EIO;
	ref = upgrade_lookup(u->vol->root_ino, "$Extend");
	if (IS_ERR_MREF(ref) || ref != MK_MREF(FILE_Extend, NTFS_I(u->extend)->seq_no))
		return -EIO;
	err = upgrade_check_index(u, u->secure, "$SDH", AT_UNUSED,
				  COLLATION_NTOFS_SECURITY_HASH);
	if (!err)
		err = upgrade_check_index(u, u->secure, "$SII", AT_UNUSED, COLLATION_NTOFS_ULONG);
	if (!err)
		err = upgrade_check_index(u, u->extend, "$I30", AT_FILE_NAME, COLLATION_FILE_NAME);
	if (err)
		return err;
	for (i = 0; i < ARRAY_SIZE(indexes); i++) {
		ref = upgrade_lookup(u->extend, upgrade_names[UPGRADE_QUOTA + i]);
		if (IS_ERR_MREF(ref))
			return MREF_ERR(ref);
		vi = ntfs_iget(u->vol->sb, MREF(ref));
		if (IS_ERR(vi))
			return PTR_ERR(vi);
		err = MSEQNO(ref) == NTFS_I(vi)->seq_no ?
			upgrade_check_index(u, vi, indexes[i], AT_UNUSED, rules[i]) : -EIO;
		if (!err && !i)
			err = upgrade_check_index(u, vi, "$O", AT_UNUSED, COLLATION_NTOFS_SID);
		iput(vi);
		if (err)
			return err;
	}
	return 0;
}

/* Append a resident attribute to a newly laid out, private record buffer. */
static int upgrade_add_attr(struct mft_record *m, __le32 type, const char *name,
			    const void *value, u32 size)
{
	u32 pos = le32_to_cpu(m->bytes_in_use) - 8;
	u32 name_len = strlen(name);
	u32 value_ofs = ALIGN(24 + name_len * sizeof(__le16), 8);
	u32 len = ALIGN(value_ofs + size, 8);
	struct attr_record *a;

	if (len + 8 > le32_to_cpu(m->bytes_allocated) - pos)
		return -ENOSPC;
	a = (void *)m + pos;
	memset(a, 0, len + 8);
	a->type = type;
	a->length = cpu_to_le32(len);
	a->name_length = name_len;
	a->name_offset = cpu_to_le16(24);
	a->instance = m->next_attr_instance;
	m->next_attr_instance = cpu_to_le16(le16_to_cpu(m->next_attr_instance) + 1);
	a->data.resident.value_offset = cpu_to_le16(value_ofs);
	a->data.resident.value_length = cpu_to_le32(size);
	a->data.resident.flags = type == AT_FILE_NAME ? RESIDENT_ATTR_IS_INDEXED : 0;
	upgrade_unicode((void *)a + 24, name);
	if (size)
		memcpy((void *)a + value_ofs, value, size);
	((struct attr_record *)((void *)a + len))->type = AT_END;
	m->bytes_in_use = cpu_to_le32(pos + len + 8);
	return 0;
}

static int upgrade_add_index(struct ntfs_upgrade *u, struct mft_record *m,
			     const char *name, __le32 type, __le32 rule,
			     const void *entry, u32 entry_len)
{
	struct index_root *ir;
	struct index_entry_header *end;
	u32 size = sizeof(*ir) + entry_len + sizeof(*end);
	int err;

	ir = kzalloc(size, GFP_NOFS);
	if (!ir)
		return -ENOMEM;
	ir->type = type;
	ir->collation_rule = rule;
	ir->index_block_size = cpu_to_le32(u->vol->index_record_size);
	ir->clusters_per_index_block = u->vol->cluster_size <= u->vol->index_record_size ?
		u->vol->index_record_size >> u->vol->cluster_size_bits :
		u->vol->index_record_size >> NTFS_BLOCK_SIZE_BITS;
	ir->index.entries_offset = cpu_to_le32(sizeof(struct index_header));
	ir->index.index_length = cpu_to_le32(size - offsetof(struct index_root, index));
	ir->index.allocated_size = ir->index.index_length;
	if (entry_len)
		memcpy((void *)(ir + 1), entry, entry_len);
	end = (void *)(ir + 1) + entry_len;
	end->length = cpu_to_le16(sizeof(*end));
	end->flags = INDEX_ENTRY_END;
	err = upgrade_add_attr(m, AT_INDEX_ROOT, name, ir, size);
	kfree(ir);
	return err;
}

static int upgrade_security_indexes(struct ntfs_upgrade *u, struct mft_record *m)
{
	struct upgrade_security_header *header = (void *)u->sds;
	u8 entry[48] = {};
	struct index_entry_header *ie = (void *)entry;
	struct sdh_index_key *key = (void *)(ie + 1);
	int err;

	ie->data.vi.data_offset = cpu_to_le16(24);
	ie->data.vi.data_length = cpu_to_le16(sizeof(*header));
	ie->length = cpu_to_le16(sizeof(entry));
	ie->key_length = cpu_to_le16(sizeof(*key));
	key->hash = header->hash;
	key->security_id = header->security_id;
	memcpy(entry + 24, header, sizeof(*header));
	err = upgrade_add_index(u, m, "$SDH", AT_UNUSED, COLLATION_NTOFS_SECURITY_HASH,
				entry, sizeof(entry));
	if (err)
		return err;
	memset(entry, 0, sizeof(entry));
	ie->data.vi.data_offset = cpu_to_le16(20);
	ie->data.vi.data_length = cpu_to_le16(sizeof(*header));
	ie->length = cpu_to_le16(40);
	ie->key_length = cpu_to_le16(sizeof(__le32));
	memcpy(entry + 16, &header->security_id, sizeof(__le32));
	memcpy(entry + 20, header, sizeof(*header));
	return upgrade_add_index(u, m, "$SII", AT_UNUSED, COLLATION_NTOFS_ULONG, entry, 40);
}

static int upgrade_quota_indexes(struct ntfs_upgrade *u, struct mft_record *m)
{
	u8 entry[72] = {};
	struct index_entry_header *ie = (void *)entry;
	struct quota_control_entry *q = (void *)(entry + 20);
	__le32 key = QUOTA_DEFAULTS_ID;
	int err;

	ie->data.vi.data_offset = cpu_to_le16(20);
	ie->data.vi.data_length = cpu_to_le16(48);
	ie->length = cpu_to_le16(sizeof(entry));
	ie->key_length = cpu_to_le16(sizeof(key));
	memcpy(entry + 16, &key, sizeof(key));
	q->version = cpu_to_le32(QUOTA_VERSION);
	q->flags = QUOTA_FLAG_DEFAULT_LIMITS | QUOTA_FLAG_OUT_OF_DATE;
	q->change_time = u->now;
	q->threshold = cpu_to_le64(-1);
	q->limit = cpu_to_le64(-1);
	err = upgrade_add_index(u, m, "$O", AT_UNUSED, COLLATION_NTOFS_SID, NULL, 0);
	if (!err)
		err = upgrade_add_index(u, m, "$Q", AT_UNUSED, COLLATION_NTOFS_ULONG,
					entry, sizeof(entry));
	return err;
}

static int upgrade_build_record(struct ntfs_upgrade *u, struct ntfs_inode *ni,
				enum upgrade_file file, __le64 parent)
{
	struct mft_record *m = ni->mrec;
	struct standard_information si = {};
	u8 name[sizeof(struct file_name_attr) + 8 * sizeof(__le16)] = {};
	struct file_name_attr *fn = (void *)name;
	__le16 seq = m->sequence_number;
	__le32 flags = FILE_ATTR_SYSTEM | FILE_ATTR_HIDDEN;
	int err;

	err = ntfs_mft_record_layout(u->target, ni->mft_no, m);
	if (err)
		return err;
	/* Windows and other drivers use fixed references for system slots. */
	m->sequence_number = file <= UPGRADE_EXTEND ? cpu_to_le16(ni->mft_no) : seq;
	m->flags = MFT_RECORD_IN_USE;
	m->link_count = cpu_to_le16(1);
	if (file == UPGRADE_EXTEND) {
		m->flags |= MFT_RECORD_IS_DIRECTORY;
		flags |= FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT;
	} else {
		m->flags |= MFT_RECORD_IS_VIEW_INDEX;
		flags |= FILE_ATTR_DUP_VIEW_INDEX_PRESENT;
		if (file >= UPGRADE_QUOTA) {
			m->flags |= MFT_RECORD_IS_4;
			flags |= FILE_ATTR_ARCHIVE;
		}
	}
	si.creation_time = u->now;
	si.last_data_change_time = u->now;
	si.last_mft_change_time = u->now;
	si.last_access_time = u->now;
	si.file_attributes = flags;
	si.ver.v3.security_id = cpu_to_le32(UPGRADE_SECURITY_ID);
	err = upgrade_add_attr(m, AT_STANDARD_INFORMATION, "", &si, sizeof(si));
	if (err)
		return err;
	fn->parent_directory = parent;
	fn->creation_time = u->now;
	fn->last_data_change_time = u->now;
	fn->last_mft_change_time = u->now;
	fn->last_access_time = u->now;
	fn->file_attributes = flags;
	fn->file_name_type = FILE_NAME_WIN32_AND_DOS;
	fn->file_name_length = upgrade_unicode(fn->file_name, upgrade_names[file]);
	err = upgrade_add_attr(m, AT_FILE_NAME, "", fn,
			       sizeof(*fn) + fn->file_name_length * sizeof(__le16));
	if (err)
		return err;
	switch (file) {
	case UPGRADE_SECURE:
		err = upgrade_add_attr(m, AT_DATA, "$SDS", NULL, 0);
		if (!err)
			err = upgrade_security_indexes(u, m);
		break;
	case UPGRADE_EXTEND:
		err = upgrade_add_index(u, m, "$I30", AT_FILE_NAME, COLLATION_FILE_NAME, NULL, 0);
		break;
	case UPGRADE_QUOTA:
		err = upgrade_quota_indexes(u, m);
		break;
	case UPGRADE_OBJID:
		err = upgrade_add_index(u, m, "$O", AT_UNUSED, COLLATION_NTOFS_ULONGS, NULL, 0);
		break;
	case UPGRADE_REPARSE:
		err = upgrade_add_index(u, m, "$R", AT_UNUSED, COLLATION_NTOFS_ULONGS, NULL, 0);
		break;
	}
	return err;
}

static int upgrade_link(struct inode *dir, struct ntfs_inode *ni)
{
	struct mft_record *m = ni->mrec;
	struct attr_record *a = upgrade_find_attr(m, AT_FILE_NAME, "");
	int err;

	mutex_lock(&NTFS_I(dir)->mrec_lock);
	err = ntfs_index_add_filename(NTFS_I(dir), upgrade_value(a),
				      MK_MREF(ni->mft_no, le16_to_cpu(m->sequence_number)));
	mutex_unlock(&NTFS_I(dir)->mrec_lock);
	return err;
}

static int upgrade_create_child(struct ntfs_upgrade *u, enum upgrade_file file)
{
	struct inode *vi = new_inode(u->vol->sb);
	struct ntfs_inode *ni;
	struct mft_record *m;
	int err;

	if (!vi)
		return -ENOMEM;
	ntfs_init_big_inode(vi);
	ni = NTFS_I(vi);
	ni->type = AT_DATA;
	ni->name = NULL;
	ni->name_len = 0;
	ni->data_size = 0;
	vi->i_mode = S_IFREG | 0600;
	simple_inode_init_ts(vi);
	err = ntfs_mft_record_alloc(u->vol, vi->i_mode, &ni, NULL, &m, -1);
	if (err)
		goto out;
	vi->i_ino = ni->mft_no;
	err = upgrade_build_record(u, ni, file,
				   MK_LE_MREF(FILE_Extend, NTFS_I(u->extend)->seq_no));
	if (!err)
		err = upgrade_write_record(ni);
	if (!err)
		err = upgrade_link(u->extend, ni);
	unmap_mft_record(ni);
out:
	/* Keep failed conversions dirty and do not delete a partially linked file. */
	NInoClearDirty(ni);
	iput(vi);
	return err;
}

static int upgrade_sync_inode(struct inode *vi)
{
	int err;

	if (!vi)
		return 0;
	err = filemap_write_and_wait(vi->i_mapping);
	if (!err)
		err = __ntfs_write_inode(vi, 1);
	if (!err && NInoDirty(NTFS_I(vi)))
		err = -ENOMEM;
	return err;
}

static int upgrade_sync(struct ntfs_upgrade *u)
{
	struct ntfs_volume *vol = u->vol;
	struct inode *inodes[] = {
		u->secure, u->extend, vol->root_ino, vol->lcnbmp_ino,
		vol->mftbmp_ino, vol->logfile_ino, vol->mft_ino, vol->mftmirr_ino,
	};
	unsigned int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(inodes); i++) {
		err = upgrade_sync_inode(inodes[i]);
		if (err)
			return err;
	}
	err = sync_blockdev(vol->sb->s_bdev);
	if (!err)
		err = blkdev_issue_flush(vol->sb->s_bdev);
	if (!err && NVolErrors(vol))
		err = -EIO;
	return err;
}

/* Build the NTFS 3.x attribute definitions, including a zero terminator. */
static int upgrade_prepare_attrdef(struct ntfs_upgrade *u)
{
	static const struct {
		const char *name;
		u32 type, flags;
		s64 min, max;
	} defs[] = {
		{ "$STANDARD_INFORMATION", 0x10, 0x40, 48, 72 },
		{ "$ATTRIBUTE_LIST", 0x20, 0x80, 0, -1 },
		{ "$FILE_NAME", 0x30, 0x42, 68, 578 },
		{ "$OBJECT_ID", 0x40, 0x40, 0, 256 },
		{ "$SECURITY_DESCRIPTOR", 0x50, 0x80, 0, -1 },
		{ "$VOLUME_NAME", 0x60, 0x40, 2, 256 },
		{ "$VOLUME_INFORMATION", 0x70, 0x40, 12, 12 },
		{ "$DATA", 0x80, 0, 0, -1 },
		{ "$INDEX_ROOT", 0x90, 0x40, 0, -1 },
		{ "$INDEX_ALLOCATION", 0xa0, 0x80, 0, -1 },
		{ "$BITMAP", 0xb0, 0x80, 0, -1 },
		{ "$REPARSE_POINT", 0xc0, 0x80, 0, 16384 },
		{ "$EA_INFORMATION", 0xd0, 0x40, 8, 8 },
		{ "$EA", 0xe0, 0, 0, 65536 },
		{ "$LOGGED_UTILITY_STREAM", 0x100, 0x80, 0, 65536 },
	};
	unsigned int i;

	u->attrdef = kvcalloc(ARRAY_SIZE(defs) + 1, sizeof(*u->attrdef), GFP_NOFS);
	if (!u->attrdef)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(defs); i++) {
		upgrade_unicode(u->attrdef[i].name, defs[i].name);
		u->attrdef[i].type = cpu_to_le32(defs[i].type);
		u->attrdef[i].flags = cpu_to_le32(defs[i].flags);
		u->attrdef[i].min_size = cpu_to_le64(defs[i].min);
		u->attrdef[i].max_size = cpu_to_le64(defs[i].max);
	}
	return 0;
}

static int upgrade_write_attrdef(struct ntfs_upgrade *u)
{
	struct inode *vi = ntfs_iget(u->vol->sb, FILE_AttrDef);
	struct inode *data;
	s64 written;
	int err;

	if (IS_ERR(vi))
		return PTR_ERR(vi);
	data = ntfs_attr_iget(vi, AT_DATA, NULL, 0);
	if (IS_ERR(data)) {
		err = PTR_ERR(data);
		goto put;
	}
	written = ntfs_inode_attr_pwrite(data, 0, 2560, (u8 *)u->attrdef, true);
	err = written == 2560 ? 0 : written < 0 ? written : -EIO;
	if (!err) {
		mutex_lock(&NTFS_I(vi)->mrec_lock);
		err = ntfs_attr_truncate(NTFS_I(data), 2560);
		mutex_unlock(&NTFS_I(vi)->mrec_lock);
	}
	if (!err)
		err = upgrade_sync_inode(data);
	if (!err)
		err = upgrade_sync_inode(vi);
	iput(data);
put:
	iput(vi);
	/* Reload the base inode's sizes after writing through the attribute. */
	if (!err) {
		vi = ntfs_iget(u->vol->sb, FILE_AttrDef);
		if (IS_ERR(vi))
			return PTR_ERR(vi);
		mutex_lock(&NTFS_I(vi)->mrec_lock);
		err = ntfs_inode_sync_filename(NTFS_I(vi));
		mutex_unlock(&NTFS_I(vi)->mrec_lock);
		if (!err)
			err = upgrade_sync_inode(vi);
		iput(vi);
	}
	if (!err) {
		kvfree(u->vol->attrdef);
		u->vol->attrdef = u->attrdef;
		u->vol->attrdef_size = 2560;
		u->attrdef = NULL;
	}
	return err;
}

static int upgrade_prepare_security(struct ntfs_upgrade *u)
{
	struct upgrade_security_header *header;
	struct security_descriptor_relative *desc;
	u8 *sd;
	s64 sd_len;
	u32 hash = 0;
	unsigned int i;

	sd = ntfs_attr_readall(NTFS_I(u->vol->root_ino), AT_SECURITY_DESCRIPTOR,
			       AT_UNNAMED, 0, &sd_len);
	if (IS_ERR(sd))
		return PTR_ERR(sd);
	if (sd_len < sizeof(struct security_descriptor_relative) ||
	    sd_len > 65536 || (sd_len & 3)) {
		kvfree(sd);
		return -EOPNOTSUPP;
	}
	desc = (void *)sd;
	if (desc->revision != 1 || !(desc->control & SE_SELF_RELATIVE)) {
		kvfree(sd);
		return -EIO;
	}
	for (i = 0; i < 4; i++) {
		u32 ofs = get_unaligned_le32(sd + offsetof(typeof(*desc), owner) + 4 * i);
		u32 size;

		if (!ofs)
			continue;
		if ((ofs & 3) || ofs < sizeof(*desc) || ofs > sd_len - 8)
			goto bad_descriptor;
		if (i < 2)
			size = 8 + sd[ofs + 1] * sizeof(__le32);
		else
			size = get_unaligned_le16(sd + ofs + 2);
		if (size < 8 || size > sd_len - ofs)
			goto bad_descriptor;
	}
	u->sds_len = SDS_BLOCK_SIZE + sizeof(*header) + sd_len;
	u->sds = kvzalloc(u->sds_len, GFP_NOFS);
	if (!u->sds) {
		kvfree(sd);
		return -ENOMEM;
	}
	for (i = 0; i < sd_len; i += sizeof(__le32))
		hash = rol32(hash, 3) + get_unaligned_le32(sd + i);
	header = (void *)u->sds;
	header->hash = cpu_to_le32(hash);
	header->security_id = cpu_to_le32(UPGRADE_SECURITY_ID);
	header->length = cpu_to_le32(sizeof(*header) + sd_len);
	memcpy(u->sds + sizeof(*header), sd, sd_len);
	memcpy(u->sds + SDS_BLOCK_SIZE, u->sds, sizeof(*header) + sd_len);
	kvfree(sd);
	return 0;
bad_descriptor:
	kvfree(sd);
	return -EIO;
}

static int upgrade_create_metadata(struct ntfs_upgrade *u)
{
	struct ntfs_volume *vol = u->vol;
	struct mft_record *m = u->slot[0]->mrec;
	struct attr_record *a = upgrade_find_attr(m, AT_FILE_NAME, "");
	struct inode *sds;
	s64 written;
	unsigned int i;
	int err;

	if (a) {
		mutex_lock(&NTFS_I(vol->root_ino)->mrec_lock);
		err = ntfs_index_remove(NTFS_I(vol->root_ino), upgrade_value(a),
					le32_to_cpu(a->data.resident.value_length));
		mutex_unlock(&NTFS_I(vol->root_ino)->mrec_lock);
		if (err)
			return err;
	}
	for (i = 0; i < ARRAY_SIZE(u->slot); i++) {
		err = upgrade_build_record(u, u->slot[i], i, u->root_ref);
		if (!err)
			err = upgrade_write_record(u->slot[i]);
		if (err)
			return err;
		down_write(&vol->mftbmp_lock);
		err = ntfs_bitmap_set_bit(vol->mftbmp_ino, u->slot[i]->mft_no);
		up_write(&vol->mftbmp_lock);
		if (!err)
			err = upgrade_link(vol->root_ino, u->slot[i]);
		if (err)
			return err;
	}
	u->secure = ntfs_iget(vol->sb, FILE_Secure);
	if (IS_ERR(u->secure))
		return PTR_ERR(u->secure);
	u->extend = ntfs_iget(vol->sb, FILE_Extend);
	if (IS_ERR(u->extend))
		return PTR_ERR(u->extend);
	{
		__le16 name[4];

		upgrade_unicode(name, "$SDS");
		sds = ntfs_attr_iget(u->secure, AT_DATA, name, ARRAY_SIZE(name));
	}
	if (IS_ERR(sds))
		return PTR_ERR(sds);
	written = ntfs_inode_attr_pwrite(sds, 0, u->sds_len, u->sds, true);
	err = written == u->sds_len ? 0 : written < 0 ? written : -EIO;
	if (!err)
		err = upgrade_sync_inode(sds);
	iput(sds);
	if (err)
		return err;
	for (i = UPGRADE_QUOTA; i <= UPGRADE_REPARSE; i++) {
		err = upgrade_create_child(u, i);
		if (err)
			return err;
	}
	return 0;
}

static int upgrade_commit_version(struct ntfs_upgrade *u)
{
	struct ntfs_volume *vol = u->vol;
	struct ntfs_inode *ni = NTFS_I(vol->vol_ino);
	struct ntfs_attr_search_ctx *ctx;
	struct volume_information *info;
	__le16 flags;
	int err;

	mutex_lock(&ni->mrec_lock);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}
	err = ntfs_attr_lookup(AT_VOLUME_INFORMATION, NULL, 0, CASE_SENSITIVE,
			       0, NULL, 0, ctx);
	if (err)
		goto put;
	if (ctx->attr->non_resident ||
	    le32_to_cpu(ctx->attr->data.resident.value_length) < sizeof(*info)) {
		err = -EIO;
		goto put;
	}
	flags = vol->vol_flags & ~(VOLUME_UPGRADE_ON_MOUNT | VOLUME_MOUNTED_ON_NT4);
	info = upgrade_value(ctx->attr);
	info->major_ver = 3;
	info->minor_ver = 0;
	info->flags = flags;
	mark_mft_record_dirty(ctx->ntfs_ino);
put:
	ntfs_attr_put_search_ctx(ctx);
out:
	mutex_unlock(&ni->mrec_lock);
	if (err)
		return err;
	err = upgrade_sync_inode(vol->vol_ino);
	if (!err)
		err = upgrade_sync(u);
	if (!err) {
		vol->major_ver = 3;
		vol->minor_ver = 0;
		vol->vol_flags = flags;
	}
	return err;
}

static int upgrade_check_space(struct ntfs_upgrade *u)
{
	struct ntfs_volume *vol = u->vol;
	u64 nr, nr_free = 0, end, bytes, growth;
	unsigned int needed = UPGRADE_REPARSE - UPGRADE_QUOTA + 1 + MFT_RECORD_RESERVE;
	s64 clusters = DIV_ROUND_UP(u->sds_len, vol->cluster_size) + 4;

	/* Budget the MFT metadata reserve as well as the three child records. */
	for (nr = FILE_first_user; nr < u->nr_records && nr_free < needed; nr++) {
		if (nr >= vol->mft_record_reserve_pos && nr < vol->mft_record_reserve_end)
			continue;
		if (!(u->bitmap[nr >> 3] & BIT(nr & 7)))
			nr_free++;
	}
	if (nr_free < needed) {
		end = max_t(u64, u->nr_records, FILE_first_user) + needed - nr_free;
		if (end > U32_MAX)
			return -ENOSPC;
		bytes = end << vol->mft_record_size_bits;
		if (bytes > NTFS_I(vol->mft_ino)->allocated_size) {
			/* The allocator normally grows $MFT by sixteen records. */
			growth = max_t(u64, vol->mft_record_size * MFT_DATA_EXTEND_RECORDS,
				       vol->cluster_size);
			bytes = round_up(bytes - NTFS_I(vol->mft_ino)->allocated_size, growth);
			if ((NTFS_I(vol->mft_ino)->allocated_size + bytes) >>
			    vol->mft_record_size_bits >= (1ULL << 32))
				return -ENOSPC;
			clusters += bytes >> vol->cluster_size_bits;
		}
		bytes = round_up(DIV_ROUND_UP_ULL(end, 8), 8);
		if (bytes > NTFS_I(vol->mftbmp_ino)->allocated_size) {
			if (NInoNonResident(NTFS_I(vol->mftbmp_ino)))
				bytes -= NTFS_I(vol->mftbmp_ino)->allocated_size;
			clusters += DIV_ROUND_UP_ULL(bytes, vol->cluster_size);
		}
	}
	/* Allocation must not wait for the work queued after fill_super(). */
	return get_nr_free_clusters(vol) < clusters ? -ENOSPC : 0;
}

int ntfs_upgrade_volume(struct ntfs_volume *vol)
{
	struct ntfs_upgrade u = { .vol = vol };
	struct mft_record *m;
	s64 bitmap_len, bytes_read;
	unsigned int i;
	bool started = false;
	int err;

	if (sb_rdonly(vol->sb) || vol->major_ver >= 3)
		return 0;
	/* An old version alone does not request an on-disk format change. */
	if (!(vol->vol_flags & VOLUME_UPGRADE_ON_MOUNT))
		return 0;
	if (vol->major_ver != 1 || vol->minor_ver != 2) {
		err = -EOPNOTSUPP;
		goto out;
	}
	if (NVolErrors(vol) ||
	    (vol->vol_flags & (VOLUME_MUST_MOUNT_RO_MASK & ~VOLUME_UPGRADE_ON_MOUNT))) {
		err = -EROFS;
		goto out;
	}
	ntfs_warning(vol->sb, "Upgrading NTFS 1.2 to 3.0 before completing the mount.");
	u.target = kmemdup(vol, sizeof(*vol), GFP_NOFS);
	u.pairs = kmalloc(vol->mft_record_size, GFP_NOFS);
	if (!u.target || !u.pairs) {
		err = -ENOMEM;
		goto out;
	}
	u.target->major_ver = 3;
	u.target->minor_ver = 0;
	u.nr_records = NTFS_I(vol->mft_ino)->initialized_size >> vol->mft_record_size_bits;
	if (u.nr_records <= FILE_Extend || u.nr_records > U32_MAX) {
		err = -EIO;
		goto out;
	}
	bitmap_len = DIV_ROUND_UP_ULL(u.nr_records, 8);
	if (bitmap_len > NTFS_I(vol->mftbmp_ino)->initialized_size) {
		err = -EIO;
		goto out;
	}
	u.bitmap = kvmalloc(bitmap_len, GFP_NOFS);
	if (!u.bitmap) {
		err = -ENOMEM;
		goto out;
	}
	bytes_read = ntfs_inode_attr_pread(vol->mftbmp_ino, 0, bitmap_len, u.bitmap);
	if (bytes_read != bitmap_len) {
		err = bytes_read < 0 ? bytes_read : -EIO;
		goto out;
	}
	u.root_ref = MK_LE_MREF(FILE_root, NTFS_I(vol->root_ino)->seq_no);
	u.now = utc2ntfs(current_time(vol->root_ino));
	for (i = 0; i < ARRAY_SIZE(u.slot); i++) {
		u.slot[i] = upgrade_map_record(vol, i ? FILE_Extend : FILE_Secure);
		if (IS_ERR(u.slot[i])) {
			err = PTR_ERR(u.slot[i]);
			goto out;
		}
		err = upgrade_check_record(&u, u.slot[i]);
		if (err)
			goto out;
	}
	u.prepared = upgrade_record_named(u.slot[0]->mrec, "$Secure") &&
		upgrade_record_named(u.slot[1]->mrec, "$Extend");
	if (u.prepared) {
		err = upgrade_check_prepared(&u);
	} else {
		for (i = 0; i < ARRAY_SIZE(u.slot); i++) {
			err = upgrade_check_slot(&u, i);
			if (err)
				goto out;
		}
		for (i = 0; i < 2; i++) {
			u64 ref = upgrade_lookup(vol->root_ino, upgrade_names[i]);

			if (ref != ERR_MREF(-ENOENT)) {
				err = IS_ERR_MREF(ref) ? MREF_ERR(ref) : -EEXIST;
				goto out;
			}
		}
		err = upgrade_prepare_security(&u);
	}
	if (err)
		goto out;
	err = upgrade_walk_mft(&u, false);
	if (err)
		goto out;
	if (!u.prepared) {
		err = upgrade_prepare_attrdef(&u);
		if (err)
			goto out;
		/* Check record space before touching the old system-file slots. */
		m = kmalloc(vol->mft_record_size, GFP_NOFS);
		if (!m) {
			err = -ENOMEM;
			goto out;
		}
		for (i = UPGRADE_SECURE; i <= UPGRADE_REPARSE; i++) {
			struct ntfs_inode tmp = {
				.mft_no = i < 2 ? (i ? FILE_Extend : FILE_Secure) : 24,
			};

			memset(m, 0, vol->mft_record_size);
			tmp.mrec = m;
			err = upgrade_build_record(&u, &tmp, i, u.root_ref);
			if (err)
				break;
		}
		kfree(m);
		if (err)
			goto out;
		err = upgrade_check_space(&u);
		if (err)
			goto out;
	}

	/* All preflight checks are read-only. Persist the recovery marker first. */
	err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY | VOLUME_UPGRADE_ON_MOUNT);
	if (err)
		goto out;
	started = true;
	err = upgrade_sync_inode(vol->vol_ino);
	if (!err)
		err = upgrade_sync(&u);
	if (err)
		goto out;
	if (vol->logfile_ino && !ntfs_empty_logfile(vol->logfile_ino)) {
		err = -EIO;
		goto out;
	}
	if (!u.prepared) {
		err = upgrade_create_metadata(&u);
		if (!err)
			err = upgrade_write_attrdef(&u);
		if (err)
			goto out;
	}
	err = upgrade_walk_mft(&u, true);
	if (!err)
		err = upgrade_sync(&u);
	/* The version and upgrade flag are the final writes, after the barrier. */
	if (!err)
		err = upgrade_commit_version(&u);
out:
	if (err) {
		if (!started && (err == -EOPNOTSUPP || err == -ENOSPC ||
				 err == -EROFS || err == -EEXIST)) {
			vol->sb->s_flags |= SB_RDONLY;
			ntfs_warning(vol->sb,
				     "NTFS upgrade unavailable (%d). Mounting read-only. Upgrade in Windows.",
				     err);
			err = 0;
		} else {
			if (started)
				NVolSetErrors(vol);
			ntfs_error(vol->sb, "NTFS upgrade failed (%d)%s", err,
				   started ? ". Volume left dirty. Run chkdsk in Windows." :
				   ". No upgrade metadata was changed.");
		}
	} else {
		ntfs_warning(vol->sb, "NTFS upgrade to 3.0 completed.");
	}
	if (!IS_ERR_OR_NULL(u.extend))
		iput(u.extend);
	if (!IS_ERR_OR_NULL(u.secure))
		iput(u.secure);
	for (i = 0; i < ARRAY_SIZE(u.slot); i++)
		upgrade_unmap_record(u.slot[i]);
	kfree(u.target);
	kfree(u.pairs);
	kvfree(u.bitmap);
	kvfree(u.sds);
	kvfree(u.attrdef);
	return err;
}
