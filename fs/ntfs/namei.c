// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS kernel directory inode operations.
 *
 * Copyright (c) 2001-2006 Anton Altaparmakov
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/exportfs.h>
#include <linux/iversion.h>
#include <linux/namei.h>
#include <linux/posix_acl.h>

#include "ntfs.h"
#include "attrlist.h"
#include "time.h"
#include "index.h"
#include "logfile.h"
#include "reparse.h"
#include "object_id.h"
#include "ea.h"
#include "stream.h"

static const __le16 aux_name_le[3] = {
	cpu_to_le16('A'), cpu_to_le16('U'), cpu_to_le16('X')
};

static const __le16 con_name_le[3] = {
	cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('N')
};

static const __le16 com_name_le[3] = {
	cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M')
};

static const __le16 lpt_name_le[3] = {
	cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T')
};

static const __le16 nul_name_le[3] = {
	cpu_to_le16('N'), cpu_to_le16('U'), cpu_to_le16('L')
};

static const __le16 prn_name_le[3] = {
	cpu_to_le16('P'), cpu_to_le16('R'), cpu_to_le16('N')
};

struct ntfs_index_size_snapshot {
	s64 data_size;
	s64 initialized_size;
	s64 allocated_size;
	s64 zeroed_size;
	loff_t i_size;
};

struct ntfs_mft_snapshot {
	struct ntfs_inode *ni;
	struct mft_record *mrec;
	struct mft_record *before;
	struct ntfs_index_size_snapshot index_size;
	unsigned int nlink;
	bool restore_index_size;
};

static void ntfs_index_size_snapshot(struct ntfs_inode *ni,
		struct ntfs_index_size_snapshot *snapshot)
{
	snapshot->data_size = ni->data_size;
	snapshot->initialized_size = ni->initialized_size;
	snapshot->allocated_size = ni->allocated_size;
	snapshot->zeroed_size = ni->zeroed_size;
	snapshot->i_size = i_size_read(VFS_I(ni));
}

static void ntfs_index_size_restore(struct ntfs_inode *ni,
		const struct ntfs_index_size_snapshot *snapshot)
{
	ni->data_size = snapshot->data_size;
	ni->initialized_size = snapshot->initialized_size;
	ni->allocated_size = snapshot->allocated_size;
	ni->zeroed_size = snapshot->zeroed_size;
	i_size_write(VFS_I(ni), snapshot->i_size);
}

static int ntfs_mft_snapshot_take(struct ntfs_mft_snapshot *snapshots,
		unsigned int *count, unsigned int capacity, struct ntfs_inode *ni,
		bool restore_index_size)
{
	struct ntfs_mft_snapshot *snapshot;
	unsigned int i;

	for (i = 0; i < *count; i++) {
		if (snapshots[i].ni != ni)
			continue;
		if (restore_index_size && !snapshots[i].restore_index_size) {
			ntfs_index_size_snapshot(ni, &snapshots[i].index_size);
			snapshots[i].restore_index_size = true;
		}
		return 0;
	}
	if (*count >= capacity)
		return -E2BIG;

	snapshot = &snapshots[*count];
	snapshot->mrec = map_mft_record(ni);
	if (IS_ERR(snapshot->mrec)) {
		int err = PTR_ERR(snapshot->mrec);

		snapshot->mrec = NULL;
		return err;
	}
	snapshot->before = kmemdup(snapshot->mrec, ni->vol->mft_record_size,
			GFP_NOFS);
	if (!snapshot->before) {
		unmap_mft_record(ni);
		snapshot->mrec = NULL;
		return -ENOMEM;
	}
	snapshot->ni = ni;
	snapshot->nlink = VFS_I(ni)->i_nlink;
	snapshot->restore_index_size = restore_index_size;
	if (restore_index_size)
		ntfs_index_size_snapshot(ni, &snapshot->index_size);
	(*count)++;
	return 0;
}

static void ntfs_mft_snapshots_restore(struct ntfs_mft_snapshot *snapshots,
		unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		struct ntfs_mft_snapshot *snapshot = &snapshots[i];

		memcpy(snapshot->mrec, snapshot->before,
				snapshot->ni->vol->mft_record_size);
		set_nlink(VFS_I(snapshot->ni), snapshot->nlink);
		if (snapshot->restore_index_size)
			ntfs_index_size_restore(snapshot->ni,
					&snapshot->index_size);
		mark_mft_record_dirty(snapshot->ni);
	}
}

static void ntfs_mft_snapshots_release(struct ntfs_mft_snapshot *snapshots,
		unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		kfree(snapshots[i].before);
		unmap_mft_record(snapshots[i].ni);
	}
}

static int ntfs_mft_set_link_count(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, struct mft_record *mrec, u16 count)
{
	struct mft_record *after;
	u64 lsn = 0;
	int err;

	if (handle && mrec->link_count == cpu_to_le16(count))
		return 0;
	if (handle) {
		after = kmemdup(mrec, ni->vol->mft_record_size, GFP_NOFS);
		if (!after)
			return -ENOMEM;
		after->link_count = cpu_to_le16(count);
		err = ntfs_attr_mft_register_home_undo(handle, ni, mrec);
		if (!err)
			err = ntfs_log_mft_record_update(handle, ni->mft_no,
					mrec, after, &lsn);
		kfree(after);
		if (err)
			return err;
	}
	mrec->link_count = cpu_to_le16(count);
	if (lsn)
		mrec->lsn = cpu_to_le64(lsn);
	mark_mft_record_dirty(ni);
	return 0;
}

static int ntfs_filename_log_credits(struct ntfs_volume *vol,
		u16 name_len, unsigned int entries, bool may_remove)
{
	u32 fn_len, attr_len, entry_len;
	unsigned int attr_credits, per_entry;
	int allocation_credits, index_credits, snapshot_credits;
	int node_remove_credits, remove_credits, reparent_credits, split_credits;

	if (!entries || name_len > NTFS_MAX_NAME_LEN)
		return -EINVAL;
	fn_len = sizeof(struct file_name_attr) +
		name_len * sizeof(__le16);
	attr_len = offsetof(struct attr_record, data.resident.reserved) +
		sizeof_field(struct attr_record, data.resident.reserved) +
		ALIGN(fn_len, 8);
	entry_len = ALIGN(sizeof(struct index_entry_header) + fn_len, 8);
	if (attr_len > U16_MAX || entry_len > U16_MAX)
		return -E2BIG;

	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	snapshot_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, vol->mft_record_size);
	if (snapshot_credits < 0)
		return snapshot_credits;
	/* One update for the filename and one for the base link count. */
	if (check_mul_overflow((unsigned int)snapshot_credits, 2U,
			&attr_credits))
		return -EOVERFLOW;
	index_credits = ntfs_log_index_root_credits(vol, entry_len);
	if (index_credits < 0)
		return index_credits;
	allocation_credits = ntfs_log_index_allocation_credits(vol,
			vol->index_record_size, entry_len);
	if (allocation_credits < 0 && allocation_credits != -EOPNOTSUPP)
		return allocation_credits;
	if (allocation_credits >= 0)
		index_credits = max(index_credits, allocation_credits);
	reparent_credits = ntfs_index_root_reparent_log_credits(vol,
			vol->index_record_size);
	if (reparent_credits < 0 && reparent_credits != -EOPNOTSUPP)
		return reparent_credits;
	if (reparent_credits >= 0)
		index_credits = max(index_credits, reparent_credits);
	split_credits = ntfs_index_leaf_split_log_credits(vol,
			vol->index_record_size);
	if (split_credits < 0 && split_credits != -EOPNOTSUPP)
		return split_credits;
	if (split_credits >= 0)
		index_credits = max(index_credits, split_credits);
	if (may_remove) {
		remove_credits = ntfs_index_leaf_remove_log_credits(vol,
								    vol->index_record_size);
		if (remove_credits < 0 && remove_credits != -EOPNOTSUPP)
			return remove_credits;
		if (remove_credits >= 0)
			index_credits = max(index_credits, remove_credits);
		node_remove_credits = ntfs_index_node_remove_log_credits(vol,
									 vol->index_record_size);
		if (node_remove_credits < 0 &&
		    node_remove_credits != -EOPNOTSUPP)
			return node_remove_credits;
		if (node_remove_credits >= 0)
			index_credits = max(index_credits, node_remove_credits);
	}
	if (check_add_overflow((unsigned int)attr_credits,
			(unsigned int)index_credits, &per_entry) ||
	    check_mul_overflow(per_entry, entries, &per_entry) ||
	    per_entry > INT_MAX)
		return -EOVERFLOW;
	return per_entry;
}

static int ntfs_filename_attrlist_extra_credits(struct ntfs_volume *vol,
		unsigned int entries)
{
	unsigned int credits;
	int extent_credits;
	int list_credits;

	if (!vol || !entries)
		return -EINVAL;
	extent_credits = ntfs_attrlist_extent_log_credits(vol);
	if (extent_credits < 0)
		return extent_credits;
	list_credits = ntfs_attrlist_nonresident_log_credits(vol);
	if (list_credits < 0)
		return list_credits;
	if (check_mul_overflow((unsigned int)max(extent_credits,
			list_credits), entries, &credits) || credits > INT_MAX)
		return -EOVERFLOW;
	return credits;
}

static inline int ntfs_check_bad_char(const __le16 *wc, unsigned int wc_len)
{
	int i;

	for (i = 0; i < wc_len; i++) {
		u16 c = le16_to_cpu(wc[i]);

		if (c < 0x0020 ||
		    c == 0x0022 || c == 0x002A || c == 0x002F ||
		    c == 0x003A || c == 0x003C || c == 0x003E ||
		    c == 0x003F || c == 0x005C || c == 0x007C)
			return -EINVAL;
	}

	return 0;
}

/*
 * ntfs_check_bad_windows_name() - Validate a name against Windows rules
 * @vol: NTFS volume
 * @wc: UTF-16LE name
 * @wc_len: length of @wc in UTF-16 code units
 *
 * When Windows-name checks are enabled, reject disallowed characters,
 * trailing spaces or dots, and reserved DOS device names.
 *
 * Return: 0 if valid, or -EINVAL otherwise.
 */
int ntfs_check_bad_windows_name(struct ntfs_volume *vol,
				       const __le16 *wc,
				       unsigned int wc_len)
{
	if (!NVolCheckWindowsNames(vol))
		return 0;

	if (ntfs_check_bad_char(wc, wc_len))
		return -EINVAL;

	/* Check for trailing space or dot. */
	if (wc_len > 0 &&
	    (wc[wc_len - 1] == cpu_to_le16(' ') ||
	    wc[wc_len - 1] == cpu_to_le16('.')))
		return -EINVAL;

	if (wc_len == 3 || (wc_len > 3 && wc[3] == cpu_to_le16('.'))) {
		__le16 *upcase = vol->upcase;
		u32 size = vol->upcase_len;

		if (ntfs_are_names_equal(wc, 3, aux_name_le, 3, IGNORE_CASE, upcase, size) ||
		    ntfs_are_names_equal(wc, 3, con_name_le, 3, IGNORE_CASE, upcase, size) ||
		    ntfs_are_names_equal(wc, 3, nul_name_le, 3, IGNORE_CASE, upcase, size) ||
		    ntfs_are_names_equal(wc, 3, prn_name_le, 3, IGNORE_CASE, upcase, size))
			return -EINVAL;
	}

	if (wc_len == 4 || (wc_len > 4 && wc[4] == cpu_to_le16('.'))) {
		__le16 *upcase = vol->upcase;
		u32 size = vol->upcase_len, port;

		if (ntfs_are_names_equal(wc, 3, com_name_le, 3, IGNORE_CASE, upcase, size) ||
		    ntfs_are_names_equal(wc, 3, lpt_name_le, 3, IGNORE_CASE, upcase, size)) {
			port = le16_to_cpu(wc[3]);
			if (port >= '1' && port <= '9')
				return -EINVAL;
		}
	}
	return 0;
}

/*
 * ntfs_lookup - find the inode represented by a dentry in a directory inode
 * @dir_ino:	directory inode in which to look for the inode
 * @dent:	dentry representing the inode to look for
 * @flags:	lookup flags
 *
 * In short, ntfs_lookup() looks for the inode represented by the dentry @dent
 * in the directory inode @dir_ino and if found attaches the inode to the
 * dentry @dent.
 *
 * In more detail, the dentry @dent specifies which inode to look for by
 * supplying the name of the inode in @dent->d_name.name. ntfs_lookup()
 * converts the name to Unicode and walks the contents of the directory inode
 * @dir_ino looking for the converted Unicode name. If the name is found in the
 * directory, the corresponding inode is loaded by calling ntfs_iget() on its
 * inode number and the inode is associated with the dentry @dent via a call to
 * d_splice_alias().
 *
 * If the name is not found in the directory, a NULL inode is inserted into the
 * dentry @dent via a call to d_add(). The dentry is then termed a negative
 * dentry.
 *
 * Only if an actual error occurs, do we return an error via ERR_PTR().
 *
 * In order to handle the case insensitivity issues of NTFS with regards to the
 * dcache and the dcache requiring only one dentry per directory, we deal with
 * dentry aliases that only differ in case in ->ntfs_lookup() while maintaining
 * a case sensitive dcache. This means that we get the full benefit of dcache
 * speed when the file/directory is looked up with the same case as returned by
 * ->ntfs_readdir() but that a lookup for any other case (or for the short file
 * name) will not find anything in dcache and will enter ->ntfs_lookup()
 * instead, where we search the directory for a fully matching file name
 * (including case) and if that is not found, we search for a file name that
 * matches with different case and if that has non-POSIX semantics we return
 * that. We actually do only one search (case sensitive) and keep tabs on
 * whether we have found a case insensitive match in the process.
 *
 * To simplify matters for us, we do not treat the short vs long filenames as
 * two hard links but instead if the lookup matches a short filename, we
 * return the dentry for the corresponding long filename instead.
 *
 * There are three cases we need to distinguish here:
 *
 * 1) @dent perfectly matches (i.e. including case) a directory entry with a
 *    file name in the WIN32 or POSIX namespaces. In this case
 *    ntfs_lookup_inode_by_name() will return with name set to NULL and we
 *    just d_splice_alias() @dent.
 * 2) @dent matches (not including case) a directory entry with a file name in
 *    the WIN32 namespace. In this case ntfs_lookup_inode_by_name() will return
 *    with name set to point to a kmalloc()ed ntfs_name structure containing
 *    the properly cased little endian Unicode name. We convert the name to the
 *    current NLS code page, search if a dentry with this name already exists
 *    and if so return that instead of @dent.  At this point things are
 *    complicated by the possibility of 'disconnected' dentries due to NFS
 *    which we deal with appropriately (see the code comments).  The VFS will
 *    then destroy the old @dent and use the one we returned.  If a dentry is
 *    not found, we allocate a new one, d_splice_alias() it, and return it as
 *    above.
 * 3) @dent matches either perfectly or not (i.e. we don't care about case) a
 *    directory entry with a file name in the DOS namespace. In this case
 *    ntfs_lookup_inode_by_name() will return with name set to point to a
 *    kmalloc()ed ntfs_name structure containing the mft reference (cpu endian)
 *    of the inode. We use the mft reference to read the inode and to find the
 *    file name in the WIN32 namespace corresponding to the matched short file
 *    name. We then convert the name to the current NLS code page, and proceed
 *    searching for a dentry with this name, etc, as in case 2), above.
 *
 * Locking: Caller must hold i_mutex on the directory.
 */

static struct dentry *ntfs_lookup(struct inode *dir_ino, struct dentry *dent,
		unsigned int flags)
{
	struct ntfs_volume *vol = NTFS_SB(dir_ino->i_sb);
	struct ntfs_stream_path stream_path;
	struct inode *dent_inode;
	__le16 *uname;
	struct ntfs_name *name = NULL;
	u64 mref;
	unsigned long dent_ino;
	int uname_len;
	int stream_path_len;

	ntfs_debug("Looking up %pd in directory inode 0x%llx.",
			dent, NTFS_I(dir_ino)->mft_no);
	stream_path_len = ntfs_stream_path_parse(vol, &dent->d_name,
			&stream_path);
	if (stream_path_len < 0)
		return ERR_PTR(stream_path_len);
	if (stream_path_len)
		return ntfs_lookup_stream(dir_ino, dent, &stream_path);

	/* Convert the name of the dentry to Unicode. */
	uname_len = ntfs_nlstoucs(vol, dent->d_name.name, dent->d_name.len,
				  &uname, NTFS_MAX_NAME_LEN);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_debug("Failed to convert name to Unicode.");
		return ERR_PTR(uname_len);
	}
	mutex_lock(&NTFS_I(dir_ino)->mrec_lock);
	mref = ntfs_lookup_inode_by_name(NTFS_I(dir_ino), uname, uname_len,
			&name);
	mutex_unlock(&NTFS_I(dir_ino)->mrec_lock);
	kmem_cache_free(ntfs_name_cache, uname);
	if (!IS_ERR_MREF(mref)) {
		dent_ino = MREF(mref);
		ntfs_debug("Found inode 0x%lx. Calling ntfs_iget.", dent_ino);
		dent_inode = ntfs_iget(vol->sb, dent_ino);
		if (!IS_ERR(dent_inode)) {
			/* Consistency check. */
			if (MSEQNO(mref) == NTFS_I(dent_inode)->seq_no ||
			    dent_ino == FILE_MFT) {
				/* Perfect WIN32/POSIX match. -- Case 1. */
				if (!name) {
					ntfs_debug("Done.  (Case 1.)");
					return d_splice_alias(dent_inode, dent);
				}
				/*
				 * We are too indented.  Handle imperfect
				 * matches and short file names further below.
				 */
				goto handle_name;
			}
			ntfs_error(vol->sb,
				"Found stale reference to inode 0x%lx (reference sequence number = 0x%x, inode sequence number = 0x%x), returning -EIO. Run chkdsk.",
				dent_ino, MSEQNO(mref),
				NTFS_I(dent_inode)->seq_no);
			iput(dent_inode);
			dent_inode = ERR_PTR(-EIO);
		} else
			ntfs_error(vol->sb, "ntfs_iget(0x%lx) failed with error code %li.",
					dent_ino, PTR_ERR(dent_inode));
		kfree(name);
		/* Return the error code. */
		return ERR_CAST(dent_inode);
	}
	kfree(name);
	/* It is guaranteed that @name is no longer allocated at this point. */
	if (MREF_ERR(mref) == -ENOENT) {
		ntfs_debug("Entry was not found, adding negative dentry.");
		/* The dcache will handle negative entries. */
		ntfs_debug("Done.");
		return d_splice_alias(NULL, dent);
	}
	ntfs_error(vol->sb, "ntfs_lookup_ino_by_name() failed with error code %i.",
			-MREF_ERR(mref));
	return ERR_PTR(MREF_ERR(mref));
handle_name:
	{
		struct mft_record *m;
		struct ntfs_attr_search_ctx *ctx;
		struct ntfs_inode *ni = NTFS_I(dent_inode);
		int err;
		struct qstr nls_name;

		nls_name.name = NULL;
		if (name->type != FILE_NAME_DOS) {			/* Case 2. */
			ntfs_debug("Case 2.");
			nls_name.len = (unsigned int)ntfs_ucstonls(vol,
					(__le16 *)&name->name, name->len,
					(unsigned char **)&nls_name.name, 0);
			kfree(name);
		} else /* if (name->type == FILE_NAME_DOS) */ {		/* Case 3. */
			struct file_name_attr *fn;

			ntfs_debug("Case 3.");
			kfree(name);

			/* Find the WIN32 name corresponding to the matched DOS name. */
			ni = NTFS_I(dent_inode);
			m = map_mft_record(ni);
			if (IS_ERR(m)) {
				err = PTR_ERR(m);
				m = NULL;
				ctx = NULL;
				goto err_out;
			}
			ctx = ntfs_attr_get_search_ctx(ni, m);
			if (unlikely(!ctx)) {
				err = -ENOMEM;
				goto err_out;
			}
			do {
				struct attr_record *a;

				err = ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, 0, 0,
						NULL, 0, ctx);
				if (unlikely(err)) {
					ntfs_error(vol->sb,
						"Inode corrupt: No WIN32 namespace counterpart to DOS file name. Run chkdsk.");
					if (err == -ENOENT)
						err = -EIO;
					goto err_out;
				}
				/* Consistency checks. */
				a = ctx->attr;
				if (a->non_resident || a->flags)
					goto eio_err_out;
				fn = (struct file_name_attr *)((u8 *)ctx->attr + le16_to_cpu(
							ctx->attr->data.resident.value_offset));
			} while (fn->file_name_type != FILE_NAME_WIN32);

			/* Convert the found WIN32 name to current NLS code page. */
			nls_name.len = (unsigned int)ntfs_ucstonls(vol,
					(__le16 *)&fn->file_name, fn->file_name_length,
					(unsigned char **)&nls_name.name, 0);

			ntfs_attr_put_search_ctx(ctx);
			unmap_mft_record(ni);
		}
		m = NULL;
		ctx = NULL;

		/* Check if a conversion error occurred. */
		if ((int)nls_name.len < 0) {
			err = (int)nls_name.len;
			goto err_out;
		}
		nls_name.hash = full_name_hash(dent, nls_name.name, nls_name.len);

		dent = d_add_ci(dent, dent_inode, &nls_name);
		kfree(nls_name.name);
		return dent;

eio_err_out:
		ntfs_error(vol->sb, "Illegal file name attribute. Run chkdsk.");
		err = -EIO;
err_out:
		if (ctx)
			ntfs_attr_put_search_ctx(ctx);
		if (m)
			unmap_mft_record(ni);
		iput(dent_inode);
		ntfs_error(vol->sb, "Failed, returning error code %i.", err);
		return ERR_PTR(err);
	}
}

static int ntfs_sd_add_everyone(struct ntfs_log_handle *log_handle,
		struct ntfs_inode *ni)
{
	struct security_descriptor_relative *sd;
	struct ntfs_acl *acl;
	struct ntfs_ace *ace;
	struct ntfs_sid *sid;
	int ret, sd_len;

	/* Create SECURITY_DESCRIPTOR attribute (everyone has full access). */
	/*
	 * Calculate security descriptor length. We have 2 sub-authorities in
	 * owner and group SIDs, So add 8 bytes to every SID.
	 */
	sd_len = sizeof(struct security_descriptor_relative) + 2 *
		(sizeof(struct ntfs_sid) + 8) + sizeof(struct ntfs_acl) +
		sizeof(struct ntfs_ace) + 4;
	sd = kzalloc(sd_len, GFP_NOFS);
	if (!sd)
		return -ENOMEM;

	sd->revision = 1;
	sd->control = SE_DACL_PRESENT | SE_SELF_RELATIVE;

	sid = (struct ntfs_sid *)((u8 *)sd + sizeof(struct security_descriptor_relative));
	sid->revision = 1;
	sid->sub_authority_count = 2;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	sid->identifier_authority.value[5] = 5;
	sd->owner = cpu_to_le32((u8 *)sid - (u8 *)sd);

	sid = (struct ntfs_sid *)((u8 *)sid + sizeof(struct ntfs_sid) + 8);
	sid->revision = 1;
	sid->sub_authority_count = 2;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	sid->identifier_authority.value[5] = 5;
	sd->group = cpu_to_le32((u8 *)sid - (u8 *)sd);

	acl = (struct ntfs_acl *)((u8 *)sid + sizeof(struct ntfs_sid) + 8);
	acl->revision = 2;
	acl->size = cpu_to_le16(sizeof(struct ntfs_acl) + sizeof(struct ntfs_ace) + 4);
	acl->ace_count = cpu_to_le16(1);
	sd->dacl = cpu_to_le32((u8 *)acl - (u8 *)sd);

	ace = (struct ntfs_ace *)((u8 *)acl + sizeof(struct ntfs_acl));
	ace->type = ACCESS_ALLOWED_ACE_TYPE;
	ace->flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	ace->size = cpu_to_le16(sizeof(struct ntfs_ace) + 4);
	ace->mask = cpu_to_le32(0x1f01ff);
	ace->sid.revision = 1;
	ace->sid.sub_authority_count = 1;
	ace->sid.sub_authority[0] = 0;
	ace->sid.identifier_authority.value[5] = 1;

	if (log_handle)
		ret = ntfs_attr_add_transacted(log_handle, ni,
				AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0, (u8 *)sd,
				sd_len);
	else
		ret = ntfs_attr_add(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0,
				(u8 *)sd, sd_len);
	if (ret)
		ntfs_error(ni->vol->sb, "Failed to add SECURITY_DESCRIPTOR\n");

	kfree(sd);
	return ret;
}

static struct ntfs_inode *__ntfs_create(const struct mnt_idmap *idmap, struct inode *dir,
		__le16 *name, u8 name_len, mode_t mode, dev_t dev,
		const char *target, int target_len)
{
	struct ntfs_inode *dir_ni = NTFS_I(dir);
	struct ntfs_volume *vol = dir_ni->vol;
	struct ntfs_log_handle *log_handle = NULL;
	struct ntfs_inode *ni;
	bool rollback_data = false, rollback_sd = false, rollback_reparse = false;
	bool created_data = false;
	bool created_ea = false;
	bool journal_create = false;
	bool system_index_locked = false;
	bool mft_allocation_aborted = false;
	bool mft_allocation_pending = false;
	bool needs_reparse;
	bool reparse_present = false;
	char *converted_target = NULL;
	char *native_target = NULL;
	struct file_name_attr *fn = NULL;
	struct standard_information *si = NULL;
	int err = 0, fn_len, si_len;
	unsigned int journal_credits;
	struct inode *vi;
	struct mft_record *ni_mrec = NULL, *dni_mrec;
	struct super_block *sb = dir_ni->vol->sb;
	struct inode *rollback_data_vi = NULL, *rollback_sd_vi = NULL;
	__le64 parent_mft_ref;
	u64 child_mft_ref;
	__le16 ea_size;
#ifdef CONFIG_NTFS_FS_POSIX_ACL
	struct posix_acl *default_acl = NULL, *acl = NULL;
	bool init_acl = false;
#endif

	vi = new_inode(vol->sb);
	if (!vi)
		return ERR_PTR(-ENOMEM);

	ntfs_init_big_inode(vi);
	ni = NTFS_I(vi);
	ni->vol = dir_ni->vol;
	ni->name_len = 0;
	ni->name = NULL;

	/*
	 * Set the appropriate mode, attribute type, and name.  For
	 * directories, also setup the index values to the defaults.
	 */
	if (S_ISDIR(mode)) {
		NInoSetMstProtected(ni);
		ni->itype.index.block_size = 4096;
		ni->itype.index.block_size_bits = ntfs_ffs(4096) - 1;
		ni->itype.index.collation_rule = COLLATION_FILE_NAME;
		if (vol->cluster_size <= ni->itype.index.block_size) {
			ni->itype.index.vcn_size = vol->cluster_size;
			ni->itype.index.vcn_size_bits =
				vol->cluster_size_bits;
		} else {
			ni->itype.index.vcn_size = NTFS_BLOCK_SIZE;
			ni->itype.index.vcn_size_bits = NTFS_BLOCK_SIZE_BITS;
		}
	}

	if (IS_RDONLY(vi))
		mode &= ~0222;

	inode_init_owner(idmap, vi, dir, mode);

	mode = vi->i_mode;
	needs_reparse = S_ISLNK(mode) || S_ISBLK(mode) || S_ISCHR(mode) ||
		S_ISSOCK(mode) || S_ISFIFO(mode);

#ifdef CONFIG_NTFS_FS_POSIX_ACL
	if (!S_ISLNK(mode) && (sb->s_flags & SB_POSIXACL)) {
		err = posix_acl_create(dir, &vi->i_mode, &default_acl, &acl);
		if (err) {
			iput(vi);
			return ERR_PTR(err);
		}
		init_acl = true;
	} else
#endif
	{
		vi->i_flags |= S_NOSEC;
	}

	if (uid_valid(vol->uid))
		vi->i_uid = vol->uid;

	if (gid_valid(vol->gid))
		vi->i_gid = vol->gid;

	/*
	 * Set the file size to 0, the ntfs inode sizes are set to 0 by
	 * the call to ntfs_init_big_inode() below.
	 */
	vi->i_size = 0;
	vi->i_blocks = 0;

	inode_inc_iversion(vi);

	simple_inode_init_ts(vi);
	ni->i_crtime = inode_get_ctime(vi);

	inode_set_mtime_to_ts(dir, ni->i_crtime);
	inode_set_ctime_to_ts(dir, ni->i_crtime);
	mark_inode_dirty(dir);

	if (vol->journal) {
		int credits = ntfs_log_mft_record_credits(vol);
		int extra_credits;
		int filename_credits;
		int mft_credits;
		int reparse_credits = 0;
		unsigned int records = needs_reparse ? 6 : 5;

		if (credits < 0 || check_mul_overflow((unsigned int)credits,
				records,
				&journal_credits)) {
			err = credits < 0 ? credits : -EOVERFLOW;
			goto free_unhashed_record;
		}
		extra_credits = ntfs_attrlist_extent_log_credits(vol);
		if (extra_credits < 0 || check_add_overflow(journal_credits,
				(unsigned int)extra_credits, &journal_credits)) {
			err = extra_credits < 0 ? extra_credits : -EOVERFLOW;
			goto free_unhashed_record;
		}
		mft_credits = ntfs_mft_record_alloc_credits(vol);
		if (mft_credits < 0 || check_add_overflow(journal_credits,
				(unsigned int)mft_credits, &journal_credits)) {
			err = mft_credits < 0 ? mft_credits : -EOVERFLOW;
			goto free_unhashed_record;
		}
		if (needs_reparse) {
			reparse_credits = S_ISLNK(mode) ?
				(NVolSymlinkNative(vol) ?
					ntfs_reparse_native_symlink_log_credits(ni,
							target_len) :
					ntfs_reparse_wsl_symlink_log_credits(ni,
							target_len)) :
				ntfs_reparse_wsl_not_symlink_log_credits(ni);
			if (reparse_credits < 0 ||
			    check_add_overflow(journal_credits,
					(unsigned int)reparse_credits,
					&journal_credits)) {
				err = reparse_credits < 0 ? reparse_credits :
					-EOVERFLOW;
				goto free_unhashed_record;
			}
		}
		filename_credits = ntfs_filename_log_credits(vol, name_len, 1,
							     false);
		if (filename_credits < 0 ||
		    check_add_overflow(journal_credits,
				(unsigned int)filename_credits,
				&journal_credits)) {
			err = filename_credits < 0 ? filename_credits : -EOVERFLOW;
			goto free_unhashed_record;
		}
		if (NInoAttrList(dir_ni)) {
			extra_credits = ntfs_index_attrlist_log_credits(vol, 1);
			if (extra_credits < 0 ||
			    check_add_overflow(journal_credits,
					(unsigned int)extra_credits,
					&journal_credits)) {
				err = extra_credits < 0 ? extra_credits :
					-EOVERFLOW;
				goto free_unhashed_record;
			}
		}
#ifdef CONFIG_NTFS_FS_POSIX_ACL
		extra_credits = ntfs_acl_create_log_credits(vol, default_acl, acl);
		if (extra_credits < 0 ||
		    check_add_overflow(journal_credits,
				(unsigned int)extra_credits, &journal_credits)) {
			err = extra_credits < 0 ? extra_credits : -EOVERFLOW;
			goto free_unhashed_record;
		}
#endif
		log_handle = ntfs_log_begin(vol, journal_credits);
		if (IS_ERR(log_handle)) {
			err = PTR_ERR(log_handle);
			ntfs_error(sb,
				"Create journal begin failed (credits %u, error %d).",
				journal_credits, err);
			log_handle = NULL;
			goto free_unhashed_record;
		}
		journal_create = true;
		if (needs_reparse) {
			mutex_lock(&vol->system_index_lock);
			system_index_locked = true;
		}
	}

	if (log_handle)
		err = ntfs_mft_base_record_alloc_transacted(log_handle, vol, mode,
				&ni, &ni_mrec);
	else
		err = ntfs_mft_record_alloc(vol, mode, &ni, NULL, &ni_mrec, -1);
	if (err) {
		if (log_handle)
			ntfs_error(sb,
				"Create transacted MFT allocation failed (credits %u, error %d).",
				journal_credits, err);
		if (log_handle) {
			int abort_err = ntfs_log_abort(log_handle);

			log_handle = NULL;
			if (abort_err)
				err = abort_err;
		}
		goto free_unhashed_record;
	}
	if (log_handle)
		mft_allocation_pending = true;

	/*
	 * Prevent iget and writeback from finding this inode.
	 * Caller must call d_instantiate_new instead of d_instantiate.
	 */
	spin_lock(&vi->i_lock);
	inode_state_set(vi, I_NEW | I_CREATING);
	spin_unlock(&vi->i_lock);

	/* Add the inode to the inode hash for the superblock. */
	vi->i_ino = (unsigned long)ni->mft_no;
	inode_set_iversion(vi, 1);
	insert_inode_hash(vi);

	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	mutex_lock_nested(&dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
	if (!ni_mrec) {
		ni_mrec = map_mft_record(ni);
		if (IS_ERR(ni_mrec)) {
			err = PTR_ERR(ni_mrec);
			ni_mrec = NULL;
			ntfs_error(sb,
				"Create failed to map new MFT record (error %d).", err);
			goto err_out;
		}
	}
	if (NInoBeingDeleted(dir_ni)) {
		err = -ENOENT;
		ntfs_error(sb, "Create parent inode is being deleted (error %d).",
			err);
		goto err_out;
	}

	dni_mrec = map_mft_record(dir_ni);
	if (IS_ERR(dni_mrec)) {
		ntfs_error(dir_ni->vol->sb, "failed to map mft record for file 0x%llx.\n",
			   dir_ni->mft_no);
		err = -EIO;
		goto err_out;
	}
	parent_mft_ref = MK_LE_MREF(dir_ni->mft_no,
				    le16_to_cpu(dni_mrec->sequence_number));
	unmap_mft_record(dir_ni);

	/*
	 * Create STANDARD_INFORMATION attribute. Write STANDARD_INFORMATION
	 * version 1.2, windows will upgrade it to version 3 if needed.
	 */
	si_len = offsetof(struct standard_information, file_attributes) +
		sizeof(__le32) + 12;
	si = kzalloc(si_len, GFP_NOFS);
	if (!si) {
		err = -ENOMEM;
		goto err_out;
	}

	si->creation_time = si->last_data_change_time = utc2ntfs(ni->i_crtime);
	si->last_mft_change_time = si->last_access_time = si->creation_time;

	if (!S_ISREG(mode) && !S_ISDIR(mode))
		si->file_attributes = FILE_ATTR_SYSTEM;
	if (needs_reparse) {
		si->file_attributes |= FILE_ATTR_REPARSE_POINT;
		if (!S_ISLNK(mode))
			si->file_attributes |= FILE_ATTRIBUTE_RECALL_ON_OPEN;
	}

	/* Add STANDARD_INFORMATION to inode. */
	if (log_handle)
		err = ntfs_attr_add_transacted(log_handle, ni,
				AT_STANDARD_INFORMATION, AT_UNNAMED, 0, (u8 *)si,
				si_len);
	else
		err = ntfs_attr_add(ni, AT_STANDARD_INFORMATION, AT_UNNAMED, 0,
				(u8 *)si, si_len);
	if (err) {
		ntfs_error(sb, "Failed to add STANDARD_INFORMATION attribute.\n");
		goto err_out;
	}

	err = ntfs_sd_add_everyone(log_handle, ni);
	if (err) {
		ntfs_error(sb,
			"Create failed to add SECURITY_DESCRIPTOR (error %d).", err);
		goto err_out;
	}
	if (!log_handle)
		rollback_sd = true;

	if (S_ISDIR(mode)) {
		struct index_root *ir = NULL;
		struct index_entry *ie;
		int ir_len, index_len;

		/* Create struct index_root attribute. */
		index_len = sizeof(struct index_header) + sizeof(struct index_entry_header);
		ir_len = offsetof(struct index_root, index) + index_len;
		ir = kzalloc(ir_len, GFP_NOFS);
		if (!ir) {
			err = -ENOMEM;
			goto err_out;
		}
		ir->type = AT_FILE_NAME;
		ir->collation_rule = COLLATION_FILE_NAME;
		ir->index_block_size = cpu_to_le32(ni->vol->index_record_size);
		if (ni->vol->cluster_size <= ni->vol->index_record_size)
			ir->clusters_per_index_block =
				NTFS_B_TO_CLU(vol, ni->vol->index_record_size);
		else
			ir->clusters_per_index_block =
				ni->vol->index_record_size >> NTFS_BLOCK_SIZE_BITS;
		ir->index.entries_offset = cpu_to_le32(sizeof(struct index_header));
		ir->index.index_length = cpu_to_le32(index_len);
		ir->index.allocated_size = cpu_to_le32(index_len);
		ie = (struct index_entry *)((u8 *)ir + sizeof(struct index_root));
		ie->length = cpu_to_le16(sizeof(struct index_entry_header));
		ie->key_length = 0;
		ie->flags = INDEX_ENTRY_END;

		/* Add struct index_root attribute to inode. */
		if (log_handle)
			err = ntfs_attr_add_transacted(log_handle, ni,
					AT_INDEX_ROOT, I30, 4, (u8 *)ir, ir_len);
		else
			err = ntfs_attr_add(ni, AT_INDEX_ROOT, I30, 4,
					(u8 *)ir, ir_len);
		if (err) {
			kfree(ir);
			ntfs_error(vi->i_sb,
				"Create failed to add INDEX_ROOT attribute (error %d).",
				err);
			goto err_out;
		}
		kfree(ir);
		err = ntfs_attr_open(ni, AT_INDEX_ROOT, I30, 4);
		if (err) {
			ntfs_error(sb,
				"Create failed to open INDEX_ROOT attribute (error %d).",
				err);
			goto err_out;
		}
	} else {
		/* Add DATA attribute to inode. */
		if (log_handle)
			err = ntfs_attr_add_transacted(log_handle, ni, AT_DATA,
					AT_UNNAMED, 0, NULL, 0);
		else
			err = ntfs_attr_add(ni, AT_DATA, AT_UNNAMED, 0, NULL, 0);
		if (err) {
			ntfs_error(dir_ni->vol->sb,
				"Create failed to add DATA attribute (error %d).", err);
			goto err_out;
		}
		created_data = true;
		if (!log_handle)
			rollback_data = true;

		err = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
		if (err) {
			ntfs_error(sb,
				"Create failed to open DATA attribute (error %d).", err);
			goto err_out;
		}
	}
	if (log_handle && needs_reparse) {
		struct reparse_point rp = {};

		err = ntfs_attr_add_transacted(log_handle, ni, AT_REPARSE_POINT,
				AT_UNNAMED, 0, (u8 *)&rp, sizeof(rp));
		if (err) {
			ntfs_error(sb,
				"Create failed to add REPARSE_POINT attribute (error %d).",
				err);
			goto err_out;
		}
	}
	if (log_handle) {
		err = ntfs_ea_add_wsl_transacted(log_handle, vi, dev, &ea_size,
				NTFS_EA_UID | NTFS_EA_GID | NTFS_EA_MODE);
		if (err) {
			ntfs_error(sb,
				"Create failed to add initial WSL EA attributes (error %d).",
				err);
			goto err_out;
		}
		created_ea = true;
	}

	if (needs_reparse) {
		int reparse_err;

		if (journal_create) {
			unmap_mft_record(ni);
			ni_mrec = NULL;
			mutex_unlock(&dir_ni->mrec_lock);
			mutex_unlock(&ni->mrec_lock);
		}
		if (S_ISLNK(mode)) {
			if (journal_create) {
				if (NVolSymlinkNative(vol))
					reparse_err =
						ntfs_reparse_set_native_symlink_transacted(
							log_handle, ni, target,
							target_len, &native_target);
				else
					reparse_err =
						ntfs_reparse_set_wsl_symlink_transacted(
							log_handle, ni, target,
							target_len,
							&converted_target);
			} else if (NVolSymlinkNative(vol)) {
				reparse_err = ntfs_reparse_set_native_symlink(ni,
						target, target_len);
			} else {
				reparse_err = ntfs_reparse_set_wsl_symlink(ni,
						target, target_len);
			}
		} else {
			ni->flags = FILE_ATTRIBUTE_RECALL_ON_OPEN;
			if (journal_create)
				reparse_err =
					ntfs_reparse_set_wsl_not_symlink_transacted(
						log_handle, ni, mode);
			else
				reparse_err = ntfs_reparse_set_wsl_not_symlink(ni,
						mode);
		}
		if (journal_create) {
			mutex_lock_nested(&ni->mrec_lock,
					NTFS_INODE_MUTEX_NORMAL);
			mutex_lock_nested(&dir_ni->mrec_lock,
					NTFS_INODE_MUTEX_PARENT);
			ni_mrec = map_mft_record(ni);
			if (IS_ERR(ni_mrec)) {
				err = PTR_ERR(ni_mrec);
				ni_mrec = NULL;
				ntfs_error(sb,
					"Create failed to remap new MFT record (error %d).",
					err);
				goto err_out;
			}
		}
		err = reparse_err;
		if (!err) {
			reparse_present = true;
			ni->flags |= FILE_ATTR_REPARSE_POINT;
			if (!journal_create)
				rollback_reparse = true;
		}
	}
	if (err) {
		ntfs_error(sb, "Create reparse setup failed (error %d).", err);
		goto err_out;
	}

	if (!journal_create) {
		err = ntfs_ea_set_wsl_inode(vi, dev, &ea_size,
				NTFS_EA_UID | NTFS_EA_GID | NTFS_EA_MODE);
		if (err) {
			ntfs_error(sb,
				"Create failed to set initial WSL EA attributes (error %d).",
				err);
			goto err_out;
		}
	}

#ifdef CONFIG_NTFS_FS_POSIX_ACL
	if (init_acl) {
		err = ntfs_init_acl(log_handle, vi, default_acl, acl, &ea_size);
		if (err)
			goto err_out;
	}
#endif

	/* Create FILE_NAME attribute. */
	fn_len = sizeof(struct file_name_attr) + name_len * sizeof(__le16);
	fn = kzalloc(fn_len, GFP_NOFS);
	if (!fn) {
		err = -ENOMEM;
		goto err_out;
	}

	fn->file_attributes |= ni->flags;
	fn->parent_directory = parent_mft_ref;
	fn->file_name_length = name_len;
	fn->file_name_type = FILE_NAME_POSIX;
	fn->type.ea.packed_ea_size = ea_size;
	if (S_ISDIR(mode)) {
		fn->file_attributes = FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT;
		fn->allocated_size = fn->data_size = 0;
	} else {
		fn->data_size = cpu_to_le64(ntfs_inode_recorded_data_size(ni));
		fn->allocated_size = cpu_to_le64(ni->allocated_size);
	}
	if (!S_ISREG(mode) && !S_ISDIR(mode)) {
		fn->file_attributes = FILE_ATTR_SYSTEM;
		if (reparse_present)
			fn->file_attributes |= FILE_ATTR_REPARSE_POINT;
	}
	if (NVolHideDotFiles(vol) && name_len > 0 && name[0] == cpu_to_le16('.'))
		fn->file_attributes |= FILE_ATTR_HIDDEN;
	fn->creation_time = fn->last_data_change_time = utc2ntfs(ni->i_crtime);
	fn->last_mft_change_time = fn->last_access_time = fn->creation_time;
	memcpy(fn->file_name, name, name_len * sizeof(__le16));
	/* Add FILE_NAME attribute to inode. */
	if (log_handle)
		err = ntfs_attr_add_transacted(log_handle, ni, AT_FILE_NAME,
				AT_UNNAMED, 0, (u8 *)fn, fn_len);
	else
		err = ntfs_attr_add(ni, AT_FILE_NAME, AT_UNNAMED, 0,
				(u8 *)fn, fn_len);
	if (err) {
		ntfs_error(sb,
			"Create failed to add FILE_NAME attribute (error %d).", err);
		goto err_out;
	}

	child_mft_ref = MK_MREF(ni->mft_no,
				le16_to_cpu(ni_mrec->sequence_number));
	err = ntfs_mft_set_link_count(log_handle, ni, ni_mrec, 1);
	if (err)
		goto err_out;

	/* Add FILE_NAME attribute to index. */
	if (log_handle)
		err = ntfs_index_add_filename_transacted(log_handle, dir_ni, fn,
				child_mft_ref);
	else
		err = ntfs_index_add_filename(dir_ni, fn, child_mft_ref);
	if (err) {
		ntfs_error(sb,
			"Create failed to add FILE_NAME index entry (error %d).", err);
		goto err_out;
	}
	if (log_handle) {
		unmap_mft_record(ni);
		ni_mrec = NULL;
		err = ntfs_log_commit(log_handle);
		log_handle = NULL;
		if (err) {
			ntfs_error(sb,
				"Create transaction commit failed (error %d).", err);
			mft_allocation_aborted = true;
			mft_allocation_pending = false;
			goto err_out;
		}
		mft_allocation_pending = false;
		rollback_sd = true;
		rollback_data = created_data;
		if (created_ea)
			NInoSetHasEA(ni);
		if (converted_target) {
			ni->target = converted_target;
			converted_target = NULL;
		}
		if (native_target) {
			ni->target = native_target;
			native_target = NULL;
		}
	}

	if (ni_mrec)
		unmap_mft_record(ni);
	mutex_unlock(&dir_ni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);
	if (system_index_locked)
		mutex_unlock(&vol->system_index_lock);

	ni->flags = fn->file_attributes |
		    (ni->flags & FILE_ATTRIBUTE_RECALL_ON_OPEN);
	/* Set the sequence number. */
	vi->i_generation = ni->seq_no;
	set_nlink(vi, 1);
	ntfs_set_vfs_operations(vi, mode, dev);

	/* Done! */
	kfree(fn);
	kfree(si);
#ifdef CONFIG_NTFS_FS_POSIX_ACL
	posix_acl_release(default_acl);
	posix_acl_release(acl);
#endif
	ntfs_debug("Done.\n");
	return ni;

err_out:
	/*
	 * The MFT number can be reused as soon as the allocation is undone.
	 * Do not leave attribute inodes from the failed create in the hash.
	 */
	ntfs_unhash_inode_attributes(ni);
	if (log_handle) {
		int abort_err;

		if (mft_allocation_pending && ni_mrec) {
			unmap_mft_record(ni);
			ni_mrec = NULL;
		}
		abort_err = ntfs_log_abort(log_handle);
		log_handle = NULL;
		if (mft_allocation_pending) {
			mft_allocation_aborted = true;
			mft_allocation_pending = false;
		}
		if (abort_err) {
			ntfs_error(sb,
				"Failed to abort create transaction (error %i).",
				abort_err);
			NVolSetErrors(vol);
			err = abort_err;
		}
	}
	kfree(converted_target);
	kfree(native_target);
	if (rollback_sd) {
		int rollback_err;

		rollback_err = ntfs_attr_remove(ni,
				AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0,
				&rollback_sd_vi);
		if (rollback_err)
			ntfs_error(sb,
				"Failed to roll back security descriptor.\n");
	}

	if (rollback_data) {
		int rollback_err;

		rollback_err = ntfs_attr_remove(ni, AT_DATA, AT_UNNAMED,
				0, &rollback_data_vi);
		if (rollback_err)
			ntfs_error(sb, "Failed to roll back DATA attribute.\n");
	}

	if (rollback_reparse && vol->journal) {
		int cleanup_err;

		if (ni_mrec) {
			unmap_mft_record(ni);
			ni_mrec = NULL;
		}
		mutex_unlock(&dir_ni->mrec_lock);
		mutex_unlock(&ni->mrec_lock);
		cleanup_err = ntfs_delete_reparse_index(ni);
		if (cleanup_err < 0) {
			ntfs_error(sb,
				"Failed to roll back reparse index (error %i).",
				cleanup_err);
			NVolSetErrors(vol);
		}
		mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
		mutex_lock_nested(&dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
		ni_mrec = map_mft_record(ni);
		if (IS_ERR(ni_mrec)) {
			ntfs_error(sb,
				"Failed to remap new inode during create rollback.");
			NVolSetErrors(vol);
			ni_mrec = NULL;
		}
		rollback_reparse = false;
	}
	if (rollback_reparse)
		ntfs_delete_reparse_index(ni);
	ntfs_unhash_inode_attributes(ni);
	/*
	 * Free extent MFT records (should not exist any with current
	 * ntfs_create implementation, but for any case if something will be
	 * changed in the future).
	 */
	while (!mft_allocation_aborted && ni->nr_extents != 0) {
		int err2;

		err2 = ntfs_mft_record_free(ni->vol, *(ni->ext.extent_ntfs_inos));
		if (err2)
			ntfs_error(sb,
				"Failed to free extent MFT record. Leaving inconsistent metadata.\n");
		ntfs_inode_close(*(ni->ext.extent_ntfs_inos));
	}
	if (!mft_allocation_aborted && ntfs_mft_record_free(ni->vol, ni))
		ntfs_error(sb,
			"Failed to free MFT record. Leaving inconsistent metadata. Run chkdsk.\n");
	if (ni_mrec)
		unmap_mft_record(ni);
	kfree(fn);
	kfree(si);

	mutex_unlock(&dir_ni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);
	if (system_index_locked)
		mutex_unlock(&vol->system_index_lock);

	if (rollback_data_vi)
		iput(rollback_data_vi);
	if (rollback_sd_vi)
		iput(rollback_sd_vi);
#ifdef CONFIG_NTFS_FS_POSIX_ACL
	posix_acl_release(default_acl);
	posix_acl_release(acl);
#endif
	remove_inode_hash(vi);
	discard_new_inode(vi);
	return ERR_PTR(err);

free_unhashed_record:
	if (system_index_locked)
		mutex_unlock(&vol->system_index_lock);
#ifdef CONFIG_NTFS_FS_POSIX_ACL
	posix_acl_release(default_acl);
	posix_acl_release(acl);
#endif
	iput(vi);
	return ERR_PTR(err);
}

static int ntfs_create(const struct mnt_idmap *idmap, struct inode *dir,
		struct dentry *dentry, umode_t mode)
{
	struct ntfs_volume *vol = NTFS_SB(dir->i_sb);
	struct ntfs_inode *ni;
	struct inode *stream_vi = NULL;
	__le16 *uname, *base_name = NULL, *stream_name = NULL;
	int uname_len, stream_len, path_result, err;

	if (NVolShutdown(vol))
		return -EIO;

	path_result = ntfs_stream_path_names(vol, &dentry->d_name, &base_name,
			&uname_len, &stream_name, &stream_len);
	if (path_result) {
		if (path_result < 0)
			return path_result;
		stream_vi = ntfs_create_named_stream(idmap, dir, base_name,
				uname_len, stream_name, stream_len);
		if (IS_ERR(stream_vi)) {
			err = PTR_ERR(stream_vi);
			goto out_free_stream_names;
		}
		kmem_cache_free(ntfs_name_cache, stream_name);
		kmem_cache_free(ntfs_name_cache, base_name);
		d_instantiate(dentry, stream_vi);
		return 0;

out_free_stream_names:
		kmem_cache_free(ntfs_name_cache, stream_name);
		kmem_cache_free(ntfs_name_cache, base_name);
		return err;
	}

	uname_len = ntfs_nlstoucs(vol, dentry->d_name.name, dentry->d_name.len,
				  &uname, NTFS_MAX_NAME_LEN);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(vol->sb, "Failed to convert name to unicode.");
		return uname_len;
	}

	err = ntfs_check_bad_windows_name(vol, uname, uname_len);
	if (err) {
		kmem_cache_free(ntfs_name_cache, uname);
		return err;
	}

	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	ni = __ntfs_create(idmap, dir, uname, uname_len, S_IFREG | mode, 0,
			NULL, 0);
	kmem_cache_free(ntfs_name_cache, uname);
	if (IS_ERR(ni)) {
		err = PTR_ERR(ni);
		ntfs_error(dir->i_sb,
			"Create failed for inode name length %u (error %d).",
			dentry->d_name.len, err);
		return err;
	}

	d_instantiate_new(dentry, VFS_I(ni));

	return 0;
}

static int ntfs_check_unlinkable_dir(struct ntfs_attr_search_ctx *ctx, struct file_name_attr *fn)
{
	int link_count;
	int ret;
	struct ntfs_inode *ni = ctx->base_ntfs_ino ? ctx->base_ntfs_ino : ctx->ntfs_ino;
	struct mft_record *ni_mrec = ctx->base_mrec ? ctx->base_mrec : ctx->mrec;

	ret = ntfs_check_empty_dir(ni, ni_mrec);
	if (!ret || ret != -ENOTEMPTY)
		return ret;

	link_count = le16_to_cpu(ni_mrec->link_count);
	/*
	 * Directory is non-empty, so we can unlink only if there is more than
	 * one "real" hard link, i.e. links aren't different DOS and WIN32 names
	 */
	if ((link_count == 1) ||
	    (link_count == 2 && fn->file_name_type == FILE_NAME_DOS)) {
		ret = -ENOTEMPTY;
		ntfs_debug("Non-empty directory without hard links\n");
		goto no_hardlink;
	}

	ret = 0;
no_hardlink:
	return ret;
}

static int ntfs_test_inode_attr(struct inode *vi, void *data)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	u64 mft_no = (u64)(uintptr_t)data;

	if (ni->mft_no != mft_no)
		return 0;
	if (!READ_ONCE(vi->i_nlink))
		return 0;
	if (NInoAttr(ni) || ni->nr_extents == -1)
		return 1;
	return 0;
}

static void ntfs_cleanup_deleted_inode(struct ntfs_inode *ni)
{
	struct inode *attr_vi;
	struct super_block *sb = VFS_I(ni)->i_sb;

	if (!NInoBeingDeleted(ni))
		return;

	while ((attr_vi = ilookup5(sb, ni->mft_no, ntfs_test_inode_attr,
			(void *)(uintptr_t)ni->mft_no))) {
		struct ntfs_inode *attr_ni = NTFS_I(attr_vi);

		if (ntfs_inode_is_named_stream(attr_ni)) {
			if (atomic_read(&attr_ni->stream_open_count) > 0)
				NInoSetStreamUnlinked(attr_ni);
			remove_inode_hash(attr_vi);
		}
		clear_nlink(attr_vi);
		iput(attr_vi);
	}
}

static void ntfs_delete_metadata_post_commit(struct ntfs_inode *ni)
{
	NInoSetBeingDeleted(ni);
	ntfs_delete_reparse_index(ni);
	ntfs_delete_object_id_index(ni);
}

struct ntfs_deleted_attribute {
	struct ntfs_deleted_attribute *next;
	__le32 type;
	u8 name_len;
	__le16 name[];
};

int ntfs_reclaim_deleted_attributes(struct ntfs_inode *ni, bool recovery)
{
	struct ntfs_deleted_attribute *attributes = NULL;
	struct ntfs_deleted_attribute **attributes_tail = &attributes;
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_deleted_attribute *entry;
	struct ntfs_deleted_attribute *next;
	struct inode *attr_vi;
	struct ntfs_attr na;
	struct attr_record *attr;
	__le16 *name;
	size_t name_bytes;
	u32 attr_len;
	u16 name_off;
	int err;
	int first_err = 0;
	bool enumeration_error = false;

	if (!ni->vol->journal || !NInoBeingDeleted(ni))
		return 0;
	mutex_lock(&ni->mrec_lock);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unlock;
	}
	while (!(err = ntfs_attrs_walk(ctx))) {
		attr = ctx->attr;
		if (!attr->non_resident ||
		    !ntfs_deleted_attribute_reclaimable(attr->type,
			    attr->name_length) ||
		    le64_to_cpu(attr->data.non_resident.lowest_vcn))
			continue;
		attr_len = le32_to_cpu(attr->length);
		name_off = le16_to_cpu(attr->name_offset);
		name_bytes = attr->name_length * sizeof(__le16);
		if (name_off > attr_len || name_bytes > attr_len - name_off) {
			err = -EIO;
			break;
		}
		entry = kmalloc(struct_size(entry, name, attr->name_length),
				GFP_NOFS);
		if (!entry) {
			err = -ENOMEM;
			break;
		}
		entry->next = NULL;
		entry->type = attr->type;
		entry->name_len = attr->name_length;
		memcpy(entry->name, (u8 *)attr + name_off, name_bytes);
		*attributes_tail = entry;
		attributes_tail = &entry->next;
	}
	ntfs_attr_put_search_ctx(ctx);
out_unlock:
	mutex_unlock(&ni->mrec_lock);
	if (err != -ENOENT) {
		first_err = err;
		enumeration_error = true;
	}

	for (entry = attributes; entry; entry = next) {
		next = entry->next;
		name = entry->name_len ? entry->name : AT_UNNAMED;
		na = (struct ntfs_attr) {
			.mft_no = ni->mft_no,
			.name = name,
			.name_len = entry->name_len,
			.type = entry->type,
		};
		attr_vi = ilookup5(ni->vol->sb, ni->mft_no, ntfs_test_inode,
				&na);
		if (!attr_vi) {
			if (entry->type == AT_INDEX_ALLOCATION) {
				mutex_lock(&ni->mrec_lock);
				attr_vi = ntfs_index_iget(VFS_I(ni), name,
						entry->name_len);
				mutex_unlock(&ni->mrec_lock);
			} else {
				attr_vi = ntfs_attr_iget(VFS_I(ni), entry->type,
						name, entry->name_len);
			}
		}
		if (IS_ERR(attr_vi)) {
			err = PTR_ERR(attr_vi);
			if (err != -ENOENT && !first_err)
				first_err = err;
		} else {
			struct ntfs_inode *attr_ni = NTFS_I(attr_vi);
			bool stream_open = ntfs_inode_is_named_stream(attr_ni) &&
					atomic_read(&attr_ni->stream_open_count) > 0;

			if (recovery &&
			    (stream_open || atomic_read(&attr_vi->i_count) != 1)) {
				if (!first_err)
					first_err = -EBUSY;
			} else {
				if (ntfs_inode_is_named_stream(attr_ni)) {
					if (stream_open)
						NInoSetStreamUnlinked(attr_ni);
					remove_inode_hash(attr_vi);
				}
				clear_nlink(attr_vi);
				if (!stream_open &&
				    atomic_read(&attr_vi->i_count) == 1) {
					err = ntfs_reclaim_deleted_attribute(
							attr_vi);
					if (err && !first_err)
						first_err = err;
				}
			}
			iput(attr_vi);
		}
		kfree(entry);
	}
	if (first_err) {
		if (enumeration_error)
			ntfs_warning(ni->vol->sb,
				"Failed to enumerate deleted attributes (error %d).",
				first_err);
		else
			ntfs_warning(ni->vol->sb,
				"Failed to reclaim deleted attributes (error %d).",
				first_err);
	}
	return first_err;
}

static void ntfs_delete_attr_inodes_post_commit(struct ntfs_inode *ni)
{
	ntfs_reclaim_deleted_attributes(ni, false);
	ntfs_cleanup_deleted_inode(ni);
}

static int ntfs_has_system_index_entry(struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *ctx;
	struct mft_record *mrec;
	int err;

	if (ni->flags & FILE_ATTR_REPARSE_POINT)
		return 1;
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	ctx = ntfs_attr_get_search_ctx(ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}
	err = ntfs_attr_lookup(AT_OBJECT_ID, AT_UNNAMED, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx);
	ntfs_attr_put_search_ctx(ctx);
	if (!err)
		err = 1;
	else if (err == -ENOENT)
		err = 0;
out_unmap:
	unmap_mft_record(ni);
	return err;
}

static int ntfs_prepare_system_index_removals(struct ntfs_inode *ni,
		struct ntfs_system_index_ctx *reparse,
		struct ntfs_system_index_ctx *object_id)
{
	int err;

	err = ntfs_prepare_reparse_index_remove(ni, reparse);
	if (err)
		return err;
	return ntfs_prepare_object_id_index_remove(ni, object_id);
}

static int ntfs_system_index_remove_log_credits(struct ntfs_inode *ni)
{
	int credits;
	int extra_credits;

	credits = ntfs_reparse_index_remove_log_credits(ni);
	if (credits < 0)
		return credits;
	extra_credits = ntfs_object_id_index_remove_log_credits(ni);
	if (extra_credits < 0 || check_add_overflow(credits, extra_credits,
			&credits))
		return extra_credits < 0 ? extra_credits : -EOVERFLOW;
	return credits;
}

static int ntfs_delete_transaction_credits(struct ntfs_inode *ni,
		struct ntfs_inode *dir_ni)
{
	int credits;
	int extra_credits;

	credits = ntfs_filename_log_credits(ni->vol, NTFS_MAX_NAME_LEN, 2,
					    true);
	if (credits < 0)
		return credits;
	if (NInoAttrList(ni)) {
		extra_credits = ntfs_filename_attrlist_extra_credits(ni->vol, 2);
		if (extra_credits < 0 || check_add_overflow(credits,
				extra_credits, &credits))
			return extra_credits < 0 ? extra_credits : -EOVERFLOW;
	}
	if (NInoAttrList(dir_ni)) {
		extra_credits = ntfs_index_attrlist_log_credits(ni->vol, 2);
		if (extra_credits < 0 || check_add_overflow(credits,
				extra_credits, &credits))
			return extra_credits < 0 ? extra_credits : -EOVERFLOW;
	}
	extra_credits = ntfs_system_index_remove_log_credits(ni);
	if (extra_credits < 0 || check_add_overflow(credits, extra_credits,
			&credits))
		return extra_credits < 0 ? extra_credits : -EOVERFLOW;
	return credits;
}

/*
 * ntfs_delete - delete file or directory from ntfs volume
 * @log_handle: caller-owned transaction handle, or NULL
 * @ni:         ntfs inode for object to delte
 * @dir_ni:     ntfs inode for directory in which delete object
 * @name:       unicode name of the object to delete
 * @name_len:   length of the name in unicode characters
 * @need_lock:  whether mrec lock is needed or not
 * @link_count_zero_out: deferred deletion result for caller transaction
 *
 * Delete the specified name from the directory index @dir_ni and decrement
 * the link count of the target inode @ni.
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_delete(struct ntfs_log_handle *log_handle,
		struct ntfs_inode *ni, struct ntfs_inode *dir_ni, __le16 *name,
		u8 name_len, bool need_lock, bool *link_count_zero_out)
{
	struct ntfs_attr_search_ctx *actx = NULL;
	struct file_name_attr *fn = NULL;
	struct mft_record *ni_before = NULL, *dir_before = NULL;
	struct mft_record *dir_mrec = NULL;
	struct ntfs_index_size_snapshot dir_size_before;
	bool looking_for_dos_name = false, looking_for_win32_name = false;
	bool case_sensitive_match = true;
	bool link_count_zero = false;
	int err = 0;
	struct mft_record *ni_mrec;
	struct super_block *sb;
	bool own_transaction = false;
	bool external_transaction = log_handle != NULL;
	unsigned int nlink_before = 0;
	u16 next_link_count;

	ntfs_debug("Entering.\n");
	if (link_count_zero_out)
		*link_count_zero_out = false;
	if (external_transaction && (need_lock || !link_count_zero_out))
		return -EINVAL;
	if (need_lock && ni->vol->journal) {
		int credits = ntfs_delete_transaction_credits(ni, dir_ni);

		if (credits < 0)
			return credits;
		log_handle = ntfs_log_begin(ni->vol, credits);
		if (IS_ERR(log_handle))
			return PTR_ERR(log_handle);
		own_transaction = true;
	}

	if (need_lock == true) {
		mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
		mutex_lock_nested(&dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
	}

	sb = dir_ni->vol->sb;

	if (ni->nr_extents == -1)
		ni = ni->ext.base_ntfs_ino;
	if (dir_ni->nr_extents == -1)
		dir_ni = dir_ni->ext.base_ntfs_ino;
	/*
	 * Search for FILE_NAME attribute with such name. If it's in POSIX or
	 * WIN32_AND_DOS namespace, then simply remove it from index and inode.
	 * If filename in DOS or in WIN32 namespace, then remove DOS name first,
	 * only then remove WIN32 name.
	 */
	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		ntfs_error(sb, "%s, Failed to get search context", __func__);
		err = -ENOMEM;
		goto err_out;
	}
	if (own_transaction) {
		ni_mrec = actx->base_mrec ? actx->base_mrec : actx->mrec;
		ni_before = kmemdup(ni_mrec, ni->vol->mft_record_size, GFP_NOFS);
		if (!ni_before) {
			err = -ENOMEM;
			goto err_out;
		}
		dir_mrec = map_mft_record(dir_ni);
		if (IS_ERR(dir_mrec)) {
			err = PTR_ERR(dir_mrec);
			dir_mrec = NULL;
			goto err_out;
		}
		dir_before = kmemdup(dir_mrec, ni->vol->mft_record_size,
				GFP_NOFS);
		if (!dir_before) {
			err = -ENOMEM;
			goto err_out;
		}
		ntfs_index_size_snapshot(dir_ni, &dir_size_before);
		nlink_before = VFS_I(ni)->i_nlink;
	}
search:
	while ((err = ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE,
				0, NULL, 0, actx)) == 0) {
#ifdef DEBUG
		unsigned char *s;
#endif
		bool case_sensitive = IGNORE_CASE;

		fn = (struct file_name_attr *)((u8 *)actx->attr +
				le16_to_cpu(actx->attr->data.resident.value_offset));
#ifdef DEBUG
		s = ntfs_attr_name_get(ni->vol, fn->file_name, fn->file_name_length);
		ntfs_debug("name: '%s'  type: %d  dos: %d  win32: %d case: %d\n",
				s, fn->file_name_type,
				looking_for_dos_name, looking_for_win32_name,
				case_sensitive_match);
		ntfs_attr_name_free(&s);
#endif
		if (looking_for_dos_name) {
			if (fn->file_name_type == FILE_NAME_DOS)
				break;
			continue;
		}
		if (looking_for_win32_name) {
			if  (fn->file_name_type == FILE_NAME_WIN32)
				break;
			continue;
		}

		/* Ignore hard links from other directories */
		if (dir_ni->mft_no != MREF_LE(fn->parent_directory)) {
			ntfs_debug("MFT record numbers don't match (%llu != %lu)\n",
					dir_ni->mft_no,
					MREF_LE(fn->parent_directory));
			continue;
		}

		if (fn->file_name_type == FILE_NAME_POSIX || case_sensitive_match)
			case_sensitive = CASE_SENSITIVE;

		if (ntfs_names_are_equal(fn->file_name, fn->file_name_length,
					name, name_len, case_sensitive,
					ni->vol->upcase, ni->vol->upcase_len)) {
			if (fn->file_name_type == FILE_NAME_WIN32) {
				looking_for_dos_name = true;
				ntfs_attr_reinit_search_ctx(actx);
				continue;
			}
			if (fn->file_name_type == FILE_NAME_DOS)
				looking_for_dos_name = true;
			break;
		}
	}
	if (err) {
		/*
		 * If case sensitive search failed, then try once again
		 * ignoring case.
		 */
		if (err == -ENOENT && case_sensitive_match) {
			case_sensitive_match = false;
			ntfs_attr_reinit_search_ctx(actx);
			goto search;
		}
		goto err_out;
	}

	err = ntfs_check_unlinkable_dir(actx, fn);
	if (err)
		goto err_out;

	if (log_handle)
		err = ntfs_index_remove_transacted(log_handle, dir_ni, fn,
				le32_to_cpu(actx->attr->data.resident.value_length));
	else
		err = ntfs_index_remove(dir_ni, fn,
				le32_to_cpu(actx->attr->data.resident.value_length));
	if (err)
		goto err_out;

	ni_mrec = actx->base_mrec ? actx->base_mrec : actx->mrec;
	next_link_count = le16_to_cpu(ni_mrec->link_count) - 1;
	if (log_handle)
		err = ntfs_attr_record_rm_transacted(log_handle, actx);
	else
		err = ntfs_attr_record_rm(actx);
	if (err)
		goto err_out;

	ni_mrec = actx->base_mrec ? actx->base_mrec : actx->mrec;
	err = ntfs_mft_set_link_count(log_handle, ni, ni_mrec,
			next_link_count);
	if (err)
		goto err_out;
	if (!S_ISDIR(VFS_I(ni)->i_mode))
		drop_nlink(VFS_I(ni));

	if (looking_for_dos_name) {
		looking_for_dos_name = false;
		looking_for_win32_name = true;
		ntfs_attr_reinit_search_ctx(actx);
		goto search;
	}
	if (own_transaction) {
		err = ntfs_log_commit(log_handle);
		log_handle = NULL;
		if (err)
			goto err_out;
		unmap_mft_record(dir_ni);
		dir_mrec = NULL;
		kfree(ni_before);
		ni_before = NULL;
		kfree(dir_before);
		dir_before = NULL;
	}

	/*
	 * For directories, Drop VFS nlink only when mft record link count
	 * becomes zero. Because we fixes VFS nlink to 1 for directories.
	 */
	if (S_ISDIR(VFS_I(ni)->i_mode) && !le16_to_cpu(ni_mrec->link_count))
		drop_nlink(VFS_I(ni));

	/*
	 * If hard link count is not equal to zero then we are done. In other
	 * case there are no reference to this inode left, so we should free all
	 * non-resident attributes and mark all MFT record as not in use.
	 */
	if (ni_mrec->link_count == 0) {
		link_count_zero = true;
		if (!external_transaction)
			NInoSetBeingDeleted(ni);
		if (link_count_zero_out)
			*link_count_zero_out = true;
	}

	ntfs_attr_put_search_ctx(actx);
	if (need_lock == true) {
		mutex_unlock(&dir_ni->mrec_lock);
		mutex_unlock(&ni->mrec_lock);
	}

	if (link_count_zero && !external_transaction) {
		ntfs_delete_metadata_post_commit(ni);
		if (need_lock)
			ntfs_delete_attr_inodes_post_commit(ni);
	}
	ntfs_debug("Done.\n");
	return 0;
err_out:
	if (ni_before && actx) {
		ni_mrec = actx->base_mrec ? actx->base_mrec : actx->mrec;
		memcpy(ni_mrec, ni_before, ni->vol->mft_record_size);
		set_nlink(VFS_I(ni), nlink_before);
		mark_mft_record_dirty(ni);
	}
	if (dir_before && dir_mrec) {
		memcpy(dir_mrec, dir_before, ni->vol->mft_record_size);
		ntfs_index_size_restore(dir_ni, &dir_size_before);
		mark_mft_record_dirty(dir_ni);
	}
	if (own_transaction && log_handle) {
		int abort_err = ntfs_log_abort(log_handle);

		log_handle = NULL;
		if (abort_err) {
			ntfs_error(sb,
				"Failed to abort unlink transaction (error %i).",
				abort_err);
			NVolSetErrors(ni->vol);
			err = abort_err;
		}
	}
	if (dir_mrec)
		unmap_mft_record(dir_ni);
	kfree(ni_before);
	kfree(dir_before);
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	if (need_lock) {
		mutex_unlock(&dir_ni->mrec_lock);
		mutex_unlock(&ni->mrec_lock);
	}
	return err;
}

static int ntfs_delete_vfs(struct ntfs_inode *ni,
		struct ntfs_inode *dir_ni, __le16 *name, u8 name_len)
{
	struct ntfs_log_handle *handle;
	struct ntfs_mft_snapshot snapshots[2] = {};
	struct ntfs_system_index_ctx reparse = {}, object_id = {};
	unsigned int snapshot_count = 0;
	bool link_count_zero = false;
	bool system_index_locked = false;
	bool retry = false;
	bool had_reparse;
	int abort_err;
	int credits;
	int err;

	if (!ni->vol->journal)
		return ntfs_delete(NULL, ni, dir_ni, name, name_len, true, NULL);
retry:
	mutex_lock(&ni->mrec_lock);
	err = ntfs_has_system_index_entry(ni);
	mutex_unlock(&ni->mrec_lock);
	if (err < 0)
		return err;
	system_index_locked = err > 0;
	credits = ntfs_delete_transaction_credits(ni, dir_ni);
	if (credits < 0)
		return credits;
	handle = ntfs_log_begin(ni->vol, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	if (system_index_locked) {
		mutex_lock(&ni->vol->system_index_lock);
		err = ntfs_prepare_system_index_removals(ni, &reparse,
				&object_id);
		if (err)
			goto abort_unlocked;
	}
	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	mutex_lock_nested(&dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
	if (!system_index_locked) {
		err = ntfs_has_system_index_entry(ni);
		if (err > 0) {
			retry = true;
			err = -EAGAIN;
		}
		if (err)
			goto rollback;
	}
	had_reparse = ni->flags & FILE_ATTR_REPARSE_POINT;
	err = ntfs_mft_snapshot_take(snapshots, &snapshot_count,
			ARRAY_SIZE(snapshots), ni, false);
	if (!err)
		err = ntfs_mft_snapshot_take(snapshots, &snapshot_count,
				ARRAY_SIZE(snapshots), dir_ni, true);
	if (!err)
		err = ntfs_delete(handle, ni, dir_ni, name, name_len, false,
				&link_count_zero);
	if (!err && link_count_zero && system_index_locked) {
		err = ntfs_delete_reparse_index_transacted(handle, ni, &reparse);
		if (!err)
			err = ntfs_delete_object_id_index_transacted(handle, ni,
					&object_id);
	}
	if (err)
		goto rollback;
	err = ntfs_log_commit(handle);
	handle = NULL;
	if (err)
		goto rollback;
	ntfs_mft_snapshots_release(snapshots, snapshot_count);
	snapshot_count = 0;
	if (link_count_zero) {
		NInoSetBeingDeleted(ni);
		if (had_reparse) {
			ni->flags &= ~FILE_ATTR_REPARSE_POINT;
			NInoSetFileNameDirty(ni);
			mark_mft_record_dirty(ni);
		}
	}
	mutex_unlock(&dir_ni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);
	if (system_index_locked)
		mutex_unlock(&ni->vol->system_index_lock);
	ntfs_system_index_ctx_put(&object_id);
	ntfs_system_index_ctx_put(&reparse);
	if (link_count_zero)
		ntfs_delete_attr_inodes_post_commit(ni);
	return 0;

rollback:
	if (snapshot_count)
		ntfs_mft_snapshots_restore(snapshots, snapshot_count);
	if (handle) {
		abort_err = ntfs_log_abort(handle);
		if (abort_err) {
			err = abort_err;
			retry = false;
		}
	}
	ntfs_mft_snapshots_release(snapshots, snapshot_count);
	mutex_unlock(&dir_ni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);
	if (system_index_locked)
		mutex_unlock(&ni->vol->system_index_lock);
	ntfs_system_index_ctx_put(&object_id);
	ntfs_system_index_ctx_put(&reparse);
	if (retry) {
		retry = false;
		snapshot_count = 0;
		link_count_zero = false;
		goto retry;
	}
	return err;

abort_unlocked:
	abort_err = ntfs_log_abort(handle);
	if (abort_err)
		err = abort_err;
	mutex_unlock(&ni->vol->system_index_lock);
	ntfs_system_index_ctx_put(&object_id);
	ntfs_system_index_ctx_put(&reparse);
	return err;
}

static int ntfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *vi = dentry->d_inode;
	struct super_block *sb = dir->i_sb;
	struct ntfs_volume *vol = NTFS_SB(sb);
	int err = 0;
	struct ntfs_inode *ni = NTFS_I(vi);
	__le16 *uname = NULL;
	int uname_len;

	if (NVolShutdown(vol))
		return -EIO;

	if (ntfs_stream_path_has_colon(vol, &dentry->d_name))
		return ntfs_unlink_named_stream(dir, dentry);
	if (NInoAttr(ni))
		return -EOPNOTSUPP;

	uname_len = ntfs_nlstoucs(vol, dentry->d_name.name, dentry->d_name.len,
				  &uname, NTFS_MAX_NAME_LEN);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(sb, "Failed to convert name to Unicode.");
		return -ENOMEM;
	}

	err = ntfs_check_bad_windows_name(vol, uname, uname_len);
	if (err) {
		kmem_cache_free(ntfs_name_cache, uname);
		return err;
	}

	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	err = ntfs_delete_vfs(ni, NTFS_I(dir), uname, uname_len);
	if (err)
		goto out;

	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	mark_inode_dirty(dir);
	inode_set_ctime_to_ts(vi, inode_get_ctime(dir));
	if (vi->i_nlink)
		mark_inode_dirty(vi);
out:
	kmem_cache_free(ntfs_name_cache, uname);
	return err;
}

static struct dentry *ntfs_mkdir(const struct mnt_idmap *idmap, struct inode *dir,
		struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct ntfs_volume *vol = NTFS_SB(sb);
	int err = 0;
	struct ntfs_inode *ni;
	__le16 *uname;
	int uname_len;

	if (NVolShutdown(vol))
		return ERR_PTR(-EIO);

	err = ntfs_stream_path_check(vol, &dentry->d_name);
	if (err)
		return ERR_PTR(err);

	uname_len = ntfs_nlstoucs(vol, dentry->d_name.name, dentry->d_name.len,
				  &uname, NTFS_MAX_NAME_LEN);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(sb, "Failed to convert name to unicode.");
		return ERR_PTR(-ENOMEM);
	}

	err = ntfs_check_bad_windows_name(vol, uname, uname_len);
	if (err) {
		kmem_cache_free(ntfs_name_cache, uname);
		return ERR_PTR(err);
	}

	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	ni = __ntfs_create(idmap, dir, uname, uname_len, mode, 0,
			NULL, 0);
	kmem_cache_free(ntfs_name_cache, uname);
	if (IS_ERR(ni)) {
		err = PTR_ERR(ni);
		return ERR_PTR(err);
	}

	d_instantiate_new(dentry, VFS_I(ni));
	return NULL;
}

static int ntfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *vi = dentry->d_inode;
	struct super_block *sb = dir->i_sb;
	struct ntfs_volume *vol = NTFS_SB(sb);
	int err = 0;
	struct ntfs_inode *ni;
	__le16 *uname = NULL;
	int uname_len;

	if (NVolShutdown(vol))
		return -EIO;

	err = ntfs_stream_path_check(vol, &dentry->d_name);
	if (err)
		return err;

	ni = NTFS_I(vi);
	uname_len = ntfs_nlstoucs(vol, dentry->d_name.name, dentry->d_name.len,
				  &uname, NTFS_MAX_NAME_LEN);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(sb, "Failed to convert name to unicode.");
		return -ENOMEM;
	}

	err = ntfs_check_bad_windows_name(vol, uname, uname_len);
	if (err) {
		kmem_cache_free(ntfs_name_cache, uname);
		return err;
	}

	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	err = ntfs_delete_vfs(ni, NTFS_I(dir), uname, uname_len);
	if (err)
		goto out;

	inode_set_mtime_to_ts(vi, inode_set_atime_to_ts(vi, current_time(vi)));
out:
	kmem_cache_free(ntfs_name_cache, uname);
	return err;
}

/*
 * __ntfs_link - create hard link for file or directory
 * @log_handle:	reserved transaction handle, or NULL
 * @finish_transaction: commit or abort @log_handle in this helper
 * @ni:		ntfs inode for object to create hard link
 * @dir_ni:	ntfs inode for directory in which new link should be placed
 * @name:	unicode name of the new link
 * @name_len:	length of the name in unicode characters
 *
 * Create a new hard link. This involves adding an entry to the directory
 * index and adding a new FILE_NAME attribute to the target inode.
 *
 * Return 0 on success and -errno on error.
 */
static int __ntfs_link(struct ntfs_log_handle *log_handle,
		struct ntfs_inode *ni, struct ntfs_inode *dir_ni,
		__le16 *name, u8 name_len, bool finish_transaction)
{
	struct super_block *sb;
	struct inode *vi = VFS_I(ni);
	struct file_name_attr *fn = NULL;
	struct mft_record *ni_before = NULL, *dir_before = NULL;
	struct ntfs_index_size_snapshot dir_size_before;
	unsigned int nlink_before = 0;
	int fn_len, err = 0;
	struct mft_record *dir_mrec = NULL, *ni_mrec = NULL;
	u16 next_link_count;

	ntfs_debug("Entering.\n");

	sb = dir_ni->vol->sb;
	if (NInoBeingDeleted(dir_ni) || NInoBeingDeleted(ni)) {
		err = -ENOENT;
		goto err_out;
	}
	ni_mrec = map_mft_record(ni);
	if (IS_ERR(ni_mrec)) {
		err = -EIO;
		goto err_out;
	}

	if (le16_to_cpu(ni_mrec->link_count) == 0) {
		err = -ENOENT;
		goto err_out;
	}
	next_link_count = le16_to_cpu(ni_mrec->link_count) + 1;

	/* Create FILE_NAME attribute. */
	fn_len = sizeof(struct file_name_attr) + name_len * sizeof(__le16);

	fn = kzalloc(fn_len, GFP_NOFS);
	if (!fn) {
		err = -ENOMEM;
		goto err_out;
	}

	dir_mrec = map_mft_record(dir_ni);
	if (IS_ERR(dir_mrec)) {
		err = -EIO;
		dir_mrec = NULL;
		goto err_out;
	}

	fn->parent_directory = MK_LE_MREF(dir_ni->mft_no,
			le16_to_cpu(dir_mrec->sequence_number));
	fn->file_name_length = name_len;
	fn->file_name_type = FILE_NAME_POSIX;
	fn->file_attributes = ni->flags;
	if (ni_mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		fn->file_attributes |= FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT;
		fn->allocated_size = fn->data_size = 0;
	} else {
		if (NInoSparse(ni) || NInoCompressed(ni))
			fn->allocated_size =
				cpu_to_le64(ni->itype.compressed.size);
		else
			fn->allocated_size = cpu_to_le64(ni->allocated_size);
		fn->data_size = cpu_to_le64(ntfs_inode_recorded_data_size(ni));
	}
	if (NVolHideDotFiles(dir_ni->vol) && name_len > 0 && name[0] == cpu_to_le16('.'))
		fn->file_attributes |= FILE_ATTR_HIDDEN;

	fn->creation_time = utc2ntfs(ni->i_crtime);
	fn->last_data_change_time = utc2ntfs(inode_get_mtime(vi));
	fn->last_mft_change_time = utc2ntfs(inode_get_ctime(vi));
	fn->last_access_time = utc2ntfs(inode_get_atime(vi));
	memcpy(fn->file_name, name, name_len * sizeof(__le16));
	if (log_handle && finish_transaction) {
		ni_before = kmemdup(ni_mrec, ni->vol->mft_record_size, GFP_NOFS);
		if (!ni_before) {
			err = -ENOMEM;
			goto err_out;
		}
		dir_before = kmemdup(dir_mrec, ni->vol->mft_record_size,
				GFP_NOFS);
		if (!dir_before) {
			err = -ENOMEM;
			goto err_out;
		}
		ntfs_index_size_snapshot(dir_ni, &dir_size_before);
		nlink_before = vi->i_nlink;
	}
	if (log_handle) {
		err = ntfs_attr_add_transacted(log_handle, ni, AT_FILE_NAME,
				AT_UNNAMED, 0, (u8 *)fn, fn_len);
		if (err) {
			ntfs_error(sb, "Failed to add FILE_NAME attribute.\n");
			goto err_out;
		}
		err = ntfs_mft_set_link_count(log_handle, ni, ni_mrec,
				next_link_count);
		if (err)
			goto err_out;
		if (!S_ISDIR(vi->i_mode))
			inc_nlink(vi);

		err = ntfs_index_add_filename_transacted(log_handle, dir_ni, fn,
				MK_MREF(ni->mft_no,
					le16_to_cpu(ni_mrec->sequence_number)));
		if (err) {
			ntfs_error(sb, "Failed to add filename to the index");
			goto err_out;
		}
		if (finish_transaction) {
			err = ntfs_log_commit(log_handle);
			log_handle = NULL;
			if (err)
				goto err_out;
		}
		goto done;
	}

	/* Add FILE_NAME attribute to index. */
	err = ntfs_index_add_filename(dir_ni, fn, MK_MREF(ni->mft_no,
					le16_to_cpu(ni_mrec->sequence_number)));
	if (err) {
		ntfs_error(sb, "Failed to add filename to the index");
		goto err_out;
	}
	/* Add FILE_NAME attribute to inode. */
	err = ntfs_attr_add(ni, AT_FILE_NAME, AT_UNNAMED, 0, (u8 *)fn, fn_len);
	if (err) {
		ntfs_error(sb, "Failed to add FILE_NAME attribute.\n");
		/* Try to remove just added attribute from index. */
		if (ntfs_index_remove(dir_ni, fn, fn_len))
			goto rollback_failed;
		goto err_out;
	}
	/* Increment hard links count. */
	ni_mrec->link_count = cpu_to_le16(le16_to_cpu(ni_mrec->link_count) + 1);
	if (!S_ISDIR(vi->i_mode))
		inc_nlink(VFS_I(ni));

	/* Done! */
	mark_mft_record_dirty(ni);
done:
	kfree(fn);
	kfree(ni_before);
	kfree(dir_before);
	unmap_mft_record(dir_ni);
	unmap_mft_record(ni);

	ntfs_debug("Done.\n");

	return 0;
rollback_failed:
	ntfs_error(sb, "Rollback failed. Leaving inconsistent metadata.\n");
err_out:
	if (ni_before && ni_mrec) {
		memcpy(ni_mrec, ni_before, ni->vol->mft_record_size);
		set_nlink(vi, nlink_before);
		mark_mft_record_dirty(ni);
	}
	if (dir_before && dir_mrec) {
		memcpy(dir_mrec, dir_before, ni->vol->mft_record_size);
		ntfs_index_size_restore(dir_ni, &dir_size_before);
		mark_mft_record_dirty(dir_ni);
	}
	if (log_handle && finish_transaction) {
		int abort_err = ntfs_log_abort(log_handle);

		log_handle = NULL;
		if (abort_err) {
			ntfs_error(sb,
				"Failed to abort hard-link transaction (error %i).",
				abort_err);
			NVolSetErrors(ni->vol);
			err = abort_err;
		}
	}
	kfree(fn);
	kfree(ni_before);
	kfree(dir_before);
	if (dir_mrec)
		unmap_mft_record(dir_ni);
	if (!IS_ERR_OR_NULL(ni_mrec))
		unmap_mft_record(ni);
	return err;
}

static int ntfs_rename(const struct mnt_idmap *idmap, struct inode *old_dir,
		struct dentry *old_dentry, struct inode *new_dir,
		struct dentry *new_dentry, unsigned int flags)
{
	struct inode *old_inode, *new_inode = NULL;
	struct ntfs_log_handle *log_handle = NULL;
	struct ntfs_mft_snapshot snapshots[4] = {};
	struct ntfs_system_index_ctx reparse = {}, object_id = {};
	unsigned int snapshot_count = 0;
	int err = 0;
	int is_dir;
	int has_system_index = 0;
	struct super_block *sb = old_dir->i_sb;
	__le16 *uname_new = NULL;
	__le16 *uname_old = NULL;
	int new_name_len;
	int old_name_len;
	struct ntfs_volume *vol = NTFS_SB(sb);
	struct ntfs_inode *old_ni, *new_ni = NULL;
	struct ntfs_inode *old_dir_ni = NTFS_I(old_dir), *new_dir_ni = NTFS_I(new_dir);
	bool new_dir_first = false;
	bool new_link_count_zero = false, old_link_count_zero = false;
	bool delete_new_attrs = false, delete_old_attrs = false;
	bool new_had_reparse = false;
	bool system_index_locked = false;
	bool retry = false;

	if (NVolShutdown(old_dir_ni->vol))
		return -EIO;

	err = ntfs_stream_path_check(vol, &old_dentry->d_name);
	if (err)
		return err;
	err = ntfs_stream_path_check(vol, &new_dentry->d_name);
	if (err)
		return err;

	if (flags & (RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	new_name_len = ntfs_nlstoucs(NTFS_I(new_dir)->vol, new_dentry->d_name.name,
				     new_dentry->d_name.len, &uname_new,
				     NTFS_MAX_NAME_LEN);
	if (new_name_len < 0) {
		if (new_name_len != -ENAMETOOLONG)
			ntfs_error(sb, "Failed to convert name to unicode.");
		return -ENOMEM;
	}

	err = ntfs_check_bad_windows_name(vol, uname_new, new_name_len);
	if (err) {
		kmem_cache_free(ntfs_name_cache, uname_new);
		return err;
	}

	old_name_len = ntfs_nlstoucs(NTFS_I(old_dir)->vol, old_dentry->d_name.name,
				     old_dentry->d_name.len, &uname_old,
				     NTFS_MAX_NAME_LEN);
	if (old_name_len < 0) {
		kmem_cache_free(ntfs_name_cache, uname_new);
		if (old_name_len != -ENAMETOOLONG)
			ntfs_error(sb, "Failed to convert name to unicode.");
		return -ENOMEM;
	}

	old_inode = old_dentry->d_inode;
	new_inode = new_dentry->d_inode;
	old_ni = NTFS_I(old_inode);
	if (new_inode)
		new_ni = NTFS_I(new_inode);
	if (old_dir != new_dir)
		new_dir_first = is_subdir(new_dentry->d_parent,
					  old_dentry->d_parent);

	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
retry_transaction:
	has_system_index = 0;
	if (vol->journal && new_ni && new_ni != old_ni) {
		mutex_lock(&new_ni->mrec_lock);
		has_system_index = ntfs_has_system_index_entry(new_ni);
		mutex_unlock(&new_ni->mrec_lock);
		if (has_system_index < 0) {
			err = has_system_index;
			goto out;
		}
	}
	if (vol->journal) {
		unsigned int entries = new_inode ? 5 : 3;
		unsigned int directory_entries = 0;
		int credits;
		int extra_credits;

		credits = ntfs_filename_log_credits(vol, NTFS_MAX_NAME_LEN,
				entries, true);
		if (credits < 0) {
			err = credits;
			goto out;
		}
		if (NInoAttrList(old_ni)) {
			extra_credits = ntfs_filename_attrlist_extra_credits(vol, 3);
			if (extra_credits < 0 || check_add_overflow(credits,
					extra_credits, &credits)) {
				err = extra_credits < 0 ? extra_credits : -EOVERFLOW;
				goto out;
			}
		}
		if (new_inode && NInoAttrList(NTFS_I(new_inode))) {
			extra_credits = ntfs_filename_attrlist_extra_credits(vol, 2);
			if (extra_credits < 0 || check_add_overflow(credits,
					extra_credits, &credits)) {
				err = extra_credits < 0 ? extra_credits : -EOVERFLOW;
				goto out;
			}
		}
		if (NInoAttrList(old_dir_ni))
			directory_entries++;
		if (NInoAttrList(new_dir_ni))
			directory_entries += new_inode ? 2 : 1;
		if (directory_entries) {
			extra_credits = ntfs_index_attrlist_log_credits(vol,
					directory_entries);
			if (extra_credits < 0 || check_add_overflow(credits,
					extra_credits, &credits)) {
				err = extra_credits < 0 ? extra_credits : -EOVERFLOW;
				goto out;
			}
		}
		if (new_inode && NTFS_I(new_inode) != old_ni) {
			extra_credits = ntfs_system_index_remove_log_credits(
					NTFS_I(new_inode));
			if (extra_credits < 0 || check_add_overflow(credits,
					extra_credits, &credits)) {
				err = extra_credits < 0 ? extra_credits :
					-EOVERFLOW;
				goto out;
			}
		}
		log_handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(log_handle)) {
			err = PTR_ERR(log_handle);
			log_handle = NULL;
			goto out;
		}
		if (has_system_index) {
			mutex_lock(&vol->system_index_lock);
			system_index_locked = true;
			err = ntfs_prepare_system_index_removals(new_ni, &reparse,
					&object_id);
			if (err)
				goto abort_before_inode_locks;
		}
	}

	mutex_lock_nested(&old_ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	if (new_ni)
		mutex_lock_nested(&new_ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL_2);

	if (old_dir == new_dir) {
		mutex_lock_nested(&old_dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
	} else if (new_dir_first) {
		mutex_lock_nested(&new_dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
		mutex_lock_nested(&old_dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT_2);
	} else {
		mutex_lock_nested(&old_dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
		mutex_lock_nested(&new_dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT_2);
	}

	if (NInoBeingDeleted(old_ni) || NInoBeingDeleted(old_dir_ni) ||
	    (new_ni && NInoBeingDeleted(new_ni)) ||
	    (old_dir != new_dir && NInoBeingDeleted(new_dir_ni))) {
		err = -ENOENT;
		goto rollback;
	}
	if (log_handle && new_ni && new_ni != old_ni &&
	    !system_index_locked) {
		err = ntfs_has_system_index_entry(new_ni);
		if (err > 0) {
			retry = true;
			err = -EAGAIN;
		}
		if (err)
			goto rollback;
	}
	if (new_ni)
		new_had_reparse = new_ni->flags & FILE_ATTR_REPARSE_POINT;

	is_dir = S_ISDIR(old_inode->i_mode);

	if (new_inode) {
		if (is_dir) {
			struct mft_record *ni_mrec;

			ni_mrec = map_mft_record(NTFS_I(new_inode));
			if (IS_ERR(ni_mrec)) {
				err = -EIO;
				goto rollback;
			}
			err = ntfs_check_empty_dir(NTFS_I(new_inode), ni_mrec);
			unmap_mft_record(NTFS_I(new_inode));
			if (err)
				goto rollback;
		}
	}
	if (NInoBeingDeleted(old_ni) || NInoBeingDeleted(old_dir_ni)) {
		err = -ENOENT;
		goto rollback;
	}
	if (log_handle) {
		err = ntfs_mft_snapshot_take(snapshots, &snapshot_count,
				ARRAY_SIZE(snapshots), old_ni, false);
		if (err)
			goto rollback;
		err = ntfs_mft_snapshot_take(snapshots, &snapshot_count,
				ARRAY_SIZE(snapshots), old_dir_ni, true);
		if (err)
			goto rollback;
		err = ntfs_mft_snapshot_take(snapshots, &snapshot_count,
				ARRAY_SIZE(snapshots), new_dir_ni, true);
		if (err)
			goto rollback;
		if (new_ni) {
			err = ntfs_mft_snapshot_take(snapshots, &snapshot_count,
					ARRAY_SIZE(snapshots), new_ni, false);
			if (err)
				goto rollback;
		}
	}

	if (new_inode) {
		err = ntfs_delete(log_handle, new_ni, new_dir_ni, uname_new,
				new_name_len, false, &new_link_count_zero);
		if (err)
			goto rollback;
	}

	err = __ntfs_link(log_handle, old_ni, new_dir_ni, uname_new,
			new_name_len, false);
	if (err)
		goto rollback;

	err = ntfs_delete(log_handle, old_ni, old_dir_ni, uname_old,
			old_name_len, false, &old_link_count_zero);
	if (err) {
		int err2;

		ntfs_error(sb, "Failed to delete old ntfs inode(%llu) in old dir, err : %d\n",
				old_ni->mft_no, err);
		if (log_handle)
			goto rollback;
		err2 = ntfs_delete(NULL, old_ni, new_dir_ni, uname_new,
				new_name_len, false, NULL);
		if (err2)
			ntfs_error(sb, "Failed to delete old ntfs inode in new dir, err : %d\n",
					err2);
		goto err_out;
	}
	if (log_handle) {
		if (new_link_count_zero && new_ni != old_ni &&
		    system_index_locked) {
			err = ntfs_delete_reparse_index_transacted(log_handle,
					new_ni, &reparse);
			if (!err)
				err = ntfs_delete_object_id_index_transacted(
						log_handle, new_ni, &object_id);
			if (err)
				goto rollback;
		}
		err = ntfs_log_commit(log_handle);
		log_handle = NULL;
		if (err)
			goto rollback;
		ntfs_mft_snapshots_release(snapshots, snapshot_count);
		snapshot_count = 0;
		if (new_link_count_zero)
			delete_new_attrs = true;
		if (old_link_count_zero)
			delete_old_attrs = true;
		if (new_link_count_zero && new_ni != old_ni) {
			NInoSetBeingDeleted(new_ni);
			if (new_had_reparse) {
				new_ni->flags &= ~FILE_ATTR_REPARSE_POINT;
				NInoSetFileNameDirty(new_ni);
				mark_mft_record_dirty(new_ni);
			}
		}
	}

	simple_rename_timestamp(old_dir, old_dentry, new_dir, new_dentry);
	mark_inode_dirty(old_inode);
	mark_inode_dirty(old_dir);
	if (old_dir != new_dir)
		mark_inode_dirty(new_dir);
	if (new_inode)
		mark_inode_dirty(old_inode);

	inode_inc_iversion(new_dir);

	ntfs_mft_snapshots_release(snapshots, snapshot_count);
	snapshot_count = 0;
	goto err_out;

rollback:
	if (snapshot_count)
		ntfs_mft_snapshots_restore(snapshots, snapshot_count);
	if (log_handle) {
		int abort_err = ntfs_log_abort(log_handle);

		log_handle = NULL;
		if (abort_err) {
			ntfs_error(sb,
				"Failed to abort rename transaction (error %i).",
				abort_err);
			NVolSetErrors(vol);
			err = abort_err;
			retry = false;
		}
	}
	ntfs_mft_snapshots_release(snapshots, snapshot_count);
	snapshot_count = 0;
err_out:
	if (old_dir == new_dir) {
		mutex_unlock(&old_dir_ni->mrec_lock);
	} else if (new_dir_first) {
		mutex_unlock(&old_dir_ni->mrec_lock);
		mutex_unlock(&new_dir_ni->mrec_lock);
	} else {
		mutex_unlock(&new_dir_ni->mrec_lock);
		mutex_unlock(&old_dir_ni->mrec_lock);
	}
	if (new_ni)
		mutex_unlock(&new_ni->mrec_lock);
	mutex_unlock(&old_ni->mrec_lock);
	if (system_index_locked) {
		mutex_unlock(&vol->system_index_lock);
		system_index_locked = false;
	}
	ntfs_system_index_ctx_put(&object_id);
	ntfs_system_index_ctx_put(&reparse);
	if (retry) {
		retry = false;
		goto retry_transaction;
	}
	if (delete_new_attrs) {
		if (new_ni == old_ni)
			ntfs_delete_metadata_post_commit(new_ni);
		ntfs_delete_attr_inodes_post_commit(new_ni);
	}
	if (delete_old_attrs) {
		ntfs_delete_metadata_post_commit(old_ni);
		ntfs_delete_attr_inodes_post_commit(old_ni);
	}
	if (new_ni)
		ntfs_cleanup_deleted_inode(new_ni);
	if (old_link_count_zero)
		ntfs_cleanup_deleted_inode(old_ni);
	goto out;

abort_before_inode_locks:
	{
		int abort_err = ntfs_log_abort(log_handle);

		log_handle = NULL;
		if (abort_err) {
			ntfs_error(sb,
				"Failed to abort rename transaction (error %i).",
				abort_err);
			NVolSetErrors(vol);
			err = abort_err;
		}
	}
	mutex_unlock(&vol->system_index_lock);
	ntfs_system_index_ctx_put(&object_id);
	ntfs_system_index_ctx_put(&reparse);
out:
	if (uname_new)
		kmem_cache_free(ntfs_name_cache, uname_new);
	if (uname_old)
		kmem_cache_free(ntfs_name_cache, uname_old);

	return err;
}

static int ntfs_symlink(const struct mnt_idmap *idmap, struct inode *dir,
		struct dentry *dentry, const char *symname)
{
	struct super_block *sb = dir->i_sb;
	struct ntfs_volume *vol = NTFS_SB(sb);
	struct inode *vi;
	int err = 0;
	struct ntfs_inode *ni;
	__le16 *usrc;
	int usrc_len;
	int symlen = strlen(symname);

	if (NVolShutdown(vol))
		return -EIO;

	err = ntfs_stream_path_check(vol, &dentry->d_name);
	if (err)
		return err;

	usrc_len = ntfs_nlstoucs(vol, dentry->d_name.name,
				 dentry->d_name.len, &usrc, NTFS_MAX_NAME_LEN);
	if (usrc_len < 0) {
		if (usrc_len != -ENAMETOOLONG)
			ntfs_error(sb, "Failed to convert name to Unicode.");
		err =  -ENOMEM;
		goto out;
	}

	err = ntfs_check_bad_windows_name(vol, usrc, usrc_len);
	if (err) {
		kmem_cache_free(ntfs_name_cache, usrc);
		goto out;
	}

	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	ni = __ntfs_create(idmap, dir, usrc, usrc_len, S_IFLNK | 0777, 0,
			   symname, symlen);
	kmem_cache_free(ntfs_name_cache, usrc);
	if (IS_ERR(ni)) {
		err = PTR_ERR(ni);
		goto out;
	}

	vi = VFS_I(ni);
	vi->i_size = symlen;
	d_instantiate_new(dentry, vi);
out:
	return err;
}

static int ntfs_mknod(const struct mnt_idmap *idmap, struct inode *dir,
		struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct ntfs_volume *vol = NTFS_SB(sb);
	int err = 0;
	struct ntfs_inode *ni;
	__le16 *uname = NULL;
	int uname_len;

	if (NVolShutdown(vol))
		return -EIO;

	err = ntfs_stream_path_check(vol, &dentry->d_name);
	if (err)
		return err;

	uname_len = ntfs_nlstoucs(vol, dentry->d_name.name,
			dentry->d_name.len, &uname, NTFS_MAX_NAME_LEN);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(sb, "Failed to convert name to Unicode.");
		return -ENOMEM;
	}

	err = ntfs_check_bad_windows_name(vol, uname, uname_len);
	if (err) {
		kmem_cache_free(ntfs_name_cache, uname);
		return err;
	}

	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	switch (mode & S_IFMT) {
	case S_IFCHR:
	case S_IFBLK:
		ni = __ntfs_create(idmap, dir, uname, uname_len,
				mode, rdev, NULL, 0);
		break;
	default:
		ni = __ntfs_create(idmap, dir, uname, uname_len,
				mode, 0, NULL, 0);
	}

	kmem_cache_free(ntfs_name_cache, uname);
	if (IS_ERR(ni)) {
		err = PTR_ERR(ni);
		goto out;
	}

	d_instantiate_new(dentry, VFS_I(ni));
out:
	return err;
}

static int ntfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	struct inode *vi = old_dentry->d_inode;
	struct super_block *sb = vi->i_sb;
	struct ntfs_volume *vol = NTFS_SB(sb);
	__le16 *uname = NULL;
	int uname_len;
	int err;
	struct ntfs_log_handle *log_handle = NULL;
	struct ntfs_inode *ni = NTFS_I(vi), *dir_ni = NTFS_I(dir);

	if (NVolShutdown(vol))
		return -EIO;

	if (NInoAttr(ni))
		return -EOPNOTSUPP;

	err = ntfs_stream_path_check(vol, &dentry->d_name);
	if (err)
		return err;

	uname_len = ntfs_nlstoucs(vol, dentry->d_name.name,
			dentry->d_name.len, &uname, NTFS_MAX_NAME_LEN);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(sb, "Failed to convert name to unicode.");
		return -ENOMEM;
	}

	ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
	if (vol->journal) {
		int credits;
		int extra_credits;

		credits = ntfs_filename_log_credits(vol, uname_len, 1, false);
		if (credits < 0) {
			err = credits;
			goto out;
		}
		if (NInoAttrList(ni)) {
			extra_credits = ntfs_filename_attrlist_extra_credits(vol, 1);
			if (extra_credits < 0) {
				err = extra_credits;
				goto out;
			}
			if (check_add_overflow(credits, extra_credits, &credits)) {
				err = -EOVERFLOW;
				goto out;
			}
		}
		if (NInoAttrList(dir_ni)) {
			extra_credits = ntfs_index_attrlist_log_credits(vol, 1);
			if (extra_credits < 0) {
				err = extra_credits;
				goto out;
			}
			if (check_add_overflow(credits, extra_credits, &credits)) {
				err = -EOVERFLOW;
				goto out;
			}
		}
		log_handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(log_handle)) {
			err = PTR_ERR(log_handle);
			goto out;
		}
	}

	ihold(vi);
	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	mutex_lock_nested(&dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
	err = __ntfs_link(log_handle, NTFS_I(vi), NTFS_I(dir), uname,
			uname_len, true);
	if (err) {
		mutex_unlock(&dir_ni->mrec_lock);
		mutex_unlock(&ni->mrec_lock);
		iput(vi);
		pr_err("failed to create link, err = %d\n", err);
		goto out;
	}

	inode_inc_iversion(dir);
	simple_inode_init_ts(dir);

	inode_inc_iversion(vi);
	simple_inode_init_ts(vi);

	/* timestamp is already written, so mark_inode_dirty() is unneeded. */
	d_instantiate(dentry, vi);
	mutex_unlock(&dir_ni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);

out:
	kmem_cache_free(ntfs_name_cache, uname);
	return err;
}

/*
 * Inode operations for directories.
 */
const struct inode_operations ntfs_dir_inode_ops = {
	.lookup		= ntfs_lookup,	/* VFS: Lookup directory. */
	.create		= ntfs_create,
	.unlink		= ntfs_unlink,
	.mkdir		= ntfs_mkdir,
	.rmdir		= ntfs_rmdir,
	.rename		= ntfs_rename,
	.get_acl	= ntfs_get_acl,
	.set_acl	= ntfs_set_acl,
	.listxattr	= ntfs_listxattr,
	.setattr	= ntfs_setattr,
	.getattr	= ntfs_getattr,
	.fileattr_get	= ntfs_fileattr_get,
	.fileattr_set	= ntfs_fileattr_set,
	.symlink	= ntfs_symlink,
	.mknod		= ntfs_mknod,
	.link		= ntfs_link,
};

/*
 * ntfs_get_parent - find the dentry of the parent of a given directory dentry
 * @child_dent:		dentry of the directory whose parent directory to find
 *
 * Find the dentry for the parent directory of the directory specified by the
 * dentry @child_dent.  This function is called from
 * fs/exportfs/expfs.c::find_exported_dentry() which in turn is called from the
 * default ->decode_fh() which is export_decode_fh() in the same file.
 *
 * Note: ntfs_get_parent() is called with @d_inode(child_dent)->i_mutex down.
 *
 * Return the dentry of the parent directory on success or the error code on
 * error (IS_ERR() is true).
 */
static struct dentry *ntfs_get_parent(struct dentry *child_dent)
{
	struct inode *vi = d_inode(child_dent);
	struct ntfs_inode *ni = NTFS_I(vi);
	struct mft_record *mrec;
	struct ntfs_attr_search_ctx *ctx;
	struct attr_record *attr;
	struct file_name_attr *fn;
	unsigned long parent_ino;
	int err;

	ntfs_debug("Entering for inode 0x%llx.", ni->mft_no);
	/* Get the mft record of the inode belonging to the child dentry. */
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return ERR_CAST(mrec);
	/* Find the first file name attribute in the mft record. */
	ctx = ntfs_attr_get_search_ctx(ni, mrec);
	if (unlikely(!ctx)) {
		unmap_mft_record(ni);
		return ERR_PTR(-ENOMEM);
	}
try_next:
	err = ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, CASE_SENSITIVE, 0, NULL,
			0, ctx);
	if (unlikely(err)) {
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(ni);
		if (err == -ENOENT)
			ntfs_error(vi->i_sb,
				   "Inode 0x%llx does not have a file name attribute.  Run chkdsk.",
				   ni->mft_no);
		return ERR_PTR(err);
	}
	attr = ctx->attr;
	if (unlikely(attr->non_resident))
		goto try_next;
	fn = (struct file_name_attr *)((u8 *)attr +
			le16_to_cpu(attr->data.resident.value_offset));
	if (unlikely((u8 *)fn + le32_to_cpu(attr->data.resident.value_length) >
	    (u8 *)attr + le32_to_cpu(attr->length)))
		goto try_next;
	/* Get the inode number of the parent directory. */
	parent_ino = MREF_LE(fn->parent_directory);
	/* Release the search context and the mft record of the child. */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(ni);

	return d_obtain_alias(ntfs_iget(vi->i_sb, parent_ino));
}

static struct inode *ntfs_nfs_get_inode(struct super_block *sb,
		u64 ino, u32 generation)
{
	struct inode *inode;

	inode = ntfs_iget(sb, ino);
	if (!IS_ERR(inode)) {
		if (inode->i_generation != generation) {
			iput(inode);
			inode = ERR_PTR(-ESTALE);
		}
	}

	return inode;
}

static struct dentry *ntfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    ntfs_nfs_get_inode);
}

static struct dentry *ntfs_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    ntfs_nfs_get_inode);
}

static int ntfs_encode_fh(struct inode *inode, u32 *fh, int *max_len,
		struct inode *parent)
{
	if (ntfs_inode_is_named_stream(NTFS_I(inode)))
		return -EOPNOTSUPP;
	return generic_encode_ino32_fh(inode, fh, max_len, parent);
}

/*
 * Export operations allowing NFS exporting of mounted NTFS partitions.
 */
const struct export_operations ntfs_export_ops = {
	.encode_fh	= ntfs_encode_fh,
	.get_parent	= ntfs_get_parent,	/* Find the parent of a given directory. */
	.fh_to_dentry	= ntfs_fh_to_dentry,
	.fh_to_parent	= ntfs_fh_to_parent,
};
