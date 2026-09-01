// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS kernel directory inode operations.
 *
 * Copyright (c) 2001-2006 Anton Altaparmakov
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/exportfs.h>
#include <linux/fsnotify.h>
#include <linux/iversion.h>
#include <linux/namei.h>
#include <linux/security.h>

#include "ntfs.h"
#include "time.h"
#include "index.h"
#include "reparse.h"
#include "object_id.h"
#include "ea.h"

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

static int ntfs_check_bad_windows_name(struct ntfs_volume *vol,
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
struct ntfs_stream_path {
	const char *base_name;
	unsigned int base_len;
	const char *stream_name;
	unsigned int stream_len;
};

static int ntfs_stream_path_parse(struct ntfs_volume *vol,
		const struct qstr *qname, struct ntfs_stream_path *path)
{
	const unsigned char *colon;

	if (!NVolStreamsWindows(vol))
		return 0;

	colon = memchr(qname->name, ':', qname->len);
	if (!colon)
		return 0;
	if (colon == qname->name || colon + 1 == qname->name + qname->len)
		return -EINVAL;
	if (memchr(colon + 1, ':', qname->name + qname->len - colon - 1))
		return -EINVAL;

	path->base_name = (const char *)qname->name;
	path->base_len = colon - qname->name;
	path->stream_name = (const char *)colon + 1;
	path->stream_len = qname->name + qname->len - colon - 1;
	return 1;
}

static bool ntfs_stream_path_has_colon(struct ntfs_volume *vol,
		const struct qstr *qname)
{
	return NVolStreamsWindows(vol) &&
		memchr(qname->name, ':', qname->len);
}

static int ntfs_stream_path_check(struct ntfs_volume *vol,
		const struct qstr *qname)
{
	struct ntfs_stream_path path;
	int ret;

	ret = ntfs_stream_path_parse(vol, qname, &path);
	if (ret < 0)
		return ret;
	return ret ? -EOPNOTSUPP : 0;
}

static struct inode *ntfs_stream_lookup_inode_by_name(struct inode *dir_ino,
		__le16 *uname, int uname_len)
{
	struct ntfs_volume *vol = NTFS_SB(dir_ino->i_sb);
	struct ntfs_name *name = NULL;
	struct inode *inode;
	u64 mref;

	mutex_lock(&NTFS_I(dir_ino)->mrec_lock);
	mref = ntfs_lookup_inode_by_name(NTFS_I(dir_ino), uname, uname_len,
			&name);
	mutex_unlock(&NTFS_I(dir_ino)->mrec_lock);
	kfree(name);

	if (IS_ERR_MREF(mref))
		return ERR_PTR(MREF_ERR(mref));

	inode = ntfs_iget(vol->sb, MREF(mref));
	if (IS_ERR(inode))
		return inode;
	if (MSEQNO(mref) != NTFS_I(inode)->seq_no &&
	    MREF(mref) != FILE_MFT) {
		iput(inode);
		return ERR_PTR(-EIO);
	}
	return inode;
}

static int ntfs_stream_d_revalidate(struct inode *dir,
		const struct qstr *qname, struct dentry *dentry,
		unsigned int flags)
{
	struct inode *inode = d_inode(dentry);
	struct ntfs_inode *ni;
	struct ntfs_stream_path path;
	struct inode *base_vi;
	__le16 *base_name = NULL, *stream_name = NULL;
	int base_len, stream_len, err, ret = 0;

	if (flags & LOOKUP_RCU)
		return -ECHILD;
	if (!inode)
		return 0;
	if (!inode->i_nlink)
		return 0;
	if (NVolShutdown(NTFS_SB(dir->i_sb)))
		return 0;

	ni = NTFS_I(inode);
	if (!ntfs_inode_is_named_stream(ni))
		return 0;

	err = ntfs_stream_path_parse(NTFS_SB(dir->i_sb), qname, &path);
	if (err <= 0)
		return 0;
	base_len = ntfs_nlstoucs(NTFS_SB(dir->i_sb), path.base_name,
			path.base_len, &base_name, NTFS_MAX_NAME_LEN);
	if (base_len < 0)
		return base_len;
	stream_len = ntfs_nlstoucs(NTFS_SB(dir->i_sb), path.stream_name,
			path.stream_len, &stream_name, NTFS_MAX_NAME_LEN);
	if (stream_len < 0) {
		ret = stream_len;
		goto out;
	}
	base_vi = ntfs_stream_lookup_inode_by_name(dir, base_name, base_len);
	if (IS_ERR(base_vi)) {
		err = PTR_ERR(base_vi);
		if (err != -ENOENT)
			ret = err;
		goto out;
	}
	if (NTFS_I(base_vi) != ni->ext.base_ntfs_ino) {
		iput(base_vi);
		goto out;
	}

	mutex_lock(&NTFS_I(base_vi)->mrec_lock);
	if (stream_len != ni->name_len ||
	    !ntfs_names_are_equal(stream_name, stream_len, ni->name,
			ni->name_len, CASE_SENSITIVE, ni->vol->upcase,
			ni->vol->upcase_len))
		err = -ESTALE;
	else
		err = ntfs_stream_inode_validate(inode);
	mutex_unlock(&NTFS_I(base_vi)->mrec_lock);
	iput(base_vi);
	if (!err)
		ret = 1;
	else if (err != -ENOENT && err != -ESTALE)
		ret = err;
out:
	if (stream_name)
		kmem_cache_free(ntfs_name_cache, stream_name);
	kmem_cache_free(ntfs_name_cache, base_name);
	return ret;
}

static const struct dentry_operations ntfs_stream_dentry_ops = {
	.d_revalidate	= ntfs_stream_d_revalidate,
	.d_delete	= always_delete_dentry,
};

static void ntfs_stream_set_dentry_ops(struct dentry *dentry)
{
	if (dentry->d_op == &ntfs_stream_dentry_ops)
		return;
	dentry->d_op = &ntfs_stream_dentry_ops;
	dentry->d_flags |= DCACHE_OP_REVALIDATE | DCACHE_OP_DELETE;
}

static struct dentry *ntfs_lookup_stream(struct inode *dir_ino,
		struct dentry *dent, const struct ntfs_stream_path *path)
{
	struct ntfs_volume *vol = NTFS_SB(dir_ino->i_sb);
	struct inode *base_vi, *stream_vi;
	__le16 *base_uname = NULL, *stream_uname = NULL;
	int base_len, stream_len, err;

	if (NVolShutdown(vol))
		return ERR_PTR(-EIO);
	ntfs_stream_set_dentry_ops(dent);

	base_len = ntfs_nlstoucs(vol, path->base_name, path->base_len,
			&base_uname, NTFS_MAX_NAME_LEN);
	if (base_len < 0)
		return ERR_PTR(base_len);

	stream_len = ntfs_nlstoucs(vol, path->stream_name, path->stream_len,
			&stream_uname, NTFS_MAX_NAME_LEN);
	if (stream_len < 0) {
		kmem_cache_free(ntfs_name_cache, base_uname);
		return ERR_PTR(stream_len);
	}

	base_vi = ntfs_stream_lookup_inode_by_name(dir_ino, base_uname,
			base_len);
	kmem_cache_free(ntfs_name_cache, base_uname);
	if (IS_ERR(base_vi)) {
		err = PTR_ERR(base_vi);
		kmem_cache_free(ntfs_name_cache, stream_uname);
		if (err == -ENOENT)
			return d_splice_alias(NULL, dent);
		return ERR_PTR(err);
	}

	if (!S_ISREG(base_vi->i_mode)) {
		iput(base_vi);
		kmem_cache_free(ntfs_name_cache, stream_uname);
		return ERR_PTR(-EISDIR);
	}

	mutex_lock(&NTFS_I(base_vi)->mrec_lock);
	stream_vi = ntfs_attr_iget(base_vi, AT_DATA, stream_uname, stream_len);
	if (!IS_ERR(stream_vi)) {
		if (NInoStreamUnlinked(NTFS_I(stream_vi)))
			err = -ENOENT;
		else
			err = ntfs_stream_inode_validate(stream_vi);
		if (err) {
			iput(stream_vi);
			stream_vi = ERR_PTR(err);
		}
	}
	mutex_unlock(&NTFS_I(base_vi)->mrec_lock);
	iput(base_vi);
	kmem_cache_free(ntfs_name_cache, stream_uname);

	if (IS_ERR(stream_vi)) {
		err = PTR_ERR(stream_vi);
		if (err == -ENOENT || err == -ESTALE)
			return d_splice_alias(NULL, dent);
		return ERR_PTR(err);
	}

	return d_splice_alias(stream_vi, dent);
}

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

static int ntfs_sd_add_everyone(struct ntfs_inode *ni)
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

	ret = ntfs_attr_add(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0, (u8 *)sd,
			sd_len);
	if (ret)
		ntfs_error(ni->vol->sb, "Failed to add SECURITY_DESCRIPTOR\n");

	kfree(sd);
	return ret;
}

static struct ntfs_inode *__ntfs_create(struct mnt_idmap *idmap, struct inode *dir,
		__le16 *name, u8 name_len, mode_t mode, dev_t dev,
		const char *target, int target_len, __le16 *stream_name,
		u8 stream_name_len, struct inode **stream_vi)
{
	struct ntfs_inode *dir_ni = NTFS_I(dir);
	struct ntfs_volume *vol = dir_ni->vol;
	struct ntfs_inode *ni;
	bool rollback_data = false, rollback_sd = false, rollback_reparse = false;
	bool rollback_stream = false;
	struct file_name_attr *fn = NULL;
	struct standard_information *si = NULL;
	int err = 0, fn_len, si_len;
	struct inode *vi;
	struct mft_record *ni_mrec, *dni_mrec;
	struct super_block *sb = dir_ni->vol->sb;
	__le64 parent_mft_ref;
	u64 child_mft_ref;
	__le16 ea_size;

	if (stream_vi)
		*stream_vi = NULL;

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
			ni->itype.index.vcn_size = vol->sector_size;
			ni->itype.index.vcn_size_bits =
				vol->sector_size_bits;
		}
	}

	if (IS_RDONLY(vi))
		mode &= ~0222;

	inode_init_owner(idmap, vi, dir, mode);

	mode = vi->i_mode;

#ifdef CONFIG_NTFS_FS_POSIX_ACL
	if (!S_ISLNK(mode) && (sb->s_flags & SB_POSIXACL)) {
		err = ntfs_init_acl(idmap, vi, dir);
		if (err)
			goto err_out;
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

	err = ntfs_mft_record_alloc(dir_ni->vol, mode, &ni, NULL,
			&ni_mrec, -1);
	if (err) {
		iput(vi);
		return ERR_PTR(err);
	}

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
	if (NInoBeingDeleted(dir_ni)) {
		err = -ENOENT;
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

	/* Add STANDARD_INFORMATION to inode. */
	err = ntfs_attr_add(ni, AT_STANDARD_INFORMATION, AT_UNNAMED, 0, (u8 *)si,
			si_len);
	if (err) {
		ntfs_error(sb, "Failed to add STANDARD_INFORMATION attribute.\n");
		goto err_out;
	}

	err = ntfs_sd_add_everyone(ni);
	if (err)
		goto err_out;
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
				ni->vol->index_record_size >> ni->vol->sector_size_bits;
		ir->index.entries_offset = cpu_to_le32(sizeof(struct index_header));
		ir->index.index_length = cpu_to_le32(index_len);
		ir->index.allocated_size = cpu_to_le32(index_len);
		ie = (struct index_entry *)((u8 *)ir + sizeof(struct index_root));
		ie->length = cpu_to_le16(sizeof(struct index_entry_header));
		ie->key_length = 0;
		ie->flags = INDEX_ENTRY_END;

		/* Add struct index_root attribute to inode. */
		err = ntfs_attr_add(ni, AT_INDEX_ROOT, I30, 4, (u8 *)ir, ir_len);
		if (err) {
			kfree(ir);
			ntfs_error(vi->i_sb, "Failed to add struct index_root attribute.\n");
			goto err_out;
		}
		kfree(ir);
		err = ntfs_attr_open(ni, AT_INDEX_ROOT, I30, 4);
		if (err)
			goto err_out;
	} else {
		/* Add DATA attribute to inode. */
		err = ntfs_attr_add(ni, AT_DATA, AT_UNNAMED, 0, NULL, 0);
		if (err) {
			ntfs_error(dir_ni->vol->sb, "Failed to add DATA attribute.\n");
			goto err_out;
		}
		rollback_data = true;

		err = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
		if (err)
			goto err_out;

		if (stream_name_len) {
			err = ntfs_attr_add(ni, AT_DATA, stream_name,
					stream_name_len, NULL, 0);
			if (err) {
				ntfs_error(sb,
					"Failed to add named DATA attribute.\n");
				goto err_out;
			}
			rollback_stream = true;

			*stream_vi = ntfs_attr_iget(vi, AT_DATA, stream_name,
					stream_name_len);
			if (IS_ERR(*stream_vi)) {
				err = PTR_ERR(*stream_vi);
				*stream_vi = NULL;
				goto err_out;
			}
		}

		if (S_ISLNK(mode)) {
			if (NVolSymlinkNative(vol))
				err = ntfs_reparse_set_native_symlink(ni, target, target_len);
			else
				err = ntfs_reparse_set_wsl_symlink(ni, target, target_len);
			if (!err)
				rollback_reparse = true;
		} else if (S_ISBLK(mode) || S_ISCHR(mode) || S_ISSOCK(mode) ||
			   S_ISFIFO(mode)) {
			si->file_attributes = FILE_ATTRIBUTE_RECALL_ON_OPEN;
			ni->flags = FILE_ATTRIBUTE_RECALL_ON_OPEN;
			err = ntfs_reparse_set_wsl_not_symlink(ni, mode);
			if (!err)
				rollback_reparse = true;
		}
		if (err)
			goto err_out;
	}

	err = ntfs_ea_set_wsl_inode(vi, dev, &ea_size,
			NTFS_EA_UID | NTFS_EA_GID | NTFS_EA_MODE);
	if (err)
		goto err_out;

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
		fn->data_size = cpu_to_le64(ni->data_size);
		fn->allocated_size = cpu_to_le64(ni->allocated_size);
	}
	if (!S_ISREG(mode) && !S_ISDIR(mode)) {
		fn->file_attributes = FILE_ATTR_SYSTEM;
		if (rollback_reparse)
			fn->file_attributes |= FILE_ATTR_REPARSE_POINT;
	}
	if (NVolHideDotFiles(vol) && name_len > 0 && name[0] == cpu_to_le16('.'))
		fn->file_attributes |= FILE_ATTR_HIDDEN;
	fn->creation_time = fn->last_data_change_time = utc2ntfs(ni->i_crtime);
	fn->last_mft_change_time = fn->last_access_time = fn->creation_time;
	memcpy(fn->file_name, name, name_len * sizeof(__le16));

	/* Add FILE_NAME attribute to inode. */
	err = ntfs_attr_add(ni, AT_FILE_NAME, AT_UNNAMED, 0, (u8 *)fn, fn_len);
	if (err) {
		ntfs_error(sb, "Failed to add FILE_NAME attribute.\n");
		goto err_out;
	}

	child_mft_ref = MK_MREF(ni->mft_no,
				le16_to_cpu(ni_mrec->sequence_number));
	/* Set hard links count and directory flag. */
	ni_mrec->link_count = cpu_to_le16(1);
	mark_mft_record_dirty(ni);

	/* Add FILE_NAME attribute to index. */
	err = ntfs_index_add_filename(dir_ni, fn, child_mft_ref);
	if (err) {
		ntfs_debug("Failed to add entry to the index");
		goto err_out;
	}

	unmap_mft_record(ni);
	mutex_unlock(&dir_ni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);

	ni->flags = fn->file_attributes |
		    (ni->flags & FILE_ATTRIBUTE_RECALL_ON_OPEN);
	/* Set the sequence number. */
	vi->i_generation = ni->seq_no;
	set_nlink(vi, 1);
	ntfs_set_vfs_operations(vi, mode, dev);

	/* Done! */
	kfree(fn);
	kfree(si);
	ntfs_debug("Done.\n");
	return ni;

err_out:
	if (stream_vi && *stream_vi) {
		clear_nlink(*stream_vi);
		remove_inode_hash(*stream_vi);
		iput(*stream_vi);
		*stream_vi = NULL;
	}

	if (rollback_stream)
		ntfs_attr_remove(ni, AT_DATA, stream_name, stream_name_len);

	if (rollback_sd)
		ntfs_attr_remove(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0);

	if (rollback_data)
		ntfs_attr_remove(ni, AT_DATA, AT_UNNAMED, 0);

	if (rollback_reparse)
		ntfs_delete_reparse_index(ni);
	/*
	 * Free extent MFT records (should not exist any with current
	 * ntfs_create implementation, but for any case if something will be
	 * changed in the future).
	 */
	while (ni->nr_extents != 0) {
		int err2;

		err2 = ntfs_mft_record_free(ni->vol, *(ni->ext.extent_ntfs_inos));
		if (err2)
			ntfs_error(sb,
				"Failed to free extent MFT record. Leaving inconsistent metadata.\n");
		ntfs_inode_close(*(ni->ext.extent_ntfs_inos));
	}
	if (ntfs_mft_record_free(ni->vol, ni))
		ntfs_error(sb,
			"Failed to free MFT record. Leaving inconsistent metadata. Run chkdsk.\n");
	unmap_mft_record(ni);
	kfree(fn);
	kfree(si);

	mutex_unlock(&dir_ni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);

	remove_inode_hash(vi);
	discard_new_inode(vi);
	return ERR_PTR(err);
}

static struct dentry *ntfs_stream_prepare_base_dentry(struct mnt_idmap *idmap,
		struct inode *dir, struct dentry *stream_dentry,
		const struct ntfs_stream_path *path, umode_t mode)
{
	struct qstr base_qstr = {
		.name = path->base_name,
		.len = path->base_len,
	};
	struct dentry *base_dentry;
	int err;

	base_qstr.hash = full_name_hash(stream_dentry->d_parent,
			base_qstr.name, base_qstr.len);
	base_dentry = d_lookup(stream_dentry->d_parent, &base_qstr);
	if (!base_dentry) {
		base_dentry = d_alloc(stream_dentry->d_parent, &base_qstr);
		if (!base_dentry)
			return ERR_PTR(-ENOMEM);
		d_rehash(base_dentry);
	}

	err = may_create_dentry(idmap, dir, base_dentry);
	if (!err)
		err = security_inode_create(dir, base_dentry, mode);
	if (err) {
		dput(base_dentry);
		return ERR_PTR(err);
	}
	return base_dentry;
}

static int ntfs_stream_path_names(struct ntfs_volume *vol,
		const struct qstr *qname, __le16 **base_name, int *base_len,
		__le16 **stream_name, int *stream_len)
{
	struct ntfs_stream_path path;
	int err;

	*base_name = NULL;
	*stream_name = NULL;
	err = ntfs_stream_path_parse(vol, qname, &path);
	if (err <= 0)
		return err;

	*base_len = ntfs_nlstoucs(vol, path.base_name, path.base_len,
			base_name, NTFS_MAX_NAME_LEN);
	if (*base_len < 0)
		return *base_len;

	*stream_len = ntfs_nlstoucs(vol, path.stream_name, path.stream_len,
			stream_name, NTFS_MAX_NAME_LEN);
	if (*stream_len < 0) {
		kmem_cache_free(ntfs_name_cache, *base_name);
		*base_name = NULL;
		return *stream_len;
	}

	err = ntfs_check_bad_windows_name(vol, *base_name, *base_len);
	if (err)
		goto out_free;
	err = ntfs_check_bad_windows_name(vol, *stream_name, *stream_len);
	if (err)
		goto out_free;
	return 1;

out_free:
	kmem_cache_free(ntfs_name_cache, *stream_name);
	kmem_cache_free(ntfs_name_cache, *base_name);
	*stream_name = NULL;
	*base_name = NULL;
	return err;
}

static struct inode *ntfs_create_named_stream(struct mnt_idmap *idmap,
		struct inode *dir,
		__le16 *base_name, int base_len, __le16 *stream_name,
		int stream_len)
{
	struct ntfs_inode *base_ni;
	struct inode *base_vi, *stream_vi;
	struct ntfs_attr_search_ctx *ctx;
	int err;

	base_vi = ntfs_stream_lookup_inode_by_name(dir, base_name, base_len);
	if (IS_ERR(base_vi))
		return base_vi;
	if (!S_ISREG(base_vi->i_mode)) {
		iput(base_vi);
		return ERR_PTR(-EISDIR);
	}
	err = inode_permission(idmap, base_vi, MAY_OPEN | MAY_WRITE);
	if (err)
		goto out_iput;
	if (IS_APPEND(base_vi) || IS_IMMUTABLE(base_vi)) {
		err = -EPERM;
		goto out_iput;
	}
	if (!(NTFS_SB(base_vi->i_sb)->vol_flags & VOLUME_IS_DIRTY)) {
		err = ntfs_set_volume_flags(NTFS_SB(base_vi->i_sb),
				VOLUME_IS_DIRTY);
		if (err)
			goto out_iput;
	}

	base_ni = NTFS_I(base_vi);
	mutex_lock(&base_ni->mrec_lock);
	if (NVolShutdown(base_ni->vol)) {
		err = -EIO;
		goto out_unlock;
	}
	if (NInoBeingDeleted(base_ni) || !base_vi->i_nlink) {
		err = -ENOENT;
		goto out_unlock;
	}
	if (IS_APPEND(base_vi) || IS_IMMUTABLE(base_vi)) {
		err = -EPERM;
		goto out_unlock;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unlock;
	}

	err = ntfs_attr_lookup(AT_DATA, stream_name, stream_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (!err) {
		if (ntfs_stream_is_unlinked(base_ni, stream_name, stream_len))
			err = -EBUSY;
		else
			err = -EEXIST;
	} else if (err == -ENOENT) {
		if (NVolShutdown(base_ni->vol)) {
			err = -EIO;
			goto out_put_ctx;
		}
		err = ntfs_attr_add(base_ni, AT_DATA, stream_name, stream_len,
				NULL, 0);
		if (!err) {
			mark_mft_record_dirty(base_ni);
			inode_set_mtime_to_ts(base_vi,
					inode_set_ctime_current(base_vi));
			mark_inode_dirty(base_vi);
		}
	}
	ntfs_attr_put_search_ctx(ctx);
	if (err)
		goto out_unlock;

	stream_vi = ntfs_attr_iget(base_vi, AT_DATA, stream_name, stream_len);
	if (!IS_ERR(stream_vi)) {
		err = ntfs_stream_inode_validate(stream_vi);
		if (err) {
			iput(stream_vi);
			stream_vi = ERR_PTR(err);
		}
	}
	mutex_unlock(&base_ni->mrec_lock);
	iput(base_vi);
	return stream_vi;

out_put_ctx:
	ntfs_attr_put_search_ctx(ctx);
out_unlock:
	mutex_unlock(&base_ni->mrec_lock);
out_iput:
	iput(base_vi);
	return ERR_PTR(err);
}

static int ntfs_create(struct mnt_idmap *idmap, struct inode *dir,
		struct dentry *dentry, umode_t mode)
{
	struct ntfs_volume *vol = NTFS_SB(dir->i_sb);
	struct ntfs_inode *ni;
	struct ntfs_stream_path stream_path;
	struct dentry *base_dentry;
	struct inode *stream_vi = NULL;
	__le16 *uname, *base_name = NULL, *stream_name = NULL;
	int uname_len, stream_len, path_result, err;

	if (NVolShutdown(vol))
		return -EIO;

	path_result = ntfs_stream_path_parse(vol, &dentry->d_name,
			&stream_path);
	if (path_result < 0)
		return path_result;

	path_result = ntfs_stream_path_names(vol, &dentry->d_name, &base_name,
			&uname_len, &stream_name, &stream_len);
	if (path_result) {
		if (path_result < 0)
			return path_result;
		stream_vi = ntfs_create_named_stream(idmap, dir, base_name,
				uname_len, stream_name, stream_len);
		if (IS_ERR(stream_vi) && PTR_ERR(stream_vi) == -ENOENT) {
			base_dentry = ntfs_stream_prepare_base_dentry(idmap, dir,
					dentry, &stream_path, mode);
			if (IS_ERR(base_dentry)) {
				err = PTR_ERR(base_dentry);
				goto out_free_stream_names;
			}

			if (!(vol->vol_flags & VOLUME_IS_DIRTY)) {
				err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
				if (err)
					goto out_dput_base;
			}

			ni = __ntfs_create(idmap, dir, base_name, uname_len,
					S_IFREG | mode, 0, NULL, 0,
					stream_name, stream_len, &stream_vi);
			if (IS_ERR(ni)) {
				err = PTR_ERR(ni);
				goto out_dput_base;
			}

			d_instantiate_new(base_dentry, VFS_I(ni));
			fsnotify_create(dir, base_dentry);
			dput(base_dentry);
		}
		if (IS_ERR(stream_vi)) {
			err = PTR_ERR(stream_vi);
			goto out_free_stream_names;
		}
		kmem_cache_free(ntfs_name_cache, stream_name);
		kmem_cache_free(ntfs_name_cache, base_name);
		ntfs_stream_set_dentry_ops(dentry);
		d_instantiate(dentry, stream_vi);
		return 0;

out_dput_base:
		dput(base_dentry);
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

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	ni = __ntfs_create(idmap, dir, uname, uname_len, S_IFREG | mode, 0,
			NULL, 0, NULL, 0, NULL);
	kmem_cache_free(ntfs_name_cache, uname);
	if (IS_ERR(ni))
		return PTR_ERR(ni);

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
	if (NInoAttr(ni) || ni->nr_extents == -1)
		return 1;
	else
		return 0;
}

static int ntfs_test_inode_stream(struct inode *vi, void *data)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	u64 mft_no = (u64)(uintptr_t)data;

	return ni->mft_no == mft_no && ntfs_inode_is_named_stream(ni);
}

static void ntfs_invalidate_stream_inodes(struct ntfs_inode *ni)
{
	struct inode *attr_vi;
	struct super_block *sb = VFS_I(ni)->i_sb;

	lockdep_assert_held(&ni->mrec_lock);
	while ((attr_vi = ilookup5(sb, ni->mft_no, ntfs_test_inode_stream,
			(void *)(uintptr_t)ni->mft_no))) {
		struct ntfs_inode *attr_ni = NTFS_I(attr_vi);

		if (atomic_read(&attr_ni->stream_open_count) > 0)
			NInoSetStreamUnlinked(attr_ni);
		clear_nlink(attr_vi);
		remove_inode_hash(attr_vi);
		iput(attr_vi);
	}
}

/*
 * ntfs_delete - delete file or directory from ntfs volume
 * @ni:         ntfs inode for object to delte
 * @dir_ni:     ntfs inode for directory in which delete object
 * @name:       unicode name of the object to delete
 * @name_len:   length of the name in unicode characters
 * @need_lock:  whether mrec lock is needed or not
 *
 * Delete the specified name from the directory index @dir_ni and decrement
 * the link count of the target inode @ni.
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_delete(struct ntfs_inode *ni, struct ntfs_inode *dir_ni,
		__le16 *name, u8 name_len, bool need_lock)
{
	struct ntfs_attr_search_ctx *actx = NULL;
	struct file_name_attr *fn = NULL;
	bool looking_for_dos_name = false, looking_for_win32_name = false;
	bool case_sensitive_match = true;
	bool link_count_zero = false;
	int err = 0;
	struct mft_record *ni_mrec;
	struct super_block *sb;

	ntfs_debug("Entering.\n");

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
		if (need_lock) {
			mutex_unlock(&dir_ni->mrec_lock);
			mutex_unlock(&ni->mrec_lock);
		}
		return -ENOMEM;
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

	err = ntfs_index_remove(dir_ni, fn, le32_to_cpu(actx->attr->data.resident.value_length));
	if (err)
		goto err_out;

	err = ntfs_attr_record_rm(actx);
	if (err)
		goto err_out;

	ni_mrec = actx->base_mrec ? actx->base_mrec : actx->mrec;
	ni_mrec->link_count = cpu_to_le16(le16_to_cpu(ni_mrec->link_count) - 1);
	if (!S_ISDIR(VFS_I(ni)->i_mode))
		drop_nlink(VFS_I(ni));

	mark_mft_record_dirty(ni);
	if (looking_for_dos_name) {
		looking_for_dos_name = false;
		looking_for_win32_name = true;
		ntfs_attr_reinit_search_ctx(actx);
		goto search;
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
		NInoSetBeingDeleted(ni);
		ntfs_delete_reparse_index(ni);
		ntfs_delete_object_id_index(ni);
		ntfs_invalidate_stream_inodes(ni);
		link_count_zero = true;
	}

	ntfs_attr_put_search_ctx(actx);
	if (need_lock == true) {
		mutex_unlock(&dir_ni->mrec_lock);
		mutex_unlock(&ni->mrec_lock);
	}

	if (link_count_zero) {
		struct inode *attr_vi;

		while ((attr_vi = ilookup5(sb, ni->mft_no,
				ntfs_test_inode_attr,
				(void *)(uintptr_t)ni->mft_no))) {
			clear_nlink(attr_vi);
			iput(attr_vi);
		}
	}

	ntfs_debug("Done.\n");
	return 0;
err_out:
	ntfs_attr_put_search_ctx(actx);
	if (need_lock) {
		mutex_unlock(&dir_ni->mrec_lock);
		mutex_unlock(&ni->mrec_lock);
	}
	return err;
}

static int ntfs_unlink_named_stream(struct inode *dir, struct dentry *dentry)
{
	struct ntfs_volume *vol = NTFS_SB(dir->i_sb);
	struct inode *base_vi;
	__le16 *base_name = NULL, *stream_name = NULL;
	int base_len, stream_len, path_result, err;

	path_result = ntfs_stream_path_names(vol, &dentry->d_name, &base_name,
			&base_len, &stream_name, &stream_len);
	if (path_result < 0)
		return path_result;
	if (!path_result)
		return -EINVAL;

	base_vi = ntfs_stream_lookup_inode_by_name(dir, base_name, base_len);
	if (IS_ERR(base_vi)) {
		err = PTR_ERR(base_vi);
		goto out_free;
	}
	if (!S_ISREG(base_vi->i_mode)) {
		err = -EISDIR;
		goto out_iput;
	}
	if (!ntfs_inode_is_named_stream(NTFS_I(dentry->d_inode))) {
		err = -ESTALE;
		goto out_iput;
	}
	if (NTFS_I(dentry->d_inode)->ext.base_ntfs_ino != NTFS_I(base_vi)) {
		err = -ESTALE;
		goto out_iput;
	}

	err = ntfs_remove_named_stream(NTFS_I(base_vi), stream_name,
			stream_len, dentry->d_inode);

out_iput:
	iput(base_vi);
out_free:
	kmem_cache_free(ntfs_name_cache, stream_name);
	kmem_cache_free(ntfs_name_cache, base_name);
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

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	err = ntfs_delete(ni, NTFS_I(dir), uname, uname_len, true);
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

static struct dentry *ntfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
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

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	ni = __ntfs_create(idmap, dir, uname, uname_len, mode, 0,
			NULL, 0, NULL, 0, NULL);
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

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	err = ntfs_delete(ni, NTFS_I(dir), uname, uname_len, true);
	if (err)
		goto out;

	inode_set_mtime_to_ts(vi, inode_set_atime_to_ts(vi, current_time(vi)));
out:
	kmem_cache_free(ntfs_name_cache, uname);
	return err;
}

/*
 * __ntfs_link - create hard link for file or directory
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
static int __ntfs_link(struct ntfs_inode *ni, struct ntfs_inode *dir_ni,
		__le16 *name, u8 name_len)
{
	struct super_block *sb;
	struct inode *vi = VFS_I(ni);
	struct file_name_attr *fn = NULL;
	int fn_len, err = 0;
	struct mft_record *dir_mrec = NULL, *ni_mrec = NULL;

	ntfs_debug("Entering.\n");

	sb = dir_ni->vol->sb;
	if (NInoBeingDeleted(dir_ni) || NInoBeingDeleted(ni))
		return -ENOENT;

	ni_mrec = map_mft_record(ni);
	if (IS_ERR(ni_mrec)) {
		err = -EIO;
		goto err_out;
	}

	if (le16_to_cpu(ni_mrec->link_count) == 0) {
		err = -ENOENT;
		goto err_out;
	}

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
		goto err_out;
	}

	fn->parent_directory = MK_LE_MREF(dir_ni->mft_no,
			le16_to_cpu(dir_mrec->sequence_number));
	unmap_mft_record(dir_ni);
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
		fn->data_size = cpu_to_le64(ni->data_size);
	}
	if (NVolHideDotFiles(dir_ni->vol) && name_len > 0 && name[0] == cpu_to_le16('.'))
		fn->file_attributes |= FILE_ATTR_HIDDEN;

	fn->creation_time = utc2ntfs(ni->i_crtime);
	fn->last_data_change_time = utc2ntfs(inode_get_mtime(vi));
	fn->last_mft_change_time = utc2ntfs(inode_get_ctime(vi));
	fn->last_access_time = utc2ntfs(inode_get_atime(vi));
	memcpy(fn->file_name, name, name_len * sizeof(__le16));

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
	kfree(fn);
	unmap_mft_record(ni);

	ntfs_debug("Done.\n");

	return 0;
rollback_failed:
	ntfs_error(sb, "Rollback failed. Leaving inconsistent metadata.\n");
err_out:
	kfree(fn);
	if (!IS_ERR_OR_NULL(ni_mrec))
		unmap_mft_record(ni);
	return err;
}

static int ntfs_rename_named_stream(struct inode *old_dir,
		struct dentry *old_dentry, struct inode *new_dir,
		struct dentry *new_dentry, unsigned int flags)
{
	struct ntfs_volume *vol = NTFS_SB(old_dir->i_sb);
	struct inode *old_base_vi = NULL, *new_base_vi = NULL;
	struct inode *stream_vi = d_inode(old_dentry);
	struct ntfs_inode *base_ni;
	struct ntfs_inode *stream_ni;
	__le16 *old_base_name = NULL, *old_stream_name = NULL;
	__le16 *new_base_name = NULL, *new_stream_name = NULL;
	__le16 *cached_name = NULL;
	int old_base_len, old_stream_len;
	int new_base_len, new_stream_len;
	int old_result, new_result;
	int err;

	if (flags & (RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;
	if (d_inode(new_dentry))
		return flags & RENAME_NOREPLACE ? -EEXIST : -EOPNOTSUPP;

	old_result = ntfs_stream_path_names(vol, &old_dentry->d_name,
			&old_base_name, &old_base_len, &old_stream_name,
			&old_stream_len);
	if (old_result < 0)
		return old_result;
	new_result = ntfs_stream_path_names(vol, &new_dentry->d_name,
			&new_base_name, &new_base_len, &new_stream_name,
			&new_stream_len);
	if (new_result < 0) {
		err = new_result;
		goto out;
	}
	if (!old_result || !new_result) {
		err = -EXDEV;
		goto out;
	}
	if (!stream_vi ||
	    !ntfs_inode_is_named_stream(NTFS_I(stream_vi))) {
		err = -ESTALE;
		goto out;
	}

	old_base_vi = ntfs_stream_lookup_inode_by_name(old_dir,
			old_base_name, old_base_len);
	if (IS_ERR(old_base_vi)) {
		err = PTR_ERR(old_base_vi);
		old_base_vi = NULL;
		goto out;
	}
	new_base_vi = ntfs_stream_lookup_inode_by_name(new_dir,
			new_base_name, new_base_len);
	if (IS_ERR(new_base_vi)) {
		err = PTR_ERR(new_base_vi);
		new_base_vi = NULL;
		goto out;
	}
	if (old_base_vi != new_base_vi) {
		err = -EXDEV;
		goto out;
	}
	if (!S_ISREG(old_base_vi->i_mode)) {
		err = -EISDIR;
		goto out;
	}

	base_ni = NTFS_I(old_base_vi);
	stream_ni = NTFS_I(stream_vi);

	cached_name = kmemdup(new_stream_name,
			(new_stream_len + 1) * sizeof(__le16), GFP_NOFS);
	if (!cached_name) {
		err = -ENOMEM;
		goto out;
	}
	cached_name[new_stream_len] = 0;

	if (!(vol->vol_flags & VOLUME_IS_DIRTY)) {
		err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
		if (err)
			goto out;
	}

	mutex_lock(&base_ni->mrec_lock);
	if (NVolShutdown(vol)) {
		err = -EIO;
		goto out_unlock;
	}
	if (NInoBeingDeleted(base_ni) || !old_base_vi->i_nlink) {
		err = -ENOENT;
		goto out_unlock;
	}
	if (IS_APPEND(old_base_vi) || IS_IMMUTABLE(old_base_vi)) {
		err = -EPERM;
		goto out_unlock;
	}
	if (stream_ni->ext.base_ntfs_ino != base_ni ||
	    stream_ni->name_len != old_stream_len ||
	    !ntfs_names_are_equal(stream_ni->name, stream_ni->name_len,
		    old_stream_name, old_stream_len, CASE_SENSITIVE,
		    vol->upcase, vol->upcase_len)) {
		err = -ESTALE;
		goto out_unlock;
	}
	if (NInoStreamUnlinked(stream_ni)) {
		err = -ENOENT;
		goto out_unlock;
	}
	err = ntfs_stream_inode_validate(stream_vi);
	if (err)
		goto out_unlock;
	if (ntfs_stream_is_unlinked(base_ni, new_stream_name,
			new_stream_len)) {
		err = -EBUSY;
		goto out_unlock;
	}

	down_write(&stream_ni->runlist.lock);
	err = ntfs_attr_rename(base_ni, AT_DATA, old_stream_name,
			old_stream_len, new_stream_name, new_stream_len);
	if (err)
		goto out_unlock_runlist;

	ntfs_stream_inode_set_name(stream_vi, cached_name,
			new_stream_len);
	cached_name = NULL;
	inode_set_mtime_to_ts(old_base_vi,
			inode_set_ctime_current(old_base_vi));
	mark_inode_dirty(old_base_vi);
	ntfs_stream_inode_refresh(stream_vi);

out_unlock_runlist:
	up_write(&stream_ni->runlist.lock);
out_unlock:
	mutex_unlock(&base_ni->mrec_lock);
out:
	kfree(cached_name);
	if (new_base_vi)
		iput(new_base_vi);
	if (old_base_vi)
		iput(old_base_vi);
	if (new_stream_name)
		kmem_cache_free(ntfs_name_cache, new_stream_name);
	if (new_base_name)
		kmem_cache_free(ntfs_name_cache, new_base_name);
	if (old_stream_name)
		kmem_cache_free(ntfs_name_cache, old_stream_name);
	if (old_base_name)
		kmem_cache_free(ntfs_name_cache, old_base_name);
	return err;
}

static int ntfs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
		struct dentry *old_dentry, struct inode *new_dir,
		struct dentry *new_dentry, unsigned int flags)
{
	struct inode *old_inode, *new_inode = NULL;
	int err = 0;
	int is_dir;
	struct super_block *sb = old_dir->i_sb;
	__le16 *uname_new = NULL;
	__le16 *uname_old = NULL;
	int new_name_len;
	int old_name_len;
	struct ntfs_volume *vol = NTFS_SB(sb);
	struct ntfs_inode *old_ni, *new_ni = NULL;
	struct ntfs_inode *old_dir_ni = NTFS_I(old_dir), *new_dir_ni = NTFS_I(new_dir);
	bool new_dir_first = false;

	if (NVolShutdown(old_dir_ni->vol))
		return -EIO;

	if (ntfs_stream_path_has_colon(vol, &old_dentry->d_name) ||
	    ntfs_stream_path_has_colon(vol, &new_dentry->d_name))
		return ntfs_rename_named_stream(old_dir, old_dentry, new_dir,
				new_dentry, flags);

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

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

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
		goto err_out;
	}

	is_dir = S_ISDIR(old_inode->i_mode);

	if (new_inode) {
		if (is_dir) {
			struct mft_record *ni_mrec;

			ni_mrec = map_mft_record(NTFS_I(new_inode));
			if (IS_ERR(ni_mrec)) {
				err = -EIO;
				goto err_out;
			}
			err = ntfs_check_empty_dir(NTFS_I(new_inode), ni_mrec);
			unmap_mft_record(NTFS_I(new_inode));
			if (err)
				goto err_out;
		}

		err = ntfs_delete(new_ni, new_dir_ni, uname_new, new_name_len, false);
		if (err)
			goto err_out;
	}

	err = __ntfs_link(old_ni, new_dir_ni, uname_new, new_name_len);
	if (err)
		goto err_out;

	err = ntfs_delete(old_ni, old_dir_ni, uname_old, old_name_len, false);
	if (err) {
		int err2;

		ntfs_error(sb, "Failed to delete old ntfs inode(%llu) in old dir, err : %d\n",
				old_ni->mft_no, err);
		err2 = ntfs_delete(old_ni, new_dir_ni, uname_new, new_name_len, false);
		if (err2)
			ntfs_error(sb, "Failed to delete old ntfs inode in new dir, err : %d\n",
					err2);
		goto err_out;
	}

	simple_rename_timestamp(old_dir, old_dentry, new_dir, new_dentry);
	mark_inode_dirty(old_inode);
	mark_inode_dirty(old_dir);
	if (old_dir != new_dir)
		mark_inode_dirty(new_dir);
	if (new_inode)
		mark_inode_dirty(old_inode);

	inode_inc_iversion(new_dir);

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
	if (uname_new)
		kmem_cache_free(ntfs_name_cache, uname_new);
	if (uname_old)
		kmem_cache_free(ntfs_name_cache, uname_old);

	return err;
}

static int ntfs_symlink(struct mnt_idmap *idmap, struct inode *dir,
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

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	ni = __ntfs_create(idmap, dir, usrc, usrc_len, S_IFLNK | 0777, 0,
			   symname, symlen, NULL, 0, NULL);
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

static int ntfs_mknod(struct mnt_idmap *idmap, struct inode *dir,
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
	if (NInoAttr(ni))
		return -EOPNOTSUPP;

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

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	switch (mode & S_IFMT) {
	case S_IFCHR:
	case S_IFBLK:
		ni = __ntfs_create(idmap, dir, uname, uname_len,
				mode, rdev, NULL, 0, NULL, 0, NULL);
		break;
	default:
		ni = __ntfs_create(idmap, dir, uname, uname_len,
				mode, 0, NULL, 0, NULL, 0, NULL);
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
	struct ntfs_inode *ni = NTFS_I(vi), *dir_ni = NTFS_I(dir);

	if (NVolShutdown(vol))
		return -EIO;

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

	if (!(vol->vol_flags & VOLUME_IS_DIRTY))
		ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);

	ihold(vi);
	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	mutex_lock_nested(&dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
	err = __ntfs_link(NTFS_I(vi), NTFS_I(dir), uname, uname_len);
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
