// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Pocessing of EA's
 *
 * Part of this file is based on code from the NTFS-3G project.
 *
 * Copyright (c) 2014-2021 Jean-Pierre Andre
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 */

#include <linux/fs.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>

#include "layout.h"
#include "attrib.h"
#include "index.h"
#include "dir.h"
#include "ea.h"
#include "misc.h"

static int ntfs_write_ea(struct ntfs_inode *ni, int type, char *value, s64 ea_off,
		s64 ea_size)
{
	struct inode *ea_vi;
	int err = 0;
	s64 written;

	ea_vi = ntfs_attr_iget(VFS_I(ni), type, AT_UNNAMED, 0);
	if (IS_ERR(ea_vi))
		return PTR_ERR(ea_vi);

	written = ntfs_inode_attr_pwrite(ea_vi, ea_off, ea_size, value, false);
	if (written != ea_size)
		err = -EIO;
	else
		mark_mft_record_dirty(ni);

	iput(ea_vi);
	return err;
}

static int ntfs_ea_lookup(char *ea_buf, s64 ea_buf_size, const char *name,
		int name_len, s64 *ea_offset, s64 *ea_size)
{
	const struct ea_attr *p_ea;
	s64 offset;
	unsigned int next;

	if (ea_buf_size < sizeof(struct ea_attr))
		goto out;

	offset = 0;
	do {
		p_ea = (const struct ea_attr *)&ea_buf[offset];
		next = le32_to_cpu(p_ea->next_entry_offset);

		if (offset + next > ea_buf_size ||
		    ((1 + p_ea->ea_name_length) > (ea_buf_size - offset)))
			break;

		if (p_ea->ea_name_length == name_len &&
		    !memcmp(p_ea->ea_name, name, name_len)) {
			*ea_offset = offset;
			if (next)
				*ea_size = next;
			else {
				unsigned int ea_len = 1 + p_ea->ea_name_length +
						le16_to_cpu(p_ea->ea_value_length);

				if ((ea_buf_size - offset) < ea_len)
					goto out;

				*ea_size = ALIGN(struct_size(p_ea, ea_name,
							1 + p_ea->ea_name_length +
							le16_to_cpu(p_ea->ea_value_length)), 4);
			}

			if (ea_buf_size < *ea_offset + *ea_size)
				goto out;

			return 0;
		}
		offset += next;
	} while (next > 0 && offset < ea_buf_size &&
		 sizeof(struct ea_attr) < (ea_buf_size - offset));

out:
	return -ENOENT;
}

/*
 * Return the existing EA
 *
 * The EA_INFORMATION is not examined and the consistency of the
 * existing EA is not checked.
 *
 * If successful, the full attribute is returned unchanged
 * and its size is returned.
 * If the designated buffer is too small, the needed size is
 * returned, and the buffer is left unchanged.
 * If there is an error, a negative value is returned and errno
 * is set according to the error.
 */
static int ntfs_get_ea(struct inode *inode, const char *name, size_t name_len,
		void *buffer, size_t size)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	const struct ea_attr *p_ea;
	char *ea_buf;
	s64 ea_off, ea_size, all_ea_size, ea_info_size;
	int err;
	unsigned short int ea_value_len, ea_info_qlen;
	struct ea_information *p_ea_info;

	if (!NInoHasEA(ni))
		return -ENODATA;

	p_ea_info = ntfs_attr_readall(ni, AT_EA_INFORMATION, NULL, 0,
			&ea_info_size);
	if (!p_ea_info || ea_info_size != sizeof(struct ea_information)) {
		ntfs_free(p_ea_info);
		return -ENODATA;
	}

	ea_info_qlen = le16_to_cpu(p_ea_info->ea_query_length);
	ntfs_free(p_ea_info);

	ea_buf = ntfs_attr_readall(ni, AT_EA, NULL, 0, &all_ea_size);
	if (!ea_buf)
		return -ENODATA;

	err = ntfs_ea_lookup(ea_buf, ea_info_qlen, name, name_len, &ea_off,
			&ea_size);
	if (!err) {
		p_ea = (struct ea_attr *)&ea_buf[ea_off];
		ea_value_len = le16_to_cpu(p_ea->ea_value_length);
		if (!buffer) {
			ntfs_free(ea_buf);
			return ea_value_len;
		}

		if (ea_value_len > size) {
			err = -ERANGE;
			goto free_ea_buf;
		}

		memcpy(buffer, &p_ea->ea_name[p_ea->ea_name_length + 1],
				ea_value_len);
		ntfs_free(ea_buf);
		return ea_value_len;
	}

	err = -ENODATA;
free_ea_buf:
	ntfs_free(ea_buf);
	return err;
}

static inline int ea_packed_size(const struct ea_attr *p_ea)
{
	/*
	 * 4 bytes for header (flags and lengths) + name length + 1 +
	 * value length.
	 */
	return 5 + p_ea->ea_name_length + le16_to_cpu(p_ea->ea_value_length);
}

/*
 * Set a new EA, and set EA_INFORMATION accordingly
 *
 * This is roughly the same as ZwSetEaFile() on Windows, however
 * the "offset to next" of the last EA should not be cleared.
 *
 * Consistency of the new EA is first checked.
 *
 * EA_INFORMATION is set first, and it is restored to its former
 * state if setting EA fails.
 */
static int ntfs_set_ea(struct inode *inode, const char *name, size_t name_len,
		const void *value, size_t val_size, int flags,
		__le16 *packed_ea_size)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	struct ea_information *p_ea_info = NULL;
	int ea_packed, err = 0;
	struct ea_attr *p_ea;
	unsigned short int ea_info_qsize;
	char *ea_buf = NULL;
	size_t new_ea_size = ALIGN(struct_size(p_ea, ea_name, 1 + name_len + val_size), 4);
	s64 ea_off, ea_info_size, all_ea_size, ea_size;

	if (name_len > 255)
		return -ENAMETOOLONG;

	if (ntfs_attr_exist(ni, AT_EA_INFORMATION, AT_UNNAMED, 0)) {
		p_ea_info = ntfs_attr_readall(ni, AT_EA_INFORMATION, NULL, 0,
						&ea_info_size);
		if (!p_ea_info || ea_info_size != sizeof(struct ea_information))
			goto out;

		ea_buf = ntfs_attr_readall(ni, AT_EA, NULL, 0, &all_ea_size);
		if (!ea_buf) {
			ea_info_qsize = 0;
			ntfs_free(p_ea_info);
			goto create_ea_info;
		}

		ea_info_qsize = le16_to_cpu(p_ea_info->ea_query_length);
	} else {
create_ea_info:
		p_ea_info = ntfs_malloc_nofs(sizeof(struct ea_information));
		if (!p_ea_info)
			return -ENOMEM;

		ea_info_qsize = 0;
		err = ntfs_attr_add(ni, AT_EA_INFORMATION, AT_UNNAMED, 0,
				(char *)p_ea_info, sizeof(struct ea_information));
		if (err)
			goto out;

		if (ntfs_attr_exist(ni, AT_EA, AT_UNNAMED, 0)) {
			err = ntfs_attr_remove(ni, AT_EA, AT_UNNAMED, 0);
			if (err)
				goto out;
		}

		goto alloc_new_ea;
	}

	if (ea_info_qsize > all_ea_size) {
		err = -EIO;
		goto out;
	}

	err = ntfs_ea_lookup(ea_buf, ea_info_qsize, name, name_len, &ea_off,
			&ea_size);
	if (ea_info_qsize && !err) {
		if (flags & XATTR_CREATE) {
			err = -EEXIST;
			goto out;
		}

		p_ea = (struct ea_attr *)(ea_buf + ea_off);

		if (val_size &&
		    le16_to_cpu(p_ea->ea_value_length) == val_size &&
		    !memcmp(p_ea->ea_name + p_ea->ea_name_length + 1, value,
			    val_size))
			goto out;

		le16_add_cpu(&p_ea_info->ea_length, 0 - ea_packed_size(p_ea));

		if (p_ea->flags & NEED_EA)
			le16_add_cpu(&p_ea_info->need_ea_count, -1);

		memmove((char *)p_ea, (char *)p_ea + ea_size, ea_info_qsize - (ea_off + ea_size));
		ea_info_qsize -= ea_size;
		memset(ea_buf + ea_info_qsize, 0, ea_size);
		p_ea_info->ea_query_length = cpu_to_le16(ea_info_qsize);

		err = ntfs_write_ea(ni, AT_EA_INFORMATION, (char *)p_ea_info, 0,
				sizeof(struct ea_information));
		if (err)
			goto out;

		err = ntfs_write_ea(ni, AT_EA, ea_buf, 0, all_ea_size);
		if (err)
			goto out;

		if ((flags & XATTR_REPLACE) && !val_size) {
			/* Remove xattr. */
			goto out;
		}
	} else {
		if (flags & XATTR_REPLACE) {
			err = -ENODATA;
			goto out;
		}
	}
	ntfs_free(ea_buf);

alloc_new_ea:
	ea_buf = kzalloc(new_ea_size, GFP_NOFS);
	if (!ea_buf) {
		err = -ENOMEM;
		goto out;
	}

	/*
	 * EA and REPARSE_POINT compatibility not checked any more,
	 * required by Windows 10, but having both may lead to
	 * problems with earlier versions.
	 */
	p_ea = (struct ea_attr *)ea_buf;
	memcpy(p_ea->ea_name, name, name_len);
	p_ea->ea_name_length = name_len;
	p_ea->ea_name[name_len] = 0;
	memcpy(p_ea->ea_name + name_len + 1, value, val_size);
	p_ea->ea_value_length = cpu_to_le16(val_size);
	p_ea->next_entry_offset = cpu_to_le32(new_ea_size);

	ea_packed = le16_to_cpu(p_ea_info->ea_length) + ea_packed_size(p_ea);
	p_ea_info->ea_length = cpu_to_le16(ea_packed);
	p_ea_info->ea_query_length = cpu_to_le32(ea_info_qsize + new_ea_size);

	if (ea_packed > 0xffff ||
	    ntfs_attr_size_bounds_check(ni->vol, AT_EA, new_ea_size)) {
		err = -EFBIG;
		goto out;
	}

	/*
	 * no EA or EA_INFORMATION : add them
	 */
	if (!ntfs_attr_exist(ni, AT_EA, AT_UNNAMED, 0)) {
		err = ntfs_attr_add(ni, AT_EA, AT_UNNAMED, 0, (char *)p_ea,
				new_ea_size);
		if (err)
			goto out;
	} else {
		err = ntfs_write_ea(ni, AT_EA, (char *)p_ea, ea_info_qsize,
				new_ea_size);
		if (err)
			goto out;
	}

	err = ntfs_write_ea(ni, AT_EA_INFORMATION, (char *)p_ea_info, 0,
			sizeof(struct ea_information));
	if (err)
		goto out;

	if (packed_ea_size)
		*packed_ea_size = p_ea_info->ea_length;
	mark_mft_record_dirty(ni);
out:
	if (ea_info_qsize > 0)
		NInoSetHasEA(ni);
	else
		NInoClearHasEA(ni);

	ntfs_free(ea_buf);
	ntfs_free(p_ea_info);

	return err;
}

/*
 * Check for the presence of an EA "$LXDEV" (used by WSL)
 * and return its value as a device address
 */
int ntfs_ea_get_wsl_inode(struct inode *inode, dev_t *rdevp, unsigned int flags)
{
	int err;
	__le32 v;

	if (!(flags & NTFS_VOL_UID)) {
		/* Load uid to lxuid EA */
		err = ntfs_get_ea(inode, "$LXUID", sizeof("$LXUID") - 1, &v,
				sizeof(v));
		if (err < 0)
			return err;
		i_uid_write(inode, le32_to_cpu(v));
	}

	if (!(flags & NTFS_VOL_UID)) {
		/* Load gid to lxgid EA */
		err = ntfs_get_ea(inode, "$LXGID", sizeof("$LXGID") - 1, &v,
				sizeof(v));
		if (err < 0)
			return err;
		i_gid_write(inode, le32_to_cpu(v));
	}

	/* Load mode to lxmod EA */
	err = ntfs_get_ea(inode, "$LXMOD", sizeof("$LXMOD") - 1, &v, sizeof(v));
	if (err > 0) {
		inode->i_mode = le32_to_cpu(v);
	} else {
		/* Everyone gets all permissions. */
		inode->i_mode |= 0777;
	}

	/* Load mode to lxdev EA */
	err = ntfs_get_ea(inode, "$LXDEV", sizeof("$LXDEV") - 1, &v, sizeof(v));
	if (err > 0)
		*rdevp = le32_to_cpu(v);
	err = 0;

	return err;
}

int ntfs_ea_set_wsl_inode(struct inode *inode, dev_t rdev, __le16 *ea_size,
		unsigned int flags)
{
	__le32 v;
	int err;

	if (flags & NTFS_EA_UID) {
		/* Store uid to lxuid EA */
		v = cpu_to_le32(i_uid_read(inode));
		err = ntfs_set_ea(inode, "$LXUID", sizeof("$LXUID") - 1, &v,
				sizeof(v), 0, ea_size);
		if (err)
			return err;
	}

	if (flags & NTFS_EA_GID) {
		/* Store gid to lxgid EA */
		v = cpu_to_le32(i_gid_read(inode));
		err = ntfs_set_ea(inode, "$LXGID", sizeof("$LXGID") - 1, &v,
				sizeof(v), 0, ea_size);
		if (err)
			return err;
	}

	if (flags & NTFS_EA_MODE) {
		/* Store mode to lxmod EA */
		v = cpu_to_le32(inode->i_mode);
		err = ntfs_set_ea(inode, "$LXMOD", sizeof("$LXMOD") - 1, &v,
				sizeof(v), 0, ea_size);
		if (err)
			return err;
	}

	if (rdev) {
		v = cpu_to_le32(rdev);
		err = ntfs_set_ea(inode, "$LXDEV", sizeof("$LXDEV") - 1, &v, sizeof(v),
				0, ea_size);
	}

	return err;
}

ssize_t ntfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = d_inode(dentry);
	struct ntfs_inode *ni = NTFS_I(inode);
	const struct ea_attr *p_ea;
	s64 offset, ea_buf_size, ea_info_size;
	int next, err = 0, ea_size;
	unsigned int ea_info_qsize;
	char *ea_buf = NULL;
	ssize_t ret = 0;
	struct ea_information *ea_info;

	if (!NInoHasEA(ni))
		return 0;

	mutex_lock(&NTFS_I(inode)->mrec_lock);
	ea_info = ntfs_attr_readall(ni, AT_EA_INFORMATION, NULL, 0,
			&ea_info_size);
	if (!ea_info || ea_info_size != sizeof(struct ea_information))
		goto out;

	ea_info_qsize = le16_to_cpu(ea_info->ea_query_length);

	ea_buf = ntfs_attr_readall(ni, AT_EA, NULL, 0, &ea_buf_size);
	if (!ea_buf)
		goto out;

	if (ea_info_qsize > ea_buf_size)
		goto out;

	if (ea_buf_size < sizeof(struct ea_attr))
		goto out;

	offset = 0;
	do {
		p_ea = (const struct ea_attr *)&ea_buf[offset];
		next = le32_to_cpu(p_ea->next_entry_offset);
		if (next)
			ea_size = next;
		else
			ea_size = ALIGN(struct_size(p_ea, ea_name,
						1 + p_ea->ea_name_length +
						le16_to_cpu(p_ea->ea_value_length)),
					4);
		if (buffer) {
			if (offset + ea_size > ea_info_qsize)
				break;

			if (ret + p_ea->ea_name_length + 1 > size) {
				err = -ERANGE;
				goto out;
			}

			if (p_ea->ea_name_length + 1 > (ea_info_qsize - offset))
				break;

			memcpy(buffer + ret, p_ea->ea_name, p_ea->ea_name_length);
			buffer[ret + p_ea->ea_name_length] = 0;
		}

		ret += p_ea->ea_name_length + 1;
		offset += ea_size;
	} while (next > 0 && offset < ea_info_qsize &&
		 sizeof(struct ea_attr) < (ea_info_qsize - offset));

out:
	mutex_unlock(&NTFS_I(inode)->mrec_lock);
	ntfs_free(ea_info);
	ntfs_free(ea_buf);

	return err ? err : ret;
}

static int ntfs_getxattr(const struct xattr_handler *handler,
		struct dentry *unused, struct inode *inode, const char *name,
		void *buffer, size_t size)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	int err;

	mutex_lock(&ni->mrec_lock);
	err = ntfs_get_ea(inode, name, strlen(name), buffer, size);
	mutex_unlock(&ni->mrec_lock);

	return err;
}

static int ntfs_setxattr(const struct xattr_handler *handler,
		struct mnt_idmap *idmap, struct dentry *unused,
		struct inode *inode, const char *name, const void *value,
		size_t size, int flags)
{
	struct ntfs_inode *ni = NTFS_I(inode);
	int err;

	mutex_lock(&ni->mrec_lock);
	err = ntfs_set_ea(inode, name, strlen(name), value, size, flags, NULL);
	mutex_unlock(&ni->mrec_lock);

	inode_set_ctime_current(inode);
	mark_inode_dirty(inode);
	return err;
}

static bool ntfs_xattr_user_list(struct dentry *dentry)
{
	return true;
}

// clang-format off
static const struct xattr_handler ntfs_other_xattr_handler = {
	.prefix	= "",
	.get	= ntfs_getxattr,
	.set	= ntfs_setxattr,
	.list	= ntfs_xattr_user_list,
};

const struct xattr_handler * const ntfs_xattr_handlers[] = {
	&ntfs_other_xattr_handler,
	NULL,
};
// clang-format on

#ifdef CONFIG_NTFSPLUS_FS_POSIX_ACL
struct posix_acl *ntfs_get_acl(struct mnt_idmap *idmap, struct dentry *dentry,
			       int type)
{
	struct inode *inode = d_inode(dentry);
	struct ntfs_inode *ni = NTFS_I(inode);
	const char *name;
	size_t name_len;
	struct posix_acl *acl;
	int err;
	void *buf;

	/* Allocate PATH_MAX bytes. */
	buf = __getname();
	if (!buf)
		return ERR_PTR(-ENOMEM);

	/* Possible values of 'type' was already checked above. */
	if (type == ACL_TYPE_ACCESS) {
		name = XATTR_NAME_POSIX_ACL_ACCESS;
		name_len = sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1;
	} else {
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
		name_len = sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1;
	}

	mutex_lock(&ni->mrec_lock);
	err = ntfs_get_ea(inode, name, name_len, buf, PATH_MAX);
	mutex_unlock(&ni->mrec_lock);

	/* Translate extended attribute to acl. */
	if (err >= 0)
		acl = posix_acl_from_xattr(&init_user_ns, buf, err);
	else if (err == -ENODATA)
		acl = NULL;
	else
		acl = ERR_PTR(err);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	__putname(buf);

	return acl;
}

static noinline int ntfs_set_acl_ex(struct mnt_idmap *idmap,
				    struct inode *inode, struct posix_acl *acl,
				    int type, bool init_acl)
{
	const char *name;
	size_t size, name_len;
	void *value;
	int err;
	int flags;
	umode_t mode;

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

	mode = inode->i_mode;
	switch (type) {
	case ACL_TYPE_ACCESS:
		/* Do not change i_mode if we are in init_acl */
		if (acl && !init_acl) {
			err = posix_acl_update_mode(idmap, inode, &mode, &acl);
			if (err)
				return err;
		}
		name = XATTR_NAME_POSIX_ACL_ACCESS;
		name_len = sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1;
		break;

	case ACL_TYPE_DEFAULT:
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
		name_len = sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1;
		break;

	default:
		return -EINVAL;
	}

	if (!acl) {
		/* Remove xattr if it can be presented via mode. */
		size = 0;
		value = NULL;
		flags = XATTR_REPLACE;
	} else {
		size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(size, GFP_NOFS);
		if (!value)
			return -ENOMEM;
		err = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		if (err < 0)
			goto out;
		flags = 0;
	}

	mutex_lock(&NTFS_I(inode)->mrec_lock);
	err = ntfs_set_ea(inode, name, name_len, value, size, flags, NULL);
	mutex_unlock(&NTFS_I(inode)->mrec_lock);
	if (err == -ENODATA && !size)
		err = 0; /* Removing non existed xattr. */
	if (!err) {
		set_cached_acl(inode, type, acl);
		inode->i_mode = mode;
		inode_set_ctime_current(inode);
		mark_inode_dirty(inode);
	}

out:
	kfree(value);

	return err;
}

int ntfs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		 struct posix_acl *acl, int type)
{
	return ntfs_set_acl_ex(idmap, d_inode(dentry), acl, type, false);
}

int ntfs_init_acl(struct mnt_idmap *idmap, struct inode *inode,
		  struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int err;

	err = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (err)
		return err;

	if (default_acl) {
		err = ntfs_set_acl_ex(idmap, inode, default_acl,
				      ACL_TYPE_DEFAULT, true);
		posix_acl_release(default_acl);
	} else {
		inode->i_default_acl = NULL;
	}

	if (acl) {
		if (!err)
			err = ntfs_set_acl_ex(idmap, inode, acl,
					      ACL_TYPE_ACCESS, true);
		posix_acl_release(acl);
	} else {
		inode->i_acl = NULL;
	}

	return err;
}
#endif
