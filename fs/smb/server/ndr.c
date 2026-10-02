// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 */

#include <linux/fs.h>
#include <linux/overflow.h>

#include "glob.h"
#include "ndr.h"
#include "xattr.h"

static inline char *ndr_get_field(struct ndr *n)
{
	return n->data + n->offset;
}

static int ndr_init(struct ndr *n, size_t length)
{
	n->offset = 0;
	n->length = 0;
	n->data = NULL;
	if (length > INT_MAX)
		return -EOVERFLOW;

	n->length = length;
	n->data = kzalloc(length, KSMBD_DEFAULT_GFP);
	if (!n->data)
		return -ENOMEM;

	return 0;
}

static int ndr_reserve(struct ndr *n, size_t sz)
{
	size_t required, length;
	char *data;

	if (check_add_overflow((size_t)n->offset, sz, &required) ||
	    required > INT_MAX)
		return -EOVERFLOW;

	if (required <= n->length)
		return 0;

	length = max(required, min_t(size_t, (size_t)n->length * 2, INT_MAX));
	data = krealloc(n->data, length, KSMBD_DEFAULT_GFP);
	if (!data)
		return -ENOMEM;

	n->data = data;
	n->length = length;
	return 0;
}

static int ndr_write_bytes(struct ndr *n, const void *value, size_t sz)
{
	int ret;

	ret = ndr_reserve(n, sz);
	if (ret)
		return ret;

	memcpy(ndr_get_field(n), value, sz);
	n->offset += sz;
	return 0;
}

static int ndr_write_align(struct ndr *n, unsigned int alignment)
{
	size_t padding = ALIGN((size_t)n->offset, alignment) - n->offset;
	int ret;

	ret = ndr_reserve(n, padding);
	if (ret)
		return ret;

	memset(ndr_get_field(n), 0, padding);
	n->offset += padding;
	return 0;
}

static int ndr_write_int16(struct ndr *n, __u16 value)
{
	__le16 encoded = cpu_to_le16(value);

	return ndr_write_bytes(n, &encoded, sizeof(encoded));
}

static int ndr_write_int32(struct ndr *n, __u32 value)
{
	__le32 encoded = cpu_to_le32(value);

	return ndr_write_bytes(n, &encoded, sizeof(encoded));
}

static int ndr_write_int64(struct ndr *n, __u64 value)
{
	__le64 encoded = cpu_to_le64(value);

	return ndr_write_bytes(n, &encoded, sizeof(encoded));
}

static int ndr_write_string(struct ndr *n, const char *value)
{
	int ret;

	ret = ndr_write_bytes(n, value, strlen(value) + 1);
	if (ret)
		return ret;

	return ndr_write_align(n, 2);
}

static int ndr_read_bytes(struct ndr *n, void *value, size_t sz)
{
	if (n->offset < 0 || n->offset > n->length ||
	    sz > n->length - n->offset)
		return -EINVAL;

	if (value)
		memcpy(value, ndr_get_field(n), sz);
	n->offset += sz;
	return 0;
}

static int ndr_read_string(struct ndr *n, size_t max_len)
{
	size_t len, limit;
	int ret;

	ret = ndr_read_bytes(n, NULL, 0);
	if (ret)
		return ret;

	limit = min_t(size_t, max_len, n->length - n->offset);
	len = strnlen(ndr_get_field(n), limit);
	if (len == limit)
		return -EINVAL;

	len = ALIGN((size_t)n->offset + len + 1, 2) - n->offset;
	return ndr_read_bytes(n, NULL, len);
}

static int ndr_read_int16(struct ndr *n, __u16 *value)
{
	__le16 encoded;
	int ret;

	ret = ndr_read_bytes(n, value ? &encoded : NULL, sizeof(encoded));
	if (!ret && value)
		*value = le16_to_cpu(encoded);
	return ret;
}

static int ndr_read_int32(struct ndr *n, __u32 *value)
{
	__le32 encoded;
	int ret;

	ret = ndr_read_bytes(n, value ? &encoded : NULL, sizeof(encoded));
	if (!ret && value)
		*value = le32_to_cpu(encoded);
	return ret;
}

static int ndr_read_int64(struct ndr *n, __u64 *value)
{
	__le64 encoded;
	int ret;

	ret = ndr_read_bytes(n, value ? &encoded : NULL, sizeof(encoded));
	if (!ret && value)
		*value = le64_to_cpu(encoded);
	return ret;
}

static int ndr_write_version(struct ndr *n, __u16 version)
{
	int ret;

	ret = ndr_write_int16(n, version);
	if (ret)
		return ret;
	return ndr_write_int32(n, version);
}

static int ndr_read_version(struct ndr *n, __u16 *version)
{
	__u32 version2;
	int ret;

	ret = ndr_read_int16(n, version);
	if (ret)
		return ret;
	ret = ndr_read_int32(n, &version2);
	if (ret)
		return ret;
	if (*version != version2) {
		ksmbd_debug(VFS, "ndr version mismatched(version: %d, version2: %d)\n",
			    *version, version2);
		return -EINVAL;
	}
	return 0;
}

int ndr_encode_dos_attr(struct ndr *n, struct xattr_dos_attrib *da)
{
	char hex_attr[12] = {0};
	int ret;

	ret = ndr_init(n, 64);
	if (ret)
		return ret;

	if (da->version == 3) {
		snprintf(hex_attr, sizeof(hex_attr), "0x%x", da->attr);
		ret = ndr_write_string(n, hex_attr);
	} else {
		ret = ndr_write_string(n, "");
	}
	if (ret)
		return ret;

	ret = ndr_write_version(n, da->version);
	if (ret)
		return ret;

	ret = ndr_write_int32(n, da->flags);
	if (ret)
		return ret;

	ret = ndr_write_int32(n, da->attr);
	if (ret)
		return ret;

	if (da->version == 3) {
		ret = ndr_write_int32(n, da->ea_size);
		if (ret)
			return ret;
		ret = ndr_write_int64(n, da->size);
		if (ret)
			return ret;
		ret = ndr_write_int64(n, da->alloc_size);
	} else {
		ret = ndr_write_int64(n, da->itime);
	}
	if (ret)
		return ret;

	ret = ndr_write_int64(n, da->create_time);
	if (ret)
		return ret;

	if (da->version == 3)
		ret = ndr_write_int64(n, da->change_time);
	return ret;
}

int ndr_decode_dos_attr(struct ndr *n, struct xattr_dos_attrib *da)
{
	int ret;

	n->offset = 0;
	ret = ndr_read_string(n, 12);
	if (ret)
		return ret;

	ret = ndr_read_version(n, &da->version);
	if (ret)
		return ret;

	if (da->version != 3 && da->version != 4) {
		ksmbd_debug(VFS, "v%d version is not supported\n", da->version);
		return -EINVAL;
	}

	ret = ndr_read_int32(n, NULL);
	if (ret)
		return ret;

	ret = ndr_read_int32(n, &da->attr);
	if (ret)
		return ret;

	if (da->version == 4) {
		ret = ndr_read_int64(n, &da->itime);
		if (ret)
			return ret;

		ret = ndr_read_int64(n, &da->create_time);
	} else {
		ret = ndr_read_int32(n, NULL);
		if (ret)
			return ret;

		ret = ndr_read_int64(n, NULL);
		if (ret)
			return ret;

		ret = ndr_read_int64(n, NULL);
		if (ret)
			return ret;

		ret = ndr_read_int64(n, &da->create_time);
		if (ret)
			return ret;

		ret = ndr_read_int64(n, NULL);
	}

	return ret;
}

static int ndr_encode_posix_acl_entry(struct ndr *n, struct xattr_smb_acl *acl)
{
	int i, ret;

	ret = ndr_write_int32(n, acl->count);
	if (ret)
		return ret;

	ret = ndr_write_align(n, 8);
	if (ret)
		return ret;
	ret = ndr_write_int32(n, acl->count);
	if (ret)
		return ret;

	ret = ndr_write_int32(n, 0);
	if (ret)
		return ret;

	for (i = 0; i < acl->count; i++) {
		ret = ndr_write_align(n, 8);
		if (ret)
			return ret;
		ret = ndr_write_int16(n, acl->entries[i].type);
		if (ret)
			return ret;

		ret = ndr_write_int16(n, acl->entries[i].type);
		if (ret)
			return ret;

		if (acl->entries[i].type == SMB_ACL_USER ||
		    acl->entries[i].type == SMB_ACL_GROUP) {
			ret = ndr_write_align(n, 8);
			if (ret)
				return ret;
			ret = ndr_write_int64(n, acl->entries[i].type == SMB_ACL_USER ?
					      acl->entries[i].uid : acl->entries[i].gid);
		}
		if (ret)
			return ret;

		/* push permission */
		ret = ndr_write_int32(n, acl->entries[i].perm);
		if (ret)
			return ret;
	}

	return ret;
}

int ndr_encode_posix_acl(struct ndr *n,
			 struct mnt_idmap *idmap,
			 struct inode *inode,
			 struct xattr_smb_acl *acl,
			 struct xattr_smb_acl *def_acl)
{
	unsigned int ref_id = 0x00020000;
	int ret;
	vfsuid_t vfsuid;
	vfsgid_t vfsgid;

	ret = ndr_init(n, 1024);
	if (ret)
		return ret;

	if (acl) {
		/* ACL ACCESS */
		ret = ndr_write_int32(n, ref_id);
		ref_id += 4;
	} else {
		ret = ndr_write_int32(n, 0);
	}
	if (ret)
		return ret;

	if (def_acl) {
		/* DEFAULT ACL ACCESS */
		ret = ndr_write_int32(n, ref_id);
	} else {
		ret = ndr_write_int32(n, 0);
	}
	if (ret)
		return ret;

	vfsuid = i_uid_into_vfsuid(idmap, inode);
	ret = ndr_write_int64(n, from_kuid(&init_user_ns, vfsuid_into_kuid(vfsuid)));
	if (ret)
		return ret;
	vfsgid = i_gid_into_vfsgid(idmap, inode);
	ret = ndr_write_int64(n, from_kgid(&init_user_ns, vfsgid_into_kgid(vfsgid)));
	if (ret)
		return ret;
	ret = ndr_write_int32(n, inode->i_mode);
	if (ret)
		return ret;

	if (acl) {
		ret = ndr_encode_posix_acl_entry(n, acl);
		if (ret)
			return ret;
	}
	if (def_acl)
		return ndr_encode_posix_acl_entry(n, def_acl);
	return 0;
}

int ndr_encode_v4_ntacl(struct ndr *n, struct xattr_ntacl *acl)
{
	unsigned int ref_id = 0x00020004;
	int ret;

	ret = ndr_init(n, size_add(NDR_NTSD_OFFSETOF, acl->sd_size));
	if (ret)
		return ret;

	ret = ndr_write_version(n, acl->version);
	if (ret)
		return ret;

	ret = ndr_write_int16(n, 2);
	if (ret)
		return ret;

	ret = ndr_write_int32(n, ref_id);
	if (ret)
		return ret;

	/* push hash type and hash 64bytes */
	ret = ndr_write_int16(n, acl->hash_type);
	if (ret)
		return ret;

	ret = ndr_write_bytes(n, acl->hash, XATTR_SD_HASH_SIZE);
	if (ret)
		return ret;

	ret = ndr_write_bytes(n, acl->desc, acl->desc_len);
	if (ret)
		return ret;

	ret = ndr_write_int64(n, acl->current_time);
	if (ret)
		return ret;

	ret = ndr_write_bytes(n, acl->posix_acl_hash, XATTR_SD_HASH_SIZE);
	if (ret)
		return ret;

	/* push ndr for security descriptor */
	ret = ndr_write_bytes(n, acl->sd_buf, acl->sd_size);
	return ret;
}

int ndr_decode_v4_ntacl(struct ndr *n, struct xattr_ntacl *acl)
{
	int ret;

	n->offset = 0;
	ret = ndr_read_version(n, &acl->version);
	if (ret)
		return ret;
	if (acl->version != 4) {
		ksmbd_debug(VFS, "v%d version is not supported\n", acl->version);
		return -EINVAL;
	}

	/* Read Level */
	ret = ndr_read_int16(n, NULL);
	if (ret)
		return ret;

	/* Read Ref Id */
	ret = ndr_read_int32(n, NULL);
	if (ret)
		return ret;

	ret = ndr_read_int16(n, &acl->hash_type);
	if (ret)
		return ret;

	ret = ndr_read_bytes(n, acl->hash, XATTR_SD_HASH_SIZE);
	if (ret)
		return ret;

	ret = ndr_read_bytes(n, acl->desc, sizeof(acl->desc));
	if (ret)
		return ret;
	if (strncmp(acl->desc, "posix_acl", 9)) {
		pr_err("Invalid acl description : %.*s\n",
		       (int)sizeof(acl->desc), acl->desc);
		return -EINVAL;
	}

	/* Read Time */
	ret = ndr_read_int64(n, NULL);
	if (ret)
		return ret;

	/* Read Posix ACL hash */
	ret = ndr_read_bytes(n, acl->posix_acl_hash, XATTR_SD_HASH_SIZE);
	if (ret)
		return ret;

	acl->sd_size = n->length - n->offset;
	acl->sd_buf = kmemdup(ndr_get_field(n), acl->sd_size, KSMBD_DEFAULT_GFP);
	if (!acl->sd_buf)
		return -ENOMEM;

	n->offset += acl->sd_size;
	return 0;
}
