// SPDX-License-Identifier: GPL-2.0-or-later
/* KUnit tests for ksmbd's on-disk NDR formats. */

#include <kunit/test.h>
#include <linux/fs.h>
#include <linux/mnt_idmapping.h>
#include <linux/slab.h>
#include <linux/unaligned.h>

#include "../ndr.h"
#include "../xattr.h"

static void ndr_test_free(void *data)
{
	kfree(data);
}

static const struct xattr_dos_attrib dos_attr = {
	.flags = 0x51,
	.attr = 0x20,
	.ea_size = 0x1234,
	.size = 0x2122232425262728ULL,
	.alloc_size = 0x3132333435363738ULL,
	.create_time = 0x1112131415161718ULL,
	.change_time = 0x4142434445464748ULL,
	.itime = 0x0102030405060708ULL,
};

static const u8 dos_v3[] = {
	'0', 'x', '2', '0', 0, 0, 3, 0,
	3, 0, 0, 0, 0x51, 0, 0, 0,
	0x20, 0, 0, 0, 0x34, 0x12, 0, 0,
	0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
	0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
	0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41,
};

static const u8 dos_v4[] = {
	0, 0, 4, 0, 4, 0, 0, 0,
	0x51, 0, 0, 0, 0x20, 0, 0, 0,
	8, 7, 6, 5, 4, 3, 2, 1,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
};

static void ndr_dos_format_test(struct kunit *test)
{
	struct xattr_dos_attrib input = dos_attr, output;
	struct ndr n;
	const u8 *expected;
	size_t size;
	int version, ret;

	for (version = 3; version <= 4; version++) {
		input.version = version;
		ret = ndr_encode_dos_attr(&n, &input);
		KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, ndr_test_free, n.data), 0);
		KUNIT_ASSERT_EQ(test, ret, 0);
		expected = version == 3 ? dos_v3 : dos_v4;
		size = version == 3 ? sizeof(dos_v3) : sizeof(dos_v4);
		KUNIT_ASSERT_EQ(test, n.offset, size);
		KUNIT_EXPECT_MEMEQ(test, n.data, expected, size);

		n.length = n.offset;
		memset(&output, 0, sizeof(output));
		KUNIT_ASSERT_EQ(test, ndr_decode_dos_attr(&n, &output), 0);
		KUNIT_EXPECT_EQ(test, output.version, input.version);
		KUNIT_EXPECT_EQ(test, output.attr, input.attr);
		KUNIT_EXPECT_EQ(test, output.create_time, input.create_time);
		if (version == 4)
			KUNIT_EXPECT_EQ(test, output.itime, input.itime);
	}
}

static void ndr_dos_invalid_test(struct kunit *test)
{
	struct xattr_dos_attrib output;
	char data[sizeof(dos_v4)];
	struct ndr n = { .data = data };
	int len;

	memcpy(data, dos_v4, sizeof(data));
	for (len = 0; len < sizeof(data); len++) {
		n.length = len;
		KUNIT_EXPECT_EQ_MSG(test, ndr_decode_dos_attr(&n, &output),
				    -EINVAL, "length %d", len);
		KUNIT_EXPECT_LE(test, n.offset, n.length);
	}

	n.length = sizeof(data);
	data[4] = 3;
	KUNIT_EXPECT_EQ(test, ndr_decode_dos_attr(&n, &output), -EINVAL);
	memset(data, 'x', sizeof(data));
	KUNIT_EXPECT_EQ(test, ndr_decode_dos_attr(&n, &output), -EINVAL);
	n.length = -1;
	KUNIT_EXPECT_EQ(test, ndr_decode_dos_attr(&n, &output), -EINVAL);
}

static void ndr_dos_full_hex_test(struct kunit *test)
{
	struct xattr_dos_attrib input = dos_attr, output;
	struct ndr n;
	int ret;

	input.version = 3;
	input.attr = U32_MAX;
	ret = ndr_encode_dos_attr(&n, &input);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, ndr_test_free, n.data), 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_MEMEQ(test, n.data, "0xffffffff", sizeof("0xffffffff"));
	KUNIT_EXPECT_EQ(test, n.data[11], 0);
	n.length = n.offset;
	KUNIT_ASSERT_EQ(test, ndr_decode_dos_attr(&n, &output), 0);
	KUNIT_EXPECT_EQ(test, output.attr, U32_MAX);
}

static void ndr_ntacl_large_test(struct kunit *test)
{
	static const u8 header[] = { 4, 0, 4, 0, 0, 0, 2, 0, 4, 0, 2, 0, 1, 0 };
	struct xattr_ntacl input = {
		.version = 4,
		.hash_type = XATTR_SD_HASH_TYPE_SHA256,
		.desc = "posix_acl",
		.desc_len = sizeof(input.desc),
		.sd_size = 8193,
		.current_time = 0x0102030405060708ULL,
	}, output = {};
	struct ndr n;
	int i, ret;

	input.sd_buf = kunit_kmalloc(test, input.sd_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, input.sd_buf);
	for (i = 0; i < input.sd_size; i++)
		((u8 *)input.sd_buf)[i] = i;
	memset(input.hash, 0x5a, sizeof(input.hash));
	memset(input.posix_acl_hash, 0xa5, sizeof(input.posix_acl_hash));

	ret = ndr_encode_v4_ntacl(&n, &input);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, ndr_test_free, n.data), 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_GE(test, n.length, n.offset);
	KUNIT_ASSERT_EQ(test, n.offset, NDR_NTSD_OFFSETOF + input.sd_size);
	KUNIT_EXPECT_MEMEQ(test, n.data, header, sizeof(header));
	KUNIT_EXPECT_MEMEQ(test, n.data + 14, input.hash, sizeof(input.hash));
	KUNIT_EXPECT_MEMEQ(test, n.data + 78, input.desc, sizeof(input.desc));
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(n.data + 88), input.current_time);
	KUNIT_EXPECT_MEMEQ(test, n.data + 96, input.posix_acl_hash,
			   sizeof(input.posix_acl_hash));
	KUNIT_EXPECT_MEMEQ(test, n.data + NDR_NTSD_OFFSETOF, input.sd_buf, input.sd_size);

	n.length = n.offset;
	ret = ndr_decode_v4_ntacl(&n, &output);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, ndr_test_free, output.sd_buf), 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output.sd_size, input.sd_size);
	KUNIT_EXPECT_MEMEQ(test, output.sd_buf, input.sd_buf, input.sd_size);
	KUNIT_EXPECT_MEMEQ(test, output.hash, input.hash, sizeof(input.hash));
	KUNIT_EXPECT_MEMEQ(test, output.posix_acl_hash, input.posix_acl_hash,
			   sizeof(input.posix_acl_hash));
}

static void ndr_ntacl_truncated_test(struct kunit *test)
{
	struct xattr_ntacl input = {
		.version = 4,
		.hash_type = XATTR_SD_HASH_TYPE_SHA256,
		.desc = "posix_acl",
		.desc_len = sizeof(input.desc),
	};
	struct ndr n;
	int len, ret;

	ret = ndr_encode_v4_ntacl(&n, &input);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, ndr_test_free, n.data), 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	for (len = 0; len < NDR_NTSD_OFFSETOF; len++) {
		/* A prefilled description must not hide a failed read. */
		struct xattr_ntacl output = { .desc = "posix_acl" };

		n.length = len;
		KUNIT_EXPECT_EQ_MSG(test, ndr_decode_v4_ntacl(&n, &output),
				    -EINVAL, "length %d", len);
		KUNIT_EXPECT_LE(test, n.offset, n.length);
		kfree(output.sd_buf);
	}
}

static void ndr_ntacl_overflow_test(struct kunit *test)
{
	struct xattr_ntacl input = { .sd_size = U32_MAX };
	struct ndr n;

	KUNIT_EXPECT_EQ(test, ndr_encode_v4_ntacl(&n, &input), -EOVERFLOW);
	KUNIT_EXPECT_PTR_EQ(test, n.data, NULL);
	KUNIT_EXPECT_EQ(test, n.offset, 0);
	kfree(n.data);
}

static struct inode *ndr_test_inode(struct kunit *test)
{
	struct super_block *sb;
	struct inode *inode;

	sb = kunit_kzalloc(test, sizeof(*sb), GFP_KERNEL);
	if (!sb)
		return NULL;
	inode = kunit_kzalloc(test, sizeof(*inode), GFP_KERNEL);
	if (!inode)
		return NULL;
	sb->s_user_ns = &init_user_ns;
	inode->i_sb = sb;
	inode->i_uid = KUIDT_INIT(1000);
	inode->i_gid = KGIDT_INIT(100);
	inode->i_mode = S_IFDIR | 0750;
	return inode;
}

static void ndr_posix_default_only_test(struct kunit *test)
{
	static const u8 expected[] = {
		0, 0, 0, 0, 0, 0, 2, 0,
		0xe8, 3, 0, 0, 0, 0, 0, 0,
		100, 0, 0, 0, 0, 0, 0, 0,
		0xe8, 0x41, 0, 0, 1, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0,
		5, 0, 5, 0, 7, 0, 0, 0,
	};
	struct xattr_smb_acl *acl;
	struct inode *inode;
	struct ndr n;
	int ret;

	inode = ndr_test_inode(test);
	KUNIT_ASSERT_NOT_NULL(test, inode);
	acl = kunit_kzalloc(test, struct_size(acl, entries, 1), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, acl);
	acl->count = 1;
	acl->entries[0].type = SMB_ACL_OTHER;
	acl->entries[0].perm = 7;
	ret = ndr_encode_posix_acl(&n, &nop_mnt_idmap, inode, NULL, acl);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, ndr_test_free, n.data), 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, n.offset, sizeof(expected));
	KUNIT_EXPECT_MEMEQ(test, n.data, expected, sizeof(expected));
}

static void ndr_posix_large_test(struct kunit *test)
{
	struct xattr_smb_acl *acl;
	struct inode *inode;
	struct ndr n;
	int i, ret;

	inode = ndr_test_inode(test);
	KUNIT_ASSERT_NOT_NULL(test, inode);
	acl = kunit_kzalloc(test, struct_size(acl, entries, 256), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, acl);
	acl->count = 256;
	for (i = 0; i < acl->count; i++) {
		acl->entries[i].type = i % 2 ? SMB_ACL_GROUP : SMB_ACL_USER;
		acl->entries[i].uid = i + 1000;
		acl->entries[i].gid = i + 100;
		acl->entries[i].perm = i % 8;
	}

	ret = ndr_encode_posix_acl(&n, &nop_mnt_idmap, inode, acl, NULL);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, ndr_test_free, n.data), 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_GE(test, n.length, n.offset);
	KUNIT_ASSERT_EQ(test, n.offset, 40 + 24 * acl->count - 4);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(n.data), 0x00020000);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(n.data + 28), acl->count);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(n.data + 32), acl->count);
	for (i = 0; i < acl->count; i++) {
		char *entry = n.data + 40 + i * 24;

		KUNIT_EXPECT_EQ(test, get_unaligned_le16(entry), acl->entries[i].type);
		KUNIT_EXPECT_EQ(test, get_unaligned_le16(entry + 2), acl->entries[i].type);
		KUNIT_EXPECT_EQ(test, get_unaligned_le32(entry + 4), 0);
		KUNIT_EXPECT_EQ(test, get_unaligned_le64(entry + 8), i + (i % 2 ? 100 : 1000));
		KUNIT_EXPECT_EQ(test, get_unaligned_le32(entry + 16), acl->entries[i].perm);
		if (i < acl->count - 1)
			KUNIT_EXPECT_EQ(test, get_unaligned_le32(entry + 20), 0);
	}
}

static struct kunit_case ksmbd_ndr_test_cases[] = {
	KUNIT_CASE(ndr_dos_format_test),
	KUNIT_CASE(ndr_dos_invalid_test),
	KUNIT_CASE(ndr_dos_full_hex_test),
	KUNIT_CASE(ndr_ntacl_large_test),
	KUNIT_CASE(ndr_ntacl_truncated_test),
	KUNIT_CASE(ndr_ntacl_overflow_test),
	KUNIT_CASE(ndr_posix_default_only_test),
	KUNIT_CASE(ndr_posix_large_test),
	{}
};

static struct kunit_suite ksmbd_ndr_test_suite = {
	.name = "ksmbd-ndr",
	.test_cases = ksmbd_ndr_test_cases,
};

kunit_test_suite(ksmbd_ndr_test_suite);

MODULE_DESCRIPTION("KUnit tests for ksmbd NDR formats");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
