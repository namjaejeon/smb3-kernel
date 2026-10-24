// SPDX-License-Identifier: GPL-2.0-or-later
/* Regression tests for reparse storage and native symlink traversal. */

#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/fs_struct.h>
#include <linux/kthread.h>
#include <linux/mount.h>
#include <linux/nls.h>
#include <linux/random.h>
#include <linux/sched/task.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>
#include <linux/unicode.h>
#include <linux/xattr.h>

#include "../connection.h"
#include "../ksmbd_work.h"
#include "../mgmt/share_config.h"
#include "../mgmt/tree_connect.h"
#include "../mgmt/user_config.h"
#include "../mgmt/user_session.h"
#include "../oplock.h"
#include "../server.h"
#include "../smb_common.h"
#include "../unicode.h"
#include "../vfs.h"
#include "../vfs_cache.h"
#include "../../common/smb2status.h"
#include "../../common/smbfsctl.h"

struct reparse_test_ctx {
	struct ksmbd_share_config share;
	struct ksmbd_tree_connect tcon;
	struct ksmbd_conn conn;
	struct ksmbd_work work;
	struct ksmbd_session sess;
	struct ksmbd_user user;
	struct smb_version_values values;
};

static void reparse_test_unmount(void *data)
{
	kern_unmount(data);
}

static void reparse_test_dput(void *data)
{
	dput(data);
}

static int reparse_test_init(struct kunit *test)
{
	struct reparse_test_ctx *ctx;
	struct file_system_type *type;
	struct vfsmount *mnt;
	int ret;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	type = get_fs_type("tmpfs");
	if (!type)
		return -ENODEV;
	mnt = kern_mount(type);
	put_filesystem(type);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);
	ret = kunit_add_action_or_reset(test, reparse_test_unmount, mnt);
	if (ret)
		return ret;
	ctx->share.vfs_path.mnt = mnt;
	ctx->share.vfs_path.dentry = mnt->mnt_root;
	ctx->tcon.share_conf = &ctx->share;
	ctx->work.tcon = &ctx->tcon;
	ctx->work.conn = &ctx->conn;
	test->priv = ctx;
	return 0;
}

static struct dentry *reparse_test_create(struct kunit *test,
					struct dentry *parent,
					const char *name, umode_t mode,
					const char *target)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct mnt_idmap *idmap = mnt_idmap(ctx->share.vfs_path.mnt);
	struct qstr qname = QSTR_INIT(name, strlen(name));
	struct dentry *dentry;
	int ret;

	dentry = start_creating_noperm(parent, &qname);
	if (IS_ERR(dentry))
		return dentry;
	if (S_ISDIR(mode)) {
		dentry = vfs_mkdir(idmap, d_inode(parent), dentry, mode, NULL);
	} else if (target) {
		ret = vfs_symlink(idmap, d_inode(parent), dentry, target, NULL);
		if (ret) {
			end_creating(dentry);
			return ERR_PTR(ret);
		}
	} else {
		ret = vfs_create(idmap, dentry, mode, NULL);
		if (ret) {
			end_creating(dentry);
			return ERR_PTR(ret);
		}
	}
	dentry = end_creating_keep(dentry);
	if (IS_ERR(dentry))
		return dentry;
	ret = kunit_add_action_or_reset(test, reparse_test_dput, dentry);
	return ret ? ERR_PTR(ret) : dentry;
}

static int reparse_test_set(struct reparse_test_ctx *ctx, struct dentry *dentry,
			    u32 tag, const void *data, u32 len)
{
	struct path path = { .mnt = ctx->share.vfs_path.mnt, .dentry = dentry };

	guard(rwsem_write)(&ksmbd_reparse_sem);
	return ksmbd_vfs_set_rp_xattr(mnt_idmap(path.mnt), &path, tag, data, len);
}

static int reparse_test_lookup(struct reparse_test_ctx *ctx, char *name,
			       unsigned int flags, bool caseless)
{
	struct path path;
	int ret;

	guard(rwsem_read)(&ksmbd_reparse_sem);
	ret = ksmbd_vfs_kern_path(&ctx->work, name, flags, &path, caseless);
	if (!ret)
		path_put(&path);
	return ret;
}

static void reparse_test_unload_nls(void *data)
{
	unload_nls(data);
}

static void reparse_test_unload_unicode(void *data)
{
	if (IS_ENABLED(CONFIG_UNICODE))
		utf8_unload(data);
}

static void reparse_test_close_files(void *data)
{
	struct reparse_test_ctx *ctx = data;

	smb2_complete_request_open(&ctx->work);
	ksmbd_close_tree_conn_fds(&ctx->work);
	ksmbd_destroy_file_table(&ctx->sess);
	/* Oplock callbacks retain the embedded connection until their RCU grace period. */
	rcu_barrier();
}

static void reparse_test_init_open(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;

	ctx->conn.local_nls = load_nls("utf8");
	KUNIT_ASSERT_NOT_NULL(test, ctx->conn.local_nls);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, reparse_test_unload_nls,
						      ctx->conn.local_nls), 0);
	KUNIT_ASSERT_EQ(test, ksmbd_init_file_table(&ctx->sess.file_table), 0);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, reparse_test_close_files,
						      ctx), 0);
	ctx->sess.user = &ctx->user;
	ctx->user.name = "kunit";
	work->sess = &ctx->sess;
	ctx->conn.dialect = SMB21_PROT_ID;
	init_smb2_1_server(&ctx->conn);
	atomic_set(&ctx->conn.refcnt, 1);
	atomic_set(&ctx->share.refcount, 1);
	INIT_LIST_HEAD(&ctx->share.veto_list);
	ctx->share.force_uid = KSMBD_SHARE_INVALID_UID;
	ctx->share.force_gid = KSMBD_SHARE_INVALID_GID;
	ctx->share.create_mask = 0777;
	ctx->share.directory_mask = 0777;
	ctx->tcon.flags = KSMBD_TREE_CONN_FLAG_WRITABLE;
	ksmbd_set_fd_limit(1024);
	work->request_buf = kunit_kzalloc(test, 4096, GFP_KERNEL);
	work->response_buf = kunit_kzalloc(test, SZ_64K, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->request_buf);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);
	work->response_sz = SZ_64K;
	work->compound_fid = KSMBD_NO_FID;
	work->compound_pfid = KSMBD_NO_FID;
	work->iov = work->iov_inline;
	work->iov_alloc_cnt = ARRAY_SIZE(work->iov_inline);
}

static struct smb2_create_req *reparse_test_open_req(struct reparse_test_ctx *ctx,
						   const char *name)
{
	struct smb2_create_req *req = smb_get_msg(ctx->work.request_buf);
	int len;

	req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	req->hdr.Command = SMB2_CREATE;
	req->StructureSize = cpu_to_le16(57);
	req->NameOffset = cpu_to_le16(offsetof(struct smb2_create_req, Buffer));
	len = smbConvertToUTF16((__le16 *)req->Buffer, name, strlen(name),
				ctx->conn.local_nls, 0);
	req->NameLength = cpu_to_le16(len * sizeof(__le16));
	req->DesiredAccess = FILE_READ_ATTRIBUTES_LE;
	req->CreateDisposition = FILE_OPEN_LE;
	req->ShareAccess = FILE_SHARE_ALL_LE;
	inc_rfc1001_len(ctx->work.request_buf,
		       offsetof(struct smb2_create_req, Buffer) + len * sizeof(__le16));
	return req;
}

static void reparse_test_reset_request(struct reparse_test_ctx *ctx)
{
	struct ksmbd_work *work = &ctx->work;

	smb2_complete_request_open(work);
	memset(work->request_buf, 0, 4096);
	memset(work->response_buf, 0, SZ_64K);
	work->iov_idx = 0;
	work->iov_cnt = 0;
	work->next_smb2_rcv_hdr_off = 0;
	work->next_smb2_rsp_hdr_off = 0;
	work->curr_smb2_rsp_hdr_off = 0;
	work->compound_fid = KSMBD_NO_FID;
	work->compound_pfid = KSMBD_NO_FID;
	work->compound_status = STATUS_SUCCESS;
}

static struct create_context_hdr *
reparse_test_lease_req(struct reparse_test_ctx *ctx, struct smb2_create_req *req,
		       u8 key, __le32 state)
{
	unsigned int off = ALIGN(le16_to_cpu(req->NameOffset) + le16_to_cpu(req->NameLength), 8);
	struct create_lease *lease = (void *)req + off;
	bool v2 = ctx->conn.dialect >= SMB30_PROT_ID;
	unsigned int len = v2 ? sizeof(struct create_lease_v2) : sizeof(*lease);

	lease->ccontext.NameOffset = cpu_to_le16(offsetof(struct create_lease, Name));
	lease->ccontext.NameLength = cpu_to_le16(4);
	lease->ccontext.DataOffset = cpu_to_le16(offsetof(struct create_lease, lcontext));
	lease->ccontext.DataLength = cpu_to_le32(v2 ? sizeof(struct lease_context_v2) :
						    sizeof(struct lease_context));
	memcpy(lease->Name, SMB2_CREATE_REQUEST_LEASE, 4);
	lease->lcontext.LeaseKey[0] = key;
	lease->lcontext.LeaseState = state;
	req->RequestedOplockLevel = SMB2_OPLOCK_LEVEL_LEASE;
	req->CreateContextsOffset = cpu_to_le32(off);
	req->CreateContextsLength = cpu_to_le32(len);
	*(__be32 *)ctx->work.request_buf = 0;
	inc_rfc1001_len(ctx->work.request_buf, off + len);
	return &lease->ccontext;
}

static void reparse_test_durable_context(struct reparse_test_ctx *ctx,
					 struct smb2_create_req *req, bool reconnect,
					 u64 id, u64 pid)
{
	unsigned int off = le32_to_cpu(req->CreateContextsOffset);
	unsigned int len = le32_to_cpu(req->CreateContextsLength);
	struct create_context_hdr *lease = (void *)req + off;
	struct create_context_hdr *context = (void *)lease + len;
	const char *tag;
	unsigned int size, data_len;

	lease->Next = cpu_to_le32(len);
	if (ctx->conn.dialect < SMB30_PROT_ID) {
		create_durable_req_t *dh = (void *)context;

		tag = reconnect ? SMB2_CREATE_DURABLE_HANDLE_RECONNECT :
			SMB2_CREATE_DURABLE_HANDLE_REQUEST;
		size = sizeof(*dh);
		data_len = sizeof(dh->Data);
		if (reconnect) {
			dh->Data.Fid.VolatileFileId = id;
			dh->Data.Fid.PersistentFileId = pid;
		}
	} else if (reconnect) {
		struct create_durable_handle_reconnect_v2 *dh = (void *)context;

		tag = SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2;
		size = sizeof(*dh);
		data_len = sizeof(dh->dcontext);
		dh->dcontext.Fid.VolatileFileId = id;
		dh->dcontext.Fid.PersistentFileId = pid;
		dh->dcontext.CreateGuid[0] = 42;
	} else {
		struct create_durable_req_v2 *dh = (void *)context;

		tag = SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2;
		size = sizeof(*dh);
		data_len = sizeof(dh->dcontext);
		dh->dcontext.CreateGuid[0] = 42;
	}
	context->NameOffset = cpu_to_le16(sizeof(*context));
	context->NameLength = cpu_to_le16(4);
	context->DataOffset = cpu_to_le16(offsetof(create_durable_req_t, Data));
	context->DataLength = cpu_to_le32(data_len);
	memcpy((u8 *)context + sizeof(*context), tag, 4);
	req->CreateContextsLength = cpu_to_le32(len + size);
	*(__be32 *)ctx->work.request_buf = 0;
	inc_rfc1001_len(ctx->work.request_buf, off + len + size);
}

static int reparse_test_durable_open(struct reparse_test_ctx *ctx)
{
	unsigned int flags = server_conf.flags;
	int ret;

	server_conf.flags |= KSMBD_GLOBAL_FLAG_DURABLE_HANDLE;
	ret = smb2_open(&ctx->work);
	server_conf.flags = flags;
	return ret;
}

static void reparse_test_put_durable(void *data)
{
	struct ksmbd_file *fp = data;

	/* A failed reconnect still owns the disconnected durable lifetime ref. */
	if (!fp->conn && fp->f_state == FP_INITED)
		ksmbd_put_durable_fd(fp);
	ksmbd_put_durable_fd(fp);
}

static int reparse_test_set_ioctl(struct reparse_test_ctx *ctx, u64 id, u64 pid)
{
	struct ksmbd_work *work = &ctx->work;
	struct smb2_ioctl_req *req;
	struct reparse_data_buffer *rp;

	reparse_test_reset_request(ctx);
	req = smb_get_msg(work->request_buf);
	req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	req->hdr.Command = SMB2_IOCTL;
	req->StructureSize = cpu_to_le16(57);
	req->CtlCode = cpu_to_le32(FSCTL_SET_REPARSE_POINT);
	req->PersistentFileId = pid;
	req->VolatileFileId = id;
	req->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
	req->InputOffset = cpu_to_le32(offsetof(struct smb2_ioctl_req, Buffer));
	req->InputCount = cpu_to_le32(sizeof(*rp));
	rp = (void *)req->Buffer;
	rp->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_LX_FIFO);
	inc_rfc1001_len(work->request_buf, offsetof(struct smb2_ioctl_req, Buffer) + sizeof(*rp));
	return smb2_ioctl(work);
}

static int reparse_test_write(struct reparse_test_ctx *ctx, u64 id, u64 pid)
{
	struct smb2_write_req *req;

	reparse_test_reset_request(ctx);
	req = smb_get_msg(ctx->work.request_buf);
	req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	req->hdr.Command = SMB2_WRITE;
	req->StructureSize = cpu_to_le16(49);
	req->PersistentFileId = pid;
	req->VolatileFileId = id;
	req->DataOffset = cpu_to_le16(offsetof(struct smb2_write_req, Buffer));
	req->Length = cpu_to_le32(1);
	req->Buffer[0] = 'x';
	inc_rfc1001_len(ctx->work.request_buf, sizeof(*req) + 1);
	return smb2_write(&ctx->work);
}

static int reparse_test_query_info(struct reparse_test_ctx *ctx, u64 id, u64 pid,
				   u8 info_class)
{
	struct ksmbd_work *work = &ctx->work;
	struct smb2_query_info_req *req;

	reparse_test_reset_request(ctx);
	req = smb_get_msg(work->request_buf);
	req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	req->hdr.Command = SMB2_QUERY_INFO;
	req->StructureSize = cpu_to_le16(41);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = info_class;
	req->OutputBufferLength = cpu_to_le32(4096);
	req->VolatileFileId = id;
	req->PersistentFileId = pid;
	inc_rfc1001_len(work->request_buf, sizeof(*req));
	return smb2_query_info(work);
}

static __le32 reparse_test_query_attributes(struct smb2_query_info_rsp *rsp,
					   u8 info_class)
{
	switch (info_class) {
	case FILE_BASIC_INFORMATION:
		return ((struct file_basic_info *)rsp->Buffer)->Attributes;
	case FILE_ALL_INFORMATION:
		return ((struct smb2_file_all_info *)rsp->Buffer)->Attributes;
	case FILE_NETWORK_OPEN_INFORMATION:
		return ((struct smb2_file_network_open_info *)rsp->Buffer)->Attributes;
	case FILE_ATTRIBUTE_TAG_INFORMATION:
		return ((struct smb2_file_attr_tag_info *)rsp->Buffer)->FileAttributes;
	case SMB_FIND_FILE_POSIX_INFO:
		return ((struct smb311_posix_qinfo *)rsp->Buffer)->DosAttributes;
	default:
		return 0;
	}
}

static void reparse_test_close_disconnected(void *data)
{
	struct dentry *dentry = data;

	ksmbd_close_disconnected_durable_delete_on_close(dentry);
	dput(dentry);
}

struct reparse_durable_case {
	const char *name;
	__le32 disposition;
};

static const struct reparse_durable_case reparse_durable_cases[] = {
	{ "open-if", FILE_OPEN_IF_LE },
	{ "overwrite-if", FILE_OVERWRITE_IF_LE },
};

KUNIT_ARRAY_PARAM_DESC(reparse_durable, reparse_durable_cases, name);

static void reparse_durable_delete_on_close(struct kunit *test)
{
	const struct reparse_durable_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct path path = { .mnt = ctx->share.vfs_path.mnt };
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp;
	struct file *filp;
	char name[] = "file";
	int ret;

	path.dentry = reparse_test_create(test, ctx->share.vfs_path.dentry,
					  name, S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, path.dentry);
	reparse_test_init_open(test);
	filp = dentry_open(&path, O_RDWR, current_cred());
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	fp = ksmbd_open_fd(work, filp);
	if (IS_ERR(fp))
		fput(filp);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, fp);
	ksmbd_open_durable_fd(fp);
	fp->is_durable = true;
	fp->f_state = FP_INITED;
	list_add(&fp->node, &fp->f_ci->m_fp_list);
	ksmbd_fd_set_delete_on_close(fp, FILE_CREATED);

	/* Model the retained handle after its session has disconnected. */
	idr_remove(ctx->sess.file_table.idr, fp->volatile_id);
	fp->volatile_id = KSMBD_NO_FID;
	fp->conn = NULL;
	fp->tcon = NULL;
	atomic_dec(&ctx->conn.stats.open_files_count);
	ksmbd_conn_put(&ctx->conn);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, reparse_test_close_disconnected,
						      dget(path.dentry)), 0);

	req = reparse_test_open_req(ctx, name);
	req->DesiredAccess = FILE_READ_DATA_LE | FILE_WRITE_DATA_LE |
		FILE_READ_ATTRIBUTES_LE | FILE_DELETE_LE;
	req->CreateOptions = FILE_DELETE_ON_CLOSE_LE;
	req->CreateDisposition = param->disposition;
	ret = smb2_open(work);
	KUNIT_ASSERT_EQ(test, ret, 0);
	rsp = smb_get_msg(work->response_buf);
	KUNIT_EXPECT_EQ(test, rsp->CreateAction, cpu_to_le32(FILE_CREATED));
	fp = ksmbd_lookup_fd_slow(work, rsp->VolatileFileId, rsp->PersistentFileId);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_PTR_NE(test, fp->filp->f_path.dentry, path.dentry);
	KUNIT_EXPECT_EQ(test, d_inode(path.dentry)->i_nlink, 0);
	ksmbd_fd_put(work, fp);
	smb2_complete_request_open(work);
	KUNIT_EXPECT_EQ(test, ksmbd_close_fd(work, rsp->VolatileFileId), 0);
	KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, name, 0, false), -ENOENT);
}

struct reparse_stream_case {
	const char *name;
	const char *path;
	u16 unparsed_len;
	u16 dialect;
	bool stored;
	bool compound;
};

static const struct reparse_stream_case reparse_stream_cases[] = {
	{ "native-final", "link:stream", 14, SMB21_PROT_ID, false },
	{ "native-parent", "link\\child:stream", 26, SMB21_PROT_ID, false },
	{ "stored-final", "link:stream", 14, SMB311_PROT_ID, true },
	{ "stored-parent", "link\\child:stream", 26, SMB311_PROT_ID, true },
	{ "native-unnamed", "link::$DATA", 14, SMB21_PROT_ID, false },
	{ "stored-unnamed", "link::$DATA", 14, SMB311_PROT_ID, true },
	{ "native-typed", "link:stream:$DATA", 26, SMB311_PROT_ID, false },
	{ "stored-typed", "link:stream:$DATA", 26, SMB21_PROT_ID, true },
	{ "native-surrogate", "link:\xf0\x9f\x99\x82", 6, SMB311_PROT_ID, false },
	{ "stored-surrogate", "link:\xf0\x9f\x99\x82", 6, SMB21_PROT_ID, true },
	{ "native-no-stream", "link", 0, SMB21_PROT_ID, false },
	{ "stored-no-stream", "link\\child", 12, SMB311_PROT_ID, true },
	{ "native-trailing", "link\\", 2, SMB21_PROT_ID, false },
	{ "stored-trailing", "link\\", 2, SMB311_PROT_ID, true },
	{ "native-parent-trailing", "link\\child\\", 14, SMB311_PROT_ID, false },
	{ "stored-parent-trailing", "link\\child\\", 14, SMB21_PROT_ID, true },
	{ "native-multiple-trailing", "link\\\\\\", 6, SMB311_PROT_ID, false },
	{ "stored-unix-trailing", "link/", 2, SMB21_PROT_ID, true },
	{ "native-stream-trailing", "link:stream:$DATA\\", 28, SMB21_PROT_ID, false },
	{ "stored-stream-trailing", "link:stream:$DATA\\", 28, SMB311_PROT_ID, true },
	{ "native-unicode-trailing", "link\\\xf0\x9f\x99\x82\\", 8, SMB21_PROT_ID, false },
	{ "stored-unicode-trailing", "link\\\xf0\x9f\x99\x82\\", 8, SMB311_PROT_ID, true },
	{ "native-compound-trailing", "link\\", 2, SMB311_PROT_ID, false, true },
	{ "stored-compound-trailing", "link\\", 2, SMB21_PROT_ID, true, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_stream, reparse_stream_cases, name);

static void reparse_symlink_stream_suffix(struct kunit *test)
{
	const struct reparse_stream_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct reparse_symlink_data_buffer *rp;
	struct smb2_err_rsp *rsp;
	struct dentry *link;
	u8 *error_data;
	int ret;

	link = reparse_test_create(test, ctx->share.vfs_path.dentry, "link",
				   param->stored ? S_IFDIR | 0700 : S_IFLNK | 0777,
				   param->stored ? NULL : "target");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, link);
	reparse_test_init_open(test);
	ctx->share.flags |= KSMBD_SHARE_FLAG_STREAMS;
	ctx->conn.dialect = param->dialect;
	if (param->stored) {
		u32 len = sizeof(*rp) - sizeof(struct reparse_data_buffer) + 12;

		rp = kunit_kzalloc(test, sizeof(*rp) + 14, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, rp);
		rp->SubstituteNameLength = cpu_to_le16(12);
		rp->PrintNameLength = cpu_to_le16(12);
		rp->Flags = cpu_to_le32(SYMLINK_FLAG_RELATIVE);
		smbConvertToUTF16((__le16 *)rp->PathBuffer, "target", 6,
				  ctx->conn.local_nls, 0);
		KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, link, IO_REPARSE_TAG_SYMLINK,
						     &rp->SubstituteNameOffset, len), 0);
	}
	reparse_test_open_req(ctx, param->path);
	if (param->compound) {
		struct ksmbd_work *work = &ctx->work;
		struct smb2_hdr *hdr = smb_get_msg(work->request_buf);
		unsigned int len = get_rfc1002_len(work->request_buf);

		memmove((u8 *)hdr + 256, hdr, len);
		memset(hdr, 0, 256);
		hdr->ProtocolId = SMB2_PROTO_NUMBER;
		hdr->Command = SMB2_ECHO;
		hdr->NextCommand = cpu_to_le32(256);
		((struct smb2_hdr *)((u8 *)hdr + 256))->Flags = SMB2_FLAGS_RELATED_OPERATIONS;
		inc_rfc1001_len(work->request_buf, 256);
		KUNIT_ASSERT_EQ(test, smb2_echo(work), 0);
		KUNIT_ASSERT_TRUE(test, is_chained_smb2_message(work));
	}
	ret = smb2_open(&ctx->work);
	KUNIT_EXPECT_EQ(test, ret, -ELOOP);
	rsp = ksmbd_resp_buf_next(&ctx->work);
	KUNIT_ASSERT_EQ(test, rsp->hdr.Status, STATUS_STOPPED_ON_SYMLINK);
	error_data = rsp->ErrorData;
	if (param->dialect == SMB311_PROT_ID) {
		KUNIT_ASSERT_EQ(test, rsp->ErrorContextCount, 1);
		error_data += 8;
	}
	/* Skip SymLinkLength and SymLinkErrorTag to the reparse header. */
	rp = (struct reparse_symlink_data_buffer *)(error_data + 8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(&rp->Reserved), param->unparsed_len);
}

struct reparse_type_case {
	const char *name;
	const char *target;
	const char *path;
	__le32 options;
	__le32 status;
	bool directory;
};

static const struct reparse_type_case reparse_type_cases[] = {
	{ "directory", "target/", "link", FILE_DIRECTORY_FILE_LE, STATUS_SUCCESS, true },
	{ "file", "target", "link", FILE_NON_DIRECTORY_FILE_LE, STATUS_SUCCESS, false },
	{ "directory-as-file", "target/", "link", FILE_NON_DIRECTORY_FILE_LE,
		STATUS_FILE_IS_A_DIRECTORY, true },
	{ "file-as-directory", "target", "link", FILE_DIRECTORY_FILE_LE,
		STATUS_NOT_A_DIRECTORY, false },
	{ "directory-any-type", "target/", "link", 0, STATUS_SUCCESS, true },
	{ "directory-data-stream", "target/", "link::$DATA", 0,
		STATUS_FILE_IS_A_DIRECTORY, true },
	{ "directory-delete", "target/", "link", FILE_DIRECTORY_FILE_LE | FILE_DELETE_ON_CLOSE_LE,
		STATUS_SUCCESS, true },
	{ "file-delete", "target", "link", FILE_NON_DIRECTORY_FILE_LE | FILE_DELETE_ON_CLOSE_LE,
		STATUS_SUCCESS, false },
};

KUNIT_ARRAY_PARAM_DESC(reparse_type, reparse_type_cases, name);

static void reparse_native_symlink_open_type(struct kunit *test)
{
	const struct reparse_type_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp;
	struct dentry *link;
	int ret;

	/* The target is absent: a reparse open must only inspect the link. */
	link = reparse_test_create(test, ctx->share.vfs_path.dentry, "link",
				   S_IFLNK | 0777, param->target);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, link);
	reparse_test_init_open(test);
	ctx->share.flags |= KSMBD_SHARE_FLAG_STREAMS;
	req = reparse_test_open_req(ctx, param->path);
	req->CreateOptions = FILE_OPEN_REPARSE_POINT_LE | param->options;
	if (param->options & FILE_DELETE_ON_CLOSE_LE)
		req->DesiredAccess |= FILE_DELETE_LE;
	ret = smb2_open(work);
	rsp = smb_get_msg(work->response_buf);
	KUNIT_EXPECT_EQ(test, rsp->hdr.Status, param->status);
	if (param->status) {
		KUNIT_EXPECT_LT(test, ret, 0);
		return;
	}
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, rsp->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT_LE);
	KUNIT_EXPECT_EQ(test, !!(rsp->FileAttributes & FILE_ATTRIBUTE_DIRECTORY_LE),
			param->directory);
	fp = ksmbd_lookup_fd_slow(work, rsp->VolatileFileId, rsp->PersistentFileId);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_PTR_EQ(test, fp->filp->f_path.dentry, link);
	KUNIT_EXPECT_TRUE(test, fp->filp->f_mode & FMODE_PATH);
	ksmbd_fd_put(work, fp);
	smb2_complete_request_open(work);
	KUNIT_EXPECT_EQ(test, ksmbd_close_fd(work, rsp->VolatileFileId), 0);
	KUNIT_EXPECT_EQ(test, d_inode(link)->i_nlink,
			param->options & FILE_DELETE_ON_CLOSE_LE ? 0 : 1);
}

static void reparse_storage_roundtrip(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *file;
	static const char payload[] = "opaque reparse data";
	void *data = NULL;
	u32 tag, len;
	int ret;

	file = reparse_test_create(test, ctx->share.vfs_path.dentry,
				   "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	ret = reparse_test_set(ctx, file, IO_REPARSE_TAG_NFS, payload, sizeof(payload));
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = ksmbd_vfs_get_rp_xattr(mnt_idmap(ctx->share.vfs_path.mnt), file,
				     &tag, &data, &len);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, tag, IO_REPARSE_TAG_NFS);
	KUNIT_EXPECT_EQ(test, len, sizeof(payload));
	if (len == sizeof(payload))
		KUNIT_EXPECT_MEMEQ(test, data, payload, len);
	kfree(data);
	KUNIT_EXPECT_EQ(test, reparse_test_set(ctx, file, IO_REPARSE_TAG_LX_FIFO,
					      NULL, 0), -EEXIST);
}

static void reparse_storage_checksum(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct path path = { .mnt = ctx->share.vfs_path.mnt };
	void *data;
	char *blob;
	u32 tag, len;
	ssize_t size;
	int ret;

	path.dentry = reparse_test_create(test, ctx->share.vfs_path.dentry,
					 "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, path.dentry);
	KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, path.dentry,
						IO_REPARSE_TAG_LX_FIFO, NULL, 0), 0);
	size = ksmbd_vfs_getxattr(mnt_idmap(path.mnt), path.dentry, XATTR_NAME_RP, &blob);
	KUNIT_ASSERT_GT(test, size, 0);
	blob[size - 1] ^= 1;
	ret = vfs_setxattr(mnt_idmap(path.mnt), path.dentry, XATTR_NAME_RP, blob, size, 0);
	kfree(blob);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = ksmbd_vfs_get_rp_xattr(mnt_idmap(path.mnt), path.dentry, &tag, &data, &len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	if (!ret)
		kfree(data);
}

static void reparse_storage_native_symlink(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *link;

	link = reparse_test_create(test, ctx->share.vfs_path.dentry,
				   "link", S_IFLNK | 0777, "target");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, link);
	KUNIT_EXPECT_EQ(test, reparse_test_set(ctx, link, IO_REPARSE_TAG_LX_FIFO,
					      NULL, 0), -EOPNOTSUPP);
}

static void reparse_storage_size_limit(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	u32 limit = KSMBD_MAX_REPARSE_DATA_SIZE - sizeof(struct reparse_data_buffer);
	struct dentry *file;
	char *data;

	file = reparse_test_create(test, ctx->share.vfs_path.dentry,
				   "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	data = kunit_kzalloc(test, limit + 1, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, data);
	KUNIT_EXPECT_EQ(test, reparse_test_set(ctx, file, IO_REPARSE_TAG_NFS,
					      data, limit), 0);
	KUNIT_EXPECT_EQ(test, reparse_test_set(ctx, file, IO_REPARSE_TAG_NFS,
					      data, limit + 1), -EBADMSG);
}

static void reparse_storage_nonempty_directory(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *dir;

	dir = reparse_test_create(test, ctx->share.vfs_path.dentry,
				  "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, dir,
					"file", S_IFREG | 0600, NULL));
	KUNIT_EXPECT_EQ(test, reparse_test_set(ctx, dir, IO_REPARSE_TAG_LX_FIFO,
					      NULL, 0), -ENOTEMPTY);
}

static void reparse_native_symlink_create(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root = ctx->share.vfs_path.dentry;
	int create_ret, mkdir_ret, nofollow_ret;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"dir", S_IFDIR | 0700, NULL));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"link", S_IFLNK | 0777, "dir"));
	scoped_guard(rwsem_read, &ksmbd_reparse_sem) {
		create_ret = ksmbd_vfs_create(&ctx->work, "link/file", 0600, true);
		mkdir_ret = ksmbd_vfs_mkdir(&ctx->work, "link/subdir", 0700, true);
		nofollow_ret = ksmbd_vfs_create(&ctx->work, "link/blocked", 0600, false);
	}
	KUNIT_EXPECT_EQ(test, create_ret, 0);
	KUNIT_EXPECT_EQ(test, mkdir_ret, 0);
	KUNIT_EXPECT_EQ(test, nofollow_ret, -ELOOP);
}

static void reparse_native_symlink_limit(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root = ctx->share.vfs_path.dentry;
	char name[2 * (MAXSYMLINKS + 1) + sizeof("file")];
	int i, ret;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"file", S_IFREG | 0600, NULL));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"s", S_IFLNK | 0777, "."));
	for (i = 0; i < MAXSYMLINKS; i++)
		memcpy(name + 2 * i, "s/", 2);
	memcpy(name + 2 * MAXSYMLINKS, "file", sizeof("file"));
	/* namei may spend part of MAXSYMLINKS on an RCU-walk retry. */
	for (i = 0; i < 3; i++) {
		ret = reparse_test_lookup(ctx, name, LOOKUP_FOLLOW, false);
		if (ret != -ELOOP)
			break;
	}
	KUNIT_EXPECT_EQ(test, ret, 0);
	memcpy(name + 2 * MAXSYMLINKS, "s/file", sizeof("s/file"));
	KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, name, LOOKUP_FOLLOW, false), -ELOOP);
}

static void reparse_native_symlink_stub_dotdot(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root = ctx->share.vfs_path.dentry, *stub;
	char name[] = "link/file";

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"file", S_IFREG | 0600, NULL));
	stub = reparse_test_create(test, root, "stub", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, stub);
	KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, stub, IO_REPARSE_TAG_LX_FIFO, NULL, 0), 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"link", S_IFLNK | 0777, "stub/.."));
	KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, name, LOOKUP_FOLLOW, false), -EREMOTE);
}

static void reparse_native_symlink_create_stub_dotdot(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root = ctx->share.vfs_path.dentry, *stub;
	char file_name[] = "created-file";
	char dir_name[] = "created-dir";
	int create_ret, mkdir_ret;

	stub = reparse_test_create(test, root, "stub", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, stub);
	KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, stub, IO_REPARSE_TAG_LX_FIFO,
						     NULL, 0), 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"link", S_IFLNK | 0777, "stub/.."));
	scoped_guard(rwsem_read, &ksmbd_reparse_sem) {
		create_ret = ksmbd_vfs_create(&ctx->work, "link/created-file",
					      0600, true);
		mkdir_ret = ksmbd_vfs_mkdir(&ctx->work, "link/created-dir",
					    0700, true);
	}
	KUNIT_EXPECT_EQ(test, create_ret, -EREMOTE);
	KUNIT_EXPECT_EQ(test, mkdir_ret, -EREMOTE);
	KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, file_name, 0, false), -ENOENT);
	KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, dir_name, 0, false), -ENOENT);
}

static void reparse_native_symlink_casefold(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root = ctx->share.vfs_path.dentry, *dir;
	char name[] = "alias/FILE";

	dir = reparse_test_create(test, root, "Dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, dir,
					"file", S_IFREG | 0600, NULL));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"Alias", S_IFLNK | 0777, "Dir"));
	KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, name, LOOKUP_FOLLOW, true), 0);
	KUNIT_EXPECT_STREQ(test, name, "Alias/file");
}

struct reparse_namespace_case {
	const char *name;
	const char *target;
	int error;
	bool hardlink;
	bool follow;
	bool replace;
	bool stub;
};

static const struct reparse_namespace_case reparse_namespace_cases[] = {
	{ "rename-follow", "dir", 0, false, true },
	{ "hardlink-follow", "dir", 0, true, true },
	{ "rename-nofollow", "dir", -ELOOP },
	{ "hardlink-nofollow", "dir", -ELOOP, true },
	{ "rename-replace", "dir", 0, false, true, true },
	{ "hardlink-replace", "dir", 0, true, true, true },
	{ "rename-stub", "stub", -EREMOTE, false, true, false, true },
	{ "hardlink-stub", "stub", -EREMOTE, true, true, false, true },
	{ "rename-stub-dotdot", "stub/../dir", -EREMOTE, false, true, false, true },
	{ "hardlink-stub-dotdot", "stub/../dir", -EREMOTE, true, true, false, true },
	{ "rename-wide", "../outside", -EXDEV, false, true },
	{ "hardlink-wide", "../outside", -EXDEV, true, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_namespace, reparse_namespace_cases, name);

static void reparse_native_symlink_namespace(struct kunit *test)
{
	const struct reparse_namespace_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct dentry *root = ctx->share.vfs_path.dentry, *dir, *source, *stub;
	struct smb2_create_req *create;
	struct smb2_create_rsp *opened;
	struct smb2_set_info_req *req;
	struct path path;
	u64 id, pid;
	unsigned int size;
	int len, ret;
	char destination[] = "dir/result";
	char original[] = "dir/source";

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"outside", S_IFDIR | 0700, NULL));
	root = reparse_test_create(test, root, "share", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, root);
	ctx->share.vfs_path.dentry = root;
	dir = reparse_test_create(test, root, "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	source = reparse_test_create(test, dir, "source", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, source);
	if (param->replace)
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, dir,
						"result", S_IFREG | 0600, NULL));
	if (param->stub) {
		stub = reparse_test_create(test, root, "stub", S_IFDIR | 0700, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, stub);
		KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, stub, IO_REPARSE_TAG_LX_FIFO,
						     NULL, 0), 0);
	}
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"alias", S_IFLNK | 0777, param->target));
	reparse_test_init_open(test);
	if (param->follow)
		ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS;
	/* Namespace operations must remain confined even on a wide-link share. */
	ctx->share.flags |= KSMBD_SHARE_FLAG_WIDE_LINKS;
	create = reparse_test_open_req(ctx, original);
	create->DesiredAccess |= FILE_WRITE_DATA_LE | FILE_DELETE_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	id = opened->VolatileFileId;
	pid = opened->PersistentFileId;
	reparse_test_reset_request(ctx);
	req = smb_get_msg(work->request_buf);
	req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	req->hdr.Command = SMB2_SET_INFO;
	req->StructureSize = cpu_to_le16(33);
	req->InfoType = SMB2_O_INFO_FILE;
	req->BufferOffset = cpu_to_le16(offsetof(struct smb2_set_info_req, Buffer));
	req->VolatileFileId = id;
	req->PersistentFileId = pid;
	if (param->hardlink) {
		struct smb2_file_link_info *info = (void *)req->Buffer;

		req->FileInfoClass = FILE_LINK_INFORMATION;
		info->ReplaceIfExists = param->replace;
		len = smbConvertToUTF16((__le16 *)info->FileName, "alias\\result", 12,
					ctx->conn.local_nls, 0);
		info->FileNameLength = cpu_to_le32(len * sizeof(__le16));
		size = sizeof(*info) + len * sizeof(__le16);
	} else {
		struct smb2_file_rename_info *info = (void *)req->Buffer;

		req->FileInfoClass = FILE_RENAME_INFORMATION;
		info->ReplaceIfExists = param->replace;
		len = smbConvertToUTF16((__le16 *)info->FileName, "alias\\result", 12,
					ctx->conn.local_nls, 0);
		info->FileNameLength = cpu_to_le32(len * sizeof(__le16));
		size = sizeof(*info) + len * sizeof(__le16);
	}
	req->BufferLength = cpu_to_le32(size);
	inc_rfc1001_len(work->request_buf, offsetof(struct smb2_set_info_req, Buffer) + size);
	ret = smb2_set_info(work);
	KUNIT_ASSERT_EQ(test, ret, param->error);
	if (ret) {
		KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, original, 0, false), 0);
		KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, destination, 0, false), -ENOENT);
		return;
	}
	scoped_guard(rwsem_read, &ksmbd_reparse_sem)
		ret = ksmbd_vfs_kern_path(work, destination, 0, &path, false);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, d_inode(path.dentry), d_inode(source));
	path_put(&path);
	KUNIT_EXPECT_EQ(test, reparse_test_lookup(ctx, original, 0, false),
			param->hardlink ? 0 : -ENOENT);
}

struct reparse_compound_case {
	const char *name;
	u16 dialect;
	bool small_buffer;
};

static const struct reparse_compound_case reparse_compound_cases[] = {
	{ "smb21", SMB21_PROT_ID, false },
	{ "smb311", SMB311_PROT_ID, false },
	{ "smb21-small-buffer", SMB21_PROT_ID, true },
	{ "smb311-small-buffer", SMB311_PROT_ID, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_compound, reparse_compound_cases, name);

static void reparse_compound_symlink_error(struct kunit *test)
{
	static const __le16 commands[] = { SMB2_CREATE, SMB2_QUERY_INFO, SMB2_CLOSE };
	const struct reparse_compound_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct reparse_symlink_data_buffer *rp;
	struct smb2_err_rsp *first_rsp, *rsp;
	struct smb2_hdr *req;
	size_t context_len = param->dialect == SMB311_PROT_ID ? 8 : 0;
	size_t target_len = param->small_buffer ? 1024 : 12;
	size_t symlink_len = 8 + sizeof(*rp) + target_len;
	size_t error_len = context_len + symlink_len;
	size_t response_len = ALIGN(sizeof(*rsp) + error_len, 8);
	size_t buffer_len = 4 + 3 * response_len + MAX_CIFS_SMALL_BUFFER_SIZE;
	u8 *expected, *sym;
	int i, ret;

	expected = kunit_kzalloc(test, error_len, GFP_KERNEL);
	work->request_buf = kunit_kzalloc(test, 4 + 3 * 256, GFP_KERNEL);
	work->response_buf = kunit_kzalloc(test, buffer_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, expected);
	KUNIT_ASSERT_NOT_NULL(test, work->request_buf);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);
	work->response_sz = param->small_buffer ?
		4 + response_len + 2 * MAX_CIFS_SMALL_BUFFER_SIZE : buffer_len;
	work->compound_fid = KSMBD_NO_FID;
	work->iov = work->iov_inline;
	work->iov_alloc_cnt = ARRAY_SIZE(work->iov_inline);
	ctx->conn.dialect = param->dialect;
	if (param->small_buffer)
		memset(work->response_buf + work->response_sz, 0xa5,
		       buffer_len - work->response_sz);

	/* Prepare the wire error data returned by the initial failed CREATE. */
	if (context_len)
		put_unaligned_le32(symlink_len, expected);
	sym = expected + context_len;
	put_unaligned_le32(symlink_len - 4, sym);
	put_unaligned_le32(0x4c4d5953, sym + 4);
	rp = (struct reparse_symlink_data_buffer *)(sym + 8);
	rp->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
	rp->ReparseDataLength = cpu_to_le16(sizeof(*rp) -
						 sizeof(struct reparse_data_buffer) + target_len);
	put_unaligned_le16(2, &rp->Reserved); /* UnparsedPathLength */
	rp->SubstituteNameLength = cpu_to_le16(target_len);
	rp->PrintNameLength = cpu_to_le16(target_len);
	rp->Flags = cpu_to_le32(SYMLINK_FLAG_RELATIVE);
	for (i = 0; i < target_len; i += 2)
		put_unaligned_le16('x', rp->PathBuffer + i);

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		req = work->request_buf + 4 + i * 256;
		req->ProtocolId = SMB2_PROTO_NUMBER;
		req->Command = commands[i];
		req->NextCommand = i < 2 ? cpu_to_le32(256) : 0;
		if (i)
			req->Flags = SMB2_FLAGS_RELATED_OPERATIONS;
	}
	inc_rfc1001_len(work->request_buf, 3 * 256);
	first_rsp = smb_get_msg(work->response_buf);
	first_rsp->hdr.Command = SMB2_CREATE;
	first_rsp->hdr.Status = STATUS_STOPPED_ON_SYMLINK;
	memcpy(first_rsp->ErrorData, expected, error_len);
	smb2_set_err_rsp(work);

	for (i = 0; i < 2; i++) {
		KUNIT_ASSERT_TRUE(test, is_chained_smb2_message(work));
		rsp = ksmbd_resp_buf_next(work);
		ret = i ? smb2_close(work) : smb2_query_info(work);
		KUNIT_EXPECT_EQ(test, ret, -EACCES);
		KUNIT_EXPECT_FALSE(test, work->send_no_response);
		if (param->small_buffer) {
			KUNIT_EXPECT_EQ(test, rsp->hdr.Status, STATUS_INSUFFICIENT_RESOURCES);
			KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->ByteCount), 0);
			KUNIT_EXPECT_EQ(test, rsp->ErrorContextCount, 0);
		} else {
			KUNIT_EXPECT_EQ(test, rsp->hdr.Status, STATUS_STOPPED_ON_SYMLINK);
			KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->ByteCount), error_len);
			KUNIT_EXPECT_EQ(test, rsp->ErrorContextCount, !!context_len);
			KUNIT_EXPECT_MEMEQ(test, rsp->ErrorData, expected, error_len);
		}
	}
	KUNIT_EXPECT_FALSE(test, is_chained_smb2_message(work));
	KUNIT_EXPECT_MEMEQ(test, first_rsp->ErrorData, expected, error_len);
	if (param->small_buffer)
		KUNIT_EXPECT_PTR_EQ(test,
			memchr_inv(work->response_buf + work->response_sz, 0xa5,
				   buffer_len - work->response_sz), NULL);
}

struct reparse_fileid_case {
	const char *name;
	u16 dialect;
	bool compound;
};

static const struct reparse_fileid_case reparse_fileid_cases[] = {
	{ "smb21", SMB21_PROT_ID, false },
	{ "smb311", SMB311_PROT_ID, false },
	{ "smb21-compound", SMB21_PROT_ID, true },
	{ "smb311-compound", SMB311_PROT_ID, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_fileid, reparse_fileid_cases, name);

static void reparse_fsctl_fileid(struct kunit *test)
{
	static const u32 commands[] = {
		FSCTL_SET_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_DELETE_REPARSE_POINT,
	};
	const struct reparse_fileid_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct dentry *file;
	struct smb2_create_req *create;
	struct smb2_create_rsp *opened;
	struct smb2_ioctl_req *req;
	struct smb2_ioctl_rsp *rsp;
	struct reparse_data_buffer *rp;
	u64 volatile_id, persistent_id;
	unsigned int i;

	file = reparse_test_create(test, ctx->share.vfs_path.dentry, "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	create = reparse_test_open_req(ctx, "file");
	create->DesiredAccess |= FILE_WRITE_ATTRIBUTES_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	volatile_id = opened->VolatileFileId;
	persistent_id = opened->PersistentFileId;
	KUNIT_ASSERT_NE(test, volatile_id, 0);
	KUNIT_ASSERT_NE(test, persistent_id, 0);

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		unsigned int req_offset = param->compound ? 256 : 0;
		unsigned int input_len = commands[i] == FSCTL_GET_REPARSE_POINT ? 0 :
					 sizeof(*rp);

		reparse_test_reset_request(ctx);
		if (param->compound) {
			create = reparse_test_open_req(ctx, "file");
			create->DesiredAccess |= FILE_WRITE_ATTRIBUTES_LE;
			create->CreateOptions = FILE_OPEN_REPARSE_POINT_LE;
			create->hdr.NextCommand = cpu_to_le32(req_offset);
		}
		req = work->request_buf + 4 + req_offset;
		req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
		req->hdr.Command = SMB2_IOCTL;
		if (param->compound)
			req->hdr.Flags = SMB2_FLAGS_RELATED_OPERATIONS;
		req->StructureSize = cpu_to_le16(57);
		req->CtlCode = cpu_to_le32(commands[i]);
		req->PersistentFileId = param->compound ? KSMBD_NO_FID : persistent_id;
		req->VolatileFileId = param->compound ? KSMBD_NO_FID : volatile_id;
		req->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
		req->InputOffset = cpu_to_le32(offsetof(struct smb2_ioctl_req, Buffer));
		req->InputCount = cpu_to_le32(input_len);
		req->MaxOutputResponse = cpu_to_le32(sizeof(*rp));
		if (input_len) {
			rp = (struct reparse_data_buffer *)req->Buffer;
			rp->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_LX_FIFO);
		}
		*(__be32 *)work->request_buf = 0;
		inc_rfc1001_len(work->request_buf, req_offset +
			       offsetof(struct smb2_ioctl_req, Buffer) + input_len);
		if (param->compound) {
			KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
			opened = smb_get_msg(work->response_buf);
			volatile_id = opened->VolatileFileId;
			persistent_id = opened->PersistentFileId;
			smb2_complete_request_open(work);
			KUNIT_ASSERT_TRUE(test, is_chained_smb2_message(work));
		}
		KUNIT_ASSERT_EQ(test, smb2_ioctl(work), 0);
		rsp = ksmbd_resp_buf_next(work);
		KUNIT_EXPECT_EQ(test, rsp->hdr.Status, STATUS_SUCCESS);
		KUNIT_EXPECT_EQ_MSG(test, rsp->VolatileFileId, volatile_id,
				    "FSCTL %#x returned the wrong volatile ID", commands[i]);
		KUNIT_EXPECT_EQ_MSG(test, rsp->PersistentFileId, persistent_id,
				    "FSCTL %#x returned the wrong persistent ID", commands[i]);
	}
}

struct reparse_alias_case {
	const char *name;
	const char *path;
	const char *native_target;
	const char *child;
	u16 dialect;
	bool nested;
	bool directory;
	bool file_stub;
};

static const struct reparse_alias_case reparse_alias_cases[] = {
	{ "final-smb21", "alias", "dir/stub", NULL, SMB21_PROT_ID },
	{ "final-smb311", "alias", "dir/stub", NULL, SMB311_PROT_ID },
	{ "parent-smb21", "alias\\child", "dir/stub", "child", SMB21_PROT_ID },
	{ "parent-smb311", "alias\\child", "dir/stub", "child", SMB311_PROT_ID },
	{ "final-stream", "alias:stream:$DATA", "dir/stub", NULL, SMB311_PROT_ID },
	{ "parent-stream", "alias\\child:stream:$DATA", "dir/stub", "child", SMB21_PROT_ID },
	{ "directory-alias", "alias\\stub", "dir", NULL, SMB21_PROT_ID },
	{ "directory-alias-parent", "alias\\stub\\child", "dir", "child", SMB311_PROT_ID },
	{ "unicode-suffix", "alias\\\xf0\x9f\x99\x82::$DATA", "dir/stub",
	  "\xf0\x9f\x99\x82", SMB311_PROT_ID },
	{ "nested-alias", "prefix\\alias", "../dir/stub", NULL, SMB21_PROT_ID, true },
	{ "body-child-smb21", "alias", "dir/stub/child", "child", SMB21_PROT_ID },
	{ "body-child-smb311", "alias", "dir/stub/child", "child", SMB311_PROT_ID },
	{ "body-file-stub-smb21", "alias", "dir/stub/child", "child",
	  SMB21_PROT_ID, false, false, true },
	{ "body-file-stub-smb311", "alias", "dir/stub/child", "child",
	  SMB311_PROT_ID, false, false, true },
	{ "body-trailing-smb21", "alias", "dir/stub/", NULL,
	  SMB21_PROT_ID, false, true },
	{ "body-trailing-smb311", "alias", "dir/stub/", NULL,
	  SMB311_PROT_ID, false, true },
	{ "body-parent-smb21", "alias\\child", "dir/stub/.", "child", SMB21_PROT_ID },
	{ "body-parent-smb311", "alias\\child", "dir/stub/.", "child", SMB311_PROT_ID },
	{ "body-stream", "alias:stream:$DATA", "dir/stub/child", "child", SMB311_PROT_ID },
	{ "body-unicode", "alias", "dir/stub/\xf0\x9f\x99\x82",
	  "\xf0\x9f\x99\x82", SMB311_PROT_ID },
};

KUNIT_ARRAY_PARAM_DESC(reparse_alias, reparse_alias_cases, name);

/* SMB clients normalize dot components before issuing the next CREATE. */
static void reparse_test_normalize_name(char *name)
{
	char *src = name, *dst = name, *component;

	strreplace(name, '/', '\\');
	while ((component = strsep(&src, "\\"))) {
		size_t len;

		if (!*component || !strcmp(component, "."))
			continue;
		if (!strcmp(component, "..")) {
			while (dst > name && dst[-1] != '\\')
				dst--;
			if (dst > name)
				dst--;
			continue;
		}
		if (dst > name)
			*dst++ = '\\';
		len = strlen(component);
		memmove(dst, component, len);
		dst += len;
	}
	*dst = '\0';
}

/* Apply a relative symlink response to the original UTF-16 request name. */
static void reparse_test_follow_link(struct kunit *test, char *name, size_t size)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct smb2_create_req *req = smb_get_msg(ctx->work.request_buf);
	struct smb2_err_rsp *rsp = smb_get_msg(ctx->work.response_buf);
	struct reparse_symlink_data_buffer *rp;
	const char *original = (char *)req + le16_to_cpu(req->NameOffset);
	u16 original_len = le16_to_cpu(req->NameLength);
	u16 unparsed_len, parsed_len, parent_len, target_len;
	u8 *error_data = rsp->ErrorData;
	char *wire, *converted;

	KUNIT_ASSERT_EQ(test, rsp->hdr.Status, STATUS_STOPPED_ON_SYMLINK);
	if (ctx->conn.dialect == SMB311_PROT_ID) {
		KUNIT_ASSERT_EQ(test, rsp->ErrorContextCount, 1);
		error_data += 8;
	}
	rp = (struct reparse_symlink_data_buffer *)(error_data + 8);
	KUNIT_ASSERT_EQ(test, rp->Flags, cpu_to_le32(SYMLINK_FLAG_RELATIVE));
	unparsed_len = get_unaligned_le16(&rp->Reserved);
	KUNIT_ASSERT_LE(test, unparsed_len, original_len);
	parsed_len = original_len - unparsed_len;
	parent_len = parsed_len;
	while (parent_len && get_unaligned_le16(original + parent_len - 2) != '\\')
		parent_len -= 2;
	target_len = le16_to_cpu(rp->SubstituteNameLength);
	wire = kunit_kzalloc(test, parent_len + target_len + unparsed_len + 2, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, wire);
	memcpy(wire, original, parent_len);
	memcpy(wire + parent_len, rp->PathBuffer + le16_to_cpu(rp->SubstituteNameOffset),
	       target_len);
	memcpy(wire + parent_len + target_len, original + parsed_len, unparsed_len);
	converted = smb_strndup_from_utf16(wire, parent_len + target_len + unparsed_len,
					   1, ctx->conn.local_nls);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, converted);
	reparse_test_normalize_name(converted);
	KUNIT_EXPECT_GE(test, strscpy(name, converted, size), 0);
	kfree(converted);
}

struct reparse_unicode_case {
	const char *name;
	const char *path;
	u16 unparsed_len;
	u16 dialect;
	bool stored;
	bool parent;
	bool compound;
};

static const struct reparse_unicode_case reparse_unicode_cases[] = {
	{ "native-smb21", "alias\\SS", 6, SMB21_PROT_ID },
	{ "native-smb311", "alias\\SS", 6, SMB311_PROT_ID },
	{ "stored-final-smb21", "alias\\SS", 6, SMB21_PROT_ID, true },
	{ "stored-final-smb311", "alias\\SS", 6, SMB311_PROT_ID, true },
	{ "stored-parent-smb21", "alias\\SS\\child", 18, SMB21_PROT_ID, true, true },
	{ "stored-parent-smb311", "alias\\SS\\child", 18, SMB311_PROT_ID, true, true },
	{ "native-stream", "alias\\SS:stream:$DATA", 32, SMB311_PROT_ID },
	{ "stored-parent-stream", "alias\\SS\\child:stream:$DATA", 44, SMB21_PROT_ID, true, true },
	{ "native-trailing", "alias\\SS\\\\", 10, SMB21_PROT_ID },
	{ "stored-parent-trailing", "alias\\SS\\child\\", 20, SMB311_PROT_ID, true, true },
	{ "native-compound", "alias\\SS", 6, SMB311_PROT_ID, false, false, true },
	{ "stored-parent-compound", "alias\\SS\\child", 18, SMB21_PROT_ID, true, true, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_unicode, reparse_unicode_cases, name);

static void reparse_unicode_symlink_suffix(struct kunit *test)
{
	const struct reparse_unicode_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct dentry *root = ctx->share.vfs_path.dentry, *dir, *link, *target;
	struct reparse_symlink_data_buffer *rp;
	struct smb2_create_req *req;
	struct smb2_create_rsp *opened;
	struct smb2_err_rsp *rsp;
	struct ksmbd_file *fp;
	u8 *error_data;
	char name[128];
	int i, ret = -ELOOP;
	umode_t mode = param->parent ? S_IFDIR | 0700 : S_IFREG | 0600;

	if (!IS_ENABLED(CONFIG_UNICODE)) {
		kunit_skip(test, "CONFIG_UNICODE is disabled");
		return;
	}
	dir = reparse_test_create(test, root, "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	target = reparse_test_create(test, dir, "target", mode, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);
	if (param->parent) {
		target = reparse_test_create(test, target, "child", S_IFREG | 0600, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);
	}
	/* The two UTF-8 bytes in SS match one UTF-16 character after folding. */
	link = reparse_test_create(test, dir, "\xc3\x9f",
				   param->stored ? mode : S_IFLNK | 0777,
				   param->stored ? NULL : "target");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, link);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"alias", S_IFLNK | 0777, "dir"));
	reparse_test_init_open(test);
	ctx->conn.um = utf8_load(UNICODE_AGE(12, 1, 0));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->conn.um);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, reparse_test_unload_unicode,
						      ctx->conn.um), 0);
	ctx->conn.dialect = param->dialect;
	ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS | KSMBD_SHARE_FLAG_STREAMS;
	if (param->stored) {
		rp = kunit_kzalloc(test, sizeof(*rp) + 14, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, rp);
		rp->SubstituteNameLength = cpu_to_le16(12);
		rp->PrintNameLength = cpu_to_le16(12);
		rp->Flags = cpu_to_le32(SYMLINK_FLAG_RELATIVE);
		smbConvertToUTF16((__le16 *)rp->PathBuffer, "target", 6, ctx->conn.local_nls, 0);
		KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, link, IO_REPARSE_TAG_SYMLINK,
						     &rp->SubstituteNameOffset, 24), 0);
	}
	if (strstr(param->path, ":stream")) {
		struct path path = { .mnt = ctx->share.vfs_path.mnt, .dentry = target };
		char *stream_name;
		size_t stream_size;

		KUNIT_ASSERT_EQ(test, ksmbd_vfs_xattr_stream_name("stream", &stream_name,
								 &stream_size, DATA_STREAM), 0);
		ret = ksmbd_vfs_setxattr(mnt_idmap(path.mnt), &path, stream_name,
					 NULL, 0, 0, true);
		kfree(stream_name);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}
	reparse_test_open_req(ctx, param->path);
	if (param->compound) {
		struct smb2_hdr *hdr = smb_get_msg(work->request_buf);
		unsigned int len = get_rfc1002_len(work->request_buf);

		memmove((u8 *)hdr + 256, hdr, len);
		memset(hdr, 0, 256);
		hdr->ProtocolId = SMB2_PROTO_NUMBER;
		hdr->Command = SMB2_ECHO;
		hdr->NextCommand = cpu_to_le32(256);
		((struct smb2_hdr *)((u8 *)hdr + 256))->Flags = SMB2_FLAGS_RELATED_OPERATIONS;
		inc_rfc1001_len(work->request_buf, 256);
		KUNIT_ASSERT_EQ(test, smb2_echo(work), 0);
		KUNIT_ASSERT_TRUE(test, is_chained_smb2_message(work));
	}
	KUNIT_ASSERT_EQ(test, smb2_open(work), -ELOOP);
	rsp = ksmbd_resp_buf_next(work);
	KUNIT_ASSERT_EQ(test, rsp->hdr.Status, STATUS_STOPPED_ON_SYMLINK);
	error_data = rsp->ErrorData;
	if (param->dialect == SMB311_PROT_ID) {
		KUNIT_ASSERT_EQ(test, rsp->ErrorContextCount, 1);
		error_data += 8;
	}
	rp = (void *)(error_data + 8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(&rp->Reserved), param->unparsed_len);
	if (param->compound)
		return;
	reparse_test_follow_link(test, name, sizeof(name));
	for (i = 0; i < 3; i++) {
		reparse_test_reset_request(ctx);
		req = reparse_test_open_req(ctx, name);
		req->DesiredAccess |= FILE_READ_DATA_LE;
		ret = smb2_open(work);
		if (!ret)
			break;
		KUNIT_ASSERT_EQ(test, ret, -ELOOP);
		reparse_test_follow_link(test, name, sizeof(name));
	}
	KUNIT_ASSERT_EQ(test, ret, 0);
	opened = smb_get_msg(work->response_buf);
	fp = ksmbd_lookup_fd_slow(work, opened->VolatileFileId, opened->PersistentFileId);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_PTR_EQ(test, fp->filp->f_path.dentry, target);
	ksmbd_fd_put(work, fp);
}

static void reparse_native_alias_relative_target(struct kunit *test)
{
	const struct reparse_alias_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct dentry *root = ctx->share.vfs_path.dentry, *dir, *stub, *alias_parent;
	struct dentry *target, *decoy;
	struct reparse_symlink_data_buffer *rp;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp;
	struct path target_path = { .mnt = ctx->share.vfs_path.mnt };
	char *stream_name;
	size_t stream_name_size;
	char name[256];
	int i, ret = -ELOOP;
	umode_t mode = param->child || param->directory ?
		S_IFDIR | 0700 : S_IFREG | 0600;

	dir = reparse_test_create(test, root, "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	stub = reparse_test_create(test, dir, "stub",
				   param->file_stub ? S_IFREG | 0600 : mode, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, stub);
	target = reparse_test_create(test, dir, "target", mode, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);
	/* A wrong root-relative retry must also be caught when it can succeed. */
	decoy = reparse_test_create(test, root, "target", mode, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decoy);
	if (param->child) {
		target = reparse_test_create(test, target, param->child, S_IFREG | 0600, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);
		decoy = reparse_test_create(test, decoy, param->child, S_IFREG | 0600, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decoy);
	}
	alias_parent = root;
	if (param->nested) {
		alias_parent = reparse_test_create(test, root, "prefix", S_IFDIR | 0700, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, alias_parent);
	}
	alias_parent = reparse_test_create(test, alias_parent, "alias", S_IFLNK | 0777,
					   param->native_target);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, alias_parent);
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS | KSMBD_SHARE_FLAG_STREAMS;
	rp = kunit_kzalloc(test, sizeof(*rp) + 14, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, rp);
	rp->SubstituteNameLength = cpu_to_le16(12);
	rp->PrintNameLength = cpu_to_le16(12);
	rp->Flags = cpu_to_le32(SYMLINK_FLAG_RELATIVE);
	smbConvertToUTF16((__le16 *)rp->PathBuffer, "target", 6, ctx->conn.local_nls, 0);
	KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, stub, IO_REPARSE_TAG_SYMLINK,
					       &rp->SubstituteNameOffset, 24), 0);
	if (strstr(param->path, ":stream")) {
		target_path.dentry = target;
		ret = ksmbd_vfs_xattr_stream_name("stream", &stream_name,
						  &stream_name_size, DATA_STREAM);
		KUNIT_ASSERT_EQ(test, ret, 0);
		ret = ksmbd_vfs_setxattr(mnt_idmap(target_path.mnt), &target_path,
					 stream_name, NULL, 0, 0, true);
		kfree(stream_name);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}
	strscpy(name, param->path, sizeof(name));
	for (i = 0; i < 3; i++) {
		reparse_test_reset_request(ctx);
		req = reparse_test_open_req(ctx, name);
		req->DesiredAccess |= FILE_READ_DATA_LE;
		ret = smb2_open(work);
		if (!ret)
			break;
		KUNIT_ASSERT_EQ(test, ret, -ELOOP);
		reparse_test_follow_link(test, name, sizeof(name));
	}
	KUNIT_ASSERT_EQ(test, ret, 0);
	rsp = smb_get_msg(work->response_buf);
	fp = ksmbd_lookup_fd_slow(work, rsp->VolatileFileId, rsp->PersistentFileId);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_PTR_EQ(test, fp->filp->f_path.dentry, target);
	ksmbd_fd_put(work, fp);
}

struct reparse_dialect_case {
	const char *name;
	u16 dialect;
};

static const struct reparse_dialect_case reparse_dialect_cases[] = {
	{ "smb21", SMB21_PROT_ID },
	{ "smb311", SMB311_PROT_ID },
};

KUNIT_ARRAY_PARAM_DESC(reparse_dialect, reparse_dialect_cases, name);

static void reparse_hardlink_file_attributes(struct kunit *test)
{
	static const u8 classes[] = {
		FILE_BASIC_INFORMATION, FILE_ALL_INFORMATION, FILE_NETWORK_OPEN_INFORMATION,
		FILE_ATTRIBUTE_TAG_INFORMATION, SMB_FIND_FILE_POSIX_INFO,
	};
	const struct reparse_dialect_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct smb2_create_req *create;
	struct smb2_create_rsp *opened;
	struct ksmbd_file *fp;
	u64 source_id, source_pid, alias_id, alias_pid;
	unsigned int step, i;
	int ret;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test,
				ctx->share.vfs_path.dentry, "source", S_IFREG | 0600, NULL));
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	ctx->tcon.posix_extensions = true;
	ctx->share.path = "";
	create = reparse_test_open_req(ctx, "source");
	create->DesiredAccess |= FILE_WRITE_ATTRIBUTES_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	source_id = opened->VolatileFileId;
	source_pid = opened->PersistentFileId;
	fp = ksmbd_lookup_fd_slow(work, source_id, source_pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	scoped_guard(rwsem_read, &ksmbd_reparse_sem)
		ret = ksmbd_vfs_link(work, fp, "alias");
	ksmbd_fd_put(work, fp);
	KUNIT_ASSERT_EQ(test, ret, 0);
	reparse_test_reset_request(ctx);
	reparse_test_open_req(ctx, "alias");
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	alias_id = opened->VolatileFileId;
	alias_pid = opened->PersistentFileId;
	fp = ksmbd_lookup_fd_slow(work, alias_id, alias_pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	fp->is_posix_ctxt = true;
	ksmbd_fd_put(work, fp);
	for (step = 0; step < 2; step++) {
		struct smb2_ioctl_req *ioctl;
		struct reparse_data_buffer *rp;
		struct smb2_close_req *close;
		struct smb2_close_rsp *closed;
		u64 close_id, close_pid;

		/* Cache the old state on a second alias handle before SET or DELETE. */
		reparse_test_reset_request(ctx);
		create = reparse_test_open_req(ctx, "alias");
		create->CreateOptions = FILE_OPEN_REPARSE_POINT_LE;
		KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
		opened = smb_get_msg(work->response_buf);
		close_id = opened->VolatileFileId;
		close_pid = opened->PersistentFileId;
		reparse_test_reset_request(ctx);
		ioctl = smb_get_msg(work->request_buf);
		ioctl->hdr.ProtocolId = SMB2_PROTO_NUMBER;
		ioctl->hdr.Command = SMB2_IOCTL;
		ioctl->StructureSize = cpu_to_le16(57);
		ioctl->CtlCode = cpu_to_le32(step ? FSCTL_DELETE_REPARSE_POINT :
							FSCTL_SET_REPARSE_POINT);
		ioctl->PersistentFileId = source_pid;
		ioctl->VolatileFileId = source_id;
		ioctl->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
		ioctl->InputOffset = cpu_to_le32(offsetof(struct smb2_ioctl_req, Buffer));
		ioctl->InputCount = cpu_to_le32(sizeof(*rp));
		rp = (void *)ioctl->Buffer;
		rp->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_LX_FIFO);
		inc_rfc1001_len(work->request_buf,
			       offsetof(struct smb2_ioctl_req, Buffer) + sizeof(*rp));
		KUNIT_ASSERT_EQ(test, smb2_ioctl(work), 0);
		for (i = 0; i < ARRAY_SIZE(classes); i++) {
			struct smb2_query_info_rsp *rsp;
			__le32 attrs;

			if (classes[i] == SMB_FIND_FILE_POSIX_INFO &&
			    param->dialect != SMB311_PROT_ID)
				continue;
			KUNIT_ASSERT_EQ(test, reparse_test_query_info(ctx, alias_id,
								      alias_pid, classes[i]), 0);
			rsp = smb_get_msg(work->response_buf);
			attrs = reparse_test_query_attributes(rsp, classes[i]);
			KUNIT_EXPECT_EQ_MSG(test, !!(attrs & FILE_ATTRIBUTE_REPARSE_POINT_LE),
					    !step, "class %#x after %s", classes[i],
					    step ? "DELETE" : "SET");
		}
		reparse_test_reset_request(ctx);
		close = smb_get_msg(work->request_buf);
		close->hdr.ProtocolId = SMB2_PROTO_NUMBER;
		close->hdr.Command = SMB2_CLOSE;
		close->StructureSize = cpu_to_le16(24);
		close->Flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
		close->PersistentFileId = close_pid;
		close->VolatileFileId = close_id;
		inc_rfc1001_len(work->request_buf, sizeof(*close));
		KUNIT_ASSERT_EQ(test, smb2_close(work), 0);
		closed = smb_get_msg(work->response_buf);
		KUNIT_EXPECT_EQ(test, !!(closed->Attributes & FILE_ATTRIBUTE_REPARSE_POINT_LE),
				!step);
	}
}

static void reparse_directory_link_query_info(struct kunit *test)
{
	static const u8 classes[] = { FILE_STANDARD_INFORMATION, FILE_ALL_INFORMATION };
	const struct reparse_dialect_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct smb2_create_req *create;
	struct smb2_create_rsp *opened;
	u64 id, pid;
	unsigned int i;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test,
				ctx->share.vfs_path.dentry, "link", S_IFLNK | 0777, "target/"));
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	ctx->share.path = "";
	create = reparse_test_open_req(ctx, "link");
	create->CreateOptions = FILE_OPEN_REPARSE_POINT_LE | FILE_DIRECTORY_FILE_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	KUNIT_ASSERT_TRUE(test, opened->FileAttributes & FILE_ATTRIBUTE_DIRECTORY_LE);
	id = opened->VolatileFileId;
	pid = opened->PersistentFileId;
	for (i = 0; i < ARRAY_SIZE(classes); i++) {
		struct smb2_query_info_rsp *rsp;
		u8 directory;

		KUNIT_ASSERT_EQ(test, reparse_test_query_info(ctx, id, pid, classes[i]), 0);
		rsp = smb_get_msg(work->response_buf);
		if (classes[i] == FILE_STANDARD_INFORMATION) {
			struct smb2_file_standard_info *info = (void *)rsp->Buffer;

			directory = info->Directory;
		} else {
			struct smb2_file_all_info *info = (void *)rsp->Buffer;

			directory = info->Directory;
			KUNIT_EXPECT_TRUE(test, info->Attributes & FILE_ATTRIBUTE_DIRECTORY_LE);
		}
		KUNIT_EXPECT_EQ_MSG(test, directory, 1, "class %#x", classes[i]);
	}
}

static void reparse_native_alias_metadata(struct kunit *test)
{
	const struct reparse_dialect_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root = ctx->share.vfs_path.dentry, *dir, *subdir, *target;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp;
	char name[128] = "alias\\link";
	int i, ret = -ELOOP;

	dir = reparse_test_create(test, root, "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	subdir = reparse_test_create(test, dir, "subdir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, subdir);
	target = reparse_test_create(test, dir, "target", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"target", S_IFREG | 0600, NULL));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, root,
					"alias", S_IFLNK | 0777, "dir/subdir"));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test, subdir,
					"link", S_IFLNK | 0777, "../target"));
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS;
	for (i = 0; i < 3; i++) {
		reparse_test_reset_request(ctx);
		reparse_test_open_req(ctx, name);
		ret = smb2_open(&ctx->work);
		if (!ret)
			break;
		KUNIT_ASSERT_EQ(test, ret, -ELOOP);
		reparse_test_follow_link(test, name, sizeof(name));
	}
	KUNIT_ASSERT_EQ(test, ret, 0);
	rsp = smb_get_msg(ctx->work.response_buf);
	fp = ksmbd_lookup_fd_slow(&ctx->work, rsp->VolatileFileId, rsp->PersistentFileId);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_PTR_EQ(test, fp->filp->f_path.dentry, target);
	ksmbd_fd_put(&ctx->work, fp);
}

static void reparse_wide_link_file_info(struct kunit *test)
{
	static const u8 classes[] = {
		FILE_ALL_INFORMATION, FILE_NORMALIZED_NAME_INFORMATION, SMB_FIND_FILE_POSIX_INFO,
	};
	const struct reparse_dialect_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct smb2_create_rsp *opened;
	struct ksmbd_file *fp;
	char *alias;
	u64 id, pid;
	unsigned int i;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test,
				ctx->share.vfs_path.dentry, "outside", S_IFREG | 0600, NULL));
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	ctx->share.path = "/share";
	ctx->share.path_sz = strlen(ctx->share.path);
	ctx->tcon.posix_extensions = true;
	reparse_test_open_req(ctx, "outside");
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	id = opened->VolatileFileId;
	pid = opened->PersistentFileId;
	fp = ksmbd_lookup_fd_slow(work, id, pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	/* Keep the fixture private while modeling a target outside /share. */
	fp->is_wide_link = true;
	fp->is_posix_ctxt = true;
	alias = kstrdup("alias/file", GFP_KERNEL);
	fp->wide_link_name = alias;
	ksmbd_fd_put(work, fp);
	KUNIT_ASSERT_NOT_NULL(test, alias);
	for (i = 0; i < ARRAY_SIZE(classes); i++) {
		struct smb2_query_info_req *req;
		struct smb2_query_info_rsp *rsp;
		const char *name, *expected;
		char *converted;
		u32 len;

		if (i && param->dialect != SMB311_PROT_ID)
			continue;
		reparse_test_reset_request(ctx);
		req = smb_get_msg(work->request_buf);
		req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
		req->hdr.Command = SMB2_QUERY_INFO;
		req->StructureSize = cpu_to_le16(41);
		req->InfoType = SMB2_O_INFO_FILE;
		req->FileInfoClass = classes[i];
		req->OutputBufferLength = cpu_to_le32(4096);
		req->VolatileFileId = id;
		req->PersistentFileId = pid;
		inc_rfc1001_len(work->request_buf, sizeof(*req));
		KUNIT_ASSERT_EQ_MSG(test, smb2_query_info(work), 0,
				    "File information class %#x failed", classes[i]);
		rsp = smb_get_msg(work->response_buf);
		KUNIT_ASSERT_EQ(test, rsp->hdr.Status, STATUS_SUCCESS);
		expected = "alias\\file";
		if (classes[i] == FILE_ALL_INFORMATION) {
			struct smb2_file_all_info *info = (void *)rsp->Buffer;

			name = info->FileName;
			len = le32_to_cpu(info->FileNameLength);
			expected = "\\alias\\file";
		} else if (classes[i] == FILE_NORMALIZED_NAME_INFORMATION) {
			struct smb2_file_name_info *info = (void *)rsp->Buffer;

			name = info->FileName;
			len = le32_to_cpu(info->FileNameLength);
		} else {
			struct smb311_posix_qinfo *info = (void *)rsp->Buffer;

			name = &info->Sids[36];
			len = get_unaligned_le32(&info->Sids[32]);
		}
		converted = smb_strndup_from_utf16(name, len, true, ctx->conn.local_nls);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, converted);
		KUNIT_EXPECT_STREQ(test, converted, expected);
		kfree(converted);
	}
}

static void reparse_directory_link_basic_info(struct kunit *test)
{
	const struct reparse_dialect_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct smb2_create_req *create;
	struct smb2_create_rsp *opened;
	struct smb2_set_info_req *req;
	struct file_basic_info *basic;
	struct ksmbd_file *fp;
	u64 id, pid;
	__le32 attrs;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, reparse_test_create(test,
				ctx->share.vfs_path.dentry, "link", S_IFLNK | 0777, "target/"));
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	create = reparse_test_open_req(ctx, "link");
	create->DesiredAccess |= FILE_WRITE_ATTRIBUTES_LE;
	create->CreateOptions = FILE_OPEN_REPARSE_POINT_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	id = opened->VolatileFileId;
	pid = opened->PersistentFileId;
	attrs = opened->FileAttributes | FILE_ATTRIBUTE_HIDDEN_LE;
	KUNIT_ASSERT_TRUE(test, attrs & FILE_ATTRIBUTE_DIRECTORY_LE);
	reparse_test_reset_request(ctx);
	req = smb_get_msg(work->request_buf);
	req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	req->hdr.Command = SMB2_SET_INFO;
	req->StructureSize = cpu_to_le16(33);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = FILE_BASIC_INFORMATION;
	req->BufferOffset = cpu_to_le16(offsetof(struct smb2_set_info_req, Buffer));
	req->BufferLength = cpu_to_le32(sizeof(*basic));
	req->VolatileFileId = id;
	req->PersistentFileId = pid;
	basic = (void *)req->Buffer;
	basic->Attributes = attrs;
	inc_rfc1001_len(work->request_buf,
		       offsetof(struct smb2_set_info_req, Buffer) + sizeof(*basic));
	KUNIT_ASSERT_EQ(test, smb2_set_info(work), 0);
	fp = ksmbd_lookup_fd_slow(work, id, pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_EQ(test, fp->f_ci->m_fattr, attrs);
	ksmbd_fd_put(work, fp);
}

static void reparse_test_put_path(void *data)
{
	path_put(data);
}

static void reparse_test_unlink_host_path(void *data)
{
	struct path *path = data;
	struct file *filp;

	filp = dentry_open(path, O_PATH | O_NOFOLLOW, current_cred());
	if (!IS_ERR(filp)) {
		ksmbd_vfs_unlink(filp);
		fput(filp);
	}
	path_put(path);
}

static int reparse_test_clean_host_dentry(struct kunit *test, struct dentry *dentry)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct path *path = kunit_kmalloc(test, sizeof(*path), GFP_KERNEL);

	if (!path)
		return -ENOMEM;
	*path = ctx->share.vfs_path;
	path->dentry = dentry;
	path_get(path);
	return kunit_add_action_or_reset(test, reparse_test_unlink_host_path, path);
}

static struct dentry *reparse_test_host_create(struct kunit *test, struct dentry *parent,
					       const char *name, umode_t mode,
					       const char *target)
{
	struct dentry *dentry = reparse_test_create(test, parent, name, mode, target);
	int ret;

	if (IS_ERR(dentry))
		return dentry;
	ret = reparse_test_clean_host_dentry(test, dentry);
	return ret ? ERR_PTR(ret) : dentry;
}

/* Absolute native links require a directory reachable through the host root. */
static struct dentry *reparse_test_host_root(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct path *root = kunit_kmalloc(test, sizeof(*root), GFP_KERNEL);
	char name[40];
	int ret;

	if (!root)
		return ERR_PTR(-ENOMEM);
	scoped_with_init_fs()
		ret = kern_path("/", LOOKUP_DIRECTORY, root);
	if (ret)
		return ERR_PTR(ret);
	ret = kunit_add_action_or_reset(test, reparse_test_put_path, root);
	if (ret)
		return ERR_PTR(ret);
	ctx->share.vfs_path = *root;
	snprintf(name, sizeof(name), "ksmbd-reparse-%08x", get_random_u32());
	ctx->share.path = kunit_kmalloc(test, 128, GFP_KERNEL);
	if (!ctx->share.path)
		return ERR_PTR(-ENOMEM);
	snprintf(ctx->share.path, 128, "/%s/share", name);
	ctx->share.path_sz = strlen(ctx->share.path);
	return reparse_test_host_create(test, root->dentry, name, S_IFDIR | 0700, NULL);
}

struct reparse_absolute_case {
	const char *name;
	const char *target;
	int error;
	bool wide;
	bool write;
	bool nofollow;
	bool is_wide;
};

static const struct reparse_absolute_case reparse_absolute_cases[] = {
	{ "inside-read", "share/file" },
	{ "inside-write", "share/file", 0, false, true },
	{ "inside-wide-read", "share/file", 0, true },
	{ "inside-wide-write", "share/file", 0, true, true },
	{ "inside-dotdot", "share/dir/../file", 0, false, true },
	{ "inside-slashes", "/share/file", 0, false, true },
	{ "inside-slashes-wide", "/share/file", 0, true, true },
	{ "inside-dot-prefix", "./share/file", 0, false, true },
	{ "inside-dot-prefix-wide", "./share/file", 0, true, true },
	{ "inside-dot-suffix", "share/./file", 0, false, true },
	{ "outside-read", "outside/file", -EXDEV },
	{ "outside-write", "outside/file", -EXDEV, false, true },
	{ "outside-wide-read", "outside/file", 0, true, false, false, true },
	{ "outside-wide-write", "outside/file", -EACCES, true, true },
	{ "leave-and-return", "share/../share/file", -EXDEV },
	{ "dot-leave-and-return", "./share/../share/file", -EXDEV },
	{ "leave-and-return-wide", "share/../share/file", 0, true, false, false, true },
	{ "stub-dotdot", "share/stub/../file", -ELOOP },
	{ "dot-stub-dotdot", "./share/stub/../file", -ELOOP },
	{ "nofollow", "share/file", -ELOOP, false, false, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_absolute, reparse_absolute_cases, name);

static void reparse_absolute_native_link(struct kunit *test)
{
	const struct reparse_absolute_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root, *share, *outside, *stub, *entry;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp;
	char target[160];
	u64 id, pid;
	int ret;

	root = reparse_test_host_root(test);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, root);
	share = reparse_test_host_create(test, root, "share", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, share);
	outside = reparse_test_host_create(test, root, "outside", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, outside);
	ctx->share.vfs_path.dentry = share;
	entry = reparse_test_host_create(test, share, "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
	entry = reparse_test_host_create(test, outside, "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
	entry = reparse_test_host_create(test, share, "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
	stub = reparse_test_host_create(test, share, "stub", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, stub);
	KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, stub, IO_REPARSE_TAG_LX_FIFO, NULL, 0), 0);
	snprintf(target, sizeof(target), "/%s/%s", root->d_name.name, param->target);
	entry = reparse_test_host_create(test, share, "link", S_IFLNK | 0777, target);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
	reparse_test_init_open(test);
	if (!param->nofollow)
		ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS;
	if (param->wide)
		ctx->share.flags |= KSMBD_SHARE_FLAG_WIDE_LINKS;
	req = reparse_test_open_req(ctx, "link");
	req->DesiredAccess |= FILE_READ_DATA_LE;
	if (param->write)
		req->DesiredAccess |= FILE_WRITE_DATA_LE;
	ret = smb2_open(&ctx->work);
	KUNIT_ASSERT_EQ(test, ret, param->error);
	if (ret)
		return;
	rsp = smb_get_msg(ctx->work.response_buf);
	id = rsp->VolatileFileId;
	pid = rsp->PersistentFileId;
	fp = ksmbd_lookup_fd_slow(&ctx->work, id, pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_EQ(test, fp->is_wide_link, param->is_wide);
	KUNIT_EXPECT_PTR_EQ(test, fp->filp->f_path.dentry->d_parent,
			    str_has_prefix(param->target, "outside/") ? outside : share);
	ksmbd_fd_put(&ctx->work, fp);
	if (param->write)
		KUNIT_EXPECT_EQ(test, reparse_test_write(ctx, id, pid), 0);
}

enum reparse_namespace_operation {
	REPARSE_CREATE,
	REPARSE_MKDIR,
	REPARSE_RENAME,
	REPARSE_LINK,
};

struct reparse_absolute_namespace_case {
	const char *name;
	enum reparse_namespace_operation operation;
	bool outside;
	bool nofollow;
	bool smb_create;
};

static const struct reparse_absolute_namespace_case reparse_absolute_namespace_cases[] = {
	{ "create", REPARSE_CREATE },
	{ "mkdir", REPARSE_MKDIR },
	{ "rename", REPARSE_RENAME },
	{ "hardlink", REPARSE_LINK },
	{ "create-outside", REPARSE_CREATE, true },
	{ "mkdir-outside", REPARSE_MKDIR, true },
	{ "rename-outside", REPARSE_RENAME, true },
	{ "hardlink-outside", REPARSE_LINK, true },
	{ "create-nofollow", REPARSE_CREATE, false, true },
	{ "mkdir-nofollow", REPARSE_MKDIR, false, true },
	{ "rename-nofollow", REPARSE_RENAME, false, true },
	{ "hardlink-nofollow", REPARSE_LINK, false, true },
	{ "smb-create", REPARSE_CREATE, false, false, true },
	{ "smb-mkdir", REPARSE_MKDIR, false, false, true },
	{ "smb-create-outside", REPARSE_CREATE, true, false, true },
	{ "smb-mkdir-outside", REPARSE_MKDIR, true, false, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_absolute_namespace, reparse_absolute_namespace_cases, name);

static void reparse_absolute_native_namespace(struct kunit *test)
{
	const struct reparse_absolute_namespace_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root, *share, *dir, *entry;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp;
	struct path path;
	char target[160], result[] = "dir/result";
	char destination[] = "alias/result";
	int ret;

	root = reparse_test_host_root(test);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, root);
	share = reparse_test_host_create(test, root, "share", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, share);
	dir = reparse_test_host_create(test, param->outside ? root : share,
				       "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	ctx->share.vfs_path.dentry = share;
	snprintf(target, sizeof(target), "/%s/%sdir", root->d_name.name,
		 param->outside ? "" : "share/");
	entry = reparse_test_host_create(test, share, "alias", S_IFLNK | 0777, target);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
	entry = reparse_test_host_create(test, share, "source", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
	reparse_test_init_open(test);
	ctx->share.flags |= KSMBD_SHARE_FLAG_WIDE_LINKS;
	if (!param->nofollow)
		ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS;
	req = reparse_test_open_req(ctx, "source");
	req->DesiredAccess |= FILE_WRITE_DATA_LE | FILE_DELETE_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(&ctx->work), 0);
	rsp = smb_get_msg(ctx->work.response_buf);
	fp = ksmbd_lookup_fd_slow(&ctx->work, rsp->VolatileFileId, rsp->PersistentFileId);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	if (param->smb_create) {
		reparse_test_reset_request(ctx);
		req = reparse_test_open_req(ctx, destination);
		req->CreateDisposition = FILE_CREATE_LE;
		req->DesiredAccess |= FILE_READ_DATA_LE | FILE_WRITE_DATA_LE;
		if (param->operation == REPARSE_MKDIR)
			req->CreateOptions = FILE_DIRECTORY_FILE_LE;
		ret = smb2_open(&ctx->work);
	} else {
		guard(rwsem_read)(&ksmbd_reparse_sem);

		switch (param->operation) {
		case REPARSE_CREATE:
			ret = ksmbd_vfs_create(&ctx->work, destination, 0600, !param->nofollow);
			break;
		case REPARSE_MKDIR:
			ret = ksmbd_vfs_mkdir(&ctx->work, destination, 0700, !param->nofollow);
			break;
		case REPARSE_RENAME:
			ret = ksmbd_vfs_rename(&ctx->work, fp, destination, RENAME_NOREPLACE);
			break;
		case REPARSE_LINK:
			ret = ksmbd_vfs_link(&ctx->work, fp, destination);
			break;
		}
	}
	ksmbd_fd_put(&ctx->work, fp);
	KUNIT_ASSERT_EQ(test, ret, param->nofollow ? -ELOOP : param->outside ? -EXDEV : 0);
	if (ret)
		return;
	scoped_guard(rwsem_read, &ksmbd_reparse_sem)
		ret = ksmbd_vfs_kern_path(&ctx->work, result, 0, &path, false);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, path.dentry->d_parent, dir);
	ret = reparse_test_clean_host_dentry(test, path.dentry);
	path_put(&path);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

struct reparse_reconnect_case {
	const char *name;
	const char *open_name;
	const char *reject_name;
	u16 dialect;
	bool parent;
	bool absolute;
	bool wide;
	bool retarget;
	const char *rename_name;
	int rename_error;
};

static const struct reparse_reconnect_case reparse_reconnect_cases[] = {
	{ "smb21-final", "alias", "target", SMB21_PROT_ID },
	{ "smb311-final", "alias", "target", SMB311_PROT_ID },
	{ "smb21-parent", "alias/target", "dir/target", SMB21_PROT_ID, .parent = true },
	{ "smb311-parent", "alias/target", "dir/target", SMB311_PROT_ID, .parent = true },
	{ "smb311-absolute", "alias", "target", SMB311_PROT_ID, .absolute = true },
	{ "smb311-wide", "alias", "target", SMB311_PROT_ID, .wide = true },
	{ "smb21-casefold", "ALIAS", "target", SMB21_PROT_ID },
	{ "smb311-casefold", "ALIAS", "target", SMB311_PROT_ID },
	{ "smb21-rename", "alias", "alias", SMB21_PROT_ID, .rename_name = "renamed" },
	{ "smb311-rename-parent", "alias", "alias", SMB311_PROT_ID,
		.rename_name = "alias-dir/renamed" },
	{ "smb311-rename-failure", "alias", "target", SMB311_PROT_ID,
		.rename_name = "missing/renamed", .rename_error = -ENOENT },
	{ "smb311-retargeted", "alias", "target", SMB311_PROT_ID, .retarget = true },
	{ "smb311-regular", "target", "alias", SMB311_PROT_ID },
	{ "smb311-share-root", "", "target", SMB311_PROT_ID },
};

KUNIT_ARRAY_PARAM_DESC(reparse_reconnect, reparse_reconnect_cases, name);

static void reparse_native_alias_reconnect(struct kunit *test)
{
	const struct reparse_reconnect_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct dentry *root, *share, *dir, *parent, *target, *alias, *entry;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp, *reconnected;
	struct lease_ctx_info lc = { .lease_key = { 10 } };
	struct ksmbd_share_config other_share = {};
	const char *name, *link;
	__le32 state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	u64 id, pid;
	int ret;

	root = reparse_test_host_root(test);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, root);
	share = reparse_test_host_create(test, root, "share", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, share);
	dir = reparse_test_host_create(test, share, "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	parent = param->parent ? dir : share;
	if (param->wide) {
		parent = reparse_test_host_create(test, root, "outside", S_IFDIR | 0700, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, parent);
	}
	target = reparse_test_host_create(test, parent, "target", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);
	link = param->parent ? "dir" : param->wide ? "../outside/target" : "target";
	if (param->absolute) {
		char *absolute = kunit_kmalloc(test, PATH_MAX, GFP_KERNEL);

		KUNIT_ASSERT_NOT_NULL(test, absolute);
		snprintf(absolute, PATH_MAX, "%s/target", ctx->share.path);
		link = absolute;
	}
	alias = reparse_test_host_create(test, share, "alias", S_IFLNK | 0777, link);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, alias);
	entry = reparse_test_host_create(test, share, "alias-dir", S_IFLNK | 0777, "dir");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
	ctx->share.vfs_path.dentry = share;
	ctx->share.real_path = ctx->share.path;
	ctx->share.real_path_sz = ctx->share.path_sz;
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	ctx->values = *ctx->conn.vals;
	ctx->values.req_capabilities |= SMB2_GLOBAL_CAP_LEASING;
	ctx->conn.vals = &ctx->values;
	ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS | KSMBD_SHARE_FLAG_OPLOCKS;
	if (param->wide)
		ctx->share.flags |= KSMBD_SHARE_FLAG_WIDE_LINKS;
	req = reparse_test_open_req(ctx, param->open_name);
	req->DesiredAccess |= FILE_READ_DATA_LE;
	if (param->rename_name)
		req->DesiredAccess |= FILE_DELETE_LE;
	if (!param->open_name[0])
		req->CreateOptions = FILE_DIRECTORY_FILE_LE;
	reparse_test_lease_req(ctx, req, 10, state);
	reparse_test_durable_context(ctx, req, false, 0, 0);
	KUNIT_ASSERT_EQ(test, reparse_test_durable_open(ctx), 0);
	rsp = smb_get_msg(work->response_buf);
	id = rsp->VolatileFileId;
	pid = rsp->PersistentFileId;
	fp = ksmbd_lookup_fd_slow(work, id, pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, reparse_test_put_durable, fp), 0);
	KUNIT_ASSERT_TRUE(test, fp->is_durable);
	if (!param->open_name[0])
		target = share;
	KUNIT_ASSERT_PTR_EQ(test, fp->filp->f_path.dentry, target);

	name = param->open_name;
	if (param->rename_name) {
		struct smb2_set_info_req *rename_req;
		struct smb2_file_rename_info *info;
		int len;

		reparse_test_reset_request(ctx);
		rename_req = smb_get_msg(work->request_buf);
		rename_req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
		rename_req->hdr.Command = SMB2_SET_INFO;
		rename_req->StructureSize = cpu_to_le16(33);
		rename_req->InfoType = SMB2_O_INFO_FILE;
		rename_req->FileInfoClass = FILE_RENAME_INFORMATION;
		rename_req->BufferOffset = cpu_to_le16(offsetof(struct smb2_set_info_req, Buffer));
		rename_req->VolatileFileId = id;
		rename_req->PersistentFileId = pid;
		info = (void *)rename_req->Buffer;
		len = smbConvertToUTF16((__le16 *)info->FileName, param->rename_name,
					strlen(param->rename_name), ctx->conn.local_nls, 0);
		len *= sizeof(__le16);
		info->FileNameLength = cpu_to_le32(len);
		rename_req->BufferLength = cpu_to_le32(sizeof(*info) + len);
		inc_rfc1001_len(work->request_buf, offsetof(struct smb2_set_info_req, Buffer) +
				 sizeof(*info) + len);
		KUNIT_ASSERT_EQ(test, smb2_set_info(work), param->rename_error);
		if (!param->rename_error)
			name = param->rename_name;
	}
	if (param->retarget) {
		struct path path = { .mnt = ctx->share.vfs_path.mnt, .dentry = alias };
		struct file *filp = dentry_open(&path, O_PATH | O_NOFOLLOW, current_cred());

		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
		ret = ksmbd_vfs_unlink(filp);
		fput(filp);
		KUNIT_ASSERT_EQ(test, ret, 0);
		entry = reparse_test_host_create(test, share, "other", S_IFREG | 0600, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
		entry = reparse_test_host_create(test, share, "alias", S_IFLNK | 0777, "other");
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entry);
	}
	reparse_test_reset_request(ctx);
	ksmbd_close_session_fds(work);
	KUNIT_ASSERT_NULL(test, fp->conn);
	lc.version = param->dialect >= SMB30_PROT_ID ? 2 : 1;
	other_share.vfs_path = ctx->share.vfs_path;
	other_share.vfs_path.dentry = dir;
	ret = smb2_check_durable_oplock(&ctx->conn, &other_share, fp, &lc, &ctx->user, name);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	/* Reject a different name without consuming the retained durable open. */
	req = reparse_test_open_req(ctx, param->reject_name);
	req->DesiredAccess |= FILE_READ_DATA_LE;
	reparse_test_lease_req(ctx, req, 10, state);
	reparse_test_durable_context(ctx, req, true, id, pid);
	KUNIT_EXPECT_EQ(test, reparse_test_durable_open(ctx), -EINVAL);
	rsp = smb_get_msg(work->response_buf);
	KUNIT_EXPECT_EQ(test, rsp->hdr.Status, STATUS_INVALID_PARAMETER);

	reparse_test_reset_request(ctx);
	req = reparse_test_open_req(ctx, name);
	req->DesiredAccess |= FILE_READ_DATA_LE;
	reparse_test_lease_req(ctx, req, 10, state);
	reparse_test_durable_context(ctx, req, true, id, pid);
	KUNIT_ASSERT_EQ(test, reparse_test_durable_open(ctx), 0);
	rsp = smb_get_msg(work->response_buf);
	KUNIT_EXPECT_EQ(test, rsp->PersistentFileId, pid);
	reconnected = ksmbd_lookup_fd_slow(work, rsp->VolatileFileId, pid);
	KUNIT_ASSERT_NOT_NULL(test, reconnected);
	KUNIT_EXPECT_PTR_EQ(test, reconnected, fp);
	KUNIT_EXPECT_PTR_EQ(test, reconnected->filp->f_path.dentry, target);
	ksmbd_fd_put(work, reconnected);
}

struct reparse_shared_reconnect_case {
	const char *name;
	u16 dialect;
	bool alias;
	bool rename;
};

static const struct reparse_shared_reconnect_case reparse_shared_reconnect_cases[] = {
	{ "smb21-casefold", SMB21_PROT_ID },
	{ "smb311-casefold", SMB311_PROT_ID },
	{ "smb21-alias", SMB21_PROT_ID, .alias = true },
	{ "smb311-alias", SMB311_PROT_ID, .alias = true },
	{ "smb21-rename", SMB21_PROT_ID, .alias = true, .rename = true },
	{ "smb311-rename", SMB311_PROT_ID, .alias = true, .rename = true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_shared_reconnect, reparse_shared_reconnect_cases, name);

static void reparse_shared_lease_reconnect(struct kunit *test)
{
	const struct reparse_shared_reconnect_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp[2], *reconnected;
	struct oplock_info *opinfo[2];
	struct dentry *file;
	const char *names[2];
	__le32 state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	u64 ids[2], pids[2];
	int i, retry, ret;

	names[0] = param->alias ? "alias" : "FILE";
	names[1] = "file";
	file = reparse_test_create(test, ctx->share.vfs_path.dentry,
				   "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	if (param->alias) {
		struct dentry *alias = reparse_test_create(test, ctx->share.vfs_path.dentry,
							 "alias", S_IFLNK | 0777, "file");

		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, alias);
	}
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	ctx->values = *ctx->conn.vals;
	ctx->values.req_capabilities |= SMB2_GLOBAL_CAP_LEASING;
	ctx->conn.vals = &ctx->values;
	ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS | KSMBD_SHARE_FLAG_OPLOCKS;
	for (i = 0; i < ARRAY_SIZE(fp); i++) {
		reparse_test_reset_request(ctx);
		req = reparse_test_open_req(ctx, names[i]);
		req->DesiredAccess |= FILE_READ_DATA_LE;
		if (param->rename && !i)
			req->DesiredAccess |= FILE_DELETE_LE;
		reparse_test_lease_req(ctx, req, 10, state);
		reparse_test_durable_context(ctx, req, false, 0, 0);
		if (param->dialect >= SMB30_PROT_ID) {
			struct create_durable_req_v2 *dh = (void *)smb2_find_context_vals(req,
				SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2, 4);

			KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dh);
			dh->dcontext.CreateGuid[0] = i + 1;
		}
		KUNIT_ASSERT_EQ(test, reparse_test_durable_open(ctx), 0);
		rsp = smb_get_msg(work->response_buf);
		ids[i] = rsp->VolatileFileId;
		pids[i] = rsp->PersistentFileId;
		fp[i] = ksmbd_lookup_fd_slow(work, ids[i], pids[i]);
		KUNIT_ASSERT_NOT_NULL(test, fp[i]);
		ret = kunit_add_action_or_reset(test, reparse_test_put_durable, fp[i]);
		KUNIT_ASSERT_EQ(test, ret, 0);
		KUNIT_ASSERT_TRUE(test, fp[i]->is_durable);
	}
	opinfo[0] = opinfo_get(fp[0]);
	opinfo[1] = opinfo_get(fp[1]);
	KUNIT_ASSERT_NOT_NULL(test, opinfo[0]);
	KUNIT_ASSERT_NOT_NULL(test, opinfo[1]);
	KUNIT_EXPECT_PTR_EQ(test, opinfo[0]->o_lease, opinfo[1]->o_lease);
	opinfo_put(opinfo[0]);
	opinfo_put(opinfo[1]);

	if (param->rename) {
		struct smb2_set_info_req *rename_req;
		struct smb2_file_rename_info *info;
		int len;

		reparse_test_reset_request(ctx);
		rename_req = smb_get_msg(work->request_buf);
		rename_req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
		rename_req->hdr.Command = SMB2_SET_INFO;
		rename_req->StructureSize = cpu_to_le16(33);
		rename_req->InfoType = SMB2_O_INFO_FILE;
		rename_req->FileInfoClass = FILE_RENAME_INFORMATION;
		rename_req->BufferOffset = cpu_to_le16(offsetof(struct smb2_set_info_req, Buffer));
		rename_req->VolatileFileId = ids[0];
		rename_req->PersistentFileId = pids[0];
		info = (void *)rename_req->Buffer;
		len = smbConvertToUTF16((__le16 *)info->FileName, "renamed", 7,
					ctx->conn.local_nls, 0) * sizeof(__le16);
		info->FileNameLength = cpu_to_le32(len);
		rename_req->BufferLength = cpu_to_le32(sizeof(*info) + len);
		inc_rfc1001_len(work->request_buf, offsetof(struct smb2_set_info_req, Buffer) +
				 sizeof(*info) + len);
		KUNIT_ASSERT_EQ(test, smb2_set_info(work), 0);
		names[0] = "renamed";
	}
	reparse_test_reset_request(ctx);
	ksmbd_close_session_fds(work);
	KUNIT_ASSERT_NULL(test, fp[0]->conn);
	KUNIT_ASSERT_NULL(test, fp[1]->conn);

	for (i = 0; i < ARRAY_SIZE(fp); i++) {
		/* Each open must reject its peer's name and accept its own name. */
		for (retry = 0; retry < 2; retry++) {
			reparse_test_reset_request(ctx);
			req = reparse_test_open_req(ctx, names[retry ? i : 1 - i]);
			req->DesiredAccess |= FILE_READ_DATA_LE;
			reparse_test_lease_req(ctx, req, 10, state);
			reparse_test_durable_context(ctx, req, true, ids[i], pids[i]);
			if (param->dialect >= SMB30_PROT_ID) {
				struct create_durable_handle_reconnect_v2 *dh =
					(void *)smb2_find_context_vals(req,
						SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2, 4);

				KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dh);
				dh->dcontext.CreateGuid[0] = i + 1;
			}
			if (!retry) {
				KUNIT_EXPECT_EQ(test, reparse_test_durable_open(ctx), -EINVAL);
				rsp = smb_get_msg(work->response_buf);
				KUNIT_EXPECT_EQ(test, rsp->hdr.Status, STATUS_INVALID_PARAMETER);
			} else {
				KUNIT_ASSERT_EQ(test, reparse_test_durable_open(ctx), 0);
			}
		}
		rsp = smb_get_msg(work->response_buf);
		KUNIT_EXPECT_EQ(test, rsp->PersistentFileId, pids[i]);
		ids[i] = rsp->VolatileFileId;
		reconnected = ksmbd_lookup_fd_slow(work, ids[i], pids[i]);
		KUNIT_ASSERT_NOT_NULL(test, reconnected);
		KUNIT_EXPECT_PTR_EQ(test, reconnected, fp[i]);
		KUNIT_EXPECT_PTR_EQ(test, reconnected->filp->f_path.dentry, file);
		ksmbd_fd_put(work, reconnected);
		reparse_test_reset_request(ctx);
		KUNIT_ASSERT_EQ(test, ksmbd_close_fd(work, ids[i]), 0);
	}
}

struct reparse_absolute_response_case {
	const char *name;
	const char *path;
	const char *target;
	const char *child;
	u16 dialect;
	bool nested;
	bool metadata;
	bool stream;
};

static const struct reparse_absolute_response_case reparse_absolute_response_cases[] = {
	{ "directory-smb21", "alias\\stub", "share/dir", NULL, SMB21_PROT_ID },
	{ "directory-smb311", "alias\\stub", "share/dir", NULL, SMB311_PROT_ID },
	{ "file", "alias", "share/dir/stub", NULL, SMB21_PROT_ID },
	{ "nested", "prefix\\alias\\stub", "share/dir", NULL, SMB311_PROT_ID, true },
	{ "body-child", "alias", "share/dir/stub/child", "child", SMB21_PROT_ID },
	{ "parent", "alias\\child", "share/dir/stub", "child", SMB311_PROT_ID },
	{ "unicode", "alias\\\xf0\x9f\x99\x82", "share/dir/stub",
	  "\xf0\x9f\x99\x82", SMB311_PROT_ID },
	{ "stream", "alias\\stub:stream:$DATA", "share/dir", NULL,
	  SMB311_PROT_ID, false, false, true },
	{ "dot-prefix", "alias\\stub", "./share/dir", NULL, SMB21_PROT_ID },
	{ "metadata", "alias", "share/dir/target", NULL, SMB21_PROT_ID, false, true },
	{ "metadata-nested", "prefix\\alias", "share/dir/target", NULL,
	  SMB311_PROT_ID, true, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_absolute_response, reparse_absolute_response_cases, name);

static void reparse_absolute_symlink_response(struct kunit *test)
{
	const struct reparse_absolute_response_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct dentry *root, *share, *dir, *stub, *target, *parent;
	struct reparse_symlink_data_buffer *rp;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct ksmbd_file *fp;
	char native[160], name[256];
	umode_t mode = param->child ? S_IFDIR | 0700 : S_IFREG | 0600;
	int i, ret = -ELOOP;

	root = reparse_test_host_root(test);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, root);
	share = reparse_test_host_create(test, root, "share", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, share);
	ctx->share.vfs_path.dentry = share;
	dir = reparse_test_host_create(test, share, "dir", S_IFDIR | 0700, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dir);
	stub = reparse_test_host_create(test, dir, "stub", mode, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, stub);
	target = reparse_test_host_create(test, dir, "target", mode, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);
	if (param->child) {
		target = reparse_test_host_create(test, target, param->child, S_IFREG | 0600, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);
	}
	parent = share;
	if (param->nested) {
		parent = reparse_test_host_create(test, share, "prefix", S_IFDIR | 0700, NULL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, parent);
	}
	snprintf(native, sizeof(native), "/%s/%s", root->d_name.name, param->target);
	parent = reparse_test_host_create(test, parent, "alias", S_IFLNK | 0777, native);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, parent);
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	ctx->share.flags |= KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS | KSMBD_SHARE_FLAG_STREAMS;
	rp = kunit_kzalloc(test, sizeof(*rp) + 14, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, rp);
	rp->SubstituteNameLength = cpu_to_le16(12);
	rp->PrintNameLength = cpu_to_le16(12);
	rp->Flags = cpu_to_le32(SYMLINK_FLAG_RELATIVE);
	smbConvertToUTF16((__le16 *)rp->PathBuffer, "target", 6, ctx->conn.local_nls, 0);
	KUNIT_ASSERT_EQ(test, reparse_test_set(ctx, stub, IO_REPARSE_TAG_SYMLINK,
					       &rp->SubstituteNameOffset, 24), 0);
	if (param->stream) {
		struct path path = ctx->share.vfs_path;
		char *stream_name;
		size_t stream_size;

		path.dentry = target;
		KUNIT_ASSERT_EQ(test, ksmbd_vfs_xattr_stream_name("stream", &stream_name,
								  &stream_size, DATA_STREAM), 0);
		ret = ksmbd_vfs_setxattr(mnt_idmap(path.mnt), &path,
					 stream_name, NULL, 0, 0, true);
		kfree(stream_name);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}
	strscpy(name, param->path, sizeof(name));
	for (i = 0; i < 3; i++) {
		reparse_test_reset_request(ctx);
		req = reparse_test_open_req(ctx, name);
		if (!param->metadata)
			req->DesiredAccess |= FILE_READ_DATA_LE;
		ret = smb2_open(&ctx->work);
		if (!ret)
			break;
		KUNIT_ASSERT_EQ(test, ret, -ELOOP);
		reparse_test_follow_link(test, name, sizeof(name));
	}
	KUNIT_ASSERT_EQ(test, ret, 0);
	rsp = smb_get_msg(ctx->work.response_buf);
	fp = ksmbd_lookup_fd_slow(&ctx->work, rsp->VolatileFileId, rsp->PersistentFileId);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_PTR_EQ(test, fp->filp->f_path.dentry, target);
	ksmbd_fd_put(&ctx->work, fp);
}

struct reparse_busy_case {
	const char *name;
	u8 level;
	__le32 lease_state;
	bool alias;
	bool self;
	bool in_flight;
};

static const struct reparse_busy_case reparse_busy_cases[] = {
	{ "uncached", SMB2_OPLOCK_LEVEL_NONE },
	{ "exclusive", SMB2_OPLOCK_LEVEL_EXCLUSIVE },
	{ "batch", SMB2_OPLOCK_LEVEL_BATCH },
	{ "level-ii", SMB2_OPLOCK_LEVEL_II },
	{ "lease-read", SMB2_OPLOCK_LEVEL_LEASE, SMB2_LEASE_READ_CACHING_LE },
	{ "lease-write", SMB2_OPLOCK_LEVEL_LEASE,
		SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE |
		SMB2_LEASE_HANDLE_CACHING_LE },
	{ "alias-uncached", SMB2_OPLOCK_LEVEL_NONE, 0, true },
	{ "alias-exclusive", SMB2_OPLOCK_LEVEL_EXCLUSIVE, 0, true },
	{ "self-exclusive", SMB2_OPLOCK_LEVEL_EXCLUSIVE, 0, false, true },
	{ "self-lease", SMB2_OPLOCK_LEVEL_LEASE,
		SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE, false, true },
	{ "in-flight", SMB2_OPLOCK_LEVEL_NONE, 0, false, false, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_busy, reparse_busy_cases, name);

static void reparse_set_busy_inode(struct kunit *test)
{
	const struct reparse_busy_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = &ctx->work;
	struct smb2_create_req *req;
	struct smb2_create_rsp *opened;
	struct smb2_ioctl_rsp *rsp;
	struct ksmbd_file *fp;
	struct ksmbd_file *in_flight = NULL;
	struct oplock_info *opinfo;
	struct dentry *file;
	void *data;
	u32 tag, len;
	u64 data_id, data_pid, meta_id, meta_pid;
	u8 expected_level = param->lease_state ? smb2_map_lease_to_oplock(param->lease_state) :
		param->level;
	int ret;

	file = reparse_test_create(test, ctx->share.vfs_path.dentry,
				   "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	reparse_test_init_open(test);
	ctx->share.flags |= KSMBD_SHARE_FLAG_OPLOCKS;
	if (param->lease_state) {
		ctx->values = *ctx->conn.vals;
		ctx->values.req_capabilities |= SMB2_GLOBAL_CAP_LEASING;
		ctx->conn.vals = &ctx->values;
	}
	req = reparse_test_open_req(ctx, "file");
	req->DesiredAccess |= FILE_READ_DATA_LE | FILE_WRITE_DATA_LE;
	req->RequestedOplockLevel = param->level;
	if (param->lease_state) {
		unsigned int off = ALIGN(le16_to_cpu(req->NameOffset) +
					 le16_to_cpu(req->NameLength), 8);
		struct create_lease *lease = (void *)req + off;

		lease->ccontext.NameOffset = cpu_to_le16(offsetof(struct create_lease, Name));
		lease->ccontext.NameLength = cpu_to_le16(4);
		lease->ccontext.DataOffset = cpu_to_le16(offsetof(struct create_lease, lcontext));
		lease->ccontext.DataLength = cpu_to_le32(sizeof(lease->lcontext));
		memcpy(lease->Name, SMB2_CREATE_REQUEST_LEASE, 4);
		lease->lcontext.LeaseKey[0] = 1;
		lease->lcontext.LeaseState = param->lease_state;
		req->CreateContextsOffset = cpu_to_le32(off);
		req->CreateContextsLength = cpu_to_le32(sizeof(*lease));
		*(__be32 *)work->request_buf = 0;
		inc_rfc1001_len(work->request_buf, off + sizeof(*lease));
	}
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	KUNIT_ASSERT_EQ(test, opened->OplockLevel, param->level);
	data_id = opened->VolatileFileId;
	data_pid = opened->PersistentFileId;
	fp = ksmbd_lookup_fd_slow(work, data_id, data_pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	if (param->alias) {
		scoped_guard(rwsem_read, &ksmbd_reparse_sem)
			ret = ksmbd_vfs_link(work, fp, "alias");
		KUNIT_EXPECT_EQ(test, ret, 0);
	}
	ksmbd_fd_put(work, fp);
	reparse_test_reset_request(ctx);
	req = reparse_test_open_req(ctx, param->alias ? "alias" : "file");
	req->DesiredAccess |= FILE_WRITE_ATTRIBUTES_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(work), 0);
	opened = smb_get_msg(work->response_buf);
	meta_id = opened->VolatileFileId;
	meta_pid = opened->PersistentFileId;
	if (param->in_flight) {
		in_flight = ksmbd_lookup_fd_slow(work, data_id, data_pid);
		KUNIT_ASSERT_NOT_NULL(test, in_flight);
		ret = ksmbd_update_fstate(&ctx->sess.file_table, in_flight, FP_NEW);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}
	ret = reparse_test_set_ioctl(ctx, param->self ? data_id : meta_id,
				     param->self ? data_pid : meta_pid);
	KUNIT_EXPECT_EQ(test, ret, -ESHARE);
	rsp = smb_get_msg(work->response_buf);
	KUNIT_EXPECT_EQ(test, rsp->hdr.Status, STATUS_SHARING_VIOLATION);
	ret = ksmbd_vfs_get_rp_xattr(mnt_idmap(ctx->share.vfs_path.mnt), file,
				     &tag, &data, &len);
	KUNIT_EXPECT_EQ(test, ret, -ENODATA);
	if (!ret)
		kfree(data);
	if (param->in_flight) {
		ret = ksmbd_update_fstate(&ctx->sess.file_table, in_flight, FP_INITED);
		KUNIT_EXPECT_EQ(test, ret, 0);
		ksmbd_fd_put(work, in_flight);
	} else {
		fp = ksmbd_lookup_fd_slow(work, data_id, data_pid);
		KUNIT_ASSERT_NOT_NULL(test, fp);
		opinfo = opinfo_get(fp);
		KUNIT_ASSERT_NOT_NULL(test, opinfo);
		KUNIT_EXPECT_EQ(test, opinfo->level, expected_level);
		opinfo_put(opinfo);
		ksmbd_fd_put(work, fp);
		if (param->level == SMB2_OPLOCK_LEVEL_NONE ||
		    param->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE || param->lease_state)
			KUNIT_EXPECT_EQ(test, reparse_test_write(ctx, data_id, data_pid), 0);
	}
	reparse_test_reset_request(ctx);
	KUNIT_ASSERT_EQ(test, ksmbd_close_fd(work, data_id), 0);
	KUNIT_EXPECT_EQ(test, reparse_test_set_ioctl(ctx, meta_id, meta_pid), 0);
}

struct reparse_overwrite_case {
	const char *name;
	__le32 disposition;
	bool native;
	bool read_only;
};

static const struct reparse_overwrite_case reparse_overwrite_cases[] = {
	{ "overwrite", FILE_OVERWRITE_LE },
	{ "overwrite-if", FILE_OVERWRITE_IF_LE },
	{ "supersede", FILE_SUPERSEDE_LE },
	{ "native-overwrite", FILE_OVERWRITE_LE, true },
	{ "native-overwrite-if", FILE_OVERWRITE_IF_LE, true },
	{ "native-supersede", FILE_SUPERSEDE_LE, true },
	{ "read-only", FILE_OVERWRITE_LE, false, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_overwrite, reparse_overwrite_cases, name);

static void reparse_overwrite_denied(struct kunit *test)
{
	const struct reparse_overwrite_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct smb2_create_req *req;
	struct smb2_err_rsp *rsp;
	struct dentry *file;

	file = reparse_test_create(test, ctx->share.vfs_path.dentry,
				   "file", param->native ? S_IFLNK | 0777 : S_IFREG | 0600,
				   param->native ? "target" : NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	if (!param->native) {
		struct path path = ctx->share.vfs_path;
		struct file *filp;
		loff_t pos = 0;
		int ret;

		path.dentry = file;
		filp = dentry_open(&path, O_RDWR, current_cred());
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
		ret = kernel_write(filp, "data", 4, &pos);
		fput(filp);
		KUNIT_ASSERT_EQ(test, ret, 4);
		ret = reparse_test_set(ctx, file, IO_REPARSE_TAG_LX_FIFO, NULL, 0);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}
	reparse_test_init_open(test);
	if (param->read_only)
		ctx->tcon.flags &= ~KSMBD_TREE_CONN_FLAG_WRITABLE;
	req = reparse_test_open_req(ctx, "file");
	req->DesiredAccess |= FILE_WRITE_DATA_LE | FILE_DELETE_LE;
	req->CreateOptions = FILE_OPEN_REPARSE_POINT_LE;
	req->CreateDisposition = param->disposition;
	KUNIT_EXPECT_EQ(test, smb2_open(&ctx->work), -EACCES);
	rsp = smb_get_msg(ctx->work.response_buf);
	KUNIT_EXPECT_EQ(test, rsp->hdr.Status, STATUS_ACCESS_DENIED);
	if (!param->native)
		KUNIT_EXPECT_EQ(test, i_size_read(d_inode(file)), 4);
}

struct reparse_test_transport {
	struct ksmbd_transport base;
	struct completion break_sent;
};

static int reparse_test_transport_write(struct ksmbd_transport *t,
					const struct ksmbd_transport_write *tx)
{
	struct reparse_test_transport *transport =
		container_of(t, struct reparse_test_transport, base);
	int i;

	for (i = 0; i < tx->iov_cnt; i++) {
		struct smb2_hdr *hdr = tx->iov[i].iov_base;

		if (tx->iov[i].iov_len >= sizeof(*hdr) &&
		    hdr->ProtocolId == SMB2_PROTO_NUMBER && hdr->Command == SMB2_OPLOCK_BREAK)
			complete(&transport->break_sent);
	}
	return tx->size;
}

static const struct ksmbd_transport_ops reparse_test_transport_ops = {
	.writev = reparse_test_transport_write,
};

struct reparse_test_thread {
	struct ksmbd_work *work;
	struct reparse_test_ctx *ctx;
	struct completion done;
	u64 id, pid;
	int ret;
};

static struct task_struct *reparse_test_start_thread(int (*fn)(void *), void *data,
						     const char *name)
{
	struct task_struct *task = kthread_create(fn, data, "%s", name);

	if (IS_ERR(task))
		return task;
	/* A handler can finish before the test reaches kthread_stop_put(). */
	get_task_struct(task);
	wake_up_process(task);
	return task;
}

static int reparse_test_rename_thread(void *data)
{
	struct reparse_test_thread *thread = data;

	thread->ret = smb2_set_info(thread->work);
	complete(&thread->done);
	return 0;
}

static int reparse_test_set_thread(void *data)
{
	struct reparse_test_thread *thread = data;

	thread->ret = reparse_test_set_ioctl(thread->ctx, thread->id, thread->pid);
	complete(&thread->done);
	return 0;
}

static int reparse_test_close_thread(void *data)
{
	struct reparse_test_thread *thread = data;

	thread->ret = smb2_close(thread->work);
	complete(&thread->done);
	return 0;
}

static void reparse_test_free_work(void *data)
{
	struct ksmbd_work *work = data;

	smb2_complete_request_open(work);
	ksmbd_free_work_struct(work);
}

static struct ksmbd_work *reparse_test_alloc_work(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	struct ksmbd_work *work = ksmbd_alloc_work_struct();
	int ret;

	if (!work)
		return NULL;
	work->conn = &ctx->conn;
	work->tcon = &ctx->tcon;
	work->sess = &ctx->sess;
	work->request_buf = kvzalloc(4096, GFP_KERNEL);
	work->response_buf = kvzalloc(SZ_64K, GFP_KERNEL);
	work->response_sz = SZ_64K;
	if (!work->request_buf || !work->response_buf) {
		reparse_test_free_work(work);
		return NULL;
	}
	ret = kunit_add_action_or_reset(test, reparse_test_free_work, work);
	return ret ? NULL : work;
}

static void reparse_test_destroy_ida(void *data)
{
	ida_destroy(data);
}

static void reparse_lease_break_close(struct kunit *test)
{
	struct reparse_test_ctx *ctx = test->priv;
	const struct reparse_dialect_case *param = test->param_value;
	struct reparse_test_transport *transport;
	struct reparse_test_thread rename = {}, writer = {}, close = {};
	struct ksmbd_work *ack_work;
	struct smb2_create_req *create;
	struct smb2_create_rsp *opened;
	struct smb2_set_info_req *rename_req;
	struct smb2_file_rename_info *info;
	struct smb2_close_req *close_req;
	struct smb2_lease_ack *ack;
	struct ksmbd_file *lease_fp;
	struct oplock_info *op;
	struct dentry *file;
	struct task_struct *rename_task = NULL, *writer_task = NULL, *close_task = NULL;
	u64 lease_id, lease_pid, rename_id, rename_pid, set_id, set_pid;
	unsigned int off;
	unsigned long waited;
	int name_len;

	transport = kunit_kzalloc(test, sizeof(*transport), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, transport);
	file = reparse_test_create(test, ctx->share.vfs_path.dentry, "file", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	file = reparse_test_create(test, ctx->share.vfs_path.dentry, "other", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	reparse_test_init_open(test);
	ctx->conn.dialect = param->dialect;
	mutex_init(&ctx->conn.srv_mutex);
	spin_lock_init(&ctx->conn.request_lock);
	spin_lock_init(&ctx->conn.credits_lock);
	INIT_LIST_HEAD(&ctx->conn.requests);
	INIT_LIST_HEAD(&ctx->conn.async_requests);
	init_waitqueue_head(&ctx->conn.r_count_q);
	ida_init(&ctx->conn.async_ida);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, reparse_test_destroy_ida,
							&ctx->conn.async_ida), 0);
	ksmbd_conn_set_good(&ctx->conn);
	init_completion(&transport->break_sent);
	transport->base.ops = &reparse_test_transport_ops;
	transport->base.conn = &ctx->conn;
	ctx->conn.transport = &transport->base;
	ctx->values = *ctx->conn.vals;
	ctx->values.req_capabilities |= SMB2_GLOBAL_CAP_LEASING;
	ctx->conn.vals = &ctx->values;
	ctx->share.flags |= KSMBD_SHARE_FLAG_OPLOCKS;
	create = reparse_test_open_req(ctx, "file");
	create->DesiredAccess |= FILE_READ_DATA_LE;
	create->RequestedOplockLevel = SMB2_OPLOCK_LEVEL_LEASE;
	off = ALIGN(le16_to_cpu(create->NameOffset) + le16_to_cpu(create->NameLength), 8);
	{
		struct create_lease *lease = (void *)create + off;

		lease->ccontext.NameOffset = cpu_to_le16(offsetof(struct create_lease, Name));
		lease->ccontext.NameLength = cpu_to_le16(4);
		lease->ccontext.DataOffset = cpu_to_le16(offsetof(struct create_lease, lcontext));
		lease->ccontext.DataLength = cpu_to_le32(sizeof(lease->lcontext));
		memcpy(lease->Name, SMB2_CREATE_REQUEST_LEASE, 4);
		lease->lcontext.LeaseKey[0] = 1;
		lease->lcontext.LeaseState = SMB2_LEASE_READ_CACHING_LE |
			SMB2_LEASE_HANDLE_CACHING_LE;
		create->CreateContextsOffset = cpu_to_le32(off);
		create->CreateContextsLength = cpu_to_le32(sizeof(*lease));
		*(__be32 *)ctx->work.request_buf = 0;
		inc_rfc1001_len(ctx->work.request_buf, off + sizeof(*lease));
	}
	KUNIT_ASSERT_EQ(test, smb2_open(&ctx->work), 0);
	opened = smb_get_msg(ctx->work.response_buf);
	lease_id = opened->VolatileFileId;
	lease_pid = opened->PersistentFileId;
	lease_fp = ksmbd_lookup_fd_slow(&ctx->work, lease_id, lease_pid);
	KUNIT_ASSERT_NOT_NULL(test, lease_fp);
	op = opinfo_get(lease_fp);
	KUNIT_ASSERT_NOT_NULL(test, op);
	KUNIT_ASSERT_EQ(test, op->o_lease->state,
			SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE);
	opinfo_put(op);
	ksmbd_fd_put(&ctx->work, lease_fp);

	reparse_test_reset_request(ctx);
	create = reparse_test_open_req(ctx, "file");
	create->DesiredAccess |= FILE_DELETE_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(&ctx->work), 0);
	opened = smb_get_msg(ctx->work.response_buf);
	rename_id = opened->VolatileFileId;
	rename_pid = opened->PersistentFileId;
	reparse_test_reset_request(ctx);
	create = reparse_test_open_req(ctx, "other");
	create->DesiredAccess |= FILE_WRITE_ATTRIBUTES_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(&ctx->work), 0);
	opened = smb_get_msg(ctx->work.response_buf);
	set_id = opened->VolatileFileId;
	set_pid = opened->PersistentFileId;
	reparse_test_reset_request(ctx);

	rename.work = reparse_test_alloc_work(test);
	close.work = reparse_test_alloc_work(test);
	ack_work = reparse_test_alloc_work(test);
	KUNIT_ASSERT_NOT_NULL(test, rename.work);
	KUNIT_ASSERT_NOT_NULL(test, close.work);
	KUNIT_ASSERT_NOT_NULL(test, ack_work);
	init_completion(&rename.done);
	init_completion(&writer.done);
	init_completion(&close.done);
	writer.ctx = ctx;
	writer.id = set_id;
	writer.pid = set_pid;
	rename_req = smb_get_msg(rename.work->request_buf);
	rename_req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	rename_req->hdr.Command = SMB2_SET_INFO;
	rename_req->StructureSize = cpu_to_le16(33);
	rename_req->InfoType = SMB2_O_INFO_FILE;
	rename_req->FileInfoClass = FILE_RENAME_INFORMATION;
	rename_req->BufferOffset = cpu_to_le16(offsetof(struct smb2_set_info_req, Buffer));
	rename_req->VolatileFileId = rename_id;
	rename_req->PersistentFileId = rename_pid;
	info = (void *)rename_req->Buffer;
	name_len = smbConvertToUTF16((__le16 *)info->FileName, "renamed", 7,
				     ctx->conn.local_nls, 0) * sizeof(__le16);
	info->FileNameLength = cpu_to_le32(name_len);
	rename_req->BufferLength = cpu_to_le32(sizeof(*info) + name_len);
	inc_rfc1001_len(rename.work->request_buf, offsetof(struct smb2_set_info_req, Buffer) +
			 sizeof(*info) + name_len);
	close_req = smb_get_msg(close.work->request_buf);
	close_req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	close_req->hdr.Command = SMB2_CLOSE;
	close_req->StructureSize = cpu_to_le16(24);
	close_req->Flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
	close_req->VolatileFileId = lease_id;
	close_req->PersistentFileId = lease_pid;
	inc_rfc1001_len(close.work->request_buf, sizeof(*close_req));
	ack = smb_get_msg(ack_work->request_buf);
	ack->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	ack->hdr.Command = SMB2_OPLOCK_BREAK;
	ack->StructureSize = cpu_to_le16(36);
	ack->LeaseKey[0] = 1;
	ack->LeaseState = SMB2_LEASE_READ_CACHING_LE;
	inc_rfc1001_len(ack_work->request_buf, sizeof(*ack));

	rename_task = reparse_test_start_thread(reparse_test_rename_thread, &rename,
						"reparse-rename");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, rename_task);
	waited = wait_for_completion_timeout(&transport->break_sent, msecs_to_jiffies(2000));
	KUNIT_EXPECT_NE_MSG(test, waited, 0, "rename should request an RH lease break");
	if (!waited)
		goto out;
	KUNIT_EXPECT_FALSE(test, completion_done(&rename.done));

	writer_task = reparse_test_start_thread(reparse_test_set_thread, &writer,
						"reparse-set");
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, writer_task);
	if (IS_ERR_OR_NULL(writer_task))
		goto out;
	waited = wait_for_completion_timeout(&writer.done, msecs_to_jiffies(1000));
	KUNIT_EXPECT_NE_MSG(test, waited, 0, "SET on another inode must not wait for a lease ACK");

	close_task = reparse_test_start_thread(reparse_test_close_thread, &close,
					       "reparse-close");
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, close_task);
	if (IS_ERR_OR_NULL(close_task))
		goto out;
	waited = wait_for_completion_timeout(&close.done, msecs_to_jiffies(1000));
	KUNIT_EXPECT_NE_MSG(test, waited, 0, "CLOSE with attributes must complete before the ACK");
	waited = wait_for_completion_timeout(&rename.done, msecs_to_jiffies(1000));
	KUNIT_EXPECT_NE_MSG(test, waited, 0, "CLOSE must implicitly acknowledge the lease break");
out:
	/* Recover a failed test without leaving requests blocked until the timeout. */
	if (!completion_done(&rename.done))
		smb2_oplock_break(ack_work);
	if (!IS_ERR_OR_NULL(close_task))
		kthread_stop_put(close_task);
	if (!IS_ERR_OR_NULL(writer_task))
		kthread_stop_put(writer_task);
	kthread_stop_put(rename_task);
	KUNIT_EXPECT_EQ(test, rename.ret, 0);
	KUNIT_EXPECT_EQ(test, writer.ret, 0);
	KUNIT_EXPECT_EQ(test, close.ret, 0);
}

struct reparse_clone_case {
	const char *name;
	bool clone;
	bool fail;
};

static const struct reparse_clone_case reparse_clone_cases[] = {
	{ "clone", true },
	{ "copy" },
	{ "copy-error", false, true },
};

KUNIT_ARRAY_PARAM_DESC(reparse_clone, reparse_clone_cases, name);

struct reparse_clone_test {
	struct ksmbd_transport transport;
	struct ksmbd_work *work, *ack_work;
	struct file_operations ops;
	struct file *in, *out;
	const struct file_operations *in_ops, *out_ops;
	u64 source_id;
	unsigned int breaks;
	int close_ret, ack_ret;
	bool reparse_held;
	bool fail;
};

static void reparse_test_restore_clone_files(void *data)
{
	struct reparse_clone_test *clone = data;

	if (clone->in) {
		clone->in->f_op = clone->in_ops;
		fput(clone->in);
	}
	if (clone->out) {
		clone->out->f_op = clone->out_ops;
		fput(clone->out);
	}
}

static void reparse_test_clone_close_source(struct reparse_clone_test *clone)
{
	/* Model SMB2 CLOSE after the source lookup, before its final put. */
	clone->close_ret = ksmbd_close_fd(clone->work, clone->source_id);
	clone->in->f_op = clone->in_ops;
	clone->out->f_op = clone->out_ops;
}

static loff_t reparse_test_clone_range(struct file *in, loff_t src,
				       struct file *out, loff_t dst,
				       loff_t len, unsigned int flags)
{
	struct reparse_clone_test *clone = container_of(in->f_op, struct reparse_clone_test, ops);

	reparse_test_clone_close_source(clone);
	return len;
}

static ssize_t reparse_test_copy_range(struct file *in, loff_t src,
				       struct file *out, loff_t dst,
				       size_t len, unsigned int flags)
{
	struct reparse_clone_test *clone = container_of(in->f_op, struct reparse_clone_test, ops);

	reparse_test_clone_close_source(clone);
	if (clone->fail)
		return -EIO;
	return len;
}

static int reparse_test_clone_ack(struct ksmbd_transport *t,
				  const struct ksmbd_transport_write *tx)
{
	struct reparse_clone_test *clone = container_of(t, struct reparse_clone_test, transport);
	int i;

	for (i = 0; i < tx->iov_cnt; i++) {
		struct smb2_hdr *hdr = tx->iov[i].iov_base;

		if (tx->iov[i].iov_len < sizeof(*hdr) ||
		    hdr->ProtocolId != SMB2_PROTO_NUMBER || hdr->Command != SMB2_OPLOCK_BREAK)
			continue;
		clone->breaks++;
		clone->reparse_held |= rwsem_is_locked(&ksmbd_reparse_sem);
		clone->ack_ret = smb2_oplock_break(clone->ack_work);
	}
	return tx->size;
}

static const struct ksmbd_transport_ops reparse_test_clone_transport_ops = {
	.writev = reparse_test_clone_ack,
};

static void reparse_clone_source_close(struct kunit *test)
{
	const struct reparse_clone_case *param = test->param_value;
	struct reparse_test_ctx *ctx = test->priv;
	struct reparse_clone_test *clone;
	struct smb2_create_req *create;
	struct smb2_create_rsp *opened;
	struct smb2_ioctl_req *req;
	struct duplicate_extents_to_file *dup;
	struct smb2_lease_ack *ack;
	struct ksmbd_file *fp;
	struct dentry *file;
	u64 source_id, source_pid, target_id, target_pid;
	int ret;

	clone = kunit_kzalloc(test, sizeof(*clone), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, clone);
	file = reparse_test_create(test, ctx->share.vfs_path.dentry,
				   "source", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	file = reparse_test_create(test, ctx->share.vfs_path.dentry,
				   "target", S_IFREG | 0600, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	reparse_test_init_open(test);
	ctx->conn.dialect = SMB311_PROT_ID;
	ctx->values = *ctx->conn.vals;
	ctx->values.req_capabilities |= SMB2_GLOBAL_CAP_LEASING;
	ctx->conn.vals = &ctx->values;
	ctx->share.flags |= KSMBD_SHARE_FLAG_OPLOCKS;
	mutex_init(&ctx->conn.srv_mutex);
	spin_lock_init(&ctx->conn.request_lock);
	spin_lock_init(&ctx->conn.credits_lock);
	INIT_LIST_HEAD(&ctx->conn.requests);
	INIT_LIST_HEAD(&ctx->conn.async_requests);
	init_waitqueue_head(&ctx->conn.r_count_q);
	ida_init(&ctx->conn.async_ida);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, reparse_test_destroy_ida,
							&ctx->conn.async_ida), 0);
	ksmbd_conn_set_good(&ctx->conn);
	clone->transport.ops = &reparse_test_clone_transport_ops;
	clone->transport.conn = &ctx->conn;
	ctx->conn.transport = &clone->transport;
	clone->work = &ctx->work;
	clone->fail = param->fail;
	clone->close_ret = -EINPROGRESS;
	clone->ack_ret = -EINPROGRESS;
	clone->ack_work = reparse_test_alloc_work(test);
	KUNIT_ASSERT_NOT_NULL(test, clone->ack_work);
	ack = smb_get_msg(clone->ack_work->request_buf);
	ack->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	ack->hdr.Command = SMB2_OPLOCK_BREAK;
	ack->StructureSize = cpu_to_le16(36);
	ack->LeaseKey[0] = 11;
	ack->LeaseState = SMB2_LEASE_NONE_LE;
	inc_rfc1001_len(clone->ack_work->request_buf, sizeof(*ack));

	create = reparse_test_open_req(ctx, "source");
	create->DesiredAccess |= FILE_READ_DATA_LE | FILE_WRITE_DATA_LE;
	reparse_test_lease_req(ctx, create, 12, SMB2_LEASE_READ_CACHING_LE |
		SMB2_LEASE_WRITE_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE);
	KUNIT_ASSERT_EQ(test, smb2_open(&ctx->work), 0);
	opened = smb_get_msg(ctx->work.response_buf);
	source_id = opened->VolatileFileId;
	source_pid = opened->PersistentFileId;
	KUNIT_ASSERT_EQ(test, reparse_test_write(ctx, source_id, source_pid), 0);
	reparse_test_reset_request(ctx);
	create = reparse_test_open_req(ctx, "target");
	create->DesiredAccess |= FILE_READ_DATA_LE | FILE_WRITE_DATA_LE;
	KUNIT_ASSERT_EQ(test, smb2_open(&ctx->work), 0);
	opened = smb_get_msg(ctx->work.response_buf);
	target_id = opened->VolatileFileId;
	target_pid = opened->PersistentFileId;
	KUNIT_ASSERT_EQ(test, reparse_test_write(ctx, target_id, target_pid), 0);

	/* Open the parent lease after the writes have reserved a close-time break. */
	reparse_test_reset_request(ctx);
	create = reparse_test_open_req(ctx, "");
	create->DesiredAccess |= FILE_READ_DATA_LE;
	create->CreateOptions = FILE_DIRECTORY_FILE_LE;
	reparse_test_lease_req(ctx, create, 11,
			       SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE);
	KUNIT_ASSERT_EQ(test, smb2_open(&ctx->work), 0);
	reparse_test_reset_request(ctx);

	fp = ksmbd_lookup_fd_slow(&ctx->work, source_id, source_pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	KUNIT_EXPECT_TRUE(test, fp->reserve_lease_break);
	clone->in = get_file(fp->filp);
	clone->in_ops = fp->filp->f_op;
	ksmbd_fd_put(&ctx->work, fp);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, reparse_test_restore_clone_files,
							clone), 0);
	fp = ksmbd_lookup_fd_slow(&ctx->work, target_id, target_pid);
	KUNIT_ASSERT_NOT_NULL(test, fp);
	clone->out = get_file(fp->filp);
	clone->out_ops = fp->filp->f_op;
	ksmbd_fd_put(&ctx->work, fp);
	clone->source_id = source_id;
	clone->ops = *clone->in_ops;
	clone->ops.remap_file_range = param->clone ? reparse_test_clone_range : NULL;
	clone->ops.copy_file_range = reparse_test_copy_range;
	clone->in->f_op = &clone->ops;
	clone->out->f_op = &clone->ops;

	req = smb_get_msg(ctx->work.request_buf);
	req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	req->hdr.Command = SMB2_IOCTL;
	req->StructureSize = cpu_to_le16(57);
	req->CtlCode = cpu_to_le32(FSCTL_DUPLICATE_EXTENTS_TO_FILE);
	req->VolatileFileId = target_id;
	req->PersistentFileId = target_pid;
	req->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
	req->InputOffset = cpu_to_le32(offsetof(struct smb2_ioctl_req, Buffer));
	req->InputCount = cpu_to_le32(sizeof(*dup));
	dup = (void *)req->Buffer;
	dup->VolatileFileHandle = source_id;
	dup->PersistentFileHandle = source_pid;
	dup->ByteCount = cpu_to_le64(1);
	inc_rfc1001_len(ctx->work.request_buf,
			offsetof(struct smb2_ioctl_req, Buffer) + sizeof(*dup));
	ret = smb2_ioctl(&ctx->work);
	KUNIT_EXPECT_EQ(test, ret, param->fail ? -EIO : 0);
	KUNIT_EXPECT_EQ(test, clone->close_ret, 0);
	KUNIT_EXPECT_EQ(test, clone->ack_ret, 0);
	KUNIT_EXPECT_EQ(test, clone->breaks, 1);
	KUNIT_EXPECT_FALSE_MSG(test, clone->reparse_held,
			       "final source put must not wait for a lease ACK under reparse_sem");
}

static struct kunit_case reparse_test_cases[] = {
	KUNIT_CASE_PARAM(reparse_clone_source_close, reparse_clone_gen_params),
	KUNIT_CASE_PARAM(reparse_shared_lease_reconnect, reparse_shared_reconnect_gen_params),
	KUNIT_CASE_PARAM(reparse_native_alias_reconnect, reparse_reconnect_gen_params),
	KUNIT_CASE_PARAM(reparse_lease_break_close, reparse_dialect_gen_params),
	KUNIT_CASE_PARAM(reparse_absolute_symlink_response, reparse_absolute_response_gen_params),
	KUNIT_CASE_PARAM(reparse_absolute_native_link, reparse_absolute_gen_params),
	KUNIT_CASE_PARAM(reparse_absolute_native_namespace, reparse_absolute_namespace_gen_params),
	KUNIT_CASE_PARAM(reparse_set_busy_inode, reparse_busy_gen_params),
	KUNIT_CASE_PARAM(reparse_overwrite_denied, reparse_overwrite_gen_params),
	KUNIT_CASE_PARAM(reparse_native_symlink_namespace, reparse_namespace_gen_params),
	KUNIT_CASE_PARAM(reparse_unicode_symlink_suffix, reparse_unicode_gen_params),
	KUNIT_CASE_PARAM(reparse_hardlink_file_attributes, reparse_dialect_gen_params),
	KUNIT_CASE_PARAM(reparse_directory_link_query_info, reparse_dialect_gen_params),
	KUNIT_CASE_PARAM(reparse_native_alias_metadata, reparse_dialect_gen_params),
	KUNIT_CASE_PARAM(reparse_wide_link_file_info, reparse_dialect_gen_params),
	KUNIT_CASE_PARAM(reparse_directory_link_basic_info, reparse_dialect_gen_params),
	KUNIT_CASE_PARAM(reparse_fsctl_fileid, reparse_fileid_gen_params),
	KUNIT_CASE_PARAM(reparse_native_alias_relative_target, reparse_alias_gen_params),
	KUNIT_CASE_PARAM(reparse_durable_delete_on_close, reparse_durable_gen_params),
	KUNIT_CASE_PARAM(reparse_symlink_stream_suffix, reparse_stream_gen_params),
	KUNIT_CASE_PARAM(reparse_native_symlink_open_type, reparse_type_gen_params),
	KUNIT_CASE(reparse_storage_roundtrip),
	KUNIT_CASE(reparse_storage_checksum),
	KUNIT_CASE(reparse_storage_native_symlink),
	KUNIT_CASE(reparse_storage_size_limit),
	KUNIT_CASE(reparse_storage_nonempty_directory),
	KUNIT_CASE(reparse_native_symlink_create),
	KUNIT_CASE(reparse_native_symlink_limit),
	KUNIT_CASE(reparse_native_symlink_stub_dotdot),
	KUNIT_CASE(reparse_native_symlink_create_stub_dotdot),
	KUNIT_CASE(reparse_native_symlink_casefold),
	KUNIT_CASE_PARAM(reparse_compound_symlink_error, reparse_compound_gen_params),
	{}
};

static struct kunit_suite reparse_test_suite = {
	.name = "ksmbd-reparse",
	.init = reparse_test_init,
	.test_cases = reparse_test_cases,
};

kunit_test_suite(reparse_test_suite);

MODULE_DESCRIPTION("KUnit tests for ksmbd reparse points");
MODULE_LICENSE("GPL");
