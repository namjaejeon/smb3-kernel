// SPDX-License-Identifier: LGPL-2.1+
/*
 *   Copyright (C) International Business Machines  Corp., 2007,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 */

#include <linux/fs.h>
#include <kunit/visibility.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mnt_idmapping.h>

#include "smbacl.h"
#include "smb_common.h"
#include "server.h"
#include "misc.h"
#include "mgmt/share_config.h"

#define SMB_ACE_MIN_SIZE (offsetof(struct smb_ace, sid) + CIFS_SID_BASE_SIZE)

struct smb_acl_iter {
	struct smb_ace *ace;
	size_t remaining;
	u16 count;
};

static const struct smb_sid domain = {1, 4, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(21), cpu_to_le32(1), cpu_to_le32(2), cpu_to_le32(3),
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* security id for everyone/world system group */
static const struct smb_sid creator_owner = {
	1, 1, {0, 0, 0, 0, 0, 3}, {0} };
/* security id for everyone/world system group */
static const struct smb_sid creator_group = {
	1, 1, {0, 0, 0, 0, 0, 3}, {cpu_to_le32(1)} };
/* security id for owner rights */
static const struct smb_sid sid_owner_rights = {
	1, 1, {0, 0, 0, 0, 0, 3}, {cpu_to_le32(4)} };

/* security id for everyone/world system group */
static const struct smb_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };
/* security id for Authenticated Users system group */
static const struct smb_sid sid_authusers = {
	1, 1, {0, 0, 0, 0, 0, 5}, {cpu_to_le32(11)} };

/* S-1-22-1 Unmapped Unix users */
static const struct smb_sid sid_unix_users = {1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-22-2 Unmapped Unix groups */
static const struct smb_sid sid_unix_groups = { 1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * See http://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */

/* S-1-5-88 MS NFS and Apple style UID/GID/mode */

/* S-1-5-88-1 Unix uid */
static const struct smb_sid sid_unix_NFS_users = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-2 Unix gid */
static const struct smb_sid sid_unix_NFS_groups = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-3 Unix mode */
static const struct smb_sid sid_unix_NFS_mode = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(3), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * if the two SIDs (roughly equivalent to a UUID for a user or group) are
 * the same returns zero, if they do not match returns non-zero.
 */
int compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid)
{
	int i;
	int num_subauth, num_sat, num_saw;

	if (!ctsid || !cwsid)
		return 1;

	/* compare the revision */
	if (ctsid->revision != cwsid->revision) {
		if (ctsid->revision > cwsid->revision)
			return 1;
		else
			return -1;
	}

	/* compare all of the six auth values */
	for (i = 0; i < NUM_AUTHS; ++i) {
		if (ctsid->authority[i] != cwsid->authority[i]) {
			if (ctsid->authority[i] > cwsid->authority[i])
				return 1;
			else
				return -1;
		}
	}

	/* compare all of the subauth values if any */
	num_sat = ctsid->num_subauth;
	num_saw = cwsid->num_subauth;
	num_subauth = min(num_sat, num_saw);
	if (num_subauth) {
		for (i = 0; i < num_subauth; ++i) {
			if (ctsid->sub_auth[i] != cwsid->sub_auth[i]) {
				if (le32_to_cpu(ctsid->sub_auth[i]) >
				    le32_to_cpu(cwsid->sub_auth[i]))
					return 1;
				else
					return -1;
			}
		}
	}

	return 0; /* sids compare/match */
}

static void smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src)
{
	u8 num_subauth = min_t(u8, src->num_subauth, SID_MAX_SUB_AUTHORITIES);

	memcpy(dst, src, CIFS_SID_BASE_SIZE + num_subauth * sizeof(__le32));
	dst->num_subauth = num_subauth;
}

static size_t smb_sid_size(const struct smb_sid *sid)
{
	return CIFS_SID_BASE_SIZE + sid->num_subauth * sizeof(__le32);
}

static u16 smb_ace_size(const struct smb_sid *sid)
{
	return offsetof(struct smb_ace, sid) + smb_sid_size(sid);
}

static bool smb_sid_valid(const struct smb_sid *sid, size_t remaining)
{
	return remaining >= CIFS_SID_BASE_SIZE &&
		sid->num_subauth <= SID_MAX_SUB_AUTHORITIES &&
		smb_sid_size(sid) <= remaining;
}

static void smb_acl_iter_init(struct smb_acl_iter *iter, struct smb_acl *acl)
{
	iter->ace = (struct smb_ace *)(acl + 1);
	iter->remaining = le16_to_cpu(acl->size) - sizeof(*acl);
	iter->count = le16_to_cpu(acl->num_aces);
}

/* Validate the ACE extent first; callers decide how to handle invalid SIDs. */
static struct smb_ace *smb_acl_next_ace(struct smb_acl_iter *iter)
{
	struct smb_ace *ace = iter->ace;
	u16 size;

	if (!iter->count || iter->remaining < SMB_ACE_MIN_SIZE)
		return NULL;

	size = le16_to_cpu(ace->size);
	if (size < SMB_ACE_MIN_SIZE || size > iter->remaining)
		return NULL;

	iter->ace = (struct smb_ace *)((char *)ace + size);
	iter->remaining -= size;
	iter->count--;
	return ace;
}

static bool smb_ace_sid_valid(const struct smb_ace *ace)
{
	return smb_sid_valid(&ace->sid, le16_to_cpu(ace->size) -
			     offsetof(struct smb_ace, sid));
}

static int smb_get_dacl(struct smb_ntsd *ntsd, size_t size, struct smb_acl **acl)
{
	unsigned int offset;
	struct smb_acl *dacl;
	u16 dacl_size;

	*acl = NULL;
	if (size < sizeof(*ntsd))
		return -EINVAL;

	offset = le32_to_cpu(ntsd->dacloffset);
	if (!offset)
		return 0;
	if (offset < sizeof(*ntsd) || offset > size ||
	    size - offset < sizeof(*dacl))
		return -EINVAL;

	dacl = (struct smb_acl *)((char *)ntsd + offset);
	dacl_size = le16_to_cpu(dacl->size);
	if (dacl_size < sizeof(*dacl) || dacl_size > size - offset)
		return -EINVAL;

	*acl = dacl;
	return 0;
}

static int smb_validate_ntsd_sid(struct smb_ntsd *ntsd, size_t size,
				 unsigned int offset, struct smb_sid **sid,
				 size_t *sid_size)
{
	struct smb_sid *psid;

	*sid = NULL;
	if (sid_size)
		*sid_size = 0;
	if (!offset)
		return 0;
	if (offset < sizeof(*ntsd) || offset > size ||
	    size - offset < CIFS_SID_BASE_SIZE)
		return -EINVAL;

	psid = (struct smb_sid *)((char *)ntsd + offset);
	if (!smb_sid_valid(psid, size - offset))
		return -EINVAL;

	*sid = psid;
	if (sid_size)
		*sid_size = smb_sid_size(psid);
	return 0;
}

static void smb_set_ace(struct smb_ace *ace, const struct smb_sid *sid, u8 type,
			u8 flags, __le32 access_req)
{
	ace->type = type;
	ace->flags = flags;
	ace->access_req = access_req;
	smb_copy_sid(&ace->sid, sid);
	ace->size = cpu_to_le16(smb_ace_size(&ace->sid));
}

static struct smb_ace *smb_acl_reserve_ace(struct smb_acl *acl, u16 ace_size)
{
	u16 size = le16_to_cpu(acl->size);
	u16 count = le16_to_cpu(acl->num_aces);
	struct smb_ace *ace;

	if (ace_size > U16_MAX - size || count == U16_MAX)
		return ERR_PTR(-EOVERFLOW);

	ace = (struct smb_ace *)((char *)acl + size);
	acl->size = cpu_to_le16(size + ace_size);
	acl->num_aces = cpu_to_le16(count + 1);
	return ace;
}

/*
 * change posix mode to reflect permissions
 * pmode is the existing mode (we only want to overwrite part of this
 * bits to set can be: S_IRWXU, S_IRWXG or S_IRWXO ie 00700 or 00070 or 00007
 */
static umode_t access_flags_to_mode(struct smb_fattr *fattr, __le32 ace_flags,
				    int type)
{
	__u32 flags = le32_to_cpu(ace_flags);
	umode_t mode = 0;

	if (flags & GENERIC_ALL) {
		mode = 0777;
		ksmbd_debug(SMB, "all perms\n");
		return mode;
	}

	if ((flags & GENERIC_READ) || (flags & FILE_READ_RIGHTS))
		mode = 0444;
	if ((flags & GENERIC_WRITE) || (flags & FILE_WRITE_RIGHTS)) {
		mode |= 0222;
		if (S_ISDIR(fattr->cf_mode))
			mode |= 0111;
	}
	if ((flags & GENERIC_EXECUTE) || (flags & FILE_EXEC_RIGHTS))
		mode |= 0111;

	if (type == ACCESS_DENIED_ACE_TYPE || type == ACCESS_DENIED_OBJECT_ACE_TYPE)
		mode = ~mode;

	ksmbd_debug(SMB, "access flags 0x%x mode now %04o\n", flags, mode);

	return mode;
}

/*
 * Generate access flags to reflect permissions mode is the existing mode.
 * This function is called for every ACE in the DACL whose SID matches
 * with either owner or group or everyone.
 */
static void mode_to_access_flags(umode_t mode, umode_t bits_to_use,
				 __u32 *pace_flags)
{
	/* reset access mask */
	*pace_flags = 0x0;

	/* bits to use are either S_IRWXU or S_IRWXG or S_IRWXO */
	mode &= bits_to_use;

	/*
	 * check for R/W/X UGO since we do not know whose flags
	 * is this but we have cleared all the bits sans RWX for
	 * either user or group or other as per bits_to_use
	 */
	if (mode & 0444)
		*pace_flags |= SET_FILE_READ_RIGHTS;
	if (mode & 0222)
		*pace_flags |= FILE_WRITE_RIGHTS;
	if (mode & 0111)
		*pace_flags |= SET_FILE_EXEC_RIGHTS;

	ksmbd_debug(SMB, "mode: %o, access flags now 0x%x\n",
		    mode, *pace_flags);
}

static int smb_acl_add_mode_ace(struct smb_acl *acl, const struct smb_sid *sid,
				u8 flags, umode_t mode, umode_t bits,
				__le32 extra_access)
{
	struct smb_ace *ace;
	u32 access_req;

	ace = smb_acl_reserve_ace(acl, smb_ace_size(sid));
	if (IS_ERR(ace))
		return PTR_ERR(ace);
	mode_to_access_flags(mode, bits, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	smb_set_ace(ace, sid, ACCESS_ALLOWED, flags,
		    cpu_to_le32(access_req) | extra_access);
	return 0;
}

void id_to_sid(unsigned int cid, uint sidtype, struct smb_sid *ssid)
{
	switch (sidtype) {
	case SIDOWNER:
		smb_copy_sid(ssid, &server_conf.domain_sid);
		break;
	case SIDUNIX_USER:
		smb_copy_sid(ssid, &sid_unix_users);
		break;
	case SIDUNIX_GROUP:
		smb_copy_sid(ssid, &sid_unix_groups);
		break;
	case SIDCREATOR_OWNER:
		smb_copy_sid(ssid, &creator_owner);
		return;
	case SIDCREATOR_GROUP:
		smb_copy_sid(ssid, &creator_group);
		return;
	case SIDNFS_USER:
		smb_copy_sid(ssid, &sid_unix_NFS_users);
		break;
	case SIDNFS_GROUP:
		smb_copy_sid(ssid, &sid_unix_NFS_groups);
		break;
	case SIDNFS_MODE:
		smb_copy_sid(ssid, &sid_unix_NFS_mode);
		break;
	default:
		return;
	}

	/* RID */
	ssid->sub_auth[ssid->num_subauth] = cpu_to_le32(cid);
	ssid->num_subauth++;
}

static int sid_to_id(struct mnt_idmap *idmap,
		     struct smb_sid *psid, uint sidtype,
		     struct smb_fattr *fattr)
{
	const struct smb_sid *sid_prefix;
	int rc = -EINVAL;

	/*
	 * If we have too many subauthorities, then something is really wrong.
	 * Just return an error.
	 */
	if (unlikely(psid->num_subauth > SID_MAX_SUB_AUTHORITIES)) {
		pr_err("%s: %u subauthorities is too many!\n",
		       __func__, psid->num_subauth);
		return -EIO;
	}

	if (psid->num_subauth == 0) {
		pr_err("%s: zero subauthorities!\n", __func__);
		return -EIO;
	}

	if (sidtype == SIDOWNER) {
		kuid_t uid;
		uid_t id;

		/* Only the server domain RID has a local uid representation. */
		sid_prefix = &server_conf.domain_sid;
		if (psid->num_subauth != sid_prefix->num_subauth + 1 ||
		    compare_sids(psid, sid_prefix))
			return -EINVAL;

		id = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);
		uid = KUIDT_INIT(id);
		uid = from_vfsuid(idmap, &init_user_ns, VFSUIDT_INIT(uid));
		if (uid_valid(uid)) {
			fattr->cf_uid = uid;
			rc = 0;
		}
	} else {
		kgid_t gid;
		gid_t id;

		/* Local gids are represented by S-1-22-2-<gid>. */
		sid_prefix = &sid_unix_groups;
		if (psid->num_subauth != sid_prefix->num_subauth + 1 ||
		    compare_sids(psid, sid_prefix))
			return -EINVAL;

		id = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);
		gid = KGIDT_INIT(id);
		gid = from_vfsgid(idmap, &init_user_ns, VFSGIDT_INIT(gid));
		if (gid_valid(gid)) {
			fattr->cf_gid = gid;
			rc = 0;
		}
	}

	return rc;
}

void posix_state_to_acl(struct posix_acl_state *state,
			struct posix_acl_entry *pace)
{
	int i;

	pace->e_tag = ACL_USER_OBJ;
	pace->e_perm = state->owner.allow;
	for (i = 0; i < state->users->n; i++) {
		pace++;
		pace->e_tag = ACL_USER;
		pace->e_uid = state->users->aces[i].uid;
		pace->e_perm = state->users->aces[i].perms.allow;
	}

	pace++;
	pace->e_tag = ACL_GROUP_OBJ;
	pace->e_perm = state->group.allow;

	for (i = 0; i < state->groups->n; i++) {
		pace++;
		pace->e_tag = ACL_GROUP;
		pace->e_gid = state->groups->aces[i].gid;
		pace->e_perm = state->groups->aces[i].perms.allow;
	}

	if (state->users->n || state->groups->n) {
		pace++;
		pace->e_tag = ACL_MASK;
		pace->e_perm = state->mask.allow;
	}

	pace++;
	pace->e_tag = ACL_OTHER;
	pace->e_perm = state->other.allow;
}

int init_acl_state(struct posix_acl_state *state, u16 cnt)
{
	size_t alloc;

	memset(state, 0, sizeof(*state));
	/*
	 * In the worst case, each individual acl could be for a distinct
	 * named user or group, but we don't know which, so we allocate
	 * enough space for either:
	 */
	alloc = struct_size(state->users, aces, cnt);
	state->users = kzalloc(alloc, KSMBD_DEFAULT_GFP);
	if (!state->users)
		return -ENOMEM;
	state->groups = kzalloc(alloc, KSMBD_DEFAULT_GFP);
	if (!state->groups) {
		kfree(state->users);
		return -ENOMEM;
	}
	return 0;
}

void free_acl_state(struct posix_acl_state *state)
{
	kfree(state->users);
	kfree(state->groups);
}

static void smb_acl_state_add_user(struct posix_acl_state *state, kuid_t uid,
				   umode_t mode)
{
	struct posix_user_ace_state *user = &state->users->aces[state->users->n++];

	/* The owner must be set to at least read-only. */
	state->owner.allow = ((mode & 0700) >> 6) | 0004;
	user->uid = uid;
	user->perms.allow = state->owner.allow;
}

static int smb_acl_state_alloc_posix(struct posix_acl_state *state,
				     struct posix_acl **acl)
{
	if (!IS_ENABLED(CONFIG_FS_POSIX_ACL) ||
	    (!state->users->n && !state->groups->n))
		return 0;

	*acl = posix_acl_alloc(state->users->n + state->groups->n + 4,
			       KSMBD_DEFAULT_GFP);
	if (!*acl)
		return -ENOMEM;

	state->mask.allow = 0x07;
	posix_state_to_acl(state, (*acl)->a_entries);
	return 0;
}

static int parse_dacl(struct mnt_idmap *idmap,
		      struct smb_acl *pdacl,
		      struct smb_sid *pownersid, struct smb_sid *pgrpsid,
		      struct smb_fattr *fattr)
{
	int i, ret;
	u16 num_aces;
	struct smb_acl_iter iter;
	struct smb_ace *ace;
	struct posix_acl_state acl_state;
	umode_t mode = 0, acl_mode;
	bool owner_found = false, group_found = false, others_found = false;

	if (!pdacl)
		return 0;

	ksmbd_debug(SMB, "DACL revision %d size %d num aces %d\n",
		    le16_to_cpu(pdacl->revision), le16_to_cpu(pdacl->size),
		    le16_to_cpu(pdacl->num_aces));

	num_aces = le16_to_cpu(pdacl->num_aces);
	if (!num_aces)
		return 0;

	smb_acl_iter_init(&iter, pdacl);
	if (num_aces > iter.remaining / (SMB_ACE_MIN_SIZE + sizeof(__le32)))
		return -EINVAL;

	ret = init_acl_state(&acl_state, num_aces);
	if (ret)
		return ret;
	for (i = 0; i < num_aces; ++i) {
		ace = smb_acl_next_ace(&iter);
		if (!ace || !smb_ace_sid_valid(ace) || !ace->sid.num_subauth) {
			ret = -EINVAL;
			goto out;
		}

		ace->access_req = smb_map_generic_desired_access(ace->access_req);

		if (ace->type == ACCESS_ALLOWED &&
		    ace->sid.num_subauth >= 3 &&
		    !compare_sids(&ace->sid, &sid_unix_NFS_mode)) {
			fattr->cf_mode = le32_to_cpu(ace->sid.sub_auth[2]);
			fattr->cf_posix_mode = true;
			break;
		} else if (!compare_sids(&ace->sid, pownersid)) {
			acl_mode = access_flags_to_mode(fattr, ace->access_req, ace->type);
			acl_mode &= 0700;

			if (!owner_found) {
				mode &= ~(0700);
				mode |= acl_mode;
			}
			owner_found = true;
		} else if (!compare_sids(&ace->sid, pgrpsid) ||
			   ace->sid.sub_auth[ace->sid.num_subauth - 1] ==
			    DOMAIN_USER_RID_LE) {
			acl_mode = access_flags_to_mode(fattr, ace->access_req, ace->type);
			acl_mode &= 0070;
			if (!group_found) {
				mode &= ~(0070);
				mode |= acl_mode;
			}
			group_found = true;
		} else if (!compare_sids(&ace->sid, &sid_everyone)) {
			acl_mode = access_flags_to_mode(fattr, ace->access_req, ace->type);
			acl_mode &= 0007;
			if (!others_found) {
				mode &= ~(0007);
				mode |= acl_mode;
			}
			others_found = true;
		} else if (!compare_sids(&ace->sid, &creator_owner) ||
			   !compare_sids(&ace->sid, &creator_group) ||
			   !compare_sids(&ace->sid, &sid_authusers)) {
			continue;
		} else {
			struct smb_fattr temp_fattr;

			acl_mode = access_flags_to_mode(fattr, ace->access_req, ace->type);
			temp_fattr.cf_uid = INVALID_UID;
			ret = sid_to_id(idmap, &ace->sid, SIDOWNER, &temp_fattr);
			if (ret || uid_eq(temp_fattr.cf_uid, INVALID_UID)) {
				pr_err_ratelimited("%s: Error %d mapping Owner SID to uid\n",
						   __func__, ret);
				continue;
			}

			smb_acl_state_add_user(&acl_state, temp_fattr.cf_uid, acl_mode);
		}
	}
	if (fattr->cf_posix_mode) {
		ret = 0;
		goto out;
	}

	if (owner_found)
		smb_acl_state_add_user(&acl_state, fattr->cf_uid, mode);

	if (group_found) {
		acl_state.group.allow = (mode & 0070) >> 3;
		acl_state.groups->aces[acl_state.groups->n].gid =
			fattr->cf_gid;
		acl_state.groups->aces[acl_state.groups->n++].perms.allow =
			(mode & 0070) >> 3;
	}

	if (others_found) {
		fattr->cf_mode &= ~(0007);
		fattr->cf_mode |= mode & 0007;

		acl_state.other.allow = mode & 0007;
	}

	ret = smb_acl_state_alloc_posix(&acl_state, &fattr->cf_acls);
	if (!ret)
		ret = smb_acl_state_alloc_posix(&acl_state, &fattr->cf_dacls);
out:
	free_acl_state(&acl_state);
	return ret;
}

static bool smb_posix_acl_entry_sid(struct mnt_idmap *idmap,
				    struct posix_acl_entry *entry,
				    struct smb_sid *sid)
{
	uid_t uid;

	switch (entry->e_tag) {
	case ACL_USER:
		uid = posix_acl_uid_translate(idmap, entry);
		id_to_sid(uid, uid ? SIDOWNER : SIDUNIX_USER, sid);
		return true;
	case ACL_GROUP:
		id_to_sid(posix_acl_gid_translate(idmap, entry), SIDUNIX_GROUP, sid);
		return true;
	case ACL_OTHER:
		smb_copy_sid(sid, &sid_everyone);
		return true;
	default:
		return false;
	}
}

static bool smb_acl_has_rid(struct smb_acl *acl, u16 count,
			    const struct smb_sid *sid)
{
	struct smb_acl_iter iter;
	struct smb_ace *ace;
	__le32 rid = sid->sub_auth[sid->num_subauth - 1];

	smb_acl_iter_init(&iter, acl);
	iter.count = count;
	while ((ace = smb_acl_next_ace(&iter))) {
		if (ace->sid.sub_auth[ace->sid.num_subauth - 1] == rid)
			return true;
	}
	return false;
}

static int set_posix_acl_entries_dacl(struct mnt_idmap *idmap,
				      struct smb_acl *acl,
				      struct smb_fattr *fattr,
				      u16 existing_nt_aces, bool had_nt_aces)
{
	struct posix_acl_entry *entry;
	struct smb_sid sid;
	const struct smb_sid *creator;
	bool is_dir = S_ISDIR(fattr->cf_mode);
	u8 inherit_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	__le32 extra_access;
	int i, ret;

	if (!fattr->cf_acls)
		goto posix_default_acl;

	entry = fattr->cf_acls->a_entries;
	for (i = 0; i < fattr->cf_acls->a_count; i++, entry++) {
		u8 flags = 0;

		if ((entry->e_tag == ACL_OTHER && had_nt_aces) ||
		    !smb_posix_acl_entry_sid(idmap, entry, &sid))
			continue;
		if (smb_acl_has_rid(acl, existing_nt_aces, &sid))
			continue;

		if (is_dir && entry->e_tag == ACL_OTHER)
			flags = inherit_flags;
		extra_access = entry->e_tag == ACL_USER ?
			FILE_DELETE_LE | FILE_DELETE_CHILD_LE : 0;
		ret = smb_acl_add_mode_ace(acl, &sid, flags, entry->e_perm,
					   0777, extra_access);
		if (ret)
			return ret;

		if (is_dir && (entry->e_tag == ACL_USER || entry->e_tag == ACL_GROUP)) {
			ret = smb_acl_add_mode_ace(acl, &sid, inherit_flags,
						   entry->e_perm, 0777, extra_access);
			if (ret)
				return ret;
		}
	}

	if (had_nt_aces)
		return 0;

posix_default_acl:
	if (!fattr->cf_dacls)
		return 0;

	entry = fattr->cf_dacls->a_entries;
	for (i = 0; i < fattr->cf_dacls->a_count; i++, entry++) {
		switch (entry->e_tag) {
		case ACL_USER:
			creator = &creator_owner;
			extra_access = FILE_DELETE_LE | FILE_DELETE_CHILD_LE;
			break;
		case ACL_GROUP:
			creator = &creator_group;
			extra_access = 0;
			break;
		default:
			continue;
		}

		ret = smb_acl_add_mode_ace(acl, creator,
					   inherit_flags | INHERIT_ONLY_ACE,
					   entry->e_perm, 0777, extra_access);
		if (ret)
			return ret;
	}
	return 0;
}

static int set_ntacl_dacl(struct mnt_idmap *idmap, struct smb_acl *acl,
			  struct smb_acl *nt_dacl, struct smb_fattr *fattr)
{
	struct smb_acl_iter iter;
	struct smb_ace *ace, *new_ace;
	u16 copied_nt_aces;

	smb_acl_iter_init(&iter, nt_dacl);
	while ((ace = smb_acl_next_ace(&iter))) {
		if (!smb_ace_sid_valid(ace) || !ace->sid.num_subauth)
			continue;

		new_ace = smb_acl_reserve_ace(acl, le16_to_cpu(ace->size));
		if (IS_ERR(new_ace))
			return PTR_ERR(new_ace);
		memcpy(new_ace, ace, le16_to_cpu(ace->size));
	}

	copied_nt_aces = le16_to_cpu(acl->num_aces);
	return set_posix_acl_entries_dacl(idmap, acl, fattr, copied_nt_aces,
					  nt_dacl->num_aces != 0);
}

static int set_mode_dacl(struct mnt_idmap *idmap,
			 struct smb_acl *acl, struct smb_fattr *fattr)
{
	struct smb_sid sid;
	uid_t uid;
	u8 flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;
	int ret;

	if (fattr->cf_acls)
		return set_posix_acl_entries_dacl(idmap, acl, fattr, 0, false);

	uid = from_kuid(&init_user_ns, fattr->cf_uid);
	id_to_sid(uid, uid ? SIDOWNER : SIDUNIX_USER, &sid);
	ret = smb_acl_add_mode_ace(acl, &sid, 0, fattr->cf_mode, 0700, 0);
	if (ret)
		return ret;

	id_to_sid(from_kgid(&init_user_ns, fattr->cf_gid), SIDUNIX_GROUP, &sid);
	ret = smb_acl_add_mode_ace(acl, &sid, 0, fattr->cf_mode, 0070, 0);
	if (ret)
		return ret;

	if (S_ISDIR(fattr->cf_mode)) {
		ret = smb_acl_add_mode_ace(acl, &creator_owner, flags,
					   fattr->cf_mode, 0700, 0);
		if (ret)
			return ret;
		ret = smb_acl_add_mode_ace(acl, &creator_group, flags,
					   fattr->cf_mode, 0070, 0);
		if (ret)
			return ret;
	}

	return smb_acl_add_mode_ace(acl, &sid_everyone, 0, fattr->cf_mode, 0007, 0);
}

/* Convert CIFS ACL to POSIX form */
int parse_sec_desc(struct mnt_idmap *idmap, struct smb_ntsd *pntsd,
		   int acl_len, struct smb_fattr *fattr)
{
	int rc = 0;
	struct smb_sid *owner_sid_ptr, *group_sid_ptr;
	struct smb_acl *dacl_ptr; /* no need for SACL ptr */
	__u32 dacloffset;
	int pntsd_type;

	if (!pntsd)
		return -EIO;

	if (acl_len < (int)sizeof(*pntsd))
		return -EINVAL;

	owner_sid_ptr = NULL;
	group_sid_ptr = NULL;
	dacloffset = le32_to_cpu(pntsd->dacloffset);
	ksmbd_debug(SMB,
		    "revision %d type 0x%x ooffset 0x%x goffset 0x%x sacloffset 0x%x dacloffset 0x%x\n",
		    pntsd->revision, pntsd->type, le32_to_cpu(pntsd->osidoffset),
		    le32_to_cpu(pntsd->gsidoffset),
		    le32_to_cpu(pntsd->sacloffset), dacloffset);

	pntsd_type = le16_to_cpu(pntsd->type);
	if (!(pntsd_type & DACL_PRESENT)) {
		ksmbd_debug(SMB, "DACL_PRESENT in DACL type is not set\n");
		return rc;
	}

	pntsd->type = cpu_to_le16(DACL_PRESENT);

	if (pntsd->osidoffset) {
		rc = smb_validate_ntsd_sid(pntsd, acl_len,
					   le32_to_cpu(pntsd->osidoffset),
					   &owner_sid_ptr, NULL);
		if (rc) {
			pr_err("%s: Error %d parsing Owner SID\n", __func__, rc);
			return rc;
		}

		rc = sid_to_id(idmap, owner_sid_ptr, SIDOWNER, fattr);
		if (rc) {
			ksmbd_debug(SMB, "Owner SID has no Unix uid mapping\n");
			owner_sid_ptr = NULL;
			rc = 0;
		}
	}

	if (pntsd->gsidoffset) {
		rc = smb_validate_ntsd_sid(pntsd, acl_len,
					   le32_to_cpu(pntsd->gsidoffset),
					   &group_sid_ptr, NULL);
		if (rc) {
			pr_err("%s: Error %d mapping Owner SID to gid\n",
			       __func__, rc);
			return rc;
		}
		rc = sid_to_id(idmap, group_sid_ptr, SIDUNIX_GROUP, fattr);
		if (rc) {
			ksmbd_debug(SMB, "Group SID has no Unix gid mapping\n");
			group_sid_ptr = NULL;
			rc = 0;
		}
	}

	if ((pntsd_type & (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ)) ==
	    (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ))
		pntsd->type |= cpu_to_le16(DACL_AUTO_INHERITED);
	if (pntsd_type & DACL_PROTECTED)
		pntsd->type |= cpu_to_le16(DACL_PROTECTED);

	if (dacloffset) {
		rc = smb_get_dacl(pntsd, acl_len, &dacl_ptr);
		if (rc)
			return rc;
		rc = parse_dacl(idmap, dacl_ptr,
				owner_sid_ptr, group_sid_ptr, fattr);
		if (rc)
			return rc;
	}

	return 0;
}

size_t smb_acl_sec_desc_scratch_len(struct smb_fattr *fattr,
		struct smb_ntsd *ppntsd, int ppntsd_size, int addition_info)
{
	size_t len = sizeof(struct smb_ntsd);
	size_t tmp;

	if (addition_info & OWNER_SECINFO)
		len += sizeof(struct smb_sid);
	if (addition_info & GROUP_SECINFO)
		len += sizeof(struct smb_sid);
	if (!(addition_info & DACL_SECINFO))
		return len;

	len += sizeof(struct smb_acl);
	if (ppntsd && ppntsd_size >= (int)sizeof(*ppntsd)) {
		unsigned int dacl_offset = le32_to_cpu(ppntsd->dacloffset);

		if (dacl_offset < ppntsd_size &&
		    check_add_overflow(len, ppntsd_size - dacl_offset, &len))
			return 0;
	}

	if (fattr->cf_acls) {
		if (check_mul_overflow((size_t)fattr->cf_acls->a_count,
					2 * sizeof(struct smb_ace), &tmp) ||
		    check_add_overflow(len, tmp, &len))
			return 0;
	} else {
		/* default/minimum DACL */
		if (check_add_overflow(len, 5 * sizeof(struct smb_ace), &len))
			return 0;
	}

	if (fattr->cf_dacls) {
		if (check_mul_overflow((size_t)fattr->cf_dacls->a_count,
					sizeof(struct smb_ace), &tmp) ||
		    check_add_overflow(len, tmp, &len))
			return 0;
	}

	return len;
}

/* Convert permission bits from mode to equivalent CIFS ACL */
int build_sec_desc(struct mnt_idmap *idmap,
		   struct smb_ntsd *pntsd, struct smb_ntsd *ppntsd,
		   int ppntsd_size, int addition_info, __u32 *secdesclen,
		   struct smb_fattr *fattr)
{
	int rc = 0;
	__u32 offset = sizeof(*pntsd);
	struct smb_sid *sid;
	struct smb_acl *dacl;
	uid_t uid;

	if (ppntsd && ppntsd_size < (int)sizeof(*ppntsd))
		return -EINVAL;

	pntsd->osidoffset = 0;
	pntsd->gsidoffset = 0;
	pntsd->sacloffset = 0;
	pntsd->dacloffset = 0;
	pntsd->revision = cpu_to_le16(SD_REVISION);
	pntsd->type = cpu_to_le16(SELF_RELATIVE);
	if (ppntsd)
		pntsd->type |= ppntsd->type;

	if (addition_info & OWNER_SECINFO) {
		pntsd->osidoffset = cpu_to_le32(offset);
		sid = (struct smb_sid *)((char *)pntsd + offset);
		uid = from_kuid(&init_user_ns, fattr->cf_uid);
		id_to_sid(uid, uid ? SIDOWNER : SIDUNIX_USER, sid);
		offset += smb_sid_size(sid);
	}

	if (addition_info & GROUP_SECINFO) {
		pntsd->gsidoffset = cpu_to_le32(offset);
		sid = (struct smb_sid *)((char *)pntsd + offset);
		id_to_sid(from_kgid(&init_user_ns, fattr->cf_gid), SIDUNIX_GROUP, sid);
		offset += smb_sid_size(sid);
	}

	if (addition_info & DACL_SECINFO) {
		struct smb_acl *nt_dacl;

		pntsd->type |= cpu_to_le16(DACL_PRESENT);
		dacl = (struct smb_acl *)((char *)pntsd + offset);
		dacl->revision = cpu_to_le16(2);
		dacl->size = cpu_to_le16(sizeof(*dacl));
		dacl->num_aces = 0;
		dacl->reserved = 0;

		if (!ppntsd) {
			rc = set_mode_dacl(idmap, dacl, fattr);
		} else {
			if (smb_get_dacl(ppntsd, ppntsd_size, &nt_dacl) || !nt_dacl)
				goto out;
			rc = set_ntacl_dacl(idmap, dacl, nt_dacl, fattr);
		}
		if (rc)
			goto out;

		pntsd->dacloffset = cpu_to_le32(offset);
		offset += le16_to_cpu(dacl->size);
	}

out:
	*secdesclen = offset;
	return rc;
}

static int smb_append_inherited_ace(struct smb_ace **ace, int *nt_size,
				    u16 *ace_cnt, const struct smb_sid *sid,
				    u8 type, u8 flags, __le32 access_req)
{
	int ace_size;

	ace_size = smb_ace_size(sid);
	/* pdacl->size is __le16 and includes struct smb_acl. */
	if (*nt_size > U16_MAX - (int)sizeof(struct smb_acl) - ace_size)
		return -EINVAL;

	smb_set_ace(*ace, sid, type, flags, access_req);
	*nt_size += ace_size;
	(*ace_cnt)++;
	*ace = (struct smb_ace *)((char *)*ace + ace_size);
	return 0;
}

int smb_inherit_dacl(struct ksmbd_conn *conn,
		     const struct path *path,
		     unsigned int uid, unsigned int gid)
{
	const struct smb_sid *psid, *creator = NULL;
	struct smb_ace *parent_aces, *aces;
	struct smb_acl *parent_pdacl;
	struct smb_ntsd *parent_pntsd = NULL;
	struct smb_sid owner_sid, group_sid;
	struct smb_acl_iter iter;
	struct dentry *parent = path->dentry->d_parent;
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
	int inherited_flags = 0, flags = 0, nt_size = 0;
	int rc = 0, pntsd_type, ppntsd_size;
	u16 num_aces, ace_cnt = 0;
	char *aces_base;
	bool is_dir = S_ISDIR(d_inode(path->dentry)->i_mode);

	ppntsd_size = ksmbd_vfs_get_sd_xattr(conn, idmap,
					    parent, &parent_pntsd);
	if (ppntsd_size <= 0)
		return -ENOENT;

	rc = smb_get_dacl(parent_pntsd, ppntsd_size, &parent_pdacl);
	if (rc || !parent_pdacl) {
		rc = -EINVAL;
		goto free_parent_pntsd;
	}

	num_aces = le16_to_cpu(parent_pdacl->num_aces);
	pntsd_type = le16_to_cpu(parent_pntsd->type);
	smb_acl_iter_init(&iter, parent_pdacl);
	if (num_aces > iter.remaining / SMB_ACE_MIN_SIZE) {
		rc = -EINVAL;
		goto free_parent_pntsd;
	}

	aces_base = kmalloc_array(num_aces * 2, sizeof(struct smb_ace),
				  KSMBD_DEFAULT_GFP);
	if (!aces_base) {
		rc = -ENOMEM;
		goto free_parent_pntsd;
	}

	aces = (struct smb_ace *)aces_base;

	if (pntsd_type & DACL_AUTO_INHERITED)
		inherited_flags = INHERITED_ACE;

	while ((parent_aces = smb_acl_next_ace(&iter))) {
		if (!smb_ace_sid_valid(parent_aces))
			break;

		flags = parent_aces->flags;
		if (!smb_inherit_flags(flags, is_dir))
			continue;
		if (is_dir) {
			flags &= ~(INHERIT_ONLY_ACE | INHERITED_ACE);
			if (!(flags & CONTAINER_INHERIT_ACE))
				flags |= INHERIT_ONLY_ACE;
			if (flags & NO_PROPAGATE_INHERIT_ACE)
				flags = 0;
		} else {
			flags = 0;
		}

		if (!compare_sids(&creator_owner, &parent_aces->sid)) {
			creator = &creator_owner;
			id_to_sid(uid, SIDOWNER, &owner_sid);
			psid = &owner_sid;
		} else if (!compare_sids(&creator_group, &parent_aces->sid)) {
			creator = &creator_group;
			id_to_sid(gid, SIDUNIX_GROUP, &group_sid);
			psid = &group_sid;
		} else {
			creator = NULL;
			psid = &parent_aces->sid;
		}

		if (is_dir && creator && flags & CONTAINER_INHERIT_ACE) {
			rc = smb_append_inherited_ace(&aces, &nt_size, &ace_cnt,
						      psid, parent_aces->type,
						      inherited_flags,
						      parent_aces->access_req);
			if (rc)
				goto free_aces_base;
			flags |= INHERIT_ONLY_ACE;
			psid = creator;
		} else if (is_dir && !(parent_aces->flags & NO_PROPAGATE_INHERIT_ACE)) {
			psid = &parent_aces->sid;
		}

		rc = smb_append_inherited_ace(&aces, &nt_size, &ace_cnt, psid,
					      parent_aces->type,
					      flags | inherited_flags,
					      parent_aces->access_req);
		if (rc)
			goto free_aces_base;
	}

	if (nt_size > 0) {
		struct smb_ntsd *pntsd;
		struct smb_acl *pdacl;
		struct smb_sid *powner_sid = NULL, *pgroup_sid = NULL;
		size_t powner_sid_size = 0, pgroup_sid_size = 0, pntsd_size;
		size_t pntsd_alloc_size;

		rc = smb_validate_ntsd_sid(parent_pntsd, ppntsd_size,
					   le32_to_cpu(parent_pntsd->osidoffset),
					   &powner_sid, &powner_sid_size);
		if (rc)
			goto free_aces_base;
		rc = smb_validate_ntsd_sid(parent_pntsd, ppntsd_size,
					   le32_to_cpu(parent_pntsd->gsidoffset),
					   &pgroup_sid, &pgroup_sid_size);
		if (rc)
			goto free_aces_base;

		if (check_add_overflow(sizeof(struct smb_ntsd),
				       (size_t)powner_sid_size,
				       &pntsd_alloc_size) ||
		    check_add_overflow(pntsd_alloc_size,
				       (size_t)pgroup_sid_size,
				       &pntsd_alloc_size) ||
		    check_add_overflow(pntsd_alloc_size, sizeof(struct smb_acl),
				       &pntsd_alloc_size) ||
		    check_add_overflow(pntsd_alloc_size, (size_t)nt_size,
				       &pntsd_alloc_size)) {
			rc = -EINVAL;
			goto free_aces_base;
		}

		pntsd = kzalloc(pntsd_alloc_size, KSMBD_DEFAULT_GFP);
		if (!pntsd) {
			rc = -ENOMEM;
			goto free_aces_base;
		}

		pntsd->revision = cpu_to_le16(1);
		pntsd->type = cpu_to_le16(SELF_RELATIVE | DACL_PRESENT);
		if (le16_to_cpu(parent_pntsd->type) & DACL_AUTO_INHERITED)
			pntsd->type |= cpu_to_le16(DACL_AUTO_INHERITED);
		pntsd_size = sizeof(struct smb_ntsd);
		pntsd->osidoffset = parent_pntsd->osidoffset;
		pntsd->gsidoffset = parent_pntsd->gsidoffset;
		pntsd->dacloffset = parent_pntsd->dacloffset;

		if ((u64)le32_to_cpu(pntsd->osidoffset) + powner_sid_size >
		    pntsd_alloc_size) {
			rc = -EINVAL;
			kfree(pntsd);
			goto free_aces_base;
		}

		if ((u64)le32_to_cpu(pntsd->gsidoffset) + pgroup_sid_size >
		    pntsd_alloc_size) {
			rc = -EINVAL;
			kfree(pntsd);
			goto free_aces_base;
		}

		if ((u64)le32_to_cpu(pntsd->dacloffset) + sizeof(struct smb_acl) + nt_size >
		    pntsd_alloc_size) {
			rc = -EINVAL;
			kfree(pntsd);
			goto free_aces_base;
		}

		if (pntsd->osidoffset) {
			struct smb_sid *owner_sid = (struct smb_sid *)((char *)pntsd +
					le32_to_cpu(pntsd->osidoffset));
			memcpy(owner_sid, powner_sid, powner_sid_size);
			pntsd_size += powner_sid_size;
		}

		if (pntsd->gsidoffset) {
			struct smb_sid *group_sid = (struct smb_sid *)((char *)pntsd +
					le32_to_cpu(pntsd->gsidoffset));
			memcpy(group_sid, pgroup_sid, pgroup_sid_size);
			pntsd_size += pgroup_sid_size;
		}

		if (pntsd->dacloffset) {
			struct smb_ace *pace;

			pdacl = (struct smb_acl *)((char *)pntsd + le32_to_cpu(pntsd->dacloffset));
			pdacl->revision = cpu_to_le16(2);
			pdacl->size = cpu_to_le16(sizeof(struct smb_acl) + nt_size);
			pdacl->num_aces = cpu_to_le16(ace_cnt);
			pace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));
			memcpy(pace, aces_base, nt_size);
			pntsd_size += sizeof(struct smb_acl) + nt_size;
		}

		ksmbd_vfs_set_sd_xattr(conn, idmap, path, pntsd, pntsd_size, false);
		kfree(pntsd);
	}

free_aces_base:
	kfree(aces_base);
free_parent_pntsd:
	kfree(parent_pntsd);
	return rc;
}

bool smb_inherit_flags(int flags, bool is_dir)
{
	if (!is_dir)
		return (flags & OBJECT_INHERIT_ACE) != 0;

	if (flags & OBJECT_INHERIT_ACE && !(flags & NO_PROPAGATE_INHERIT_ACE))
		return true;

	if (flags & CONTAINER_INHERIT_ACE)
		return true;
	return false;
}

int smb_check_perm_dacl(struct ksmbd_conn *conn, const struct path *path,
			__le32 *pdaccess, __le32 raw_daccess, int uid,
			bool strict)
{
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
	struct smb_ntsd *pntsd = NULL;
	struct smb_acl *pdacl;
	struct smb_acl_iter iter;
	struct posix_acl *posix_acls;
	int rc = 0, pntsd_size;
	struct smb_sid sid;
	int requested = le32_to_cpu(*pdaccess & ~FILE_MAXIMAL_ACCESS_LE);
	int granted = requested;
	struct smb_ace *ace;
	struct smb_ace *matched_ace = NULL;
	int i, found = 0;
	unsigned int access_bits = 0, denied = 0;
	struct smb_ace *others_ace = NULL;
	struct posix_acl_entry *pa_entry;
	unsigned int sid_type = SIDOWNER;
	bool is_owner, owner_rights = false;
	bool maximal_access = *pdaccess & FILE_MAXIMAL_ACCESS_LE;
	vfsuid_t vfsuid;

	ksmbd_debug(SMB, "check permission using windows acl\n");
	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, idmap,
					    path->dentry, &pntsd);
	if (pntsd_size <= 0 || !pntsd)
		goto err_out;

	if (smb_get_dacl(pntsd, pntsd_size, &pdacl) || !pdacl)
		goto err_out;

	if (!pdacl->num_aces) {
		if (le16_to_cpu(pdacl->size) == sizeof(*pdacl) &&
		    *pdaccess & ~(FILE_READ_CONTROL_LE | FILE_WRITE_DAC_LE)) {
			rc = -EACCES;
			goto err_out;
		}
		goto err_out;
	}

	if (!uid)
		sid_type = SIDUNIX_USER;
	id_to_sid(uid, sid_type, &sid);
	vfsuid = i_uid_into_vfsuid(idmap, d_inode(path->dentry));
	is_owner = uid == from_kuid(&init_user_ns, vfsuid_into_kuid(vfsuid));

	smb_acl_iter_init(&iter, pdacl);
	while ((ace = smb_acl_next_ace(&iter))) {
		bool matches_user, matches_other;

		if (!smb_ace_sid_valid(ace))
			break;

		matches_user = !compare_sids(&sid, &ace->sid) ||
			       !compare_sids(&sid_unix_NFS_mode, &ace->sid);
		matches_other = !compare_sids(&sid_everyone, &ace->sid) ||
				!compare_sids(&sid_authusers, &ace->sid);
		if (!found) {
			if (matches_user) {
				matched_ace = ace;
				found = 1;
			} else if (matches_other) {
				others_ace = ace;
			}
		}

		if (!maximal_access) {
			if (found)
				break;
			continue;
		}

		if (!compare_sids(&sid_owner_rights, &ace->sid)) {
			owner_rights = true;
			if (!is_owner)
				continue;
		} else if (!matches_user && !matches_other) {
			continue;
		}

		if (ace->flags & INHERIT_ONLY_ACE)
			continue;
		switch (ace->type) {
		case ACCESS_ALLOWED_ACE_TYPE:
			access_bits |= le32_to_cpu(ace->access_req);
			break;
		case ACCESS_DENIED_ACE_TYPE:
		case ACCESS_DENIED_CALLBACK_ACE_TYPE:
			denied |= ~access_bits & le32_to_cpu(ace->access_req);
			break;
		}
	}

	if (maximal_access) {
		if (is_owner && !owner_rights)
			access_bits |= READ_CONTROL | WRITE_DAC |
				FILE_READ_ATTRIBUTES | DELETE;
		access_bits &= ~denied;
		if ((raw_daccess & FILE_GENERIC_EXECUTE_LE) &&
		    S_ISREG(d_inode(path->dentry)->i_mode) &&
		    (access_bits & GENERIC_READ_FLAGS) == GENERIC_READ_FLAGS)
			access_bits |= FILE_EXECUTE;
		granted = requested | access_bits;
	}
	ace = matched_ace;

	if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {
		posix_acls = get_inode_acl(d_inode(path->dentry), ACL_TYPE_ACCESS);
		if (!IS_ERR_OR_NULL(posix_acls) && !found && !others_ace) {
			unsigned int id = -1;

			pa_entry = posix_acls->a_entries;
			for (i = 0; i < posix_acls->a_count; i++, pa_entry++) {
				if (pa_entry->e_tag == ACL_USER)
					id = posix_acl_uid_translate(idmap, pa_entry);
				else if (pa_entry->e_tag == ACL_GROUP)
					id = posix_acl_gid_translate(idmap, pa_entry);
				else
					continue;

				if (id == uid) {
					mode_to_access_flags(pa_entry->e_perm,
							     0777,
							     &access_bits);
					if (!access_bits)
						access_bits =
							SET_MINIMUM_RIGHTS;
					posix_acl_release(posix_acls);
					goto check_access_bits;
				}
			}
		}
		if (!IS_ERR_OR_NULL(posix_acls))
			posix_acl_release(posix_acls);
	}

	if (!found) {
		if (others_ace) {
			ace = others_ace;
		} else {
			ksmbd_debug(SMB, "Can't find corresponding sid\n");
			rc = -EACCES;
			goto err_out;
		}
	}

	if (!(*pdaccess & FILE_MAXIMAL_ACCESS_LE)) {
		switch (ace->type) {
		case ACCESS_ALLOWED_ACE_TYPE:
			access_bits = le32_to_cpu(ace->access_req);
			break;
		case ACCESS_DENIED_ACE_TYPE:
		case ACCESS_DENIED_CALLBACK_ACE_TYPE:
			access_bits = le32_to_cpu(~ace->access_req);
			break;
		}
	}

check_access_bits:
	if (strict) {
		access_bits &= granted;
	} else {
		access_bits |= FILE_READ_ATTRIBUTES | READ_CONTROL |
			WRITE_DAC | DELETE;
	}

	if (granted & ~access_bits) {
		ksmbd_debug(SMB, "Access denied with winACL, granted : %x, access_req : %x\n",
			    granted, access_bits);
		rc = -EACCES;
		goto err_out;
	}

	*pdaccess = cpu_to_le32(granted);
err_out:
	kfree(pntsd);
	return rc;
}
EXPORT_SYMBOL_IF_KUNIT(smb_check_perm_dacl);

int set_info_sec(struct ksmbd_conn *conn, struct ksmbd_tree_connect *tcon,
		 const struct path *path, struct smb_ntsd *pntsd, int ntsd_len,
		 bool type_check, bool get_write, bool posix_open,
		 bool dacl_requested)
{
	int rc;
	struct smb_fattr fattr = {{0}};
	struct inode *inode = d_inode(path->dentry);
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
	struct iattr newattrs;

	fattr.cf_uid = INVALID_UID;
	fattr.cf_gid = INVALID_GID;
	fattr.cf_mode = inode->i_mode;

	rc = parse_sec_desc(idmap, pntsd, ntsd_len, &fattr);
	if (rc)
		goto out;
	if (fattr.cf_posix_mode && !dacl_requested) {
		fattr.cf_posix_mode = false;
		fattr.cf_mode = inode->i_mode;
	}
	if (fattr.cf_posix_mode && !posix_open) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	newattrs.ia_valid = ATTR_CTIME;
	if (!uid_eq(fattr.cf_uid, INVALID_UID)) {
		newattrs.ia_valid |= ATTR_UID;
		newattrs.ia_uid = fattr.cf_uid;
	}
	if (!gid_eq(fattr.cf_gid, INVALID_GID)) {
		newattrs.ia_valid |= ATTR_GID;
		newattrs.ia_gid = fattr.cf_gid;
	}
	newattrs.ia_valid |= ATTR_MODE;
	if (fattr.cf_posix_mode)
		newattrs.ia_mode = (inode->i_mode & ~07777) |
				   (fattr.cf_mode & 07777);
	else
		newattrs.ia_mode = (inode->i_mode & ~0777) |
				   (fattr.cf_mode & 0777);

	ksmbd_vfs_remove_acl_xattrs(idmap, path);
	/* Update posix acls */
	if (IS_ENABLED(CONFIG_FS_POSIX_ACL) && fattr.cf_dacls) {
		rc = set_posix_acl(idmap, path->dentry,
				   ACL_TYPE_ACCESS, fattr.cf_acls);
		if (rc < 0)
			ksmbd_debug(SMB,
				    "Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",
				    rc);
		if (S_ISDIR(inode->i_mode) && fattr.cf_dacls) {
			rc = set_posix_acl(idmap, path->dentry,
					   ACL_TYPE_DEFAULT, fattr.cf_dacls);
			if (rc)
				ksmbd_debug(SMB,
					    "Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",
					    rc);
		}
	}

	inode_lock(inode);
	rc = notify_change(idmap, path->dentry, &newattrs, NULL);
	inode_unlock(inode);
	if (rc)
		goto out;

	/* Check it only calling from SD BUFFER context */
	if (type_check && !(le16_to_cpu(pntsd->type) & DACL_PRESENT))
		goto out;

	if (test_share_config_flag(tcon->share_conf, KSMBD_SHARE_FLAG_ACL_XATTR)) {
		/* Update WinACL in xattr */
		ksmbd_vfs_remove_sd_xattrs(idmap, path);
		ksmbd_vfs_set_sd_xattr(conn, idmap, path, pntsd, ntsd_len,
				get_write);
	}

out:
	posix_acl_release(fattr.cf_acls);
	posix_acl_release(fattr.cf_dacls);
	return rc;
}

void ksmbd_init_domain(u32 *sub_auth)
{
	int i;

	memcpy(&server_conf.domain_sid, &domain, sizeof(struct smb_sid));
	for (i = 0; i < 3; ++i)
		server_conf.domain_sid.sub_auth[i + 1] = cpu_to_le32(sub_auth[i]);
}
