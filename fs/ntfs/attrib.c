// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NTFS attribute operations.
 *
 * Copyright (c) 2001-2012 Anton Altaparmakov and Tuxera Inc.
 * Copyright (c) 2002 Richard Russon
 * Copyright (c) 2025 LG Electronics Co., Ltd.
 *
 * Part of this file is based on code from the NTFS-3G.
 * and is copyrighted by the respective authors below:
 * Copyright (c) 2000-2010 Anton Altaparmakov
 * Copyright (c) 2002-2005 Richard Russon
 * Copyright (c) 2002-2008 Szabolcs Szakacsits
 * Copyright (c) 2004-2007 Yura Pakhuchiy
 * Copyright (c) 2007-2021 Jean-Pierre Andre
 * Copyright (c) 2010 Erik Larsson
 */

#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/string_choices.h>
#include <linux/writeback.h>
#include <linux/iomap.h>

#include "attrib.h"
#include "attrlist.h"
#include "lcnalloc.h"
#include "debug.h"
#include "logfile.h"
#include "mft.h"
#include "ntfs.h"
#include "iomap.h"
#include "inode.h"

#define ntfs_attrib_kvmemdup kvmemdup

__le16 AT_UNNAMED[] = { cpu_to_le16('\0') };

/*
 * Maximum size allowed for reading attributes by ntfs_attr_readall().
 * Extended attribute, reparse point are not expected to be larger than this size.
 */

#define NTFS_ATTR_READALL_MAX_SIZE	(64 * 1024)

/*
 * ntfs_map_runlist_nolock - map (a part of) a runlist of an ntfs inode
 * @ni:		ntfs inode for which to map (part of) a runlist
 * @vcn:	map runlist part containing this vcn
 * @ctx:	active attribute search context if present or NULL if not
 *
 * Map the part of a runlist containing the @vcn of the ntfs inode @ni.
 *
 * If @ctx is specified, it is an active search context of @ni and its base mft
 * record.  This is needed when ntfs_map_runlist_nolock() encounters unmapped
 * runlist fragments and allows their mapping.  If you do not have the mft
 * record mapped, you can specify @ctx as NULL and ntfs_map_runlist_nolock()
 * will perform the necessary mapping and unmapping.
 *
 * Note, ntfs_map_runlist_nolock() saves the state of @ctx on entry and
 * restores it before returning.  Thus, @ctx will be left pointing to the same
 * attribute on return as on entry.  However, the actual pointers in @ctx may
 * point to different memory locations on return, so you must remember to reset
 * any cached pointers from the @ctx, i.e. after the call to
 * ntfs_map_runlist_nolock(), you will probably want to do:
 *	m = ctx->mrec;
 *	a = ctx->attr;
 * Assuming you cache ctx->attr in a variable @a of type struct attr_record *
 * and that you cache ctx->mrec in a variable @m of type struct mft_record *.
 *
 * Return 0 on success and -errno on error.  There is one special error code
 * which is not an error as such.  This is -ENOENT.  It means that @vcn is out
 * of bounds of the runlist.
 *
 * Note the runlist can be NULL after this function returns if @vcn is zero and
 * the attribute has zero allocated size, i.e. there simply is no runlist.
 *
 * WARNING: If @ctx is supplied, regardless of whether success or failure is
 *	    returned, you need to check IS_ERR(@ctx->mrec) and if 'true' the @ctx
 *	    is no longer valid, i.e. you need to either call
 *	    ntfs_attr_reinit_search_ctx() or ntfs_attr_put_search_ctx() on it.
 *	    In that case PTR_ERR(@ctx->mrec) will give you the error code for
 *	    why the mapping of the old inode failed.
 *
 * Locking: - The runlist described by @ni must be locked for writing on entry
 *	      and is locked on return.  Note the runlist will be modified.
 *	    - If @ctx is NULL, the base mft record of @ni must not be mapped on
 *	      entry and it will be left unmapped on return.
 *	    - If @ctx is not NULL, the base mft record must be mapped on entry
 *	      and it will be left mapped on return.
 */
int ntfs_map_runlist_nolock(struct ntfs_inode *ni, s64 vcn, struct ntfs_attr_search_ctx *ctx)
{
	s64 end_vcn;
	unsigned long flags;
	struct ntfs_inode *base_ni;
	struct mft_record *m;
	struct attr_record *a;
	struct runlist_element *rl;
	struct folio *put_this_folio = NULL;
	int err = 0;
	bool ctx_is_temporary = false, ctx_needs_reset = false;
	struct ntfs_attr_search_ctx old_ctx = { NULL, };
	size_t new_rl_count;

	ntfs_debug("Mapping runlist part containing vcn 0x%llx.",
			(unsigned long long)vcn);
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	/*
	 * ntfs_read_inode_mount() builds $MFT's runlist itself, so nothing
	 * should reach here for $MFT.  A crafted image can: the read that
	 * gets here already holds the $MFT folio lock it would wait on.
	 */
	if (unlikely(NVolMftBootstrap(ni->vol) &&
		     base_ni == NTFS_I(ni->vol->mft_ino))) {
		ntfs_error(ni->vol->sb,
			   "$MFT needs its own extent records to describe itself; cannot mount.");
		return -EIO;
	}
	if (!ctx) {
		ctx_is_temporary = ctx_needs_reset = true;
		m = map_mft_record(base_ni);
		if (IS_ERR(m))
			return PTR_ERR(m);
		ctx = ntfs_attr_get_search_ctx(base_ni, m);
		if (unlikely(!ctx)) {
			err = -ENOMEM;
			goto err_out;
		}
	} else {
		s64 allocated_size_vcn;

		WARN_ON(IS_ERR(ctx->mrec));
		a = ctx->attr;
		if (!a->non_resident) {
			err = -EIO;
			goto err_out;
		}
		end_vcn = le64_to_cpu(a->data.non_resident.highest_vcn);
		read_lock_irqsave(&ni->size_lock, flags);
		allocated_size_vcn =
			ntfs_bytes_to_cluster(ni->vol, ni->allocated_size);
		read_unlock_irqrestore(&ni->size_lock, flags);
		if (!a->data.non_resident.lowest_vcn && end_vcn <= 0)
			end_vcn = allocated_size_vcn - 1;
		/*
		 * If we already have the attribute extent containing @vcn in
		 * @ctx, no need to look it up again.  We slightly cheat in
		 * that if vcn exceeds the allocated size, we will refuse to
		 * map the runlist below, so there is definitely no need to get
		 * the right attribute extent.
		 */
		if (vcn >= allocated_size_vcn || (a->type == ni->type &&
				a->name_length == ni->name_len &&
				!memcmp((u8 *)a + le16_to_cpu(a->name_offset),
				ni->name, ni->name_len) &&
				le64_to_cpu(a->data.non_resident.lowest_vcn)
				<= vcn && end_vcn >= vcn))
			ctx_needs_reset = false;
		else {
			/* Save the old search context. */
			old_ctx = *ctx;
			/*
			 * If the currently mapped (extent) inode is not the
			 * base inode we will unmap it when we reinitialize the
			 * search context which means we need to get a
			 * reference to the page containing the mapped mft
			 * record so we do not accidentally drop changes to the
			 * mft record when it has not been marked dirty yet.
			 */
			if (old_ctx.base_ntfs_ino && old_ctx.ntfs_ino !=
					old_ctx.base_ntfs_ino) {
				put_this_folio = old_ctx.ntfs_ino->folio;
				folio_get(put_this_folio);
			}
			/*
			 * Reinitialize the search context so we can lookup the
			 * needed attribute extent.
			 */
			ntfs_attr_reinit_search_ctx(ctx);
			ctx_needs_reset = true;
		}
	}
	if (ctx_needs_reset) {
		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, vcn, NULL, 0, ctx);
		if (unlikely(err)) {
			if (err == -ENOENT)
				err = -EIO;
			goto err_out;
		}
		if (unlikely(!ctx->attr->non_resident)) {
			err = -EIO;
			goto err_out;
		}
	}
	a = ctx->attr;
	/*
	 * Only decompress the mapping pairs if @vcn is inside it.  Otherwise
	 * we get into problems when we try to map an out of bounds vcn because
	 * we then try to map the already mapped runlist fragment and
	 * ntfs_mapping_pairs_decompress() fails.
	 */
	end_vcn = le64_to_cpu(a->data.non_resident.highest_vcn) + 1;
	if (unlikely(vcn && vcn >= end_vcn)) {
		err = -ENOENT;
		goto err_out;
	}
	rl = ntfs_mapping_pairs_decompress(ni->vol, a, &ni->runlist, &new_rl_count);
	if (IS_ERR(rl))
		err = PTR_ERR(rl);
	else {
		ni->runlist.rl = rl;
		ni->runlist.count = new_rl_count;
	}
err_out:
	if (ctx_is_temporary) {
		if (likely(ctx))
			ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(base_ni);
	} else if (ctx_needs_reset) {
		/*
		 * If there is no attribute list, restoring the search context
		 * is accomplished simply by copying the saved context back over
		 * the caller supplied context.  If there is an attribute list,
		 * things are more complicated as we need to deal with mapping
		 * of mft records and resulting potential changes in pointers.
		 */
		if (NInoAttrList(base_ni)) {
			/*
			 * If the currently mapped (extent) inode is not the
			 * one we had before, we need to unmap it and map the
			 * old one.
			 */
			if (ctx->ntfs_ino != old_ctx.ntfs_ino) {
				/*
				 * If the currently mapped inode is not the
				 * base inode, unmap it.
				 */
				if (ctx->base_ntfs_ino && ctx->ntfs_ino !=
						ctx->base_ntfs_ino) {
					unmap_extent_mft_record(ctx->ntfs_ino);
					ctx->mrec = ctx->base_mrec;
					WARN_ON(!ctx->mrec);
				}
				/*
				 * If the old mapped inode is not the base
				 * inode, map it.
				 */
				if (old_ctx.base_ntfs_ino &&
				    old_ctx.ntfs_ino !=	old_ctx.base_ntfs_ino) {
retry_map:
					ctx->mrec = map_mft_record(old_ctx.ntfs_ino);
					/*
					 * Something bad has happened.  If out
					 * of memory retry till it succeeds.
					 * Any other errors are fatal and we
					 * return the error code in ctx->mrec.
					 * Let the caller deal with it...  We
					 * just need to fudge things so the
					 * caller can reinit and/or put the
					 * search context safely.
					 */
					if (IS_ERR(ctx->mrec)) {
						if (PTR_ERR(ctx->mrec) == -ENOMEM) {
							schedule();
							goto retry_map;
						} else
							old_ctx.ntfs_ino =
								old_ctx.base_ntfs_ino;
					}
				}
			}
			/* Update the changed pointers in the saved context. */
			if (ctx->mrec != old_ctx.mrec) {
				if (!IS_ERR(ctx->mrec))
					old_ctx.attr = (struct attr_record *)(
							(u8 *)ctx->mrec +
							((u8 *)old_ctx.attr -
							(u8 *)old_ctx.mrec));
				old_ctx.mrec = ctx->mrec;
			}
		}
		/* Restore the search context to the saved one. */
		*ctx = old_ctx;
		/*
		 * We drop the reference on the page we took earlier.  In the
		 * case that IS_ERR(ctx->mrec) is true this means we might lose
		 * some changes to the mft record that had been made between
		 * the last time it was marked dirty/written out and now.  This
		 * at this stage is not a problem as the mapping error is fatal
		 * enough that the mft record cannot be written out anyway and
		 * the caller is very likely to shutdown the whole inode
		 * immediately and mark the volume dirty for chkdsk to pick up
		 * the pieces anyway.
		 */
		if (put_this_folio)
			folio_put(put_this_folio);
	}
	return err;
}

/*
 * ntfs_map_runlist - map (a part of) a runlist of an ntfs inode
 * @ni:		ntfs inode for which to map (part of) a runlist
 * @vcn:	map runlist part containing this vcn
 *
 * Map the part of a runlist containing the @vcn of the ntfs inode @ni.
 *
 * Return 0 on success and -errno on error.  There is one special error code
 * which is not an error as such.  This is -ENOENT.  It means that @vcn is out
 * of bounds of the runlist.
 *
 * Locking: - The runlist must be unlocked on entry and is unlocked on return.
 *	    - This function takes the runlist lock for writing and may modify
 *	      the runlist.
 */
int ntfs_map_runlist(struct ntfs_inode *ni, s64 vcn)
{
	int err = 0;

	down_write(&ni->runlist.lock);
	/* Make sure someone else didn't do the work while we were sleeping. */
	if (likely(ntfs_rl_vcn_to_lcn(ni->runlist.rl, vcn) <=
			LCN_RL_NOT_MAPPED))
		err = ntfs_map_runlist_nolock(ni, vcn, NULL);
	up_write(&ni->runlist.lock);
	return err;
}

struct runlist_element *ntfs_attr_vcn_to_rl(struct ntfs_inode *ni, s64 vcn, s64 *lcn)
{
	struct runlist_element *rl = ni->runlist.rl;
	int err = 0;
	bool is_retry = false;

	if (!rl) {
		err = ntfs_attr_map_whole_runlist(ni);
		if (err)
			return ERR_PTR(-ENOENT);
		rl = ni->runlist.rl;
	}

remap_rl:
	/* Seek to element containing target vcn. */
	while (rl->length && rl[1].vcn <= vcn)
		rl++;
	*lcn = ntfs_rl_vcn_to_lcn(rl, vcn);

	if (*lcn <= LCN_RL_NOT_MAPPED && is_retry == false) {
		is_retry = true;
		err = ntfs_map_runlist_nolock(ni, vcn, NULL);
		if (!err) {
			rl = ni->runlist.rl;
			goto remap_rl;
		}
	}

	/*
	 * Neither the runlist nor the retry mapped @vcn, e.g. because the
	 * extent mft record holding it is corrupt or because the mapping
	 * pairs end too soon.  ntfs_map_runlist_nolock() reports the latter
	 * as -ENOENT, as @vcn lies past the extent it found.  Below the
	 * allocated size, callers would treat LCN_RL_NOT_MAPPED or LCN_ENOENT
	 * as a hole, so fail instead.  At or beyond it nothing is mapped: the
	 * runlist ends there with LCN_ENOENT, or with LCN_RL_NOT_MAPPED if
	 * only a later extent has been mapped, so return that end as it is.
	 */
	if (*lcn <= LCN_RL_NOT_MAPPED) {
		unsigned long flags;
		s64 allocated_size;

		read_lock_irqsave(&ni->size_lock, flags);
		allocated_size = ni->allocated_size;
		read_unlock_irqrestore(&ni->size_lock, flags);
		if ((s64)ntfs_cluster_to_bytes(ni->vol, vcn) < allocated_size)
			return ERR_PTR(err == -ENOMEM ? -ENOMEM : -EIO);
	}

	return rl;
}

/*
 * ntfs_attr_vcn_to_lcn_nolock - convert a vcn into a lcn given an ntfs inode
 * @ni:			ntfs inode of the attribute whose runlist to search
 * @vcn:		vcn to convert
 * @write_locked:	true if the runlist is locked for writing
 *
 * Find the virtual cluster number @vcn in the runlist of the ntfs attribute
 * described by the ntfs inode @ni and return the corresponding logical cluster
 * number (lcn).
 *
 * If the @vcn is not mapped yet, the attempt is made to map the attribute
 * extent containing the @vcn and the vcn to lcn conversion is retried.
 *
 * If @write_locked is true the caller has locked the runlist for writing and
 * if false for reading.
 *
 * Since lcns must be >= 0, we use negative return codes with special meaning:
 *
 * Return code	Meaning / Description
 * ==========================================
 *  LCN_HOLE	Hole / not allocated on disk.
 *  LCN_ENOENT	There is no such vcn in the runlist, i.e. @vcn is out of bounds.
 *  LCN_ENOMEM	Not enough memory to map runlist.
 *  LCN_EIO	Critical error (runlist/file is corrupt, i/o error, etc).
 *
 * Locking: - The runlist must be locked on entry and is left locked on return.
 *	    - If @write_locked is 'false', i.e. the runlist is locked for reading,
 *	      the lock may be dropped inside the function so you cannot rely on
 *	      the runlist still being the same when this function returns.
 */
s64 ntfs_attr_vcn_to_lcn_nolock(struct ntfs_inode *ni, const s64 vcn,
		const bool write_locked)
{
	s64 lcn;
	unsigned long flags;
	bool is_retry = false;

	ntfs_debug("Entering for i_ino 0x%llx, vcn 0x%llx, %s_locked.",
			ni->mft_no, (unsigned long long)vcn,
			write_locked ? "write" : "read");
	if (!ni->runlist.rl) {
		read_lock_irqsave(&ni->size_lock, flags);
		if (!ni->allocated_size) {
			read_unlock_irqrestore(&ni->size_lock, flags);
			return LCN_ENOENT;
		}
		read_unlock_irqrestore(&ni->size_lock, flags);
	}
retry_remap:
	/* Convert vcn to lcn.  If that fails map the runlist and retry once. */
	lcn = ntfs_rl_vcn_to_lcn(ni->runlist.rl, vcn);
	if (likely(lcn >= LCN_HOLE)) {
		ntfs_debug("Done, lcn 0x%llx.", (long long)lcn);
		return lcn;
	}
	if (lcn != LCN_RL_NOT_MAPPED) {
		if (lcn != LCN_ENOENT)
			lcn = LCN_EIO;
	} else if (!is_retry) {
		int err;

		if (!write_locked) {
			up_read(&ni->runlist.lock);
			down_write(&ni->runlist.lock);
			if (unlikely(ntfs_rl_vcn_to_lcn(ni->runlist.rl, vcn) !=
					LCN_RL_NOT_MAPPED)) {
				up_write(&ni->runlist.lock);
				down_read(&ni->runlist.lock);
				goto retry_remap;
			}
		}
		err = ntfs_map_runlist_nolock(ni, vcn, NULL);
		if (!write_locked) {
			up_write(&ni->runlist.lock);
			down_read(&ni->runlist.lock);
		}
		if (likely(!err)) {
			is_retry = true;
			goto retry_remap;
		}
		if (err == -ENOENT)
			lcn = LCN_ENOENT;
		else if (err == -ENOMEM)
			lcn = LCN_ENOMEM;
		else
			lcn = LCN_EIO;
	}
	if (lcn != LCN_ENOENT)
		ntfs_error(ni->vol->sb, "Failed with error code %lli.",
				(long long)lcn);
	return lcn;
}

struct runlist_element *__ntfs_attr_find_vcn_nolock(struct runlist *runlist, const s64 vcn)
{
	size_t lower_idx, upper_idx, idx;
	struct runlist_element *run;
	int rh = runlist->rl_hint;

	if (runlist->count <= 1)
		return ERR_PTR(-ENOENT);

	if (runlist->count - 1 > rh && runlist->rl[rh].vcn <= vcn) {
		if (vcn < runlist->rl[rh].vcn + runlist->rl[rh].length)
			return &runlist->rl[rh];
		if (runlist->count - 2 == rh)
			return ERR_PTR(-ENOENT);

		lower_idx = rh + 1;
	} else {
		run = &runlist->rl[0];
		if (vcn < run->vcn)
			return ERR_PTR(-ENOENT);
		else if (vcn < run->vcn + run->length) {
			runlist->rl_hint = 0;
			return run;
		}

		lower_idx = 1;
	}

	run = &runlist->rl[runlist->count - 2];
	if (vcn >= run->vcn && vcn < run->vcn + run->length) {
		runlist->rl_hint = runlist->count - 2;
		return run;
	}
	if (vcn >= run->vcn + run->length)
		return ERR_PTR(-ENOENT);

	upper_idx = runlist->count - 2;

	while (lower_idx <= upper_idx) {
		idx = (lower_idx + upper_idx) >> 1;
		run = &runlist->rl[idx];

		if (vcn < run->vcn)
			upper_idx = idx - 1;
		else if (vcn >= run->vcn + run->length)
			lower_idx = idx + 1;
		else {
			runlist->rl_hint = idx;
			return run;
		}
	}

	return ERR_PTR(-ENOENT);
}

/*
 * ntfs_attr_find_vcn_nolock - find a vcn in the runlist of an ntfs inode
 * @ni:		ntfs inode describing the runlist to search
 * @vcn:	vcn to find
 * @ctx:	active attribute search context if present or NULL if not
 *
 * Find the virtual cluster number @vcn in the runlist described by the ntfs
 * inode @ni and return the address of the runlist element containing the @vcn.
 *
 * If the @vcn is not mapped yet, the attempt is made to map the attribute
 * extent containing the @vcn and the vcn to lcn conversion is retried.
 *
 * If @ctx is specified, it is an active search context of @ni and its base mft
 * record.  This is needed when ntfs_attr_find_vcn_nolock() encounters unmapped
 * runlist fragments and allows their mapping.  If you do not have the mft
 * record mapped, you can specify @ctx as NULL and ntfs_attr_find_vcn_nolock()
 * will perform the necessary mapping and unmapping.
 *
 * Note, ntfs_attr_find_vcn_nolock() saves the state of @ctx on entry and
 * restores it before returning.  Thus, @ctx will be left pointing to the same
 * attribute on return as on entry.  However, the actual pointers in @ctx may
 * point to different memory locations on return, so you must remember to reset
 * any cached pointers from the @ctx, i.e. after the call to
 * ntfs_attr_find_vcn_nolock(), you will probably want to do:
 *	m = ctx->mrec;
 *	a = ctx->attr;
 * Assuming you cache ctx->attr in a variable @a of type attr_record * and that
 * you cache ctx->mrec in a variable @m of type struct mft_record *.
 * Note you need to distinguish between the lcn of the returned runlist element
 * being >= 0 and LCN_HOLE.  In the later case you have to return zeroes on
 * read and allocate clusters on write.
 */
struct runlist_element *ntfs_attr_find_vcn_nolock(struct ntfs_inode *ni, const s64 vcn,
		struct ntfs_attr_search_ctx *ctx)
{
	unsigned long flags;
	struct runlist_element *rl;
	int err = 0;
	bool is_retry = false;

	ntfs_debug("Entering for i_ino 0x%llx, vcn 0x%llx, with%s ctx.",
			ni->mft_no, (unsigned long long)vcn, ctx ? "" : "out");
	if (!ni->runlist.rl) {
		read_lock_irqsave(&ni->size_lock, flags);
		if (!ni->allocated_size) {
			read_unlock_irqrestore(&ni->size_lock, flags);
			return ERR_PTR(-ENOENT);
		}
		read_unlock_irqrestore(&ni->size_lock, flags);
	}

retry_remap:
	rl = ni->runlist.rl;
	if (likely(rl && vcn >= rl[0].vcn)) {
		rl = __ntfs_attr_find_vcn_nolock(&ni->runlist, vcn);
		if (IS_ERR(rl))
			err = PTR_ERR(rl);
		else if (rl->lcn >= LCN_HOLE)
			return rl;
		else if (rl->lcn <= LCN_ENOENT)
			err = -EIO;
	}
	if (!err && !is_retry) {
		/*
		 * If the search context is invalid we cannot map the unmapped
		 * region.
		 */
		if (ctx && IS_ERR(ctx->mrec))
			err = PTR_ERR(ctx->mrec);
		else {
			/*
			 * The @vcn is in an unmapped region, map the runlist
			 * and retry.
			 */
			err = ntfs_map_runlist_nolock(ni, vcn, ctx);
			if (likely(!err)) {
				is_retry = true;
				goto retry_remap;
			}
		}
		if (err == -EINVAL)
			err = -EIO;
	} else if (!err)
		err = -EIO;
	if (err != -ENOENT)
		ntfs_error(ni->vol->sb, "Failed with error code %i.", err);
	return ERR_PTR(err);
}

static u32 ntfs_resident_attr_min_value_length(const __le32 type)
{
	switch (type) {
	case AT_STANDARD_INFORMATION:
		return offsetof(struct standard_information, ver) +
		       sizeof(((struct standard_information *)0)->ver.v1.reserved12);
	case AT_FILE_NAME:
		return offsetof(struct file_name_attr, file_name) +
			sizeof(__le16) * 1;
	case AT_VOLUME_INFORMATION:
		return sizeof(struct volume_information);
	case AT_INDEX_ROOT:
		return sizeof(struct index_root);
	case AT_EA_INFORMATION:
		return sizeof(struct ea_information);
	default:
		return 0;
	}
}

static bool ntfs_attr_type_is_resident_only(const __le32 type)
{
	switch (type) {
	case AT_STANDARD_INFORMATION:
	case AT_FILE_NAME:
	case AT_OBJECT_ID:
	case AT_VOLUME_NAME:
	case AT_VOLUME_INFORMATION:
	case AT_INDEX_ROOT:
	case AT_EA_INFORMATION:
		return true;
	default:
		return false;
	}
}

static bool ntfs_file_name_attr_value_is_valid(const u8 *value, const u32 value_length)
{
	const struct file_name_attr *fn;
	u32 file_name_size;

	fn = (const struct file_name_attr *)value;
	file_name_size = fn->file_name_length * sizeof(__le16);

	return file_name_size <=
			value_length - offsetof(struct file_name_attr, file_name);
}

static bool ntfs_volume_name_attr_value_is_valid(const u32 value_length)
{
	if (value_length & 1)
		return false;

	return value_length <= NTFS_MAX_LABEL_LEN * sizeof(__le16);
}

static bool ntfs_index_root_attr_value_is_valid(const u8 *value, const u32 value_length)
{
	const struct index_root *ir;
	u32 index_size;
	u32 entries_offset;
	u32 index_length;
	u32 allocated_size;

	ir = (const struct index_root *)value;
	index_size = value_length - offsetof(struct index_root, index);
	entries_offset = le32_to_cpu(ir->index.entries_offset);
	index_length = le32_to_cpu(ir->index.index_length);
	allocated_size = le32_to_cpu(ir->index.allocated_size);

	if ((entries_offset | index_length | allocated_size) & 7 ||
	    entries_offset < sizeof(struct index_header) ||
	    entries_offset > index_length ||
	    index_length > allocated_size ||
	    allocated_size > index_size ||
	    index_length - entries_offset < sizeof(struct index_entry_header))
		return false;

	return true;
}

struct ntfs_resident_attr_value {
	const u8 *data;
	u32 len;
};

static bool ntfs_resident_attr_value_get(const struct attr_record *a,
					 struct ntfs_resident_attr_value *value)
{
	u32 attr_len;
	u32 min_len;
	u16 value_offset;

	attr_len = le32_to_cpu(a->length);
	min_len = offsetof(struct attr_record, data.resident.reserved) +
		  sizeof(a->data.resident.reserved);
	if (attr_len < min_len)
		return false;

	value->len = le32_to_cpu(a->data.resident.value_length);
	value_offset = le16_to_cpu(a->data.resident.value_offset);

	if (value_offset < min_len || value->len > attr_len ||
	    value_offset > attr_len - value->len)
		return false;

	value->data = (const u8 *)a + value_offset;
	return true;
}

static bool ntfs_non_resident_attr_value_is_valid(const struct attr_record *a)
{
	u32 attr_len;
	u32 min_len;
	u16 mp_offset;
	u16 name_offset;
	u32 name_end;

	attr_len = le32_to_cpu(a->length);
	min_len = offsetof(struct attr_record, data.non_resident.initialized_size) +
		  sizeof(a->data.non_resident.initialized_size);

	/*
	 * Only the first extent of sparse and compressed attributes has the
	 * extra compressed_size field.
	 */
	if ((a->flags & (ATTR_IS_SPARSE | ATTR_COMPRESSION_MASK)) &&
	    !a->data.non_resident.lowest_vcn)
		min_len += sizeof(a->data.non_resident.compressed_size);

	if (attr_len < min_len)
		return false;

	mp_offset = le16_to_cpu(a->data.non_resident.mapping_pairs_offset);
	if (mp_offset < min_len || mp_offset > attr_len)
		return false;

	if (a->name_length) {
		name_offset = le16_to_cpu(a->name_offset);

		if (name_offset < min_len || name_offset >= attr_len)
			return false;

		name_end = name_offset + a->name_length * sizeof(__le16);
		if (name_end > attr_len || name_end > mp_offset)
			return false;
	}

	/* Ensure there's room for the compressed_size field if needed. */
	if (!(a->flags & (ATTR_IS_SPARSE | ATTR_COMPRESSION_MASK)) &&
	    attr_len - mp_offset <
			sizeof(a->data.non_resident.compressed_size))
		return false;

	return true;
}

static bool ntfs_attr_value_is_valid(struct ntfs_volume *vol,
				     const struct attr_record *a,
				     const u64 mft_no)
{
	struct ntfs_resident_attr_value value;
	u32 min_len;

	if (a->non_resident) {
		if (ntfs_attr_type_is_resident_only(a->type))
			goto corrupt;
		if (!ntfs_non_resident_attr_value_is_valid(a))
			goto corrupt;
		return true;
	}

	if (!ntfs_resident_attr_value_get(a, &value))
		goto corrupt;

	min_len = ntfs_resident_attr_min_value_length(a->type);
	if (min_len && value.len < min_len)
		goto corrupt;

	switch (a->type) {
	case AT_FILE_NAME:
		if (!ntfs_file_name_attr_value_is_valid(value.data, value.len))
			goto corrupt;
		break;
	case AT_VOLUME_NAME:
		if (!ntfs_volume_name_attr_value_is_valid(value.len))
			goto corrupt;
		break;
	case AT_INDEX_ROOT:
		if (!ntfs_index_root_attr_value_is_valid(value.data, value.len))
			goto corrupt;
		break;
	}
	return true;

corrupt:
	ntfs_error(vol->sb,
		   "Corrupt %#x attribute in MFT record %llu\n",
		   le32_to_cpu(a->type), mft_no);
	return false;
}

/*
 * ntfs_attr_find - find (next) attribute in mft record
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * You should not need to call this function directly.  Use ntfs_attr_lookup()
 * instead.
 *
 * ntfs_attr_find() takes a search context @ctx as parameter and searches the
 * mft record specified by @ctx->mrec, beginning at @ctx->attr, for an
 * attribute of @type, optionally @name and @val.
 *
 * If the attribute is found, ntfs_attr_find() returns 0 and @ctx->attr will
 * point to the found attribute.
 *
 * If the attribute is not found, ntfs_attr_find() returns -ENOENT and
 * @ctx->attr will point to the attribute before which the attribute being
 * searched for would need to be inserted if such an action were to be desired.
 *
 * On actual error, ntfs_attr_find() returns -EIO.  In this case @ctx->attr is
 * undefined and in particular do not rely on it not changing.
 *
 * If @ctx->is_first is 'true', the search begins with @ctx->attr itself.  If it
 * is 'false', the search begins after @ctx->attr.
 *
 * If @ic is IGNORE_CASE, the @name comparisson is not case sensitive and
 * @ctx->ntfs_ino must be set to the ntfs inode to which the mft record
 * @ctx->mrec belongs.  This is so we can get at the ntfs volume and hence at
 * the upcase table.  If @ic is CASE_SENSITIVE, the comparison is case
 * sensitive.  When @name is present, @name_len is the @name length in Unicode
 * characters.
 *
 * If @name is not present (NULL), we assume that the unnamed attribute is
 * being searched for.
 *
 * Finally, the resident attribute value @val is looked for, if present.  If
 * @val is not present (NULL), @val_len is ignored.
 *
 * ntfs_attr_find() only searches the specified mft record and it ignores the
 * presence of an attribute list attribute (unless it is the one being searched
 * for, obviously).  If you need to take attribute lists into consideration,
 * use ntfs_attr_lookup() instead (see below).  This also means that you cannot
 * use ntfs_attr_find() to search for extent records of non-resident
 * attributes, as extents with lowest_vcn != 0 are usually described by the
 * attribute list attribute only. - Note that it is possible that the first
 * extent is only in the attribute list while the last extent is in the base
 * mft record, so do not rely on being able to find the first extent in the
 * base mft record.
 *
 * Warning: Never use @val when looking for attribute types which can be
 *	    non-resident as this most likely will result in a crash!
 */
static int ntfs_attr_find(const __le32 type, const __le16 *name,
		const u32 name_len, const u32 ic,
		const u8 *val, const u32 val_len, struct ntfs_attr_search_ctx *ctx)
{
	struct attr_record *a;
	struct ntfs_volume *vol = ctx->ntfs_ino->vol;
	__le16 *upcase = vol->upcase;
	u32 upcase_len = vol->upcase_len;
	unsigned int space;
	u16 name_offset;
	u32 attr_len;
	u32 name_size;

	/*
	 * Iterate over attributes in mft record starting at @ctx->attr, or the
	 * attribute following that, if @ctx->is_first is 'true'.
	 */
	if (ctx->is_first) {
		a = ctx->attr;
		ctx->is_first = false;
	} else
		a = (struct attr_record *)((u8 *)ctx->attr +
				le32_to_cpu(ctx->attr->length));
	for (;;	a = (struct attr_record *)((u8 *)a + le32_to_cpu(a->length))) {
		if ((u8 *)a < (u8 *)ctx->mrec || (u8 *)a > (u8 *)ctx->mrec +
				le32_to_cpu(ctx->mrec->bytes_allocated))
			break;

		space = le32_to_cpu(ctx->mrec->bytes_in_use) - ((u8 *)a - (u8 *)ctx->mrec);
		if ((space < offsetof(struct attr_record, data.resident.reserved) + 1 ||
		      space < le32_to_cpu(a->length)) && (space < 4 || a->type != AT_END))
			break;

		ctx->attr = a;
		if (((type != AT_UNUSED) && (le32_to_cpu(a->type) > le32_to_cpu(type))) ||
				a->type == AT_END)
			return -ENOENT;
		if (unlikely(!a->length))
			break;
		if (a->name_length) {
			name_offset = le16_to_cpu(a->name_offset);
			attr_len = le32_to_cpu(a->length);
			name_size = a->name_length * sizeof(__le16);

			if (name_offset > attr_len ||
			    attr_len - name_offset < name_size) {
				ntfs_error(vol->sb,
					   "Corrupt attribute name in MFT record %llu\n",
					   ctx->ntfs_ino->mft_no);
				break;
			}
		}

		if (type == AT_UNUSED) {
			if (!ntfs_attr_value_is_valid(vol, a, ctx->ntfs_ino->mft_no))
				break;
			return 0;
		}
		if (a->type != type)
			continue;
		/*
		 * If @name is present, compare the two names.  If @name is
		 * missing, assume we want an unnamed attribute.
		 */
		if (!name || name == AT_UNNAMED) {
			/* The search failed if the found attribute is named. */
			if (a->name_length)
				return -ENOENT;
		} else {
			if (!ntfs_are_names_equal(name, name_len,
					(__le16 *)((u8 *)a + le16_to_cpu(a->name_offset)),
					a->name_length, ic, upcase, upcase_len)) {
				register int rc;

				rc = ntfs_collate_names(name, name_len,
						(__le16 *)((u8 *)a + le16_to_cpu(a->name_offset)),
						a->name_length, true, IGNORE_CASE,
						upcase, upcase_len);
				/*
				 * If @name collates before a->name, there is no
				 * matching attribute.
				 */
				if (rc == -1)
					return -ENOENT;
				/* If the strings are not equal, continue search. */
				if (rc)
					continue;
				rc = ntfs_collate_names(name, name_len,
						(__le16 *)((u8 *)a + le16_to_cpu(a->name_offset)),
						a->name_length, true, CASE_SENSITIVE,
						upcase, upcase_len);
				if (rc == -1)
					return -ENOENT;
				if (rc)
					continue;
			}
		}

		if (!ntfs_attr_value_is_valid(vol, a, ctx->ntfs_ino->mft_no))
			break;

		/*
		 * The names match or @name not present and attribute is
		 * unnamed.  If no @val specified, we have found the attribute
		 * and are done.
		 */
		if (!val || a->non_resident)
			return 0;
		/* @val is present; compare values. */
		else {
			u32 value_length = le32_to_cpu(a->data.resident.value_length);
			int rc;

			rc = memcmp(val, (u8 *)a + le16_to_cpu(
					a->data.resident.value_offset),
					min_t(u32, val_len, value_length));
			/*
			 * If @val collates before the current attribute's
			 * value, there is no matching attribute.
			 */
			if (!rc) {
				if (val_len == value_length)
					return 0;
				if (val_len < value_length)
					return -ENOENT;
			} else if (rc < 0)
				return -ENOENT;
		}
	}
	ntfs_error(vol->sb, "mft %#llx, type %#x is corrupt. Run chkdsk.",
		   (long long)ctx->ntfs_ino->mft_no, le32_to_cpu(type));
	NVolSetErrors(vol);
	return -EIO;
}

int ntfs_attrs_walk_mft_record(struct ntfs_attr_search_ctx *ctx)
{
	return ntfs_attr_find(AT_UNUSED, NULL, 0, 0, NULL, 0, ctx);
}

void ntfs_attr_name_free(unsigned char **name)
{
	if (*name) {
		kfree(*name);
		*name = NULL;
	}
}

char *ntfs_attr_name_get(const struct ntfs_volume *vol, const __le16 *uname,
		const int uname_len)
{
	unsigned char *name = NULL;
	int name_len;

	name_len = ntfs_ucstonls(vol, uname, uname_len, &name, 0);
	if (name_len < 0) {
		ntfs_error(vol->sb, "ntfs_ucstonls error");
		/* This function when returns -1, memory for name might
		 * be allocated. So lets free this memory.
		 */
		ntfs_attr_name_free(&name);
		return NULL;

	} else if (name_len > 0)
		return name;

	ntfs_attr_name_free(&name);
	return NULL;
}

/*
 * ntfs_attr_list_entry_is_valid - sanity check one $ATTRIBUTE_LIST entry
 * @ale:	the attribute-list entry to check
 * @al_end:	end of the attribute-list buffer @ale lives in
 *
 * Verify that @ale is a well-formed attr_list_entry wholly contained in
 * [.., @al_end): its fixed header must lie in range before any field is
 * dereferenced, its length must be a multiple of 8 that covers the fixed
 * header plus the name, the name must lie within the buffer, the entry must
 * be in use and carry a live MFT reference.  Return true if valid.
 */
bool ntfs_attr_list_entry_is_valid(const struct attr_list_entry *ale,
				   const u8 *al_end)
{
	const u8 *al = (const u8 *)ale;
	u16 ale_len;

	/* The fixed header must be in bounds before it is parsed. */
	if (al + offsetof(struct attr_list_entry, name) > al_end)
		return false;
	ale_len = le16_to_cpu(ale->length);
	/* On-disk entries are 8-byte aligned (see struct attr_list_entry). */
	if (ale_len & 7)
		return false;
	if (ale->name_offset != sizeof(struct attr_list_entry))
		return false;
	if ((u32)ale->name_offset +
	    (u32)ale->name_length * sizeof(__le16) > ale_len ||
	    al + ale_len > al_end)
		return false;
	if (ale->type == AT_UNUSED)
		return false;
	if (MSEQNO_LE(ale->mft_reference) == 0)
		return false;
	return true;
}

/*
 * ntfs_attr_list_is_valid - sanity check an in-memory $ATTRIBUTE_LIST
 * @al_start:	start of the attribute list buffer
 * @size:	length of the attribute list in bytes
 *
 * Verify that [@al_start, @al_start + @size) is a sequence of valid
 * attr_list_entry records (see ntfs_attr_list_entry_is_valid()) that tile the
 * buffer exactly.  Return true if valid, false otherwise.
 */
bool ntfs_attr_list_is_valid(const u8 *al_start, s64 size)
{
	const u8 *al = al_start;
	const u8 *al_end = al_start + size;

	while (al < al_end) {
		const struct attr_list_entry *ale =
				(const struct attr_list_entry *)al;

		if (!ntfs_attr_list_entry_is_valid(ale, al_end))
			return false;
		al += le16_to_cpu(ale->length);
	}
	return al == al_end;
}

int load_attribute_list(struct ntfs_inode *base_ni, u8 *al_start, const s64 size)
{
	struct inode *attr_vi = NULL;

	if (!al_start || size <= 0)
		return -EINVAL;

	attr_vi = ntfs_attr_iget(VFS_I(base_ni), AT_ATTRIBUTE_LIST, AT_UNNAMED, 0);
	if (IS_ERR(attr_vi)) {
		ntfs_error(base_ni->vol->sb,
			   "Failed to open an inode for Attribute list, mft = %llu",
			   base_ni->mft_no);
		return PTR_ERR(attr_vi);
	}

	if (ntfs_inode_attr_pread(attr_vi, 0, size, al_start) != size) {
		iput(attr_vi);
		ntfs_error(base_ni->vol->sb,
			   "Failed to read attribute list, mft = %llu",
			   base_ni->mft_no);
		return -EIO;
	}
	iput(attr_vi);

	if (!ntfs_attr_list_is_valid(al_start, size)) {
		ntfs_error(base_ni->vol->sb, "Corrupt attribute list, mft = %llu",
			   base_ni->mft_no);
		return -EIO;
	}
	return 0;
}

/*
 * ntfs_external_attr_find - find an attribute in the attribute list of an inode
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @lowest_vcn:	lowest vcn to find (optional, non-resident attributes only)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * You should not need to call this function directly.  Use ntfs_attr_lookup()
 * instead.
 *
 * Find an attribute by searching the attribute list for the corresponding
 * attribute list entry.  Having found the entry, map the mft record if the
 * attribute is in a different mft record/inode, ntfs_attr_find() the attribute
 * in there and return it.
 *
 * On first search @ctx->ntfs_ino must be the base mft record and @ctx must
 * have been obtained from a call to ntfs_attr_get_search_ctx().  On subsequent
 * calls @ctx->ntfs_ino can be any extent inode, too (@ctx->base_ntfs_ino is
 * then the base inode).
 *
 * After finishing with the attribute/mft record you need to call
 * ntfs_attr_put_search_ctx() to cleanup the search context (unmapping any
 * mapped inodes, etc).
 *
 * If the attribute is found, ntfs_external_attr_find() returns 0 and
 * @ctx->attr will point to the found attribute.  @ctx->mrec will point to the
 * mft record in which @ctx->attr is located and @ctx->al_entry will point to
 * the attribute list entry for the attribute.
 *
 * If the attribute is not found, ntfs_external_attr_find() returns -ENOENT and
 * @ctx->attr will point to the attribute in the base mft record before which
 * the attribute being searched for would need to be inserted if such an action
 * were to be desired.  @ctx->mrec will point to the mft record in which
 * @ctx->attr is located and @ctx->al_entry will point to the attribute list
 * entry of the attribute before which the attribute being searched for would
 * need to be inserted if such an action were to be desired.
 *
 * Thus to insert the not found attribute, one wants to add the attribute to
 * @ctx->mrec (the base mft record) and if there is not enough space, the
 * attribute should be placed in a newly allocated extent mft record.  The
 * attribute list entry for the inserted attribute should be inserted in the
 * attribute list attribute at @ctx->al_entry.
 *
 * On actual error, ntfs_external_attr_find() returns -EIO.  In this case
 * @ctx->attr is undefined and in particular do not rely on it not changing.
 */
static int ntfs_external_attr_find(const __le32 type,
		const __le16 *name, const u32 name_len,
		const u32 ic, const s64 lowest_vcn,
		const u8 *val, const u32 val_len, struct ntfs_attr_search_ctx *ctx)
{
	struct ntfs_inode *base_ni = ctx->base_ntfs_ino, *ni = ctx->ntfs_ino;
	struct ntfs_volume *vol;
	struct attr_list_entry *al_entry, *next_al_entry;
	u8 *al_start, *al_end;
	struct attr_record *a;
	__le16 *al_name;
	u32 al_name_len;
	u32 attr_len, mft_free_len;
	bool is_first_search = false;
	int err = 0;
	static const char *es = " Unmount and run chkdsk.";

	ntfs_debug("Entering for inode 0x%llx, type 0x%x.", ni->mft_no, type);
	if (!base_ni) {
		/* First call happens with the base mft record. */
		base_ni = ctx->base_ntfs_ino = ctx->ntfs_ino;
		ctx->base_mrec = ctx->mrec;
		ctx->mapped_base_mrec = ctx->mapped_mrec;
	}
	if (ni == base_ni)
		ctx->base_attr = ctx->attr;
	if (type == AT_END)
		goto not_found;
	vol = base_ni->vol;
	al_start = base_ni->attr_list;
	al_end = al_start + base_ni->attr_list_size;
	if (!ctx->al_entry) {
		ctx->al_entry = (struct attr_list_entry *)al_start;
		is_first_search = true;
	}
	/*
	 * Iterate over entries in attribute list starting at @ctx->al_entry,
	 * or the entry following that, if @ctx->is_first is 'true'.
	 */
	if (ctx->is_first) {
		al_entry = ctx->al_entry;
		ctx->is_first = false;
		/*
		 * If an enumeration and the first attribute is higher than
		 * the attribute list itself, need to return the attribute list
		 * attribute.
		 */
		if ((type == AT_UNUSED) && is_first_search &&
				le32_to_cpu(al_entry->type) >
				le32_to_cpu(AT_ATTRIBUTE_LIST))
			goto find_attr_list_attr;
	} else {
		/* Check for small entry */
		if (((al_end - (u8 *)ctx->al_entry) <
		      (long)offsetof(struct attr_list_entry, name)) ||
		    (le16_to_cpu(ctx->al_entry->length) & 7) ||
		    (le16_to_cpu(ctx->al_entry->length) < offsetof(struct attr_list_entry, name)))
			goto corrupt;

		al_entry = (struct attr_list_entry *)((u8 *)ctx->al_entry +
				le16_to_cpu(ctx->al_entry->length));

		if ((u8 *)al_entry == al_end)
			goto not_found;

		/* Preliminary check for small entry */
		if ((al_end - (u8 *)al_entry) <
		    (long)offsetof(struct attr_list_entry, name))
			goto corrupt;

		/*
		 * If this is an enumeration and the attribute list attribute
		 * is the next one in the enumeration sequence, just return the
		 * attribute list attribute from the base mft record as it is
		 * not listed in the attribute list itself.
		 */
		if ((type == AT_UNUSED) && le32_to_cpu(ctx->al_entry->type) <
				le32_to_cpu(AT_ATTRIBUTE_LIST) &&
				le32_to_cpu(al_entry->type) >
				le32_to_cpu(AT_ATTRIBUTE_LIST)) {
find_attr_list_attr:

			/* Check for bogus calls. */
			if (name || name_len || val || val_len || lowest_vcn)
				return -EINVAL;

			/* We want the base record. */
			if (ctx->ntfs_ino != base_ni)
				unmap_mft_record(ctx->ntfs_ino);
			ctx->ntfs_ino = base_ni;
			ctx->mapped_mrec = ctx->mapped_base_mrec;
			ctx->mrec = ctx->base_mrec;
			ctx->is_first = true;

			/* Sanity checks are performed elsewhere. */
			ctx->attr = (struct attr_record *)((u8 *)ctx->mrec +
					le16_to_cpu(ctx->mrec->attrs_offset));

			/* Find the attribute list attribute. */
			err = ntfs_attr_find(AT_ATTRIBUTE_LIST, NULL, 0,
					IGNORE_CASE, NULL, 0, ctx);

			/*
			 * Setup the search context so the correct
			 * attribute is returned next time round.
			 */
			ctx->al_entry = al_entry;
			ctx->is_first = true;

			/* Got it. Done. */
			if (!err)
				return 0;

			/* Error! If other than not found return it. */
			if (err != -ENOENT)
				return err;

			/* Not found?!? Absurd! */
			ntfs_error(ctx->ntfs_ino->vol->sb, "Attribute list wasn't found");
			return -EIO;
		}
	}
	for (;; al_entry = next_al_entry) {
		/* Out of bounds check. */
		if ((u8 *)al_entry < base_ni->attr_list ||
				(u8 *)al_entry > al_end)
			break;	/* Inode is corrupt. */
		ctx->al_entry = al_entry;
		/* Catch the end of the attribute list. */
		if ((u8 *)al_entry == al_end)
			goto not_found;

		if ((((u8 *)al_entry + offsetof(struct attr_list_entry, name)) > al_end) ||
		    ((u8 *)al_entry + le16_to_cpu(al_entry->length) > al_end) ||
		    (le16_to_cpu(al_entry->length) & 7) ||
		    (le16_to_cpu(al_entry->length) <
		     offsetof(struct attr_list_entry, name_length)) ||
		    (al_entry->name_length && ((u8 *)al_entry + al_entry->name_offset +
					       al_entry->name_length * sizeof(__le16)) > al_end))
			break; /* corrupt */

		next_al_entry = (struct attr_list_entry *)((u8 *)al_entry +
				le16_to_cpu(al_entry->length));
		if (type != AT_UNUSED) {
			if (le32_to_cpu(al_entry->type) > le32_to_cpu(type))
				goto not_found;
			if (type != al_entry->type)
				continue;
		}
		/*
		 * If @name is present, compare the two names.  If @name is
		 * missing, assume we want an unnamed attribute.
		 */
		al_name_len = al_entry->name_length;
		al_name = (__le16 *)((u8 *)al_entry + al_entry->name_offset);

		/*
		 * If !@type we want the attribute represented by this
		 * attribute list entry.
		 */
		if (type == AT_UNUSED)
			goto is_enumeration;

		if (!name || name == AT_UNNAMED) {
			if (al_name_len)
				goto not_found;
		} else if (!ntfs_are_names_equal(al_name, al_name_len, name,
				name_len, ic, vol->upcase, vol->upcase_len)) {
			register int rc;

			rc = ntfs_collate_names(name, name_len, al_name,
					al_name_len, true, IGNORE_CASE,
					vol->upcase, vol->upcase_len);
			/*
			 * If @name collates before al_name, there is no
			 * matching attribute.
			 */
			if (rc == -1)
				goto not_found;
			/* If the strings are not equal, continue search. */
			if (rc)
				continue;

			rc = ntfs_collate_names(name, name_len, al_name,
					al_name_len, true, CASE_SENSITIVE,
					vol->upcase, vol->upcase_len);
			if (rc == -1)
				goto not_found;
			if (rc)
				continue;
		}
		/*
		 * The names match or @name not present and attribute is
		 * unnamed.  Now check @lowest_vcn.  Continue search if the
		 * next attribute list entry still fits @lowest_vcn.  Otherwise
		 * we have reached the right one or the search has failed.
		 */
		if (lowest_vcn && (u8 *)next_al_entry >= al_start &&
				ntfs_attr_list_entry_is_valid(next_al_entry,
							      al_end) &&
				le64_to_cpu(next_al_entry->lowest_vcn) <=
					lowest_vcn &&
				next_al_entry->type == al_entry->type &&
				next_al_entry->name_length == al_name_len &&
				ntfs_are_names_equal((__le16 *)((u8 *)
					next_al_entry +
					next_al_entry->name_offset),
					next_al_entry->name_length,
					al_name, al_name_len, CASE_SENSITIVE,
					vol->upcase, vol->upcase_len))
			continue;

is_enumeration:
		if (MREF_LE(al_entry->mft_reference) == ni->mft_no) {
			if (MSEQNO_LE(al_entry->mft_reference) != ni->seq_no) {
				ntfs_error(vol->sb,
					"Found stale mft reference in attribute list of base inode 0x%llx.%s",
					base_ni->mft_no, es);
				err = -EIO;
				break;
			}
		} else { /* Mft references do not match. */
			/* If there is a mapped record unmap it first. */
			if (ni != base_ni)
				unmap_extent_mft_record(ni);
			/* Do we want the base record back? */
			if (MREF_LE(al_entry->mft_reference) ==
					base_ni->mft_no) {
				ni = ctx->ntfs_ino = base_ni;
				ctx->mrec = ctx->base_mrec;
				ctx->mapped_mrec = ctx->mapped_base_mrec;
			} else {
				/* We want an extent record. */
				ctx->mrec = map_extent_mft_record(base_ni,
						le64_to_cpu(
						al_entry->mft_reference), &ni);
				if (IS_ERR(ctx->mrec)) {
					ntfs_error(vol->sb,
							"Failed to map extent mft record 0x%lx of base inode 0x%llx.%s",
							MREF_LE(al_entry->mft_reference),
							base_ni->mft_no, es);
					err = PTR_ERR(ctx->mrec);
					if (err == -ENOENT)
						err = -EIO;
					/* Cause @ctx to be sanitized below. */
					ni = NULL;
					break;
				}
				ctx->ntfs_ino = ni;
				ctx->mapped_mrec = true;

			}
		}
		a = ctx->attr = (struct attr_record *)((u8 *)ctx->mrec +
					le16_to_cpu(ctx->mrec->attrs_offset));
		/*
		 * ctx->vfs_ino, ctx->mrec, and ctx->attr now point to the
		 * mft record containing the attribute represented by the
		 * current al_entry.
		 */
		/*
		 * We could call into ntfs_attr_find() to find the right
		 * attribute in this mft record but this would be less
		 * efficient and not quite accurate as ntfs_attr_find() ignores
		 * the attribute instance numbers for example which become
		 * important when one plays with attribute lists.  Also,
		 * because a proper match has been found in the attribute list
		 * entry above, the comparison can now be optimized.  So it is
		 * worth re-implementing a simplified ntfs_attr_find() here.
		 */
		/*
		 * Use a manual loop so we can still use break and continue
		 * with the same meanings as above.
		 */
do_next_attr_loop:
		if ((u8 *)a < (u8 *)ctx->mrec ||
		    (u8 *)a >= (u8 *)ctx->mrec + le32_to_cpu(ctx->mrec->bytes_allocated) ||
		    (u8 *)a >= (u8 *)ctx->mrec + le32_to_cpu(ctx->mrec->bytes_in_use))
			break;

		mft_free_len = le32_to_cpu(ctx->mrec->bytes_in_use) -
			       ((u8 *)a - (u8 *)ctx->mrec);
		if (mft_free_len >= sizeof(a->type) && a->type == AT_END)
			continue;

		attr_len = le32_to_cpu(a->length);
		if (!attr_len ||
		    attr_len < offsetof(struct attr_record, data.resident.reserved) +
		    sizeof(a->data.resident.reserved) ||
		    attr_len > mft_free_len)
			break;

		if (al_entry->instance != a->instance)
			goto do_next_attr;
		/*
		 * If the type and/or the name are mismatched between the
		 * attribute list entry and the attribute record, there is
		 * corruption so we break and return error EIO.
		 */
		if (al_entry->type != a->type)
			break;
		if (a->name_length && ((le16_to_cpu(a->name_offset) +
			       a->name_length * sizeof(__le16)) > attr_len))
			break;
		if (!ntfs_are_names_equal((__le16 *)((u8 *)a +
				le16_to_cpu(a->name_offset)), a->name_length,
				al_name, al_name_len, CASE_SENSITIVE,
				vol->upcase, vol->upcase_len))
			break;

		ctx->attr = a;

		if (!ntfs_attr_value_is_valid(vol, a, ctx->ntfs_ino->mft_no))
			break;

		/*
		 * If no @val specified or @val specified and it matches, we
		 * have found it!
		 */
		if ((type == AT_UNUSED) || !val)
			goto attr_found;
		if (!a->non_resident) {
			u32 value_length = le32_to_cpu(a->data.resident.value_length);
			u16 value_offset = le16_to_cpu(a->data.resident.value_offset);

			if (value_length == val_len &&
			    !memcmp((u8 *)a + value_offset, val, val_len)) {
attr_found:
				ntfs_debug("Done, found.");
				return 0;
			}
		}
do_next_attr:
		/* Proceed to the next attribute in the current mft record. */
		a = (struct attr_record *)((u8 *)a + attr_len);
		goto do_next_attr_loop;
	}

corrupt:
	if (ni != base_ni) {
		if (ni)
			unmap_extent_mft_record(ni);
		ctx->ntfs_ino = base_ni;
		ctx->mrec = ctx->base_mrec;
		ctx->attr = ctx->base_attr;
		ctx->mapped_mrec = ctx->mapped_base_mrec;
	}

	if (!err) {
		u64 mft_no = ctx->al_entry ? MREF_LE(ctx->al_entry->mft_reference) : 0;
		u32 type = ctx->al_entry ? le32_to_cpu(ctx->al_entry->type) : 0;

		ntfs_error(vol->sb,
			"Base inode 0x%llx contains corrupt attribute, mft %#llx, type %#x. %s",
			(long long)base_ni->mft_no, (long long)mft_no, type,
			"Unmount and run chkdsk.");
		err = -EIO;
	}

	if (err != -ENOMEM)
		NVolSetErrors(vol);
	return err;
not_found:
	/*
	 * If we were looking for AT_END, we reset the search context @ctx and
	 * use ntfs_attr_find() to seek to the end of the base mft record.
	 */
	if (type == AT_UNUSED || type == AT_END) {
		ntfs_attr_reinit_search_ctx(ctx);
		return ntfs_attr_find(AT_END, name, name_len, ic, val, val_len,
				ctx);
	}
	/*
	 * The attribute was not found.  Before we return, we want to ensure
	 * @ctx->mrec and @ctx->attr indicate the position at which the
	 * attribute should be inserted in the base mft record.  Since we also
	 * want to preserve @ctx->al_entry we cannot reinitialize the search
	 * context using ntfs_attr_reinit_search_ctx() as this would set
	 * @ctx->al_entry to NULL.  Thus we do the necessary bits manually (see
	 * ntfs_attr_init_search_ctx() below).  Note, we _only_ preserve
	 * @ctx->al_entry as the remaining fields (base_*) are identical to
	 * their non base_ counterparts and we cannot set @ctx->base_attr
	 * correctly yet as we do not know what @ctx->attr will be set to by
	 * the call to ntfs_attr_find() below.
	 */
	if (ni != base_ni)
		unmap_extent_mft_record(ni);
	ctx->mrec = ctx->base_mrec;
	ctx->attr = (struct attr_record *)((u8 *)ctx->mrec +
			le16_to_cpu(ctx->mrec->attrs_offset));
	ctx->is_first = true;
	ctx->ntfs_ino = base_ni;
	ctx->base_ntfs_ino = NULL;
	ctx->base_mrec = NULL;
	ctx->base_attr = NULL;
	ctx->mapped_mrec = ctx->mapped_base_mrec;
	/*
	 * In case there are multiple matches in the base mft record, need to
	 * keep enumerating until we get an attribute not found response (or
	 * another error), otherwise we would keep returning the same attribute
	 * over and over again and all programs using us for enumeration would
	 * lock up in a tight loop.
	 */
	do {
		err = ntfs_attr_find(type, name, name_len, ic, val, val_len,
				ctx);
	} while (!err);
	ntfs_debug("Done, not found.");
	return err;
}

/*
 * ntfs_attr_lookup - find an attribute in an ntfs inode
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @lowest_vcn:	lowest vcn to find (optional, non-resident attributes only)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * Find an attribute in an ntfs inode.  On first search @ctx->ntfs_ino must
 * be the base mft record and @ctx must have been obtained from a call to
 * ntfs_attr_get_search_ctx().
 *
 * This function transparently handles attribute lists and @ctx is used to
 * continue searches where they were left off at.
 *
 * After finishing with the attribute/mft record you need to call
 * ntfs_attr_put_search_ctx() to cleanup the search context (unmapping any
 * mapped inodes, etc).
 *
 * Return 0 if the search was successful and -errno if not.
 *
 * When 0, @ctx->attr is the found attribute and it is in mft record
 * @ctx->mrec.  If an attribute list attribute is present, @ctx->al_entry is
 * the attribute list entry of the found attribute.
 *
 * When -ENOENT, @ctx->attr is the attribute which collates just after the
 * attribute being searched for, i.e. if one wants to add the attribute to the
 * mft record this is the correct place to insert it into.  If an attribute
 * list attribute is present, @ctx->al_entry is the attribute list entry which
 * collates just after the attribute list entry of the attribute being searched
 * for, i.e. if one wants to add the attribute to the mft record this is the
 * correct place to insert its attribute list entry into.
 */
int ntfs_attr_lookup(const __le32 type, const __le16 *name,
		const u32 name_len, const u32 ic,
		const s64 lowest_vcn, const u8 *val, const u32 val_len,
		struct ntfs_attr_search_ctx *ctx)
{
	struct ntfs_inode *base_ni;

	ntfs_debug("Entering.");
	if (ctx->base_ntfs_ino)
		base_ni = ctx->base_ntfs_ino;
	else
		base_ni = ctx->ntfs_ino;
	/* Sanity check, just for debugging really. */
	if (!base_ni || !NInoAttrList(base_ni) || type == AT_ATTRIBUTE_LIST)
		return ntfs_attr_find(type, name, name_len, ic, val, val_len,
				ctx);
	return ntfs_external_attr_find(type, name, name_len, ic, lowest_vcn,
			val, val_len, ctx);
}

/**
 * ntfs_attr_init_search_ctx - initialize an attribute search context
 * @ctx:        attribute search context to initialize
 * @ni:         ntfs inode with which to initialize the search context
 * @mrec:       mft record with which to initialize the search context
 *
 * Initialize the attribute search context @ctx with @ni and @mrec.
 */
static bool ntfs_attr_init_search_ctx(struct ntfs_attr_search_ctx *ctx,
		struct ntfs_inode *ni, struct mft_record *mrec)
{
	if (!mrec) {
		mrec = map_mft_record(ni);
		if (IS_ERR(mrec))
			return false;
		ctx->mapped_mrec = true;
	} else {
		ctx->mapped_mrec = false;
	}

	ctx->mrec = mrec;
	/* Sanity checks are performed elsewhere. */
	ctx->attr = (struct attr_record *)((u8 *)mrec + le16_to_cpu(mrec->attrs_offset));
	ctx->is_first = true;
	ctx->ntfs_ino = ni;
	ctx->al_entry = NULL;
	ctx->base_ntfs_ino = NULL;
	ctx->base_mrec = NULL;
	ctx->base_attr = NULL;
	ctx->mapped_base_mrec = false;
	return true;
}

/*
 * ntfs_attr_reinit_search_ctx - reinitialize an attribute search context
 * @ctx:	attribute search context to reinitialize
 *
 * Reinitialize the attribute search context @ctx, unmapping an associated
 * extent mft record if present, and initialize the search context again.
 *
 * This is used when a search for a new attribute is being started to reset
 * the search context to the beginning.
 */
void ntfs_attr_reinit_search_ctx(struct ntfs_attr_search_ctx *ctx)
{
	bool mapped_mrec;

	if (likely(!ctx->base_ntfs_ino)) {
		/* No attribute list. */
		ctx->is_first = true;
		/* Sanity checks are performed elsewhere. */
		ctx->attr = (struct attr_record *)((u8 *)ctx->mrec +
				le16_to_cpu(ctx->mrec->attrs_offset));
		/*
		 * This needs resetting due to ntfs_external_attr_find() which
		 * can leave it set despite having zeroed ctx->base_ntfs_ino.
		 */
		ctx->al_entry = NULL;
		return;
	} /* Attribute list. */
	if (ctx->ntfs_ino != ctx->base_ntfs_ino && ctx->ntfs_ino)
		unmap_extent_mft_record(ctx->ntfs_ino);

	mapped_mrec = ctx->mapped_base_mrec;
	ntfs_attr_init_search_ctx(ctx, ctx->base_ntfs_ino, ctx->base_mrec);
	ctx->mapped_mrec = mapped_mrec;
}

/*
 * ntfs_attr_get_search_ctx - allocate/initialize a new attribute search context
 * @ni:		ntfs inode with which to initialize the search context
 * @mrec:	mft record with which to initialize the search context
 *
 * Allocate a new attribute search context, initialize it with @ni and @mrec,
 * and return it. Return NULL if allocation failed.
 */
struct ntfs_attr_search_ctx *ntfs_attr_get_search_ctx(struct ntfs_inode *ni,
		struct mft_record *mrec)
{
	struct ntfs_attr_search_ctx *ctx;
	bool init;

	ctx = kmem_cache_alloc(ntfs_attr_ctx_cache, GFP_NOFS);
	if (ctx) {
		init = ntfs_attr_init_search_ctx(ctx, ni, mrec);
		if (init == false) {
			kmem_cache_free(ntfs_attr_ctx_cache, ctx);
			ctx = NULL;
		}
	}

	return ctx;
}

/*
 * ntfs_attr_put_search_ctx - release an attribute search context
 * @ctx:	attribute search context to free
 *
 * Release the attribute search context @ctx, unmapping an associated extent
 * mft record if present.
 */
void ntfs_attr_put_search_ctx(struct ntfs_attr_search_ctx *ctx)
{
	if (ctx->mapped_mrec)
		unmap_mft_record(ctx->ntfs_ino);

	if (ctx->mapped_base_mrec && ctx->base_ntfs_ino &&
	    ctx->ntfs_ino != ctx->base_ntfs_ino)
		unmap_extent_mft_record(ctx->base_ntfs_ino);
	kmem_cache_free(ntfs_attr_ctx_cache, ctx);
}

/*
 * ntfs_attr_find_in_attrdef - find an attribute in the $AttrDef system file
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to find
 *
 * Search for the attribute definition record corresponding to the attribute
 * @type in the $AttrDef system file.
 *
 * Return the attribute type definition record if found and NULL if not found.
 */
static struct attr_def *ntfs_attr_find_in_attrdef(const struct ntfs_volume *vol,
		const __le32 type)
{
	struct attr_def *ad;

	WARN_ON(!type);
	for (ad = vol->attrdef; (u8 *)ad - (u8 *)vol->attrdef <=
	     vol->attrdef_size - (s32)sizeof(*ad) && ad->type; ++ad) {
		/* We have not found it yet, carry on searching. */
		if (likely(le32_to_cpu(ad->type) < le32_to_cpu(type)))
			continue;
		/* We found the attribute; return it. */
		if (likely(ad->type == type))
			return ad;
		/* We have gone too far already.  No point in continuing. */
		break;
	}
	/* Attribute not found. */
	ntfs_debug("Attribute type 0x%x not found in $AttrDef.",
			le32_to_cpu(type));
	return NULL;
}

/*
 * ntfs_attr_size_bounds_check - check a size of an attribute type for validity
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 * @size:	size which to check
 *
 * Check whether the @size in bytes is valid for an attribute of @type on the
 * ntfs volume @vol.  This information is obtained from $AttrDef system file.
 */
int ntfs_attr_size_bounds_check(const struct ntfs_volume *vol, const __le32 type,
		const s64 size)
{
	struct attr_def *ad;

	if (size < 0)
		return -EINVAL;

	/*
	 * $ATTRIBUTE_LIST has a maximum size of 256kiB, but this is not
	 * listed in $AttrDef.
	 */
	if (unlikely(type == AT_ATTRIBUTE_LIST && size > NTFS_MAX_ATTR_LIST_SIZE))
		return -ERANGE;
	/* Get the $AttrDef entry for the attribute @type. */
	ad = ntfs_attr_find_in_attrdef(vol, type);
	if (unlikely(!ad))
		return -ENOENT;
	/* Do the bounds check. */
	if (((le64_to_cpu(ad->min_size) > 0) &&
			size < le64_to_cpu(ad->min_size)) ||
			((le64_to_cpu(ad->max_size) > 0) && size >
			le64_to_cpu(ad->max_size)))
		return -ERANGE;
	return 0;
}

/*
 * ntfs_attr_can_be_non_resident - check if an attribute can be non-resident
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 *
 * Check whether the attribute of @type on the ntfs volume @vol is allowed to
 * be non-resident.  This information is obtained from $AttrDef system file.
 */
static int ntfs_attr_can_be_non_resident(const struct ntfs_volume *vol,
		const __le32 type)
{
	struct attr_def *ad;

	/* Find the attribute definition record in $AttrDef. */
	ad = ntfs_attr_find_in_attrdef(vol, type);
	if (unlikely(!ad))
		return -ENOENT;
	/* Check the flags and return the result. */
	if (ad->flags & ATTR_DEF_RESIDENT)
		return -EPERM;
	return 0;
}

/*
 * ntfs_attr_can_be_resident - check if an attribute can be resident
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 *
 * Check whether the attribute of @type on the ntfs volume @vol is allowed to
 * be resident.  This information is derived from our ntfs knowledge and may
 * not be completely accurate, especially when user defined attributes are
 * present.  Basically we allow everything to be resident except for index
 * allocation and $EA attributes.
 *
 * Return 0 if the attribute is allowed to be non-resident and -EPERM if not.
 *
 * Warning: In the system file $MFT the attribute $Bitmap must be non-resident
 *	    otherwise windows will not boot (blue screen of death)!  We cannot
 *	    check for this here as we do not know which inode's $Bitmap is
 *	    being asked about so the caller needs to special case this.
 */
int ntfs_attr_can_be_resident(const struct ntfs_volume *vol, const __le32 type)
{
	if (type == AT_INDEX_ALLOCATION)
		return -EPERM;
	return 0;
}

/*
 * ntfs_attr_record_resize - resize an attribute record
 * @m:		mft record containing attribute record
 * @a:		attribute record to resize
 * @new_size:	new size in bytes to which to resize the attribute record @a
 *
 * Resize the attribute record @a, i.e. the resident part of the attribute, in
 * the mft record @m to @new_size bytes.
 */
int ntfs_attr_record_resize(struct mft_record *m, struct attr_record *a, u32 new_size)
{
	u32 old_size, alloc_size, attr_size;

	old_size   = le32_to_cpu(m->bytes_in_use);
	alloc_size = le32_to_cpu(m->bytes_allocated);
	attr_size  = le32_to_cpu(a->length);

	ntfs_debug("Sizes: old=%u alloc=%u attr=%u new=%u\n",
			(unsigned int)old_size, (unsigned int)alloc_size,
			(unsigned int)attr_size, (unsigned int)new_size);

	/* Align to 8 bytes if it is not already done. */
	if (new_size & 7)
		new_size = (new_size + 7) & ~7;
	/* If the actual attribute length has changed, move things around. */
	if (new_size != attr_size) {
		u32 new_muse = le32_to_cpu(m->bytes_in_use) -
				attr_size + new_size;
		/* Not enough space in this mft record. */
		if (new_muse > le32_to_cpu(m->bytes_allocated))
			return -ENOSPC;

		/*
		 * The base record needs to retain room for the attributes used to
		 * reparent an index root.  An extent record has no such
		 * requirement. Applying this rule there can refuse a root that
		 * otherwise fits in the record after it was moved out of the base.
		 */
		if (!le64_to_cpu(m->base_mft_record) &&
			a->type == AT_INDEX_ROOT && new_size > attr_size &&
			new_muse + 120 > alloc_size && old_size + 120 <= alloc_size) {
			ntfs_debug("Too big struct index_root (%u > %u)\n",
					new_muse, alloc_size);
			return -ENOSPC;
		}

		/* Move attributes following @a to their new location. */
		memmove((u8 *)a + new_size, (u8 *)a + le32_to_cpu(a->length),
				le32_to_cpu(m->bytes_in_use) - ((u8 *)a -
				(u8 *)m) - attr_size);
		/* Adjust @m to reflect the change in used space. */
		m->bytes_in_use = cpu_to_le32(new_muse);
		/* Adjust @a to reflect the new size. */
		if (new_size >= offsetof(struct attr_record, length) + sizeof(a->length))
			a->length = cpu_to_le32(new_size);
	}
	return 0;
}

/*
 * ntfs_resident_attr_value_resize - resize the value of a resident attribute
 * @m:		mft record containing attribute record
 * @a:		attribute record whose value to resize
 * @new_size:	new size in bytes to which to resize the attribute value of @a
 *
 * Resize the value of the attribute @a in the mft record @m to @new_size bytes.
 * If the value is made bigger, the newly allocated space is cleared.
 */
int ntfs_resident_attr_value_resize(struct mft_record *m, struct attr_record *a,
		const u32 new_size)
{
	u32 old_size;

	/* Resize the resident part of the attribute record. */
	if (ntfs_attr_record_resize(m, a,
			le16_to_cpu(a->data.resident.value_offset) + new_size))
		return -ENOSPC;
	/*
	 * The resize succeeded!  If we made the attribute value bigger, clear
	 * the area between the old size and @new_size.
	 */
	old_size = le32_to_cpu(a->data.resident.value_length);
	if (new_size > old_size)
		memset((u8 *)a + le16_to_cpu(a->data.resident.value_offset) +
				old_size, 0, new_size - old_size);
	/* Finally update the length of the attribute value. */
	a->data.resident.value_length = cpu_to_le32(new_size);
	return 0;
}

/*
 * ntfs_attr_make_non_resident - convert a resident to a non-resident attribute
 * @ni:		ntfs inode describing the attribute to convert
 * @data_size:	size of the resident data to copy to the non-resident attribute
 *
 * Convert the resident ntfs attribute described by the ntfs inode @ni to a
 * non-resident one.
 *
 * @data_size must be equal to the attribute value size.  This is needed since
 * we need to know the size before we can map the mft record and our callers
 * always know it.  The reason we cannot simply read the size from the vfs
 * inode i_size is that this is not necessarily uptodate.  This happens when
 * ntfs_attr_make_non_resident() is called in the ->truncate call path(s).
 */
static int __ntfs_attr_make_non_resident(struct ntfs_inode *ni, const u32 data_size,
		bool nowait);

int ntfs_attr_make_non_resident(struct ntfs_inode *ni, const u32 data_size)
{
	return __ntfs_attr_make_non_resident(ni, data_size, false);
}

/*
 * With @nowait the folio lock is only tried: a caller that holds mrec_lock
 * must not wait for a folio lock, the read path takes them the other way
 * round. Fails with -EAGAIN if the folio is locked.
 */
static int __ntfs_attr_make_non_resident(struct ntfs_inode *ni, const u32 data_size,
		bool nowait)
{
	s64 new_size;
	struct inode *vi = VFS_I(ni);
	struct ntfs_volume *vol = ni->vol;
	struct ntfs_inode *base_ni;
	struct mft_record *m;
	struct attr_record *a;
	struct ntfs_attr_search_ctx *ctx;
	struct folio *folio;
	struct runlist_element *rl;
	unsigned long flags;
	int mp_size, mp_ofs, name_ofs, arec_size, err, err2;
	u32 attr_size;
	u8 old_res_attr_flags;

	if (NInoNonResident(ni)) {
		ntfs_warning(vol->sb,
			"Trying to make non-resident attribute non-resident.  Aborting...\n");
		return -EINVAL;
	}

	/* Check that the attribute is allowed to be non-resident. */
	err = ntfs_attr_can_be_non_resident(vol, ni->type);
	if (unlikely(err)) {
		if (err == -EPERM)
			ntfs_debug("Attribute is not allowed to be non-resident.");
		else
			ntfs_debug("Attribute not defined on the NTFS volume!");
		return err;
	}

	if (NInoEncrypted(ni))
		return -EIO;

	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		ctx = NULL;
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			err = -EIO;
		goto err_out;
	}
	m = ctx->mrec;
	a = ctx->attr;

	/*
	 * The size needs to be aligned to a cluster boundary for allocation
	 * purposes.
	 */
	new_size = (data_size + vol->cluster_size - 1) &
			~(vol->cluster_size - 1);
	if (new_size > 0) {
		if ((a->flags & ATTR_COMPRESSION_MASK) == ATTR_IS_COMPRESSED) {
			/* must allocate full compression blocks */
			new_size =
				((new_size - 1) |
				 ((1L << (STANDARD_COMPRESSION_UNIT +
					  vol->cluster_size_bits)) - 1)) + 1;
		}

		/*
		 * Will need folio later and since folio lock nests
		 * outside all ntfs locks, we need to get the folio now.
		 */
		folio = __filemap_get_folio(vi->i_mapping, 0,
					    FGP_CREAT | FGP_LOCK |
					    (nowait ? FGP_NOWAIT : 0),
					    mapping_gfp_mask(vi->i_mapping));
		if (IS_ERR(folio)) {
			err = -ENOMEM;
			if (nowait) {
				/*
				 * FGP_NOWAIT also fails when it can not
				 * allocate the folio. Only a folio that is
				 * there and locked means a busy folio.
				 */
				folio = filemap_get_folio(vi->i_mapping, 0);
				if (!IS_ERR(folio)) {
					folio_put(folio);
					err = -EAGAIN;
				}
			}
			goto err_out;
		}

		/* Start by allocating clusters to hold the attribute value. */
		rl = ntfs_cluster_alloc(vol, 0,
				ntfs_bytes_to_cluster(vol, new_size),
				-1, DATA_ZONE, true, false, false);
		if (IS_ERR(rl)) {
			err = PTR_ERR(rl);
			ntfs_debug("Failed to allocate cluster%s, error code %i.",
					str_plural(ntfs_bytes_to_cluster(vol, new_size)),
					err);
			goto folio_err_out;
		}
	} else {
		rl = NULL;
		folio = NULL;
	}

	down_write(&ni->runlist.lock);
	/* Determine the size of the mapping pairs array. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl, 0, -1, -1);
	if (unlikely(mp_size < 0)) {
		err = mp_size;
		ntfs_debug("Failed to get size for mapping pairs array, error code %i.\n", err);
		goto rl_err_out;
	}

	if (NInoNonResident(ni) || a->non_resident) {
		err = -EIO;
		goto rl_err_out;
	}

	/*
	 * Calculate new offsets for the name and the mapping pairs array.
	 */
	if (NInoSparse(ni) || NInoCompressed(ni))
		name_ofs = (offsetof(struct attr_record,
				data.non_resident.compressed_size) +
				sizeof(a->data.non_resident.compressed_size) +
				7) & ~7;
	else
		name_ofs = (offsetof(struct attr_record,
				data.non_resident.compressed_size) + 7) & ~7;
	mp_ofs = (name_ofs + a->name_length * sizeof(__le16) + 7) & ~7;
	/*
	 * Determine the size of the resident part of the now non-resident
	 * attribute record.
	 */
	arec_size = (mp_ofs + mp_size + 7) & ~7;
	/*
	 * If the folio is not uptodate bring it uptodate by copying from the
	 * attribute value.
	 */
	attr_size = le32_to_cpu(a->data.resident.value_length);
	WARN_ON(attr_size != data_size);
	if (folio && !folio_test_uptodate(folio)) {
		folio_fill_tail(folio, 0, (u8 *)a +
				le16_to_cpu(a->data.resident.value_offset),
				attr_size);
		folio_mark_uptodate(folio);
	}

	/* Backup the attribute flag. */
	old_res_attr_flags = a->data.resident.flags;
	/* Resize the resident part of the attribute record. */
	err = ntfs_attr_record_resize(m, a, arec_size);
	if (unlikely(err))
		goto rl_err_out;

	/*
	 * Convert the resident part of the attribute record to describe a
	 * non-resident attribute.
	 */
	a->non_resident = 1;
	/* Move the attribute name if it exists and update the offset. */
	if (a->name_length)
		memmove((u8 *)a + name_ofs, (u8 *)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(__le16));
	a->name_offset = cpu_to_le16(name_ofs);
	/* Setup the fields specific to non-resident attributes. */
	a->data.non_resident.lowest_vcn = 0;
	a->data.non_resident.highest_vcn =
		cpu_to_le64(ntfs_bytes_to_cluster(vol, new_size - 1));
	a->data.non_resident.mapping_pairs_offset = cpu_to_le16(mp_ofs);
	memset(&a->data.non_resident.reserved, 0,
			sizeof(a->data.non_resident.reserved));
	a->data.non_resident.allocated_size = cpu_to_le64(new_size);
	a->data.non_resident.data_size =
			a->data.non_resident.initialized_size =
			cpu_to_le64(attr_size);
	if (NInoSparse(ni) || NInoCompressed(ni)) {
		a->data.non_resident.compression_unit = 0;
		if (NInoCompressed(ni) || vol->major_ver < 3)
			a->data.non_resident.compression_unit = 4;
		a->data.non_resident.compressed_size =
				a->data.non_resident.allocated_size;
	} else
		a->data.non_resident.compression_unit = 0;
	/* Generate the mapping pairs array into the attribute record. */
	err = ntfs_mapping_pairs_build(vol, (u8 *)a + mp_ofs,
			arec_size - mp_ofs, rl, 0, -1, NULL, NULL, NULL);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Failed to build mapping pairs, error code %i.",
				err);
		goto undo_err_out;
	}

	/* Setup the in-memory attribute structure to be non-resident. */
	ni->runlist.rl = rl;
	if (rl) {
		for (ni->runlist.count = 1; rl->length != 0; rl++)
			ni->runlist.count++;
	} else
		ni->runlist.count = 0;
	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = new_size;
	if ((NInoSparse(ni) && !NInoWofCompressed(ni)) || NInoCompressed(ni)) {
		ni->itype.compressed.size = ni->allocated_size;
		if (a->data.non_resident.compression_unit) {
			ni->itype.compressed.block_size = 1U <<
				(a->data.non_resident.compression_unit +
				 vol->cluster_size_bits);
			ni->itype.compressed.block_size_bits =
					ffs(ni->itype.compressed.block_size) -
					1;
			ni->itype.compressed.block_clusters = 1U <<
					a->data.non_resident.compression_unit;
		} else {
			ni->itype.compressed.block_size = 0;
			ni->itype.compressed.block_size_bits = 0;
			ni->itype.compressed.block_clusters = 0;
		}
		vi->i_blocks = ni->itype.compressed.size >> 9;
	} else
		vi->i_blocks = ni->allocated_size >> 9;
	write_unlock_irqrestore(&ni->size_lock, flags);
	/*
	 * This needs to be last since the address space operations ->read_folio
	 * and ->writepage can run concurrently with us as they are not
	 * serialized on i_mutex.  Note, we are not allowed to fail once we flip
	 * this switch, which is another reason to do this last.
	 */
	NInoSetNonResident(ni);
	NInoSetFullyMapped(ni);
	/* Mark the mft record dirty, so it gets written back. */
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	up_write(&ni->runlist.lock);
	if (folio) {
		iomap_dirty_folio(vi->i_mapping, folio);
		folio_unlock(folio);
		folio_put(folio);
	}
	ntfs_debug("Done.");
	return 0;
undo_err_out:
	/* Convert the attribute back into a resident attribute. */
	a->non_resident = 0;
	/* Move the attribute name if it exists and update the offset. */
	name_ofs = (offsetof(struct attr_record, data.resident.reserved) +
			sizeof(a->data.resident.reserved) + 7) & ~7;
	if (a->name_length)
		memmove((u8 *)a + name_ofs, (u8 *)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(__le16));
	mp_ofs = (name_ofs + a->name_length * sizeof(__le16) + 7) & ~7;
	a->name_offset = cpu_to_le16(name_ofs);
	arec_size = (mp_ofs + attr_size + 7) & ~7;
	/* Resize the resident part of the attribute record. */
	err2 = ntfs_attr_record_resize(m, a, arec_size);
	if (unlikely(err2)) {
		/*
		 * This cannot happen (well if memory corruption is at work it
		 * could happen in theory), but deal with it as well as we can.
		 * If the old size is too small, truncate the attribute,
		 * otherwise simply give it a larger allocated size.
		 */
		arec_size = le32_to_cpu(a->length);
		if ((mp_ofs + attr_size) > arec_size) {
			err2 = attr_size;
			attr_size = arec_size - mp_ofs;
			ntfs_error(vol->sb,
				"Failed to undo partial resident to non-resident attribute conversion.  Truncating inode 0x%llx, attribute type 0x%x from %i bytes to %i bytes to maintain metadata consistency.  THIS MEANS YOU ARE LOSING %i BYTES DATA FROM THIS %s.",
					ni->mft_no,
					(unsigned int)le32_to_cpu(ni->type),
					err2, attr_size, err2 - attr_size,
					((ni->type == AT_DATA) &&
					!ni->name_len) ? "FILE" : "ATTRIBUTE");
			write_lock_irqsave(&ni->size_lock, flags);
			ni->initialized_size = attr_size;
			i_size_write(vi, attr_size);
			write_unlock_irqrestore(&ni->size_lock, flags);
		}
	}
	/* Setup the fields specific to resident attributes. */
	a->data.resident.value_length = cpu_to_le32(attr_size);
	a->data.resident.value_offset = cpu_to_le16(mp_ofs);
	a->data.resident.flags = old_res_attr_flags;
	memset(&a->data.resident.reserved, 0,
			sizeof(a->data.resident.reserved));
	/* Copy the data from folio back to the attribute value. */
	if (folio)
		memcpy_from_folio((u8 *)a + mp_ofs, folio, 0, attr_size);
	/* Setup the allocated size in the ntfs inode in case it changed. */
	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = arec_size - mp_ofs;
	write_unlock_irqrestore(&ni->size_lock, flags);
	/* Mark the mft record dirty, so it gets written back. */
	mark_mft_record_dirty(ctx->ntfs_ino);
rl_err_out:
	up_write(&ni->runlist.lock);
	if (ctx) {
		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
	}
	if (m) {
		unmap_mft_record(base_ni);
		m = NULL;
	}
folio_err_out:
	if (folio) {
		folio_unlock(folio);
		folio_put(folio);
	}
	if (!IS_ERR_OR_NULL(rl)) {
		if (ntfs_cluster_free_from_rl(vol, rl) < 0) {
			ntfs_error(vol->sb,
				"Failed to release allocated cluster(s) in error code path.  Run chkdsk to recover the lost cluster(s).");
			NVolSetErrors(vol);
		}
		kvfree(rl);
		rl = NULL;
	}
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	ni->runlist.rl = NULL;

	if (err == -EINVAL)
		err = -EIO;
	return err;
}

/*
 * ntfs_attr_set - fill (a part of) an attribute with a byte
 * @ni:		ntfs inode describing the attribute to fill
 * @ofs:	offset inside the attribute at which to start to fill
 * @cnt:	number of bytes to fill
 * @val:	the unsigned 8-bit value with which to fill the attribute
 *
 * Fill @cnt bytes of the attribute described by the ntfs inode @ni starting at
 * byte offset @ofs inside the attribute with the constant byte @val.
 *
 * This function is effectively like memset() applied to an ntfs attribute.
 * Note thie function actually only operates on the page cache pages belonging
 * to the ntfs attribute and it marks them dirty after doing the memset().
 * Thus it relies on the vm dirty page write code paths to cause the modified
 * pages to be written to the mft record/disk.
 */
int ntfs_attr_set(struct ntfs_inode *ni, s64 ofs, s64 cnt, const u8 val)
{
	struct address_space *mapping = VFS_I(ni)->i_mapping;
	struct folio *folio;
	pgoff_t index;
	u8 *addr;
	unsigned long offset;
	size_t attr_len;
	int ret = 0;

	index = ofs >> PAGE_SHIFT;
	while (cnt) {
		folio = ntfs_read_metadata_folio(mapping, index);
		if (IS_ERR(folio)) {
			ret = PTR_ERR(folio);
			ntfs_error(VFS_I(ni)->i_sb, "Failed to read a page %lu for attr %#x: %ld",
				   index, ni->type, PTR_ERR(folio));
			break;
		}

		offset = offset_in_folio(folio, ofs);
		attr_len = min_t(size_t, (size_t)cnt, folio_size(folio) - offset);

		folio_lock(folio);
		addr = kmap_local_folio(folio, offset);
		memset(addr, val, attr_len);
		kunmap_local(addr);

		folio_mark_dirty(folio);
		folio_unlock(folio);
		folio_put(folio);

		ofs += attr_len;
		cnt -= attr_len;
		index++;
		cond_resched();
	}

	return ret;
}

int ntfs_attr_set_initialized_size(struct ntfs_inode *ni, loff_t new_size)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	int err = 0;

	if (!NInoNonResident(ni))
		return -EINVAL;

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;

	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			       CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out_ctx;

	ctx->attr->data.non_resident.initialized_size = cpu_to_le64(new_size);
	if (new_size < ni->initialized_size || new_size > ni->zeroed_size)
		ni->zeroed_size = new_size;
	ni->initialized_size = new_size;
	mark_mft_record_dirty(ctx->ntfs_ino);
out_ctx:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

/*
 * ntfs_make_room_for_attr - make room for an attribute inside an mft record
 * @m:		mft record
 * @pos:	position at which to make space
 * @size:	byte size to make available at this position
 *
 * @pos points to the attribute in front of which we want to make space.
 */
static int ntfs_check_room_for_attr(struct mft_record *m, u8 *pos, u32 size)
{
	u32 biu;

	/* Make size 8-byte alignment. */
	size = (size + 7) & ~7;

	/* Rigorous consistency checks. */
	if (!m || !pos || pos < (u8 *)m) {
		pr_err("%s: pos=%p  m=%p\n", __func__, pos, m);
		return -EINVAL;
	}

	/* The -8 is for the attribute terminator. */
	if (pos - (u8 *)m > (int)le32_to_cpu(m->bytes_in_use) - 8)
		return -EINVAL;
	/* Nothing to do. */
	if (!size)
		return 0;

	biu = le32_to_cpu(m->bytes_in_use);
	/* Do we have enough space? */
	if (biu + size > le32_to_cpu(m->bytes_allocated) ||
	    pos + size > (u8 *)m + le32_to_cpu(m->bytes_allocated)) {
		ntfs_debug("No enough space in the MFT record\n");
		return -ENOSPC;
	}
	return 0;
}

static int ntfs_make_room_for_attr(struct mft_record *m, u8 *pos, u32 size)
{
	u32 biu;
	int err;

	if (!m || !pos)
		return -EINVAL;
	ntfs_debug("Entering for pos 0x%x, size %u.\n",
			(int)(pos - (u8 *)m), (unsigned int)size);

	/* Make size 8-byte alignment. */
	size = (size + 7) & ~7;
	err = ntfs_check_room_for_attr(m, pos, size);
	if (err)
		return err;
	if (!size)
		return 0;

	biu = le32_to_cpu(m->bytes_in_use);
	/* Move everything after pos to pos + size. */
	memmove(pos + size, pos, biu - (pos - (u8 *)m));
	/* Update mft record. */
	m->bytes_in_use = cpu_to_le32(biu + size);
	return 0;
}

static void ntfs_init_resident_attr_record(struct attr_record *a, u32 length,
		__le32 type, const __le16 *name, u8 name_len, const u8 *val,
		u32 size, __le16 flags, __le16 instance)
{
	memset(a, 0, length);
	a->type = type;
	a->length = cpu_to_le32(length);
	a->name_length = name_len;
	a->name_offset = name_len ? cpu_to_le16(offsetof(struct attr_record,
			data.resident.reserved) + sizeof(a->data.resident.reserved)) :
			cpu_to_le16(0);
	a->flags = flags;
	a->instance = instance;
	a->data.resident.value_length = cpu_to_le32(size);
	a->data.resident.value_offset =
		cpu_to_le16(length - ALIGN(size, 8));
	if (val)
		memcpy((u8 *)a + le16_to_cpu(a->data.resident.value_offset),
				val, size);
	if (type == AT_FILE_NAME)
		a->data.resident.flags = RESIDENT_ATTR_IS_INDEXED;
	if (name_len)
		memcpy((u8 *)a + le16_to_cpu(a->name_offset), name,
				name_len * sizeof(__le16));
}

static bool ntfs_filename_link_count_in_record(struct ntfs_inode *ni,
		const struct attr_record *attr)
{
	return ni->nr_extents != -1 && !attr->non_resident &&
		(attr->data.resident.flags & RESIDENT_ATTR_IS_INDEXED);
}

/*
 * Indexed attribute replay adjusts the containing record's link count.
 * That is correct for a base record, but not for a filename in an extent.
 */
static int ntfs_log_filename_attr_update(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, struct mft_record *mrec, u16 offset,
		const struct attr_record *new_attr, u32 length, u64 *lsn)
{
	const struct attr_record *attr = new_attr ? new_attr :
		(const struct attr_record *)((const u8 *)mrec + offset);
	struct mft_record *after;
	int err;

	if (ntfs_filename_link_count_in_record(ni, attr)) {
		err = ntfs_attr_mft_register_home_undo(handle, ni, mrec);
		if (err)
			return err;
		if (new_attr)
			return ntfs_log_mft_attribute_create(handle, ni->mft_no,
					offset, new_attr, length, lsn);
		return ntfs_log_mft_attribute_delete(handle, ni->mft_no,
				offset, attr, le32_to_cpu(attr->length), lsn);
	}

	after = kmemdup(mrec, ni->vol->mft_record_size, GFP_NOFS);
	if (!after)
		return -ENOMEM;
	if (new_attr) {
		err = ntfs_make_room_for_attr(after, (u8 *)after + offset, length);
		if (!err) {
			memcpy((u8 *)after + offset, new_attr, length);
			le16_add_cpu(&after->next_attr_instance, 1);
		}
	} else {
		err = ntfs_attr_record_resize(after,
				(struct attr_record *)((u8 *)after + offset), 0);
	}
	if (!err)
		err = ntfs_attr_mft_register_home_undo(handle, ni, mrec);
	if (!err)
		err = ntfs_log_mft_record_update(handle, ni->mft_no, mrec,
				after, lsn);
	kfree(after);
	return err;
}

/*
 * ntfs_resident_attr_record_add - add resident attribute to inode
 * @ni:		opened ntfs inode to which MFT record add attribute
 * @type:	type of the new attribute
 * @name:	name of the new attribute
 * @name_len:	name length of the new attribute
 * @val:	value of the new attribute
 * @size:	size of new attribute (length of @val, if @val != NULL)
 * @flags:	flags of the new attribute
 */
static int __ntfs_resident_attr_record_add(struct ntfs_log_handle *log_handle,
		struct ntfs_inode *ni, __le32 type,
		__le16 *name, u8 name_len, u8 *val, u32 size,
		__le16 flags)
{
	struct ntfs_attr_search_ctx *ctx;
	struct attr_record *new_attr = NULL;
	u32 length;
	struct attr_record *a;
	struct mft_record *m;
	u64 operation_lsn = 0;
	int err, offset;
	struct ntfs_inode *base_ni;
	u32 ic;
	bool update_link_count = false;

	if (!ni || (!name && name_len))
		return -EINVAL;

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x, flags 0x%x.\n",
			(long long) ni->mft_no, (unsigned int) le32_to_cpu(type),
			(unsigned int) le16_to_cpu(flags));

	err = ntfs_attr_can_be_resident(ni->vol, type);
	if (err) {
		if (err == -EPERM)
			ntfs_debug("Attribute can't be resident.\n");
		else
			ntfs_debug("ntfs_attr_can_be_resident failed.\n");
		return err;
	}

	/* Locate place where record should be. */
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		ntfs_error(ni->vol->sb, "%s: Failed to get search context",
				__func__);
		return -ENOMEM;
	}
	/*
	 * Use ntfs_attr_find instead of ntfs_attr_lookup to find place for
	 * attribute in @ni->mrec, not any extent inode in case if @ni is base
	 * file record.
	 */
	ic = type == AT_DATA && name_len ? IGNORE_CASE : CASE_SENSITIVE;
	err = ntfs_attr_find(type, name, name_len, ic, val, size, ctx);
	if (!err) {
		err = -EEXIST;
		ntfs_debug("Attribute already present.\n");
		goto put_err_out;
	}
	if (err != -ENOENT) {
		err = -EIO;
		goto put_err_out;
	}
	a = ctx->attr;
	m = ctx->mrec;
	if (ni->nr_extents == -1)
		base_ni = ni->ext.base_ntfs_ino;
	else
		base_ni = ni;

	/* Make room for attribute. */
	length = offsetof(struct attr_record, data.resident.reserved) +
			  sizeof(a->data.resident.reserved) +
		((name_len * sizeof(__le16) + 7) & ~7) +
		((size + 7) & ~7);
	if (length > U16_MAX) {
		err = -E2BIG;
		goto put_err_out;
	}
	if (log_handle) {
		err = ntfs_check_room_for_attr(m, (u8 *)a, length);
		if (err)
			goto put_err_out;
		new_attr = kzalloc(length, GFP_NOFS);
		if (!new_attr) {
			err = -ENOMEM;
			goto put_err_out;
		}
		ntfs_init_resident_attr_record(new_attr, length, type, name,
				name_len, val, size, flags, m->next_attr_instance);
		offset = (u8 *)a - (u8 *)m;
		if (offset > U16_MAX) {
			err = -E2BIG;
			goto put_err_out;
		}
		if (type == AT_FILE_NAME) {
			update_link_count =
				ntfs_filename_link_count_in_record(ni, new_attr);
			err = ntfs_log_filename_attr_update(log_handle, ni, m,
					offset, new_attr, length, &operation_lsn);
		} else {
			err = ntfs_log_mft_attribute_create(log_handle, ni->mft_no,
					offset, new_attr, length, &operation_lsn);
		}
		if (err)
			goto put_err_out;
	}
	err = ntfs_make_room_for_attr(ctx->mrec, (u8 *) ctx->attr, length);
	if (err) {
		ntfs_debug("Failed to make room for attribute.\n");
		goto put_err_out;
	}

	/* Setup record fields. */
	offset = ((u8 *)a - (u8 *)m);
	if (new_attr)
		memcpy(a, new_attr, length);
	else
		ntfs_init_resident_attr_record(a, length, type, name, name_len,
				val, size, flags, m->next_attr_instance);
	kfree(new_attr);
	new_attr = NULL;
	m->next_attr_instance =
		cpu_to_le16((le16_to_cpu(m->next_attr_instance) + 1) & 0xffff);
	if (update_link_count)
		le16_add_cpu(&m->link_count, 1);
	if (!log_handle && type != AT_ATTRIBUTE_LIST &&
	    NInoAttrList(base_ni)) {
		err = ntfs_attrlist_entry_add(ni, a);
		if (err) {
			ntfs_attr_record_resize(m, a, 0);
			mark_mft_record_dirty(ctx->ntfs_ino);
			ntfs_debug("Failed add attribute entry to ATTRIBUTE_LIST.\n");
			goto put_err_out;
		}
	}
	if (operation_lsn)
		m->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ni);
	ntfs_attr_put_search_ctx(ctx);
	return offset;
put_err_out:
	kfree(new_attr);
	ntfs_attr_put_search_ctx(ctx);
	return log_handle ? err : -EIO;
}

int ntfs_resident_attr_record_add(struct ntfs_inode *ni, __le32 type,
		__le16 *name, u8 name_len, u8 *val, u32 size, __le16 flags)
{
	return __ntfs_resident_attr_record_add(NULL, ni, type, name, name_len,
			val, size, flags);
}

int ntfs_resident_attr_record_add_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, __le32 type, __le16 *name, u8 name_len,
		u8 *val, u32 size, __le16 flags)
{
	if (!handle)
		return -EINVAL;
	return __ntfs_resident_attr_record_add(handle, ni, type, name,
			name_len, val, size, flags);
}

static void ntfs_init_non_resident_attr_record(struct attr_record *a,
		u32 length, __le32 type, const __le16 *name, u8 name_len,
		s64 lowest_vcn, u32 dataruns_size, __le16 flags, __le16 instance)
{
	memset(a, 0, length);
	a->type = type;
	a->length = cpu_to_le32(length);
	a->non_resident = 1;
	a->name_length = name_len;
	a->name_offset = cpu_to_le16(offsetof(struct attr_record,
			data.non_resident.compressed_size) +
			((flags & (ATTR_IS_COMPRESSED | ATTR_IS_SPARSE)) ?
			 sizeof(a->data.non_resident.compressed_size) : 0));
	a->flags = flags;
	a->instance = instance;
	a->data.non_resident.lowest_vcn = cpu_to_le64(lowest_vcn);
	a->data.non_resident.mapping_pairs_offset =
		cpu_to_le16(length - dataruns_size);
	a->data.non_resident.compression_unit =
		(flags & ATTR_IS_COMPRESSED) ? STANDARD_COMPRESSION_UNIT : 0;
	if (!lowest_vcn) {
		a->data.non_resident.highest_vcn = cpu_to_le64(-1);
		*((u8 *)a + le16_to_cpu(
			a->data.non_resident.mapping_pairs_offset)) = 0;
	}
	if (name_len)
		memcpy((u8 *)a + le16_to_cpu(a->name_offset), name,
				name_len * sizeof(__le16));
}

/*
 * ntfs_non_resident_attr_record_add - add extent of non-resident attribute
 * @ni:			opened ntfs inode to which MFT record add attribute
 * @type:		type of the new attribute extent
 * @name:		name of the new attribute extent
 * @name_len:		name length of the new attribute extent
 * @lowest_vcn:		lowest vcn of the new attribute extent
 * @dataruns_size:	dataruns size of the new attribute extent
 * @flags:		flags of the new attribute extent
 */
static int ntfs_non_resident_attr_record_add(
		struct ntfs_log_handle *log_handle, struct ntfs_inode *ni,
		__le32 type, __le16 *name, u8 name_len, s64 lowest_vcn,
		int dataruns_size, __le16 flags)
{
	struct ntfs_attr_search_ctx *ctx;
	struct attr_record *new_attr = NULL;
	u32 length;
	struct attr_record *a;
	struct mft_record *m;
	struct ntfs_inode *base_ni;
	u64 operation_lsn = 0;
	int err, offset;
	u32 ic;

	if (!ni || dataruns_size <= 0 || (!name && name_len))
		return -EINVAL;

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x, lowest_vcn %lld, dataruns_size %d, flags 0x%x.\n",
			(long long) ni->mft_no, (unsigned int) le32_to_cpu(type),
			(long long) lowest_vcn, dataruns_size,
			(unsigned int) le16_to_cpu(flags));

	err = ntfs_attr_can_be_non_resident(ni->vol, type);
	if (err) {
		if (err == -EPERM)
			pr_err("Attribute can't be non resident\n");
		else
			pr_err("ntfs_attr_can_be_non_resident failed\n");
		return err;
	}

	/* Locate place where record should be. */
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		pr_err("%s: Failed to get search context\n", __func__);
		return -ENOMEM;
	}
	/*
	 * Use ntfs_attr_find instead of ntfs_attr_lookup to find place for
	 * attribute in @ni->mrec, not any extent inode in case if @ni is base
	 * file record.
	 */
	ic = type == AT_DATA && name_len ? IGNORE_CASE : CASE_SENSITIVE;
	err = ntfs_attr_find(type, name, name_len, ic, NULL, 0, ctx);
	if (!err) {
		err = -EEXIST;
		pr_err("Attribute 0x%x already present\n", type);
		goto put_err_out;
	}
	if (err != -ENOENT) {
		pr_err("ntfs_attr_find failed\n");
		err = -EIO;
		goto put_err_out;
	}
	a = ctx->attr;
	m = ctx->mrec;
	if (ni->nr_extents == -1)
		base_ni = ni->ext.base_ntfs_ino;
	else
		base_ni = ni;

	/* Make room for attribute. */
	dataruns_size = (dataruns_size + 7) & ~7;
	length = offsetof(struct attr_record, data.non_resident.compressed_size) +
		((sizeof(__le16) * name_len + 7) & ~7) + dataruns_size +
		((flags & (ATTR_IS_COMPRESSED | ATTR_IS_SPARSE)) ?
		 sizeof(a->data.non_resident.compressed_size) : 0);
	if (length > U16_MAX) {
		err = -E2BIG;
		goto put_err_out;
	}
	if (log_handle) {
		err = ntfs_check_room_for_attr(m, (u8 *)a, length);
		if (err)
			goto put_err_out;
		new_attr = kzalloc(length, GFP_NOFS);
		if (!new_attr) {
			err = -ENOMEM;
			goto put_err_out;
		}
		ntfs_init_non_resident_attr_record(new_attr, length, type, name,
				name_len, lowest_vcn, dataruns_size, flags,
				m->next_attr_instance);
		offset = (u8 *)a - (u8 *)m;
		if (offset > U16_MAX) {
			err = -E2BIG;
			goto put_err_out;
		}
		err = ntfs_log_mft_attribute_create(log_handle, ni->mft_no,
				offset, new_attr, length, &operation_lsn);
		if (err)
			goto put_err_out;
	}
	err = ntfs_make_room_for_attr(ctx->mrec, (u8 *) ctx->attr, length);
	if (err) {
		pr_err("Failed to make room for attribute\n");
		goto put_err_out;
	}

	/* Setup record fields. */
	if (new_attr)
		memcpy(a, new_attr, length);
	else
		ntfs_init_non_resident_attr_record(a, length, type, name,
				name_len, lowest_vcn, dataruns_size, flags,
				m->next_attr_instance);
	kfree(new_attr);
	new_attr = NULL;
	m->next_attr_instance =
		cpu_to_le16((le16_to_cpu(m->next_attr_instance) + 1) & 0xffff);
	if (!log_handle && type != AT_ATTRIBUTE_LIST &&
	    NInoAttrList(base_ni)) {
		err = ntfs_attrlist_entry_add(ni, a);
		if (err) {
			pr_err("Failed add attr entry to attrlist\n");
			ntfs_attr_record_resize(m, a, 0);
			goto put_err_out;
		}
	}
	if (operation_lsn)
		m->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ni);
	/* The caller publishes the matching attribute-list entry separately. */
	if (log_handle) {
		ntfs_attr_put_search_ctx(ctx);
		return offset;
	}
	/*
	 * Locate offset from start of the MFT record where new attribute is
	 * placed. We need relookup it, because record maybe moved during
	 * update of attribute list.
	 */
	ntfs_attr_reinit_search_ctx(ctx);
	err = ntfs_attr_lookup(type, name, name_len, ic,
				lowest_vcn, NULL, 0, ctx);
	if (err) {
		pr_err("%s: attribute lookup failed\n", __func__);
		ntfs_attr_put_search_ctx(ctx);
		return err;

	}
	offset = (u8 *)ctx->attr - (u8 *)ctx->mrec;
	ntfs_attr_put_search_ctx(ctx);
	return offset;
put_err_out:
	kfree(new_attr);
	ntfs_attr_put_search_ctx(ctx);
	return log_handle ? err : -1;
}

int ntfs_non_resident_attr_record_add_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		__le32 type, __le16 *name, u8 name_len, s64 lowest_vcn,
		int dataruns_size, __le16 flags)
{
	if (!handle)
		return -EINVAL;
	return ntfs_non_resident_attr_record_add(handle, ni, type, name,
			name_len, lowest_vcn, dataruns_size, flags);
}

/*
 * ntfs_attr_record_rm - remove attribute extent
 * @ctx:	search context describing the attribute which should be removed
 *
 * If this function succeed, user should reinit search context if he/she wants
 * use it anymore.
 */
static int __ntfs_attr_record_rm(struct ntfs_log_handle *log_handle,
		struct ntfs_attr_search_ctx *ctx)
{
	struct ntfs_inode *base_ni, *ni;
	u32 attr_len;
	u32 attrs_off;
	u32 used;
	__le32 type;
	u64 operation_lsn = 0;
	u16 record_off;
	ptrdiff_t offset;
	bool update_link_count = false;
	int err;

	if (!ctx || !ctx->ntfs_ino || !ctx->mrec || !ctx->attr)
		return -EINVAL;

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x.\n",
			(long long) ctx->ntfs_ino->mft_no,
			(unsigned int) le32_to_cpu(ctx->attr->type));
	type = ctx->attr->type;
	ni = ctx->ntfs_ino;
	if (ctx->base_ntfs_ino)
		base_ni = ctx->base_ntfs_ino;
	else
		base_ni = ctx->ntfs_ino;
	attr_len = le32_to_cpu(ctx->attr->length);
	if (log_handle) {
		if (type == AT_ATTRIBUTE_LIST)
			return -EOPNOTSUPP;
		if ((u8 *)ctx->attr < (u8 *)ctx->mrec)
			return -EIO;
		offset = (u8 *)ctx->attr - (u8 *)ctx->mrec;
		used = le32_to_cpu(ctx->mrec->bytes_in_use);
		attrs_off = le16_to_cpu(ctx->mrec->attrs_offset);
		if (attr_len > U16_MAX || offset > U16_MAX || offset > used ||
		    attr_len > used - offset || attrs_off > used - attr_len)
			return -EIO;
		if (used - attr_len - attrs_off == 8 && ni == base_ni)
			return -EOPNOTSUPP;
		record_off = offset;
		if (type == AT_FILE_NAME) {
			update_link_count =
				ntfs_filename_link_count_in_record(ni, ctx->attr);
			err = ntfs_log_filename_attr_update(log_handle, ni,
					ctx->mrec, record_off, NULL, 0,
					&operation_lsn);
		} else {
			err = ntfs_attr_mft_register_home_undo(log_handle, ni,
					ctx->mrec);
			if (err)
				return err;
			err = ntfs_log_mft_attribute_delete(log_handle, ni->mft_no,
					record_off, ctx->attr, attr_len,
					&operation_lsn);
		}
		if (err)
			return err;
	}

	/* Remove attribute itself. */
	if (ntfs_attr_record_resize(ctx->mrec, ctx->attr, 0)) {
		ntfs_error(ni->vol->sb,
			   "Could not resize attribute record for removal from MFT record 0x%llx (attr 0x%x).",
			   (unsigned long long)ni->mft_no, le32_to_cpu(type));
		return -EIO;
	}
	if (update_link_count)
		le16_add_cpu(&ctx->mrec->link_count, -1);
	if (operation_lsn)
		ctx->mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ni);

	/*
	 * Remove record from $ATTRIBUTE_LIST if present and we don't want
	 * delete $ATTRIBUTE_LIST itself.
	 */
	if (NInoAttrList(base_ni) && type != AT_ATTRIBUTE_LIST) {
		if (log_handle)
			err = ntfs_attrlist_entry_rm_transacted(log_handle, ctx);
		else
			err = ntfs_attrlist_entry_rm(ctx);
		if (err) {
			ntfs_error(ni->vol->sb,
				   "Could not remove attribute list entry for MFT record 0x%llx (error %d).",
				   (unsigned long long)ni->mft_no, err);
			return err;
		}
	}
	if (log_handle) {
		used = le32_to_cpu(ctx->mrec->bytes_in_use);
		attrs_off = le16_to_cpu(ctx->mrec->attrs_offset);
		if (ni->nr_extents == -1 && attrs_off <= used &&
		    used - attrs_off == 8) {
			ntfs_attr_reinit_search_ctx(ctx);
			return ntfs_mft_record_free_transacted(log_handle, ni);
		}
		return 0;
	}

	/* Post $ATTRIBUTE_LIST delete setup. */
	if (type == AT_ATTRIBUTE_LIST) {
		if (NInoAttrList(base_ni) && base_ni->attr_list)
			kvfree(base_ni->attr_list);
		base_ni->attr_list = NULL;
		NInoClearAttrList(base_ni);
	}

	/* Free MFT record, if it doesn't contain attributes. */
	if (le32_to_cpu(ctx->mrec->bytes_in_use) -
			le16_to_cpu(ctx->mrec->attrs_offset) == 8) {
		err = ntfs_mft_record_free(ni->vol, ni);
		if (err) {
			ntfs_error(base_ni->vol->sb,
				   "Could not free empty MFT record 0x%llx (error %d).",
				   (unsigned long long)ni->mft_no, err);
			return err;
		}
		/* Remove done if we freed base inode. */
		if (ni == base_ni)
			return 0;
		ntfs_inode_close(ni);
		ctx->ntfs_ino = ni = NULL;
	}

	if (type == AT_ATTRIBUTE_LIST || !NInoAttrList(base_ni))
		return 0;

	/* Remove attribute list if we don't need it any more. */
	if (!ntfs_attrlist_need(base_ni)) {
		struct ntfs_attr na;
		struct inode *attr_vi;

		ntfs_attr_reinit_search_ctx(ctx);
		if (ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, CASE_SENSITIVE,
					0, NULL, 0, ctx)) {
			ntfs_debug("Couldn't find attribute list. Succeed anyway.\n");
			return 0;
		}
		/* Deallocate clusters. */
		if (ctx->attr->non_resident) {
			struct runlist_element *al_rl;
			size_t new_rl_count;

			al_rl = ntfs_mapping_pairs_decompress(base_ni->vol,
					ctx->attr, NULL, &new_rl_count);
			if (IS_ERR(al_rl)) {
				ntfs_debug("Couldn't decompress attribute list runlist. Succeed anyway.\n");
				return 0;
			}
			if (ntfs_cluster_free_from_rl(base_ni->vol, al_rl))
				ntfs_debug("Leaking clusters! Run chkdsk. Couldn't free clusters from attribute list runlist.\n");
			kvfree(al_rl);
		}
		/* Remove attribute record itself. */
		if (ntfs_attr_record_rm(ctx)) {
			ntfs_debug("Couldn't remove attribute list. Succeed anyway.\n");
			return 0;
		}

		na.mft_no = VFS_I(base_ni)->i_ino;
		na.type = AT_ATTRIBUTE_LIST;
		na.name = NULL;
		na.name_len = 0;

		attr_vi = ilookup5(VFS_I(base_ni)->i_sb, VFS_I(base_ni)->i_ino,
				   ntfs_test_inode, &na);
		if (attr_vi) {
			clear_nlink(attr_vi);
			iput(attr_vi);
		}

	}
	return 0;
}

int ntfs_attr_record_rm(struct ntfs_attr_search_ctx *ctx)
{
	return __ntfs_attr_record_rm(NULL, ctx);
}

int ntfs_attr_record_rm_transacted(struct ntfs_log_handle *handle,
		struct ntfs_attr_search_ctx *ctx)
{
	if (!handle)
		return -EINVAL;
	return __ntfs_attr_record_rm(handle, ctx);
}

static int ntfs_resident_attr_add_listed_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni,
		__le32 type, __le16 *name, u8 name_len, u8 *val, u32 size,
		u32 attr_rec_size)
{
	struct ntfs_inode *target_ni = NULL;
	struct mft_record *mrec = NULL;
	struct attr_record *attr_copy = NULL;
	int offset;
	int err;
	int i;

	if (!handle || !base_ni || !NInoAttrList(base_ni) ||
	    !base_ni->attr_list || !attr_rec_size)
		return -EINVAL;
	err = ntfs_inode_attach_all_extents(base_ni);
	if (err) {
		ntfs_error(base_ni->vol->sb,
			   "Failed to attach extents while adding attribute 0x%x to inode %llu (error %d).",
			   le32_to_cpu(type),
			   (unsigned long long)base_ni->mft_no, err);
		return err;
	}
	for (i = -1; i < base_ni->nr_extents; i++) {
		target_ni = i < 0 ? base_ni : base_ni->ext.extent_ntfs_inos[i];
		if (!target_ni)
			return -EIO;
		mrec = map_mft_record(target_ni);
		if (IS_ERR(mrec)) {
			err = PTR_ERR(mrec);
			mrec = NULL;
			ntfs_error(base_ni->vol->sb,
				   "Failed to map extent while adding attribute 0x%x to inode %llu (error %d).",
				   le32_to_cpu(type),
				   (unsigned long long)base_ni->mft_no, err);
			return err;
		}
		if (le32_to_cpu(mrec->bytes_in_use) <=
		    le32_to_cpu(mrec->bytes_allocated) &&
		    attr_rec_size <= le32_to_cpu(mrec->bytes_allocated) -
			    le32_to_cpu(mrec->bytes_in_use))
			break;
		unmap_mft_record(target_ni);
		mrec = NULL;
	}
	if (!mrec) {
		target_ni = NULL;
		err = ntfs_mft_record_alloc_transacted(handle, base_ni->vol,
				&target_ni, base_ni, &mrec);
		if (err) {
			ntfs_error(base_ni->vol->sb,
				   "Failed to allocate extent while adding attribute 0x%x to inode %llu (error %d).",
				   le32_to_cpu(type),
				   (unsigned long long)base_ni->mft_no, err);
			return err;
		}
	}
	/* Filename record logging registers its own home undo. */
	err = type == AT_FILE_NAME ? 0 :
		ntfs_attr_mft_register_home_undo(handle, target_ni, mrec);
	unmap_mft_record(target_ni);
	mrec = NULL;
	if (err) {
		ntfs_error(base_ni->vol->sb,
			   "Failed to register extent undo while adding attribute 0x%x to inode %llu (error %d).",
			   le32_to_cpu(type),
			   (unsigned long long)base_ni->mft_no, err);
		return err;
	}
	offset = __ntfs_resident_attr_record_add(handle, target_ni, type,
			name, name_len, val, size, 0);
	if (offset < 0) {
		ntfs_error(base_ni->vol->sb,
			   "Failed to add resident attribute 0x%x to extent of inode %llu (error %d).",
			   le32_to_cpu(type),
			   (unsigned long long)base_ni->mft_no, offset);
		return offset;
	}
	mrec = map_mft_record(target_ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	if (offset > le32_to_cpu(mrec->bytes_in_use) ||
	    attr_rec_size > le32_to_cpu(mrec->bytes_in_use) - offset) {
		err = -EIO;
		goto out_unmap;
	}
	if (le32_to_cpu(((struct attr_record *)((u8 *)mrec + offset))->length) !=
	    attr_rec_size) {
		err = -EIO;
		goto out_unmap;
	}
	attr_copy = kmemdup((u8 *)mrec + offset, attr_rec_size, GFP_NOFS);
	if (!attr_copy) {
		err = -ENOMEM;
		goto out_unmap;
	}
	unmap_mft_record(target_ni);
	mrec = NULL;
	err = ntfs_attrlist_entry_add_transacted(handle, target_ni,
			attr_copy);
	kfree(attr_copy);
	if (err)
		ntfs_error(base_ni->vol->sb,
			   "Failed to add attribute-list entry for attribute 0x%x on inode %llu (error %d).",
			   le32_to_cpu(type),
			   (unsigned long long)base_ni->mft_no, err);
	return err;

out_unmap:
	unmap_mft_record(target_ni);
	kfree(attr_copy);
	return err;
}

static int ntfs_non_resident_attr_add_listed_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni,
		__le32 type, __le16 *name, u8 name_len, __le16 flags,
		u32 attr_rec_size)
{
	struct ntfs_inode *target_ni = NULL;
	struct mft_record *mrec = NULL;
	struct attr_record *attr_copy = NULL;
	u32 attr_len;
	int offset;
	int err;
	int i;

	if (!handle || !base_ni || !NInoAttrList(base_ni) ||
		!base_ni->attr_list || !attr_rec_size)
		return -EINVAL;
	err = ntfs_inode_attach_all_extents(base_ni);
	if (err) {
		ntfs_error(base_ni->vol->sb,
			   "Failed to attach extents while adding non-resident attribute 0x%x to inode %llu (error %d).",
			   le32_to_cpu(type),
			   (unsigned long long)base_ni->mft_no, err);
		return err;
	}
	for (i = -1; i < base_ni->nr_extents; i++) {
		target_ni = i < 0 ? base_ni : base_ni->ext.extent_ntfs_inos[i];
		if (!target_ni)
			return -EIO;
		mrec = map_mft_record(target_ni);
		if (IS_ERR(mrec)) {
			err = PTR_ERR(mrec);
			mrec = NULL;
			return err;
		}
		if (le32_to_cpu(mrec->bytes_in_use) <=
				le32_to_cpu(mrec->bytes_allocated) &&
			attr_rec_size <= le32_to_cpu(mrec->bytes_allocated) -
					le32_to_cpu(mrec->bytes_in_use))
			break;
		unmap_mft_record(target_ni);
		mrec = NULL;
	}
	if (!mrec) {
		target_ni = NULL;
		err = ntfs_mft_record_alloc_transacted(handle, base_ni->vol,
				&target_ni, base_ni, &mrec);
		if (err) {
			ntfs_error(base_ni->vol->sb,
				   "Failed to allocate extent while adding non-resident attribute 0x%x to inode %llu (error %d).",
				   le32_to_cpu(type),
				   (unsigned long long)base_ni->mft_no, err);
			return err;
		}
	}
	err = ntfs_attr_mft_register_home_undo(handle, target_ni, mrec);
	unmap_mft_record(target_ni);
	mrec = NULL;
	if (err)
		return err;
	offset = ntfs_non_resident_attr_record_add_transacted(handle,
			target_ni, type, name, name_len, 0, 8, flags);
	if (offset < 0) {
		ntfs_error(base_ni->vol->sb,
			   "Failed to add non-resident attribute 0x%x to inode %llu (error %d).",
			   le32_to_cpu(type),
			   (unsigned long long)base_ni->mft_no, offset);
		return offset;
	}
	mrec = map_mft_record(target_ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	if (offset > le32_to_cpu(mrec->bytes_in_use) ||
		le32_to_cpu(mrec->bytes_in_use) - offset <
				(u32)offsetof(struct attr_record,
					data.non_resident.compressed_size)) {
		err = -EIO;
		goto out_unmap;
	}
	attr_len = le32_to_cpu(((struct attr_record *)((u8 *)mrec + offset))->length);
	if (!attr_len || attr_len > le32_to_cpu(mrec->bytes_in_use) - offset ||
		attr_len != attr_rec_size) {
		err = -EIO;
		goto out_unmap;
	}
	attr_copy = kmemdup((u8 *)mrec + offset, attr_len, GFP_NOFS);
	if (!attr_copy) {
		err = -ENOMEM;
		goto out_unmap;
	}
	unmap_mft_record(target_ni);
	mrec = NULL;
	err = ntfs_attrlist_entry_add_transacted(handle, target_ni,
			attr_copy);
	kfree(attr_copy);
	return err;

out_unmap:
	unmap_mft_record(target_ni);
	kfree(attr_copy);
	return err;
}

/*
 * ntfs_attr_add - add attribute to inode
 * @ni:		opened ntfs inode to which add attribute
 * @type:	type of the new attribute
 * @name:	name in unicode of the new attribute
 * @name_len:	name length in unicode characters of the new attribute
 * @val:	value of new attribute
 * @size:	size of the new attribute / length of @val (if specified)
 *
 * @val should always be specified for always resident attributes (eg. FILE_NAME
 * attribute), for attributes that can become non-resident @val can be NULL
 * (eg. DATA attribute). @size can be specified even if @val is NULL, in this
 * case data size will be equal to @size and initialized size will be equal
 * to 0.
 *
 * If inode haven't got enough space to add attribute, add attribute to one of
 * it extents, if no extents present or no one of them have enough space, than
 * allocate new extent and add attribute to it.
 *
 * If on one of this steps attribute list is needed but not present, than it is
 * added transparently to caller. So, this function should not be called with
 * @type == AT_ATTRIBUTE_LIST, if you really need to add attribute list call
 * ntfs_inode_add_attrlist instead.
 *
 * On success return 0. On error return -1 with errno set to the error code.
 */
static int __ntfs_attr_add(struct ntfs_log_handle *log_handle,
		struct ntfs_inode *ni, __le32 type, __le16 *name, u8 name_len,
		u8 *val, s64 size)
{
	struct super_block *sb;
	u32 attr_rec_size;
	int err, i, offset;
	bool is_resident;
	bool can_be_non_resident = false;
	struct ntfs_inode *attr_ni;
	struct inode *attr_vi;
	struct mft_record *ni_mrec;

	if (!ni || size < 0 || type == AT_ATTRIBUTE_LIST)
		return -EINVAL;

	ntfs_debug("Entering for inode 0x%llx, attr %x, size %lld.\n",
			(long long) ni->mft_no, type, size);

	if (ni->nr_extents == -1)
		ni = ni->ext.base_ntfs_ino;

	/* Check the attribute type and the size. */
	err = ntfs_attr_size_bounds_check(ni->vol, type, size);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		return err;
	}

	sb = ni->vol->sb;
	/* Sanity checks for always resident attributes. */
	err = ntfs_attr_can_be_non_resident(ni->vol, type);
	if (err) {
		if (err != -EPERM) {
			ntfs_error(sb, "ntfs_attr_can_be_non_resident failed");
			goto err_out;
		}
		/* @val is mandatory. */
		if (!val) {
			ntfs_error(sb,
				"val is mandatory for always resident attributes");
			return -EINVAL;
		}
		if (size > ni->vol->mft_record_size) {
			ntfs_error(sb, "Attribute is too big");
			return -ERANGE;
		}
	} else
		can_be_non_resident = true;

	/*
	 * Determine resident or not will be new attribute. We add 8 to size in
	 * non resident case for mapping pairs.
	 */
	err = ntfs_attr_can_be_resident(ni->vol, type);
	if (!err) {
		is_resident = true;
	} else {
		if (err != -EPERM) {
			ntfs_error(sb, "ntfs_attr_can_be_resident failed");
			goto err_out;
		}
		is_resident = false;
	}
	if (log_handle && !is_resident && size)
		return -EOPNOTSUPP;

	/* Calculate attribute record size. */
	if (is_resident)
		attr_rec_size = offsetof(struct attr_record, data.resident.reserved) +
			1 +
			((name_len * sizeof(__le16) + 7) & ~7) +
			((size + 7) & ~7);
	else
		attr_rec_size = offsetof(struct attr_record, data.non_resident.compressed_size) +
			((name_len * sizeof(__le16) + 7) & ~7) + 8;
	if (log_handle && NInoAttrList(ni)) {
		if (!is_resident) {
			if (size)
				return -EOPNOTSUPP;
			return ntfs_non_resident_attr_add_listed_transacted(log_handle,
					ni, type, name, name_len, 0, attr_rec_size);
		}
		return ntfs_resident_attr_add_listed_transacted(log_handle, ni,
				type, name, name_len, val, size, attr_rec_size);
	}

	/*
	 * If we have enough free space for the new attribute in the base MFT
	 * record, then add attribute to it.
	 */
retry:
	ni_mrec = map_mft_record(ni);
	if (IS_ERR(ni_mrec)) {
		err = -EIO;
		goto err_out;
	}

	if (le32_to_cpu(ni_mrec->bytes_allocated) -
			le32_to_cpu(ni_mrec->bytes_in_use) >= attr_rec_size) {
		/* An EA update can fail after creating its first attribute. */
		if (log_handle &&
		    (type == AT_EA || type == AT_EA_INFORMATION)) {
			err = ntfs_attr_mft_register_home_undo(log_handle, ni,
					ni_mrec);
			if (err) {
				unmap_mft_record(ni);
				goto err_out;
			}
		}
		attr_ni = ni;
		unmap_mft_record(ni);
		goto add_attr_record;
	}
	unmap_mft_record(ni);
	if (log_handle) {
		/*
		 * A transaction may need to add a resident attribute after the
		 * base record has run out of room.  The non-transactional path
		 * creates an attribute list and places the new record in an extent.
		 * Keep the same on-disk layout for the WAL path instead of failing
		 * merely because the base record is full.
		 */
		if (!is_resident) {
			if (size)
				return -EOPNOTSUPP;
			if (!NInoAttrList(ni)) {
				err = ntfs_inode_add_attrlist_transacted(log_handle, ni);
				if (err) {
					ntfs_error(sb,
						   "Failed to create attribute list while adding non-resident attribute 0x%x to inode %llu (error %d).",
						   le32_to_cpu(type),
						   (unsigned long long)ni->mft_no, err);
					goto err_out;
				}
			}
			return ntfs_non_resident_attr_add_listed_transacted(log_handle,
					ni, type, name, name_len, 0, attr_rec_size);
		}
		if (!NInoAttrList(ni)) {
			err = ntfs_inode_add_attrlist_transacted(log_handle, ni);
			if (err) {
				ntfs_error(sb,
					   "Failed to create attribute list while adding attribute 0x%x to inode %llu (error %d).",
					   le32_to_cpu(type),
					   (unsigned long long)ni->mft_no, err);
				goto err_out;
			}
		}
		err = ntfs_resident_attr_add_listed_transacted(log_handle, ni,
				type, name, name_len, val, size, attr_rec_size);
		if (err)
			ntfs_error(sb,
				   "Failed to add listed resident attribute 0x%x to inode %llu (error %d).",
				   le32_to_cpu(type),
				   (unsigned long long)ni->mft_no, err);
		return err;
	}

	/* Try to add to extent inodes. */
	err = ntfs_inode_attach_all_extents(ni);
	if (err) {
		ntfs_error(sb, "Failed to attach all extents to inode");
		goto err_out;
	}

	for (i = 0; i < ni->nr_extents; i++) {
		attr_ni = ni->ext.extent_ntfs_inos[i];
		ni_mrec = map_mft_record(attr_ni);
		if (IS_ERR(ni_mrec)) {
			err = -EIO;
			goto err_out;
		}

		if (le32_to_cpu(ni_mrec->bytes_allocated) -
				le32_to_cpu(ni_mrec->bytes_in_use) >=
				attr_rec_size) {
			unmap_mft_record(attr_ni);
			goto add_attr_record;
		}
		unmap_mft_record(attr_ni);
	}

	/* There is no extent that contain enough space for new attribute. */
	if (!NInoAttrList(ni)) {
		/* Add attribute list not present, add it and retry. */
		err = ntfs_inode_add_attrlist(ni);
		if (err) {
			ntfs_error(sb, "Failed to add attribute list");
			goto err_out;
		}
		goto retry;
	}

	attr_ni = NULL;
	/* Allocate new extent. */
	err = ntfs_mft_record_alloc(ni->vol, 0, &attr_ni, ni, NULL, -1);
	if (err) {
		ntfs_error(sb, "Failed to allocate extent record");
		goto err_out;
	}
	unmap_mft_record(attr_ni);

add_attr_record:
	if (is_resident) {
		/* Add resident attribute. */
		offset = __ntfs_resident_attr_record_add(log_handle, attr_ni,
				type, name, name_len, val, size, 0);
		if (offset < 0) {
			if (offset == -ENOSPC && can_be_non_resident)
				goto add_non_resident;
			err = offset;
			ntfs_error(sb, "Failed to add resident attribute");
			goto free_err_out;
		}
		return 0;
	}

add_non_resident:
	if (log_handle && size) {
		err = -EOPNOTSUPP;
		goto err_out;
	}
	/* Add non resident attribute. */
	offset = ntfs_non_resident_attr_record_add(log_handle, attr_ni, type,
			name, name_len, 0, 8, 0);
	if (offset < 0) {
		err = offset;
		ntfs_error(sb, "Failed to add non resident attribute");
		goto free_err_out;
	}

	/* If @size == 0, we are done. */
	if (!size)
		return 0;

	/* Open new attribute and resize it. */
	attr_vi = ntfs_attr_iget(VFS_I(ni), type, name, name_len);
	if (IS_ERR(attr_vi)) {
		err = PTR_ERR(attr_vi);
		ntfs_error(sb, "Failed to open just added attribute");
		goto rm_attr_err_out;
	}
	attr_ni = NTFS_I(attr_vi);

	/* Resize and set attribute value. */
	if (ntfs_attr_truncate(attr_ni, size) ||
		(val && (ntfs_inode_attr_pwrite(attr_vi, 0, size, val, false) != size))) {
		err = -EIO;
		ntfs_error(sb, "Failed to initialize just added attribute");
		if (ntfs_attr_rm(attr_ni))
			ntfs_error(sb, "Failed to remove just added attribute");
		iput(attr_vi);
		goto err_out;
	}
	iput(attr_vi);
	return 0;

rm_attr_err_out:
	/* Remove just added attribute. */
	ni_mrec = map_mft_record(attr_ni);
	if (!IS_ERR(ni_mrec)) {
		if (ntfs_attr_record_resize(ni_mrec,
					(struct attr_record *)((u8 *)ni_mrec + offset), 0))
			ntfs_error(sb, "Failed to remove just added attribute #2");
		unmap_mft_record(attr_ni);
	} else
		pr_err("EIO when try to remove new added attr\n");

free_err_out:
	/* Free MFT record, if it doesn't contain attributes. */
	ni_mrec = map_mft_record(attr_ni);
	if (!IS_ERR(ni_mrec)) {
		int attr_size;

		attr_size = le32_to_cpu(ni_mrec->bytes_in_use) -
			le16_to_cpu(ni_mrec->attrs_offset);
		unmap_mft_record(attr_ni);
		if (attr_size == 8) {
			if (ntfs_mft_record_free(attr_ni->vol, attr_ni))
				ntfs_error(sb, "Failed to free MFT record");
			if (attr_ni->nr_extents < 0)
				ntfs_inode_close(attr_ni);
		}
	} else
		pr_err("EIO when testing mft record is free-able\n");

err_out:
	return err;
}

int ntfs_attr_add(struct ntfs_inode *ni, __le32 type,
		__le16 *name, u8 name_len, u8 *val, s64 size)
{
	return __ntfs_attr_add(NULL, ni, type, name, name_len, val, size);
}

int ntfs_attr_add_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, __le32 type, __le16 *name, u8 name_len,
		u8 *val, s64 size)
{
	if (!handle)
		return -EINVAL;
	return __ntfs_attr_add(handle, ni, type, name, name_len, val, size);
}

/*
 * __ntfs_attr_init - primary initialization of an ntfs attribute structure
 * @ni:		ntfs attribute inode to initialize
 * @ni:		ntfs inode with which to initialize the ntfs attribute
 * @type:	attribute type
 * @name:	attribute name in little endian Unicode or NULL
 * @name_len:	length of attribute @name in Unicode characters (if @name given)
 *
 * Initialize the ntfs attribute @na with @ni, @type, @name, and @name_len.
 */
static void __ntfs_attr_init(struct ntfs_inode *ni,
		const __le32 type, __le16 *name, const u32 name_len)
{
	ni->runlist.rl = NULL;
	ni->type = type;
	ni->name = name;
	if (name)
		ni->name_len = name_len;
	else
		ni->name_len = 0;
}

/*
 * ntfs_attr_init - initialize an ntfs_attr with data sizes and status
 * @ni: ntfs inode to initialize
 * @non_resident: true if attribute is non-resident
 * @compressed: true if attribute is compressed
 * @encrypted: true if attribute is encrypted
 * @sparse: true if attribute is sparse
 * @allocated_size: allocated size of the attribute
 * @data_size: actual data size of the attribute
 * @initialized_size: initialized size of the attribute
 * @compressed_size: compressed size (if compressed or sparse)
 * @compression_unit: compression unit size (log2 of clusters)
 *
 * Final initialization for an ntfs attribute.
 */
static void ntfs_attr_init(struct ntfs_inode *ni, const bool non_resident,
		const bool compressed, const bool encrypted, const bool sparse,
		const s64 allocated_size, const s64 data_size,
		const s64 initialized_size, const s64 compressed_size,
		const u8 compression_unit)
{
	if (non_resident)
		NInoSetNonResident(ni);
	if (compressed) {
		NInoSetCompressed(ni);
		ni->flags |= FILE_ATTR_COMPRESSED;
	}
	if (encrypted) {
		NInoSetEncrypted(ni);
		ni->flags |= FILE_ATTR_ENCRYPTED;
	}
	if (sparse) {
		NInoSetSparse(ni);
		ni->flags |= FILE_ATTR_SPARSE_FILE;
	}
	ni->allocated_size = allocated_size;
	ni->data_size = data_size;
	ni->initialized_size = initialized_size;
	if (compressed || sparse) {
		struct ntfs_volume *vol = ni->vol;

		ni->itype.compressed.size = compressed_size;
		ni->itype.compressed.block_clusters = 1 << compression_unit;
		ni->itype.compressed.block_size = 1 << (compression_unit +
				vol->cluster_size_bits);
		ni->itype.compressed.block_size_bits = ffs(
				ni->itype.compressed.block_size) - 1;
	}
}

/*
 * ntfs_attr_open - open an ntfs attribute for access
 * @ni:		open ntfs inode in which the ntfs attribute resides
 * @type:	attribute type
 * @name:	attribute name in little endian Unicode or AT_UNNAMED or NULL
 * @name_len:	length of attribute @name in Unicode characters (if @name given)
 */
int ntfs_attr_open(struct ntfs_inode *ni, const __le32 type,
		__le16 *name, u32 name_len)
{
	struct ntfs_attr_search_ctx *ctx;
	__le16 *newname = NULL;
	struct attr_record *a;
	bool cs;
	struct ntfs_inode *base_ni;
	u32 ic;
	int err;

	if (!ni || !ni->vol)
		return -EINVAL;

	ntfs_debug("Entering for inode %lld, attr 0x%x.\n",
			ni->mft_no, type);

	base_ni = ntfs_base_inode(ni);

	if (name && name != AT_UNNAMED && name != I30) {
		name = ntfs_ucsndup(name, name_len);
		if (!name) {
			err = -ENOMEM;
			goto err_out;
		}
		newname = name;
	}

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		pr_err("%s: Failed to get search context\n", __func__);
		goto err_out;
	}

	ic = type == AT_DATA && name_len ? IGNORE_CASE : CASE_SENSITIVE;
	err = ntfs_attr_lookup(type, name, name_len, ic, 0, NULL, 0, ctx);
	if (err)
		goto put_err_out;

	a = ctx->attr;

	if (!name) {
		if (a->name_length) {
			name = ntfs_ucsndup((__le16 *)((u8 *)a + le16_to_cpu(a->name_offset)),
					    a->name_length);
			if (!name)
				goto put_err_out;
			newname = name;
			name_len = a->name_length;
		} else {
			name = AT_UNNAMED;
			name_len = 0;
		}
	}

	__ntfs_attr_init(ni, type, name, name_len);

	/*
	 * Wipe the flags in case they are not zero for an attribute list
	 * attribute.  Windows does not complain about invalid flags and chkdsk
	 * does not detect or fix them so we need to cope with it, too.
	 */
	if (type == AT_ATTRIBUTE_LIST)
		a->flags = 0;

	if ((type == AT_DATA) &&
	    (a->non_resident ? !a->data.non_resident.initialized_size :
	     !a->data.resident.value_length)) {
		/*
		 * Define/redefine the compression state if stream is
		 * empty, based on the compression mark on parent
		 * directory (for unnamed data streams) or on current
		 * inode (for named data streams). The compression mark
		 * may change any time, the compression state can only
		 * change when stream is wiped out.
		 *
		 * Also prevent compression on NTFS version < 3.0
		 * or cluster size > 4K or compression is disabled
		 */
		a->flags &= ~ATTR_COMPRESSION_MASK;
		if (NInoCompressed(ni)
				&& (ni->vol->major_ver >= 3)
				&& NVolCompression(ni->vol)
				&& (ni->vol->cluster_size <= MAX_COMPRESSION_CLUSTER_SIZE))
			a->flags |= ATTR_IS_COMPRESSED;
	}

	cs = a->flags & (ATTR_IS_COMPRESSED | ATTR_IS_SPARSE);

	if (ni->type == AT_DATA && ni->name == AT_UNNAMED &&
	    ((!(a->flags & ATTR_IS_COMPRESSED) != !NInoCompressed(ni)) ||
	     (!(a->flags & ATTR_IS_SPARSE)     != !NInoSparse(ni)) ||
	     (!(a->flags & ATTR_IS_ENCRYPTED)  != !NInoEncrypted(ni)))) {
		err = -EIO;
		pr_err("Inode %lld has corrupt attribute flags (0x%x <> 0x%x)\n",
				(unsigned long long)ni->mft_no,
				a->flags, ni->flags);
		goto put_err_out;
	}

	if (a->non_resident) {
		if (((a->flags & ATTR_COMPRESSION_MASK) || a->data.non_resident.compression_unit) &&
				(ni->vol->major_ver < 3)) {
			err = -EIO;
			pr_err("Compressed inode %lld not allowed  on NTFS %d.%d\n",
					(unsigned long long)ni->mft_no,
					ni->vol->major_ver,
					ni->vol->major_ver);
			goto put_err_out;
		}

		if ((a->flags & ATTR_IS_COMPRESSED) && !a->data.non_resident.compression_unit) {
			err = -EIO;
			pr_err("Compressed inode %lld attr 0x%x has no compression unit\n",
					(unsigned long long)ni->mft_no, type);
			goto put_err_out;
		}
		if ((a->flags & ATTR_COMPRESSION_MASK) &&
		    (a->data.non_resident.compression_unit != STANDARD_COMPRESSION_UNIT)) {
			err = -EIO;
			pr_err("Compressed inode %lld attr 0x%lx has an unsupported compression unit %d\n",
					(unsigned long long)ni->mft_no,
					(long)le32_to_cpu(type),
					(int)a->data.non_resident.compression_unit);
			goto put_err_out;
		}
		ntfs_attr_init(ni, true, a->flags & ATTR_IS_COMPRESSED,
				a->flags & ATTR_IS_ENCRYPTED,
				a->flags & ATTR_IS_SPARSE,
				le64_to_cpu(a->data.non_resident.allocated_size),
				le64_to_cpu(a->data.non_resident.data_size),
				le64_to_cpu(a->data.non_resident.initialized_size),
				cs ? le64_to_cpu(a->data.non_resident.compressed_size) : 0,
				cs ? a->data.non_resident.compression_unit : 0);
	} else {
		s64 l = le32_to_cpu(a->data.resident.value_length);

		ntfs_attr_init(ni, false, a->flags & ATTR_IS_COMPRESSED,
				a->flags & ATTR_IS_ENCRYPTED,
				a->flags & ATTR_IS_SPARSE, (l + 7) & ~7, l, l,
				cs ? (l + 7) & ~7 : 0, 0);
	}
	ntfs_attr_put_search_ctx(ctx);
out:
	ntfs_debug("\n");
	return err;

put_err_out:
	ntfs_attr_put_search_ctx(ctx);
err_out:
	kfree(newname);
	goto out;
}

/*
 * ntfs_attr_close - free an ntfs attribute structure
 * @ni:		ntfs inode to free
 *
 * Release all memory associated with the ntfs attribute @na and then release
 * @na itself.
 */
void ntfs_attr_close(struct ntfs_inode *ni)
{
	if (NInoNonResident(ni) && ni->runlist.rl)
		kvfree(ni->runlist.rl);
	/* Don't release if using an internal constant. */
	if (ni->name != AT_UNNAMED && ni->name != I30)
		kfree(ni->name);
}

/*
 * ntfs_attr_map_whole_runlist - map the whole runlist of an ntfs attribute
 * @ni:		ntfs inode for which to map the runlist
 *
 * Map the whole runlist of the ntfs attribute @na.  For an attribute made up
 * of only one attribute extent this is the same as calling
 * ntfs_map_runlist(ni, 0) but for an attribute with multiple extents this
 * will map the runlist fragments from each of the extents thus giving access
 * to the entirety of the disk allocation of an attribute.
 */
int ntfs_attr_map_whole_runlist(struct ntfs_inode *ni)
{
	s64 next_vcn, last_vcn, highest_vcn;
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_volume *vol = ni->vol;
	struct super_block *sb = vol->sb;
	struct attr_record *a;
	int err;
	struct ntfs_inode *base_ni;
	int not_mapped;
	size_t new_rl_count;

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x.\n",
			(unsigned long long)ni->mft_no, ni->type);

	if (NInoFullyMapped(ni) && ni->runlist.rl)
		return 0;

	if (NInoAttr(ni))
		base_ni = ni->ext.base_ntfs_ino;
	else
		base_ni = ni;

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		ntfs_error(sb, "%s: Failed to get search context", __func__);
		return -ENOMEM;
	}

	/* Map all attribute extents one by one. */
	next_vcn = last_vcn = highest_vcn = 0;
	a = NULL;
	while (1) {
		struct runlist_element *rl;

		not_mapped = 0;
		if (ntfs_rl_vcn_to_lcn(ni->runlist.rl, next_vcn) == LCN_RL_NOT_MAPPED)
			not_mapped = 1;

		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
					CASE_SENSITIVE, next_vcn,
					NULL, 0, ctx);
		if (err)
			break;

		a = ctx->attr;

		if (not_mapped) {
			/* Decode the runlist. */
			rl = ntfs_mapping_pairs_decompress(ni->vol, a, &ni->runlist,
							   &new_rl_count);
			if (IS_ERR(rl)) {
				err = PTR_ERR(rl);
				goto err_out;
			}
			ni->runlist.rl = rl;
			ni->runlist.count = new_rl_count;
		}

		/* Are we in the first extent? */
		if (!next_vcn) {
			if (a->data.non_resident.lowest_vcn) {
				err = -EIO;
				ntfs_error(sb,
					"First extent of inode %llu attribute has non-zero lowest_vcn",
					(unsigned long long)ni->mft_no);
				goto err_out;
			}
			/* Get the last vcn in the attribute. */
			last_vcn = ntfs_bytes_to_cluster(vol,
					le64_to_cpu(a->data.non_resident.allocated_size));
		}

		/* Get the lowest vcn for the next extent. */
		highest_vcn = le64_to_cpu(a->data.non_resident.highest_vcn);
		next_vcn = highest_vcn + 1;

		/* Only one extent or error, which we catch below. */
		if (next_vcn <= 0) {
			err = -ENOENT;
			break;
		}

		/* Avoid endless loops due to corruption. */
		if (next_vcn < le64_to_cpu(a->data.non_resident.lowest_vcn)) {
			err = -EIO;
			ntfs_error(sb, "Inode %llu has corrupt attribute list",
					(unsigned long long)ni->mft_no);
			goto err_out;
		}
	}
	if (!a) {
		ntfs_error(sb, "Couldn't find attribute for runlist mapping");
		goto err_out;
	}
	if (not_mapped && highest_vcn && highest_vcn != last_vcn - 1) {
		err = -EIO;
		ntfs_error(sb,
			"Failed to load full runlist: inode: %llu highest_vcn: 0x%llx last_vcn: 0x%llx",
			(unsigned long long)ni->mft_no,
			(long long)highest_vcn, (long long)last_vcn);
		goto err_out;
	}
	ntfs_attr_put_search_ctx(ctx);
	if (err == -ENOENT) {
		NInoSetFullyMapped(ni);
		return 0;
	}

	return err;

err_out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

/*
 * ntfs_attr_record_move_to - move attribute record to target inode
 * @ctx:	attribute search context describing the attribute record
 * @ni:		opened ntfs inode to which move attribute record
 */
int ntfs_attr_record_move_to(struct ntfs_attr_search_ctx *ctx, struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *nctx;
	struct attr_record *a;
	int err;
	u32 ic;
	struct mft_record *ni_mrec;
	struct super_block *sb;

	if (!ctx || !ctx->attr || !ctx->ntfs_ino || !ni) {
		ntfs_debug("Invalid arguments passed.\n");
		return -EINVAL;
	}

	sb = ni->vol->sb;
	ntfs_debug("Entering for ctx->attr->type 0x%x, ctx->ntfs_ino->mft_no 0x%llx, ni->mft_no 0x%llx.\n",
			(unsigned int) le32_to_cpu(ctx->attr->type),
			(long long) ctx->ntfs_ino->mft_no,
			(long long) ni->mft_no);

	if (ctx->ntfs_ino == ni)
		return 0;

	if (!ctx->al_entry) {
		ntfs_debug("Inode should contain attribute list to use this function.\n");
		return -EINVAL;
	}

	/* Find place in MFT record where attribute will be moved. */
	a = ctx->attr;
	nctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!nctx) {
		ntfs_error(sb, "%s: Failed to get search context", __func__);
		return -ENOMEM;
	}

	/*
	 * Use ntfs_attr_find instead of ntfs_attr_lookup to find place for
	 * attribute in @ni->mrec, not any extent inode in case if @ni is base
	 * file record.
	 */
	ic = a->type == AT_DATA && a->name_length ?
			IGNORE_CASE : CASE_SENSITIVE;
	err = ntfs_attr_find(a->type,
			(__le16 *)((u8 *)a + le16_to_cpu(a->name_offset)),
			a->name_length, ic, NULL, 0, nctx);
	if (!err) {
		ntfs_debug("Attribute of such type, with same name already present in this MFT record.\n");
		err = -EEXIST;
		goto put_err_out;
	}
	if (err != -ENOENT) {
		ntfs_debug("Attribute lookup failed.\n");
		goto put_err_out;
	}

	/* Make space and move attribute. */
	ni_mrec = map_mft_record(ni);
	if (IS_ERR(ni_mrec)) {
		err = -EIO;
		goto put_err_out;
	}

	err = ntfs_make_room_for_attr(ni_mrec, (u8 *) nctx->attr,
				le32_to_cpu(a->length));
	if (err) {
		ntfs_debug("Couldn't make space for attribute.\n");
		unmap_mft_record(ni);
		goto put_err_out;
	}
	memcpy(nctx->attr, a, le32_to_cpu(a->length));
	nctx->attr->instance = nctx->mrec->next_attr_instance;
	nctx->mrec->next_attr_instance =
		cpu_to_le16((le16_to_cpu(nctx->mrec->next_attr_instance) + 1) & 0xffff);
	ntfs_attr_record_resize(ctx->mrec, a, 0);
	mark_mft_record_dirty(ctx->ntfs_ino);
	mark_mft_record_dirty(ni);

	/* Update attribute list. */
	ctx->al_entry->mft_reference =
		MK_LE_MREF(ni->mft_no, le16_to_cpu(ni_mrec->sequence_number));
	ctx->al_entry->instance = nctx->attr->instance;
	unmap_mft_record(ni);
put_err_out:
	ntfs_attr_put_search_ctx(nctx);
	return err;
}

/*
 * ntfs_attr_record_move_away - move away attribute record from it's mft record
 * @ctx:	attribute search context describing the attribute record
 * @extra:	minimum amount of free space in the new holder of record
 */
int ntfs_attr_record_move_away(struct ntfs_attr_search_ctx *ctx, int extra)
{
	struct ntfs_inode *base_ni, *ni = NULL;
	struct mft_record *m;
	int i, err;
	struct super_block *sb;

	if (!ctx || !ctx->attr || !ctx->ntfs_ino || extra < 0)
		return -EINVAL;

	ntfs_debug("Entering for attr 0x%x, inode %llu\n",
			(unsigned int) le32_to_cpu(ctx->attr->type),
			(unsigned long long)ctx->ntfs_ino->mft_no);

	if (ctx->ntfs_ino->nr_extents == -1)
		base_ni = ctx->base_ntfs_ino;
	else
		base_ni = ctx->ntfs_ino;

	sb = ctx->ntfs_ino->vol->sb;
	if (!NInoAttrList(base_ni)) {
		ntfs_error(sb, "Inode %llu has no attrlist",
				(unsigned long long)base_ni->mft_no);
		return -EINVAL;
	}

	err = ntfs_inode_attach_all_extents(ctx->ntfs_ino);
	if (err) {
		ntfs_error(sb, "Couldn't attach extents, inode=%llu",
			(unsigned long long)base_ni->mft_no);
		return err;
	}

	mutex_lock(&base_ni->extent_lock);
	/* Walk through all extents and try to move attribute to them. */
	for (i = 0; i < base_ni->nr_extents; i++) {
		ni = base_ni->ext.extent_ntfs_inos[i];

		if (ctx->ntfs_ino->mft_no == ni->mft_no)
			continue;
		m = map_mft_record(ni);
		if (IS_ERR(m)) {
			ntfs_error(sb, "Can not map mft record for mft_no %lld",
					(unsigned long long)ni->mft_no);
			mutex_unlock(&base_ni->extent_lock);
			return -EIO;
		}
		if (le32_to_cpu(m->bytes_allocated) -
		    le32_to_cpu(m->bytes_in_use) < le32_to_cpu(ctx->attr->length) + extra) {
			unmap_mft_record(ni);
			continue;
		}
		unmap_mft_record(ni);

		/*
		 * ntfs_attr_record_move_to can fail if extent with other lowest
		 * s64 already present in inode we trying move record to. So,
		 * do not return error.
		 */
		if (!ntfs_attr_record_move_to(ctx, ni)) {
			mutex_unlock(&base_ni->extent_lock);
			return 0;
		}
	}
	mutex_unlock(&base_ni->extent_lock);

	/*
	 * Failed to move attribute to one of the current extents, so allocate
	 * new extent and move attribute to it.
	 */
	ni = NULL;
	err = ntfs_mft_record_alloc(base_ni->vol, 0, &ni, base_ni, NULL, -1);
	if (err) {
		ntfs_error(sb, "Couldn't allocate MFT record, err : %d", err);
		return err;
	}
	unmap_mft_record(ni);

	err = ntfs_attr_record_move_to(ctx, ni);
	if (err) {
		ntfs_error(sb, "Couldn't move attribute to MFT record");
		if (ntfs_mft_record_free(base_ni->vol, ni))
			ntfs_error(sb, "Couldn't free empty MFT record");
		else
			ntfs_inode_close(ni);
	}

	return err;
}

static struct inode *ntfs_attr_accounting_inode(struct ntfs_inode *ni)
{
	return VFS_I(ntfs_inode_is_named_stream(ni) ? ni : ntfs_base_inode(ni));
}

/*
 * If we are in the first extent, then set/clean sparse bit,
 * update allocated and compressed size.
 */
static int ntfs_attr_update_meta(struct attr_record *a, struct ntfs_inode *ni,
		struct mft_record *m, struct ntfs_attr_search_ctx *ctx,
		struct ntfs_inode *locked_ni, bool defer_attrlist)
{
	int sparse, err = 0;
	struct ntfs_inode *base_ni;
	struct super_block *sb = ni->vol->sb;

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x\n",
			(unsigned long long)ni->mft_no, ni->type);

	if (NInoAttr(ni))
		base_ni = ni->ext.base_ntfs_ino;
	else
		base_ni = ni;

	if (a->data.non_resident.lowest_vcn)
		goto out;

	a->data.non_resident.allocated_size = cpu_to_le64(ni->allocated_size);

	sparse = ntfs_rl_sparse(ni->runlist.rl);
	if (sparse < 0) {
		err = -EIO;
		goto out;
	}

	/* Attribute become sparse. */
	if (sparse && !(a->flags & (ATTR_IS_SPARSE | ATTR_IS_COMPRESSED))) {
		/*
		 * Move attribute to another mft record, if attribute is too
		 * small to add compressed_size field to it and we have no
		 * free space in the current mft record.
		 */
		if ((le32_to_cpu(a->length) -
		     le16_to_cpu(a->data.non_resident.mapping_pairs_offset) == 8) &&
		    !(le32_to_cpu(m->bytes_allocated) - le32_to_cpu(m->bytes_in_use))) {

			if (defer_attrlist)
				return -ENOSPC;
			if (!NInoAttrList(base_ni)) {
				err = ntfs_inode_add_attrlist(base_ni);
				if (err)
					goto out;
				err = -EAGAIN;
				goto out;
			}
			err = ntfs_attr_record_move_away(ctx, 8);
			if (err) {
				ntfs_error(sb, "Failed to move attribute");
				goto out;
			}

			err = ntfs_attrlist_update_locked(base_ni, locked_ni);
			if (err)
				goto out;
			err = -EAGAIN;
			goto out;
		}
		if (!(le32_to_cpu(a->length) -
		    le16_to_cpu(a->data.non_resident.mapping_pairs_offset))) {
			err = -EIO;
			ntfs_error(sb, "Mapping pairs space is 0");
			goto out;
		}

		NInoSetSparse(ni);
		ni->flags |= FILE_ATTR_SPARSE_FILE;
		a->flags |= ATTR_IS_SPARSE;
		a->data.non_resident.compression_unit = 0;

		memmove((u8 *)a + le16_to_cpu(a->name_offset) + 8,
				(u8 *)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(__le16));

		a->name_offset = cpu_to_le16(le16_to_cpu(a->name_offset) + 8);

		a->data.non_resident.mapping_pairs_offset =
			cpu_to_le16(le16_to_cpu(a->data.non_resident.mapping_pairs_offset) + 8);
	}

	/* Attribute no longer sparse. */
	if (!sparse && (a->flags & ATTR_IS_SPARSE) &&
	    !(a->flags & ATTR_IS_COMPRESSED)) {
		NInoClearSparse(ni);
		ni->flags &= ~FILE_ATTR_SPARSE_FILE;
		a->flags &= ~ATTR_IS_SPARSE;
		a->data.non_resident.compression_unit = 0;

		memmove((u8 *)a + le16_to_cpu(a->name_offset) - 8,
				(u8 *)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(__le16));

		if (le16_to_cpu(a->name_offset) >= 8)
			a->name_offset = cpu_to_le16(le16_to_cpu(a->name_offset) - 8);

		a->data.non_resident.mapping_pairs_offset =
			cpu_to_le16(le16_to_cpu(a->data.non_resident.mapping_pairs_offset) - 8);
	}

	/* Update compressed size if required. */
	if (NInoFullyMapped(ni) && (sparse || NInoCompressed(ni))) {
		s64 new_compr_size;

		new_compr_size = ntfs_rl_get_compressed_size(ni->vol, ni->runlist.rl);
		if (new_compr_size < 0) {
			err = new_compr_size;
			goto out;
		}

		ni->itype.compressed.size = new_compr_size;
		a->data.non_resident.compressed_size = cpu_to_le64(new_compr_size);
	}

	if (NInoSparse(ni) || NInoCompressed(ni))
		ntfs_attr_accounting_inode(ni)->i_blocks =
				ni->itype.compressed.size >> 9;
	else
		ntfs_attr_accounting_inode(ni)->i_blocks = ni->allocated_size >> 9;
	/*
	 * Set FILE_NAME dirty flag, to update sparse bit and
	 * allocated size in the index.
	 */
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
out:
	return err;
}

#define NTFS_VCN_DELETE_MARK -2

static bool ntfs_attr_record_flags_match(struct ntfs_inode *ni,
		const struct attr_record *attr);

struct ntfs_attr_mft_home_undo {
	struct ntfs_inode *ni;
	u8 *mrec;
	bool mft_dirty;
};

struct ntfs_attr_size_home_undo {
	struct inode *vi;
	bool vi_held;
	s64 allocated_size;
	s64 data_size;
	s64 initialized_size;
	s64 zeroed_size;
	s64 compressed_size;
	loff_t i_size;
	bool filename_dirty;
	bool has_compressed_size;
	bool pending_empty_eof;
};

struct ntfs_attr_append_home_undo {
	struct ntfs_attr_size_home_undo size;
	struct ntfs_new_attribute_sizes sizes;
	__le64 lsn;
	u16 record_off;
	__le16 instance;
	__le16 sequence_number;
	bool mft_dirty;
};

struct ntfs_attr_value_home_undo {
	struct inode *vi;
	bool vi_held;
	u8 *value;
	u64 pos;
	u32 bytes;
};

struct ntfs_attr_allocation_home_undo {
	struct inode *vi;
	struct inode *base_vi;
	bool vi_held;
	bool base_vi_held;
	struct runlist_element *runlist;
	size_t runlist_count;
	int runlist_hint;
	s64 allocated_size;
	s64 data_size;
	s64 initialized_size;
	s64 zeroed_size;
	s64 compressed_size;
	u32 compression_block_size;
	u8 compression_block_size_bits;
	u8 compression_block_clusters;
	__le32 sparse_flag;
	unsigned int delayed_clusters;
	unsigned int truncated_delayed_clusters;
	loff_t i_size;
	blkcnt_t vi_i_blocks;
	blkcnt_t base_i_blocks;
	bool filename_dirty;
	bool runlist_dirty;
	bool nonresident;
	bool fully_mapped;
	bool sparse;
	bool pending_empty_eof;
};

static int ntfs_attr_mft_home_restore(void *data)
{
	struct ntfs_attr_mft_home_undo *undo = data;
	struct mft_record *mrec;
	int err;

	mrec = map_mft_record(undo->ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	memcpy(mrec, undo->mrec, undo->ni->vol->mft_record_size);
	err = ntfs_prepare_mft_record_write(undo->ni);
	if (err)
		goto out_unmap;
	NInoSetDirty(undo->ni);
	err = write_mft_record(undo->ni, mrec, 1);
	if (!err && undo->mft_dirty)
		NInoSetDirty(undo->ni);
out_unmap:
	unmap_mft_record(undo->ni);
	return err;
}

static void ntfs_attr_mft_home_release(void *data)
{
	struct ntfs_attr_mft_home_undo *undo = data;

	kfree(undo->mrec);
	kfree(undo);
}

int ntfs_attr_mft_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		const struct mft_record *mrec)
{
	struct ntfs_attr_mft_home_undo *undo;
	int err;

	if (!handle || !ni || !mrec)
		return -EINVAL;
	undo = kzalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->mrec = kmemdup(mrec, ni->vol->mft_record_size, GFP_NOFS);
	if (!undo->mrec) {
		kfree(undo);
		return -ENOMEM;
	}
	undo->ni = ni;
	undo->mft_dirty = NInoDirty(ni);
	err = ntfs_log_register_home_undo(handle, ntfs_attr_mft_home_restore,
			ntfs_attr_mft_home_release, undo);
	if (err)
		ntfs_attr_mft_home_release(undo);
	return err;
}

static int ntfs_attr_value_home_restore(void *data)
{
	struct ntfs_attr_value_home_undo *undo = data;
	s64 written;

	written = ntfs_inode_attr_pwrite_existing(undo->vi, undo->pos, undo->bytes,
			undo->value, true);
	return written == undo->bytes ? 0 : written < 0 ? written : -EIO;
}

static void ntfs_attr_value_home_release(void *data)
{
	struct ntfs_attr_value_home_undo *undo = data;

	kfree(undo->value);
	ntfs_home_undo_iput(undo->vi, undo->vi_held);
	kfree(undo);
}

static int ntfs_attr_value_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni, u64 pos,
		const u8 *value, u32 bytes)
{
	struct ntfs_attr_value_home_undo *undo;
	int err;

	undo = kzalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	undo->value = kmemdup(value, bytes, GFP_NOFS);
	if (!undo->value) {
		kfree(undo);
		return -ENOMEM;
	}
	undo->vi_held = ntfs_home_undo_igrab(VFS_I(ni));
	undo->vi = VFS_I(ni);
	undo->pos = pos;
	undo->bytes = bytes;
	err = ntfs_log_register_home_undo(handle,
			ntfs_attr_value_home_restore,
			ntfs_attr_value_home_release, undo);
	if (err)
		ntfs_attr_value_home_release(undo);
	return err;
}

int ntfs_attr_value_snapshot_undo(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, u64 pos, u32 bytes)
{
	u8 *value;
	s64 read_bytes;
	int err;

	if (!handle || !ni || !NInoAttr(ni) || !NInoNonResident(ni) ||
	    ni->data_size < 0 || !bytes || pos > (u64)ni->data_size ||
	    bytes > (u64)ni->data_size - pos)
		return -EINVAL;
	value = kvmalloc(bytes, GFP_NOFS);
	if (!value)
		return -ENOMEM;
	read_bytes = ntfs_inode_attr_pread(VFS_I(ni), pos, bytes, value);
	if (read_bytes != bytes) {
		err = read_bytes < 0 ? read_bytes : -EIO;
		goto out;
	}
	err = ntfs_log_nonresident_value_undo(handle, VFS_I(ni), pos, value,
			bytes);
	if (!err)
		err = ntfs_attr_value_register_home_undo(handle, ni, pos, value,
				bytes);
out:
	kvfree(value);
	return err;
}

int ntfs_attr_pwrite_log_credits(struct ntfs_volume *vol, u32 bytes,
		bool nonresident)
{
	if (!vol || !bytes)
		return -EINVAL;
	if (nonresident)
		return ntfs_log_nonresident_value_update_credits(vol, bytes, true);
	if (bytes > U16_MAX)
		return -E2BIG;
	return ntfs_log_mft_attribute_credits(vol, bytes, bytes);
}

int ntfs_attr_pwrite_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, u64 pos, const u8 *value, u32 bytes)
{
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	u8 *old_value;
	u64 operation_lsn;
	u64 end;
	u32 attr_len;
	u32 used;
	u32 value_len;
	u32 old_bytes;
	u16 attr_off;
	u16 record_off;
	u16 value_off;
	ptrdiff_t record_pos;
	s64 written;
	int err;

	if (!handle || !ni || !NInoAttr(ni) || !value || !bytes ||
	    check_add_overflow(pos, (u64)bytes, &end) || end > S64_MAX ||
	    end > ni->data_size ||
	    (end > ni->initialized_size &&
	     (!NInoNonResident(ni) || pos > ni->initialized_size)))
		return -EINVAL;
	old_value = kvmalloc(bytes, GFP_NOFS);
	if (!old_value)
		return -ENOMEM;
	if (NInoNonResident(ni)) {
		old_bytes = pos < ni->initialized_size ?
			min_t(u64, bytes, ni->initialized_size - pos) : 0;
		if (old_bytes) {
			written = ntfs_inode_attr_pread(VFS_I(ni), pos, old_bytes,
					old_value);
			if (written != old_bytes) {
				err = written < 0 ? written : -EIO;
				goto out;
			}
		}
		memset(old_value + old_bytes, 0, bytes - old_bytes);
		if (NInoCompressed(ni) || NInoSparse(ni) || NInoEncrypted(ni)) {
			err = -EOPNOTSUPP;
			goto out;
		}
		err = ntfs_attr_value_register_home_undo(handle, ni, pos,
				old_value, bytes);
		if (err)
			goto out;
		err = 0;
		if (old_bytes)
			err = ntfs_log_nonresident_value_update(handle, VFS_I(ni),
					pos, old_value, value, old_bytes,
					&operation_lsn);
		if (!err && old_bytes < bytes)
			err = ntfs_log_nonresident_value_update(handle, VFS_I(ni),
					pos + old_bytes, NULL, value + old_bytes,
					bytes - old_bytes, &operation_lsn);
		if (err)
			goto out;
		/*
		 * Write while the fresh tail is still uninitialized so read_folio
		 * zeroes it instead of reading stale disk contents.  Publish the
		 * initialized size only after the entire new value is cached.
		 */
		written = ntfs_inode_attr_pwrite_existing(VFS_I(ni), pos, bytes,
				(u8 *)value, false);
		err = written == bytes ? 0 : written < 0 ? written : -EIO;
		if (!err && end > ni->initialized_size)
			err = ntfs_attr_initialized_grow_transacted(handle, ni, end);
		goto out;
	}

	written = ntfs_inode_attr_pread(VFS_I(ni), pos, bytes, old_value);
	if (written != bytes) {
		err = written < 0 ? written : -EIO;
		goto out;
	}
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni || pos > U16_MAX || end > U16_MAX) {
		err = -E2BIG;
		goto out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || attr->non_resident) {
		err = -EIO;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    attr_len > U16_MAX || record_pos > used ||
	    attr_len > used - record_pos || value_off > attr_len ||
	    value_len > attr_len - value_off || value_len != ni->data_size ||
	    end > value_len || pos > U16_MAX - value_off ||
	    !ntfs_attr_record_flags_match(ni, attr)) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	attr_off = value_off + pos;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out;
	err = ntfs_log_mft_resident_update(handle, ctx->ntfs_ino->mft_no,
			record_off, attr_off, old_value, bytes, value,
			bytes, &operation_lsn);
	if (err)
		goto out;
	memcpy((u8 *)attr + value_off + pos, value, bytes);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
	err = 0;
out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	kvfree(old_value);
	return err;
}

int ntfs_resident_attr_update_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, u64 pos, const u8 *value, u32 bytes)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	ptrdiff_t record_pos;
	u64 operation_lsn;
	u64 end;
	u32 attr_len;
	u32 used;
	u32 value_len;
	u16 attr_off;
	u16 record_off;
	u16 value_off;
	int err;

	if (!handle || !ni || !value || !bytes || NInoNonResident(ni) ||
	    check_add_overflow(pos, (u64)bytes, &end) || end > U16_MAX)
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || attr->non_resident) {
		err = -EIO;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	value_len = le32_to_cpu(attr->data.resident.value_length);
	if (record_pos < 0 || record_pos > U16_MAX || attr_len > U16_MAX ||
	    record_pos > used || attr_len > used - record_pos ||
	    value_off > attr_len || value_len > attr_len - value_off ||
	    value_len != ni->data_size || end > value_len ||
	    pos > U16_MAX - value_off ||
	    !ntfs_attr_record_flags_match(ni, attr)) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	attr_off = value_off + pos;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out;
	err = ntfs_log_mft_resident_update(handle, ctx->ntfs_ino->mft_no,
			record_off, attr_off, (u8 *)attr + attr_off, bytes,
			value, bytes, &operation_lsn);
	if (err)
		goto out;
	memcpy((u8 *)attr + attr_off, value, bytes);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

static int ntfs_attr_size_home_restore(void *data)
{
	struct ntfs_attr_size_home_undo *undo = data;
	struct ntfs_inode *ni = NTFS_I(undo->vi);

	ni->allocated_size = undo->allocated_size;
	ni->data_size = undo->data_size;
	ni->initialized_size = undo->initialized_size;
	ni->zeroed_size = undo->zeroed_size;
	if (undo->has_compressed_size)
		ni->itype.compressed.size = undo->compressed_size;
	i_size_write(undo->vi, undo->i_size);
	if (undo->filename_dirty)
		NInoSetFileNameDirty(ni);
	else
		NInoClearFileNameDirty(ni);
	if (undo->pending_empty_eof)
		NInoSetPendingEmptyEof(ni);
	else
		NInoClearPendingEmptyEof(ni);
	return 0;
}

static void ntfs_attr_size_home_release(void *data)
{
	struct ntfs_attr_size_home_undo *undo = data;

	ntfs_home_undo_iput(undo->vi, undo->vi_held);
	kfree(undo);
}

static int ntfs_attr_append_home_restore(void *data)
{
	struct ntfs_attr_append_home_undo *undo = data;
	struct ntfs_inode *ni = NTFS_I(undo->size.vi);
	struct mft_record *mrec;
	struct attr_record *attr;
	u32 used, length;
	int err;

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return PTR_ERR(mrec);
	used = le32_to_cpu(mrec->bytes_in_use);
	if (mrec->magic != magic_FILE ||
	    mrec->sequence_number != undo->sequence_number ||
	    used > ni->vol->mft_record_size || undo->record_off > used ||
	    used - undo->record_off < offsetof(struct attr_record,
			data.non_resident.compressed_size)) {
		err = -EIO;
		goto out;
	}
	attr = (void *)((u8 *)mrec + undo->record_off);
	length = le32_to_cpu(attr->length);
	if (attr->type != AT_DATA || attr->name_length || !attr->non_resident ||
	    attr->instance != undo->instance ||
	    attr->data.non_resident.lowest_vcn ||
	    length < offsetof(struct attr_record, data.non_resident.compressed_size) ||
	    length > used - undo->record_off) {
		err = -EIO;
		goto out;
	}
	attr->data.non_resident.allocated_size = undo->sizes.alloc_size;
	attr->data.non_resident.data_size = undo->sizes.data_size;
	attr->data.non_resident.initialized_size = undo->sizes.valid_size;
	mrec->lsn = undo->lsn;
	err = ntfs_prepare_mft_record_write(ni);
	if (err)
		goto out;
	NInoSetDirty(ni);
	err = write_mft_record(ni, mrec, 1);
	if (!err && undo->mft_dirty)
		NInoSetDirty(ni);
out:
	unmap_mft_record(ni);
	if (!err)
		err = ntfs_attr_size_home_restore(&undo->size);
	return err;
}

static void ntfs_attr_append_home_release(void *data)
{
	struct ntfs_attr_append_home_undo *undo = data;

	ntfs_home_undo_iput(undo->size.vi, undo->size.vi_held);
}

static int ntfs_attr_append_register_home_undo(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, struct ntfs_attr_search_ctx *ctx, u16 record_off)
{
	struct ntfs_attr_append_home_undo undo = { };
	struct attr_record *attr = ctx->attr;
	int err;

	BUILD_BUG_ON(sizeof(undo) > NTFS_LOG_HOME_UNDO_BUFFER_BYTES);
	/* Extent records and general attribute edits keep the full snapshot. */
	if (NInoAttr(ni) || ctx->ntfs_ino != ni || ni->type != AT_DATA ||
	    ni->name != AT_UNNAMED || NInoCompressed(ni) || NInoSparse(ni))
		return -EOPNOTSUPP;
	undo.size.vi = VFS_I(ni);
	undo.size.vi_held = ntfs_home_undo_igrab(undo.size.vi);
	undo.size.allocated_size = ni->allocated_size;
	undo.size.data_size = ni->data_size;
	undo.size.initialized_size = ni->initialized_size;
	undo.size.zeroed_size = ni->zeroed_size;
	undo.size.i_size = i_size_read(undo.size.vi);
	undo.size.filename_dirty = NInoFileNameDirty(ni);
	undo.size.pending_empty_eof = NInoPendingEmptyEof(ni);
	undo.sizes.alloc_size = attr->data.non_resident.allocated_size;
	undo.sizes.data_size = attr->data.non_resident.data_size;
	undo.sizes.valid_size = attr->data.non_resident.initialized_size;
	undo.lsn = ctx->mrec->lsn;
	undo.record_off = record_off;
	undo.instance = attr->instance;
	undo.sequence_number = ctx->mrec->sequence_number;
	undo.mft_dirty = NInoDirty(ni);
	err = ntfs_log_register_home_undo_buffer(handle,
			ntfs_attr_append_home_restore, ntfs_attr_append_home_release,
			&undo, sizeof(undo));
	if (err)
		ntfs_attr_append_home_release(&undo);
	return err;
}

int ntfs_attr_size_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_attr_size_home_undo *undo;
	struct inode *vi;
	int err;

	if (!handle || !ni)
		return -EINVAL;
	undo = kmalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	vi = VFS_I(ni);
	undo->vi_held = ntfs_home_undo_igrab(vi);
	undo->vi = vi;
	undo->allocated_size = ni->allocated_size;
	undo->data_size = ni->data_size;
	undo->initialized_size = ni->initialized_size;
	undo->zeroed_size = ni->zeroed_size;
	undo->has_compressed_size = NInoCompressed(ni) || NInoSparse(ni);
	if (undo->has_compressed_size)
		undo->compressed_size = ni->itype.compressed.size;
	undo->i_size = i_size_read(vi);
	undo->filename_dirty = NInoFileNameDirty(ni);
	undo->pending_empty_eof = NInoPendingEmptyEof(ni);
	err = ntfs_log_register_home_undo(handle,
			ntfs_attr_size_home_restore,
			ntfs_attr_size_home_release, undo);
	if (err)
		ntfs_attr_size_home_release(undo);
	return err;
}

static int ntfs_attr_allocation_home_restore(void *data)
{
	struct ntfs_attr_allocation_home_undo *undo = data;
	struct ntfs_inode *ni = NTFS_I(undo->vi);

	down_write(&ni->runlist.lock);
	kvfree(ni->runlist.rl);
	ni->runlist.rl = undo->runlist;
	undo->runlist = NULL;
	ni->runlist.count = undo->runlist_count;
	ni->runlist.rl_hint = undo->runlist_hint;
	if (undo->nonresident)
		NInoSetNonResident(ni);
	else
		NInoClearNonResident(ni);
	if (undo->fully_mapped)
		NInoSetFullyMapped(ni);
	else
		NInoClearFullyMapped(ni);
	ni->allocated_size = undo->allocated_size;
	ni->data_size = undo->data_size;
	ni->initialized_size = undo->initialized_size;
	ni->zeroed_size = undo->zeroed_size;
	ni->itype.compressed.size = undo->compressed_size;
	ni->itype.compressed.block_size = undo->compression_block_size;
	ni->itype.compressed.block_size_bits = undo->compression_block_size_bits;
	ni->itype.compressed.block_clusters = undo->compression_block_clusters;
	if (undo->sparse)
		NInoSetSparse(ni);
	else
		NInoClearSparse(ni);
	ni->flags = (ni->flags & ~FILE_ATTR_SPARSE_FILE) | undo->sparse_flag;
	ni->i_dealloc_clusters = undo->delayed_clusters;
	undo->truncated_delayed_clusters = 0;
	i_size_write(undo->vi, undo->i_size);
	undo->vi->i_blocks = undo->vi_i_blocks;
	undo->base_vi->i_blocks = undo->base_i_blocks;
	if (undo->filename_dirty)
		NInoSetFileNameDirty(ni);
	else
		NInoClearFileNameDirty(ni);
	if (undo->runlist_dirty)
		NInoSetRunlistDirty(ni);
	else
		NInoClearRunlistDirty(ni);
	if (undo->pending_empty_eof)
		NInoSetPendingEmptyEof(ni);
	else
		NInoClearPendingEmptyEof(ni);
	up_write(&ni->runlist.lock);
	return 0;
}

static void ntfs_attr_allocation_home_release(void *data)
{
	struct ntfs_attr_allocation_home_undo *undo = data;

	/* Abort keeps the reservation for the restored DELALLOC runlist. */
	if (undo->truncated_delayed_clusters)
		ntfs_release_dirty_clusters(NTFS_I(undo->vi)->vol,
				undo->truncated_delayed_clusters);
	kvfree(undo->runlist);
	ntfs_home_undo_iput(undo->base_vi, undo->base_vi_held);
	ntfs_home_undo_iput(undo->vi, undo->vi_held);
	kfree(undo);
}

/* Caller holds ni->runlist.lock for write. */
static int ntfs_attr_allocation_register_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		struct ntfs_attr_allocation_home_undo **undo_out)
{
	struct ntfs_attr_allocation_home_undo *undo;
	struct ntfs_inode *base_ni;
	struct inode *base_vi;
	struct inode *vi;
	size_t bytes;
	int err;

	if (!handle || !ni || (!ni->runlist.rl != !ni->runlist.count))
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni || check_mul_overflow(ni->runlist.count,
			sizeof(*ni->runlist.rl), &bytes))
		return base_ni ? -EOVERFLOW : -EINVAL;
	undo = kzalloc_obj(*undo, GFP_NOFS);
	if (!undo)
		return -ENOMEM;
	if (bytes) {
		undo->runlist = ntfs_attrib_kvmemdup(ni->runlist.rl, bytes,
				GFP_NOFS);
		if (!undo->runlist) {
			kfree(undo);
			return -ENOMEM;
		}
	}
	vi = VFS_I(ni);
	base_vi = VFS_I(base_ni);
	undo->vi_held = ntfs_home_undo_igrab(vi);
	undo->base_vi_held = ntfs_home_undo_igrab(base_vi);
	undo->vi = vi;
	undo->base_vi = base_vi;
	undo->runlist_count = ni->runlist.count;
	undo->runlist_hint = ni->runlist.rl_hint;
	undo->allocated_size = ni->allocated_size;
	undo->data_size = ni->data_size;
	undo->initialized_size = ni->initialized_size;
	undo->zeroed_size = ni->zeroed_size;
	undo->compressed_size = ni->itype.compressed.size;
	undo->compression_block_size = ni->itype.compressed.block_size;
	undo->compression_block_size_bits = ni->itype.compressed.block_size_bits;
	undo->compression_block_clusters = ni->itype.compressed.block_clusters;
	undo->sparse_flag = ni->flags & FILE_ATTR_SPARSE_FILE;
	undo->delayed_clusters = ni->i_dealloc_clusters;
	undo->i_size = i_size_read(vi);
	undo->vi_i_blocks = vi->i_blocks;
	undo->base_i_blocks = base_vi->i_blocks;
	undo->filename_dirty = NInoFileNameDirty(ni);
	undo->runlist_dirty = NInoRunlistDirty(ni);
	undo->nonresident = NInoNonResident(ni);
	undo->fully_mapped = NInoFullyMapped(ni);
	undo->sparse = NInoSparse(ni);
	undo->pending_empty_eof = NInoPendingEmptyEof(ni);
	err = ntfs_log_register_home_undo(handle,
			ntfs_attr_allocation_home_restore,
			ntfs_attr_allocation_home_release, undo);
	if (err)
		ntfs_attr_allocation_home_release(undo);
	else if (undo_out)
		*undo_out = undo;
	return err;
}

int ntfs_attr_allocation_register_home_undo(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	return ntfs_attr_allocation_register_undo(handle, ni, NULL);
}

int ntfs_attr_record_move_to_new_extent_transacted(
		struct ntfs_log_handle *handle, struct ntfs_attr_search_ctx *ctx,
		struct ntfs_inode *target_ni, struct mft_record *target_mrec,
		u8 *pending_list, u32 pending_size)
{
	struct ntfs_attr_search_ctx *target_ctx = NULL;
	struct attr_record *new_attr = NULL;
	struct attr_record *source_attr;
	struct mft_record *source_mrec;
	struct mft_record *after = NULL;
	__le64 target_mref;
	__le16 target_instance;
	u64 operation_lsn;
	u32 attr_len;
	u32 used;
	u16 source_off;
	u16 target_off;
	ptrdiff_t record_pos;
	int err;

	if (!handle || !ctx || !ctx->ntfs_ino || !ctx->mrec || !ctx->attr ||
	    (!ctx->al_entry && (!pending_list || !pending_size)) ||
	    (pending_list && !pending_size) || !target_ni || !target_mrec)
		return -EINVAL;
	source_attr = ctx->attr;
	source_mrec = ctx->mrec;
	attr_len = le32_to_cpu(source_attr->length);
	used = le32_to_cpu(source_mrec->bytes_in_use);
	record_pos = (u8 *)source_attr - (u8 *)source_mrec;
	if (!attr_len || attr_len > U16_MAX || !IS_ALIGNED(attr_len, 8) ||
	    record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || record_pos > used ||
	    attr_len > used - record_pos)
		return -EIO;
	source_off = record_pos;
	target_ctx = ntfs_attr_get_search_ctx(target_ni, target_mrec);
	if (!target_ctx)
		return -ENOMEM;
	err = ntfs_attr_find(source_attr->type,
			source_attr->name_length ?
			(__le16 *)((u8 *)source_attr +
				le16_to_cpu(source_attr->name_offset)) : AT_UNNAMED,
			source_attr->name_length, CASE_SENSITIVE,
			source_attr->non_resident ? NULL :
			(u8 *)source_attr + le16_to_cpu(
				source_attr->data.resident.value_offset),
			source_attr->non_resident ? 0 : le32_to_cpu(
				source_attr->data.resident.value_length), target_ctx);
	if (!err) {
		err = -EEXIST;
		goto out;
	}
	if (err != -ENOENT)
		goto out;
	record_pos = (u8 *)target_ctx->attr - (u8 *)target_mrec;
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8)) {
		err = -EIO;
		goto out;
	}
	target_off = record_pos;
	err = ntfs_check_room_for_attr(target_mrec,
			(u8 *)target_ctx->attr, attr_len);
	if (err)
		goto out;
	new_attr = kmemdup(source_attr, attr_len, GFP_NOFS);
	if (!new_attr) {
		err = -ENOMEM;
		goto out;
	}
	target_instance = target_mrec->next_attr_instance;
	new_attr->instance = target_instance;
	target_mref = MK_LE_MREF(target_ni->mft_no,
			le16_to_cpu(target_mrec->sequence_number));
	after = kmemdup(target_mrec, target_ni->vol->mft_record_size, GFP_NOFS);
	if (!after) {
		err = -ENOMEM;
		goto out;
	}
	err = ntfs_make_room_for_attr(after, (u8 *)after + target_off, attr_len);
	if (err)
		goto out;
	memcpy((u8 *)after + target_off, new_attr, attr_len);
	after->next_attr_instance = cpu_to_le16(
			(le16_to_cpu(target_instance) + 1) & 0xffff);
	err = ntfs_log_mft_record_update(handle, target_ni->mft_no,
			target_mrec, after, &operation_lsn);
	if (err)
		goto out;
	err = ntfs_make_room_for_attr(target_mrec,
			(u8 *)target_ctx->attr, attr_len);
	if (err)
		goto out;
	memcpy(target_ctx->attr, new_attr, attr_len);
	target_mrec->next_attr_instance = cpu_to_le16(
			(le16_to_cpu(target_instance) + 1) & 0xffff);
	target_mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(target_ni);
	if (ctx->al_entry)
		err = ntfs_attrlist_entry_move_transacted(handle, ctx, target_mref,
				target_instance, pending_list, pending_size);
	else
		err = ntfs_attrlist_pending_entry_move(source_attr,
			pending_list, pending_size,
			MK_LE_MREF(ctx->ntfs_ino->mft_no,
				le16_to_cpu(source_mrec->sequence_number)),
			source_attr->instance, target_mref, target_instance);
	if (err)
		goto out;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino,
			source_mrec);
	if (err)
		goto out;
	memcpy(after, source_mrec, target_ni->vol->mft_record_size);
	err = ntfs_attr_record_resize(after,
			(struct attr_record *)((u8 *)after + source_off), 0);
	if (err)
		goto out;
	err = ntfs_log_mft_record_update(handle, ctx->ntfs_ino->mft_no,
			source_mrec, after, &operation_lsn);
	if (err)
		goto out;
	err = ntfs_attr_record_resize(source_mrec, source_attr, 0);
	if (err)
		goto out;
	source_mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
out:
	kfree(after);
	kfree(new_attr);
	ntfs_attr_put_search_ctx(target_ctx);
	return err;
}

int ntfs_attr_relocate_resident_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, u32 required_len)
{
	struct ntfs_inode *base_ni, *target_ni = NULL;
	struct ntfs_attr_search_ctx *ctx;
	struct mft_record *target_mrec = NULL;
	u32 allocated, attr_len, used;
	int err;

	if (!handle || !ni || NInoNonResident(ni) || required_len > U16_MAX)
		return -EINVAL;
	base_ni = ntfs_base_inode(ni);
retry:
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out;
	if (ctx->attr->non_resident) {
		err = -EIO;
		goto out;
	}
	attr_len = le32_to_cpu(ctx->attr->length);
	used = le32_to_cpu(ctx->mrec->bytes_in_use);
	allocated = le32_to_cpu(ctx->mrec->bytes_allocated);
	if (used > allocated || attr_len > used) {
		err = -EIO;
		goto out;
	}
	required_len = max(required_len, attr_len);
	if (required_len <= attr_len + allocated - used) {
		err = 0;
		goto out;
	}
	if (!NInoAttrList(base_ni)) {
		ntfs_attr_put_search_ctx(ctx);
		err = ntfs_inode_add_attrlist_transacted(handle, base_ni);
		if (!err)
			goto retry;
		return err;
	}
	err = ntfs_mft_record_alloc_transacted(handle, ni->vol, &target_ni,
			base_ni, &target_mrec);
	if (err)
		goto out;
	used = le32_to_cpu(target_mrec->bytes_in_use);
	allocated = le32_to_cpu(target_mrec->bytes_allocated);
	if (used > allocated || required_len > allocated - used)
		err = -ENOSPC;
	else
		err = ntfs_attr_record_move_to_new_extent_transacted(handle, ctx,
				target_ni, target_mrec, NULL, 0);
	unmap_mft_record(target_ni);
out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

int ntfs_attr_make_base_record_space_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni,
		u32 required_free, u32 max_moves, u8 *pending_list,
		u32 pending_size)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *target_ni;
	struct mft_record *target_mrec;
	struct mft_record *mrec;
	struct attr_record *attr;
	u32 allocated;
	u32 attr_len;
	u32 free_bytes;
	u32 moves;
	u32 used;
	int err;

	if (!handle || !base_ni || !required_free || !max_moves ||
	    !NInoAttrList(base_ni) || !base_ni->attr_list ||
	    (!!pending_list != !!pending_size))
		return -EINVAL;
	for (moves = 0; ; moves++) {
		mrec = map_mft_record(base_ni);
		if (IS_ERR(mrec))
			return PTR_ERR(mrec);
		used = le32_to_cpu(mrec->bytes_in_use);
		allocated = le32_to_cpu(mrec->bytes_allocated);
		unmap_mft_record(base_ni);
		if (used > allocated)
			return -EIO;
		free_bytes = allocated - used;
		if (free_bytes >= required_free)
			return 0;
		if (moves == max_moves) {
			ntfs_error(base_ni->vol->sb,
				   "Attribute-list space exhausted on inode %llu (free %u, need %u, moves %u/%u).",
				   (unsigned long long)base_ni->mft_no, free_bytes,
				   required_free, moves, max_moves);
			return -EOPNOTSUPP;
		}

		target_ni = NULL;
		target_mrec = NULL;
		ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
		if (!ctx)
			return -ENOMEM;
		for (;;) {
			err = ntfs_attr_lookup(AT_UNUSED, NULL, 0, CASE_SENSITIVE,
					0, NULL, 0, ctx);
			if (err)
				break;
			attr = ctx->attr;
			if (!attr || ctx->ntfs_ino != base_ni || !ctx->al_entry)
				continue;
			if (le32_to_cpu(attr->type) < le32_to_cpu(AT_FILE_NAME) ||
			    attr->type == AT_INDEX_ROOT ||
			    (base_ni->mft_no == FILE_MFT &&
			     attr->type == AT_DATA))
				continue;
			attr_len = le32_to_cpu(attr->length);
			if (!attr_len || !IS_ALIGNED(attr_len, 8)) {
				err = -EIO;
				break;
			}
			err = ntfs_mft_record_alloc_transacted(handle,
					base_ni->vol, &target_ni, base_ni,
					&target_mrec);
			if (err) {
				ntfs_error(base_ni->vol->sb,
					   "Attribute-list extent allocation failed on inode %llu (attribute 0x%x, length %u, error %d).",
					   (unsigned long long)base_ni->mft_no,
					   le32_to_cpu(attr->type), attr_len, err);
				break;
			}
			err = ntfs_attr_record_move_to_new_extent_transacted(handle,
					ctx, target_ni, target_mrec, pending_list,
					pending_size);
			if (err)
				ntfs_error(base_ni->vol->sb,
					   "Attribute move failed on inode %llu (attribute 0x%x, length %u, error %d).",
					   (unsigned long long)base_ni->mft_no,
					   le32_to_cpu(attr->type), attr_len, err);
			unmap_mft_record(target_ni);
			target_ni = NULL;
			target_mrec = NULL;
			break;
		}
		if (target_ni)
			unmap_mft_record(target_ni);
		if (err == -ENOENT) {
			ntfs_error(base_ni->vol->sb,
				   "No movable attribute found for attribute list on inode %llu.",
				   (unsigned long long)base_ni->mft_no);
			err = -EOPNOTSUPP;
		}
		ntfs_attr_put_search_ctx(ctx);
		if (err)
			return err;
	}
}

/*
 * Make room for the first resident $ATTRIBUTE_LIST.  At this point there is
 * no published list and therefore no list entry that can be updated by the
 * normal extent-move path. The caller supplies the list image that will be
 * published after the moves complete.
 */
int ntfs_attr_make_base_record_space_initial_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *base_ni,
		u32 required_free, u32 max_moves, u8 *pending_list,
		u32 pending_size)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *target_ni;
	struct mft_record *target_mrec;
	struct mft_record *mrec;
	struct attr_record *attr;
	u32 allocated;
	u32 attr_len;
	u32 free_bytes;
	u32 moves;
	u32 used;
	int err;

	if (!handle || !base_ni || !required_free || !max_moves ||
		NInoAttrList(base_ni) || base_ni->nr_extents ||
		!pending_list || !pending_size)
		return -EINVAL;
	for (moves = 0; ; moves++) {
		mrec = map_mft_record(base_ni);
		if (IS_ERR(mrec))
			return PTR_ERR(mrec);
		used = le32_to_cpu(mrec->bytes_in_use);
		allocated = le32_to_cpu(mrec->bytes_allocated);
		unmap_mft_record(base_ni);
		if (used > allocated)
			return -EIO;
		free_bytes = allocated - used;
		if (free_bytes >= required_free)
			return 0;
		if (moves == max_moves) {
			ntfs_error(base_ni->vol->sb,
				   "Initial attribute-list space exhausted on inode %llu (free %u, need %u, moves %u/%u).",
				   (unsigned long long)base_ni->mft_no, free_bytes,
				   required_free, moves, max_moves);
			return -EOPNOTSUPP;
		}

		target_ni = NULL;
		target_mrec = NULL;
		ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
		if (!ctx)
			return -ENOMEM;
		for (;;) {
			err = ntfs_attr_lookup(AT_UNUSED, NULL, 0, CASE_SENSITIVE,
					0, NULL, 0, ctx);
			if (err)
				break;
			attr = ctx->attr;
			if (!attr || ctx->ntfs_ino != base_ni)
				continue;
			if (le32_to_cpu(attr->type) < le32_to_cpu(AT_FILE_NAME) ||
				attr->type == AT_INDEX_ROOT ||
				(base_ni->mft_no == FILE_MFT &&
				 attr->type == AT_DATA))
				continue;
			attr_len = le32_to_cpu(attr->length);
			if (!attr_len || !IS_ALIGNED(attr_len, 8)) {
				err = -EIO;
				break;
			}
			err = ntfs_mft_record_alloc_transacted(handle,
					base_ni->vol, &target_ni, base_ni,
					&target_mrec);
			if (err) {
				ntfs_error(base_ni->vol->sb,
					   "Initial attribute-list extent allocation failed on inode %llu (attribute 0x%x, length %u, error %d).",
					   (unsigned long long)base_ni->mft_no,
					   le32_to_cpu(attr->type), attr_len, err);
				break;
			}
			err = ntfs_attr_record_move_to_new_extent_transacted(handle,
					ctx, target_ni, target_mrec, pending_list,
					pending_size);
			if (err)
				ntfs_error(base_ni->vol->sb,
					   "Initial attribute move failed on inode %llu (attribute 0x%x, length %u, error %d).",
					   (unsigned long long)base_ni->mft_no,
					   le32_to_cpu(attr->type), attr_len, err);
			unmap_mft_record(target_ni);
			target_ni = NULL;
			target_mrec = NULL;
			break;
		}
		if (target_ni)
			unmap_mft_record(target_ni);
		if (err == -ENOENT) {
			ntfs_error(base_ni->vol->sb,
				   "No movable attribute found for initial attribute list on inode %llu.",
				   (unsigned long long)base_ni->mft_no);
			err = -EOPNOTSUPP;
		}
		ntfs_attr_put_search_ctx(ctx);
		if (err)
			return err;
	}
}

static int __ntfs_attr_update_mapping_pairs_log_credits(struct ntfs_volume *vol,
		u16 old_len, u16 new_len, u64 max_new_extents,
		u64 max_removed_extents, u32 max_list_bytes)
{
	u32 max_extents;
	int alloc_credits;
	int attr_credits;
	int delete_credits;
	int extent_mapping_credits;
	int free_credits;
	int list_credits;
	int mapping_credits;
	int per_extent_credits;
	int remove_credits;
	int size_credits;
	int single_credits;
	int sparse_credits;
	int sparse_create_credits;
	int sparse_flag_credits;
	int credits;

	mapping_credits = ntfs_log_mft_mapping_pairs_credits(vol, old_len,
			new_len);
	if (mapping_credits < 0)
		return mapping_credits;
	size_credits = ntfs_log_mft_attribute_sizes_credits(vol, true);
	if (size_credits < 0)
		return size_credits;
	if (check_add_overflow(mapping_credits, size_credits, &single_credits))
		return -EOVERFLOW;
	/* A mapping update can add/remove the sparse header in the base extent. */
	sparse_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, 0);
	if (sparse_credits < 0)
		return sparse_credits;
	sparse_create_credits = ntfs_log_mft_attribute_credits(vol,
			0, vol->mft_record_size);
	if (sparse_create_credits < 0)
		return sparse_create_credits;
	sparse_flag_credits = ntfs_log_mft_attribute_credits(vol,
			sizeof(__le32), sizeof(__le32));
	if (sparse_flag_credits < 0)
		return sparse_flag_credits;
	if (check_add_overflow(sparse_credits, sparse_create_credits,
			&sparse_credits) ||
	    check_add_overflow(sparse_credits, sparse_flag_credits,
			&sparse_credits) ||
	    check_add_overflow(single_credits, sparse_credits, &single_credits))
		return -EOVERFLOW;
	if (!max_new_extents && !max_removed_extents)
		return single_credits;
	attr_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, vol->mft_record_size);
	if (attr_credits < 0)
		return attr_credits;
	if (max_new_extents)
		list_credits = ntfs_attrlist_nonresident_log_credits(vol);
	else
		list_credits = ntfs_attrlist_shrink_log_credits(vol,
				max_list_bytes);
	if (list_credits < 0)
		return list_credits;
	list_credits = max(list_credits, attr_credits);
	credits = single_credits;
	if (max_new_extents) {
		alloc_credits = ntfs_mft_record_alloc_credits(vol);
		if (alloc_credits < 0)
			return alloc_credits;
		extent_mapping_credits = ntfs_log_mft_mapping_pairs_credits(vol,
				vol->mft_record_size, vol->mft_record_size);
		if (extent_mapping_credits < 0)
			return extent_mapping_credits;
		/* The 256-KiB attribute-list format bounds published extents. */
		max_extents = min_t(u64, max_new_extents,
				(256 * 1024) /
				ALIGN(sizeof(struct attr_list_entry), 8));
		if (!max_extents)
			return -E2BIG;
		/* Per extent: MFT allocation, create, mapping, list resize. */
		if (check_add_overflow(alloc_credits, attr_credits,
				&per_extent_credits) ||
		    check_add_overflow(per_extent_credits,
				extent_mapping_credits, &per_extent_credits) ||
		    check_add_overflow(per_extent_credits, list_credits,
				&per_extent_credits) ||
		    check_mul_overflow(max_extents, per_extent_credits,
				&per_extent_credits) ||
		    /* The no-list path may create a resident list first. */
		    check_add_overflow(per_extent_credits, attr_credits,
				&per_extent_credits) ||
		    /* The existing last extent may consume another prefix. */
		    check_add_overflow(per_extent_credits,
				extent_mapping_credits, &per_extent_credits) ||
		    check_add_overflow(per_extent_credits, single_credits,
				&per_extent_credits))
			return -EOVERFLOW;
		credits = max(credits, per_extent_credits);
	}
	if (max_removed_extents) {
		delete_credits = ntfs_log_mft_attribute_credits(vol,
				vol->mft_record_size, 0);
		if (delete_credits < 0)
			return delete_credits;
		free_credits = ntfs_mft_record_free_credits(vol);
		if (free_credits < 0)
			return free_credits;
		max_extents = min_t(u64, max_removed_extents,
				(256 * 1024) /
				ALIGN(sizeof(struct attr_list_entry), 8));
		if (!max_extents)
			return -E2BIG;
		/* Per extent: attribute delete, list resize, MFT record free. */
		if (check_add_overflow(delete_credits, list_credits,
				&remove_credits) ||
		    check_add_overflow(remove_credits, free_credits,
				&remove_credits) ||
		    check_mul_overflow(max_extents, remove_credits,
				&remove_credits) ||
		    check_add_overflow(remove_credits, single_credits,
				&remove_credits))
			return -EOVERFLOW;
		credits = max(credits, remove_credits);
	}
	return credits;
}

int ntfs_attr_update_mapping_pairs_log_credits(struct ntfs_volume *vol,
		u16 old_len, u16 new_len, u64 max_new_extents,
		u64 max_removed_extents)
{
	return __ntfs_attr_update_mapping_pairs_log_credits(vol, old_len,
			new_len, max_new_extents, max_removed_extents, 256 * 1024);
}

static bool ntfs_attr_has_compressed_size(struct ntfs_inode *ni)
{
	return NInoCompressed(ni) || NInoSparse(ni);
}

static bool ntfs_attr_deleted_encrypted(struct ntfs_inode *ni)
{
	struct ntfs_inode *base_ni;

	if (!NInoEncrypted(ni) || VFS_I(ni)->i_nlink)
		return false;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	return base_ni && NInoBeingDeleted(base_ni);
}

static bool ntfs_attr_record_flags_match(struct ntfs_inode *ni,
		const struct attr_record *attr)
{
	if ((!!(attr->flags & ATTR_IS_ENCRYPTED) != !!NInoEncrypted(ni)) ||
	    ((attr->flags & ATTR_COMPRESSION_MASK) !=
		    (NInoCompressed(ni) ? ATTR_IS_COMPRESSED : 0)) ||
	    (!!(attr->flags & ATTR_IS_SPARSE) != !!NInoSparse(ni)))
		return false;
	return !NInoCompressed(ni) ||
		attr->data.non_resident.compression_unit ==
			STANDARD_COMPRESSION_UNIT;
}

/* The mapping-pairs callers hold @ni's runlist lock for writing. */
static bool ntfs_attr_holds_mft_runlist(struct ntfs_inode *ni)
{
	return ni == NTFS_I(ni->vol->mft_ino);
}

static int ntfs_attr_log_mapping_update(struct ntfs_log_handle *handle,
					struct ntfs_inode *ni,
					u64 mft_no, u16 record_off, u16 attr_off,
					const void *old_pairs, u16 old_len,
					const void *new_pairs, u16 new_len, u64 *lsn_out)
{
	if (ntfs_attr_holds_mft_runlist(ni))
		return ntfs_log_mft_mapping_pairs_locked(handle, mft_no,
				record_off, attr_off, old_pairs, old_len,
				new_pairs, new_len, lsn_out);
	return ntfs_log_mft_mapping_pairs_update(handle, mft_no, record_off,
			attr_off, old_pairs, old_len, new_pairs, new_len, lsn_out);
}

static int ntfs_attr_log_sizes_update(struct ntfs_log_handle *handle,
				      struct ntfs_inode *ni,
				      u64 mft_no, u16 record_off,
				      const struct ntfs_new_attribute_sizes *old_sizes,
				      const struct ntfs_new_attribute_sizes *new_sizes,
				      bool has_compressed_size, u64 *lsn_out)
{
	if (ntfs_attr_holds_mft_runlist(ni))
		return ntfs_log_mft_attribute_sizes_locked(handle, mft_no,
				record_off, old_sizes, new_sizes,
				has_compressed_size, lsn_out);
	return ntfs_log_mft_attribute_sizes_update(handle, mft_no, record_off,
			old_sizes, new_sizes, has_compressed_size, lsn_out);
}

static int ntfs_attr_update_base_sizes_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		struct ntfs_inode *base_ni, __le16 *attr_flags)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct ntfs_attr_search_ctx *ctx;
	struct attr_record *attr;
	struct mft_record *mrec;
	u64 operation_lsn;
	u32 attr_len;
	u32 used;
	u16 mapping_off;
	u16 record_off;
	ptrdiff_t record_pos;
	bool has_compressed_size;
	int err;

	has_compressed_size = ntfs_attr_has_compressed_size(ni);

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || !attr->non_resident ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    !ntfs_attr_record_flags_match(ni, attr)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off = le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(mapping_off, 8) ||
	    mapping_off < offsetof(struct attr_record,
			data.non_resident.compressed_size) +
			(has_compressed_size ? sizeof(__le64) : 0) ||
	    mapping_off > attr_len || attr_len > U16_MAX ||
	    record_pos > used || attr_len > used - record_pos) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out;
	old_sizes.alloc_size = attr->data.non_resident.allocated_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	new_sizes.alloc_size = cpu_to_le64(ni->allocated_size);
	new_sizes.valid_size = cpu_to_le64(ntfs_inode_recorded_initialized_size(ni));
	new_sizes.data_size = cpu_to_le64(ntfs_inode_recorded_data_size(ni));
	if (has_compressed_size) {
		old_sizes.total_size = attr->data.non_resident.compressed_size;
		new_sizes.total_size = cpu_to_le64(ni->itype.compressed.size);
	}
	err = ntfs_attr_log_sizes_update(handle, ni, ctx->ntfs_ino->mft_no,
					 record_off, &old_sizes, &new_sizes, has_compressed_size,
					 &operation_lsn);
	if (err)
		goto out;
	attr->data.non_resident.allocated_size = new_sizes.alloc_size;
	attr->data.non_resident.initialized_size = new_sizes.valid_size;
	attr->data.non_resident.data_size = new_sizes.data_size;
	if (has_compressed_size)
		attr->data.non_resident.compressed_size = new_sizes.total_size;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
	*attr_flags = attr->flags;
	err = 0;
out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

static int ntfs_attr_new_extent_mapping_capacity(struct ntfs_inode *ni,
		const struct mft_record *mrec, __le16 attr_flags)
{
	u32 allocated;
	u32 fixed;
	u32 free_bytes;
	u32 used;

	allocated = le32_to_cpu(mrec->bytes_allocated);
	used = le32_to_cpu(mrec->bytes_in_use);
	fixed = offsetof(struct attr_record,
			data.non_resident.compressed_size) +
		ALIGN(ni->name_len * sizeof(__le16), 8);
	if (attr_flags & (ATTR_IS_COMPRESSED | ATTR_IS_SPARSE))
		fixed += sizeof(((struct attr_record *)NULL)->
			data.non_resident.compressed_size);
	if (used > allocated)
		return -EIO;
	free_bytes = allocated - used;
	if (free_bytes <= fixed)
		return -ENOSPC;
	free_bytes = round_down(free_bytes - fixed, 8);
	if (!free_bytes || free_bytes > U16_MAX)
		return free_bytes ? -E2BIG : -ENOSPC;
	return free_bytes;
}

static int ntfs_attr_extent_remove_transacted(
		struct ntfs_log_handle *handle, struct ntfs_attr_search_ctx *ctx,
		struct ntfs_inode **empty_ni)
{
	struct ntfs_inode *ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	u64 operation_lsn;
	u32 attr_len;
	u32 attrs_off;
	u32 used;
	u16 record_off;
	ptrdiff_t record_pos;
	int err;

	if (!handle || !ctx || !ctx->ntfs_ino || !ctx->mrec || !ctx->attr ||
	    !ctx->al_entry || !empty_ni)
		return -EINVAL;
	*empty_ni = NULL;
	ni = ctx->ntfs_ino;
	mrec = ctx->mrec;
	attr = ctx->attr;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	attrs_off = le16_to_cpu(mrec->attrs_offset);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    record_pos > used || attr_len > used - record_pos ||
	    attrs_off > used - attr_len)
		return -EIO;
	record_off = record_pos;
	err = ntfs_attr_mft_register_home_undo(handle, ni, mrec);
	if (err)
		return err;
	err = ntfs_log_mft_attribute_delete(handle, ni->mft_no, record_off,
			attr, attr_len, &operation_lsn);
	if (err)
		return err;
	err = ntfs_attr_record_resize(mrec, attr, 0);
	if (err)
		return err;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ni);
	err = ntfs_attrlist_entry_rm_transacted(handle, ctx);
	if (err)
		return err;
	used = le32_to_cpu(mrec->bytes_in_use);
	attrs_off = le16_to_cpu(mrec->attrs_offset);
	if (ni->nr_extents == -1 && attrs_off <= used &&
	    used - attrs_off == 8)
		*empty_ni = ni;
	return 0;
}

/* Leave the surviving tail mapped for the common resize/split path. */
static int ntfs_attr_remove_truncated_extents_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		struct ntfs_inode *base_ni, s64 end_vcn,
		struct ntfs_attr_search_ctx **last_ctx)
{
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct ntfs_inode *empty_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	s64 highest_vcn;
	s64 lowest_vcn;
	int err;

	*last_ctx = NULL;
	for (;;) {
		ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
		if (!ctx)
			return -ENOMEM;
		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, S64_MAX, NULL, 0, ctx);
		if (err)
			goto out;
		attr = ctx->attr;
		mrec = ctx->mrec;
		if (!attr || !mrec || !attr->non_resident ||
		    !ntfs_attr_record_flags_match(ni, attr)) {
			err = -EIO;
			goto out;
		}
		lowest_vcn = le64_to_cpu(attr->data.non_resident.lowest_vcn);
		highest_vcn = le64_to_cpu(attr->data.non_resident.highest_vcn);
		if (lowest_vcn < 0 || highest_vcn < lowest_vcn - 1 ||
		    highest_vcn == S64_MAX) {
			err = -EIO;
			goto out;
		}
		if (lowest_vcn < end_vcn || !lowest_vcn) {
			*last_ctx = ctx;
			return 0;
		}
		err = ntfs_attr_extent_remove_transacted(handle, ctx, &empty_ni);
		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
		if (err)
			return err;
		if (empty_ni) {
			err = ntfs_mft_record_free_transacted(handle, empty_ni);
			if (err)
				return err;
		}
	}
out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	return err;
}

/*
 * Create extents for runs [@next_vcn, @last_vcn] (or to the end of the runlist
 * when @last_vcn is -1) and publish them in the attribute list.
 */
static int ntfs_attr_publish_mapping_extents_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		struct ntfs_inode *base_ni, s64 next_vcn,
		struct runlist_element *next_rl, s64 last_vcn,
		__le16 attr_flags)
{
	struct ntfs_inode *ext_ni = NULL;
	struct mft_record *ext_mrec = NULL;
	struct attr_record *attr;
	u8 *new_pairs = NULL;
	u8 *old_pairs = NULL;
	u64 operation_lsn;
	u32 attr_len;
	u16 mapping_len;
	u16 mapping_off;
	s64 lowest_vcn;
	bool finished;
	bool has_compressed_size = ntfs_attr_has_compressed_size(ni);
	int mapping_size;
	int offset;
	const char *stage = "input validation";
	int err;

	if (!next_rl || !next_rl->length || next_vcn < 0 ||
	    (last_vcn != -1 && last_vcn < next_vcn)) {
		err = -EIO;
		goto out;
	}
	for (;;) {
		stage = "MFT extent allocation";
		err = ntfs_mft_record_alloc_transacted(handle, ni->vol, &ext_ni,
				base_ni, &ext_mrec);
		if (err)
			goto out;
		stage = "extent mapping capacity";
		mapping_size = ntfs_attr_new_extent_mapping_capacity(ni,
				ext_mrec, attr_flags);
		if (mapping_size < 0) {
			err = mapping_size;
			goto out;
		}
		stage = "mapping-pair sizing";
		err = ntfs_get_size_for_mapping_pairs(ni->vol, next_rl,
				next_vcn, last_vcn, mapping_size);
		if (err <= 0)
			goto out;
		mapping_size = min(mapping_size, err);
		stage = "extent attribute creation";
		offset = ntfs_non_resident_attr_record_add_transacted(handle,
				ext_ni, ni->type, ni->name, ni->name_len, next_vcn,
				mapping_size, attr_flags);
		if (offset < 0) {
			err = offset;
			goto out;
		}
		attr = (struct attr_record *)((u8 *)ext_mrec + offset);
		attr_len = le32_to_cpu(attr->length);
		mapping_off = le16_to_cpu(
				attr->data.non_resident.mapping_pairs_offset);
		stage = "extent attribute validation";
		if (mapping_off >= attr_len || attr_len > U16_MAX ||
		    mapping_off < offsetof(struct attr_record,
				data.non_resident.compressed_size) +
				(has_compressed_size ? sizeof(__le64) : 0) ||
		    !IS_ALIGNED(mapping_off, 8)) {
			err = -EIO;
			goto out;
		}
		mapping_len = attr_len - mapping_off;
		stage = "mapping-pair buffer allocation";
		old_pairs = kmemdup((u8 *)attr + mapping_off, mapping_len,
				GFP_NOFS);
		new_pairs = kzalloc(mapping_len, GFP_NOFS);
		if (!old_pairs || !new_pairs) {
			err = -ENOMEM;
			goto out;
		}
		lowest_vcn = next_vcn;
		stage = "mapping-pair encoding";
		err = ntfs_mapping_pairs_build(ni->vol, new_pairs, mapping_len,
				next_rl, lowest_vcn, last_vcn, &next_vcn,
				&next_rl, NULL);
		if (err && err != -ENOSPC)
			goto out;
		finished = !err;
		if (next_vcn <= lowest_vcn || !next_rl ||
		    (!finished && !next_rl->length) ||
		    (finished && last_vcn != -1 && next_vcn != last_vcn + 1)) {
			err = -EIO;
			goto out;
		}
		stage = "mapping-pair journal record";
		err = ntfs_attr_log_mapping_update(handle, ni, ext_ni->mft_no,
				offset, mapping_off, old_pairs,
				mapping_len, new_pairs, mapping_len,
				&operation_lsn);
		if (err)
			goto out;
		memcpy((u8 *)attr + mapping_off, new_pairs, mapping_len);
		attr->data.non_resident.highest_vcn =
				cpu_to_le64(next_vcn - 1);
		ext_mrec->lsn = cpu_to_le64(operation_lsn);
		mark_mft_record_dirty(ext_ni);
		stage = "attribute-list entry update";
		err = ntfs_attrlist_entry_add_transacted(handle, ext_ni, attr);
		if (err)
			goto out;
		unmap_mft_record(ext_ni);
		ext_ni = NULL;
		ext_mrec = NULL;
		kfree(old_pairs);
		old_pairs = NULL;
		kfree(new_pairs);
		new_pairs = NULL;
		if (finished)
			return 0;
	}
out:
	if (err)
		ntfs_error(ni->vol->sb,
			   "Failed to publish mapping extent for inode %llu attr 0x%x at %s (error %d).",
			   (unsigned long long)base_ni->mft_no,
			   le32_to_cpu(ni->type), stage, err);
	if (ext_ni)
		unmap_mft_record(ext_ni);
	kfree(old_pairs);
	kfree(new_pairs);
	return err;
}

static int ntfs_attr_update_mapping_pairs_extent_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct ntfs_inode *base_ni;
	struct runlist_element *next_rl = NULL;
	struct attr_record *attr;
	struct mft_record *mrec;
	u8 *new_pairs = NULL;
	u8 *old_pairs = NULL;
	u64 operation_lsn;
	u32 allocated;
	u32 attr_len;
	u32 entry_len;
	u32 free_bytes;
	u32 max_attr_len;
	u32 new_attr_len;
	u32 used;
	__le16 attr_flags;
	u16 mapping_len;
	u16 mapping_off;
	u16 old_mapping_len;
	u16 record_off;
	s64 end_vcn;
	s64 highest_vcn;
	s64 lowest_vcn;
	s64 next_vcn;
	s64 old_next_vcn;
	ptrdiff_t record_pos;
	bool finished;
	bool has_compressed_size;
	int required_mapping_size;
	const char *stage = "runlist validation";
	int err;

	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni ||
	    (NInoEncrypted(ni) && !ntfs_attr_deleted_encrypted(ni)) ||
	    (NInoCompressed(ni) && NInoSparse(ni)))
		return -EOPNOTSUPP;
	has_compressed_size = ntfs_attr_has_compressed_size(ni);
	if (!ni->runlist.rl)
		return -EINVAL;
	next_rl = ni->runlist.rl;
	while (next_rl->length)
		next_rl++;
	end_vcn = next_rl->vcn;
	if (end_vcn < 0)
		return -EOPNOTSUPP;

	if (!NInoAttrList(base_ni)) {
		if (base_ni->nr_extents)
			return -EOPNOTSUPP;
		stage = "initial attribute-list creation";
		err = ntfs_inode_add_attrlist_transacted(handle, base_ni);
		if (err)
			return err;
	}
	/*
	 * Only rewrite the last extent.  If its new mapping pairs no longer fit,
	 * the remaining runs (including any previously covered tail) can start
	 * in a new extent at the returned run boundary.
	 */
	stage = "last extent lookup/truncation";
	err = ntfs_attr_remove_truncated_extents_transacted(handle, ni,
			base_ni, end_vcn, &ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	stage = "last extent validation";
	if (!attr || !mrec || !attr->non_resident ||
	    !ntfs_attr_record_flags_match(ni, attr)) {
		err = -EIO;
		goto out;
	}
	lowest_vcn = le64_to_cpu(attr->data.non_resident.lowest_vcn);
	highest_vcn = le64_to_cpu(attr->data.non_resident.highest_vcn);
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off = le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(mapping_off, 8) ||
	    mapping_off < offsetof(struct attr_record,
			data.non_resident.compressed_size) +
			(has_compressed_size ? sizeof(__le64) : 0) ||
	    mapping_off >= attr_len || attr_len > U16_MAX || used > allocated ||
	    record_pos > used || attr_len > used - record_pos ||
	    lowest_vcn < 0 || lowest_vcn > end_vcn ||
	    highest_vcn < lowest_vcn - 1 ||
	    highest_vcn == S64_MAX) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	old_mapping_len = attr_len - mapping_off;
	old_next_vcn = highest_vcn + 1;
	if (ni->type == AT_ATTRIBUTE_LIST) {
		stage = "attribute-list mapping capacity";
		required_mapping_size = ntfs_get_size_for_mapping_pairs(ni->vol,
				ni->runlist.rl, lowest_vcn, -1, -1);
		if (required_mapping_size <= 0 ||
		    check_add_overflow((u32)mapping_off,
				(u32)required_mapping_size, &max_attr_len)) {
			err = required_mapping_size < 0 ?
				required_mapping_size : -EIO;
			goto out;
		}
		max_attr_len = ALIGN(max_attr_len, 8);
		if (max_attr_len > attr_len + allocated - used) {
			err = -EOPNOTSUPP;
			goto out;
		}
	} else if (ctx->ntfs_ino == base_ni) {
		max_attr_len = attr_len;
	} else {
		max_attr_len = attr_len + allocated - used;
	}
	if (max_attr_len > U16_MAX || max_attr_len <= mapping_off) {
		err = -E2BIG;
		goto out;
	}
	mapping_len = max_attr_len - mapping_off;
	new_attr_len = max_attr_len;
	stage = "mapping-pair buffer allocation";
	old_pairs = kmemdup((u8 *)attr + mapping_off, old_mapping_len,
			GFP_NOFS);
	new_pairs = kzalloc(mapping_len, GFP_NOFS);
	if (!old_pairs || !new_pairs) {
		err = -ENOMEM;
		goto out;
	}
	next_vcn = lowest_vcn;
	stage = "mapping-pair encoding";
	err = ntfs_mapping_pairs_build(ni->vol, new_pairs, mapping_len,
			ni->runlist.rl, lowest_vcn, -1, &next_vcn,
			&next_rl, NULL);
	/* An empty base extent may need a few more bytes for its first run. */
	if (err == -ENOSPC && next_vcn == lowest_vcn && next_rl &&
	    highest_vcn == lowest_vcn - 1 && next_rl->length &&
	    next_rl[1].vcn > lowest_vcn) {
		required_mapping_size = ntfs_get_size_for_mapping_pairs(
				ni->vol, next_rl, lowest_vcn,
				next_rl[1].vcn - 1, -1);
		if (required_mapping_size <= 0 ||
		    check_add_overflow((u32)mapping_off,
				(u32)required_mapping_size, &new_attr_len)) {
			err = required_mapping_size < 0 ?
				required_mapping_size : -EIO;
			goto out;
		}
		new_attr_len = ALIGN(new_attr_len, 8);
		free_bytes = allocated - used;
		entry_len = next_rl[1].length ?
			ALIGN(sizeof(struct attr_list_entry) +
				ni->name_len * sizeof(__le16), 8) : 0;
		if (new_attr_len > U16_MAX || entry_len > free_bytes ||
		    new_attr_len > attr_len + free_bytes - entry_len) {
			err = -EOPNOTSUPP;
			goto out;
		}
		mapping_len = new_attr_len - mapping_off;
		kfree(new_pairs);
		new_pairs = kzalloc(mapping_len, GFP_NOFS);
		if (!new_pairs) {
			err = -ENOMEM;
			goto out;
		}
		next_vcn = lowest_vcn;
		err = ntfs_mapping_pairs_build(ni->vol, new_pairs,
				mapping_len, ni->runlist.rl, lowest_vcn,
				-1, &next_vcn, &next_rl, NULL);
	}
	if (err && err != -ENOSPC)
		goto out;
	if (err == -ENOSPC && ni->type == AT_ATTRIBUTE_LIST) {
		err = -EOPNOTSUPP;
		goto out;
	}
	finished = !err;
	if (!next_rl || (finished && next_vcn != end_vcn) ||
	    (!finished && !next_rl->length)) {
		err = -EIO;
		goto out;
	}
	if (!finished && next_vcn <= lowest_vcn) {
		ntfs_error(ni->vol->sb,
			   "Last mapping extent cannot fit its first run (inode %llu, attr 0x%x, start %lld, old end %lld, stream end %lld).",
			   (unsigned long long)base_ni->mft_no,
			   le32_to_cpu(ni->type), lowest_vcn, old_next_vcn,
			   end_vcn);
		err = -EOPNOTSUPP;
		goto out;
	}
	if (next_vcn != old_next_vcn ||
	    mapping_len != old_mapping_len ||
	    memcmp(old_pairs, new_pairs, mapping_len)) {
		stage = "mapping-pair home undo registration";
		err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino,
				mrec);
		if (err)
			goto out;
		stage = "mapping-pair journal record";
		err = ntfs_attr_log_mapping_update(handle, ni,
						   ctx->ntfs_ino->mft_no, record_off, mapping_off,
						   old_pairs, old_mapping_len, new_pairs,
						   mapping_len, &operation_lsn);
		if (err)
			goto out;
		stage = "mapping-pair record resize";
		err = ntfs_attr_record_resize(mrec, attr, new_attr_len);
		if (err)
			goto out;
		memcpy((u8 *)attr + mapping_off, new_pairs, mapping_len);
		attr->data.non_resident.highest_vcn =
				cpu_to_le64(next_vcn - 1);
		mrec->lsn = cpu_to_le64(operation_lsn);
		mark_mft_record_dirty(ctx->ntfs_ino);
		kfree(old_pairs);
		old_pairs = NULL;
		kfree(new_pairs);
		new_pairs = NULL;
	} else {
		kfree(old_pairs);
		old_pairs = NULL;
		kfree(new_pairs);
		new_pairs = NULL;
	}
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	if (next_vcn < 0 || next_vcn > end_vcn) {
		stage = "mapping extent boundary";
		err = -EOPNOTSUPP;
		goto out;
	}
	stage = "base inode size update";
	err = ntfs_attr_update_base_sizes_transacted(handle, ni, base_ni,
			&attr_flags);
	if (err)
		goto out;
	if (finished)
		return 0;

	stage = "split extent publication";
	err = ntfs_attr_publish_mapping_extents_transacted(handle, ni, base_ni,
			next_vcn, next_rl, -1, attr_flags);
	goto out;
out:
	if (err)
		ntfs_error(ni->vol->sb,
			   "Failed to update mapping extent for inode %llu attr 0x%x at %s (error %d).",
			   (unsigned long long)base_ni->mft_no,
			   le32_to_cpu(ni->type), stage, err);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	kfree(old_pairs);
	kfree(new_pairs);
	return err;
}

int ntfs_attr_update_non_tail_mapping_pairs_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	struct runlist_element *end_rl;
	struct runlist_element *stop_rl;
	u8 *old_pairs = NULL;
	u8 *new_pairs = NULL;
	u64 last_mft_no;
	u64 operation_lsn;
	u32 attr_len;
	u32 new_attr_len;
	u32 used;
	u32 allocated;
	u32 free_bytes;
	u16 last_record_off;
	u16 last_instance;
	u16 record_off;
	u16 mapping_off;
	u16 mapping_len;
	u16 old_mapping_len;
	u16 name_off;
	s64 end_vcn;
	s64 lowest_vcn;
	s64 highest_vcn;
	s64 stop_vcn;
	ptrdiff_t record_pos;
	__le16 attr_flags;
	bool split;
	int mapping_size;
	const char *stage = "runlist validation";
	int err;

	if (!handle || !ni || !ni->runlist.rl)
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	if (!NInoAttrList(base_ni))
		return 0;

	end_rl = ni->runlist.rl;
	while (end_rl->length)
		end_rl++;
	end_vcn = end_rl->vcn;
	if (end_vcn < 0) {
		stage = "runlist end";
		err = -EIO;
		goto out;
	}

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	stage = "last extent lookup";
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, S64_MAX, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	stage = "last extent validation";
	if (!attr || !mrec || !ctx->ntfs_ino || !attr->non_resident ||
	    !ntfs_attr_record_flags_match(ni, attr)) {
		err = -EIO;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	lowest_vcn = le64_to_cpu(attr->data.non_resident.lowest_vcn);
	highest_vcn = le64_to_cpu(attr->data.non_resident.highest_vcn);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || used > allocated ||
	    record_pos > used || attr_len > used - record_pos ||
	    attr_len > U16_MAX || lowest_vcn < 0 ||
	    highest_vcn < lowest_vcn - 1 || highest_vcn == S64_MAX) {
		err = -EIO;
		goto out;
	}
	last_mft_no = ctx->ntfs_ino->mft_no;
	last_record_off = record_pos;
	last_instance = attr->instance;
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;

restart:
	stage = "non-tail extent scan";
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	while (!(err = ntfs_attrs_walk(ctx))) {
		stage = "non-tail attribute scan";
		attr = ctx->attr;
		if (!attr->non_resident ||
		    attr->type != ni->type ||
		    !ntfs_attr_record_flags_match(ni, attr) ||
		    attr->name_length != ni->name_len)
			continue;

		attr_len = le32_to_cpu(attr->length);
		name_off = le16_to_cpu(attr->name_offset);
		if (attr->name_length &&
		    (name_off > attr_len ||
		     attr->name_length * sizeof(__le16) > attr_len - name_off)) {
			err = -EIO;
			break;
		}
		if (attr->name_length &&
		    !ntfs_are_names_equal((__le16 *)((u8 *)attr + name_off),
			    attr->name_length, ni->name, ni->name_len,
			    CASE_SENSITIVE, ni->vol->upcase,
			    ni->vol->upcase_len))
			continue;

		stage = "non-tail extent validation";
		mrec = ctx->mrec;
		record_pos = (u8 *)attr - (u8 *)mrec;
		if (record_pos < 0 || record_pos > U16_MAX ||
		    !IS_ALIGNED(record_pos, 8)) {
			err = -EIO;
			break;
		}
		if (ctx->ntfs_ino->mft_no == last_mft_no &&
		    record_pos == last_record_off &&
		    attr->instance == last_instance)
			continue;

		lowest_vcn = le64_to_cpu(attr->data.non_resident.lowest_vcn);
		highest_vcn = le64_to_cpu(attr->data.non_resident.highest_vcn);
		if (lowest_vcn < 0 || highest_vcn < lowest_vcn - 1 ||
		    highest_vcn == S64_MAX) {
			err = -EIO;
			break;
		}
		if (lowest_vcn >= end_vcn ||
		    highest_vcn == lowest_vcn - 1)
			continue;
		/* The tail updater handles the extent overlapping the new end. */
		if (highest_vcn + 1 >= end_vcn)
			continue;

		used = le32_to_cpu(mrec->bytes_in_use);
		allocated = le32_to_cpu(mrec->bytes_allocated);
		mapping_off =
			le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
		if (used > allocated || attr_len > U16_MAX ||
		    record_pos > used || attr_len > used - record_pos ||
		    !IS_ALIGNED(mapping_off, 8) ||
		    mapping_off < offsetof(struct attr_record,
			    data.non_resident.compressed_size) +
			    (ntfs_attr_has_compressed_size(ni) ?
			     sizeof(__le64) : 0) ||
		    mapping_off >= attr_len) {
			err = -EIO;
			break;
		}
		stage = "non-tail mapping-pair sizing";
		old_mapping_len = attr_len - mapping_off;
		mapping_size = ntfs_get_size_for_mapping_pairs(ni->vol,
				ni->runlist.rl, lowest_vcn, highest_vcn, -1);
		if (mapping_size <= 0) {
			err = mapping_size ? mapping_size : -EIO;
			break;
		}
		stage = "non-tail extent sizing";
		new_attr_len = attr_len;
		split = false;
		if (mapping_size > old_mapping_len) {
			if (check_add_overflow((u32)mapping_off,
					(u32)mapping_size, &new_attr_len)) {
				err = -EOVERFLOW;
				break;
			}
			new_attr_len = ALIGN(new_attr_len, 8);
			free_bytes = allocated - used;
			if (new_attr_len > U16_MAX ||
			    new_attr_len - attr_len > free_bytes) {
				/*
				 * Keep what fits here and move the remaining
				 * runs of this extent into new extent records.
				 * The base record keeps its size so the
				 * attribute list can still grow.
				 */
				split = true;
				new_attr_len = attr_len;
				if (ctx->ntfs_ino != base_ni)
					new_attr_len = round_down(min_t(u32,
						attr_len + free_bytes,
						U16_MAX), 8);
				if (new_attr_len <= mapping_off) {
					err = -EOPNOTSUPP;
					break;
				}
			}
		}
		mapping_len = new_attr_len - mapping_off;
		stage = "non-tail mapping-pair buffer allocation";
		old_pairs = kmemdup((u8 *)attr + mapping_off, old_mapping_len,
				GFP_NOFS);
		new_pairs = kzalloc(mapping_len, GFP_NOFS);
		if (!old_pairs || !new_pairs) {
			err = -ENOMEM;
			break;
		}
		stop_vcn = highest_vcn + 1;
		stop_rl = NULL;
		stage = "non-tail mapping-pair encoding";
		err = ntfs_mapping_pairs_build(ni->vol, (s8 *)new_pairs,
				mapping_len, ni->runlist.rl, lowest_vcn,
				highest_vcn, &stop_vcn, &stop_rl, NULL);
		if (err == -ENOSPC && split) {
			if (stop_vcn <= lowest_vcn || stop_vcn > highest_vcn ||
			    !stop_rl || !stop_rl->length) {
				ntfs_error(ni->vol->sb,
					   "Cannot split mapping extent (inode %llu, attr 0x%x, vcn %lld-%lld, stop %lld).",
					   (unsigned long long)base_ni->mft_no,
					   le32_to_cpu(ni->type), lowest_vcn,
					   highest_vcn, stop_vcn);
				err = -EOPNOTSUPP;
				break;
			}
			err = 0;
		} else if (err) {
			break;
		} else {
			split = false;
		}
		if (mapping_len != old_mapping_len ||
		    memcmp(old_pairs, new_pairs, old_mapping_len)) {
			record_off = record_pos;
			stage = "non-tail MFT undo registration";
			err = ntfs_attr_mft_register_home_undo(handle,
					ctx->ntfs_ino, mrec);
			if (err)
				break;
			stage = "non-tail mapping-pair journal record";
			err = ntfs_attr_log_mapping_update(handle, ni,
					ctx->ntfs_ino->mft_no, record_off,
					mapping_off, old_pairs, old_mapping_len,
					new_pairs, mapping_len, &operation_lsn);
			if (err)
				break;
			stage = "non-tail mapping-pair record resize";
			err = ntfs_attr_record_resize(mrec, attr, new_attr_len);
			if (err)
				break;
			memcpy((u8 *)attr + mapping_off, new_pairs, mapping_len);
			if (split)
				attr->data.non_resident.highest_vcn =
						cpu_to_le64(stop_vcn - 1);
			mrec->lsn = cpu_to_le64(operation_lsn);
			mark_mft_record_dirty(ctx->ntfs_ino);
		}
		kfree(old_pairs);
		old_pairs = NULL;
		kfree(new_pairs);
		new_pairs = NULL;
		if (split) {
			attr_flags = attr->flags;
			ntfs_attr_put_search_ctx(ctx);
			ctx = NULL;
			stage = "non-tail split extent publication";
			err = ntfs_attr_publish_mapping_extents_transacted(
					handle, ni, base_ni, stop_vcn, stop_rl,
					highest_vcn, attr_flags);
			if (err)
				goto out;
			/* The attribute list changed. Rescan the extents. */
			goto restart;
		}
	}
	if (err == -ENOENT)
		err = 0;
out:
	if (err)
		ntfs_error(ni->vol->sb,
			   "Failed to update non-tail mapping pairs for inode %llu attr 0x%x at %s (error %d).",
			   (unsigned long long)base_ni->mft_no,
			   le32_to_cpu(ni->type), stage, err);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	kfree(old_pairs);
	kfree(new_pairs);
	return err;
}

static int ntfs_attr_sync_sparse_flag_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni, bool sparse)
{
	struct ntfs_attr_search_ctx *ctx;
	struct standard_information *si;
	struct attr_record *attr;
	struct mft_record *mrec;
	const u32 flag_end = offsetof(struct standard_information, file_attributes) +
			sizeof(si->file_attributes);
	ptrdiff_t record_pos;
	u64 operation_lsn;
	u32 attr_len;
	u32 used;
	u16 value_off;
	u16 flag_off;
	__le32 old_flags;
	__le32 new_flags;
	int err;

	if (NInoAttr(ni) || ni->name != AT_UNNAMED)
		return 0;
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(AT_STANDARD_INFORMATION, NULL, 0,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	if (attr->non_resident || record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || record_pos > used ||
	    attr_len > used - record_pos || value_off > attr_len ||
	    le32_to_cpu(attr->data.resident.value_length) < flag_end ||
	    flag_end > attr_len - value_off ||
	    value_off > U16_MAX - flag_end) {
		err = -EIO;
		goto out;
	}
	flag_off = value_off +
			offsetof(struct standard_information, file_attributes);
	si = (struct standard_information *)((u8 *)attr + value_off);
	old_flags = si->file_attributes;
	new_flags = sparse ? old_flags | FILE_ATTR_SPARSE_FILE :
			old_flags & ~FILE_ATTR_SPARSE_FILE;
	if (old_flags == new_flags) {
		err = 0;
		goto out;
	}
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out;
	err = ntfs_log_mft_resident_update(handle, ctx->ntfs_ino->mft_no,
			record_pos, flag_off, &old_flags, sizeof(old_flags),
			&new_flags, sizeof(new_flags), &operation_lsn);
	if (err)
		goto out;
	si->file_attributes = new_flags;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

/* Caller holds the stream runlist and base MFT locks. */
static int ntfs_attr_update_sparse_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	struct runlist_element *end_rl;
	struct runlist_element *stop_rl;
	struct ntfs_inode *base_ni;
	struct ntfs_inode *target_ni;
	struct ntfs_attr_search_ctx *ctx;
	struct attr_record *attr;
	struct attr_record *new_attr = NULL;
	struct mft_record *mrec;
	struct mft_record *target_mrec;
	u64 operation_lsn;
	s64 physical_size;
	s64 lowest_vcn;
	s64 end_vcn;
	s64 stop_vcn;
	ptrdiff_t record_pos;
	u32 attr_len;
	u32 new_len;
	u32 old_header;
	u32 new_header;
	u32 used;
	u32 allocated;
	u16 name_off;
	u16 mapping_off;
	u16 new_mapping_off;
	__le16 split_flags;
	bool old_sparse;
	bool repack;
	bool split;
	int sparse;
	int err;

	if (ni->type != AT_DATA || NInoCompressed(ni) || NInoEncrypted(ni))
		return 0;
	sparse = ntfs_rl_sparse(ni->runlist.rl);
	if (sparse < 0)
		return sparse;
	physical_size = ntfs_rl_get_compressed_size(ni->vol, ni->runlist.rl);
	if (physical_size < 0)
		return physical_size;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	if (!!sparse == !!NInoSparse(ni))
		goto update_size;
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		return err;
restart:
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	while (!(err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx))) {
		attr = ctx->attr;
		mrec = ctx->mrec;
		if (!attr || !mrec || !attr->non_resident ||
		    (attr->flags & (ATTR_IS_COMPRESSED | ATTR_IS_ENCRYPTED))) {
			err = -EIO;
			goto out;
		}
		old_sparse = !!(attr->flags & ATTR_IS_SPARSE);
		if (old_sparse == !!sparse)
			continue;
		record_pos = (u8 *)attr - (u8 *)mrec;
		attr_len = le32_to_cpu(attr->length);
		used = le32_to_cpu(mrec->bytes_in_use);
		allocated = le32_to_cpu(mrec->bytes_allocated);
		mapping_off = le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
		name_off = le16_to_cpu(attr->name_offset);
		old_header = offsetof(struct attr_record,
				data.non_resident.compressed_size) +
				(old_sparse ? sizeof(__le64) : 0);
		new_header = offsetof(struct attr_record,
				data.non_resident.compressed_size) +
				(sparse ? sizeof(__le64) : 0);
		if (record_pos < 0 || record_pos > U16_MAX ||
		    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(attr_len, 8) ||
		    attr_len > U16_MAX || used > allocated || record_pos > used ||
		    attr_len > used - record_pos || mapping_off < old_header ||
		    mapping_off >= attr_len ||
		    (attr->name_length && (name_off < old_header ||
		     name_off > mapping_off ||
		     attr->name_length * sizeof(__le16) > mapping_off - name_off))) {
			err = -EIO;
			goto out;
		}
		new_len = attr_len - old_header + new_header;
		if (new_len > U16_MAX) {
			err = -E2BIG;
			goto out;
		}
		repack = false;
		split = false;
		stop_rl = NULL;
		new_mapping_off = mapping_off - old_header + new_header;
		if (new_len > attr_len + allocated - used) {
			if (!NInoAttrList(base_ni)) {
				ntfs_attr_put_search_ctx(ctx);
				err = ntfs_inode_add_attrlist_transacted(handle, base_ni);
				if (err)
					return err;
				goto restart;
			}
			/* A full extent cannot gain space by moving unchanged. */
			if (new_mapping_off >= attr_len)
				goto relocate;
			repack = true;
			new_len = attr_len;
		}
		new_attr = kzalloc(new_len, GFP_NOFS);
		if (!new_attr) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(new_attr, attr, offsetof(struct attr_record,
				data.non_resident.compressed_size));
		memcpy((u8 *)new_attr + new_header, (u8 *)attr + old_header,
				repack ? mapping_off - old_header :
					attr_len - old_header);
		new_attr->length = cpu_to_le32(new_len);
		new_attr->flags = sparse ? attr->flags | ATTR_IS_SPARSE :
				attr->flags & ~ATTR_IS_SPARSE;
		new_attr->data.non_resident.compression_unit = 0;
		if (name_off)
			new_attr->name_offset = cpu_to_le16(name_off - old_header +
					new_header);
		new_attr->data.non_resident.mapping_pairs_offset =
				cpu_to_le16(new_mapping_off);
		if (sparse)
			new_attr->data.non_resident.compressed_size =
					cpu_to_le64(physical_size);
		if (repack) {
			lowest_vcn = le64_to_cpu(attr->data.non_resident.lowest_vcn);
			end_vcn = le64_to_cpu(attr->data.non_resident.highest_vcn);
			if (!ni->runlist.rl || lowest_vcn < 0 ||
			    end_vcn < lowest_vcn - 1 || end_vcn == S64_MAX) {
				err = -EIO;
				goto out;
			}
			end_vcn++;
			end_rl = ni->runlist.rl;
			while (end_rl->length)
				end_rl++;
			end_vcn = min(end_vcn, end_rl->vcn);
			stop_vcn = lowest_vcn;
			if (end_vcn > lowest_vcn) {
				err = ntfs_mapping_pairs_build(ni->vol,
						(s8 *)new_attr + new_mapping_off,
						new_len - new_mapping_off,
						ni->runlist.rl, lowest_vcn,
						end_vcn - 1, &stop_vcn, &stop_rl,
						NULL);
				if (err && err != -ENOSPC)
					goto out;
				if (stop_vcn <= lowest_vcn)
					goto relocate;
				split = err == -ENOSPC;
				if (stop_vcn > end_vcn ||
				    (split && (!stop_rl || !stop_rl->length)) ||
				    (!split && stop_vcn != end_vcn)) {
					err = -EIO;
					goto out;
				}
			}
			new_attr->data.non_resident.highest_vcn =
					cpu_to_le64(stop_vcn - 1);
		}
		err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
		if (err)
			goto out;
		/* Header layout changes must replay as whole attribute replacements. */
		err = ntfs_log_mft_attribute_delete(handle, ctx->ntfs_ino->mft_no,
				record_pos, attr, attr_len, &operation_lsn);
		if (!err)
			err = ntfs_log_mft_attribute_create(handle, ctx->ntfs_ino->mft_no,
					record_pos, new_attr, new_len, &operation_lsn);
		if (err)
			goto out;
		err = ntfs_attr_record_resize(mrec, attr, new_len);
		if (err)
			goto out;
		memcpy(attr, new_attr, new_len);
		kfree(new_attr);
		new_attr = NULL;
		mrec->lsn = cpu_to_le64(operation_lsn);
		mark_mft_record_dirty(ctx->ntfs_ino);
		if (split) {
			split_flags = attr->flags;
			ntfs_attr_put_search_ctx(ctx);
			err = ntfs_attr_publish_mapping_extents_transacted(handle,
					ni, base_ni, stop_vcn, stop_rl,
					end_vcn - 1, split_flags);
			if (err)
				return err;
			goto restart;
		}
		continue;

relocate:
		kfree(new_attr);
		new_attr = NULL;
		target_ni = NULL;
		target_mrec = NULL;
		err = ntfs_mft_record_alloc_transacted(handle, ni->vol,
				&target_ni, base_ni, &target_mrec);
		if (err)
			goto out;
		/* Relocation must leave room for the expanded header. */
		if (le32_to_cpu(target_mrec->bytes_in_use) >
		    le32_to_cpu(target_mrec->bytes_allocated) ||
		    attr_len - old_header + new_header >
			le32_to_cpu(target_mrec->bytes_allocated) -
			le32_to_cpu(target_mrec->bytes_in_use))
			err = -EOPNOTSUPP;
		else
			err = ntfs_attr_record_move_to_new_extent_transacted(handle,
					ctx, target_ni, target_mrec, NULL, 0);
		unmap_mft_record(target_ni);
		ntfs_attr_put_search_ctx(ctx);
		if (err)
			return err;
		goto restart;
	}
	if (err == -ENOENT)
		err = 0;
out:
	kfree(new_attr);
	ntfs_attr_put_search_ctx(ctx);
	if (err)
		return err;
	err = ntfs_attr_sync_sparse_flag_transacted(handle, ni, sparse);
	if (err)
		return err;
	if (sparse) {
		NInoSetSparse(ni);
		ni->flags |= FILE_ATTR_SPARSE_FILE;
	} else {
		NInoClearSparse(ni);
		ni->flags &= ~FILE_ATTR_SPARSE_FILE;
	}
	ni->itype.compressed.block_size = 0;
	ni->itype.compressed.block_size_bits = 0;
	ni->itype.compressed.block_clusters = 0;
update_size:
	ni->itype.compressed.size = physical_size;
	VFS_I(ni)->i_blocks = physical_size >> 9;
	ntfs_attr_accounting_inode(ni)->i_blocks = VFS_I(ni)->i_blocks;
	if (ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	return 0;
}

/* Caller holds the runlist lock. */
static bool ntfs_attr_pending_eof_mapped(struct ntfs_inode *ni)
{
	struct runlist_element *rl;
	s64 last_vcn;

	if (!ni->data_size)
		return true;
	last_vcn = ntfs_bytes_to_cluster(ni->vol, ni->data_size - 1);
	for (rl = ni->runlist.rl; rl && rl->length && rl->vcn <= last_vcn; rl++)
		if (rl->lcn >= 0)
			return true;
	return false;
}

int ntfs_attr_update_mapping_pairs_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	struct runlist_element *stop_rl;
	ptrdiff_t record_pos;
	s64 stop_vcn;
	u64 operation_lsn;
	u8 *new_pairs = NULL;
	u8 *old_pairs = NULL;
	u32 attr_len;
	u32 new_attr_len;
	u32 used;
	u32 allocated;
	u16 record_off;
	u16 mapping_off;
	u16 old_len;
	u16 new_len;
	int mapping_size;
	const char *stage = "attribute lookup";
	bool has_compressed_size;
	bool publish_pending = false;
	int err;

	if (!handle || !ni || !NInoNonResident(ni))
		return -EINVAL;
	if ((NInoEncrypted(ni) && !ntfs_attr_deleted_encrypted(ni)) ||
	    (NInoCompressed(ni) && NInoSparse(ni)))
		return -EOPNOTSUPP;
	/* Publish the deferred EOF only with a mapping inside the file. */
	if (NInoPendingEmptyEof(ni) && ntfs_attr_pending_eof_mapped(ni)) {
		NInoClearPendingEmptyEof(ni);
		publish_pending = true;
	}
	err = ntfs_attr_update_sparse_transacted(handle, ni);
	if (err)
		goto out_pending;
	has_compressed_size = ntfs_attr_has_compressed_size(ni);
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni) {
		err = -EINVAL;
		goto out_pending;
	}
	if (NInoAttrList(base_ni)) {
		err = ntfs_attr_update_mapping_pairs_extent_transacted(handle, ni);
		if (err && ni == NTFS_I(ni->vol->mft_ino))
			ntfs_error(ni->vol->sb,
				   "Failed transacted $MFT mapping extent update (error %d).",
				   err);
		goto out_pending;
	}

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_pending;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	stage = "attribute state";
	if (!attr || !mrec || !attr->non_resident ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    !ntfs_attr_record_flags_match(ni, attr)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off = le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(mapping_off, 8) ||
	    mapping_off < offsetof(struct attr_record,
			data.non_resident.compressed_size) +
			(has_compressed_size ? sizeof(__le64) : 0) ||
	    mapping_off > attr_len || attr_len > U16_MAX ||
	    used < record_pos + attr_len || used > allocated) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	old_len = attr_len - mapping_off;
	if (!old_len) {
		err = -EIO;
		goto out;
	}

	stage = "mapping size";
	mapping_size = ntfs_get_size_for_mapping_pairs(ni->vol,
			ni->runlist.rl, 0, -1, -1);
	if (mapping_size <= 0) {
		err = mapping_size ? mapping_size : -EIO;
		goto out;
	}
	if (check_add_overflow((u32)mapping_off, (u32)mapping_size,
			&new_attr_len)) {
		err = -EOVERFLOW;
		goto out;
	}
	new_attr_len = ALIGN(new_attr_len, 8);
	if (new_attr_len > U16_MAX ||
	    new_attr_len > attr_len + allocated - used) {
		ntfs_attr_put_search_ctx(ctx);
		err = ntfs_attr_update_mapping_pairs_extent_transacted(handle, ni);
		goto out_pending;
	}
	new_len = new_attr_len - mapping_off;
	old_pairs = kmemdup((u8 *)attr + mapping_off, old_len, GFP_NOFS);
	new_pairs = kzalloc(new_len, GFP_NOFS);
	if (!old_pairs || !new_pairs) {
		err = -ENOMEM;
		goto out;
	}
	stop_vcn = 0;
	stop_rl = NULL;
	stage = "mapping build";
	err = ntfs_mapping_pairs_build(ni->vol, new_pairs, mapping_size,
			ni->runlist.rl, 0, -1, &stop_vcn, &stop_rl, NULL);
	if (err || !stop_rl || stop_rl->length) {
		if (!err)
			err = -EIO;
		goto out;
	}

	old_sizes.alloc_size = attr->data.non_resident.allocated_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	new_sizes.alloc_size = cpu_to_le64(ni->allocated_size);
	new_sizes.valid_size = cpu_to_le64(ntfs_inode_recorded_initialized_size(ni));
	new_sizes.data_size = cpu_to_le64(ntfs_inode_recorded_data_size(ni));
	if (has_compressed_size) {
		old_sizes.total_size = attr->data.non_resident.compressed_size;
		new_sizes.total_size = cpu_to_le64(ni->itype.compressed.size);
	}
	stage = "home undo registration";
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out;
	stage = "mapping journal record";
	err = ntfs_attr_log_mapping_update(handle, ni, ctx->ntfs_ino->mft_no,
					   record_off, mapping_off, old_pairs, old_len, new_pairs,
					   new_len, &operation_lsn);
	if (err)
		goto out;
	stage = "size journal record";
	err = ntfs_attr_log_sizes_update(handle, ni, ctx->ntfs_ino->mft_no,
					 record_off, &old_sizes, &new_sizes, has_compressed_size,
					 &operation_lsn);
	if (err)
		goto out;

	stage = "attribute resize";
	err = ntfs_attr_record_resize(mrec, attr, new_attr_len);
	if (err)
		goto out;
	memcpy((u8 *)attr + mapping_off, new_pairs, new_len);
	attr->data.non_resident.highest_vcn = cpu_to_le64(stop_vcn - 1);
	attr->data.non_resident.allocated_size = new_sizes.alloc_size;
	attr->data.non_resident.initialized_size = new_sizes.valid_size;
	attr->data.non_resident.data_size = new_sizes.data_size;
	if (has_compressed_size)
		attr->data.non_resident.compressed_size = new_sizes.total_size;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
out:
	if (err)
		ntfs_error(ni->vol->sb,
			   "Failed transacted mapping update for inode %llu attr 0x%x at %s (error %d).",
			   (unsigned long long)base_ni->mft_no,
			   le32_to_cpu(ni->type), stage, err);
	kfree(new_pairs);
	kfree(old_pairs);
	ntfs_attr_put_search_ctx(ctx);
out_pending:
	if (err && publish_pending)
		NInoSetPendingEmptyEof(ni);
	return err;
}

int ntfs_attr_logical_shrink_log_credits(struct ntfs_volume *vol,
		bool has_compressed_size)
{
	if (!vol)
		return -EINVAL;
	return ntfs_log_mft_attribute_sizes_credits(vol, has_compressed_size);
}

int ntfs_attr_logical_grow_log_credits(struct ntfs_volume *vol,
		bool has_compressed_size)
{
	return ntfs_attr_logical_shrink_log_credits(vol,
			has_compressed_size);
}

/* Grow the logical EOF without changing allocation or mapping pairs. */
static int __ntfs_attr_logical_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_log *coalesce_log, struct ntfs_inode *ni, s64 new_size,
		bool initialize, bool ordered, bool delalloc, bool publish_pending)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	u64 operation_lsn;
	u32 attr_len;
	u32 used;
	u16 mapping_off;
	u16 record_off;
	ptrdiff_t record_pos;
	bool has_compressed_size;
	int err;

	if ((!!handle == !!coalesce_log) || !ni || new_size < 0 ||
	    !NInoNonResident(ni))
		return -EINVAL;
	if (publish_pending && (!handle || !NInoPendingEmptyEof(ni) ||
	    !new_size || new_size != ni->data_size))
		return -EINVAL;
	if ((NInoEncrypted(ni) && !ntfs_attr_deleted_encrypted(ni)) ||
	    (NInoCompressed(ni) && NInoSparse(ni)))
		return -EOPNOTSUPP;
	if (new_size < ni->data_size || new_size > ni->allocated_size)
		return -EINVAL;
	/* An unzeroed tail requires a data dependency before its size record. */
	if (initialize && (ni->initialized_size != ni->data_size ||
	    (delalloc ? (!NInoGapAppend(ni) || NInoCompressed(ni)) :
	     (NInoSparse(ni) || NInoCompressed(ni) ||
	      (!ordered && new_size > ni->zeroed_size)))))
		return -EINVAL;
	if (new_size == ni->data_size && !publish_pending)
		return 0;
	err = ntfs_attr_size_bounds_check(ni->vol, ni->type, new_size);
	if (err)
		return err == -ENOENT ? -EIO : err;
	has_compressed_size = ntfs_attr_has_compressed_size(ni);
	if (ni->allocated_size < 0 || ni->data_size < 0 ||
	    ni->initialized_size < 0 || ni->zeroed_size < 0 ||
	    ni->initialized_size > ni->data_size ||
	    !IS_ALIGNED(ni->allocated_size, ni->vol->cluster_size) ||
	    (has_compressed_size && (ni->itype.compressed.size < 0 ||
	     !IS_ALIGNED(ni->itype.compressed.size,
			ni->vol->cluster_size))))
		return -EIO;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out;
	}
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || !attr->non_resident ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    !ntfs_attr_record_flags_match(ni, attr)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off = le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    !IS_ALIGNED(mapping_off, 8) || mapping_off > attr_len ||
	    (has_compressed_size && mapping_off < offsetof(struct attr_record,
			data.non_resident.compressed_size) + sizeof(__le64)) ||
	    record_pos > used || attr_len > used - record_pos ||
	    le64_to_cpu(attr->data.non_resident.allocated_size) !=
			ni->allocated_size ||
	    le64_to_cpu(attr->data.non_resident.data_size) !=
			ntfs_inode_recorded_data_size(ni) ||
	    le64_to_cpu(attr->data.non_resident.initialized_size) !=
			ntfs_inode_recorded_initialized_size(ni) ||
	    (has_compressed_size &&
	     le64_to_cpu(attr->data.non_resident.compressed_size) !=
			ni->itype.compressed.size)) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	old_sizes.alloc_size = attr->data.non_resident.allocated_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	new_sizes.alloc_size = old_sizes.alloc_size;
	new_sizes.valid_size = old_sizes.valid_size;
	new_sizes.data_size = cpu_to_le64(NInoPendingEmptyEof(ni) &&
			!publish_pending ? 0 : new_size);
	if (publish_pending)
		new_sizes.valid_size = cpu_to_le64(ni->initialized_size);
	else if (initialize)
		new_sizes.valid_size = new_sizes.data_size;
	if (has_compressed_size) {
		old_sizes.total_size = attr->data.non_resident.compressed_size;
		new_sizes.total_size = old_sizes.total_size;
	}
	if (coalesce_log) {
		err = ntfs_log_mft_attribute_sizes_coalesce(coalesce_log,
				ctx->ntfs_ino->mft_no, record_off, &old_sizes,
				&new_sizes, has_compressed_size,
				le64_to_cpu(mrec->lsn), &operation_lsn);
	} else {
		err = initialize ? ntfs_attr_append_register_home_undo(handle, ni,
				ctx, record_off) : -EOPNOTSUPP;
		if (err == -EOPNOTSUPP) {
			err = ntfs_attr_size_register_home_undo(handle, ni);
			if (err)
				goto out;
			err = ntfs_attr_mft_register_home_undo(handle,
					ctx->ntfs_ino, mrec);
		}
		if (err)
			goto out;
		err = ntfs_log_mft_attribute_sizes_update(handle,
				ctx->ntfs_ino->mft_no, record_off, &old_sizes,
				&new_sizes, has_compressed_size, &operation_lsn);
	}
	if (err)
		goto out;
	attr->data.non_resident.data_size = new_sizes.data_size;
	ni->data_size = new_size;
	if (publish_pending) {
		attr->data.non_resident.initialized_size = new_sizes.valid_size;
		NInoClearPendingEmptyEof(ni);
	} else if (initialize) {
		attr->data.non_resident.initialized_size = new_sizes.valid_size;
		ni->initialized_size = new_size;
		if ((ordered || delalloc) && ni->zeroed_size < new_size)
			ni->zeroed_size = new_size;
	}
	if (!publish_pending)
		i_size_write(VFS_I(ni), new_size);
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
	err = 0;
out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

int ntfs_attr_logical_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size)
{
	return __ntfs_attr_logical_grow_transacted(handle, NULL, ni, new_size,
			false, false, false, false);
}

int ntfs_attr_publish_pending_empty_eof(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	return __ntfs_attr_logical_grow_transacted(handle, NULL, ni,
			ni->data_size, false, false, false, true);
}

int ntfs_attr_append_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size, bool ordered)
{
	return __ntfs_attr_logical_grow_transacted(handle, NULL, ni, new_size,
			true, ordered, false, false);
}

int ntfs_attr_delalloc_grow_coalesced(struct ntfs_log *log,
		struct ntfs_inode *ni, s64 new_size)
{
	return __ntfs_attr_logical_grow_transacted(NULL, log, ni, new_size,
			true, false, true, false);
}

static bool ntfs_attr_has_single_mapping_extent(struct ntfs_inode *ni,
		struct ntfs_attr_search_ctx *ctx)
{
	struct attr_list_entry *next;
	const u8 *end;

	if (!NInoAttrList(ni))
		return true;
	if (!ni->attr_list || !ctx->al_entry)
		return false;
	end = ni->attr_list + ni->attr_list_size;
	if ((u8 *)ctx->al_entry < ni->attr_list ||
	    (u8 *)ctx->al_entry >= end ||
	    !ntfs_attr_list_entry_is_valid(ctx->al_entry, end) ||
	    ctx->al_entry->type != AT_DATA || ctx->al_entry->name_length)
		return false;
	next = (void *)((u8 *)ctx->al_entry +
			le16_to_cpu(ctx->al_entry->length));
	if ((u8 *)next == end)
		return true;
	return (u8 *)next < end && ntfs_attr_list_entry_is_valid(next, end) &&
		(next->type != AT_DATA || next->name_length);
}

/*
 * Extend only the real EOF allocation, reusing an unflushed mapping/size pair.
 * The caller pins journal admission and holds the base MFT-record mutex.
 */
int ntfs_attr_delalloc_mapping_grow_coalesced(struct ntfs_log *log,
		struct ntfs_inode *ni, s64 new_size)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes;
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct runlist_element *new_rl = NULL;
	struct runlist_element *old_rl;
	struct runlist_element *stop_rl;
	struct attr_record *attr;
	struct mft_record *mrec;
	struct inode *vi = VFS_I(ni);
	struct ntfs_volume *vol = ni->vol;
	ptrdiff_t record_pos;
	size_t old_count;
	size_t new_count;
	u64 old_clusters;
	u64 target_clusters;
	u64 operation_lsn;
	s64 physical_size;
	s64 stop_vcn;
	u8 *new_pairs = NULL;
	u32 attr_len;
	u32 allocated;
	u32 used;
	u16 mapping_off;
	u16 pairs_len;
	int mapping_size;
	int err = -EAGAIN;

	if (!log || !NInoGapAppend(ni) || !NInoNonResident(ni) ||
	    !NInoSparse(ni) || !NInoFullyMapped(ni) || NInoAttr(ni) ||
	    NInoCompressed(ni) || NInoEncrypted(ni) ||
	    ni->type != AT_DATA || ni->name != AT_UNNAMED ||
	    new_size <= ni->allocated_size || ni->allocated_size < 0 ||
	    ni->data_size < 0 || ni->initialized_size != ni->data_size ||
	    ni->zeroed_size < 0 || i_size_read(vi) != ni->data_size ||
	    !IS_ALIGNED(ni->allocated_size, vol->cluster_size) ||
	    ni->itype.compressed.size < 0 ||
	    !IS_ALIGNED(ni->itype.compressed.size, vol->cluster_size))
		return -EAGAIN;
	err = ntfs_attr_size_bounds_check(vol, ni->type, new_size);
	if (err)
		return err == -ENOENT ? -EIO : err;
	target_clusters = DIV_ROUND_UP_ULL((u64)new_size, vol->cluster_size);
	if (target_clusters > ((u64)S64_MAX >> vol->cluster_size_bits))
		return -EFBIG;
	old_clusters = ni->allocated_size >> vol->cluster_size_bits;
	if (target_clusters <= old_clusters)
		return -EAGAIN;

	err = -EAGAIN;
	down_write(&ni->runlist.lock);
	old_rl = ni->runlist.rl;
	old_count = ni->runlist.count;
	if (!old_rl || old_count < 2 ||
	    old_rl[old_count - 1].length ||
	    old_rl[old_count - 1].lcn != LCN_ENOENT ||
	    old_rl[old_count - 1].vcn != old_clusters ||
	    old_rl[old_count - 2].vcn < 0 ||
	    old_rl[old_count - 2].vcn >= old_clusters ||
	    old_rl[old_count - 2].length !=
			old_clusters - old_rl[old_count - 2].vcn)
		goto out;
	physical_size = ntfs_rl_get_compressed_size(vol, old_rl);
	if (physical_size < 0 || physical_size != ni->itype.compressed.size)
		goto out;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx || ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx))
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || !attr->non_resident ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    le64_to_cpu(attr->data.non_resident.highest_vcn) != old_clusters - 1 ||
	    !(attr->flags & ATTR_IS_SPARSE) ||
	    !ntfs_attr_has_single_mapping_extent(ni, ctx) ||
	    !ntfs_attr_record_flags_match(ni, attr))
		goto out;
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off = le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	/* Extent mapping updates otherwise consume the record's free space. */
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(attr_len, 8) ||
	    !IS_ALIGNED(mapping_off, 8) || attr_len > U16_MAX ||
	    mapping_off < offsetof(struct attr_record,
			data.non_resident.compressed_size) + sizeof(__le64) ||
	    mapping_off >= attr_len || used > allocated ||
	    (NInoAttrList(ni) && ctx->ntfs_ino != ni && used != allocated) ||
	    record_pos > used ||
	    attr_len > used - record_pos ||
	    le64_to_cpu(attr->data.non_resident.allocated_size) !=
			ni->allocated_size ||
	    le64_to_cpu(attr->data.non_resident.data_size) !=
			ntfs_inode_recorded_data_size(ni) ||
	    le64_to_cpu(attr->data.non_resident.initialized_size) !=
			ntfs_inode_recorded_initialized_size(ni) ||
	    le64_to_cpu(attr->data.non_resident.compressed_size) != physical_size)
		goto out;
	pairs_len = attr_len - mapping_off;
	if (check_add_overflow(old_count, (size_t)1, &new_count))
		goto out;
	new_rl = kvmalloc_array(new_count, sizeof(*new_rl), GFP_NOFS);
	if (!new_rl)
		goto out;
	memcpy(new_rl, old_rl, old_count * sizeof(*new_rl));
	if (new_rl[old_count - 2].lcn == LCN_HOLE) {
		new_rl[old_count - 2].length += target_clusters - old_clusters;
		new_rl[old_count - 1].vcn = target_clusters;
		new_count = old_count;
	} else {
		new_rl[old_count - 1].vcn = old_clusters;
		new_rl[old_count - 1].lcn = LCN_HOLE;
		new_rl[old_count - 1].length = target_clusters - old_clusters;
		new_rl[old_count].vcn = target_clusters;
		new_rl[old_count].lcn = LCN_ENOENT;
		new_rl[old_count].length = 0;
	}
	mapping_size = ntfs_get_size_for_mapping_pairs(vol, new_rl, 0, -1, -1);
	if (mapping_size <= 0 || mapping_size > pairs_len ||
	    (!NInoAttrList(ni) &&
	     ALIGN(mapping_off + mapping_size, 8) != attr_len))
		goto out;
	new_pairs = kzalloc(pairs_len, GFP_NOFS);
	if (!new_pairs)
		goto out;
	stop_rl = NULL;
	stop_vcn = 0;
	if (ntfs_mapping_pairs_build(vol, new_pairs, mapping_size, new_rl, 0,
			-1, &stop_vcn, &stop_rl, NULL) ||
	    !stop_rl || stop_rl->length || stop_vcn != target_clusters)
		goto out;

	old_sizes.alloc_size = attr->data.non_resident.allocated_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.total_size = attr->data.non_resident.compressed_size;
	new_sizes = old_sizes;
	new_sizes.alloc_size = cpu_to_le64(ntfs_cluster_to_bytes(vol,
			target_clusters));
	new_sizes.data_size = new_sizes.valid_size =
			cpu_to_le64(NInoPendingEmptyEof(ni) ? 0 : new_size);
	err = ntfs_log_mft_mapping_sizes_coalesce(log, ctx->ntfs_ino->mft_no,
			record_pos, mapping_off, (u8 *)attr + mapping_off,
			new_pairs, pairs_len, &old_sizes, &new_sizes,
			le64_to_cpu(mrec->lsn), &operation_lsn);
	if (err)
		goto out;

	memcpy((u8 *)attr + mapping_off, new_pairs, pairs_len);
	attr->data.non_resident.highest_vcn = cpu_to_le64(target_clusters - 1);
	attr->data.non_resident.allocated_size = new_sizes.alloc_size;
	attr->data.non_resident.data_size = new_sizes.data_size;
	attr->data.non_resident.initialized_size = new_sizes.valid_size;
	ni->runlist.rl = new_rl;
	ni->runlist.count = new_count;
	ni->runlist.rl_hint = -1;
	new_rl = NULL;
	kvfree(old_rl);
	ni->allocated_size = le64_to_cpu(new_sizes.alloc_size);
	ni->data_size = ni->initialized_size = new_size;
	if (ni->zeroed_size < new_size)
		ni->zeroed_size = new_size;
	i_size_write(vi, new_size);
	vi->i_blocks = physical_size >> 9;
	NInoSetFileNameDirty(ni);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
out:
	kfree(new_pairs);
	kvfree(new_rl);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	up_write(&ni->runlist.lock);
	return err;
}

int ntfs_attr_initialized_grow_log_credits(struct ntfs_volume *vol,
		bool has_compressed_size)
{
	return ntfs_log_mft_attribute_sizes_credits(vol,
			has_compressed_size);
}

int ntfs_attr_initialized_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	ptrdiff_t record_pos;
	u64 operation_lsn;
	u32 attr_len;
	u32 used;
	u16 record_off;
	bool has_compressed_size;
	int err;

	if (!handle || !ni || !NInoNonResident(ni) || new_size < 0 ||
	    new_size > ni->data_size)
		return -EINVAL;
	if (new_size == ni->initialized_size)
		return 0;
	if (NInoEncrypted(ni) || (NInoCompressed(ni) && NInoSparse(ni)))
		return -EOPNOTSUPP;
	has_compressed_size = ntfs_attr_has_compressed_size(ni);
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || !attr->non_resident ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    !ntfs_attr_record_flags_match(ni, attr)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	if (record_pos < 0 || record_pos > U16_MAX || attr_len > U16_MAX ||
	    record_pos > used || attr_len > used - record_pos ||
	    le64_to_cpu(attr->data.non_resident.allocated_size) !=
			ni->allocated_size ||
	    le64_to_cpu(attr->data.non_resident.data_size) !=
			ntfs_inode_recorded_data_size(ni) ||
	    le64_to_cpu(attr->data.non_resident.initialized_size) !=
			ntfs_inode_recorded_initialized_size(ni) ||
	    (has_compressed_size &&
	     le64_to_cpu(attr->data.non_resident.compressed_size) !=
			ni->itype.compressed.size)) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	err = ntfs_attr_size_register_home_undo(handle, ni);
	if (err)
		goto out;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out;
	old_sizes.alloc_size = attr->data.non_resident.allocated_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	new_sizes = old_sizes;
	new_sizes.valid_size = cpu_to_le64(NInoPendingEmptyEof(ni) ? 0 : new_size);
	if (has_compressed_size) {
		old_sizes.total_size = attr->data.non_resident.compressed_size;
		new_sizes.total_size = old_sizes.total_size;
	}
	err = ntfs_log_mft_attribute_sizes_update(handle,
			ctx->ntfs_ino->mft_no, record_off, &old_sizes, &new_sizes,
			has_compressed_size, &operation_lsn);
	if (err)
		goto out;
	attr->data.non_resident.initialized_size = new_sizes.valid_size;
	if (new_size < ni->initialized_size || new_size > ni->zeroed_size)
		ni->zeroed_size = new_size;
	ni->initialized_size = new_size;
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

int ntfs_resident_attr_resize_log_credits(struct ntfs_volume *vol,
		u16 old_size, u16 new_size)
{
	if (!vol)
		return -EINVAL;
	return ntfs_log_mft_attribute_credits(vol, old_size, new_size);
}

int ntfs_resident_attr_resize_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, u32 new_size)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	u8 *new_value = NULL;
	u8 *old_value = NULL;
	u64 operation_lsn;
	u32 allocated;
	u32 attr_len;
	u32 new_attr_len;
	u32 old_size;
	u32 used;
	u16 record_off;
	u16 value_off;
	ptrdiff_t record_pos;
	int err;

	if (!handle || !ni || NInoNonResident(ni) || new_size > U16_MAX)
		return -EINVAL;
	err = ntfs_attr_size_bounds_check(ni->vol, ni->type, new_size);
	if (err)
		return err == -ENOENT ? -EIO : err;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out;
	}
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || attr->non_resident) {
		err = -EOPNOTSUPP;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	old_size = le32_to_cpu(attr->data.resident.value_length);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(attr_len, 8) ||
	    value_off > attr_len || old_size > attr_len - value_off ||
	    old_size != ni->data_size || ni->allocated_size != ALIGN(old_size, 8) ||
	    ni->initialized_size != old_size ||
	    ni->zeroed_size != old_size || used > allocated ||
	    ((NInoCompressed(ni) || NInoSparse(ni)) &&
	     ni->itype.compressed.size != ni->allocated_size) ||
	    record_pos > used || attr_len > used - record_pos ||
	    check_add_overflow((u32)value_off, new_size, &new_attr_len)) {
		err = -EIO;
		goto out;
	}
	new_attr_len = ALIGN(new_attr_len, 8);
	if (new_attr_len > U16_MAX ||
	    new_attr_len > attr_len + allocated - used) {
		err = -ENOSPC;
		goto out;
	}
	if (new_size == old_size) {
		err = 0;
		goto out;
	}
	if (old_size) {
		old_value = kmemdup((u8 *)attr + value_off, old_size, GFP_NOFS);
		if (!old_value) {
			err = -ENOMEM;
			goto out;
		}
	}
	if (new_size) {
		new_value = kzalloc(new_size, GFP_NOFS);
		if (!new_value) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(new_value, (u8 *)attr + value_off,
				min(old_size, new_size));
	}
	record_off = record_pos;
	err = ntfs_attr_size_register_home_undo(handle, ni);
	if (err)
		goto out;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out;
	err = ntfs_log_mft_resident_update(handle, ctx->ntfs_ino->mft_no,
			record_off, value_off, old_value, old_size, new_value,
			new_size, &operation_lsn);
	if (err)
		goto out;
	err = ntfs_resident_attr_value_resize(mrec, attr, new_size);
	if (err)
		goto out;
	ni->allocated_size = ALIGN(new_size, 8);
	ni->data_size = new_size;
	ni->initialized_size = new_size;
	ni->zeroed_size = new_size;
	i_size_write(VFS_I(ni), new_size);
	if (NInoCompressed(ni) || NInoSparse(ni))
		ni->itype.compressed.size = ni->allocated_size;
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
	err = 0;
out:
	kfree(new_value);
	kfree(old_value);
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

int ntfs_attr_sparse_grow_log_credits(struct ntfs_volume *vol)
{
	if (!vol)
		return -EINVAL;
	return ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size, 1, 0);
}

static int __ntfs_attr_sparse_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size, bool publish_eof,
		bool initialize)
{
	struct runlist_element *new_rl;
	struct runlist_element *tail;
	struct ntfs_inode *base_ni;
	size_t new_rl_count;
	u64 old_clusters;
	u64 target_clusters;
	int err;

	if (!handle || !ni || new_size < 0 || !NInoNonResident(ni) ||
	    ni->type != AT_DATA)
		return -EINVAL;
	if (NInoEncrypted(ni) || NInoCompressed(ni))
		return -EOPNOTSUPP;
	if (initialize && (!publish_eof || !NInoGapAppend(ni) ||
	    ni->initialized_size != ni->data_size))
		return -EINVAL;
	if (new_size < ni->data_size)
		return -EINVAL;
	if (new_size == ni->data_size)
		return 0;
	err = ntfs_attr_size_bounds_check(ni->vol, ni->type, new_size);
	if (err)
		return err == -ENOENT ? -EIO : err;
	if (ni->allocated_size < 0 || ni->data_size < 0 ||
	    ni->initialized_size < 0 || ni->zeroed_size < 0 ||
	    ni->initialized_size > ni->data_size ||
	    ni->itype.compressed.size < 0 ||
	    !IS_ALIGNED(ni->allocated_size, ni->vol->cluster_size) ||
	    !IS_ALIGNED(ni->itype.compressed.size, ni->vol->cluster_size))
		return -EIO;
	target_clusters = DIV_ROUND_UP_ULL((u64)new_size,
			ni->vol->cluster_size);
	if (target_clusters > ((u64)S64_MAX >>
			ni->vol->cluster_size_bits))
		return -EFBIG;
	old_clusters = ni->allocated_size >> ni->vol->cluster_size_bits;
	if (target_clusters <= old_clusters)
		return publish_eof ?
			__ntfs_attr_logical_grow_transacted(handle, NULL, ni, new_size,
					initialize, false, initialize, false) : 0;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	tail = kmalloc_array(2, sizeof(*tail), GFP_NOFS);
	if (!tail)
		return -ENOMEM;
	tail[0].vcn = old_clusters;
	tail[0].lcn = LCN_HOLE;
	tail[0].length = target_clusters - old_clusters;
	tail[1].vcn = target_clusters;
	tail[1].lcn = LCN_ENOENT;
	tail[1].length = 0;

	down_write(&ni->runlist.lock);
	if (!ni->runlist.rl || !ni->runlist.count ||
	    ni->runlist.rl[ni->runlist.count - 1].length ||
	    ni->runlist.rl[ni->runlist.count - 1].vcn != old_clusters ||
	    ni->runlist.rl[ni->runlist.count - 1].lcn != LCN_ENOENT) {
		err = -EIO;
		goto out_unlock;
	}
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		goto out_unlock;
	new_rl = ntfs_runlists_merge(&ni->runlist, tail, 0, &new_rl_count);
	if (IS_ERR(new_rl)) {
		err = PTR_ERR(new_rl);
		goto out_unlock;
	}
	tail = NULL;
	ni->runlist.rl = new_rl;
	ni->runlist.count = new_rl_count;
	ni->runlist.rl_hint = -1;
	/* An empty buffered write must not leave a durable hole-only EOF. */
	if (publish_eof && !ni->data_size && !ni->allocated_size &&
	    NInoEmptyBufferedWrite(ni) && !NInoAttr(ni) &&
	    ni->name == AT_UNNAMED)
		NInoSetPendingEmptyEof(ni);
	ni->allocated_size = ntfs_cluster_to_bytes(ni->vol, target_clusters);
	if (publish_eof) {
		ni->data_size = new_size;
		if (initialize) {
			ni->initialized_size = new_size;
			if (ni->zeroed_size < new_size)
				ni->zeroed_size = new_size;
		}
		i_size_write(VFS_I(ni), new_size);
	}
	VFS_I(ni)->i_blocks = ni->itype.compressed.size >> 9;
	ntfs_attr_accounting_inode(ni)->i_blocks = VFS_I(ni)->i_blocks;
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
out_unlock:
	up_write(&ni->runlist.lock);
	kvfree(tail);
	return err;
}

int ntfs_attr_sparse_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size)
{
	return __ntfs_attr_sparse_grow_transacted(handle, ni, new_size, true,
			false);
}

int ntfs_attr_delalloc_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size)
{
	return __ntfs_attr_sparse_grow_transacted(handle, ni, new_size, true,
			true);
}

int ntfs_attr_compressed_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size)
{
	struct runlist_element *new_rl;
	struct runlist_element *tail = NULL;
	struct ntfs_inode *base_ni;
	size_t new_rl_count;
	u64 old_clusters;
	u64 target_clusters;
	u64 allocation_size;
	int err;

	if (!handle || !ni || new_size < 0 || !NInoNonResident(ni) ||
	    !NInoCompressed(ni) || NInoEncrypted(ni) || NInoSparse(ni))
		return -EINVAL;
	if (new_size < ni->data_size)
		return -EINVAL;
	if (new_size == ni->data_size)
		return 0;
	if (!ni->itype.compressed.block_size ||
	    !is_power_of_2(ni->itype.compressed.block_size))
		return -EIO;
	if (check_add_overflow((u64)new_size,
			(u64)ni->itype.compressed.block_size - 1,
			&allocation_size))
		return -EFBIG;
	allocation_size &= ~((u64)ni->itype.compressed.block_size - 1);
	if (allocation_size > S64_MAX ||
	    !IS_ALIGNED(ni->allocated_size, ni->vol->cluster_size))
		return -EFBIG;
	target_clusters = allocation_size >> ni->vol->cluster_size_bits;
	old_clusters = ni->allocated_size >> ni->vol->cluster_size_bits;
	if (target_clusters <= old_clusters)
		return ntfs_attr_logical_grow_transacted(handle, ni, new_size);
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni || target_clusters > S64_MAX)
		return -EFBIG;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	tail = kmalloc_array(2, sizeof(*tail), GFP_NOFS);
	if (!tail)
		return -ENOMEM;
	tail[0].vcn = old_clusters;
	tail[0].lcn = LCN_HOLE;
	tail[0].length = target_clusters - old_clusters;
	tail[1].vcn = target_clusters;
	tail[1].lcn = LCN_ENOENT;
	tail[1].length = 0;
	down_write(&ni->runlist.lock);
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		goto out;
	new_rl = ntfs_runlists_merge(&ni->runlist, tail, 0,
			&new_rl_count);
	if (IS_ERR(new_rl)) {
		err = PTR_ERR(new_rl);
		goto out;
	}
	tail = NULL;
	ni->runlist.rl = new_rl;
	ni->runlist.count = new_rl_count;
	ni->runlist.rl_hint = -1;
	ni->allocated_size = allocation_size;
	ni->data_size = new_size;
	i_size_write(VFS_I(ni), new_size);
	VFS_I(ni)->i_blocks = ni->itype.compressed.size >> 9;
	ntfs_attr_accounting_inode(ni)->i_blocks = VFS_I(ni)->i_blocks;
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
out:
	up_write(&ni->runlist.lock);
	kvfree(tail);
	return err;
}

int ntfs_attr_physical_grow_log_credits(struct ntfs_volume *vol,
		u64 clusters)
{
	int allocation_credits;
	int mapping_credits;
	int credits;

	if (!vol || !clusters || clusters > S64_MAX)
		return -EINVAL;
	allocation_credits = ntfs_cluster_alloc_log_credits(clusters);
	if (allocation_credits < 0)
		return allocation_credits;
	mapping_credits = ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size, clusters, 0);
	if (mapping_credits < 0)
		return mapping_credits;
	if (check_add_overflow(allocation_credits, mapping_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

static int __ntfs_attr_physical_grow_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		s64 new_size, u64 max_clusters, bool publish_eof, bool zero_fresh)
{
	struct runlist_element *allocated_rl = NULL;
	struct runlist_element *new_rl;
	struct ntfs_inode *base_ni;
	size_t new_rl_count;
	u64 grow_clusters;
	u64 old_clusters;
	u64 target_clusters;
	bool initialize_tail;
	int err;

	if (!handle || !ni || new_size < 0 || !max_clusters ||
	    max_clusters > S64_MAX || !NInoNonResident(ni))
		return -EINVAL;
	if (NInoEncrypted(ni) || NInoCompressed(ni) || NInoSparse(ni))
		return -EOPNOTSUPP;
	if (new_size <= ni->data_size)
		return new_size == ni->data_size ? 0 : -EINVAL;
	err = ntfs_attr_size_bounds_check(ni->vol, ni->type, new_size);
	if (err)
		return err == -ENOENT ? -EIO : err;
	if (ni->allocated_size < 0 || ni->data_size < 0 ||
	    ni->initialized_size < 0 || ni->zeroed_size < 0 ||
	    ni->initialized_size > ni->data_size ||
	    ni->data_size > ni->allocated_size ||
	    !IS_ALIGNED(ni->allocated_size, ni->vol->cluster_size))
		return -EIO;
	target_clusters = DIV_ROUND_UP_ULL((u64)new_size,
			ni->vol->cluster_size);
	if (target_clusters > ((u64)S64_MAX >>
			ni->vol->cluster_size_bits))
		return -EFBIG;
	old_clusters = ni->allocated_size >> ni->vol->cluster_size_bits;
	/*
	 * Append preallocation may extend a partially used last cluster only
	 * when the rest of the existing allocation is already prezeroed.
	 */
	initialize_tail = zero_fresh &&
		(ni->initialized_size == ni->allocated_size ||
		 (!publish_eof && ni->initialized_size == ni->data_size &&
		  ni->zeroed_size == ni->allocated_size)) &&
		ni->type == AT_DATA && ni->name == AT_UNNAMED &&
		S_ISREG(VFS_I(ni)->i_mode);
	if (zero_fresh && !publish_eof && !initialize_tail)
		return -EOPNOTSUPP;
	if (target_clusters <= old_clusters)
		return publish_eof ?
			ntfs_attr_logical_grow_transacted(handle, ni, new_size) : 0;
	grow_clusters = target_clusters - old_clusters;
	if (grow_clusters > max_clusters)
		return -E2BIG;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	down_write(&ni->runlist.lock);
	if (!ni->runlist.rl || !ni->runlist.count ||
	    ni->runlist.rl[ni->runlist.count - 1].length ||
	    ni->runlist.rl[ni->runlist.count - 1].vcn != old_clusters ||
	    ni->runlist.rl[ni->runlist.count - 1].lcn != LCN_ENOENT) {
		err = -EIO;
		goto out;
	}
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		goto out;
	allocated_rl = ntfs_cluster_alloc_transacted(handle, ni->vol,
			old_clusters, grow_clusters, -1, DATA_ZONE, true, false,
			false);
	if (IS_ERR(allocated_rl)) {
		err = PTR_ERR(allocated_rl);
		allocated_rl = NULL;
		goto out;
	}
	if (initialize_tail) {
		struct runlist_element *rl;

		/* Never zero an existing/partially initialized cluster here. */
		for (rl = allocated_rl; rl->length; rl++) {
			err = ntfs_dio_zero_range(VFS_I(ni),
					ntfs_cluster_to_bytes(ni->vol, rl->lcn),
					ntfs_cluster_to_bytes(ni->vol, rl->length));
			if (err)
				goto out;
		}
		err = ntfs_log_ordered_data(handle);
		if (err)
			goto out;
	}
	new_rl = ntfs_runlists_merge(&ni->runlist, allocated_rl, 0,
			&new_rl_count);
	if (IS_ERR(new_rl)) {
		err = PTR_ERR(new_rl);
		goto out;
	}
	allocated_rl = NULL;
	ni->runlist.rl = new_rl;
	ni->runlist.count = new_rl_count;
	ni->runlist.rl_hint = -1;
	ni->allocated_size = ntfs_cluster_to_bytes(ni->vol, target_clusters);
	if (initialize_tail)
		/* Every byte of this fresh allocation has completed direct zero I/O. */
		ni->zeroed_size = ni->allocated_size;
	if (publish_eof) {
		ni->data_size = new_size;
		if (initialize_tail)
			ni->initialized_size = new_size;
		i_size_write(VFS_I(ni), new_size);
	}
	VFS_I(ni)->i_blocks = ni->allocated_size >> 9;
	ntfs_attr_accounting_inode(ni)->i_blocks = VFS_I(ni)->i_blocks;
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
out:
	up_write(&ni->runlist.lock);
	kvfree(allocated_rl);
	return err;
}

int ntfs_attr_physical_grow_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size, u64 max_clusters)
{
	return __ntfs_attr_physical_grow_transacted(handle, ni, new_size,
			max_clusters, true, true);
}

int ntfs_attr_physical_prealloc_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 allocation_size, u64 max_clusters)
{
	return __ntfs_attr_physical_grow_transacted(handle, ni,
			allocation_size, max_clusters, false, false);
}

/* Allocate and initialize a bounded append tail without publishing any EOF. */
int ntfs_attr_append_prealloc_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 allocation_size, u64 max_clusters)
{
	return __ntfs_attr_physical_grow_transacted(handle, ni,
			allocation_size, max_clusters, false, true);
}

int ntfs_attr_empty_make_nonresident_log_credits(struct ntfs_volume *vol,
		u8 name_len)
{
	u32 name_bytes;
	u32 new_len;
	u32 old_len;
	int create_credits;
	int delete_credits;
	int credits;

	if (!vol)
		return -EINVAL;
	name_bytes = ALIGN(name_len * sizeof(__le16), 8);
	old_len = offsetof(struct attr_record, data.resident.reserved) +
			sizeof_field(struct attr_record, data.resident.reserved) +
			name_bytes;
	new_len = offsetof(struct attr_record,
			data.non_resident.compressed_size) + name_bytes + 8;
	if (old_len > U16_MAX || new_len > U16_MAX)
		return -E2BIG;
	delete_credits = ntfs_log_mft_attribute_credits(vol, old_len, 0);
	if (delete_credits < 0)
		return delete_credits;
	create_credits = ntfs_log_mft_attribute_credits(vol, 0, new_len);
	if (create_credits < 0)
		return create_credits;
	if (check_add_overflow(delete_credits, create_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_attr_empty_make_nonresident_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *ctx;
	struct runlist_element *new_rl = NULL;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct attr_record *new_attr = NULL;
	struct mft_record *mrec;
	u64 operation_lsn;
	u32 allocated;
	u32 attr_len;
	u32 new_len;
	u32 used;
	u16 instance;
	u16 record_off;
	ptrdiff_t record_pos;
	int err;

	if (!handle || !ni || NInoNonResident(ni) || ni->data_size ||
	    ni->allocated_size || ni->initialized_size || ni->zeroed_size ||
	    i_size_read(VFS_I(ni)) || ni->runlist.rl || ni->runlist.count)
		return -EINVAL;
	if (NInoEncrypted(ni) || NInoCompressed(ni) || NInoSparse(ni))
		return -EOPNOTSUPP;
	err = ntfs_attr_can_be_non_resident(ni->vol, ni->type);
	if (err)
		return err;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out;
	}
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || attr->non_resident || attr->flags ||
	    attr->name_length != ni->name_len ||
	    le32_to_cpu(attr->data.resident.value_length)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	new_len = offsetof(struct attr_record,
			data.non_resident.compressed_size) +
			ALIGN(ni->name_len * sizeof(__le16), 8) + 8;
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(attr_len, 8) ||
	    attr_len > U16_MAX || used > allocated || record_pos > used ||
	    attr_len > used - record_pos || new_len > U16_MAX) {
		err = -EIO;
		goto out;
	}
	if (new_len > attr_len + allocated - used) {
		err = -ENOSPC;
		goto out;
	}
	new_attr = kzalloc(new_len, GFP_NOFS);
	new_rl = kzalloc_obj(*new_rl, GFP_NOFS);
	if (!new_attr || !new_rl) {
		err = -ENOMEM;
		goto out;
	}
	instance = attr->instance;
	ntfs_init_non_resident_attr_record(new_attr, new_len, ni->type,
			ni->name, ni->name_len, 0, 8, 0, instance);
	record_off = record_pos;
	down_write(&ni->runlist.lock);
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		goto out_unlock;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out_unlock;
	err = ntfs_log_mft_attribute_delete(handle, ctx->ntfs_ino->mft_no,
			record_off, attr, attr_len, &operation_lsn);
	if (err)
		goto out_unlock;
	err = ntfs_log_mft_attribute_create(handle, ctx->ntfs_ino->mft_no,
			record_off, new_attr, new_len, &operation_lsn);
	if (err)
		goto out_unlock;
	err = ntfs_attr_record_resize(mrec, attr, new_len);
	if (err)
		goto out_unlock;
	memcpy(attr, new_attr, new_len);
	new_rl->vcn = 0;
	new_rl->lcn = LCN_ENOENT;
	new_rl->length = 0;
	ni->runlist.rl = new_rl;
	new_rl = NULL;
	ni->runlist.count = 1;
	ni->runlist.rl_hint = -1;
	NInoSetNonResident(ni);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
	err = 0;
out_unlock:
	up_write(&ni->runlist.lock);
out:
	ntfs_attr_put_search_ctx(ctx);
	kfree(new_rl);
	kfree(new_attr);
	return err;
}

static int ntfs_attr_write_allocated_value(struct ntfs_volume *vol,
		const struct runlist_element *rl, const u8 *value, u32 size)
{
	u32 written = 0;
	int err;
	int i;

	if (!vol || !rl || !value || !size)
		return -EINVAL;
	for (i = 0; rl[i].length && written < size; i++) {
		u64 run_bytes;
		u64 dev_off;
		u32 bytes;

		if (rl[i].lcn < 0 || rl[i].length < 0 ||
		    check_mul_overflow((u64)rl[i].length,
				(u64)vol->cluster_size, &run_bytes) ||
		    check_mul_overflow((u64)rl[i].lcn,
				(u64)vol->cluster_size, &dev_off))
			return -EIO;
		bytes = min_t(u64, size - written, run_bytes);
		err = ntfs_bdev_write(vol->sb, (u8 *)value + written,
				dev_off, bytes);
		if (err)
			return err;
		written += bytes;
	}
	if (written != size)
		return -EIO;
	return sync_blockdev(vol->sb->s_bdev);
}

int ntfs_attr_make_nonresident_log_credits(struct ntfs_volume *vol,
		u8 name_len, u32 data_size)
{
	u64 clusters;
	u64 mapping_bytes;
	u32 name_bytes;
	u32 new_len;
	u32 old_len;
	int allocation_credits;
	int create_credits;
	int delete_credits;
	int credits;

	if (!vol || !data_size)
		return -EINVAL;
	clusters = DIV_ROUND_UP_ULL(data_size, vol->cluster_size);
	if (!clusters || clusters > S64_MAX ||
	    check_mul_overflow(clusters, 1 + 2 * sizeof(s64),
			&mapping_bytes) ||
	    check_add_overflow(mapping_bytes, 1, &mapping_bytes))
		return -EOVERFLOW;
	name_bytes = ALIGN(name_len * sizeof(__le16), 8);
	old_len = offsetof(struct attr_record, data.resident.reserved) +
			sizeof_field(struct attr_record, data.resident.reserved) +
			name_bytes + ALIGN(data_size, 8);
	if (mapping_bytes > U16_MAX)
		return -E2BIG;
	new_len = offsetof(struct attr_record,
			data.non_resident.compressed_size) + name_bytes +
			ALIGN(mapping_bytes, 8);
	if (old_len > U16_MAX || new_len > U16_MAX)
		return -E2BIG;
	allocation_credits = ntfs_cluster_alloc_log_credits(clusters);
	if (allocation_credits < 0)
		return allocation_credits;
	delete_credits = ntfs_log_mft_attribute_credits(vol, old_len, 0);
	if (delete_credits < 0)
		return delete_credits;
	create_credits = ntfs_log_mft_attribute_credits(vol, 0, new_len);
	if (create_credits < 0)
		return create_credits;
	if (check_add_overflow(allocation_credits, delete_credits, &credits) ||
	    check_add_overflow(credits, create_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_attr_make_nonresident_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *ctx;
	struct runlist_element *allocated_rl = NULL;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct attr_record *new_attr = NULL;
	struct mft_record *mrec;
	u8 *value = NULL;
	u64 operation_lsn;
	u64 clusters;
	u32 allocated;
	u32 attr_len;
	u32 data_size;
	u32 value_size;
	u32 new_len;
	u32 used;
	u16 instance;
	u16 mapping_off;
	u16 record_off;
	u16 value_off;
	ptrdiff_t record_pos;
	int mapping_size;
	int run_count;
	int err;
	bool prezero_tail;

	if (!handle || !ni || NInoNonResident(ni) || ni->data_size <= 0 ||
	    ni->data_size > U32_MAX || ni->allocated_size <
			ALIGN(ni->data_size, 8) ||
	    ni->initialized_size != ni->data_size ||
	    ni->zeroed_size != ni->data_size || ni->runlist.rl ||
	    ni->runlist.count)
		return -EINVAL;
	if (NInoEncrypted(ni) || NInoCompressed(ni) || NInoSparse(ni))
		return -EOPNOTSUPP;
	err = ntfs_attr_can_be_non_resident(ni->vol, ni->type);
	if (err)
		return err;
	data_size = ni->data_size;
	clusters = DIV_ROUND_UP_ULL(data_size, ni->vol->cluster_size);
	prezero_tail = !NInoAttr(ni) && ni->type == AT_DATA &&
			ni->name == AT_UNNAMED && S_ISREG(VFS_I(ni)->i_mode);
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out;
	}
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || attr->non_resident || attr->flags ||
	    le32_to_cpu(attr->data.resident.value_length) != data_size) {
		err = -EOPNOTSUPP;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	value_off = le16_to_cpu(attr->data.resident.value_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	allocated = le32_to_cpu(mrec->bytes_allocated);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || !IS_ALIGNED(attr_len, 8) ||
	    attr_len > U16_MAX || used > allocated || record_pos > used ||
	    attr_len > used - record_pos || value_off > attr_len ||
	    data_size > attr_len - value_off ||
	    ni->allocated_size != attr_len - value_off) {
		err = -EIO;
		goto out;
	}
	value_size = data_size;
	if (prezero_tail) {
		u64 allocation_size = ntfs_cluster_to_bytes(ni->vol, clusters);

		if (allocation_size > U32_MAX) {
			err = -E2BIG;
			goto out;
		}
		value_size = allocation_size;
	}
	value = kvzalloc(value_size, GFP_NOFS);
	if (!value) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(value, (u8 *)attr + value_off, data_size);
	down_write(&ni->runlist.lock);
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		goto out_unlock;
	allocated_rl = ntfs_cluster_alloc_transacted(handle, ni->vol, 0,
			clusters, -1, DATA_ZONE, true, false, false);
	if (IS_ERR(allocated_rl)) {
		err = PTR_ERR(allocated_rl);
		allocated_rl = NULL;
		goto out_unlock;
	}
	mapping_size = ntfs_get_size_for_mapping_pairs(ni->vol, allocated_rl,
			0, -1, -1);
	if (mapping_size <= 0) {
		err = mapping_size ? mapping_size : -EIO;
		goto out_unlock;
	}
	mapping_off = ALIGN(offsetof(struct attr_record,
			data.non_resident.compressed_size) +
			ni->name_len * sizeof(__le16), 8);
	new_len = ALIGN(mapping_off + mapping_size, 8);
	if (new_len > U16_MAX || new_len > attr_len + allocated - used) {
		err = -ENOSPC;
		goto out_unlock;
	}
	new_attr = kzalloc(new_len, GFP_NOFS);
	if (!new_attr) {
		err = -ENOMEM;
		goto out_unlock;
	}
	instance = attr->instance;
	ntfs_init_non_resident_attr_record(new_attr, new_len, ni->type,
			ni->name, ni->name_len, 0, new_len - mapping_off, 0,
			instance);
	new_attr->data.non_resident.highest_vcn = cpu_to_le64(clusters - 1);
	new_attr->data.non_resident.allocated_size =
			cpu_to_le64(ntfs_cluster_to_bytes(ni->vol, clusters));
	new_attr->data.non_resident.data_size = cpu_to_le64(data_size);
	new_attr->data.non_resident.initialized_size = cpu_to_le64(data_size);
	err = ntfs_mapping_pairs_build(ni->vol,
			(u8 *)new_attr + mapping_off, new_len - mapping_off,
			allocated_rl, 0, -1, NULL, NULL, NULL);
	if (err)
		goto out_unlock;
	err = ntfs_attr_write_allocated_value(ni->vol, allocated_rl, value,
			value_size);
	if (err)
		goto out_unlock;
	err = ntfs_log_ordered_data(handle);
	if (err)
		goto out_unlock;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out_unlock;
	record_off = record_pos;
	err = ntfs_log_mft_attribute_delete(handle, ctx->ntfs_ino->mft_no,
			record_off, attr, attr_len, &operation_lsn);
	if (err)
		goto out_unlock;
	err = ntfs_log_mft_attribute_create(handle, ctx->ntfs_ino->mft_no,
			record_off, new_attr, new_len, &operation_lsn);
	if (err)
		goto out_unlock;
	err = ntfs_attr_record_resize(mrec, attr, new_len);
	if (err)
		goto out_unlock;
	memcpy(attr, new_attr, new_len);
	ni->runlist.rl = allocated_rl;
	allocated_rl = NULL;
	for (run_count = 1; ni->runlist.rl[run_count - 1].length;
	     run_count++)
		;
	ni->runlist.count = run_count;
	ni->runlist.rl_hint = -1;
	ni->allocated_size = ntfs_cluster_to_bytes(ni->vol, clusters);
	if (prezero_tail)
		ni->zeroed_size = ni->allocated_size;
	VFS_I(ni)->i_blocks = ni->allocated_size >> 9;
	NInoSetNonResident(ni);
	NInoSetFullyMapped(ni);
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED) {
		VFS_I(base_ni)->i_blocks = VFS_I(ni)->i_blocks;
		NInoSetFileNameDirty(ni);
	}
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
	err = 0;
out_unlock:
	up_write(&ni->runlist.lock);
out:
	ntfs_attr_put_search_ctx(ctx);
	kvfree(allocated_rl);
	kfree(new_attr);
	kvfree(value);
	return err;
}

/*
 * Publish a smaller logical size while retaining the current allocation and
 * mapping pairs.  Physical tail removal is deliberately a separate operation
 * so callers can establish ordered-data and page-cache boundaries first.
 */
int ntfs_attr_logical_shrink_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size)
{
	struct ntfs_new_attribute_sizes old_sizes = { };
	struct ntfs_new_attribute_sizes new_sizes = { };
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct attr_record *attr;
	struct mft_record *mrec;
	u64 operation_lsn;
	u32 attr_len;
	u32 used;
	u16 mapping_off;
	u16 record_off;
	ptrdiff_t record_pos;
	bool has_compressed_size;
	int err;

	if (!handle || !ni || new_size < 0 || !NInoNonResident(ni))
		return -EINVAL;
	if ((NInoEncrypted(ni) && !ntfs_attr_deleted_encrypted(ni)) ||
	    (NInoCompressed(ni) && NInoSparse(ni)))
		return -EOPNOTSUPP;
	has_compressed_size = NInoCompressed(ni) || NInoSparse(ni);
	if (new_size > ni->data_size)
		return -EINVAL;
	if (new_size == ni->data_size)
		return 0;
	err = ntfs_attr_size_bounds_check(ni->vol, ni->type, new_size);
	if (err)
		return err == -ENOENT ? -EIO : err;
	if (ni->allocated_size < 0 || ni->data_size < 0 ||
	    ni->initialized_size < 0 || ni->zeroed_size < 0 ||
	    ni->initialized_size > ni->data_size ||
	    (!NInoSparse(ni) && ni->data_size > ni->allocated_size) ||
	    (has_compressed_size && (ni->itype.compressed.size < 0 ||
	     !IS_ALIGNED(ni->itype.compressed.size,
			ni->vol->cluster_size))) ||
	    (NInoCompressed(ni) &&
	     ni->itype.compressed.block_clusters !=
			(1U << STANDARD_COMPRESSION_UNIT)) ||
	    !IS_ALIGNED(ni->allocated_size, ni->vol->cluster_size))
		return -EIO;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		goto out;
	}
	attr = ctx->attr;
	mrec = ctx->mrec;
	if (!attr || !mrec || !attr->non_resident ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    (!!(attr->flags & ATTR_IS_ENCRYPTED) != !!NInoEncrypted(ni)) ||
	    ((attr->flags & ATTR_COMPRESSION_MASK) !=
		    (NInoCompressed(ni) ? ATTR_IS_COMPRESSED : 0)) ||
	    (NInoCompressed(ni) && attr->data.non_resident.compression_unit !=
			STANDARD_COMPRESSION_UNIT) ||
	    (!!(attr->flags & ATTR_IS_SPARSE) != !!NInoSparse(ni))) {
		err = -EOPNOTSUPP;
		goto out;
	}
	record_pos = (u8 *)attr - (u8 *)mrec;
	attr_len = le32_to_cpu(attr->length);
	mapping_off = le16_to_cpu(attr->data.non_resident.mapping_pairs_offset);
	used = le32_to_cpu(mrec->bytes_in_use);
	if (record_pos < 0 || record_pos > U16_MAX ||
	    !IS_ALIGNED(record_pos, 8) || attr_len > U16_MAX ||
	    !IS_ALIGNED(mapping_off, 8) || mapping_off > attr_len ||
	    (has_compressed_size && mapping_off < offsetof(struct attr_record,
			data.non_resident.compressed_size) + sizeof(__le64)) ||
	    record_pos > used || attr_len > used - record_pos ||
	    le64_to_cpu(attr->data.non_resident.allocated_size) !=
			ni->allocated_size ||
	    le64_to_cpu(attr->data.non_resident.data_size) !=
			ntfs_inode_recorded_data_size(ni) ||
	    le64_to_cpu(attr->data.non_resident.initialized_size) !=
			ntfs_inode_recorded_initialized_size(ni) ||
	    (has_compressed_size &&
	     le64_to_cpu(attr->data.non_resident.compressed_size) !=
			ni->itype.compressed.size)) {
		err = -EIO;
		goto out;
	}
	record_off = record_pos;
	err = ntfs_attr_size_register_home_undo(handle, ni);
	if (err)
		goto out;
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino, mrec);
	if (err)
		goto out;
	old_sizes.alloc_size = attr->data.non_resident.allocated_size;
	old_sizes.valid_size = attr->data.non_resident.initialized_size;
	old_sizes.data_size = attr->data.non_resident.data_size;
	new_sizes.alloc_size = old_sizes.alloc_size;
	new_sizes.valid_size = cpu_to_le64(NInoPendingEmptyEof(ni) ? 0 :
			min(ni->initialized_size, new_size));
	new_sizes.data_size = cpu_to_le64(NInoPendingEmptyEof(ni) ? 0 : new_size);
	if (has_compressed_size) {
		old_sizes.total_size = attr->data.non_resident.compressed_size;
		new_sizes.total_size = old_sizes.total_size;
	}
	err = ntfs_log_mft_attribute_sizes_update(handle,
			ctx->ntfs_ino->mft_no, record_off, &old_sizes, &new_sizes,
			has_compressed_size, &operation_lsn);
	if (err)
		goto out;
	attr->data.non_resident.initialized_size = new_sizes.valid_size;
	attr->data.non_resident.data_size = new_sizes.data_size;
	ni->data_size = new_size;
	ni->initialized_size = min(ni->initialized_size, new_size);
	ni->zeroed_size = min(ni->zeroed_size, new_size);
	if (!new_size)
		NInoClearPendingEmptyEof(ni);
	i_size_write(VFS_I(ni), new_size);
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	mrec->lsn = cpu_to_le64(operation_lsn);
	mark_mft_record_dirty(ctx->ntfs_ino);
	err = 0;
out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

int ntfs_attr_shrink_log_credits_bound(struct ntfs_volume *vol,
		u64 max_free_clusters, bool has_compressed_size,
		u64 max_attr_extents)
{
	u32 max_list_bytes;
	int compressed_size_credits;
	int free_credits;
	int mapping_credits;
	int size_credits;
	int credits;

	if (!vol || max_free_clusters > S64_MAX)
		return -EINVAL;
	if (!max_free_clusters)
		return ntfs_attr_logical_shrink_log_credits(vol,
				has_compressed_size);
	/* extent_bound is floor(list_size / sizeof(entry)). Round up safely. */
	if (max_attr_extents >= (256 * 1024) / sizeof(struct attr_list_entry))
		max_list_bytes = 256 * 1024;
	else
		max_list_bytes = (max_attr_extents + 1) *
				sizeof(struct attr_list_entry);
	mapping_credits = __ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size, 0,
			min(max_free_clusters, max_attr_extents), max_list_bytes);
	if (mapping_credits < 0)
		return mapping_credits;
	if (has_compressed_size) {
		size_credits = ntfs_log_mft_attribute_sizes_credits(vol, false);
		if (size_credits < 0)
			return size_credits;
		compressed_size_credits =
				ntfs_log_mft_attribute_sizes_credits(vol, true);
		if (compressed_size_credits < 0)
			return compressed_size_credits;
		if (compressed_size_credits < size_credits)
			return -EIO;
		if (check_add_overflow(mapping_credits,
				compressed_size_credits - size_credits,
				&mapping_credits))
			return -EOVERFLOW;
	}
	free_credits = ntfs_cluster_free_log_credits(max_free_clusters);
	if (free_credits < 0)
		return free_credits;
	if (check_add_overflow(mapping_credits, free_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

int ntfs_attr_shrink_log_credits(struct ntfs_volume *vol,
		u64 max_free_clusters, bool has_compressed_size)
{
	return ntfs_attr_shrink_log_credits_bound(vol, max_free_clusters,
			has_compressed_size, U64_MAX);
}

/* Holes and delayed allocations consume no cluster-bitmap log credits. */
static int ntfs_attr_shrink_tail_vcn(struct ntfs_inode *ni, s64 start_vcn,
		s64 end_vcn, u64 max_allocated_clusters, u64 max_attr_extents,
		s64 *target_vcn)
{
	const struct runlist_element *rl = ni->runlist.rl;
	s64 expected = end_vcn;
	s64 from;
	s64 run_end;
	s64 length;
	size_t i;

	for (i = 0; i < ni->runlist.count && rl[i].length; i++)
		;
	if (i == ni->runlist.count || rl[i].vcn != end_vcn ||
	    rl[i].lcn != LCN_ENOENT)
		return -EIO;
	/*
	 * The mapping-pairs reservation covers at most max_allocated_clusters
	 * removed extents.  Holes can otherwise span more extents than that
	 * without consuming any of the physical-cluster budget.
	 */
	if (max_attr_extents > max_allocated_clusters &&
	    (u64)(end_vcn - start_vcn) > max_allocated_clusters)
		start_vcn = end_vcn - max_allocated_clusters;
	if (start_vcn == end_vcn) {
		*target_vcn = end_vcn;
		return 0;
	}
	while (i) {
		i--;
		if (rl[i].length < 0 || rl[i].vcn < 0 ||
		    check_add_overflow(rl[i].vcn, rl[i].length, &run_end) ||
		    run_end != expected)
			return -EIO;
		from = max(rl[i].vcn, start_vcn);
		length = run_end - from;
		if (length <= 0)
			return -EIO;
		if (rl[i].lcn >= 0) {
			if ((u64)length > max_allocated_clusters) {
				*target_vcn = run_end - max_allocated_clusters;
				return 0;
			}
			max_allocated_clusters -= length;
		} else if (rl[i].lcn != LCN_HOLE &&
			   rl[i].lcn != LCN_DELALLOC) {
			return -EOPNOTSUPP;
		}
		if (from == start_vcn) {
			*target_vcn = from;
			return 0;
		}
		expected = from;
	}
	return -EIO;
}

static int ntfs_attr_tail_runlist(struct ntfs_inode *ni, s64 start_vcn,
		s64 end_vcn, struct runlist_element **tail_out,
		u64 *allocated_clusters_out, u64 *delayed_clusters_out)
{
	struct runlist_element *rl;
	struct runlist_element *tail;
	u64 allocated_clusters = 0;
	u64 delayed_clusters = 0;
	s64 covered = 0;
	s64 expected;
	s64 from;
	s64 lcn;
	s64 length;
	s64 run_end;
	s64 run_off;
	size_t i;
	size_t nr = 0;
	bool terminated = false;

	if (!ni || !tail_out || !allocated_clusters_out ||
	    !delayed_clusters_out || start_vcn < 0 ||
	    end_vcn <= start_vcn ||
	    !ni->runlist.rl || !ni->runlist.count)
		return -EINVAL;
	tail = kvmalloc_array(ni->runlist.count, sizeof(*tail), GFP_NOFS);
	if (!tail)
		return -ENOMEM;
	rl = ni->runlist.rl;
	for (i = 0; i < ni->runlist.count; i++) {
		if (!rl[i].length) {
			terminated = true;
			break;
		}
		if (rl[i].length < 0 ||
		    check_add_overflow(rl[i].vcn, rl[i].length, &run_end)) {
			kvfree(tail);
			return -EIO;
		}
		if (run_end <= start_vcn)
			continue;
		if (rl[i].vcn >= end_vcn)
			break;
		from = max(rl[i].vcn, start_vcn);
		run_end = min(run_end, end_vcn);
		run_off = from - rl[i].vcn;
		length = run_end - from;
		if (check_add_overflow(start_vcn, covered, &expected) ||
		    from != expected || length <= 0 ||
		    check_add_overflow(covered, length, &covered)) {
			kvfree(tail);
			return -EIO;
		}
		if (rl[i].lcn == LCN_HOLE)
			continue;
		if (rl[i].lcn == LCN_DELALLOC) {
			delayed_clusters += length;
			continue;
		}
		if (rl[i].lcn < 0 ||
		    check_add_overflow(rl[i].lcn, run_off, &lcn) ||
		    check_add_overflow(allocated_clusters, (u64)length,
				&allocated_clusters)) {
			kvfree(tail);
			return rl[i].lcn < 0 ? -EOPNOTSUPP : -EIO;
		}
		tail[nr].vcn = from;
		tail[nr].lcn = lcn;
		tail[nr].length = length;
		nr++;
	}
	if (!terminated || covered != end_vcn - start_vcn ||
	    nr >= ni->runlist.count) {
		kvfree(tail);
		return -EIO;
	}
	tail[nr].vcn = end_vcn;
	tail[nr].lcn = LCN_ENOENT;
	tail[nr].length = 0;
	*tail_out = tail;
	*allocated_clusters_out = allocated_clusters;
	*delayed_clusters_out = delayed_clusters;
	return 0;
}

int ntfs_attr_shrink_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 new_size, u64 max_free_clusters)
{
	struct ntfs_attr_allocation_home_undo *undo;
	struct ntfs_inode *base_ni;
	struct runlist_element *tail = NULL;
	u64 allocated_tail_clusters;
	u64 delayed_tail_clusters;
	u64 old_clusters;
	u64 required_clusters;
	u64 target_clusters;
	u64 free_clusters;
	u64 compression_units;
	bool has_compressed_size;
	int err;

	if (!handle || !ni || new_size < 0 || !NInoNonResident(ni) ||
	    max_free_clusters > S64_MAX)
		return -EINVAL;
	if ((NInoEncrypted(ni) && !ntfs_attr_deleted_encrypted(ni)) ||
	    (NInoCompressed(ni) && NInoSparse(ni)))
		return -EOPNOTSUPP;
	has_compressed_size = ntfs_attr_has_compressed_size(ni);
	if (new_size > ni->data_size)
		return -EINVAL;
	if (new_size == ni->data_size && !max_free_clusters)
		return 0;
	if (ni->allocated_size < 0 ||
	    !IS_ALIGNED(ni->allocated_size, ni->vol->cluster_size) ||
	    (has_compressed_size && (ni->itype.compressed.size < 0 ||
	     !IS_ALIGNED(ni->itype.compressed.size,
			ni->vol->cluster_size))))
		return -EIO;
	old_clusters = ni->allocated_size >> ni->vol->cluster_size_bits;
	if (NInoCompressed(ni)) {
		if (ni->itype.compressed.block_clusters !=
				(1U << STANDARD_COMPRESSION_UNIT) ||
		    ni->itype.compressed.block_size !=
				(ni->vol->cluster_size <<
				 STANDARD_COMPRESSION_UNIT) ||
		    !IS_ALIGNED(ni->allocated_size,
				ni->itype.compressed.block_size))
			return -EIO;
		compression_units = DIV_ROUND_UP_ULL((u64)new_size,
				ni->itype.compressed.block_size);
		if (check_mul_overflow(compression_units,
				(u64)ni->itype.compressed.block_clusters,
				&required_clusters))
			return -EOVERFLOW;
	} else {
		required_clusters = DIV_ROUND_UP_ULL(new_size,
				ni->vol->cluster_size);
	}
	if (required_clusters > old_clusters)
		return -EIO;
	free_clusters = min(max_free_clusters,
			old_clusters - required_clusters);
	if (NInoCompressed(ni))
		free_clusters = round_down(free_clusters,
				(u64)ni->itype.compressed.block_clusters);
	if (!free_clusters)
		return ntfs_attr_logical_shrink_transacted(handle, ni, new_size);
	target_clusters = old_clusters - free_clusters;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	down_write(&ni->runlist.lock);
	if (!NInoCompressed(ni)) {
		s64 target_vcn;
		u64 max_attr_extents = 0;

		if (NInoAttrList(base_ni)) {
			if (base_ni->attr_list_size <
			    sizeof(struct attr_list_entry)) {
				err = -EIO;
				goto out_unlock;
			}
			max_attr_extents = base_ni->attr_list_size /
					sizeof(struct attr_list_entry);
		}

		err = ntfs_attr_shrink_tail_vcn(ni, required_clusters,
				old_clusters, max_free_clusters, max_attr_extents,
				&target_vcn);
		if (err)
			goto out_unlock;
		target_clusters = target_vcn;
	}
	err = ntfs_attr_allocation_register_undo(handle, ni, &undo);
	if (err)
		goto out_unlock;
	err = ntfs_attr_tail_runlist(ni, target_clusters, old_clusters,
			&tail, &allocated_tail_clusters, &delayed_tail_clusters);
	if (err)
		goto out_unlock;
	if (delayed_tail_clusters > ni->i_dealloc_clusters) {
		err = -EIO;
		goto out_unlock;
	}
	if (has_compressed_size &&
	    allocated_tail_clusters >
		    (u64)ni->itype.compressed.size >>
			    ni->vol->cluster_size_bits) {
		err = -EIO;
		goto out_unlock;
	}
	err = ntfs_rl_truncate_nolock(ni->vol, &ni->runlist,
			target_clusters);
	if (err)
		goto out_unlock;
	ni->runlist.rl_hint = -1;
	ni->i_dealloc_clusters -= delayed_tail_clusters;
	undo->truncated_delayed_clusters = delayed_tail_clusters;
	ni->allocated_size = ntfs_cluster_to_bytes(ni->vol,
			target_clusters);
	if (has_compressed_size)
		ni->itype.compressed.size -= ntfs_cluster_to_bytes(ni->vol,
				allocated_tail_clusters);
	ni->data_size = new_size;
	ni->initialized_size = min(ni->initialized_size, new_size);
	ni->zeroed_size = min(ni->zeroed_size, new_size);
	i_size_write(VFS_I(ni), new_size);
	VFS_I(ni)->i_blocks = (has_compressed_size ?
			ni->itype.compressed.size : ni->allocated_size) >> 9;
	ntfs_attr_accounting_inode(ni)->i_blocks = VFS_I(ni)->i_blocks;
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
out_unlock:
	up_write(&ni->runlist.lock);
	if (!err)
		err = ntfs_cluster_free_from_rl_transacted(handle, ni->vol, tail);
	kvfree(tail);
	return err;
}

/*
 * ntfs_attr_update_mapping_pairs - update mapping pairs for ntfs attribute
 * @ni:		non-resident ntfs inode for which we need update
 * @from_vcn:	update runlist starting this VCN
 * @locked_ni:	inode whose runlist write lock is already held
 * @defer_attrlist: return -ENOSPC instead of updating an attribute list
 *
 * Build mapping pairs from @na->rl and write them to the disk. Also, this
 * function updates sparse bit, allocated and compressed size (allocates/frees
 * space for this field if required).
 *
 * @na->allocated_size should be set to correct value for the new runlist before
 * call to this function. Vice-versa @na->compressed_size will be calculated and
 * set to correct value during this function.
 */
static int __ntfs_attr_update_mapping_pairs(struct ntfs_inode *ni,
					    s64 from_vcn,
					    struct ntfs_inode *locked_ni,
					    bool defer_attrlist)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct mft_record *m;
	struct attr_record *a;
	s64 stop_vcn;
	int err = 0, mp_size, cur_max_mp_size, exp_max_mp_size;
	bool finished_build;
	bool first_updated = false;
	struct super_block *sb;
	struct runlist_element *start_rl;
	unsigned int de_cluster_count = 0;

retry:
	if (!ni || !ni->runlist.rl)
		return -EINVAL;

	ntfs_debug("Entering for inode %llu, attr 0x%x\n",
			(unsigned long long)ni->mft_no, ni->type);

	sb = ni->vol->sb;
	if (!NInoNonResident(ni)) {
		ntfs_error(sb, "%s: resident attribute", __func__);
		return -EINVAL;
	}

	if (ni->nr_extents == -1)
		base_ni = ni->ext.base_ntfs_ino;
	else
		base_ni = ni;

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		ntfs_error(sb, "%s: Failed to get search context", __func__);
		return -ENOMEM;
	}

	/* Fill attribute records with new mapping pairs. */
	stop_vcn = 0;
	finished_build = false;
	start_rl = ni->runlist.rl;
	while (!(err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, from_vcn, NULL, 0, ctx))) {
		unsigned int de_cnt = 0;

		a = ctx->attr;
		m = ctx->mrec;
		if (!a->data.non_resident.lowest_vcn)
			first_updated = true;

		/*
		 * If runlist is updating not from the beginning, then set
		 * @stop_vcn properly, i.e. to the lowest vcn of record that
		 * contain @from_vcn. Also we do not need @from_vcn anymore,
		 * set it to 0 to make ntfs_attr_lookup enumerate attributes.
		 */
		if (from_vcn) {
			s64 first_lcn;

			stop_vcn = le64_to_cpu(a->data.non_resident.lowest_vcn);
			from_vcn = 0;
			/*
			 * Check whether the first run we need to update is
			 * the last run in runlist, if so, then deallocate
			 * all attrubute extents starting this one.
			 */
			first_lcn = ntfs_rl_vcn_to_lcn(ni->runlist.rl, stop_vcn);
			if (first_lcn == LCN_EINVAL) {
				err = -EIO;
				ntfs_error(sb, "Bad runlist");
				goto put_err_out;
			}
			if (first_lcn == LCN_ENOENT ||
			    first_lcn == LCN_RL_NOT_MAPPED)
				finished_build = true;
		}

		/*
		 * Check whether we finished mapping pairs build, if so mark
		 * extent as need to delete (by setting highest vcn to
		 * NTFS_VCN_DELETE_MARK (-2), we shall check it later and
		 * delete extent) and continue search.
		 */
		if (finished_build) {
			ntfs_debug("Mark attr 0x%x for delete in inode 0x%llx.\n",
				(unsigned int)le32_to_cpu(a->type), ctx->ntfs_ino->mft_no);
			a->data.non_resident.highest_vcn = cpu_to_le64(NTFS_VCN_DELETE_MARK);
			mark_mft_record_dirty(ctx->ntfs_ino);
			continue;
		}

		err = ntfs_attr_update_meta(a, ni, m, ctx, locked_ni,
					    defer_attrlist);
		if (err < 0) {
			if (err == -EAGAIN) {
				ntfs_attr_put_search_ctx(ctx);
				goto retry;
			}
			goto put_err_out;
		}

		/*
		 * Determine maximum possible length of mapping pairs,
		 * if we shall *not* expand space for mapping pairs.
		 */
		cur_max_mp_size = le32_to_cpu(a->length) -
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset);
		/*
		 * Determine maximum possible length of mapping pairs in the
		 * current mft record, if we shall expand space for mapping
		 * pairs.
		 */
		exp_max_mp_size = le32_to_cpu(m->bytes_allocated) -
			le32_to_cpu(m->bytes_in_use) + cur_max_mp_size;

		/* Get the size for the rest of mapping pairs array. */
		mp_size = ntfs_get_size_for_mapping_pairs(ni->vol, start_rl,
				stop_vcn, -1, exp_max_mp_size);
		if (mp_size <= 0) {
			err = mp_size;
			ntfs_error(sb, "%s: get MP size failed", __func__);
			goto put_err_out;
		}
		/* Test mapping pairs for fitting in the current mft record. */
		if (mp_size > exp_max_mp_size) {
			/*
			 * Mapping pairs of $ATTRIBUTE_LIST attribute must fit
			 * in the base mft record. Try to move out other
			 * attributes and try again.
			 */
			if (ni->type == AT_ATTRIBUTE_LIST) {
				ntfs_attr_put_search_ctx(ctx);
				ctx = NULL;
				if (locked_ni == ni || defer_attrlist) {
					err = -ENOSPC;
					goto put_err_out;
				}
				err = ntfs_inode_free_space(base_ni, mp_size -
							cur_max_mp_size);
				if (err)
					return err;
				err = ntfs_attrlist_update_locked(
					base_ni, locked_ni);
				if (err)
					return err;
				goto retry;
			}

			/* Add attribute list if it isn't present, and retry. */
			if (!NInoAttrList(base_ni)) {
				if (defer_attrlist) {
					err = -ENOSPC;
					goto put_err_out;
				}
				ntfs_attr_put_search_ctx(ctx);
				if (ntfs_inode_add_attrlist(base_ni)) {
					ntfs_error(sb, "Can not add attrlist");
					return -EIO;
				}
				goto retry;
			}

			/*
			 * Set mapping pairs size to maximum possible for this
			 * mft record. We shall write the rest of mapping pairs
			 * to another MFT records.
			 */
			mp_size = exp_max_mp_size;
		}

		/* Change space for mapping pairs if we need it. */
		if (((mp_size + 7) & ~7) != cur_max_mp_size) {
			if (ntfs_attr_record_resize(m, a,
					le16_to_cpu(a->data.non_resident.mapping_pairs_offset) +
						mp_size)) {
				err = -EIO;
				ntfs_error(sb, "Failed to resize attribute");
				goto put_err_out;
			}
		}

		if (defer_attrlist &&
		    (ctx->ntfs_ino->nr_extents == -1 ||
		     NInoAttrList(ctx->ntfs_ino)) &&
		    ctx->attr->type != AT_ATTRIBUTE_LIST) {
			err = -ENOSPC;
			goto put_err_out;
		}

		/* Update lowest vcn. */
		a->data.non_resident.lowest_vcn = cpu_to_le64(stop_vcn);
		mark_mft_record_dirty(ctx->ntfs_ino);
		if ((ctx->ntfs_ino->nr_extents == -1 || NInoAttrList(ctx->ntfs_ino)) &&
		    ctx->attr->type != AT_ATTRIBUTE_LIST) {
			ctx->al_entry->lowest_vcn = cpu_to_le64(stop_vcn);
			err = ntfs_attrlist_update_locked(base_ni, locked_ni);
			if (err)
				goto put_err_out;
		}

		/*
		 * Generate the new mapping pairs array directly into the
		 * correct destination, i.e. the attribute record itself.
		 */
		err = ntfs_mapping_pairs_build(ni->vol,
				(u8 *)a + le16_to_cpu(a->data.non_resident.mapping_pairs_offset),
				mp_size, start_rl, stop_vcn, -1, &stop_vcn, &start_rl, &de_cnt);
		if (!err)
			finished_build = true;
		if (!finished_build && err != -ENOSPC) {
			ntfs_error(sb, "Failed to build mapping pairs");
			goto put_err_out;
		}
		a->data.non_resident.highest_vcn = cpu_to_le64(stop_vcn - 1);
		mark_mft_record_dirty(ctx->ntfs_ino);
		de_cluster_count += de_cnt;
	}

	/* Check whether error occurred. */
	if (err && err != -ENOENT) {
		ntfs_error(sb, "%s: Attribute lookup failed", __func__);
		goto put_err_out;
	}

	/*
	 * If the base extent was skipped in the above process,
	 * we still may have to update the sizes.
	 */
	if (!first_updated) {
		ntfs_attr_reinit_search_ctx(ctx);
		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, 0, NULL, 0, ctx);
		if (!err) {
			a = ctx->attr;
			a->data.non_resident.allocated_size = cpu_to_le64(ni->allocated_size);
			if (NInoCompressed(ni) || NInoSparse(ni))
				a->data.non_resident.compressed_size =
					cpu_to_le64(ni->itype.compressed.size);
			/* Updating sizes taints the extent holding the attr */
			if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
				NInoSetFileNameDirty(ni);
			mark_mft_record_dirty(ctx->ntfs_ino);
		} else {
			ntfs_error(sb, "Failed to update sizes in base extent\n");
			goto put_err_out;
		}
	}

	/* Deallocate not used attribute extents and return with success. */
	if (finished_build) {
		ntfs_attr_reinit_search_ctx(ctx);
		ntfs_debug("Deallocate marked extents.\n");
		while (!(err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, 0, NULL, 0,
				ctx))) {
			if (le64_to_cpu(ctx->attr->data.non_resident.highest_vcn) !=
					NTFS_VCN_DELETE_MARK)
				continue;
			/* Remove unused attribute record. */
			err = ntfs_attr_record_rm(ctx);
			if (err) {
				ntfs_error(sb,
					   "Could not remove unused attr 0x%x from MFT record 0x%llx (base 0x%llx, error %d).",
					   le32_to_cpu(ni->type),
					   (unsigned long long)ctx->ntfs_ino->mft_no,
					   (unsigned long long)base_ni->mft_no, err);
				goto put_err_out;
			}
			ntfs_attr_reinit_search_ctx(ctx);
		}
		if (err && err != -ENOENT) {
			ntfs_error(sb, "%s: Attr lookup failed", __func__);
			goto put_err_out;
		}
		ntfs_debug("Deallocate done.\n");
		ntfs_attr_put_search_ctx(ctx);
		goto out;
	}
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;

	/* Allocate new MFT records for the rest of mapping pairs. */
	while (1) {
		struct ntfs_inode *ext_ni = NULL;
		unsigned int de_cnt = 0;

		/* Allocate new mft record. */
		err = ntfs_mft_record_alloc(ni->vol, 0, &ext_ni, base_ni, NULL,
					    base_ni->mft_no == FILE_MFT &&
					    ni->type == AT_DATA &&
					    ni->name == AT_UNNAMED ? stop_vcn : -1);
		if (err) {
			ntfs_error(sb, "Failed to allocate extent record");
			goto put_err_out;
		}
		unmap_mft_record(ext_ni);

		m = map_mft_record(ext_ni);
		if (IS_ERR(m)) {
			ntfs_error(sb, "Could not map new MFT record");
			if (ntfs_mft_record_free(ni->vol, ext_ni))
				ntfs_error(sb, "Could not free MFT record");
			ntfs_inode_close(ext_ni);
			err = -ENOMEM;
			ext_ni = NULL;
			goto put_err_out;
		}
		/*
		 * If mapping size exceed available space, set them to
		 * possible maximum.
		 */
		cur_max_mp_size = le32_to_cpu(m->bytes_allocated) -
			le32_to_cpu(m->bytes_in_use) -
			(sizeof(struct attr_record) +
			 ((NInoCompressed(ni) || NInoSparse(ni)) ?
			  sizeof(a->data.non_resident.compressed_size) : 0)) -
			((sizeof(__le16) * ni->name_len + 7) & ~7);

		/* Calculate size of rest mapping pairs. */
		mp_size = ntfs_get_size_for_mapping_pairs(ni->vol,
				start_rl, stop_vcn, -1, cur_max_mp_size);
		if (mp_size <= 0) {
			unmap_mft_record(ext_ni);
			ntfs_inode_close(ext_ni);
			err = mp_size;
			ntfs_error(sb, "%s: get mp size failed", __func__);
			goto put_err_out;
		}

		if (mp_size > cur_max_mp_size)
			mp_size = cur_max_mp_size;
		/* Add attribute extent to new record. */
		err = ntfs_non_resident_attr_record_add(NULL, ext_ni, ni->type,
				ni->name, ni->name_len, stop_vcn, mp_size, 0);
		if (err < 0) {
			ntfs_error(sb, "Could not add attribute extent");
			unmap_mft_record(ext_ni);
			if (ntfs_mft_record_free(ni->vol, ext_ni))
				ntfs_error(sb, "Could not free MFT record");
			ntfs_inode_close(ext_ni);
			goto put_err_out;
		}
		a = (struct attr_record *)((u8 *)m + err);

		err = ntfs_mapping_pairs_build(ni->vol, (u8 *)a +
				le16_to_cpu(a->data.non_resident.mapping_pairs_offset),
				mp_size, start_rl, stop_vcn, -1, &stop_vcn, &start_rl,
				&de_cnt);
		if (err < 0 && err != -ENOSPC) {
			ntfs_error(sb, "Failed to build MP");
			unmap_mft_record(ext_ni);
			if (ntfs_mft_record_free(ni->vol, ext_ni))
				ntfs_error(sb, "Couldn't free MFT record");
			goto put_err_out;
		}
		a->data.non_resident.highest_vcn = cpu_to_le64(stop_vcn - 1);
		mark_mft_record_dirty(ext_ni);
		unmap_mft_record(ext_ni);

		de_cluster_count += de_cnt;
		/* All mapping pairs has been written. */
		if (!err)
			break;
	}
out:
	if (from_vcn == 0)
		ni->i_dealloc_clusters = de_cluster_count;
	return 0;

put_err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	return err;
}

int ntfs_attr_update_mapping_pairs_locked(struct ntfs_inode *ni,
					  s64 from_vcn,
					 struct ntfs_inode *locked_ni)
{
	return __ntfs_attr_update_mapping_pairs(ni, from_vcn, locked_ni,
						false);
}

int ntfs_attr_update_mapping_pairs(struct ntfs_inode *ni, s64 from_vcn)
{
	return ntfs_attr_update_mapping_pairs_locked(ni, from_vcn, NULL);
}

/*
 * ntfs_attr_make_resident - convert a non-resident to a resident attribute
 * @ni:		open ntfs attribute to make resident
 * @ctx:	ntfs search context describing the attribute
 *
 * Convert a non-resident ntfs attribute to a resident one.
 */
static int ntfs_attr_make_resident(struct ntfs_inode *ni, struct ntfs_attr_search_ctx *ctx)
{
	struct ntfs_volume *vol = ni->vol;
	struct super_block *sb = vol->sb;
	struct attr_record *a = ctx->attr;
	int name_ofs, val_ofs, err;
	s64 arec_size;

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x.\n",
			(unsigned long long)ni->mft_no, ni->type);

	/* Should be called for the first extent of the attribute. */
	if (le64_to_cpu(a->data.non_resident.lowest_vcn)) {
		ntfs_debug("Eeek!  Should be called for the first extent of the attribute.  Aborting...\n");
		return -EINVAL;
	}

	/* Some preliminary sanity checking. */
	if (!NInoNonResident(ni)) {
		ntfs_debug("Eeek!  Trying to make resident attribute resident. Aborting...\n");
		return -EINVAL;
	}

	/* Make sure this is not $MFT/$BITMAP or Windows will not boot! */
	if (ni->type == AT_BITMAP && ni->mft_no == FILE_MFT)
		return -EPERM;

	/* Check that the attribute is allowed to be resident. */
	err = ntfs_attr_can_be_resident(vol, ni->type);
	if (err)
		return err;

	if (NInoCompressed(ni) || NInoEncrypted(ni)) {
		ntfs_debug("Making compressed or encrypted files resident is not implemented yet.\n");
		return -EOPNOTSUPP;
	}

	/* Work out offsets into and size of the resident attribute. */
	name_ofs = 24; /* = sizeof(resident_struct attr_record) */
	val_ofs = (name_ofs + a->name_length * sizeof(__le16) + 7) & ~7;
	arec_size = (val_ofs + ni->data_size + 7) & ~7;

	/* Sanity check the size before we start modifying the attribute. */
	if (le32_to_cpu(ctx->mrec->bytes_in_use) - le32_to_cpu(a->length) +
	    arec_size > le32_to_cpu(ctx->mrec->bytes_allocated)) {
		ntfs_debug("Not enough space to make attribute resident\n");
		return -ENOSPC;
	}

	/* Read and cache the whole runlist if not already done. */
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;

	/* Move the attribute name if it exists and update the offset. */
	if (a->name_length) {
		memmove((u8 *)a + name_ofs, (u8 *)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(__le16));
	}
	a->name_offset = cpu_to_le16(name_ofs);

	/* Resize the resident part of the attribute record. */
	if (ntfs_attr_record_resize(ctx->mrec, a, arec_size) < 0) {
		/*
		 * Bug, because ntfs_attr_record_resize should not fail (we
		 * already checked that attribute fits MFT record).
		 */
		ntfs_error(ctx->ntfs_ino->vol->sb, "BUG! Failed to resize attribute record. ");
		return -EIO;
	}

	/* Convert the attribute record to describe a resident attribute. */
	a->non_resident = 0;
	a->flags = 0;
	a->data.resident.value_length = cpu_to_le32(ni->data_size);
	a->data.resident.value_offset = cpu_to_le16(val_ofs);
	/*
	 * File names cannot be non-resident so we would never see this here
	 * but at least it serves as a reminder that there may be attributes
	 * for which we do need to set this flag. (AIA)
	 */
	if (a->type == AT_FILE_NAME)
		a->data.resident.flags = RESIDENT_ATTR_IS_INDEXED;
	else
		a->data.resident.flags = 0;
	a->data.resident.reserved = 0;

	/*
	 * Deallocate clusters from the runlist.
	 *
	 * NOTE: We can use ntfs_cluster_free() because we have already mapped
	 * the whole run list and thus it doesn't matter that the attribute
	 * record is in a transiently corrupted state at this moment in time.
	 */
	err = ntfs_cluster_free(ni, 0, -1, ctx);
	if (err) {
		ntfs_error(sb, "Eeek! Failed to release allocated clusters");
		ntfs_debug("Ignoring error and leaving behind wasted clusters.\n");
	}

	/* Throw away the now unused runlist. */
	kvfree(ni->runlist.rl);
	ni->runlist.rl = NULL;
	ni->runlist.count = 0;
	/* Update in-memory struct ntfs_attr. */
	NInoClearNonResident(ni);
	NInoClearCompressed(ni);
	ni->flags &= ~FILE_ATTR_COMPRESSED;
	NInoClearSparse(ni);
	ni->flags &= ~FILE_ATTR_SPARSE_FILE;
	NInoClearEncrypted(ni);
	ni->flags &= ~FILE_ATTR_ENCRYPTED;
	ni->initialized_size = ni->data_size;
	ni->allocated_size = ni->itype.compressed.size = (ni->data_size + 7) & ~7;
	ni->itype.compressed.block_size = 0;
	ni->itype.compressed.block_size_bits = ni->itype.compressed.block_clusters = 0;
	return 0;
}

/*
 * ntfs_non_resident_attr_shrink - shrink a non-resident, open ntfs attribute
 * @ni:		non-resident ntfs attribute to shrink
 * @newsize:	new size (in bytes) to which to shrink the attribute
 * @pagecache_truncated: page cache was already truncated to @newsize
 *
 * Reduce the size of a non-resident, open ntfs attribute @na to @newsize bytes.
 */
static int ntfs_non_resident_attr_shrink(struct ntfs_inode *ni,
					 const s64 newsize,
					struct ntfs_inode *locked_ni,
					bool pagecache_truncated)
{
	struct ntfs_volume *vol;
	struct ntfs_attr_search_ctx *ctx;
	s64 first_free_vcn;
	s64 nr_freed_clusters;
	int err;
	struct ntfs_inode *base_ni;
	bool runlist_locked = locked_ni == ni;

	ntfs_debug("Inode 0x%llx attr 0x%x new size %lld\n",
		(unsigned long long)ni->mft_no, ni->type, (long long)newsize);

	vol = ni->vol;

	if (NInoAttr(ni))
		base_ni = ni->ext.base_ntfs_ino;
	else
		base_ni = ni;

	/*
	 * Check the attribute type and the corresponding minimum size
	 * against @newsize and fail if @newsize is too small.
	 */
	err = ntfs_attr_size_bounds_check(vol, ni->type, newsize);
	if (err) {
		if (err == -ERANGE)
			ntfs_debug("Eeek! Size bounds check failed. Aborting...\n");
		else if (err == -ENOENT)
			err = -EIO;
		return err;
	}

	/* The first cluster outside the new allocation. */
	if (NInoCompressed(ni))
		/*
		 * For compressed files we must keep full compressions blocks,
		 * but currently we do not decompress/recompress the last
		 * block to truncate the data, so we may leave more allocated
		 * clusters than really needed.
		 */
		first_free_vcn = ntfs_bytes_to_cluster(vol,
				((newsize - 1) | (ni->itype.compressed.block_size - 1)) + 1);
	else
		first_free_vcn =
			ntfs_bytes_to_cluster(vol, newsize + vol->cluster_size - 1);

	if (first_free_vcn < 0)
		return -EINVAL;
	/*
	 * Compare the new allocation with the old one and only deallocate
	 * clusters if there is a change.
	 */
	if (ntfs_bytes_to_cluster(vol, ni->allocated_size) != first_free_vcn) {
		/*
		 * ntfs_cluster_free() and ntfs_rl_truncate_nolock()
		 * both require this lock.
		 */
		if (!runlist_locked)
			down_write(&ni->runlist.lock);

		err = ntfs_attr_map_whole_runlist(ni);
		if (err) {
			ntfs_debug("Eeek! ntfs_attr_map_whole_runlist failed.\n");
			goto unlock_runlist;
		}

		ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
		if (!ctx) {
			ntfs_error(vol->sb, "%s: Failed to get search context", __func__);
			err = -ENOMEM;
			goto unlock_runlist;
		}

		/* Deallocate all clusters starting with the first free one. */
		nr_freed_clusters = ntfs_cluster_free(ni, first_free_vcn, -1, ctx);
		if (nr_freed_clusters < 0) {
			ntfs_debug("Eeek! Freeing of clusters failed. Aborting...\n");
			ntfs_attr_put_search_ctx(ctx);
			err = (int)nr_freed_clusters;
			goto unlock_runlist;
		}
		ntfs_attr_put_search_ctx(ctx);

		/* Truncate the runlist itself. */
		if (ntfs_rl_truncate_nolock(vol, &ni->runlist, first_free_vcn)) {
			/*
			 * Failed to truncate the runlist, so just throw it
			 * away, it will be mapped afresh on next use.
			 */
			kvfree(ni->runlist.rl);
			ni->runlist.rl = NULL;
			ntfs_error(vol->sb, "Eeek! Run list truncation failed.\n");
			err = -EIO;
			goto unlock_runlist;
		}

		/* Prepare to mapping pairs update. */
		ni->allocated_size = ntfs_cluster_to_bytes(vol, first_free_vcn);

		if (NInoSparse(ni) || NInoCompressed(ni)) {
			if (nr_freed_clusters) {
				ni->itype.compressed.size -=
					ntfs_cluster_to_bytes(vol, nr_freed_clusters);
				ntfs_attr_accounting_inode(ni)->i_blocks =
						ni->itype.compressed.size >> 9;
			}
		} else
			ntfs_attr_accounting_inode(ni)->i_blocks =
					ni->allocated_size >> 9;

		/* Write mapping pairs for new runlist. */
		err = ntfs_attr_update_mapping_pairs_locked(ni, 0, ni);
		if (err) {
			ntfs_debug("Eeek! Mapping pairs update failed. Leaving inconstant metadata. Run chkdsk.\n");
			goto unlock_runlist;
		}
		if (!runlist_locked)
			up_write(&ni->runlist.lock);
	}

	/* Get the first attribute record. */
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		ntfs_error(vol->sb, "%s: Failed to get search context", __func__);
		return -ENOMEM;
	}

	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		ntfs_debug("Eeek! Lookup of first attribute extent failed. Leaving inconstant metadata.\n");
		goto put_err_out;
	}

	/* Update data and initialized size. */
	ni->data_size = newsize;
	ctx->attr->data.non_resident.data_size = cpu_to_le64(newsize);
	if (newsize < ni->initialized_size) {
		ni->initialized_size = newsize;
		ctx->attr->data.non_resident.initialized_size = cpu_to_le64(newsize);
	}

	/*
	 * Drop any page-cache folios that now lie beyond the shrunk
	 * attribute. The clusters backing them have just been freed and the
	 * runlist truncated, so leaving stale dirty folios around makes a
	 * later writeback map a vcn past the new allocation, which fails with
	 * -ENOENT and loses the write.
	 */
	if (!pagecache_truncated)
		truncate_inode_pages(VFS_I(ni)->i_mapping, newsize);

	/* Update data size in the index. */
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);

	/*
	 * This path cannot log a resident conversion.  On journaled volumes,
	 * keep the nonresident layout so later attribute offsets remain valid
	 * during replay.
	 */
	if (!newsize && !vol->journal &&
	    !NInoEncrypted(ni) && !NInoCompressed(ni)) {
		if (!runlist_locked)
			down_write(&ni->runlist.lock);
		err = ntfs_attr_make_resident(ni, ctx);
		if (!runlist_locked)
			up_write(&ni->runlist.lock);
		if (err) {
			/* If couldn't make resident, just continue. */
			if (err != -EPERM)
				ntfs_error(ni->vol->sb,
					"Failed to make attribute resident. Leaving as is...\n");
		}
	}

	/* Set the inode dirty so it is written out later. */
	mark_mft_record_dirty(ctx->ntfs_ino);
	/* Done! */
	ntfs_attr_put_search_ctx(ctx);
	return 0;
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
	return err;

unlock_runlist:
	if (!runlist_locked)
		up_write(&ni->runlist.lock);
	return err;
}

/*
 * ntfs_non_resident_attr_expand - expand a non-resident, open ntfs attribute
 * @ni:			non-resident ntfs attribute to expand
 * @prealloc_size:	preallocation size (in bytes) to which to expand the attribute
 * @newsize:		new size (in bytes) to which to expand the attribute
 * @holes:		how to create a hole if expanding
 * @locked_ni:		inode whose runlist lock is already held
 *
 * Expand the size of a non-resident, open ntfs attribute @na to @newsize bytes,
 * by allocating new clusters.
 */
static int ntfs_non_resident_attr_expand(struct ntfs_inode *ni, const s64 newsize,
		const s64 prealloc_size, unsigned int holes,
		struct ntfs_inode *locked_ni)
{
	s64 lcn_seek_from;
	s64 first_free_vcn;
	struct ntfs_volume *vol;
	struct ntfs_attr_search_ctx *ctx = NULL;
	struct runlist_element *rl, *rln;
	s64 org_alloc_size, org_compressed_size;
	int err, err2;
	struct ntfs_inode *base_ni;
	struct super_block *sb = ni->vol->sb;
	size_t new_rl_count;
	unsigned long flags;
	bool runlist_locked = locked_ni == ni;

	ntfs_debug("Inode 0x%llx, attr 0x%x, new size %lld old size %lld\n",
			(unsigned long long)ni->mft_no, ni->type,
			(long long)newsize, (long long)ni->data_size);

	vol = ni->vol;

	if (NInoAttr(ni))
		base_ni = ni->ext.base_ntfs_ino;
	else
		base_ni = ni;

	/*
	 * Check the attribute type and the corresponding maximum size
	 * against @newsize and fail if @newsize is too big.
	 */
	err = ntfs_attr_size_bounds_check(vol, ni->type, newsize);
	if (err	< 0) {
		ntfs_error(sb, "%s: bounds check failed", __func__);
		return err;
	}

	/* Save for future use. */
	org_alloc_size = ni->allocated_size;
	org_compressed_size = ni->itype.compressed.size;

	/* The first cluster outside the new allocation. */
	if (prealloc_size)
		first_free_vcn =
			ntfs_bytes_to_cluster(vol, prealloc_size + vol->cluster_size - 1);
	else
		first_free_vcn =
			ntfs_bytes_to_cluster(vol, newsize + vol->cluster_size - 1);
	if (first_free_vcn < 0)
		return -EFBIG;

	/*
	 * Compare the new allocation with the old one and only allocate
	 * clusters if there is a change.
	 */
	if (ntfs_bytes_to_cluster(vol, ni->allocated_size) < first_free_vcn) {
		/*
		 * The runlist array is replaced below.  Readers such as the
		 * iomap read path hold only the runlist lock, not mrec_lock.
		 */
		if (runlist_locked)
			lockdep_assert_held_write(&ni->runlist.lock);
		else
			down_write(&ni->runlist.lock);

		err = ntfs_attr_map_whole_runlist(ni);
		if (err) {
			ntfs_error(sb, "ntfs_attr_map_whole_runlist failed");
			goto unlock_runlist;
		}

		/*
		 * If we extend $DATA attribute on NTFS 3+ volume, we can add
		 * sparse runs instead of real allocation of clusters.
		 */
		if ((ni->type == AT_DATA && (vol->major_ver >= 3 || !NInoSparseDisabled(ni))) &&
		    (holes != HOLES_NO)) {
			if (NInoCompressed(ni)) {
				int last = 0, i = 0;
				s64 alloc_size;
				u64 more_entries = round_up(first_free_vcn -
						 ntfs_bytes_to_cluster(vol, ni->allocated_size),
						 ni->itype.compressed.block_clusters);

				do_div(more_entries, ni->itype.compressed.block_clusters);

				while (ni->runlist.rl[last].length)
					last++;

				rl = ntfs_rl_realloc(ni->runlist.rl, last + 1,
						last + more_entries + 1);
				if (IS_ERR(rl)) {
					err = -ENOMEM;
					goto unlock_runlist;
				}

				alloc_size = ni->allocated_size;
				while (i++ < more_entries) {
					rl[last].vcn = ntfs_bytes_to_cluster(vol,
							round_up(alloc_size, vol->cluster_size));
					rl[last].length = ni->itype.compressed.block_clusters -
						(rl[last].vcn &
						 (ni->itype.compressed.block_clusters - 1));
					rl[last].lcn = LCN_HOLE;
					last++;
					alloc_size += ni->itype.compressed.block_size;
				}

				rl[last].vcn = first_free_vcn;
				rl[last].lcn = LCN_ENOENT;
				rl[last].length = 0;

				ni->runlist.rl = rl;
				ni->runlist.count += more_entries;
			} else {
				rl = kmalloc(sizeof(struct runlist_element) * 2, GFP_NOFS);
				if (!rl) {
					err = -ENOMEM;
					goto unlock_runlist;
				}

				rl[0].vcn = ntfs_bytes_to_cluster(vol, ni->allocated_size);
				rl[0].lcn = LCN_HOLE;
				rl[0].length = first_free_vcn -
					ntfs_bytes_to_cluster(vol, ni->allocated_size);
				rl[1].vcn = first_free_vcn;
				rl[1].lcn = LCN_ENOENT;
				rl[1].length = 0;
			}
		} else {
			/*
			 * Determine first after last LCN of attribute.
			 * We will start seek clusters from this LCN to avoid
			 * fragmentation.  If there are no valid LCNs in the
			 * attribute let the cluster allocator choose the
			 * starting LCN.
			 */
			lcn_seek_from = -1;
			if (ni->runlist.rl->length) {
				/* Seek to the last run list element. */
				for (rl = ni->runlist.rl; (rl + 1)->length; rl++)
					;
				/*
				 * If the last LCN is a hole or similar seek
				 * back to last valid LCN.
				 */
				while (rl->lcn < 0 && rl != ni->runlist.rl)
					rl--;
				/*
				 * Only set lcn_seek_from it the LCN is valid.
				 */
				if (rl->lcn >= 0)
					lcn_seek_from = rl->lcn + rl->length;
			}

			rl = ntfs_cluster_alloc(vol,
					ntfs_bytes_to_cluster(vol, ni->allocated_size),
					first_free_vcn -
					ntfs_bytes_to_cluster(vol, ni->allocated_size),
					lcn_seek_from, DATA_ZONE, false,
					ni->type == AT_ATTRIBUTE_LIST, false);
			if (IS_ERR(rl)) {
				ntfs_debug("Cluster allocation failed (%lld)",
						(long long)first_free_vcn -
						ntfs_bytes_to_cluster(vol, ni->allocated_size));
				err = PTR_ERR(rl);
				goto unlock_runlist;
			}
			/*
			 * A contiguous ATTRIBUTE_LIST allocation keeps its mapping
			 * pairs small enough to fit in the base MFT record. The
			 * allocator can return a short run when contiguity was
			 * requested, so discard it and retry normally if necessary.
			 */
			if (ni->type == AT_ATTRIBUTE_LIST &&
				(rl->vcn != ntfs_bytes_to_cluster(vol,
						ni->allocated_size) ||
				 rl->length != first_free_vcn -
					ntfs_bytes_to_cluster(vol, ni->allocated_size) ||
				 rl[1].length)) {
				ntfs_cluster_free_from_rl(vol, rl);
				kvfree(rl);
				rl = ntfs_cluster_alloc(vol,
						ntfs_bytes_to_cluster(vol,
								ni->allocated_size),
						first_free_vcn -
						ntfs_bytes_to_cluster(vol,
								ni->allocated_size),
						lcn_seek_from, DATA_ZONE, false,
						false, false);
				if (IS_ERR(rl)) {
					err = PTR_ERR(rl);
					goto unlock_runlist;
				}
			}
		}

		if (!NInoCompressed(ni)) {
			/* Append new clusters to attribute runlist. */
			rln = ntfs_runlists_merge(&ni->runlist, rl, 0, &new_rl_count);
			if (IS_ERR(rln)) {
				/* Failed, free just allocated clusters. */
				ntfs_error(sb, "Run list merge failed");
				ntfs_cluster_free_from_rl(vol, rl);
				kvfree(rl);
				err = -EIO;
				goto unlock_runlist;
			}
			ni->runlist.rl = rln;
			ni->runlist.count = new_rl_count;
		}

		/* Prepare to mapping pairs update. */
		ni->allocated_size = ntfs_cluster_to_bytes(vol, first_free_vcn);
		if (ni->type == AT_ATTRIBUTE_LIST && !runlist_locked) {
			/*
			 * Making room for the list's mapping pairs can resize
			 * this attribute list again through
			 * ntfs_attrlist_update_locked(), which takes its
			 * runlist lock.
			 */
			up_write(&ni->runlist.lock);
			err = ntfs_attr_update_mapping_pairs_locked(ni, 0,
								    locked_ni);
			if (err) {
				ntfs_debug("Mapping pairs update failed");
				goto rollback;
			}
		} else {
			err = ntfs_attr_update_mapping_pairs_locked(ni, 0, ni);
			if (err) {
				ntfs_debug("Mapping pairs update failed");
				goto rollback_locked;
			}
			if (!runlist_locked)
				up_write(&ni->runlist.lock);
		}
	}

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		if (ni->allocated_size == org_alloc_size)
			return err;
		goto rollback;
	}

	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			       CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		if (ni->allocated_size != org_alloc_size)
			goto rollback;
		goto put_err_out;
	}

	/* Update data size. */
	ni->data_size = newsize;
	ctx->attr->data.non_resident.data_size = cpu_to_le64(newsize);
	/* Update data size in the index. */
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	/* Set the inode dirty so it is written out later. */
	mark_mft_record_dirty(ctx->ntfs_ino);
	/* Done! */
	ntfs_attr_put_search_ctx(ctx);
	return 0;
rollback:
	if (!runlist_locked)
		down_write(&ni->runlist.lock);
rollback_locked:
	/* Free allocated clusters. */
	err2 = ntfs_cluster_free(ni, ntfs_bytes_to_cluster(vol, org_alloc_size),
				-1, ctx);
	if (err2 < 0) {
		ntfs_error(sb,
			   "Failed to free clusters during expansion rollback for inode 0x%llx (error %d).",
			   (unsigned long long)ni->mft_no, err2);
		NVolSetErrors(vol);
	}

	/*
	 * Now, truncate the runlist itself.  Restore allocated_size before
	 * dropping the lock: ntfs_attr_vcn_to_rl() fails a lookup below the
	 * allocated size that falls past the end of the runlist.
	 */
	err2 = ntfs_rl_truncate_nolock(vol, &ni->runlist,
			ntfs_bytes_to_cluster(vol, org_alloc_size));
	if (!err2) {
		write_lock_irqsave(&ni->size_lock, flags);
		ni->allocated_size = org_alloc_size;
		write_unlock_irqrestore(&ni->size_lock, flags);
	}
	if (err2) {
		/*
		 * Failed to truncate the runlist, so just throw it away, it
		 * will be mapped afresh on next use.
		 */
		kvfree(ni->runlist.rl);
		ni->runlist.rl = NULL;
		ntfs_error(sb, "Couldn't truncate runlist. Rollback failed");
		NVolSetErrors(vol);
	} else {
		/* Restore mapping pairs. */
		err2 = __ntfs_attr_update_mapping_pairs(ni, 0, ni, true);
		if (err2) {
			ntfs_error(sb,
				   "Failed to restore old mapping pairs for inode 0x%llx, attr 0x%x (error %d).",
				   (unsigned long long)ni->mft_no,
				   le32_to_cpu(ni->type), err2);
			NVolSetErrors(vol);
		}

		if (NInoSparse(ni) || NInoCompressed(ni)) {
			ni->itype.compressed.size =  org_compressed_size;
			ntfs_attr_accounting_inode(ni)->i_blocks =
					ni->itype.compressed.size >> 9;
		} else
			ntfs_attr_accounting_inode(ni)->i_blocks =
					ni->allocated_size >> 9;
	}
	if (!runlist_locked)
		up_write(&ni->runlist.lock);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	return err;
put_err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	return err;
unlock_runlist:
	if (!runlist_locked)
		up_write(&ni->runlist.lock);
	return err;
}

/*
 * ntfs_resident_attr_resize - resize a resident, open ntfs attribute
 * @attr_ni:		resident ntfs inode to resize
 * @newsize:		new size (in bytes) to which to resize the attribute
 * @prealloc_size:	preallocation size (in bytes) to which to resize the attribute
 * @holes:		flags indicating how to handle holes
 *
 * Change the size of a resident, open ntfs attribute @na to @newsize bytes.
 */
static int ntfs_resident_attr_resize(struct ntfs_inode *attr_ni, const s64 newsize,
		const s64 prealloc_size, unsigned int holes)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_volume *vol = attr_ni->vol;
	struct super_block *sb = vol->sb;
	int err = -EIO;
	struct ntfs_inode *base_ni, *ext_ni = NULL;

attr_resize_again:
	ntfs_debug("Inode 0x%llx attr 0x%x new size %lld\n",
			(unsigned long long)attr_ni->mft_no, attr_ni->type,
			(long long)newsize);

	if (NInoAttr(attr_ni))
		base_ni = attr_ni->ext.base_ntfs_ino;
	else
		base_ni = attr_ni;

	/* Get the attribute record that needs modification. */
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		ntfs_error(sb, "%s: Failed to get search context", __func__);
		return -ENOMEM;
	}

	err = ntfs_attr_lookup(attr_ni->type, attr_ni->name, attr_ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		ntfs_error(sb, "ntfs_attr_lookup failed");
		goto put_err_out;
	}

	/*
	 * Check the attribute type and the corresponding minimum and maximum
	 * sizes against @newsize and fail if @newsize is out of bounds.
	 */
	err = ntfs_attr_size_bounds_check(vol, attr_ni->type, newsize);
	if (err) {
		if (err == -ENOENT)
			err = -EIO;
		ntfs_debug("%s: bounds check failed", __func__);
		goto put_err_out;
	}
	/*
	 * If @newsize is bigger than the mft record we need to make the
	 * attribute non-resident if the attribute type supports it. If it is
	 * smaller we can go ahead and attempt the resize.
	 */
	if (newsize < vol->mft_record_size) {
		/* Perform the resize of the attribute record. */
		err = ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr,
					newsize);
		if (!err) {
			/* Update attribute size everywhere. */
			attr_ni->data_size = attr_ni->initialized_size = newsize;
			attr_ni->zeroed_size = newsize;
			attr_ni->allocated_size = (newsize + 7) & ~7;
			if (NInoCompressed(attr_ni) || NInoSparse(attr_ni))
				attr_ni->itype.compressed.size = attr_ni->allocated_size;
			if (attr_ni->type == AT_DATA && attr_ni->name == AT_UNNAMED)
				NInoSetFileNameDirty(attr_ni);
			goto resize_done;
		}

		/* Prefer AT_INDEX_ALLOCATION instead of AT_ATTRIBUTE_LIST */
		if (err == -ENOSPC && ctx->attr->type == AT_INDEX_ROOT)
			goto put_err_out;

	}
	/* There is not enough space in the mft record to perform the resize. */

	/* Make the attribute non-resident if possible. */
	err = __ntfs_attr_make_non_resident(attr_ni,
			le32_to_cpu(ctx->attr->data.resident.value_length), true);
	/*
	 * A reader holding folio 0 waits for mrec_lock, which we hold. Do not
	 * wait for it and do not look for room elsewhere either: the reader
	 * keeps the folio until we drop the lock, so the attribute can neither
	 * be converted nor written without waiting for it, and the loop below
	 * would only convert other attributes for nothing.
	 */
	if (err == -EAGAIN) {
		/*
		 * Not -EAGAIN, it would reach user space and index.c uses it
		 * for its own retry. Not -ENOSPC, the record is not full.
		 */
		err = -EBUSY;
		goto put_err_out;
	}
	if (!err) {
		mark_mft_record_dirty(ctx->ntfs_ino);
		ntfs_attr_put_search_ctx(ctx);
		/* Resize non-resident attribute */
		return ntfs_non_resident_attr_expand(
				attr_ni, newsize, prealloc_size, holes, NULL);
	} else if (err != -ENOSPC && err != -EPERM) {
		ntfs_error(sb, "Failed to make attribute non-resident");
		goto put_err_out;
	}

	/* Try to make other attributes non-resident and retry each time. */
	ntfs_attr_reinit_search_ctx(ctx);
	while (!(err = ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx))) {
		struct inode *tvi;
		struct attr_record *a;
		__le16 *name;
		u32 value_len;

		a = ctx->attr;
		if (a->non_resident || a->type == AT_ATTRIBUTE_LIST)
			continue;
		value_len = le32_to_cpu(a->data.resident.value_length);
		name = (__le16 *)((u8 *)a + le16_to_cpu(a->name_offset));

		if (ntfs_attr_can_be_non_resident(vol, a->type))
			continue;

		/*
		 * Check out whether convert is reasonable. Assume that mapping
		 * pairs will take 8 bytes.
		 */
		if (le32_to_cpu(a->length) <= (sizeof(struct attr_record) - sizeof(s64)) +
				((a->name_length * sizeof(__le16) + 7) & ~7) + 8)
			continue;
		if (a->type == AT_DATA && !value_len)
			continue;

		/*
		 * The attribute inode of an unlinked file is evicted on the
		 * last iput() together with its dirty folio.
		 */
		if (NInoBeingDeleted(base_ni) || !VFS_I(base_ni)->i_nlink)
			continue;

		/*
		 * Not the attribute being resized. Its conversion was tried
		 * above and failed, for instance on a busy folio, and
		 * converting it here would leave the resize to go on with the
		 * resident layout of a non-resident record.
		 */
		if (a->type == attr_ni->type &&
		    a->name_length == attr_ni->name_len &&
		    (!a->name_length ||
		     !memcmp(name, attr_ni->name,
			     a->name_length * sizeof(__le16))))
			continue;

		/*
		 * Not the unnamed data either. Only the resize of the unnamed
		 * data itself holds its i_rwsem, a writer of the file can be
		 * between its residency check and the mft record lock.
		 */
		if (a->type == AT_DATA && !a->name_length)
			continue;

		/*
		 * A named $DATA stream is converted only if nobody has it open:
		 * an open one can be unlinked, being removed or in use. A WOF
		 * file reads its stream from the device, so the stream must
		 * stay resident.
		 */
		if (a->type == AT_DATA) {
			if (NInoWofCompressed(base_ni))
				continue;
			tvi = ntfs_attr_ilookup(VFS_I(base_ni), a->type,
					name, a->name_length);
			if (tvi) {
				iput(tvi);
				continue;
			}
		}
		tvi = ntfs_attr_iget(VFS_I(base_ni), a->type, name,
				a->name_length);
		/* the lookup ignores case for streams, ours does not */
		if (!IS_ERR(tvi) && a->type == AT_DATA &&
		    memcmp(NTFS_I(tvi)->name, name,
			   a->name_length * sizeof(__le16))) {
			iput(tvi);
			continue;
		}
		if (IS_ERR(tvi)) {
			ntfs_error(sb, "Couldn't open attribute");
			continue;
		}

		if (__ntfs_attr_make_non_resident(NTFS_I(tvi), value_len, true)) {
			iput(tvi);
			continue;
		}

		mark_mft_record_dirty(ctx->ntfs_ino);
		iput(tvi);
		ntfs_attr_put_search_ctx(ctx);
		goto attr_resize_again;
	}

	/* Check whether error occurred. */
	if (err != -ENOENT) {
		ntfs_error(sb, "%s: Attribute lookup failed 1", __func__);
		goto put_err_out;
	}

	/*
	 * The standard information and attribute list attributes can't be
	 * moved out from the base MFT record, so try to move out others.
	 */
	if (attr_ni->type == AT_STANDARD_INFORMATION ||
	    attr_ni->type == AT_ATTRIBUTE_LIST) {
		ntfs_attr_put_search_ctx(ctx);

		if (!NInoAttrList(base_ni)) {
			err = ntfs_inode_add_attrlist(base_ni);
			if (err)
				return err;
		}

		err = ntfs_inode_free_space(base_ni, sizeof(struct attr_record));
		if (err) {
			err = -ENOSPC;
			ntfs_error(sb,
				"Couldn't free space in the MFT record to make attribute list non resident");
			return err;
		}
		err = ntfs_attrlist_update(base_ni);
		if (err)
			return err;
		goto attr_resize_again;
	}

	/*
	 * Move the attribute to a new mft record, creating an attribute list
	 * attribute or modifying it if it is already present.
	 */

	/* Point search context back to attribute which we need resize. */
	ntfs_attr_reinit_search_ctx(ctx);
	err = ntfs_attr_lookup(attr_ni->type, attr_ni->name, attr_ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		ntfs_error(sb, "%s: Attribute lookup failed 2", __func__);
		goto put_err_out;
	}

	/*
	 * Check whether attribute is already single in this MFT record.
	 * 8 added for the attribute terminator.
	 */
	if (le32_to_cpu(ctx->mrec->bytes_in_use) ==
	    le16_to_cpu(ctx->mrec->attrs_offset) + le32_to_cpu(ctx->attr->length) + 8) {
		err = -ENOSPC;
		ntfs_debug("MFT record is filled with one attribute\n");
		goto put_err_out;
	}

	/* Add attribute list if not present. */
	if (!NInoAttrList(base_ni)) {
		ntfs_attr_put_search_ctx(ctx);
		err = ntfs_inode_add_attrlist(base_ni);
		if (err)
			return err;
		goto attr_resize_again;
	}

	/* Allocate new mft record. */
	err = ntfs_mft_record_alloc(base_ni->vol, 0, &ext_ni, base_ni, NULL, -1);
	if (err) {
		ntfs_error(sb, "Couldn't allocate MFT record");
		goto put_err_out;
	}
	unmap_mft_record(ext_ni);

	/* Move attribute to it. */
	err = ntfs_attr_record_move_to(ctx, ext_ni);
	if (err) {
		ntfs_error(sb, "Couldn't move attribute to new MFT record");
		err = -ENOMEM;
		goto put_err_out;
	}

	err = ntfs_attrlist_update(base_ni);
	if (err < 0)
		goto put_err_out;

	ntfs_attr_put_search_ctx(ctx);
	/* Try to perform resize once again. */
	goto attr_resize_again;

resize_done:
	/*
	 * Set the inode (and its base inode if it exists) dirty so it is
	 * written out later.
	 */
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	return 0;

put_err_out:
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

int __ntfs_attr_truncate_vfs(struct ntfs_inode *ni, const s64 newsize,
		const s64 i_size)
{
	int err = 0;

	if (newsize < 0 ||
	    (ni->mft_no == FILE_MFT && ni->type == AT_DATA)) {
		ntfs_debug("Invalid arguments passed.\n");
		return -EINVAL;
	}

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x, size %lld\n",
			(unsigned long long)ni->mft_no, ni->type, newsize);

	if (NInoNonResident(ni)) {
		if (newsize > i_size) {
			down_write(&ni->runlist.lock);
			err = ntfs_non_resident_attr_expand(
					ni, newsize, 0,
					NVolDisableSparse(ni->vol) ?
					HOLES_NO : HOLES_OK, ni);
			up_write(&ni->runlist.lock);
		} else
			err = ntfs_non_resident_attr_shrink(
					ni, newsize, NULL, true);
	} else
		err = ntfs_resident_attr_resize(ni, newsize, 0,
						NVolDisableSparse(ni->vol) ?
						HOLES_NO : HOLES_OK);
	ntfs_debug("Return status %d\n", err);
	return err;
}

int ntfs_attr_expand_locked(struct ntfs_inode *ni, const s64 newsize,
			    const s64 prealloc_size,
			   struct ntfs_inode *locked_ni)
{
	int err = 0;

	if (newsize < 0 ||
	    (ni->mft_no == FILE_MFT && ni->type == AT_DATA)) {
		ntfs_debug("Invalid arguments passed.\n");
		return -EINVAL;
	}

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x, size %lld\n",
			(unsigned long long)ni->mft_no, ni->type, newsize);

	if (ni->data_size == newsize &&
		(!prealloc_size || prealloc_size <= ni->allocated_size)) {
		ntfs_debug("Size is already ok\n");
		return 0;
	}

	if ((newsize > ni->data_size &&
	     newsize > S64_MAX - ni->vol->cluster_size_mask) ||
	    (prealloc_size > ni->allocated_size &&
	     prealloc_size > S64_MAX - ni->vol->cluster_size_mask))
		return -EFBIG;

	/*
	 * Encrypted attributes are not supported. We return access denied,
	 * which is what Windows NT4 does, too.
	 */
	if (NInoEncrypted(ni)) {
		pr_err("Failed to truncate encrypted attribute\n");
		return -EACCES;
	}

	if (NInoNonResident(ni)) {
		if (newsize > ni->data_size || prealloc_size > ni->allocated_size)
			err = ntfs_non_resident_attr_expand(
					ni, newsize, prealloc_size,
					NVolDisableSparse(ni->vol) ?
					HOLES_NO : HOLES_OK, locked_ni);
	} else
		err = ntfs_resident_attr_resize(ni, newsize, prealloc_size,
						NVolDisableSparse(ni->vol) ?
						HOLES_NO : HOLES_OK);
	if (!err)
		i_size_write(VFS_I(ni), newsize);
	ntfs_debug("Return status %d\n", err);
	return err;
}

int ntfs_attr_expand(struct ntfs_inode *ni, const s64 newsize,
		     const s64 prealloc_size)
{
	return ntfs_attr_expand_locked(ni, newsize, prealloc_size, NULL);
}

/*
 * ntfs_attr_truncate_i - resize an ntfs attribute
 * @ni:		open ntfs inode to resize
 * @newsize:	new size (in bytes) to which to resize the attribute
 * @holes:	how to create a hole if expanding
 *
 * Change the size of an open ntfs attribute @na to @newsize bytes. If the
 * attribute is made bigger and the attribute is resident the newly
 * "allocated" space is cleared and if the attribute is non-resident the
 * newly allocated space is marked as not initialised and no real allocation
 * on disk is performed.
 */
int ntfs_attr_truncate_i_locked(struct ntfs_inode *ni, const s64 newsize,
				unsigned int holes,
			       struct ntfs_inode *locked_ni)
{
	int err;

	if (newsize < 0 ||
	    (ni->mft_no == FILE_MFT && ni->type == AT_DATA)) {
		ntfs_debug("Invalid arguments passed.\n");
		return -EINVAL;
	}

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x, size %lld\n",
			(unsigned long long)ni->mft_no, ni->type, newsize);

	if (ni->data_size == newsize) {
		ntfs_debug("Size is already ok\n");
		return 0;
	}

	/*
	 * Encrypted attributes are not supported. We return access denied,
	 * which is what Windows NT4 does, too.
	 */
	if (NInoEncrypted(ni)) {
		pr_err("Failed to truncate encrypted attribute\n");
		return -EACCES;
	}

	if (NInoCompressed(ni)) {
		pr_err("Failed to truncate compressed attribute\n");
		return -EOPNOTSUPP;
	}

	if (NInoNonResident(ni)) {
		if (newsize > ni->data_size)
			err = ntfs_non_resident_attr_expand(
					ni, newsize, 0, holes, locked_ni);
		else
			err = ntfs_non_resident_attr_shrink(
					ni, newsize, locked_ni, false);
	} else
		err = ntfs_resident_attr_resize(ni, newsize, 0, holes);
	if (!err && NInoAttr(ni))
		i_size_write(VFS_I(ni), newsize);
	ntfs_debug("Return status %d\n", err);
	return err;
}

int ntfs_attr_truncate_i(struct ntfs_inode *ni, const s64 newsize,
			 unsigned int holes)
{
	return ntfs_attr_truncate_i_locked(ni, newsize, holes, NULL);
}

/*
 * Resize an attribute, creating a hole if relevant
 */
int ntfs_attr_truncate(struct ntfs_inode *ni, const s64 newsize)
{
	return ntfs_attr_truncate_i(ni, newsize,
				    NVolDisableSparse(ni->vol) ?
				    HOLES_NO : HOLES_OK);
}

int ntfs_attr_map_cluster(struct ntfs_inode *ni, s64 vcn_start, s64 *lcn_start,
		s64 *lcn_count, s64 max_clu_count, bool *balloc, bool update_mp,
		bool skip_holes, bool low_space)
{
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct ntfs_attr_search_ctx *ctx;
	struct runlist_element *rl, *rlc;
	struct runlist_element *old_rl = NULL;
	s64 vcn = vcn_start, lcn, clu_count;
	s64 lcn_seek_from = -1;
	bool was_delalloc;
	int err = 0;
	size_t new_rl_count, old_rl_count;

	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		ntfs_error(vol->sb, "%s: Failed to get search context", __func__);
		return -ENOMEM;
	}

	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, vcn, NULL, 0, ctx);
	if (err) {
		ntfs_error(vol->sb,
			   "ntfs_attr_lookup failed, ntfs inode(mft_no : %llu) type : 0x%x, err : %d",
			   ni->mft_no, ni->type, err);
		goto out;
	}

	rl = ntfs_attr_find_vcn_nolock(ni, vcn, ctx);
	if (IS_ERR(rl)) {
		ntfs_error(vol->sb, "Failed to find run after mapping runlist.");
		err = PTR_ERR(rl);
		goto out;
	}

	lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
	was_delalloc = lcn == LCN_DELALLOC;
	clu_count = min(max_clu_count, rl->length - (vcn - rl->vcn));
	if (lcn >= LCN_HOLE) {
		if (lcn > LCN_DELALLOC ||
		    (lcn == LCN_HOLE && skip_holes)) {
			*lcn_start = lcn;
			*lcn_count = clu_count;
			*balloc = false;
			goto out;
		}
		if (was_delalloc && clu_count > ni->i_dealloc_clusters) {
			err = -EIO;
			goto out;
		}
	} else {
		WARN_ON(lcn == LCN_RL_NOT_MAPPED);
		if (lcn == LCN_ENOENT)
			err = -ENOENT;
		else
			err = -EIO;
		goto out;
	}

	/* Search backwards to find the best lcn to start seek from. */
	rlc = rl;
	while (rlc->vcn) {
		rlc--;
		if (rlc->lcn >= 0) {
			/*
			 * avoid fragmenting a compressed file
			 * Windows does not do that, and that may
			 * not be desirable for files which can
			 * be updated
			 */
			if (NInoCompressed(ni))
				lcn_seek_from = rlc->lcn + rlc->length;
			else
				lcn_seek_from = rlc->lcn + (vcn - rlc->vcn);
			break;
		}
	}

	if (lcn_seek_from == -1) {
		/* Backwards search failed, search forwards. */
		rlc = rl;
		while (rlc->length) {
			rlc++;
			if (rlc->lcn >= 0) {
				lcn_seek_from = rlc->lcn - (rlc->vcn - vcn);
				if (lcn_seek_from < -1)
					lcn_seek_from = -1;
				break;
			}
		}
	}

	if (low_space)
		rlc = ntfs_cluster_alloc_data_partial(vol, vcn, clu_count,
				lcn_seek_from, was_delalloc);
	else
		rlc = ntfs_cluster_alloc(vol, vcn, clu_count, lcn_seek_from,
				DATA_ZONE, false, true, was_delalloc);
	if (IS_ERR(rlc)) {
		err = PTR_ERR(rlc);
		goto out;
	}

	WARN_ON(rlc->vcn != vcn);
	lcn = rlc->lcn;
	clu_count = rlc->length;
	if (low_space) {
		/* Do not publish a new mapping until its media is zeroed. */
		err = ntfs_dio_zero_range(VFS_I(ni),
				ntfs_cluster_to_bytes(vol, lcn),
				ntfs_cluster_to_bytes(vol, clu_count));
		if (err)
			goto free_alloc;
	}
	old_rl_count = ni->runlist.count;
	old_rl = kmemdup(ni->runlist.rl,
			 old_rl_count * sizeof(*old_rl), GFP_NOFS);
	if (!old_rl) {
		err = -ENOMEM;
		goto free_alloc;
	}

	rl = ntfs_runlists_merge(&ni->runlist, rlc, 0, &new_rl_count);
	if (IS_ERR(rl)) {
		ntfs_error(vol->sb, "Failed to merge runlists");
		err = PTR_ERR(rl);
		goto free_alloc;
	}
	ni->runlist.rl = rl;
	ni->runlist.count = new_rl_count;

	if (!update_mp) {
		u64 free = atomic64_read(&vol->free_clusters) * 100;

		do_div(free, vol->nr_clusters);
		if (free <= 5)
			update_mp = true;
	}

	if (update_mp) {
		ntfs_attr_reinit_search_ctx(ctx);
		err = ntfs_attr_update_mapping_pairs_locked(ni, 0, ni);
		if (err) {
			int err2;

			if (was_delalloc)
				ntfs_hold_dirty_clusters(vol, clu_count);
			err2 = ntfs_cluster_free(ni, vcn, clu_count, ctx);
			if (err2 < 0 || err2 != clu_count) {
				ntfs_error(vol->sb,
					   "Failed to free cluster allocation. Leaving inconsistent metadata.\n");
				NVolSetErrors(vol);
				goto out;
			}

			/*
			 * Restore the runlist before repairing the on-disk
			 * mapping pairs.
			 */
			kvfree(ni->runlist.rl);
			ni->runlist.rl = old_rl;
			ni->runlist.count = old_rl_count;
			old_rl = NULL;
			if (ntfs_attr_update_mapping_pairs_locked(
					ni, 0, ni)) {
				ntfs_error(vol->sb,
					   "Failed to restore mapping pairs after allocation rollback.\n");
				NVolSetErrors(vol);
			}
		}
	} else {
		VFS_I(ni)->i_blocks += clu_count << (vol->cluster_size_bits - 9);
		NInoSetRunlistDirty(ni);
		mark_mft_record_dirty(base_ni);
	}

	*lcn_start = lcn;
	*lcn_count = clu_count;
	*balloc = true;
	if (!err && was_delalloc)
		ni->i_dealloc_clusters -= clu_count;
	goto out;
free_alloc:
	if (was_delalloc)
		ntfs_hold_dirty_clusters(vol, clu_count);
	if (ntfs_cluster_free_from_rl(vol, rlc)) {
		ntfs_error(vol->sb, "Failed to free cluster allocation.");
		NVolSetErrors(vol);
	}
	kvfree(rlc);
out:
	kvfree(old_rl);
	ntfs_attr_put_search_ctx(ctx);
	return err;
}

int ntfs_attr_map_cluster_log_credits(struct ntfs_volume *vol, u64 clusters)
{
	int allocation_credits;
	int mapping_credits;
	int credits;

	if (!vol || !clusters || clusters > S64_MAX)
		return -EINVAL;
	allocation_credits = ntfs_cluster_alloc_log_credits(clusters);
	if (allocation_credits < 0)
		return allocation_credits;
	/* The transacted mapper requests one contiguous run and refuses splits. */
	mapping_credits = ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size, 1, 0);
	if (mapping_credits < 0)
		return mapping_credits;
	if (check_add_overflow(allocation_credits, mapping_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

/* Caller holds mrec_lock and runlist.lock. Inode DELALLOC is consumed here. */
int ntfs_attr_map_cluster_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni, s64 vcn_start, s64 *lcn_start,
		s64 *lcn_count, s64 max_clu_count, bool *balloc,
		bool skip_holes, bool *was_delalloc, s64 zero_clusters)
{
	struct ntfs_volume *vol;
	struct runlist_element *allocated = NULL;
	struct runlist_element *new_rl;
	struct runlist_element *rl;
	struct runlist_element *seek;
	s64 lcn_seek_from = -1;
	s64 clu_count;
	s64 lcn;
	s64 vcn = vcn_start;
	size_t new_rl_count;
	const char *mapping_stage = "extent mapping update";
	int err;

	if (!handle || !ni || !lcn_start || !lcn_count || !balloc ||
	    !was_delalloc ||
	    vcn < 0 || max_clu_count <= 0 || zero_clusters < 0)
		return -EINVAL;
	vol = ni->vol;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	rl = ntfs_rl_find_vcn_nolock(ni->runlist.rl, vcn);
	if (!rl)
		return -EIO;
	lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
	*was_delalloc = lcn == LCN_DELALLOC;
	clu_count = min(max_clu_count, rl->length - (vcn - rl->vcn));
	if (lcn >= LCN_HOLE) {
		if (lcn > LCN_DELALLOC ||
		    (lcn == LCN_HOLE && skip_holes)) {
			*lcn_start = lcn;
			*lcn_count = clu_count;
			*balloc = false;
			return 0;
		}
	} else {
		return lcn == LCN_ENOENT ? -ENOENT : -EIO;
	}
	if (*was_delalloc && clu_count > ni->i_dealloc_clusters) {
		ntfs_error(vol->sb,
			   "Insufficient delayed allocation charge for inode %llu (vcn %lld, clusters %lld, reserved %u).",
			   (unsigned long long)ni->mft_no, vcn, clu_count,
			   ni->i_dealloc_clusters);
		return -EIO;
	}

	seek = rl;
	while (seek != ni->runlist.rl) {
		seek--;
		if (seek->lcn < 0)
			continue;
		lcn_seek_from = NInoCompressed(ni) ?
			seek->lcn + seek->length :
			seek->lcn + (vcn - seek->vcn);
		break;
	}
	if (lcn_seek_from == -1) {
		for (seek = rl; seek->length; seek++) {
			if (seek->lcn < 0)
				continue;
			lcn_seek_from = seek->lcn - (seek->vcn - vcn);
			if (lcn_seek_from < -1)
				lcn_seek_from = -1;
			break;
		}
	}

	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		return err;
	allocated = ntfs_cluster_alloc_transacted_partial(handle, vol, vcn,
			clu_count, 1, lcn_seek_from, DATA_ZONE, false, true,
			*was_delalloc, 0);
	if (IS_ERR(allocated))
		return PTR_ERR(allocated);
	if (allocated->vcn != vcn || allocated->lcn < 0 ||
	    allocated->length <= 0 || allocated->length > clu_count ||
	    allocated[1].length) {
		ntfs_error(vol->sb,
			   "Invalid transacted cluster allocation for inode %llu (vcn %lld, requested %lld, returned vcn %lld, lcn %lld, length %lld).",
			   (unsigned long long)ni->mft_no, vcn, clu_count,
			   allocated->vcn, allocated->lcn, allocated->length);
		kvfree(allocated);
		return -EIO;
	}
	lcn = allocated->lcn;
	clu_count = allocated->length;
	if (zero_clusters) {
		/* Readers must not see the new mapping until zeroing succeeds. */
		err = ntfs_dio_zero_range(VFS_I(ni),
				ntfs_cluster_to_bytes(vol, lcn),
				ntfs_cluster_to_bytes(vol,
					min(zero_clusters, clu_count)));
		if (!err)
			err = ntfs_log_ordered_data(handle);
		if (err) {
			kvfree(allocated);
			return err;
		}
	}
	new_rl = ntfs_runlists_merge(&ni->runlist, allocated, 0,
			&new_rl_count);
	if (IS_ERR(new_rl)) {
		kvfree(allocated);
		return PTR_ERR(new_rl);
	}
	ni->runlist.rl = new_rl;
	ni->runlist.count = new_rl_count;
	ni->runlist.rl_hint = -1;
	/* Undo and the mapping locks must cover the delayed-cluster charge too. */
	if (*was_delalloc)
		ni->i_dealloc_clusters -= clu_count;
	if (NInoSparse(ni) || NInoCompressed(ni))
		ni->itype.compressed.size += ntfs_cluster_to_bytes(vol,
				clu_count);
	VFS_I(ni)->i_blocks += clu_count << (vol->cluster_size_bits - 9);
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
	/* The tail updater only rewrites the last extent. A filled hole may be earlier. */
	if (!err) {
		mapping_stage = "non-tail mapping update";
		err = ntfs_attr_update_non_tail_mapping_pairs_transacted(handle,
				ni);
	}
	if (err) {
		ntfs_error(vol->sb,
			   "Failed to journal mapping pairs during %s for inode %llu attr 0x%x (vcn %lld, clusters %lld, attribute list %d, error %d).",
			   mapping_stage, (unsigned long long)ni->mft_no,
			   le32_to_cpu(ni->type), vcn, clu_count,
			   !!NInoAttrList(ni), err);
		return err;
	}
	NInoClearRunlistDirty(ni);
	*lcn_start = lcn;
	*lcn_count = clu_count;
	*balloc = true;
	return 0;
}

/*
 * ntfs_attr_rm - remove attribute from ntfs inode
 * @ni:		opened ntfs attribute to delete
 *
 * Remove attribute and all it's extents from ntfs inode. If attribute was non
 * resident also free all clusters allocated by attribute.
 */
static int __ntfs_attr_rm(struct ntfs_log_handle *log_handle,
		struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *ctx;
	struct runlist_element *rl;
	bool has_compressed_size;
	int err = 0, ret = 0;
	struct ntfs_inode *base_ni;
	struct super_block *sb = ni->vol->sb;

	base_ni = ntfs_base_inode(ni);
	if (log_handle && NInoAttrList(base_ni))
		return -EOPNOTSUPP;
	if (log_handle && NInoNonResident(ni)) {
		has_compressed_size = NInoCompressed(ni) || NInoSparse(ni);
		if ((NInoEncrypted(ni) && !ntfs_attr_deleted_encrypted(ni)) ||
		    ni->allocated_size || ni->data_size ||
		    ni->initialized_size || ni->zeroed_size ||
		    (has_compressed_size && ni->itype.compressed.size) ||
		    i_size_read(VFS_I(ni)))
			return -EOPNOTSUPP;
		err = ntfs_attr_map_whole_runlist(ni);
		if (err)
			return err;
		down_read(&ni->runlist.lock);
		rl = ni->runlist.rl;
		if (!rl || ni->runlist.count != 1 || rl->vcn || rl->length ||
		    rl->lcn != LCN_ENOENT)
			err = -EIO;
		up_read(&ni->runlist.lock);
		if (err)
			return err;
	}

	ntfs_debug("Entering for inode 0x%llx, attr 0x%x.\n",
			(long long) ni->mft_no, ni->type);

	/* Free cluster allocation. */
	if (NInoNonResident(ni) && !log_handle) {
		struct ntfs_attr_search_ctx *ctx;

		err = ntfs_attr_map_whole_runlist(ni);
		if (err)
			return err;
		ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
		if (!ctx) {
			ntfs_error(sb, "%s: Failed to get search context", __func__);
			return -ENOMEM;
		}

		ret = ntfs_cluster_free(ni, 0, -1, ctx);
		if (ret < 0)
			ntfs_error(sb,
				"Failed to free cluster allocation. Leaving inconstant metadata.\n");
		else
			ret = 0;
		ntfs_attr_put_search_ctx(ctx);
	}

	/* Search for attribute extents and remove them all. */
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		ntfs_error(sb, "%s: Failed to get search context", __func__);
		return -ENOMEM;
	}
	while (!(err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, 0, NULL, 0, ctx))) {
		if (log_handle && ctx->attr->non_resident &&
		    (!NInoNonResident(ni) ||
		     ctx->attr->data.non_resident.lowest_vcn ||
		     le64_to_cpu(ctx->attr->data.non_resident.highest_vcn) != -1 ||
		     ctx->attr->data.non_resident.allocated_size ||
		     ctx->attr->data.non_resident.data_size ||
		     ctx->attr->data.non_resident.initialized_size)) {
			err = -EOPNOTSUPP;
			ret = err;
			break;
		}
		err = __ntfs_attr_record_rm(log_handle, ctx);
		if (err) {
			ntfs_error(sb,
				"Failed to remove attribute extent. Leaving inconstant metadata.\n");
			ret = err;
			if (log_handle)
				break;
		}
		ntfs_attr_reinit_search_ctx(ctx);
	}
	ntfs_attr_put_search_ctx(ctx);
	if (err != -ENOENT) {
		ntfs_error(sb, "Attribute lookup failed. Probably leaving inconstant metadata.\n");
		ret = err;
	}

	return ret;
}

int ntfs_attr_rm(struct ntfs_inode *ni)
{
	return __ntfs_attr_rm(NULL, ni);
}

int ntfs_attr_rm_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	if (!handle)
		return -EINVAL;
	return __ntfs_attr_rm(handle, ni);
}

int ntfs_attr_rm_empty_log_credits(struct ntfs_volume *vol,
		bool has_attr_list, bool nonresident_attr_list)
{
	u64 max_clusters;
	int attr_credits;
	int cluster_credits;
	int delete_credits;
	int free_credits;
	int list_credits;
	int credits;

	if (!vol || !vol->journal)
		return -EROFS;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	delete_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, 0);
	if (delete_credits < 0)
		return delete_credits;
	if (!has_attr_list)
		return delete_credits;
	attr_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, vol->mft_record_size);
	if (attr_credits < 0)
		return attr_credits;
	list_credits = ntfs_attrlist_nonresident_log_credits(vol);
	if (list_credits < 0)
		return list_credits;
	list_credits = max(list_credits, attr_credits);
	free_credits = ntfs_mft_record_free_credits(vol);
	if (free_credits < 0)
		return free_credits;
	if (check_add_overflow(delete_credits, list_credits, &credits) ||
	    check_add_overflow(credits, free_credits, &credits) ||
	    check_add_overflow(credits, delete_credits, &credits))
		return -EOVERFLOW;
	if (nonresident_attr_list) {
		if (!vol->cluster_size)
			return -EINVAL;
		max_clusters = DIV_ROUND_UP_ULL(256 * 1024,
				vol->cluster_size);
		if (max_clusters > S64_MAX)
			return -E2BIG;
		cluster_credits = ntfs_cluster_free_log_credits(max_clusters);
		if (cluster_credits < 0)
			return cluster_credits;
		if (check_add_overflow(credits, cluster_credits, &credits))
			return -EOVERFLOW;
	}
	return credits;
}

/*
 * Remove a fully reclaimed nonresident attribute while retaining enough home
 * state to undo a failed runtime transaction.  Attribute-list and empty MFT
 * record retirement require their own allocator transactions.
 */
int ntfs_attr_rm_empty_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *empty_ni = NULL;
	struct ntfs_inode *base_ni;
	struct runlist_element *rl;
	struct attr_record *attr;
	bool has_compressed_size;
	bool listed;
	u32 attr_len;
	u32 attrs_off;
	u32 used;
	u16 record_off;
	ptrdiff_t offset;
	int need;
	int err;

	if (!handle || !ni)
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EIO;
	listed = NInoAttrList(base_ni);
	has_compressed_size = NInoCompressed(ni) || NInoSparse(ni);
	if (!NInoNonResident(ni) ||
	    (NInoEncrypted(ni) && !ntfs_attr_deleted_encrypted(ni)) ||
	    ni->allocated_size || ni->data_size || ni->initialized_size ||
	    ni->zeroed_size ||
	    (has_compressed_size && ni->itype.compressed.size) ||
	    i_size_read(VFS_I(ni)))
		return -EOPNOTSUPP;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	down_read(&ni->runlist.lock);
	rl = ni->runlist.rl;
	if (!rl || ni->runlist.count != 1 || rl->vcn || rl->length ||
	    rl->lcn != LCN_ENOENT)
		err = -EIO;
	up_read(&ni->runlist.lock);
	if (err)
		return err;
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err)
		goto out;
	attr = ctx->attr;
	attr_len = le32_to_cpu(attr->length);
	attrs_off = le16_to_cpu(ctx->mrec->attrs_offset);
	used = le32_to_cpu(ctx->mrec->bytes_in_use);
	offset = (u8 *)attr - (u8 *)ctx->mrec;
	has_compressed_size = attr->flags &
			(ATTR_IS_COMPRESSED | ATTR_IS_SPARSE);
	if (!attr->non_resident ||
	    le64_to_cpu(attr->data.non_resident.lowest_vcn) ||
	    le64_to_cpu(attr->data.non_resident.highest_vcn) != -1 ||
	    !ntfs_attr_record_flags_match(ni, attr) ||
	    (has_compressed_size &&
	     attr->data.non_resident.compressed_size)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	if (offset < 0 || offset > U16_MAX || attr_len > U16_MAX) {
		err = -EIO;
		goto out;
	}
	record_off = offset;
	if (record_off > used || attr_len > used - record_off ||
	    attrs_off > used - attr_len) {
		err = -EIO;
		goto out;
	}
	if (!listed && used - attr_len - attrs_off == 8) {
		err = -EOPNOTSUPP;
		goto out;
	}
	if (listed) {
		err = ntfs_attr_extent_remove_transacted(handle, ctx, &empty_ni);
		if (!err) {
			need = ntfs_attrlist_need(base_ni);
			if (need < 0)
				err = need;
			else if (!need) {
				if (NInoAttrListNonResident(base_ni))
					err =
					ntfs_attrlist_remove_nonresident_transacted(
						handle, base_ni);
				else
					err =
					ntfs_attrlist_remove_resident_transacted(
						handle, base_ni);
			}
		}
		goto out;
	}
	err = ntfs_attr_mft_register_home_undo(handle, ctx->ntfs_ino,
			ctx->mrec);
out:
	ntfs_attr_put_search_ctx(ctx);
	if (err)
		return err;
	if (empty_ni)
		return ntfs_mft_record_free_transacted(handle, empty_ni);
	if (listed)
		return 0;
	return __ntfs_attr_rm(handle, ni);
}

static int ntfs_attr_stream_free_log_credits(struct ntfs_inode *ni,
		bool packed)
{
	const struct runlist_element *rl;
	s64 expected = 0;
	s64 next;
	size_t i;
	int credits = 0;
	int extra;
	int err;

	if (!NInoNonResident(ni))
		return 0;
	if (ni->allocated_size < 0 ||
	    !IS_ALIGNED(ni->allocated_size, ni->vol->cluster_size))
		return -EIO;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	down_read(&ni->runlist.lock);
	rl = ni->runlist.rl;
	if (!rl || !ni->runlist.count) {
		err = -EIO;
		goto out;
	}
	for (i = 0; i < ni->runlist.count; i++) {
		if (rl[i].vcn != expected) {
			err = -EIO;
			goto out;
		}
		if (!rl[i].length) {
			if (rl[i].lcn != LCN_ENOENT ||
			    expected != ni->allocated_size >>
					ni->vol->cluster_size_bits)
				err = -EIO;
			goto out;
		}
		if (rl[i].length < 0 ||
		    check_add_overflow(expected, rl[i].length, &next)) {
			err = -EIO;
			goto out;
		}
		expected = next;
		if (rl[i].lcn == LCN_HOLE)
			continue;
		if (rl[i].lcn < 0 || rl[i].length > ni->vol->nr_clusters ||
		    rl[i].lcn > ni->vol->nr_clusters - rl[i].length) {
			err = -EIO;
			goto out;
		}
		extra = ntfs_log_bitmap_update_credits(rl[i].lcn, rl[i].length);
		if (extra < 0) {
			err = extra;
			goto out;
		}
		if (!credits)
			credits = 1;
		if (check_add_overflow(credits, extra - 1, &credits)) {
			err = -EOVERFLOW;
			goto out;
		}
	}
	err = -EIO;
out:
	up_read(&ni->runlist.lock);
	if (!err && packed && credits)
		return ntfs_log_bitmap_packed_credits(ni->vol, credits - 1);
	return err ? err : credits;
}

static int ntfs_attrlist_needed_after_stream_rm(struct ntfs_inode *base_ni,
		struct ntfs_inode *ni)
{
	struct attr_list_entry *entry;
	u32 entry_len;
	u32 name_bytes;
	u32 remaining;
	u8 *pos;
	u8 *end;

	if (!base_ni->attr_list || !base_ni->attr_list_size)
		return -EIO;
	pos = base_ni->attr_list;
	end = pos + base_ni->attr_list_size;
	while (pos < end) {
		entry = (struct attr_list_entry *)pos;
		remaining = end - pos;
		if (remaining < sizeof(*entry))
			return -EIO;
		entry_len = le16_to_cpu(entry->length);
		name_bytes = entry->name_length * sizeof(__le16);
		if (entry_len < sizeof(*entry) || !IS_ALIGNED(entry_len, 8) ||
		    entry_len > remaining || entry->name_offset > entry_len ||
		    (entry->name_length && entry->name_offset <
			    offsetof(struct attr_list_entry, name)) ||
		    name_bytes > entry_len - entry->name_offset)
			return -EIO;
		if (MREF_LE(entry->mft_reference) != base_ni->mft_no &&
		    (entry->type != ni->type ||
		     entry->name_length != ni->name_len ||
		     memcmp(pos + entry->name_offset, ni->name, name_bytes)))
			return 1;
		pos += entry_len;
	}
	return 0;
}

/*
 * The base inode's MFT lock serializes changes to the stream and attribute
 * list while this bound is calculated. Recheck it after reserving the log.
 */
int ntfs_attr_rm_stream_log_credits(struct ntfs_inode *ni)
{
	struct ntfs_inode *base_ni;
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_volume *vol;
	int delete_credits;
	int list_credits = 0;
	int free_credits = 0;
	int extent_credits;
	int cleanup_credits = 0;
	int bitmap_credits;
	int list_needed;
	int extents = 0;
	int credits;
	int shared_credits;
	int err;

	if (!ni || !ntfs_inode_is_named_stream(ni))
		return -EINVAL;
	base_ni = ntfs_base_inode(ni);
	vol = ni->vol;
	lockdep_assert_held(&base_ni->mrec_lock);
	if (!vol->journal)
		return -EROFS;
	if (vol->mft_record_size > U16_MAX)
		return -E2BIG;
	bitmap_credits = ntfs_attr_stream_free_log_credits(ni, true);
	if (bitmap_credits < 0)
		return bitmap_credits;
	delete_credits = ntfs_log_mft_attribute_credits(vol,
			vol->mft_record_size, 0);
	if (delete_credits < 0)
		return delete_credits;
	if (NInoAttrList(base_ni)) {
		list_credits = ntfs_attrlist_shrink_log_credits(vol,
				base_ni->attr_list_size);
		if (list_credits < 0)
			return list_credits;
		free_credits = ntfs_mft_record_free_credits(vol);
		if (free_credits < 0)
			return free_credits;
		list_needed = ntfs_attrlist_needed_after_stream_rm(base_ni, ni);
		if (list_needed < 0)
			return list_needed;
		if (!list_needed) {
			cleanup_credits = delete_credits;
			if (NInoAttrListNonResident(base_ni)) {
				struct inode *list_vi;

				list_vi = ntfs_attr_iget(VFS_I(base_ni),
						AT_ATTRIBUTE_LIST, AT_UNNAMED, 0);
				if (IS_ERR(list_vi))
					return PTR_ERR(list_vi);
				err = ntfs_attr_stream_free_log_credits(
						NTFS_I(list_vi), false);
				iput(list_vi);
				if (err < 0)
					return err;
				if (check_add_overflow(cleanup_credits, err,
						&cleanup_credits))
					return -EOVERFLOW;
			}
		}
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx)
		return -ENOMEM;
	while (!(err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx))) {
		if (!!ctx->attr->non_resident != !!NInoNonResident(ni) ||
		    extents == INT_MAX) {
			err = -EIO;
			break;
		}
		extents++;
	}
	ntfs_attr_put_search_ctx(ctx);
	if (err != -ENOENT)
		return err;
	if (!extents)
		return -ENOENT;
	if (!NInoAttrList(base_ni) && extents != 1)
		return -EIO;
	if (check_add_overflow(delete_credits, list_credits,
			&extent_credits) ||
	    check_add_overflow(extent_credits, free_credits,
			&extent_credits) ||
	    check_mul_overflow(extent_credits, extents, &credits))
		return -EOVERFLOW;
	if (NInoAttrList(base_ni)) {
		/*
		 * Each extent budget includes an open of $MFT:$DATA for the
		 * deletion, list update and record free, and an open of
		 * $MFT:$BITMAP for the free.  Opens remain cached for the
		 * lifetime of this transaction.
		 */
		if (check_mul_overflow(extents, 4, &shared_credits) ||
		    credits < shared_credits - 2)
			return -EOVERFLOW;
		credits -= shared_credits - 2;
	}
	if (check_add_overflow(credits, cleanup_credits, &credits) ||
	    check_add_overflow(credits, bitmap_credits, &credits))
		return -EOVERFLOW;
	return credits;
}

/*
 * Remove every stream extent and free its clusters in the same transaction.
 * The caller has reserved credits and holds the base inode's MFT lock.
 */
int ntfs_attr_rm_stream_transacted(struct ntfs_log_handle *handle,
		struct ntfs_inode *ni)
{
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_inode *base_ni;
	struct ntfs_inode *empty_ni;
	struct runlist_element *runs = NULL;
	size_t bytes;
	bool listed;
	int err;
	int need;
	int removed = 0;

	if (!handle || !ni || !ntfs_inode_is_named_stream(ni))
		return -EINVAL;
	base_ni = ntfs_base_inode(ni);
	lockdep_assert_held(&base_ni->mrec_lock);
	listed = NInoAttrList(base_ni);
	if (NInoNonResident(ni)) {
		err = ntfs_attr_map_whole_runlist(ni);
		if (err)
			return err;
		down_read(&ni->runlist.lock);
		if (!ni->runlist.rl || !ni->runlist.count ||
		    check_mul_overflow(ni->runlist.count, sizeof(*runs), &bytes)) {
			err = -EIO;
		} else {
			runs = kvmalloc(bytes, GFP_NOFS);
			if (!runs)
				err = -ENOMEM;
			else {
				memcpy(runs, ni->runlist.rl, bytes);
				err = 0;
			}
		}
		up_read(&ni->runlist.lock);
		if (err)
			return err;
		err = ntfs_cluster_free_from_rl_packed(handle, ni->vol, runs);
		kvfree(runs);
		if (err)
			return err;
	}
	for (;;) {
		ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
		if (!ctx)
			return -ENOMEM;
		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, S64_MAX, NULL, 0, ctx);
		if (err) {
			ntfs_attr_put_search_ctx(ctx);
			if (err == -ENOENT && removed)
				break;
			return err;
		}
		empty_ni = NULL;
		if (listed)
			err = ntfs_attr_extent_remove_transacted(handle, ctx,
					&empty_ni);
		else
			err = ntfs_attr_record_rm_transacted(handle, ctx);
		ntfs_attr_put_search_ctx(ctx);
		if (err)
			return err;
		if (empty_ni) {
			err = ntfs_mft_record_free_transacted(handle, empty_ni);
			if (err)
				return err;
		}
		removed++;
	}
	if (!listed)
		return 0;
	need = ntfs_attrlist_need(base_ni);
	if (need < 0)
		return need;
	if (need)
		return 0;
	if (NInoAttrListNonResident(base_ni))
		return ntfs_attrlist_remove_nonresident_transacted(handle, base_ni);
	return ntfs_attrlist_remove_resident_transacted(handle, base_ni);
}

int ntfs_attr_exist(struct ntfs_inode *ni, const __le32 type, __le16 *name,
		u32 name_len)
{
	struct ntfs_attr_search_ctx *ctx;
	u32 ic;
	int ret;

	ntfs_debug("Entering\n");

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		ntfs_error(ni->vol->sb, "%s: Failed to get search context",
				__func__);
		return 0;
	}

	ic = type == AT_DATA && name_len ? IGNORE_CASE : CASE_SENSITIVE;
	ret = ntfs_attr_lookup(type, name, name_len, ic,
			0, NULL, 0, ctx);
	ntfs_attr_put_search_ctx(ctx);

	return !ret;
}

/*
 * If @attr_vi is non-NULL, the attribute inode reference is returned to the
 * caller, which must release it after dropping ni->mrec_lock.
 */
int ntfs_attr_remove(struct ntfs_inode *ni, const __le32 type, __le16 *name,
		u32 name_len, struct inode **attr_vi)
{
	int err;
	struct inode *vi;
	struct ntfs_inode *attr_ni;

	ntfs_debug("Entering\n");

	if (attr_vi)
		*attr_vi = NULL;
	if (!ni)
		return -EINVAL;

	vi = ntfs_attr_iget(VFS_I(ni), type, name, name_len);
	if (IS_ERR(vi)) {
		err = PTR_ERR(vi);
		ntfs_error(ni->vol->sb, "Failed to open attribute 0x%02x of inode 0x%llx",
				type, (unsigned long long)ni->mft_no);
		return err;
	}
	attr_ni = NTFS_I(vi);

	err = ntfs_attr_rm(attr_ni);
	if (err) {
		ntfs_error(ni->vol->sb, "Failed to remove attribute 0x%02x of inode 0x%llx",
				type, (unsigned long long)ni->mft_no);
	} else {
		NInoClearDirty(attr_ni);
		clear_nlink(vi);
		remove_inode_hash(vi);
	}
	if (attr_vi)
		*attr_vi = vi;
	else
		iput(vi);
	return err;
}

/*
 * ntfs_attr_readall - read the entire data from an ntfs attribute
 * @ni:		open ntfs inode in which the ntfs attribute resides
 * @type:	attribute type
 * @name:	attribute name in little endian Unicode or AT_UNNAMED or NULL
 * @name_len:	length of attribute @name in Unicode characters (if @name given)
 * @data_size:	if non-NULL then store here the data size
 *
 * This function will read the entire content of an ntfs attribute.
 * If @name is AT_UNNAMED then look specifically for an unnamed attribute.
 * If @name is NULL then the attribute could be either named or not.
 * In both those cases @name_len is not used at all.
 *
 * On success a buffer is allocated with the content of the attribute
 * and which needs to be freed when it's not needed anymore. If the
 * @data_size parameter is non-NULL then the data size is set there.
 * On error, an ERR_PTR() containing the negative error code is returned.
 */
void *ntfs_attr_readall(struct ntfs_inode *ni, const __le32 type,
		__le16 *name, u32 name_len, s64 *data_size)
{
	struct ntfs_inode *bmp_ni;
	struct inode *bmp_vi;
	void *data, *ret = NULL;
	s64 size;
	struct super_block *sb = ni->vol->sb;

	ntfs_debug("Entering\n");

	bmp_vi = ntfs_attr_iget(VFS_I(ni), type, name, name_len);
	if (IS_ERR(bmp_vi)) {
		ret = ERR_PTR(PTR_ERR(bmp_vi));
		ntfs_debug("ntfs_attr_iget failed");
		goto err_exit;
	}
	bmp_ni = NTFS_I(bmp_vi);

	if (bmp_ni->data_size > NTFS_ATTR_READALL_MAX_SIZE &&
		(bmp_ni->type != AT_BITMAP ||
		bmp_ni->data_size > ((ni->vol->nr_clusters + 7) >> 3))) {
		ntfs_error(sb, "Invalid attribute data size");
		ret = ERR_PTR(-EIO);
		goto out;
	}

	data = kvmalloc(bmp_ni->data_size, GFP_NOFS);
	if (!data) {
		ret = ERR_PTR(-ENOMEM);
		goto out;
	}

	size = ntfs_inode_attr_pread(VFS_I(bmp_ni), 0, bmp_ni->data_size,
			(u8 *)data);
	if (size != bmp_ni->data_size) {
		ntfs_error(sb, "ntfs_attr_pread failed");
		ret = size < 0 ? ERR_PTR((int)size) : ERR_PTR(-EIO);
		kvfree(data);
		goto out;
	}
	ret = data;
	if (data_size)
		*data_size = size;
out:
	iput(bmp_vi);
err_exit:
	ntfs_debug("\n");
	return ret;
}

int ntfs_attr_range_update_log_credits(struct ntfs_volume *vol,
		u64 clusters, bool alloc_clusters, bool free_clusters)
{
	int credits;
	int extra;

	if (!vol || !clusters || clusters > S64_MAX)
		return -EINVAL;
	credits = ntfs_attr_update_mapping_pairs_log_credits(vol,
			vol->mft_record_size, vol->mft_record_size,
			clusters, clusters);
	if (credits < 0)
		return credits;
	if (alloc_clusters) {
		extra = ntfs_cluster_alloc_log_credits(clusters);
		if (extra < 0)
			return extra;
		if (check_add_overflow(credits, extra, &credits))
			return -EOVERFLOW;
	}
	if (free_clusters) {
		extra = ntfs_cluster_free_log_credits(clusters);
		if (extra < 0)
			return extra;
		if (check_add_overflow(credits, extra, &credits))
			return -EOVERFLOW;
	}
	return credits;
}

static int ntfs_attr_mapping_extent_count(struct ntfs_inode *ni, u64 *count)
{
	struct ntfs_inode *base_ni;
	const struct attr_list_entry *entry;
	const u8 *entry_bytes;
	const u8 *al_end;
	u64 nr_extents = 0;

	if (!ni || !count)
		return -EINVAL;
	base_ni = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	if (!base_ni)
		return -EINVAL;
	if (!NInoAttrList(base_ni)) {
		*count = 1;
		return 0;
	}
	if (!base_ni->attr_list || !base_ni->attr_list_size ||
	    !ntfs_attr_list_is_valid(base_ni->attr_list,
		    base_ni->attr_list_size))
		return -EIO;

	entry_bytes = base_ni->attr_list;
	al_end = entry_bytes + base_ni->attr_list_size;
	while (entry_bytes < al_end) {
		entry = (const struct attr_list_entry *)entry_bytes;
		if (entry->type == ni->type &&
		    entry->name_length == ni->name_len &&
		    (!ni->name_len ||
		     ntfs_are_names_equal((__le16 *)(entry_bytes +
			     entry->name_offset), entry->name_length, ni->name,
			     ni->name_len, CASE_SENSITIVE, ni->vol->upcase,
			     ni->vol->upcase_len)))
			nr_extents++;
		entry_bytes += le16_to_cpu(entry->length);
	}
	if (!nr_extents)
		return -EIO;
	*count = nr_extents;
	return 0;
}

int ntfs_attr_range_update_log_credits_for_inode(struct ntfs_inode *ni,
		u64 clusters, bool alloc_clusters, bool free_clusters)
{
	u64 extent_count;
	u64 extra;
	u64 total;
	int mapping_credits;
	int credits;
	int err;

	if (!ni)
		return -EINVAL;
	credits = ntfs_attr_range_update_log_credits(ni->vol, clusters,
			alloc_clusters, free_clusters);
	if (credits < 0)
		return credits;
	err = ntfs_attr_mapping_extent_count(ni, &extent_count);
	if (err)
		return err;
	if (extent_count <= 1)
		return credits;
	mapping_credits = ntfs_log_mft_mapping_pairs_credits(ni->vol,
			ni->vol->mft_record_size, ni->vol->mft_record_size);
	if (mapping_credits < 0)
		return mapping_credits;
	if (check_mul_overflow(extent_count - 1,
			(u64)mapping_credits, &extra) ||
	    check_add_overflow((u64)credits, extra, &total) ||
	    total > INT_MAX)
		return -EOVERFLOW;
	return total;
}

int ntfs_non_resident_attr_insert_range_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		s64 start_vcn, s64 len)
{
	struct ntfs_volume *vol;
	struct runlist_element *hole_rl;
	struct runlist_element *new_rl;
	s64 end_vcn;
	s64 range_bytes;
	size_t new_rl_count;
	int err;

	if (!handle || !ni || start_vcn < 0 || len <= 0 || NInoAttr(ni) ||
	    ni->type != AT_DATA || !NInoNonResident(ni))
		return -EINVAL;
	vol = ni->vol;
	if (check_add_overflow(start_vcn, len, &end_vcn) ||
	    check_shl_overflow(len, vol->cluster_size_bits, &range_bytes) ||
	    start_vcn > ntfs_bytes_to_cluster(vol, ni->allocated_size) ||
	    ni->allocated_size < 0 || ni->data_size < 0 ||
	    ni->allocated_size > S64_MAX - range_bytes ||
	    ni->data_size > S64_MAX - range_bytes ||
	    (ntfs_cluster_to_bytes(vol, start_vcn) < ni->initialized_size &&
	     ni->initialized_size > S64_MAX - range_bytes))
		return -EINVAL;
	hole_rl = kmalloc_array(2, sizeof(*hole_rl), GFP_NOFS);
	if (!hole_rl)
		return -ENOMEM;
	hole_rl[0].vcn = start_vcn;
	hole_rl[0].lcn = LCN_HOLE;
	hole_rl[0].length = len;
	hole_rl[1].vcn = end_vcn;
	hole_rl[1].lcn = LCN_ENOENT;
	hole_rl[1].length = 0;

	down_write(&ni->runlist.lock);
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		goto out_unlock;
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		goto out_unlock;
	new_rl = ntfs_rl_insert_range(ni->runlist.rl, ni->runlist.count,
			hole_rl, 1, &new_rl_count);
	if (IS_ERR(new_rl)) {
		err = PTR_ERR(new_rl);
		goto out_unlock;
	}
	hole_rl = NULL;
	ni->runlist.rl = new_rl;
	ni->runlist.count = new_rl_count;
	ni->runlist.rl_hint = -1;
	ni->allocated_size += range_bytes;
	ni->data_size += range_bytes;
	if (ntfs_cluster_to_bytes(vol, start_vcn) < ni->initialized_size) {
		ni->initialized_size += range_bytes;
		ni->zeroed_size = ni->initialized_size;
	}
	i_size_write(VFS_I(ni), ni->data_size);
	NInoSetFileNameDirty(ni);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
	if (!err)
		err = ntfs_attr_update_non_tail_mapping_pairs_transacted(handle, ni);
out_unlock:
	up_write(&ni->runlist.lock);
	kfree(hole_rl);
	return err;
}

int ntfs_non_resident_attr_punch_hole_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		s64 start_vcn, s64 len)
{
	struct ntfs_volume *vol;
	struct runlist_element *punch_rl = NULL;
	struct runlist_element *new_rl;
	struct runlist_element *rl;
	s64 freed_bytes;
	s64 end_vcn;
	s64 freed = 0;
	size_t new_rl_count;
	int run_count = 0;
	int i;
	int err;

	if (!handle || !ni || start_vcn < 0 || len <= 0 || NInoAttr(ni) ||
	    ni->type != AT_DATA || !NInoNonResident(ni))
		return -EINVAL;
	vol = ni->vol;
	end_vcn = ntfs_bytes_to_cluster(vol, ni->allocated_size);
	if (start_vcn >= end_vcn)
		return -EINVAL;
	down_write(&ni->runlist.lock);
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		goto out_unlock;
	for (rl = ni->runlist.rl; rl && rl->length; rl++)
		run_count++;
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		goto out_unlock;
	len = min(len, end_vcn - start_vcn);
	new_rl = ntfs_rl_punch_hole(ni->runlist.rl, run_count + 1,
			start_vcn, len, &punch_rl, &new_rl_count);
	if (IS_ERR(new_rl)) {
		err = PTR_ERR(new_rl);
		goto out_unlock;
	}
	ni->runlist.rl = new_rl;
	ni->runlist.count = new_rl_count;
	ni->runlist.rl_hint = -1;
	for (i = 0; punch_rl && punch_rl[i].length; i++)
		if (punch_rl[i].lcn >= 0) {
			if (freed > S64_MAX - punch_rl[i].length) {
				err = -EOVERFLOW;
				goto out_unlock;
			}
			freed += punch_rl[i].length;
		}
	if (check_shl_overflow(freed, vol->cluster_size_bits,
			&freed_bytes) ||
	    ((NInoSparse(ni) || NInoCompressed(ni)) &&
	     ni->itype.compressed.size < freed_bytes) ||
	    (freed_bytes >> 9) > VFS_I(ni)->i_blocks) {
		err = -EIO;
		goto out_unlock;
	}
	if (NInoSparse(ni) || NInoCompressed(ni))
		ni->itype.compressed.size -= freed_bytes;
	VFS_I(ni)->i_blocks -= freed_bytes >> 9;
	NInoSetFileNameDirty(ni);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
	if (!err)
		err = ntfs_attr_update_non_tail_mapping_pairs_transacted(handle, ni);
	if (!err)
		err = ntfs_cluster_free_from_rl_transacted(handle, vol, punch_rl);
out_unlock:
	up_write(&ni->runlist.lock);
	kvfree(punch_rl);
	return err;
}

int ntfs_non_resident_attr_collapse_range_transacted(
		struct ntfs_log_handle *handle, struct ntfs_inode *ni,
		s64 start_vcn, s64 len)
{
	struct ntfs_volume *vol;
	struct runlist_element *punch_rl = NULL;
	struct runlist_element *new_rl;
	struct runlist_element *rl;
	s64 range_bytes;
	s64 freed_bytes;
	s64 end_vcn;
	s64 freed = 0;
	size_t new_rl_count;
	int run_count = 0;
	int i;
	int err;

	if (!handle || !ni || start_vcn < 0 || len <= 0 || NInoAttr(ni) ||
	    ni->type != AT_DATA || !NInoNonResident(ni))
		return -EINVAL;
	vol = ni->vol;
	end_vcn = ntfs_bytes_to_cluster(vol, ni->allocated_size);
	if (check_shl_overflow(len, vol->cluster_size_bits, &range_bytes) ||
	    start_vcn >= end_vcn || len > end_vcn - start_vcn ||
	    ni->allocated_size < range_bytes)
		return -EINVAL;
	down_write(&ni->runlist.lock);
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		goto out_unlock;
	for (rl = ni->runlist.rl; rl && rl->length; rl++)
		run_count++;
	len = min(len, end_vcn - start_vcn);
	err = ntfs_attr_allocation_register_home_undo(handle, ni);
	if (err)
		goto out_unlock;
	new_rl = ntfs_rl_collapse_range(ni->runlist.rl, run_count + 1,
			start_vcn, len, &punch_rl, &new_rl_count);
	if (IS_ERR(new_rl)) {
		err = PTR_ERR(new_rl);
		goto out_unlock;
	}
	ni->runlist.rl = new_rl;
	ni->runlist.count = new_rl_count;
	ni->runlist.rl_hint = -1;
	ni->allocated_size -= range_bytes;
	if (ni->data_size > ntfs_cluster_to_bytes(vol, start_vcn))
		ni->data_size = max_t(s64,
				ntfs_cluster_to_bytes(vol, start_vcn),
				ni->data_size - ntfs_cluster_to_bytes(vol, len));
	if (ni->initialized_size > ntfs_cluster_to_bytes(vol, start_vcn)) {
		ni->initialized_size = max_t(s64,
				ntfs_cluster_to_bytes(vol, start_vcn),
				ni->initialized_size - ntfs_cluster_to_bytes(vol, len));
		ni->zeroed_size = ni->initialized_size;
	}
	for (i = 0; punch_rl && punch_rl[i].length; i++)
		if (punch_rl[i].lcn >= 0) {
			if (freed > S64_MAX - punch_rl[i].length) {
				err = -EOVERFLOW;
				goto out_unlock;
			}
			freed += punch_rl[i].length;
		}
	if (check_shl_overflow(freed, vol->cluster_size_bits,
			&freed_bytes) ||
	    ((NInoSparse(ni) || NInoCompressed(ni)) &&
	     ni->itype.compressed.size < freed_bytes) ||
	    (freed_bytes >> 9) > VFS_I(ni)->i_blocks) {
		err = -EIO;
		goto out_unlock;
	}
	if (NInoSparse(ni) || NInoCompressed(ni))
		ni->itype.compressed.size -= freed_bytes;
	VFS_I(ni)->i_blocks -= freed_bytes >> 9;
	i_size_write(VFS_I(ni), ni->data_size);
	NInoSetFileNameDirty(ni);
	err = ntfs_attr_update_mapping_pairs_transacted(handle, ni);
	if (!err)
		err = ntfs_attr_update_non_tail_mapping_pairs_transacted(handle, ni);
	if (!err)
		err = ntfs_cluster_free_from_rl_transacted(handle, vol, punch_rl);
out_unlock:
	up_write(&ni->runlist.lock);
	kvfree(punch_rl);
	return err;
}

int ntfs_non_resident_attr_insert_range(struct ntfs_inode *ni, s64 start_vcn, s64 len)
{
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct runlist_element *hole_rl, *rl;
	struct ntfs_attr_search_ctx *ctx;
	int ret;
	size_t new_rl_count;

	if (ni->type != AT_DATA)
		return -EOPNOTSUPP;
	if (start_vcn > ntfs_bytes_to_cluster(vol, ni->allocated_size))
		return -EINVAL;

	hole_rl = kmalloc(sizeof(*hole_rl) * 2, GFP_NOFS);
	if (!hole_rl)
		return -ENOMEM;
	hole_rl[0].vcn = start_vcn;
	hole_rl[0].lcn = LCN_HOLE;
	hole_rl[0].length = len;
	hole_rl[1].vcn = start_vcn + len;
	hole_rl[1].lcn = LCN_ENOENT;
	hole_rl[1].length = 0;

	down_write(&ni->runlist.lock);
	ret = ntfs_attr_map_whole_runlist(ni);
	if (ret) {
		up_write(&ni->runlist.lock);
		kfree(hole_rl);
		return ret;
	}

	rl = ntfs_rl_find_vcn_nolock(ni->runlist.rl, start_vcn);
	if (!rl) {
		up_write(&ni->runlist.lock);
		kfree(hole_rl);
		return -EIO;
	}

	rl = ntfs_rl_insert_range(ni->runlist.rl, (int)ni->runlist.count,
				  hole_rl, 1, &new_rl_count);
	if (IS_ERR(rl)) {
		up_write(&ni->runlist.lock);
		kfree(hole_rl);
		return PTR_ERR(rl);
	}
	ni->runlist.rl =  rl;
	ni->runlist.count = new_rl_count;

	ni->allocated_size += ntfs_cluster_to_bytes(vol, len);
	ni->data_size += ntfs_cluster_to_bytes(vol, len);
	if (ntfs_cluster_to_bytes(vol, start_vcn) < ni->initialized_size)
		ni->initialized_size += ntfs_cluster_to_bytes(vol, len);
	ret = ntfs_attr_update_mapping_pairs_locked(ni, 0, ni);
	up_write(&ni->runlist.lock);
	if (ret)
		return ret;

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		ret = -ENOMEM;
		return ret;
	}

	ret = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			       CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (ret) {
		ntfs_attr_put_search_ctx(ctx);
		return ret;
	}

	ctx->attr->data.non_resident.data_size = cpu_to_le64(ni->data_size);
	ctx->attr->data.non_resident.initialized_size = cpu_to_le64(ni->initialized_size);
	if (ni->type == AT_DATA && ni->name == AT_UNNAMED)
		NInoSetFileNameDirty(ni);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	return ret;
}

int ntfs_non_resident_attr_collapse_range(struct ntfs_inode *ni, s64 start_vcn, s64 len)
{
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct runlist_element *punch_rl, *rl;
	struct ntfs_attr_search_ctx *ctx = NULL;
	s64 end_vcn;
	int dst_cnt;
	int ret;
	size_t new_rl_cnt;

	if (ni->type != AT_DATA)
		return -EOPNOTSUPP;

	end_vcn = ntfs_bytes_to_cluster(vol, ni->allocated_size);
	if (start_vcn >= end_vcn)
		return -EINVAL;

	down_write(&ni->runlist.lock);
	ret = ntfs_attr_map_whole_runlist(ni);
	if (ret) {
		up_write(&ni->runlist.lock);
		return ret;
	}

	len = min(len, end_vcn - start_vcn);
	for (rl = ni->runlist.rl, dst_cnt = 0; rl && rl->length; rl++)
		dst_cnt++;
	rl = ntfs_rl_find_vcn_nolock(ni->runlist.rl, start_vcn);
	if (!rl) {
		up_write(&ni->runlist.lock);
		return -EIO;
	}

	rl = ntfs_rl_collapse_range(ni->runlist.rl, dst_cnt + 1,
				    start_vcn, len, &punch_rl, &new_rl_cnt);
	if (IS_ERR(rl)) {
		up_write(&ni->runlist.lock);
		return PTR_ERR(rl);
	}
	ni->runlist.rl = rl;
	ni->runlist.count = new_rl_cnt;

	ni->allocated_size -= ntfs_cluster_to_bytes(vol, len);
	if (ni->data_size > ntfs_cluster_to_bytes(vol, start_vcn)) {
		if (ni->data_size > ntfs_cluster_to_bytes(vol, (start_vcn + len)))
			ni->data_size -= ntfs_cluster_to_bytes(vol, len);
		else
			ni->data_size = ntfs_cluster_to_bytes(vol, start_vcn);
	}
	if (ni->initialized_size > ntfs_cluster_to_bytes(vol, start_vcn)) {
		if (ni->initialized_size >
		    ntfs_cluster_to_bytes(vol, start_vcn + len))
			ni->initialized_size -= ntfs_cluster_to_bytes(vol, len);
		else
			ni->initialized_size = ntfs_cluster_to_bytes(vol, start_vcn);
	}

	if (ni->allocated_size > 0) {
		ret = ntfs_attr_update_mapping_pairs_locked(ni, 0, ni);
		if (ret) {
			up_write(&ni->runlist.lock);
			goto out_rl;
		}
	}
	up_write(&ni->runlist.lock);

	ctx = ntfs_attr_get_search_ctx(base_ni, NULL);
	if (!ctx) {
		ret = -ENOMEM;
		goto out_rl;
	}

	ret = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			       CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (ret)
		goto out_ctx;

	ctx->attr->data.non_resident.data_size = cpu_to_le64(ni->data_size);
	ctx->attr->data.non_resident.initialized_size = cpu_to_le64(ni->initialized_size);
	if (ni->allocated_size == 0)
		ntfs_attr_make_resident(ni, ctx);
	mark_mft_record_dirty(ctx->ntfs_ino);

	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	ret = ntfs_cluster_free_from_rl(vol, punch_rl);
	if (ret)
		ntfs_error(vol->sb, "Freeing of clusters failed");
out_ctx:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
out_rl:
	kvfree(punch_rl);
	mark_mft_record_dirty(base_ni);
	return ret;
}

int ntfs_non_resident_attr_punch_hole(struct ntfs_inode *ni, s64 start_vcn, s64 len)
{
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct runlist_element *punch_rl, *rl;
	s64 end_vcn;
	int dst_cnt;
	int ret;
	size_t new_rl_count;

	if (ni->type != AT_DATA)
		return -EOPNOTSUPP;

	end_vcn = ntfs_bytes_to_cluster(vol, ni->allocated_size);
	if (start_vcn >= end_vcn)
		return -EINVAL;

	down_write(&ni->runlist.lock);
	ret = ntfs_attr_map_whole_runlist(ni);
	if (ret) {
		up_write(&ni->runlist.lock);
		return ret;
	}

	len = min(len, end_vcn - start_vcn + 1);
	for (rl = ni->runlist.rl, dst_cnt = 0; rl && rl->length; rl++)
		dst_cnt++;
	rl = ntfs_rl_find_vcn_nolock(ni->runlist.rl, start_vcn);
	if (!rl) {
		up_write(&ni->runlist.lock);
		return -EIO;
	}

	rl = ntfs_rl_punch_hole(ni->runlist.rl, dst_cnt + 1,
				start_vcn, len, &punch_rl, &new_rl_count);
	if (IS_ERR(rl)) {
		up_write(&ni->runlist.lock);
		return PTR_ERR(rl);
	}
	ni->runlist.rl = rl;
	ni->runlist.count = new_rl_count;

	ret = ntfs_attr_update_mapping_pairs_locked(ni, 0, ni);
	up_write(&ni->runlist.lock);
	if (ret) {
		kvfree(punch_rl);
		return ret;
	}

	ret = ntfs_cluster_free_from_rl(vol, punch_rl);
	if (ret)
		ntfs_error(vol->sb, "Freeing of clusters failed");

	kvfree(punch_rl);
	mark_mft_record_dirty(base_ni);
	return ret;
}

static int ntfs_attr_fallocate_journaled(struct ntfs_inode *ni, loff_t start,
		loff_t byte_len, bool keep_size)
{
	struct ntfs_inode *mrec_ni = NInoAttr(ni) ?
			ni->ext.base_ntfs_ino : ni;
	struct ntfs_log_handle *handle;
	struct runlist_element *rl;
	struct ntfs_volume *vol = ni->vol;
	loff_t end;
	s64 alloc_count;
	s64 lcn;
	s64 max_count;
	s64 vcn;
	s64 vcn_end;
	s64 vcn_uninit;
	bool balloc;
	bool was_delalloc;
	int abort_err;
	int credits;
	int err;

	if (!mrec_ni || check_add_overflow(start, byte_len, &end) ||
	    start < 0 || byte_len <= 0)
		return -EINVAL;
	if (end > S64_MAX - vol->cluster_size_mask)
		return -EFBIG;
	if (signal_pending(current))
		return -EINTR;
	if (end > ni->data_size && !keep_size) {
		err = ntfs_truncate_vfs(VFS_I(ni), end,
				i_size_read(VFS_I(ni)));
		if (err)
			return err;
	}
	if (keep_size && end > ni->allocated_size && !NInoNonResident(ni)) {
		if (ni->data_size < 0 || ni->data_size > U16_MAX)
			return -EIO;
		credits = ni->data_size ?
			ntfs_attr_make_nonresident_log_credits(vol, ni->name_len,
					ni->data_size) :
			ntfs_attr_empty_make_nonresident_log_credits(vol,
					ni->name_len);
		if (credits < 0)
			return credits;
		handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		mutex_lock(&mrec_ni->mrec_lock);
		if (ni->data_size)
			err = ntfs_attr_make_nonresident_transacted(handle, ni);
		else
			err = ntfs_attr_empty_make_nonresident_transacted(handle, ni);
		if (err) {
			abort_err = ntfs_log_abort(handle);
			mutex_unlock(&mrec_ni->mrec_lock);
			return abort_err ? abort_err : err;
		}
		err = ntfs_log_commit(handle);
		mutex_unlock(&mrec_ni->mrec_lock);
		if (err)
			return err;
	}
	while (keep_size && end > ni->allocated_size) {
		u64 old_clusters;
		u64 target_clusters;
		u64 grow_clusters;
		s64 allocation_size;
		bool was_sparse;
		bool sparse;

		if (signal_pending(current))
			return -EINTR;
		if (!NInoNonResident(ni) ||
		    NInoCompressed(ni) || NInoEncrypted(ni))
			return -EOPNOTSUPP;
		was_sparse = NInoSparse(ni);
		sparse = was_sparse;
		old_clusters = ni->allocated_size >> vol->cluster_size_bits;
		target_clusters = DIV_ROUND_UP_ULL((u64)end,
				vol->cluster_size);
		if (!sparse && old_clusters <
				ntfs_bytes_to_cluster(vol, start) &&
		    vol->major_ver >= 3 && !NVolDisableSparse(vol) &&
		    !NInoSparseDisabled(ni)) {
			/* Keep only the requested extent allocated. */
			sparse = true;
		}
		if (sparse) {
			/* Extend with holes. Allocate the requested range below. */
			grow_clusters = target_clusters - old_clusters;
			credits = ntfs_attr_sparse_grow_log_credits(vol);
			if (credits < 0)
				return credits;
		} else {
			grow_clusters = min_t(u64, target_clusters - old_clusters,
					NTFS_ATTR_GROW_MAX_CLUSTERS);
			for (;;) {
				credits = ntfs_attr_physical_grow_log_credits(vol,
						grow_clusters);
				if (credits >= 0 && credits <= (U16_MAX - 2) / 2)
					break;
				if (grow_clusters == 1)
					return credits < 0 ? credits : -E2BIG;
				grow_clusters >>= 1;
			}
		}
		handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		allocation_size = ntfs_cluster_to_bytes(vol,
				old_clusters + grow_clusters);
		mutex_lock(&mrec_ni->mrec_lock);
		if (!!NInoSparse(ni) != was_sparse) {
			mutex_unlock(&mrec_ni->mrec_lock);
			err = ntfs_log_abort(handle);
			if (err)
				return err;
			continue;
		}
		if (sparse)
			err = __ntfs_attr_sparse_grow_transacted(handle, ni,
					allocation_size, false, false);
		else
			err = ntfs_attr_physical_prealloc_transacted(handle, ni,
					allocation_size, grow_clusters);
		if (err) {
			abort_err = ntfs_log_abort(handle);
			mutex_unlock(&mrec_ni->mrec_lock);
			return abort_err ? abort_err : err;
		}
		err = ntfs_log_commit(handle);
		mutex_unlock(&mrec_ni->mrec_lock);
		if (err)
			return err;
		cond_resched();
	}
	if (!NInoNonResident(ni))
		return 0;
	err = ntfs_attr_map_whole_runlist(ni);
	if (err)
		return err;
	vcn = ntfs_bytes_to_cluster(vol, start);
	vcn_end = ntfs_bytes_to_cluster(vol,
			round_up(end, vol->cluster_size));
	vcn_uninit = min_t(s64, vcn_end,
			DIV_ROUND_UP_ULL(ni->initialized_size,
				vol->cluster_size));
	while (vcn < vcn_end) {
		if (signal_pending(current))
			return -EINTR;
		down_read(&ni->runlist.lock);
		rl = ntfs_rl_find_vcn_nolock(ni->runlist.rl, vcn);
		if (!rl) {
			up_read(&ni->runlist.lock);
			return -EIO;
		}
		if (rl->lcn >= 0) {
			vcn += min_t(s64, vcn_end - vcn,
					rl->length - (vcn - rl->vcn));
			up_read(&ni->runlist.lock);
			continue;
		}
		if (rl->lcn != LCN_HOLE && rl->lcn != LCN_DELALLOC) {
			up_read(&ni->runlist.lock);
			return -EIO;
		}
		max_count = min_t(s64, vcn_end - vcn,
				rl->length - (vcn - rl->vcn));
		max_count = min_t(s64, max_count,
				NTFS_ATTR_GROW_MAX_CLUSTERS);
		up_read(&ni->runlist.lock);
		credits = ntfs_attr_map_cluster_log_credits(vol, max_count);
		if (credits < 0)
			return credits;
		handle = ntfs_log_begin(vol, credits);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		mutex_lock(&mrec_ni->mrec_lock);
		down_write(&ni->runlist.lock);
		err = ntfs_attr_map_cluster_transacted(handle, ni, vcn, &lcn,
				&alloc_count, max_count, &balloc, false,
				&was_delalloc, max_t(s64, vcn_uninit - vcn, 0));
		up_write(&ni->runlist.lock);
		if (err) {
			abort_err = ntfs_log_abort(handle);
			mutex_unlock(&mrec_ni->mrec_lock);
			return abort_err ? abort_err : err;
		}
		err = ntfs_log_commit(handle);
		mutex_unlock(&mrec_ni->mrec_lock);
		if (err)
			return err;
		vcn += alloc_count;
		cond_resched();
	}
	return 0;
}

int ntfs_attr_fallocate(struct ntfs_inode *ni, loff_t start, loff_t byte_len, bool keep_size)
{
	struct ntfs_inode *base_ni = ntfs_base_inode(ni);
	struct ntfs_volume *vol = ni->vol;
	struct mft_record *mrec;
	struct ntfs_attr_search_ctx *ctx;
	s64 old_data_size;
	s64 vcn_start, vcn_end, vcn_uninit, vcn, try_alloc_cnt;
	s64 lcn, alloc_cnt;
	s64 rl_lcn, rl_length, rl_vcn;
	int err = 0;
	struct runlist_element *rl;
	bool balloc;

	if (ni->type != AT_DATA)
		return -EINVAL;
	if (ni->vol->journal)
		return ntfs_attr_fallocate_journaled(ni, start, byte_len,
				keep_size);

	if (NInoNonResident(ni) && !NInoFullyMapped(ni)) {
		down_write(&ni->runlist.lock);
		err = ntfs_attr_map_whole_runlist(ni);
		up_write(&ni->runlist.lock);
		if (err)
			return err;
	}

	mutex_lock_nested(&base_ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	mrec = map_mft_record(base_ni);
	if (IS_ERR(mrec)) {
		mutex_unlock(&base_ni->mrec_lock);
		return PTR_ERR(mrec);
	}

	ctx = ntfs_attr_get_search_ctx(base_ni, mrec);
	if (!ctx) {
		err = -ENOMEM;
		goto out_unmap;
	}

	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (err) {
		err = -EIO;
		goto out_unmap;
	}

	old_data_size = ni->data_size;
	if (start + byte_len > ni->data_size) {
		err = ntfs_attr_truncate(ni, start + byte_len);
		if (err)
			goto out_unmap;
		if (keep_size) {
			ntfs_attr_reinit_search_ctx(ctx);
			err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
					CASE_SENSITIVE, 0, NULL, 0,
					ctx);
			if (err) {
				err = -EIO;
				goto out_unmap;
			}
			ni->data_size = old_data_size;
			i_size_write(VFS_I(ni), old_data_size);
			if (NInoNonResident(ni))
				ctx->attr->data.non_resident.data_size =
					cpu_to_le64(old_data_size);
			else
				ctx->attr->data.resident.value_length =
					cpu_to_le32((u32)old_data_size);
			mark_mft_record_dirty(base_ni);
		}
	}

	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	mutex_unlock(&base_ni->mrec_lock);

	if (!NInoNonResident(ni))
		goto out;

	vcn_start = (s64)ntfs_bytes_to_cluster(vol, start);
	vcn_end = (s64)ntfs_bytes_to_cluster(vol,
			round_up(start + byte_len, vol->cluster_size));
	vcn_uninit = (s64)ntfs_bytes_to_cluster(vol,
			round_up(ni->initialized_size, vol->cluster_size));
	vcn_uninit = min_t(s64, vcn_uninit, vcn_end);

	/*
	 * we have to allocate clusters for holes and delayed within initialized_size,
	 * and zero out the clusters only for the holes.
	 */
	vcn = vcn_start;
	while (vcn < vcn_uninit) {
		down_read(&ni->runlist.lock);
		rl = ntfs_attr_find_vcn_nolock(ni, vcn, NULL);
		if (IS_ERR(rl)) {
			up_read(&ni->runlist.lock);
			err = PTR_ERR(rl);
			goto out;
		}
		rl_lcn = rl->lcn;
		rl_length = rl->length;
		rl_vcn = rl->vcn;
		up_read(&ni->runlist.lock);

		if (rl_lcn > 0) {
			vcn += rl_length - (vcn - rl_vcn);
		} else if (rl_lcn == LCN_DELALLOC || rl_lcn == LCN_HOLE) {
			try_alloc_cnt = min(rl_length - (vcn - rl_vcn),
					    vcn_uninit - vcn);

			if (rl_lcn == LCN_DELALLOC) {
				vcn += try_alloc_cnt;
				continue;
			}

			while (try_alloc_cnt > 0) {
				mutex_lock_nested(&base_ni->mrec_lock,
						NTFS_INODE_MUTEX_NORMAL);
				down_write(&ni->runlist.lock);
				err = ntfs_attr_map_cluster(ni, vcn, &lcn, &alloc_cnt,
							    try_alloc_cnt, &balloc, false, false,
							    false);
				up_write(&ni->runlist.lock);
				mutex_unlock(&base_ni->mrec_lock);
				if (err)
					goto out;

				if (balloc) {
					err = ntfs_dio_zero_range(VFS_I(ni),
								  lcn << vol->cluster_size_bits,
								  alloc_cnt <<
								  vol->cluster_size_bits);
					if (err)
						goto out;
				}

				if (fatal_signal_pending(current))
					goto signal_out;

				vcn += alloc_cnt;
				try_alloc_cnt -= alloc_cnt;
			}
		} else {
			err = -EIO;
			goto out;
		}
	}

	/* allocate clusters outside of initialized_size */
	try_alloc_cnt = vcn_end - vcn;
	while (try_alloc_cnt > 0) {
		mutex_lock_nested(&base_ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
		down_write(&ni->runlist.lock);
		err = ntfs_attr_map_cluster(ni, vcn, &lcn, &alloc_cnt,
					    try_alloc_cnt, &balloc, false, false, false);
		up_write(&ni->runlist.lock);
		mutex_unlock(&base_ni->mrec_lock);
		if (err || fatal_signal_pending(current))
			goto signal_out;

		vcn += alloc_cnt;
		try_alloc_cnt -= alloc_cnt;
		cond_resched();
	}

	if (NInoRunlistDirty(ni)) {
		mutex_lock_nested(&base_ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
		down_write(&ni->runlist.lock);
		err = ntfs_attr_update_mapping_pairs_locked(ni, 0, ni);
		if (err)
			ntfs_error(ni->vol->sb, "Updating mapping pairs failed");
		else
			NInoClearRunlistDirty(ni);
		up_write(&ni->runlist.lock);
		mutex_unlock(&base_ni->mrec_lock);
	}
	return err;
out_unmap:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	mutex_unlock(&base_ni->mrec_lock);
out:
	return err >= 0 ? 0 : err;
signal_out:
	if (!err)
		err = -EINTR;
	goto out;
}
