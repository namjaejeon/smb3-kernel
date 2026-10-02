// SPDX-License-Identifier: GPL-2.0-or-later
/* Free cluster extents indexed by starting LCN and decreasing length. */

#include <linux/bitops.h>
#include <linux/slab.h>

#include "free_space.h"
#include "lcnalloc.h"
#include "ntfs.h"

#define NTFS_MAX_FREE_EXTENTS (32U * 1024)

struct ntfs_free_extent {
	struct rb_node start_node;
	struct rb_node length_node;
	s64 start;
	s64 length;
};

struct ntfs_cluster_range {
	s64 start;
	s64 end;
};

static void ntfs_free_extent_unlink(struct ntfs_free_space *space,
		struct ntfs_free_extent *extent)
{
	rb_erase(&extent->start_node, &space->by_start);
	rb_erase(&extent->length_node, &space->by_length);
	space->nr_extents--;
}

static void ntfs_free_extent_link(struct ntfs_free_space *space,
		struct ntfs_free_extent *extent)
{
	struct rb_node **link = &space->by_start.rb_node, *parent = NULL;

	while (*link) {
		struct ntfs_free_extent *entry;

		parent = *link;
		entry = rb_entry(parent, struct ntfs_free_extent, start_node);
		if (extent->start < entry->start)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&extent->start_node, parent, link);
	rb_insert_color(&extent->start_node, &space->by_start);

	link = &space->by_length.rb_node;
	parent = NULL;
	while (*link) {
		struct ntfs_free_extent *entry;

		parent = *link;
		entry = rb_entry(parent, struct ntfs_free_extent, length_node);
		if (extent->length > entry->length ||
		    (extent->length == entry->length &&
		     extent->start < entry->start))
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&extent->length_node, parent, link);
	rb_insert_color(&extent->length_node, &space->by_length);
	space->nr_extents++;
}

/* Find the last extent starting at or before @start. */
static struct rb_node *ntfs_free_extent_before(struct ntfs_free_space *space,
		s64 start)
{
	struct rb_node *node = space->by_start.rb_node, *before = NULL;

	while (node) {
		struct ntfs_free_extent *extent;

		extent = rb_entry(node, struct ntfs_free_extent, start_node);
		if (extent->start > start) {
			node = node->rb_left;
		} else {
			before = node;
			node = node->rb_right;
		}
	}
	return before;
}

void ntfs_free_space_destroy(struct ntfs_free_space *space)
{
	struct rb_node *node;

	while ((node = rb_first(&space->by_start))) {
		struct ntfs_free_extent *extent;

		extent = rb_entry(node, struct ntfs_free_extent, start_node);
		rb_erase(node, &space->by_start);
		kfree(extent);
	}
	space->by_length = RB_ROOT;
	space->nr_extents = 0;
	space->complete = false;
}

void ntfs_free_space_add(struct ntfs_free_space *space, s64 start, s64 length)
{
	struct ntfs_free_extent *extent = NULL;
	struct rb_node *node;
	s64 end = start + length;

	if (!length)
		return;

	node = ntfs_free_extent_before(space, start);
	if (node) {
		struct ntfs_free_extent *entry;

		entry = rb_entry(node, struct ntfs_free_extent, start_node);
		if (entry->start + entry->length < start)
			node = rb_next(node);
	} else {
		node = rb_first(&space->by_start);
	}

	/* Merge adjacent or overlapping extents, including rollback updates. */
	while (node) {
		struct ntfs_free_extent *entry;
		struct rb_node *next = rb_next(node);

		entry = rb_entry(node, struct ntfs_free_extent, start_node);
		if (entry->start > end)
			break;
		start = min(start, entry->start);
		end = max(end, entry->start + entry->length);
		ntfs_free_extent_unlink(space, entry);
		if (!extent)
			extent = entry;
		else
			kfree(entry);
		node = next;
	}

	if (!extent && space->nr_extents == NTFS_MAX_FREE_EXTENTS) {
		struct ntfs_free_extent *smallest;

		space->complete = false;
		node = rb_last(&space->by_length);
		smallest = rb_entry(node, struct ntfs_free_extent, length_node);
		if (end - start <= smallest->length)
			return;
		ntfs_free_extent_unlink(space, smallest);
		extent = smallest;
	}
	if (!extent) {
		/* Cache misses must not make cluster allocation fail. */
		extent = kmalloc_obj(*extent, GFP_NOWAIT | __GFP_NOWARN);
		if (!extent) {
			space->complete = false;
			return;
		}
	}
	extent->start = start;
	extent->length = end - start;
	ntfs_free_extent_link(space, extent);
}

void ntfs_free_space_remove(struct ntfs_free_space *space, s64 start, s64 length)
{
	struct rb_node *node = ntfs_free_extent_before(space, start);
	s64 end = start + length;

	if (!node)
		node = rb_first(&space->by_start);
	while (node) {
		struct ntfs_free_extent *extent;
		struct rb_node *next = rb_next(node);
		s64 extent_end;

		extent = rb_entry(node, struct ntfs_free_extent, start_node);
		if (extent->start >= end)
			break;
		extent_end = extent->start + extent->length;
		if (extent_end <= start) {
			node = next;
			continue;
		}
		ntfs_free_extent_unlink(space, extent);
		if (extent->start < start) {
			extent->length = start - extent->start;
			ntfs_free_extent_link(space, extent);
			if (extent_end > end) {
				ntfs_free_space_add(space, end, extent_end - end);
				break;
			}
		} else {
			if (extent_end > end) {
				extent->start = end;
				extent->length = extent_end - end;
				ntfs_free_extent_link(space, extent);
				break;
			}
			kfree(extent);
		}
		node = next;
	}
}

void ntfs_free_space_add_bitmap(struct ntfs_free_space *space,
		const unsigned long *bitmap, s64 start, unsigned int bits)
{
	unsigned int bit = 0;

	while (bit < bits) {
		unsigned int end;

		bit = find_next_zero_bit_le(bitmap, bits, bit);
		if (bit == bits)
			break;
		end = find_next_bit_le(bitmap, bits, bit);
		ntfs_free_space_add(space, start + bit, end - bit);
		bit = end;
	}
}

static void ntfs_select_free_extent(s64 start, s64 end,
		const struct ntfs_cluster_range *range, s64 *best_start,
		s64 *best_length)
{
	start = max(start, range->start);
	end = min(end, range->end);
	if (end - start > *best_length) {
		*best_start = start;
		*best_length = end - start;
	}
}

/* Scan the bitmap only when the extent cache cannot satisfy the request. */
static int ntfs_free_space_scan(struct ntfs_volume *vol,
		const struct ntfs_cluster_range *range, s64 count,
		s64 *best_start, s64 *best_length)
{
	struct address_space *mapping = vol->lcnbmp_ino->i_mapping;
	s64 run_start = 0, run_length = 0;
	pgoff_t index, last;

	if (range->start >= range->end)
		return 0;
	index = range->start >> (PAGE_SHIFT + 3);
	last = (range->end - 1) >> (PAGE_SHIFT + 3);
	for (; index <= last; index++) {
		struct folio *folio;
		unsigned long *bitmap;
		s64 page_start = (s64)index << (PAGE_SHIFT + 3);
		unsigned int bit = max_t(s64, range->start - page_start, 0);
		unsigned int bits = min_t(s64, range->end - page_start,
					 PAGE_SIZE * BITS_PER_BYTE);

		if (!vol->lcn_empty_bits_per_page[index]) {
			run_length = 0;
			continue;
		}
		folio = read_mapping_folio(mapping, index, NULL);
		if (IS_ERR(folio))
			return PTR_ERR(folio);
		folio_lock(folio);
		bitmap = kmap_local_folio(folio, 0);
		while (bit < bits) {
			unsigned int free_bit, end;

			free_bit = find_next_zero_bit_le(bitmap, bits, bit);
			if (free_bit > bit)
				run_length = 0;
			if (free_bit == bits)
				break;
			end = find_next_bit_le(bitmap, bits, free_bit);
			if (!run_length)
				run_start = page_start + free_bit;
			run_length += end - free_bit;
			ntfs_free_space_add(&vol->free_space,
					    page_start + free_bit, end - free_bit);
			if (run_length > *best_length) {
				*best_start = run_start;
				*best_length = run_length;
			}
			if (run_length >= count)
				break;
			if (end < bits)
				run_length = 0;
			bit = end;
		}
		kunmap_local(bitmap);
		folio_unlock(folio);
		folio_put(folio);
		if (*best_length >= count)
			break;
	}
	return 0;
}

/* Find only the free run starting at @hint; do not change allocation zones. */
int ntfs_free_space_find_at(struct ntfs_volume *vol, s64 hint, s64 end,
		s64 count, s64 *length)
{
	struct ntfs_free_space *space = &vol->free_space;
	struct address_space *mapping = vol->lcnbmp_ino->i_mapping;
	struct rb_node *node;
	s64 pos = hint;

	lockdep_assert_held_write(&vol->lcnbmp_lock);
	*length = 0;
	if (hint < 0 || hint >= end)
		return 0;
	node = ntfs_free_extent_before(space, hint);
	if (node) {
		struct ntfs_free_extent *extent;

		extent = rb_entry(node, struct ntfs_free_extent, start_node);
		if (extent->start + extent->length > hint) {
			*length = min(extent->start + extent->length, end) - hint;
			*length = min(*length, count);
			return 0;
		}
	}
	if (space->complete)
		return 0;

	/* A missing cached extent may still contain a valid adjacency hint. */
	end = hint + min(count, end - hint);
	while (pos < end) {
		pgoff_t index = pos >> (PAGE_SHIFT + 3);
		s64 page_start = (s64)index << (PAGE_SHIFT + 3);
		unsigned int bit = pos - page_start;
		unsigned int bits = min_t(s64, end - page_start,
					 PAGE_SIZE * BITS_PER_BYTE);
		struct folio *folio;
		unsigned long *bitmap;
		unsigned int used_bit;

		if (!vol->lcn_empty_bits_per_page[index])
			break;
		folio = read_mapping_folio(mapping, index, NULL);
		if (IS_ERR(folio))
			return PTR_ERR(folio);
		folio_lock(folio);
		bitmap = kmap_local_folio(folio, 0);
		used_bit = find_next_bit_le(bitmap, bits, bit);
		ntfs_free_space_add(space, pos, used_bit - bit);
		kunmap_local(bitmap);
		folio_unlock(folio);
		folio_put(folio);
		*length += used_bit - bit;
		if (used_bit < bits)
			break;
		pos = page_start + bits;
	}
	return 0;
}

/* Find the largest free run in the current bitmap page's remaining range. */
static int ntfs_free_space_find_local(struct ntfs_volume *vol, s64 begin,
		s64 end, s64 *start, s64 *length)
{
	struct ntfs_free_space *space = &vol->free_space;
	struct ntfs_cluster_range range = {
		.start = begin,
		.end = begin + min_t(s64, end - begin,
			PAGE_SIZE * BITS_PER_BYTE -
			(begin & (PAGE_SIZE * BITS_PER_BYTE - 1))),
	};
	struct rb_node *node = ntfs_free_extent_before(space, begin);

	if (!node)
		node = rb_first(&space->by_start);
	for (; node; node = rb_next(node)) {
		struct ntfs_free_extent *extent;

		extent = rb_entry(node, struct ntfs_free_extent, start_node);
		if (extent->start >= range.end)
			break;
		ntfs_select_free_extent(extent->start,
				extent->start + extent->length, &range,
				start, length);
	}
	if (space->complete)
		return 0;

	/* An incomplete cache cannot establish the largest run in this page. */
	return ntfs_free_space_scan(vol, &range, range.end - range.start,
				   start, length);
}

/* The allocator supplies one zone pass; the cache only selects an extent. */
int ntfs_free_space_find(struct ntfs_volume *vol, s64 begin, s64 end,
		s64 count, s64 *start, s64 *length)
{
	struct ntfs_free_space *space = &vol->free_space;
	struct ntfs_cluster_range range = { .start = begin, .end = end };
	struct rb_node *node;
	int err;

	lockdep_assert_held_write(&vol->lcnbmp_lock);
	*length = 0;
	if (begin >= end)
		return 0;

	/*
	 * Prefer a local maximum that can satisfy the request, leaving its tail
	 * available for this file's adjacency hint. Small concurrent allocations
	 * can then start in separate holes instead of sharing one large extent.
	 * Use the zone-wide index when the local runs are too short, so larger
	 * requests still benefit from extents spanning bitmap pages.
	 */
	err = ntfs_free_space_find_local(vol, begin, end, start, length);
	if (err)
		return err;
	if (*length >= count) {
		*length = count;
		return 0;
	}
	*length = 0;
	for (node = rb_first(&space->by_length); node; node = rb_next(node)) {
		struct ntfs_free_extent *extent;

		extent = rb_entry(node, struct ntfs_free_extent, length_node);
		if (extent->length <= *length)
			break;
		ntfs_select_free_extent(extent->start,
				extent->start + extent->length, &range,
				start, length);
	}
	if (*length >= count || space->complete) {
		*length = min(*length, count);
		return 0;
	}

	err = ntfs_free_space_scan(vol, &range, count, start, length);
	if (err)
		return err;
	*length = min(*length, count);
	return 0;
}
