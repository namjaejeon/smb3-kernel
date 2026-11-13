# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_NTFS_FS) += ntfs.o

ntfs-y := aops.o attrib.o collate.o dir.o file.o index.o inode.o \
	  mft.o mst.o namei.o runlist.o super.o unistr.o attrlist.o ea.o \
	  upcase.o bitmap.o lcnalloc.o logfile.o logfile_record.o logfile_replay_io.o \
	  reparse.o compress.o \
	  iomap.o debug.o sysctl.o object_id.o bdev-io.o named_stream.o

ntfs-$(CONFIG_NTFS_FS_WOF_COMPRESSION) += wof.o \
	lib/decompress_common.o lib/lzx_decompress.o lib/xpress_decompress.o

ccflags-$(CONFIG_NTFS_DEBUG) += -DDEBUG
CFLAGS_logfile.o += -I$(src)
CFLAGS_logfile_record.o += -I$(src)
CFLAGS_logfile_replay_io.o += -I$(src)
