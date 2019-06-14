#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#include "buffer_cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCK_NUM 123
#define INDIRECT_BLOCK_NUM 1
#define D_INDIRECT_BLOCK_NUM 1  
#define INDIRECT_BLOCK_SIZE BLOCK_SECTOR_SIZE / sizeof (block_sector_t)
#define MAXIMUM_NUMBER_OF_BLOCKS DIRECT_BLOCK_NUM + INDIRECT_BLOCK_SIZE * (INDIRECT_BLOCK_NUM + D_INDIRECT_BLOCK_NUM*INDIRECT_BLOCK_SIZE)
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */   

    block_sector_t direct_blocks[DIRECT_BLOCK_NUM];
    block_sector_t indirect_blocks[INDIRECT_BLOCK_NUM];
    block_sector_t d_indirect_blocks[D_INDIRECT_BLOCK_NUM];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
    ASSERT (inode != NULL);
    if (pos < inode->data.length) {
        if (pos < BLOCK_SECTOR_SIZE * DIRECT_BLOCK_NUM) {
            return inode->data.direct_blocks[pos / BLOCK_SECTOR_SIZE];
        }
        uint32_t indirect_relative = pos - BLOCK_SECTOR_SIZE * DIRECT_BLOCK_NUM;
        if (indirect_relative < INDIRECT_BLOCK_NUM * (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)) * BLOCK_SECTOR_SIZE) {
            block_sector_t direct_blocks[INDIRECT_BLOCK_SIZE];
            block_read (fs_device,
                        inode->data.indirect_blocks[(indirect_relative / BLOCK_SECTOR_SIZE) /  INDIRECT_BLOCK_SIZE],
                        direct_blocks);
            return direct_blocks[(indirect_relative / BLOCK_SECTOR_SIZE) %  INDIRECT_BLOCK_SIZE];
        }
        /*
            Data is not stored in direct or indirect
            blocks, therefore it's in doubly indirect blocks
        */
        uint32_t d_indirect_relative = indirect_relative - INDIRECT_BLOCK_NUM * (BLOCK_SECTOR_SIZE / sizeof (block_sector_t) * BLOCK_SECTOR_SIZE);
        block_sector_t indirect_blocks[INDIRECT_BLOCK_SIZE];
        block_read (fs_device,
                    inode->data.indirect_blocks[d_indirect_relative/(INDIRECT_BLOCK_SIZE * INDIRECT_BLOCK_SIZE * BLOCK_SECTOR_SIZE)],
                    indirect_blocks);       
        block_sector_t direct_blocks[INDIRECT_BLOCK_SIZE];
        block_read (fs_device,
                    indirect_blocks[(d_indirect_relative/(INDIRECT_BLOCK_SIZE * BLOCK_SECTOR_SIZE))%INDIRECT_BLOCK_SIZE],
                    direct_blocks);       
        return direct_blocks[(d_indirect_relative/(BLOCK_SECTOR_SIZE))%INDIRECT_BLOCK_SIZE];
    } else {
        return -1;
    }
    // return inode->data.start + pos / BLOCK_SECTOR_SIZE
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  buffer_cache_test();
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
	  if (sectors > MAXIMUM_NUMBER_OF_BLOCKS) {
		  goto revert;
	  }
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
        static char zeros[BLOCK_SECTOR_SIZE];

		block_sector_t * block_arr = &(disk_inode->direct_blocks);
		size_t block_arr_len = DIRECT_BLOCK_NUM;

		if (allocate_block_array (block_arr, block_arr_len) < block_arr_len) {
			goto revert;
		}

		int i = 0;
		for (i = 0; i < INDIRECT_BLOCK_NUM; i ++) {
			if (!free_map_allocate (1, &disk_inode->indirect_blocks[i])) {
				goto revert;
			}
			block_write (fs_device, disk_inode->indirect_blocks[i], zeros);

			block_sector_t direct_block_arr[INDIRECT_BLOCK_SIZE];
			block_arr = direct_block_arr;
			block_arr_len = INDIRECT_BLOCK_SIZE;
			if (allocate_block_array (block_arr, block_arr_len) < block_arr_len) {
				goto revert;
			}

			block_write (fs_device, disk_inode->indirect_blocks[i], direct_block_arr);
		}

		int j = 0;
		for (i = 0; i < D_INDIRECT_BLOCK_NUM; i ++) {
			if (!free_map_allocate (1, &disk_inode->d_indirect_blocks[i])) {
				goto revert;
			}
			block_write (fs_device, disk_inode->d_indirect_blocks[i], zeros);
			block_sector_t indirect_block_arr[INDIRECT_BLOCK_SIZE];

			for (j = 0; j < INDIRECT_BLOCK_SIZE; j ++) {
				block_sector_t direct_block_arr[INDIRECT_BLOCK_SIZE];
				block_arr = direct_block_arr;
				block_arr_len = INDIRECT_BLOCK_SIZE;
				if (allocate_block_array (block_arr, block_arr_len) < block_arr_len) {
					goto revert;
				}
				block_write (fs_device, indirect_block_arr[i], direct_block_arr);
			}

			block_write (fs_device, disk_inode->indirect_blocks[i], indirect_block_arr);			
		}
      free (disk_inode);
    }

  return success;

  revert :
	// TODO: Edit revert
	return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      //DASAWERIA
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);
		  //TODO: Edit
        //   free_map_release (inode->data.start,
        //                     bytes_to_sectors (inode->data.length));
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      buffer_cache_read(sector_idx, buffer + bytes_read, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      buffer_cache_write(sector_idx, buffer + bytes_written, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
