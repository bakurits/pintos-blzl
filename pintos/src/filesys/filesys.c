#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/buffer_cache.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();
  buffer_cache_init();

  if (format) do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  free_map_close();
  buffer_cache_full_flush();
  buffer_cache_deinit();
}

static int split_file_path(const char *whole_path, char *dir, char *file) {
  dir[0] = file[0] = '\0';
  int n = strlen(whole_path);
  int i;
  for (i = n - 1; i >= 0; i--) {
    if (whole_path[i] == '/') {
      strlcpy(dir, whole_path, i - 1);
      strlcpy(file, &whole_path[i + 1], n - i);
      return true;
    }
  }
  if (n > NAME_MAX) return false;

  strlcpy(file, whole_path, n + 1);
  return true;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size,
                    enum file_type_t type) {
  block_sector_t inode_sector = 0;

  char dir_path[strlen(name)];
  char file_name[NAME_MAX + 1];

  split_file_path(name, dir_path, file_name);

  struct dir *dir = dir_open_path(thread_current()->cwd, dir_path);

  bool success = (dir != NULL && free_map_allocate(1, &inode_sector));
  if (!success) goto finish;
  if (type == Directory) {
    success = dir_create(inode_sector, initial_size);
    if (!success) goto finish;
    struct dir *new_dir = dir_open(inode_open(inode_sector));
    dir_add(new_dir, "..", inode_get_inumber(dir_get_inode(dir)));
    dir_add(new_dir, ".", inode_get_inumber(dir_get_inode(new_dir)));
  } else {
    success = inode_create(inode_sector, initial_size, 0);
  }
  success = success && dir_add(dir, file_name, inode_sector);

finish:
  if (!success && inode_sector != 0) free_map_release(inode_sector, 1);

  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open(const char *name) {
  char dir_path[strlen(name)];
  char file_name[NAME_MAX + 1];

  split_file_path(name, dir_path, file_name);
  struct dir *dir = dir_open_path(thread_current()->cwd, dir_path);
  struct inode *inode = NULL;

  if (dir != NULL) dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char *name) {
  char dir_path[strlen(name)];
  char file_name[NAME_MAX + 1];

  split_file_path(name, dir_path, file_name);
  struct dir *dir = dir_open_path(thread_current()->cwd, dir_path);
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16)) PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}