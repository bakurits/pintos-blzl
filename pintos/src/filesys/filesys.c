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


static void print_dirs(struct dir* dir) {
  printf("Printing dir content\n");
  char name[NAME_MAX + 1];
  while (dir_readdir (dir, name))
    printf ("%s\n", name);
}

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
      strlcpy(dir, whole_path, i + 2);
      strlcpy(file, &whole_path[i + 1], n - i + 1);
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
  if (strlen(file_name) == 0) return false;

  
  struct dir *dir = dir_open_path(thread_current()->cwd, dir_path);
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector));
  if (!success) goto finish;
  if (type == Directory) {
    success = dir_create(inode_sector, initial_size);
    if (!success) goto finish;
    struct dir *new_dir = dir_open(inode_open(inode_sector));
    dir_add(new_dir, "..", inode_get_inumber(dir_get_inode(dir)));
    dir_add(new_dir, ".", inode_get_inumber(dir_get_inode(new_dir)));
    dir_close(new_dir);
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
  if (name == NULL || strlen(name) == 0) return NULL;
  char dir_path[strlen(name)];
  char file_name[NAME_MAX + 1];
  
  split_file_path(name, dir_path, file_name);
  struct dir *dir = dir_open_path(thread_current()->cwd, dir_path);
  
  struct file* res = NULL;
  if (dir == NULL) return NULL;
  if (strlen(file_name) == 0) {
    struct inode *inode = dir_get_inode(dir);
    if (inode == NULL) {
      dir_close(dir);
      return NULL;
    } 
    res = file_open(inode);    
  } else {
    struct inode *inode = NULL;
    if (!dir_lookup(dir, file_name, &inode)) {
      dir_close(dir);
      return NULL;
    }
    res = file_open(inode);
  }
  dir_close(dir);
  if (res == NULL) return NULL;
  return res;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char *name) {
  char dir_path[strlen(name)];
  char file_name[NAME_MAX + 1];

  split_file_path(name, dir_path, file_name);
  struct dir *parent_dir = dir_open_path(thread_current()->cwd, dir_path);

  //printf("dir : %s file %s %p\n", dir_path, file_name, parent_dir);
  if (parent_dir == NULL) {
    dir_close(parent_dir);
    return false;
  }
  struct inode *inode = NULL;
  if (!dir_lookup(parent_dir, file_name, &inode)) goto error;
  
  if (inode_is_dir(inode)) {
    // if deleting directory
    
    if (inode_is_opened(inode)) goto error;
    //printf("dir : %s file %s %p\n", dir_path, file_name, inode);
    struct dir* dir = dir_open(inode);
    if (dir == NULL || !dir_is_empty(dir)) {
      dir_close(dir);
      goto error;
    }
    if (dir_get_inode(dir) == dir_get_inode(parent_dir)) {
      dir_close(parent_dir);
      goto error;
    }

    bool success = dir_remove(parent_dir, file_name);
    dir_close(parent_dir);
    dir_close(dir);
    return success;
  } else {
    // if deleting file
    bool success = dir_remove(parent_dir, file_name);
    dir_close(parent_dir);
    return success;
  }

error:
  dir_close(parent_dir);
  return false;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16)) PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
