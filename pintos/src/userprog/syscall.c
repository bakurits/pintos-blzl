#include "userprog/syscall.h"
#include <console.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "list.h"
#include "process.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

// static struct lock filesys_lock;
static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
  // lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_halt(struct intr_frame *f UNUSED, uint32_t *args UNUSED);
static void syscall_exit(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_exec(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_wait(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_create(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_remove(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_open(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_filesize(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_read(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_write(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_seek(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_tell(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_close(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_practice(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_chdir(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_mkdir(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_readdir(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_isdir(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_inumber(struct intr_frame *f UNUSED, uint32_t *args);

typedef void (*syscall_func_t)(struct intr_frame *f UNUSED, uint32_t *args);

static bool valid_ptr(void *ptr, int size) {
  if (ptr == NULL) return false;

  ptr += size - 1;
  if (!is_user_vaddr(ptr)) return false;
  if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL) return false;

  return true;
}

syscall_func_t syscall_func_arr[21] = {syscall_halt,
                                       syscall_exit,
                                       syscall_exec,
                                       syscall_wait,
                                       syscall_create,
                                       syscall_remove,
                                       syscall_open,
                                       syscall_filesize,
                                       syscall_read,
                                       syscall_write,
                                       syscall_seek,
                                       syscall_tell,
                                       syscall_close,
                                       syscall_practice,
                                       NULL,
                                       NULL,
                                       syscall_chdir,
                                       syscall_mkdir,
                                       syscall_readdir,
                                       syscall_isdir,
                                       syscall_inumber};

static void syscall_handler(struct intr_frame *f UNUSED) {
  uint32_t *args = ((uint32_t *)f->esp);
  if (!valid_ptr(args, sizeof(void *))) {
    _exit(-1);
  }

  syscall_func_arr[args[0]](f, args);
}

static void syscall_halt(struct intr_frame *f UNUSED, uint32_t *args UNUSED) {
  _halt();
}

static void syscall_exit(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(void *))) {
    _exit(-1);
  }
  _exit(*(int *)(&args[1]));
}

static void syscall_exec(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(void *))) {
    _exit(-1);
  }
  if (!valid_ptr((void *)args[1], sizeof(char))) {
    _exit(-1);
  }
  f->eax = _exec((char *)args[1]);
}

static void syscall_wait(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(pid_t))) {
    _exit(-1);
  }
  f->eax = _wait(args[1]);
}

static void syscall_create(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), 2 * sizeof(char *) + sizeof(unsigned))) {
    _exit(-1);
  }

  if (!valid_ptr((void *)args[1], sizeof(char))) {
    _exit(-1);
  }

  f->eax = _create((char *)args[1], (unsigned)args[2]);
}

static void syscall_remove(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(char *))) {
    _exit(-1);
  }
  if (!valid_ptr((void *)args[1], sizeof(char))) {
    _exit(-1);
  }

  f->eax = _remove((char *)args[1]);
}

static void syscall_open(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(char *))) {
    _exit(-1);
  }
  if (!valid_ptr((void *)args[1], sizeof(char))) {
    _exit(-1);
  }
  char *file_name = (char *)args[1];
  f->eax = _open(file_name);
}

static void syscall_filesize(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(char *))) {
    _exit(-1);
  }

  f->eax = _filesize((int)args[1]);
}

static void syscall_read(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1),
                 sizeof(int) + sizeof(char *) + sizeof(unsigned))) {
    _exit(-1);
  }
  if (!valid_ptr((void *)args[2], sizeof(char))) {
    _exit(-1);
  }
  int fd = (int)args[1];
  void *buff = (void *)args[2];
  unsigned sz = (int)args[3];

  // check pointer
  if (!valid_ptr(buff, (int)sz)) {
    _exit(-1);
    NOT_REACHED();
  }

  f->eax = _read(fd, buff, sz);
}

static void syscall_write(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1),
                 sizeof(int) + sizeof(char *) + sizeof(unsigned))) {
    _exit(-1);
  }
  if (!valid_ptr((void *)args[2], sizeof(char))) {
    _exit(-1);
  }
  int fd = (int)args[1];
  void *buff = (void *)args[2];
  unsigned sz = (int)args[3];

  // check pointer
  if (!valid_ptr(buff, (int)sz)) {
    _exit(-1);
    NOT_REACHED();
  }

  f->eax = _write(fd, buff, sz);
}

static void syscall_seek(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(int) + sizeof(unsigned))) {
    _exit(-1);
  }

  int fd = (int)args[1];
  unsigned pos = (unsigned)args[2];

  _seek(fd, pos);
}

static void syscall_tell(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(int))) {
    _exit(-1);
  };
  int fd = (int)args[1];
  f->eax = _tell(fd);
}

static void syscall_close(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(int))) {
    _exit(-1);
  }
  int fd = (int)args[1];
  _close(fd);
}

static void syscall_practice(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(int))) {
    _exit(-1);
  }
  f->eax = _practice((int)args[1]);
}

static void syscall_chdir(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(char *))) {
    _exit(-1);
  }
  if (!valid_ptr((void *)args[1], sizeof(char))) {
    _exit(-1);
  }

  f->eax = _chdir((char *)args[1]);
}
static void syscall_mkdir(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(char *))) {
    _exit(-1);
  }
  if (!valid_ptr((void *)args[1], sizeof(char))) {
    _exit(-1);
  }

  f->eax = _mkdir((char *)args[1]);
}
static void syscall_readdir(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(int) + sizeof(char *))) {
    _exit(-1);
  }
  if (!valid_ptr((void *)args[2], sizeof(char))) {
    _exit(-1);
  }
  int fd = (int)args[1];
  char *name = (void *)args[2];

  f->eax = _readdir(fd, name);
}
static void syscall_isdir(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(int))) {
    _exit(-1);
  };
  int fd = (int)args[1];
  f->eax = _isdir(fd);
}
static void syscall_inumber(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr((void *)(args + 1), sizeof(int))) {
    _exit(-1);
  };
  int fd = (int)args[1];
  f->eax = _inumber(fd);
}

int _practice(int i) { return i + 1; }

void _halt(void) { shutdown_power_off(); }

void _exit(int status) {
  printf("%s: exit(%d)\n", thread_name(), status);

  struct list_elem *e = get_chldelem_parent(thread_current());
  if (e != NULL) {
    struct child_info_t *child = list_entry(e, struct child_info_t, elem);
    child->status = status;
  }
  thread_exit();
}

pid_t _exec(const char *cmd_line) {
  // lock_acquire(&filesys_lock);
  tid_t process_pid = process_execute(cmd_line);
  // lock_release(&filesys_lock);
  return process_pid;
}

int _wait(pid_t pid) {
  tid_t tid = pid;
  return process_wait(tid);
}

bool _create(const char *file, unsigned initial_size) {
  // lock_acquire(&filesys_lock);
  bool res = filesys_create(file, initial_size, File);
  // lock_release(&filesys_lock);
  return res;
}

bool _remove(const char *file) {
  // lock_acquire(&filesys_lock);
  bool res = filesys_remove(file);
  // lock_release(&filesys_lock);
  return res;
}

int _open(const char *file) {
  lock_acquire(&(thread_current()->files.lock));
  struct list *process_files = &(thread_current()->files.list);
  int new_fd = 0;

  if (list_empty(process_files)) {
    new_fd = 2;  // non-standard dscriptors start from 2
  } else {
    struct list_elem *e = list_front(process_files);
    struct file_info_t *front_file_info =
        list_entry(e, struct file_info_t, elem);
    new_fd = front_file_info->fd + 1;
  }
  lock_release(&(thread_current()->files.lock));
  // lock_acquire(&filesys_lock);
  // Get file struct of given path
  struct file *cur_file_data = filesys_open(file);

  // lock_release(&filesys_lock);
  int res;

  if (cur_file_data == NULL) {
    res = -1;
    goto done;
  }
  //printf("Start fd: %d sector: %u\n", new_fd, inode_get_inumber(cur_file_data->inode));

  // Fill our struct members
  struct file_info_t *cur_file_info =
      (struct file_info_t *)malloc(sizeof(struct file_info_t));
  cur_file_info->fd = new_fd;
  cur_file_info->is_dir = inode_is_dir(cur_file_data->inode);
  if (cur_file_info->is_dir) {
    cur_file_info->dir = dir_open(cur_file_data->inode);
    //printf("Directory fd: %d sector: %u\n", new_fd, inode_get_inumber(dir_get_inode(cur_file_info->dir)));
    //file_close(cur_file_data);
  } else {
    cur_file_info->file_data = cur_file_data;
    //printf("File fd: %d sector: %u\n", new_fd, inode_get_inumber(cur_file_data->inode));
  }
  

  

  res = new_fd;
  // Add new opened file to list of opened files for this thread
  lock_acquire(&(thread_current()->files.lock));
  list_push_front(&(thread_current()->files.list), &(cur_file_info->elem));
  lock_release(&(thread_current()->files.lock));

done:

  return res;
}

int _filesize(int fd) {
  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return -1;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);
  // lock_acquire(&filesys_lock);
  if (file == NULL || file->is_dir) return 0;
  int res = file_length(file->file_data);
  // lock_release(&filesys_lock);
  return res;
}

int _read(int fd, void *buffer, unsigned size) {
  if (fd == 0) {
    char *charbuff = (char *)buffer;
    int i = 0;
    for (i = 0; i < (int)size; i++) {
      charbuff[i] = input_getc();
    }
  }

  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return -1;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);
  if (file == NULL || file->is_dir) return -1;

  // lock_acquire(&filesys_lock);
  int res = file_read(file->file_data, buffer, size);
  // lock_release(&filesys_lock);
  return res;
}

int _write(int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }

  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return -1;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);
  if (file == NULL || file->is_dir) return -1;

  // lock_acquire(&filesys_lock);
  int res = file_write(file->file_data, buffer, size);
  // lock_release(&filesys_lock);
  return res;
}

void _seek(int fd, unsigned position) {
  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);

  // lock_acquire(&filesys_lock);
  if (file != NULL && !file->is_dir)
    file_seek(file->file_data, position);
  // lock_release(&filesys_lock);
}

unsigned _tell(int fd) {
  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return -1;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);
  // lock_acquire(&filesys_lock);
  if (file == NULL || file->is_dir) return -1;
  unsigned res = file_tell(file->file_data);
  // lock_release(&filesys_lock);
  return res;
}

void _close(int fd) {
  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);
  if (file == NULL) return;
  
  // lock_acquire(&filesys_lock);
  if (file->is_dir) {
    dir_close(file->dir);
  } else {
    file_close(file->file_data);
  }
  // lock_release(&filesys_lock);
  lock_acquire(&thread_current()->files.lock);
  list_remove(&file->elem);
  lock_release(&thread_current()->files.lock);
  free(file);
}

bool _chdir(const char *dir) {
  struct dir* cwd = thread_current()->cwd;
  
  struct dir *new_dir = dir_open_path(cwd, (char *)dir);
  if (new_dir == NULL) {
    return false;
  }
  thread_current()->cwd = new_dir;
  return true;
}

bool _mkdir(const char *dir) { return filesys_create(dir, 0, Directory); }

bool _readdir(int fd, char *name) {
  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return false;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);
  if (file == NULL || !file->is_dir) return false;
  bool success = dir_readdir(file->dir, name);
  return success;
}

bool _isdir(int fd) {
  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return false;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);
  return (file != NULL && file->is_dir);
}

int _inumber(int fd) {
  struct list_elem *e = get_file_list_elem(fd);
  if (e == NULL) {
    return -1;
  }
  struct file_info_t *file = list_entry(e, struct file_info_t, elem);
  struct inode* inode;
  if (file->is_dir) {
    inode = dir_get_inode(file->dir);
  } else {
    inode = file->file_data->inode;
  }
  return inode_get_inumber(inode);
}