#include "userprog/syscall.h"
#include <console.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "process.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static struct lock filesys_lock;
static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void syscall_halt(struct intr_frame *f UNUSED, uint32_t *args);
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

typedef void (*syscall_func_t)(struct intr_frame *f UNUSED, uint32_t *args);

syscall_func_t syscall_func_arr[14] = {
    syscall_halt,   syscall_exit,    syscall_exec, syscall_wait,
    syscall_create, syscall_remove,  syscall_open, syscall_filesize,
    syscall_read,   syscall_write,   syscall_seek, syscall_tell,
    syscall_close,  syscall_practice};

static void syscall_handler(struct intr_frame *f UNUSED) {
  uint32_t *args = ((uint32_t *)f->esp);
  syscall_func_arr[args[0]](f, args);
}

static bool valid_ptr(void *ptr, int size) {
  if (ptr == NULL) return false;

  ptr += size - 1;
  if (!is_user_vaddr(ptr)) return false;
  if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL) return false;

  return true;
}

static void _exit(int status) {
  printf("%s: exit(%d)\n", &thread_current()->name, status);
  struct child_info_t *child = get_child_info_t(thread_current());
  if (child != NULL) {
    child->status = status;
  }
  thread_exit();
}

static void syscall_halt(struct intr_frame *f UNUSED, uint32_t *args) {
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f UNUSED, uint32_t *args) {
  _exit(*(int *)(&args[1]));
}

static void syscall_exec(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args[1], sizeof(char))) {
    _exit(-1);
    NOT_REACHED();
  }

  lock_acquire(&filesys_lock);
  tid_t process_pid = process_execute((char *)args[1]);
  f->eax = process_pid;
  if (process_pid != TID_ERROR) {
	lock_release(&filesys_lock);

    process_exit();
  }
  lock_release(&filesys_lock);
}

static void syscall_wait(struct intr_frame *f UNUSED, uint32_t *args) {
  tid_t pid = args[1];
  f->eax = process_wait(pid);
}

static void syscall_create(struct intr_frame *f UNUSED, uint32_t *args) {
  // retrieving file name
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  char *file_name = *((char **)cur_arg);
  // retrieving size
  cur_arg += sizeof(char *);
  off_t sz = *(off_t *)cur_arg;
  // check pointer
  if (!valid_ptr(file_name, sizeof(char))) {
    _exit(-1);
    NOT_REACHED();
  }
  lock_acquire(&filesys_lock);
  f->eax = filesys_create(file_name, sz);
  lock_release(&filesys_lock);
}

static void syscall_remove(struct intr_frame *f UNUSED, uint32_t *args) {
  // retrieving file name
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  char *file_name = *((char **)cur_arg);
  // check pointer
  if (!valid_ptr(file_name, sizeof(char))) {
    _exit(-1);
    NOT_REACHED();
  }
  lock_acquire(&filesys_lock);
  f->eax = filesys_remove(file_name);
  lock_release(&filesys_lock);
}

static void syscall_open(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args[1], sizeof(char))) {
    _exit(-1);
    NOT_REACHED();
  }

  lock_acquire(&filesys_lock);
  char *file_name = (char *)args[1];
  struct list *process_files = &(thread_current()->files);
  int new_fd = 0;

  if (list_empty(process_files)) {
    new_fd = 2;  // non-standard dscriptors start from 2
  } else {
    struct file_info_t *front_file_info =
        list_entry(list_front(process_files), struct file_info_t, elem);
    new_fd = front_file_info->fd + 1;
  }

  // Get file struct of given path
  struct file *cur_file_data = filesys_open(file_name);

  // Fill our struct members
  struct file_info_t *cur_file_info =
      (struct file_info_t *)malloc(sizeof(struct file_info_t));
  cur_file_info->fd = new_fd;
  cur_file_info->file_data = cur_file_data;

  // Add new opened file to list of opened files for this thread
  list_push_front(&(thread_current()->files), &(cur_file_info->elem));
  f->eax = new_fd;

  lock_release(&filesys_lock);
}

static void syscall_filesize(struct intr_frame *f UNUSED, uint32_t *args) {
  int fd = args[1];
  struct file_info_t *file = get_file_info_t(fd);
  f->eax = file_length(file->file_data);
}

static void syscall_read(struct intr_frame *f UNUSED, uint32_t *args) {
  // retrieving fd
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  int fd = *((int *)cur_arg);
  // retrieving buff pointer
  cur_arg += sizeof(int);
  void *buff = *(void **)cur_arg;

  // retrieving size
  cur_arg += sizeof(void *);
  off_t sz = *(off_t *)cur_arg;

  // check pointer
  if (!valid_ptr(buff, sz)) {
    _exit(-1);
    NOT_REACHED();
  }
  if (fd == 0) {
    // TODO: კლავიატურიდან წაკითხვა
    return;
  }

  struct file_info_t *file = get_file_info_t(fd);

  if (file == NULL) {
    _exit(-1);
    NOT_REACHED();
  }

  lock_acquire(&filesys_lock);
  f->eax = file_read(file->file_data, buff, sz);
  lock_release(&filesys_lock);
}

static void syscall_write(struct intr_frame *f UNUSED, uint32_t *args) {

    //  printf("\n write start\n"); 
  // retrieving fd
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  int fd = *((int *)cur_arg);
  // retrieving buff pointer
  cur_arg += sizeof(int);
  void *buff = *(void **)cur_arg;

  // retrieving size
  cur_arg += sizeof(void *);
  off_t sz = *(off_t *)cur_arg;

//   printf ("ppp: %p %d\n", buff, sz);

  // check pointer
  if (!valid_ptr(buff, sz)) {
    _exit(-1);
    NOT_REACHED();
  }

  if (fd == 1) {
    putbuf(buff, sz);
    //  printf("\n write :   %s\n", buff); 
    f->eax = sz;
    return;
  }

  struct file_info_t *file = get_file_info_t(fd);

  if (file == NULL) {
    _exit(-1);
    NOT_REACHED();
  }

  lock_acquire(&filesys_lock);
  f->eax = file_write(file->file_data, buff, sz);
  lock_release(&filesys_lock);
}

static void syscall_seek(struct intr_frame *f UNUSED, uint32_t *args) {
  // retrieving fd
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  int fd = *((int *)cur_arg);
  // retrieving size
  cur_arg += sizeof(int);
  off_t pos = *(off_t *)cur_arg;

  struct file_info_t *file = get_file_info_t(fd);
  if (file == NULL) {
    _exit(-1);
    NOT_REACHED();
  }

  lock_acquire(&filesys_lock);
  file_seek(file->file_data, pos);
  lock_release(&filesys_lock);
}

static void syscall_tell(struct intr_frame *f UNUSED, uint32_t *args) {
  // retrieving fd
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  int fd = *((int *)cur_arg);
  struct file_info_t *file = get_file_info_t(fd);
  if (file == NULL) {
    _exit(-1);
    NOT_REACHED();
  }
  lock_acquire(&filesys_lock);
  f->eax = file_tell(file->file_data);
  lock_release(&filesys_lock);
}

static void syscall_close(struct intr_frame *f UNUSED, uint32_t *args) {
  // retrieving fd
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  int fd = *((int *)cur_arg);
  struct file_info_t *file = get_file_info_t(fd);
  if (file == NULL) {
    _exit(-1);
    NOT_REACHED();
  }
  lock_acquire(&filesys_lock);
  file_close(file->file_data);
  lock_release(&filesys_lock);
}

static void syscall_practice(struct intr_frame *f UNUSED, uint32_t *args) {
  f->eax = args[1] + 1;
}