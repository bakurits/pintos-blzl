#include "userprog/syscall.h"
#include <console.h>
#include <stdio.h>
#include <syscall-nr.h>
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

static bool valid_ptr(void *ptr, int size) {
  if (ptr == NULL) return false;

  ptr += size - 1;
  if (!is_user_vaddr(ptr)) return false;
  if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL) return false;

  return true;
}

syscall_func_t syscall_func_arr[14] = {
    syscall_halt,   syscall_exit,    syscall_exec, syscall_wait,
    syscall_create, syscall_remove,  syscall_open, syscall_filesize,
    syscall_read,   syscall_write,   syscall_seek, syscall_tell,
    syscall_close,  syscall_practice};

static void syscall_handler(struct intr_frame *f UNUSED) {
  uint32_t *args = ((uint32_t *)f->esp);
  if (!valid_ptr(args, sizeof(void *))) {
    _exit(-1);
  }

  syscall_func_arr[args[0]](f, args);
}

static void syscall_halt(struct intr_frame *f UNUSED, uint32_t *args) {
  _halt();
}

static void syscall_exit(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(void *))) {
    _exit(-1);
  }
  _exit(*(int *)(&args[1]));
}

static void syscall_exec(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(void *))) {
    _exit(-1);
  }
  if (!valid_ptr(args[1], sizeof(char *))) {
    _exit(-1);
  }
  f->eax = _exec((char *)args[1]);
}

static void syscall_wait(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(pid_t))) {
    _exit(-1);
  }
  f->eax = _wait(args[1]);
}

static void syscall_create(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(char *) + sizeof(unsigned))) {
    _exit(-1);
  }

  if (!valid_ptr(args[1], sizeof(char))) {
    _exit(-1);
  }

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

  f->eax = _create(file_name, sz);
}

static void syscall_remove(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(char *))) {
    _exit(-1);
  }
  if (!valid_ptr(args[1], sizeof(char))) {
    _exit(-1);
  }

  // retrieving file name
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  char *file_name = *((char **)cur_arg);
  // check pointer
  if (!valid_ptr(file_name, sizeof(char))) {
    _exit(-1);
    NOT_REACHED();
  }

  f->eax = _remove(file_name);
}

static void syscall_open(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(char *))) {
    _exit(-1);
  }
  if (!valid_ptr(args[1], sizeof(char))) {
    _exit(-1);
  }
  char *file_name = (char *)args[1];
  f->eax = _open(file_name);
}

static void syscall_filesize(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(char *))) {
    _exit(-1);
  }

  f->eax = _filesize(args[1]);
}

static void syscall_read(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(int) + sizeof(char *) + sizeof(unsigned))) {
    _exit(-1);
  }
  if (!valid_ptr(args[2], sizeof(char))) {
    _exit(-1);
  }

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

  f->eax = _read(fd, buff, sz);
}

static void syscall_write(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(int) + sizeof(char *) + sizeof(unsigned))) {
    _exit(-1);
  }
  if (!valid_ptr(args[2], sizeof(char))) {
    _exit(-1);
  }

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

  f->eax = _write(fd, buff, sz);
}

static void syscall_seek(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(int) + sizeof(unsigned))) {
    _exit(-1);
  }

  // retrieving fd
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  int fd = *((int *)cur_arg);
  // retrieving size
  cur_arg += sizeof(int);
  off_t pos = *(off_t *)cur_arg;
  _seek(fd, pos);
}

static void syscall_tell(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(int))) {
    _exit(-1);
  }
  // retrieving fd
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  int fd = *((int *)cur_arg);
  f->eax = _tell(fd);
}

static void syscall_close(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(int))) {
    _exit(-1);
  }
  // retrieving fd
  char *cur_arg = args;
  cur_arg += sizeof(void *);
  int fd = *((int *)cur_arg);
  _close(fd);
}

static void syscall_practice(struct intr_frame *f UNUSED, uint32_t *args) {
  if (!valid_ptr(args + 1, sizeof(int))) {
    _exit(-1);
  }
  f->eax = _practice(args[1]);
}

int _practice(int i) { return i + 1; }

void _halt(void) { shutdown_power_off(); }

void _exit(int status) {
  printf("%s: exit(%d)\n", &thread_current()->name, status);
  struct child_info_t *child = get_child_info_t(thread_current());
  if (child != NULL) {
    child->status = status;
  }
  thread_exit();
}

pid_t _exec(const char *cmd_line) {
  lock_acquire(&filesys_lock);
  tid_t process_pid = process_execute(cmd_line);
  lock_release(&filesys_lock);
  return process_pid;
}

int _wait(pid_t pid) {
  tid_t tid = pid;
  return process_wait(tid);
}

bool _create(const char *file, unsigned initial_size) {
  lock_acquire(&filesys_lock);
  bool res = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return res;
}

bool _remove(const char *file) {
  lock_acquire(&filesys_lock);
  bool res = filesys_remove(file);
  lock_release(&filesys_lock);
  return res;
}

int _open(const char *file) {
  struct list *process_files = &(thread_current()->files);
  int new_fd = 0;

  if (list_empty(process_files)) {
    new_fd = 2;  // non-standard dscriptors start from 2
  } else {
    struct list_elem *e = list_back(process_files);
    struct file_info_t *front_file_info =
        list_entry(e, struct file_info_t, elem);
    new_fd = front_file_info->fd + 1;
  }
  lock_acquire(&filesys_lock);
  // Get file struct of given path
  struct file *cur_file_data = filesys_open(file);
  int res;

	if (cur_file_data == NULL) {
		res = -1;
		goto done;
	}

  // Fill our struct members
  struct file_info_t *cur_file_info =
      (struct file_info_t *)malloc(sizeof(struct file_info_t));
  cur_file_info->fd = new_fd;
  cur_file_info->file_data = cur_file_data;

	res = new_fd;
  // Add new opened file to list of opened files for this thread
  list_push_front(&(thread_current()->files), &(cur_file_info->elem));

	done :
		lock_release(&filesys_lock);
		return res;
}

int _filesize(int fd) {
  struct file_info_t *file = get_file_info_t(fd);
  if (file == NULL) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  int res = file_length(file->file_data);
  lock_release(&filesys_lock);
  return res;
}

int _read(int fd, void *buffer, unsigned size) {
  if (fd == 0) {
    // TODO: კლავიატურიდან წაკითხვა
    return size;
  }

  struct file_info_t *file = get_file_info_t(fd);

  if (file == NULL) {
    return -1;
  }

  lock_acquire(&filesys_lock);
  int res = file_read(file->file_data, buffer, size);
  lock_release(&filesys_lock);
  return res;
}

int _write(int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);
    //  printf("\n write :   %s\n", buff);
    return size;
  }

  struct file_info_t *file = get_file_info_t(fd);

  if (file == NULL) {
    return -1;
  }

  lock_acquire(&filesys_lock);
  int res = file_write(file->file_data, buffer, size);
  lock_release(&filesys_lock);
  return res;
}

void _seek(int fd, unsigned position) {
  struct file_info_t *file = get_file_info_t(fd);
  if (file == NULL) {
    return;
  }

  lock_acquire(&filesys_lock);
  file_seek(file->file_data, position);
  lock_release(&filesys_lock);
}

unsigned _tell(int fd) {
  struct file_info_t *file = get_file_info_t(fd);
  if (file == NULL) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  unsigned res = file_tell(file->file_data);
  lock_release(&filesys_lock);
  return res;
}

void _close(int fd) {
  struct file_info_t *file = get_file_info_t(fd);
  if (file == NULL) {
    return;
    NOT_REACHED();
  }
  lock_acquire(&filesys_lock);
  file_close(file->file_data);
  lock_release(&filesys_lock);
}