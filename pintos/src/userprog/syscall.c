#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/filesys.h"

static struct lock filesys_lock;
static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
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
  printf("System call number: %d\n", args[0]);

  syscall_func_arr[args[0]](f, args);
}

static void syscall_halt(struct intr_frame *f UNUSED, uint32_t *args) {
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f UNUSED, uint32_t *args) {
  f->eax = args[1];
  printf("%s: exit(%d)\n", &thread_current()->name, args[1]);
  thread_exit();
  ASSERT(intr_get_level() == INTR_OFF);
  struct child_info_t *child = get_child_info_t(thread_current());
  if (child != NULL) {
    child->status = args[1];
  }
}

static void syscall_exec(struct intr_frame *f UNUSED, uint32_t *args) {
	lock_acquire (&filesys_lock);
	tid_t process_pid =  process_execute ((char*)args[1]);
	f->eax = process_pid;
	if (process_pid != TID_ERROR) {
		process_exit ();
	}

	lock_release (&filesys_lock);
}

static void syscall_wait(struct intr_frame *f UNUSED, uint32_t *args) {
  tid_t pid = args[1];
  f->eax = process_wait(pid);
}

static void syscall_create(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_remove(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_open(struct intr_frame *f UNUSED, uint32_t *args) {
	lock_acquire (&filesys_lock);
	char * file_name = (char *) args[1];
	struct list * process_files = &(thread_current()->files);
	int new_fd = 0;


	if (list_empty (process_files)) {
		new_fd = 2; // non-standard dscriptors start from 2
	} else {
		struct file_info_t * front_file_info = list_entry (list_front (process_files), struct file_info_t, elem);
		int new_fd = front_file_info->fd + 2; 
	}

	// Get file struct of given path
	struct file * cur_file_data = filesys_open (file_name);

	// Fill our struct members
	struct file_info_t * cur_file_info = (struct file_info_t *) malloc (sizeof (struct file_info_t));
	cur_file_info -> fd = new_fd;
	cur_file_info -> file_data = *cur_file_data;

	// Add new opened file to list of opened files for this thread
	list_push_front (&(thread_current()->files), &(cur_file_info -> elem));


	lock_release (&filesys_lock);
}

static void syscall_filesize(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_read(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_write(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_seek(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_tell(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_close(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_practice(struct intr_frame *f UNUSED, uint32_t *args) {
  f->eax = args[1] + 1;
}
